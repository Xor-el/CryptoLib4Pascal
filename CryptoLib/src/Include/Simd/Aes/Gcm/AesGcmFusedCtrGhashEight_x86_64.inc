// Fused AES-NI CTR keystream + 8-way GHASH kernel (x86-64).
// -------------------------------------------------------------------
// Technique: Shay Gueron, "Intel AES New Instructions" Rev 3.01 - AES
// and PCLMULQDQ instructions are interleaved so the AES port and the
// carry-less-multiply port operate in parallel, hiding GHASH latency
// inside the AES critical path.
//
// Loops over BatchCount pipelined batches. Each batch AES-encrypts eight
// counter blocks (generated in-register from Counter32 + PJ0Template) to
// produce a keystream, XORs it with PXorIn to produce POut, and concurrently
// GHASHes the PREVIOUS batch's 8 ciphertext blocks into the running
// authentication state (the pipeline lags by one batch). AES inside GCM is
// always CTR keystream construction; GhashFromOutput picks which buffer feeds
// GHASH (output on encrypt, input on decrypt). The mode primes batch 0 and
// drains the last.
//
// PHPow128 holds the kernel-owned H^8..H^1 table PRE-MULTIPLIED BY x in the
// reflected representation, so the batch product reduces with two
// carry-less multiplies by 0xC2000000_00000000 instead of a shift/XOR
// ladder. The running GHASH state stays reflected between batches and is
// only byte-reversed at kernel entry/exit.
//
// Variant selection (set EXACTLY ONE):
//   GCM_FUSED_AES_ROUNDS_10  -> AES-128 (schedule = 11 x 16 bytes).
//   GCM_FUSED_AES_ROUNDS_12  -> AES-192 (schedule = 13 x 16 bytes).
//   GCM_FUSED_AES_ROUNDS_14  -> AES-256 (schedule = 15 x 16 bytes).
//
// On entry (after ClpSimdProc1Begin_x86_64.inc): rcx = PCtx.
// Context layout (TGcmFusedCtx in ClpAesNiGcmKernel.pas; 8-byte fields):
//   [rcx +  0]  PXorIn    [rcx +  8]  POut       [rcx + 16]  PPrevCipher
//   [rcx + 24]  PRoundKeys (16-byte aligned)     [rcx + 32]  PHPow128
//   [rcx + 40]  PFS       [rcx + 48]  PMask      [rcx + 56]  Counter32
//   [rcx + 64]  PJ0Template                      [rcx + 72]  BatchCount
//   [rcx + 80]  GhashFromOutput (1 = encrypt)
//
// All loop-carried state lives in registers - no context memory is
// touched inside the batch loop:
//   rsi/rdi = PXorIn/POut (advance)   r10 = PPrevCipher (rotates)
//   rdx = PRoundKeys   r11 = PHPow128   r8d = counter32
//   rbx = batch count   ebp = GHASH-from-output flag   rax = scratch
//
// XMM (16/16 used):
//   xmm0..xmm7  : 8 AES keystream lanes (round keys via memory operands)
//   xmm8        : keystream-XOR scratch (free during the rounds)
//   xmm9..xmm11 : Z0 / Z1 / Z2 GHASH accumulators; xmm9 doubles as the
//                 reflected running state carried across batches
//   xmm12       : GHASH input block (byte-reversed, per iter)
//   xmm13       : current H-power limb (per iter)
//   xmm14       : pclmul scratch destination
//   xmm15       : byte-reverse mask (held for the whole kernel)
//
// Stack (below the nonvolatile-save area; [rsp] is 16-aligned):
//   [rsp +  0]   reduction constant (low qword 0xC2000000_00000000)
//   [rsp + 16..143]  8 aligned counter-block slots. The fixed 12-byte J0
//     prefix is staged once in the prologue, and each batch's AES-only
//     tail rounds stage the NEXT batch's counter words (GPR stores, no
//     shuffle-port inserts), so the loop-top movdqa loads never read a
//     freshly written slot (no store-forward stalls). The prologue
//     pre-stages batch 0; the final batch over-stages into scratch.
//
// AES-NI and PCLMULQDQ instructions, plus selected forms touching
// xmm8..xmm15 (pxor) and PSHUFD, are db-encoded for broad assembler
// compatibility.
// -------------------------------------------------------------------

  push      rbx
  push      rsi
  push      rdi
  push      rbp
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  sub       rsp, 152                            // [rsp] 16-aligned
  mov       rax, $C200000000000000
  mov       [rsp], rax                          // reduction constant (low qword)
  xor       eax, eax
  mov       [rsp + 8], rax

  // --- Stage the fixed J0 prefix into the 8 counter slots once; only
  //     bytes 12..15 (the counter word) change per batch. ---
  mov       rax, [rcx + 64]                     // PJ0Template
  mov       rdx, [rax]                          // J0 bytes 0..7
  mov       eax, [rax + 8]                      // J0 bytes 8..11
  mov       [rsp + 16], rdx
  mov       [rsp + 24], eax
  mov       [rsp + 32], rdx
  mov       [rsp + 40], eax
  mov       [rsp + 48], rdx
  mov       [rsp + 56], eax
  mov       [rsp + 64], rdx
  mov       [rsp + 72], eax
  mov       [rsp + 80], rdx
  mov       [rsp + 88], eax
  mov       [rsp + 96], rdx
  mov       [rsp + 104], eax
  mov       [rsp + 112], rdx
  mov       [rsp + 120], eax
  mov       [rsp + 128], rdx
  mov       [rsp + 136], eax

  // --- Hoist the whole loop state into registers. ---
  mov       rdx, [rcx + 24]                     // rdx = PRoundKeys (aligned)
  mov       r11, [rcx + 32]                     // r11 = PHPow128 (x-shifted)
  mov       rax, [rcx + 48]
  movdqu    xmm15, [rax]                        // xmm15 = byte-reverse mask
  mov       rsi, [rcx + 0]                      // rsi = PXorIn
  mov       rdi, [rcx + 8]                      // rdi = POut
  mov       r10, [rcx + 16]                     // r10 = PPrevCipher
  mov       r8d, [rcx + 56]                     // r8d = counter32
  mov       rbx, [rcx + 72]                     // rbx = batch count
  mov       ebp, [rcx + 80]                     // ebp = GHASH-from-output flag
  mov       rax, [rcx + 40]                     // rax = PFS
  movdqu    xmm9, [rax]
  pshufb    xmm9, xmm15                         // xmm9 = reflected running state

  // --- Pre-stage batch 0's counter words (counter32+1..+8, big-endian). ---
  lea       eax, [r8 + 1]
  bswap     eax
  mov       [rsp + 28], eax
  lea       eax, [r8 + 2]
  bswap     eax
  mov       [rsp + 44], eax
  lea       eax, [r8 + 3]
  bswap     eax
  mov       [rsp + 60], eax
  lea       eax, [r8 + 4]
  bswap     eax
  mov       [rsp + 76], eax
  lea       eax, [r8 + 5]
  bswap     eax
  mov       [rsp + 92], eax
  lea       eax, [r8 + 6]
  bswap     eax
  mov       [rsp + 108], eax
  lea       eax, [r8 + 7]
  bswap     eax
  mov       [rsp + 124], eax
  lea       eax, [r8 + 8]
  bswap     eax
  mov       [rsp + 140], eax

@@GcmFusedLoop:
  // Load the 8 pre-staged counter blocks: block j = J0[0..11] ||
  // BE(counter32+j+1) (GCM's counter holds the last-used value, matching
  // FillCtr8BlocksRaw). The words were staged a full round-chain ago.
  movdqa    xmm0, [rsp + 16]
  movdqa    xmm1, [rsp + 32]
  movdqa    xmm2, [rsp + 48]
  movdqa    xmm3, [rsp + 64]
  movdqa    xmm4, [rsp + 80]
  movdqa    xmm5, [rsp + 96]
  movdqa    xmm6, [rsp + 112]
  movdqa    xmm7, [rsp + 128]

  // --- Round 0: AddRoundKey (aligned key memory operands) + zero Z1/Z2.
  //     Z0 (xmm9) still holds the carried state; iter 0 folds and clears it. ---
  pxor      xmm0, [rdx]
  pxor      xmm1, [rdx]
  pxor      xmm2, [rdx]
  pxor      xmm3, [rdx]
  pxor      xmm4, [rdx]
  pxor      xmm5, [rdx]
  pxor      xmm6, [rdx]
  pxor      xmm7, [rdx]
  db $66, $45, $0F, $EF, $D2                    // pxor xmm10, xmm10   (Z1=0)
  db $66, $45, $0F, $EF, $DB                    // pxor xmm11, xmm11   (Z2=0)

  // --- Round 1 + GHASH iter 0 (with carried-state fold). ---
  movdqu    xmm12, [r10 + 0]                 // prev cipher block 0
  pshufb    xmm12, xmm15                       // byte-reverse
  db $66, $45, $0F, $EF, $E1                    // pxor xmm12, xmm9 (fold carried state)
  db $66, $45, $0F, $EF, $C9                    // pxor xmm9, xmm9  (Z0=0)
  movdqu    xmm13, [r11 + 0]                 // H^8 (x-shifted)

  db $66, $0F, $38, $DC, $42, $10               // aesenc xmm0, [rdx+16]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $4A, $10               // aesenc xmm1, [rdx+16]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $52, $10               // aesenc xmm2, [rdx+16]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $5A, $10               // aesenc xmm3, [rdx+16]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $62, $10               // aesenc xmm4, [rdx+16]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $6A, $10               // aesenc xmm5, [rdx+16]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $72, $10               // aesenc xmm6, [rdx+16]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $7A, $10               // aesenc xmm7, [rdx+16]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Round 2 + GHASH iter 1. ---
  movdqu    xmm12, [r10 + 16]                 // prev cipher block 1
  pshufb    xmm12, xmm15                       // byte-reverse
  movdqu    xmm13, [r11 + 16]                 // H^7 (x-shifted)

  db $66, $0F, $38, $DC, $42, $20               // aesenc xmm0, [rdx+32]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $4A, $20               // aesenc xmm1, [rdx+32]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $52, $20               // aesenc xmm2, [rdx+32]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $5A, $20               // aesenc xmm3, [rdx+32]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $62, $20               // aesenc xmm4, [rdx+32]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $6A, $20               // aesenc xmm5, [rdx+32]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $72, $20               // aesenc xmm6, [rdx+32]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $7A, $20               // aesenc xmm7, [rdx+32]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Round 3 + GHASH iter 2. ---
  movdqu    xmm12, [r10 + 32]                 // prev cipher block 2
  pshufb    xmm12, xmm15                       // byte-reverse
  movdqu    xmm13, [r11 + 32]                 // H^6 (x-shifted)

  db $66, $0F, $38, $DC, $42, $30               // aesenc xmm0, [rdx+48]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $4A, $30               // aesenc xmm1, [rdx+48]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $52, $30               // aesenc xmm2, [rdx+48]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $5A, $30               // aesenc xmm3, [rdx+48]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $62, $30               // aesenc xmm4, [rdx+48]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $6A, $30               // aesenc xmm5, [rdx+48]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $72, $30               // aesenc xmm6, [rdx+48]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $7A, $30               // aesenc xmm7, [rdx+48]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Round 4 + GHASH iter 3. ---
  movdqu    xmm12, [r10 + 48]                 // prev cipher block 3
  pshufb    xmm12, xmm15                       // byte-reverse
  movdqu    xmm13, [r11 + 48]                 // H^5 (x-shifted)

  db $66, $0F, $38, $DC, $42, $40               // aesenc xmm0, [rdx+64]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $4A, $40               // aesenc xmm1, [rdx+64]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $52, $40               // aesenc xmm2, [rdx+64]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $5A, $40               // aesenc xmm3, [rdx+64]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $62, $40               // aesenc xmm4, [rdx+64]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $6A, $40               // aesenc xmm5, [rdx+64]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $72, $40               // aesenc xmm6, [rdx+64]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $7A, $40               // aesenc xmm7, [rdx+64]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Round 5 + GHASH iter 4. ---
  movdqu    xmm12, [r10 + 64]                 // prev cipher block 4
  pshufb    xmm12, xmm15                       // byte-reverse
  movdqu    xmm13, [r11 + 64]                 // H^4 (x-shifted)

  db $66, $0F, $38, $DC, $42, $50               // aesenc xmm0, [rdx+80]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $4A, $50               // aesenc xmm1, [rdx+80]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $52, $50               // aesenc xmm2, [rdx+80]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $5A, $50               // aesenc xmm3, [rdx+80]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $62, $50               // aesenc xmm4, [rdx+80]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $6A, $50               // aesenc xmm5, [rdx+80]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $72, $50               // aesenc xmm6, [rdx+80]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $7A, $50               // aesenc xmm7, [rdx+80]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Round 6 + GHASH iter 5. ---
  movdqu    xmm12, [r10 + 80]                 // prev cipher block 5
  pshufb    xmm12, xmm15                       // byte-reverse
  movdqu    xmm13, [r11 + 80]                 // H^3 (x-shifted)

  db $66, $0F, $38, $DC, $42, $60               // aesenc xmm0, [rdx+96]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $4A, $60               // aesenc xmm1, [rdx+96]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $52, $60               // aesenc xmm2, [rdx+96]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $5A, $60               // aesenc xmm3, [rdx+96]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $62, $60               // aesenc xmm4, [rdx+96]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $6A, $60               // aesenc xmm5, [rdx+96]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $72, $60               // aesenc xmm6, [rdx+96]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $7A, $60               // aesenc xmm7, [rdx+96]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Round 7 + GHASH iter 6. ---
  movdqu    xmm12, [r10 + 96]                 // prev cipher block 6
  pshufb    xmm12, xmm15                       // byte-reverse
  movdqu    xmm13, [r11 + 96]                 // H^2 (x-shifted)

  db $66, $0F, $38, $DC, $42, $70               // aesenc xmm0, [rdx+112]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $4A, $70               // aesenc xmm1, [rdx+112]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $52, $70               // aesenc xmm2, [rdx+112]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $5A, $70               // aesenc xmm3, [rdx+112]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $62, $70               // aesenc xmm4, [rdx+112]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $6A, $70               // aesenc xmm5, [rdx+112]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $72, $70               // aesenc xmm6, [rdx+112]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $7A, $70               // aesenc xmm7, [rdx+112]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Round 8 + GHASH iter 7. ---
  movdqu    xmm12, [r10 + 112]                 // prev cipher block 7
  pshufb    xmm12, xmm15                       // byte-reverse
  movdqu    xmm13, [r11 + 112]                 // H^1 (x-shifted)

  db $66, $0F, $38, $DC, $82, $80, $00, $00, $00   // aesenc xmm0, [rdx+128]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00          // pclmulqdq xmm14, xmm13, 0x00
  db $66, $0F, $38, $DC, $8A, $80, $00, $00, $00   // aesenc xmm1, [rdx+128]
  db $66, $45, $0F, $EF, $CE                    // pxor xmm9, xmm14  (Z0 +=)
  db $66, $0F, $38, $DC, $92, $80, $00, $00, $00   // aesenc xmm2, [rdx+128]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01          // pclmulqdq xmm14, xmm13, 0x01
  db $66, $0F, $38, $DC, $9A, $80, $00, $00, $00   // aesenc xmm3, [rdx+128]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $A2, $80, $00, $00, $00   // aesenc xmm4, [rdx+128]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10          // pclmulqdq xmm14, xmm13, 0x10
  db $66, $0F, $38, $DC, $AA, $80, $00, $00, $00   // aesenc xmm5, [rdx+128]
  db $66, $45, $0F, $EF, $D6                    // pxor xmm10, xmm14  (Z1 +=)
  db $66, $0F, $38, $DC, $B2, $80, $00, $00, $00   // aesenc xmm6, [rdx+128]
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11          // pclmulqdq xmm14, xmm13, 0x11
  db $66, $0F, $38, $DC, $BA, $80, $00, $00, $00   // aesenc xmm7, [rdx+128]
  db $66, $45, $0F, $EF, $DE                    // pxor xmm11, xmm14  (Z2 +=)

  // --- Variant-specific tail: aesenc rounds 9..Nr-1, then aesenclast.
  //     Round 9 interleaves the staging of the NEXT batch's counter
  //     words (counter32+9..+16) into the slots. ---
  db $66, $0F, $38, $DC, $82, $90, $00, $00, $00   // aesenc xmm0, [rdx+144]
  lea       eax, [r8 + 9]
  bswap     eax
  mov       [rsp + 28], eax
  db $66, $0F, $38, $DC, $8A, $90, $00, $00, $00   // aesenc xmm1, [rdx+144]
  lea       eax, [r8 + 10]
  bswap     eax
  mov       [rsp + 44], eax
  db $66, $0F, $38, $DC, $92, $90, $00, $00, $00   // aesenc xmm2, [rdx+144]
  lea       eax, [r8 + 11]
  bswap     eax
  mov       [rsp + 60], eax
  db $66, $0F, $38, $DC, $9A, $90, $00, $00, $00   // aesenc xmm3, [rdx+144]
  lea       eax, [r8 + 12]
  bswap     eax
  mov       [rsp + 76], eax
  db $66, $0F, $38, $DC, $A2, $90, $00, $00, $00   // aesenc xmm4, [rdx+144]
  lea       eax, [r8 + 13]
  bswap     eax
  mov       [rsp + 92], eax
  db $66, $0F, $38, $DC, $AA, $90, $00, $00, $00   // aesenc xmm5, [rdx+144]
  lea       eax, [r8 + 14]
  bswap     eax
  mov       [rsp + 108], eax
  db $66, $0F, $38, $DC, $B2, $90, $00, $00, $00   // aesenc xmm6, [rdx+144]
  lea       eax, [r8 + 15]
  bswap     eax
  mov       [rsp + 124], eax
  db $66, $0F, $38, $DC, $BA, $90, $00, $00, $00   // aesenc xmm7, [rdx+144]
  lea       eax, [r8 + 16]
  bswap     eax
  mov       [rsp + 140], eax
{$IF DEFINED(GCM_FUSED_AES_ROUNDS_12) OR DEFINED(GCM_FUSED_AES_ROUNDS_14)}
  db $66, $0F, $38, $DC, $82, $A0, $00, $00, $00   // aesenc xmm0, [rdx+160]
  db $66, $0F, $38, $DC, $8A, $A0, $00, $00, $00   // aesenc xmm1, [rdx+160]
  db $66, $0F, $38, $DC, $92, $A0, $00, $00, $00   // aesenc xmm2, [rdx+160]
  db $66, $0F, $38, $DC, $9A, $A0, $00, $00, $00   // aesenc xmm3, [rdx+160]
  db $66, $0F, $38, $DC, $A2, $A0, $00, $00, $00   // aesenc xmm4, [rdx+160]
  db $66, $0F, $38, $DC, $AA, $A0, $00, $00, $00   // aesenc xmm5, [rdx+160]
  db $66, $0F, $38, $DC, $B2, $A0, $00, $00, $00   // aesenc xmm6, [rdx+160]
  db $66, $0F, $38, $DC, $BA, $A0, $00, $00, $00   // aesenc xmm7, [rdx+160]
  db $66, $0F, $38, $DC, $82, $B0, $00, $00, $00   // aesenc xmm0, [rdx+176]
  db $66, $0F, $38, $DC, $8A, $B0, $00, $00, $00   // aesenc xmm1, [rdx+176]
  db $66, $0F, $38, $DC, $92, $B0, $00, $00, $00   // aesenc xmm2, [rdx+176]
  db $66, $0F, $38, $DC, $9A, $B0, $00, $00, $00   // aesenc xmm3, [rdx+176]
  db $66, $0F, $38, $DC, $A2, $B0, $00, $00, $00   // aesenc xmm4, [rdx+176]
  db $66, $0F, $38, $DC, $AA, $B0, $00, $00, $00   // aesenc xmm5, [rdx+176]
  db $66, $0F, $38, $DC, $B2, $B0, $00, $00, $00   // aesenc xmm6, [rdx+176]
  db $66, $0F, $38, $DC, $BA, $B0, $00, $00, $00   // aesenc xmm7, [rdx+176]
{$IFEND}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  db $66, $0F, $38, $DC, $82, $C0, $00, $00, $00   // aesenc xmm0, [rdx+192]
  db $66, $0F, $38, $DC, $8A, $C0, $00, $00, $00   // aesenc xmm1, [rdx+192]
  db $66, $0F, $38, $DC, $92, $C0, $00, $00, $00   // aesenc xmm2, [rdx+192]
  db $66, $0F, $38, $DC, $9A, $C0, $00, $00, $00   // aesenc xmm3, [rdx+192]
  db $66, $0F, $38, $DC, $A2, $C0, $00, $00, $00   // aesenc xmm4, [rdx+192]
  db $66, $0F, $38, $DC, $AA, $C0, $00, $00, $00   // aesenc xmm5, [rdx+192]
  db $66, $0F, $38, $DC, $B2, $C0, $00, $00, $00   // aesenc xmm6, [rdx+192]
  db $66, $0F, $38, $DC, $BA, $C0, $00, $00, $00   // aesenc xmm7, [rdx+192]
  db $66, $0F, $38, $DC, $82, $D0, $00, $00, $00   // aesenc xmm0, [rdx+208]
  db $66, $0F, $38, $DC, $8A, $D0, $00, $00, $00   // aesenc xmm1, [rdx+208]
  db $66, $0F, $38, $DC, $92, $D0, $00, $00, $00   // aesenc xmm2, [rdx+208]
  db $66, $0F, $38, $DC, $9A, $D0, $00, $00, $00   // aesenc xmm3, [rdx+208]
  db $66, $0F, $38, $DC, $A2, $D0, $00, $00, $00   // aesenc xmm4, [rdx+208]
  db $66, $0F, $38, $DC, $AA, $D0, $00, $00, $00   // aesenc xmm5, [rdx+208]
  db $66, $0F, $38, $DC, $B2, $D0, $00, $00, $00   // aesenc xmm6, [rdx+208]
  db $66, $0F, $38, $DC, $BA, $D0, $00, $00, $00   // aesenc xmm7, [rdx+208]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  db $66, $0F, $38, $DD, $82, $A0, $00, $00, $00   // aesenclast xmm0, [rdx+160]
  db $66, $0F, $38, $DD, $8A, $A0, $00, $00, $00   // aesenclast xmm1, [rdx+160]
  db $66, $0F, $38, $DD, $92, $A0, $00, $00, $00   // aesenclast xmm2, [rdx+160]
  db $66, $0F, $38, $DD, $9A, $A0, $00, $00, $00   // aesenclast xmm3, [rdx+160]
  db $66, $0F, $38, $DD, $A2, $A0, $00, $00, $00   // aesenclast xmm4, [rdx+160]
  db $66, $0F, $38, $DD, $AA, $A0, $00, $00, $00   // aesenclast xmm5, [rdx+160]
  db $66, $0F, $38, $DD, $B2, $A0, $00, $00, $00   // aesenclast xmm6, [rdx+160]
  db $66, $0F, $38, $DD, $BA, $A0, $00, $00, $00   // aesenclast xmm7, [rdx+160]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_12}
  db $66, $0F, $38, $DD, $82, $C0, $00, $00, $00   // aesenclast xmm0, [rdx+192]
  db $66, $0F, $38, $DD, $8A, $C0, $00, $00, $00   // aesenclast xmm1, [rdx+192]
  db $66, $0F, $38, $DD, $92, $C0, $00, $00, $00   // aesenclast xmm2, [rdx+192]
  db $66, $0F, $38, $DD, $9A, $C0, $00, $00, $00   // aesenclast xmm3, [rdx+192]
  db $66, $0F, $38, $DD, $A2, $C0, $00, $00, $00   // aesenclast xmm4, [rdx+192]
  db $66, $0F, $38, $DD, $AA, $C0, $00, $00, $00   // aesenclast xmm5, [rdx+192]
  db $66, $0F, $38, $DD, $B2, $C0, $00, $00, $00   // aesenclast xmm6, [rdx+192]
  db $66, $0F, $38, $DD, $BA, $C0, $00, $00, $00   // aesenclast xmm7, [rdx+192]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  db $66, $0F, $38, $DD, $82, $E0, $00, $00, $00   // aesenclast xmm0, [rdx+224]
  db $66, $0F, $38, $DD, $8A, $E0, $00, $00, $00   // aesenclast xmm1, [rdx+224]
  db $66, $0F, $38, $DD, $92, $E0, $00, $00, $00   // aesenclast xmm2, [rdx+224]
  db $66, $0F, $38, $DD, $9A, $E0, $00, $00, $00   // aesenclast xmm3, [rdx+224]
  db $66, $0F, $38, $DD, $A2, $E0, $00, $00, $00   // aesenclast xmm4, [rdx+224]
  db $66, $0F, $38, $DD, $AA, $E0, $00, $00, $00   // aesenclast xmm5, [rdx+224]
  db $66, $0F, $38, $DD, $B2, $E0, $00, $00, $00   // aesenclast xmm6, [rdx+224]
  db $66, $0F, $38, $DD, $BA, $E0, $00, $00, $00   // aesenclast xmm7, [rdx+224]
{$ENDIF}

  // --- Post-AES: XOR keystream with PXorIn, store to POut. ---
  movdqu    xmm8, [rsi]
  db $66, $41, $0F, $EF, $C0                    // pxor xmm0, xmm8
  movdqu    [rdi], xmm0
  movdqu    xmm8, [rsi + 16]
  db $66, $41, $0F, $EF, $C8                    // pxor xmm1, xmm8
  movdqu    [rdi + 16], xmm1
  movdqu    xmm8, [rsi + 32]
  db $66, $41, $0F, $EF, $D0                    // pxor xmm2, xmm8
  movdqu    [rdi + 32], xmm2
  movdqu    xmm8, [rsi + 48]
  db $66, $41, $0F, $EF, $D8                    // pxor xmm3, xmm8
  movdqu    [rdi + 48], xmm3
  movdqu    xmm8, [rsi + 64]
  db $66, $41, $0F, $EF, $E0                    // pxor xmm4, xmm8
  movdqu    [rdi + 64], xmm4
  movdqu    xmm8, [rsi + 80]
  db $66, $41, $0F, $EF, $E8                    // pxor xmm5, xmm8
  movdqu    [rdi + 80], xmm5
  movdqu    xmm8, [rsi + 96]
  db $66, $41, $0F, $EF, $F0                    // pxor xmm6, xmm8
  movdqu    [rdi + 96], xmm6
  movdqu    xmm8, [rsi + 112]
  db $66, $41, $0F, $EF, $F8                    // pxor xmm7, xmm8
  movdqu    [rdi + 112], xmm7

  // --- Reduce [Z2:Z1:Z0] modulo the field polynomial: fold Z1 into
  //     the 256-bit product, then two carry-less multiplies by the
  //     folded constant 0xC2000000_00000000 (the H powers are
  //     pre-multiplied by x, so no bit-shift correction is needed). ---
  movdqa    xmm0, xmm9                         // Z0
  movdqa    xmm1, xmm10                        // Z1
  movdqa    xmm2, xmm11                        // Z2
  movdqa    xmm3, [rsp]
  movdqa    xmm4, xmm1
  pslldq    xmm4, 8
  pxor      xmm0, xmm4                         // ZLo ^= Z1 << 64
  movdqa    xmm5, xmm1
  psrldq    xmm5, 8
  pxor      xmm2, xmm5                         // ZHi ^= Z1 >> 64
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E3, $00               // pclmulqdq xmm4, xmm3, 0x00
  db $66, $0F, $70, $C0, $4E                    // pshufd xmm0, xmm0, 0x4E (swap halves)
  pxor      xmm0, xmm4                         // fold 1
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E3, $00               // pclmulqdq xmm4, xmm3, 0x00
  db $66, $0F, $70, $C0, $4E                    // pshufd xmm0, xmm0, 0x4E (swap halves)
  pxor      xmm0, xmm4                         // fold 2
  pxor      xmm0, xmm2                         // ^= ZHi -> reflected state
  movdqa    xmm9, xmm0                         // carry state to the next batch

  // --- Advance for the next batch: PPrevCipher becomes this batch's
  //     ciphertext (output on encrypt, input on decrypt). ---
  mov       r10, rdi
  test      ebp, ebp                            // GHASH-from-output flag
  jnz       @@GcmPrevSet
  mov       r10, rsi                            // decrypt: prev = input
@@GcmPrevSet:
  add       rsi, 128
  add       rdi, 128
  add       r8d, 8
  dec       rbx
  jnz       @@GcmFusedLoop

  // --- Epilogue: canonicalize the state, store counter + PFS, unwind. ---
  mov       [rcx + 56], r8d                     // store advanced counter32
  pshufb    xmm9, xmm15                         // reflected -> canonical
  mov       rax, [rcx + 40]                     // PFS
  movdqu    [rax], xmm9
  add       rsp, 152
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
  pop       rbp
  pop       rdi
  pop       rsi
  pop       rbx

