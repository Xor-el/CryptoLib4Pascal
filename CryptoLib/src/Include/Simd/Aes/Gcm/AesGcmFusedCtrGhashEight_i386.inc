// Fused AES-NI CTR keystream + 8-way GHASH kernel (i386).
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
// The 8-xmm budget does not fit a single-pass 8-wide layout, so the body
// processes the batch as two back-to-back 4-block halves sharing the same
// Z0/Z1/Z2 accumulator slots; each half packs 4 GHASH iters into AES
// rounds 1..4, rounds 5..N-1 are AES-only, and the reduction runs once
// after half 2. Only 4 counter blocks are live per half, so each half
// builds its four in-register right before that half runs.
//
// On entry (after ClpSimdProc1Begin_i386.inc): ebx = PCtx.
// Context layout (TGcmFusedCtx in ClpAesNiGcmKernel.pas; 4-byte fields):
//   [ebx +  0]  PXorIn    [ebx +  4]  POut       [ebx +  8]  PPrevCipher
//   [ebx + 12]  PRoundKeys (16-byte aligned)     [ebx + 16]  PHPow128
//   [ebx + 20]  PFS       [ebx + 24]  PMask      [ebx + 28]  Counter32
//   [ebx + 32]  PJ0Template                      [ebx + 36]  BatchCount
//   [ebx + 40]  GhashFromOutput (1 = encrypt)
//
// GPR: ebx=PCtx, edi=Keys (pinned), ebp=HPow (pinned), esi=PPrevCipher
//   (rotates per batch), ecx=counter32 (in-register across the call),
//   eax/edx=scratch.
//
// XMM: xmm0..xmm3 = 4 AES keystream lanes (per half); xmm4 = GHASH block;
//   xmm5 = H-power limb; xmm6/xmm7 = pclmul product scratch.
//
// Stack scratch (base 16-aligned; caller esp parked inside):
//   [esp +  0]  Z0   [esp + 16]  Z1   [esp + 32]  Z2   (movdqa)
//   [esp + 48]  reflected running state (carried across batches)
//   [esp + 64]  byte-reverse mask copy (PSHUFB memory operand)
//   [esp + 80]  reduction constant     [esp + 96]  parked caller esp
//
// AES-NI (aesenc / aesenclast), PCLMULQDQ, PINSRD, PSHUFD and the
// PSHUFB memory-operand form are db-encoded for broad assembler
// compatibility.
// -------------------------------------------------------------------

  // --- Callee-save prologue (ClpSimdProc1Begin_i386.inc already pushed
  //     ebx); park the caller esp inside the 16-aligned frame. ---
  push      edi
  push      esi
  push      ebp
  mov       eax, esp
  sub       esp, 120
  and       esp, -16                            // align the frame
  mov       [esp + 96], eax                     // park the caller esp

  // --- Frame constants: reduction constant, mask copy, reflected state. ---
  mov       dword ptr [esp + 80], 0
  mov       dword ptr [esp + 84], $C2000000
  mov       dword ptr [esp + 88], 0
  mov       dword ptr [esp + 92], 0
  mov       eax, [ebx + 24]                     // PMask
  movdqu    xmm0, [eax]
  movdqa    [esp + 64], xmm0
  mov       eax, [ebx + 20]                     // PFS
  movdqu    xmm1, [eax]
  pshufb    xmm1, xmm0                          // canonical -> reflected
  movdqa    [esp + 48], xmm1

  // --- Pinned loop registers. ---
  mov       edi, [ebx + 12]                     // edi = PRoundKeys (aligned)
  mov       ebp, [ebx + 16]                     // ebp = PHPow128 (x-shifted)
  mov       esi, [ebx + 8]                      // esi = PPrevCipher
  mov       ecx, [ebx + 28]                     // ecx = counter32

@@GcmFusedLoop:
  // --- Zero the Z accumulator slots. ---
  pxor      xmm0, xmm0
  movdqa    [esp + 0], xmm0                    // Z0 = 0
  movdqa    [esp + 16], xmm0                   // Z1 = 0
  movdqa    [esp + 32], xmm0                   // Z2 = 0

  // --- Build 4 counter blocks for HALF 1 (blocks 0..3): J0[0..11] ||
  //     BE(counter32+1..+4); the counter holds the last-used value. ---
  mov       eax, [ebx + 32]                     // PJ0Template
  movdqu    xmm0, [eax]
  movdqu    xmm1, [eax]
  movdqu    xmm2, [eax]
  movdqu    xmm3, [eax]
  lea       edx, [ecx + 1]
  bswap     edx
  db $66, $0F, $3A, $22, $C2, $03               // pinsrd xmm0, edx, 3
  lea       edx, [ecx + 2]
  bswap     edx
  db $66, $0F, $3A, $22, $CA, $03               // pinsrd xmm1, edx, 3
  lea       edx, [ecx + 3]
  bswap     edx
  db $66, $0F, $3A, $22, $D2, $03               // pinsrd xmm2, edx, 3
  lea       edx, [ecx + 4]
  bswap     edx
  db $66, $0F, $3A, $22, $DA, $03               // pinsrd xmm3, edx, 3

  // ======================================================================
  // HALF 1: blocks 0..3, GHASH iters 0..3 (prev_cipher[0..3], H^8..H^5);
  //         iter 0 additionally folds the carried reflected state.
  // ======================================================================

  // --- Round 0: AddRoundKey (aligned key memory operands). ---
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]

  // --- Round 1 + GHASH iter 0 (with carried-state fold). ---
  db $66, $0F, $38, $DC, $47, $10               // aesenc xmm0, [edi+0x10]
  db $66, $0F, $38, $DC, $4F, $10               // aesenc xmm1, [edi+0x10]
  db $66, $0F, $38, $DC, $57, $10               // aesenc xmm2, [edi+0x10]
  db $66, $0F, $38, $DC, $5F, $10               // aesenc xmm3, [edi+0x10]

  movdqu    xmm4, [esi + 0]                   // prev cipher block 0
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  pxor      xmm4, [esp + 48]                  // fold carried state
  movdqu    xmm5, [ebp + 0]                   // H^8 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Round 2 + GHASH iter 1. ---
  db $66, $0F, $38, $DC, $47, $20               // aesenc xmm0, [edi+0x20]
  db $66, $0F, $38, $DC, $4F, $20               // aesenc xmm1, [edi+0x20]
  db $66, $0F, $38, $DC, $57, $20               // aesenc xmm2, [edi+0x20]
  db $66, $0F, $38, $DC, $5F, $20               // aesenc xmm3, [edi+0x20]

  movdqu    xmm4, [esi + 16]                   // prev cipher block 1
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  movdqu    xmm5, [ebp + 16]                   // H^7 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Round 3 + GHASH iter 2. ---
  db $66, $0F, $38, $DC, $47, $30               // aesenc xmm0, [edi+0x30]
  db $66, $0F, $38, $DC, $4F, $30               // aesenc xmm1, [edi+0x30]
  db $66, $0F, $38, $DC, $57, $30               // aesenc xmm2, [edi+0x30]
  db $66, $0F, $38, $DC, $5F, $30               // aesenc xmm3, [edi+0x30]

  movdqu    xmm4, [esi + 32]                   // prev cipher block 2
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  movdqu    xmm5, [ebp + 32]                   // H^6 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Round 4 + GHASH iter 3. ---
  db $66, $0F, $38, $DC, $47, $40               // aesenc xmm0, [edi+0x40]
  db $66, $0F, $38, $DC, $4F, $40               // aesenc xmm1, [edi+0x40]
  db $66, $0F, $38, $DC, $57, $40               // aesenc xmm2, [edi+0x40]
  db $66, $0F, $38, $DC, $5F, $40               // aesenc xmm3, [edi+0x40]

  movdqu    xmm4, [esi + 48]                   // prev cipher block 3
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  movdqu    xmm5, [ebp + 48]                   // H^5 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Rounds 5..Nr-1 (variant-specific): AES-only. ---
  // Round 5
  db $66, $0F, $38, $DC, $47, $50               // aesenc xmm0, [edi+0x50]
  db $66, $0F, $38, $DC, $4F, $50               // aesenc xmm1, [edi+0x50]
  db $66, $0F, $38, $DC, $57, $50               // aesenc xmm2, [edi+0x50]
  db $66, $0F, $38, $DC, $5F, $50               // aesenc xmm3, [edi+0x50]
  // Round 6
  db $66, $0F, $38, $DC, $47, $60               // aesenc xmm0, [edi+0x60]
  db $66, $0F, $38, $DC, $4F, $60               // aesenc xmm1, [edi+0x60]
  db $66, $0F, $38, $DC, $57, $60               // aesenc xmm2, [edi+0x60]
  db $66, $0F, $38, $DC, $5F, $60               // aesenc xmm3, [edi+0x60]
  // Round 7
  db $66, $0F, $38, $DC, $47, $70               // aesenc xmm0, [edi+0x70]
  db $66, $0F, $38, $DC, $4F, $70               // aesenc xmm1, [edi+0x70]
  db $66, $0F, $38, $DC, $57, $70               // aesenc xmm2, [edi+0x70]
  db $66, $0F, $38, $DC, $5F, $70               // aesenc xmm3, [edi+0x70]
  // Round 8
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+0x80]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00   // aesenc xmm1, [edi+0x80]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00   // aesenc xmm2, [edi+0x80]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00   // aesenc xmm3, [edi+0x80]
  // Round 9
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+0x90]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00   // aesenc xmm1, [edi+0x90]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00   // aesenc xmm2, [edi+0x90]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00   // aesenc xmm3, [edi+0x90]
{$IF DEFINED(GCM_FUSED_AES_ROUNDS_12) OR DEFINED(GCM_FUSED_AES_ROUNDS_14)}
  // Round 10
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+0xA0]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00   // aesenc xmm1, [edi+0xA0]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00   // aesenc xmm2, [edi+0xA0]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00   // aesenc xmm3, [edi+0xA0]
  // Round 11
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+0xB0]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00   // aesenc xmm1, [edi+0xB0]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00   // aesenc xmm2, [edi+0xB0]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00   // aesenc xmm3, [edi+0xB0]
{$IFEND}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  // Round 12
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+0xC0]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00   // aesenc xmm1, [edi+0xC0]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00   // aesenc xmm2, [edi+0xC0]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00   // aesenc xmm3, [edi+0xC0]
  // Round 13
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+0xD0]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00   // aesenc xmm1, [edi+0xD0]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00   // aesenc xmm2, [edi+0xD0]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00   // aesenc xmm3, [edi+0xD0]
{$ENDIF}

  // --- Final AES round (aesenclast on rk[Nr]). ---
{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+0xA0]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00   // aesenclast xmm1, [edi+0xA0]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00   // aesenclast xmm2, [edi+0xA0]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00   // aesenclast xmm3, [edi+0xA0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_12}
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+0xC0]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00   // aesenclast xmm1, [edi+0xC0]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00   // aesenclast xmm2, [edi+0xC0]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00   // aesenclast xmm3, [edi+0xC0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+0xE0]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00   // aesenclast xmm1, [edi+0xE0]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00   // aesenclast xmm2, [edi+0xE0]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00   // aesenclast xmm3, [edi+0xE0]
{$ENDIF}

  // --- Post-AES (half 1): XOR with PXorIn[0..48], store POut. ---
  mov       eax, [ebx + 0]                      // eax = PXorIn
  mov       edx, [ebx + 4]                      // edx = POut
  movdqu    xmm4, [eax + 0]
  pxor      xmm0, xmm4
  movdqu    [edx + 0], xmm0
  movdqu    xmm4, [eax + 16]
  pxor      xmm1, xmm4
  movdqu    [edx + 16], xmm1
  movdqu    xmm4, [eax + 32]
  pxor      xmm2, xmm4
  movdqu    [edx + 32], xmm2
  movdqu    xmm4, [eax + 48]
  pxor      xmm3, xmm4
  movdqu    [edx + 48], xmm3

  // --- Build 4 counter blocks for HALF 2 (blocks 4..7): counter32+5..+8. ---
  mov       eax, [ebx + 32]                     // PJ0Template
  movdqu    xmm0, [eax]
  movdqu    xmm1, [eax]
  movdqu    xmm2, [eax]
  movdqu    xmm3, [eax]
  lea       edx, [ecx + 5]
  bswap     edx
  db $66, $0F, $3A, $22, $C2, $03               // pinsrd xmm0, edx, 3
  lea       edx, [ecx + 6]
  bswap     edx
  db $66, $0F, $3A, $22, $CA, $03               // pinsrd xmm1, edx, 3
  lea       edx, [ecx + 7]
  bswap     edx
  db $66, $0F, $3A, $22, $D2, $03               // pinsrd xmm2, edx, 3
  lea       edx, [ecx + 8]
  bswap     edx
  db $66, $0F, $3A, $22, $DA, $03               // pinsrd xmm3, edx, 3

  // ======================================================================
  // HALF 2: blocks 4..7, GHASH iters 4..7 (prev_cipher[4..7], H^4..H^1);
  //         no state fold (already consumed by iter 0 of half 1).
  // ======================================================================

  // --- Round 0: AddRoundKey. ---
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]

  // --- Round 1 + GHASH iter 4. ---
  db $66, $0F, $38, $DC, $47, $10               // aesenc xmm0, [edi+0x10]
  db $66, $0F, $38, $DC, $4F, $10               // aesenc xmm1, [edi+0x10]
  db $66, $0F, $38, $DC, $57, $10               // aesenc xmm2, [edi+0x10]
  db $66, $0F, $38, $DC, $5F, $10               // aesenc xmm3, [edi+0x10]

  movdqu    xmm4, [esi + 64]                   // prev cipher block 4
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  movdqu    xmm5, [ebp + 64]                   // H^4 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Round 2 + GHASH iter 5. ---
  db $66, $0F, $38, $DC, $47, $20               // aesenc xmm0, [edi+0x20]
  db $66, $0F, $38, $DC, $4F, $20               // aesenc xmm1, [edi+0x20]
  db $66, $0F, $38, $DC, $57, $20               // aesenc xmm2, [edi+0x20]
  db $66, $0F, $38, $DC, $5F, $20               // aesenc xmm3, [edi+0x20]

  movdqu    xmm4, [esi + 80]                   // prev cipher block 5
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  movdqu    xmm5, [ebp + 80]                   // H^3 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Round 3 + GHASH iter 6. ---
  db $66, $0F, $38, $DC, $47, $30               // aesenc xmm0, [edi+0x30]
  db $66, $0F, $38, $DC, $4F, $30               // aesenc xmm1, [edi+0x30]
  db $66, $0F, $38, $DC, $57, $30               // aesenc xmm2, [edi+0x30]
  db $66, $0F, $38, $DC, $5F, $30               // aesenc xmm3, [edi+0x30]

  movdqu    xmm4, [esi + 96]                   // prev cipher block 6
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  movdqu    xmm5, [ebp + 96]                   // H^2 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Round 4 + GHASH iter 7. ---
  db $66, $0F, $38, $DC, $47, $40               // aesenc xmm0, [edi+0x40]
  db $66, $0F, $38, $DC, $4F, $40               // aesenc xmm1, [edi+0x40]
  db $66, $0F, $38, $DC, $57, $40               // aesenc xmm2, [edi+0x40]
  db $66, $0F, $38, $DC, $5F, $40               // aesenc xmm3, [edi+0x40]

  movdqu    xmm4, [esi + 112]                   // prev cipher block 7
  db $66, $0F, $38, $00, $64, $24, $40          // pshufb xmm4, [esp+64] (byte-reverse)
  movdqu    xmm5, [ebp + 112]                   // H^1 (x-shifted)

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00               // pclmulqdq xmm6, xmm5, 0x00
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11               // pclmulqdq xmm7, xmm5, 0x11
  pxor      xmm6, [esp + 0]
  movdqa    [esp + 0], xmm6                    // Z0 +=
  pxor      xmm7, [esp + 32]
  movdqa    [esp + 32], xmm7                   // Z2 +=
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01               // pclmulqdq xmm6, xmm5, 0x01
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $10               // pclmulqdq xmm7, xmm5, 0x10
  pxor      xmm6, xmm7                          // both cross products
  pxor      xmm6, [esp + 16]
  movdqa    [esp + 16], xmm6                   // Z1 +=

  // --- Rounds 5..Nr-1 (variant-specific): AES-only. ---
  // Round 5
  db $66, $0F, $38, $DC, $47, $50               // aesenc xmm0, [edi+0x50]
  db $66, $0F, $38, $DC, $4F, $50               // aesenc xmm1, [edi+0x50]
  db $66, $0F, $38, $DC, $57, $50               // aesenc xmm2, [edi+0x50]
  db $66, $0F, $38, $DC, $5F, $50               // aesenc xmm3, [edi+0x50]
  // Round 6
  db $66, $0F, $38, $DC, $47, $60               // aesenc xmm0, [edi+0x60]
  db $66, $0F, $38, $DC, $4F, $60               // aesenc xmm1, [edi+0x60]
  db $66, $0F, $38, $DC, $57, $60               // aesenc xmm2, [edi+0x60]
  db $66, $0F, $38, $DC, $5F, $60               // aesenc xmm3, [edi+0x60]
  // Round 7
  db $66, $0F, $38, $DC, $47, $70               // aesenc xmm0, [edi+0x70]
  db $66, $0F, $38, $DC, $4F, $70               // aesenc xmm1, [edi+0x70]
  db $66, $0F, $38, $DC, $57, $70               // aesenc xmm2, [edi+0x70]
  db $66, $0F, $38, $DC, $5F, $70               // aesenc xmm3, [edi+0x70]
  // Round 8
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+0x80]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00   // aesenc xmm1, [edi+0x80]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00   // aesenc xmm2, [edi+0x80]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00   // aesenc xmm3, [edi+0x80]
  // Round 9
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+0x90]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00   // aesenc xmm1, [edi+0x90]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00   // aesenc xmm2, [edi+0x90]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00   // aesenc xmm3, [edi+0x90]
{$IF DEFINED(GCM_FUSED_AES_ROUNDS_12) OR DEFINED(GCM_FUSED_AES_ROUNDS_14)}
  // Round 10
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+0xA0]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00   // aesenc xmm1, [edi+0xA0]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00   // aesenc xmm2, [edi+0xA0]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00   // aesenc xmm3, [edi+0xA0]
  // Round 11
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+0xB0]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00   // aesenc xmm1, [edi+0xB0]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00   // aesenc xmm2, [edi+0xB0]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00   // aesenc xmm3, [edi+0xB0]
{$IFEND}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  // Round 12
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+0xC0]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00   // aesenc xmm1, [edi+0xC0]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00   // aesenc xmm2, [edi+0xC0]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00   // aesenc xmm3, [edi+0xC0]
  // Round 13
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+0xD0]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00   // aesenc xmm1, [edi+0xD0]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00   // aesenc xmm2, [edi+0xD0]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00   // aesenc xmm3, [edi+0xD0]
{$ENDIF}

  // --- Final AES round (aesenclast on rk[Nr]). ---
{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+0xA0]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00   // aesenclast xmm1, [edi+0xA0]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00   // aesenclast xmm2, [edi+0xA0]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00   // aesenclast xmm3, [edi+0xA0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_12}
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+0xC0]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00   // aesenclast xmm1, [edi+0xC0]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00   // aesenclast xmm2, [edi+0xC0]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00   // aesenclast xmm3, [edi+0xC0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+0xE0]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00   // aesenclast xmm1, [edi+0xE0]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00   // aesenclast xmm2, [edi+0xE0]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00   // aesenclast xmm3, [edi+0xE0]
{$ENDIF}

  // --- Post-AES (half 2): XOR with PXorIn[64..112], store POut. ---
  mov       eax, [ebx + 0]                      // eax = PXorIn
  mov       edx, [ebx + 4]                      // edx = POut
  movdqu    xmm4, [eax + 64]
  pxor      xmm0, xmm4
  movdqu    [edx + 64], xmm0
  movdqu    xmm4, [eax + 80]
  pxor      xmm1, xmm4
  movdqu    [edx + 80], xmm1
  movdqu    xmm4, [eax + 96]
  pxor      xmm2, xmm4
  movdqu    [edx + 96], xmm2
  movdqu    xmm4, [eax + 112]
  pxor      xmm3, xmm4
  movdqu    [edx + 112], xmm3

  // --- Reduce [Z2:Z1:Z0] modulo the field polynomial: fold Z1 into
  //     the 256-bit product, then two carry-less multiplies by the
  //     folded constant 0xC2000000_00000000 (the H powers are
  //     pre-multiplied by x, so no bit-shift correction is needed). ---
  movdqa    xmm0, [esp + 0]                    // Z0
  movdqa    xmm1, [esp + 16]                   // Z1
  movdqa    xmm2, [esp + 32]                   // Z2
  movdqa    xmm3, [esp + 80]
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
  movdqa    [esp + 48], xmm0                   // carry state to the next batch

  // --- Advance for the next batch: PPrevCipher becomes this batch's
  //     ciphertext (output on encrypt, input on decrypt). ---
  mov       esi, [ebx + 4]                      // POut (encrypt: prev = output)
  cmp       dword ptr [ebx + 40], 0             // GHASH-from-output flag
  jne       @@GcmPrevSet
  mov       esi, [ebx + 0]                      // PXorIn (decrypt: prev = input)
@@GcmPrevSet:
  add       dword ptr [ebx + 0], 128            // PXorIn += 128
  add       dword ptr [ebx + 4], 128            // POut   += 128
  add       ecx, 8                              // counter32 += 8
  dec       dword ptr [ebx + 36]                // batch count
  jnz       @@GcmFusedLoop

  // --- Epilogue: store counter, canonicalize + store the state, unwind.
  //     ebx is popped last (ClpSimdProc1Begin_i386.inc pushed it first). ---
  mov       [ebx + 28], ecx                     // store advanced counter32
  movdqa    xmm0, [esp + 48]
  db $66, $0F, $38, $00, $44, $24, $40          // pshufb xmm0, [esp+64] (-> canonical)
  mov       eax, [ebx + 20]                     // PFS
  movdqu    [eax], xmm0

  mov       esp, [esp + 96]
  pop       ebp
  pop       esi
  pop       edi
  pop       ebx

