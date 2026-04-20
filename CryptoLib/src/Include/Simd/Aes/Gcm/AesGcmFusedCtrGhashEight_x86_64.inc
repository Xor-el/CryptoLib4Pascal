// Fused AES-NI CTR keystream + 8-way GHASH kernel (x86-64).
//
// Processes one pipelined batch: AES encrypts eight counter blocks to produce
// a keystream, XORs it with PXorIn (plaintext on GCM encrypt, ciphertext on
// GCM decrypt) to produce the current batch's POut, and CONCURRENTLY GHASHes
// the PREVIOUS batch's ciphertext into the running authentication state.
// AES inside GCM is always CTR keystream construction regardless of GCM
// direction -- nothing in the kernel branches on encrypt vs decrypt; the
// Pascal wrapper just picks which buffers become PXorIn / POut / PPrevCipher.
//
// This is the Gueron-style interleaved kernel: aesenc instructions (which run
// on port 0 on Skylake+/Zen+) are issued alternating with pclmulqdq
// instructions (which run on port 5) so the two execution ports operate in
// parallel, hiding most of the GHASH latency inside the AES critical path.
//
// Variant selection (set EXACTLY ONE of these defines before {$I}-including):
//   GCM_FUSED_AES_ROUNDS_10  -> AES-128 (10 rounds, schedule = 11 x 16 bytes)
//   GCM_FUSED_AES_ROUNDS_12  -> AES-192 (12 rounds, schedule = 13 x 16 bytes)
//   GCM_FUSED_AES_ROUNDS_14  -> AES-256 (14 rounds, schedule = 15 x 16 bytes)
// Common code (rounds 0..8 with all 8 GHASH iters, post-AES XOR/store, inline
// 3-limb GHASH reduction, epilogue) is shared verbatim. Only rounds 9..N-1
// (extra aesenc) and round N (aesenclast on rk[N]) are conditional on the
// round count.
//
// After SimdProc1Begin_x86_64.inc: rcx = PCtx (TGcmFusedBatchCtx pointer).
// Ctx layout (all Pointer, natural 8-byte alignment, no padding):
//   [rcx+  0] PXorIn      : 128-byte input to XOR with keystream
//                           (plaintext on GCM encrypt, ciphertext on GCM decrypt)
//   [rcx+  8] POut        : 128-byte output buffer
//                           (ciphertext on GCM encrypt, plaintext on GCM decrypt)
//   [rcx+ 16] PCtrCurr    : 8 counter blocks (128 bytes) to AES-encrypt
//   [rcx+ 24] PPrevCipher : 128 bytes previous batch's ciphertext for GHASH
//                           (taken from the OUTPUT buffer on GCM encrypt, from
//                            the INPUT buffer on GCM decrypt)
//   [rcx+ 32] PRoundKeys  : AES encrypt round-key schedule
//                           (176 / 208 / 240 bytes for AES-128 / 192 / 256)
//   [rcx+ 40] PHPow128    : H^8..H^1 as eight 16-byte limbs, field form
//   [rcx+ 48] PFS         : 16-byte running GHASH state (in/out, canonical)
//   [rcx+ 56] PMask       : 16-byte PSHUFB byte-reverse mask
//
// XMM register allocation (15 of 16 XMM registers used):
//   xmm0..xmm7  : 8 AES counter -> keystream blocks (persist across rounds)
//   xmm8        : current AES round key (reloaded per round)
//   xmm9..xmm11 : Z0, Z1, Z2 GHASH accumulators (persist across all 8 iters)
//   xmm12       : GHASH input block (byte-reversed, loaded per iter)
//   xmm13       : current H-power limb  (loaded per iter)
//   xmm14       : pclmul scratch destination (reused every product)
//   xmm15       : byte-reverse mask (held for the entire kernel)
//
// GPR usage (all MS x64 / SysV-volatile regs; no non-volatile saves needed):
//   rcx : PCtx (preserved across the whole kernel)
//   rax : scratch (pointer loads / byte-reverse state fold)
//   rdx : PRoundKeys (during AES phase), then POut (post-AES)
//   r10 : PPrevCipher
//   r11 : PHPow128
//
// Interleave schedule:
//   Round 0     : AddRoundKey + init Z0/Z1/Z2
//   Rounds 1..8 : one aesenc combined with one full GHASH iteration
//                 (block i = r-1, using H^(8-i) from the H-power table).
//                 Round 1 additionally folds the running state into block 0.
//   Rounds 9..N-1 (variant): aesenc only (no GHASH work remaining).
//   Round N     : aesenclast (final AES round; N = 10 / 12 / 14).
//   Post-AES    : XOR keystream with PXorIn, store to POut.
//   Finalize    : inline 3-limb GHASH reduction on Z0/Z1/Z2 (fold Z1 into
//                 Z0/Z2, then reduce modulo x^128 + x^7 + x^2 + x + 1),
//                 byte-reverse, store to PFS.
//
// AES-NI (aesenc/aesenclast) and PCLMULQDQ instructions whose operands
// reference extended XMM registers (xmm8..xmm15) are db-encoded for broad
// assembler compatibility; a trailing comment shows the mnemonic.
//
// -------------------------------------------------------------------------

  // --- Prologue: load pointers and initial state -----------------------
  mov       rax, [rcx + 16]                    // rax = PCtrCurr
  movdqu    xmm0, [rax]
  movdqu    xmm1, [rax + 16]
  movdqu    xmm2, [rax + 32]
  movdqu    xmm3, [rax + 48]
  movdqu    xmm4, [rax + 64]
  movdqu    xmm5, [rax + 80]
  movdqu    xmm6, [rax + 96]
  movdqu    xmm7, [rax + 112]

  mov       rax, [rcx + 56]                    // rax = PMask
  movdqu    xmm15, [rax]                       // xmm15 = byte-reverse mask

  mov       rdx, [rcx + 32]                    // rdx = PRoundKeys
  mov       r10, [rcx + 24]                    // r10 = PPrevCipher
  mov       r11, [rcx + 40]                    // r11 = PHPow128

  // --- Round 0: AddRoundKey + zero Z0/Z1/Z2 ----------------------------
  movdqa    xmm8, [rdx]                        // rk[0]
  db $66, $41, $0F, $EF, $C0                   // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8                   // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0                   // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8                   // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0                   // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8                   // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0                   // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8                   // pxor xmm7, xmm8
  db $66, $45, $0F, $EF, $C9                   // pxor xmm9, xmm9     (Z0=0)
  db $66, $45, $0F, $EF, $D2                   // pxor xmm10, xmm10   (Z1=0)
  db $66, $45, $0F, $EF, $DB                   // pxor xmm11, xmm11   (Z2=0)

  // --- Round 1 + GHASH iter 0 (with state fold) ------------------------
  movdqa    xmm8, [rdx + 16]                   // rk[1]

  // GHASH iter 0 setup: load block 0, byte-reverse, fold running state
  movdqu    xmm12, [r10]                       // prev cipher block 0
  pshufb    xmm12, xmm15                       // byte-reverse
  mov       rax, [rcx + 48]                    // rax = PFS
  movdqu    xmm14, [rax]                       // load running state
  pshufb    xmm14, xmm15                       // byte-reverse state
  db $66, $45, $0F, $EF, $E6                   // pxor xmm12, xmm14 (fold)
  movdqu    xmm13, [r11]                       // H^8

  // Interleave 8 aesenc with 4 pclmul + 4 xor-accumulate
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14   (Z0+=)
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14  (Z1+=)
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14  (Z1+=)
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14  (Z2+=)

  // --- Round 2 + GHASH iter 1 ------------------------------------------
  movdqa    xmm8, [rdx + 32]                   // rk[2]
  movdqu    xmm12, [r10 + 16]                  // prev cipher block 1
  pshufb    xmm12, xmm15
  movdqu    xmm13, [r11 + 16]                  // H^7

  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14

  // --- Round 3 + GHASH iter 2 ------------------------------------------
  movdqa    xmm8, [rdx + 48]                   // rk[3]
  movdqu    xmm12, [r10 + 32]                  // prev cipher block 2
  pshufb    xmm12, xmm15
  movdqu    xmm13, [r11 + 32]                  // H^6

  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14

  // --- Round 4 + GHASH iter 3 ------------------------------------------
  movdqa    xmm8, [rdx + 64]                   // rk[4]
  movdqu    xmm12, [r10 + 48]                  // prev cipher block 3
  pshufb    xmm12, xmm15
  movdqu    xmm13, [r11 + 48]                  // H^5

  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14

  // --- Round 5 + GHASH iter 4 ------------------------------------------
  movdqa    xmm8, [rdx + 80]                   // rk[5]
  movdqu    xmm12, [r10 + 64]                  // prev cipher block 4
  pshufb    xmm12, xmm15
  movdqu    xmm13, [r11 + 64]                  // H^4

  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14

  // --- Round 6 + GHASH iter 5 ------------------------------------------
  movdqa    xmm8, [rdx + 96]                   // rk[6]
  movdqu    xmm12, [r10 + 80]                  // prev cipher block 5
  pshufb    xmm12, xmm15
  movdqu    xmm13, [r11 + 80]                  // H^3

  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14

  // --- Round 7 + GHASH iter 6 ------------------------------------------
  movdqa    xmm8, [rdx + 112]                  // rk[7]
  movdqu    xmm12, [r10 + 96]                  // prev cipher block 6
  pshufb    xmm12, xmm15
  movdqu    xmm13, [r11 + 96]                  // H^2

  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14

  // --- Round 8 + GHASH iter 7 (last GHASH) -----------------------------
  movdqa    xmm8, [rdx + 128]                  // rk[8]
  movdqu    xmm12, [r10 + 112]                 // prev cipher block 7
  pshufb    xmm12, xmm15
  movdqu    xmm13, [r11 + 112]                 // H^1

  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $00         // pclmulqdq xmm14,xmm13,0
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $45, $0F, $EF, $CE                   // pxor xmm9, xmm14
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $01         // pclmulqdq xmm14,xmm13,1
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $10         // pclmulqdq xmm14,xmm13,16
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $45, $0F, $EF, $D6                   // pxor xmm10, xmm14
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  movdqa    xmm14, xmm12
  db $66, $45, $0F, $3A, $44, $F5, $11         // pclmulqdq xmm14,xmm13,17
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
  db $66, $45, $0F, $EF, $DE                   // pxor xmm11, xmm14

  // --- Variant-specific tail: aesenc rounds 9..Nr-1, then aesenclast ---
  // AES-128 (Nr=10): aesenc rk[9];           aesenclast on rk[10] (offset 160).
  // AES-192 (Nr=12): aesenc rk[9..11];       aesenclast on rk[12] (offset 192).
  // AES-256 (Nr=14): aesenc rk[9..13];       aesenclast on rk[14] (offset 224).
  // All three variants consume rk[9] (offset 144) as their first tail key.

{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  movdqa    xmm8, [rdx + 144]                  // rk[9]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
{$ENDIF}

{$IFDEF GCM_FUSED_AES_ROUNDS_12}
  movdqa    xmm8, [rdx + 144]                  // rk[9]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8

  movdqa    xmm8, [rdx + 160]                  // rk[10]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8

  movdqa    xmm8, [rdx + 176]                  // rk[11]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
{$ENDIF}

{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  movdqa    xmm8, [rdx + 144]                  // rk[9]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8

  movdqa    xmm8, [rdx + 160]                  // rk[10]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8

  movdqa    xmm8, [rdx + 176]                  // rk[11]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8

  movdqa    xmm8, [rdx + 192]                  // rk[12]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8

  movdqa    xmm8, [rdx + 208]                  // rk[13]
  db $66, $41, $0F, $38, $DC, $C0              // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8              // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0              // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8              // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0              // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8              // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0              // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8              // aesenc xmm7, xmm8
{$ENDIF}

  // --- Final AES round: aesenclast on rk[Nr] ---------------------------
{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  movdqa    xmm8, [rdx + 160]                  // rk[10] (last for AES-128)
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_12}
  movdqa    xmm8, [rdx + 192]                  // rk[12] (last for AES-192)
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  movdqa    xmm8, [rdx + 224]                  // rk[14] (last for AES-256)
{$ENDIF}
  db $66, $41, $0F, $38, $DD, $C0              // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8              // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0              // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8              // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0              // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8              // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0              // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8              // aesenclast xmm7, xmm8

  // --- Post-AES: XOR keystream with PXorIn, store to POut --------------
  mov       rax, [rcx + 0]                     // rax = PXorIn
  mov       rdx, [rcx + 8]                     // rdx = POut  (was PRoundKeys; no longer needed)

  movdqu    xmm8, [rax]
  db $66, $41, $0F, $EF, $C0                   // pxor xmm0, xmm8
  movdqu    [rdx], xmm0
  movdqu    xmm8, [rax + 16]
  db $66, $41, $0F, $EF, $C8                   // pxor xmm1, xmm8
  movdqu    [rdx + 16], xmm1
  movdqu    xmm8, [rax + 32]
  db $66, $41, $0F, $EF, $D0                   // pxor xmm2, xmm8
  movdqu    [rdx + 32], xmm2
  movdqu    xmm8, [rax + 48]
  db $66, $41, $0F, $EF, $D8                   // pxor xmm3, xmm8
  movdqu    [rdx + 48], xmm3
  movdqu    xmm8, [rax + 64]
  db $66, $41, $0F, $EF, $E0                   // pxor xmm4, xmm8
  movdqu    [rdx + 64], xmm4
  movdqu    xmm8, [rax + 80]
  db $66, $41, $0F, $EF, $E8                   // pxor xmm5, xmm8
  movdqu    [rdx + 80], xmm5
  movdqu    xmm8, [rax + 96]
  db $66, $41, $0F, $EF, $F0                   // pxor xmm6, xmm8
  movdqu    [rdx + 96], xmm6
  movdqu    xmm8, [rax + 112]
  db $66, $41, $0F, $EF, $F8                   // pxor xmm7, xmm8
  movdqu    [rdx + 112], xmm7

  // --- Inline 3-limb GHASH reduction on Z0 (xmm9), Z1 (xmm10), Z2 (xmm11):
  // fold Z1 into (Z0, Z2), then reduce modulo x^128 + x^7 + x^2 + x + 1. ---
  // Migrate to xmm0/xmm1/xmm2 to mirror GcmReduce3FoldSse2 layout so the
  // scalar shift/XOR sequence below reuses xmm0..xmm7 as scratch freely.
  movdqa    xmm0, xmm9                         // xmm0 = Z0
  movdqa    xmm1, xmm10                        // xmm1 = Z1
  movdqa    xmm2, xmm11                        // xmm2 = Z2

  // Fold Z1 into Z0/Z2
  movdqa    xmm4, xmm1
  movdqa    xmm5, xmm1
  pslldq    xmm4, 8
  psrldq    xmm5, 8
  pxor      xmm0, xmm4                         // Z0 ^= (Z1 << 64)
  pxor      xmm2, xmm5                         // Z2 ^= (Z1 >> 64)

  // Extract T3, T1 (low 64s); T2, T0 (upper 64s).
  movq      xmm3, xmm0                         // T3 = low64(Z0 folded)
  movq      xmm4, xmm2                         // T1 = low64(Z2 folded)
  movdqa    xmm5, xmm3
  psrlq     xmm5, 1
  movdqa    xmm6, xmm3
  psrlq     xmm6, 2
  movdqa    xmm7, xmm3
  psrlq     xmm7, 7
  pxor      xmm4, xmm3
  pxor      xmm4, xmm5
  pxor      xmm4, xmm6
  pxor      xmm4, xmm7                         // T1 ^ T3 ^ (T3>>1)^(>>2)^(>>7)

  movdqa    xmm1, xmm0
  psrldq    xmm1, 8                            // T2 = upper64(Z0 folded)
  movdqa    xmm5, xmm3
  psllq     xmm5, 63
  movdqa    xmm6, xmm3
  psllq     xmm6, 62
  movdqa    xmm7, xmm3
  psllq     xmm7, 57
  pxor      xmm1, xmm5
  pxor      xmm1, xmm6
  pxor      xmm1, xmm7                         // T2 ^ (T3<<63)^(<<62)^(<<57)

  movdqa    xmm5, xmm2
  psrldq    xmm5, 8                            // T0 = upper64(Z2 folded)
  movdqa    xmm6, xmm5
  psllq     xmm6, 1
  movdqa    xmm7, xmm4
  psrlq     xmm7, 63
  por       xmm6, xmm7                         // LZ0 init = (T0<<1)|(T1>>63)

  movdqa    xmm7, xmm4
  psllq     xmm7, 1
  movdqa    xmm3, xmm1
  psrlq     xmm3, 63
  por       xmm7, xmm3                         // LZ1 init = (T1<<1)|(T2>>63)

  movdqa    xmm0, xmm1
  psllq     xmm0, 1                            // LZ2 = T2<<1

  movdqa    xmm3, xmm0
  psrlq     xmm3, 1
  movdqa    xmm2, xmm0
  psrlq     xmm2, 2
  movdqa    xmm5, xmm0
  psrlq     xmm5, 7
  pxor      xmm6, xmm0
  pxor      xmm6, xmm3
  pxor      xmm6, xmm2
  pxor      xmm6, xmm5                         // xmm6.low = final LZ0

  movdqa    xmm3, xmm1
  psllq     xmm3, 63
  movdqa    xmm2, xmm1
  psllq     xmm2, 58
  pxor      xmm7, xmm3
  pxor      xmm7, xmm2                         // xmm7.low = final LZ1

  // Pack and byte-reverse final GHASH state; store to PFS.
  movq      xmm0, xmm7
  pslldq    xmm6, 8
  por       xmm0, xmm6                         // xmm0 = [LZ0 | LZ1]
  pshufb    xmm0, xmm15                        // byte-reverse -> canonical
  mov       rax, [rcx + 48]                    // PFS
  movdqu    [rax], xmm0
