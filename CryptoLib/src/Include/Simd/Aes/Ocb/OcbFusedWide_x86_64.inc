// OCB fused 8-wide AES-NI kernel (x86_64) with internal amortising loop.
// -------------------------------------------------------------------
// Processes ABlockCount consecutive 16-byte OCB body blocks in chunks of
// 8 blocks (128 bytes) per iteration, matching TAesEngineX86's 8-wide
// pipeline width so the mode layer's offset ladder, checksum fold, and
// kernel dispatch all share a single batch cadence. ABlockCount must be
// a positive multiple of 8 (caller guarantees).
//
// Algorithm identity (encrypt; decrypt is symmetric with AES^-1):
//   C_i = offset_i XOR AES_K(P_i XOR offset_i)
// Implemented non-fused (no AESENCLAST source-fold):
//   state_0   = P_i XOR offset_i XOR K_0      (pre-whitening)
//   state_N-1 = aesenc^(N-1)(state_0)
//   state_N   = aesenclast(state_N-1, K_N)
//   C_i       = state_N XOR offset_i          (post-whitening)
// Dropping the fold frees xmm10..xmm15 and eliminates the per-chunk
// "xmm_{10+i} = offset_i XOR K_N" precomputation that the 6-wide variant
// spent on entry. The cost is one extra pxor per block (reload offsets
// and XOR again after the final round), fully absorbed by the L1 load
// ports that would otherwise idle beside the AES pipe.
//
// On entry (after SimdProc1Begin_x86_64.inc): rcx = PCtx.
//
// Context layout (4 pointers + 1 NativeUInt count = 40 bytes, natural
// 8-byte alignment, no padding). See TOcbFusedWideCtx in
// ClpAesNiOcbKernel.pas.
//   [rcx +  0]  Keys       : AES expanded schedule (encrypt for
//                            OcbFusedEncWide*; inverse-MixColumns for
//                            OcbFusedDecWide*). 176 / 208 / 240 bytes,
//                            16-byte aligned.
//   [rcx +  8]  InPtr      : base of ABlockCount consecutive 16-byte
//                            input blocks (plaintext on enc, ciphertext
//                            on dec). Advanced 128 bytes per iteration.
//   [rcx + 16]  OutPtr     : base of ABlockCount consecutive 16-byte
//                            output blocks (may alias InPtr). Advanced
//                            128 bytes per iteration.
//   [rcx + 24]  Offsets    : base of ABlockCount consecutive 16-byte
//                            raw Delta offsets. Read-only, advanced
//                            128 bytes per iteration.
//   [rcx + 32]  BlockCount : NativeUInt; total blocks to process. MUST
//                            be a positive multiple of 8; caller
//                            guarantees via MinimumBlockCount contract.
//
// XMM register allocation (x86_64; 9 of 16 registers used):
//   xmm0..xmm7 : 8 data lanes (pre-whitening -> AES chain -> post-whitened
//                output). No cross-lane dependencies inside a chunk.
//   xmm8       : round-key scratch (movdqa reload per AES round) and
//                offset scratch during pre/post whitening.
//   xmm9..xmm15: unused (free budget for future expansion).
//
// GPR usage (all MS x64 / SysV-volatile; no non-volatile saves needed):
//   rcx : PCtx (preserved across the kernel)
//   rdx : Keys (alive across all rounds as the base of [rdx + 16*r])
//   rax : InPtr  (advancing per chunk; +128 per iter)
//   r8  : OutPtr (advancing per chunk; +128 per iter)
//   r9  : Offsets (advancing per chunk; +128 per iter)
//   r10 : loop counter (= BlockCount / 8 at entry; decrements to 0)
//
// Win64 ABI: xmm6..xmm15 are callee-save. This kernel is compiled as a
// leaf asm procedure (SimdProc1Begin_x86_64.inc emits nostackframe) and
// is only called from Pascal. Consistent with the other fused kernels
// in this tree, which treat xmm6..xmm15 as scratch in the same
// leaf-asm context.
//
// Direction: define CRYPTOLIB_AESNI_DECRYPT to emit aesdec/aesdeclast,
//            otherwise aesenc/aesenclast is emitted.
// Key size : define exactly ONE of CRYPTOLIB_AESNI_KEY128 /
//            CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256.
//
// Encoding: AES-NI instructions and pxor-with-xmm8 are db-encoded for
// broad assembler compatibility (matches the rest of the tree).
// REX prefix for xmm8 in the r/m slot = $41 (REX.B=1). ModRM byte is
// $C0 + reg*8 + 0 (xmm8 encodes as 0 with REX.B supplying the top bit).
// -------------------------------------------------------------------

  // --- Prologue: load context pointers and initialise loop counter. ---
  mov       rdx, [rcx +  0]                         // rdx = Keys
  mov       rax, [rcx +  8]                         // rax = InPtr
  mov       r8,  [rcx + 16]                         // r8  = OutPtr
  mov       r9,  [rcx + 24]                         // r9  = Offsets
  mov       r10, [rcx + 32]                         // r10 = BlockCount
  shr       r10, 3                                  // r10 = BlockCount / 8 (>= 1)

@@ocb_x64_loop:

  // --- Load 8 input blocks into xmm0..xmm7. ---
  movdqu    xmm0, [rax +   0]
  movdqu    xmm1, [rax +  16]
  movdqu    xmm2, [rax +  32]
  movdqu    xmm3, [rax +  48]
  movdqu    xmm4, [rax +  64]
  movdqu    xmm5, [rax +  80]
  movdqu    xmm6, [rax +  96]
  movdqu    xmm7, [rax + 112]

  // --- Pre-whiten with K_0 via scratch xmm8 (Keys schedule is aligned). ---
  movdqa    xmm8, [rdx]                             // xmm8 = K_0
  db $66, $41, $0F, $EF, $C0                        // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0                        // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8                        // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0                        // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8                        // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0                        // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8                        // pxor xmm7, xmm8

  // --- Pre-whiten with offsets (offsets are 16-byte staged by the
  //     mode but stack locals are only 4/8-byte aligned under FPC, so
  //     load via movdqu into xmm8 then reg-reg pxor). ---
  movdqu    xmm8, [r9 +   0]
  db $66, $41, $0F, $EF, $C0                        // pxor xmm0, xmm8
  movdqu    xmm8, [r9 +  16]
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8
  movdqu    xmm8, [r9 +  32]
  db $66, $41, $0F, $EF, $D0                        // pxor xmm2, xmm8
  movdqu    xmm8, [r9 +  48]
  db $66, $41, $0F, $EF, $D8                        // pxor xmm3, xmm8
  movdqu    xmm8, [r9 +  64]
  db $66, $41, $0F, $EF, $E0                        // pxor xmm4, xmm8
  movdqu    xmm8, [r9 +  80]
  db $66, $41, $0F, $EF, $E8                        // pxor xmm5, xmm8
  movdqu    xmm8, [r9 +  96]
  db $66, $41, $0F, $EF, $F0                        // pxor xmm6, xmm8
  movdqu    xmm8, [r9 + 112]
  db $66, $41, $0F, $EF, $F8                        // pxor xmm7, xmm8

  // ------------------------------------------------------------------
  // Middle rounds 1..N-1 (aesenc / aesdec via CRYPTOLIB_AESNI_DECRYPT).
  // Each round: movdqa xmm8, [rdx + 16*r]; aes* xmm0..xmm7, xmm8.
  // ------------------------------------------------------------------
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

  // Round 1
  movdqa    xmm8, [rdx + 16]
  db $66, $41, $0F, $38, $DE, $C0                   // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8                   // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0                   // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8                   // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0                   // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8                   // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0                   // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8                   // aesdec xmm7, xmm8
  // Round 2
  movdqa    xmm8, [rdx + 32]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 3
  movdqa    xmm8, [rdx + 48]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 4
  movdqa    xmm8, [rdx + 64]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 5
  movdqa    xmm8, [rdx + 80]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 6
  movdqa    xmm8, [rdx + 96]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 7
  movdqa    xmm8, [rdx + 112]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 8
  movdqa    xmm8, [rdx + 128]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 9
  movdqa    xmm8, [rdx + 144]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8

{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Round 10
  movdqa    xmm8, [rdx + 160]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 11
  movdqa    xmm8, [rdx + 176]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
{$ENDIF}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 10
  movdqa    xmm8, [rdx + 160]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 11
  movdqa    xmm8, [rdx + 176]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 12
  movdqa    xmm8, [rdx + 192]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
  // Round 13
  movdqa    xmm8, [rdx + 208]
  db $66, $41, $0F, $38, $DE, $C0
  db $66, $41, $0F, $38, $DE, $C8
  db $66, $41, $0F, $38, $DE, $D0
  db $66, $41, $0F, $38, $DE, $D8
  db $66, $41, $0F, $38, $DE, $E0
  db $66, $41, $0F, $38, $DE, $E8
  db $66, $41, $0F, $38, $DE, $F0
  db $66, $41, $0F, $38, $DE, $F8
{$ENDIF}

  // --- Final round: aesdeclast xmm0..xmm7, xmm8. ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [rdx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [rdx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [rdx + 224]
{$ENDIF}
  db $66, $41, $0F, $38, $DF, $C0                   // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8                   // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0                   // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8                   // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0                   // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8                   // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0                   // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8                   // aesdeclast xmm7, xmm8

{$ELSE} // ===================== ENCRYPT variant =====================

  // Round 1
  movdqa    xmm8, [rdx + 16]
  db $66, $41, $0F, $38, $DC, $C0                   // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                   // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                   // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                   // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                   // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                   // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                   // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                   // aesenc xmm7, xmm8
  // Round 2
  movdqa    xmm8, [rdx + 32]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 3
  movdqa    xmm8, [rdx + 48]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 4
  movdqa    xmm8, [rdx + 64]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 5
  movdqa    xmm8, [rdx + 80]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 6
  movdqa    xmm8, [rdx + 96]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 7
  movdqa    xmm8, [rdx + 112]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 8
  movdqa    xmm8, [rdx + 128]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 9
  movdqa    xmm8, [rdx + 144]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8

{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Round 10
  movdqa    xmm8, [rdx + 160]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 11
  movdqa    xmm8, [rdx + 176]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
{$ENDIF}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 10
  movdqa    xmm8, [rdx + 160]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 11
  movdqa    xmm8, [rdx + 176]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 12
  movdqa    xmm8, [rdx + 192]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
  // Round 13
  movdqa    xmm8, [rdx + 208]
  db $66, $41, $0F, $38, $DC, $C0
  db $66, $41, $0F, $38, $DC, $C8
  db $66, $41, $0F, $38, $DC, $D0
  db $66, $41, $0F, $38, $DC, $D8
  db $66, $41, $0F, $38, $DC, $E0
  db $66, $41, $0F, $38, $DC, $E8
  db $66, $41, $0F, $38, $DC, $F0
  db $66, $41, $0F, $38, $DC, $F8
{$ENDIF}

  // --- Final round: aesenclast xmm0..xmm7, xmm8. ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [rdx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [rdx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [rdx + 224]
{$ENDIF}
  db $66, $41, $0F, $38, $DD, $C0                   // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8                   // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0                   // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8                   // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0                   // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8                   // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0                   // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8                   // aesenclast xmm7, xmm8

{$ENDIF}

  // --- Post-whiten with offsets (reload via movdqu scratch). ---
  movdqu    xmm8, [r9 +   0]
  db $66, $41, $0F, $EF, $C0                        // pxor xmm0, xmm8
  movdqu    xmm8, [r9 +  16]
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8
  movdqu    xmm8, [r9 +  32]
  db $66, $41, $0F, $EF, $D0                        // pxor xmm2, xmm8
  movdqu    xmm8, [r9 +  48]
  db $66, $41, $0F, $EF, $D8                        // pxor xmm3, xmm8
  movdqu    xmm8, [r9 +  64]
  db $66, $41, $0F, $EF, $E0                        // pxor xmm4, xmm8
  movdqu    xmm8, [r9 +  80]
  db $66, $41, $0F, $EF, $E8                        // pxor xmm5, xmm8
  movdqu    xmm8, [r9 +  96]
  db $66, $41, $0F, $EF, $F0                        // pxor xmm6, xmm8
  movdqu    xmm8, [r9 + 112]
  db $66, $41, $0F, $EF, $F8                        // pxor xmm7, xmm8

  // --- Store 8 output blocks. ---
  movdqu    [r8 +   0], xmm0
  movdqu    [r8 +  16], xmm1
  movdqu    [r8 +  32], xmm2
  movdqu    [r8 +  48], xmm3
  movdqu    [r8 +  64], xmm4
  movdqu    [r8 +  80], xmm5
  movdqu    [r8 +  96], xmm6
  movdqu    [r8 + 112], xmm7

  // --- Advance pointers and loop. ---
  add       rax, 128
  add       r8,  128
  add       r9,  128
  dec       r10
  jnz       @@ocb_x64_loop
