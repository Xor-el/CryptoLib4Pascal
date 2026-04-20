// AesNiEightRoundsOnly x86_64 (reusable 8-wide AES-NI round chain)
// -----------------------------------------------------------------
// Consumed by the in-place / out-of-place AES-NI aggregators (this
// file's original parent AesNiEightCipher[InOut]_x86_64.inc) AND by
// every fused AEAD kernel in Phase 1-4 (OCB, CCM, GCM-SIV, EAX).
// Keeping the round chain in a single file guarantees that any future
// micro-optimisation (e.g. xmm8/xmm9 ping-pong to hide round-key load
// latency, or EVEX promotion) lands in every consumer at once.
//
// Contract on entry:
//   xmm0..xmm7 = 8 data blocks (little-endian, NOT pre-pxor-ed with the
//                 whitening key -- that happens in round 0 inside this
//                 file, matching the existing aggregator semantics)
//   r8         = pointer to the expanded round-key schedule for the
//                 current direction / key size. MUST be a round-count-
//                 consistent schedule (i.e. decrypt consumers pass the
//                 inverse-MixColumns-applied schedule; encrypt consumers
//                 pass the forward schedule). Lifetime is the current
//                 AES engine init -- see IAesEngineX86.TryGet{Enc,Dec}
//                 KeysPtr in ClpIAesEngineX86.
//
// Contract on exit:
//   xmm0..xmm7 = 8 post-AES blocks (ready for the caller to store,
//                 XOR with counters / offsets / masks, etc.)
//   r8         = unchanged (callee-read-only; aggregators rely on this)
//   xmm8       = CLOBBERED (used as the shared round-key broadcast
//                 register; encoded via REX.B=1 so the data registers
//                 xmm0..xmm7 do not need to be spilled)
//
// Direction: define CRYPTOLIB_AESNI_DECRYPT to select aesdec/aesdeclast,
//            otherwise aesenc/aesenclast is emitted.
// Key size : define exactly ONE of CRYPTOLIB_AESNI_KEY128 /
//            CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256 before the
//            {$I} include so the right number of rounds (10 / 12 / 14)
//            is emitted.
//
// Encoding notes: AES-NI instructions are db-encoded for broad assembler
// compatibility. REX.B = 1 (prefix $41) because the source register is
// xmm8. ModRM for "xmmN, xmm8": $C0 + N*8 -> C0/C8/D0/D8/E0/E8/F0/F8
// for N=0..7.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 224]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}
// Encrypt variant (aesenc / aesenclast). See the top-of-file contract
// comment for the full register / lifetime / direction specification.
// Round count: KEY128 -> 10, KEY192 -> 12, KEY256 -> 14.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 224]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
