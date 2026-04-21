// AES-NI 8-wide round chain, reusable kernel, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
// Shared round chain consumed by every 8-wide AES-NI aggregator and
// fused AEAD kernel in this tree (AesNiEightCipher[InOut], OCB, CCM,
// GCM, GCM-SIV, EAX). Keeping the round loop in one file guarantees
// that any future micro-optimisation lands everywhere at once.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R
//                              (10 / 12 / 14 rounds).
//
// On entry:
//   xmm0..xmm7 = 8 data blocks (LE, NOT pre-XORed with the whitening key;
//                  K_0 XOR happens in round 0 inside this file).
//   r8         = expanded round-key schedule pointer; must match the
//                  direction (decrypt consumers pass the inverse-
//                  MixColumns schedule). See IAesEngineX86 in
//                  ClpIAesEngineX86.
//
// On exit:
//   xmm0..xmm7 = 8 post-AES blocks, ready for caller storeback / XOR.
//   r8         = unchanged (aggregators rely on this).
//   xmm8       = clobbered (shared round-key broadcast register).
//
// AES-NI instructions, plus pxor forms touching xmm8, are db-encoded
// for broad assembler compatibility.
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
