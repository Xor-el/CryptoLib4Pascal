// AES-NI 4-wide round chain, reusable kernel, merged Enc + Dec, merged key sizes (i386).
// -------------------------------------------------------------------
//
// Shared 4-wide AES round chain consumed by the merged AesNiFourCipher_i386
// wrapper. The fused AEAD kernels (OCB / GCM / CCM / EAX) carry their
// own round chains with different register allocations and do NOT
// include this file.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R
//                              (10 / 12 / 14 rounds).
//
// On entry:
//   xmm0..xmm3 = 4 data blocks (NOT pre-whitened; K_0 XOR happens in round 0
//                  inside this file).
//   edi = expanded round-key schedule pointer; must match the direction
//                  (decrypt consumers pass the inverse-MixColumns schedule).
//   each round key is loaded into xmm4 and broadcast across the lanes.
//
// On exit:
//   xmm0..xmm3 = 4 post-AES blocks, ready for caller storeback / XOR.
//   edi = unchanged.
//   Scratch: xmm4 (clobbered: shared round-key broadcast register)
//
// AES-NI instructions, plus pxor forms touching extended registers,
// are db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DF, $C4   // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC   // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4   // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC   // aesdeclast xmm3, xmm4
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 176]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 192]
  db $66, $0F, $38, $DF, $C4   // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC   // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4   // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC   // aesdeclast xmm3, xmm4
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 176]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 192]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 208]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 224]
  db $66, $0F, $38, $DF, $C4   // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC   // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4   // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC   // aesdeclast xmm3, xmm4
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DD, $C4   // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC   // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4   // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC   // aesenclast xmm3, xmm4
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 176]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 192]
  db $66, $0F, $38, $DD, $C4   // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC   // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4   // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC   // aesenclast xmm3, xmm4
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 176]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 192]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 208]
  db $66, $0F, $38, $DC, $C4   // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC   // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4   // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC   // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 224]
  db $66, $0F, $38, $DD, $C4   // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC   // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4   // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC   // aesenclast xmm3, xmm4
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
