// AesNiFourEncInOut i386 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line four-block AES-NI (@4_e128), i386 register convention. ebx=RIn, esi=ROut, edi=Keys (after SimdProc2Begin_i386).
  movdqu    xmm0, [ebx]
  movdqu    xmm1, [ebx + 16]
  movdqu    xmm2, [ebx + 32]
  movdqu    xmm3, [ebx + 48]
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
  movdqu    [esi], xmm0
  movdqu    [esi + 16], xmm1
  movdqu    [esi + 32], xmm2
  movdqu    [esi + 48], xmm3
  pop edi
  pop esi
  pop ebx
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line four-block AES-NI (@4_e192), i386 register convention. ebx=RIn, esi=ROut, edi=Keys (after SimdProc2Begin_i386).
    movdqu    xmm0, [ebx]
    movdqu    xmm1, [ebx + 16]
    movdqu    xmm2, [ebx + 32]
    movdqu    xmm3, [ebx + 48]
    movdqa    xmm4, [edi]
    db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
    db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
    db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
    db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
    movdqa    xmm4, [edi + 16]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 32]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 48]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 64]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 80]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 96]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 112]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 128]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 144]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 160]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 176]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [edi + 192]
    db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
    db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
    db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
    db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
    movdqu    [esi], xmm0
    movdqu    [esi + 16], xmm1
    movdqu    [esi + 32], xmm2
    movdqu    [esi + 48], xmm3
    pop edi
    pop esi
    pop ebx
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line four-block AES-NI (@4_e256), i386 register convention. ebx=RIn, esi=ROut, edi=Keys (after SimdProc2Begin_i386).
      movdqu    xmm0, [ebx]
      movdqu    xmm1, [ebx + 16]
      movdqu    xmm2, [ebx + 32]
      movdqu    xmm3, [ebx + 48]
      movdqa    xmm4, [edi]
      db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
      db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
      db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
      db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
      movdqa    xmm4, [edi + 16]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 32]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 48]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 64]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 80]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 96]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 112]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 128]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 144]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 160]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 176]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 192]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 208]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [edi + 224]
      db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
      db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
      db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
      db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
      movdqu    [esi], xmm0
      movdqu    [esi + 16], xmm1
      movdqu    [esi + 32], xmm2
      movdqu    [esi + 48], xmm3
      pop edi
      pop esi
      pop ebx
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

