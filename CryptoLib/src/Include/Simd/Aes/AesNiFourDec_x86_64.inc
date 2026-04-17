// AesNiFourDec x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line four-block AES-NI (@4_d128), x86-64. rcx=state, rdx=keys.
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [rdx]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [rdx + 16]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line four-block AES-NI (@4_d192), x86-64. rcx=state, rdx=keys.
    movdqu    xmm0, [rcx]
    movdqu    xmm1, [rcx + 16]
    movdqu    xmm2, [rcx + 32]
    movdqu    xmm3, [rcx + 48]
    movdqa    xmm4, [rdx]
    db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
    db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
    db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
    db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
    movdqa    xmm4, [rdx + 16]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 32]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 48]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 64]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 80]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 96]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 112]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 128]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 144]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 160]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 176]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [rdx + 192]
    db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
    db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
    db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
    db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
    movdqu    [rcx], xmm0
    movdqu    [rcx + 16], xmm1
    movdqu    [rcx + 32], xmm2
    movdqu    [rcx + 48], xmm3
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line four-block AES-NI (@4_d256), x86-64. rcx=state, rdx=keys.
      movdqu    xmm0, [rcx]
      movdqu    xmm1, [rcx + 16]
      movdqu    xmm2, [rcx + 32]
      movdqu    xmm3, [rcx + 48]
      movdqa    xmm4, [rdx]
      db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
      db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
      db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
      db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
      movdqa    xmm4, [rdx + 16]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 32]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 48]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 64]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 80]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 96]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 112]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 128]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 144]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 160]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 176]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 192]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 208]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [rdx + 224]
      db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
      db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
      db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
      db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
      movdqu    [rcx], xmm0
      movdqu    [rcx + 16], xmm1
      movdqu    [rcx + 32], xmm2
      movdqu    [rcx + 48], xmm3
    @4_done:
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

