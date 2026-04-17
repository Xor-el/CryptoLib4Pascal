// AesNiOneEncInOut x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line one-block AES-NI (@aes_e128), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [r8]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqa    xmm1, [r8 + 16]
  db $66, $0F, $38, $DC, $C1         // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 32]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 48]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 64]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 80]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 96]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 112]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 128]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 144]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [r8 + 160]
  db $66, $0F, $38, $DD, $C1         // aesenclast xmm0, xmm1
  movdqu    [rdx], xmm0
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line one-block AES-NI (@aes_e192), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
    movdqu    xmm0, [rcx]
    movdqa    xmm1, [r8]
    db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
    movdqa    xmm1, [r8 + 16]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 32]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 48]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 64]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 80]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 96]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 112]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 128]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 144]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 160]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 176]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [r8 + 192]
    db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
    movdqu    [rdx], xmm0
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line one-block AES-NI (@aes_e256), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
      movdqu    xmm0, [rcx]
      movdqa    xmm1, [r8]
      db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
      movdqa    xmm1, [r8 + 16]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 32]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 48]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 64]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 80]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 96]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 112]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 128]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 144]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 160]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 176]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 192]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 208]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [r8 + 224]
      db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
      movdqu    [rdx], xmm0
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

