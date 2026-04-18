// AesNiFourCipherInOut x86_64 (merged Enc + Dec)
// Direction: define CRYPTOLIB_AESNI_DECRYPT to use the decrypt variant
// (aesdec / aesdeclast). Otherwise the encrypt variant is selected.
// Key size: define exactly one of CRYPTOLIB_AESNI_KEY128 /
// CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256 before including
// (see ClpAesEngineX86). AES-NI instructions are db-encoded for
// broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
// AesNiFourDecInOut x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line four-block AES-NI (@4_d128), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [r8]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [r8 + 16]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 32]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 48]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 64]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 80]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 96]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 112]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 128]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 144]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [r8 + 160]
  db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line four-block AES-NI (@4_d192), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
    movdqu    xmm0, [rcx]
    movdqu    xmm1, [rcx + 16]
    movdqu    xmm2, [rcx + 32]
    movdqu    xmm3, [rcx + 48]
    movdqa    xmm4, [r8]
    db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
    db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
    db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
    db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
    movdqa    xmm4, [r8 + 16]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 32]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 48]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 64]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 80]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 96]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 112]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 128]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 144]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 160]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 176]
    db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
    db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
    db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
    db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
    movdqa    xmm4, [r8 + 192]
    db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
    db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
    db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
    db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
    movdqu    [rdx], xmm0
    movdqu    [rdx + 16], xmm1
    movdqu    [rdx + 32], xmm2
    movdqu    [rdx + 48], xmm3
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line four-block AES-NI (@4_d256), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
      movdqu    xmm0, [rcx]
      movdqu    xmm1, [rcx + 16]
      movdqu    xmm2, [rcx + 32]
      movdqu    xmm3, [rcx + 48]
      movdqa    xmm4, [r8]
      db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
      db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
      db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
      db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
      movdqa    xmm4, [r8 + 16]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 32]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 48]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 64]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 80]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 96]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 112]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 128]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 144]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 160]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 176]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 192]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 208]
      db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
      db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
      db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
      db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
      movdqa    xmm4, [r8 + 224]
      db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
      db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
      db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
      db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
      movdqu    [rdx], xmm0
      movdqu    [rdx + 16], xmm1
      movdqu    [rdx + 32], xmm2
      movdqu    [rdx + 48], xmm3
    @4_done:
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}
// AesNiFourEncInOut x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line four-block AES-NI (@4_e128), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [r8]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [r8 + 16]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 32]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 48]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 64]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 80]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 96]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 112]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 128]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 144]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [r8 + 160]
  db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line four-block AES-NI (@4_e192), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
    movdqu    xmm0, [rcx]
    movdqu    xmm1, [rcx + 16]
    movdqu    xmm2, [rcx + 32]
    movdqu    xmm3, [rcx + 48]
    movdqa    xmm4, [r8]
    db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
    db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
    db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
    db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
    movdqa    xmm4, [r8 + 16]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 32]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 48]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 64]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 80]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 96]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 112]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 128]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 144]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 160]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 176]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [r8 + 192]
    db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
    db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
    db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
    db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
    movdqu    [rdx], xmm0
    movdqu    [rdx + 16], xmm1
    movdqu    [rdx + 32], xmm2
    movdqu    [rdx + 48], xmm3
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line four-block AES-NI (@4_e256), x86-64. rcx=RIn, rdx=ROut, r8=Keys.
      movdqu    xmm0, [rcx]
      movdqu    xmm1, [rcx + 16]
      movdqu    xmm2, [rcx + 32]
      movdqu    xmm3, [rcx + 48]
      movdqa    xmm4, [r8]
      db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
      db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
      db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
      db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
      movdqa    xmm4, [r8 + 16]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 32]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 48]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 64]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 80]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 96]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 112]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 128]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 144]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 160]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 176]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 192]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 208]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [r8 + 224]
      db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
      db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
      db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
      db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
      movdqu    [rdx], xmm0
      movdqu    [rdx + 16], xmm1
      movdqu    [rdx + 32], xmm2
      movdqu    [rdx + 48], xmm3
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}