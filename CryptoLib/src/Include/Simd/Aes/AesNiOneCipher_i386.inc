// AesNiOneCipher i386 (merged Enc + Dec)
// Direction: define CRYPTOLIB_AESNI_DECRYPT to use the decrypt variant
// (aesdec / aesdeclast). Otherwise the encrypt variant is selected.
// Key size: define exactly one of CRYPTOLIB_AESNI_KEY128 /
// CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256 before including
// (see ClpAesEngineX86). AES-NI instructions are db-encoded for
// broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
// AesNiOneDec i386 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line one-block AES-NI (@aes_d128), i386 register convention. ebx=state, esi=keys (after SimdProc2Begin_i386).
  movdqu    xmm0, [ebx]
  movdqa    xmm1, [esi]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [esi + 16]
  db $66, $0F, $38, $DE, $C1         // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 32]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 48]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 64]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 80]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 96]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 112]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 128]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 144]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [esi + 160]
  db $66, $0F, $38, $DF, $C1         // aesdeclast xmm0, xmm1
  movdqu    [ebx], xmm0
  pop esi
  pop ebx
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line one-block AES-NI (@aes_d192), i386 register convention. ebx=state, esi=keys (after SimdProc2Begin_i386).
    movdqu    xmm0, [ebx]
    movdqa    xmm1, [esi]
    db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
    movdqa    xmm1, [esi + 16]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 32]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 48]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 64]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 80]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 96]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 112]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 128]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 144]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 160]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 176]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [esi + 192]
    db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
    movdqu    [ebx], xmm0
    pop esi
    pop ebx
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line one-block AES-NI (@aes_d256), i386 register convention. ebx=state, esi=keys (after SimdProc2Begin_i386).
      movdqu    xmm0, [ebx]
      movdqa    xmm1, [esi]
      db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
      movdqa    xmm1, [esi + 16]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 32]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 48]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 64]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 80]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 96]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 112]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 128]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 144]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 160]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 176]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 192]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 208]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [esi + 224]
      db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
      movdqu    [ebx], xmm0
    @aes_ir_done:
      pop esi
      pop ebx
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}
// AesNiOneEnc i386 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line one-block AES-NI (@aes_e128), i386 register convention. ebx=state, esi=keys (after SimdProc2Begin_i386).
  movdqu    xmm0, [ebx]
  movdqa    xmm1, [esi]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqa    xmm1, [esi + 16]
  db $66, $0F, $38, $DC, $C1         // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 32]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 48]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 64]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 80]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 96]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 112]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 128]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 144]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [esi + 160]
  db $66, $0F, $38, $DD, $C1         // aesenclast xmm0, xmm1
  movdqu    [ebx], xmm0
  pop esi
  pop ebx
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line one-block AES-NI (@aes_e192), i386 register convention. ebx=state, esi=keys (after SimdProc2Begin_i386).
    movdqu    xmm0, [ebx]
    movdqa    xmm1, [esi]
    db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
    movdqa    xmm1, [esi + 16]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 32]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 48]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 64]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 80]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 96]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 112]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 128]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 144]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 160]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 176]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [esi + 192]
    db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
    movdqu    [ebx], xmm0
    pop esi
    pop ebx
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line one-block AES-NI (@aes_e256), i386 register convention. ebx=state, esi=keys (after SimdProc2Begin_i386).
      movdqu    xmm0, [ebx]
      movdqa    xmm1, [esi]
      db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
      movdqa    xmm1, [esi + 16]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 32]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 48]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 64]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 80]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 96]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 112]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 128]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 144]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 160]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 176]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 192]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 208]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [esi + 224]
      db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
      movdqu    [ebx], xmm0
      pop esi
      pop ebx
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}