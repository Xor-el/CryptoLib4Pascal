// AesNiOneDecInOut i386 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line one-block AES-NI (@aes_d128), i386 register convention. ebx=RIn, esi=ROut, edi=Keys (after SimdProc2Begin_i386).
  movdqu    xmm0, [ebx]
  movdqa    xmm1, [edi]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [edi + 16]
  db $66, $0F, $38, $DE, $C1         // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 32]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 48]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 64]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 80]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 96]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 112]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 128]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 144]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [edi + 160]
  db $66, $0F, $38, $DF, $C1         // aesdeclast xmm0, xmm1
  movdqu    [esi], xmm0
  pop edi
  pop esi
  pop ebx
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line one-block AES-NI (@aes_d192), i386 register convention. ebx=RIn, esi=ROut, edi=Keys (after SimdProc2Begin_i386).
    movdqu    xmm0, [ebx]
    movdqa    xmm1, [edi]
    db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
    movdqa    xmm1, [edi + 16]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 32]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 48]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 64]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 80]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 96]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 112]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 128]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 144]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 160]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 176]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [edi + 192]
    db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
    movdqu    [esi], xmm0
    pop edi
    pop esi
    pop ebx
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line one-block AES-NI (@aes_d256), i386 register convention. ebx=RIn, esi=ROut, edi=Keys (after SimdProc2Begin_i386).
      movdqu    xmm0, [ebx]
      movdqa    xmm1, [edi]
      db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
      movdqa    xmm1, [edi + 16]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 32]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 48]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 64]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 80]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 96]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 112]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 128]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 144]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 160]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 176]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 192]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 208]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [edi + 224]
      db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
      movdqu    [esi], xmm0
    @aes_ir_done:
      pop edi
      pop esi
      pop ebx
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

