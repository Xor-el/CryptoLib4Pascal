// AesNiOneEnc x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line one-block AES-NI (@aes_e128), x86-64. rcx=state, rdx=keys.
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DC, $C1         // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DD, $C1         // aesenclast xmm0, xmm1
  movdqu    [rcx], xmm0
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line one-block AES-NI (@aes_e192), x86-64. rcx=state, rdx=keys.
    movdqu    xmm0, [rcx]
    movdqa    xmm1, [rdx]
    db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
    movdqa    xmm1, [rdx + 16]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 32]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 48]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 64]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 80]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 96]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 112]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 128]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 144]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 160]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 176]
    db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
    movdqa    xmm1, [rdx + 192]
    db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
    movdqu    [rcx], xmm0
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line one-block AES-NI (@aes_e256), x86-64. rcx=state, rdx=keys.
      movdqu    xmm0, [rcx]
      movdqa    xmm1, [rdx]
      db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
      movdqa    xmm1, [rdx + 16]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 32]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 48]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 64]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 80]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 96]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 112]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 128]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 144]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 160]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 176]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 192]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 208]
      db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
      movdqa    xmm1, [rdx + 224]
      db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
      movdqu    [rcx], xmm0
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

