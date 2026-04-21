// AES-NI one-block cipher, in-place, merged Enc + Dec, merged key sizes (x86-64).
// Straight-line AES on a single 16-byte block: XOR K_0, run N_R - 1 aesenc
// (or aesdec when CRYPTOLIB_AESNI_DECRYPT is set) rounds on K_1..K_{N_R-1},
// and finish with aesenclast (or aesdeclast) on K_{N_R}. N_R = 10 / 12 / 14
// for AES-128 / 192 / 256.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// After SimdProc2Begin_x86_64.inc: rcx = state (16 bytes, in/out), rdx = keys.
// Schedule layout: 11 / 13 / 15 consecutive 16-byte round keys
// (see ClpAesEngineX86 for the allocation / key-expansion site).
// Uses xmm0 (data) and xmm1 (round-key scratch).
// AES-NI instructions are db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DE, $C1         // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DF, $C1         // aesdeclast xmm0, xmm1
  movdqu    [rcx], xmm0
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
    movdqu    xmm0, [rcx]
    movdqa    xmm1, [rdx]
    db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
    movdqa    xmm1, [rdx + 16]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 32]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 48]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 64]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 80]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 96]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 112]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 128]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 144]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 160]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 176]
    db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
    movdqa    xmm1, [rdx + 192]
    db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
    movdqu    [rcx], xmm0
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
      movdqu    xmm0, [rcx]
      movdqa    xmm1, [rdx]
      db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
      movdqa    xmm1, [rdx + 16]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 32]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 48]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 64]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 80]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 96]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 112]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 128]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 144]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 160]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 176]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 192]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 208]
      db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
      movdqa    xmm1, [rdx + 224]
      db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
      movdqu    [rcx], xmm0
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
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

{$ENDIF}
