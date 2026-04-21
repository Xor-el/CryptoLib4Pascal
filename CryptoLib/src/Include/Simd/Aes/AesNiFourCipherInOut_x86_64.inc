// AES-NI four-block cipher, out-of-place, merged Enc + Dec, merged key sizes (x86-64).
// Straight-line AES on four independent 16-byte blocks (xmm0..xmm3) sharing
// each round-key broadcast: XOR K_0, run N_R - 1 aesenc (or aesdec when
// CRYPTOLIB_AESNI_DECRYPT is set) rounds on K_1..K_{N_R-1}, and finish with
// aesenclast (or aesdeclast) on K_{N_R}. N_R = 10 / 12 / 14 for
// AES-128 / 192 / 256. Reads from RIn, writes to ROut (the two may alias).
// Pipelining four lanes against one round key issues four AES instructions
// per loaded K_i which hides the aesenc latency (~4c on modern Intel/Zen).
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// After SimdProc3Begin_x86_64.inc: rcx = RIn (64 bytes), rdx = ROut (64 bytes),
// r8 = keys.
// Schedule layout: 11 / 13 / 15 consecutive 16-byte round keys
// (see ClpAesEngineX86 for the allocation / key-expansion site).
// Uses xmm0..xmm3 (data blocks) and xmm4 (round-key scratch).
// AES-NI instructions are db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
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
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
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
