// AES-NI four-block cipher, in-place, merged Enc + Dec, merged key sizes (x86-64).
// Straight-line AES on four independent 16-byte blocks (xmm0..xmm3) sharing
// each round-key broadcast: XOR K_0, run N_R - 1 aesenc (or aesdec when
// CRYPTOLIB_AESNI_DECRYPT is set) rounds on K_1..K_{N_R-1}, and finish with
// aesenclast (or aesdeclast) on K_{N_R}. N_R = 10 / 12 / 14 for
// AES-128 / 192 / 256. Pipelining four lanes against one round key issues
// four AES instructions per loaded K_i which hides the aesenc latency
// (~4c on modern Intel/Zen).
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// After SimdProc2Begin_x86_64.inc: rcx = state (64 bytes = 4 x 16, in/out),
// rdx = keys.
// Schedule layout: 11 / 13 / 15 consecutive 16-byte round keys
// (see ClpAesEngineX86 for the allocation / key-expansion site).
// Uses xmm0..xmm3 (data blocks) and xmm4 (round-key scratch).
// AES-NI instructions are db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
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

{$ELSE}
// AesNiFourEnc x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// Straight-line four-block AES-NI (@4_e128), x86-64. rcx=state, rdx=keys.
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
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Straight-line four-block AES-NI (@4_e192), x86-64. rcx=state, rdx=keys.
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
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 32]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 48]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 64]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 80]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 96]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 112]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 128]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 144]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 160]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 176]
    db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
    db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
    db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
    db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
    movdqa    xmm4, [rdx + 192]
    db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
    db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
    db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
    db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
    movdqu    [rcx], xmm0
    movdqu    [rcx + 16], xmm1
    movdqu    [rcx + 32], xmm2
    movdqu    [rcx + 48], xmm3
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // Straight-line four-block AES-NI (@4_e256), x86-64. rcx=state, rdx=keys.
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
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 32]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 48]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 64]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 80]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 96]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 112]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 128]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 144]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 160]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 176]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 192]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 208]
      db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
      db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
      db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
      db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
      movdqa    xmm4, [rdx + 224]
      db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
      db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
      db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
      db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
      movdqu    [rcx], xmm0
      movdqu    [rcx + 16], xmm1
      movdqu    [rcx + 32], xmm2
      movdqu    [rcx + 48], xmm3
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}