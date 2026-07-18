// AES-NI block-cipher kernel, merged widths 1 / 4 / 8, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
//
// Out-of-place AES over 1, 4 or 8 consecutive 16-byte blocks; the
// width is selected per include site. In-place callers pass
// RIn = ROut; partial overlap is unsupported. The fused mode kernels
// (CTR / CBC / OCB / GCM / CCM / EAX) carry their own round chains and
// do NOT include this file.
//
// Variant selection:
//   Exactly one of CRYPTOLIB_AESNI_ONE / FOUR / EIGHT selects the width.
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R
//                              (10 / 12 / 14 rounds).
//
// Entry (after ClpSimdProc3Begin_x86_64.inc): rcx = RIn, rdx = ROut,
// r8 = expanded round-key schedule pointer; must match the direction
// (decrypt consumers pass the inverse-MixColumns schedule).
//
// Scratch: width 1 none (round keys consumed as memory operands);
// width 4 xmm4; width 8 xmm8 (round-key broadcast), with callee-saved
// xmm6..xmm7 preserved via ClpSimdNonVolatileSave/Restore.
//
// Reference: Shay Gueron, "Intel AES New Instructions" whitepaper - the
// multi-block-interleaved AES-NI technique implemented by the round
// chains below.
//
// AES-NI instructions, plus pxor forms touching extended registers,
// are db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_ONE}
  movdqu    xmm0, [rcx]
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DE, $40, $10    // aesdec xmm0, [r8+16]
  db $66, $41, $0F, $38, $DE, $40, $20    // aesdec xmm0, [r8+32]
  db $66, $41, $0F, $38, $DE, $40, $30    // aesdec xmm0, [r8+48]
  db $66, $41, $0F, $38, $DE, $40, $40    // aesdec xmm0, [r8+64]
  db $66, $41, $0F, $38, $DE, $40, $50    // aesdec xmm0, [r8+80]
  db $66, $41, $0F, $38, $DE, $40, $60    // aesdec xmm0, [r8+96]
  db $66, $41, $0F, $38, $DE, $40, $70    // aesdec xmm0, [r8+112]
  db $66, $41, $0F, $38, $DE, $80, $80, $00, $00, $00 // aesdec xmm0, [r8+128]
  db $66, $41, $0F, $38, $DE, $80, $90, $00, $00, $00 // aesdec xmm0, [r8+144]
  db $66, $41, $0F, $38, $DF, $80, $A0, $00, $00, $00 // aesdeclast xmm0, [r8+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DE, $40, $10    // aesdec xmm0, [r8+16]
  db $66, $41, $0F, $38, $DE, $40, $20    // aesdec xmm0, [r8+32]
  db $66, $41, $0F, $38, $DE, $40, $30    // aesdec xmm0, [r8+48]
  db $66, $41, $0F, $38, $DE, $40, $40    // aesdec xmm0, [r8+64]
  db $66, $41, $0F, $38, $DE, $40, $50    // aesdec xmm0, [r8+80]
  db $66, $41, $0F, $38, $DE, $40, $60    // aesdec xmm0, [r8+96]
  db $66, $41, $0F, $38, $DE, $40, $70    // aesdec xmm0, [r8+112]
  db $66, $41, $0F, $38, $DE, $80, $80, $00, $00, $00 // aesdec xmm0, [r8+128]
  db $66, $41, $0F, $38, $DE, $80, $90, $00, $00, $00 // aesdec xmm0, [r8+144]
  db $66, $41, $0F, $38, $DE, $80, $A0, $00, $00, $00 // aesdec xmm0, [r8+160]
  db $66, $41, $0F, $38, $DE, $80, $B0, $00, $00, $00 // aesdec xmm0, [r8+176]
  db $66, $41, $0F, $38, $DF, $80, $C0, $00, $00, $00 // aesdeclast xmm0, [r8+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DE, $40, $10    // aesdec xmm0, [r8+16]
  db $66, $41, $0F, $38, $DE, $40, $20    // aesdec xmm0, [r8+32]
  db $66, $41, $0F, $38, $DE, $40, $30    // aesdec xmm0, [r8+48]
  db $66, $41, $0F, $38, $DE, $40, $40    // aesdec xmm0, [r8+64]
  db $66, $41, $0F, $38, $DE, $40, $50    // aesdec xmm0, [r8+80]
  db $66, $41, $0F, $38, $DE, $40, $60    // aesdec xmm0, [r8+96]
  db $66, $41, $0F, $38, $DE, $40, $70    // aesdec xmm0, [r8+112]
  db $66, $41, $0F, $38, $DE, $80, $80, $00, $00, $00 // aesdec xmm0, [r8+128]
  db $66, $41, $0F, $38, $DE, $80, $90, $00, $00, $00 // aesdec xmm0, [r8+144]
  db $66, $41, $0F, $38, $DE, $80, $A0, $00, $00, $00 // aesdec xmm0, [r8+160]
  db $66, $41, $0F, $38, $DE, $80, $B0, $00, $00, $00 // aesdec xmm0, [r8+176]
  db $66, $41, $0F, $38, $DE, $80, $C0, $00, $00, $00 // aesdec xmm0, [r8+192]
  db $66, $41, $0F, $38, $DE, $80, $D0, $00, $00, $00 // aesdec xmm0, [r8+208]
  db $66, $41, $0F, $38, $DF, $80, $E0, $00, $00, $00 // aesdeclast xmm0, [r8+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DD, $80, $A0, $00, $00, $00 // aesenclast xmm0, [r8+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DC, $80, $A0, $00, $00, $00 // aesenc xmm0, [r8+160]
  db $66, $41, $0F, $38, $DC, $80, $B0, $00, $00, $00 // aesenc xmm0, [r8+176]
  db $66, $41, $0F, $38, $DD, $80, $C0, $00, $00, $00 // aesenclast xmm0, [r8+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DC, $80, $A0, $00, $00, $00 // aesenc xmm0, [r8+160]
  db $66, $41, $0F, $38, $DC, $80, $B0, $00, $00, $00 // aesenc xmm0, [r8+176]
  db $66, $41, $0F, $38, $DC, $80, $C0, $00, $00, $00 // aesenc xmm0, [r8+192]
  db $66, $41, $0F, $38, $DC, $80, $D0, $00, $00, $00 // aesenc xmm0, [r8+208]
  db $66, $41, $0F, $38, $DD, $80, $E0, $00, $00, $00 // aesenclast xmm0, [r8+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
  movdqu    [rdx], xmm0
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_FOUR}
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
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
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
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
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
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
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
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
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
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
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
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
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_EIGHT}
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqu    xmm4, [rcx + 64]
  movdqu    xmm5, [rcx + 80]
  movdqu    xmm6, [rcx + 96]
  movdqu    xmm7, [rcx + 112]
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 224]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 224]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_ONE, CRYPTOLIB_AESNI_FOUR, CRYPTOLIB_AESNI_EIGHT must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
