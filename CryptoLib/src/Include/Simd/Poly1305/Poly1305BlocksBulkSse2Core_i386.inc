// Poly1305 2-way SSE2 bulk MAC kernel (i386).
// -------------------------------------------------------------------
// 2-lane (128-bit xmm) radix-2^26 narrowing of the 4-way AVX2 kernel:
// same 5x5 schoolbook multiply mod 2^130-5 (with the 5*r wraparound),
// 2 blocks per iteration against an r/r^2 power table, then a single
// pshufd-based horizontal fold of the 2 lanes.
//
// i386 has only xmm0..7 (no callee-saved xmm), so the accumulator
// H0..H4 and the transient products D0..D4 live in a 160-byte esp
// stack frame; xmm7 = mask26 and xmm6 = padbit stay resident. Every
// table/state access is an unaligned movdqu load/store (SSE memory-
// operand arithmetic would #GP on the non-16-aligned power table).
//
// On entry (after ClpSimdProc5Begin_i386.inc):
//   ebx = ACtx (72-byte R/S/H/K state); esi = APowTable (160-byte r/r^2)
//   edi = AInp; eax = ALen (multiple of 32, >= 32); ecx = APad (ignored)
//
// Power table: row j at [esi + 16*j]; rows 0..4 r-limbs [r2,r2,r2,r1],
// rows 5..8 s-limbs (5*r), row 9 pad. Bulk reads [+16*j] (broadcast r^2);
// tail reads [+16*j+4] ([r^2,r^1]).

  sub     esp, 160
  // ---- Prologue: mask26 (xmm7), padbit (xmm6) ----
  db $66, $0F, $76, $FF                           // pcmpeqd xmm7, xmm7
  db $66, $0F, $73, $D7, $26                      // psrlq xmm7, 38
  db $66, $0F, $76, $F6                           // pcmpeqd xmm6, xmm6
  db $66, $0F, $73, $D6, $3F                      // psrlq xmm6, 63
  db $66, $0F, $73, $F6, $18                      // psllq xmm6, 24
  // ---- Load H0..H4 (lane 0) into the stack frame ----
  db $66, $0F, $6E, $43, $24                      // movd xmm0, dword ptr [ebx + 36]
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $66, $0F, $6E, $43, $28                      // movd xmm0, dword ptr [ebx + 40]
  db $F3, $0F, $7F, $44, $24, $10                 // movdqu [esp + 16], xmm0
  db $66, $0F, $6E, $43, $2C                      // movd xmm0, dword ptr [ebx + 44]
  db $F3, $0F, $7F, $44, $24, $20                 // movdqu [esp + 32], xmm0
  db $66, $0F, $6E, $43, $30                      // movd xmm0, dword ptr [ebx + 48]
  db $F3, $0F, $7F, $44, $24, $30                 // movdqu [esp + 48], xmm0
  db $66, $0F, $6E, $43, $34                      // movd xmm0, dword ptr [ebx + 52]
  db $F3, $0F, $7F, $44, $24, $40                 // movdqu [esp + 64], xmm0
  // ---- Pre-loop: absorb first 2 blocks ----
  db $F3, $0F, $6F, $07                           // movdqu xmm0, [edi]
  db $F3, $0F, $6F, $4F, $10                      // movdqu xmm1, [edi + 16]
  add     edi, 32
  db $66, $0F, $6F, $D0                           // movdqa xmm2, xmm0
  db $66, $0F, $73, $DA, $06                      // psrldq xmm2, 6
  db $66, $0F, $6F, $D9                           // movdqa xmm3, xmm1
  db $66, $0F, $73, $DB, $06                      // psrldq xmm3, 6
  db $66, $0F, $6F, $E0                           // movdqa xmm4, xmm0
  db $66, $0F, $6D, $E1                           // punpckhqdq xmm4, xmm1
  db $66, $0F, $6C, $C1                           // punpcklqdq xmm0, xmm1
  db $66, $0F, $6C, $D3                           // punpcklqdq xmm2, xmm3
  db $66, $0F, $6F, $DA                           // movdqa xmm3, xmm2
  db $66, $0F, $73, $D3, $1E                      // psrlq xmm3, 30
  db $66, $0F, $73, $D2, $04                      // psrlq xmm2, 4
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $73, $D4, $28                      // psrlq xmm4, 40
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $66, $0F, $DB, $CF                           // pand xmm1, xmm7
  db $66, $0F, $DB, $D7                           // pand xmm2, xmm7
  db $66, $0F, $DB, $DF                           // pand xmm3, xmm7
  db $66, $0F, $EB, $E6                           // por xmm4, xmm6
  db $F3, $0F, $6F, $2C, $24                      // movdqu xmm5, [esp]
  db $66, $0F, $D4, $E8                           // paddq xmm5, xmm0
  db $F3, $0F, $7F, $2C, $24                      // movdqu [esp], xmm5
  db $F3, $0F, $6F, $6C, $24, $10                 // movdqu xmm5, [esp + 16]
  db $66, $0F, $D4, $E9                           // paddq xmm5, xmm1
  db $F3, $0F, $7F, $6C, $24, $10                 // movdqu [esp + 16], xmm5
  db $F3, $0F, $6F, $6C, $24, $20                 // movdqu xmm5, [esp + 32]
  db $66, $0F, $D4, $EA                           // paddq xmm5, xmm2
  db $F3, $0F, $7F, $6C, $24, $20                 // movdqu [esp + 32], xmm5
  db $F3, $0F, $6F, $6C, $24, $30                 // movdqu xmm5, [esp + 48]
  db $66, $0F, $D4, $EB                           // paddq xmm5, xmm3
  db $F3, $0F, $7F, $6C, $24, $30                 // movdqu [esp + 48], xmm5
  db $F3, $0F, $6F, $6C, $24, $40                 // movdqu xmm5, [esp + 64]
  db $66, $0F, $D4, $EC                           // paddq xmm5, xmm4
  db $F3, $0F, $7F, $6C, $24, $40                 // movdqu [esp + 64], xmm5
  sub     eax, 32
  jz      @@poly1305_sse2_tail

@@poly1305_sse2_loop:
  // ---- Bulk: H *= r^2 (broadcast) ----
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $40                      // movdqu xmm1, [esi + 64]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $56, $30                      // movdqu xmm2, [esi + 48]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $56, $20                      // movdqu xmm2, [esi + 32]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $56, $10                      // movdqu xmm2, [esi + 16]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $16                           // movdqu xmm2, [esi]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $84, $24, $90, $00, $00, $00  // movdqu [esp + 144], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $30                      // movdqu xmm1, [esi + 48]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $56, $20                      // movdqu xmm2, [esi + 32]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $56, $10                      // movdqu xmm2, [esi + 16]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $16                           // movdqu xmm2, [esi]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $96, $80, $00, $00, $00       // movdqu xmm2, [esi + 128]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $84, $24, $80, $00, $00, $00  // movdqu [esp + 128], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $20                      // movdqu xmm1, [esi + 32]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $56, $10                      // movdqu xmm2, [esi + 16]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $16                           // movdqu xmm2, [esi]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $96, $80, $00, $00, $00       // movdqu xmm2, [esi + 128]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $56, $70                      // movdqu xmm2, [esi + 112]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $70                 // movdqu [esp + 112], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $10                      // movdqu xmm1, [esi + 16]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $16                           // movdqu xmm2, [esi]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $96, $80, $00, $00, $00       // movdqu xmm2, [esi + 128]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $56, $70                      // movdqu xmm2, [esi + 112]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $56, $60                      // movdqu xmm2, [esi + 96]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $60                 // movdqu [esp + 96], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $0E                           // movdqu xmm1, [esi]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $96, $80, $00, $00, $00       // movdqu xmm2, [esi + 128]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $56, $70                      // movdqu xmm2, [esi + 112]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $56, $60                      // movdqu xmm2, [esi + 96]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $56, $50                      // movdqu xmm2, [esi + 80]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $50                 // movdqu [esp + 80], xmm0
  // ---- Lazy reduce D -> H ----
  db $F3, $0F, $6F, $44, $24, $50                 // movdqu xmm0, [esp + 80]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $F3, $0F, $6F, $54, $24, $60                 // movdqu xmm2, [esp + 96]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $60                 // movdqu [esp + 96], xmm2
  db $F3, $0F, $6F, $44, $24, $60                 // movdqu xmm0, [esp + 96]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $10                 // movdqu [esp + 16], xmm0
  db $F3, $0F, $6F, $54, $24, $70                 // movdqu xmm2, [esp + 112]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $70                 // movdqu [esp + 112], xmm2
  db $F3, $0F, $6F, $44, $24, $70                 // movdqu xmm0, [esp + 112]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $20                 // movdqu [esp + 32], xmm0
  db $F3, $0F, $6F, $94, $24, $80, $00, $00, $00  // movdqu xmm2, [esp + 128]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $94, $24, $80, $00, $00, $00  // movdqu [esp + 128], xmm2
  db $F3, $0F, $6F, $84, $24, $80, $00, $00, $00  // movdqu xmm0, [esp + 128]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $30                 // movdqu [esp + 48], xmm0
  db $F3, $0F, $6F, $94, $24, $90, $00, $00, $00  // movdqu xmm2, [esp + 144]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $94, $24, $90, $00, $00, $00  // movdqu [esp + 144], xmm2
  db $F3, $0F, $6F, $84, $24, $90, $00, $00, $00  // movdqu xmm0, [esp + 144]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $40                 // movdqu [esp + 64], xmm0
  db $66, $0F, $6F, $D1                           // movdqa xmm2, xmm1
  db $66, $0F, $73, $F2, $02                      // psllq xmm2, 2
  db $66, $0F, $D4, $CA                           // paddq xmm1, xmm2
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $F3, $0F, $6F, $54, $24, $10                 // movdqu xmm2, [esp + 16]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $10                 // movdqu [esp + 16], xmm2
  // ---- Absorb next 2 blocks ----
  db $F3, $0F, $6F, $07                           // movdqu xmm0, [edi]
  db $F3, $0F, $6F, $4F, $10                      // movdqu xmm1, [edi + 16]
  add     edi, 32
  db $66, $0F, $6F, $D0                           // movdqa xmm2, xmm0
  db $66, $0F, $73, $DA, $06                      // psrldq xmm2, 6
  db $66, $0F, $6F, $D9                           // movdqa xmm3, xmm1
  db $66, $0F, $73, $DB, $06                      // psrldq xmm3, 6
  db $66, $0F, $6F, $E0                           // movdqa xmm4, xmm0
  db $66, $0F, $6D, $E1                           // punpckhqdq xmm4, xmm1
  db $66, $0F, $6C, $C1                           // punpcklqdq xmm0, xmm1
  db $66, $0F, $6C, $D3                           // punpcklqdq xmm2, xmm3
  db $66, $0F, $6F, $DA                           // movdqa xmm3, xmm2
  db $66, $0F, $73, $D3, $1E                      // psrlq xmm3, 30
  db $66, $0F, $73, $D2, $04                      // psrlq xmm2, 4
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $73, $D4, $28                      // psrlq xmm4, 40
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $66, $0F, $DB, $CF                           // pand xmm1, xmm7
  db $66, $0F, $DB, $D7                           // pand xmm2, xmm7
  db $66, $0F, $DB, $DF                           // pand xmm3, xmm7
  db $66, $0F, $EB, $E6                           // por xmm4, xmm6
  db $F3, $0F, $6F, $2C, $24                      // movdqu xmm5, [esp]
  db $66, $0F, $D4, $E8                           // paddq xmm5, xmm0
  db $F3, $0F, $7F, $2C, $24                      // movdqu [esp], xmm5
  db $F3, $0F, $6F, $6C, $24, $10                 // movdqu xmm5, [esp + 16]
  db $66, $0F, $D4, $E9                           // paddq xmm5, xmm1
  db $F3, $0F, $7F, $6C, $24, $10                 // movdqu [esp + 16], xmm5
  db $F3, $0F, $6F, $6C, $24, $20                 // movdqu xmm5, [esp + 32]
  db $66, $0F, $D4, $EA                           // paddq xmm5, xmm2
  db $F3, $0F, $7F, $6C, $24, $20                 // movdqu [esp + 32], xmm5
  db $F3, $0F, $6F, $6C, $24, $30                 // movdqu xmm5, [esp + 48]
  db $66, $0F, $D4, $EB                           // paddq xmm5, xmm3
  db $F3, $0F, $7F, $6C, $24, $30                 // movdqu [esp + 48], xmm5
  db $F3, $0F, $6F, $6C, $24, $40                 // movdqu xmm5, [esp + 64]
  db $66, $0F, $D4, $EC                           // paddq xmm5, xmm4
  db $F3, $0F, $7F, $6C, $24, $40                 // movdqu [esp + 64], xmm5
  sub     eax, 32
  jnz     @@poly1305_sse2_loop

@@poly1305_sse2_tail:
  // ---- Tail: H *= [r^2, r^1] (shifted table read) ----
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $44                      // movdqu xmm1, [esi + 68]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $56, $34                      // movdqu xmm2, [esi + 52]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $56, $24                      // movdqu xmm2, [esi + 36]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $56, $14                      // movdqu xmm2, [esi + 20]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $56, $04                      // movdqu xmm2, [esi + 4]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $84, $24, $90, $00, $00, $00  // movdqu [esp + 144], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $34                      // movdqu xmm1, [esi + 52]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $56, $24                      // movdqu xmm2, [esi + 36]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $56, $14                      // movdqu xmm2, [esi + 20]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $56, $04                      // movdqu xmm2, [esi + 4]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $96, $84, $00, $00, $00       // movdqu xmm2, [esi + 132]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $84, $24, $80, $00, $00, $00  // movdqu [esp + 128], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $24                      // movdqu xmm1, [esi + 36]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $56, $14                      // movdqu xmm2, [esi + 20]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $56, $04                      // movdqu xmm2, [esi + 4]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $96, $84, $00, $00, $00       // movdqu xmm2, [esi + 132]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $56, $74                      // movdqu xmm2, [esi + 116]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $70                 // movdqu [esp + 112], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $14                      // movdqu xmm1, [esi + 20]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $56, $04                      // movdqu xmm2, [esi + 4]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $96, $84, $00, $00, $00       // movdqu xmm2, [esi + 132]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $56, $74                      // movdqu xmm2, [esi + 116]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $56, $64                      // movdqu xmm2, [esi + 100]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $60                 // movdqu [esp + 96], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $F3, $0F, $6F, $4E, $04                      // movdqu xmm1, [esi + 4]
  db $66, $0F, $F4, $C1                           // pmuludq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $10                 // movdqu xmm1, [esp + 16]
  db $F3, $0F, $6F, $96, $84, $00, $00, $00       // movdqu xmm2, [esi + 132]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $20                 // movdqu xmm1, [esp + 32]
  db $F3, $0F, $6F, $56, $74                      // movdqu xmm2, [esi + 116]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $30                 // movdqu xmm1, [esp + 48]
  db $F3, $0F, $6F, $56, $64                      // movdqu xmm2, [esi + 100]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $6F, $4C, $24, $40                 // movdqu xmm1, [esp + 64]
  db $F3, $0F, $6F, $56, $54                      // movdqu xmm2, [esi + 84]
  db $66, $0F, $F4, $CA                           // pmuludq xmm1, xmm2
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $50                 // movdqu [esp + 80], xmm0
  db $F3, $0F, $6F, $44, $24, $50                 // movdqu xmm0, [esp + 80]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $F3, $0F, $6F, $54, $24, $60                 // movdqu xmm2, [esp + 96]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $60                 // movdqu [esp + 96], xmm2
  db $F3, $0F, $6F, $44, $24, $60                 // movdqu xmm0, [esp + 96]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $10                 // movdqu [esp + 16], xmm0
  db $F3, $0F, $6F, $54, $24, $70                 // movdqu xmm2, [esp + 112]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $70                 // movdqu [esp + 112], xmm2
  db $F3, $0F, $6F, $44, $24, $70                 // movdqu xmm0, [esp + 112]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $20                 // movdqu [esp + 32], xmm0
  db $F3, $0F, $6F, $94, $24, $80, $00, $00, $00  // movdqu xmm2, [esp + 128]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $94, $24, $80, $00, $00, $00  // movdqu [esp + 128], xmm2
  db $F3, $0F, $6F, $84, $24, $80, $00, $00, $00  // movdqu xmm0, [esp + 128]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $30                 // movdqu [esp + 48], xmm0
  db $F3, $0F, $6F, $94, $24, $90, $00, $00, $00  // movdqu xmm2, [esp + 144]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $94, $24, $90, $00, $00, $00  // movdqu [esp + 144], xmm2
  db $F3, $0F, $6F, $84, $24, $90, $00, $00, $00  // movdqu xmm0, [esp + 144]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $40                 // movdqu [esp + 64], xmm0
  db $66, $0F, $6F, $D1                           // movdqa xmm2, xmm1
  db $66, $0F, $73, $F2, $02                      // psllq xmm2, 2
  db $66, $0F, $D4, $CA                           // paddq xmm1, xmm2
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $F3, $0F, $6F, $54, $24, $10                 // movdqu xmm2, [esp + 16]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $10                 // movdqu [esp + 16], xmm2
  // ---- Horizontal fold 2 lanes -> 1, final reduce, store ----
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $66, $0F, $70, $C8, $4E                      // pshufd xmm1, xmm0, 0x4E
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $F3, $0F, $6F, $44, $24, $10                 // movdqu xmm0, [esp + 16]
  db $66, $0F, $70, $C8, $4E                      // pshufd xmm1, xmm0, 0x4E
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $10                 // movdqu [esp + 16], xmm0
  db $F3, $0F, $6F, $44, $24, $20                 // movdqu xmm0, [esp + 32]
  db $66, $0F, $70, $C8, $4E                      // pshufd xmm1, xmm0, 0x4E
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $20                 // movdqu [esp + 32], xmm0
  db $F3, $0F, $6F, $44, $24, $30                 // movdqu xmm0, [esp + 48]
  db $66, $0F, $70, $C8, $4E                      // pshufd xmm1, xmm0, 0x4E
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $30                 // movdqu [esp + 48], xmm0
  db $F3, $0F, $6F, $44, $24, $40                 // movdqu xmm0, [esp + 64]
  db $66, $0F, $70, $C8, $4E                      // pshufd xmm1, xmm0, 0x4E
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $F3, $0F, $7F, $44, $24, $40                 // movdqu [esp + 64], xmm0
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $F3, $0F, $6F, $54, $24, $10                 // movdqu xmm2, [esp + 16]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $10                 // movdqu [esp + 16], xmm2
  db $F3, $0F, $6F, $44, $24, $10                 // movdqu xmm0, [esp + 16]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $10                 // movdqu [esp + 16], xmm0
  db $F3, $0F, $6F, $54, $24, $20                 // movdqu xmm2, [esp + 32]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $20                 // movdqu [esp + 32], xmm2
  db $F3, $0F, $6F, $44, $24, $20                 // movdqu xmm0, [esp + 32]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $20                 // movdqu [esp + 32], xmm0
  db $F3, $0F, $6F, $54, $24, $30                 // movdqu xmm2, [esp + 48]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $30                 // movdqu [esp + 48], xmm2
  db $F3, $0F, $6F, $44, $24, $30                 // movdqu xmm0, [esp + 48]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $30                 // movdqu [esp + 48], xmm0
  db $F3, $0F, $6F, $54, $24, $40                 // movdqu xmm2, [esp + 64]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $40                 // movdqu [esp + 64], xmm2
  db $F3, $0F, $6F, $44, $24, $40                 // movdqu xmm0, [esp + 64]
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $44, $24, $40                 // movdqu [esp + 64], xmm0
  db $66, $0F, $6F, $D1                           // movdqa xmm2, xmm1
  db $66, $0F, $73, $F2, $02                      // psllq xmm2, 2
  db $66, $0F, $D4, $CA                           // paddq xmm1, xmm2
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $66, $0F, $D4, $C1                           // paddq xmm0, xmm1
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0
  db $66, $0F, $73, $D1, $1A                      // psrlq xmm1, 26
  db $66, $0F, $DB, $C7                           // pand xmm0, xmm7
  db $F3, $0F, $7F, $04, $24                      // movdqu [esp], xmm0
  db $F3, $0F, $6F, $54, $24, $10                 // movdqu xmm2, [esp + 16]
  db $66, $0F, $D4, $D1                           // paddq xmm2, xmm1
  db $F3, $0F, $7F, $54, $24, $10                 // movdqu [esp + 16], xmm2
  db $F3, $0F, $6F, $04, $24                      // movdqu xmm0, [esp]
  db $66, $0F, $7E, $43, $24                      // movd dword ptr [ebx + 36], xmm0
  db $F3, $0F, $6F, $44, $24, $10                 // movdqu xmm0, [esp + 16]
  db $66, $0F, $7E, $43, $28                      // movd dword ptr [ebx + 40], xmm0
  db $F3, $0F, $6F, $44, $24, $20                 // movdqu xmm0, [esp + 32]
  db $66, $0F, $7E, $43, $2C                      // movd dword ptr [ebx + 44], xmm0
  db $F3, $0F, $6F, $44, $24, $30                 // movdqu xmm0, [esp + 48]
  db $66, $0F, $7E, $43, $30                      // movd dword ptr [ebx + 48], xmm0
  db $F3, $0F, $6F, $44, $24, $40                 // movdqu xmm0, [esp + 64]
  db $66, $0F, $7E, $43, $34                      // movd dword ptr [ebx + 52], xmm0
  add     esp, 160
  pop     edi
  pop     esi
  pop     ebx
