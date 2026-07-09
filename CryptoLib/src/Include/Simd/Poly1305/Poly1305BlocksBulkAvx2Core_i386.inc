// Poly1305 4-way AVX2 bulk MAC kernel (i386).
// -------------------------------------------------------------------
// Goll-Gueron / Polyakov: 4 blocks per iteration in 4 ymm lanes against an
// r^1..r^4 power table (320 bytes, 32-byte rows). radix-2^26 schoolbook
// multiply mod 2^130-5 (5*r wraparound); VEX tolerates unaligned memory so
// the table is read straight into vpmuludq. The bulk-loop carry-reduce uses
// the carry-reduce stays serial: i386 has only ymm0..7, and the two-chain
// schedule the x86-64 kernel uses needs a second carry temp that would
// clobber padbit (rebuild each iter) - measured slower on this
// throughput-bound, spill-heavy loop. D0..D4 and an H backup live in a
// 320-byte esp frame; the multiply spills each product accumulator per term.
//
// On entry (after ClpSimdProc5Begin_i386.inc):
//   ebx = ACtx (72-byte R/S/H/K state); esi = APowTable (320-byte r^1..r^4)
//   edi = AInp; eax = ALen (multiple of 64, >= 64); ecx = APad (ignored)
//
// Power table: row j at [esi + 32*j]; rows 0..4 r-limbs, rows 5..8 s-limbs
// (5*r), row 9 pad. Bulk reads [+32*j] (broadcast r^4); tail reads
// [+32*j+4] ([r^4,r^3,r^2,r^1]).

  sub        esp, 320
  // ---- Prologue: mask26 (ymm5), padbit (ymm6) ----
  db $C5, $D5, $76, $ED                           // vpcmpeqd ymm5, ymm5, ymm5
  db $C5, $D5, $73, $D5, $26                      // vpsrlq ymm5, ymm5, 38
  db $C5, $CD, $76, $F6                           // vpcmpeqd ymm6, ymm6, ymm6
  db $C5, $CD, $73, $D6, $3F                      // vpsrlq ymm6, ymm6, 63
  db $C5, $CD, $73, $F6, $18                      // vpsllq ymm6, ymm6, 24
  // ---- Load H0..H4 into lane 0 ----
  db $C5, $F9, $6E, $43, $24                      // vmovd xmm0, dword ptr [ebx + 36]
  db $C5, $F9, $6E, $4B, $28                      // vmovd xmm1, dword ptr [ebx + 40]
  db $C5, $F9, $6E, $53, $2C                      // vmovd xmm2, dword ptr [ebx + 44]
  db $C5, $F9, $6E, $5B, $30                      // vmovd xmm3, dword ptr [ebx + 48]
  db $C5, $F9, $6E, $63, $34                      // vmovd xmm4, dword ptr [ebx + 52]
  // ---- Pre-loop: spill H, absorb first 4 blocks ----
  db $C5, $FE, $7F, $84, $24, $A0, $00, $00, $00  // vmovdqu [esp + 160], ymm0
  db $C5, $FE, $7F, $8C, $24, $C0, $00, $00, $00  // vmovdqu [esp + 192], ymm1
  db $C5, $FE, $7F, $94, $24, $E0, $00, $00, $00  // vmovdqu [esp + 224], ymm2
  db $C5, $FE, $7F, $9C, $24, $00, $01, $00, $00  // vmovdqu [esp + 256], ymm3
  db $C5, $FE, $7F, $A4, $24, $20, $01, $00, $00  // vmovdqu [esp + 288], ymm4
  db $C5, $FA, $6F, $07                           // vmovdqu xmm0, [edi]
  db $C5, $FA, $6F, $4F, $10                      // vmovdqu xmm1, [edi + 16]
  db $C4, $E3, $7D, $38, $47, $20, $01            // vinserti128 ymm0, ymm0, [edi + 32], 1
  db $C4, $E3, $75, $38, $4F, $30, $01            // vinserti128 ymm1, ymm1, [edi + 48], 1
  add  edi, 64
  db $C5, $ED, $73, $D8, $06                      // vpsrldq ymm2, ymm0, 6
  db $C5, $E5, $73, $D9, $06                      // vpsrldq ymm3, ymm1, 6
  db $C5, $FD, $6D, $E1                           // vpunpckhqdq ymm4, ymm0, ymm1
  db $C5, $FD, $6C, $C1                           // vpunpcklqdq ymm0, ymm0, ymm1
  db $C5, $ED, $6C, $D3                           // vpunpcklqdq ymm2, ymm2, ymm3
  db $C5, $E5, $73, $D2, $1E                      // vpsrlq ymm3, ymm2, 30
  db $C5, $ED, $73, $D2, $04                      // vpsrlq ymm2, ymm2, 4
  db $C5, $F5, $73, $D0, $1A                      // vpsrlq ymm1, ymm0, 26
  db $C5, $DD, $73, $D4, $28                      // vpsrlq ymm4, ymm4, 40
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $DB, $CD                           // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $DB, $D5                           // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $DB, $DD                           // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $EB, $E6                           // vpor ymm4, ymm4, ymm6
  db $C5, $FD, $D4, $84, $24, $A0, $00, $00, $00  // vpaddq ymm0, ymm0, [esp + 160]
  db $C5, $F5, $D4, $8C, $24, $C0, $00, $00, $00  // vpaddq ymm1, ymm1, [esp + 192]
  db $C5, $ED, $D4, $94, $24, $E0, $00, $00, $00  // vpaddq ymm2, ymm2, [esp + 224]
  db $C5, $E5, $D4, $9C, $24, $00, $01, $00, $00  // vpaddq ymm3, ymm3, [esp + 256]
  db $C5, $DD, $D4, $A4, $24, $20, $01, $00, $00  // vpaddq ymm4, ymm4, [esp + 288]
  sub  eax, 64
  jz   @@poly1305_avx2_i386_tail

@@poly1305_avx2_i386_loop:
  // ---- Bulk: H *= r^4 (broadcast), D0..D4 spilled ----
  db $C5, $FD, $F4, $BE, $80, $00, $00, $00       // vpmuludq ymm7, ymm0, [esi + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $F5, $F4, $7E, $60                      // vpmuludq ymm7, ymm1, [esi + 96]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $ED, $F4, $7E, $40                      // vpmuludq ymm7, ymm2, [esi + 64]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $E5, $F4, $7E, $20                      // vpmuludq ymm7, ymm3, [esi + 32]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $DD, $F4, $3E                           // vpmuludq ymm7, ymm4, [esi]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $FD, $F4, $7E, $60                      // vpmuludq ymm7, ymm0, [esi + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $F5, $F4, $7E, $40                      // vpmuludq ymm7, ymm1, [esi + 64]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $ED, $F4, $7E, $20                      // vpmuludq ymm7, ymm2, [esi + 32]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $E5, $F4, $3E                           // vpmuludq ymm7, ymm3, [esi]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $DD, $F4, $BE, $00, $01, $00, $00       // vpmuludq ymm7, ymm4, [esi + 256]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $FD, $F4, $7E, $40                      // vpmuludq ymm7, ymm0, [esi + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $F5, $F4, $7E, $20                      // vpmuludq ymm7, ymm1, [esi + 32]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $ED, $F4, $3E                           // vpmuludq ymm7, ymm2, [esi]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $E5, $F4, $BE, $00, $01, $00, $00       // vpmuludq ymm7, ymm3, [esi + 256]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $DD, $F4, $BE, $E0, $00, $00, $00       // vpmuludq ymm7, ymm4, [esi + 224]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $FD, $F4, $7E, $20                      // vpmuludq ymm7, ymm0, [esi + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $F5, $F4, $3E                           // vpmuludq ymm7, ymm1, [esi]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $ED, $F4, $BE, $00, $01, $00, $00       // vpmuludq ymm7, ymm2, [esi + 256]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $E5, $F4, $BE, $E0, $00, $00, $00       // vpmuludq ymm7, ymm3, [esi + 224]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $DD, $F4, $BE, $C0, $00, $00, $00       // vpmuludq ymm7, ymm4, [esi + 192]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $FD, $F4, $3E                           // vpmuludq ymm7, ymm0, [esi]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $F5, $F4, $BE, $00, $01, $00, $00       // vpmuludq ymm7, ymm1, [esi + 256]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $ED, $F4, $BE, $E0, $00, $00, $00       // vpmuludq ymm7, ymm2, [esi + 224]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $E5, $F4, $BE, $C0, $00, $00, $00       // vpmuludq ymm7, ymm3, [esi + 192]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $DD, $F4, $BE, $A0, $00, $00, $00       // vpmuludq ymm7, ymm4, [esi + 160]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  // ---- Lazy reduce ----
  db $C5, $FE, $6F, $04, $24                      // vmovdqu ymm0, [esp]
  db $C5, $FE, $6F, $4C, $24, $20                 // vmovdqu ymm1, [esp + 32]
  db $C5, $FE, $6F, $54, $24, $40                 // vmovdqu ymm2, [esp + 64]
  db $C5, $FE, $6F, $5C, $24, $60                 // vmovdqu ymm3, [esp + 96]
  db $C5, $FE, $6F, $A4, $24, $80, $00, $00, $00  // vmovdqu ymm4, [esp + 128]
  db $C5, $C5, $73, $D0, $1A                      // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $D1, $1A                      // vpsrlq ymm7, ymm1, 26
  db $C5, $F5, $DB, $CD                           // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $D4, $D7                           // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $D2, $1A                      // vpsrlq ymm7, ymm2, 26
  db $C5, $ED, $DB, $D5                           // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $D4, $DF                           // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $D3, $1A                      // vpsrlq ymm7, ymm3, 26
  db $C5, $E5, $DB, $DD                           // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $D4, $E7                           // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $D4, $1A                      // vpsrlq ymm7, ymm4, 26
  db $C5, $DD, $DB, $E5                           // vpand ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $C5, $73, $F7, $02                      // vpsllq ymm7, ymm7, 2
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FD, $D4, $C7                           // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D0, $1A                      // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  // ---- Absorb next 4 blocks ----
  db $C5, $FE, $7F, $84, $24, $A0, $00, $00, $00  // vmovdqu [esp + 160], ymm0
  db $C5, $FE, $7F, $8C, $24, $C0, $00, $00, $00  // vmovdqu [esp + 192], ymm1
  db $C5, $FE, $7F, $94, $24, $E0, $00, $00, $00  // vmovdqu [esp + 224], ymm2
  db $C5, $FE, $7F, $9C, $24, $00, $01, $00, $00  // vmovdqu [esp + 256], ymm3
  db $C5, $FE, $7F, $A4, $24, $20, $01, $00, $00  // vmovdqu [esp + 288], ymm4
  db $C5, $FA, $6F, $07                           // vmovdqu xmm0, [edi]
  db $C5, $FA, $6F, $4F, $10                      // vmovdqu xmm1, [edi + 16]
  db $C4, $E3, $7D, $38, $47, $20, $01            // vinserti128 ymm0, ymm0, [edi + 32], 1
  db $C4, $E3, $75, $38, $4F, $30, $01            // vinserti128 ymm1, ymm1, [edi + 48], 1
  add  edi, 64
  db $C5, $ED, $73, $D8, $06                      // vpsrldq ymm2, ymm0, 6
  db $C5, $E5, $73, $D9, $06                      // vpsrldq ymm3, ymm1, 6
  db $C5, $FD, $6D, $E1                           // vpunpckhqdq ymm4, ymm0, ymm1
  db $C5, $FD, $6C, $C1                           // vpunpcklqdq ymm0, ymm0, ymm1
  db $C5, $ED, $6C, $D3                           // vpunpcklqdq ymm2, ymm2, ymm3
  db $C5, $E5, $73, $D2, $1E                      // vpsrlq ymm3, ymm2, 30
  db $C5, $ED, $73, $D2, $04                      // vpsrlq ymm2, ymm2, 4
  db $C5, $F5, $73, $D0, $1A                      // vpsrlq ymm1, ymm0, 26
  db $C5, $DD, $73, $D4, $28                      // vpsrlq ymm4, ymm4, 40
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $DB, $CD                           // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $DB, $D5                           // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $DB, $DD                           // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $EB, $E6                           // vpor ymm4, ymm4, ymm6
  db $C5, $FD, $D4, $84, $24, $A0, $00, $00, $00  // vpaddq ymm0, ymm0, [esp + 160]
  db $C5, $F5, $D4, $8C, $24, $C0, $00, $00, $00  // vpaddq ymm1, ymm1, [esp + 192]
  db $C5, $ED, $D4, $94, $24, $E0, $00, $00, $00  // vpaddq ymm2, ymm2, [esp + 224]
  db $C5, $E5, $D4, $9C, $24, $00, $01, $00, $00  // vpaddq ymm3, ymm3, [esp + 256]
  db $C5, $DD, $D4, $A4, $24, $20, $01, $00, $00  // vpaddq ymm4, ymm4, [esp + 288]
  sub  eax, 64
  jnz  @@poly1305_avx2_i386_loop

@@poly1305_avx2_i386_tail:
  // ---- Tail: H *= [r^1, r^2, r^3, r^4] (shifted table read) ----
  db $C5, $FD, $F4, $BE, $84, $00, $00, $00       // vpmuludq ymm7, ymm0, [esi + 132]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $F5, $F4, $7E, $64                      // vpmuludq ymm7, ymm1, [esi + 100]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $ED, $F4, $7E, $44                      // vpmuludq ymm7, ymm2, [esi + 68]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $E5, $F4, $7E, $24                      // vpmuludq ymm7, ymm3, [esi + 36]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $DD, $F4, $7E, $04                      // vpmuludq ymm7, ymm4, [esi + 4]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00  // vpaddq ymm7, ymm7, [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00  // vmovdqu [esp + 128], ymm7
  db $C5, $FD, $F4, $7E, $64                      // vpmuludq ymm7, ymm0, [esi + 100]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $F5, $F4, $7E, $44                      // vpmuludq ymm7, ymm1, [esi + 68]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $ED, $F4, $7E, $24                      // vpmuludq ymm7, ymm2, [esi + 36]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $E5, $F4, $7E, $04                      // vpmuludq ymm7, ymm3, [esi + 4]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $DD, $F4, $BE, $04, $01, $00, $00       // vpmuludq ymm7, ymm4, [esi + 260]
  db $C5, $C5, $D4, $7C, $24, $60                 // vpaddq ymm7, ymm7, [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                 // vmovdqu [esp + 96], ymm7
  db $C5, $FD, $F4, $7E, $44                      // vpmuludq ymm7, ymm0, [esi + 68]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $F5, $F4, $7E, $24                      // vpmuludq ymm7, ymm1, [esi + 36]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $ED, $F4, $7E, $04                      // vpmuludq ymm7, ymm2, [esi + 4]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $E5, $F4, $BE, $04, $01, $00, $00       // vpmuludq ymm7, ymm3, [esi + 260]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $DD, $F4, $BE, $E4, $00, $00, $00       // vpmuludq ymm7, ymm4, [esi + 228]
  db $C5, $C5, $D4, $7C, $24, $40                 // vpaddq ymm7, ymm7, [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                 // vmovdqu [esp + 64], ymm7
  db $C5, $FD, $F4, $7E, $24                      // vpmuludq ymm7, ymm0, [esi + 36]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $F5, $F4, $7E, $04                      // vpmuludq ymm7, ymm1, [esi + 4]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $ED, $F4, $BE, $04, $01, $00, $00       // vpmuludq ymm7, ymm2, [esi + 260]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $E5, $F4, $BE, $E4, $00, $00, $00       // vpmuludq ymm7, ymm3, [esi + 228]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $DD, $F4, $BE, $C4, $00, $00, $00       // vpmuludq ymm7, ymm4, [esi + 196]
  db $C5, $C5, $D4, $7C, $24, $20                 // vpaddq ymm7, ymm7, [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                 // vmovdqu [esp + 32], ymm7
  db $C5, $FD, $F4, $7E, $04                      // vpmuludq ymm7, ymm0, [esi + 4]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $F5, $F4, $BE, $04, $01, $00, $00       // vpmuludq ymm7, ymm1, [esi + 260]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $ED, $F4, $BE, $E4, $00, $00, $00       // vpmuludq ymm7, ymm2, [esi + 228]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $E5, $F4, $BE, $C4, $00, $00, $00       // vpmuludq ymm7, ymm3, [esi + 196]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $DD, $F4, $BE, $A4, $00, $00, $00       // vpmuludq ymm7, ymm4, [esi + 164]
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  // ---- Tail lazy reduce ----
  db $C5, $FE, $6F, $04, $24                      // vmovdqu ymm0, [esp]
  db $C5, $FE, $6F, $4C, $24, $20                 // vmovdqu ymm1, [esp + 32]
  db $C5, $FE, $6F, $54, $24, $40                 // vmovdqu ymm2, [esp + 64]
  db $C5, $FE, $6F, $5C, $24, $60                 // vmovdqu ymm3, [esp + 96]
  db $C5, $FE, $6F, $A4, $24, $80, $00, $00, $00  // vmovdqu ymm4, [esp + 128]
  db $C5, $C5, $73, $D0, $1A                      // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $D1, $1A                      // vpsrlq ymm7, ymm1, 26
  db $C5, $F5, $DB, $CD                           // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $D4, $D7                           // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $D2, $1A                      // vpsrlq ymm7, ymm2, 26
  db $C5, $ED, $DB, $D5                           // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $D4, $DF                           // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $D3, $1A                      // vpsrlq ymm7, ymm3, 26
  db $C5, $E5, $DB, $DD                           // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $D4, $E7                           // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $D4, $1A                      // vpsrlq ymm7, ymm4, 26
  db $C5, $DD, $DB, $E5                           // vpand ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $C5, $73, $F7, $02                      // vpsllq ymm7, ymm7, 2
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FD, $D4, $C7                           // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D0, $1A                      // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  // ---- Horizontal sum 4 lanes -> lane 0 ----
  db $C5, $C5, $73, $D8, $08                      // vpsrldq ymm7, ymm0, 8
  db $C5, $FD, $D4, $C7                           // vpaddq ymm0, ymm0, ymm7
  db $C4, $E3, $FD, $00, $F8, $4E                 // vpermq ymm7, ymm0, 0x4E
  db $C5, $FD, $D4, $C7                           // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D9, $08                      // vpsrldq ymm7, ymm1, 8
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  db $C4, $E3, $FD, $00, $F9, $4E                 // vpermq ymm7, ymm1, 0x4E
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $DA, $08                      // vpsrldq ymm7, ymm2, 8
  db $C5, $ED, $D4, $D7                           // vpaddq ymm2, ymm2, ymm7
  db $C4, $E3, $FD, $00, $FA, $4E                 // vpermq ymm7, ymm2, 0x4E
  db $C5, $ED, $D4, $D7                           // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $DB, $08                      // vpsrldq ymm7, ymm3, 8
  db $C5, $E5, $D4, $DF                           // vpaddq ymm3, ymm3, ymm7
  db $C4, $E3, $FD, $00, $FB, $4E                 // vpermq ymm7, ymm3, 0x4E
  db $C5, $E5, $D4, $DF                           // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $DC, $08                      // vpsrldq ymm7, ymm4, 8
  db $C5, $DD, $D4, $E7                           // vpaddq ymm4, ymm4, ymm7
  db $C4, $E3, $FD, $00, $FC, $4E                 // vpermq ymm7, ymm4, 0x4E
  db $C5, $DD, $D4, $E7                           // vpaddq ymm4, ymm4, ymm7
  // ---- Final lazy reduce (lane 0 scalars) ----
  db $C5, $C5, $73, $D0, $1A                      // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $D1, $1A                      // vpsrlq ymm7, ymm1, 26
  db $C5, $F5, $DB, $CD                           // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $D4, $D7                           // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $D2, $1A                      // vpsrlq ymm7, ymm2, 26
  db $C5, $ED, $DB, $D5                           // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $D4, $DF                           // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $D3, $1A                      // vpsrlq ymm7, ymm3, 26
  db $C5, $E5, $DB, $DD                           // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $D4, $E7                           // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $D4, $1A                      // vpsrlq ymm7, ymm4, 26
  db $C5, $DD, $DB, $E5                           // vpand ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $3C, $24                      // vmovdqu [esp], ymm7
  db $C5, $C5, $73, $F7, $02                      // vpsllq ymm7, ymm7, 2
  db $C5, $C5, $D4, $3C, $24                      // vpaddq ymm7, ymm7, [esp]
  db $C5, $FD, $D4, $C7                           // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D0, $1A                      // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                           // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                           // vpaddq ymm1, ymm1, ymm7
  // ---- Store H0..H4 back to ctx ----
  db $C5, $F9, $7E, $43, $24                      // vmovd dword ptr [ebx + 36], xmm0
  db $C5, $F9, $7E, $4B, $28                      // vmovd dword ptr [ebx + 40], xmm1
  db $C5, $F9, $7E, $53, $2C                      // vmovd dword ptr [ebx + 44], xmm2
  db $C5, $F9, $7E, $5B, $30                      // vmovd dword ptr [ebx + 48], xmm3
  db $C5, $F9, $7E, $63, $34                      // vmovd dword ptr [ebx + 52], xmm4
  db $C5, $F8, $77                                // vzeroupper
  add  esp, 320
  pop  edi
  pop  esi
  pop  ebx
