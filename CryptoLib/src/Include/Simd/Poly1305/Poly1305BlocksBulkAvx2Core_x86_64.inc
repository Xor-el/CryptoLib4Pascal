// Poly1305 4-way AVX2 bulk MAC kernel (x86-64).
// -------------------------------------------------------------------
// Goll-Gueron / Polyakov: 4 blocks per iteration in 4 ymm lanes against an
// r^1..r^4 power table (320 bytes, 32-byte rows). radix-2^26 schoolbook
// multiply mod 2^130-5 (5*r wraparound); VEX tolerates unaligned memory so
// the table is read straight into vpmuludq. The bulk-loop carry-reduce uses
// two interleaved chains (low D0->D1->D2->D3->H4, high D3->D4->H0->H1) to
// shorten the serial critical path; the run-once tail/final reduces stay
// serial. A vpermq-based horizontal sum folds the 4 lanes at the end.
//
// On entry (after ClpSimdProc5Begin_x86_64.inc):
//   rcx = ACtx (72-byte R/S/H/K state); rdx = APowTable (320-byte r^1..r^4)
//   r8 = AInp; r9 = ALen (multiple of 64, >= 64); r10 = APad (ignored)
//
// Power table: row j at [rdx + 32*j]; rows 0..4 r-limbs, rows 5..8 s-limbs
// (5*r), row 9 pad. Bulk reads [+32*j] (broadcast r^4); tail reads
// [+32*j+4] ([r^4,r^3,r^2,r^1]).

{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  // ---- Prologue: mask26 (ymm5), padbit (ymm6) ----
  db $C5, $D5, $76, $ED                      // vpcmpeqd ymm5, ymm5, ymm5
  db $C5, $D5, $73, $D5, $26                 // vpsrlq ymm5, ymm5, 38
  db $C5, $CD, $76, $F6                      // vpcmpeqd ymm6, ymm6, ymm6
  db $C5, $CD, $73, $D6, $3F                 // vpsrlq ymm6, ymm6, 63
  db $C5, $CD, $73, $F6, $18                 // vpsllq ymm6, ymm6, 24
  // ---- Load H0..H4 into lane 0 ----
  db $C5, $F9, $6E, $41, $24                 // vmovd xmm0, dword ptr [rcx + 36]
  db $C5, $F9, $6E, $49, $28                 // vmovd xmm1, dword ptr [rcx + 40]
  db $C5, $F9, $6E, $51, $2C                 // vmovd xmm2, dword ptr [rcx + 44]
  db $C5, $F9, $6E, $59, $30                 // vmovd xmm3, dword ptr [rcx + 48]
  db $C5, $F9, $6E, $61, $34                 // vmovd xmm4, dword ptr [rcx + 52]
  // ---- Pre-loop: absorb first 4 blocks ----
  db $C4, $41, $7A, $6F, $20                 // vmovdqu xmm12, [r8]
  db $C4, $41, $7A, $6F, $68, $10            // vmovdqu xmm13, [r8 + 16]
  db $C4, $43, $1D, $38, $60, $20, $01       // vinserti128 ymm12, ymm12, [r8 + 32], 1
  db $C4, $43, $15, $38, $68, $30, $01       // vinserti128 ymm13, ymm13, [r8 + 48], 1
  add  r8, 64
  db $C4, $C1, $0D, $73, $DC, $06            // vpsrldq ymm14, ymm12, 6
  db $C4, $C1, $05, $73, $DD, $06            // vpsrldq ymm15, ymm13, 6
  db $C4, $C1, $1D, $6D, $FD                 // vpunpckhqdq ymm7, ymm12, ymm13
  db $C4, $41, $1D, $6C, $E5                 // vpunpcklqdq ymm12, ymm12, ymm13
  db $C4, $41, $0D, $6C, $F7                 // vpunpcklqdq ymm14, ymm14, ymm15
  db $C4, $C1, $05, $73, $D6, $1E            // vpsrlq ymm15, ymm14, 30
  db $C4, $C1, $0D, $73, $D6, $04            // vpsrlq ymm14, ymm14, 4
  db $C4, $C1, $15, $73, $D4, $1A            // vpsrlq ymm13, ymm12, 26
  db $C5, $C5, $73, $D7, $28                 // vpsrlq ymm7, ymm7, 40
  db $C5, $1D, $DB, $E5                      // vpand ymm12, ymm12, ymm5
  db $C5, $15, $DB, $ED                      // vpand ymm13, ymm13, ymm5
  db $C5, $0D, $DB, $F5                      // vpand ymm14, ymm14, ymm5
  db $C5, $05, $DB, $FD                      // vpand ymm15, ymm15, ymm5
  db $C5, $C5, $EB, $FE                      // vpor ymm7, ymm7, ymm6
  db $C4, $C1, $7D, $D4, $C4                 // vpaddq ymm0, ymm0, ymm12
  db $C4, $C1, $75, $D4, $CD                 // vpaddq ymm1, ymm1, ymm13
  db $C4, $C1, $6D, $D4, $D6                 // vpaddq ymm2, ymm2, ymm14
  db $C4, $C1, $65, $D4, $DF                 // vpaddq ymm3, ymm3, ymm15
  db $C5, $DD, $D4, $E7                      // vpaddq ymm4, ymm4, ymm7
  sub  r9, 64
  jz   @@poly1305_avx2_tail

@@poly1305_avx2_loop:
  // ---- Bulk: H *= r^4 (broadcast) ----
  db $C5, $7D, $F4, $A2, $80, $00, $00, $00  // vpmuludq ymm12, ymm0, [rdx + 128]
  db $C5, $75, $F4, $6A, $60                 // vpmuludq ymm13, ymm1, [rdx + 96]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $6D, $F4, $6A, $40                 // vpmuludq ymm13, ymm2, [rdx + 64]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $65, $F4, $6A, $20                 // vpmuludq ymm13, ymm3, [rdx + 32]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $5D, $F4, $2A                      // vpmuludq ymm13, ymm4, [rdx]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $7D, $F4, $5A, $60                 // vpmuludq ymm11, ymm0, [rdx + 96]
  db $C5, $75, $F4, $6A, $40                 // vpmuludq ymm13, ymm1, [rdx + 64]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $6D, $F4, $6A, $20                 // vpmuludq ymm13, ymm2, [rdx + 32]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $65, $F4, $2A                      // vpmuludq ymm13, ymm3, [rdx]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $5D, $F4, $AA, $00, $01, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 256]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $7D, $F4, $52, $40                 // vpmuludq ymm10, ymm0, [rdx + 64]
  db $C5, $75, $F4, $6A, $20                 // vpmuludq ymm13, ymm1, [rdx + 32]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $6D, $F4, $2A                      // vpmuludq ymm13, ymm2, [rdx]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $65, $F4, $AA, $00, $01, $00, $00  // vpmuludq ymm13, ymm3, [rdx + 256]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $5D, $F4, $AA, $E0, $00, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 224]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $7D, $F4, $4A, $20                 // vpmuludq ymm9, ymm0, [rdx + 32]
  db $C5, $75, $F4, $2A                      // vpmuludq ymm13, ymm1, [rdx]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $6D, $F4, $AA, $00, $01, $00, $00  // vpmuludq ymm13, ymm2, [rdx + 256]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $65, $F4, $AA, $E0, $00, $00, $00  // vpmuludq ymm13, ymm3, [rdx + 224]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $5D, $F4, $AA, $C0, $00, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 192]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $7D, $F4, $02                      // vpmuludq ymm8, ymm0, [rdx]
  db $C5, $75, $F4, $AA, $00, $01, $00, $00  // vpmuludq ymm13, ymm1, [rdx + 256]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  db $C5, $6D, $F4, $AA, $E0, $00, $00, $00  // vpmuludq ymm13, ymm2, [rdx + 224]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  db $C5, $65, $F4, $AA, $C0, $00, $00, $00  // vpmuludq ymm13, ymm3, [rdx + 192]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  db $C5, $5D, $F4, $AA, $A0, $00, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 160]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  // ---- Lazy reduce (two interleaved carry chains) ----
  db $C4, $C1, $15, $73, $D0, $1A            // vpsrlq ymm13, ymm8, 26
  db $C4, $C1, $0D, $73, $D3, $1A            // vpsrlq ymm14, ymm11, 26
  db $C5, $BD, $DB, $C5                      // vpand ymm0, ymm8, ymm5
  db $C5, $25, $DB, $DD                      // vpand ymm11, ymm11, ymm5
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C4, $41, $1D, $D4, $E6                 // vpaddq ymm12, ymm12, ymm14
  db $C4, $C1, $15, $73, $D1, $1A            // vpsrlq ymm13, ymm9, 26
  db $C4, $C1, $0D, $73, $D4, $1A            // vpsrlq ymm14, ymm12, 26
  db $C5, $B5, $DB, $CD                      // vpand ymm1, ymm9, ymm5
  db $C5, $9D, $DB, $E5                      // vpand ymm4, ymm12, ymm5
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C4, $C1, $05, $73, $F6, $02            // vpsllq ymm15, ymm14, 2
  db $C4, $41, $0D, $D4, $F7                 // vpaddq ymm14, ymm14, ymm15
  db $C4, $C1, $7D, $D4, $C6                 // vpaddq ymm0, ymm0, ymm14
  db $C4, $C1, $15, $73, $D2, $1A            // vpsrlq ymm13, ymm10, 26
  db $C5, $8D, $73, $D0, $1A                 // vpsrlq ymm14, ymm0, 26
  db $C5, $AD, $DB, $D5                      // vpand ymm2, ymm10, ymm5
  db $C5, $FD, $DB, $C5                      // vpand ymm0, ymm0, ymm5
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C4, $C1, $75, $D4, $CE                 // vpaddq ymm1, ymm1, ymm14
  db $C4, $C1, $15, $73, $D3, $1A            // vpsrlq ymm13, ymm11, 26
  db $C5, $A5, $DB, $DD                      // vpand ymm3, ymm11, ymm5
  db $C4, $C1, $5D, $D4, $E5                 // vpaddq ymm4, ymm4, ymm13
  // ---- Absorb next 4 blocks ----
  db $C4, $41, $7A, $6F, $20                 // vmovdqu xmm12, [r8]
  db $C4, $41, $7A, $6F, $68, $10            // vmovdqu xmm13, [r8 + 16]
  db $C4, $43, $1D, $38, $60, $20, $01       // vinserti128 ymm12, ymm12, [r8 + 32], 1
  db $C4, $43, $15, $38, $68, $30, $01       // vinserti128 ymm13, ymm13, [r8 + 48], 1
  add  r8, 64
  db $C4, $C1, $0D, $73, $DC, $06            // vpsrldq ymm14, ymm12, 6
  db $C4, $C1, $05, $73, $DD, $06            // vpsrldq ymm15, ymm13, 6
  db $C4, $C1, $1D, $6D, $FD                 // vpunpckhqdq ymm7, ymm12, ymm13
  db $C4, $41, $1D, $6C, $E5                 // vpunpcklqdq ymm12, ymm12, ymm13
  db $C4, $41, $0D, $6C, $F7                 // vpunpcklqdq ymm14, ymm14, ymm15
  db $C4, $C1, $05, $73, $D6, $1E            // vpsrlq ymm15, ymm14, 30
  db $C4, $C1, $0D, $73, $D6, $04            // vpsrlq ymm14, ymm14, 4
  db $C4, $C1, $15, $73, $D4, $1A            // vpsrlq ymm13, ymm12, 26
  db $C5, $C5, $73, $D7, $28                 // vpsrlq ymm7, ymm7, 40
  db $C5, $1D, $DB, $E5                      // vpand ymm12, ymm12, ymm5
  db $C5, $15, $DB, $ED                      // vpand ymm13, ymm13, ymm5
  db $C5, $0D, $DB, $F5                      // vpand ymm14, ymm14, ymm5
  db $C5, $05, $DB, $FD                      // vpand ymm15, ymm15, ymm5
  db $C5, $C5, $EB, $FE                      // vpor ymm7, ymm7, ymm6
  db $C4, $C1, $7D, $D4, $C4                 // vpaddq ymm0, ymm0, ymm12
  db $C4, $C1, $75, $D4, $CD                 // vpaddq ymm1, ymm1, ymm13
  db $C4, $C1, $6D, $D4, $D6                 // vpaddq ymm2, ymm2, ymm14
  db $C4, $C1, $65, $D4, $DF                 // vpaddq ymm3, ymm3, ymm15
  db $C5, $DD, $D4, $E7                      // vpaddq ymm4, ymm4, ymm7
  sub  r9, 64
  jnz  @@poly1305_avx2_loop

@@poly1305_avx2_tail:
  // ---- Tail: H *= [r^1, r^2, r^3, r^4] (shifted table read) ----
  db $C5, $7D, $F4, $A2, $84, $00, $00, $00  // vpmuludq ymm12, ymm0, [rdx + 132]
  db $C5, $75, $F4, $6A, $64                 // vpmuludq ymm13, ymm1, [rdx + 100]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $6D, $F4, $6A, $44                 // vpmuludq ymm13, ymm2, [rdx + 68]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $65, $F4, $6A, $24                 // vpmuludq ymm13, ymm3, [rdx + 36]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $5D, $F4, $6A, $04                 // vpmuludq ymm13, ymm4, [rdx + 4]
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C5, $7D, $F4, $5A, $64                 // vpmuludq ymm11, ymm0, [rdx + 100]
  db $C5, $75, $F4, $6A, $44                 // vpmuludq ymm13, ymm1, [rdx + 68]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $6D, $F4, $6A, $24                 // vpmuludq ymm13, ymm2, [rdx + 36]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $65, $F4, $6A, $04                 // vpmuludq ymm13, ymm3, [rdx + 4]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $5D, $F4, $AA, $04, $01, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 260]
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C5, $7D, $F4, $52, $44                 // vpmuludq ymm10, ymm0, [rdx + 68]
  db $C5, $75, $F4, $6A, $24                 // vpmuludq ymm13, ymm1, [rdx + 36]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $6D, $F4, $6A, $04                 // vpmuludq ymm13, ymm2, [rdx + 4]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $65, $F4, $AA, $04, $01, $00, $00  // vpmuludq ymm13, ymm3, [rdx + 260]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $5D, $F4, $AA, $E4, $00, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 228]
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C5, $7D, $F4, $4A, $24                 // vpmuludq ymm9, ymm0, [rdx + 36]
  db $C5, $75, $F4, $6A, $04                 // vpmuludq ymm13, ymm1, [rdx + 4]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $6D, $F4, $AA, $04, $01, $00, $00  // vpmuludq ymm13, ymm2, [rdx + 260]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $65, $F4, $AA, $E4, $00, $00, $00  // vpmuludq ymm13, ymm3, [rdx + 228]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $5D, $F4, $AA, $C4, $00, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 196]
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C5, $7D, $F4, $42, $04                 // vpmuludq ymm8, ymm0, [rdx + 4]
  db $C5, $75, $F4, $AA, $04, $01, $00, $00  // vpmuludq ymm13, ymm1, [rdx + 260]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  db $C5, $6D, $F4, $AA, $E4, $00, $00, $00  // vpmuludq ymm13, ymm2, [rdx + 228]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  db $C5, $65, $F4, $AA, $C4, $00, $00, $00  // vpmuludq ymm13, ymm3, [rdx + 196]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  db $C5, $5D, $F4, $AA, $A4, $00, $00, $00  // vpmuludq ymm13, ymm4, [rdx + 164]
  db $C4, $41, $3D, $D4, $C5                 // vpaddq ymm8, ymm8, ymm13
  // ---- Tail lazy reduce ----
  db $C4, $C1, $15, $73, $D0, $1A            // vpsrlq ymm13, ymm8, 26
  db $C5, $BD, $DB, $C5                      // vpand ymm0, ymm8, ymm5
  db $C4, $41, $35, $D4, $CD                 // vpaddq ymm9, ymm9, ymm13
  db $C4, $C1, $15, $73, $D1, $1A            // vpsrlq ymm13, ymm9, 26
  db $C5, $B5, $DB, $CD                      // vpand ymm1, ymm9, ymm5
  db $C4, $41, $2D, $D4, $D5                 // vpaddq ymm10, ymm10, ymm13
  db $C4, $C1, $15, $73, $D2, $1A            // vpsrlq ymm13, ymm10, 26
  db $C5, $AD, $DB, $D5                      // vpand ymm2, ymm10, ymm5
  db $C4, $41, $25, $D4, $DD                 // vpaddq ymm11, ymm11, ymm13
  db $C4, $C1, $15, $73, $D3, $1A            // vpsrlq ymm13, ymm11, 26
  db $C5, $A5, $DB, $DD                      // vpand ymm3, ymm11, ymm5
  db $C4, $41, $1D, $D4, $E5                 // vpaddq ymm12, ymm12, ymm13
  db $C4, $C1, $15, $73, $D4, $1A            // vpsrlq ymm13, ymm12, 26
  db $C5, $9D, $DB, $E5                      // vpand ymm4, ymm12, ymm5
  db $C4, $C1, $05, $73, $F5, $02            // vpsllq ymm15, ymm13, 2
  db $C4, $41, $15, $D4, $EF                 // vpaddq ymm13, ymm13, ymm15
  db $C4, $C1, $7D, $D4, $C5                 // vpaddq ymm0, ymm0, ymm13
  db $C5, $95, $73, $D0, $1A                 // vpsrlq ymm13, ymm0, 26
  db $C5, $FD, $DB, $C5                      // vpand ymm0, ymm0, ymm5
  db $C4, $C1, $75, $D4, $CD                 // vpaddq ymm1, ymm1, ymm13
  // ---- Horizontal sum 4 lanes -> lane 0 ----
  db $C5, $C5, $73, $D8, $08                 // vpsrldq ymm7, ymm0, 8
  db $C5, $FD, $D4, $C7                      // vpaddq ymm0, ymm0, ymm7
  db $C4, $E3, $FD, $00, $F8, $4E            // vpermq ymm7, ymm0, 0x4E
  db $C5, $FD, $D4, $C7                      // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D9, $08                 // vpsrldq ymm7, ymm1, 8
  db $C5, $F5, $D4, $CF                      // vpaddq ymm1, ymm1, ymm7
  db $C4, $E3, $FD, $00, $F9, $4E            // vpermq ymm7, ymm1, 0x4E
  db $C5, $F5, $D4, $CF                      // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $DA, $08                 // vpsrldq ymm7, ymm2, 8
  db $C5, $ED, $D4, $D7                      // vpaddq ymm2, ymm2, ymm7
  db $C4, $E3, $FD, $00, $FA, $4E            // vpermq ymm7, ymm2, 0x4E
  db $C5, $ED, $D4, $D7                      // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $DB, $08                 // vpsrldq ymm7, ymm3, 8
  db $C5, $E5, $D4, $DF                      // vpaddq ymm3, ymm3, ymm7
  db $C4, $E3, $FD, $00, $FB, $4E            // vpermq ymm7, ymm3, 0x4E
  db $C5, $E5, $D4, $DF                      // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $DC, $08                 // vpsrldq ymm7, ymm4, 8
  db $C5, $DD, $D4, $E7                      // vpaddq ymm4, ymm4, ymm7
  db $C4, $E3, $FD, $00, $FC, $4E            // vpermq ymm7, ymm4, 0x4E
  db $C5, $DD, $D4, $E7                      // vpaddq ymm4, ymm4, ymm7
  // ---- Final lazy reduce (lane 0 scalars) ----
  db $C5, $95, $73, $D0, $1A                 // vpsrlq ymm13, ymm0, 26
  db $C5, $FD, $DB, $C5                      // vpand ymm0, ymm0, ymm5
  db $C4, $C1, $75, $D4, $CD                 // vpaddq ymm1, ymm1, ymm13
  db $C5, $95, $73, $D1, $1A                 // vpsrlq ymm13, ymm1, 26
  db $C5, $F5, $DB, $CD                      // vpand ymm1, ymm1, ymm5
  db $C4, $C1, $6D, $D4, $D5                 // vpaddq ymm2, ymm2, ymm13
  db $C5, $95, $73, $D2, $1A                 // vpsrlq ymm13, ymm2, 26
  db $C5, $ED, $DB, $D5                      // vpand ymm2, ymm2, ymm5
  db $C4, $C1, $65, $D4, $DD                 // vpaddq ymm3, ymm3, ymm13
  db $C5, $95, $73, $D3, $1A                 // vpsrlq ymm13, ymm3, 26
  db $C5, $E5, $DB, $DD                      // vpand ymm3, ymm3, ymm5
  db $C4, $C1, $5D, $D4, $E5                 // vpaddq ymm4, ymm4, ymm13
  db $C5, $95, $73, $D4, $1A                 // vpsrlq ymm13, ymm4, 26
  db $C5, $DD, $DB, $E5                      // vpand ymm4, ymm4, ymm5
  db $C4, $C1, $05, $73, $F5, $02            // vpsllq ymm15, ymm13, 2
  db $C4, $41, $15, $D4, $EF                 // vpaddq ymm13, ymm13, ymm15
  db $C4, $C1, $7D, $D4, $C5                 // vpaddq ymm0, ymm0, ymm13
  db $C5, $95, $73, $D0, $1A                 // vpsrlq ymm13, ymm0, 26
  db $C5, $FD, $DB, $C5                      // vpand ymm0, ymm0, ymm5
  db $C4, $C1, $75, $D4, $CD                 // vpaddq ymm1, ymm1, ymm13
  // ---- Store H0..H4 back to ctx ----
  db $C5, $F9, $7E, $41, $24                 // vmovd dword ptr [rcx + 36], xmm0
  db $C5, $F9, $7E, $49, $28                 // vmovd dword ptr [rcx + 40], xmm1
  db $C5, $F9, $7E, $51, $2C                 // vmovd dword ptr [rcx + 44], xmm2
  db $C5, $F9, $7E, $59, $30                 // vmovd dword ptr [rcx + 48], xmm3
  db $C5, $F9, $7E, $61, $34                 // vmovd dword ptr [rcx + 52], xmm4
  db $C5, $F8, $77                           // vzeroupper
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
