// Poly1305 2-way SSE2 bulk MAC kernel (x86-64).
// -------------------------------------------------------------------
// 2-lane (128-bit xmm) radix-2^26 narrowing of the 4-way AVX2 kernel:
// same 5x5 schoolbook multiply mod 2^130-5 (with the 5*r wraparound),
// 2 blocks per iteration against an r/r^2 power table, then a single
// pshufd-based horizontal fold of the 2 lanes. Every instruction is
// db-encoded with its mnemonic beside it for broad assembler compatibility.
//
// On entry (after ClpSimdProc5Begin_x86_64.inc):
//   rcx = ACtx      (72-byte R/S/H/K state); rdx = APowTable (160-byte r/r^2)
//   r8 = AInp; r9 = ALen (multiple of 32, >= 32); r10 = APad (ignored)
//
// Power table: row j at [rdx + 16*j]; rows 0..4 r-limbs [r2,r2,r2,r1],
// rows 5..8 s-limbs (5*r), row 9 pad. Bulk reads [+16*j] (broadcast r^2);
// tail reads [+16*j+4] ([r^2,r^1]).
//
// Reference: Goll/Gueron, "Vectorization of Poly1305 Message Authentication
// Code" - the radix-2^26 multi-lane construction that this 2-lane form narrows
// from the 4-lane AVX2 kernel (Poly1305BlocksBulkAvx2Core_x86_64.inc).

{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  // ---- 64B-aligned frame: bulk table rows copied in once ----
  mov     r11, rsp
  sub     rsp, 192
  and     rsp, -64
  db $F3, $44, $0F, $6F, $22                           // movdqu xmm12, [rdx]
  db $66, $44, $0F, $7F, $24, $24                      // movdqa [rsp + 0], xmm12
  db $F3, $44, $0F, $6F, $62, $10                      // movdqu xmm12, [rdx + 16]
  db $66, $44, $0F, $7F, $64, $24, $10                 // movdqa [rsp + 16], xmm12
  db $F3, $44, $0F, $6F, $62, $20                      // movdqu xmm12, [rdx + 32]
  db $66, $44, $0F, $7F, $64, $24, $20                 // movdqa [rsp + 32], xmm12
  db $F3, $44, $0F, $6F, $62, $30                      // movdqu xmm12, [rdx + 48]
  db $66, $44, $0F, $7F, $64, $24, $30                 // movdqa [rsp + 48], xmm12
  db $F3, $44, $0F, $6F, $62, $40                      // movdqu xmm12, [rdx + 64]
  db $66, $44, $0F, $7F, $64, $24, $40                 // movdqa [rsp + 64], xmm12
  db $F3, $44, $0F, $6F, $62, $50                      // movdqu xmm12, [rdx + 80]
  db $66, $44, $0F, $7F, $64, $24, $50                 // movdqa [rsp + 80], xmm12
  db $F3, $44, $0F, $6F, $62, $60                      // movdqu xmm12, [rdx + 96]
  db $66, $44, $0F, $7F, $64, $24, $60                 // movdqa [rsp + 96], xmm12
  db $F3, $44, $0F, $6F, $62, $70                      // movdqu xmm12, [rdx + 112]
  db $66, $44, $0F, $7F, $64, $24, $70                 // movdqa [rsp + 112], xmm12
  db $F3, $44, $0F, $6F, $A2, $80, $00, $00, $00       // movdqu xmm12, [rdx + 128]
  db $66, $44, $0F, $7F, $A4, $24, $80, $00, $00, $00  // movdqa [rsp + 128], xmm12
  // ---- Prologue: mask26 (xmm5), padbit (xmm6) ----
  db $66, $0F, $76, $ED                                // pcmpeqd xmm5, xmm5
  db $66, $0F, $73, $D5, $26                           // psrlq xmm5, 38
  db $66, $0F, $76, $F6                                // pcmpeqd xmm6, xmm6
  db $66, $0F, $73, $D6, $3F                           // psrlq xmm6, 63
  db $66, $0F, $73, $F6, $18                           // psllq xmm6, 24
  // ---- Load H0..H4 into lane 0 ----
  db $66, $0F, $6E, $41, $24                           // movd xmm0, dword ptr [rcx + 36]
  db $66, $0F, $6E, $49, $28                           // movd xmm1, dword ptr [rcx + 40]
  db $66, $0F, $6E, $51, $2C                           // movd xmm2, dword ptr [rcx + 44]
  db $66, $0F, $6E, $59, $30                           // movd xmm3, dword ptr [rcx + 48]
  db $66, $0F, $6E, $61, $34                           // movd xmm4, dword ptr [rcx + 52]
  // ---- Pre-loop: absorb first 2 blocks ----
  db $F3, $45, $0F, $6F, $20                           // movdqu xmm12, [r8]
  db $F3, $45, $0F, $6F, $68, $10                      // movdqu xmm13, [r8 + 16]
  add     r8, 32
  db $66, $45, $0F, $6F, $F4                           // movdqa xmm14, xmm12
  db $66, $41, $0F, $73, $DE, $06                      // psrldq xmm14, 6
  db $66, $45, $0F, $6F, $FD                           // movdqa xmm15, xmm13
  db $66, $41, $0F, $73, $DF, $06                      // psrldq xmm15, 6
  db $66, $41, $0F, $6F, $FC                           // movdqa xmm7, xmm12
  db $66, $41, $0F, $6D, $FD                           // punpckhqdq xmm7, xmm13
  db $66, $45, $0F, $6C, $E5                           // punpcklqdq xmm12, xmm13
  db $66, $45, $0F, $6C, $F7                           // punpcklqdq xmm14, xmm15
  db $66, $45, $0F, $6F, $FE                           // movdqa xmm15, xmm14
  db $66, $41, $0F, $73, $D7, $1E                      // psrlq xmm15, 30
  db $66, $41, $0F, $73, $D6, $04                      // psrlq xmm14, 4
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $0F, $73, $D7, $28                           // psrlq xmm7, 40
  db $66, $44, $0F, $DB, $E5                           // pand xmm12, xmm5
  db $66, $44, $0F, $DB, $ED                           // pand xmm13, xmm5
  db $66, $44, $0F, $DB, $F5                           // pand xmm14, xmm5
  db $66, $44, $0F, $DB, $FD                           // pand xmm15, xmm5
  db $66, $0F, $EB, $FE                                // por xmm7, xmm6
  db $66, $41, $0F, $D4, $C4                           // paddq xmm0, xmm12
  db $66, $41, $0F, $D4, $CD                           // paddq xmm1, xmm13
  db $66, $41, $0F, $D4, $D6                           // paddq xmm2, xmm14
  db $66, $41, $0F, $D4, $DF                           // paddq xmm3, xmm15
  db $66, $0F, $D4, $E7                                // paddq xmm4, xmm7
  sub     r9, 32
  jz      @@poly1305_sse2_tail

@@poly1305_sse2_loop:
  // ---- Bulk: H *= r^2 (broadcast) ----
  db $66, $44, $0F, $6F, $D8                           // movdqa xmm11, xmm0
  db $66, $44, $0F, $F4, $5C, $24, $40                 // pmuludq xmm11, [rsp + 64]
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $66, $44, $0F, $F4, $64, $24, $30                 // pmuludq xmm12, [rsp + 48]
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $66, $44, $0F, $F4, $64, $24, $20                 // pmuludq xmm12, [rsp + 32]
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $66, $44, $0F, $F4, $64, $24, $10                 // pmuludq xmm12, [rsp + 16]
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $66, $44, $0F, $F4, $24, $24                      // pmuludq xmm12, [rsp + 0]
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $D0                           // movdqa xmm10, xmm0
  db $66, $44, $0F, $F4, $54, $24, $30                 // pmuludq xmm10, [rsp + 48]
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $66, $44, $0F, $F4, $64, $24, $20                 // pmuludq xmm12, [rsp + 32]
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $66, $44, $0F, $F4, $64, $24, $10                 // pmuludq xmm12, [rsp + 16]
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $66, $44, $0F, $F4, $24, $24                      // pmuludq xmm12, [rsp + 0]
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $66, $44, $0F, $F4, $A4, $24, $80, $00, $00, $00  // pmuludq xmm12, [rsp + 128]
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $C8                           // movdqa xmm9, xmm0
  db $66, $44, $0F, $F4, $4C, $24, $20                 // pmuludq xmm9, [rsp + 32]
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $66, $44, $0F, $F4, $64, $24, $10                 // pmuludq xmm12, [rsp + 16]
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $66, $44, $0F, $F4, $24, $24                      // pmuludq xmm12, [rsp + 0]
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $66, $44, $0F, $F4, $A4, $24, $80, $00, $00, $00  // pmuludq xmm12, [rsp + 128]
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $66, $44, $0F, $F4, $64, $24, $70                 // pmuludq xmm12, [rsp + 112]
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $C0                           // movdqa xmm8, xmm0
  db $66, $44, $0F, $F4, $44, $24, $10                 // pmuludq xmm8, [rsp + 16]
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $66, $44, $0F, $F4, $24, $24                      // pmuludq xmm12, [rsp + 0]
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $66, $44, $0F, $F4, $A4, $24, $80, $00, $00, $00  // pmuludq xmm12, [rsp + 128]
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $66, $44, $0F, $F4, $64, $24, $70                 // pmuludq xmm12, [rsp + 112]
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $66, $44, $0F, $F4, $64, $24, $60                 // pmuludq xmm12, [rsp + 96]
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $0F, $6F, $F8                                // movdqa xmm7, xmm0
  db $66, $0F, $F4, $3C, $24                           // pmuludq xmm7, [rsp + 0]
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $66, $44, $0F, $F4, $A4, $24, $80, $00, $00, $00  // pmuludq xmm12, [rsp + 128]
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $66, $44, $0F, $F4, $64, $24, $70                 // pmuludq xmm12, [rsp + 112]
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $66, $44, $0F, $F4, $64, $24, $60                 // pmuludq xmm12, [rsp + 96]
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $66, $44, $0F, $F4, $64, $24, $50                 // pmuludq xmm12, [rsp + 80]
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  // ---- Lazy reduce D -> H ----
  db $66, $44, $0F, $6F, $EF                           // movdqa xmm13, xmm7
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $0F, $DB, $FD                                // pand xmm7, xmm5
  db $66, $0F, $6F, $C7                                // movdqa xmm0, xmm7
  db $66, $45, $0F, $D4, $C5                           // paddq xmm8, xmm13
  db $66, $45, $0F, $6F, $E8                           // movdqa xmm13, xmm8
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $C5                           // pand xmm8, xmm5
  db $66, $41, $0F, $6F, $C8                           // movdqa xmm1, xmm8
  db $66, $45, $0F, $D4, $CD                           // paddq xmm9, xmm13
  db $66, $45, $0F, $6F, $E9                           // movdqa xmm13, xmm9
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $CD                           // pand xmm9, xmm5
  db $66, $41, $0F, $6F, $D1                           // movdqa xmm2, xmm9
  db $66, $45, $0F, $D4, $D5                           // paddq xmm10, xmm13
  db $66, $45, $0F, $6F, $EA                           // movdqa xmm13, xmm10
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $D5                           // pand xmm10, xmm5
  db $66, $41, $0F, $6F, $DA                           // movdqa xmm3, xmm10
  db $66, $45, $0F, $D4, $DD                           // paddq xmm11, xmm13
  db $66, $45, $0F, $6F, $EB                           // movdqa xmm13, xmm11
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $DD                           // pand xmm11, xmm5
  db $66, $41, $0F, $6F, $E3                           // movdqa xmm4, xmm11
  db $66, $45, $0F, $6F, $E5                           // movdqa xmm12, xmm13
  db $66, $41, $0F, $73, $F4, $02                      // psllq xmm12, 2
  db $66, $45, $0F, $D4, $EC                           // paddq xmm13, xmm12
  db $66, $41, $0F, $D4, $C5                           // paddq xmm0, xmm13
  db $66, $44, $0F, $6F, $E8                           // movdqa xmm13, xmm0
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $0F, $DB, $C5                                // pand xmm0, xmm5
  db $66, $41, $0F, $D4, $CD                           // paddq xmm1, xmm13
  // ---- Absorb next 2 blocks ----
  db $F3, $45, $0F, $6F, $20                           // movdqu xmm12, [r8]
  db $F3, $45, $0F, $6F, $68, $10                      // movdqu xmm13, [r8 + 16]
  add     r8, 32
  db $66, $45, $0F, $6F, $F4                           // movdqa xmm14, xmm12
  db $66, $41, $0F, $73, $DE, $06                      // psrldq xmm14, 6
  db $66, $45, $0F, $6F, $FD                           // movdqa xmm15, xmm13
  db $66, $41, $0F, $73, $DF, $06                      // psrldq xmm15, 6
  db $66, $41, $0F, $6F, $FC                           // movdqa xmm7, xmm12
  db $66, $41, $0F, $6D, $FD                           // punpckhqdq xmm7, xmm13
  db $66, $45, $0F, $6C, $E5                           // punpcklqdq xmm12, xmm13
  db $66, $45, $0F, $6C, $F7                           // punpcklqdq xmm14, xmm15
  db $66, $45, $0F, $6F, $FE                           // movdqa xmm15, xmm14
  db $66, $41, $0F, $73, $D7, $1E                      // psrlq xmm15, 30
  db $66, $41, $0F, $73, $D6, $04                      // psrlq xmm14, 4
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $0F, $73, $D7, $28                           // psrlq xmm7, 40
  db $66, $44, $0F, $DB, $E5                           // pand xmm12, xmm5
  db $66, $44, $0F, $DB, $ED                           // pand xmm13, xmm5
  db $66, $44, $0F, $DB, $F5                           // pand xmm14, xmm5
  db $66, $44, $0F, $DB, $FD                           // pand xmm15, xmm5
  db $66, $0F, $EB, $FE                                // por xmm7, xmm6
  db $66, $41, $0F, $D4, $C4                           // paddq xmm0, xmm12
  db $66, $41, $0F, $D4, $CD                           // paddq xmm1, xmm13
  db $66, $41, $0F, $D4, $D6                           // paddq xmm2, xmm14
  db $66, $41, $0F, $D4, $DF                           // paddq xmm3, xmm15
  db $66, $0F, $D4, $E7                                // paddq xmm4, xmm7
  sub     r9, 32
  jnz     @@poly1305_sse2_loop

@@poly1305_sse2_tail:
  // ---- Tail: H *= [r^2, r^1] (shifted table read) ----
  db $66, $44, $0F, $6F, $D8                           // movdqa xmm11, xmm0
  db $F3, $44, $0F, $6F, $6A, $44                      // movdqu xmm13, [rdx + 68]
  db $66, $45, $0F, $F4, $DD                           // pmuludq xmm11, xmm13
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $F3, $44, $0F, $6F, $6A, $34                      // movdqu xmm13, [rdx + 52]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $F3, $44, $0F, $6F, $6A, $24                      // movdqu xmm13, [rdx + 36]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $F3, $44, $0F, $6F, $6A, $14                      // movdqu xmm13, [rdx + 20]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $F3, $44, $0F, $6F, $6A, $04                      // movdqu xmm13, [rdx + 4]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $DC                           // paddq xmm11, xmm12
  db $66, $44, $0F, $6F, $D0                           // movdqa xmm10, xmm0
  db $F3, $44, $0F, $6F, $6A, $34                      // movdqu xmm13, [rdx + 52]
  db $66, $45, $0F, $F4, $D5                           // pmuludq xmm10, xmm13
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $F3, $44, $0F, $6F, $6A, $24                      // movdqu xmm13, [rdx + 36]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $F3, $44, $0F, $6F, $6A, $14                      // movdqu xmm13, [rdx + 20]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $F3, $44, $0F, $6F, $6A, $04                      // movdqu xmm13, [rdx + 4]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $F3, $44, $0F, $6F, $AA, $84, $00, $00, $00       // movdqu xmm13, [rdx + 132]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $D4                           // paddq xmm10, xmm12
  db $66, $44, $0F, $6F, $C8                           // movdqa xmm9, xmm0
  db $F3, $44, $0F, $6F, $6A, $24                      // movdqu xmm13, [rdx + 36]
  db $66, $45, $0F, $F4, $CD                           // pmuludq xmm9, xmm13
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $F3, $44, $0F, $6F, $6A, $14                      // movdqu xmm13, [rdx + 20]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $F3, $44, $0F, $6F, $6A, $04                      // movdqu xmm13, [rdx + 4]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $F3, $44, $0F, $6F, $AA, $84, $00, $00, $00       // movdqu xmm13, [rdx + 132]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $F3, $44, $0F, $6F, $6A, $74                      // movdqu xmm13, [rdx + 116]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $CC                           // paddq xmm9, xmm12
  db $66, $44, $0F, $6F, $C0                           // movdqa xmm8, xmm0
  db $F3, $44, $0F, $6F, $6A, $14                      // movdqu xmm13, [rdx + 20]
  db $66, $45, $0F, $F4, $C5                           // pmuludq xmm8, xmm13
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $F3, $44, $0F, $6F, $6A, $04                      // movdqu xmm13, [rdx + 4]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $F3, $44, $0F, $6F, $AA, $84, $00, $00, $00       // movdqu xmm13, [rdx + 132]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $F3, $44, $0F, $6F, $6A, $74                      // movdqu xmm13, [rdx + 116]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $F3, $44, $0F, $6F, $6A, $64                      // movdqu xmm13, [rdx + 100]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $45, $0F, $D4, $C4                           // paddq xmm8, xmm12
  db $66, $0F, $6F, $F8                                // movdqa xmm7, xmm0
  db $F3, $44, $0F, $6F, $6A, $04                      // movdqu xmm13, [rdx + 4]
  db $66, $41, $0F, $F4, $FD                           // pmuludq xmm7, xmm13
  db $66, $44, $0F, $6F, $E1                           // movdqa xmm12, xmm1
  db $F3, $44, $0F, $6F, $AA, $84, $00, $00, $00       // movdqu xmm13, [rdx + 132]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $44, $0F, $6F, $E2                           // movdqa xmm12, xmm2
  db $F3, $44, $0F, $6F, $6A, $74                      // movdqu xmm13, [rdx + 116]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $F3, $44, $0F, $6F, $6A, $64                      // movdqu xmm13, [rdx + 100]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $F3, $44, $0F, $6F, $6A, $54                      // movdqu xmm13, [rdx + 84]
  db $66, $45, $0F, $F4, $E5                           // pmuludq xmm12, xmm13
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $44, $0F, $6F, $EF                           // movdqa xmm13, xmm7
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $0F, $DB, $FD                                // pand xmm7, xmm5
  db $66, $0F, $6F, $C7                                // movdqa xmm0, xmm7
  db $66, $45, $0F, $D4, $C5                           // paddq xmm8, xmm13
  db $66, $45, $0F, $6F, $E8                           // movdqa xmm13, xmm8
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $C5                           // pand xmm8, xmm5
  db $66, $41, $0F, $6F, $C8                           // movdqa xmm1, xmm8
  db $66, $45, $0F, $D4, $CD                           // paddq xmm9, xmm13
  db $66, $45, $0F, $6F, $E9                           // movdqa xmm13, xmm9
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $CD                           // pand xmm9, xmm5
  db $66, $41, $0F, $6F, $D1                           // movdqa xmm2, xmm9
  db $66, $45, $0F, $D4, $D5                           // paddq xmm10, xmm13
  db $66, $45, $0F, $6F, $EA                           // movdqa xmm13, xmm10
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $D5                           // pand xmm10, xmm5
  db $66, $41, $0F, $6F, $DA                           // movdqa xmm3, xmm10
  db $66, $45, $0F, $D4, $DD                           // paddq xmm11, xmm13
  db $66, $45, $0F, $6F, $EB                           // movdqa xmm13, xmm11
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $44, $0F, $DB, $DD                           // pand xmm11, xmm5
  db $66, $41, $0F, $6F, $E3                           // movdqa xmm4, xmm11
  db $66, $45, $0F, $6F, $E5                           // movdqa xmm12, xmm13
  db $66, $41, $0F, $73, $F4, $02                      // psllq xmm12, 2
  db $66, $45, $0F, $D4, $EC                           // paddq xmm13, xmm12
  db $66, $41, $0F, $D4, $C5                           // paddq xmm0, xmm13
  db $66, $44, $0F, $6F, $E8                           // movdqa xmm13, xmm0
  db $66, $41, $0F, $73, $D5, $1A                      // psrlq xmm13, 26
  db $66, $0F, $DB, $C5                                // pand xmm0, xmm5
  db $66, $41, $0F, $D4, $CD                           // paddq xmm1, xmm13
  // ---- Horizontal fold 2 lanes -> 1, final reduce, store ----
  db $66, $0F, $70, $F8, $4E                           // pshufd xmm7, xmm0, 0x4E
  db $66, $0F, $D4, $C7                                // paddq xmm0, xmm7
  db $66, $0F, $70, $F9, $4E                           // pshufd xmm7, xmm1, 0x4E
  db $66, $0F, $D4, $CF                                // paddq xmm1, xmm7
  db $66, $0F, $70, $FA, $4E                           // pshufd xmm7, xmm2, 0x4E
  db $66, $0F, $D4, $D7                                // paddq xmm2, xmm7
  db $66, $0F, $70, $FB, $4E                           // pshufd xmm7, xmm3, 0x4E
  db $66, $0F, $D4, $DF                                // paddq xmm3, xmm7
  db $66, $0F, $70, $FC, $4E                           // pshufd xmm7, xmm4, 0x4E
  db $66, $0F, $D4, $E7                                // paddq xmm4, xmm7
  db $66, $0F, $6F, $F8                                // movdqa xmm7, xmm0
  db $66, $0F, $73, $D7, $1A                           // psrlq xmm7, 26
  db $66, $0F, $DB, $C5                                // pand xmm0, xmm5
  db $66, $0F, $D4, $CF                                // paddq xmm1, xmm7
  db $66, $0F, $6F, $F9                                // movdqa xmm7, xmm1
  db $66, $0F, $73, $D7, $1A                           // psrlq xmm7, 26
  db $66, $0F, $DB, $CD                                // pand xmm1, xmm5
  db $66, $0F, $D4, $D7                                // paddq xmm2, xmm7
  db $66, $0F, $6F, $FA                                // movdqa xmm7, xmm2
  db $66, $0F, $73, $D7, $1A                           // psrlq xmm7, 26
  db $66, $0F, $DB, $D5                                // pand xmm2, xmm5
  db $66, $0F, $D4, $DF                                // paddq xmm3, xmm7
  db $66, $0F, $6F, $FB                                // movdqa xmm7, xmm3
  db $66, $0F, $73, $D7, $1A                           // psrlq xmm7, 26
  db $66, $0F, $DB, $DD                                // pand xmm3, xmm5
  db $66, $0F, $D4, $E7                                // paddq xmm4, xmm7
  db $66, $0F, $6F, $FC                                // movdqa xmm7, xmm4
  db $66, $0F, $73, $D7, $1A                           // psrlq xmm7, 26
  db $66, $0F, $DB, $E5                                // pand xmm4, xmm5
  db $66, $44, $0F, $6F, $E7                           // movdqa xmm12, xmm7
  db $66, $41, $0F, $73, $F4, $02                      // psllq xmm12, 2
  db $66, $41, $0F, $D4, $FC                           // paddq xmm7, xmm12
  db $66, $0F, $D4, $C7                                // paddq xmm0, xmm7
  db $66, $0F, $6F, $F8                                // movdqa xmm7, xmm0
  db $66, $0F, $73, $D7, $1A                           // psrlq xmm7, 26
  db $66, $0F, $DB, $C5                                // pand xmm0, xmm5
  db $66, $0F, $D4, $CF                                // paddq xmm1, xmm7
  db $66, $0F, $7E, $41, $24                           // movd dword ptr [rcx + 36], xmm0
  db $66, $0F, $7E, $49, $28                           // movd dword ptr [rcx + 40], xmm1
  db $66, $0F, $7E, $51, $2C                           // movd dword ptr [rcx + 44], xmm2
  db $66, $0F, $7E, $59, $30                           // movd dword ptr [rcx + 48], xmm3
  db $66, $0F, $7E, $61, $34                           // movd dword ptr [rcx + 52], xmm4
  mov     rsp, r11
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
