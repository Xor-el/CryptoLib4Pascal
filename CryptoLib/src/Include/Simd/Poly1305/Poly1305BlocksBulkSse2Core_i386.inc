// Poly1305 2-way SSE2 bulk MAC kernel (i386).
// -------------------------------------------------------------------
// 2-lane (128-bit xmm) radix-2^26 narrowing of the 4-way AVX2 kernel:
// same 5x5 schoolbook multiply mod 2^130-5 (with the 5*r wraparound),
// 2 blocks per iteration against an r/r^2 power table, then a single
// pshufd-based horizontal fold of the 2 lanes.
//
// i386 has only xmm0..7 (no callee-saved xmm): H0..H4 stay RESIDENT
// in xmm0..4, xmm5..7 are the accumulator/product temps, and the
// 64B-aligned esp frame holds a one-time copy of the bulk table rows
// plus mask26/padbit, making SSE memory-operand arithmetic against
// [esp+off] legal and every hot access aligned.
//
// On entry (after ClpSimdProc5Begin_i386.inc):
//   ebx = ACtx (72-byte R/S/H/K state); esi = APowTable (160-byte r/r^2)
//   edi = AInp; eax = ALen (multiple of 32, >= 32); ecx = APad (ignored)
//
// Power table: row j at [esi + 16*j]; rows 0..4 r-limbs [r2,r2,r2,r1],
// rows 5..8 s-limbs (5*r), row 9 pad. Bulk reads [+16*j] (broadcast r^2);
// tail reads [+16*j+4] ([r^2,r^1]).
//
// Reference: Goll/Gueron, "Vectorization of Poly1305 Message Authentication
// Code" - the radix-2^26 multi-lane construction that this 2-lane form narrows
// from the 4-lane AVX2 kernel (Poly1305BlocksBulkAvx2Core_i386.inc).

  // ---- 64B-aligned frame: table copy + D slots + mask/pad ----
  mov     edx, esp
  sub     esp, 256
  and     esp, -64
  mov     dword ptr [esp + 240], edx
  db $F3, $0F, $6F, $2E                           // movdqu xmm5, [esi]
  db $66, $0F, $7F, $2C, $24                      // movdqa [esp + 0], xmm5
  db $F3, $0F, $6F, $6E, $10                      // movdqu xmm5, [esi + 16]
  db $66, $0F, $7F, $6C, $24, $10                 // movdqa [esp + 16], xmm5
  db $F3, $0F, $6F, $6E, $20                      // movdqu xmm5, [esi + 32]
  db $66, $0F, $7F, $6C, $24, $20                 // movdqa [esp + 32], xmm5
  db $F3, $0F, $6F, $6E, $30                      // movdqu xmm5, [esi + 48]
  db $66, $0F, $7F, $6C, $24, $30                 // movdqa [esp + 48], xmm5
  db $F3, $0F, $6F, $6E, $40                      // movdqu xmm5, [esi + 64]
  db $66, $0F, $7F, $6C, $24, $40                 // movdqa [esp + 64], xmm5
  db $F3, $0F, $6F, $6E, $50                      // movdqu xmm5, [esi + 80]
  db $66, $0F, $7F, $6C, $24, $50                 // movdqa [esp + 80], xmm5
  db $F3, $0F, $6F, $6E, $60                      // movdqu xmm5, [esi + 96]
  db $66, $0F, $7F, $6C, $24, $60                 // movdqa [esp + 96], xmm5
  db $F3, $0F, $6F, $6E, $70                      // movdqu xmm5, [esi + 112]
  db $66, $0F, $7F, $6C, $24, $70                 // movdqa [esp + 112], xmm5
  db $F3, $0F, $6F, $AE, $80, $00, $00, $00       // movdqu xmm5, [esi + 128]
  db $66, $0F, $7F, $AC, $24, $80, $00, $00, $00  // movdqa [esp + 128], xmm5
  db $66, $0F, $76, $ED                           // pcmpeqd xmm5, xmm5
  db $66, $0F, $73, $D5, $26                      // psrlq xmm5, 38
  db $66, $0F, $7F, $AC, $24, $D0, $00, $00, $00  // movdqa [esp + 208], xmm5
  db $66, $0F, $76, $ED                           // pcmpeqd xmm5, xmm5
  db $66, $0F, $73, $D5, $3F                      // psrlq xmm5, 63
  db $66, $0F, $73, $F5, $18                      // psllq xmm5, 24
  db $66, $0F, $7F, $AC, $24, $E0, $00, $00, $00  // movdqa [esp + 224], xmm5
  // ---- Load H0..H4 into lane 0 (resident) ----
  db $66, $0F, $6E, $43, $24                      // movd xmm0, dword ptr [ebx + 36]
  db $66, $0F, $6E, $4B, $28                      // movd xmm1, dword ptr [ebx + 40]
  db $66, $0F, $6E, $53, $2C                      // movd xmm2, dword ptr [ebx + 44]
  db $66, $0F, $6E, $5B, $30                      // movd xmm3, dword ptr [ebx + 48]
  db $66, $0F, $6E, $63, $34                      // movd xmm4, dword ptr [ebx + 52]
  // ---- Pre-loop: absorb first 2 blocks ----
  db $F3, $0F, $6F, $2F                           // movdqu xmm5, [edi]
  db $F3, $0F, $6F, $77, $10                      // movdqu xmm6, [edi + 16]
  add     edi, 32
  db $66, $0F, $6F, $FD                           // movdqa xmm7, xmm5
  db $66, $0F, $6D, $FE                           // punpckhqdq xmm7, xmm6
  db $66, $0F, $73, $D7, $28                      // psrlq xmm7, 40
  db $66, $0F, $EB, $BC, $24, $E0, $00, $00, $00  // por xmm7, [esp + 224]
  db $66, $0F, $D4, $E7                           // paddq xmm4, xmm7
  db $66, $0F, $6F, $FD                           // movdqa xmm7, xmm5
  db $66, $0F, $73, $DF, $06                      // psrldq xmm7, 6
  db $66, $0F, $6C, $EE                           // punpcklqdq xmm5, xmm6
  db $66, $0F, $73, $DE, $06                      // psrldq xmm6, 6
  db $66, $0F, $6C, $FE                           // punpcklqdq xmm7, xmm6
  db $66, $0F, $6F, $F7                           // movdqa xmm6, xmm7
  db $66, $0F, $73, $D6, $1E                      // psrlq xmm6, 30
  db $66, $0F, $DB, $B4, $24, $D0, $00, $00, $00  // pand xmm6, [esp + 208]
  db $66, $0F, $D4, $DE                           // paddq xmm3, xmm6
  db $66, $0F, $73, $D7, $04                      // psrlq xmm7, 4
  db $66, $0F, $DB, $BC, $24, $D0, $00, $00, $00  // pand xmm7, [esp + 208]
  db $66, $0F, $D4, $D7                           // paddq xmm2, xmm7
  db $66, $0F, $6F, $F5                           // movdqa xmm6, xmm5
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $B4, $24, $D0, $00, $00, $00  // pand xmm6, [esp + 208]
  db $66, $0F, $D4, $CE                           // paddq xmm1, xmm6
  db $66, $0F, $DB, $AC, $24, $D0, $00, $00, $00  // pand xmm5, [esp + 208]
  db $66, $0F, $D4, $C5                           // paddq xmm0, xmm5
  sub     eax, 32
  jz      @@poly1305_sse2_tail

@@poly1305_sse2_loop:
  // ---- Bulk: H *= r^2 (broadcast), k-major resident accumulator ----
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $66, $0F, $F4, $6C, $24, $40                 // pmuludq xmm5, [esp + 64]
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $F4, $74, $24, $30                 // pmuludq xmm6, [esp + 48]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $F4, $74, $24, $20                 // pmuludq xmm6, [esp + 32]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $F4, $74, $24, $10                 // pmuludq xmm6, [esp + 16]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $F4, $34, $24                      // pmuludq xmm6, [esp + 0]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $C0, $00, $00, $00  // movdqa [esp + 192], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $66, $0F, $F4, $6C, $24, $30                 // pmuludq xmm5, [esp + 48]
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $F4, $74, $24, $20                 // pmuludq xmm6, [esp + 32]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $F4, $74, $24, $10                 // pmuludq xmm6, [esp + 16]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $F4, $34, $24                      // pmuludq xmm6, [esp + 0]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $F4, $B4, $24, $80, $00, $00, $00  // pmuludq xmm6, [esp + 128]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $B0, $00, $00, $00  // movdqa [esp + 176], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $66, $0F, $F4, $6C, $24, $20                 // pmuludq xmm5, [esp + 32]
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $F4, $74, $24, $10                 // pmuludq xmm6, [esp + 16]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $F4, $34, $24                      // pmuludq xmm6, [esp + 0]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $F4, $B4, $24, $80, $00, $00, $00  // pmuludq xmm6, [esp + 128]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $F4, $74, $24, $70                 // pmuludq xmm6, [esp + 112]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $A0, $00, $00, $00  // movdqa [esp + 160], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $66, $0F, $F4, $6C, $24, $10                 // pmuludq xmm5, [esp + 16]
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $F4, $34, $24                      // pmuludq xmm6, [esp + 0]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $F4, $B4, $24, $80, $00, $00, $00  // pmuludq xmm6, [esp + 128]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $F4, $74, $24, $70                 // pmuludq xmm6, [esp + 112]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $F4, $74, $24, $60                 // pmuludq xmm6, [esp + 96]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $90, $00, $00, $00  // movdqa [esp + 144], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $66, $0F, $F4, $2C, $24                      // pmuludq xmm5, [esp + 0]
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $F4, $B4, $24, $80, $00, $00, $00  // pmuludq xmm6, [esp + 128]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $F4, $74, $24, $70                 // pmuludq xmm6, [esp + 112]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $F4, $74, $24, $60                 // pmuludq xmm6, [esp + 96]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $F4, $74, $24, $50                 // pmuludq xmm6, [esp + 80]
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  // ---- Lazy reduce (D0 from xmm5) ----
  db $66, $0F, $6F, $F5                           // movdqa xmm6, xmm5
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $AC, $24, $D0, $00, $00, $00  // pand xmm5, [esp + 208]
  db $66, $0F, $6F, $C5                           // movdqa xmm0, xmm5
  db $66, $0F, $6F, $CE                           // movdqa xmm1, xmm6
  db $66, $0F, $D4, $8C, $24, $90, $00, $00, $00  // paddq xmm1, [esp + 144]
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $8C, $24, $D0, $00, $00, $00  // pand xmm1, [esp + 208]
  db $66, $0F, $6F, $D6                           // movdqa xmm2, xmm6
  db $66, $0F, $D4, $94, $24, $A0, $00, $00, $00  // paddq xmm2, [esp + 160]
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $94, $24, $D0, $00, $00, $00  // pand xmm2, [esp + 208]
  db $66, $0F, $6F, $DE                           // movdqa xmm3, xmm6
  db $66, $0F, $D4, $9C, $24, $B0, $00, $00, $00  // paddq xmm3, [esp + 176]
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $9C, $24, $D0, $00, $00, $00  // pand xmm3, [esp + 208]
  db $66, $0F, $6F, $E6                           // movdqa xmm4, xmm6
  db $66, $0F, $D4, $A4, $24, $C0, $00, $00, $00  // paddq xmm4, [esp + 192]
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $A4, $24, $D0, $00, $00, $00  // pand xmm4, [esp + 208]
  db $66, $0F, $6F, $FE                           // movdqa xmm7, xmm6
  db $66, $0F, $73, $F7, $02                      // psllq xmm7, 2
  db $66, $0F, $D4, $F7                           // paddq xmm6, xmm7
  db $66, $0F, $D4, $C6                           // paddq xmm0, xmm6
  db $66, $0F, $6F, $F0                           // movdqa xmm6, xmm0
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $84, $24, $D0, $00, $00, $00  // pand xmm0, [esp + 208]
  db $66, $0F, $D4, $CE                           // paddq xmm1, xmm6
  // ---- Absorb next 2 blocks ----
  db $F3, $0F, $6F, $2F                           // movdqu xmm5, [edi]
  db $F3, $0F, $6F, $77, $10                      // movdqu xmm6, [edi + 16]
  add     edi, 32
  db $66, $0F, $6F, $FD                           // movdqa xmm7, xmm5
  db $66, $0F, $6D, $FE                           // punpckhqdq xmm7, xmm6
  db $66, $0F, $73, $D7, $28                      // psrlq xmm7, 40
  db $66, $0F, $EB, $BC, $24, $E0, $00, $00, $00  // por xmm7, [esp + 224]
  db $66, $0F, $D4, $E7                           // paddq xmm4, xmm7
  db $66, $0F, $6F, $FD                           // movdqa xmm7, xmm5
  db $66, $0F, $73, $DF, $06                      // psrldq xmm7, 6
  db $66, $0F, $6C, $EE                           // punpcklqdq xmm5, xmm6
  db $66, $0F, $73, $DE, $06                      // psrldq xmm6, 6
  db $66, $0F, $6C, $FE                           // punpcklqdq xmm7, xmm6
  db $66, $0F, $6F, $F7                           // movdqa xmm6, xmm7
  db $66, $0F, $73, $D6, $1E                      // psrlq xmm6, 30
  db $66, $0F, $DB, $B4, $24, $D0, $00, $00, $00  // pand xmm6, [esp + 208]
  db $66, $0F, $D4, $DE                           // paddq xmm3, xmm6
  db $66, $0F, $73, $D7, $04                      // psrlq xmm7, 4
  db $66, $0F, $DB, $BC, $24, $D0, $00, $00, $00  // pand xmm7, [esp + 208]
  db $66, $0F, $D4, $D7                           // paddq xmm2, xmm7
  db $66, $0F, $6F, $F5                           // movdqa xmm6, xmm5
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $B4, $24, $D0, $00, $00, $00  // pand xmm6, [esp + 208]
  db $66, $0F, $D4, $CE                           // paddq xmm1, xmm6
  db $66, $0F, $DB, $AC, $24, $D0, $00, $00, $00  // pand xmm5, [esp + 208]
  db $66, $0F, $D4, $C5                           // paddq xmm0, xmm5
  sub     eax, 32
  jnz     @@poly1305_sse2_loop

@@poly1305_sse2_tail:
  // ---- Tail: H *= [r^2, r^1] (shifted table read) ----
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $F3, $0F, $6F, $7E, $44                      // movdqu xmm7, [esi + 68]
  db $66, $0F, $F4, $EF                           // pmuludq xmm5, xmm7
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $F3, $0F, $6F, $7E, $34                      // movdqu xmm7, [esi + 52]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $F3, $0F, $6F, $7E, $24                      // movdqu xmm7, [esi + 36]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $F3, $0F, $6F, $7E, $14                      // movdqu xmm7, [esi + 20]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $F3, $0F, $6F, $7E, $04                      // movdqu xmm7, [esi + 4]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $C0, $00, $00, $00  // movdqa [esp + 192], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $F3, $0F, $6F, $7E, $34                      // movdqu xmm7, [esi + 52]
  db $66, $0F, $F4, $EF                           // pmuludq xmm5, xmm7
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $F3, $0F, $6F, $7E, $24                      // movdqu xmm7, [esi + 36]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $F3, $0F, $6F, $7E, $14                      // movdqu xmm7, [esi + 20]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $F3, $0F, $6F, $7E, $04                      // movdqu xmm7, [esi + 4]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $F3, $0F, $6F, $BE, $84, $00, $00, $00       // movdqu xmm7, [esi + 132]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $B0, $00, $00, $00  // movdqa [esp + 176], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $F3, $0F, $6F, $7E, $24                      // movdqu xmm7, [esi + 36]
  db $66, $0F, $F4, $EF                           // pmuludq xmm5, xmm7
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $F3, $0F, $6F, $7E, $14                      // movdqu xmm7, [esi + 20]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $F3, $0F, $6F, $7E, $04                      // movdqu xmm7, [esi + 4]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $F3, $0F, $6F, $BE, $84, $00, $00, $00       // movdqu xmm7, [esi + 132]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $F3, $0F, $6F, $7E, $74                      // movdqu xmm7, [esi + 116]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $A0, $00, $00, $00  // movdqa [esp + 160], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $F3, $0F, $6F, $7E, $14                      // movdqu xmm7, [esi + 20]
  db $66, $0F, $F4, $EF                           // pmuludq xmm5, xmm7
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $F3, $0F, $6F, $7E, $04                      // movdqu xmm7, [esi + 4]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $F3, $0F, $6F, $BE, $84, $00, $00, $00       // movdqu xmm7, [esi + 132]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $F3, $0F, $6F, $7E, $74                      // movdqu xmm7, [esi + 116]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $F3, $0F, $6F, $7E, $64                      // movdqu xmm7, [esi + 100]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $7F, $AC, $24, $90, $00, $00, $00  // movdqa [esp + 144], xmm5
  db $66, $0F, $6F, $E8                           // movdqa xmm5, xmm0
  db $F3, $0F, $6F, $7E, $04                      // movdqu xmm7, [esi + 4]
  db $66, $0F, $F4, $EF                           // pmuludq xmm5, xmm7
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $F3, $0F, $6F, $BE, $84, $00, $00, $00       // movdqu xmm7, [esi + 132]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $F3, $0F, $6F, $7E, $74                      // movdqu xmm7, [esi + 116]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $F3, $0F, $6F, $7E, $64                      // movdqu xmm7, [esi + 100]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $F3, $0F, $6F, $7E, $54                      // movdqu xmm7, [esi + 84]
  db $66, $0F, $F4, $F7                           // pmuludq xmm6, xmm7
  db $66, $0F, $D4, $EE                           // paddq xmm5, xmm6
  db $66, $0F, $6F, $F5                           // movdqa xmm6, xmm5
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $AC, $24, $D0, $00, $00, $00  // pand xmm5, [esp + 208]
  db $66, $0F, $6F, $C5                           // movdqa xmm0, xmm5
  db $66, $0F, $6F, $CE                           // movdqa xmm1, xmm6
  db $66, $0F, $D4, $8C, $24, $90, $00, $00, $00  // paddq xmm1, [esp + 144]
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $8C, $24, $D0, $00, $00, $00  // pand xmm1, [esp + 208]
  db $66, $0F, $6F, $D6                           // movdqa xmm2, xmm6
  db $66, $0F, $D4, $94, $24, $A0, $00, $00, $00  // paddq xmm2, [esp + 160]
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $94, $24, $D0, $00, $00, $00  // pand xmm2, [esp + 208]
  db $66, $0F, $6F, $DE                           // movdqa xmm3, xmm6
  db $66, $0F, $D4, $9C, $24, $B0, $00, $00, $00  // paddq xmm3, [esp + 176]
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $9C, $24, $D0, $00, $00, $00  // pand xmm3, [esp + 208]
  db $66, $0F, $6F, $E6                           // movdqa xmm4, xmm6
  db $66, $0F, $D4, $A4, $24, $C0, $00, $00, $00  // paddq xmm4, [esp + 192]
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $A4, $24, $D0, $00, $00, $00  // pand xmm4, [esp + 208]
  db $66, $0F, $6F, $FE                           // movdqa xmm7, xmm6
  db $66, $0F, $73, $F7, $02                      // psllq xmm7, 2
  db $66, $0F, $D4, $F7                           // paddq xmm6, xmm7
  db $66, $0F, $D4, $C6                           // paddq xmm0, xmm6
  db $66, $0F, $6F, $F0                           // movdqa xmm6, xmm0
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $84, $24, $D0, $00, $00, $00  // pand xmm0, [esp + 208]
  db $66, $0F, $D4, $CE                           // paddq xmm1, xmm6
  // ---- Horizontal fold 2 lanes -> 1, final reduce, store ----
  db $66, $0F, $70, $F0, $4E                      // pshufd xmm6, xmm0, 0x4E
  db $66, $0F, $D4, $C6                           // paddq xmm0, xmm6
  db $66, $0F, $70, $F1, $4E                      // pshufd xmm6, xmm1, 0x4E
  db $66, $0F, $D4, $CE                           // paddq xmm1, xmm6
  db $66, $0F, $70, $F2, $4E                      // pshufd xmm6, xmm2, 0x4E
  db $66, $0F, $D4, $D6                           // paddq xmm2, xmm6
  db $66, $0F, $70, $F3, $4E                      // pshufd xmm6, xmm3, 0x4E
  db $66, $0F, $D4, $DE                           // paddq xmm3, xmm6
  db $66, $0F, $70, $F4, $4E                      // pshufd xmm6, xmm4, 0x4E
  db $66, $0F, $D4, $E6                           // paddq xmm4, xmm6
  db $66, $0F, $6F, $F0                           // movdqa xmm6, xmm0
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $84, $24, $D0, $00, $00, $00  // pand xmm0, [esp + 208]
  db $66, $0F, $D4, $CE                           // paddq xmm1, xmm6
  db $66, $0F, $6F, $F1                           // movdqa xmm6, xmm1
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $8C, $24, $D0, $00, $00, $00  // pand xmm1, [esp + 208]
  db $66, $0F, $D4, $D6                           // paddq xmm2, xmm6
  db $66, $0F, $6F, $F2                           // movdqa xmm6, xmm2
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $94, $24, $D0, $00, $00, $00  // pand xmm2, [esp + 208]
  db $66, $0F, $D4, $DE                           // paddq xmm3, xmm6
  db $66, $0F, $6F, $F3                           // movdqa xmm6, xmm3
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $9C, $24, $D0, $00, $00, $00  // pand xmm3, [esp + 208]
  db $66, $0F, $D4, $E6                           // paddq xmm4, xmm6
  db $66, $0F, $6F, $F4                           // movdqa xmm6, xmm4
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $A4, $24, $D0, $00, $00, $00  // pand xmm4, [esp + 208]
  db $66, $0F, $6F, $FE                           // movdqa xmm7, xmm6
  db $66, $0F, $73, $F7, $02                      // psllq xmm7, 2
  db $66, $0F, $D4, $F7                           // paddq xmm6, xmm7
  db $66, $0F, $D4, $C6                           // paddq xmm0, xmm6
  db $66, $0F, $6F, $F0                           // movdqa xmm6, xmm0
  db $66, $0F, $73, $D6, $1A                      // psrlq xmm6, 26
  db $66, $0F, $DB, $84, $24, $D0, $00, $00, $00  // pand xmm0, [esp + 208]
  db $66, $0F, $D4, $CE                           // paddq xmm1, xmm6
  db $66, $0F, $7E, $43, $24                      // movd dword ptr [ebx + 36], xmm0
  db $66, $0F, $7E, $4B, $28                      // movd dword ptr [ebx + 40], xmm1
  db $66, $0F, $7E, $53, $2C                      // movd dword ptr [ebx + 44], xmm2
  db $66, $0F, $7E, $5B, $30                      // movd dword ptr [ebx + 48], xmm3
  db $66, $0F, $7E, $63, $34                      // movd dword ptr [ebx + 52], xmm4
  mov     esp, dword ptr [esp + 240]
  pop     edi
  pop     esi
  pop     ebx
