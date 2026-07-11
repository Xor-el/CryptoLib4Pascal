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

  // ---- 64B-aligned frame; mask26/padbit stored as mem operands ----
  mov  edx, esp
  sub  esp, 256
  and  esp, -64
  mov  dword ptr [esp + 224], edx
  db $C5, $D5, $76, $ED                           // vpcmpeqd ymm5, ymm5, ymm5
  db $C5, $D5, $73, $D5, $26                      // vpsrlq ymm5, ymm5, 38
  db $C5, $FD, $7F, $AC, $24, $A0, $00, $00, $00  // vmovdqa [esp + 160], ymm5
  db $C5, $D5, $76, $ED                           // vpcmpeqd ymm5, ymm5, ymm5
  db $C5, $D5, $73, $D5, $3F                      // vpsrlq ymm5, ymm5, 63
  db $C5, $D5, $73, $F5, $18                      // vpsllq ymm5, ymm5, 24
  db $C5, $FD, $7F, $AC, $24, $C0, $00, $00, $00  // vmovdqa [esp + 192], ymm5
  // ---- Load H0..H4 into lane 0 ----
  db $C5, $F9, $6E, $43, $24                      // vmovd xmm0, dword ptr [ebx + 36]
  db $C5, $F9, $6E, $4B, $28                      // vmovd xmm1, dword ptr [ebx + 40]
  db $C5, $F9, $6E, $53, $2C                      // vmovd xmm2, dword ptr [ebx + 44]
  db $C5, $F9, $6E, $5B, $30                      // vmovd xmm3, dword ptr [ebx + 48]
  db $C5, $F9, $6E, $63, $34                      // vmovd xmm4, dword ptr [ebx + 52]
  // ---- Pre-loop: absorb first 4 blocks ----
  db $C5, $FA, $6F, $2F                           // vmovdqu xmm5, [edi]
  db $C5, $FA, $6F, $77, $10                      // vmovdqu xmm6, [edi + 16]
  db $C4, $E3, $55, $38, $6F, $20, $01            // vinserti128 ymm5, ymm5, [edi + 32], 1
  db $C4, $E3, $4D, $38, $77, $30, $01            // vinserti128 ymm6, ymm6, [edi + 48], 1
  add  edi, 64
  db $C5, $D5, $6D, $FE                           // vpunpckhqdq ymm7, ymm5, ymm6
  db $C5, $C5, $73, $D7, $28                      // vpsrlq ymm7, ymm7, 40
  db $C5, $C5, $EB, $BC, $24, $C0, $00, $00, $00  // vpor ymm7, ymm7, [esp + 192]
  db $C5, $DD, $D4, $E7                           // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $DD, $06                      // vpsrldq ymm7, ymm5, 6
  db $C5, $D5, $6C, $EE                           // vpunpcklqdq ymm5, ymm5, ymm6
  db $C5, $CD, $73, $DE, $06                      // vpsrldq ymm6, ymm6, 6
  db $C5, $C5, $6C, $FE                           // vpunpcklqdq ymm7, ymm7, ymm6
  db $C5, $CD, $73, $D7, $1E                      // vpsrlq ymm6, ymm7, 30
  db $C5, $CD, $DB, $B4, $24, $A0, $00, $00, $00  // vpand ymm6, ymm6, [esp + 160]
  db $C5, $E5, $D4, $DE                           // vpaddq ymm3, ymm3, ymm6
  db $C5, $C5, $73, $D7, $04                      // vpsrlq ymm7, ymm7, 4
  db $C5, $C5, $DB, $BC, $24, $A0, $00, $00, $00  // vpand ymm7, ymm7, [esp + 160]
  db $C5, $ED, $D4, $D7                           // vpaddq ymm2, ymm2, ymm7
  db $C5, $CD, $73, $D5, $1A                      // vpsrlq ymm6, ymm5, 26
  db $C5, $CD, $DB, $B4, $24, $A0, $00, $00, $00  // vpand ymm6, ymm6, [esp + 160]
  db $C5, $F5, $D4, $CE                           // vpaddq ymm1, ymm1, ymm6
  db $C5, $D5, $DB, $AC, $24, $A0, $00, $00, $00  // vpand ymm5, ymm5, [esp + 160]
  db $C5, $FD, $D4, $C5                           // vpaddq ymm0, ymm0, ymm5
  sub  eax, 64
  jz   @@poly1305_avx2_i386_tail

@@poly1305_avx2_i386_loop:
  // ---- Bulk: H *= r^4 (broadcast), k-major resident accumulator ----
  db $C5, $FD, $F4, $AE, $80, $00, $00, $00       // vpmuludq ymm5, ymm0, [esi + 128]
  db $C5, $F5, $F4, $76, $60                      // vpmuludq ymm6, ymm1, [esi + 96]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $76, $40                      // vpmuludq ymm6, ymm2, [esi + 64]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $76, $20                      // vpmuludq ymm6, ymm3, [esi + 32]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $36                           // vpmuludq ymm6, ymm4, [esi]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $AC, $24, $80, $00, $00, $00  // vmovdqa [esp + 128], ymm5
  db $C5, $FD, $F4, $6E, $60                      // vpmuludq ymm5, ymm0, [esi + 96]
  db $C5, $F5, $F4, $76, $40                      // vpmuludq ymm6, ymm1, [esi + 64]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $76, $20                      // vpmuludq ymm6, ymm2, [esi + 32]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $36                           // vpmuludq ymm6, ymm3, [esi]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $00, $01, $00, $00       // vpmuludq ymm6, ymm4, [esi + 256]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $6C, $24, $60                 // vmovdqa [esp + 96], ymm5
  db $C5, $FD, $F4, $6E, $40                      // vpmuludq ymm5, ymm0, [esi + 64]
  db $C5, $F5, $F4, $76, $20                      // vpmuludq ymm6, ymm1, [esi + 32]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $36                           // vpmuludq ymm6, ymm2, [esi]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $B6, $00, $01, $00, $00       // vpmuludq ymm6, ymm3, [esi + 256]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $E0, $00, $00, $00       // vpmuludq ymm6, ymm4, [esi + 224]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $6C, $24, $40                 // vmovdqa [esp + 64], ymm5
  db $C5, $FD, $F4, $6E, $20                      // vpmuludq ymm5, ymm0, [esi + 32]
  db $C5, $F5, $F4, $36                           // vpmuludq ymm6, ymm1, [esi]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $B6, $00, $01, $00, $00       // vpmuludq ymm6, ymm2, [esi + 256]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $B6, $E0, $00, $00, $00       // vpmuludq ymm6, ymm3, [esi + 224]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $C0, $00, $00, $00       // vpmuludq ymm6, ymm4, [esi + 192]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $6C, $24, $20                 // vmovdqa [esp + 32], ymm5
  db $C5, $FD, $F4, $2E                           // vpmuludq ymm5, ymm0, [esi]
  db $C5, $F5, $F4, $B6, $00, $01, $00, $00       // vpmuludq ymm6, ymm1, [esi + 256]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $B6, $E0, $00, $00, $00       // vpmuludq ymm6, ymm2, [esi + 224]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $B6, $C0, $00, $00, $00       // vpmuludq ymm6, ymm3, [esi + 192]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $A0, $00, $00, $00       // vpmuludq ymm6, ymm4, [esi + 160]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  // ---- Lazy reduce (D0 from ymm5) ----
  db $C5, $CD, $73, $D5, $1A                      // vpsrlq ymm6, ymm5, 26
  db $C5, $D5, $DB, $84, $24, $A0, $00, $00, $00  // vpand ymm0, ymm5, [esp + 160]
  db $C5, $CD, $D4, $4C, $24, $20                 // vpaddq ymm1, ymm6, [esp + 32]
  db $C5, $CD, $73, $D1, $1A                      // vpsrlq ymm6, ymm1, 26
  db $C5, $F5, $DB, $8C, $24, $A0, $00, $00, $00  // vpand ymm1, ymm1, [esp + 160]
  db $C5, $CD, $D4, $54, $24, $40                 // vpaddq ymm2, ymm6, [esp + 64]
  db $C5, $CD, $73, $D2, $1A                      // vpsrlq ymm6, ymm2, 26
  db $C5, $ED, $DB, $94, $24, $A0, $00, $00, $00  // vpand ymm2, ymm2, [esp + 160]
  db $C5, $CD, $D4, $5C, $24, $60                 // vpaddq ymm3, ymm6, [esp + 96]
  db $C5, $CD, $73, $D3, $1A                      // vpsrlq ymm6, ymm3, 26
  db $C5, $E5, $DB, $9C, $24, $A0, $00, $00, $00  // vpand ymm3, ymm3, [esp + 160]
  db $C5, $CD, $D4, $A4, $24, $80, $00, $00, $00  // vpaddq ymm4, ymm6, [esp + 128]
  db $C5, $CD, $73, $D4, $1A                      // vpsrlq ymm6, ymm4, 26
  db $C5, $DD, $DB, $A4, $24, $A0, $00, $00, $00  // vpand ymm4, ymm4, [esp + 160]
  db $C5, $C5, $73, $F6, $02                      // vpsllq ymm7, ymm6, 2
  db $C5, $CD, $D4, $F7                           // vpaddq ymm6, ymm6, ymm7
  db $C5, $FD, $D4, $C6                           // vpaddq ymm0, ymm0, ymm6
  db $C5, $CD, $73, $D0, $1A                      // vpsrlq ymm6, ymm0, 26
  db $C5, $FD, $DB, $84, $24, $A0, $00, $00, $00  // vpand ymm0, ymm0, [esp + 160]
  db $C5, $F5, $D4, $CE                           // vpaddq ymm1, ymm1, ymm6
  // ---- Absorb next 4 blocks ----
  db $C5, $FA, $6F, $2F                           // vmovdqu xmm5, [edi]
  db $C5, $FA, $6F, $77, $10                      // vmovdqu xmm6, [edi + 16]
  db $C4, $E3, $55, $38, $6F, $20, $01            // vinserti128 ymm5, ymm5, [edi + 32], 1
  db $C4, $E3, $4D, $38, $77, $30, $01            // vinserti128 ymm6, ymm6, [edi + 48], 1
  add  edi, 64
  db $C5, $D5, $6D, $FE                           // vpunpckhqdq ymm7, ymm5, ymm6
  db $C5, $C5, $73, $D7, $28                      // vpsrlq ymm7, ymm7, 40
  db $C5, $C5, $EB, $BC, $24, $C0, $00, $00, $00  // vpor ymm7, ymm7, [esp + 192]
  db $C5, $DD, $D4, $E7                           // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $DD, $06                      // vpsrldq ymm7, ymm5, 6
  db $C5, $D5, $6C, $EE                           // vpunpcklqdq ymm5, ymm5, ymm6
  db $C5, $CD, $73, $DE, $06                      // vpsrldq ymm6, ymm6, 6
  db $C5, $C5, $6C, $FE                           // vpunpcklqdq ymm7, ymm7, ymm6
  db $C5, $CD, $73, $D7, $1E                      // vpsrlq ymm6, ymm7, 30
  db $C5, $CD, $DB, $B4, $24, $A0, $00, $00, $00  // vpand ymm6, ymm6, [esp + 160]
  db $C5, $E5, $D4, $DE                           // vpaddq ymm3, ymm3, ymm6
  db $C5, $C5, $73, $D7, $04                      // vpsrlq ymm7, ymm7, 4
  db $C5, $C5, $DB, $BC, $24, $A0, $00, $00, $00  // vpand ymm7, ymm7, [esp + 160]
  db $C5, $ED, $D4, $D7                           // vpaddq ymm2, ymm2, ymm7
  db $C5, $CD, $73, $D5, $1A                      // vpsrlq ymm6, ymm5, 26
  db $C5, $CD, $DB, $B4, $24, $A0, $00, $00, $00  // vpand ymm6, ymm6, [esp + 160]
  db $C5, $F5, $D4, $CE                           // vpaddq ymm1, ymm1, ymm6
  db $C5, $D5, $DB, $AC, $24, $A0, $00, $00, $00  // vpand ymm5, ymm5, [esp + 160]
  db $C5, $FD, $D4, $C5                           // vpaddq ymm0, ymm0, ymm5
  sub  eax, 64
  jnz  @@poly1305_avx2_i386_loop

@@poly1305_avx2_i386_tail:
  // ---- Tail: H *= [r^1, r^2, r^3, r^4] (shifted table read) ----
  db $C5, $FD, $F4, $AE, $84, $00, $00, $00       // vpmuludq ymm5, ymm0, [esi + 132]
  db $C5, $F5, $F4, $76, $64                      // vpmuludq ymm6, ymm1, [esi + 100]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $76, $44                      // vpmuludq ymm6, ymm2, [esi + 68]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $76, $24                      // vpmuludq ymm6, ymm3, [esi + 36]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $76, $04                      // vpmuludq ymm6, ymm4, [esi + 4]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $AC, $24, $80, $00, $00, $00  // vmovdqa [esp + 128], ymm5
  db $C5, $FD, $F4, $6E, $64                      // vpmuludq ymm5, ymm0, [esi + 100]
  db $C5, $F5, $F4, $76, $44                      // vpmuludq ymm6, ymm1, [esi + 68]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $76, $24                      // vpmuludq ymm6, ymm2, [esi + 36]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $76, $04                      // vpmuludq ymm6, ymm3, [esi + 4]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $04, $01, $00, $00       // vpmuludq ymm6, ymm4, [esi + 260]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $6C, $24, $60                 // vmovdqa [esp + 96], ymm5
  db $C5, $FD, $F4, $6E, $44                      // vpmuludq ymm5, ymm0, [esi + 68]
  db $C5, $F5, $F4, $76, $24                      // vpmuludq ymm6, ymm1, [esi + 36]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $76, $04                      // vpmuludq ymm6, ymm2, [esi + 4]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $B6, $04, $01, $00, $00       // vpmuludq ymm6, ymm3, [esi + 260]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $E4, $00, $00, $00       // vpmuludq ymm6, ymm4, [esi + 228]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $6C, $24, $40                 // vmovdqa [esp + 64], ymm5
  db $C5, $FD, $F4, $6E, $24                      // vpmuludq ymm5, ymm0, [esi + 36]
  db $C5, $F5, $F4, $76, $04                      // vpmuludq ymm6, ymm1, [esi + 4]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $B6, $04, $01, $00, $00       // vpmuludq ymm6, ymm2, [esi + 260]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $B6, $E4, $00, $00, $00       // vpmuludq ymm6, ymm3, [esi + 228]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $C4, $00, $00, $00       // vpmuludq ymm6, ymm4, [esi + 196]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $FD, $7F, $6C, $24, $20                 // vmovdqa [esp + 32], ymm5
  db $C5, $FD, $F4, $6E, $04                      // vpmuludq ymm5, ymm0, [esi + 4]
  db $C5, $F5, $F4, $B6, $04, $01, $00, $00       // vpmuludq ymm6, ymm1, [esi + 260]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $ED, $F4, $B6, $E4, $00, $00, $00       // vpmuludq ymm6, ymm2, [esi + 228]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $E5, $F4, $B6, $C4, $00, $00, $00       // vpmuludq ymm6, ymm3, [esi + 196]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  db $C5, $DD, $F4, $B6, $A4, $00, $00, $00       // vpmuludq ymm6, ymm4, [esi + 164]
  db $C5, $D5, $D4, $EE                           // vpaddq ymm5, ymm5, ymm6
  // ---- Tail lazy reduce ----
  db $C5, $CD, $73, $D5, $1A                      // vpsrlq ymm6, ymm5, 26
  db $C5, $D5, $DB, $84, $24, $A0, $00, $00, $00  // vpand ymm0, ymm5, [esp + 160]
  db $C5, $CD, $D4, $4C, $24, $20                 // vpaddq ymm1, ymm6, [esp + 32]
  db $C5, $CD, $73, $D1, $1A                      // vpsrlq ymm6, ymm1, 26
  db $C5, $F5, $DB, $8C, $24, $A0, $00, $00, $00  // vpand ymm1, ymm1, [esp + 160]
  db $C5, $CD, $D4, $54, $24, $40                 // vpaddq ymm2, ymm6, [esp + 64]
  db $C5, $CD, $73, $D2, $1A                      // vpsrlq ymm6, ymm2, 26
  db $C5, $ED, $DB, $94, $24, $A0, $00, $00, $00  // vpand ymm2, ymm2, [esp + 160]
  db $C5, $CD, $D4, $5C, $24, $60                 // vpaddq ymm3, ymm6, [esp + 96]
  db $C5, $CD, $73, $D3, $1A                      // vpsrlq ymm6, ymm3, 26
  db $C5, $E5, $DB, $9C, $24, $A0, $00, $00, $00  // vpand ymm3, ymm3, [esp + 160]
  db $C5, $CD, $D4, $A4, $24, $80, $00, $00, $00  // vpaddq ymm4, ymm6, [esp + 128]
  db $C5, $CD, $73, $D4, $1A                      // vpsrlq ymm6, ymm4, 26
  db $C5, $DD, $DB, $A4, $24, $A0, $00, $00, $00  // vpand ymm4, ymm4, [esp + 160]
  db $C5, $C5, $73, $F6, $02                      // vpsllq ymm7, ymm6, 2
  db $C5, $CD, $D4, $F7                           // vpaddq ymm6, ymm6, ymm7
  db $C5, $FD, $D4, $C6                           // vpaddq ymm0, ymm0, ymm6
  db $C5, $CD, $73, $D0, $1A                      // vpsrlq ymm6, ymm0, 26
  db $C5, $FD, $DB, $84, $24, $A0, $00, $00, $00  // vpand ymm0, ymm0, [esp + 160]
  db $C5, $F5, $D4, $CE                           // vpaddq ymm1, ymm1, ymm6
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
  db $C5, $CD, $73, $D0, $1A                      // vpsrlq ymm6, ymm0, 26
  db $C5, $FD, $DB, $84, $24, $A0, $00, $00, $00  // vpand ymm0, ymm0, [esp + 160]
  db $C5, $F5, $D4, $CE                           // vpaddq ymm1, ymm1, ymm6
  db $C5, $CD, $73, $D1, $1A                      // vpsrlq ymm6, ymm1, 26
  db $C5, $F5, $DB, $8C, $24, $A0, $00, $00, $00  // vpand ymm1, ymm1, [esp + 160]
  db $C5, $ED, $D4, $D6                           // vpaddq ymm2, ymm2, ymm6
  db $C5, $CD, $73, $D2, $1A                      // vpsrlq ymm6, ymm2, 26
  db $C5, $ED, $DB, $94, $24, $A0, $00, $00, $00  // vpand ymm2, ymm2, [esp + 160]
  db $C5, $E5, $D4, $DE                           // vpaddq ymm3, ymm3, ymm6
  db $C5, $CD, $73, $D3, $1A                      // vpsrlq ymm6, ymm3, 26
  db $C5, $E5, $DB, $9C, $24, $A0, $00, $00, $00  // vpand ymm3, ymm3, [esp + 160]
  db $C5, $DD, $D4, $E6                           // vpaddq ymm4, ymm4, ymm6
  db $C5, $CD, $73, $D4, $1A                      // vpsrlq ymm6, ymm4, 26
  db $C5, $DD, $DB, $A4, $24, $A0, $00, $00, $00  // vpand ymm4, ymm4, [esp + 160]
  db $C5, $C5, $73, $F6, $02                      // vpsllq ymm7, ymm6, 2
  db $C5, $CD, $D4, $F7                           // vpaddq ymm6, ymm6, ymm7
  db $C5, $FD, $D4, $C6                           // vpaddq ymm0, ymm0, ymm6
  db $C5, $CD, $73, $D0, $1A                      // vpsrlq ymm6, ymm0, 26
  db $C5, $FD, $DB, $84, $24, $A0, $00, $00, $00  // vpand ymm0, ymm0, [esp + 160]
  db $C5, $F5, $D4, $CE                           // vpaddq ymm1, ymm1, ymm6
  // ---- Store H0..H4 back to ctx ----
  db $C5, $F9, $7E, $43, $24                      // vmovd dword ptr [ebx + 36], xmm0
  db $C5, $F9, $7E, $4B, $28                      // vmovd dword ptr [ebx + 40], xmm1
  db $C5, $F9, $7E, $53, $2C                      // vmovd dword ptr [ebx + 44], xmm2
  db $C5, $F9, $7E, $5B, $30                      // vmovd dword ptr [ebx + 48], xmm3
  db $C5, $F9, $7E, $63, $34                      // vmovd dword ptr [ebx + 52], xmm4
  db $C5, $F8, $77                                // vzeroupper
  mov  esp, dword ptr [esp + 224]
  pop  edi
  pop  esi
  pop  ebx
