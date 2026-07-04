// x86/V128 BinPoly fixed-size carryless multiply kernels for limb counts 1..10.
// PCLMULQDQ instruction is db-encoded for broad assembler compatibility.
// Included inside BinPolyPclmulImplMulSmall after SimdProc4Begin_x86_64.inc:
//   rcx = ALen, rdx = PX, r8 = PY, r9 = PZz
// ZZ output: V128 lane k at byte offset 16*k in PZz.

  // Each size case reaches @@BinPolySmallXmmDone via `jmp` (not `ret`) so the
  // restore of the registers saved here always runs.
{$I ..\..\Include\Simd\Common\SimdNonVolatileSave_x86_64.inc}
  cmp       rcx, 1
  je        @@BinPolySmallSize1
  cmp       rcx, 2
  je        @@BinPolySmallSize2
  cmp       rcx, 3
  je        @@BinPolySmallSize3
  cmp       rcx, 4
  je        @@BinPolySmallSize4
  cmp       rcx, 5
  je        @@BinPolySmallSize5
  cmp       rcx, 6
  je        @@BinPolySmallSize6
  cmp       rcx, 7
  je        @@BinPolySmallSize7
  cmp       rcx, 8
  je        @@BinPolySmallSize8
  cmp       rcx, 9
  je        @@BinPolySmallSize9
  cmp       rcx, 10
  je        @@BinPolySmallSize10
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize1:
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [r8 + 0]
  punpcklqdq xmm0, xmm15
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    [r9 + 0], xmm1
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize2:
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [rdx + 8]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [r8 + 0]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm1, xmm15
  movdqa    xmm2, xmm0
  punpcklqdq xmm2, xmm1
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm1
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D1, $00  // pclmulqdq xmm2, xmm1, 0
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $D9, $11  // pclmulqdq xmm3, xmm1, 17
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm3
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm4
  pslldq    xmm0, 8
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm4
  psrldq    xmm0, 8
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm0
  movdqu    [r9 + 0], xmm1
  movdqu    [r9 + 16], xmm2
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize3:
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [r8 + 0]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 8]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [r8 + 16]
  punpcklqdq xmm2, xmm15
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm4, xmm1
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm1
  movdqa    xmm7, xmm0
  pxor      xmm7, xmm2
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqa    xmm1, xmm6
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm2, xmm7
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm4
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm3
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm5
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm4
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqa    xmm7, xmm3
  pxor      xmm7, xmm0
  movdqa    xmm0, xmm1
  psrldq    xmm0, 8
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm6
  pslldq    xmm0, 8
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm6
  psrldq    xmm1, 8
  movdqa    xmm2, xmm5
  pxor      xmm2, xmm1
  movdqu    [r9 + 0], xmm7
  movdqu    [r9 + 16], xmm0
  movdqu    [r9 + 32], xmm2
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize4:
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [rdx + 8]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [rdx + 24]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [r8 + 0]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm2, xmm15
  movq      xmm3, qword ptr [r8 + 16]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqa    xmm7, xmm0
  punpckhqdq xmm7, xmm2
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm7
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $00  // pclmulqdq xmm6, xmm2, 0
  movdqa    xmm7, xmm0
  db $66, $0F, $3A, $44, $FA, $11  // pclmulqdq xmm7, xmm2, 17
  movdqa    xmm0, xmm8
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm7
  movdqa    xmm8, xmm2
  pxor      xmm8, xmm0
  movdqa    xmm0, xmm8
  pslldq    xmm0, 8
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm6, xmm7
  pxor      xmm6, xmm0
  movdqa    xmm0, xmm1
  punpcklqdq xmm0, xmm3
  movdqa    xmm7, xmm1
  punpckhqdq xmm7, xmm3
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm7
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C3, $00  // pclmulqdq xmm0, xmm3, 0
  movdqa    xmm7, xmm1
  db $66, $0F, $3A, $44, $FB, $11  // pclmulqdq xmm7, xmm3, 17
  movdqa    xmm1, xmm8
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm7
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm1
  movdqa    xmm1, xmm8
  pslldq    xmm1, 8
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm1
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm4
  punpcklqdq xmm0, xmm5
  movdqa    xmm7, xmm4
  punpckhqdq xmm7, xmm5
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm7
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C5, $00  // pclmulqdq xmm0, xmm5, 0
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11  // pclmulqdq xmm7, xmm5, 17
  movdqa    xmm4, xmm8
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm7
  movdqa    xmm8, xmm5
  pxor      xmm8, xmm4
  movdqa    xmm4, xmm8
  pslldq    xmm4, 8
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm4, xmm7
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm2
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm1
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm3
  movdqu    [r9 + 0], xmm2
  movdqu    [r9 + 16], xmm5
  movdqu    [r9 + 32], xmm4
  movdqu    [r9 + 48], xmm1
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize5:
  sub       rsp, 48
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [r8 + 0]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 8]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [r8 + 16]
  punpcklqdq xmm2, xmm15
  movq      xmm3, qword ptr [rdx + 24]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movq      xmm4, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [r8 + 32]
  punpcklqdq xmm4, xmm15
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm6, xmm1
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm7, xmm2
  db $66, $0F, $3A, $44, $FF, $01  // pclmulqdq xmm7, xmm7, 1
  movdqa    xmm8, xmm3
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm9, xmm4
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm1
  movdqa    xmm11, xmm0
  pxor      xmm11, xmm2
  movdqa    xmm12, xmm0
  pxor      xmm12, xmm3
  movdqa    xmm13, xmm0
  pxor      xmm13, xmm4
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqa    xmm14, xmm1
  pxor      xmm14, xmm3
  movdqu    [rsp + 0], xmm9
  movdqa    xmm9, xmm1
  pxor      xmm9, xmm4
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm3
  movdqu    [rsp + 16], xmm8
  movdqa    xmm8, xmm2
  pxor      xmm8, xmm4
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm4
  movdqa    xmm3, xmm10
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm4, xmm11
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm10, xmm12
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm13
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm0
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm0, xmm14
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm13, xmm9
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm9, xmm1
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm1, xmm8
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm8, xmm2
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm5
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm6
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm5
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm7
  movdqa    xmm2, xmm10
  pxor      xmm2, xmm5
  movdqu    xmm10, [rsp + 16]
  movdqa    xmm14, xmm2
  pxor      xmm14, xmm10
  movdqa    xmm2, xmm11
  pxor      xmm2, xmm5
  movdqu    xmm11, [rsp + 0]
  movdqu    [rsp + 16], xmm10
  movdqa    xmm10, xmm2
  pxor      xmm10, xmm11
  movdqa    xmm2, xmm12
  pxor      xmm2, xmm6
  movdqa    xmm12, xmm2
  pxor      xmm12, xmm7
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm6
  movdqu    xmm0, [rsp + 16]
  movdqu    [rsp + 0], xmm11
  movdqa    xmm11, xmm2
  pxor      xmm11, xmm0
  movdqa    xmm2, xmm13
  pxor      xmm2, xmm6
  movdqu    xmm13, [rsp + 0]
  movdqu    [rsp + 16], xmm0
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm13
  movdqa    xmm2, xmm9
  pxor      xmm2, xmm7
  movdqu    xmm9, [rsp + 16]
  movdqu    [rsp + 0], xmm13
  movdqa    xmm13, xmm2
  pxor      xmm13, xmm9
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm7
  movdqu    xmm1, [rsp + 0]
  movdqu    [rsp + 16], xmm9
  movdqa    xmm9, xmm2
  pxor      xmm9, xmm1
  movdqu    xmm2, [rsp + 16]
  movdqu    [rsp + 0], xmm1
  movdqa    xmm1, xmm8
  pxor      xmm1, xmm2
  movdqu    xmm8, [rsp + 0]
  movdqu    [rsp + 32], xmm9
  movdqa    xmm9, xmm1
  pxor      xmm9, xmm8
  movdqa    xmm1, xmm14
  pxor      xmm1, xmm12
  movdqa    xmm12, xmm10
  pxor      xmm12, xmm11
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm13
  movdqa    xmm0, xmm3
  pslldq    xmm0, 8
  movdqa    xmm11, xmm5
  pxor      xmm11, xmm0
  movdqa    xmm0, xmm3
  psrldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm5
  movdqa    xmm3, xmm1
  psrldq    xmm3, 8
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm3
  movdqa    xmm3, xmm10
  pslldq    xmm3, 8
  movdqa    xmm4, xmm12
  pxor      xmm4, xmm3
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm4
  movdqa    xmm1, xmm10
  psrldq    xmm1, 8
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm1
  movdqa    xmm1, xmm9
  pslldq    xmm1, 8
  movdqu    xmm2, [rsp + 32]
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm5
  movdqa    xmm2, xmm9
  psrldq    xmm2, 8
  movdqa    xmm4, xmm8
  pxor      xmm4, xmm2
  movdqu    [r9 + 0], xmm11
  movdqu    [r9 + 16], xmm0
  movdqu    [r9 + 32], xmm3
  movdqu    [r9 + 48], xmm1
  movdqu    [r9 + 64], xmm4
  add       rsp, 48
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize6:
  sub       rsp, 32
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [r8 + 0]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 8]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [r8 + 16]
  punpcklqdq xmm2, xmm15
  movq      xmm3, qword ptr [rdx + 24]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movq      xmm4, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [r8 + 32]
  punpcklqdq xmm4, xmm15
  movq      xmm5, qword ptr [rdx + 40]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm5, xmm15
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm7, xmm1
  db $66, $0F, $3A, $44, $FF, $01  // pclmulqdq xmm7, xmm7, 1
  movdqa    xmm8, xmm2
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm1
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm2
  movdqa    xmm11, xmm1
  pxor      xmm11, xmm2
  movdqa    xmm12, xmm9
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm9, xmm10
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm11
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm12
  pxor      xmm11, xmm6
  movdqa    xmm12, xmm11
  pxor      xmm12, xmm7
  movdqa    xmm11, xmm9
  pxor      xmm11, xmm6
  movdqa    xmm9, xmm11
  pxor      xmm9, xmm8
  movdqa    xmm11, xmm10
  pxor      xmm11, xmm7
  movdqa    xmm10, xmm11
  pxor      xmm10, xmm8
  movdqa    xmm11, xmm12
  pslldq    xmm11, 8
  movdqa    xmm13, xmm6
  pxor      xmm13, xmm11
  movdqa    xmm6, xmm12
  psrldq    xmm6, 8
  movdqa    xmm11, xmm7
  pxor      xmm11, xmm6
  movdqa    xmm6, xmm10
  pslldq    xmm6, 8
  movdqa    xmm7, xmm9
  pxor      xmm7, xmm6
  movdqa    xmm6, xmm11
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm10
  psrldq    xmm7, 8
  movdqa    xmm9, xmm8
  pxor      xmm9, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FF, $01  // pclmulqdq xmm7, xmm7, 1
  movdqa    xmm8, xmm4
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm10, xmm5
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm3
  pxor      xmm11, xmm4
  movdqa    xmm12, xmm3
  pxor      xmm12, xmm5
  movdqa    xmm14, xmm4
  pxor      xmm14, xmm5
  movdqu    [rsp + 0], xmm13
  movdqa    xmm13, xmm11
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm11, xmm12
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm14
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm14, xmm13
  pxor      xmm14, xmm7
  movdqa    xmm13, xmm14
  pxor      xmm13, xmm8
  movdqa    xmm14, xmm11
  pxor      xmm14, xmm7
  movdqa    xmm11, xmm14
  pxor      xmm11, xmm10
  movdqa    xmm14, xmm12
  pxor      xmm14, xmm8
  movdqa    xmm12, xmm14
  pxor      xmm12, xmm10
  movdqa    xmm14, xmm13
  pslldq    xmm14, 8
  movdqu    [rsp + 16], xmm9
  movdqa    xmm9, xmm7
  pxor      xmm9, xmm14
  movdqa    xmm7, xmm13
  psrldq    xmm7, 8
  movdqa    xmm13, xmm8
  pxor      xmm13, xmm7
  movdqa    xmm7, xmm12
  pslldq    xmm7, 8
  movdqa    xmm8, xmm11
  pxor      xmm8, xmm7
  movdqa    xmm7, xmm13
  pxor      xmm7, xmm8
  movdqa    xmm8, xmm12
  psrldq    xmm8, 8
  movdqa    xmm11, xmm10
  pxor      xmm11, xmm8
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm3
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm4
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm5
  movdqa    xmm2, xmm8
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm4, xmm1
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm8
  pxor      xmm5, xmm0
  movdqa    xmm10, xmm8
  pxor      xmm10, xmm1
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm1
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm10
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm5, xmm8
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm2
  movdqa    xmm0, xmm8
  pxor      xmm0, xmm3
  movdqa    xmm8, xmm1
  pxor      xmm8, xmm2
  movdqa    xmm1, xmm8
  pxor      xmm1, xmm4
  movdqa    xmm8, xmm5
  pxor      xmm8, xmm3
  movdqa    xmm5, xmm8
  pxor      xmm5, xmm4
  movdqa    xmm8, xmm0
  pslldq    xmm8, 8
  movdqa    xmm10, xmm2
  pxor      xmm10, xmm8
  movdqa    xmm2, xmm0
  psrldq    xmm2, 8
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm2
  movdqa    xmm2, xmm5
  pslldq    xmm2, 8
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm2
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm3
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm0
  movdqu    xmm0, [rsp + 0]
  movdqa    xmm3, xmm10
  pxor      xmm3, xmm0
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm9
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm6
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm7
  movdqu    xmm3, [rsp + 16]
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm2, xmm5
  pxor      xmm2, xmm11
  movdqa    xmm5, xmm4
  pslldq    xmm5, 8
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm5
  movdqa    xmm5, xmm4
  psrldq    xmm5, 8
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm5
  movdqa    xmm3, xmm1
  pslldq    xmm3, 8
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm3
  movdqa    xmm3, xmm1
  psrldq    xmm3, 8
  movdqa    xmm1, xmm9
  pxor      xmm1, xmm3
  movdqa    xmm3, xmm2
  pslldq    xmm3, 8
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm3
  movdqa    xmm1, xmm2
  psrldq    xmm1, 8
  movdqa    xmm2, xmm7
  pxor      xmm2, xmm1
  movdqu    [r9 + 0], xmm0
  movdqu    [r9 + 16], xmm8
  movdqu    [r9 + 32], xmm5
  movdqu    [r9 + 48], xmm4
  movdqu    [r9 + 64], xmm2
  movdqu    [r9 + 80], xmm11
  add       rsp, 32
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize7:
  sub       rsp, 16
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [rdx + 8]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [rdx + 24]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [r8 + 0]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm2, xmm15
  movq      xmm3, qword ptr [r8 + 16]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqa    xmm7, xmm0
  punpckhqdq xmm7, xmm2
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm7
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $00  // pclmulqdq xmm6, xmm2, 0
  movdqa    xmm7, xmm0
  db $66, $0F, $3A, $44, $FA, $11  // pclmulqdq xmm7, xmm2, 17
  movdqa    xmm0, xmm8
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm7
  movdqa    xmm8, xmm2
  pxor      xmm8, xmm0
  movdqa    xmm0, xmm8
  pslldq    xmm0, 8
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm6, xmm7
  pxor      xmm6, xmm0
  movdqa    xmm0, xmm1
  punpcklqdq xmm0, xmm3
  movdqa    xmm7, xmm1
  punpckhqdq xmm7, xmm3
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm7
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C3, $00  // pclmulqdq xmm0, xmm3, 0
  movdqa    xmm7, xmm1
  db $66, $0F, $3A, $44, $FB, $11  // pclmulqdq xmm7, xmm3, 17
  movdqa    xmm1, xmm8
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm7
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm1
  movdqa    xmm1, xmm8
  pslldq    xmm1, 8
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm1
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm4
  punpcklqdq xmm0, xmm5
  movdqa    xmm7, xmm4
  punpckhqdq xmm7, xmm5
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm7
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C5, $00  // pclmulqdq xmm0, xmm5, 0
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11  // pclmulqdq xmm7, xmm5, 17
  movdqa    xmm4, xmm8
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm7
  movdqa    xmm8, xmm5
  pxor      xmm8, xmm4
  movdqa    xmm4, xmm8
  pslldq    xmm4, 8
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm4, xmm7
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm2
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm1
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm3
  movq      xmm0, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [r8 + 32]
  punpcklqdq xmm0, xmm15
  movq      xmm3, qword ptr [rdx + 40]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm3, xmm15
  movq      xmm6, qword ptr [rdx + 48]
  movq      xmm15, qword ptr [r8 + 48]
  punpcklqdq xmm6, xmm15
  movdqa    xmm7, xmm0
  db $66, $0F, $3A, $44, $FF, $01  // pclmulqdq xmm7, xmm7, 1
  movdqa    xmm8, xmm3
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm9, xmm6
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm3
  movdqa    xmm11, xmm0
  pxor      xmm11, xmm6
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm6
  movdqa    xmm3, xmm10
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm6, xmm11
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm10, xmm0
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm7
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm8
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm7
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm9
  movdqa    xmm0, xmm10
  pxor      xmm0, xmm8
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm9
  movdqa    xmm0, xmm3
  pslldq    xmm0, 8
  movdqa    xmm11, xmm7
  pxor      xmm11, xmm0
  movdqa    xmm0, xmm3
  psrldq    xmm0, 8
  movdqa    xmm3, xmm8
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm10
  pslldq    xmm0, 8
  movdqa    xmm7, xmm6
  pxor      xmm7, xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm7
  movdqa    xmm3, xmm10
  psrldq    xmm3, 8
  movdqa    xmm6, xmm9
  pxor      xmm6, xmm3
  movq      xmm3, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [rdx + 8]
  punpcklqdq xmm3, xmm15
  movq      xmm7, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [rdx + 40]
  punpcklqdq xmm7, xmm15
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm7
  movq      xmm3, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [rdx + 24]
  punpcklqdq xmm3, xmm15
  movq      xmm7, qword ptr [rdx + 48]
  movdqa    xmm9, xmm3
  pxor      xmm9, xmm7
  movq      xmm3, qword ptr [r8 + 0]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm3, xmm15
  movq      xmm7, qword ptr [r8 + 32]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm7, xmm15
  movdqa    xmm10, xmm3
  pxor      xmm10, xmm7
  movq      xmm3, qword ptr [r8 + 16]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movq      xmm7, qword ptr [r8 + 48]
  movdqa    xmm12, xmm3
  pxor      xmm12, xmm7
  movdqa    xmm3, xmm8
  pxor      xmm3, xmm9
  movdqa    xmm7, xmm10
  pxor      xmm7, xmm12
  movdqa    xmm13, xmm8
  punpcklqdq xmm13, xmm10
  movdqa    xmm14, xmm8
  punpckhqdq xmm14, xmm10
  movdqu    [rsp + 0], xmm6
  movdqa    xmm6, xmm13
  pxor      xmm6, xmm14
  movdqa    xmm13, xmm8
  db $66, $45, $0F, $3A, $44, $EA, $00  // pclmulqdq xmm13, xmm10, 0
  movdqa    xmm14, xmm8
  db $66, $45, $0F, $3A, $44, $F2, $11  // pclmulqdq xmm14, xmm10, 17
  movdqa    xmm8, xmm6
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm6, xmm13
  pxor      xmm6, xmm14
  movdqa    xmm10, xmm6
  pxor      xmm10, xmm8
  movdqa    xmm6, xmm10
  pslldq    xmm6, 8
  movdqa    xmm8, xmm13
  pxor      xmm8, xmm6
  movdqa    xmm6, xmm10
  psrldq    xmm6, 8
  movdqa    xmm10, xmm14
  pxor      xmm10, xmm6
  movdqa    xmm6, xmm9
  punpcklqdq xmm6, xmm12
  movdqa    xmm13, xmm9
  punpckhqdq xmm13, xmm12
  movdqa    xmm14, xmm6
  pxor      xmm14, xmm13
  movdqa    xmm6, xmm9
  db $66, $41, $0F, $3A, $44, $F4, $00  // pclmulqdq xmm6, xmm12, 0
  movdqa    xmm13, xmm9
  db $66, $45, $0F, $3A, $44, $EC, $11  // pclmulqdq xmm13, xmm12, 17
  movdqa    xmm9, xmm14
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm12, xmm6
  pxor      xmm12, xmm13
  movdqa    xmm14, xmm12
  pxor      xmm14, xmm9
  movdqa    xmm9, xmm14
  pslldq    xmm9, 8
  movdqa    xmm12, xmm6
  pxor      xmm12, xmm9
  movdqa    xmm6, xmm14
  psrldq    xmm6, 8
  movdqa    xmm9, xmm13
  pxor      xmm9, xmm6
  movdqa    xmm6, xmm3
  punpcklqdq xmm6, xmm7
  movdqa    xmm13, xmm3
  punpckhqdq xmm13, xmm7
  movdqa    xmm14, xmm6
  pxor      xmm14, xmm13
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F7, $00  // pclmulqdq xmm6, xmm7, 0
  movdqa    xmm13, xmm3
  db $66, $44, $0F, $3A, $44, $EF, $11  // pclmulqdq xmm13, xmm7, 17
  movdqa    xmm3, xmm14
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm7, xmm6
  pxor      xmm7, xmm13
  movdqa    xmm14, xmm7
  pxor      xmm14, xmm3
  movdqa    xmm3, xmm14
  pslldq    xmm3, 8
  movdqa    xmm7, xmm6
  pxor      xmm7, xmm3
  movdqa    xmm3, xmm14
  psrldq    xmm3, 8
  movdqa    xmm6, xmm13
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm10
  pxor      xmm3, xmm12
  movdqa    xmm10, xmm7
  pxor      xmm10, xmm8
  movdqa    xmm7, xmm3
  pxor      xmm7, xmm10
  movdqa    xmm10, xmm6
  pxor      xmm10, xmm9
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm10
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm11
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm8
  pxor      xmm0, xmm2
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm7
  pxor      xmm0, xmm5
  movdqa    xmm7, xmm4
  pxor      xmm7, xmm0
  movdqu    xmm0, [rsp + 0]
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm0
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm8
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm9
  movdqu    [r9 + 0], xmm2
  movdqu    [r9 + 16], xmm5
  movdqu    [r9 + 32], xmm1
  movdqu    [r9 + 48], xmm7
  movdqu    [r9 + 64], xmm6
  movdqu    [r9 + 80], xmm3
  movdqu    [r9 + 96], xmm0
  add       rsp, 16
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize8:
  sub       rsp, 32
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [rdx + 8]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [rdx + 24]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [r8 + 0]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm2, xmm15
  movq      xmm3, qword ptr [r8 + 16]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqa    xmm7, xmm0
  punpckhqdq xmm7, xmm2
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm7
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $00  // pclmulqdq xmm6, xmm2, 0
  movdqa    xmm7, xmm0
  db $66, $0F, $3A, $44, $FA, $11  // pclmulqdq xmm7, xmm2, 17
  movdqa    xmm0, xmm8
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm7
  movdqa    xmm8, xmm2
  pxor      xmm8, xmm0
  movdqa    xmm0, xmm8
  pslldq    xmm0, 8
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm6, xmm7
  pxor      xmm6, xmm0
  movdqa    xmm0, xmm1
  punpcklqdq xmm0, xmm3
  movdqa    xmm7, xmm1
  punpckhqdq xmm7, xmm3
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm7
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C3, $00  // pclmulqdq xmm0, xmm3, 0
  movdqa    xmm7, xmm1
  db $66, $0F, $3A, $44, $FB, $11  // pclmulqdq xmm7, xmm3, 17
  movdqa    xmm1, xmm8
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm7
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm1
  movdqa    xmm1, xmm8
  pslldq    xmm1, 8
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm1
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm4
  punpcklqdq xmm0, xmm5
  movdqa    xmm7, xmm4
  punpckhqdq xmm7, xmm5
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm7
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C5, $00  // pclmulqdq xmm0, xmm5, 0
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FD, $11  // pclmulqdq xmm7, xmm5, 17
  movdqa    xmm4, xmm8
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm7
  movdqa    xmm8, xmm5
  pxor      xmm8, xmm4
  movdqa    xmm4, xmm8
  pslldq    xmm4, 8
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm4, xmm7
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm2
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm1
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm3
  movq      xmm0, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [rdx + 40]
  punpcklqdq xmm0, xmm15
  movq      xmm3, qword ptr [rdx + 48]
  movq      xmm15, qword ptr [rdx + 56]
  punpcklqdq xmm3, xmm15
  movq      xmm6, qword ptr [r8 + 32]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm6, xmm15
  movq      xmm7, qword ptr [r8 + 48]
  movq      xmm15, qword ptr [r8 + 56]
  punpcklqdq xmm7, xmm15
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm3
  movdqa    xmm9, xmm6
  pxor      xmm9, xmm7
  movdqa    xmm10, xmm0
  punpcklqdq xmm10, xmm6
  movdqa    xmm11, xmm0
  punpckhqdq xmm11, xmm6
  movdqa    xmm12, xmm10
  pxor      xmm12, xmm11
  movdqa    xmm10, xmm0
  db $66, $44, $0F, $3A, $44, $D6, $00  // pclmulqdq xmm10, xmm6, 0
  movdqa    xmm11, xmm0
  db $66, $44, $0F, $3A, $44, $DE, $11  // pclmulqdq xmm11, xmm6, 17
  movdqa    xmm0, xmm12
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm6, xmm10
  pxor      xmm6, xmm11
  movdqa    xmm12, xmm6
  pxor      xmm12, xmm0
  movdqa    xmm0, xmm12
  pslldq    xmm0, 8
  movdqa    xmm6, xmm10
  pxor      xmm6, xmm0
  movdqa    xmm0, xmm12
  psrldq    xmm0, 8
  movdqa    xmm10, xmm11
  pxor      xmm10, xmm0
  movdqa    xmm0, xmm3
  punpcklqdq xmm0, xmm7
  movdqa    xmm11, xmm3
  punpckhqdq xmm11, xmm7
  movdqa    xmm12, xmm0
  pxor      xmm12, xmm11
  movdqa    xmm0, xmm3
  db $66, $0F, $3A, $44, $C7, $00  // pclmulqdq xmm0, xmm7, 0
  movdqa    xmm11, xmm3
  db $66, $44, $0F, $3A, $44, $DF, $11  // pclmulqdq xmm11, xmm7, 17
  movdqa    xmm3, xmm12
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm7, xmm0
  pxor      xmm7, xmm11
  movdqa    xmm12, xmm7
  pxor      xmm12, xmm3
  movdqa    xmm3, xmm12
  pslldq    xmm3, 8
  movdqa    xmm7, xmm0
  pxor      xmm7, xmm3
  movdqa    xmm0, xmm12
  psrldq    xmm0, 8
  movdqa    xmm3, xmm11
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm8
  punpcklqdq xmm0, xmm9
  movdqa    xmm11, xmm8
  punpckhqdq xmm11, xmm9
  movdqa    xmm12, xmm0
  pxor      xmm12, xmm11
  movdqa    xmm0, xmm8
  db $66, $41, $0F, $3A, $44, $C1, $00  // pclmulqdq xmm0, xmm9, 0
  movdqa    xmm11, xmm8
  db $66, $45, $0F, $3A, $44, $D9, $11  // pclmulqdq xmm11, xmm9, 17
  movdqa    xmm8, xmm12
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm11
  movdqa    xmm12, xmm9
  pxor      xmm12, xmm8
  movdqa    xmm8, xmm12
  pslldq    xmm8, 8
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm8
  movdqa    xmm0, xmm12
  psrldq    xmm0, 8
  movdqa    xmm8, xmm11
  pxor      xmm8, xmm0
  movdqa    xmm0, xmm10
  pxor      xmm0, xmm7
  movdqa    xmm7, xmm9
  pxor      xmm7, xmm6
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm7
  movdqa    xmm7, xmm8
  pxor      xmm7, xmm3
  movdqa    xmm8, xmm0
  pxor      xmm8, xmm7
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [rdx + 8]
  punpcklqdq xmm0, xmm15
  movq      xmm7, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [rdx + 40]
  punpcklqdq xmm7, xmm15
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm7
  movq      xmm0, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [rdx + 24]
  punpcklqdq xmm0, xmm15
  movq      xmm7, qword ptr [rdx + 48]
  movq      xmm15, qword ptr [rdx + 56]
  punpcklqdq xmm7, xmm15
  movdqa    xmm11, xmm0
  pxor      xmm11, xmm7
  movq      xmm0, qword ptr [r8 + 0]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm0, xmm15
  movq      xmm7, qword ptr [r8 + 32]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm7, xmm15
  movdqa    xmm12, xmm0
  pxor      xmm12, xmm7
  movq      xmm0, qword ptr [r8 + 16]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm0, xmm15
  movq      xmm7, qword ptr [r8 + 48]
  movq      xmm15, qword ptr [r8 + 56]
  punpcklqdq xmm7, xmm15
  movdqa    xmm13, xmm0
  pxor      xmm13, xmm7
  movdqa    xmm0, xmm10
  pxor      xmm0, xmm11
  movdqa    xmm7, xmm12
  pxor      xmm7, xmm13
  movdqa    xmm14, xmm10
  punpcklqdq xmm14, xmm12
  movdqu    [rsp + 0], xmm3
  movdqa    xmm3, xmm10
  punpckhqdq xmm3, xmm12
  movdqu    [rsp + 16], xmm8
  movdqa    xmm8, xmm14
  pxor      xmm8, xmm3
  movdqa    xmm3, xmm10
  db $66, $41, $0F, $3A, $44, $DC, $00  // pclmulqdq xmm3, xmm12, 0
  movdqa    xmm14, xmm10
  db $66, $45, $0F, $3A, $44, $F4, $11  // pclmulqdq xmm14, xmm12, 17
  movdqa    xmm10, xmm8
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm14
  movdqa    xmm12, xmm8
  pxor      xmm12, xmm10
  movdqa    xmm8, xmm12
  pslldq    xmm8, 8
  movdqa    xmm10, xmm3
  pxor      xmm10, xmm8
  movdqa    xmm3, xmm12
  psrldq    xmm3, 8
  movdqa    xmm8, xmm14
  pxor      xmm8, xmm3
  movdqa    xmm3, xmm11
  punpcklqdq xmm3, xmm13
  movdqa    xmm12, xmm11
  punpckhqdq xmm12, xmm13
  movdqa    xmm14, xmm3
  pxor      xmm14, xmm12
  movdqa    xmm3, xmm11
  db $66, $41, $0F, $3A, $44, $DD, $00  // pclmulqdq xmm3, xmm13, 0
  movdqa    xmm12, xmm11
  db $66, $45, $0F, $3A, $44, $E5, $11  // pclmulqdq xmm12, xmm13, 17
  movdqa    xmm11, xmm14
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm13, xmm3
  pxor      xmm13, xmm12
  movdqa    xmm14, xmm13
  pxor      xmm14, xmm11
  movdqa    xmm11, xmm14
  pslldq    xmm11, 8
  movdqa    xmm13, xmm3
  pxor      xmm13, xmm11
  movdqa    xmm3, xmm14
  psrldq    xmm3, 8
  movdqa    xmm11, xmm12
  pxor      xmm11, xmm3
  movdqa    xmm3, xmm0
  punpcklqdq xmm3, xmm7
  movdqa    xmm12, xmm0
  punpckhqdq xmm12, xmm7
  movdqa    xmm14, xmm3
  pxor      xmm14, xmm12
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DF, $00  // pclmulqdq xmm3, xmm7, 0
  movdqa    xmm12, xmm0
  db $66, $44, $0F, $3A, $44, $E7, $11  // pclmulqdq xmm12, xmm7, 17
  movdqa    xmm0, xmm14
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm7, xmm3
  pxor      xmm7, xmm12
  movdqa    xmm14, xmm7
  pxor      xmm14, xmm0
  movdqa    xmm0, xmm14
  pslldq    xmm0, 8
  movdqa    xmm7, xmm3
  pxor      xmm7, xmm0
  movdqa    xmm0, xmm14
  psrldq    xmm0, 8
  movdqa    xmm3, xmm12
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm8
  pxor      xmm0, xmm13
  movdqa    xmm8, xmm7
  pxor      xmm8, xmm10
  movdqa    xmm7, xmm0
  pxor      xmm7, xmm8
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm11
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm8
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm6
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm9
  movdqa    xmm1, xmm10
  pxor      xmm1, xmm2
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm5
  movdqa    xmm7, xmm4
  pxor      xmm7, xmm1
  movdqu    xmm1, [rsp + 16]
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm8
  movdqu    xmm0, [rsp + 0]
  movdqa    xmm8, xmm11
  pxor      xmm8, xmm0
  movdqa    xmm9, xmm4
  pxor      xmm9, xmm8
  movdqu    [r9 + 0], xmm2
  movdqu    [r9 + 16], xmm5
  movdqu    [r9 + 32], xmm6
  movdqu    [r9 + 48], xmm7
  movdqu    [r9 + 64], xmm3
  movdqu    [r9 + 80], xmm9
  movdqu    [r9 + 96], xmm1
  movdqu    [r9 + 112], xmm0
  add       rsp, 32
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize9:
  sub       rsp, 192
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [r8 + 0]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 8]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [r8 + 16]
  punpcklqdq xmm2, xmm15
  movq      xmm3, qword ptr [rdx + 24]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movq      xmm4, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [r8 + 32]
  punpcklqdq xmm4, xmm15
  movq      xmm5, qword ptr [rdx + 40]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm5, xmm15
  movq      xmm6, qword ptr [rdx + 48]
  movq      xmm15, qword ptr [r8 + 48]
  punpcklqdq xmm6, xmm15
  movq      xmm7, qword ptr [rdx + 56]
  movq      xmm15, qword ptr [r8 + 56]
  punpcklqdq xmm7, xmm15
  movq      xmm8, qword ptr [rdx + 64]
  movq      xmm15, qword ptr [r8 + 64]
  punpcklqdq xmm8, xmm15
  movdqa    xmm9, xmm0
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm1
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm2
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm0
  pxor      xmm12, xmm1
  movdqa    xmm13, xmm0
  pxor      xmm13, xmm2
  movdqa    xmm14, xmm1
  pxor      xmm14, xmm2
  movdqu    [rsp + 0], xmm5
  movdqa    xmm5, xmm12
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm12, xmm13
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm13, xmm14
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm14, xmm5
  pxor      xmm14, xmm9
  movdqa    xmm5, xmm14
  pxor      xmm5, xmm10
  movdqa    xmm14, xmm12
  pxor      xmm14, xmm9
  movdqa    xmm12, xmm14
  pxor      xmm12, xmm11
  movdqa    xmm14, xmm13
  pxor      xmm14, xmm10
  movdqa    xmm13, xmm14
  pxor      xmm13, xmm11
  movdqa    xmm14, xmm5
  pslldq    xmm14, 8
  movdqu    [rsp + 16], xmm8
  movdqa    xmm8, xmm9
  pxor      xmm8, xmm14
  movdqa    xmm9, xmm5
  psrldq    xmm9, 8
  movdqa    xmm5, xmm10
  pxor      xmm5, xmm9
  movdqa    xmm9, xmm13
  pslldq    xmm9, 8
  movdqa    xmm10, xmm12
  pxor      xmm10, xmm9
  movdqa    xmm9, xmm5
  pxor      xmm9, xmm10
  movdqa    xmm5, xmm13
  psrldq    xmm5, 8
  movdqa    xmm10, xmm11
  pxor      xmm10, xmm5
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm11, xmm4
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqu    xmm12, [rsp + 0]
  movdqa    xmm13, xmm12
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm14, xmm3
  pxor      xmm14, xmm4
  movdqu    [rsp + 32], xmm8
  movdqa    xmm8, xmm3
  pxor      xmm8, xmm12
  movdqu    [rsp + 48], xmm10
  movdqa    xmm10, xmm4
  pxor      xmm10, xmm12
  movdqu    [rsp + 64], xmm9
  movdqa    xmm9, xmm14
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm14, xmm8
  db $66, $45, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm14, xmm14, 1
  movdqa    xmm8, xmm10
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm10, xmm9
  pxor      xmm10, xmm5
  movdqa    xmm9, xmm10
  pxor      xmm9, xmm11
  movdqa    xmm10, xmm14
  pxor      xmm10, xmm5
  movdqa    xmm14, xmm10
  pxor      xmm14, xmm13
  movdqa    xmm10, xmm8
  pxor      xmm10, xmm11
  movdqa    xmm8, xmm10
  pxor      xmm8, xmm13
  movdqa    xmm10, xmm9
  pslldq    xmm10, 8
  movdqu    [rsp + 0], xmm12
  movdqa    xmm12, xmm5
  pxor      xmm12, xmm10
  movdqa    xmm5, xmm9
  psrldq    xmm5, 8
  movdqa    xmm9, xmm11
  pxor      xmm9, xmm5
  movdqa    xmm5, xmm8
  pslldq    xmm5, 8
  movdqa    xmm10, xmm14
  pxor      xmm10, xmm5
  movdqa    xmm5, xmm9
  pxor      xmm5, xmm10
  movdqa    xmm9, xmm8
  psrldq    xmm9, 8
  movdqa    xmm8, xmm13
  pxor      xmm8, xmm9
  movdqa    xmm9, xmm6
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm7
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqu    xmm11, [rsp + 16]
  movdqa    xmm13, xmm11
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm14, xmm6
  pxor      xmm14, xmm7
  movdqu    [rsp + 80], xmm8
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm11
  movdqu    [rsp + 96], xmm5
  movdqa    xmm5, xmm7
  pxor      xmm5, xmm11
  movdqu    [rsp + 112], xmm12
  movdqa    xmm12, xmm14
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm14, xmm8
  db $66, $45, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm14, xmm14, 1
  movdqa    xmm8, xmm5
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm5, xmm12
  pxor      xmm5, xmm9
  movdqa    xmm12, xmm5
  pxor      xmm12, xmm10
  movdqa    xmm5, xmm14
  pxor      xmm5, xmm9
  movdqa    xmm14, xmm5
  pxor      xmm14, xmm13
  movdqa    xmm5, xmm8
  pxor      xmm5, xmm10
  movdqa    xmm8, xmm5
  pxor      xmm8, xmm13
  movdqa    xmm5, xmm12
  pslldq    xmm5, 8
  movdqu    [rsp + 16], xmm11
  movdqa    xmm11, xmm9
  pxor      xmm11, xmm5
  movdqa    xmm5, xmm12
  psrldq    xmm5, 8
  movdqa    xmm9, xmm10
  pxor      xmm9, xmm5
  movdqa    xmm5, xmm8
  pslldq    xmm5, 8
  movdqa    xmm10, xmm14
  pxor      xmm10, xmm5
  movdqa    xmm5, xmm9
  pxor      xmm5, xmm10
  movdqa    xmm9, xmm8
  psrldq    xmm9, 8
  movdqa    xmm8, xmm13
  pxor      xmm8, xmm9
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm3
  movdqa    xmm10, xmm1
  pxor      xmm10, xmm4
  movdqu    xmm12, [rsp + 0]
  movdqa    xmm13, xmm2
  pxor      xmm13, xmm12
  movdqa    xmm14, xmm9
  db $66, $45, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm14, xmm14, 1
  movdqu    [rsp + 128], xmm8
  movdqa    xmm8, xmm10
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqu    [rsp + 144], xmm5
  movdqa    xmm5, xmm13
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    [rsp + 160], xmm11
  movdqa    xmm11, xmm9
  pxor      xmm11, xmm10
  movdqu    [rsp + 0], xmm12
  movdqa    xmm12, xmm9
  pxor      xmm12, xmm13
  movdqa    xmm9, xmm10
  pxor      xmm9, xmm13
  movdqa    xmm10, xmm11
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm12
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm9
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm9, xmm10
  pxor      xmm9, xmm14
  movdqa    xmm10, xmm9
  pxor      xmm10, xmm8
  movdqa    xmm9, xmm11
  pxor      xmm9, xmm14
  movdqa    xmm11, xmm9
  pxor      xmm11, xmm5
  movdqa    xmm9, xmm12
  pxor      xmm9, xmm8
  movdqa    xmm12, xmm9
  pxor      xmm12, xmm5
  movdqa    xmm9, xmm10
  pslldq    xmm9, 8
  movdqa    xmm13, xmm14
  pxor      xmm13, xmm9
  movdqa    xmm9, xmm10
  psrldq    xmm9, 8
  movdqa    xmm10, xmm8
  pxor      xmm10, xmm9
  movdqa    xmm8, xmm12
  pslldq    xmm8, 8
  movdqa    xmm9, xmm11
  pxor      xmm9, xmm8
  movdqa    xmm8, xmm10
  pxor      xmm8, xmm9
  movdqa    xmm9, xmm12
  psrldq    xmm9, 8
  movdqa    xmm10, xmm5
  pxor      xmm10, xmm9
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm7
  movdqu    xmm1, [rsp + 16]
  movdqa    xmm9, xmm2
  pxor      xmm9, xmm1
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm11, xmm0
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm9
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm14, xmm5
  pxor      xmm14, xmm0
  movdqu    [rsp + 176], xmm10
  movdqa    xmm10, xmm5
  pxor      xmm10, xmm9
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm9
  movdqa    xmm0, xmm14
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm9, xmm10
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm5
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm2
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm11
  movdqa    xmm5, xmm9
  pxor      xmm5, xmm2
  movdqa    xmm9, xmm5
  pxor      xmm9, xmm12
  movdqa    xmm5, xmm10
  pxor      xmm5, xmm11
  movdqa    xmm10, xmm5
  pxor      xmm10, xmm12
  movdqa    xmm5, xmm0
  pslldq    xmm5, 8
  movdqa    xmm14, xmm2
  pxor      xmm14, xmm5
  movdqa    xmm2, xmm0
  psrldq    xmm2, 8
  movdqa    xmm0, xmm11
  pxor      xmm0, xmm2
  movdqa    xmm2, xmm10
  pslldq    xmm2, 8
  movdqa    xmm5, xmm9
  pxor      xmm5, xmm2
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm5
  movdqa    xmm0, xmm10
  psrldq    xmm0, 8
  movdqa    xmm5, xmm12
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm6
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm7
  movdqu    xmm4, [rsp + 0]
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm4, xmm3
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm7, xmm6
  db $66, $0F, $3A, $44, $FF, $01  // pclmulqdq xmm7, xmm7, 1
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm3
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm6
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm6
  movdqa    xmm3, xmm9
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm6, xmm10
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm9, xmm0
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm4
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm1
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm7
  movdqa    xmm0, xmm9
  pxor      xmm0, xmm4
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm7
  movdqa    xmm0, xmm3
  pslldq    xmm0, 8
  movdqa    xmm10, xmm1
  pxor      xmm10, xmm0
  movdqa    xmm0, xmm3
  psrldq    xmm0, 8
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm9
  pslldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm9
  psrldq    xmm1, 8
  movdqa    xmm3, xmm7
  pxor      xmm3, xmm1
  movdqu    xmm1, [rsp + 32]
  movdqa    xmm4, xmm13
  pxor      xmm4, xmm1
  movdqu    xmm6, [rsp + 112]
  movdqa    xmm7, xmm4
  pxor      xmm7, xmm6
  movdqu    xmm4, [rsp + 64]
  movdqa    xmm9, xmm8
  pxor      xmm9, xmm4
  movdqu    xmm8, [rsp + 96]
  movdqa    xmm11, xmm9
  pxor      xmm11, xmm8
  movdqu    xmm9, [rsp + 176]
  movdqu    xmm12, [rsp + 48]
  movdqa    xmm13, xmm9
  pxor      xmm13, xmm12
  movdqu    xmm9, [rsp + 80]
  movdqu    [rsp + 32], xmm1
  movdqa    xmm1, xmm13
  pxor      xmm1, xmm9
  movdqu    xmm13, [rsp + 32]
  movdqu    [rsp + 80], xmm9
  movdqa    xmm9, xmm14
  pxor      xmm9, xmm13
  movdqu    xmm14, [rsp + 160]
  movdqu    [rsp + 32], xmm13
  movdqa    xmm13, xmm9
  pxor      xmm13, xmm14
  movdqa    xmm9, xmm2
  pxor      xmm9, xmm4
  movdqu    xmm2, [rsp + 144]
  movdqu    [rsp + 160], xmm14
  movdqa    xmm14, xmm9
  pxor      xmm14, xmm2
  movdqa    xmm9, xmm5
  pxor      xmm9, xmm12
  movdqu    xmm5, [rsp + 128]
  movdqu    [rsp + 144], xmm2
  movdqa    xmm2, xmm9
  pxor      xmm2, xmm5
  movdqa    xmm9, xmm10
  pxor      xmm9, xmm6
  movdqu    xmm10, [rsp + 160]
  movdqu    [rsp + 128], xmm5
  movdqa    xmm5, xmm9
  pxor      xmm5, xmm10
  movdqa    xmm9, xmm0
  pxor      xmm9, xmm8
  movdqu    xmm0, [rsp + 144]
  movdqu    [rsp + 160], xmm10
  movdqa    xmm10, xmm9
  pxor      xmm10, xmm0
  movdqu    xmm9, [rsp + 80]
  movdqu    [rsp + 144], xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm9
  movdqu    xmm3, [rsp + 128]
  movdqu    [rsp + 176], xmm10
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm3
  movdqa    xmm0, xmm7
  pslldq    xmm0, 8
  movdqu    [rsp + 128], xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm7
  psrldq    xmm0, 8
  movdqa    xmm4, xmm12
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm11
  pslldq    xmm0, 8
  movdqa    xmm7, xmm4
  pxor      xmm7, xmm0
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm13
  movdqa    xmm4, xmm11
  psrldq    xmm4, 8
  movdqa    xmm6, xmm1
  pslldq    xmm6, 8
  movdqa    xmm11, xmm4
  pxor      xmm11, xmm6
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm11
  movdqa    xmm0, xmm8
  pxor      xmm0, xmm14
  movdqa    xmm6, xmm1
  psrldq    xmm6, 8
  movdqa    xmm1, xmm5
  pslldq    xmm1, 8
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm8
  movdqa    xmm0, xmm9
  pxor      xmm0, xmm2
  movdqa    xmm2, xmm5
  psrldq    xmm2, 8
  movdqu    xmm5, [rsp + 176]
  movdqa    xmm6, xmm5
  pslldq    xmm6, 8
  movdqa    xmm8, xmm2
  pxor      xmm8, xmm6
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm8
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm5, xmm10
  pslldq    xmm5, 8
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movdqu    xmm0, [rsp + 160]
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqa    xmm0, xmm10
  psrldq    xmm0, 8
  movdqu    xmm6, [rsp + 144]
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm0
  movdqu    xmm0, [rsp + 32]
  movdqu    [r9 + 0], xmm0
  movdqu    [r9 + 16], xmm3
  movdqu    [r9 + 32], xmm7
  movdqu    [r9 + 48], xmm4
  movdqu    [r9 + 64], xmm1
  movdqu    [r9 + 80], xmm2
  movdqu    [r9 + 96], xmm5
  movdqu    [r9 + 112], xmm8
  movdqu    xmm0, [rsp + 128]
  movdqu    [r9 + 128], xmm0
  add       rsp, 192
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallSize10:
  sub       rsp, 288
  movq      xmm0, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [r8 + 0]
  punpcklqdq xmm0, xmm15
  movq      xmm1, qword ptr [rdx + 8]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm1, xmm15
  movq      xmm2, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [r8 + 16]
  punpcklqdq xmm2, xmm15
  movq      xmm3, qword ptr [rdx + 24]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm3, xmm15
  movq      xmm4, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [r8 + 32]
  punpcklqdq xmm4, xmm15
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm6, xmm1
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm7, xmm2
  db $66, $0F, $3A, $44, $FF, $01  // pclmulqdq xmm7, xmm7, 1
  movdqa    xmm8, xmm3
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm9, xmm4
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm1
  movdqa    xmm11, xmm0
  pxor      xmm11, xmm2
  movdqa    xmm12, xmm0
  pxor      xmm12, xmm3
  movdqa    xmm13, xmm0
  pxor      xmm13, xmm4
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqa    xmm14, xmm1
  pxor      xmm14, xmm3
  movdqu    [rsp + 0], xmm9
  movdqa    xmm9, xmm1
  pxor      xmm9, xmm4
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm3
  movdqu    [rsp + 16], xmm8
  movdqa    xmm8, xmm2
  pxor      xmm8, xmm4
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm4
  movdqa    xmm3, xmm10
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm4, xmm11
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm10, xmm12
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm13
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm0
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm0, xmm14
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm13, xmm9
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm9, xmm1
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm1, xmm8
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm8, xmm2
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm5
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm6
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm5
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm7
  movdqa    xmm2, xmm10
  pxor      xmm2, xmm5
  movdqu    xmm10, [rsp + 16]
  movdqa    xmm14, xmm2
  pxor      xmm14, xmm10
  movdqa    xmm2, xmm11
  pxor      xmm2, xmm5
  movdqu    xmm11, [rsp + 0]
  movdqu    [rsp + 16], xmm10
  movdqa    xmm10, xmm2
  pxor      xmm10, xmm11
  movdqa    xmm2, xmm12
  pxor      xmm2, xmm6
  movdqa    xmm12, xmm2
  pxor      xmm12, xmm7
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm6
  movdqu    xmm0, [rsp + 16]
  movdqu    [rsp + 0], xmm11
  movdqa    xmm11, xmm2
  pxor      xmm11, xmm0
  movdqa    xmm2, xmm13
  pxor      xmm2, xmm6
  movdqu    xmm13, [rsp + 0]
  movdqu    [rsp + 16], xmm0
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm13
  movdqa    xmm2, xmm9
  pxor      xmm2, xmm7
  movdqu    xmm9, [rsp + 16]
  movdqu    [rsp + 0], xmm13
  movdqa    xmm13, xmm2
  pxor      xmm13, xmm9
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm7
  movdqu    xmm1, [rsp + 0]
  movdqu    [rsp + 16], xmm9
  movdqa    xmm9, xmm2
  pxor      xmm9, xmm1
  movdqu    xmm2, [rsp + 16]
  movdqu    [rsp + 0], xmm1
  movdqa    xmm1, xmm8
  pxor      xmm1, xmm2
  movdqu    xmm8, [rsp + 0]
  movdqu    [rsp + 32], xmm9
  movdqa    xmm9, xmm1
  pxor      xmm9, xmm8
  movdqa    xmm1, xmm14
  pxor      xmm1, xmm12
  movdqa    xmm12, xmm10
  pxor      xmm12, xmm11
  movdqa    xmm10, xmm0
  pxor      xmm10, xmm13
  movdqa    xmm0, xmm3
  pslldq    xmm0, 8
  movdqa    xmm11, xmm5
  pxor      xmm11, xmm0
  movdqa    xmm0, xmm3
  psrldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm5
  movdqa    xmm3, xmm1
  psrldq    xmm3, 8
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm3
  movdqa    xmm3, xmm10
  pslldq    xmm3, 8
  movdqa    xmm4, xmm12
  pxor      xmm4, xmm3
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm4
  movdqa    xmm1, xmm10
  psrldq    xmm1, 8
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm1
  movdqa    xmm1, xmm9
  pslldq    xmm1, 8
  movdqu    xmm2, [rsp + 32]
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm5
  movdqa    xmm2, xmm9
  psrldq    xmm2, 8
  movdqa    xmm4, xmm8
  pxor      xmm4, xmm2
  movq      xmm2, qword ptr [rdx + 40]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm2, xmm15
  movq      xmm5, qword ptr [rdx + 48]
  movq      xmm15, qword ptr [r8 + 48]
  punpcklqdq xmm5, xmm15
  movq      xmm6, qword ptr [rdx + 56]
  movq      xmm15, qword ptr [r8 + 56]
  punpcklqdq xmm6, xmm15
  movq      xmm7, qword ptr [rdx + 64]
  movq      xmm15, qword ptr [r8 + 64]
  punpcklqdq xmm7, xmm15
  movq      xmm8, qword ptr [rdx + 72]
  movq      xmm15, qword ptr [r8 + 72]
  punpcklqdq xmm8, xmm15
  movdqa    xmm9, xmm2
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm10, xmm5
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm12, xmm6
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm13, xmm7
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm14, xmm8
  db $66, $45, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm14, xmm14, 1
  movdqu    [rsp + 0], xmm4
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm5
  movdqu    [rsp + 32], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm6
  movdqu    [rsp + 16], xmm3
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm7
  movdqu    [rsp + 48], xmm0
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm8
  movdqa    xmm2, xmm5
  pxor      xmm2, xmm6
  movdqu    [rsp + 64], xmm11
  movdqa    xmm11, xmm5
  pxor      xmm11, xmm7
  movdqu    [rsp + 80], xmm14
  movdqa    xmm14, xmm5
  pxor      xmm14, xmm8
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm7
  movdqu    [rsp + 96], xmm13
  movdqa    xmm13, xmm6
  pxor      xmm13, xmm8
  movdqa    xmm6, xmm7
  pxor      xmm6, xmm8
  movdqa    xmm7, xmm4
  db $66, $0F, $3A, $44, $FF, $01  // pclmulqdq xmm7, xmm7, 1
  movdqa    xmm4, xmm1
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm1, xmm3
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm0, xmm2
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm11
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm8, xmm14
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm11, xmm5
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm5, xmm13
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm13, xmm6
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm6, xmm7
  pxor      xmm6, xmm9
  movdqa    xmm7, xmm6
  pxor      xmm7, xmm10
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm9
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm12
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm9
  movdqu    xmm1, [rsp + 96]
  movdqa    xmm14, xmm6
  pxor      xmm14, xmm1
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm9
  movdqu    xmm3, [rsp + 80]
  movdqu    [rsp + 96], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm3
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm10
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm12
  movdqa    xmm6, xmm2
  pxor      xmm6, xmm10
  movdqu    xmm2, [rsp + 96]
  movdqu    [rsp + 80], xmm3
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm2
  movdqa    xmm6, xmm8
  pxor      xmm6, xmm10
  movdqu    xmm8, [rsp + 80]
  movdqu    [rsp + 96], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm8
  movdqa    xmm6, xmm11
  pxor      xmm6, xmm12
  movdqu    xmm11, [rsp + 96]
  movdqu    [rsp + 80], xmm8
  movdqa    xmm8, xmm6
  pxor      xmm8, xmm11
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm12
  movdqu    xmm5, [rsp + 80]
  movdqu    [rsp + 96], xmm11
  movdqa    xmm11, xmm6
  pxor      xmm11, xmm5
  movdqu    xmm6, [rsp + 96]
  movdqu    [rsp + 80], xmm5
  movdqa    xmm5, xmm13
  pxor      xmm5, xmm6
  movdqu    xmm13, [rsp + 80]
  movdqu    [rsp + 112], xmm11
  movdqa    xmm11, xmm5
  pxor      xmm11, xmm13
  movdqa    xmm5, xmm14
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm8
  movdqa    xmm2, xmm7
  pslldq    xmm2, 8
  movdqa    xmm3, xmm9
  pxor      xmm3, xmm2
  movdqa    xmm2, xmm7
  psrldq    xmm2, 8
  movdqa    xmm7, xmm10
  pxor      xmm7, xmm2
  movdqa    xmm2, xmm5
  pslldq    xmm2, 8
  movdqa    xmm8, xmm4
  pxor      xmm8, xmm2
  movdqa    xmm2, xmm7
  pxor      xmm2, xmm8
  movdqa    xmm4, xmm5
  psrldq    xmm4, 8
  movdqa    xmm5, xmm12
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm1
  pslldq    xmm4, 8
  movdqa    xmm7, xmm0
  pxor      xmm7, xmm4
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm7
  movdqa    xmm4, xmm1
  psrldq    xmm4, 8
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm4
  movdqa    xmm4, xmm11
  pslldq    xmm4, 8
  movdqu    xmm5, [rsp + 112]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm6
  movdqa    xmm1, xmm11
  psrldq    xmm1, 8
  movdqa    xmm5, xmm13
  pxor      xmm5, xmm1
  movq      xmm1, qword ptr [rdx + 0]
  movq      xmm15, qword ptr [r8 + 40]
  punpcklqdq xmm1, xmm15
  movq      xmm6, qword ptr [rdx + 8]
  movq      xmm15, qword ptr [r8 + 48]
  punpcklqdq xmm6, xmm15
  movq      xmm7, qword ptr [rdx + 16]
  movq      xmm15, qword ptr [r8 + 56]
  punpcklqdq xmm7, xmm15
  movq      xmm8, qword ptr [rdx + 24]
  movq      xmm15, qword ptr [r8 + 64]
  punpcklqdq xmm8, xmm15
  movq      xmm9, qword ptr [rdx + 32]
  movq      xmm15, qword ptr [r8 + 72]
  punpcklqdq xmm9, xmm15
  movdqa    xmm10, xmm1
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm6
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm7
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm13, xmm8
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm14, xmm9
  db $66, $45, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm14, xmm14, 1
  movdqu    [rsp + 80], xmm5
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm6
  movdqu    [rsp + 112], xmm4
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm7
  movdqu    [rsp + 96], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm8
  movdqu    [rsp + 128], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm9
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm7
  movdqu    [rsp + 144], xmm3
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm8
  movdqu    [rsp + 160], xmm14
  movdqa    xmm14, xmm6
  pxor      xmm14, xmm9
  movdqa    xmm6, xmm7
  pxor      xmm6, xmm8
  movdqu    [rsp + 176], xmm13
  movdqa    xmm13, xmm7
  pxor      xmm13, xmm9
  movdqa    xmm7, xmm8
  pxor      xmm7, xmm9
  movdqa    xmm8, xmm5
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm5, xmm4
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm0, xmm2
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm1
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm1, xmm3
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm14
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm9, xmm6
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm6, xmm13
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm13, xmm7
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm7, xmm8
  pxor      xmm7, xmm10
  movdqa    xmm8, xmm7
  pxor      xmm8, xmm11
  movdqa    xmm7, xmm5
  pxor      xmm7, xmm10
  movdqa    xmm5, xmm7
  pxor      xmm5, xmm12
  movdqa    xmm7, xmm4
  pxor      xmm7, xmm10
  movdqu    xmm4, [rsp + 176]
  movdqa    xmm14, xmm7
  pxor      xmm14, xmm4
  movdqa    xmm7, xmm0
  pxor      xmm7, xmm10
  movdqu    xmm0, [rsp + 160]
  movdqu    [rsp + 176], xmm4
  movdqa    xmm4, xmm7
  pxor      xmm4, xmm0
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm11
  movdqa    xmm2, xmm7
  pxor      xmm2, xmm12
  movdqa    xmm7, xmm1
  pxor      xmm7, xmm11
  movdqu    xmm1, [rsp + 176]
  movdqu    [rsp + 160], xmm0
  movdqa    xmm0, xmm7
  pxor      xmm0, xmm1
  movdqa    xmm7, xmm3
  pxor      xmm7, xmm11
  movdqu    xmm3, [rsp + 160]
  movdqu    [rsp + 176], xmm1
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm3
  movdqa    xmm7, xmm9
  pxor      xmm7, xmm12
  movdqu    xmm9, [rsp + 176]
  movdqu    [rsp + 160], xmm3
  movdqa    xmm3, xmm7
  pxor      xmm3, xmm9
  movdqa    xmm7, xmm6
  pxor      xmm7, xmm12
  movdqu    xmm6, [rsp + 160]
  movdqu    [rsp + 176], xmm9
  movdqa    xmm9, xmm7
  pxor      xmm9, xmm6
  movdqu    xmm7, [rsp + 176]
  movdqu    [rsp + 160], xmm6
  movdqa    xmm6, xmm13
  pxor      xmm6, xmm7
  movdqu    xmm13, [rsp + 160]
  movdqu    [rsp + 192], xmm9
  movdqa    xmm9, xmm6
  pxor      xmm9, xmm13
  movdqa    xmm6, xmm14
  pxor      xmm6, xmm2
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm8
  pslldq    xmm1, 8
  movdqa    xmm3, xmm10
  pxor      xmm3, xmm1
  movdqa    xmm1, xmm8
  psrldq    xmm1, 8
  movdqa    xmm4, xmm11
  pxor      xmm4, xmm1
  movdqa    xmm1, xmm6
  pslldq    xmm1, 8
  movdqa    xmm8, xmm5
  pxor      xmm8, xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm8
  movdqa    xmm4, xmm6
  psrldq    xmm4, 8
  movdqa    xmm5, xmm12
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm0
  pslldq    xmm4, 8
  movdqa    xmm6, xmm2
  pxor      xmm6, xmm4
  movdqa    xmm2, xmm5
  pxor      xmm2, xmm6
  movdqa    xmm4, xmm0
  psrldq    xmm4, 8
  movdqa    xmm0, xmm7
  pxor      xmm0, xmm4
  movdqa    xmm4, xmm9
  pslldq    xmm4, 8
  movdqu    xmm5, [rsp + 192]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm6
  movdqa    xmm0, xmm9
  psrldq    xmm0, 8
  movdqa    xmm5, xmm13
  pxor      xmm5, xmm0
  movq      xmm0, qword ptr [rdx + 40]
  movq      xmm15, qword ptr [r8 + 0]
  punpcklqdq xmm0, xmm15
  movq      xmm6, qword ptr [rdx + 48]
  movq      xmm15, qword ptr [r8 + 8]
  punpcklqdq xmm6, xmm15
  movq      xmm7, qword ptr [rdx + 56]
  movq      xmm15, qword ptr [r8 + 16]
  punpcklqdq xmm7, xmm15
  movq      xmm8, qword ptr [rdx + 64]
  movq      xmm15, qword ptr [r8 + 24]
  punpcklqdq xmm8, xmm15
  movq      xmm9, qword ptr [rdx + 72]
  movq      xmm15, qword ptr [r8 + 32]
  punpcklqdq xmm9, xmm15
  movdqa    xmm10, xmm0
  db $66, $45, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm10, xmm10, 1
  movdqa    xmm11, xmm6
  db $66, $45, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm11, xmm11, 1
  movdqa    xmm12, xmm7
  db $66, $45, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm12, xmm12, 1
  movdqa    xmm13, xmm8
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm14, xmm9
  db $66, $45, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm14, xmm14, 1
  movdqu    [rsp + 160], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqu    [rsp + 192], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm7
  movdqu    [rsp + 176], xmm2
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm8
  movdqu    [rsp + 208], xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm9
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm7
  movdqu    [rsp + 224], xmm3
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm8
  movdqu    [rsp + 240], xmm14
  movdqa    xmm14, xmm6
  pxor      xmm14, xmm9
  movdqa    xmm6, xmm7
  pxor      xmm6, xmm8
  movdqu    [rsp + 256], xmm13
  movdqa    xmm13, xmm7
  pxor      xmm13, xmm9
  movdqa    xmm7, xmm8
  pxor      xmm7, xmm9
  movdqa    xmm8, xmm5
  db $66, $45, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm8, xmm8, 1
  movdqa    xmm5, xmm4
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm4, xmm2
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm2, xmm1
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm0, xmm3
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm3, xmm14
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm9, xmm6
  db $66, $45, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm9, xmm9, 1
  movdqa    xmm6, xmm13
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm13, xmm7
  db $66, $45, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm13, xmm13, 1
  movdqa    xmm7, xmm8
  pxor      xmm7, xmm10
  movdqa    xmm8, xmm7
  pxor      xmm8, xmm11
  movdqa    xmm7, xmm5
  pxor      xmm7, xmm10
  movdqa    xmm5, xmm7
  pxor      xmm5, xmm12
  movdqa    xmm7, xmm4
  pxor      xmm7, xmm10
  movdqu    xmm4, [rsp + 256]
  movdqa    xmm14, xmm7
  pxor      xmm14, xmm4
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm10
  movdqu    xmm2, [rsp + 240]
  movdqu    [rsp + 256], xmm4
  movdqa    xmm4, xmm7
  pxor      xmm4, xmm2
  movdqa    xmm7, xmm1
  pxor      xmm7, xmm11
  movdqa    xmm1, xmm7
  pxor      xmm1, xmm12
  movdqa    xmm7, xmm0
  pxor      xmm7, xmm11
  movdqu    xmm0, [rsp + 256]
  movdqu    [rsp + 240], xmm2
  movdqa    xmm2, xmm7
  pxor      xmm2, xmm0
  movdqa    xmm7, xmm3
  pxor      xmm7, xmm11
  movdqu    xmm3, [rsp + 240]
  movdqu    [rsp + 256], xmm0
  movdqa    xmm0, xmm7
  pxor      xmm0, xmm3
  movdqa    xmm7, xmm9
  pxor      xmm7, xmm12
  movdqu    xmm9, [rsp + 256]
  movdqu    [rsp + 240], xmm3
  movdqa    xmm3, xmm7
  pxor      xmm3, xmm9
  movdqa    xmm7, xmm6
  pxor      xmm7, xmm12
  movdqu    xmm6, [rsp + 240]
  movdqu    [rsp + 256], xmm9
  movdqa    xmm9, xmm7
  pxor      xmm9, xmm6
  movdqu    xmm7, [rsp + 256]
  movdqu    [rsp + 240], xmm6
  movdqa    xmm6, xmm13
  pxor      xmm6, xmm7
  movdqu    xmm13, [rsp + 240]
  movdqu    [rsp + 272], xmm9
  movdqa    xmm9, xmm6
  pxor      xmm9, xmm13
  movdqa    xmm6, xmm14
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm2
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm3
  movdqa    xmm0, xmm8
  pslldq    xmm0, 8
  movdqa    xmm3, xmm10
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm8
  psrldq    xmm0, 8
  movdqa    xmm4, xmm11
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm6
  pslldq    xmm0, 8
  movdqa    xmm8, xmm5
  pxor      xmm8, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm8
  movdqa    xmm4, xmm6
  psrldq    xmm4, 8
  movdqa    xmm5, xmm12
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm2
  pslldq    xmm4, 8
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm4
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm6
  movdqa    xmm4, xmm2
  psrldq    xmm4, 8
  movdqa    xmm2, xmm7
  pxor      xmm2, xmm4
  movdqa    xmm4, xmm9
  pslldq    xmm4, 8
  movdqu    xmm5, [rsp + 272]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm6
  movdqa    xmm2, xmm9
  psrldq    xmm2, 8
  movdqa    xmm5, xmm13
  pxor      xmm5, xmm2
  movdqu    xmm2, [rsp + 224]
  movdqa    xmm6, xmm2
  pxor      xmm6, xmm3
  movdqu    xmm2, [rsp + 208]
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm0
  movdqu    xmm0, [rsp + 176]
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm1
  movdqu    xmm0, [rsp + 192]
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm4
  movdqu    xmm0, [rsp + 160]
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm5
  movdqu    xmm0, [rsp + 64]
  movdqu    [r9 + 0], xmm0
  movdqu    xmm0, [rsp + 48]
  movdqu    [r9 + 16], xmm0
  movdqu    xmm0, [rsp + 16]
  movdqu    [r9 + 32], xmm0
  movdqu    xmm0, [rsp + 32]
  movdqu    [r9 + 48], xmm0
  movdqu    xmm0, [rsp + 0]
  movdqu    [r9 + 64], xmm0
  movdqu    xmm0, [rsp + 144]
  movdqu    [r9 + 80], xmm0
  movdqu    xmm0, [rsp + 128]
  movdqu    [r9 + 96], xmm0
  movdqu    xmm0, [rsp + 96]
  movdqu    [r9 + 112], xmm0
  movdqu    xmm0, [rsp + 112]
  movdqu    [r9 + 128], xmm0
  movdqu    xmm0, [rsp + 80]
  movdqu    [r9 + 144], xmm0
  movdqu    xmm0, [r9 + 40]
  pxor      xmm0, xmm6
  movdqu    [r9 + 40], xmm0
  movdqu    xmm0, [r9 + 56]
  pxor      xmm0, xmm3
  movdqu    [r9 + 56], xmm0
  movdqu    xmm0, [r9 + 72]
  pxor      xmm0, xmm2
  movdqu    [r9 + 72], xmm0
  movdqu    xmm0, [r9 + 88]
  pxor      xmm0, xmm1
  movdqu    [r9 + 88], xmm0
  movdqu    xmm0, [r9 + 104]
  pxor      xmm0, xmm4
  movdqu    [r9 + 104], xmm0
  add       rsp, 288
  jmp       @@BinPolySmallXmmDone

@@BinPolySmallXmmDone:
{$I ..\..\Include\Simd\Common\SimdNonVolatileRestore_x86_64.inc}

