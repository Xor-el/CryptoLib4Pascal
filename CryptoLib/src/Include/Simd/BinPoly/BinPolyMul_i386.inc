// Binary-polynomial (GF(2)[x]) PCLMULQDQ multiply/square kernels, merged (i386).
// -------------------------------------------------------------------
//
// One selector-driven file per arch; exactly one of the following must be
// defined before including this file:
//
//   CRYPTOLIB_BINPOLY_SMALL   (ClpSimdProc4Begin: ebx = ALen, esi = PX, edi = PY, eax = PZz)
//     - fully-unrolled fixed-size multiply, limb counts 1..10; ZZ output
//       is packed V128 lanes (lane k at byte offset 16*k).
//   CRYPTOLIB_BINPOLY_EVEN    (ClpSimdProc4Begin: ebx = ALen, esi = PX, edi = PY, eax = PZz)
//     - looped N-limb schoolbook multiply over the inlined 2x2 Karatsuba
//       primitive, N even.
//   CRYPTOLIB_BINPOLY_ODD     (same entry; N odd).
//   CRYPTOLIB_BINPOLY_SQUARE  (ClpSimdProc3Begin: ebx = ALen, esi = PX, edi = PZz)
//     - carryless square: bits of each limb spread to even positions via
//       one pclmulqdq(a, a) per limb; PZz receives 2*ALen limbs.
// Every op's epilogue pops the Proc-prologue registers.
// PCLMULQDQ forms are db-encoded for broad assembler compatibility.
//
// Reference: Karatsuba's algorithm applied to carry-less multiplication -
// the 3-multiply reduction described in Shay Gueron / Michael E. Kounavis,
// "Intel(R) Carry-Less Multiplication Instruction and its Usage for
// Computing the GCM Mode" (white paper).
{$IFDEF CRYPTOLIB_BINPOLY_SMALL}
  cmp       ebx, 1
  je        @@BinPolySmallSize1
  cmp       ebx, 2
  je        @@BinPolySmallSize2
  cmp       ebx, 3
  je        @@BinPolySmallSize3
  cmp       ebx, 4
  je        @@BinPolySmallSize4
  cmp       ebx, 5
  je        @@BinPolySmallSize5
  cmp       ebx, 6
  je        @@BinPolySmallSize6
  cmp       ebx, 7
  je        @@BinPolySmallSize7
  cmp       ebx, 8
  je        @@BinPolySmallSize8
  cmp       ebx, 9
  je        @@BinPolySmallSize9
  cmp       ebx, 10
  je        @@BinPolySmallSize10
  jmp       @@BinPolySmallDone

@@BinPolySmallSize1:
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [edi + 0]
  punpcklqdq xmm0, xmm7
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    [eax + 0], xmm1
  jmp       @@BinPolySmallDone

@@BinPolySmallSize2:
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [esi + 8]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [edi + 0]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm1, xmm7
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
  movdqu    [eax + 0], xmm1
  movdqu    [eax + 16], xmm2
  jmp       @@BinPolySmallDone

@@BinPolySmallSize3:
  sub       esp, 16
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [edi + 0]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 8]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [esi + 16]
  movq      xmm7, qword ptr [edi + 16]
  punpcklqdq xmm2, xmm7
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm4, xmm1
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm1
  movdqu    [esp + 0], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm2
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqa    xmm1, xmm6
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm4
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm3
  movdqu    xmm2, [esp + 0]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm2
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm4
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm2
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqu    [esp + 0], xmm2
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm1
  psrldq    xmm0, 8
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm5
  psrldq    xmm1, 8
  movdqu    xmm3, [esp + 0]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm1
  movdqu    [eax + 0], xmm2
  movdqu    [eax + 16], xmm0
  movdqu    [eax + 32], xmm4
  add       esp, 16
  jmp       @@BinPolySmallDone

@@BinPolySmallSize4:
  sub       esp, 64
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [esi + 8]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 16]
  movq      xmm7, qword ptr [esi + 24]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [edi + 0]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm2, xmm7
  movq      xmm3, qword ptr [edi + 16]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm3, xmm7
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqu    [esp + 0], xmm4
  movdqa    xmm4, xmm0
  punpckhqdq xmm4, xmm2
  movdqu    [esp + 16], xmm5
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E2, $00  // pclmulqdq xmm4, xmm2, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $11  // pclmulqdq xmm6, xmm2, 17
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm6
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm1
  punpcklqdq xmm0, xmm3
  movdqa    xmm5, xmm1
  punpckhqdq xmm5, xmm3
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C3, $00  // pclmulqdq xmm0, xmm3, 0
  movdqa    xmm5, xmm1
  db $66, $0F, $3A, $44, $EB, $11  // pclmulqdq xmm5, xmm3, 17
  movdqa    xmm1, xmm6
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm6
  pslldq    xmm1, 8
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm1
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm0
  movdqu    xmm0, [esp + 0]
  movdqu    xmm5, [esp + 16]
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm5
  movdqu    [esp + 32], xmm1
  movdqa    xmm1, xmm0
  punpckhqdq xmm1, xmm5
  movdqu    [esp + 48], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $CD, $00  // pclmulqdq xmm1, xmm5, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F5, $11  // pclmulqdq xmm6, xmm5, 17
  movdqa    xmm0, xmm2
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm6
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqu    xmm3, [esp + 48]
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm4
  movdqu    xmm4, [esp + 32]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm5
  movdqu    [eax + 0], xmm3
  movdqu    [eax + 16], xmm2
  movdqu    [eax + 32], xmm1
  movdqu    [eax + 48], xmm4
  add       esp, 64
  jmp       @@BinPolySmallDone

@@BinPolySmallSize5:
  sub       esp, 176
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [edi + 0]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 8]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [esi + 16]
  movq      xmm7, qword ptr [edi + 16]
  punpcklqdq xmm2, xmm7
  movq      xmm3, qword ptr [esi + 24]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm3, xmm7
  movq      xmm4, qword ptr [esi + 32]
  movq      xmm7, qword ptr [edi + 32]
  punpcklqdq xmm4, xmm7
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm6, xmm1
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 0], xmm6
  movdqa    xmm6, xmm2
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 32], xmm6
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 48], xmm6
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm1
  movdqu    [esp + 64], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm2
  movdqu    [esp + 80], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqu    [esp + 96], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqu    [esp + 112], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqu    [esp + 128], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm4
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm3
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm4
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm4
  movdqa    xmm3, xmm6
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    xmm4, [esp + 80]
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    xmm4, [esp + 96]
  movdqu    [esp + 80], xmm6
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    xmm5, [esp + 112]
  movdqu    [esp + 96], xmm4
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    xmm5, [esp + 128]
  movdqu    [esp + 112], xmm4
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    xmm0, [esp + 144]
  movdqu    [esp + 128], xmm5
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm2
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    xmm2, [esp + 64]
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm2
  movdqu    xmm3, [esp + 0]
  movdqu    [esp + 64], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm3
  movdqu    xmm1, [esp + 80]
  movdqu    [esp + 0], xmm3
  movdqu    xmm3, [esp + 64]
  movdqu    [esp + 160], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm3
  movdqu    xmm1, [esp + 16]
  movdqu    [esp + 64], xmm3
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm1
  movdqu    xmm2, [esp + 64]
  movdqu    [esp + 16], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm2
  movdqu    xmm6, [esp + 32]
  movdqu    [esp + 80], xmm3
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm6
  movdqu    xmm1, [esp + 96]
  movdqu    [esp + 32], xmm6
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm2
  movdqu    xmm1, [esp + 48]
  movdqu    [esp + 64], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqu    xmm6, [esp + 112]
  movdqu    [esp + 48], xmm1
  movdqu    xmm1, [esp + 0]
  movdqu    [esp + 96], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqu    xmm6, [esp + 16]
  movdqu    [esp + 0], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm6
  movdqu    xmm2, [esp + 0]
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm2
  movdqu    xmm4, [esp + 32]
  movdqu    [esp + 0], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm4
  movdqu    xmm6, [esp + 128]
  movdqu    [esp + 32], xmm4
  movdqu    xmm4, [esp + 0]
  movdqu    [esp + 112], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm4
  movdqu    xmm6, [esp + 48]
  movdqu    [esp + 0], xmm4
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm6
  movdqu    xmm2, [esp + 16]
  movdqu    [esp + 48], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 32]
  movdqu    [esp + 16], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm5
  movdqu    xmm6, [esp + 16]
  movdqu    [esp + 32], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqu    xmm0, [esp + 48]
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqu    xmm5, [esp + 144]
  movdqu    [esp + 48], xmm0
  movdqu    xmm0, [esp + 32]
  movdqu    [esp + 128], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqu    xmm5, [esp + 48]
  movdqu    [esp + 32], xmm0
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm5
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm1
  movdqu    xmm1, [esp + 96]
  movdqu    xmm3, [esp + 112]
  movdqu    [esp + 48], xmm5
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm3
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm2
  movdqu    xmm2, [esp + 160]
  movdqa    xmm3, xmm2
  pslldq    xmm3, 8
  movdqu    xmm4, [esp + 64]
  movdqu    [esp + 112], xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm2
  psrldq    xmm3, 8
  movdqu    xmm2, [esp + 0]
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm2, xmm6
  pslldq    xmm2, 8
  movdqu    xmm3, [esp + 80]
  movdqu    [esp + 0], xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm2
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqu    xmm3, [esp + 16]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm1
  psrldq    xmm3, 8
  movdqu    xmm1, [esp + 32]
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm3
  movdqu    xmm1, [esp + 112]
  movdqa    xmm3, xmm1
  pslldq    xmm3, 8
  movdqu    xmm5, [esp + 128]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm6
  movdqa    xmm4, xmm1
  psrldq    xmm4, 8
  movdqu    xmm1, [esp + 48]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movdqu    xmm1, [esp + 0]
  movdqu    [eax + 0], xmm1
  movdqu    [eax + 16], xmm2
  movdqu    [eax + 32], xmm0
  movdqu    [eax + 48], xmm3
  movdqu    [eax + 64], xmm5
  add       esp, 176
  jmp       @@BinPolySmallDone

@@BinPolySmallSize6:
  sub       esp, 160
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [edi + 0]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 8]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [esi + 16]
  movq      xmm7, qword ptr [edi + 16]
  punpcklqdq xmm2, xmm7
  movq      xmm3, qword ptr [esi + 24]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm3, xmm7
  movq      xmm4, qword ptr [esi + 32]
  movq      xmm7, qword ptr [edi + 32]
  punpcklqdq xmm4, xmm7
  movq      xmm5, qword ptr [esi + 40]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm5, xmm7
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 0], xmm2
  movdqa    xmm2, xmm1
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 16], xmm5
  movdqu    xmm5, [esp + 0]
  movdqu    [esp + 32], xmm1
  movdqa    xmm1, xmm5
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    [esp + 0], xmm5
  movdqu    xmm5, [esp + 32]
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm5
  movdqu    [esp + 32], xmm5
  movdqu    xmm5, [esp + 0]
  movdqu    [esp + 64], xmm3
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqu    [esp + 0], xmm5
  movdqu    xmm5, [esp + 32]
  movdqu    [esp + 80], xmm0
  movdqu    xmm0, [esp + 0]
  movdqu    [esp + 96], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm0
  movdqu    [esp + 0], xmm0
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm4, xmm3
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm3, xmm1
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm6
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm6
  movdqu    xmm4, [esp + 96]
  movdqu    [esp + 32], xmm5
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm2
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm4
  movdqa    xmm1, xmm0
  pslldq    xmm1, 8
  movdqu    [esp + 96], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm1
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm1
  movdqa    xmm1, xmm3
  pslldq    xmm1, 8
  movdqa    xmm2, xmm5
  pxor      xmm2, xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm2
  movdqa    xmm0, xmm3
  psrldq    xmm0, 8
  movdqu    xmm2, [esp + 96]
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm0
  movdqu    xmm0, [esp + 64]
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    xmm5, [esp + 48]
  movdqa    xmm6, xmm5
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 96], xmm4
  movdqu    xmm4, [esp + 16]
  movdqu    [esp + 112], xmm3
  movdqa    xmm3, xmm4
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    [esp + 128], xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm5
  movdqu    [esp + 48], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqu    [esp + 16], xmm4
  movdqu    xmm4, [esp + 48]
  movdqu    [esp + 64], xmm0
  movdqu    xmm0, [esp + 16]
  movdqu    [esp + 144], xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm0
  movdqu    [esp + 16], xmm0
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm5
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm2
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm6
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm2
  movdqu    xmm1, [esp + 144]
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm1
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm6
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm1
  movdqa    xmm3, xmm0
  pslldq    xmm3, 8
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm3
  movdqa    xmm2, xmm0
  psrldq    xmm2, 8
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm2
  movdqa    xmm2, xmm5
  pslldq    xmm2, 8
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm2
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm3
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqu    xmm3, [esp + 144]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqu    xmm0, [esp + 80]
  movdqu    xmm3, [esp + 64]
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqu    xmm0, [esp + 32]
  movdqu    xmm3, [esp + 48]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm3
  movdqu    xmm0, [esp + 0]
  movdqu    xmm3, [esp + 16]
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm3
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm3, xmm6
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    [esp + 16], xmm2
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 0], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm6
  movdqu    [esp + 32], xmm2
  movdqa    xmm2, xmm5
  pxor      xmm2, xmm4
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm1
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm1, xmm2
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm0
  movdqa    xmm4, xmm5
  pxor      xmm4, xmm3
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm0
  movdqu    xmm1, [esp + 32]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm1
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm2, xmm5
  pxor      xmm2, xmm1
  movdqa    xmm5, xmm4
  pslldq    xmm5, 8
  movdqu    [esp + 32], xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm5
  movdqa    xmm0, xmm4
  psrldq    xmm0, 8
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm2
  pslldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm2
  psrldq    xmm3, 8
  movdqu    xmm2, [esp + 32]
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqu    xmm2, [esp + 96]
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm2
  movdqu    xmm1, [esp + 0]
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm1
  movdqu    xmm3, [esp + 128]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm3
  movdqu    xmm0, [esp + 16]
  movdqu    [esp + 96], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm0
  movdqu    xmm6, [esp + 112]
  movdqu    [esp + 16], xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm6
  movdqu    xmm4, [esp + 48]
  movdqu    [esp + 0], xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm4
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm2
  pslldq    xmm0, 8
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm2
  psrldq    xmm0, 8
  movdqu    xmm2, [esp + 0]
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm1
  psrldq    xmm0, 8
  movdqu    xmm1, [esp + 16]
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm0
  movdqu    xmm0, [esp + 96]
  movdqu    [eax + 0], xmm0
  movdqu    [eax + 16], xmm4
  movdqu    [eax + 32], xmm5
  movdqu    [eax + 48], xmm2
  movdqu    [eax + 64], xmm3
  movdqu    xmm0, [esp + 48]
  movdqu    [eax + 80], xmm0
  add       esp, 160
  jmp       @@BinPolySmallDone

@@BinPolySmallSize7:
  sub       esp, 176
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [esi + 8]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 16]
  movq      xmm7, qword ptr [esi + 24]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [edi + 0]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm2, xmm7
  movq      xmm3, qword ptr [edi + 16]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm3, xmm7
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqu    [esp + 0], xmm4
  movdqa    xmm4, xmm0
  punpckhqdq xmm4, xmm2
  movdqu    [esp + 16], xmm5
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E2, $00  // pclmulqdq xmm4, xmm2, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $11  // pclmulqdq xmm6, xmm2, 17
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm6
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm1
  punpcklqdq xmm0, xmm3
  movdqa    xmm5, xmm1
  punpckhqdq xmm5, xmm3
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C3, $00  // pclmulqdq xmm0, xmm3, 0
  movdqa    xmm5, xmm1
  db $66, $0F, $3A, $44, $EB, $11  // pclmulqdq xmm5, xmm3, 17
  movdqa    xmm1, xmm6
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm6
  pslldq    xmm1, 8
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm1
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm0
  movdqu    xmm0, [esp + 0]
  movdqu    xmm5, [esp + 16]
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm5
  movdqu    [esp + 32], xmm2
  movdqa    xmm2, xmm0
  punpckhqdq xmm2, xmm5
  movdqu    [esp + 48], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D5, $00  // pclmulqdq xmm2, xmm5, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F5, $11  // pclmulqdq xmm6, xmm5, 17
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm6
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqu    xmm3, [esp + 32]
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm3
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm4
  movdqu    xmm4, [esp + 48]
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm4
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm5
  movq      xmm0, qword ptr [esi + 32]
  movq      xmm7, qword ptr [edi + 32]
  punpcklqdq xmm0, xmm7
  movq      xmm5, qword ptr [esi + 40]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm5, xmm7
  movq      xmm6, qword ptr [esi + 48]
  movq      xmm7, qword ptr [edi + 48]
  punpcklqdq xmm6, xmm7
  movdqu    [esp + 16], xmm1
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    [esp + 32], xmm3
  movdqa    xmm3, xmm5
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm6
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    [esp + 0], xmm2
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm5
  movdqu    [esp + 64], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm6
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm6
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm1
  movdqu    xmm2, [esp + 64]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm2
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm2
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqu    [esp + 64], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm4
  pslldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm4
  psrldq    xmm1, 8
  movdqu    xmm3, [esp + 64]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm1
  movq      xmm1, qword ptr [esi + 0]
  movq      xmm7, qword ptr [esi + 8]
  punpcklqdq xmm1, xmm7
  movq      xmm3, qword ptr [esi + 32]
  movq      xmm7, qword ptr [esi + 40]
  punpcklqdq xmm3, xmm7
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm3
  movq      xmm1, qword ptr [esi + 16]
  movq      xmm7, qword ptr [esi + 24]
  punpcklqdq xmm1, xmm7
  movq      xmm3, qword ptr [esi + 48]
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm3
  movq      xmm1, qword ptr [edi + 0]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm1, xmm7
  movq      xmm3, qword ptr [edi + 32]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm3, xmm7
  movdqu    [esp + 64], xmm4
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm3
  movq      xmm1, qword ptr [edi + 16]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm1, xmm7
  movq      xmm3, qword ptr [edi + 48]
  movdqu    [esp + 80], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm6
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm0
  movdqu    [esp + 96], xmm2
  movdqa    xmm2, xmm5
  punpcklqdq xmm2, xmm4
  movdqu    [esp + 112], xmm1
  movdqa    xmm1, xmm5
  punpckhqdq xmm1, xmm4
  movdqu    [esp + 128], xmm3
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm1
  movdqa    xmm1, xmm5
  db $66, $0F, $3A, $44, $CC, $00  // pclmulqdq xmm1, xmm4, 0
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D4, $11  // pclmulqdq xmm2, xmm4, 17
  movdqa    xmm4, xmm3
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm2
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm4
  movdqa    xmm3, xmm5
  pslldq    xmm3, 8
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm3
  movdqa    xmm1, xmm5
  psrldq    xmm1, 8
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm1
  movdqa    xmm1, xmm6
  punpcklqdq xmm1, xmm0
  movdqa    xmm2, xmm6
  punpckhqdq xmm2, xmm0
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm2
  movdqa    xmm1, xmm6
  db $66, $0F, $3A, $44, $C8, $00  // pclmulqdq xmm1, xmm0, 0
  movdqa    xmm2, xmm6
  db $66, $0F, $3A, $44, $D0, $11  // pclmulqdq xmm2, xmm0, 17
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm2
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqa    xmm0, xmm6
  pslldq    xmm0, 8
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm0
  movdqu    xmm0, [esp + 112]
  movdqu    xmm2, [esp + 128]
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm0
  punpckhqdq xmm1, xmm2
  movdqu    [esp + 160], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm1
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $CA, $00  // pclmulqdq xmm1, xmm2, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $11  // pclmulqdq xmm6, xmm2, 17
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm6
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm4
  pslldq    xmm0, 8
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm4
  psrldq    xmm0, 8
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm5
  movdqu    xmm3, [esp + 160]
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm4
  movdqu    xmm4, [esp + 144]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm5
  movdqu    xmm0, [esp + 0]
  movdqu    xmm5, [esp + 96]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movdqu    xmm0, [esp + 48]
  movdqu    xmm5, [esp + 80]
  movdqu    [esp + 144], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm5
  movdqu    xmm0, [esp + 32]
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm0
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm5
  movdqu    xmm5, [esp + 16]
  movdqu    [esp + 160], xmm3
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm5
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm3
  movdqu    xmm3, [esp + 64]
  movdqu    [esp + 80], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm3
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm2
  movdqu    xmm2, [esp + 144]
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm2
  movdqu    [eax + 0], xmm0
  movdqu    [eax + 16], xmm5
  movdqu    xmm0, [esp + 160]
  movdqu    [eax + 32], xmm0
  movdqu    xmm0, [esp + 80]
  movdqu    [eax + 48], xmm0
  movdqu    [eax + 64], xmm1
  movdqu    [eax + 80], xmm6
  movdqu    [eax + 96], xmm3
  add       esp, 176
  jmp       @@BinPolySmallDone

@@BinPolySmallSize8:
  sub       esp, 192
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [esi + 8]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 16]
  movq      xmm7, qword ptr [esi + 24]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [edi + 0]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm2, xmm7
  movq      xmm3, qword ptr [edi + 16]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm3, xmm7
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqu    [esp + 0], xmm4
  movdqa    xmm4, xmm0
  punpckhqdq xmm4, xmm2
  movdqu    [esp + 16], xmm5
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E2, $00  // pclmulqdq xmm4, xmm2, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $11  // pclmulqdq xmm6, xmm2, 17
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm6
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm1
  punpcklqdq xmm0, xmm3
  movdqa    xmm5, xmm1
  punpckhqdq xmm5, xmm3
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C3, $00  // pclmulqdq xmm0, xmm3, 0
  movdqa    xmm5, xmm1
  db $66, $0F, $3A, $44, $EB, $11  // pclmulqdq xmm5, xmm3, 17
  movdqa    xmm1, xmm6
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm6
  pslldq    xmm1, 8
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm1
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm0
  movdqu    xmm0, [esp + 0]
  movdqu    xmm5, [esp + 16]
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm5
  movdqu    [esp + 32], xmm2
  movdqa    xmm2, xmm0
  punpckhqdq xmm2, xmm5
  movdqu    [esp + 48], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D5, $00  // pclmulqdq xmm2, xmm5, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F5, $11  // pclmulqdq xmm6, xmm5, 17
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm6
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqu    xmm3, [esp + 32]
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm3
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm4
  movdqu    xmm4, [esp + 48]
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm4
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm5
  movq      xmm0, qword ptr [esi + 32]
  movq      xmm7, qword ptr [esi + 40]
  punpcklqdq xmm0, xmm7
  movq      xmm5, qword ptr [esi + 48]
  movq      xmm7, qword ptr [esi + 56]
  punpcklqdq xmm5, xmm7
  movq      xmm6, qword ptr [edi + 32]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm6, xmm7
  movdqu    [esp + 16], xmm1
  movq      xmm1, qword ptr [edi + 48]
  movq      xmm7, qword ptr [edi + 56]
  punpcklqdq xmm1, xmm7
  movdqu    [esp + 32], xmm3
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm1
  movdqu    [esp + 0], xmm2
  movdqa    xmm2, xmm0
  punpcklqdq xmm2, xmm6
  movdqu    [esp + 64], xmm3
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm6
  movdqu    [esp + 80], xmm4
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D6, $00  // pclmulqdq xmm2, xmm6, 0
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DE, $11  // pclmulqdq xmm3, xmm6, 17
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm0
  movdqa    xmm0, xmm6
  pslldq    xmm0, 8
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm5
  punpcklqdq xmm0, xmm1
  movdqa    xmm3, xmm5
  punpckhqdq xmm3, xmm1
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm3
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C1, $00  // pclmulqdq xmm0, xmm1, 0
  movdqa    xmm3, xmm5
  db $66, $0F, $3A, $44, $D9, $11  // pclmulqdq xmm3, xmm1, 17
  movdqa    xmm1, xmm6
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm6
  pslldq    xmm1, 8
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm0
  movdqu    xmm0, [esp + 64]
  movdqu    xmm3, [esp + 80]
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm3
  movdqu    [esp + 96], xmm1
  movdqa    xmm1, xmm0
  punpckhqdq xmm1, xmm3
  movdqu    [esp + 112], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm1
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $CB, $00  // pclmulqdq xmm1, xmm3, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F3, $11  // pclmulqdq xmm6, xmm3, 17
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm6
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm4
  pslldq    xmm0, 8
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm4
  psrldq    xmm0, 8
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm5
  movdqu    xmm2, [esp + 112]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm2
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm4
  movdqu    xmm4, [esp + 96]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm5
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [esi + 8]
  punpcklqdq xmm0, xmm7
  movq      xmm5, qword ptr [esi + 32]
  movq      xmm7, qword ptr [esi + 40]
  punpcklqdq xmm5, xmm7
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movq      xmm0, qword ptr [esi + 16]
  movq      xmm7, qword ptr [esi + 24]
  punpcklqdq xmm0, xmm7
  movq      xmm5, qword ptr [esi + 48]
  movq      xmm7, qword ptr [esi + 56]
  punpcklqdq xmm5, xmm7
  movdqu    [esp + 96], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm5
  movq      xmm0, qword ptr [edi + 0]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm0, xmm7
  movq      xmm5, qword ptr [edi + 32]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm5, xmm7
  movdqu    [esp + 80], xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm5
  movq      xmm0, qword ptr [edi + 16]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm0, xmm7
  movq      xmm5, qword ptr [edi + 48]
  movq      xmm7, qword ptr [edi + 56]
  punpcklqdq xmm5, xmm7
  movdqu    [esp + 64], xmm3
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm4
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm3
  movdqu    [esp + 112], xmm2
  movdqa    xmm2, xmm6
  punpcklqdq xmm2, xmm1
  movdqu    [esp + 128], xmm0
  movdqa    xmm0, xmm6
  punpckhqdq xmm0, xmm1
  movdqu    [esp + 144], xmm5
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm6
  db $66, $0F, $3A, $44, $C1, $00  // pclmulqdq xmm0, xmm1, 0
  movdqa    xmm2, xmm6
  db $66, $0F, $3A, $44, $D1, $11  // pclmulqdq xmm2, xmm1, 17
  movdqa    xmm1, xmm5
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm2
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm1
  movdqa    xmm1, xmm6
  pslldq    xmm1, 8
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm0
  movdqa    xmm0, xmm4
  punpcklqdq xmm0, xmm3
  movdqa    xmm2, xmm4
  punpckhqdq xmm2, xmm3
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm2
  movdqa    xmm0, xmm4
  db $66, $0F, $3A, $44, $C3, $00  // pclmulqdq xmm0, xmm3, 0
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D3, $11  // pclmulqdq xmm2, xmm3, 17
  movdqa    xmm3, xmm6
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm2
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm6
  pslldq    xmm3, 8
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm3
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm0
  movdqu    xmm0, [esp + 128]
  movdqu    xmm2, [esp + 144]
  movdqa    xmm6, xmm0
  punpcklqdq xmm6, xmm2
  movdqu    [esp + 160], xmm3
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm2
  movdqu    [esp + 176], xmm5
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm3
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DA, $00  // pclmulqdq xmm3, xmm2, 0
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F2, $11  // pclmulqdq xmm6, xmm2, 17
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm6
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm5
  pslldq    xmm0, 8
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm4
  movdqu    xmm1, [esp + 176]
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm1
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm4
  movdqu    xmm4, [esp + 160]
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm4
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqu    xmm0, [esp + 0]
  movdqu    xmm5, [esp + 112]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm5
  movdqu    xmm0, [esp + 48]
  movdqu    xmm5, [esp + 64]
  movdqu    [esp + 160], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm5
  movdqu    xmm0, [esp + 32]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm0
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm5
  movdqu    xmm5, [esp + 16]
  movdqu    [esp + 176], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm5
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm1
  movdqu    xmm1, [esp + 80]
  movdqu    [esp + 64], xmm2
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm1
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm2
  movdqu    xmm2, [esp + 160]
  movdqu    xmm6, [esp + 96]
  movdqu    [esp + 80], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm6
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm1
  movdqu    [eax + 0], xmm0
  movdqu    [eax + 16], xmm5
  movdqu    xmm0, [esp + 176]
  movdqu    [eax + 32], xmm0
  movdqu    xmm0, [esp + 64]
  movdqu    [eax + 48], xmm0
  movdqu    [eax + 64], xmm3
  movdqu    [eax + 80], xmm2
  movdqu    xmm0, [esp + 80]
  movdqu    [eax + 96], xmm0
  movdqu    [eax + 112], xmm6
  add       esp, 192
  jmp       @@BinPolySmallDone

@@BinPolySmallSize9:
  sub       esp, 304
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [edi + 0]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 8]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [esi + 16]
  movq      xmm7, qword ptr [edi + 16]
  punpcklqdq xmm2, xmm7
  movq      xmm3, qword ptr [esi + 24]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm3, xmm7
  movq      xmm4, qword ptr [esi + 32]
  movq      xmm7, qword ptr [edi + 32]
  punpcklqdq xmm4, xmm7
  movq      xmm5, qword ptr [esi + 40]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm5, xmm7
  movq      xmm6, qword ptr [esi + 48]
  movq      xmm7, qword ptr [edi + 48]
  punpcklqdq xmm6, xmm7
  movdqu    [esp + 0], xmm5
  movq      xmm5, qword ptr [esi + 56]
  movq      xmm7, qword ptr [edi + 56]
  punpcklqdq xmm5, xmm7
  movdqu    [esp + 16], xmm4
  movq      xmm4, qword ptr [esi + 64]
  movq      xmm7, qword ptr [edi + 64]
  punpcklqdq xmm4, xmm7
  movdqu    [esp + 32], xmm4
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    [esp + 48], xmm5
  movdqa    xmm5, xmm1
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    [esp + 64], xmm3
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    [esp + 80], xmm6
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm1
  movdqu    [esp + 96], xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm2
  movdqu    [esp + 112], xmm2
  movdqu    xmm2, [esp + 96]
  movdqu    [esp + 128], xmm0
  movdqu    xmm0, [esp + 112]
  movdqu    [esp + 144], xmm3
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm0
  movdqu    [esp + 112], xmm0
  movdqa    xmm0, xmm6
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm6, xmm1
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm1, xmm3
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm4
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm5
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm4
  movdqu    xmm6, [esp + 144]
  movdqu    [esp + 96], xmm2
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm6
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm5
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm6
  movdqa    xmm3, xmm0
  pslldq    xmm3, 8
  movdqu    [esp + 144], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm0
  psrldq    xmm3, 8
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm1
  pslldq    xmm3, 8
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm4
  movdqa    xmm0, xmm1
  psrldq    xmm0, 8
  movdqu    xmm1, [esp + 144]
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm0
  movdqu    xmm0, [esp + 64]
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    xmm4, [esp + 16]
  movdqa    xmm5, xmm4
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    [esp + 144], xmm6
  movdqu    xmm6, [esp + 0]
  movdqu    [esp + 160], xmm3
  movdqa    xmm3, xmm6
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    [esp + 176], xmm2
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm4
  movdqu    [esp + 16], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm6
  movdqu    [esp + 0], xmm6
  movdqu    xmm6, [esp + 16]
  movdqu    [esp + 64], xmm0
  movdqu    xmm0, [esp + 0]
  movdqu    [esp + 192], xmm3
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm0
  movdqu    [esp + 0], xmm0
  movdqa    xmm0, xmm2
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm4, xmm3
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm1
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm5
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm1
  movdqu    xmm2, [esp + 192]
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm2
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm5
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm2
  movdqa    xmm3, xmm0
  pslldq    xmm3, 8
  movdqu    [esp + 192], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm3
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm1
  movdqa    xmm1, xmm4
  pslldq    xmm1, 8
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm3
  movdqa    xmm0, xmm4
  psrldq    xmm0, 8
  movdqu    xmm3, [esp + 192]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqu    xmm0, [esp + 80]
  movdqa    xmm3, xmm0
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    xmm5, [esp + 48]
  movdqa    xmm6, xmm5
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 192], xmm4
  movdqu    xmm4, [esp + 32]
  movdqu    [esp + 208], xmm1
  movdqa    xmm1, xmm4
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    [esp + 224], xmm2
  movdqa    xmm2, xmm0
  pxor      xmm2, xmm5
  movdqu    [esp + 48], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqu    [esp + 32], xmm4
  movdqu    xmm4, [esp + 48]
  movdqu    [esp + 80], xmm0
  movdqu    xmm0, [esp + 32]
  movdqu    [esp + 240], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm0
  movdqu    [esp + 32], xmm0
  movdqa    xmm0, xmm2
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm5, xmm1
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm3
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm6
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm3
  movdqu    xmm2, [esp + 240]
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm2
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm6
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm2
  movdqa    xmm1, xmm0
  pslldq    xmm1, 8
  movdqu    [esp + 240], xmm2
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm1
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm1
  movdqa    xmm1, xmm5
  pslldq    xmm1, 8
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm3
  movdqa    xmm0, xmm5
  psrldq    xmm0, 8
  movdqu    xmm3, [esp + 240]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqu    xmm0, [esp + 128]
  movdqu    xmm3, [esp + 64]
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqu    xmm6, [esp + 96]
  movdqu    [esp + 240], xmm4
  movdqu    xmm4, [esp + 16]
  movdqu    [esp + 256], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm4
  movdqu    [esp + 272], xmm2
  movdqu    xmm2, [esp + 112]
  movdqu    [esp + 16], xmm4
  movdqu    xmm4, [esp + 0]
  movdqu    [esp + 64], xmm3
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm4
  movdqu    [esp + 0], xmm4
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    [esp + 112], xmm2
  movdqa    xmm2, xmm1
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 96], xmm6
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 128], xmm0
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm1
  movdqu    [esp + 288], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm3
  movdqa    xmm1, xmm0
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm0, xmm6
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm3, xmm5
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm2
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqu    xmm0, [esp + 288]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm2
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm0
  movdqa    xmm5, xmm1
  pslldq    xmm5, 8
  movdqu    [esp + 288], xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm5
  movdqa    xmm4, xmm1
  psrldq    xmm4, 8
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm4
  movdqa    xmm2, xmm3
  pslldq    xmm2, 8
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm4
  movdqa    xmm1, xmm3
  psrldq    xmm1, 8
  movdqu    xmm3, [esp + 288]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm1
  movdqu    xmm1, [esp + 128]
  movdqu    xmm3, [esp + 80]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm3
  movdqu    xmm1, [esp + 96]
  movdqu    xmm6, [esp + 48]
  movdqu    [esp + 128], xmm4
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm6
  movdqu    xmm1, [esp + 112]
  movdqu    [esp + 96], xmm2
  movdqu    xmm2, [esp + 32]
  movdqu    [esp + 288], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqa    xmm1, xmm5
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    [esp + 32], xmm2
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 48], xmm6
  movdqa    xmm6, xmm0
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 80], xmm3
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm4
  movdqu    [esp + 112], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm0
  movdqa    xmm0, xmm3
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm3, xmm6
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm2
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm1
  movdqu    xmm3, [esp + 112]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm2
  movdqa    xmm4, xmm5
  pxor      xmm4, xmm3
  movdqa    xmm5, xmm0
  pslldq    xmm5, 8
  movdqu    [esp + 112], xmm3
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm5
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8
  movdqa    xmm0, xmm2
  pxor      xmm0, xmm1
  movdqa    xmm1, xmm4
  pslldq    xmm1, 8
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm2
  movdqa    xmm0, xmm4
  psrldq    xmm0, 8
  movdqu    xmm2, [esp + 112]
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm0
  movdqu    xmm0, [esp + 64]
  movdqu    xmm2, [esp + 80]
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm2
  movdqu    xmm0, [esp + 16]
  movdqu    xmm2, [esp + 48]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm2
  movdqu    xmm0, [esp + 0]
  movdqu    xmm2, [esp + 32]
  movdqu    [esp + 48], xmm4
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm2
  movdqa    xmm0, xmm5
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm2, xmm6
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 32], xmm1
  movdqa    xmm1, xmm4
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    [esp + 0], xmm3
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm6
  movdqu    [esp + 16], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm4
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm4
  movdqa    xmm4, xmm3
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm3, xmm1
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqa    xmm1, xmm5
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm0
  movdqa    xmm4, xmm5
  pxor      xmm4, xmm2
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm0
  movdqu    xmm3, [esp + 16]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm2
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm3
  movdqa    xmm5, xmm4
  pslldq    xmm5, 8
  movdqu    [esp + 16], xmm3
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqa    xmm0, xmm4
  psrldq    xmm0, 8
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm2
  movdqa    xmm2, xmm1
  psrldq    xmm2, 8
  movdqu    xmm1, [esp + 16]
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm2
  movdqu    xmm1, [esp + 288]
  movdqu    xmm2, [esp + 144]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm2
  movdqu    xmm1, [esp + 224]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm1
  movdqu    xmm5, [esp + 96]
  movdqu    [esp + 144], xmm2
  movdqu    xmm2, [esp + 176]
  movdqu    [esp + 224], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm2
  movdqu    xmm5, [esp + 208]
  movdqu    [esp + 96], xmm6
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm5
  movdqu    xmm1, [esp + 128]
  movdqu    [esp + 208], xmm5
  movdqu    xmm5, [esp + 160]
  movdqu    [esp + 288], xmm6
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm5
  movdqu    xmm1, [esp + 192]
  movdqu    [esp + 160], xmm5
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm1
  movdqu    xmm6, [esp + 0]
  movdqu    [esp + 192], xmm1
  movdqu    xmm1, [esp + 144]
  movdqu    [esp + 128], xmm5
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm1
  movdqu    xmm6, [esp + 272]
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm6
  movdqu    xmm5, [esp + 32]
  movdqu    [esp + 272], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 256]
  movdqu    [esp + 32], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm5
  movdqu    xmm6, [esp + 48]
  movdqu    [esp + 256], xmm5
  movdqu    xmm5, [esp + 160]
  movdqu    [esp + 0], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm5
  movdqu    xmm6, [esp + 240]
  movdqu    [esp + 160], xmm5
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm6
  movdqu    xmm1, [esp + 224]
  movdqu    [esp + 240], xmm6
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm1
  movdqu    xmm3, [esp + 272]
  movdqu    [esp + 48], xmm5
  movdqa    xmm5, xmm6
  pxor      xmm5, xmm3
  movdqu    xmm6, [esp + 208]
  movdqu    [esp + 272], xmm3
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm6
  movdqu    xmm0, [esp + 256]
  movdqu    [esp + 16], xmm5
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm0
  movdqu    xmm3, [esp + 192]
  movdqu    [esp + 256], xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqu    xmm4, [esp + 240]
  movdqu    [esp + 80], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqu    xmm0, [esp + 96]
  movdqu    [esp + 240], xmm4
  movdqa    xmm4, xmm0
  pslldq    xmm4, 8
  movdqu    [esp + 64], xmm5
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm4
  movdqa    xmm2, xmm0
  psrldq    xmm2, 8
  movdqu    xmm0, [esp + 160]
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm2
  movdqu    xmm0, [esp + 288]
  movdqa    xmm2, xmm0
  pslldq    xmm2, 8
  movdqu    [esp + 160], xmm5
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm2
  movdqu    xmm2, [esp + 32]
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm2
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8
  movdqu    xmm0, [esp + 128]
  movdqa    xmm2, xmm0
  pslldq    xmm2, 8
  movdqu    [esp + 288], xmm5
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm2
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm5
  movdqu    xmm2, [esp + 0]
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm2
  movdqa    xmm2, xmm0
  psrldq    xmm2, 8
  movdqu    xmm0, [esp + 16]
  movdqa    xmm5, xmm0
  pslldq    xmm5, 8
  movdqa    xmm6, xmm2
  pxor      xmm6, xmm5
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm6
  movdqu    xmm4, [esp + 48]
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm4
  movdqa    xmm3, xmm0
  psrldq    xmm3, 8
  movdqu    xmm0, [esp + 80]
  movdqa    xmm4, xmm0
  pslldq    xmm4, 8
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm4
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm6
  movdqa    xmm4, xmm0
  psrldq    xmm4, 8
  movdqu    xmm0, [esp + 64]
  movdqa    xmm5, xmm0
  pslldq    xmm5, 8
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm5
  movdqu    xmm4, [esp + 272]
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm6
  movdqa    xmm4, xmm0
  psrldq    xmm4, 8
  movdqu    xmm0, [esp + 256]
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm4
  movdqu    xmm0, [esp + 144]
  movdqu    [eax + 0], xmm0
  movdqu    xmm0, [esp + 160]
  movdqu    [eax + 16], xmm0
  movdqu    xmm0, [esp + 288]
  movdqu    [eax + 32], xmm0
  movdqu    [eax + 48], xmm1
  movdqu    [eax + 64], xmm2
  movdqu    [eax + 80], xmm3
  movdqu    [eax + 96], xmm5
  movdqu    [eax + 112], xmm6
  movdqu    xmm0, [esp + 240]
  movdqu    [eax + 128], xmm0
  add       esp, 304
  jmp       @@BinPolySmallDone

@@BinPolySmallSize10:
  sub       esp, 416
  movq      xmm0, qword ptr [esi + 0]
  movq      xmm7, qword ptr [edi + 0]
  punpcklqdq xmm0, xmm7
  movq      xmm1, qword ptr [esi + 8]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm1, xmm7
  movq      xmm2, qword ptr [esi + 16]
  movq      xmm7, qword ptr [edi + 16]
  punpcklqdq xmm2, xmm7
  movq      xmm3, qword ptr [esi + 24]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm3, xmm7
  movq      xmm4, qword ptr [esi + 32]
  movq      xmm7, qword ptr [edi + 32]
  punpcklqdq xmm4, xmm7
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm6, xmm1
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 0], xmm6
  movdqa    xmm6, xmm2
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 32], xmm6
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    [esp + 48], xmm6
  movdqa    xmm6, xmm0
  pxor      xmm6, xmm1
  movdqu    [esp + 64], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm2
  movdqu    [esp + 80], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm3
  movdqu    [esp + 96], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm4
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm2
  movdqu    [esp + 112], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqu    [esp + 128], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm4
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm3
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm4
  movdqa    xmm2, xmm3
  pxor      xmm2, xmm4
  movdqa    xmm3, xmm6
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    xmm4, [esp + 80]
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqu    xmm4, [esp + 96]
  movdqu    [esp + 80], xmm6
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    xmm5, [esp + 112]
  movdqu    [esp + 96], xmm4
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    xmm5, [esp + 128]
  movdqu    [esp + 112], xmm4
  movdqa    xmm4, xmm5
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    xmm0, [esp + 144]
  movdqu    [esp + 128], xmm5
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm2
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqu    xmm2, [esp + 64]
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm3
  pxor      xmm1, xmm2
  movdqu    xmm3, [esp + 0]
  movdqu    [esp + 64], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm3
  movdqu    xmm1, [esp + 80]
  movdqu    [esp + 0], xmm3
  movdqu    xmm3, [esp + 64]
  movdqu    [esp + 160], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm3
  movdqu    xmm1, [esp + 16]
  movdqu    [esp + 64], xmm3
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm1
  movdqu    xmm2, [esp + 64]
  movdqu    [esp + 16], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm2
  movdqu    xmm6, [esp + 32]
  movdqu    [esp + 80], xmm3
  movdqa    xmm3, xmm1
  pxor      xmm3, xmm6
  movdqu    xmm1, [esp + 96]
  movdqu    [esp + 32], xmm6
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm2
  movdqu    xmm1, [esp + 48]
  movdqu    [esp + 64], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqu    xmm6, [esp + 112]
  movdqu    [esp + 48], xmm1
  movdqu    xmm1, [esp + 0]
  movdqu    [esp + 96], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqu    xmm6, [esp + 16]
  movdqu    [esp + 0], xmm1
  movdqa    xmm1, xmm2
  pxor      xmm1, xmm6
  movdqu    xmm2, [esp + 0]
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm2
  movdqu    xmm4, [esp + 32]
  movdqu    [esp + 0], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm4
  movdqu    xmm6, [esp + 128]
  movdqu    [esp + 32], xmm4
  movdqu    xmm4, [esp + 0]
  movdqu    [esp + 112], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm4
  movdqu    xmm6, [esp + 48]
  movdqu    [esp + 0], xmm4
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm6
  movdqu    xmm2, [esp + 16]
  movdqu    [esp + 48], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 32]
  movdqu    [esp + 16], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm5
  movdqu    xmm6, [esp + 16]
  movdqu    [esp + 32], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqu    xmm0, [esp + 48]
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqu    xmm5, [esp + 144]
  movdqu    [esp + 48], xmm0
  movdqu    xmm0, [esp + 32]
  movdqu    [esp + 128], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqu    xmm5, [esp + 48]
  movdqu    [esp + 32], xmm0
  movdqa    xmm0, xmm6
  pxor      xmm0, xmm5
  movdqa    xmm6, xmm3
  pxor      xmm6, xmm1
  movdqu    xmm1, [esp + 96]
  movdqu    xmm3, [esp + 112]
  movdqu    [esp + 48], xmm5
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm3
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm2
  movdqu    xmm2, [esp + 160]
  movdqa    xmm3, xmm2
  pslldq    xmm3, 8
  movdqu    xmm4, [esp + 64]
  movdqu    [esp + 112], xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm2
  psrldq    xmm3, 8
  movdqu    xmm2, [esp + 0]
  movdqa    xmm4, xmm2
  pxor      xmm4, xmm3
  movdqa    xmm2, xmm6
  pslldq    xmm2, 8
  movdqu    xmm3, [esp + 80]
  movdqu    [esp + 0], xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm2
  movdqa    xmm2, xmm4
  pxor      xmm2, xmm0
  movdqa    xmm0, xmm6
  psrldq    xmm0, 8
  movdqu    xmm3, [esp + 16]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm0
  movdqa    xmm0, xmm1
  pslldq    xmm0, 8
  movdqa    xmm3, xmm5
  pxor      xmm3, xmm0
  movdqa    xmm0, xmm4
  pxor      xmm0, xmm3
  movdqa    xmm3, xmm1
  psrldq    xmm3, 8
  movdqu    xmm1, [esp + 32]
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm3
  movdqu    xmm1, [esp + 112]
  movdqa    xmm3, xmm1
  pslldq    xmm3, 8
  movdqu    xmm5, [esp + 128]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm6
  movdqa    xmm4, xmm1
  psrldq    xmm4, 8
  movdqu    xmm1, [esp + 48]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movq      xmm1, qword ptr [esi + 40]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm1, xmm7
  movq      xmm4, qword ptr [esi + 48]
  movq      xmm7, qword ptr [edi + 48]
  punpcklqdq xmm4, xmm7
  movq      xmm6, qword ptr [esi + 56]
  movq      xmm7, qword ptr [edi + 56]
  punpcklqdq xmm6, xmm7
  movdqu    [esp + 48], xmm5
  movq      xmm5, qword ptr [esi + 64]
  movq      xmm7, qword ptr [edi + 64]
  punpcklqdq xmm5, xmm7
  movdqu    [esp + 112], xmm3
  movq      xmm3, qword ptr [esi + 72]
  movq      xmm7, qword ptr [edi + 72]
  punpcklqdq xmm3, xmm7
  movdqu    [esp + 128], xmm0
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqu    [esp + 32], xmm2
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 16], xmm2
  movdqa    xmm2, xmm6
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 80], xmm2
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 160], xmm2
  movdqa    xmm2, xmm3
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 64], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm4
  movdqu    [esp + 96], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm6
  movdqu    [esp + 144], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm5
  movdqu    [esp + 176], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm6
  movdqu    [esp + 192], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm5
  movdqu    [esp + 208], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm3
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm5
  movdqu    [esp + 224], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm3
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    xmm2, [esp + 144]
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    xmm2, [esp + 176]
  movdqu    [esp + 144], xmm5
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    xmm0, [esp + 192]
  movdqu    [esp + 176], xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    xmm0, [esp + 208]
  movdqu    [esp + 192], xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqu    xmm1, [esp + 224]
  movdqu    [esp + 208], xmm0
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm4
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm4, xmm6
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    xmm6, [esp + 96]
  movdqu    [esp + 224], xmm4
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm6
  movdqu    xmm3, [esp + 16]
  movdqu    [esp + 96], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqu    xmm4, [esp + 144]
  movdqu    [esp + 16], xmm3
  movdqu    xmm3, [esp + 96]
  movdqu    [esp + 240], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqu    xmm4, [esp + 80]
  movdqu    [esp + 96], xmm3
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm4
  movdqu    xmm6, [esp + 96]
  movdqu    [esp + 80], xmm4
  movdqa    xmm4, xmm5
  pxor      xmm4, xmm6
  movdqu    xmm5, [esp + 160]
  movdqu    [esp + 144], xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm5
  movdqu    xmm4, [esp + 176]
  movdqu    [esp + 160], xmm5
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm6
  movdqu    xmm4, [esp + 64]
  movdqu    [esp + 96], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqu    xmm5, [esp + 192]
  movdqu    [esp + 64], xmm4
  movdqu    xmm4, [esp + 16]
  movdqu    [esp + 176], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqu    xmm5, [esp + 80]
  movdqu    [esp + 16], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm5
  movdqu    xmm6, [esp + 16]
  movdqu    [esp + 80], xmm5
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm6
  movdqu    xmm2, [esp + 160]
  movdqu    [esp + 16], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 208]
  movdqu    [esp + 160], xmm2
  movdqu    xmm2, [esp + 16]
  movdqu    [esp + 192], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 64]
  movdqu    [esp + 16], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm5
  movdqu    xmm6, [esp + 80]
  movdqu    [esp + 64], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqu    xmm0, [esp + 160]
  movdqu    [esp + 80], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqu    xmm5, [esp + 80]
  movdqu    [esp + 160], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm5
  movdqu    xmm1, [esp + 64]
  movdqu    [esp + 80], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqu    xmm0, [esp + 224]
  movdqu    [esp + 64], xmm1
  movdqu    xmm1, [esp + 160]
  movdqu    [esp + 208], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqu    xmm0, [esp + 64]
  movdqu    [esp + 160], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm0
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm4
  movdqu    xmm3, [esp + 176]
  movdqu    xmm4, [esp + 192]
  movdqu    [esp + 64], xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm4
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm6
  movdqu    xmm2, [esp + 240]
  movdqa    xmm4, xmm2
  pslldq    xmm4, 8
  movdqu    xmm6, [esp + 96]
  movdqu    [esp + 192], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm4
  movdqa    xmm4, xmm2
  psrldq    xmm4, 8
  movdqu    xmm2, [esp + 16]
  movdqa    xmm6, xmm2
  pxor      xmm6, xmm4
  movdqa    xmm2, xmm5
  pslldq    xmm2, 8
  movdqu    xmm4, [esp + 144]
  movdqu    [esp + 16], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqa    xmm1, xmm5
  psrldq    xmm1, 8
  movdqu    xmm4, [esp + 80]
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm1
  movdqa    xmm1, xmm3
  pslldq    xmm1, 8
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm4
  movdqa    xmm1, xmm3
  psrldq    xmm1, 8
  movdqu    xmm3, [esp + 160]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm1
  movdqu    xmm1, [esp + 192]
  movdqa    xmm3, xmm1
  pslldq    xmm3, 8
  movdqu    xmm5, [esp + 208]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm6
  movdqa    xmm4, xmm1
  psrldq    xmm4, 8
  movdqu    xmm1, [esp + 64]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movq      xmm1, qword ptr [esi + 0]
  movq      xmm7, qword ptr [edi + 40]
  punpcklqdq xmm1, xmm7
  movq      xmm4, qword ptr [esi + 8]
  movq      xmm7, qword ptr [edi + 48]
  punpcklqdq xmm4, xmm7
  movq      xmm6, qword ptr [esi + 16]
  movq      xmm7, qword ptr [edi + 56]
  punpcklqdq xmm6, xmm7
  movdqu    [esp + 64], xmm5
  movq      xmm5, qword ptr [esi + 24]
  movq      xmm7, qword ptr [edi + 64]
  punpcklqdq xmm5, xmm7
  movdqu    [esp + 192], xmm3
  movq      xmm3, qword ptr [esi + 32]
  movq      xmm7, qword ptr [edi + 72]
  punpcklqdq xmm3, xmm7
  movdqu    [esp + 208], xmm0
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqu    [esp + 160], xmm2
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 80], xmm2
  movdqa    xmm2, xmm6
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 144], xmm2
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 240], xmm2
  movdqa    xmm2, xmm3
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 96], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm4
  movdqu    [esp + 176], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm6
  movdqu    [esp + 224], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm5
  movdqu    [esp + 256], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm6
  movdqu    [esp + 272], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm5
  movdqu    [esp + 288], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm3
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm5
  movdqu    [esp + 304], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm3
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    xmm2, [esp + 224]
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    xmm2, [esp + 256]
  movdqu    [esp + 224], xmm5
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    xmm0, [esp + 272]
  movdqu    [esp + 256], xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    xmm0, [esp + 288]
  movdqu    [esp + 272], xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqu    xmm1, [esp + 304]
  movdqu    [esp + 288], xmm0
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm4
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm4, xmm6
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    xmm6, [esp + 176]
  movdqu    [esp + 304], xmm4
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm6
  movdqu    xmm3, [esp + 80]
  movdqu    [esp + 176], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqu    xmm4, [esp + 224]
  movdqu    [esp + 80], xmm3
  movdqu    xmm3, [esp + 176]
  movdqu    [esp + 320], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqu    xmm4, [esp + 144]
  movdqu    [esp + 176], xmm3
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm4
  movdqu    xmm6, [esp + 176]
  movdqu    [esp + 144], xmm4
  movdqa    xmm4, xmm5
  pxor      xmm4, xmm6
  movdqu    xmm5, [esp + 240]
  movdqu    [esp + 224], xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm5
  movdqu    xmm4, [esp + 256]
  movdqu    [esp + 240], xmm5
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm6
  movdqu    xmm4, [esp + 96]
  movdqu    [esp + 176], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqu    xmm5, [esp + 272]
  movdqu    [esp + 96], xmm4
  movdqu    xmm4, [esp + 80]
  movdqu    [esp + 256], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqu    xmm5, [esp + 144]
  movdqu    [esp + 80], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm5
  movdqu    xmm6, [esp + 80]
  movdqu    [esp + 144], xmm5
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm6
  movdqu    xmm2, [esp + 240]
  movdqu    [esp + 80], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 288]
  movdqu    [esp + 240], xmm2
  movdqu    xmm2, [esp + 80]
  movdqu    [esp + 272], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 96]
  movdqu    [esp + 80], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm5
  movdqu    xmm6, [esp + 144]
  movdqu    [esp + 96], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqu    xmm0, [esp + 240]
  movdqu    [esp + 144], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqu    xmm5, [esp + 144]
  movdqu    [esp + 240], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm5
  movdqu    xmm1, [esp + 96]
  movdqu    [esp + 144], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqu    xmm0, [esp + 304]
  movdqu    [esp + 96], xmm1
  movdqu    xmm1, [esp + 240]
  movdqu    [esp + 288], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqu    xmm0, [esp + 96]
  movdqu    [esp + 240], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm0
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm4
  movdqu    xmm3, [esp + 256]
  movdqu    xmm4, [esp + 272]
  movdqu    [esp + 96], xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm4
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm6
  movdqu    xmm2, [esp + 320]
  movdqa    xmm4, xmm2
  pslldq    xmm4, 8
  movdqu    xmm6, [esp + 176]
  movdqu    [esp + 272], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm4
  movdqa    xmm4, xmm2
  psrldq    xmm4, 8
  movdqu    xmm2, [esp + 80]
  movdqa    xmm6, xmm2
  pxor      xmm6, xmm4
  movdqa    xmm2, xmm5
  pslldq    xmm2, 8
  movdqu    xmm4, [esp + 224]
  movdqu    [esp + 80], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqa    xmm1, xmm5
  psrldq    xmm1, 8
  movdqu    xmm4, [esp + 144]
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm1
  movdqa    xmm1, xmm3
  pslldq    xmm1, 8
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm4
  movdqa    xmm1, xmm3
  psrldq    xmm1, 8
  movdqu    xmm3, [esp + 240]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm1
  movdqu    xmm1, [esp + 272]
  movdqa    xmm3, xmm1
  pslldq    xmm3, 8
  movdqu    xmm5, [esp + 288]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm6
  movdqa    xmm4, xmm1
  psrldq    xmm4, 8
  movdqu    xmm1, [esp + 96]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movq      xmm1, qword ptr [esi + 40]
  movq      xmm7, qword ptr [edi + 0]
  punpcklqdq xmm1, xmm7
  movq      xmm4, qword ptr [esi + 48]
  movq      xmm7, qword ptr [edi + 8]
  punpcklqdq xmm4, xmm7
  movq      xmm6, qword ptr [esi + 56]
  movq      xmm7, qword ptr [edi + 16]
  punpcklqdq xmm6, xmm7
  movdqu    [esp + 96], xmm5
  movq      xmm5, qword ptr [esi + 64]
  movq      xmm7, qword ptr [edi + 24]
  punpcklqdq xmm5, xmm7
  movdqu    [esp + 272], xmm3
  movq      xmm3, qword ptr [esi + 72]
  movq      xmm7, qword ptr [edi + 32]
  punpcklqdq xmm3, xmm7
  movdqu    [esp + 288], xmm0
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqu    [esp + 240], xmm2
  movdqa    xmm2, xmm4
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 144], xmm2
  movdqa    xmm2, xmm6
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 224], xmm2
  movdqa    xmm2, xmm5
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 320], xmm2
  movdqa    xmm2, xmm3
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    [esp + 176], xmm2
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm4
  movdqu    [esp + 256], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm6
  movdqu    [esp + 304], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm5
  movdqu    [esp + 336], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm3
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm6
  movdqu    [esp + 352], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm5
  movdqu    [esp + 368], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm3
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm5
  movdqu    [esp + 384], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm3
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DB, $01  // pclmulqdq xmm3, xmm3, 1
  movdqu    xmm2, [esp + 304]
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqu    xmm2, [esp + 336]
  movdqu    [esp + 304], xmm5
  movdqa    xmm5, xmm2
  db $66, $0F, $3A, $44, $ED, $01  // pclmulqdq xmm5, xmm5, 1
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    xmm0, [esp + 352]
  movdqu    [esp + 336], xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqu    xmm0, [esp + 368]
  movdqu    [esp + 352], xmm2
  movdqa    xmm2, xmm0
  db $66, $0F, $3A, $44, $D2, $01  // pclmulqdq xmm2, xmm2, 1
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqu    xmm1, [esp + 384]
  movdqu    [esp + 368], xmm0
  movdqa    xmm0, xmm1
  db $66, $0F, $3A, $44, $C0, $01  // pclmulqdq xmm0, xmm0, 1
  movdqa    xmm1, xmm4
  db $66, $0F, $3A, $44, $C9, $01  // pclmulqdq xmm1, xmm1, 1
  movdqa    xmm4, xmm6
  db $66, $0F, $3A, $44, $E4, $01  // pclmulqdq xmm4, xmm4, 1
  movdqu    xmm6, [esp + 256]
  movdqu    [esp + 384], xmm4
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm6
  movdqu    xmm3, [esp + 144]
  movdqu    [esp + 256], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqu    xmm4, [esp + 304]
  movdqu    [esp + 144], xmm3
  movdqu    xmm3, [esp + 256]
  movdqu    [esp + 400], xmm6
  movdqa    xmm6, xmm4
  pxor      xmm6, xmm3
  movdqu    xmm4, [esp + 224]
  movdqu    [esp + 256], xmm3
  movdqa    xmm3, xmm6
  pxor      xmm3, xmm4
  movdqu    xmm6, [esp + 256]
  movdqu    [esp + 224], xmm4
  movdqa    xmm4, xmm5
  pxor      xmm4, xmm6
  movdqu    xmm5, [esp + 320]
  movdqu    [esp + 304], xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm5
  movdqu    xmm4, [esp + 336]
  movdqu    [esp + 320], xmm5
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm6
  movdqu    xmm4, [esp + 176]
  movdqu    [esp + 256], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqu    xmm5, [esp + 352]
  movdqu    [esp + 176], xmm4
  movdqu    xmm4, [esp + 144]
  movdqu    [esp + 336], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm4
  movdqu    xmm5, [esp + 224]
  movdqu    [esp + 144], xmm4
  movdqa    xmm4, xmm6
  pxor      xmm4, xmm5
  movdqu    xmm6, [esp + 144]
  movdqu    [esp + 224], xmm5
  movdqa    xmm5, xmm2
  pxor      xmm5, xmm6
  movdqu    xmm2, [esp + 320]
  movdqu    [esp + 144], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 368]
  movdqu    [esp + 320], xmm2
  movdqu    xmm2, [esp + 144]
  movdqu    [esp + 352], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm2
  movdqu    xmm5, [esp + 176]
  movdqu    [esp + 144], xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm5
  movdqu    xmm6, [esp + 224]
  movdqu    [esp + 176], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm6
  movdqu    xmm0, [esp + 320]
  movdqu    [esp + 224], xmm6
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm0
  movdqu    xmm5, [esp + 224]
  movdqu    [esp + 320], xmm0
  movdqa    xmm0, xmm1
  pxor      xmm0, xmm5
  movdqu    xmm1, [esp + 176]
  movdqu    [esp + 224], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqu    xmm0, [esp + 384]
  movdqu    [esp + 176], xmm1
  movdqu    xmm1, [esp + 320]
  movdqu    [esp + 368], xmm5
  movdqa    xmm5, xmm0
  pxor      xmm5, xmm1
  movdqu    xmm0, [esp + 176]
  movdqu    [esp + 320], xmm1
  movdqa    xmm1, xmm5
  pxor      xmm1, xmm0
  movdqa    xmm5, xmm3
  pxor      xmm5, xmm4
  movdqu    xmm3, [esp + 336]
  movdqu    xmm4, [esp + 352]
  movdqu    [esp + 176], xmm0
  movdqa    xmm0, xmm3
  pxor      xmm0, xmm4
  movdqa    xmm3, xmm2
  pxor      xmm3, xmm6
  movdqu    xmm2, [esp + 400]
  movdqa    xmm4, xmm2
  pslldq    xmm4, 8
  movdqu    xmm6, [esp + 256]
  movdqu    [esp + 352], xmm1
  movdqa    xmm1, xmm6
  pxor      xmm1, xmm4
  movdqa    xmm4, xmm2
  psrldq    xmm4, 8
  movdqu    xmm2, [esp + 144]
  movdqa    xmm6, xmm2
  pxor      xmm6, xmm4
  movdqa    xmm2, xmm5
  pslldq    xmm2, 8
  movdqu    xmm4, [esp + 304]
  movdqu    [esp + 144], xmm1
  movdqa    xmm1, xmm4
  pxor      xmm1, xmm2
  movdqa    xmm2, xmm6
  pxor      xmm2, xmm1
  movdqa    xmm1, xmm5
  psrldq    xmm1, 8
  movdqu    xmm4, [esp + 224]
  movdqa    xmm5, xmm4
  pxor      xmm5, xmm1
  movdqa    xmm1, xmm3
  pslldq    xmm1, 8
  movdqa    xmm4, xmm0
  pxor      xmm4, xmm1
  movdqa    xmm0, xmm5
  pxor      xmm0, xmm4
  movdqa    xmm1, xmm3
  psrldq    xmm1, 8
  movdqu    xmm3, [esp + 320]
  movdqa    xmm4, xmm3
  pxor      xmm4, xmm1
  movdqu    xmm1, [esp + 352]
  movdqa    xmm3, xmm1
  pslldq    xmm3, 8
  movdqu    xmm5, [esp + 368]
  movdqa    xmm6, xmm5
  pxor      xmm6, xmm3
  movdqa    xmm3, xmm4
  pxor      xmm3, xmm6
  movdqa    xmm4, xmm1
  psrldq    xmm4, 8
  movdqu    xmm1, [esp + 176]
  movdqa    xmm5, xmm1
  pxor      xmm5, xmm4
  movdqu    xmm1, [esp + 80]
  movdqu    xmm4, [esp + 144]
  movdqa    xmm6, xmm1
  pxor      xmm6, xmm4
  movdqu    xmm1, [esp + 240]
  movdqa    xmm4, xmm1
  pxor      xmm4, xmm2
  movdqu    xmm1, [esp + 288]
  movdqa    xmm2, xmm1
  pxor      xmm2, xmm0
  movdqu    xmm0, [esp + 272]
  movdqa    xmm1, xmm0
  pxor      xmm1, xmm3
  movdqu    xmm0, [esp + 96]
  movdqa    xmm3, xmm0
  pxor      xmm3, xmm5
  movdqu    xmm0, [esp + 0]
  movdqu    [eax + 0], xmm0
  movdqu    xmm0, [esp + 32]
  movdqu    [eax + 16], xmm0
  movdqu    xmm0, [esp + 128]
  movdqu    [eax + 32], xmm0
  movdqu    xmm0, [esp + 112]
  movdqu    [eax + 48], xmm0
  movdqu    xmm0, [esp + 48]
  movdqu    [eax + 64], xmm0
  movdqu    xmm0, [esp + 16]
  movdqu    [eax + 80], xmm0
  movdqu    xmm0, [esp + 160]
  movdqu    [eax + 96], xmm0
  movdqu    xmm0, [esp + 208]
  movdqu    [eax + 112], xmm0
  movdqu    xmm0, [esp + 192]
  movdqu    [eax + 128], xmm0
  movdqu    xmm0, [esp + 64]
  movdqu    [eax + 144], xmm0
  movdqu    xmm0, [eax + 40]
  pxor      xmm0, xmm6
  movdqu    [eax + 40], xmm0
  movdqu    xmm0, [eax + 56]
  pxor      xmm0, xmm4
  movdqu    [eax + 56], xmm0
  movdqu    xmm0, [eax + 72]
  pxor      xmm0, xmm2
  movdqu    [eax + 72], xmm0
  movdqu    xmm0, [eax + 88]
  pxor      xmm0, xmm1
  movdqu    [eax + 88], xmm0
  movdqu    xmm0, [eax + 104]
  pxor      xmm0, xmm3
  movdqu    [eax + 104], xmm0
  add       esp, 416
  jmp       @@BinPolySmallDone

@@BinPolySmallDone:
  pop       edi
  pop       esi
  pop       ebx

{$ELSE}
  {$IFDEF CRYPTOLIB_BINPOLY_EVEN}
  push      ebp
  push      edx
  sub       esp, 24

  mov       ebp, eax
  mov       edx, ebx
  shr       edx, 1
  mov       dword ptr [esp], edx            // L = ALen >> 1

  // Diagonal: for i = 0..L-1, ZZ[2i], ZZ[2i+1] = Mul2x2(X[i], Y[i]).
  xor       ecx, ecx
@@BinPolyMulEvenDiagLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulEvenDiagDone

  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm0, [esi + edx]
  movdqu    xmm1, [edi + edx]
  // ---- inline: 2x2-limb carryless Karatsuba ----
  movdqa    xmm2, xmm0
  punpcklqdq xmm2, xmm1
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm1
  pxor      xmm2, xmm3

  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $00  // pclmulqdq xmm4, xmm1, 0
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $E9, $11  // pclmulqdq xmm5, xmm1, 17
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DA, $01  // pclmulqdq xmm3, xmm2, 1

  movdqa    xmm2, xmm4
  pxor      xmm2, xmm5
  pxor      xmm2, xmm3

  movdqa    xmm6, xmm2
  pslldq    xmm6, 8
  pxor      xmm6, xmm4

  movdqa    xmm7, xmm2
  psrldq    xmm7, 8
  pxor      xmm7, xmm5

  mov       eax, ecx
  shl       eax, 5
  movdqu    [ebp + eax], xmm6
  movdqu    [ebp + eax + 16], xmm7

  inc       ecx
  jmp       @@BinPolyMulEvenDiagLoop
@@BinPolyMulEvenDiagDone:

  // Streak:
  // V0 = ZZ[0], V1 = ZZ[1]
  // for i = 1..L-1:
  //   V0 ^= ZZ[2i]
  //   ZZ[i] = V0 ^ V1                  (overwrite)
  //   V1 ^= ZZ[2i+1]
  movdqu    xmm2, [ebp]
  movdqu    xmm3, [ebp + 16]
  mov       ecx, 1
@@BinPolyMulEvenStreakLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulEvenStreakDone

  mov       edx, ecx
  shl       edx, 5
  movdqu    xmm4, [ebp + edx]   // ZZ[2i]
  pxor      xmm2, xmm4

  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  mov       eax, ecx
  shl       eax, 4
  movdqu    [ebp + eax], xmm5   // ZZ[i] = V0 ^ V1

  movdqu    xmm4, [ebp + edx + 16] // ZZ[2i+1]
  pxor      xmm3, xmm4

  inc       ecx
  jmp       @@BinPolyMulEvenStreakLoop
@@BinPolyMulEvenStreakDone:

  // W = V0 ^ V1; ZZ[L+i] = ZZ[i] ^ W for i = 0..L-1.
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm3
  xor       ecx, ecx
@@BinPolyMulEvenFoldLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulEvenFoldDone

  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm4, [ebp + edx]
  pxor      xmm4, xmm7

  mov       eax, dword ptr [esp]
  add       eax, ecx
  shl       eax, 4
  movdqu    [ebp + eax], xmm4

  inc       ecx
  jmp       @@BinPolyMulEvenFoldLoop
@@BinPolyMulEvenFoldDone:

  // Cross products:
  // last = L-1; zPos = 1..2*last-1.
  mov       eax, dword ptr [esp]
  dec       eax
  mov       dword ptr [esp + 4], eax         // last
  cmp       eax, 0
  jle       @@BinPolyMulEvenDone

  mov       edx, eax
  shl       edx, 1
  dec       edx
  mov       dword ptr [esp + 8], edx         // zPosMax
  mov       dword ptr [esp + 12], 1          // zPos
@@BinPolyMulEvenZPosLoop:
  mov       ecx, dword ptr [esp + 12]        // zPos
  cmp       ecx, dword ptr [esp + 8]
  jg        @@BinPolyMulEvenDone

  // hi = min(last, zPos)
  mov       eax, dword ptr [esp + 4]         // last
  cmp       ecx, eax
  jle       @@BinPolyMulEvenSetHiFromZPos
  mov       dword ptr [esp + 20], eax
  jmp       @@BinPolyMulEvenHiDone
@@BinPolyMulEvenSetHiFromZPos:
  mov       dword ptr [esp + 20], ecx
@@BinPolyMulEvenHiDone:
  mov       eax, ecx
  sub       eax, dword ptr [esp + 20]
  mov       dword ptr [esp + 16], eax        // lo = zPos - hi

@@BinPolyMulEvenPairLoop:
  mov       ecx, dword ptr [esp + 16]        // lo
  cmp       ecx, dword ptr [esp + 20]        // hi
  jge       @@BinPolyMulEvenNextZPos

  mov       edx, ecx
  shl       edx, 4
  mov       eax, dword ptr [esp + 20]
  shl       eax, 4

  movdqu    xmm0, [esi + edx]
  movdqu    xmm4, [esi + eax]
  pxor      xmm0, xmm4
  movdqu    xmm1, [edi + edx]
  movdqu    xmm5, [edi + eax]
  pxor      xmm1, xmm5
  // ---- inline: 2x2-limb carryless Karatsuba ----
  movdqa    xmm2, xmm0
  punpcklqdq xmm2, xmm1
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm1
  pxor      xmm2, xmm3

  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $00  // pclmulqdq xmm4, xmm1, 0
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $E9, $11  // pclmulqdq xmm5, xmm1, 17
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DA, $01  // pclmulqdq xmm3, xmm2, 1

  movdqa    xmm2, xmm4
  pxor      xmm2, xmm5
  pxor      xmm2, xmm3

  movdqa    xmm6, xmm2
  pslldq    xmm6, 8
  pxor      xmm6, xmm4

  movdqa    xmm7, xmm2
  psrldq    xmm7, 8
  pxor      xmm7, xmm5

  mov       edx, dword ptr [esp + 12]        // zPos
  shl       edx, 4
  movdqu    xmm4, [ebp + edx]
  pxor      xmm4, xmm6
  movdqu    [ebp + edx], xmm4
  movdqu    xmm4, [ebp + edx + 16]
  pxor      xmm4, xmm7
  movdqu    [ebp + edx + 16], xmm4

  inc       dword ptr [esp + 16]             // lo++
  dec       dword ptr [esp + 20]             // hi--
  jmp       @@BinPolyMulEvenPairLoop

@@BinPolyMulEvenNextZPos:
  inc       dword ptr [esp + 12]
  jmp       @@BinPolyMulEvenZPosLoop

@@BinPolyMulEvenDone:
  add       esp, 24
  pop       edx
  pop       ebp
  pop       edi
  pop       esi
  pop       ebx

  {$ELSE}
    {$IFDEF CRYPTOLIB_BINPOLY_ODD}
  push      ebp
  push      edx
  sub       esp, 24

  mov       ebp, eax
  mov       edx, ebx
  shr       edx, 1
  mov       dword ptr [esp], edx            // L = ALen >> 1

  // Diagonal full pairs: for i = 0..L-1.
  xor       ecx, ecx
@@BinPolyMulOddDiagLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulOddDiagDone

  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm0, [esi + edx]
  movdqu    xmm1, [edi + edx]
  // ---- inline: 2x2-limb carryless Karatsuba ----
  movdqa    xmm2, xmm0
  punpcklqdq xmm2, xmm1
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm1
  pxor      xmm2, xmm3

  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $00  // pclmulqdq xmm4, xmm1, 0
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $E9, $11  // pclmulqdq xmm5, xmm1, 17
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DA, $01  // pclmulqdq xmm3, xmm2, 1

  movdqa    xmm2, xmm4
  pxor      xmm2, xmm5
  pxor      xmm2, xmm3

  movdqa    xmm6, xmm2
  pslldq    xmm6, 8
  pxor      xmm6, xmm4

  movdqa    xmm7, xmm2
  psrldq    xmm7, 8
  pxor      xmm7, xmm5

  mov       eax, ecx
  shl       eax, 5
  movdqu    [ebp + eax], xmm6
  movdqu    [ebp + eax + 16], xmm7

  inc       ecx
  jmp       @@BinPolyMulOddDiagLoop
@@BinPolyMulOddDiagDone:

  // Tail diagonal at ZZ[2L]: Mul((x[2L],0), (y[2L],0)) with pclmul imm8=0x00.
  mov       edx, dword ptr [esp]
  shl       edx, 4
  pxor      xmm0, xmm0
  pxor      xmm1, xmm1
  movq      xmm0, qword ptr [esi + edx]
  movq      xmm1, qword ptr [edi + edx]
  db $66, $0F, $3A, $44, $C8, $00
  mov       eax, dword ptr [esp]
  shl       eax, 5
  movdqu    [ebp + eax], xmm1

  // ALen = 1 special case (L = 0): only tail diagonal exists.
  cmp       dword ptr [esp], 0
  je        @@BinPolyMulOddDone

  // Streak:
  // V0 = ZZ[0], V1 = ZZ[1]
  // for i = 1..L:
  //   V0 ^= ZZ[2i]
  //   ZZ[i] = V0 ^ V1                  (overwrite)
  //   if i <> L then V1 ^= ZZ[2i+1]
  movdqu    xmm2, [ebp]
  movdqu    xmm3, [ebp + 16]
  mov       ecx, 1
@@BinPolyMulOddStreakLoop:
  cmp       ecx, dword ptr [esp]
  jg        @@BinPolyMulOddStreakDone

  mov       edx, ecx
  shl       edx, 5
  movdqu    xmm4, [ebp + edx]   // ZZ[2i]
  pxor      xmm2, xmm4

  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  mov       eax, ecx
  shl       eax, 4
  movdqu    [ebp + eax], xmm5   // ZZ[i] = V0 ^ V1

  cmp       ecx, dword ptr [esp]
  je        @@BinPolyMulOddStreakNoV1
  movdqu    xmm4, [ebp + edx + 16] // ZZ[2i+1]
  pxor      xmm3, xmm4
@@BinPolyMulOddStreakNoV1:

  inc       ecx
  jmp       @@BinPolyMulOddStreakLoop
@@BinPolyMulOddStreakDone:

  // W = V0 ^ V1; ZZ[(L+1)+i] = ZZ[i] ^ W for i = 0..L-1.
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm3
  xor       ecx, ecx
@@BinPolyMulOddFoldLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulOddFoldDone

  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm4, [ebp + edx]
  pxor      xmm4, xmm7

  mov       eax, dword ptr [esp]
  add       eax, ecx
  inc       eax
  shl       eax, 4
  movdqu    [ebp + eax], xmm4

  inc       ecx
  jmp       @@BinPolyMulOddFoldLoop
@@BinPolyMulOddFoldDone:

  // Cross products:
  // last = L; zPos = 1..2*last-1, using tail vectors when hi = last.
  mov       eax, dword ptr [esp]
  mov       dword ptr [esp + 4], eax         // last
  cmp       eax, 0
  jle       @@BinPolyMulOddDone

  mov       edx, eax
  shl       edx, 1
  dec       edx
  mov       dword ptr [esp + 8], edx         // zPosMax
  mov       dword ptr [esp + 12], 1          // zPos
@@BinPolyMulOddZPosLoop:
  mov       ecx, dword ptr [esp + 12]        // zPos
  cmp       ecx, dword ptr [esp + 8]
  jg        @@BinPolyMulOddDone

  // hi = min(last, zPos)
  mov       eax, dword ptr [esp + 4]         // last
  cmp       ecx, eax
  jle       @@BinPolyMulOddSetHiFromZPos
  mov       dword ptr [esp + 20], eax
  jmp       @@BinPolyMulOddHiDone
@@BinPolyMulOddSetHiFromZPos:
  mov       dword ptr [esp + 20], ecx
@@BinPolyMulOddHiDone:
  mov       eax, ecx
  sub       eax, dword ptr [esp + 20]
  mov       dword ptr [esp + 16], eax        // lo = zPos - hi

@@BinPolyMulOddPairLoop:
  mov       ecx, dword ptr [esp + 16]        // lo
  cmp       ecx, dword ptr [esp + 20]        // hi
  jge       @@BinPolyMulOddNextZPos

  // Xxor = X[lo] xor X[hi] (tail-form when hi == last).
  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm0, [esi + edx]
  mov       eax, dword ptr [esp + 20]        // hi
  cmp       eax, dword ptr [esp + 4]         // last
  jne       @@BinPolyMulOddXHiFull
  pxor      xmm4, xmm4
  mov       eax, dword ptr [esp + 4]
  shl       eax, 4
  movq      xmm4, qword ptr [esi + eax]
  jmp       @@BinPolyMulOddXHiDone
@@BinPolyMulOddXHiFull:
  shl       eax, 4
  movdqu    xmm4, [esi + eax]
@@BinPolyMulOddXHiDone:
  pxor      xmm0, xmm4

  // Yxor = Y[lo] xor Y[hi] (tail-form when hi == last).
  movdqu    xmm1, [edi + edx]
  mov       eax, dword ptr [esp + 20]        // hi
  cmp       eax, dword ptr [esp + 4]         // last
  jne       @@BinPolyMulOddYHiFull
  pxor      xmm5, xmm5
  mov       eax, dword ptr [esp + 4]
  shl       eax, 4
  movq      xmm5, qword ptr [edi + eax]
  jmp       @@BinPolyMulOddYHiDone
@@BinPolyMulOddYHiFull:
  shl       eax, 4
  movdqu    xmm5, [edi + eax]
@@BinPolyMulOddYHiDone:
  pxor      xmm1, xmm5
  // ---- inline: 2x2-limb carryless Karatsuba ----
  movdqa    xmm2, xmm0
  punpcklqdq xmm2, xmm1
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm1
  pxor      xmm2, xmm3

  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $00  // pclmulqdq xmm4, xmm1, 0
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $E9, $11  // pclmulqdq xmm5, xmm1, 17
  movdqa    xmm3, xmm2
  db $66, $0F, $3A, $44, $DA, $01  // pclmulqdq xmm3, xmm2, 1

  movdqa    xmm2, xmm4
  pxor      xmm2, xmm5
  pxor      xmm2, xmm3

  movdqa    xmm6, xmm2
  pslldq    xmm6, 8
  pxor      xmm6, xmm4

  movdqa    xmm7, xmm2
  psrldq    xmm7, 8
  pxor      xmm7, xmm5

  mov       edx, dword ptr [esp + 12]        // zPos
  shl       edx, 4
  movdqu    xmm4, [ebp + edx]
  pxor      xmm4, xmm6
  movdqu    [ebp + edx], xmm4
  movdqu    xmm4, [ebp + edx + 16]
  pxor      xmm4, xmm7
  movdqu    [ebp + edx + 16], xmm4

  inc       dword ptr [esp + 16]             // lo++
  dec       dword ptr [esp + 20]             // hi--
  jmp       @@BinPolyMulOddPairLoop

@@BinPolyMulOddNextZPos:
  inc       dword ptr [esp + 12]
  jmp       @@BinPolyMulOddZPosLoop

@@BinPolyMulOddDone:
  add       esp, 24
  pop       edx
  pop       ebp
  pop       edi
  pop       esi
  pop       ebx

    {$ELSE}
      {$IFDEF CRYPTOLIB_BINPOLY_SQUARE}
  test      ebx, ebx
  jz        @@BinPolySquareDoneI386
@@BinPolySquareLoopI386:
  movq      xmm0, qword ptr [esi]
  db $66, $0F, $3A, $44, $C0, $00  // pclmulqdq xmm0, xmm0, 0
  movdqu    [edi], xmm0
  add       esi, 8
  add       edi, 16
  sub       ebx, 1
  jnz       @@BinPolySquareLoopI386
@@BinPolySquareDoneI386:
  pop       edi
  pop       esi
  pop       ebx
      {$ELSE}
      {$FATAL Exactly one of CRYPTOLIB_BINPOLY_SMALL, CRYPTOLIB_BINPOLY_EVEN, CRYPTOLIB_BINPOLY_ODD, CRYPTOLIB_BINPOLY_SQUARE must be defined before including this file}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
