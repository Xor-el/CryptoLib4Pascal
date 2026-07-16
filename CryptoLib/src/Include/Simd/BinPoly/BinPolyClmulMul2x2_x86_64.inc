// 2x2-limb carryless Karatsuba multiply (x86-64).
// -------------------------------------------------------------------
// Multiplies two 2-limb (256-bit) polynomials X=(x0,x1), Y=(y0,y1) over
// GF(2)[x] using 3 PCLMULQDQ products instead of the schoolbook 4 (x0*y0,
// x1*y1, and (x0 xor x1)*(y0 xor y1) to recover the cross term), then
// combines the partials into the 4-limb (512-bit) product W=(W0,W1).
//
// On entry: xmm0 = X (x0, x1), xmm1 = Y (y0, y1).
// On exit:  xmm8 = W0, xmm9 = W1.
// Clobbers: xmm2..xmm7.
//
// PCLMULQDQ forms are db-encoded for broad assembler compatibility.
//
// Reference: Karatsuba's algorithm applied to carry-less multiplication -
// the standard 3-multiply reduction described in Shay Gueron / Michael E.
// Kounavis, "Intel(R) Carry-Less Multiplication Instruction and its Usage
// for Computing the GCM Mode" (white paper).
  movdqa    xmm2, xmm0
  punpcklqdq xmm2, xmm1
  movdqa    xmm3, xmm0
  punpckhqdq xmm3, xmm1
  pxor      xmm2, xmm3

  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $00  // pclmulqdq xmm4, xmm1, 0
  movdqa    xmm5, xmm0
  db $66, $0F, $3A, $44, $E9, $11  // pclmulqdq xmm5, xmm1, 17
  movdqa    xmm6, xmm2
  db $66, $0F, $3A, $44, $F6, $01  // pclmulqdq xmm6, xmm6, 1

  movdqa    xmm7, xmm4
  pxor      xmm7, xmm5
  pxor      xmm7, xmm6

  movdqa    xmm8, xmm7
  pslldq    xmm8, 8
  pxor      xmm8, xmm4

  movdqa    xmm9, xmm7
  psrldq    xmm9, 8
  pxor      xmm9, xmm5
