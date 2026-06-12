// 2x2 carryless Karatsuba multiply (3 PCLMULQDQ).
// Entry:  xmm0 = X (x0, x1), xmm1 = Y (y0, y1).
// Exit:   xmm6 = W0, xmm7 = W1 (i386 has xmm0..xmm7 only).
// Clobbers: xmm2..xmm5.
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
