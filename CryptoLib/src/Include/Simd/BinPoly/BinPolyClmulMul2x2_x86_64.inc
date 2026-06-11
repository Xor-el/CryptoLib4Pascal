// 2x2 carryless Karatsuba multiply (3 PCLMULQDQ).
// Entry:  xmm0 = X (x0, x1), xmm1 = Y (y0, y1).
// Exit:   xmm8 = W0, xmm9 = W1.
// Clobbers: xmm2..xmm7.
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
