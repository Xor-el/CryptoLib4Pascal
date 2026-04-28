// SSE2 + PCLMULQDQ GHASH field multiply, partial carryless product (x86-64).
// Produces the 256-bit Karatsuba partial product (Z0, Z1, Z2) for two GHASH
// field elements before degree reduction.
// After SimdProc3Begin_x86_64.inc: rcx = @X (TFieldElement), rdx = @Y,
// r8 = @TGcmPartial128 output.
// X.N0, X.N1 and Y.N0, Y.N1 are UInt64 GHASH field limbs (TFieldElement).
// Pack each limb into xmm as high qword then low (movq + punpcklqdq);
// little-endian 128-bit layout.
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
  movq      xmm0, qword ptr [rcx + 8]
  movq      xmm4, qword ptr [rcx]
  punpcklqdq xmm0, xmm4

  movq      xmm1, qword ptr [rdx + 8]
  movq      xmm4, qword ptr [rdx]
  punpcklqdq xmm1, xmm4

  movdqu    xmm2, xmm0
  db $66, $0F, $3A, $44, $D1, $00  // pclmulqdq xmm2, xmm1, 0

  movdqu    xmm3, xmm0
  db $66, $0F, $3A, $44, $D9, $01  // pclmulqdq xmm3, xmm1, 1
  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $10  // pclmulqdq xmm4, xmm1, 16
  pxor      xmm3, xmm4

  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $11  // pclmulqdq xmm4, xmm1, 17

  movdqu    xmm5, xmm3
  pslldq    xmm5, 8
  pxor      xmm2, xmm5
  movdqu    xmm5, xmm3
  psrldq    xmm5, 8
  pxor      xmm4, xmm5

  movq      qword ptr [r8 + 0], xmm2
  movdqu    xmm5, xmm2
  psrldq    xmm5, 8
  movq      qword ptr [r8 + 8], xmm5

  movq      qword ptr [r8 + 16], xmm4
  movdqu    xmm5, xmm4
  psrldq    xmm5, 8
  movq      qword ptr [r8 + 24], xmm5
