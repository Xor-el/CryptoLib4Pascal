// GHASH field multiply: partial 256-bit carryless product (i386).
// After SimdProc3Begin_i386.inc: ebx = @X, esi = @Y, edi = @TGcmPartial128 output.
// Epilogue: pop edi, esi, ebx (matches SimdProc3Begin pushes).
//
  movq      xmm0, qword ptr [ebx + 8]
  movq      xmm4, qword ptr [ebx]
  punpcklqdq xmm0, xmm4

  movq      xmm1, qword ptr [esi + 8]
  movq      xmm4, qword ptr [esi]
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

  movq      qword ptr [edi + 0], xmm2
  movdqu    xmm5, xmm2
  psrldq    xmm5, 8
  movq      qword ptr [edi + 8], xmm5

  movq      qword ptr [edi + 16], xmm4
  movdqu    xmm5, xmm4
  psrldq    xmm5, 8
  movq      qword ptr [edi + 24], xmm5

  pop edi
  pop esi
  pop ebx
