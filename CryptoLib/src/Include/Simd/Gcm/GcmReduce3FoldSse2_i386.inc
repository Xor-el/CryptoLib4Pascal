// Fold Z1 into Z0/Z2. ebx=PZ0, esi=PZ1, edi=PZ2.
//
  movdqu    xmm0, [ebx]
  movdqu    xmm2, [edi]
  movdqu    xmm1, [esi]
  movdqa    xmm4, xmm1
  movdqa    xmm5, xmm1
  pslldq    xmm4, 8
  psrldq    xmm5, 8
  pxor      xmm0, xmm4
  pxor      xmm2, xmm5
  movdqu    [ebx], xmm0
  movdqu    [edi], xmm2
  pop edi
  pop esi
  pop ebx
