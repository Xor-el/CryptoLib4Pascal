// Fold Z1 into Z0/Z2 (SSE2 PSLLDQ/PSRLDQ). rcx=PZ0, rdx=PZ1, r8=PZ2 (16 bytes each).
//
  movdqu    xmm0, [rcx]
  movdqu    xmm2, [r8]
  movdqu    xmm1, [rdx]
  movdqa    xmm4, xmm1
  movdqa    xmm5, xmm1
  pslldq    xmm4, 8
  psrldq    xmm5, 8
  pxor      xmm0, xmm4
  pxor      xmm2, xmm5
  movdqu    [rcx], xmm0
  movdqu    [r8], xmm2
