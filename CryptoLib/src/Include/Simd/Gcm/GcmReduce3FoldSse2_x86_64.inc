// 3-limb GHASH reduction (SSE2): fold Z1 into (Z0, Z2), then reduce the
// (Z0, Z2) pair modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1, writing
// the resulting 16-byte field element to POut. Z0/Z1/Z2 are the three 128-bit
// limbs carried across a batch of Karatsuba-style PCLMULQDQ GHASH products.
// rcx=PZ0, rdx=PZ1, r8=PZ2, r9=POut (MS x64 ABI / FPC remapped SysV).
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
  movdqu    xmm0, [rcx]
  movdqu    xmm2, [r8]
  movq      xmm3, xmm0
  movq      xmm4, xmm2
  movdqa    xmm5, xmm3
  psrlq     xmm5, 1
  movdqa    xmm6, xmm3
  psrlq     xmm6, 2
  movdqa    xmm7, xmm3
  psrlq     xmm7, 7
  pxor      xmm4, xmm3
  pxor      xmm4, xmm5
  pxor      xmm4, xmm6
  pxor      xmm4, xmm7
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8
  movdqa    xmm5, xmm3
  psllq     xmm5, 63
  movdqa    xmm6, xmm3
  psllq     xmm6, 62
  movdqa    xmm7, xmm3
  psllq     xmm7, 57
  pxor      xmm1, xmm5
  pxor      xmm1, xmm6
  pxor      xmm1, xmm7
  movdqa    xmm5, xmm2
  psrldq    xmm5, 8
  movdqa    xmm6, xmm5
  psllq     xmm6, 1
  movdqa    xmm7, xmm4
  psrlq     xmm7, 63
  por       xmm6, xmm7
  movdqa    xmm7, xmm4
  psllq     xmm7, 1
  movdqa    xmm3, xmm1
  psrlq     xmm3, 63
  por       xmm7, xmm3
  movdqa    xmm0, xmm1
  psllq     xmm0, 1
  movdqa    xmm3, xmm0
  psrlq     xmm3, 1
  movdqa    xmm2, xmm0
  psrlq     xmm2, 2
  movdqa    xmm5, xmm0
  psrlq     xmm5, 7
  pxor      xmm6, xmm0
  pxor      xmm6, xmm3
  pxor      xmm6, xmm2
  pxor      xmm6, xmm5
  movdqa    xmm3, xmm1
  psllq     xmm3, 63
  movdqa    xmm2, xmm1
  psllq     xmm2, 58
  pxor      xmm7, xmm3
  pxor      xmm7, xmm2
  movq      qword ptr [r9], xmm7
  movq      qword ptr [r9 + 8], xmm6
