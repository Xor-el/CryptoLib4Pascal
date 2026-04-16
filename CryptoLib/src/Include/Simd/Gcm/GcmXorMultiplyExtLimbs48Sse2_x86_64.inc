// Xor 16-byte limbs: *PA0 ^= PSrc[0..15], *PA1 ^= PSrc[16..31], *PA2 ^= PSrc[32..47].
// rcx=PA0, rdx=PA1, r8=PA2, r9=PSrc48. Unaligned movdqu (stack buffers may be misaligned).
//
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [r9]
  pxor      xmm0, xmm1
  movdqu    [rcx], xmm0

  movdqu    xmm0, [rdx]
  movdqu    xmm1, [r9 + 16]
  pxor      xmm0, xmm1
  movdqu    [rdx], xmm0

  movdqu    xmm0, [r8]
  movdqu    xmm1, [r9 + 32]
  pxor      xmm0, xmm1
  movdqu    [r8], xmm0
