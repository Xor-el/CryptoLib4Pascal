// SSE2 16-byte XOR utility (x86-64).
// After SimdProc2Begin_x86_64.inc: rcx = PDst, rdx = PSrc.
// Computes [rcx] ^= [rdx].
// Uses xmm0, xmm1.
//
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rdx]
  pxor      xmm0, xmm1
  movdqu    [rcx], xmm0
