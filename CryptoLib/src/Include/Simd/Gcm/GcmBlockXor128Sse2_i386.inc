// SSE2 16-byte XOR utility (i386).
// After SimdProc2Begin_i386: ebx = PDst, esi = PSrc.
// Computes [ebx] ^= [esi].
// Uses xmm0, xmm1.
//
  movdqu    xmm0, [ebx]
  movdqu    xmm1, [esi]
  pxor      xmm0, xmm1
  movdqu    [ebx], xmm0
  pop esi
  pop ebx
