// SSE2 48-byte 3-limb XOR utility (i386).
// Xor 16-byte limbs in place: [ebx] ^= [eax + 0], [esi] ^= [eax + 16],
// [edi] ^= [eax + 32]. Unaligned movdqu (stack buffers may be misaligned).
// After SimdProc4Begin_i386.inc: ebx = PA0, esi = PA1, edi = PA2, eax = PSrc48.
// Uses xmm0, xmm1.
//
  movdqu    xmm0, [ebx]
  movdqu    xmm1, [eax]
  pxor      xmm0, xmm1
  movdqu    [ebx], xmm0

  movdqu    xmm0, [esi]
  movdqu    xmm1, [eax + 16]
  pxor      xmm0, xmm1
  movdqu    [esi], xmm0

  movdqu    xmm0, [edi]
  movdqu    xmm1, [eax + 32]
  pxor      xmm0, xmm1
  movdqu    [edi], xmm0

  pop edi
  pop esi
  pop ebx
