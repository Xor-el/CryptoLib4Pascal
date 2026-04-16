// 16-byte XOR (i386): [ebx] ^= [esi] after SimdProc2Begin_i386 (ebx = dst, esi = src).
//
  movdqu    xmm0, [ebx]
  movdqu    xmm1, [esi]
  pxor      xmm0, xmm1
  movdqu    [ebx], xmm0
  pop esi
  pop ebx
