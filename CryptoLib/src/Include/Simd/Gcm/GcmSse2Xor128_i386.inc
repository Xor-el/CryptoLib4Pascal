// 16-byte XOR (i386): [ebx] ^= [esi] after SimdProc2Begin_i386 (eax=dst, edx=src)
// SimdProc2Begin leaves eax, edx as params — use them directly.
//
  movdqu    xmm0, [eax]
  movdqu    xmm1, [edx]
  pxor      xmm0, xmm1
  movdqu    [eax], xmm0
