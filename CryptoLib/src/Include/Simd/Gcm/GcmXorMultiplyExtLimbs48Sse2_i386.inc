// Xor 16-byte limbs: *ebx ^= [eax+0], *esi ^= [eax+16], *edi ^= [eax+32].
// After SimdProc4Begin_i386: ebx=PA0, esi=PA1, edi=PA2, eax=PSrc48.
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
