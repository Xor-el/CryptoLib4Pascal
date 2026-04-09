// 16-byte reverse: [esi] -> [ebx]; shuffle control at [edi]. After SimdProc3Begin_i386.
//
  movdqu    xmm0, [esi]
  movdqu    xmm1, [edi]
  pshufb    xmm0, xmm1
  movdqu    [ebx], xmm0

  pop edi
  pop esi
  pop ebx
