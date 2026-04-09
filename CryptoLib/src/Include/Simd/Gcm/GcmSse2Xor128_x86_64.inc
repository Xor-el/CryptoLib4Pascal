// 16-byte XOR: [rcx] ^= [rdx]  (MS x64 ABI: rcx = PDst, rdx = PSrc)
//
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rdx]
  pxor      xmm0, xmm1
  movdqu    [rcx], xmm0
