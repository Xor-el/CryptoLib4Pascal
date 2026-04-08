// 16-byte reverse: [rdx] -> [rcx]; shuffle control at [r8].
// PSHUFB: data in/out xmm0, control xmm1.
//
  movdqu    xmm0, [rdx]
  movdqu    xmm1, [r8]
  pshufb    xmm0, xmm1
  movdqu    [rcx], xmm0
