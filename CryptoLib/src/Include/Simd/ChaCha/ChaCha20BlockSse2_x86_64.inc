// ChaCha20 one 16*UInt32 block: LE state in, LE out, SSE2.
// Double round: two half-rounds; pshufd row shuffles; 64B stack copy of AIn; final + input to work state, store.
// After SimdProc3Begin_x86_64.inc: rcx = ARounds, rdx = AIn (16 UInt32), r8 = AOut (16 UInt32).
  sub     rsp, 64
  movdqu  xmm0, [rdx+0]
  movdqu  xmm1, [rdx+16]
  movdqu  xmm2, [rdx+32]
  movdqu  xmm3, [rdx+48]
  movdqu  [rsp], xmm0
  movdqu  [rsp+16], xmm1
  movdqu  [rsp+32], xmm2
  movdqu  [rsp+48], xmm3
@@chacha20_sse2_x64_round:
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 16
  pslld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 20
  pslld   xmm4, 12
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 24
  pslld   xmm4, 8
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 25
  pslld   xmm4, 7
  por     xmm1, xmm4
  pshufd  xmm1, xmm1, $39
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $93
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 16
  pslld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 20
  pslld   xmm4, 12
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 24
  pslld   xmm4, 8
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 25
  pslld   xmm4, 7
  por     xmm1, xmm4
  pshufd  xmm1, xmm1, $93
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $39
  sub     rcx, 2
  jg      @@chacha20_sse2_x64_round
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  add     rsp, 64
  movdqu  [r8+0], xmm0
  movdqu  [r8+16], xmm1
  movdqu  [r8+32], xmm2
  movdqu  [r8+48], xmm3
