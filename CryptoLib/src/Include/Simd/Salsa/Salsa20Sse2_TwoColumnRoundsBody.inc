// Two Salsa20 column rounds (4-lane SSE4.1 quarter-round path): swap xmm1/xmm3,
// first SalsaQ on xmm0..3, diagonal pshufd, swap again, second SalsaQ, pshufd.
// Shared IA-32 / x86-64: XMM ARX + pshufd only — no stack, no GPR round counter.
// Parent must emit the loop label immediately before this include, then after
// the include: sub <roundsReg>, 2 / jg <sameLabel>. xmm0..xmm3 hold packed
// state lanes; xmm4..xmm7 are scratch.
  movdqa  xmm4, xmm1
  movdqa  xmm1, xmm3
  movdqa  xmm3, xmm4
  movdqa  xmm4, xmm0
  paddd   xmm4, xmm3
  movdqa  xmm5, xmm4
  pslld   xmm4, 7
  psrld   xmm5, 25
  por     xmm4, xmm5
  pxor    xmm1, xmm4
  movdqa  xmm4, xmm1
  paddd   xmm4, xmm0
  movdqa  xmm5, xmm4
  pslld   xmm4, 9
  psrld   xmm5, 23
  por     xmm4, xmm5
  pxor    xmm2, xmm4
  movdqa  xmm4, xmm2
  paddd   xmm4, xmm1
  movdqa  xmm5, xmm4
  pslld   xmm4, 13
  psrld   xmm5, 19
  por     xmm4, xmm5
  pxor    xmm3, xmm4
  movdqa  xmm4, xmm3
  paddd   xmm4, xmm2
  movdqa  xmm5, xmm4
  pslld   xmm4, 18
  psrld   xmm5, 14
  por     xmm4, xmm5
  pxor    xmm0, xmm4
  pshufd  xmm1, xmm1, $93
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $39
  movdqa  xmm4, xmm1
  movdqa  xmm1, xmm3
  movdqa  xmm3, xmm4
  movdqa  xmm4, xmm0
  paddd   xmm4, xmm3
  movdqa  xmm5, xmm4
  pslld   xmm4, 7
  psrld   xmm5, 25
  por     xmm4, xmm5
  pxor    xmm1, xmm4
  movdqa  xmm4, xmm1
  paddd   xmm4, xmm0
  movdqa  xmm5, xmm4
  pslld   xmm4, 9
  psrld   xmm5, 23
  por     xmm4, xmm5
  pxor    xmm2, xmm4
  movdqa  xmm4, xmm2
  paddd   xmm4, xmm1
  movdqa  xmm5, xmm4
  pslld   xmm4, 13
  psrld   xmm5, 19
  por     xmm4, xmm5
  pxor    xmm3, xmm4
  movdqa  xmm4, xmm3
  paddd   xmm4, xmm2
  movdqa  xmm5, xmm4
  pslld   xmm4, 18
  psrld   xmm5, 14
  por     xmm4, xmm5
  pxor    xmm0, xmm4
  pshufd  xmm1, xmm1, $93
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $39
