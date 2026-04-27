// One ChaCha double round (2 column rounds + 3 row shuffles), SSE2, x86-64. ARX only — no I/O xor here.
// ChaCha20 parent stores keystream to AOut; ChaCha7539 parent xors in/out (fused I/O) after the round loop.
// Include after the loop label; parent must emit: sub <roundsReg>, 2 / jg <loopLabel>.
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
