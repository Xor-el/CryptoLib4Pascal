// ChaCha20 one 64-byte block, LE uint32[16] state, SSE2. After SimdProc3Begin_i386.inc: ebx = ARounds, esi = AIn, edi = AOut.
// End with: add esp, 64; add esp, eax; pop edi; pop esi; pop ebx
  mov     eax, esp
  and     eax, 15
  sub     esp, eax
  sub     esp, 64
  movdqu  xmm0, [esi+0]
  movdqu  xmm1, [esi+16]
  movdqu  xmm2, [esi+32]
  movdqu  xmm3, [esi+48]
  movdqu  [esp], xmm0
  movdqu  [esp+16], xmm1
  movdqu  [esp+32], xmm2
  movdqu  [esp+48], xmm3
@@chacha20_sse2_i386_round:
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
  sub     ebx, 2
  jg      @@chacha20_sse2_i386_round
  movdqu  xmm4, [esp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+48]
  paddd   xmm3, xmm4
  add     esp, 64
  add     esp, eax
  movdqu  [edi+0], xmm0
  movdqu  [edi+16], xmm1
  movdqu  [edi+32], xmm2
  movdqu  [edi+48], xmm3
  pop     edi
  pop     esi
  pop     ebx
