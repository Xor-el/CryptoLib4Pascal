// Salsa20 one-block (16*UInt32) core, pure SSE2 (i386).
// -------------------------------------------------------------------
// Diagonal transpose via scalar gather/scatter (no pblendw).
//
// On entry (after ClpSimdProc3Begin_i386.inc):
//   ebx = ARounds, esi = AIn, edi = AOut.
//
// End with: add esp, 512;
// pop edi; pop esi; pop ebx.
//
// Reference: D.J. Bernstein's Salsa20 SSE2 reference implementation
// (cr.yp.to/salsa20/) - the diagonal-extraction layout that this kernel's
// gather/scatter reproduces (see Salsa20BlockSse2_x86_64.inc).
  sub     esp, 512
{ -- diagonal gather: b0..b3 into [esp+0..63] -- }
  mov     eax, [esi+0]
  mov     [esp+0], eax
  mov     eax, [esi+20]
  mov     [esp+4], eax
  mov     eax, [esi+40]
  mov     [esp+8], eax
  mov     eax, [esi+60]
  mov     [esp+12], eax
  mov     eax, [esi+48]
  mov     [esp+16], eax
  mov     eax, [esi+4]
  mov     [esp+20], eax
  mov     eax, [esi+24]
  mov     [esp+24], eax
  mov     eax, [esi+44]
  mov     [esp+28], eax
  mov     eax, [esi+32]
  mov     [esp+32], eax
  mov     eax, [esi+52]
  mov     [esp+36], eax
  mov     eax, [esi+8]
  mov     [esp+40], eax
  mov     eax, [esi+28]
  mov     [esp+44], eax
  mov     eax, [esi+16]
  mov     [esp+48], eax
  mov     eax, [esi+36]
  mov     [esp+52], eax
  mov     eax, [esi+56]
  mov     [esp+56], eax
  mov     eax, [esi+12]
  mov     [esp+60], eax
  movdqu  xmm0, [esp+0]
  movdqu  xmm1, [esp+16]
  movdqu  xmm2, [esp+32]
  movdqu  xmm3, [esp+48]
@@salsa20_sse2_i386_rd:
  { ---- inline: shared SSE2 two column rounds ---- }
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
  sub     ebx, 2
  jg      @@salsa20_sse2_i386_rd
  movdqu  xmm4, [esp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+48]
  paddd   xmm3, xmm4
{ -- inverse diagonal scatter: lanes -> natural state at edi -- }
  movdqu  [esp+64], xmm0
  movdqu  [esp+80], xmm1
  movdqu  [esp+96], xmm2
  movdqu  [esp+112], xmm3
  mov     eax, [esp+64]
  mov     [edi+0], eax
  mov     eax, [esp+68]
  mov     [edi+20], eax
  mov     eax, [esp+72]
  mov     [edi+40], eax
  mov     eax, [esp+76]
  mov     [edi+60], eax
  mov     eax, [esp+80]
  mov     [edi+48], eax
  mov     eax, [esp+84]
  mov     [edi+4], eax
  mov     eax, [esp+88]
  mov     [edi+24], eax
  mov     eax, [esp+92]
  mov     [edi+44], eax
  mov     eax, [esp+96]
  mov     [edi+32], eax
  mov     eax, [esp+100]
  mov     [edi+52], eax
  mov     eax, [esp+104]
  mov     [edi+8], eax
  mov     eax, [esp+108]
  mov     [edi+28], eax
  mov     eax, [esp+112]
  mov     [edi+16], eax
  mov     eax, [esp+116]
  mov     [edi+36], eax
  mov     eax, [esp+120]
  mov     [edi+56], eax
  mov     eax, [esp+124]
  mov     [edi+12], eax
  add     esp, 512
  pop     edi
  pop     esi
  pop     ebx


