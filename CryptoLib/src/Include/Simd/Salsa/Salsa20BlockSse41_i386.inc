// Salsa20 block, SSE4.1 (pblendw). After SimdProc3Begin_i386.inc: ebx = ARounds, esi = AIn, edi = AOut.
// Rounds: Salsa20Sse41_TwoColumnRoundsBody.inc.
// End with: add esp, 512; pop edi; pop esi; pop ebx
  sub     esp, 512
{ -- expand: edx was param - use esi = AIn }
{ row 0 }
  mov     eax, [esi+0]
  mov     word ptr [esp+0], ax
  shr     eax, 16
  mov     word ptr [esp+2], ax
  mov     eax, [esi+4]
  mov     word ptr [esp+4], ax
  shr     eax, 16
  mov     word ptr [esp+6], ax
  mov     eax, [esi+8]
  mov     word ptr [esp+8], ax
  shr     eax, 16
  mov     word ptr [esp+10], ax
  mov     eax, [esi+12]
  mov     word ptr [esp+12], ax
  shr     eax, 16
  mov     word ptr [esp+14], ax
{ row 1 }
  mov     eax, [esi+16]
  mov     word ptr [esp+16], ax
  shr     eax, 16
  mov     word ptr [esp+18], ax
  mov     eax, [esi+20]
  mov     word ptr [esp+20], ax
  shr     eax, 16
  mov     word ptr [esp+22], ax
  mov     eax, [esi+24]
  mov     word ptr [esp+24], ax
  shr     eax, 16
  mov     word ptr [esp+26], ax
  mov     eax, [esi+28]
  mov     word ptr [esp+28], ax
  shr     eax, 16
  mov     word ptr [esp+30], ax
{ row 2 }
  mov     eax, [esi+32]
  mov     word ptr [esp+32], ax
  shr     eax, 16
  mov     word ptr [esp+34], ax
  mov     eax, [esi+36]
  mov     word ptr [esp+36], ax
  shr     eax, 16
  mov     word ptr [esp+38], ax
  mov     eax, [esi+40]
  mov     word ptr [esp+40], ax
  shr     eax, 16
  mov     word ptr [esp+42], ax
  mov     eax, [esi+44]
  mov     word ptr [esp+44], ax
  shr     eax, 16
  mov     word ptr [esp+46], ax
{ row 3 }
  mov     eax, [esi+48]
  mov     word ptr [esp+48], ax
  shr     eax, 16
  mov     word ptr [esp+50], ax
  mov     eax, [esi+52]
  mov     word ptr [esp+52], ax
  shr     eax, 16
  mov     word ptr [esp+54], ax
  mov     eax, [esi+56]
  mov     word ptr [esp+56], ax
  shr     eax, 16
  mov     word ptr [esp+58], ax
  mov     eax, [esi+60]
  mov     word ptr [esp+60], ax
  shr     eax, 16
  mov     word ptr [esp+62], ax
  movdqu  xmm0, [esp+0]
  movdqu  xmm1, [esp+16]
  movdqu  xmm2, [esp+32]
  movdqu  xmm3, [esp+48]
  movdqa  xmm4, xmm0
  pblendw xmm4, xmm2, $F0
  movdqa  xmm5, xmm1
  pblendw xmm5, xmm3, $C3
  movdqa  xmm6, xmm0
  pblendw xmm6, xmm2, $0F
  movdqa  xmm7, xmm1
  pblendw xmm7, xmm3, $3C
  movdqa  xmm0, xmm4
  pblendw xmm0, xmm5, $CC
  movdqa  xmm1, xmm4
  pblendw xmm1, xmm5, $33
  movdqa  xmm2, xmm6
  pblendw xmm2, xmm7, $CC
  movdqa  xmm3, xmm6
  pblendw xmm3, xmm7, $33
  movdqu  [esp+64], xmm0
  movdqu  [esp+80], xmm1
  movdqu  [esp+96], xmm2
  movdqu  [esp+112], xmm3
@@salsa20_sse41_i386_rd:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse41_TwoColumnRoundsBody.inc}
  sub     ebx, 2
  jg      @@salsa20_sse41_i386_rd
  movdqu  xmm4, [esp+64]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+80]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+96]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+112]
  paddd   xmm3, xmm4
  movdqu  [esp+192], xmm0
  movdqu  [esp+208], xmm1
  movdqu  [esp+224], xmm2
  movdqu  [esp+240], xmm3
  movdqu  xmm0, [esp+192]
  movdqu  xmm1, [esp+208]
  movdqu  xmm2, [esp+224]
  movdqu  xmm3, [esp+240]
  movdqa  xmm4, xmm0
  pblendw xmm4, xmm1, $CC
  movdqa  xmm5, xmm0
  pblendw xmm5, xmm1, $33
  movdqa  xmm6, xmm2
  pblendw xmm6, xmm3, $CC
  movdqa  xmm7, xmm2
  pblendw xmm7, xmm3, $33
  movdqa  xmm0, xmm4
  pblendw xmm0, xmm6, $F0
  movdqa  xmm1, xmm5
  pblendw xmm1, xmm7, $C3
  movdqa  xmm2, xmm4
  pblendw xmm2, xmm6, $0F
  movdqa  xmm3, xmm5
  pblendw xmm3, xmm7, $3C
  movdqu  [esp+256], xmm0
  movdqu  [esp+272], xmm1
  movdqu  [esp+288], xmm2
  movdqu  [esp+304], xmm3
  mov     eax, [esp+256]
  mov     [edi+0], eax
  mov     eax, [esp+260]
  mov     [edi+4], eax
  mov     eax, [esp+264]
  mov     [edi+8], eax
  mov     eax, [esp+268]
  mov     [edi+12], eax
  mov     eax, [esp+272]
  mov     [edi+16], eax
  mov     eax, [esp+276]
  mov     [edi+20], eax
  mov     eax, [esp+280]
  mov     [edi+24], eax
  mov     eax, [esp+284]
  mov     [edi+28], eax
  mov     eax, [esp+288]
  mov     [edi+32], eax
  mov     eax, [esp+292]
  mov     [edi+36], eax
  mov     eax, [esp+296]
  mov     [edi+40], eax
  mov     eax, [esp+300]
  mov     [edi+44], eax
  mov     eax, [esp+304]
  mov     [edi+48], eax
  mov     eax, [esp+308]
  mov     [edi+52], eax
  mov     eax, [esp+312]
  mov     [edi+56], eax
  mov     eax, [esp+316]
  mov     [edi+60], eax
  add     esp, 512
  pop     edi
  pop     esi
  pop     ebx
