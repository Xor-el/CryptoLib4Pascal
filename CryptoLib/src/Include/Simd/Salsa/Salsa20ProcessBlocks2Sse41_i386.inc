// Salsa20 128B, SSE4.1 i386. After SimdProc4Begin: ebx=ARounds, esi=AState, edi=AIn, eax=AOut.
// Rounds: Salsa20Sse41_TwoColumnRoundsBody.inc.
// edx: saved ARounds. push eax/ pop eax: expand clobbers eax; xor needs AOut in eax.
  mov     edx, ebx
  push    eax
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
@@s2p2_i386_b1r:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse41_TwoColumnRoundsBody.inc}
  sub     ebx, 2
  jg      @@s2p2_i386_b1r
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
  mov     eax, [esp+512]
  mov     ebx, [esp+256]
  mov     ecx, [edi+0]
  xor     ebx, ecx
  mov     [eax+0], ebx
  mov     ebx, [esp+260]
  mov     ecx, [edi+4]
  xor     ebx, ecx
  mov     [eax+4], ebx
  mov     ebx, [esp+264]
  mov     ecx, [edi+8]
  xor     ebx, ecx
  mov     [eax+8], ebx
  mov     ebx, [esp+268]
  mov     ecx, [edi+12]
  xor     ebx, ecx
  mov     [eax+12], ebx
  mov     ebx, [esp+272]
  mov     ecx, [edi+16]
  xor     ebx, ecx
  mov     [eax+16], ebx
  mov     ebx, [esp+276]
  mov     ecx, [edi+20]
  xor     ebx, ecx
  mov     [eax+20], ebx
  mov     ebx, [esp+280]
  mov     ecx, [edi+24]
  xor     ebx, ecx
  mov     [eax+24], ebx
  mov     ebx, [esp+284]
  mov     ecx, [edi+28]
  xor     ebx, ecx
  mov     [eax+28], ebx
  mov     ebx, [esp+288]
  mov     ecx, [edi+32]
  xor     ebx, ecx
  mov     [eax+32], ebx
  mov     ebx, [esp+292]
  mov     ecx, [edi+36]
  xor     ebx, ecx
  mov     [eax+36], ebx
  mov     ebx, [esp+296]
  mov     ecx, [edi+40]
  xor     ebx, ecx
  mov     [eax+40], ebx
  mov     ebx, [esp+300]
  mov     ecx, [edi+44]
  xor     ebx, ecx
  mov     [eax+44], ebx
  mov     ebx, [esp+304]
  mov     ecx, [edi+48]
  xor     ebx, ecx
  mov     [eax+48], ebx
  mov     ebx, [esp+308]
  mov     ecx, [edi+52]
  xor     ebx, ecx
  mov     [eax+52], ebx
  mov     ebx, [esp+312]
  mov     ecx, [edi+56]
  xor     ebx, ecx
  mov     [eax+56], ebx
  mov     ebx, [esp+316]
  mov     ecx, [edi+60]
  xor     ebx, ecx
  mov     [eax+60], ebx
  add     esp, 512
  pop     eax
  add     dword [esi+32], 1
  jnz     @@s2p2_i386_c1d
  add     dword [esi+36], 1
@@s2p2_i386_c1d:
  mov     ebx, edx
  push    eax
  sub     esp, 512
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
@@s2p2_i386_b2r:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse41_TwoColumnRoundsBody.inc}
  sub     ebx, 2
  jg      @@s2p2_i386_b2r
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
  mov     eax, [esp+512]
  mov     ebx, [esp+256]
  mov     ecx, [edi+64]
  xor     ebx, ecx
  mov     [eax+64], ebx
  mov     ebx, [esp+260]
  mov     ecx, [edi+68]
  xor     ebx, ecx
  mov     [eax+68], ebx
  mov     ebx, [esp+264]
  mov     ecx, [edi+72]
  xor     ebx, ecx
  mov     [eax+72], ebx
  mov     ebx, [esp+268]
  mov     ecx, [edi+76]
  xor     ebx, ecx
  mov     [eax+76], ebx
  mov     ebx, [esp+272]
  mov     ecx, [edi+80]
  xor     ebx, ecx
  mov     [eax+80], ebx
  mov     ebx, [esp+276]
  mov     ecx, [edi+84]
  xor     ebx, ecx
  mov     [eax+84], ebx
  mov     ebx, [esp+280]
  mov     ecx, [edi+88]
  xor     ebx, ecx
  mov     [eax+88], ebx
  mov     ebx, [esp+284]
  mov     ecx, [edi+92]
  xor     ebx, ecx
  mov     [eax+92], ebx
  mov     ebx, [esp+288]
  mov     ecx, [edi+96]
  xor     ebx, ecx
  mov     [eax+96], ebx
  mov     ebx, [esp+292]
  mov     ecx, [edi+100]
  xor     ebx, ecx
  mov     [eax+100], ebx
  mov     ebx, [esp+296]
  mov     ecx, [edi+104]
  xor     ebx, ecx
  mov     [eax+104], ebx
  mov     ebx, [esp+300]
  mov     ecx, [edi+108]
  xor     ebx, ecx
  mov     [eax+108], ebx
  mov     ebx, [esp+304]
  mov     ecx, [edi+112]
  xor     ebx, ecx
  mov     [eax+112], ebx
  mov     ebx, [esp+308]
  mov     ecx, [edi+116]
  xor     ebx, ecx
  mov     [eax+116], ebx
  mov     ebx, [esp+312]
  mov     ecx, [edi+120]
  xor     ebx, ecx
  mov     [eax+120], ebx
  mov     ebx, [esp+316]
  mov     ecx, [edi+124]
  xor     ebx, ecx
  mov     [eax+124], ebx
  add     esp, 512
  pop     eax
  add     dword [esi+32], 1
  jnz     @@s2p2_i386_c2d
  add     dword [esi+36], 1
@@s2p2_i386_c2d:
  pop     edi
  pop     esi
  pop     ebx
