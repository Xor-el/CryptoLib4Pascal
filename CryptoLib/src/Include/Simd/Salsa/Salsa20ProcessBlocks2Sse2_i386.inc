// Salsa20 128B (two 64B blocks), fused I/O, pure SSE2 (i386).
// -------------------------------------------------------------------
// Diagonal transpose via scalar gather/scatter (no pblendw); see
// Salsa20BlockSse2_i386.inc. Rounds: Salsa20Sse2_TwoColumnRoundsBody.inc.
//
// On entry (after ClpSimdProc4Begin_i386.inc):
//   ebx = ARounds, esi = AState, edi = AIn, eax = AOut.
//
// edx: saved ARounds. push eax/pop eax: gather clobbers eax; xor needs
// AOut in eax.
//
// Reference: D.J. Bernstein's Salsa20 SSE2 reference implementation
// (cr.yp.to/salsa20/) - the diagonal-extraction layout that this kernel's
// gather/scatter reproduces.
  mov     edx, ebx
  push    eax
  sub     esp, 512
{ -------- block 1 (64B) at I/O offset 0 -------- }
{ -- diagonal gather from [esi] into [esp+0..63] -- }
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
@@s2p2s2_i386_b1r:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse2_TwoColumnRoundsBody.inc}
  sub     ebx, 2
  jg      @@s2p2s2_i386_b1r
  movdqu  xmm4, [esp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+48]
  paddd   xmm3, xmm4
  movdqu  [esp+64], xmm0
  movdqu  [esp+80], xmm1
  movdqu  [esp+96], xmm2
  movdqu  [esp+112], xmm3
  mov     eax, [esp+512]
  mov     ebx, [esp+64]
  mov     ecx, [edi+0]
  xor     ebx, ecx
  mov     [eax+0], ebx
  mov     ebx, [esp+68]
  mov     ecx, [edi+20]
  xor     ebx, ecx
  mov     [eax+20], ebx
  mov     ebx, [esp+72]
  mov     ecx, [edi+40]
  xor     ebx, ecx
  mov     [eax+40], ebx
  mov     ebx, [esp+76]
  mov     ecx, [edi+60]
  xor     ebx, ecx
  mov     [eax+60], ebx
  mov     ebx, [esp+80]
  mov     ecx, [edi+48]
  xor     ebx, ecx
  mov     [eax+48], ebx
  mov     ebx, [esp+84]
  mov     ecx, [edi+4]
  xor     ebx, ecx
  mov     [eax+4], ebx
  mov     ebx, [esp+88]
  mov     ecx, [edi+24]
  xor     ebx, ecx
  mov     [eax+24], ebx
  mov     ebx, [esp+92]
  mov     ecx, [edi+44]
  xor     ebx, ecx
  mov     [eax+44], ebx
  mov     ebx, [esp+96]
  mov     ecx, [edi+32]
  xor     ebx, ecx
  mov     [eax+32], ebx
  mov     ebx, [esp+100]
  mov     ecx, [edi+52]
  xor     ebx, ecx
  mov     [eax+52], ebx
  mov     ebx, [esp+104]
  mov     ecx, [edi+8]
  xor     ebx, ecx
  mov     [eax+8], ebx
  mov     ebx, [esp+108]
  mov     ecx, [edi+28]
  xor     ebx, ecx
  mov     [eax+28], ebx
  mov     ebx, [esp+112]
  mov     ecx, [edi+16]
  xor     ebx, ecx
  mov     [eax+16], ebx
  mov     ebx, [esp+116]
  mov     ecx, [edi+36]
  xor     ebx, ecx
  mov     [eax+36], ebx
  mov     ebx, [esp+120]
  mov     ecx, [edi+56]
  xor     ebx, ecx
  mov     [eax+56], ebx
  mov     ebx, [esp+124]
  mov     ecx, [edi+12]
  xor     ebx, ecx
  mov     [eax+12], ebx
  add     esp, 512
  pop     eax
  add     dword [esi+32], 1
  jnz     @@s2p2s2_i386_c1d
  add     dword [esi+36], 1
@@s2p2s2_i386_c1d:
{ -------- block 2 (64B) at I/O offset 64, counter already advanced -------- }
  mov     ebx, edx
  push    eax
  sub     esp, 512
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
@@s2p2s2_i386_b2r:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse2_TwoColumnRoundsBody.inc}
  sub     ebx, 2
  jg      @@s2p2s2_i386_b2r
  movdqu  xmm4, [esp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+48]
  paddd   xmm3, xmm4
  movdqu  [esp+64], xmm0
  movdqu  [esp+80], xmm1
  movdqu  [esp+96], xmm2
  movdqu  [esp+112], xmm3
  mov     eax, [esp+512]
  mov     ebx, [esp+64]
  mov     ecx, [edi+64]
  xor     ebx, ecx
  mov     [eax+64], ebx
  mov     ebx, [esp+68]
  mov     ecx, [edi+84]
  xor     ebx, ecx
  mov     [eax+84], ebx
  mov     ebx, [esp+72]
  mov     ecx, [edi+104]
  xor     ebx, ecx
  mov     [eax+104], ebx
  mov     ebx, [esp+76]
  mov     ecx, [edi+124]
  xor     ebx, ecx
  mov     [eax+124], ebx
  mov     ebx, [esp+80]
  mov     ecx, [edi+112]
  xor     ebx, ecx
  mov     [eax+112], ebx
  mov     ebx, [esp+84]
  mov     ecx, [edi+68]
  xor     ebx, ecx
  mov     [eax+68], ebx
  mov     ebx, [esp+88]
  mov     ecx, [edi+88]
  xor     ebx, ecx
  mov     [eax+88], ebx
  mov     ebx, [esp+92]
  mov     ecx, [edi+108]
  xor     ebx, ecx
  mov     [eax+108], ebx
  mov     ebx, [esp+96]
  mov     ecx, [edi+96]
  xor     ebx, ecx
  mov     [eax+96], ebx
  mov     ebx, [esp+100]
  mov     ecx, [edi+116]
  xor     ebx, ecx
  mov     [eax+116], ebx
  mov     ebx, [esp+104]
  mov     ecx, [edi+72]
  xor     ebx, ecx
  mov     [eax+72], ebx
  mov     ebx, [esp+108]
  mov     ecx, [edi+92]
  xor     ebx, ecx
  mov     [eax+92], ebx
  mov     ebx, [esp+112]
  mov     ecx, [edi+80]
  xor     ebx, ecx
  mov     [eax+80], ebx
  mov     ebx, [esp+116]
  mov     ecx, [edi+100]
  xor     ebx, ecx
  mov     [eax+100], ebx
  mov     ebx, [esp+120]
  mov     ecx, [edi+120]
  xor     ebx, ecx
  mov     [eax+120], ebx
  mov     ebx, [esp+124]
  mov     ecx, [edi+76]
  xor     ebx, ecx
  mov     [eax+76], ebx
  add     esp, 512
  pop     eax
  add     dword [esi+32], 1
  jnz     @@s2p2s2_i386_c2d
  add     dword [esi+36], 1
@@s2p2s2_i386_c2d:
  pop     edi
  pop     esi
  pop     ebx
