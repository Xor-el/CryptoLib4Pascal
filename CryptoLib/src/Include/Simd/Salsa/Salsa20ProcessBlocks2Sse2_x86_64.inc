// Salsa20 128B, pure SSE2: two 64B blocks, fused I/O (xor) like ChaCha7539ProcessBlocks2Sse2.
// Diagonal transpose done as a scalar gather/scatter (no pblendw); see Salsa20BlockSse2_x86_64.inc.
// Rounds: Salsa20Sse2_TwoColumnRoundsBody.inc.
// After ClpSimdProc4Begin_x86_64.inc: rcx=ARounds, rdx=AState, r8=AIn (plain), r9=AOut (cipher).
// r10 = round counter per block. Counter words: FEngineState[8]@[rdx+32], FEngineState[9]@[rdx+36].
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  sub     rsp, 512
{ -------- block 1 (64B) at I/O offset 0 -------- }
  mov     r10, rcx
  mov     eax, [rdx+0]
  mov     [rsp+0], eax
  mov     eax, [rdx+20]
  mov     [rsp+4], eax
  mov     eax, [rdx+40]
  mov     [rsp+8], eax
  mov     eax, [rdx+60]
  mov     [rsp+12], eax
  mov     eax, [rdx+48]
  mov     [rsp+16], eax
  mov     eax, [rdx+4]
  mov     [rsp+20], eax
  mov     eax, [rdx+24]
  mov     [rsp+24], eax
  mov     eax, [rdx+44]
  mov     [rsp+28], eax
  mov     eax, [rdx+32]
  mov     [rsp+32], eax
  mov     eax, [rdx+52]
  mov     [rsp+36], eax
  mov     eax, [rdx+8]
  mov     [rsp+40], eax
  mov     eax, [rdx+28]
  mov     [rsp+44], eax
  mov     eax, [rdx+16]
  mov     [rsp+48], eax
  mov     eax, [rdx+36]
  mov     [rsp+52], eax
  mov     eax, [rdx+56]
  mov     [rsp+56], eax
  mov     eax, [rdx+12]
  mov     [rsp+60], eax
  movdqu  xmm0, [rsp+0]
  movdqu  xmm1, [rsp+16]
  movdqu  xmm2, [rsp+32]
  movdqu  xmm3, [rsp+48]
@@s2p2s2_x64_b1r:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse2_TwoColumnRoundsBody.inc}
  sub     r10, 2
  jg      @@s2p2s2_x64_b1r
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  movdqu  [rsp+64], xmm0
  movdqu  [rsp+80], xmm1
  movdqu  [rsp+96], xmm2
  movdqu  [rsp+112], xmm3
  mov     eax, [rsp+64]
  xor     eax, [r8+0]
  mov     [r9+0], eax
  mov     eax, [rsp+68]
  xor     eax, [r8+20]
  mov     [r9+20], eax
  mov     eax, [rsp+72]
  xor     eax, [r8+40]
  mov     [r9+40], eax
  mov     eax, [rsp+76]
  xor     eax, [r8+60]
  mov     [r9+60], eax
  mov     eax, [rsp+80]
  xor     eax, [r8+48]
  mov     [r9+48], eax
  mov     eax, [rsp+84]
  xor     eax, [r8+4]
  mov     [r9+4], eax
  mov     eax, [rsp+88]
  xor     eax, [r8+24]
  mov     [r9+24], eax
  mov     eax, [rsp+92]
  xor     eax, [r8+44]
  mov     [r9+44], eax
  mov     eax, [rsp+96]
  xor     eax, [r8+32]
  mov     [r9+32], eax
  mov     eax, [rsp+100]
  xor     eax, [r8+52]
  mov     [r9+52], eax
  mov     eax, [rsp+104]
  xor     eax, [r8+8]
  mov     [r9+8], eax
  mov     eax, [rsp+108]
  xor     eax, [r8+28]
  mov     [r9+28], eax
  mov     eax, [rsp+112]
  xor     eax, [r8+16]
  mov     [r9+16], eax
  mov     eax, [rsp+116]
  xor     eax, [r8+36]
  mov     [r9+36], eax
  mov     eax, [rsp+120]
  xor     eax, [r8+56]
  mov     [r9+56], eax
  mov     eax, [rsp+124]
  xor     eax, [r8+12]
  mov     [r9+12], eax
{ AdvanceCounter: Inc(state[8]); if 0 then Inc(state[9]) }
  add     dword [rdx+32], 1
  jnz     @@s2p2s2_x64_c1d
  add     dword [rdx+36], 1
@@s2p2s2_x64_c1d:
{ -------- block 2 (64B) at I/O offset 64, counter already advanced -------- }
  mov     r10, rcx
  mov     eax, [rdx+0]
  mov     [rsp+0], eax
  mov     eax, [rdx+20]
  mov     [rsp+4], eax
  mov     eax, [rdx+40]
  mov     [rsp+8], eax
  mov     eax, [rdx+60]
  mov     [rsp+12], eax
  mov     eax, [rdx+48]
  mov     [rsp+16], eax
  mov     eax, [rdx+4]
  mov     [rsp+20], eax
  mov     eax, [rdx+24]
  mov     [rsp+24], eax
  mov     eax, [rdx+44]
  mov     [rsp+28], eax
  mov     eax, [rdx+32]
  mov     [rsp+32], eax
  mov     eax, [rdx+52]
  mov     [rsp+36], eax
  mov     eax, [rdx+8]
  mov     [rsp+40], eax
  mov     eax, [rdx+28]
  mov     [rsp+44], eax
  mov     eax, [rdx+16]
  mov     [rsp+48], eax
  mov     eax, [rdx+36]
  mov     [rsp+52], eax
  mov     eax, [rdx+56]
  mov     [rsp+56], eax
  mov     eax, [rdx+12]
  mov     [rsp+60], eax
  movdqu  xmm0, [rsp+0]
  movdqu  xmm1, [rsp+16]
  movdqu  xmm2, [rsp+32]
  movdqu  xmm3, [rsp+48]
@@s2p2s2_x64_b2r:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse2_TwoColumnRoundsBody.inc}
  sub     r10, 2
  jg      @@s2p2s2_x64_b2r
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  movdqu  [rsp+64], xmm0
  movdqu  [rsp+80], xmm1
  movdqu  [rsp+96], xmm2
  movdqu  [rsp+112], xmm3
  mov     eax, [rsp+64]
  xor     eax, [r8+64]
  mov     [r9+64], eax
  mov     eax, [rsp+68]
  xor     eax, [r8+84]
  mov     [r9+84], eax
  mov     eax, [rsp+72]
  xor     eax, [r8+104]
  mov     [r9+104], eax
  mov     eax, [rsp+76]
  xor     eax, [r8+124]
  mov     [r9+124], eax
  mov     eax, [rsp+80]
  xor     eax, [r8+112]
  mov     [r9+112], eax
  mov     eax, [rsp+84]
  xor     eax, [r8+68]
  mov     [r9+68], eax
  mov     eax, [rsp+88]
  xor     eax, [r8+88]
  mov     [r9+88], eax
  mov     eax, [rsp+92]
  xor     eax, [r8+108]
  mov     [r9+108], eax
  mov     eax, [rsp+96]
  xor     eax, [r8+96]
  mov     [r9+96], eax
  mov     eax, [rsp+100]
  xor     eax, [r8+116]
  mov     [r9+116], eax
  mov     eax, [rsp+104]
  xor     eax, [r8+72]
  mov     [r9+72], eax
  mov     eax, [rsp+108]
  xor     eax, [r8+92]
  mov     [r9+92], eax
  mov     eax, [rsp+112]
  xor     eax, [r8+80]
  mov     [r9+80], eax
  mov     eax, [rsp+116]
  xor     eax, [r8+100]
  mov     [r9+100], eax
  mov     eax, [rsp+120]
  xor     eax, [r8+120]
  mov     [r9+120], eax
  mov     eax, [rsp+124]
  xor     eax, [r8+76]
  mov     [r9+76], eax
  add     dword [rdx+32], 1
  jnz     @@s2p2s2_x64_c2d
  add     dword [rdx+36], 1
@@s2p2s2_x64_c2d:
  add     rsp, 512
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
