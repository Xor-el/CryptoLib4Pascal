// Salsa20 128B, SSE4.1: two 64B blocks, fused I/O (xor) like ChaCha7539ProcessBlocks2Sse2.
// After SimdProc4Begin_x86_64.inc: rcx=ARounds, rdx=AState, r8=AIn (plain), r9=AOut (cipher).
// r10 = round counter per block. Advance counter: FEngineState[8]@[rdx+32], FEngineState[9]@[rdx+36].
{ -------- block 1 (64B) -------- }
  sub     rsp, 512
  mov     r10, rcx
{ -- expand: state in rdx -- }
  mov     eax, [rdx+0]
  mov     word ptr [rsp+0], ax
  shr     eax, 16
  mov     word ptr [rsp+2], ax
  mov     eax, [rdx+4]
  mov     word ptr [rsp+4], ax
  shr     eax, 16
  mov     word ptr [rsp+6], ax
  mov     eax, [rdx+8]
  mov     word ptr [rsp+8], ax
  shr     eax, 16
  mov     word ptr [rsp+10], ax
  mov     eax, [rdx+12]
  mov     word ptr [rsp+12], ax
  shr     eax, 16
  mov     word ptr [rsp+14], ax
  mov     eax, [rdx+16]
  mov     word ptr [rsp+16], ax
  shr     eax, 16
  mov     word ptr [rsp+18], ax
  mov     eax, [rdx+20]
  mov     word ptr [rsp+20], ax
  shr     eax, 16
  mov     word ptr [rsp+22], ax
  mov     eax, [rdx+24]
  mov     word ptr [rsp+24], ax
  shr     eax, 16
  mov     word ptr [rsp+26], ax
  mov     eax, [rdx+28]
  mov     word ptr [rsp+28], ax
  shr     eax, 16
  mov     word ptr [rsp+30], ax
  mov     eax, [rdx+32]
  mov     word ptr [rsp+32], ax
  shr     eax, 16
  mov     word ptr [rsp+34], ax
  mov     eax, [rdx+36]
  mov     word ptr [rsp+36], ax
  shr     eax, 16
  mov     word ptr [rsp+38], ax
  mov     eax, [rdx+40]
  mov     word ptr [rsp+40], ax
  shr     eax, 16
  mov     word ptr [rsp+42], ax
  mov     eax, [rdx+44]
  mov     word ptr [rsp+44], ax
  shr     eax, 16
  mov     word ptr [rsp+46], ax
  mov     eax, [rdx+48]
  mov     word ptr [rsp+48], ax
  shr     eax, 16
  mov     word ptr [rsp+50], ax
  mov     eax, [rdx+52]
  mov     word ptr [rsp+52], ax
  shr     eax, 16
  mov     word ptr [rsp+54], ax
  mov     eax, [rdx+56]
  mov     word ptr [rsp+56], ax
  shr     eax, 16
  mov     word ptr [rsp+58], ax
  mov     eax, [rdx+60]
  mov     word ptr [rsp+60], ax
  shr     eax, 16
  mov     word ptr [rsp+62], ax
  movdqu  xmm0, [rsp+0]
  movdqu  xmm1, [rsp+16]
  movdqu  xmm2, [rsp+32]
  movdqu  xmm3, [rsp+48]
{ pack -> b0..b3 }
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
  movdqu  [rsp+64], xmm0
  movdqu  [rsp+80], xmm1
  movdqu  [rsp+96], xmm2
  movdqu  [rsp+112], xmm3
@@s2p2_x64_b1r:
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
  sub     r10, 2
  jg      @@s2p2_x64_b1r
  movdqu  xmm4, [rsp+64]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+80]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+96]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+112]
  paddd   xmm3, xmm4
  movdqu  [rsp+192], xmm0
  movdqu  [rsp+208], xmm1
  movdqu  [rsp+224], xmm2
  movdqu  [rsp+240], xmm3
  movdqu  xmm0, [rsp+192]
  movdqu  xmm1, [rsp+208]
  movdqu  xmm2, [rsp+224]
  movdqu  xmm3, [rsp+240]
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
  movdqu  [rsp+256], xmm0
  movdqu  [rsp+272], xmm1
  movdqu  [rsp+288], xmm2
  movdqu  [rsp+304], xmm3
{ xor with plain at r8, out at r9 }
  mov     eax, [rsp+256]
  mov     r10d, [r8+0]
  xor     eax, r10d
  mov     [r9+0], eax
  mov     eax, [rsp+260]
  mov     r10d, [r8+4]
  xor     eax, r10d
  mov     [r9+4], eax
  mov     eax, [rsp+264]
  mov     r10d, [r8+8]
  xor     eax, r10d
  mov     [r9+8], eax
  mov     eax, [rsp+268]
  mov     r10d, [r8+12]
  xor     eax, r10d
  mov     [r9+12], eax
  mov     eax, [rsp+272]
  mov     r10d, [r8+16]
  xor     eax, r10d
  mov     [r9+16], eax
  mov     eax, [rsp+276]
  mov     r10d, [r8+20]
  xor     eax, r10d
  mov     [r9+20], eax
  mov     eax, [rsp+280]
  mov     r10d, [r8+24]
  xor     eax, r10d
  mov     [r9+24], eax
  mov     eax, [rsp+284]
  mov     r10d, [r8+28]
  xor     eax, r10d
  mov     [r9+28], eax
  mov     eax, [rsp+288]
  mov     r10d, [r8+32]
  xor     eax, r10d
  mov     [r9+32], eax
  mov     eax, [rsp+292]
  mov     r10d, [r8+36]
  xor     eax, r10d
  mov     [r9+36], eax
  mov     eax, [rsp+296]
  mov     r10d, [r8+40]
  xor     eax, r10d
  mov     [r9+40], eax
  mov     eax, [rsp+300]
  mov     r10d, [r8+44]
  xor     eax, r10d
  mov     [r9+44], eax
  mov     eax, [rsp+304]
  mov     r10d, [r8+48]
  xor     eax, r10d
  mov     [r9+48], eax
  mov     eax, [rsp+308]
  mov     r10d, [r8+52]
  xor     eax, r10d
  mov     [r9+52], eax
  mov     eax, [rsp+312]
  mov     r10d, [r8+56]
  xor     eax, r10d
  mov     [r9+56], eax
  mov     eax, [rsp+316]
  mov     r10d, [r8+60]
  xor     eax, r10d
  mov     [r9+60], eax
  add     rsp, 512
{ AdvanceCounter: Inc(state[8]); if 0 then Inc(state[9]) }
  add     dword [rdx+32], 1
  jnz     @@s2p2_x64_c1d
  add     dword [rdx+36], 1
@@s2p2_x64_c1d:
{ -------- block 2 (64B) at +64 I/O, same state in memory (counter updated) -------- }
  sub     rsp, 512
  mov     r10, rcx
  mov     eax, [rdx+0]
  mov     word ptr [rsp+0], ax
  shr     eax, 16
  mov     word ptr [rsp+2], ax
  mov     eax, [rdx+4]
  mov     word ptr [rsp+4], ax
  shr     eax, 16
  mov     word ptr [rsp+6], ax
  mov     eax, [rdx+8]
  mov     word ptr [rsp+8], ax
  shr     eax, 16
  mov     word ptr [rsp+10], ax
  mov     eax, [rdx+12]
  mov     word ptr [rsp+12], ax
  shr     eax, 16
  mov     word ptr [rsp+14], ax
  mov     eax, [rdx+16]
  mov     word ptr [rsp+16], ax
  shr     eax, 16
  mov     word ptr [rsp+18], ax
  mov     eax, [rdx+20]
  mov     word ptr [rsp+20], ax
  shr     eax, 16
  mov     word ptr [rsp+22], ax
  mov     eax, [rdx+24]
  mov     word ptr [rsp+24], ax
  shr     eax, 16
  mov     word ptr [rsp+26], ax
  mov     eax, [rdx+28]
  mov     word ptr [rsp+28], ax
  shr     eax, 16
  mov     word ptr [rsp+30], ax
  mov     eax, [rdx+32]
  mov     word ptr [rsp+32], ax
  shr     eax, 16
  mov     word ptr [rsp+34], ax
  mov     eax, [rdx+36]
  mov     word ptr [rsp+36], ax
  shr     eax, 16
  mov     word ptr [rsp+38], ax
  mov     eax, [rdx+40]
  mov     word ptr [rsp+40], ax
  shr     eax, 16
  mov     word ptr [rsp+42], ax
  mov     eax, [rdx+44]
  mov     word ptr [rsp+44], ax
  shr     eax, 16
  mov     word ptr [rsp+46], ax
  mov     eax, [rdx+48]
  mov     word ptr [rsp+48], ax
  shr     eax, 16
  mov     word ptr [rsp+50], ax
  mov     eax, [rdx+52]
  mov     word ptr [rsp+52], ax
  shr     eax, 16
  mov     word ptr [rsp+54], ax
  mov     eax, [rdx+56]
  mov     word ptr [rsp+56], ax
  shr     eax, 16
  mov     word ptr [rsp+58], ax
  mov     eax, [rdx+60]
  mov     word ptr [rsp+60], ax
  shr     eax, 16
  mov     word ptr [rsp+62], ax
  movdqu  xmm0, [rsp+0]
  movdqu  xmm1, [rsp+16]
  movdqu  xmm2, [rsp+32]
  movdqu  xmm3, [rsp+48]
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
  movdqu  [rsp+64], xmm0
  movdqu  [rsp+80], xmm1
  movdqu  [rsp+96], xmm2
  movdqu  [rsp+112], xmm3
@@s2p2_x64_b2r:
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
  sub     r10, 2
  jg      @@s2p2_x64_b2r
  movdqu  xmm4, [rsp+64]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+80]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+96]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+112]
  paddd   xmm3, xmm4
  movdqu  [rsp+192], xmm0
  movdqu  [rsp+208], xmm1
  movdqu  [rsp+224], xmm2
  movdqu  [rsp+240], xmm3
  movdqu  xmm0, [rsp+192]
  movdqu  xmm1, [rsp+208]
  movdqu  xmm2, [rsp+224]
  movdqu  xmm3, [rsp+240]
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
  movdqu  [rsp+256], xmm0
  movdqu  [rsp+272], xmm1
  movdqu  [rsp+288], xmm2
  movdqu  [rsp+304], xmm3
  mov     eax, [rsp+256]
  mov     r10d, [r8+64]
  xor     eax, r10d
  mov     [r9+64], eax
  mov     eax, [rsp+260]
  mov     r10d, [r8+68]
  xor     eax, r10d
  mov     [r9+68], eax
  mov     eax, [rsp+264]
  mov     r10d, [r8+72]
  xor     eax, r10d
  mov     [r9+72], eax
  mov     eax, [rsp+268]
  mov     r10d, [r8+76]
  xor     eax, r10d
  mov     [r9+76], eax
  mov     eax, [rsp+272]
  mov     r10d, [r8+80]
  xor     eax, r10d
  mov     [r9+80], eax
  mov     eax, [rsp+276]
  mov     r10d, [r8+84]
  xor     eax, r10d
  mov     [r9+84], eax
  mov     eax, [rsp+280]
  mov     r10d, [r8+88]
  xor     eax, r10d
  mov     [r9+88], eax
  mov     eax, [rsp+284]
  mov     r10d, [r8+92]
  xor     eax, r10d
  mov     [r9+92], eax
  mov     eax, [rsp+288]
  mov     r10d, [r8+96]
  xor     eax, r10d
  mov     [r9+96], eax
  mov     eax, [rsp+292]
  mov     r10d, [r8+100]
  xor     eax, r10d
  mov     [r9+100], eax
  mov     eax, [rsp+296]
  mov     r10d, [r8+104]
  xor     eax, r10d
  mov     [r9+104], eax
  mov     eax, [rsp+300]
  mov     r10d, [r8+108]
  xor     eax, r10d
  mov     [r9+108], eax
  mov     eax, [rsp+304]
  mov     r10d, [r8+112]
  xor     eax, r10d
  mov     [r9+112], eax
  mov     eax, [rsp+308]
  mov     r10d, [r8+116]
  xor     eax, r10d
  mov     [r9+116], eax
  mov     eax, [rsp+312]
  mov     r10d, [r8+120]
  xor     eax, r10d
  mov     [r9+120], eax
  mov     eax, [rsp+316]
  mov     r10d, [r8+124]
  xor     eax, r10d
  mov     [r9+124], eax
  add     rsp, 512
  add     dword [rdx+32], 1
  jnz     @@s2p2_x64_c2d
  add     dword [rdx+36], 1
@@s2p2_x64_c2d:
