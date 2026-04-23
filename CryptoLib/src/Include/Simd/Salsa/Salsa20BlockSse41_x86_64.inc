// Salsa20 one 16*UInt32 block: LE state in, LE state+input out, SSE4.1 (pblendw) + SSSE3 (pshufd) + SSE2.
// 4-lane quarter rounds; UInt16 interleave and pack/unpack via pblendw.
// After SimdProc3Begin_x86_64.inc: rcx = ARounds, rdx = AIn (16 UInt32), r8 = AOut (16 UInt32).
  sub     rsp, 512
  mov     r9, rcx
{ -- expand 4*4 dwords to 4*8 u16 in [rsp+0] }
{ row 0: rdx+0; dest rsp+0 }
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
{ row 1: rdx+16, rsp+16 }
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
{ row 2: rdx+32, rsp+32 }
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
{ row 3: rdx+48, rsp+48 }
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
{ t0..t3 }
  movdqu  xmm0, [rsp+0]
  movdqu  xmm1, [rsp+16]
  movdqu  xmm2, [rsp+32]
  movdqu  xmm3, [rsp+48]
{ pack -> b0..b3 in xmm0..3 }
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
{ save b0..3 }
  movdqu  [rsp+64], xmm0
  movdqu  [rsp+80], xmm1
  movdqu  [rsp+96], xmm2
  movdqu  [rsp+112], xmm3
{ c := b }
{ rounds }
@@salsa20_sse41_x64_rd:
  movdqa  xmm4, xmm1
  movdqa  xmm1, xmm3
  movdqa  xmm3, xmm4
{ SalsaQ }
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
{ swap1,3 again }
  movdqa  xmm4, xmm1
  movdqa  xmm1, xmm3
  movdqa  xmm3, xmm4
{ SalsaQ 2 }
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
  sub     r9, 2
  jg      @@salsa20_sse41_x64_rd
{ c += b (saved) }
  movdqu  xmm4, [rsp+64]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+80]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+96]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+112]
  paddd   xmm3, xmm4
{ save c to [rsp+192] }
  movdqu  [rsp+192], xmm0
  movdqu  [rsp+208], xmm1
  movdqu  [rsp+224], xmm2
  movdqu  [rsp+240], xmm3
{ unpack }
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
{ 16* LE UInt32 to r8 }
  mov     eax, [rsp+256]
  mov     [r8+0], eax
  mov     eax, [rsp+260]
  mov     [r8+4], eax
  mov     eax, [rsp+264]
  mov     [r8+8], eax
  mov     eax, [rsp+268]
  mov     [r8+12], eax
  mov     eax, [rsp+272]
  mov     [r8+16], eax
  mov     eax, [rsp+276]
  mov     [r8+20], eax
  mov     eax, [rsp+280]
  mov     [r8+24], eax
  mov     eax, [rsp+284]
  mov     [r8+28], eax
  mov     eax, [rsp+288]
  mov     [r8+32], eax
  mov     eax, [rsp+292]
  mov     [r8+36], eax
  mov     eax, [rsp+296]
  mov     [r8+40], eax
  mov     eax, [rsp+300]
  mov     [r8+44], eax
  mov     eax, [rsp+304]
  mov     [r8+48], eax
  mov     eax, [rsp+308]
  mov     [r8+52], eax
  mov     eax, [rsp+312]
  mov     [r8+56], eax
  mov     eax, [rsp+316]
  mov     [r8+60], eax
  add     rsp, 512
