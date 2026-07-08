// Salsa20 one 16*UInt32 block: LE state in, LE state+input out, pure SSE2.
// The 4-lane quarter round works on the diagonal layout
//   b0=[s0,s5,s10,s15] b1=[s12,s1,s6,s11] b2=[s8,s13,s2,s7] b3=[s4,s9,s14,s3].
// SSE2 has no pblendw, so the diagonal transpose is a direct scalar gather on
// the way in and the inverse scatter on the way out (dword granular, no masks).
// Rounds: Salsa20Sse2_TwoColumnRoundsBody.inc (pure SSE2 body).
// After ClpSimdProc3Begin_x86_64.inc: rcx = ARounds, rdx = AIn (16 UInt32), r8 = AOut (16 UInt32).
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  sub     rsp, 512
  mov     r9, rcx
{ -- diagonal gather: b0..b3 into [rsp+0..63] -- }
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
{ rounds }
@@salsa20_sse2_x64_rd:
{$I ..\..\Include\Simd\Salsa\Salsa20Sse2_TwoColumnRoundsBody.inc}
  sub     r9, 2
  jg      @@salsa20_sse2_x64_rd
{ c += b (initial diagonal state, still in [rsp+0..63]) }
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
{ -- inverse diagonal scatter: lanes -> natural state at r8 -- }
  movdqu  [rsp+64], xmm0
  movdqu  [rsp+80], xmm1
  movdqu  [rsp+96], xmm2
  movdqu  [rsp+112], xmm3
  mov     eax, [rsp+64]
  mov     [r8+0], eax
  mov     eax, [rsp+68]
  mov     [r8+20], eax
  mov     eax, [rsp+72]
  mov     [r8+40], eax
  mov     eax, [rsp+76]
  mov     [r8+60], eax
  mov     eax, [rsp+80]
  mov     [r8+48], eax
  mov     eax, [rsp+84]
  mov     [r8+4], eax
  mov     eax, [rsp+88]
  mov     [r8+24], eax
  mov     eax, [rsp+92]
  mov     [r8+44], eax
  mov     eax, [rsp+96]
  mov     [r8+32], eax
  mov     eax, [rsp+100]
  mov     [r8+52], eax
  mov     eax, [rsp+104]
  mov     [r8+8], eax
  mov     eax, [rsp+108]
  mov     [r8+28], eax
  mov     eax, [rsp+112]
  mov     [r8+16], eax
  mov     eax, [rsp+116]
  mov     [r8+36], eax
  mov     eax, [rsp+120]
  mov     [r8+56], eax
  mov     eax, [rsp+124]
  mov     [r8+12], eax
  add     rsp, 512
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
