// ChaCha7539 (IETF) 128B, SSE2. Two 64B blocks; little-endian state in [rdx]. Rounds: ChaChaSse2_DoubleRoundBody.inc.
// Fused I/O xor: read plaintext at AIn (r8), xor with ChaCha output, write to AOut (r9) — no 64B LK/keystream temp in Pascal.
// After SimdProc4Begin_x86_64.inc: rcx=ARounds, rdx=AState (R/W, 16 UInt32), r8=AIn, r9=AOut.
// Word 12 at [rdx+48] is advanced by 2 (once per 64B block). On 32-bit counter wrap to 0, calls ChaCha7539RaiseCounter7539.
  mov     r11, rcx
  // --- block 1 (counter C in memory) ---
  sub     rsp, 64
  movdqu  xmm0, [rdx+0]
  movdqu  xmm1, [rdx+16]
  movdqu  xmm2, [rdx+32]
  movdqu  xmm3, [rdx+48]
  movdqu  [rsp], xmm0
  movdqu  [rsp+16], xmm1
  movdqu  [rsp+32], xmm2
  movdqu  [rsp+48], xmm3
  mov     r10, r11
@@c53b1r:
{$I ..\..\Include\Simd\ChaCha\ChaChaSse2_DoubleRoundBody.inc}
  sub     r10, 2
  jg      @@c53b1r
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  add     rsp, 64
  movdqu  xmm4, [r8+0]
  pxor    xmm0, xmm4
  movdqu  [r9+0], xmm0
  movdqu  xmm4, [r8+16]
  pxor    xmm1, xmm4
  movdqu  [r9+16], xmm1
  movdqu  xmm4, [r8+32]
  pxor    xmm2, xmm4
  movdqu  [r9+32], xmm2
  movdqu  xmm4, [r8+48]
  pxor    xmm3, xmm4
  movdqu  [r9+48], xmm3
  add     dword [rdx+48], 1
  jz      @@c53bad
  // --- block 2 (counter C+1 in memory) ---
  sub     rsp, 64
  movdqu  xmm0, [rdx+0]
  movdqu  xmm1, [rdx+16]
  movdqu  xmm2, [rdx+32]
  movdqu  xmm3, [rdx+48]
  movdqu  [rsp], xmm0
  movdqu  [rsp+16], xmm1
  movdqu  [rsp+32], xmm2
  movdqu  [rsp+48], xmm3
  mov     r10, r11
@@c53b2r:
{$I ..\..\Include\Simd\ChaCha\ChaChaSse2_DoubleRoundBody.inc}
  sub     r10, 2
  jg      @@c53b2r
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  add     rsp, 64
  movdqu  xmm4, [r8+64]
  pxor    xmm0, xmm4
  movdqu  [r9+64], xmm0
  movdqu  xmm4, [r8+80]
  pxor    xmm1, xmm4
  movdqu  [r9+80], xmm1
  movdqu  xmm4, [r8+96]
  pxor    xmm2, xmm4
  movdqu  [r9+96], xmm2
  movdqu  xmm4, [r8+112]
  pxor    xmm3, xmm4
  movdqu  [r9+112], xmm3
  add     dword [rdx+48], 1
  jz      @@c53bad
  jmp     @@c53done
@@c53bad:
  call    ChaCha7539RaiseCounter7539
@@c53done:
