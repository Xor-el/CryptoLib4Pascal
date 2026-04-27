// ChaCha20 one 64B block, SSE2, x86-64. Little-endian state in, 64B keystream out to AOut (keystream-only path, not ChaCha7539 fused I/O xor).
// Rounds: ChaChaSse2_DoubleRoundBody.inc. 64B stack copy of state; add initial state; store block to AOut.
// After SimdProc3Begin_x86_64.inc: rcx=ARounds, rdx=AIn (16 UInt32 state), r8=AOut (64B output).
  sub     rsp, 64
  movdqu  xmm0, [rdx+0]
  movdqu  xmm1, [rdx+16]
  movdqu  xmm2, [rdx+32]
  movdqu  xmm3, [rdx+48]
  movdqu  [rsp], xmm0
  movdqu  [rsp+16], xmm1
  movdqu  [rsp+32], xmm2
  movdqu  [rsp+48], xmm3
@@chacha20_sse2_x64_round:
{$I ..\..\Include\Simd\ChaCha\ChaChaSse2_DoubleRoundBody.inc}
  sub     rcx, 2
  jg      @@chacha20_sse2_x64_round
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  add     rsp, 64
  movdqu  [r8+0], xmm0
  movdqu  [r8+16], xmm1
  movdqu  [r8+32], xmm2
  movdqu  [r8+48], xmm3
