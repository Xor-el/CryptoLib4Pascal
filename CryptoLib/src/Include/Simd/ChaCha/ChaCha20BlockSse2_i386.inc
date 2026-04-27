// ChaCha20 one 64B block, SSE2, i386. Keystream only: state in, 64B out to AOut (not ChaCha7539 fused I/O xor). Rounds: ChaChaSse2_DoubleRoundBody.inc.
// After SimdProc3Begin_i386.inc: ebx=ARounds, esi=AIn, edi=AOut. End: add esp, 64; add esp, eax; pop edi; pop esi; pop ebx
  mov     eax, esp
  and     eax, 15
  sub     esp, eax
  sub     esp, 64
  movdqu  xmm0, [esi+0]
  movdqu  xmm1, [esi+16]
  movdqu  xmm2, [esi+32]
  movdqu  xmm3, [esi+48]
  movdqu  [esp], xmm0
  movdqu  [esp+16], xmm1
  movdqu  [esp+32], xmm2
  movdqu  [esp+48], xmm3
@@chacha20_sse2_i386_round:
{$I ..\..\Include\Simd\ChaCha\ChaChaSse2_DoubleRoundBody.inc}
  sub     ebx, 2
  jg      @@chacha20_sse2_i386_round
  movdqu  xmm4, [esp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+48]
  paddd   xmm3, xmm4
  add     esp, 64
  add     esp, eax
  movdqu  [edi+0], xmm0
  movdqu  [edi+16], xmm1
  movdqu  [edi+32], xmm2
  movdqu  [edi+48], xmm3
  pop     edi
  pop     esi
  pop     ebx
