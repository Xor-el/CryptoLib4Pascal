// ChaCha7539 (IETF) 128B, SSE2, i386. Two 64B blocks; little-endian state in [esi]. Rounds: ChaChaSse2_DoubleRoundBody.inc.
// Fused I/O xor: read plaintext at AIn (edi), xor with ChaCha output, write to AOut (eax) — no 64B LK/keystream temp in Pascal.
// After SimdProc4Begin_i386.inc: ebx=ARounds, esi=AState (R/W), edi=AIn, eax=AOut.
// ecx: 16B stack realign before each 64B round scratch. edx: copy of ARounds between blocks. Word 12 at [esi+48] +2 per 64B block; wrap 0 -> ChaCha7539RaiseCounter7539.
  mov     edx, ebx
  // --- block 1 (counter C in memory) ---
  mov     ecx, esp
  and     ecx, 15
  sub     esp, ecx
  sub     esp, 64
  movdqu  xmm0, [esi+0]
  movdqu  xmm1, [esi+16]
  movdqu  xmm2, [esi+32]
  movdqu  xmm3, [esi+48]
  movdqu  [esp], xmm0
  movdqu  [esp+16], xmm1
  movdqu  [esp+32], xmm2
  movdqu  [esp+48], xmm3
  mov     ebx, edx
@@c53ib1r:
{$I ..\..\Include\Simd\ChaCha\ChaChaSse2_DoubleRoundBody.inc}
  sub     ebx, 2
  jg      @@c53ib1r
  movdqu  xmm4, [esp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+48]
  paddd   xmm3, xmm4
  add     esp, 64
  add     esp, ecx
  movdqu  xmm4, [edi+0]
  pxor    xmm0, xmm4
  movdqu  [eax+0], xmm0
  movdqu  xmm4, [edi+16]
  pxor    xmm1, xmm4
  movdqu  [eax+16], xmm1
  movdqu  xmm4, [edi+32]
  pxor    xmm2, xmm4
  movdqu  [eax+32], xmm2
  movdqu  xmm4, [edi+48]
  pxor    xmm3, xmm4
  movdqu  [eax+48], xmm3
  add     dword [esi+48], 1
  jz      @@c53ibad
  // --- block 2 (counter C+1 in memory) ---
  mov     ecx, esp
  and     ecx, 15
  sub     esp, ecx
  sub     esp, 64
  movdqu  xmm0, [esi+0]
  movdqu  xmm1, [esi+16]
  movdqu  xmm2, [esi+32]
  movdqu  xmm3, [esi+48]
  movdqu  [esp], xmm0
  movdqu  [esp+16], xmm1
  movdqu  [esp+32], xmm2
  movdqu  [esp+48], xmm3
  mov     ebx, edx
@@c53ib2r:
{$I ..\..\Include\Simd\ChaCha\ChaChaSse2_DoubleRoundBody.inc}
  sub     ebx, 2
  jg      @@c53ib2r
  movdqu  xmm4, [esp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [esp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [esp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [esp+48]
  paddd   xmm3, xmm4
  add     esp, 64
  add     esp, ecx
  movdqu  xmm4, [edi+64]
  pxor    xmm0, xmm4
  movdqu  [eax+64], xmm0
  movdqu  xmm4, [edi+80]
  pxor    xmm1, xmm4
  movdqu  [eax+80], xmm1
  movdqu  xmm4, [edi+96]
  pxor    xmm2, xmm4
  movdqu  [eax+96], xmm2
  movdqu  xmm4, [edi+112]
  pxor    xmm3, xmm4
  movdqu  [eax+112], xmm3
  add     dword [esi+48], 1
  jz      @@c53ibad
  jmp     @@c53idone
@@c53ibad:
  call    ChaCha7539RaiseCounter7539
@@c53idone:
  pop     edi
  pop     esi
  pop     ebx
