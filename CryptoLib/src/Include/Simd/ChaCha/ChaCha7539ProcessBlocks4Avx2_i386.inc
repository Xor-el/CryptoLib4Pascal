// ChaCha7539 (IETF) 256B, AVX2, i386. Two 128B blocks: same fused I/O xor as ProcessBlocks2 (AIn=edi, AOut=eax).
// One vzeroupper; add edi/eax,+128 between blocks. LoadState .inc reloads IETF state at [esi] (word 12 already advanced after block 1).
// After SimdProc4Begin_i386.inc: ebx=ARounds, esi=AState, edi=AIn, eax=AOut.
  mov     edx, ebx
  // --- first 128B ---
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_LoadState_i386.inc}
  @@c7539_avx2_i386_pb4_b1:
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_DoubleRound.inc}
  sub     edx, 2
  jg      @@c7539_avx2_i386_pb4_b1
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_XorStore_i386.inc}
  db $81, $C4, $C8, $00, $00, $00  // add esp, 0xc8
  add     edi, 128
  add     eax, 128
  mov     edx, ebx
  // --- second 128B (IETF state at [esi+48] is already advanced) ---
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_LoadState_i386.inc}
  @@c7539_avx2_i386_pb4_b2:
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_DoubleRound.inc}
  sub     edx, 2
  jg      @@c7539_avx2_i386_pb4_b2
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_XorStore_i386.inc}
  db $81, $C4, $C8, $00, $00, $00  // add esp, 0xc8
  db $C5, $F8, $77                 // vzeroupper
  pop     edi
  pop     esi
  pop     ebx
