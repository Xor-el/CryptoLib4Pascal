// ChaCha7539 (IETF) 256B, AVX2. Two 128B blocks: same fused I/O xor as ProcessBlocks2 (AIn=r8, AOut=r9; no large keystream temp in Pascal).
// One vzeroupper; add r8/r9,+128 between blocks. LoadState .inc reloads IETF state at [rdx] (word 12 already advanced after block 1).
// After SimdProc4Begin_x86_64.inc: rcx=ARounds, rdx=AState, r8=AIn, r9=AOut.
  mov     r10, rcx
  // --- first 128B ---
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_LoadState_x86_64.inc}
  @@c7539_avx2_pb4_b1:
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_DoubleRound_x86_64.inc}
  sub     r10, 2
  jg      @@c7539_avx2_pb4_b1
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_XorStore_x86_64.inc}
  db $48, $81, $C4, $C8, $00, $00, $00  // add rsp, 0xc8
  add     r8, 128
  add     r9, 128
  mov     r10, rcx
  // --- second 128B (IETF state at [rdx+48] is already advanced) ---
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_LoadState_x86_64.inc}
  @@c7539_avx2_pb4_b2:
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_DoubleRound_x86_64.inc}
  sub     r10, 2
  jg      @@c7539_avx2_pb4_b2
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_XorStore_x86_64.inc}
  db $48, $81, $C4, $C8, $00, $00, $00  // add rsp, 0xc8
  db $C5, $F8, $77                      // vzeroupper
