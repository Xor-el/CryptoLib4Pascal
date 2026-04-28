// ChaCha7539 (IETF) 128B, AVX2. Little-endian state in [rdx]; two 32-bit block counters in YMM lanes.
// Fused I/O xor: read plaintext at AIn (r8), xor with ChaCha output, write to AOut (r9) — no 128B keystream temp in Pascal; xor in asm (XorStore) after rounds.
// Fragments: ChaCha7539_Avx2_128B_LoadState, ChaCha7539_Avx2_DoubleRound.inc (VEX db), ChaCha7539_Avx2_128B_XorStore .inc
// After SimdProc4Begin_x86_64.inc: rcx=ARounds, rdx=AState, r8=AIn, r9=AOut.
  mov     r10, rcx
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_LoadState_x86_64.inc}
  @@chacha7539_avx2_dround:
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_DoubleRound.inc}
  sub     r10, 2
  jg      @@chacha7539_avx2_dround
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_XorStore_x86_64.inc}
  db $48, $81, $C4, $C8, $00, $00, $00  // add rsp, 0xc8
  db $C5, $F8, $77                      // vzeroupper
