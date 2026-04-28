// ChaCha7539 (IETF) 128B, AVX2, i386. Little-endian state in [esi]; two 32-bit block counters in YMM lanes.
// Fused I/O xor: read plaintext at AIn (edi), xor with ChaCha output, write to AOut (eax).
// Fragments: ChaCha7539_Avx2_128B_LoadState_i386, ChaCha7539_Avx2_DoubleRound.inc, ChaCha7539_Avx2_128B_XorStore_i386
// After SimdProc4Begin_i386.inc: ebx=ARounds, esi=AState, edi=AIn, eax=AOut.
  mov     edx, ebx
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_LoadState_i386.inc}
  @@chacha7539_avx2_i386_pb2:
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_DoubleRound.inc}
  sub     edx, 2
  jg      @@chacha7539_avx2_i386_pb2
{$I ..\..\Include\Simd\ChaCha\ChaCha7539_Avx2_128B_XorStore_i386.inc}
  db $81, $C4, $C8, $00, $00, $00  // add esp, 0xc8
  db $C5, $F8, $77                 // vzeroupper
  pop     edi
  pop     esi
  pop     ebx
