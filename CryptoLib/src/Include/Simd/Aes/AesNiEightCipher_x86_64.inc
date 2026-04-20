// AES-NI 8-wide cipher aggregator, in-place, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
// Thin wrapper over AesNiEightRoundsOnly_x86_64.inc. This file is
// included from procedures prologue'd by SimdProc2Begin_x86_64.inc, so
// on entry:
//   rcx = state pointer (8 consecutive 16-byte blocks)
//   rdx = keys  pointer (expanded round-key schedule)
// The rounds-only include expects the keys pointer in r8 (its canonical
// register, shared with every fused AEAD kernel in Phase 1-4). r8 is a
// volatile scratch on both Win64 and Unix, so a single `mov r8, rdx`
// is enough -- no push/pop needed.
// Direction is selected by CRYPTOLIB_AESNI_DECRYPT; key size by exactly
// one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256. Both defines are
// forwarded verbatim to the rounds-only include.
//
// Nested {$I} path: Delphi resolves nested includes relative to the
// top-level .pas (ClpAesEngineX86.pas in Crypto\Engines\), not to the
// enclosing .inc, so a bare 'AesNiEightRoundsOnly_x86_64.inc' raises
// F1026 under dcc. Using '..\..\Include\Simd\Aes\' keeps both Delphi
// and FPC happy (FPC also accepts the path and resolves to the same
// absolute file).
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqu    xmm4, [rcx + 64]
  movdqu    xmm5, [rcx + 80]
  movdqu    xmm6, [rcx + 96]
  movdqu    xmm7, [rcx + 112]
  mov       r8, rdx
{$I ..\..\Include\Simd\Aes\AesNiEightRoundsOnly_x86_64.inc}
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  movdqu    [rcx + 64], xmm4
  movdqu    [rcx + 80], xmm5
  movdqu    [rcx + 96], xmm6
  movdqu    [rcx + 112], xmm7
