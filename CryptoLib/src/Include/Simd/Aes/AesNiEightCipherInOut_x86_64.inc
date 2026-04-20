// AES-NI 8-wide cipher aggregator, out-of-place, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
// Thin wrapper over AesNiEightRoundsOnly_x86_64.inc. This file is
// included from procedures prologue'd by SimdProc3Begin_x86_64.inc,
// so on entry:
//   rcx = RIn  (8 consecutive 16-byte input blocks)
//   rdx = ROut (8 consecutive 16-byte output buffer)
//   r8  = Keys (expanded round-key schedule)
// r8 is already the canonical rounds-only register, so no register
// move is needed -- the rounds run directly.
// Direction is selected by CRYPTOLIB_AESNI_DECRYPT; key size by
// exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256. Both
// defines are forwarded verbatim to the rounds-only include.
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
{$I ..\..\Include\Simd\Aes\AesNiEightRoundsOnly_x86_64.inc}
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
