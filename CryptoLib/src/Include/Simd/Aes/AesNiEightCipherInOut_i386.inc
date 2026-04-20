// AesNiEightCipherInOut i386 aggregator (out-of-place, merged Enc +
// Dec, merged key sizes).
// -------------------------------------------------------------------
// Thin wrapper over AesNiEightRoundsOnly_i386.inc. This file is
// included from procedures prologue'd by SimdProc3Begin_i386.inc, so
// on entry (after the prologue has pushed ebx/esi/edi and remapped):
//   ebx = RIn  (8 consecutive 16-byte input blocks)
//   esi = ROut (8 consecutive 16-byte output buffer)
//   edi = Keys (expanded round-key schedule)
// edi is already the canonical rounds-only register, so no register
// move is needed -- the rounds run directly.
// Direction is selected by CRYPTOLIB_AESNI_DECRYPT; key size by
// exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256. Both
// defines are forwarded verbatim to the rounds-only include.
// Epilogue mirrors the 3-param prologue: pop edi, pop esi, pop ebx
// before return.
//
// Nested {$I} path: Delphi resolves nested includes relative to the
// top-level .pas (ClpAesEngineX86.pas in Crypto\Engines\), not to the
// enclosing .inc, so a bare 'AesNiEightRoundsOnly_i386.inc' raises
// F1026 under dcc. Using '..\..\Include\Simd\Aes\' keeps both Delphi
// and FPC happy (FPC also accepts the path and resolves to the same
// absolute file).
  movdqu    xmm0, [ebx + 0]
  movdqu    xmm1, [ebx + 16]
  movdqu    xmm2, [ebx + 32]
  movdqu    xmm3, [ebx + 48]
  movdqu    xmm4, [ebx + 64]
  movdqu    xmm5, [ebx + 80]
  movdqu    xmm6, [ebx + 96]
  movdqu    xmm7, [ebx + 112]
{$I ..\..\Include\Simd\Aes\AesNiEightRoundsOnly_i386.inc}
  movdqu    [esi + 0], xmm0
  movdqu    [esi + 16], xmm1
  movdqu    [esi + 32], xmm2
  movdqu    [esi + 48], xmm3
  movdqu    [esi + 64], xmm4
  movdqu    [esi + 80], xmm5
  movdqu    [esi + 96], xmm6
  movdqu    [esi + 112], xmm7
  pop       edi
  pop       esi
  pop       ebx
