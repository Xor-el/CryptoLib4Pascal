// AES-NI 8-wide cipher aggregator, out-of-place, merged Enc + Dec, merged key sizes (i386).
// -------------------------------------------------------------------
// Thin wrapper over AesNiEightRoundsOnly_i386.inc. Entry (after
// SimdProc3Begin_i386.inc has pushed ebx/esi/edi and remapped):
//   ebx = RIn (8 consecutive 16-byte input blocks)
//   esi = ROut (8 consecutive 16-byte output buffer)
//   edi = Keys (expanded round-key schedule)
// edi is already the canonical rounds-only register, so the rounds run
// directly - no register move needed. Epilogue pops edi, esi, ebx.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> decrypt; else encrypt.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
// Both defines are forwarded verbatim to the rounds-only include.
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
