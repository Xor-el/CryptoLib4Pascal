// AES-NI 8-wide cipher aggregator, out-of-place, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
// Thin wrapper over AesNiEightRoundsOnly_x86_64.inc. Entry (after
// SimdProc3Begin_x86_64.inc):
//   rcx = RIn (8 consecutive 16-byte input blocks)
//   rdx = ROut (8 consecutive 16-byte output buffer)
//   r8  = Keys (expanded round-key schedule)
// r8 is already the canonical rounds-only register, so the rounds run
// directly - no register move needed.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> decrypt; else encrypt.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
// Both defines are forwarded verbatim to the rounds-only include.
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
