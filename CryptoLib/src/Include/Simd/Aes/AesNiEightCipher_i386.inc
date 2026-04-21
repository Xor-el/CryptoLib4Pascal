// AES-NI 8-wide cipher aggregator, in-place, merged Enc + Dec, merged key sizes (i386).
// -------------------------------------------------------------------
// Thin wrapper over AesNiEightRoundsOnly_i386.inc. Entry (after
// SimdProc2Begin_i386.inc has pushed ebx/esi and remapped):
//   ebx = state (8 consecutive 16-byte blocks)
//   esi = keys (expanded round-key schedule)
// The rounds-only include takes its keys pointer in edi (its canonical
// register, shared with every fused AEAD kernel). edi is callee-saved
// and the shared 2-param prologue does NOT push it, so we push/pop it
// here locally. Epilogue pops esi then ebx before return.
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
  push      edi
  mov       edi, esi
{$I ..\..\Include\Simd\Aes\AesNiEightRoundsOnly_i386.inc}
  pop       edi
  movdqu    [ebx + 0], xmm0
  movdqu    [ebx + 16], xmm1
  movdqu    [ebx + 32], xmm2
  movdqu    [ebx + 48], xmm3
  movdqu    [ebx + 64], xmm4
  movdqu    [ebx + 80], xmm5
  movdqu    [ebx + 96], xmm6
  movdqu    [ebx + 112], xmm7
  pop       esi
  pop       ebx
