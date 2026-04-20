// AesNiEightCipher i386 aggregator (in-place, merged Enc + Dec,
// merged key sizes).
// -------------------------------------------------------------------
// Thin wrapper over AesNiEightRoundsOnly_i386.inc. This file is
// included from procedures prologue'd by SimdProc2Begin_i386.inc, so
// on entry (after the prologue has pushed ebx/esi and remapped):
//   ebx = state pointer (8 consecutive 16-byte blocks)
//   esi = keys  pointer (expanded round-key schedule)
// The rounds-only include expects the keys pointer in edi (its
// canonical register, shared with every fused AEAD kernel in Phase
// 1-4). edi is callee-saved on FPC i386 and the shared 2-param
// prologue does NOT push it, so we push/pop it here locally.
// Direction is selected by CRYPTOLIB_AESNI_DECRYPT; key size by
// exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256. Both
// defines are forwarded verbatim to the rounds-only include.
// Epilogue mirrors the prologue: pop esi then pop ebx before return.
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
