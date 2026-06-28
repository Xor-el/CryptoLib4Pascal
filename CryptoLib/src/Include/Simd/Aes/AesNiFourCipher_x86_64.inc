// AES-NI 4-wide cipher wrapper, merged in-place + out-of-place, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
//
// Thin load/store shell over AesNiFourRoundsOnly_x86_64.inc, operating on
// 4 consecutive 16-byte blocks.
//
// Mode selection:
//   CRYPTOLIB_AESNI_INOUT defined  -> out-of-place (read RIn, write ROut).
//   undefined                      -> in-place (read/write state).
// In-place (SimdProc2Begin): rcx = state, rdx = keys.
// Out-of-place (SimdProc3Begin, CRYPTOLIB_AESNI_INOUT): rcx = RIn, rdx = ROut, r8 = keys.
//
// In-place must move the keys pointer into the canonical rounds-only
// register (mov r8, rdx); out-of-place already has keys in r8.
//
// Variant selection (forwarded to the rounds-only include):
//   CRYPTOLIB_AESNI_DECRYPT  -> decrypt; else encrypt.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
{$IFNDEF CRYPTOLIB_AESNI_INOUT}
  mov       r8, rdx
{$ENDIF}
{$I ..\..\Include\Simd\Aes\AesNiFourRoundsOnly_x86_64.inc}
{$IFDEF CRYPTOLIB_AESNI_INOUT}
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
{$ELSE}
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
{$ENDIF}
