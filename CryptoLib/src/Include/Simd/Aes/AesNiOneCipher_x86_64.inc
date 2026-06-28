// AES-NI 1-wide cipher wrapper, merged in-place + out-of-place, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
//
// Thin load/store shell over AesNiOneRoundsOnly_x86_64.inc, operating on
// a single 16-byte block.
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
{$IFNDEF CRYPTOLIB_AESNI_INOUT}
  mov       r8, rdx
{$ENDIF}
{$I ..\..\Include\Simd\Aes\AesNiOneRoundsOnly_x86_64.inc}
{$IFDEF CRYPTOLIB_AESNI_INOUT}
  movdqu    [rdx], xmm0
{$ELSE}
  movdqu    [rcx], xmm0
{$ENDIF}
