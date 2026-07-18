// AES CryptoExt (FEAT_AES) block-cipher kernel, merged widths 1 / 4 / 8,
// merged Enc + Dec, merged key sizes (aarch64).
// -------------------------------------------------------------------
//
// Out-of-place AES over 1, 4 or 8 consecutive 16-byte blocks; the width is
// selected per include site. In-place callers pass RIn = ROut; partial
// overlap is unsupported.
//
// Variant selection:
//   Exactly one of CRYPTOLIB_AESCRYPTOEXT_ONE / FOUR / EIGHT selects the width.
//   CRYPTOLIB_AESCRYPTOEXT_DECRYPT -> aesd / aesimc over the inverse schedule;
//                              else aese / aesmc.
//   Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128 / KEY192 / KEY256 selects N_R
//                              (10 / 12 / 14 rounds).
//
// Entry (after ClpSimdProc3Begin_aarch64.inc): x0 = RIn, x1 = ROut,
// x2 = expanded round-key schedule pointer; must match the direction
// (decrypt consumers pass the inverse-MixColumns schedule).
//
// Register map: v0..v7 data lanes, v16..v30 round keys; v8..v15 untouched
// (only d8..d15 are callee-saved under AAPCS64, so no save frame is needed).
// Each aese/aesd is immediately followed by its aesmc/aesimc on the same
// register - AES-capable cores fuse the pair; the final round key is applied
// with a plain eor (AArch64 has no *LAST forms).
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_ONE}
  .long 0x3dc00000                    // ldr q0, [x0]
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}

{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0x3dc0285a                    // ldr q26, [x2, #160]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0x3dc0305c                    // ldr q28, [x2, #192]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b40                    // aesd v0.16b, v26.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0xad46745c                    // ldp q28, q29, [x2, #192]
  .long 0x3dc0385e                    // ldr q30, [x2, #224]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b40                    // aesd v0.16b, v26.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b80                    // aesd v0.16b, v28.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ba0                    // aesd v0.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0x3dc0285a                    // ldr q26, [x2, #160]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0x3dc0305c                    // ldr q28, [x2, #192]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0xad46745c                    // ldp q28, q29, [x2, #192]
  .long 0x3dc0385e                    // ldr q30, [x2, #224]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
  .long 0x3d800020                    // str q0, [x1]
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_FOUR}
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x3dc00401                    // ldr q1, [x0, #16]
  .long 0x3dc00802                    // ldr q2, [x0, #32]
  .long 0x3dc00c03                    // ldr q3, [x0, #48]
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}

{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0x3dc0285a                    // ldr q26, [x2, #160]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a01                    // aesd v1.16b, v16.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a02                    // aesd v2.16b, v16.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a03                    // aesd v3.16b, v16.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a21                    // aesd v1.16b, v17.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a22                    // aesd v2.16b, v17.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a23                    // aesd v3.16b, v17.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a41                    // aesd v1.16b, v18.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a42                    // aesd v2.16b, v18.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a43                    // aesd v3.16b, v18.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a61                    // aesd v1.16b, v19.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a62                    // aesd v2.16b, v19.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a63                    // aesd v3.16b, v19.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a81                    // aesd v1.16b, v20.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a82                    // aesd v2.16b, v20.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a83                    // aesd v3.16b, v20.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa1                    // aesd v1.16b, v21.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285aa2                    // aesd v2.16b, v21.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285aa3                    // aesd v3.16b, v21.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac1                    // aesd v1.16b, v22.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ac2                    // aesd v2.16b, v22.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ac3                    // aesd v3.16b, v22.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae1                    // aesd v1.16b, v23.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ae2                    // aesd v2.16b, v23.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ae3                    // aesd v3.16b, v23.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b01                    // aesd v1.16b, v24.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b02                    // aesd v2.16b, v24.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b03                    // aesd v3.16b, v24.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0x3dc0305c                    // ldr q28, [x2, #192]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a01                    // aesd v1.16b, v16.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a02                    // aesd v2.16b, v16.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a03                    // aesd v3.16b, v16.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a21                    // aesd v1.16b, v17.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a22                    // aesd v2.16b, v17.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a23                    // aesd v3.16b, v17.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a41                    // aesd v1.16b, v18.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a42                    // aesd v2.16b, v18.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a43                    // aesd v3.16b, v18.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a61                    // aesd v1.16b, v19.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a62                    // aesd v2.16b, v19.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a63                    // aesd v3.16b, v19.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a81                    // aesd v1.16b, v20.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a82                    // aesd v2.16b, v20.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a83                    // aesd v3.16b, v20.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa1                    // aesd v1.16b, v21.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285aa2                    // aesd v2.16b, v21.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285aa3                    // aesd v3.16b, v21.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac1                    // aesd v1.16b, v22.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ac2                    // aesd v2.16b, v22.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ac3                    // aesd v3.16b, v22.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae1                    // aesd v1.16b, v23.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ae2                    // aesd v2.16b, v23.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ae3                    // aesd v3.16b, v23.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b01                    // aesd v1.16b, v24.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b02                    // aesd v2.16b, v24.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b03                    // aesd v3.16b, v24.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b40                    // aesd v0.16b, v26.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b41                    // aesd v1.16b, v26.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b42                    // aesd v2.16b, v26.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b43                    // aesd v3.16b, v26.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x4e285b61                    // aesd v1.16b, v27.16b
  .long 0x4e285b62                    // aesd v2.16b, v27.16b
  .long 0x4e285b63                    // aesd v3.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0xad46745c                    // ldp q28, q29, [x2, #192]
  .long 0x3dc0385e                    // ldr q30, [x2, #224]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a01                    // aesd v1.16b, v16.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a02                    // aesd v2.16b, v16.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a03                    // aesd v3.16b, v16.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a21                    // aesd v1.16b, v17.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a22                    // aesd v2.16b, v17.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a23                    // aesd v3.16b, v17.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a41                    // aesd v1.16b, v18.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a42                    // aesd v2.16b, v18.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a43                    // aesd v3.16b, v18.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a61                    // aesd v1.16b, v19.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a62                    // aesd v2.16b, v19.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a63                    // aesd v3.16b, v19.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a81                    // aesd v1.16b, v20.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a82                    // aesd v2.16b, v20.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a83                    // aesd v3.16b, v20.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa1                    // aesd v1.16b, v21.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285aa2                    // aesd v2.16b, v21.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285aa3                    // aesd v3.16b, v21.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac1                    // aesd v1.16b, v22.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ac2                    // aesd v2.16b, v22.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ac3                    // aesd v3.16b, v22.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae1                    // aesd v1.16b, v23.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ae2                    // aesd v2.16b, v23.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ae3                    // aesd v3.16b, v23.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b01                    // aesd v1.16b, v24.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b02                    // aesd v2.16b, v24.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b03                    // aesd v3.16b, v24.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b40                    // aesd v0.16b, v26.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b41                    // aesd v1.16b, v26.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b42                    // aesd v2.16b, v26.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b43                    // aesd v3.16b, v26.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b61                    // aesd v1.16b, v27.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b62                    // aesd v2.16b, v27.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b63                    // aesd v3.16b, v27.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b80                    // aesd v0.16b, v28.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b81                    // aesd v1.16b, v28.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b82                    // aesd v2.16b, v28.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b83                    // aesd v3.16b, v28.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ba0                    // aesd v0.16b, v29.16b
  .long 0x4e285ba1                    // aesd v1.16b, v29.16b
  .long 0x4e285ba2                    // aesd v2.16b, v29.16b
  .long 0x4e285ba3                    // aesd v3.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0x3dc0285a                    // ldr q26, [x2, #160]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0x3dc0305c                    // ldr q28, [x2, #192]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0xad46745c                    // ldp q28, q29, [x2, #192]
  .long 0x3dc0385e                    // ldr q30, [x2, #224]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b82                    // aese v2.16b, v28.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b83                    // aese v3.16b, v28.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x4e284ba2                    // aese v2.16b, v29.16b
  .long 0x4e284ba3                    // aese v3.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
  .long 0x3d800020                    // str q0, [x1]
  .long 0x3d800421                    // str q1, [x1, #16]
  .long 0x3d800822                    // str q2, [x1, #32]
  .long 0x3d800c23                    // str q3, [x1, #48]
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_EIGHT}
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x3dc00401                    // ldr q1, [x0, #16]
  .long 0x3dc00802                    // ldr q2, [x0, #32]
  .long 0x3dc00c03                    // ldr q3, [x0, #48]
  .long 0x3dc01004                    // ldr q4, [x0, #64]
  .long 0x3dc01405                    // ldr q5, [x0, #80]
  .long 0x3dc01806                    // ldr q6, [x0, #96]
  .long 0x3dc01c07                    // ldr q7, [x0, #112]
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}

{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0x3dc0285a                    // ldr q26, [x2, #160]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a01                    // aesd v1.16b, v16.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a02                    // aesd v2.16b, v16.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a03                    // aesd v3.16b, v16.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a04                    // aesd v4.16b, v16.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a05                    // aesd v5.16b, v16.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a06                    // aesd v6.16b, v16.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a07                    // aesd v7.16b, v16.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a21                    // aesd v1.16b, v17.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a22                    // aesd v2.16b, v17.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a23                    // aesd v3.16b, v17.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a24                    // aesd v4.16b, v17.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a25                    // aesd v5.16b, v17.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a26                    // aesd v6.16b, v17.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a27                    // aesd v7.16b, v17.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a41                    // aesd v1.16b, v18.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a42                    // aesd v2.16b, v18.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a43                    // aesd v3.16b, v18.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a44                    // aesd v4.16b, v18.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a45                    // aesd v5.16b, v18.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a46                    // aesd v6.16b, v18.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a47                    // aesd v7.16b, v18.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a61                    // aesd v1.16b, v19.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a62                    // aesd v2.16b, v19.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a63                    // aesd v3.16b, v19.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a64                    // aesd v4.16b, v19.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a65                    // aesd v5.16b, v19.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a66                    // aesd v6.16b, v19.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a67                    // aesd v7.16b, v19.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a81                    // aesd v1.16b, v20.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a82                    // aesd v2.16b, v20.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a83                    // aesd v3.16b, v20.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a84                    // aesd v4.16b, v20.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a85                    // aesd v5.16b, v20.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a86                    // aesd v6.16b, v20.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a87                    // aesd v7.16b, v20.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa1                    // aesd v1.16b, v21.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285aa2                    // aesd v2.16b, v21.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285aa3                    // aesd v3.16b, v21.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285aa4                    // aesd v4.16b, v21.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285aa5                    // aesd v5.16b, v21.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285aa6                    // aesd v6.16b, v21.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285aa7                    // aesd v7.16b, v21.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac1                    // aesd v1.16b, v22.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ac2                    // aesd v2.16b, v22.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ac3                    // aesd v3.16b, v22.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ac4                    // aesd v4.16b, v22.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285ac5                    // aesd v5.16b, v22.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285ac6                    // aesd v6.16b, v22.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285ac7                    // aesd v7.16b, v22.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae1                    // aesd v1.16b, v23.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ae2                    // aesd v2.16b, v23.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ae3                    // aesd v3.16b, v23.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ae4                    // aesd v4.16b, v23.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285ae5                    // aesd v5.16b, v23.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285ae6                    // aesd v6.16b, v23.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285ae7                    // aesd v7.16b, v23.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b01                    // aesd v1.16b, v24.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b02                    // aesd v2.16b, v24.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b03                    // aesd v3.16b, v24.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b04                    // aesd v4.16b, v24.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b05                    // aesd v5.16b, v24.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b06                    // aesd v6.16b, v24.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b07                    // aesd v7.16b, v24.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x4e285b24                    // aesd v4.16b, v25.16b
  .long 0x4e285b25                    // aesd v5.16b, v25.16b
  .long 0x4e285b26                    // aesd v6.16b, v25.16b
  .long 0x4e285b27                    // aesd v7.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0x3dc0305c                    // ldr q28, [x2, #192]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a01                    // aesd v1.16b, v16.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a02                    // aesd v2.16b, v16.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a03                    // aesd v3.16b, v16.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a04                    // aesd v4.16b, v16.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a05                    // aesd v5.16b, v16.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a06                    // aesd v6.16b, v16.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a07                    // aesd v7.16b, v16.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a21                    // aesd v1.16b, v17.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a22                    // aesd v2.16b, v17.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a23                    // aesd v3.16b, v17.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a24                    // aesd v4.16b, v17.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a25                    // aesd v5.16b, v17.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a26                    // aesd v6.16b, v17.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a27                    // aesd v7.16b, v17.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a41                    // aesd v1.16b, v18.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a42                    // aesd v2.16b, v18.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a43                    // aesd v3.16b, v18.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a44                    // aesd v4.16b, v18.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a45                    // aesd v5.16b, v18.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a46                    // aesd v6.16b, v18.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a47                    // aesd v7.16b, v18.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a61                    // aesd v1.16b, v19.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a62                    // aesd v2.16b, v19.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a63                    // aesd v3.16b, v19.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a64                    // aesd v4.16b, v19.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a65                    // aesd v5.16b, v19.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a66                    // aesd v6.16b, v19.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a67                    // aesd v7.16b, v19.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a81                    // aesd v1.16b, v20.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a82                    // aesd v2.16b, v20.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a83                    // aesd v3.16b, v20.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a84                    // aesd v4.16b, v20.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a85                    // aesd v5.16b, v20.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a86                    // aesd v6.16b, v20.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a87                    // aesd v7.16b, v20.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa1                    // aesd v1.16b, v21.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285aa2                    // aesd v2.16b, v21.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285aa3                    // aesd v3.16b, v21.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285aa4                    // aesd v4.16b, v21.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285aa5                    // aesd v5.16b, v21.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285aa6                    // aesd v6.16b, v21.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285aa7                    // aesd v7.16b, v21.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac1                    // aesd v1.16b, v22.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ac2                    // aesd v2.16b, v22.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ac3                    // aesd v3.16b, v22.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ac4                    // aesd v4.16b, v22.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285ac5                    // aesd v5.16b, v22.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285ac6                    // aesd v6.16b, v22.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285ac7                    // aesd v7.16b, v22.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae1                    // aesd v1.16b, v23.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ae2                    // aesd v2.16b, v23.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ae3                    // aesd v3.16b, v23.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ae4                    // aesd v4.16b, v23.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285ae5                    // aesd v5.16b, v23.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285ae6                    // aesd v6.16b, v23.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285ae7                    // aesd v7.16b, v23.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b01                    // aesd v1.16b, v24.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b02                    // aesd v2.16b, v24.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b03                    // aesd v3.16b, v24.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b04                    // aesd v4.16b, v24.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b05                    // aesd v5.16b, v24.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b06                    // aesd v6.16b, v24.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b07                    // aesd v7.16b, v24.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b24                    // aesd v4.16b, v25.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b25                    // aesd v5.16b, v25.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b26                    // aesd v6.16b, v25.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b27                    // aesd v7.16b, v25.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b40                    // aesd v0.16b, v26.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b41                    // aesd v1.16b, v26.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b42                    // aesd v2.16b, v26.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b43                    // aesd v3.16b, v26.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b44                    // aesd v4.16b, v26.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b45                    // aesd v5.16b, v26.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b46                    // aesd v6.16b, v26.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b47                    // aesd v7.16b, v26.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x4e285b61                    // aesd v1.16b, v27.16b
  .long 0x4e285b62                    // aesd v2.16b, v27.16b
  .long 0x4e285b63                    // aesd v3.16b, v27.16b
  .long 0x4e285b64                    // aesd v4.16b, v27.16b
  .long 0x4e285b65                    // aesd v5.16b, v27.16b
  .long 0x4e285b66                    // aesd v6.16b, v27.16b
  .long 0x4e285b67                    // aesd v7.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  .long 0x6e3c1c84                    // eor v4.16b, v4.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1cc6                    // eor v6.16b, v6.16b, v28.16b
  .long 0x6e3c1ce7                    // eor v7.16b, v7.16b, v28.16b
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0xad46745c                    // ldp q28, q29, [x2, #192]
  .long 0x3dc0385e                    // ldr q30, [x2, #224]
  .long 0x4e285a00                    // aesd v0.16b, v16.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a01                    // aesd v1.16b, v16.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a02                    // aesd v2.16b, v16.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a03                    // aesd v3.16b, v16.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a04                    // aesd v4.16b, v16.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a05                    // aesd v5.16b, v16.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a06                    // aesd v6.16b, v16.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a07                    // aesd v7.16b, v16.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a20                    // aesd v0.16b, v17.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a21                    // aesd v1.16b, v17.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a22                    // aesd v2.16b, v17.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a23                    // aesd v3.16b, v17.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a24                    // aesd v4.16b, v17.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a25                    // aesd v5.16b, v17.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a26                    // aesd v6.16b, v17.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a27                    // aesd v7.16b, v17.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a40                    // aesd v0.16b, v18.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a41                    // aesd v1.16b, v18.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a42                    // aesd v2.16b, v18.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a43                    // aesd v3.16b, v18.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a44                    // aesd v4.16b, v18.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a45                    // aesd v5.16b, v18.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a46                    // aesd v6.16b, v18.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a47                    // aesd v7.16b, v18.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a60                    // aesd v0.16b, v19.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a61                    // aesd v1.16b, v19.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a62                    // aesd v2.16b, v19.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a63                    // aesd v3.16b, v19.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a64                    // aesd v4.16b, v19.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a65                    // aesd v5.16b, v19.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a66                    // aesd v6.16b, v19.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a67                    // aesd v7.16b, v19.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285a80                    // aesd v0.16b, v20.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285a81                    // aesd v1.16b, v20.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285a82                    // aesd v2.16b, v20.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285a83                    // aesd v3.16b, v20.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285a84                    // aesd v4.16b, v20.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285a85                    // aesd v5.16b, v20.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285a86                    // aesd v6.16b, v20.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285a87                    // aesd v7.16b, v20.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285aa0                    // aesd v0.16b, v21.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285aa1                    // aesd v1.16b, v21.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285aa2                    // aesd v2.16b, v21.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285aa3                    // aesd v3.16b, v21.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285aa4                    // aesd v4.16b, v21.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285aa5                    // aesd v5.16b, v21.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285aa6                    // aesd v6.16b, v21.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285aa7                    // aesd v7.16b, v21.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285ac0                    // aesd v0.16b, v22.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ac1                    // aesd v1.16b, v22.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ac2                    // aesd v2.16b, v22.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ac3                    // aesd v3.16b, v22.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ac4                    // aesd v4.16b, v22.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285ac5                    // aesd v5.16b, v22.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285ac6                    // aesd v6.16b, v22.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285ac7                    // aesd v7.16b, v22.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285ae0                    // aesd v0.16b, v23.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285ae1                    // aesd v1.16b, v23.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285ae2                    // aesd v2.16b, v23.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285ae3                    // aesd v3.16b, v23.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285ae4                    // aesd v4.16b, v23.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285ae5                    // aesd v5.16b, v23.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285ae6                    // aesd v6.16b, v23.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285ae7                    // aesd v7.16b, v23.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b00                    // aesd v0.16b, v24.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b01                    // aesd v1.16b, v24.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b02                    // aesd v2.16b, v24.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b03                    // aesd v3.16b, v24.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b04                    // aesd v4.16b, v24.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b05                    // aesd v5.16b, v24.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b06                    // aesd v6.16b, v24.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b07                    // aesd v7.16b, v24.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b24                    // aesd v4.16b, v25.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b25                    // aesd v5.16b, v25.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b26                    // aesd v6.16b, v25.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b27                    // aesd v7.16b, v25.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b40                    // aesd v0.16b, v26.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b41                    // aesd v1.16b, v26.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b42                    // aesd v2.16b, v26.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b43                    // aesd v3.16b, v26.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b44                    // aesd v4.16b, v26.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b45                    // aesd v5.16b, v26.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b46                    // aesd v6.16b, v26.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b47                    // aesd v7.16b, v26.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b61                    // aesd v1.16b, v27.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b62                    // aesd v2.16b, v27.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b63                    // aesd v3.16b, v27.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b64                    // aesd v4.16b, v27.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b65                    // aesd v5.16b, v27.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b66                    // aesd v6.16b, v27.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b67                    // aesd v7.16b, v27.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285b80                    // aesd v0.16b, v28.16b
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x4e285b81                    // aesd v1.16b, v28.16b
  .long 0x4e287821                    // aesimc v1.16b, v1.16b
  .long 0x4e285b82                    // aesd v2.16b, v28.16b
  .long 0x4e287842                    // aesimc v2.16b, v2.16b
  .long 0x4e285b83                    // aesd v3.16b, v28.16b
  .long 0x4e287863                    // aesimc v3.16b, v3.16b
  .long 0x4e285b84                    // aesd v4.16b, v28.16b
  .long 0x4e287884                    // aesimc v4.16b, v4.16b
  .long 0x4e285b85                    // aesd v5.16b, v28.16b
  .long 0x4e2878a5                    // aesimc v5.16b, v5.16b
  .long 0x4e285b86                    // aesd v6.16b, v28.16b
  .long 0x4e2878c6                    // aesimc v6.16b, v6.16b
  .long 0x4e285b87                    // aesd v7.16b, v28.16b
  .long 0x4e2878e7                    // aesimc v7.16b, v7.16b
  .long 0x4e285ba0                    // aesd v0.16b, v29.16b
  .long 0x4e285ba1                    // aesd v1.16b, v29.16b
  .long 0x4e285ba2                    // aesd v2.16b, v29.16b
  .long 0x4e285ba3                    // aesd v3.16b, v29.16b
  .long 0x4e285ba4                    // aesd v4.16b, v29.16b
  .long 0x4e285ba5                    // aesd v5.16b, v29.16b
  .long 0x4e285ba6                    // aesd v6.16b, v29.16b
  .long 0x4e285ba7                    // aesd v7.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0x3dc0285a                    // ldr q26, [x2, #160]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0x3dc0305c                    // ldr q28, [x2, #192]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b44                    // aese v4.16b, v26.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b46                    // aese v6.16b, v26.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b47                    // aese v7.16b, v26.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e284b64                    // aese v4.16b, v27.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e284b66                    // aese v6.16b, v27.16b
  .long 0x4e284b67                    // aese v7.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  .long 0x6e3c1c84                    // eor v4.16b, v4.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1cc6                    // eor v6.16b, v6.16b, v28.16b
  .long 0x6e3c1ce7                    // eor v7.16b, v7.16b, v28.16b
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xad404450                    // ldp q16, q17, [x2]
  .long 0xad414c52                    // ldp q18, q19, [x2, #32]
  .long 0xad425454                    // ldp q20, q21, [x2, #64]
  .long 0xad435c56                    // ldp q22, q23, [x2, #96]
  .long 0xad446458                    // ldp q24, q25, [x2, #128]
  .long 0xad456c5a                    // ldp q26, q27, [x2, #160]
  .long 0xad46745c                    // ldp q28, q29, [x2, #192]
  .long 0x3dc0385e                    // ldr q30, [x2, #224]
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b44                    // aese v4.16b, v26.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b46                    // aese v6.16b, v26.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b47                    // aese v7.16b, v26.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b64                    // aese v4.16b, v27.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b66                    // aese v6.16b, v27.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b67                    // aese v7.16b, v27.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b82                    // aese v2.16b, v28.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b83                    // aese v3.16b, v28.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b84                    // aese v4.16b, v28.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b85                    // aese v5.16b, v28.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b86                    // aese v6.16b, v28.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b87                    // aese v7.16b, v28.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x4e284ba2                    // aese v2.16b, v29.16b
  .long 0x4e284ba3                    // aese v3.16b, v29.16b
  .long 0x4e284ba4                    // aese v4.16b, v29.16b
  .long 0x4e284ba5                    // aese v5.16b, v29.16b
  .long 0x4e284ba6                    // aese v6.16b, v29.16b
  .long 0x4e284ba7                    // aese v7.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
  .long 0x3d800020                    // str q0, [x1]
  .long 0x3d800421                    // str q1, [x1, #16]
  .long 0x3d800822                    // str q2, [x1, #32]
  .long 0x3d800c23                    // str q3, [x1, #48]
  .long 0x3d801024                    // str q4, [x1, #64]
  .long 0x3d801425                    // str q5, [x1, #80]
  .long 0x3d801826                    // str q6, [x1, #96]
  .long 0x3d801c27                    // str q7, [x1, #112]
  ret
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_ONE, CRYPTOLIB_AESCRYPTOEXT_FOUR, CRYPTOLIB_AESCRYPTOEXT_EIGHT must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
