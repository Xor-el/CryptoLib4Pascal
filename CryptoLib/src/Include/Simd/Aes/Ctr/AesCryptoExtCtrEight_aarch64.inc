// AES CryptoExt (FEAT_AES) 8-wide CTR keystream + XOR, fused kernel (aarch64).
// -------------------------------------------------------------------
//
// Fused counter-mode body for TSicBlockCipher's bulk path: processes eight
// AES-CTR blocks per iteration, XORing the keystream with the input in one
// pass. The eight cipher lanes live in v0..v7 across the whole round chain;
// counters are staged raw (no pre-whitening is needed on AArch64 - the first
// aese consumes K_0), patched per lane into the low dword of the base block
// via GPR add / rev / ins.
//
// Entry (after ClpSimdProc1Begin_aarch64.inc): x0 = pointer to TCtrFusedCtx
// (all 8-byte fields): InPtr 0, OutPtr 8, KeysPtr 16, CounterPtr 24,
// BlockCount 32. BlockCount is a positive multiple of 8 (caller guarantees).
//
// Counter contract: the caller guarantees the low-32 counter dword does NOT
// wrap within the call (ctr32 + BlockCount <= 2^32) - TAesCryptoExtCtrKernel
// splits runs at the 2^32 boundary and propagates the carry into the upper
// 12 bytes in Pascal. The kernel never touches counter bytes 0..11; only the
// low dword is stored back (mod 2^32).
//
// Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128 / KEY192 / KEY256 must be
// defined; the direction is always encrypt (CTR keystream).
//
// Register map: v0..v7 lanes, v16..v(16+N_R) resident round keys, v31 =
// counter base / plaintext scratch (dual use), w6..w8 + x1..x5 GPR scratch;
// v8..v15 and x18+ untouched.
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9400c04                    // ldr x4, [x0, #24]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  // x1 = InPtr, x2 = OutPtr, x3 = KeysPtr, x4 = CounterPtr, x5 = BlockCount
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0x3dc0287a                    // ldr q26, [x3, #160]
  .long 0xb9400c86                    // ldr w6, [x4, #12]
  .long 0x5ac008c6                    // rev w6, w6
.Laesce_ctr128_loop:
  .long 0x3dc0009f                    // ldr q31, [x4]
  .long 0x4ebf1fe0                    // orr v0.16b, v31.16b, v31.16b
  add w7, w6, #0
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d00                    // ins v0.s[3], w8
  .long 0x4ebf1fe1                    // orr v1.16b, v31.16b, v31.16b
  add w7, w6, #1
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d01                    // ins v1.s[3], w8
  .long 0x4ebf1fe2                    // orr v2.16b, v31.16b, v31.16b
  add w7, w6, #2
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d02                    // ins v2.s[3], w8
  .long 0x4ebf1fe3                    // orr v3.16b, v31.16b, v31.16b
  add w7, w6, #3
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d03                    // ins v3.s[3], w8
  .long 0x4ebf1fe4                    // orr v4.16b, v31.16b, v31.16b
  add w7, w6, #4
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d04                    // ins v4.s[3], w8
  .long 0x4ebf1fe5                    // orr v5.16b, v31.16b, v31.16b
  add w7, w6, #5
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d05                    // ins v5.s[3], w8
  .long 0x4ebf1fe6                    // orr v6.16b, v31.16b, v31.16b
  add w7, w6, #6
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d06                    // ins v6.s[3], w8
  .long 0x4ebf1fe7                    // orr v7.16b, v31.16b, v31.16b
  add w7, w6, #7
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d07                    // ins v7.s[3], w8
  add w6, w6, #8
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
  .long 0x3dc0003f                    // ldr q31, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x3dc0043f                    // ldr q31, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x3dc0083f                    // ldr q31, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x3dc00c3f                    // ldr q31, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x3dc0103f                    // ldr q31, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x3dc0143f                    // ldr q31, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x3dc0183f                    // ldr q31, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x3dc01c3f                    // ldr q31, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  add x1, x1, #128
  add x2, x2, #128
  sub x5, x5, #8
  cbnz x5, .Laesce_ctr128_loop
  .long 0x5ac008c7                    // rev w7, w6
  .long 0xb9000c87                    // str w7, [x4, #12]
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9400c04                    // ldr x4, [x0, #24]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  // x1 = InPtr, x2 = OutPtr, x3 = KeysPtr, x4 = CounterPtr, x5 = BlockCount
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0x3dc0307c                    // ldr q28, [x3, #192]
  .long 0xb9400c86                    // ldr w6, [x4, #12]
  .long 0x5ac008c6                    // rev w6, w6
.Laesce_ctr192_loop:
  .long 0x3dc0009f                    // ldr q31, [x4]
  .long 0x4ebf1fe0                    // orr v0.16b, v31.16b, v31.16b
  add w7, w6, #0
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d00                    // ins v0.s[3], w8
  .long 0x4ebf1fe1                    // orr v1.16b, v31.16b, v31.16b
  add w7, w6, #1
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d01                    // ins v1.s[3], w8
  .long 0x4ebf1fe2                    // orr v2.16b, v31.16b, v31.16b
  add w7, w6, #2
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d02                    // ins v2.s[3], w8
  .long 0x4ebf1fe3                    // orr v3.16b, v31.16b, v31.16b
  add w7, w6, #3
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d03                    // ins v3.s[3], w8
  .long 0x4ebf1fe4                    // orr v4.16b, v31.16b, v31.16b
  add w7, w6, #4
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d04                    // ins v4.s[3], w8
  .long 0x4ebf1fe5                    // orr v5.16b, v31.16b, v31.16b
  add w7, w6, #5
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d05                    // ins v5.s[3], w8
  .long 0x4ebf1fe6                    // orr v6.16b, v31.16b, v31.16b
  add w7, w6, #6
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d06                    // ins v6.s[3], w8
  .long 0x4ebf1fe7                    // orr v7.16b, v31.16b, v31.16b
  add w7, w6, #7
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d07                    // ins v7.s[3], w8
  add w6, w6, #8
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
  .long 0x3dc0003f                    // ldr q31, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x3dc0043f                    // ldr q31, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x3dc0083f                    // ldr q31, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x3dc00c3f                    // ldr q31, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x3dc0103f                    // ldr q31, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x3dc0143f                    // ldr q31, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x3dc0183f                    // ldr q31, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x3dc01c3f                    // ldr q31, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  add x1, x1, #128
  add x2, x2, #128
  sub x5, x5, #8
  cbnz x5, .Laesce_ctr192_loop
  .long 0x5ac008c7                    // rev w7, w6
  .long 0xb9000c87                    // str w7, [x4, #12]
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9400c04                    // ldr x4, [x0, #24]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  // x1 = InPtr, x2 = OutPtr, x3 = KeysPtr, x4 = CounterPtr, x5 = BlockCount
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0xad46747c                    // ldp q28, q29, [x3, #192]
  .long 0x3dc0387e                    // ldr q30, [x3, #224]
  .long 0xb9400c86                    // ldr w6, [x4, #12]
  .long 0x5ac008c6                    // rev w6, w6
.Laesce_ctr256_loop:
  .long 0x3dc0009f                    // ldr q31, [x4]
  .long 0x4ebf1fe0                    // orr v0.16b, v31.16b, v31.16b
  add w7, w6, #0
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d00                    // ins v0.s[3], w8
  .long 0x4ebf1fe1                    // orr v1.16b, v31.16b, v31.16b
  add w7, w6, #1
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d01                    // ins v1.s[3], w8
  .long 0x4ebf1fe2                    // orr v2.16b, v31.16b, v31.16b
  add w7, w6, #2
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d02                    // ins v2.s[3], w8
  .long 0x4ebf1fe3                    // orr v3.16b, v31.16b, v31.16b
  add w7, w6, #3
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d03                    // ins v3.s[3], w8
  .long 0x4ebf1fe4                    // orr v4.16b, v31.16b, v31.16b
  add w7, w6, #4
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d04                    // ins v4.s[3], w8
  .long 0x4ebf1fe5                    // orr v5.16b, v31.16b, v31.16b
  add w7, w6, #5
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d05                    // ins v5.s[3], w8
  .long 0x4ebf1fe6                    // orr v6.16b, v31.16b, v31.16b
  add w7, w6, #6
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d06                    // ins v6.s[3], w8
  .long 0x4ebf1fe7                    // orr v7.16b, v31.16b, v31.16b
  add w7, w6, #7
  .long 0x5ac008e8                    // rev w8, w7
  .long 0x4e1c1d07                    // ins v7.s[3], w8
  add w6, w6, #8
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
  .long 0x3dc0003f                    // ldr q31, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x3dc0043f                    // ldr q31, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x3dc0083f                    // ldr q31, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x3dc00c3f                    // ldr q31, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x3dc0103f                    // ldr q31, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x3dc0143f                    // ldr q31, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x3dc0183f                    // ldr q31, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x3dc01c3f                    // ldr q31, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  add x1, x1, #128
  add x2, x2, #128
  sub x5, x5, #8
  cbnz x5, .Laesce_ctr256_loop
  .long 0x5ac008c7                    // rev w7, w6
  .long 0xb9000c87                    // str w7, [x4, #12]
  ret
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
