// AES CryptoExt (FEAT_AES) 8-wide fused CBC decrypt (aarch64).
// -------------------------------------------------------------------
//
// P_i = D_K(C_i) xor C_{i-1}: the inverse transforms are independent, so the
// kernel decrypts 8-wide with a 1-wide tail and folds the chain XOR into the
// same pass, turning the mode's decrypt-then-XOR two passes into one.
// In-place safe: every C_i is reloaded from the input before P_i is stored
// over it (identical or fully-disjoint buffers only). Writes the final
// ciphertext block back to the chaining slot at IvPtr.
//
// Entry (after ClpSimdProc1Begin_aarch64.inc): x0 = pointer to TCbcFusedCtx
// (all 8-byte fields): InPtr 0, OutPtr 8, KeysPtr 16, IvPtr 24,
// BlockCount 32. BlockCount is positive (caller guarantees). Consumes the
// inverse-MixColumns (decrypt) schedule.
//
// Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128 / KEY192 / KEY256 must be
// defined.
//
// Register map: v0..v7 lanes, v16..v(16+N_R-1) resident round keys, v30 =
// final round key / ciphertext-reload scratch (dual use), v31 = chain;
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
  // x1 = InPtr, x2 = OutPtr, x3 = KeysPtr, x4 = IvPtr, x5 = BlockCount
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0x3dc0009f                    // ldr q31, [x4]
.Laesce_cbcdec128_wide:
  cmp x5, #8
  b.lo .Laesce_cbcdec128_tail
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00421                    // ldr q1, [x1, #16]
  .long 0x3dc00822                    // ldr q2, [x1, #32]
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
  .long 0x3dc01024                    // ldr q4, [x1, #64]
  .long 0x3dc01425                    // ldr q5, [x1, #80]
  .long 0x3dc01826                    // ldr q6, [x1, #96]
  .long 0x3dc01c27                    // ldr q7, [x1, #112]
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
  .long 0x3dc0287e                    // ldr q30, [x3, #160]
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x3dc0003e                    // ldr q30, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0043e                    // ldr q30, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0083e                    // ldr q30, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc00c3e                    // ldr q30, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0103e                    // ldr q30, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0143e                    // ldr q30, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0183e                    // ldr q30, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc01c3e                    // ldr q30, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  add x1, x1, #128
  add x2, x2, #128
  sub x5, x5, #8
  cbnz x5, .Laesce_cbcdec128_wide
.Laesce_cbcdec128_tail:
  cbz x5, .Laesce_cbcdec128_done
.Laesce_cbcdec128_tail_loop:
  .long 0x3dc00020                    // ldr q0, [x1]
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
  .long 0x3dc0287e                    // ldr q30, [x3, #160]
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x3dc0003e                    // ldr q30, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  add x1, x1, #16
  add x2, x2, #16
  sub x5, x5, #1
  cbnz x5, .Laesce_cbcdec128_tail_loop
.Laesce_cbcdec128_done:
  .long 0x3d80009f                    // str q31, [x4]
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9400c04                    // ldr x4, [x0, #24]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  // x1 = InPtr, x2 = OutPtr, x3 = KeysPtr, x4 = IvPtr, x5 = BlockCount
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0x3dc0009f                    // ldr q31, [x4]
.Laesce_cbcdec192_wide:
  cmp x5, #8
  b.lo .Laesce_cbcdec192_tail
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00421                    // ldr q1, [x1, #16]
  .long 0x3dc00822                    // ldr q2, [x1, #32]
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
  .long 0x3dc01024                    // ldr q4, [x1, #64]
  .long 0x3dc01425                    // ldr q5, [x1, #80]
  .long 0x3dc01826                    // ldr q6, [x1, #96]
  .long 0x3dc01c27                    // ldr q7, [x1, #112]
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
  .long 0x3dc0307e                    // ldr q30, [x3, #192]
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x3dc0003e                    // ldr q30, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0043e                    // ldr q30, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0083e                    // ldr q30, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc00c3e                    // ldr q30, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0103e                    // ldr q30, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0143e                    // ldr q30, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0183e                    // ldr q30, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc01c3e                    // ldr q30, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  add x1, x1, #128
  add x2, x2, #128
  sub x5, x5, #8
  cbnz x5, .Laesce_cbcdec192_wide
.Laesce_cbcdec192_tail:
  cbz x5, .Laesce_cbcdec192_done
.Laesce_cbcdec192_tail_loop:
  .long 0x3dc00020                    // ldr q0, [x1]
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
  .long 0x3dc0307e                    // ldr q30, [x3, #192]
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x3dc0003e                    // ldr q30, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  add x1, x1, #16
  add x2, x2, #16
  sub x5, x5, #1
  cbnz x5, .Laesce_cbcdec192_tail_loop
.Laesce_cbcdec192_done:
  .long 0x3d80009f                    // str q31, [x4]
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9400c04                    // ldr x4, [x0, #24]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  // x1 = InPtr, x2 = OutPtr, x3 = KeysPtr, x4 = IvPtr, x5 = BlockCount
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0xad46747c                    // ldp q28, q29, [x3, #192]
  .long 0x3dc0009f                    // ldr q31, [x4]
.Laesce_cbcdec256_wide:
  cmp x5, #8
  b.lo .Laesce_cbcdec256_tail
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00421                    // ldr q1, [x1, #16]
  .long 0x3dc00822                    // ldr q2, [x1, #32]
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
  .long 0x3dc01024                    // ldr q4, [x1, #64]
  .long 0x3dc01425                    // ldr q5, [x1, #80]
  .long 0x3dc01826                    // ldr q6, [x1, #96]
  .long 0x3dc01c27                    // ldr q7, [x1, #112]
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
  .long 0x3dc0387e                    // ldr q30, [x3, #224]
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x3dc0003e                    // ldr q30, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0043e                    // ldr q30, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0083e                    // ldr q30, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc00c3e                    // ldr q30, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0103e                    // ldr q30, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0143e                    // ldr q30, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc0183e                    // ldr q30, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  .long 0x3dc01c3e                    // ldr q30, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  add x1, x1, #128
  add x2, x2, #128
  sub x5, x5, #8
  cbnz x5, .Laesce_cbcdec256_wide
.Laesce_cbcdec256_tail:
  cbz x5, .Laesce_cbcdec256_done
.Laesce_cbcdec256_tail_loop:
  .long 0x3dc00020                    // ldr q0, [x1]
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
  .long 0x3dc0387e                    // ldr q30, [x3, #224]
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x3dc0003e                    // ldr q30, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ebe1fdf                    // orr v31.16b, v30.16b, v30.16b
  add x1, x1, #16
  add x2, x2, #16
  sub x5, x5, #1
  cbnz x5, .Laesce_cbcdec256_tail_loop
.Laesce_cbcdec256_done:
  .long 0x3d80009f                    // str q31, [x4]
  ret
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
