// AES CryptoExt (FEAT_AES) serial fused CBC encrypt (aarch64).
// -------------------------------------------------------------------
//
// C_i = E_K(P_i xor C_{i-1}), 1-wide (the chain is inherently serial), with
// the chaining value held in v31 across the whole run and the round keys
// preloaded once. Writes the final ciphertext block back to the chaining
// slot at IvPtr.
//
// Entry (after ClpSimdProc1Begin_aarch64.inc): x0 = pointer to TCbcFusedCtx
// (all 8-byte fields): InPtr 0, OutPtr 8, KeysPtr 16, IvPtr 24,
// BlockCount 32. BlockCount is positive (caller guarantees).
//
// Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128 / KEY192 / KEY256 must be
// defined; consumes the forward (encrypt) schedule.
//
// Register map: v0 lane, v16..v(16+N_R) resident round keys, v31 = chain;
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
  .long 0x3dc0287a                    // ldr q26, [x3, #160]
  .long 0x3dc0009f                    // ldr q31, [x4]
.Laesce_cbcenc128_loop:
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
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
  .long 0x4ea01c1f                    // orr v31.16b, v0.16b, v0.16b
  .long 0x3d800040                    // str q0, [x2]
  add x1, x1, #16
  add x2, x2, #16
  sub x5, x5, #1
  cbnz x5, .Laesce_cbcenc128_loop
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
  .long 0x3dc0307c                    // ldr q28, [x3, #192]
  .long 0x3dc0009f                    // ldr q31, [x4]
.Laesce_cbcenc192_loop:
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
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
  .long 0x4ea01c1f                    // orr v31.16b, v0.16b, v0.16b
  .long 0x3d800040                    // str q0, [x2]
  add x1, x1, #16
  add x2, x2, #16
  sub x5, x5, #1
  cbnz x5, .Laesce_cbcenc192_loop
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
  .long 0x3dc0387e                    // ldr q30, [x3, #224]
  .long 0x3dc0009f                    // ldr q31, [x4]
.Laesce_cbcenc256_loop:
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
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
  .long 0x4ea01c1f                    // orr v31.16b, v0.16b, v0.16b
  .long 0x3d800040                    // str q0, [x2]
  add x1, x1, #16
  add x2, x2, #16
  sub x5, x5, #1
  cbnz x5, .Laesce_cbcenc256_loop
  .long 0x3d80009f                    // str q31, [x4]
  ret
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
