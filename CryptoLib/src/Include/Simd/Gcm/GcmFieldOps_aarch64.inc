// GHASH field-op kernels, merged (aarch64).
// -------------------------------------------------------------------
//
// Five small GHASH field primitives merged under one selector; exactly one
// of the following must be defined before including this file:
//
//   CRYPTOLIB_GCMFIELD_PARTIAL       (ClpSimdProc3Begin: x0 = @X, x1 = @Y,
//     x2 = @TGcmPartial128 out) - 256-bit partial product (Z0, Z1 folded in,
//     Z2) of two GHASH field elements before degree reduction. X.N0, X.N1
//     and Y.N0, Y.N1 are UInt64 GHASH field limbs (TFieldElement); each
//     element is packed into a vector as low qword = N1, high qword = N0.
//   CRYPTOLIB_GCMFIELD_MULTIPLY_EXT  (ClpSimdProc3Begin: x0 = PX, x1 = PY,
//     x2 = POut48) - carryless multiply without reduction; operands are
//     16-byte limbs (LE UInt64 pair each), output Z0, Z1, Z2 (48 bytes;
//     no Z1 merge / reduction).
//   CRYPTOLIB_GCMFIELD_REDUCE3       (ClpSimdProc4Begin: x0 = PZ0, x1 = PZ1,
//     x2 = PZ2, x3 = POut) - fold Z1 into (Z0, Z2), then reduce the (Z0, Z2)
//     pair modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1, writing the
//     16-byte field element to POut. Z0/Z1/Z2 are the three 128-bit limbs
//     carried across a batch of carry-less GHASH products; the folded
//     Z0/Z2 are stored back in place (matching the x86 kernel).
//   CRYPTOLIB_GCMFIELD_XOR_LIMBS48   (ClpSimdProc4Begin: x0 = PA0, x1 = PA1,
//     x2 = PA2, x3 = PSrc48) - xor 16-byte limbs in place:
//     *PA0 ^= PSrc[0..15], *PA1 ^= PSrc[16..31], *PA2 ^= PSrc[32..47].
//   CRYPTOLIB_GCMFIELD_BLOCK_REVERSE (ClpSimdProc2Begin: x0 = PDst,
//     x1 = PSrc) - [x0] := byte-reverse([x1]) (rev64 + half swap; no
//     shuffle mask needed on AArch64).
//
// Scratch: v0..v6 and x5..x6 only; v8..v15 untouched (only d8..d15 are
// callee-saved under AAPCS64).
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$IFDEF CRYPTOLIB_GCMFIELD_PARTIAL}
  .long 0xf9400405                    // ldr x5, [x0, #8]
  .long 0xf9400006                    // ldr x6, [x0]
  .long 0x4e081ca0                    // ins v0.d[0], x5
  .long 0x4e181cc0                    // ins v0.d[1], x6
  .long 0xf9400425                    // ldr x5, [x1, #8]
  .long 0xf9400026                    // ldr x6, [x1]
  .long 0x4e081ca1                    // ins v1.d[0], x5
  .long 0x4e181cc1                    // ins v1.d[1], x6
  .long 0x6e004005                    // ext v5.16b, v0.16b, v0.16b, #8
  .long 0x0ee1e002                    // pmull v2.1q, v0.1d, v1.1d
  .long 0x4ee1e004                    // pmull2 v4.1q, v0.2d, v1.2d
  .long 0x0ee1e0a3                    // pmull v3.1q, v5.1d, v1.1d
  .long 0x4ee1e0a5                    // pmull2 v5.1q, v5.2d, v1.2d
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4f00e406                    // movi v6.16b, #0
  .long 0x6e0340c5                    // ext v5.16b, v6.16b, v3.16b, #8
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e064065                    // ext v5.16b, v3.16b, v6.16b, #8
  .long 0x6e251c84                    // eor v4.16b, v4.16b, v5.16b
  .long 0x3d800042                    // str q2, [x2]
  .long 0x3d800444                    // str q4, [x2, #16]
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_GCMFIELD_MULTIPLY_EXT}
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x3dc00021                    // ldr q1, [x1]
  .long 0x6e004005                    // ext v5.16b, v0.16b, v0.16b, #8
  .long 0x0ee1e002                    // pmull v2.1q, v0.1d, v1.1d
  .long 0x4ee1e004                    // pmull2 v4.1q, v0.2d, v1.2d
  .long 0x0ee1e0a3                    // pmull v3.1q, v5.1d, v1.1d
  .long 0x4ee1e0a5                    // pmull2 v5.1q, v5.2d, v1.2d
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x3d800042                    // str q2, [x2]
  .long 0x3d800443                    // str q3, [x2, #16]
  .long 0x3d800844                    // str q4, [x2, #32]
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_GCMFIELD_REDUCE3}
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x3dc00042                    // ldr q2, [x2]
  .long 0x3dc00021                    // ldr q1, [x1]
  .long 0x4f00e406                    // movi v6.16b, #0
  .long 0x6e0140c4                    // ext v4.16b, v6.16b, v1.16b, #8
  .long 0x6e064025                    // ext v5.16b, v1.16b, v6.16b, #8
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x3d800000                    // str q0, [x0]
  .long 0x3d800042                    // str q2, [x2]
  .long 0x1e604003                    // fmov d3, d0
  .long 0x1e604044                    // fmov d4, d2
  .long 0x6f7f0465                    // ushr v5.2d, v3.2d, #1
  .long 0x6e231c84                    // eor v4.16b, v4.16b, v3.16b
  .long 0x6e251c84                    // eor v4.16b, v4.16b, v5.16b
  .long 0x6f7e0465                    // ushr v5.2d, v3.2d, #2
  .long 0x6e251c84                    // eor v4.16b, v4.16b, v5.16b
  .long 0x6f790465                    // ushr v5.2d, v3.2d, #7
  .long 0x6e251c84                    // eor v4.16b, v4.16b, v5.16b
  .long 0x6e064001                    // ext v1.16b, v0.16b, v6.16b, #8
  .long 0x4f7f5465                    // shl v5.2d, v3.2d, #63
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4f7e5465                    // shl v5.2d, v3.2d, #62
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4f795465                    // shl v5.2d, v3.2d, #57
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x6e064045                    // ext v5.16b, v2.16b, v6.16b, #8
  .long 0x4f4154a2                    // shl v2.2d, v5.2d, #1
  .long 0x6f410485                    // ushr v5.2d, v4.2d, #63
  .long 0x4ea51c42                    // orr v2.16b, v2.16b, v5.16b
  .long 0x4f415483                    // shl v3.2d, v4.2d, #1
  .long 0x6f410425                    // ushr v5.2d, v1.2d, #63
  .long 0x4ea51c63                    // orr v3.16b, v3.16b, v5.16b
  .long 0x4f415420                    // shl v0.2d, v1.2d, #1
  .long 0x6f7f0405                    // ushr v5.2d, v0.2d, #1
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6f7e0405                    // ushr v5.2d, v0.2d, #2
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6f790405                    // ushr v5.2d, v0.2d, #7
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x4f7f5425                    // shl v5.2d, v1.2d, #63
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0x4f7a5425                    // shl v5.2d, v1.2d, #58
  .long 0x6e251c63                    // eor v3.16b, v3.16b, v5.16b
  .long 0xfd000063                    // str d3, [x3]
  .long 0xfd000462                    // str d2, [x3, #8]
  ret
    {$ELSE}
      {$IFDEF CRYPTOLIB_GCMFIELD_XOR_LIMBS48}
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x3dc00061                    // ldr q1, [x3]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3d800000                    // str q0, [x0]
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00461                    // ldr q1, [x3, #16]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3d800020                    // str q0, [x1]
  .long 0x3dc00040                    // ldr q0, [x2]
  .long 0x3dc00861                    // ldr q1, [x3, #32]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3d800040                    // str q0, [x2]
  ret
      {$ELSE}
        {$IFDEF CRYPTOLIB_GCMFIELD_BLOCK_REVERSE}
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x3d800000                    // str q0, [x0]
  ret
        {$ELSE}
        {$FATAL Exactly one of CRYPTOLIB_GCMFIELD_PARTIAL, CRYPTOLIB_GCMFIELD_MULTIPLY_EXT, CRYPTOLIB_GCMFIELD_REDUCE3, CRYPTOLIB_GCMFIELD_XOR_LIMBS48, CRYPTOLIB_GCMFIELD_BLOCK_REVERSE must be defined before including this file}
        {$ENDIF}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
