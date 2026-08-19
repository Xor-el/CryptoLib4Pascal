// GHASH field-op kernels, merged (aarch64).
// -------------------------------------------------------------------
//
// Two small GHASH field primitives merged under one selector; exactly one
// of the following must be defined before including this file:
//
//   CRYPTOLIB_GCMFIELD_PARTIAL       (ClpSimdProc3Begin: x0 = @X, x1 = @Y,
//     x2 = @TGcmPartial128 out) - 256-bit partial product (Z0, Z1 folded in,
//     Z2) of two GHASH field elements before degree reduction. X.N0, X.N1
//     and Y.N0, Y.N1 are UInt64 GHASH field limbs (TFieldElement); each
//     element is packed into a vector as low qword = N1, high qword = N0.
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
  {$IFDEF CRYPTOLIB_GCMFIELD_BLOCK_REVERSE}
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x3d800000                    // str q0, [x0]
  ret
  {$ELSE}
  {$FATAL Exactly one of CRYPTOLIB_GCMFIELD_PARTIAL, CRYPTOLIB_GCMFIELD_BLOCK_REVERSE must be defined before including this file}
  {$ENDIF}
{$ENDIF}
