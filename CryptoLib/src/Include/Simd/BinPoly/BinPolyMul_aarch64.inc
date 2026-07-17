// Binary-polynomial (GF(2)[x]) PMULL multiply/square kernels, merged
// (aarch64), matching the selector contract of BinPolyMul_x86_64.inc.
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined
// before including this file:
//
//   CRYPTOLIB_BINPOLY_SMALL   (ClpSimdProc4Begin: x0 = ALen, x1 = PX,
//                              x2 = PY, x3 = PZz)
//     - fully-unrolled fixed-size multiply, limb counts 1..10; ZZ output
//       is packed V128 lanes (lane k at byte offset 16*k). Each size case
//       runs the same carry-less product schedule (Karatsuba decomposition
//       and reconstruction) as the matching x86_64 case: operands are
//       XOR-combined input limbs (built in v28/v29), one pmull per product
//       (v30), with the product halves routed into the slot accumulators
//       (v0..v7, then v16/v17) directly or through fmov/ext half-isolation (v26,
//       zero in v25).
//   CRYPTOLIB_BINPOLY_EVEN    (same entry)
//     - looped N-limb schoolbook multiply over the inlined 2x2 Karatsuba
//       tile (pmull/pmull2 + one pmull of the half-sums), N even.
//   CRYPTOLIB_BINPOLY_ODD     (same entry; N odd, single-limb tail tile).
//   CRYPTOLIB_BINPOLY_SQUARE  (ClpSimdProc3Begin: x0 = ALen, x1 = PX,
//                              x2 = PZz)
//     - carryless square: bits of each limb spread to even positions via
//       one pmull(a, a) per limb; PZz receives 2*ALen limbs.
//
// Every path uses only caller-saved registers (v0..v7, v16/v17,
// v25..v30, x4..x13), so no save frames are needed; each selector returns with a
// plain ret.
//
// Reference: Karatsuba's algorithm applied to carry-less multiplication -
// the 3-multiply reduction described in Shay Gueron / Michael E. Kounavis,
// "Intel(R) Carry-Less Multiplication Instruction and its Usage for
// Computing the GCM Mode" (white paper).
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$IFDEF CRYPTOLIB_BINPOLY_SMALL}
  cmp x0, #1
  b.eq .Lbpsmall_case1
  cmp x0, #2
  b.eq .Lbpsmall_case2
  cmp x0, #3
  b.eq .Lbpsmall_case3
  cmp x0, #4
  b.eq .Lbpsmall_case4
  cmp x0, #5
  b.eq .Lbpsmall_case5
  cmp x0, #6
  b.eq .Lbpsmall_case6
  cmp x0, #7
  b.eq .Lbpsmall_case7
  cmp x0, #8
  b.eq .Lbpsmall_case8
  cmp x0, #9
  b.eq .Lbpsmall_case9
  cmp x0, #10
  b.eq .Lbpsmall_case10
  ret

.Lbpsmall_case1:
  // 1 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x3d800060                    // str q0, [x3]
  ret

.Lbpsmall_case2:
  // 3 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  ret

.Lbpsmall_case3:
  // 6 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  ret

.Lbpsmall_case4:
  // 9 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e403                    // movi v3.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  ret

.Lbpsmall_case5:
  // 15 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e403                    // movi v3.16b, #0
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  ret

.Lbpsmall_case6:
  // 18 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e403                    // movi v3.16b, #0
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x4f00e405                    // movi v5.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  ret

.Lbpsmall_case7:
  // 24 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e403                    // movi v3.16b, #0
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x4f00e405                    // movi v5.16b, #0
  .long 0x4f00e406                    // movi v6.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  ret

.Lbpsmall_case8:
  // 27 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e403                    // movi v3.16b, #0
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x4f00e405                    // movi v5.16b, #0
  .long 0x4f00e406                    // movi v6.16b, #0
  .long 0x4f00e407                    // movi v7.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  ret

.Lbpsmall_case9:
  // 36 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e403                    // movi v3.16b, #0
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x4f00e405                    // movi v5.16b, #0
  .long 0x4f00e406                    // movi v6.16b, #0
  .long 0x4f00e407                    // movi v7.16b, #0
  .long 0x4f00e410                    // movi v16.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0xfd40203c                    // ldr d28, [x1, #64]
  .long 0xfd40205d                    // ldr d29, [x2, #64]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e3e1e10                    // eor v16.16b, v16.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40143b                    // ldr d27, [x1, #40]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0xfd40145b                    // ldr d27, [x2, #40]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  .long 0x3d802070                    // str q16, [x3, #128]
  ret

.Lbpsmall_case10:
  // 60 products, schedule extracted from the x86_64 case
  .long 0x4f00e400                    // movi v0.16b, #0
  .long 0x4f00e401                    // movi v1.16b, #0
  .long 0x4f00e402                    // movi v2.16b, #0
  .long 0x4f00e403                    // movi v3.16b, #0
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x4f00e405                    // movi v5.16b, #0
  .long 0x4f00e406                    // movi v6.16b, #0
  .long 0x4f00e407                    // movi v7.16b, #0
  .long 0x4f00e410                    // movi v16.16b, #0
  .long 0x4f00e411                    // movi v17.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e3e1e10                    // eor v16.16b, v16.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0xfd40203c                    // ldr d28, [x1, #64]
  .long 0xfd40205d                    // ldr d29, [x2, #64]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e3e1e10                    // eor v16.16b, v16.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e31                    // eor v17.16b, v17.16b, v26.16b
  .long 0xfd40243c                    // ldr d28, [x1, #72]
  .long 0xfd40245d                    // ldr d29, [x2, #72]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e3e1e10                    // eor v16.16b, v16.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0x6e3e1e31                    // eor v17.16b, v17.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e31                    // eor v17.16b, v17.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1e10                    // eor v16.16b, v16.16b, v30.16b
  .long 0xfd40203c                    // ldr d28, [x1, #64]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40205d                    // ldr d29, [x2, #64]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1e10                    // eor v16.16b, v16.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1e31                    // eor v17.16b, v17.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40205d                    // ldr d29, [x2, #64]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40103c                    // ldr d28, [x1, #32]
  .long 0xfd40245d                    // ldr d29, [x2, #72]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40043b                    // ldr d27, [x1, #8]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40185b                    // ldr d27, [x2, #48]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0xfd40003c                    // ldr d28, [x1]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40145d                    // ldr d29, [x2, #40]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40083b                    // ldr d27, [x1, #16]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd401c5b                    // ldr d27, [x2, #56]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40043c                    // ldr d28, [x1, #8]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40185d                    // ldr d29, [x2, #48]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd400c3b                    // ldr d27, [x1, #24]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0xfd40205b                    // ldr d27, [x2, #64]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0xfd40083c                    // ldr d28, [x1, #16]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd401c5d                    // ldr d29, [x2, #56]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd400c3c                    // ldr d28, [x1, #24]
  .long 0xfd40103b                    // ldr d27, [x1, #32]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40205d                    // ldr d29, [x2, #64]
  .long 0xfd40245b                    // ldr d27, [x2, #72]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40203c                    // ldr d28, [x1, #64]
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40243c                    // ldr d28, [x1, #72]
  .long 0xfd40105d                    // ldr d29, [x2, #32]
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40183b                    // ldr d27, [x1, #48]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40045b                    // ldr d27, [x2, #8]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0xfd40143c                    // ldr d28, [x1, #40]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40005d                    // ldr d29, [x2]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd401c3b                    // ldr d27, [x1, #56]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40085b                    // ldr d27, [x2, #16]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0xfd40183c                    // ldr d28, [x1, #48]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40045d                    // ldr d29, [x2, #8]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd40203b                    // ldr d27, [x1, #64]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd400c5b                    // ldr d27, [x2, #24]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0xfd401c3c                    // ldr d28, [x1, #56]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd40085d                    // ldr d29, [x2, #16]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e1e433a                    // ext v26.16b, v25.16b, v30.16b, #8
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e1943da                    // ext v26.16b, v30.16b, v25.16b, #8
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0xfd40203c                    // ldr d28, [x1, #64]
  .long 0xfd40243b                    // ldr d27, [x1, #72]
  .long 0x6e3b1f9c                    // eor v28.16b, v28.16b, v27.16b
  .long 0xfd400c5d                    // ldr d29, [x2, #24]
  .long 0xfd40105b                    // ldr d27, [x2, #32]
  .long 0x6e3b1fbd                    // eor v29.16b, v29.16b, v27.16b
  .long 0x0efde39e                    // pmull v30.1q, v28.1d, v29.1d
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  .long 0x3d802070                    // str q16, [x3, #128]
  .long 0x3d802471                    // str q17, [x3, #144]
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_BINPOLY_EVEN}
  .long 0xd341fc04                    // lsr x4, x0, #1
  // x4 = L = ALen >> 1
  .long 0x4f00e419                    // movi v25.16b, #0
  // Diagonal: for i = 0..L-1, ZZ[2i], ZZ[2i+1] = Mul2x2(X[i], Y[i]).
  mov x5, #0
.Lbpeven_diag:
  cmp x5, x4
  b.ge .Lbpeven_diag_done
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x1, x6
  .long 0x3dc000e0                    // ldr q0, [x7]
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x2, x6
  .long 0x3dc000e1                    // ldr q1, [x7]
  // ---- inline: 2x2-limb carryless Karatsuba (v0, v1 -> v16, v17) ----
  .long 0x6e004002                    // ext v2.16b, v0.16b, v0.16b, #8
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e014023                    // ext v3.16b, v1.16b, v1.16b, #8
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x0ee1e004                    // pmull v4.1q, v0.1d, v1.1d
  .long 0x4ee1e005                    // pmull2 v5.1q, v0.2d, v1.2d
  .long 0x0ee3e046                    // pmull v6.1q, v2.1d, v3.1d
  .long 0x6e251c87                    // eor v7.16b, v4.16b, v5.16b
  .long 0x6e261ce7                    // eor v7.16b, v7.16b, v6.16b
  .long 0x6e074322                    // ext v2.16b, v25.16b, v7.16b, #8
  .long 0x6e221c90                    // eor v16.16b, v4.16b, v2.16b
  .long 0x6e1940e3                    // ext v3.16b, v7.16b, v25.16b, #8
  .long 0x6e231cb1                    // eor v17.16b, v5.16b, v3.16b
  .long 0xd37be8a6                    // lsl x6, x5, #5
  add x7, x3, x6
  .long 0x3d8000f0                    // str q16, [x7]
  .long 0x3d8004f1                    // str q17, [x7, #16]
  add x5, x5, #1
  b .Lbpeven_diag
.Lbpeven_diag_done:
  // Streak: V0 = ZZ[0], V1 = ZZ[1]; for i = 1..L-1:
  //   V0 ^= ZZ[2i]; ZZ[i] = V0 ^ V1; V1 ^= ZZ[2i+1]
  .long 0x3dc00062                    // ldr q2, [x3]
  .long 0x3dc00463                    // ldr q3, [x3, #16]
  mov x5, #1
.Lbpeven_streak:
  cmp x5, x4
  b.ge .Lbpeven_streak_done
  .long 0xd37be8a6                    // lsl x6, x5, #5
  add x7, x3, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e231c45                    // eor v5.16b, v2.16b, v3.16b
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x8, x3, x6
  .long 0x3d800105                    // str q5, [x8]
  .long 0x3dc004e4                    // ldr q4, [x7, #16]
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  add x5, x5, #1
  b .Lbpeven_streak
.Lbpeven_streak_done:
  // W = V0 ^ V1; ZZ[L+i] = ZZ[i] ^ W for i = 0..L-1.
  .long 0x6e231c47                    // eor v7.16b, v2.16b, v3.16b
  mov x5, #0
.Lbpeven_fold:
  cmp x5, x4
  b.ge .Lbpeven_fold_done
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x3, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e271c84                    // eor v4.16b, v4.16b, v7.16b
  add x8, x4, x5
  .long 0xd37ced06                    // lsl x6, x8, #4
  add x8, x3, x6
  .long 0x3d800104                    // str q4, [x8]
  add x5, x5, #1
  b .Lbpeven_fold
.Lbpeven_fold_done:
  // Cross products: last = L-1; zPos = 1..2*last-1.
  sub x13, x4, #1
  cmp x13, #0
  b.le .Lbpeven_done
  .long 0xd37ff9ac                    // lsl x12, x13, #1
  sub x12, x12, #1
  mov x10, #1
.Lbpeven_zpos:
  cmp x10, x12
  b.gt .Lbpeven_done
  cmp x10, x13
  .long 0x9a8dd14b                    // csel x11, x10, x13, le
  // x11 = hi = min(last, zPos)
  sub x5, x10, x11
  // x5 = lo = zPos - hi
.Lbpeven_pair:
  cmp x5, x11
  b.ge .Lbpeven_next_zpos
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x1, x6
  .long 0x3dc000e0                    // ldr q0, [x7]
  .long 0xd37ced66                    // lsl x6, x11, #4
  add x7, x1, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x2, x6
  .long 0x3dc000e1                    // ldr q1, [x7]
  .long 0xd37ced66                    // lsl x6, x11, #4
  add x7, x2, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  // ---- inline: 2x2-limb carryless Karatsuba (v0, v1 -> v16, v17) ----
  .long 0x6e004002                    // ext v2.16b, v0.16b, v0.16b, #8
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e014023                    // ext v3.16b, v1.16b, v1.16b, #8
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x0ee1e004                    // pmull v4.1q, v0.1d, v1.1d
  .long 0x4ee1e005                    // pmull2 v5.1q, v0.2d, v1.2d
  .long 0x0ee3e046                    // pmull v6.1q, v2.1d, v3.1d
  .long 0x6e251c87                    // eor v7.16b, v4.16b, v5.16b
  .long 0x6e261ce7                    // eor v7.16b, v7.16b, v6.16b
  .long 0x6e074322                    // ext v2.16b, v25.16b, v7.16b, #8
  .long 0x6e221c90                    // eor v16.16b, v4.16b, v2.16b
  .long 0x6e1940e3                    // ext v3.16b, v7.16b, v25.16b, #8
  .long 0x6e231cb1                    // eor v17.16b, v5.16b, v3.16b
  .long 0xd37ced46                    // lsl x6, x10, #4
  add x7, x3, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e301c84                    // eor v4.16b, v4.16b, v16.16b
  .long 0x3d8000e4                    // str q4, [x7]
  .long 0x3dc004e4                    // ldr q4, [x7, #16]
  .long 0x6e311c84                    // eor v4.16b, v4.16b, v17.16b
  .long 0x3d8004e4                    // str q4, [x7, #16]
  add x5, x5, #1
  sub x11, x11, #1
  b .Lbpeven_pair
.Lbpeven_next_zpos:
  add x10, x10, #1
  b .Lbpeven_zpos
.Lbpeven_done:
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_BINPOLY_ODD}
  .long 0xd341fc04                    // lsr x4, x0, #1
  // x4 = L = ALen >> 1
  .long 0x4f00e419                    // movi v25.16b, #0
  // Diagonal full pairs: for i = 0..L-1.
  mov x5, #0
.Lbpodd_diag:
  cmp x5, x4
  b.ge .Lbpodd_diag_done
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x1, x6
  .long 0x3dc000e0                    // ldr q0, [x7]
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x2, x6
  .long 0x3dc000e1                    // ldr q1, [x7]
  // ---- inline: 2x2-limb carryless Karatsuba (v0, v1 -> v16, v17) ----
  .long 0x6e004002                    // ext v2.16b, v0.16b, v0.16b, #8
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e014023                    // ext v3.16b, v1.16b, v1.16b, #8
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x0ee1e004                    // pmull v4.1q, v0.1d, v1.1d
  .long 0x4ee1e005                    // pmull2 v5.1q, v0.2d, v1.2d
  .long 0x0ee3e046                    // pmull v6.1q, v2.1d, v3.1d
  .long 0x6e251c87                    // eor v7.16b, v4.16b, v5.16b
  .long 0x6e261ce7                    // eor v7.16b, v7.16b, v6.16b
  .long 0x6e074322                    // ext v2.16b, v25.16b, v7.16b, #8
  .long 0x6e221c90                    // eor v16.16b, v4.16b, v2.16b
  .long 0x6e1940e3                    // ext v3.16b, v7.16b, v25.16b, #8
  .long 0x6e231cb1                    // eor v17.16b, v5.16b, v3.16b
  .long 0xd37be8a6                    // lsl x6, x5, #5
  add x7, x3, x6
  .long 0x3d8000f0                    // str q16, [x7]
  .long 0x3d8004f1                    // str q17, [x7, #16]
  add x5, x5, #1
  b .Lbpodd_diag
.Lbpodd_diag_done:
  // Tail diagonal at ZZ[2L]: Mul((x[2L], 0), (y[2L], 0)).
  .long 0xd37cec86                    // lsl x6, x4, #4
  add x7, x1, x6
  .long 0xfd4000e0                    // ldr d0, [x7]
  .long 0xd37cec86                    // lsl x6, x4, #4
  add x7, x2, x6
  .long 0xfd4000e1                    // ldr d1, [x7]
  .long 0x0ee1e010                    // pmull v16.1q, v0.1d, v1.1d
  .long 0xd37be886                    // lsl x6, x4, #5
  add x7, x3, x6
  .long 0x3d8000f0                    // str q16, [x7]
  // ALen = 1 special case (L = 0): only tail diagonal exists.
  cbz x4, .Lbpodd_done
  // Streak: V0 = ZZ[0], V1 = ZZ[1]; for i = 1..L:
  //   V0 ^= ZZ[2i]; ZZ[i] = V0 ^ V1; if i <> L then V1 ^= ZZ[2i+1]
  .long 0x3dc00062                    // ldr q2, [x3]
  .long 0x3dc00463                    // ldr q3, [x3, #16]
  mov x5, #1
.Lbpodd_streak:
  cmp x5, x4
  b.gt .Lbpodd_streak_done
  .long 0xd37be8a6                    // lsl x6, x5, #5
  add x7, x3, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x6e231c45                    // eor v5.16b, v2.16b, v3.16b
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x8, x3, x6
  .long 0x3d800105                    // str q5, [x8]
  cmp x5, x4
  b.eq .Lbpodd_streak_nov1
  .long 0x3dc004e4                    // ldr q4, [x7, #16]
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
.Lbpodd_streak_nov1:
  add x5, x5, #1
  b .Lbpodd_streak
.Lbpodd_streak_done:
  // W = V0 ^ V1; ZZ[(L+1)+i] = ZZ[i] ^ W for i = 0..L-1.
  .long 0x6e231c47                    // eor v7.16b, v2.16b, v3.16b
  mov x5, #0
.Lbpodd_fold:
  cmp x5, x4
  b.ge .Lbpodd_fold_done
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x3, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e271c84                    // eor v4.16b, v4.16b, v7.16b
  add x8, x4, x5
  add x8, x8, #1
  .long 0xd37ced06                    // lsl x6, x8, #4
  add x8, x3, x6
  .long 0x3d800104                    // str q4, [x8]
  add x5, x5, #1
  b .Lbpodd_fold
.Lbpodd_fold_done:
  // Cross products: last = L; zPos = 1..2*last-1,
  // using tail-form loads when hi = last.
  mov x13, x4
  .long 0xd37ff9ac                    // lsl x12, x13, #1
  sub x12, x12, #1
  mov x10, #1
.Lbpodd_zpos:
  cmp x10, x12
  b.gt .Lbpodd_done
  cmp x10, x13
  .long 0x9a8dd14b                    // csel x11, x10, x13, le
  // x11 = hi = min(last, zPos)
  sub x5, x10, x11
  // x5 = lo = zPos - hi
.Lbpodd_pair:
  cmp x5, x11
  b.ge .Lbpodd_next_zpos
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x1, x6
  .long 0x3dc000e0                    // ldr q0, [x7]
  cmp x11, x13
  b.ne .Lbpodd_xhi_full
  .long 0xd37ceda6                    // lsl x6, x13, #4
  add x7, x1, x6
  .long 0xfd4000e4                    // ldr d4, [x7]
  b .Lbpodd_xhi_done
.Lbpodd_xhi_full:
  .long 0xd37ced66                    // lsl x6, x11, #4
  add x7, x1, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
.Lbpodd_xhi_done:
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0xd37ceca6                    // lsl x6, x5, #4
  add x7, x2, x6
  .long 0x3dc000e1                    // ldr q1, [x7]
  cmp x11, x13
  b.ne .Lbpodd_yhi_full
  .long 0xd37ceda6                    // lsl x6, x13, #4
  add x7, x2, x6
  .long 0xfd4000e4                    // ldr d4, [x7]
  b .Lbpodd_yhi_done
.Lbpodd_yhi_full:
  .long 0xd37ced66                    // lsl x6, x11, #4
  add x7, x2, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
.Lbpodd_yhi_done:
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  // ---- inline: 2x2-limb carryless Karatsuba (v0, v1 -> v16, v17) ----
  .long 0x6e004002                    // ext v2.16b, v0.16b, v0.16b, #8
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x6e014023                    // ext v3.16b, v1.16b, v1.16b, #8
  .long 0x6e211c63                    // eor v3.16b, v3.16b, v1.16b
  .long 0x0ee1e004                    // pmull v4.1q, v0.1d, v1.1d
  .long 0x4ee1e005                    // pmull2 v5.1q, v0.2d, v1.2d
  .long 0x0ee3e046                    // pmull v6.1q, v2.1d, v3.1d
  .long 0x6e251c87                    // eor v7.16b, v4.16b, v5.16b
  .long 0x6e261ce7                    // eor v7.16b, v7.16b, v6.16b
  .long 0x6e074322                    // ext v2.16b, v25.16b, v7.16b, #8
  .long 0x6e221c90                    // eor v16.16b, v4.16b, v2.16b
  .long 0x6e1940e3                    // ext v3.16b, v7.16b, v25.16b, #8
  .long 0x6e231cb1                    // eor v17.16b, v5.16b, v3.16b
  .long 0xd37ced46                    // lsl x6, x10, #4
  add x7, x3, x6
  .long 0x3dc000e4                    // ldr q4, [x7]
  .long 0x6e301c84                    // eor v4.16b, v4.16b, v16.16b
  .long 0x3d8000e4                    // str q4, [x7]
  .long 0x3dc004e4                    // ldr q4, [x7, #16]
  .long 0x6e311c84                    // eor v4.16b, v4.16b, v17.16b
  .long 0x3d8004e4                    // str q4, [x7, #16]
  add x5, x5, #1
  sub x11, x11, #1
  b .Lbpodd_pair
.Lbpodd_next_zpos:
  add x10, x10, #1
  b .Lbpodd_zpos
.Lbpodd_done:
  ret
    {$ELSE}
      {$IFDEF CRYPTOLIB_BINPOLY_SQUARE}
  cbz x0, .Lbpsq_done
.Lbpsq_loop:
  .long 0xfd400020                    // ldr d0, [x1]
  .long 0x0ee0e000                    // pmull v0.1q, v0.1d, v0.1d
  .long 0x3d800040                    // str q0, [x2]
  add x1, x1, #8
  add x2, x2, #16
  sub x0, x0, #1
  cbnz x0, .Lbpsq_loop
.Lbpsq_done:
  ret
      {$ELSE}
      {$FATAL Exactly one of CRYPTOLIB_BINPOLY_SMALL, CRYPTOLIB_BINPOLY_EVEN, CRYPTOLIB_BINPOLY_ODD, CRYPTOLIB_BINPOLY_SQUARE must be defined before including this file}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
