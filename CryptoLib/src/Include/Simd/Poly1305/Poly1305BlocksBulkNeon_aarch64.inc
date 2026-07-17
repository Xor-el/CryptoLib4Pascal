// Poly1305 2-way NEON bulk MAC kernel (aarch64), matching the contract of
// the 2-lane chain in Poly1305BlocksBulkSse2Core_x86_64.inc.
// -------------------------------------------------------------------
// Same radix-2^26 field arithmetic (5x5 schoolbook multiply mod 2^130-5
// with the 5*r wraparound), 2 blocks per iteration against the same
// 160-byte r/r^2 power table, the same serial lazy reduction chain, the
// same tail multiply by [r^2, r^1] and 2-lane horizontal fold. On NEON
// the multiply inputs live as 32-bit lanes, so each of the 25 products is
// one umull/umlal into a 64-bit accumulator lane; the reduction runs on
// the 64-bit accumulators and narrows back to the 32-bit multiply form
// at the end of the chain (the 5*carry fold can exceed 32 bits). The
// power-table rows need no aligned staging copy, and no callee-saved
// vector registers are touched, so the kernel is frame-free.
//
// On entry (after ClpSimdProc5Begin_aarch64.inc):
//   x0 = ACtx      (72-byte R/S/H/K state); x1 = APowTable (160-byte r/r^2)
//   x2 = AInp; x3 = ALen (multiple of 32, >= 32); x4 = APad (ignored)
//
// Power table: row j at [x1 + 16*j]; rows 0..4 r-limbs [r2,r2,r2,r1],
// rows 5..8 s-limbs (5*r), row 9 pad. Bulk broadcasts the r^2 limb;
// the tail reads [+16*j+4] and un-interleaves to ([r^2, r^1]).
//
// Register map: v0..v4 H limbs (.2s), v5/v7 mask26 (.2d/.4s), v6 padbit,
// v16..v24 resident bulk rows, v25..v29 accumulators, v30/v31 scratch;
// v8..v15 and x18+ untouched.
//
// Reference: Goll/Gueron, "Vectorization of Poly1305 Message Authentication
// Code" - the radix-2^26 multi-lane construction that this 2-lane form
// shares with the x86 kernels.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  // ---- Constants: mask26 (.2d / .4s), padbit ----
  .long 0x6ea58ca5                    // cmeq v5.4s, v5.4s, v5.4s
  .long 0x6ea78ce7                    // cmeq v7.4s, v7.4s, v7.4s
  .long 0x6ea68cc6                    // cmeq v6.4s, v6.4s, v6.4s
  .long 0x6f5a04a5                    // ushr v5.2d, v5.2d, #38
  .long 0x6f3a04e7                    // ushr v7.4s, v7.4s, #6
  .long 0x6f4104c6                    // ushr v6.2d, v6.2d, #63
  .long 0x4f5854c6                    // shl v6.2d, v6.2d, #24
  // ---- Preload bulk rows: broadcast r^2 / 5*r^2 limbs ----
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x0e040cd0                    // dup v16.2s, w6
  .long 0xb9401026                    // ldr w6, [x1, #16]
  .long 0x0e040cd1                    // dup v17.2s, w6
  .long 0xb9402026                    // ldr w6, [x1, #32]
  .long 0x0e040cd2                    // dup v18.2s, w6
  .long 0xb9403026                    // ldr w6, [x1, #48]
  .long 0x0e040cd3                    // dup v19.2s, w6
  .long 0xb9404026                    // ldr w6, [x1, #64]
  .long 0x0e040cd4                    // dup v20.2s, w6
  .long 0xb9405026                    // ldr w6, [x1, #80]
  .long 0x0e040cd5                    // dup v21.2s, w6
  .long 0xb9406026                    // ldr w6, [x1, #96]
  .long 0x0e040cd6                    // dup v22.2s, w6
  .long 0xb9407026                    // ldr w6, [x1, #112]
  .long 0x0e040cd7                    // dup v23.2s, w6
  .long 0xb9408026                    // ldr w6, [x1, #128]
  .long 0x0e040cd8                    // dup v24.2s, w6
  // ---- Load H0..H4 into lane 0 ----
  .long 0xbd402400                    // ldr s0, [x0, #36]
  .long 0xbd402801                    // ldr s1, [x0, #40]
  .long 0xbd402c02                    // ldr s2, [x0, #44]
  .long 0xbd403003                    // ldr s3, [x0, #48]
  .long 0xbd403404                    // ldr s4, [x0, #52]
  // ---- Absorb next 2 blocks ----
  .long 0x3dc0005e                    // ldr q30, [x2]
  .long 0x3dc0045f                    // ldr q31, [x2, #16]
  add x2, x2, #32
  .long 0x6e1e33db                    // ext v27.16b, v30.16b, v30.16b, #6
  .long 0x6e1f33fc                    // ext v28.16b, v31.16b, v31.16b, #6
  .long 0x4edf7bda                    // zip2 v26.2d, v30.2d, v31.2d
  .long 0x4edf3bd9                    // zip1 v25.2d, v30.2d, v31.2d
  .long 0x4edc3b7b                    // zip1 v27.2d, v27.2d, v28.2d
  .long 0x6f66073c                    // ushr v28.2d, v25.2d, #26
  .long 0x4e251f39                    // and v25.16b, v25.16b, v5.16b
  .long 0x4e251f9c                    // and v28.16b, v28.16b, v5.16b
  .long 0x6f62077d                    // ushr v29.2d, v27.2d, #30
  .long 0x6f7c077b                    // ushr v27.2d, v27.2d, #4
  .long 0x4e251f7b                    // and v27.16b, v27.16b, v5.16b
  .long 0x4e251fbd                    // and v29.16b, v29.16b, v5.16b
  .long 0x6f58075a                    // ushr v26.2d, v26.2d, #40
  .long 0x4ea61f5a                    // orr v26.16b, v26.16b, v6.16b
  .long 0x0ea12b3e                    // xtn v30.2s, v25.2d
  .long 0x4ebe8400                    // add v0.4s, v0.4s, v30.4s
  .long 0x0ea12b9e                    // xtn v30.2s, v28.2d
  .long 0x4ebe8421                    // add v1.4s, v1.4s, v30.4s
  .long 0x0ea12b7e                    // xtn v30.2s, v27.2d
  .long 0x4ebe8442                    // add v2.4s, v2.4s, v30.4s
  .long 0x0ea12bbe                    // xtn v30.2s, v29.2d
  .long 0x4ebe8463                    // add v3.4s, v3.4s, v30.4s
  .long 0x0ea12b5e                    // xtn v30.2s, v26.2d
  .long 0x4ebe8484                    // add v4.4s, v4.4s, v30.4s
  subs x3, x3, #32
  b.eq .Lpoly1305_neon_tail
.Lpoly1305_neon_loop:
  // ---- Bulk: H *= r^2 (broadcast rows), 25 umull/umlal ----
  .long 0x2eb4c01d                    // umull v29.2d, v0.2s, v20.2s
  .long 0x2eb3803d                    // umlal v29.2d, v1.2s, v19.2s
  .long 0x2eb2805d                    // umlal v29.2d, v2.2s, v18.2s
  .long 0x2eb1807d                    // umlal v29.2d, v3.2s, v17.2s
  .long 0x2eb0809d                    // umlal v29.2d, v4.2s, v16.2s
  .long 0x2eb3c01c                    // umull v28.2d, v0.2s, v19.2s
  .long 0x2eb2803c                    // umlal v28.2d, v1.2s, v18.2s
  .long 0x2eb1805c                    // umlal v28.2d, v2.2s, v17.2s
  .long 0x2eb0807c                    // umlal v28.2d, v3.2s, v16.2s
  .long 0x2eb8809c                    // umlal v28.2d, v4.2s, v24.2s
  .long 0x2eb2c01b                    // umull v27.2d, v0.2s, v18.2s
  .long 0x2eb1803b                    // umlal v27.2d, v1.2s, v17.2s
  .long 0x2eb0805b                    // umlal v27.2d, v2.2s, v16.2s
  .long 0x2eb8807b                    // umlal v27.2d, v3.2s, v24.2s
  .long 0x2eb7809b                    // umlal v27.2d, v4.2s, v23.2s
  .long 0x2eb1c01a                    // umull v26.2d, v0.2s, v17.2s
  .long 0x2eb0803a                    // umlal v26.2d, v1.2s, v16.2s
  .long 0x2eb8805a                    // umlal v26.2d, v2.2s, v24.2s
  .long 0x2eb7807a                    // umlal v26.2d, v3.2s, v23.2s
  .long 0x2eb6809a                    // umlal v26.2d, v4.2s, v22.2s
  .long 0x2eb0c019                    // umull v25.2d, v0.2s, v16.2s
  .long 0x2eb88039                    // umlal v25.2d, v1.2s, v24.2s
  .long 0x2eb78059                    // umlal v25.2d, v2.2s, v23.2s
  .long 0x2eb68079                    // umlal v25.2d, v3.2s, v22.2s
  .long 0x2eb58099                    // umlal v25.2d, v4.2s, v21.2s
  // ---- Lazy reduce D -> H ----
  .long 0x6f66073e                    // ushr v30.2d, v25.2d, #26
  .long 0x4e251f39                    // and v25.16b, v25.16b, v5.16b
  .long 0x4efe875a                    // add v26.2d, v26.2d, v30.2d
  .long 0x6f66075e                    // ushr v30.2d, v26.2d, #26
  .long 0x4e251f5a                    // and v26.16b, v26.16b, v5.16b
  .long 0x4efe877b                    // add v27.2d, v27.2d, v30.2d
  .long 0x6f66077e                    // ushr v30.2d, v27.2d, #26
  .long 0x4e251f7b                    // and v27.16b, v27.16b, v5.16b
  .long 0x4efe879c                    // add v28.2d, v28.2d, v30.2d
  .long 0x6f66079e                    // ushr v30.2d, v28.2d, #26
  .long 0x4e251f9c                    // and v28.16b, v28.16b, v5.16b
  .long 0x4efe87bd                    // add v29.2d, v29.2d, v30.2d
  .long 0x6f6607be                    // ushr v30.2d, v29.2d, #26
  .long 0x4e251fbd                    // and v29.16b, v29.16b, v5.16b
  .long 0x4f4257df                    // shl v31.2d, v30.2d, #2
  .long 0x4eff87de                    // add v30.2d, v30.2d, v31.2d
  .long 0x4efe8739                    // add v25.2d, v25.2d, v30.2d
  .long 0x6f66073e                    // ushr v30.2d, v25.2d, #26
  .long 0x4e251f39                    // and v25.16b, v25.16b, v5.16b
  .long 0x4efe875a                    // add v26.2d, v26.2d, v30.2d
  .long 0x0ea12b20                    // xtn v0.2s, v25.2d
  .long 0x0ea12b41                    // xtn v1.2s, v26.2d
  .long 0x0ea12b62                    // xtn v2.2s, v27.2d
  .long 0x0ea12b83                    // xtn v3.2s, v28.2d
  .long 0x0ea12ba4                    // xtn v4.2s, v29.2d
  // ---- Absorb next 2 blocks ----
  .long 0x3dc0005e                    // ldr q30, [x2]
  .long 0x3dc0045f                    // ldr q31, [x2, #16]
  add x2, x2, #32
  .long 0x6e1e33db                    // ext v27.16b, v30.16b, v30.16b, #6
  .long 0x6e1f33fc                    // ext v28.16b, v31.16b, v31.16b, #6
  .long 0x4edf7bda                    // zip2 v26.2d, v30.2d, v31.2d
  .long 0x4edf3bd9                    // zip1 v25.2d, v30.2d, v31.2d
  .long 0x4edc3b7b                    // zip1 v27.2d, v27.2d, v28.2d
  .long 0x6f66073c                    // ushr v28.2d, v25.2d, #26
  .long 0x4e251f39                    // and v25.16b, v25.16b, v5.16b
  .long 0x4e251f9c                    // and v28.16b, v28.16b, v5.16b
  .long 0x6f62077d                    // ushr v29.2d, v27.2d, #30
  .long 0x6f7c077b                    // ushr v27.2d, v27.2d, #4
  .long 0x4e251f7b                    // and v27.16b, v27.16b, v5.16b
  .long 0x4e251fbd                    // and v29.16b, v29.16b, v5.16b
  .long 0x6f58075a                    // ushr v26.2d, v26.2d, #40
  .long 0x4ea61f5a                    // orr v26.16b, v26.16b, v6.16b
  .long 0x0ea12b3e                    // xtn v30.2s, v25.2d
  .long 0x4ebe8400                    // add v0.4s, v0.4s, v30.4s
  .long 0x0ea12b9e                    // xtn v30.2s, v28.2d
  .long 0x4ebe8421                    // add v1.4s, v1.4s, v30.4s
  .long 0x0ea12b7e                    // xtn v30.2s, v27.2d
  .long 0x4ebe8442                    // add v2.4s, v2.4s, v30.4s
  .long 0x0ea12bbe                    // xtn v30.2s, v29.2d
  .long 0x4ebe8463                    // add v3.4s, v3.4s, v30.4s
  .long 0x0ea12b5e                    // xtn v30.2s, v26.2d
  .long 0x4ebe8484                    // add v4.4s, v4.4s, v30.4s
  subs x3, x3, #32
  b.ne .Lpoly1305_neon_loop
.Lpoly1305_neon_tail:
  // ---- Tail: H *= [r^2, r^1] (shifted table reads) ----
  .long 0x3cc4403e                    // ldur q30, [x1, #68]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec01d                    // umull v29.2d, v0.2s, v30.2s
  .long 0x3cc3403e                    // ldur q30, [x1, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe803d                    // umlal v29.2d, v1.2s, v30.2s
  .long 0x3cc2403e                    // ldur q30, [x1, #36]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe805d                    // umlal v29.2d, v2.2s, v30.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe807d                    // umlal v29.2d, v3.2s, v30.2s
  .long 0x3cc0403e                    // ldur q30, [x1, #4]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe809d                    // umlal v29.2d, v4.2s, v30.2s
  .long 0x3cc3403e                    // ldur q30, [x1, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec01c                    // umull v28.2d, v0.2s, v30.2s
  .long 0x3cc2403e                    // ldur q30, [x1, #36]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe803c                    // umlal v28.2d, v1.2s, v30.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe805c                    // umlal v28.2d, v2.2s, v30.2s
  .long 0x3cc0403e                    // ldur q30, [x1, #4]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe807c                    // umlal v28.2d, v3.2s, v30.2s
  .long 0x3cc8403e                    // ldur q30, [x1, #132]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe809c                    // umlal v28.2d, v4.2s, v30.2s
  .long 0x3cc2403e                    // ldur q30, [x1, #36]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec01b                    // umull v27.2d, v0.2s, v30.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe803b                    // umlal v27.2d, v1.2s, v30.2s
  .long 0x3cc0403e                    // ldur q30, [x1, #4]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe805b                    // umlal v27.2d, v2.2s, v30.2s
  .long 0x3cc8403e                    // ldur q30, [x1, #132]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe807b                    // umlal v27.2d, v3.2s, v30.2s
  .long 0x3cc7403e                    // ldur q30, [x1, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe809b                    // umlal v27.2d, v4.2s, v30.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec01a                    // umull v26.2d, v0.2s, v30.2s
  .long 0x3cc0403e                    // ldur q30, [x1, #4]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe803a                    // umlal v26.2d, v1.2s, v30.2s
  .long 0x3cc8403e                    // ldur q30, [x1, #132]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe805a                    // umlal v26.2d, v2.2s, v30.2s
  .long 0x3cc7403e                    // ldur q30, [x1, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe807a                    // umlal v26.2d, v3.2s, v30.2s
  .long 0x3cc6403e                    // ldur q30, [x1, #100]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe809a                    // umlal v26.2d, v4.2s, v30.2s
  .long 0x3cc0403e                    // ldur q30, [x1, #4]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec019                    // umull v25.2d, v0.2s, v30.2s
  .long 0x3cc8403e                    // ldur q30, [x1, #132]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8039                    // umlal v25.2d, v1.2s, v30.2s
  .long 0x3cc7403e                    // ldur q30, [x1, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8059                    // umlal v25.2d, v2.2s, v30.2s
  .long 0x3cc6403e                    // ldur q30, [x1, #100]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8079                    // umlal v25.2d, v3.2s, v30.2s
  .long 0x3cc5403e                    // ldur q30, [x1, #84]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8099                    // umlal v25.2d, v4.2s, v30.2s
  // ---- Lazy reduce D -> H ----
  .long 0x6f66073e                    // ushr v30.2d, v25.2d, #26
  .long 0x4e251f39                    // and v25.16b, v25.16b, v5.16b
  .long 0x4efe875a                    // add v26.2d, v26.2d, v30.2d
  .long 0x6f66075e                    // ushr v30.2d, v26.2d, #26
  .long 0x4e251f5a                    // and v26.16b, v26.16b, v5.16b
  .long 0x4efe877b                    // add v27.2d, v27.2d, v30.2d
  .long 0x6f66077e                    // ushr v30.2d, v27.2d, #26
  .long 0x4e251f7b                    // and v27.16b, v27.16b, v5.16b
  .long 0x4efe879c                    // add v28.2d, v28.2d, v30.2d
  .long 0x6f66079e                    // ushr v30.2d, v28.2d, #26
  .long 0x4e251f9c                    // and v28.16b, v28.16b, v5.16b
  .long 0x4efe87bd                    // add v29.2d, v29.2d, v30.2d
  .long 0x6f6607be                    // ushr v30.2d, v29.2d, #26
  .long 0x4e251fbd                    // and v29.16b, v29.16b, v5.16b
  .long 0x4f4257df                    // shl v31.2d, v30.2d, #2
  .long 0x4eff87de                    // add v30.2d, v30.2d, v31.2d
  .long 0x4efe8739                    // add v25.2d, v25.2d, v30.2d
  .long 0x6f66073e                    // ushr v30.2d, v25.2d, #26
  .long 0x4e251f39                    // and v25.16b, v25.16b, v5.16b
  .long 0x4efe875a                    // add v26.2d, v26.2d, v30.2d
  .long 0x0ea12b20                    // xtn v0.2s, v25.2d
  .long 0x0ea12b41                    // xtn v1.2s, v26.2d
  .long 0x0ea12b62                    // xtn v2.2s, v27.2d
  .long 0x0ea12b83                    // xtn v3.2s, v28.2d
  .long 0x0ea12ba4                    // xtn v4.2s, v29.2d
  // ---- Horizontal fold 2 lanes -> 1, final reduce, store ----
  .long 0x0ea0bc00                    // addp v0.2s, v0.2s, v0.2s
  .long 0x0ea1bc21                    // addp v1.2s, v1.2s, v1.2s
  .long 0x0ea2bc42                    // addp v2.2s, v2.2s, v2.2s
  .long 0x0ea3bc63                    // addp v3.2s, v3.2s, v3.2s
  .long 0x0ea4bc84                    // addp v4.2s, v4.2s, v4.2s
  .long 0x6f26041e                    // ushr v30.4s, v0.4s, #26
  .long 0x4e271c00                    // and v0.16b, v0.16b, v7.16b
  .long 0x4ebe8421                    // add v1.4s, v1.4s, v30.4s
  .long 0x6f26043e                    // ushr v30.4s, v1.4s, #26
  .long 0x4e271c21                    // and v1.16b, v1.16b, v7.16b
  .long 0x4ebe8442                    // add v2.4s, v2.4s, v30.4s
  .long 0x6f26045e                    // ushr v30.4s, v2.4s, #26
  .long 0x4e271c42                    // and v2.16b, v2.16b, v7.16b
  .long 0x4ebe8463                    // add v3.4s, v3.4s, v30.4s
  .long 0x6f26047e                    // ushr v30.4s, v3.4s, #26
  .long 0x4e271c63                    // and v3.16b, v3.16b, v7.16b
  .long 0x4ebe8484                    // add v4.4s, v4.4s, v30.4s
  .long 0x6f26049e                    // ushr v30.4s, v4.4s, #26
  .long 0x4e271c84                    // and v4.16b, v4.16b, v7.16b
  .long 0x4f2257df                    // shl v31.4s, v30.4s, #2
  .long 0x4ebf87de                    // add v30.4s, v30.4s, v31.4s
  .long 0x4ebe8400                    // add v0.4s, v0.4s, v30.4s
  .long 0x6f26041e                    // ushr v30.4s, v0.4s, #26
  .long 0x4e271c00                    // and v0.16b, v0.16b, v7.16b
  .long 0x4ebe8421                    // add v1.4s, v1.4s, v30.4s
  .long 0xbd002400                    // str s0, [x0, #36]
  .long 0xbd002801                    // str s1, [x0, #40]
  .long 0xbd002c02                    // str s2, [x0, #44]
  .long 0xbd003003                    // str s3, [x0, #48]
  .long 0xbd003404                    // str s4, [x0, #52]
  ret
