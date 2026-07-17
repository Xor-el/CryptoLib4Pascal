// Poly1305 4-way NEON bulk MAC kernel (aarch64), matching the contract of
// the 4-way chain in Poly1305BlocksBulkAvx2Core_x86_64.inc.
// -------------------------------------------------------------------
// Same radix-2^26 field arithmetic (5x5 schoolbook multiply mod 2^130-5
// with the 5*r wraparound), 4 blocks per iteration against the same
// 320-byte r^1..r^4 power table, the same two-interleaved-chain lazy
// reduction (low D0->D1->D2->D3->H4, high D3->D4->H0->H1), the same tail
// multiply by [r^4, r^3, r^2, r^1] and 4-lane horizontal fold. The four
// block lanes live as two 128-bit halves (blocks 0/1, 2/3); multiply
// inputs are 32-bit lanes so each of the 50 products per iteration is one
// umull/umlal into a 64-bit accumulator lane, and the reduction runs four
// independent carry sub-chains (two chains x two halves) before narrowing
// back to the 32-bit multiply form (the 5*carry fold can exceed 32 bits).
//
// On entry (after ClpSimdProc5Begin_aarch64.inc):
//   x0 = ACtx      (72-byte R/S/H/K state); x1 = APowTable (320-byte r^1..r^4)
//   x2 = AInp; x3 = ALen (multiple of 64, >= 64); x4 = APad (ignored)
//
// Power table: row j at [x1 + 32*j]; rows 0..4 r-limbs, rows 5..8 s-limbs
// (5*r), row 9 pad. Row lanes: [r4,r4,r4,r3 | r4,r2,r4,r1]. Bulk
// broadcasts the r^4 limb (lane 0); the tail reads [+32*j+4] / [+32*j+20]
// and un-interleaves to the (r^4, r^3) / (r^2, r^1) lane pairs.
//
// Register map: v0..v9 H limbs (.2s halves), v10..v19 accumulators (.2d),
// v20..v28 resident bulk rows, v29..v31 scratch (mask26/padbit rebuilt on
// demand - the working set fills the register file). The kernel clobbers
// v10..v15, so it brackets itself with the shared d8..d15 save/restore
// frames.
//
// Reference: Goll/Gueron, "Vectorization of Poly1305 Message Authentication
// Code" - the radix-2^26 multi-lane construction shared with the x86
// kernels.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
  // ---- Preload bulk rows: broadcast r^4 / 5*r^4 limbs ----
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x0e040cd4                    // dup v20.2s, w6
  .long 0xb9402026                    // ldr w6, [x1, #32]
  .long 0x0e040cd5                    // dup v21.2s, w6
  .long 0xb9404026                    // ldr w6, [x1, #64]
  .long 0x0e040cd6                    // dup v22.2s, w6
  .long 0xb9406026                    // ldr w6, [x1, #96]
  .long 0x0e040cd7                    // dup v23.2s, w6
  .long 0xb9408026                    // ldr w6, [x1, #128]
  .long 0x0e040cd8                    // dup v24.2s, w6
  .long 0xb940a026                    // ldr w6, [x1, #160]
  .long 0x0e040cd9                    // dup v25.2s, w6
  .long 0xb940c026                    // ldr w6, [x1, #192]
  .long 0x0e040cda                    // dup v26.2s, w6
  .long 0xb940e026                    // ldr w6, [x1, #224]
  .long 0x0e040cdb                    // dup v27.2s, w6
  .long 0xb9410026                    // ldr w6, [x1, #256]
  .long 0x0e040cdc                    // dup v28.2s, w6
  // ---- Load H0..H4 into lane 0 of half A; half B zero ----
  .long 0xbd402400                    // ldr s0, [x0, #36]
  .long 0x4f00e405                    // movi v5.16b, #0
  .long 0xbd402801                    // ldr s1, [x0, #40]
  .long 0x4f00e406                    // movi v6.16b, #0
  .long 0xbd402c02                    // ldr s2, [x0, #44]
  .long 0x4f00e407                    // movi v7.16b, #0
  .long 0xbd403003                    // ldr s3, [x0, #48]
  .long 0x4f00e408                    // movi v8.16b, #0
  .long 0xbd403404                    // ldr s4, [x0, #52]
  .long 0x4f00e409                    // movi v9.16b, #0
  // ---- Absorb next 4 blocks ----
  .long 0x6ebd8fbd                    // cmeq v29.4s, v29.4s, v29.4s
  .long 0x6f5a07bd                    // ushr v29.2d, v29.2d, #38
  .long 0x6ebe8fde                    // cmeq v30.4s, v30.4s, v30.4s
  .long 0x6f4107de                    // ushr v30.2d, v30.2d, #63
  .long 0x4f5857de                    // shl v30.2d, v30.2d, #24
  .long 0x3dc0004a                    // ldr q10, [x2]
  .long 0x3dc0044b                    // ldr q11, [x2, #16]
  .long 0x6e0a314c                    // ext v12.16b, v10.16b, v10.16b, #6
  .long 0x6e0b316d                    // ext v13.16b, v11.16b, v11.16b, #6
  .long 0x4ecd398e                    // zip1 v14.2d, v12.2d, v13.2d
  .long 0x4ecb794d                    // zip2 v13.2d, v10.2d, v11.2d
  .long 0x4ecb394c                    // zip1 v12.2d, v10.2d, v11.2d
  .long 0x6f66058a                    // ushr v10.2d, v12.2d, #26
  .long 0x4e3d1d8c                    // and v12.16b, v12.16b, v29.16b
  .long 0x4e3d1d4a                    // and v10.16b, v10.16b, v29.16b
  .long 0x6f6205cb                    // ushr v11.2d, v14.2d, #30
  .long 0x6f7c05ce                    // ushr v14.2d, v14.2d, #4
  .long 0x4e3d1dce                    // and v14.16b, v14.16b, v29.16b
  .long 0x4e3d1d6b                    // and v11.16b, v11.16b, v29.16b
  .long 0x6f5805ad                    // ushr v13.2d, v13.2d, #40
  .long 0x4ebe1dad                    // orr v13.16b, v13.16b, v30.16b
  .long 0x0ea1299f                    // xtn v31.2s, v12.2d
  .long 0x4ebf8400                    // add v0.4s, v0.4s, v31.4s
  .long 0x0ea1295f                    // xtn v31.2s, v10.2d
  .long 0x4ebf8421                    // add v1.4s, v1.4s, v31.4s
  .long 0x0ea129df                    // xtn v31.2s, v14.2d
  .long 0x4ebf8442                    // add v2.4s, v2.4s, v31.4s
  .long 0x0ea1297f                    // xtn v31.2s, v11.2d
  .long 0x4ebf8463                    // add v3.4s, v3.4s, v31.4s
  .long 0x0ea129bf                    // xtn v31.2s, v13.2d
  .long 0x4ebf8484                    // add v4.4s, v4.4s, v31.4s
  .long 0x3dc0084f                    // ldr q15, [x2, #32]
  .long 0x3dc00c50                    // ldr q16, [x2, #48]
  .long 0x6e0f31f1                    // ext v17.16b, v15.16b, v15.16b, #6
  .long 0x6e103212                    // ext v18.16b, v16.16b, v16.16b, #6
  .long 0x4ed23a33                    // zip1 v19.2d, v17.2d, v18.2d
  .long 0x4ed079f2                    // zip2 v18.2d, v15.2d, v16.2d
  .long 0x4ed039f1                    // zip1 v17.2d, v15.2d, v16.2d
  .long 0x6f66062f                    // ushr v15.2d, v17.2d, #26
  .long 0x4e3d1e31                    // and v17.16b, v17.16b, v29.16b
  .long 0x4e3d1def                    // and v15.16b, v15.16b, v29.16b
  .long 0x6f620670                    // ushr v16.2d, v19.2d, #30
  .long 0x6f7c0673                    // ushr v19.2d, v19.2d, #4
  .long 0x4e3d1e73                    // and v19.16b, v19.16b, v29.16b
  .long 0x4e3d1e10                    // and v16.16b, v16.16b, v29.16b
  .long 0x6f580652                    // ushr v18.2d, v18.2d, #40
  .long 0x4ebe1e52                    // orr v18.16b, v18.16b, v30.16b
  .long 0x0ea12a3f                    // xtn v31.2s, v17.2d
  .long 0x4ebf84a5                    // add v5.4s, v5.4s, v31.4s
  .long 0x0ea129ff                    // xtn v31.2s, v15.2d
  .long 0x4ebf84c6                    // add v6.4s, v6.4s, v31.4s
  .long 0x0ea12a7f                    // xtn v31.2s, v19.2d
  .long 0x4ebf84e7                    // add v7.4s, v7.4s, v31.4s
  .long 0x0ea12a1f                    // xtn v31.2s, v16.2d
  .long 0x4ebf8508                    // add v8.4s, v8.4s, v31.4s
  .long 0x0ea12a5f                    // xtn v31.2s, v18.2d
  .long 0x4ebf8529                    // add v9.4s, v9.4s, v31.4s
  add x2, x2, #64
  subs x3, x3, #64
  b.eq .Lpoly1305_neon_tail
.Lpoly1305_neon_loop:
  // ---- Bulk: H *= r^4 (broadcast rows), 50 umull/umlal ----
  .long 0x2eb4c00a                    // umull v10.2d, v0.2s, v20.2s
  .long 0x2eb4c0af                    // umull v15.2d, v5.2s, v20.2s
  .long 0x2ebc802a                    // umlal v10.2d, v1.2s, v28.2s
  .long 0x2ebc80cf                    // umlal v15.2d, v6.2s, v28.2s
  .long 0x2ebb804a                    // umlal v10.2d, v2.2s, v27.2s
  .long 0x2ebb80ef                    // umlal v15.2d, v7.2s, v27.2s
  .long 0x2eba806a                    // umlal v10.2d, v3.2s, v26.2s
  .long 0x2eba810f                    // umlal v15.2d, v8.2s, v26.2s
  .long 0x2eb9808a                    // umlal v10.2d, v4.2s, v25.2s
  .long 0x2eb9812f                    // umlal v15.2d, v9.2s, v25.2s
  .long 0x2eb5c00b                    // umull v11.2d, v0.2s, v21.2s
  .long 0x2eb5c0b0                    // umull v16.2d, v5.2s, v21.2s
  .long 0x2eb4802b                    // umlal v11.2d, v1.2s, v20.2s
  .long 0x2eb480d0                    // umlal v16.2d, v6.2s, v20.2s
  .long 0x2ebc804b                    // umlal v11.2d, v2.2s, v28.2s
  .long 0x2ebc80f0                    // umlal v16.2d, v7.2s, v28.2s
  .long 0x2ebb806b                    // umlal v11.2d, v3.2s, v27.2s
  .long 0x2ebb8110                    // umlal v16.2d, v8.2s, v27.2s
  .long 0x2eba808b                    // umlal v11.2d, v4.2s, v26.2s
  .long 0x2eba8130                    // umlal v16.2d, v9.2s, v26.2s
  .long 0x2eb6c00c                    // umull v12.2d, v0.2s, v22.2s
  .long 0x2eb6c0b1                    // umull v17.2d, v5.2s, v22.2s
  .long 0x2eb5802c                    // umlal v12.2d, v1.2s, v21.2s
  .long 0x2eb580d1                    // umlal v17.2d, v6.2s, v21.2s
  .long 0x2eb4804c                    // umlal v12.2d, v2.2s, v20.2s
  .long 0x2eb480f1                    // umlal v17.2d, v7.2s, v20.2s
  .long 0x2ebc806c                    // umlal v12.2d, v3.2s, v28.2s
  .long 0x2ebc8111                    // umlal v17.2d, v8.2s, v28.2s
  .long 0x2ebb808c                    // umlal v12.2d, v4.2s, v27.2s
  .long 0x2ebb8131                    // umlal v17.2d, v9.2s, v27.2s
  .long 0x2eb7c00d                    // umull v13.2d, v0.2s, v23.2s
  .long 0x2eb7c0b2                    // umull v18.2d, v5.2s, v23.2s
  .long 0x2eb6802d                    // umlal v13.2d, v1.2s, v22.2s
  .long 0x2eb680d2                    // umlal v18.2d, v6.2s, v22.2s
  .long 0x2eb5804d                    // umlal v13.2d, v2.2s, v21.2s
  .long 0x2eb580f2                    // umlal v18.2d, v7.2s, v21.2s
  .long 0x2eb4806d                    // umlal v13.2d, v3.2s, v20.2s
  .long 0x2eb48112                    // umlal v18.2d, v8.2s, v20.2s
  .long 0x2ebc808d                    // umlal v13.2d, v4.2s, v28.2s
  .long 0x2ebc8132                    // umlal v18.2d, v9.2s, v28.2s
  .long 0x2eb8c00e                    // umull v14.2d, v0.2s, v24.2s
  .long 0x2eb8c0b3                    // umull v19.2d, v5.2s, v24.2s
  .long 0x2eb7802e                    // umlal v14.2d, v1.2s, v23.2s
  .long 0x2eb780d3                    // umlal v19.2d, v6.2s, v23.2s
  .long 0x2eb6804e                    // umlal v14.2d, v2.2s, v22.2s
  .long 0x2eb680f3                    // umlal v19.2d, v7.2s, v22.2s
  .long 0x2eb5806e                    // umlal v14.2d, v3.2s, v21.2s
  .long 0x2eb58113                    // umlal v19.2d, v8.2s, v21.2s
  .long 0x2eb4808e                    // umlal v14.2d, v4.2s, v20.2s
  .long 0x2eb48133                    // umlal v19.2d, v9.2s, v20.2s
  // ---- Two-chain lazy reduce D -> H ----
  .long 0x6ebf8fff                    // cmeq v31.4s, v31.4s, v31.4s
  .long 0x6f5a07ff                    // ushr v31.2d, v31.2d, #38
  .long 0x6f66055d                    // ushr v29.2d, v10.2d, #26
  .long 0x4e3f1d4a                    // and v10.16b, v10.16b, v31.16b
  .long 0x4efd856b                    // add v11.2d, v11.2d, v29.2d
  .long 0x6f6605bd                    // ushr v29.2d, v13.2d, #26
  .long 0x4e3f1dad                    // and v13.16b, v13.16b, v31.16b
  .long 0x4efd85ce                    // add v14.2d, v14.2d, v29.2d
  .long 0x6f6605fe                    // ushr v30.2d, v15.2d, #26
  .long 0x4e3f1def                    // and v15.16b, v15.16b, v31.16b
  .long 0x4efe8610                    // add v16.2d, v16.2d, v30.2d
  .long 0x6f66065e                    // ushr v30.2d, v18.2d, #26
  .long 0x4e3f1e52                    // and v18.16b, v18.16b, v31.16b
  .long 0x4efe8673                    // add v19.2d, v19.2d, v30.2d
  .long 0x6f66057d                    // ushr v29.2d, v11.2d, #26
  .long 0x4e3f1d6b                    // and v11.16b, v11.16b, v31.16b
  .long 0x4efd858c                    // add v12.2d, v12.2d, v29.2d
  .long 0x6f6605dd                    // ushr v29.2d, v14.2d, #26
  .long 0x4e3f1dce                    // and v14.16b, v14.16b, v31.16b
  .long 0x4efd854a                    // add v10.2d, v10.2d, v29.2d
  .long 0x4f4257bd                    // shl v29.2d, v29.2d, #2
  .long 0x4efd854a                    // add v10.2d, v10.2d, v29.2d
  .long 0x6f66061e                    // ushr v30.2d, v16.2d, #26
  .long 0x4e3f1e10                    // and v16.16b, v16.16b, v31.16b
  .long 0x4efe8631                    // add v17.2d, v17.2d, v30.2d
  .long 0x6f66067e                    // ushr v30.2d, v19.2d, #26
  .long 0x4e3f1e73                    // and v19.16b, v19.16b, v31.16b
  .long 0x4efe85ef                    // add v15.2d, v15.2d, v30.2d
  .long 0x4f4257de                    // shl v30.2d, v30.2d, #2
  .long 0x4efe85ef                    // add v15.2d, v15.2d, v30.2d
  .long 0x6f66059d                    // ushr v29.2d, v12.2d, #26
  .long 0x4e3f1d8c                    // and v12.16b, v12.16b, v31.16b
  .long 0x4efd85ad                    // add v13.2d, v13.2d, v29.2d
  .long 0x6f66055d                    // ushr v29.2d, v10.2d, #26
  .long 0x4e3f1d4a                    // and v10.16b, v10.16b, v31.16b
  .long 0x4efd856b                    // add v11.2d, v11.2d, v29.2d
  .long 0x6f66063e                    // ushr v30.2d, v17.2d, #26
  .long 0x4e3f1e31                    // and v17.16b, v17.16b, v31.16b
  .long 0x4efe8652                    // add v18.2d, v18.2d, v30.2d
  .long 0x6f6605fe                    // ushr v30.2d, v15.2d, #26
  .long 0x4e3f1def                    // and v15.16b, v15.16b, v31.16b
  .long 0x4efe8610                    // add v16.2d, v16.2d, v30.2d
  .long 0x6f6605bd                    // ushr v29.2d, v13.2d, #26
  .long 0x4e3f1dad                    // and v13.16b, v13.16b, v31.16b
  .long 0x4efd85ce                    // add v14.2d, v14.2d, v29.2d
  .long 0x6f66065e                    // ushr v30.2d, v18.2d, #26
  .long 0x4e3f1e52                    // and v18.16b, v18.16b, v31.16b
  .long 0x4efe8673                    // add v19.2d, v19.2d, v30.2d
  // narrow to the .2s multiply form
  .long 0x0ea12940                    // xtn v0.2s, v10.2d
  .long 0x0ea129e5                    // xtn v5.2s, v15.2d
  .long 0x0ea12961                    // xtn v1.2s, v11.2d
  .long 0x0ea12a06                    // xtn v6.2s, v16.2d
  .long 0x0ea12982                    // xtn v2.2s, v12.2d
  .long 0x0ea12a27                    // xtn v7.2s, v17.2d
  .long 0x0ea129a3                    // xtn v3.2s, v13.2d
  .long 0x0ea12a48                    // xtn v8.2s, v18.2d
  .long 0x0ea129c4                    // xtn v4.2s, v14.2d
  .long 0x0ea12a69                    // xtn v9.2s, v19.2d
  // ---- Absorb next 4 blocks ----
  .long 0x6ebd8fbd                    // cmeq v29.4s, v29.4s, v29.4s
  .long 0x6f5a07bd                    // ushr v29.2d, v29.2d, #38
  .long 0x6ebe8fde                    // cmeq v30.4s, v30.4s, v30.4s
  .long 0x6f4107de                    // ushr v30.2d, v30.2d, #63
  .long 0x4f5857de                    // shl v30.2d, v30.2d, #24
  .long 0x3dc0004a                    // ldr q10, [x2]
  .long 0x3dc0044b                    // ldr q11, [x2, #16]
  .long 0x6e0a314c                    // ext v12.16b, v10.16b, v10.16b, #6
  .long 0x6e0b316d                    // ext v13.16b, v11.16b, v11.16b, #6
  .long 0x4ecd398e                    // zip1 v14.2d, v12.2d, v13.2d
  .long 0x4ecb794d                    // zip2 v13.2d, v10.2d, v11.2d
  .long 0x4ecb394c                    // zip1 v12.2d, v10.2d, v11.2d
  .long 0x6f66058a                    // ushr v10.2d, v12.2d, #26
  .long 0x4e3d1d8c                    // and v12.16b, v12.16b, v29.16b
  .long 0x4e3d1d4a                    // and v10.16b, v10.16b, v29.16b
  .long 0x6f6205cb                    // ushr v11.2d, v14.2d, #30
  .long 0x6f7c05ce                    // ushr v14.2d, v14.2d, #4
  .long 0x4e3d1dce                    // and v14.16b, v14.16b, v29.16b
  .long 0x4e3d1d6b                    // and v11.16b, v11.16b, v29.16b
  .long 0x6f5805ad                    // ushr v13.2d, v13.2d, #40
  .long 0x4ebe1dad                    // orr v13.16b, v13.16b, v30.16b
  .long 0x0ea1299f                    // xtn v31.2s, v12.2d
  .long 0x4ebf8400                    // add v0.4s, v0.4s, v31.4s
  .long 0x0ea1295f                    // xtn v31.2s, v10.2d
  .long 0x4ebf8421                    // add v1.4s, v1.4s, v31.4s
  .long 0x0ea129df                    // xtn v31.2s, v14.2d
  .long 0x4ebf8442                    // add v2.4s, v2.4s, v31.4s
  .long 0x0ea1297f                    // xtn v31.2s, v11.2d
  .long 0x4ebf8463                    // add v3.4s, v3.4s, v31.4s
  .long 0x0ea129bf                    // xtn v31.2s, v13.2d
  .long 0x4ebf8484                    // add v4.4s, v4.4s, v31.4s
  .long 0x3dc0084f                    // ldr q15, [x2, #32]
  .long 0x3dc00c50                    // ldr q16, [x2, #48]
  .long 0x6e0f31f1                    // ext v17.16b, v15.16b, v15.16b, #6
  .long 0x6e103212                    // ext v18.16b, v16.16b, v16.16b, #6
  .long 0x4ed23a33                    // zip1 v19.2d, v17.2d, v18.2d
  .long 0x4ed079f2                    // zip2 v18.2d, v15.2d, v16.2d
  .long 0x4ed039f1                    // zip1 v17.2d, v15.2d, v16.2d
  .long 0x6f66062f                    // ushr v15.2d, v17.2d, #26
  .long 0x4e3d1e31                    // and v17.16b, v17.16b, v29.16b
  .long 0x4e3d1def                    // and v15.16b, v15.16b, v29.16b
  .long 0x6f620670                    // ushr v16.2d, v19.2d, #30
  .long 0x6f7c0673                    // ushr v19.2d, v19.2d, #4
  .long 0x4e3d1e73                    // and v19.16b, v19.16b, v29.16b
  .long 0x4e3d1e10                    // and v16.16b, v16.16b, v29.16b
  .long 0x6f580652                    // ushr v18.2d, v18.2d, #40
  .long 0x4ebe1e52                    // orr v18.16b, v18.16b, v30.16b
  .long 0x0ea12a3f                    // xtn v31.2s, v17.2d
  .long 0x4ebf84a5                    // add v5.4s, v5.4s, v31.4s
  .long 0x0ea129ff                    // xtn v31.2s, v15.2d
  .long 0x4ebf84c6                    // add v6.4s, v6.4s, v31.4s
  .long 0x0ea12a7f                    // xtn v31.2s, v19.2d
  .long 0x4ebf84e7                    // add v7.4s, v7.4s, v31.4s
  .long 0x0ea12a1f                    // xtn v31.2s, v16.2d
  .long 0x4ebf8508                    // add v8.4s, v8.4s, v31.4s
  .long 0x0ea12a5f                    // xtn v31.2s, v18.2d
  .long 0x4ebf8529                    // add v9.4s, v9.4s, v31.4s
  add x2, x2, #64
  subs x3, x3, #64
  b.ne .Lpoly1305_neon_loop
.Lpoly1305_neon_tail:
  // ---- Tail: H *= [r^4, r^3, r^2, r^1] (shifted table reads) ----
  add x5, x1, #160
  .long 0x3cc0403d                    // ldur q29, [x1, #4]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebdc00a                    // umull v10.2d, v0.2s, v29.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec0af                    // umull v15.2d, v5.2s, v30.2s
  .long 0x3cc640bd                    // ldur q29, [x5, #100]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd802a                    // umlal v10.2d, v1.2s, v29.2s
  .long 0x3cc740be                    // ldur q30, [x5, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80cf                    // umlal v15.2d, v6.2s, v30.2s
  .long 0x3cc440bd                    // ldur q29, [x5, #68]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd804a                    // umlal v10.2d, v2.2s, v29.2s
  .long 0x3cc540be                    // ldur q30, [x5, #84]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80ef                    // umlal v15.2d, v7.2s, v30.2s
  .long 0x3cc240bd                    // ldur q29, [x5, #36]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd806a                    // umlal v10.2d, v3.2s, v29.2s
  .long 0x3cc340be                    // ldur q30, [x5, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe810f                    // umlal v15.2d, v8.2s, v30.2s
  .long 0x3cc040bd                    // ldur q29, [x5, #4]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd808a                    // umlal v10.2d, v4.2s, v29.2s
  .long 0x3cc140be                    // ldur q30, [x5, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe812f                    // umlal v15.2d, v9.2s, v30.2s
  .long 0x3cc2403d                    // ldur q29, [x1, #36]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebdc00b                    // umull v11.2d, v0.2s, v29.2s
  .long 0x3cc3403e                    // ldur q30, [x1, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec0b0                    // umull v16.2d, v5.2s, v30.2s
  .long 0x3cc0403d                    // ldur q29, [x1, #4]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd802b                    // umlal v11.2d, v1.2s, v29.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80d0                    // umlal v16.2d, v6.2s, v30.2s
  .long 0x3cc640bd                    // ldur q29, [x5, #100]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd804b                    // umlal v11.2d, v2.2s, v29.2s
  .long 0x3cc740be                    // ldur q30, [x5, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80f0                    // umlal v16.2d, v7.2s, v30.2s
  .long 0x3cc440bd                    // ldur q29, [x5, #68]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd806b                    // umlal v11.2d, v3.2s, v29.2s
  .long 0x3cc540be                    // ldur q30, [x5, #84]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8110                    // umlal v16.2d, v8.2s, v30.2s
  .long 0x3cc240bd                    // ldur q29, [x5, #36]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd808b                    // umlal v11.2d, v4.2s, v29.2s
  .long 0x3cc340be                    // ldur q30, [x5, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8130                    // umlal v16.2d, v9.2s, v30.2s
  .long 0x3cc4403d                    // ldur q29, [x1, #68]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebdc00c                    // umull v12.2d, v0.2s, v29.2s
  .long 0x3cc5403e                    // ldur q30, [x1, #84]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec0b1                    // umull v17.2d, v5.2s, v30.2s
  .long 0x3cc2403d                    // ldur q29, [x1, #36]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd802c                    // umlal v12.2d, v1.2s, v29.2s
  .long 0x3cc3403e                    // ldur q30, [x1, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80d1                    // umlal v17.2d, v6.2s, v30.2s
  .long 0x3cc0403d                    // ldur q29, [x1, #4]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd804c                    // umlal v12.2d, v2.2s, v29.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80f1                    // umlal v17.2d, v7.2s, v30.2s
  .long 0x3cc640bd                    // ldur q29, [x5, #100]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd806c                    // umlal v12.2d, v3.2s, v29.2s
  .long 0x3cc740be                    // ldur q30, [x5, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8111                    // umlal v17.2d, v8.2s, v30.2s
  .long 0x3cc440bd                    // ldur q29, [x5, #68]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd808c                    // umlal v12.2d, v4.2s, v29.2s
  .long 0x3cc540be                    // ldur q30, [x5, #84]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8131                    // umlal v17.2d, v9.2s, v30.2s
  .long 0x3cc6403d                    // ldur q29, [x1, #100]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebdc00d                    // umull v13.2d, v0.2s, v29.2s
  .long 0x3cc7403e                    // ldur q30, [x1, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec0b2                    // umull v18.2d, v5.2s, v30.2s
  .long 0x3cc4403d                    // ldur q29, [x1, #68]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd802d                    // umlal v13.2d, v1.2s, v29.2s
  .long 0x3cc5403e                    // ldur q30, [x1, #84]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80d2                    // umlal v18.2d, v6.2s, v30.2s
  .long 0x3cc2403d                    // ldur q29, [x1, #36]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd804d                    // umlal v13.2d, v2.2s, v29.2s
  .long 0x3cc3403e                    // ldur q30, [x1, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80f2                    // umlal v18.2d, v7.2s, v30.2s
  .long 0x3cc0403d                    // ldur q29, [x1, #4]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd806d                    // umlal v13.2d, v3.2s, v29.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8112                    // umlal v18.2d, v8.2s, v30.2s
  .long 0x3cc640bd                    // ldur q29, [x5, #100]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd808d                    // umlal v13.2d, v4.2s, v29.2s
  .long 0x3cc740be                    // ldur q30, [x5, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8132                    // umlal v18.2d, v9.2s, v30.2s
  .long 0x3cc8403d                    // ldur q29, [x1, #132]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebdc00e                    // umull v14.2d, v0.2s, v29.2s
  .long 0x3cc9403e                    // ldur q30, [x1, #148]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebec0b3                    // umull v19.2d, v5.2s, v30.2s
  .long 0x3cc6403d                    // ldur q29, [x1, #100]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd802e                    // umlal v14.2d, v1.2s, v29.2s
  .long 0x3cc7403e                    // ldur q30, [x1, #116]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80d3                    // umlal v19.2d, v6.2s, v30.2s
  .long 0x3cc4403d                    // ldur q29, [x1, #68]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd804e                    // umlal v14.2d, v2.2s, v29.2s
  .long 0x3cc5403e                    // ldur q30, [x1, #84]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe80f3                    // umlal v19.2d, v7.2s, v30.2s
  .long 0x3cc2403d                    // ldur q29, [x1, #36]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd806e                    // umlal v14.2d, v3.2s, v29.2s
  .long 0x3cc3403e                    // ldur q30, [x1, #52]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8113                    // umlal v19.2d, v8.2s, v30.2s
  .long 0x3cc0403d                    // ldur q29, [x1, #4]
  .long 0x4e9d1bbd                    // uzp1 v29.4s, v29.4s, v29.4s
  .long 0x2ebd808e                    // umlal v14.2d, v4.2s, v29.2s
  .long 0x3cc1403e                    // ldur q30, [x1, #20]
  .long 0x4e9e1bde                    // uzp1 v30.4s, v30.4s, v30.4s
  .long 0x2ebe8133                    // umlal v19.2d, v9.2s, v30.2s
  // ---- Two-chain lazy reduce D -> H ----
  .long 0x6ebf8fff                    // cmeq v31.4s, v31.4s, v31.4s
  .long 0x6f5a07ff                    // ushr v31.2d, v31.2d, #38
  .long 0x6f66055d                    // ushr v29.2d, v10.2d, #26
  .long 0x4e3f1d4a                    // and v10.16b, v10.16b, v31.16b
  .long 0x4efd856b                    // add v11.2d, v11.2d, v29.2d
  .long 0x6f6605bd                    // ushr v29.2d, v13.2d, #26
  .long 0x4e3f1dad                    // and v13.16b, v13.16b, v31.16b
  .long 0x4efd85ce                    // add v14.2d, v14.2d, v29.2d
  .long 0x6f6605fe                    // ushr v30.2d, v15.2d, #26
  .long 0x4e3f1def                    // and v15.16b, v15.16b, v31.16b
  .long 0x4efe8610                    // add v16.2d, v16.2d, v30.2d
  .long 0x6f66065e                    // ushr v30.2d, v18.2d, #26
  .long 0x4e3f1e52                    // and v18.16b, v18.16b, v31.16b
  .long 0x4efe8673                    // add v19.2d, v19.2d, v30.2d
  .long 0x6f66057d                    // ushr v29.2d, v11.2d, #26
  .long 0x4e3f1d6b                    // and v11.16b, v11.16b, v31.16b
  .long 0x4efd858c                    // add v12.2d, v12.2d, v29.2d
  .long 0x6f6605dd                    // ushr v29.2d, v14.2d, #26
  .long 0x4e3f1dce                    // and v14.16b, v14.16b, v31.16b
  .long 0x4efd854a                    // add v10.2d, v10.2d, v29.2d
  .long 0x4f4257bd                    // shl v29.2d, v29.2d, #2
  .long 0x4efd854a                    // add v10.2d, v10.2d, v29.2d
  .long 0x6f66061e                    // ushr v30.2d, v16.2d, #26
  .long 0x4e3f1e10                    // and v16.16b, v16.16b, v31.16b
  .long 0x4efe8631                    // add v17.2d, v17.2d, v30.2d
  .long 0x6f66067e                    // ushr v30.2d, v19.2d, #26
  .long 0x4e3f1e73                    // and v19.16b, v19.16b, v31.16b
  .long 0x4efe85ef                    // add v15.2d, v15.2d, v30.2d
  .long 0x4f4257de                    // shl v30.2d, v30.2d, #2
  .long 0x4efe85ef                    // add v15.2d, v15.2d, v30.2d
  .long 0x6f66059d                    // ushr v29.2d, v12.2d, #26
  .long 0x4e3f1d8c                    // and v12.16b, v12.16b, v31.16b
  .long 0x4efd85ad                    // add v13.2d, v13.2d, v29.2d
  .long 0x6f66055d                    // ushr v29.2d, v10.2d, #26
  .long 0x4e3f1d4a                    // and v10.16b, v10.16b, v31.16b
  .long 0x4efd856b                    // add v11.2d, v11.2d, v29.2d
  .long 0x6f66063e                    // ushr v30.2d, v17.2d, #26
  .long 0x4e3f1e31                    // and v17.16b, v17.16b, v31.16b
  .long 0x4efe8652                    // add v18.2d, v18.2d, v30.2d
  .long 0x6f6605fe                    // ushr v30.2d, v15.2d, #26
  .long 0x4e3f1def                    // and v15.16b, v15.16b, v31.16b
  .long 0x4efe8610                    // add v16.2d, v16.2d, v30.2d
  .long 0x6f6605bd                    // ushr v29.2d, v13.2d, #26
  .long 0x4e3f1dad                    // and v13.16b, v13.16b, v31.16b
  .long 0x4efd85ce                    // add v14.2d, v14.2d, v29.2d
  .long 0x6f66065e                    // ushr v30.2d, v18.2d, #26
  .long 0x4e3f1e52                    // and v18.16b, v18.16b, v31.16b
  .long 0x4efe8673                    // add v19.2d, v19.2d, v30.2d
  // narrow to the .2s multiply form
  .long 0x0ea12940                    // xtn v0.2s, v10.2d
  .long 0x0ea129e5                    // xtn v5.2s, v15.2d
  .long 0x0ea12961                    // xtn v1.2s, v11.2d
  .long 0x0ea12a06                    // xtn v6.2s, v16.2d
  .long 0x0ea12982                    // xtn v2.2s, v12.2d
  .long 0x0ea12a27                    // xtn v7.2s, v17.2d
  .long 0x0ea129a3                    // xtn v3.2s, v13.2d
  .long 0x0ea12a48                    // xtn v8.2s, v18.2d
  .long 0x0ea129c4                    // xtn v4.2s, v14.2d
  .long 0x0ea12a69                    // xtn v9.2s, v19.2d
  // ---- Horizontal fold 4 lanes -> 1, final reduce, store ----
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x0ea0bc00                    // addp v0.2s, v0.2s, v0.2s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x0ea1bc21                    // addp v1.2s, v1.2s, v1.2s
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x0ea2bc42                    // addp v2.2s, v2.2s, v2.2s
  .long 0x4ea88463                    // add v3.4s, v3.4s, v8.4s
  .long 0x0ea3bc63                    // addp v3.2s, v3.2s, v3.2s
  .long 0x4ea98484                    // add v4.4s, v4.4s, v9.4s
  .long 0x0ea4bc84                    // addp v4.2s, v4.2s, v4.2s
  .long 0x6ebf8fff                    // cmeq v31.4s, v31.4s, v31.4s
  .long 0x6f3a07ff                    // ushr v31.4s, v31.4s, #6
  .long 0x6f26041d                    // ushr v29.4s, v0.4s, #26
  .long 0x4e3f1c00                    // and v0.16b, v0.16b, v31.16b
  .long 0x4ebd8421                    // add v1.4s, v1.4s, v29.4s
  .long 0x6f26043d                    // ushr v29.4s, v1.4s, #26
  .long 0x4e3f1c21                    // and v1.16b, v1.16b, v31.16b
  .long 0x4ebd8442                    // add v2.4s, v2.4s, v29.4s
  .long 0x6f26045d                    // ushr v29.4s, v2.4s, #26
  .long 0x4e3f1c42                    // and v2.16b, v2.16b, v31.16b
  .long 0x4ebd8463                    // add v3.4s, v3.4s, v29.4s
  .long 0x6f26047d                    // ushr v29.4s, v3.4s, #26
  .long 0x4e3f1c63                    // and v3.16b, v3.16b, v31.16b
  .long 0x4ebd8484                    // add v4.4s, v4.4s, v29.4s
  .long 0x6f26049d                    // ushr v29.4s, v4.4s, #26
  .long 0x4e3f1c84                    // and v4.16b, v4.16b, v31.16b
  .long 0x4f2257be                    // shl v30.4s, v29.4s, #2
  .long 0x4ebe87bd                    // add v29.4s, v29.4s, v30.4s
  .long 0x4ebd8400                    // add v0.4s, v0.4s, v29.4s
  .long 0x6f26041d                    // ushr v29.4s, v0.4s, #26
  .long 0x4e3f1c00                    // and v0.16b, v0.16b, v31.16b
  .long 0x4ebd8421                    // add v1.4s, v1.4s, v29.4s
  .long 0xbd002400                    // str s0, [x0, #36]
  .long 0xbd002801                    // str s1, [x0, #40]
  .long 0xbd002c02                    // str s2, [x0, #44]
  .long 0xbd003003                    // str s3, [x0, #48]
  .long 0xbd003404                    // str s4, [x0, #52]
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
