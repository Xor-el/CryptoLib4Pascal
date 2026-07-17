// ChaCha 4-way NEON keystream kernel, vertical layout (aarch64), matching
// the streaming contract of the width-4 chain in
// ChaCha7539Blocks4Sse2_x86_64.inc.
// -------------------------------------------------------------------
//
// Four 64-byte ChaCha blocks per group, state words held vertically (one
// block per 32-bit lane): the whole working state is register-resident in
// v0..v15, with the broadcast originals of words 2..15 parked in v18..v31
// (the two sigma words are re-broadcast from AState instead of parked, so
// v16/v17 remain free as the only rotate/transpose scratch; no stack
// frame beyond the shared d8..d15 save). rot16 is one in-place rev32 on
// 16-bit lanes; rot12/rot8/rot7 use ushr+shl+orr. Quarter-rounds run as
// interleaved independent pairs.
//
// Streams AGroups x 256B in one call: prologue once, light per-group
// reload (counter lanes +4), fused accumulate/transpose/xor tail straight
// to AOut (4x4 zip transpose per word quad).
//
// Variant selection:
//   CHACHA_CTR64  -> the per-group AState counter write-back is a 64-bit
//     add spanning words 12/13 (DJB); else a 32-bit add on word 12
//     (RFC 7539). The vector counter lanes always broadcast word 13, so
//     the caller must guarantee the low counter word does not wrap inside
//     the 4*AGroups-block span (TChaChaBaseEngine.WideBlocksSafe).
//
// On entry (after ClpSimdProc5Begin_aarch64.inc):
//   x0 = ARounds, x1 = AState (16 UInt32), x2 = AIn, x3 = AOut,
//   x4 = AGroups (4-block groups, >= 1; Int32 - zero-extended on entry).
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 4*AGroups (carrying into
//   word 13 under CHACHA_CTR64); the keystream is xored with AIn into AOut
//   (256*AGroups bytes).
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  mov w4, w4
  // AGroups is Int32: zero-extend before use as a counter
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
  // broadcast originals of words 2..15 into v18..v31
  .long 0xb9400826                    // ldr w6, [x1, #8]
  .long 0x4e040cd2                    // dup v18.4s, w6
  .long 0xb9400c26                    // ldr w6, [x1, #12]
  .long 0x4e040cd3                    // dup v19.4s, w6
  .long 0xb9401026                    // ldr w6, [x1, #16]
  .long 0x4e040cd4                    // dup v20.4s, w6
  .long 0xb9401426                    // ldr w6, [x1, #20]
  .long 0x4e040cd5                    // dup v21.4s, w6
  .long 0xb9401826                    // ldr w6, [x1, #24]
  .long 0x4e040cd6                    // dup v22.4s, w6
  .long 0xb9401c26                    // ldr w6, [x1, #28]
  .long 0x4e040cd7                    // dup v23.4s, w6
  .long 0xb9402026                    // ldr w6, [x1, #32]
  .long 0x4e040cd8                    // dup v24.4s, w6
  .long 0xb9402426                    // ldr w6, [x1, #36]
  .long 0x4e040cd9                    // dup v25.4s, w6
  .long 0xb9402826                    // ldr w6, [x1, #40]
  .long 0x4e040cda                    // dup v26.4s, w6
  .long 0xb9402c26                    // ldr w6, [x1, #44]
  .long 0x4e040cdb                    // dup v27.4s, w6
  .long 0xb9403026                    // ldr w6, [x1, #48]
  .long 0x4e040cdc                    // dup v28.4s, w6
  .long 0xb9403426                    // ldr w6, [x1, #52]
  .long 0x4e040cdd                    // dup v29.4s, w6
  .long 0xb9403826                    // ldr w6, [x1, #56]
  .long 0x4e040cde                    // dup v30.4s, w6
  .long 0xb9403c26                    // ldr w6, [x1, #60]
  .long 0x4e040cdf                    // dup v31.4s, w6
  // counter lanes: orig word 12 += (0, 1, 2, 3)
  .long 0x4f000410                    // movi v16.4s, #0
  mov w6, #1
  .long 0x4e0c1cd0                    // ins v16.s[1], w6
  mov w6, #2
  .long 0x4e141cd0                    // ins v16.s[2], w6
  mov w6, #3
  .long 0x4e1c1cd0                    // ins v16.s[3], w6
  .long 0x4eb0879c                    // add v28.4s, v28.4s, v16.4s
  b .Lc7539_neon_enter
.Lc7539_neon_outer:
  // next group: counter lanes += 4
  .long 0x4f000490                    // movi v16.4s, #4
  .long 0x4eb0879c                    // add v28.4s, v28.4s, v16.4s
.Lc7539_neon_enter:
  // seed the working state (sigma words re-broadcast)
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cc0                    // dup v0.4s, w6
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cc1                    // dup v1.4s, w6
  .long 0x4eb21e42                    // orr v2.16b, v18.16b, v18.16b
  .long 0x4eb31e63                    // orr v3.16b, v19.16b, v19.16b
  .long 0x4eb41e84                    // orr v4.16b, v20.16b, v20.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x4eb61ec6                    // orr v6.16b, v22.16b, v22.16b
  .long 0x4eb71ee7                    // orr v7.16b, v23.16b, v23.16b
  .long 0x4eb81f08                    // orr v8.16b, v24.16b, v24.16b
  .long 0x4eb91f29                    // orr v9.16b, v25.16b, v25.16b
  .long 0x4eba1f4a                    // orr v10.16b, v26.16b, v26.16b
  .long 0x4ebb1f6b                    // orr v11.16b, v27.16b, v27.16b
  .long 0x4ebc1f8c                    // orr v12.16b, v28.16b, v28.16b
  .long 0x4ebd1fad                    // orr v13.16b, v29.16b, v29.16b
  .long 0x4ebe1fce                    // orr v14.16b, v30.16b, v30.16b
  .long 0x4ebf1fef                    // orr v15.16b, v31.16b, v31.16b
  mov w5, w0
.Lc7539_neon_round:
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c84                    // eor v4.16b, v4.16b, v8.16b
  .long 0x6e291ca5                    // eor v5.16b, v5.16b, v9.16b
  .long 0x6f2c0490                    // ushr v16.4s, v4.4s, #20
  .long 0x6f2c04b1                    // ushr v17.4s, v5.4s, #20
  .long 0x4f2c5484                    // shl v4.4s, v4.4s, #12
  .long 0x4f2c54a5                    // shl v5.4s, v5.4s, #12
  .long 0x4eb01c84                    // orr v4.16b, v4.16b, v16.16b
  .long 0x4eb11ca5                    // orr v5.16b, v5.16b, v17.16b
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6f280590                    // ushr v16.4s, v12.4s, #24
  .long 0x6f2805b1                    // ushr v17.4s, v13.4s, #24
  .long 0x4f28558c                    // shl v12.4s, v12.4s, #8
  .long 0x4f2855ad                    // shl v13.4s, v13.4s, #8
  .long 0x4eb01d8c                    // orr v12.16b, v12.16b, v16.16b
  .long 0x4eb11dad                    // orr v13.16b, v13.16b, v17.16b
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c84                    // eor v4.16b, v4.16b, v8.16b
  .long 0x6e291ca5                    // eor v5.16b, v5.16b, v9.16b
  .long 0x6f270490                    // ushr v16.4s, v4.4s, #25
  .long 0x6f2704b1                    // ushr v17.4s, v5.4s, #25
  .long 0x4f275484                    // shl v4.4s, v4.4s, #7
  .long 0x4f2754a5                    // shl v5.4s, v5.4s, #7
  .long 0x4eb01c84                    // orr v4.16b, v4.16b, v16.16b
  .long 0x4eb11ca5                    // orr v5.16b, v5.16b, v17.16b
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cc6                    // eor v6.16b, v6.16b, v10.16b
  .long 0x6e2b1ce7                    // eor v7.16b, v7.16b, v11.16b
  .long 0x6f2c04d0                    // ushr v16.4s, v6.4s, #20
  .long 0x6f2c04f1                    // ushr v17.4s, v7.4s, #20
  .long 0x4f2c54c6                    // shl v6.4s, v6.4s, #12
  .long 0x4f2c54e7                    // shl v7.4s, v7.4s, #12
  .long 0x4eb01cc6                    // orr v6.16b, v6.16b, v16.16b
  .long 0x4eb11ce7                    // orr v7.16b, v7.16b, v17.16b
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6f2805d0                    // ushr v16.4s, v14.4s, #24
  .long 0x6f2805f1                    // ushr v17.4s, v15.4s, #24
  .long 0x4f2855ce                    // shl v14.4s, v14.4s, #8
  .long 0x4f2855ef                    // shl v15.4s, v15.4s, #8
  .long 0x4eb01dce                    // orr v14.16b, v14.16b, v16.16b
  .long 0x4eb11def                    // orr v15.16b, v15.16b, v17.16b
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cc6                    // eor v6.16b, v6.16b, v10.16b
  .long 0x6e2b1ce7                    // eor v7.16b, v7.16b, v11.16b
  .long 0x6f2704d0                    // ushr v16.4s, v6.4s, #25
  .long 0x6f2704f1                    // ushr v17.4s, v7.4s, #25
  .long 0x4f2754c6                    // shl v6.4s, v6.4s, #7
  .long 0x4f2754e7                    // shl v7.4s, v7.4s, #7
  .long 0x4eb01cc6                    // orr v6.16b, v6.16b, v16.16b
  .long 0x4eb11ce7                    // orr v7.16b, v7.16b, v17.16b
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1ca5                    // eor v5.16b, v5.16b, v10.16b
  .long 0x6e2b1cc6                    // eor v6.16b, v6.16b, v11.16b
  .long 0x6f2c04b0                    // ushr v16.4s, v5.4s, #20
  .long 0x6f2c04d1                    // ushr v17.4s, v6.4s, #20
  .long 0x4f2c54a5                    // shl v5.4s, v5.4s, #12
  .long 0x4f2c54c6                    // shl v6.4s, v6.4s, #12
  .long 0x4eb01ca5                    // orr v5.16b, v5.16b, v16.16b
  .long 0x4eb11cc6                    // orr v6.16b, v6.16b, v17.16b
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6f2805f0                    // ushr v16.4s, v15.4s, #24
  .long 0x6f280591                    // ushr v17.4s, v12.4s, #24
  .long 0x4f2855ef                    // shl v15.4s, v15.4s, #8
  .long 0x4f28558c                    // shl v12.4s, v12.4s, #8
  .long 0x4eb01def                    // orr v15.16b, v15.16b, v16.16b
  .long 0x4eb11d8c                    // orr v12.16b, v12.16b, v17.16b
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1ca5                    // eor v5.16b, v5.16b, v10.16b
  .long 0x6e2b1cc6                    // eor v6.16b, v6.16b, v11.16b
  .long 0x6f2704b0                    // ushr v16.4s, v5.4s, #25
  .long 0x6f2704d1                    // ushr v17.4s, v6.4s, #25
  .long 0x4f2754a5                    // shl v5.4s, v5.4s, #7
  .long 0x4f2754c6                    // shl v6.4s, v6.4s, #7
  .long 0x4eb01ca5                    // orr v5.16b, v5.16b, v16.16b
  .long 0x4eb11cc6                    // orr v6.16b, v6.16b, v17.16b
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281ce7                    // eor v7.16b, v7.16b, v8.16b
  .long 0x6e291c84                    // eor v4.16b, v4.16b, v9.16b
  .long 0x6f2c04f0                    // ushr v16.4s, v7.4s, #20
  .long 0x6f2c0491                    // ushr v17.4s, v4.4s, #20
  .long 0x4f2c54e7                    // shl v7.4s, v7.4s, #12
  .long 0x4f2c5484                    // shl v4.4s, v4.4s, #12
  .long 0x4eb01ce7                    // orr v7.16b, v7.16b, v16.16b
  .long 0x4eb11c84                    // orr v4.16b, v4.16b, v17.16b
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6f2805b0                    // ushr v16.4s, v13.4s, #24
  .long 0x6f2805d1                    // ushr v17.4s, v14.4s, #24
  .long 0x4f2855ad                    // shl v13.4s, v13.4s, #8
  .long 0x4f2855ce                    // shl v14.4s, v14.4s, #8
  .long 0x4eb01dad                    // orr v13.16b, v13.16b, v16.16b
  .long 0x4eb11dce                    // orr v14.16b, v14.16b, v17.16b
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281ce7                    // eor v7.16b, v7.16b, v8.16b
  .long 0x6e291c84                    // eor v4.16b, v4.16b, v9.16b
  .long 0x6f2704f0                    // ushr v16.4s, v7.4s, #25
  .long 0x6f270491                    // ushr v17.4s, v4.4s, #25
  .long 0x4f2754e7                    // shl v7.4s, v7.4s, #7
  .long 0x4f275484                    // shl v4.4s, v4.4s, #7
  .long 0x4eb01ce7                    // orr v7.16b, v7.16b, v16.16b
  .long 0x4eb11c84                    // orr v4.16b, v4.16b, v17.16b
  subs w5, w5, #2
  b.gt .Lc7539_neon_round
  // advance the state block counter (word 12)
{$IFDEF CHACHA_CTR64}
  .long 0xf9401826                    // ldr x6, [x1, #48]
  add x6, x6, #4
  .long 0xf9001826                    // str x6, [x1, #48]
{$ELSE}
  .long 0xb9403026                    // ldr w6, [x1, #48]
  add w6, w6, #4
  .long 0xb9003026                    // str w6, [x1, #48]
{$ENDIF}
  // quad 0 (words 0..3): accumulate, transpose, xor
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08421                    // add v1.4s, v1.4s, v16.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x4e813810                    // zip1 v16.4s, v0.4s, v1.4s
  .long 0x4e817811                    // zip2 v17.4s, v0.4s, v1.4s
  .long 0x4e833840                    // zip1 v0.4s, v2.4s, v3.4s
  .long 0x4e837841                    // zip2 v1.4s, v2.4s, v3.4s
  .long 0x4ec03a02                    // zip1 v2.2d, v16.2d, v0.2d
  .long 0x4ec07a03                    // zip2 v3.2d, v16.2d, v0.2d
  .long 0x4ec13a30                    // zip1 v16.2d, v17.2d, v1.2d
  .long 0x4ec17a31                    // zip2 v17.2d, v17.2d, v1.2d
  .long 0x3dc00040                    // ldr q0, [x2]
  .long 0x6e201c40                    // eor v0.16b, v2.16b, v0.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3dc01040                    // ldr q0, [x2, #64]
  .long 0x6e201c60                    // eor v0.16b, v3.16b, v0.16b
  .long 0x3d801060                    // str q0, [x3, #64]
  .long 0x3dc02040                    // ldr q0, [x2, #128]
  .long 0x6e201e00                    // eor v0.16b, v16.16b, v0.16b
  .long 0x3d802060                    // str q0, [x3, #128]
  .long 0x3dc03040                    // ldr q0, [x2, #192]
  .long 0x6e201e20                    // eor v0.16b, v17.16b, v0.16b
  .long 0x3d803060                    // str q0, [x3, #192]
  // quad 1 (words 4..7): accumulate, transpose, xor
  .long 0x4eb48484                    // add v4.4s, v4.4s, v20.4s
  .long 0x4eb584a5                    // add v5.4s, v5.4s, v21.4s
  .long 0x4eb684c6                    // add v6.4s, v6.4s, v22.4s
  .long 0x4eb784e7                    // add v7.4s, v7.4s, v23.4s
  .long 0x4e853890                    // zip1 v16.4s, v4.4s, v5.4s
  .long 0x4e857891                    // zip2 v17.4s, v4.4s, v5.4s
  .long 0x4e8738c4                    // zip1 v4.4s, v6.4s, v7.4s
  .long 0x4e8778c5                    // zip2 v5.4s, v6.4s, v7.4s
  .long 0x4ec43a06                    // zip1 v6.2d, v16.2d, v4.2d
  .long 0x4ec47a07                    // zip2 v7.2d, v16.2d, v4.2d
  .long 0x4ec53a30                    // zip1 v16.2d, v17.2d, v5.2d
  .long 0x4ec57a31                    // zip2 v17.2d, v17.2d, v5.2d
  .long 0x3dc00444                    // ldr q4, [x2, #16]
  .long 0x6e241cc4                    // eor v4.16b, v6.16b, v4.16b
  .long 0x3d800464                    // str q4, [x3, #16]
  .long 0x3dc01444                    // ldr q4, [x2, #80]
  .long 0x6e241ce4                    // eor v4.16b, v7.16b, v4.16b
  .long 0x3d801464                    // str q4, [x3, #80]
  .long 0x3dc02444                    // ldr q4, [x2, #144]
  .long 0x6e241e04                    // eor v4.16b, v16.16b, v4.16b
  .long 0x3d802464                    // str q4, [x3, #144]
  .long 0x3dc03444                    // ldr q4, [x2, #208]
  .long 0x6e241e24                    // eor v4.16b, v17.16b, v4.16b
  .long 0x3d803464                    // str q4, [x3, #208]
  // quad 2 (words 8..11): accumulate, transpose, xor
  .long 0x4eb88508                    // add v8.4s, v8.4s, v24.4s
  .long 0x4eb98529                    // add v9.4s, v9.4s, v25.4s
  .long 0x4eba854a                    // add v10.4s, v10.4s, v26.4s
  .long 0x4ebb856b                    // add v11.4s, v11.4s, v27.4s
  .long 0x4e893910                    // zip1 v16.4s, v8.4s, v9.4s
  .long 0x4e897911                    // zip2 v17.4s, v8.4s, v9.4s
  .long 0x4e8b3948                    // zip1 v8.4s, v10.4s, v11.4s
  .long 0x4e8b7949                    // zip2 v9.4s, v10.4s, v11.4s
  .long 0x4ec83a0a                    // zip1 v10.2d, v16.2d, v8.2d
  .long 0x4ec87a0b                    // zip2 v11.2d, v16.2d, v8.2d
  .long 0x4ec93a30                    // zip1 v16.2d, v17.2d, v9.2d
  .long 0x4ec97a31                    // zip2 v17.2d, v17.2d, v9.2d
  .long 0x3dc00848                    // ldr q8, [x2, #32]
  .long 0x6e281d48                    // eor v8.16b, v10.16b, v8.16b
  .long 0x3d800868                    // str q8, [x3, #32]
  .long 0x3dc01848                    // ldr q8, [x2, #96]
  .long 0x6e281d68                    // eor v8.16b, v11.16b, v8.16b
  .long 0x3d801868                    // str q8, [x3, #96]
  .long 0x3dc02848                    // ldr q8, [x2, #160]
  .long 0x6e281e08                    // eor v8.16b, v16.16b, v8.16b
  .long 0x3d802868                    // str q8, [x3, #160]
  .long 0x3dc03848                    // ldr q8, [x2, #224]
  .long 0x6e281e28                    // eor v8.16b, v17.16b, v8.16b
  .long 0x3d803868                    // str q8, [x3, #224]
  // quad 3 (words 12..15): accumulate, transpose, xor
  .long 0x4ebc858c                    // add v12.4s, v12.4s, v28.4s
  .long 0x4ebd85ad                    // add v13.4s, v13.4s, v29.4s
  .long 0x4ebe85ce                    // add v14.4s, v14.4s, v30.4s
  .long 0x4ebf85ef                    // add v15.4s, v15.4s, v31.4s
  .long 0x4e8d3990                    // zip1 v16.4s, v12.4s, v13.4s
  .long 0x4e8d7991                    // zip2 v17.4s, v12.4s, v13.4s
  .long 0x4e8f39cc                    // zip1 v12.4s, v14.4s, v15.4s
  .long 0x4e8f79cd                    // zip2 v13.4s, v14.4s, v15.4s
  .long 0x4ecc3a0e                    // zip1 v14.2d, v16.2d, v12.2d
  .long 0x4ecc7a0f                    // zip2 v15.2d, v16.2d, v12.2d
  .long 0x4ecd3a30                    // zip1 v16.2d, v17.2d, v13.2d
  .long 0x4ecd7a31                    // zip2 v17.2d, v17.2d, v13.2d
  .long 0x3dc00c4c                    // ldr q12, [x2, #48]
  .long 0x6e2c1dcc                    // eor v12.16b, v14.16b, v12.16b
  .long 0x3d800c6c                    // str q12, [x3, #48]
  .long 0x3dc01c4c                    // ldr q12, [x2, #112]
  .long 0x6e2c1dec                    // eor v12.16b, v15.16b, v12.16b
  .long 0x3d801c6c                    // str q12, [x3, #112]
  .long 0x3dc02c4c                    // ldr q12, [x2, #176]
  .long 0x6e2c1e0c                    // eor v12.16b, v16.16b, v12.16b
  .long 0x3d802c6c                    // str q12, [x3, #176]
  .long 0x3dc03c4c                    // ldr q12, [x2, #240]
  .long 0x6e2c1e2c                    // eor v12.16b, v17.16b, v12.16b
  .long 0x3d803c6c                    // str q12, [x3, #240]
  add x2, x2, #256
  add x3, x3, #256
  sub x4, x4, #1
  cbnz x4, .Lc7539_neon_outer
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
