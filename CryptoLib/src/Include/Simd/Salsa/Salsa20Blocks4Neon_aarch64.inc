// Salsa20 4-way NEON keystream kernel, vertical layout (aarch64), matching
// the streaming contract of the width-4 chain in
// Salsa20Blocks4Sse2_x86_64.inc.
// -------------------------------------------------------------------
//
// Four 64-byte Salsa20 blocks per group, state words held vertically (one
// block per 32-bit lane): the whole working state is register-resident in
// v0..v15, with the broadcast originals of the 12 non-constant words
// parked in v20..v31 (the four diagonal constants 0/5/10/15 are
// re-broadcast from AState instead of parked, so v16..v19 remain free as
// four rotate temps; no stack frame beyond the shared d8..d15 save).
// Rotations 7/9/13/18 are shl+sri pairs on the quarter-round sum;
// quarter-rounds run as step-interleaved independent pairs (column then
// row quarters per double round).
//
// Streams AGroups x 256B in one call: prologue once, light per-group
// reload (counter lanes +4), fused accumulate/transpose/xor tail straight
// to AOut (4x4 zip transpose per word quad).
//
// The per-group AState counter write-back over words 8/9 is a single
// 64-bit add (Salsa's counter is 64-bit). The vector counter lanes always
// broadcast word 9, so the caller must guarantee the low counter word
// does not wrap inside the 4*AGroups-block span
// (TSalsa20Engine.WideGroupsSafe).
//
// On entry (after ClpSimdProc5Begin_aarch64.inc):
//   x0 = ARounds, x1 = AState (16 UInt32), x2 = AIn, x3 = AOut,
//   x4 = AGroups (4-block groups, >= 1; Int32 - zero-extended on entry).
//
// On exit:
//   AState words 8/9 counter (byte 32) advanced by 4*AGroups as one
//   64-bit value; the keystream is xored with AIn into AOut
//   (256*AGroups bytes).
//
// Reference: D.J. Bernstein, "Salsa20 specification" (cr.yp.to/salsa20/) -
// the quarterround/rowround/columnround arithmetic that this kernel's
// rounds implement.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  mov w4, w4
  // AGroups is Int32: zero-extend before use as a counter
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
  // park originals of the non-constant words in v20..v31
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cd4                    // dup v20.4s, w6
  .long 0xb9400826                    // ldr w6, [x1, #8]
  .long 0x4e040cd5                    // dup v21.4s, w6
  .long 0xb9400c26                    // ldr w6, [x1, #12]
  .long 0x4e040cd6                    // dup v22.4s, w6
  .long 0xb9401026                    // ldr w6, [x1, #16]
  .long 0x4e040cd7                    // dup v23.4s, w6
  .long 0xb9401826                    // ldr w6, [x1, #24]
  .long 0x4e040cd8                    // dup v24.4s, w6
  .long 0xb9401c26                    // ldr w6, [x1, #28]
  .long 0x4e040cd9                    // dup v25.4s, w6
  .long 0xb9402026                    // ldr w6, [x1, #32]
  .long 0x4e040cda                    // dup v26.4s, w6
  .long 0xb9402426                    // ldr w6, [x1, #36]
  .long 0x4e040cdb                    // dup v27.4s, w6
  .long 0xb9402c26                    // ldr w6, [x1, #44]
  .long 0x4e040cdc                    // dup v28.4s, w6
  .long 0xb9403026                    // ldr w6, [x1, #48]
  .long 0x4e040cdd                    // dup v29.4s, w6
  .long 0xb9403426                    // ldr w6, [x1, #52]
  .long 0x4e040cde                    // dup v30.4s, w6
  .long 0xb9403826                    // ldr w6, [x1, #56]
  .long 0x4e040cdf                    // dup v31.4s, w6
  // counter lanes: orig word 8 += (0, 1, 2, 3)
  .long 0x4f000410                    // movi v16.4s, #0
  mov w6, #1
  .long 0x4e0c1cd0                    // ins v16.s[1], w6
  mov w6, #2
  .long 0x4e141cd0                    // ins v16.s[2], w6
  mov w6, #3
  .long 0x4e1c1cd0                    // ins v16.s[3], w6
  .long 0x4eb0875a                    // add v26.4s, v26.4s, v16.4s
  b .Lsalsa_neon_b4_enter
.Lsalsa_neon_b4_outer:
  // next group: counter lanes += 4
  .long 0x4f000490                    // movi v16.4s, #4
  .long 0x4eb0875a                    // add v26.4s, v26.4s, v16.4s
.Lsalsa_neon_b4_enter:
  // seed the working state (constant words re-broadcast)
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cc0                    // dup v0.4s, w6
  .long 0xb9401426                    // ldr w6, [x1, #20]
  .long 0x4e040cc5                    // dup v5.4s, w6
  .long 0xb9402826                    // ldr w6, [x1, #40]
  .long 0x4e040cca                    // dup v10.4s, w6
  .long 0xb9403c26                    // ldr w6, [x1, #60]
  .long 0x4e040ccf                    // dup v15.4s, w6
  .long 0x4eb41e81                    // orr v1.16b, v20.16b, v20.16b
  .long 0x4eb51ea2                    // orr v2.16b, v21.16b, v21.16b
  .long 0x4eb61ec3                    // orr v3.16b, v22.16b, v22.16b
  .long 0x4eb71ee4                    // orr v4.16b, v23.16b, v23.16b
  .long 0x4eb81f06                    // orr v6.16b, v24.16b, v24.16b
  .long 0x4eb91f27                    // orr v7.16b, v25.16b, v25.16b
  .long 0x4eba1f48                    // orr v8.16b, v26.16b, v26.16b
  .long 0x4ebb1f69                    // orr v9.16b, v27.16b, v27.16b
  .long 0x4ebc1f8b                    // orr v11.16b, v28.16b, v28.16b
  .long 0x4ebd1fac                    // orr v12.16b, v29.16b, v29.16b
  .long 0x4ebe1fcd                    // orr v13.16b, v30.16b, v30.16b
  .long 0x4ebf1fee                    // orr v14.16b, v31.16b, v31.16b
  mov w5, w0
.Lsalsa_neon_b4_round:
  // column quarter-rounds
  .long 0x4eac8410                    // add v16.4s, v0.4s, v12.4s
  .long 0x4ea184b2                    // add v18.4s, v5.4s, v1.4s
  .long 0x4f275611                    // shl v17.4s, v16.4s, #7
  .long 0x4f275653                    // shl v19.4s, v18.4s, #7
  .long 0x6f274611                    // sri v17.4s, v16.4s, #25
  .long 0x6f274653                    // sri v19.4s, v18.4s, #25
  .long 0x6e311c84                    // eor v4.16b, v4.16b, v17.16b
  .long 0x6e331d29                    // eor v9.16b, v9.16b, v19.16b
  .long 0x4ea08490                    // add v16.4s, v4.4s, v0.4s
  .long 0x4ea58532                    // add v18.4s, v9.4s, v5.4s
  .long 0x4f295611                    // shl v17.4s, v16.4s, #9
  .long 0x4f295653                    // shl v19.4s, v18.4s, #9
  .long 0x6f294611                    // sri v17.4s, v16.4s, #23
  .long 0x6f294653                    // sri v19.4s, v18.4s, #23
  .long 0x6e311d08                    // eor v8.16b, v8.16b, v17.16b
  .long 0x6e331dad                    // eor v13.16b, v13.16b, v19.16b
  .long 0x4ea48510                    // add v16.4s, v8.4s, v4.4s
  .long 0x4ea985b2                    // add v18.4s, v13.4s, v9.4s
  .long 0x4f2d5611                    // shl v17.4s, v16.4s, #13
  .long 0x4f2d5653                    // shl v19.4s, v18.4s, #13
  .long 0x6f2d4611                    // sri v17.4s, v16.4s, #19
  .long 0x6f2d4653                    // sri v19.4s, v18.4s, #19
  .long 0x6e311d8c                    // eor v12.16b, v12.16b, v17.16b
  .long 0x6e331c21                    // eor v1.16b, v1.16b, v19.16b
  .long 0x4ea88590                    // add v16.4s, v12.4s, v8.4s
  .long 0x4ead8432                    // add v18.4s, v1.4s, v13.4s
  .long 0x4f325611                    // shl v17.4s, v16.4s, #18
  .long 0x4f325653                    // shl v19.4s, v18.4s, #18
  .long 0x6f324611                    // sri v17.4s, v16.4s, #14
  .long 0x6f324653                    // sri v19.4s, v18.4s, #14
  .long 0x6e311c00                    // eor v0.16b, v0.16b, v17.16b
  .long 0x6e331ca5                    // eor v5.16b, v5.16b, v19.16b
  .long 0x4ea68550                    // add v16.4s, v10.4s, v6.4s
  .long 0x4eab85f2                    // add v18.4s, v15.4s, v11.4s
  .long 0x4f275611                    // shl v17.4s, v16.4s, #7
  .long 0x4f275653                    // shl v19.4s, v18.4s, #7
  .long 0x6f274611                    // sri v17.4s, v16.4s, #25
  .long 0x6f274653                    // sri v19.4s, v18.4s, #25
  .long 0x6e311dce                    // eor v14.16b, v14.16b, v17.16b
  .long 0x6e331c63                    // eor v3.16b, v3.16b, v19.16b
  .long 0x4eaa85d0                    // add v16.4s, v14.4s, v10.4s
  .long 0x4eaf8472                    // add v18.4s, v3.4s, v15.4s
  .long 0x4f295611                    // shl v17.4s, v16.4s, #9
  .long 0x4f295653                    // shl v19.4s, v18.4s, #9
  .long 0x6f294611                    // sri v17.4s, v16.4s, #23
  .long 0x6f294653                    // sri v19.4s, v18.4s, #23
  .long 0x6e311c42                    // eor v2.16b, v2.16b, v17.16b
  .long 0x6e331ce7                    // eor v7.16b, v7.16b, v19.16b
  .long 0x4eae8450                    // add v16.4s, v2.4s, v14.4s
  .long 0x4ea384f2                    // add v18.4s, v7.4s, v3.4s
  .long 0x4f2d5611                    // shl v17.4s, v16.4s, #13
  .long 0x4f2d5653                    // shl v19.4s, v18.4s, #13
  .long 0x6f2d4611                    // sri v17.4s, v16.4s, #19
  .long 0x6f2d4653                    // sri v19.4s, v18.4s, #19
  .long 0x6e311cc6                    // eor v6.16b, v6.16b, v17.16b
  .long 0x6e331d6b                    // eor v11.16b, v11.16b, v19.16b
  .long 0x4ea284d0                    // add v16.4s, v6.4s, v2.4s
  .long 0x4ea78572                    // add v18.4s, v11.4s, v7.4s
  .long 0x4f325611                    // shl v17.4s, v16.4s, #18
  .long 0x4f325653                    // shl v19.4s, v18.4s, #18
  .long 0x6f324611                    // sri v17.4s, v16.4s, #14
  .long 0x6f324653                    // sri v19.4s, v18.4s, #14
  .long 0x6e311d4a                    // eor v10.16b, v10.16b, v17.16b
  .long 0x6e331def                    // eor v15.16b, v15.16b, v19.16b
  // row quarter-rounds
  .long 0x4ea38410                    // add v16.4s, v0.4s, v3.4s
  .long 0x4ea484b2                    // add v18.4s, v5.4s, v4.4s
  .long 0x4f275611                    // shl v17.4s, v16.4s, #7
  .long 0x4f275653                    // shl v19.4s, v18.4s, #7
  .long 0x6f274611                    // sri v17.4s, v16.4s, #25
  .long 0x6f274653                    // sri v19.4s, v18.4s, #25
  .long 0x6e311c21                    // eor v1.16b, v1.16b, v17.16b
  .long 0x6e331cc6                    // eor v6.16b, v6.16b, v19.16b
  .long 0x4ea08430                    // add v16.4s, v1.4s, v0.4s
  .long 0x4ea584d2                    // add v18.4s, v6.4s, v5.4s
  .long 0x4f295611                    // shl v17.4s, v16.4s, #9
  .long 0x4f295653                    // shl v19.4s, v18.4s, #9
  .long 0x6f294611                    // sri v17.4s, v16.4s, #23
  .long 0x6f294653                    // sri v19.4s, v18.4s, #23
  .long 0x6e311c42                    // eor v2.16b, v2.16b, v17.16b
  .long 0x6e331ce7                    // eor v7.16b, v7.16b, v19.16b
  .long 0x4ea18450                    // add v16.4s, v2.4s, v1.4s
  .long 0x4ea684f2                    // add v18.4s, v7.4s, v6.4s
  .long 0x4f2d5611                    // shl v17.4s, v16.4s, #13
  .long 0x4f2d5653                    // shl v19.4s, v18.4s, #13
  .long 0x6f2d4611                    // sri v17.4s, v16.4s, #19
  .long 0x6f2d4653                    // sri v19.4s, v18.4s, #19
  .long 0x6e311c63                    // eor v3.16b, v3.16b, v17.16b
  .long 0x6e331c84                    // eor v4.16b, v4.16b, v19.16b
  .long 0x4ea28470                    // add v16.4s, v3.4s, v2.4s
  .long 0x4ea78492                    // add v18.4s, v4.4s, v7.4s
  .long 0x4f325611                    // shl v17.4s, v16.4s, #18
  .long 0x4f325653                    // shl v19.4s, v18.4s, #18
  .long 0x6f324611                    // sri v17.4s, v16.4s, #14
  .long 0x6f324653                    // sri v19.4s, v18.4s, #14
  .long 0x6e311c00                    // eor v0.16b, v0.16b, v17.16b
  .long 0x6e331ca5                    // eor v5.16b, v5.16b, v19.16b
  .long 0x4ea98550                    // add v16.4s, v10.4s, v9.4s
  .long 0x4eae85f2                    // add v18.4s, v15.4s, v14.4s
  .long 0x4f275611                    // shl v17.4s, v16.4s, #7
  .long 0x4f275653                    // shl v19.4s, v18.4s, #7
  .long 0x6f274611                    // sri v17.4s, v16.4s, #25
  .long 0x6f274653                    // sri v19.4s, v18.4s, #25
  .long 0x6e311d6b                    // eor v11.16b, v11.16b, v17.16b
  .long 0x6e331d8c                    // eor v12.16b, v12.16b, v19.16b
  .long 0x4eaa8570                    // add v16.4s, v11.4s, v10.4s
  .long 0x4eaf8592                    // add v18.4s, v12.4s, v15.4s
  .long 0x4f295611                    // shl v17.4s, v16.4s, #9
  .long 0x4f295653                    // shl v19.4s, v18.4s, #9
  .long 0x6f294611                    // sri v17.4s, v16.4s, #23
  .long 0x6f294653                    // sri v19.4s, v18.4s, #23
  .long 0x6e311d08                    // eor v8.16b, v8.16b, v17.16b
  .long 0x6e331dad                    // eor v13.16b, v13.16b, v19.16b
  .long 0x4eab8510                    // add v16.4s, v8.4s, v11.4s
  .long 0x4eac85b2                    // add v18.4s, v13.4s, v12.4s
  .long 0x4f2d5611                    // shl v17.4s, v16.4s, #13
  .long 0x4f2d5653                    // shl v19.4s, v18.4s, #13
  .long 0x6f2d4611                    // sri v17.4s, v16.4s, #19
  .long 0x6f2d4653                    // sri v19.4s, v18.4s, #19
  .long 0x6e311d29                    // eor v9.16b, v9.16b, v17.16b
  .long 0x6e331dce                    // eor v14.16b, v14.16b, v19.16b
  .long 0x4ea88530                    // add v16.4s, v9.4s, v8.4s
  .long 0x4ead85d2                    // add v18.4s, v14.4s, v13.4s
  .long 0x4f325611                    // shl v17.4s, v16.4s, #18
  .long 0x4f325653                    // shl v19.4s, v18.4s, #18
  .long 0x6f324611                    // sri v17.4s, v16.4s, #14
  .long 0x6f324653                    // sri v19.4s, v18.4s, #14
  .long 0x6e311d4a                    // eor v10.16b, v10.16b, v17.16b
  .long 0x6e331def                    // eor v15.16b, v15.16b, v19.16b
  subs w5, w5, #2
  b.gt .Lsalsa_neon_b4_round
  // advance the state counter (words 8/9, one 64-bit add)
  .long 0xf9401026                    // ldr x6, [x1, #32]
  add x6, x6, #4
  .long 0xf9001026                    // str x6, [x1, #32]
  // quad 0 (words 0..3): accumulate, transpose, xor
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x4eb48421                    // add v1.4s, v1.4s, v20.4s
  .long 0x4eb58442                    // add v2.4s, v2.4s, v21.4s
  .long 0x4eb68463                    // add v3.4s, v3.4s, v22.4s
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
  .long 0x4eb78484                    // add v4.4s, v4.4s, v23.4s
  .long 0xb9401426                    // ldr w6, [x1, #20]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb084a5                    // add v5.4s, v5.4s, v16.4s
  .long 0x4eb884c6                    // add v6.4s, v6.4s, v24.4s
  .long 0x4eb984e7                    // add v7.4s, v7.4s, v25.4s
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
  .long 0x4eba8508                    // add v8.4s, v8.4s, v26.4s
  .long 0x4ebb8529                    // add v9.4s, v9.4s, v27.4s
  .long 0xb9402826                    // ldr w6, [x1, #40]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb0854a                    // add v10.4s, v10.4s, v16.4s
  .long 0x4ebc856b                    // add v11.4s, v11.4s, v28.4s
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
  .long 0x4ebd858c                    // add v12.4s, v12.4s, v29.4s
  .long 0x4ebe85ad                    // add v13.4s, v13.4s, v30.4s
  .long 0x4ebf85ce                    // add v14.4s, v14.4s, v31.4s
  .long 0xb9403c26                    // ldr w6, [x1, #60]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb085ef                    // add v15.4s, v15.4s, v16.4s
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
  cbnz x4, .Lsalsa_neon_b4_outer
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
