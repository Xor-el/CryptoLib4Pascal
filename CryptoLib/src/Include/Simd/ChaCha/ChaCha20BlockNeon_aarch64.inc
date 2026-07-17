// ChaCha one-block (64B) core, NEON (aarch64), matching the contract of
// ChaCha20BlockSse2_x86_64.inc.
// -------------------------------------------------------------------
// Little-endian state in, 64B keystream out to AOut (keystream-only path,
// not the fused-I/O kernels' xor). Horizontal layout: one state row per
// vector (v0..v3), originals parked in v16..v19 (no stack copy needed on
// AArch64), v4 rotate scratch; rot16 is an in-place rev32 on 16-bit lanes,
// rot12/rot8/rot7 fold the preceding xor into v4 and rotate with shl + sri,
// and the diagonal re-indexing uses ext #4/#8/#12 lane rotations.
//
// On entry (after ClpSimdProc3Begin_aarch64.inc):
//   x0 = ARounds, x1 = AIn (16 UInt32 state), x2 = AOut (64B output).
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00421                    // ldr q1, [x1, #16]
  .long 0x3dc00822                    // ldr q2, [x1, #32]
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
  .long 0x4ea01c10                    // orr v16.16b, v0.16b, v0.16b
  .long 0x4ea11c31                    // orr v17.16b, v1.16b, v1.16b
  .long 0x4ea21c52                    // orr v18.16b, v2.16b, v2.16b
  .long 0x4ea31c73                    // orr v19.16b, v3.16b, v3.16b
  mov w5, w0
.Lc20_neon_core_round:
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f2c5481                    // shl v1.4s, v4.4s, #12
  .long 0x6f2c4481                    // sri v1.4s, v4.4s, #20
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c64                    // eor v4.16b, v3.16b, v0.16b
  .long 0x4f285483                    // shl v3.4s, v4.4s, #8
  .long 0x6f284483                    // sri v3.4s, v4.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f275481                    // shl v1.4s, v4.4s, #7
  .long 0x6f274481                    // sri v1.4s, v4.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e036063                    // ext v3.16b, v3.16b, v3.16b, #12
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f2c5481                    // shl v1.4s, v4.4s, #12
  .long 0x6f2c4481                    // sri v1.4s, v4.4s, #20
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c64                    // eor v4.16b, v3.16b, v0.16b
  .long 0x4f285483                    // shl v3.4s, v4.4s, #8
  .long 0x6f284483                    // sri v3.4s, v4.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f275481                    // shl v1.4s, v4.4s, #7
  .long 0x6f274481                    // sri v1.4s, v4.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  subs w5, w5, #2
  b.gt .Lc20_neon_core_round
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x4eb18421                    // add v1.4s, v1.4s, v17.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x3d800040                    // str q0, [x2]
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x3d800c43                    // str q3, [x2, #48]
  ret
