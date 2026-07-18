// OCB fused 8-wide AES CryptoExt kernel (aarch64) with a round-interleaved
// offset ladder, L-table lookup and checksum fold, matching the width-8
// chain in AesOcbFusedWide_x86_64.inc.
// -------------------------------------------------------------------
// Processes ABlockCount consecutive 16-byte OCB body blocks, two 8-block
// iterations (256 bytes) per loop pass. v0..v7 data lanes, v8 offset
// accumulator, v9 checksum accumulator, v16..v(16+N_R) resident round keys,
// v31 L-table / delta-reload scratch. The offset ladder for the NEXT
// 8-block iteration is staged between the AES round groups of the current
// one into the opposite of two ping-pong delta banks on the stack, so the
// ladder's serial rbit/clz/load/xor chain rides the AES latency instead of
// running as a prefix; the prologue pre-stages iteration 0, and the final
// pass over-stages one iteration, undone afterwards by re-XORing the same
// eight L entries (XOR is self-inverse; the counter is not persisted, so
// only the offset accumulator needs the rollback). The 64-bit block counter
// lives whole in x6, so the ladder is branch-free (rbit/clz sees zero only
// at the 2^64 wrap, unreachable under OCB limits). No K_0 pre-whitening is
// needed on AArch64 - the first aese/aesd consumes the first schedule slot;
// lanes are whitened with the stashed deltas alone.
//
// Variant selection:
//   CRYPTOLIB_AESCRYPTOEXT_DECRYPT -> aesd / aesimc over the inverse
//                              schedule; else aese / aesmc.
//   Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128 / KEY192 / KEY256
//                              selects N_R.
//
// On entry (after ClpSimdProc1Begin_aarch64.inc): x0 = PCtx.
// Context layout: see TOcbFusedKernelCtx in ClpAesCryptoExtOcbKernel.pas
// (field offsets identical to the x86_64 kernel's).
// BlockCount must be a positive multiple of 16.
//
// GPR: x0 = PCtx, x1 = Keys, x2 = InPtr, x3 = OutPtr, x4 = LTablePtr,
//   x5 = pass countdown, x6 = block counter, x7 = ladder scratch,
//   x8 = iteration block-0 source pointer.
//
// Stack scratch (16-aligned, below the d8..d15 save frame):
//   [sp+0..127] delta bank 0, [sp+128..255] delta bank 1.
//
// The kernel clobbers v8 / v9, so it brackets itself with the shared
// ClpSimdNonVolatileSave/Restore_aarch64.inc d8..d15 frames.
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
  .long 0xd10403ff                    // sub sp, sp, #256
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9401404                    // ldr x4, [x0, #40]
  .long 0xf9401c05                    // ldr x5, [x0, #56]
  .long 0xd344fca5                    // lsr x5, x5, #4
  .long 0xf9402006                    // ldr x6, [x0, #64]
  // x1 = Keys, x2 = InPtr, x3 = OutPtr, x4 = LTablePtr,
  // x5 = pass countdown (BlockCount / 16), x6 = block counter
  .long 0xad404430                    // ldp q16, q17, [x1]
  .long 0xad414c32                    // ldp q18, q19, [x1, #32]
  .long 0xad425434                    // ldp q20, q21, [x1, #64]
  .long 0xad435c36                    // ldp q22, q23, [x1, #96]
  .long 0xad446438                    // ldp q24, q25, [x1, #128]
  .long 0x3dc0283a                    // ldr q26, [x1, #160]
  .long 0xf9400c07                    // ldr x7, [x0, #24]
  .long 0x3dc000e8                    // ldr q8, [x7]
  .long 0xf9401007                    // ldr x7, [x0, #32]
  .long 0x3dc000e9                    // ldr q9, [x7]
  // pre-stage iteration 0's Deltas into bank 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  .long 0xf9401808                    // ldr x8, [x0, #48]
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
.Laesce_ocbdec128_loop:
{$ELSE}
.Laesce_ocbenc128_loop:
{$ENDIF}
  // load 8 blocks (block 0 via the staged source)
  .long 0x3dc00100                    // ldr q0, [x8]
  .long 0x3dc00441                    // ldr q1, [x2, #16]
  .long 0x3dc00842                    // ldr q2, [x2, #32]
  .long 0x3dc00c43                    // ldr q3, [x2, #48]
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x3dc01445                    // ldr q5, [x2, #80]
  .long 0x3dc01846                    // ldr q6, [x2, #96]
  .long 0x3dc01c47                    // ldr q7, [x2, #112]
{$IFNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  // pre-whiten with this iteration's stashed Deltas
  .long 0x3dc003ff                    // ldr q31, [sp]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc007ff                    // ldr q31, [sp, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc00bff                    // ldr q31, [sp, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc00fff                    // ldr q31, [sp, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc013ff                    // ldr q31, [sp, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc017ff                    // ldr q31, [sp, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc01bff                    // ldr q31, [sp, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc01fff                    // ldr q31, [sp, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // round 0
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
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8023e8                    // str q8, [sp, #128]
  // round 1
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
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8027e8                    // str q8, [sp, #144]
  // round 2
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
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802be8                    // str q8, [sp, #160]
  // round 3
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
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802fe8                    // str q8, [sp, #176]
  // round 4
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
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8033e8                    // str q8, [sp, #192]
  // round 5
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
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8037e8                    // str q8, [sp, #208]
  // round 6
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
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803be8                    // str q8, [sp, #224]
  // round 7
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
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803fe8                    // str q8, [sp, #240]
  // round 8
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
  // round 9
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x4e285b24                    // aesd v4.16b, v25.16b
  .long 0x4e285b25                    // aesd v5.16b, v25.16b
  .long 0x4e285b26                    // aesd v6.16b, v25.16b
  .long 0x4e285b27                    // aesd v7.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
{$ELSE}
  // round 0
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8023e8                    // str q8, [sp, #128]
  // round 1
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8027e8                    // str q8, [sp, #144]
  // round 2
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802be8                    // str q8, [sp, #160]
  // round 3
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802fe8                    // str q8, [sp, #176]
  // round 4
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8033e8                    // str q8, [sp, #192]
  // round 5
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8037e8                    // str q8, [sp, #208]
  // round 6
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803be8                    // str q8, [sp, #224]
  // round 7
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803fe8                    // str q8, [sp, #240]
  // round 8
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 9
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
{$ENDIF}
  // post-whiten with this iteration's Deltas
  .long 0x3dc003ff                    // ldr q31, [sp]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc007ff                    // ldr q31, [sp, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc00bff                    // ldr q31, [sp, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc00fff                    // ldr q31, [sp, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc013ff                    // ldr q31, [sp, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc017ff                    // ldr q31, [sp, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc01bff                    // ldr q31, [sp, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc01fff                    // ldr q31, [sp, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold recovered plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  add x2, x2, #128
  add x3, x3, #128
  mov x8, x2
  // load 8 blocks (block 0 via the staged source)
  .long 0x3dc00100                    // ldr q0, [x8]
  .long 0x3dc00441                    // ldr q1, [x2, #16]
  .long 0x3dc00842                    // ldr q2, [x2, #32]
  .long 0x3dc00c43                    // ldr q3, [x2, #48]
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x3dc01445                    // ldr q5, [x2, #80]
  .long 0x3dc01846                    // ldr q6, [x2, #96]
  .long 0x3dc01c47                    // ldr q7, [x2, #112]
{$IFNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  // pre-whiten with this iteration's stashed Deltas
  .long 0x3dc023ff                    // ldr q31, [sp, #128]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc027ff                    // ldr q31, [sp, #144]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc02bff                    // ldr q31, [sp, #160]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc02fff                    // ldr q31, [sp, #176]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc033ff                    // ldr q31, [sp, #192]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc037ff                    // ldr q31, [sp, #208]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc03bff                    // ldr q31, [sp, #224]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc03fff                    // ldr q31, [sp, #240]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // round 0
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
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  // round 1
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
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  // round 2
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
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  // round 3
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
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  // round 4
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
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  // round 5
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
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  // round 6
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
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  // round 7
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
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  // round 8
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
  // round 9
  .long 0x4e285b20                    // aesd v0.16b, v25.16b
  .long 0x4e285b21                    // aesd v1.16b, v25.16b
  .long 0x4e285b22                    // aesd v2.16b, v25.16b
  .long 0x4e285b23                    // aesd v3.16b, v25.16b
  .long 0x4e285b24                    // aesd v4.16b, v25.16b
  .long 0x4e285b25                    // aesd v5.16b, v25.16b
  .long 0x4e285b26                    // aesd v6.16b, v25.16b
  .long 0x4e285b27                    // aesd v7.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
{$ELSE}
  // round 0
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  // round 1
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  // round 2
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  // round 3
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  // round 4
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  // round 5
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  // round 6
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  // round 7
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  // round 8
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 9
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e3a1c42                    // eor v2.16b, v2.16b, v26.16b
  .long 0x6e3a1c63                    // eor v3.16b, v3.16b, v26.16b
  .long 0x6e3a1c84                    // eor v4.16b, v4.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1cc6                    // eor v6.16b, v6.16b, v26.16b
  .long 0x6e3a1ce7                    // eor v7.16b, v7.16b, v26.16b
{$ENDIF}
  // post-whiten with this iteration's Deltas
  .long 0x3dc023ff                    // ldr q31, [sp, #128]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc027ff                    // ldr q31, [sp, #144]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc02bff                    // ldr q31, [sp, #160]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc02fff                    // ldr q31, [sp, #176]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc033ff                    // ldr q31, [sp, #192]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc037ff                    // ldr q31, [sp, #208]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc03bff                    // ldr q31, [sp, #224]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc03fff                    // ldr q31, [sp, #240]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold recovered plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  add x2, x2, #128
  add x3, x3, #128
  mov x8, x2
  sub x5, x5, #1
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  cbnz x5, .Laesce_ocbdec128_loop
{$ELSE}
  cbnz x5, .Laesce_ocbenc128_loop
{$ENDIF}
  // undo the one-iteration ladder over-stage (XOR self-inverse)
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  // flush accumulators, unwind
  .long 0xf9400c07                    // ldr x7, [x0, #24]
  .long 0x3d8000e8                    // str q8, [x7]
  .long 0xf9401007                    // ldr x7, [x0, #32]
  .long 0x3d8000e9                    // str q9, [x7]
  .long 0x910403ff                    // add sp, sp, #256
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
  .long 0xd10403ff                    // sub sp, sp, #256
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9401404                    // ldr x4, [x0, #40]
  .long 0xf9401c05                    // ldr x5, [x0, #56]
  .long 0xd344fca5                    // lsr x5, x5, #4
  .long 0xf9402006                    // ldr x6, [x0, #64]
  // x1 = Keys, x2 = InPtr, x3 = OutPtr, x4 = LTablePtr,
  // x5 = pass countdown (BlockCount / 16), x6 = block counter
  .long 0xad404430                    // ldp q16, q17, [x1]
  .long 0xad414c32                    // ldp q18, q19, [x1, #32]
  .long 0xad425434                    // ldp q20, q21, [x1, #64]
  .long 0xad435c36                    // ldp q22, q23, [x1, #96]
  .long 0xad446438                    // ldp q24, q25, [x1, #128]
  .long 0xad456c3a                    // ldp q26, q27, [x1, #160]
  .long 0x3dc0303c                    // ldr q28, [x1, #192]
  .long 0xf9400c07                    // ldr x7, [x0, #24]
  .long 0x3dc000e8                    // ldr q8, [x7]
  .long 0xf9401007                    // ldr x7, [x0, #32]
  .long 0x3dc000e9                    // ldr q9, [x7]
  // pre-stage iteration 0's Deltas into bank 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  .long 0xf9401808                    // ldr x8, [x0, #48]
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
.Laesce_ocbdec192_loop:
{$ELSE}
.Laesce_ocbenc192_loop:
{$ENDIF}
  // load 8 blocks (block 0 via the staged source)
  .long 0x3dc00100                    // ldr q0, [x8]
  .long 0x3dc00441                    // ldr q1, [x2, #16]
  .long 0x3dc00842                    // ldr q2, [x2, #32]
  .long 0x3dc00c43                    // ldr q3, [x2, #48]
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x3dc01445                    // ldr q5, [x2, #80]
  .long 0x3dc01846                    // ldr q6, [x2, #96]
  .long 0x3dc01c47                    // ldr q7, [x2, #112]
{$IFNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  // pre-whiten with this iteration's stashed Deltas
  .long 0x3dc003ff                    // ldr q31, [sp]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc007ff                    // ldr q31, [sp, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc00bff                    // ldr q31, [sp, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc00fff                    // ldr q31, [sp, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc013ff                    // ldr q31, [sp, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc017ff                    // ldr q31, [sp, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc01bff                    // ldr q31, [sp, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc01fff                    // ldr q31, [sp, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // round 0
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
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8023e8                    // str q8, [sp, #128]
  // round 1
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
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8027e8                    // str q8, [sp, #144]
  // round 2
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
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802be8                    // str q8, [sp, #160]
  // round 3
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
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802fe8                    // str q8, [sp, #176]
  // round 4
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
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8033e8                    // str q8, [sp, #192]
  // round 5
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
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8037e8                    // str q8, [sp, #208]
  // round 6
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
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803be8                    // str q8, [sp, #224]
  // round 7
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
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803fe8                    // str q8, [sp, #240]
  // round 8
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
  // round 9
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
  // round 10
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
  // round 11
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x4e285b61                    // aesd v1.16b, v27.16b
  .long 0x4e285b62                    // aesd v2.16b, v27.16b
  .long 0x4e285b63                    // aesd v3.16b, v27.16b
  .long 0x4e285b64                    // aesd v4.16b, v27.16b
  .long 0x4e285b65                    // aesd v5.16b, v27.16b
  .long 0x4e285b66                    // aesd v6.16b, v27.16b
  .long 0x4e285b67                    // aesd v7.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  .long 0x6e3c1c84                    // eor v4.16b, v4.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1cc6                    // eor v6.16b, v6.16b, v28.16b
  .long 0x6e3c1ce7                    // eor v7.16b, v7.16b, v28.16b
{$ELSE}
  // round 0
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8023e8                    // str q8, [sp, #128]
  // round 1
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8027e8                    // str q8, [sp, #144]
  // round 2
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802be8                    // str q8, [sp, #160]
  // round 3
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802fe8                    // str q8, [sp, #176]
  // round 4
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8033e8                    // str q8, [sp, #192]
  // round 5
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8037e8                    // str q8, [sp, #208]
  // round 6
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803be8                    // str q8, [sp, #224]
  // round 7
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803fe8                    // str q8, [sp, #240]
  // round 8
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 9
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 10
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b44                    // aese v4.16b, v26.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b46                    // aese v6.16b, v26.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b47                    // aese v7.16b, v26.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 11
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e284b64                    // aese v4.16b, v27.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e284b66                    // aese v6.16b, v27.16b
  .long 0x4e284b67                    // aese v7.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  .long 0x6e3c1c84                    // eor v4.16b, v4.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1cc6                    // eor v6.16b, v6.16b, v28.16b
  .long 0x6e3c1ce7                    // eor v7.16b, v7.16b, v28.16b
{$ENDIF}
  // post-whiten with this iteration's Deltas
  .long 0x3dc003ff                    // ldr q31, [sp]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc007ff                    // ldr q31, [sp, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc00bff                    // ldr q31, [sp, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc00fff                    // ldr q31, [sp, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc013ff                    // ldr q31, [sp, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc017ff                    // ldr q31, [sp, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc01bff                    // ldr q31, [sp, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc01fff                    // ldr q31, [sp, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold recovered plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  add x2, x2, #128
  add x3, x3, #128
  mov x8, x2
  // load 8 blocks (block 0 via the staged source)
  .long 0x3dc00100                    // ldr q0, [x8]
  .long 0x3dc00441                    // ldr q1, [x2, #16]
  .long 0x3dc00842                    // ldr q2, [x2, #32]
  .long 0x3dc00c43                    // ldr q3, [x2, #48]
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x3dc01445                    // ldr q5, [x2, #80]
  .long 0x3dc01846                    // ldr q6, [x2, #96]
  .long 0x3dc01c47                    // ldr q7, [x2, #112]
{$IFNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  // pre-whiten with this iteration's stashed Deltas
  .long 0x3dc023ff                    // ldr q31, [sp, #128]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc027ff                    // ldr q31, [sp, #144]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc02bff                    // ldr q31, [sp, #160]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc02fff                    // ldr q31, [sp, #176]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc033ff                    // ldr q31, [sp, #192]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc037ff                    // ldr q31, [sp, #208]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc03bff                    // ldr q31, [sp, #224]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc03fff                    // ldr q31, [sp, #240]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // round 0
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
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  // round 1
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
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  // round 2
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
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  // round 3
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
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  // round 4
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
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  // round 5
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
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  // round 6
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
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  // round 7
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
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  // round 8
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
  // round 9
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
  // round 10
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
  // round 11
  .long 0x4e285b60                    // aesd v0.16b, v27.16b
  .long 0x4e285b61                    // aesd v1.16b, v27.16b
  .long 0x4e285b62                    // aesd v2.16b, v27.16b
  .long 0x4e285b63                    // aesd v3.16b, v27.16b
  .long 0x4e285b64                    // aesd v4.16b, v27.16b
  .long 0x4e285b65                    // aesd v5.16b, v27.16b
  .long 0x4e285b66                    // aesd v6.16b, v27.16b
  .long 0x4e285b67                    // aesd v7.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  .long 0x6e3c1c84                    // eor v4.16b, v4.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1cc6                    // eor v6.16b, v6.16b, v28.16b
  .long 0x6e3c1ce7                    // eor v7.16b, v7.16b, v28.16b
{$ELSE}
  // round 0
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  // round 1
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  // round 2
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  // round 3
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  // round 4
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  // round 5
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  // round 6
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  // round 7
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  // round 8
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 9
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 10
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b44                    // aese v4.16b, v26.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b46                    // aese v6.16b, v26.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b47                    // aese v7.16b, v26.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 11
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e284b64                    // aese v4.16b, v27.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e284b66                    // aese v6.16b, v27.16b
  .long 0x4e284b67                    // aese v7.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e3c1c42                    // eor v2.16b, v2.16b, v28.16b
  .long 0x6e3c1c63                    // eor v3.16b, v3.16b, v28.16b
  .long 0x6e3c1c84                    // eor v4.16b, v4.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1cc6                    // eor v6.16b, v6.16b, v28.16b
  .long 0x6e3c1ce7                    // eor v7.16b, v7.16b, v28.16b
{$ENDIF}
  // post-whiten with this iteration's Deltas
  .long 0x3dc023ff                    // ldr q31, [sp, #128]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc027ff                    // ldr q31, [sp, #144]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc02bff                    // ldr q31, [sp, #160]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc02fff                    // ldr q31, [sp, #176]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc033ff                    // ldr q31, [sp, #192]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc037ff                    // ldr q31, [sp, #208]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc03bff                    // ldr q31, [sp, #224]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc03fff                    // ldr q31, [sp, #240]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold recovered plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  add x2, x2, #128
  add x3, x3, #128
  mov x8, x2
  sub x5, x5, #1
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  cbnz x5, .Laesce_ocbdec192_loop
{$ELSE}
  cbnz x5, .Laesce_ocbenc192_loop
{$ENDIF}
  // undo the one-iteration ladder over-stage (XOR self-inverse)
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  // flush accumulators, unwind
  .long 0xf9400c07                    // ldr x7, [x0, #24]
  .long 0x3d8000e8                    // str q8, [x7]
  .long 0xf9401007                    // ldr x7, [x0, #32]
  .long 0x3d8000e9                    // str q9, [x7]
  .long 0x910403ff                    // add sp, sp, #256
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
  .long 0xd10403ff                    // sub sp, sp, #256
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9401404                    // ldr x4, [x0, #40]
  .long 0xf9401c05                    // ldr x5, [x0, #56]
  .long 0xd344fca5                    // lsr x5, x5, #4
  .long 0xf9402006                    // ldr x6, [x0, #64]
  // x1 = Keys, x2 = InPtr, x3 = OutPtr, x4 = LTablePtr,
  // x5 = pass countdown (BlockCount / 16), x6 = block counter
  .long 0xad404430                    // ldp q16, q17, [x1]
  .long 0xad414c32                    // ldp q18, q19, [x1, #32]
  .long 0xad425434                    // ldp q20, q21, [x1, #64]
  .long 0xad435c36                    // ldp q22, q23, [x1, #96]
  .long 0xad446438                    // ldp q24, q25, [x1, #128]
  .long 0xad456c3a                    // ldp q26, q27, [x1, #160]
  .long 0xad46743c                    // ldp q28, q29, [x1, #192]
  .long 0x3dc0383e                    // ldr q30, [x1, #224]
  .long 0xf9400c07                    // ldr x7, [x0, #24]
  .long 0x3dc000e8                    // ldr q8, [x7]
  .long 0xf9401007                    // ldr x7, [x0, #32]
  .long 0x3dc000e9                    // ldr q9, [x7]
  // pre-stage iteration 0's Deltas into bank 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  .long 0xf9401808                    // ldr x8, [x0, #48]
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
.Laesce_ocbdec256_loop:
{$ELSE}
.Laesce_ocbenc256_loop:
{$ENDIF}
  // load 8 blocks (block 0 via the staged source)
  .long 0x3dc00100                    // ldr q0, [x8]
  .long 0x3dc00441                    // ldr q1, [x2, #16]
  .long 0x3dc00842                    // ldr q2, [x2, #32]
  .long 0x3dc00c43                    // ldr q3, [x2, #48]
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x3dc01445                    // ldr q5, [x2, #80]
  .long 0x3dc01846                    // ldr q6, [x2, #96]
  .long 0x3dc01c47                    // ldr q7, [x2, #112]
{$IFNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  // pre-whiten with this iteration's stashed Deltas
  .long 0x3dc003ff                    // ldr q31, [sp]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc007ff                    // ldr q31, [sp, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc00bff                    // ldr q31, [sp, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc00fff                    // ldr q31, [sp, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc013ff                    // ldr q31, [sp, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc017ff                    // ldr q31, [sp, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc01bff                    // ldr q31, [sp, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc01fff                    // ldr q31, [sp, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // round 0
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
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8023e8                    // str q8, [sp, #128]
  // round 1
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
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8027e8                    // str q8, [sp, #144]
  // round 2
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
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802be8                    // str q8, [sp, #160]
  // round 3
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
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802fe8                    // str q8, [sp, #176]
  // round 4
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
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8033e8                    // str q8, [sp, #192]
  // round 5
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
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8037e8                    // str q8, [sp, #208]
  // round 6
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
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803be8                    // str q8, [sp, #224]
  // round 7
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
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803fe8                    // str q8, [sp, #240]
  // round 8
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
  // round 9
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
  // round 10
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
  // round 11
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
  // round 12
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
  // round 13
  .long 0x4e285ba0                    // aesd v0.16b, v29.16b
  .long 0x4e285ba1                    // aesd v1.16b, v29.16b
  .long 0x4e285ba2                    // aesd v2.16b, v29.16b
  .long 0x4e285ba3                    // aesd v3.16b, v29.16b
  .long 0x4e285ba4                    // aesd v4.16b, v29.16b
  .long 0x4e285ba5                    // aesd v5.16b, v29.16b
  .long 0x4e285ba6                    // aesd v6.16b, v29.16b
  .long 0x4e285ba7                    // aesd v7.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
{$ELSE}
  // round 0
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8023e8                    // str q8, [sp, #128]
  // round 1
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8027e8                    // str q8, [sp, #144]
  // round 2
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802be8                    // str q8, [sp, #160]
  // round 3
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d802fe8                    // str q8, [sp, #176]
  // round 4
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8033e8                    // str q8, [sp, #192]
  // round 5
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8037e8                    // str q8, [sp, #208]
  // round 6
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803be8                    // str q8, [sp, #224]
  // round 7
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d803fe8                    // str q8, [sp, #240]
  // round 8
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 9
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 10
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b44                    // aese v4.16b, v26.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b46                    // aese v6.16b, v26.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b47                    // aese v7.16b, v26.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 11
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b64                    // aese v4.16b, v27.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b66                    // aese v6.16b, v27.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b67                    // aese v7.16b, v27.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 12
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b82                    // aese v2.16b, v28.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b83                    // aese v3.16b, v28.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b84                    // aese v4.16b, v28.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b85                    // aese v5.16b, v28.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b86                    // aese v6.16b, v28.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b87                    // aese v7.16b, v28.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 13
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x4e284ba2                    // aese v2.16b, v29.16b
  .long 0x4e284ba3                    // aese v3.16b, v29.16b
  .long 0x4e284ba4                    // aese v4.16b, v29.16b
  .long 0x4e284ba5                    // aese v5.16b, v29.16b
  .long 0x4e284ba6                    // aese v6.16b, v29.16b
  .long 0x4e284ba7                    // aese v7.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
{$ENDIF}
  // post-whiten with this iteration's Deltas
  .long 0x3dc003ff                    // ldr q31, [sp]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc007ff                    // ldr q31, [sp, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc00bff                    // ldr q31, [sp, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc00fff                    // ldr q31, [sp, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc013ff                    // ldr q31, [sp, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc017ff                    // ldr q31, [sp, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc01bff                    // ldr q31, [sp, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc01fff                    // ldr q31, [sp, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold recovered plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  add x2, x2, #128
  add x3, x3, #128
  mov x8, x2
  // load 8 blocks (block 0 via the staged source)
  .long 0x3dc00100                    // ldr q0, [x8]
  .long 0x3dc00441                    // ldr q1, [x2, #16]
  .long 0x3dc00842                    // ldr q2, [x2, #32]
  .long 0x3dc00c43                    // ldr q3, [x2, #48]
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x3dc01445                    // ldr q5, [x2, #80]
  .long 0x3dc01846                    // ldr q6, [x2, #96]
  .long 0x3dc01c47                    // ldr q7, [x2, #112]
{$IFNDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  // pre-whiten with this iteration's stashed Deltas
  .long 0x3dc023ff                    // ldr q31, [sp, #128]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc027ff                    // ldr q31, [sp, #144]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc02bff                    // ldr q31, [sp, #160]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc02fff                    // ldr q31, [sp, #176]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc033ff                    // ldr q31, [sp, #192]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc037ff                    // ldr q31, [sp, #208]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc03bff                    // ldr q31, [sp, #224]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc03fff                    // ldr q31, [sp, #240]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // round 0
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
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  // round 1
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
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  // round 2
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
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  // round 3
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
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  // round 4
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
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  // round 5
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
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  // round 6
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
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  // round 7
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
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  // round 8
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
  // round 9
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
  // round 10
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
  // round 11
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
  // round 12
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
  // round 13
  .long 0x4e285ba0                    // aesd v0.16b, v29.16b
  .long 0x4e285ba1                    // aesd v1.16b, v29.16b
  .long 0x4e285ba2                    // aesd v2.16b, v29.16b
  .long 0x4e285ba3                    // aesd v3.16b, v29.16b
  .long 0x4e285ba4                    // aesd v4.16b, v29.16b
  .long 0x4e285ba5                    // aesd v5.16b, v29.16b
  .long 0x4e285ba6                    // aesd v6.16b, v29.16b
  .long 0x4e285ba7                    // aesd v7.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
{$ELSE}
  // round 0
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 0
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8003e8                    // str q8, [sp]
  // round 1
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 1
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8007e8                    // str q8, [sp, #16]
  // round 2
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 2
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800be8                    // str q8, [sp, #32]
  // round 3
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 3
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d800fe8                    // str q8, [sp, #48]
  // round 4
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 4
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8013e8                    // str q8, [sp, #64]
  // round 5
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 5
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d8017e8                    // str q8, [sp, #80]
  // round 6
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 6
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801be8                    // str q8, [sp, #96]
  // round 7
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // stage next-iteration Delta 7
  add x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  .long 0x3d801fe8                    // str q8, [sp, #112]
  // round 8
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 9
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 10
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b44                    // aese v4.16b, v26.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b46                    // aese v6.16b, v26.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b47                    // aese v7.16b, v26.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 11
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b64                    // aese v4.16b, v27.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b66                    // aese v6.16b, v27.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b67                    // aese v7.16b, v27.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 12
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b82                    // aese v2.16b, v28.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e284b83                    // aese v3.16b, v28.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e284b84                    // aese v4.16b, v28.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e284b85                    // aese v5.16b, v28.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b86                    // aese v6.16b, v28.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b87                    // aese v7.16b, v28.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  // round 13
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x4e284ba2                    // aese v2.16b, v29.16b
  .long 0x4e284ba3                    // aese v3.16b, v29.16b
  .long 0x4e284ba4                    // aese v4.16b, v29.16b
  .long 0x4e284ba5                    // aese v5.16b, v29.16b
  .long 0x4e284ba6                    // aese v6.16b, v29.16b
  .long 0x4e284ba7                    // aese v7.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e3e1c42                    // eor v2.16b, v2.16b, v30.16b
  .long 0x6e3e1c63                    // eor v3.16b, v3.16b, v30.16b
  .long 0x6e3e1c84                    // eor v4.16b, v4.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1cc6                    // eor v6.16b, v6.16b, v30.16b
  .long 0x6e3e1ce7                    // eor v7.16b, v7.16b, v30.16b
{$ENDIF}
  // post-whiten with this iteration's Deltas
  .long 0x3dc023ff                    // ldr q31, [sp, #128]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3dc027ff                    // ldr q31, [sp, #144]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3dc02bff                    // ldr q31, [sp, #160]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3dc02fff                    // ldr q31, [sp, #176]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3dc033ff                    // ldr q31, [sp, #192]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3dc037ff                    // ldr q31, [sp, #208]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3dc03bff                    // ldr q31, [sp, #224]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3dc03fff                    // ldr q31, [sp, #240]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  // fold recovered plaintext into the checksum
  .long 0x6e201d29                    // eor v9.16b, v9.16b, v0.16b
  .long 0x6e211d29                    // eor v9.16b, v9.16b, v1.16b
  .long 0x6e221d29                    // eor v9.16b, v9.16b, v2.16b
  .long 0x6e231d29                    // eor v9.16b, v9.16b, v3.16b
  .long 0x6e241d29                    // eor v9.16b, v9.16b, v4.16b
  .long 0x6e251d29                    // eor v9.16b, v9.16b, v5.16b
  .long 0x6e261d29                    // eor v9.16b, v9.16b, v6.16b
  .long 0x6e271d29                    // eor v9.16b, v9.16b, v7.16b
{$ENDIF}
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3d800c63                    // str q3, [x3, #48]
  .long 0x3d801064                    // str q4, [x3, #64]
  .long 0x3d801465                    // str q5, [x3, #80]
  .long 0x3d801866                    // str q6, [x3, #96]
  .long 0x3d801c67                    // str q7, [x3, #112]
  add x2, x2, #128
  add x3, x3, #128
  mov x8, x2
  sub x5, x5, #1
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_DECRYPT}
  cbnz x5, .Laesce_ocbdec256_loop
{$ELSE}
  cbnz x5, .Laesce_ocbenc256_loop
{$ENDIF}
  // undo the one-iteration ladder over-stage (XOR self-inverse)
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  .long 0xdac000c7                    // rbit x7, x6
  .long 0xdac010e7                    // clz x7, x7
  .long 0xd37cece7                    // lsl x7, x7, #4
  add x7, x4, x7
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x6e3f1d08                    // eor v8.16b, v8.16b, v31.16b
  sub x6, x6, #1
  // flush accumulators, unwind
  .long 0xf9400c07                    // ldr x7, [x0, #24]
  .long 0x3d8000e8                    // str q8, [x7]
  .long 0xf9401007                    // ldr x7, [x0, #32]
  .long 0x3d8000e9                    // str q9, [x7]
  .long 0x910403ff                    // add sp, sp, #256
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
