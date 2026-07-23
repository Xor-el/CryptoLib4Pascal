// Fused AES CryptoExt CTR keystream + 8-way PMULL GHASH kernel (aarch64).
// -------------------------------------------------------------------
// The AES and carry-less-multiply instruction streams are interleaved so
// both execution pipes run in parallel, hiding GHASH latency inside the
// AES critical path.
//
// Loops over BatchCount pipelined batches. Each batch AES-encrypts eight
// counter blocks (generated in-register from Counter32 + PJ0Template) to
// produce a keystream, XORs it with PXorIn to produce POut, and concurrently
// GHASHes 8 ciphertext blocks into the running authentication state. AES inside
// GCM is always CTR keystream construction; GhashFromOutput selects the GHASH
// source: encrypt folds the PREVIOUS batch's output ciphertext (the pipeline
// lags by one batch, so the mode primes batch 0 and drains the last); decrypt
// folds THIS batch's input ciphertext, read before the XOR overwrites it (no
// lag, no prime/drain, and PXorIn/POut may alias for in-place decrypt).
//
// PHPow128 holds the kernel-owned H^8..H^1 table PRE-MULTIPLIED BY x in the
// reflected representation, so the batch product reduces with two
// carry-less multiplies by 0xC2000000_00000000 instead of a shift/XOR
// ladder. The running GHASH state stays reflected between batches and is
// only byte-reversed at kernel entry/exit (rev64 + half swap - the PMask
// field is accepted for context-layout parity but unused on AArch64).
//
// Variant selection (set EXACTLY ONE):
//   GCM_FUSED_AES_ROUNDS_10  -> AES-128 (schedule = 11 x 16 bytes).
//   GCM_FUSED_AES_ROUNDS_12  -> AES-192 (schedule = 13 x 16 bytes).
//   GCM_FUSED_AES_ROUNDS_14  -> AES-256 (schedule = 15 x 16 bytes).
//
// On entry (after ClpSimdProc1Begin_aarch64.inc): x0 = PCtx.
// Context layout (TGcmFusedCtx in ClpAesCryptoExtGcmKernel.pas; 8-byte
// fields, identical offsets to the x86_64 kernel):
//   [x0 +  0]  PXorIn    [x0 +  8]  POut       [x0 + 16]  PPrevCipher
//   [x0 + 24]  PRoundKeys (16-byte aligned)    [x0 + 32]  PHPow128
//   [x0 + 40]  PFS       [x0 + 48]  PMask (unused)        [x0 + 56]  Counter32
//   [x0 + 64]  PJ0Template                     [x0 + 72]  BatchCount
//   [x0 + 80]  GhashFromOutput (1 = encrypt)
//
// Counter blocks: block j = J0[0..11] || BE32(Counter32 + j + 1); only the
// advanced Counter32 is written back (mod 2^32; the mode owns the value).
//
// Register map:
//   v0..v7   : 8 AES keystream lanes    v16..v(16+N_R) : resident round keys
//   v31      : J0 staging base / keystream-XOR scratch (per batch)
//   v8       : Z0 accumulator / reflected running GHASH state (loop-carried)
//   v9/v10   : Z1 / Z2 accumulators     v11 : GHASH input block
//   v12      : H-power limb             v13 : halves-swap scratch / zero
//   v14      : product scratch          v15 : reduction constant
//   x1/x2 = in/out, x4 = GHASH source, x5 = batch count, w6 = counter32,
//   x7 = PJ0Template, x9 = GhashFromOutput, x10/x11 = batch-start in/out,
//   w12/w13 = counter staging, x14 = PHPow128, x15 = PFS; x0 = PCtx (kept).
// v8..v15 are clobbered, so the d8..d15 save/restore frame brackets the
// body (ClpSimdNonVolatileSave/Restore_aarch64.inc).
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400804                    // ldr x4, [x0, #16]
  .long 0xf9400c03                    // ldr x3, [x0, #24]
  .long 0xf940100e                    // ldr x14, [x0, #32]
  .long 0xf940140f                    // ldr x15, [x0, #40]
  .long 0xb9403806                    // ldr w6, [x0, #56]
  .long 0xf9402007                    // ldr x7, [x0, #64]
  .long 0xf9402405                    // ldr x5, [x0, #72]
  .long 0xf9402809                    // ldr x9, [x0, #80]
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0x3dc0287a                    // ldr q26, [x3, #160]
  .long 0xd2f8400c                    // movz x12, #0xc200, lsl #48
  .long 0x4f00e40f                    // movi v15.16b, #0
  .long 0x4e081d8f                    // ins v15.d[0], x12
  .long 0x3dc001e8                    // ldr q8, [x15]
  .long 0x4e200908                    // rev64 v8.16b, v8.16b
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
.Lgcmfused10_batch:
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x4ebf1fe0                    // orr v0.16b, v31.16b, v31.16b
  add w12, w6, #1
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da0                    // ins v0.s[3], w13
  .long 0x4ebf1fe1                    // orr v1.16b, v31.16b, v31.16b
  add w12, w6, #2
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da1                    // ins v1.s[3], w13
  .long 0x4ebf1fe2                    // orr v2.16b, v31.16b, v31.16b
  add w12, w6, #3
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da2                    // ins v2.s[3], w13
  .long 0x4ebf1fe3                    // orr v3.16b, v31.16b, v31.16b
  add w12, w6, #4
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da3                    // ins v3.s[3], w13
  .long 0x4ebf1fe4                    // orr v4.16b, v31.16b, v31.16b
  add w12, w6, #5
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da4                    // ins v4.s[3], w13
  .long 0x4ebf1fe5                    // orr v5.16b, v31.16b, v31.16b
  add w12, w6, #6
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da5                    // ins v5.s[3], w13
  .long 0x4ebf1fe6                    // orr v6.16b, v31.16b, v31.16b
  add w12, w6, #7
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da6                    // ins v6.s[3], w13
  .long 0x4ebf1fe7                    // orr v7.16b, v31.16b, v31.16b
  add w12, w6, #8
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da7                    // ins v7.s[3], w13
  add w6, w6, #8
  mov x10, x1
  mov x11, x2
  cmp x9, #0
  .long 0x9a8a1084                    // csel x4, x4, x10, ne
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x3dc0008b                    // ldr q11, [x4]
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e281d6b                    // eor v11.16b, v11.16b, v8.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x3dc001cc                    // ldr q12, [x14]
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x0eece168                    // pmull v8.1q, v11.1d, v12.1d
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4eece16a                    // pmull2 v10.1q, v11.2d, v12.2d
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x0eece1a9                    // pmull v9.1q, v13.1d, v12.1d
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4eece1ad                    // pmull2 v13.1q, v13.2d, v12.2d
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x6e2d1d29                    // eor v9.16b, v9.16b, v13.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x3dc0048b                    // ldr q11, [x4, #16]
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x3dc005cc                    // ldr q12, [x14, #16]
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x3dc0088b                    // ldr q11, [x4, #32]
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x3dc009cc                    // ldr q12, [x14, #32]
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x3dc00c8b                    // ldr q11, [x4, #48]
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x3dc00dcc                    // ldr q12, [x14, #48]
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x3dc0108b                    // ldr q11, [x4, #64]
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x3dc011cc                    // ldr q12, [x14, #64]
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x3dc0148b                    // ldr q11, [x4, #80]
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x3dc015cc                    // ldr q12, [x14, #80]
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x3dc0188b                    // ldr q11, [x4, #96]
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x3dc019cc                    // ldr q12, [x14, #96]
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x3dc01c8b                    // ldr q11, [x4, #112]
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x3dc01dcc                    // ldr q12, [x14, #112]
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
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
  .long 0x4f00e40d                    // movi v13.16b, #0
  .long 0x6e0941ae                    // ext v14.16b, v13.16b, v9.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x6e0d412e                    // ext v14.16b, v9.16b, v13.16b, #8
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x0eefe10e                    // pmull v14.1q, v8.1d, v15.1d
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x0eefe10e                    // pmull v14.1q, v8.1d, v15.1d
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x6e2a1d08                    // eor v8.16b, v8.16b, v10.16b
  .long 0x3dc0003f                    // ldr q31, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x3dc0043f                    // ldr q31, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x3dc0083f                    // ldr q31, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x3dc00c3f                    // ldr q31, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x3dc0103f                    // ldr q31, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x3dc0143f                    // ldr q31, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x3dc0183f                    // ldr q31, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x3dc01c3f                    // ldr q31, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  add x1, x1, #128
  add x2, x2, #128
  cmp x9, #0
  .long 0x9a8a1164                    // csel x4, x11, x10, ne
  sub x5, x5, #1
  cbnz x5, .Lgcmfused10_batch
  .long 0x4e200908                    // rev64 v8.16b, v8.16b
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x3d8001e8                    // str q8, [x15]
  .long 0xb9003806                    // str w6, [x0, #56]
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
{$ELSE}
  {$IFDEF GCM_FUSED_AES_ROUNDS_12}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400804                    // ldr x4, [x0, #16]
  .long 0xf9400c03                    // ldr x3, [x0, #24]
  .long 0xf940100e                    // ldr x14, [x0, #32]
  .long 0xf940140f                    // ldr x15, [x0, #40]
  .long 0xb9403806                    // ldr w6, [x0, #56]
  .long 0xf9402007                    // ldr x7, [x0, #64]
  .long 0xf9402405                    // ldr x5, [x0, #72]
  .long 0xf9402809                    // ldr x9, [x0, #80]
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0x3dc0307c                    // ldr q28, [x3, #192]
  .long 0xd2f8400c                    // movz x12, #0xc200, lsl #48
  .long 0x4f00e40f                    // movi v15.16b, #0
  .long 0x4e081d8f                    // ins v15.d[0], x12
  .long 0x3dc001e8                    // ldr q8, [x15]
  .long 0x4e200908                    // rev64 v8.16b, v8.16b
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
.Lgcmfused12_batch:
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x4ebf1fe0                    // orr v0.16b, v31.16b, v31.16b
  add w12, w6, #1
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da0                    // ins v0.s[3], w13
  .long 0x4ebf1fe1                    // orr v1.16b, v31.16b, v31.16b
  add w12, w6, #2
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da1                    // ins v1.s[3], w13
  .long 0x4ebf1fe2                    // orr v2.16b, v31.16b, v31.16b
  add w12, w6, #3
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da2                    // ins v2.s[3], w13
  .long 0x4ebf1fe3                    // orr v3.16b, v31.16b, v31.16b
  add w12, w6, #4
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da3                    // ins v3.s[3], w13
  .long 0x4ebf1fe4                    // orr v4.16b, v31.16b, v31.16b
  add w12, w6, #5
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da4                    // ins v4.s[3], w13
  .long 0x4ebf1fe5                    // orr v5.16b, v31.16b, v31.16b
  add w12, w6, #6
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da5                    // ins v5.s[3], w13
  .long 0x4ebf1fe6                    // orr v6.16b, v31.16b, v31.16b
  add w12, w6, #7
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da6                    // ins v6.s[3], w13
  .long 0x4ebf1fe7                    // orr v7.16b, v31.16b, v31.16b
  add w12, w6, #8
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da7                    // ins v7.s[3], w13
  add w6, w6, #8
  mov x10, x1
  mov x11, x2
  cmp x9, #0
  .long 0x9a8a1084                    // csel x4, x4, x10, ne
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x3dc0008b                    // ldr q11, [x4]
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e281d6b                    // eor v11.16b, v11.16b, v8.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x3dc001cc                    // ldr q12, [x14]
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x0eece168                    // pmull v8.1q, v11.1d, v12.1d
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4eece16a                    // pmull2 v10.1q, v11.2d, v12.2d
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x0eece1a9                    // pmull v9.1q, v13.1d, v12.1d
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4eece1ad                    // pmull2 v13.1q, v13.2d, v12.2d
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x6e2d1d29                    // eor v9.16b, v9.16b, v13.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x3dc0048b                    // ldr q11, [x4, #16]
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x3dc005cc                    // ldr q12, [x14, #16]
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x3dc0088b                    // ldr q11, [x4, #32]
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x3dc009cc                    // ldr q12, [x14, #32]
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x3dc00c8b                    // ldr q11, [x4, #48]
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x3dc00dcc                    // ldr q12, [x14, #48]
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x3dc0108b                    // ldr q11, [x4, #64]
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x3dc011cc                    // ldr q12, [x14, #64]
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x3dc0148b                    // ldr q11, [x4, #80]
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x3dc015cc                    // ldr q12, [x14, #80]
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x3dc0188b                    // ldr q11, [x4, #96]
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x3dc019cc                    // ldr q12, [x14, #96]
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x3dc01c8b                    // ldr q11, [x4, #112]
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x3dc01dcc                    // ldr q12, [x14, #112]
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
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
  .long 0x4f00e40d                    // movi v13.16b, #0
  .long 0x6e0941ae                    // ext v14.16b, v13.16b, v9.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x6e0d412e                    // ext v14.16b, v9.16b, v13.16b, #8
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x0eefe10e                    // pmull v14.1q, v8.1d, v15.1d
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x0eefe10e                    // pmull v14.1q, v8.1d, v15.1d
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x6e2a1d08                    // eor v8.16b, v8.16b, v10.16b
  .long 0x3dc0003f                    // ldr q31, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x3dc0043f                    // ldr q31, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x3dc0083f                    // ldr q31, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x3dc00c3f                    // ldr q31, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x3dc0103f                    // ldr q31, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x3dc0143f                    // ldr q31, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x3dc0183f                    // ldr q31, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x3dc01c3f                    // ldr q31, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  add x1, x1, #128
  add x2, x2, #128
  cmp x9, #0
  .long 0x9a8a1164                    // csel x4, x11, x10, ne
  sub x5, x5, #1
  cbnz x5, .Lgcmfused12_batch
  .long 0x4e200908                    // rev64 v8.16b, v8.16b
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x3d8001e8                    // str q8, [x15]
  .long 0xb9003806                    // str w6, [x0, #56]
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
  {$ELSE}
    {$IFDEF GCM_FUSED_AES_ROUNDS_14}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400804                    // ldr x4, [x0, #16]
  .long 0xf9400c03                    // ldr x3, [x0, #24]
  .long 0xf940100e                    // ldr x14, [x0, #32]
  .long 0xf940140f                    // ldr x15, [x0, #40]
  .long 0xb9403806                    // ldr w6, [x0, #56]
  .long 0xf9402007                    // ldr x7, [x0, #64]
  .long 0xf9402405                    // ldr x5, [x0, #72]
  .long 0xf9402809                    // ldr x9, [x0, #80]
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0xad46747c                    // ldp q28, q29, [x3, #192]
  .long 0x3dc0387e                    // ldr q30, [x3, #224]
  .long 0xd2f8400c                    // movz x12, #0xc200, lsl #48
  .long 0x4f00e40f                    // movi v15.16b, #0
  .long 0x4e081d8f                    // ins v15.d[0], x12
  .long 0x3dc001e8                    // ldr q8, [x15]
  .long 0x4e200908                    // rev64 v8.16b, v8.16b
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
.Lgcmfused14_batch:
  .long 0x3dc000ff                    // ldr q31, [x7]
  .long 0x4ebf1fe0                    // orr v0.16b, v31.16b, v31.16b
  add w12, w6, #1
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da0                    // ins v0.s[3], w13
  .long 0x4ebf1fe1                    // orr v1.16b, v31.16b, v31.16b
  add w12, w6, #2
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da1                    // ins v1.s[3], w13
  .long 0x4ebf1fe2                    // orr v2.16b, v31.16b, v31.16b
  add w12, w6, #3
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da2                    // ins v2.s[3], w13
  .long 0x4ebf1fe3                    // orr v3.16b, v31.16b, v31.16b
  add w12, w6, #4
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da3                    // ins v3.s[3], w13
  .long 0x4ebf1fe4                    // orr v4.16b, v31.16b, v31.16b
  add w12, w6, #5
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da4                    // ins v4.s[3], w13
  .long 0x4ebf1fe5                    // orr v5.16b, v31.16b, v31.16b
  add w12, w6, #6
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da5                    // ins v5.s[3], w13
  .long 0x4ebf1fe6                    // orr v6.16b, v31.16b, v31.16b
  add w12, w6, #7
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da6                    // ins v6.s[3], w13
  .long 0x4ebf1fe7                    // orr v7.16b, v31.16b, v31.16b
  add w12, w6, #8
  .long 0x5ac0098d                    // rev w13, w12
  .long 0x4e1c1da7                    // ins v7.s[3], w13
  add w6, w6, #8
  mov x10, x1
  mov x11, x2
  cmp x9, #0
  .long 0x9a8a1084                    // csel x4, x4, x10, ne
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x3dc0008b                    // ldr q11, [x4]
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a02                    // aese v2.16b, v16.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a03                    // aese v3.16b, v16.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e281d6b                    // eor v11.16b, v11.16b, v8.16b
  .long 0x4e284a04                    // aese v4.16b, v16.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x3dc001cc                    // ldr q12, [x14]
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a06                    // aese v6.16b, v16.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x0eece168                    // pmull v8.1q, v11.1d, v12.1d
  .long 0x4e284a07                    // aese v7.16b, v16.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4eece16a                    // pmull2 v10.1q, v11.2d, v12.2d
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x0eece1a9                    // pmull v9.1q, v13.1d, v12.1d
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4eece1ad                    // pmull2 v13.1q, v13.2d, v12.2d
  .long 0x4e284a22                    // aese v2.16b, v17.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2d1d29                    // eor v9.16b, v9.16b, v13.16b
  .long 0x4e284a23                    // aese v3.16b, v17.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x3dc0048b                    // ldr q11, [x4, #16]
  .long 0x4e284a24                    // aese v4.16b, v17.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a26                    // aese v6.16b, v17.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x3dc005cc                    // ldr q12, [x14, #16]
  .long 0x4e284a27                    // aese v7.16b, v17.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a42                    // aese v2.16b, v18.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284a43                    // aese v3.16b, v18.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a44                    // aese v4.16b, v18.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a46                    // aese v6.16b, v18.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284a47                    // aese v7.16b, v18.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x3dc0088b                    // ldr q11, [x4, #32]
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a62                    // aese v2.16b, v19.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284a63                    // aese v3.16b, v19.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x3dc009cc                    // ldr q12, [x14, #32]
  .long 0x4e284a64                    // aese v4.16b, v19.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284a66                    // aese v6.16b, v19.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284a67                    // aese v7.16b, v19.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284a82                    // aese v2.16b, v20.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a83                    // aese v3.16b, v20.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284a84                    // aese v4.16b, v20.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x3dc00c8b                    // ldr q11, [x4, #48]
  .long 0x4e284a86                    // aese v6.16b, v20.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284a87                    // aese v7.16b, v20.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x3dc00dcc                    // ldr q12, [x14, #48]
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284aa2                    // aese v2.16b, v21.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284aa3                    // aese v3.16b, v21.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284aa4                    // aese v4.16b, v21.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284aa6                    // aese v6.16b, v21.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284aa7                    // aese v7.16b, v21.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284ac2                    // aese v2.16b, v22.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x3dc0108b                    // ldr q11, [x4, #64]
  .long 0x4e284ac3                    // aese v3.16b, v22.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284ac4                    // aese v4.16b, v22.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x3dc011cc                    // ldr q12, [x14, #64]
  .long 0x4e284ac6                    // aese v6.16b, v22.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284ac7                    // aese v7.16b, v22.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284ae2                    // aese v2.16b, v23.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284ae3                    // aese v3.16b, v23.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284ae4                    // aese v4.16b, v23.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284ae6                    // aese v6.16b, v23.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284ae7                    // aese v7.16b, v23.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x3dc0148b                    // ldr q11, [x4, #80]
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284b02                    // aese v2.16b, v24.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x3dc015cc                    // ldr q12, [x14, #80]
  .long 0x4e284b03                    // aese v3.16b, v24.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284b04                    // aese v4.16b, v24.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284b06                    // aese v6.16b, v24.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284b07                    // aese v7.16b, v24.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284b22                    // aese v2.16b, v25.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284b23                    // aese v3.16b, v25.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284b24                    // aese v4.16b, v25.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x3dc0188b                    // ldr q11, [x4, #96]
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284b26                    // aese v6.16b, v25.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284b27                    // aese v7.16b, v25.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x3dc019cc                    // ldr q12, [x14, #96]
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284b42                    // aese v2.16b, v26.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284b43                    // aese v3.16b, v26.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284b44                    // aese v4.16b, v26.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284b46                    // aese v6.16b, v26.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284b47                    // aese v7.16b, v26.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x3dc01c8b                    // ldr q11, [x4, #112]
  .long 0x4e284b62                    // aese v2.16b, v27.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x4e20096b                    // rev64 v11.16b, v11.16b
  .long 0x4e284b63                    // aese v3.16b, v27.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e0b416b                    // ext v11.16b, v11.16b, v11.16b, #8
  .long 0x4e284b64                    // aese v4.16b, v27.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x3dc01dcc                    // ldr q12, [x14, #112]
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e0b416d                    // ext v13.16b, v11.16b, v11.16b, #8
  .long 0x4e284b66                    // aese v6.16b, v27.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x0eece16e                    // pmull v14.1q, v11.1d, v12.1d
  .long 0x4e284b67                    // aese v7.16b, v27.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4eece16e                    // pmull2 v14.1q, v11.2d, v12.2d
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x4e284b82                    // aese v2.16b, v28.16b
  .long 0x4e286842                    // aesmc v2.16b, v2.16b
  .long 0x0eece1ae                    // pmull v14.1q, v13.1d, v12.1d
  .long 0x4e284b83                    // aese v3.16b, v28.16b
  .long 0x4e286863                    // aesmc v3.16b, v3.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284b84                    // aese v4.16b, v28.16b
  .long 0x4e286884                    // aesmc v4.16b, v4.16b
  .long 0x4eece1ae                    // pmull2 v14.1q, v13.2d, v12.2d
  .long 0x4e284b85                    // aese v5.16b, v28.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x6e2e1d29                    // eor v9.16b, v9.16b, v14.16b
  .long 0x4e284b86                    // aese v6.16b, v28.16b
  .long 0x4e2868c6                    // aesmc v6.16b, v6.16b
  .long 0x4e284b87                    // aese v7.16b, v28.16b
  .long 0x4e2868e7                    // aesmc v7.16b, v7.16b
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
  .long 0x4f00e40d                    // movi v13.16b, #0
  .long 0x6e0941ae                    // ext v14.16b, v13.16b, v9.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x6e0d412e                    // ext v14.16b, v9.16b, v13.16b, #8
  .long 0x6e2e1d4a                    // eor v10.16b, v10.16b, v14.16b
  .long 0x0eefe10e                    // pmull v14.1q, v8.1d, v15.1d
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x0eefe10e                    // pmull v14.1q, v8.1d, v15.1d
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x6e2e1d08                    // eor v8.16b, v8.16b, v14.16b
  .long 0x6e2a1d08                    // eor v8.16b, v8.16b, v10.16b
  .long 0x3dc0003f                    // ldr q31, [x1]
  .long 0x6e3f1c00                    // eor v0.16b, v0.16b, v31.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x3dc0043f                    // ldr q31, [x1, #16]
  .long 0x6e3f1c21                    // eor v1.16b, v1.16b, v31.16b
  .long 0x3d800441                    // str q1, [x2, #16]
  .long 0x3dc0083f                    // ldr q31, [x1, #32]
  .long 0x6e3f1c42                    // eor v2.16b, v2.16b, v31.16b
  .long 0x3d800842                    // str q2, [x2, #32]
  .long 0x3dc00c3f                    // ldr q31, [x1, #48]
  .long 0x6e3f1c63                    // eor v3.16b, v3.16b, v31.16b
  .long 0x3d800c43                    // str q3, [x2, #48]
  .long 0x3dc0103f                    // ldr q31, [x1, #64]
  .long 0x6e3f1c84                    // eor v4.16b, v4.16b, v31.16b
  .long 0x3d801044                    // str q4, [x2, #64]
  .long 0x3dc0143f                    // ldr q31, [x1, #80]
  .long 0x6e3f1ca5                    // eor v5.16b, v5.16b, v31.16b
  .long 0x3d801445                    // str q5, [x2, #80]
  .long 0x3dc0183f                    // ldr q31, [x1, #96]
  .long 0x6e3f1cc6                    // eor v6.16b, v6.16b, v31.16b
  .long 0x3d801846                    // str q6, [x2, #96]
  .long 0x3dc01c3f                    // ldr q31, [x1, #112]
  .long 0x6e3f1ce7                    // eor v7.16b, v7.16b, v31.16b
  .long 0x3d801c47                    // str q7, [x2, #112]
  add x1, x1, #128
  add x2, x2, #128
  cmp x9, #0
  .long 0x9a8a1164                    // csel x4, x11, x10, ne
  sub x5, x5, #1
  cbnz x5, .Lgcmfused14_batch
  .long 0x4e200908                    // rev64 v8.16b, v8.16b
  .long 0x6e084108                    // ext v8.16b, v8.16b, v8.16b, #8
  .long 0x3d8001e8                    // str q8, [x15]
  .long 0xb9003806                    // str w6, [x0, #56]
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
    {$ELSE}
    {$FATAL Exactly one of GCM_FUSED_AES_ROUNDS_10, GCM_FUSED_AES_ROUNDS_12, GCM_FUSED_AES_ROUNDS_14 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
