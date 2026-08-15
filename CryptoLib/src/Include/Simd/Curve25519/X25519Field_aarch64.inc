// Curve25519 field kernels (AArch64), radix-2^25.5, ten signed Int32 limbs.
// One selector-driven file; define exactly one of the following before the
// include (each pairs with its ClpSimdProc<n>Begin prologue):
//
//   CRYPTOLIB_CURVE25519_MUL      (Proc3: x0=PF, x1=PG, x2=PH)
//     PH := PF * PG
//   CRYPTOLIB_CURVE25519_SQR      (Proc2: x0=PX, x1=PZ)
//     PZ := PX^2
//   CRYPTOLIB_CURVE25519_ADD      (Proc3: x0=PX, x1=PY, x2=PZ)
//     PZ := PX + PY
//   CRYPTOLIB_CURVE25519_SUB      (Proc3: x0=PX, x1=PY, x2=PZ)
//     PZ := PX - PY
//   CRYPTOLIB_CURVE25519_APM      (Proc4: x0=PX, x1=PY, x2=PZp, x3=PZm)
//     PZp := PX+PY; PZm := PX-PY
//   CRYPTOLIB_CURVE25519_CSWAP    (Proc3: x0=ASwap, x1=PA, x2=PB)
//     constant-time swap of PA, PB
//   CRYPTOLIB_CURVE25519_CARRY    (Proc1: x0=PZ)
//     carry-propagate (reduce) PZ in place
//   CRYPTOLIB_CURVE25519_MULWORD  (Proc3: x0=PX, x1=AY, x2=PZ)
//     PZ := PX * AY (small scalar AY)
//
// Register-resident: Mul/Sqr keep the ten columns in x3..x12 (smull with a
// per-column x19 fold); Carry stays in registers. All results mod 2^255-19;
// signed limbs => smull only. Constant-time; x0..x17 only, no prolog spill.
{$IFDEF CRYPTOLIB_CURVE25519_MUL}
  ldr w13, [x0, #4]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x3, x15, #2
  ldr w13, [x0, #8]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x3, x3, x15, lsl #2
  ldr w13, [x0, #12]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x3, x3, x15, lsl #2
  ldr w13, [x0, #16]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x3, x3, x15, lsl #2
  ldr w13, [x0, #20]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x3, x3, x15, lsl #1
  ldr w13, [x0, #24]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x3, x3, x15, lsl #2
  ldr w13, [x0, #28]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x3, x3, x15, lsl #2
  ldr w13, [x0, #32]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x3, x3, x15, lsl #2
  ldr w13, [x0, #36]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x3, x3, x15, lsl #2
  lsl x16, x3, #4
  add x16, x16, x3, lsl #1
  add x3, x16, x3
  ldr w13, [x0, #0]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x3, x3, x15
  ldr w13, [x0, #8]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x4, x15, #2
  ldr w13, [x0, #12]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x4, x4, x15, lsl #1
  ldr w13, [x0, #16]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x4, x4, x15, lsl #2
  ldr w13, [x0, #20]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x4, x4, x15, lsl #1
  ldr w13, [x0, #24]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x4, x4, x15, lsl #1
  ldr w13, [x0, #28]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x4, x4, x15, lsl #2
  ldr w13, [x0, #32]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x4, x4, x15, lsl #1
  ldr w13, [x0, #36]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x4, x4, x15, lsl #2
  lsl x16, x4, #4
  add x16, x16, x4, lsl #1
  add x4, x16, x4
  ldr w13, [x0, #0]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x4, x4, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x4, x4, x15
  ldr w13, [x0, #12]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x5, x15, #1
  ldr w13, [x0, #16]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  ldr w13, [x0, #20]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  ldr w13, [x0, #24]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  ldr w13, [x0, #28]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  ldr w13, [x0, #32]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  ldr w13, [x0, #36]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  lsl x16, x5, #4
  add x16, x16, x5, lsl #1
  add x5, x16, x5
  ldr w13, [x0, #0]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x5, x5, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x5, x5, x15
  ldr w13, [x0, #8]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x5, x5, x15
  ldr w13, [x0, #16]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x6, x15, #2
  ldr w13, [x0, #20]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x6, x6, x15, lsl #1
  ldr w13, [x0, #24]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x6, x6, x15, lsl #2
  ldr w13, [x0, #28]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x6, x6, x15, lsl #2
  ldr w13, [x0, #32]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x6, x6, x15, lsl #1
  ldr w13, [x0, #36]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x6, x6, x15, lsl #2
  lsl x16, x6, #4
  add x16, x16, x6, lsl #1
  add x6, x16, x6
  ldr w13, [x0, #0]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x6, x6, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x6, x6, x15, lsl #1
  ldr w13, [x0, #8]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x6, x6, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x6, x6, x15
  ldr w13, [x0, #20]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x7, x15, #1
  ldr w13, [x0, #24]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x7, x7, x15, lsl #1
  ldr w13, [x0, #28]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x7, x7, x15, lsl #2
  ldr w13, [x0, #32]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x7, x7, x15, lsl #1
  ldr w13, [x0, #36]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x7, x7, x15, lsl #1
  lsl x16, x7, #4
  add x16, x16, x7, lsl #1
  add x7, x16, x7
  ldr w13, [x0, #0]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x7, x7, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x7, x7, x15
  ldr w13, [x0, #8]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x7, x7, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x7, x7, x15
  ldr w13, [x0, #16]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x7, x7, x15
  ldr w13, [x0, #24]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x8, x15, #2
  ldr w13, [x0, #28]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x8, x8, x15, lsl #2
  ldr w13, [x0, #32]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x8, x8, x15, lsl #2
  ldr w13, [x0, #36]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x8, x8, x15, lsl #2
  lsl x16, x8, #4
  add x16, x16, x8, lsl #1
  add x8, x16, x8
  ldr w13, [x0, #0]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x8, x8, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x8, x8, x15, lsl #1
  ldr w13, [x0, #8]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x8, x8, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x8, x8, x15, lsl #1
  ldr w13, [x0, #16]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x8, x8, x15, lsl #1
  ldr w13, [x0, #20]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x8, x8, x15
  ldr w13, [x0, #28]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x9, x15, #2
  ldr w13, [x0, #32]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x9, x9, x15, lsl #1
  ldr w13, [x0, #36]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x9, x9, x15, lsl #2
  lsl x16, x9, #4
  add x16, x16, x9, lsl #1
  add x9, x16, x9
  ldr w13, [x0, #0]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x9, x9, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x9, x9, x15
  ldr w13, [x0, #8]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x9, x9, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x9, x9, x15
  ldr w13, [x0, #16]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x9, x9, x15, lsl #1
  ldr w13, [x0, #20]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x9, x9, x15
  ldr w13, [x0, #24]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x9, x9, x15
  ldr w13, [x0, #32]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x10, x15, #1
  ldr w13, [x0, #36]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x10, x10, x15, lsl #1
  lsl x16, x10, #4
  add x16, x16, x10, lsl #1
  add x10, x16, x10
  ldr w13, [x0, #0]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #8]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #12]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #16]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #20]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #24]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #28]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x10, x10, x15
  ldr w13, [x0, #36]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  lsl x11, x15, #2
  lsl x16, x11, #4
  add x16, x16, x11, lsl #1
  add x11, x16, x11
  ldr w13, [x0, #0]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x11, x11, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #8]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x11, x11, x15
  ldr w13, [x0, #16]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #20]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x11, x11, x15
  ldr w13, [x0, #24]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #28]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #32]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x11, x11, x15
  ldr w13, [x0, #0]
  ldr w14, [x1, #36]
  smull x15, w13, w14
  mov x12, x15
  ldr w13, [x0, #4]
  ldr w14, [x1, #32]
  smull x15, w13, w14
  add x12, x12, x15
  ldr w13, [x0, #8]
  ldr w14, [x1, #28]
  smull x15, w13, w14
  add x12, x12, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x1, #24]
  smull x15, w13, w14
  add x12, x12, x15
  ldr w13, [x0, #16]
  ldr w14, [x1, #20]
  smull x15, w13, w14
  add x12, x12, x15
  ldr w13, [x0, #20]
  ldr w14, [x1, #16]
  smull x15, w13, w14
  add x12, x12, x15
  ldr w13, [x0, #24]
  ldr w14, [x1, #12]
  smull x15, w13, w14
  add x12, x12, x15
  ldr w13, [x0, #28]
  ldr w14, [x1, #8]
  smull x15, w13, w14
  add x12, x12, x15, lsl #1
  ldr w13, [x0, #32]
  ldr w14, [x1, #4]
  smull x15, w13, w14
  add x12, x12, x15
  ldr w13, [x0, #36]
  ldr w14, [x1, #0]
  smull x15, w13, w14
  add x12, x12, x15
  asr x16, x4, #26
  add x5, x5, x16
  and x4, x4, #0x3FFFFFF
  asr x16, x6, #26
  add x7, x7, x16
  and x6, x6, #0x3FFFFFF
  asr x16, x9, #26
  add x10, x10, x16
  and x9, x9, #0x3FFFFFF
  asr x16, x11, #26
  add x12, x12, x16
  and x11, x11, #0x3FFFFFF
  asr x16, x5, #25
  add x6, x6, x16
  and x5, x5, #0x1FFFFFF
  asr x16, x7, #25
  add x8, x8, x16
  and x7, x7, #0x1FFFFFF
  asr x16, x10, #25
  add x11, x11, x16
  and x10, x10, #0x1FFFFFF
  asr x16, x12, #25
  mov x17, #38
  madd x3, x16, x17, x3
  and x12, x12, #0x1FFFFFF
  asr x16, x3, #26
  add x4, x4, x16
  and x3, x3, #0x3FFFFFF
  asr x16, x8, #26
  add x9, x9, x16
  and x8, x8, #0x3FFFFFF
  asr x16, x4, #26
  add x5, x5, x16
  and x4, x4, #0x3FFFFFF
  asr x16, x6, #26
  add x7, x7, x16
  and x6, x6, #0x3FFFFFF
  asr x16, x9, #26
  add x10, x10, x16
  and x9, x9, #0x3FFFFFF
  asr x16, x11, #26
  add x12, x12, x16
  and x11, x11, #0x3FFFFFF
  str w3, [x2, #0]
  str w4, [x2, #4]
  str w5, [x2, #8]
  str w6, [x2, #12]
  str w7, [x2, #16]
  str w8, [x2, #20]
  str w9, [x2, #24]
  str w10, [x2, #28]
  str w11, [x2, #32]
  str w12, [x2, #36]
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_SQR}
  ldr w13, [x0, #4]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x3, x15, #3
  ldr w13, [x0, #8]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x3, x3, x15, lsl #3
  ldr w13, [x0, #12]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x3, x3, x15, lsl #3
  ldr w13, [x0, #16]
  ldr w14, [x0, #24]
  smull x15, w13, w14
  add x3, x3, x15, lsl #3
  ldr w13, [x0, #20]
  ldr w14, [x0, #20]
  smull x15, w13, w14
  add x3, x3, x15, lsl #1
  lsl x16, x3, #4
  add x16, x16, x3, lsl #1
  add x3, x16, x3
  ldr w13, [x0, #0]
  ldr w14, [x0, #0]
  smull x15, w13, w14
  add x3, x3, x15
  ldr w13, [x0, #8]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x4, x15, #3
  ldr w13, [x0, #12]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x4, x4, x15, lsl #2
  ldr w13, [x0, #16]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x4, x4, x15, lsl #3
  ldr w13, [x0, #20]
  ldr w14, [x0, #24]
  smull x15, w13, w14
  add x4, x4, x15, lsl #2
  lsl x16, x4, #4
  add x16, x16, x4, lsl #1
  add x4, x16, x4
  ldr w13, [x0, #0]
  ldr w14, [x0, #4]
  smull x15, w13, w14
  add x4, x4, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x5, x15, #2
  ldr w13, [x0, #16]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x5, x5, x15, lsl #2
  ldr w13, [x0, #20]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x5, x5, x15, lsl #2
  ldr w13, [x0, #24]
  ldr w14, [x0, #24]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  lsl x16, x5, #4
  add x16, x16, x5, lsl #1
  add x5, x16, x5
  ldr w13, [x0, #0]
  ldr w14, [x0, #8]
  smull x15, w13, w14
  add x5, x5, x15, lsl #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #4]
  smull x15, w13, w14
  add x5, x5, x15
  ldr w13, [x0, #16]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x6, x15, #3
  ldr w13, [x0, #20]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x6, x6, x15, lsl #2
  ldr w13, [x0, #24]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x6, x6, x15, lsl #3
  lsl x16, x6, #4
  add x16, x16, x6, lsl #1
  add x6, x16, x6
  ldr w13, [x0, #0]
  ldr w14, [x0, #12]
  smull x15, w13, w14
  add x6, x6, x15, lsl #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #8]
  smull x15, w13, w14
  add x6, x6, x15, lsl #2
  ldr w13, [x0, #20]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x7, x15, #2
  ldr w13, [x0, #24]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x7, x7, x15, lsl #2
  ldr w13, [x0, #28]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x7, x7, x15, lsl #2
  lsl x16, x7, #4
  add x16, x16, x7, lsl #1
  add x7, x16, x7
  ldr w13, [x0, #0]
  ldr w14, [x0, #16]
  smull x15, w13, w14
  add x7, x7, x15, lsl #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #12]
  smull x15, w13, w14
  add x7, x7, x15, lsl #1
  ldr w13, [x0, #8]
  ldr w14, [x0, #8]
  smull x15, w13, w14
  add x7, x7, x15, lsl #1
  ldr w13, [x0, #24]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x8, x15, #3
  ldr w13, [x0, #28]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x8, x8, x15, lsl #3
  lsl x16, x8, #4
  add x16, x16, x8, lsl #1
  add x8, x16, x8
  ldr w13, [x0, #0]
  ldr w14, [x0, #20]
  smull x15, w13, w14
  add x8, x8, x15, lsl #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #16]
  smull x15, w13, w14
  add x8, x8, x15, lsl #2
  ldr w13, [x0, #8]
  ldr w14, [x0, #12]
  smull x15, w13, w14
  add x8, x8, x15, lsl #2
  ldr w13, [x0, #28]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x9, x15, #3
  ldr w13, [x0, #32]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x9, x9, x15, lsl #1
  lsl x16, x9, #4
  add x16, x16, x9, lsl #1
  add x9, x16, x9
  ldr w13, [x0, #0]
  ldr w14, [x0, #24]
  smull x15, w13, w14
  add x9, x9, x15, lsl #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #20]
  smull x15, w13, w14
  add x9, x9, x15, lsl #1
  ldr w13, [x0, #8]
  ldr w14, [x0, #16]
  smull x15, w13, w14
  add x9, x9, x15, lsl #2
  ldr w13, [x0, #12]
  ldr w14, [x0, #12]
  smull x15, w13, w14
  add x9, x9, x15
  ldr w13, [x0, #32]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x10, x15, #2
  lsl x16, x10, #4
  add x16, x16, x10, lsl #1
  add x10, x16, x10
  ldr w13, [x0, #0]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x10, x10, x15, lsl #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #24]
  smull x15, w13, w14
  add x10, x10, x15, lsl #1
  ldr w13, [x0, #8]
  ldr w14, [x0, #20]
  smull x15, w13, w14
  add x10, x10, x15, lsl #1
  ldr w13, [x0, #12]
  ldr w14, [x0, #16]
  smull x15, w13, w14
  add x10, x10, x15, lsl #1
  ldr w13, [x0, #36]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x11, x15, #2
  lsl x16, x11, #4
  add x16, x16, x11, lsl #1
  add x11, x16, x11
  ldr w13, [x0, #0]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x11, x11, x15, lsl #2
  ldr w13, [x0, #8]
  ldr w14, [x0, #24]
  smull x15, w13, w14
  add x11, x11, x15, lsl #2
  ldr w13, [x0, #12]
  ldr w14, [x0, #20]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #16]
  ldr w14, [x0, #16]
  smull x15, w13, w14
  add x11, x11, x15, lsl #1
  ldr w13, [x0, #0]
  ldr w14, [x0, #36]
  smull x15, w13, w14
  lsl x12, x15, #1
  ldr w13, [x0, #4]
  ldr w14, [x0, #32]
  smull x15, w13, w14
  add x12, x12, x15, lsl #1
  ldr w13, [x0, #8]
  ldr w14, [x0, #28]
  smull x15, w13, w14
  add x12, x12, x15, lsl #2
  ldr w13, [x0, #12]
  ldr w14, [x0, #24]
  smull x15, w13, w14
  add x12, x12, x15, lsl #1
  ldr w13, [x0, #16]
  ldr w14, [x0, #20]
  smull x15, w13, w14
  add x12, x12, x15, lsl #1
  asr x16, x4, #26
  add x5, x5, x16
  and x4, x4, #0x3FFFFFF
  asr x16, x6, #26
  add x7, x7, x16
  and x6, x6, #0x3FFFFFF
  asr x16, x9, #26
  add x10, x10, x16
  and x9, x9, #0x3FFFFFF
  asr x16, x11, #26
  add x12, x12, x16
  and x11, x11, #0x3FFFFFF
  asr x16, x5, #25
  add x6, x6, x16
  and x5, x5, #0x1FFFFFF
  asr x16, x7, #25
  add x8, x8, x16
  and x7, x7, #0x1FFFFFF
  asr x16, x10, #25
  add x11, x11, x16
  and x10, x10, #0x1FFFFFF
  asr x16, x12, #25
  mov x17, #38
  madd x3, x16, x17, x3
  and x12, x12, #0x1FFFFFF
  asr x16, x3, #26
  add x4, x4, x16
  and x3, x3, #0x3FFFFFF
  asr x16, x8, #26
  add x9, x9, x16
  and x8, x8, #0x3FFFFFF
  asr x16, x4, #26
  add x5, x5, x16
  and x4, x4, #0x3FFFFFF
  asr x16, x6, #26
  add x7, x7, x16
  and x6, x6, #0x3FFFFFF
  asr x16, x9, #26
  add x10, x10, x16
  and x9, x9, #0x3FFFFFF
  asr x16, x11, #26
  add x12, x12, x16
  and x11, x11, #0x3FFFFFF
  str w3, [x1, #0]
  str w4, [x1, #4]
  str w5, [x1, #8]
  str w6, [x1, #12]
  str w7, [x1, #16]
  str w8, [x1, #20]
  str w9, [x1, #24]
  str w10, [x1, #28]
  str w11, [x1, #32]
  str w12, [x1, #36]
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_ADD}
  ldr w3, [x0, #0]
  ldr w4, [x1, #0]
  add w3, w3, w4
  str w3, [x2, #0]
  ldr w3, [x0, #4]
  ldr w4, [x1, #4]
  add w3, w3, w4
  str w3, [x2, #4]
  ldr w3, [x0, #8]
  ldr w4, [x1, #8]
  add w3, w3, w4
  str w3, [x2, #8]
  ldr w3, [x0, #12]
  ldr w4, [x1, #12]
  add w3, w3, w4
  str w3, [x2, #12]
  ldr w3, [x0, #16]
  ldr w4, [x1, #16]
  add w3, w3, w4
  str w3, [x2, #16]
  ldr w3, [x0, #20]
  ldr w4, [x1, #20]
  add w3, w3, w4
  str w3, [x2, #20]
  ldr w3, [x0, #24]
  ldr w4, [x1, #24]
  add w3, w3, w4
  str w3, [x2, #24]
  ldr w3, [x0, #28]
  ldr w4, [x1, #28]
  add w3, w3, w4
  str w3, [x2, #28]
  ldr w3, [x0, #32]
  ldr w4, [x1, #32]
  add w3, w3, w4
  str w3, [x2, #32]
  ldr w3, [x0, #36]
  ldr w4, [x1, #36]
  add w3, w3, w4
  str w3, [x2, #36]
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_SUB}
  ldr w3, [x0, #0]
  ldr w4, [x1, #0]
  sub w3, w3, w4
  str w3, [x2, #0]
  ldr w3, [x0, #4]
  ldr w4, [x1, #4]
  sub w3, w3, w4
  str w3, [x2, #4]
  ldr w3, [x0, #8]
  ldr w4, [x1, #8]
  sub w3, w3, w4
  str w3, [x2, #8]
  ldr w3, [x0, #12]
  ldr w4, [x1, #12]
  sub w3, w3, w4
  str w3, [x2, #12]
  ldr w3, [x0, #16]
  ldr w4, [x1, #16]
  sub w3, w3, w4
  str w3, [x2, #16]
  ldr w3, [x0, #20]
  ldr w4, [x1, #20]
  sub w3, w3, w4
  str w3, [x2, #20]
  ldr w3, [x0, #24]
  ldr w4, [x1, #24]
  sub w3, w3, w4
  str w3, [x2, #24]
  ldr w3, [x0, #28]
  ldr w4, [x1, #28]
  sub w3, w3, w4
  str w3, [x2, #28]
  ldr w3, [x0, #32]
  ldr w4, [x1, #32]
  sub w3, w3, w4
  str w3, [x2, #32]
  ldr w3, [x0, #36]
  ldr w4, [x1, #36]
  sub w3, w3, w4
  str w3, [x2, #36]
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_APM}
  ldr w4, [x0, #0]
  ldr w5, [x1, #0]
  add w6, w4, w5
  str w6, [x2, #0]
  sub w7, w4, w5
  str w7, [x3, #0]
  ldr w4, [x0, #4]
  ldr w5, [x1, #4]
  add w6, w4, w5
  str w6, [x2, #4]
  sub w7, w4, w5
  str w7, [x3, #4]
  ldr w4, [x0, #8]
  ldr w5, [x1, #8]
  add w6, w4, w5
  str w6, [x2, #8]
  sub w7, w4, w5
  str w7, [x3, #8]
  ldr w4, [x0, #12]
  ldr w5, [x1, #12]
  add w6, w4, w5
  str w6, [x2, #12]
  sub w7, w4, w5
  str w7, [x3, #12]
  ldr w4, [x0, #16]
  ldr w5, [x1, #16]
  add w6, w4, w5
  str w6, [x2, #16]
  sub w7, w4, w5
  str w7, [x3, #16]
  ldr w4, [x0, #20]
  ldr w5, [x1, #20]
  add w6, w4, w5
  str w6, [x2, #20]
  sub w7, w4, w5
  str w7, [x3, #20]
  ldr w4, [x0, #24]
  ldr w5, [x1, #24]
  add w6, w4, w5
  str w6, [x2, #24]
  sub w7, w4, w5
  str w7, [x3, #24]
  ldr w4, [x0, #28]
  ldr w5, [x1, #28]
  add w6, w4, w5
  str w6, [x2, #28]
  sub w7, w4, w5
  str w7, [x3, #28]
  ldr w4, [x0, #32]
  ldr w5, [x1, #32]
  add w6, w4, w5
  str w6, [x2, #32]
  sub w7, w4, w5
  str w7, [x3, #32]
  ldr w4, [x0, #36]
  ldr w5, [x1, #36]
  add w6, w4, w5
  str w6, [x2, #36]
  sub w7, w4, w5
  str w7, [x3, #36]
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_CSWAP}
  neg w0, w0
  ldr w4, [x1, #0]
  ldr w5, [x2, #0]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #0]
  str w5, [x2, #0]
  ldr w4, [x1, #4]
  ldr w5, [x2, #4]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #4]
  str w5, [x2, #4]
  ldr w4, [x1, #8]
  ldr w5, [x2, #8]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #8]
  str w5, [x2, #8]
  ldr w4, [x1, #12]
  ldr w5, [x2, #12]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #12]
  str w5, [x2, #12]
  ldr w4, [x1, #16]
  ldr w5, [x2, #16]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #16]
  str w5, [x2, #16]
  ldr w4, [x1, #20]
  ldr w5, [x2, #20]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #20]
  str w5, [x2, #20]
  ldr w4, [x1, #24]
  ldr w5, [x2, #24]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #24]
  str w5, [x2, #24]
  ldr w4, [x1, #28]
  ldr w5, [x2, #28]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #28]
  str w5, [x2, #28]
  ldr w4, [x1, #32]
  ldr w5, [x2, #32]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #32]
  str w5, [x2, #32]
  ldr w4, [x1, #36]
  ldr w5, [x2, #36]
  eor w6, w4, w5
  and w6, w6, w0
  eor w4, w4, w6
  eor w5, w5, w6
  str w4, [x1, #36]
  str w5, [x2, #36]
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_CARRY}
  ldr w1, [x0, #0]
  ldr w2, [x0, #4]
  ldr w3, [x0, #8]
  ldr w4, [x0, #12]
  ldr w5, [x0, #16]
  ldr w6, [x0, #20]
  ldr w7, [x0, #24]
  ldr w8, [x0, #28]
  ldr w9, [x0, #32]
  ldr w10, [x0, #36]
  asr w11, w2, #26
  add w3, w3, w11
  and w2, w2, #0x3FFFFFF
  asr w11, w4, #26
  add w5, w5, w11
  and w4, w4, #0x3FFFFFF
  asr w11, w7, #26
  add w8, w8, w11
  and w7, w7, #0x3FFFFFF
  asr w11, w9, #26
  add w10, w10, w11
  and w9, w9, #0x3FFFFFF
  asr w11, w3, #25
  add w4, w4, w11
  and w3, w3, #0x1FFFFFF
  asr w11, w5, #25
  add w6, w6, w11
  and w5, w5, #0x1FFFFFF
  asr w11, w8, #25
  add w9, w9, w11
  and w8, w8, #0x1FFFFFF
  asr w11, w10, #25
  mov w12, #38
  madd w1, w11, w12, w1
  and w10, w10, #0x1FFFFFF
  asr w11, w1, #26
  add w2, w2, w11
  and w1, w1, #0x3FFFFFF
  asr w11, w6, #26
  add w7, w7, w11
  and w6, w6, #0x3FFFFFF
  asr w11, w2, #26
  add w3, w3, w11
  and w2, w2, #0x3FFFFFF
  asr w11, w4, #26
  add w5, w5, w11
  and w4, w4, #0x3FFFFFF
  asr w11, w7, #26
  add w8, w8, w11
  and w7, w7, #0x3FFFFFF
  asr w11, w9, #26
  add w10, w10, w11
  and w9, w9, #0x3FFFFFF
  str w1, [x0, #0]
  str w2, [x0, #4]
  str w3, [x0, #8]
  str w4, [x0, #12]
  str w5, [x0, #16]
  str w6, [x0, #20]
  str w7, [x0, #24]
  str w8, [x0, #28]
  str w9, [x0, #32]
  str w10, [x0, #36]
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_MULWORD}
  ldr w12, [x0, #8]
  smull x3, w12, w1
  and w7, w3, #0x1FFFFFF
  asr x3, x3, #25
  ldr w12, [x0, #16]
  smull x4, w12, w1
  and w8, w4, #0x1FFFFFF
  asr x4, x4, #25
  ldr w12, [x0, #28]
  smull x5, w12, w1
  and w9, w5, #0x1FFFFFF
  asr x5, x5, #25
  ldr w12, [x0, #36]
  smull x6, w12, w1
  and w10, w6, #0x1FFFFFF
  asr x6, x6, #25
  mov w13, #38
  mul x6, x6, x13
  ldr w12, [x0, #0]
  smull x13, w12, w1
  add x6, x6, x13
  and w13, w6, #0x3FFFFFF
  str w13, [x2, #0]
  asr x6, x6, #26
  ldr w12, [x0, #20]
  smull x13, w12, w1
  add x4, x4, x13
  and w13, w4, #0x3FFFFFF
  str w13, [x2, #20]
  asr x4, x4, #26
  ldr w12, [x0, #4]
  smull x13, w12, w1
  add x6, x6, x13
  and w13, w6, #0x3FFFFFF
  str w13, [x2, #4]
  asr x6, x6, #26
  ldr w12, [x0, #12]
  smull x13, w12, w1
  add x3, x3, x13
  and w13, w3, #0x3FFFFFF
  str w13, [x2, #12]
  asr x3, x3, #26
  ldr w12, [x0, #24]
  smull x13, w12, w1
  add x4, x4, x13
  and w13, w4, #0x3FFFFFF
  str w13, [x2, #24]
  asr x4, x4, #26
  ldr w12, [x0, #32]
  smull x13, w12, w1
  add x5, x5, x13
  and w13, w5, #0x3FFFFFF
  str w13, [x2, #32]
  asr x5, x5, #26
  add w13, w7, w6
  str w13, [x2, #8]
  add w13, w8, w3
  str w13, [x2, #16]
  add w13, w9, w4
  str w13, [x2, #28]
  add w13, w10, w5
  str w13, [x2, #36]
{$ELSE}
{$FATAL Define one of CRYPTOLIB_CURVE25519_MUL/SQR/ADD/SUB/APM/CSWAP/CARRY/MULWORD}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
