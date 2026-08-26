// Fused P-256 RCB complete-group-law point kernels (secp256r1, a=-3, AArch64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined
// before including this file:
//
//   CRYPTOLIB_FP_P256_POINTDOUBLE   (ClpSimdProc3Begin: x0 = PR, x1 = PA, x2 = PCtx)
//     - straight-line RCB2016 a=-3 doubling PR := 2*PA (Algorithm 6) over a
//       homogeneous point.
//   CRYPTOLIB_FP_P256_POINTADD   (ClpSimdProc4Begin: x0 = PR, x1 = PA, x2 = PQ, x3 = PCtx)
//     - straight-line RCB2016 a=-3 complete addition PR := PA + PQ
//       (Algorithm 4) of two homogeneous points.
//   CRYPTOLIB_FP_P256_POINTADDMIXED   (ClpSimdProc4Begin: x0 = PR, x1 = PA, x2 = PQ, x3 = PCtx)
//     - the same complete addition with PQ an AFFINE point (TFeAffine X,Y);
//       the unit Z2 is taken from PCtx.MontOne (R mod p) at +160.
//
// Shared across all three: PR/PA/PQ are TFePoint (or TFeAffine) bases with
// coords at SizeOf(TFe) strides (X,Y,Z at +0/+72/+144); PCtx = [n0', N,
// p0..p3] with the curve's Fb (b*R mod p) at +304. Every intermediate lives
// in a fixed stack frame and both inputs are copied in up front, so a call
// with PR aliasing an input (incl. add(P,P)) is safe. The field multiply is
// the folded special-prime mul_mont_p256 body (mul/umulh product + shift/add
// reduce), reused verbatim and inlined under a single prologue/epilogue per
// proc. Base ARMv8-A integer instructions are emitted as mnemonics.
//
// Constant-time: straight-line and data-independent (no branch or memory
// address depends on the point); PCtx is pinned in x3 and every intermediate
// lives in a self-managed stack frame using only caller-saved registers
// (x0..x16), so no callee-saved (x19..x28) preservation is needed; each proc
// frees its frame in the epilogue. Backend-gated on AArch64 (active SIMD
// level); any other target uses the generic per-op RCB formula, bit-for-bit.
{$IFDEF CRYPTOLIB_FP_P256_POINTDOUBLE}
  mov x3, x2            // x3 = PCtx (pinned; cores read [x3 + ..])
  sub sp, sp, #336
  str x0, [sp, #320]     // save output-point pointer
  // load input point X,Y,Z into frame
  ldr x16, [x1, #0]
  str x16, [sp, #0]
  ldr x16, [x1, #8]
  str x16, [sp, #8]
  ldr x16, [x1, #16]
  str x16, [sp, #16]
  ldr x16, [x1, #24]
  str x16, [sp, #24]
  ldr x16, [x1, #72]
  str x16, [sp, #32]
  ldr x16, [x1, #80]
  str x16, [sp, #40]
  ldr x16, [x1, #88]
  str x16, [sp, #48]
  ldr x16, [x1, #96]
  str x16, [sp, #56]
  ldr x16, [x1, #144]
  str x16, [sp, #64]
  ldr x16, [x1, #152]
  str x16, [sp, #72]
  ldr x16, [x1, #160]
  str x16, [sp, #80]
  ldr x16, [x1, #168]
  str x16, [sp, #88]
  // sqr t0 = X
  add x0, sp, #96
  add x1, sp, #0
  add x2, sp, #0
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // sqr t1 = Y
  add x0, sp, #128
  add x1, sp, #32
  add x2, sp, #32
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // sqr t2 = Z
  add x0, sp, #160
  add x1, sp, #64
  add x2, sp, #64
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t3 = X * Y
  add x0, sp, #192
  add x1, sp, #0
  add x2, sp, #32
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t3 = t3 + t3
  ldr x4, [sp, #192]
  ldr x9, [sp, #192]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #200]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #208]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #216]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #192]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #200]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #208]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #216]
  // mul Z3 = X * Z
  add x0, sp, #288
  add x1, sp, #0
  add x2, sp, #64
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Z3 = Z3 + Z3
  ldr x4, [sp, #288]
  ldr x9, [sp, #288]
  adds x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #296]
  adcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #304]
  adcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #312]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #288]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #296]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #304]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #312]
  // mulb Y3 = t2 * b
  add x0, sp, #256
  add x1, sp, #160
  add x2, x3, #304
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModSub Y3 = Y3 - Z3
  ldr x4, [sp, #256]
  ldr x9, [sp, #288]
  subs x4, x4, x9
  ldr x5, [sp, #264]
  ldr x9, [sp, #296]
  sbcs x5, x5, x9
  ldr x6, [sp, #272]
  ldr x9, [sp, #304]
  sbcs x6, x6, x9
  ldr x7, [sp, #280]
  ldr x9, [sp, #312]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #256]
  str x5, [sp, #264]
  str x6, [sp, #272]
  str x7, [sp, #280]
  // ModAdd X3 = Y3 + Y3
  ldr x4, [sp, #256]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #264]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #272]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #280]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #224]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #232]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #240]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #248]
  // ModAdd Y3 = X3 + Y3
  ldr x4, [sp, #224]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #256]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #264]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #272]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #280]
  // ModSub X3 = t1 - Y3
  ldr x4, [sp, #128]
  ldr x9, [sp, #256]
  subs x4, x4, x9
  ldr x5, [sp, #136]
  ldr x9, [sp, #264]
  sbcs x5, x5, x9
  ldr x6, [sp, #144]
  ldr x9, [sp, #272]
  sbcs x6, x6, x9
  ldr x7, [sp, #152]
  ldr x9, [sp, #280]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #224]
  str x5, [sp, #232]
  str x6, [sp, #240]
  str x7, [sp, #248]
  // ModAdd Y3 = t1 + Y3
  ldr x4, [sp, #128]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #136]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #144]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #152]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #256]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #264]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #272]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #280]
  // mul Y3 = X3 * Y3
  add x0, sp, #256
  add x1, sp, #224
  add x2, sp, #256
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul X3 = X3 * t3
  add x0, sp, #224
  add x1, sp, #224
  add x2, sp, #192
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t3 = t2 + t2
  ldr x4, [sp, #160]
  ldr x9, [sp, #160]
  adds x4, x4, x9
  ldr x5, [sp, #168]
  ldr x9, [sp, #168]
  adcs x5, x5, x9
  ldr x6, [sp, #176]
  ldr x9, [sp, #176]
  adcs x6, x6, x9
  ldr x7, [sp, #184]
  ldr x9, [sp, #184]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #192]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #200]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #208]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #216]
  // ModAdd t2 = t2 + t3
  ldr x4, [sp, #160]
  ldr x9, [sp, #192]
  adds x4, x4, x9
  ldr x5, [sp, #168]
  ldr x9, [sp, #200]
  adcs x5, x5, x9
  ldr x6, [sp, #176]
  ldr x9, [sp, #208]
  adcs x6, x6, x9
  ldr x7, [sp, #184]
  ldr x9, [sp, #216]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #160]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #168]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #176]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #184]
  // mulb Z3 = Z3 * b
  add x0, sp, #288
  add x1, sp, #288
  add x2, x3, #304
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModSub Z3 = Z3 - t2
  ldr x4, [sp, #288]
  ldr x9, [sp, #160]
  subs x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #168]
  sbcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #176]
  sbcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #184]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #288]
  str x5, [sp, #296]
  str x6, [sp, #304]
  str x7, [sp, #312]
  // ModSub Z3 = Z3 - t0
  ldr x4, [sp, #288]
  ldr x9, [sp, #96]
  subs x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #104]
  sbcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #112]
  sbcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #120]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #288]
  str x5, [sp, #296]
  str x6, [sp, #304]
  str x7, [sp, #312]
  // ModAdd t3 = Z3 + Z3
  ldr x4, [sp, #288]
  ldr x9, [sp, #288]
  adds x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #296]
  adcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #304]
  adcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #312]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #192]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #200]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #208]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #216]
  // ModAdd Z3 = Z3 + t3
  ldr x4, [sp, #288]
  ldr x9, [sp, #192]
  adds x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #200]
  adcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #208]
  adcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #216]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #288]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #296]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #304]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #312]
  // ModAdd t3 = t0 + t0
  ldr x4, [sp, #96]
  ldr x9, [sp, #96]
  adds x4, x4, x9
  ldr x5, [sp, #104]
  ldr x9, [sp, #104]
  adcs x5, x5, x9
  ldr x6, [sp, #112]
  ldr x9, [sp, #112]
  adcs x6, x6, x9
  ldr x7, [sp, #120]
  ldr x9, [sp, #120]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #192]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #200]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #208]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #216]
  // ModAdd t0 = t3 + t0
  ldr x4, [sp, #192]
  ldr x9, [sp, #96]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #104]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #112]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #120]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #96]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #104]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #112]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #120]
  // ModSub t0 = t0 - t2
  ldr x4, [sp, #96]
  ldr x9, [sp, #160]
  subs x4, x4, x9
  ldr x5, [sp, #104]
  ldr x9, [sp, #168]
  sbcs x5, x5, x9
  ldr x6, [sp, #112]
  ldr x9, [sp, #176]
  sbcs x6, x6, x9
  ldr x7, [sp, #120]
  ldr x9, [sp, #184]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #96]
  str x5, [sp, #104]
  str x6, [sp, #112]
  str x7, [sp, #120]
  // mul t0 = t0 * Z3
  add x0, sp, #96
  add x1, sp, #96
  add x2, sp, #288
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Y3 = Y3 + t0
  ldr x4, [sp, #256]
  ldr x9, [sp, #96]
  adds x4, x4, x9
  ldr x5, [sp, #264]
  ldr x9, [sp, #104]
  adcs x5, x5, x9
  ldr x6, [sp, #272]
  ldr x9, [sp, #112]
  adcs x6, x6, x9
  ldr x7, [sp, #280]
  ldr x9, [sp, #120]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #256]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #264]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #272]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #280]
  // mul t0 = Y * Z
  add x0, sp, #96
  add x1, sp, #32
  add x2, sp, #64
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t0 = t0 + t0
  ldr x4, [sp, #96]
  ldr x9, [sp, #96]
  adds x4, x4, x9
  ldr x5, [sp, #104]
  ldr x9, [sp, #104]
  adcs x5, x5, x9
  ldr x6, [sp, #112]
  ldr x9, [sp, #112]
  adcs x6, x6, x9
  ldr x7, [sp, #120]
  ldr x9, [sp, #120]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #96]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #104]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #112]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #120]
  // mul Z3 = t0 * Z3
  add x0, sp, #288
  add x1, sp, #96
  add x2, sp, #288
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModSub X3 = X3 - Z3
  ldr x4, [sp, #224]
  ldr x9, [sp, #288]
  subs x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #296]
  sbcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #304]
  sbcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #312]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #224]
  str x5, [sp, #232]
  str x6, [sp, #240]
  str x7, [sp, #248]
  // mul Z3 = t0 * t1
  add x0, sp, #288
  add x1, sp, #96
  add x2, sp, #128
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Z3 = Z3 + Z3
  ldr x4, [sp, #288]
  ldr x9, [sp, #288]
  adds x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #296]
  adcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #304]
  adcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #312]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #288]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #296]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #304]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #312]
  // ModAdd Z3 = Z3 + Z3
  ldr x4, [sp, #288]
  ldr x9, [sp, #288]
  adds x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #296]
  adcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #304]
  adcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #312]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #288]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #296]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #304]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #312]
  // store result point X3,Y3,Z3
  ldr x0, [sp, #320]
  ldr x16, [sp, #224]
  str x16, [x0, #0]
  ldr x16, [sp, #232]
  str x16, [x0, #8]
  ldr x16, [sp, #240]
  str x16, [x0, #16]
  ldr x16, [sp, #248]
  str x16, [x0, #24]
  ldr x16, [sp, #256]
  str x16, [x0, #72]
  ldr x16, [sp, #264]
  str x16, [x0, #80]
  ldr x16, [sp, #272]
  str x16, [x0, #88]
  ldr x16, [sp, #280]
  str x16, [x0, #96]
  ldr x16, [sp, #288]
  str x16, [x0, #144]
  ldr x16, [sp, #296]
  str x16, [x0, #152]
  ldr x16, [sp, #304]
  str x16, [x0, #160]
  ldr x16, [sp, #312]
  str x16, [x0, #168]
  add sp, sp, #336
{$ELSE}
  {$IFDEF CRYPTOLIB_FP_P256_POINTADD}
  sub sp, sp, #464
  str x0, [sp, #448]     // save output-point pointer
  // load input point P X,Y,Z into frame
  ldr x16, [x1, #0]
  str x16, [sp, #0]
  ldr x16, [x1, #8]
  str x16, [sp, #8]
  ldr x16, [x1, #16]
  str x16, [sp, #16]
  ldr x16, [x1, #24]
  str x16, [sp, #24]
  ldr x16, [x1, #72]
  str x16, [sp, #32]
  ldr x16, [x1, #80]
  str x16, [sp, #40]
  ldr x16, [x1, #88]
  str x16, [sp, #48]
  ldr x16, [x1, #96]
  str x16, [sp, #56]
  ldr x16, [x1, #144]
  str x16, [sp, #64]
  ldr x16, [x1, #152]
  str x16, [sp, #72]
  ldr x16, [x1, #160]
  str x16, [sp, #80]
  ldr x16, [x1, #168]
  str x16, [sp, #88]
  // load input point Q X,Y into frame
  ldr x16, [x2, #0]
  str x16, [sp, #96]
  ldr x16, [x2, #8]
  str x16, [sp, #104]
  ldr x16, [x2, #16]
  str x16, [sp, #112]
  ldr x16, [x2, #24]
  str x16, [sp, #120]
  ldr x16, [x2, #72]
  str x16, [sp, #128]
  ldr x16, [x2, #80]
  str x16, [sp, #136]
  ldr x16, [x2, #88]
  str x16, [sp, #144]
  ldr x16, [x2, #96]
  str x16, [sp, #152]
  // load input point Q Z into frame
  ldr x16, [x2, #144]
  str x16, [sp, #160]
  ldr x16, [x2, #152]
  str x16, [sp, #168]
  ldr x16, [x2, #160]
  str x16, [sp, #176]
  ldr x16, [x2, #168]
  str x16, [sp, #184]
  // mul t0 = X1 * X2
  add x0, sp, #192
  add x1, sp, #0
  add x2, sp, #96
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t1 = Y1 * Y2
  add x0, sp, #224
  add x1, sp, #32
  add x2, sp, #128
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t2 = Z1 * Z2
  add x0, sp, #256
  add x1, sp, #64
  add x2, sp, #160
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t3 = X1 + Y1
  ldr x4, [sp, #0]
  ldr x9, [sp, #32]
  adds x4, x4, x9
  ldr x5, [sp, #8]
  ldr x9, [sp, #40]
  adcs x5, x5, x9
  ldr x6, [sp, #16]
  ldr x9, [sp, #48]
  adcs x6, x6, x9
  ldr x7, [sp, #24]
  ldr x9, [sp, #56]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #288]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #296]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #304]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #312]
  // ModAdd t4 = X2 + Y2
  ldr x4, [sp, #96]
  ldr x9, [sp, #128]
  adds x4, x4, x9
  ldr x5, [sp, #104]
  ldr x9, [sp, #136]
  adcs x5, x5, x9
  ldr x6, [sp, #112]
  ldr x9, [sp, #144]
  adcs x6, x6, x9
  ldr x7, [sp, #120]
  ldr x9, [sp, #152]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #320]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #328]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #336]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #344]
  // mul t3 = t3 * t4
  add x0, sp, #288
  add x1, sp, #288
  add x2, sp, #320
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t4 = t0 + t1
  ldr x4, [sp, #192]
  ldr x9, [sp, #224]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #232]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #240]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #248]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #320]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #328]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #336]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #344]
  // ModSub t3 = t3 - t4
  ldr x4, [sp, #288]
  ldr x9, [sp, #320]
  subs x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #328]
  sbcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #336]
  sbcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #344]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #288]
  str x5, [sp, #296]
  str x6, [sp, #304]
  str x7, [sp, #312]
  // ModAdd t4 = Y1 + Z1
  ldr x4, [sp, #32]
  ldr x9, [sp, #64]
  adds x4, x4, x9
  ldr x5, [sp, #40]
  ldr x9, [sp, #72]
  adcs x5, x5, x9
  ldr x6, [sp, #48]
  ldr x9, [sp, #80]
  adcs x6, x6, x9
  ldr x7, [sp, #56]
  ldr x9, [sp, #88]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #320]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #328]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #336]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #344]
  // ModAdd X3 = Y2 + Z2
  ldr x4, [sp, #128]
  ldr x9, [sp, #160]
  adds x4, x4, x9
  ldr x5, [sp, #136]
  ldr x9, [sp, #168]
  adcs x5, x5, x9
  ldr x6, [sp, #144]
  ldr x9, [sp, #176]
  adcs x6, x6, x9
  ldr x7, [sp, #152]
  ldr x9, [sp, #184]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // mul t4 = t4 * X3
  add x0, sp, #320
  add x1, sp, #320
  add x2, sp, #352
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd X3 = t1 + t2
  ldr x4, [sp, #224]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // ModSub t4 = t4 - X3
  ldr x4, [sp, #320]
  ldr x9, [sp, #352]
  subs x4, x4, x9
  ldr x5, [sp, #328]
  ldr x9, [sp, #360]
  sbcs x5, x5, x9
  ldr x6, [sp, #336]
  ldr x9, [sp, #368]
  sbcs x6, x6, x9
  ldr x7, [sp, #344]
  ldr x9, [sp, #376]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #320]
  str x5, [sp, #328]
  str x6, [sp, #336]
  str x7, [sp, #344]
  // ModAdd X3 = X1 + Z1
  ldr x4, [sp, #0]
  ldr x9, [sp, #64]
  adds x4, x4, x9
  ldr x5, [sp, #8]
  ldr x9, [sp, #72]
  adcs x5, x5, x9
  ldr x6, [sp, #16]
  ldr x9, [sp, #80]
  adcs x6, x6, x9
  ldr x7, [sp, #24]
  ldr x9, [sp, #88]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // ModAdd Y3 = X2 + Z2
  ldr x4, [sp, #96]
  ldr x9, [sp, #160]
  adds x4, x4, x9
  ldr x5, [sp, #104]
  ldr x9, [sp, #168]
  adcs x5, x5, x9
  ldr x6, [sp, #112]
  ldr x9, [sp, #176]
  adcs x6, x6, x9
  ldr x7, [sp, #120]
  ldr x9, [sp, #184]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // mul X3 = X3 * Y3
  add x0, sp, #352
  add x1, sp, #352
  add x2, sp, #384
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Y3 = t0 + t2
  ldr x4, [sp, #192]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // ModSub Y3 = X3 - Y3
  ldr x4, [sp, #352]
  ldr x9, [sp, #384]
  subs x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #392]
  sbcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #400]
  sbcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #408]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #384]
  str x5, [sp, #392]
  str x6, [sp, #400]
  str x7, [sp, #408]
  // mulb Z3 = t2 * b
  add x0, sp, #416
  add x1, sp, #256
  add x2, x3, #304
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModSub X3 = Y3 - Z3
  ldr x4, [sp, #384]
  ldr x9, [sp, #416]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #424]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #432]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #440]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #352]
  str x5, [sp, #360]
  str x6, [sp, #368]
  str x7, [sp, #376]
  // ModAdd Z3 = X3 + X3
  ldr x4, [sp, #352]
  ldr x9, [sp, #352]
  adds x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #360]
  adcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #368]
  adcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #376]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #416]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #424]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #432]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #440]
  // ModAdd X3 = X3 + Z3
  ldr x4, [sp, #352]
  ldr x9, [sp, #416]
  adds x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #424]
  adcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #432]
  adcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #440]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // ModSub Z3 = t1 - X3
  ldr x4, [sp, #224]
  ldr x9, [sp, #352]
  subs x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #360]
  sbcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #368]
  sbcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #376]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #416]
  str x5, [sp, #424]
  str x6, [sp, #432]
  str x7, [sp, #440]
  // ModAdd X3 = t1 + X3
  ldr x4, [sp, #224]
  ldr x9, [sp, #352]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #360]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #368]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #376]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // mulb Y3 = Y3 * b
  add x0, sp, #384
  add x1, sp, #384
  add x2, x3, #304
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t1 = t2 + t2
  ldr x4, [sp, #256]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #264]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #272]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #280]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #224]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #232]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #240]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #248]
  // ModAdd t2 = t1 + t2
  ldr x4, [sp, #224]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #256]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #264]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #272]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #280]
  // ModSub Y3 = Y3 - t2
  ldr x4, [sp, #384]
  ldr x9, [sp, #256]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #264]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #272]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #280]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #384]
  str x5, [sp, #392]
  str x6, [sp, #400]
  str x7, [sp, #408]
  // ModSub Y3 = Y3 - t0
  ldr x4, [sp, #384]
  ldr x9, [sp, #192]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #200]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #208]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #216]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #384]
  str x5, [sp, #392]
  str x6, [sp, #400]
  str x7, [sp, #408]
  // ModAdd t1 = Y3 + Y3
  ldr x4, [sp, #384]
  ldr x9, [sp, #384]
  adds x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #392]
  adcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #400]
  adcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #408]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #224]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #232]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #240]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #248]
  // ModAdd Y3 = t1 + Y3
  ldr x4, [sp, #224]
  ldr x9, [sp, #384]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #392]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #400]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #408]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // ModAdd t1 = t0 + t0
  ldr x4, [sp, #192]
  ldr x9, [sp, #192]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #200]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #208]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #216]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #224]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #232]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #240]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #248]
  // ModAdd t0 = t1 + t0
  ldr x4, [sp, #224]
  ldr x9, [sp, #192]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #200]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #208]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #216]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #192]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #200]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #208]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #216]
  // ModSub t0 = t0 - t2
  ldr x4, [sp, #192]
  ldr x9, [sp, #256]
  subs x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #264]
  sbcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #272]
  sbcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #280]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #192]
  str x5, [sp, #200]
  str x6, [sp, #208]
  str x7, [sp, #216]
  // mul t1 = t4 * Y3
  add x0, sp, #224
  add x1, sp, #320
  add x2, sp, #384
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t2 = t0 * Y3
  add x0, sp, #256
  add x1, sp, #192
  add x2, sp, #384
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul Y3 = X3 * Z3
  add x0, sp, #384
  add x1, sp, #352
  add x2, sp, #416
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Y3 = Y3 + t2
  ldr x4, [sp, #384]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // mul X3 = t3 * X3
  add x0, sp, #352
  add x1, sp, #288
  add x2, sp, #352
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModSub X3 = X3 - t1
  ldr x4, [sp, #352]
  ldr x9, [sp, #224]
  subs x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #232]
  sbcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #240]
  sbcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #248]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #352]
  str x5, [sp, #360]
  str x6, [sp, #368]
  str x7, [sp, #376]
  // mul Z3 = t4 * Z3
  add x0, sp, #416
  add x1, sp, #320
  add x2, sp, #416
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t1 = t3 * t0
  add x0, sp, #224
  add x1, sp, #288
  add x2, sp, #192
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Z3 = Z3 + t1
  ldr x4, [sp, #416]
  ldr x9, [sp, #224]
  adds x4, x4, x9
  ldr x5, [sp, #424]
  ldr x9, [sp, #232]
  adcs x5, x5, x9
  ldr x6, [sp, #432]
  ldr x9, [sp, #240]
  adcs x6, x6, x9
  ldr x7, [sp, #440]
  ldr x9, [sp, #248]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #416]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #424]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #432]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #440]
  // store result point X3,Y3,Z3
  ldr x0, [sp, #448]
  ldr x16, [sp, #352]
  str x16, [x0, #0]
  ldr x16, [sp, #360]
  str x16, [x0, #8]
  ldr x16, [sp, #368]
  str x16, [x0, #16]
  ldr x16, [sp, #376]
  str x16, [x0, #24]
  ldr x16, [sp, #384]
  str x16, [x0, #72]
  ldr x16, [sp, #392]
  str x16, [x0, #80]
  ldr x16, [sp, #400]
  str x16, [x0, #88]
  ldr x16, [sp, #408]
  str x16, [x0, #96]
  ldr x16, [sp, #416]
  str x16, [x0, #144]
  ldr x16, [sp, #424]
  str x16, [x0, #152]
  ldr x16, [sp, #432]
  str x16, [x0, #160]
  ldr x16, [sp, #440]
  str x16, [x0, #168]
  add sp, sp, #464
  {$ELSE}
    {$IFDEF CRYPTOLIB_FP_P256_POINTADDMIXED}
  sub sp, sp, #464
  str x0, [sp, #448]     // save output-point pointer
  // load input point P X,Y,Z into frame
  ldr x16, [x1, #0]
  str x16, [sp, #0]
  ldr x16, [x1, #8]
  str x16, [sp, #8]
  ldr x16, [x1, #16]
  str x16, [sp, #16]
  ldr x16, [x1, #24]
  str x16, [sp, #24]
  ldr x16, [x1, #72]
  str x16, [sp, #32]
  ldr x16, [x1, #80]
  str x16, [sp, #40]
  ldr x16, [x1, #88]
  str x16, [sp, #48]
  ldr x16, [x1, #96]
  str x16, [sp, #56]
  ldr x16, [x1, #144]
  str x16, [sp, #64]
  ldr x16, [x1, #152]
  str x16, [sp, #72]
  ldr x16, [x1, #160]
  str x16, [sp, #80]
  ldr x16, [x1, #168]
  str x16, [sp, #88]
  // load input point Q X,Y into frame
  ldr x16, [x2, #0]
  str x16, [sp, #96]
  ldr x16, [x2, #8]
  str x16, [sp, #104]
  ldr x16, [x2, #16]
  str x16, [sp, #112]
  ldr x16, [x2, #24]
  str x16, [sp, #120]
  ldr x16, [x2, #72]
  str x16, [sp, #128]
  ldr x16, [x2, #80]
  str x16, [sp, #136]
  ldr x16, [x2, #88]
  str x16, [sp, #144]
  ldr x16, [x2, #96]
  str x16, [sp, #152]
  // Q is affine: Z2 := MontOne (R mod p) off PCtx
  ldr x16, [x3, #160]
  str x16, [sp, #160]
  ldr x16, [x3, #168]
  str x16, [sp, #168]
  ldr x16, [x3, #176]
  str x16, [sp, #176]
  ldr x16, [x3, #184]
  str x16, [sp, #184]
  // mul t0 = X1 * X2
  add x0, sp, #192
  add x1, sp, #0
  add x2, sp, #96
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t1 = Y1 * Y2
  add x0, sp, #224
  add x1, sp, #32
  add x2, sp, #128
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t2 = Z1 * Z2
  add x0, sp, #256
  add x1, sp, #64
  add x2, sp, #160
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t3 = X1 + Y1
  ldr x4, [sp, #0]
  ldr x9, [sp, #32]
  adds x4, x4, x9
  ldr x5, [sp, #8]
  ldr x9, [sp, #40]
  adcs x5, x5, x9
  ldr x6, [sp, #16]
  ldr x9, [sp, #48]
  adcs x6, x6, x9
  ldr x7, [sp, #24]
  ldr x9, [sp, #56]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #288]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #296]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #304]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #312]
  // ModAdd t4 = X2 + Y2
  ldr x4, [sp, #96]
  ldr x9, [sp, #128]
  adds x4, x4, x9
  ldr x5, [sp, #104]
  ldr x9, [sp, #136]
  adcs x5, x5, x9
  ldr x6, [sp, #112]
  ldr x9, [sp, #144]
  adcs x6, x6, x9
  ldr x7, [sp, #120]
  ldr x9, [sp, #152]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #320]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #328]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #336]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #344]
  // mul t3 = t3 * t4
  add x0, sp, #288
  add x1, sp, #288
  add x2, sp, #320
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t4 = t0 + t1
  ldr x4, [sp, #192]
  ldr x9, [sp, #224]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #232]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #240]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #248]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #320]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #328]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #336]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #344]
  // ModSub t3 = t3 - t4
  ldr x4, [sp, #288]
  ldr x9, [sp, #320]
  subs x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #328]
  sbcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #336]
  sbcs x6, x6, x9
  ldr x7, [sp, #312]
  ldr x9, [sp, #344]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #288]
  str x5, [sp, #296]
  str x6, [sp, #304]
  str x7, [sp, #312]
  // ModAdd t4 = Y1 + Z1
  ldr x4, [sp, #32]
  ldr x9, [sp, #64]
  adds x4, x4, x9
  ldr x5, [sp, #40]
  ldr x9, [sp, #72]
  adcs x5, x5, x9
  ldr x6, [sp, #48]
  ldr x9, [sp, #80]
  adcs x6, x6, x9
  ldr x7, [sp, #56]
  ldr x9, [sp, #88]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #320]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #328]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #336]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #344]
  // ModAdd X3 = Y2 + Z2
  ldr x4, [sp, #128]
  ldr x9, [sp, #160]
  adds x4, x4, x9
  ldr x5, [sp, #136]
  ldr x9, [sp, #168]
  adcs x5, x5, x9
  ldr x6, [sp, #144]
  ldr x9, [sp, #176]
  adcs x6, x6, x9
  ldr x7, [sp, #152]
  ldr x9, [sp, #184]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // mul t4 = t4 * X3
  add x0, sp, #320
  add x1, sp, #320
  add x2, sp, #352
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd X3 = t1 + t2
  ldr x4, [sp, #224]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // ModSub t4 = t4 - X3
  ldr x4, [sp, #320]
  ldr x9, [sp, #352]
  subs x4, x4, x9
  ldr x5, [sp, #328]
  ldr x9, [sp, #360]
  sbcs x5, x5, x9
  ldr x6, [sp, #336]
  ldr x9, [sp, #368]
  sbcs x6, x6, x9
  ldr x7, [sp, #344]
  ldr x9, [sp, #376]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #320]
  str x5, [sp, #328]
  str x6, [sp, #336]
  str x7, [sp, #344]
  // ModAdd X3 = X1 + Z1
  ldr x4, [sp, #0]
  ldr x9, [sp, #64]
  adds x4, x4, x9
  ldr x5, [sp, #8]
  ldr x9, [sp, #72]
  adcs x5, x5, x9
  ldr x6, [sp, #16]
  ldr x9, [sp, #80]
  adcs x6, x6, x9
  ldr x7, [sp, #24]
  ldr x9, [sp, #88]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // ModAdd Y3 = X2 + Z2
  ldr x4, [sp, #96]
  ldr x9, [sp, #160]
  adds x4, x4, x9
  ldr x5, [sp, #104]
  ldr x9, [sp, #168]
  adcs x5, x5, x9
  ldr x6, [sp, #112]
  ldr x9, [sp, #176]
  adcs x6, x6, x9
  ldr x7, [sp, #120]
  ldr x9, [sp, #184]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // mul X3 = X3 * Y3
  add x0, sp, #352
  add x1, sp, #352
  add x2, sp, #384
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Y3 = t0 + t2
  ldr x4, [sp, #192]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // ModSub Y3 = X3 - Y3
  ldr x4, [sp, #352]
  ldr x9, [sp, #384]
  subs x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #392]
  sbcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #400]
  sbcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #408]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #384]
  str x5, [sp, #392]
  str x6, [sp, #400]
  str x7, [sp, #408]
  // mulb Z3 = t2 * b
  add x0, sp, #416
  add x1, sp, #256
  add x2, x3, #304
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModSub X3 = Y3 - Z3
  ldr x4, [sp, #384]
  ldr x9, [sp, #416]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #424]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #432]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #440]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #352]
  str x5, [sp, #360]
  str x6, [sp, #368]
  str x7, [sp, #376]
  // ModAdd Z3 = X3 + X3
  ldr x4, [sp, #352]
  ldr x9, [sp, #352]
  adds x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #360]
  adcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #368]
  adcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #376]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #416]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #424]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #432]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #440]
  // ModAdd X3 = X3 + Z3
  ldr x4, [sp, #352]
  ldr x9, [sp, #416]
  adds x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #424]
  adcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #432]
  adcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #440]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // ModSub Z3 = t1 - X3
  ldr x4, [sp, #224]
  ldr x9, [sp, #352]
  subs x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #360]
  sbcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #368]
  sbcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #376]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #416]
  str x5, [sp, #424]
  str x6, [sp, #432]
  str x7, [sp, #440]
  // ModAdd X3 = t1 + X3
  ldr x4, [sp, #224]
  ldr x9, [sp, #352]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #360]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #368]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #376]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #352]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #360]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #368]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #376]
  // mulb Y3 = Y3 * b
  add x0, sp, #384
  add x1, sp, #384
  add x2, x3, #304
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd t1 = t2 + t2
  ldr x4, [sp, #256]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #264]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #272]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #280]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #224]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #232]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #240]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #248]
  // ModAdd t2 = t1 + t2
  ldr x4, [sp, #224]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #256]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #264]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #272]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #280]
  // ModSub Y3 = Y3 - t2
  ldr x4, [sp, #384]
  ldr x9, [sp, #256]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #264]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #272]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #280]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #384]
  str x5, [sp, #392]
  str x6, [sp, #400]
  str x7, [sp, #408]
  // ModSub Y3 = Y3 - t0
  ldr x4, [sp, #384]
  ldr x9, [sp, #192]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #200]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #208]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #216]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #384]
  str x5, [sp, #392]
  str x6, [sp, #400]
  str x7, [sp, #408]
  // ModAdd t1 = Y3 + Y3
  ldr x4, [sp, #384]
  ldr x9, [sp, #384]
  adds x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #392]
  adcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #400]
  adcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #408]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #224]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #232]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #240]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #248]
  // ModAdd Y3 = t1 + Y3
  ldr x4, [sp, #224]
  ldr x9, [sp, #384]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #392]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #400]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #408]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // ModAdd t1 = t0 + t0
  ldr x4, [sp, #192]
  ldr x9, [sp, #192]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #200]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #208]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #216]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #224]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #232]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #240]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #248]
  // ModAdd t0 = t1 + t0
  ldr x4, [sp, #224]
  ldr x9, [sp, #192]
  adds x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #200]
  adcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #208]
  adcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #216]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #192]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #200]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #208]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #216]
  // ModSub t0 = t0 - t2
  ldr x4, [sp, #192]
  ldr x9, [sp, #256]
  subs x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #264]
  sbcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #272]
  sbcs x6, x6, x9
  ldr x7, [sp, #216]
  ldr x9, [sp, #280]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #192]
  str x5, [sp, #200]
  str x6, [sp, #208]
  str x7, [sp, #216]
  // mul t1 = t4 * Y3
  add x0, sp, #224
  add x1, sp, #320
  add x2, sp, #384
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t2 = t0 * Y3
  add x0, sp, #256
  add x1, sp, #192
  add x2, sp, #384
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul Y3 = X3 * Z3
  add x0, sp, #384
  add x1, sp, #352
  add x2, sp, #416
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Y3 = Y3 + t2
  ldr x4, [sp, #384]
  ldr x9, [sp, #256]
  adds x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #264]
  adcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #272]
  adcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #280]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #384]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #392]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #400]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #408]
  // mul X3 = t3 * X3
  add x0, sp, #352
  add x1, sp, #288
  add x2, sp, #352
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModSub X3 = X3 - t1
  ldr x4, [sp, #352]
  ldr x9, [sp, #224]
  subs x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #232]
  sbcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #240]
  sbcs x6, x6, x9
  ldr x7, [sp, #376]
  ldr x9, [sp, #248]
  sbcs x7, x7, x9
  sbc x15, xzr, xzr
  ldr x9, [x3, #16]
  and x9, x9, x15
  adds x4, x4, x9
  ldr x9, [x3, #24]
  and x9, x9, x15
  adcs x5, x5, x9
  ldr x9, [x3, #32]
  and x9, x9, x15
  adcs x6, x6, x9
  ldr x9, [x3, #40]
  and x9, x9, x15
  adcs x7, x7, x9
  str x4, [sp, #352]
  str x5, [sp, #360]
  str x6, [sp, #368]
  str x7, [sp, #376]
  // mul Z3 = t4 * Z3
  add x0, sp, #416
  add x1, sp, #320
  add x2, sp, #416
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // mul t1 = t3 * t0
  add x0, sp, #224
  add x1, sp, #288
  add x2, sp, #192
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  ldr  x10, [x2, #0]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #8]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #16]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  ldr  x10, [x2, #24]
  mov  x11, xzr
  ldr  x15, [x1, #0]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x4, x4, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #8]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x5, x5, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #16]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x6, x6, x13
  adc  x11, x14, xzr
  ldr  x15, [x1, #24]
  mul  x13, x15, x10
  umulh x14, x15, x10
  adds x13, x13, x11
  adc  x14, x14, xzr
  adds x7, x7, x13
  adc  x11, x14, xzr
  adds x8, x8, x11
  adc  x9, xzr, xzr
  lsl  x13, x4, #32       // low64(m<<32)
  lsr  x14, x4, #32       // high32(m<<32)
  adds x5, x5, x13        // t[1..] += m<<96
  adcs x6, x6, x14
  adcs x7, x7, xzr
  adcs x8, x8, xzr
  adc  x9, x9, xzr
  subs x15, x4, x13       // x15:x12 = m*p3 = m + m<<64 - m<<32
  sbc  x12, x4, x14
  adds x7, x7, x15        // t[3..] += m*p3 << 192
  adcs x8, x8, x12
  adc  x9, x9, xzr
  mov  x4, x5             // shift down one limb (drop t0)
  mov  x5, x6
  mov  x6, x7
  mov  x7, x8
  mov  x8, x9
  mov  x11, xzr
  ldr  x15, [x3, #16]
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #24]
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #32]
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  ldr  x15, [x3, #40]
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  subs x13, x8, x11
  adc  x12, xzr, xzr
  neg  x12, x12
  mov  x11, xzr
  ldr  x15, [x3, #16]
  and  x15, x15, x12
  subs x13, x4, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #0]
  ldr  x15, [x3, #24]
  and  x15, x15, x12
  subs x13, x5, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #8]
  ldr  x15, [x3, #32]
  and  x15, x15, x12
  subs x13, x6, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #16]
  ldr  x15, [x3, #40]
  and  x15, x15, x12
  subs x13, x7, x11
  sbc  x14, xzr, xzr
  subs x13, x13, x15
  sbc  x10, xzr, xzr
  add  x11, x14, x10
  neg  x11, x11
  str  x13, [x0, #24]
  // ModAdd Z3 = Z3 + t1
  ldr x4, [sp, #416]
  ldr x9, [sp, #224]
  adds x4, x4, x9
  ldr x5, [sp, #424]
  ldr x9, [sp, #232]
  adcs x5, x5, x9
  ldr x6, [sp, #432]
  ldr x9, [sp, #240]
  adcs x6, x6, x9
  ldr x7, [sp, #440]
  ldr x9, [sp, #248]
  adcs x7, x7, x9
  adc x8, xzr, xzr
  ldr x9, [x3, #16]
  subs x10, x4, x9
  ldr x9, [x3, #24]
  sbcs x11, x5, x9
  ldr x9, [x3, #32]
  sbcs x12, x6, x9
  ldr x9, [x3, #40]
  sbcs x13, x7, x9
  sbc x14, xzr, xzr
  eor x15, x8, #1
  and x15, x15, x14
  neg x15, x15
  eor x16, x4, x10
  and x16, x16, x15
  eor x16, x10, x16
  str x16, [sp, #416]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #424]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #432]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #440]
  // store result point X3,Y3,Z3
  ldr x0, [sp, #448]
  ldr x16, [sp, #352]
  str x16, [x0, #0]
  ldr x16, [sp, #360]
  str x16, [x0, #8]
  ldr x16, [sp, #368]
  str x16, [x0, #16]
  ldr x16, [sp, #376]
  str x16, [x0, #24]
  ldr x16, [sp, #384]
  str x16, [x0, #72]
  ldr x16, [sp, #392]
  str x16, [x0, #80]
  ldr x16, [sp, #400]
  str x16, [x0, #88]
  ldr x16, [sp, #408]
  str x16, [x0, #96]
  ldr x16, [sp, #416]
  str x16, [x0, #144]
  ldr x16, [sp, #424]
  str x16, [x0, #152]
  ldr x16, [sp, #432]
  str x16, [x0, #160]
  ldr x16, [sp, #440]
  str x16, [x0, #168]
  add sp, sp, #464
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_FP_P256_POINTDOUBLE, CRYPTOLIB_FP_P256_POINTADD, CRYPTOLIB_FP_P256_POINTADDMIXED must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
