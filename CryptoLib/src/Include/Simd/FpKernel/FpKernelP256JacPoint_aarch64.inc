// Fused P-256 incomplete-Jacobian point kernels (secp256r1, a=-3, AArch64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined
// before including this file:
//
//   CRYPTOLIB_FP_P256_JACPOINTDOUBLE   (ClpSimdProc3Begin: x0 = PR, x1 = PA, x2 = PCtx)
//     - straight-line incomplete Jacobian doubling PR := 2*PA (dbl-2001-b,
//       a=-3). Infinity (Z=0) maps to infinity with no branch.
//   CRYPTOLIB_FP_P256_JACPOINTADD   (ClpSimdProc4Begin: x0 = PScratch, x1 = PA, x2 = PQ, x3 = PCtx)
//     - incomplete Jacobian addition (add-2007-bl) with the branch-free
//       masked-infinity completion applied inside the kernel, writing the
//       result to PScratch.R and the predicate operands H (= U2-U1) and
//       RS (= S2-S1) to PScratch.H / PScratch.RS. The caller owns the P=Q
//       detect-and-double BRANCH (fires iff both finite and H=0 and RS=0);
//       no data-dependent branch lives in the asm.
//   CRYPTOLIB_FP_P256_JACPOINTADDMIXED   (ClpSimdProc4Begin: x0 = PScratch, x1 = PA, x2 = PQ, x3 = PCtx)
//     - the same addition with PQ an AFFINE point (Z2=1 via PCtx.MontOne
//       at +160).
//
// PScratch is a record { R: TFePoint; H, RS: TFe } (R.X/Y/Z at +0/+72/+144,
// H at +216, RS at +288). PA/PQ are TFePoint (or TFeAffine) bases. PCtx =
// [n0', N, p0..p3]; these kernels carry NO b-multiply, so Fb is never read.
// Every intermediate lives in a fixed stack frame and both inputs are copied
// in up front, so PScratch never aliases an input. The field multiply is the
// folded special-prime mul_mont_p256 body, inlined verbatim. Constant-time:
// straight-line and data-independent; the masked-infinity completion and the
// exposed predicate are branch-free. Backend-gated; any other target uses the
// generic per-op incomplete-Jacobian formula, bit-for-bit.
{$IFDEF CRYPTOLIB_FP_P256_JACPOINTDOUBLE}
  mov x3, x2            // x3 = PCtx (pinned; cores read [x3 + ..])
  sub sp, sp, #432
  str x0, [sp, #416]     // save output-point pointer
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
  // sqr delta = Z
  add x0, sp, #96
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
  // sqr gamma = Y
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
  // mul beta = X * gamma
  add x0, sp, #160
  add x1, sp, #0
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
  // ModSub t = X - delta
  ldr x4, [sp, #0]
  ldr x9, [sp, #96]
  subs x4, x4, x9
  ldr x5, [sp, #8]
  ldr x9, [sp, #104]
  sbcs x5, x5, x9
  ldr x6, [sp, #16]
  ldr x9, [sp, #112]
  sbcs x6, x6, x9
  ldr x7, [sp, #24]
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
  str x4, [sp, #224]
  str x5, [sp, #232]
  str x6, [sp, #240]
  str x7, [sp, #248]
  // ModAdd u = X + delta
  ldr x4, [sp, #0]
  ldr x9, [sp, #96]
  adds x4, x4, x9
  ldr x5, [sp, #8]
  ldr x9, [sp, #104]
  adcs x5, x5, x9
  ldr x6, [sp, #16]
  ldr x9, [sp, #112]
  adcs x6, x6, x9
  ldr x7, [sp, #24]
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
  // mul tmp = t * u
  add x0, sp, #288
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
  // ModAdd alpha = tmp + tmp
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
  // ModAdd alpha = alpha + tmp
  ldr x4, [sp, #192]
  ldr x9, [sp, #288]
  adds x4, x4, x9
  ldr x5, [sp, #200]
  ldr x9, [sp, #296]
  adcs x5, x5, x9
  ldr x6, [sp, #208]
  ldr x9, [sp, #304]
  adcs x6, x6, x9
  ldr x7, [sp, #216]
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
  // sqr X3 = alpha
  add x0, sp, #320
  add x1, sp, #192
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
  // ModAdd tmp = beta + beta
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
  // ModAdd tmp = tmp + tmp
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
  // ModAdd tmp = tmp + tmp
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
  // ModSub X3 = X3 - tmp
  ldr x4, [sp, #320]
  ldr x9, [sp, #288]
  subs x4, x4, x9
  ldr x5, [sp, #328]
  ldr x9, [sp, #296]
  sbcs x5, x5, x9
  ldr x6, [sp, #336]
  ldr x9, [sp, #304]
  sbcs x6, x6, x9
  ldr x7, [sp, #344]
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
  str x4, [sp, #320]
  str x5, [sp, #328]
  str x6, [sp, #336]
  str x7, [sp, #344]
  // ModAdd Z3 = Y + Z
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
  // sqr Z3 = Z3
  add x0, sp, #384
  add x1, sp, #384
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
  // ModSub Z3 = Z3 - gamma
  ldr x4, [sp, #384]
  ldr x9, [sp, #128]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #136]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #144]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
  ldr x9, [sp, #152]
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
  // ModSub Z3 = Z3 - delta
  ldr x4, [sp, #384]
  ldr x9, [sp, #96]
  subs x4, x4, x9
  ldr x5, [sp, #392]
  ldr x9, [sp, #104]
  sbcs x5, x5, x9
  ldr x6, [sp, #400]
  ldr x9, [sp, #112]
  sbcs x6, x6, x9
  ldr x7, [sp, #408]
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
  str x4, [sp, #384]
  str x5, [sp, #392]
  str x6, [sp, #400]
  str x7, [sp, #408]
  // ModAdd tmp = beta + beta
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
  // ModAdd tmp = tmp + tmp
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
  // ModSub tmp = tmp - X3
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
  // mul Y3 = alpha * tmp
  add x0, sp, #352
  add x1, sp, #192
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
  // sqr tmp = gamma
  add x0, sp, #288
  add x1, sp, #128
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
  // ModAdd tmp = tmp + tmp
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
  // ModAdd tmp = tmp + tmp
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
  // ModAdd tmp = tmp + tmp
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
  // ModSub Y3 = Y3 - tmp
  ldr x4, [sp, #352]
  ldr x9, [sp, #288]
  subs x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #296]
  sbcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #304]
  sbcs x6, x6, x9
  ldr x7, [sp, #376]
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
  str x4, [sp, #352]
  str x5, [sp, #360]
  str x6, [sp, #368]
  str x7, [sp, #376]
  // store result point X3,Y3,Z3
  ldr x0, [sp, #416]
  ldr x16, [sp, #320]
  str x16, [x0, #0]
  ldr x16, [sp, #328]
  str x16, [x0, #8]
  ldr x16, [sp, #336]
  str x16, [x0, #16]
  ldr x16, [sp, #344]
  str x16, [x0, #24]
  ldr x16, [sp, #352]
  str x16, [x0, #72]
  ldr x16, [sp, #360]
  str x16, [x0, #80]
  ldr x16, [sp, #368]
  str x16, [x0, #88]
  ldr x16, [sp, #376]
  str x16, [x0, #96]
  ldr x16, [sp, #384]
  str x16, [x0, #144]
  ldr x16, [sp, #392]
  str x16, [x0, #152]
  ldr x16, [sp, #400]
  str x16, [x0, #160]
  ldr x16, [sp, #408]
  str x16, [x0, #168]
  add sp, sp, #432
{$ELSE}
  {$IFDEF CRYPTOLIB_FP_P256_JACPOINTADD}
  sub sp, sp, #720
  str x0, [sp, #704]     // save output scratch pointer
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
  // sqr Z1Z1 = Z1
  add x0, sp, #192
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
  // sqr Z2Z2 = Z2
  add x0, sp, #224
  add x1, sp, #160
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
  // mul U1 = X1 * Z2Z2
  add x0, sp, #256
  add x1, sp, #0
  add x2, sp, #224
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
  // mul U2 = X2 * Z1Z1
  add x0, sp, #288
  add x1, sp, #96
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
  // mul t = Y1 * Z2
  add x0, sp, #576
  add x1, sp, #32
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
  // mul S1 = t * Z2Z2
  add x0, sp, #320
  add x1, sp, #576
  add x2, sp, #224
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
  // mul t = Y2 * Z1
  add x0, sp, #576
  add x1, sp, #128
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
  // mul S2 = t * Z1Z1
  add x0, sp, #352
  add x1, sp, #576
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
  // ModSub H = U2 - U1
  ldr x4, [sp, #288]
  ldr x9, [sp, #256]
  subs x4, x4, x9
  ldr x5, [sp, #296]
  ldr x9, [sp, #264]
  sbcs x5, x5, x9
  ldr x6, [sp, #304]
  ldr x9, [sp, #272]
  sbcs x6, x6, x9
  ldr x7, [sp, #312]
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
  // ModSub RS = S2 - S1
  ldr x4, [sp, #352]
  ldr x9, [sp, #320]
  subs x4, x4, x9
  ldr x5, [sp, #360]
  ldr x9, [sp, #328]
  sbcs x5, x5, x9
  ldr x6, [sp, #368]
  ldr x9, [sp, #336]
  sbcs x6, x6, x9
  ldr x7, [sp, #376]
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
  str x4, [sp, #416]
  str x5, [sp, #424]
  str x6, [sp, #432]
  str x7, [sp, #440]
  // ModAdd R = RS + RS
  ldr x4, [sp, #416]
  ldr x9, [sp, #416]
  adds x4, x4, x9
  ldr x5, [sp, #424]
  ldr x9, [sp, #424]
  adcs x5, x5, x9
  ldr x6, [sp, #432]
  ldr x9, [sp, #432]
  adcs x6, x6, x9
  ldr x7, [sp, #440]
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
  str x16, [sp, #448]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #456]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #464]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #472]
  // ModAdd t = H + H
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
  str x16, [sp, #576]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #584]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #592]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #600]
  // sqr I = t
  add x0, sp, #480
  add x1, sp, #576
  add x2, sp, #576
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
  // mul J = H * I
  add x0, sp, #512
  add x1, sp, #384
  add x2, sp, #480
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
  // mul V = U1 * I
  add x0, sp, #544
  add x1, sp, #256
  add x2, sp, #480
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
  // sqr X3 = R
  add x0, sp, #608
  add x1, sp, #448
  add x2, sp, #448
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
  // ModSub X3 = X3 - J
  ldr x4, [sp, #608]
  ldr x9, [sp, #512]
  subs x4, x4, x9
  ldr x5, [sp, #616]
  ldr x9, [sp, #520]
  sbcs x5, x5, x9
  ldr x6, [sp, #624]
  ldr x9, [sp, #528]
  sbcs x6, x6, x9
  ldr x7, [sp, #632]
  ldr x9, [sp, #536]
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
  str x4, [sp, #608]
  str x5, [sp, #616]
  str x6, [sp, #624]
  str x7, [sp, #632]
  // ModAdd t = V + V
  ldr x4, [sp, #544]
  ldr x9, [sp, #544]
  adds x4, x4, x9
  ldr x5, [sp, #552]
  ldr x9, [sp, #552]
  adcs x5, x5, x9
  ldr x6, [sp, #560]
  ldr x9, [sp, #560]
  adcs x6, x6, x9
  ldr x7, [sp, #568]
  ldr x9, [sp, #568]
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
  str x16, [sp, #576]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #584]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #592]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #600]
  // ModSub X3 = X3 - t
  ldr x4, [sp, #608]
  ldr x9, [sp, #576]
  subs x4, x4, x9
  ldr x5, [sp, #616]
  ldr x9, [sp, #584]
  sbcs x5, x5, x9
  ldr x6, [sp, #624]
  ldr x9, [sp, #592]
  sbcs x6, x6, x9
  ldr x7, [sp, #632]
  ldr x9, [sp, #600]
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
  str x4, [sp, #608]
  str x5, [sp, #616]
  str x6, [sp, #624]
  str x7, [sp, #632]
  // ModSub t = V - X3
  ldr x4, [sp, #544]
  ldr x9, [sp, #608]
  subs x4, x4, x9
  ldr x5, [sp, #552]
  ldr x9, [sp, #616]
  sbcs x5, x5, x9
  ldr x6, [sp, #560]
  ldr x9, [sp, #624]
  sbcs x6, x6, x9
  ldr x7, [sp, #568]
  ldr x9, [sp, #632]
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
  str x4, [sp, #576]
  str x5, [sp, #584]
  str x6, [sp, #592]
  str x7, [sp, #600]
  // mul Y3 = R * t
  add x0, sp, #640
  add x1, sp, #448
  add x2, sp, #576
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
  // mul t = S1 * J
  add x0, sp, #576
  add x1, sp, #320
  add x2, sp, #512
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
  // ModAdd t = t + t
  ldr x4, [sp, #576]
  ldr x9, [sp, #576]
  adds x4, x4, x9
  ldr x5, [sp, #584]
  ldr x9, [sp, #584]
  adcs x5, x5, x9
  ldr x6, [sp, #592]
  ldr x9, [sp, #592]
  adcs x6, x6, x9
  ldr x7, [sp, #600]
  ldr x9, [sp, #600]
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
  str x16, [sp, #576]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #584]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #592]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #600]
  // ModSub Y3 = Y3 - t
  ldr x4, [sp, #640]
  ldr x9, [sp, #576]
  subs x4, x4, x9
  ldr x5, [sp, #648]
  ldr x9, [sp, #584]
  sbcs x5, x5, x9
  ldr x6, [sp, #656]
  ldr x9, [sp, #592]
  sbcs x6, x6, x9
  ldr x7, [sp, #664]
  ldr x9, [sp, #600]
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
  str x4, [sp, #640]
  str x5, [sp, #648]
  str x6, [sp, #656]
  str x7, [sp, #664]
  // ModAdd Z3 = Z1 + Z2
  ldr x4, [sp, #64]
  ldr x9, [sp, #160]
  adds x4, x4, x9
  ldr x5, [sp, #72]
  ldr x9, [sp, #168]
  adcs x5, x5, x9
  ldr x6, [sp, #80]
  ldr x9, [sp, #176]
  adcs x6, x6, x9
  ldr x7, [sp, #88]
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
  str x16, [sp, #672]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #680]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #688]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #696]
  // sqr Z3 = Z3
  add x0, sp, #672
  add x1, sp, #672
  add x2, sp, #672
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
  // ModSub Z3 = Z3 - Z1Z1
  ldr x4, [sp, #672]
  ldr x9, [sp, #192]
  subs x4, x4, x9
  ldr x5, [sp, #680]
  ldr x9, [sp, #200]
  sbcs x5, x5, x9
  ldr x6, [sp, #688]
  ldr x9, [sp, #208]
  sbcs x6, x6, x9
  ldr x7, [sp, #696]
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
  str x4, [sp, #672]
  str x5, [sp, #680]
  str x6, [sp, #688]
  str x7, [sp, #696]
  // ModSub Z3 = Z3 - Z2Z2
  ldr x4, [sp, #672]
  ldr x9, [sp, #224]
  subs x4, x4, x9
  ldr x5, [sp, #680]
  ldr x9, [sp, #232]
  sbcs x5, x5, x9
  ldr x6, [sp, #688]
  ldr x9, [sp, #240]
  sbcs x6, x6, x9
  ldr x7, [sp, #696]
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
  str x4, [sp, #672]
  str x5, [sp, #680]
  str x6, [sp, #688]
  str x7, [sp, #696]
  // mul Z3 = Z3 * H
  add x0, sp, #672
  add x1, sp, #672
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
  // infinity masks in1 (x13), in2 (x14)
  ldr x9, [sp, #64]
  ldr x10, [sp, #72]
  orr x9, x9, x10
  ldr x10, [sp, #80]
  orr x9, x9, x10
  ldr x10, [sp, #88]
  orr x9, x9, x10
  cmp x9, #0
  cset x13, eq
  neg x13, x13
  ldr x9, [sp, #160]
  ldr x10, [sp, #168]
  orr x9, x9, x10
  ldr x10, [sp, #176]
  orr x9, x9, x10
  ldr x10, [sp, #184]
  orr x9, x9, x10
  cmp x9, #0
  cset x14, eq
  neg x14, x14
  ldr x0, [sp, #704]
  // masked select X3 -> R
  ldr x4, [sp, #608]
  ldr x5, [sp, #0]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #96]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #0]
  ldr x4, [sp, #616]
  ldr x5, [sp, #8]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #104]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #8]
  ldr x4, [sp, #624]
  ldr x5, [sp, #16]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #112]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #16]
  ldr x4, [sp, #632]
  ldr x5, [sp, #24]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #120]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #24]
  // masked select Y3 -> R
  ldr x4, [sp, #640]
  ldr x5, [sp, #32]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #128]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #72]
  ldr x4, [sp, #648]
  ldr x5, [sp, #40]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #136]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #80]
  ldr x4, [sp, #656]
  ldr x5, [sp, #48]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #144]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #88]
  ldr x4, [sp, #664]
  ldr x5, [sp, #56]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #152]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #96]
  // masked select Z3 -> R
  ldr x4, [sp, #672]
  ldr x5, [sp, #64]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #160]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #144]
  ldr x4, [sp, #680]
  ldr x5, [sp, #72]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #168]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #152]
  ldr x4, [sp, #688]
  ldr x5, [sp, #80]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #176]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #160]
  ldr x4, [sp, #696]
  ldr x5, [sp, #88]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #184]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #168]
  // expose predicate operands H, RS
  ldr x16, [sp, #384]
  str x16, [x0, #216]
  ldr x16, [sp, #392]
  str x16, [x0, #224]
  ldr x16, [sp, #400]
  str x16, [x0, #232]
  ldr x16, [sp, #408]
  str x16, [x0, #240]
  ldr x16, [sp, #416]
  str x16, [x0, #288]
  ldr x16, [sp, #424]
  str x16, [x0, #296]
  ldr x16, [sp, #432]
  str x16, [x0, #304]
  ldr x16, [sp, #440]
  str x16, [x0, #312]
  add sp, sp, #720
  {$ELSE}
    {$IFDEF CRYPTOLIB_FP_P256_JACPOINTADDMIXED}
  sub sp, sp, #624
  str x0, [sp, #608]     // save output scratch pointer
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
  // affine Q: 'one' := MontOne (R mod p) off PCtx
  ldr x16, [x3, #160]
  str x16, [sp, #160]
  ldr x16, [x3, #168]
  str x16, [sp, #168]
  ldr x16, [x3, #176]
  str x16, [sp, #176]
  ldr x16, [x3, #184]
  str x16, [sp, #184]
  // sqr Z1Z1 = Z1
  add x0, sp, #192
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
  // mul U2 = X2 * Z1Z1
  add x0, sp, #224
  add x1, sp, #96
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
  // mul t = Y2 * Z1
  add x0, sp, #480
  add x1, sp, #128
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
  // mul S2 = t * Z1Z1
  add x0, sp, #256
  add x1, sp, #480
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
  // ModSub H = U2 - X1
  ldr x4, [sp, #224]
  ldr x9, [sp, #0]
  subs x4, x4, x9
  ldr x5, [sp, #232]
  ldr x9, [sp, #8]
  sbcs x5, x5, x9
  ldr x6, [sp, #240]
  ldr x9, [sp, #16]
  sbcs x6, x6, x9
  ldr x7, [sp, #248]
  ldr x9, [sp, #24]
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
  // ModSub RS = S2 - Y1
  ldr x4, [sp, #256]
  ldr x9, [sp, #32]
  subs x4, x4, x9
  ldr x5, [sp, #264]
  ldr x9, [sp, #40]
  sbcs x5, x5, x9
  ldr x6, [sp, #272]
  ldr x9, [sp, #48]
  sbcs x6, x6, x9
  ldr x7, [sp, #280]
  ldr x9, [sp, #56]
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
  // ModAdd R = RS + RS
  ldr x4, [sp, #320]
  ldr x9, [sp, #320]
  adds x4, x4, x9
  ldr x5, [sp, #328]
  ldr x9, [sp, #328]
  adcs x5, x5, x9
  ldr x6, [sp, #336]
  ldr x9, [sp, #336]
  adcs x6, x6, x9
  ldr x7, [sp, #344]
  ldr x9, [sp, #344]
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
  // ModAdd t = H + H
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
  str x16, [sp, #480]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #488]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #496]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #504]
  // sqr I = t
  add x0, sp, #384
  add x1, sp, #480
  add x2, sp, #480
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
  // mul J = H * I
  add x0, sp, #416
  add x1, sp, #288
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
  // mul V = X1 * I
  add x0, sp, #448
  add x1, sp, #0
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
  // sqr X3 = R
  add x0, sp, #512
  add x1, sp, #352
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
  // ModSub X3 = X3 - J
  ldr x4, [sp, #512]
  ldr x9, [sp, #416]
  subs x4, x4, x9
  ldr x5, [sp, #520]
  ldr x9, [sp, #424]
  sbcs x5, x5, x9
  ldr x6, [sp, #528]
  ldr x9, [sp, #432]
  sbcs x6, x6, x9
  ldr x7, [sp, #536]
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
  str x4, [sp, #512]
  str x5, [sp, #520]
  str x6, [sp, #528]
  str x7, [sp, #536]
  // ModAdd t = V + V
  ldr x4, [sp, #448]
  ldr x9, [sp, #448]
  adds x4, x4, x9
  ldr x5, [sp, #456]
  ldr x9, [sp, #456]
  adcs x5, x5, x9
  ldr x6, [sp, #464]
  ldr x9, [sp, #464]
  adcs x6, x6, x9
  ldr x7, [sp, #472]
  ldr x9, [sp, #472]
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
  str x16, [sp, #480]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #488]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #496]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #504]
  // ModSub X3 = X3 - t
  ldr x4, [sp, #512]
  ldr x9, [sp, #480]
  subs x4, x4, x9
  ldr x5, [sp, #520]
  ldr x9, [sp, #488]
  sbcs x5, x5, x9
  ldr x6, [sp, #528]
  ldr x9, [sp, #496]
  sbcs x6, x6, x9
  ldr x7, [sp, #536]
  ldr x9, [sp, #504]
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
  str x4, [sp, #512]
  str x5, [sp, #520]
  str x6, [sp, #528]
  str x7, [sp, #536]
  // ModSub t = V - X3
  ldr x4, [sp, #448]
  ldr x9, [sp, #512]
  subs x4, x4, x9
  ldr x5, [sp, #456]
  ldr x9, [sp, #520]
  sbcs x5, x5, x9
  ldr x6, [sp, #464]
  ldr x9, [sp, #528]
  sbcs x6, x6, x9
  ldr x7, [sp, #472]
  ldr x9, [sp, #536]
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
  str x4, [sp, #480]
  str x5, [sp, #488]
  str x6, [sp, #496]
  str x7, [sp, #504]
  // mul Y3 = R * t
  add x0, sp, #544
  add x1, sp, #352
  add x2, sp, #480
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
  // mul t = Y1 * J
  add x0, sp, #480
  add x1, sp, #32
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
  // ModAdd t = t + t
  ldr x4, [sp, #480]
  ldr x9, [sp, #480]
  adds x4, x4, x9
  ldr x5, [sp, #488]
  ldr x9, [sp, #488]
  adcs x5, x5, x9
  ldr x6, [sp, #496]
  ldr x9, [sp, #496]
  adcs x6, x6, x9
  ldr x7, [sp, #504]
  ldr x9, [sp, #504]
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
  str x16, [sp, #480]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #488]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #496]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #504]
  // ModSub Y3 = Y3 - t
  ldr x4, [sp, #544]
  ldr x9, [sp, #480]
  subs x4, x4, x9
  ldr x5, [sp, #552]
  ldr x9, [sp, #488]
  sbcs x5, x5, x9
  ldr x6, [sp, #560]
  ldr x9, [sp, #496]
  sbcs x6, x6, x9
  ldr x7, [sp, #568]
  ldr x9, [sp, #504]
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
  str x4, [sp, #544]
  str x5, [sp, #552]
  str x6, [sp, #560]
  str x7, [sp, #568]
  // ModAdd Z3 = Z1 + one
  ldr x4, [sp, #64]
  ldr x9, [sp, #160]
  adds x4, x4, x9
  ldr x5, [sp, #72]
  ldr x9, [sp, #168]
  adcs x5, x5, x9
  ldr x6, [sp, #80]
  ldr x9, [sp, #176]
  adcs x6, x6, x9
  ldr x7, [sp, #88]
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
  str x16, [sp, #576]
  eor x16, x5, x11
  and x16, x16, x15
  eor x16, x11, x16
  str x16, [sp, #584]
  eor x16, x6, x12
  and x16, x16, x15
  eor x16, x12, x16
  str x16, [sp, #592]
  eor x16, x7, x13
  and x16, x16, x15
  eor x16, x13, x16
  str x16, [sp, #600]
  // sqr Z3 = Z3
  add x0, sp, #576
  add x1, sp, #576
  add x2, sp, #576
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
  // ModSub Z3 = Z3 - Z1Z1
  ldr x4, [sp, #576]
  ldr x9, [sp, #192]
  subs x4, x4, x9
  ldr x5, [sp, #584]
  ldr x9, [sp, #200]
  sbcs x5, x5, x9
  ldr x6, [sp, #592]
  ldr x9, [sp, #208]
  sbcs x6, x6, x9
  ldr x7, [sp, #600]
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
  str x4, [sp, #576]
  str x5, [sp, #584]
  str x6, [sp, #592]
  str x7, [sp, #600]
  // ModSub Z3 = Z3 - one
  ldr x4, [sp, #576]
  ldr x9, [sp, #160]
  subs x4, x4, x9
  ldr x5, [sp, #584]
  ldr x9, [sp, #168]
  sbcs x5, x5, x9
  ldr x6, [sp, #592]
  ldr x9, [sp, #176]
  sbcs x6, x6, x9
  ldr x7, [sp, #600]
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
  str x4, [sp, #576]
  str x5, [sp, #584]
  str x6, [sp, #592]
  str x7, [sp, #600]
  // mul Z3 = Z3 * H
  add x0, sp, #576
  add x1, sp, #576
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
  // infinity masks in1 (x13), in2 (x14)
  ldr x9, [sp, #64]
  ldr x10, [sp, #72]
  orr x9, x9, x10
  ldr x10, [sp, #80]
  orr x9, x9, x10
  ldr x10, [sp, #88]
  orr x9, x9, x10
  cmp x9, #0
  cset x13, eq
  neg x13, x13
  mov x14, xzr
  ldr x0, [sp, #608]
  // masked select X3 -> R
  ldr x4, [sp, #512]
  ldr x5, [sp, #0]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #96]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #0]
  ldr x4, [sp, #520]
  ldr x5, [sp, #8]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #104]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #8]
  ldr x4, [sp, #528]
  ldr x5, [sp, #16]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #112]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #16]
  ldr x4, [sp, #536]
  ldr x5, [sp, #24]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #120]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #24]
  // masked select Y3 -> R
  ldr x4, [sp, #544]
  ldr x5, [sp, #32]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #128]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #72]
  ldr x4, [sp, #552]
  ldr x5, [sp, #40]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #136]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #80]
  ldr x4, [sp, #560]
  ldr x5, [sp, #48]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #144]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #88]
  ldr x4, [sp, #568]
  ldr x5, [sp, #56]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #152]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #96]
  // masked select Z3 -> R
  ldr x4, [sp, #576]
  ldr x5, [sp, #64]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #160]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #144]
  ldr x4, [sp, #584]
  ldr x5, [sp, #72]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #168]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #152]
  ldr x4, [sp, #592]
  ldr x5, [sp, #80]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #176]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #160]
  ldr x4, [sp, #600]
  ldr x5, [sp, #88]
  and x5, x5, x14
  bic x4, x4, x14
  orr x4, x4, x5
  ldr x5, [sp, #184]
  and x5, x5, x13
  bic x4, x4, x13
  orr x4, x4, x5
  str x4, [x0, #168]
  // expose predicate operands H, RS
  ldr x16, [sp, #288]
  str x16, [x0, #216]
  ldr x16, [sp, #296]
  str x16, [x0, #224]
  ldr x16, [sp, #304]
  str x16, [x0, #232]
  ldr x16, [sp, #312]
  str x16, [x0, #240]
  ldr x16, [sp, #320]
  str x16, [x0, #288]
  ldr x16, [sp, #328]
  str x16, [x0, #296]
  ldr x16, [sp, #336]
  str x16, [x0, #304]
  ldr x16, [sp, #344]
  str x16, [x0, #312]
  add sp, sp, #624
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_FP_P256_JACPOINTDOUBLE, CRYPTOLIB_FP_P256_JACPOINTADD, CRYPTOLIB_FP_P256_JACPOINTADDMIXED must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
