// Prime-agnostic width-parametric modular-arithmetic kernels (AArch64).
// -------------------------------------------------------------------
//
// MontKernel family: schoolbook multiply/square, the CIOS Montgomery
// multiply (width-general and register-resident per width), and constant-
// time modular add/subtract. Prime-agnostic and width-parametric -- the
// curve-specific special-prime P-256 kernels live in the PointKernel family.
//
// One selector-driven file per arch; exactly one of the selectors listed in
// the {$FATAL} tail must be defined before including this file. PCtx =
// [n0', N, p[0..N-1]] with n0' = -p^-1 mod 2^64 (montmul); modadd/modsub take
// the same PCtx with n0' unused. (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//
// Constant-time: no data-dependent branches or memory addresses; the final
// conditional subtract is a masked select. Kernel bodies are byte-identical
// to the pre-decomposition FpKernel_<arch>.inc (shared emitter module).
{$IFDEF CRYPTOLIB_FP_MUL}
  // x0=X, x1=Y, x2=Z, x3=N
  lsl   x10, x3, #1                 // 2N
  mov   x5, xzr                     // k
.LFpMulZero:
  str   xzr, [x2, x5, lsl #3]
  add   x5, x5, #1
  cmp   x5, x10
  b.lo  .LFpMulZero
  mov   x4, xzr                     // i
.LFpMulRow:
  ldr   x6, [x0, x4, lsl #3]        // X[i]
  mov   x7, xzr                     // carry
  mov   x5, xzr                     // j
.LFpMulCol:
  ldr   x11, [x1, x5, lsl #3]       // Y[j]
  mul   x8, x6, x11                 // lo
  umulh x9, x6, x11                 // hi
  adds  x8, x8, x7                  // lo += carry
  adc   x9, x9, xzr
  add   x12, x4, x5                 // i+j
  ldr   x13, [x2, x12, lsl #3]
  adds  x8, x8, x13                 // lo += Z[i+j]
  adc   x9, x9, xzr
  str   x8, [x2, x12, lsl #3]
  mov   x7, x9                      // carry
  add   x5, x5, #1
  cmp   x5, x3
  b.lo  .LFpMulCol
  add   x12, x4, x3                 // i+N
  str   x7, [x2, x12, lsl #3]
  add   x4, x4, #1
  cmp   x4, x3
  b.lo  .LFpMulRow
{$ELSE}
  {$IFDEF CRYPTOLIB_FP_SQR}
  // x0=X, x1=Z, x2=N
  lsl   x10, x2, #1                 // 2N
  mov   x5, xzr
.LFpSqrZero:
  str   xzr, [x1, x5, lsl #3]
  add   x5, x5, #1
  cmp   x5, x10
  b.lo  .LFpSqrZero
  // phase 1: off-diagonal sum (i in 0..N-2, j in i+1..N-1)
  mov   x4, xzr                     // i
.LFpSqrP1Row:
  sub   x14, x2, #1                 // N-1
  cmp   x4, x14
  b.hs  .LFpSqrP1Done
  ldr   x6, [x0, x4, lsl #3]        // X[i]
  mov   x7, xzr                     // carry
  add   x5, x4, #1                  // j = i+1
.LFpSqrP1Col:
  ldr   x11, [x0, x5, lsl #3]       // X[j]
  mul   x8, x6, x11
  umulh x9, x6, x11
  adds  x8, x8, x7
  adc   x9, x9, xzr
  add   x12, x4, x5                 // i+j
  ldr   x13, [x1, x12, lsl #3]
  adds  x8, x8, x13
  adc   x9, x9, xzr
  str   x8, [x1, x12, lsl #3]
  mov   x7, x9
  add   x5, x5, #1
  cmp   x5, x2
  b.lo  .LFpSqrP1Col
  add   x12, x4, x2                 // i+N
  str   x7, [x1, x12, lsl #3]
  add   x4, x4, #1
  b     .LFpSqrP1Row
.LFpSqrP1Done:
  // phase 2: Z := 2*Z
  mov   x7, xzr                     // carry bit
  lsl   x10, x2, #1                 // 2N
  mov   x5, xzr
.LFpSqrP2:
  ldr   x8, [x1, x5, lsl #3]
  lsr   x9, x8, #63
  lsl   x8, x8, #1
  orr   x8, x8, x7
  str   x8, [x1, x5, lsl #3]
  mov   x7, x9
  add   x5, x5, #1
  cmp   x5, x10
  b.lo  .LFpSqrP2
  // phase 3: add diagonal X[i]^2 at position 2i
  mov   x7, xzr                     // carry-in word (0/1)
  mov   x4, xzr                     // i
.LFpSqrP3:
  ldr   x6, [x0, x4, lsl #3]
  mul   x8, x6, x6                  // lo
  umulh x9, x6, x6                  // hi
  lsl   x12, x4, #1                 // 2i
  ldr   x13, [x1, x12, lsl #3]
  mov   x14, xzr
  adds  x13, x13, x8
  adc   x14, x14, xzr
  adds  x13, x13, x7
  adc   x14, x14, xzr
  str   x13, [x1, x12, lsl #3]
  add   x15, x12, #1
  ldr   x13, [x1, x15, lsl #3]
  mov   x7, xzr
  adds  x13, x13, x9
  adc   x7, x7, xzr
  adds  x13, x13, x14
  adc   x7, x7, xzr
  str   x13, [x1, x15, lsl #3]
  add   x4, x4, #1
  cmp   x4, x2
  b.lo  .LFpSqrP3
  {$ELSE}
    {$IFDEF CRYPTOLIB_FP_MONTMUL}
  // x0=PR (N+2 scratch + result), x1=PA, x2=PB, x3=PCtx ([n0'@0, N@8, p@16]).
  // Width-general memory-resident CIOS Montgomery multiply (any N); single carry
  // chain (adds/adc); carry/borrow via adc/sbc with xzr.
  ldr   x4, [x3, #8]               // N
  add   x5, x4, #2                 // N+2
  mov   x6, xzr
.LFpMontZero:
  str   xzr, [x0, x6, lsl #3]      // t[0..N+1] = 0
  add   x6, x6, #1
  cmp   x6, x5
  b.lo  .LFpMontZero
  add   x17, x3, #16               // p base (const)
  mov   x7, xzr                    // i
.LFpMontRow:
  ldr   x8, [x2, x7, lsl #3]       // b[i]
  mov   x9, xzr                    // carry
  mov   x6, xzr                    // j
.LFpMontMul:
  ldr   x10, [x1, x6, lsl #3]      // a[j]
  mul   x11, x10, x8               // lo
  umulh x12, x10, x8               // hi
  adds  x11, x11, x9               // lo += carry
  adc   x12, x12, xzr
  ldr   x13, [x0, x6, lsl #3]      // t[j]
  adds  x11, x11, x13              // lo += t[j]
  adc   x12, x12, xzr
  str   x11, [x0, x6, lsl #3]
  mov   x9, x12                    // carry = hi
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpMontMul
  ldr   x13, [x0, x4, lsl #3]      // t[N]
  adds  x13, x13, x9
  str   x13, [x0, x4, lsl #3]
  adc   x15, xzr, xzr              // carry-out
  add   x14, x4, #1                // N+1
  str   x15, [x0, x14, lsl #3]     // t[N+1] = carry-out
  // reduce row: m = t[0]*n0'; t := (t + m*p) >> 64
  ldr   x16, [x3]                  // n0'
  ldr   x13, [x0]                  // t[0]
  mul   x16, x13, x16              // m
  ldr   x10, [x17]                 // p[0]
  mul   x11, x16, x10
  umulh x12, x16, x10
  ldr   x13, [x0]                  // t[0]
  adds  x11, x11, x13              // low limb discarded (== 0)
  adc   x12, x12, xzr
  mov   x9, x12                    // carry
  mov   x6, #1                     // j
.LFpMontRed:
  ldr   x10, [x17, x6, lsl #3]     // p[j]
  mul   x11, x16, x10
  umulh x12, x16, x10
  adds  x11, x11, x9
  adc   x12, x12, xzr
  ldr   x13, [x0, x6, lsl #3]      // t[j]
  adds  x11, x11, x13
  adc   x12, x12, xzr
  sub   x14, x6, #1                // j-1
  str   x11, [x0, x14, lsl #3]     // t[j-1]
  mov   x9, x12
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpMontRed
  ldr   x13, [x0, x4, lsl #3]      // t[N]
  adds  x13, x13, x9
  sub   x14, x4, #1                // N-1
  str   x13, [x0, x14, lsl #3]     // t[N-1]
  adc   x15, xzr, xzr
  add   x14, x4, #1                // N+1
  ldr   x13, [x0, x14, lsl #3]     // t[N+1]
  add   x13, x13, x15
  str   x13, [x0, x4, lsl #3]      // t[N] = t[N+1] + carry
  add   x7, x7, #1
  cmp   x7, x4
  b.lo  .LFpMontRow
  // constant-time final reduce: d := t - p in place; keep d if t>=p else restore t.
  mov   x9, xzr                    // borrow
  mov   x6, xzr                    // j
.LFpMontFSub:
  ldr   x10, [x0, x6, lsl #3]      // t[j]
  ldr   x13, [x17, x6, lsl #3]     // p[j]
  subs  x10, x10, x9               // - borrow
  sbc   x14, xzr, xzr              // -(borrow1)
  subs  x10, x10, x13              // - p[j]
  sbc   x15, xzr, xzr              // -(borrow2)
  str   x10, [x0, x6, lsl #3]
  add   x9, x14, x15               // -(borrow_out)
  neg   x9, x9                     // borrow_out (0/1)
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpMontFSub
  ldr   x10, [x0, x4, lsl #3]      // t[N] guard
  subs  x10, x10, x9
  sbc   x15, xzr, xzr              // mask = all-ones if t<p (restore), else 0
  mov   x9, xzr                    // carry
  mov   x6, xzr
.LFpMontFAdd:
  ldr   x13, [x17, x6, lsl #3]     // p[j]
  and   x13, x13, x15              // p[j] & mask
  ldr   x10, [x0, x6, lsl #3]      // diff
  adds  x10, x10, x13
  adc   x14, xzr, xzr              // carry1
  adds  x10, x10, x9               // + carry
  adc   x8,  xzr, xzr              // carry2
  str   x10, [x0, x6, lsl #3]
  add   x9, x14, x8                // carry_out (0/1)
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpMontFAdd
    {$ELSE}
      {$IFDEF CRYPTOLIB_FP_MONTMUL_REG4}
  ldp   x10, x11, [x1]
  ldp   x12, x13, [x1, #16]
  ldr   x14, [x2]
  mul   x4, x10, x14
  umulh x5, x10, x14
  mul   x15, x11, x14
  umulh x6, x11, x14
  mul   x16, x12, x14
  umulh x7, x12, x14
  mul   x17, x13, x14
  umulh x8, x13, x14
  adds  x5, x5, x15
  adcs  x6, x6, x16
  adcs  x7, x7, x17
  adc   x8, x8, xzr
  mov   x9, xzr
  ldr   x15, [x3]
  mul   x14, x4, x15
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  mul   x17, x14, x15
  adds  x4, x4, x17
  mul   x17, x14, x16
  adcs  x5, x5, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  mul   x17, x14, x15
  adcs  x6, x6, x17
  mul   x17, x14, x16
  adcs  x7, x7, x17
  adcs  x8, x8, xzr
  adc   x9, x9, xzr
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  umulh x17, x14, x15
  adds  x5, x5, x17
  umulh x17, x14, x16
  adcs  x6, x6, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  umulh x17, x14, x15
  adcs  x7, x7, x17
  umulh x17, x14, x16
  adcs  x8, x8, x17
  adc   x9, x9, xzr
  ldr   x14, [x2, #8]
  mul   x15, x10, x14
  mul   x16, x11, x14
  mul   x17, x12, x14
  adds  x5, x5, x15
  adcs  x6, x6, x16
  mul   x15, x13, x14
  adcs  x7, x7, x17
  adcs  x8, x8, x15
  adcs  x9, x9, xzr
  adc   x4, x4, xzr
  umulh x15, x10, x14
  umulh x16, x11, x14
  umulh x17, x12, x14
  adds  x6, x6, x15
  adcs  x7, x7, x16
  umulh x15, x13, x14
  adcs  x8, x8, x17
  adcs  x9, x9, x15
  adc   x4, x4, xzr
  ldr   x15, [x3]
  mul   x14, x5, x15
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  mul   x17, x14, x15
  adds  x5, x5, x17
  mul   x17, x14, x16
  adcs  x6, x6, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  mul   x17, x14, x15
  adcs  x7, x7, x17
  mul   x17, x14, x16
  adcs  x8, x8, x17
  adcs  x9, x9, xzr
  adc   x4, x4, xzr
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  umulh x17, x14, x15
  adds  x6, x6, x17
  umulh x17, x14, x16
  adcs  x7, x7, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  umulh x17, x14, x15
  adcs  x8, x8, x17
  umulh x17, x14, x16
  adcs  x9, x9, x17
  adc   x4, x4, xzr
  ldr   x14, [x2, #16]
  mul   x15, x10, x14
  mul   x16, x11, x14
  mul   x17, x12, x14
  adds  x6, x6, x15
  adcs  x7, x7, x16
  mul   x15, x13, x14
  adcs  x8, x8, x17
  adcs  x9, x9, x15
  adcs  x4, x4, xzr
  adc   x5, x5, xzr
  umulh x15, x10, x14
  umulh x16, x11, x14
  umulh x17, x12, x14
  adds  x7, x7, x15
  adcs  x8, x8, x16
  umulh x15, x13, x14
  adcs  x9, x9, x17
  adcs  x4, x4, x15
  adc   x5, x5, xzr
  ldr   x15, [x3]
  mul   x14, x6, x15
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  mul   x17, x14, x15
  adds  x6, x6, x17
  mul   x17, x14, x16
  adcs  x7, x7, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  mul   x17, x14, x15
  adcs  x8, x8, x17
  mul   x17, x14, x16
  adcs  x9, x9, x17
  adcs  x4, x4, xzr
  adc   x5, x5, xzr
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  umulh x17, x14, x15
  adds  x7, x7, x17
  umulh x17, x14, x16
  adcs  x8, x8, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  umulh x17, x14, x15
  adcs  x9, x9, x17
  umulh x17, x14, x16
  adcs  x4, x4, x17
  adc   x5, x5, xzr
  ldr   x14, [x2, #24]
  mul   x15, x10, x14
  mul   x16, x11, x14
  mul   x17, x12, x14
  adds  x7, x7, x15
  adcs  x8, x8, x16
  mul   x15, x13, x14
  adcs  x9, x9, x17
  adcs  x4, x4, x15
  adcs  x5, x5, xzr
  adc   x6, x6, xzr
  umulh x15, x10, x14
  umulh x16, x11, x14
  umulh x17, x12, x14
  adds  x8, x8, x15
  adcs  x9, x9, x16
  umulh x15, x13, x14
  adcs  x4, x4, x17
  adcs  x5, x5, x15
  adc   x6, x6, xzr
  ldr   x15, [x3]
  mul   x14, x7, x15
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  mul   x17, x14, x15
  adds  x7, x7, x17
  mul   x17, x14, x16
  adcs  x8, x8, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  mul   x17, x14, x15
  adcs  x9, x9, x17
  mul   x17, x14, x16
  adcs  x4, x4, x17
  adcs  x5, x5, xzr
  adc   x6, x6, xzr
  ldr   x15, [x3, #16]
  ldr   x16, [x3, #24]
  umulh x17, x14, x15
  adds  x8, x8, x17
  umulh x17, x14, x16
  adcs  x9, x9, x17
  ldr   x15, [x3, #32]
  ldr   x16, [x3, #40]
  umulh x17, x14, x15
  adcs  x4, x4, x17
  umulh x17, x14, x16
  adcs  x5, x5, x17
  adc   x6, x6, xzr
  ldp   x10, x11, [x3, #16]
  ldp   x12, x13, [x3, #32]
  subs  x14, x8, x10
  sbcs  x15, x9, x11
  sbcs  x16, x4, x12
  sbcs  x17, x5, x13
  sbcs  xzr, x6, xzr
  sbc   x6, xzr, xzr
  and   x10, x10, x6
  and   x11, x11, x6
  and   x12, x12, x6
  and   x13, x13, x6
  adds  x14, x14, x10
  adcs  x15, x15, x11
  adcs  x16, x16, x12
  adc   x17, x17, x13
  stp   x14, x15, [x0]
  stp   x16, x17, [x0, #16]
      {$ELSE}
        {$IFDEF CRYPTOLIB_FP_MONTMUL_REG5}
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  mov  x10, xzr
  ldr  x11, [x2, #0]
  mov  x12, xzr
  ldr  x16, [x1, #0]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x4, x4, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #8]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x5, x5, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #16]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x6, x6, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #24]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x7, x7, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #32]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x8, x8, x14
  adc  x12, x15, xzr
  adds x9, x9, x12
  adc  x10, xzr, xzr
  ldr  x13, [x3]
  mul  x13, x4, x13
  ldr  x16, [x3, #16]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x4
  adc  x12, x15, xzr
  ldr  x16, [x3, #24]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x5
  adc  x12, x15, xzr
  mov  x4, x14
  ldr  x16, [x3, #32]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x6
  adc  x12, x15, xzr
  mov  x5, x14
  ldr  x16, [x3, #40]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x7
  adc  x12, x15, xzr
  mov  x6, x14
  ldr  x16, [x3, #48]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x8
  adc  x12, x15, xzr
  mov  x7, x14
  adds x14, x9, x12
  mov  x8, x14
  adc  x12, xzr, xzr
  add  x9, x10, x12
  ldr  x11, [x2, #8]
  mov  x12, xzr
  ldr  x16, [x1, #0]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x4, x4, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #8]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x5, x5, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #16]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x6, x6, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #24]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x7, x7, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #32]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x8, x8, x14
  adc  x12, x15, xzr
  adds x9, x9, x12
  adc  x10, xzr, xzr
  ldr  x13, [x3]
  mul  x13, x4, x13
  ldr  x16, [x3, #16]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x4
  adc  x12, x15, xzr
  ldr  x16, [x3, #24]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x5
  adc  x12, x15, xzr
  mov  x4, x14
  ldr  x16, [x3, #32]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x6
  adc  x12, x15, xzr
  mov  x5, x14
  ldr  x16, [x3, #40]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x7
  adc  x12, x15, xzr
  mov  x6, x14
  ldr  x16, [x3, #48]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x8
  adc  x12, x15, xzr
  mov  x7, x14
  adds x14, x9, x12
  mov  x8, x14
  adc  x12, xzr, xzr
  add  x9, x10, x12
  ldr  x11, [x2, #16]
  mov  x12, xzr
  ldr  x16, [x1, #0]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x4, x4, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #8]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x5, x5, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #16]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x6, x6, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #24]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x7, x7, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #32]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x8, x8, x14
  adc  x12, x15, xzr
  adds x9, x9, x12
  adc  x10, xzr, xzr
  ldr  x13, [x3]
  mul  x13, x4, x13
  ldr  x16, [x3, #16]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x4
  adc  x12, x15, xzr
  ldr  x16, [x3, #24]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x5
  adc  x12, x15, xzr
  mov  x4, x14
  ldr  x16, [x3, #32]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x6
  adc  x12, x15, xzr
  mov  x5, x14
  ldr  x16, [x3, #40]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x7
  adc  x12, x15, xzr
  mov  x6, x14
  ldr  x16, [x3, #48]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x8
  adc  x12, x15, xzr
  mov  x7, x14
  adds x14, x9, x12
  mov  x8, x14
  adc  x12, xzr, xzr
  add  x9, x10, x12
  ldr  x11, [x2, #24]
  mov  x12, xzr
  ldr  x16, [x1, #0]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x4, x4, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #8]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x5, x5, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #16]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x6, x6, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #24]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x7, x7, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #32]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x8, x8, x14
  adc  x12, x15, xzr
  adds x9, x9, x12
  adc  x10, xzr, xzr
  ldr  x13, [x3]
  mul  x13, x4, x13
  ldr  x16, [x3, #16]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x4
  adc  x12, x15, xzr
  ldr  x16, [x3, #24]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x5
  adc  x12, x15, xzr
  mov  x4, x14
  ldr  x16, [x3, #32]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x6
  adc  x12, x15, xzr
  mov  x5, x14
  ldr  x16, [x3, #40]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x7
  adc  x12, x15, xzr
  mov  x6, x14
  ldr  x16, [x3, #48]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x8
  adc  x12, x15, xzr
  mov  x7, x14
  adds x14, x9, x12
  mov  x8, x14
  adc  x12, xzr, xzr
  add  x9, x10, x12
  ldr  x11, [x2, #32]
  mov  x12, xzr
  ldr  x16, [x1, #0]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x4, x4, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #8]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x5, x5, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #16]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x6, x6, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #24]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x7, x7, x14
  adc  x12, x15, xzr
  ldr  x16, [x1, #32]
  mul  x14, x16, x11
  umulh x15, x16, x11
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x8, x8, x14
  adc  x12, x15, xzr
  adds x9, x9, x12
  adc  x10, xzr, xzr
  ldr  x13, [x3]
  mul  x13, x4, x13
  ldr  x16, [x3, #16]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x4
  adc  x12, x15, xzr
  ldr  x16, [x3, #24]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x5
  adc  x12, x15, xzr
  mov  x4, x14
  ldr  x16, [x3, #32]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x6
  adc  x12, x15, xzr
  mov  x5, x14
  ldr  x16, [x3, #40]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x7
  adc  x12, x15, xzr
  mov  x6, x14
  ldr  x16, [x3, #48]
  mul  x14, x13, x16
  umulh x15, x13, x16
  adds x14, x14, x12
  adc  x15, x15, xzr
  adds x14, x14, x8
  adc  x12, x15, xzr
  mov  x7, x14
  adds x14, x9, x12
  mov  x8, x14
  adc  x12, xzr, xzr
  add  x9, x10, x12
  mov  x12, xzr
  ldr  x16, [x3, #16]
  subs x14, x4, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  ldr  x16, [x3, #24]
  subs x14, x5, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  ldr  x16, [x3, #32]
  subs x14, x6, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  ldr  x16, [x3, #40]
  subs x14, x7, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  ldr  x16, [x3, #48]
  subs x14, x8, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  subs x14, x9, x12
  adc  x13, xzr, xzr
  neg  x13, x13
  mov  x12, xzr
  ldr  x16, [x3, #16]
  and  x16, x16, x13
  subs x14, x4, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  str  x14, [x0, #0]
  ldr  x16, [x3, #24]
  and  x16, x16, x13
  subs x14, x5, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  str  x14, [x0, #8]
  ldr  x16, [x3, #32]
  and  x16, x16, x13
  subs x14, x6, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  str  x14, [x0, #16]
  ldr  x16, [x3, #40]
  and  x16, x16, x13
  subs x14, x7, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  str  x14, [x0, #24]
  ldr  x16, [x3, #48]
  and  x16, x16, x13
  subs x14, x8, x12
  sbc  x15, xzr, xzr
  subs x14, x14, x16
  sbc  x11, xzr, xzr
  add  x12, x15, x11
  neg  x12, x12
  str  x14, [x0, #32]
        {$ELSE}
          {$IFDEF CRYPTOLIB_FP_MONTMUL_REG6}
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  mov  x10, xzr
  mov  x11, xzr
  ldr  x12, [x2, #0]
  mov  x13, xzr
  ldr  x17, [x1, #0]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x4, x4, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #8]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x5, x5, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #16]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x6, x6, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #24]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x7, x7, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #32]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x8, x8, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #40]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x9, x9, x15
  adc  x13, x16, xzr
  adds x10, x10, x13
  adc  x11, xzr, xzr
  ldr  x14, [x3]
  mul  x14, x4, x14
  ldr  x17, [x3, #16]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x4
  adc  x13, x16, xzr
  ldr  x17, [x3, #24]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x5
  adc  x13, x16, xzr
  mov  x4, x15
  ldr  x17, [x3, #32]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x6
  adc  x13, x16, xzr
  mov  x5, x15
  ldr  x17, [x3, #40]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x7
  adc  x13, x16, xzr
  mov  x6, x15
  ldr  x17, [x3, #48]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x8
  adc  x13, x16, xzr
  mov  x7, x15
  ldr  x17, [x3, #56]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x9
  adc  x13, x16, xzr
  mov  x8, x15
  adds x15, x10, x13
  mov  x9, x15
  adc  x13, xzr, xzr
  add  x10, x11, x13
  ldr  x12, [x2, #8]
  mov  x13, xzr
  ldr  x17, [x1, #0]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x4, x4, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #8]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x5, x5, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #16]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x6, x6, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #24]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x7, x7, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #32]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x8, x8, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #40]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x9, x9, x15
  adc  x13, x16, xzr
  adds x10, x10, x13
  adc  x11, xzr, xzr
  ldr  x14, [x3]
  mul  x14, x4, x14
  ldr  x17, [x3, #16]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x4
  adc  x13, x16, xzr
  ldr  x17, [x3, #24]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x5
  adc  x13, x16, xzr
  mov  x4, x15
  ldr  x17, [x3, #32]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x6
  adc  x13, x16, xzr
  mov  x5, x15
  ldr  x17, [x3, #40]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x7
  adc  x13, x16, xzr
  mov  x6, x15
  ldr  x17, [x3, #48]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x8
  adc  x13, x16, xzr
  mov  x7, x15
  ldr  x17, [x3, #56]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x9
  adc  x13, x16, xzr
  mov  x8, x15
  adds x15, x10, x13
  mov  x9, x15
  adc  x13, xzr, xzr
  add  x10, x11, x13
  ldr  x12, [x2, #16]
  mov  x13, xzr
  ldr  x17, [x1, #0]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x4, x4, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #8]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x5, x5, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #16]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x6, x6, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #24]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x7, x7, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #32]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x8, x8, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #40]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x9, x9, x15
  adc  x13, x16, xzr
  adds x10, x10, x13
  adc  x11, xzr, xzr
  ldr  x14, [x3]
  mul  x14, x4, x14
  ldr  x17, [x3, #16]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x4
  adc  x13, x16, xzr
  ldr  x17, [x3, #24]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x5
  adc  x13, x16, xzr
  mov  x4, x15
  ldr  x17, [x3, #32]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x6
  adc  x13, x16, xzr
  mov  x5, x15
  ldr  x17, [x3, #40]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x7
  adc  x13, x16, xzr
  mov  x6, x15
  ldr  x17, [x3, #48]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x8
  adc  x13, x16, xzr
  mov  x7, x15
  ldr  x17, [x3, #56]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x9
  adc  x13, x16, xzr
  mov  x8, x15
  adds x15, x10, x13
  mov  x9, x15
  adc  x13, xzr, xzr
  add  x10, x11, x13
  ldr  x12, [x2, #24]
  mov  x13, xzr
  ldr  x17, [x1, #0]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x4, x4, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #8]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x5, x5, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #16]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x6, x6, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #24]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x7, x7, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #32]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x8, x8, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #40]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x9, x9, x15
  adc  x13, x16, xzr
  adds x10, x10, x13
  adc  x11, xzr, xzr
  ldr  x14, [x3]
  mul  x14, x4, x14
  ldr  x17, [x3, #16]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x4
  adc  x13, x16, xzr
  ldr  x17, [x3, #24]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x5
  adc  x13, x16, xzr
  mov  x4, x15
  ldr  x17, [x3, #32]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x6
  adc  x13, x16, xzr
  mov  x5, x15
  ldr  x17, [x3, #40]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x7
  adc  x13, x16, xzr
  mov  x6, x15
  ldr  x17, [x3, #48]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x8
  adc  x13, x16, xzr
  mov  x7, x15
  ldr  x17, [x3, #56]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x9
  adc  x13, x16, xzr
  mov  x8, x15
  adds x15, x10, x13
  mov  x9, x15
  adc  x13, xzr, xzr
  add  x10, x11, x13
  ldr  x12, [x2, #32]
  mov  x13, xzr
  ldr  x17, [x1, #0]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x4, x4, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #8]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x5, x5, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #16]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x6, x6, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #24]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x7, x7, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #32]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x8, x8, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #40]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x9, x9, x15
  adc  x13, x16, xzr
  adds x10, x10, x13
  adc  x11, xzr, xzr
  ldr  x14, [x3]
  mul  x14, x4, x14
  ldr  x17, [x3, #16]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x4
  adc  x13, x16, xzr
  ldr  x17, [x3, #24]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x5
  adc  x13, x16, xzr
  mov  x4, x15
  ldr  x17, [x3, #32]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x6
  adc  x13, x16, xzr
  mov  x5, x15
  ldr  x17, [x3, #40]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x7
  adc  x13, x16, xzr
  mov  x6, x15
  ldr  x17, [x3, #48]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x8
  adc  x13, x16, xzr
  mov  x7, x15
  ldr  x17, [x3, #56]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x9
  adc  x13, x16, xzr
  mov  x8, x15
  adds x15, x10, x13
  mov  x9, x15
  adc  x13, xzr, xzr
  add  x10, x11, x13
  ldr  x12, [x2, #40]
  mov  x13, xzr
  ldr  x17, [x1, #0]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x4, x4, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #8]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x5, x5, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #16]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x6, x6, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #24]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x7, x7, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #32]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x8, x8, x15
  adc  x13, x16, xzr
  ldr  x17, [x1, #40]
  mul  x15, x17, x12
  umulh x16, x17, x12
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x9, x9, x15
  adc  x13, x16, xzr
  adds x10, x10, x13
  adc  x11, xzr, xzr
  ldr  x14, [x3]
  mul  x14, x4, x14
  ldr  x17, [x3, #16]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x4
  adc  x13, x16, xzr
  ldr  x17, [x3, #24]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x5
  adc  x13, x16, xzr
  mov  x4, x15
  ldr  x17, [x3, #32]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x6
  adc  x13, x16, xzr
  mov  x5, x15
  ldr  x17, [x3, #40]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x7
  adc  x13, x16, xzr
  mov  x6, x15
  ldr  x17, [x3, #48]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x8
  adc  x13, x16, xzr
  mov  x7, x15
  ldr  x17, [x3, #56]
  mul  x15, x14, x17
  umulh x16, x14, x17
  adds x15, x15, x13
  adc  x16, x16, xzr
  adds x15, x15, x9
  adc  x13, x16, xzr
  mov  x8, x15
  adds x15, x10, x13
  mov  x9, x15
  adc  x13, xzr, xzr
  add  x10, x11, x13
  mov  x13, xzr
  ldr  x17, [x3, #16]
  subs x15, x4, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  ldr  x17, [x3, #24]
  subs x15, x5, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  ldr  x17, [x3, #32]
  subs x15, x6, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  ldr  x17, [x3, #40]
  subs x15, x7, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  ldr  x17, [x3, #48]
  subs x15, x8, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  ldr  x17, [x3, #56]
  subs x15, x9, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  subs x15, x10, x13
  adc  x14, xzr, xzr
  neg  x14, x14
  mov  x13, xzr
  ldr  x17, [x3, #16]
  and  x17, x17, x14
  subs x15, x4, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  str  x15, [x0, #0]
  ldr  x17, [x3, #24]
  and  x17, x17, x14
  subs x15, x5, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  str  x15, [x0, #8]
  ldr  x17, [x3, #32]
  and  x17, x17, x14
  subs x15, x6, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  str  x15, [x0, #16]
  ldr  x17, [x3, #40]
  and  x17, x17, x14
  subs x15, x7, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  str  x15, [x0, #24]
  ldr  x17, [x3, #48]
  and  x17, x17, x14
  subs x15, x8, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  str  x15, [x0, #32]
  ldr  x17, [x3, #56]
  and  x17, x17, x14
  subs x15, x9, x13
  sbc  x16, xzr, xzr
  subs x15, x15, x17
  sbc  x12, xzr, xzr
  add  x13, x16, x12
  neg  x13, x13
  str  x15, [x0, #40]
          {$ELSE}
            {$IFDEF CRYPTOLIB_FP_MONTMUL_REG7}
  sub  sp, sp, #16
  str  x19, [sp, #0]
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  mov  x10, xzr
  mov  x11, xzr
  mov  x12, xzr
  ldr  x13, [x2, #0]
  mov  x14, xzr
  ldr  x19, [x1, #0]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x4, x4, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #8]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x5, x5, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #16]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x6, x6, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #24]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x7, x7, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #32]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x8, x8, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #40]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x9, x9, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #48]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x10, x10, x16
  adc  x14, x17, xzr
  adds x11, x11, x14
  adc  x12, xzr, xzr
  ldr  x15, [x3]
  mul  x15, x4, x15
  ldr  x19, [x3, #16]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x4
  adc  x14, x17, xzr
  ldr  x19, [x3, #24]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x5
  adc  x14, x17, xzr
  mov  x4, x16
  ldr  x19, [x3, #32]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x6
  adc  x14, x17, xzr
  mov  x5, x16
  ldr  x19, [x3, #40]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x7
  adc  x14, x17, xzr
  mov  x6, x16
  ldr  x19, [x3, #48]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x8
  adc  x14, x17, xzr
  mov  x7, x16
  ldr  x19, [x3, #56]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x9
  adc  x14, x17, xzr
  mov  x8, x16
  ldr  x19, [x3, #64]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x10
  adc  x14, x17, xzr
  mov  x9, x16
  adds x16, x11, x14
  mov  x10, x16
  adc  x14, xzr, xzr
  add  x11, x12, x14
  ldr  x13, [x2, #8]
  mov  x14, xzr
  ldr  x19, [x1, #0]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x4, x4, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #8]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x5, x5, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #16]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x6, x6, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #24]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x7, x7, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #32]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x8, x8, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #40]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x9, x9, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #48]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x10, x10, x16
  adc  x14, x17, xzr
  adds x11, x11, x14
  adc  x12, xzr, xzr
  ldr  x15, [x3]
  mul  x15, x4, x15
  ldr  x19, [x3, #16]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x4
  adc  x14, x17, xzr
  ldr  x19, [x3, #24]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x5
  adc  x14, x17, xzr
  mov  x4, x16
  ldr  x19, [x3, #32]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x6
  adc  x14, x17, xzr
  mov  x5, x16
  ldr  x19, [x3, #40]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x7
  adc  x14, x17, xzr
  mov  x6, x16
  ldr  x19, [x3, #48]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x8
  adc  x14, x17, xzr
  mov  x7, x16
  ldr  x19, [x3, #56]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x9
  adc  x14, x17, xzr
  mov  x8, x16
  ldr  x19, [x3, #64]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x10
  adc  x14, x17, xzr
  mov  x9, x16
  adds x16, x11, x14
  mov  x10, x16
  adc  x14, xzr, xzr
  add  x11, x12, x14
  ldr  x13, [x2, #16]
  mov  x14, xzr
  ldr  x19, [x1, #0]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x4, x4, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #8]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x5, x5, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #16]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x6, x6, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #24]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x7, x7, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #32]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x8, x8, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #40]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x9, x9, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #48]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x10, x10, x16
  adc  x14, x17, xzr
  adds x11, x11, x14
  adc  x12, xzr, xzr
  ldr  x15, [x3]
  mul  x15, x4, x15
  ldr  x19, [x3, #16]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x4
  adc  x14, x17, xzr
  ldr  x19, [x3, #24]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x5
  adc  x14, x17, xzr
  mov  x4, x16
  ldr  x19, [x3, #32]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x6
  adc  x14, x17, xzr
  mov  x5, x16
  ldr  x19, [x3, #40]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x7
  adc  x14, x17, xzr
  mov  x6, x16
  ldr  x19, [x3, #48]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x8
  adc  x14, x17, xzr
  mov  x7, x16
  ldr  x19, [x3, #56]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x9
  adc  x14, x17, xzr
  mov  x8, x16
  ldr  x19, [x3, #64]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x10
  adc  x14, x17, xzr
  mov  x9, x16
  adds x16, x11, x14
  mov  x10, x16
  adc  x14, xzr, xzr
  add  x11, x12, x14
  ldr  x13, [x2, #24]
  mov  x14, xzr
  ldr  x19, [x1, #0]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x4, x4, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #8]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x5, x5, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #16]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x6, x6, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #24]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x7, x7, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #32]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x8, x8, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #40]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x9, x9, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #48]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x10, x10, x16
  adc  x14, x17, xzr
  adds x11, x11, x14
  adc  x12, xzr, xzr
  ldr  x15, [x3]
  mul  x15, x4, x15
  ldr  x19, [x3, #16]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x4
  adc  x14, x17, xzr
  ldr  x19, [x3, #24]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x5
  adc  x14, x17, xzr
  mov  x4, x16
  ldr  x19, [x3, #32]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x6
  adc  x14, x17, xzr
  mov  x5, x16
  ldr  x19, [x3, #40]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x7
  adc  x14, x17, xzr
  mov  x6, x16
  ldr  x19, [x3, #48]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x8
  adc  x14, x17, xzr
  mov  x7, x16
  ldr  x19, [x3, #56]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x9
  adc  x14, x17, xzr
  mov  x8, x16
  ldr  x19, [x3, #64]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x10
  adc  x14, x17, xzr
  mov  x9, x16
  adds x16, x11, x14
  mov  x10, x16
  adc  x14, xzr, xzr
  add  x11, x12, x14
  ldr  x13, [x2, #32]
  mov  x14, xzr
  ldr  x19, [x1, #0]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x4, x4, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #8]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x5, x5, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #16]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x6, x6, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #24]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x7, x7, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #32]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x8, x8, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #40]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x9, x9, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #48]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x10, x10, x16
  adc  x14, x17, xzr
  adds x11, x11, x14
  adc  x12, xzr, xzr
  ldr  x15, [x3]
  mul  x15, x4, x15
  ldr  x19, [x3, #16]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x4
  adc  x14, x17, xzr
  ldr  x19, [x3, #24]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x5
  adc  x14, x17, xzr
  mov  x4, x16
  ldr  x19, [x3, #32]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x6
  adc  x14, x17, xzr
  mov  x5, x16
  ldr  x19, [x3, #40]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x7
  adc  x14, x17, xzr
  mov  x6, x16
  ldr  x19, [x3, #48]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x8
  adc  x14, x17, xzr
  mov  x7, x16
  ldr  x19, [x3, #56]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x9
  adc  x14, x17, xzr
  mov  x8, x16
  ldr  x19, [x3, #64]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x10
  adc  x14, x17, xzr
  mov  x9, x16
  adds x16, x11, x14
  mov  x10, x16
  adc  x14, xzr, xzr
  add  x11, x12, x14
  ldr  x13, [x2, #40]
  mov  x14, xzr
  ldr  x19, [x1, #0]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x4, x4, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #8]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x5, x5, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #16]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x6, x6, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #24]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x7, x7, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #32]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x8, x8, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #40]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x9, x9, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #48]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x10, x10, x16
  adc  x14, x17, xzr
  adds x11, x11, x14
  adc  x12, xzr, xzr
  ldr  x15, [x3]
  mul  x15, x4, x15
  ldr  x19, [x3, #16]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x4
  adc  x14, x17, xzr
  ldr  x19, [x3, #24]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x5
  adc  x14, x17, xzr
  mov  x4, x16
  ldr  x19, [x3, #32]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x6
  adc  x14, x17, xzr
  mov  x5, x16
  ldr  x19, [x3, #40]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x7
  adc  x14, x17, xzr
  mov  x6, x16
  ldr  x19, [x3, #48]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x8
  adc  x14, x17, xzr
  mov  x7, x16
  ldr  x19, [x3, #56]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x9
  adc  x14, x17, xzr
  mov  x8, x16
  ldr  x19, [x3, #64]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x10
  adc  x14, x17, xzr
  mov  x9, x16
  adds x16, x11, x14
  mov  x10, x16
  adc  x14, xzr, xzr
  add  x11, x12, x14
  ldr  x13, [x2, #48]
  mov  x14, xzr
  ldr  x19, [x1, #0]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x4, x4, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #8]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x5, x5, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #16]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x6, x6, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #24]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x7, x7, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #32]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x8, x8, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #40]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x9, x9, x16
  adc  x14, x17, xzr
  ldr  x19, [x1, #48]
  mul  x16, x19, x13
  umulh x17, x19, x13
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x10, x10, x16
  adc  x14, x17, xzr
  adds x11, x11, x14
  adc  x12, xzr, xzr
  ldr  x15, [x3]
  mul  x15, x4, x15
  ldr  x19, [x3, #16]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x4
  adc  x14, x17, xzr
  ldr  x19, [x3, #24]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x5
  adc  x14, x17, xzr
  mov  x4, x16
  ldr  x19, [x3, #32]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x6
  adc  x14, x17, xzr
  mov  x5, x16
  ldr  x19, [x3, #40]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x7
  adc  x14, x17, xzr
  mov  x6, x16
  ldr  x19, [x3, #48]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x8
  adc  x14, x17, xzr
  mov  x7, x16
  ldr  x19, [x3, #56]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x9
  adc  x14, x17, xzr
  mov  x8, x16
  ldr  x19, [x3, #64]
  mul  x16, x15, x19
  umulh x17, x15, x19
  adds x16, x16, x14
  adc  x17, x17, xzr
  adds x16, x16, x10
  adc  x14, x17, xzr
  mov  x9, x16
  adds x16, x11, x14
  mov  x10, x16
  adc  x14, xzr, xzr
  add  x11, x12, x14
  mov  x14, xzr
  ldr  x19, [x3, #16]
  subs x16, x4, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  ldr  x19, [x3, #24]
  subs x16, x5, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  ldr  x19, [x3, #32]
  subs x16, x6, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  ldr  x19, [x3, #40]
  subs x16, x7, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  ldr  x19, [x3, #48]
  subs x16, x8, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  ldr  x19, [x3, #56]
  subs x16, x9, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  ldr  x19, [x3, #64]
  subs x16, x10, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  subs x16, x11, x14
  adc  x15, xzr, xzr
  neg  x15, x15
  mov  x14, xzr
  ldr  x19, [x3, #16]
  and  x19, x19, x15
  subs x16, x4, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  str  x16, [x0, #0]
  ldr  x19, [x3, #24]
  and  x19, x19, x15
  subs x16, x5, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  str  x16, [x0, #8]
  ldr  x19, [x3, #32]
  and  x19, x19, x15
  subs x16, x6, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  str  x16, [x0, #16]
  ldr  x19, [x3, #40]
  and  x19, x19, x15
  subs x16, x7, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  str  x16, [x0, #24]
  ldr  x19, [x3, #48]
  and  x19, x19, x15
  subs x16, x8, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  str  x16, [x0, #32]
  ldr  x19, [x3, #56]
  and  x19, x19, x15
  subs x16, x9, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  str  x16, [x0, #40]
  ldr  x19, [x3, #64]
  and  x19, x19, x15
  subs x16, x10, x14
  sbc  x17, xzr, xzr
  subs x16, x16, x19
  sbc  x13, xzr, xzr
  add  x14, x17, x13
  neg  x14, x14
  str  x16, [x0, #48]
  ldr  x19, [sp, #0]
  add  sp, sp, #16
            {$ELSE}
              {$IFDEF CRYPTOLIB_FP_MONTMUL_REG8}
  sub  sp, sp, #16
  stp  x19, x20, [sp, #0]
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  mov  x10, xzr
  mov  x11, xzr
  mov  x12, xzr
  mov  x13, xzr
  ldr  x14, [x2, #0]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  ldr  x14, [x2, #8]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  ldr  x14, [x2, #16]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  ldr  x14, [x2, #24]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  ldr  x14, [x2, #32]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  ldr  x14, [x2, #40]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  ldr  x14, [x2, #48]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  ldr  x14, [x2, #56]
  mov  x15, xzr
  ldr  x20, [x1, #0]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x4, x4, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #8]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x5, x5, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #16]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x6, x6, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #24]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x7, x7, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #32]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x8, x8, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #40]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x9, x9, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #48]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x10, x10, x17
  adc  x15, x19, xzr
  ldr  x20, [x1, #56]
  mul  x17, x20, x14
  umulh x19, x20, x14
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x11, x11, x17
  adc  x15, x19, xzr
  adds x12, x12, x15
  adc  x13, xzr, xzr
  ldr  x16, [x3]
  mul  x16, x4, x16
  ldr  x20, [x3, #16]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x4
  adc  x15, x19, xzr
  ldr  x20, [x3, #24]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x5
  adc  x15, x19, xzr
  mov  x4, x17
  ldr  x20, [x3, #32]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x6
  adc  x15, x19, xzr
  mov  x5, x17
  ldr  x20, [x3, #40]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x7
  adc  x15, x19, xzr
  mov  x6, x17
  ldr  x20, [x3, #48]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x8
  adc  x15, x19, xzr
  mov  x7, x17
  ldr  x20, [x3, #56]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x9
  adc  x15, x19, xzr
  mov  x8, x17
  ldr  x20, [x3, #64]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x10
  adc  x15, x19, xzr
  mov  x9, x17
  ldr  x20, [x3, #72]
  mul  x17, x16, x20
  umulh x19, x16, x20
  adds x17, x17, x15
  adc  x19, x19, xzr
  adds x17, x17, x11
  adc  x15, x19, xzr
  mov  x10, x17
  adds x17, x12, x15
  mov  x11, x17
  adc  x15, xzr, xzr
  add  x12, x13, x15
  mov  x15, xzr
  ldr  x20, [x3, #16]
  subs x17, x4, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  ldr  x20, [x3, #24]
  subs x17, x5, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  ldr  x20, [x3, #32]
  subs x17, x6, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  ldr  x20, [x3, #40]
  subs x17, x7, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  ldr  x20, [x3, #48]
  subs x17, x8, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  ldr  x20, [x3, #56]
  subs x17, x9, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  ldr  x20, [x3, #64]
  subs x17, x10, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  ldr  x20, [x3, #72]
  subs x17, x11, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  subs x17, x12, x15
  adc  x16, xzr, xzr
  neg  x16, x16
  mov  x15, xzr
  ldr  x20, [x3, #16]
  and  x20, x20, x16
  subs x17, x4, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #0]
  ldr  x20, [x3, #24]
  and  x20, x20, x16
  subs x17, x5, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #8]
  ldr  x20, [x3, #32]
  and  x20, x20, x16
  subs x17, x6, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #16]
  ldr  x20, [x3, #40]
  and  x20, x20, x16
  subs x17, x7, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #24]
  ldr  x20, [x3, #48]
  and  x20, x20, x16
  subs x17, x8, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #32]
  ldr  x20, [x3, #56]
  and  x20, x20, x16
  subs x17, x9, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #40]
  ldr  x20, [x3, #64]
  and  x20, x20, x16
  subs x17, x10, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #48]
  ldr  x20, [x3, #72]
  and  x20, x20, x16
  subs x17, x11, x15
  sbc  x19, xzr, xzr
  subs x17, x17, x20
  sbc  x14, xzr, xzr
  add  x15, x19, x14
  neg  x15, x15
  str  x17, [x0, #56]
  ldp  x19, x20, [sp, #0]
  add  sp, sp, #16
              {$ELSE}
                {$IFDEF CRYPTOLIB_FP_MONTMUL_REG9}
  sub  sp, sp, #32
  stp  x19, x20, [sp, #0]
  str  x21, [sp, #16]
  mov  x4, xzr
  mov  x5, xzr
  mov  x6, xzr
  mov  x7, xzr
  mov  x8, xzr
  mov  x9, xzr
  mov  x10, xzr
  mov  x11, xzr
  mov  x12, xzr
  mov  x13, xzr
  mov  x14, xzr
  ldr  x15, [x2, #0]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #8]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #16]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #24]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #32]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #40]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #48]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #56]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  ldr  x15, [x2, #64]
  mov  x16, xzr
  ldr  x21, [x1, #0]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x4, x4, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #8]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x5, x5, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #16]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x6, x6, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #24]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x7, x7, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #32]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x8, x8, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #40]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x9, x9, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #48]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x10, x10, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #56]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x11, x11, x19
  adc  x16, x20, xzr
  ldr  x21, [x1, #64]
  mul  x19, x21, x15
  umulh x20, x21, x15
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x12, x12, x19
  adc  x16, x20, xzr
  adds x13, x13, x16
  adc  x14, xzr, xzr
  ldr  x17, [x3]
  mul  x17, x4, x17
  ldr  x21, [x3, #16]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x4
  adc  x16, x20, xzr
  ldr  x21, [x3, #24]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x5
  adc  x16, x20, xzr
  mov  x4, x19
  ldr  x21, [x3, #32]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x6
  adc  x16, x20, xzr
  mov  x5, x19
  ldr  x21, [x3, #40]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x7
  adc  x16, x20, xzr
  mov  x6, x19
  ldr  x21, [x3, #48]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x8
  adc  x16, x20, xzr
  mov  x7, x19
  ldr  x21, [x3, #56]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x9
  adc  x16, x20, xzr
  mov  x8, x19
  ldr  x21, [x3, #64]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x10
  adc  x16, x20, xzr
  mov  x9, x19
  ldr  x21, [x3, #72]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x11
  adc  x16, x20, xzr
  mov  x10, x19
  ldr  x21, [x3, #80]
  mul  x19, x17, x21
  umulh x20, x17, x21
  adds x19, x19, x16
  adc  x20, x20, xzr
  adds x19, x19, x12
  adc  x16, x20, xzr
  mov  x11, x19
  adds x19, x13, x16
  mov  x12, x19
  adc  x16, xzr, xzr
  add  x13, x14, x16
  mov  x16, xzr
  ldr  x21, [x3, #16]
  subs x19, x4, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #24]
  subs x19, x5, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #32]
  subs x19, x6, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #40]
  subs x19, x7, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #48]
  subs x19, x8, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #56]
  subs x19, x9, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #64]
  subs x19, x10, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #72]
  subs x19, x11, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  ldr  x21, [x3, #80]
  subs x19, x12, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  subs x19, x13, x16
  adc  x17, xzr, xzr
  neg  x17, x17
  mov  x16, xzr
  ldr  x21, [x3, #16]
  and  x21, x21, x17
  subs x19, x4, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #0]
  ldr  x21, [x3, #24]
  and  x21, x21, x17
  subs x19, x5, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #8]
  ldr  x21, [x3, #32]
  and  x21, x21, x17
  subs x19, x6, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #16]
  ldr  x21, [x3, #40]
  and  x21, x21, x17
  subs x19, x7, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #24]
  ldr  x21, [x3, #48]
  and  x21, x21, x17
  subs x19, x8, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #32]
  ldr  x21, [x3, #56]
  and  x21, x21, x17
  subs x19, x9, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #40]
  ldr  x21, [x3, #64]
  and  x21, x21, x17
  subs x19, x10, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #48]
  ldr  x21, [x3, #72]
  and  x21, x21, x17
  subs x19, x11, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #56]
  ldr  x21, [x3, #80]
  and  x21, x21, x17
  subs x19, x12, x16
  sbc  x20, xzr, xzr
  subs x19, x19, x21
  sbc  x15, xzr, xzr
  add  x16, x20, x15
  neg  x16, x16
  str  x19, [x0, #64]
  ldp  x19, x20, [sp, #0]
  ldr  x21, [sp, #16]
  add  sp, sp, #32
                {$ELSE}
                  {$IFDEF CRYPTOLIB_FP_MODADD}
  // x0=PR, x1=PA, x2=PB, x3=PCtx ([n0'(unused)@0, N@8, p@16]); inputs < p.
  // R := (A + B) mod p, constant-time. Width-general, single carry chain.
  ldr   x4, [x3, #8]               // N
  add   x17, x3, #16               // p base
  mov   x9, xzr                    // carry
  mov   x6, xzr                    // j
.LFpModAddSum:
  ldr   x10, [x1, x6, lsl #3]      // a[j]
  ldr   x11, [x2, x6, lsl #3]      // b[j]
  adds  x10, x10, x11
  adc   x12, xzr, xzr
  adds  x10, x10, x9               // + carry_in
  adc   x13, xzr, xzr
  str   x10, [x0, x6, lsl #3]
  add   x9, x12, x13               // carry_out (0/1)
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpModAddSum
  mov   x16, x9                    // save top carry c
  // R := R - p (borrow in x9)
  mov   x9, xzr
  mov   x6, xzr
.LFpModAddSub:
  ldr   x10, [x0, x6, lsl #3]
  ldr   x11, [x17, x6, lsl #3]     // p[j]
  subs  x10, x10, x9               // - borrow
  sbc   x12, xzr, xzr
  subs  x10, x10, x11              // - p[j]
  sbc   x13, xzr, xzr
  str   x10, [x0, x6, lsl #3]
  add   x9, x12, x13
  neg   x9, x9                     // borrow_out (0/1)
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpModAddSub
  // add-back p iff (c == 0) and (borrow == 1); mask in x15
  eor   x16, x16, #1               // (c == 0) ? 1 : 0
  and   x16, x16, x9               // & borrow
  neg   x15, x16                   // mask (all-ones if add-back)
  mov   x9, xzr                    // carry
  mov   x6, xzr
.LFpModAddBack:
  ldr   x11, [x17, x6, lsl #3]     // p[j]
  and   x11, x11, x15
  ldr   x10, [x0, x6, lsl #3]
  adds  x10, x10, x11
  adc   x12, xzr, xzr
  adds  x10, x10, x9
  adc   x13, xzr, xzr
  str   x10, [x0, x6, lsl #3]
  add   x9, x12, x13
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpModAddBack
                  {$ELSE}
                    {$IFDEF CRYPTOLIB_FP_MODSUB}
  // x0=PR, x1=PA, x2=PB, x3=PCtx ([n0'(unused)@0, N@8, p@16]); inputs < p.
  // R := (A - B) mod p, constant-time. Width-general, single borrow chain.
  ldr   x4, [x3, #8]               // N
  add   x17, x3, #16               // p base
  mov   x9, xzr                    // borrow
  mov   x6, xzr                    // j
.LFpModSubDiff:
  ldr   x10, [x1, x6, lsl #3]      // a[j]
  ldr   x11, [x2, x6, lsl #3]      // b[j]
  subs  x10, x10, x9               // - borrow
  sbc   x12, xzr, xzr
  subs  x10, x10, x11              // - b[j]
  sbc   x13, xzr, xzr
  str   x10, [x0, x6, lsl #3]
  add   x9, x12, x13
  neg   x9, x9                     // borrow_out (0/1)
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpModSubDiff
  neg   x15, x9                    // mask (all-ones if we borrowed, i.e. A < B)
  mov   x9, xzr                    // carry
  mov   x6, xzr
.LFpModSubBack:
  ldr   x11, [x17, x6, lsl #3]     // p[j]
  and   x11, x11, x15
  ldr   x10, [x0, x6, lsl #3]
  adds  x10, x10, x11
  adc   x12, xzr, xzr
  adds  x10, x10, x9
  adc   x13, xzr, xzr
  str   x10, [x0, x6, lsl #3]
  add   x9, x12, x13
  add   x6, x6, #1
  cmp   x6, x4
  b.lo  .LFpModSubBack
                    {$ELSE}
                    {$FATAL Exactly one of CRYPTOLIB_FP_MUL, CRYPTOLIB_FP_SQR, CRYPTOLIB_FP_MONTMUL, CRYPTOLIB_FP_MONTMUL_REG4, CRYPTOLIB_FP_MONTMUL_REG5, CRYPTOLIB_FP_MONTMUL_REG6, CRYPTOLIB_FP_MONTMUL_REG7, CRYPTOLIB_FP_MONTMUL_REG8, CRYPTOLIB_FP_MONTMUL_REG9, CRYPTOLIB_FP_MODADD, CRYPTOLIB_FP_MODSUB must be defined before including this file}
                    {$ENDIF}
                  {$ENDIF}
                {$ENDIF}
              {$ENDIF}
            {$ENDIF}
          {$ENDIF}
        {$ENDIF}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
