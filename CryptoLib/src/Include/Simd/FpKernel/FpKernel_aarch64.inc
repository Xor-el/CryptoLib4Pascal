// Prime-field (Fp) big-integer 64-bit-limb multiply/square kernels (AArch64).
// -------------------------------------------------------------------
//
// One selector-driven file per arch; exactly one of the following must be
// defined before including this file:
//
//   CRYPTOLIB_FP_MUL   (ClpSimdProc4Begin: x0 = PX, x1 = PY, x2 = PZ, x3 = N)
//     - schoolbook Z[0..2N-1] := X[0..N-1] * Y[0..N-1] over 64-bit limbs;
//       callers reinterpret 32-bit-limb field arrays (uint32[2N] == uint64[N]).
//   CRYPTOLIB_FP_SQR   (ClpSimdProc3Begin: x0 = PX, x1 = PZ, x2 = N)
//     - dedicated schoolbook square Z[0..2N-1] := X[0..N-1]^2 (off-diagonal
//       sum, double, then add the diagonal X[i]^2 terms).
//
// Constant-time. Uses only caller-saved x4..x15 plus the argument registers,
// so no callee-saved (x19..x28) preservation is required. Base ARMv8-A
// integer instructions (mul/umulh/adds/adc/ldr/str) are emitted as mnemonics.
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
  {$FATAL Exactly one of CRYPTOLIB_FP_MUL, CRYPTOLIB_FP_SQR must be defined before including this file}
  {$ENDIF}
{$ENDIF}
