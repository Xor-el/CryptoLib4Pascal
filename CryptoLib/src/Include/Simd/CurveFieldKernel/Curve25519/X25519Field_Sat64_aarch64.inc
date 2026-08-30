// Curve25519 radix-2^64 (saturated, 4 x 64-bit limbs) field primitives and the
// fused Montgomery ladder step (AArch64).
// -------------------------------------------------------------------
//
// Selector-driven; exactly one of the following must be defined before including:
//
//   CRYPTOLIB_CURVE25519_SAT64MUL     PH := PF * PG       mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64SQR     PH := PF^2          mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64ADD     PH := PF + PG       mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64SUB     PH := PF - PG       mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64M121666 PH := PF * 121666   mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64SQRN    PH := PF^(2^AN)     mod (2^255-19), AN >= 1
//   CRYPTOLIB_CURVE25519_SAT64LADDER  one Montgomery ladder step + cswap
//
// Representation: 4 x 64-bit limbs, radix 2^64 (limb i at [ptr+8i]) - the RFC 7748
// byte layout. Inputs are loosely reduced (value < 2^256); outputs form a value
// < 2^256 congruent mod p, reusable as inputs.
//
// Entry: PH/PF/PG via ClpSimdProc3Begin_aarch64 (x0/x1/x2); two-arg forms via
// ClpSimdProc2Begin_aarch64 (x0/x1). SAT64LADDER: x0 = PState (x1,x2,z2,x3,z3
// contiguous, 4 limbs each), x1 = swap mask (0 or all-ones).
//
// mul/umulh give the 128-bit product halves; the 4x4 product is comba (column
// accumulation) and the 2^255-19 pseudo-Mersenne reduction folds the high half in
// with x38, unconditionally.
// Constant-time: no data-dependent branches or addresses (cswap is masked; the
// SAT64SQRN loop counter AN is a public value, not a secret).


{$IFDEF CRYPTOLIB_CURVE25519_SAT64MUL}
  stp x19, x20, [sp, #-80]!
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  ldp x3, x4, [x1]
  ldp x5, x6, [x1, #16]
  ldp x7, x8, [x2]
  ldp x9, x10, [x2, #16]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0]
  stp x9, x10, [x0, #16]
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x19, x20, [sp], #80
{$ENDIF CRYPTOLIB_CURVE25519_SAT64MUL}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64SQR}
  stp x19, x20, [sp, #-80]!
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  ldp x3, x4, [x1]
  ldp x5, x6, [x1, #16]
  ldp x7, x8, [x1]
  ldp x9, x10, [x1, #16]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0]
  stp x9, x10, [x0, #16]
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x19, x20, [sp], #80
{$ENDIF CRYPTOLIB_CURVE25519_SAT64SQR}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64ADD}
  stp x19, x20, [sp, #-80]!
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  ldp x3, x4, [x1]
  ldp x5, x6, [x1, #16]
  ldp x7, x8, [x2]
  ldp x9, x10, [x2, #16]
  adds x11, x3, x7
  adcs x12, x4, x8
  adcs x13, x5, x9
  adcs x14, x6, x10
  adc x15, xzr, xzr
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0]
  stp x13, x14, [x0, #16]
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x19, x20, [sp], #80
{$ENDIF CRYPTOLIB_CURVE25519_SAT64ADD}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64SUB}
  stp x19, x20, [sp, #-80]!
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  ldp x3, x4, [x1]
  ldp x5, x6, [x1, #16]
  ldp x7, x8, [x2]
  ldp x9, x10, [x2, #16]
  subs x11, x3, x7
  sbcs x12, x4, x8
  sbcs x13, x5, x9
  sbcs x14, x6, x10
  adc x15, xzr, xzr
  subs x11, x11, #76
  sbcs x12, x12, xzr
  sbcs x13, x13, xzr
  sbcs x14, x14, xzr
  adc x16, xzr, xzr
  add x15, x15, x16
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0]
  stp x13, x14, [x0, #16]
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x19, x20, [sp], #80
{$ENDIF CRYPTOLIB_CURVE25519_SAT64SUB}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64M121666}
  stp x19, x20, [sp, #-80]!
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  ldp x3, x4, [x1]
  ldp x5, x6, [x1, #16]
  movz x7, #0xDB42
  movk x7, #0x1, lsl #16
  mul x11, x3, x7
  umulh x10, x3, x7
  mul x8, x4, x7
  umulh x9, x4, x7
  adds x8, x8, x10
  adc x9, x9, xzr
  mov x12, x8
  mov x10, x9
  mul x8, x5, x7
  umulh x9, x5, x7
  adds x8, x8, x10
  adc x9, x9, xzr
  mov x13, x8
  mov x10, x9
  mul x8, x6, x7
  umulh x9, x6, x7
  adds x8, x8, x10
  adc x9, x9, xzr
  mov x14, x8
  mov x10, x9
  mov x16, #38
  mul x17, x10, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x10, xzr, xzr
  mul x17, x10, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0]
  stp x13, x14, [x0, #16]
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x19, x20, [sp], #80
{$ENDIF CRYPTOLIB_CURVE25519_SAT64M121666}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64SQRN}
  stp x19, x20, [sp, #-80]!
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  mov x28, x2
  ldp x3, x4, [x1]
  ldp x5, x6, [x1, #16]
  ldp x7, x8, [x1]
  ldp x9, x10, [x1, #16]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0]
  stp x9, x10, [x0, #16]
  subs x28, x28, #1
  b.eq .LFe64SqrNDoneA64
.LFe64SqrNLoopA64:
  ldp x3, x4, [x0]
  ldp x5, x6, [x0, #16]
  ldp x7, x8, [x0]
  ldp x9, x10, [x0, #16]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0]
  stp x9, x10, [x0, #16]
  subs x28, x28, #1
  b.ne .LFe64SqrNLoopA64
.LFe64SqrNDoneA64:
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x19, x20, [sp], #80
{$ENDIF CRYPTOLIB_CURVE25519_SAT64SQRN}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64LADDER}
  stp x19, x20, [sp, #-80]!
  stp x21, x22, [sp, #16]
  stp x23, x24, [sp, #32]
  stp x25, x26, [sp, #48]
  stp x27, x28, [sp, #64]
  sub sp, sp, #64
  mov x28, x1
  ldp x3, x4, [x0, #96]
  ldp x5, x6, [x0, #112]
  ldp x7, x8, [x0, #128]
  ldp x9, x10, [x0, #144]
  adds x11, x3, x7
  adcs x12, x4, x8
  adcs x13, x5, x9
  adcs x14, x6, x10
  adc x15, xzr, xzr
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [sp]
  stp x13, x14, [sp, #16]
  ldp x3, x4, [x0, #96]
  ldp x5, x6, [x0, #112]
  ldp x7, x8, [x0, #128]
  ldp x9, x10, [x0, #144]
  subs x11, x3, x7
  sbcs x12, x4, x8
  sbcs x13, x5, x9
  sbcs x14, x6, x10
  adc x15, xzr, xzr
  subs x11, x11, #76
  sbcs x12, x12, xzr
  sbcs x13, x13, xzr
  sbcs x14, x14, xzr
  adc x16, xzr, xzr
  add x15, x15, x16
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0, #96]
  stp x13, x14, [x0, #112]
  ldp x3, x4, [x0, #32]
  ldp x5, x6, [x0, #48]
  ldp x7, x8, [x0, #64]
  ldp x9, x10, [x0, #80]
  adds x11, x3, x7
  adcs x12, x4, x8
  adcs x13, x5, x9
  adcs x14, x6, x10
  adc x15, xzr, xzr
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0, #128]
  stp x13, x14, [x0, #144]
  ldp x3, x4, [x0, #32]
  ldp x5, x6, [x0, #48]
  ldp x7, x8, [x0, #64]
  ldp x9, x10, [x0, #80]
  subs x11, x3, x7
  sbcs x12, x4, x8
  sbcs x13, x5, x9
  sbcs x14, x6, x10
  adc x15, xzr, xzr
  subs x11, x11, #76
  sbcs x12, x12, xzr
  sbcs x13, x13, xzr
  sbcs x14, x14, xzr
  adc x16, xzr, xzr
  add x15, x15, x16
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0, #32]
  stp x13, x14, [x0, #48]
  ldp x3, x4, [sp]
  ldp x5, x6, [sp, #16]
  ldp x7, x8, [x0, #32]
  ldp x9, x10, [x0, #48]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [sp]
  stp x9, x10, [sp, #16]
  ldp x3, x4, [x0, #96]
  ldp x5, x6, [x0, #112]
  ldp x7, x8, [x0, #128]
  ldp x9, x10, [x0, #144]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #96]
  stp x9, x10, [x0, #112]
  ldp x3, x4, [x0, #128]
  ldp x5, x6, [x0, #144]
  ldp x7, x8, [x0, #128]
  ldp x9, x10, [x0, #144]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #128]
  stp x9, x10, [x0, #144]
  ldp x3, x4, [x0, #32]
  ldp x5, x6, [x0, #48]
  ldp x7, x8, [x0, #32]
  ldp x9, x10, [x0, #48]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #32]
  stp x9, x10, [x0, #48]
  ldp x3, x4, [x0, #128]
  ldp x5, x6, [x0, #144]
  ldp x7, x8, [x0, #32]
  ldp x9, x10, [x0, #48]
  subs x11, x3, x7
  sbcs x12, x4, x8
  sbcs x13, x5, x9
  sbcs x14, x6, x10
  adc x15, xzr, xzr
  subs x11, x11, #76
  sbcs x12, x12, xzr
  sbcs x13, x13, xzr
  sbcs x14, x14, xzr
  adc x16, xzr, xzr
  add x15, x15, x16
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [sp, #32]
  stp x13, x14, [sp, #48]
  ldp x3, x4, [sp, #32]
  ldp x5, x6, [sp, #48]
  movz x7, #0xDB42
  movk x7, #0x1, lsl #16
  mul x11, x3, x7
  umulh x10, x3, x7
  mul x8, x4, x7
  umulh x9, x4, x7
  adds x8, x8, x10
  adc x9, x9, xzr
  mov x12, x8
  mov x10, x9
  mul x8, x5, x7
  umulh x9, x5, x7
  adds x8, x8, x10
  adc x9, x9, xzr
  mov x13, x8
  mov x10, x9
  mul x8, x6, x7
  umulh x9, x6, x7
  adds x8, x8, x10
  adc x9, x9, xzr
  mov x14, x8
  mov x10, x9
  mov x16, #38
  mul x17, x10, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x10, xzr, xzr
  mul x17, x10, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0, #64]
  stp x13, x14, [x0, #80]
  ldp x3, x4, [x0, #64]
  ldp x5, x6, [x0, #80]
  ldp x7, x8, [x0, #32]
  ldp x9, x10, [x0, #48]
  adds x11, x3, x7
  adcs x12, x4, x8
  adcs x13, x5, x9
  adcs x14, x6, x10
  adc x15, xzr, xzr
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0, #64]
  stp x13, x14, [x0, #80]
  ldp x3, x4, [x0, #64]
  ldp x5, x6, [x0, #80]
  ldp x7, x8, [sp, #32]
  ldp x9, x10, [sp, #48]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #64]
  stp x9, x10, [x0, #80]
  ldp x3, x4, [x0, #32]
  ldp x5, x6, [x0, #48]
  ldp x7, x8, [x0, #128]
  ldp x9, x10, [x0, #144]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #32]
  stp x9, x10, [x0, #48]
  ldp x3, x4, [sp]
  ldp x5, x6, [sp, #16]
  ldp x7, x8, [x0, #96]
  ldp x9, x10, [x0, #112]
  subs x11, x3, x7
  sbcs x12, x4, x8
  sbcs x13, x5, x9
  sbcs x14, x6, x10
  adc x15, xzr, xzr
  subs x11, x11, #76
  sbcs x12, x12, xzr
  sbcs x13, x13, xzr
  sbcs x14, x14, xzr
  adc x16, xzr, xzr
  add x15, x15, x16
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0, #128]
  stp x13, x14, [x0, #144]
  ldp x3, x4, [sp]
  ldp x5, x6, [sp, #16]
  ldp x7, x8, [x0, #96]
  ldp x9, x10, [x0, #112]
  adds x11, x3, x7
  adcs x12, x4, x8
  adcs x13, x5, x9
  adcs x14, x6, x10
  adc x15, xzr, xzr
  mov x16, #38
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  adc x15, xzr, xzr
  mul x17, x15, x16
  adds x11, x11, x17
  adcs x12, x12, xzr
  adcs x13, x13, xzr
  adcs x14, x14, xzr
  stp x11, x12, [x0, #96]
  stp x13, x14, [x0, #112]
  ldp x3, x4, [x0, #96]
  ldp x5, x6, [x0, #112]
  ldp x7, x8, [x0, #96]
  ldp x9, x10, [x0, #112]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #96]
  stp x9, x10, [x0, #112]
  ldp x3, x4, [x0, #128]
  ldp x5, x6, [x0, #144]
  ldp x7, x8, [x0, #128]
  ldp x9, x10, [x0, #144]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #128]
  stp x9, x10, [x0, #144]
  ldp x3, x4, [x0, #128]
  ldp x5, x6, [x0, #144]
  ldp x7, x8, [x0]
  ldp x9, x10, [x0, #16]
  mov x20, xzr
  mov x21, xzr
  mov x22, xzr
  mul x23, x3, x7
  umulh x24, x3, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x11, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x8
  umulh x24, x3, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x7
  umulh x24, x4, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x12, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x9
  umulh x24, x3, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x8
  umulh x24, x4, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x7
  umulh x24, x5, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x13, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x3, x10
  umulh x24, x3, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x4, x9
  umulh x24, x4, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x8
  umulh x24, x5, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x7
  umulh x24, x6, x7
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x14, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x4, x10
  umulh x24, x4, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x5, x9
  umulh x24, x5, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x8
  umulh x24, x6, x8
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x15, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x5, x10
  umulh x24, x5, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mul x23, x6, x9
  umulh x24, x6, x9
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x16, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mul x23, x6, x10
  umulh x24, x6, x10
  adds x20, x20, x23
  adcs x21, x21, x24
  adc x22, x22, xzr
  mov x17, x20
  mov x20, x21
  mov x21, x22
  mov x22, xzr
  mov x19, x20
  mov x3, #38
  mov x4, xzr
  mul x5, x15, x3
  umulh x6, x15, x3
  adds x7, x11, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x16, x3
  umulh x6, x16, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x8, x12, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x17, x3
  umulh x6, x17, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x9, x13, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x19, x3
  umulh x6, x19, x3
  adds x5, x5, x4
  adc x6, x6, xzr
  adds x10, x14, x5
  adc x6, x6, xzr
  mov x4, x6
  mul x5, x4, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  adc x5, xzr, xzr
  mul x5, x5, x3
  adds x7, x7, x5
  adcs x8, x8, xzr
  adcs x9, x9, xzr
  adcs x10, x10, xzr
  stp x7, x8, [x0, #128]
  stp x9, x10, [x0, #144]
  ldr x3, [x0, #32]
  ldr x4, [x0, #96]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #32]
  str x4, [x0, #96]
  ldr x3, [x0, #40]
  ldr x4, [x0, #104]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #40]
  str x4, [x0, #104]
  ldr x3, [x0, #48]
  ldr x4, [x0, #112]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #48]
  str x4, [x0, #112]
  ldr x3, [x0, #56]
  ldr x4, [x0, #120]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #56]
  str x4, [x0, #120]
  ldr x3, [x0, #64]
  ldr x4, [x0, #128]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #64]
  str x4, [x0, #128]
  ldr x3, [x0, #72]
  ldr x4, [x0, #136]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #72]
  str x4, [x0, #136]
  ldr x3, [x0, #80]
  ldr x4, [x0, #144]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #80]
  str x4, [x0, #144]
  ldr x3, [x0, #88]
  ldr x4, [x0, #152]
  eor x5, x3, x4
  and x5, x5, x28
  eor x3, x3, x5
  eor x4, x4, x5
  str x3, [x0, #88]
  str x4, [x0, #152]
  add sp, sp, #64
  ldp x21, x22, [sp, #16]
  ldp x23, x24, [sp, #32]
  ldp x25, x26, [sp, #48]
  ldp x27, x28, [sp, #64]
  ldp x19, x20, [sp], #80
{$ENDIF CRYPTOLIB_CURVE25519_SAT64LADDER}
