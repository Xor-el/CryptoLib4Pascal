// Curve25519 radix-2^51 (fe51 / donna64) field multiply and square (AArch64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined before
// including this file:
//
//   CRYPTOLIB_CURVE25519_FE64MUL   PH := PF * PG mod (2^255-19)
//   CRYPTOLIB_CURVE25519_FE64SQR   PH := PF^2  mod (2^255-19)
//
// Representation: 5 x 64-bit limbs, radix 2^51 (limb i at [ptr+8i]). Limbs are
// UNSIGNED and loosely reduced (each < 2^52); output limbs < 2^52.
//
// On entry (via ClpSimdProc3Begin_aarch64): x0 = PH, x1 = PF, x2 = PG.
// FE64SQR (via ClpSimdProc2Begin_aarch64): x0 = PH, x1 = PF.
//
// The five 128-bit column accumulators are formed and reduced one at a time
// (sequential carry), keeping the whole kernel register-resident bar four
// callee-saved temporaries. umulh gives the high 64 bits of each product; the
// limbs are unsigned so umulh (not smulh) is correct.
// Reference: 64-bit radix-2^51 field arithmetic (Bernstein curve25519 / ref10-64).

{$IFDEF CRYPTOLIB_CURVE25519_FE64MUL}
  stp  x19, x20, [sp, #-32]!
  stp  x21, x22, [sp, #16]
  ldp  x3, x4, [x1]
  ldp  x5, x6, [x1, #16]
  ldr  x7, [x1, #32]
  ldp  x8, x9, [x2]
  ldp  x10, x11, [x2, #16]
  ldr  x12, [x2, #32]
  // 19*g1..19*g4
  mov  x13, #19
  mul  x14, x9, x13
  mul  x15, x10, x13
  mul  x16, x11, x13
  mul  x17, x12, x13
  // MASK51 = 0x0007FFFFFFFFFFFF
  movz x13, #0xFFFF
  movk x13, #0xFFFF, lsl #16
  movk x13, #0xFFFF, lsl #32
  movk x13, #0x7, lsl #48
  // column 0: f0*g0 + f1*19g4 + f2*19g3 + f3*19g2 + f4*19g1
  mul  x1, x3, x8;   umulh x2, x3, x8
  mul  x19, x4, x17; umulh x20, x4, x17; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x5, x16; umulh x20, x5, x16; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x6, x15; umulh x20, x6, x15; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x7, x14; umulh x20, x7, x14; adds x1, x1, x19; adc x2, x2, x20
  and  x21, x1, x13
  str  x21, [x0]
  extr x22, x2, x1, #51
  // column 1: c + f0*g1 + f1*g0 + f2*19g4 + f3*19g3 + f4*19g2
  mul  x1, x3, x9;   umulh x2, x3, x9;   adds x1, x1, x22; adc x2, x2, xzr
  mul  x19, x4, x8;  umulh x20, x4, x8;  adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x5, x17; umulh x20, x5, x17; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x6, x16; umulh x20, x6, x16; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x7, x15; umulh x20, x7, x15; adds x1, x1, x19; adc x2, x2, x20
  and  x21, x1, x13
  str  x21, [x0, #8]
  extr x22, x2, x1, #51
  // column 2: c + f0*g2 + f1*g1 + f2*g0 + f3*19g4 + f4*19g3
  mul  x1, x3, x10;  umulh x2, x3, x10;  adds x1, x1, x22; adc x2, x2, xzr
  mul  x19, x4, x9;  umulh x20, x4, x9;  adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x5, x8;  umulh x20, x5, x8;  adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x6, x17; umulh x20, x6, x17; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x7, x16; umulh x20, x7, x16; adds x1, x1, x19; adc x2, x2, x20
  and  x21, x1, x13
  str  x21, [x0, #16]
  extr x22, x2, x1, #51
  // column 3: c + f0*g3 + f1*g2 + f2*g1 + f3*g0 + f4*19g4
  mul  x1, x3, x11;  umulh x2, x3, x11;  adds x1, x1, x22; adc x2, x2, xzr
  mul  x19, x4, x10; umulh x20, x4, x10; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x5, x9;  umulh x20, x5, x9;  adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x6, x8;  umulh x20, x6, x8;  adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x7, x17; umulh x20, x7, x17; adds x1, x1, x19; adc x2, x2, x20
  and  x21, x1, x13
  str  x21, [x0, #24]
  extr x22, x2, x1, #51
  // column 4: c + f0*g4 + f1*g3 + f2*g2 + f3*g1 + f4*g0
  mul  x1, x3, x12;  umulh x2, x3, x12;  adds x1, x1, x22; adc x2, x2, xzr
  mul  x19, x4, x11; umulh x20, x4, x11; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x5, x10; umulh x20, x5, x10; adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x6, x9;  umulh x20, x6, x9;  adds x1, x1, x19; adc x2, x2, x20
  mul  x19, x7, x8;  umulh x20, x7, x8;  adds x1, x1, x19; adc x2, x2, x20
  and  x21, x1, x13
  str  x21, [x0, #32]
  extr x22, x2, x1, #51
  // fold top carry x19 into limb 0, one short carry into limb 1
  mov  x19, #19
  ldr  x20, [x0]
  madd x20, x22, x19, x20
  lsr  x22, x20, #51
  and  x20, x20, x13
  str  x20, [x0]
  ldr  x19, [x0, #8]
  add  x19, x19, x22
  str  x19, [x0, #8]
  ldp  x21, x22, [sp, #16]
  ldp  x19, x20, [sp], #32
{$ENDIF CRYPTOLIB_CURVE25519_FE64MUL}

{$IFDEF CRYPTOLIB_CURVE25519_FE64SQR}
  stp  x19, x20, [sp, #-16]!
  ldp  x3, x4, [x1]
  ldp  x5, x6, [x1, #16]
  ldr  x7, [x1, #32]
  // precompute 2f0, 2f1, 38f2, 19f3, 19f4, 38f4
  add  x8, x3, x3
  add  x9, x4, x4
  mov  x15, #38
  mul  x10, x5, x15
  mov  x15, #19
  mul  x11, x6, x15
  mul  x12, x7, x15
  add  x13, x12, x12
  // MASK51 -> x14
  movz x14, #0xFFFF
  movk x14, #0xFFFF, lsl #16
  movk x14, #0xFFFF, lsl #32
  movk x14, #0x7, lsl #48
  // column 0: f0*f0 + f1*38f4 + f3*38f2
  mul  x1, x3, x3;   umulh x2, x3, x3
  mul  x15, x4, x13; umulh x16, x4, x13; adds x1, x1, x15; adc x2, x2, x16
  mul  x15, x6, x10; umulh x16, x6, x10; adds x1, x1, x15; adc x2, x2, x16
  and  x17, x1, x14
  str  x17, [x0]
  extr x19, x2, x1, #51
  // column 1: c + 2f0*f1 + f2*38f4 + f3*19f3
  mul  x1, x8, x4;   umulh x2, x8, x4;   adds x1, x1, x19; adc x2, x2, xzr
  mul  x15, x5, x13; umulh x16, x5, x13; adds x1, x1, x15; adc x2, x2, x16
  mul  x15, x6, x11; umulh x16, x6, x11; adds x1, x1, x15; adc x2, x2, x16
  and  x17, x1, x14
  str  x17, [x0, #8]
  extr x19, x2, x1, #51
  // column 2: c + 2f0*f2 + f1*f1 + f3*38f4
  mul  x1, x8, x5;   umulh x2, x8, x5;   adds x1, x1, x19; adc x2, x2, xzr
  mul  x15, x4, x4;  umulh x16, x4, x4;  adds x1, x1, x15; adc x2, x2, x16
  mul  x15, x6, x13; umulh x16, x6, x13; adds x1, x1, x15; adc x2, x2, x16
  and  x17, x1, x14
  str  x17, [x0, #16]
  extr x19, x2, x1, #51
  // column 3: c + 2f0*f3 + 2f1*f2 + f4*19f4
  mul  x1, x8, x6;   umulh x2, x8, x6;   adds x1, x1, x19; adc x2, x2, xzr
  mul  x15, x9, x5;  umulh x16, x9, x5;  adds x1, x1, x15; adc x2, x2, x16
  mul  x15, x7, x12; umulh x16, x7, x12; adds x1, x1, x15; adc x2, x2, x16
  and  x17, x1, x14
  str  x17, [x0, #24]
  extr x19, x2, x1, #51
  // column 4: c + 2f0*f4 + 2f1*f3 + f2*f2
  mul  x1, x8, x7;   umulh x2, x8, x7;   adds x1, x1, x19; adc x2, x2, xzr
  mul  x15, x9, x6;  umulh x16, x9, x6;  adds x1, x1, x15; adc x2, x2, x16
  mul  x15, x5, x5;  umulh x16, x5, x5;  adds x1, x1, x15; adc x2, x2, x16
  and  x17, x1, x14
  str  x17, [x0, #32]
  extr x19, x2, x1, #51
  // fold top carry into limb 0, one short carry into limb 1
  mov  x15, #19
  ldr  x16, [x0]
  madd x16, x19, x15, x16
  lsr  x19, x16, #51
  and  x16, x16, x14
  str  x16, [x0]
  ldr  x15, [x0, #8]
  add  x15, x15, x19
  str  x15, [x0, #8]
  ldp  x19, x20, [sp], #16
{$ENDIF CRYPTOLIB_CURVE25519_FE64SQR}
