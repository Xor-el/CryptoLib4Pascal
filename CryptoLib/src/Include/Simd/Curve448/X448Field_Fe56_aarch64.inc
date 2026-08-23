// Curve448 radix-2^56 (fe56 / Goldilocks) field multiply and square (AArch64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined before
// including this file:
//
//   CRYPTOLIB_CURVE448_FE56MUL   PH := PF * PG mod (2^448-2^224-1)
//   CRYPTOLIB_CURVE448_FE56SQR   PH := PF^2  mod (2^448-2^224-1)
//
// Representation: 8 x 64-bit limbs, radix 2^56 (limb i at [ptr+8i]). Limbs are
// UNSIGNED and loosely reduced (each < 2^57); output limbs < 2^57.
//
// On entry (via ClpSimdProc3Begin_aarch64): x0 = PH, x1 = PF, x2 = PG.
// FE56SQR (via ClpSimdProc2Begin_aarch64): x0 = PH, x1 = PF (g = f).
//
// Each of the fifteen 128-bit columns is summed in a register pair (mul/umulh,
// limbs unsigned so umulh is correct) and stored to a 256-byte frame; then the
// Goldilocks fold (column k -> k-4 and k-8 for k=14..8, high-to-low so the
// cascade re-folds), then a radix-2^56 carry (extr for the 56-bit carry) with the
// top carry into limbs 0 and 4. Only caller-saved x3..x10 are used. Constant-time.
// Reference: 64-bit radix-2^56 Goldilocks field arithmetic (edwards448 / ed448-goldilocks).


{$IFDEF CRYPTOLIB_CURVE448_FE56MUL}
  sub  sp, sp, #256
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #0]
  mul  x5, x3, x4
  umulh x6, x3, x4
  stp  x5, x6, [sp, #0]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #8]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #16]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #16]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #32]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #24]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #48]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #32]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #64]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #40]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #80]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #48]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #96]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #112]
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #128]
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #144]
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #160]
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #176]
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #192]
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #208]
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  stp  x5, x6, [sp, #224]
  ldp  x3, x4, [sp, #224]
  ldp  x5, x6, [sp, #160]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #160]
  ldp  x5, x6, [sp, #96]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #96]
  ldp  x3, x4, [sp, #208]
  ldp  x5, x6, [sp, #144]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #144]
  ldp  x5, x6, [sp, #80]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #80]
  ldp  x3, x4, [sp, #192]
  ldp  x5, x6, [sp, #128]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #128]
  ldp  x5, x6, [sp, #64]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #64]
  ldp  x3, x4, [sp, #176]
  ldp  x5, x6, [sp, #112]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #112]
  ldp  x5, x6, [sp, #48]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #48]
  ldp  x3, x4, [sp, #160]
  ldp  x5, x6, [sp, #96]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #96]
  ldp  x5, x6, [sp, #32]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #32]
  ldp  x3, x4, [sp, #144]
  ldp  x5, x6, [sp, #80]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #80]
  ldp  x5, x6, [sp, #16]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #16]
  ldp  x3, x4, [sp, #128]
  ldp  x5, x6, [sp, #64]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #64]
  ldp  x5, x6, [sp, #0]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #0]
  movz x9, #0xFFFF
  movk x9, #0xFFFF, lsl #16
  movk x9, #0xFFFF, lsl #32
  movk x9, #0x00FF, lsl #48
  mov  x10, xzr
  ldp  x3, x4, [sp, #0]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #0]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #16]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #8]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #32]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #16]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #48]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #24]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #64]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #32]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #80]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #40]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #96]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #48]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #112]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #56]
  extr x10, x4, x3, #56
  ldr  x3, [x0, #0]
  add  x3, x3, x10
  ldr  x4, [x0, #32]
  add  x4, x4, x10
  lsr  x5, x3, #56
  and  x3, x3, x9
  str  x3, [x0, #0]
  ldr  x6, [x0, #8]
  add  x6, x6, x5
  str  x6, [x0, #8]
  lsr  x5, x4, #56
  and  x4, x4, x9
  str  x4, [x0, #32]
  ldr  x6, [x0, #40]
  add  x6, x6, x5
  str  x6, [x0, #40]
  add  sp, sp, #256
{$ENDIF CRYPTOLIB_CURVE448_FE56MUL}

{$IFDEF CRYPTOLIB_CURVE448_FE56SQR}
  mov  x2, x1
  sub  sp, sp, #256
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #0]
  mul  x5, x3, x4
  umulh x6, x3, x4
  stp  x5, x6, [sp, #0]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #8]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #16]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #16]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #32]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #24]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #48]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #32]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #64]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #40]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #80]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #48]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #96]
  ldr  x3, [x1, #0]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #0]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #112]
  ldr  x3, [x1, #8]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #8]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #128]
  ldr  x3, [x1, #16]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #16]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #144]
  ldr  x3, [x1, #24]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #24]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #160]
  ldr  x3, [x1, #32]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #32]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #176]
  ldr  x3, [x1, #40]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #40]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #192]
  ldr  x3, [x1, #48]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #48]
  mul  x7, x3, x4
  umulh x8, x3, x4
  adds x5, x5, x7
  adc  x6, x6, x8
  stp  x5, x6, [sp, #208]
  ldr  x3, [x1, #56]
  ldr  x4, [x2, #56]
  mul  x5, x3, x4
  umulh x6, x3, x4
  stp  x5, x6, [sp, #224]
  ldp  x3, x4, [sp, #224]
  ldp  x5, x6, [sp, #160]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #160]
  ldp  x5, x6, [sp, #96]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #96]
  ldp  x3, x4, [sp, #208]
  ldp  x5, x6, [sp, #144]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #144]
  ldp  x5, x6, [sp, #80]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #80]
  ldp  x3, x4, [sp, #192]
  ldp  x5, x6, [sp, #128]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #128]
  ldp  x5, x6, [sp, #64]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #64]
  ldp  x3, x4, [sp, #176]
  ldp  x5, x6, [sp, #112]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #112]
  ldp  x5, x6, [sp, #48]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #48]
  ldp  x3, x4, [sp, #160]
  ldp  x5, x6, [sp, #96]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #96]
  ldp  x5, x6, [sp, #32]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #32]
  ldp  x3, x4, [sp, #144]
  ldp  x5, x6, [sp, #80]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #80]
  ldp  x5, x6, [sp, #16]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #16]
  ldp  x3, x4, [sp, #128]
  ldp  x5, x6, [sp, #64]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #64]
  ldp  x5, x6, [sp, #0]
  adds x5, x5, x3
  adc  x6, x6, x4
  stp  x5, x6, [sp, #0]
  movz x9, #0xFFFF
  movk x9, #0xFFFF, lsl #16
  movk x9, #0xFFFF, lsl #32
  movk x9, #0x00FF, lsl #48
  mov  x10, xzr
  ldp  x3, x4, [sp, #0]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #0]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #16]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #8]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #32]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #16]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #48]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #24]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #64]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #32]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #80]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #40]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #96]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #48]
  extr x10, x4, x3, #56
  ldp  x3, x4, [sp, #112]
  adds x3, x3, x10
  adc  x4, x4, xzr
  and  x5, x3, x9
  str  x5, [x0, #56]
  extr x10, x4, x3, #56
  ldr  x3, [x0, #0]
  add  x3, x3, x10
  ldr  x4, [x0, #32]
  add  x4, x4, x10
  lsr  x5, x3, #56
  and  x3, x3, x9
  str  x3, [x0, #0]
  ldr  x6, [x0, #8]
  add  x6, x6, x5
  str  x6, [x0, #8]
  lsr  x5, x4, #56
  and  x4, x4, x9
  str  x4, [x0, #32]
  ldr  x6, [x0, #40]
  add  x6, x6, x5
  str  x6, [x0, #40]
  add  sp, sp, #256
{$ENDIF CRYPTOLIB_CURVE448_FE56SQR}
