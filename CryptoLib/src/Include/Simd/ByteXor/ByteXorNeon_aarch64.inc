// NEON variable-length XOR utility (aarch64), matching the contract of
// ByteXorSse2_x86_64.inc.
// After ClpSimdProc4Begin_aarch64.inc: x0 = ALen, x1 = PX, x2 = PY, x3 = PZ.
// Computes PZ[i] := PX[i] xor PY[i] for i in [0, ALen). PZ may alias PX or
// PY (forward processing). 16-byte vector chunks, then a byte tail. Uses
// v0/v1 and w4/w5 only - no callee-saved registers, no frame.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
.Lbytexor_neon_loop16:
  cmp x0, #16
  b.lo .Lbytexor_neon_tail
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00041                    // ldr q1, [x2]
  .long 0x6e211c00                    // eor v0.16b, v0.16b, v1.16b
  .long 0x3d800060                    // str q0, [x3]
  add x1, x1, #16
  add x2, x2, #16
  add x3, x3, #16
  sub x0, x0, #16
  b .Lbytexor_neon_loop16
.Lbytexor_neon_tail:
  cbz x0, .Lbytexor_neon_done
.Lbytexor_neon_tail_loop:
  .long 0x39400024                    // ldrb w4, [x1]
  .long 0x39400045                    // ldrb w5, [x2]
  .long 0x4a050084                    // eor w4, w4, w5
  .long 0x39000064                    // strb w4, [x3]
  add x1, x1, #1
  add x2, x2, #1
  add x3, x3, #1
  sub x0, x0, #1
  cbnz x0, .Lbytexor_neon_tail_loop
.Lbytexor_neon_done:
  ret
