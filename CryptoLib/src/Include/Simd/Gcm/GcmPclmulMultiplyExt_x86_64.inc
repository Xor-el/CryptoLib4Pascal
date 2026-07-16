// SSE2 + PCLMULQDQ Karatsuba-style carryless multiply without reduction (x86-64).
// -------------------------------------------------------------------
// MultiplyExt: Z0, Z1, Z2 only (no Z1 merge / reduction). Operands are 16-byte
// limbs, LE UInt64 pair each.
//
// On entry (after ClpSimdProc3Begin_x86_64.inc):
//   rcx = PX, rdx = PY, r8 = POut (48 bytes: Z0, Z1, Z2).
//
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
// Reference: Shay Gueron / Michael E. Kounavis, "Intel(R) Carry-Less
// Multiplication Instruction and its Usage for Computing the GCM Mode"
// (white paper) - the 3-multiply carry-less Karatsuba split that this
// kernel implements.
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rdx]

  movdqu    xmm2, xmm0
  db $66, $0F, $3A, $44, $D1, $00  // pclmulqdq xmm2, xmm1, 0

  movdqu    xmm3, xmm0
  db $66, $0F, $3A, $44, $D9, $01  // pclmulqdq xmm3, xmm1, 1
  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $10  // pclmulqdq xmm4, xmm1, 16
  pxor      xmm3, xmm4

  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $11  // pclmulqdq xmm4, xmm1, 17

  movdqu    [r8 + 0], xmm2
  movdqu    [r8 + 16], xmm3
  movdqu    [r8 + 32], xmm4
