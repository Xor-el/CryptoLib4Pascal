// SSE2 + PCLMULQDQ Karatsuba-style carryless multiply without reduction (i386).
// MultiplyExt: Z0, Z1, Z2 only (no Z1 merge / reduction). Operands are 16-byte
// limbs, LE UInt64 pair each.
// After SimdProc3Begin_i386.inc: ebx = PX, esi = PY, edi = POut
// (48 bytes: Z0, Z1, Z2).
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
  movdqu    xmm0, [ebx]
  movdqu    xmm1, [esi]

  movdqu    xmm2, xmm0
  db $66, $0F, $3A, $44, $D1, $00  // pclmulqdq xmm2, xmm1, 0

  movdqu    xmm3, xmm0
  db $66, $0F, $3A, $44, $D9, $01  // pclmulqdq xmm3, xmm1, 1
  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $10  // pclmulqdq xmm4, xmm1, 16
  pxor      xmm3, xmm4

  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $11  // pclmulqdq xmm4, xmm1, 17

  movdqu    [edi + 0], xmm2
  movdqu    [edi + 16], xmm3
  movdqu    [edi + 32], xmm4

  pop edi
  pop esi
  pop ebx
