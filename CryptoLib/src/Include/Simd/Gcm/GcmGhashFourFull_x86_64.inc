// Fused full 4-way GHASH batch kernel (x86-64).
// Monolithic sibling of GcmGhashEightFull_x86_64.inc for 4-block batches.
//
// After SimdProc4Begin_x86_64.inc: rcx = PFS (16-byte running GHASH state,
// canonical/byte-reversed form; in + out), rdx = PC0 (64 bytes ciphertext,
// canonical form), r8 = PHPow64 (H^4..H^1 as four 16-byte limbs,
// GHASH-field little-endian form), r9 = PMask (16-byte PSHUFB control).
//
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
  movdqu    xmm8, [r9]
  pxor      xmm0, xmm0
  pxor      xmm1, xmm1
  pxor      xmm2, xmm2

  // Block 0: byte-reverse + fold running state
  movdqu    xmm3, [rdx]
  pshufb    xmm3, xmm8
  movdqu    xmm5, [rcx]
  pshufb    xmm5, xmm8
  pxor      xmm3, xmm5
  movdqu    xmm4, [r8]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00              // pclmulqdq xmm5, xmm4, 0
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01              // pclmulqdq xmm6, xmm4, 1
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10              // pclmulqdq xmm7, xmm4, 16
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11              // pclmulqdq xmm7, xmm4, 17
  pxor      xmm0, xmm5
  pxor      xmm1, xmm6
  pxor      xmm2, xmm7

  // Block 1
  movdqu    xmm3, [rdx + 16]
  pshufb    xmm3, xmm8
  movdqu    xmm4, [r8 + 16]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00              // pclmulqdq xmm5, xmm4, 0
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01              // pclmulqdq xmm6, xmm4, 1
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10              // pclmulqdq xmm7, xmm4, 16
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11              // pclmulqdq xmm7, xmm4, 17
  pxor      xmm0, xmm5
  pxor      xmm1, xmm6
  pxor      xmm2, xmm7

  // Block 2
  movdqu    xmm3, [rdx + 32]
  pshufb    xmm3, xmm8
  movdqu    xmm4, [r8 + 32]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00              // pclmulqdq xmm5, xmm4, 0
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01              // pclmulqdq xmm6, xmm4, 1
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10              // pclmulqdq xmm7, xmm4, 16
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11              // pclmulqdq xmm7, xmm4, 17
  pxor      xmm0, xmm5
  pxor      xmm1, xmm6
  pxor      xmm2, xmm7

  // Block 3
  movdqu    xmm3, [rdx + 48]
  pshufb    xmm3, xmm8
  movdqu    xmm4, [r8 + 48]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00              // pclmulqdq xmm5, xmm4, 0
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01              // pclmulqdq xmm6, xmm4, 1
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10              // pclmulqdq xmm7, xmm4, 16
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11              // pclmulqdq xmm7, xmm4, 17
  pxor      xmm0, xmm5
  pxor      xmm1, xmm6
  pxor      xmm2, xmm7

  // Inline Reduce3 (identical to the 8-way sibling).
  movdqa    xmm4, xmm1
  movdqa    xmm5, xmm1
  pslldq    xmm4, 8
  psrldq    xmm5, 8
  pxor      xmm0, xmm4
  pxor      xmm2, xmm5
  movq      xmm3, xmm0
  movq      xmm4, xmm2
  movdqa    xmm5, xmm3
  psrlq     xmm5, 1
  movdqa    xmm6, xmm3
  psrlq     xmm6, 2
  movdqa    xmm7, xmm3
  psrlq     xmm7, 7
  pxor      xmm4, xmm3
  pxor      xmm4, xmm5
  pxor      xmm4, xmm6
  pxor      xmm4, xmm7
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8
  movdqa    xmm5, xmm3
  psllq     xmm5, 63
  movdqa    xmm6, xmm3
  psllq     xmm6, 62
  movdqa    xmm7, xmm3
  psllq     xmm7, 57
  pxor      xmm1, xmm5
  pxor      xmm1, xmm6
  pxor      xmm1, xmm7
  movdqa    xmm5, xmm2
  psrldq    xmm5, 8
  movdqa    xmm6, xmm5
  psllq     xmm6, 1
  movdqa    xmm7, xmm4
  psrlq     xmm7, 63
  por       xmm6, xmm7
  movdqa    xmm7, xmm4
  psllq     xmm7, 1
  movdqa    xmm3, xmm1
  psrlq     xmm3, 63
  por       xmm7, xmm3
  movdqa    xmm0, xmm1
  psllq     xmm0, 1
  movdqa    xmm3, xmm0
  psrlq     xmm3, 1
  movdqa    xmm2, xmm0
  psrlq     xmm2, 2
  movdqa    xmm5, xmm0
  psrlq     xmm5, 7
  pxor      xmm6, xmm0
  pxor      xmm6, xmm3
  pxor      xmm6, xmm2
  pxor      xmm6, xmm5
  movdqa    xmm3, xmm1
  psllq     xmm3, 63
  movdqa    xmm2, xmm1
  psllq     xmm2, 58
  pxor      xmm7, xmm3
  pxor      xmm7, xmm2

  movq      xmm0, xmm7
  pslldq    xmm6, 8
  por       xmm0, xmm6
  pshufb    xmm0, xmm8
  movdqu    [rcx], xmm0
