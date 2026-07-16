// GHASH field-op kernels, merged (x86-64).
// -------------------------------------------------------------------
//
// Five small GHASH field primitives merged under one selector; exactly one
// of the following must be defined before including this file:
//
//   CRYPTOLIB_GCMFIELD_PARTIAL       (ClpSimdProc3Begin: rcx = @X, rdx = @Y,
//     r8 = @TGcmPartial128 out) - 256-bit Karatsuba partial product
//     (Z0, Z1, Z2) of two GHASH field elements before degree reduction.
//     X.N0, X.N1 and Y.N0, Y.N1 are UInt64 GHASH field limbs (TFieldElement);
//     each limb is packed into xmm as high qword then low
//     (movq + punpcklqdq), little-endian 128-bit layout.
//   CRYPTOLIB_GCMFIELD_MULTIPLY_EXT  (ClpSimdProc3Begin: rcx = PX, rdx = PY,
//     r8 = POut48) - Karatsuba-style carryless multiply without reduction;
//     operands are 16-byte limbs (LE UInt64 pair each), output Z0, Z1, Z2
//     (48 bytes; no Z1 merge / reduction).
//   CRYPTOLIB_GCMFIELD_REDUCE3       (ClpSimdProc4Begin: rcx = PZ0, rdx = PZ1,
//     r8 = PZ2, r9 = POut) - fold Z1 into (Z0, Z2), then reduce the (Z0, Z2)
//     pair modulo the GCM polynomial x^128 + x^7 + x^2 + x + 1, writing the
//     16-byte field element to POut. Z0/Z1/Z2 are the three 128-bit limbs
//     carried across a batch of Karatsuba-style PCLMULQDQ GHASH products.
//   CRYPTOLIB_GCMFIELD_XOR_LIMBS48   (ClpSimdProc4Begin: rcx = PA0, rdx = PA1,
//     r8 = PA2, r9 = PSrc48) - xor 16-byte limbs in place:
//     *PA0 ^= PSrc[0..15], *PA1 ^= PSrc[16..31], *PA2 ^= PSrc[32..47].
//   CRYPTOLIB_GCMFIELD_BLOCK_REVERSE (ClpSimdProc3Begin: rcx = PDst,
//     rdx = PSrc, r8 = PShuffleCtrl) - [rcx] := pshufb([rdx], [r8])
//     (SSSE3 16-byte byte reverse).
//
// Unaligned movdqu throughout (stack buffers may be misaligned). PCLMULQDQ
// instructions are db-encoded for broad assembler compatibility.
//
// Reference: Shay Gueron / Michael E. Kounavis, "Intel(R) Carry-Less
// Multiplication Instruction and its Usage for Computing the GCM Mode"
// (white paper) - the 3-multiply carry-less Karatsuba split and the
// shift/XOR reduction implemented by the multiply / reduce ops.
{$IFDEF CRYPTOLIB_GCMFIELD_PARTIAL}
  movq      xmm0, qword ptr [rcx + 8]
  movq      xmm4, qword ptr [rcx]
  punpcklqdq xmm0, xmm4

  movq      xmm1, qword ptr [rdx + 8]
  movq      xmm4, qword ptr [rdx]
  punpcklqdq xmm1, xmm4

  movdqu    xmm2, xmm0
  db $66, $0F, $3A, $44, $D1, $00  // pclmulqdq xmm2, xmm1, 0

  movdqu    xmm3, xmm0
  db $66, $0F, $3A, $44, $D9, $01  // pclmulqdq xmm3, xmm1, 1
  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $10  // pclmulqdq xmm4, xmm1, 16
  pxor      xmm3, xmm4

  movdqu    xmm4, xmm0
  db $66, $0F, $3A, $44, $E1, $11  // pclmulqdq xmm4, xmm1, 17

  movdqu    xmm5, xmm3
  pslldq    xmm5, 8
  pxor      xmm2, xmm5
  movdqu    xmm5, xmm3
  psrldq    xmm5, 8
  pxor      xmm4, xmm5

  movq      qword ptr [r8 + 0], xmm2
  movdqu    xmm5, xmm2
  psrldq    xmm5, 8
  movq      qword ptr [r8 + 8], xmm5

  movq      qword ptr [r8 + 16], xmm4
  movdqu    xmm5, xmm4
  psrldq    xmm5, 8
  movq      qword ptr [r8 + 24], xmm5
{$ELSE}
  {$IFDEF CRYPTOLIB_GCMFIELD_MULTIPLY_EXT}
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
  {$ELSE}
    {$IFDEF CRYPTOLIB_GCMFIELD_REDUCE3}
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  movdqu    xmm0, [rcx]
  movdqu    xmm2, [r8]
  movdqu    xmm1, [rdx]
  movdqa    xmm4, xmm1
  movdqa    xmm5, xmm1
  pslldq    xmm4, 8
  psrldq    xmm5, 8
  pxor      xmm0, xmm4
  pxor      xmm2, xmm5
  movdqu    [rcx], xmm0
  movdqu    [r8], xmm2
  movdqu    xmm0, [rcx]
  movdqu    xmm2, [r8]
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
  movq      qword ptr [r9], xmm7
  movq      qword ptr [r9 + 8], xmm6
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
    {$ELSE}
      {$IFDEF CRYPTOLIB_GCMFIELD_XOR_LIMBS48}
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [r9]
  pxor      xmm0, xmm1
  movdqu    [rcx], xmm0

  movdqu    xmm0, [rdx]
  movdqu    xmm1, [r9 + 16]
  pxor      xmm0, xmm1
  movdqu    [rdx], xmm0

  movdqu    xmm0, [r8]
  movdqu    xmm1, [r9 + 32]
  pxor      xmm0, xmm1
  movdqu    [r8], xmm0
      {$ELSE}
        {$IFDEF CRYPTOLIB_GCMFIELD_BLOCK_REVERSE}
  movdqu    xmm0, [rdx]
  movdqu    xmm1, [r8]
  pshufb    xmm0, xmm1
  movdqu    [rcx], xmm0
        {$ELSE}
        {$FATAL Exactly one of CRYPTOLIB_GCMFIELD_PARTIAL, CRYPTOLIB_GCMFIELD_MULTIPLY_EXT, CRYPTOLIB_GCMFIELD_REDUCE3, CRYPTOLIB_GCMFIELD_XOR_LIMBS48, CRYPTOLIB_GCMFIELD_BLOCK_REVERSE must be defined before including this file}
        {$ENDIF}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
