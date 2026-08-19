// GHASH field-op kernels, merged (x86-64).
// -------------------------------------------------------------------
//
// Two small GHASH field primitives merged under one selector; exactly one
// of the following must be defined before including this file:
//
//   CRYPTOLIB_GCMFIELD_PARTIAL       (ClpSimdProc3Begin: rcx = @X, rdx = @Y,
//     r8 = @TGcmPartial128 out) - 256-bit Karatsuba partial product
//     (Z0, Z1, Z2) of two GHASH field elements before degree reduction.
//     X.N0, X.N1 and Y.N0, Y.N1 are UInt64 GHASH field limbs (TFieldElement);
//     each limb is packed into xmm as high qword then low
//     (movq + punpcklqdq), little-endian 128-bit layout.
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
  {$IFDEF CRYPTOLIB_GCMFIELD_BLOCK_REVERSE}
  movdqu    xmm0, [rdx]
  movdqu    xmm1, [r8]
  pshufb    xmm0, xmm1
  movdqu    [rcx], xmm0
  {$ELSE}
  {$FATAL Exactly one of CRYPTOLIB_GCMFIELD_PARTIAL, CRYPTOLIB_GCMFIELD_BLOCK_REVERSE must be defined before including this file}
  {$ENDIF}
{$ENDIF}
