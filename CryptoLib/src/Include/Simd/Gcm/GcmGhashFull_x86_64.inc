// SSE2 + PCLMULQDQ fused N-way GHASH batch kernel (x86-64).
// -------------------------------------------------------------------
// One monolithic body that performs a full GHASH batch fold: for each
// block loads the (byte-reversed) ciphertext, XORs the running state
// into block 0, multiplies by the matching H power via four PCLMULQDQ
// products (Karatsuba), accumulates across blocks into three 128-bit
// limbs Z0/Z1/Z2, then folds Z1 and reduces (Z0, Z2) modulo the GCM
// polynomial x^128 + x^7 + x^2 + x + 1 to a single field element,
// byte-reverses, and stores back to PFS. Replaces the previous chain
// of 11 Pascal -> ASM calls (one byte-reverse per block, one XOR fold,
// multiply-accumulate, 3-limb reduction, byte-reverse back) with a
// single kernel.
//
// Variant selection (set EXACTLY ONE):
//   GCM_GHASH_FULL_BLOCKS_4  -> 4-block (64-byte) batch, H^4..H^1.
//   GCM_GHASH_FULL_BLOCKS_8  -> 8-block (128-byte) batch, H^8..H^1.
//
// On entry (after SimdProc4Begin_x86_64.inc):
//   rcx = PFS    (16-byte running GHASH state, canonical; in/out)
//   rdx = PC0    (64 or 128 bytes ciphertext, canonical form)
//   r8  = PHPow  (H^N..H^1 as 16-byte limbs, field form)
//   r9  = PMask  (16-byte PSHUFB byte-reverse control)
//
// XMM (9/16 used):
//   xmm0..xmm2 : Z0 / Z1 / Z2 accumulators (persistent across blocks)
//   xmm3       : current byte-reversed data block
//   xmm4       : current H-power limb
//   xmm5..xmm7 : pclmul product destinations (per-block)
//   xmm8       : byte-reverse mask (held for the whole kernel)
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

{$IFDEF GCM_GHASH_FULL_BLOCKS_8}
  // Block 4
  movdqu    xmm3, [rdx + 64]
  pshufb    xmm3, xmm8
  movdqu    xmm4, [r8 + 64]
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

  // Block 5
  movdqu    xmm3, [rdx + 80]
  pshufb    xmm3, xmm8
  movdqu    xmm4, [r8 + 80]
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

  // Block 6
  movdqu    xmm3, [rdx + 96]
  pshufb    xmm3, xmm8
  movdqu    xmm4, [r8 + 96]
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

  // Block 7
  movdqu    xmm3, [rdx + 112]
  pshufb    xmm3, xmm8
  movdqu    xmm4, [r8 + 112]
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
{$ENDIF GCM_GHASH_FULL_BLOCKS_8}

  // Inline 3-limb GHASH reduction (Z0=xmm0, Z1=xmm1, Z2=xmm2): fold Z1 into
  // (Z0, Z2), then reduce modulo x^128 + x^7 + x^2 + x + 1.
  // Step 1 -- fold Z1 into Z0/Z2.
  movdqa    xmm4, xmm1
  movdqa    xmm5, xmm1
  pslldq    xmm4, 8
  psrldq    xmm5, 8
  pxor      xmm0, xmm4
  pxor      xmm2, xmm5
  // Extract T3, T1 as lower-64 halves; T2, T0 as upper-64 halves.
  movq      xmm3, xmm0                         // xmm3 = T3 (low 64 of folded Z0)
  movq      xmm4, xmm2                         // xmm4 = T1 (low 64 of folded Z2)
  movdqa    xmm5, xmm3
  psrlq     xmm5, 1
  movdqa    xmm6, xmm3
  psrlq     xmm6, 2
  movdqa    xmm7, xmm3
  psrlq     xmm7, 7
  pxor      xmm4, xmm3
  pxor      xmm4, xmm5
  pxor      xmm4, xmm6
  pxor      xmm4, xmm7                         // xmm4 = T1 ^ T3 ^ (T3>>1) ^ (T3>>2) ^ (T3>>7)
  movdqa    xmm1, xmm0
  psrldq    xmm1, 8                            // xmm1 = T2 (upper 64 of folded Z0, now in lower)
  movdqa    xmm5, xmm3
  psllq     xmm5, 63
  movdqa    xmm6, xmm3
  psllq     xmm6, 62
  movdqa    xmm7, xmm3
  psllq     xmm7, 57
  pxor      xmm1, xmm5
  pxor      xmm1, xmm6
  pxor      xmm1, xmm7                         // xmm1 = T2 ^ (T3<<63) ^ (T3<<62) ^ (T3<<57)
  movdqa    xmm5, xmm2
  psrldq    xmm5, 8                            // xmm5 = T0 (upper 64 of folded Z2)
  movdqa    xmm6, xmm5
  psllq     xmm6, 1
  movdqa    xmm7, xmm4
  psrlq     xmm7, 63
  por       xmm6, xmm7                         // xmm6 = LZ0 initial = (T0<<1) | (T1>>63)
  movdqa    xmm7, xmm4
  psllq     xmm7, 1
  movdqa    xmm3, xmm1
  psrlq     xmm3, 63
  por       xmm7, xmm3                         // xmm7 = LZ1 initial = (T1<<1) | (T2>>63)
  movdqa    xmm0, xmm1
  psllq     xmm0, 1                            // xmm0 = LZ2 = T2<<1
  movdqa    xmm3, xmm0
  psrlq     xmm3, 1
  movdqa    xmm2, xmm0
  psrlq     xmm2, 2
  movdqa    xmm5, xmm0
  psrlq     xmm5, 7
  pxor      xmm6, xmm0
  pxor      xmm6, xmm3
  pxor      xmm6, xmm2
  pxor      xmm6, xmm5                         // xmm6 (low 64) = final LZ0
  movdqa    xmm3, xmm1
  psllq     xmm3, 63
  movdqa    xmm2, xmm1
  psllq     xmm2, 58
  pxor      xmm7, xmm3
  pxor      xmm7, xmm2                         // xmm7 (low 64) = final LZ1

  // Pack 16-byte result: bytes 0..7 = xmm7.q0, bytes 8..15 = xmm6.q0.
  movq      xmm0, xmm7
  pslldq    xmm6, 8
  por       xmm0, xmm6
  // Byte-reverse to canonical form and store to PFS.
  pshufb    xmm0, xmm8
  movdqu    [rcx], xmm0
