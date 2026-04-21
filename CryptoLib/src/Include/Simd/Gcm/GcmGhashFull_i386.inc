// SSE2 + PCLMULQDQ fused N-way GHASH batch kernel (i386).
// -------------------------------------------------------------------
// One monolithic body that performs a full GHASH batch fold: for each
// block loads the (byte-reversed) ciphertext, XORs the running state
// into block 0, multiplies by the matching H power via four PCLMULQDQ
// products (Karatsuba), accumulates across blocks into three 128-bit
// limbs Z0/Z1/Z2, then folds Z1 and reduces (Z0, Z2) modulo the GCM
// polynomial x^128 + x^7 + x^2 + x + 1 to a single field element,
// byte-reverses, and stores back to PFS. i386 has only 8 XMM
// registers so the PSHUFB mask cannot stay pinned; it is reloaded
// from [eax] on every use.
//
// Variant selection (set EXACTLY ONE):
//   GCM_GHASH_FULL_BLOCKS_4  -> 4-block (64-byte) batch, H^4..H^1.
//   GCM_GHASH_FULL_BLOCKS_8  -> 8-block (128-byte) batch, H^8..H^1.
//
// On entry (after SimdProc4Begin_i386.inc):
//   ebx = PFS    (16-byte running GHASH state, canonical; in/out)
//   esi = PC0    (64 or 128 bytes ciphertext, canonical form)
//   edi = PHPow  (H^N..H^1 as 16-byte limbs, field form)
//   eax = PMask  (16-byte PSHUFB byte-reverse control)
//
// XMM (8/8 used):
//   xmm0..xmm2 : Z0 / Z1 / Z2 accumulators (persistent across blocks)
//   xmm3       : current byte-reversed data block
//   xmm4       : current H-power limb
//   xmm5..xmm7 : pclmul product destinations (per-block); xmm7 is also
//                reused as the byte-reverse mask (reloaded from [eax]
//                before each PSHUFB)
//
// PCLMULQDQ instructions are db-encoded for broad assembler compatibility.
//
  pxor      xmm0, xmm0
  pxor      xmm1, xmm1
  pxor      xmm2, xmm2

  // Block 0: byte-reverse + fold running state
  movdqu    xmm3, [esi]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm5, [ebx]
  pshufb    xmm5, xmm7
  pxor      xmm3, xmm5
  movdqu    xmm4, [edi]
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
  movdqu    xmm3, [esi + 16]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm4, [edi + 16]
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
  movdqu    xmm3, [esi + 32]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm4, [edi + 32]
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
  movdqu    xmm3, [esi + 48]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm4, [edi + 48]
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
  movdqu    xmm3, [esi + 64]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm4, [edi + 64]
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
  movdqu    xmm3, [esi + 80]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm4, [edi + 80]
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
  movdqu    xmm3, [esi + 96]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm4, [edi + 96]
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
  movdqu    xmm3, [esi + 112]
  movdqu    xmm7, [eax]
  pshufb    xmm3, xmm7
  movdqu    xmm4, [edi + 112]
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

  // Pack and byte-reverse.
  movq      xmm0, xmm7
  pslldq    xmm6, 8
  por       xmm0, xmm6
  movdqu    xmm7, [eax]
  pshufb    xmm0, xmm7
  movdqu    [ebx], xmm0

  pop edi
  pop esi
  pop ebx
