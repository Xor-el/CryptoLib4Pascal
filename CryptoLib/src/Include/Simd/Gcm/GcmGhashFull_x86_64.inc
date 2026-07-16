// SSE2 + PCLMULQDQ N-way GHASH batch kernel (x86-64).
// -------------------------------------------------------------------
// Loops over ABatchCount batches inside the asm body. Per batch: for each
// block loads the (byte-reversed) data, XORs the running state into
// block 0, multiplies by the matching H power via four PCLMULQDQ products,
// accumulates across blocks into three 128-bit limbs Z0/Z1/Z2, then folds
// Z1 and reduces with two carry-less multiplies by the folded constant
// 0xC2000000_00000000 (PHPow holds the powers PRE-MULTIPLIED BY x in the
// reflected representation - see TGcmUtilities.InitEightWayHPowFromH - so
// no bit-shift correction is needed). The running state stays reflected
// across batches; the canonical byte order is only touched at entry/exit,
// and the nonvolatile save, mask load and reduction constant are paid
// once per call instead of once per batch.
//
// Variant selection (set EXACTLY ONE of the block counts):
//   GCM_GHASH_FULL_BLOCKS_4  -> 4-block (64-byte) batches, H^4..H^1.
//   GCM_GHASH_FULL_BLOCKS_8  -> 8-block (128-byte) batches, H^8..H^1.
// Optional:
//   GCM_GHASH_RAW_INPUT      -> the data blocks are already in field form, so
//                              skip the per-block input byte-reverse. Used by the
//                              GCM-SIV POLYVAL kernel, which supplies raw blocks;
//                              the running-state load and the final store are
//                              still byte-reversed. Unset for GCM (canonical
//                              input), leaving that path byte-identical.
//
// On entry (after ClpSimdProc5Begin_x86_64.inc):
//   rcx = PFS    (16-byte running GHASH state, canonical; in/out)
//   rdx = PC0    (data blocks; canonical, or field form with RAW_INPUT; advances)
//   r8  = PHPow  (H^N..H^1 as 16-byte limbs, x-pre-multiplied)
//   r9  = PMask  (16-byte PSHUFB byte-reverse control)
//   r10 = ABatchCount (> 0)
//
// XMM (10/16 used): xmm0..xmm2 = Z0/Z1/Z2, xmm3 = data block / reduction
// constant, xmm4..xmm7 = scratch, xmm8 = mask (whole call), xmm9 =
// reflected running state (whole call). [rsp] (16-aligned) holds the
// reduction constant.
//
// PCLMULQDQ / PSHUFD and pxor forms touching xmm8/xmm9 are db-encoded
// for broad assembler compatibility.
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  sub       rsp, 24                             // [rsp] 16-aligned
  mov       rax, $C200000000000000
  mov       [rsp], rax                          // reduction constant (low qword)
  xor       eax, eax
  mov       [rsp + 8], rax
  movdqu    xmm8, [r9]                          // byte-reverse mask
  movdqu    xmm9, [rcx]
  pshufb    xmm9, xmm8                          // reflected running state

@@GhashFullLoop:
  pxor      xmm0, xmm0                          // Z0 = 0
  pxor      xmm1, xmm1                          // Z1 = 0
  pxor      xmm2, xmm2                          // Z2 = 0

  // Block 0 (folds the carried state)
  movdqu    xmm3, [rdx]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  db $66, $41, $0F, $EF, $D9                    // pxor xmm3, xmm9 (fold carried state)
  movdqu    xmm4, [r8]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=

  // Block 1 (folds the carried state)
  movdqu    xmm3, [rdx + 16]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  movdqu    xmm4, [r8 + 16]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=

  // Block 2 (folds the carried state)
  movdqu    xmm3, [rdx + 32]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  movdqu    xmm4, [r8 + 32]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=

  // Block 3 (folds the carried state)
  movdqu    xmm3, [rdx + 48]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  movdqu    xmm4, [r8 + 48]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=
{$IFDEF GCM_GHASH_FULL_BLOCKS_8}

  // Block 4 (folds the carried state)
  movdqu    xmm3, [rdx + 64]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  movdqu    xmm4, [r8 + 64]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=

  // Block 5 (folds the carried state)
  movdqu    xmm3, [rdx + 80]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  movdqu    xmm4, [r8 + 80]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=

  // Block 6 (folds the carried state)
  movdqu    xmm3, [rdx + 96]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  movdqu    xmm4, [r8 + 96]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=

  // Block 7 (folds the carried state)
  movdqu    xmm3, [rdx + 112]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  pshufb    xmm3, xmm8
{$ENDIF}
  movdqu    xmm4, [r8 + 112]
  movdqa    xmm5, xmm3
  db $66, $0F, $3A, $44, $EC, $00               // pclmulqdq xmm5, xmm4, 0x00
  movdqa    xmm6, xmm3
  db $66, $0F, $3A, $44, $F4, $01               // pclmulqdq xmm6, xmm4, 0x01
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $10               // pclmulqdq xmm7, xmm4, 0x10
  pxor      xmm6, xmm7
  movdqa    xmm7, xmm3
  db $66, $0F, $3A, $44, $FC, $11               // pclmulqdq xmm7, xmm4, 0x11
  pxor      xmm0, xmm5                          // Z0 +=
  pxor      xmm1, xmm6                          // Z1 +=
  pxor      xmm2, xmm7                          // Z2 +=
{$ENDIF GCM_GHASH_FULL_BLOCKS_8}

  // --- Reduce [Z2:Z1:Z0] modulo the field polynomial: fold Z1 into
  //     the 256-bit product, then two carry-less multiplies by the
  //     folded constant 0xC2000000_00000000 (the H powers are
  //     pre-multiplied by x, so no bit-shift correction is needed). ---
  movdqa    xmm3, [rsp]
  movdqa    xmm4, xmm1
  pslldq    xmm4, 8
  pxor      xmm0, xmm4                         // ZLo ^= Z1 << 64
  movdqa    xmm5, xmm1
  psrldq    xmm5, 8
  pxor      xmm2, xmm5                         // ZHi ^= Z1 >> 64
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E3, $00               // pclmulqdq xmm4, xmm3, 0x00
  db $66, $0F, $70, $C0, $4E                    // pshufd xmm0, xmm0, 0x4E (swap halves)
  pxor      xmm0, xmm4                         // fold 1
  movdqa    xmm4, xmm0
  db $66, $0F, $3A, $44, $E3, $00               // pclmulqdq xmm4, xmm3, 0x00
  db $66, $0F, $70, $C0, $4E                    // pshufd xmm0, xmm0, 0x4E (swap halves)
  pxor      xmm0, xmm4                         // fold 2
  pxor      xmm0, xmm2                         // ^= ZHi -> reflected state
  movdqa    xmm9, xmm0                         // carry state to the next batch

{$IFDEF GCM_GHASH_FULL_BLOCKS_8}
  add       rdx, 128
{$ELSE}
  add       rdx, 64
{$ENDIF}
  dec       r10
  jnz       @@GhashFullLoop

  pshufb    xmm9, xmm8                          // reflected -> canonical
  movdqu    [rcx], xmm9
  add       rsp, 24
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

