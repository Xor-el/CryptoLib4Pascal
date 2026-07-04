// AES-NI 8-wide CTR keystream + XOR, single-pass fused kernel (x86-64).
// -------------------------------------------------------------------
//
// Fused counter-mode body for TSicBlockCipher's bulk path: generates 8
// consecutive AES-CTR keystream blocks and XORs them with the input in one
// register-resident pass (no scalar counter staging, no separate XOR pass).
// Replaces the three-pass Pascal path (FillNextCounterBlocks + bulk AES +
// TByteUtilities.Xor).
//
// Entry (after SimdProc5Begin_x86_64.inc):
//   rcx = input  (advances +128 per 8-block iteration)
//   rdx = output (advances +128)
//   r8  = AES encrypt round-key schedule (16-byte aligned; consumed by the
//         reused AesNiEightRoundsOnly body, which keeps r8 unchanged)
//   r9  = pointer to the 16-byte big-endian counter (updated in place on exit)
//   r10 = block count (NativeInt); MUST be a positive multiple of 8 (caller
//         guarantees it)
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt (CTR keystream), so CRYPTOLIB_AESNI_DECRYPT must
// NOT be defined when including this file.
//
// The 128-bit counter is held natively as r11 (high 64 bits) : rbx (low 64
// bits) across the whole span. Each counter block is built directly in its xmm
// lane: MOVQ writes the big-endian high half into bytes 0-7, PINSRQ writes the
// big-endian low half into bytes 8-15 - no memory round-trip. The low half is
// bumped with add/adc so carry propagates through the full 128 bits, matching
// SIC's big-endian whole-counter increment.
//
// Register/stack notes: rbx is callee-saved (push/pop). xmm6-15 are saved once
// via the shared core (the reused rounds body + the xmm8 XOR scratch touch the
// nonvolatile set). xmm8 is the round-key broadcast / plaintext-load scratch.
// MOVQ (r64->xmm) and PINSRQ are db-encoded for broad assembler compatibility,
// like the AES-NI ops.
  push      rbx
{$I ..\..\..\Include\Simd\Common\SimdNonVolatileSave_x86_64.inc}

  mov       r11, [r9]                             // high 64 bits (big-endian)
  bswap     r11
  mov       rbx, [r9 + 8]                         // low 64 bits (big-endian)
  bswap     rbx

@@CtrEightLoop:
  // ---- build 8 big-endian counter blocks straight into xmm0..7 ----
  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $C0                      // movq xmm0, rax  (hi -> [0..7])
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $C0, $01            // pinsrq xmm0, rax, 1  (lo -> [8..15])
  add       rbx, 1
  adc       r11, 0

  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $C8                      // movq xmm1, rax
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $C8, $01            // pinsrq xmm1, rax, 1
  add       rbx, 1
  adc       r11, 0

  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $D0                      // movq xmm2, rax
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $D0, $01            // pinsrq xmm2, rax, 1
  add       rbx, 1
  adc       r11, 0

  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $D8                      // movq xmm3, rax
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $D8, $01            // pinsrq xmm3, rax, 1
  add       rbx, 1
  adc       r11, 0

  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $E0                      // movq xmm4, rax
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $E0, $01            // pinsrq xmm4, rax, 1
  add       rbx, 1
  adc       r11, 0

  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $E8                      // movq xmm5, rax
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $E8, $01            // pinsrq xmm5, rax, 1
  add       rbx, 1
  adc       r11, 0

  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $F0                      // movq xmm6, rax
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $F0, $01            // pinsrq xmm6, rax, 1
  add       rbx, 1
  adc       r11, 0

  mov       rax, r11
  bswap     rax
  db $66, $48, $0F, $6E, $F8                      // movq xmm7, rax
  mov       rax, rbx
  bswap     rax
  db $66, $48, $0F, $3A, $22, $F8, $01            // pinsrq xmm7, rax, 1
  add       rbx, 1
  adc       r11, 0

  // ---- AES-encrypt the 8 raw counters (K_0 XOR happens inside) ----
{$I ..\..\..\Include\Simd\Aes\AesNiEightRoundsOnly_x86_64.inc}

  // ---- keystream ^ plaintext -> output (xmm8 = unaligned plaintext load) ----
  movdqu    xmm8, [rcx]
  db $66, $41, $0F, $EF, $C0                      // pxor xmm0, xmm8
  movdqu    [rdx], xmm0
  movdqu    xmm8, [rcx + 16]
  db $66, $41, $0F, $EF, $C8                      // pxor xmm1, xmm8
  movdqu    [rdx + 16], xmm1
  movdqu    xmm8, [rcx + 32]
  db $66, $41, $0F, $EF, $D0                      // pxor xmm2, xmm8
  movdqu    [rdx + 32], xmm2
  movdqu    xmm8, [rcx + 48]
  db $66, $41, $0F, $EF, $D8                      // pxor xmm3, xmm8
  movdqu    [rdx + 48], xmm3
  movdqu    xmm8, [rcx + 64]
  db $66, $41, $0F, $EF, $E0                      // pxor xmm4, xmm8
  movdqu    [rdx + 64], xmm4
  movdqu    xmm8, [rcx + 80]
  db $66, $41, $0F, $EF, $E8                      // pxor xmm5, xmm8
  movdqu    [rdx + 80], xmm5
  movdqu    xmm8, [rcx + 96]
  db $66, $41, $0F, $EF, $F0                      // pxor xmm6, xmm8
  movdqu    [rdx + 96], xmm6
  movdqu    xmm8, [rcx + 112]
  db $66, $41, $0F, $EF, $F8                      // pxor xmm7, xmm8
  movdqu    [rdx + 112], xmm7

  add       rcx, 128
  add       rdx, 128
  sub       r10, 8
  jnz       @@CtrEightLoop

  // ---- write the advanced counter back (big-endian) ----
  mov       rax, r11
  bswap     rax
  mov       [r9], rax
  mov       rax, rbx
  bswap     rax
  mov       [r9 + 8], rax

{$I ..\..\..\Include\Simd\Common\SimdNonVolatileRestore_x86_64.inc}
  pop       rbx
