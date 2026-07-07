// AES-NI 8-wide CTR keystream + XOR, interleaved fused kernel (x86-64).
// -------------------------------------------------------------------
//
// Fused counter-mode body for TSicBlockCipher's bulk path: processes eight
// AES-CTR blocks per iteration, XORing the keystream with the input in one pass.
//
// Technique (Shay Gueron, "Intel AES New Instructions"): the eight cipher lanes
// live in xmm0..7 across the whole AES round chain, and the NEXT batch's eight
// counter blocks are materialised (to a 128-byte stack scratch) *interleaved
// between the aesenc rounds* of the current batch. The counter build is scalar
// (mov / bswap / add / adc on the integer ports) so it overlaps the aesenc
// throughput (vector port) instead of serialising ahead of it. The XOR with
// plaintext reuses xmm8 (the round-key scratch) after the final round.
//
// Entry (after SimdProc1Begin_x86_64.inc): rcx = pointer to TCtrFusedCtx. The
// kernel unpacks it (InPtr loaded into rcx last) into the working registers:
//   [rcx +  0]  InPtr      -> rcx : input  (advances +128 per 8-block iteration)
//   [rcx +  8]  OutPtr     -> rdx : output (advances +128)
//   [rcx + 16]  KeysPtr    -> r8  : AES encrypt round-key schedule (16-byte aligned)
//   [rcx + 24]  CounterPtr -> r9  : 16-byte big-endian counter (updated in place)
//   [rcx + 32]  BlockCount -> r10 : positive multiple of 8 (caller guarantees it)
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt (CTR keystream), so CRYPTOLIB_AESNI_DECRYPT must
// NOT be defined when including this file.
//
// The 128-bit counter is held natively as r11 (high 64 bits) : rbx (low 64 bits)
// across the whole span; the low half is bumped with add/adc so carry propagates
// through the full 128 bits, matching SIC's big-endian whole-counter increment.
// Each staged block writes bswap(r11) || bswap(rbx) (big-endian) to the scratch,
// then advances. The pipeline builds one batch ahead, so on exit the counter has
// over-run by exactly one batch (8) - undone before write-back.
//
// Register/stack notes: rbx is callee-saved (push/pop). xmm6-15 are saved once
// via the shared core (xmm8 is the round-key / plaintext-XOR scratch). A 128-byte
// stack scratch below the xmm save area holds the next batch's counter blocks.
// AES-NI instructions and pxor forms touching xmm8 are db-encoded for broad
// assembler compatibility.
  push      rbx
{$I ..\..\..\Include\Simd\Common\SimdNonVolatileSave_x86_64.inc}
  sub       rsp, 128                              // next-batch counter scratch: [rsp+0..127]

  // ---- unpack TCtrFusedCtx (rcx = PCtx); load InPtr into rcx last ----
  mov       r8, [rcx + 16]                        // KeysPtr
  mov       r9, [rcx + 24]                        // CounterPtr
  mov       r10, [rcx + 32]                       // BlockCount
  mov       rdx, [rcx + 8]                        // OutPtr
  mov       rcx, [rcx + 0]                        // InPtr (overwrites PCtx)

  mov       r11, [r9]                             // counter high 64 bits (big-endian)
  bswap     r11
  mov       rbx, [r9 + 8]                         // counter low 64 bits (big-endian)
  bswap     rbx

  // ---- stage batch 0 into the scratch, then load it into xmm0..7 ----
  mov       rax, r11
  bswap     rax
  mov       [rsp + 0], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 8], rax
  add       rbx, 1
  adc       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [rsp + 16], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 24], rax
  add       rbx, 1
  adc       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [rsp + 32], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 40], rax
  add       rbx, 1
  adc       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [rsp + 48], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 56], rax
  add       rbx, 1
  adc       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [rsp + 64], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 72], rax
  add       rbx, 1
  adc       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [rsp + 80], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 88], rax
  add       rbx, 1
  adc       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [rsp + 96], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 104], rax
  add       rbx, 1
  adc       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [rsp + 112], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 120], rax
  add       rbx, 1
  adc       r11, 0

  movdqu    xmm0, [rsp]
  movdqu    xmm1, [rsp + 16]
  movdqu    xmm2, [rsp + 32]
  movdqu    xmm3, [rsp + 48]
  movdqu    xmm4, [rsp + 64]
  movdqu    xmm5, [rsp + 80]
  movdqu    xmm6, [rsp + 96]
  movdqu    xmm7, [rsp + 112]

@@CtrEightLoop:
  // ---- round 0: whiten with K_0 ----
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0                      // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8                      // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0                      // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8                      // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0                      // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8                      // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0                      // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8                      // pxor xmm7, xmm8

  // ---- rounds 1..8: aesenc, each interleaved with staging one next counter ----
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 0], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 8], rax
  add       rbx, 1
  adc       r11, 0

  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 16], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 24], rax
  add       rbx, 1
  adc       r11, 0

  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 32], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 40], rax
  add       rbx, 1
  adc       r11, 0

  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 48], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 56], rax
  add       rbx, 1
  adc       r11, 0

  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 64], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 72], rax
  add       rbx, 1
  adc       r11, 0

  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 80], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 88], rax
  add       rbx, 1
  adc       r11, 0

  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 96], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 104], rax
  add       rbx, 1
  adc       r11, 0

  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       rax, r11
  bswap     rax
  mov       [rsp + 112], rax
  mov       rax, rbx
  bswap     rax
  mov       [rsp + 120], rax
  add       rbx, 1
  adc       r11, 0

  // ---- round 9 (all key sizes): aesenc, no more staging ----
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8

{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
{$IFEND}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
{$ENDIF}

  // ---- final round: aesenclast on the last round key ----
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8 + 224]
{$ENDIF}
  db $66, $41, $0F, $38, $DD, $C0                 // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8                 // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0                 // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8                 // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0                 // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8                 // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0                 // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8                 // aesenclast xmm7, xmm8

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

  // ---- load the staged next-batch counters into xmm0..7 ----
  movdqu    xmm0, [rsp]
  movdqu    xmm1, [rsp + 16]
  movdqu    xmm2, [rsp + 32]
  movdqu    xmm3, [rsp + 48]
  movdqu    xmm4, [rsp + 64]
  movdqu    xmm5, [rsp + 80]
  movdqu    xmm6, [rsp + 96]
  movdqu    xmm7, [rsp + 112]

  add       rcx, 128
  add       rdx, 128
  sub       r10, 8
  jnz       @@CtrEightLoop

  // ---- undo the one-batch build-ahead, write the counter back (big-endian) ----
  sub       rbx, 8
  sbb       r11, 0
  mov       rax, r11
  bswap     rax
  mov       [r9], rax
  mov       rax, rbx
  bswap     rax
  mov       [r9 + 8], rax

  add       rsp, 128
{$I ..\..\..\Include\Simd\Common\SimdNonVolatileRestore_x86_64.inc}
  pop       rbx
