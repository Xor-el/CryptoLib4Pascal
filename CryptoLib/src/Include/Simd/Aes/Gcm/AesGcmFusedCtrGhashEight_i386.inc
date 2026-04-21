// Fused AES-NI CTR keystream + 8-way GHASH kernel (i386).
// -------------------------------------------------------------------
// Technique: Shay Gueron, "Intel AES New Instructions" Rev 3.01 - AES
// and PCLMULQDQ instructions are interleaved so the AES port (p0 on
// Skylake+/Zen+) and the PCLMUL port (p5) operate in parallel, hiding
// GHASH latency inside the AES critical path.
//
// Processes one pipelined batch: AES encrypts eight counter blocks to
// produce a keystream, XORs it with PXorIn to produce POut, and
// concurrently GHASHes the PREVIOUS batch's 8 ciphertext blocks into
// the running authentication state. AES inside GCM is always CTR
// keystream construction; the Pascal wrapper picks which buffers
// become PXorIn / POut / PPrevCipher for encrypt vs decrypt. The 8-xmm
// budget does not fit a single-pass 8-wide layout, so the kernel
// processes the batch as two back-to-back 4-block halves sharing the
// same running Z0/Z1/Z2 accumulators; each half packs 4 GHASH iters
// into AES rounds 1..4 to keep both ports busy, rounds 5..N-1 are
// AES-only, and the 3-limb reduction runs once after half 2.
//
// Variant selection (set EXACTLY ONE):
//   GCM_FUSED_AES_ROUNDS_10  -> AES-128 (schedule = 11 x 16 bytes).
//   GCM_FUSED_AES_ROUNDS_12  -> AES-192 (schedule = 13 x 16 bytes).
//   GCM_FUSED_AES_ROUNDS_14  -> AES-256 (schedule = 15 x 16 bytes).
//
// On entry (after SimdProc1Begin_i386.inc): ebx = PCtx.
//
// Context layout (8 pointers = 32 bytes, 4-byte aligned). See
// TGcmFusedBatchCtx in ClpAesNiGcmKernel.pas.
//   [ebx +  0]  PXorIn      : 128-byte input to XOR with keystream
//   [ebx +  4]  POut        : 128-byte output buffer (may alias PXorIn)
//   [ebx +  8]  PCtrCurr    : 8 counter blocks (128 bytes) to encrypt
//   [ebx + 12]  PPrevCipher : 128 bytes prev-batch ciphertext for GHASH
//   [ebx + 16]  PRoundKeys  : AES encrypt round-key schedule (16-byte aligned)
//   [ebx + 20]  PHPow128    : H^8..H^1, eight 16-byte limbs (field form)
//   [ebx + 24]  PFS         : 16-byte running GHASH state (in/out, canonical)
//   [ebx + 28]  PMask       : 16-byte PSHUFB byte-reverse mask
//
// XMM (8/8 used; i386 has only xmm0..xmm7):
//   xmm0..xmm3 : 4 AES keystream lanes (per half; reloaded between halves)
//   xmm4       : GHASH block cache (byte-reversed prev-cipher block, per iter)
//   xmm5       : current H-power limb (per iter)
//   xmm6       : pclmul product destination (re-inited from xmm4 per imm)
//   xmm7       : transient scratch (byte-reverse mask, then Z-reload fold)
//
// Stack scratch (64 bytes, base unaligned - movdqu only):
//   [esp +  0..15]  Z0 accumulator  (updated 8x per batch)
//   [esp + 16..31]  Z1 accumulator  (updated 16x per batch; imm=1 + imm=16)
//   [esp + 32..47]  Z2 accumulator  (updated 8x per batch)
//   [esp + 48..63]  byte-reversed PFS (computed once, folded into iter 0)
//
// AES-NI (aesenc / aesenclast) and PCLMULQDQ instructions are db-encoded
// for broad assembler compatibility.
// -------------------------------------------------------------------

  // --- Callee-save prologue. SimdProc1Begin_i386.inc already pushed ebx
  //     and moved PCtx into ebx, so this block only pushes the other
  //     three callee-saved GPRs and reserves the Z / br(PFS) scratch. ---
  push      edi
  push      esi
  push      ebp
  sub       esp, 64

  // --- Load context pointers. ---
  mov       edi, [ebx + 16]                   // edi = PRoundKeys (pinned)
  mov       esi, [ebx + 12]                   // esi = PPrevCipher (pinned base)
  mov       ebp, [ebx + 20]                   // ebp = PHPow128 (pinned base)
  mov       ecx, [ebx + 28]                   // ecx = PMask (pinned)

  // --- Zero Z0 / Z1 / Z2 accumulator slots. ---
  pxor      xmm0, xmm0
  movdqu    [esp +  0], xmm0                  // Z0 = 0
  movdqu    [esp + 16], xmm0                  // Z1 = 0
  movdqu    [esp + 32], xmm0                  // Z2 = 0

  // --- Compute byte-reversed running state once, stash for iter-0 fold. ---
  mov       eax, [ebx + 24]                   // eax = PFS
  movdqu    xmm0, [eax]                       // load canonical PFS
  movdqu    xmm7, [ecx]                       // mask
  pshufb    xmm0, xmm7                        // byte-reverse
  movdqu    [esp + 48], xmm0                  // stash byte-reversed PFS

  // --- Load 4 counter blocks for HALF 1 (blocks 0..3). ---
  mov       eax, [ebx + 8]                    // eax = PCtrCurr
  movdqu    xmm0, [eax +  0]
  movdqu    xmm1, [eax + 16]
  movdqu    xmm2, [eax + 32]
  movdqu    xmm3, [eax + 48]

  // ======================================================================
  // HALF 1: blocks 0..3, GHASH iters 0..3 (prev_cipher[0..3], H^8..H^5)
  //         iter 0 additionally folds byte-reversed PFS into the block.
  // ======================================================================

  // --- Round 0: AddRoundKey (pxor with rk[0]). Round keys are aligned. ---
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]

  // --- Round 1 + GHASH iter 0 (with state fold). ---
  db $66, $0F, $38, $DC, $47, $10              // aesenc     xmm0, [edi+0x10]
  db $66, $0F, $38, $DC, $4F, $10              // aesenc     xmm1, [edi+0x10]
  db $66, $0F, $38, $DC, $57, $10              // aesenc     xmm2, [edi+0x10]
  db $66, $0F, $38, $DC, $5F, $10              // aesenc     xmm3, [edi+0x10]

  // GHASH iter 0: block 0 byte-reverse + state fold
  movdqu    xmm4, [esi + 0]                    // prev cipher block 0
  movdqu    xmm7, [ecx]                        // mask
  pshufb    xmm4, xmm7                         // byte-reverse
  movdqu    xmm7, [esp + 48]                   // byte-reversed PFS
  pxor      xmm4, xmm7                         // fold running state
  movdqu    xmm5, [ebp + 0]                    // H^8

  // 4 pclmul -> Z0 (imm=0), Z1 (imm=1), Z1 (imm=16), Z2 (imm=17).
  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7                    // Z0 +=

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7                   // Z1 +=

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7                   // Z1 +=

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7                   // Z2 +=

  // --- Round 2 + GHASH iter 1. ---
  db $66, $0F, $38, $DC, $47, $20              // aesenc     xmm0, [edi+0x20]
  db $66, $0F, $38, $DC, $4F, $20              // aesenc     xmm1, [edi+0x20]
  db $66, $0F, $38, $DC, $57, $20              // aesenc     xmm2, [edi+0x20]
  db $66, $0F, $38, $DC, $5F, $20              // aesenc     xmm3, [edi+0x20]

  movdqu    xmm4, [esi + 16]                   // prev cipher block 1
  movdqu    xmm7, [ecx]
  pshufb    xmm4, xmm7
  movdqu    xmm5, [ebp + 16]                   // H^7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7

  // --- Round 3 + GHASH iter 2. ---
  db $66, $0F, $38, $DC, $47, $30              // aesenc     xmm0, [edi+0x30]
  db $66, $0F, $38, $DC, $4F, $30              // aesenc     xmm1, [edi+0x30]
  db $66, $0F, $38, $DC, $57, $30              // aesenc     xmm2, [edi+0x30]
  db $66, $0F, $38, $DC, $5F, $30              // aesenc     xmm3, [edi+0x30]

  movdqu    xmm4, [esi + 32]                   // prev cipher block 2
  movdqu    xmm7, [ecx]
  pshufb    xmm4, xmm7
  movdqu    xmm5, [ebp + 32]                   // H^6

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7

  // --- Round 4 + GHASH iter 3 (last GHASH iter of half 1). ---
  db $66, $0F, $38, $DC, $47, $40              // aesenc     xmm0, [edi+0x40]
  db $66, $0F, $38, $DC, $4F, $40              // aesenc     xmm1, [edi+0x40]
  db $66, $0F, $38, $DC, $57, $40              // aesenc     xmm2, [edi+0x40]
  db $66, $0F, $38, $DC, $5F, $40              // aesenc     xmm3, [edi+0x40]

  movdqu    xmm4, [esi + 48]                   // prev cipher block 3
  movdqu    xmm7, [ecx]
  pshufb    xmm4, xmm7
  movdqu    xmm5, [ebp + 48]                   // H^5

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7

  // --- Rounds 5..Nr-1 (variant-specific): AES-only. ---

  // Round 5 (disp8 = 80)
  db $66, $0F, $38, $DC, $47, $50              // aesenc     xmm0, [edi+0x50]
  db $66, $0F, $38, $DC, $4F, $50              // aesenc     xmm1, [edi+0x50]
  db $66, $0F, $38, $DC, $57, $50              // aesenc     xmm2, [edi+0x50]
  db $66, $0F, $38, $DC, $5F, $50              // aesenc     xmm3, [edi+0x50]
  // Round 6 (disp8 = 96)
  db $66, $0F, $38, $DC, $47, $60              // aesenc     xmm0, [edi+0x60]
  db $66, $0F, $38, $DC, $4F, $60              // aesenc     xmm1, [edi+0x60]
  db $66, $0F, $38, $DC, $57, $60              // aesenc     xmm2, [edi+0x60]
  db $66, $0F, $38, $DC, $5F, $60              // aesenc     xmm3, [edi+0x60]
  // Round 7 (disp8 = 112)
  db $66, $0F, $38, $DC, $47, $70              // aesenc     xmm0, [edi+0x70]
  db $66, $0F, $38, $DC, $4F, $70              // aesenc     xmm1, [edi+0x70]
  db $66, $0F, $38, $DC, $57, $70              // aesenc     xmm2, [edi+0x70]
  db $66, $0F, $38, $DC, $5F, $70              // aesenc     xmm3, [edi+0x70]
  // Round 8 (disp32 = 128)
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+0x80]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00   // aesenc xmm1, [edi+0x80]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00   // aesenc xmm2, [edi+0x80]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00   // aesenc xmm3, [edi+0x80]
  // Round 9 (disp32 = 144)
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+0x90]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00   // aesenc xmm1, [edi+0x90]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00   // aesenc xmm2, [edi+0x90]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00   // aesenc xmm3, [edi+0x90]

{$IF DEFINED(GCM_FUSED_AES_ROUNDS_12) OR DEFINED(GCM_FUSED_AES_ROUNDS_14)}
  // Round 10 (disp32 = 160)
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+0xA0]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00   // aesenc xmm1, [edi+0xA0]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00   // aesenc xmm2, [edi+0xA0]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00   // aesenc xmm3, [edi+0xA0]
  // Round 11 (disp32 = 176)
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+0xB0]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00   // aesenc xmm1, [edi+0xB0]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00   // aesenc xmm2, [edi+0xB0]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00   // aesenc xmm3, [edi+0xB0]
{$IFEND}

{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  // Round 12 (disp32 = 192)
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+0xC0]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00   // aesenc xmm1, [edi+0xC0]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00   // aesenc xmm2, [edi+0xC0]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00   // aesenc xmm3, [edi+0xC0]
  // Round 13 (disp32 = 208)
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+0xD0]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00   // aesenc xmm1, [edi+0xD0]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00   // aesenc xmm2, [edi+0xD0]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00   // aesenc xmm3, [edi+0xD0]
{$ENDIF}

  // --- Final AES round (aesenclast on rk[Nr]). ---
{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  // AES-128: aesenclast at disp32 = 160
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+0xA0]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00   // aesenclast xmm1, [edi+0xA0]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00   // aesenclast xmm2, [edi+0xA0]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00   // aesenclast xmm3, [edi+0xA0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_12}
  // AES-192: aesenclast at disp32 = 192
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+0xC0]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00   // aesenclast xmm1, [edi+0xC0]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00   // aesenclast xmm2, [edi+0xC0]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00   // aesenclast xmm3, [edi+0xC0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  // AES-256: aesenclast at disp32 = 224
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+0xE0]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00   // aesenclast xmm1, [edi+0xE0]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00   // aesenclast xmm2, [edi+0xE0]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00   // aesenclast xmm3, [edi+0xE0]
{$ENDIF}

  // --- Post-AES (half 1): XOR with PXorIn[0..48] and store to POut[0..48]. ---
  mov       eax, [ebx + 0]                    // eax = PXorIn
  mov       edx, [ebx + 4]                    // edx = POut

  movdqu    xmm7, [eax + 0]
  pxor      xmm0, xmm7
  movdqu    [edx + 0], xmm0
  movdqu    xmm7, [eax + 16]
  pxor      xmm1, xmm7
  movdqu    [edx + 16], xmm1
  movdqu    xmm7, [eax + 32]
  pxor      xmm2, xmm7
  movdqu    [edx + 32], xmm2
  movdqu    xmm7, [eax + 48]
  pxor      xmm3, xmm7
  movdqu    [edx + 48], xmm3

  // ======================================================================
  // HALF 2: blocks 4..7, GHASH iters 4..7 (prev_cipher[4..7], H^4..H^1)
  //         no state fold (already consumed by iter 0 of half 1).
  // ======================================================================

  // --- Load 4 counter blocks for half 2 (blocks 4..7). ---
  mov       eax, [ebx + 8]                    // eax = PCtrCurr
  movdqu    xmm0, [eax + 64]
  movdqu    xmm1, [eax + 80]
  movdqu    xmm2, [eax + 96]
  movdqu    xmm3, [eax + 112]

  // --- Round 0: AddRoundKey. ---
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]

  // --- Round 1 + GHASH iter 4. ---
  db $66, $0F, $38, $DC, $47, $10              // aesenc     xmm0, [edi+0x10]
  db $66, $0F, $38, $DC, $4F, $10              // aesenc     xmm1, [edi+0x10]
  db $66, $0F, $38, $DC, $57, $10              // aesenc     xmm2, [edi+0x10]
  db $66, $0F, $38, $DC, $5F, $10              // aesenc     xmm3, [edi+0x10]

  movdqu    xmm4, [esi + 64]                   // prev cipher block 4
  movdqu    xmm7, [ecx]
  pshufb    xmm4, xmm7
  movdqu    xmm5, [ebp + 64]                   // H^4

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7

  // --- Round 2 + GHASH iter 5. ---
  db $66, $0F, $38, $DC, $47, $20              // aesenc     xmm0, [edi+0x20]
  db $66, $0F, $38, $DC, $4F, $20              // aesenc     xmm1, [edi+0x20]
  db $66, $0F, $38, $DC, $57, $20              // aesenc     xmm2, [edi+0x20]
  db $66, $0F, $38, $DC, $5F, $20              // aesenc     xmm3, [edi+0x20]

  movdqu    xmm4, [esi + 80]                   // prev cipher block 5
  movdqu    xmm7, [ecx]
  pshufb    xmm4, xmm7
  movdqu    xmm5, [ebp + 80]                   // H^3

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7

  // --- Round 3 + GHASH iter 6. ---
  db $66, $0F, $38, $DC, $47, $30              // aesenc     xmm0, [edi+0x30]
  db $66, $0F, $38, $DC, $4F, $30              // aesenc     xmm1, [edi+0x30]
  db $66, $0F, $38, $DC, $57, $30              // aesenc     xmm2, [edi+0x30]
  db $66, $0F, $38, $DC, $5F, $30              // aesenc     xmm3, [edi+0x30]

  movdqu    xmm4, [esi + 96]                   // prev cipher block 6
  movdqu    xmm7, [ecx]
  pshufb    xmm4, xmm7
  movdqu    xmm5, [ebp + 96]                   // H^2

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7

  // --- Round 4 + GHASH iter 7 (last GHASH iter of batch). ---
  db $66, $0F, $38, $DC, $47, $40              // aesenc     xmm0, [edi+0x40]
  db $66, $0F, $38, $DC, $4F, $40              // aesenc     xmm1, [edi+0x40]
  db $66, $0F, $38, $DC, $57, $40              // aesenc     xmm2, [edi+0x40]
  db $66, $0F, $38, $DC, $5F, $40              // aesenc     xmm3, [edi+0x40]

  movdqu    xmm4, [esi + 112]                  // prev cipher block 7
  movdqu    xmm7, [ecx]
  pshufb    xmm4, xmm7
  movdqu    xmm5, [ebp + 112]                  // H^1

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $00              // pclmulqdq  xmm6, xmm5, 0x00
  movdqu    xmm7, [esp + 0]
  pxor      xmm7, xmm6
  movdqu    [esp + 0], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $01              // pclmulqdq  xmm6, xmm5, 0x01
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $10              // pclmulqdq  xmm6, xmm5, 0x10
  movdqu    xmm7, [esp + 16]
  pxor      xmm7, xmm6
  movdqu    [esp + 16], xmm7

  movdqa    xmm6, xmm4
  db $66, $0F, $3A, $44, $F5, $11              // pclmulqdq  xmm6, xmm5, 0x11
  movdqu    xmm7, [esp + 32]
  pxor      xmm7, xmm6
  movdqu    [esp + 32], xmm7

  // --- Rounds 5..Nr-1 AES-only (variant-specific). ---
  // Round 5 (disp8 = 80)
  db $66, $0F, $38, $DC, $47, $50              // aesenc     xmm0, [edi+0x50]
  db $66, $0F, $38, $DC, $4F, $50              // aesenc     xmm1, [edi+0x50]
  db $66, $0F, $38, $DC, $57, $50              // aesenc     xmm2, [edi+0x50]
  db $66, $0F, $38, $DC, $5F, $50              // aesenc     xmm3, [edi+0x50]
  // Round 6 (disp8 = 96)
  db $66, $0F, $38, $DC, $47, $60              // aesenc     xmm0, [edi+0x60]
  db $66, $0F, $38, $DC, $4F, $60              // aesenc     xmm1, [edi+0x60]
  db $66, $0F, $38, $DC, $57, $60              // aesenc     xmm2, [edi+0x60]
  db $66, $0F, $38, $DC, $5F, $60              // aesenc     xmm3, [edi+0x60]
  // Round 7 (disp8 = 112)
  db $66, $0F, $38, $DC, $47, $70              // aesenc     xmm0, [edi+0x70]
  db $66, $0F, $38, $DC, $4F, $70              // aesenc     xmm1, [edi+0x70]
  db $66, $0F, $38, $DC, $57, $70              // aesenc     xmm2, [edi+0x70]
  db $66, $0F, $38, $DC, $5F, $70              // aesenc     xmm3, [edi+0x70]
  // Round 8 (disp32 = 128)
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+0x80]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00   // aesenc xmm1, [edi+0x80]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00   // aesenc xmm2, [edi+0x80]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00   // aesenc xmm3, [edi+0x80]
  // Round 9 (disp32 = 144)
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+0x90]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00   // aesenc xmm1, [edi+0x90]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00   // aesenc xmm2, [edi+0x90]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00   // aesenc xmm3, [edi+0x90]

{$IF DEFINED(GCM_FUSED_AES_ROUNDS_12) OR DEFINED(GCM_FUSED_AES_ROUNDS_14)}
  // Round 10 (disp32 = 160)
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+0xA0]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00   // aesenc xmm1, [edi+0xA0]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00   // aesenc xmm2, [edi+0xA0]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00   // aesenc xmm3, [edi+0xA0]
  // Round 11 (disp32 = 176)
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+0xB0]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00   // aesenc xmm1, [edi+0xB0]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00   // aesenc xmm2, [edi+0xB0]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00   // aesenc xmm3, [edi+0xB0]
{$IFEND}

{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  // Round 12 (disp32 = 192)
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+0xC0]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00   // aesenc xmm1, [edi+0xC0]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00   // aesenc xmm2, [edi+0xC0]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00   // aesenc xmm3, [edi+0xC0]
  // Round 13 (disp32 = 208)
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+0xD0]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00   // aesenc xmm1, [edi+0xD0]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00   // aesenc xmm2, [edi+0xD0]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00   // aesenc xmm3, [edi+0xD0]
{$ENDIF}

  // --- Final AES round (aesenclast) for half 2. ---
{$IFDEF GCM_FUSED_AES_ROUNDS_10}
  // AES-128: aesenclast at disp32 = 160
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+0xA0]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00   // aesenclast xmm1, [edi+0xA0]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00   // aesenclast xmm2, [edi+0xA0]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00   // aesenclast xmm3, [edi+0xA0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_12}
  // AES-192: aesenclast at disp32 = 192
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+0xC0]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00   // aesenclast xmm1, [edi+0xC0]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00   // aesenclast xmm2, [edi+0xC0]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00   // aesenclast xmm3, [edi+0xC0]
{$ENDIF}
{$IFDEF GCM_FUSED_AES_ROUNDS_14}
  // AES-256: aesenclast at disp32 = 224
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+0xE0]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00   // aesenclast xmm1, [edi+0xE0]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00   // aesenclast xmm2, [edi+0xE0]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00   // aesenclast xmm3, [edi+0xE0]
{$ENDIF}

  // --- Post-AES (half 2): XOR with PXorIn[64..112] and store POut[64..112]. ---
  mov       eax, [ebx + 0]                    // eax = PXorIn
  mov       edx, [ebx + 4]                    // edx = POut

  movdqu    xmm7, [eax + 64]
  pxor      xmm0, xmm7
  movdqu    [edx + 64], xmm0
  movdqu    xmm7, [eax + 80]
  pxor      xmm1, xmm7
  movdqu    [edx + 80], xmm1
  movdqu    xmm7, [eax + 96]
  pxor      xmm2, xmm7
  movdqu    [edx + 96], xmm2
  movdqu    xmm7, [eax + 112]
  pxor      xmm3, xmm7
  movdqu    [edx + 112], xmm3

  // ======================================================================
  // Inline 3-limb GHASH reduction on Z0 / Z1 / Z2 (copied from
  // GcmGhashFull_i386.inc). Load the stack-resident accumulators into
  // xmm0..xmm2 (keystream lanes are no longer needed after the stores
  // above), then fold Z1 into (Z0, Z2) and reduce modulo
  // x^128 + x^7 + x^2 + x + 1.
  // ======================================================================
  movdqu    xmm0, [esp + 0]                    // Z0
  movdqu    xmm1, [esp + 16]                   // Z1
  movdqu    xmm2, [esp + 32]                   // Z2

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

  // Pack and byte-reverse final GHASH state; store to PFS.
  movq      xmm0, xmm7
  pslldq    xmm6, 8
  por       xmm0, xmm6
  movdqu    xmm7, [ecx]                        // mask reload
  pshufb    xmm0, xmm7                         // byte-reverse -> canonical
  mov       eax, [ebx + 24]                    // PFS
  movdqu    [eax], xmm0

  // --- Epilogue: unwind stack scratch and pop callee-saved GPRs. ebx
  //     is popped last because SimdProc1Begin_i386.inc pushed it first. ---
  add       esp, 64
  pop       ebp
  pop       esi
  pop       edi
  pop       ebx
