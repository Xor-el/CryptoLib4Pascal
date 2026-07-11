// OCB fused 6-wide AES-NI kernel (i386) with a round-interleaved offset
// ladder, L-table lookup and checksum fold.
// -------------------------------------------------------------------
// Processes ABlockCount consecutive 16-byte OCB body blocks, two 6-block
// iterations (192 bytes) per loop pass. All 8 xmm registers are
// productive: xmm0..5 data lanes, xmm6 offset accumulator, xmm7
// checksum accumulator outside the rounds / L-table scratch inside them
// (the checksum spills to an aligned frame slot across the round chain,
// where it is never read). The offset ladder for the NEXT 6-block
// iteration is staged between the AES round groups of the current one
// into the opposite of two ping-pong delta banks, so the ladder's
// serial bsf/load/xor chain rides the AES latency instead of running
// as a prefix; the prologue pre-stages iteration 0, and the final
// pass over-stages one iteration, undone afterwards by re-XORing the
// same six L entries (XOR is self-inverse; the counter is not
// persisted, so only the offset accumulator needs the rollback).
// Whitening / unwhitening take the aligned stashes and the aligned key
// schedule as pxor memory operands. The kernel owns all per-block OCB
// bookkeeping across the batch: it seeds xmm_offset / xmm_checksum and
// the 64-bit block counter on entry, derives ntz per block (bsf; the
// counter-high dword is only touched on a low-dword wrap), and writes
// both accumulators back on exit.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// On entry (after ClpSimdProc1Begin_i386.inc): ebx = PCtx.
// Context layout: see TOcbFusedKernelCtx in ClpAesNiOcbKernel.pas.
// BlockCount must be a positive multiple of 12.
//
// GPR: ebx=PCtx, edi=Keys, edx=InPtr, esi=OutPtr, ecx=BlockCount,
//   ebp=block counter low dword (bsf source), eax=scratch.
//
// Stack scratch (16-aligned; caller esp parked inside):
//   [esp +   0..95]   delta bank 0 (6 x 16)   [esp + 96..191]  delta bank 1
//   [esp + 192]  LTablePtr cache              [esp + 196]  counter high dword
//   [esp + 200]  parked caller esp            [esp + 204]  block-0 source ptr
//   [esp + 208..223]  checksum spill during the round chain
//
// AES-NI instructions are db-encoded for broad assembler compatibility.
// -------------------------------------------------------------------

  push      edi
  push      esi
  push      ebp
  mov       eax, esp
  sub       esp, 240
  and       esp, -16                              // align the stash frame
  mov       [esp + 200], eax                       // park the caller esp

  // --- Load context, seed accumulators and the block counter. ---
  mov       edi, [ebx +  0]                       // edi = Keys (pinned)
  mov       edx, [ebx +  4]                       // edx = InPtr (advancing)
  mov       esi, [ebx +  8]                       // esi = OutPtr (advancing)
  mov       ecx, [ebx + 28]                       // ecx = BlockCount (>= 12, multiple of 12)
  mov       ebp, [ebx + 32]                       // ebp = StartBlockCount low
  mov       eax, [ebx + 36]
  mov       [esp + 196], eax                      // counter high dword
  mov       eax, [ebx + 20]
  mov       [esp + 192], eax                      // LTablePtr cache
  mov       eax, [ebx + 24]
  mov       [esp + 204], eax                      // iteration-0 block-0 source
  mov       eax, [ebx + 12]
  movdqu    xmm6, [eax]                           // xmm6 = FOffsetMAIN
  mov       eax, [ebx + 16]
  movdqu    xmm7, [eax]                           // xmm7 = FChecksum

  // --- Pre-stage iteration 0's Deltas into bank 0 (lanes dead: xmm0
  //     is the table scratch here). ---
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_p0
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_p0:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  movdqa    [esp +   0], xmm6
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_p1
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_p1:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  movdqa    [esp +  16], xmm6
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_p2
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_p2:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  movdqa    [esp +  32], xmm6
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_p3
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_p3:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  movdqa    [esp +  48], xmm6
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_p4
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_p4:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  movdqa    [esp +  64], xmm6
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_p5
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_p5:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  movdqa    [esp +  80], xmm6

@@ocb_i386_loop:

  // --- Iteration A: load 6 blocks (block 0 via the staged source). ---
  mov       eax, [esp + 204]
  movdqu    xmm0, [eax]
  movdqu    xmm1, [edx + 16]
  movdqu    xmm2, [edx + 32]
  movdqu    xmm3, [edx + 48]
  movdqu    xmm4, [edx + 64]
  movdqu    xmm5, [edx + 80]

{$IFNDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold plaintext into the checksum (still live in xmm7).
  pxor      xmm7, xmm0
  pxor      xmm7, xmm1
  pxor      xmm7, xmm2
  pxor      xmm7, xmm3
  pxor      xmm7, xmm4
  pxor      xmm7, xmm5
{$ENDIF}
  movdqa    [esp + 208], xmm7                     // spill checksum; xmm7 = ladder scratch

  // Pre-whiten with K_0 and this iteration's stashed Deltas.
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]
  pxor      xmm4, [edi + 0]
  pxor      xmm5, [edi + 0]
  pxor      xmm0, [esp +   0]
  pxor      xmm1, [esp +  16]
  pxor      xmm2, [esp +  32]
  pxor      xmm3, [esp +  48]
  pxor      xmm4, [esp +  64]
  pxor      xmm5, [esp +  80]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Round 1
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $4F, $10   // aesdec xmm1, [edi+16]
  db $66, $0F, $38, $DE, $57, $10   // aesdec xmm2, [edi+16]
  db $66, $0F, $38, $DE, $5F, $10   // aesdec xmm3, [edi+16]
  db $66, $0F, $38, $DE, $67, $10   // aesdec xmm4, [edi+16]
  db $66, $0F, $38, $DE, $6F, $10   // aesdec xmm5, [edi+16]
  // stage next-iteration Delta 0 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA0
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA0:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  96], xmm6
  // Round 2
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $4F, $20   // aesdec xmm1, [edi+32]
  db $66, $0F, $38, $DE, $57, $20   // aesdec xmm2, [edi+32]
  db $66, $0F, $38, $DE, $5F, $20   // aesdec xmm3, [edi+32]
  db $66, $0F, $38, $DE, $67, $20   // aesdec xmm4, [edi+32]
  db $66, $0F, $38, $DE, $6F, $20   // aesdec xmm5, [edi+32]
  // stage next-iteration Delta 1 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA1
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA1:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 112], xmm6
  // Round 3
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $4F, $30   // aesdec xmm1, [edi+48]
  db $66, $0F, $38, $DE, $57, $30   // aesdec xmm2, [edi+48]
  db $66, $0F, $38, $DE, $5F, $30   // aesdec xmm3, [edi+48]
  db $66, $0F, $38, $DE, $67, $30   // aesdec xmm4, [edi+48]
  db $66, $0F, $38, $DE, $6F, $30   // aesdec xmm5, [edi+48]
  // stage next-iteration Delta 2 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA2
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA2:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 128], xmm6
  // Round 4
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $4F, $40   // aesdec xmm1, [edi+64]
  db $66, $0F, $38, $DE, $57, $40   // aesdec xmm2, [edi+64]
  db $66, $0F, $38, $DE, $5F, $40   // aesdec xmm3, [edi+64]
  db $66, $0F, $38, $DE, $67, $40   // aesdec xmm4, [edi+64]
  db $66, $0F, $38, $DE, $6F, $40   // aesdec xmm5, [edi+64]
  // stage next-iteration Delta 3 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA3
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA3:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 144], xmm6
  // Round 5
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $4F, $50   // aesdec xmm1, [edi+80]
  db $66, $0F, $38, $DE, $57, $50   // aesdec xmm2, [edi+80]
  db $66, $0F, $38, $DE, $5F, $50   // aesdec xmm3, [edi+80]
  db $66, $0F, $38, $DE, $67, $50   // aesdec xmm4, [edi+80]
  db $66, $0F, $38, $DE, $6F, $50   // aesdec xmm5, [edi+80]
  // stage next-iteration Delta 4 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA4
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA4:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 160], xmm6
  // Round 6
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $4F, $60   // aesdec xmm1, [edi+96]
  db $66, $0F, $38, $DE, $57, $60   // aesdec xmm2, [edi+96]
  db $66, $0F, $38, $DE, $5F, $60   // aesdec xmm3, [edi+96]
  db $66, $0F, $38, $DE, $67, $60   // aesdec xmm4, [edi+96]
  db $66, $0F, $38, $DE, $6F, $60   // aesdec xmm5, [edi+96]
  // stage next-iteration Delta 5 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA5
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA5:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 176], xmm6
  // Round 7
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $4F, $70   // aesdec xmm1, [edi+112]
  db $66, $0F, $38, $DE, $57, $70   // aesdec xmm2, [edi+112]
  db $66, $0F, $38, $DE, $5F, $70   // aesdec xmm3, [edi+112]
  db $66, $0F, $38, $DE, $67, $70   // aesdec xmm4, [edi+112]
  db $66, $0F, $38, $DE, $6F, $70   // aesdec xmm5, [edi+112]
  // Round 8
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $8F, $80, $00, $00, $00   // aesdec xmm1, [edi+128]
  db $66, $0F, $38, $DE, $97, $80, $00, $00, $00   // aesdec xmm2, [edi+128]
  db $66, $0F, $38, $DE, $9F, $80, $00, $00, $00   // aesdec xmm3, [edi+128]
  db $66, $0F, $38, $DE, $A7, $80, $00, $00, $00   // aesdec xmm4, [edi+128]
  db $66, $0F, $38, $DE, $AF, $80, $00, $00, $00   // aesdec xmm5, [edi+128]
  // Round 9
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DE, $8F, $90, $00, $00, $00   // aesdec xmm1, [edi+144]
  db $66, $0F, $38, $DE, $97, $90, $00, $00, $00   // aesdec xmm2, [edi+144]
  db $66, $0F, $38, $DE, $9F, $90, $00, $00, $00   // aesdec xmm3, [edi+144]
  db $66, $0F, $38, $DE, $A7, $90, $00, $00, $00   // aesdec xmm4, [edi+144]
  db $66, $0F, $38, $DE, $AF, $90, $00, $00, $00   // aesdec xmm5, [edi+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00   // aesdec xmm0, [edi+160]
  db $66, $0F, $38, $DE, $8F, $A0, $00, $00, $00   // aesdec xmm1, [edi+160]
  db $66, $0F, $38, $DE, $97, $A0, $00, $00, $00   // aesdec xmm2, [edi+160]
  db $66, $0F, $38, $DE, $9F, $A0, $00, $00, $00   // aesdec xmm3, [edi+160]
  db $66, $0F, $38, $DE, $A7, $A0, $00, $00, $00   // aesdec xmm4, [edi+160]
  db $66, $0F, $38, $DE, $AF, $A0, $00, $00, $00   // aesdec xmm5, [edi+160]
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00   // aesdec xmm0, [edi+176]
  db $66, $0F, $38, $DE, $8F, $B0, $00, $00, $00   // aesdec xmm1, [edi+176]
  db $66, $0F, $38, $DE, $97, $B0, $00, $00, $00   // aesdec xmm2, [edi+176]
  db $66, $0F, $38, $DE, $9F, $B0, $00, $00, $00   // aesdec xmm3, [edi+176]
  db $66, $0F, $38, $DE, $A7, $B0, $00, $00, $00   // aesdec xmm4, [edi+176]
  db $66, $0F, $38, $DE, $AF, $B0, $00, $00, $00   // aesdec xmm5, [edi+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DE, $87, $C0, $00, $00, $00   // aesdec xmm0, [edi+192]
  db $66, $0F, $38, $DE, $8F, $C0, $00, $00, $00   // aesdec xmm1, [edi+192]
  db $66, $0F, $38, $DE, $97, $C0, $00, $00, $00   // aesdec xmm2, [edi+192]
  db $66, $0F, $38, $DE, $9F, $C0, $00, $00, $00   // aesdec xmm3, [edi+192]
  db $66, $0F, $38, $DE, $A7, $C0, $00, $00, $00   // aesdec xmm4, [edi+192]
  db $66, $0F, $38, $DE, $AF, $C0, $00, $00, $00   // aesdec xmm5, [edi+192]
  db $66, $0F, $38, $DE, $87, $D0, $00, $00, $00   // aesdec xmm0, [edi+208]
  db $66, $0F, $38, $DE, $8F, $D0, $00, $00, $00   // aesdec xmm1, [edi+208]
  db $66, $0F, $38, $DE, $97, $D0, $00, $00, $00   // aesdec xmm2, [edi+208]
  db $66, $0F, $38, $DE, $9F, $D0, $00, $00, $00   // aesdec xmm3, [edi+208]
  db $66, $0F, $38, $DE, $A7, $D0, $00, $00, $00   // aesdec xmm4, [edi+208]
  db $66, $0F, $38, $DE, $AF, $D0, $00, $00, $00   // aesdec xmm5, [edi+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DF, $87, $A0, $00, $00, $00   // aesdeclast xmm0, [edi+160]
  db $66, $0F, $38, $DF, $8F, $A0, $00, $00, $00   // aesdeclast xmm1, [edi+160]
  db $66, $0F, $38, $DF, $97, $A0, $00, $00, $00   // aesdeclast xmm2, [edi+160]
  db $66, $0F, $38, $DF, $9F, $A0, $00, $00, $00   // aesdeclast xmm3, [edi+160]
  db $66, $0F, $38, $DF, $A7, $A0, $00, $00, $00   // aesdeclast xmm4, [edi+160]
  db $66, $0F, $38, $DF, $AF, $A0, $00, $00, $00   // aesdeclast xmm5, [edi+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DF, $87, $C0, $00, $00, $00   // aesdeclast xmm0, [edi+192]
  db $66, $0F, $38, $DF, $8F, $C0, $00, $00, $00   // aesdeclast xmm1, [edi+192]
  db $66, $0F, $38, $DF, $97, $C0, $00, $00, $00   // aesdeclast xmm2, [edi+192]
  db $66, $0F, $38, $DF, $9F, $C0, $00, $00, $00   // aesdeclast xmm3, [edi+192]
  db $66, $0F, $38, $DF, $A7, $C0, $00, $00, $00   // aesdeclast xmm4, [edi+192]
  db $66, $0F, $38, $DF, $AF, $C0, $00, $00, $00   // aesdeclast xmm5, [edi+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DF, $87, $E0, $00, $00, $00   // aesdeclast xmm0, [edi+224]
  db $66, $0F, $38, $DF, $8F, $E0, $00, $00, $00   // aesdeclast xmm1, [edi+224]
  db $66, $0F, $38, $DF, $97, $E0, $00, $00, $00   // aesdeclast xmm2, [edi+224]
  db $66, $0F, $38, $DF, $9F, $E0, $00, $00, $00   // aesdeclast xmm3, [edi+224]
  db $66, $0F, $38, $DF, $A7, $E0, $00, $00, $00   // aesdeclast xmm4, [edi+224]
  db $66, $0F, $38, $DF, $AF, $E0, $00, $00, $00   // aesdeclast xmm5, [edi+224]
{$ENDIF}
{$ELSE}
  // Round 1
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $4F, $10   // aesenc xmm1, [edi+16]
  db $66, $0F, $38, $DC, $57, $10   // aesenc xmm2, [edi+16]
  db $66, $0F, $38, $DC, $5F, $10   // aesenc xmm3, [edi+16]
  db $66, $0F, $38, $DC, $67, $10   // aesenc xmm4, [edi+16]
  db $66, $0F, $38, $DC, $6F, $10   // aesenc xmm5, [edi+16]
  // stage next-iteration Delta 0 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA0
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA0:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  96], xmm6
  // Round 2
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $4F, $20   // aesenc xmm1, [edi+32]
  db $66, $0F, $38, $DC, $57, $20   // aesenc xmm2, [edi+32]
  db $66, $0F, $38, $DC, $5F, $20   // aesenc xmm3, [edi+32]
  db $66, $0F, $38, $DC, $67, $20   // aesenc xmm4, [edi+32]
  db $66, $0F, $38, $DC, $6F, $20   // aesenc xmm5, [edi+32]
  // stage next-iteration Delta 1 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA1
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA1:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 112], xmm6
  // Round 3
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $4F, $30   // aesenc xmm1, [edi+48]
  db $66, $0F, $38, $DC, $57, $30   // aesenc xmm2, [edi+48]
  db $66, $0F, $38, $DC, $5F, $30   // aesenc xmm3, [edi+48]
  db $66, $0F, $38, $DC, $67, $30   // aesenc xmm4, [edi+48]
  db $66, $0F, $38, $DC, $6F, $30   // aesenc xmm5, [edi+48]
  // stage next-iteration Delta 2 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA2
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA2:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 128], xmm6
  // Round 4
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $4F, $40   // aesenc xmm1, [edi+64]
  db $66, $0F, $38, $DC, $57, $40   // aesenc xmm2, [edi+64]
  db $66, $0F, $38, $DC, $5F, $40   // aesenc xmm3, [edi+64]
  db $66, $0F, $38, $DC, $67, $40   // aesenc xmm4, [edi+64]
  db $66, $0F, $38, $DC, $6F, $40   // aesenc xmm5, [edi+64]
  // stage next-iteration Delta 3 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA3
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA3:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 144], xmm6
  // Round 5
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $4F, $50   // aesenc xmm1, [edi+80]
  db $66, $0F, $38, $DC, $57, $50   // aesenc xmm2, [edi+80]
  db $66, $0F, $38, $DC, $5F, $50   // aesenc xmm3, [edi+80]
  db $66, $0F, $38, $DC, $67, $50   // aesenc xmm4, [edi+80]
  db $66, $0F, $38, $DC, $6F, $50   // aesenc xmm5, [edi+80]
  // stage next-iteration Delta 4 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA4
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA4:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 160], xmm6
  // Round 6
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $4F, $60   // aesenc xmm1, [edi+96]
  db $66, $0F, $38, $DC, $57, $60   // aesenc xmm2, [edi+96]
  db $66, $0F, $38, $DC, $5F, $60   // aesenc xmm3, [edi+96]
  db $66, $0F, $38, $DC, $67, $60   // aesenc xmm4, [edi+96]
  db $66, $0F, $38, $DC, $6F, $60   // aesenc xmm5, [edi+96]
  // stage next-iteration Delta 5 -> bank 1
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sA5
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sA5:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp + 176], xmm6
  // Round 7
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $4F, $70   // aesenc xmm1, [edi+112]
  db $66, $0F, $38, $DC, $57, $70   // aesenc xmm2, [edi+112]
  db $66, $0F, $38, $DC, $5F, $70   // aesenc xmm3, [edi+112]
  db $66, $0F, $38, $DC, $67, $70   // aesenc xmm4, [edi+112]
  db $66, $0F, $38, $DC, $6F, $70   // aesenc xmm5, [edi+112]
  // Round 8
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00   // aesenc xmm1, [edi+128]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00   // aesenc xmm2, [edi+128]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00   // aesenc xmm3, [edi+128]
  db $66, $0F, $38, $DC, $A7, $80, $00, $00, $00   // aesenc xmm4, [edi+128]
  db $66, $0F, $38, $DC, $AF, $80, $00, $00, $00   // aesenc xmm5, [edi+128]
  // Round 9
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00   // aesenc xmm1, [edi+144]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00   // aesenc xmm2, [edi+144]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00   // aesenc xmm3, [edi+144]
  db $66, $0F, $38, $DC, $A7, $90, $00, $00, $00   // aesenc xmm4, [edi+144]
  db $66, $0F, $38, $DC, $AF, $90, $00, $00, $00   // aesenc xmm5, [edi+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00   // aesenc xmm1, [edi+160]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00   // aesenc xmm2, [edi+160]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00   // aesenc xmm3, [edi+160]
  db $66, $0F, $38, $DC, $A7, $A0, $00, $00, $00   // aesenc xmm4, [edi+160]
  db $66, $0F, $38, $DC, $AF, $A0, $00, $00, $00   // aesenc xmm5, [edi+160]
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00   // aesenc xmm1, [edi+176]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00   // aesenc xmm2, [edi+176]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00   // aesenc xmm3, [edi+176]
  db $66, $0F, $38, $DC, $A7, $B0, $00, $00, $00   // aesenc xmm4, [edi+176]
  db $66, $0F, $38, $DC, $AF, $B0, $00, $00, $00   // aesenc xmm5, [edi+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+192]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00   // aesenc xmm1, [edi+192]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00   // aesenc xmm2, [edi+192]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00   // aesenc xmm3, [edi+192]
  db $66, $0F, $38, $DC, $A7, $C0, $00, $00, $00   // aesenc xmm4, [edi+192]
  db $66, $0F, $38, $DC, $AF, $C0, $00, $00, $00   // aesenc xmm5, [edi+192]
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+208]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00   // aesenc xmm1, [edi+208]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00   // aesenc xmm2, [edi+208]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00   // aesenc xmm3, [edi+208]
  db $66, $0F, $38, $DC, $A7, $D0, $00, $00, $00   // aesenc xmm4, [edi+208]
  db $66, $0F, $38, $DC, $AF, $D0, $00, $00, $00   // aesenc xmm5, [edi+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+160]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00   // aesenclast xmm1, [edi+160]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00   // aesenclast xmm2, [edi+160]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00   // aesenclast xmm3, [edi+160]
  db $66, $0F, $38, $DD, $A7, $A0, $00, $00, $00   // aesenclast xmm4, [edi+160]
  db $66, $0F, $38, $DD, $AF, $A0, $00, $00, $00   // aesenclast xmm5, [edi+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+192]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00   // aesenclast xmm1, [edi+192]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00   // aesenclast xmm2, [edi+192]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00   // aesenclast xmm3, [edi+192]
  db $66, $0F, $38, $DD, $A7, $C0, $00, $00, $00   // aesenclast xmm4, [edi+192]
  db $66, $0F, $38, $DD, $AF, $C0, $00, $00, $00   // aesenclast xmm5, [edi+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+224]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00   // aesenclast xmm1, [edi+224]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00   // aesenclast xmm2, [edi+224]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00   // aesenclast xmm3, [edi+224]
  db $66, $0F, $38, $DD, $A7, $E0, $00, $00, $00   // aesenclast xmm4, [edi+224]
  db $66, $0F, $38, $DD, $AF, $E0, $00, $00, $00   // aesenclast xmm5, [edi+224]
{$ENDIF}
{$ENDIF}

  movdqa    xmm7, [esp + 208]                     // reload checksum
  // Post-whiten with this iteration's Deltas.
  pxor      xmm0, [esp +   0]
  pxor      xmm1, [esp +  16]
  pxor      xmm2, [esp +  32]
  pxor      xmm3, [esp +  48]
  pxor      xmm4, [esp +  64]
  pxor      xmm5, [esp +  80]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold recovered plaintext into the checksum.
  pxor      xmm7, xmm0
  pxor      xmm7, xmm1
  pxor      xmm7, xmm2
  pxor      xmm7, xmm3
  pxor      xmm7, xmm4
  pxor      xmm7, xmm5
{$ENDIF}

  movdqu    [esi +  0], xmm0
  movdqu    [esi + 16], xmm1
  movdqu    [esi + 32], xmm2
  movdqu    [esi + 48], xmm3
  movdqu    [esi + 64], xmm4
  movdqu    [esi + 80], xmm5
  add       edx, 96
  add       esi, 96
  mov       [esp + 204], edx                      // next iteration's block-0 source

  // --- Iteration B: load 6 blocks (block 0 via the staged source). ---
  mov       eax, [esp + 204]
  movdqu    xmm0, [eax]
  movdqu    xmm1, [edx + 16]
  movdqu    xmm2, [edx + 32]
  movdqu    xmm3, [edx + 48]
  movdqu    xmm4, [edx + 64]
  movdqu    xmm5, [edx + 80]

{$IFNDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold plaintext into the checksum (still live in xmm7).
  pxor      xmm7, xmm0
  pxor      xmm7, xmm1
  pxor      xmm7, xmm2
  pxor      xmm7, xmm3
  pxor      xmm7, xmm4
  pxor      xmm7, xmm5
{$ENDIF}
  movdqa    [esp + 208], xmm7                     // spill checksum; xmm7 = ladder scratch

  // Pre-whiten with K_0 and this iteration's stashed Deltas.
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]
  pxor      xmm4, [edi + 0]
  pxor      xmm5, [edi + 0]
  pxor      xmm0, [esp +  96]
  pxor      xmm1, [esp + 112]
  pxor      xmm2, [esp + 128]
  pxor      xmm3, [esp + 144]
  pxor      xmm4, [esp + 160]
  pxor      xmm5, [esp + 176]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Round 1
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $4F, $10   // aesdec xmm1, [edi+16]
  db $66, $0F, $38, $DE, $57, $10   // aesdec xmm2, [edi+16]
  db $66, $0F, $38, $DE, $5F, $10   // aesdec xmm3, [edi+16]
  db $66, $0F, $38, $DE, $67, $10   // aesdec xmm4, [edi+16]
  db $66, $0F, $38, $DE, $6F, $10   // aesdec xmm5, [edi+16]
  // stage next-iteration Delta 0 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB0
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB0:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +   0], xmm6
  // Round 2
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $4F, $20   // aesdec xmm1, [edi+32]
  db $66, $0F, $38, $DE, $57, $20   // aesdec xmm2, [edi+32]
  db $66, $0F, $38, $DE, $5F, $20   // aesdec xmm3, [edi+32]
  db $66, $0F, $38, $DE, $67, $20   // aesdec xmm4, [edi+32]
  db $66, $0F, $38, $DE, $6F, $20   // aesdec xmm5, [edi+32]
  // stage next-iteration Delta 1 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB1
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB1:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  16], xmm6
  // Round 3
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $4F, $30   // aesdec xmm1, [edi+48]
  db $66, $0F, $38, $DE, $57, $30   // aesdec xmm2, [edi+48]
  db $66, $0F, $38, $DE, $5F, $30   // aesdec xmm3, [edi+48]
  db $66, $0F, $38, $DE, $67, $30   // aesdec xmm4, [edi+48]
  db $66, $0F, $38, $DE, $6F, $30   // aesdec xmm5, [edi+48]
  // stage next-iteration Delta 2 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB2
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB2:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  32], xmm6
  // Round 4
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $4F, $40   // aesdec xmm1, [edi+64]
  db $66, $0F, $38, $DE, $57, $40   // aesdec xmm2, [edi+64]
  db $66, $0F, $38, $DE, $5F, $40   // aesdec xmm3, [edi+64]
  db $66, $0F, $38, $DE, $67, $40   // aesdec xmm4, [edi+64]
  db $66, $0F, $38, $DE, $6F, $40   // aesdec xmm5, [edi+64]
  // stage next-iteration Delta 3 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB3
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB3:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  48], xmm6
  // Round 5
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $4F, $50   // aesdec xmm1, [edi+80]
  db $66, $0F, $38, $DE, $57, $50   // aesdec xmm2, [edi+80]
  db $66, $0F, $38, $DE, $5F, $50   // aesdec xmm3, [edi+80]
  db $66, $0F, $38, $DE, $67, $50   // aesdec xmm4, [edi+80]
  db $66, $0F, $38, $DE, $6F, $50   // aesdec xmm5, [edi+80]
  // stage next-iteration Delta 4 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB4
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB4:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  64], xmm6
  // Round 6
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $4F, $60   // aesdec xmm1, [edi+96]
  db $66, $0F, $38, $DE, $57, $60   // aesdec xmm2, [edi+96]
  db $66, $0F, $38, $DE, $5F, $60   // aesdec xmm3, [edi+96]
  db $66, $0F, $38, $DE, $67, $60   // aesdec xmm4, [edi+96]
  db $66, $0F, $38, $DE, $6F, $60   // aesdec xmm5, [edi+96]
  // stage next-iteration Delta 5 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB5
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB5:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  80], xmm6
  // Round 7
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $4F, $70   // aesdec xmm1, [edi+112]
  db $66, $0F, $38, $DE, $57, $70   // aesdec xmm2, [edi+112]
  db $66, $0F, $38, $DE, $5F, $70   // aesdec xmm3, [edi+112]
  db $66, $0F, $38, $DE, $67, $70   // aesdec xmm4, [edi+112]
  db $66, $0F, $38, $DE, $6F, $70   // aesdec xmm5, [edi+112]
  // Round 8
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $8F, $80, $00, $00, $00   // aesdec xmm1, [edi+128]
  db $66, $0F, $38, $DE, $97, $80, $00, $00, $00   // aesdec xmm2, [edi+128]
  db $66, $0F, $38, $DE, $9F, $80, $00, $00, $00   // aesdec xmm3, [edi+128]
  db $66, $0F, $38, $DE, $A7, $80, $00, $00, $00   // aesdec xmm4, [edi+128]
  db $66, $0F, $38, $DE, $AF, $80, $00, $00, $00   // aesdec xmm5, [edi+128]
  // Round 9
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DE, $8F, $90, $00, $00, $00   // aesdec xmm1, [edi+144]
  db $66, $0F, $38, $DE, $97, $90, $00, $00, $00   // aesdec xmm2, [edi+144]
  db $66, $0F, $38, $DE, $9F, $90, $00, $00, $00   // aesdec xmm3, [edi+144]
  db $66, $0F, $38, $DE, $A7, $90, $00, $00, $00   // aesdec xmm4, [edi+144]
  db $66, $0F, $38, $DE, $AF, $90, $00, $00, $00   // aesdec xmm5, [edi+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00   // aesdec xmm0, [edi+160]
  db $66, $0F, $38, $DE, $8F, $A0, $00, $00, $00   // aesdec xmm1, [edi+160]
  db $66, $0F, $38, $DE, $97, $A0, $00, $00, $00   // aesdec xmm2, [edi+160]
  db $66, $0F, $38, $DE, $9F, $A0, $00, $00, $00   // aesdec xmm3, [edi+160]
  db $66, $0F, $38, $DE, $A7, $A0, $00, $00, $00   // aesdec xmm4, [edi+160]
  db $66, $0F, $38, $DE, $AF, $A0, $00, $00, $00   // aesdec xmm5, [edi+160]
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00   // aesdec xmm0, [edi+176]
  db $66, $0F, $38, $DE, $8F, $B0, $00, $00, $00   // aesdec xmm1, [edi+176]
  db $66, $0F, $38, $DE, $97, $B0, $00, $00, $00   // aesdec xmm2, [edi+176]
  db $66, $0F, $38, $DE, $9F, $B0, $00, $00, $00   // aesdec xmm3, [edi+176]
  db $66, $0F, $38, $DE, $A7, $B0, $00, $00, $00   // aesdec xmm4, [edi+176]
  db $66, $0F, $38, $DE, $AF, $B0, $00, $00, $00   // aesdec xmm5, [edi+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DE, $87, $C0, $00, $00, $00   // aesdec xmm0, [edi+192]
  db $66, $0F, $38, $DE, $8F, $C0, $00, $00, $00   // aesdec xmm1, [edi+192]
  db $66, $0F, $38, $DE, $97, $C0, $00, $00, $00   // aesdec xmm2, [edi+192]
  db $66, $0F, $38, $DE, $9F, $C0, $00, $00, $00   // aesdec xmm3, [edi+192]
  db $66, $0F, $38, $DE, $A7, $C0, $00, $00, $00   // aesdec xmm4, [edi+192]
  db $66, $0F, $38, $DE, $AF, $C0, $00, $00, $00   // aesdec xmm5, [edi+192]
  db $66, $0F, $38, $DE, $87, $D0, $00, $00, $00   // aesdec xmm0, [edi+208]
  db $66, $0F, $38, $DE, $8F, $D0, $00, $00, $00   // aesdec xmm1, [edi+208]
  db $66, $0F, $38, $DE, $97, $D0, $00, $00, $00   // aesdec xmm2, [edi+208]
  db $66, $0F, $38, $DE, $9F, $D0, $00, $00, $00   // aesdec xmm3, [edi+208]
  db $66, $0F, $38, $DE, $A7, $D0, $00, $00, $00   // aesdec xmm4, [edi+208]
  db $66, $0F, $38, $DE, $AF, $D0, $00, $00, $00   // aesdec xmm5, [edi+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DF, $87, $A0, $00, $00, $00   // aesdeclast xmm0, [edi+160]
  db $66, $0F, $38, $DF, $8F, $A0, $00, $00, $00   // aesdeclast xmm1, [edi+160]
  db $66, $0F, $38, $DF, $97, $A0, $00, $00, $00   // aesdeclast xmm2, [edi+160]
  db $66, $0F, $38, $DF, $9F, $A0, $00, $00, $00   // aesdeclast xmm3, [edi+160]
  db $66, $0F, $38, $DF, $A7, $A0, $00, $00, $00   // aesdeclast xmm4, [edi+160]
  db $66, $0F, $38, $DF, $AF, $A0, $00, $00, $00   // aesdeclast xmm5, [edi+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DF, $87, $C0, $00, $00, $00   // aesdeclast xmm0, [edi+192]
  db $66, $0F, $38, $DF, $8F, $C0, $00, $00, $00   // aesdeclast xmm1, [edi+192]
  db $66, $0F, $38, $DF, $97, $C0, $00, $00, $00   // aesdeclast xmm2, [edi+192]
  db $66, $0F, $38, $DF, $9F, $C0, $00, $00, $00   // aesdeclast xmm3, [edi+192]
  db $66, $0F, $38, $DF, $A7, $C0, $00, $00, $00   // aesdeclast xmm4, [edi+192]
  db $66, $0F, $38, $DF, $AF, $C0, $00, $00, $00   // aesdeclast xmm5, [edi+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DF, $87, $E0, $00, $00, $00   // aesdeclast xmm0, [edi+224]
  db $66, $0F, $38, $DF, $8F, $E0, $00, $00, $00   // aesdeclast xmm1, [edi+224]
  db $66, $0F, $38, $DF, $97, $E0, $00, $00, $00   // aesdeclast xmm2, [edi+224]
  db $66, $0F, $38, $DF, $9F, $E0, $00, $00, $00   // aesdeclast xmm3, [edi+224]
  db $66, $0F, $38, $DF, $A7, $E0, $00, $00, $00   // aesdeclast xmm4, [edi+224]
  db $66, $0F, $38, $DF, $AF, $E0, $00, $00, $00   // aesdeclast xmm5, [edi+224]
{$ENDIF}
{$ELSE}
  // Round 1
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $4F, $10   // aesenc xmm1, [edi+16]
  db $66, $0F, $38, $DC, $57, $10   // aesenc xmm2, [edi+16]
  db $66, $0F, $38, $DC, $5F, $10   // aesenc xmm3, [edi+16]
  db $66, $0F, $38, $DC, $67, $10   // aesenc xmm4, [edi+16]
  db $66, $0F, $38, $DC, $6F, $10   // aesenc xmm5, [edi+16]
  // stage next-iteration Delta 0 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB0
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB0:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +   0], xmm6
  // Round 2
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $4F, $20   // aesenc xmm1, [edi+32]
  db $66, $0F, $38, $DC, $57, $20   // aesenc xmm2, [edi+32]
  db $66, $0F, $38, $DC, $5F, $20   // aesenc xmm3, [edi+32]
  db $66, $0F, $38, $DC, $67, $20   // aesenc xmm4, [edi+32]
  db $66, $0F, $38, $DC, $6F, $20   // aesenc xmm5, [edi+32]
  // stage next-iteration Delta 1 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB1
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB1:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  16], xmm6
  // Round 3
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $4F, $30   // aesenc xmm1, [edi+48]
  db $66, $0F, $38, $DC, $57, $30   // aesenc xmm2, [edi+48]
  db $66, $0F, $38, $DC, $5F, $30   // aesenc xmm3, [edi+48]
  db $66, $0F, $38, $DC, $67, $30   // aesenc xmm4, [edi+48]
  db $66, $0F, $38, $DC, $6F, $30   // aesenc xmm5, [edi+48]
  // stage next-iteration Delta 2 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB2
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB2:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  32], xmm6
  // Round 4
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $4F, $40   // aesenc xmm1, [edi+64]
  db $66, $0F, $38, $DC, $57, $40   // aesenc xmm2, [edi+64]
  db $66, $0F, $38, $DC, $5F, $40   // aesenc xmm3, [edi+64]
  db $66, $0F, $38, $DC, $67, $40   // aesenc xmm4, [edi+64]
  db $66, $0F, $38, $DC, $6F, $40   // aesenc xmm5, [edi+64]
  // stage next-iteration Delta 3 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB3
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB3:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  48], xmm6
  // Round 5
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $4F, $50   // aesenc xmm1, [edi+80]
  db $66, $0F, $38, $DC, $57, $50   // aesenc xmm2, [edi+80]
  db $66, $0F, $38, $DC, $5F, $50   // aesenc xmm3, [edi+80]
  db $66, $0F, $38, $DC, $67, $50   // aesenc xmm4, [edi+80]
  db $66, $0F, $38, $DC, $6F, $50   // aesenc xmm5, [edi+80]
  // stage next-iteration Delta 4 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB4
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB4:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  64], xmm6
  // Round 6
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $4F, $60   // aesenc xmm1, [edi+96]
  db $66, $0F, $38, $DC, $57, $60   // aesenc xmm2, [edi+96]
  db $66, $0F, $38, $DC, $5F, $60   // aesenc xmm3, [edi+96]
  db $66, $0F, $38, $DC, $67, $60   // aesenc xmm4, [edi+96]
  db $66, $0F, $38, $DC, $6F, $60   // aesenc xmm5, [edi+96]
  // stage next-iteration Delta 5 -> bank 0
  add       ebp, 1
  bsf       eax, ebp
  jnz       @@ocb_i386_sB5
  inc       dword [esp + 196]
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_sB5:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm7, [eax]
  pxor      xmm6, xmm7
  movdqa    [esp +  80], xmm6
  // Round 7
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $4F, $70   // aesenc xmm1, [edi+112]
  db $66, $0F, $38, $DC, $57, $70   // aesenc xmm2, [edi+112]
  db $66, $0F, $38, $DC, $5F, $70   // aesenc xmm3, [edi+112]
  db $66, $0F, $38, $DC, $67, $70   // aesenc xmm4, [edi+112]
  db $66, $0F, $38, $DC, $6F, $70   // aesenc xmm5, [edi+112]
  // Round 8
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00   // aesenc xmm1, [edi+128]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00   // aesenc xmm2, [edi+128]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00   // aesenc xmm3, [edi+128]
  db $66, $0F, $38, $DC, $A7, $80, $00, $00, $00   // aesenc xmm4, [edi+128]
  db $66, $0F, $38, $DC, $AF, $80, $00, $00, $00   // aesenc xmm5, [edi+128]
  // Round 9
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00   // aesenc xmm1, [edi+144]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00   // aesenc xmm2, [edi+144]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00   // aesenc xmm3, [edi+144]
  db $66, $0F, $38, $DC, $A7, $90, $00, $00, $00   // aesenc xmm4, [edi+144]
  db $66, $0F, $38, $DC, $AF, $90, $00, $00, $00   // aesenc xmm5, [edi+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00   // aesenc xmm1, [edi+160]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00   // aesenc xmm2, [edi+160]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00   // aesenc xmm3, [edi+160]
  db $66, $0F, $38, $DC, $A7, $A0, $00, $00, $00   // aesenc xmm4, [edi+160]
  db $66, $0F, $38, $DC, $AF, $A0, $00, $00, $00   // aesenc xmm5, [edi+160]
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00   // aesenc xmm1, [edi+176]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00   // aesenc xmm2, [edi+176]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00   // aesenc xmm3, [edi+176]
  db $66, $0F, $38, $DC, $A7, $B0, $00, $00, $00   // aesenc xmm4, [edi+176]
  db $66, $0F, $38, $DC, $AF, $B0, $00, $00, $00   // aesenc xmm5, [edi+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+192]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00   // aesenc xmm1, [edi+192]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00   // aesenc xmm2, [edi+192]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00   // aesenc xmm3, [edi+192]
  db $66, $0F, $38, $DC, $A7, $C0, $00, $00, $00   // aesenc xmm4, [edi+192]
  db $66, $0F, $38, $DC, $AF, $C0, $00, $00, $00   // aesenc xmm5, [edi+192]
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+208]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00   // aesenc xmm1, [edi+208]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00   // aesenc xmm2, [edi+208]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00   // aesenc xmm3, [edi+208]
  db $66, $0F, $38, $DC, $A7, $D0, $00, $00, $00   // aesenc xmm4, [edi+208]
  db $66, $0F, $38, $DC, $AF, $D0, $00, $00, $00   // aesenc xmm5, [edi+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+160]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00   // aesenclast xmm1, [edi+160]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00   // aesenclast xmm2, [edi+160]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00   // aesenclast xmm3, [edi+160]
  db $66, $0F, $38, $DD, $A7, $A0, $00, $00, $00   // aesenclast xmm4, [edi+160]
  db $66, $0F, $38, $DD, $AF, $A0, $00, $00, $00   // aesenclast xmm5, [edi+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+192]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00   // aesenclast xmm1, [edi+192]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00   // aesenclast xmm2, [edi+192]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00   // aesenclast xmm3, [edi+192]
  db $66, $0F, $38, $DD, $A7, $C0, $00, $00, $00   // aesenclast xmm4, [edi+192]
  db $66, $0F, $38, $DD, $AF, $C0, $00, $00, $00   // aesenclast xmm5, [edi+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+224]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00   // aesenclast xmm1, [edi+224]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00   // aesenclast xmm2, [edi+224]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00   // aesenclast xmm3, [edi+224]
  db $66, $0F, $38, $DD, $A7, $E0, $00, $00, $00   // aesenclast xmm4, [edi+224]
  db $66, $0F, $38, $DD, $AF, $E0, $00, $00, $00   // aesenclast xmm5, [edi+224]
{$ENDIF}
{$ENDIF}

  movdqa    xmm7, [esp + 208]                     // reload checksum
  // Post-whiten with this iteration's Deltas.
  pxor      xmm0, [esp +  96]
  pxor      xmm1, [esp + 112]
  pxor      xmm2, [esp + 128]
  pxor      xmm3, [esp + 144]
  pxor      xmm4, [esp + 160]
  pxor      xmm5, [esp + 176]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold recovered plaintext into the checksum.
  pxor      xmm7, xmm0
  pxor      xmm7, xmm1
  pxor      xmm7, xmm2
  pxor      xmm7, xmm3
  pxor      xmm7, xmm4
  pxor      xmm7, xmm5
{$ENDIF}

  movdqu    [esi +  0], xmm0
  movdqu    [esi + 16], xmm1
  movdqu    [esi + 32], xmm2
  movdqu    [esi + 48], xmm3
  movdqu    [esi + 64], xmm4
  movdqu    [esi + 80], xmm5
  add       edx, 96
  add       esi, 96
  mov       [esp + 204], edx                      // next iteration's block-0 source

  sub       ecx, 12
  jnz       @@ocb_i386_loop

  // --- Undo the one-iteration ladder over-stage: re-XOR the same six
  //     L entries while walking the counter back (XOR is self-inverse;
  //     only xmm_offset needs this - the counter is not persisted). ---
  bsf       eax, ebp
  jnz       @@ocb_i386_u0
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_u0:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  sub       ebp, 1
  sbb       dword [esp + 196], 0
  bsf       eax, ebp
  jnz       @@ocb_i386_u1
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_u1:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  sub       ebp, 1
  sbb       dword [esp + 196], 0
  bsf       eax, ebp
  jnz       @@ocb_i386_u2
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_u2:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  sub       ebp, 1
  sbb       dword [esp + 196], 0
  bsf       eax, ebp
  jnz       @@ocb_i386_u3
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_u3:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  sub       ebp, 1
  sbb       dword [esp + 196], 0
  bsf       eax, ebp
  jnz       @@ocb_i386_u4
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_u4:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  sub       ebp, 1
  sbb       dword [esp + 196], 0
  bsf       eax, ebp
  jnz       @@ocb_i386_u5
  bsf       eax, [esp + 196]
  add       eax, 32
@@ocb_i386_u5:
  shl       eax, 4
  add       eax, [esp + 192]
  movdqu    xmm0, [eax]
  pxor      xmm6, xmm0
  sub       ebp, 1
  sbb       dword [esp + 196], 0

  // --- Epilogue: flush accumulators, unwind, pop callee-saves
  //     (ebx last: ClpSimdProc1Begin_i386.inc pushed it first). ---
  mov       eax, [ebx + 12]
  movdqu    [eax], xmm6
  mov       eax, [ebx + 16]
  movdqu    [eax], xmm7

  mov       esp, [esp + 200]
  pop       ebp
  pop       esi
  pop       edi
  pop       ebx

