// OCB fused 8-wide AES-NI kernel (x86-64) with a round-interleaved offset
// ladder, L-table lookup and checksum fold.
// -------------------------------------------------------------------
// Processes ABlockCount consecutive 16-byte OCB body blocks, two 8-block
// iterations (256 bytes) per loop pass. xmm0..7 data lanes, xmm8 offset
// accumulator, xmm9 checksum accumulator, xmm11 L-table scratch. Round
// keys are aesenc/aesdec memory operands against the 16-aligned
// schedule. The offset ladder for the NEXT 8-block iteration is staged
// between the AES round groups of the current one into the opposite of
// two ping-pong delta banks, so the ladder's serial bsf/load/xor chain
// rides the AES latency instead of running as a prefix; the prologue
// pre-stages iteration 0, and the final pass over-stages one iteration,
// undone afterwards by re-XORing the same eight L entries (XOR is
// self-inverse; the counter is not persisted, so only the offset
// accumulator needs the rollback). The 64-bit block counter lives whole
// in r11, so the ladder is branch-free (bsf sees zero only at the 2^64
// wrap, unreachable under OCB limits).
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// On entry (after ClpSimdProc1Begin_x86_64.inc): rcx = PCtx (pinned).
// Context layout: see TOcbFusedKernelCtx in ClpAesNiOcbKernel.pas.
// BlockCount must be a positive multiple of 16.
//
// GPR: rcx=PCtx, rdx=Keys, rbx=InPtr, r8=OutPtr, r9=LTablePtr,
//   r10=pass countdown, r11=block counter, rax=scratch/block-0 source.
//
// Stack scratch (16-aligned): [rsp+0..127] delta bank 0, [rsp+128..255]
// delta bank 1.
//
// AES-NI instructions and forms touching xmm8..xmm15 are db-encoded for
// broad assembler compatibility.
// -------------------------------------------------------------------

{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  // --- Prologue: preserve rbx, reserve the aligned delta banks. ---
  push      rbx                                     // rsp: 8 -> 0 mod 16
  sub       rsp, 256

  mov       rdx, [rcx +  0]                         // rdx = Keys
  mov       rbx, [rcx +  8]                         // rbx = InPtr
  mov       r8,  [rcx + 16]                         // r8  = OutPtr
  mov       r9,  [rcx + 40]                         // r9  = LTablePtr
  mov       r11, [rcx + 64]                         // r11 = running block counter
  mov       r10, [rcx + 56]                         // r10 = BlockCount
  shr       r10, 4                                  // r10 = pass count (BlockCount/16)

  mov       rax, [rcx + 24]
  db $F3, $44, $0F, $6F, $00   // movdqu xmm8, [rax]  (FOffsetMAIN)
  mov       rax, [rcx + 32]
  db $F3, $44, $0F, $6F, $08   // movdqu xmm9, [rax]  (FChecksum)

  // --- Pre-stage iteration 0's Deltas into bank 0. ---
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $04, $24   // movdqa [rsp+0], xmm8
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $10   // movdqa [rsp+16], xmm8
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $20   // movdqa [rsp+32], xmm8
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $30   // movdqa [rsp+48], xmm8
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $40   // movdqa [rsp+64], xmm8
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $50   // movdqa [rsp+80], xmm8
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $60   // movdqa [rsp+96], xmm8
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $70   // movdqa [rsp+112], xmm8
  mov       rax, [rcx + 48]                         // iteration-0 block-0 source

@@ocb_x64_loop:

  // --- Iteration A: load 8 blocks (block 0 via the staged source). ---
  movdqu    xmm0, [rax]
  movdqu    xmm1, [rbx + 16]
  movdqu    xmm2, [rbx + 32]
  movdqu    xmm3, [rbx + 48]
  movdqu    xmm4, [rbx + 64]
  movdqu    xmm5, [rbx + 80]
  movdqu    xmm6, [rbx + 96]
  movdqu    xmm7, [rbx + 112]

{$IFNDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold plaintext into the checksum.
  db $66, $44, $0F, $EF, $C8   // pxor xmm9, xmm0
  db $66, $44, $0F, $EF, $C9   // pxor xmm9, xmm1
  db $66, $44, $0F, $EF, $CA   // pxor xmm9, xmm2
  db $66, $44, $0F, $EF, $CB   // pxor xmm9, xmm3
  db $66, $44, $0F, $EF, $CC   // pxor xmm9, xmm4
  db $66, $44, $0F, $EF, $CD   // pxor xmm9, xmm5
  db $66, $44, $0F, $EF, $CE   // pxor xmm9, xmm6
  db $66, $44, $0F, $EF, $CF   // pxor xmm9, xmm7
{$ENDIF}

  // Pre-whiten with K_0 and this iteration's stashed Deltas.
  pxor      xmm0, [rdx + 0]
  pxor      xmm1, [rdx + 0]
  pxor      xmm2, [rdx + 0]
  pxor      xmm3, [rdx + 0]
  pxor      xmm4, [rdx + 0]
  pxor      xmm5, [rdx + 0]
  pxor      xmm6, [rdx + 0]
  pxor      xmm7, [rdx + 0]
  pxor      xmm0, [rsp +   0]
  pxor      xmm1, [rsp +  16]
  pxor      xmm2, [rsp +  32]
  pxor      xmm3, [rsp +  48]
  pxor      xmm4, [rsp +  64]
  pxor      xmm5, [rsp +  80]
  pxor      xmm6, [rsp +  96]
  pxor      xmm7, [rsp + 112]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Round 1
  db $66, $0F, $38, $DE, $42, $10   // aesdec xmm0, [rdx+16]
  db $66, $0F, $38, $DE, $4A, $10   // aesdec xmm1, [rdx+16]
  db $66, $0F, $38, $DE, $52, $10   // aesdec xmm2, [rdx+16]
  db $66, $0F, $38, $DE, $5A, $10   // aesdec xmm3, [rdx+16]
  db $66, $0F, $38, $DE, $62, $10   // aesdec xmm4, [rdx+16]
  db $66, $0F, $38, $DE, $6A, $10   // aesdec xmm5, [rdx+16]
  db $66, $0F, $38, $DE, $72, $10   // aesdec xmm6, [rdx+16]
  db $66, $0F, $38, $DE, $7A, $10   // aesdec xmm7, [rdx+16]
  // stage next-iteration Delta 0 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $80, $00, $00, $00   // movdqa [rsp+128], xmm8
  // Round 2
  db $66, $0F, $38, $DE, $42, $20   // aesdec xmm0, [rdx+32]
  db $66, $0F, $38, $DE, $4A, $20   // aesdec xmm1, [rdx+32]
  db $66, $0F, $38, $DE, $52, $20   // aesdec xmm2, [rdx+32]
  db $66, $0F, $38, $DE, $5A, $20   // aesdec xmm3, [rdx+32]
  db $66, $0F, $38, $DE, $62, $20   // aesdec xmm4, [rdx+32]
  db $66, $0F, $38, $DE, $6A, $20   // aesdec xmm5, [rdx+32]
  db $66, $0F, $38, $DE, $72, $20   // aesdec xmm6, [rdx+32]
  db $66, $0F, $38, $DE, $7A, $20   // aesdec xmm7, [rdx+32]
  // stage next-iteration Delta 1 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $90, $00, $00, $00   // movdqa [rsp+144], xmm8
  // Round 3
  db $66, $0F, $38, $DE, $42, $30   // aesdec xmm0, [rdx+48]
  db $66, $0F, $38, $DE, $4A, $30   // aesdec xmm1, [rdx+48]
  db $66, $0F, $38, $DE, $52, $30   // aesdec xmm2, [rdx+48]
  db $66, $0F, $38, $DE, $5A, $30   // aesdec xmm3, [rdx+48]
  db $66, $0F, $38, $DE, $62, $30   // aesdec xmm4, [rdx+48]
  db $66, $0F, $38, $DE, $6A, $30   // aesdec xmm5, [rdx+48]
  db $66, $0F, $38, $DE, $72, $30   // aesdec xmm6, [rdx+48]
  db $66, $0F, $38, $DE, $7A, $30   // aesdec xmm7, [rdx+48]
  // stage next-iteration Delta 2 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $A0, $00, $00, $00   // movdqa [rsp+160], xmm8
  // Round 4
  db $66, $0F, $38, $DE, $42, $40   // aesdec xmm0, [rdx+64]
  db $66, $0F, $38, $DE, $4A, $40   // aesdec xmm1, [rdx+64]
  db $66, $0F, $38, $DE, $52, $40   // aesdec xmm2, [rdx+64]
  db $66, $0F, $38, $DE, $5A, $40   // aesdec xmm3, [rdx+64]
  db $66, $0F, $38, $DE, $62, $40   // aesdec xmm4, [rdx+64]
  db $66, $0F, $38, $DE, $6A, $40   // aesdec xmm5, [rdx+64]
  db $66, $0F, $38, $DE, $72, $40   // aesdec xmm6, [rdx+64]
  db $66, $0F, $38, $DE, $7A, $40   // aesdec xmm7, [rdx+64]
  // stage next-iteration Delta 3 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $B0, $00, $00, $00   // movdqa [rsp+176], xmm8
  // Round 5
  db $66, $0F, $38, $DE, $42, $50   // aesdec xmm0, [rdx+80]
  db $66, $0F, $38, $DE, $4A, $50   // aesdec xmm1, [rdx+80]
  db $66, $0F, $38, $DE, $52, $50   // aesdec xmm2, [rdx+80]
  db $66, $0F, $38, $DE, $5A, $50   // aesdec xmm3, [rdx+80]
  db $66, $0F, $38, $DE, $62, $50   // aesdec xmm4, [rdx+80]
  db $66, $0F, $38, $DE, $6A, $50   // aesdec xmm5, [rdx+80]
  db $66, $0F, $38, $DE, $72, $50   // aesdec xmm6, [rdx+80]
  db $66, $0F, $38, $DE, $7A, $50   // aesdec xmm7, [rdx+80]
  // stage next-iteration Delta 4 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $C0, $00, $00, $00   // movdqa [rsp+192], xmm8
  // Round 6
  db $66, $0F, $38, $DE, $42, $60   // aesdec xmm0, [rdx+96]
  db $66, $0F, $38, $DE, $4A, $60   // aesdec xmm1, [rdx+96]
  db $66, $0F, $38, $DE, $52, $60   // aesdec xmm2, [rdx+96]
  db $66, $0F, $38, $DE, $5A, $60   // aesdec xmm3, [rdx+96]
  db $66, $0F, $38, $DE, $62, $60   // aesdec xmm4, [rdx+96]
  db $66, $0F, $38, $DE, $6A, $60   // aesdec xmm5, [rdx+96]
  db $66, $0F, $38, $DE, $72, $60   // aesdec xmm6, [rdx+96]
  db $66, $0F, $38, $DE, $7A, $60   // aesdec xmm7, [rdx+96]
  // stage next-iteration Delta 5 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $D0, $00, $00, $00   // movdqa [rsp+208], xmm8
  // Round 7
  db $66, $0F, $38, $DE, $42, $70   // aesdec xmm0, [rdx+112]
  db $66, $0F, $38, $DE, $4A, $70   // aesdec xmm1, [rdx+112]
  db $66, $0F, $38, $DE, $52, $70   // aesdec xmm2, [rdx+112]
  db $66, $0F, $38, $DE, $5A, $70   // aesdec xmm3, [rdx+112]
  db $66, $0F, $38, $DE, $62, $70   // aesdec xmm4, [rdx+112]
  db $66, $0F, $38, $DE, $6A, $70   // aesdec xmm5, [rdx+112]
  db $66, $0F, $38, $DE, $72, $70   // aesdec xmm6, [rdx+112]
  db $66, $0F, $38, $DE, $7A, $70   // aesdec xmm7, [rdx+112]
  // stage next-iteration Delta 6 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $E0, $00, $00, $00   // movdqa [rsp+224], xmm8
  // Round 8
  db $66, $0F, $38, $DE, $82, $80, $00, $00, $00   // aesdec xmm0, [rdx+128]
  db $66, $0F, $38, $DE, $8A, $80, $00, $00, $00   // aesdec xmm1, [rdx+128]
  db $66, $0F, $38, $DE, $92, $80, $00, $00, $00   // aesdec xmm2, [rdx+128]
  db $66, $0F, $38, $DE, $9A, $80, $00, $00, $00   // aesdec xmm3, [rdx+128]
  db $66, $0F, $38, $DE, $A2, $80, $00, $00, $00   // aesdec xmm4, [rdx+128]
  db $66, $0F, $38, $DE, $AA, $80, $00, $00, $00   // aesdec xmm5, [rdx+128]
  db $66, $0F, $38, $DE, $B2, $80, $00, $00, $00   // aesdec xmm6, [rdx+128]
  db $66, $0F, $38, $DE, $BA, $80, $00, $00, $00   // aesdec xmm7, [rdx+128]
  // stage next-iteration Delta 7 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $F0, $00, $00, $00   // movdqa [rsp+240], xmm8
  // Round 9
  db $66, $0F, $38, $DE, $82, $90, $00, $00, $00   // aesdec xmm0, [rdx+144]
  db $66, $0F, $38, $DE, $8A, $90, $00, $00, $00   // aesdec xmm1, [rdx+144]
  db $66, $0F, $38, $DE, $92, $90, $00, $00, $00   // aesdec xmm2, [rdx+144]
  db $66, $0F, $38, $DE, $9A, $90, $00, $00, $00   // aesdec xmm3, [rdx+144]
  db $66, $0F, $38, $DE, $A2, $90, $00, $00, $00   // aesdec xmm4, [rdx+144]
  db $66, $0F, $38, $DE, $AA, $90, $00, $00, $00   // aesdec xmm5, [rdx+144]
  db $66, $0F, $38, $DE, $B2, $90, $00, $00, $00   // aesdec xmm6, [rdx+144]
  db $66, $0F, $38, $DE, $BA, $90, $00, $00, $00   // aesdec xmm7, [rdx+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DE, $82, $A0, $00, $00, $00   // aesdec xmm0, [rdx+160]
  db $66, $0F, $38, $DE, $8A, $A0, $00, $00, $00   // aesdec xmm1, [rdx+160]
  db $66, $0F, $38, $DE, $92, $A0, $00, $00, $00   // aesdec xmm2, [rdx+160]
  db $66, $0F, $38, $DE, $9A, $A0, $00, $00, $00   // aesdec xmm3, [rdx+160]
  db $66, $0F, $38, $DE, $A2, $A0, $00, $00, $00   // aesdec xmm4, [rdx+160]
  db $66, $0F, $38, $DE, $AA, $A0, $00, $00, $00   // aesdec xmm5, [rdx+160]
  db $66, $0F, $38, $DE, $B2, $A0, $00, $00, $00   // aesdec xmm6, [rdx+160]
  db $66, $0F, $38, $DE, $BA, $A0, $00, $00, $00   // aesdec xmm7, [rdx+160]
  db $66, $0F, $38, $DE, $82, $B0, $00, $00, $00   // aesdec xmm0, [rdx+176]
  db $66, $0F, $38, $DE, $8A, $B0, $00, $00, $00   // aesdec xmm1, [rdx+176]
  db $66, $0F, $38, $DE, $92, $B0, $00, $00, $00   // aesdec xmm2, [rdx+176]
  db $66, $0F, $38, $DE, $9A, $B0, $00, $00, $00   // aesdec xmm3, [rdx+176]
  db $66, $0F, $38, $DE, $A2, $B0, $00, $00, $00   // aesdec xmm4, [rdx+176]
  db $66, $0F, $38, $DE, $AA, $B0, $00, $00, $00   // aesdec xmm5, [rdx+176]
  db $66, $0F, $38, $DE, $B2, $B0, $00, $00, $00   // aesdec xmm6, [rdx+176]
  db $66, $0F, $38, $DE, $BA, $B0, $00, $00, $00   // aesdec xmm7, [rdx+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DE, $82, $C0, $00, $00, $00   // aesdec xmm0, [rdx+192]
  db $66, $0F, $38, $DE, $8A, $C0, $00, $00, $00   // aesdec xmm1, [rdx+192]
  db $66, $0F, $38, $DE, $92, $C0, $00, $00, $00   // aesdec xmm2, [rdx+192]
  db $66, $0F, $38, $DE, $9A, $C0, $00, $00, $00   // aesdec xmm3, [rdx+192]
  db $66, $0F, $38, $DE, $A2, $C0, $00, $00, $00   // aesdec xmm4, [rdx+192]
  db $66, $0F, $38, $DE, $AA, $C0, $00, $00, $00   // aesdec xmm5, [rdx+192]
  db $66, $0F, $38, $DE, $B2, $C0, $00, $00, $00   // aesdec xmm6, [rdx+192]
  db $66, $0F, $38, $DE, $BA, $C0, $00, $00, $00   // aesdec xmm7, [rdx+192]
  db $66, $0F, $38, $DE, $82, $D0, $00, $00, $00   // aesdec xmm0, [rdx+208]
  db $66, $0F, $38, $DE, $8A, $D0, $00, $00, $00   // aesdec xmm1, [rdx+208]
  db $66, $0F, $38, $DE, $92, $D0, $00, $00, $00   // aesdec xmm2, [rdx+208]
  db $66, $0F, $38, $DE, $9A, $D0, $00, $00, $00   // aesdec xmm3, [rdx+208]
  db $66, $0F, $38, $DE, $A2, $D0, $00, $00, $00   // aesdec xmm4, [rdx+208]
  db $66, $0F, $38, $DE, $AA, $D0, $00, $00, $00   // aesdec xmm5, [rdx+208]
  db $66, $0F, $38, $DE, $B2, $D0, $00, $00, $00   // aesdec xmm6, [rdx+208]
  db $66, $0F, $38, $DE, $BA, $D0, $00, $00, $00   // aesdec xmm7, [rdx+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DF, $82, $A0, $00, $00, $00   // aesdeclast xmm0, [rdx+160]
  db $66, $0F, $38, $DF, $8A, $A0, $00, $00, $00   // aesdeclast xmm1, [rdx+160]
  db $66, $0F, $38, $DF, $92, $A0, $00, $00, $00   // aesdeclast xmm2, [rdx+160]
  db $66, $0F, $38, $DF, $9A, $A0, $00, $00, $00   // aesdeclast xmm3, [rdx+160]
  db $66, $0F, $38, $DF, $A2, $A0, $00, $00, $00   // aesdeclast xmm4, [rdx+160]
  db $66, $0F, $38, $DF, $AA, $A0, $00, $00, $00   // aesdeclast xmm5, [rdx+160]
  db $66, $0F, $38, $DF, $B2, $A0, $00, $00, $00   // aesdeclast xmm6, [rdx+160]
  db $66, $0F, $38, $DF, $BA, $A0, $00, $00, $00   // aesdeclast xmm7, [rdx+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DF, $82, $C0, $00, $00, $00   // aesdeclast xmm0, [rdx+192]
  db $66, $0F, $38, $DF, $8A, $C0, $00, $00, $00   // aesdeclast xmm1, [rdx+192]
  db $66, $0F, $38, $DF, $92, $C0, $00, $00, $00   // aesdeclast xmm2, [rdx+192]
  db $66, $0F, $38, $DF, $9A, $C0, $00, $00, $00   // aesdeclast xmm3, [rdx+192]
  db $66, $0F, $38, $DF, $A2, $C0, $00, $00, $00   // aesdeclast xmm4, [rdx+192]
  db $66, $0F, $38, $DF, $AA, $C0, $00, $00, $00   // aesdeclast xmm5, [rdx+192]
  db $66, $0F, $38, $DF, $B2, $C0, $00, $00, $00   // aesdeclast xmm6, [rdx+192]
  db $66, $0F, $38, $DF, $BA, $C0, $00, $00, $00   // aesdeclast xmm7, [rdx+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DF, $82, $E0, $00, $00, $00   // aesdeclast xmm0, [rdx+224]
  db $66, $0F, $38, $DF, $8A, $E0, $00, $00, $00   // aesdeclast xmm1, [rdx+224]
  db $66, $0F, $38, $DF, $92, $E0, $00, $00, $00   // aesdeclast xmm2, [rdx+224]
  db $66, $0F, $38, $DF, $9A, $E0, $00, $00, $00   // aesdeclast xmm3, [rdx+224]
  db $66, $0F, $38, $DF, $A2, $E0, $00, $00, $00   // aesdeclast xmm4, [rdx+224]
  db $66, $0F, $38, $DF, $AA, $E0, $00, $00, $00   // aesdeclast xmm5, [rdx+224]
  db $66, $0F, $38, $DF, $B2, $E0, $00, $00, $00   // aesdeclast xmm6, [rdx+224]
  db $66, $0F, $38, $DF, $BA, $E0, $00, $00, $00   // aesdeclast xmm7, [rdx+224]
{$ENDIF}
{$ELSE}
  // Round 1
  db $66, $0F, $38, $DC, $42, $10   // aesenc xmm0, [rdx+16]
  db $66, $0F, $38, $DC, $4A, $10   // aesenc xmm1, [rdx+16]
  db $66, $0F, $38, $DC, $52, $10   // aesenc xmm2, [rdx+16]
  db $66, $0F, $38, $DC, $5A, $10   // aesenc xmm3, [rdx+16]
  db $66, $0F, $38, $DC, $62, $10   // aesenc xmm4, [rdx+16]
  db $66, $0F, $38, $DC, $6A, $10   // aesenc xmm5, [rdx+16]
  db $66, $0F, $38, $DC, $72, $10   // aesenc xmm6, [rdx+16]
  db $66, $0F, $38, $DC, $7A, $10   // aesenc xmm7, [rdx+16]
  // stage next-iteration Delta 0 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $80, $00, $00, $00   // movdqa [rsp+128], xmm8
  // Round 2
  db $66, $0F, $38, $DC, $42, $20   // aesenc xmm0, [rdx+32]
  db $66, $0F, $38, $DC, $4A, $20   // aesenc xmm1, [rdx+32]
  db $66, $0F, $38, $DC, $52, $20   // aesenc xmm2, [rdx+32]
  db $66, $0F, $38, $DC, $5A, $20   // aesenc xmm3, [rdx+32]
  db $66, $0F, $38, $DC, $62, $20   // aesenc xmm4, [rdx+32]
  db $66, $0F, $38, $DC, $6A, $20   // aesenc xmm5, [rdx+32]
  db $66, $0F, $38, $DC, $72, $20   // aesenc xmm6, [rdx+32]
  db $66, $0F, $38, $DC, $7A, $20   // aesenc xmm7, [rdx+32]
  // stage next-iteration Delta 1 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $90, $00, $00, $00   // movdqa [rsp+144], xmm8
  // Round 3
  db $66, $0F, $38, $DC, $42, $30   // aesenc xmm0, [rdx+48]
  db $66, $0F, $38, $DC, $4A, $30   // aesenc xmm1, [rdx+48]
  db $66, $0F, $38, $DC, $52, $30   // aesenc xmm2, [rdx+48]
  db $66, $0F, $38, $DC, $5A, $30   // aesenc xmm3, [rdx+48]
  db $66, $0F, $38, $DC, $62, $30   // aesenc xmm4, [rdx+48]
  db $66, $0F, $38, $DC, $6A, $30   // aesenc xmm5, [rdx+48]
  db $66, $0F, $38, $DC, $72, $30   // aesenc xmm6, [rdx+48]
  db $66, $0F, $38, $DC, $7A, $30   // aesenc xmm7, [rdx+48]
  // stage next-iteration Delta 2 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $A0, $00, $00, $00   // movdqa [rsp+160], xmm8
  // Round 4
  db $66, $0F, $38, $DC, $42, $40   // aesenc xmm0, [rdx+64]
  db $66, $0F, $38, $DC, $4A, $40   // aesenc xmm1, [rdx+64]
  db $66, $0F, $38, $DC, $52, $40   // aesenc xmm2, [rdx+64]
  db $66, $0F, $38, $DC, $5A, $40   // aesenc xmm3, [rdx+64]
  db $66, $0F, $38, $DC, $62, $40   // aesenc xmm4, [rdx+64]
  db $66, $0F, $38, $DC, $6A, $40   // aesenc xmm5, [rdx+64]
  db $66, $0F, $38, $DC, $72, $40   // aesenc xmm6, [rdx+64]
  db $66, $0F, $38, $DC, $7A, $40   // aesenc xmm7, [rdx+64]
  // stage next-iteration Delta 3 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $B0, $00, $00, $00   // movdqa [rsp+176], xmm8
  // Round 5
  db $66, $0F, $38, $DC, $42, $50   // aesenc xmm0, [rdx+80]
  db $66, $0F, $38, $DC, $4A, $50   // aesenc xmm1, [rdx+80]
  db $66, $0F, $38, $DC, $52, $50   // aesenc xmm2, [rdx+80]
  db $66, $0F, $38, $DC, $5A, $50   // aesenc xmm3, [rdx+80]
  db $66, $0F, $38, $DC, $62, $50   // aesenc xmm4, [rdx+80]
  db $66, $0F, $38, $DC, $6A, $50   // aesenc xmm5, [rdx+80]
  db $66, $0F, $38, $DC, $72, $50   // aesenc xmm6, [rdx+80]
  db $66, $0F, $38, $DC, $7A, $50   // aesenc xmm7, [rdx+80]
  // stage next-iteration Delta 4 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $C0, $00, $00, $00   // movdqa [rsp+192], xmm8
  // Round 6
  db $66, $0F, $38, $DC, $42, $60   // aesenc xmm0, [rdx+96]
  db $66, $0F, $38, $DC, $4A, $60   // aesenc xmm1, [rdx+96]
  db $66, $0F, $38, $DC, $52, $60   // aesenc xmm2, [rdx+96]
  db $66, $0F, $38, $DC, $5A, $60   // aesenc xmm3, [rdx+96]
  db $66, $0F, $38, $DC, $62, $60   // aesenc xmm4, [rdx+96]
  db $66, $0F, $38, $DC, $6A, $60   // aesenc xmm5, [rdx+96]
  db $66, $0F, $38, $DC, $72, $60   // aesenc xmm6, [rdx+96]
  db $66, $0F, $38, $DC, $7A, $60   // aesenc xmm7, [rdx+96]
  // stage next-iteration Delta 5 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $D0, $00, $00, $00   // movdqa [rsp+208], xmm8
  // Round 7
  db $66, $0F, $38, $DC, $42, $70   // aesenc xmm0, [rdx+112]
  db $66, $0F, $38, $DC, $4A, $70   // aesenc xmm1, [rdx+112]
  db $66, $0F, $38, $DC, $52, $70   // aesenc xmm2, [rdx+112]
  db $66, $0F, $38, $DC, $5A, $70   // aesenc xmm3, [rdx+112]
  db $66, $0F, $38, $DC, $62, $70   // aesenc xmm4, [rdx+112]
  db $66, $0F, $38, $DC, $6A, $70   // aesenc xmm5, [rdx+112]
  db $66, $0F, $38, $DC, $72, $70   // aesenc xmm6, [rdx+112]
  db $66, $0F, $38, $DC, $7A, $70   // aesenc xmm7, [rdx+112]
  // stage next-iteration Delta 6 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $E0, $00, $00, $00   // movdqa [rsp+224], xmm8
  // Round 8
  db $66, $0F, $38, $DC, $82, $80, $00, $00, $00   // aesenc xmm0, [rdx+128]
  db $66, $0F, $38, $DC, $8A, $80, $00, $00, $00   // aesenc xmm1, [rdx+128]
  db $66, $0F, $38, $DC, $92, $80, $00, $00, $00   // aesenc xmm2, [rdx+128]
  db $66, $0F, $38, $DC, $9A, $80, $00, $00, $00   // aesenc xmm3, [rdx+128]
  db $66, $0F, $38, $DC, $A2, $80, $00, $00, $00   // aesenc xmm4, [rdx+128]
  db $66, $0F, $38, $DC, $AA, $80, $00, $00, $00   // aesenc xmm5, [rdx+128]
  db $66, $0F, $38, $DC, $B2, $80, $00, $00, $00   // aesenc xmm6, [rdx+128]
  db $66, $0F, $38, $DC, $BA, $80, $00, $00, $00   // aesenc xmm7, [rdx+128]
  // stage next-iteration Delta 7 -> bank 1
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $84, $24, $F0, $00, $00, $00   // movdqa [rsp+240], xmm8
  // Round 9
  db $66, $0F, $38, $DC, $82, $90, $00, $00, $00   // aesenc xmm0, [rdx+144]
  db $66, $0F, $38, $DC, $8A, $90, $00, $00, $00   // aesenc xmm1, [rdx+144]
  db $66, $0F, $38, $DC, $92, $90, $00, $00, $00   // aesenc xmm2, [rdx+144]
  db $66, $0F, $38, $DC, $9A, $90, $00, $00, $00   // aesenc xmm3, [rdx+144]
  db $66, $0F, $38, $DC, $A2, $90, $00, $00, $00   // aesenc xmm4, [rdx+144]
  db $66, $0F, $38, $DC, $AA, $90, $00, $00, $00   // aesenc xmm5, [rdx+144]
  db $66, $0F, $38, $DC, $B2, $90, $00, $00, $00   // aesenc xmm6, [rdx+144]
  db $66, $0F, $38, $DC, $BA, $90, $00, $00, $00   // aesenc xmm7, [rdx+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DC, $82, $A0, $00, $00, $00   // aesenc xmm0, [rdx+160]
  db $66, $0F, $38, $DC, $8A, $A0, $00, $00, $00   // aesenc xmm1, [rdx+160]
  db $66, $0F, $38, $DC, $92, $A0, $00, $00, $00   // aesenc xmm2, [rdx+160]
  db $66, $0F, $38, $DC, $9A, $A0, $00, $00, $00   // aesenc xmm3, [rdx+160]
  db $66, $0F, $38, $DC, $A2, $A0, $00, $00, $00   // aesenc xmm4, [rdx+160]
  db $66, $0F, $38, $DC, $AA, $A0, $00, $00, $00   // aesenc xmm5, [rdx+160]
  db $66, $0F, $38, $DC, $B2, $A0, $00, $00, $00   // aesenc xmm6, [rdx+160]
  db $66, $0F, $38, $DC, $BA, $A0, $00, $00, $00   // aesenc xmm7, [rdx+160]
  db $66, $0F, $38, $DC, $82, $B0, $00, $00, $00   // aesenc xmm0, [rdx+176]
  db $66, $0F, $38, $DC, $8A, $B0, $00, $00, $00   // aesenc xmm1, [rdx+176]
  db $66, $0F, $38, $DC, $92, $B0, $00, $00, $00   // aesenc xmm2, [rdx+176]
  db $66, $0F, $38, $DC, $9A, $B0, $00, $00, $00   // aesenc xmm3, [rdx+176]
  db $66, $0F, $38, $DC, $A2, $B0, $00, $00, $00   // aesenc xmm4, [rdx+176]
  db $66, $0F, $38, $DC, $AA, $B0, $00, $00, $00   // aesenc xmm5, [rdx+176]
  db $66, $0F, $38, $DC, $B2, $B0, $00, $00, $00   // aesenc xmm6, [rdx+176]
  db $66, $0F, $38, $DC, $BA, $B0, $00, $00, $00   // aesenc xmm7, [rdx+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DC, $82, $C0, $00, $00, $00   // aesenc xmm0, [rdx+192]
  db $66, $0F, $38, $DC, $8A, $C0, $00, $00, $00   // aesenc xmm1, [rdx+192]
  db $66, $0F, $38, $DC, $92, $C0, $00, $00, $00   // aesenc xmm2, [rdx+192]
  db $66, $0F, $38, $DC, $9A, $C0, $00, $00, $00   // aesenc xmm3, [rdx+192]
  db $66, $0F, $38, $DC, $A2, $C0, $00, $00, $00   // aesenc xmm4, [rdx+192]
  db $66, $0F, $38, $DC, $AA, $C0, $00, $00, $00   // aesenc xmm5, [rdx+192]
  db $66, $0F, $38, $DC, $B2, $C0, $00, $00, $00   // aesenc xmm6, [rdx+192]
  db $66, $0F, $38, $DC, $BA, $C0, $00, $00, $00   // aesenc xmm7, [rdx+192]
  db $66, $0F, $38, $DC, $82, $D0, $00, $00, $00   // aesenc xmm0, [rdx+208]
  db $66, $0F, $38, $DC, $8A, $D0, $00, $00, $00   // aesenc xmm1, [rdx+208]
  db $66, $0F, $38, $DC, $92, $D0, $00, $00, $00   // aesenc xmm2, [rdx+208]
  db $66, $0F, $38, $DC, $9A, $D0, $00, $00, $00   // aesenc xmm3, [rdx+208]
  db $66, $0F, $38, $DC, $A2, $D0, $00, $00, $00   // aesenc xmm4, [rdx+208]
  db $66, $0F, $38, $DC, $AA, $D0, $00, $00, $00   // aesenc xmm5, [rdx+208]
  db $66, $0F, $38, $DC, $B2, $D0, $00, $00, $00   // aesenc xmm6, [rdx+208]
  db $66, $0F, $38, $DC, $BA, $D0, $00, $00, $00   // aesenc xmm7, [rdx+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DD, $82, $A0, $00, $00, $00   // aesenclast xmm0, [rdx+160]
  db $66, $0F, $38, $DD, $8A, $A0, $00, $00, $00   // aesenclast xmm1, [rdx+160]
  db $66, $0F, $38, $DD, $92, $A0, $00, $00, $00   // aesenclast xmm2, [rdx+160]
  db $66, $0F, $38, $DD, $9A, $A0, $00, $00, $00   // aesenclast xmm3, [rdx+160]
  db $66, $0F, $38, $DD, $A2, $A0, $00, $00, $00   // aesenclast xmm4, [rdx+160]
  db $66, $0F, $38, $DD, $AA, $A0, $00, $00, $00   // aesenclast xmm5, [rdx+160]
  db $66, $0F, $38, $DD, $B2, $A0, $00, $00, $00   // aesenclast xmm6, [rdx+160]
  db $66, $0F, $38, $DD, $BA, $A0, $00, $00, $00   // aesenclast xmm7, [rdx+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DD, $82, $C0, $00, $00, $00   // aesenclast xmm0, [rdx+192]
  db $66, $0F, $38, $DD, $8A, $C0, $00, $00, $00   // aesenclast xmm1, [rdx+192]
  db $66, $0F, $38, $DD, $92, $C0, $00, $00, $00   // aesenclast xmm2, [rdx+192]
  db $66, $0F, $38, $DD, $9A, $C0, $00, $00, $00   // aesenclast xmm3, [rdx+192]
  db $66, $0F, $38, $DD, $A2, $C0, $00, $00, $00   // aesenclast xmm4, [rdx+192]
  db $66, $0F, $38, $DD, $AA, $C0, $00, $00, $00   // aesenclast xmm5, [rdx+192]
  db $66, $0F, $38, $DD, $B2, $C0, $00, $00, $00   // aesenclast xmm6, [rdx+192]
  db $66, $0F, $38, $DD, $BA, $C0, $00, $00, $00   // aesenclast xmm7, [rdx+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DD, $82, $E0, $00, $00, $00   // aesenclast xmm0, [rdx+224]
  db $66, $0F, $38, $DD, $8A, $E0, $00, $00, $00   // aesenclast xmm1, [rdx+224]
  db $66, $0F, $38, $DD, $92, $E0, $00, $00, $00   // aesenclast xmm2, [rdx+224]
  db $66, $0F, $38, $DD, $9A, $E0, $00, $00, $00   // aesenclast xmm3, [rdx+224]
  db $66, $0F, $38, $DD, $A2, $E0, $00, $00, $00   // aesenclast xmm4, [rdx+224]
  db $66, $0F, $38, $DD, $AA, $E0, $00, $00, $00   // aesenclast xmm5, [rdx+224]
  db $66, $0F, $38, $DD, $B2, $E0, $00, $00, $00   // aesenclast xmm6, [rdx+224]
  db $66, $0F, $38, $DD, $BA, $E0, $00, $00, $00   // aesenclast xmm7, [rdx+224]
{$ENDIF}
{$ENDIF}

  // Post-whiten with this iteration's Deltas.
  pxor      xmm0, [rsp +   0]
  pxor      xmm1, [rsp +  16]
  pxor      xmm2, [rsp +  32]
  pxor      xmm3, [rsp +  48]
  pxor      xmm4, [rsp +  64]
  pxor      xmm5, [rsp +  80]
  pxor      xmm6, [rsp +  96]
  pxor      xmm7, [rsp + 112]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold recovered plaintext into the checksum.
  db $66, $44, $0F, $EF, $C8   // pxor xmm9, xmm0
  db $66, $44, $0F, $EF, $C9   // pxor xmm9, xmm1
  db $66, $44, $0F, $EF, $CA   // pxor xmm9, xmm2
  db $66, $44, $0F, $EF, $CB   // pxor xmm9, xmm3
  db $66, $44, $0F, $EF, $CC   // pxor xmm9, xmm4
  db $66, $44, $0F, $EF, $CD   // pxor xmm9, xmm5
  db $66, $44, $0F, $EF, $CE   // pxor xmm9, xmm6
  db $66, $44, $0F, $EF, $CF   // pxor xmm9, xmm7
{$ENDIF}

  movdqu    [r8 +   0], xmm0
  movdqu    [r8 +  16], xmm1
  movdqu    [r8 +  32], xmm2
  movdqu    [r8 +  48], xmm3
  movdqu    [r8 +  64], xmm4
  movdqu    [r8 +  80], xmm5
  movdqu    [r8 +  96], xmm6
  movdqu    [r8 + 112], xmm7
  add       rbx, 128
  add       r8, 128
  mov       rax, rbx                                // next iteration's block-0 source

  // --- Iteration B: load 8 blocks (block 0 via the staged source). ---
  movdqu    xmm0, [rax]
  movdqu    xmm1, [rbx + 16]
  movdqu    xmm2, [rbx + 32]
  movdqu    xmm3, [rbx + 48]
  movdqu    xmm4, [rbx + 64]
  movdqu    xmm5, [rbx + 80]
  movdqu    xmm6, [rbx + 96]
  movdqu    xmm7, [rbx + 112]

{$IFNDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold plaintext into the checksum.
  db $66, $44, $0F, $EF, $C8   // pxor xmm9, xmm0
  db $66, $44, $0F, $EF, $C9   // pxor xmm9, xmm1
  db $66, $44, $0F, $EF, $CA   // pxor xmm9, xmm2
  db $66, $44, $0F, $EF, $CB   // pxor xmm9, xmm3
  db $66, $44, $0F, $EF, $CC   // pxor xmm9, xmm4
  db $66, $44, $0F, $EF, $CD   // pxor xmm9, xmm5
  db $66, $44, $0F, $EF, $CE   // pxor xmm9, xmm6
  db $66, $44, $0F, $EF, $CF   // pxor xmm9, xmm7
{$ENDIF}

  // Pre-whiten with K_0 and this iteration's stashed Deltas.
  pxor      xmm0, [rdx + 0]
  pxor      xmm1, [rdx + 0]
  pxor      xmm2, [rdx + 0]
  pxor      xmm3, [rdx + 0]
  pxor      xmm4, [rdx + 0]
  pxor      xmm5, [rdx + 0]
  pxor      xmm6, [rdx + 0]
  pxor      xmm7, [rdx + 0]
  pxor      xmm0, [rsp + 128]
  pxor      xmm1, [rsp + 144]
  pxor      xmm2, [rsp + 160]
  pxor      xmm3, [rsp + 176]
  pxor      xmm4, [rsp + 192]
  pxor      xmm5, [rsp + 208]
  pxor      xmm6, [rsp + 224]
  pxor      xmm7, [rsp + 240]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Round 1
  db $66, $0F, $38, $DE, $42, $10   // aesdec xmm0, [rdx+16]
  db $66, $0F, $38, $DE, $4A, $10   // aesdec xmm1, [rdx+16]
  db $66, $0F, $38, $DE, $52, $10   // aesdec xmm2, [rdx+16]
  db $66, $0F, $38, $DE, $5A, $10   // aesdec xmm3, [rdx+16]
  db $66, $0F, $38, $DE, $62, $10   // aesdec xmm4, [rdx+16]
  db $66, $0F, $38, $DE, $6A, $10   // aesdec xmm5, [rdx+16]
  db $66, $0F, $38, $DE, $72, $10   // aesdec xmm6, [rdx+16]
  db $66, $0F, $38, $DE, $7A, $10   // aesdec xmm7, [rdx+16]
  // stage next-iteration Delta 0 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $04, $24   // movdqa [rsp+0], xmm8
  // Round 2
  db $66, $0F, $38, $DE, $42, $20   // aesdec xmm0, [rdx+32]
  db $66, $0F, $38, $DE, $4A, $20   // aesdec xmm1, [rdx+32]
  db $66, $0F, $38, $DE, $52, $20   // aesdec xmm2, [rdx+32]
  db $66, $0F, $38, $DE, $5A, $20   // aesdec xmm3, [rdx+32]
  db $66, $0F, $38, $DE, $62, $20   // aesdec xmm4, [rdx+32]
  db $66, $0F, $38, $DE, $6A, $20   // aesdec xmm5, [rdx+32]
  db $66, $0F, $38, $DE, $72, $20   // aesdec xmm6, [rdx+32]
  db $66, $0F, $38, $DE, $7A, $20   // aesdec xmm7, [rdx+32]
  // stage next-iteration Delta 1 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $10   // movdqa [rsp+16], xmm8
  // Round 3
  db $66, $0F, $38, $DE, $42, $30   // aesdec xmm0, [rdx+48]
  db $66, $0F, $38, $DE, $4A, $30   // aesdec xmm1, [rdx+48]
  db $66, $0F, $38, $DE, $52, $30   // aesdec xmm2, [rdx+48]
  db $66, $0F, $38, $DE, $5A, $30   // aesdec xmm3, [rdx+48]
  db $66, $0F, $38, $DE, $62, $30   // aesdec xmm4, [rdx+48]
  db $66, $0F, $38, $DE, $6A, $30   // aesdec xmm5, [rdx+48]
  db $66, $0F, $38, $DE, $72, $30   // aesdec xmm6, [rdx+48]
  db $66, $0F, $38, $DE, $7A, $30   // aesdec xmm7, [rdx+48]
  // stage next-iteration Delta 2 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $20   // movdqa [rsp+32], xmm8
  // Round 4
  db $66, $0F, $38, $DE, $42, $40   // aesdec xmm0, [rdx+64]
  db $66, $0F, $38, $DE, $4A, $40   // aesdec xmm1, [rdx+64]
  db $66, $0F, $38, $DE, $52, $40   // aesdec xmm2, [rdx+64]
  db $66, $0F, $38, $DE, $5A, $40   // aesdec xmm3, [rdx+64]
  db $66, $0F, $38, $DE, $62, $40   // aesdec xmm4, [rdx+64]
  db $66, $0F, $38, $DE, $6A, $40   // aesdec xmm5, [rdx+64]
  db $66, $0F, $38, $DE, $72, $40   // aesdec xmm6, [rdx+64]
  db $66, $0F, $38, $DE, $7A, $40   // aesdec xmm7, [rdx+64]
  // stage next-iteration Delta 3 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $30   // movdqa [rsp+48], xmm8
  // Round 5
  db $66, $0F, $38, $DE, $42, $50   // aesdec xmm0, [rdx+80]
  db $66, $0F, $38, $DE, $4A, $50   // aesdec xmm1, [rdx+80]
  db $66, $0F, $38, $DE, $52, $50   // aesdec xmm2, [rdx+80]
  db $66, $0F, $38, $DE, $5A, $50   // aesdec xmm3, [rdx+80]
  db $66, $0F, $38, $DE, $62, $50   // aesdec xmm4, [rdx+80]
  db $66, $0F, $38, $DE, $6A, $50   // aesdec xmm5, [rdx+80]
  db $66, $0F, $38, $DE, $72, $50   // aesdec xmm6, [rdx+80]
  db $66, $0F, $38, $DE, $7A, $50   // aesdec xmm7, [rdx+80]
  // stage next-iteration Delta 4 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $40   // movdqa [rsp+64], xmm8
  // Round 6
  db $66, $0F, $38, $DE, $42, $60   // aesdec xmm0, [rdx+96]
  db $66, $0F, $38, $DE, $4A, $60   // aesdec xmm1, [rdx+96]
  db $66, $0F, $38, $DE, $52, $60   // aesdec xmm2, [rdx+96]
  db $66, $0F, $38, $DE, $5A, $60   // aesdec xmm3, [rdx+96]
  db $66, $0F, $38, $DE, $62, $60   // aesdec xmm4, [rdx+96]
  db $66, $0F, $38, $DE, $6A, $60   // aesdec xmm5, [rdx+96]
  db $66, $0F, $38, $DE, $72, $60   // aesdec xmm6, [rdx+96]
  db $66, $0F, $38, $DE, $7A, $60   // aesdec xmm7, [rdx+96]
  // stage next-iteration Delta 5 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $50   // movdqa [rsp+80], xmm8
  // Round 7
  db $66, $0F, $38, $DE, $42, $70   // aesdec xmm0, [rdx+112]
  db $66, $0F, $38, $DE, $4A, $70   // aesdec xmm1, [rdx+112]
  db $66, $0F, $38, $DE, $52, $70   // aesdec xmm2, [rdx+112]
  db $66, $0F, $38, $DE, $5A, $70   // aesdec xmm3, [rdx+112]
  db $66, $0F, $38, $DE, $62, $70   // aesdec xmm4, [rdx+112]
  db $66, $0F, $38, $DE, $6A, $70   // aesdec xmm5, [rdx+112]
  db $66, $0F, $38, $DE, $72, $70   // aesdec xmm6, [rdx+112]
  db $66, $0F, $38, $DE, $7A, $70   // aesdec xmm7, [rdx+112]
  // stage next-iteration Delta 6 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $60   // movdqa [rsp+96], xmm8
  // Round 8
  db $66, $0F, $38, $DE, $82, $80, $00, $00, $00   // aesdec xmm0, [rdx+128]
  db $66, $0F, $38, $DE, $8A, $80, $00, $00, $00   // aesdec xmm1, [rdx+128]
  db $66, $0F, $38, $DE, $92, $80, $00, $00, $00   // aesdec xmm2, [rdx+128]
  db $66, $0F, $38, $DE, $9A, $80, $00, $00, $00   // aesdec xmm3, [rdx+128]
  db $66, $0F, $38, $DE, $A2, $80, $00, $00, $00   // aesdec xmm4, [rdx+128]
  db $66, $0F, $38, $DE, $AA, $80, $00, $00, $00   // aesdec xmm5, [rdx+128]
  db $66, $0F, $38, $DE, $B2, $80, $00, $00, $00   // aesdec xmm6, [rdx+128]
  db $66, $0F, $38, $DE, $BA, $80, $00, $00, $00   // aesdec xmm7, [rdx+128]
  // stage next-iteration Delta 7 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $70   // movdqa [rsp+112], xmm8
  // Round 9
  db $66, $0F, $38, $DE, $82, $90, $00, $00, $00   // aesdec xmm0, [rdx+144]
  db $66, $0F, $38, $DE, $8A, $90, $00, $00, $00   // aesdec xmm1, [rdx+144]
  db $66, $0F, $38, $DE, $92, $90, $00, $00, $00   // aesdec xmm2, [rdx+144]
  db $66, $0F, $38, $DE, $9A, $90, $00, $00, $00   // aesdec xmm3, [rdx+144]
  db $66, $0F, $38, $DE, $A2, $90, $00, $00, $00   // aesdec xmm4, [rdx+144]
  db $66, $0F, $38, $DE, $AA, $90, $00, $00, $00   // aesdec xmm5, [rdx+144]
  db $66, $0F, $38, $DE, $B2, $90, $00, $00, $00   // aesdec xmm6, [rdx+144]
  db $66, $0F, $38, $DE, $BA, $90, $00, $00, $00   // aesdec xmm7, [rdx+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DE, $82, $A0, $00, $00, $00   // aesdec xmm0, [rdx+160]
  db $66, $0F, $38, $DE, $8A, $A0, $00, $00, $00   // aesdec xmm1, [rdx+160]
  db $66, $0F, $38, $DE, $92, $A0, $00, $00, $00   // aesdec xmm2, [rdx+160]
  db $66, $0F, $38, $DE, $9A, $A0, $00, $00, $00   // aesdec xmm3, [rdx+160]
  db $66, $0F, $38, $DE, $A2, $A0, $00, $00, $00   // aesdec xmm4, [rdx+160]
  db $66, $0F, $38, $DE, $AA, $A0, $00, $00, $00   // aesdec xmm5, [rdx+160]
  db $66, $0F, $38, $DE, $B2, $A0, $00, $00, $00   // aesdec xmm6, [rdx+160]
  db $66, $0F, $38, $DE, $BA, $A0, $00, $00, $00   // aesdec xmm7, [rdx+160]
  db $66, $0F, $38, $DE, $82, $B0, $00, $00, $00   // aesdec xmm0, [rdx+176]
  db $66, $0F, $38, $DE, $8A, $B0, $00, $00, $00   // aesdec xmm1, [rdx+176]
  db $66, $0F, $38, $DE, $92, $B0, $00, $00, $00   // aesdec xmm2, [rdx+176]
  db $66, $0F, $38, $DE, $9A, $B0, $00, $00, $00   // aesdec xmm3, [rdx+176]
  db $66, $0F, $38, $DE, $A2, $B0, $00, $00, $00   // aesdec xmm4, [rdx+176]
  db $66, $0F, $38, $DE, $AA, $B0, $00, $00, $00   // aesdec xmm5, [rdx+176]
  db $66, $0F, $38, $DE, $B2, $B0, $00, $00, $00   // aesdec xmm6, [rdx+176]
  db $66, $0F, $38, $DE, $BA, $B0, $00, $00, $00   // aesdec xmm7, [rdx+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DE, $82, $C0, $00, $00, $00   // aesdec xmm0, [rdx+192]
  db $66, $0F, $38, $DE, $8A, $C0, $00, $00, $00   // aesdec xmm1, [rdx+192]
  db $66, $0F, $38, $DE, $92, $C0, $00, $00, $00   // aesdec xmm2, [rdx+192]
  db $66, $0F, $38, $DE, $9A, $C0, $00, $00, $00   // aesdec xmm3, [rdx+192]
  db $66, $0F, $38, $DE, $A2, $C0, $00, $00, $00   // aesdec xmm4, [rdx+192]
  db $66, $0F, $38, $DE, $AA, $C0, $00, $00, $00   // aesdec xmm5, [rdx+192]
  db $66, $0F, $38, $DE, $B2, $C0, $00, $00, $00   // aesdec xmm6, [rdx+192]
  db $66, $0F, $38, $DE, $BA, $C0, $00, $00, $00   // aesdec xmm7, [rdx+192]
  db $66, $0F, $38, $DE, $82, $D0, $00, $00, $00   // aesdec xmm0, [rdx+208]
  db $66, $0F, $38, $DE, $8A, $D0, $00, $00, $00   // aesdec xmm1, [rdx+208]
  db $66, $0F, $38, $DE, $92, $D0, $00, $00, $00   // aesdec xmm2, [rdx+208]
  db $66, $0F, $38, $DE, $9A, $D0, $00, $00, $00   // aesdec xmm3, [rdx+208]
  db $66, $0F, $38, $DE, $A2, $D0, $00, $00, $00   // aesdec xmm4, [rdx+208]
  db $66, $0F, $38, $DE, $AA, $D0, $00, $00, $00   // aesdec xmm5, [rdx+208]
  db $66, $0F, $38, $DE, $B2, $D0, $00, $00, $00   // aesdec xmm6, [rdx+208]
  db $66, $0F, $38, $DE, $BA, $D0, $00, $00, $00   // aesdec xmm7, [rdx+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DF, $82, $A0, $00, $00, $00   // aesdeclast xmm0, [rdx+160]
  db $66, $0F, $38, $DF, $8A, $A0, $00, $00, $00   // aesdeclast xmm1, [rdx+160]
  db $66, $0F, $38, $DF, $92, $A0, $00, $00, $00   // aesdeclast xmm2, [rdx+160]
  db $66, $0F, $38, $DF, $9A, $A0, $00, $00, $00   // aesdeclast xmm3, [rdx+160]
  db $66, $0F, $38, $DF, $A2, $A0, $00, $00, $00   // aesdeclast xmm4, [rdx+160]
  db $66, $0F, $38, $DF, $AA, $A0, $00, $00, $00   // aesdeclast xmm5, [rdx+160]
  db $66, $0F, $38, $DF, $B2, $A0, $00, $00, $00   // aesdeclast xmm6, [rdx+160]
  db $66, $0F, $38, $DF, $BA, $A0, $00, $00, $00   // aesdeclast xmm7, [rdx+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DF, $82, $C0, $00, $00, $00   // aesdeclast xmm0, [rdx+192]
  db $66, $0F, $38, $DF, $8A, $C0, $00, $00, $00   // aesdeclast xmm1, [rdx+192]
  db $66, $0F, $38, $DF, $92, $C0, $00, $00, $00   // aesdeclast xmm2, [rdx+192]
  db $66, $0F, $38, $DF, $9A, $C0, $00, $00, $00   // aesdeclast xmm3, [rdx+192]
  db $66, $0F, $38, $DF, $A2, $C0, $00, $00, $00   // aesdeclast xmm4, [rdx+192]
  db $66, $0F, $38, $DF, $AA, $C0, $00, $00, $00   // aesdeclast xmm5, [rdx+192]
  db $66, $0F, $38, $DF, $B2, $C0, $00, $00, $00   // aesdeclast xmm6, [rdx+192]
  db $66, $0F, $38, $DF, $BA, $C0, $00, $00, $00   // aesdeclast xmm7, [rdx+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DF, $82, $E0, $00, $00, $00   // aesdeclast xmm0, [rdx+224]
  db $66, $0F, $38, $DF, $8A, $E0, $00, $00, $00   // aesdeclast xmm1, [rdx+224]
  db $66, $0F, $38, $DF, $92, $E0, $00, $00, $00   // aesdeclast xmm2, [rdx+224]
  db $66, $0F, $38, $DF, $9A, $E0, $00, $00, $00   // aesdeclast xmm3, [rdx+224]
  db $66, $0F, $38, $DF, $A2, $E0, $00, $00, $00   // aesdeclast xmm4, [rdx+224]
  db $66, $0F, $38, $DF, $AA, $E0, $00, $00, $00   // aesdeclast xmm5, [rdx+224]
  db $66, $0F, $38, $DF, $B2, $E0, $00, $00, $00   // aesdeclast xmm6, [rdx+224]
  db $66, $0F, $38, $DF, $BA, $E0, $00, $00, $00   // aesdeclast xmm7, [rdx+224]
{$ENDIF}
{$ELSE}
  // Round 1
  db $66, $0F, $38, $DC, $42, $10   // aesenc xmm0, [rdx+16]
  db $66, $0F, $38, $DC, $4A, $10   // aesenc xmm1, [rdx+16]
  db $66, $0F, $38, $DC, $52, $10   // aesenc xmm2, [rdx+16]
  db $66, $0F, $38, $DC, $5A, $10   // aesenc xmm3, [rdx+16]
  db $66, $0F, $38, $DC, $62, $10   // aesenc xmm4, [rdx+16]
  db $66, $0F, $38, $DC, $6A, $10   // aesenc xmm5, [rdx+16]
  db $66, $0F, $38, $DC, $72, $10   // aesenc xmm6, [rdx+16]
  db $66, $0F, $38, $DC, $7A, $10   // aesenc xmm7, [rdx+16]
  // stage next-iteration Delta 0 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $04, $24   // movdqa [rsp+0], xmm8
  // Round 2
  db $66, $0F, $38, $DC, $42, $20   // aesenc xmm0, [rdx+32]
  db $66, $0F, $38, $DC, $4A, $20   // aesenc xmm1, [rdx+32]
  db $66, $0F, $38, $DC, $52, $20   // aesenc xmm2, [rdx+32]
  db $66, $0F, $38, $DC, $5A, $20   // aesenc xmm3, [rdx+32]
  db $66, $0F, $38, $DC, $62, $20   // aesenc xmm4, [rdx+32]
  db $66, $0F, $38, $DC, $6A, $20   // aesenc xmm5, [rdx+32]
  db $66, $0F, $38, $DC, $72, $20   // aesenc xmm6, [rdx+32]
  db $66, $0F, $38, $DC, $7A, $20   // aesenc xmm7, [rdx+32]
  // stage next-iteration Delta 1 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $10   // movdqa [rsp+16], xmm8
  // Round 3
  db $66, $0F, $38, $DC, $42, $30   // aesenc xmm0, [rdx+48]
  db $66, $0F, $38, $DC, $4A, $30   // aesenc xmm1, [rdx+48]
  db $66, $0F, $38, $DC, $52, $30   // aesenc xmm2, [rdx+48]
  db $66, $0F, $38, $DC, $5A, $30   // aesenc xmm3, [rdx+48]
  db $66, $0F, $38, $DC, $62, $30   // aesenc xmm4, [rdx+48]
  db $66, $0F, $38, $DC, $6A, $30   // aesenc xmm5, [rdx+48]
  db $66, $0F, $38, $DC, $72, $30   // aesenc xmm6, [rdx+48]
  db $66, $0F, $38, $DC, $7A, $30   // aesenc xmm7, [rdx+48]
  // stage next-iteration Delta 2 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $20   // movdqa [rsp+32], xmm8
  // Round 4
  db $66, $0F, $38, $DC, $42, $40   // aesenc xmm0, [rdx+64]
  db $66, $0F, $38, $DC, $4A, $40   // aesenc xmm1, [rdx+64]
  db $66, $0F, $38, $DC, $52, $40   // aesenc xmm2, [rdx+64]
  db $66, $0F, $38, $DC, $5A, $40   // aesenc xmm3, [rdx+64]
  db $66, $0F, $38, $DC, $62, $40   // aesenc xmm4, [rdx+64]
  db $66, $0F, $38, $DC, $6A, $40   // aesenc xmm5, [rdx+64]
  db $66, $0F, $38, $DC, $72, $40   // aesenc xmm6, [rdx+64]
  db $66, $0F, $38, $DC, $7A, $40   // aesenc xmm7, [rdx+64]
  // stage next-iteration Delta 3 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $30   // movdqa [rsp+48], xmm8
  // Round 5
  db $66, $0F, $38, $DC, $42, $50   // aesenc xmm0, [rdx+80]
  db $66, $0F, $38, $DC, $4A, $50   // aesenc xmm1, [rdx+80]
  db $66, $0F, $38, $DC, $52, $50   // aesenc xmm2, [rdx+80]
  db $66, $0F, $38, $DC, $5A, $50   // aesenc xmm3, [rdx+80]
  db $66, $0F, $38, $DC, $62, $50   // aesenc xmm4, [rdx+80]
  db $66, $0F, $38, $DC, $6A, $50   // aesenc xmm5, [rdx+80]
  db $66, $0F, $38, $DC, $72, $50   // aesenc xmm6, [rdx+80]
  db $66, $0F, $38, $DC, $7A, $50   // aesenc xmm7, [rdx+80]
  // stage next-iteration Delta 4 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $40   // movdqa [rsp+64], xmm8
  // Round 6
  db $66, $0F, $38, $DC, $42, $60   // aesenc xmm0, [rdx+96]
  db $66, $0F, $38, $DC, $4A, $60   // aesenc xmm1, [rdx+96]
  db $66, $0F, $38, $DC, $52, $60   // aesenc xmm2, [rdx+96]
  db $66, $0F, $38, $DC, $5A, $60   // aesenc xmm3, [rdx+96]
  db $66, $0F, $38, $DC, $62, $60   // aesenc xmm4, [rdx+96]
  db $66, $0F, $38, $DC, $6A, $60   // aesenc xmm5, [rdx+96]
  db $66, $0F, $38, $DC, $72, $60   // aesenc xmm6, [rdx+96]
  db $66, $0F, $38, $DC, $7A, $60   // aesenc xmm7, [rdx+96]
  // stage next-iteration Delta 5 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $50   // movdqa [rsp+80], xmm8
  // Round 7
  db $66, $0F, $38, $DC, $42, $70   // aesenc xmm0, [rdx+112]
  db $66, $0F, $38, $DC, $4A, $70   // aesenc xmm1, [rdx+112]
  db $66, $0F, $38, $DC, $52, $70   // aesenc xmm2, [rdx+112]
  db $66, $0F, $38, $DC, $5A, $70   // aesenc xmm3, [rdx+112]
  db $66, $0F, $38, $DC, $62, $70   // aesenc xmm4, [rdx+112]
  db $66, $0F, $38, $DC, $6A, $70   // aesenc xmm5, [rdx+112]
  db $66, $0F, $38, $DC, $72, $70   // aesenc xmm6, [rdx+112]
  db $66, $0F, $38, $DC, $7A, $70   // aesenc xmm7, [rdx+112]
  // stage next-iteration Delta 6 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $60   // movdqa [rsp+96], xmm8
  // Round 8
  db $66, $0F, $38, $DC, $82, $80, $00, $00, $00   // aesenc xmm0, [rdx+128]
  db $66, $0F, $38, $DC, $8A, $80, $00, $00, $00   // aesenc xmm1, [rdx+128]
  db $66, $0F, $38, $DC, $92, $80, $00, $00, $00   // aesenc xmm2, [rdx+128]
  db $66, $0F, $38, $DC, $9A, $80, $00, $00, $00   // aesenc xmm3, [rdx+128]
  db $66, $0F, $38, $DC, $A2, $80, $00, $00, $00   // aesenc xmm4, [rdx+128]
  db $66, $0F, $38, $DC, $AA, $80, $00, $00, $00   // aesenc xmm5, [rdx+128]
  db $66, $0F, $38, $DC, $B2, $80, $00, $00, $00   // aesenc xmm6, [rdx+128]
  db $66, $0F, $38, $DC, $BA, $80, $00, $00, $00   // aesenc xmm7, [rdx+128]
  // stage next-iteration Delta 7 -> bank 0
  add       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $70   // movdqa [rsp+112], xmm8
  // Round 9
  db $66, $0F, $38, $DC, $82, $90, $00, $00, $00   // aesenc xmm0, [rdx+144]
  db $66, $0F, $38, $DC, $8A, $90, $00, $00, $00   // aesenc xmm1, [rdx+144]
  db $66, $0F, $38, $DC, $92, $90, $00, $00, $00   // aesenc xmm2, [rdx+144]
  db $66, $0F, $38, $DC, $9A, $90, $00, $00, $00   // aesenc xmm3, [rdx+144]
  db $66, $0F, $38, $DC, $A2, $90, $00, $00, $00   // aesenc xmm4, [rdx+144]
  db $66, $0F, $38, $DC, $AA, $90, $00, $00, $00   // aesenc xmm5, [rdx+144]
  db $66, $0F, $38, $DC, $B2, $90, $00, $00, $00   // aesenc xmm6, [rdx+144]
  db $66, $0F, $38, $DC, $BA, $90, $00, $00, $00   // aesenc xmm7, [rdx+144]
{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DC, $82, $A0, $00, $00, $00   // aesenc xmm0, [rdx+160]
  db $66, $0F, $38, $DC, $8A, $A0, $00, $00, $00   // aesenc xmm1, [rdx+160]
  db $66, $0F, $38, $DC, $92, $A0, $00, $00, $00   // aesenc xmm2, [rdx+160]
  db $66, $0F, $38, $DC, $9A, $A0, $00, $00, $00   // aesenc xmm3, [rdx+160]
  db $66, $0F, $38, $DC, $A2, $A0, $00, $00, $00   // aesenc xmm4, [rdx+160]
  db $66, $0F, $38, $DC, $AA, $A0, $00, $00, $00   // aesenc xmm5, [rdx+160]
  db $66, $0F, $38, $DC, $B2, $A0, $00, $00, $00   // aesenc xmm6, [rdx+160]
  db $66, $0F, $38, $DC, $BA, $A0, $00, $00, $00   // aesenc xmm7, [rdx+160]
  db $66, $0F, $38, $DC, $82, $B0, $00, $00, $00   // aesenc xmm0, [rdx+176]
  db $66, $0F, $38, $DC, $8A, $B0, $00, $00, $00   // aesenc xmm1, [rdx+176]
  db $66, $0F, $38, $DC, $92, $B0, $00, $00, $00   // aesenc xmm2, [rdx+176]
  db $66, $0F, $38, $DC, $9A, $B0, $00, $00, $00   // aesenc xmm3, [rdx+176]
  db $66, $0F, $38, $DC, $A2, $B0, $00, $00, $00   // aesenc xmm4, [rdx+176]
  db $66, $0F, $38, $DC, $AA, $B0, $00, $00, $00   // aesenc xmm5, [rdx+176]
  db $66, $0F, $38, $DC, $B2, $B0, $00, $00, $00   // aesenc xmm6, [rdx+176]
  db $66, $0F, $38, $DC, $BA, $B0, $00, $00, $00   // aesenc xmm7, [rdx+176]
{$IFEND}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DC, $82, $C0, $00, $00, $00   // aesenc xmm0, [rdx+192]
  db $66, $0F, $38, $DC, $8A, $C0, $00, $00, $00   // aesenc xmm1, [rdx+192]
  db $66, $0F, $38, $DC, $92, $C0, $00, $00, $00   // aesenc xmm2, [rdx+192]
  db $66, $0F, $38, $DC, $9A, $C0, $00, $00, $00   // aesenc xmm3, [rdx+192]
  db $66, $0F, $38, $DC, $A2, $C0, $00, $00, $00   // aesenc xmm4, [rdx+192]
  db $66, $0F, $38, $DC, $AA, $C0, $00, $00, $00   // aesenc xmm5, [rdx+192]
  db $66, $0F, $38, $DC, $B2, $C0, $00, $00, $00   // aesenc xmm6, [rdx+192]
  db $66, $0F, $38, $DC, $BA, $C0, $00, $00, $00   // aesenc xmm7, [rdx+192]
  db $66, $0F, $38, $DC, $82, $D0, $00, $00, $00   // aesenc xmm0, [rdx+208]
  db $66, $0F, $38, $DC, $8A, $D0, $00, $00, $00   // aesenc xmm1, [rdx+208]
  db $66, $0F, $38, $DC, $92, $D0, $00, $00, $00   // aesenc xmm2, [rdx+208]
  db $66, $0F, $38, $DC, $9A, $D0, $00, $00, $00   // aesenc xmm3, [rdx+208]
  db $66, $0F, $38, $DC, $A2, $D0, $00, $00, $00   // aesenc xmm4, [rdx+208]
  db $66, $0F, $38, $DC, $AA, $D0, $00, $00, $00   // aesenc xmm5, [rdx+208]
  db $66, $0F, $38, $DC, $B2, $D0, $00, $00, $00   // aesenc xmm6, [rdx+208]
  db $66, $0F, $38, $DC, $BA, $D0, $00, $00, $00   // aesenc xmm7, [rdx+208]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DD, $82, $A0, $00, $00, $00   // aesenclast xmm0, [rdx+160]
  db $66, $0F, $38, $DD, $8A, $A0, $00, $00, $00   // aesenclast xmm1, [rdx+160]
  db $66, $0F, $38, $DD, $92, $A0, $00, $00, $00   // aesenclast xmm2, [rdx+160]
  db $66, $0F, $38, $DD, $9A, $A0, $00, $00, $00   // aesenclast xmm3, [rdx+160]
  db $66, $0F, $38, $DD, $A2, $A0, $00, $00, $00   // aesenclast xmm4, [rdx+160]
  db $66, $0F, $38, $DD, $AA, $A0, $00, $00, $00   // aesenclast xmm5, [rdx+160]
  db $66, $0F, $38, $DD, $B2, $A0, $00, $00, $00   // aesenclast xmm6, [rdx+160]
  db $66, $0F, $38, $DD, $BA, $A0, $00, $00, $00   // aesenclast xmm7, [rdx+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DD, $82, $C0, $00, $00, $00   // aesenclast xmm0, [rdx+192]
  db $66, $0F, $38, $DD, $8A, $C0, $00, $00, $00   // aesenclast xmm1, [rdx+192]
  db $66, $0F, $38, $DD, $92, $C0, $00, $00, $00   // aesenclast xmm2, [rdx+192]
  db $66, $0F, $38, $DD, $9A, $C0, $00, $00, $00   // aesenclast xmm3, [rdx+192]
  db $66, $0F, $38, $DD, $A2, $C0, $00, $00, $00   // aesenclast xmm4, [rdx+192]
  db $66, $0F, $38, $DD, $AA, $C0, $00, $00, $00   // aesenclast xmm5, [rdx+192]
  db $66, $0F, $38, $DD, $B2, $C0, $00, $00, $00   // aesenclast xmm6, [rdx+192]
  db $66, $0F, $38, $DD, $BA, $C0, $00, $00, $00   // aesenclast xmm7, [rdx+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DD, $82, $E0, $00, $00, $00   // aesenclast xmm0, [rdx+224]
  db $66, $0F, $38, $DD, $8A, $E0, $00, $00, $00   // aesenclast xmm1, [rdx+224]
  db $66, $0F, $38, $DD, $92, $E0, $00, $00, $00   // aesenclast xmm2, [rdx+224]
  db $66, $0F, $38, $DD, $9A, $E0, $00, $00, $00   // aesenclast xmm3, [rdx+224]
  db $66, $0F, $38, $DD, $A2, $E0, $00, $00, $00   // aesenclast xmm4, [rdx+224]
  db $66, $0F, $38, $DD, $AA, $E0, $00, $00, $00   // aesenclast xmm5, [rdx+224]
  db $66, $0F, $38, $DD, $B2, $E0, $00, $00, $00   // aesenclast xmm6, [rdx+224]
  db $66, $0F, $38, $DD, $BA, $E0, $00, $00, $00   // aesenclast xmm7, [rdx+224]
{$ENDIF}
{$ENDIF}

  // Post-whiten with this iteration's Deltas.
  pxor      xmm0, [rsp + 128]
  pxor      xmm1, [rsp + 144]
  pxor      xmm2, [rsp + 160]
  pxor      xmm3, [rsp + 176]
  pxor      xmm4, [rsp + 192]
  pxor      xmm5, [rsp + 208]
  pxor      xmm6, [rsp + 224]
  pxor      xmm7, [rsp + 240]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // Fold recovered plaintext into the checksum.
  db $66, $44, $0F, $EF, $C8   // pxor xmm9, xmm0
  db $66, $44, $0F, $EF, $C9   // pxor xmm9, xmm1
  db $66, $44, $0F, $EF, $CA   // pxor xmm9, xmm2
  db $66, $44, $0F, $EF, $CB   // pxor xmm9, xmm3
  db $66, $44, $0F, $EF, $CC   // pxor xmm9, xmm4
  db $66, $44, $0F, $EF, $CD   // pxor xmm9, xmm5
  db $66, $44, $0F, $EF, $CE   // pxor xmm9, xmm6
  db $66, $44, $0F, $EF, $CF   // pxor xmm9, xmm7
{$ENDIF}

  movdqu    [r8 +   0], xmm0
  movdqu    [r8 +  16], xmm1
  movdqu    [r8 +  32], xmm2
  movdqu    [r8 +  48], xmm3
  movdqu    [r8 +  64], xmm4
  movdqu    [r8 +  80], xmm5
  movdqu    [r8 +  96], xmm6
  movdqu    [r8 + 112], xmm7
  add       rbx, 128
  add       r8, 128
  mov       rax, rbx                                // next iteration's block-0 source

  sub       r10, 1
  jnz       @@ocb_x64_loop

  // --- Undo the one-iteration ladder over-stage (XOR self-inverse). ---
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1
  bsf       rax, r11
  shl       rax, 4
  add       rax, r9
  db $F3, $44, $0F, $6F, $18   // movdqu xmm11, [rax]
  db $66, $45, $0F, $EF, $C3   // pxor xmm8, xmm11
  sub       r11, 1

  // --- Epilogue: flush accumulators, unwind. ---
  mov       rax, [rcx + 24]
  db $F3, $44, $0F, $7F, $00   // movdqu [rax], xmm8
  mov       rax, [rcx + 32]
  db $F3, $44, $0F, $7F, $08   // movdqu [rax], xmm9

  add       rsp, 256
  pop       rbx
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

