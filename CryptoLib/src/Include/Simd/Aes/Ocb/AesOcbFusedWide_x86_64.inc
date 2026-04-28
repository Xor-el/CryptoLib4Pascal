// OCB fused 8-wide AES-NI kernel (x86-64) with in-kernel offset ladder,
// L-table lookup and checksum fold.
// -------------------------------------------------------------------
// Processes ABlockCount consecutive 16-byte OCB body blocks in chunks
// of 8 blocks (128 bytes) per iteration. The kernel owns all per-block
// OCB bookkeeping across the batch: on entry it seeds xmm_offset from
// OffsetPtr and xmm_checksum from ChecksumPtr; the loop walks a
// pre-computed ntz byte array, XORs the L-table entry into xmm_offset
// to derive each Delta, runs P_i XOR delta XOR K_0 through the AES
// rounds, XORs delta into the post-aesenclast state to produce C_i,
// and folds plaintext into xmm_checksum; on exit it writes xmm_offset
// and xmm_checksum back. The mode layer never touches per-block state.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// On entry (after SimdProc1Begin_x86_64.inc): rcx = PCtx.
//
// Context layout (8 pointers + 1 NativeUInt = 72 bytes, 8-byte aligned).
// See TOcbFusedKernelCtx in ClpAesNiOcbKernel.pas.
//   [rcx +  0]  Keys        : AES schedule (encrypt or inv-MixColumns; 16-byte aligned)
//   [rcx +  8]  InPtr       : base of the main 16-byte-block stream
//   [rcx + 16]  OutPtr      : base of BlockCount output blocks (may alias InPtr)
//   [rcx + 24]  OffsetPtr   : 16-byte live FOffsetMAIN (r/w)
//   [rcx + 32]  ChecksumPtr : 16-byte live FChecksum (r/w)
//   [rcx + 40]  LTablePtr   : flat L[0..LMax] * 16 bytes (read-only)
//   [rcx + 48]  NtzPtr      : BlockCount bytes of pre-computed ntz values
//   [rcx + 56]  Block0Ptr   : 16-byte source of iteration-0 block 0 (may alias InPtr)
//   [rcx + 64]  BlockCount  : NativeUInt; multiple of 8
//
// XMM (12/16 used):
//   xmm0..xmm7   : 8 data lanes
//   xmm8         : xmm_offset accumulator (seeded/stored once per batch)
//   xmm9         : xmm_checksum accumulator (seeded/stored once per batch)
//   xmm10        : AES round-key scratch (movdqa reload per round)
//   xmm11        : L-table load scratch
//   xmm12..xmm15 : free
//
// Stack scratch (128 bytes, 16-aligned):
//   [rsp +   0 ..  127]  8 x 16-byte per-block offset stashes (movdqa-safe)
//
// AES-NI instructions and selected forms touching xmm8..xmm15 (pxor,
// movdqa) are db-encoded for broad assembler compatibility.
// -------------------------------------------------------------------

  // --- Prologue: preserve rbx, reserve 128B aligned stack scratch. ---
  push      rbx                                     // rsp: 8 -> 0 mod 16
  sub       rsp, 128                                // rsp stays 0 mod 16

  // --- Load context pointers. rcx (PCtx) stays live for the
  //     epilogue store-backs; everything else derives from rcx now. ---
  mov       rdx, [rcx +  0]                         // rdx = Keys
  mov       rbx, [rcx +  8]                         // rbx = InPtr
  mov       r8,  [rcx + 16]                         // r8  = OutPtr
  mov       r9,  [rcx + 40]                         // r9  = LTablePtr
  mov       r11, [rcx + 48]                         // r11 = NtzPtr
  mov       r10, [rcx + 64]                         // r10 = BlockCount
  shr       r10, 3                                  // r10 /= 8 (>= 1)

  // --- Seed the persistent accumulators from memory (one-shot).
  //     rax is used as a scratch for the two-hop ptr-of-ptr loads
  //     and is then overwritten with Block0Ptr for the loop. ---
  mov       rax, [rcx + 24]                         // rax = OffsetPtr
  movdqu    xmm8, [rax]                             // xmm8 = FOffsetMAIN
  mov       rax, [rcx + 32]                         // rax = ChecksumPtr
  movdqu    xmm9, [rax]                             // xmm9 = FChecksum

  // --- Seed the block-0 pointer. rax persists across loop
  //     iterations: iter 0 consumes it via Phase 2 below, and
  //     every iteration's bottom refreshes it to rbx (the main
  //     stream advance) so iter >= 1 loads block 0 from the
  //     normal +0 offset transparently. ---
  mov       rax, [rcx + 56]                         // rax = Block0Ptr

@@ocb_x64_loop:

  // ------------------------------------------------------------------
  // Phase 2: load 8 input blocks into xmm0..xmm7. Must run BEFORE the
  // ladder because Phase 1 below clobbers rax (ntz scratch and
  // L-table index). On iter 0 rax points at Block0Ptr (which may be
  // unrelated to rbx, e.g. FMainBlock for full-MAC decrypt); on every
  // subsequent iter the end-of-iter epilogue sets rax := rbx (the
  // freshly advanced main stream), so `movdqu xmm0, [rax]` becomes
  // effectively identical to `movdqu xmm0, [rbx + 0]`. Blocks 1..7
  // always come from the advancing main stream at rbx + 16..112.
  // ------------------------------------------------------------------
  movdqu    xmm0, [rax]
  movdqu    xmm1, [rbx +  16]
  movdqu    xmm2, [rbx +  32]
  movdqu    xmm3, [rbx +  48]
  movdqu    xmm4, [rbx +  64]
  movdqu    xmm5, [rbx +  80]
  movdqu    xmm6, [rbx +  96]
  movdqu    xmm7, [rbx + 112]

  // ------------------------------------------------------------------
  // Phase 1: offset ladder. For each block i in 0..7 read ntz[i],
  // scale to a 16-byte L-table offset, XOR the entry into xmm_offset
  // (xmm8) and stash the post-XOR value into [rsp + 16*i]. After this
  // phase [rsp + 0..127] holds eight consecutive 16-byte Delta values
  // and xmm8 holds the Delta after the final block of this chunk
  // (which is also the starting Delta for the next chunk).
  //
  // Each step emits:
  //   movzx eax, byte [r11 + i]          ; eax = ntz[i]
  //   shl   rax, 4                       ; rax = ntz[i] * 16
  //   movdqu xmm11, [r9 + rax]           ; xmm11 = L[ntz[i]]
  //   pxor  xmm8, xmm11                  ; xmm8 ^= L[ntz[i]]  (db)
  //   movdqa [rsp + 16*i], xmm8          ; stash offset_i      (db)
  // ------------------------------------------------------------------
  // Block 0
  movzx     eax, byte [r11 + 0]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                        // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $00              // movdqa [rsp+0], xmm8
  // Block 1
  movzx     eax, byte [r11 + 1]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                       // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $10              // movdqa [rsp+16], xmm8
  // Block 2
  movzx     eax, byte [r11 + 2]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                       // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $20              // movdqa [rsp+32], xmm8
  // Block 3
  movzx     eax, byte [r11 + 3]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                       // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $30              // movdqa [rsp+48], xmm8
  // Block 4
  movzx     eax, byte [r11 + 4]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                       // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $40              // movdqa [rsp+64], xmm8
  // Block 5
  movzx     eax, byte [r11 + 5]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                       // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $50              // movdqa [rsp+80], xmm8
  // Block 6
  movzx     eax, byte [r11 + 6]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                       // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $60              // movdqa [rsp+96], xmm8
  // Block 7
  movzx     eax, byte [r11 + 7]
  shl       rax, 4
  movdqu    xmm11, [r9 + rax]
  db $66, $45, $0F, $EF, $C3                       // pxor xmm8, xmm11
  db $66, $44, $0F, $7F, $44, $24, $70              // movdqa [rsp+112], xmm8

{$IFNDEF CRYPTOLIB_AESNI_DECRYPT}
  // --- Phase 3 (encrypt): fold plaintext into xmm_checksum BEFORE
  //     any data XOR. ---
  // pxor xmm9, xmmX : REX.R only ($44), ModR/M = 11 001 rrr (reg=xmm9,
  // r/m=xmmX). bytes: $C8 $C9 $CA $CB $CC $CD $CE $CF for xmm0..xmm7.
  db $66, $44, $0F, $EF, $C8                        // pxor xmm9, xmm0
  db $66, $44, $0F, $EF, $C9                        // pxor xmm9, xmm1
  db $66, $44, $0F, $EF, $CA                        // pxor xmm9, xmm2
  db $66, $44, $0F, $EF, $CB                        // pxor xmm9, xmm3
  db $66, $44, $0F, $EF, $CC                        // pxor xmm9, xmm4
  db $66, $44, $0F, $EF, $CD                        // pxor xmm9, xmm5
  db $66, $44, $0F, $EF, $CE                        // pxor xmm9, xmm6
  db $66, $44, $0F, $EF, $CF                        // pxor xmm9, xmm7
{$ENDIF}

  // --- Phase 4: pre-whiten with K_0 (aligned reg reload into xmm10
  //     broadcast across all 8 data lanes via db-encoded pxor). ---
  movdqa    xmm10, [rdx]                            // xmm10 = K_0
  // pxor xmmX, xmm10 : REX.B ($41), ModR/M = 11 rrr 010 (r/m=xmm10,
  // low-3 bits = 010). bytes for reg=xmm0..xmm7:
  //   $C2 $CA $D2 $DA $E2 $EA $F2 $FA
  db $66, $41, $0F, $EF, $C2                        // pxor xmm0, xmm10
  db $66, $41, $0F, $EF, $CA                        // pxor xmm1, xmm10
  db $66, $41, $0F, $EF, $D2                        // pxor xmm2, xmm10
  db $66, $41, $0F, $EF, $DA                        // pxor xmm3, xmm10
  db $66, $41, $0F, $EF, $E2                        // pxor xmm4, xmm10
  db $66, $41, $0F, $EF, $EA                        // pxor xmm5, xmm10
  db $66, $41, $0F, $EF, $F2                        // pxor xmm6, xmm10
  db $66, $41, $0F, $EF, $FA                        // pxor xmm7, xmm10

  // --- Phase 5: pre-whiten with stashed per-block offsets. Stack
  //     scratch is 16-aligned so memory-form pxor is safe; no REX. ---
  pxor      xmm0, [rsp +   0]
  pxor      xmm1, [rsp +  16]
  pxor      xmm2, [rsp +  32]
  pxor      xmm3, [rsp +  48]
  pxor      xmm4, [rsp +  64]
  pxor      xmm5, [rsp +  80]
  pxor      xmm6, [rsp +  96]
  pxor      xmm7, [rsp + 112]

  // ------------------------------------------------------------------
  // Phase 6: AES middle rounds 1..N-1. xmm10 is reloaded per round
  // with the round key and broadcast-XORed/AES'd across all 8 data
  // lanes. Opcode byte selects direction:
  //   $DC = aesenc    $DE = aesdec
  // ModR/M bytes with r/m=xmm10 follow the same $C2..$FA sequence
  // used in Phase 4.
  // ------------------------------------------------------------------
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

  // Round 1
  movdqa    xmm10, [rdx + 16]
  db $66, $41, $0F, $38, $DE, $C2                   // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                   // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                   // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                   // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                   // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                   // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                   // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                   // aesdec xmm7, xmm10
  // Round 2
  movdqa    xmm10, [rdx + 32]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 3
  movdqa    xmm10, [rdx + 48]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 4
  movdqa    xmm10, [rdx + 64]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 5
  movdqa    xmm10, [rdx + 80]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 6
  movdqa    xmm10, [rdx + 96]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 7
  movdqa    xmm10, [rdx + 112]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 8
  movdqa    xmm10, [rdx + 128]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 9
  movdqa    xmm10, [rdx + 144]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10

{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Round 10
  movdqa    xmm10, [rdx + 160]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 11
  movdqa    xmm10, [rdx + 176]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
{$ENDIF}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 10
  movdqa    xmm10, [rdx + 160]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 11
  movdqa    xmm10, [rdx + 176]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 12
  movdqa    xmm10, [rdx + 192]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
  // Round 13
  movdqa    xmm10, [rdx + 208]
  db $66, $41, $0F, $38, $DE, $C2                  // aesdec xmm0, xmm10
  db $66, $41, $0F, $38, $DE, $CA                  // aesdec xmm1, xmm10
  db $66, $41, $0F, $38, $DE, $D2                  // aesdec xmm2, xmm10
  db $66, $41, $0F, $38, $DE, $DA                  // aesdec xmm3, xmm10
  db $66, $41, $0F, $38, $DE, $E2                  // aesdec xmm4, xmm10
  db $66, $41, $0F, $38, $DE, $EA                  // aesdec xmm5, xmm10
  db $66, $41, $0F, $38, $DE, $F2                  // aesdec xmm6, xmm10
  db $66, $41, $0F, $38, $DE, $FA                  // aesdec xmm7, xmm10
{$ENDIF}

  // --- Phase 7: final round. Opcode $DF = aesdeclast. ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm10, [rdx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm10, [rdx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm10, [rdx + 224]
{$ENDIF}
  db $66, $41, $0F, $38, $DF, $C2                   // aesdeclast xmm0, xmm10
  db $66, $41, $0F, $38, $DF, $CA                   // aesdeclast xmm1, xmm10
  db $66, $41, $0F, $38, $DF, $D2                   // aesdeclast xmm2, xmm10
  db $66, $41, $0F, $38, $DF, $DA                   // aesdeclast xmm3, xmm10
  db $66, $41, $0F, $38, $DF, $E2                   // aesdeclast xmm4, xmm10
  db $66, $41, $0F, $38, $DF, $EA                   // aesdeclast xmm5, xmm10
  db $66, $41, $0F, $38, $DF, $F2                   // aesdeclast xmm6, xmm10
  db $66, $41, $0F, $38, $DF, $FA                   // aesdeclast xmm7, xmm10

{$ELSE} // ===================== ENCRYPT variant =====================

  // Round 1
  movdqa    xmm10, [rdx + 16]
  db $66, $41, $0F, $38, $DC, $C2                   // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 2
  movdqa    xmm10, [rdx + 32]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 3
  movdqa    xmm10, [rdx + 48]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 4
  movdqa    xmm10, [rdx + 64]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 5
  movdqa    xmm10, [rdx + 80]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 6
  movdqa    xmm10, [rdx + 96]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 7
  movdqa    xmm10, [rdx + 112]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 8
  movdqa    xmm10, [rdx + 128]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 9
  movdqa    xmm10, [rdx + 144]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10

{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // Round 10
  movdqa    xmm10, [rdx + 160]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 11
  movdqa    xmm10, [rdx + 176]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
{$ENDIF}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 10
  movdqa    xmm10, [rdx + 160]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 11
  movdqa    xmm10, [rdx + 176]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 12
  movdqa    xmm10, [rdx + 192]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
  // Round 13
  movdqa    xmm10, [rdx + 208]
  db $66, $41, $0F, $38, $DC, $C2                  // aesenc xmm0, xmm10
  db $66, $41, $0F, $38, $DC, $CA                  // aesenc xmm1, xmm10
  db $66, $41, $0F, $38, $DC, $D2                  // aesenc xmm2, xmm10
  db $66, $41, $0F, $38, $DC, $DA                  // aesenc xmm3, xmm10
  db $66, $41, $0F, $38, $DC, $E2                  // aesenc xmm4, xmm10
  db $66, $41, $0F, $38, $DC, $EA                  // aesenc xmm5, xmm10
  db $66, $41, $0F, $38, $DC, $F2                  // aesenc xmm6, xmm10
  db $66, $41, $0F, $38, $DC, $FA                  // aesenc xmm7, xmm10
{$ENDIF}

  // --- Phase 7: final round. Opcode $DD = aesenclast. ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm10, [rdx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm10, [rdx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm10, [rdx + 224]
{$ENDIF}
  db $66, $41, $0F, $38, $DD, $C2                   // aesenclast xmm0, xmm10
  db $66, $41, $0F, $38, $DD, $CA                   // aesenclast xmm1, xmm10
  db $66, $41, $0F, $38, $DD, $D2                   // aesenclast xmm2, xmm10
  db $66, $41, $0F, $38, $DD, $DA                   // aesenclast xmm3, xmm10
  db $66, $41, $0F, $38, $DD, $E2                   // aesenclast xmm4, xmm10
  db $66, $41, $0F, $38, $DD, $EA                   // aesenclast xmm5, xmm10
  db $66, $41, $0F, $38, $DD, $F2                   // aesenclast xmm6, xmm10
  db $66, $41, $0F, $38, $DD, $FA                   // aesenclast xmm7, xmm10

{$ENDIF}

  // --- Phase 8: post-whiten with stashed per-block offsets. ---
  pxor      xmm0, [rsp +   0]
  pxor      xmm1, [rsp +  16]
  pxor      xmm2, [rsp +  32]
  pxor      xmm3, [rsp +  48]
  pxor      xmm4, [rsp +  64]
  pxor      xmm5, [rsp +  80]
  pxor      xmm6, [rsp +  96]
  pxor      xmm7, [rsp + 112]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // --- Phase 9 (decrypt): fold recovered plaintext into xmm_checksum
  //     AFTER post-whiten. ---
  db $66, $44, $0F, $EF, $C8                        // pxor xmm9, xmm0
  db $66, $44, $0F, $EF, $C9                        // pxor xmm9, xmm1
  db $66, $44, $0F, $EF, $CA                        // pxor xmm9, xmm2
  db $66, $44, $0F, $EF, $CB                        // pxor xmm9, xmm3
  db $66, $44, $0F, $EF, $CC                        // pxor xmm9, xmm4
  db $66, $44, $0F, $EF, $CD                        // pxor xmm9, xmm5
  db $66, $44, $0F, $EF, $CE                        // pxor xmm9, xmm6
  db $66, $44, $0F, $EF, $CF                        // pxor xmm9, xmm7
{$ENDIF}

  // --- Phase 10: store 8 output blocks. ---
  movdqu    [r8 +   0], xmm0
  movdqu    [r8 +  16], xmm1
  movdqu    [r8 +  32], xmm2
  movdqu    [r8 +  48], xmm3
  movdqu    [r8 +  64], xmm4
  movdqu    [r8 +  80], xmm5
  movdqu    [r8 +  96], xmm6
  movdqu    [r8 + 112], xmm7

  // --- Advance pointers and decrement loop counter. ---
  add       rbx, 128
  add       r8,  128
  add       r11, 8
  mov       rax, rbx                                // next iter's block-0 source
                                                    // tracks the main stream
  dec       r10
  jnz       @@ocb_x64_loop

  // --- Epilogue: flush xmm_offset and xmm_checksum back to memory,
  //     release stack scratch, restore rbx. ---
  mov       rax, [rcx + 24]                         // rax = OffsetPtr
  movdqu    [rax], xmm8
  mov       rax, [rcx + 32]                         // rax = ChecksumPtr
  movdqu    [rax], xmm9

  add       rsp, 128
  pop       rbx

