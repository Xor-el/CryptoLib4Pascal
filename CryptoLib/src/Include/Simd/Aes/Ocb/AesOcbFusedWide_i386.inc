// OCB fused 4-wide AES-NI kernel (i386) with in-kernel offset ladder,
// L-table lookup and checksum fold.
// -------------------------------------------------------------------
// Processes ABlockCount consecutive 16-byte OCB body blocks in chunks
// of 4 blocks (64 bytes) per iteration. 4 is the widest fused lane
// count that fits the 8-xmm budget once xmm_offset + xmm_checksum +
// scratch are reserved; memory-form aesenc / aesdec is therefore
// used throughout against the 16-byte-aligned round-key schedule.
// The kernel owns all per-block OCB bookkeeping across the batch:
// on entry it seeds xmm_offset from OffsetPtr and xmm_checksum from
// ChecksumPtr; the loop walks a pre-computed ntz byte array, XORs
// the L-table entry into xmm_offset to derive each Delta, runs
// P_i XOR delta XOR K_0 through the AES rounds, XORs delta into
// the post-aesenclast state to produce C_i, and folds plaintext
// into xmm_checksum; on exit it writes xmm_offset and xmm_checksum
// back. The mode layer never touches per-block state.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// On entry (after SimdProc1Begin_i386.inc): ebx = PCtx.
//
// Context layout (8 pointers + 1 NativeUInt = 36 bytes, 4-byte aligned).
// See TOcbFusedKernelCtx in ClpAesNiOcbKernel.pas.
//   [ebx +  0]  Keys        : AES schedule (encrypt or inv-MixColumns; 16-byte aligned)
//   [ebx +  4]  InPtr       : base of the main 16-byte-block stream
//   [ebx +  8]  OutPtr      : base of BlockCount output blocks (may alias InPtr)
//   [ebx + 12]  OffsetPtr   : 16-byte live FOffsetMAIN (r/w)
//   [ebx + 16]  ChecksumPtr : 16-byte live FChecksum (r/w)
//   [ebx + 20]  LTablePtr   : flat L[0..LMax] * 16 bytes (read-only; cached on stack)
//   [ebx + 24]  NtzPtr      : BlockCount bytes of pre-computed ntz values
//   [ebx + 28]  Block0Ptr   : 16-byte source of iteration-0 block 0 (may alias InPtr)
//   [ebx + 32]  BlockCount  : NativeUInt; multiple of 4
//
// XMM (7/8 used; i386 has only xmm0..xmm7):
//   xmm0..xmm3 : 4 data lanes
//   xmm4       : xmm_offset accumulator (seeded/stored once per batch)
//   xmm5       : xmm_checksum accumulator (seeded/stored once per batch)
//   xmm6       : scratch (L-table loads; stack-offset reloads during whitening)
//   xmm7       : free
//
// Stack scratch (68 bytes, base unaligned - movdqu only):
//   [esp +  0..63]  4 x 16-byte per-block offset stashes
//   [esp + 64..67]  LTablePtr cache (one dword; GPR budget cannot pin it)
//
// AES-NI instructions are db-encoded for broad assembler compatibility.
// -------------------------------------------------------------------

  // --- Callee-save prologue. SimdProc1Begin_i386.inc already pushed ebx
  //     and moved PCtx into ebx, so this block only pushes the other
  //     three callee-saved GPRs and reserves stack scratch. ---
  push      edi
  push      esi
  push      ebp
  sub       esp, 68

  // --- Load context pointers and seed accumulators. ---
  mov       edi, [ebx +  0]                       // edi = Keys (pinned)
  mov       edx, [ebx +  4]                       // edx = InPtr (advancing)
  mov       esi, [ebx +  8]                       // esi = OutPtr (advancing)
  mov       ebp, [ebx + 24]                       // ebp = NtzPtr (advancing)
  mov       ecx, [ebx + 32]                       // ecx = BlockCount (>= 4, multiple of 4)

  // Stash LTablePtr into the stack slot at [esp + 64]; the inner loop
  // re-adds it to ntz*16 to form each L-table entry address.
  mov       eax, [ebx + 20]                       // eax = LTablePtr
  mov       [esp + 64], eax

  // Seed xmm_offset from [OffsetPtr] and xmm_checksum from [ChecksumPtr].
  mov       eax, [ebx + 12]                       // eax = OffsetPtr
  movdqu    xmm4, [eax]                           // xmm4 = FOffsetMAIN
  mov       eax, [ebx + 16]                       // eax = ChecksumPtr
  movdqu    xmm5, [eax]                           // xmm5 = FChecksum

  // Seed the block-0 pointer. eax is consumed by Phase 2 at the top
  // of each iteration (before Phase 1 clobbers it), and refreshed to
  // edx at the bottom of every iteration so iter >= 1 transparently
  // reads block 0 from the advancing main stream at offset 0.
  mov       eax, [ebx + 28]                       // eax = Block0Ptr

@@ocb_i386_loop:

  // --- Phase 2: load 4 input blocks. Must run BEFORE the ladder
  //     because Phase 1 below clobbers eax (ntz scratch / L-table
  //     index). Block 0 comes from eax (iter 0: Block0Ptr; iter >= 1:
  //     main stream via the mov eax, edx at the bottom of iter k-1).
  //     Blocks 1..3 always come from the advancing main stream edx
  //     at [edx + 16..48]. ---
  movdqu    xmm0, [eax]
  movdqu    xmm1, [edx + 16]
  movdqu    xmm2, [edx + 32]
  movdqu    xmm3, [edx + 48]

  // ------------------------------------------------------------------
  // Phase 1: offset ladder. For each block i in 0..3:
  //   eax   = ntz[i]          (movzx from [ebp + i])
  //   eax   = eax * 16        (shl eax, 4)
  //   eax   = LTablePtr + eax (add from stashed slot)
  //   xmm6  = L[ntz[i]]       (movdqu from [eax])
  //   xmm4 ^= xmm6            (pxor)
  //   [esp + 16*i] <- xmm4    (movdqu stash of offset_i)
  // After this phase xmm4 holds offset_3 which is the Delta carried
  // into the next iteration, and [esp + 0..63] holds offsets_0..3.
  // ------------------------------------------------------------------
  // Block 0
  movzx     eax, byte [ebp + 0]
  shl       eax, 4
  add       eax, [esp + 64]
  movdqu    xmm6, [eax]
  pxor      xmm4, xmm6
  movdqu    [esp +  0], xmm4
  // Block 1
  movzx     eax, byte [ebp + 1]
  shl       eax, 4
  add       eax, [esp + 64]
  movdqu    xmm6, [eax]
  pxor      xmm4, xmm6
  movdqu    [esp + 16], xmm4
  // Block 2
  movzx     eax, byte [ebp + 2]
  shl       eax, 4
  add       eax, [esp + 64]
  movdqu    xmm6, [eax]
  pxor      xmm4, xmm6
  movdqu    [esp + 32], xmm4
  // Block 3
  movzx     eax, byte [ebp + 3]
  shl       eax, 4
  add       eax, [esp + 64]
  movdqu    xmm6, [eax]
  pxor      xmm4, xmm6
  movdqu    [esp + 48], xmm4

{$IFNDEF CRYPTOLIB_AESNI_DECRYPT}
  // --- Phase 3 (encrypt): fold plaintext into xmm_checksum. ---
  pxor      xmm5, xmm0
  pxor      xmm5, xmm1
  pxor      xmm5, xmm2
  pxor      xmm5, xmm3
{$ENDIF}

  // --- Phase 4: pre-whiten with K_0 (memory-form, aligned schedule). ---
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]

  // --- Phase 5: pre-whiten with stashed per-block offsets (unaligned
  //     stack -> movdqu + reg-reg pxor). ---
  movdqu    xmm6, [esp +  0]
  pxor      xmm0, xmm6
  movdqu    xmm6, [esp + 16]
  pxor      xmm1, xmm6
  movdqu    xmm6, [esp + 32]
  pxor      xmm2, xmm6
  movdqu    xmm6, [esp + 48]
  pxor      xmm3, xmm6

  // ------------------------------------------------------------------
  // Phase 6: AES middle rounds 1..N-1 via memory-form aesenc / aesdec.
  // Key size drives the number of rounds; shared through the same
  // pattern used by the previous 6-wide kernel.
  // ------------------------------------------------------------------
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

  // Round 1 (disp8 = 16)
  db $66, $0F, $38, $DE, $47, $10                 // aesdec xmm0, [edi+0x10]
  db $66, $0F, $38, $DE, $4F, $10                  // aesdec xmm1, [edi+16]
  db $66, $0F, $38, $DE, $57, $10                  // aesdec xmm2, [edi+16]
  db $66, $0F, $38, $DE, $5F, $10                  // aesdec xmm3, [edi+16]
  // Round 2 (disp8 = 32)
  db $66, $0F, $38, $DE, $47, $20                  // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $4F, $20                  // aesdec xmm1, [edi+32]
  db $66, $0F, $38, $DE, $57, $20                  // aesdec xmm2, [edi+32]
  db $66, $0F, $38, $DE, $5F, $20                  // aesdec xmm3, [edi+32]
  // Round 3 (disp8 = 48)
  db $66, $0F, $38, $DE, $47, $30                  // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $4F, $30                  // aesdec xmm1, [edi+48]
  db $66, $0F, $38, $DE, $57, $30                  // aesdec xmm2, [edi+48]
  db $66, $0F, $38, $DE, $5F, $30                  // aesdec xmm3, [edi+48]
  // Round 4 (disp8 = 64)
  db $66, $0F, $38, $DE, $47, $40                  // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $4F, $40                  // aesdec xmm1, [edi+64]
  db $66, $0F, $38, $DE, $57, $40                  // aesdec xmm2, [edi+64]
  db $66, $0F, $38, $DE, $5F, $40                  // aesdec xmm3, [edi+64]
  // Round 5 (disp8 = 80)
  db $66, $0F, $38, $DE, $47, $50                  // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $4F, $50                  // aesdec xmm1, [edi+80]
  db $66, $0F, $38, $DE, $57, $50                  // aesdec xmm2, [edi+80]
  db $66, $0F, $38, $DE, $5F, $50                  // aesdec xmm3, [edi+80]
  // Round 6 (disp8 = 96)
  db $66, $0F, $38, $DE, $47, $60                  // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $4F, $60                  // aesdec xmm1, [edi+96]
  db $66, $0F, $38, $DE, $57, $60                  // aesdec xmm2, [edi+96]
  db $66, $0F, $38, $DE, $5F, $60                  // aesdec xmm3, [edi+96]
  // Round 7 (disp8 = 112)
  db $66, $0F, $38, $DE, $47, $70                  // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $4F, $70                  // aesdec xmm1, [edi+112]
  db $66, $0F, $38, $DE, $57, $70                  // aesdec xmm2, [edi+112]
  db $66, $0F, $38, $DE, $5F, $70                  // aesdec xmm3, [edi+112]
  // Round 8 (disp32 = 128)
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $8F, $80, $00, $00, $00   // aesdec xmm1, [edi+128]
  db $66, $0F, $38, $DE, $97, $80, $00, $00, $00   // aesdec xmm2, [edi+128]
  db $66, $0F, $38, $DE, $9F, $80, $00, $00, $00   // aesdec xmm3, [edi+128]
  // Round 9 (disp32 = 144)
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DE, $8F, $90, $00, $00, $00   // aesdec xmm1, [edi+144]
  db $66, $0F, $38, $DE, $97, $90, $00, $00, $00   // aesdec xmm2, [edi+144]
  db $66, $0F, $38, $DE, $9F, $90, $00, $00, $00   // aesdec xmm3, [edi+144]

{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  // Round 10 (disp32 = 160)
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00   // aesdec xmm0, [edi+160]
  db $66, $0F, $38, $DE, $8F, $A0, $00, $00, $00   // aesdec xmm1, [edi+160]
  db $66, $0F, $38, $DE, $97, $A0, $00, $00, $00   // aesdec xmm2, [edi+160]
  db $66, $0F, $38, $DE, $9F, $A0, $00, $00, $00   // aesdec xmm3, [edi+160]
  // Round 11 (disp32 = 176)
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00   // aesdec xmm0, [edi+176]
  db $66, $0F, $38, $DE, $8F, $B0, $00, $00, $00   // aesdec xmm1, [edi+176]
  db $66, $0F, $38, $DE, $97, $B0, $00, $00, $00   // aesdec xmm2, [edi+176]
  db $66, $0F, $38, $DE, $9F, $B0, $00, $00, $00   // aesdec xmm3, [edi+176]
{$IFEND}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 12 (disp32 = 192)
  db $66, $0F, $38, $DE, $87, $C0, $00, $00, $00   // aesdec xmm0, [edi+192]
  db $66, $0F, $38, $DE, $8F, $C0, $00, $00, $00   // aesdec xmm1, [edi+192]
  db $66, $0F, $38, $DE, $97, $C0, $00, $00, $00   // aesdec xmm2, [edi+192]
  db $66, $0F, $38, $DE, $9F, $C0, $00, $00, $00   // aesdec xmm3, [edi+192]
  // Round 13 (disp32 = 208)
  db $66, $0F, $38, $DE, $87, $D0, $00, $00, $00   // aesdec xmm0, [edi+208]
  db $66, $0F, $38, $DE, $8F, $D0, $00, $00, $00   // aesdec xmm1, [edi+208]
  db $66, $0F, $38, $DE, $97, $D0, $00, $00, $00   // aesdec xmm2, [edi+208]
  db $66, $0F, $38, $DE, $9F, $D0, $00, $00, $00   // aesdec xmm3, [edi+208]
{$ENDIF}

  // --- Phase 7: final round (aesdeclast). ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  // AES-128 final at disp32 = 160
  db $66, $0F, $38, $DF, $87, $A0, $00, $00, $00   // aesdeclast xmm0, [edi+160]
  db $66, $0F, $38, $DF, $8F, $A0, $00, $00, $00   // aesdeclast xmm1, [edi+160]
  db $66, $0F, $38, $DF, $97, $A0, $00, $00, $00   // aesdeclast xmm2, [edi+160]
  db $66, $0F, $38, $DF, $9F, $A0, $00, $00, $00   // aesdeclast xmm3, [edi+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // AES-192 final at disp32 = 192
  db $66, $0F, $38, $DF, $87, $C0, $00, $00, $00   // aesdeclast xmm0, [edi+192]
  db $66, $0F, $38, $DF, $8F, $C0, $00, $00, $00   // aesdeclast xmm1, [edi+192]
  db $66, $0F, $38, $DF, $97, $C0, $00, $00, $00   // aesdeclast xmm2, [edi+192]
  db $66, $0F, $38, $DF, $9F, $C0, $00, $00, $00   // aesdeclast xmm3, [edi+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // AES-256 final at disp32 = 224
  db $66, $0F, $38, $DF, $87, $E0, $00, $00, $00   // aesdeclast xmm0, [edi+224]
  db $66, $0F, $38, $DF, $8F, $E0, $00, $00, $00   // aesdeclast xmm1, [edi+224]
  db $66, $0F, $38, $DF, $97, $E0, $00, $00, $00   // aesdeclast xmm2, [edi+224]
  db $66, $0F, $38, $DF, $9F, $E0, $00, $00, $00   // aesdeclast xmm3, [edi+224]
{$ENDIF}

{$ELSE} // ====================== ENCRYPT variant ======================

  // Rounds 1..9 : aesenc xmm_i, [edi + 16*r]  (opcode $DC)
  // Round 1 (disp8 = 16)
  db $66, $0F, $38, $DC, $47, $10                  // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $4F, $10                  // aesenc xmm1, [edi+16]
  db $66, $0F, $38, $DC, $57, $10                  // aesenc xmm2, [edi+16]
  db $66, $0F, $38, $DC, $5F, $10                  // aesenc xmm3, [edi+16]
  // Round 2 (disp8 = 32)
  db $66, $0F, $38, $DC, $47, $20                  // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $4F, $20                  // aesenc xmm1, [edi+32]
  db $66, $0F, $38, $DC, $57, $20                  // aesenc xmm2, [edi+32]
  db $66, $0F, $38, $DC, $5F, $20                  // aesenc xmm3, [edi+32]
  // Round 3 (disp8 = 48)
  db $66, $0F, $38, $DC, $47, $30                  // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $4F, $30                  // aesenc xmm1, [edi+48]
  db $66, $0F, $38, $DC, $57, $30                  // aesenc xmm2, [edi+48]
  db $66, $0F, $38, $DC, $5F, $30                  // aesenc xmm3, [edi+48]
  // Round 4 (disp8 = 64)
  db $66, $0F, $38, $DC, $47, $40                  // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $4F, $40                  // aesenc xmm1, [edi+64]
  db $66, $0F, $38, $DC, $57, $40                  // aesenc xmm2, [edi+64]
  db $66, $0F, $38, $DC, $5F, $40                  // aesenc xmm3, [edi+64]
  // Round 5 (disp8 = 80)
  db $66, $0F, $38, $DC, $47, $50                  // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $4F, $50                  // aesenc xmm1, [edi+80]
  db $66, $0F, $38, $DC, $57, $50                  // aesenc xmm2, [edi+80]
  db $66, $0F, $38, $DC, $5F, $50                  // aesenc xmm3, [edi+80]
  // Round 6 (disp8 = 96)
  db $66, $0F, $38, $DC, $47, $60                  // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $4F, $60                  // aesenc xmm1, [edi+96]
  db $66, $0F, $38, $DC, $57, $60                  // aesenc xmm2, [edi+96]
  db $66, $0F, $38, $DC, $5F, $60                  // aesenc xmm3, [edi+96]
  // Round 7 (disp8 = 112)
  db $66, $0F, $38, $DC, $47, $70                  // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $4F, $70                  // aesenc xmm1, [edi+112]
  db $66, $0F, $38, $DC, $57, $70                  // aesenc xmm2, [edi+112]
  db $66, $0F, $38, $DC, $5F, $70                  // aesenc xmm3, [edi+112]
  // Round 8 (disp32 = 128)
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00   // aesenc xmm1, [edi+128]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00   // aesenc xmm2, [edi+128]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00   // aesenc xmm3, [edi+128]
  // Round 9 (disp32 = 144)
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00   // aesenc xmm1, [edi+144]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00   // aesenc xmm2, [edi+144]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00   // aesenc xmm3, [edi+144]

{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  // Round 10 (disp32 = 160)
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00   // aesenc xmm1, [edi+160]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00   // aesenc xmm2, [edi+160]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00   // aesenc xmm3, [edi+160]
  // Round 11 (disp32 = 176)
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00   // aesenc xmm1, [edi+176]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00   // aesenc xmm2, [edi+176]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00   // aesenc xmm3, [edi+176]
{$IFEND}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 12 (disp32 = 192)
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+192]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00   // aesenc xmm1, [edi+192]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00   // aesenc xmm2, [edi+192]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00   // aesenc xmm3, [edi+192]
  // Round 13 (disp32 = 208)
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+208]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00   // aesenc xmm1, [edi+208]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00   // aesenc xmm2, [edi+208]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00   // aesenc xmm3, [edi+208]
{$ENDIF}

  // --- Phase 7: final round (aesenclast). ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  // AES-128 final at disp32 = 160
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+160]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00   // aesenclast xmm1, [edi+160]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00   // aesenclast xmm2, [edi+160]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00   // aesenclast xmm3, [edi+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // AES-192 final at disp32 = 192
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+192]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00   // aesenclast xmm1, [edi+192]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00   // aesenclast xmm2, [edi+192]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00   // aesenclast xmm3, [edi+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // AES-256 final at disp32 = 224
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+224]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00   // aesenclast xmm1, [edi+224]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00   // aesenclast xmm2, [edi+224]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00   // aesenclast xmm3, [edi+224]
{$ENDIF}

{$ENDIF} // CRYPTOLIB_AESNI_DECRYPT

  // --- Phase 8: post-whiten with stashed per-block offsets. ---
  movdqu    xmm6, [esp +  0]
  pxor      xmm0, xmm6
  movdqu    xmm6, [esp + 16]
  pxor      xmm1, xmm6
  movdqu    xmm6, [esp + 32]
  pxor      xmm2, xmm6
  movdqu    xmm6, [esp + 48]
  pxor      xmm3, xmm6

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
  // --- Phase 9 (decrypt): fold recovered plaintext into checksum. ---
  pxor      xmm5, xmm0
  pxor      xmm5, xmm1
  pxor      xmm5, xmm2
  pxor      xmm5, xmm3
{$ENDIF}

  // --- Phase 10: store 4 output blocks. ---
  movdqu    [esi +  0], xmm0
  movdqu    [esi + 16], xmm1
  movdqu    [esi + 32], xmm2
  movdqu    [esi + 48], xmm3

  // --- Advance pointers and decrement loop counter. ---
  add       edx, 64
  add       esi, 64
  add       ebp, 4
  mov       eax, edx                              // next iter's block-0 source
                                                  // tracks the main stream
  sub       ecx, 4
  jnz       @@ocb_i386_loop

  // --- Epilogue: flush accumulators back to memory, then unwind the
  //     stack scratch and pop the callee-saved GPRs. ebx is popped
  //     last because SimdProc1Begin_i386.inc pushed it first. ---
  mov       eax, [ebx + 12]                       // eax = OffsetPtr
  movdqu    [eax], xmm4
  mov       eax, [ebx + 16]                       // eax = ChecksumPtr
  movdqu    [eax], xmm5

  add       esp, 68
  pop       ebp
  pop       esi
  pop       edi
  pop       ebx

