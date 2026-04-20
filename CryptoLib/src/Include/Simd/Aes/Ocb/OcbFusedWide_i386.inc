// OCB fused 6-wide AES-NI kernel (i386) with internal amortising loop.
// -------------------------------------------------------------------
// Processes ABlockCount consecutive 16-byte OCB body blocks in chunks of
// 6 blocks (96 bytes) per iteration. ABlockCount must be a positive
// multiple of 6 (caller guarantees via MinimumBlockCount contract).
//
// 6 is the widest fused lane count reachable on i386 inside an 8-xmm
// register budget (xmm0..xmm5 for the data, xmm6 as shared scratch for
// offsets, xmm7 unused). x86_64 uses an 8-wide companion kernel
// (OcbFusedWide_x86_64.inc) that lives in the same mode dispatch.
//
// Algorithm identity (encrypt; decrypt is symmetric with AES^-1):
//   state_0   = P_i XOR offset_i XOR K_0         (pre-whitening)
//   state_N-1 = aesenc^(N-1)(state_0)
//   state_N   = aesenclast(state_N-1, K_N)
//   C_i       = state_N XOR offset_i             (post-whitening)
// No AESENCLAST source-fold (i386 cannot afford the extra live xmm slot
// that the x86_64 6-wide predecessor used); we spend one extra pxor per
// block post-AES to reapply the offset instead.
//
// On entry (after SimdProc1Begin_i386.inc): ebx = PCtx.
//
// Context layout (4 pointers + 1 Int32 count = 20 bytes on i386). See
// TOcbFusedWideCtx in ClpAesNiOcbKernel.pas.
//   [ebx +  0]  Keys       : AES expanded schedule (encrypt for
//                            OcbFusedEncWide*; inverse-MixColumns for
//                            OcbFusedDecWide*).
//   [ebx +  4]  InPtr      : base of ABlockCount input blocks.
//   [ebx +  8]  OutPtr     : base of ABlockCount output blocks (may
//                            alias InPtr).
//   [ebx + 12]  Offsets    : base of ABlockCount raw Delta offsets.
//   [ebx + 16]  BlockCount : Int32; positive multiple of 6.
//
// XMM register allocation (7 of 8 xmm registers used):
//   xmm0..xmm5 : 6 data lanes (pre-whitening -> AES chain -> post-whitened
//                output).
//   xmm6       : scratch reload slot for raw Delta offsets. Offsets sit
//                on a 4-byte-aligned stack buffer in Pascal, so `pxor
//                xmm, m128` is unsafe; every offset XOR routes through
//                movdqu + pxor reg,reg.
//   xmm7       : unused.
//
// GPR usage (all scratch except the callee-saved pushes documented):
//   ebx : PCtx (preserved; SimdProc1Begin_i386 pushed it).
//   edi : Keys base (pinned across the whole procedure; pushed here).
//   esi : OutPtr (advancing +96 per iter; pushed here).
//   edx : InPtr (advancing +96 per iter; scratch).
//   eax : Offsets (advancing +96 per iter; scratch).
//   ecx : BlockCount / loop counter (decrementing by 6; scratch).
//
// Encoding: AES-NI instructions are db-encoded to match the pattern used
// by the rest of the tree (older FPC releases lacked aesenc / aesdec /
// aesenclast / aesdeclast mnemonics). Standard SSE1/SSE2 instructions
// (movdqu, pxor) use FPC mnemonics.
// AES-NI opcode reference (66 0F 38 .. /r):
//   $DC = AESENC         $DD = AESENCLAST
//   $DE = AESDEC         $DF = AESDECLAST
// ModR/M byte with rm=7 (edi base):
//   disp8  : $47/$4F/$57/$5F/$67/$6F              for xmm0..xmm5
//   disp32 : $87/$8F/$97/$9F/$A7/$AF              for xmm0..xmm5
// -------------------------------------------------------------------

  // --- Save callee-saved registers and materialise advancing pointers. ---
  push      edi
  push      esi
  mov       edi, [ebx +  0]                       // edi = Keys (pinned)
  mov       edx, [ebx +  4]                       // edx = InPtr (advancing)
  mov       esi, [ebx +  8]                       // esi = OutPtr (advancing)
  mov       eax, [ebx + 12]                       // eax = Offsets (advancing)
  mov       ecx, [ebx + 16]                       // ecx = BlockCount (multiple of 6)

@@ocb_i386_loop:

  // --- Load 6 input blocks from [edx]. ---
  movdqu    xmm0, [edx +  0]
  movdqu    xmm1, [edx + 16]
  movdqu    xmm2, [edx + 32]
  movdqu    xmm3, [edx + 48]
  movdqu    xmm4, [edx + 64]
  movdqu    xmm5, [edx + 80]

  // --- Pre-whiten with raw offsets (offsets buffer is only 4-byte
  //     aligned; load via movdqu + pxor reg,reg). ---
  movdqu    xmm6, [eax +  0]
  pxor      xmm0, xmm6
  movdqu    xmm6, [eax + 16]
  pxor      xmm1, xmm6
  movdqu    xmm6, [eax + 32]
  pxor      xmm2, xmm6
  movdqu    xmm6, [eax + 48]
  pxor      xmm3, xmm6
  movdqu    xmm6, [eax + 64]
  pxor      xmm4, xmm6
  movdqu    xmm6, [eax + 80]
  pxor      xmm5, xmm6

  // --- Pre-whiten with K_0 (aligned; memory-form pxor is safe). ---
  pxor      xmm0, [edi + 0]
  pxor      xmm1, [edi + 0]
  pxor      xmm2, [edi + 0]
  pxor      xmm3, [edi + 0]
  pxor      xmm4, [edi + 0]
  pxor      xmm5, [edi + 0]

{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

  // ===================== DECRYPT middle rounds =======================
  // Rounds 1..9 : aesdec xmm_i, [edi + 16*r]  for r = 1..9
  // Round 1 (disp8 = 16)
  db $66, $0F, $38, $DE, $47, $10                   // aesdec xmm0, [edi+0x10]
  db $66, $0F, $38, $DE, $4F, $10                   // aesdec xmm1, [edi+0x10]
  db $66, $0F, $38, $DE, $57, $10                   // aesdec xmm2, [edi+0x10]
  db $66, $0F, $38, $DE, $5F, $10                   // aesdec xmm3, [edi+0x10]
  db $66, $0F, $38, $DE, $67, $10                   // aesdec xmm4, [edi+0x10]
  db $66, $0F, $38, $DE, $6F, $10                   // aesdec xmm5, [edi+0x10]
  // Round 2 (disp8 = 32)
  db $66, $0F, $38, $DE, $47, $20                   // aesdec xmm0, [edi+0x20]
  db $66, $0F, $38, $DE, $4F, $20                   // aesdec xmm1, [edi+0x20]
  db $66, $0F, $38, $DE, $57, $20                   // aesdec xmm2, [edi+0x20]
  db $66, $0F, $38, $DE, $5F, $20                   // aesdec xmm3, [edi+0x20]
  db $66, $0F, $38, $DE, $67, $20                   // aesdec xmm4, [edi+0x20]
  db $66, $0F, $38, $DE, $6F, $20                   // aesdec xmm5, [edi+0x20]
  // Round 3 (disp8 = 48)
  db $66, $0F, $38, $DE, $47, $30                   // aesdec xmm0, [edi+0x30]
  db $66, $0F, $38, $DE, $4F, $30                   // aesdec xmm1, [edi+0x30]
  db $66, $0F, $38, $DE, $57, $30                   // aesdec xmm2, [edi+0x30]
  db $66, $0F, $38, $DE, $5F, $30                   // aesdec xmm3, [edi+0x30]
  db $66, $0F, $38, $DE, $67, $30                   // aesdec xmm4, [edi+0x30]
  db $66, $0F, $38, $DE, $6F, $30                   // aesdec xmm5, [edi+0x30]
  // Round 4 (disp8 = 64)
  db $66, $0F, $38, $DE, $47, $40                   // aesdec xmm0, [edi+0x40]
  db $66, $0F, $38, $DE, $4F, $40                   // aesdec xmm1, [edi+0x40]
  db $66, $0F, $38, $DE, $57, $40                   // aesdec xmm2, [edi+0x40]
  db $66, $0F, $38, $DE, $5F, $40                   // aesdec xmm3, [edi+0x40]
  db $66, $0F, $38, $DE, $67, $40                   // aesdec xmm4, [edi+0x40]
  db $66, $0F, $38, $DE, $6F, $40                   // aesdec xmm5, [edi+0x40]
  // Round 5 (disp8 = 80)
  db $66, $0F, $38, $DE, $47, $50                   // aesdec xmm0, [edi+0x50]
  db $66, $0F, $38, $DE, $4F, $50                   // aesdec xmm1, [edi+0x50]
  db $66, $0F, $38, $DE, $57, $50                   // aesdec xmm2, [edi+0x50]
  db $66, $0F, $38, $DE, $5F, $50                   // aesdec xmm3, [edi+0x50]
  db $66, $0F, $38, $DE, $67, $50                   // aesdec xmm4, [edi+0x50]
  db $66, $0F, $38, $DE, $6F, $50                   // aesdec xmm5, [edi+0x50]
  // Round 6 (disp8 = 96)
  db $66, $0F, $38, $DE, $47, $60                   // aesdec xmm0, [edi+0x60]
  db $66, $0F, $38, $DE, $4F, $60                   // aesdec xmm1, [edi+0x60]
  db $66, $0F, $38, $DE, $57, $60                   // aesdec xmm2, [edi+0x60]
  db $66, $0F, $38, $DE, $5F, $60                   // aesdec xmm3, [edi+0x60]
  db $66, $0F, $38, $DE, $67, $60                   // aesdec xmm4, [edi+0x60]
  db $66, $0F, $38, $DE, $6F, $60                   // aesdec xmm5, [edi+0x60]
  // Round 7 (disp8 = 112)
  db $66, $0F, $38, $DE, $47, $70                   // aesdec xmm0, [edi+0x70]
  db $66, $0F, $38, $DE, $4F, $70                   // aesdec xmm1, [edi+0x70]
  db $66, $0F, $38, $DE, $57, $70                   // aesdec xmm2, [edi+0x70]
  db $66, $0F, $38, $DE, $5F, $70                   // aesdec xmm3, [edi+0x70]
  db $66, $0F, $38, $DE, $67, $70                   // aesdec xmm4, [edi+0x70]
  db $66, $0F, $38, $DE, $6F, $70                   // aesdec xmm5, [edi+0x70]
  // Round 8 (disp32 = 128)
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00    // aesdec xmm0, [edi+0x80]
  db $66, $0F, $38, $DE, $8F, $80, $00, $00, $00    // aesdec xmm1, [edi+0x80]
  db $66, $0F, $38, $DE, $97, $80, $00, $00, $00    // aesdec xmm2, [edi+0x80]
  db $66, $0F, $38, $DE, $9F, $80, $00, $00, $00    // aesdec xmm3, [edi+0x80]
  db $66, $0F, $38, $DE, $A7, $80, $00, $00, $00    // aesdec xmm4, [edi+0x80]
  db $66, $0F, $38, $DE, $AF, $80, $00, $00, $00    // aesdec xmm5, [edi+0x80]
  // Round 9 (disp32 = 144)
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00    // aesdec xmm0, [edi+0x90]
  db $66, $0F, $38, $DE, $8F, $90, $00, $00, $00    // aesdec xmm1, [edi+0x90]
  db $66, $0F, $38, $DE, $97, $90, $00, $00, $00    // aesdec xmm2, [edi+0x90]
  db $66, $0F, $38, $DE, $9F, $90, $00, $00, $00    // aesdec xmm3, [edi+0x90]
  db $66, $0F, $38, $DE, $A7, $90, $00, $00, $00    // aesdec xmm4, [edi+0x90]
  db $66, $0F, $38, $DE, $AF, $90, $00, $00, $00    // aesdec xmm5, [edi+0x90]

{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  // Round 10 (disp32 = 160)
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00    // aesdec xmm0, [edi+0xA0]
  db $66, $0F, $38, $DE, $8F, $A0, $00, $00, $00    // aesdec xmm1, [edi+0xA0]
  db $66, $0F, $38, $DE, $97, $A0, $00, $00, $00    // aesdec xmm2, [edi+0xA0]
  db $66, $0F, $38, $DE, $9F, $A0, $00, $00, $00    // aesdec xmm3, [edi+0xA0]
  db $66, $0F, $38, $DE, $A7, $A0, $00, $00, $00    // aesdec xmm4, [edi+0xA0]
  db $66, $0F, $38, $DE, $AF, $A0, $00, $00, $00    // aesdec xmm5, [edi+0xA0]
  // Round 11 (disp32 = 176)
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00    // aesdec xmm0, [edi+0xB0]
  db $66, $0F, $38, $DE, $8F, $B0, $00, $00, $00    // aesdec xmm1, [edi+0xB0]
  db $66, $0F, $38, $DE, $97, $B0, $00, $00, $00    // aesdec xmm2, [edi+0xB0]
  db $66, $0F, $38, $DE, $9F, $B0, $00, $00, $00    // aesdec xmm3, [edi+0xB0]
  db $66, $0F, $38, $DE, $A7, $B0, $00, $00, $00    // aesdec xmm4, [edi+0xB0]
  db $66, $0F, $38, $DE, $AF, $B0, $00, $00, $00    // aesdec xmm5, [edi+0xB0]
{$IFEND}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 12 (disp32 = 192)
  db $66, $0F, $38, $DE, $87, $C0, $00, $00, $00    // aesdec xmm0, [edi+0xC0]
  db $66, $0F, $38, $DE, $8F, $C0, $00, $00, $00    // aesdec xmm1, [edi+0xC0]
  db $66, $0F, $38, $DE, $97, $C0, $00, $00, $00    // aesdec xmm2, [edi+0xC0]
  db $66, $0F, $38, $DE, $9F, $C0, $00, $00, $00    // aesdec xmm3, [edi+0xC0]
  db $66, $0F, $38, $DE, $A7, $C0, $00, $00, $00    // aesdec xmm4, [edi+0xC0]
  db $66, $0F, $38, $DE, $AF, $C0, $00, $00, $00    // aesdec xmm5, [edi+0xC0]
  // Round 13 (disp32 = 208)
  db $66, $0F, $38, $DE, $87, $D0, $00, $00, $00    // aesdec xmm0, [edi+0xD0]
  db $66, $0F, $38, $DE, $8F, $D0, $00, $00, $00    // aesdec xmm1, [edi+0xD0]
  db $66, $0F, $38, $DE, $97, $D0, $00, $00, $00    // aesdec xmm2, [edi+0xD0]
  db $66, $0F, $38, $DE, $9F, $D0, $00, $00, $00    // aesdec xmm3, [edi+0xD0]
  db $66, $0F, $38, $DE, $A7, $D0, $00, $00, $00    // aesdec xmm4, [edi+0xD0]
  db $66, $0F, $38, $DE, $AF, $D0, $00, $00, $00    // aesdec xmm5, [edi+0xD0]
{$ENDIF}

  // --- Final round: aesdeclast xmm_i, [edi + 16*N] ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  // AES-128 final at disp32 = 160
  db $66, $0F, $38, $DF, $87, $A0, $00, $00, $00    // aesdeclast xmm0, [edi+0xA0]
  db $66, $0F, $38, $DF, $8F, $A0, $00, $00, $00    // aesdeclast xmm1, [edi+0xA0]
  db $66, $0F, $38, $DF, $97, $A0, $00, $00, $00    // aesdeclast xmm2, [edi+0xA0]
  db $66, $0F, $38, $DF, $9F, $A0, $00, $00, $00    // aesdeclast xmm3, [edi+0xA0]
  db $66, $0F, $38, $DF, $A7, $A0, $00, $00, $00    // aesdeclast xmm4, [edi+0xA0]
  db $66, $0F, $38, $DF, $AF, $A0, $00, $00, $00    // aesdeclast xmm5, [edi+0xA0]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // AES-192 final at disp32 = 192
  db $66, $0F, $38, $DF, $87, $C0, $00, $00, $00    // aesdeclast xmm0, [edi+0xC0]
  db $66, $0F, $38, $DF, $8F, $C0, $00, $00, $00    // aesdeclast xmm1, [edi+0xC0]
  db $66, $0F, $38, $DF, $97, $C0, $00, $00, $00    // aesdeclast xmm2, [edi+0xC0]
  db $66, $0F, $38, $DF, $9F, $C0, $00, $00, $00    // aesdeclast xmm3, [edi+0xC0]
  db $66, $0F, $38, $DF, $A7, $C0, $00, $00, $00    // aesdeclast xmm4, [edi+0xC0]
  db $66, $0F, $38, $DF, $AF, $C0, $00, $00, $00    // aesdeclast xmm5, [edi+0xC0]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // AES-256 final at disp32 = 224
  db $66, $0F, $38, $DF, $87, $E0, $00, $00, $00    // aesdeclast xmm0, [edi+0xE0]
  db $66, $0F, $38, $DF, $8F, $E0, $00, $00, $00    // aesdeclast xmm1, [edi+0xE0]
  db $66, $0F, $38, $DF, $97, $E0, $00, $00, $00    // aesdeclast xmm2, [edi+0xE0]
  db $66, $0F, $38, $DF, $9F, $E0, $00, $00, $00    // aesdeclast xmm3, [edi+0xE0]
  db $66, $0F, $38, $DF, $A7, $E0, $00, $00, $00    // aesdeclast xmm4, [edi+0xE0]
  db $66, $0F, $38, $DF, $AF, $E0, $00, $00, $00    // aesdeclast xmm5, [edi+0xE0]
{$ENDIF}

{$ELSE} // ====================== ENCRYPT variant ======================

  // Rounds 1..9 : aesenc xmm_i, [edi + 16*r]  (opcode $DC)
  // Round 1 (disp8 = 16)
  db $66, $0F, $38, $DC, $47, $10                   // aesenc xmm0, [edi+0x10]
  db $66, $0F, $38, $DC, $4F, $10                   // aesenc xmm1, [edi+0x10]
  db $66, $0F, $38, $DC, $57, $10                   // aesenc xmm2, [edi+0x10]
  db $66, $0F, $38, $DC, $5F, $10                   // aesenc xmm3, [edi+0x10]
  db $66, $0F, $38, $DC, $67, $10                   // aesenc xmm4, [edi+0x10]
  db $66, $0F, $38, $DC, $6F, $10                   // aesenc xmm5, [edi+0x10]
  // Round 2 (disp8 = 32)
  db $66, $0F, $38, $DC, $47, $20                   // aesenc xmm0, [edi+0x20]
  db $66, $0F, $38, $DC, $4F, $20                   // aesenc xmm1, [edi+0x20]
  db $66, $0F, $38, $DC, $57, $20                   // aesenc xmm2, [edi+0x20]
  db $66, $0F, $38, $DC, $5F, $20                   // aesenc xmm3, [edi+0x20]
  db $66, $0F, $38, $DC, $67, $20                   // aesenc xmm4, [edi+0x20]
  db $66, $0F, $38, $DC, $6F, $20                   // aesenc xmm5, [edi+0x20]
  // Round 3 (disp8 = 48)
  db $66, $0F, $38, $DC, $47, $30                   // aesenc xmm0, [edi+0x30]
  db $66, $0F, $38, $DC, $4F, $30                   // aesenc xmm1, [edi+0x30]
  db $66, $0F, $38, $DC, $57, $30                   // aesenc xmm2, [edi+0x30]
  db $66, $0F, $38, $DC, $5F, $30                   // aesenc xmm3, [edi+0x30]
  db $66, $0F, $38, $DC, $67, $30                   // aesenc xmm4, [edi+0x30]
  db $66, $0F, $38, $DC, $6F, $30                   // aesenc xmm5, [edi+0x30]
  // Round 4 (disp8 = 64)
  db $66, $0F, $38, $DC, $47, $40                   // aesenc xmm0, [edi+0x40]
  db $66, $0F, $38, $DC, $4F, $40                   // aesenc xmm1, [edi+0x40]
  db $66, $0F, $38, $DC, $57, $40                   // aesenc xmm2, [edi+0x40]
  db $66, $0F, $38, $DC, $5F, $40                   // aesenc xmm3, [edi+0x40]
  db $66, $0F, $38, $DC, $67, $40                   // aesenc xmm4, [edi+0x40]
  db $66, $0F, $38, $DC, $6F, $40                   // aesenc xmm5, [edi+0x40]
  // Round 5 (disp8 = 80)
  db $66, $0F, $38, $DC, $47, $50                   // aesenc xmm0, [edi+0x50]
  db $66, $0F, $38, $DC, $4F, $50                   // aesenc xmm1, [edi+0x50]
  db $66, $0F, $38, $DC, $57, $50                   // aesenc xmm2, [edi+0x50]
  db $66, $0F, $38, $DC, $5F, $50                   // aesenc xmm3, [edi+0x50]
  db $66, $0F, $38, $DC, $67, $50                   // aesenc xmm4, [edi+0x50]
  db $66, $0F, $38, $DC, $6F, $50                   // aesenc xmm5, [edi+0x50]
  // Round 6 (disp8 = 96)
  db $66, $0F, $38, $DC, $47, $60                   // aesenc xmm0, [edi+0x60]
  db $66, $0F, $38, $DC, $4F, $60                   // aesenc xmm1, [edi+0x60]
  db $66, $0F, $38, $DC, $57, $60                   // aesenc xmm2, [edi+0x60]
  db $66, $0F, $38, $DC, $5F, $60                   // aesenc xmm3, [edi+0x60]
  db $66, $0F, $38, $DC, $67, $60                   // aesenc xmm4, [edi+0x60]
  db $66, $0F, $38, $DC, $6F, $60                   // aesenc xmm5, [edi+0x60]
  // Round 7 (disp8 = 112)
  db $66, $0F, $38, $DC, $47, $70                   // aesenc xmm0, [edi+0x70]
  db $66, $0F, $38, $DC, $4F, $70                   // aesenc xmm1, [edi+0x70]
  db $66, $0F, $38, $DC, $57, $70                   // aesenc xmm2, [edi+0x70]
  db $66, $0F, $38, $DC, $5F, $70                   // aesenc xmm3, [edi+0x70]
  db $66, $0F, $38, $DC, $67, $70                   // aesenc xmm4, [edi+0x70]
  db $66, $0F, $38, $DC, $6F, $70                   // aesenc xmm5, [edi+0x70]
  // Round 8 (disp32 = 128)
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00    // aesenc xmm0, [edi+0x80]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00    // aesenc xmm1, [edi+0x80]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00    // aesenc xmm2, [edi+0x80]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00    // aesenc xmm3, [edi+0x80]
  db $66, $0F, $38, $DC, $A7, $80, $00, $00, $00    // aesenc xmm4, [edi+0x80]
  db $66, $0F, $38, $DC, $AF, $80, $00, $00, $00    // aesenc xmm5, [edi+0x80]
  // Round 9 (disp32 = 144)
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00    // aesenc xmm0, [edi+0x90]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00    // aesenc xmm1, [edi+0x90]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00    // aesenc xmm2, [edi+0x90]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00    // aesenc xmm3, [edi+0x90]
  db $66, $0F, $38, $DC, $A7, $90, $00, $00, $00    // aesenc xmm4, [edi+0x90]
  db $66, $0F, $38, $DC, $AF, $90, $00, $00, $00    // aesenc xmm5, [edi+0x90]

{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  // Round 10 (disp32 = 160)
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00    // aesenc xmm0, [edi+0xA0]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00    // aesenc xmm1, [edi+0xA0]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00    // aesenc xmm2, [edi+0xA0]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00    // aesenc xmm3, [edi+0xA0]
  db $66, $0F, $38, $DC, $A7, $A0, $00, $00, $00    // aesenc xmm4, [edi+0xA0]
  db $66, $0F, $38, $DC, $AF, $A0, $00, $00, $00    // aesenc xmm5, [edi+0xA0]
  // Round 11 (disp32 = 176)
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00    // aesenc xmm0, [edi+0xB0]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00    // aesenc xmm1, [edi+0xB0]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00    // aesenc xmm2, [edi+0xB0]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00    // aesenc xmm3, [edi+0xB0]
  db $66, $0F, $38, $DC, $A7, $B0, $00, $00, $00    // aesenc xmm4, [edi+0xB0]
  db $66, $0F, $38, $DC, $AF, $B0, $00, $00, $00    // aesenc xmm5, [edi+0xB0]
{$IFEND}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // Round 12 (disp32 = 192)
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00    // aesenc xmm0, [edi+0xC0]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00    // aesenc xmm1, [edi+0xC0]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00    // aesenc xmm2, [edi+0xC0]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00    // aesenc xmm3, [edi+0xC0]
  db $66, $0F, $38, $DC, $A7, $C0, $00, $00, $00    // aesenc xmm4, [edi+0xC0]
  db $66, $0F, $38, $DC, $AF, $C0, $00, $00, $00    // aesenc xmm5, [edi+0xC0]
  // Round 13 (disp32 = 208)
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00    // aesenc xmm0, [edi+0xD0]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00    // aesenc xmm1, [edi+0xD0]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00    // aesenc xmm2, [edi+0xD0]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00    // aesenc xmm3, [edi+0xD0]
  db $66, $0F, $38, $DC, $A7, $D0, $00, $00, $00    // aesenc xmm4, [edi+0xD0]
  db $66, $0F, $38, $DC, $AF, $D0, $00, $00, $00    // aesenc xmm5, [edi+0xD0]
{$ENDIF}

  // --- Final round: aesenclast xmm_i, [edi + 16*N] ---
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  // AES-128 final at disp32 = 160
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00    // aesenclast xmm0, [edi+0xA0]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00    // aesenclast xmm1, [edi+0xA0]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00    // aesenclast xmm2, [edi+0xA0]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00    // aesenclast xmm3, [edi+0xA0]
  db $66, $0F, $38, $DD, $A7, $A0, $00, $00, $00    // aesenclast xmm4, [edi+0xA0]
  db $66, $0F, $38, $DD, $AF, $A0, $00, $00, $00    // aesenclast xmm5, [edi+0xA0]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  // AES-192 final at disp32 = 192
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00    // aesenclast xmm0, [edi+0xC0]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00    // aesenclast xmm1, [edi+0xC0]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00    // aesenclast xmm2, [edi+0xC0]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00    // aesenclast xmm3, [edi+0xC0]
  db $66, $0F, $38, $DD, $A7, $C0, $00, $00, $00    // aesenclast xmm4, [edi+0xC0]
  db $66, $0F, $38, $DD, $AF, $C0, $00, $00, $00    // aesenclast xmm5, [edi+0xC0]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  // AES-256 final at disp32 = 224
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00    // aesenclast xmm0, [edi+0xE0]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00    // aesenclast xmm1, [edi+0xE0]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00    // aesenclast xmm2, [edi+0xE0]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00    // aesenclast xmm3, [edi+0xE0]
  db $66, $0F, $38, $DD, $A7, $E0, $00, $00, $00    // aesenclast xmm4, [edi+0xE0]
  db $66, $0F, $38, $DD, $AF, $E0, $00, $00, $00    // aesenclast xmm5, [edi+0xE0]
{$ENDIF}

{$ENDIF} // CRYPTOLIB_AESNI_DECRYPT

  // --- Post-whiten: XOR with raw offsets (unaligned-safe movdqu+pxor). ---
  movdqu    xmm6, [eax +  0]
  pxor      xmm0, xmm6
  movdqu    xmm6, [eax + 16]
  pxor      xmm1, xmm6
  movdqu    xmm6, [eax + 32]
  pxor      xmm2, xmm6
  movdqu    xmm6, [eax + 48]
  pxor      xmm3, xmm6
  movdqu    xmm6, [eax + 64]
  pxor      xmm4, xmm6
  movdqu    xmm6, [eax + 80]
  pxor      xmm5, xmm6

  // --- Store 6 output blocks to [esi]. ---
  movdqu    [esi +  0], xmm0
  movdqu    [esi + 16], xmm1
  movdqu    [esi + 32], xmm2
  movdqu    [esi + 48], xmm3
  movdqu    [esi + 64], xmm4
  movdqu    [esi + 80], xmm5

  // --- Advance pointers and decrement loop counter. ---
  add       edx, 96
  add       esi, 96
  add       eax, 96
  sub       ecx, 6
  jnz       @@ocb_i386_loop

  // Epilogue: restore all three callee-saved GPRs. SimdProc1Begin_i386.inc
  // uses `nostackframe`, so the Pascal `end;` only emits `ret`; bodies own
  // the pops (order reverses the pushes: ebx was pushed by the prologue,
  // then edi, esi by this kernel).
  pop       esi
  pop       edi
  pop       ebx
