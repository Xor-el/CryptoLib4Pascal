// AES-NI 8-wide CTR keystream + XOR, interleaved fused kernel (i386).
// -------------------------------------------------------------------
//
// i386 counterpart of AesNiCtrEight_x86_64.inc: processes eight AES-CTR blocks
// per iteration for TSicBlockCipher's bulk path, XORing the keystream with the
// input in one pass. The eight cipher lanes live in xmm0..7 across the whole
// round chain (round keys are consumed as [edi + K] memory operands, so no key
// register is needed), and the NEXT batch's eight counter blocks are staged into
// a 128-byte stack scratch *interleaved between the aesenc rounds* of the current
// batch - the scalar counter build overlaps the aesenc throughput instead of
// serialising ahead of it.
//
// Counters are staged PRE-WHITENED: the K_0 XOR is folded into the scalar
// counter build. The whitened base block (counter ^ K_0) is written to all
// eight scratch slots once at entry; only the counter dword (bytes 12..15)
// changes between blocks, so each staged lane is a 4-byte patch of
// bswap(ctr32) ^ K_0.dword3. This removes the whole round-0 pxor pass from
// the AES port budget (the round chain starts directly at K_1) and shrinks
// the per-lane staging from a 16-byte block copy to one dword store.
//
// Entry (after ClpSimdProc1Begin_i386.inc): ebx = pointer to TCtrFusedCtx. The
// kernel pushes esi/edi and unpacks the record (InPtr loaded into ebx last):
//   [ebx +  0]  InPtr      -> ebx : input  (advances +128 per 8-block iteration)
//   [ebx +  4]  OutPtr     -> esi : output (advances +128)
//   [ebx +  8]  KeysPtr    -> edi : AES round-key schedule (consumed as [edi+K])
//   [ebx + 12]  CounterPtr -> eax : 16-byte big-endian counter (low dword updated
//                                   in place; parked in a frame slot, eax then
//                                   holds the K_0.dword3 whitening constant)
//   [ebx + 16]  BlockCount -> ecx : positive multiple of 8 (caller guarantees it)
//
// Counter contract: the caller guarantees the low-32 counter dword does NOT
// wrap within the call (ctr32 + BlockCount <= 2^32) - TAesNiCtrKernel splits
// runs at the 2^32 boundary and propagates the carry into the upper 12 bytes
// in Pascal. The kernel therefore carries no in-loop carry logic and never
// touches counter bytes 0..11; only the low dword is stored back. The
// pipeline builds one batch ahead, so edx over-runs by exactly 8 - undone
// (modulo 2^32) before write-back.
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt (CTR keystream), so CRYPTOLIB_AESNI_DECRYPT must
// NOT be defined when including this file.
//
// Constraints: i386 has only xmm0..7 (all volatile). BlockCount parks in a frame
// slot so ecx serves the staging: edx holds the counter's low dword native-LE
// across the whole span, eax the whitening constant. The keystream^plaintext XOR
// has no free xmm for the plaintext (nor can it use a memory-operand pxor, which
// would require the input to be 16-byte aligned), so it spills lane 7 to a
// scratch slot above the counter area and reuses xmm7 for the movdqu plaintext
// load. AES-NI and register pxor forms are db-encoded for broad assembler
// compatibility.
  // ---- unpack TCtrFusedCtx (ebx = PCtx); load InPtr into ebx last ----
  push      esi
  push      edi
  mov       esi, [ebx + 4]                        // OutPtr
  mov       edi, [ebx + 8]                        // KeysPtr
  mov       eax, [ebx + 12]                       // CounterPtr
  mov       ecx, [ebx + 16]                       // BlockCount
  mov       ebx, [ebx + 0]                        // InPtr (overwrites PCtx)

  sub       esp, 152                              // next-batch counters [esp+0..127]; ks7 spill [esp+128..143]; countdown [esp+144]; CounterPtr [esp+148]
  mov       [esp + 144], ecx                      // park BlockCount; ecx = staging scratch
  mov       [esp + 148], eax                      // park CounterPtr; eax = whitening constant
  mov       edx, [eax + 12]                       // counter low dword, kept native-LE in edx
  bswap     edx

  // ---- whitened base block (counter ^ K_0) into all 8 scratch slots ----
  movdqu    xmm0, [eax]                           // counter block
  db $66, $0F, $EF, $07                           // pxor xmm0, [edi+0]  (K_0; schedule is 16-byte aligned)
  movdqu    [esp + 0], xmm0
  movdqu    [esp + 16], xmm0
  movdqu    [esp + 32], xmm0
  movdqu    [esp + 48], xmm0
  movdqu    [esp + 64], xmm0
  movdqu    [esp + 80], xmm0
  movdqu    [esp + 96], xmm0
  movdqu    [esp + 112], xmm0
  mov       eax, [edi + 12]                       // K_0.dword3 whitening constant

  // ---- stage batch 0: patch the whitened counter dword of each slot ----
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 12], ecx
  add       edx, 1
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 28], ecx
  add       edx, 1
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 44], ecx
  add       edx, 1
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 60], ecx
  add       edx, 1
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 76], ecx
  add       edx, 1
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 92], ecx
  add       edx, 1
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 108], ecx
  add       edx, 1
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 124], ecx
  add       edx, 1

  movdqu    xmm0, [esp + 0]
  movdqu    xmm1, [esp + 16]
  movdqu    xmm2, [esp + 32]
  movdqu    xmm3, [esp + 48]
  movdqu    xmm4, [esp + 64]
  movdqu    xmm5, [esp + 80]
  movdqu    xmm6, [esp + 96]
  movdqu    xmm7, [esp + 112]

@@CtrEightLoopI386:
  // ---- rounds 1..8: aesenc (lanes are pre-whitened), each interleaved with
  //      staging one next pre-whitened counter dword ----
  db $66, $0F, $38, $DC, $47, $10                 // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $4F, $10                 // aesenc xmm1, [edi+16]
  db $66, $0F, $38, $DC, $57, $10                 // aesenc xmm2, [edi+16]
  db $66, $0F, $38, $DC, $5F, $10                 // aesenc xmm3, [edi+16]
  db $66, $0F, $38, $DC, $67, $10                 // aesenc xmm4, [edi+16]
  db $66, $0F, $38, $DC, $6F, $10                 // aesenc xmm5, [edi+16]
  db $66, $0F, $38, $DC, $77, $10                 // aesenc xmm6, [edi+16]
  db $66, $0F, $38, $DC, $7F, $10                 // aesenc xmm7, [edi+16]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 12], ecx
  add       edx, 1

  db $66, $0F, $38, $DC, $47, $20                 // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $4F, $20                 // aesenc xmm1, [edi+32]
  db $66, $0F, $38, $DC, $57, $20                 // aesenc xmm2, [edi+32]
  db $66, $0F, $38, $DC, $5F, $20                 // aesenc xmm3, [edi+32]
  db $66, $0F, $38, $DC, $67, $20                 // aesenc xmm4, [edi+32]
  db $66, $0F, $38, $DC, $6F, $20                 // aesenc xmm5, [edi+32]
  db $66, $0F, $38, $DC, $77, $20                 // aesenc xmm6, [edi+32]
  db $66, $0F, $38, $DC, $7F, $20                 // aesenc xmm7, [edi+32]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 28], ecx
  add       edx, 1

  db $66, $0F, $38, $DC, $47, $30                 // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $4F, $30                 // aesenc xmm1, [edi+48]
  db $66, $0F, $38, $DC, $57, $30                 // aesenc xmm2, [edi+48]
  db $66, $0F, $38, $DC, $5F, $30                 // aesenc xmm3, [edi+48]
  db $66, $0F, $38, $DC, $67, $30                 // aesenc xmm4, [edi+48]
  db $66, $0F, $38, $DC, $6F, $30                 // aesenc xmm5, [edi+48]
  db $66, $0F, $38, $DC, $77, $30                 // aesenc xmm6, [edi+48]
  db $66, $0F, $38, $DC, $7F, $30                 // aesenc xmm7, [edi+48]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 44], ecx
  add       edx, 1

  db $66, $0F, $38, $DC, $47, $40                 // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $4F, $40                 // aesenc xmm1, [edi+64]
  db $66, $0F, $38, $DC, $57, $40                 // aesenc xmm2, [edi+64]
  db $66, $0F, $38, $DC, $5F, $40                 // aesenc xmm3, [edi+64]
  db $66, $0F, $38, $DC, $67, $40                 // aesenc xmm4, [edi+64]
  db $66, $0F, $38, $DC, $6F, $40                 // aesenc xmm5, [edi+64]
  db $66, $0F, $38, $DC, $77, $40                 // aesenc xmm6, [edi+64]
  db $66, $0F, $38, $DC, $7F, $40                 // aesenc xmm7, [edi+64]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 60], ecx
  add       edx, 1

  db $66, $0F, $38, $DC, $47, $50                 // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $4F, $50                 // aesenc xmm1, [edi+80]
  db $66, $0F, $38, $DC, $57, $50                 // aesenc xmm2, [edi+80]
  db $66, $0F, $38, $DC, $5F, $50                 // aesenc xmm3, [edi+80]
  db $66, $0F, $38, $DC, $67, $50                 // aesenc xmm4, [edi+80]
  db $66, $0F, $38, $DC, $6F, $50                 // aesenc xmm5, [edi+80]
  db $66, $0F, $38, $DC, $77, $50                 // aesenc xmm6, [edi+80]
  db $66, $0F, $38, $DC, $7F, $50                 // aesenc xmm7, [edi+80]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 76], ecx
  add       edx, 1

  db $66, $0F, $38, $DC, $47, $60                 // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $4F, $60                 // aesenc xmm1, [edi+96]
  db $66, $0F, $38, $DC, $57, $60                 // aesenc xmm2, [edi+96]
  db $66, $0F, $38, $DC, $5F, $60                 // aesenc xmm3, [edi+96]
  db $66, $0F, $38, $DC, $67, $60                 // aesenc xmm4, [edi+96]
  db $66, $0F, $38, $DC, $6F, $60                 // aesenc xmm5, [edi+96]
  db $66, $0F, $38, $DC, $77, $60                 // aesenc xmm6, [edi+96]
  db $66, $0F, $38, $DC, $7F, $60                 // aesenc xmm7, [edi+96]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 92], ecx
  add       edx, 1

  db $66, $0F, $38, $DC, $47, $70                 // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $4F, $70                 // aesenc xmm1, [edi+112]
  db $66, $0F, $38, $DC, $57, $70                 // aesenc xmm2, [edi+112]
  db $66, $0F, $38, $DC, $5F, $70                 // aesenc xmm3, [edi+112]
  db $66, $0F, $38, $DC, $67, $70                 // aesenc xmm4, [edi+112]
  db $66, $0F, $38, $DC, $6F, $70                 // aesenc xmm5, [edi+112]
  db $66, $0F, $38, $DC, $77, $70                 // aesenc xmm6, [edi+112]
  db $66, $0F, $38, $DC, $7F, $70                 // aesenc xmm7, [edi+112]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 108], ecx
  add       edx, 1

  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00  // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00  // aesenc xmm1, [edi+128]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00  // aesenc xmm2, [edi+128]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00  // aesenc xmm3, [edi+128]
  db $66, $0F, $38, $DC, $A7, $80, $00, $00, $00  // aesenc xmm4, [edi+128]
  db $66, $0F, $38, $DC, $AF, $80, $00, $00, $00  // aesenc xmm5, [edi+128]
  db $66, $0F, $38, $DC, $B7, $80, $00, $00, $00  // aesenc xmm6, [edi+128]
  db $66, $0F, $38, $DC, $BF, $80, $00, $00, $00  // aesenc xmm7, [edi+128]
  mov       ecx, edx
  bswap     ecx
  xor       ecx, eax
  mov       [esp + 124], ecx
  add       edx, 1

  // ---- round 9 (all key sizes): aesenc, no more staging ----
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00  // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $8F, $90, $00, $00, $00  // aesenc xmm1, [edi+144]
  db $66, $0F, $38, $DC, $97, $90, $00, $00, $00  // aesenc xmm2, [edi+144]
  db $66, $0F, $38, $DC, $9F, $90, $00, $00, $00  // aesenc xmm3, [edi+144]
  db $66, $0F, $38, $DC, $A7, $90, $00, $00, $00  // aesenc xmm4, [edi+144]
  db $66, $0F, $38, $DC, $AF, $90, $00, $00, $00  // aesenc xmm5, [edi+144]
  db $66, $0F, $38, $DC, $B7, $90, $00, $00, $00  // aesenc xmm6, [edi+144]
  db $66, $0F, $38, $DC, $BF, $90, $00, $00, $00  // aesenc xmm7, [edi+144]

{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00  // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $8F, $A0, $00, $00, $00  // aesenc xmm1, [edi+160]
  db $66, $0F, $38, $DC, $97, $A0, $00, $00, $00  // aesenc xmm2, [edi+160]
  db $66, $0F, $38, $DC, $9F, $A0, $00, $00, $00  // aesenc xmm3, [edi+160]
  db $66, $0F, $38, $DC, $A7, $A0, $00, $00, $00  // aesenc xmm4, [edi+160]
  db $66, $0F, $38, $DC, $AF, $A0, $00, $00, $00  // aesenc xmm5, [edi+160]
  db $66, $0F, $38, $DC, $B7, $A0, $00, $00, $00  // aesenc xmm6, [edi+160]
  db $66, $0F, $38, $DC, $BF, $A0, $00, $00, $00  // aesenc xmm7, [edi+160]
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00  // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DC, $8F, $B0, $00, $00, $00  // aesenc xmm1, [edi+176]
  db $66, $0F, $38, $DC, $97, $B0, $00, $00, $00  // aesenc xmm2, [edi+176]
  db $66, $0F, $38, $DC, $9F, $B0, $00, $00, $00  // aesenc xmm3, [edi+176]
  db $66, $0F, $38, $DC, $A7, $B0, $00, $00, $00  // aesenc xmm4, [edi+176]
  db $66, $0F, $38, $DC, $AF, $B0, $00, $00, $00  // aesenc xmm5, [edi+176]
  db $66, $0F, $38, $DC, $B7, $B0, $00, $00, $00  // aesenc xmm6, [edi+176]
  db $66, $0F, $38, $DC, $BF, $B0, $00, $00, $00  // aesenc xmm7, [edi+176]
{$IFEND}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00  // aesenc xmm0, [edi+192]
  db $66, $0F, $38, $DC, $8F, $C0, $00, $00, $00  // aesenc xmm1, [edi+192]
  db $66, $0F, $38, $DC, $97, $C0, $00, $00, $00  // aesenc xmm2, [edi+192]
  db $66, $0F, $38, $DC, $9F, $C0, $00, $00, $00  // aesenc xmm3, [edi+192]
  db $66, $0F, $38, $DC, $A7, $C0, $00, $00, $00  // aesenc xmm4, [edi+192]
  db $66, $0F, $38, $DC, $AF, $C0, $00, $00, $00  // aesenc xmm5, [edi+192]
  db $66, $0F, $38, $DC, $B7, $C0, $00, $00, $00  // aesenc xmm6, [edi+192]
  db $66, $0F, $38, $DC, $BF, $C0, $00, $00, $00  // aesenc xmm7, [edi+192]
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00  // aesenc xmm0, [edi+208]
  db $66, $0F, $38, $DC, $8F, $D0, $00, $00, $00  // aesenc xmm1, [edi+208]
  db $66, $0F, $38, $DC, $97, $D0, $00, $00, $00  // aesenc xmm2, [edi+208]
  db $66, $0F, $38, $DC, $9F, $D0, $00, $00, $00  // aesenc xmm3, [edi+208]
  db $66, $0F, $38, $DC, $A7, $D0, $00, $00, $00  // aesenc xmm4, [edi+208]
  db $66, $0F, $38, $DC, $AF, $D0, $00, $00, $00  // aesenc xmm5, [edi+208]
  db $66, $0F, $38, $DC, $B7, $D0, $00, $00, $00  // aesenc xmm6, [edi+208]
  db $66, $0F, $38, $DC, $BF, $D0, $00, $00, $00  // aesenc xmm7, [edi+208]
{$ENDIF}

  // ---- final round: aesenclast on the last round key ----
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00  // aesenclast xmm0, [edi+160]
  db $66, $0F, $38, $DD, $8F, $A0, $00, $00, $00  // aesenclast xmm1, [edi+160]
  db $66, $0F, $38, $DD, $97, $A0, $00, $00, $00  // aesenclast xmm2, [edi+160]
  db $66, $0F, $38, $DD, $9F, $A0, $00, $00, $00  // aesenclast xmm3, [edi+160]
  db $66, $0F, $38, $DD, $A7, $A0, $00, $00, $00  // aesenclast xmm4, [edi+160]
  db $66, $0F, $38, $DD, $AF, $A0, $00, $00, $00  // aesenclast xmm5, [edi+160]
  db $66, $0F, $38, $DD, $B7, $A0, $00, $00, $00  // aesenclast xmm6, [edi+160]
  db $66, $0F, $38, $DD, $BF, $A0, $00, $00, $00  // aesenclast xmm7, [edi+160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00  // aesenclast xmm0, [edi+192]
  db $66, $0F, $38, $DD, $8F, $C0, $00, $00, $00  // aesenclast xmm1, [edi+192]
  db $66, $0F, $38, $DD, $97, $C0, $00, $00, $00  // aesenclast xmm2, [edi+192]
  db $66, $0F, $38, $DD, $9F, $C0, $00, $00, $00  // aesenclast xmm3, [edi+192]
  db $66, $0F, $38, $DD, $A7, $C0, $00, $00, $00  // aesenclast xmm4, [edi+192]
  db $66, $0F, $38, $DD, $AF, $C0, $00, $00, $00  // aesenclast xmm5, [edi+192]
  db $66, $0F, $38, $DD, $B7, $C0, $00, $00, $00  // aesenclast xmm6, [edi+192]
  db $66, $0F, $38, $DD, $BF, $C0, $00, $00, $00  // aesenclast xmm7, [edi+192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00  // aesenclast xmm0, [edi+224]
  db $66, $0F, $38, $DD, $8F, $E0, $00, $00, $00  // aesenclast xmm1, [edi+224]
  db $66, $0F, $38, $DD, $97, $E0, $00, $00, $00  // aesenclast xmm2, [edi+224]
  db $66, $0F, $38, $DD, $9F, $E0, $00, $00, $00  // aesenclast xmm3, [edi+224]
  db $66, $0F, $38, $DD, $A7, $E0, $00, $00, $00  // aesenclast xmm4, [edi+224]
  db $66, $0F, $38, $DD, $AF, $E0, $00, $00, $00  // aesenclast xmm5, [edi+224]
  db $66, $0F, $38, $DD, $B7, $E0, $00, $00, $00  // aesenclast xmm6, [edi+224]
  db $66, $0F, $38, $DD, $BF, $E0, $00, $00, $00  // aesenclast xmm7, [edi+224]
{$ENDIF}

  // ---- keystream ^ plaintext -> output. Spill ks7 to the scratch slot above
  //      the counters, reuse xmm7 as the movdqu plaintext scratch for blocks
  //      0..6, then reload ks7 into the consumed xmm0 for block 7. ----
  movdqu    [esp + 128], xmm7                     // spill ks7
  movdqu    xmm7, [ebx + 0]
  db $66, $0F, $EF, $F8                           // pxor xmm7, xmm0
  movdqu    [esi + 0], xmm7
  movdqu    xmm7, [ebx + 16]
  db $66, $0F, $EF, $F9                           // pxor xmm7, xmm1
  movdqu    [esi + 16], xmm7
  movdqu    xmm7, [ebx + 32]
  db $66, $0F, $EF, $FA                           // pxor xmm7, xmm2
  movdqu    [esi + 32], xmm7
  movdqu    xmm7, [ebx + 48]
  db $66, $0F, $EF, $FB                           // pxor xmm7, xmm3
  movdqu    [esi + 48], xmm7
  movdqu    xmm7, [ebx + 64]
  db $66, $0F, $EF, $FC                           // pxor xmm7, xmm4
  movdqu    [esi + 64], xmm7
  movdqu    xmm7, [ebx + 80]
  db $66, $0F, $EF, $FD                           // pxor xmm7, xmm5
  movdqu    [esi + 80], xmm7
  movdqu    xmm7, [ebx + 96]
  db $66, $0F, $EF, $FE                           // pxor xmm7, xmm6
  movdqu    [esi + 96], xmm7
  movdqu    xmm0, [esp + 128]                     // reload ks7 into consumed xmm0
  movdqu    xmm7, [ebx + 112]
  db $66, $0F, $EF, $F8                           // pxor xmm7, xmm0
  movdqu    [esi + 112], xmm7

  // ---- load the staged next-batch pre-whitened counters into xmm0..7 ----
  movdqu    xmm0, [esp + 0]
  movdqu    xmm1, [esp + 16]
  movdqu    xmm2, [esp + 32]
  movdqu    xmm3, [esp + 48]
  movdqu    xmm4, [esp + 64]
  movdqu    xmm5, [esp + 80]
  movdqu    xmm6, [esp + 96]
  movdqu    xmm7, [esp + 112]

  add       ebx, 128
  add       esi, 128
  sub       dword ptr [esp + 144], 8
  jnz       @@CtrEightLoopI386

  // ---- undo the one-batch build-ahead (mod 2^32; no carry by contract),
  //      write the low counter dword back big-endian ----
  mov       eax, [esp + 148]                      // CounterPtr
  sub       edx, 8
  bswap     edx
  mov       [eax + 12], edx

  add       esp, 152
  pop       edi
  pop       esi
  pop       ebx
