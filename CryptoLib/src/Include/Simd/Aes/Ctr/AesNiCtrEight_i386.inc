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
// Entry (after ClpSimdProc1Begin_i386.inc): ebx = pointer to TCtrFusedCtx. The
// kernel pushes esi/edi and unpacks the record (InPtr loaded into ebx last):
//   [ebx +  0]  InPtr      -> ebx : input  (advances +128 per 8-block iteration)
//   [ebx +  4]  OutPtr     -> esi : output (advances +128)
//   [ebx +  8]  KeysPtr    -> edi : AES round-key schedule (consumed as [edi+K])
//   [ebx + 12]  CounterPtr -> eax : 16-byte big-endian counter (advanced in place)
//   [ebx + 16]  BlockCount -> ecx : positive multiple of 8 (caller guarantees it)
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt (CTR keystream), so CRYPTOLIB_AESNI_DECRYPT must
// NOT be defined when including this file.
//
// Constraints: i386 has only xmm0..7 (all volatile). BlockCount parks in a frame
// slot so both edx and ecx serve the staging: edx holds the counter's low dword
// native-LE across the whole span (bswap/store/bswap/add per staged block - no
// read-modify-write of counter memory, so no store-forward stalls), while ecx
// copies the constant 12-byte prefix from [eax+0..11] (written only by the rare
// carry-out path, which bumps those bytes big-endian). The pipeline builds one
// batch ahead, so edx over-runs by exactly one batch (8) - undone (with a
// byte-wise borrow when it crosses back over a 2^32 boundary) before the low
// dword is stored back to [eax+12]. The keystream^plaintext XOR has no free xmm for the
// plaintext (nor can it use a memory-operand pxor, which would require the input
// to be 16-byte aligned), so it spills lane 7 to a scratch slot above the counter
// area and reuses xmm7 for the movdqu plaintext load. AES-NI and register pxor
// forms are db-encoded for broad assembler compatibility.
  // ---- unpack TCtrFusedCtx (ebx = PCtx); load InPtr into ebx last ----
  push      esi
  push      edi
  mov       esi, [ebx + 4]                        // OutPtr
  mov       edi, [ebx + 8]                        // KeysPtr
  mov       eax, [ebx + 12]                       // CounterPtr
  mov       ecx, [ebx + 16]                       // BlockCount
  mov       ebx, [ebx + 0]                        // InPtr (overwrites PCtx)

  sub       esp, 152                              // next-batch counters [esp+0..127]; ks7 spill [esp+128..143]; countdown [esp+144]
  mov       [esp + 144], ecx                        // park BlockCount; ecx = staging scratch
  mov       edx, [eax + 12]                         // counter low dword, kept native-LE in edx
  bswap     edx

  // ---- stage batch 0 into the scratch (xmm0 is free here), then load it ----
  mov       ecx, [eax]
  mov       [esp + 0], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 4], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 8], ecx
  bswap     edx
  mov       [esp + 12], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP0
  mov       ecx, 11
@@StgCyP0:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP0
  dec       ecx
  jns       @@StgCyP0
@@StgOkP0:
  mov       ecx, [eax]
  mov       [esp + 16], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 20], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 24], ecx
  bswap     edx
  mov       [esp + 28], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP1
  mov       ecx, 11
@@StgCyP1:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP1
  dec       ecx
  jns       @@StgCyP1
@@StgOkP1:
  mov       ecx, [eax]
  mov       [esp + 32], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 36], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 40], ecx
  bswap     edx
  mov       [esp + 44], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP2
  mov       ecx, 11
@@StgCyP2:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP2
  dec       ecx
  jns       @@StgCyP2
@@StgOkP2:
  mov       ecx, [eax]
  mov       [esp + 48], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 52], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 56], ecx
  bswap     edx
  mov       [esp + 60], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP3
  mov       ecx, 11
@@StgCyP3:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP3
  dec       ecx
  jns       @@StgCyP3
@@StgOkP3:
  mov       ecx, [eax]
  mov       [esp + 64], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 68], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 72], ecx
  bswap     edx
  mov       [esp + 76], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP4
  mov       ecx, 11
@@StgCyP4:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP4
  dec       ecx
  jns       @@StgCyP4
@@StgOkP4:
  mov       ecx, [eax]
  mov       [esp + 80], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 84], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 88], ecx
  bswap     edx
  mov       [esp + 92], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP5
  mov       ecx, 11
@@StgCyP5:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP5
  dec       ecx
  jns       @@StgCyP5
@@StgOkP5:
  mov       ecx, [eax]
  mov       [esp + 96], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 100], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 104], ecx
  bswap     edx
  mov       [esp + 108], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP6
  mov       ecx, 11
@@StgCyP6:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP6
  dec       ecx
  jns       @@StgCyP6
@@StgOkP6:
  mov       ecx, [eax]
  mov       [esp + 112], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 116], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 120], ecx
  bswap     edx
  mov       [esp + 124], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkP7
  mov       ecx, 11
@@StgCyP7:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkP7
  dec       ecx
  jns       @@StgCyP7
@@StgOkP7:

  movdqu    xmm0, [esp + 0]
  movdqu    xmm1, [esp + 16]
  movdqu    xmm2, [esp + 32]
  movdqu    xmm3, [esp + 48]
  movdqu    xmm4, [esp + 64]
  movdqu    xmm5, [esp + 80]
  movdqu    xmm6, [esp + 96]
  movdqu    xmm7, [esp + 112]

@@CtrEightLoopI386:
  // ---- round 0: whiten with K_0 ----
  db $66, $0F, $EF, $07                           // pxor xmm0, [edi+0]
  db $66, $0F, $EF, $0F                           // pxor xmm1, [edi+0]
  db $66, $0F, $EF, $17                           // pxor xmm2, [edi+0]
  db $66, $0F, $EF, $1F                           // pxor xmm3, [edi+0]
  db $66, $0F, $EF, $27                           // pxor xmm4, [edi+0]
  db $66, $0F, $EF, $2F                           // pxor xmm5, [edi+0]
  db $66, $0F, $EF, $37                           // pxor xmm6, [edi+0]
  db $66, $0F, $EF, $3F                           // pxor xmm7, [edi+0]

  // ---- rounds 1..8: aesenc, each interleaved with staging one next counter ----
  db $66, $0F, $38, $DC, $47, $10                 // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $4F, $10                 // aesenc xmm1, [edi+16]
  db $66, $0F, $38, $DC, $57, $10                 // aesenc xmm2, [edi+16]
  db $66, $0F, $38, $DC, $5F, $10                 // aesenc xmm3, [edi+16]
  db $66, $0F, $38, $DC, $67, $10                 // aesenc xmm4, [edi+16]
  db $66, $0F, $38, $DC, $6F, $10                 // aesenc xmm5, [edi+16]
  db $66, $0F, $38, $DC, $77, $10                 // aesenc xmm6, [edi+16]
  db $66, $0F, $38, $DC, $7F, $10                 // aesenc xmm7, [edi+16]
  mov       ecx, [eax]
  mov       [esp + 0], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 4], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 8], ecx
  bswap     edx
  mov       [esp + 12], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL0
  mov       ecx, 11
@@StgCyL0:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL0
  dec       ecx
  jns       @@StgCyL0
@@StgOkL0:

  db $66, $0F, $38, $DC, $47, $20                 // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $4F, $20                 // aesenc xmm1, [edi+32]
  db $66, $0F, $38, $DC, $57, $20                 // aesenc xmm2, [edi+32]
  db $66, $0F, $38, $DC, $5F, $20                 // aesenc xmm3, [edi+32]
  db $66, $0F, $38, $DC, $67, $20                 // aesenc xmm4, [edi+32]
  db $66, $0F, $38, $DC, $6F, $20                 // aesenc xmm5, [edi+32]
  db $66, $0F, $38, $DC, $77, $20                 // aesenc xmm6, [edi+32]
  db $66, $0F, $38, $DC, $7F, $20                 // aesenc xmm7, [edi+32]
  mov       ecx, [eax]
  mov       [esp + 16], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 20], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 24], ecx
  bswap     edx
  mov       [esp + 28], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL1
  mov       ecx, 11
@@StgCyL1:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL1
  dec       ecx
  jns       @@StgCyL1
@@StgOkL1:

  db $66, $0F, $38, $DC, $47, $30                 // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $4F, $30                 // aesenc xmm1, [edi+48]
  db $66, $0F, $38, $DC, $57, $30                 // aesenc xmm2, [edi+48]
  db $66, $0F, $38, $DC, $5F, $30                 // aesenc xmm3, [edi+48]
  db $66, $0F, $38, $DC, $67, $30                 // aesenc xmm4, [edi+48]
  db $66, $0F, $38, $DC, $6F, $30                 // aesenc xmm5, [edi+48]
  db $66, $0F, $38, $DC, $77, $30                 // aesenc xmm6, [edi+48]
  db $66, $0F, $38, $DC, $7F, $30                 // aesenc xmm7, [edi+48]
  mov       ecx, [eax]
  mov       [esp + 32], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 36], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 40], ecx
  bswap     edx
  mov       [esp + 44], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL2
  mov       ecx, 11
@@StgCyL2:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL2
  dec       ecx
  jns       @@StgCyL2
@@StgOkL2:

  db $66, $0F, $38, $DC, $47, $40                 // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $4F, $40                 // aesenc xmm1, [edi+64]
  db $66, $0F, $38, $DC, $57, $40                 // aesenc xmm2, [edi+64]
  db $66, $0F, $38, $DC, $5F, $40                 // aesenc xmm3, [edi+64]
  db $66, $0F, $38, $DC, $67, $40                 // aesenc xmm4, [edi+64]
  db $66, $0F, $38, $DC, $6F, $40                 // aesenc xmm5, [edi+64]
  db $66, $0F, $38, $DC, $77, $40                 // aesenc xmm6, [edi+64]
  db $66, $0F, $38, $DC, $7F, $40                 // aesenc xmm7, [edi+64]
  mov       ecx, [eax]
  mov       [esp + 48], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 52], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 56], ecx
  bswap     edx
  mov       [esp + 60], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL3
  mov       ecx, 11
@@StgCyL3:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL3
  dec       ecx
  jns       @@StgCyL3
@@StgOkL3:

  db $66, $0F, $38, $DC, $47, $50                 // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $4F, $50                 // aesenc xmm1, [edi+80]
  db $66, $0F, $38, $DC, $57, $50                 // aesenc xmm2, [edi+80]
  db $66, $0F, $38, $DC, $5F, $50                 // aesenc xmm3, [edi+80]
  db $66, $0F, $38, $DC, $67, $50                 // aesenc xmm4, [edi+80]
  db $66, $0F, $38, $DC, $6F, $50                 // aesenc xmm5, [edi+80]
  db $66, $0F, $38, $DC, $77, $50                 // aesenc xmm6, [edi+80]
  db $66, $0F, $38, $DC, $7F, $50                 // aesenc xmm7, [edi+80]
  mov       ecx, [eax]
  mov       [esp + 64], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 68], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 72], ecx
  bswap     edx
  mov       [esp + 76], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL4
  mov       ecx, 11
@@StgCyL4:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL4
  dec       ecx
  jns       @@StgCyL4
@@StgOkL4:

  db $66, $0F, $38, $DC, $47, $60                 // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $4F, $60                 // aesenc xmm1, [edi+96]
  db $66, $0F, $38, $DC, $57, $60                 // aesenc xmm2, [edi+96]
  db $66, $0F, $38, $DC, $5F, $60                 // aesenc xmm3, [edi+96]
  db $66, $0F, $38, $DC, $67, $60                 // aesenc xmm4, [edi+96]
  db $66, $0F, $38, $DC, $6F, $60                 // aesenc xmm5, [edi+96]
  db $66, $0F, $38, $DC, $77, $60                 // aesenc xmm6, [edi+96]
  db $66, $0F, $38, $DC, $7F, $60                 // aesenc xmm7, [edi+96]
  mov       ecx, [eax]
  mov       [esp + 80], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 84], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 88], ecx
  bswap     edx
  mov       [esp + 92], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL5
  mov       ecx, 11
@@StgCyL5:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL5
  dec       ecx
  jns       @@StgCyL5
@@StgOkL5:

  db $66, $0F, $38, $DC, $47, $70                 // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $4F, $70                 // aesenc xmm1, [edi+112]
  db $66, $0F, $38, $DC, $57, $70                 // aesenc xmm2, [edi+112]
  db $66, $0F, $38, $DC, $5F, $70                 // aesenc xmm3, [edi+112]
  db $66, $0F, $38, $DC, $67, $70                 // aesenc xmm4, [edi+112]
  db $66, $0F, $38, $DC, $6F, $70                 // aesenc xmm5, [edi+112]
  db $66, $0F, $38, $DC, $77, $70                 // aesenc xmm6, [edi+112]
  db $66, $0F, $38, $DC, $7F, $70                 // aesenc xmm7, [edi+112]
  mov       ecx, [eax]
  mov       [esp + 96], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 100], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 104], ecx
  bswap     edx
  mov       [esp + 108], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL6
  mov       ecx, 11
@@StgCyL6:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL6
  dec       ecx
  jns       @@StgCyL6
@@StgOkL6:

  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00  // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00  // aesenc xmm1, [edi+128]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00  // aesenc xmm2, [edi+128]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00  // aesenc xmm3, [edi+128]
  db $66, $0F, $38, $DC, $A7, $80, $00, $00, $00  // aesenc xmm4, [edi+128]
  db $66, $0F, $38, $DC, $AF, $80, $00, $00, $00  // aesenc xmm5, [edi+128]
  db $66, $0F, $38, $DC, $B7, $80, $00, $00, $00  // aesenc xmm6, [edi+128]
  db $66, $0F, $38, $DC, $BF, $80, $00, $00, $00  // aesenc xmm7, [edi+128]
  mov       ecx, [eax]
  mov       [esp + 112], ecx
  mov       ecx, [eax + 4]
  mov       [esp + 116], ecx
  mov       ecx, [eax + 8]
  mov       [esp + 120], ecx
  bswap     edx
  mov       [esp + 124], edx
  bswap     edx
  add       edx, 1
  jnc       @@StgOkL7
  mov       ecx, 11
@@StgCyL7:
  inc       byte ptr [eax + ecx]
  jnz       @@StgOkL7
  dec       ecx
  jns       @@StgCyL7
@@StgOkL7:

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

  // ---- load the staged next-batch counters into xmm0..7 ----
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

  // ---- undo the one-batch build-ahead (edx is 8 blocks ahead); a borrow
  //      unwinds the prefix bytes, then the low dword stores big-endian ----
  sub       edx, 8
  jnc       @@CtrWbStore
  mov       ecx, 11
@@CtrWbBorrow:
  sub       byte ptr [eax + ecx], 1
  jnc       @@CtrWbStore
  dec       ecx
  jns       @@CtrWbBorrow
@@CtrWbStore:
  bswap     edx
  mov       [eax + 12], edx

  add       esp, 152
  pop       edi
  pop       esi
  pop       ebx
