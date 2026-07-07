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
// Entry (after SimdProc1Begin_i386.inc): ebx = pointer to TCtrFusedCtx. The
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
// Constraints: i386 has only xmm0..7 (all volatile) and, after unpacking the
// context, only edx as a free scratch GP register. The 128-bit counter lives in
// memory at [eax] and is bumped in place with a byte-wise big-endian carry (edx =
// byte index). Each staged block copies the current [eax] to the scratch (four
// dword moves through edx, since no xmm is free mid-round) then advances. The
// pipeline builds one batch ahead, so [eax] over-runs by exactly one batch (8) -
// undone before returning. The keystream^plaintext XOR has no free xmm for the
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

  sub       esp, 144                              // next-batch counters [esp+0..127]; ks7 spill [esp+128..143]

  // ---- stage batch 0 into the scratch (xmm0 is free here), then load it ----
  movdqu    xmm0, [eax]
  movdqu    [esp + 0], xmm0
  mov       edx, 15
@@PreA0:
  inc       byte ptr [eax + edx]
  jnz       @@PreD0
  dec       edx
  jns       @@PreA0
@@PreD0:
  movdqu    xmm0, [eax]
  movdqu    [esp + 16], xmm0
  mov       edx, 15
@@PreA1:
  inc       byte ptr [eax + edx]
  jnz       @@PreD1
  dec       edx
  jns       @@PreA1
@@PreD1:
  movdqu    xmm0, [eax]
  movdqu    [esp + 32], xmm0
  mov       edx, 15
@@PreA2:
  inc       byte ptr [eax + edx]
  jnz       @@PreD2
  dec       edx
  jns       @@PreA2
@@PreD2:
  movdqu    xmm0, [eax]
  movdqu    [esp + 48], xmm0
  mov       edx, 15
@@PreA3:
  inc       byte ptr [eax + edx]
  jnz       @@PreD3
  dec       edx
  jns       @@PreA3
@@PreD3:
  movdqu    xmm0, [eax]
  movdqu    [esp + 64], xmm0
  mov       edx, 15
@@PreA4:
  inc       byte ptr [eax + edx]
  jnz       @@PreD4
  dec       edx
  jns       @@PreA4
@@PreD4:
  movdqu    xmm0, [eax]
  movdqu    [esp + 80], xmm0
  mov       edx, 15
@@PreA5:
  inc       byte ptr [eax + edx]
  jnz       @@PreD5
  dec       edx
  jns       @@PreA5
@@PreD5:
  movdqu    xmm0, [eax]
  movdqu    [esp + 96], xmm0
  mov       edx, 15
@@PreA6:
  inc       byte ptr [eax + edx]
  jnz       @@PreD6
  dec       edx
  jns       @@PreA6
@@PreD6:
  movdqu    xmm0, [eax]
  movdqu    [esp + 112], xmm0
  mov       edx, 15
@@PreA7:
  inc       byte ptr [eax + edx]
  jnz       @@PreD7
  dec       edx
  jns       @@PreA7
@@PreD7:

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
  mov       edx, [eax]
  mov       [esp + 0], edx
  mov       edx, [eax + 4]
  mov       [esp + 4], edx
  mov       edx, [eax + 8]
  mov       [esp + 8], edx
  mov       edx, [eax + 12]
  mov       [esp + 12], edx
  mov       edx, 15
@@LpA0:
  inc       byte ptr [eax + edx]
  jnz       @@LpD0
  dec       edx
  jns       @@LpA0
@@LpD0:

  db $66, $0F, $38, $DC, $47, $20                 // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $4F, $20                 // aesenc xmm1, [edi+32]
  db $66, $0F, $38, $DC, $57, $20                 // aesenc xmm2, [edi+32]
  db $66, $0F, $38, $DC, $5F, $20                 // aesenc xmm3, [edi+32]
  db $66, $0F, $38, $DC, $67, $20                 // aesenc xmm4, [edi+32]
  db $66, $0F, $38, $DC, $6F, $20                 // aesenc xmm5, [edi+32]
  db $66, $0F, $38, $DC, $77, $20                 // aesenc xmm6, [edi+32]
  db $66, $0F, $38, $DC, $7F, $20                 // aesenc xmm7, [edi+32]
  mov       edx, [eax]
  mov       [esp + 16], edx
  mov       edx, [eax + 4]
  mov       [esp + 20], edx
  mov       edx, [eax + 8]
  mov       [esp + 24], edx
  mov       edx, [eax + 12]
  mov       [esp + 28], edx
  mov       edx, 15
@@LpA1:
  inc       byte ptr [eax + edx]
  jnz       @@LpD1
  dec       edx
  jns       @@LpA1
@@LpD1:

  db $66, $0F, $38, $DC, $47, $30                 // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $4F, $30                 // aesenc xmm1, [edi+48]
  db $66, $0F, $38, $DC, $57, $30                 // aesenc xmm2, [edi+48]
  db $66, $0F, $38, $DC, $5F, $30                 // aesenc xmm3, [edi+48]
  db $66, $0F, $38, $DC, $67, $30                 // aesenc xmm4, [edi+48]
  db $66, $0F, $38, $DC, $6F, $30                 // aesenc xmm5, [edi+48]
  db $66, $0F, $38, $DC, $77, $30                 // aesenc xmm6, [edi+48]
  db $66, $0F, $38, $DC, $7F, $30                 // aesenc xmm7, [edi+48]
  mov       edx, [eax]
  mov       [esp + 32], edx
  mov       edx, [eax + 4]
  mov       [esp + 36], edx
  mov       edx, [eax + 8]
  mov       [esp + 40], edx
  mov       edx, [eax + 12]
  mov       [esp + 44], edx
  mov       edx, 15
@@LpA2:
  inc       byte ptr [eax + edx]
  jnz       @@LpD2
  dec       edx
  jns       @@LpA2
@@LpD2:

  db $66, $0F, $38, $DC, $47, $40                 // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $4F, $40                 // aesenc xmm1, [edi+64]
  db $66, $0F, $38, $DC, $57, $40                 // aesenc xmm2, [edi+64]
  db $66, $0F, $38, $DC, $5F, $40                 // aesenc xmm3, [edi+64]
  db $66, $0F, $38, $DC, $67, $40                 // aesenc xmm4, [edi+64]
  db $66, $0F, $38, $DC, $6F, $40                 // aesenc xmm5, [edi+64]
  db $66, $0F, $38, $DC, $77, $40                 // aesenc xmm6, [edi+64]
  db $66, $0F, $38, $DC, $7F, $40                 // aesenc xmm7, [edi+64]
  mov       edx, [eax]
  mov       [esp + 48], edx
  mov       edx, [eax + 4]
  mov       [esp + 52], edx
  mov       edx, [eax + 8]
  mov       [esp + 56], edx
  mov       edx, [eax + 12]
  mov       [esp + 60], edx
  mov       edx, 15
@@LpA3:
  inc       byte ptr [eax + edx]
  jnz       @@LpD3
  dec       edx
  jns       @@LpA3
@@LpD3:

  db $66, $0F, $38, $DC, $47, $50                 // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $4F, $50                 // aesenc xmm1, [edi+80]
  db $66, $0F, $38, $DC, $57, $50                 // aesenc xmm2, [edi+80]
  db $66, $0F, $38, $DC, $5F, $50                 // aesenc xmm3, [edi+80]
  db $66, $0F, $38, $DC, $67, $50                 // aesenc xmm4, [edi+80]
  db $66, $0F, $38, $DC, $6F, $50                 // aesenc xmm5, [edi+80]
  db $66, $0F, $38, $DC, $77, $50                 // aesenc xmm6, [edi+80]
  db $66, $0F, $38, $DC, $7F, $50                 // aesenc xmm7, [edi+80]
  mov       edx, [eax]
  mov       [esp + 64], edx
  mov       edx, [eax + 4]
  mov       [esp + 68], edx
  mov       edx, [eax + 8]
  mov       [esp + 72], edx
  mov       edx, [eax + 12]
  mov       [esp + 76], edx
  mov       edx, 15
@@LpA4:
  inc       byte ptr [eax + edx]
  jnz       @@LpD4
  dec       edx
  jns       @@LpA4
@@LpD4:

  db $66, $0F, $38, $DC, $47, $60                 // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $4F, $60                 // aesenc xmm1, [edi+96]
  db $66, $0F, $38, $DC, $57, $60                 // aesenc xmm2, [edi+96]
  db $66, $0F, $38, $DC, $5F, $60                 // aesenc xmm3, [edi+96]
  db $66, $0F, $38, $DC, $67, $60                 // aesenc xmm4, [edi+96]
  db $66, $0F, $38, $DC, $6F, $60                 // aesenc xmm5, [edi+96]
  db $66, $0F, $38, $DC, $77, $60                 // aesenc xmm6, [edi+96]
  db $66, $0F, $38, $DC, $7F, $60                 // aesenc xmm7, [edi+96]
  mov       edx, [eax]
  mov       [esp + 80], edx
  mov       edx, [eax + 4]
  mov       [esp + 84], edx
  mov       edx, [eax + 8]
  mov       [esp + 88], edx
  mov       edx, [eax + 12]
  mov       [esp + 92], edx
  mov       edx, 15
@@LpA5:
  inc       byte ptr [eax + edx]
  jnz       @@LpD5
  dec       edx
  jns       @@LpA5
@@LpD5:

  db $66, $0F, $38, $DC, $47, $70                 // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $4F, $70                 // aesenc xmm1, [edi+112]
  db $66, $0F, $38, $DC, $57, $70                 // aesenc xmm2, [edi+112]
  db $66, $0F, $38, $DC, $5F, $70                 // aesenc xmm3, [edi+112]
  db $66, $0F, $38, $DC, $67, $70                 // aesenc xmm4, [edi+112]
  db $66, $0F, $38, $DC, $6F, $70                 // aesenc xmm5, [edi+112]
  db $66, $0F, $38, $DC, $77, $70                 // aesenc xmm6, [edi+112]
  db $66, $0F, $38, $DC, $7F, $70                 // aesenc xmm7, [edi+112]
  mov       edx, [eax]
  mov       [esp + 96], edx
  mov       edx, [eax + 4]
  mov       [esp + 100], edx
  mov       edx, [eax + 8]
  mov       [esp + 104], edx
  mov       edx, [eax + 12]
  mov       [esp + 108], edx
  mov       edx, 15
@@LpA6:
  inc       byte ptr [eax + edx]
  jnz       @@LpD6
  dec       edx
  jns       @@LpA6
@@LpD6:

  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00  // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $8F, $80, $00, $00, $00  // aesenc xmm1, [edi+128]
  db $66, $0F, $38, $DC, $97, $80, $00, $00, $00  // aesenc xmm2, [edi+128]
  db $66, $0F, $38, $DC, $9F, $80, $00, $00, $00  // aesenc xmm3, [edi+128]
  db $66, $0F, $38, $DC, $A7, $80, $00, $00, $00  // aesenc xmm4, [edi+128]
  db $66, $0F, $38, $DC, $AF, $80, $00, $00, $00  // aesenc xmm5, [edi+128]
  db $66, $0F, $38, $DC, $B7, $80, $00, $00, $00  // aesenc xmm6, [edi+128]
  db $66, $0F, $38, $DC, $BF, $80, $00, $00, $00  // aesenc xmm7, [edi+128]
  mov       edx, [eax]
  mov       [esp + 112], edx
  mov       edx, [eax + 4]
  mov       [esp + 116], edx
  mov       edx, [eax + 8]
  mov       [esp + 120], edx
  mov       edx, [eax + 12]
  mov       [esp + 124], edx
  mov       edx, 15
@@LpA7:
  inc       byte ptr [eax + edx]
  jnz       @@LpD7
  dec       edx
  jns       @@LpA7
@@LpD7:

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
  sub       ecx, 8
  jnz       @@CtrEightLoopI386

  // ---- undo the one-batch build-ahead: counter (at [eax]) -= 8, big-endian ----
  sub       byte ptr [eax + 15], 8
  jnc       @@CtrWbDone
  mov       edx, 14
@@CtrWbBorrow:
  sub       byte ptr [eax + edx], 1
  jnc       @@CtrWbDone
  dec       edx
  jns       @@CtrWbBorrow
@@CtrWbDone:

  add       esp, 144
  pop       edi
  pop       esi
  pop       ebx
