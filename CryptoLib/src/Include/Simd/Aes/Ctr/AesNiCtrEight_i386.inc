// AES-NI 8-wide CTR keystream + XOR, single-pass fused kernel (i386).
// -------------------------------------------------------------------
//
// i386 counterpart of AesNiCtrEight_x86_64.inc: generates 8 AES-CTR keystream
// blocks and XORs them with the input in one pass, for TSicBlockCipher's bulk
// path. Reuses the shared 8-wide round chain AesNiEightRoundsOnly_i386.inc.
//
// Entry (after SimdProc1Begin_i386.inc): ebx = pointer to TCtrFusedCtx. The
// kernel pushes esi/edi and unpacks the record (InPtr loaded into ebx last):
//   [ebx +  0]  InPtr      -> ebx : input  (advances +128 per 8-block iteration)
//   [ebx +  4]  OutPtr     -> esi : output (advances +128)
//   [ebx +  8]  KeysPtr    -> edi : AES round-key schedule (16-byte aligned;
//                                   consumed by the reused round chain as
//                                   [edi + K] memory operands, unchanged on exit)
//   [ebx + 12]  CounterPtr -> eax : 16-byte big-endian counter (advanced in place)
//   [ebx + 16]  BlockCount -> ecx : positive multiple of 8 (caller guarantees it)
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt (CTR keystream), so CRYPTOLIB_AESNI_DECRYPT must
// NOT be defined when including this file.
//
// Constraints that shape this kernel: i386 has only xmm0-7 (all volatile, so no
// save/restore), and after unpacking the context only edx is a free scratch GP
// register. So the 8 counter blocks are materialised into a 128-byte stack
// scratch, the 16-byte counter is bumped in place with a byte-wise big-endian
// carry (edx = byte
// index), and the keystream^plaintext XOR spills xmm7 to reuse it as the
// plaintext-load scratch (no 8th xmm exists). The register-form PXOR below is
// db-encoded for broad assembler compatibility, like the AES-NI ops.
  // ---- unpack TCtrFusedCtx (ebx = PCtx); load InPtr into ebx last ----
  push      esi
  push      edi
  mov       esi, [ebx + 4]                        // OutPtr
  mov       edi, [ebx + 8]                        // KeysPtr
  mov       eax, [ebx + 12]                       // CounterPtr
  mov       ecx, [ebx + 16]                       // BlockCount
  mov       ebx, [ebx + 0]                        // InPtr (overwrites PCtx)

  sub       esp, 128                              // 8 x 16-byte counter scratch

@@CtrEightLoopI386:
  // ---- materialise 8 big-endian counter blocks, bumping [eax] after each ----
  movdqu    xmm0, [eax]
  movdqu    [esp + 0], xmm0
  mov       edx, 15
@@CtrIncA0:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD0
  dec       edx
  jns       @@CtrIncA0
@@CtrIncD0:
  movdqu    xmm0, [eax]
  movdqu    [esp + 16], xmm0
  mov       edx, 15
@@CtrIncA1:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD1
  dec       edx
  jns       @@CtrIncA1
@@CtrIncD1:
  movdqu    xmm0, [eax]
  movdqu    [esp + 32], xmm0
  mov       edx, 15
@@CtrIncA2:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD2
  dec       edx
  jns       @@CtrIncA2
@@CtrIncD2:
  movdqu    xmm0, [eax]
  movdqu    [esp + 48], xmm0
  mov       edx, 15
@@CtrIncA3:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD3
  dec       edx
  jns       @@CtrIncA3
@@CtrIncD3:
  movdqu    xmm0, [eax]
  movdqu    [esp + 64], xmm0
  mov       edx, 15
@@CtrIncA4:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD4
  dec       edx
  jns       @@CtrIncA4
@@CtrIncD4:
  movdqu    xmm0, [eax]
  movdqu    [esp + 80], xmm0
  mov       edx, 15
@@CtrIncA5:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD5
  dec       edx
  jns       @@CtrIncA5
@@CtrIncD5:
  movdqu    xmm0, [eax]
  movdqu    [esp + 96], xmm0
  mov       edx, 15
@@CtrIncA6:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD6
  dec       edx
  jns       @@CtrIncA6
@@CtrIncD6:
  movdqu    xmm0, [eax]
  movdqu    [esp + 112], xmm0
  mov       edx, 15
@@CtrIncA7:
  inc       byte ptr [eax + edx]
  jnz       @@CtrIncD7
  dec       edx
  jns       @@CtrIncA7
@@CtrIncD7:

  // ---- load raw counters, AES-encrypt (K_0 XOR happens inside) ----
  movdqu    xmm0, [esp + 0]
  movdqu    xmm1, [esp + 16]
  movdqu    xmm2, [esp + 32]
  movdqu    xmm3, [esp + 48]
  movdqu    xmm4, [esp + 64]
  movdqu    xmm5, [esp + 80]
  movdqu    xmm6, [esp + 96]
  movdqu    xmm7, [esp + 112]

{$I ..\..\..\Include\Simd\Aes\AesNiEightRoundsOnly_i386.inc}

  // ---- keystream ^ plaintext -> output. Spill ks7, use xmm7 as the plaintext
  //      scratch for blocks 0..6, then reload ks7 into the consumed xmm0 for 7.
  movdqu    [esp + 112], xmm7                     // spill ks7
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
  movdqu    xmm0, [esp + 112]                     // reload ks7 into consumed xmm0
  movdqu    xmm7, [ebx + 112]
  db $66, $0F, $EF, $F8                           // pxor xmm7, xmm0
  movdqu    [esi + 112], xmm7

  add       ebx, 128
  add       esi, 128
  sub       ecx, 8
  jnz       @@CtrEightLoopI386

  add       esp, 128
  pop       edi
  pop       esi
  pop       ebx
