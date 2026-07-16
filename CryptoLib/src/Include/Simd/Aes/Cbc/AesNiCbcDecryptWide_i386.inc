// AES-NI CBC decryption, parallel 4-wide + fused chain XOR kernel (i386).
// -------------------------------------------------------------------
//
// i386 counterpart of AesNiCbcDecryptWide_x86_64.inc: P_i = D_K(C_i) xor
// C_{i-1} (C_{-1} = IV). The D_K(C_i) are independent, so blocks run through
// an embedded aesdec chain in parallel; the trailing XOR (fed by input
// ciphertext) folds into the same pass, replacing the mode's decrypt-then-XOR
// two passes with one. i386 has only xmm0..7 (all volatile) and the embedded
// 4-wide chain (matching the width-4 chain in AesNiCipher_i386.inc) uses
// xmm4 as its round-key register, so the batch is 4 blocks: xmm0..3 = data, xmm4 =
// feedback reload scratch (free once the chain completes), xmm5 =
// chaining value (persists across groups). An embedded 1-wide tail chain
// drains 1..3 residual blocks; the kernel accepts any block count >= 1.
//
// In-place safe: within each 4-block group every input read (4 block loads +
// 3 feedback reloads + the next chain seed) precedes the first output store,
// so OutPtr may alias InPtr.
//
// Entry (after ClpSimdProc1Begin_i386.inc): ebx = pointer to
// TCbcFusedCtx. The kernel pushes esi/edi and unpacks the record:
//   [ebx +  0]  InPtr      -> esi : input  (advances +16 per block)
//   [ebx +  4]  OutPtr     -> edx : output (advances +16; may alias InPtr)
//   [ebx +  8]  KeysPtr    -> edi : AES *decrypt* (inverse-MixColumns) schedule
//   [ebx + 12]  IvPtr            : 16-byte chaining value (seed + writeback)
//   [ebx + 16]  BlockCount -> ecx : number of blocks, caller guarantees >= 1
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined;
// the embedded chains are always the decrypt direction (aesdec over the
// inverse-MixColumns schedule).
//
// AES-NI instructions and register pxor/movdqa forms are db-encoded for broad
// assembler compatibility.
  // ---- unpack TCbcFusedCtx (ebx = PCtx) ----
  push      esi
  push      edi
  mov       esi, [ebx + 0]                        // InPtr
  mov       edx, [ebx + 4]                        // OutPtr
  mov       edi, [ebx + 8]                        // KeysPtr (decrypt schedule)
  mov       ecx, [ebx + 16]                       // BlockCount
  mov       eax, [ebx + 12]                       // IvPtr
  movdqu    xmm5, [eax]                           // chain = C_{-1} (the IV)

  cmp       ecx, 4
  jb        @@CbcDecTailI386

@@CbcDecWideI386:
  movdqu    xmm0, [esi +  0]                      // C_0 .. C_3
  movdqu    xmm1, [esi + 16]
  movdqu    xmm2, [esi + 32]
  movdqu    xmm3, [esi + 48]
  // xmm0..3 = D_K(C_i): embedded 4-wide decrypt round chain
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DF, $C4   // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC   // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4   // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC   // aesdeclast xmm3, xmm4
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 176]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 192]
  db $66, $0F, $38, $DF, $C4   // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC   // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4   // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC   // aesdeclast xmm3, xmm4
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm4, [edi]
  db $66, $0F, $EF, $C4   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC   // pxor xmm3, xmm4
  movdqa    xmm4, [edi + 16]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 32]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 48]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 64]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 80]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 96]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 112]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 128]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 144]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 160]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 176]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 192]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 208]
  db $66, $0F, $38, $DE, $C4   // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC   // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4   // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC   // aesdec xmm3, xmm4
  movdqa    xmm4, [edi + 224]
  db $66, $0F, $38, $DF, $C4   // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC   // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4   // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC   // aesdeclast xmm3, xmm4
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
  // feedback: P_i = D_K(C_i) xor C_{i-1}. C_0..C_2 reloaded from the (still
  // intact) input; block 0 uses the running chain. All reads precede stores.
  movdqu    xmm4, [esi +  0]
  db $66, $0F, $EF, $CC                           // pxor xmm1, xmm4  (^ C_0)
  movdqu    xmm4, [esi + 16]
  db $66, $0F, $EF, $D4                           // pxor xmm2, xmm4  (^ C_1)
  movdqu    xmm4, [esi + 32]
  db $66, $0F, $EF, $DC                           // pxor xmm3, xmm4  (^ C_2)
  db $66, $0F, $EF, $C5                           // pxor xmm0, xmm5  (^ chain = C_{-1})
  movdqu    xmm5, [esi + 48]                      // next chain = C_3 (before any store)
  movdqu    [edx +  0], xmm0                      // P_0 .. P_3
  movdqu    [edx + 16], xmm1
  movdqu    [edx + 32], xmm2
  movdqu    [edx + 48], xmm3
  add       esi, 64
  add       edx, 64
  sub       ecx, 4
  cmp       ecx, 4
  jae       @@CbcDecWideI386

@@CbcDecTailI386:
  test      ecx, ecx
  jz        @@CbcDecDoneI386
@@CbcDecTailLoopI386:
  movdqu    xmm0, [esi]                           // C_i
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0  (save C_i)
  // xmm0 = D_K(C_i): embedded 1-wide decrypt round chain
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DF, $87, $A0, $00, $00, $00   // aesdeclast xmm0, [edi+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00   // aesdec xmm0, [edi+160]
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00   // aesdec xmm0, [edi+176]
  db $66, $0F, $38, $DF, $87, $C0, $00, $00, $00   // aesdeclast xmm0, [edi+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00   // aesdec xmm0, [edi+160]
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00   // aesdec xmm0, [edi+176]
  db $66, $0F, $38, $DE, $87, $C0, $00, $00, $00   // aesdec xmm0, [edi+192]
  db $66, $0F, $38, $DE, $87, $D0, $00, $00, $00   // aesdec xmm0, [edi+208]
  db $66, $0F, $38, $DF, $87, $E0, $00, $00, $00   // aesdeclast xmm0, [edi+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
  db $66, $0F, $EF, $C5                           // pxor xmm0, xmm5   (^ chain)
  db $66, $0F, $6F, $E9                           // movdqa xmm5, xmm1 (chain = C_i)
  movdqu    [edx], xmm0                           // P_i
  add       esi, 16
  add       edx, 16
  sub       ecx, 1
  jnz       @@CbcDecTailLoopI386

@@CbcDecDoneI386:
  mov       eax, [ebx + 12]                       // IvPtr
  movdqu    [eax], xmm5                           // write final chain (= last C) back
  db $66, $0F, $EF, $C0                           // pxor xmm0, xmm0  (scrub last plaintext)
  db $66, $0F, $EF, $ED                           // pxor xmm5, xmm5  (scrub chain)

  pop       edi
  pop       esi
  pop       ebx
