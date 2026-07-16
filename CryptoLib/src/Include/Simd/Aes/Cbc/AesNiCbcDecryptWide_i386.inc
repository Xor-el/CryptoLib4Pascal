// AES-NI CBC decryption, parallel 4-wide + fused chain XOR kernel (i386).
// -------------------------------------------------------------------
//
// i386 counterpart of AesNiCbcDecryptWide_x86_64.inc: P_i = D_K(C_i) xor
// C_{i-1} (C_{-1} = IV). The D_K(C_i) are independent, so blocks run through
// the shared aesdec chain in parallel; the trailing XOR (fed by input
// ciphertext) folds into the same pass, replacing the mode's decrypt-then-XOR
// two passes with one. i386 has only xmm0..7 (all volatile) and the shared
// 4-wide chain (AesNiCipher_i386.inc under CRYPTOLIB_AESNI_ROUNDS_ONLY) uses
// xmm4 as its round-key register, so the batch is 4 blocks: xmm0..3 = data,
// xmm4 = feedback reload scratch (free once the chain returns), xmm5 =
// chaining value (persists across groups). A 1-wide rounds-only tail drains
// 1..3 residual blocks; the kernel accepts any block count >= 1.
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
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined,
// together with CRYPTOLIB_AESNI_DECRYPT (selects aesdec in the shared chains).
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
{$DEFINE CRYPTOLIB_AESNI_ROUNDS_ONLY}
{$DEFINE CRYPTOLIB_AESNI_FOUR}
{$I ..\..\..\Include\Simd\Aes\AesNiCipher_i386.inc}            // xmm0..3 = D_K(C_i)
{$UNDEF CRYPTOLIB_AESNI_FOUR}
{$UNDEF CRYPTOLIB_AESNI_ROUNDS_ONLY}
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
{$DEFINE CRYPTOLIB_AESNI_ROUNDS_ONLY}
{$DEFINE CRYPTOLIB_AESNI_ONE}
{$I ..\..\..\Include\Simd\Aes\AesNiCipher_i386.inc}            // xmm0 = D_K(C_i)
{$UNDEF CRYPTOLIB_AESNI_ONE}
{$UNDEF CRYPTOLIB_AESNI_ROUNDS_ONLY}
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
