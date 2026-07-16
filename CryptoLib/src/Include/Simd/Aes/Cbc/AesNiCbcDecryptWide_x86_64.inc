// AES-NI CBC decryption, parallel 8-wide + fused chain XOR kernel (x86-64).
// -------------------------------------------------------------------
//
// Fused CBC-decrypt body for TCbcBlockCipher's bulk path:
//   P_i = D_K(C_i) xor C_{i-1}   (C_{-1} = IV).
// Unlike CBC encrypt, the D_K(C_i) are mutually independent, so 8 blocks
// run through the shared 8-wide aesdec chain (AesNiCipher_x86_64.inc under
// CRYPTOLIB_AESNI_ROUNDS_ONLY); the only serial part is the trailing XOR, and
// every feed is an *input* ciphertext block. Folding that XOR into the decrypt
// pass turns the mode's decrypt-then-XOR (two passes over memory) into a
// single pass. A 1-wide rounds-only tail drains the 1..7 residual blocks, so
// the kernel accepts any block count >= 1.
//
// In-place safe: within each 8-block group every input read (8 block loads +
// 7 feedback reloads + the next chain seed) completes before the first output
// store, so OutPtr may alias InPtr.
//
// Entry (after ClpSimdProc1Begin_x86_64.inc): rcx = pointer to
// TCbcFusedCtx. The kernel unpacks it (InPtr loaded into r11 last):
//   [rcx +  0]  InPtr      -> r11 : input  (advances +16 per block)
//   [rcx +  8]  OutPtr     -> rdx : output (advances +16; may alias InPtr)
//   [rcx + 16]  KeysPtr    -> r8  : AES *decrypt* (inverse-MixColumns) schedule
//   [rcx + 24]  IvPtr      -> r9  : 16-byte chaining value (seed + writeback)
//   [rcx + 32]  BlockCount -> r10 : number of blocks, caller guarantees >= 1
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined,
// together with CRYPTOLIB_AESNI_DECRYPT (selects aesdec in the shared chains).
//
// XMM: xmm0..xmm7 = 8 data lanes; xmm8 = shared round-key scratch (owned by
// the 8-wide rounds-only chain); xmm9 = chaining value (persists across groups);
// xmm10 = feedback reload scratch. xmm6..xmm10 are nonvolatile on Win64, so
// the ClpSimdNonVolatile{Save,Restore} frame brackets the body.
//
// AES-NI instructions and pxor/movdqa forms touching xmm8..xmm15 are
// db-encoded for broad assembler compatibility.
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  // ---- unpack TCbcFusedCtx (rcx = PCtx); load InPtr into r11 last ----
  mov       r8,  [rcx + 16]                      // KeysPtr (decrypt schedule)
  mov       r9,  [rcx + 24]                      // IvPtr
  mov       r10, [rcx + 32]                      // BlockCount
  mov       rdx, [rcx + 8]                       // OutPtr
  mov       r11, [rcx + 0]                       // InPtr

  movdqu    xmm9, [r9]                            // chain = C_{-1} (the IV)

  cmp       r10, 8
  jb        @@CbcDecTail

@@CbcDecWide:
  movdqu    xmm0, [r11 +   0]                     // C_0 .. C_7
  movdqu    xmm1, [r11 +  16]
  movdqu    xmm2, [r11 +  32]
  movdqu    xmm3, [r11 +  48]
  movdqu    xmm4, [r11 +  64]
  movdqu    xmm5, [r11 +  80]
  movdqu    xmm6, [r11 +  96]
  movdqu    xmm7, [r11 + 112]
{$DEFINE CRYPTOLIB_AESNI_ROUNDS_ONLY}
{$DEFINE CRYPTOLIB_AESNI_EIGHT}
{$I ..\..\..\Include\Simd\Aes\AesNiCipher_x86_64.inc}          // xmm0..7 = D_K(C_i)
{$UNDEF CRYPTOLIB_AESNI_EIGHT}
{$UNDEF CRYPTOLIB_AESNI_ROUNDS_ONLY}
  // feedback: P_i = D_K(C_i) xor C_{i-1}. C_0..C_6 reloaded from the (still
  // intact) input; block 0 uses the running chain. All reads precede stores.
  movdqu    xmm10, [r11 +   0]
  db $66, $41, $0F, $EF, $CA                      // pxor xmm1, xmm10  (^ C_0)
  movdqu    xmm10, [r11 +  16]
  db $66, $41, $0F, $EF, $D2                      // pxor xmm2, xmm10  (^ C_1)
  movdqu    xmm10, [r11 +  32]
  db $66, $41, $0F, $EF, $DA                      // pxor xmm3, xmm10  (^ C_2)
  movdqu    xmm10, [r11 +  48]
  db $66, $41, $0F, $EF, $E2                      // pxor xmm4, xmm10  (^ C_3)
  movdqu    xmm10, [r11 +  64]
  db $66, $41, $0F, $EF, $EA                      // pxor xmm5, xmm10  (^ C_4)
  movdqu    xmm10, [r11 +  80]
  db $66, $41, $0F, $EF, $F2                      // pxor xmm6, xmm10  (^ C_5)
  movdqu    xmm10, [r11 +  96]
  db $66, $41, $0F, $EF, $FA                      // pxor xmm7, xmm10  (^ C_6)
  db $66, $41, $0F, $EF, $C1                      // pxor xmm0, xmm9   (^ chain = C_{-1})
  movdqu    xmm9, [r11 + 112]                     // next chain = C_7 (before any store)
  movdqu    [rdx +   0], xmm0                     // P_0 .. P_7
  movdqu    [rdx +  16], xmm1
  movdqu    [rdx +  32], xmm2
  movdqu    [rdx +  48], xmm3
  movdqu    [rdx +  64], xmm4
  movdqu    [rdx +  80], xmm5
  movdqu    [rdx +  96], xmm6
  movdqu    [rdx + 112], xmm7
  add       r11, 128
  add       rdx, 128
  sub       r10, 8
  cmp       r10, 8
  jae       @@CbcDecWide

@@CbcDecTail:
  test      r10, r10
  jz        @@CbcDecDone
@@CbcDecTailLoop:
  movdqu    xmm0, [r11]                           // C_i
  db $66, $44, $0F, $6F, $D0                      // movdqa xmm10, xmm0  (save C_i)
{$DEFINE CRYPTOLIB_AESNI_ROUNDS_ONLY}
{$DEFINE CRYPTOLIB_AESNI_ONE}
{$I ..\..\..\Include\Simd\Aes\AesNiCipher_x86_64.inc}          // xmm0 = D_K(C_i)
{$UNDEF CRYPTOLIB_AESNI_ONE}
{$UNDEF CRYPTOLIB_AESNI_ROUNDS_ONLY}
  db $66, $41, $0F, $EF, $C1                      // pxor xmm0, xmm9    (^ chain)
  db $66, $45, $0F, $6F, $CA                      // movdqa xmm9, xmm10 (chain = C_i)
  movdqu    [rdx], xmm0                           // P_i
  add       r11, 16
  add       rdx, 16
  sub       r10, 1
  jnz       @@CbcDecTailLoop

@@CbcDecDone:
  movdqu    [r9], xmm9                            // write final chain (= last C) back
  db $66, $0F, $EF, $C0                           // pxor xmm0, xmm0  (scrub last plaintext)
  db $66, $0F, $EF, $C9                           // pxor xmm1, xmm1  (scrub)
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
