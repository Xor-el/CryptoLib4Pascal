// AES-NI 1-wide CBC encryption, serial in-register chain kernel (x86-64).
// -------------------------------------------------------------------
//
// Fused CBC-encrypt body for TCbcBlockCipher's bulk path: C_i = E_K(P_i xor
// C_{i-1}), the serial chaining mode. CBC encrypt cannot be block-parallelised
// (each block needs the previous block's ciphertext), so the win here is purely
// in orchestration: the chaining value lives in xmm1 across the whole run -- no
// per-block store/reload, no XOR helper call, no per-block dispatch/validation.
//
// The AES rounds reuse the shared 1-wide chain (AesNiOneRoundsOnly_x86_64.inc),
// which consumes round keys as [r8 + K] memory operands and touches only xmm0.
// Every working register (rcx,rdx,r8,r9,r10,r11,xmm0,xmm1) is volatile on the
// MS x64 ABI, so this stays a true leaf: no xmm6-15 save, no callee-saved push.
//
// Entry (after ClpSimdProc1Begin_x86_64.inc): rcx = pointer to TCbcEncryptFusedCtx.
// The kernel unpacks it (InPtr loaded into r11):
//   [rcx +  0]  InPtr      -> r11 : input  (advances +16 per block)
//   [rcx +  8]  OutPtr     -> rdx : output (advances +16)
//   [rcx + 16]  KeysPtr    -> r8  : AES encrypt round-key schedule ([r8 + K])
//   [rcx + 24]  IvPtr      -> r9  : 16-byte chaining value (seed + writeback)
//   [rcx + 32]  BlockCount -> r10 : number of blocks, caller guarantees >= 1
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt, so CRYPTOLIB_AESNI_DECRYPT must NOT be defined.
//
// AES-NI instructions and the register pxor forms are db-encoded for broad
// assembler compatibility.
  // ---- unpack TCbcEncryptFusedCtx (rcx = PCtx); load InPtr into r11 last ----
  mov       r8,  [rcx + 16]                       // KeysPtr
  mov       r9,  [rcx + 24]                       // IvPtr
  mov       r10, [rcx + 32]                       // BlockCount
  mov       rdx, [rcx + 8]                        // OutPtr
  mov       r11, [rcx + 0]                        // InPtr

  movdqu    xmm1, [r9]                            // chain = C_{-1} (the IV)

@@CbcEncryptSerialLoop:
  movdqu    xmm0, [r11]                           // P_i
  db $66, $0F, $EF, $C1                           // pxor xmm0, xmm1  (P_i xor chain)
{$I ..\..\..\Include\Simd\Aes\AesNiOneRoundsOnly_x86_64.inc} // xmm0 = E_K(xmm0)
  movdqu    [rdx], xmm0                           // C_i
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0  (chain = C_i)
  add       r11, 16
  add       rdx, 16
  sub       r10, 1
  jnz       @@CbcEncryptSerialLoop

  movdqu    [r9], xmm1                            // write final chain (= last C) back
  db $66, $0F, $EF, $C0                           // pxor xmm0, xmm0  (scrub)
  db $66, $0F, $EF, $C9                           // pxor xmm1, xmm1  (scrub)
