// AES-NI 1-wide CBC encryption, serial in-register chain kernel (x86-64).
// -------------------------------------------------------------------
//
// Fused CBC-encrypt body for TCbcBlockCipher's bulk path: C_i = E_K(P_i xor
// C_{i-1}), the serial chaining mode. CBC encrypt cannot be block-parallelised
// (each block needs the previous block's ciphertext), so the win here is purely
// in orchestration: the chaining value lives in xmm1 across the whole run -- no
// per-block store/reload, no XOR helper call, no per-block dispatch/validation.
//
// The AES rounds are an embedded 1-wide chain, matching the width-1 chain
// in AesNiCipher_x86_64.inc: round keys are consumed as [r8 + K] memory
// operands and only xmm0 is touched.
// Every working register (rcx,rdx,r8,r9,r10,r11,xmm0,xmm1) is volatile on the
// MS x64 ABI, so this stays a true leaf: no xmm6-15 save, no callee-saved push.
//
// Entry (after ClpSimdProc1Begin_x86_64.inc): rcx = pointer to TCbcFusedCtx.
// The kernel unpacks it (InPtr loaded into r11):
//   [rcx +  0]  InPtr      -> r11 : input  (advances +16 per block)
//   [rcx +  8]  OutPtr     -> rdx : output (advances +16)
//   [rcx + 16]  KeysPtr    -> r8  : AES encrypt round-key schedule ([r8 + K])
//   [rcx + 24]  IvPtr      -> r9  : 16-byte chaining value (seed + writeback)
//   [rcx + 32]  BlockCount -> r10 : number of blocks, caller guarantees >= 1
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined;
// the embedded chain is always the encrypt direction.
//
// AES-NI instructions and the register pxor forms are db-encoded for broad
// assembler compatibility.
  // ---- unpack TCbcFusedCtx (rcx = PCtx); load InPtr into r11 last ----
  mov       r8,  [rcx + 16]                       // KeysPtr
  mov       r9,  [rcx + 24]                       // IvPtr
  mov       r10, [rcx + 32]                       // BlockCount
  mov       rdx, [rcx + 8]                        // OutPtr
  mov       r11, [rcx + 0]                        // InPtr

  movdqu    xmm1, [r9]                            // chain = C_{-1} (the IV)

@@CbcEncryptSerialLoop:
  movdqu    xmm0, [r11]                           // P_i
  db $66, $0F, $EF, $C1                           // pxor xmm0, xmm1  (P_i xor chain)
  // xmm0 = E_K(xmm0): embedded 1-wide encrypt round chain
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DD, $80, $A0, $00, $00, $00 // aesenclast xmm0, [r8+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DC, $80, $A0, $00, $00, $00 // aesenc xmm0, [r8+160]
  db $66, $41, $0F, $38, $DC, $80, $B0, $00, $00, $00 // aesenc xmm0, [r8+176]
  db $66, $41, $0F, $38, $DD, $80, $C0, $00, $00, $00 // aesenclast xmm0, [r8+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DC, $80, $A0, $00, $00, $00 // aesenc xmm0, [r8+160]
  db $66, $41, $0F, $38, $DC, $80, $B0, $00, $00, $00 // aesenc xmm0, [r8+176]
  db $66, $41, $0F, $38, $DC, $80, $C0, $00, $00, $00 // aesenc xmm0, [r8+192]
  db $66, $41, $0F, $38, $DC, $80, $D0, $00, $00, $00 // aesenc xmm0, [r8+208]
  db $66, $41, $0F, $38, $DD, $80, $E0, $00, $00, $00 // aesenclast xmm0, [r8+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
  movdqu    [rdx], xmm0                           // C_i
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0  (chain = C_i)
  add       r11, 16
  add       rdx, 16
  sub       r10, 1
  jnz       @@CbcEncryptSerialLoop

  movdqu    [r9], xmm1                            // write final chain (= last C) back
  db $66, $0F, $EF, $C0                           // pxor xmm0, xmm0  (scrub)
  db $66, $0F, $EF, $C9                           // pxor xmm1, xmm1  (scrub)
