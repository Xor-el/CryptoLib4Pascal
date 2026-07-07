// AES-NI 1-wide CBC encryption, serial in-register chain kernel (i386).
// -------------------------------------------------------------------
//
// i386 counterpart of AesNiCbcEncryptSerial_x86_64.inc: C_i = E_K(P_i xor C_{i-1}),
// the serial CBC chaining mode, for TCbcBlockCipher's bulk path. CBC encrypt is
// inherently serial, so the win is orchestration only: the chaining value stays
// in xmm1 across the whole run -- no per-block store/reload, no XOR helper call,
// no per-block dispatch/validation.
//
// The AES rounds reuse the shared 1-wide chain (AesNiOneRoundsOnly_i386.inc),
// which consumes round keys as [edi + K] memory operands and touches only xmm0.
// i386 has only xmm0..7 (all volatile); the chain uses xmm1. ebx (pushed by the
// prologue), esi and edi are callee-saved and restored before return.
//
// Entry (after SimdProc1Begin_i386.inc): ebx = pointer to TCbcEncryptFusedCtx. The
// kernel pushes esi/edi and unpacks the record:
//   [ebx +  0]  InPtr      -> esi : input  (advances +16 per block)
//   [ebx +  4]  OutPtr     -> edx : output (advances +16)
//   [ebx +  8]  KeysPtr    -> edi : AES round-key schedule ([edi + K])
//   [ebx + 12]  IvPtr      -> eax : 16-byte chaining value (seed + writeback)
//   [ebx + 16]  BlockCount -> ecx : number of blocks, caller guarantees >= 1
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt, so CRYPTOLIB_AESNI_DECRYPT must NOT be defined.
//
// AES-NI instructions and the register pxor forms are db-encoded for broad
// assembler compatibility.
  // ---- unpack TCbcEncryptFusedCtx (ebx = PCtx) ----
  push      esi
  push      edi
  mov       esi, [ebx + 0]                        // InPtr
  mov       edx, [ebx + 4]                        // OutPtr
  mov       edi, [ebx + 8]                        // KeysPtr
  mov       eax, [ebx + 12]                       // IvPtr
  mov       ecx, [ebx + 16]                       // BlockCount

  movdqu    xmm1, [eax]                           // chain = C_{-1} (the IV)

@@CbcEncryptSerialLoopI386:
  movdqu    xmm0, [esi]                           // P_i
  db $66, $0F, $EF, $C1                           // pxor xmm0, xmm1  (P_i xor chain)
{$I ..\..\..\Include\Simd\Aes\AesNiOneRoundsOnly_i386.inc} // xmm0 = E_K(xmm0)
  movdqu    [edx], xmm0                           // C_i
  db $66, $0F, $6F, $C8                           // movdqa xmm1, xmm0  (chain = C_i)
  add       esi, 16
  add       edx, 16
  sub       ecx, 1
  jnz       @@CbcEncryptSerialLoopI386

  movdqu    [eax], xmm1                           // write final chain (= last C) back
  db $66, $0F, $EF, $C0                           // pxor xmm0, xmm0  (scrub)
  db $66, $0F, $EF, $C9                           // pxor xmm1, xmm1  (scrub)

  pop       edi
  pop       esi
  pop       ebx
