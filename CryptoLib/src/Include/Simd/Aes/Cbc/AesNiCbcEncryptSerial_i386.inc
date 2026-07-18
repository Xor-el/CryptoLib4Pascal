// AES-NI 1-wide CBC encryption, serial in-register chain kernel (i386).
// -------------------------------------------------------------------
//
// i386 counterpart of AesNiCbcEncryptSerial_x86_64.inc: C_i = E_K(P_i xor C_{i-1}),
// the serial CBC chaining mode, for TCbcBlockCipher's bulk path. CBC encrypt is
// inherently serial, so the win is orchestration only: the chaining value stays
// in xmm1 across the whole run -- no per-block store/reload, no XOR helper call,
// no per-block dispatch/validation.
//
// The AES rounds are an embedded 1-wide chain, matching the width-1 chain
// in AesNiCipher_i386.inc: round keys are consumed as [edi + K] memory
// operands and only xmm0 is touched.
// i386 has only xmm0..7 (all volatile); the chain uses xmm1. ebx (pushed by the
// prologue), esi and edi are callee-saved and restored before return.
//
// Entry (after ClpSimdProc1Begin_i386.inc): ebx = pointer to TCbcFusedCtx. The
// kernel pushes esi/edi and unpacks the record:
//   [ebx +  0]  InPtr      -> esi : input  (advances +16 per block)
//   [ebx +  4]  OutPtr     -> edx : output (advances +16)
//   [ebx +  8]  KeysPtr    -> edi : AES round-key schedule ([edi + K])
//   [ebx + 12]  IvPtr      -> eax : 16-byte chaining value (seed + writeback)
//   [ebx + 16]  BlockCount -> ecx : number of blocks, caller guarantees >= 1
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined;
// the embedded chain is always the encrypt direction.
//
// AES-NI instructions and the register pxor forms are db-encoded for broad
// assembler compatibility.
  // ---- unpack TCbcFusedCtx (ebx = PCtx) ----
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
  // xmm0 = E_K(xmm0): embedded 1-wide encrypt round chain
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+192]
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+208]
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
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
