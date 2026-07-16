// AES-NI 8-wide CTR keystream + XOR, interleaved fused kernel (x86-64).
// -------------------------------------------------------------------
//
// Fused counter-mode body for TSicBlockCipher's bulk path: processes eight
// AES-CTR blocks per iteration, XORing the keystream with the input in one pass.
//
// Technique (Shay Gueron, "Intel AES New Instructions"): the eight cipher lanes
// live in xmm0..7 across the whole AES round chain, and the NEXT batch's eight
// counter blocks are materialised (to a 128-byte stack scratch) *interleaved
// between the aesenc rounds* of the current batch. The counter build is scalar
// (mov / bswap / xor on the integer ports) so it overlaps the aesenc
// throughput (vector port) instead of serialising ahead of it. The XOR with
// plaintext reuses xmm8 (the round-key scratch) after the final round.
//
// Counters are staged PRE-WHITENED: the K_0 XOR is folded into the scalar
// counter build. The whitened base block (counter ^ K_0) is written to all
// eight scratch slots once at entry; only the counter dword (bytes 12..15)
// changes between blocks, so each staged lane is a 4-byte patch of
// bswap(ctr32) ^ K_0.dword3. This removes the whole round-0 pxor pass from
// the AES port budget, and the round chain starts directly at K_1.
//
// Entry (after ClpSimdProc1Begin_x86_64.inc): rcx = pointer to TCtrFusedCtx. The
// kernel unpacks it (InPtr loaded into rcx last) into the working registers:
//   [rcx +  0]  InPtr      -> rcx : input  (advances +128 per 8-block iteration)
//   [rcx +  8]  OutPtr     -> rdx : output (advances +128)
//   [rcx + 16]  KeysPtr    -> r8  : AES encrypt round-key schedule (16-byte aligned)
//   [rcx + 24]  CounterPtr -> r9  : 16-byte big-endian counter (low dword updated in place)
//   [rcx + 32]  BlockCount -> r10 : positive multiple of 8 (caller guarantees it)
//
// Counter contract: the caller guarantees the low-32 counter dword does NOT
// wrap within the call (ctr32 + BlockCount <= 2^32) - TAesNiCtrKernel splits
// runs at the 2^32 boundary and propagates the carry into the upper 12 bytes
// in Pascal. The kernel therefore carries no in-loop carry logic and never
// touches counter bytes 0..11; only the low dword is stored back. The
// pipeline builds one batch ahead, so ebx over-runs by exactly 8 - undone
// (modulo 2^32) before write-back.
//
// Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 must be defined; the
// direction is always encrypt (CTR keystream), so CRYPTOLIB_AESNI_DECRYPT must
// NOT be defined when including this file.
//
// Register/stack notes: rbx is callee-saved (push/pop); ebx = counter low dword
// native-LE, r11d = K_0.dword3 (whitening constant), rax = staging scratch.
// xmm6-15 are saved once via the shared core (xmm8 is the round-key /
// plaintext-XOR scratch). A 128-byte stack scratch below the xmm save area
// holds the next batch's pre-whitened counter blocks. AES-NI instructions and
// pxor forms touching xmm8 are db-encoded for broad assembler compatibility.
  push      rbx
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  sub       rsp, 128                              // next-batch counter scratch: [rsp+0..127]

  // ---- unpack TCtrFusedCtx (rcx = PCtx); load InPtr into rcx last ----
  mov       r8, [rcx + 16]                        // KeysPtr
  mov       r9, [rcx + 24]                        // CounterPtr
  mov       r10, [rcx + 32]                       // BlockCount
  mov       rdx, [rcx + 8]                        // OutPtr
  mov       rcx, [rcx + 0]                        // InPtr (overwrites PCtx)

  // ---- whitened base block (counter ^ K_0) into all 8 scratch slots ----
  movdqu    xmm0, [r9]                            // counter block
  movdqa    xmm8, [r8]                            // K_0
  db $66, $41, $0F, $EF, $C0                      // pxor xmm0, xmm8
  movdqu    [rsp], xmm0
  movdqu    [rsp + 16], xmm0
  movdqu    [rsp + 32], xmm0
  movdqu    [rsp + 48], xmm0
  movdqu    [rsp + 64], xmm0
  movdqu    [rsp + 80], xmm0
  movdqu    [rsp + 96], xmm0
  movdqu    [rsp + 112], xmm0

  mov       ebx, [r9 + 12]                        // counter low dword (big-endian in memory)
  bswap     ebx                                   // native-LE in ebx
  mov       r11d, [r8 + 12]                       // K_0.dword3 whitening constant

  // ---- stage batch 0: patch the whitened counter dword of each slot ----
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 12], eax
  add       ebx, 1
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 28], eax
  add       ebx, 1
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 44], eax
  add       ebx, 1
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 60], eax
  add       ebx, 1
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 76], eax
  add       ebx, 1
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 92], eax
  add       ebx, 1
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 108], eax
  add       ebx, 1
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 124], eax
  add       ebx, 1

  movdqu    xmm0, [rsp]
  movdqu    xmm1, [rsp + 16]
  movdqu    xmm2, [rsp + 32]
  movdqu    xmm3, [rsp + 48]
  movdqu    xmm4, [rsp + 64]
  movdqu    xmm5, [rsp + 80]
  movdqu    xmm6, [rsp + 96]
  movdqu    xmm7, [rsp + 112]

@@CtrEightLoop:
  // ---- rounds 1..8: aesenc (lanes are pre-whitened), each interleaved with
  //      staging one next pre-whitened counter dword ----
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 12], eax
  add       ebx, 1

  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 28], eax
  add       ebx, 1

  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 44], eax
  add       ebx, 1

  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 60], eax
  add       ebx, 1

  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 76], eax
  add       ebx, 1

  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 92], eax
  add       ebx, 1

  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 108], eax
  add       ebx, 1

  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  mov       eax, ebx
  bswap     eax
  xor       eax, r11d
  mov       [rsp + 124], eax
  add       ebx, 1

  // ---- round 9 (all key sizes): aesenc, no more staging ----
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8

{$IF DEFINED(CRYPTOLIB_AESNI_KEY192) OR DEFINED(CRYPTOLIB_AESNI_KEY256)}
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
{$IFEND}

{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DC, $C0                 // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8                 // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0                 // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8                 // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0                 // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8                 // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0                 // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8                 // aesenc xmm7, xmm8
{$ENDIF}

  // ---- final round: aesenclast on the last round key ----
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm8, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm8, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm8, [r8 + 224]
{$ENDIF}
  db $66, $41, $0F, $38, $DD, $C0                 // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8                 // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0                 // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8                 // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0                 // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8                 // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0                 // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8                 // aesenclast xmm7, xmm8

  // ---- keystream ^ plaintext -> output (xmm8 = unaligned plaintext load) ----
  movdqu    xmm8, [rcx]
  db $66, $41, $0F, $EF, $C0                      // pxor xmm0, xmm8
  movdqu    [rdx], xmm0
  movdqu    xmm8, [rcx + 16]
  db $66, $41, $0F, $EF, $C8                      // pxor xmm1, xmm8
  movdqu    [rdx + 16], xmm1
  movdqu    xmm8, [rcx + 32]
  db $66, $41, $0F, $EF, $D0                      // pxor xmm2, xmm8
  movdqu    [rdx + 32], xmm2
  movdqu    xmm8, [rcx + 48]
  db $66, $41, $0F, $EF, $D8                      // pxor xmm3, xmm8
  movdqu    [rdx + 48], xmm3
  movdqu    xmm8, [rcx + 64]
  db $66, $41, $0F, $EF, $E0                      // pxor xmm4, xmm8
  movdqu    [rdx + 64], xmm4
  movdqu    xmm8, [rcx + 80]
  db $66, $41, $0F, $EF, $E8                      // pxor xmm5, xmm8
  movdqu    [rdx + 80], xmm5
  movdqu    xmm8, [rcx + 96]
  db $66, $41, $0F, $EF, $F0                      // pxor xmm6, xmm8
  movdqu    [rdx + 96], xmm6
  movdqu    xmm8, [rcx + 112]
  db $66, $41, $0F, $EF, $F8                      // pxor xmm7, xmm8
  movdqu    [rdx + 112], xmm7

  // ---- load the staged next-batch pre-whitened counters into xmm0..7 ----
  movdqu    xmm0, [rsp]
  movdqu    xmm1, [rsp + 16]
  movdqu    xmm2, [rsp + 32]
  movdqu    xmm3, [rsp + 48]
  movdqu    xmm4, [rsp + 64]
  movdqu    xmm5, [rsp + 80]
  movdqu    xmm6, [rsp + 96]
  movdqu    xmm7, [rsp + 112]

  add       rcx, 128
  add       rdx, 128
  sub       r10, 8
  jnz       @@CtrEightLoop

  // ---- undo the one-batch build-ahead (mod 2^32; no carry by contract),
  //      write the low counter dword back big-endian ----
  sub       ebx, 8
  bswap     ebx
  mov       [r9 + 12], ebx

  add       rsp, 128
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
  pop       rbx
