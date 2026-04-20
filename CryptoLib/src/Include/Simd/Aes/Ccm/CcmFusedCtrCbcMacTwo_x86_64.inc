// CCM fused 2-wide AES-NI CTR+CBC-MAC kernel (x86_64).
// -------------------------------------------------------------------
// Mirrors OpenSSL's aesni_ccm64_encrypt_blocks / aesni_ccm64_decrypt_blocks
// (crypto/aes/asm/aesni-x86_64.pl:988-1187, Andy Polyakov / @dot-asm).
// Technique: Shay Gueron, "Intel AES New Instructions" white paper Rev 3.01.
//
// Two AES lanes issued per round-key broadcast, sharing the key load:
//   xmm0 = CTR lane   (counter -> keystream)
//   xmm1 = MAC lane   (CBC-MAC state; fed (M_prev XOR P_i) on each block)
// AES-NI aesenc has ~6-cycle latency but 1/cycle throughput, so the second
// aesenc issued on the same round key uses the pipeline slot that would
// otherwise idle. This is the only source of the CCM speedup; the inner
// body is intentionally NOT delegated to AesNiEightRoundsOnly (that would
// serialise the lanes and eat the win).
//
// On entry (after SimdProc1Begin_x86_64.inc): rcx = PCtx.
//
// Context layout (7 pointers + 1 count, natural 8-byte alignment, no
// padding). See TCcmFusedTwoCtx in ClpAesNiCcmKernel.pas.
//   [rcx +  0]  InPtr       : body blocks (plaintext on enc, ciphertext on dec)
//   [rcx +  8]  OutPtr      : body output buffer (may alias InPtr)
//   [rcx + 16]  Keys        : AES encrypt schedule (176/208/240 bytes for
//                             AES-128/192/256, 16-byte aligned)
//   [rcx + 24]  CtrState    : 16-byte CCM counter block in big-endian form
//                             (flags || nonce || counter_BE); read then
//                             overwritten with the post-body counter.
//   [rcx + 32]  MacState    : 16-byte running CBC-MAC state (post-header,
//                             in/out; overwritten with post-body state).
//   [rcx + 40]  PMask       : 16-byte PSHUFB full-reverse control
//                             (readonly): [15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0].
//                             Used to flip the BE counter to LE for paddq.
//   [rcx + 48]  PIncrement  : 16-byte CTR increment constant (readonly):
//                             [0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,1] = 1 in the
//                             LSB slot of a BE 128-bit integer, and also =
//                             1 in the low qword slot of an LE register
//                             after full byte-reverse; added via paddq.
//   [rcx + 56]  BlockCount  : NativeUInt; number of full 16-byte body blocks
//                             (MUST be >= 1; caller guarantees).
//
// XMM register allocation (x86_64; 9 of 16 registers used, no Win64 save):
//   xmm0        : CTR lane per-block (counter -> aesenc chain -> keystream)
//   xmm1        : MAC lane per-block. At iter start holds
//                 (M_prev XOR P_lag_prev XOR K_0) ready for the AES chain;
//                 at iter end holds the new running MAC state M_i.
//                 Across iterations xmm1 IS the running MAC state.
//   xmm2        : round-key scratch (reloaded per round via movdqa)
//   xmm3        : data-block cache. Encrypt: holds P_i for the keystream XOR.
//                 Decrypt: holds C_i for the keystream XOR.
//   xmm4        : CTR increment constant (loaded once from [rcx+48])
//   xmm5        : CTR-counter-LE scratch (transient during counter increment)
//   xmm6        : CTR counter in BE form (the canonical CCM counter). Loaded
//                 from [rcx+24] at entry, stored back at exit.
//   xmm7        : PSHUFB byte-reverse mask (loaded once from [rcx+40]).
//   xmm8        : (decrypt only) prev_P slot: P_{i-1} carried across iter
//                 boundaries so the next iteration can fold it into the MAC
//                 lane as (M_prev XOR P_{i-1}). Encoded with explicit REX
//                 bytes for Delphi-assembler compatibility.
//
// GPR usage (all MS x64 / SysV-volatile; no non-volatile saves needed):
//   rcx : PCtx (preserved across the kernel)
//   rax : InPtr (advancing)
//   rdx : OutPtr (advancing)
//   r8  : Keys base (alive across all rounds as the base of [r8 + 16*r])
//   r9  : scratch / CtrState pointer / MacState pointer at epilogue
//   r11 : BlockCount / loop counter (decrementing)
//
// Win64 ABI: xmm6..xmm15 are callee-save. This kernel is compiled as a
// leaf asm procedure (SimdProc1Begin_x86_64.inc emits nostackframe) and is
// only called from Pascal. Consistent with existing TOcbUtilities /
// TGcmUtilities kernels in this tree, which already treat xmm6..xmm15 as
// scratch in the same leaf-asm context.
//
// Direction : define CRYPTOLIB_CCM_DECRYPT for the decrypt variant (MAC
//             lags CTR by one block, trailing in-kernel scalar MAC fold
//             of P_{last}). Otherwise the encrypt variant is emitted.
// Key size  : define exactly ONE of CRYPTOLIB_AESNI_KEY128 /
//             CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256.
//
// Encoding: AES-NI instructions (aesenc / aesenclast) and instructions
// touching xmm8..xmm15 are db-encoded for broad assembler compatibility.
// The rest uses normal FPC mnemonics. REX prefix encoding used below:
//   $41 = REX.B=1            (source register in r/m field is xmm8..xmm15)
//   $44 = REX.R=1            (destination register is xmm8..xmm15)
//   $45 = REX.RB=1           (both dest and src are xmm8..xmm15)
// ModRM byte $C0+d*8+s where d, s are the low-3-bits of the register
// numbers (xmm8 encodes as 0 because REX.B/R supplies the top bit).
//
// -------------------------------------------------------------------
// Prologue: load pointers, persistent state, and entry counter.
// -------------------------------------------------------------------

  mov       rax, [rcx +  0]                         // rax = InPtr
  mov       rdx, [rcx +  8]                         // rdx = OutPtr
  mov       r8,  [rcx + 16]                         // r8  = Keys (base)
  mov       r11, [rcx + 56]                         // r11 = BlockCount

  // Persistent xmm state ------------------------------------------------
  mov       r9,  [rcx + 24]
  movdqu    xmm6, [r9]                              // xmm6 = CTR counter (BE)
  mov       r9,  [rcx + 32]
  movdqu    xmm1, [r9]                              // xmm1 = MAC state (running)
  mov       r9,  [rcx + 40]
  movdqu    xmm7, [r9]                              // xmm7 = byteswap mask
  mov       r9,  [rcx + 48]
  movdqu    xmm4, [r9]                              // xmm4 = CTR increment constant

{$IFNDEF CRYPTOLIB_CCM_DECRYPT}

// -------------------------------------------------------------------
// ENCRYPT direction: per-block interleaved CTR + MAC-on-plaintext.
//
// Loop invariant at .ccm_enc_loop head:
//   xmm1   = running MAC state M_{i-1}
//   xmm6   = CCM counter value for block i (BE form; will be encrypted)
//   rax    = &InPtr[i*16]
//   rdx    = &OutPtr[i*16]
//   r11    = remaining blocks (>= 1)
// -------------------------------------------------------------------

@@ccm_enc_loop:

  // Load P_i and fold into MAC lane. xmm3 keeps P_i for the post-AES
  // XOR with keystream to produce C_i.
  movdqu    xmm3, [rax]                             // xmm3 = P_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR P_i

  // CTR lane starts from the BE counter.
  movdqa    xmm0, xmm6                              // xmm0 = counter_i (BE)

  // Pre-whiten both lanes with K_0.
  movdqa    xmm2, [r8]                              // xmm2 = K_0
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  // -------------------- Middle rounds 1..N-1 -----------------------
  // Two aesenc per round, same round key, maximising AES-NI pipeline.
  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}

  // -------------------- Final round (aesenclast) -------------------
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0, xmm2  -> xmm0 = keystream_i
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> xmm1 = M_i (new MAC state)

  // -------------------- Produce ciphertext C_i ---------------------
  pxor      xmm0, xmm3                              // xmm0 = C_i = P_i XOR keystream
  movdqu    [rdx], xmm0                             // store C_i

  // -------------------- Advance counter, pointers ------------------
  pshufb    xmm6, xmm7                              // BE -> LE for paddq
  paddq     xmm6, xmm4                              // counter_LE += 1
  pshufb    xmm6, xmm7                              // LE -> BE

  add       rax, 16
  add       rdx, 16
  dec       r11
  jnz       @@ccm_enc_loop

{$ELSE} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// DECRYPT direction: MAC lags CTR by one block, in-kernel trailing
// scalar MAC AES on P_{last}.
//
// Pass 1  : CTR-only on block 0 (cold start; MAC lane idle).
// Pass 2  : if BlockCount > 1, BlockCount-1 interleaved iterations
//           where MAC-lane folds P_{i-1} while CTR-lane generates
//           keystream_i.
// Pass 3  : scalar MAC AES folding in the final P_{BlockCount-1}.
//
// Across passes: xmm8 carries prev_P = P_{i-1}; xmm1 carries the
// running MAC state.
// -------------------------------------------------------------------

  // -------------------- Pass 1: block 0 CTR-only -------------------
  // Encrypt counter_0 on the CTR lane (single-lane AES), XOR to get P_0,
  // stash P_0 into xmm8 as prev_P. MAC lane is idle because we don't
  // yet have plaintext to fold.

  movdqa    xmm0, xmm6                              // xmm0 = counter_0 (BE)
  movdqa    xmm2, [r8]
  pxor      xmm0, xmm2

  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0, xmm2  -> xmm0 = keystream_0

  movdqu    xmm3, [rax]                             // xmm3 = C_0
  pxor      xmm0, xmm3                              // xmm0 = P_0
  movdqu    [rdx], xmm0                             // store P_0

  // Stash P_0 into xmm8 = prev_P (db-encoded movdqa xmm8, xmm0).
  //   movdqa xmm8, xmm0  =>  66 44 0F 6F C0
  db $66, $44, $0F, $6F, $C0

  // Advance counter and pointers for the next pass.
  pshufb    xmm6, xmm7
  paddq     xmm6, xmm4
  pshufb    xmm6, xmm7

  add       rax, 16
  add       rdx, 16
  dec       r11
  jz        @@ccm_dec_trailing                     // BlockCount == 1: no interleaved loop

  // -------------------- Pass 2: interleaved iters 1..N-1 -----------
  // Loop invariant at .ccm_dec_loop head:
  //   xmm1  = running MAC state M_{i-1} (= M_0 at first entry)
  //   xmm8  = prev_P = P_{i-1}
  //   xmm6  = counter_i (BE)
  //   rax   = &InPtr[i*16]
  //   rdx   = &OutPtr[i*16]
  //   r11   = remaining blocks to process in this pass (>= 1)
@@ccm_dec_loop:

  movdqu    xmm3, [rax]                             // xmm3 = C_i

  // MAC lane input = M_{i-1} XOR prev_P, then pre-whiten with K_0.
  //   pxor xmm1, xmm8  =>  66 41 0F EF C8
  db $66, $41, $0F, $EF, $C8

  movdqa    xmm0, xmm6                              // xmm0 = counter_i

  movdqa    xmm2, [r8]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0, xmm2  -> xmm0 = keystream_i
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> xmm1 = M_i (MAC now
                                                    //          folded P_{i-1})

  // P_i = C_i XOR keystream_i.
  pxor      xmm0, xmm3                              // xmm0 = P_i
  movdqu    [rdx], xmm0                             // store P_i

  // Update prev_P = xmm8 <- P_i (xmm0). movdqa xmm8, xmm0 = 66 44 0F 6F C0
  db $66, $44, $0F, $6F, $C0

  // Advance counter, pointers.
  pshufb    xmm6, xmm7
  paddq     xmm6, xmm4
  pshufb    xmm6, xmm7

  add       rax, 16
  add       rdx, 16
  dec       r11
  jnz       @@ccm_dec_loop

@@ccm_dec_trailing:
  // -------------------- Pass 3: trailing MAC fold ------------------
  // Fold P_{last} (= xmm8 = prev_P) into the MAC state and run a
  // single-lane AES to produce the final MAC.
  //   pxor xmm1, xmm8  =>  66 41 0F EF C8
  db $66, $41, $0F, $EF, $C8

  movdqa    xmm2, [r8]
  pxor      xmm1, xmm2

  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> xmm1 = final MAC state

{$ENDIF} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// Epilogue: write back CtrState and MacState.
// -------------------------------------------------------------------

  mov       r9,  [rcx + 24]
  movdqu    [r9], xmm6                              // CtrState <- updated counter
  mov       r9,  [rcx + 32]
  movdqu    [r9], xmm1                              // MacState <- final MAC
