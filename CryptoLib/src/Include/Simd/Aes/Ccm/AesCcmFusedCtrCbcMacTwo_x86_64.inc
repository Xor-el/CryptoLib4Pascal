// CCM fused AES-NI CTR+CBC-MAC kernel (x86_64).
// -------------------------------------------------------------------
// Inspired by OpenSSL aesni_ccm64_{encrypt,decrypt}_blocks
// (crypto/aes/asm/aesni-x86_64.pl, Andy Polyakov / @dot-asm).
// Technique: Shay Gueron, "Intel AES New Instructions" Rev 3.01.
//
// Two lanes (CTR / MAC) share each round-key broadcast. Issuing a
// second aesenc on the same round key uses the pipeline slot that
// would otherwise idle (aesenc on modern Intel/Zen: ~4c latency,
// 1/cycle throughput). That is the structural source of the CCM
// speed-up. Going wider than 2 lanes cannot beat the CBC-MAC serial
// chain (M_i depends on M_{i-1} via aesenclast): CCM is MAC-bound.
//
// Phase-2 optimisations layered on top of the baseline 2-wide kernel:
//   * Counter hoist - the CCM counter is kept in LE canonical form
//     in xmm6 for the full body; each block pulls a BE view via one
//     pshufb and increments the LE canonical counter via paddq. The
//     baseline kernel paid one pshufb at the start AND one at the end
//     of every block (BE -> LE -> BE); this variant pays one pshufb
//     per block total.
//   * 2x unroll - the steady-state loop processes blocks in pairs.
//     Each pair issues three aesenc lanes per round-key broadcast
//     (CTR_i, CTR_{i+1}, MAC_i on encrypt; CTR_i, CTR_{i+1},
//     MAC(prev_P) on decrypt) followed by a single-lane MAC chain for
//     the second block of the pair. MAC-bound throughput is unchanged
//     but loop-overhead per block halves and the OoO window sees more
//     in-flight work per iteration. A trailing single-block body
//     (structurally the 2-wide baseline) handles odd BlockCount.
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
//                             overwritten with the post-body counter (BE).
//   [rcx + 32]  MacState    : 16-byte running CBC-MAC state (post-header,
//                             in/out; overwritten with post-body state).
//   [rcx + 40]  PMask       : 16-byte PSHUFB full-reverse control
//                             (readonly): [15,14,...,0]. Maps BE <-> LE.
//   [rcx + 48]  PIncrement  : 16-byte CTR increment = 1 in the low qword
//                             (when viewed LE). Added via paddq to the LE
//                             canonical counter; sufficient for CCM's
//                             <= 8-byte counter field.
//   [rcx + 56]  BlockCount  : NativeUInt; number of full 16-byte body blocks
//                             (MUST be >= 1; caller guarantees).
//
// XMM register allocation (x86_64; low regs + xmm8 used):
//   xmm0        : CTR A lane - counter_i -> aesenc chain -> keystream_i
//   xmm1        : MAC lane. Running CBC-MAC state across iterations.
//                 Inside a pair: M_{i-1} XOR P_i XOR K_0 -> aesenc ->
//                 M_i, then M_i XOR P_{i+1} XOR K_0 -> aesenc -> M_{i+1}.
//                 On decrypt the first XOR is with prev_P = P_{i-1}.
//   xmm2        : round-key scratch (reloaded per round via movdqa)
//   xmm3        : data-block cache block i (P_i on enc, C_i on dec)
//   xmm4        : CTR increment constant (loaded once from [rcx+48])
//   xmm5        : data-block cache block i+1 (P_{i+1}/C_{i+1}); also reused
//                 as a scratch in single-block tail paths
//   xmm6        : CTR counter in LE canonical form (persistent). Entered
//                 as BE, pshufb'd once to LE at prologue; pshufb'd back
//                 to BE at epilogue before storeback.
//   xmm7        : PSHUFB full-reverse mask (loaded once from [rcx+40])
//   xmm8        : DUAL ROLE. Inside the encrypt/decrypt pair loop:
//                 CTR B lane (counter_{i+1} -> aesenc -> keystream_{i+1}).
//                 Across decrypt iterations (pair loop boundary, single-
//                 block tail, and Pass 3 trailing MAC): carries prev_P =
//                 P_{i+1}. On encrypt xmm8 is transient per-iteration.
//                 Always db-encoded for Delphi-assembler compatibility.
//
// GPR usage (all MS x64 / Unix-volatile; no non-volatile saves needed):
//   rcx : PCtx (preserved across the kernel)
//   rax : InPtr (advancing; +16 in tail, +32 in pair)
//   rdx : OutPtr (advancing)
//   r8  : Keys base (alive across all rounds as the base of [r8 + 16*r])
//   r9  : scratch / CtrState pointer / MacState pointer at epilogue
//   r11 : BlockCount / loop counter (decrementing)
//
// Win64 ABI: xmm6..xmm15 are callee-save in general but this leaf-asm
// kernel is only called from Pascal (nostackframe via SimdProc1Begin),
// matching the OCB/GCM utility kernels in this tree.
//
// Direction : define CRYPTOLIB_CCM_DECRYPT for the decrypt variant
//             (MAC lags CTR by one block; Pass 1 cold start on block 0;
//             Pass 3 trailing scalar MAC AES on P_{last}).
// Key size  : define exactly ONE of CRYPTOLIB_AESNI_KEY128 /
//             CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256.
//
// Encoding: AES-NI instructions (aesenc / aesenclast) and instructions
// touching xmm8 are db-encoded. Standard SSE2 uses FPC mnemonics.
//   REX prefixes used below:
//     $41 = REX.B=1  (source register in r/m is xmm8..xmm15)
//     $44 = REX.R=1  (destination register is xmm8..xmm15)
//     $45 = REX.RB=1 (both dest and src are xmm8..xmm15; unused here)
//
// -------------------------------------------------------------------
// Prologue: load pointers, persistent state, and entry counter.
// Counter hoist: the canonical counter in xmm6 is kept in LE form for
// the body. We convert BE -> LE once here, LE -> BE once at epilogue.
// -------------------------------------------------------------------

  mov       rax, [rcx +  0]                         // rax = InPtr
  mov       rdx, [rcx +  8]                         // rdx = OutPtr
  mov       r8,  [rcx + 16]                         // r8  = Keys (base)
  mov       r11, [rcx + 56]                         // r11 = BlockCount

  // Persistent xmm state ------------------------------------------------
  mov       r9,  [rcx + 24]
  movdqu    xmm6, [r9]                              // xmm6 = CTR counter (BE form, from CtrState)
  mov       r9,  [rcx + 32]
  movdqu    xmm1, [r9]                              // xmm1 = MAC state (running)
  mov       r9,  [rcx + 40]
  movdqu    xmm7, [r9]                              // xmm7 = byteswap mask
  mov       r9,  [rcx + 48]
  movdqu    xmm4, [r9]                              // xmm4 = CTR increment constant

  pshufb    xmm6, xmm7                              // xmm6 = LE canonical counter

{$IFNDEF CRYPTOLIB_CCM_DECRYPT}

// -------------------------------------------------------------------
// ENCRYPT direction.
//
// Steady-state pair loop invariant at .ccm_enc_pair_loop head:
//   xmm1 = running MAC state M_{i-1}
//   xmm6 = LE canonical counter for block i
//   rax  = &InPtr[i*16]
//   rdx  = &OutPtr[i*16]
//   r11  = remaining blocks (>= 2; loop entry requires r11 >= 2)
// Per pair: produce C_i, C_{i+1}; fold P_i and P_{i+1} into MAC in
// order; advance pointers +32 and counter by 2.
// -------------------------------------------------------------------

  cmp       r11, 2
  jb        @@ccm_enc_tail                          // <2 blocks: skip to single-block tail

@@ccm_enc_pair_loop:

  // ----- Phase A: set up three AES input lanes --------------------
  // CTR A = BE(counter_i); CTR B = BE(counter_{i+1}); xmm6 <- LE(counter_{i+2}).
  movdqa    xmm0, xmm6                              // xmm0 = counter_i (LE)
  pshufb    xmm0, xmm7                              // xmm0 = counter_i (BE)
  paddq     xmm6, xmm4                              // xmm6 = counter_{i+1} (LE)
  db $66, $44, $0F, $6F, $C6                        // movdqa xmm8, xmm6  (xmm8 = counter_{i+1} LE)
  db $66, $44, $0F, $38, $00, $C7                   // pshufb xmm8, xmm7  (xmm8 = counter_{i+1} BE)
  paddq     xmm6, xmm4                              // xmm6 = counter_{i+2} (LE)

  // Load P_i and fold into MAC lane. xmm3 keeps P_i for the post-AES
  // XOR with keystream to produce C_i.
  movdqu    xmm3, [rax]                             // xmm3 = P_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR P_i

  // ----- Phase B: pre-whiten 3 lanes with K_0 ---------------------
  movdqa    xmm2, [r8]                              // xmm2 = K_0
  pxor      xmm0, xmm2
  db $66, $44, $0F, $EF, $C2                        // pxor xmm8, xmm2
  pxor      xmm1, xmm2

  // ----- Phase C: middle rounds, 3-wide (K_1 .. K_{Nr-1}) ---------
  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                   // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}

  // ----- Phase D: aesenclast, 3-wide ------------------------------
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0, xmm2  -> keystream_i
  db $66, $44, $0F, $38, $DD, $C2                   // aesenclast xmm8, xmm2  -> keystream_{i+1}
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> M_i

  // ----- Phase E: produce C_i -------------------------------------
  pxor      xmm0, xmm3                              // xmm0 = C_i = keystream_i XOR P_i
  movdqu    [rdx], xmm0                             // store C_i

  // ----- Phase F: load P_{i+1}, produce C_{i+1} -------------------
  movdqu    xmm3, [rax + 16]                        // xmm3 = P_{i+1}   (reused from P_i slot)
  db $66, $44, $0F, $EF, $C3                        // pxor xmm8, xmm3
  db $F3, $44, $0F, $7F, $42, $10                   // movdqu [rdx+16], xmm8  -> store C_{i+1}

  // ----- Phase G: serial MAC chain for block i+1 ------------------
  pxor      xmm1, xmm3                              // xmm1 = M_i XOR P_{i+1}

  movdqa    xmm2, [r8]
  pxor      xmm1, xmm2                              // pre-whiten
  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> M_{i+1}

  // ----- Phase H: advance pointers, close pair --------------------
  add       rax, 32
  add       rdx, 32
  sub       r11, 2
  cmp       r11, 2
  jae       @@ccm_enc_pair_loop

@@ccm_enc_tail:
  // Single-block 2-wide tail. Entered when 0 or 1 blocks remain after
  // the pair loop. Structurally identical to the baseline 2-wide body,
  // just operating on xmm6 in LE canonical form.
  test      r11, r11
  jz        @@ccm_enc_done

  movdqu    xmm3, [rax]                             // xmm3 = P_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR P_i

  movdqa    xmm0, xmm6                              // xmm0 = counter_i (LE)
  pshufb    xmm0, xmm7                              // xmm0 = counter_i (BE)
  paddq     xmm6, xmm4                              // xmm6 = counter_{i+1} (LE)

  movdqa    xmm2, [r8]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0 -> keystream
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_i

  pxor      xmm0, xmm3                              // C_i = keystream XOR P_i
  movdqu    [rdx], xmm0

@@ccm_enc_done:

{$ELSE} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// DECRYPT direction.
//
// Structure:
//   Pass 1 : block 0 CTR-only (cold start; MAC idle). Stashes P_0 in
//            xmm8 as prev_P.
//   Pass 2 : steady-state pair loop (3-wide aesenc: CTR_i, CTR_{i+1},
//            MAC(prev_P)) plus serial MAC chain for P_i; if an odd
//            tail remains, one baseline 2-wide iteration runs.
//   Pass 3 : trailing scalar MAC AES folding in the final P_{last}
//            (carried in xmm8).
//
// Across the whole decrypt path xmm8 carries prev_P and xmm1 carries
// the running MAC state.
// -------------------------------------------------------------------

  // ----- Pass 1: block 0 CTR-only, 1-wide -------------------------
  movdqa    xmm0, xmm6                              // xmm0 = counter_0 (LE)
  pshufb    xmm0, xmm7                              // xmm0 = counter_0 (BE)
  paddq     xmm6, xmm4                              // xmm6 = counter_1 (LE)

  movdqa    xmm2, [r8]
  pxor      xmm0, xmm2

  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
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
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0 -> keystream_0

  movdqu    xmm3, [rax]                             // xmm3 = C_0
  pxor      xmm0, xmm3                              // xmm0 = P_0
  movdqu    [rdx], xmm0                             // store P_0

  // Stash xmm8 = prev_P = P_0.
  db $66, $44, $0F, $6F, $C0                        // movdqa xmm8, xmm0

  add       rax, 16
  add       rdx, 16
  dec       r11
  jz        @@ccm_dec_trailing                      // BlockCount == 1

  // ----- Pass 2 dispatch ------------------------------------------
  cmp       r11, 2
  jb        @@ccm_dec_single_tail                   // exactly 1 body block left

  // Pair loop invariant at .ccm_dec_pair_loop head:
  //   xmm1 = M_{i-1}                                (running MAC state)
  //   xmm8 = prev_P = P_{i-1}                       (from Pass 1 or prev pair)
  //   xmm6 = LE canonical counter_i
  //   rax  = &InPtr[i*16]
  //   rdx  = &OutPtr[i*16]
  //   r11  = remaining blocks in Pass 2 (>= 2 on entry)
  // Per pair: produce P_i, P_{i+1}; fold P_{i-1} (in xmm8) and P_i
  // into MAC in order; prev_P update happens in-place via CTR B lane.

@@ccm_dec_pair_loop:

  // Load C_i, C_{i+1}
  movdqu    xmm3, [rax]                             // xmm3 = C_i
  movdqu    xmm5, [rax + 16]                        // xmm5 = C_{i+1}

  // MAC input for block i: M_{i-1} XOR prev_P (= P_{i-1}).
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8

  // CTR A = BE(counter_i); CTR B = BE(counter_{i+1}); advance xmm6.
  // xmm8 is consumed above and re-used as CTR B lane here; at end of
  // pair it will hold P_{i+1}, becoming the new prev_P naturally.
  movdqa    xmm0, xmm6                              // LE counter_i
  pshufb    xmm0, xmm7                              // BE counter_i
  paddq     xmm6, xmm4                              // LE counter_{i+1}
  db $66, $44, $0F, $6F, $C6                        // movdqa xmm8, xmm6  (LE counter_{i+1})
  db $66, $44, $0F, $38, $00, $C7                   // pshufb xmm8, xmm7  (BE counter_{i+1})
  paddq     xmm6, xmm4                              // LE counter_{i+2}

  // Pre-whiten 3 lanes with K_0.
  movdqa    xmm2, [r8]
  pxor      xmm0, xmm2
  db $66, $44, $0F, $EF, $C2                        // pxor xmm8, xmm2
  pxor      xmm1, xmm2

  // Middle rounds, 3-wide.
  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $44, $0F, $38, $DC, $C2                  // aesenc xmm8, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}

  // aesenclast, 3-wide.
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [r8 + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0 -> keystream_i
  db $66, $44, $0F, $38, $DD, $C2                   // aesenclast xmm8 -> keystream_{i+1}
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_i (MAC just folded P_{i-1})

  // Produce P_i = keystream_i XOR C_i. xmm0 is now P_i; we need it for
  // the MAC fold (so it must survive to Phase serial-MAC below).
  pxor      xmm0, xmm3                              // xmm0 = P_i
  movdqu    [rdx], xmm0                             // store P_i

  // Produce P_{i+1} = keystream_{i+1} XOR C_{i+1}. After the store,
  // xmm8 holds P_{i+1} in-place, which becomes prev_P for the next
  // pair iteration automatically.
  db $66, $44, $0F, $EF, $C5                        // pxor xmm8, xmm5
  db $F3, $44, $0F, $7F, $42, $10                   // movdqu [rdx+16], xmm8  -> store P_{i+1}

  // Serial MAC chain: fold P_i (= xmm0) into M_i -> M_{i+1}.
  pxor      xmm1, xmm0                              // xmm1 = M_i XOR P_i

  movdqa    xmm2, [r8]
  pxor      xmm1, xmm2
  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_{i+1}

  // Advance pointers, close pair.
  add       rax, 32
  add       rdx, 32
  sub       r11, 2
  cmp       r11, 2
  jae       @@ccm_dec_pair_loop

@@ccm_dec_single_tail:
  // One body block left (Pass 2 tail), baseline 2-wide body. xmm8 =
  // prev_P entering; xmm8 updated to this block's P at the end so
  // Pass 3 can fold it.
  test      r11, r11
  jz        @@ccm_dec_trailing

  movdqu    xmm3, [rax]                             // xmm3 = C_i
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8  (MAC input)

  movdqa    xmm0, xmm6                              // LE
  pshufb    xmm0, xmm7                              // BE
  paddq     xmm6, xmm4                              // advance LE

  movdqa    xmm2, [r8]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0 -> keystream_i
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_i

  pxor      xmm0, xmm3                              // xmm0 = P_i
  movdqu    [rdx], xmm0

  // Update prev_P = P_i.
  db $66, $44, $0F, $6F, $C0                        // movdqa xmm8, xmm0

@@ccm_dec_trailing:
  // ----- Pass 3: trailing MAC fold --------------------------------
  // Fold P_{last} (= xmm8) into the MAC and run a single-lane AES
  // chain to produce the final MAC.
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8

  movdqa    xmm2, [r8]
  pxor      xmm1, xmm2

  movdqa    xmm2, [r8 + 16]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 32]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 48]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 64]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 80]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 96]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 112]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 128]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 144]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [r8 + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 192]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [r8 + 208]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> final MAC state

{$ENDIF} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// Epilogue: convert xmm6 LE -> BE, write back CtrState and MacState.
// -------------------------------------------------------------------

  pshufb    xmm6, xmm7                              // xmm6 = counter (BE) for storage
  mov       r9,  [rcx + 24]
  movdqu    [r9], xmm6                              // CtrState <- updated counter
  mov       r9,  [rcx + 32]
  movdqu    [r9], xmm1                              // MacState <- final MAC

