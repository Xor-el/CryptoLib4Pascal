// EAX fused AES-NI CTR+OMAC kernel (x86-64).
// -------------------------------------------------------------------
// Novel work for CryptoLib: no fused EAX reference kernel is known in
// OpenSSL, BoringSSL, AWS-LC or Botan (all ship scalar EAX). Technique
// derived from Bogdanov-Lauridsen-Tischhauser "Comb to Pipeline" (FSE
// 2016, eprint 2016/047) and the AES-NI AEAD pattern shared with CCM
// (Shay Gueron, "Intel AES New Instructions" Rev 3.01).
//
// Two lanes (CTR / MAC) share each round-key broadcast: the second
// aesenc fills a pipeline slot that would otherwise idle. EAX is
// MAC-bound because OMAC's CBC chain has the same aesenclast-to-aesenc
// serial dependency as CCM's CBC-MAC. OMAC consumes CIPHERTEXT (output
// on encrypt, input on decrypt), so the 1-iteration lag lives on the
// OPPOSITE direction from CCM: EAX-encrypt (MAC lags CTR by 1) mirrors
// CCM-decrypt; EAX-decrypt mirrors CCM-encrypt. Optimisations: counter
// hoist (canonical counter LE in xmm6, one pshufb per block) and a 2x
// pair unroll issuing three aesenc lanes per round-key broadcast with
// a serial MAC chain on the second block; single-block tail handles
// odd counts.
//
// Variant selection:
//   CRYPTOLIB_EAX_DECRYPT  -> decrypt variant (no MAC lag; 2-wide loop).
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R.
//
// On entry (after SimdProc1Begin_x86_64.inc): rcx = PCtx.
//
// Context layout (7 pointers + 1 NativeUInt = 64 bytes, 8-byte aligned).
// See TEaxFusedTwoCtx in ClpAesNiEaxKernel.pas.
//   [rcx +  0]  InPtr       : body blocks (plaintext on enc, ciphertext on dec)
//   [rcx +  8]  OutPtr      : body output buffer (may alias InPtr)
//   [rcx + 16]  Keys        : AES encrypt schedule (176/208/240 bytes, 16-byte aligned)
//   [rcx + 24]  CtrState    : 16-byte EAX counter (BE; in/out)
//   [rcx + 32]  OmacState   : 16-byte running OMAC state (in/out)
//   [rcx + 40]  PMask       : 16-byte PSHUFB full-reverse control (BE <-> LE)
//   [rcx + 48]  PIncrement  : 16-byte CTR increment = 1 in low qword (LE)
//   [rcx + 56]  BlockCount  : NativeUInt; full body blocks (>= 2)
//
// XMM (9/16 used):
//   xmm0 : CTR A lane (transient per block)
//   xmm1 : MAC lane (running OMAC state)
//   xmm2 : round-key scratch
//   xmm3 : data-block cache block i (P_i / C_i)
//   xmm4 : CTR increment constant (loaded once from [rcx + 48])
//   xmm5 : data-block cache block i+1 (also scratch on single-block tail)
//   xmm6 : canonical LE counter (BE -> LE at prologue, LE -> BE at epilogue)
//   xmm7 : PSHUFB full-reverse mask (loaded once from [rcx + 40])
//   xmm8 : ENC: prev_C across iterations / DEC: CTR B lane (pair loop)
//
// AES-NI instructions and xmm8-touching forms are db-encoded for broad
// assembler compatibility.

  mov       rax, [rcx +  0]                         // rax = InPtr
  mov       rdx, [rcx +  8]                         // rdx = OutPtr
  mov       r8,  [rcx + 16]                         // r8  = Keys (base)
  mov       r11, [rcx + 56]                         // r11 = BlockCount

  mov       r9,  [rcx + 24]
  movdqu    xmm6, [r9]                              // xmm6 = CTR counter (BE, from CtrState)
  mov       r9,  [rcx + 32]
  movdqu    xmm1, [r9]                              // xmm1 = OMAC state (running)
  mov       r9,  [rcx + 40]
  movdqu    xmm7, [r9]                              // xmm7 = byteswap mask
  mov       r9,  [rcx + 48]
  movdqu    xmm4, [r9]                              // xmm4 = CTR increment constant

  pshufb    xmm6, xmm7                              // xmm6 = LE canonical counter

{$IFNDEF CRYPTOLIB_EAX_DECRYPT}

// -------------------------------------------------------------------
// ENCRYPT direction (MAC lags CTR by one block; mirrors CCM decrypt).
//
// Structure:
//   Pass 1 : block 0 CTR-only (cold start; MAC idle until C_0 exists).
//            Stashes C_0 in xmm8 as prev_C.
//   Pass 2 : steady-state pair loop (3-wide aesenc: CTR_i, CTR_{i+1},
//            MAC(prev_C)) plus serial MAC chain for C_i; if an odd
//            tail remains, one baseline 2-wide iteration runs.
//   Pass 3 : trailing scalar MAC AES folding in the final C_{last}
//            (carried in xmm8).
//
// Across the whole encrypt path xmm8 carries prev_C and xmm1 carries
// the running OMAC state.
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

  movdqu    xmm3, [rax]                             // xmm3 = P_0
  pxor      xmm0, xmm3                              // xmm0 = C_0
  movdqu    [rdx], xmm0                             // store C_0

  // Stash xmm8 = prev_C = C_0.
  db $66, $44, $0F, $6F, $C0                        // movdqa xmm8, xmm0

  add       rax, 16
  add       rdx, 16
  dec       r11
  jz        @@eax_enc_trailing                      // BlockCount == 1

  // ----- Pass 2 dispatch ------------------------------------------
  cmp       r11, 2
  jb        @@eax_enc_single_tail                   // exactly 1 body block left

  // Pair loop invariant at .eax_enc_pair_loop head:
  //   xmm1 = M_{i-1}                                (running OMAC state)
  //   xmm8 = prev_C = C_{i-1}                       (from Pass 1 or prev pair)
  //   xmm6 = LE canonical counter_i
  //   rax  = &InPtr[i*16]
  //   rdx  = &OutPtr[i*16]
  //   r11  = remaining blocks in Pass 2 (>= 2 on entry)
  // Per pair: produce C_i, C_{i+1}; fold C_{i-1} (in xmm8) and C_i
  // into MAC in order; prev_C update happens in-place via CTR B lane.

@@eax_enc_pair_loop:

  // Load P_i, P_{i+1}.
  movdqu    xmm3, [rax]                             // xmm3 = P_i
  movdqu    xmm5, [rax + 16]                        // xmm5 = P_{i+1}

  // MAC input for block i: M_{i-1} XOR prev_C (= C_{i-1}).
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8

  // CTR A = BE(counter_i); CTR B = BE(counter_{i+1}); advance xmm6.
  // xmm8 is consumed above and re-used as CTR B lane here; at end of
  // pair it will hold C_{i+1}, becoming the new prev_C naturally.
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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_i (MAC just folded C_{i-1})

  // Produce C_i = keystream_i XOR P_i. xmm0 is now C_i; we need it for
  // the MAC fold (must survive to the serial-MAC phase below).
  pxor      xmm0, xmm3                              // xmm0 = C_i
  movdqu    [rdx], xmm0                             // store C_i

  // Produce C_{i+1} = keystream_{i+1} XOR P_{i+1}. After the store,
  // xmm8 holds C_{i+1} in-place, which becomes prev_C for the next
  // pair iteration automatically.
  db $66, $44, $0F, $EF, $C5                        // pxor xmm8, xmm5
  db $F3, $44, $0F, $7F, $42, $10                   // movdqu [rdx+16], xmm8  -> store C_{i+1}

  // Serial MAC chain: fold C_i (= xmm0) into M_i -> M_{i+1}.
  pxor      xmm1, xmm0                              // xmm1 = M_i XOR C_i

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
  jae       @@eax_enc_pair_loop

@@eax_enc_single_tail:
  // One body block left (Pass 2 tail), baseline 2-wide body. xmm8 =
  // prev_C entering; xmm8 updated to this block's C at the end so
  // Pass 3 can fold it.
  test      r11, r11
  jz        @@eax_enc_trailing

  movdqu    xmm3, [rax]                             // xmm3 = P_i
  db $66, $41, $0F, $EF, $C8                        // pxor xmm1, xmm8  (MAC input = M_{i-1} XOR prev_C)

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

  pxor      xmm0, xmm3                              // xmm0 = C_i
  movdqu    [rdx], xmm0

  // Update prev_C = C_i.
  db $66, $44, $0F, $6F, $C0                        // movdqa xmm8, xmm0

@@eax_enc_trailing:
  // ----- Pass 3: trailing OMAC fold --------------------------------
  // Fold C_{last} (= xmm8) into the OMAC state and run a single-lane
  // AES chain to produce the final OMAC.
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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> final OMAC state

{$ELSE} // CRYPTOLIB_EAX_DECRYPT

// -------------------------------------------------------------------
// DECRYPT direction (no lag; MAC substrate = input ciphertext;
// mirrors CCM encrypt).
//
// Pair loop invariant at .eax_dec_pair_loop head:
//   xmm1 = running OMAC state M_{i-1}
//   xmm6 = LE canonical counter for block i
//   rax  = &InPtr[i*16]
//   rdx  = &OutPtr[i*16]
//   r11  = remaining blocks (>= 2; loop entry requires r11 >= 2)
// Per pair: produce P_i, P_{i+1}; fold C_i and C_{i+1} into MAC in
// order; advance pointers +32 and counter by 2.
// -------------------------------------------------------------------

  cmp       r11, 2
  jb        @@eax_dec_tail

@@eax_dec_pair_loop:

  // CTR A = BE(counter_i); CTR B = BE(counter_{i+1}); xmm6 <- LE(counter_{i+2}).
  movdqa    xmm0, xmm6                              // counter_i (LE)
  pshufb    xmm0, xmm7                              // counter_i (BE)
  paddq     xmm6, xmm4                              // counter_{i+1} (LE)
  db $66, $44, $0F, $6F, $C6                        // movdqa xmm8, xmm6  (counter_{i+1} LE)
  db $66, $44, $0F, $38, $00, $C7                   // pshufb xmm8, xmm7  (counter_{i+1} BE)
  paddq     xmm6, xmm4                              // counter_{i+2} (LE)

  // Load C_i, fold into MAC lane. xmm3 keeps C_i for the post-AES
  // keystream XOR.
  movdqu    xmm3, [rax]                             // xmm3 = C_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR C_i

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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_i

  // Produce P_i = keystream_i XOR C_i; store.
  pxor      xmm0, xmm3
  movdqu    [rdx], xmm0

  // Reload xmm3 = C_{i+1}; produce P_{i+1} and store.
  movdqu    xmm3, [rax + 16]                        // xmm3 = C_{i+1}
  db $66, $44, $0F, $EF, $C3                        // pxor xmm8, xmm3
  db $F3, $44, $0F, $7F, $42, $10                   // movdqu [rdx+16], xmm8  -> store P_{i+1}

  // Serial MAC chain: fold C_{i+1} (= xmm3) into M_i -> M_{i+1}.
  pxor      xmm1, xmm3                              // xmm1 = M_i XOR C_{i+1}

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

  add       rax, 32
  add       rdx, 32
  sub       r11, 2
  cmp       r11, 2
  jae       @@eax_dec_pair_loop

@@eax_dec_tail:
  // Single-block 2-wide tail. Entered when 0 or 1 blocks remain after
  // the pair loop. Structurally identical to the baseline 2-wide body,
  // just operating on xmm6 in LE canonical form.
  test      r11, r11
  jz        @@eax_dec_done

  movdqu    xmm3, [rax]                             // xmm3 = C_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR C_i

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

@@eax_dec_done:

{$ENDIF} // CRYPTOLIB_EAX_DECRYPT

// -------------------------------------------------------------------
// Epilogue: convert xmm6 LE -> BE, write back CtrState and OmacState.
// -------------------------------------------------------------------

  pshufb    xmm6, xmm7                              // xmm6 = counter (BE) for storage
  mov       r9,  [rcx + 24]
  movdqu    [r9], xmm6                              // CtrState <- updated counter
  mov       r9,  [rcx + 32]
  movdqu    [r9], xmm1                              // OmacState <- final OMAC

