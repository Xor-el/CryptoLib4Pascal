// CCM fused AES-NI CTR+CBC-MAC kernel (i386).
// -------------------------------------------------------------------
// 32-bit sibling of AesCcmFusedCtrCbcMacTwo_x86_64.inc. See that file for
// the full rationale (two-lane AES-NI pipelining, counter hoist, 2x
// unroll). The algorithm, context layout (field-for-field), and
// semantics are identical; only the pointer width, register budget
// (xmm0..xmm7), and 2x-unroll scope differ.
//
// Pointer-width differences (32-bit field offsets):
//   [ebx +  0]  InPtr
//   [ebx +  4]  OutPtr
//   [ebx +  8]  Keys
//   [ebx + 12]  CtrState
//   [ebx + 16]  MacState
//   [ebx + 20]  PMask
//   [ebx + 24]  PIncrement
//   [ebx + 28]  BlockCount (NativeUInt = 4 bytes on i386)
//
// Phase-2 optimisations present on this 8-xmm-budget path:
//   * Counter hoist - applied to BOTH encrypt and decrypt. The canonical
//     counter in xmm6 is kept in LE form across the whole body. The
//     baseline kernel paid pshufb BE->LE and pshufb LE->BE around each
//     paddq; this variant pays one pshufb per block total (LE->BE at
//     each use).
//   * 2x unroll - applied to ENCRYPT ONLY. On the encrypt side xmm4
//     (the decrypt-only prev_P slot) is free and doubles as CTR B,
//     allowing a 3-wide aesenc pair loop with a single-block tail.
//     The decrypt side leaves xmm4 pinned as prev_P; fitting a 2x
//     unroll there would cost a stack-spill slot for prev_P and two
//     extra movdqu per pair, which on the MAC-bound CCM chain eats
//     roughly half of the loop-overhead saving. The i386-dec path
//     therefore stays at baseline 2-wide width plus counter hoist.
//
// On entry (after SimdProc1Begin_i386.inc): ebx = PCtx.
// The wrapping Pascal procedure must terminate with:
//   pop edi
//   pop esi
//   pop ebx
// before the final 'end;' that emits RET. This kernel emits those
// pops itself in the epilogue; the SimdProc1Begin prologue already
// pushed ebx.
//
// XMM register allocation (8 of 8 xmm registers used on i386):
//   xmm0 : CTR A lane (transient; counter_i -> aesenc chain -> keystream_i)
//   xmm1 : MAC lane - running CBC-MAC state. Per-iter becomes
//          M_{i-1} XOR P_i XOR K_0 before rounds; M_i after rounds.
//   xmm2 : round-key scratch (reloaded per round via movdqa)
//   xmm3 : data-block cache (P_i/C_i; reloaded to P_{i+1}/C_{i+1} in
//          the encrypt pair loop between the 3-wide aesenclast and
//          the serial MAC chain for block i+1)
//   xmm4 : ENCRYPT: CTR B lane (transient per pair; counter_{i+1}
//                    -> aesenc chain -> keystream_{i+1}).
//          DECRYPT: prev_P slot - P_{i-1} carried across iteration
//                    boundaries. Unused on encrypt's tail/singleton
//                    paths.
//   xmm5 : CTR increment constant (loaded once from [ebx + 24])
//   xmm6 : CTR counter in LE canonical form (persistent). Entered as
//          BE, pshufb'd to LE at prologue; pshufb'd back to BE at
//          epilogue before storeback.
//   xmm7 : PSHUFB full-reverse mask (loaded once from [ebx + 20])
//
// GPR usage (i386 fastcall / nostackframe):
//   ebx : PCtx                              (preserved; prologue pushed)
//   eax : InPtr (advancing)                 (scratch)
//   esi : OutPtr (advancing)                (callee-saved; pushed here)
//   edx : Keys base                         (scratch)
//   ecx : BlockCount / loop counter         (scratch; decrementing)
//   edi : scratch (CtrState / MacState ptrs (callee-saved; pushed here)
//         at prologue / epilogue)
//
// Direction : define CRYPTOLIB_CCM_DECRYPT for the decrypt variant.
// Key size  : define exactly ONE of CRYPTOLIB_AESNI_KEY128 /
//             CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256.
//
// -------------------------------------------------------------------
// Prologue: save callee-saved, load pointers and persistent state.
// Counter hoist converts xmm6 BE -> LE once.
// -------------------------------------------------------------------

  push      esi
  push      edi

  mov       eax, [ebx +  0]                         // eax = InPtr
  mov       esi, [ebx +  4]                         // esi = OutPtr
  mov       edx, [ebx +  8]                         // edx = Keys (base)
  mov       ecx, [ebx + 28]                         // ecx = BlockCount

  mov       edi, [ebx + 12]
  movdqu    xmm6, [edi]                             // xmm6 = CTR counter (BE)
  mov       edi, [ebx + 16]
  movdqu    xmm1, [edi]                             // xmm1 = MAC state (running)
  mov       edi, [ebx + 20]
  movdqu    xmm7, [edi]                             // xmm7 = byteswap mask
  mov       edi, [ebx + 24]
  movdqu    xmm5, [edi]                             // xmm5 = increment constant

  pshufb    xmm6, xmm7                              // xmm6 = LE canonical counter

{$IFNDEF CRYPTOLIB_CCM_DECRYPT}

// -------------------------------------------------------------------
// ENCRYPT direction: counter hoist + 2x unroll.
//
// Pair loop invariant at .ccm_enc_pair_loop head:
//   xmm1 = running MAC state M_{i-1}
//   xmm6 = LE canonical counter for block i
//   eax  = &InPtr[i*16]
//   esi  = &OutPtr[i*16]
//   ecx  = remaining blocks (>= 2; loop entry requires ecx >= 2)
// -------------------------------------------------------------------

  cmp       ecx, 2
  jb        @@ccm_enc_tail

@@ccm_enc_pair_loop:

  // CTR A = BE(counter_i); CTR B = BE(counter_{i+1}); xmm6 <- LE(counter_{i+2}).
  movdqa    xmm0, xmm6                              // counter_i (LE)
  pshufb    xmm0, xmm7                              // counter_i (BE)
  paddq     xmm6, xmm5                              // counter_{i+1} (LE)
  movdqa    xmm4, xmm6                              // counter_{i+1} (LE)
  pshufb    xmm4, xmm7                              // counter_{i+1} (BE) -- CTR B lane
  paddq     xmm6, xmm5                              // counter_{i+2} (LE)

  // Load P_i; fold into MAC lane. xmm3 keeps P_i for the post-AES
  // ciphertext XOR.
  movdqu    xmm3, [eax]                             // xmm3 = P_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR P_i

  // Pre-whiten 3 lanes with K_0.
  movdqa    xmm2, [edx]                             // K_0
  pxor      xmm0, xmm2
  pxor      xmm4, xmm2
  pxor      xmm1, xmm2

  // Middle rounds, 3-wide (K_1 .. K_{Nr-1}).
  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                        // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $E2                       // aesenc xmm4, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}

  // aesenclast, 3-wide.
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [edx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0 -> keystream_i
  db $66, $0F, $38, $DD, $E2                        // aesenclast xmm4 -> keystream_{i+1}
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_i

  // Produce C_i = keystream_i XOR P_i; store.
  pxor      xmm0, xmm3
  movdqu    [esi], xmm0

  // Reload xmm3 = P_{i+1}; produce C_{i+1} = keystream_{i+1} XOR P_{i+1}.
  movdqu    xmm3, [eax + 16]
  pxor      xmm4, xmm3
  movdqu    [esi + 16], xmm4

  // Serial MAC chain for block i+1.
  pxor      xmm1, xmm3                              // xmm1 = M_i XOR P_{i+1}

  movdqa    xmm2, [edx]
  pxor      xmm1, xmm2
  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [edx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_{i+1}

  add       eax, 32
  add       esi, 32
  sub       ecx, 2
  cmp       ecx, 2
  jae       @@ccm_enc_pair_loop

@@ccm_enc_tail:
  // Single-block 2-wide tail. Entered when 0 or 1 blocks remain after
  // the pair loop.
  test      ecx, ecx
  jz        @@ccm_enc_done

  movdqu    xmm3, [eax]                             // P_i
  pxor      xmm1, xmm3

  movdqa    xmm0, xmm6                              // LE
  pshufb    xmm0, xmm7                              // BE
  paddq     xmm6, xmm5                              // advance LE

  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [edx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1

  pxor      xmm0, xmm3                              // C_i
  movdqu    [esi], xmm0

@@ccm_enc_done:

{$ELSE} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// DECRYPT direction: counter hoist, baseline 2-wide width.
//
// Pass 1: block 0 CTR-only, stash xmm4 = prev_P = P_0.
// Pass 2: BlockCount-1 interleaved iterations (2-wide CTR+MAC).
// Pass 3: trailing scalar MAC AES on P_{last} (= xmm4).
// -------------------------------------------------------------------

  // ----- Pass 1: block 0 CTR-only, 1-wide -------------------------
  movdqa    xmm0, xmm6                              // counter_0 (LE)
  pshufb    xmm0, xmm7                              // counter_0 (BE)
  paddq     xmm6, xmm5                              // counter_1 (LE)

  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [edx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0 -> keystream_0

  movdqu    xmm3, [eax]                             // C_0
  pxor      xmm0, xmm3                              // P_0
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // xmm4 = prev_P = P_0

  add       eax, 16
  add       esi, 16
  dec       ecx
  jz        @@ccm_dec_trailing

  // ----- Pass 2: 2-wide interleaved iterations --------------------
@@ccm_dec_loop:

  movdqu    xmm3, [eax]                             // C_i
  pxor      xmm1, xmm4                              // MAC input = M_{i-1} XOR P_{i-1}

  movdqa    xmm0, xmm6                              // counter_i (LE)
  pshufb    xmm0, xmm7                              // counter_i (BE)
  paddq     xmm6, xmm5                              // counter_{i+1} (LE)

  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2                       // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [edx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0 -> keystream_i
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> M_i

  pxor      xmm0, xmm3                              // P_i
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // prev_P = P_i

  add       eax, 16
  add       esi, 16
  dec       ecx
  jnz       @@ccm_dec_loop

@@ccm_dec_trailing:
  // ----- Pass 3: trailing scalar MAC fold --------------------------
  pxor      xmm1, xmm4                              // M XOR P_{last}

  movdqa    xmm2, [edx]
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $CA                       // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqa    xmm2, [edx + 160]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 192]
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 224]
{$ENDIF}
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> final MAC state

{$ENDIF} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// Epilogue: convert xmm6 LE -> BE, write back CtrState and MacState,
// restore callee-saved GPRs (edi/esi/ebx).
// -------------------------------------------------------------------

  pshufb    xmm6, xmm7                              // xmm6 = counter (BE) for storage
  mov       edi, [ebx + 12]
  movdqu    [edi], xmm6                             // CtrState <- counter
  mov       edi, [ebx + 16]
  movdqu    [edi], xmm1                             // MacState <- final MAC

  pop       edi
  pop       esi
  pop       ebx

