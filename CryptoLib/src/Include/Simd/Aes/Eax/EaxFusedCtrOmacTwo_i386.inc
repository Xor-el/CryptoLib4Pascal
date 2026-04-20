// EAX fused AES-NI CTR+OMAC kernel (i386).
// -------------------------------------------------------------------
// 32-bit sibling of EaxFusedCtrOmacTwo_x86_64.inc. See that file for
// the full rationale (two-lane AES-NI pipelining, counter hoist, 2x
// unroll, EAX vs CCM mirror). The algorithm, context layout (field-
// for-field), and semantics are identical; only the pointer width,
// register budget (xmm0..xmm7), and 2x-unroll scope differ.
//
// Pointer-width differences (32-bit field offsets):
//   [ebx +  0]  InPtr
//   [ebx +  4]  OutPtr
//   [ebx +  8]  Keys
//   [ebx + 12]  CtrState
//   [ebx + 16]  OmacState
//   [ebx + 20]  PMask
//   [ebx + 24]  PIncrement
//   [ebx + 28]  BlockCount (NativeUInt = 4 bytes on i386)
//
// Phase-3 optimisations present on this 8-xmm-budget path:
//   * Counter hoist - applied to BOTH encrypt and decrypt. The canonical
//     counter in xmm6 is kept in LE form across the whole body. The
//     baseline kernel paid pshufb BE->LE and pshufb LE->BE around each
//     paddq; this variant pays one pshufb per block total (LE->BE at
//     each use).
//   * 2x unroll - applied to DECRYPT ONLY. On the decrypt side xmm4
//     (the encrypt-only prev_C slot) is free and doubles as CTR B,
//     allowing a 3-wide aesenc pair loop with a single-block tail.
//     The encrypt side leaves xmm4 pinned as prev_C; fitting a 2x
//     unroll there would cost a stack-spill slot for prev_C and two
//     extra movdqu per pair, which on the MAC-bound EAX chain eats
//     roughly half of the loop-overhead saving. The i386-enc path
//     therefore stays at baseline 2-wide width plus counter hoist.
//
//   Mirror of CCM: CCM i386 unrolls enc (xmm4 free on enc) and keeps
//   dec 2-wide (xmm4 = prev_P). EAX i386 does the opposite because
//   prev_C lives on encrypt instead of decrypt.
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
//   xmm1 : MAC lane - running OMAC state across iterations.
//   xmm2 : round-key scratch (reloaded per round via movdqa)
//   xmm3 : data-block cache (P_i/C_i; reloaded to P_{i+1}/C_{i+1} in
//          the decrypt pair loop between the 3-wide aesenclast and
//          the serial MAC chain for block i+1)
//   xmm4 : ENCRYPT: prev_C slot - C_{i-1} carried across iteration
//                    boundaries. Unused on decrypt's tail/singleton
//                    paths.
//          DECRYPT: CTR B lane (transient per pair; counter_{i+1}
//                    -> aesenc chain -> keystream_{i+1}).
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
//   edi : scratch (CtrState / OmacState     (callee-saved; pushed here)
//         ptrs at prologue / epilogue)
//
// Direction : define CRYPTOLIB_EAX_DECRYPT for the decrypt variant.
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
  movdqu    xmm1, [edi]                             // xmm1 = OMAC state (running)
  mov       edi, [ebx + 20]
  movdqu    xmm7, [edi]                             // xmm7 = byteswap mask
  mov       edi, [ebx + 24]
  movdqu    xmm5, [edi]                             // xmm5 = increment constant

  pshufb    xmm6, xmm7                              // xmm6 = LE canonical counter

{$IFNDEF CRYPTOLIB_EAX_DECRYPT}

// -------------------------------------------------------------------
// ENCRYPT direction: counter hoist, baseline 2-wide width (xmm4 = prev_C).
//
// Pass 1: block 0 CTR-only, stash xmm4 = prev_C = C_0.
// Pass 2: BlockCount-1 interleaved iterations (2-wide CTR+MAC).
// Pass 3: trailing scalar MAC AES on C_{last} (= xmm4).
// -------------------------------------------------------------------

  // ----- Pass 1: block 0 CTR-only, 1-wide -------------------------
  movdqa    xmm0, xmm6                              // counter_0 (LE)
  pshufb    xmm0, xmm7                              // counter_0 (BE)
  paddq     xmm6, xmm5                              // counter_1 (LE)

  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2
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

  movdqu    xmm3, [eax]                             // P_0
  pxor      xmm0, xmm3                              // C_0
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // xmm4 = prev_C = C_0

  add       eax, 16
  add       esi, 16
  dec       ecx
  jz        @@eax_enc_trailing

  // ----- Pass 2: 2-wide interleaved iterations --------------------
@@eax_enc_loop:

  movdqu    xmm3, [eax]                             // P_i
  pxor      xmm1, xmm4                              // MAC input = M_{i-1} XOR C_{i-1}

  movdqa    xmm0, xmm6                              // counter_i (LE)
  pshufb    xmm0, xmm7                              // counter_i (BE)
  paddq     xmm6, xmm5                              // counter_{i+1} (LE)

  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
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

  pxor      xmm0, xmm3                              // C_i
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // prev_C = C_i

  add       eax, 16
  add       esi, 16
  dec       ecx
  jnz       @@eax_enc_loop

@@eax_enc_trailing:
  // ----- Pass 3: trailing scalar MAC fold --------------------------
  pxor      xmm1, xmm4                              // M XOR C_{last}

  movdqa    xmm2, [edx]
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $CA
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $CA
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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1 -> final OMAC state

{$ELSE} // CRYPTOLIB_EAX_DECRYPT

// -------------------------------------------------------------------
// DECRYPT direction: counter hoist + 2x unroll.
//
// Pair loop invariant at .eax_dec_pair_loop head:
//   xmm1 = running OMAC state M_{i-1}
//   xmm6 = LE canonical counter for block i
//   eax  = &InPtr[i*16]
//   esi  = &OutPtr[i*16]
//   ecx  = remaining blocks (>= 2; loop entry requires ecx >= 2)
// -------------------------------------------------------------------

  cmp       ecx, 2
  jb        @@eax_dec_tail

@@eax_dec_pair_loop:

  // CTR A = BE(counter_i); CTR B = BE(counter_{i+1}); xmm6 <- LE(counter_{i+2}).
  movdqa    xmm0, xmm6                              // counter_i (LE)
  pshufb    xmm0, xmm7                              // counter_i (BE)
  paddq     xmm6, xmm5                              // counter_{i+1} (LE)
  movdqa    xmm4, xmm6                              // counter_{i+1} (LE)
  pshufb    xmm4, xmm7                              // counter_{i+1} (BE) -- CTR B lane
  paddq     xmm6, xmm5                              // counter_{i+2} (LE)

  // Load C_i; fold into MAC lane. xmm3 keeps C_i for the post-AES
  // keystream XOR.
  movdqu    xmm3, [eax]                             // xmm3 = C_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR C_i

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
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $E2
  db $66, $0F, $38, $DC, $CA
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

  // Produce P_i = keystream_i XOR C_i; store.
  pxor      xmm0, xmm3
  movdqu    [esi], xmm0

  // Reload xmm3 = C_{i+1}; produce P_{i+1} and store.
  movdqu    xmm3, [eax + 16]
  pxor      xmm4, xmm3
  movdqu    [esi + 16], xmm4

  // Serial MAC chain for block i+1.
  pxor      xmm1, xmm3                              // xmm1 = M_i XOR C_{i+1}

  movdqa    xmm2, [edx]
  pxor      xmm1, xmm2
  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $CA
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $CA
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
  jae       @@eax_dec_pair_loop

@@eax_dec_tail:
  // Single-block 2-wide tail. Entered when 0 or 1 blocks remain after
  // the pair loop.
  test      ecx, ecx
  jz        @@eax_dec_done

  movdqu    xmm3, [eax]                             // C_i
  pxor      xmm1, xmm3                              // MAC input = M_{i-1} XOR C_i

  movdqa    xmm0, xmm6                              // LE
  pshufb    xmm0, xmm7                              // BE
  paddq     xmm6, xmm5                              // advance LE

  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2
  db $66, $0F, $38, $DC, $CA
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

  pxor      xmm0, xmm3                              // P_i
  movdqu    [esi], xmm0

@@eax_dec_done:

{$ENDIF} // CRYPTOLIB_EAX_DECRYPT

// -------------------------------------------------------------------
// Epilogue: convert xmm6 LE -> BE, write back CtrState and OmacState,
// restore callee-saved GPRs (edi/esi/ebx).
// -------------------------------------------------------------------

  pshufb    xmm6, xmm7                              // xmm6 = counter (BE) for storage
  mov       edi, [ebx + 12]
  movdqu    [edi], xmm6                             // CtrState <- counter
  mov       edi, [ebx + 16]
  movdqu    [edi], xmm1                             // OmacState <- final OMAC

  pop       edi
  pop       esi
  pop       ebx
