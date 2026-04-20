// EAX fused 2-wide AES-NI CTR+OMAC kernel (i386).
// -------------------------------------------------------------------
// 32-bit sibling of EaxFusedCtrOmacTwo_x86_64.inc. See that file for
// the full rationale of the mirror between EAX and CCM kernels, the
// "MAC lags CTR by one block" encrypt shape, the OMAC / CBC-MAC
// invariant, and the novelty note (no mainstream library ships a
// fused EAX kernel).
//
// On entry (after SimdProc1Begin_i386.inc): ebx = PCtx.
// The wrapping Pascal procedure is responsible for popping edi/esi/ebx
// -- this kernel owns the full epilogue.
//
// Context field offsets (4-byte pointer width on i386):
//   [ebx +  0]  InPtr
//   [ebx +  4]  OutPtr
//   [ebx +  8]  Keys
//   [ebx + 12]  CtrState
//   [ebx + 16]  OmacState
//   [ebx + 20]  PMask
//   [ebx + 24]  PIncrement
//   [ebx + 28]  BlockCount (NativeUInt = 4 bytes)
//
// XMM register allocation (8 of 8 xmm registers used on i386):
//   xmm0 : CTR lane (transient; counter -> aesenc chain -> keystream)
//   xmm1 : MAC lane (running OMAC state; per-iter becomes
//          M_{i-1} XOR <ciphertext_lag_or_input> XOR K_0 before rounds;
//          M_i after rounds)
//   xmm2 : round-key scratch (reloaded per round via movdqa)
//   xmm3 : data-block cache (P_i on encrypt, C_i on decrypt)
//   xmm4 : (encrypt only) prev_C slot, i.e. C_{i-1} carried across
//          iteration boundaries. Unused on decrypt.
//   xmm5 : CTR increment constant (loaded once from [ebx + 24])
//   xmm6 : CTR counter in BE form
//   xmm7 : PSHUFB full-reverse mask (loaded once from [ebx + 20])
//
// GPR usage (i386 fastcall / nostackframe):
//   ebx : PCtx                             (preserved; prologue pushed)
//   eax : InPtr (advancing)                (scratch)
//   esi : OutPtr (advancing)               (callee-saved; pushed here)
//   edx : Keys base                        (scratch)
//   ecx : BlockCount / loop counter        (scratch; decrementing)
//   edi : scratch (CtrState / OmacState ptrs at prologue / epilogue)
//
// Direction : define CRYPTOLIB_EAX_DECRYPT for the decrypt variant.
// Key size  : define exactly ONE of CRYPTOLIB_AESNI_KEY128 /
//             CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256.
//
// -------------------------------------------------------------------
// Prologue: save callee-saved, load pointers and persistent state.
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

{$IFDEF CRYPTOLIB_EAX_DECRYPT}

// -------------------------------------------------------------------
// DECRYPT direction: per-block interleaved CTR + MAC-on-input-ciphertext.
// No lag; MAC substrate (ciphertext) is the input, available at iter
// start. Mirrors the CCM encrypt shape.
// -------------------------------------------------------------------

@@eax_dec_loop:

  movdqu    xmm3, [eax]                             // xmm3 = C_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR C_i

  movdqa    xmm0, xmm6                              // xmm0 = counter_i (BE)

  movdqa    xmm2, [edx]                             // K_0
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0, xmm2  -> xmm0 = keystream_i
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> xmm1 = M_i

  pxor      xmm0, xmm3                              // xmm0 = P_i = C_i XOR keystream
  movdqu    [esi], xmm0

  pshufb    xmm6, xmm7                              // BE -> LE
  paddq     xmm6, xmm5                              // counter_LE += 1
  pshufb    xmm6, xmm7                              // LE -> BE

  add       eax, 16
  add       esi, 16
  dec       ecx
  jnz       @@eax_dec_loop

{$ELSE} // !CRYPTOLIB_EAX_DECRYPT  (encrypt path)

// -------------------------------------------------------------------
// ENCRYPT direction: MAC lags CTR by one block via xmm4 = prev_C.
// Pass 1: cold CTR-only on block 0.
// Pass 2: BlockCount-1 interleaved iterations.
// Pass 3: trailing scalar MAC AES on C_{last}.
// Mirrors the CCM decrypt shape.
// -------------------------------------------------------------------

  // -------------------- Pass 1: block 0 CTR-only -------------------
  movdqa    xmm0, xmm6                              // xmm0 = counter_0 (BE)
  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
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
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0, xmm2  -> xmm0 = keystream_0

  movdqu    xmm3, [eax]                             // xmm3 = P_0
  pxor      xmm0, xmm3                              // xmm0 = C_0
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // xmm4 = prev_C = C_0

  pshufb    xmm6, xmm7
  paddq     xmm6, xmm5
  pshufb    xmm6, xmm7

  add       eax, 16
  add       esi, 16
  dec       ecx
  jz        @@eax_enc_trailing

  // -------------------- Pass 2: interleaved iters 1..N-1 -----------
@@eax_enc_loop:

  movdqu    xmm3, [eax]                             // xmm3 = P_i
  pxor      xmm1, xmm4                              // MAC input = M_{i-1} XOR C_{i-1}

  movdqa    xmm0, xmm6

  movdqa    xmm2, [edx]
  pxor      xmm0, xmm2
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $C2                        // aesenc xmm0, xmm2
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $C2                        // aesenclast xmm0, xmm2  -> xmm0 = keystream_i
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> xmm1 = M_i

  pxor      xmm0, xmm3                              // xmm0 = C_i
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // xmm4 = prev_C = C_i

  pshufb    xmm6, xmm7
  paddq     xmm6, xmm5
  pshufb    xmm6, xmm7

  add       eax, 16
  add       esi, 16
  dec       ecx
  jnz       @@eax_enc_loop

@@eax_enc_trailing:
  // -------------------- Pass 3: trailing scalar MAC ----------------
  pxor      xmm1, xmm4                              // M XOR C_{last}

  movdqa    xmm2, [edx]
  pxor      xmm1, xmm2

  movdqa    xmm2, [edx + 16]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 32]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 48]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 64]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 80]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 96]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 112]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 128]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 144]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
{$ENDIF}
{$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqa    xmm2, [edx + 160]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 176]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 192]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
  movdqa    xmm2, [edx + 208]
  db $66, $0F, $38, $DC, $CA                        // aesenc xmm1, xmm2
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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> xmm1 = final OMAC state

{$ENDIF} // CRYPTOLIB_EAX_DECRYPT

// -------------------------------------------------------------------
// Epilogue: write back CtrState and OmacState, restore callee-saved
// GPRs (edi/esi/ebx). This kernel owns the full epilogue -- the
// wrapping Pascal procedure only emits 'end;' (the ret) per the
// SimdProc1Begin_i386.inc prologue contract.
// -------------------------------------------------------------------

  mov       edi, [ebx + 12]
  movdqu    [edi], xmm6                             // CtrState <- counter
  mov       edi, [ebx + 16]
  movdqu    [edi], xmm1                             // OmacState <- final OMAC

  pop       edi
  pop       esi
  pop       ebx
