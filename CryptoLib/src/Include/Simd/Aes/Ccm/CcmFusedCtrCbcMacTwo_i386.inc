// CCM fused 2-wide AES-NI CTR+CBC-MAC kernel (i386).
// -------------------------------------------------------------------
// 32-bit sibling of CcmFusedCtrCbcMacTwo_x86_64.inc. Mirrors OpenSSL's
// aesni-x86.pl:659-854 layout for aesni_ccm64_encrypt_blocks /
// aesni_ccm64_decrypt_blocks. Technique identical to the x86_64 kernel:
// two AES lanes (CTR / MAC) issued per round-key broadcast, which is
// the source of the CCM speedup.
//
// The algorithm, context layout (field-for-field), and semantics are
// identical to CcmFusedCtrCbcMacTwo_x86_64.inc -- see that file for the
// full rationale of the encrypt/decrypt interleave, the "MAC lags CTR
// by one block" decrypt shape, and the trailing scalar MAC AES. The
// only differences here are:
//   - Pointer width is 4 bytes, so context field offsets compress:
//       [ebx +  0]  InPtr
//       [ebx +  4]  OutPtr
//       [ebx +  8]  Keys
//       [ebx + 12]  CtrState
//       [ebx + 16]  MacState
//       [ebx + 20]  PMask
//       [ebx + 24]  PIncrement
//       [ebx + 28]  BlockCount (NativeUInt = 4 bytes on i386)
//   - Only xmm0..xmm7 are available, so prev_P (decrypt only) is kept
//     in xmm4 instead of xmm8. AES-NI instructions (aesenc / aesenclast)
//     are db-encoded for broad assembler compatibility, matching the
//     pattern used by AesNiEightRoundsOnly_i386.inc. Standard SSE1/SSE2
//     instructions (movdqu, pxor) use FPC mnemonics.
//   - GPR set is tight (6 scratch total). esi/edi are callee-saved and
//     manually pushed/popped around the body; the SimdProc1Begin_i386
//     prologue already pushed ebx.
//
// On entry (after SimdProc1Begin_i386.inc): ebx = PCtx.
// The wrapping Pascal procedure must terminate with:
//   pop edi
//   pop esi
//   pop ebx
// before the final 'end;' that emits RET. This kernel does not emit
// those pops -- the utility unit's procedure body appends them after
// this inc file, matching the OCB i386 idiom.
//
// XMM register allocation (8 of 8 xmm registers used on i386):
//   xmm0 : CTR lane (transient; counter -> aesenc chain -> keystream)
//   xmm1 : MAC lane (running MAC state; per-iter becomes
//          M_{i-1} XOR P_i XOR K_0 before rounds; M_i after rounds)
//   xmm2 : round-key scratch (reloaded per round via movdqa)
//   xmm3 : data-block cache (P_i on encrypt, C_i on decrypt)
//   xmm4 : (decrypt only) prev_P slot, i.e. P_{i-1} carried across
//          iteration boundaries. Unused on encrypt.
//   xmm5 : CTR increment constant (loaded once from [ebx + 24])
//   xmm6 : CTR counter in BE form (persistent; transiently byteswapped
//          to LE during the paddq increment, then byteswapped back).
//   xmm7 : PSHUFB full-reverse mask (loaded once from [ebx + 20])
//
// GPR usage (i386 fastcall / nostackframe):
//   ebx : PCtx                              (preserved; prologue pushed)
//   eax : InPtr (advancing)                 (scratch)
//   esi : OutPtr (advancing)                (callee-saved; pushed here)
//   edx : Keys base                         (scratch)
//   ecx : BlockCount / loop counter         (scratch; decrementing)
//   edi : scratch (CtrState / MacState ptrs  (callee-saved; pushed here)
//         at prologue / epilogue)
//
// Direction : define CRYPTOLIB_CCM_DECRYPT for the decrypt variant.
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
  movdqu    xmm1, [edi]                             // xmm1 = MAC state (running)
  mov       edi, [ebx + 20]
  movdqu    xmm7, [edi]                             // xmm7 = byteswap mask
  mov       edi, [ebx + 24]
  movdqu    xmm5, [edi]                             // xmm5 = increment constant

{$IFNDEF CRYPTOLIB_CCM_DECRYPT}

// -------------------------------------------------------------------
// ENCRYPT direction: per-block interleaved CTR + MAC-on-plaintext.
// See CcmFusedCtrCbcMacTwo_x86_64.inc for the invariant.
// -------------------------------------------------------------------

@@ccm_enc_loop:

  movdqu    xmm3, [eax]                             // xmm3 = P_i
  pxor      xmm1, xmm3                              // xmm1 = M_{i-1} XOR P_i

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

  pxor      xmm0, xmm3                              // xmm0 = C_i
  movdqu    [esi], xmm0

  pshufb    xmm6, xmm7                              // BE -> LE
  paddq     xmm6, xmm5                              // counter_LE += 1
  pshufb    xmm6, xmm7                              // LE -> BE

  add       eax, 16
  add       esi, 16
  dec       ecx
  jnz       @@ccm_enc_loop

{$ELSE} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// DECRYPT direction: MAC lags CTR by one block.
// Pass 1: cold CTR-only on block 0 (MAC idle).
// Pass 2: BlockCount-1 interleaved iterations.
// Pass 3: trailing scalar MAC AES on P_{last}.
// -------------------------------------------------------------------

  // -------------------- Pass 1: block 0 CTR-only -------------------
  movdqa    xmm0, xmm6
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

  movdqu    xmm3, [eax]                             // xmm3 = C_0
  pxor      xmm0, xmm3                              // xmm0 = P_0
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // xmm4 = prev_P = P_0

  pshufb    xmm6, xmm7
  paddq     xmm6, xmm5
  pshufb    xmm6, xmm7

  add       eax, 16
  add       esi, 16
  dec       ecx
  jz        @@ccm_dec_trailing

  // -------------------- Pass 2: interleaved iters 1..N-1 -----------
@@ccm_dec_loop:

  movdqu    xmm3, [eax]                             // xmm3 = C_i
  pxor      xmm1, xmm4                              // MAC input = M_{i-1} XOR P_{i-1}

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

  pxor      xmm0, xmm3                              // xmm0 = P_i
  movdqu    [esi], xmm0
  movdqa    xmm4, xmm0                              // xmm4 = prev_P = P_i

  pshufb    xmm6, xmm7
  paddq     xmm6, xmm5
  pshufb    xmm6, xmm7

  add       eax, 16
  add       esi, 16
  dec       ecx
  jnz       @@ccm_dec_loop

@@ccm_dec_trailing:
  // -------------------- Pass 3: trailing scalar MAC ----------------
  pxor      xmm1, xmm4                              // M XOR P_{last}

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
  db $66, $0F, $38, $DD, $CA                        // aesenclast xmm1, xmm2  -> xmm1 = final MAC state

{$ENDIF} // CRYPTOLIB_CCM_DECRYPT

// -------------------------------------------------------------------
// Epilogue: write back CtrState and MacState, restore callee-saved
// GPRs (edi/esi/ebx). This kernel owns the full epilogue -- the
// wrapping Pascal procedure only emits 'end;' (the ret) per the
// SimdProc1Begin_i386.inc prologue contract.
// -------------------------------------------------------------------

  mov       edi, [ebx + 12]
  movdqu    [edi], xmm6                             // CtrState <- counter
  mov       edi, [ebx + 16]
  movdqu    [edi], xmm1                             // MacState <- final MAC

  pop       edi
  pop       esi
  pop       ebx
