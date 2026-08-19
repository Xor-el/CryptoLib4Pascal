// ChaCha20-Poly1305 fused kernel (i386).
// -------------------------------------------------------------------
// Radix-2^26 scalar Poly1305 (poly1305-donna-32 shape: five 26-bit limbs;
// i386 has no 64-bit registers), sharing one .inc with two selectors: the
// bare block loop and the AEAD kernel that interleaves it with 4-way SSE2
// ChaCha20. h0..h4, r0..r4, s1..s4 (= 5*r1..5*r4) and the five 64-bit d
// accumulators are frame-resident; 32x32->64 products land in edx:eax. Per
// block: h += m (26-bit limbs via shrd), d_j = sum h_i*(r|s), 26-bit carry
// propagation, then the 5*(carry) fold of the >2^130 limb.
//
// Variant selection (set EXACTLY ONE):
//   CRYPTOLIB_CHACHAPOLY_POLY_ONLY - the block loop alone. Absorbs ABlockCount
//     full 16-byte blocks (padbit = 1) from a source pointer into the
//     accumulator. On entry (after ClpSimdProc3Begin_i386.inc): ebx = APolyState
//     ; esi = ASrc (16*ABlockCount bytes) ; edi = ABlockCount. Only h0..h4
//     (in/out) and r0..r4/s1..s4 (in) are touched. GPR: esi = src (advances
//     +16/block) ; eax/ebx/ecx/edx/edi = mul/carry scratch (eax:edx = the mul
//     pair); loop count + state base live in frame slots so all six GPRs are
//     free (callee-saved ebx/esi/edi = the ClpSimdProc3Begin push/pop pair).
//   CRYPTOLIB_CHACHAPOLY_FUSED - the AEAD kernel over N 256-byte (4-block)
//     groups. Generates ChaCha20 keystream 4 blocks at a time (identical bytes
//     to the standalone ChaCha7539Blocks4Sse2_i386 kernel), XORs it against AIn
//     into AOut, and folds the ciphertext into the accumulator with the poly's
//     mul/carry chains spliced through the vector rounds so the integer and
//     vector ports overlap. The SSE2 rounds touch only xmm0-4 + esp, so all six
//     GPRs are free: esi pins the fold source, eax/ebx/ecx/edx/edi carry the mul
//     (eax:edx) and carry chains, and h0..h4/r0..r4/s1..s4/d0..d4 live in frame
//     slots above the ChaCha frame. 5-arg proc; the ClpSimdProc5Begin_i386.inc
//     prologue pushes ebx/esi/edi and normalizes the all-4-byte args to
//     ebx=APolyState, esi=AState, edi=AIn, eax=AOut, ecx=AGroups (edx free).
//     The dead ARounds arg is not passed on i386. The epilogue pops edi/esi/ebx.
//
// APolyState (consecutive UInt32): h0,h1,h2,h3,h4, r0,r1,r2,r3,r4, s1,s2,s3,s4,
//   pad0,pad1,pad2,pad3, FoldFromInput. h0..h4 (in/out) and r0..r4/s1..s4 (in)
//   are used by the asm; pad0..pad3 untouched (the final reduce+tag is a separate
//   arch-neutral step). AState word-12 counter (byte 48) advances by 4 per group
//   (IETF 32-bit). FoldFromInput @ byte 72 selects 0 = ENCRYPT (lagged: peel
//   group 0, fold the previous group's [AOut-256], scalar drain) / 1 = DECRYPT
//   (fold the current [AIn], no lag/peel/drain - AIn==AOut safe).
//
// The SSE2 ChaCha vector forms (pshufd/punpck*/...) are db-encoded for broad
// assembler compatibility.

{$IFDEF CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
  sub     esp, 112
  // ---- park the block count and the state base (the block loop needs edi/ebx) ----
  mov     dword ptr [esp + 96], edi
  mov     dword ptr [esp + 100], ebx
  // ---- load poly key limbs r0..r4 / s1..s4 and accumulator h0..h4 ----
  mov     eax, dword ptr [ebx + 20]
  mov     dword ptr [esp], eax
  mov     eax, dword ptr [ebx + 24]
  mov     dword ptr [esp + 4], eax
  mov     eax, dword ptr [ebx + 28]
  mov     dword ptr [esp + 8], eax
  mov     eax, dword ptr [ebx + 32]
  mov     dword ptr [esp + 12], eax
  mov     eax, dword ptr [ebx + 36]
  mov     dword ptr [esp + 16], eax
  mov     eax, dword ptr [ebx + 40]
  mov     dword ptr [esp + 20], eax
  mov     eax, dword ptr [ebx + 44]
  mov     dword ptr [esp + 24], eax
  mov     eax, dword ptr [ebx + 48]
  mov     dword ptr [esp + 28], eax
  mov     eax, dword ptr [ebx + 52]
  mov     dword ptr [esp + 32], eax
  mov     eax, dword ptr [ebx + 0]
  mov     dword ptr [esp + 36], eax
  mov     eax, dword ptr [ebx + 4]
  mov     dword ptr [esp + 40], eax
  mov     eax, dword ptr [ebx + 8]
  mov     dword ptr [esp + 44], eax
  mov     eax, dword ptr [ebx + 12]
  mov     dword ptr [esp + 48], eax
  mov     eax, dword ptr [ebx + 16]
  mov     dword ptr [esp + 52], eax
  cmp     dword ptr [esp + 96], 0
  je      @@poly_r26_done

@@poly_r26_loop:
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 36], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 40], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 44], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 48], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 52], eax
  mov     eax, dword ptr [esp + 36]
  mul     dword ptr [esp]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 40]
  mul     dword ptr [esp + 32]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 44]
  mul     dword ptr [esp + 28]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 48]
  mul     dword ptr [esp + 24]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 52]
  mul     dword ptr [esp + 20]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 56], edi
  mov     dword ptr [esp + 60], ebx
  mov     eax, dword ptr [esp + 36]
  mul     dword ptr [esp + 4]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 40]
  mul     dword ptr [esp]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 44]
  mul     dword ptr [esp + 32]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 48]
  mul     dword ptr [esp + 28]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 52]
  mul     dword ptr [esp + 24]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 64], edi
  mov     dword ptr [esp + 68], ebx
  mov     eax, dword ptr [esp + 36]
  mul     dword ptr [esp + 8]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 40]
  mul     dword ptr [esp + 4]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 44]
  mul     dword ptr [esp]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 48]
  mul     dword ptr [esp + 32]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 52]
  mul     dword ptr [esp + 28]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 72], edi
  mov     dword ptr [esp + 76], ebx
  mov     eax, dword ptr [esp + 36]
  mul     dword ptr [esp + 12]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 40]
  mul     dword ptr [esp + 8]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 44]
  mul     dword ptr [esp + 4]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 48]
  mul     dword ptr [esp]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 52]
  mul     dword ptr [esp + 32]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 80], edi
  mov     dword ptr [esp + 84], ebx
  mov     eax, dword ptr [esp + 36]
  mul     dword ptr [esp + 16]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 40]
  mul     dword ptr [esp + 12]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 44]
  mul     dword ptr [esp + 8]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 48]
  mul     dword ptr [esp + 4]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 52]
  mul     dword ptr [esp]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 88], edi
  mov     dword ptr [esp + 92], ebx
  mov     eax, dword ptr [esp + 56]
  mov     edx, dword ptr [esp + 60]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 36], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 64]
  mov     ebx, dword ptr [esp + 68]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 40], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 72]
  mov     ebx, dword ptr [esp + 76]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 44], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 80]
  mov     ebx, dword ptr [esp + 84]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 48], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 88]
  mov     ebx, dword ptr [esp + 92]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 52], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 36]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 36], ecx
  shr     eax, 26
  add     dword ptr [esp + 40], eax
  add     esi, 16
  // ---- decrement block count ----
  dec     dword ptr [esp + 96]
  jnz     @@poly_r26_loop

@@poly_r26_done:
  // ---- write the accumulator h0..h4 back to APolyState ----
  mov     ebx, dword ptr [esp + 100]
  mov     eax, dword ptr [esp + 36]
  mov     dword ptr [ebx + 0], eax
  mov     eax, dword ptr [esp + 40]
  mov     dword ptr [ebx + 4], eax
  mov     eax, dword ptr [esp + 44]
  mov     dword ptr [ebx + 8], eax
  mov     eax, dword ptr [esp + 48]
  mov     dword ptr [ebx + 12], eax
  mov     eax, dword ptr [esp + 52]
  mov     dword ptr [ebx + 16], eax
  add     esp, 112
  // ---- restore callee-saved GPRs (ClpSimdProc3Begin pushed ebx/esi/edi) ----
  pop     edi
  pop     esi
  pop     ebx
{$ENDIF CRYPTOLIB_CHACHAPOLY_POLY_ONLY}

{$IFDEF CRYPTOLIB_CHACHAPOLY_FUSED}
  // ---- build the 64B-aligned frame; park the original (post-push) esp ----
  mov     edx, esp
  sub     esp, 704
  and     esp, -64
  mov     dword ptr [esp + 544], edx
  // ---- spill the ChaCha pointers + APolyState to frame slots ----
  mov     dword ptr [esp + 672], esi      // AState
  mov     dword ptr [esp + 676], edi      // AIn
  mov     dword ptr [esp + 680], eax      // AOut
  mov     dword ptr [esp + 684], ecx      // AGroups
  mov     dword ptr [esp + 688], ebx      // APolyState
  mov     edx, ebx
  // ---- load poly key limbs r0..r4 / s1..s4 and accumulator h0..h4 ----
  mov     eax, dword ptr [edx + 20]
  mov     dword ptr [esp + 576], eax
  mov     eax, dword ptr [edx + 24]
  mov     dword ptr [esp + 580], eax
  mov     eax, dword ptr [edx + 28]
  mov     dword ptr [esp + 584], eax
  mov     eax, dword ptr [edx + 32]
  mov     dword ptr [esp + 588], eax
  mov     eax, dword ptr [edx + 36]
  mov     dword ptr [esp + 592], eax
  mov     eax, dword ptr [edx + 40]
  mov     dword ptr [esp + 596], eax
  mov     eax, dword ptr [edx + 44]
  mov     dword ptr [esp + 600], eax
  mov     eax, dword ptr [edx + 48]
  mov     dword ptr [esp + 604], eax
  mov     eax, dword ptr [edx + 52]
  mov     dword ptr [esp + 608], eax
  mov     eax, dword ptr [edx + 0]
  mov     dword ptr [esp + 612], eax
  mov     eax, dword ptr [edx + 4]
  mov     dword ptr [esp + 616], eax
  mov     eax, dword ptr [edx + 8]
  mov     dword ptr [esp + 620], eax
  mov     eax, dword ptr [edx + 12]
  mov     dword ptr [esp + 624], eax
  mov     eax, dword ptr [edx + 16]
  mov     dword ptr [esp + 628], eax
  // ---- one-time ChaCha state broadcast (esi = AState) ----
  mov     dword ptr [esp + 512], 0
  mov     dword ptr [esp + 516], 1
  mov     dword ptr [esp + 520], 2
  mov     dword ptr [esp + 524], 3
  mov     dword ptr [esp + 528], 4
  mov     dword ptr [esp + 532], 4
  mov     dword ptr [esp + 536], 4
  mov     dword ptr [esp + 540], 4
  movd    xmm0, [esi]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp], xmm0
  movdqa  [esp + 256], xmm0
  movd    xmm0, [esi + 4]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 272], xmm0
  movd    xmm0, [esi + 8]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 288], xmm0
  movd    xmm0, [esi + 12]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 304], xmm0
  movd    xmm0, [esi + 16]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 64], xmm0
  movdqa  [esp + 320], xmm0
  movd    xmm0, [esi + 20]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 80], xmm0
  movdqa  [esp + 336], xmm0
  movd    xmm0, [esi + 24]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 96], xmm0
  movdqa  [esp + 352], xmm0
  movd    xmm0, [esi + 28]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 112], xmm0
  movdqa  [esp + 368], xmm0
  movd    xmm0, [esi + 32]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 128], xmm0
  movdqa  [esp + 384], xmm0
  movd    xmm0, [esi + 36]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 144], xmm0
  movdqa  [esp + 400], xmm0
  movd    xmm0, [esi + 40]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 160], xmm0
  movdqa  [esp + 416], xmm0
  movd    xmm0, [esi + 44]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 176], xmm0
  movdqa  [esp + 432], xmm0
  movd    xmm0, [esi + 48]
  pshufd  xmm0, xmm0, $00
  db $66, $0F, $FE, $84, $24, $00, $02, $00, $00  // paddd xmm0, [esp + 512]
  movdqa  [esp + 192], xmm0
  movdqa  [esp + 448], xmm0
  movd    xmm0, [esi + 52]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 208], xmm0
  movdqa  [esp + 464], xmm0
  movd    xmm0, [esi + 56]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 224], xmm0
  movdqa  [esp + 480], xmm0
  movd    xmm0, [esi + 60]
  pshufd  xmm0, xmm0, $00
  movdqa  [esp + 240], xmm0
  movdqa  [esp + 496], xmm0
  // ---- select the fold path on FoldFromInput ----
  mov     eax, dword ptr [edx + 72]      // FoldFromInput
  test    eax, eax
  jnz     @@cp_decrypt

  // ================= ENCRYPT (lagged: fold ciphertext at [AOut-256]) =====
  // ---- peel group 0: keystream only, no poly (no ciphertext yet) ----
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     esi, dword ptr [esp + 672]
  add     dword ptr [esi + 48], 4
  mov     edi, dword ptr [esp + 676]
  mov     eax, dword ptr [esp + 680]
  movdqa  xmm0, [esp]
  db $66, $0F, $FE, $84, $24, $00, $01, $00, $00  // paddd xmm0, [esp + 256]
  movdqa  xmm1, [esp + 16]
  db $66, $0F, $FE, $8C, $24, $10, $01, $00, $00  // paddd xmm1, [esp + 272]
  movdqa  xmm2, [esp + 32]
  db $66, $0F, $FE, $94, $24, $20, $01, $00, $00  // paddd xmm2, [esp + 288]
  movdqa  xmm3, [esp + 48]
  db $66, $0F, $FE, $9C, $24, $30, $01, $00, $00  // paddd xmm3, [esp + 304]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi]
  pxor    xmm0, xmm5
  movdqu  [eax], xmm0
  movdqu  xmm5, [edi + 64]
  pxor    xmm1, xmm5
  movdqu  [eax + 64], xmm1
  movdqu  xmm5, [edi + 128]
  pxor    xmm4, xmm5
  movdqu  [eax + 128], xmm4
  movdqu  xmm5, [edi + 192]
  pxor    xmm3, xmm5
  movdqu  [eax + 192], xmm3
  movdqa  xmm0, [esp + 64]
  db $66, $0F, $FE, $84, $24, $40, $01, $00, $00  // paddd xmm0, [esp + 320]
  movdqa  xmm1, [esp + 80]
  db $66, $0F, $FE, $8C, $24, $50, $01, $00, $00  // paddd xmm1, [esp + 336]
  movdqa  xmm2, [esp + 96]
  db $66, $0F, $FE, $94, $24, $60, $01, $00, $00  // paddd xmm2, [esp + 352]
  movdqa  xmm3, [esp + 112]
  db $66, $0F, $FE, $9C, $24, $70, $01, $00, $00  // paddd xmm3, [esp + 368]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 16]
  pxor    xmm0, xmm5
  movdqu  [eax + 16], xmm0
  movdqu  xmm5, [edi + 80]
  pxor    xmm1, xmm5
  movdqu  [eax + 80], xmm1
  movdqu  xmm5, [edi + 144]
  pxor    xmm4, xmm5
  movdqu  [eax + 144], xmm4
  movdqu  xmm5, [edi + 208]
  pxor    xmm3, xmm5
  movdqu  [eax + 208], xmm3
  movdqa  xmm0, [esp + 128]
  db $66, $0F, $FE, $84, $24, $80, $01, $00, $00  // paddd xmm0, [esp + 384]
  movdqa  xmm1, [esp + 144]
  db $66, $0F, $FE, $8C, $24, $90, $01, $00, $00  // paddd xmm1, [esp + 400]
  movdqa  xmm2, [esp + 160]
  db $66, $0F, $FE, $94, $24, $A0, $01, $00, $00  // paddd xmm2, [esp + 416]
  movdqa  xmm3, [esp + 176]
  db $66, $0F, $FE, $9C, $24, $B0, $01, $00, $00  // paddd xmm3, [esp + 432]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 32]
  pxor    xmm0, xmm5
  movdqu  [eax + 32], xmm0
  movdqu  xmm5, [edi + 96]
  pxor    xmm1, xmm5
  movdqu  [eax + 96], xmm1
  movdqu  xmm5, [edi + 160]
  pxor    xmm4, xmm5
  movdqu  [eax + 160], xmm4
  movdqu  xmm5, [edi + 224]
  pxor    xmm3, xmm5
  movdqu  [eax + 224], xmm3
  movdqa  xmm0, [esp + 192]
  db $66, $0F, $FE, $84, $24, $C0, $01, $00, $00  // paddd xmm0, [esp + 448]
  movdqa  xmm1, [esp + 208]
  db $66, $0F, $FE, $8C, $24, $D0, $01, $00, $00  // paddd xmm1, [esp + 464]
  movdqa  xmm2, [esp + 224]
  db $66, $0F, $FE, $94, $24, $E0, $01, $00, $00  // paddd xmm2, [esp + 480]
  movdqa  xmm3, [esp + 240]
  db $66, $0F, $FE, $9C, $24, $F0, $01, $00, $00  // paddd xmm3, [esp + 496]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 48]
  pxor    xmm0, xmm5
  movdqu  [eax + 48], xmm0
  movdqu  xmm5, [edi + 112]
  pxor    xmm1, xmm5
  movdqu  [eax + 112], xmm1
  movdqu  xmm5, [edi + 176]
  pxor    xmm4, xmm5
  movdqu  [eax + 176], xmm4
  movdqu  xmm5, [edi + 240]
  pxor    xmm3, xmm5
  movdqu  [eax + 240], xmm3
  add     dword ptr [esp + 676], 256
  add     dword ptr [esp + 680], 256
  dec     dword ptr [esp + 684]
  jz      @@cp_enc_drain
@@cp_enc_loop:
  movdqa  xmm0, [esp + 256]
  movdqa  [esp], xmm0
  movdqa  xmm0, [esp + 272]
  movdqa  [esp + 16], xmm0
  movdqa  xmm0, [esp + 288]
  movdqa  [esp + 32], xmm0
  movdqa  xmm0, [esp + 304]
  movdqa  [esp + 48], xmm0
  movdqa  xmm0, [esp + 320]
  movdqa  [esp + 64], xmm0
  movdqa  xmm0, [esp + 336]
  movdqa  [esp + 80], xmm0
  movdqa  xmm0, [esp + 352]
  movdqa  [esp + 96], xmm0
  movdqa  xmm0, [esp + 368]
  movdqa  [esp + 112], xmm0
  movdqa  xmm0, [esp + 384]
  movdqa  [esp + 128], xmm0
  movdqa  xmm0, [esp + 400]
  movdqa  [esp + 144], xmm0
  movdqa  xmm0, [esp + 416]
  movdqa  [esp + 160], xmm0
  movdqa  xmm0, [esp + 432]
  movdqa  [esp + 176], xmm0
  movdqa  xmm0, [esp + 448]
  db $66, $0F, $FE, $84, $24, $10, $02, $00, $00  // paddd xmm0, [esp + 528]
  movdqa  [esp + 448], xmm0
  movdqa  [esp + 192], xmm0
  movdqa  xmm0, [esp + 464]
  movdqa  [esp + 208], xmm0
  movdqa  xmm0, [esp + 480]
  movdqa  [esp + 224], xmm0
  movdqa  xmm0, [esp + 496]
  movdqa  [esp + 240], xmm0
  // ---- fold the PREVIOUS group's ciphertext (output) while encrypting ----
  mov     esi, dword ptr [esp + 680]
  sub     esi, 256
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     esi, dword ptr [esp + 672]
  add     dword ptr [esi + 48], 4
  mov     edi, dword ptr [esp + 676]
  mov     eax, dword ptr [esp + 680]
  movdqa  xmm0, [esp]
  db $66, $0F, $FE, $84, $24, $00, $01, $00, $00  // paddd xmm0, [esp + 256]
  movdqa  xmm1, [esp + 16]
  db $66, $0F, $FE, $8C, $24, $10, $01, $00, $00  // paddd xmm1, [esp + 272]
  movdqa  xmm2, [esp + 32]
  db $66, $0F, $FE, $94, $24, $20, $01, $00, $00  // paddd xmm2, [esp + 288]
  movdqa  xmm3, [esp + 48]
  db $66, $0F, $FE, $9C, $24, $30, $01, $00, $00  // paddd xmm3, [esp + 304]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi]
  pxor    xmm0, xmm5
  movdqu  [eax], xmm0
  movdqu  xmm5, [edi + 64]
  pxor    xmm1, xmm5
  movdqu  [eax + 64], xmm1
  movdqu  xmm5, [edi + 128]
  pxor    xmm4, xmm5
  movdqu  [eax + 128], xmm4
  movdqu  xmm5, [edi + 192]
  pxor    xmm3, xmm5
  movdqu  [eax + 192], xmm3
  movdqa  xmm0, [esp + 64]
  db $66, $0F, $FE, $84, $24, $40, $01, $00, $00  // paddd xmm0, [esp + 320]
  movdqa  xmm1, [esp + 80]
  db $66, $0F, $FE, $8C, $24, $50, $01, $00, $00  // paddd xmm1, [esp + 336]
  movdqa  xmm2, [esp + 96]
  db $66, $0F, $FE, $94, $24, $60, $01, $00, $00  // paddd xmm2, [esp + 352]
  movdqa  xmm3, [esp + 112]
  db $66, $0F, $FE, $9C, $24, $70, $01, $00, $00  // paddd xmm3, [esp + 368]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 16]
  pxor    xmm0, xmm5
  movdqu  [eax + 16], xmm0
  movdqu  xmm5, [edi + 80]
  pxor    xmm1, xmm5
  movdqu  [eax + 80], xmm1
  movdqu  xmm5, [edi + 144]
  pxor    xmm4, xmm5
  movdqu  [eax + 144], xmm4
  movdqu  xmm5, [edi + 208]
  pxor    xmm3, xmm5
  movdqu  [eax + 208], xmm3
  movdqa  xmm0, [esp + 128]
  db $66, $0F, $FE, $84, $24, $80, $01, $00, $00  // paddd xmm0, [esp + 384]
  movdqa  xmm1, [esp + 144]
  db $66, $0F, $FE, $8C, $24, $90, $01, $00, $00  // paddd xmm1, [esp + 400]
  movdqa  xmm2, [esp + 160]
  db $66, $0F, $FE, $94, $24, $A0, $01, $00, $00  // paddd xmm2, [esp + 416]
  movdqa  xmm3, [esp + 176]
  db $66, $0F, $FE, $9C, $24, $B0, $01, $00, $00  // paddd xmm3, [esp + 432]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 32]
  pxor    xmm0, xmm5
  movdqu  [eax + 32], xmm0
  movdqu  xmm5, [edi + 96]
  pxor    xmm1, xmm5
  movdqu  [eax + 96], xmm1
  movdqu  xmm5, [edi + 160]
  pxor    xmm4, xmm5
  movdqu  [eax + 160], xmm4
  movdqu  xmm5, [edi + 224]
  pxor    xmm3, xmm5
  movdqu  [eax + 224], xmm3
  movdqa  xmm0, [esp + 192]
  db $66, $0F, $FE, $84, $24, $C0, $01, $00, $00  // paddd xmm0, [esp + 448]
  movdqa  xmm1, [esp + 208]
  db $66, $0F, $FE, $8C, $24, $D0, $01, $00, $00  // paddd xmm1, [esp + 464]
  movdqa  xmm2, [esp + 224]
  db $66, $0F, $FE, $94, $24, $E0, $01, $00, $00  // paddd xmm2, [esp + 480]
  movdqa  xmm3, [esp + 240]
  db $66, $0F, $FE, $9C, $24, $F0, $01, $00, $00  // paddd xmm3, [esp + 496]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 48]
  pxor    xmm0, xmm5
  movdqu  [eax + 48], xmm0
  movdqu  xmm5, [edi + 112]
  pxor    xmm1, xmm5
  movdqu  [eax + 112], xmm1
  movdqu  xmm5, [edi + 176]
  pxor    xmm4, xmm5
  movdqu  [eax + 176], xmm4
  movdqu  xmm5, [edi + 240]
  pxor    xmm3, xmm5
  movdqu  [eax + 240], xmm3
  add     dword ptr [esp + 676], 256
  add     dword ptr [esp + 680], 256
  dec     dword ptr [esp + 684]
  jnz     @@cp_enc_loop
@@cp_enc_drain:
  // ---- drain: fold the last group's ciphertext at [AOut-256] ----
  mov     esi, dword ptr [esp + 680]
  sub     esi, 256
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  jmp     @@cp_done

@@cp_decrypt:
  // ================= DECRYPT (current: fold ciphertext at [AIn]) ========
  jmp     @@cp_dec_enter
@@cp_dec_outer:
  movdqa  xmm0, [esp + 256]
  movdqa  [esp], xmm0
  movdqa  xmm0, [esp + 272]
  movdqa  [esp + 16], xmm0
  movdqa  xmm0, [esp + 288]
  movdqa  [esp + 32], xmm0
  movdqa  xmm0, [esp + 304]
  movdqa  [esp + 48], xmm0
  movdqa  xmm0, [esp + 320]
  movdqa  [esp + 64], xmm0
  movdqa  xmm0, [esp + 336]
  movdqa  [esp + 80], xmm0
  movdqa  xmm0, [esp + 352]
  movdqa  [esp + 96], xmm0
  movdqa  xmm0, [esp + 368]
  movdqa  [esp + 112], xmm0
  movdqa  xmm0, [esp + 384]
  movdqa  [esp + 128], xmm0
  movdqa  xmm0, [esp + 400]
  movdqa  [esp + 144], xmm0
  movdqa  xmm0, [esp + 416]
  movdqa  [esp + 160], xmm0
  movdqa  xmm0, [esp + 432]
  movdqa  [esp + 176], xmm0
  movdqa  xmm0, [esp + 448]
  db $66, $0F, $FE, $84, $24, $10, $02, $00, $00  // paddd xmm0, [esp + 528]
  movdqa  [esp + 448], xmm0
  movdqa  [esp + 192], xmm0
  movdqa  xmm0, [esp + 464]
  movdqa  [esp + 208], xmm0
  movdqa  xmm0, [esp + 480]
  movdqa  [esp + 224], xmm0
  movdqa  xmm0, [esp + 496]
  movdqa  [esp + 240], xmm0
@@cp_dec_enter:
  // ---- fold the CURRENT group's input ciphertext (read before the tail) ----
  mov     esi, dword ptr [esp + 676]
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 224], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp]
  movdqa  xmm1, [esp + 80]
  movdqa  xmm2, [esp + 160]
  movdqa  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp], xmm0
  movdqa  [esp + 80], xmm1
  movdqa  [esp + 160], xmm2
  movdqa  [esp + 240], xmm3
  movdqa  xmm0, [esp + 16]
  movdqa  xmm1, [esp + 96]
  movdqa  xmm2, [esp + 176]
  movdqa  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 16], xmm0
  movdqa  [esp + 96], xmm1
  movdqa  [esp + 176], xmm2
  movdqa  [esp + 192], xmm3
  movdqa  xmm0, [esp + 32]
  movdqa  xmm1, [esp + 112]
  movdqa  xmm2, [esp + 128]
  movdqa  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 32], xmm0
  movdqa  [esp + 112], xmm1
  movdqa  [esp + 128], xmm2
  movdqa  [esp + 208], xmm3
  movdqa  xmm0, [esp + 48]
  movdqa  xmm1, [esp + 64]
  movdqa  xmm2, [esp + 144]
  movdqa  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 16
  psrld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  pslld   xmm3, 8
  psrld   xmm4, 24
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqa  [esp + 48], xmm0
  movdqa  [esp + 64], xmm1
  movdqa  [esp + 144], xmm2
  movdqa  [esp + 224], xmm3
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     eax, dword ptr [esi]
  mov     ebx, dword ptr [esi + 4]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  add     dword ptr [esp + 612], ecx
  shrd    eax, ebx, 26
  and     eax, $03FFFFFF
  add     dword ptr [esp + 616], eax
  mov     eax, ebx
  mov     ecx, dword ptr [esi + 8]
  shrd    eax, ecx, 20
  and     eax, $03FFFFFF
  add     dword ptr [esp + 620], eax
  mov     eax, ecx
  mov     edx, dword ptr [esi + 12]
  shrd    eax, edx, 14
  and     eax, $03FFFFFF
  add     dword ptr [esp + 624], eax
  mov     eax, edx
  shr     eax, 8
  or      eax, $01000000
  add     dword ptr [esp + 628], eax
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 576]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 596]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 632], edi
  mov     dword ptr [esp + 636], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 580]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 600]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 640], edi
  mov     dword ptr [esp + 644], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 584]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 604]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 648], edi
  mov     dword ptr [esp + 652], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 588]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 608]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 656], edi
  mov     dword ptr [esp + 660], ebx
  mov     eax, dword ptr [esp + 612]
  mul     dword ptr [esp + 592]
  mov     edi, eax
  mov     ebx, edx
  mov     eax, dword ptr [esp + 616]
  mul     dword ptr [esp + 588]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 620]
  mul     dword ptr [esp + 584]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 624]
  mul     dword ptr [esp + 580]
  add     edi, eax
  adc     ebx, edx
  mov     eax, dword ptr [esp + 628]
  mul     dword ptr [esp + 576]
  add     edi, eax
  adc     ebx, edx
  mov     dword ptr [esp + 664], edi
  mov     dword ptr [esp + 668], ebx
  mov     eax, dword ptr [esp + 632]
  mov     edx, dword ptr [esp + 636]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shrd    eax, edx, 26
  mov     edi, dword ptr [esp + 640]
  mov     ebx, dword ptr [esp + 644]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 616], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 648]
  mov     ebx, dword ptr [esp + 652]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 620], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 656]
  mov     ebx, dword ptr [esp + 660]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 624], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  mov     edi, dword ptr [esp + 664]
  mov     ebx, dword ptr [esp + 668]
  add     edi, eax
  adc     ebx, 0
  mov     ecx, edi
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 628], ecx
  mov     eax, edi
  shrd    eax, ebx, 26
  lea     eax, [eax + eax*4]
  add     eax, dword ptr [esp + 612]
  mov     ecx, eax
  and     ecx, $03FFFFFF
  mov     dword ptr [esp + 612], ecx
  shr     eax, 26
  add     dword ptr [esp + 616], eax
  add     esi, 16
  mov     esi, dword ptr [esp + 672]
  add     dword ptr [esi + 48], 4
  mov     edi, dword ptr [esp + 676]
  mov     eax, dword ptr [esp + 680]
  movdqa  xmm0, [esp]
  db $66, $0F, $FE, $84, $24, $00, $01, $00, $00  // paddd xmm0, [esp + 256]
  movdqa  xmm1, [esp + 16]
  db $66, $0F, $FE, $8C, $24, $10, $01, $00, $00  // paddd xmm1, [esp + 272]
  movdqa  xmm2, [esp + 32]
  db $66, $0F, $FE, $94, $24, $20, $01, $00, $00  // paddd xmm2, [esp + 288]
  movdqa  xmm3, [esp + 48]
  db $66, $0F, $FE, $9C, $24, $30, $01, $00, $00  // paddd xmm3, [esp + 304]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi]
  pxor    xmm0, xmm5
  movdqu  [eax], xmm0
  movdqu  xmm5, [edi + 64]
  pxor    xmm1, xmm5
  movdqu  [eax + 64], xmm1
  movdqu  xmm5, [edi + 128]
  pxor    xmm4, xmm5
  movdqu  [eax + 128], xmm4
  movdqu  xmm5, [edi + 192]
  pxor    xmm3, xmm5
  movdqu  [eax + 192], xmm3
  movdqa  xmm0, [esp + 64]
  db $66, $0F, $FE, $84, $24, $40, $01, $00, $00  // paddd xmm0, [esp + 320]
  movdqa  xmm1, [esp + 80]
  db $66, $0F, $FE, $8C, $24, $50, $01, $00, $00  // paddd xmm1, [esp + 336]
  movdqa  xmm2, [esp + 96]
  db $66, $0F, $FE, $94, $24, $60, $01, $00, $00  // paddd xmm2, [esp + 352]
  movdqa  xmm3, [esp + 112]
  db $66, $0F, $FE, $9C, $24, $70, $01, $00, $00  // paddd xmm3, [esp + 368]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 16]
  pxor    xmm0, xmm5
  movdqu  [eax + 16], xmm0
  movdqu  xmm5, [edi + 80]
  pxor    xmm1, xmm5
  movdqu  [eax + 80], xmm1
  movdqu  xmm5, [edi + 144]
  pxor    xmm4, xmm5
  movdqu  [eax + 144], xmm4
  movdqu  xmm5, [edi + 208]
  pxor    xmm3, xmm5
  movdqu  [eax + 208], xmm3
  movdqa  xmm0, [esp + 128]
  db $66, $0F, $FE, $84, $24, $80, $01, $00, $00  // paddd xmm0, [esp + 384]
  movdqa  xmm1, [esp + 144]
  db $66, $0F, $FE, $8C, $24, $90, $01, $00, $00  // paddd xmm1, [esp + 400]
  movdqa  xmm2, [esp + 160]
  db $66, $0F, $FE, $94, $24, $A0, $01, $00, $00  // paddd xmm2, [esp + 416]
  movdqa  xmm3, [esp + 176]
  db $66, $0F, $FE, $9C, $24, $B0, $01, $00, $00  // paddd xmm3, [esp + 432]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 32]
  pxor    xmm0, xmm5
  movdqu  [eax + 32], xmm0
  movdqu  xmm5, [edi + 96]
  pxor    xmm1, xmm5
  movdqu  [eax + 96], xmm1
  movdqu  xmm5, [edi + 160]
  pxor    xmm4, xmm5
  movdqu  [eax + 160], xmm4
  movdqu  xmm5, [edi + 224]
  pxor    xmm3, xmm5
  movdqu  [eax + 224], xmm3
  movdqa  xmm0, [esp + 192]
  db $66, $0F, $FE, $84, $24, $C0, $01, $00, $00  // paddd xmm0, [esp + 448]
  movdqa  xmm1, [esp + 208]
  db $66, $0F, $FE, $8C, $24, $D0, $01, $00, $00  // paddd xmm1, [esp + 464]
  movdqa  xmm2, [esp + 224]
  db $66, $0F, $FE, $94, $24, $E0, $01, $00, $00  // paddd xmm2, [esp + 480]
  movdqa  xmm3, [esp + 240]
  db $66, $0F, $FE, $9C, $24, $F0, $01, $00, $00  // paddd xmm3, [esp + 496]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1                           // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1                           // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3                           // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB                           // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                           // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                           // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5                           // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD                           // punpckhqdq xmm3, xmm5
  movdqu  xmm5, [edi + 48]
  pxor    xmm0, xmm5
  movdqu  [eax + 48], xmm0
  movdqu  xmm5, [edi + 112]
  pxor    xmm1, xmm5
  movdqu  [eax + 112], xmm1
  movdqu  xmm5, [edi + 176]
  pxor    xmm4, xmm5
  movdqu  [eax + 176], xmm4
  movdqu  xmm5, [edi + 240]
  pxor    xmm3, xmm5
  movdqu  [eax + 240], xmm3
  add     dword ptr [esp + 676], 256
  add     dword ptr [esp + 680], 256
  dec     dword ptr [esp + 684]
  jnz     @@cp_dec_outer
@@cp_done:
  // ---- write the accumulator h0..h4 back to APolyState ----
  mov     edx, dword ptr [esp + 688]
  mov     eax, dword ptr [esp + 612]
  mov     dword ptr [edx + 0], eax
  mov     eax, dword ptr [esp + 616]
  mov     dword ptr [edx + 4], eax
  mov     eax, dword ptr [esp + 620]
  mov     dword ptr [edx + 8], eax
  mov     eax, dword ptr [esp + 624]
  mov     dword ptr [edx + 12], eax
  mov     eax, dword ptr [esp + 628]
  mov     dword ptr [edx + 16], eax
  // ---- restore esp and callee-saved GPRs ----
  mov     esp, dword ptr [esp + 544]
  pop     edi
  pop     esi
  pop     ebx
{$ENDIF CRYPTOLIB_CHACHAPOLY_FUSED}
