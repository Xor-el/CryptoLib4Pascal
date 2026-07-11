// ChaCha7539 (IETF) 4-way SSE2 keystream kernel, vertical layout (i386).
// -------------------------------------------------------------------
//
// Four 64-byte ChaCha20 blocks per group, state words held vertically (one
// block per xmm lane). i386 has only 8 xmm, so the 16 state words live in a
// 64B-aligned stack frame (original esp parked inside it); each quarter-round
// loads its 4 words into xmm0-3 (temp xmm4).
// rot16/rot8 use shift+or; rot12/rot7 use shift+or.
//
// Streams AGroups x 256B in one call: prologue once, per-group ORIG->STATE
// reload (counter lanes +4), fused accumulate/transpose/xor tail to AOut.
//
// On entry (after ClpSimdProc5Begin_i386.inc):
//   ebx = ARounds, esi = AState (16 UInt32), edi = AIn, eax = AOut,
//   ecx = AGroups (4-block groups, >= 1).
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 4*AGroups; the keystream is
//   xored with AIn into AOut (256*AGroups bytes).
//
// punpck* / pshufb are db-encoded for broad assembler compatibility.
  mov     edx, esp
  sub     esp, 560
  and     esp, -64
  mov     dword ptr [esp + 544], edx
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
  jmp     @@c7539_sse2_enter
@@c7539_sse2_outer:
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
@@c7539_sse2_enter:
  mov     edx, ebx
@@c7539_sse2_round:
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
  sub     edx, 2
  jg      @@c7539_sse2_round
  add     dword ptr [esi + 48], 4
{$IFDEF CHACHA_CTR64}
  adc     dword ptr [esi + 52], 0
{$ENDIF}
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
  add     edi, 256
  add     eax, 256
  dec     ecx
  jnz     @@c7539_sse2_outer
  mov     esp, dword ptr [esp + 544]
  pop     edi
  pop     esi
  pop     ebx

