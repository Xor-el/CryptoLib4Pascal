// ChaCha7539 (IETF) 4-way (256B) SSSE3 keystream kernel, vertical layout (i386).
// -------------------------------------------------------------------
//
// Four 64-byte ChaCha20 blocks, state words held vertically (one block per
// xmm lane). i386 has only 8 xmm, so the 16 state words live in a stack frame;
// each quarter-round loads its 4 words into xmm0-3 (temp xmm4) and the rot16/rot8 masks in xmm6-7.
// rot16/rot8 use pshufb; rot12/rot7 use shift+or.
//
// On entry (after ClpSimdProc4Begin_i386.inc):
//   ebx = ARounds, esi = AState (16 UInt32), edi = AIn, eax = AOut.
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 4; the keystream is xored
//   with AIn into AOut (256 bytes).
//
// punpck* / pshufb are db-encoded for broad assembler compatibility.
  sub     esp, 560
  mov     dword ptr [esp + 528], $01000302
  mov     dword ptr [esp + 532], $05040706
  mov     dword ptr [esp + 536], $09080B0A
  mov     dword ptr [esp + 540], $0D0C0F0E
  mov     dword ptr [esp + 544], $02010003
  mov     dword ptr [esp + 548], $06050407
  mov     dword ptr [esp + 552], $0A09080B
  mov     dword ptr [esp + 556], $0E0D0C0F
  movdqu  xmm6, [esp + 528]
  movdqu  xmm7, [esp + 544]
  mov     dword ptr [esp + 512], 0
  mov     dword ptr [esp + 516], 1
  mov     dword ptr [esp + 520], 2
  mov     dword ptr [esp + 524], 3
  movd    xmm0, [esi]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp], xmm0
  movdqu  [esp + 256], xmm0
  movd    xmm0, [esi + 4]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 16], xmm0
  movdqu  [esp + 272], xmm0
  movd    xmm0, [esi + 8]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 32], xmm0
  movdqu  [esp + 288], xmm0
  movd    xmm0, [esi + 12]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 48], xmm0
  movdqu  [esp + 304], xmm0
  movd    xmm0, [esi + 16]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 64], xmm0
  movdqu  [esp + 320], xmm0
  movd    xmm0, [esi + 20]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 80], xmm0
  movdqu  [esp + 336], xmm0
  movd    xmm0, [esi + 24]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 96], xmm0
  movdqu  [esp + 352], xmm0
  movd    xmm0, [esi + 28]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 112], xmm0
  movdqu  [esp + 368], xmm0
  movd    xmm0, [esi + 32]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 128], xmm0
  movdqu  [esp + 384], xmm0
  movd    xmm0, [esi + 36]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 144], xmm0
  movdqu  [esp + 400], xmm0
  movd    xmm0, [esi + 40]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 160], xmm0
  movdqu  [esp + 416], xmm0
  movd    xmm0, [esi + 44]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 176], xmm0
  movdqu  [esp + 432], xmm0
  movd    xmm0, [esi + 48]
  pshufd  xmm0, xmm0, $00
  movdqu  xmm1, [esp + 512]
  paddd   xmm0, xmm1
  movdqu  [esp + 192], xmm0
  movdqu  [esp + 448], xmm0
  movd    xmm0, [esi + 52]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 208], xmm0
  movdqu  [esp + 464], xmm0
  movd    xmm0, [esi + 56]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 224], xmm0
  movdqu  [esp + 480], xmm0
  movd    xmm0, [esi + 60]
  pshufd  xmm0, xmm0, $00
  movdqu  [esp + 240], xmm0
  movdqu  [esp + 496], xmm0
@@c7539_ssse3_round:
  movdqu  xmm0, [esp]
  movdqu  xmm1, [esp + 64]
  movdqu  xmm2, [esp + 128]
  movdqu  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp], xmm0
  movdqu  [esp + 64], xmm1
  movdqu  [esp + 128], xmm2
  movdqu  [esp + 192], xmm3
  movdqu  xmm0, [esp + 16]
  movdqu  xmm1, [esp + 80]
  movdqu  xmm2, [esp + 144]
  movdqu  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp + 16], xmm0
  movdqu  [esp + 80], xmm1
  movdqu  [esp + 144], xmm2
  movdqu  [esp + 208], xmm3
  movdqu  xmm0, [esp + 32]
  movdqu  xmm1, [esp + 96]
  movdqu  xmm2, [esp + 160]
  movdqu  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp + 32], xmm0
  movdqu  [esp + 96], xmm1
  movdqu  [esp + 160], xmm2
  movdqu  [esp + 224], xmm3
  movdqu  xmm0, [esp + 48]
  movdqu  xmm1, [esp + 112]
  movdqu  xmm2, [esp + 176]
  movdqu  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp + 48], xmm0
  movdqu  [esp + 112], xmm1
  movdqu  [esp + 176], xmm2
  movdqu  [esp + 240], xmm3
  movdqu  xmm0, [esp]
  movdqu  xmm1, [esp + 80]
  movdqu  xmm2, [esp + 160]
  movdqu  xmm3, [esp + 240]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp], xmm0
  movdqu  [esp + 80], xmm1
  movdqu  [esp + 160], xmm2
  movdqu  [esp + 240], xmm3
  movdqu  xmm0, [esp + 16]
  movdqu  xmm1, [esp + 96]
  movdqu  xmm2, [esp + 176]
  movdqu  xmm3, [esp + 192]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp + 16], xmm0
  movdqu  [esp + 96], xmm1
  movdqu  [esp + 176], xmm2
  movdqu  [esp + 192], xmm3
  movdqu  xmm0, [esp + 32]
  movdqu  xmm1, [esp + 112]
  movdqu  xmm2, [esp + 128]
  movdqu  xmm3, [esp + 208]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp + 32], xmm0
  movdqu  [esp + 112], xmm1
  movdqu  [esp + 128], xmm2
  movdqu  [esp + 208], xmm3
  movdqu  xmm0, [esp + 48]
  movdqu  xmm1, [esp + 64]
  movdqu  xmm2, [esp + 144]
  movdqu  xmm3, [esp + 224]
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DE  // pshufb xmm3, xmm6
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 12
  psrld   xmm4, 20
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  db $66, $0F, $38, $00, $DF  // pshufb xmm3, xmm7
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  pslld   xmm1, 7
  psrld   xmm4, 25
  por     xmm1, xmm4
  movdqu  [esp + 48], xmm0
  movdqu  [esp + 64], xmm1
  movdqu  [esp + 144], xmm2
  movdqu  [esp + 224], xmm3
  sub     ebx, 2
  jg      @@c7539_ssse3_round
  movdqu  xmm0, [esp]
  movdqu  xmm1, [esp + 256]
  paddd   xmm0, xmm1
  movdqu  [esp], xmm0
  movdqu  xmm0, [esp + 16]
  movdqu  xmm1, [esp + 272]
  paddd   xmm0, xmm1
  movdqu  [esp + 16], xmm0
  movdqu  xmm0, [esp + 32]
  movdqu  xmm1, [esp + 288]
  paddd   xmm0, xmm1
  movdqu  [esp + 32], xmm0
  movdqu  xmm0, [esp + 48]
  movdqu  xmm1, [esp + 304]
  paddd   xmm0, xmm1
  movdqu  [esp + 48], xmm0
  movdqu  xmm0, [esp + 64]
  movdqu  xmm1, [esp + 320]
  paddd   xmm0, xmm1
  movdqu  [esp + 64], xmm0
  movdqu  xmm0, [esp + 80]
  movdqu  xmm1, [esp + 336]
  paddd   xmm0, xmm1
  movdqu  [esp + 80], xmm0
  movdqu  xmm0, [esp + 96]
  movdqu  xmm1, [esp + 352]
  paddd   xmm0, xmm1
  movdqu  [esp + 96], xmm0
  movdqu  xmm0, [esp + 112]
  movdqu  xmm1, [esp + 368]
  paddd   xmm0, xmm1
  movdqu  [esp + 112], xmm0
  movdqu  xmm0, [esp + 128]
  movdqu  xmm1, [esp + 384]
  paddd   xmm0, xmm1
  movdqu  [esp + 128], xmm0
  movdqu  xmm0, [esp + 144]
  movdqu  xmm1, [esp + 400]
  paddd   xmm0, xmm1
  movdqu  [esp + 144], xmm0
  movdqu  xmm0, [esp + 160]
  movdqu  xmm1, [esp + 416]
  paddd   xmm0, xmm1
  movdqu  [esp + 160], xmm0
  movdqu  xmm0, [esp + 176]
  movdqu  xmm1, [esp + 432]
  paddd   xmm0, xmm1
  movdqu  [esp + 176], xmm0
  movdqu  xmm0, [esp + 192]
  movdqu  xmm1, [esp + 448]
  paddd   xmm0, xmm1
  movdqu  [esp + 192], xmm0
  movdqu  xmm0, [esp + 208]
  movdqu  xmm1, [esp + 464]
  paddd   xmm0, xmm1
  movdqu  [esp + 208], xmm0
  movdqu  xmm0, [esp + 224]
  movdqu  xmm1, [esp + 480]
  paddd   xmm0, xmm1
  movdqu  [esp + 224], xmm0
  movdqu  xmm0, [esp + 240]
  movdqu  xmm1, [esp + 496]
  paddd   xmm0, xmm1
  movdqu  [esp + 240], xmm0
  add     dword ptr [esi + 48], 4
{$IFDEF CHACHA_CTR64}
  adc     dword ptr [esi + 52], 0
{$ENDIF}
  movdqu  xmm0, [esp]
  movdqu  xmm1, [esp + 16]
  movdqu  xmm2, [esp + 32]
  movdqu  xmm3, [esp + 48]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1       // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1       // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3       // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB       // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2       // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA       // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5       // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD       // punpckhqdq xmm3, xmm5
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
  movdqu  xmm0, [esp + 64]
  movdqu  xmm1, [esp + 80]
  movdqu  xmm2, [esp + 96]
  movdqu  xmm3, [esp + 112]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1       // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1       // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3       // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB       // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2       // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA       // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5       // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD       // punpckhqdq xmm3, xmm5
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
  movdqu  xmm0, [esp + 128]
  movdqu  xmm1, [esp + 144]
  movdqu  xmm2, [esp + 160]
  movdqu  xmm3, [esp + 176]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1       // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1       // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3       // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB       // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2       // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA       // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5       // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD       // punpckhqdq xmm3, xmm5
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
  movdqu  xmm0, [esp + 192]
  movdqu  xmm1, [esp + 208]
  movdqu  xmm2, [esp + 224]
  movdqu  xmm3, [esp + 240]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1       // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1       // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3       // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB       // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2       // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA       // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5       // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD       // punpckhqdq xmm3, xmm5
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
  add     esp, 560
  pop     edi
  pop     esi
  pop     ebx

