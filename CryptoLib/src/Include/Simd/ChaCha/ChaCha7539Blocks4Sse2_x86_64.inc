// ChaCha7539 (IETF) 4-way (256B) SSE2 keystream kernel, vertical layout (x86-64).
// -------------------------------------------------------------------
//
// Four 64-byte ChaCha20 blocks, state words held vertically (one block per
// xmm lane): xmm0-3 = words a (0-3), xmm4-7 = words b (4-7), xmm12-15 = words
// d (12-15). Words c (8-11) live in a stack slot; xmm8-9 are scratch.
// rot16/rot8 use shift+or; rot12/rot7 use shift+or.
//
// On entry (after ClpSimdProc4Begin_x86_64.inc):
//   rcx = ARounds, rdx = AState (16 UInt32), r8 = AIn, r9 = AOut.
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 4; the keystream is xored
//   with AIn into AOut (256 bytes).
//
// Ops touching the extended xmm8-15 registers are db-encoded for broad
// assembler compatibility.
  mov     r10, rcx
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  sub     rsp, 336
  mov     dword ptr [rsp + 320], 0
  mov     dword ptr [rsp + 324], 1
  mov     dword ptr [rsp + 328], 2
  mov     dword ptr [rsp + 332], 3
  movd    xmm0, [rdx]
  pshufd  xmm0, xmm0, $00
  movdqu  [rsp + 64], xmm0
  movd    xmm1, [rdx + 4]
  pshufd  xmm1, xmm1, $00
  movdqu  [rsp + 80], xmm1
  movd    xmm2, [rdx + 8]
  pshufd  xmm2, xmm2, $00
  movdqu  [rsp + 96], xmm2
  movd    xmm3, [rdx + 12]
  pshufd  xmm3, xmm3, $00
  movdqu  [rsp + 112], xmm3
  movd    xmm4, [rdx + 16]
  pshufd  xmm4, xmm4, $00
  movdqu  [rsp + 128], xmm4
  movd    xmm5, [rdx + 20]
  pshufd  xmm5, xmm5, $00
  movdqu  [rsp + 144], xmm5
  movd    xmm6, [rdx + 24]
  pshufd  xmm6, xmm6, $00
  movdqu  [rsp + 160], xmm6
  movd    xmm7, [rdx + 28]
  pshufd  xmm7, xmm7, $00
  movdqu  [rsp + 176], xmm7
  movd    xmm8, [rdx + 32]
  db $66, $45, $0F, $70, $C0, $00  // pshufd xmm8, xmm8, $00
  movdqu  [rsp], xmm8
  movdqu  [rsp + 192], xmm8
  movd    xmm8, [rdx + 36]
  db $66, $45, $0F, $70, $C0, $00  // pshufd xmm8, xmm8, $00
  movdqu  [rsp + 16], xmm8
  movdqu  [rsp + 208], xmm8
  movd    xmm8, [rdx + 40]
  db $66, $45, $0F, $70, $C0, $00  // pshufd xmm8, xmm8, $00
  movdqu  [rsp + 32], xmm8
  movdqu  [rsp + 224], xmm8
  movd    xmm8, [rdx + 44]
  db $66, $45, $0F, $70, $C0, $00  // pshufd xmm8, xmm8, $00
  movdqu  [rsp + 48], xmm8
  movdqu  [rsp + 240], xmm8
  movd    xmm12, [rdx + 48]
  db $66, $45, $0F, $70, $E4, $00  // pshufd xmm12, xmm12, $00
  movdqu  xmm8, [rsp + 320]
  db $66, $45, $0F, $FE, $E0       // paddd xmm12, xmm8
  movdqu  [rsp + 256], xmm12
  movd    xmm13, [rdx + 52]
  db $66, $45, $0F, $70, $ED, $00  // pshufd xmm13, xmm13, $00
  movdqu  [rsp + 272], xmm13
  movd    xmm14, [rdx + 56]
  db $66, $45, $0F, $70, $F6, $00  // pshufd xmm14, xmm14, $00
  movdqu  [rsp + 288], xmm14
  movd    xmm15, [rdx + 60]
  db $66, $45, $0F, $70, $FF, $00  // pshufd xmm15, xmm15, $00
  movdqu  [rsp + 304], xmm15
@@c7539_sse2_round:
  movdqu  xmm8, [rsp]
  paddd   xmm0, xmm4
  db $66, $44, $0F, $EF, $E0       // pxor xmm12, xmm0
  db $66, $45, $0F, $6F, $CC       // movdqa xmm9, xmm12
  db $66, $41, $0F, $72, $F4, $10  // pslld xmm12, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $E1       // por xmm12, xmm9
  db $66, $45, $0F, $FE, $C4       // paddd xmm8, xmm12
  db $66, $41, $0F, $EF, $E0       // pxor xmm4, xmm8
  db $66, $44, $0F, $6F, $CC       // movdqa xmm9, xmm4
  pslld   xmm4, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $E1       // por xmm4, xmm9
  paddd   xmm0, xmm4
  db $66, $44, $0F, $EF, $E0       // pxor xmm12, xmm0
  db $66, $45, $0F, $6F, $CC       // movdqa xmm9, xmm12
  db $66, $41, $0F, $72, $F4, $08  // pslld xmm12, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $E1       // por xmm12, xmm9
  db $66, $45, $0F, $FE, $C4       // paddd xmm8, xmm12
  db $66, $41, $0F, $EF, $E0       // pxor xmm4, xmm8
  db $66, $44, $0F, $6F, $CC       // movdqa xmm9, xmm4
  pslld   xmm4, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $E1       // por xmm4, xmm9
  movdqu  [rsp], xmm8
  movdqu  xmm8, [rsp + 16]
  paddd   xmm1, xmm5
  db $66, $44, $0F, $EF, $E9       // pxor xmm13, xmm1
  db $66, $45, $0F, $6F, $CD       // movdqa xmm9, xmm13
  db $66, $41, $0F, $72, $F5, $10  // pslld xmm13, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $E9       // por xmm13, xmm9
  db $66, $45, $0F, $FE, $C5       // paddd xmm8, xmm13
  db $66, $41, $0F, $EF, $E8       // pxor xmm5, xmm8
  db $66, $44, $0F, $6F, $CD       // movdqa xmm9, xmm5
  pslld   xmm5, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $E9       // por xmm5, xmm9
  paddd   xmm1, xmm5
  db $66, $44, $0F, $EF, $E9       // pxor xmm13, xmm1
  db $66, $45, $0F, $6F, $CD       // movdqa xmm9, xmm13
  db $66, $41, $0F, $72, $F5, $08  // pslld xmm13, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $E9       // por xmm13, xmm9
  db $66, $45, $0F, $FE, $C5       // paddd xmm8, xmm13
  db $66, $41, $0F, $EF, $E8       // pxor xmm5, xmm8
  db $66, $44, $0F, $6F, $CD       // movdqa xmm9, xmm5
  pslld   xmm5, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $E9       // por xmm5, xmm9
  movdqu  [rsp + 16], xmm8
  movdqu  xmm8, [rsp + 32]
  paddd   xmm2, xmm6
  db $66, $44, $0F, $EF, $F2       // pxor xmm14, xmm2
  db $66, $45, $0F, $6F, $CE       // movdqa xmm9, xmm14
  db $66, $41, $0F, $72, $F6, $10  // pslld xmm14, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $F1       // por xmm14, xmm9
  db $66, $45, $0F, $FE, $C6       // paddd xmm8, xmm14
  db $66, $41, $0F, $EF, $F0       // pxor xmm6, xmm8
  db $66, $44, $0F, $6F, $CE       // movdqa xmm9, xmm6
  pslld   xmm6, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $F1       // por xmm6, xmm9
  paddd   xmm2, xmm6
  db $66, $44, $0F, $EF, $F2       // pxor xmm14, xmm2
  db $66, $45, $0F, $6F, $CE       // movdqa xmm9, xmm14
  db $66, $41, $0F, $72, $F6, $08  // pslld xmm14, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $F1       // por xmm14, xmm9
  db $66, $45, $0F, $FE, $C6       // paddd xmm8, xmm14
  db $66, $41, $0F, $EF, $F0       // pxor xmm6, xmm8
  db $66, $44, $0F, $6F, $CE       // movdqa xmm9, xmm6
  pslld   xmm6, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $F1       // por xmm6, xmm9
  movdqu  [rsp + 32], xmm8
  movdqu  xmm8, [rsp + 48]
  paddd   xmm3, xmm7
  db $66, $44, $0F, $EF, $FB       // pxor xmm15, xmm3
  db $66, $45, $0F, $6F, $CF       // movdqa xmm9, xmm15
  db $66, $41, $0F, $72, $F7, $10  // pslld xmm15, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $F9       // por xmm15, xmm9
  db $66, $45, $0F, $FE, $C7       // paddd xmm8, xmm15
  db $66, $41, $0F, $EF, $F8       // pxor xmm7, xmm8
  db $66, $44, $0F, $6F, $CF       // movdqa xmm9, xmm7
  pslld   xmm7, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $F9       // por xmm7, xmm9
  paddd   xmm3, xmm7
  db $66, $44, $0F, $EF, $FB       // pxor xmm15, xmm3
  db $66, $45, $0F, $6F, $CF       // movdqa xmm9, xmm15
  db $66, $41, $0F, $72, $F7, $08  // pslld xmm15, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $F9       // por xmm15, xmm9
  db $66, $45, $0F, $FE, $C7       // paddd xmm8, xmm15
  db $66, $41, $0F, $EF, $F8       // pxor xmm7, xmm8
  db $66, $44, $0F, $6F, $CF       // movdqa xmm9, xmm7
  pslld   xmm7, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $F9       // por xmm7, xmm9
  movdqu  [rsp + 48], xmm8
  movdqu  xmm8, [rsp + 32]
  paddd   xmm0, xmm5
  db $66, $44, $0F, $EF, $F8       // pxor xmm15, xmm0
  db $66, $45, $0F, $6F, $CF       // movdqa xmm9, xmm15
  db $66, $41, $0F, $72, $F7, $10  // pslld xmm15, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $F9       // por xmm15, xmm9
  db $66, $45, $0F, $FE, $C7       // paddd xmm8, xmm15
  db $66, $41, $0F, $EF, $E8       // pxor xmm5, xmm8
  db $66, $44, $0F, $6F, $CD       // movdqa xmm9, xmm5
  pslld   xmm5, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $E9       // por xmm5, xmm9
  paddd   xmm0, xmm5
  db $66, $44, $0F, $EF, $F8       // pxor xmm15, xmm0
  db $66, $45, $0F, $6F, $CF       // movdqa xmm9, xmm15
  db $66, $41, $0F, $72, $F7, $08  // pslld xmm15, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $F9       // por xmm15, xmm9
  db $66, $45, $0F, $FE, $C7       // paddd xmm8, xmm15
  db $66, $41, $0F, $EF, $E8       // pxor xmm5, xmm8
  db $66, $44, $0F, $6F, $CD       // movdqa xmm9, xmm5
  pslld   xmm5, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $E9       // por xmm5, xmm9
  movdqu  [rsp + 32], xmm8
  movdqu  xmm8, [rsp + 48]
  paddd   xmm1, xmm6
  db $66, $44, $0F, $EF, $E1       // pxor xmm12, xmm1
  db $66, $45, $0F, $6F, $CC       // movdqa xmm9, xmm12
  db $66, $41, $0F, $72, $F4, $10  // pslld xmm12, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $E1       // por xmm12, xmm9
  db $66, $45, $0F, $FE, $C4       // paddd xmm8, xmm12
  db $66, $41, $0F, $EF, $F0       // pxor xmm6, xmm8
  db $66, $44, $0F, $6F, $CE       // movdqa xmm9, xmm6
  pslld   xmm6, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $F1       // por xmm6, xmm9
  paddd   xmm1, xmm6
  db $66, $44, $0F, $EF, $E1       // pxor xmm12, xmm1
  db $66, $45, $0F, $6F, $CC       // movdqa xmm9, xmm12
  db $66, $41, $0F, $72, $F4, $08  // pslld xmm12, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $E1       // por xmm12, xmm9
  db $66, $45, $0F, $FE, $C4       // paddd xmm8, xmm12
  db $66, $41, $0F, $EF, $F0       // pxor xmm6, xmm8
  db $66, $44, $0F, $6F, $CE       // movdqa xmm9, xmm6
  pslld   xmm6, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $F1       // por xmm6, xmm9
  movdqu  [rsp + 48], xmm8
  movdqu  xmm8, [rsp]
  paddd   xmm2, xmm7
  db $66, $44, $0F, $EF, $EA       // pxor xmm13, xmm2
  db $66, $45, $0F, $6F, $CD       // movdqa xmm9, xmm13
  db $66, $41, $0F, $72, $F5, $10  // pslld xmm13, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $E9       // por xmm13, xmm9
  db $66, $45, $0F, $FE, $C5       // paddd xmm8, xmm13
  db $66, $41, $0F, $EF, $F8       // pxor xmm7, xmm8
  db $66, $44, $0F, $6F, $CF       // movdqa xmm9, xmm7
  pslld   xmm7, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $F9       // por xmm7, xmm9
  paddd   xmm2, xmm7
  db $66, $44, $0F, $EF, $EA       // pxor xmm13, xmm2
  db $66, $45, $0F, $6F, $CD       // movdqa xmm9, xmm13
  db $66, $41, $0F, $72, $F5, $08  // pslld xmm13, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $E9       // por xmm13, xmm9
  db $66, $45, $0F, $FE, $C5       // paddd xmm8, xmm13
  db $66, $41, $0F, $EF, $F8       // pxor xmm7, xmm8
  db $66, $44, $0F, $6F, $CF       // movdqa xmm9, xmm7
  pslld   xmm7, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $F9       // por xmm7, xmm9
  movdqu  [rsp], xmm8
  movdqu  xmm8, [rsp + 16]
  paddd   xmm3, xmm4
  db $66, $44, $0F, $EF, $F3       // pxor xmm14, xmm3
  db $66, $45, $0F, $6F, $CE       // movdqa xmm9, xmm14
  db $66, $41, $0F, $72, $F6, $10  // pslld xmm14, 16
  db $66, $41, $0F, $72, $D1, $10  // psrld xmm9, 16
  db $66, $45, $0F, $EB, $F1       // por xmm14, xmm9
  db $66, $45, $0F, $FE, $C6       // paddd xmm8, xmm14
  db $66, $41, $0F, $EF, $E0       // pxor xmm4, xmm8
  db $66, $44, $0F, $6F, $CC       // movdqa xmm9, xmm4
  pslld   xmm4, 12
  db $66, $41, $0F, $72, $D1, $14  // psrld xmm9, 20
  db $66, $41, $0F, $EB, $E1       // por xmm4, xmm9
  paddd   xmm3, xmm4
  db $66, $44, $0F, $EF, $F3       // pxor xmm14, xmm3
  db $66, $45, $0F, $6F, $CE       // movdqa xmm9, xmm14
  db $66, $41, $0F, $72, $F6, $08  // pslld xmm14, 8
  db $66, $41, $0F, $72, $D1, $18  // psrld xmm9, 24
  db $66, $45, $0F, $EB, $F1       // por xmm14, xmm9
  db $66, $45, $0F, $FE, $C6       // paddd xmm8, xmm14
  db $66, $41, $0F, $EF, $E0       // pxor xmm4, xmm8
  db $66, $44, $0F, $6F, $CC       // movdqa xmm9, xmm4
  pslld   xmm4, 7
  db $66, $41, $0F, $72, $D1, $19  // psrld xmm9, 25
  db $66, $41, $0F, $EB, $E1       // por xmm4, xmm9
  movdqu  [rsp + 16], xmm8
  sub     r10, 2
  jg      @@c7539_sse2_round
  movdqu  xmm8, [rsp + 64]
  db $66, $41, $0F, $FE, $C0       // paddd xmm0, xmm8
  movdqu  [rsp + 64], xmm0
  movdqu  xmm8, [rsp + 80]
  db $66, $41, $0F, $FE, $C8       // paddd xmm1, xmm8
  movdqu  [rsp + 80], xmm1
  movdqu  xmm8, [rsp + 96]
  db $66, $41, $0F, $FE, $D0       // paddd xmm2, xmm8
  movdqu  [rsp + 96], xmm2
  movdqu  xmm8, [rsp + 112]
  db $66, $41, $0F, $FE, $D8       // paddd xmm3, xmm8
  movdqu  [rsp + 112], xmm3
  movdqu  xmm8, [rsp + 128]
  db $66, $41, $0F, $FE, $E0       // paddd xmm4, xmm8
  movdqu  [rsp + 128], xmm4
  movdqu  xmm8, [rsp + 144]
  db $66, $41, $0F, $FE, $E8       // paddd xmm5, xmm8
  movdqu  [rsp + 144], xmm5
  movdqu  xmm8, [rsp + 160]
  db $66, $41, $0F, $FE, $F0       // paddd xmm6, xmm8
  movdqu  [rsp + 160], xmm6
  movdqu  xmm8, [rsp + 176]
  db $66, $41, $0F, $FE, $F8       // paddd xmm7, xmm8
  movdqu  [rsp + 176], xmm7
  movdqu  xmm8, [rsp + 256]
  db $66, $45, $0F, $FE, $E0       // paddd xmm12, xmm8
  movdqu  [rsp + 256], xmm12
  movdqu  xmm8, [rsp + 272]
  db $66, $45, $0F, $FE, $E8       // paddd xmm13, xmm8
  movdqu  [rsp + 272], xmm13
  movdqu  xmm8, [rsp + 288]
  db $66, $45, $0F, $FE, $F0       // paddd xmm14, xmm8
  movdqu  [rsp + 288], xmm14
  movdqu  xmm8, [rsp + 304]
  db $66, $45, $0F, $FE, $F8       // paddd xmm15, xmm8
  movdqu  [rsp + 304], xmm15
  movdqu  xmm8, [rsp]
  movdqu  xmm9, [rsp + 192]
  db $66, $45, $0F, $FE, $C1       // paddd xmm8, xmm9
  movdqu  [rsp + 192], xmm8
  movdqu  xmm8, [rsp + 16]
  movdqu  xmm9, [rsp + 208]
  db $66, $45, $0F, $FE, $C1       // paddd xmm8, xmm9
  movdqu  [rsp + 208], xmm8
  movdqu  xmm8, [rsp + 32]
  movdqu  xmm9, [rsp + 224]
  db $66, $45, $0F, $FE, $C1       // paddd xmm8, xmm9
  movdqu  [rsp + 224], xmm8
  movdqu  xmm8, [rsp + 48]
  movdqu  xmm9, [rsp + 240]
  db $66, $45, $0F, $FE, $C1       // paddd xmm8, xmm9
  movdqu  [rsp + 240], xmm8
  add     dword ptr [rdx + 48], 4
{$IFDEF CHACHA_CTR64}
  adc     dword ptr [rdx + 52], 0
{$ENDIF}
  movdqu  xmm0, [rsp + 64]
  movdqu  xmm1, [rsp + 80]
  movdqu  xmm2, [rsp + 96]
  movdqu  xmm3, [rsp + 112]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1            // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1            // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3            // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB            // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2            // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA            // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5            // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD            // punpckhqdq xmm3, xmm5
  movdqu  xmm6, [r8]
  pxor    xmm0, xmm6
  movdqu  [r9], xmm0
  movdqu  xmm6, [r8 + 64]
  pxor    xmm1, xmm6
  movdqu  [r9 + 64], xmm1
  movdqu  xmm6, [r8 + 128]
  pxor    xmm4, xmm6
  movdqu  [r9 + 128], xmm4
  movdqu  xmm6, [r8 + 192]
  pxor    xmm3, xmm6
  movdqu  [r9 + 192], xmm3
  movdqu  xmm0, [rsp + 128]
  movdqu  xmm1, [rsp + 144]
  movdqu  xmm2, [rsp + 160]
  movdqu  xmm3, [rsp + 176]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1            // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1            // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3            // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB            // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2            // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA            // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5            // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD            // punpckhqdq xmm3, xmm5
  movdqu  xmm6, [r8 + 16]
  pxor    xmm0, xmm6
  movdqu  [r9 + 16], xmm0
  movdqu  xmm6, [r8 + 80]
  pxor    xmm1, xmm6
  movdqu  [r9 + 80], xmm1
  movdqu  xmm6, [r8 + 144]
  pxor    xmm4, xmm6
  movdqu  [r9 + 144], xmm4
  movdqu  xmm6, [r8 + 208]
  pxor    xmm3, xmm6
  movdqu  [r9 + 208], xmm3
  movdqu  xmm0, [rsp + 192]
  movdqu  xmm1, [rsp + 208]
  movdqu  xmm2, [rsp + 224]
  movdqu  xmm3, [rsp + 240]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1            // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1            // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3            // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB            // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2            // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA            // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5            // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD            // punpckhqdq xmm3, xmm5
  movdqu  xmm6, [r8 + 32]
  pxor    xmm0, xmm6
  movdqu  [r9 + 32], xmm0
  movdqu  xmm6, [r8 + 96]
  pxor    xmm1, xmm6
  movdqu  [r9 + 96], xmm1
  movdqu  xmm6, [r8 + 160]
  pxor    xmm4, xmm6
  movdqu  [r9 + 160], xmm4
  movdqu  xmm6, [r8 + 224]
  pxor    xmm3, xmm6
  movdqu  [r9 + 224], xmm3
  movdqu  xmm0, [rsp + 256]
  movdqu  xmm1, [rsp + 272]
  movdqu  xmm2, [rsp + 288]
  movdqu  xmm3, [rsp + 304]
  movdqa  xmm4, xmm0
  db $66, $0F, $62, $C1            // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $E1            // punpckhdq xmm4, xmm1
  movdqa  xmm5, xmm2
  db $66, $0F, $62, $D3            // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $EB            // punpckhdq xmm5, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2            // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA            // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm4
  db $66, $0F, $6C, $E5            // punpcklqdq xmm4, xmm5
  db $66, $0F, $6D, $DD            // punpckhqdq xmm3, xmm5
  movdqu  xmm6, [r8 + 48]
  pxor    xmm0, xmm6
  movdqu  [r9 + 48], xmm0
  movdqu  xmm6, [r8 + 112]
  pxor    xmm1, xmm6
  movdqu  [r9 + 112], xmm1
  movdqu  xmm6, [r8 + 176]
  pxor    xmm4, xmm6
  movdqu  [r9 + 176], xmm4
  movdqu  xmm6, [r8 + 240]
  pxor    xmm3, xmm6
  movdqu  [r9 + 240], xmm3
  add     rsp, 336
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

