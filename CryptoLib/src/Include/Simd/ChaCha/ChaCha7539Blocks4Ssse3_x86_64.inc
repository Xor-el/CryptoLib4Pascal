// ChaCha7539 (IETF) 4-way SSSE3 keystream kernel, vertical layout (x86-64).
// -------------------------------------------------------------------
//
// Four 64-byte ChaCha20 blocks per group, state words held vertically (one
// block per xmm lane): xmm0-3 = words a (0-3), xmm4-7 = words b (4-7),
// xmm12-15 = words d (12-15). Words c (8-11): two are resident in xmm8/xmm9,
// the other two wait in stack slots; quarter-rounds run as two resident pairs
// with one pair swap per round (2 stores + 2 loads). xmm10/xmm11 are the
// rotate temps. rot16/rot8 use pshufb (mask reloaded into the just-freed temp);
// rot12/rot7 use shift+or. The frame is 64B-aligned (r11 = frame register).
//
// Streams AGroups x 256B in one call: prologue once, light per-group reload
// (counter lanes +4), fused accumulate/transpose/xor tail straight to AOut.
//
// On entry (after ClpSimdProc5Begin_x86_64.inc):
//   rcx = ARounds, rdx = AState (16 UInt32), r8 = AIn, r9 = AOut,
//   r10 = AGroups (4-block groups, >= 1).
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 4*AGroups; the keystream is
//   xored with AIn into AOut (256*AGroups bytes).
//
// Ops touching the extended xmm8-15 registers are db-encoded for broad
// assembler compatibility.
  mov     r10d, r10d
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  mov     r11, rsp
  sub     rsp, 384
  and     rsp, -64
  mov     dword ptr [rsp + 320], 0
  mov     dword ptr [rsp + 324], 1
  mov     dword ptr [rsp + 328], 2
  mov     dword ptr [rsp + 332], 3
  mov     dword ptr [rsp + 336], 4
  mov     dword ptr [rsp + 340], 4
  mov     dword ptr [rsp + 344], 4
  mov     dword ptr [rsp + 348], 4
  mov     dword ptr [rsp + 352], $01000302
  mov     dword ptr [rsp + 356], $05040706
  mov     dword ptr [rsp + 360], $09080B0A
  mov     dword ptr [rsp + 364], $0D0C0F0E
  mov     dword ptr [rsp + 368], $02010003
  mov     dword ptr [rsp + 372], $06050407
  mov     dword ptr [rsp + 376], $0A09080B
  mov     dword ptr [rsp + 380], $0E0D0C0F
  movd    xmm0, [rdx]
  pshufd  xmm0, xmm0, $00
  movdqa  [rsp + 64], xmm0
  movd    xmm1, [rdx + 4]
  pshufd  xmm1, xmm1, $00
  movdqa  [rsp + 80], xmm1
  movd    xmm2, [rdx + 8]
  pshufd  xmm2, xmm2, $00
  movdqa  [rsp + 96], xmm2
  movd    xmm3, [rdx + 12]
  pshufd  xmm3, xmm3, $00
  movdqa  [rsp + 112], xmm3
  movd    xmm4, [rdx + 16]
  pshufd  xmm4, xmm4, $00
  movdqa  [rsp + 128], xmm4
  movd    xmm5, [rdx + 20]
  pshufd  xmm5, xmm5, $00
  movdqa  [rsp + 144], xmm5
  movd    xmm6, [rdx + 24]
  pshufd  xmm6, xmm6, $00
  movdqa  [rsp + 160], xmm6
  movd    xmm7, [rdx + 28]
  pshufd  xmm7, xmm7, $00
  movdqa  [rsp + 176], xmm7
  movd    xmm8, [rdx + 32]
  db $66, $45, $0F, $70, $C0, $00                      // pshufd xmm8, xmm8, $00
  movdqa  [rsp + 192], xmm8
  movd    xmm9, [rdx + 36]
  db $66, $45, $0F, $70, $C9, $00                      // pshufd xmm9, xmm9, $00
  movdqa  [rsp + 208], xmm9
  movd    xmm10, [rdx + 40]
  db $66, $45, $0F, $70, $D2, $00                      // pshufd xmm10, xmm10, $00
  movdqa  [rsp + 224], xmm10
  movdqa  [rsp + 32], xmm10
  movd    xmm10, [rdx + 44]
  db $66, $45, $0F, $70, $D2, $00                      // pshufd xmm10, xmm10, $00
  movdqa  [rsp + 240], xmm10
  movdqa  [rsp + 48], xmm10
  movd    xmm12, [rdx + 48]
  db $66, $45, $0F, $70, $E4, $00                      // pshufd xmm12, xmm12, $00
  db $66, $44, $0F, $FE, $A4, $24, $40, $01, $00, $00  // paddd xmm12, [rsp + 320]
  movdqa  [rsp + 256], xmm12
  movd    xmm13, [rdx + 52]
  db $66, $45, $0F, $70, $ED, $00                      // pshufd xmm13, xmm13, $00
  movdqa  [rsp + 272], xmm13
  movd    xmm14, [rdx + 56]
  db $66, $45, $0F, $70, $F6, $00                      // pshufd xmm14, xmm14, $00
  movdqa  [rsp + 288], xmm14
  movd    xmm15, [rdx + 60]
  db $66, $45, $0F, $70, $FF, $00                      // pshufd xmm15, xmm15, $00
  movdqa  [rsp + 304], xmm15
  movdqa  xmm11, [rsp + 352]
  jmp     @@c7539_ssse3_enter
@@c7539_ssse3_outer:
  movdqa  xmm0, [rsp + 64]
  movdqa  xmm1, [rsp + 80]
  movdqa  xmm2, [rsp + 96]
  movdqa  xmm3, [rsp + 112]
  movdqa  xmm4, [rsp + 128]
  movdqa  xmm5, [rsp + 144]
  movdqa  xmm6, [rsp + 160]
  movdqa  xmm7, [rsp + 176]
  movdqa  xmm8, [rsp + 192]
  movdqa  xmm9, [rsp + 208]
  movdqa  xmm10, [rsp + 224]
  movdqa  [rsp + 32], xmm10
  movdqa  xmm10, [rsp + 240]
  movdqa  [rsp + 48], xmm10
  movdqa  xmm12, [rsp + 256]
  db $66, $44, $0F, $FE, $A4, $24, $50, $01, $00, $00  // paddd xmm12, [rsp + 336]
  movdqa  [rsp + 256], xmm12
  movdqa  xmm13, [rsp + 272]
  movdqa  xmm14, [rsp + 288]
  movdqa  xmm15, [rsp + 304]
  movdqa  xmm11, [rsp + 352]
@@c7539_ssse3_enter:
  mov     eax, ecx
@@c7539_ssse3_round:
  paddd   xmm0, xmm4
  db $66, $44, $0F, $EF, $E0                           // pxor xmm12, xmm0
  db $66, $45, $0F, $38, $00, $E3                      // pshufb xmm12, xmm11
  paddd   xmm1, xmm5
  db $66, $44, $0F, $EF, $E9                           // pxor xmm13, xmm1
  db $66, $45, $0F, $38, $00, $EB                      // pshufb xmm13, xmm11
  db $66, $45, $0F, $FE, $C4                           // paddd xmm8, xmm12
  db $66, $41, $0F, $EF, $E0                           // pxor xmm4, xmm8
  db $66, $44, $0F, $6F, $D4                           // movdqa xmm10, xmm4
  pslld   xmm4, 12
  db $66, $41, $0F, $72, $D2, $14                      // psrld xmm10, 20
  db $66, $41, $0F, $EB, $E2                           // por xmm4, xmm10
  movdqa  xmm10, [rsp + 368]
  db $66, $45, $0F, $FE, $CD                           // paddd xmm9, xmm13
  db $66, $41, $0F, $EF, $E9                           // pxor xmm5, xmm9
  db $66, $44, $0F, $6F, $DD                           // movdqa xmm11, xmm5
  pslld   xmm5, 12
  db $66, $41, $0F, $72, $D3, $14                      // psrld xmm11, 20
  db $66, $41, $0F, $EB, $EB                           // por xmm5, xmm11
  paddd   xmm0, xmm4
  db $66, $44, $0F, $EF, $E0                           // pxor xmm12, xmm0
  db $66, $45, $0F, $38, $00, $E2                      // pshufb xmm12, xmm10
  paddd   xmm1, xmm5
  db $66, $44, $0F, $EF, $E9                           // pxor xmm13, xmm1
  db $66, $45, $0F, $38, $00, $EA                      // pshufb xmm13, xmm10
  db $66, $45, $0F, $FE, $C4                           // paddd xmm8, xmm12
  db $66, $41, $0F, $EF, $E0                           // pxor xmm4, xmm8
  db $66, $44, $0F, $6F, $DC                           // movdqa xmm11, xmm4
  pslld   xmm4, 7
  db $66, $41, $0F, $72, $D3, $19                      // psrld xmm11, 25
  db $66, $41, $0F, $EB, $E3                           // por xmm4, xmm11
  movdqa  xmm11, [rsp + 352]
  db $66, $45, $0F, $FE, $CD                           // paddd xmm9, xmm13
  db $66, $41, $0F, $EF, $E9                           // pxor xmm5, xmm9
  db $66, $44, $0F, $6F, $D5                           // movdqa xmm10, xmm5
  pslld   xmm5, 7
  db $66, $41, $0F, $72, $D2, $19                      // psrld xmm10, 25
  db $66, $41, $0F, $EB, $EA                           // por xmm5, xmm10
  movdqa  [rsp], xmm8
  movdqa  [rsp + 16], xmm9
  movdqa  xmm8, [rsp + 32]
  movdqa  xmm9, [rsp + 48]
  paddd   xmm2, xmm6
  db $66, $44, $0F, $EF, $F2                           // pxor xmm14, xmm2
  db $66, $45, $0F, $38, $00, $F3                      // pshufb xmm14, xmm11
  paddd   xmm3, xmm7
  db $66, $44, $0F, $EF, $FB                           // pxor xmm15, xmm3
  db $66, $45, $0F, $38, $00, $FB                      // pshufb xmm15, xmm11
  db $66, $45, $0F, $FE, $C6                           // paddd xmm8, xmm14
  db $66, $41, $0F, $EF, $F0                           // pxor xmm6, xmm8
  db $66, $44, $0F, $6F, $D6                           // movdqa xmm10, xmm6
  pslld   xmm6, 12
  db $66, $41, $0F, $72, $D2, $14                      // psrld xmm10, 20
  db $66, $41, $0F, $EB, $F2                           // por xmm6, xmm10
  movdqa  xmm10, [rsp + 368]
  db $66, $45, $0F, $FE, $CF                           // paddd xmm9, xmm15
  db $66, $41, $0F, $EF, $F9                           // pxor xmm7, xmm9
  db $66, $44, $0F, $6F, $DF                           // movdqa xmm11, xmm7
  pslld   xmm7, 12
  db $66, $41, $0F, $72, $D3, $14                      // psrld xmm11, 20
  db $66, $41, $0F, $EB, $FB                           // por xmm7, xmm11
  paddd   xmm2, xmm6
  db $66, $44, $0F, $EF, $F2                           // pxor xmm14, xmm2
  db $66, $45, $0F, $38, $00, $F2                      // pshufb xmm14, xmm10
  paddd   xmm3, xmm7
  db $66, $44, $0F, $EF, $FB                           // pxor xmm15, xmm3
  db $66, $45, $0F, $38, $00, $FA                      // pshufb xmm15, xmm10
  db $66, $45, $0F, $FE, $C6                           // paddd xmm8, xmm14
  db $66, $41, $0F, $EF, $F0                           // pxor xmm6, xmm8
  db $66, $44, $0F, $6F, $DE                           // movdqa xmm11, xmm6
  pslld   xmm6, 7
  db $66, $41, $0F, $72, $D3, $19                      // psrld xmm11, 25
  db $66, $41, $0F, $EB, $F3                           // por xmm6, xmm11
  movdqa  xmm11, [rsp + 352]
  db $66, $45, $0F, $FE, $CF                           // paddd xmm9, xmm15
  db $66, $41, $0F, $EF, $F9                           // pxor xmm7, xmm9
  db $66, $44, $0F, $6F, $D7                           // movdqa xmm10, xmm7
  pslld   xmm7, 7
  db $66, $41, $0F, $72, $D2, $19                      // psrld xmm10, 25
  db $66, $41, $0F, $EB, $FA                           // por xmm7, xmm10
  paddd   xmm0, xmm5
  db $66, $44, $0F, $EF, $F8                           // pxor xmm15, xmm0
  db $66, $45, $0F, $38, $00, $FB                      // pshufb xmm15, xmm11
  paddd   xmm1, xmm6
  db $66, $44, $0F, $EF, $E1                           // pxor xmm12, xmm1
  db $66, $45, $0F, $38, $00, $E3                      // pshufb xmm12, xmm11
  db $66, $45, $0F, $FE, $C7                           // paddd xmm8, xmm15
  db $66, $41, $0F, $EF, $E8                           // pxor xmm5, xmm8
  db $66, $44, $0F, $6F, $D5                           // movdqa xmm10, xmm5
  pslld   xmm5, 12
  db $66, $41, $0F, $72, $D2, $14                      // psrld xmm10, 20
  db $66, $41, $0F, $EB, $EA                           // por xmm5, xmm10
  movdqa  xmm10, [rsp + 368]
  db $66, $45, $0F, $FE, $CC                           // paddd xmm9, xmm12
  db $66, $41, $0F, $EF, $F1                           // pxor xmm6, xmm9
  db $66, $44, $0F, $6F, $DE                           // movdqa xmm11, xmm6
  pslld   xmm6, 12
  db $66, $41, $0F, $72, $D3, $14                      // psrld xmm11, 20
  db $66, $41, $0F, $EB, $F3                           // por xmm6, xmm11
  paddd   xmm0, xmm5
  db $66, $44, $0F, $EF, $F8                           // pxor xmm15, xmm0
  db $66, $45, $0F, $38, $00, $FA                      // pshufb xmm15, xmm10
  paddd   xmm1, xmm6
  db $66, $44, $0F, $EF, $E1                           // pxor xmm12, xmm1
  db $66, $45, $0F, $38, $00, $E2                      // pshufb xmm12, xmm10
  db $66, $45, $0F, $FE, $C7                           // paddd xmm8, xmm15
  db $66, $41, $0F, $EF, $E8                           // pxor xmm5, xmm8
  db $66, $44, $0F, $6F, $DD                           // movdqa xmm11, xmm5
  pslld   xmm5, 7
  db $66, $41, $0F, $72, $D3, $19                      // psrld xmm11, 25
  db $66, $41, $0F, $EB, $EB                           // por xmm5, xmm11
  movdqa  xmm11, [rsp + 352]
  db $66, $45, $0F, $FE, $CC                           // paddd xmm9, xmm12
  db $66, $41, $0F, $EF, $F1                           // pxor xmm6, xmm9
  db $66, $44, $0F, $6F, $D6                           // movdqa xmm10, xmm6
  pslld   xmm6, 7
  db $66, $41, $0F, $72, $D2, $19                      // psrld xmm10, 25
  db $66, $41, $0F, $EB, $F2                           // por xmm6, xmm10
  movdqa  [rsp + 32], xmm8
  movdqa  [rsp + 48], xmm9
  movdqa  xmm8, [rsp]
  movdqa  xmm9, [rsp + 16]
  paddd   xmm2, xmm7
  db $66, $44, $0F, $EF, $EA                           // pxor xmm13, xmm2
  db $66, $45, $0F, $38, $00, $EB                      // pshufb xmm13, xmm11
  paddd   xmm3, xmm4
  db $66, $44, $0F, $EF, $F3                           // pxor xmm14, xmm3
  db $66, $45, $0F, $38, $00, $F3                      // pshufb xmm14, xmm11
  db $66, $45, $0F, $FE, $C5                           // paddd xmm8, xmm13
  db $66, $41, $0F, $EF, $F8                           // pxor xmm7, xmm8
  db $66, $44, $0F, $6F, $D7                           // movdqa xmm10, xmm7
  pslld   xmm7, 12
  db $66, $41, $0F, $72, $D2, $14                      // psrld xmm10, 20
  db $66, $41, $0F, $EB, $FA                           // por xmm7, xmm10
  movdqa  xmm10, [rsp + 368]
  db $66, $45, $0F, $FE, $CE                           // paddd xmm9, xmm14
  db $66, $41, $0F, $EF, $E1                           // pxor xmm4, xmm9
  db $66, $44, $0F, $6F, $DC                           // movdqa xmm11, xmm4
  pslld   xmm4, 12
  db $66, $41, $0F, $72, $D3, $14                      // psrld xmm11, 20
  db $66, $41, $0F, $EB, $E3                           // por xmm4, xmm11
  paddd   xmm2, xmm7
  db $66, $44, $0F, $EF, $EA                           // pxor xmm13, xmm2
  db $66, $45, $0F, $38, $00, $EA                      // pshufb xmm13, xmm10
  paddd   xmm3, xmm4
  db $66, $44, $0F, $EF, $F3                           // pxor xmm14, xmm3
  db $66, $45, $0F, $38, $00, $F2                      // pshufb xmm14, xmm10
  db $66, $45, $0F, $FE, $C5                           // paddd xmm8, xmm13
  db $66, $41, $0F, $EF, $F8                           // pxor xmm7, xmm8
  db $66, $44, $0F, $6F, $DF                           // movdqa xmm11, xmm7
  pslld   xmm7, 7
  db $66, $41, $0F, $72, $D3, $19                      // psrld xmm11, 25
  db $66, $41, $0F, $EB, $FB                           // por xmm7, xmm11
  movdqa  xmm11, [rsp + 352]
  db $66, $45, $0F, $FE, $CE                           // paddd xmm9, xmm14
  db $66, $41, $0F, $EF, $E1                           // pxor xmm4, xmm9
  db $66, $44, $0F, $6F, $D4                           // movdqa xmm10, xmm4
  pslld   xmm4, 7
  db $66, $41, $0F, $72, $D2, $19                      // psrld xmm10, 25
  db $66, $41, $0F, $EB, $E2                           // por xmm4, xmm10
  sub     eax, 2
  jg      @@c7539_ssse3_round
  add     dword ptr [rdx + 48], 4
{$IFDEF CHACHA_CTR64}
  adc     dword ptr [rdx + 52], 0
{$ENDIF}
  db $66, $0F, $FE, $44, $24, $40                      // paddd xmm0, [rsp + 64]
  db $66, $0F, $FE, $4C, $24, $50                      // paddd xmm1, [rsp + 80]
  db $66, $0F, $FE, $54, $24, $60                      // paddd xmm2, [rsp + 96]
  db $66, $0F, $FE, $5C, $24, $70                      // paddd xmm3, [rsp + 112]
  db $66, $44, $0F, $6F, $D0                           // movdqa xmm10, xmm0
  db $66, $0F, $62, $C1                                // punpckldq xmm0, xmm1
  db $66, $44, $0F, $6A, $D1                           // punpckhdq xmm10, xmm1
  db $66, $44, $0F, $6F, $DA                           // movdqa xmm11, xmm2
  db $66, $0F, $62, $D3                                // punpckldq xmm2, xmm3
  db $66, $44, $0F, $6A, $DB                           // punpckhdq xmm11, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                                // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                                // punpckhqdq xmm1, xmm2
  db $66, $41, $0F, $6F, $DA                           // movdqa xmm3, xmm10
  db $66, $45, $0F, $6C, $D3                           // punpcklqdq xmm10, xmm11
  db $66, $41, $0F, $6D, $DB                           // punpckhqdq xmm3, xmm11
  db $66, $0F, $FE, $A4, $24, $80, $00, $00, $00       // paddd xmm4, [rsp + 128]
  db $66, $0F, $FE, $AC, $24, $90, $00, $00, $00       // paddd xmm5, [rsp + 144]
  db $66, $0F, $FE, $B4, $24, $A0, $00, $00, $00       // paddd xmm6, [rsp + 160]
  db $66, $0F, $FE, $BC, $24, $B0, $00, $00, $00       // paddd xmm7, [rsp + 176]
  movdqa  xmm2, xmm4
  db $66, $0F, $62, $E5                                // punpckldq xmm4, xmm5
  db $66, $0F, $6A, $D5                                // punpckhdq xmm2, xmm5
  db $66, $44, $0F, $6F, $DE                           // movdqa xmm11, xmm6
  db $66, $0F, $62, $F7                                // punpckldq xmm6, xmm7
  db $66, $44, $0F, $6A, $DF                           // punpckhdq xmm11, xmm7
  movdqa  xmm5, xmm4
  db $66, $0F, $6C, $E6                                // punpcklqdq xmm4, xmm6
  db $66, $0F, $6D, $EE                                // punpckhqdq xmm5, xmm6
  movdqa  xmm7, xmm2
  db $66, $41, $0F, $6C, $D3                           // punpcklqdq xmm2, xmm11
  db $66, $41, $0F, $6D, $FB                           // punpckhqdq xmm7, xmm11
  movdqu  xmm6, [r8]
  pxor    xmm0, xmm6
  movdqu  [r9], xmm0
  movdqu  xmm6, [r8 + 64]
  pxor    xmm1, xmm6
  movdqu  [r9 + 64], xmm1
  movdqu  xmm6, [r8 + 128]
  db $66, $44, $0F, $EF, $D6                           // pxor xmm10, xmm6
  movdqu  [r9 + 128], xmm10
  movdqu  xmm6, [r8 + 192]
  pxor    xmm3, xmm6
  movdqu  [r9 + 192], xmm3
  movdqu  xmm6, [r8 + 16]
  pxor    xmm4, xmm6
  movdqu  [r9 + 16], xmm4
  movdqu  xmm6, [r8 + 80]
  pxor    xmm5, xmm6
  movdqu  [r9 + 80], xmm5
  movdqu  xmm6, [r8 + 144]
  pxor    xmm2, xmm6
  movdqu  [r9 + 144], xmm2
  movdqu  xmm6, [r8 + 208]
  pxor    xmm7, xmm6
  movdqu  [r9 + 208], xmm7
  movdqa  xmm0, [rsp + 32]
  movdqa  xmm1, [rsp + 48]
  db $66, $44, $0F, $FE, $84, $24, $C0, $00, $00, $00  // paddd xmm8, [rsp + 192]
  db $66, $44, $0F, $FE, $8C, $24, $D0, $00, $00, $00  // paddd xmm9, [rsp + 208]
  db $66, $0F, $FE, $84, $24, $E0, $00, $00, $00       // paddd xmm0, [rsp + 224]
  db $66, $0F, $FE, $8C, $24, $F0, $00, $00, $00       // paddd xmm1, [rsp + 240]
  db $66, $41, $0F, $6F, $D0                           // movdqa xmm2, xmm8
  db $66, $45, $0F, $62, $C1                           // punpckldq xmm8, xmm9
  db $66, $41, $0F, $6A, $D1                           // punpckhdq xmm2, xmm9
  movdqa  xmm3, xmm0
  db $66, $0F, $62, $C1                                // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $D9                                // punpckhdq xmm3, xmm1
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $44, $0F, $6C, $C0                           // punpcklqdq xmm8, xmm0
  db $66, $44, $0F, $6D, $C8                           // punpckhqdq xmm9, xmm0
  movdqa  xmm1, xmm2
  db $66, $0F, $6C, $D3                                // punpcklqdq xmm2, xmm3
  db $66, $0F, $6D, $CB                                // punpckhqdq xmm1, xmm3
  db $66, $44, $0F, $FE, $A4, $24, $00, $01, $00, $00  // paddd xmm12, [rsp + 256]
  db $66, $44, $0F, $FE, $AC, $24, $10, $01, $00, $00  // paddd xmm13, [rsp + 272]
  db $66, $44, $0F, $FE, $B4, $24, $20, $01, $00, $00  // paddd xmm14, [rsp + 288]
  db $66, $44, $0F, $FE, $BC, $24, $30, $01, $00, $00  // paddd xmm15, [rsp + 304]
  db $66, $41, $0F, $6F, $C4                           // movdqa xmm0, xmm12
  db $66, $45, $0F, $62, $E5                           // punpckldq xmm12, xmm13
  db $66, $41, $0F, $6A, $C5                           // punpckhdq xmm0, xmm13
  db $66, $41, $0F, $6F, $DE                           // movdqa xmm3, xmm14
  db $66, $45, $0F, $62, $F7                           // punpckldq xmm14, xmm15
  db $66, $41, $0F, $6A, $DF                           // punpckhdq xmm3, xmm15
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $45, $0F, $6C, $E6                           // punpcklqdq xmm12, xmm14
  db $66, $45, $0F, $6D, $EE                           // punpckhqdq xmm13, xmm14
  db $66, $44, $0F, $6F, $F8                           // movdqa xmm15, xmm0
  db $66, $0F, $6C, $C3                                // punpcklqdq xmm0, xmm3
  db $66, $44, $0F, $6D, $FB                           // punpckhqdq xmm15, xmm3
  movdqu  xmm3, [r8 + 32]
  db $66, $44, $0F, $EF, $C3                           // pxor xmm8, xmm3
  movdqu  [r9 + 32], xmm8
  movdqu  xmm3, [r8 + 96]
  db $66, $44, $0F, $EF, $CB                           // pxor xmm9, xmm3
  movdqu  [r9 + 96], xmm9
  movdqu  xmm3, [r8 + 160]
  pxor    xmm2, xmm3
  movdqu  [r9 + 160], xmm2
  movdqu  xmm3, [r8 + 224]
  pxor    xmm1, xmm3
  movdqu  [r9 + 224], xmm1
  movdqu  xmm3, [r8 + 48]
  db $66, $44, $0F, $EF, $E3                           // pxor xmm12, xmm3
  movdqu  [r9 + 48], xmm12
  movdqu  xmm3, [r8 + 112]
  db $66, $44, $0F, $EF, $EB                           // pxor xmm13, xmm3
  movdqu  [r9 + 112], xmm13
  movdqu  xmm3, [r8 + 176]
  pxor    xmm0, xmm3
  movdqu  [r9 + 176], xmm0
  movdqu  xmm3, [r8 + 240]
  db $66, $44, $0F, $EF, $FB                           // pxor xmm15, xmm3
  movdqu  [r9 + 240], xmm15
  add     r8, 256
  add     r9, 256
  dec     r10
  jnz     @@c7539_ssse3_outer
  mov     rsp, r11
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

