// ChaCha7539 (IETF) 8-way (512B) AVX2 keystream kernel, vertical layout (x86-64).
// -------------------------------------------------------------------
//
// Eight 64-byte ChaCha20 blocks, state words held vertically (one block per
// ymm lane). ymm0-3 = words a (0-3), ymm4-7 = words b (4-7), ymm12-15 = words
// d (12-15). Words c (8-11): two are resident in ymm8/ymm9 while the other two
// wait in stack slots; quarter-rounds run as two resident pairs and the pair a
// round ends with is the pair the next round starts with, so a round costs one
// pair swap (2 stores + 2 loads). ymm10/ymm11 are the rotate temps; rot16/rot8
// use vpshufb (mask reloaded into the just-freed temp), rot12/rot7 use
// vpslld/vpsrld/vpor. The frame is 64B-aligned (r11 = frame register), so all
// stack traffic is aligned vmovdqa.
//
// Streams AGroups x 512B in one call: frame, broadcasts and constants are set
// up once; each group re-enters via a light state reload (counter lanes +8)
// and ends with a fused accumulate/transpose/xor written straight to AOut
// (vperm2i128 pairs whole 32-byte block halves; no bounce buffer).
//
// On entry (after ClpSimdProc5Begin_x86_64.inc):
//   rcx = ARounds, rdx = AState (16 UInt32), r8 = AIn, r9 = AOut,
//   r10 = AGroups (8-block groups, >= 1).
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 8*AGroups; the keystream is
//   xored with AIn into AOut (512*AGroups bytes).
//
// VEX-encoded instructions are db-encoded for broad assembler compatibility.
  mov     r10d, r10d
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  mov     r11, rsp
  sub     rsp, 832
  and     rsp, -64
  mov     dword ptr [rsp + 640], 0
  mov     dword ptr [rsp + 644], 1
  mov     dword ptr [rsp + 648], 2
  mov     dword ptr [rsp + 652], 3
  mov     dword ptr [rsp + 656], 4
  mov     dword ptr [rsp + 660], 5
  mov     dword ptr [rsp + 664], 6
  mov     dword ptr [rsp + 668], 7
  mov     dword ptr [rsp + 672], 8
  mov     dword ptr [rsp + 676], 8
  mov     dword ptr [rsp + 680], 8
  mov     dword ptr [rsp + 684], 8
  mov     dword ptr [rsp + 688], 8
  mov     dword ptr [rsp + 692], 8
  mov     dword ptr [rsp + 696], 8
  mov     dword ptr [rsp + 700], 8
  mov     dword ptr [rsp + 704], $01000302
  mov     dword ptr [rsp + 708], $05040706
  mov     dword ptr [rsp + 712], $09080B0A
  mov     dword ptr [rsp + 716], $0D0C0F0E
  mov     dword ptr [rsp + 720], $01000302
  mov     dword ptr [rsp + 724], $05040706
  mov     dword ptr [rsp + 728], $09080B0A
  mov     dword ptr [rsp + 732], $0D0C0F0E
  mov     dword ptr [rsp + 736], $02010003
  mov     dword ptr [rsp + 740], $06050407
  mov     dword ptr [rsp + 744], $0A09080B
  mov     dword ptr [rsp + 748], $0E0D0C0F
  mov     dword ptr [rsp + 752], $02010003
  mov     dword ptr [rsp + 756], $06050407
  mov     dword ptr [rsp + 760], $0A09080B
  mov     dword ptr [rsp + 764], $0E0D0C0F
  db $C4, $E2, $7D, $58, $02                      // vpbroadcastd ymm0, [rdx]
  db $C5, $FD, $7F, $84, $24, $80, $00, $00, $00  // vmovdqa [rsp + 128], ymm0
  db $C4, $E2, $7D, $58, $4A, $04                 // vpbroadcastd ymm1, [rdx + 4]
  db $C5, $FD, $7F, $8C, $24, $A0, $00, $00, $00  // vmovdqa [rsp + 160], ymm1
  db $C4, $E2, $7D, $58, $52, $08                 // vpbroadcastd ymm2, [rdx + 8]
  db $C5, $FD, $7F, $94, $24, $C0, $00, $00, $00  // vmovdqa [rsp + 192], ymm2
  db $C4, $E2, $7D, $58, $5A, $0C                 // vpbroadcastd ymm3, [rdx + 12]
  db $C5, $FD, $7F, $9C, $24, $E0, $00, $00, $00  // vmovdqa [rsp + 224], ymm3
  db $C4, $E2, $7D, $58, $62, $10                 // vpbroadcastd ymm4, [rdx + 16]
  db $C5, $FD, $7F, $A4, $24, $00, $01, $00, $00  // vmovdqa [rsp + 256], ymm4
  db $C4, $E2, $7D, $58, $6A, $14                 // vpbroadcastd ymm5, [rdx + 20]
  db $C5, $FD, $7F, $AC, $24, $20, $01, $00, $00  // vmovdqa [rsp + 288], ymm5
  db $C4, $E2, $7D, $58, $72, $18                 // vpbroadcastd ymm6, [rdx + 24]
  db $C5, $FD, $7F, $B4, $24, $40, $01, $00, $00  // vmovdqa [rsp + 320], ymm6
  db $C4, $E2, $7D, $58, $7A, $1C                 // vpbroadcastd ymm7, [rdx + 28]
  db $C5, $FD, $7F, $BC, $24, $60, $01, $00, $00  // vmovdqa [rsp + 352], ymm7
  db $C4, $62, $7D, $58, $42, $20                 // vpbroadcastd ymm8, [rdx + 32]
  db $C5, $7D, $7F, $84, $24, $80, $01, $00, $00  // vmovdqa [rsp + 384], ymm8
  db $C4, $62, $7D, $58, $4A, $24                 // vpbroadcastd ymm9, [rdx + 36]
  db $C5, $7D, $7F, $8C, $24, $A0, $01, $00, $00  // vmovdqa [rsp + 416], ymm9
  db $C4, $62, $7D, $58, $52, $28                 // vpbroadcastd ymm10, [rdx + 40]
  db $C5, $7D, $7F, $94, $24, $C0, $01, $00, $00  // vmovdqa [rsp + 448], ymm10
  db $C5, $7D, $7F, $54, $24, $40                 // vmovdqa [rsp + 64], ymm10
  db $C4, $62, $7D, $58, $52, $2C                 // vpbroadcastd ymm10, [rdx + 44]
  db $C5, $7D, $7F, $94, $24, $E0, $01, $00, $00  // vmovdqa [rsp + 480], ymm10
  db $C5, $7D, $7F, $54, $24, $60                 // vmovdqa [rsp + 96], ymm10
  db $C4, $62, $7D, $58, $62, $30                 // vpbroadcastd ymm12, [rdx + 48]
  db $C5, $1D, $FE, $A4, $24, $80, $02, $00, $00  // vpaddd ymm12, ymm12, [rsp + 640]
  db $C5, $7D, $7F, $A4, $24, $00, $02, $00, $00  // vmovdqa [rsp + 512], ymm12
  db $C4, $62, $7D, $58, $6A, $34                 // vpbroadcastd ymm13, [rdx + 52]
  db $C5, $7D, $7F, $AC, $24, $20, $02, $00, $00  // vmovdqa [rsp + 544], ymm13
  db $C4, $62, $7D, $58, $72, $38                 // vpbroadcastd ymm14, [rdx + 56]
  db $C5, $7D, $7F, $B4, $24, $40, $02, $00, $00  // vmovdqa [rsp + 576], ymm14
  db $C4, $62, $7D, $58, $7A, $3C                 // vpbroadcastd ymm15, [rdx + 60]
  db $C5, $7D, $7F, $BC, $24, $60, $02, $00, $00  // vmovdqa [rsp + 608], ymm15
  db $C5, $7D, $6F, $9C, $24, $C0, $02, $00, $00  // vmovdqa ymm11, [rsp + 704]
  jmp     @@c7539_avx2_8x_enter
@@c7539_avx2_8x_outer:
  db $C5, $FD, $6F, $84, $24, $80, $00, $00, $00  // vmovdqa ymm0, [rsp + 128]
  db $C5, $FD, $6F, $8C, $24, $A0, $00, $00, $00  // vmovdqa ymm1, [rsp + 160]
  db $C5, $FD, $6F, $94, $24, $C0, $00, $00, $00  // vmovdqa ymm2, [rsp + 192]
  db $C5, $FD, $6F, $9C, $24, $E0, $00, $00, $00  // vmovdqa ymm3, [rsp + 224]
  db $C5, $FD, $6F, $A4, $24, $00, $01, $00, $00  // vmovdqa ymm4, [rsp + 256]
  db $C5, $FD, $6F, $AC, $24, $20, $01, $00, $00  // vmovdqa ymm5, [rsp + 288]
  db $C5, $FD, $6F, $B4, $24, $40, $01, $00, $00  // vmovdqa ymm6, [rsp + 320]
  db $C5, $FD, $6F, $BC, $24, $60, $01, $00, $00  // vmovdqa ymm7, [rsp + 352]
  db $C5, $7D, $6F, $84, $24, $80, $01, $00, $00  // vmovdqa ymm8, [rsp + 384]
  db $C5, $7D, $6F, $8C, $24, $A0, $01, $00, $00  // vmovdqa ymm9, [rsp + 416]
  db $C5, $7D, $6F, $94, $24, $C0, $01, $00, $00  // vmovdqa ymm10, [rsp + 448]
  db $C5, $7D, $7F, $54, $24, $40                 // vmovdqa [rsp + 64], ymm10
  db $C5, $7D, $6F, $94, $24, $E0, $01, $00, $00  // vmovdqa ymm10, [rsp + 480]
  db $C5, $7D, $7F, $54, $24, $60                 // vmovdqa [rsp + 96], ymm10
  db $C5, $7D, $6F, $A4, $24, $00, $02, $00, $00  // vmovdqa ymm12, [rsp + 512]
  db $C5, $1D, $FE, $A4, $24, $A0, $02, $00, $00  // vpaddd ymm12, ymm12, [rsp + 672]
  db $C5, $7D, $7F, $A4, $24, $00, $02, $00, $00  // vmovdqa [rsp + 512], ymm12
  db $C5, $7D, $6F, $AC, $24, $20, $02, $00, $00  // vmovdqa ymm13, [rsp + 544]
  db $C5, $7D, $6F, $B4, $24, $40, $02, $00, $00  // vmovdqa ymm14, [rsp + 576]
  db $C5, $7D, $6F, $BC, $24, $60, $02, $00, $00  // vmovdqa ymm15, [rsp + 608]
  db $C5, $7D, $6F, $9C, $24, $C0, $02, $00, $00  // vmovdqa ymm11, [rsp + 704]
@@c7539_avx2_8x_enter:
  mov     eax, ecx
@@c7539_avx2_8x_round:
  db $C5, $FD, $FE, $C4                           // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                           // vpxor ymm12, ymm12, ymm0
  db $C4, $42, $1D, $00, $E3                      // vpshufb ymm12, ymm12, ymm11
  db $C5, $F5, $FE, $CD                           // vpaddd ymm1, ymm1, ymm5
  db $C5, $15, $EF, $E9                           // vpxor ymm13, ymm13, ymm1
  db $C4, $42, $15, $00, $EB                      // vpshufb ymm13, ymm13, ymm11
  db $C4, $41, $3D, $FE, $C4                      // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                      // vpxor ymm4, ymm4, ymm8
  db $C5, $AD, $72, $F4, $0C                      // vpslld ymm10, ymm4, 12
  db $C5, $DD, $72, $D4, $14                      // vpsrld ymm4, ymm4, 20
  db $C5, $AD, $EB, $E4                           // vpor ymm4, ymm10, ymm4
  db $C5, $7D, $6F, $94, $24, $E0, $02, $00, $00  // vmovdqa ymm10, [rsp + 736]
  db $C4, $41, $35, $FE, $CD                      // vpaddd ymm9, ymm9, ymm13
  db $C4, $C1, $55, $EF, $E9                      // vpxor ymm5, ymm5, ymm9
  db $C5, $A5, $72, $F5, $0C                      // vpslld ymm11, ymm5, 12
  db $C5, $D5, $72, $D5, $14                      // vpsrld ymm5, ymm5, 20
  db $C5, $A5, $EB, $ED                           // vpor ymm5, ymm11, ymm5
  db $C5, $FD, $FE, $C4                           // vpaddd ymm0, ymm0, ymm4
  db $C5, $1D, $EF, $E0                           // vpxor ymm12, ymm12, ymm0
  db $C4, $42, $1D, $00, $E2                      // vpshufb ymm12, ymm12, ymm10
  db $C5, $F5, $FE, $CD                           // vpaddd ymm1, ymm1, ymm5
  db $C5, $15, $EF, $E9                           // vpxor ymm13, ymm13, ymm1
  db $C4, $42, $15, $00, $EA                      // vpshufb ymm13, ymm13, ymm10
  db $C4, $41, $3D, $FE, $C4                      // vpaddd ymm8, ymm8, ymm12
  db $C4, $C1, $5D, $EF, $E0                      // vpxor ymm4, ymm4, ymm8
  db $C5, $A5, $72, $F4, $07                      // vpslld ymm11, ymm4, 7
  db $C5, $DD, $72, $D4, $19                      // vpsrld ymm4, ymm4, 25
  db $C5, $A5, $EB, $E4                           // vpor ymm4, ymm11, ymm4
  db $C5, $7D, $6F, $9C, $24, $C0, $02, $00, $00  // vmovdqa ymm11, [rsp + 704]
  db $C4, $41, $35, $FE, $CD                      // vpaddd ymm9, ymm9, ymm13
  db $C4, $C1, $55, $EF, $E9                      // vpxor ymm5, ymm5, ymm9
  db $C5, $AD, $72, $F5, $07                      // vpslld ymm10, ymm5, 7
  db $C5, $D5, $72, $D5, $19                      // vpsrld ymm5, ymm5, 25
  db $C5, $AD, $EB, $ED                           // vpor ymm5, ymm10, ymm5
  db $C5, $7D, $7F, $04, $24                      // vmovdqa [rsp], ymm8
  db $C5, $7D, $7F, $4C, $24, $20                 // vmovdqa [rsp + 32], ymm9
  db $C5, $7D, $6F, $44, $24, $40                 // vmovdqa ymm8, [rsp + 64]
  db $C5, $7D, $6F, $4C, $24, $60                 // vmovdqa ymm9, [rsp + 96]
  db $C5, $ED, $FE, $D6                           // vpaddd ymm2, ymm2, ymm6
  db $C5, $0D, $EF, $F2                           // vpxor ymm14, ymm14, ymm2
  db $C4, $42, $0D, $00, $F3                      // vpshufb ymm14, ymm14, ymm11
  db $C5, $E5, $FE, $DF                           // vpaddd ymm3, ymm3, ymm7
  db $C5, $05, $EF, $FB                           // vpxor ymm15, ymm15, ymm3
  db $C4, $42, $05, $00, $FB                      // vpshufb ymm15, ymm15, ymm11
  db $C4, $41, $3D, $FE, $C6                      // vpaddd ymm8, ymm8, ymm14
  db $C4, $C1, $4D, $EF, $F0                      // vpxor ymm6, ymm6, ymm8
  db $C5, $AD, $72, $F6, $0C                      // vpslld ymm10, ymm6, 12
  db $C5, $CD, $72, $D6, $14                      // vpsrld ymm6, ymm6, 20
  db $C5, $AD, $EB, $F6                           // vpor ymm6, ymm10, ymm6
  db $C5, $7D, $6F, $94, $24, $E0, $02, $00, $00  // vmovdqa ymm10, [rsp + 736]
  db $C4, $41, $35, $FE, $CF                      // vpaddd ymm9, ymm9, ymm15
  db $C4, $C1, $45, $EF, $F9                      // vpxor ymm7, ymm7, ymm9
  db $C5, $A5, $72, $F7, $0C                      // vpslld ymm11, ymm7, 12
  db $C5, $C5, $72, $D7, $14                      // vpsrld ymm7, ymm7, 20
  db $C5, $A5, $EB, $FF                           // vpor ymm7, ymm11, ymm7
  db $C5, $ED, $FE, $D6                           // vpaddd ymm2, ymm2, ymm6
  db $C5, $0D, $EF, $F2                           // vpxor ymm14, ymm14, ymm2
  db $C4, $42, $0D, $00, $F2                      // vpshufb ymm14, ymm14, ymm10
  db $C5, $E5, $FE, $DF                           // vpaddd ymm3, ymm3, ymm7
  db $C5, $05, $EF, $FB                           // vpxor ymm15, ymm15, ymm3
  db $C4, $42, $05, $00, $FA                      // vpshufb ymm15, ymm15, ymm10
  db $C4, $41, $3D, $FE, $C6                      // vpaddd ymm8, ymm8, ymm14
  db $C4, $C1, $4D, $EF, $F0                      // vpxor ymm6, ymm6, ymm8
  db $C5, $A5, $72, $F6, $07                      // vpslld ymm11, ymm6, 7
  db $C5, $CD, $72, $D6, $19                      // vpsrld ymm6, ymm6, 25
  db $C5, $A5, $EB, $F6                           // vpor ymm6, ymm11, ymm6
  db $C5, $7D, $6F, $9C, $24, $C0, $02, $00, $00  // vmovdqa ymm11, [rsp + 704]
  db $C4, $41, $35, $FE, $CF                      // vpaddd ymm9, ymm9, ymm15
  db $C4, $C1, $45, $EF, $F9                      // vpxor ymm7, ymm7, ymm9
  db $C5, $AD, $72, $F7, $07                      // vpslld ymm10, ymm7, 7
  db $C5, $C5, $72, $D7, $19                      // vpsrld ymm7, ymm7, 25
  db $C5, $AD, $EB, $FF                           // vpor ymm7, ymm10, ymm7
  db $C5, $FD, $FE, $C5                           // vpaddd ymm0, ymm0, ymm5
  db $C5, $05, $EF, $F8                           // vpxor ymm15, ymm15, ymm0
  db $C4, $42, $05, $00, $FB                      // vpshufb ymm15, ymm15, ymm11
  db $C5, $F5, $FE, $CE                           // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                           // vpxor ymm12, ymm12, ymm1
  db $C4, $42, $1D, $00, $E3                      // vpshufb ymm12, ymm12, ymm11
  db $C4, $41, $3D, $FE, $C7                      // vpaddd ymm8, ymm8, ymm15
  db $C4, $C1, $55, $EF, $E8                      // vpxor ymm5, ymm5, ymm8
  db $C5, $AD, $72, $F5, $0C                      // vpslld ymm10, ymm5, 12
  db $C5, $D5, $72, $D5, $14                      // vpsrld ymm5, ymm5, 20
  db $C5, $AD, $EB, $ED                           // vpor ymm5, ymm10, ymm5
  db $C5, $7D, $6F, $94, $24, $E0, $02, $00, $00  // vmovdqa ymm10, [rsp + 736]
  db $C4, $41, $35, $FE, $CC                      // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $4D, $EF, $F1                      // vpxor ymm6, ymm6, ymm9
  db $C5, $A5, $72, $F6, $0C                      // vpslld ymm11, ymm6, 12
  db $C5, $CD, $72, $D6, $14                      // vpsrld ymm6, ymm6, 20
  db $C5, $A5, $EB, $F6                           // vpor ymm6, ymm11, ymm6
  db $C5, $FD, $FE, $C5                           // vpaddd ymm0, ymm0, ymm5
  db $C5, $05, $EF, $F8                           // vpxor ymm15, ymm15, ymm0
  db $C4, $42, $05, $00, $FA                      // vpshufb ymm15, ymm15, ymm10
  db $C5, $F5, $FE, $CE                           // vpaddd ymm1, ymm1, ymm6
  db $C5, $1D, $EF, $E1                           // vpxor ymm12, ymm12, ymm1
  db $C4, $42, $1D, $00, $E2                      // vpshufb ymm12, ymm12, ymm10
  db $C4, $41, $3D, $FE, $C7                      // vpaddd ymm8, ymm8, ymm15
  db $C4, $C1, $55, $EF, $E8                      // vpxor ymm5, ymm5, ymm8
  db $C5, $A5, $72, $F5, $07                      // vpslld ymm11, ymm5, 7
  db $C5, $D5, $72, $D5, $19                      // vpsrld ymm5, ymm5, 25
  db $C5, $A5, $EB, $ED                           // vpor ymm5, ymm11, ymm5
  db $C5, $7D, $6F, $9C, $24, $C0, $02, $00, $00  // vmovdqa ymm11, [rsp + 704]
  db $C4, $41, $35, $FE, $CC                      // vpaddd ymm9, ymm9, ymm12
  db $C4, $C1, $4D, $EF, $F1                      // vpxor ymm6, ymm6, ymm9
  db $C5, $AD, $72, $F6, $07                      // vpslld ymm10, ymm6, 7
  db $C5, $CD, $72, $D6, $19                      // vpsrld ymm6, ymm6, 25
  db $C5, $AD, $EB, $F6                           // vpor ymm6, ymm10, ymm6
  db $C5, $7D, $7F, $44, $24, $40                 // vmovdqa [rsp + 64], ymm8
  db $C5, $7D, $7F, $4C, $24, $60                 // vmovdqa [rsp + 96], ymm9
  db $C5, $7D, $6F, $04, $24                      // vmovdqa ymm8, [rsp]
  db $C5, $7D, $6F, $4C, $24, $20                 // vmovdqa ymm9, [rsp + 32]
  db $C5, $ED, $FE, $D7                           // vpaddd ymm2, ymm2, ymm7
  db $C5, $15, $EF, $EA                           // vpxor ymm13, ymm13, ymm2
  db $C4, $42, $15, $00, $EB                      // vpshufb ymm13, ymm13, ymm11
  db $C5, $E5, $FE, $DC                           // vpaddd ymm3, ymm3, ymm4
  db $C5, $0D, $EF, $F3                           // vpxor ymm14, ymm14, ymm3
  db $C4, $42, $0D, $00, $F3                      // vpshufb ymm14, ymm14, ymm11
  db $C4, $41, $3D, $FE, $C5                      // vpaddd ymm8, ymm8, ymm13
  db $C4, $C1, $45, $EF, $F8                      // vpxor ymm7, ymm7, ymm8
  db $C5, $AD, $72, $F7, $0C                      // vpslld ymm10, ymm7, 12
  db $C5, $C5, $72, $D7, $14                      // vpsrld ymm7, ymm7, 20
  db $C5, $AD, $EB, $FF                           // vpor ymm7, ymm10, ymm7
  db $C5, $7D, $6F, $94, $24, $E0, $02, $00, $00  // vmovdqa ymm10, [rsp + 736]
  db $C4, $41, $35, $FE, $CE                      // vpaddd ymm9, ymm9, ymm14
  db $C4, $C1, $5D, $EF, $E1                      // vpxor ymm4, ymm4, ymm9
  db $C5, $A5, $72, $F4, $0C                      // vpslld ymm11, ymm4, 12
  db $C5, $DD, $72, $D4, $14                      // vpsrld ymm4, ymm4, 20
  db $C5, $A5, $EB, $E4                           // vpor ymm4, ymm11, ymm4
  db $C5, $ED, $FE, $D7                           // vpaddd ymm2, ymm2, ymm7
  db $C5, $15, $EF, $EA                           // vpxor ymm13, ymm13, ymm2
  db $C4, $42, $15, $00, $EA                      // vpshufb ymm13, ymm13, ymm10
  db $C5, $E5, $FE, $DC                           // vpaddd ymm3, ymm3, ymm4
  db $C5, $0D, $EF, $F3                           // vpxor ymm14, ymm14, ymm3
  db $C4, $42, $0D, $00, $F2                      // vpshufb ymm14, ymm14, ymm10
  db $C4, $41, $3D, $FE, $C5                      // vpaddd ymm8, ymm8, ymm13
  db $C4, $C1, $45, $EF, $F8                      // vpxor ymm7, ymm7, ymm8
  db $C5, $A5, $72, $F7, $07                      // vpslld ymm11, ymm7, 7
  db $C5, $C5, $72, $D7, $19                      // vpsrld ymm7, ymm7, 25
  db $C5, $A5, $EB, $FF                           // vpor ymm7, ymm11, ymm7
  db $C5, $7D, $6F, $9C, $24, $C0, $02, $00, $00  // vmovdqa ymm11, [rsp + 704]
  db $C4, $41, $35, $FE, $CE                      // vpaddd ymm9, ymm9, ymm14
  db $C4, $C1, $5D, $EF, $E1                      // vpxor ymm4, ymm4, ymm9
  db $C5, $AD, $72, $F4, $07                      // vpslld ymm10, ymm4, 7
  db $C5, $DD, $72, $D4, $19                      // vpsrld ymm4, ymm4, 25
  db $C5, $AD, $EB, $E4                           // vpor ymm4, ymm10, ymm4
  sub     eax, 2
  jg      @@c7539_avx2_8x_round
  add     dword ptr [rdx + 48], 8
{$IFDEF CHACHA_CTR64}
  adc     dword ptr [rdx + 52], 0
{$ENDIF}
  db $C5, $FD, $FE, $84, $24, $80, $00, $00, $00  // vpaddd ymm0, ymm0, [rsp + 128]
  db $C5, $F5, $FE, $8C, $24, $A0, $00, $00, $00  // vpaddd ymm1, ymm1, [rsp + 160]
  db $C5, $ED, $FE, $94, $24, $C0, $00, $00, $00  // vpaddd ymm2, ymm2, [rsp + 192]
  db $C5, $E5, $FE, $9C, $24, $E0, $00, $00, $00  // vpaddd ymm3, ymm3, [rsp + 224]
  db $C5, $7D, $62, $D1                           // vpunpckldq ymm10, ymm0, ymm1
  db $C5, $6D, $62, $DB                           // vpunpckldq ymm11, ymm2, ymm3
  db $C5, $FD, $6A, $C1                           // vpunpckhdq ymm0, ymm0, ymm1
  db $C5, $ED, $6A, $D3                           // vpunpckhdq ymm2, ymm2, ymm3
  db $C4, $C1, $2D, $6C, $CB                      // vpunpcklqdq ymm1, ymm10, ymm11
  db $C4, $41, $2D, $6D, $D3                      // vpunpckhqdq ymm10, ymm10, ymm11
  db $C5, $FD, $6C, $DA                           // vpunpcklqdq ymm3, ymm0, ymm2
  db $C5, $FD, $6D, $C2                           // vpunpckhqdq ymm0, ymm0, ymm2
  db $C5, $DD, $FE, $A4, $24, $00, $01, $00, $00  // vpaddd ymm4, ymm4, [rsp + 256]
  db $C5, $D5, $FE, $AC, $24, $20, $01, $00, $00  // vpaddd ymm5, ymm5, [rsp + 288]
  db $C5, $CD, $FE, $B4, $24, $40, $01, $00, $00  // vpaddd ymm6, ymm6, [rsp + 320]
  db $C5, $C5, $FE, $BC, $24, $60, $01, $00, $00  // vpaddd ymm7, ymm7, [rsp + 352]
  db $C5, $DD, $62, $D5                           // vpunpckldq ymm2, ymm4, ymm5
  db $C5, $4D, $62, $DF                           // vpunpckldq ymm11, ymm6, ymm7
  db $C5, $DD, $6A, $E5                           // vpunpckhdq ymm4, ymm4, ymm5
  db $C5, $CD, $6A, $F7                           // vpunpckhdq ymm6, ymm6, ymm7
  db $C4, $C1, $6D, $6C, $EB                      // vpunpcklqdq ymm5, ymm2, ymm11
  db $C4, $C1, $6D, $6D, $D3                      // vpunpckhqdq ymm2, ymm2, ymm11
  db $C5, $DD, $6C, $FE                           // vpunpcklqdq ymm7, ymm4, ymm6
  db $C5, $DD, $6D, $E6                           // vpunpckhqdq ymm4, ymm4, ymm6
  db $C4, $E3, $75, $46, $F5, $20                 // vperm2i128 ymm6, ymm1, ymm5, $20
  db $C4, $E3, $75, $46, $ED, $31                 // vperm2i128 ymm5, ymm1, ymm5, $31
  db $C4, $E3, $2D, $46, $CA, $20                 // vperm2i128 ymm1, ymm10, ymm2, $20
  db $C4, $E3, $2D, $46, $D2, $31                 // vperm2i128 ymm2, ymm10, ymm2, $31
  db $C4, $63, $65, $46, $D7, $20                 // vperm2i128 ymm10, ymm3, ymm7, $20
  db $C4, $E3, $65, $46, $FF, $31                 // vperm2i128 ymm7, ymm3, ymm7, $31
  db $C4, $E3, $7D, $46, $DC, $20                 // vperm2i128 ymm3, ymm0, ymm4, $20
  db $C4, $E3, $7D, $46, $E4, $31                 // vperm2i128 ymm4, ymm0, ymm4, $31
  db $C5, $FD, $7F, $B4, $24, $00, $03, $00, $00  // vmovdqa [rsp + 768], ymm6
  db $C5, $FD, $7F, $8C, $24, $20, $03, $00, $00  // vmovdqa [rsp + 800], ymm1
  db $C5, $FD, $6F, $44, $24, $40                 // vmovdqa ymm0, [rsp + 64]
  db $C5, $FD, $6F, $4C, $24, $60                 // vmovdqa ymm1, [rsp + 96]
  db $C5, $3D, $FE, $84, $24, $80, $01, $00, $00  // vpaddd ymm8, ymm8, [rsp + 384]
  db $C5, $35, $FE, $8C, $24, $A0, $01, $00, $00  // vpaddd ymm9, ymm9, [rsp + 416]
  db $C5, $FD, $FE, $84, $24, $C0, $01, $00, $00  // vpaddd ymm0, ymm0, [rsp + 448]
  db $C5, $F5, $FE, $8C, $24, $E0, $01, $00, $00  // vpaddd ymm1, ymm1, [rsp + 480]
  db $C4, $C1, $3D, $62, $F1                      // vpunpckldq ymm6, ymm8, ymm9
  db $C5, $7D, $62, $D9                           // vpunpckldq ymm11, ymm0, ymm1
  db $C4, $41, $3D, $6A, $C1                      // vpunpckhdq ymm8, ymm8, ymm9
  db $C5, $FD, $6A, $C1                           // vpunpckhdq ymm0, ymm0, ymm1
  db $C4, $41, $4D, $6C, $CB                      // vpunpcklqdq ymm9, ymm6, ymm11
  db $C4, $C1, $4D, $6D, $F3                      // vpunpckhqdq ymm6, ymm6, ymm11
  db $C5, $BD, $6C, $C8                           // vpunpcklqdq ymm1, ymm8, ymm0
  db $C5, $3D, $6D, $C0                           // vpunpckhqdq ymm8, ymm8, ymm0
  db $C5, $1D, $FE, $A4, $24, $00, $02, $00, $00  // vpaddd ymm12, ymm12, [rsp + 512]
  db $C5, $15, $FE, $AC, $24, $20, $02, $00, $00  // vpaddd ymm13, ymm13, [rsp + 544]
  db $C5, $0D, $FE, $B4, $24, $40, $02, $00, $00  // vpaddd ymm14, ymm14, [rsp + 576]
  db $C5, $05, $FE, $BC, $24, $60, $02, $00, $00  // vpaddd ymm15, ymm15, [rsp + 608]
  db $C4, $C1, $1D, $62, $C5                      // vpunpckldq ymm0, ymm12, ymm13
  db $C4, $41, $0D, $62, $DF                      // vpunpckldq ymm11, ymm14, ymm15
  db $C4, $41, $1D, $6A, $E5                      // vpunpckhdq ymm12, ymm12, ymm13
  db $C4, $41, $0D, $6A, $F7                      // vpunpckhdq ymm14, ymm14, ymm15
  db $C4, $41, $7D, $6C, $EB                      // vpunpcklqdq ymm13, ymm0, ymm11
  db $C4, $C1, $7D, $6D, $C3                      // vpunpckhqdq ymm0, ymm0, ymm11
  db $C4, $41, $1D, $6C, $FE                      // vpunpcklqdq ymm15, ymm12, ymm14
  db $C4, $41, $1D, $6D, $E6                      // vpunpckhqdq ymm12, ymm12, ymm14
  db $C4, $43, $35, $46, $DD, $20                 // vperm2i128 ymm11, ymm9, ymm13, $20
  db $C4, $43, $35, $46, $ED, $31                 // vperm2i128 ymm13, ymm9, ymm13, $31
  db $C4, $63, $4D, $46, $C8, $20                 // vperm2i128 ymm9, ymm6, ymm0, $20
  db $C4, $E3, $4D, $46, $C0, $31                 // vperm2i128 ymm0, ymm6, ymm0, $31
  db $C4, $C3, $75, $46, $F7, $20                 // vperm2i128 ymm6, ymm1, ymm15, $20
  db $C4, $43, $75, $46, $FF, $31                 // vperm2i128 ymm15, ymm1, ymm15, $31
  db $C4, $C3, $3D, $46, $CC, $20                 // vperm2i128 ymm1, ymm8, ymm12, $20
  db $C4, $43, $3D, $46, $E4, $31                 // vperm2i128 ymm12, ymm8, ymm12, $31
  db $C5, $7D, $6F, $84, $24, $00, $03, $00, $00  // vmovdqa ymm8, [rsp + 768]
  db $C4, $41, $3D, $EF, $00                      // vpxor ymm8, ymm8, [r8 + 0]
  db $C4, $41, $7E, $7F, $01                      // vmovdqu [r9], ymm8
  db $C4, $41, $25, $EF, $58, $20                 // vpxor ymm11, ymm11, [r8 + 32]
  db $C4, $41, $7E, $7F, $59, $20                 // vmovdqu [r9 + 32], ymm11
  db $C5, $7D, $6F, $B4, $24, $20, $03, $00, $00  // vmovdqa ymm14, [rsp + 800]
  db $C4, $41, $0D, $EF, $70, $40                 // vpxor ymm14, ymm14, [r8 + 64]
  db $C4, $41, $7E, $7F, $71, $40                 // vmovdqu [r9 + 64], ymm14
  db $C4, $41, $35, $EF, $48, $60                 // vpxor ymm9, ymm9, [r8 + 96]
  db $C4, $41, $7E, $7F, $49, $60                 // vmovdqu [r9 + 96], ymm9
  db $C4, $41, $2D, $EF, $90, $80, $00, $00, $00  // vpxor ymm10, ymm10, [r8 + 128]
  db $C4, $41, $7E, $7F, $91, $80, $00, $00, $00  // vmovdqu [r9 + 128], ymm10
  db $C4, $C1, $4D, $EF, $B0, $A0, $00, $00, $00  // vpxor ymm6, ymm6, [r8 + 160]
  db $C4, $C1, $7E, $7F, $B1, $A0, $00, $00, $00  // vmovdqu [r9 + 160], ymm6
  db $C4, $C1, $65, $EF, $98, $C0, $00, $00, $00  // vpxor ymm3, ymm3, [r8 + 192]
  db $C4, $C1, $7E, $7F, $99, $C0, $00, $00, $00  // vmovdqu [r9 + 192], ymm3
  db $C4, $C1, $75, $EF, $88, $E0, $00, $00, $00  // vpxor ymm1, ymm1, [r8 + 224]
  db $C4, $C1, $7E, $7F, $89, $E0, $00, $00, $00  // vmovdqu [r9 + 224], ymm1
  db $C4, $C1, $55, $EF, $A8, $00, $01, $00, $00  // vpxor ymm5, ymm5, [r8 + 256]
  db $C4, $C1, $7E, $7F, $A9, $00, $01, $00, $00  // vmovdqu [r9 + 256], ymm5
  db $C4, $41, $15, $EF, $A8, $20, $01, $00, $00  // vpxor ymm13, ymm13, [r8 + 288]
  db $C4, $41, $7E, $7F, $A9, $20, $01, $00, $00  // vmovdqu [r9 + 288], ymm13
  db $C4, $C1, $6D, $EF, $90, $40, $01, $00, $00  // vpxor ymm2, ymm2, [r8 + 320]
  db $C4, $C1, $7E, $7F, $91, $40, $01, $00, $00  // vmovdqu [r9 + 320], ymm2
  db $C4, $C1, $7D, $EF, $80, $60, $01, $00, $00  // vpxor ymm0, ymm0, [r8 + 352]
  db $C4, $C1, $7E, $7F, $81, $60, $01, $00, $00  // vmovdqu [r9 + 352], ymm0
  db $C4, $C1, $45, $EF, $B8, $80, $01, $00, $00  // vpxor ymm7, ymm7, [r8 + 384]
  db $C4, $C1, $7E, $7F, $B9, $80, $01, $00, $00  // vmovdqu [r9 + 384], ymm7
  db $C4, $41, $05, $EF, $B8, $A0, $01, $00, $00  // vpxor ymm15, ymm15, [r8 + 416]
  db $C4, $41, $7E, $7F, $B9, $A0, $01, $00, $00  // vmovdqu [r9 + 416], ymm15
  db $C4, $C1, $5D, $EF, $A0, $C0, $01, $00, $00  // vpxor ymm4, ymm4, [r8 + 448]
  db $C4, $C1, $7E, $7F, $A1, $C0, $01, $00, $00  // vmovdqu [r9 + 448], ymm4
  db $C4, $41, $1D, $EF, $A0, $E0, $01, $00, $00  // vpxor ymm12, ymm12, [r8 + 480]
  db $C4, $41, $7E, $7F, $A1, $E0, $01, $00, $00  // vmovdqu [r9 + 480], ymm12
  add     r8, 512
  add     r9, 512
  dec     r10
  jnz     @@c7539_avx2_8x_outer
  db $C5, $F8, $77                                // vzeroupper
  mov     rsp, r11
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

