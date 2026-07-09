// ChaCha7539 (IETF) 8-way (512B) AVX2 keystream kernel, vertical layout (x86-64).
// -------------------------------------------------------------------
//
// Eight 64-byte ChaCha20 blocks, state words held vertically (one block per
// ymm lane). ymm0-3 = words a (0-3), ymm4-7 = words b (4-7), ymm12-15 = words
// d (12-15); words c (8-11) live in a stack slot; ymm8-11 are scratch. The four
// quarter-rounds of each round are step-interleaved; rot16/rot8 use vpshufb with
// the mask read from memory; rot12/rot7 use vpslld/vpsrld/vpor.
//
// On entry (after ClpSimdProc4Begin_x86_64.inc):
//   rcx = ARounds, rdx = AState (16 UInt32), r8 = AIn, r9 = AOut.
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 8; the keystream is xored
//   with AIn into AOut (512 bytes).
//
// VEX-encoded instructions are db-encoded for broad assembler compatibility.
  mov     r10, rcx
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  sub     rsp, 1248
  mov     dword ptr [rsp + 640], 0
  mov     dword ptr [rsp + 644], 1
  mov     dword ptr [rsp + 648], 2
  mov     dword ptr [rsp + 652], 3
  mov     dword ptr [rsp + 656], 4
  mov     dword ptr [rsp + 660], 5
  mov     dword ptr [rsp + 664], 6
  mov     dword ptr [rsp + 668], 7
  mov     dword ptr [rsp + 672], $01000302
  mov     dword ptr [rsp + 676], $05040706
  mov     dword ptr [rsp + 680], $09080B0A
  mov     dword ptr [rsp + 684], $0D0C0F0E
  mov     dword ptr [rsp + 688], $01000302
  mov     dword ptr [rsp + 692], $05040706
  mov     dword ptr [rsp + 696], $09080B0A
  mov     dword ptr [rsp + 700], $0D0C0F0E
  mov     dword ptr [rsp + 704], $02010003
  mov     dword ptr [rsp + 708], $06050407
  mov     dword ptr [rsp + 712], $0A09080B
  mov     dword ptr [rsp + 716], $0E0D0C0F
  mov     dword ptr [rsp + 720], $02010003
  mov     dword ptr [rsp + 724], $06050407
  mov     dword ptr [rsp + 728], $0A09080B
  mov     dword ptr [rsp + 732], $0E0D0C0F
  db $C4, $E2, $7D, $58, $02                                // vpbroadcastd ymm0, [rdx]
  db $C5, $FE, $7F, $84, $24, $80, $00, $00, $00            // vmovdqu [rsp + 128], ymm0
  db $C4, $E2, $7D, $58, $4A, $04                           // vpbroadcastd ymm1, [rdx + 4]
  db $C5, $FE, $7F, $8C, $24, $A0, $00, $00, $00            // vmovdqu [rsp + 160], ymm1
  db $C4, $E2, $7D, $58, $52, $08                           // vpbroadcastd ymm2, [rdx + 8]
  db $C5, $FE, $7F, $94, $24, $C0, $00, $00, $00            // vmovdqu [rsp + 192], ymm2
  db $C4, $E2, $7D, $58, $5A, $0C                           // vpbroadcastd ymm3, [rdx + 12]
  db $C5, $FE, $7F, $9C, $24, $E0, $00, $00, $00            // vmovdqu [rsp + 224], ymm3
  db $C4, $E2, $7D, $58, $62, $10                           // vpbroadcastd ymm4, [rdx + 16]
  db $C5, $FE, $7F, $A4, $24, $00, $01, $00, $00            // vmovdqu [rsp + 256], ymm4
  db $C4, $E2, $7D, $58, $6A, $14                           // vpbroadcastd ymm5, [rdx + 20]
  db $C5, $FE, $7F, $AC, $24, $20, $01, $00, $00            // vmovdqu [rsp + 288], ymm5
  db $C4, $E2, $7D, $58, $72, $18                           // vpbroadcastd ymm6, [rdx + 24]
  db $C5, $FE, $7F, $B4, $24, $40, $01, $00, $00            // vmovdqu [rsp + 320], ymm6
  db $C4, $E2, $7D, $58, $7A, $1C                           // vpbroadcastd ymm7, [rdx + 28]
  db $C5, $FE, $7F, $BC, $24, $60, $01, $00, $00            // vmovdqu [rsp + 352], ymm7
  db $C4, $62, $7D, $58, $42, $20                           // vpbroadcastd ymm8, [rdx + 32]
  db $C5, $7E, $7F, $84, $24, $80, $01, $00, $00            // vmovdqu [rsp + 384], ymm8
  db $C5, $7E, $7F, $04, $24                                // vmovdqu [rsp], ymm8
  db $C4, $62, $7D, $58, $42, $24                           // vpbroadcastd ymm8, [rdx + 36]
  db $C5, $7E, $7F, $84, $24, $A0, $01, $00, $00            // vmovdqu [rsp + 416], ymm8
  db $C5, $7E, $7F, $44, $24, $20                           // vmovdqu [rsp + 32], ymm8
  db $C4, $62, $7D, $58, $42, $28                           // vpbroadcastd ymm8, [rdx + 40]
  db $C5, $7E, $7F, $84, $24, $C0, $01, $00, $00            // vmovdqu [rsp + 448], ymm8
  db $C5, $7E, $7F, $44, $24, $40                           // vmovdqu [rsp + 64], ymm8
  db $C4, $62, $7D, $58, $42, $2C                           // vpbroadcastd ymm8, [rdx + 44]
  db $C5, $7E, $7F, $84, $24, $E0, $01, $00, $00            // vmovdqu [rsp + 480], ymm8
  db $C5, $7E, $7F, $44, $24, $60                           // vmovdqu [rsp + 96], ymm8
  db $C4, $62, $7D, $58, $62, $30                           // vpbroadcastd ymm12, [rdx + 48]
  db $C5, $1D, $FE, $A4, $24, $80, $02, $00, $00            // vpaddd ymm12, ymm12, [rsp + 640]
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00            // vmovdqu [rsp + 512], ymm12
  db $C4, $62, $7D, $58, $6A, $34                           // vpbroadcastd ymm13, [rdx + 52]
  db $C5, $7E, $7F, $AC, $24, $20, $02, $00, $00            // vmovdqu [rsp + 544], ymm13
  db $C4, $62, $7D, $58, $72, $38                           // vpbroadcastd ymm14, [rdx + 56]
  db $C5, $7E, $7F, $B4, $24, $40, $02, $00, $00            // vmovdqu [rsp + 576], ymm14
  db $C4, $62, $7D, $58, $7A, $3C                           // vpbroadcastd ymm15, [rdx + 60]
  db $C5, $7E, $7F, $BC, $24, $60, $02, $00, $00            // vmovdqu [rsp + 608], ymm15
@@c7539_avx2_8x_round:
  db $C5, $FD, $FE, $C4                                     // vpaddd ymm0, ymm0, ymm4
  db $C5, $F5, $FE, $CD                                     // vpaddd ymm1, ymm1, ymm5
  db $C5, $ED, $FE, $D6                                     // vpaddd ymm2, ymm2, ymm6
  db $C5, $E5, $FE, $DF                                     // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E0                                     // vpxor ymm12, ymm12, ymm0
  db $C5, $15, $EF, $E9                                     // vpxor ymm13, ymm13, ymm1
  db $C5, $0D, $EF, $F2                                     // vpxor ymm14, ymm14, ymm2
  db $C5, $05, $EF, $FB                                     // vpxor ymm15, ymm15, ymm3
  db $C5, $7E, $6F, $84, $24, $A0, $02, $00, $00            // vmovdqu ymm8, [rsp + 672]
  db $C4, $42, $1D, $00, $E0                                // vpshufb ymm12, ymm12, ymm8
  db $C4, $42, $15, $00, $E8                                // vpshufb ymm13, ymm13, ymm8
  db $C4, $42, $0D, $00, $F0                                // vpshufb ymm14, ymm14, ymm8
  db $C4, $42, $05, $00, $F8                                // vpshufb ymm15, ymm15, ymm8
  db $C5, $7E, $6F, $04, $24                                // vmovdqu ymm8, [rsp]
  db $C5, $7E, $6F, $4C, $24, $20                           // vmovdqu ymm9, [rsp + 32]
  db $C5, $7E, $6F, $54, $24, $40                           // vmovdqu ymm10, [rsp + 64]
  db $C5, $7E, $6F, $5C, $24, $60                           // vmovdqu ymm11, [rsp + 96]
  db $C4, $41, $3D, $FE, $C4                                // vpaddd ymm8, ymm8, ymm12
  db $C4, $41, $35, $FE, $CD                                // vpaddd ymm9, ymm9, ymm13
  db $C4, $41, $2D, $FE, $D6                                // vpaddd ymm10, ymm10, ymm14
  db $C4, $41, $25, $FE, $DF                                // vpaddd ymm11, ymm11, ymm15
  db $C4, $C1, $5D, $EF, $E0                                // vpxor ymm4, ymm4, ymm8
  db $C4, $C1, $55, $EF, $E9                                // vpxor ymm5, ymm5, ymm9
  db $C4, $C1, $4D, $EF, $F2                                // vpxor ymm6, ymm6, ymm10
  db $C4, $C1, $45, $EF, $FB                                // vpxor ymm7, ymm7, ymm11
  db $C5, $7E, $7F, $04, $24                                // vmovdqu [rsp], ymm8
  db $C5, $7E, $7F, $4C, $24, $20                           // vmovdqu [rsp + 32], ymm9
  db $C5, $7E, $7F, $54, $24, $40                           // vmovdqu [rsp + 64], ymm10
  db $C5, $7E, $7F, $5C, $24, $60                           // vmovdqu [rsp + 96], ymm11
  db $C5, $BD, $72, $F4, $0C                                // vpslld ymm8, ymm4, 12
  db $C5, $B5, $72, $F5, $0C                                // vpslld ymm9, ymm5, 12
  db $C5, $AD, $72, $F6, $0C                                // vpslld ymm10, ymm6, 12
  db $C5, $A5, $72, $F7, $0C                                // vpslld ymm11, ymm7, 12
  db $C5, $DD, $72, $D4, $14                                // vpsrld ymm4, ymm4, 20
  db $C5, $D5, $72, $D5, $14                                // vpsrld ymm5, ymm5, 20
  db $C5, $CD, $72, $D6, $14                                // vpsrld ymm6, ymm6, 20
  db $C5, $C5, $72, $D7, $14                                // vpsrld ymm7, ymm7, 20
  db $C5, $BD, $EB, $E4                                     // vpor ymm4, ymm8, ymm4
  db $C5, $B5, $EB, $ED                                     // vpor ymm5, ymm9, ymm5
  db $C5, $AD, $EB, $F6                                     // vpor ymm6, ymm10, ymm6
  db $C5, $A5, $EB, $FF                                     // vpor ymm7, ymm11, ymm7
  db $C5, $FD, $FE, $C4                                     // vpaddd ymm0, ymm0, ymm4
  db $C5, $F5, $FE, $CD                                     // vpaddd ymm1, ymm1, ymm5
  db $C5, $ED, $FE, $D6                                     // vpaddd ymm2, ymm2, ymm6
  db $C5, $E5, $FE, $DF                                     // vpaddd ymm3, ymm3, ymm7
  db $C5, $1D, $EF, $E0                                     // vpxor ymm12, ymm12, ymm0
  db $C5, $15, $EF, $E9                                     // vpxor ymm13, ymm13, ymm1
  db $C5, $0D, $EF, $F2                                     // vpxor ymm14, ymm14, ymm2
  db $C5, $05, $EF, $FB                                     // vpxor ymm15, ymm15, ymm3
  db $C5, $7E, $6F, $84, $24, $C0, $02, $00, $00            // vmovdqu ymm8, [rsp + 704]
  db $C4, $42, $1D, $00, $E0                                // vpshufb ymm12, ymm12, ymm8
  db $C4, $42, $15, $00, $E8                                // vpshufb ymm13, ymm13, ymm8
  db $C4, $42, $0D, $00, $F0                                // vpshufb ymm14, ymm14, ymm8
  db $C4, $42, $05, $00, $F8                                // vpshufb ymm15, ymm15, ymm8
  db $C5, $7E, $6F, $04, $24                                // vmovdqu ymm8, [rsp]
  db $C5, $7E, $6F, $4C, $24, $20                           // vmovdqu ymm9, [rsp + 32]
  db $C5, $7E, $6F, $54, $24, $40                           // vmovdqu ymm10, [rsp + 64]
  db $C5, $7E, $6F, $5C, $24, $60                           // vmovdqu ymm11, [rsp + 96]
  db $C4, $41, $3D, $FE, $C4                                // vpaddd ymm8, ymm8, ymm12
  db $C4, $41, $35, $FE, $CD                                // vpaddd ymm9, ymm9, ymm13
  db $C4, $41, $2D, $FE, $D6                                // vpaddd ymm10, ymm10, ymm14
  db $C4, $41, $25, $FE, $DF                                // vpaddd ymm11, ymm11, ymm15
  db $C4, $C1, $5D, $EF, $E0                                // vpxor ymm4, ymm4, ymm8
  db $C4, $C1, $55, $EF, $E9                                // vpxor ymm5, ymm5, ymm9
  db $C4, $C1, $4D, $EF, $F2                                // vpxor ymm6, ymm6, ymm10
  db $C4, $C1, $45, $EF, $FB                                // vpxor ymm7, ymm7, ymm11
  db $C5, $7E, $7F, $04, $24                                // vmovdqu [rsp], ymm8
  db $C5, $7E, $7F, $4C, $24, $20                           // vmovdqu [rsp + 32], ymm9
  db $C5, $7E, $7F, $54, $24, $40                           // vmovdqu [rsp + 64], ymm10
  db $C5, $7E, $7F, $5C, $24, $60                           // vmovdqu [rsp + 96], ymm11
  db $C5, $BD, $72, $F4, $07                                // vpslld ymm8, ymm4, 7
  db $C5, $B5, $72, $F5, $07                                // vpslld ymm9, ymm5, 7
  db $C5, $AD, $72, $F6, $07                                // vpslld ymm10, ymm6, 7
  db $C5, $A5, $72, $F7, $07                                // vpslld ymm11, ymm7, 7
  db $C5, $DD, $72, $D4, $19                                // vpsrld ymm4, ymm4, 25
  db $C5, $D5, $72, $D5, $19                                // vpsrld ymm5, ymm5, 25
  db $C5, $CD, $72, $D6, $19                                // vpsrld ymm6, ymm6, 25
  db $C5, $C5, $72, $D7, $19                                // vpsrld ymm7, ymm7, 25
  db $C5, $BD, $EB, $E4                                     // vpor ymm4, ymm8, ymm4
  db $C5, $B5, $EB, $ED                                     // vpor ymm5, ymm9, ymm5
  db $C5, $AD, $EB, $F6                                     // vpor ymm6, ymm10, ymm6
  db $C5, $A5, $EB, $FF                                     // vpor ymm7, ymm11, ymm7
  db $C5, $FD, $FE, $C5                                     // vpaddd ymm0, ymm0, ymm5
  db $C5, $F5, $FE, $CE                                     // vpaddd ymm1, ymm1, ymm6
  db $C5, $ED, $FE, $D7                                     // vpaddd ymm2, ymm2, ymm7
  db $C5, $E5, $FE, $DC                                     // vpaddd ymm3, ymm3, ymm4
  db $C5, $05, $EF, $F8                                     // vpxor ymm15, ymm15, ymm0
  db $C5, $1D, $EF, $E1                                     // vpxor ymm12, ymm12, ymm1
  db $C5, $15, $EF, $EA                                     // vpxor ymm13, ymm13, ymm2
  db $C5, $0D, $EF, $F3                                     // vpxor ymm14, ymm14, ymm3
  db $C5, $7E, $6F, $84, $24, $A0, $02, $00, $00            // vmovdqu ymm8, [rsp + 672]
  db $C4, $42, $05, $00, $F8                                // vpshufb ymm15, ymm15, ymm8
  db $C4, $42, $1D, $00, $E0                                // vpshufb ymm12, ymm12, ymm8
  db $C4, $42, $15, $00, $E8                                // vpshufb ymm13, ymm13, ymm8
  db $C4, $42, $0D, $00, $F0                                // vpshufb ymm14, ymm14, ymm8
  db $C5, $7E, $6F, $44, $24, $40                           // vmovdqu ymm8, [rsp + 64]
  db $C5, $7E, $6F, $4C, $24, $60                           // vmovdqu ymm9, [rsp + 96]
  db $C5, $7E, $6F, $14, $24                                // vmovdqu ymm10, [rsp]
  db $C5, $7E, $6F, $5C, $24, $20                           // vmovdqu ymm11, [rsp + 32]
  db $C4, $41, $3D, $FE, $C7                                // vpaddd ymm8, ymm8, ymm15
  db $C4, $41, $35, $FE, $CC                                // vpaddd ymm9, ymm9, ymm12
  db $C4, $41, $2D, $FE, $D5                                // vpaddd ymm10, ymm10, ymm13
  db $C4, $41, $25, $FE, $DE                                // vpaddd ymm11, ymm11, ymm14
  db $C4, $C1, $55, $EF, $E8                                // vpxor ymm5, ymm5, ymm8
  db $C4, $C1, $4D, $EF, $F1                                // vpxor ymm6, ymm6, ymm9
  db $C4, $C1, $45, $EF, $FA                                // vpxor ymm7, ymm7, ymm10
  db $C4, $C1, $5D, $EF, $E3                                // vpxor ymm4, ymm4, ymm11
  db $C5, $7E, $7F, $44, $24, $40                           // vmovdqu [rsp + 64], ymm8
  db $C5, $7E, $7F, $4C, $24, $60                           // vmovdqu [rsp + 96], ymm9
  db $C5, $7E, $7F, $14, $24                                // vmovdqu [rsp], ymm10
  db $C5, $7E, $7F, $5C, $24, $20                           // vmovdqu [rsp + 32], ymm11
  db $C5, $BD, $72, $F5, $0C                                // vpslld ymm8, ymm5, 12
  db $C5, $B5, $72, $F6, $0C                                // vpslld ymm9, ymm6, 12
  db $C5, $AD, $72, $F7, $0C                                // vpslld ymm10, ymm7, 12
  db $C5, $A5, $72, $F4, $0C                                // vpslld ymm11, ymm4, 12
  db $C5, $D5, $72, $D5, $14                                // vpsrld ymm5, ymm5, 20
  db $C5, $CD, $72, $D6, $14                                // vpsrld ymm6, ymm6, 20
  db $C5, $C5, $72, $D7, $14                                // vpsrld ymm7, ymm7, 20
  db $C5, $DD, $72, $D4, $14                                // vpsrld ymm4, ymm4, 20
  db $C5, $BD, $EB, $ED                                     // vpor ymm5, ymm8, ymm5
  db $C5, $B5, $EB, $F6                                     // vpor ymm6, ymm9, ymm6
  db $C5, $AD, $EB, $FF                                     // vpor ymm7, ymm10, ymm7
  db $C5, $A5, $EB, $E4                                     // vpor ymm4, ymm11, ymm4
  db $C5, $FD, $FE, $C5                                     // vpaddd ymm0, ymm0, ymm5
  db $C5, $F5, $FE, $CE                                     // vpaddd ymm1, ymm1, ymm6
  db $C5, $ED, $FE, $D7                                     // vpaddd ymm2, ymm2, ymm7
  db $C5, $E5, $FE, $DC                                     // vpaddd ymm3, ymm3, ymm4
  db $C5, $05, $EF, $F8                                     // vpxor ymm15, ymm15, ymm0
  db $C5, $1D, $EF, $E1                                     // vpxor ymm12, ymm12, ymm1
  db $C5, $15, $EF, $EA                                     // vpxor ymm13, ymm13, ymm2
  db $C5, $0D, $EF, $F3                                     // vpxor ymm14, ymm14, ymm3
  db $C5, $7E, $6F, $84, $24, $C0, $02, $00, $00            // vmovdqu ymm8, [rsp + 704]
  db $C4, $42, $05, $00, $F8                                // vpshufb ymm15, ymm15, ymm8
  db $C4, $42, $1D, $00, $E0                                // vpshufb ymm12, ymm12, ymm8
  db $C4, $42, $15, $00, $E8                                // vpshufb ymm13, ymm13, ymm8
  db $C4, $42, $0D, $00, $F0                                // vpshufb ymm14, ymm14, ymm8
  db $C5, $7E, $6F, $44, $24, $40                           // vmovdqu ymm8, [rsp + 64]
  db $C5, $7E, $6F, $4C, $24, $60                           // vmovdqu ymm9, [rsp + 96]
  db $C5, $7E, $6F, $14, $24                                // vmovdqu ymm10, [rsp]
  db $C5, $7E, $6F, $5C, $24, $20                           // vmovdqu ymm11, [rsp + 32]
  db $C4, $41, $3D, $FE, $C7                                // vpaddd ymm8, ymm8, ymm15
  db $C4, $41, $35, $FE, $CC                                // vpaddd ymm9, ymm9, ymm12
  db $C4, $41, $2D, $FE, $D5                                // vpaddd ymm10, ymm10, ymm13
  db $C4, $41, $25, $FE, $DE                                // vpaddd ymm11, ymm11, ymm14
  db $C4, $C1, $55, $EF, $E8                                // vpxor ymm5, ymm5, ymm8
  db $C4, $C1, $4D, $EF, $F1                                // vpxor ymm6, ymm6, ymm9
  db $C4, $C1, $45, $EF, $FA                                // vpxor ymm7, ymm7, ymm10
  db $C4, $C1, $5D, $EF, $E3                                // vpxor ymm4, ymm4, ymm11
  db $C5, $7E, $7F, $44, $24, $40                           // vmovdqu [rsp + 64], ymm8
  db $C5, $7E, $7F, $4C, $24, $60                           // vmovdqu [rsp + 96], ymm9
  db $C5, $7E, $7F, $14, $24                                // vmovdqu [rsp], ymm10
  db $C5, $7E, $7F, $5C, $24, $20                           // vmovdqu [rsp + 32], ymm11
  db $C5, $BD, $72, $F5, $07                                // vpslld ymm8, ymm5, 7
  db $C5, $B5, $72, $F6, $07                                // vpslld ymm9, ymm6, 7
  db $C5, $AD, $72, $F7, $07                                // vpslld ymm10, ymm7, 7
  db $C5, $A5, $72, $F4, $07                                // vpslld ymm11, ymm4, 7
  db $C5, $D5, $72, $D5, $19                                // vpsrld ymm5, ymm5, 25
  db $C5, $CD, $72, $D6, $19                                // vpsrld ymm6, ymm6, 25
  db $C5, $C5, $72, $D7, $19                                // vpsrld ymm7, ymm7, 25
  db $C5, $DD, $72, $D4, $19                                // vpsrld ymm4, ymm4, 25
  db $C5, $BD, $EB, $ED                                     // vpor ymm5, ymm8, ymm5
  db $C5, $B5, $EB, $F6                                     // vpor ymm6, ymm9, ymm6
  db $C5, $AD, $EB, $FF                                     // vpor ymm7, ymm10, ymm7
  db $C5, $A5, $EB, $E4                                     // vpor ymm4, ymm11, ymm4
  sub     r10, 2
  jg      @@c7539_avx2_8x_round
  db $C5, $7E, $6F, $84, $24, $80, $00, $00, $00            // vmovdqu ymm8, [rsp + 128]
  db $C4, $C1, $7D, $FE, $C0                                // vpaddd ymm0, ymm0, ymm8
  db $C5, $FE, $7F, $84, $24, $80, $00, $00, $00            // vmovdqu [rsp + 128], ymm0
  db $C5, $7E, $6F, $84, $24, $A0, $00, $00, $00            // vmovdqu ymm8, [rsp + 160]
  db $C4, $C1, $75, $FE, $C8                                // vpaddd ymm1, ymm1, ymm8
  db $C5, $FE, $7F, $8C, $24, $A0, $00, $00, $00            // vmovdqu [rsp + 160], ymm1
  db $C5, $7E, $6F, $84, $24, $C0, $00, $00, $00            // vmovdqu ymm8, [rsp + 192]
  db $C4, $C1, $6D, $FE, $D0                                // vpaddd ymm2, ymm2, ymm8
  db $C5, $FE, $7F, $94, $24, $C0, $00, $00, $00            // vmovdqu [rsp + 192], ymm2
  db $C5, $7E, $6F, $84, $24, $E0, $00, $00, $00            // vmovdqu ymm8, [rsp + 224]
  db $C4, $C1, $65, $FE, $D8                                // vpaddd ymm3, ymm3, ymm8
  db $C5, $FE, $7F, $9C, $24, $E0, $00, $00, $00            // vmovdqu [rsp + 224], ymm3
  db $C5, $7E, $6F, $84, $24, $00, $01, $00, $00            // vmovdqu ymm8, [rsp + 256]
  db $C4, $C1, $5D, $FE, $E0                                // vpaddd ymm4, ymm4, ymm8
  db $C5, $FE, $7F, $A4, $24, $00, $01, $00, $00            // vmovdqu [rsp + 256], ymm4
  db $C5, $7E, $6F, $84, $24, $20, $01, $00, $00            // vmovdqu ymm8, [rsp + 288]
  db $C4, $C1, $55, $FE, $E8                                // vpaddd ymm5, ymm5, ymm8
  db $C5, $FE, $7F, $AC, $24, $20, $01, $00, $00            // vmovdqu [rsp + 288], ymm5
  db $C5, $7E, $6F, $84, $24, $40, $01, $00, $00            // vmovdqu ymm8, [rsp + 320]
  db $C4, $C1, $4D, $FE, $F0                                // vpaddd ymm6, ymm6, ymm8
  db $C5, $FE, $7F, $B4, $24, $40, $01, $00, $00            // vmovdqu [rsp + 320], ymm6
  db $C5, $7E, $6F, $84, $24, $60, $01, $00, $00            // vmovdqu ymm8, [rsp + 352]
  db $C4, $C1, $45, $FE, $F8                                // vpaddd ymm7, ymm7, ymm8
  db $C5, $FE, $7F, $BC, $24, $60, $01, $00, $00            // vmovdqu [rsp + 352], ymm7
  db $C5, $7E, $6F, $84, $24, $00, $02, $00, $00            // vmovdqu ymm8, [rsp + 512]
  db $C4, $41, $1D, $FE, $E0                                // vpaddd ymm12, ymm12, ymm8
  db $C5, $7E, $7F, $A4, $24, $00, $02, $00, $00            // vmovdqu [rsp + 512], ymm12
  db $C5, $7E, $6F, $84, $24, $20, $02, $00, $00            // vmovdqu ymm8, [rsp + 544]
  db $C4, $41, $15, $FE, $E8                                // vpaddd ymm13, ymm13, ymm8
  db $C5, $7E, $7F, $AC, $24, $20, $02, $00, $00            // vmovdqu [rsp + 544], ymm13
  db $C5, $7E, $6F, $84, $24, $40, $02, $00, $00            // vmovdqu ymm8, [rsp + 576]
  db $C4, $41, $0D, $FE, $F0                                // vpaddd ymm14, ymm14, ymm8
  db $C5, $7E, $7F, $B4, $24, $40, $02, $00, $00            // vmovdqu [rsp + 576], ymm14
  db $C5, $7E, $6F, $84, $24, $60, $02, $00, $00            // vmovdqu ymm8, [rsp + 608]
  db $C4, $41, $05, $FE, $F8                                // vpaddd ymm15, ymm15, ymm8
  db $C5, $7E, $7F, $BC, $24, $60, $02, $00, $00            // vmovdqu [rsp + 608], ymm15
  db $C5, $7E, $6F, $04, $24                                // vmovdqu ymm8, [rsp]
  db $C5, $7E, $6F, $8C, $24, $80, $01, $00, $00            // vmovdqu ymm9, [rsp + 384]
  db $C4, $41, $3D, $FE, $C1                                // vpaddd ymm8, ymm8, ymm9
  db $C5, $7E, $7F, $84, $24, $80, $01, $00, $00            // vmovdqu [rsp + 384], ymm8
  db $C5, $7E, $6F, $44, $24, $20                           // vmovdqu ymm8, [rsp + 32]
  db $C5, $7E, $6F, $8C, $24, $A0, $01, $00, $00            // vmovdqu ymm9, [rsp + 416]
  db $C4, $41, $3D, $FE, $C1                                // vpaddd ymm8, ymm8, ymm9
  db $C5, $7E, $7F, $84, $24, $A0, $01, $00, $00            // vmovdqu [rsp + 416], ymm8
  db $C5, $7E, $6F, $44, $24, $40                           // vmovdqu ymm8, [rsp + 64]
  db $C5, $7E, $6F, $8C, $24, $C0, $01, $00, $00            // vmovdqu ymm9, [rsp + 448]
  db $C4, $41, $3D, $FE, $C1                                // vpaddd ymm8, ymm8, ymm9
  db $C5, $7E, $7F, $84, $24, $C0, $01, $00, $00            // vmovdqu [rsp + 448], ymm8
  db $C5, $7E, $6F, $44, $24, $60                           // vmovdqu ymm8, [rsp + 96]
  db $C5, $7E, $6F, $8C, $24, $E0, $01, $00, $00            // vmovdqu ymm9, [rsp + 480]
  db $C4, $41, $3D, $FE, $C1                                // vpaddd ymm8, ymm8, ymm9
  db $C5, $7E, $7F, $84, $24, $E0, $01, $00, $00            // vmovdqu [rsp + 480], ymm8
  add     dword ptr [rdx + 48], 8
{$IFDEF CHACHA_CTR64}
  adc     dword ptr [rdx + 52], 0
{$ENDIF}
  db $C5, $FE, $6F, $84, $24, $80, $00, $00, $00            // vmovdqu ymm0, [rsp + 128]
  db $C5, $FE, $6F, $8C, $24, $A0, $00, $00, $00            // vmovdqu ymm1, [rsp + 160]
  db $C5, $FE, $6F, $94, $24, $C0, $00, $00, $00            // vmovdqu ymm2, [rsp + 192]
  db $C5, $FE, $6F, $9C, $24, $E0, $00, $00, $00            // vmovdqu ymm3, [rsp + 224]
  db $C5, $FD, $6F, $E0                                     // vmovdqa ymm4, ymm0
  db $C5, $FD, $62, $C1                                     // vpunpckldq ymm0, ymm0, ymm1
  db $C5, $DD, $6A, $E1                                     // vpunpckhdq ymm4, ymm4, ymm1
  db $C5, $FD, $6F, $EA                                     // vmovdqa ymm5, ymm2
  db $C5, $ED, $62, $D3                                     // vpunpckldq ymm2, ymm2, ymm3
  db $C5, $D5, $6A, $EB                                     // vpunpckhdq ymm5, ymm5, ymm3
  db $C5, $FD, $6F, $C8                                     // vmovdqa ymm1, ymm0
  db $C5, $FD, $6C, $C2                                     // vpunpcklqdq ymm0, ymm0, ymm2
  db $C5, $F5, $6D, $CA                                     // vpunpckhqdq ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $DC                                     // vmovdqa ymm3, ymm4
  db $C5, $DD, $6C, $E5                                     // vpunpcklqdq ymm4, ymm4, ymm5
  db $C5, $E5, $6D, $DD                                     // vpunpckhqdq ymm3, ymm3, ymm5
  db $C5, $FA, $7F, $84, $24, $E0, $02, $00, $00            // vmovdqu [rsp + 736], xmm0
  db $C4, $E3, $7D, $39, $84, $24, $E0, $03, $00, $00, $01  // vextracti128 [rsp + 992], ymm0, 1
  db $C5, $FA, $7F, $8C, $24, $20, $03, $00, $00            // vmovdqu [rsp + 800], xmm1
  db $C4, $E3, $7D, $39, $8C, $24, $20, $04, $00, $00, $01  // vextracti128 [rsp + 1056], ymm1, 1
  db $C5, $FA, $7F, $A4, $24, $60, $03, $00, $00            // vmovdqu [rsp + 864], xmm4
  db $C4, $E3, $7D, $39, $A4, $24, $60, $04, $00, $00, $01  // vextracti128 [rsp + 1120], ymm4, 1
  db $C5, $FA, $7F, $9C, $24, $A0, $03, $00, $00            // vmovdqu [rsp + 928], xmm3
  db $C4, $E3, $7D, $39, $9C, $24, $A0, $04, $00, $00, $01  // vextracti128 [rsp + 1184], ymm3, 1
  db $C5, $FE, $6F, $84, $24, $00, $01, $00, $00            // vmovdqu ymm0, [rsp + 256]
  db $C5, $FE, $6F, $8C, $24, $20, $01, $00, $00            // vmovdqu ymm1, [rsp + 288]
  db $C5, $FE, $6F, $94, $24, $40, $01, $00, $00            // vmovdqu ymm2, [rsp + 320]
  db $C5, $FE, $6F, $9C, $24, $60, $01, $00, $00            // vmovdqu ymm3, [rsp + 352]
  db $C5, $FD, $6F, $E0                                     // vmovdqa ymm4, ymm0
  db $C5, $FD, $62, $C1                                     // vpunpckldq ymm0, ymm0, ymm1
  db $C5, $DD, $6A, $E1                                     // vpunpckhdq ymm4, ymm4, ymm1
  db $C5, $FD, $6F, $EA                                     // vmovdqa ymm5, ymm2
  db $C5, $ED, $62, $D3                                     // vpunpckldq ymm2, ymm2, ymm3
  db $C5, $D5, $6A, $EB                                     // vpunpckhdq ymm5, ymm5, ymm3
  db $C5, $FD, $6F, $C8                                     // vmovdqa ymm1, ymm0
  db $C5, $FD, $6C, $C2                                     // vpunpcklqdq ymm0, ymm0, ymm2
  db $C5, $F5, $6D, $CA                                     // vpunpckhqdq ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $DC                                     // vmovdqa ymm3, ymm4
  db $C5, $DD, $6C, $E5                                     // vpunpcklqdq ymm4, ymm4, ymm5
  db $C5, $E5, $6D, $DD                                     // vpunpckhqdq ymm3, ymm3, ymm5
  db $C5, $FA, $7F, $84, $24, $F0, $02, $00, $00            // vmovdqu [rsp + 752], xmm0
  db $C4, $E3, $7D, $39, $84, $24, $F0, $03, $00, $00, $01  // vextracti128 [rsp + 1008], ymm0, 1
  db $C5, $FA, $7F, $8C, $24, $30, $03, $00, $00            // vmovdqu [rsp + 816], xmm1
  db $C4, $E3, $7D, $39, $8C, $24, $30, $04, $00, $00, $01  // vextracti128 [rsp + 1072], ymm1, 1
  db $C5, $FA, $7F, $A4, $24, $70, $03, $00, $00            // vmovdqu [rsp + 880], xmm4
  db $C4, $E3, $7D, $39, $A4, $24, $70, $04, $00, $00, $01  // vextracti128 [rsp + 1136], ymm4, 1
  db $C5, $FA, $7F, $9C, $24, $B0, $03, $00, $00            // vmovdqu [rsp + 944], xmm3
  db $C4, $E3, $7D, $39, $9C, $24, $B0, $04, $00, $00, $01  // vextracti128 [rsp + 1200], ymm3, 1
  db $C5, $FE, $6F, $84, $24, $80, $01, $00, $00            // vmovdqu ymm0, [rsp + 384]
  db $C5, $FE, $6F, $8C, $24, $A0, $01, $00, $00            // vmovdqu ymm1, [rsp + 416]
  db $C5, $FE, $6F, $94, $24, $C0, $01, $00, $00            // vmovdqu ymm2, [rsp + 448]
  db $C5, $FE, $6F, $9C, $24, $E0, $01, $00, $00            // vmovdqu ymm3, [rsp + 480]
  db $C5, $FD, $6F, $E0                                     // vmovdqa ymm4, ymm0
  db $C5, $FD, $62, $C1                                     // vpunpckldq ymm0, ymm0, ymm1
  db $C5, $DD, $6A, $E1                                     // vpunpckhdq ymm4, ymm4, ymm1
  db $C5, $FD, $6F, $EA                                     // vmovdqa ymm5, ymm2
  db $C5, $ED, $62, $D3                                     // vpunpckldq ymm2, ymm2, ymm3
  db $C5, $D5, $6A, $EB                                     // vpunpckhdq ymm5, ymm5, ymm3
  db $C5, $FD, $6F, $C8                                     // vmovdqa ymm1, ymm0
  db $C5, $FD, $6C, $C2                                     // vpunpcklqdq ymm0, ymm0, ymm2
  db $C5, $F5, $6D, $CA                                     // vpunpckhqdq ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $DC                                     // vmovdqa ymm3, ymm4
  db $C5, $DD, $6C, $E5                                     // vpunpcklqdq ymm4, ymm4, ymm5
  db $C5, $E5, $6D, $DD                                     // vpunpckhqdq ymm3, ymm3, ymm5
  db $C5, $FA, $7F, $84, $24, $00, $03, $00, $00            // vmovdqu [rsp + 768], xmm0
  db $C4, $E3, $7D, $39, $84, $24, $00, $04, $00, $00, $01  // vextracti128 [rsp + 1024], ymm0, 1
  db $C5, $FA, $7F, $8C, $24, $40, $03, $00, $00            // vmovdqu [rsp + 832], xmm1
  db $C4, $E3, $7D, $39, $8C, $24, $40, $04, $00, $00, $01  // vextracti128 [rsp + 1088], ymm1, 1
  db $C5, $FA, $7F, $A4, $24, $80, $03, $00, $00            // vmovdqu [rsp + 896], xmm4
  db $C4, $E3, $7D, $39, $A4, $24, $80, $04, $00, $00, $01  // vextracti128 [rsp + 1152], ymm4, 1
  db $C5, $FA, $7F, $9C, $24, $C0, $03, $00, $00            // vmovdqu [rsp + 960], xmm3
  db $C4, $E3, $7D, $39, $9C, $24, $C0, $04, $00, $00, $01  // vextracti128 [rsp + 1216], ymm3, 1
  db $C5, $FE, $6F, $84, $24, $00, $02, $00, $00            // vmovdqu ymm0, [rsp + 512]
  db $C5, $FE, $6F, $8C, $24, $20, $02, $00, $00            // vmovdqu ymm1, [rsp + 544]
  db $C5, $FE, $6F, $94, $24, $40, $02, $00, $00            // vmovdqu ymm2, [rsp + 576]
  db $C5, $FE, $6F, $9C, $24, $60, $02, $00, $00            // vmovdqu ymm3, [rsp + 608]
  db $C5, $FD, $6F, $E0                                     // vmovdqa ymm4, ymm0
  db $C5, $FD, $62, $C1                                     // vpunpckldq ymm0, ymm0, ymm1
  db $C5, $DD, $6A, $E1                                     // vpunpckhdq ymm4, ymm4, ymm1
  db $C5, $FD, $6F, $EA                                     // vmovdqa ymm5, ymm2
  db $C5, $ED, $62, $D3                                     // vpunpckldq ymm2, ymm2, ymm3
  db $C5, $D5, $6A, $EB                                     // vpunpckhdq ymm5, ymm5, ymm3
  db $C5, $FD, $6F, $C8                                     // vmovdqa ymm1, ymm0
  db $C5, $FD, $6C, $C2                                     // vpunpcklqdq ymm0, ymm0, ymm2
  db $C5, $F5, $6D, $CA                                     // vpunpckhqdq ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $DC                                     // vmovdqa ymm3, ymm4
  db $C5, $DD, $6C, $E5                                     // vpunpcklqdq ymm4, ymm4, ymm5
  db $C5, $E5, $6D, $DD                                     // vpunpckhqdq ymm3, ymm3, ymm5
  db $C5, $FA, $7F, $84, $24, $10, $03, $00, $00            // vmovdqu [rsp + 784], xmm0
  db $C4, $E3, $7D, $39, $84, $24, $10, $04, $00, $00, $01  // vextracti128 [rsp + 1040], ymm0, 1
  db $C5, $FA, $7F, $8C, $24, $50, $03, $00, $00            // vmovdqu [rsp + 848], xmm1
  db $C4, $E3, $7D, $39, $8C, $24, $50, $04, $00, $00, $01  // vextracti128 [rsp + 1104], ymm1, 1
  db $C5, $FA, $7F, $A4, $24, $90, $03, $00, $00            // vmovdqu [rsp + 912], xmm4
  db $C4, $E3, $7D, $39, $A4, $24, $90, $04, $00, $00, $01  // vextracti128 [rsp + 1168], ymm4, 1
  db $C5, $FA, $7F, $9C, $24, $D0, $03, $00, $00            // vmovdqu [rsp + 976], xmm3
  db $C4, $E3, $7D, $39, $9C, $24, $D0, $04, $00, $00, $01  // vextracti128 [rsp + 1232], ymm3, 1
  db $C5, $FE, $6F, $84, $24, $E0, $02, $00, $00            // vmovdqu ymm0, [rsp + 736]
  db $C4, $C1, $7D, $EF, $00                                // vpxor ymm0, ymm0, [r8 + 0]
  db $C4, $C1, $7E, $7F, $01                                // vmovdqu [r9], ymm0
  db $C5, $FE, $6F, $84, $24, $00, $03, $00, $00            // vmovdqu ymm0, [rsp + 768]
  db $C4, $C1, $7D, $EF, $40, $20                           // vpxor ymm0, ymm0, [r8 + 32]
  db $C4, $C1, $7E, $7F, $41, $20                           // vmovdqu [r9 + 32], ymm0
  db $C5, $FE, $6F, $84, $24, $20, $03, $00, $00            // vmovdqu ymm0, [rsp + 800]
  db $C4, $C1, $7D, $EF, $40, $40                           // vpxor ymm0, ymm0, [r8 + 64]
  db $C4, $C1, $7E, $7F, $41, $40                           // vmovdqu [r9 + 64], ymm0
  db $C5, $FE, $6F, $84, $24, $40, $03, $00, $00            // vmovdqu ymm0, [rsp + 832]
  db $C4, $C1, $7D, $EF, $40, $60                           // vpxor ymm0, ymm0, [r8 + 96]
  db $C4, $C1, $7E, $7F, $41, $60                           // vmovdqu [r9 + 96], ymm0
  db $C5, $FE, $6F, $84, $24, $60, $03, $00, $00            // vmovdqu ymm0, [rsp + 864]
  db $C4, $C1, $7D, $EF, $80, $80, $00, $00, $00            // vpxor ymm0, ymm0, [r8 + 128]
  db $C4, $C1, $7E, $7F, $81, $80, $00, $00, $00            // vmovdqu [r9 + 128], ymm0
  db $C5, $FE, $6F, $84, $24, $80, $03, $00, $00            // vmovdqu ymm0, [rsp + 896]
  db $C4, $C1, $7D, $EF, $80, $A0, $00, $00, $00            // vpxor ymm0, ymm0, [r8 + 160]
  db $C4, $C1, $7E, $7F, $81, $A0, $00, $00, $00            // vmovdqu [r9 + 160], ymm0
  db $C5, $FE, $6F, $84, $24, $A0, $03, $00, $00            // vmovdqu ymm0, [rsp + 928]
  db $C4, $C1, $7D, $EF, $80, $C0, $00, $00, $00            // vpxor ymm0, ymm0, [r8 + 192]
  db $C4, $C1, $7E, $7F, $81, $C0, $00, $00, $00            // vmovdqu [r9 + 192], ymm0
  db $C5, $FE, $6F, $84, $24, $C0, $03, $00, $00            // vmovdqu ymm0, [rsp + 960]
  db $C4, $C1, $7D, $EF, $80, $E0, $00, $00, $00            // vpxor ymm0, ymm0, [r8 + 224]
  db $C4, $C1, $7E, $7F, $81, $E0, $00, $00, $00            // vmovdqu [r9 + 224], ymm0
  db $C5, $FE, $6F, $84, $24, $E0, $03, $00, $00            // vmovdqu ymm0, [rsp + 992]
  db $C4, $C1, $7D, $EF, $80, $00, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 256]
  db $C4, $C1, $7E, $7F, $81, $00, $01, $00, $00            // vmovdqu [r9 + 256], ymm0
  db $C5, $FE, $6F, $84, $24, $00, $04, $00, $00            // vmovdqu ymm0, [rsp + 1024]
  db $C4, $C1, $7D, $EF, $80, $20, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 288]
  db $C4, $C1, $7E, $7F, $81, $20, $01, $00, $00            // vmovdqu [r9 + 288], ymm0
  db $C5, $FE, $6F, $84, $24, $20, $04, $00, $00            // vmovdqu ymm0, [rsp + 1056]
  db $C4, $C1, $7D, $EF, $80, $40, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 320]
  db $C4, $C1, $7E, $7F, $81, $40, $01, $00, $00            // vmovdqu [r9 + 320], ymm0
  db $C5, $FE, $6F, $84, $24, $40, $04, $00, $00            // vmovdqu ymm0, [rsp + 1088]
  db $C4, $C1, $7D, $EF, $80, $60, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 352]
  db $C4, $C1, $7E, $7F, $81, $60, $01, $00, $00            // vmovdqu [r9 + 352], ymm0
  db $C5, $FE, $6F, $84, $24, $60, $04, $00, $00            // vmovdqu ymm0, [rsp + 1120]
  db $C4, $C1, $7D, $EF, $80, $80, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 384]
  db $C4, $C1, $7E, $7F, $81, $80, $01, $00, $00            // vmovdqu [r9 + 384], ymm0
  db $C5, $FE, $6F, $84, $24, $80, $04, $00, $00            // vmovdqu ymm0, [rsp + 1152]
  db $C4, $C1, $7D, $EF, $80, $A0, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 416]
  db $C4, $C1, $7E, $7F, $81, $A0, $01, $00, $00            // vmovdqu [r9 + 416], ymm0
  db $C5, $FE, $6F, $84, $24, $A0, $04, $00, $00            // vmovdqu ymm0, [rsp + 1184]
  db $C4, $C1, $7D, $EF, $80, $C0, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 448]
  db $C4, $C1, $7E, $7F, $81, $C0, $01, $00, $00            // vmovdqu [r9 + 448], ymm0
  db $C5, $FE, $6F, $84, $24, $C0, $04, $00, $00            // vmovdqu ymm0, [rsp + 1216]
  db $C4, $C1, $7D, $EF, $80, $E0, $01, $00, $00            // vpxor ymm0, ymm0, [r8 + 480]
  db $C4, $C1, $7E, $7F, $81, $E0, $01, $00, $00            // vmovdqu [r9 + 480], ymm0
  db $C5, $F8, $77                                          // vzeroupper
  add     rsp, 1248
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

