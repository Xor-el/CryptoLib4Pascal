// ChaCha7539 (IETF) 8-way AVX2 keystream kernel, vertical layout (i386).
// -------------------------------------------------------------------
//
// Eight 64-byte ChaCha20 blocks per group, state words held vertically (one
// block per ymm lane). i386 has only 8 ymm, so the 16 state rows live in a
// 64B-aligned stack frame (original esp parked inside it); each quarter-round
// loads its 4 rows into ymm0-3 (temp ymm4), with the rot16/rot8 vpshufb masks
// resident in ymm6/ymm7. rot12/rot7 use vpslld/vpsrld/vpor.
//
// Streams AGroups x 512B in one call: prologue once, per-group ORIG->STATE
// reload (counter lanes +8), fused accumulate/transpose/xor tail to AOut
// (vextracti128 lifts each row's high block piece).
//
// On entry (after ClpSimdProc5Begin_i386.inc):
//   ebx = ARounds, esi = AState (16 UInt32), edi = AIn, eax = AOut,
//   ecx = AGroups (8-block groups, >= 1).
//
// On exit:
//   AState word-12 counter (byte 48) advanced by 8*AGroups; the keystream is
//   xored with AIn into AOut (512*AGroups bytes).
//
// VEX-encoded instructions are db-encoded for broad assembler compatibility.
  mov     edx, esp
  sub     esp, 1168
  and     esp, -64
  mov     dword ptr [esp + 1152], edx
  mov     dword ptr [esp + 1024], 0
  mov     dword ptr [esp + 1028], 1
  mov     dword ptr [esp + 1032], 2
  mov     dword ptr [esp + 1036], 3
  mov     dword ptr [esp + 1040], 4
  mov     dword ptr [esp + 1044], 5
  mov     dword ptr [esp + 1048], 6
  mov     dword ptr [esp + 1052], 7
  mov     dword ptr [esp + 1056], 8
  mov     dword ptr [esp + 1060], 8
  mov     dword ptr [esp + 1064], 8
  mov     dword ptr [esp + 1068], 8
  mov     dword ptr [esp + 1072], 8
  mov     dword ptr [esp + 1076], 8
  mov     dword ptr [esp + 1080], 8
  mov     dword ptr [esp + 1084], 8
  mov     dword ptr [esp + 1088], $01000302
  mov     dword ptr [esp + 1092], $05040706
  mov     dword ptr [esp + 1096], $09080B0A
  mov     dword ptr [esp + 1100], $0D0C0F0E
  mov     dword ptr [esp + 1104], $01000302
  mov     dword ptr [esp + 1108], $05040706
  mov     dword ptr [esp + 1112], $09080B0A
  mov     dword ptr [esp + 1116], $0D0C0F0E
  mov     dword ptr [esp + 1120], $02010003
  mov     dword ptr [esp + 1124], $06050407
  mov     dword ptr [esp + 1128], $0A09080B
  mov     dword ptr [esp + 1132], $0E0D0C0F
  mov     dword ptr [esp + 1136], $02010003
  mov     dword ptr [esp + 1140], $06050407
  mov     dword ptr [esp + 1144], $0A09080B
  mov     dword ptr [esp + 1148], $0E0D0C0F
  db $C5, $FD, $6F, $B4, $24, $40, $04, $00, $00  // vmovdqa ymm6, [esp + 1088]
  db $C5, $FD, $6F, $BC, $24, $60, $04, $00, $00  // vmovdqa ymm7, [esp + 1120]
  db $C4, $E2, $7D, $58, $06                      // vpbroadcastd ymm0, [esi + 0]
  db $C5, $FD, $7F, $04, $24                      // vmovdqa [esp + 0], ymm0
  db $C5, $FD, $7F, $84, $24, $00, $02, $00, $00  // vmovdqa [esp + 512], ymm0
  db $C4, $E2, $7D, $58, $46, $04                 // vpbroadcastd ymm0, [esi + 4]
  db $C5, $FD, $7F, $44, $24, $20                 // vmovdqa [esp + 32], ymm0
  db $C5, $FD, $7F, $84, $24, $20, $02, $00, $00  // vmovdqa [esp + 544], ymm0
  db $C4, $E2, $7D, $58, $46, $08                 // vpbroadcastd ymm0, [esi + 8]
  db $C5, $FD, $7F, $44, $24, $40                 // vmovdqa [esp + 64], ymm0
  db $C5, $FD, $7F, $84, $24, $40, $02, $00, $00  // vmovdqa [esp + 576], ymm0
  db $C4, $E2, $7D, $58, $46, $0C                 // vpbroadcastd ymm0, [esi + 12]
  db $C5, $FD, $7F, $44, $24, $60                 // vmovdqa [esp + 96], ymm0
  db $C5, $FD, $7F, $84, $24, $60, $02, $00, $00  // vmovdqa [esp + 608], ymm0
  db $C4, $E2, $7D, $58, $46, $10                 // vpbroadcastd ymm0, [esi + 16]
  db $C5, $FD, $7F, $84, $24, $80, $00, $00, $00  // vmovdqa [esp + 128], ymm0
  db $C5, $FD, $7F, $84, $24, $80, $02, $00, $00  // vmovdqa [esp + 640], ymm0
  db $C4, $E2, $7D, $58, $46, $14                 // vpbroadcastd ymm0, [esi + 20]
  db $C5, $FD, $7F, $84, $24, $A0, $00, $00, $00  // vmovdqa [esp + 160], ymm0
  db $C5, $FD, $7F, $84, $24, $A0, $02, $00, $00  // vmovdqa [esp + 672], ymm0
  db $C4, $E2, $7D, $58, $46, $18                 // vpbroadcastd ymm0, [esi + 24]
  db $C5, $FD, $7F, $84, $24, $C0, $00, $00, $00  // vmovdqa [esp + 192], ymm0
  db $C5, $FD, $7F, $84, $24, $C0, $02, $00, $00  // vmovdqa [esp + 704], ymm0
  db $C4, $E2, $7D, $58, $46, $1C                 // vpbroadcastd ymm0, [esi + 28]
  db $C5, $FD, $7F, $84, $24, $E0, $00, $00, $00  // vmovdqa [esp + 224], ymm0
  db $C5, $FD, $7F, $84, $24, $E0, $02, $00, $00  // vmovdqa [esp + 736], ymm0
  db $C4, $E2, $7D, $58, $46, $20                 // vpbroadcastd ymm0, [esi + 32]
  db $C5, $FD, $7F, $84, $24, $00, $01, $00, $00  // vmovdqa [esp + 256], ymm0
  db $C5, $FD, $7F, $84, $24, $00, $03, $00, $00  // vmovdqa [esp + 768], ymm0
  db $C4, $E2, $7D, $58, $46, $24                 // vpbroadcastd ymm0, [esi + 36]
  db $C5, $FD, $7F, $84, $24, $20, $01, $00, $00  // vmovdqa [esp + 288], ymm0
  db $C5, $FD, $7F, $84, $24, $20, $03, $00, $00  // vmovdqa [esp + 800], ymm0
  db $C4, $E2, $7D, $58, $46, $28                 // vpbroadcastd ymm0, [esi + 40]
  db $C5, $FD, $7F, $84, $24, $40, $01, $00, $00  // vmovdqa [esp + 320], ymm0
  db $C5, $FD, $7F, $84, $24, $40, $03, $00, $00  // vmovdqa [esp + 832], ymm0
  db $C4, $E2, $7D, $58, $46, $2C                 // vpbroadcastd ymm0, [esi + 44]
  db $C5, $FD, $7F, $84, $24, $60, $01, $00, $00  // vmovdqa [esp + 352], ymm0
  db $C5, $FD, $7F, $84, $24, $60, $03, $00, $00  // vmovdqa [esp + 864], ymm0
  db $C4, $E2, $7D, $58, $46, $30                 // vpbroadcastd ymm0, [esi + 48]
  db $C5, $FD, $FE, $84, $24, $00, $04, $00, $00  // vpaddd ymm0, ymm0, [esp + 1024]
  db $C5, $FD, $7F, $84, $24, $80, $01, $00, $00  // vmovdqa [esp + 384], ymm0
  db $C5, $FD, $7F, $84, $24, $80, $03, $00, $00  // vmovdqa [esp + 896], ymm0
  db $C4, $E2, $7D, $58, $46, $34                 // vpbroadcastd ymm0, [esi + 52]
  db $C5, $FD, $7F, $84, $24, $A0, $01, $00, $00  // vmovdqa [esp + 416], ymm0
  db $C5, $FD, $7F, $84, $24, $A0, $03, $00, $00  // vmovdqa [esp + 928], ymm0
  db $C4, $E2, $7D, $58, $46, $38                 // vpbroadcastd ymm0, [esi + 56]
  db $C5, $FD, $7F, $84, $24, $C0, $01, $00, $00  // vmovdqa [esp + 448], ymm0
  db $C5, $FD, $7F, $84, $24, $C0, $03, $00, $00  // vmovdqa [esp + 960], ymm0
  db $C4, $E2, $7D, $58, $46, $3C                 // vpbroadcastd ymm0, [esi + 60]
  db $C5, $FD, $7F, $84, $24, $E0, $01, $00, $00  // vmovdqa [esp + 480], ymm0
  db $C5, $FD, $7F, $84, $24, $E0, $03, $00, $00  // vmovdqa [esp + 992], ymm0
  jmp     @@c7539_avx2_8x_i386_enter
@@c7539_avx2_8x_i386_outer:
  db $C5, $FD, $6F, $84, $24, $00, $02, $00, $00  // vmovdqa ymm0, [esp + 512]
  db $C5, $FD, $7F, $04, $24                      // vmovdqa [esp + 0], ymm0
  db $C5, $FD, $6F, $84, $24, $20, $02, $00, $00  // vmovdqa ymm0, [esp + 544]
  db $C5, $FD, $7F, $44, $24, $20                 // vmovdqa [esp + 32], ymm0
  db $C5, $FD, $6F, $84, $24, $40, $02, $00, $00  // vmovdqa ymm0, [esp + 576]
  db $C5, $FD, $7F, $44, $24, $40                 // vmovdqa [esp + 64], ymm0
  db $C5, $FD, $6F, $84, $24, $60, $02, $00, $00  // vmovdqa ymm0, [esp + 608]
  db $C5, $FD, $7F, $44, $24, $60                 // vmovdqa [esp + 96], ymm0
  db $C5, $FD, $6F, $84, $24, $80, $02, $00, $00  // vmovdqa ymm0, [esp + 640]
  db $C5, $FD, $7F, $84, $24, $80, $00, $00, $00  // vmovdqa [esp + 128], ymm0
  db $C5, $FD, $6F, $84, $24, $A0, $02, $00, $00  // vmovdqa ymm0, [esp + 672]
  db $C5, $FD, $7F, $84, $24, $A0, $00, $00, $00  // vmovdqa [esp + 160], ymm0
  db $C5, $FD, $6F, $84, $24, $C0, $02, $00, $00  // vmovdqa ymm0, [esp + 704]
  db $C5, $FD, $7F, $84, $24, $C0, $00, $00, $00  // vmovdqa [esp + 192], ymm0
  db $C5, $FD, $6F, $84, $24, $E0, $02, $00, $00  // vmovdqa ymm0, [esp + 736]
  db $C5, $FD, $7F, $84, $24, $E0, $00, $00, $00  // vmovdqa [esp + 224], ymm0
  db $C5, $FD, $6F, $84, $24, $00, $03, $00, $00  // vmovdqa ymm0, [esp + 768]
  db $C5, $FD, $7F, $84, $24, $00, $01, $00, $00  // vmovdqa [esp + 256], ymm0
  db $C5, $FD, $6F, $84, $24, $20, $03, $00, $00  // vmovdqa ymm0, [esp + 800]
  db $C5, $FD, $7F, $84, $24, $20, $01, $00, $00  // vmovdqa [esp + 288], ymm0
  db $C5, $FD, $6F, $84, $24, $40, $03, $00, $00  // vmovdqa ymm0, [esp + 832]
  db $C5, $FD, $7F, $84, $24, $40, $01, $00, $00  // vmovdqa [esp + 320], ymm0
  db $C5, $FD, $6F, $84, $24, $60, $03, $00, $00  // vmovdqa ymm0, [esp + 864]
  db $C5, $FD, $7F, $84, $24, $60, $01, $00, $00  // vmovdqa [esp + 352], ymm0
  db $C5, $FD, $6F, $84, $24, $80, $03, $00, $00  // vmovdqa ymm0, [esp + 896]
  db $C5, $FD, $FE, $84, $24, $20, $04, $00, $00  // vpaddd ymm0, ymm0, [esp + 1056]
  db $C5, $FD, $7F, $84, $24, $80, $03, $00, $00  // vmovdqa [esp + 896], ymm0
  db $C5, $FD, $7F, $84, $24, $80, $01, $00, $00  // vmovdqa [esp + 384], ymm0
  db $C5, $FD, $6F, $84, $24, $A0, $03, $00, $00  // vmovdqa ymm0, [esp + 928]
  db $C5, $FD, $7F, $84, $24, $A0, $01, $00, $00  // vmovdqa [esp + 416], ymm0
  db $C5, $FD, $6F, $84, $24, $C0, $03, $00, $00  // vmovdqa ymm0, [esp + 960]
  db $C5, $FD, $7F, $84, $24, $C0, $01, $00, $00  // vmovdqa [esp + 448], ymm0
  db $C5, $FD, $6F, $84, $24, $E0, $03, $00, $00  // vmovdqa ymm0, [esp + 992]
  db $C5, $FD, $7F, $84, $24, $E0, $01, $00, $00  // vmovdqa [esp + 480], ymm0
@@c7539_avx2_8x_i386_enter:
  mov     edx, ebx
@@c7539_avx2_8x_i386_round:
  db $C5, $FD, $6F, $04, $24                      // vmovdqa ymm0, [esp + 0]
  db $C5, $FD, $6F, $8C, $24, $80, $00, $00, $00  // vmovdqa ymm1, [esp + 128]
  db $C5, $FD, $6F, $94, $24, $00, $01, $00, $00  // vmovdqa ymm2, [esp + 256]
  db $C5, $FD, $6F, $9C, $24, $80, $01, $00, $00  // vmovdqa ymm3, [esp + 384]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $04, $24                      // vmovdqa [esp + 0], ymm0
  db $C5, $FD, $7F, $8C, $24, $80, $00, $00, $00  // vmovdqa [esp + 128], ymm1
  db $C5, $FD, $7F, $94, $24, $00, $01, $00, $00  // vmovdqa [esp + 256], ymm2
  db $C5, $FD, $7F, $9C, $24, $80, $01, $00, $00  // vmovdqa [esp + 384], ymm3
  db $C5, $FD, $6F, $44, $24, $20                 // vmovdqa ymm0, [esp + 32]
  db $C5, $FD, $6F, $8C, $24, $A0, $00, $00, $00  // vmovdqa ymm1, [esp + 160]
  db $C5, $FD, $6F, $94, $24, $20, $01, $00, $00  // vmovdqa ymm2, [esp + 288]
  db $C5, $FD, $6F, $9C, $24, $A0, $01, $00, $00  // vmovdqa ymm3, [esp + 416]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $44, $24, $20                 // vmovdqa [esp + 32], ymm0
  db $C5, $FD, $7F, $8C, $24, $A0, $00, $00, $00  // vmovdqa [esp + 160], ymm1
  db $C5, $FD, $7F, $94, $24, $20, $01, $00, $00  // vmovdqa [esp + 288], ymm2
  db $C5, $FD, $7F, $9C, $24, $A0, $01, $00, $00  // vmovdqa [esp + 416], ymm3
  db $C5, $FD, $6F, $44, $24, $40                 // vmovdqa ymm0, [esp + 64]
  db $C5, $FD, $6F, $8C, $24, $C0, $00, $00, $00  // vmovdqa ymm1, [esp + 192]
  db $C5, $FD, $6F, $94, $24, $40, $01, $00, $00  // vmovdqa ymm2, [esp + 320]
  db $C5, $FD, $6F, $9C, $24, $C0, $01, $00, $00  // vmovdqa ymm3, [esp + 448]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $44, $24, $40                 // vmovdqa [esp + 64], ymm0
  db $C5, $FD, $7F, $8C, $24, $C0, $00, $00, $00  // vmovdqa [esp + 192], ymm1
  db $C5, $FD, $7F, $94, $24, $40, $01, $00, $00  // vmovdqa [esp + 320], ymm2
  db $C5, $FD, $7F, $9C, $24, $C0, $01, $00, $00  // vmovdqa [esp + 448], ymm3
  db $C5, $FD, $6F, $44, $24, $60                 // vmovdqa ymm0, [esp + 96]
  db $C5, $FD, $6F, $8C, $24, $E0, $00, $00, $00  // vmovdqa ymm1, [esp + 224]
  db $C5, $FD, $6F, $94, $24, $60, $01, $00, $00  // vmovdqa ymm2, [esp + 352]
  db $C5, $FD, $6F, $9C, $24, $E0, $01, $00, $00  // vmovdqa ymm3, [esp + 480]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $44, $24, $60                 // vmovdqa [esp + 96], ymm0
  db $C5, $FD, $7F, $8C, $24, $E0, $00, $00, $00  // vmovdqa [esp + 224], ymm1
  db $C5, $FD, $7F, $94, $24, $60, $01, $00, $00  // vmovdqa [esp + 352], ymm2
  db $C5, $FD, $7F, $9C, $24, $E0, $01, $00, $00  // vmovdqa [esp + 480], ymm3
  db $C5, $FD, $6F, $04, $24                      // vmovdqa ymm0, [esp + 0]
  db $C5, $FD, $6F, $8C, $24, $A0, $00, $00, $00  // vmovdqa ymm1, [esp + 160]
  db $C5, $FD, $6F, $94, $24, $40, $01, $00, $00  // vmovdqa ymm2, [esp + 320]
  db $C5, $FD, $6F, $9C, $24, $E0, $01, $00, $00  // vmovdqa ymm3, [esp + 480]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $04, $24                      // vmovdqa [esp + 0], ymm0
  db $C5, $FD, $7F, $8C, $24, $A0, $00, $00, $00  // vmovdqa [esp + 160], ymm1
  db $C5, $FD, $7F, $94, $24, $40, $01, $00, $00  // vmovdqa [esp + 320], ymm2
  db $C5, $FD, $7F, $9C, $24, $E0, $01, $00, $00  // vmovdqa [esp + 480], ymm3
  db $C5, $FD, $6F, $44, $24, $20                 // vmovdqa ymm0, [esp + 32]
  db $C5, $FD, $6F, $8C, $24, $C0, $00, $00, $00  // vmovdqa ymm1, [esp + 192]
  db $C5, $FD, $6F, $94, $24, $60, $01, $00, $00  // vmovdqa ymm2, [esp + 352]
  db $C5, $FD, $6F, $9C, $24, $80, $01, $00, $00  // vmovdqa ymm3, [esp + 384]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $44, $24, $20                 // vmovdqa [esp + 32], ymm0
  db $C5, $FD, $7F, $8C, $24, $C0, $00, $00, $00  // vmovdqa [esp + 192], ymm1
  db $C5, $FD, $7F, $94, $24, $60, $01, $00, $00  // vmovdqa [esp + 352], ymm2
  db $C5, $FD, $7F, $9C, $24, $80, $01, $00, $00  // vmovdqa [esp + 384], ymm3
  db $C5, $FD, $6F, $44, $24, $40                 // vmovdqa ymm0, [esp + 64]
  db $C5, $FD, $6F, $8C, $24, $E0, $00, $00, $00  // vmovdqa ymm1, [esp + 224]
  db $C5, $FD, $6F, $94, $24, $00, $01, $00, $00  // vmovdqa ymm2, [esp + 256]
  db $C5, $FD, $6F, $9C, $24, $A0, $01, $00, $00  // vmovdqa ymm3, [esp + 416]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $44, $24, $40                 // vmovdqa [esp + 64], ymm0
  db $C5, $FD, $7F, $8C, $24, $E0, $00, $00, $00  // vmovdqa [esp + 224], ymm1
  db $C5, $FD, $7F, $94, $24, $00, $01, $00, $00  // vmovdqa [esp + 256], ymm2
  db $C5, $FD, $7F, $9C, $24, $A0, $01, $00, $00  // vmovdqa [esp + 416], ymm3
  db $C5, $FD, $6F, $44, $24, $60                 // vmovdqa ymm0, [esp + 96]
  db $C5, $FD, $6F, $8C, $24, $80, $00, $00, $00  // vmovdqa ymm1, [esp + 128]
  db $C5, $FD, $6F, $94, $24, $20, $01, $00, $00  // vmovdqa ymm2, [esp + 288]
  db $C5, $FD, $6F, $9C, $24, $C0, $01, $00, $00  // vmovdqa ymm3, [esp + 448]
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DE                      // vpshufb ymm3, ymm3, ymm6
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $0C                      // vpslld ymm4, ymm1, 12
  db $C5, $F5, $72, $D1, $14                      // vpsrld ymm1, ymm1, 20
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $FE, $C1                           // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                           // vpxor ymm3, ymm3, ymm0
  db $C4, $E2, $65, $00, $DF                      // vpshufb ymm3, ymm3, ymm7
  db $C5, $ED, $FE, $D3                           // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                           // vpxor ymm1, ymm1, ymm2
  db $C5, $DD, $72, $F1, $07                      // vpslld ymm4, ymm1, 7
  db $C5, $F5, $72, $D1, $19                      // vpsrld ymm1, ymm1, 25
  db $C5, $DD, $EB, $C9                           // vpor ymm1, ymm4, ymm1
  db $C5, $FD, $7F, $44, $24, $60                 // vmovdqa [esp + 96], ymm0
  db $C5, $FD, $7F, $8C, $24, $80, $00, $00, $00  // vmovdqa [esp + 128], ymm1
  db $C5, $FD, $7F, $94, $24, $20, $01, $00, $00  // vmovdqa [esp + 288], ymm2
  db $C5, $FD, $7F, $9C, $24, $C0, $01, $00, $00  // vmovdqa [esp + 448], ymm3
  sub     edx, 2
  jg      @@c7539_avx2_8x_i386_round
  add     dword ptr [esi + 48], 8
{$IFDEF CHACHA_CTR64}
  adc     dword ptr [esi + 52], 0
{$ENDIF}
  db $C5, $FD, $6F, $04, $24                      // vmovdqa ymm0, [esp + 0]
  db $C5, $FD, $FE, $84, $24, $00, $02, $00, $00  // vpaddd ymm0, ymm0, [esp + 512]
  db $C5, $FD, $6F, $4C, $24, $20                 // vmovdqa ymm1, [esp + 32]
  db $C5, $F5, $FE, $8C, $24, $20, $02, $00, $00  // vpaddd ymm1, ymm1, [esp + 544]
  db $C5, $FD, $6F, $54, $24, $40                 // vmovdqa ymm2, [esp + 64]
  db $C5, $ED, $FE, $94, $24, $40, $02, $00, $00  // vpaddd ymm2, ymm2, [esp + 576]
  db $C5, $FD, $6F, $5C, $24, $60                 // vmovdqa ymm3, [esp + 96]
  db $C5, $E5, $FE, $9C, $24, $60, $02, $00, $00  // vpaddd ymm3, ymm3, [esp + 608]
  db $C5, $FD, $62, $E1                           // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $ED, $62, $EB                           // vpunpckldq ymm5, ymm2, ymm3
  db $C5, $FD, $6A, $C1                           // vpunpckhdq ymm0, ymm0, ymm1
  db $C5, $ED, $6A, $D3                           // vpunpckhdq ymm2, ymm2, ymm3
  db $C5, $DD, $6C, $CD                           // vpunpcklqdq ymm1, ymm4, ymm5
  db $C5, $DD, $6D, $E5                           // vpunpckhqdq ymm4, ymm4, ymm5
  db $C5, $FD, $6C, $DA                           // vpunpcklqdq ymm3, ymm0, ymm2
  db $C5, $FD, $6D, $C2                           // vpunpckhqdq ymm0, ymm0, ymm2
  db $C4, $E3, $7D, $39, $CD, $01                 // vextracti128 xmm5, ymm1, 1
  db $C5, $F1, $EF, $0F                           // vpxor xmm1, xmm1, [edi]
  db $C5, $FA, $7F, $08                           // vmovdqu [eax], xmm1
  db $C5, $D1, $EF, $AF, $00, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 256]
  db $C5, $FA, $7F, $A8, $00, $01, $00, $00       // vmovdqu [eax + 256], xmm5
  db $C4, $E3, $7D, $39, $E5, $01                 // vextracti128 xmm5, ymm4, 1
  db $C5, $D9, $EF, $67, $40                      // vpxor xmm4, xmm4, [edi + 64]
  db $C5, $FA, $7F, $60, $40                      // vmovdqu [eax + 64], xmm4
  db $C5, $D1, $EF, $AF, $40, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 320]
  db $C5, $FA, $7F, $A8, $40, $01, $00, $00       // vmovdqu [eax + 320], xmm5
  db $C4, $E3, $7D, $39, $DD, $01                 // vextracti128 xmm5, ymm3, 1
  db $C5, $E1, $EF, $9F, $80, $00, $00, $00       // vpxor xmm3, xmm3, [edi + 128]
  db $C5, $FA, $7F, $98, $80, $00, $00, $00       // vmovdqu [eax + 128], xmm3
  db $C5, $D1, $EF, $AF, $80, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 384]
  db $C5, $FA, $7F, $A8, $80, $01, $00, $00       // vmovdqu [eax + 384], xmm5
  db $C4, $E3, $7D, $39, $C5, $01                 // vextracti128 xmm5, ymm0, 1
  db $C5, $F9, $EF, $87, $C0, $00, $00, $00       // vpxor xmm0, xmm0, [edi + 192]
  db $C5, $FA, $7F, $80, $C0, $00, $00, $00       // vmovdqu [eax + 192], xmm0
  db $C5, $D1, $EF, $AF, $C0, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 448]
  db $C5, $FA, $7F, $A8, $C0, $01, $00, $00       // vmovdqu [eax + 448], xmm5
  db $C5, $FD, $6F, $84, $24, $80, $00, $00, $00  // vmovdqa ymm0, [esp + 128]
  db $C5, $FD, $FE, $84, $24, $80, $02, $00, $00  // vpaddd ymm0, ymm0, [esp + 640]
  db $C5, $FD, $6F, $8C, $24, $A0, $00, $00, $00  // vmovdqa ymm1, [esp + 160]
  db $C5, $F5, $FE, $8C, $24, $A0, $02, $00, $00  // vpaddd ymm1, ymm1, [esp + 672]
  db $C5, $FD, $6F, $94, $24, $C0, $00, $00, $00  // vmovdqa ymm2, [esp + 192]
  db $C5, $ED, $FE, $94, $24, $C0, $02, $00, $00  // vpaddd ymm2, ymm2, [esp + 704]
  db $C5, $FD, $6F, $9C, $24, $E0, $00, $00, $00  // vmovdqa ymm3, [esp + 224]
  db $C5, $E5, $FE, $9C, $24, $E0, $02, $00, $00  // vpaddd ymm3, ymm3, [esp + 736]
  db $C5, $FD, $62, $E1                           // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $ED, $62, $EB                           // vpunpckldq ymm5, ymm2, ymm3
  db $C5, $FD, $6A, $C1                           // vpunpckhdq ymm0, ymm0, ymm1
  db $C5, $ED, $6A, $D3                           // vpunpckhdq ymm2, ymm2, ymm3
  db $C5, $DD, $6C, $CD                           // vpunpcklqdq ymm1, ymm4, ymm5
  db $C5, $DD, $6D, $E5                           // vpunpckhqdq ymm4, ymm4, ymm5
  db $C5, $FD, $6C, $DA                           // vpunpcklqdq ymm3, ymm0, ymm2
  db $C5, $FD, $6D, $C2                           // vpunpckhqdq ymm0, ymm0, ymm2
  db $C4, $E3, $7D, $39, $CD, $01                 // vextracti128 xmm5, ymm1, 1
  db $C5, $F1, $EF, $4F, $10                      // vpxor xmm1, xmm1, [edi + 16]
  db $C5, $FA, $7F, $48, $10                      // vmovdqu [eax + 16], xmm1
  db $C5, $D1, $EF, $AF, $10, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 272]
  db $C5, $FA, $7F, $A8, $10, $01, $00, $00       // vmovdqu [eax + 272], xmm5
  db $C4, $E3, $7D, $39, $E5, $01                 // vextracti128 xmm5, ymm4, 1
  db $C5, $D9, $EF, $67, $50                      // vpxor xmm4, xmm4, [edi + 80]
  db $C5, $FA, $7F, $60, $50                      // vmovdqu [eax + 80], xmm4
  db $C5, $D1, $EF, $AF, $50, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 336]
  db $C5, $FA, $7F, $A8, $50, $01, $00, $00       // vmovdqu [eax + 336], xmm5
  db $C4, $E3, $7D, $39, $DD, $01                 // vextracti128 xmm5, ymm3, 1
  db $C5, $E1, $EF, $9F, $90, $00, $00, $00       // vpxor xmm3, xmm3, [edi + 144]
  db $C5, $FA, $7F, $98, $90, $00, $00, $00       // vmovdqu [eax + 144], xmm3
  db $C5, $D1, $EF, $AF, $90, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 400]
  db $C5, $FA, $7F, $A8, $90, $01, $00, $00       // vmovdqu [eax + 400], xmm5
  db $C4, $E3, $7D, $39, $C5, $01                 // vextracti128 xmm5, ymm0, 1
  db $C5, $F9, $EF, $87, $D0, $00, $00, $00       // vpxor xmm0, xmm0, [edi + 208]
  db $C5, $FA, $7F, $80, $D0, $00, $00, $00       // vmovdqu [eax + 208], xmm0
  db $C5, $D1, $EF, $AF, $D0, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 464]
  db $C5, $FA, $7F, $A8, $D0, $01, $00, $00       // vmovdqu [eax + 464], xmm5
  db $C5, $FD, $6F, $84, $24, $00, $01, $00, $00  // vmovdqa ymm0, [esp + 256]
  db $C5, $FD, $FE, $84, $24, $00, $03, $00, $00  // vpaddd ymm0, ymm0, [esp + 768]
  db $C5, $FD, $6F, $8C, $24, $20, $01, $00, $00  // vmovdqa ymm1, [esp + 288]
  db $C5, $F5, $FE, $8C, $24, $20, $03, $00, $00  // vpaddd ymm1, ymm1, [esp + 800]
  db $C5, $FD, $6F, $94, $24, $40, $01, $00, $00  // vmovdqa ymm2, [esp + 320]
  db $C5, $ED, $FE, $94, $24, $40, $03, $00, $00  // vpaddd ymm2, ymm2, [esp + 832]
  db $C5, $FD, $6F, $9C, $24, $60, $01, $00, $00  // vmovdqa ymm3, [esp + 352]
  db $C5, $E5, $FE, $9C, $24, $60, $03, $00, $00  // vpaddd ymm3, ymm3, [esp + 864]
  db $C5, $FD, $62, $E1                           // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $ED, $62, $EB                           // vpunpckldq ymm5, ymm2, ymm3
  db $C5, $FD, $6A, $C1                           // vpunpckhdq ymm0, ymm0, ymm1
  db $C5, $ED, $6A, $D3                           // vpunpckhdq ymm2, ymm2, ymm3
  db $C5, $DD, $6C, $CD                           // vpunpcklqdq ymm1, ymm4, ymm5
  db $C5, $DD, $6D, $E5                           // vpunpckhqdq ymm4, ymm4, ymm5
  db $C5, $FD, $6C, $DA                           // vpunpcklqdq ymm3, ymm0, ymm2
  db $C5, $FD, $6D, $C2                           // vpunpckhqdq ymm0, ymm0, ymm2
  db $C4, $E3, $7D, $39, $CD, $01                 // vextracti128 xmm5, ymm1, 1
  db $C5, $F1, $EF, $4F, $20                      // vpxor xmm1, xmm1, [edi + 32]
  db $C5, $FA, $7F, $48, $20                      // vmovdqu [eax + 32], xmm1
  db $C5, $D1, $EF, $AF, $20, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 288]
  db $C5, $FA, $7F, $A8, $20, $01, $00, $00       // vmovdqu [eax + 288], xmm5
  db $C4, $E3, $7D, $39, $E5, $01                 // vextracti128 xmm5, ymm4, 1
  db $C5, $D9, $EF, $67, $60                      // vpxor xmm4, xmm4, [edi + 96]
  db $C5, $FA, $7F, $60, $60                      // vmovdqu [eax + 96], xmm4
  db $C5, $D1, $EF, $AF, $60, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 352]
  db $C5, $FA, $7F, $A8, $60, $01, $00, $00       // vmovdqu [eax + 352], xmm5
  db $C4, $E3, $7D, $39, $DD, $01                 // vextracti128 xmm5, ymm3, 1
  db $C5, $E1, $EF, $9F, $A0, $00, $00, $00       // vpxor xmm3, xmm3, [edi + 160]
  db $C5, $FA, $7F, $98, $A0, $00, $00, $00       // vmovdqu [eax + 160], xmm3
  db $C5, $D1, $EF, $AF, $A0, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 416]
  db $C5, $FA, $7F, $A8, $A0, $01, $00, $00       // vmovdqu [eax + 416], xmm5
  db $C4, $E3, $7D, $39, $C5, $01                 // vextracti128 xmm5, ymm0, 1
  db $C5, $F9, $EF, $87, $E0, $00, $00, $00       // vpxor xmm0, xmm0, [edi + 224]
  db $C5, $FA, $7F, $80, $E0, $00, $00, $00       // vmovdqu [eax + 224], xmm0
  db $C5, $D1, $EF, $AF, $E0, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 480]
  db $C5, $FA, $7F, $A8, $E0, $01, $00, $00       // vmovdqu [eax + 480], xmm5
  db $C5, $FD, $6F, $84, $24, $80, $01, $00, $00  // vmovdqa ymm0, [esp + 384]
  db $C5, $FD, $FE, $84, $24, $80, $03, $00, $00  // vpaddd ymm0, ymm0, [esp + 896]
  db $C5, $FD, $6F, $8C, $24, $A0, $01, $00, $00  // vmovdqa ymm1, [esp + 416]
  db $C5, $F5, $FE, $8C, $24, $A0, $03, $00, $00  // vpaddd ymm1, ymm1, [esp + 928]
  db $C5, $FD, $6F, $94, $24, $C0, $01, $00, $00  // vmovdqa ymm2, [esp + 448]
  db $C5, $ED, $FE, $94, $24, $C0, $03, $00, $00  // vpaddd ymm2, ymm2, [esp + 960]
  db $C5, $FD, $6F, $9C, $24, $E0, $01, $00, $00  // vmovdqa ymm3, [esp + 480]
  db $C5, $E5, $FE, $9C, $24, $E0, $03, $00, $00  // vpaddd ymm3, ymm3, [esp + 992]
  db $C5, $FD, $62, $E1                           // vpunpckldq ymm4, ymm0, ymm1
  db $C5, $ED, $62, $EB                           // vpunpckldq ymm5, ymm2, ymm3
  db $C5, $FD, $6A, $C1                           // vpunpckhdq ymm0, ymm0, ymm1
  db $C5, $ED, $6A, $D3                           // vpunpckhdq ymm2, ymm2, ymm3
  db $C5, $DD, $6C, $CD                           // vpunpcklqdq ymm1, ymm4, ymm5
  db $C5, $DD, $6D, $E5                           // vpunpckhqdq ymm4, ymm4, ymm5
  db $C5, $FD, $6C, $DA                           // vpunpcklqdq ymm3, ymm0, ymm2
  db $C5, $FD, $6D, $C2                           // vpunpckhqdq ymm0, ymm0, ymm2
  db $C4, $E3, $7D, $39, $CD, $01                 // vextracti128 xmm5, ymm1, 1
  db $C5, $F1, $EF, $4F, $30                      // vpxor xmm1, xmm1, [edi + 48]
  db $C5, $FA, $7F, $48, $30                      // vmovdqu [eax + 48], xmm1
  db $C5, $D1, $EF, $AF, $30, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 304]
  db $C5, $FA, $7F, $A8, $30, $01, $00, $00       // vmovdqu [eax + 304], xmm5
  db $C4, $E3, $7D, $39, $E5, $01                 // vextracti128 xmm5, ymm4, 1
  db $C5, $D9, $EF, $67, $70                      // vpxor xmm4, xmm4, [edi + 112]
  db $C5, $FA, $7F, $60, $70                      // vmovdqu [eax + 112], xmm4
  db $C5, $D1, $EF, $AF, $70, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 368]
  db $C5, $FA, $7F, $A8, $70, $01, $00, $00       // vmovdqu [eax + 368], xmm5
  db $C4, $E3, $7D, $39, $DD, $01                 // vextracti128 xmm5, ymm3, 1
  db $C5, $E1, $EF, $9F, $B0, $00, $00, $00       // vpxor xmm3, xmm3, [edi + 176]
  db $C5, $FA, $7F, $98, $B0, $00, $00, $00       // vmovdqu [eax + 176], xmm3
  db $C5, $D1, $EF, $AF, $B0, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 432]
  db $C5, $FA, $7F, $A8, $B0, $01, $00, $00       // vmovdqu [eax + 432], xmm5
  db $C4, $E3, $7D, $39, $C5, $01                 // vextracti128 xmm5, ymm0, 1
  db $C5, $F9, $EF, $87, $F0, $00, $00, $00       // vpxor xmm0, xmm0, [edi + 240]
  db $C5, $FA, $7F, $80, $F0, $00, $00, $00       // vmovdqu [eax + 240], xmm0
  db $C5, $D1, $EF, $AF, $F0, $01, $00, $00       // vpxor xmm5, xmm5, [edi + 496]
  db $C5, $FA, $7F, $A8, $F0, $01, $00, $00       // vmovdqu [eax + 496], xmm5
  add     edi, 512
  add     eax, 512
  dec     ecx
  jnz     @@c7539_avx2_8x_i386_outer
  db $C5, $F8, $77                                // vzeroupper
  mov     esp, dword ptr [esp + 1152]
  pop     edi
  pop     esi
  pop     ebx

