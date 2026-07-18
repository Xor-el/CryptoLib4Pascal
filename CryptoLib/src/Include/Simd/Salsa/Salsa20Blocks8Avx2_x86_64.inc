// Salsa20 8-way (512B) AVX2 keystream kernel, vertical layout (x86-64).
// -------------------------------------------------------------------
//
// Eight 64-byte Salsa20 blocks per group, state words held vertically (one
// block per ymm lane), register-resident as ymm(i) = word i except for the
// current quarter-round temp set: parking {2,3,6,7} or {8,9,12,13} in stack
// slots frees four rotate temps and a double round costs exactly two
// 4-store/4-load swaps (see Salsa20Blocks4Sse2_x86_64.inc for the pair
// partition). All rotations (7/9/13/18) are vpslld/vpsrld/vpor - none is
// byte-aligned, so there is no vpshufb path. The frame is 64B-aligned
// (r11 = frame register), so all stack traffic is aligned vmovdqa.
//
// Streams AGroups x 512B in one call: prologue once, light per-group reload
// (counter lanes +8), fused accumulate/transpose/xor tail straight to AOut
// (vperm2i128 pairs whole 32-byte block halves; the fully-resident word
// quads 8..15 drain first, so no [a|b] spill area is needed).
//
// The vector counter lanes ride word 8 and always broadcast word 9, so the
// caller must guarantee the low counter word does not wrap inside the
// 8*AGroups-block span (TSalsa20Engine.WideGroupsSafe); the per-group AState
// write-back over words 8/9 is a true 64-bit add.
//
// On entry (after ClpSimdProc5Begin_x86_64.inc):
//   rcx = ARounds, rdx = AState (16 UInt32), r8 = AIn, r9 = AOut,
//   r10 = AGroups (8-block groups, >= 1).
//
// On exit:
//   AState words 8/9 counter (byte 32) advanced by 8*AGroups as one 64-bit
//   value; the keystream is xored with AIn into AOut (512*AGroups bytes).
//
// Reference: D.J. Bernstein, "Salsa20 specification" (cr.yp.to/salsa20/) -
// the quarterround/rowround/columnround arithmetic that this kernel's
// rounds implement.
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
  db $C4, $E2, $7D, $58, $02                      // vpbroadcastd ymm0, [rdx]
  db $C5, $FD, $7F, $84, $24, $80, $00, $00, $00  // vmovdqa [rsp + 128], ymm0
  db $C4, $E2, $7D, $58, $4A, $04                 // vpbroadcastd ymm1, [rdx + 4]
  db $C5, $FD, $7F, $8C, $24, $A0, $00, $00, $00  // vmovdqa [rsp + 160], ymm1
  db $C4, $E2, $7D, $58, $52, $08                 // vpbroadcastd ymm2, [rdx + 8]
  db $C5, $FD, $7F, $94, $24, $C0, $00, $00, $00  // vmovdqa [rsp + 192], ymm2
  db $C5, $FD, $7F, $14, $24                      // vmovdqa [rsp], ymm2
  db $C4, $E2, $7D, $58, $5A, $0C                 // vpbroadcastd ymm3, [rdx + 12]
  db $C5, $FD, $7F, $9C, $24, $E0, $00, $00, $00  // vmovdqa [rsp + 224], ymm3
  db $C5, $FD, $7F, $5C, $24, $20                 // vmovdqa [rsp + 32], ymm3
  db $C4, $E2, $7D, $58, $62, $10                 // vpbroadcastd ymm4, [rdx + 16]
  db $C5, $FD, $7F, $A4, $24, $00, $01, $00, $00  // vmovdqa [rsp + 256], ymm4
  db $C4, $E2, $7D, $58, $6A, $14                 // vpbroadcastd ymm5, [rdx + 20]
  db $C5, $FD, $7F, $AC, $24, $20, $01, $00, $00  // vmovdqa [rsp + 288], ymm5
  db $C4, $E2, $7D, $58, $72, $18                 // vpbroadcastd ymm6, [rdx + 24]
  db $C5, $FD, $7F, $B4, $24, $40, $01, $00, $00  // vmovdqa [rsp + 320], ymm6
  db $C5, $FD, $7F, $74, $24, $40                 // vmovdqa [rsp + 64], ymm6
  db $C4, $E2, $7D, $58, $7A, $1C                 // vpbroadcastd ymm7, [rdx + 28]
  db $C5, $FD, $7F, $BC, $24, $60, $01, $00, $00  // vmovdqa [rsp + 352], ymm7
  db $C5, $FD, $7F, $7C, $24, $60                 // vmovdqa [rsp + 96], ymm7
  db $C4, $62, $7D, $58, $42, $20                 // vpbroadcastd ymm8, [rdx + 32]
  db $C5, $3D, $FE, $84, $24, $80, $02, $00, $00  // vpaddd ymm8, ymm8, [rsp + 640]
  db $C5, $7D, $7F, $84, $24, $80, $01, $00, $00  // vmovdqa [rsp + 384], ymm8
  db $C4, $62, $7D, $58, $4A, $24                 // vpbroadcastd ymm9, [rdx + 36]
  db $C5, $7D, $7F, $8C, $24, $A0, $01, $00, $00  // vmovdqa [rsp + 416], ymm9
  db $C4, $62, $7D, $58, $52, $28                 // vpbroadcastd ymm10, [rdx + 40]
  db $C5, $7D, $7F, $94, $24, $C0, $01, $00, $00  // vmovdqa [rsp + 448], ymm10
  db $C4, $62, $7D, $58, $5A, $2C                 // vpbroadcastd ymm11, [rdx + 44]
  db $C5, $7D, $7F, $9C, $24, $E0, $01, $00, $00  // vmovdqa [rsp + 480], ymm11
  db $C4, $62, $7D, $58, $62, $30                 // vpbroadcastd ymm12, [rdx + 48]
  db $C5, $7D, $7F, $A4, $24, $00, $02, $00, $00  // vmovdqa [rsp + 512], ymm12
  db $C4, $62, $7D, $58, $6A, $34                 // vpbroadcastd ymm13, [rdx + 52]
  db $C5, $7D, $7F, $AC, $24, $20, $02, $00, $00  // vmovdqa [rsp + 544], ymm13
  db $C4, $62, $7D, $58, $72, $38                 // vpbroadcastd ymm14, [rdx + 56]
  db $C5, $7D, $7F, $B4, $24, $40, $02, $00, $00  // vmovdqa [rsp + 576], ymm14
  db $C4, $62, $7D, $58, $7A, $3C                 // vpbroadcastd ymm15, [rdx + 60]
  db $C5, $7D, $7F, $BC, $24, $60, $02, $00, $00  // vmovdqa [rsp + 608], ymm15
  jmp     @@salsa_avx2_8x_enter
@@salsa_avx2_8x_outer:
  db $C5, $FD, $6F, $84, $24, $80, $00, $00, $00  // vmovdqa ymm0, [rsp + 128]
  db $C5, $FD, $6F, $8C, $24, $A0, $00, $00, $00  // vmovdqa ymm1, [rsp + 160]
  db $C5, $FD, $6F, $94, $24, $C0, $00, $00, $00  // vmovdqa ymm2, [rsp + 192]
  db $C5, $FD, $7F, $14, $24                      // vmovdqa [rsp], ymm2
  db $C5, $FD, $6F, $9C, $24, $E0, $00, $00, $00  // vmovdqa ymm3, [rsp + 224]
  db $C5, $FD, $7F, $5C, $24, $20                 // vmovdqa [rsp + 32], ymm3
  db $C5, $FD, $6F, $A4, $24, $00, $01, $00, $00  // vmovdqa ymm4, [rsp + 256]
  db $C5, $FD, $6F, $AC, $24, $20, $01, $00, $00  // vmovdqa ymm5, [rsp + 288]
  db $C5, $FD, $6F, $B4, $24, $40, $01, $00, $00  // vmovdqa ymm6, [rsp + 320]
  db $C5, $FD, $7F, $74, $24, $40                 // vmovdqa [rsp + 64], ymm6
  db $C5, $FD, $6F, $BC, $24, $60, $01, $00, $00  // vmovdqa ymm7, [rsp + 352]
  db $C5, $FD, $7F, $7C, $24, $60                 // vmovdqa [rsp + 96], ymm7
  db $C5, $7D, $6F, $84, $24, $80, $01, $00, $00  // vmovdqa ymm8, [rsp + 384]
  db $C5, $3D, $FE, $84, $24, $A0, $02, $00, $00  // vpaddd ymm8, ymm8, [rsp + 672]
  db $C5, $7D, $7F, $84, $24, $80, $01, $00, $00  // vmovdqa [rsp + 384], ymm8
  db $C5, $7D, $6F, $8C, $24, $A0, $01, $00, $00  // vmovdqa ymm9, [rsp + 416]
  db $C5, $7D, $6F, $94, $24, $C0, $01, $00, $00  // vmovdqa ymm10, [rsp + 448]
  db $C5, $7D, $6F, $9C, $24, $E0, $01, $00, $00  // vmovdqa ymm11, [rsp + 480]
  db $C5, $7D, $6F, $A4, $24, $00, $02, $00, $00  // vmovdqa ymm12, [rsp + 512]
  db $C5, $7D, $6F, $AC, $24, $20, $02, $00, $00  // vmovdqa ymm13, [rsp + 544]
  db $C5, $7D, $6F, $B4, $24, $40, $02, $00, $00  // vmovdqa ymm14, [rsp + 576]
  db $C5, $7D, $6F, $BC, $24, $60, $02, $00, $00  // vmovdqa ymm15, [rsp + 608]
@@salsa_avx2_8x_enter:
  mov     eax, ecx
@@salsa_avx2_8x_round:
  db $C4, $C1, $7D, $FE, $D4                      // vpaddd ymm2, ymm0, ymm12
  db $C5, $E5, $72, $F2, $07                      // vpslld ymm3, ymm2, 7
  db $C5, $ED, $72, $D2, $19                      // vpsrld ymm2, ymm2, 25
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $DD, $EF, $E2                           // vpxor ymm4, ymm4, ymm2
  db $C5, $D5, $FE, $F1                           // vpaddd ymm6, ymm5, ymm1
  db $C5, $C5, $72, $F6, $07                      // vpslld ymm7, ymm6, 7
  db $C5, $CD, $72, $D6, $19                      // vpsrld ymm6, ymm6, 25
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $35, $EF, $CE                           // vpxor ymm9, ymm9, ymm6
  db $C5, $DD, $FE, $D0                           // vpaddd ymm2, ymm4, ymm0
  db $C5, $E5, $72, $F2, $09                      // vpslld ymm3, ymm2, 9
  db $C5, $ED, $72, $D2, $17                      // vpsrld ymm2, ymm2, 23
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $3D, $EF, $C2                           // vpxor ymm8, ymm8, ymm2
  db $C5, $B5, $FE, $F5                           // vpaddd ymm6, ymm9, ymm5
  db $C5, $C5, $72, $F6, $09                      // vpslld ymm7, ymm6, 9
  db $C5, $CD, $72, $D6, $17                      // vpsrld ymm6, ymm6, 23
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $15, $EF, $EE                           // vpxor ymm13, ymm13, ymm6
  db $C5, $BD, $FE, $D4                           // vpaddd ymm2, ymm8, ymm4
  db $C5, $E5, $72, $F2, $0D                      // vpslld ymm3, ymm2, 13
  db $C5, $ED, $72, $D2, $13                      // vpsrld ymm2, ymm2, 19
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $1D, $EF, $E2                           // vpxor ymm12, ymm12, ymm2
  db $C4, $C1, $15, $FE, $F1                      // vpaddd ymm6, ymm13, ymm9
  db $C5, $C5, $72, $F6, $0D                      // vpslld ymm7, ymm6, 13
  db $C5, $CD, $72, $D6, $13                      // vpsrld ymm6, ymm6, 19
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $F5, $EF, $CE                           // vpxor ymm1, ymm1, ymm6
  db $C4, $C1, $1D, $FE, $D0                      // vpaddd ymm2, ymm12, ymm8
  db $C5, $E5, $72, $F2, $12                      // vpslld ymm3, ymm2, 18
  db $C5, $ED, $72, $D2, $0E                      // vpsrld ymm2, ymm2, 14
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $FD, $EF, $C2                           // vpxor ymm0, ymm0, ymm2
  db $C4, $C1, $75, $FE, $F5                      // vpaddd ymm6, ymm1, ymm13
  db $C5, $C5, $72, $F6, $12                      // vpslld ymm7, ymm6, 18
  db $C5, $CD, $72, $D6, $0E                      // vpsrld ymm6, ymm6, 14
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $D5, $EF, $EE                           // vpxor ymm5, ymm5, ymm6
  db $C5, $FD, $6F, $14, $24                      // vmovdqa ymm2, [rsp]
  db $C5, $FD, $6F, $5C, $24, $20                 // vmovdqa ymm3, [rsp + 32]
  db $C5, $FD, $6F, $74, $24, $40                 // vmovdqa ymm6, [rsp + 64]
  db $C5, $FD, $6F, $7C, $24, $60                 // vmovdqa ymm7, [rsp + 96]
  db $C5, $7D, $7F, $04, $24                      // vmovdqa [rsp], ymm8
  db $C5, $7D, $7F, $4C, $24, $20                 // vmovdqa [rsp + 32], ymm9
  db $C5, $7D, $7F, $64, $24, $40                 // vmovdqa [rsp + 64], ymm12
  db $C5, $7D, $7F, $6C, $24, $60                 // vmovdqa [rsp + 96], ymm13
  db $C5, $2D, $FE, $C6                           // vpaddd ymm8, ymm10, ymm6
  db $C4, $C1, $35, $72, $F0, $07                 // vpslld ymm9, ymm8, 7
  db $C4, $C1, $3D, $72, $D0, $19                 // vpsrld ymm8, ymm8, 25
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $41, $0D, $EF, $F0                      // vpxor ymm14, ymm14, ymm8
  db $C4, $41, $05, $FE, $E3                      // vpaddd ymm12, ymm15, ymm11
  db $C4, $C1, $15, $72, $F4, $07                 // vpslld ymm13, ymm12, 7
  db $C4, $C1, $1D, $72, $D4, $19                 // vpsrld ymm12, ymm12, 25
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $C1, $65, $EF, $DC                      // vpxor ymm3, ymm3, ymm12
  db $C4, $41, $0D, $FE, $C2                      // vpaddd ymm8, ymm14, ymm10
  db $C4, $C1, $35, $72, $F0, $09                 // vpslld ymm9, ymm8, 9
  db $C4, $C1, $3D, $72, $D0, $17                 // vpsrld ymm8, ymm8, 23
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $C1, $6D, $EF, $D0                      // vpxor ymm2, ymm2, ymm8
  db $C4, $41, $65, $FE, $E7                      // vpaddd ymm12, ymm3, ymm15
  db $C4, $C1, $15, $72, $F4, $09                 // vpslld ymm13, ymm12, 9
  db $C4, $C1, $1D, $72, $D4, $17                 // vpsrld ymm12, ymm12, 23
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $C1, $45, $EF, $FC                      // vpxor ymm7, ymm7, ymm12
  db $C4, $41, $6D, $FE, $C6                      // vpaddd ymm8, ymm2, ymm14
  db $C4, $C1, $35, $72, $F0, $0D                 // vpslld ymm9, ymm8, 13
  db $C4, $C1, $3D, $72, $D0, $13                 // vpsrld ymm8, ymm8, 19
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $C1, $4D, $EF, $F0                      // vpxor ymm6, ymm6, ymm8
  db $C5, $45, $FE, $E3                           // vpaddd ymm12, ymm7, ymm3
  db $C4, $C1, $15, $72, $F4, $0D                 // vpslld ymm13, ymm12, 13
  db $C4, $C1, $1D, $72, $D4, $13                 // vpsrld ymm12, ymm12, 19
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $41, $25, $EF, $DC                      // vpxor ymm11, ymm11, ymm12
  db $C5, $4D, $FE, $C2                           // vpaddd ymm8, ymm6, ymm2
  db $C4, $C1, $35, $72, $F0, $12                 // vpslld ymm9, ymm8, 18
  db $C4, $C1, $3D, $72, $D0, $0E                 // vpsrld ymm8, ymm8, 14
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $41, $2D, $EF, $D0                      // vpxor ymm10, ymm10, ymm8
  db $C5, $25, $FE, $E7                           // vpaddd ymm12, ymm11, ymm7
  db $C4, $C1, $15, $72, $F4, $12                 // vpslld ymm13, ymm12, 18
  db $C4, $C1, $1D, $72, $D4, $0E                 // vpsrld ymm12, ymm12, 14
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $41, $05, $EF, $FC                      // vpxor ymm15, ymm15, ymm12
  db $C5, $7D, $FE, $C3                           // vpaddd ymm8, ymm0, ymm3
  db $C4, $C1, $35, $72, $F0, $07                 // vpslld ymm9, ymm8, 7
  db $C4, $C1, $3D, $72, $D0, $19                 // vpsrld ymm8, ymm8, 25
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $C1, $75, $EF, $C8                      // vpxor ymm1, ymm1, ymm8
  db $C5, $55, $FE, $E4                           // vpaddd ymm12, ymm5, ymm4
  db $C4, $C1, $15, $72, $F4, $07                 // vpslld ymm13, ymm12, 7
  db $C4, $C1, $1D, $72, $D4, $19                 // vpsrld ymm12, ymm12, 25
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $C1, $4D, $EF, $F4                      // vpxor ymm6, ymm6, ymm12
  db $C5, $75, $FE, $C0                           // vpaddd ymm8, ymm1, ymm0
  db $C4, $C1, $35, $72, $F0, $09                 // vpslld ymm9, ymm8, 9
  db $C4, $C1, $3D, $72, $D0, $17                 // vpsrld ymm8, ymm8, 23
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $C1, $6D, $EF, $D0                      // vpxor ymm2, ymm2, ymm8
  db $C5, $4D, $FE, $E5                           // vpaddd ymm12, ymm6, ymm5
  db $C4, $C1, $15, $72, $F4, $09                 // vpslld ymm13, ymm12, 9
  db $C4, $C1, $1D, $72, $D4, $17                 // vpsrld ymm12, ymm12, 23
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $C1, $45, $EF, $FC                      // vpxor ymm7, ymm7, ymm12
  db $C5, $6D, $FE, $C1                           // vpaddd ymm8, ymm2, ymm1
  db $C4, $C1, $35, $72, $F0, $0D                 // vpslld ymm9, ymm8, 13
  db $C4, $C1, $3D, $72, $D0, $13                 // vpsrld ymm8, ymm8, 19
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $C1, $65, $EF, $D8                      // vpxor ymm3, ymm3, ymm8
  db $C5, $45, $FE, $E6                           // vpaddd ymm12, ymm7, ymm6
  db $C4, $C1, $15, $72, $F4, $0D                 // vpslld ymm13, ymm12, 13
  db $C4, $C1, $1D, $72, $D4, $13                 // vpsrld ymm12, ymm12, 19
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $C1, $5D, $EF, $E4                      // vpxor ymm4, ymm4, ymm12
  db $C5, $65, $FE, $C2                           // vpaddd ymm8, ymm3, ymm2
  db $C4, $C1, $35, $72, $F0, $12                 // vpslld ymm9, ymm8, 18
  db $C4, $C1, $3D, $72, $D0, $0E                 // vpsrld ymm8, ymm8, 14
  db $C4, $41, $35, $EB, $C0                      // vpor ymm8, ymm9, ymm8
  db $C4, $C1, $7D, $EF, $C0                      // vpxor ymm0, ymm0, ymm8
  db $C5, $5D, $FE, $E7                           // vpaddd ymm12, ymm4, ymm7
  db $C4, $C1, $15, $72, $F4, $12                 // vpslld ymm13, ymm12, 18
  db $C4, $C1, $1D, $72, $D4, $0E                 // vpsrld ymm12, ymm12, 14
  db $C4, $41, $15, $EB, $E4                      // vpor ymm12, ymm13, ymm12
  db $C4, $C1, $55, $EF, $EC                      // vpxor ymm5, ymm5, ymm12
  db $C5, $7D, $6F, $04, $24                      // vmovdqa ymm8, [rsp]
  db $C5, $7D, $6F, $4C, $24, $20                 // vmovdqa ymm9, [rsp + 32]
  db $C5, $7D, $6F, $64, $24, $40                 // vmovdqa ymm12, [rsp + 64]
  db $C5, $7D, $6F, $6C, $24, $60                 // vmovdqa ymm13, [rsp + 96]
  db $C5, $FD, $7F, $14, $24                      // vmovdqa [rsp], ymm2
  db $C5, $FD, $7F, $5C, $24, $20                 // vmovdqa [rsp + 32], ymm3
  db $C5, $FD, $7F, $74, $24, $40                 // vmovdqa [rsp + 64], ymm6
  db $C5, $FD, $7F, $7C, $24, $60                 // vmovdqa [rsp + 96], ymm7
  db $C4, $C1, $2D, $FE, $D1                      // vpaddd ymm2, ymm10, ymm9
  db $C5, $E5, $72, $F2, $07                      // vpslld ymm3, ymm2, 7
  db $C5, $ED, $72, $D2, $19                      // vpsrld ymm2, ymm2, 25
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $25, $EF, $DA                           // vpxor ymm11, ymm11, ymm2
  db $C4, $C1, $05, $FE, $F6                      // vpaddd ymm6, ymm15, ymm14
  db $C5, $C5, $72, $F6, $07                      // vpslld ymm7, ymm6, 7
  db $C5, $CD, $72, $D6, $19                      // vpsrld ymm6, ymm6, 25
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $1D, $EF, $E6                           // vpxor ymm12, ymm12, ymm6
  db $C4, $C1, $25, $FE, $D2                      // vpaddd ymm2, ymm11, ymm10
  db $C5, $E5, $72, $F2, $09                      // vpslld ymm3, ymm2, 9
  db $C5, $ED, $72, $D2, $17                      // vpsrld ymm2, ymm2, 23
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $3D, $EF, $C2                           // vpxor ymm8, ymm8, ymm2
  db $C4, $C1, $1D, $FE, $F7                      // vpaddd ymm6, ymm12, ymm15
  db $C5, $C5, $72, $F6, $09                      // vpslld ymm7, ymm6, 9
  db $C5, $CD, $72, $D6, $17                      // vpsrld ymm6, ymm6, 23
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $15, $EF, $EE                           // vpxor ymm13, ymm13, ymm6
  db $C4, $C1, $3D, $FE, $D3                      // vpaddd ymm2, ymm8, ymm11
  db $C5, $E5, $72, $F2, $0D                      // vpslld ymm3, ymm2, 13
  db $C5, $ED, $72, $D2, $13                      // vpsrld ymm2, ymm2, 19
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $35, $EF, $CA                           // vpxor ymm9, ymm9, ymm2
  db $C4, $C1, $15, $FE, $F4                      // vpaddd ymm6, ymm13, ymm12
  db $C5, $C5, $72, $F6, $0D                      // vpslld ymm7, ymm6, 13
  db $C5, $CD, $72, $D6, $13                      // vpsrld ymm6, ymm6, 19
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $0D, $EF, $F6                           // vpxor ymm14, ymm14, ymm6
  db $C4, $C1, $35, $FE, $D0                      // vpaddd ymm2, ymm9, ymm8
  db $C5, $E5, $72, $F2, $12                      // vpslld ymm3, ymm2, 18
  db $C5, $ED, $72, $D2, $0E                      // vpsrld ymm2, ymm2, 14
  db $C5, $E5, $EB, $D2                           // vpor ymm2, ymm3, ymm2
  db $C5, $2D, $EF, $D2                           // vpxor ymm10, ymm10, ymm2
  db $C4, $C1, $0D, $FE, $F5                      // vpaddd ymm6, ymm14, ymm13
  db $C5, $C5, $72, $F6, $12                      // vpslld ymm7, ymm6, 18
  db $C5, $CD, $72, $D6, $0E                      // vpsrld ymm6, ymm6, 14
  db $C5, $C5, $EB, $F6                           // vpor ymm6, ymm7, ymm6
  db $C5, $05, $EF, $FE                           // vpxor ymm15, ymm15, ymm6
  sub     eax, 2
  jg      @@salsa_avx2_8x_round
  add     dword ptr [rdx + 32], 8
  adc     dword ptr [rdx + 36], 0
  db $C5, $3D, $FE, $84, $24, $80, $01, $00, $00  // vpaddd ymm8, ymm8, [rsp + 384]
  db $C5, $35, $FE, $8C, $24, $A0, $01, $00, $00  // vpaddd ymm9, ymm9, [rsp + 416]
  db $C5, $2D, $FE, $94, $24, $C0, $01, $00, $00  // vpaddd ymm10, ymm10, [rsp + 448]
  db $C5, $25, $FE, $9C, $24, $E0, $01, $00, $00  // vpaddd ymm11, ymm11, [rsp + 480]
  db $C4, $C1, $3D, $62, $D1                      // vpunpckldq ymm2, ymm8, ymm9
  db $C4, $C1, $2D, $62, $DB                      // vpunpckldq ymm3, ymm10, ymm11
  db $C4, $41, $3D, $6A, $C1                      // vpunpckhdq ymm8, ymm8, ymm9
  db $C4, $41, $2D, $6A, $D3                      // vpunpckhdq ymm10, ymm10, ymm11
  db $C5, $6D, $6C, $CB                           // vpunpcklqdq ymm9, ymm2, ymm3
  db $C5, $ED, $6D, $D3                           // vpunpckhqdq ymm2, ymm2, ymm3
  db $C4, $41, $3D, $6C, $DA                      // vpunpcklqdq ymm11, ymm8, ymm10
  db $C4, $41, $3D, $6D, $C2                      // vpunpckhqdq ymm8, ymm8, ymm10
  db $C5, $1D, $FE, $A4, $24, $00, $02, $00, $00  // vpaddd ymm12, ymm12, [rsp + 512]
  db $C5, $15, $FE, $AC, $24, $20, $02, $00, $00  // vpaddd ymm13, ymm13, [rsp + 544]
  db $C5, $0D, $FE, $B4, $24, $40, $02, $00, $00  // vpaddd ymm14, ymm14, [rsp + 576]
  db $C5, $05, $FE, $BC, $24, $60, $02, $00, $00  // vpaddd ymm15, ymm15, [rsp + 608]
  db $C4, $41, $1D, $62, $D5                      // vpunpckldq ymm10, ymm12, ymm13
  db $C4, $C1, $0D, $62, $DF                      // vpunpckldq ymm3, ymm14, ymm15
  db $C4, $41, $1D, $6A, $E5                      // vpunpckhdq ymm12, ymm12, ymm13
  db $C4, $41, $0D, $6A, $F7                      // vpunpckhdq ymm14, ymm14, ymm15
  db $C5, $2D, $6C, $EB                           // vpunpcklqdq ymm13, ymm10, ymm3
  db $C5, $2D, $6D, $D3                           // vpunpckhqdq ymm10, ymm10, ymm3
  db $C4, $41, $1D, $6C, $FE                      // vpunpcklqdq ymm15, ymm12, ymm14
  db $C4, $41, $1D, $6D, $E6                      // vpunpckhqdq ymm12, ymm12, ymm14
  db $C4, $C3, $35, $46, $F5, $20                 // vperm2i128 ymm6, ymm9, ymm13, $20
  db $C4, $43, $35, $46, $ED, $31                 // vperm2i128 ymm13, ymm9, ymm13, $31
  db $C4, $43, $6D, $46, $CA, $20                 // vperm2i128 ymm9, ymm2, ymm10, $20
  db $C4, $43, $6D, $46, $D2, $31                 // vperm2i128 ymm10, ymm2, ymm10, $31
  db $C4, $C3, $25, $46, $D7, $20                 // vperm2i128 ymm2, ymm11, ymm15, $20
  db $C4, $43, $25, $46, $FF, $31                 // vperm2i128 ymm15, ymm11, ymm15, $31
  db $C4, $43, $3D, $46, $DC, $20                 // vperm2i128 ymm11, ymm8, ymm12, $20
  db $C4, $43, $3D, $46, $E4, $31                 // vperm2i128 ymm12, ymm8, ymm12, $31
  db $C4, $C1, $4D, $EF, $70, $20                 // vpxor ymm6, ymm6, [r8 + 32]
  db $C4, $C1, $7E, $7F, $71, $20                 // vmovdqu [r9 + 32], ymm6
  db $C4, $41, $35, $EF, $48, $60                 // vpxor ymm9, ymm9, [r8 + 96]
  db $C4, $41, $7E, $7F, $49, $60                 // vmovdqu [r9 + 96], ymm9
  db $C4, $C1, $6D, $EF, $90, $A0, $00, $00, $00  // vpxor ymm2, ymm2, [r8 + 160]
  db $C4, $C1, $7E, $7F, $91, $A0, $00, $00, $00  // vmovdqu [r9 + 160], ymm2
  db $C4, $41, $25, $EF, $98, $E0, $00, $00, $00  // vpxor ymm11, ymm11, [r8 + 224]
  db $C4, $41, $7E, $7F, $99, $E0, $00, $00, $00  // vmovdqu [r9 + 224], ymm11
  db $C4, $41, $15, $EF, $A8, $20, $01, $00, $00  // vpxor ymm13, ymm13, [r8 + 288]
  db $C4, $41, $7E, $7F, $A9, $20, $01, $00, $00  // vmovdqu [r9 + 288], ymm13
  db $C4, $41, $2D, $EF, $90, $60, $01, $00, $00  // vpxor ymm10, ymm10, [r8 + 352]
  db $C4, $41, $7E, $7F, $91, $60, $01, $00, $00  // vmovdqu [r9 + 352], ymm10
  db $C4, $41, $05, $EF, $B8, $A0, $01, $00, $00  // vpxor ymm15, ymm15, [r8 + 416]
  db $C4, $41, $7E, $7F, $B9, $A0, $01, $00, $00  // vmovdqu [r9 + 416], ymm15
  db $C4, $41, $1D, $EF, $A0, $E0, $01, $00, $00  // vpxor ymm12, ymm12, [r8 + 480]
  db $C4, $41, $7E, $7F, $A1, $E0, $01, $00, $00  // vmovdqu [r9 + 480], ymm12
  db $C5, $FD, $6F, $14, $24                      // vmovdqa ymm2, [rsp]
  db $C5, $FD, $6F, $5C, $24, $20                 // vmovdqa ymm3, [rsp + 32]
  db $C5, $FD, $FE, $84, $24, $80, $00, $00, $00  // vpaddd ymm0, ymm0, [rsp + 128]
  db $C5, $F5, $FE, $8C, $24, $A0, $00, $00, $00  // vpaddd ymm1, ymm1, [rsp + 160]
  db $C5, $ED, $FE, $94, $24, $C0, $00, $00, $00  // vpaddd ymm2, ymm2, [rsp + 192]
  db $C5, $E5, $FE, $9C, $24, $E0, $00, $00, $00  // vpaddd ymm3, ymm3, [rsp + 224]
  db $C5, $FD, $62, $F1                           // vpunpckldq ymm6, ymm0, ymm1
  db $C5, $ED, $62, $FB                           // vpunpckldq ymm7, ymm2, ymm3
  db $C5, $FD, $6A, $C1                           // vpunpckhdq ymm0, ymm0, ymm1
  db $C5, $ED, $6A, $D3                           // vpunpckhdq ymm2, ymm2, ymm3
  db $C5, $CD, $6C, $CF                           // vpunpcklqdq ymm1, ymm6, ymm7
  db $C5, $CD, $6D, $F7                           // vpunpckhqdq ymm6, ymm6, ymm7
  db $C5, $FD, $6C, $DA                           // vpunpcklqdq ymm3, ymm0, ymm2
  db $C5, $FD, $6D, $C2                           // vpunpckhqdq ymm0, ymm0, ymm2
  db $C5, $7D, $6F, $44, $24, $40                 // vmovdqa ymm8, [rsp + 64]
  db $C5, $7D, $6F, $4C, $24, $60                 // vmovdqa ymm9, [rsp + 96]
  db $C5, $DD, $FE, $A4, $24, $00, $01, $00, $00  // vpaddd ymm4, ymm4, [rsp + 256]
  db $C5, $D5, $FE, $AC, $24, $20, $01, $00, $00  // vpaddd ymm5, ymm5, [rsp + 288]
  db $C5, $3D, $FE, $84, $24, $40, $01, $00, $00  // vpaddd ymm8, ymm8, [rsp + 320]
  db $C5, $35, $FE, $8C, $24, $60, $01, $00, $00  // vpaddd ymm9, ymm9, [rsp + 352]
  db $C5, $DD, $62, $D5                           // vpunpckldq ymm2, ymm4, ymm5
  db $C4, $C1, $3D, $62, $F9                      // vpunpckldq ymm7, ymm8, ymm9
  db $C5, $DD, $6A, $E5                           // vpunpckhdq ymm4, ymm4, ymm5
  db $C4, $41, $3D, $6A, $C1                      // vpunpckhdq ymm8, ymm8, ymm9
  db $C5, $ED, $6C, $EF                           // vpunpcklqdq ymm5, ymm2, ymm7
  db $C5, $ED, $6D, $D7                           // vpunpckhqdq ymm2, ymm2, ymm7
  db $C4, $41, $5D, $6C, $C8                      // vpunpcklqdq ymm9, ymm4, ymm8
  db $C4, $C1, $5D, $6D, $E0                      // vpunpckhqdq ymm4, ymm4, ymm8
  db $C4, $63, $75, $46, $C5, $20                 // vperm2i128 ymm8, ymm1, ymm5, $20
  db $C4, $E3, $75, $46, $ED, $31                 // vperm2i128 ymm5, ymm1, ymm5, $31
  db $C4, $E3, $4D, $46, $CA, $20                 // vperm2i128 ymm1, ymm6, ymm2, $20
  db $C4, $E3, $4D, $46, $D2, $31                 // vperm2i128 ymm2, ymm6, ymm2, $31
  db $C4, $C3, $65, $46, $F1, $20                 // vperm2i128 ymm6, ymm3, ymm9, $20
  db $C4, $43, $65, $46, $C9, $31                 // vperm2i128 ymm9, ymm3, ymm9, $31
  db $C4, $E3, $7D, $46, $DC, $20                 // vperm2i128 ymm3, ymm0, ymm4, $20
  db $C4, $E3, $7D, $46, $E4, $31                 // vperm2i128 ymm4, ymm0, ymm4, $31
  db $C4, $41, $3D, $EF, $00                      // vpxor ymm8, ymm8, [r8 + 0]
  db $C4, $41, $7E, $7F, $01                      // vmovdqu [r9], ymm8
  db $C4, $C1, $75, $EF, $48, $40                 // vpxor ymm1, ymm1, [r8 + 64]
  db $C4, $C1, $7E, $7F, $49, $40                 // vmovdqu [r9 + 64], ymm1
  db $C4, $C1, $4D, $EF, $B0, $80, $00, $00, $00  // vpxor ymm6, ymm6, [r8 + 128]
  db $C4, $C1, $7E, $7F, $B1, $80, $00, $00, $00  // vmovdqu [r9 + 128], ymm6
  db $C4, $C1, $65, $EF, $98, $C0, $00, $00, $00  // vpxor ymm3, ymm3, [r8 + 192]
  db $C4, $C1, $7E, $7F, $99, $C0, $00, $00, $00  // vmovdqu [r9 + 192], ymm3
  db $C4, $C1, $55, $EF, $A8, $00, $01, $00, $00  // vpxor ymm5, ymm5, [r8 + 256]
  db $C4, $C1, $7E, $7F, $A9, $00, $01, $00, $00  // vmovdqu [r9 + 256], ymm5
  db $C4, $C1, $6D, $EF, $90, $40, $01, $00, $00  // vpxor ymm2, ymm2, [r8 + 320]
  db $C4, $C1, $7E, $7F, $91, $40, $01, $00, $00  // vmovdqu [r9 + 320], ymm2
  db $C4, $41, $35, $EF, $88, $80, $01, $00, $00  // vpxor ymm9, ymm9, [r8 + 384]
  db $C4, $41, $7E, $7F, $89, $80, $01, $00, $00  // vmovdqu [r9 + 384], ymm9
  db $C4, $C1, $5D, $EF, $A0, $C0, $01, $00, $00  // vpxor ymm4, ymm4, [r8 + 448]
  db $C4, $C1, $7E, $7F, $A1, $C0, $01, $00, $00  // vmovdqu [r9 + 448], ymm4
  add     r8, 512
  add     r9, 512
  dec     r10
  jnz     @@salsa_avx2_8x_outer
  db $C5, $F8, $77                                // vzeroupper
  mov     rsp, r11
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

