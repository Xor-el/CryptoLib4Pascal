// Salsa20 4-way SSE2 keystream kernel, vertical layout (x86-64).
// -------------------------------------------------------------------
//
// Four 64-byte Salsa20 blocks per group, state words held vertically (one
// block per xmm lane), register-resident as xmm(i) = word i except for the
// current quarter-round temp set: the column pairs split the words
// {0,1,4,5,8,9,12,13} / {2,3,6,7,10,11,14,15} and the row pairs {0..7} /
// {8..15}, so parking {2,3,6,7} or {8,9,12,13} in stack slots frees four
// rotate temps and a double round costs exactly two 4-store/4-load swaps.
// All rotations (7/9/13/18) are shift+or on the quarter-round sum - none is
// byte-aligned, so there is no pshufb tier. The frame is 64B-aligned
// (r11 = frame register).
//
// Streams AGroups x 256B in one call: prologue once, light per-group reload
// (counter lanes +4), fused accumulate/transpose/xor tail straight to AOut
// (the fully-resident word quads 8..15 drain first so the parked words
// rejoin without extra spill).
//
// The vector counter lanes ride word 8 and always broadcast word 9, so the
// caller must guarantee the low counter word does not wrap inside the
// 4*AGroups-block span (TSalsa20Engine.WideGroupsSafe); the per-group AState
// write-back over words 8/9 is a true 64-bit add.
//
// On entry (after ClpSimdProc5Begin_x86_64.inc):
//   rcx = ARounds, rdx = AState (16 UInt32), r8 = AIn, r9 = AOut,
//   r10 = AGroups (4-block groups, >= 1).
//
// On exit:
//   AState words 8/9 counter (byte 32) advanced by 4*AGroups as one 64-bit
//   value; the keystream is xored with AIn into AOut (256*AGroups bytes).
//
// Reference: D.J. Bernstein, "Salsa20 specification" (cr.yp.to/salsa20/) -
// the quarterround/rowround/columnround arithmetic that this kernel's
// rounds implement.
//
// Ops touching the extended xmm8-15 registers are db-encoded for broad
// assembler compatibility.
  mov     r10d, r10d
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}
  mov     r11, rsp
  sub     rsp, 352
  and     rsp, -64
  mov     dword ptr [rsp + 320], 0
  mov     dword ptr [rsp + 324], 1
  mov     dword ptr [rsp + 328], 2
  mov     dword ptr [rsp + 332], 3
  mov     dword ptr [rsp + 336], 4
  mov     dword ptr [rsp + 340], 4
  mov     dword ptr [rsp + 344], 4
  mov     dword ptr [rsp + 348], 4
  movd    xmm0, [rdx]
  pshufd  xmm0, xmm0, $00
  movdqa  [rsp + 64], xmm0
  movd    xmm1, [rdx + 4]
  pshufd  xmm1, xmm1, $00
  movdqa  [rsp + 80], xmm1
  movd    xmm2, [rdx + 8]
  pshufd  xmm2, xmm2, $00
  movdqa  [rsp + 96], xmm2
  movdqa  [rsp], xmm2
  movd    xmm3, [rdx + 12]
  pshufd  xmm3, xmm3, $00
  movdqa  [rsp + 112], xmm3
  movdqa  [rsp + 16], xmm3
  movd    xmm4, [rdx + 16]
  pshufd  xmm4, xmm4, $00
  movdqa  [rsp + 128], xmm4
  movd    xmm5, [rdx + 20]
  pshufd  xmm5, xmm5, $00
  movdqa  [rsp + 144], xmm5
  movd    xmm6, [rdx + 24]
  pshufd  xmm6, xmm6, $00
  movdqa  [rsp + 160], xmm6
  movdqa  [rsp + 32], xmm6
  movd    xmm7, [rdx + 28]
  pshufd  xmm7, xmm7, $00
  movdqa  [rsp + 176], xmm7
  movdqa  [rsp + 48], xmm7
  movd    xmm8, [rdx + 32]
  db $66, $45, $0F, $70, $C0, $00                      // pshufd xmm8, xmm8, $00
  db $66, $44, $0F, $FE, $84, $24, $40, $01, $00, $00  // paddd xmm8, [rsp + 320]
  movdqa  [rsp + 192], xmm8
  movd    xmm9, [rdx + 36]
  db $66, $45, $0F, $70, $C9, $00                      // pshufd xmm9, xmm9, $00
  movdqa  [rsp + 208], xmm9
  movd    xmm10, [rdx + 40]
  db $66, $45, $0F, $70, $D2, $00                      // pshufd xmm10, xmm10, $00
  movdqa  [rsp + 224], xmm10
  movd    xmm11, [rdx + 44]
  db $66, $45, $0F, $70, $DB, $00                      // pshufd xmm11, xmm11, $00
  movdqa  [rsp + 240], xmm11
  movd    xmm12, [rdx + 48]
  db $66, $45, $0F, $70, $E4, $00                      // pshufd xmm12, xmm12, $00
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
  jmp     @@salsa_sse2_4x_enter
@@salsa_sse2_4x_outer:
  movdqa  xmm0, [rsp + 64]
  movdqa  xmm1, [rsp + 80]
  movdqa  xmm2, [rsp + 96]
  movdqa  [rsp], xmm2
  movdqa  xmm3, [rsp + 112]
  movdqa  [rsp + 16], xmm3
  movdqa  xmm4, [rsp + 128]
  movdqa  xmm5, [rsp + 144]
  movdqa  xmm6, [rsp + 160]
  movdqa  [rsp + 32], xmm6
  movdqa  xmm7, [rsp + 176]
  movdqa  [rsp + 48], xmm7
  movdqa  xmm8, [rsp + 192]
  db $66, $44, $0F, $FE, $84, $24, $50, $01, $00, $00  // paddd xmm8, [rsp + 336]
  movdqa  [rsp + 192], xmm8
  movdqa  xmm9, [rsp + 208]
  movdqa  xmm10, [rsp + 224]
  movdqa  xmm11, [rsp + 240]
  movdqa  xmm12, [rsp + 256]
  movdqa  xmm13, [rsp + 272]
  movdqa  xmm14, [rsp + 288]
  movdqa  xmm15, [rsp + 304]
@@salsa_sse2_4x_enter:
  mov     eax, ecx
@@salsa_sse2_4x_round:
  movdqa  xmm2, xmm0
  db $66, $41, $0F, $FE, $D4                           // paddd xmm2, xmm12
  movdqa  xmm3, xmm2
  pslld   xmm2, 7
  psrld   xmm3, 25
  por     xmm2, xmm3
  pxor    xmm4, xmm2
  movdqa  xmm6, xmm5
  paddd   xmm6, xmm1
  movdqa  xmm7, xmm6
  pslld   xmm6, 7
  psrld   xmm7, 25
  por     xmm6, xmm7
  db $66, $44, $0F, $EF, $CE                           // pxor xmm9, xmm6
  movdqa  xmm2, xmm4
  paddd   xmm2, xmm0
  movdqa  xmm3, xmm2
  pslld   xmm2, 9
  psrld   xmm3, 23
  por     xmm2, xmm3
  db $66, $44, $0F, $EF, $C2                           // pxor xmm8, xmm2
  db $66, $41, $0F, $6F, $F1                           // movdqa xmm6, xmm9
  paddd   xmm6, xmm5
  movdqa  xmm7, xmm6
  pslld   xmm6, 9
  psrld   xmm7, 23
  por     xmm6, xmm7
  db $66, $44, $0F, $EF, $EE                           // pxor xmm13, xmm6
  db $66, $41, $0F, $6F, $D0                           // movdqa xmm2, xmm8
  paddd   xmm2, xmm4
  movdqa  xmm3, xmm2
  pslld   xmm2, 13
  psrld   xmm3, 19
  por     xmm2, xmm3
  db $66, $44, $0F, $EF, $E2                           // pxor xmm12, xmm2
  db $66, $41, $0F, $6F, $F5                           // movdqa xmm6, xmm13
  db $66, $41, $0F, $FE, $F1                           // paddd xmm6, xmm9
  movdqa  xmm7, xmm6
  pslld   xmm6, 13
  psrld   xmm7, 19
  por     xmm6, xmm7
  pxor    xmm1, xmm6
  db $66, $41, $0F, $6F, $D4                           // movdqa xmm2, xmm12
  db $66, $41, $0F, $FE, $D0                           // paddd xmm2, xmm8
  movdqa  xmm3, xmm2
  pslld   xmm2, 18
  psrld   xmm3, 14
  por     xmm2, xmm3
  pxor    xmm0, xmm2
  movdqa  xmm6, xmm1
  db $66, $41, $0F, $FE, $F5                           // paddd xmm6, xmm13
  movdqa  xmm7, xmm6
  pslld   xmm6, 18
  psrld   xmm7, 14
  por     xmm6, xmm7
  pxor    xmm5, xmm6
  movdqa  xmm2, [rsp]
  movdqa  xmm3, [rsp + 16]
  movdqa  xmm6, [rsp + 32]
  movdqa  xmm7, [rsp + 48]
  movdqa  [rsp], xmm8
  movdqa  [rsp + 16], xmm9
  movdqa  [rsp + 32], xmm12
  movdqa  [rsp + 48], xmm13
  db $66, $45, $0F, $6F, $C2                           // movdqa xmm8, xmm10
  db $66, $44, $0F, $FE, $C6                           // paddd xmm8, xmm6
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $07                      // pslld xmm8, 7
  db $66, $41, $0F, $72, $D1, $19                      // psrld xmm9, 25
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $45, $0F, $EF, $F0                           // pxor xmm14, xmm8
  db $66, $45, $0F, $6F, $E7                           // movdqa xmm12, xmm15
  db $66, $45, $0F, $FE, $E3                           // paddd xmm12, xmm11
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $07                      // pslld xmm12, 7
  db $66, $41, $0F, $72, $D5, $19                      // psrld xmm13, 25
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $41, $0F, $EF, $DC                           // pxor xmm3, xmm12
  db $66, $45, $0F, $6F, $C6                           // movdqa xmm8, xmm14
  db $66, $45, $0F, $FE, $C2                           // paddd xmm8, xmm10
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $09                      // pslld xmm8, 9
  db $66, $41, $0F, $72, $D1, $17                      // psrld xmm9, 23
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $41, $0F, $EF, $D0                           // pxor xmm2, xmm8
  db $66, $44, $0F, $6F, $E3                           // movdqa xmm12, xmm3
  db $66, $45, $0F, $FE, $E7                           // paddd xmm12, xmm15
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $09                      // pslld xmm12, 9
  db $66, $41, $0F, $72, $D5, $17                      // psrld xmm13, 23
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $41, $0F, $EF, $FC                           // pxor xmm7, xmm12
  db $66, $44, $0F, $6F, $C2                           // movdqa xmm8, xmm2
  db $66, $45, $0F, $FE, $C6                           // paddd xmm8, xmm14
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $0D                      // pslld xmm8, 13
  db $66, $41, $0F, $72, $D1, $13                      // psrld xmm9, 19
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $41, $0F, $EF, $F0                           // pxor xmm6, xmm8
  db $66, $44, $0F, $6F, $E7                           // movdqa xmm12, xmm7
  db $66, $44, $0F, $FE, $E3                           // paddd xmm12, xmm3
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $0D                      // pslld xmm12, 13
  db $66, $41, $0F, $72, $D5, $13                      // psrld xmm13, 19
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $45, $0F, $EF, $DC                           // pxor xmm11, xmm12
  db $66, $44, $0F, $6F, $C6                           // movdqa xmm8, xmm6
  db $66, $44, $0F, $FE, $C2                           // paddd xmm8, xmm2
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $12                      // pslld xmm8, 18
  db $66, $41, $0F, $72, $D1, $0E                      // psrld xmm9, 14
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $45, $0F, $EF, $D0                           // pxor xmm10, xmm8
  db $66, $45, $0F, $6F, $E3                           // movdqa xmm12, xmm11
  db $66, $44, $0F, $FE, $E7                           // paddd xmm12, xmm7
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $12                      // pslld xmm12, 18
  db $66, $41, $0F, $72, $D5, $0E                      // psrld xmm13, 14
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $45, $0F, $EF, $FC                           // pxor xmm15, xmm12
  db $66, $44, $0F, $6F, $C0                           // movdqa xmm8, xmm0
  db $66, $44, $0F, $FE, $C3                           // paddd xmm8, xmm3
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $07                      // pslld xmm8, 7
  db $66, $41, $0F, $72, $D1, $19                      // psrld xmm9, 25
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $41, $0F, $EF, $C8                           // pxor xmm1, xmm8
  db $66, $44, $0F, $6F, $E5                           // movdqa xmm12, xmm5
  db $66, $44, $0F, $FE, $E4                           // paddd xmm12, xmm4
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $07                      // pslld xmm12, 7
  db $66, $41, $0F, $72, $D5, $19                      // psrld xmm13, 25
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $41, $0F, $EF, $F4                           // pxor xmm6, xmm12
  db $66, $44, $0F, $6F, $C1                           // movdqa xmm8, xmm1
  db $66, $44, $0F, $FE, $C0                           // paddd xmm8, xmm0
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $09                      // pslld xmm8, 9
  db $66, $41, $0F, $72, $D1, $17                      // psrld xmm9, 23
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $41, $0F, $EF, $D0                           // pxor xmm2, xmm8
  db $66, $44, $0F, $6F, $E6                           // movdqa xmm12, xmm6
  db $66, $44, $0F, $FE, $E5                           // paddd xmm12, xmm5
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $09                      // pslld xmm12, 9
  db $66, $41, $0F, $72, $D5, $17                      // psrld xmm13, 23
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $41, $0F, $EF, $FC                           // pxor xmm7, xmm12
  db $66, $44, $0F, $6F, $C2                           // movdqa xmm8, xmm2
  db $66, $44, $0F, $FE, $C1                           // paddd xmm8, xmm1
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $0D                      // pslld xmm8, 13
  db $66, $41, $0F, $72, $D1, $13                      // psrld xmm9, 19
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $41, $0F, $EF, $D8                           // pxor xmm3, xmm8
  db $66, $44, $0F, $6F, $E7                           // movdqa xmm12, xmm7
  db $66, $44, $0F, $FE, $E6                           // paddd xmm12, xmm6
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $0D                      // pslld xmm12, 13
  db $66, $41, $0F, $72, $D5, $13                      // psrld xmm13, 19
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $41, $0F, $EF, $E4                           // pxor xmm4, xmm12
  db $66, $44, $0F, $6F, $C3                           // movdqa xmm8, xmm3
  db $66, $44, $0F, $FE, $C2                           // paddd xmm8, xmm2
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $41, $0F, $72, $F0, $12                      // pslld xmm8, 18
  db $66, $41, $0F, $72, $D1, $0E                      // psrld xmm9, 14
  db $66, $45, $0F, $EB, $C1                           // por xmm8, xmm9
  db $66, $41, $0F, $EF, $C0                           // pxor xmm0, xmm8
  db $66, $44, $0F, $6F, $E4                           // movdqa xmm12, xmm4
  db $66, $44, $0F, $FE, $E7                           // paddd xmm12, xmm7
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $41, $0F, $72, $F4, $12                      // pslld xmm12, 18
  db $66, $41, $0F, $72, $D5, $0E                      // psrld xmm13, 14
  db $66, $45, $0F, $EB, $E5                           // por xmm12, xmm13
  db $66, $41, $0F, $EF, $EC                           // pxor xmm5, xmm12
  movdqa  xmm8, [rsp]
  movdqa  xmm9, [rsp + 16]
  movdqa  xmm12, [rsp + 32]
  movdqa  xmm13, [rsp + 48]
  movdqa  [rsp], xmm2
  movdqa  [rsp + 16], xmm3
  movdqa  [rsp + 32], xmm6
  movdqa  [rsp + 48], xmm7
  db $66, $41, $0F, $6F, $D2                           // movdqa xmm2, xmm10
  db $66, $41, $0F, $FE, $D1                           // paddd xmm2, xmm9
  movdqa  xmm3, xmm2
  pslld   xmm2, 7
  psrld   xmm3, 25
  por     xmm2, xmm3
  db $66, $44, $0F, $EF, $DA                           // pxor xmm11, xmm2
  db $66, $41, $0F, $6F, $F7                           // movdqa xmm6, xmm15
  db $66, $41, $0F, $FE, $F6                           // paddd xmm6, xmm14
  movdqa  xmm7, xmm6
  pslld   xmm6, 7
  psrld   xmm7, 25
  por     xmm6, xmm7
  db $66, $44, $0F, $EF, $E6                           // pxor xmm12, xmm6
  db $66, $41, $0F, $6F, $D3                           // movdqa xmm2, xmm11
  db $66, $41, $0F, $FE, $D2                           // paddd xmm2, xmm10
  movdqa  xmm3, xmm2
  pslld   xmm2, 9
  psrld   xmm3, 23
  por     xmm2, xmm3
  db $66, $44, $0F, $EF, $C2                           // pxor xmm8, xmm2
  db $66, $41, $0F, $6F, $F4                           // movdqa xmm6, xmm12
  db $66, $41, $0F, $FE, $F7                           // paddd xmm6, xmm15
  movdqa  xmm7, xmm6
  pslld   xmm6, 9
  psrld   xmm7, 23
  por     xmm6, xmm7
  db $66, $44, $0F, $EF, $EE                           // pxor xmm13, xmm6
  db $66, $41, $0F, $6F, $D0                           // movdqa xmm2, xmm8
  db $66, $41, $0F, $FE, $D3                           // paddd xmm2, xmm11
  movdqa  xmm3, xmm2
  pslld   xmm2, 13
  psrld   xmm3, 19
  por     xmm2, xmm3
  db $66, $44, $0F, $EF, $CA                           // pxor xmm9, xmm2
  db $66, $41, $0F, $6F, $F5                           // movdqa xmm6, xmm13
  db $66, $41, $0F, $FE, $F4                           // paddd xmm6, xmm12
  movdqa  xmm7, xmm6
  pslld   xmm6, 13
  psrld   xmm7, 19
  por     xmm6, xmm7
  db $66, $44, $0F, $EF, $F6                           // pxor xmm14, xmm6
  db $66, $41, $0F, $6F, $D1                           // movdqa xmm2, xmm9
  db $66, $41, $0F, $FE, $D0                           // paddd xmm2, xmm8
  movdqa  xmm3, xmm2
  pslld   xmm2, 18
  psrld   xmm3, 14
  por     xmm2, xmm3
  db $66, $44, $0F, $EF, $D2                           // pxor xmm10, xmm2
  db $66, $41, $0F, $6F, $F6                           // movdqa xmm6, xmm14
  db $66, $41, $0F, $FE, $F5                           // paddd xmm6, xmm13
  movdqa  xmm7, xmm6
  pslld   xmm6, 18
  psrld   xmm7, 14
  por     xmm6, xmm7
  db $66, $44, $0F, $EF, $FE                           // pxor xmm15, xmm6
  sub     eax, 2
  jg      @@salsa_sse2_4x_round
  add     dword ptr [rdx + 32], 4
  adc     dword ptr [rdx + 36], 0
  db $66, $44, $0F, $FE, $84, $24, $C0, $00, $00, $00  // paddd xmm8, [rsp + 192]
  db $66, $44, $0F, $FE, $8C, $24, $D0, $00, $00, $00  // paddd xmm9, [rsp + 208]
  db $66, $44, $0F, $FE, $94, $24, $E0, $00, $00, $00  // paddd xmm10, [rsp + 224]
  db $66, $44, $0F, $FE, $9C, $24, $F0, $00, $00, $00  // paddd xmm11, [rsp + 240]
  db $66, $41, $0F, $6F, $D0                           // movdqa xmm2, xmm8
  db $66, $45, $0F, $62, $C1                           // punpckldq xmm8, xmm9
  db $66, $41, $0F, $6A, $D1                           // punpckhdq xmm2, xmm9
  db $66, $41, $0F, $6F, $DA                           // movdqa xmm3, xmm10
  db $66, $45, $0F, $62, $D3                           // punpckldq xmm10, xmm11
  db $66, $41, $0F, $6A, $DB                           // punpckhdq xmm3, xmm11
  db $66, $45, $0F, $6F, $C8                           // movdqa xmm9, xmm8
  db $66, $45, $0F, $6C, $C2                           // punpcklqdq xmm8, xmm10
  db $66, $45, $0F, $6D, $CA                           // punpckhqdq xmm9, xmm10
  db $66, $44, $0F, $6F, $DA                           // movdqa xmm11, xmm2
  db $66, $0F, $6C, $D3                                // punpcklqdq xmm2, xmm3
  db $66, $44, $0F, $6D, $DB                           // punpckhqdq xmm11, xmm3
  movdqu  xmm10, [r8 + 32]
  db $66, $45, $0F, $EF, $C2                           // pxor xmm8, xmm10
  movdqu  [r9 + 32], xmm8
  movdqu  xmm10, [r8 + 96]
  db $66, $45, $0F, $EF, $CA                           // pxor xmm9, xmm10
  movdqu  [r9 + 96], xmm9
  movdqu  xmm10, [r8 + 160]
  db $66, $41, $0F, $EF, $D2                           // pxor xmm2, xmm10
  movdqu  [r9 + 160], xmm2
  movdqu  xmm10, [r8 + 224]
  db $66, $45, $0F, $EF, $DA                           // pxor xmm11, xmm10
  movdqu  [r9 + 224], xmm11
  db $66, $44, $0F, $FE, $A4, $24, $00, $01, $00, $00  // paddd xmm12, [rsp + 256]
  db $66, $44, $0F, $FE, $AC, $24, $10, $01, $00, $00  // paddd xmm13, [rsp + 272]
  db $66, $44, $0F, $FE, $B4, $24, $20, $01, $00, $00  // paddd xmm14, [rsp + 288]
  db $66, $44, $0F, $FE, $BC, $24, $30, $01, $00, $00  // paddd xmm15, [rsp + 304]
  db $66, $45, $0F, $6F, $D4                           // movdqa xmm10, xmm12
  db $66, $45, $0F, $62, $E5                           // punpckldq xmm12, xmm13
  db $66, $45, $0F, $6A, $D5                           // punpckhdq xmm10, xmm13
  db $66, $41, $0F, $6F, $DE                           // movdqa xmm3, xmm14
  db $66, $45, $0F, $62, $F7                           // punpckldq xmm14, xmm15
  db $66, $41, $0F, $6A, $DF                           // punpckhdq xmm3, xmm15
  db $66, $45, $0F, $6F, $EC                           // movdqa xmm13, xmm12
  db $66, $45, $0F, $6C, $E6                           // punpcklqdq xmm12, xmm14
  db $66, $45, $0F, $6D, $EE                           // punpckhqdq xmm13, xmm14
  db $66, $45, $0F, $6F, $FA                           // movdqa xmm15, xmm10
  db $66, $44, $0F, $6C, $D3                           // punpcklqdq xmm10, xmm3
  db $66, $44, $0F, $6D, $FB                           // punpckhqdq xmm15, xmm3
  movdqu  xmm14, [r8 + 48]
  db $66, $45, $0F, $EF, $E6                           // pxor xmm12, xmm14
  movdqu  [r9 + 48], xmm12
  movdqu  xmm14, [r8 + 112]
  db $66, $45, $0F, $EF, $EE                           // pxor xmm13, xmm14
  movdqu  [r9 + 112], xmm13
  movdqu  xmm14, [r8 + 176]
  db $66, $45, $0F, $EF, $D6                           // pxor xmm10, xmm14
  movdqu  [r9 + 176], xmm10
  movdqu  xmm14, [r8 + 240]
  db $66, $45, $0F, $EF, $FE                           // pxor xmm15, xmm14
  movdqu  [r9 + 240], xmm15
  movdqa  xmm2, [rsp]
  movdqa  xmm3, [rsp + 16]
  db $66, $0F, $FE, $44, $24, $40                      // paddd xmm0, [rsp + 64]
  db $66, $0F, $FE, $4C, $24, $50                      // paddd xmm1, [rsp + 80]
  db $66, $0F, $FE, $54, $24, $60                      // paddd xmm2, [rsp + 96]
  db $66, $0F, $FE, $5C, $24, $70                      // paddd xmm3, [rsp + 112]
  movdqa  xmm6, xmm0
  db $66, $0F, $62, $C1                                // punpckldq xmm0, xmm1
  db $66, $0F, $6A, $F1                                // punpckhdq xmm6, xmm1
  movdqa  xmm7, xmm2
  db $66, $0F, $62, $D3                                // punpckldq xmm2, xmm3
  db $66, $0F, $6A, $FB                                // punpckhdq xmm7, xmm3
  movdqa  xmm1, xmm0
  db $66, $0F, $6C, $C2                                // punpcklqdq xmm0, xmm2
  db $66, $0F, $6D, $CA                                // punpckhqdq xmm1, xmm2
  movdqa  xmm3, xmm6
  db $66, $0F, $6C, $F7                                // punpcklqdq xmm6, xmm7
  db $66, $0F, $6D, $DF                                // punpckhqdq xmm3, xmm7
  movdqu  xmm2, [r8]
  pxor    xmm0, xmm2
  movdqu  [r9], xmm0
  movdqu  xmm2, [r8 + 64]
  pxor    xmm1, xmm2
  movdqu  [r9 + 64], xmm1
  movdqu  xmm2, [r8 + 128]
  pxor    xmm6, xmm2
  movdqu  [r9 + 128], xmm6
  movdqu  xmm2, [r8 + 192]
  pxor    xmm3, xmm2
  movdqu  [r9 + 192], xmm3
  movdqa  xmm8, [rsp + 32]
  movdqa  xmm9, [rsp + 48]
  db $66, $0F, $FE, $A4, $24, $80, $00, $00, $00       // paddd xmm4, [rsp + 128]
  db $66, $0F, $FE, $AC, $24, $90, $00, $00, $00       // paddd xmm5, [rsp + 144]
  db $66, $44, $0F, $FE, $84, $24, $A0, $00, $00, $00  // paddd xmm8, [rsp + 160]
  db $66, $44, $0F, $FE, $8C, $24, $B0, $00, $00, $00  // paddd xmm9, [rsp + 176]
  movdqa  xmm2, xmm4
  db $66, $0F, $62, $E5                                // punpckldq xmm4, xmm5
  db $66, $0F, $6A, $D5                                // punpckhdq xmm2, xmm5
  db $66, $41, $0F, $6F, $F8                           // movdqa xmm7, xmm8
  db $66, $45, $0F, $62, $C1                           // punpckldq xmm8, xmm9
  db $66, $41, $0F, $6A, $F9                           // punpckhdq xmm7, xmm9
  movdqa  xmm5, xmm4
  db $66, $41, $0F, $6C, $E0                           // punpcklqdq xmm4, xmm8
  db $66, $41, $0F, $6D, $E8                           // punpckhqdq xmm5, xmm8
  db $66, $44, $0F, $6F, $CA                           // movdqa xmm9, xmm2
  db $66, $0F, $6C, $D7                                // punpcklqdq xmm2, xmm7
  db $66, $44, $0F, $6D, $CF                           // punpckhqdq xmm9, xmm7
  movdqu  xmm8, [r8 + 16]
  db $66, $41, $0F, $EF, $E0                           // pxor xmm4, xmm8
  movdqu  [r9 + 16], xmm4
  movdqu  xmm8, [r8 + 80]
  db $66, $41, $0F, $EF, $E8                           // pxor xmm5, xmm8
  movdqu  [r9 + 80], xmm5
  movdqu  xmm8, [r8 + 144]
  db $66, $41, $0F, $EF, $D0                           // pxor xmm2, xmm8
  movdqu  [r9 + 144], xmm2
  movdqu  xmm8, [r8 + 208]
  db $66, $45, $0F, $EF, $C8                           // pxor xmm9, xmm8
  movdqu  [r9 + 208], xmm9
  add     r8, 256
  add     r9, 256
  dec     r10
  jnz     @@salsa_sse2_4x_outer
  mov     rsp, r11
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}

