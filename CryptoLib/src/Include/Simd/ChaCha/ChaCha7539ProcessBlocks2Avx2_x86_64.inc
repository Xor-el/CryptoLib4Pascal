// ChaCha7539 IETF, 128B out, two 32-bit counters in YMM lanes, AVX2. LE state, IOxor.
// After SimdProc4Begin_x86_64.inc: rcx=ARounds, rdx=AState (R/W, 16 UInt32), r8=AIn, r9=AOut.
// VEX/AVX/AVX2 instructions are db-encoded for broad assembler compatibility.

  db $49, $89, $CA                      // mov r10, rcx
  db $48, $81, $EC, $C8, $00, $00, $00  // sub rsp, 0xc8
  db $C5, $FA, $6F, $22                 // vmovdqu xmm4, xmmword ptr [rdx]
  db $C5, $FC, $57, $C0                 // vxorps ymm0, ymm0, ymm0
  db $C4, $E3, $7D, $18, $C4, $00       // vinsertf128 ymm0, ymm0, xmm4, 0
  db $C4, $E3, $7D, $18, $C4, $01       // vinsertf128 ymm0, ymm0, xmm4, 1
  db $C5, $FA, $6F, $62, $10            // vmovdqu xmm4, xmmword ptr [rdx + 0x10]
  db $C5, $F4, $57, $C9                 // vxorps ymm1, ymm1, ymm1
  db $C4, $E3, $75, $18, $CC, $00       // vinsertf128 ymm1, ymm1, xmm4, 0
  db $C4, $E3, $75, $18, $CC, $01       // vinsertf128 ymm1, ymm1, xmm4, 1
  db $C5, $FA, $6F, $62, $20            // vmovdqu xmm4, xmmword ptr [rdx + 0x20]
  db $C5, $EC, $57, $D2                 // vxorps ymm2, ymm2, ymm2
  db $C4, $E3, $6D, $18, $D4, $00       // vinsertf128 ymm2, ymm2, xmm4, 0
  db $C4, $E3, $6D, $18, $D4, $01       // vinsertf128 ymm2, ymm2, xmm4, 1
  db $C5, $FA, $6F, $62, $30            // vmovdqu xmm4, xmmword ptr [rdx + 0x30]
  db $83, $42, $30, $01                 // add dword ptr [rdx + 0x30], 1
  db $C5, $FA, $6F, $6A, $30            // vmovdqu xmm5, xmmword ptr [rdx + 0x30]
  db $83, $42, $30, $01                 // add dword ptr [rdx + 0x30], 1
  db $C5, $E4, $57, $DB                 // vxorps ymm3, ymm3, ymm3
  db $C4, $E3, $65, $18, $DC, $00       // vinsertf128 ymm3, ymm3, xmm4, 0
  db $C4, $E3, $65, $18, $DD, $01       // vinsertf128 ymm3, ymm3, xmm5, 1
  db $C5, $FE, $7F, $04, $24            // vmovdqu ymmword ptr [rsp], ymm0
  db $C5, $FE, $7F, $4C, $24, $20       // vmovdqu ymmword ptr [rsp + 0x20], ymm1
  db $C5, $FE, $7F, $54, $24, $40       // vmovdqu ymmword ptr [rsp + 0x40], ymm2
  db $C5, $FE, $7F, $5C, $24, $60       // vmovdqu ymmword ptr [rsp + 0x60], ymm3
  @@chacha7539_avx2_dround:
  db $C5, $FD, $FE, $C1                 // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                 // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $6F, $E3                 // vmovdqa ymm4, ymm3
  db $C5, $E5, $72, $D3, $10            // vpsrld ymm3, ymm3, 0x10
  db $C5, $DD, $72, $F4, $10            // vpslld ymm4, ymm4, 0x10
  db $C5, $E5, $EB, $DC                 // vpor ymm3, ymm3, ymm4
  db $C5, $ED, $FE, $D3                 // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                 // vpxor ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $E1                 // vmovdqa ymm4, ymm1
  db $C5, $F5, $72, $D1, $14            // vpsrld ymm1, ymm1, 0x14
  db $C5, $DD, $72, $F4, $0C            // vpslld ymm4, ymm4, 0xc
  db $C5, $F5, $EB, $CC                 // vpor ymm1, ymm1, ymm4
  db $C5, $FD, $FE, $C1                 // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                 // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $6F, $E3                 // vmovdqa ymm4, ymm3
  db $C5, $E5, $72, $D3, $18            // vpsrld ymm3, ymm3, 0x18
  db $C5, $DD, $72, $F4, $08            // vpslld ymm4, ymm4, 8
  db $C5, $E5, $EB, $DC                 // vpor ymm3, ymm3, ymm4
  db $C5, $ED, $FE, $D3                 // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                 // vpxor ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $E1                 // vmovdqa ymm4, ymm1
  db $C5, $F5, $72, $D1, $19            // vpsrld ymm1, ymm1, 0x19
  db $C5, $DD, $72, $F4, $07            // vpslld ymm4, ymm4, 7
  db $C5, $F5, $EB, $CC                 // vpor ymm1, ymm1, ymm4
  db $C5, $FD, $70, $C9, $39            // vpshufd ymm1, ymm1, 0x39
  db $C5, $FD, $70, $D2, $4E            // vpshufd ymm2, ymm2, 0x4e
  db $C5, $FD, $70, $DB, $93            // vpshufd ymm3, ymm3, 0x93
  db $C5, $FD, $FE, $C1                 // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                 // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $6F, $E3                 // vmovdqa ymm4, ymm3
  db $C5, $E5, $72, $D3, $10            // vpsrld ymm3, ymm3, 0x10
  db $C5, $DD, $72, $F4, $10            // vpslld ymm4, ymm4, 0x10
  db $C5, $E5, $EB, $DC                 // vpor ymm3, ymm3, ymm4
  db $C5, $ED, $FE, $D3                 // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                 // vpxor ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $E1                 // vmovdqa ymm4, ymm1
  db $C5, $F5, $72, $D1, $14            // vpsrld ymm1, ymm1, 0x14
  db $C5, $DD, $72, $F4, $0C            // vpslld ymm4, ymm4, 0xc
  db $C5, $F5, $EB, $CC                 // vpor ymm1, ymm1, ymm4
  db $C5, $FD, $FE, $C1                 // vpaddd ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8                 // vpxor ymm3, ymm3, ymm0
  db $C5, $FD, $6F, $E3                 // vmovdqa ymm4, ymm3
  db $C5, $E5, $72, $D3, $18            // vpsrld ymm3, ymm3, 0x18
  db $C5, $DD, $72, $F4, $08            // vpslld ymm4, ymm4, 8
  db $C5, $E5, $EB, $DC                 // vpor ymm3, ymm3, ymm4
  db $C5, $ED, $FE, $D3                 // vpaddd ymm2, ymm2, ymm3
  db $C5, $F5, $EF, $CA                 // vpxor ymm1, ymm1, ymm2
  db $C5, $FD, $6F, $E1                 // vmovdqa ymm4, ymm1
  db $C5, $F5, $72, $D1, $19            // vpsrld ymm1, ymm1, 0x19
  db $C5, $DD, $72, $F4, $07            // vpslld ymm4, ymm4, 7
  db $C5, $F5, $EB, $CC                 // vpor ymm1, ymm1, ymm4
  db $C5, $FD, $70, $C9, $93            // vpshufd ymm1, ymm1, 0x93
  db $C5, $FD, $70, $D2, $4E            // vpshufd ymm2, ymm2, 0x4e
  db $C5, $FD, $70, $DB, $39            // vpshufd ymm3, ymm3, 0x39
  db $49, $83, $EA, $02                 // sub r10, 2
  db $0F, $8F, $08, $FF, $FF, $FF       // jg 0x81
  db $C5, $FE, $6F, $24, $24            // vmovdqu ymm4, ymmword ptr [rsp]
  db $C5, $FD, $FE, $C4                 // vpaddd ymm0, ymm0, ymm4
  db $C5, $FE, $6F, $64, $24, $20       // vmovdqu ymm4, ymmword ptr [rsp + 0x20]
  db $C5, $F5, $FE, $CC                 // vpaddd ymm1, ymm1, ymm4
  db $C5, $FE, $6F, $64, $24, $40       // vmovdqu ymm4, ymmword ptr [rsp + 0x40]
  db $C5, $ED, $FE, $D4                 // vpaddd ymm2, ymm2, ymm4
  db $C5, $FE, $6F, $64, $24, $60       // vmovdqu ymm4, ymmword ptr [rsp + 0x60]
  db $C5, $E5, $FE, $DC                 // vpaddd ymm3, ymm3, ymm4
  db $C4, $E3, $7D, $06, $E1, $20       // vperm2f128 ymm4, ymm0, ymm1, 0x20
  db $C4, $C1, $7E, $6F, $28            // vmovdqu ymm5, ymmword ptr [r8]
  db $C5, $DD, $EF, $E5                 // vpxor ymm4, ymm4, ymm5
  db $C4, $C1, $7E, $7F, $21            // vmovdqu ymmword ptr [r9], ymm4
  db $C4, $E3, $6D, $06, $E3, $20       // vperm2f128 ymm4, ymm2, ymm3, 0x20
  db $C4, $C1, $7E, $6F, $68, $20       // vmovdqu ymm5, ymmword ptr [r8 + 0x20]
  db $C5, $DD, $EF, $E5                 // vpxor ymm4, ymm4, ymm5
  db $C4, $C1, $7E, $7F, $61, $20       // vmovdqu ymmword ptr [r9 + 0x20], ymm4
  db $C4, $E3, $7D, $06, $E1, $31       // vperm2f128 ymm4, ymm0, ymm1, 0x31
  db $C4, $C1, $7E, $6F, $68, $40       // vmovdqu ymm5, ymmword ptr [r8 + 0x40]
  db $C5, $DD, $EF, $E5                 // vpxor ymm4, ymm4, ymm5
  db $C4, $C1, $7E, $7F, $61, $40       // vmovdqu ymmword ptr [r9 + 0x40], ymm4
  db $C4, $E3, $6D, $06, $E3, $31       // vperm2f128 ymm4, ymm2, ymm3, 0x31
  db $C4, $C1, $7E, $6F, $68, $60       // vmovdqu ymm5, ymmword ptr [r8 + 0x60]
  db $C5, $DD, $EF, $E5                 // vpxor ymm4, ymm4, ymm5
  db $C4, $C1, $7E, $7F, $61, $60       // vmovdqu ymmword ptr [r9 + 0x60], ymm4
  db $48, $81, $C4, $C8, $00, $00, $00  // add rsp, 0xc8
  db $C5, $F8, $77                      // vzeroupper
