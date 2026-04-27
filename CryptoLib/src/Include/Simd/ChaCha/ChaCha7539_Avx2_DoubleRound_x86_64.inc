// ChaCha7539 (IETF) AVX2: one "double round" in two 32-lane YMMs (4 quarter-rounds). VEX db-encoded; parent supplies: sub r10,2; jg loop.
// ARX only — no fused I/O xor here (that is XorStore .inc after the round loop). ChaCha20 in this tree uses SSE2, not this VEX include.
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
