// ChaCha7539 (IETF) AVX2: after rounds, add back initial state from [esp] scratch, vperm2f128, then fused I/O xor, i386.
// Fused I/O xor: plaintext at EDI, ciphertext at EAX (encrypt; in-place if AIn=AOut). Offsets 0..0x7F.
  db $C5, $FE, $6F, $24, $24       // vmovdqu ymm4, ymmword ptr [esp]
  db $C5, $FD, $FE, $C4            // vpaddd ymm0, ymm0, ymm4
  db $C5, $FE, $6F, $64, $24, $20  // vmovdqu ymm4, ymmword ptr [esp + 0x20]
  db $C5, $F5, $FE, $CC            // vpaddd ymm1, ymm1, ymm4
  db $C5, $FE, $6F, $64, $24, $40  // vmovdqu ymm4, ymmword ptr [esp + 0x40]
  db $C5, $ED, $FE, $D4            // vpaddd ymm2, ymm2, ymm4
  db $C5, $FE, $6F, $64, $24, $60  // vmovdqu ymm4, ymmword ptr [esp + 0x60]
  db $C5, $E5, $FE, $DC            // vpaddd ymm3, ymm3, ymm4
  db $C4, $E3, $7D, $06, $E1, $20  // vperm2f128 ymm4, ymm0, ymm1, 0x20
  db $C5, $FE, $6F, $2F            // vmovdqu ymm5, ymmword ptr [edi]
  db $C5, $DD, $EF, $E5            // vpxor ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $20            // vmovdqu ymmword ptr [eax], ymm4
  db $C4, $E3, $6D, $06, $E3, $20  // vperm2f128 ymm4, ymm2, ymm3, 0x20
  db $C5, $FE, $6F, $6F, $20       // vmovdqu ymm5, ymmword ptr [edi + 0x20]
  db $C5, $DD, $EF, $E5            // vpxor ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $60, $20       // vmovdqu ymmword ptr [eax + 0x20], ymm4
  db $C4, $E3, $7D, $06, $E1, $31  // vperm2f128 ymm4, ymm0, ymm1, 0x31
  db $C5, $FE, $6F, $6F, $40       // vmovdqu ymm5, ymmword ptr [edi + 0x40]
  db $C5, $DD, $EF, $E5            // vpxor ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $60, $40       // vmovdqu ymmword ptr [eax + 0x40], ymm4
  db $C4, $E3, $6D, $06, $E3, $31  // vperm2f128 ymm4, ymm2, ymm3, 0x31
  db $C5, $FE, $6F, $6F, $60       // vmovdqu ymm5, ymmword ptr [edi + 0x60]
  db $C5, $DD, $EF, $E5            // vpxor ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $60, $60       // vmovdqu ymmword ptr [eax + 0x60], ymm4
