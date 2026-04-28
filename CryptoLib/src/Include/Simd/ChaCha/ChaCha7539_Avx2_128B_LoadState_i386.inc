// ChaCha7539 (IETF) AVX2: 128B block prologue, i386. Fused I/O xor path: full keystream is not written to a Pascal temp; XorStore .inc xors in asm.
// sub esp,0xC8; state from ESI; bump IETF word-12 counter twice; save YMM scratch to [esp].
// Parent must set edx := ebx (ARounds) before this include, once per 128B block (ProcessBlocks2 and each half of ProcessBlocks4).
  db $81, $EC, $C8, $00, $00, $00  // sub esp, 0xc8
  db $C5, $FA, $6F, $26            // vmovdqu xmm4, xmmword ptr [esi]
  db $C5, $FC, $57, $C0            // vxorps ymm0, ymm0, ymm0
  db $C4, $E3, $7D, $18, $C4, $00  // vinsertf128 ymm0, ymm0, xmm4, 0
  db $C4, $E3, $7D, $18, $C4, $01  // vinsertf128 ymm0, ymm0, xmm4, 1
  db $C5, $FA, $6F, $66, $10       // vmovdqu xmm4, xmmword ptr [esi + 0x10]
  db $C5, $F4, $57, $C9            // vxorps ymm1, ymm1, ymm1
  db $C4, $E3, $75, $18, $CC, $00  // vinsertf128 ymm1, ymm1, xmm4, 0
  db $C4, $E3, $75, $18, $CC, $01  // vinsertf128 ymm1, ymm1, xmm4, 1
  db $C5, $FA, $6F, $66, $20       // vmovdqu xmm4, xmmword ptr [esi + 0x20]
  db $C5, $EC, $57, $D2            // vxorps ymm2, ymm2, ymm2
  db $C4, $E3, $6D, $18, $D4, $00  // vinsertf128 ymm2, ymm2, xmm4, 0
  db $C4, $E3, $6D, $18, $D4, $01  // vinsertf128 ymm2, ymm2, xmm4, 1
  db $C5, $FA, $6F, $66, $30       // vmovdqu xmm4, xmmword ptr [esi + 0x30]
  db $83, $46, $30, $01            // add dword ptr [esi + 0x30], 1
  db $C5, $FA, $6F, $6E, $30       // vmovdqu xmm5, xmmword ptr [esi + 0x30]
  db $83, $46, $30, $01            // add dword ptr [esi + 0x30], 1
  db $C5, $E4, $57, $DB            // vxorps ymm3, ymm3, ymm3
  db $C4, $E3, $65, $18, $DC, $00  // vinsertf128 ymm3, ymm3, xmm4, 0
  db $C4, $E3, $65, $18, $DD, $01  // vinsertf128 ymm3, ymm3, xmm5, 1
  db $C5, $FE, $7F, $04, $24       // vmovdqu ymmword ptr [esp], ymm0
  db $C5, $FE, $7F, $4C, $24, $20  // vmovdqu ymmword ptr [esp + 0x20], ymm1
  db $C5, $FE, $7F, $54, $24, $40  // vmovdqu ymmword ptr [esp + 0x40], ymm2
  db $C5, $FE, $7F, $5C, $24, $60  // vmovdqu ymmword ptr [esp + 0x60], ymm3
