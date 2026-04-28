// Poly1305 4-way AVX2 bulk MAC kernel (i386).
// -------------------------------------------------------------------
// Algorithm: Goll-Gueron 2015 / Polyakov OpenSSL `poly1305_blocks_avx2`.
// Sibling of the x86-64 kernel; same 4-way design, same precomputed
// r^1..r^4 power table consumed at row offset (broadcast r^4 in the
// bulk loop) and row offset+4 (shifted [r^1,r^2,r^3,r^4] in the tail
// iteration). The Pascal dispatcher rounds the SIMD count down to a
// multiple of 4 and forwards 0..3 leftover blocks to the scalar path.
//
// VEX-encoded AVX2 instructions are db-encoded for broad assembler compatibility.
// Each db line carries a mnemonic comment. The encoding uses ymm0..ymm7 only
// (i386 has no ymm8..ymm15) so all VEX prefixes are 2-byte / 3-byte
// without REX.{R,X,B}; the bytes of the inner kernel are therefore
// identical to the equivalent ymm0..ymm7 sequences in the x86-64
// sibling - only the base register names change to match the i386
// argument map.
//
// On entry (after SimdProc5Begin_i386.inc):
//   ebx = ACtx       (PTPoly1305State; 72-byte R/S/H/K record)
//   esi = APowTable  (PByte; 320-byte 10x8 power table; layout below)
//   edi = AInp       (PByte)
//   eax = ALen       (NativeUInt; multiple of 64; >= 64)
//   ecx = APad       (always 1; ignored - padbit unconditional in bulk)
//
// TPoly1305State byte offsets (no SIMD member):
//   R0..R4   :   0..16     (5 dwords)
//   S1..S4   :  20..32     (4 dwords)
//   H0..H4   :  36..52     (5 dwords)   <- loaded into ymm0..ymm4 lane 0
//   K0..K3   :  56..68     (4 dwords; not read by this kernel)
//
// Power-table byte offsets (separate 320-byte buffer; esi-based loads):
//   row j at [esi + 32*j]; bulk loop reads at row offset (broadcast
//   r^4), tail iteration reads at row offset+4 (shifted [r^4,r^3,r^2,r^1]).
//   Row 0..4 = r-limbs 0..4; row 5..8 = s-limbs 1..4 (s = 5*r); row 9 pad.
//
// Register allocation (uses ymm0..ymm7 only):
//   ymm0..ymm4 : H0..H4         (4-lane radix-2^26 accumulator)
//   ymm5       : mask26         (0x3FFFFFF per 64-bit lane low half)
//   ymm6       : padbit         (0x1000000 per 64-bit lane low half)
//   ymm7       : scratch (D0..D4 / M0..M4 transient via stack spills)
//
// Stack frame (320 bytes):
//   [esp +   0..159] = D0..D4   (5 x 32 bytes; product accumulators)
//   [esp + 160..319] = H backup (5 x 32 bytes; spilled while loading M)

  sub        esp, 320

  // ---- Prologue: build mask26 (ymm5) and padbit (ymm6) constants ----
  db $C5, $D5, $76, $ED                             // vpcmpeqd ymm5, ymm5, ymm5
  db $C5, $D5, $73, $D5, $26                        // vpsrlq ymm5, ymm5, 38     ; mask26
  db $C5, $CD, $76, $F6                             // vpcmpeqd ymm6, ymm6, ymm6
  db $C5, $CD, $73, $D6, $3F                        // vpsrlq ymm6, ymm6, 63
  db $C5, $CD, $73, $F6, $18                        // vpsllq ymm6, ymm6, 24     ; padbit = 1<<24

  // ---- Load h0..h4 from ctx into lane 0 of ymm0..ymm4 ----
  db $C5, $F9, $6E, $43, $24                        // vmovd xmm0, dword ptr [ebx + 36]   ; H0
  db $C5, $F9, $6E, $4B, $28                        // vmovd xmm1, dword ptr [ebx + 40]   ; H1
  db $C5, $F9, $6E, $53, $2C                        // vmovd xmm2, dword ptr [ebx + 44]   ; H2
  db $C5, $F9, $6E, $5B, $30                        // vmovd xmm3, dword ptr [ebx + 48]   ; H3
  db $C5, $F9, $6E, $63, $34                        // vmovd xmm4, dword ptr [ebx + 52]   ; H4

  // ---- Pre-loop: spill H, load+decompress 4 blocks, absorb H back ----
  db $C5, $FE, $7F, $84, $24, $A0, $00, $00, $00    // vmovdqu ymmword ptr [esp + 160], ymm0
  db $C5, $FE, $7F, $8C, $24, $C0, $00, $00, $00    // vmovdqu ymmword ptr [esp + 192], ymm1
  db $C5, $FE, $7F, $94, $24, $E0, $00, $00, $00    // vmovdqu ymmword ptr [esp + 224], ymm2
  db $C5, $FE, $7F, $9C, $24, $00, $01, $00, $00    // vmovdqu ymmword ptr [esp + 256], ymm3
  db $C5, $FE, $7F, $A4, $24, $20, $01, $00, $00    // vmovdqu ymmword ptr [esp + 288], ymm4

  db $C5, $FA, $6F, $07                             // vmovdqu xmm0, xmmword ptr [edi]
  db $C5, $FA, $6F, $4F, $10                        // vmovdqu xmm1, xmmword ptr [edi + 16]
  db $C4, $E3, $7D, $38, $47, $20, $01              // vinserti128 ymm0, ymm0, xmmword ptr [edi + 32], 1
  db $C4, $E3, $75, $38, $4F, $30, $01              // vinserti128 ymm1, ymm1, xmmword ptr [edi + 48], 1
  add        edi, 64

  // Decompress 4 blocks into limbs M0..M4 (ymm0, ymm1, ymm2, ymm3, ymm4)
  db $C5, $ED, $73, $D8, $06                        // vpsrldq ymm2, ymm0, 6
  db $C5, $E5, $73, $D9, $06                        // vpsrldq ymm3, ymm1, 6
  db $C5, $FD, $6D, $E1                             // vpunpckhqdq ymm4, ymm0, ymm1   ; T4 (high 64)
  db $C5, $FD, $6C, $C1                             // vpunpcklqdq ymm0, ymm0, ymm1   ; T0 (low 64)
  db $C5, $ED, $6C, $D3                             // vpunpcklqdq ymm2, ymm2, ymm3   ; T2 (limbs 2/3)
  db $C5, $E5, $73, $D2, $1E                        // vpsrlq ymm3, ymm2, 30          ; limb3 raw
  db $C5, $ED, $73, $D2, $04                        // vpsrlq ymm2, ymm2, 4           ; limb2 raw
  db $C5, $F5, $73, $D0, $1A                        // vpsrlq ymm1, ymm0, 26          ; limb1 raw
  db $C5, $DD, $73, $D4, $28                        // vpsrlq ymm4, ymm4, 40          ; limb4 raw
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5         ; M0
  db $C5, $F5, $DB, $CD                             // vpand ymm1, ymm1, ymm5         ; M1
  db $C5, $ED, $DB, $D5                             // vpand ymm2, ymm2, ymm5         ; M2
  db $C5, $E5, $DB, $DD                             // vpand ymm3, ymm3, ymm5         ; M3
  db $C5, $DD, $EB, $E6                             // vpor ymm4, ymm4, ymm6          ; M4 |= padbit

  // Absorb: H += M (H reload from stack since it was spilled)
  db $C5, $FD, $D4, $84, $24, $A0, $00, $00, $00    // vpaddq ymm0, ymm0, ymmword ptr [esp + 160]
  db $C5, $F5, $D4, $8C, $24, $C0, $00, $00, $00    // vpaddq ymm1, ymm1, ymmword ptr [esp + 192]
  db $C5, $ED, $D4, $94, $24, $E0, $00, $00, $00    // vpaddq ymm2, ymm2, ymmword ptr [esp + 224]
  db $C5, $E5, $D4, $9C, $24, $00, $01, $00, $00    // vpaddq ymm3, ymm3, ymmword ptr [esp + 256]
  db $C5, $DD, $D4, $A4, $24, $20, $01, $00, $00    // vpaddq ymm4, ymm4, ymmword ptr [esp + 288]

  sub        eax, 64
  jz         @@poly1305_avx2_i386_tail

@@poly1305_avx2_i386_loop:
  // ---- Bulk multiply: H *= r^4  (broadcast row form, base offset +0) ----
  // D4 spilled at [esp + 128]
  db $C5, $FD, $F4, $BE, $80, $00, $00, $00         // vpmuludq ymm7, ymm0, ymmword ptr [esi + 128]   ; H0 * R4
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $F5, $F4, $BE, $60, $00, $00, $00         // vpmuludq ymm7, ymm1, ymmword ptr [esi + 96]    ; H1 * R3
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $ED, $F4, $BE, $40, $00, $00, $00         // vpmuludq ymm7, ymm2, ymmword ptr [esi + 64]    ; H2 * R2
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $E5, $F4, $7E, $20                        // vpmuludq ymm7, ymm3, ymmword ptr [esi + 32]    ; H3 * R1
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $DD, $F4, $7E, $00                        // vpmuludq ymm7, ymm4, ymmword ptr [esi]         ; H4 * R0
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7

  // D3 spilled at [esp + 96]
  db $C5, $FD, $F4, $BE, $60, $00, $00, $00         // vpmuludq ymm7, ymm0, ymmword ptr [esi + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $F5, $F4, $BE, $40, $00, $00, $00         // vpmuludq ymm7, ymm1, ymmword ptr [esi + 64]
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $ED, $F4, $7E, $20                        // vpmuludq ymm7, ymm2, ymmword ptr [esi + 32]
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $E5, $F4, $7E, $00                        // vpmuludq ymm7, ymm3, ymmword ptr [esi]
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $DD, $F4, $BE, $00, $01, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 256]   ; S4
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7

  // D2 spilled at [esp + 64]
  db $C5, $FD, $F4, $BE, $40, $00, $00, $00         // vpmuludq ymm7, ymm0, ymmword ptr [esi + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $F5, $F4, $7E, $20                        // vpmuludq ymm7, ymm1, ymmword ptr [esi + 32]
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $ED, $F4, $7E, $00                        // vpmuludq ymm7, ymm2, ymmword ptr [esi]
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $E5, $F4, $BE, $00, $01, $00, $00         // vpmuludq ymm7, ymm3, ymmword ptr [esi + 256]
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $DD, $F4, $BE, $E0, $00, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 224]   ; S3
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7

  // D1 spilled at [esp + 32]
  db $C5, $FD, $F4, $7E, $20                        // vpmuludq ymm7, ymm0, ymmword ptr [esi + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $F5, $F4, $7E, $00                        // vpmuludq ymm7, ymm1, ymmword ptr [esi]
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $ED, $F4, $BE, $00, $01, $00, $00         // vpmuludq ymm7, ymm2, ymmword ptr [esi + 256]
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $E5, $F4, $BE, $E0, $00, $00, $00         // vpmuludq ymm7, ymm3, ymmword ptr [esi + 224]
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $DD, $F4, $BE, $C0, $00, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 192]   ; S2
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7

  // D0 spilled at [esp + 0]
  db $C5, $FD, $F4, $7E, $00                        // vpmuludq ymm7, ymm0, ymmword ptr [esi]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $F5, $F4, $BE, $00, $01, $00, $00         // vpmuludq ymm7, ymm1, ymmword ptr [esi + 256]
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $ED, $F4, $BE, $E0, $00, $00, $00         // vpmuludq ymm7, ymm2, ymmword ptr [esi + 224]
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $E5, $F4, $BE, $C0, $00, $00, $00         // vpmuludq ymm7, ymm3, ymmword ptr [esi + 192]
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $DD, $F4, $BE, $A0, $00, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 160]   ; S1
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7

  // ---- Lazy reduce: D0..D4 (stack) -> H0..H4 (ymm0..ymm4) ----
  db $C5, $FE, $6F, $04, $24                        // vmovdqu ymm0, ymmword ptr [esp]
  db $C5, $FE, $6F, $4C, $24, $20                   // vmovdqu ymm1, ymmword ptr [esp + 32]
  db $C5, $FE, $6F, $54, $24, $40                   // vmovdqu ymm2, ymmword ptr [esp + 64]
  db $C5, $FE, $6F, $5C, $24, $60                   // vmovdqu ymm3, ymmword ptr [esp + 96]
  db $C5, $FE, $6F, $A4, $24, $80, $00, $00, $00    // vmovdqu ymm4, ymmword ptr [esp + 128]

  db $C5, $C5, $73, $D0, $1A                        // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $D1, $1A                        // vpsrlq ymm7, ymm1, 26
  db $C5, $F5, $DB, $CD                             // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $D4, $D7                             // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $D2, $1A                        // vpsrlq ymm7, ymm2, 26
  db $C5, $ED, $DB, $D5                             // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $D4, $DF                             // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $D3, $1A                        // vpsrlq ymm7, ymm3, 26
  db $C5, $E5, $DB, $DD                             // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $D4, $E7                             // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $D4, $1A                        // vpsrlq ymm7, ymm4, 26
  db $C5, $DD, $DB, $E5                             // vpand ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7   ; (D4>>26) backup
  db $C5, $C5, $73, $F7, $02                        // vpsllq ymm7, ymm7, 2
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]   ; *5
  db $C5, $FD, $D4, $C7                             // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D0, $1A                        // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7

  // ---- Spill H, load + decompress + absorb next 4 blocks ----
  db $C5, $FE, $7F, $84, $24, $A0, $00, $00, $00    // vmovdqu ymmword ptr [esp + 160], ymm0
  db $C5, $FE, $7F, $8C, $24, $C0, $00, $00, $00    // vmovdqu ymmword ptr [esp + 192], ymm1
  db $C5, $FE, $7F, $94, $24, $E0, $00, $00, $00    // vmovdqu ymmword ptr [esp + 224], ymm2
  db $C5, $FE, $7F, $9C, $24, $00, $01, $00, $00    // vmovdqu ymmword ptr [esp + 256], ymm3
  db $C5, $FE, $7F, $A4, $24, $20, $01, $00, $00    // vmovdqu ymmword ptr [esp + 288], ymm4

  db $C5, $FA, $6F, $07                             // vmovdqu xmm0, xmmword ptr [edi]
  db $C5, $FA, $6F, $4F, $10                        // vmovdqu xmm1, xmmword ptr [edi + 16]
  db $C4, $E3, $7D, $38, $47, $20, $01              // vinserti128 ymm0, ymm0, xmmword ptr [edi + 32], 1
  db $C4, $E3, $75, $38, $4F, $30, $01              // vinserti128 ymm1, ymm1, xmmword ptr [edi + 48], 1
  add        edi, 64

  db $C5, $ED, $73, $D8, $06                        // vpsrldq ymm2, ymm0, 6
  db $C5, $E5, $73, $D9, $06                        // vpsrldq ymm3, ymm1, 6
  db $C5, $FD, $6D, $E1                             // vpunpckhqdq ymm4, ymm0, ymm1
  db $C5, $FD, $6C, $C1                             // vpunpcklqdq ymm0, ymm0, ymm1
  db $C5, $ED, $6C, $D3                             // vpunpcklqdq ymm2, ymm2, ymm3
  db $C5, $E5, $73, $D2, $1E                        // vpsrlq ymm3, ymm2, 30
  db $C5, $ED, $73, $D2, $04                        // vpsrlq ymm2, ymm2, 4
  db $C5, $F5, $73, $D0, $1A                        // vpsrlq ymm1, ymm0, 26
  db $C5, $DD, $73, $D4, $28                        // vpsrlq ymm4, ymm4, 40
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $DB, $CD                             // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $DB, $D5                             // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $DB, $DD                             // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $EB, $E6                             // vpor ymm4, ymm4, ymm6

  db $C5, $FD, $D4, $84, $24, $A0, $00, $00, $00    // vpaddq ymm0, ymm0, ymmword ptr [esp + 160]
  db $C5, $F5, $D4, $8C, $24, $C0, $00, $00, $00    // vpaddq ymm1, ymm1, ymmword ptr [esp + 192]
  db $C5, $ED, $D4, $94, $24, $E0, $00, $00, $00    // vpaddq ymm2, ymm2, ymmword ptr [esp + 224]
  db $C5, $E5, $D4, $9C, $24, $00, $01, $00, $00    // vpaddq ymm3, ymm3, ymmword ptr [esp + 256]
  db $C5, $DD, $D4, $A4, $24, $20, $01, $00, $00    // vpaddq ymm4, ymm4, ymmword ptr [esp + 288]

  sub        eax, 64
  jnz        @@poly1305_avx2_i386_loop

@@poly1305_avx2_i386_tail:
  // ---- Tail: H *= [r^1, r^2, r^3, r^4]  (offset+4 = shifted form) ----
  // D4 spilled at [esp + 128] - table loads at +4 over the bulk offsets
  db $C5, $FD, $F4, $BE, $84, $00, $00, $00         // vpmuludq ymm7, ymm0, ymmword ptr [esi + 132]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $F5, $F4, $BE, $64, $00, $00, $00         // vpmuludq ymm7, ymm1, ymmword ptr [esi + 100]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $ED, $F4, $BE, $44, $00, $00, $00         // vpmuludq ymm7, ymm2, ymmword ptr [esi + 68]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $E5, $F4, $7E, $24                        // vpmuludq ymm7, ymm3, ymmword ptr [esi + 36]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7
  db $C5, $DD, $F4, $7E, $04                        // vpmuludq ymm7, ymm4, ymmword ptr [esi + 4]
  db $C5, $C5, $D4, $BC, $24, $80, $00, $00, $00    // vpaddq ymm7, ymm7, ymmword ptr [esp + 128]
  db $C5, $FE, $7F, $BC, $24, $80, $00, $00, $00    // vmovdqu ymmword ptr [esp + 128], ymm7

  // D3 spilled at [esp + 96]
  db $C5, $FD, $F4, $BE, $64, $00, $00, $00         // vpmuludq ymm7, ymm0, ymmword ptr [esi + 100]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $F5, $F4, $BE, $44, $00, $00, $00         // vpmuludq ymm7, ymm1, ymmword ptr [esi + 68]
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $ED, $F4, $7E, $24                        // vpmuludq ymm7, ymm2, ymmword ptr [esi + 36]
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $E5, $F4, $7E, $04                        // vpmuludq ymm7, ymm3, ymmword ptr [esi + 4]
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7
  db $C5, $DD, $F4, $BE, $04, $01, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 260]   ; S4 shifted
  db $C5, $C5, $D4, $7C, $24, $60                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 96]
  db $C5, $FE, $7F, $7C, $24, $60                   // vmovdqu ymmword ptr [esp + 96], ymm7

  // D2 spilled at [esp + 64]
  db $C5, $FD, $F4, $BE, $44, $00, $00, $00         // vpmuludq ymm7, ymm0, ymmword ptr [esi + 68]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $F5, $F4, $7E, $24                        // vpmuludq ymm7, ymm1, ymmword ptr [esi + 36]
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $ED, $F4, $7E, $04                        // vpmuludq ymm7, ymm2, ymmword ptr [esi + 4]
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $E5, $F4, $BE, $04, $01, $00, $00         // vpmuludq ymm7, ymm3, ymmword ptr [esi + 260]
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7
  db $C5, $DD, $F4, $BE, $E4, $00, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 228]   ; S3 shifted
  db $C5, $C5, $D4, $7C, $24, $40                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 64]
  db $C5, $FE, $7F, $7C, $24, $40                   // vmovdqu ymmword ptr [esp + 64], ymm7

  // D1 spilled at [esp + 32]
  db $C5, $FD, $F4, $7E, $24                        // vpmuludq ymm7, ymm0, ymmword ptr [esi + 36]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $F5, $F4, $7E, $04                        // vpmuludq ymm7, ymm1, ymmword ptr [esi + 4]
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $ED, $F4, $BE, $04, $01, $00, $00         // vpmuludq ymm7, ymm2, ymmword ptr [esi + 260]
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $E5, $F4, $BE, $E4, $00, $00, $00         // vpmuludq ymm7, ymm3, ymmword ptr [esi + 228]
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7
  db $C5, $DD, $F4, $BE, $C4, $00, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 196]   ; S2 shifted
  db $C5, $C5, $D4, $7C, $24, $20                   // vpaddq ymm7, ymm7, ymmword ptr [esp + 32]
  db $C5, $FE, $7F, $7C, $24, $20                   // vmovdqu ymmword ptr [esp + 32], ymm7

  // D0 spilled at [esp + 0]
  db $C5, $FD, $F4, $7E, $04                        // vpmuludq ymm7, ymm0, ymmword ptr [esi + 4]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $F5, $F4, $BE, $04, $01, $00, $00         // vpmuludq ymm7, ymm1, ymmword ptr [esi + 260]
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $ED, $F4, $BE, $E4, $00, $00, $00         // vpmuludq ymm7, ymm2, ymmword ptr [esi + 228]
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $E5, $F4, $BE, $C4, $00, $00, $00         // vpmuludq ymm7, ymm3, ymmword ptr [esi + 196]
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $DD, $F4, $BE, $A4, $00, $00, $00         // vpmuludq ymm7, ymm4, ymmword ptr [esi + 164]   ; S1 shifted
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7

  // ---- Tail lazy reduce ----
  db $C5, $FE, $6F, $04, $24                        // vmovdqu ymm0, ymmword ptr [esp]
  db $C5, $FE, $6F, $4C, $24, $20                   // vmovdqu ymm1, ymmword ptr [esp + 32]
  db $C5, $FE, $6F, $54, $24, $40                   // vmovdqu ymm2, ymmword ptr [esp + 64]
  db $C5, $FE, $6F, $5C, $24, $60                   // vmovdqu ymm3, ymmword ptr [esp + 96]
  db $C5, $FE, $6F, $A4, $24, $80, $00, $00, $00    // vmovdqu ymm4, ymmword ptr [esp + 128]

  db $C5, $C5, $73, $D0, $1A                        // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $D1, $1A                        // vpsrlq ymm7, ymm1, 26
  db $C5, $F5, $DB, $CD                             // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $D4, $D7                             // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $D2, $1A                        // vpsrlq ymm7, ymm2, 26
  db $C5, $ED, $DB, $D5                             // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $D4, $DF                             // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $D3, $1A                        // vpsrlq ymm7, ymm3, 26
  db $C5, $E5, $DB, $DD                             // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $D4, $E7                             // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $D4, $1A                        // vpsrlq ymm7, ymm4, 26
  db $C5, $DD, $DB, $E5                             // vpand ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $C5, $73, $F7, $02                        // vpsllq ymm7, ymm7, 2
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FD, $D4, $C7                             // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D0, $1A                        // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7

  // ---- Horizontal sum across 4 lanes for ymm0..ymm4 ----
  db $C5, $C5, $73, $D8, $08                        // vpsrldq ymm7, ymm0, 8
  db $C5, $FD, $D4, $C7                             // vpaddq ymm0, ymm0, ymm7
  db $C4, $E3, $FD, $00, $F8, $4E                   // vpermq ymm7, ymm0, 0x4E
  db $C5, $FD, $D4, $C7                             // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D9, $08                        // vpsrldq ymm7, ymm1, 8
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7
  db $C4, $E3, $FD, $00, $F9, $4E                   // vpermq ymm7, ymm1, 0x4E
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $DA, $08                        // vpsrldq ymm7, ymm2, 8
  db $C5, $ED, $D4, $D7                             // vpaddq ymm2, ymm2, ymm7
  db $C4, $E3, $FD, $00, $FA, $4E                   // vpermq ymm7, ymm2, 0x4E
  db $C5, $ED, $D4, $D7                             // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $DB, $08                        // vpsrldq ymm7, ymm3, 8
  db $C5, $E5, $D4, $DF                             // vpaddq ymm3, ymm3, ymm7
  db $C4, $E3, $FD, $00, $FB, $4E                   // vpermq ymm7, ymm3, 0x4E
  db $C5, $E5, $D4, $DF                             // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $DC, $08                        // vpsrldq ymm7, ymm4, 8
  db $C5, $DD, $D4, $E7                             // vpaddq ymm4, ymm4, ymm7
  db $C4, $E3, $FD, $00, $FC, $4E                   // vpermq ymm7, ymm4, 0x4E
  db $C5, $DD, $D4, $E7                             // vpaddq ymm4, ymm4, ymm7

  // ---- Final lazy reduce on the now-scalar limbs (lane 0) ----
  db $C5, $C5, $73, $D0, $1A                        // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $D1, $1A                        // vpsrlq ymm7, ymm1, 26
  db $C5, $F5, $DB, $CD                             // vpand ymm1, ymm1, ymm5
  db $C5, $ED, $D4, $D7                             // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $D2, $1A                        // vpsrlq ymm7, ymm2, 26
  db $C5, $ED, $DB, $D5                             // vpand ymm2, ymm2, ymm5
  db $C5, $E5, $D4, $DF                             // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $D3, $1A                        // vpsrlq ymm7, ymm3, 26
  db $C5, $E5, $DB, $DD                             // vpand ymm3, ymm3, ymm5
  db $C5, $DD, $D4, $E7                             // vpaddq ymm4, ymm4, ymm7
  db $C5, $C5, $73, $D4, $1A                        // vpsrlq ymm7, ymm4, 26
  db $C5, $DD, $DB, $E5                             // vpand ymm4, ymm4, ymm5
  db $C5, $FE, $7F, $3C, $24                        // vmovdqu ymmword ptr [esp], ymm7
  db $C5, $C5, $73, $F7, $02                        // vpsllq ymm7, ymm7, 2
  db $C5, $C5, $D4, $3C, $24                        // vpaddq ymm7, ymm7, ymmword ptr [esp]
  db $C5, $FD, $D4, $C7                             // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D0, $1A                        // vpsrlq ymm7, ymm0, 26
  db $C5, $FD, $DB, $C5                             // vpand ymm0, ymm0, ymm5
  db $C5, $F5, $D4, $CF                             // vpaddq ymm1, ymm1, ymm7

  // ---- Store h0..h4 back to ctx ----
  db $C5, $F9, $7E, $43, $24                        // vmovd dword ptr [ebx + 36], xmm0
  db $C5, $F9, $7E, $4B, $28                        // vmovd dword ptr [ebx + 40], xmm1
  db $C5, $F9, $7E, $53, $2C                        // vmovd dword ptr [ebx + 44], xmm2
  db $C5, $F9, $7E, $5B, $30                        // vmovd dword ptr [ebx + 48], xmm3
  db $C5, $F9, $7E, $63, $34                        // vmovd dword ptr [ebx + 52], xmm4

  db $C5, $F8, $77                                  // vzeroupper
  add        esp, 320

  pop        edi
  pop        esi
  pop        ebx
