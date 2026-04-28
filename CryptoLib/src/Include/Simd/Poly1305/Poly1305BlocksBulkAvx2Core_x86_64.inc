// Poly1305 4-way AVX2 bulk MAC kernel (x86-64).
// -------------------------------------------------------------------
// Algorithm: Goll-Gueron 2015 / Polyakov OpenSSL `poly1305_blocks_avx2`.
// Processes 4 16-byte blocks per iteration in 4-way SIMD with a precomputed
// r^1..r^4 power table (rebuilt at SetKey when AVX2 is the chosen path).
// The bulk loop multiplies the 4-lane accumulator H by r^4 broadcast in all
// lanes; the final tail iteration uses the same table read at +4 byte
// offset, giving lanes [r^1, r^2, r^3, r^4] for a branch-free fold-back via
// a horizontal sum. No scalar-tail block from the SIMD kernel; the Pascal
// dispatcher rounds the SIMD count down to a multiple of 4 and forwards
// 0..3 leftover blocks to the scalar code path.
//
// VEX-encoded AVX2 instructions are db-encoded for broad assembler compatibility.
// Each db line carries a mnemonic comment. Most VEX bytes are shared across IA-32
// and x86-64 since the inner kernel uses ymm0..ymm15 / r-class registers
// addressable in both modes via 2-/3-byte VEX prefixes; the i386 sibling
// include shares the same algorithm but uses a different register mapping
// (ebx/esi/edi/eax instead of rcx/rdx/r8/r9) and stays inside ymm0..ymm7.
//
// On entry (after SimdProc5Begin_x86_64.inc):
//   rcx = ACtx       (PTPoly1305State; 72-byte R/S/H/K record)
//   rdx = APowTable  (PByte; 320-byte 10x8 power table; layout below)
//   r8  = AInp       (PByte; 16-byte aligned-or-not)
//   r9  = ALen       (NativeUInt; multiple of 64; >= 64)
//   r10 = APad       (always 1; ignored - padbit unconditional in bulk)
//
// TPoly1305State byte offsets (no SIMD member):
//   R0..R4   :   0..16     (5 dwords)
//   S1..S4   :  20..32     (4 dwords)
//   H0..H4   :  36..52     (5 dwords)   <- loaded into ymm0..ymm4 lane 0
//   K0..K3   :  56..68     (4 dwords; not read by this kernel)
//
// Power-table byte offsets (separate 320-byte buffer; rdx-based loads):
//   row j at [rdx + 32*j]; bulk loop reads at row offset (broadcast r^4),
//   tail iteration reads at row offset+4 (shifted [r^4,r^3,r^2,r^1]).
//   Row 0..4 = r-limbs 0..4; row 5..8 = s-limbs 1..4 (s = 5*r); row 9 pad.
//
// Register allocation (uses ymm0..ymm15):
//   ymm0..ymm4 : H0..H4         (4-lane radix-2^26 accumulator, persistent)
//   ymm5       : mask26         (0x3FFFFFF per 64-bit lane low half)
//   ymm6       : padbit         (0x1000000 per 64-bit lane low half)
//   ymm7..ymm15: D0..D4 / M0..M4 / scratch (transient)
//
// Win64 note: this kernel uses ymm6..ymm15 without explicit save/restore,
// matching the codebase's existing AES-NI/PCLMULQDQ kernels. FPC's
// `assembler; nostackframe` ABI handling is relied upon; Win64 callers
// of TPoly1305 are expected not to keep live values in xmm6..xmm15
// across the call.

  // ---- Prologue: build mask26 (ymm5) and padbit (ymm6) constants ----
  db $C5, $D5, $76, $ED                         // vpcmpeqd ymm5, ymm5, ymm5
  db $C5, $D5, $73, $D5, $26                    // vpsrlq ymm5, ymm5, 38     ; mask26 = 0x3FFFFFF per lane
  db $C5, $CD, $76, $F6                         // vpcmpeqd ymm6, ymm6, ymm6
  db $C5, $CD, $73, $D6, $3F                    // vpsrlq ymm6, ymm6, 63
  db $C5, $CD, $73, $F6, $18                    // vpsllq ymm6, ymm6, 24     ; padbit = 1<<24 per lane

  // ---- Load h0..h4 from ctx into lane 0 of ymm0..ymm4 ----
  db $C5, $F9, $6E, $41, $24                    // vmovd xmm0, dword ptr [rcx + 36]   ; H0
  db $C5, $F9, $6E, $49, $28                    // vmovd xmm1, dword ptr [rcx + 40]   ; H1
  db $C5, $F9, $6E, $51, $2C                    // vmovd xmm2, dword ptr [rcx + 44]   ; H2
  db $C5, $F9, $6E, $59, $30                    // vmovd xmm3, dword ptr [rcx + 48]   ; H3
  db $C5, $F9, $6E, $61, $34                    // vmovd xmm4, dword ptr [rcx + 52]   ; H4

  // ---- Pre-loop: load + decompress + absorb first 4 blocks ----
  db $C4, $41, $7A, $6F, $20                    // vmovdqu xmm12, xmmword ptr [r8]
  db $C4, $41, $7A, $6F, $68, $10               // vmovdqu xmm13, xmmword ptr [r8 + 16]
  db $C4, $43, $1D, $38, $60, $20, $01          // vinserti128 ymm12, ymm12, xmmword ptr [r8 + 32], 1
  db $C4, $43, $15, $38, $68, $30, $01          // vinserti128 ymm13, ymm13, xmmword ptr [r8 + 48], 1
  add  r8, 64

  // Decompress 4 blocks into limbs M0..M4 in (ymm12, ymm13, ymm14, ymm15, ymm7)
  db $C4, $C1, $0D, $73, $DC, $06               // vpsrldq ymm14, ymm12, 6
  db $C4, $C1, $05, $73, $DD, $06               // vpsrldq ymm15, ymm13, 6
  db $C4, $C1, $1D, $6D, $FD                    // vpunpckhqdq ymm7, ymm12, ymm13   ; T4 (high 64)
  db $C4, $41, $1D, $6C, $E5                    // vpunpcklqdq ymm12, ymm12, ymm13  ; T0 (low 64)
  db $C4, $41, $0D, $6C, $F7                    // vpunpcklqdq ymm14, ymm14, ymm15  ; T2 (limbs 2/3)
  db $C4, $C1, $05, $73, $D6, $1E               // vpsrlq ymm15, ymm14, 30          ; limb3 raw
  db $C4, $C1, $0D, $73, $D6, $04               // vpsrlq ymm14, ymm14, 4           ; limb2 raw
  db $C4, $C1, $15, $73, $D4, $1A               // vpsrlq ymm13, ymm12, 26          ; limb1 raw
  db $C5, $C5, $73, $D7, $28                    // vpsrlq ymm7, ymm7, 40            ; limb4 raw
  db $C5, $1D, $DB, $E5                         // vpand ymm12, ymm12, ymm5         ; M0 = limb0
  db $C5, $15, $DB, $ED                         // vpand ymm13, ymm13, ymm5         ; M1 = limb1
  db $C5, $0D, $DB, $F5                         // vpand ymm14, ymm14, ymm5         ; M2 = limb2
  db $C5, $05, $DB, $FD                         // vpand ymm15, ymm15, ymm5         ; M3 = limb3
  db $C5, $C5, $EB, $FE                         // vpor ymm7, ymm7, ymm6            ; M4 = limb4 | padbit

  // Absorb: H += M
  db $C4, $C1, $7D, $D4, $C4                    // vpaddq ymm0, ymm0, ymm12         ; H0 += M0
  db $C4, $C1, $75, $D4, $CD                    // vpaddq ymm1, ymm1, ymm13         ; H1 += M1
  db $C4, $C1, $6D, $D4, $D6                    // vpaddq ymm2, ymm2, ymm14         ; H2 += M2
  db $C4, $C1, $65, $D4, $DF                    // vpaddq ymm3, ymm3, ymm15         ; H3 += M3
  db $C5, $DD, $D4, $E7                         // vpaddq ymm4, ymm4, ymm7          ; H4 += M4

  sub  r9, 64
  jz   @@poly1305_avx2_tail

@@poly1305_avx2_loop:
  // ---- Bulk multiply: H *= r^4 (broadcast row form, base offset +0) ----
  // D4 (ymm12) = H0*R4 + H1*R3 + H2*R2 + H3*R1 + H4*R0
  db $C5, $7D, $F4, $A2, $80, $00, $00, $00     // vpmuludq ymm12, ymm0, ymmword ptr [rdx + 128]    ; H0 * R4
  db $C5, $75, $F4, $AA, $60, $00, $00, $00     // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 96]     ; H1 * R3
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13
  db $C5, $6D, $F4, $AA, $40, $00, $00, $00     // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 64]     ; H2 * R2
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13
  db $C5, $65, $F4, $6A, $20                    // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 32]     ; H3 * R1
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13
  db $C5, $5D, $F4, $6A, $00                    // vpmuludq ymm13, ymm4, ymmword ptr [rdx]          ; H4 * R0
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13

  // D3 (ymm11) = H0*R3 + H1*R2 + H2*R1 + H3*R0 + H4*S4
  db $C5, $7D, $F4, $9A, $60, $00, $00, $00     // vpmuludq ymm11, ymm0, ymmword ptr [rdx + 96]
  db $C5, $75, $F4, $AA, $40, $00, $00, $00     // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 64]
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13
  db $C5, $6D, $F4, $6A, $20                    // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 32]
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13
  db $C5, $65, $F4, $6A, $00                    // vpmuludq ymm13, ymm3, ymmword ptr [rdx]
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13
  db $C5, $5D, $F4, $AA, $00, $01, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 256]    ; S4
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13

  // D2 (ymm10) = H0*R2 + H1*R1 + H2*R0 + H3*S4 + H4*S3
  db $C5, $7D, $F4, $92, $40, $00, $00, $00     // vpmuludq ymm10, ymm0, ymmword ptr [rdx + 64]
  db $C5, $75, $F4, $6A, $20                    // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 32]
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13
  db $C5, $6D, $F4, $6A, $00                    // vpmuludq ymm13, ymm2, ymmword ptr [rdx]
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13
  db $C5, $65, $F4, $AA, $00, $01, $00, $00     // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 256]
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13
  db $C5, $5D, $F4, $AA, $E0, $00, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 224]    ; S3
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13

  // D1 (ymm9) = H0*R1 + H1*R0 + H2*S4 + H3*S3 + H4*S2
  db $C5, $7D, $F4, $4A, $20                    // vpmuludq ymm9, ymm0, ymmword ptr [rdx + 32]
  db $C5, $75, $F4, $6A, $00                    // vpmuludq ymm13, ymm1, ymmword ptr [rdx]
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13
  db $C5, $6D, $F4, $AA, $00, $01, $00, $00     // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 256]
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13
  db $C5, $65, $F4, $AA, $E0, $00, $00, $00     // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 224]
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13
  db $C5, $5D, $F4, $AA, $C0, $00, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 192]    ; S2
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13

  // D0 (ymm8) = H0*R0 + H1*S4 + H2*S3 + H3*S2 + H4*S1
  db $C5, $7D, $F4, $42, $00                    // vpmuludq ymm8, ymm0, ymmword ptr [rdx]
  db $C5, $75, $F4, $AA, $00, $01, $00, $00     // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 256]
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13
  db $C5, $6D, $F4, $AA, $E0, $00, $00, $00     // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 224]
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13
  db $C5, $65, $F4, $AA, $C0, $00, $00, $00     // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 192]
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13
  db $C5, $5D, $F4, $AA, $A0, $00, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 160]    ; S1
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13

  // ---- Lazy reduce D0..D4 (ymm8..ymm12) -> H0..H4 (ymm0..ymm4) ----
  db $C4, $C1, $15, $73, $D0, $1A               // vpsrlq ymm13, ymm8, 26
  db $C5, $BD, $DB, $C5                         // vpand ymm0, ymm8, ymm5
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13           ; D1 += D0>>26
  db $C4, $C1, $15, $73, $D1, $1A               // vpsrlq ymm13, ymm9, 26
  db $C5, $B5, $DB, $CD                         // vpand ymm1, ymm9, ymm5
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13         ; D2 += D1>>26
  db $C4, $C1, $15, $73, $D2, $1A               // vpsrlq ymm13, ymm10, 26
  db $C5, $AD, $DB, $D5                         // vpand ymm2, ymm10, ymm5
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13         ; D3 += D2>>26
  db $C4, $C1, $15, $73, $D3, $1A               // vpsrlq ymm13, ymm11, 26
  db $C5, $A5, $DB, $DD                         // vpand ymm3, ymm11, ymm5
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13         ; D4 += D3>>26
  db $C4, $C1, $15, $73, $D4, $1A               // vpsrlq ymm13, ymm12, 26
  db $C5, $9D, $DB, $E5                         // vpand ymm4, ymm12, ymm5
  db $C4, $C1, $05, $73, $F5, $02               // vpsllq ymm15, ymm13, 2
  db $C4, $41, $15, $D4, $EF                    // vpaddq ymm13, ymm13, ymm15         ; (D4>>26) *= 5
  db $C4, $C1, $7D, $D4, $C5                    // vpaddq ymm0, ymm0, ymm13           ; H0 += (D4>>26)*5
  db $C5, $95, $73, $D0, $1A                    // vpsrlq ymm13, ymm0, 26
  db $C5, $FD, $DB, $C5                         // vpand ymm0, ymm0, ymm5
  db $C4, $C1, $75, $D4, $CD                    // vpaddq ymm1, ymm1, ymm13           ; H1 += H0>>26

  // ---- Load + decompress + absorb next 4 blocks ----
  db $C4, $41, $7A, $6F, $20                    // vmovdqu xmm12, xmmword ptr [r8]
  db $C4, $41, $7A, $6F, $68, $10               // vmovdqu xmm13, xmmword ptr [r8 + 16]
  db $C4, $43, $1D, $38, $60, $20, $01          // vinserti128 ymm12, ymm12, xmmword ptr [r8 + 32], 1
  db $C4, $43, $15, $38, $68, $30, $01          // vinserti128 ymm13, ymm13, xmmword ptr [r8 + 48], 1
  add  r8, 64
  db $C4, $C1, $0D, $73, $DC, $06               // vpsrldq ymm14, ymm12, 6
  db $C4, $C1, $05, $73, $DD, $06               // vpsrldq ymm15, ymm13, 6
  db $C4, $C1, $1D, $6D, $FD                    // vpunpckhqdq ymm7, ymm12, ymm13
  db $C4, $41, $1D, $6C, $E5                    // vpunpcklqdq ymm12, ymm12, ymm13
  db $C4, $41, $0D, $6C, $F7                    // vpunpcklqdq ymm14, ymm14, ymm15
  db $C4, $C1, $05, $73, $D6, $1E               // vpsrlq ymm15, ymm14, 30
  db $C4, $C1, $0D, $73, $D6, $04               // vpsrlq ymm14, ymm14, 4
  db $C4, $C1, $15, $73, $D4, $1A               // vpsrlq ymm13, ymm12, 26
  db $C5, $C5, $73, $D7, $28                    // vpsrlq ymm7, ymm7, 40
  db $C5, $1D, $DB, $E5                         // vpand ymm12, ymm12, ymm5
  db $C5, $15, $DB, $ED                         // vpand ymm13, ymm13, ymm5
  db $C5, $0D, $DB, $F5                         // vpand ymm14, ymm14, ymm5
  db $C5, $05, $DB, $FD                         // vpand ymm15, ymm15, ymm5
  db $C5, $C5, $EB, $FE                         // vpor ymm7, ymm7, ymm6
  db $C4, $C1, $7D, $D4, $C4                    // vpaddq ymm0, ymm0, ymm12
  db $C4, $C1, $75, $D4, $CD                    // vpaddq ymm1, ymm1, ymm13
  db $C4, $C1, $6D, $D4, $D6                    // vpaddq ymm2, ymm2, ymm14
  db $C4, $C1, $65, $D4, $DF                    // vpaddq ymm3, ymm3, ymm15
  db $C5, $DD, $D4, $E7                         // vpaddq ymm4, ymm4, ymm7

  sub  r9, 64
  jnz  @@poly1305_avx2_loop

@@poly1305_avx2_tail:
  // ---- Tail: H *= [r^1, r^2, r^3, r^4]  (offset+4 = shifted form) ----
  // D4 (ymm12) - table loads at +4 over the bulk offsets
  db $C5, $7D, $F4, $A2, $84, $00, $00, $00     // vpmuludq ymm12, ymm0, ymmword ptr [rdx + 132]
  db $C5, $75, $F4, $AA, $64, $00, $00, $00     // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 100]
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13
  db $C5, $6D, $F4, $AA, $44, $00, $00, $00     // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 68]
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13
  db $C5, $65, $F4, $6A, $24                    // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 36]
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13
  db $C5, $5D, $F4, $6A, $04                    // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 4]
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13

  // D3 (ymm11)
  db $C5, $7D, $F4, $9A, $64, $00, $00, $00     // vpmuludq ymm11, ymm0, ymmword ptr [rdx + 100]
  db $C5, $75, $F4, $AA, $44, $00, $00, $00     // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 68]
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13
  db $C5, $6D, $F4, $6A, $24                    // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 36]
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13
  db $C5, $65, $F4, $6A, $04                    // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 4]
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13
  db $C5, $5D, $F4, $AA, $04, $01, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 260]    ; S4 shifted
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13

  // D2 (ymm10)
  db $C5, $7D, $F4, $92, $44, $00, $00, $00     // vpmuludq ymm10, ymm0, ymmword ptr [rdx + 68]
  db $C5, $75, $F4, $6A, $24                    // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 36]
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13
  db $C5, $6D, $F4, $6A, $04                    // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 4]
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13
  db $C5, $65, $F4, $AA, $04, $01, $00, $00     // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 260]
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13
  db $C5, $5D, $F4, $AA, $E4, $00, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 228]    ; S3 shifted
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13

  // D1 (ymm9)
  db $C5, $7D, $F4, $4A, $24                    // vpmuludq ymm9, ymm0, ymmword ptr [rdx + 36]
  db $C5, $75, $F4, $6A, $04                    // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 4]
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13
  db $C5, $6D, $F4, $AA, $04, $01, $00, $00     // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 260]
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13
  db $C5, $65, $F4, $AA, $E4, $00, $00, $00     // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 228]
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13
  db $C5, $5D, $F4, $AA, $C4, $00, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 196]    ; S2 shifted
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13

  // D0 (ymm8)
  db $C5, $7D, $F4, $42, $04                    // vpmuludq ymm8, ymm0, ymmword ptr [rdx + 4]
  db $C5, $75, $F4, $AA, $04, $01, $00, $00     // vpmuludq ymm13, ymm1, ymmword ptr [rdx + 260]
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13
  db $C5, $6D, $F4, $AA, $E4, $00, $00, $00     // vpmuludq ymm13, ymm2, ymmword ptr [rdx + 228]
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13
  db $C5, $65, $F4, $AA, $C4, $00, $00, $00     // vpmuludq ymm13, ymm3, ymmword ptr [rdx + 196]
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13
  db $C5, $5D, $F4, $AA, $A4, $00, $00, $00     // vpmuludq ymm13, ymm4, ymmword ptr [rdx + 164]    ; S1 shifted
  db $C4, $41, $3D, $D4, $C5                    // vpaddq ymm8, ymm8, ymm13

  // ---- Tail lazy reduce ----
  db $C4, $C1, $15, $73, $D0, $1A               // vpsrlq ymm13, ymm8, 26
  db $C5, $BD, $DB, $C5                         // vpand ymm0, ymm8, ymm5
  db $C4, $41, $35, $D4, $CD                    // vpaddq ymm9, ymm9, ymm13
  db $C4, $C1, $15, $73, $D1, $1A               // vpsrlq ymm13, ymm9, 26
  db $C5, $B5, $DB, $CD                         // vpand ymm1, ymm9, ymm5
  db $C4, $41, $2D, $D4, $D5                    // vpaddq ymm10, ymm10, ymm13
  db $C4, $C1, $15, $73, $D2, $1A               // vpsrlq ymm13, ymm10, 26
  db $C5, $AD, $DB, $D5                         // vpand ymm2, ymm10, ymm5
  db $C4, $41, $25, $D4, $DD                    // vpaddq ymm11, ymm11, ymm13
  db $C4, $C1, $15, $73, $D3, $1A               // vpsrlq ymm13, ymm11, 26
  db $C5, $A5, $DB, $DD                         // vpand ymm3, ymm11, ymm5
  db $C4, $41, $1D, $D4, $E5                    // vpaddq ymm12, ymm12, ymm13
  db $C4, $C1, $15, $73, $D4, $1A               // vpsrlq ymm13, ymm12, 26
  db $C5, $9D, $DB, $E5                         // vpand ymm4, ymm12, ymm5
  db $C4, $C1, $05, $73, $F5, $02               // vpsllq ymm15, ymm13, 2
  db $C4, $41, $15, $D4, $EF                    // vpaddq ymm13, ymm13, ymm15
  db $C4, $C1, $7D, $D4, $C5                    // vpaddq ymm0, ymm0, ymm13
  db $C5, $95, $73, $D0, $1A                    // vpsrlq ymm13, ymm0, 26
  db $C5, $FD, $DB, $C5                         // vpand ymm0, ymm0, ymm5
  db $C4, $C1, $75, $D4, $CD                    // vpaddq ymm1, ymm1, ymm13

  // ---- Horizontal sum across 4 lanes for ymm0..ymm4 ----
  db $C5, $C5, $73, $D8, $08                    // vpsrldq ymm7, ymm0, 8
  db $C5, $FD, $D4, $C7                         // vpaddq ymm0, ymm0, ymm7
  db $C4, $E3, $FD, $00, $F8, $4E               // vpermq ymm7, ymm0, 0x4E
  db $C5, $FD, $D4, $C7                         // vpaddq ymm0, ymm0, ymm7
  db $C5, $C5, $73, $D9, $08                    // vpsrldq ymm7, ymm1, 8
  db $C5, $F5, $D4, $CF                         // vpaddq ymm1, ymm1, ymm7
  db $C4, $E3, $FD, $00, $F9, $4E               // vpermq ymm7, ymm1, 0x4E
  db $C5, $F5, $D4, $CF                         // vpaddq ymm1, ymm1, ymm7
  db $C5, $C5, $73, $DA, $08                    // vpsrldq ymm7, ymm2, 8
  db $C5, $ED, $D4, $D7                         // vpaddq ymm2, ymm2, ymm7
  db $C4, $E3, $FD, $00, $FA, $4E               // vpermq ymm7, ymm2, 0x4E
  db $C5, $ED, $D4, $D7                         // vpaddq ymm2, ymm2, ymm7
  db $C5, $C5, $73, $DB, $08                    // vpsrldq ymm7, ymm3, 8
  db $C5, $E5, $D4, $DF                         // vpaddq ymm3, ymm3, ymm7
  db $C4, $E3, $FD, $00, $FB, $4E               // vpermq ymm7, ymm3, 0x4E
  db $C5, $E5, $D4, $DF                         // vpaddq ymm3, ymm3, ymm7
  db $C5, $C5, $73, $DC, $08                    // vpsrldq ymm7, ymm4, 8
  db $C5, $DD, $D4, $E7                         // vpaddq ymm4, ymm4, ymm7
  db $C4, $E3, $FD, $00, $FC, $4E               // vpermq ymm7, ymm4, 0x4E
  db $C5, $DD, $D4, $E7                         // vpaddq ymm4, ymm4, ymm7

  // ---- Final lazy reduce on the now-scalar limbs (lane 0) ----
  db $C5, $95, $73, $D0, $1A                    // vpsrlq ymm13, ymm0, 26
  db $C5, $FD, $DB, $C5                         // vpand ymm0, ymm0, ymm5
  db $C4, $C1, $75, $D4, $CD                    // vpaddq ymm1, ymm1, ymm13
  db $C5, $95, $73, $D1, $1A                    // vpsrlq ymm13, ymm1, 26
  db $C5, $F5, $DB, $CD                         // vpand ymm1, ymm1, ymm5
  db $C4, $C1, $6D, $D4, $D5                    // vpaddq ymm2, ymm2, ymm13
  db $C5, $95, $73, $D2, $1A                    // vpsrlq ymm13, ymm2, 26
  db $C5, $ED, $DB, $D5                         // vpand ymm2, ymm2, ymm5
  db $C4, $C1, $65, $D4, $DD                    // vpaddq ymm3, ymm3, ymm13
  db $C5, $95, $73, $D3, $1A                    // vpsrlq ymm13, ymm3, 26
  db $C5, $E5, $DB, $DD                         // vpand ymm3, ymm3, ymm5
  db $C4, $C1, $5D, $D4, $E5                    // vpaddq ymm4, ymm4, ymm13
  db $C5, $95, $73, $D4, $1A                    // vpsrlq ymm13, ymm4, 26
  db $C5, $DD, $DB, $E5                         // vpand ymm4, ymm4, ymm5
  db $C4, $C1, $05, $73, $F5, $02               // vpsllq ymm15, ymm13, 2
  db $C4, $41, $15, $D4, $EF                    // vpaddq ymm13, ymm13, ymm15
  db $C4, $C1, $7D, $D4, $C5                    // vpaddq ymm0, ymm0, ymm13
  db $C5, $95, $73, $D0, $1A                    // vpsrlq ymm13, ymm0, 26
  db $C5, $FD, $DB, $C5                         // vpand ymm0, ymm0, ymm5
  db $C4, $C1, $75, $D4, $CD                    // vpaddq ymm1, ymm1, ymm13

  // ---- Store h0..h4 back to ctx ----
  db $C5, $F9, $7E, $41, $24                    // vmovd dword ptr [rcx + 36], xmm0
  db $C5, $F9, $7E, $49, $28                    // vmovd dword ptr [rcx + 40], xmm1
  db $C5, $F9, $7E, $51, $2C                    // vmovd dword ptr [rcx + 44], xmm2
  db $C5, $F9, $7E, $59, $30                    // vmovd dword ptr [rcx + 48], xmm3
  db $C5, $F9, $7E, $61, $34                    // vmovd dword ptr [rcx + 52], xmm4

  db $C5, $F8, $77                              // vzeroupper
