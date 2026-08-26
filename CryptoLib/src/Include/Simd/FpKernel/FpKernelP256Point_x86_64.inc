// Fused P-256 RCB complete-group-law point kernels (secp256r1, a=-3, x86-64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined
// before including this file:
//
//   CRYPTOLIB_FP_P256_POINTDOUBLE   (ClpSimdProc3Begin: rcx = PR, rdx = PA, r8 = PCtx)
//     - straight-line RCB2016 a=-3 doubling PR := 2*PA (Algorithm 6) over a
//       homogeneous point.
//   CRYPTOLIB_FP_P256_POINTADD   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PQ, r9 = PCtx)
//     - straight-line RCB2016 a=-3 complete addition PR := PA + PQ
//       (Algorithm 4) of two homogeneous points.
//   CRYPTOLIB_FP_P256_POINTADDMIXED   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PQ, r9 = PCtx)
//     - the same complete addition with PQ an AFFINE point (TFeAffine X,Y);
//       the unit Z2 is taken from PCtx.MontOne (R mod p) at +160.
//
// Shared across all three: PR/PA/PQ are TFePoint (or TFeAffine) bases with
// coords at SizeOf(TFe) strides (X,Y,Z at +0/+72/+144); PCtx = [n0', N,
// p0..p3] with the curve's Fb (b*R mod p) at +304. Every intermediate lives
// in a fixed stack frame and both inputs are copied in up front, so a call
// with PR aliasing an input (incl. add(P,P)) is safe. The field multiply is
// the folded special-prime mul_mont_p256 body (MULX product + shift/add
// reduce, db-encoded), inlined under a single prologue/epilogue per proc.
//
// Constant-time: straight-line and data-independent (no branch or memory
// address depends on the point); each proc preserves the callee-saved GPRs
// its inlined cores use and frees its frame in the epilogue. Backend-gated on
// BMI2+ADX (x86-64); any other target uses the generic per-op RCB formula,
// bit-for-bit.
{$IFDEF CRYPTOLIB_FP_P256_POINTDOUBLE}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov r9, r8            // r9 = PCtx (pinned; cores read [r9 + ..])
  sub rsp, 336
  mov [rsp + 320], rcx   // save output-point pointer
  // load input point X,Y,Z into frame
  mov rax, [rdx + 0]
  mov [rsp + 0], rax
  mov rax, [rdx + 8]
  mov [rsp + 8], rax
  mov rax, [rdx + 16]
  mov [rsp + 16], rax
  mov rax, [rdx + 24]
  mov [rsp + 24], rax
  mov rax, [rdx + 72]
  mov [rsp + 32], rax
  mov rax, [rdx + 80]
  mov [rsp + 40], rax
  mov rax, [rdx + 88]
  mov [rsp + 48], rax
  mov rax, [rdx + 96]
  mov [rsp + 56], rax
  mov rax, [rdx + 144]
  mov [rsp + 64], rax
  mov rax, [rdx + 152]
  mov [rsp + 72], rax
  mov rax, [rdx + 160]
  mov [rsp + 80], rax
  mov rax, [rdx + 168]
  mov [rsp + 88], rax
  // sqr t0 = X
  lea rsi, [rsp + 0]
  lea rdi, [rsp + 0]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul0:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul0
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 96], r8
  mov [rsp + 104], r10
  mov [rsp + 112], r11
  mov [rsp + 120], r12
  // sqr t1 = Y
  lea rsi, [rsp + 32]
  lea rdi, [rsp + 32]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul1:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul1
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 128], r8
  mov [rsp + 136], r10
  mov [rsp + 144], r11
  mov [rsp + 152], r12
  // sqr t2 = Z
  lea rsi, [rsp + 64]
  lea rdi, [rsp + 64]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul2:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul2
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 160], r8
  mov [rsp + 168], r10
  mov [rsp + 176], r11
  mov [rsp + 184], r12
  // mul t3 = X * Y
  lea rsi, [rsp + 0]
  lea rdi, [rsp + 32]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul3:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul3
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 192], r8
  mov [rsp + 200], r10
  mov [rsp + 208], r11
  mov [rsp + 216], r12
  // ModAdd t3 = t3 + t3
  mov r8, [rsp + 192]
  add r8, [rsp + 192]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 192 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 192 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 192 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 192], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 200], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 208], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 216], r12
  // mul Z3 = X * Z
  lea rsi, [rsp + 0]
  lea rdi, [rsp + 64]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul4:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul4
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModAdd Z3 = Z3 + Z3
  mov r8, [rsp + 288]
  add r8, [rsp + 288]
  mov r10, [rsp + 288 + 8]
  adc r10, [rsp + 288 + 8]
  mov r11, [rsp + 288 + 16]
  adc r11, [rsp + 288 + 16]
  mov r12, [rsp + 288 + 24]
  adc r12, [rsp + 288 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 288], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 296], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 304], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 312], r12
  // mulb Y3 = t2 * b
  lea rsi, [rsp + 160]
  lea rdi, [r9 + 304]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul5:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul5
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // ModSub Y3 = Y3 - Z3
  mov r8, [rsp + 256]
  sub r8, [rsp + 288]
  mov r10, [rsp + 256 + 8]
  sbb r10, [rsp + 288 + 8]
  mov r11, [rsp + 256 + 16]
  sbb r11, [rsp + 288 + 16]
  mov r12, [rsp + 256 + 24]
  sbb r12, [rsp + 288 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // ModAdd X3 = Y3 + Y3
  mov r8, [rsp + 256]
  add r8, [rsp + 256]
  mov r10, [rsp + 256 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 256 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 256 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 224], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 232], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 240], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 248], r12
  // ModAdd Y3 = X3 + Y3
  mov r8, [rsp + 224]
  add r8, [rsp + 256]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 256], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 264], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 272], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 280], r12
  // ModSub X3 = t1 - Y3
  mov r8, [rsp + 128]
  sub r8, [rsp + 256]
  mov r10, [rsp + 128 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 128 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 128 + 24]
  sbb r12, [rsp + 256 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // ModAdd Y3 = t1 + Y3
  mov r8, [rsp + 128]
  add r8, [rsp + 256]
  mov r10, [rsp + 128 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 128 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 128 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 256], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 264], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 272], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 280], r12
  // mul Y3 = X3 * Y3
  lea rsi, [rsp + 224]
  lea rdi, [rsp + 256]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul6:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul6
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // mul X3 = X3 * t3
  lea rsi, [rsp + 224]
  lea rdi, [rsp + 192]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul7:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul7
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // ModAdd t3 = t2 + t2
  mov r8, [rsp + 160]
  add r8, [rsp + 160]
  mov r10, [rsp + 160 + 8]
  adc r10, [rsp + 160 + 8]
  mov r11, [rsp + 160 + 16]
  adc r11, [rsp + 160 + 16]
  mov r12, [rsp + 160 + 24]
  adc r12, [rsp + 160 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 192], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 200], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 208], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 216], r12
  // ModAdd t2 = t2 + t3
  mov r8, [rsp + 160]
  add r8, [rsp + 192]
  mov r10, [rsp + 160 + 8]
  adc r10, [rsp + 192 + 8]
  mov r11, [rsp + 160 + 16]
  adc r11, [rsp + 192 + 16]
  mov r12, [rsp + 160 + 24]
  adc r12, [rsp + 192 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 160], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 168], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 176], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 184], r12
  // mulb Z3 = Z3 * b
  lea rsi, [rsp + 288]
  lea rdi, [r9 + 304]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul8:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul8
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModSub Z3 = Z3 - t2
  mov r8, [rsp + 288]
  sub r8, [rsp + 160]
  mov r10, [rsp + 288 + 8]
  sbb r10, [rsp + 160 + 8]
  mov r11, [rsp + 288 + 16]
  sbb r11, [rsp + 160 + 16]
  mov r12, [rsp + 288 + 24]
  sbb r12, [rsp + 160 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModSub Z3 = Z3 - t0
  mov r8, [rsp + 288]
  sub r8, [rsp + 96]
  mov r10, [rsp + 288 + 8]
  sbb r10, [rsp + 96 + 8]
  mov r11, [rsp + 288 + 16]
  sbb r11, [rsp + 96 + 16]
  mov r12, [rsp + 288 + 24]
  sbb r12, [rsp + 96 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModAdd t3 = Z3 + Z3
  mov r8, [rsp + 288]
  add r8, [rsp + 288]
  mov r10, [rsp + 288 + 8]
  adc r10, [rsp + 288 + 8]
  mov r11, [rsp + 288 + 16]
  adc r11, [rsp + 288 + 16]
  mov r12, [rsp + 288 + 24]
  adc r12, [rsp + 288 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 192], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 200], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 208], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 216], r12
  // ModAdd Z3 = Z3 + t3
  mov r8, [rsp + 288]
  add r8, [rsp + 192]
  mov r10, [rsp + 288 + 8]
  adc r10, [rsp + 192 + 8]
  mov r11, [rsp + 288 + 16]
  adc r11, [rsp + 192 + 16]
  mov r12, [rsp + 288 + 24]
  adc r12, [rsp + 192 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 288], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 296], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 304], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 312], r12
  // ModAdd t3 = t0 + t0
  mov r8, [rsp + 96]
  add r8, [rsp + 96]
  mov r10, [rsp + 96 + 8]
  adc r10, [rsp + 96 + 8]
  mov r11, [rsp + 96 + 16]
  adc r11, [rsp + 96 + 16]
  mov r12, [rsp + 96 + 24]
  adc r12, [rsp + 96 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 192], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 200], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 208], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 216], r12
  // ModAdd t0 = t3 + t0
  mov r8, [rsp + 192]
  add r8, [rsp + 96]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 96 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 96 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 96 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 96], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 104], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 112], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 120], r12
  // ModSub t0 = t0 - t2
  mov r8, [rsp + 96]
  sub r8, [rsp + 160]
  mov r10, [rsp + 96 + 8]
  sbb r10, [rsp + 160 + 8]
  mov r11, [rsp + 96 + 16]
  sbb r11, [rsp + 160 + 16]
  mov r12, [rsp + 96 + 24]
  sbb r12, [rsp + 160 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 96], r8
  mov [rsp + 104], r10
  mov [rsp + 112], r11
  mov [rsp + 120], r12
  // mul t0 = t0 * Z3
  lea rsi, [rsp + 96]
  lea rdi, [rsp + 288]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul9:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul9
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 96], r8
  mov [rsp + 104], r10
  mov [rsp + 112], r11
  mov [rsp + 120], r12
  // ModAdd Y3 = Y3 + t0
  mov r8, [rsp + 256]
  add r8, [rsp + 96]
  mov r10, [rsp + 256 + 8]
  adc r10, [rsp + 96 + 8]
  mov r11, [rsp + 256 + 16]
  adc r11, [rsp + 96 + 16]
  mov r12, [rsp + 256 + 24]
  adc r12, [rsp + 96 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 256], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 264], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 272], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 280], r12
  // mul t0 = Y * Z
  lea rsi, [rsp + 32]
  lea rdi, [rsp + 64]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul10:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul10
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 96], r8
  mov [rsp + 104], r10
  mov [rsp + 112], r11
  mov [rsp + 120], r12
  // ModAdd t0 = t0 + t0
  mov r8, [rsp + 96]
  add r8, [rsp + 96]
  mov r10, [rsp + 96 + 8]
  adc r10, [rsp + 96 + 8]
  mov r11, [rsp + 96 + 16]
  adc r11, [rsp + 96 + 16]
  mov r12, [rsp + 96 + 24]
  adc r12, [rsp + 96 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 96], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 104], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 112], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 120], r12
  // mul Z3 = t0 * Z3
  lea rsi, [rsp + 96]
  lea rdi, [rsp + 288]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul11:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul11
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModSub X3 = X3 - Z3
  mov r8, [rsp + 224]
  sub r8, [rsp + 288]
  mov r10, [rsp + 224 + 8]
  sbb r10, [rsp + 288 + 8]
  mov r11, [rsp + 224 + 16]
  sbb r11, [rsp + 288 + 16]
  mov r12, [rsp + 224 + 24]
  sbb r12, [rsp + 288 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // mul Z3 = t0 * t1
  lea rsi, [rsp + 96]
  lea rdi, [rsp + 128]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256DblMul12:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256DblMul12
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModAdd Z3 = Z3 + Z3
  mov r8, [rsp + 288]
  add r8, [rsp + 288]
  mov r10, [rsp + 288 + 8]
  adc r10, [rsp + 288 + 8]
  mov r11, [rsp + 288 + 16]
  adc r11, [rsp + 288 + 16]
  mov r12, [rsp + 288 + 24]
  adc r12, [rsp + 288 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 288], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 296], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 304], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 312], r12
  // ModAdd Z3 = Z3 + Z3
  mov r8, [rsp + 288]
  add r8, [rsp + 288]
  mov r10, [rsp + 288 + 8]
  adc r10, [rsp + 288 + 8]
  mov r11, [rsp + 288 + 16]
  adc r11, [rsp + 288 + 16]
  mov r12, [rsp + 288 + 24]
  adc r12, [rsp + 288 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 288], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 296], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 304], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 312], r12
  // store result point X3,Y3,Z3
  mov rcx, [rsp + 320]
  mov rax, [rsp + 224]
  mov [rcx + 0], rax
  mov rax, [rsp + 232]
  mov [rcx + 8], rax
  mov rax, [rsp + 240]
  mov [rcx + 16], rax
  mov rax, [rsp + 248]
  mov [rcx + 24], rax
  mov rax, [rsp + 256]
  mov [rcx + 72], rax
  mov rax, [rsp + 264]
  mov [rcx + 80], rax
  mov rax, [rsp + 272]
  mov [rcx + 88], rax
  mov rax, [rsp + 280]
  mov [rcx + 96], rax
  mov rax, [rsp + 288]
  mov [rcx + 144], rax
  mov rax, [rsp + 296]
  mov [rcx + 152], rax
  mov rax, [rsp + 304]
  mov [rcx + 160], rax
  mov rax, [rsp + 312]
  mov [rcx + 168], rax
  add rsp, 336
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ELSE}
  {$IFDEF CRYPTOLIB_FP_P256_POINTADD}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  sub rsp, 464
  mov [rsp + 448], rcx   // save output-point pointer
  // load input point P X,Y,Z into frame
  mov rax, [rdx + 0]
  mov [rsp + 0], rax
  mov rax, [rdx + 8]
  mov [rsp + 8], rax
  mov rax, [rdx + 16]
  mov [rsp + 16], rax
  mov rax, [rdx + 24]
  mov [rsp + 24], rax
  mov rax, [rdx + 72]
  mov [rsp + 32], rax
  mov rax, [rdx + 80]
  mov [rsp + 40], rax
  mov rax, [rdx + 88]
  mov [rsp + 48], rax
  mov rax, [rdx + 96]
  mov [rsp + 56], rax
  mov rax, [rdx + 144]
  mov [rsp + 64], rax
  mov rax, [rdx + 152]
  mov [rsp + 72], rax
  mov rax, [rdx + 160]
  mov [rsp + 80], rax
  mov rax, [rdx + 168]
  mov [rsp + 88], rax
  // load input point Q X,Y into frame
  mov rax, [r8 + 0]
  mov [rsp + 96], rax
  mov rax, [r8 + 8]
  mov [rsp + 104], rax
  mov rax, [r8 + 16]
  mov [rsp + 112], rax
  mov rax, [r8 + 24]
  mov [rsp + 120], rax
  mov rax, [r8 + 72]
  mov [rsp + 128], rax
  mov rax, [r8 + 80]
  mov [rsp + 136], rax
  mov rax, [r8 + 88]
  mov [rsp + 144], rax
  mov rax, [r8 + 96]
  mov [rsp + 152], rax
  // load input point Q Z into frame
  mov rax, [r8 + 144]
  mov [rsp + 160], rax
  mov rax, [r8 + 152]
  mov [rsp + 168], rax
  mov rax, [r8 + 160]
  mov [rsp + 176], rax
  mov rax, [r8 + 168]
  mov [rsp + 184], rax
  // mul t0 = X1 * X2
  lea rsi, [rsp + 0]
  lea rdi, [rsp + 96]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul0:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul0
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 192], r8
  mov [rsp + 200], r10
  mov [rsp + 208], r11
  mov [rsp + 216], r12
  // mul t1 = Y1 * Y2
  lea rsi, [rsp + 32]
  lea rdi, [rsp + 128]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul1:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul1
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // mul t2 = Z1 * Z2
  lea rsi, [rsp + 64]
  lea rdi, [rsp + 160]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul2:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul2
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // ModAdd t3 = X1 + Y1
  mov r8, [rsp + 0]
  add r8, [rsp + 32]
  mov r10, [rsp + 0 + 8]
  adc r10, [rsp + 32 + 8]
  mov r11, [rsp + 0 + 16]
  adc r11, [rsp + 32 + 16]
  mov r12, [rsp + 0 + 24]
  adc r12, [rsp + 32 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 288], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 296], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 304], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 312], r12
  // ModAdd t4 = X2 + Y2
  mov r8, [rsp + 96]
  add r8, [rsp + 128]
  mov r10, [rsp + 96 + 8]
  adc r10, [rsp + 128 + 8]
  mov r11, [rsp + 96 + 16]
  adc r11, [rsp + 128 + 16]
  mov r12, [rsp + 96 + 24]
  adc r12, [rsp + 128 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 320], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 328], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 336], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 344], r12
  // mul t3 = t3 * t4
  lea rsi, [rsp + 288]
  lea rdi, [rsp + 320]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul3:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul3
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModAdd t4 = t0 + t1
  mov r8, [rsp + 192]
  add r8, [rsp + 224]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 224 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 224 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 224 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 320], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 328], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 336], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 344], r12
  // ModSub t3 = t3 - t4
  mov r8, [rsp + 288]
  sub r8, [rsp + 320]
  mov r10, [rsp + 288 + 8]
  sbb r10, [rsp + 320 + 8]
  mov r11, [rsp + 288 + 16]
  sbb r11, [rsp + 320 + 16]
  mov r12, [rsp + 288 + 24]
  sbb r12, [rsp + 320 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModAdd t4 = Y1 + Z1
  mov r8, [rsp + 32]
  add r8, [rsp + 64]
  mov r10, [rsp + 32 + 8]
  adc r10, [rsp + 64 + 8]
  mov r11, [rsp + 32 + 16]
  adc r11, [rsp + 64 + 16]
  mov r12, [rsp + 32 + 24]
  adc r12, [rsp + 64 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 320], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 328], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 336], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 344], r12
  // ModAdd X3 = Y2 + Z2
  mov r8, [rsp + 128]
  add r8, [rsp + 160]
  mov r10, [rsp + 128 + 8]
  adc r10, [rsp + 160 + 8]
  mov r11, [rsp + 128 + 16]
  adc r11, [rsp + 160 + 16]
  mov r12, [rsp + 128 + 24]
  adc r12, [rsp + 160 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // mul t4 = t4 * X3
  lea rsi, [rsp + 320]
  lea rdi, [rsp + 352]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul4:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul4
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 320], r8
  mov [rsp + 328], r10
  mov [rsp + 336], r11
  mov [rsp + 344], r12
  // ModAdd X3 = t1 + t2
  mov r8, [rsp + 224]
  add r8, [rsp + 256]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // ModSub t4 = t4 - X3
  mov r8, [rsp + 320]
  sub r8, [rsp + 352]
  mov r10, [rsp + 320 + 8]
  sbb r10, [rsp + 352 + 8]
  mov r11, [rsp + 320 + 16]
  sbb r11, [rsp + 352 + 16]
  mov r12, [rsp + 320 + 24]
  sbb r12, [rsp + 352 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 320], r8
  mov [rsp + 328], r10
  mov [rsp + 336], r11
  mov [rsp + 344], r12
  // ModAdd X3 = X1 + Z1
  mov r8, [rsp + 0]
  add r8, [rsp + 64]
  mov r10, [rsp + 0 + 8]
  adc r10, [rsp + 64 + 8]
  mov r11, [rsp + 0 + 16]
  adc r11, [rsp + 64 + 16]
  mov r12, [rsp + 0 + 24]
  adc r12, [rsp + 64 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // ModAdd Y3 = X2 + Z2
  mov r8, [rsp + 96]
  add r8, [rsp + 160]
  mov r10, [rsp + 96 + 8]
  adc r10, [rsp + 160 + 8]
  mov r11, [rsp + 96 + 16]
  adc r11, [rsp + 160 + 16]
  mov r12, [rsp + 96 + 24]
  adc r12, [rsp + 160 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // mul X3 = X3 * Y3
  lea rsi, [rsp + 352]
  lea rdi, [rsp + 384]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul5:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul5
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // ModAdd Y3 = t0 + t2
  mov r8, [rsp + 192]
  add r8, [rsp + 256]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // ModSub Y3 = X3 - Y3
  mov r8, [rsp + 352]
  sub r8, [rsp + 384]
  mov r10, [rsp + 352 + 8]
  sbb r10, [rsp + 384 + 8]
  mov r11, [rsp + 352 + 16]
  sbb r11, [rsp + 384 + 16]
  mov r12, [rsp + 352 + 24]
  sbb r12, [rsp + 384 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // mulb Z3 = t2 * b
  lea rsi, [rsp + 256]
  lea rdi, [r9 + 304]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul6:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul6
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 416], r8
  mov [rsp + 424], r10
  mov [rsp + 432], r11
  mov [rsp + 440], r12
  // ModSub X3 = Y3 - Z3
  mov r8, [rsp + 384]
  sub r8, [rsp + 416]
  mov r10, [rsp + 384 + 8]
  sbb r10, [rsp + 416 + 8]
  mov r11, [rsp + 384 + 16]
  sbb r11, [rsp + 416 + 16]
  mov r12, [rsp + 384 + 24]
  sbb r12, [rsp + 416 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // ModAdd Z3 = X3 + X3
  mov r8, [rsp + 352]
  add r8, [rsp + 352]
  mov r10, [rsp + 352 + 8]
  adc r10, [rsp + 352 + 8]
  mov r11, [rsp + 352 + 16]
  adc r11, [rsp + 352 + 16]
  mov r12, [rsp + 352 + 24]
  adc r12, [rsp + 352 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 416], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 424], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 432], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 440], r12
  // ModAdd X3 = X3 + Z3
  mov r8, [rsp + 352]
  add r8, [rsp + 416]
  mov r10, [rsp + 352 + 8]
  adc r10, [rsp + 416 + 8]
  mov r11, [rsp + 352 + 16]
  adc r11, [rsp + 416 + 16]
  mov r12, [rsp + 352 + 24]
  adc r12, [rsp + 416 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // ModSub Z3 = t1 - X3
  mov r8, [rsp + 224]
  sub r8, [rsp + 352]
  mov r10, [rsp + 224 + 8]
  sbb r10, [rsp + 352 + 8]
  mov r11, [rsp + 224 + 16]
  sbb r11, [rsp + 352 + 16]
  mov r12, [rsp + 224 + 24]
  sbb r12, [rsp + 352 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 416], r8
  mov [rsp + 424], r10
  mov [rsp + 432], r11
  mov [rsp + 440], r12
  // ModAdd X3 = t1 + X3
  mov r8, [rsp + 224]
  add r8, [rsp + 352]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 352 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 352 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 352 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // mulb Y3 = Y3 * b
  lea rsi, [rsp + 384]
  lea rdi, [r9 + 304]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul7:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul7
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModAdd t1 = t2 + t2
  mov r8, [rsp + 256]
  add r8, [rsp + 256]
  mov r10, [rsp + 256 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 256 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 256 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 224], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 232], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 240], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 248], r12
  // ModAdd t2 = t1 + t2
  mov r8, [rsp + 224]
  add r8, [rsp + 256]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 256], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 264], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 272], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 280], r12
  // ModSub Y3 = Y3 - t2
  mov r8, [rsp + 384]
  sub r8, [rsp + 256]
  mov r10, [rsp + 384 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 384 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 384 + 24]
  sbb r12, [rsp + 256 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModSub Y3 = Y3 - t0
  mov r8, [rsp + 384]
  sub r8, [rsp + 192]
  mov r10, [rsp + 384 + 8]
  sbb r10, [rsp + 192 + 8]
  mov r11, [rsp + 384 + 16]
  sbb r11, [rsp + 192 + 16]
  mov r12, [rsp + 384 + 24]
  sbb r12, [rsp + 192 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModAdd t1 = Y3 + Y3
  mov r8, [rsp + 384]
  add r8, [rsp + 384]
  mov r10, [rsp + 384 + 8]
  adc r10, [rsp + 384 + 8]
  mov r11, [rsp + 384 + 16]
  adc r11, [rsp + 384 + 16]
  mov r12, [rsp + 384 + 24]
  adc r12, [rsp + 384 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 224], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 232], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 240], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 248], r12
  // ModAdd Y3 = t1 + Y3
  mov r8, [rsp + 224]
  add r8, [rsp + 384]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 384 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 384 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 384 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // ModAdd t1 = t0 + t0
  mov r8, [rsp + 192]
  add r8, [rsp + 192]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 192 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 192 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 192 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 224], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 232], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 240], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 248], r12
  // ModAdd t0 = t1 + t0
  mov r8, [rsp + 224]
  add r8, [rsp + 192]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 192 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 192 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 192 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 192], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 200], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 208], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 216], r12
  // ModSub t0 = t0 - t2
  mov r8, [rsp + 192]
  sub r8, [rsp + 256]
  mov r10, [rsp + 192 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 192 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 192 + 24]
  sbb r12, [rsp + 256 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 192], r8
  mov [rsp + 200], r10
  mov [rsp + 208], r11
  mov [rsp + 216], r12
  // mul t1 = t4 * Y3
  lea rsi, [rsp + 320]
  lea rdi, [rsp + 384]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul8:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul8
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // mul t2 = t0 * Y3
  lea rsi, [rsp + 192]
  lea rdi, [rsp + 384]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul9:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul9
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // mul Y3 = X3 * Z3
  lea rsi, [rsp + 352]
  lea rdi, [rsp + 416]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul10:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul10
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModAdd Y3 = Y3 + t2
  mov r8, [rsp + 384]
  add r8, [rsp + 256]
  mov r10, [rsp + 384 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 384 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 384 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // mul X3 = t3 * X3
  lea rsi, [rsp + 288]
  lea rdi, [rsp + 352]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul11:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul11
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // ModSub X3 = X3 - t1
  mov r8, [rsp + 352]
  sub r8, [rsp + 224]
  mov r10, [rsp + 352 + 8]
  sbb r10, [rsp + 224 + 8]
  mov r11, [rsp + 352 + 16]
  sbb r11, [rsp + 224 + 16]
  mov r12, [rsp + 352 + 24]
  sbb r12, [rsp + 224 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // mul Z3 = t4 * Z3
  lea rsi, [rsp + 320]
  lea rdi, [rsp + 416]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul12:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul12
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 416], r8
  mov [rsp + 424], r10
  mov [rsp + 432], r11
  mov [rsp + 440], r12
  // mul t1 = t3 * t0
  lea rsi, [rsp + 288]
  lea rdi, [rsp + 192]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256AddMul13:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256AddMul13
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // ModAdd Z3 = Z3 + t1
  mov r8, [rsp + 416]
  add r8, [rsp + 224]
  mov r10, [rsp + 416 + 8]
  adc r10, [rsp + 224 + 8]
  mov r11, [rsp + 416 + 16]
  adc r11, [rsp + 224 + 16]
  mov r12, [rsp + 416 + 24]
  adc r12, [rsp + 224 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 416], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 424], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 432], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 440], r12
  // store result point X3,Y3,Z3
  mov rcx, [rsp + 448]
  mov rax, [rsp + 352]
  mov [rcx + 0], rax
  mov rax, [rsp + 360]
  mov [rcx + 8], rax
  mov rax, [rsp + 368]
  mov [rcx + 16], rax
  mov rax, [rsp + 376]
  mov [rcx + 24], rax
  mov rax, [rsp + 384]
  mov [rcx + 72], rax
  mov rax, [rsp + 392]
  mov [rcx + 80], rax
  mov rax, [rsp + 400]
  mov [rcx + 88], rax
  mov rax, [rsp + 408]
  mov [rcx + 96], rax
  mov rax, [rsp + 416]
  mov [rcx + 144], rax
  mov rax, [rsp + 424]
  mov [rcx + 152], rax
  mov rax, [rsp + 432]
  mov [rcx + 160], rax
  mov rax, [rsp + 440]
  mov [rcx + 168], rax
  add rsp, 464
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
  {$ELSE}
    {$IFDEF CRYPTOLIB_FP_P256_POINTADDMIXED}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  sub rsp, 464
  mov [rsp + 448], rcx   // save output-point pointer
  // load input point P X,Y,Z into frame
  mov rax, [rdx + 0]
  mov [rsp + 0], rax
  mov rax, [rdx + 8]
  mov [rsp + 8], rax
  mov rax, [rdx + 16]
  mov [rsp + 16], rax
  mov rax, [rdx + 24]
  mov [rsp + 24], rax
  mov rax, [rdx + 72]
  mov [rsp + 32], rax
  mov rax, [rdx + 80]
  mov [rsp + 40], rax
  mov rax, [rdx + 88]
  mov [rsp + 48], rax
  mov rax, [rdx + 96]
  mov [rsp + 56], rax
  mov rax, [rdx + 144]
  mov [rsp + 64], rax
  mov rax, [rdx + 152]
  mov [rsp + 72], rax
  mov rax, [rdx + 160]
  mov [rsp + 80], rax
  mov rax, [rdx + 168]
  mov [rsp + 88], rax
  // load input point Q X,Y into frame
  mov rax, [r8 + 0]
  mov [rsp + 96], rax
  mov rax, [r8 + 8]
  mov [rsp + 104], rax
  mov rax, [r8 + 16]
  mov [rsp + 112], rax
  mov rax, [r8 + 24]
  mov [rsp + 120], rax
  mov rax, [r8 + 72]
  mov [rsp + 128], rax
  mov rax, [r8 + 80]
  mov [rsp + 136], rax
  mov rax, [r8 + 88]
  mov [rsp + 144], rax
  mov rax, [r8 + 96]
  mov [rsp + 152], rax
  // Q is affine: Z2 := MontOne (R mod p) off PCtx
  mov rax, [r9 + 160]
  mov [rsp + 160], rax
  mov rax, [r9 + 168]
  mov [rsp + 168], rax
  mov rax, [r9 + 176]
  mov [rsp + 176], rax
  mov rax, [r9 + 184]
  mov [rsp + 184], rax
  // mul t0 = X1 * X2
  lea rsi, [rsp + 0]
  lea rdi, [rsp + 96]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul0:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul0
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 192], r8
  mov [rsp + 200], r10
  mov [rsp + 208], r11
  mov [rsp + 216], r12
  // mul t1 = Y1 * Y2
  lea rsi, [rsp + 32]
  lea rdi, [rsp + 128]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul1:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul1
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // mul t2 = Z1 * Z2
  lea rsi, [rsp + 64]
  lea rdi, [rsp + 160]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul2:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul2
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // ModAdd t3 = X1 + Y1
  mov r8, [rsp + 0]
  add r8, [rsp + 32]
  mov r10, [rsp + 0 + 8]
  adc r10, [rsp + 32 + 8]
  mov r11, [rsp + 0 + 16]
  adc r11, [rsp + 32 + 16]
  mov r12, [rsp + 0 + 24]
  adc r12, [rsp + 32 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 288], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 296], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 304], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 312], r12
  // ModAdd t4 = X2 + Y2
  mov r8, [rsp + 96]
  add r8, [rsp + 128]
  mov r10, [rsp + 96 + 8]
  adc r10, [rsp + 128 + 8]
  mov r11, [rsp + 96 + 16]
  adc r11, [rsp + 128 + 16]
  mov r12, [rsp + 96 + 24]
  adc r12, [rsp + 128 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 320], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 328], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 336], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 344], r12
  // mul t3 = t3 * t4
  lea rsi, [rsp + 288]
  lea rdi, [rsp + 320]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul3:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul3
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModAdd t4 = t0 + t1
  mov r8, [rsp + 192]
  add r8, [rsp + 224]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 224 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 224 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 224 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 320], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 328], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 336], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 344], r12
  // ModSub t3 = t3 - t4
  mov r8, [rsp + 288]
  sub r8, [rsp + 320]
  mov r10, [rsp + 288 + 8]
  sbb r10, [rsp + 320 + 8]
  mov r11, [rsp + 288 + 16]
  sbb r11, [rsp + 320 + 16]
  mov r12, [rsp + 288 + 24]
  sbb r12, [rsp + 320 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModAdd t4 = Y1 + Z1
  mov r8, [rsp + 32]
  add r8, [rsp + 64]
  mov r10, [rsp + 32 + 8]
  adc r10, [rsp + 64 + 8]
  mov r11, [rsp + 32 + 16]
  adc r11, [rsp + 64 + 16]
  mov r12, [rsp + 32 + 24]
  adc r12, [rsp + 64 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 320], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 328], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 336], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 344], r12
  // ModAdd X3 = Y2 + Z2
  mov r8, [rsp + 128]
  add r8, [rsp + 160]
  mov r10, [rsp + 128 + 8]
  adc r10, [rsp + 160 + 8]
  mov r11, [rsp + 128 + 16]
  adc r11, [rsp + 160 + 16]
  mov r12, [rsp + 128 + 24]
  adc r12, [rsp + 160 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // mul t4 = t4 * X3
  lea rsi, [rsp + 320]
  lea rdi, [rsp + 352]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul4:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul4
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 320], r8
  mov [rsp + 328], r10
  mov [rsp + 336], r11
  mov [rsp + 344], r12
  // ModAdd X3 = t1 + t2
  mov r8, [rsp + 224]
  add r8, [rsp + 256]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // ModSub t4 = t4 - X3
  mov r8, [rsp + 320]
  sub r8, [rsp + 352]
  mov r10, [rsp + 320 + 8]
  sbb r10, [rsp + 352 + 8]
  mov r11, [rsp + 320 + 16]
  sbb r11, [rsp + 352 + 16]
  mov r12, [rsp + 320 + 24]
  sbb r12, [rsp + 352 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 320], r8
  mov [rsp + 328], r10
  mov [rsp + 336], r11
  mov [rsp + 344], r12
  // ModAdd X3 = X1 + Z1
  mov r8, [rsp + 0]
  add r8, [rsp + 64]
  mov r10, [rsp + 0 + 8]
  adc r10, [rsp + 64 + 8]
  mov r11, [rsp + 0 + 16]
  adc r11, [rsp + 64 + 16]
  mov r12, [rsp + 0 + 24]
  adc r12, [rsp + 64 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // ModAdd Y3 = X2 + Z2
  mov r8, [rsp + 96]
  add r8, [rsp + 160]
  mov r10, [rsp + 96 + 8]
  adc r10, [rsp + 160 + 8]
  mov r11, [rsp + 96 + 16]
  adc r11, [rsp + 160 + 16]
  mov r12, [rsp + 96 + 24]
  adc r12, [rsp + 160 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // mul X3 = X3 * Y3
  lea rsi, [rsp + 352]
  lea rdi, [rsp + 384]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul5:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul5
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // ModAdd Y3 = t0 + t2
  mov r8, [rsp + 192]
  add r8, [rsp + 256]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // ModSub Y3 = X3 - Y3
  mov r8, [rsp + 352]
  sub r8, [rsp + 384]
  mov r10, [rsp + 352 + 8]
  sbb r10, [rsp + 384 + 8]
  mov r11, [rsp + 352 + 16]
  sbb r11, [rsp + 384 + 16]
  mov r12, [rsp + 352 + 24]
  sbb r12, [rsp + 384 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // mulb Z3 = t2 * b
  lea rsi, [rsp + 256]
  lea rdi, [r9 + 304]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul6:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul6
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 416], r8
  mov [rsp + 424], r10
  mov [rsp + 432], r11
  mov [rsp + 440], r12
  // ModSub X3 = Y3 - Z3
  mov r8, [rsp + 384]
  sub r8, [rsp + 416]
  mov r10, [rsp + 384 + 8]
  sbb r10, [rsp + 416 + 8]
  mov r11, [rsp + 384 + 16]
  sbb r11, [rsp + 416 + 16]
  mov r12, [rsp + 384 + 24]
  sbb r12, [rsp + 416 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // ModAdd Z3 = X3 + X3
  mov r8, [rsp + 352]
  add r8, [rsp + 352]
  mov r10, [rsp + 352 + 8]
  adc r10, [rsp + 352 + 8]
  mov r11, [rsp + 352 + 16]
  adc r11, [rsp + 352 + 16]
  mov r12, [rsp + 352 + 24]
  adc r12, [rsp + 352 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 416], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 424], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 432], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 440], r12
  // ModAdd X3 = X3 + Z3
  mov r8, [rsp + 352]
  add r8, [rsp + 416]
  mov r10, [rsp + 352 + 8]
  adc r10, [rsp + 416 + 8]
  mov r11, [rsp + 352 + 16]
  adc r11, [rsp + 416 + 16]
  mov r12, [rsp + 352 + 24]
  adc r12, [rsp + 416 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // ModSub Z3 = t1 - X3
  mov r8, [rsp + 224]
  sub r8, [rsp + 352]
  mov r10, [rsp + 224 + 8]
  sbb r10, [rsp + 352 + 8]
  mov r11, [rsp + 224 + 16]
  sbb r11, [rsp + 352 + 16]
  mov r12, [rsp + 224 + 24]
  sbb r12, [rsp + 352 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 416], r8
  mov [rsp + 424], r10
  mov [rsp + 432], r11
  mov [rsp + 440], r12
  // ModAdd X3 = t1 + X3
  mov r8, [rsp + 224]
  add r8, [rsp + 352]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 352 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 352 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 352 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 352], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 360], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 368], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 376], r12
  // mulb Y3 = Y3 * b
  lea rsi, [rsp + 384]
  lea rdi, [r9 + 304]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul7:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul7
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModAdd t1 = t2 + t2
  mov r8, [rsp + 256]
  add r8, [rsp + 256]
  mov r10, [rsp + 256 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 256 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 256 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 224], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 232], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 240], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 248], r12
  // ModAdd t2 = t1 + t2
  mov r8, [rsp + 224]
  add r8, [rsp + 256]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 256], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 264], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 272], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 280], r12
  // ModSub Y3 = Y3 - t2
  mov r8, [rsp + 384]
  sub r8, [rsp + 256]
  mov r10, [rsp + 384 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 384 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 384 + 24]
  sbb r12, [rsp + 256 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModSub Y3 = Y3 - t0
  mov r8, [rsp + 384]
  sub r8, [rsp + 192]
  mov r10, [rsp + 384 + 8]
  sbb r10, [rsp + 192 + 8]
  mov r11, [rsp + 384 + 16]
  sbb r11, [rsp + 192 + 16]
  mov r12, [rsp + 384 + 24]
  sbb r12, [rsp + 192 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModAdd t1 = Y3 + Y3
  mov r8, [rsp + 384]
  add r8, [rsp + 384]
  mov r10, [rsp + 384 + 8]
  adc r10, [rsp + 384 + 8]
  mov r11, [rsp + 384 + 16]
  adc r11, [rsp + 384 + 16]
  mov r12, [rsp + 384 + 24]
  adc r12, [rsp + 384 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 224], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 232], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 240], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 248], r12
  // ModAdd Y3 = t1 + Y3
  mov r8, [rsp + 224]
  add r8, [rsp + 384]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 384 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 384 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 384 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // ModAdd t1 = t0 + t0
  mov r8, [rsp + 192]
  add r8, [rsp + 192]
  mov r10, [rsp + 192 + 8]
  adc r10, [rsp + 192 + 8]
  mov r11, [rsp + 192 + 16]
  adc r11, [rsp + 192 + 16]
  mov r12, [rsp + 192 + 24]
  adc r12, [rsp + 192 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 224], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 232], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 240], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 248], r12
  // ModAdd t0 = t1 + t0
  mov r8, [rsp + 224]
  add r8, [rsp + 192]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 192 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 192 + 16]
  mov r12, [rsp + 224 + 24]
  adc r12, [rsp + 192 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 192], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 200], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 208], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 216], r12
  // ModSub t0 = t0 - t2
  mov r8, [rsp + 192]
  sub r8, [rsp + 256]
  mov r10, [rsp + 192 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 192 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 192 + 24]
  sbb r12, [rsp + 256 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 192], r8
  mov [rsp + 200], r10
  mov [rsp + 208], r11
  mov [rsp + 216], r12
  // mul t1 = t4 * Y3
  lea rsi, [rsp + 320]
  lea rdi, [rsp + 384]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul8:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul8
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // mul t2 = t0 * Y3
  lea rsi, [rsp + 192]
  lea rdi, [rsp + 384]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul9:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul9
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // mul Y3 = X3 * Z3
  lea rsi, [rsp + 352]
  lea rdi, [rsp + 416]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul10:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul10
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 384], r8
  mov [rsp + 392], r10
  mov [rsp + 400], r11
  mov [rsp + 408], r12
  // ModAdd Y3 = Y3 + t2
  mov r8, [rsp + 384]
  add r8, [rsp + 256]
  mov r10, [rsp + 384 + 8]
  adc r10, [rsp + 256 + 8]
  mov r11, [rsp + 384 + 16]
  adc r11, [rsp + 256 + 16]
  mov r12, [rsp + 384 + 24]
  adc r12, [rsp + 256 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 384], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 392], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 400], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 408], r12
  // mul X3 = t3 * X3
  lea rsi, [rsp + 288]
  lea rdi, [rsp + 352]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul11:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul11
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // ModSub X3 = X3 - t1
  mov r8, [rsp + 352]
  sub r8, [rsp + 224]
  mov r10, [rsp + 352 + 8]
  sbb r10, [rsp + 224 + 8]
  mov r11, [rsp + 352 + 16]
  sbb r11, [rsp + 224 + 16]
  mov r12, [rsp + 352 + 24]
  sbb r12, [rsp + 224 + 24]
  sbb rcx, rcx
  mov r13, [r9 + 16]
  and r13, rcx
  mov r14, [r9 + 24]
  and r14, rcx
  mov r15, [r9 + 32]
  and r15, rcx
  mov rbx, [r9 + 40]
  and rbx, rcx
  add r8, r13
  adc r10, r14
  adc r11, r15
  adc r12, rbx
  mov [rsp + 352], r8
  mov [rsp + 360], r10
  mov [rsp + 368], r11
  mov [rsp + 376], r12
  // mul Z3 = t4 * Z3
  lea rsi, [rsp + 320]
  lea rdi, [rsp + 416]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul12:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul12
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 416], r8
  mov [rsp + 424], r10
  mov [rsp + 432], r11
  mov [rsp + 440], r12
  // mul t1 = t3 * t0
  lea rsi, [rsp + 288]
  lea rdi, [rsp + 192]
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@P256MixMul13:
  mov rdx, [rdi]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, [rsi]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, [rsi+0x8]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, [rsi+0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, [rsi+0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, r8            // m = t[0]  (n0' = 1)
  mov rbx, rdx
  shl rbx, 32            // rbx = low64(m<<32)
  mov r15, rdx
  shr r15, 32            // r15 = high32(m<<32)
  add r10, rbx          // t[1..] += m<<96  = (m<<32) at limb 1
  adc r11, r15
  adc r12, 0
  adc r13, 0
  adc r14, 0
  mov rax, rdx          // rax:rbx = m*p3 = m + m<<64 - m<<32 (128-bit, >= 0)
  sub rax, rbx
  mov rbx, rdx
  sbb rbx, r15
  add r12, rax          // t[3..] += m*p3 << 192  = m<<192 - m<<224 + m<<256
  adc r13, rbx
  adc r14, 0
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@P256MixMul13
  mov rax, r8
  sub rax, [r9+16]
  mov r15, rax
  mov rax, r10
  sbb rax, [r9+24]
  mov rbx, rax
  mov rax, r11
  sbb rax, [r9+32]
  mov rsi, rax
  mov rax, r12
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r13
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  and r15, rdx
  or r8, r15
  and r10, rcx
  and rbx, rdx
  or r10, rbx
  and r11, rcx
  and rsi, rdx
  or r11, rsi
  and r12, rcx
  and rdi, rdx
  or r12, rdi
  mov [rsp + 224], r8
  mov [rsp + 232], r10
  mov [rsp + 240], r11
  mov [rsp + 248], r12
  // ModAdd Z3 = Z3 + t1
  mov r8, [rsp + 416]
  add r8, [rsp + 224]
  mov r10, [rsp + 416 + 8]
  adc r10, [rsp + 224 + 8]
  mov r11, [rsp + 416 + 16]
  adc r11, [rsp + 224 + 16]
  mov r12, [rsp + 416 + 24]
  adc r12, [rsp + 224 + 24]
  mov r13d, 0
  adc r13, 0
  mov r14, r8
  sub r14, [r9 + 16]
  mov r15, r10
  sbb r15, [r9 + 24]
  mov rbx, r11
  sbb rbx, [r9 + 32]
  mov rsi, r12
  sbb rsi, [r9 + 40]
  sbb rdi, rdi
  mov rax, r13
  xor rax, 1
  and rax, rdi
  neg rax
  mov rcx, rax
  not rax
  and r8, rcx
  mov rdx, r14
  and rdx, rax
  or r8, rdx
  mov [rsp + 416], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 424], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 432], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 440], r12
  // store result point X3,Y3,Z3
  mov rcx, [rsp + 448]
  mov rax, [rsp + 352]
  mov [rcx + 0], rax
  mov rax, [rsp + 360]
  mov [rcx + 8], rax
  mov rax, [rsp + 368]
  mov [rcx + 16], rax
  mov rax, [rsp + 376]
  mov [rcx + 24], rax
  mov rax, [rsp + 384]
  mov [rcx + 72], rax
  mov rax, [rsp + 392]
  mov [rcx + 80], rax
  mov rax, [rsp + 400]
  mov [rcx + 88], rax
  mov rax, [rsp + 408]
  mov [rcx + 96], rax
  mov rax, [rsp + 416]
  mov [rcx + 144], rax
  mov rax, [rsp + 424]
  mov [rcx + 152], rax
  mov rax, [rsp + 432]
  mov [rcx + 160], rax
  mov rax, [rsp + 440]
  mov [rcx + 168], rax
  add rsp, 464
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_FP_P256_POINTDOUBLE, CRYPTOLIB_FP_P256_POINTADD, CRYPTOLIB_FP_P256_POINTADDMIXED must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
