// Prime-field (Fp) big-integer 64-bit-limb multiply/square kernels (x86-64).
// -------------------------------------------------------------------
//
// One selector-driven file per arch; exactly one of the following must be
// defined before including this file:
//
//   CRYPTOLIB_FP_MUL   (ClpSimdProc4Begin: rcx = PX, rdx = PY, r8 = PZ, r9 = N)
//     - schoolbook Z[0..2N-1] := X[0..N-1] * Y[0..N-1] over 64-bit limbs;
//       callers reinterpret 32-bit-limb field arrays (uint32[2N] == uint64[N]).
//   CRYPTOLIB_FP_SQR   (ClpSimdProc3Begin: rcx = PX, rdx = PZ, r8 = N)
//     - dedicated schoolbook square Z[0..2N-1] := X[0..N-1]^2 (off-diagonal
//       sum, double, then add the diagonal X[i]^2 terms).
//   CRYPTOLIB_FP_MONTMUL   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - fused CIOS Montgomery multiply PR := PA * PB * R^-1 mod p over 64-bit
//       limbs; PCtx = [n0', N, p[0..N-1]] with n0' = -p^-1 mod 2^64. PR is the
//       N+2-limb scratch and receives the fully-reduced N-limb result.
//       Reference: CIOS Montgomery multiplication (Koc-Acar-Kaliski).
//   CRYPTOLIB_FP_MONTMUL_MULX4   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - the same CIOS Montgomery multiply for N=4, register-resident with two
//       independent carry chains (MULX + ADCX/ADOX). Backend-gated on BMI2+ADX.
//       MULX/ADCX/ADOX are db-encoded for broad assembler compatibility.
//   CRYPTOLIB_FP_MONTMUL_MULX6   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - the same CIOS Montgomery multiply for N=6, fully unrolled and
//       register-resident with two carry chains (MULX + ADCX/ADOX).
//       Backend-gated on BMI2+ADX; MULX/ADCX/ADOX are db-encoded.
//   CRYPTOLIB_FP_MONTMUL_MULX9   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - the same CIOS Montgomery multiply for N=9 (P-521), fully unrolled;
//       9 of the 11 accumulator words stay in registers by spilling the PB
//       pointer, the top two bounce through a stack slot at the chain tails.
//       Backend-gated on BMI2+ADX; MULX/ADCX/ADOX are db-encoded.
//   CRYPTOLIB_FP_MONTMUL_MULX5   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - the same CIOS Montgomery multiply for N=5 (register-resident), MULX two-carry-chain.
//   CRYPTOLIB_FP_MONTMUL_MULX7   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - the same CIOS Montgomery multiply for N=7 (PB-spill, all-register), MULX two-carry-chain.
//   CRYPTOLIB_FP_MONTMUL_MULX8   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - the same CIOS Montgomery multiply for N=8 (PB-spill + 1 stack word), MULX two-carry-chain.
//   CRYPTOLIB_FP_MODADD / CRYPTOLIB_FP_MODSUB   (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//     - constant-time modular add / subtract R := (PA +/- PB) mod p over 64-bit
//       limbs (PCtx = [n0'(unused), N, p[0..N-1]]); inputs assumed < p.
//
// Constant-time: no data-dependent branches or memory addresses. The
// multiply and square each save and restore the callee-saved GPRs they
// use (the Proc-prologue itself pushes none on x86-64).
{$IFDEF CRYPTOLIB_FP_MUL}
  push rbx
  push rsi
  push rdi
  push r12
  push r13
  mov  rsi, rcx          // PX
  mov  rdi, rdx          // PY
                         // r8 = PZ, r9 = N
  lea  r10, [r9 + r9]    // 2N
  xor  rax, rax
  xor  r11, r11
@@FpMulZero:
  mov  [r8 + r11*8], rax
  inc  r11
  cmp  r11, r10
  jb   @@FpMulZero
  xor  r10, r10          // i
@@FpMulRow:
  mov  rbx, [rsi + r10*8] // X[i]
  xor  r12, r12          // carry
  xor  r11, r11          // j
@@FpMulCol:
  mov  rax, rbx
  mul  qword ptr [rdi + r11*8] // rdx:rax = X[i]*Y[j]
  add  rax, r12
  adc  rdx, 0
  mov  r13, r10
  add  r13, r11          // i+j
  add  rax, [r8 + r13*8]
  adc  rdx, 0
  mov  [r8 + r13*8], rax
  mov  r12, rdx          // carry
  inc  r11
  cmp  r11, r9
  jb   @@FpMulCol
  mov  r13, r10
  add  r13, r9           // i+N
  mov  [r8 + r13*8], r12
  inc  r10
  cmp  r10, r9
  jb   @@FpMulRow
  pop  r13
  pop  r12
  pop  rdi
  pop  rsi
  pop  rbx
{$ELSE}
  {$IFDEF CRYPTOLIB_FP_SQR}
  push rbx
  push rsi
  push rdi
  push r12
  push r13
  push r14
  mov  rsi, rcx          // PX
  mov  r9, r8            // N
  mov  r8, rdx           // PZ
  lea  r10, [r9 + r9]    // 2N
  xor  rax, rax
  xor  r11, r11
@@FpSqrZero:
  mov  [r8 + r11*8], rax
  inc  r11
  cmp  r11, r10
  jb   @@FpSqrZero
  // phase 1: off-diagonal sum (i in 0..N-2, j in i+1..N-1)
  xor  r10, r10          // i
@@FpSqrP1Row:
  mov  rcx, r9
  dec  rcx               // N-1
  cmp  r10, rcx
  jae  @@FpSqrP1Done
  mov  rbx, [rsi + r10*8] // X[i]
  xor  r12, r12          // carry
  lea  r11, [r10 + 1]    // j = i+1
@@FpSqrP1Col:
  mov  rax, rbx
  mul  qword ptr [rsi + r11*8] // X[i]*X[j]
  add  rax, r12
  adc  rdx, 0
  mov  r13, r10
  add  r13, r11          // i+j
  add  rax, [r8 + r13*8]
  adc  rdx, 0
  mov  [r8 + r13*8], rax
  mov  r12, rdx
  inc  r11
  cmp  r11, r9
  jb   @@FpSqrP1Col
  mov  r13, r10
  add  r13, r9           // i+N
  mov  [r8 + r13*8], r12
  inc  r10
  jmp  @@FpSqrP1Row
@@FpSqrP1Done:
  // phase 2: Z := 2*Z (shift-left by 1 across 2N words)
  xor  r12, r12          // carry bit
  lea  r10, [r9 + r9]    // 2N
  xor  r11, r11          // k
@@FpSqrP2:
  mov  rax, [r8 + r11*8]
  mov  r13, rax
  shr  r13, 63
  shl  rax, 1
  or   rax, r12
  mov  [r8 + r11*8], rax
  mov  r12, r13
  inc  r11
  cmp  r11, r10
  jb   @@FpSqrP2
  // phase 3: add diagonal X[i]^2 at position 2i
  xor  r12, r12          // carry-in word (0/1)
  xor  r10, r10          // i
@@FpSqrP3:
  mov  rax, [rsi + r10*8]
  mul  rax               // rdx:rax = X[i]^2
  lea  r11, [r10 + r10]  // 2i
  xor  r14, r14
  mov  r13, [r8 + r11*8]
  add  r13, rax
  adc  r14, 0
  add  r13, r12
  adc  r14, 0
  mov  [r8 + r11*8], r13
  xor  r12, r12
  mov  r13, [r8 + r11*8 + 8]
  add  r13, rdx
  adc  r12, 0
  add  r13, r14
  adc  r12, 0
  mov  [r8 + r11*8 + 8], r13
  inc  r10
  cmp  r10, r9
  jb   @@FpSqrP3
  pop  r14
  pop  r13
  pop  r12
  pop  rdi
  pop  rsi
  pop  rbx
  {$ELSE}
    {$IFDEF CRYPTOLIB_FP_MONTMUL}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  mov  rsi, rdx          // PA
  mov  rdi, rcx          // PR (N+2-limb scratch; receives the reduced N-limb result)
  mov  rbp, r8           // PB
  mov  r15, [r9 + 8]     // N (uint64 limbs)
  cmp  r15, 4
  jne  @@FpMontGeneral
  // ---- unrolled register-resident 4-limb CIOS (P-256 / secp256k1) ----
  // t0..t5 = r10..r15; b[i] from [rbp+8i]; a from [rsi]; p from [r9+16]; n0' [r9]
  xor  r10, r10
  xor  r11, r11
  xor  r12, r12
  xor  r13, r13
  xor  r14, r14
  xor  r15, r15
  mov  rbx, [rbp + 0]
  mov  rax, [rsi + 0]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [rsi + 8]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [rsi + 16]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  mov  rax, [rsi + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r13, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r15, 0
  adc  r15, 0
  mov  rbx, [r9]
  imul rbx, r10
  mov  rax, [r9 + 16]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  rcx, rdx
  mov  rax, [r9 + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [r9 + 32]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [r9 + 40]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r13, r14
  mov  rax, 0
  adc  rax, 0
  add  r15, rax
  mov  r14, r15
  mov  rbx, [rbp + 8]
  mov  rax, [rsi + 0]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [rsi + 8]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [rsi + 16]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  mov  rax, [rsi + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r13, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r15, 0
  adc  r15, 0
  mov  rbx, [r9]
  imul rbx, r10
  mov  rax, [r9 + 16]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  rcx, rdx
  mov  rax, [r9 + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [r9 + 32]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [r9 + 40]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r13, r14
  mov  rax, 0
  adc  rax, 0
  add  r15, rax
  mov  r14, r15
  mov  rbx, [rbp + 16]
  mov  rax, [rsi + 0]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [rsi + 8]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [rsi + 16]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  mov  rax, [rsi + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r13, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r15, 0
  adc  r15, 0
  mov  rbx, [r9]
  imul rbx, r10
  mov  rax, [r9 + 16]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  rcx, rdx
  mov  rax, [r9 + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [r9 + 32]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [r9 + 40]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r13, r14
  mov  rax, 0
  adc  rax, 0
  add  r15, rax
  mov  r14, r15
  mov  rbx, [rbp + 24]
  mov  rax, [rsi + 0]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [rsi + 8]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [rsi + 16]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  mov  rax, [rsi + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r13, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r15, 0
  adc  r15, 0
  mov  rbx, [r9]
  imul rbx, r10
  mov  rax, [r9 + 16]
  mul  rbx
  add  rax, r10
  adc  rdx, 0
  mov  rcx, rdx
  mov  rax, [r9 + 24]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r11
  adc  rdx, 0
  mov  r10, rax
  mov  rcx, rdx
  mov  rax, [r9 + 32]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r12
  adc  rdx, 0
  mov  r11, rax
  mov  rcx, rdx
  mov  rax, [r9 + 40]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, r13
  adc  rdx, 0
  mov  r12, rax
  mov  rcx, rdx
  add  r14, rcx
  mov  r13, r14
  mov  rax, 0
  adc  rax, 0
  add  r15, rax
  mov  r14, r15
  // constant-time final reduce (register-resident): t in r10..r14, subtract p
  mov  rax, r10
  sub  rax, [r9 + 16]
  mov  rbx, rax
  mov  rax, r11
  sbb  rax, [r9 + 24]
  mov  rsi, rax
  mov  rax, r12
  sbb  rax, [r9 + 32]
  mov  rbp, rax
  mov  rax, r13
  sbb  rax, [r9 + 40]
  mov  r8, rax
  mov  rax, r14
  sbb  rax, 0
  sbb  rdx, rdx          // mask = all-ones if t < p (keep t)
  mov  rcx, rdx
  not  rdx
  and  r10, rcx
  and  rbx, rdx
  or   r10, rbx
  and  r11, rcx
  and  rsi, rdx
  or   r11, rsi
  and  r12, rcx
  and  rbp, rdx
  or   r12, rbp
  and  r13, rcx
  and  r8, rdx
  or   r13, r8
  mov  [rdi + 0], r10
  mov  [rdi + 8], r11
  mov  [rdi + 16], r12
  mov  [rdi + 24], r13
  jmp  @@FpMontDone
@@FpMontGeneral:
  // ---- width-general loop (any N; used by P-384/P-521 and future widths) ----
  lea  r8, [r15 + 2]     // N+2
  xor  rax, rax
  xor  r13, r13
@@FpMontZero:
  mov  [rdi + r13*8], rax
  inc  r13
  cmp  r13, r8
  jb   @@FpMontZero
  xor  r14, r14          // i
@@FpMontRow:
  mov  r12, [rbp + r14*8] // b[i]
  // multiply row: t[0..N-1] += A * b[i], carry into t[N], t[N+1]
  xor  rcx, rcx          // carry
  xor  r13, r13          // j
@@FpMontMul:
  mov  rax, [rsi + r13*8]
  mul  r12
  add  rax, rcx
  adc  rdx, 0
  add  rax, [rdi + r13*8]
  adc  rdx, 0
  mov  [rdi + r13*8], rax
  mov  rcx, rdx
  inc  r13
  cmp  r13, r15
  jb   @@FpMontMul
  mov  rax, [rdi + r15*8] // t[N]
  add  rax, rcx
  mov  [rdi + r15*8], rax
  lea  rbx, [r15 + 1]
  mov  rax, 0
  adc  rax, 0
  mov  [rdi + rbx*8], rax // t[N+1]
  // reduce row: m = t[0]*n0'; t := (t + m*p) >> 64
  mov  rbx, [r9]          // n0'
  imul rbx, [rdi]         // m
  mov  rax, [r9 + 16]     // p[0]
  mul  rbx
  add  rax, [rdi]
  adc  rdx, 0
  mov  rcx, rdx           // carry (low limb discarded)
  mov  r13, 1
@@FpMontRed:
  mov  rax, [r9 + r13*8 + 16]
  mul  rbx
  add  rax, rcx
  adc  rdx, 0
  add  rax, [rdi + r13*8]
  adc  rdx, 0
  lea  r8, [r13 - 1]
  mov  [rdi + r8*8], rax  // t[j-1]
  mov  rcx, rdx
  inc  r13
  cmp  r13, r15
  jb   @@FpMontRed
  mov  rax, [rdi + r15*8] // t[N]
  add  rax, rcx
  lea  r8, [r15 - 1]
  mov  [rdi + r8*8], rax  // t[N-1]
  mov  rax, 0
  adc  rax, 0
  lea  r8, [r15 + 1]
  mov  rdx, [rdi + r8*8]  // t[N+1]
  add  rax, rdx
  mov  [rdi + r15*8], rax // t[N]
  inc  r14
  cmp  r14, r15
  jb   @@FpMontRow
  // constant-time final reduce: t (< 2p) -= p, add p back if it underflowed
  xor  r8, r8            // borrow
  xor  r13, r13
@@FpMontFSub:
  mov  rax, [rdi + r13*8]
  sub  rax, r8
  sbb  rsi, rsi
  sub  rax, [r9 + r13*8 + 16]
  sbb  rbp, rbp
  mov  [rdi + r13*8], rax
  add  rsi, rbp
  neg  rsi
  mov  r8, rsi
  inc  r13
  cmp  r13, r15
  jb   @@FpMontFSub
  mov  rax, [rdi + r15*8]
  sub  rax, r8
  sbb  rdx, rdx          // mask = all-ones if t < p (add-back needed)
  mov  [rdi + r15*8], rax
  xor  r8, r8            // carry
  xor  r13, r13
@@FpMontFAdd:
  mov  rax, [r9 + r13*8 + 16]
  and  rax, rdx
  add  rax, [rdi + r13*8]
  mov  rcx, 0
  adc  rcx, 0
  add  rax, r8
  adc  rcx, 0
  mov  [rdi + r13*8], rax
  mov  r8, rcx
  inc  r13
  cmp  r13, r15
  jb   @@FpMontFAdd
@@FpMontDone:
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  rbp
  pop  rdi
  pop  rsi
  pop  rbx
    {$ELSE}
      {$IFDEF CRYPTOLIB_FP_MONTMUL_MULX4}
  push rbx
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  push rcx
  mov rsi, rdx
  mov rdi, r8
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  mov ecx, 4
@@FpMontMulxRow:
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
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  xor r14, r14
  add rdi, 8
  dec ecx
  jnz @@FpMontMulxRow
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
  mov rax, [rsp]
  mov [rax+0], r8
  mov [rax+8], r10
  mov [rax+16], r11
  mov [rax+24], r12
  add rsp, 8
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbx
      {$ELSE}
        {$IFDEF CRYPTOLIB_FP_MONTMUL_MULX6}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  push rcx
  mov rsi, rdx
  mov rdi, r8
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor rbp, rbp
  xor rcx, rcx
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  xor rcx, rcx
  mov rdx, [rdi+8]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  xor rcx, rcx
  mov rdx, [rdi+16]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  xor rcx, rcx
  mov rdx, [rdi+24]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  xor rcx, rcx
  mov rdx, [rdi+32]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  xor rcx, rcx
  mov rdx, [rdi+40]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  db $F3, $48, $0F, $38, $F6, $C8  // adox rcx, rax
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  xor rcx, rcx
  mov rsi, [rsp]
  mov rax, r8
  sub rax, [r9+16]
  mov [rsi], rax
  mov rax, r10
  sbb rax, [r9+24]
  mov [rsi+8], rax
  mov rax, r11
  sbb rax, [r9+32]
  mov [rsi+16], rax
  mov rax, r12
  sbb rax, [r9+40]
  mov [rsi+24], rax
  mov rax, r13
  sbb rax, [r9+48]
  mov [rsi+32], rax
  mov rax, r14
  sbb rax, [r9+56]
  mov [rsi+40], rax
  mov rax, rbp
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  mov rax, [rsi]
  and rax, rdx
  or r8, rax
  mov [rsi], r8
  and r10, rcx
  mov rax, [rsi+8]
  and rax, rdx
  or r10, rax
  mov [rsi+8], r10
  and r11, rcx
  mov rax, [rsi+16]
  and rax, rdx
  or r11, rax
  mov [rsi+16], r11
  and r12, rcx
  mov rax, [rsi+24]
  and rax, rdx
  or r12, rax
  mov [rsi+24], r12
  and r13, rcx
  mov rax, [rsi+32]
  and rax, rdx
  or r13, rax
  mov [rsi+32], r13
  and r14, rcx
  mov rax, [rsi+40]
  and rax, rdx
  or r14, rax
  mov [rsi+40], r14
  add rsp, 8
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rdi
  pop rsi
  pop rbx
        {$ELSE}
          {$IFDEF CRYPTOLIB_FP_MONTMUL_MULX9}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  sub rsp, 32
  mov [rsp], rcx
  mov [rsp+8], r8
  mov rsi, rdx
  xor eax, eax
  mov [rsp+16], rax
  mov [rsp+24], rax
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor rbp, rbp
  xor rcx, rcx
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+8]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+16]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+24]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+32]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+40]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+48]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+56]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rax, [rsp+8]
  mov rdx, [rax+64]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $E2, $83, $F6, $5E, $40  // mulx rbx, r15, [rsi+0x40]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  db $C4, $C2, $83, $F6, $59, $50  // mulx rbx, r15, [r9+0x50]
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $48, $0F, $38, $F6, $C3  // adox rax, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rax, [rsp+24]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+24], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  mov rax, [rsp+24]
  mov [rsp+16], rax
  xor eax, eax
  mov [rsp+24], rax
  mov rsi, [rsp]
  mov rax, r8
  sub rax, [r9+16]
  mov [rsi], rax
  mov rax, r10
  sbb rax, [r9+24]
  mov [rsi+8], rax
  mov rax, r11
  sbb rax, [r9+32]
  mov [rsi+16], rax
  mov rax, r12
  sbb rax, [r9+40]
  mov [rsi+24], rax
  mov rax, r13
  sbb rax, [r9+48]
  mov [rsi+32], rax
  mov rax, r14
  sbb rax, [r9+56]
  mov [rsi+40], rax
  mov rax, rbp
  sbb rax, [r9+64]
  mov [rsi+48], rax
  mov rax, rcx
  sbb rax, [r9+72]
  mov [rsi+56], rax
  mov rax, rdi
  sbb rax, [r9+80]
  mov [rsi+64], rax
  mov rax, [rsp+16]
  sbb rax, 0
  sbb rdx, rdx
  mov rbx, rdx
  not rdx
  and r8, rbx
  mov rax, [rsi]
  and rax, rdx
  or r8, rax
  mov [rsi], r8
  and r10, rbx
  mov rax, [rsi+8]
  and rax, rdx
  or r10, rax
  mov [rsi+8], r10
  and r11, rbx
  mov rax, [rsi+16]
  and rax, rdx
  or r11, rax
  mov [rsi+16], r11
  and r12, rbx
  mov rax, [rsi+24]
  and rax, rdx
  or r12, rax
  mov [rsi+24], r12
  and r13, rbx
  mov rax, [rsi+32]
  and rax, rdx
  or r13, rax
  mov [rsi+32], r13
  and r14, rbx
  mov rax, [rsi+40]
  and rax, rdx
  or r14, rax
  mov [rsi+40], r14
  and rbp, rbx
  mov rax, [rsi+48]
  and rax, rdx
  or rbp, rax
  mov [rsi+48], rbp
  and rcx, rbx
  mov rax, [rsi+56]
  and rax, rdx
  or rcx, rax
  mov [rsi+56], rcx
  and rdi, rbx
  mov rax, [rsi+64]
  and rax, rdx
  or rdi, rax
  mov [rsi+64], rdi
  add rsp, 32
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rdi
  pop rsi
  pop rbx
          {$ELSE}
            {$IFDEF CRYPTOLIB_FP_MONTMUL_MULX5}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  push rcx
  mov rsi, rdx
  mov rdi, r8
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor rbp, rbp
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  xor rbp, rbp
  mov rdx, [rdi+8]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  xor rbp, rbp
  mov rdx, [rdi+16]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  xor rbp, rbp
  mov rdx, [rdi+24]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  xor rbp, rbp
  mov rdx, [rdi+32]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $48, $0F, $38, $F6, $E8  // adox rbp, rax
  db $66, $48, $0F, $38, $F6, $E8  // adcx rbp, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  xor rbp, rbp
  mov rsi, [rsp]
  mov rax, r8
  sub rax, [r9+16]
  mov [rsi], rax
  mov rax, r10
  sbb rax, [r9+24]
  mov [rsi+8], rax
  mov rax, r11
  sbb rax, [r9+32]
  mov [rsi+16], rax
  mov rax, r12
  sbb rax, [r9+40]
  mov [rsi+24], rax
  mov rax, r13
  sbb rax, [r9+48]
  mov [rsi+32], rax
  mov rax, r14
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r8, rcx
  mov rax, [rsi]
  and rax, rdx
  or r8, rax
  mov [rsi], r8
  and r10, rcx
  mov rax, [rsi+8]
  and rax, rdx
  or r10, rax
  mov [rsi+8], r10
  and r11, rcx
  mov rax, [rsi+16]
  and rax, rdx
  or r11, rax
  mov [rsi+16], r11
  and r12, rcx
  mov rax, [rsi+24]
  and rax, rdx
  or r12, rax
  mov [rsi+24], r12
  and r13, rcx
  mov rax, [rsi+32]
  and rax, rdx
  or r13, rax
  mov [rsi+32], r13
  add rsp, 8
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rdi
  pop rsi
  pop rbx
            {$ELSE}
              {$IFDEF CRYPTOLIB_FP_MONTMUL_MULX7}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  sub rsp, 32
  mov [rsp], rcx
  mov [rsp+8], r8
  mov rsi, rdx
  xor eax, eax
  mov [rsp+16], rax
  mov [rsp+24], rax
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor rbp, rbp
  xor rcx, rcx
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax+8]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax+16]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax+24]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax+32]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax+40]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax+48]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $C8  // adcx rcx, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  xor rdi, rdi
  mov rsi, [rsp]
  mov rax, r8
  sub rax, [r9+16]
  mov [rsi], rax
  mov rax, r10
  sbb rax, [r9+24]
  mov [rsi+8], rax
  mov rax, r11
  sbb rax, [r9+32]
  mov [rsi+16], rax
  mov rax, r12
  sbb rax, [r9+40]
  mov [rsi+24], rax
  mov rax, r13
  sbb rax, [r9+48]
  mov [rsi+32], rax
  mov rax, r14
  sbb rax, [r9+56]
  mov [rsi+40], rax
  mov rax, rbp
  sbb rax, [r9+64]
  mov [rsi+48], rax
  mov rax, rcx
  sbb rax, 0
  sbb rdx, rdx
  mov rbx, rdx
  not rdx
  and r8, rbx
  mov rax, [rsi]
  and rax, rdx
  or r8, rax
  mov [rsi], r8
  and r10, rbx
  mov rax, [rsi+8]
  and rax, rdx
  or r10, rax
  mov [rsi+8], r10
  and r11, rbx
  mov rax, [rsi+16]
  and rax, rdx
  or r11, rax
  mov [rsi+16], r11
  and r12, rbx
  mov rax, [rsi+24]
  and rax, rdx
  or r12, rax
  mov [rsi+24], r12
  and r13, rbx
  mov rax, [rsi+32]
  and rax, rdx
  or r13, rax
  mov [rsi+32], r13
  and r14, rbx
  mov rax, [rsi+40]
  and rax, rdx
  or r14, rax
  mov [rsi+40], r14
  and rbp, rbx
  mov rax, [rsi+48]
  and rax, rdx
  or rbp, rax
  mov [rsi+48], rbp
  add rsp, 32
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rdi
  pop rsi
  pop rbx
              {$ELSE}
                {$IFDEF CRYPTOLIB_FP_MONTMUL_MULX8}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  sub rsp, 32
  mov [rsp], rcx
  mov [rsp+8], r8
  mov rsi, rdx
  xor eax, eax
  mov [rsp+16], rax
  mov [rsp+24], rax
  xor r8, r8
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor rbp, rbp
  xor rcx, rcx
  xor rdi, rdi
  mov rax, [rsp+8]
  mov rdx, [rax]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rax, [rsp+8]
  mov rdx, [rax+8]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rax, [rsp+8]
  mov rdx, [rax+16]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rax, [rsp+8]
  mov rdx, [rax+24]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rax, [rsp+8]
  mov rdx, [rax+32]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rax, [rsp+8]
  mov rdx, [rax+40]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rax, [rsp+8]
  mov rdx, [rax+48]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rax, [rsp+8]
  mov rdx, [rax+56]
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
  db $C4, $E2, $83, $F6, $5E, $20  // mulx rbx, r15, [rsi+0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $28  // mulx rbx, r15, [rsi+0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $E2, $83, $F6, $5E, $30  // mulx rbx, r15, [rsi+0x30]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $E2, $83, $F6, $5E, $38  // mulx rbx, r15, [rsi+0x38]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, [r9+0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, [r9+0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, [r9+0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, [r9+0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $30  // mulx rbx, r15, [r9+0x30]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $38  // mulx rbx, r15, [r9+0x38]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $48, $0F, $38, $F6, $EB  // adox rbp, rbx
  db $C4, $C2, $83, $F6, $59, $40  // mulx rbx, r15, [r9+0x40]
  db $66, $49, $0F, $38, $F6, $EF  // adcx rbp, r15
  db $F3, $48, $0F, $38, $F6, $CB  // adox rcx, rbx
  db $C4, $C2, $83, $F6, $59, $48  // mulx rbx, r15, [r9+0x48]
  db $66, $49, $0F, $38, $F6, $CF  // adcx rcx, r15
  db $F3, $48, $0F, $38, $F6, $FB  // adox rdi, rbx
  mov r15d, 0
  db $66, $49, $0F, $38, $F6, $FF  // adcx rdi, r15
  mov rax, [rsp+16]
  db $F3, $49, $0F, $38, $F6, $C7  // adox rax, r15
  db $66, $49, $0F, $38, $F6, $C7  // adcx rax, r15
  mov [rsp+16], rax
  mov r8, r10
  mov r10, r11
  mov r11, r12
  mov r12, r13
  mov r13, r14
  mov r14, rbp
  mov rbp, rcx
  mov rcx, rdi
  mov rdi, [rsp+16]
  xor eax, eax
  mov [rsp+16], rax
  mov rsi, [rsp]
  mov rax, r8
  sub rax, [r9+16]
  mov [rsi], rax
  mov rax, r10
  sbb rax, [r9+24]
  mov [rsi+8], rax
  mov rax, r11
  sbb rax, [r9+32]
  mov [rsi+16], rax
  mov rax, r12
  sbb rax, [r9+40]
  mov [rsi+24], rax
  mov rax, r13
  sbb rax, [r9+48]
  mov [rsi+32], rax
  mov rax, r14
  sbb rax, [r9+56]
  mov [rsi+40], rax
  mov rax, rbp
  sbb rax, [r9+64]
  mov [rsi+48], rax
  mov rax, rcx
  sbb rax, [r9+72]
  mov [rsi+56], rax
  mov rax, rdi
  sbb rax, 0
  sbb rdx, rdx
  mov rbx, rdx
  not rdx
  and r8, rbx
  mov rax, [rsi]
  and rax, rdx
  or r8, rax
  mov [rsi], r8
  and r10, rbx
  mov rax, [rsi+8]
  and rax, rdx
  or r10, rax
  mov [rsi+8], r10
  and r11, rbx
  mov rax, [rsi+16]
  and rax, rdx
  or r11, rax
  mov [rsi+16], r11
  and r12, rbx
  mov rax, [rsi+24]
  and rax, rdx
  or r12, rax
  mov [rsi+24], r12
  and r13, rbx
  mov rax, [rsi+32]
  and rax, rdx
  or r13, rax
  mov [rsi+32], r13
  and r14, rbx
  mov rax, [rsi+40]
  and rax, rdx
  or r14, rax
  mov [rsi+40], r14
  and rbp, rbx
  mov rax, [rsi+48]
  and rax, rdx
  or rbp, rax
  mov [rsi+48], rbp
  and rcx, rbx
  mov rax, [rsi+56]
  and rax, rdx
  or rcx, rax
  mov [rsi+56], rcx
  add rsp, 32
  pop r15
  pop r14
  pop r13
  pop r12
  pop rbp
  pop rdi
  pop rsi
  pop rbx
                {$ELSE}
                  {$IFDEF CRYPTOLIB_FP_MODADD}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  mov  rsi, rdx          // PA
  mov  rdi, r8           // PB
  mov  r8, rcx           // PR
  mov  r15, [r9 + 8]     // N
  // R := A + B (top carry in r11)
  xor  r11d, r11d
  xor  rbx, rbx
@@FpModAddSum:
  mov  rax, [rsi + rbx*8]
  add  rax, [rdi + rbx*8]
  mov  r12d, 0
  adc  r12, 0
  add  rax, r11
  adc  r12, 0
  mov  [r8 + rbx*8], rax
  mov  r11, r12
  inc  rbx
  cmp  rbx, r15
  jb   @@FpModAddSum
  // R := R - p (borrow in r12)
  xor  r12d, r12d
  xor  rbx, rbx
@@FpModAddSub:
  mov  rax, [r8 + rbx*8]
  sub  rax, r12
  sbb  r13, r13
  sub  rax, [r9 + rbx*8 + 16]
  sbb  r14, r14
  mov  [r8 + rbx*8], rax
  add  r13, r14
  neg  r13
  mov  r12, r13
  inc  rbx
  cmp  rbx, r15
  jb   @@FpModAddSub
  // constant-time add-back of p iff (carry=0 and borrow=1); mask in rdx
  mov  rax, r11
  xor  rax, 1
  and  rax, r12
  neg  rax
  mov  rdx, rax
  xor  r11d, r11d
  xor  rbx, rbx
@@FpModAddBack:
  mov  rax, [r9 + rbx*8 + 16]
  and  rax, rdx
  add  rax, [r8 + rbx*8]
  mov  r13d, 0
  adc  r13, 0
  add  rax, r11
  adc  r13, 0
  mov  [r8 + rbx*8], rax
  mov  r11, r13
  inc  rbx
  cmp  rbx, r15
  jb   @@FpModAddBack
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  rbp
  pop  rdi
  pop  rsi
  pop  rbx
                  {$ELSE}
                    {$IFDEF CRYPTOLIB_FP_MODSUB}
  push rbx
  push rsi
  push rdi
  push rbp
  push r12
  push r13
  push r14
  push r15
  mov  rsi, rdx          // PA
  mov  rdi, r8           // PB
  mov  r8, rcx           // PR
  mov  r15, [r9 + 8]     // N
  // R := A - B (top borrow in r11)
  xor  r11d, r11d
  xor  rbx, rbx
@@FpModSubDiff:
  mov  rax, [rsi + rbx*8]
  sub  rax, r11
  sbb  r12, r12
  sub  rax, [rdi + rbx*8]
  sbb  r13, r13
  mov  [r8 + rbx*8], rax
  add  r12, r13
  neg  r12
  mov  r11, r12
  inc  rbx
  cmp  rbx, r15
  jb   @@FpModSubDiff
  // constant-time add-back of p iff we borrowed (A < B); mask in rdx
  mov  rdx, r11
  neg  rdx
  xor  r11d, r11d
  xor  rbx, rbx
@@FpModSubBack:
  mov  rax, [r9 + rbx*8 + 16]
  and  rax, rdx
  add  rax, [r8 + rbx*8]
  mov  r13d, 0
  adc  r13, 0
  add  rax, r11
  adc  r13, 0
  mov  [r8 + rbx*8], rax
  mov  r11, r13
  inc  rbx
  cmp  rbx, r15
  jb   @@FpModSubBack
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  rbp
  pop  rdi
  pop  rsi
  pop  rbx
                    {$ELSE}
                    {$FATAL Exactly one of CRYPTOLIB_FP_MUL, CRYPTOLIB_FP_SQR, CRYPTOLIB_FP_MONTMUL, CRYPTOLIB_FP_MONTMUL_MULX4, CRYPTOLIB_FP_MONTMUL_MULX6, CRYPTOLIB_FP_MONTMUL_MULX9, CRYPTOLIB_FP_MONTMUL_MULX5, CRYPTOLIB_FP_MONTMUL_MULX7, CRYPTOLIB_FP_MONTMUL_MULX8, CRYPTOLIB_FP_MODADD, CRYPTOLIB_FP_MODSUB must be defined before including this file}
                    {$ENDIF}
                  {$ENDIF}
                {$ENDIF}
              {$ENDIF}
            {$ENDIF}
          {$ENDIF}
        {$ENDIF}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
