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
  {$FATAL Exactly one of CRYPTOLIB_FP_MUL, CRYPTOLIB_FP_SQR must be defined before including this file}
  {$ENDIF}
{$ENDIF}
