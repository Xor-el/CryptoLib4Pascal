// Curve25519 radix-2^64 (saturated, 4 x 64-bit limbs) field primitives and the
// fused Montgomery ladder step (x86-64, BMI2 + ADX).
// -------------------------------------------------------------------
//
// Selector-driven; exactly one of the following must be defined before including:
//
//   CRYPTOLIB_CURVE25519_SAT64MUL     PH := PF * PG       mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64SQR     PH := PF^2          mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64ADD     PH := PF + PG       mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64SUB     PH := PF - PG       mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64M121666 PH := PF * 121666   mod (2^255-19)
//   CRYPTOLIB_CURVE25519_SAT64SQRN    PH := PF^(2^AN)     mod (2^255-19), AN >= 1
//   CRYPTOLIB_CURVE25519_SAT64LADDER  one Montgomery ladder step + cswap
//
// Representation: 4 x 64-bit limbs, radix 2^64 (limb i at [ptr+8i]) - the RFC 7748
// byte layout. Inputs are loosely reduced (value < 2^256); outputs form a value
// < 2^256 congruent mod p, reusable as inputs.
//
// Entry: PH/PF/PG via ClpSimdProc3Begin_x86_64 (rcx/rdx/r8); two-arg forms via
// ClpSimdProc2Begin_x86_64 (rcx/rdx). SAT64LADDER: rcx = PState (x1,x2,z2,x3,z3
// contiguous, 4 limbs each), rdx = swap mask (0 or all-ones).
//
// MULX/ADCX/ADOX are db-encoded for broad assembler compatibility. Two-carry-chain
// product (ADCX = low halves, ADOX = high halves); the 2^255-19 pseudo-Mersenne
// reduction folds the high half in with x38, unconditionally. Constant-time: no
// data-dependent branches or addresses (cswap is masked; the SAT64SQRN loop
// counter AN is a public value, not a secret).


{$IFDEF CRYPTOLIB_CURVE25519_SAT64MUL}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov rsi, rdx
  mov rdi, r8
  mov rdx, qword ptr [rdi]
  db $C4, $62, $BB, $F6, $0E       // mulx r9, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $56, $08  // mulx r10, rbx, qword ptr [rsi + 8]
  db $C4, $62, $FB, $F6, $5E, $10  // mulx r11, rax, qword ptr [rsi + 0x10]
  db $C4, $62, $D3, $F6, $66, $18  // mulx r12, rbp, qword ptr [rsi + 0x18]
  xor r13d, r13d
  add r9, rbx
  adc r10, rax
  adc r11, rbp
  adc r12, 0
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rdi+8]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $1E       // mulx rbx, rax, qword ptr [rsi]
  db $66, $4C, $0F, $38, $F6, $C8  // adcx r9, rax
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $E2, $FB, $F6, $5E, $08  // mulx rbx, rax, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E0  // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED  // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5  // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  mov rdx, qword ptr [rdi+16]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $1E       // mulx rbx, rax, qword ptr [rsi]
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $FB, $F6, $5E, $08  // mulx rbx, rax, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E0  // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD  // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD  // adcx r15, rbp
  mov rdx, qword ptr [rdi+24]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $1E       // mulx rbx, rax, qword ptr [rsi]
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5E, $08  // mulx rbx, rax, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $E0  // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  db $66, $4C, $0F, $38, $F6, $FD  // adcx r15, rbp
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4       // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED       // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6       // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF       // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx], r8
  mov qword ptr [rcx+8], r9
  mov qword ptr [rcx+16], r10
  mov qword ptr [rcx+24], r11
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE25519_SAT64MUL}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64SQR}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov rsi, rdx
  mov rdx, qword ptr [rsi]
  db $C4, $62, $B3, $F6, $56, $08  // mulx r10, r9, qword ptr [rsi + 8]
  db $C4, $62, $E3, $F6, $5E, $10  // mulx r11, rbx, qword ptr [rsi + 0x10]
  db $C4, $62, $FB, $F6, $66, $18  // mulx r12, rax, qword ptr [rsi + 0x18]
  xor r13d, r13d
  add r10, rbx
  adc r11, rax
  adc r12, 0
  xor r8d, r8d
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rsi+8]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E0  // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED  // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5  // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  mov rdx, qword ptr [rsi+16]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD  // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD  // adcx r15, rbp
  add r8, r8
  adc r9, r9
  adc r10, r10
  adc r11, r11
  adc r12, r12
  adc r13, r13
  adc r14, r14
  adc r15, r15
  mov rdx, qword ptr [rsi]
  db $C4, $E2, $FB, $F6, $1E       // mulx rbx, rax, qword ptr [rsi]
  add r8, rax
  adc r9, rbx
  mov rdx, qword ptr [rsi+8]
  db $C4, $E2, $FB, $F6, $5E, $08  // mulx rbx, rax, qword ptr [rsi + 8]
  adc r10, rax
  adc r11, rbx
  mov rdx, qword ptr [rsi+16]
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  adc r12, rax
  adc r13, rbx
  mov rdx, qword ptr [rsi+24]
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  adc r14, rax
  adc r15, rbx
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4       // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED       // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6       // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF       // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx], r8
  mov qword ptr [rcx+8], r9
  mov qword ptr [rcx+16], r10
  mov qword ptr [rcx+24], r11
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE25519_SAT64SQR}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64ADD}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov rsi, rdx
  mov rdi, r8
  mov r8, qword ptr [rsi]
  add r8, qword ptr [rdi]
  mov r9, qword ptr [rsi+8]
  adc r9, qword ptr [rdi+8]
  mov r10, qword ptr [rsi+16]
  adc r10, qword ptr [rdi+16]
  mov r11, qword ptr [rsi+24]
  adc r11, qword ptr [rdi+24]
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx], r8
  mov qword ptr [rcx+8], r9
  mov qword ptr [rcx+16], r10
  mov qword ptr [rcx+24], r11
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE25519_SAT64ADD}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64SUB}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov rsi, rdx
  mov rdi, r8
  mov r8, qword ptr [rsi]
  sub r8, qword ptr [rdi]
  mov r9, qword ptr [rsi+8]
  sbb r9, qword ptr [rdi+8]
  mov r10, qword ptr [rsi+16]
  sbb r10, qword ptr [rdi+16]
  mov r11, qword ptr [rsi+24]
  sbb r11, qword ptr [rdi+24]
  mov ebx, 0
  adc ebx, 0
  sub r8, 76
  sbb r9, 0
  sbb r10, 0
  sbb r11, 0
  mov ebp, 0
  adc ebp, 0
  mov rax, 2
  sub rax, rbx
  sub rax, rbp
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx], r8
  mov qword ptr [rcx+8], r9
  mov qword ptr [rcx+16], r10
  mov qword ptr [rcx+24], r11
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE25519_SAT64SUB}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64M121666}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov rsi, rdx
  mov rdx, 121666
  xor ebp, ebp
  db $C4, $E2, $FB, $F6, $1E       // mulx rbx, rax, qword ptr [rsi]
  mov r8, rax
  mov rbp, rbx
  db $C4, $E2, $FB, $F6, $5E, $08  // mulx rbx, rax, qword ptr [rsi + 8]
  add rax, rbp
  adc rbx, 0
  mov r9, rax
  mov rbp, rbx
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  add rax, rbp
  adc rbx, 0
  mov r10, rax
  mov rbp, rbx
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  add rax, rbp
  adc rbx, 0
  mov r11, rax
  mov rbp, rbx
  mov rax, rbp
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx], r8
  mov qword ptr [rcx+8], r9
  mov qword ptr [rcx+16], r10
  mov qword ptr [rcx+24], r11
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE25519_SAT64M121666}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64SQRN}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov rsi, rdx
  mov rdi, r8
  mov rdx, qword ptr [rsi]
  db $C4, $62, $B3, $F6, $56, $08  // mulx r10, r9, qword ptr [rsi + 8]
  db $C4, $62, $E3, $F6, $5E, $10  // mulx r11, rbx, qword ptr [rsi + 0x10]
  db $C4, $62, $FB, $F6, $66, $18  // mulx r12, rax, qword ptr [rsi + 0x18]
  xor r13d, r13d
  add r10, rbx
  adc r11, rax
  adc r12, 0
  xor r8d, r8d
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rsi+8]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E0  // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED  // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5  // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  mov rdx, qword ptr [rsi+16]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD  // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD  // adcx r15, rbp
  add r8, r8
  adc r9, r9
  adc r10, r10
  adc r11, r11
  adc r12, r12
  adc r13, r13
  adc r14, r14
  adc r15, r15
  mov rdx, qword ptr [rsi]
  db $C4, $E2, $FB, $F6, $1E       // mulx rbx, rax, qword ptr [rsi]
  add r8, rax
  adc r9, rbx
  mov rdx, qword ptr [rsi+8]
  db $C4, $E2, $FB, $F6, $5E, $08  // mulx rbx, rax, qword ptr [rsi + 8]
  adc r10, rax
  adc r11, rbx
  mov rdx, qword ptr [rsi+16]
  db $C4, $E2, $FB, $F6, $5E, $10  // mulx rbx, rax, qword ptr [rsi + 0x10]
  adc r12, rax
  adc r13, rbx
  mov rdx, qword ptr [rsi+24]
  db $C4, $E2, $FB, $F6, $5E, $18  // mulx rbx, rax, qword ptr [rsi + 0x18]
  adc r14, rax
  adc r15, rbx
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4       // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED       // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6       // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF       // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx], r8
  mov qword ptr [rcx+8], r9
  mov qword ptr [rcx+16], r10
  mov qword ptr [rcx+24], r11
  dec rdi
@@Fe64SqrNLoop:
  test rdi, rdi
  jle @@Fe64SqrNDone
  mov rdx, qword ptr [rcx]
  db $C4, $62, $B3, $F6, $51, $08  // mulx r10, r9, qword ptr [rcx + 8]
  db $C4, $62, $E3, $F6, $59, $10  // mulx r11, rbx, qword ptr [rcx + 0x10]
  db $C4, $62, $FB, $F6, $61, $18  // mulx r12, rax, qword ptr [rcx + 0x18]
  xor r13d, r13d
  add r10, rbx
  adc r11, rax
  adc r12, 0
  xor r8d, r8d
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+8]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $10  // mulx rbx, rax, qword ptr [rcx + 0x10]
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $18  // mulx rbx, rax, qword ptr [rcx + 0x18]
  db $66, $4C, $0F, $38, $F6, $E0  // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED  // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5  // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  mov rdx, qword ptr [rcx+16]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $18  // mulx rbx, rax, qword ptr [rcx + 0x18]
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5  // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD  // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD  // adcx r15, rbp
  add r8, r8
  adc r9, r9
  adc r10, r10
  adc r11, r11
  adc r12, r12
  adc r13, r13
  adc r14, r14
  adc r15, r15
  mov rdx, qword ptr [rcx]
  db $C4, $E2, $FB, $F6, $19       // mulx rbx, rax, qword ptr [rcx]
  add r8, rax
  adc r9, rbx
  mov rdx, qword ptr [rcx+8]
  db $C4, $E2, $FB, $F6, $59, $08  // mulx rbx, rax, qword ptr [rcx + 8]
  adc r10, rax
  adc r11, rbx
  mov rdx, qword ptr [rcx+16]
  db $C4, $E2, $FB, $F6, $59, $10  // mulx rbx, rax, qword ptr [rcx + 0x10]
  adc r12, rax
  adc r13, rbx
  mov rdx, qword ptr [rcx+24]
  db $C4, $E2, $FB, $F6, $59, $18  // mulx rbx, rax, qword ptr [rcx + 0x18]
  adc r14, rax
  adc r15, rbx
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4       // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED       // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6       // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF       // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx], r8
  mov qword ptr [rcx+8], r9
  mov qword ptr [rcx+16], r10
  mov qword ptr [rcx+24], r11
  dec rdi
  jmp @@Fe64SqrNLoop
@@Fe64SqrNDone:
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE25519_SAT64SQRN}

{$IFDEF CRYPTOLIB_CURVE25519_SAT64LADDER}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  sub rsp, 64
  mov rsi, rdx
  mov r8, qword ptr [rcx+96]
  add r8, qword ptr [rcx+128]
  mov r9, qword ptr [rcx+104]
  adc r9, qword ptr [rcx+136]
  mov r10, qword ptr [rcx+112]
  adc r10, qword ptr [rcx+144]
  mov r11, qword ptr [rcx+120]
  adc r11, qword ptr [rcx+152]
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rsp], r8
  mov qword ptr [rsp+8], r9
  mov qword ptr [rsp+16], r10
  mov qword ptr [rsp+24], r11
  mov r8, qword ptr [rcx+96]
  sub r8, qword ptr [rcx+128]
  mov r9, qword ptr [rcx+104]
  sbb r9, qword ptr [rcx+136]
  mov r10, qword ptr [rcx+112]
  sbb r10, qword ptr [rcx+144]
  mov r11, qword ptr [rcx+120]
  sbb r11, qword ptr [rcx+152]
  mov ebx, 0
  adc ebx, 0
  sub r8, 76
  sbb r9, 0
  sbb r10, 0
  sbb r11, 0
  mov ebp, 0
  adc ebp, 0
  mov rax, 2
  sub rax, rbx
  sub rax, rbp
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+96], r8
  mov qword ptr [rcx+104], r9
  mov qword ptr [rcx+112], r10
  mov qword ptr [rcx+120], r11
  mov r8, qword ptr [rcx+32]
  add r8, qword ptr [rcx+64]
  mov r9, qword ptr [rcx+40]
  adc r9, qword ptr [rcx+72]
  mov r10, qword ptr [rcx+48]
  adc r10, qword ptr [rcx+80]
  mov r11, qword ptr [rcx+56]
  adc r11, qword ptr [rcx+88]
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+128], r8
  mov qword ptr [rcx+136], r9
  mov qword ptr [rcx+144], r10
  mov qword ptr [rcx+152], r11
  mov r8, qword ptr [rcx+32]
  sub r8, qword ptr [rcx+64]
  mov r9, qword ptr [rcx+40]
  sbb r9, qword ptr [rcx+72]
  mov r10, qword ptr [rcx+48]
  sbb r10, qword ptr [rcx+80]
  mov r11, qword ptr [rcx+56]
  sbb r11, qword ptr [rcx+88]
  mov ebx, 0
  adc ebx, 0
  sub r8, 76
  sbb r9, 0
  sbb r10, 0
  sbb r11, 0
  mov ebp, 0
  adc ebp, 0
  mov rax, 2
  sub rax, rbx
  sub rax, rbp
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+32], r8
  mov qword ptr [rcx+40], r9
  mov qword ptr [rcx+48], r10
  mov qword ptr [rcx+56], r11
  mov rdx, qword ptr [rcx+32]
  db $C4, $62, $BB, $F6, $0C, $24                 // mulx r9, r8, qword ptr [rsp]
  db $C4, $62, $E3, $F6, $54, $24, $08            // mulx r10, rbx, qword ptr [rsp + 8]
  db $C4, $62, $FB, $F6, $5C, $24, $10            // mulx r11, rax, qword ptr [rsp + 0x10]
  db $C4, $62, $D3, $F6, $64, $24, $18            // mulx r12, rbp, qword ptr [rsp + 0x18]
  xor r13d, r13d
  add r9, rbx
  adc r10, rax
  adc r11, rbp
  adc r12, 0
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+40]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $1C, $24                 // mulx rbx, rax, qword ptr [rsp]
  db $66, $4C, $0F, $38, $F6, $C8                 // adcx r9, rax
  db $F3, $4C, $0F, $38, $F6, $D3                 // adox r10, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $08            // mulx rbx, rax, qword ptr [rsp + 8]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $10            // mulx rbx, rax, qword ptr [rsp + 0x10]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $18            // mulx rbx, rax, qword ptr [rsp + 0x18]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+48]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $1C, $24                 // mulx rbx, rax, qword ptr [rsp]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $08            // mulx rbx, rax, qword ptr [rsp + 8]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $10            // mulx rbx, rax, qword ptr [rsp + 0x10]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $18            // mulx rbx, rax, qword ptr [rsp + 0x18]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, qword ptr [rcx+56]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $1C, $24                 // mulx rbx, rax, qword ptr [rsp]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $08            // mulx rbx, rax, qword ptr [rsp + 8]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $10            // mulx rbx, rax, qword ptr [rsp + 0x10]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $18            // mulx rbx, rax, qword ptr [rsp + 0x18]
  db $66, $4C, $0F, $38, $F6, $F0                 // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $FB                 // adox r15, rbx
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rsp], r8
  mov qword ptr [rsp+8], r9
  mov qword ptr [rsp+16], r10
  mov qword ptr [rsp+24], r11
  mov rdx, qword ptr [rcx+128]
  db $C4, $62, $BB, $F6, $49, $60                 // mulx r9, r8, qword ptr [rcx + 0x60]
  db $C4, $62, $E3, $F6, $51, $68                 // mulx r10, rbx, qword ptr [rcx + 0x68]
  db $C4, $62, $FB, $F6, $59, $70                 // mulx r11, rax, qword ptr [rcx + 0x70]
  db $C4, $62, $D3, $F6, $61, $78                 // mulx r12, rbp, qword ptr [rcx + 0x78]
  xor r13d, r13d
  add r9, rbx
  adc r10, rax
  adc r11, rbp
  adc r12, 0
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+136]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $60                 // mulx rbx, rax, qword ptr [rcx + 0x60]
  db $66, $4C, $0F, $38, $F6, $C8                 // adcx r9, rax
  db $F3, $4C, $0F, $38, $F6, $D3                 // adox r10, rbx
  db $C4, $E2, $FB, $F6, $59, $68                 // mulx rbx, rax, qword ptr [rcx + 0x68]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $59, $70                 // mulx rbx, rax, qword ptr [rcx + 0x70]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $78                 // mulx rbx, rax, qword ptr [rcx + 0x78]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+144]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $60                 // mulx rbx, rax, qword ptr [rcx + 0x60]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $59, $68                 // mulx rbx, rax, qword ptr [rcx + 0x68]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $70                 // mulx rbx, rax, qword ptr [rcx + 0x70]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $59, $78                 // mulx rbx, rax, qword ptr [rcx + 0x78]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, qword ptr [rcx+152]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $60                 // mulx rbx, rax, qword ptr [rcx + 0x60]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $68                 // mulx rbx, rax, qword ptr [rcx + 0x68]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $59, $70                 // mulx rbx, rax, qword ptr [rcx + 0x70]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $C4, $E2, $FB, $F6, $59, $78                 // mulx rbx, rax, qword ptr [rcx + 0x78]
  db $66, $4C, $0F, $38, $F6, $F0                 // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $FB                 // adox r15, rbx
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+96], r8
  mov qword ptr [rcx+104], r9
  mov qword ptr [rcx+112], r10
  mov qword ptr [rcx+120], r11
  mov rdx, qword ptr [rcx+128]
  db $C4, $62, $B3, $F6, $91, $88, $00, $00, $00  // mulx r10, r9, qword ptr [rcx + 0x88]
  db $C4, $62, $E3, $F6, $99, $90, $00, $00, $00  // mulx r11, rbx, qword ptr [rcx + 0x90]
  db $C4, $62, $FB, $F6, $A1, $98, $00, $00, $00  // mulx r12, rax, qword ptr [rcx + 0x98]
  xor r13d, r13d
  add r10, rbx
  adc r11, rax
  adc r12, 0
  xor r8d, r8d
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+136]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $99, $90, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x90]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+144]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  add r8, r8
  adc r9, r9
  adc r10, r10
  adc r11, r11
  adc r12, r12
  adc r13, r13
  adc r14, r14
  adc r15, r15
  mov rdx, qword ptr [rcx+128]
  db $C4, $E2, $FB, $F6, $99, $80, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x80]
  add r8, rax
  adc r9, rbx
  mov rdx, qword ptr [rcx+136]
  db $C4, $E2, $FB, $F6, $99, $88, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x88]
  adc r10, rax
  adc r11, rbx
  mov rdx, qword ptr [rcx+144]
  db $C4, $E2, $FB, $F6, $99, $90, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x90]
  adc r12, rax
  adc r13, rbx
  mov rdx, qword ptr [rcx+152]
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  adc r14, rax
  adc r15, rbx
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+128], r8
  mov qword ptr [rcx+136], r9
  mov qword ptr [rcx+144], r10
  mov qword ptr [rcx+152], r11
  mov rdx, qword ptr [rcx+32]
  db $C4, $62, $B3, $F6, $51, $28                 // mulx r10, r9, qword ptr [rcx + 0x28]
  db $C4, $62, $E3, $F6, $59, $30                 // mulx r11, rbx, qword ptr [rcx + 0x30]
  db $C4, $62, $FB, $F6, $61, $38                 // mulx r12, rax, qword ptr [rcx + 0x38]
  xor r13d, r13d
  add r10, rbx
  adc r11, rax
  adc r12, 0
  xor r8d, r8d
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+40]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $30                 // mulx rbx, rax, qword ptr [rcx + 0x30]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $38                 // mulx rbx, rax, qword ptr [rcx + 0x38]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+48]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $38                 // mulx rbx, rax, qword ptr [rcx + 0x38]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  add r8, r8
  adc r9, r9
  adc r10, r10
  adc r11, r11
  adc r12, r12
  adc r13, r13
  adc r14, r14
  adc r15, r15
  mov rdx, qword ptr [rcx+32]
  db $C4, $E2, $FB, $F6, $59, $20                 // mulx rbx, rax, qword ptr [rcx + 0x20]
  add r8, rax
  adc r9, rbx
  mov rdx, qword ptr [rcx+40]
  db $C4, $E2, $FB, $F6, $59, $28                 // mulx rbx, rax, qword ptr [rcx + 0x28]
  adc r10, rax
  adc r11, rbx
  mov rdx, qword ptr [rcx+48]
  db $C4, $E2, $FB, $F6, $59, $30                 // mulx rbx, rax, qword ptr [rcx + 0x30]
  adc r12, rax
  adc r13, rbx
  mov rdx, qword ptr [rcx+56]
  db $C4, $E2, $FB, $F6, $59, $38                 // mulx rbx, rax, qword ptr [rcx + 0x38]
  adc r14, rax
  adc r15, rbx
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+32], r8
  mov qword ptr [rcx+40], r9
  mov qword ptr [rcx+48], r10
  mov qword ptr [rcx+56], r11
  mov r8, qword ptr [rcx+128]
  sub r8, qword ptr [rcx+32]
  mov r9, qword ptr [rcx+136]
  sbb r9, qword ptr [rcx+40]
  mov r10, qword ptr [rcx+144]
  sbb r10, qword ptr [rcx+48]
  mov r11, qword ptr [rcx+152]
  sbb r11, qword ptr [rcx+56]
  mov ebx, 0
  adc ebx, 0
  sub r8, 76
  sbb r9, 0
  sbb r10, 0
  sbb r11, 0
  mov ebp, 0
  adc ebp, 0
  mov rax, 2
  sub rax, rbx
  sub rax, rbp
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rsp+32], r8
  mov qword ptr [rsp+40], r9
  mov qword ptr [rsp+48], r10
  mov qword ptr [rsp+56], r11
  mov rdx, 121666
  xor ebp, ebp
  db $C4, $E2, $FB, $F6, $5C, $24, $20            // mulx rbx, rax, qword ptr [rsp + 0x20]
  mov r8, rax
  mov rbp, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $28            // mulx rbx, rax, qword ptr [rsp + 0x28]
  add rax, rbp
  adc rbx, 0
  mov r9, rax
  mov rbp, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $30            // mulx rbx, rax, qword ptr [rsp + 0x30]
  add rax, rbp
  adc rbx, 0
  mov r10, rax
  mov rbp, rbx
  db $C4, $E2, $FB, $F6, $5C, $24, $38            // mulx rbx, rax, qword ptr [rsp + 0x38]
  add rax, rbp
  adc rbx, 0
  mov r11, rax
  mov rbp, rbx
  mov rax, rbp
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+64], r8
  mov qword ptr [rcx+72], r9
  mov qword ptr [rcx+80], r10
  mov qword ptr [rcx+88], r11
  mov r8, qword ptr [rcx+64]
  add r8, qword ptr [rcx+32]
  mov r9, qword ptr [rcx+72]
  adc r9, qword ptr [rcx+40]
  mov r10, qword ptr [rcx+80]
  adc r10, qword ptr [rcx+48]
  mov r11, qword ptr [rcx+88]
  adc r11, qword ptr [rcx+56]
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+64], r8
  mov qword ptr [rcx+72], r9
  mov qword ptr [rcx+80], r10
  mov qword ptr [rcx+88], r11
  mov rdx, qword ptr [rsp+32]
  db $C4, $62, $BB, $F6, $49, $40                 // mulx r9, r8, qword ptr [rcx + 0x40]
  db $C4, $62, $E3, $F6, $51, $48                 // mulx r10, rbx, qword ptr [rcx + 0x48]
  db $C4, $62, $FB, $F6, $59, $50                 // mulx r11, rax, qword ptr [rcx + 0x50]
  db $C4, $62, $D3, $F6, $61, $58                 // mulx r12, rbp, qword ptr [rcx + 0x58]
  xor r13d, r13d
  add r9, rbx
  adc r10, rax
  adc r11, rbp
  adc r12, 0
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rsp+40]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $40                 // mulx rbx, rax, qword ptr [rcx + 0x40]
  db $66, $4C, $0F, $38, $F6, $C8                 // adcx r9, rax
  db $F3, $4C, $0F, $38, $F6, $D3                 // adox r10, rbx
  db $C4, $E2, $FB, $F6, $59, $48                 // mulx rbx, rax, qword ptr [rcx + 0x48]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $59, $50                 // mulx rbx, rax, qword ptr [rcx + 0x50]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $58                 // mulx rbx, rax, qword ptr [rcx + 0x58]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rsp+48]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $40                 // mulx rbx, rax, qword ptr [rcx + 0x40]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $59, $48                 // mulx rbx, rax, qword ptr [rcx + 0x48]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $50                 // mulx rbx, rax, qword ptr [rcx + 0x50]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $59, $58                 // mulx rbx, rax, qword ptr [rcx + 0x58]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, qword ptr [rsp+56]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $40                 // mulx rbx, rax, qword ptr [rcx + 0x40]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $48                 // mulx rbx, rax, qword ptr [rcx + 0x48]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $59, $50                 // mulx rbx, rax, qword ptr [rcx + 0x50]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $C4, $E2, $FB, $F6, $59, $58                 // mulx rbx, rax, qword ptr [rcx + 0x58]
  db $66, $4C, $0F, $38, $F6, $F0                 // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $FB                 // adox r15, rbx
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+64], r8
  mov qword ptr [rcx+72], r9
  mov qword ptr [rcx+80], r10
  mov qword ptr [rcx+88], r11
  mov rdx, qword ptr [rcx+128]
  db $C4, $62, $BB, $F6, $49, $20                 // mulx r9, r8, qword ptr [rcx + 0x20]
  db $C4, $62, $E3, $F6, $51, $28                 // mulx r10, rbx, qword ptr [rcx + 0x28]
  db $C4, $62, $FB, $F6, $59, $30                 // mulx r11, rax, qword ptr [rcx + 0x30]
  db $C4, $62, $D3, $F6, $61, $38                 // mulx r12, rbp, qword ptr [rcx + 0x38]
  xor r13d, r13d
  add r9, rbx
  adc r10, rax
  adc r11, rbp
  adc r12, 0
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+136]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $20                 // mulx rbx, rax, qword ptr [rcx + 0x20]
  db $66, $4C, $0F, $38, $F6, $C8                 // adcx r9, rax
  db $F3, $4C, $0F, $38, $F6, $D3                 // adox r10, rbx
  db $C4, $E2, $FB, $F6, $59, $28                 // mulx rbx, rax, qword ptr [rcx + 0x28]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $59, $30                 // mulx rbx, rax, qword ptr [rcx + 0x30]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $38                 // mulx rbx, rax, qword ptr [rcx + 0x38]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+144]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $20                 // mulx rbx, rax, qword ptr [rcx + 0x20]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $59, $28                 // mulx rbx, rax, qword ptr [rcx + 0x28]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $30                 // mulx rbx, rax, qword ptr [rcx + 0x30]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $59, $38                 // mulx rbx, rax, qword ptr [rcx + 0x38]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, qword ptr [rcx+152]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $20                 // mulx rbx, rax, qword ptr [rcx + 0x20]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $28                 // mulx rbx, rax, qword ptr [rcx + 0x28]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $59, $30                 // mulx rbx, rax, qword ptr [rcx + 0x30]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $C4, $E2, $FB, $F6, $59, $38                 // mulx rbx, rax, qword ptr [rcx + 0x38]
  db $66, $4C, $0F, $38, $F6, $F0                 // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $FB                 // adox r15, rbx
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+32], r8
  mov qword ptr [rcx+40], r9
  mov qword ptr [rcx+48], r10
  mov qword ptr [rcx+56], r11
  mov r8, qword ptr [rsp]
  sub r8, qword ptr [rcx+96]
  mov r9, qword ptr [rsp+8]
  sbb r9, qword ptr [rcx+104]
  mov r10, qword ptr [rsp+16]
  sbb r10, qword ptr [rcx+112]
  mov r11, qword ptr [rsp+24]
  sbb r11, qword ptr [rcx+120]
  mov ebx, 0
  adc ebx, 0
  sub r8, 76
  sbb r9, 0
  sbb r10, 0
  sbb r11, 0
  mov ebp, 0
  adc ebp, 0
  mov rax, 2
  sub rax, rbx
  sub rax, rbp
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+128], r8
  mov qword ptr [rcx+136], r9
  mov qword ptr [rcx+144], r10
  mov qword ptr [rcx+152], r11
  mov r8, qword ptr [rsp]
  add r8, qword ptr [rcx+96]
  mov r9, qword ptr [rsp+8]
  adc r9, qword ptr [rcx+104]
  mov r10, qword ptr [rsp+16]
  adc r10, qword ptr [rcx+112]
  mov r11, qword ptr [rsp+24]
  adc r11, qword ptr [rcx+120]
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+96], r8
  mov qword ptr [rcx+104], r9
  mov qword ptr [rcx+112], r10
  mov qword ptr [rcx+120], r11
  mov rdx, qword ptr [rcx+96]
  db $C4, $62, $B3, $F6, $51, $68                 // mulx r10, r9, qword ptr [rcx + 0x68]
  db $C4, $62, $E3, $F6, $59, $70                 // mulx r11, rbx, qword ptr [rcx + 0x70]
  db $C4, $62, $FB, $F6, $61, $78                 // mulx r12, rax, qword ptr [rcx + 0x78]
  xor r13d, r13d
  add r10, rbx
  adc r11, rax
  adc r12, 0
  xor r8d, r8d
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+104]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $70                 // mulx rbx, rax, qword ptr [rcx + 0x70]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $59, $78                 // mulx rbx, rax, qword ptr [rcx + 0x78]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+112]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $59, $78                 // mulx rbx, rax, qword ptr [rcx + 0x78]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  add r8, r8
  adc r9, r9
  adc r10, r10
  adc r11, r11
  adc r12, r12
  adc r13, r13
  adc r14, r14
  adc r15, r15
  mov rdx, qword ptr [rcx+96]
  db $C4, $E2, $FB, $F6, $59, $60                 // mulx rbx, rax, qword ptr [rcx + 0x60]
  add r8, rax
  adc r9, rbx
  mov rdx, qword ptr [rcx+104]
  db $C4, $E2, $FB, $F6, $59, $68                 // mulx rbx, rax, qword ptr [rcx + 0x68]
  adc r10, rax
  adc r11, rbx
  mov rdx, qword ptr [rcx+112]
  db $C4, $E2, $FB, $F6, $59, $70                 // mulx rbx, rax, qword ptr [rcx + 0x70]
  adc r12, rax
  adc r13, rbx
  mov rdx, qword ptr [rcx+120]
  db $C4, $E2, $FB, $F6, $59, $78                 // mulx rbx, rax, qword ptr [rcx + 0x78]
  adc r14, rax
  adc r15, rbx
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+96], r8
  mov qword ptr [rcx+104], r9
  mov qword ptr [rcx+112], r10
  mov qword ptr [rcx+120], r11
  mov rdx, qword ptr [rcx+128]
  db $C4, $62, $B3, $F6, $91, $88, $00, $00, $00  // mulx r10, r9, qword ptr [rcx + 0x88]
  db $C4, $62, $E3, $F6, $99, $90, $00, $00, $00  // mulx r11, rbx, qword ptr [rcx + 0x90]
  db $C4, $62, $FB, $F6, $A1, $98, $00, $00, $00  // mulx r12, rax, qword ptr [rcx + 0x98]
  xor r13d, r13d
  add r10, rbx
  adc r11, rax
  adc r12, 0
  xor r8d, r8d
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+136]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $99, $90, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x90]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+144]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  add r8, r8
  adc r9, r9
  adc r10, r10
  adc r11, r11
  adc r12, r12
  adc r13, r13
  adc r14, r14
  adc r15, r15
  mov rdx, qword ptr [rcx+128]
  db $C4, $E2, $FB, $F6, $99, $80, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x80]
  add r8, rax
  adc r9, rbx
  mov rdx, qword ptr [rcx+136]
  db $C4, $E2, $FB, $F6, $99, $88, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x88]
  adc r10, rax
  adc r11, rbx
  mov rdx, qword ptr [rcx+144]
  db $C4, $E2, $FB, $F6, $99, $90, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x90]
  adc r12, rax
  adc r13, rbx
  mov rdx, qword ptr [rcx+152]
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  adc r14, rax
  adc r15, rbx
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+128], r8
  mov qword ptr [rcx+136], r9
  mov qword ptr [rcx+144], r10
  mov qword ptr [rcx+152], r11
  mov rdx, qword ptr [rcx]
  db $C4, $62, $BB, $F6, $89, $80, $00, $00, $00  // mulx r9, r8, qword ptr [rcx + 0x80]
  db $C4, $62, $E3, $F6, $91, $88, $00, $00, $00  // mulx r10, rbx, qword ptr [rcx + 0x88]
  db $C4, $62, $FB, $F6, $99, $90, $00, $00, $00  // mulx r11, rax, qword ptr [rcx + 0x90]
  db $C4, $62, $D3, $F6, $A1, $98, $00, $00, $00  // mulx r12, rbp, qword ptr [rcx + 0x98]
  xor r13d, r13d
  add r9, rbx
  adc r10, rax
  adc r11, rbp
  adc r12, 0
  xor r14d, r14d
  xor r15d, r15d
  xor ebp, ebp
  mov rdx, qword ptr [rcx+8]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $99, $80, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x80]
  db $66, $4C, $0F, $38, $F6, $C8                 // adcx r9, rax
  db $F3, $4C, $0F, $38, $F6, $D3                 // adox r10, rbx
  db $C4, $E2, $FB, $F6, $99, $88, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x88]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $99, $90, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x90]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $ED                 // adcx r13, rbp
  db $F3, $4C, $0F, $38, $F6, $F5                 // adox r14, rbp
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  mov rdx, qword ptr [rcx+16]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $99, $80, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x80]
  db $66, $4C, $0F, $38, $F6, $D0                 // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $DB                 // adox r11, rbx
  db $C4, $E2, $FB, $F6, $99, $88, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x88]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $99, $90, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x90]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F5                 // adcx r14, rbp
  db $F3, $4C, $0F, $38, $F6, $FD                 // adox r15, rbp
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, qword ptr [rcx+24]
  xor eax, eax
  db $C4, $E2, $FB, $F6, $99, $80, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x80]
  db $66, $4C, $0F, $38, $F6, $D8                 // adcx r11, rax
  db $F3, $4C, $0F, $38, $F6, $E3                 // adox r12, rbx
  db $C4, $E2, $FB, $F6, $99, $88, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x88]
  db $66, $4C, $0F, $38, $F6, $E0                 // adcx r12, rax
  db $F3, $4C, $0F, $38, $F6, $EB                 // adox r13, rbx
  db $C4, $E2, $FB, $F6, $99, $90, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x90]
  db $66, $4C, $0F, $38, $F6, $E8                 // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F3                 // adox r14, rbx
  db $C4, $E2, $FB, $F6, $99, $98, $00, $00, $00  // mulx rbx, rax, qword ptr [rcx + 0x98]
  db $66, $4C, $0F, $38, $F6, $F0                 // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $FB                 // adox r15, rbx
  db $66, $4C, $0F, $38, $F6, $FD                 // adcx r15, rbp
  mov rdx, 38
  db $C4, $42, $FB, $F6, $E4                      // mulx r12, rax, r12
  db $C4, $42, $E3, $F6, $ED                      // mulx r13, rbx, r13
  db $C4, $42, $D3, $F6, $F6                      // mulx r14, rbp, r14
  db $C4, $42, $EB, $F6, $FF                      // mulx r15, rdx, r15
  add r8, rax
  adc r9, rbx
  adc r10, rbp
  adc r11, rdx
  adc r15, 0
  add r9, r12
  adc r10, r13
  adc r11, r14
  adc r15, 0
  imul rax, r15, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov rax, 0
  adc rax, 0
  imul rax, rax, 38
  add r8, rax
  adc r9, 0
  adc r10, 0
  adc r11, 0
  mov qword ptr [rcx+128], r8
  mov qword ptr [rcx+136], r9
  mov qword ptr [rcx+144], r10
  mov qword ptr [rcx+152], r11
  mov rax, qword ptr [rcx+32]
  mov rbx, qword ptr [rcx+96]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+32], rax
  mov qword ptr [rcx+96], rbx
  mov rax, qword ptr [rcx+40]
  mov rbx, qword ptr [rcx+104]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+40], rax
  mov qword ptr [rcx+104], rbx
  mov rax, qword ptr [rcx+48]
  mov rbx, qword ptr [rcx+112]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+48], rax
  mov qword ptr [rcx+112], rbx
  mov rax, qword ptr [rcx+56]
  mov rbx, qword ptr [rcx+120]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+56], rax
  mov qword ptr [rcx+120], rbx
  mov rax, qword ptr [rcx+64]
  mov rbx, qword ptr [rcx+128]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+64], rax
  mov qword ptr [rcx+128], rbx
  mov rax, qword ptr [rcx+72]
  mov rbx, qword ptr [rcx+136]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+72], rax
  mov qword ptr [rcx+136], rbx
  mov rax, qword ptr [rcx+80]
  mov rbx, qword ptr [rcx+144]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+80], rax
  mov qword ptr [rcx+144], rbx
  mov rax, qword ptr [rcx+88]
  mov rbx, qword ptr [rcx+152]
  mov rdx, rax
  xor rdx, rbx
  and rdx, rsi
  xor rax, rdx
  xor rbx, rdx
  mov qword ptr [rcx+88], rax
  mov qword ptr [rcx+152], rbx
  add rsp, 64
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE25519_SAT64LADDER}
