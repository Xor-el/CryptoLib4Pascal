// Curve25519 radix-2^51 (fe51 / donna64) field multiply and square (x86-64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined before
// including this file:
//
//   CRYPTOLIB_CURVE25519_FE64MUL   PH := PF * PG mod (2^255-19)
//   CRYPTOLIB_CURVE25519_FE64SQR   PH := PF^2  mod (2^255-19)
//
// Representation: 5 x 64-bit limbs, radix 2^51 (limb i at [ptr+8i]). Limbs are
// UNSIGNED and loosely reduced (each < 2^52). Output limbs are < 2^52, directly
// reusable as inputs. This is the packed 64-bit rep used on the 64-bit assembly
// targets; the 32-bit radix-2^25.5 rep (X25519Field_x86_64.inc) is unaffected.
//
// On entry (via ClpSimdProc3Begin_x86_64): rcx = PH, rdx = PF, r8 = PG; rsi/rbx staged
// from PF/PG. FE64SQR (via ClpSimdProc2Begin_x86_64): rcx = PH, rdx = PF.
// On exit: PH holds the 5 reduced limbs.
//
// Register-resident: the five 128-bit column accumulators live in r8..r15/rbp/rdi;
// f limbs reload into rax per product, g limbs and the 19-scaled precomputes are
// memory operands. Stack scratch: 32 bytes (mul) / 48 bytes (sqr). All eight
// callee-saved GPRs are pushed/popped.
//
// Constant-time: no data-dependent branches or addresses. Plain integer ops
// (mul/imul/add/adc/shrd/shr/and) only.
// Reference: 64-bit radix-2^51 field arithmetic (Bernstein curve25519 / ref10-64).

{$IFDEF CRYPTOLIB_CURVE25519_FE64MUL}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  sub  rsp, 32
  mov  rsi, rdx
  mov  rbx, r8
  // 19*g1..19*g4 -> [rsp+0..24]
  mov  rax, qword ptr [rbx+8]
  imul rax, rax, 19
  mov  qword ptr [rsp], rax
  mov  rax, qword ptr [rbx+16]
  imul rax, rax, 19
  mov  qword ptr [rsp+8], rax
  mov  rax, qword ptr [rbx+24]
  imul rax, rax, 19
  mov  qword ptr [rsp+16], rax
  mov  rax, qword ptr [rbx+32]
  imul rax, rax, 19
  mov  qword ptr [rsp+24], rax
  // column 0
  mov  rax, qword ptr [rsi]
  mul  qword ptr [rbx]
  mov  r8, rax
  mov  r9, rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rsp+24]
  add  r8, rax
  adc  r9, rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rsp+16]
  add  r8, rax
  adc  r9, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rsp+8]
  add  r8, rax
  adc  r9, rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rsp]
  add  r8, rax
  adc  r9, rdx
  // column 1
  mov  rax, qword ptr [rsi]
  mul  qword ptr [rbx+8]
  mov  r10, rax
  mov  r11, rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rbx]
  add  r10, rax
  adc  r11, rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rsp+24]
  add  r10, rax
  adc  r11, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rsp+16]
  add  r10, rax
  adc  r11, rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rsp+8]
  add  r10, rax
  adc  r11, rdx
  // column 2
  mov  rax, qword ptr [rsi]
  mul  qword ptr [rbx+16]
  mov  r12, rax
  mov  r13, rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rbx+8]
  add  r12, rax
  adc  r13, rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rbx]
  add  r12, rax
  adc  r13, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rsp+24]
  add  r12, rax
  adc  r13, rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rsp+16]
  add  r12, rax
  adc  r13, rdx
  // column 3
  mov  rax, qword ptr [rsi]
  mul  qword ptr [rbx+24]
  mov  r14, rax
  mov  r15, rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rbx+16]
  add  r14, rax
  adc  r15, rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rbx+8]
  add  r14, rax
  adc  r15, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rbx]
  add  r14, rax
  adc  r15, rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rsp+24]
  add  r14, rax
  adc  r15, rdx
  // column 4
  mov  rax, qword ptr [rsi]
  mul  qword ptr [rbx+32]
  mov  rbp, rax
  mov  rdi, rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rbx+24]
  add  rbp, rax
  adc  rdi, rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rbx+16]
  add  rbp, rax
  adc  rdi, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rbx+8]
  add  rbp, rax
  adc  rdi, rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rbx]
  add  rbp, rax
  adc  rdi, rdx
  // carry chain (hi words < 2^51 so shrd yields the full carry)
  mov  rbx, $7FFFFFFFFFFFF
  mov  rax, r8
  shrd rax, r9, 51
  and  r8, rbx
  add  r10, rax
  adc  r11, 0
  mov  rax, r10
  shrd rax, r11, 51
  and  r10, rbx
  add  r12, rax
  adc  r13, 0
  mov  rax, r12
  shrd rax, r13, 51
  and  r12, rbx
  add  r14, rax
  adc  r15, 0
  mov  rax, r14
  shrd rax, r15, 51
  and  r14, rbx
  add  rbp, rax
  adc  rdi, 0
  mov  rax, rbp
  shrd rax, rdi, 51
  and  rbp, rbx
  imul rax, rax, 19
  add  r8, rax
  mov  rax, r8
  shr  rax, 51
  and  r8, rbx
  add  r10, rax
  mov  qword ptr [rcx], r8
  mov  qword ptr [rcx+8], r10
  mov  qword ptr [rcx+16], r12
  mov  qword ptr [rcx+24], r14
  mov  qword ptr [rcx+32], rbp
  add  rsp, 32
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  rdi
  pop  rsi
  pop  rbp
  pop  rbx
{$ENDIF CRYPTOLIB_CURVE25519_FE64MUL}

{$IFDEF CRYPTOLIB_CURVE25519_FE64SQR}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  sub  rsp, 48
  mov  rsi, rdx
  // precomputes: [rsp]=2f0 [rsp+8]=2f1 [rsp+16]=38f2 [rsp+24]=19f3 [rsp+32]=19f4 [rsp+40]=38f4
  mov  rax, qword ptr [rsi]
  add  rax, rax
  mov  qword ptr [rsp], rax
  mov  rax, qword ptr [rsi+8]
  add  rax, rax
  mov  qword ptr [rsp+8], rax
  mov  rax, qword ptr [rsi+16]
  imul rax, rax, 38
  mov  qword ptr [rsp+16], rax
  mov  rax, qword ptr [rsi+24]
  imul rax, rax, 19
  mov  qword ptr [rsp+24], rax
  mov  rax, qword ptr [rsi+32]
  imul rax, rax, 19
  mov  qword ptr [rsp+32], rax
  add  rax, rax
  mov  qword ptr [rsp+40], rax
  // column 0: f0*f0 + f1*38f4 + f3*38f2
  mov  rax, qword ptr [rsi]
  mul  qword ptr [rsi]
  mov  r8, rax
  mov  r9, rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rsp+40]
  add  r8, rax
  adc  r9, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rsp+16]
  add  r8, rax
  adc  r9, rdx
  // column 1: 2f0*f1 + f2*38f4 + f3*19f3
  mov  rax, qword ptr [rsp]
  mul  qword ptr [rsi+8]
  mov  r10, rax
  mov  r11, rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rsp+40]
  add  r10, rax
  adc  r11, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rsp+24]
  add  r10, rax
  adc  r11, rdx
  // column 2: 2f0*f2 + f1*f1 + f3*38f4
  mov  rax, qword ptr [rsp]
  mul  qword ptr [rsi+16]
  mov  r12, rax
  mov  r13, rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rsi+8]
  add  r12, rax
  adc  r13, rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rsp+40]
  add  r12, rax
  adc  r13, rdx
  // column 3: 2f0*f3 + 2f1*f2 + f4*19f4
  mov  rax, qword ptr [rsp]
  mul  qword ptr [rsi+24]
  mov  r14, rax
  mov  r15, rdx
  mov  rax, qword ptr [rsp+8]
  mul  qword ptr [rsi+16]
  add  r14, rax
  adc  r15, rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rsp+32]
  add  r14, rax
  adc  r15, rdx
  // column 4: 2f0*f4 + 2f1*f3 + f2*f2
  mov  rax, qword ptr [rsp]
  mul  qword ptr [rsi+32]
  mov  rbp, rax
  mov  rdi, rdx
  mov  rax, qword ptr [rsp+8]
  mul  qword ptr [rsi+24]
  add  rbp, rax
  adc  rdi, rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rsi+16]
  add  rbp, rax
  adc  rdi, rdx
  // carry chain
  mov  rbx, $7FFFFFFFFFFFF
  mov  rax, r8
  shrd rax, r9, 51
  and  r8, rbx
  add  r10, rax
  adc  r11, 0
  mov  rax, r10
  shrd rax, r11, 51
  and  r10, rbx
  add  r12, rax
  adc  r13, 0
  mov  rax, r12
  shrd rax, r13, 51
  and  r12, rbx
  add  r14, rax
  adc  r15, 0
  mov  rax, r14
  shrd rax, r15, 51
  and  r14, rbx
  add  rbp, rax
  adc  rdi, 0
  mov  rax, rbp
  shrd rax, rdi, 51
  and  rbp, rbx
  imul rax, rax, 19
  add  r8, rax
  mov  rax, r8
  shr  rax, 51
  and  r8, rbx
  add  r10, rax
  mov  qword ptr [rcx], r8
  mov  qword ptr [rcx+8], r10
  mov  qword ptr [rcx+16], r12
  mov  qword ptr [rcx+24], r14
  mov  qword ptr [rcx+32], rbp
  add  rsp, 48
  pop  r15
  pop  r14
  pop  r13
  pop  r12
  pop  rdi
  pop  rsi
  pop  rbp
  pop  rbx
{$ENDIF CRYPTOLIB_CURVE25519_FE64SQR}
