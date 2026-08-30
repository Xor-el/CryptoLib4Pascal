// Curve448 radix-2^56 (fe56 / Goldilocks) field multiply and square (x86-64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined before
// including this file:
//
//   CRYPTOLIB_CURVE448_FE56MUL   PH := PF * PG mod (2^448-2^224-1)
//   CRYPTOLIB_CURVE448_FE56SQR   PH := PF^2  mod (2^448-2^224-1)
//
// Representation: 8 x 64-bit limbs, radix 2^56 (limb i at [ptr+8i]). Limbs are
// UNSIGNED and loosely reduced (each < 2^57); output limbs < 2^57.
//
// On entry (via ClpSimdProc3Begin_x86_64): rcx = PH, rdx = PF, r8 = PG.
// FE56SQR (via ClpSimdProc2Begin_x86_64): rcx = PH, rdx = PF (g = f).
//
// Plain 8x8 schoolbook into fifteen 128-bit columns on a 256-byte stack frame,
// then the Goldilocks fold (column k -> k-4 and k-8 for k=14..8, high-to-low so
// the cascade re-folds), then a radix-2^56 carry with the top carry into limbs 0
// and 4. Plain mul/add/adc/shrd/shr/and only. Constant-time.
// Reference: 64-bit radix-2^56 Goldilocks field arithmetic (edwards448 / ed448-goldilocks).


{$IFDEF CRYPTOLIB_CURVE448_FE56MUL}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov  rsi, rdx
  mov  rdi, r8
  sub  rsp, 256
  xor  rax, rax
  mov  qword ptr [rsp+0], rax
  mov  qword ptr [rsp+8], rax
  mov  qword ptr [rsp+16], rax
  mov  qword ptr [rsp+24], rax
  mov  qword ptr [rsp+32], rax
  mov  qword ptr [rsp+40], rax
  mov  qword ptr [rsp+48], rax
  mov  qword ptr [rsp+56], rax
  mov  qword ptr [rsp+64], rax
  mov  qword ptr [rsp+72], rax
  mov  qword ptr [rsp+80], rax
  mov  qword ptr [rsp+88], rax
  mov  qword ptr [rsp+96], rax
  mov  qword ptr [rsp+104], rax
  mov  qword ptr [rsp+112], rax
  mov  qword ptr [rsp+120], rax
  mov  qword ptr [rsp+128], rax
  mov  qword ptr [rsp+136], rax
  mov  qword ptr [rsp+144], rax
  mov  qword ptr [rsp+152], rax
  mov  qword ptr [rsp+160], rax
  mov  qword ptr [rsp+168], rax
  mov  qword ptr [rsp+176], rax
  mov  qword ptr [rsp+184], rax
  mov  qword ptr [rsp+192], rax
  mov  qword ptr [rsp+200], rax
  mov  qword ptr [rsp+208], rax
  mov  qword ptr [rsp+216], rax
  mov  qword ptr [rsp+224], rax
  mov  qword ptr [rsp+232], rax
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+0], rax
  adc  qword ptr [rsp+8], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+16], rax
  adc  qword ptr [rsp+24], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+16], rax
  adc  qword ptr [rsp+24], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+192], rax
  adc  qword ptr [rsp+200], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+192], rax
  adc  qword ptr [rsp+200], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+208], rax
  adc  qword ptr [rsp+216], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+192], rax
  adc  qword ptr [rsp+200], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+208], rax
  adc  qword ptr [rsp+216], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+224], rax
  adc  qword ptr [rsp+232], rdx
  mov  rax, qword ptr [rsp+224]
  mov  r9,  qword ptr [rsp+232]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], r9
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], r9
  mov  rax, qword ptr [rsp+208]
  mov  r9,  qword ptr [rsp+216]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], r9
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], r9
  mov  rax, qword ptr [rsp+192]
  mov  r9,  qword ptr [rsp+200]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], r9
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], r9
  mov  rax, qword ptr [rsp+176]
  mov  r9,  qword ptr [rsp+184]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], r9
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], r9
  mov  rax, qword ptr [rsp+160]
  mov  r9,  qword ptr [rsp+168]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], r9
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], r9
  mov  rax, qword ptr [rsp+144]
  mov  r9,  qword ptr [rsp+152]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], r9
  add  qword ptr [rsp+16], rax
  adc  qword ptr [rsp+24], r9
  mov  rax, qword ptr [rsp+128]
  mov  r9,  qword ptr [rsp+136]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], r9
  add  qword ptr [rsp+0], rax
  adc  qword ptr [rsp+8], r9
  mov  r11, $00FFFFFFFFFFFFFF
  xor  r10, r10
  mov  rax, qword ptr [rsp+0]
  mov  rdx, qword ptr [rsp+8]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+0], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+16]
  mov  rdx, qword ptr [rsp+24]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+8], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+32]
  mov  rdx, qword ptr [rsp+40]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+16], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+48]
  mov  rdx, qword ptr [rsp+56]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+24], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+64]
  mov  rdx, qword ptr [rsp+72]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+32], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+80]
  mov  rdx, qword ptr [rsp+88]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+40], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+96]
  mov  rdx, qword ptr [rsp+104]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+48], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+112]
  mov  rdx, qword ptr [rsp+120]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+56], r9
  shrd rax, rdx, 56
  mov  r10, rax
  add  qword ptr [rcx], r10
  add  qword ptr [rcx+32], r10
  mov  rax, qword ptr [rcx]
  mov  r9, rax
  shr  r9, 56
  and  rax, r11
  mov  qword ptr [rcx], rax
  add  qword ptr [rcx+8], r9
  mov  rax, qword ptr [rcx+32]
  mov  r9, rax
  shr  r9, 56
  and  rax, r11
  mov  qword ptr [rcx+32], rax
  add  qword ptr [rcx+40], r9
  add  rsp, 256
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE448_FE56MUL}

{$IFDEF CRYPTOLIB_CURVE448_FE56SQR}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov  rsi, rdx
  mov  rdi, rsi
  sub  rsp, 256
  xor  rax, rax
  mov  qword ptr [rsp+0], rax
  mov  qword ptr [rsp+8], rax
  mov  qword ptr [rsp+16], rax
  mov  qword ptr [rsp+24], rax
  mov  qword ptr [rsp+32], rax
  mov  qword ptr [rsp+40], rax
  mov  qword ptr [rsp+48], rax
  mov  qword ptr [rsp+56], rax
  mov  qword ptr [rsp+64], rax
  mov  qword ptr [rsp+72], rax
  mov  qword ptr [rsp+80], rax
  mov  qword ptr [rsp+88], rax
  mov  qword ptr [rsp+96], rax
  mov  qword ptr [rsp+104], rax
  mov  qword ptr [rsp+112], rax
  mov  qword ptr [rsp+120], rax
  mov  qword ptr [rsp+128], rax
  mov  qword ptr [rsp+136], rax
  mov  qword ptr [rsp+144], rax
  mov  qword ptr [rsp+152], rax
  mov  qword ptr [rsp+160], rax
  mov  qword ptr [rsp+168], rax
  mov  qword ptr [rsp+176], rax
  mov  qword ptr [rsp+184], rax
  mov  qword ptr [rsp+192], rax
  mov  qword ptr [rsp+200], rax
  mov  qword ptr [rsp+208], rax
  mov  qword ptr [rsp+216], rax
  mov  qword ptr [rsp+224], rax
  mov  qword ptr [rsp+232], rax
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+0], rax
  adc  qword ptr [rsp+8], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+16], rax
  adc  qword ptr [rsp+24], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+0]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+16], rax
  adc  qword ptr [rsp+24], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+8]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+16]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+24]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+32]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+40]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+192], rax
  adc  qword ptr [rsp+200], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+192], rax
  adc  qword ptr [rsp+200], rdx
  mov  rax, qword ptr [rsi+48]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+208], rax
  adc  qword ptr [rsp+216], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+0]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+8]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+16]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+24]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+32]
  add  qword ptr [rsp+176], rax
  adc  qword ptr [rsp+184], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+40]
  add  qword ptr [rsp+192], rax
  adc  qword ptr [rsp+200], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+48]
  add  qword ptr [rsp+208], rax
  adc  qword ptr [rsp+216], rdx
  mov  rax, qword ptr [rsi+56]
  mul  qword ptr [rdi+56]
  add  qword ptr [rsp+224], rax
  adc  qword ptr [rsp+232], rdx
  mov  rax, qword ptr [rsp+224]
  mov  r9,  qword ptr [rsp+232]
  add  qword ptr [rsp+160], rax
  adc  qword ptr [rsp+168], r9
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], r9
  mov  rax, qword ptr [rsp+208]
  mov  r9,  qword ptr [rsp+216]
  add  qword ptr [rsp+144], rax
  adc  qword ptr [rsp+152], r9
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], r9
  mov  rax, qword ptr [rsp+192]
  mov  r9,  qword ptr [rsp+200]
  add  qword ptr [rsp+128], rax
  adc  qword ptr [rsp+136], r9
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], r9
  mov  rax, qword ptr [rsp+176]
  mov  r9,  qword ptr [rsp+184]
  add  qword ptr [rsp+112], rax
  adc  qword ptr [rsp+120], r9
  add  qword ptr [rsp+48], rax
  adc  qword ptr [rsp+56], r9
  mov  rax, qword ptr [rsp+160]
  mov  r9,  qword ptr [rsp+168]
  add  qword ptr [rsp+96], rax
  adc  qword ptr [rsp+104], r9
  add  qword ptr [rsp+32], rax
  adc  qword ptr [rsp+40], r9
  mov  rax, qword ptr [rsp+144]
  mov  r9,  qword ptr [rsp+152]
  add  qword ptr [rsp+80], rax
  adc  qword ptr [rsp+88], r9
  add  qword ptr [rsp+16], rax
  adc  qword ptr [rsp+24], r9
  mov  rax, qword ptr [rsp+128]
  mov  r9,  qword ptr [rsp+136]
  add  qword ptr [rsp+64], rax
  adc  qword ptr [rsp+72], r9
  add  qword ptr [rsp+0], rax
  adc  qword ptr [rsp+8], r9
  mov  r11, $00FFFFFFFFFFFFFF
  xor  r10, r10
  mov  rax, qword ptr [rsp+0]
  mov  rdx, qword ptr [rsp+8]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+0], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+16]
  mov  rdx, qword ptr [rsp+24]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+8], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+32]
  mov  rdx, qword ptr [rsp+40]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+16], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+48]
  mov  rdx, qword ptr [rsp+56]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+24], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+64]
  mov  rdx, qword ptr [rsp+72]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+32], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+80]
  mov  rdx, qword ptr [rsp+88]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+40], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+96]
  mov  rdx, qword ptr [rsp+104]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+48], r9
  shrd rax, rdx, 56
  mov  r10, rax
  mov  rax, qword ptr [rsp+112]
  mov  rdx, qword ptr [rsp+120]
  add  rax, r10
  adc  rdx, 0
  mov  r9, rax
  and  r9, r11
  mov  qword ptr [rcx+56], r9
  shrd rax, rdx, 56
  mov  r10, rax
  add  qword ptr [rcx], r10
  add  qword ptr [rcx+32], r10
  mov  rax, qword ptr [rcx]
  mov  r9, rax
  shr  r9, 56
  and  rax, r11
  mov  qword ptr [rcx], rax
  add  qword ptr [rcx+8], r9
  mov  rax, qword ptr [rcx+32]
  mov  r9, rax
  shr  r9, 56
  and  rax, r11
  mov  qword ptr [rcx+32], rax
  add  qword ptr [rcx+40], r9
  add  rsp, 256
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ENDIF CRYPTOLIB_CURVE448_FE56SQR}
