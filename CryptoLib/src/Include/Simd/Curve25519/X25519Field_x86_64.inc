// Curve25519 field kernels (x86-64), radix-2^25.5, ten signed Int32 limbs.
// One selector-driven file; define exactly one of the following before the
// include (each pairs with its ClpSimdProc<n>Begin prologue):
//
//   CRYPTOLIB_CURVE25519_MUL      (Proc3: rcx=PF, rdx=PG, r8=PH)
//     PH := PF * PG
//   CRYPTOLIB_CURVE25519_SQR      (Proc2: rcx=PX, rdx=PZ)
//     PZ := PX^2
//   CRYPTOLIB_CURVE25519_ADD      (Proc3: rcx=PX, rdx=PY, r8=PZ)
//     PZ := PX + PY
//   CRYPTOLIB_CURVE25519_SUB      (Proc3: rcx=PX, rdx=PY, r8=PZ)
//     PZ := PX - PY
//   CRYPTOLIB_CURVE25519_APM      (Proc4: rcx=PX, rdx=PY, r8=PZp, r9=PZm)
//     PZp := PX+PY; PZm := PX-PY
//   CRYPTOLIB_CURVE25519_CSWAP    (Proc3: rcx=ASwap, rdx=PA, r8=PB)
//     constant-time swap of PA, PB
//   CRYPTOLIB_CURVE25519_CARRY    (Proc1: rcx=PZ)
//     carry-propagate (reduce) PZ in place
//   CRYPTOLIB_CURVE25519_MULWORD  (Proc3: rcx=PX, rdx=AY, r8=PZ)
//     PZ := PX * AY (small scalar AY)
//
// Mul/Sqr are signed product-scanning schoolbook (stage Q[j]=19*g[j]; one
// Int64 accumulator per column, <2^62.42; canonical carry with the 2^256==38
// top fold). All results mod 2^255-19; signed limbs => imul only.
// Constant-time: no data-dependent branches or addresses.
{$IFDEF CRYPTOLIB_CURVE25519_MUL}
  push rbx
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  push rbp
  sub rsp, 240
  movsxd rax, dword ptr [rcx+0]
  mov [rsp+0], rax
  movsxd rax, dword ptr [rcx+4]
  mov [rsp+8], rax
  movsxd rax, dword ptr [rcx+8]
  mov [rsp+16], rax
  movsxd rax, dword ptr [rcx+12]
  mov [rsp+24], rax
  movsxd rax, dword ptr [rcx+16]
  mov [rsp+32], rax
  movsxd rax, dword ptr [rcx+20]
  mov [rsp+40], rax
  movsxd rax, dword ptr [rcx+24]
  mov [rsp+48], rax
  movsxd rax, dword ptr [rcx+28]
  mov [rsp+56], rax
  movsxd rax, dword ptr [rcx+32]
  mov [rsp+64], rax
  movsxd rax, dword ptr [rcx+36]
  mov [rsp+72], rax
  movsxd rax, dword ptr [rdx+0]
  mov [rsp+80], rax
  movsxd rax, dword ptr [rdx+4]
  mov [rsp+88], rax
  movsxd rax, dword ptr [rdx+8]
  mov [rsp+96], rax
  movsxd rax, dword ptr [rdx+12]
  mov [rsp+104], rax
  movsxd rax, dword ptr [rdx+16]
  mov [rsp+112], rax
  movsxd rax, dword ptr [rdx+20]
  mov [rsp+120], rax
  movsxd rax, dword ptr [rdx+24]
  mov [rsp+128], rax
  movsxd rax, dword ptr [rdx+28]
  mov [rsp+136], rax
  movsxd rax, dword ptr [rdx+32]
  mov [rsp+144], rax
  movsxd rax, dword ptr [rdx+36]
  mov [rsp+152], rax
  imul rax, [rsp+88], 19
  mov [rsp+168], rax
  imul rax, [rsp+96], 19
  mov [rsp+176], rax
  imul rax, [rsp+104], 19
  mov [rsp+184], rax
  imul rax, [rsp+112], 19
  mov [rsp+192], rax
  imul rax, [rsp+120], 19
  mov [rsp+200], rax
  imul rax, [rsp+128], 19
  mov [rsp+208], rax
  imul rax, [rsp+136], 19
  mov [rsp+216], rax
  imul rax, [rsp+144], 19
  mov [rsp+224], rax
  imul rax, [rsp+152], 19
  mov [rsp+232], rax
  mov rax, [rsp+0]
  imul rax, [rsp+80]
  mov rbx, rax
  mov rax, [rsp+8]
  imul rax, [rsp+232]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+16]
  imul rax, [rsp+224]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+24]
  imul rax, [rsp+216]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+32]
  imul rax, [rsp+208]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+40]
  imul rax, [rsp+200]
  sal rax, 1
  add rbx, rax
  mov rax, [rsp+48]
  imul rax, [rsp+192]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+56]
  imul rax, [rsp+184]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+64]
  imul rax, [rsp+176]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+72]
  imul rax, [rsp+168]
  sal rax, 2
  add rbx, rax
  mov rax, [rsp+0]
  imul rax, [rsp+88]
  mov rsi, rax
  mov rax, [rsp+8]
  imul rax, [rsp+80]
  add rsi, rax
  mov rax, [rsp+16]
  imul rax, [rsp+232]
  sal rax, 2
  add rsi, rax
  mov rax, [rsp+24]
  imul rax, [rsp+224]
  sal rax, 1
  add rsi, rax
  mov rax, [rsp+32]
  imul rax, [rsp+216]
  sal rax, 2
  add rsi, rax
  mov rax, [rsp+40]
  imul rax, [rsp+208]
  sal rax, 1
  add rsi, rax
  mov rax, [rsp+48]
  imul rax, [rsp+200]
  sal rax, 1
  add rsi, rax
  mov rax, [rsp+56]
  imul rax, [rsp+192]
  sal rax, 2
  add rsi, rax
  mov rax, [rsp+64]
  imul rax, [rsp+184]
  sal rax, 1
  add rsi, rax
  mov rax, [rsp+72]
  imul rax, [rsp+176]
  sal rax, 2
  add rsi, rax
  mov rax, [rsp+0]
  imul rax, [rsp+96]
  mov rdi, rax
  mov rax, [rsp+8]
  imul rax, [rsp+88]
  add rdi, rax
  mov rax, [rsp+16]
  imul rax, [rsp+80]
  add rdi, rax
  mov rax, [rsp+24]
  imul rax, [rsp+232]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+32]
  imul rax, [rsp+224]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+40]
  imul rax, [rsp+216]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+48]
  imul rax, [rsp+208]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+56]
  imul rax, [rsp+200]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+64]
  imul rax, [rsp+192]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+72]
  imul rax, [rsp+184]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+0]
  imul rax, [rsp+104]
  mov r9, rax
  mov rax, [rsp+8]
  imul rax, [rsp+96]
  sal rax, 1
  add r9, rax
  mov rax, [rsp+16]
  imul rax, [rsp+88]
  sal rax, 1
  add r9, rax
  mov rax, [rsp+24]
  imul rax, [rsp+80]
  add r9, rax
  mov rax, [rsp+32]
  imul rax, [rsp+232]
  sal rax, 2
  add r9, rax
  mov rax, [rsp+40]
  imul rax, [rsp+224]
  sal rax, 1
  add r9, rax
  mov rax, [rsp+48]
  imul rax, [rsp+216]
  sal rax, 2
  add r9, rax
  mov rax, [rsp+56]
  imul rax, [rsp+208]
  sal rax, 2
  add r9, rax
  mov rax, [rsp+64]
  imul rax, [rsp+200]
  sal rax, 1
  add r9, rax
  mov rax, [rsp+72]
  imul rax, [rsp+192]
  sal rax, 2
  add r9, rax
  mov rax, [rsp+0]
  imul rax, [rsp+112]
  mov r10, rax
  mov rax, [rsp+8]
  imul rax, [rsp+104]
  add r10, rax
  mov rax, [rsp+16]
  imul rax, [rsp+96]
  sal rax, 1
  add r10, rax
  mov rax, [rsp+24]
  imul rax, [rsp+88]
  add r10, rax
  mov rax, [rsp+32]
  imul rax, [rsp+80]
  add r10, rax
  mov rax, [rsp+40]
  imul rax, [rsp+232]
  sal rax, 1
  add r10, rax
  mov rax, [rsp+48]
  imul rax, [rsp+224]
  sal rax, 1
  add r10, rax
  mov rax, [rsp+56]
  imul rax, [rsp+216]
  sal rax, 2
  add r10, rax
  mov rax, [rsp+64]
  imul rax, [rsp+208]
  sal rax, 1
  add r10, rax
  mov rax, [rsp+72]
  imul rax, [rsp+200]
  sal rax, 1
  add r10, rax
  mov rax, [rsp+0]
  imul rax, [rsp+120]
  mov r11, rax
  mov rax, [rsp+8]
  imul rax, [rsp+112]
  sal rax, 1
  add r11, rax
  mov rax, [rsp+16]
  imul rax, [rsp+104]
  sal rax, 1
  add r11, rax
  mov rax, [rsp+24]
  imul rax, [rsp+96]
  sal rax, 1
  add r11, rax
  mov rax, [rsp+32]
  imul rax, [rsp+88]
  sal rax, 1
  add r11, rax
  mov rax, [rsp+40]
  imul rax, [rsp+80]
  add r11, rax
  mov rax, [rsp+48]
  imul rax, [rsp+232]
  sal rax, 2
  add r11, rax
  mov rax, [rsp+56]
  imul rax, [rsp+224]
  sal rax, 2
  add r11, rax
  mov rax, [rsp+64]
  imul rax, [rsp+216]
  sal rax, 2
  add r11, rax
  mov rax, [rsp+72]
  imul rax, [rsp+208]
  sal rax, 2
  add r11, rax
  mov rax, [rsp+0]
  imul rax, [rsp+128]
  mov r12, rax
  mov rax, [rsp+8]
  imul rax, [rsp+120]
  add r12, rax
  mov rax, [rsp+16]
  imul rax, [rsp+112]
  sal rax, 1
  add r12, rax
  mov rax, [rsp+24]
  imul rax, [rsp+104]
  add r12, rax
  mov rax, [rsp+32]
  imul rax, [rsp+96]
  sal rax, 1
  add r12, rax
  mov rax, [rsp+40]
  imul rax, [rsp+88]
  add r12, rax
  mov rax, [rsp+48]
  imul rax, [rsp+80]
  add r12, rax
  mov rax, [rsp+56]
  imul rax, [rsp+232]
  sal rax, 2
  add r12, rax
  mov rax, [rsp+64]
  imul rax, [rsp+224]
  sal rax, 1
  add r12, rax
  mov rax, [rsp+72]
  imul rax, [rsp+216]
  sal rax, 2
  add r12, rax
  mov rax, [rsp+0]
  imul rax, [rsp+136]
  mov r13, rax
  mov rax, [rsp+8]
  imul rax, [rsp+128]
  add r13, rax
  mov rax, [rsp+16]
  imul rax, [rsp+120]
  add r13, rax
  mov rax, [rsp+24]
  imul rax, [rsp+112]
  add r13, rax
  mov rax, [rsp+32]
  imul rax, [rsp+104]
  add r13, rax
  mov rax, [rsp+40]
  imul rax, [rsp+96]
  add r13, rax
  mov rax, [rsp+48]
  imul rax, [rsp+88]
  add r13, rax
  mov rax, [rsp+56]
  imul rax, [rsp+80]
  add r13, rax
  mov rax, [rsp+64]
  imul rax, [rsp+232]
  sal rax, 1
  add r13, rax
  mov rax, [rsp+72]
  imul rax, [rsp+224]
  sal rax, 1
  add r13, rax
  mov rax, [rsp+0]
  imul rax, [rsp+144]
  mov r14, rax
  mov rax, [rsp+8]
  imul rax, [rsp+136]
  sal rax, 1
  add r14, rax
  mov rax, [rsp+16]
  imul rax, [rsp+128]
  sal rax, 1
  add r14, rax
  mov rax, [rsp+24]
  imul rax, [rsp+120]
  add r14, rax
  mov rax, [rsp+32]
  imul rax, [rsp+112]
  sal rax, 1
  add r14, rax
  mov rax, [rsp+40]
  imul rax, [rsp+104]
  add r14, rax
  mov rax, [rsp+48]
  imul rax, [rsp+96]
  sal rax, 1
  add r14, rax
  mov rax, [rsp+56]
  imul rax, [rsp+88]
  sal rax, 1
  add r14, rax
  mov rax, [rsp+64]
  imul rax, [rsp+80]
  add r14, rax
  mov rax, [rsp+72]
  imul rax, [rsp+232]
  sal rax, 2
  add r14, rax
  mov rax, [rsp+0]
  imul rax, [rsp+152]
  mov r15, rax
  mov rax, [rsp+8]
  imul rax, [rsp+144]
  add r15, rax
  mov rax, [rsp+16]
  imul rax, [rsp+136]
  sal rax, 1
  add r15, rax
  mov rax, [rsp+24]
  imul rax, [rsp+128]
  add r15, rax
  mov rax, [rsp+32]
  imul rax, [rsp+120]
  add r15, rax
  mov rax, [rsp+40]
  imul rax, [rsp+112]
  add r15, rax
  mov rax, [rsp+48]
  imul rax, [rsp+104]
  add r15, rax
  mov rax, [rsp+56]
  imul rax, [rsp+96]
  sal rax, 1
  add r15, rax
  mov rax, [rsp+64]
  imul rax, [rsp+88]
  add r15, rax
  mov rax, [rsp+72]
  imul rax, [rsp+80]
  add r15, rax
  mov rax, rsi
  sar rax, 26
  add rdi, rax
  and rsi, $03FFFFFF
  mov rax, r9
  sar rax, 26
  add r10, rax
  and r9, $03FFFFFF
  mov rax, r12
  sar rax, 26
  add r13, rax
  and r12, $03FFFFFF
  mov rax, r14
  sar rax, 26
  add r15, rax
  and r14, $03FFFFFF
  mov rax, rdi
  sar rax, 25
  add r9, rax
  and rdi, $01FFFFFF
  mov rax, r10
  sar rax, 25
  add r11, rax
  and r10, $01FFFFFF
  mov rax, r13
  sar rax, 25
  add r14, rax
  and r13, $01FFFFFF
  mov rax, r15
  sar rax, 25
  imul rax, rax, 38
  add rbx, rax
  and r15, $01FFFFFF
  mov rax, rbx
  sar rax, 26
  add rsi, rax
  and rbx, $03FFFFFF
  mov rax, r11
  sar rax, 26
  add r12, rax
  and r11, $03FFFFFF
  mov rax, rsi
  sar rax, 26
  add rdi, rax
  and rsi, $03FFFFFF
  mov rax, r9
  sar rax, 26
  add r10, rax
  and r9, $03FFFFFF
  mov rax, r12
  sar rax, 26
  add r13, rax
  and r12, $03FFFFFF
  mov rax, r14
  sar rax, 26
  add r15, rax
  and r14, $03FFFFFF
  mov [r8+0], ebx
  mov [r8+4], esi
  mov [r8+8], edi
  mov [r8+12], r9d
  mov [r8+16], r10d
  mov [r8+20], r11d
  mov [r8+24], r12d
  mov [r8+28], r13d
  mov [r8+32], r14d
  mov [r8+36], r15d
  add rsp, 240
  pop rbp
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_SQR}
  push rbx
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  push rbp
  sub rsp, 160
  movsxd rax, dword ptr [rcx+0]
  mov [rsp+0], rax
  movsxd rax, dword ptr [rcx+4]
  mov [rsp+8], rax
  movsxd rax, dword ptr [rcx+8]
  mov [rsp+16], rax
  movsxd rax, dword ptr [rcx+12]
  mov [rsp+24], rax
  movsxd rax, dword ptr [rcx+16]
  mov [rsp+32], rax
  movsxd rax, dword ptr [rcx+20]
  mov [rsp+40], rax
  movsxd rax, dword ptr [rcx+24]
  mov [rsp+48], rax
  movsxd rax, dword ptr [rcx+28]
  mov [rsp+56], rax
  movsxd rax, dword ptr [rcx+32]
  mov [rsp+64], rax
  movsxd rax, dword ptr [rcx+36]
  mov [rsp+72], rax
  imul rax, [rsp+8], 19
  mov [rsp+88], rax
  imul rax, [rsp+16], 19
  mov [rsp+96], rax
  imul rax, [rsp+24], 19
  mov [rsp+104], rax
  imul rax, [rsp+32], 19
  mov [rsp+112], rax
  imul rax, [rsp+40], 19
  mov [rsp+120], rax
  imul rax, [rsp+48], 19
  mov [rsp+128], rax
  imul rax, [rsp+56], 19
  mov [rsp+136], rax
  imul rax, [rsp+64], 19
  mov [rsp+144], rax
  imul rax, [rsp+72], 19
  mov [rsp+152], rax
  mov rax, [rsp+0]
  imul rax, [rsp+0]
  mov rbx, rax
  mov rax, [rsp+8]
  imul rax, [rsp+152]
  sal rax, 3
  add rbx, rax
  mov rax, [rsp+16]
  imul rax, [rsp+144]
  sal rax, 3
  add rbx, rax
  mov rax, [rsp+24]
  imul rax, [rsp+136]
  sal rax, 3
  add rbx, rax
  mov rax, [rsp+32]
  imul rax, [rsp+128]
  sal rax, 3
  add rbx, rax
  mov rax, [rsp+40]
  imul rax, [rsp+120]
  sal rax, 1
  add rbx, rax
  mov rax, [rsp+0]
  imul rax, [rsp+8]
  sal rax, 1
  mov rsi, rax
  mov rax, [rsp+16]
  imul rax, [rsp+152]
  sal rax, 3
  add rsi, rax
  mov rax, [rsp+24]
  imul rax, [rsp+144]
  sal rax, 2
  add rsi, rax
  mov rax, [rsp+32]
  imul rax, [rsp+136]
  sal rax, 3
  add rsi, rax
  mov rax, [rsp+40]
  imul rax, [rsp+128]
  sal rax, 2
  add rsi, rax
  mov rax, [rsp+0]
  imul rax, [rsp+16]
  sal rax, 1
  mov rdi, rax
  mov rax, [rsp+8]
  imul rax, [rsp+8]
  add rdi, rax
  mov rax, [rsp+24]
  imul rax, [rsp+152]
  sal rax, 2
  add rdi, rax
  mov rax, [rsp+32]
  imul rax, [rsp+144]
  sal rax, 2
  add rdi, rax
  mov rax, [rsp+40]
  imul rax, [rsp+136]
  sal rax, 2
  add rdi, rax
  mov rax, [rsp+48]
  imul rax, [rsp+128]
  sal rax, 1
  add rdi, rax
  mov rax, [rsp+0]
  imul rax, [rsp+24]
  sal rax, 1
  mov r9, rax
  mov rax, [rsp+8]
  imul rax, [rsp+16]
  sal rax, 2
  add r9, rax
  mov rax, [rsp+32]
  imul rax, [rsp+152]
  sal rax, 3
  add r9, rax
  mov rax, [rsp+40]
  imul rax, [rsp+144]
  sal rax, 2
  add r9, rax
  mov rax, [rsp+48]
  imul rax, [rsp+136]
  sal rax, 3
  add r9, rax
  mov rax, [rsp+0]
  imul rax, [rsp+32]
  sal rax, 1
  mov r10, rax
  mov rax, [rsp+8]
  imul rax, [rsp+24]
  sal rax, 1
  add r10, rax
  mov rax, [rsp+16]
  imul rax, [rsp+16]
  sal rax, 1
  add r10, rax
  mov rax, [rsp+40]
  imul rax, [rsp+152]
  sal rax, 2
  add r10, rax
  mov rax, [rsp+48]
  imul rax, [rsp+144]
  sal rax, 2
  add r10, rax
  mov rax, [rsp+56]
  imul rax, [rsp+136]
  sal rax, 2
  add r10, rax
  mov rax, [rsp+0]
  imul rax, [rsp+40]
  sal rax, 1
  mov r11, rax
  mov rax, [rsp+8]
  imul rax, [rsp+32]
  sal rax, 2
  add r11, rax
  mov rax, [rsp+16]
  imul rax, [rsp+24]
  sal rax, 2
  add r11, rax
  mov rax, [rsp+48]
  imul rax, [rsp+152]
  sal rax, 3
  add r11, rax
  mov rax, [rsp+56]
  imul rax, [rsp+144]
  sal rax, 3
  add r11, rax
  mov rax, [rsp+0]
  imul rax, [rsp+48]
  sal rax, 1
  mov r12, rax
  mov rax, [rsp+8]
  imul rax, [rsp+40]
  sal rax, 1
  add r12, rax
  mov rax, [rsp+16]
  imul rax, [rsp+32]
  sal rax, 2
  add r12, rax
  mov rax, [rsp+24]
  imul rax, [rsp+24]
  add r12, rax
  mov rax, [rsp+56]
  imul rax, [rsp+152]
  sal rax, 3
  add r12, rax
  mov rax, [rsp+64]
  imul rax, [rsp+144]
  sal rax, 1
  add r12, rax
  mov rax, [rsp+0]
  imul rax, [rsp+56]
  sal rax, 1
  mov r13, rax
  mov rax, [rsp+8]
  imul rax, [rsp+48]
  sal rax, 1
  add r13, rax
  mov rax, [rsp+16]
  imul rax, [rsp+40]
  sal rax, 1
  add r13, rax
  mov rax, [rsp+24]
  imul rax, [rsp+32]
  sal rax, 1
  add r13, rax
  mov rax, [rsp+64]
  imul rax, [rsp+152]
  sal rax, 2
  add r13, rax
  mov rax, [rsp+0]
  imul rax, [rsp+64]
  sal rax, 1
  mov r14, rax
  mov rax, [rsp+8]
  imul rax, [rsp+56]
  sal rax, 2
  add r14, rax
  mov rax, [rsp+16]
  imul rax, [rsp+48]
  sal rax, 2
  add r14, rax
  mov rax, [rsp+24]
  imul rax, [rsp+40]
  sal rax, 1
  add r14, rax
  mov rax, [rsp+32]
  imul rax, [rsp+32]
  sal rax, 1
  add r14, rax
  mov rax, [rsp+72]
  imul rax, [rsp+152]
  sal rax, 2
  add r14, rax
  mov rax, [rsp+0]
  imul rax, [rsp+72]
  sal rax, 1
  mov r15, rax
  mov rax, [rsp+8]
  imul rax, [rsp+64]
  sal rax, 1
  add r15, rax
  mov rax, [rsp+16]
  imul rax, [rsp+56]
  sal rax, 2
  add r15, rax
  mov rax, [rsp+24]
  imul rax, [rsp+48]
  sal rax, 1
  add r15, rax
  mov rax, [rsp+32]
  imul rax, [rsp+40]
  sal rax, 1
  add r15, rax
  mov rax, rsi
  sar rax, 26
  add rdi, rax
  and rsi, $03FFFFFF
  mov rax, r9
  sar rax, 26
  add r10, rax
  and r9, $03FFFFFF
  mov rax, r12
  sar rax, 26
  add r13, rax
  and r12, $03FFFFFF
  mov rax, r14
  sar rax, 26
  add r15, rax
  and r14, $03FFFFFF
  mov rax, rdi
  sar rax, 25
  add r9, rax
  and rdi, $01FFFFFF
  mov rax, r10
  sar rax, 25
  add r11, rax
  and r10, $01FFFFFF
  mov rax, r13
  sar rax, 25
  add r14, rax
  and r13, $01FFFFFF
  mov rax, r15
  sar rax, 25
  imul rax, rax, 38
  add rbx, rax
  and r15, $01FFFFFF
  mov rax, rbx
  sar rax, 26
  add rsi, rax
  and rbx, $03FFFFFF
  mov rax, r11
  sar rax, 26
  add r12, rax
  and r11, $03FFFFFF
  mov rax, rsi
  sar rax, 26
  add rdi, rax
  and rsi, $03FFFFFF
  mov rax, r9
  sar rax, 26
  add r10, rax
  and r9, $03FFFFFF
  mov rax, r12
  sar rax, 26
  add r13, rax
  and r12, $03FFFFFF
  mov rax, r14
  sar rax, 26
  add r15, rax
  and r14, $03FFFFFF
  mov [rdx+0], ebx
  mov [rdx+4], esi
  mov [rdx+8], edi
  mov [rdx+12], r9d
  mov [rdx+16], r10d
  mov [rdx+20], r11d
  mov [rdx+24], r12d
  mov [rdx+28], r13d
  mov [rdx+32], r14d
  mov [rdx+36], r15d
  add rsp, 160
  pop rbp
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_ADD}
  mov eax, [rcx+0]
  add eax, [rdx+0]
  mov [r8+0], eax
  mov eax, [rcx+4]
  add eax, [rdx+4]
  mov [r8+4], eax
  mov eax, [rcx+8]
  add eax, [rdx+8]
  mov [r8+8], eax
  mov eax, [rcx+12]
  add eax, [rdx+12]
  mov [r8+12], eax
  mov eax, [rcx+16]
  add eax, [rdx+16]
  mov [r8+16], eax
  mov eax, [rcx+20]
  add eax, [rdx+20]
  mov [r8+20], eax
  mov eax, [rcx+24]
  add eax, [rdx+24]
  mov [r8+24], eax
  mov eax, [rcx+28]
  add eax, [rdx+28]
  mov [r8+28], eax
  mov eax, [rcx+32]
  add eax, [rdx+32]
  mov [r8+32], eax
  mov eax, [rcx+36]
  add eax, [rdx+36]
  mov [r8+36], eax
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_SUB}
  mov eax, [rcx+0]
  sub eax, [rdx+0]
  mov [r8+0], eax
  mov eax, [rcx+4]
  sub eax, [rdx+4]
  mov [r8+4], eax
  mov eax, [rcx+8]
  sub eax, [rdx+8]
  mov [r8+8], eax
  mov eax, [rcx+12]
  sub eax, [rdx+12]
  mov [r8+12], eax
  mov eax, [rcx+16]
  sub eax, [rdx+16]
  mov [r8+16], eax
  mov eax, [rcx+20]
  sub eax, [rdx+20]
  mov [r8+20], eax
  mov eax, [rcx+24]
  sub eax, [rdx+24]
  mov [r8+24], eax
  mov eax, [rcx+28]
  sub eax, [rdx+28]
  mov [r8+28], eax
  mov eax, [rcx+32]
  sub eax, [rdx+32]
  mov [r8+32], eax
  mov eax, [rcx+36]
  sub eax, [rdx+36]
  mov [r8+36], eax
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_APM}
  mov eax, [rcx+0]
  mov r11d, [rdx+0]
  mov r10d, eax
  add eax, r11d
  mov [r8+0], eax
  sub r10d, r11d
  mov [r9+0], r10d
  mov eax, [rcx+4]
  mov r11d, [rdx+4]
  mov r10d, eax
  add eax, r11d
  mov [r8+4], eax
  sub r10d, r11d
  mov [r9+4], r10d
  mov eax, [rcx+8]
  mov r11d, [rdx+8]
  mov r10d, eax
  add eax, r11d
  mov [r8+8], eax
  sub r10d, r11d
  mov [r9+8], r10d
  mov eax, [rcx+12]
  mov r11d, [rdx+12]
  mov r10d, eax
  add eax, r11d
  mov [r8+12], eax
  sub r10d, r11d
  mov [r9+12], r10d
  mov eax, [rcx+16]
  mov r11d, [rdx+16]
  mov r10d, eax
  add eax, r11d
  mov [r8+16], eax
  sub r10d, r11d
  mov [r9+16], r10d
  mov eax, [rcx+20]
  mov r11d, [rdx+20]
  mov r10d, eax
  add eax, r11d
  mov [r8+20], eax
  sub r10d, r11d
  mov [r9+20], r10d
  mov eax, [rcx+24]
  mov r11d, [rdx+24]
  mov r10d, eax
  add eax, r11d
  mov [r8+24], eax
  sub r10d, r11d
  mov [r9+24], r10d
  mov eax, [rcx+28]
  mov r11d, [rdx+28]
  mov r10d, eax
  add eax, r11d
  mov [r8+28], eax
  sub r10d, r11d
  mov [r9+28], r10d
  mov eax, [rcx+32]
  mov r11d, [rdx+32]
  mov r10d, eax
  add eax, r11d
  mov [r8+32], eax
  sub r10d, r11d
  mov [r9+32], r10d
  mov eax, [rcx+36]
  mov r11d, [rdx+36]
  mov r10d, eax
  add eax, r11d
  mov [r8+36], eax
  sub r10d, r11d
  mov [r9+36], r10d
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_CSWAP}
  neg ecx
  mov eax, [rdx+0]
  mov r10d, [r8+0]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+0], eax
  mov [r8+0], r10d
  mov eax, [rdx+4]
  mov r10d, [r8+4]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+4], eax
  mov [r8+4], r10d
  mov eax, [rdx+8]
  mov r10d, [r8+8]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+8], eax
  mov [r8+8], r10d
  mov eax, [rdx+12]
  mov r10d, [r8+12]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+12], eax
  mov [r8+12], r10d
  mov eax, [rdx+16]
  mov r10d, [r8+16]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+16], eax
  mov [r8+16], r10d
  mov eax, [rdx+20]
  mov r10d, [r8+20]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+20], eax
  mov [r8+20], r10d
  mov eax, [rdx+24]
  mov r10d, [r8+24]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+24], eax
  mov [r8+24], r10d
  mov eax, [rdx+28]
  mov r10d, [r8+28]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+28], eax
  mov [r8+28], r10d
  mov eax, [rdx+32]
  mov r10d, [r8+32]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+32], eax
  mov [r8+32], r10d
  mov eax, [rdx+36]
  mov r10d, [r8+36]
  mov r9d, eax
  xor r9d, r10d
  and r9d, ecx
  xor eax, r9d
  xor r10d, r9d
  mov [rdx+36], eax
  mov [r8+36], r10d
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_CARRY}
  push rbx
  push rsi
  push rdi
  push r12
  push rbp
  mov eax, [rcx+0]
  mov edx, [rcx+4]
  mov r8d, [rcx+8]
  mov r9d, [rcx+12]
  mov r10d, [rcx+16]
  mov r11d, [rcx+20]
  mov ebx, [rcx+24]
  mov esi, [rcx+28]
  mov edi, [rcx+32]
  mov r12d, [rcx+36]
  mov ebp, edx
  sar ebp, 26
  add r8d, ebp
  and edx, $03FFFFFF
  mov ebp, r9d
  sar ebp, 26
  add r10d, ebp
  and r9d, $03FFFFFF
  mov ebp, ebx
  sar ebp, 26
  add esi, ebp
  and ebx, $03FFFFFF
  mov ebp, edi
  sar ebp, 26
  add r12d, ebp
  and edi, $03FFFFFF
  mov ebp, r8d
  sar ebp, 25
  add r9d, ebp
  and r8d, $01FFFFFF
  mov ebp, r10d
  sar ebp, 25
  add r11d, ebp
  and r10d, $01FFFFFF
  mov ebp, esi
  sar ebp, 25
  add edi, ebp
  and esi, $01FFFFFF
  mov ebp, r12d
  sar ebp, 25
  imul ebp, ebp, 38
  add eax, ebp
  and r12d, $01FFFFFF
  mov ebp, eax
  sar ebp, 26
  add edx, ebp
  and eax, $03FFFFFF
  mov ebp, r11d
  sar ebp, 26
  add ebx, ebp
  and r11d, $03FFFFFF
  mov ebp, edx
  sar ebp, 26
  add r8d, ebp
  and edx, $03FFFFFF
  mov ebp, r9d
  sar ebp, 26
  add r10d, ebp
  and r9d, $03FFFFFF
  mov ebp, ebx
  sar ebp, 26
  add esi, ebp
  and ebx, $03FFFFFF
  mov ebp, edi
  sar ebp, 26
  add r12d, ebp
  and edi, $03FFFFFF
  mov [rcx+0], eax
  mov [rcx+4], edx
  mov [rcx+8], r8d
  mov [rcx+12], r9d
  mov [rcx+16], r10d
  mov [rcx+20], r11d
  mov [rcx+24], ebx
  mov [rcx+28], esi
  mov [rcx+32], edi
  mov [rcx+36], r12d
  pop rbp
  pop r12
  pop rdi
  pop rsi
  pop rbx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_MULWORD}
  push rbx
  push rsi
  push rdi
  push r12
  push r13
  push r14
  movsxd r11, edx
  movsxd rax, dword ptr [rcx+8]
  imul rax, r11
  mov edi, eax
  and edi, $01FFFFFF
  sar rax, 25
  mov r9, rax
  movsxd rax, dword ptr [rcx+16]
  imul rax, r11
  mov r12d, eax
  and r12d, $01FFFFFF
  sar rax, 25
  mov r10, rax
  movsxd rax, dword ptr [rcx+28]
  imul rax, r11
  mov r13d, eax
  and r13d, $01FFFFFF
  sar rax, 25
  mov rbx, rax
  movsxd rax, dword ptr [rcx+36]
  imul rax, r11
  mov r14d, eax
  and r14d, $01FFFFFF
  sar rax, 25
  mov rsi, rax
  imul rsi, rsi, 38
  movsxd rax, dword ptr [rcx+0]
  imul rax, r11
  add rsi, rax
  mov eax, esi
  and eax, $03FFFFFF
  mov [r8+0], eax
  sar rsi, 26
  movsxd rax, dword ptr [rcx+20]
  imul rax, r11
  add r10, rax
  mov eax, r10d
  and eax, $03FFFFFF
  mov [r8+20], eax
  sar r10, 26
  movsxd rax, dword ptr [rcx+4]
  imul rax, r11
  add rsi, rax
  mov eax, esi
  and eax, $03FFFFFF
  mov [r8+4], eax
  sar rsi, 26
  movsxd rax, dword ptr [rcx+12]
  imul rax, r11
  add r9, rax
  mov eax, r9d
  and eax, $03FFFFFF
  mov [r8+12], eax
  sar r9, 26
  movsxd rax, dword ptr [rcx+24]
  imul rax, r11
  add r10, rax
  mov eax, r10d
  and eax, $03FFFFFF
  mov [r8+24], eax
  sar r10, 26
  movsxd rax, dword ptr [rcx+32]
  imul rax, r11
  add rbx, rax
  mov eax, ebx
  and eax, $03FFFFFF
  mov [r8+32], eax
  sar rbx, 26
  mov eax, edi
  add eax, esi
  mov [r8+8], eax
  mov eax, r12d
  add eax, r9d
  mov [r8+16], eax
  mov eax, r13d
  add eax, r10d
  mov [r8+28], eax
  mov eax, r14d
  add eax, ebx
  mov [r8+36], eax
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbx
{$ELSE}
{$FATAL Define one of CRYPTOLIB_CURVE25519_MUL/SQR/ADD/SUB/APM/CSWAP/CARRY/MULWORD}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
{$ENDIF}
