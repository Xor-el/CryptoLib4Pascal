// Fused secp256k1 incomplete-Jacobian point kernels (a=0, x86-64).
// -------------------------------------------------------------------
//
// One selector-driven file; exactly one of the following must be defined
// before including this file:
//
//   CRYPTOLIB_FP_K256_POINTDOUBLE   (ClpSimdProc3Begin: rcx = PR, rdx = PA, r8 = PCtx)
//     - straight-line incomplete Jacobian doubling PR := 2*PA (dbl-2009-l,
//       a=0). Infinity (Z=0) maps to infinity with no branch.
//   CRYPTOLIB_FP_K256_POINTADD   (ClpSimdProc4Begin: rcx = PScratch, rdx = PA, r8 = PQ, r9 = PCtx)
//     - incomplete Jacobian addition (add-2007-bl) with the branch-free
//       masked-infinity completion applied inside the kernel, writing the
//       result to PScratch.R and the predicate operands H (= U2-U1) and
//       RS (= S2-S1) to PScratch.H / PScratch.RS. The caller owns the P=Q
//       detect-and-double BRANCH (fires iff both finite and H=0 and RS=0);
//       no data-dependent branch lives in the asm.
//   CRYPTOLIB_FP_K256_POINTADDMIXED   (ClpSimdProc4Begin: rcx = PScratch, rdx = PA, r8 = PQ, r9 = PCtx)
//     - the same addition with PQ an AFFINE point (Z2=1 via PCtx.MontOne
//       at +160).
//
// PScratch is a record { R: TFePoint; H, RS: TFe } (R.X/Y/Z at +0/+72/+144,
// H at +216, RS at +288). PA/PQ are TFePoint (or TFeAffine) bases. PCtx =
// [n0', N, p0..p3]; these kernels carry NO b-multiply. Every intermediate
// lives in a fixed stack frame and both inputs are copied in up front, so
// PScratch never aliases an input. k1's prime is pseudo-Mersenne (n0' != 1,
// no folded reduction): the field multiply is the generic MULX4 CIOS body and
// the square is the dedicated dual-chain SOS square + generic reduce, inlined
// verbatim. Constant-time: straight-line and data-independent; the masked-
// infinity completion and the exposed predicate are branch-free. Backend-gated
// on BMI2+ADX (x86-64); any other target uses the generic per-op incomplete-
// Jacobian formula, bit-for-bit.
{$IFDEF CRYPTOLIB_FP_K256_POINTDOUBLE}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  mov r9, r8            // r9 = PCtx (pinned; cores read [r9 + ..])
  sub rsp, 400
  mov [rsp + 384], rcx   // save output-point pointer
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
  // sqr A = X
  lea rsi, [rsp + 0]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // sqr B = Y
  lea rsi, [rsp + 32]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // sqr C = B
  lea rsi, [rsp + 128]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // ModAdd tmp = X + B
  mov r8, [rsp + 0]
  add r8, [rsp + 128]
  mov r10, [rsp + 0 + 8]
  adc r10, [rsp + 128 + 8]
  mov r11, [rsp + 0 + 16]
  adc r11, [rsp + 128 + 16]
  mov r12, [rsp + 0 + 24]
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
  // sqr tmp = tmp
  lea rsi, [rsp + 256]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // ModSub tmp = tmp - A
  mov r8, [rsp + 256]
  sub r8, [rsp + 96]
  mov r10, [rsp + 256 + 8]
  sbb r10, [rsp + 96 + 8]
  mov r11, [rsp + 256 + 16]
  sbb r11, [rsp + 96 + 16]
  mov r12, [rsp + 256 + 24]
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
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // ModSub tmp = tmp - C
  mov r8, [rsp + 256]
  sub r8, [rsp + 160]
  mov r10, [rsp + 256 + 8]
  sbb r10, [rsp + 160 + 8]
  mov r11, [rsp + 256 + 16]
  sbb r11, [rsp + 160 + 16]
  mov r12, [rsp + 256 + 24]
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
  mov [rsp + 256], r8
  mov [rsp + 264], r10
  mov [rsp + 272], r11
  mov [rsp + 280], r12
  // ModAdd D = tmp + tmp
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
  // ModAdd E = A + A
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
  // ModAdd E = E + A
  mov r8, [rsp + 224]
  add r8, [rsp + 96]
  mov r10, [rsp + 224 + 8]
  adc r10, [rsp + 96 + 8]
  mov r11, [rsp + 224 + 16]
  adc r11, [rsp + 96 + 16]
  mov r12, [rsp + 224 + 24]
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
  // sqr X3 = E
  lea rsi, [rsp + 224]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // ModAdd tmp = D + D
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
  // ModSub X3 = X3 - tmp
  mov r8, [rsp + 288]
  sub r8, [rsp + 256]
  mov r10, [rsp + 288 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 288 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 288 + 24]
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
  mov [rsp + 288], r8
  mov [rsp + 296], r10
  mov [rsp + 304], r11
  mov [rsp + 312], r12
  // ModSub tmp = D - X3
  mov r8, [rsp + 192]
  sub r8, [rsp + 288]
  mov r10, [rsp + 192 + 8]
  sbb r10, [rsp + 288 + 8]
  mov r11, [rsp + 192 + 16]
  sbb r11, [rsp + 288 + 16]
  mov r12, [rsp + 192 + 24]
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
  // mul Y3 = E * tmp
  lea rsi, [rsp + 224]
  lea rdi, [rsp + 256]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 320], r13
  mov [rsp + 328], r14
  mov [rsp + 336], r8
  mov [rsp + 344], r10
  // ModAdd tmp = C + C
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
  // ModAdd tmp = tmp + tmp
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
  // ModAdd tmp = tmp + tmp
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
  // ModSub Y3 = Y3 - tmp
  mov r8, [rsp + 320]
  sub r8, [rsp + 256]
  mov r10, [rsp + 320 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 320 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 320 + 24]
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
  mov [rsp + 320], r8
  mov [rsp + 328], r10
  mov [rsp + 336], r11
  mov [rsp + 344], r12
  // mul Z3 = Y * Z
  lea rsi, [rsp + 32]
  lea rdi, [rsp + 64]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 352], r13
  mov [rsp + 360], r14
  mov [rsp + 368], r8
  mov [rsp + 376], r10
  // ModAdd Z3 = Z3 + Z3
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
  // store result point X3,Y3,Z3
  mov rcx, [rsp + 384]
  mov rax, [rsp + 288]
  mov [rcx + 0], rax
  mov rax, [rsp + 296]
  mov [rcx + 8], rax
  mov rax, [rsp + 304]
  mov [rcx + 16], rax
  mov rax, [rsp + 312]
  mov [rcx + 24], rax
  mov rax, [rsp + 320]
  mov [rcx + 72], rax
  mov rax, [rsp + 328]
  mov [rcx + 80], rax
  mov rax, [rsp + 336]
  mov [rcx + 88], rax
  mov rax, [rsp + 344]
  mov [rcx + 96], rax
  mov rax, [rsp + 352]
  mov [rcx + 144], rax
  mov rax, [rsp + 360]
  mov [rcx + 152], rax
  mov rax, [rsp + 368]
  mov [rcx + 160], rax
  mov rax, [rsp + 376]
  mov [rcx + 168], rax
  add rsp, 400
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
{$ELSE}
  {$IFDEF CRYPTOLIB_FP_K256_POINTADD}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  sub rsp, 720
  mov [rsp + 704], rcx   // save output scratch pointer
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
  // sqr Z1Z1 = Z1
  lea rsi, [rsp + 64]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // sqr Z2Z2 = Z2
  lea rsi, [rsp + 160]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // mul U1 = X1 * Z2Z2
  lea rsi, [rsp + 0]
  lea rdi, [rsp + 224]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 256], r13
  mov [rsp + 264], r14
  mov [rsp + 272], r8
  mov [rsp + 280], r10
  // mul U2 = X2 * Z1Z1
  lea rsi, [rsp + 96]
  lea rdi, [rsp + 192]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 288], r13
  mov [rsp + 296], r14
  mov [rsp + 304], r8
  mov [rsp + 312], r10
  // mul t = Y1 * Z2
  lea rsi, [rsp + 32]
  lea rdi, [rsp + 160]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 576], r13
  mov [rsp + 584], r14
  mov [rsp + 592], r8
  mov [rsp + 600], r10
  // mul S1 = t * Z2Z2
  lea rsi, [rsp + 576]
  lea rdi, [rsp + 224]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 320], r13
  mov [rsp + 328], r14
  mov [rsp + 336], r8
  mov [rsp + 344], r10
  // mul t = Y2 * Z1
  lea rsi, [rsp + 128]
  lea rdi, [rsp + 64]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 576], r13
  mov [rsp + 584], r14
  mov [rsp + 592], r8
  mov [rsp + 600], r10
  // mul S2 = t * Z1Z1
  lea rsi, [rsp + 576]
  lea rdi, [rsp + 192]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 352], r13
  mov [rsp + 360], r14
  mov [rsp + 368], r8
  mov [rsp + 376], r10
  // ModSub H = U2 - U1
  mov r8, [rsp + 288]
  sub r8, [rsp + 256]
  mov r10, [rsp + 288 + 8]
  sbb r10, [rsp + 256 + 8]
  mov r11, [rsp + 288 + 16]
  sbb r11, [rsp + 256 + 16]
  mov r12, [rsp + 288 + 24]
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
  // ModSub RS = S2 - S1
  mov r8, [rsp + 352]
  sub r8, [rsp + 320]
  mov r10, [rsp + 352 + 8]
  sbb r10, [rsp + 320 + 8]
  mov r11, [rsp + 352 + 16]
  sbb r11, [rsp + 320 + 16]
  mov r12, [rsp + 352 + 24]
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
  mov [rsp + 416], r8
  mov [rsp + 424], r10
  mov [rsp + 432], r11
  mov [rsp + 440], r12
  // ModAdd R = RS + RS
  mov r8, [rsp + 416]
  add r8, [rsp + 416]
  mov r10, [rsp + 416 + 8]
  adc r10, [rsp + 416 + 8]
  mov r11, [rsp + 416 + 16]
  adc r11, [rsp + 416 + 16]
  mov r12, [rsp + 416 + 24]
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
  mov [rsp + 448], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 456], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 464], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 472], r12
  // ModAdd t = H + H
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
  mov [rsp + 576], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 584], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 592], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 600], r12
  // sqr I = t
  lea rsi, [rsp + 576]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  mov [rsp + 480], r8
  mov [rsp + 488], r10
  mov [rsp + 496], r11
  mov [rsp + 504], r12
  // mul J = H * I
  lea rsi, [rsp + 384]
  lea rdi, [rsp + 480]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 512], r13
  mov [rsp + 520], r14
  mov [rsp + 528], r8
  mov [rsp + 536], r10
  // mul V = U1 * I
  lea rsi, [rsp + 256]
  lea rdi, [rsp + 480]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 544], r13
  mov [rsp + 552], r14
  mov [rsp + 560], r8
  mov [rsp + 568], r10
  // sqr X3 = R
  lea rsi, [rsp + 448]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  mov [rsp + 608], r8
  mov [rsp + 616], r10
  mov [rsp + 624], r11
  mov [rsp + 632], r12
  // ModSub X3 = X3 - J
  mov r8, [rsp + 608]
  sub r8, [rsp + 512]
  mov r10, [rsp + 608 + 8]
  sbb r10, [rsp + 512 + 8]
  mov r11, [rsp + 608 + 16]
  sbb r11, [rsp + 512 + 16]
  mov r12, [rsp + 608 + 24]
  sbb r12, [rsp + 512 + 24]
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
  mov [rsp + 608], r8
  mov [rsp + 616], r10
  mov [rsp + 624], r11
  mov [rsp + 632], r12
  // ModAdd t = V + V
  mov r8, [rsp + 544]
  add r8, [rsp + 544]
  mov r10, [rsp + 544 + 8]
  adc r10, [rsp + 544 + 8]
  mov r11, [rsp + 544 + 16]
  adc r11, [rsp + 544 + 16]
  mov r12, [rsp + 544 + 24]
  adc r12, [rsp + 544 + 24]
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
  mov [rsp + 576], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 584], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 592], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 600], r12
  // ModSub X3 = X3 - t
  mov r8, [rsp + 608]
  sub r8, [rsp + 576]
  mov r10, [rsp + 608 + 8]
  sbb r10, [rsp + 576 + 8]
  mov r11, [rsp + 608 + 16]
  sbb r11, [rsp + 576 + 16]
  mov r12, [rsp + 608 + 24]
  sbb r12, [rsp + 576 + 24]
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
  mov [rsp + 608], r8
  mov [rsp + 616], r10
  mov [rsp + 624], r11
  mov [rsp + 632], r12
  // ModSub t = V - X3
  mov r8, [rsp + 544]
  sub r8, [rsp + 608]
  mov r10, [rsp + 544 + 8]
  sbb r10, [rsp + 608 + 8]
  mov r11, [rsp + 544 + 16]
  sbb r11, [rsp + 608 + 16]
  mov r12, [rsp + 544 + 24]
  sbb r12, [rsp + 608 + 24]
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
  mov [rsp + 576], r8
  mov [rsp + 584], r10
  mov [rsp + 592], r11
  mov [rsp + 600], r12
  // mul Y3 = R * t
  lea rsi, [rsp + 448]
  lea rdi, [rsp + 576]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 640], r13
  mov [rsp + 648], r14
  mov [rsp + 656], r8
  mov [rsp + 664], r10
  // mul t = S1 * J
  lea rsi, [rsp + 320]
  lea rdi, [rsp + 512]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 576], r13
  mov [rsp + 584], r14
  mov [rsp + 592], r8
  mov [rsp + 600], r10
  // ModAdd t = t + t
  mov r8, [rsp + 576]
  add r8, [rsp + 576]
  mov r10, [rsp + 576 + 8]
  adc r10, [rsp + 576 + 8]
  mov r11, [rsp + 576 + 16]
  adc r11, [rsp + 576 + 16]
  mov r12, [rsp + 576 + 24]
  adc r12, [rsp + 576 + 24]
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
  mov [rsp + 576], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 584], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 592], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 600], r12
  // ModSub Y3 = Y3 - t
  mov r8, [rsp + 640]
  sub r8, [rsp + 576]
  mov r10, [rsp + 640 + 8]
  sbb r10, [rsp + 576 + 8]
  mov r11, [rsp + 640 + 16]
  sbb r11, [rsp + 576 + 16]
  mov r12, [rsp + 640 + 24]
  sbb r12, [rsp + 576 + 24]
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
  mov [rsp + 640], r8
  mov [rsp + 648], r10
  mov [rsp + 656], r11
  mov [rsp + 664], r12
  // ModAdd Z3 = Z1 + Z2
  mov r8, [rsp + 64]
  add r8, [rsp + 160]
  mov r10, [rsp + 64 + 8]
  adc r10, [rsp + 160 + 8]
  mov r11, [rsp + 64 + 16]
  adc r11, [rsp + 160 + 16]
  mov r12, [rsp + 64 + 24]
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
  mov [rsp + 672], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 680], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 688], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 696], r12
  // sqr Z3 = Z3
  lea rsi, [rsp + 672]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  mov [rsp + 672], r8
  mov [rsp + 680], r10
  mov [rsp + 688], r11
  mov [rsp + 696], r12
  // ModSub Z3 = Z3 - Z1Z1
  mov r8, [rsp + 672]
  sub r8, [rsp + 192]
  mov r10, [rsp + 672 + 8]
  sbb r10, [rsp + 192 + 8]
  mov r11, [rsp + 672 + 16]
  sbb r11, [rsp + 192 + 16]
  mov r12, [rsp + 672 + 24]
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
  mov [rsp + 672], r8
  mov [rsp + 680], r10
  mov [rsp + 688], r11
  mov [rsp + 696], r12
  // ModSub Z3 = Z3 - Z2Z2
  mov r8, [rsp + 672]
  sub r8, [rsp + 224]
  mov r10, [rsp + 672 + 8]
  sbb r10, [rsp + 224 + 8]
  mov r11, [rsp + 672 + 16]
  sbb r11, [rsp + 224 + 16]
  mov r12, [rsp + 672 + 24]
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
  mov [rsp + 672], r8
  mov [rsp + 680], r10
  mov [rsp + 688], r11
  mov [rsp + 696], r12
  // mul Z3 = Z3 * H
  lea rsi, [rsp + 672]
  lea rdi, [rsp + 384]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 672], r13
  mov [rsp + 680], r14
  mov [rsp + 688], r8
  mov [rsp + 696], r10
  // infinity masks in1 (r13), in2 (r14)
  mov rax, [rsp + 64]
  or rax, [rsp + 72]
  or rax, [rsp + 80]
  or rax, [rsp + 88]
  xor r13, r13
  test rax, rax
  setz r13b
  neg r13
  mov rax, [rsp + 160]
  or rax, [rsp + 168]
  or rax, [rsp + 176]
  or rax, [rsp + 184]
  xor r14, r14
  test rax, rax
  setz r14b
  neg r14
  mov rcx, [rsp + 704]
  // masked select X3 -> R
  mov rax, [rsp + 608]
  mov rbx, [rsp + 0]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 96]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 0], rax
  mov rax, [rsp + 616]
  mov rbx, [rsp + 8]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 104]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 8], rax
  mov rax, [rsp + 624]
  mov rbx, [rsp + 16]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 112]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 16], rax
  mov rax, [rsp + 632]
  mov rbx, [rsp + 24]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 120]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 24], rax
  // masked select Y3 -> R
  mov rax, [rsp + 640]
  mov rbx, [rsp + 32]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 128]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 72], rax
  mov rax, [rsp + 648]
  mov rbx, [rsp + 40]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 136]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 80], rax
  mov rax, [rsp + 656]
  mov rbx, [rsp + 48]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 144]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 88], rax
  mov rax, [rsp + 664]
  mov rbx, [rsp + 56]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 152]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 96], rax
  // masked select Z3 -> R
  mov rax, [rsp + 672]
  mov rbx, [rsp + 64]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 160]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 144], rax
  mov rax, [rsp + 680]
  mov rbx, [rsp + 72]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 168]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 152], rax
  mov rax, [rsp + 688]
  mov rbx, [rsp + 80]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 176]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 160], rax
  mov rax, [rsp + 696]
  mov rbx, [rsp + 88]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 184]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 168], rax
  // expose predicate operands H, RS
  mov rax, [rsp + 384]
  mov [rcx + 216], rax
  mov rax, [rsp + 392]
  mov [rcx + 224], rax
  mov rax, [rsp + 400]
  mov [rcx + 232], rax
  mov rax, [rsp + 408]
  mov [rcx + 240], rax
  mov rax, [rsp + 416]
  mov [rcx + 288], rax
  mov rax, [rsp + 424]
  mov [rcx + 296], rax
  mov rax, [rsp + 432]
  mov [rcx + 304], rax
  mov rax, [rsp + 440]
  mov [rcx + 312], rax
  add rsp, 720
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
  {$ELSE}
    {$IFDEF CRYPTOLIB_FP_K256_POINTADDMIXED}
  push rbx
  push rbp
  push rsi
  push rdi
  push r12
  push r13
  push r14
  push r15
  sub rsp, 624
  mov [rsp + 608], rcx   // save output scratch pointer
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
  // affine Q: 'one' := MontOne (R mod p) off PCtx
  mov rax, [r9 + 160]
  mov [rsp + 160], rax
  mov rax, [r9 + 168]
  mov [rsp + 168], rax
  mov rax, [r9 + 176]
  mov [rsp + 176], rax
  mov rax, [r9 + 184]
  mov [rsp + 184], rax
  // sqr Z1Z1 = Z1
  lea rsi, [rsp + 64]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // mul U2 = X2 * Z1Z1
  lea rsi, [rsp + 96]
  lea rdi, [rsp + 192]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 224], r13
  mov [rsp + 232], r14
  mov [rsp + 240], r8
  mov [rsp + 248], r10
  // mul t = Y2 * Z1
  lea rsi, [rsp + 128]
  lea rdi, [rsp + 64]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 480], r13
  mov [rsp + 488], r14
  mov [rsp + 496], r8
  mov [rsp + 504], r10
  // mul S2 = t * Z1Z1
  lea rsi, [rsp + 480]
  lea rdi, [rsp + 192]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 256], r13
  mov [rsp + 264], r14
  mov [rsp + 272], r8
  mov [rsp + 280], r10
  // ModSub H = U2 - X1
  mov r8, [rsp + 224]
  sub r8, [rsp + 0]
  mov r10, [rsp + 224 + 8]
  sbb r10, [rsp + 0 + 8]
  mov r11, [rsp + 224 + 16]
  sbb r11, [rsp + 0 + 16]
  mov r12, [rsp + 224 + 24]
  sbb r12, [rsp + 0 + 24]
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
  // ModSub RS = S2 - Y1
  mov r8, [rsp + 256]
  sub r8, [rsp + 32]
  mov r10, [rsp + 256 + 8]
  sbb r10, [rsp + 32 + 8]
  mov r11, [rsp + 256 + 16]
  sbb r11, [rsp + 32 + 16]
  mov r12, [rsp + 256 + 24]
  sbb r12, [rsp + 32 + 24]
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
  // ModAdd R = RS + RS
  mov r8, [rsp + 320]
  add r8, [rsp + 320]
  mov r10, [rsp + 320 + 8]
  adc r10, [rsp + 320 + 8]
  mov r11, [rsp + 320 + 16]
  adc r11, [rsp + 320 + 16]
  mov r12, [rsp + 320 + 24]
  adc r12, [rsp + 320 + 24]
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
  // ModAdd t = H + H
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
  mov [rsp + 480], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 488], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 496], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 504], r12
  // sqr I = t
  lea rsi, [rsp + 480]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  // mul J = H * I
  lea rsi, [rsp + 288]
  lea rdi, [rsp + 384]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 416], r13
  mov [rsp + 424], r14
  mov [rsp + 432], r8
  mov [rsp + 440], r10
  // mul V = X1 * I
  lea rsi, [rsp + 0]
  lea rdi, [rsp + 384]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 448], r13
  mov [rsp + 456], r14
  mov [rsp + 464], r8
  mov [rsp + 472], r10
  // sqr X3 = R
  lea rsi, [rsp + 352]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  mov [rsp + 512], r8
  mov [rsp + 520], r10
  mov [rsp + 528], r11
  mov [rsp + 536], r12
  // ModSub X3 = X3 - J
  mov r8, [rsp + 512]
  sub r8, [rsp + 416]
  mov r10, [rsp + 512 + 8]
  sbb r10, [rsp + 416 + 8]
  mov r11, [rsp + 512 + 16]
  sbb r11, [rsp + 416 + 16]
  mov r12, [rsp + 512 + 24]
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
  mov [rsp + 512], r8
  mov [rsp + 520], r10
  mov [rsp + 528], r11
  mov [rsp + 536], r12
  // ModAdd t = V + V
  mov r8, [rsp + 448]
  add r8, [rsp + 448]
  mov r10, [rsp + 448 + 8]
  adc r10, [rsp + 448 + 8]
  mov r11, [rsp + 448 + 16]
  adc r11, [rsp + 448 + 16]
  mov r12, [rsp + 448 + 24]
  adc r12, [rsp + 448 + 24]
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
  mov [rsp + 480], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 488], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 496], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 504], r12
  // ModSub X3 = X3 - t
  mov r8, [rsp + 512]
  sub r8, [rsp + 480]
  mov r10, [rsp + 512 + 8]
  sbb r10, [rsp + 480 + 8]
  mov r11, [rsp + 512 + 16]
  sbb r11, [rsp + 480 + 16]
  mov r12, [rsp + 512 + 24]
  sbb r12, [rsp + 480 + 24]
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
  mov [rsp + 512], r8
  mov [rsp + 520], r10
  mov [rsp + 528], r11
  mov [rsp + 536], r12
  // ModSub t = V - X3
  mov r8, [rsp + 448]
  sub r8, [rsp + 512]
  mov r10, [rsp + 448 + 8]
  sbb r10, [rsp + 512 + 8]
  mov r11, [rsp + 448 + 16]
  sbb r11, [rsp + 512 + 16]
  mov r12, [rsp + 448 + 24]
  sbb r12, [rsp + 512 + 24]
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
  mov [rsp + 480], r8
  mov [rsp + 488], r10
  mov [rsp + 496], r11
  mov [rsp + 504], r12
  // mul Y3 = R * t
  lea rsi, [rsp + 352]
  lea rdi, [rsp + 480]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 544], r13
  mov [rsp + 552], r14
  mov [rsp + 560], r8
  mov [rsp + 568], r10
  // mul t = Y1 * J
  lea rsi, [rsp + 32]
  lea rdi, [rsp + 416]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 480], r13
  mov [rsp + 488], r14
  mov [rsp + 496], r8
  mov [rsp + 504], r10
  // ModAdd t = t + t
  mov r8, [rsp + 480]
  add r8, [rsp + 480]
  mov r10, [rsp + 480 + 8]
  adc r10, [rsp + 480 + 8]
  mov r11, [rsp + 480 + 16]
  adc r11, [rsp + 480 + 16]
  mov r12, [rsp + 480 + 24]
  adc r12, [rsp + 480 + 24]
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
  mov [rsp + 480], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 488], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 496], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 504], r12
  // ModSub Y3 = Y3 - t
  mov r8, [rsp + 544]
  sub r8, [rsp + 480]
  mov r10, [rsp + 544 + 8]
  sbb r10, [rsp + 480 + 8]
  mov r11, [rsp + 544 + 16]
  sbb r11, [rsp + 480 + 16]
  mov r12, [rsp + 544 + 24]
  sbb r12, [rsp + 480 + 24]
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
  mov [rsp + 544], r8
  mov [rsp + 552], r10
  mov [rsp + 560], r11
  mov [rsp + 568], r12
  // ModAdd Z3 = Z1 + one
  mov r8, [rsp + 64]
  add r8, [rsp + 160]
  mov r10, [rsp + 64 + 8]
  adc r10, [rsp + 160 + 8]
  mov r11, [rsp + 64 + 16]
  adc r11, [rsp + 160 + 16]
  mov r12, [rsp + 64 + 24]
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
  mov [rsp + 576], r8
  and r10, rcx
  mov rdx, r15
  and rdx, rax
  or r10, rdx
  mov [rsp + 584], r10
  and r11, rcx
  mov rdx, rbx
  and rdx, rax
  or r11, rdx
  mov [rsp + 592], r11
  and r12, rcx
  mov rdx, rsi
  and rdx, rax
  or r12, rdx
  mov [rsp + 600], r12
  // sqr Z3 = Z3
  lea rsi, [rsp + 576]
// dedicated Montgomery square (generic reduce): [rsi]^2 -> r8,r10,r11,r12
  xor r10, r10
  xor r11, r11
  xor r12, r12
  xor r13, r13
  xor r14, r14
  xor r15, r15
  mov rdx, [rsi]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $08  // mulx rbx, rcx, qword ptr [rsi + 8]
  db $66, $4C, $0F, $38, $F6, $D1  // adcx r10, rcx
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $D9  // adcx r11, rcx
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  mov rdx, [rsi+8]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $10  // mulx rbx, rcx, qword ptr [rsi + 0x10]
  db $66, $4C, $0F, $38, $F6, $E1  // adcx r12, rcx
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $E9  // adcx r13, rcx
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  mov rdx, [rsi+16]
  xor eax, eax
  db $C4, $E2, $F3, $F6, $5E, $18  // mulx rbx, rcx, qword ptr [rsi + 0x18]
  db $66, $4C, $0F, $38, $F6, $F1  // adcx r14, rcx
  db $F3, $4C, $0F, $38, $F6, $FB  // adox r15, rbx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  xor edi, edi
  db $66, $4D, $0F, $38, $F6, $D2  // adcx r10, r10
  mov rdx, [rsi]
  db $C4, $E2, $BB, $F6, $1E       // mulx rbx, r8, qword ptr [rsi]
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4D, $0F, $38, $F6, $DB  // adcx r11, r11
  mov rdx, [rsi+8]
  db $C4, $E2, $FB, $F6, $4E, $08  // mulx rcx, rax, qword ptr [rsi + 8]
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4D, $0F, $38, $F6, $E4  // adcx r12, r12
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $66, $4D, $0F, $38, $F6, $ED  // adcx r13, r13
  mov rdx, [rsi+16]
  db $C4, $E2, $FB, $F6, $4E, $10  // mulx rcx, rax, qword ptr [rsi + 0x10]
  db $F3, $4C, $0F, $38, $F6, $E8  // adox r13, rax
  db $66, $4D, $0F, $38, $F6, $F6  // adcx r14, r14
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $66, $4D, $0F, $38, $F6, $FF  // adcx r15, r15
  mov rdx, [rsi+24]
  db $C4, $E2, $FB, $F6, $4E, $18  // mulx rcx, rax, qword ptr [rsi + 0x18]
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $48, $0F, $38, $F6, $FF  // adcx rdi, rdi
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  xor esi, esi
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $C3  // adcx r8, rbx
  db $F3, $4C, $0F, $38, $F6, $D1  // adox r10, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $D3  // adcx r10, rbx
  db $F3, $4C, $0F, $38, $F6, $D9  // adox r11, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $F8  // adox r15, rax
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $DB  // adcx r11, rbx
  db $F3, $4C, $0F, $38, $F6, $E1  // adox r12, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  mov eax, 0
  db $66, $4C, $0F, $38, $F6, $F8  // adcx r15, rax
  db $F3, $48, $0F, $38, $F6, $F8  // adox rdi, rax
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $E3, $F6, $49, $10  // mulx rcx, rbx, qword ptr [r9 + 0x10]
  db $66, $4C, $0F, $38, $F6, $E3  // adcx r12, rbx
  db $F3, $4C, $0F, $38, $F6, $E9  // adox r13, rcx
  db $C4, $C2, $E3, $F6, $49, $18  // mulx rcx, rbx, qword ptr [r9 + 0x18]
  db $66, $4C, $0F, $38, $F6, $EB  // adcx r13, rbx
  db $F3, $4C, $0F, $38, $F6, $F1  // adox r14, rcx
  db $C4, $C2, $E3, $F6, $49, $20  // mulx rcx, rbx, qword ptr [r9 + 0x20]
  db $66, $4C, $0F, $38, $F6, $F3  // adcx r14, rbx
  db $F3, $4C, $0F, $38, $F6, $F9  // adox r15, rcx
  db $C4, $C2, $E3, $F6, $49, $28  // mulx rcx, rbx, qword ptr [r9 + 0x28]
  db $66, $4C, $0F, $38, $F6, $FB  // adcx r15, rbx
  db $F3, $48, $0F, $38, $F6, $F9  // adox rdi, rcx
  mov eax, 0
  db $66, $48, $0F, $38, $F6, $F8  // adcx rdi, rax
  db $F3, $48, $0F, $38, $F6, $F0  // adox rsi, rax
  db $66, $48, $0F, $38, $F6, $F0  // adcx rsi, rax
  mov r8, r13
  mov r10, r14
  mov r11, r15
  mov r12, rdi
  mov r13, rsi
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
  mov [rsp + 576], r8
  mov [rsp + 584], r10
  mov [rsp + 592], r11
  mov [rsp + 600], r12
  // ModSub Z3 = Z3 - Z1Z1
  mov r8, [rsp + 576]
  sub r8, [rsp + 192]
  mov r10, [rsp + 576 + 8]
  sbb r10, [rsp + 192 + 8]
  mov r11, [rsp + 576 + 16]
  sbb r11, [rsp + 192 + 16]
  mov r12, [rsp + 576 + 24]
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
  mov [rsp + 576], r8
  mov [rsp + 584], r10
  mov [rsp + 592], r11
  mov [rsp + 600], r12
  // ModSub Z3 = Z3 - one
  mov r8, [rsp + 576]
  sub r8, [rsp + 160]
  mov r10, [rsp + 576 + 8]
  sbb r10, [rsp + 160 + 8]
  mov r11, [rsp + 576 + 16]
  sbb r11, [rsp + 160 + 16]
  mov r12, [rsp + 576 + 24]
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
  mov [rsp + 576], r8
  mov [rsp + 584], r10
  mov [rsp + 592], r11
  mov [rsp + 600], r12
  // mul Z3 = Z3 * H
  lea rsi, [rsp + 576]
  lea rdi, [rsp + 288]
  mov rdx, [rdi]
  db $C4, $62, $BB, $F6, $16       // mulx r10, r8, qword ptr [rsi]
  db $C4, $62, $E3, $F6, $5E, $08  // mulx r11, rbx, qword ptr [rsi + 8]
  db $C4, $62, $F3, $F6, $66, $10  // mulx r12, rcx, qword ptr [rsi + 0x10]
  db $C4, $62, $83, $F6, $6E, $18  // mulx r13, r15, qword ptr [rsi + 0x18]
  xor r14d, r14d
  add r10, rbx
  adc r11, rcx
  adc r12, r15
  adc r13, 0
  mov rdx, [r9]
  imul rdx, r8
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $66, $4C, $0F, $38, $F6, $E8  // adcx r13, rax
  db $F3, $4C, $0F, $38, $F6, $F0  // adox r14, rax
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  mov rdx, [rdi+8]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [r9]
  imul rdx, r10
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $D7  // adcx r10, r15
  db $F3, $4C, $0F, $38, $F6, $DB  // adox r11, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $66, $4C, $0F, $38, $F6, $F0  // adcx r14, rax
  db $F3, $4C, $0F, $38, $F6, $C0  // adox r8, rax
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  mov rdx, [rdi+16]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [r9]
  imul rdx, r11
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $DF  // adcx r11, r15
  db $F3, $4C, $0F, $38, $F6, $E3  // adox r12, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $66, $4C, $0F, $38, $F6, $C0  // adcx r8, rax
  db $F3, $4C, $0F, $38, $F6, $D0  // adox r10, rax
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  mov rdx, [rdi+24]
  xor eax, eax
  db $C4, $E2, $83, $F6, $1E       // mulx rbx, r15, qword ptr [rsi]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $E2, $83, $F6, $5E, $08  // mulx rbx, r15, qword ptr [rsi + 8]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $E2, $83, $F6, $5E, $10  // mulx rbx, r15, qword ptr [rsi + 0x10]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $E2, $83, $F6, $5E, $18  // mulx rbx, r15, qword ptr [rsi + 0x18]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rdx, [r9]
  imul rdx, r12
  xor eax, eax
  db $C4, $C2, $83, $F6, $59, $10  // mulx rbx, r15, qword ptr [r9 + 0x10]
  db $66, $4D, $0F, $38, $F6, $E7  // adcx r12, r15
  db $F3, $4C, $0F, $38, $F6, $EB  // adox r13, rbx
  db $C4, $C2, $83, $F6, $59, $18  // mulx rbx, r15, qword ptr [r9 + 0x18]
  db $66, $4D, $0F, $38, $F6, $EF  // adcx r13, r15
  db $F3, $4C, $0F, $38, $F6, $F3  // adox r14, rbx
  db $C4, $C2, $83, $F6, $59, $20  // mulx rbx, r15, qword ptr [r9 + 0x20]
  db $66, $4D, $0F, $38, $F6, $F7  // adcx r14, r15
  db $F3, $4C, $0F, $38, $F6, $C3  // adox r8, rbx
  db $C4, $C2, $83, $F6, $59, $28  // mulx rbx, r15, qword ptr [r9 + 0x28]
  db $66, $4D, $0F, $38, $F6, $C7  // adcx r8, r15
  db $F3, $4C, $0F, $38, $F6, $D3  // adox r10, rbx
  db $66, $4C, $0F, $38, $F6, $D0  // adcx r10, rax
  db $F3, $4C, $0F, $38, $F6, $D8  // adox r11, rax
  db $66, $4C, $0F, $38, $F6, $D8  // adcx r11, rax
  mov rax, r13
  sub rax, [r9+16]
  mov rbx, rax
  mov rax, r14
  sbb rax, [r9+24]
  mov r15, rax
  mov rax, r8
  sbb rax, [r9+32]
  mov r12, rax
  mov rax, r10
  sbb rax, [r9+40]
  mov rdi, rax
  mov rax, r11
  sbb rax, 0
  sbb rdx, rdx
  mov rcx, rdx
  not rdx
  and r13, rcx
  and rbx, rdx
  or r13, rbx
  and r14, rcx
  and r15, rdx
  or r14, r15
  and r8, rcx
  and r12, rdx
  or r8, r12
  and r10, rcx
  and rdi, rdx
  or r10, rdi
  mov [rsp + 576], r13
  mov [rsp + 584], r14
  mov [rsp + 592], r8
  mov [rsp + 600], r10
  // infinity masks in1 (r13), in2 (r14)
  mov rax, [rsp + 64]
  or rax, [rsp + 72]
  or rax, [rsp + 80]
  or rax, [rsp + 88]
  xor r13, r13
  test rax, rax
  setz r13b
  neg r13
  xor r14, r14
  mov rcx, [rsp + 608]
  // masked select X3 -> R
  mov rax, [rsp + 512]
  mov rbx, [rsp + 0]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 96]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 0], rax
  mov rax, [rsp + 520]
  mov rbx, [rsp + 8]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 104]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 8], rax
  mov rax, [rsp + 528]
  mov rbx, [rsp + 16]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 112]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 16], rax
  mov rax, [rsp + 536]
  mov rbx, [rsp + 24]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 120]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 24], rax
  // masked select Y3 -> R
  mov rax, [rsp + 544]
  mov rbx, [rsp + 32]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 128]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 72], rax
  mov rax, [rsp + 552]
  mov rbx, [rsp + 40]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 136]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 80], rax
  mov rax, [rsp + 560]
  mov rbx, [rsp + 48]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 144]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 88], rax
  mov rax, [rsp + 568]
  mov rbx, [rsp + 56]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 152]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 96], rax
  // masked select Z3 -> R
  mov rax, [rsp + 576]
  mov rbx, [rsp + 64]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 160]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 144], rax
  mov rax, [rsp + 584]
  mov rbx, [rsp + 72]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 168]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 152], rax
  mov rax, [rsp + 592]
  mov rbx, [rsp + 80]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 176]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 160], rax
  mov rax, [rsp + 600]
  mov rbx, [rsp + 88]
  and rbx, r14
  mov rdx, r14
  not rdx
  and rax, rdx
  or rax, rbx
  mov rbx, [rsp + 184]
  and rbx, r13
  mov rdx, r13
  not rdx
  and rax, rdx
  or rax, rbx
  mov [rcx + 168], rax
  // expose predicate operands H, RS
  mov rax, [rsp + 288]
  mov [rcx + 216], rax
  mov rax, [rsp + 296]
  mov [rcx + 224], rax
  mov rax, [rsp + 304]
  mov [rcx + 232], rax
  mov rax, [rsp + 312]
  mov [rcx + 240], rax
  mov rax, [rsp + 320]
  mov [rcx + 288], rax
  mov rax, [rsp + 328]
  mov [rcx + 296], rax
  mov rax, [rsp + 336]
  mov [rcx + 304], rax
  mov rax, [rsp + 344]
  mov [rcx + 312], rax
  add rsp, 624
  pop r15
  pop r14
  pop r13
  pop r12
  pop rdi
  pop rsi
  pop rbp
  pop rbx
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_FP_K256_POINTDOUBLE, CRYPTOLIB_FP_K256_POINTADD, CRYPTOLIB_FP_K256_POINTADDMIXED must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
