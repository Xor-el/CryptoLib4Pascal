// Prime-field (Fp) big-integer 64-bit-limb multiply/square kernels (i386).
// -------------------------------------------------------------------
//
// One selector-driven file per arch; exactly one of the following must be
// defined before including this file:
//
//   CRYPTOLIB_FP_MUL   (ClpSimdProc4Begin: ebx = PX, esi = PY, edi = PZ, eax = N (uint64 limbs))
//     - schoolbook Z[0..2N-1] := X[0..N-1] * Y[0..N-1] over 64-bit limbs;
//       callers reinterpret 32-bit-limb field arrays (uint32[2N] == uint64[N]).
//   CRYPTOLIB_FP_SQR   (ClpSimdProc3Begin: ebx = PX, esi = PZ, edi = N)
//     - i386 has no dedicated square: Z := X^2 is computed via the multiply
//       kernel (X*X), reusing its body after a 3-register entry shuffle.
//
// Constant-time. The field is worked in M = 2N 32-bit limbs; loop variables
// live on a small stack frame (i386 has too few GPRs to keep them in
// registers). The epilogue frees the frame and pops the Proc-prologue GPRs.
{$IFDEF CRYPTOLIB_FP_MUL}
  push ebp                      // callee-saved; reused below as the carry accumulator
  sub  esp, 16                  // [esp]=M, [esp+4]=i, [esp+8]=j, [esp+12]=Xi
  lea  ecx, [eax + eax]         // M = 2N
  mov  [esp], ecx
  lea  edx, [ecx + ecx]         // 2M
  xor  eax, eax
  xor  ecx, ecx                 // k
@@FpMulZero:
  mov  [edi + ecx*4], eax
  inc  ecx
  cmp  ecx, edx
  jb   @@FpMulZero
  mov  dword ptr [esp+4], 0     // i = 0
@@FpMulRow:
  mov  ecx, [esp+4]             // i
  mov  eax, [ebx + ecx*4]       // X[i]
  mov  [esp+12], eax            // Xi
  xor  ebp, ebp                 // carry
  mov  dword ptr [esp+8], 0     // j = 0
@@FpMulCol:
  mov  eax, [esp+12]            // Xi
  mov  ecx, [esp+8]             // j
  mul  dword ptr [esi + ecx*4]  // edx:eax = Xi * Y[j]
  add  eax, ebp                 // + carry
  adc  edx, 0
  mov  ecx, [esp+4]             // i
  add  ecx, [esp+8]             // i+j
  add  eax, [edi + ecx*4]       // + Z[i+j]
  adc  edx, 0
  mov  [edi + ecx*4], eax
  mov  ebp, edx                 // carry
  mov  ecx, [esp+8]
  inc  ecx
  mov  [esp+8], ecx             // j++
  cmp  ecx, [esp]               // j < M
  jb   @@FpMulCol
  mov  ecx, [esp+4]
  add  ecx, [esp]               // i+M
  mov  [edi + ecx*4], ebp       // Z[i+M] = carry
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx             // i++
  cmp  ecx, [esp]               // i < M
  jb   @@FpMulRow
  add  esp, 16
  pop  ebp
  pop  edi
  pop  esi
  pop  ebx
{$ELSE}
  {$IFDEF CRYPTOLIB_FP_SQR}
  mov  eax, edi                 // N
  mov  edi, esi                 // PZ
  mov  esi, ebx                 // PY = PX (square via the multiply kernel)
  push ebp                      // callee-saved; reused below as the carry accumulator
  sub  esp, 16                  // [esp]=M, [esp+4]=i, [esp+8]=j, [esp+12]=Xi
  lea  ecx, [eax + eax]         // M = 2N
  mov  [esp], ecx
  lea  edx, [ecx + ecx]         // 2M
  xor  eax, eax
  xor  ecx, ecx                 // k
@@FpMulZero:
  mov  [edi + ecx*4], eax
  inc  ecx
  cmp  ecx, edx
  jb   @@FpMulZero
  mov  dword ptr [esp+4], 0     // i = 0
@@FpMulRow:
  mov  ecx, [esp+4]             // i
  mov  eax, [ebx + ecx*4]       // X[i]
  mov  [esp+12], eax            // Xi
  xor  ebp, ebp                 // carry
  mov  dword ptr [esp+8], 0     // j = 0
@@FpMulCol:
  mov  eax, [esp+12]            // Xi
  mov  ecx, [esp+8]             // j
  mul  dword ptr [esi + ecx*4]  // edx:eax = Xi * Y[j]
  add  eax, ebp                 // + carry
  adc  edx, 0
  mov  ecx, [esp+4]             // i
  add  ecx, [esp+8]             // i+j
  add  eax, [edi + ecx*4]       // + Z[i+j]
  adc  edx, 0
  mov  [edi + ecx*4], eax
  mov  ebp, edx                 // carry
  mov  ecx, [esp+8]
  inc  ecx
  mov  [esp+8], ecx             // j++
  cmp  ecx, [esp]               // j < M
  jb   @@FpMulCol
  mov  ecx, [esp+4]
  add  ecx, [esp]               // i+M
  mov  [edi + ecx*4], ebp       // Z[i+M] = carry
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx             // i++
  cmp  ecx, [esp]               // i < M
  jb   @@FpMulRow
  add  esp, 16
  pop  ebp
  pop  edi
  pop  esi
  pop  ebx
  {$ELSE}
  {$FATAL Exactly one of CRYPTOLIB_FP_MUL, CRYPTOLIB_FP_SQR must be defined before including this file}
  {$ENDIF}
{$ENDIF}
