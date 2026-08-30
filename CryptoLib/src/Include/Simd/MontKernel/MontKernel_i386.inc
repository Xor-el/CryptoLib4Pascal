// Prime-agnostic width-parametric modular-arithmetic kernels (i386).
// -------------------------------------------------------------------
//
// MontKernel family: schoolbook multiply/square, the CIOS Montgomery
// multiply (width-general and register-resident per width), and constant-
// time modular add/subtract. Prime-agnostic and width-parametric -- the
// curve-specific special-prime P-256 kernels live in the PointKernel family.
//
// One selector-driven file per arch; exactly one of the selectors listed in
// the {$FATAL} tail must be defined before including this file. PCtx =
// [n0', N, p[0..N-1]] with n0' = -p^-1 mod 2^64 (montmul); modadd/modsub take
// the same PCtx with n0' unused. (ClpSimdProc4Begin: rcx = PR, rdx = PA, r8 = PB, r9 = PCtx)
//
// Constant-time: no data-dependent branches or memory addresses; the final
// conditional subtract is a masked select. Kernel bodies are byte-identical
// to the pre-decomposition FpKernel_<arch>.inc (shared emitter module).
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
    {$IFDEF CRYPTOLIB_FP_MONTMUL}
  // ebx=PR (M+2 scratch + result), esi=PA, edi=PB(unused after setup), eax=PCtx.
  // Radix-2^32 width-general CIOS Montgomery multiply: M = 2N 32-bit limbs, n0'_32 =
  // low dword of the 64-bit n0' (its low half IS the 2^32 inverse). Memory-resident.
  // Frame: [esp]=M [esp+4]=i [esp+8]=j [esp+12]=mult/mask [esp+16]=PA
  //        [esp+20]=PB [esp+24]=pbase [esp+28]=n0'_32
  push ebp
  sub  esp, 32
  mov  ecx, [eax + 8]           // N (low dword)
  lea  ecx, [ecx + ecx]         // M = 2N
  mov  [esp], ecx
  mov  edx, [eax]               // n0'_32 (low dword of 64-bit n0')
  mov  [esp+28], edx
  lea  edx, [eax + 16]          // pbase
  mov  [esp+24], edx
  mov  [esp+16], esi            // PA
  mov  [esp+20], edi            // PB
  lea  edx, [ecx + 2]           // M+2
  xor  eax, eax
  xor  ecx, ecx
@@FpMontZero32:
  mov  [ebx + ecx*4], eax
  inc  ecx
  cmp  ecx, edx
  jb   @@FpMontZero32
  mov  dword ptr [esp+4], 0     // i = 0
@@FpMontRow32:
  // multiply row: t[0..M-1] += A * b[i]
  mov  ecx, [esp+4]             // i
  mov  edx, [esp+20]            // PB
  mov  eax, [edx + ecx*4]       // b[i]
  mov  [esp+12], eax            // mult
  xor  ebp, ebp                 // carry
  mov  esi, [esp+16]            // PA
  mov  dword ptr [esp+8], 0     // j = 0
@@FpMontMul32:
  mov  ecx, [esp+8]
  mov  eax, [esp+12]            // mult
  mul  dword ptr [esi + ecx*4]  // edx:eax = a[j]*mult
  add  eax, ebp
  adc  edx, 0
  add  eax, [ebx + ecx*4]       // + t[j]
  adc  edx, 0
  mov  [ebx + ecx*4], eax
  mov  ebp, edx                 // carry
  mov  ecx, [esp+8]
  inc  ecx
  mov  [esp+8], ecx
  cmp  ecx, [esp]               // j < M
  jb   @@FpMontMul32
  mov  ecx, [esp]               // M
  add  [ebx + ecx*4], ebp       // t[M] += carry
  mov  eax, 0
  adc  eax, 0
  lea  edx, [ecx + 1]           // M+1
  mov  [ebx + edx*4], eax       // t[M+1] = carry-out
  // reduce row: m = t[0]*n0'_32
  mov  eax, [ebx]               // t[0]
  mul  dword ptr [esp+28]       // edx:eax = t[0]*n0'_32 ; eax = m
  mov  [esp+12], eax            // m
  mov  esi, [esp+24]            // pbase
  mul  dword ptr [esi]          // edx:eax = m*p[0]
  add  eax, [ebx]               // + t[0] (low discarded)
  adc  edx, 0
  mov  ebp, edx                 // carry
  mov  dword ptr [esp+8], 1     // j = 1
@@FpMontRed32:
  mov  ecx, [esp+8]
  mov  eax, [esp+12]            // m
  mul  dword ptr [esi + ecx*4]  // m*p[j]
  add  eax, ebp
  adc  edx, 0
  add  eax, [ebx + ecx*4]       // + t[j]
  adc  edx, 0
  mov  ecx, [esp+8]
  lea  ecx, [ecx - 1]           // j-1
  mov  [ebx + ecx*4], eax       // t[j-1]
  mov  ebp, edx                 // carry
  mov  ecx, [esp+8]
  inc  ecx
  mov  [esp+8], ecx
  cmp  ecx, [esp]               // j < M
  jb   @@FpMontRed32
  mov  ecx, [esp]               // M
  mov  eax, [ebx + ecx*4]       // t[M]
  add  eax, ebp
  lea  edx, [ecx - 1]           // M-1
  mov  [ebx + edx*4], eax       // t[M-1]
  mov  eax, 0
  adc  eax, 0
  lea  edx, [ecx + 1]           // M+1
  add  eax, [ebx + edx*4]       // + t[M+1]
  mov  [ebx + ecx*4], eax       // t[M] = t[M+1] + carry-out
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx             // i++
  cmp  ecx, [esp]               // i < M
  jb   @@FpMontRow32
  // constant-time final reduce: d := t - p in place; restore t if t < p.
  xor  ebp, ebp                 // borrow
  mov  dword ptr [esp+8], 0     // j
  mov  esi, [esp+24]            // pbase
@@FpMontFSub32:
  mov  ecx, [esp+8]
  mov  eax, [ebx + ecx*4]       // t[j]
  sub  eax, ebp                 // - borrow
  sbb  edx, edx                 // -(borrow1)
  sub  eax, [esi + ecx*4]       // - p[j]
  sbb  ebp, ebp                 // -(borrow2)
  mov  [ebx + ecx*4], eax
  add  edx, ebp
  neg  edx
  mov  ebp, edx                 // borrow_out
  mov  ecx, [esp+8]
  inc  ecx
  mov  [esp+8], ecx
  cmp  ecx, [esp]               // j < M
  jb   @@FpMontFSub32
  mov  ecx, [esp]               // M
  mov  eax, [ebx + ecx*4]       // t[M] guard
  sub  eax, ebp
  sbb  eax, eax                 // mask = all-ones if t < p (restore)
  mov  [esp+12], eax
  xor  ebp, ebp                 // carry
  mov  dword ptr [esp+8], 0     // j
@@FpMontFAdd32:
  mov  ecx, [esp+8]
  mov  eax, [esi + ecx*4]       // p[j]
  and  eax, [esp+12]            // & mask
  add  eax, [ebx + ecx*4]       // + t[j]
  mov  edx, 0
  adc  edx, 0
  add  eax, ebp                 // + carry
  adc  edx, 0
  mov  [ebx + ecx*4], eax
  mov  ebp, edx                 // carry
  mov  ecx, [esp+8]
  inc  ecx
  mov  [esp+8], ecx
  cmp  ecx, [esp]               // j < M
  jb   @@FpMontFAdd32
  add  esp, 32
  pop  ebp
  pop  edi
  pop  esi
  pop  ebx
    {$ELSE}
      {$IFDEF CRYPTOLIB_FP_MODADD}
  // ebx=PR, esi=PA, edi=PB, eax=PCtx. R := (A + B) mod p, radix-2^32 (M=2N limbs),
  // constant-time. Frame: [esp]=M [esp+4]=j [esp+8]=c/mask [esp+12]=pbase.
  push ebp
  sub  esp, 16
  mov  ecx, [eax + 8]           // N
  lea  ecx, [ecx + ecx]         // M = 2N
  mov  [esp], ecx
  lea  edx, [eax + 16]          // pbase
  mov  [esp+12], edx
  // R := A + B (top carry -> [esp+8])
  xor  ebp, ebp
  mov  dword ptr [esp+4], 0
@@FpModAddSum32:
  mov  ecx, [esp+4]
  mov  eax, [esi + ecx*4]       // a[j]
  add  eax, [edi + ecx*4]       // + b[j]
  mov  edx, 0
  adc  edx, 0
  add  eax, ebp                 // + carry
  adc  edx, 0
  mov  [ebx + ecx*4], eax
  mov  ebp, edx
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx
  cmp  ecx, [esp]
  jb   @@FpModAddSum32
  mov  [esp+8], ebp             // c = top carry
  // R := R - p (borrow in ebp)
  xor  ebp, ebp
  mov  dword ptr [esp+4], 0
  mov  esi, [esp+12]            // pbase
@@FpModAddSub32:
  mov  ecx, [esp+4]
  mov  eax, [ebx + ecx*4]
  sub  eax, ebp
  sbb  edx, edx
  sub  eax, [esi + ecx*4]
  sbb  ebp, ebp
  mov  [ebx + ecx*4], eax
  add  edx, ebp
  neg  edx
  mov  ebp, edx                 // borrow_out
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx
  cmp  ecx, [esp]
  jb   @@FpModAddSub32
  // mask = -((c == 0) and (borrow == 1))
  mov  eax, [esp+8]
  xor  eax, 1
  and  eax, ebp
  neg  eax
  mov  [esp+8], eax             // mask
  // add-back p&mask
  xor  ebp, ebp
  mov  dword ptr [esp+4], 0
@@FpModAddBack32:
  mov  ecx, [esp+4]
  mov  eax, [esi + ecx*4]       // p[j]
  and  eax, [esp+8]
  add  eax, [ebx + ecx*4]
  mov  edx, 0
  adc  edx, 0
  add  eax, ebp
  adc  edx, 0
  mov  [ebx + ecx*4], eax
  mov  ebp, edx
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx
  cmp  ecx, [esp]
  jb   @@FpModAddBack32
  add  esp, 16
  pop  ebp
  pop  edi
  pop  esi
  pop  ebx
      {$ELSE}
        {$IFDEF CRYPTOLIB_FP_MODSUB}
  // ebx=PR, esi=PA, edi=PB, eax=PCtx. R := (A - B) mod p, radix-2^32 (M=2N limbs),
  // constant-time. Frame: [esp]=M [esp+4]=j [esp+8]=mask [esp+12]=pbase.
  push ebp
  sub  esp, 16
  mov  ecx, [eax + 8]           // N
  lea  ecx, [ecx + ecx]         // M = 2N
  mov  [esp], ecx
  lea  edx, [eax + 16]          // pbase
  mov  [esp+12], edx
  // R := A - B (borrow in ebp)
  xor  ebp, ebp
  mov  dword ptr [esp+4], 0
@@FpModSubDiff32:
  mov  ecx, [esp+4]
  mov  eax, [esi + ecx*4]       // a[j]
  sub  eax, ebp
  sbb  edx, edx
  sub  eax, [edi + ecx*4]       // - b[j]
  sbb  ebp, ebp
  mov  [ebx + ecx*4], eax
  add  edx, ebp
  neg  edx
  mov  ebp, edx                 // borrow_out
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx
  cmp  ecx, [esp]
  jb   @@FpModSubDiff32
  neg  ebp
  mov  [esp+8], ebp             // mask = all-ones if borrowed (A < B)
  // add-back p&mask
  mov  esi, [esp+12]            // pbase
  xor  ebp, ebp
  mov  dword ptr [esp+4], 0
@@FpModSubBack32:
  mov  ecx, [esp+4]
  mov  eax, [esi + ecx*4]       // p[j]
  and  eax, [esp+8]
  add  eax, [ebx + ecx*4]
  mov  edx, 0
  adc  edx, 0
  add  eax, ebp
  adc  edx, 0
  mov  [ebx + ecx*4], eax
  mov  ebp, edx
  mov  ecx, [esp+4]
  inc  ecx
  mov  [esp+4], ecx
  cmp  ecx, [esp]
  jb   @@FpModSubBack32
  add  esp, 16
  pop  ebp
  pop  edi
  pop  esi
  pop  ebx
        {$ELSE}
        {$FATAL Exactly one of CRYPTOLIB_FP_MUL, CRYPTOLIB_FP_SQR, CRYPTOLIB_FP_MONTMUL, CRYPTOLIB_FP_MODADD, CRYPTOLIB_FP_MODSUB must be defined before including this file}
        {$ENDIF}
      {$ENDIF}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
