// Curve25519 field kernels (i386), radix-2^25.5, ten signed Int32 limbs.
// One selector-driven file; define exactly one of the following before the
// include (each pairs with its ClpSimdProc<n>Begin prologue):
//
//   CRYPTOLIB_CURVE25519_MUL      (Proc3: ebx=PF, esi=PG, edi=PH)
//     PH := PF * PG
//   CRYPTOLIB_CURVE25519_SQR      (Proc2: ebx=PX, esi=PZ)
//     PZ := PX^2
//   CRYPTOLIB_CURVE25519_ADD      (Proc3: ebx=PX, esi=PY, edi=PZ)
//     PZ := PX + PY
//   CRYPTOLIB_CURVE25519_SUB      (Proc3: ebx=PX, esi=PY, edi=PZ)
//     PZ := PX - PY
//   CRYPTOLIB_CURVE25519_APM      (Proc4: ebx=PX, esi=PY, edi=PZp, eax=PZm)
//     PZp := PX+PY; PZm := PX-PY
//   CRYPTOLIB_CURVE25519_CSWAP    (Proc3: ebx=ASwap, esi=PA, edi=PB)
//     constant-time swap of PA, PB
//   CRYPTOLIB_CURVE25519_CARRY    (Proc1: ebx=PZ)
//     carry-propagate (reduce) PZ in place
//   CRYPTOLIB_CURVE25519_MULWORD  (Proc3: ebx=PX, esi=AY, edi=PZ)
//     PZ := PX * AY (small scalar AY)
//
// Register-starved: Mul uses one 64-bit accumulator (EBP:ECX) with a per-column
// x19 fold and a 10x Int64 stack area; Sqr reuses the Mul body via X*X; Carry is
// in-place. All results mod 2^255-19; signed limbs => imul only. Constant-time.
{$IFDEF CRYPTOLIB_CURVE25519_MUL}
  push ebp
  sub esp, 80
  mov eax, [ebx+4]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+32]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+24]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+16]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+12]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+8]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+4]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+0], ecx
  mov [esp+4], ebp
  mov eax, [ebx+8]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+16]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+12]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+8]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+8], ecx
  mov [esp+12], ebp
  mov eax, [ebx+12]
  imul dword ptr [esi+36]
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+28]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+12]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+8]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+16], ecx
  mov [esp+20], ebp
  mov eax, [ebx+16]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+24]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+16]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+4]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+24], ecx
  mov [esp+28], ebp
  mov eax, [ebx+20]
  imul dword ptr [esi+36]
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+16]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+32], ecx
  mov [esp+36], ebp
  mov eax, [ebx+24]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+32]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+24]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+12]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+4]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+40], ecx
  mov [esp+44], ebp
  mov eax, [ebx+28]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+24]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+48], ecx
  mov [esp+52], ebp
  mov eax, [ebx+32]
  imul dword ptr [esi+36]
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+28]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+24]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+16]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+8]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+56], ecx
  mov [esp+60], ebp
  mov eax, [ebx+36]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+32]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+28]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+4]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+64], ecx
  mov [esp+68], ebp
  mov eax, [ebx+0]
  imul dword ptr [esi+36]
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+32]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+28]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+24]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+16]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+72], ecx
  mov [esp+76], ebp
  mov eax, [esp+8]
  mov edx, [esp+12]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+16], eax
  adc [esp+20], edx
  and dword ptr [esp+8], $03FFFFFF
  mov dword ptr [esp+12], 0
  mov eax, [esp+24]
  mov edx, [esp+28]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+32], eax
  adc [esp+36], edx
  and dword ptr [esp+24], $03FFFFFF
  mov dword ptr [esp+28], 0
  mov eax, [esp+48]
  mov edx, [esp+52]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+56], eax
  adc [esp+60], edx
  and dword ptr [esp+48], $03FFFFFF
  mov dword ptr [esp+52], 0
  mov eax, [esp+64]
  mov edx, [esp+68]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+72], eax
  adc [esp+76], edx
  and dword ptr [esp+64], $03FFFFFF
  mov dword ptr [esp+68], 0
  mov eax, [esp+16]
  mov edx, [esp+20]
  shrd eax, edx, 25
  sar edx, 25
  add [esp+24], eax
  adc [esp+28], edx
  and dword ptr [esp+16], $01FFFFFF
  mov dword ptr [esp+20], 0
  mov eax, [esp+32]
  mov edx, [esp+36]
  shrd eax, edx, 25
  sar edx, 25
  add [esp+40], eax
  adc [esp+44], edx
  and dword ptr [esp+32], $01FFFFFF
  mov dword ptr [esp+36], 0
  mov eax, [esp+56]
  mov edx, [esp+60]
  shrd eax, edx, 25
  sar edx, 25
  add [esp+64], eax
  adc [esp+68], edx
  and dword ptr [esp+56], $01FFFFFF
  mov dword ptr [esp+60], 0
  mov eax, [esp+72]
  mov edx, [esp+76]
  shrd eax, edx, 25
  sar edx, 25
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebx, edx
  shld edx, eax, 4
  shl eax, 4
  add eax, ecx
  adc edx, ebx
  shld ebx, ecx, 1
  shl ecx, 1
  add eax, ecx
  adc edx, ebx
  add [esp+0], eax
  adc [esp+4], edx
  and dword ptr [esp+72], $01FFFFFF
  mov dword ptr [esp+76], 0
  mov eax, [esp+0]
  mov edx, [esp+4]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+8], eax
  adc [esp+12], edx
  and dword ptr [esp+0], $03FFFFFF
  mov dword ptr [esp+4], 0
  mov eax, [esp+40]
  mov edx, [esp+44]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+48], eax
  adc [esp+52], edx
  and dword ptr [esp+40], $03FFFFFF
  mov dword ptr [esp+44], 0
  mov eax, [esp+8]
  mov edx, [esp+12]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+16], eax
  adc [esp+20], edx
  and dword ptr [esp+8], $03FFFFFF
  mov dword ptr [esp+12], 0
  mov eax, [esp+24]
  mov edx, [esp+28]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+32], eax
  adc [esp+36], edx
  and dword ptr [esp+24], $03FFFFFF
  mov dword ptr [esp+28], 0
  mov eax, [esp+48]
  mov edx, [esp+52]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+56], eax
  adc [esp+60], edx
  and dword ptr [esp+48], $03FFFFFF
  mov dword ptr [esp+52], 0
  mov eax, [esp+64]
  mov edx, [esp+68]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+72], eax
  adc [esp+76], edx
  and dword ptr [esp+64], $03FFFFFF
  mov dword ptr [esp+68], 0
  mov eax, [esp+0]
  mov [edi+0], eax
  mov eax, [esp+8]
  mov [edi+4], eax
  mov eax, [esp+16]
  mov [edi+8], eax
  mov eax, [esp+24]
  mov [edi+12], eax
  mov eax, [esp+32]
  mov [edi+16], eax
  mov eax, [esp+40]
  mov [edi+20], eax
  mov eax, [esp+48]
  mov [edi+24], eax
  mov eax, [esp+56]
  mov [edi+28], eax
  mov eax, [esp+64]
  mov [edi+32], eax
  mov eax, [esp+72]
  mov [edi+36], eax
  add esp, 80
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_SQR}
  push edi
  mov edi, esi
  mov esi, ebx
  push ebp
  sub esp, 80
  mov eax, [ebx+4]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+32]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+24]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+16]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+12]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+8]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+4]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+0], ecx
  mov [esp+4], ebp
  mov eax, [ebx+8]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+16]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+12]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+8]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+8], ecx
  mov [esp+12], ebp
  mov eax, [ebx+12]
  imul dword ptr [esi+36]
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+28]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+12]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+8]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+16], ecx
  mov [esp+20], ebp
  mov eax, [ebx+16]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+24]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+16]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+4]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+24], ecx
  mov [esp+28], ebp
  mov eax, [ebx+20]
  imul dword ptr [esi+36]
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+20]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+16]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+32], ecx
  mov [esp+36], ebp
  mov eax, [ebx+24]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+32]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+24]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+12]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+4]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+40], ecx
  mov [esp+44], ebp
  mov eax, [ebx+28]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+28]
  shld edx, eax, 2
  shl eax, 2
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+24]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+48], ecx
  mov [esp+52], ebp
  mov eax, [ebx+32]
  imul dword ptr [esi+36]
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+32]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+28]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+24]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+16]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+8]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+56], ecx
  mov [esp+60], ebp
  mov eax, [ebx+36]
  imul dword ptr [esi+36]
  shld edx, eax, 2
  shl eax, 2
  mov ecx, eax
  mov ebp, edx
  mov eax, ecx
  mov edx, ebp
  shld ebp, ecx, 4
  shl ecx, 4
  add ecx, eax
  adc ebp, edx
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+0]
  imul dword ptr [esi+32]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+28]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+24]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+16]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+4]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+64], ecx
  mov [esp+68], ebp
  mov eax, [ebx+0]
  imul dword ptr [esi+36]
  mov ecx, eax
  mov ebp, edx
  mov eax, [ebx+4]
  imul dword ptr [esi+32]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+8]
  imul dword ptr [esi+28]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+12]
  imul dword ptr [esi+24]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+16]
  imul dword ptr [esi+20]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+20]
  imul dword ptr [esi+16]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+24]
  imul dword ptr [esi+12]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+28]
  imul dword ptr [esi+8]
  shld edx, eax, 1
  shl eax, 1
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+32]
  imul dword ptr [esi+4]
  add ecx, eax
  adc ebp, edx
  mov eax, [ebx+36]
  imul dword ptr [esi+0]
  add ecx, eax
  adc ebp, edx
  mov [esp+72], ecx
  mov [esp+76], ebp
  mov eax, [esp+8]
  mov edx, [esp+12]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+16], eax
  adc [esp+20], edx
  and dword ptr [esp+8], $03FFFFFF
  mov dword ptr [esp+12], 0
  mov eax, [esp+24]
  mov edx, [esp+28]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+32], eax
  adc [esp+36], edx
  and dword ptr [esp+24], $03FFFFFF
  mov dword ptr [esp+28], 0
  mov eax, [esp+48]
  mov edx, [esp+52]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+56], eax
  adc [esp+60], edx
  and dword ptr [esp+48], $03FFFFFF
  mov dword ptr [esp+52], 0
  mov eax, [esp+64]
  mov edx, [esp+68]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+72], eax
  adc [esp+76], edx
  and dword ptr [esp+64], $03FFFFFF
  mov dword ptr [esp+68], 0
  mov eax, [esp+16]
  mov edx, [esp+20]
  shrd eax, edx, 25
  sar edx, 25
  add [esp+24], eax
  adc [esp+28], edx
  and dword ptr [esp+16], $01FFFFFF
  mov dword ptr [esp+20], 0
  mov eax, [esp+32]
  mov edx, [esp+36]
  shrd eax, edx, 25
  sar edx, 25
  add [esp+40], eax
  adc [esp+44], edx
  and dword ptr [esp+32], $01FFFFFF
  mov dword ptr [esp+36], 0
  mov eax, [esp+56]
  mov edx, [esp+60]
  shrd eax, edx, 25
  sar edx, 25
  add [esp+64], eax
  adc [esp+68], edx
  and dword ptr [esp+56], $01FFFFFF
  mov dword ptr [esp+60], 0
  mov eax, [esp+72]
  mov edx, [esp+76]
  shrd eax, edx, 25
  sar edx, 25
  shld edx, eax, 1
  shl eax, 1
  mov ecx, eax
  mov ebx, edx
  shld edx, eax, 4
  shl eax, 4
  add eax, ecx
  adc edx, ebx
  shld ebx, ecx, 1
  shl ecx, 1
  add eax, ecx
  adc edx, ebx
  add [esp+0], eax
  adc [esp+4], edx
  and dword ptr [esp+72], $01FFFFFF
  mov dword ptr [esp+76], 0
  mov eax, [esp+0]
  mov edx, [esp+4]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+8], eax
  adc [esp+12], edx
  and dword ptr [esp+0], $03FFFFFF
  mov dword ptr [esp+4], 0
  mov eax, [esp+40]
  mov edx, [esp+44]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+48], eax
  adc [esp+52], edx
  and dword ptr [esp+40], $03FFFFFF
  mov dword ptr [esp+44], 0
  mov eax, [esp+8]
  mov edx, [esp+12]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+16], eax
  adc [esp+20], edx
  and dword ptr [esp+8], $03FFFFFF
  mov dword ptr [esp+12], 0
  mov eax, [esp+24]
  mov edx, [esp+28]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+32], eax
  adc [esp+36], edx
  and dword ptr [esp+24], $03FFFFFF
  mov dword ptr [esp+28], 0
  mov eax, [esp+48]
  mov edx, [esp+52]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+56], eax
  adc [esp+60], edx
  and dword ptr [esp+48], $03FFFFFF
  mov dword ptr [esp+52], 0
  mov eax, [esp+64]
  mov edx, [esp+68]
  shrd eax, edx, 26
  sar edx, 26
  add [esp+72], eax
  adc [esp+76], edx
  and dword ptr [esp+64], $03FFFFFF
  mov dword ptr [esp+68], 0
  mov eax, [esp+0]
  mov [edi+0], eax
  mov eax, [esp+8]
  mov [edi+4], eax
  mov eax, [esp+16]
  mov [edi+8], eax
  mov eax, [esp+24]
  mov [edi+12], eax
  mov eax, [esp+32]
  mov [edi+16], eax
  mov eax, [esp+40]
  mov [edi+20], eax
  mov eax, [esp+48]
  mov [edi+24], eax
  mov eax, [esp+56]
  mov [edi+28], eax
  mov eax, [esp+64]
  mov [edi+32], eax
  mov eax, [esp+72]
  mov [edi+36], eax
  add esp, 80
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_ADD}
  mov eax, [ebx+0]
  add eax, [esi+0]
  mov [edi+0], eax
  mov eax, [ebx+4]
  add eax, [esi+4]
  mov [edi+4], eax
  mov eax, [ebx+8]
  add eax, [esi+8]
  mov [edi+8], eax
  mov eax, [ebx+12]
  add eax, [esi+12]
  mov [edi+12], eax
  mov eax, [ebx+16]
  add eax, [esi+16]
  mov [edi+16], eax
  mov eax, [ebx+20]
  add eax, [esi+20]
  mov [edi+20], eax
  mov eax, [ebx+24]
  add eax, [esi+24]
  mov [edi+24], eax
  mov eax, [ebx+28]
  add eax, [esi+28]
  mov [edi+28], eax
  mov eax, [ebx+32]
  add eax, [esi+32]
  mov [edi+32], eax
  mov eax, [ebx+36]
  add eax, [esi+36]
  mov [edi+36], eax
  pop edi
  pop esi
  pop ebx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_SUB}
  mov eax, [ebx+0]
  sub eax, [esi+0]
  mov [edi+0], eax
  mov eax, [ebx+4]
  sub eax, [esi+4]
  mov [edi+4], eax
  mov eax, [ebx+8]
  sub eax, [esi+8]
  mov [edi+8], eax
  mov eax, [ebx+12]
  sub eax, [esi+12]
  mov [edi+12], eax
  mov eax, [ebx+16]
  sub eax, [esi+16]
  mov [edi+16], eax
  mov eax, [ebx+20]
  sub eax, [esi+20]
  mov [edi+20], eax
  mov eax, [ebx+24]
  sub eax, [esi+24]
  mov [edi+24], eax
  mov eax, [ebx+28]
  sub eax, [esi+28]
  mov [edi+28], eax
  mov eax, [ebx+32]
  sub eax, [esi+32]
  mov [edi+32], eax
  mov eax, [ebx+36]
  sub eax, [esi+36]
  mov [edi+36], eax
  pop edi
  pop esi
  pop ebx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_APM}
  push ebp
  mov ebp, eax
  mov eax, [ebx+0]
  mov edx, [esi+0]
  mov ecx, eax
  add ecx, edx
  mov [edi+0], ecx
  sub eax, edx
  mov [ebp+0], eax
  mov eax, [ebx+4]
  mov edx, [esi+4]
  mov ecx, eax
  add ecx, edx
  mov [edi+4], ecx
  sub eax, edx
  mov [ebp+4], eax
  mov eax, [ebx+8]
  mov edx, [esi+8]
  mov ecx, eax
  add ecx, edx
  mov [edi+8], ecx
  sub eax, edx
  mov [ebp+8], eax
  mov eax, [ebx+12]
  mov edx, [esi+12]
  mov ecx, eax
  add ecx, edx
  mov [edi+12], ecx
  sub eax, edx
  mov [ebp+12], eax
  mov eax, [ebx+16]
  mov edx, [esi+16]
  mov ecx, eax
  add ecx, edx
  mov [edi+16], ecx
  sub eax, edx
  mov [ebp+16], eax
  mov eax, [ebx+20]
  mov edx, [esi+20]
  mov ecx, eax
  add ecx, edx
  mov [edi+20], ecx
  sub eax, edx
  mov [ebp+20], eax
  mov eax, [ebx+24]
  mov edx, [esi+24]
  mov ecx, eax
  add ecx, edx
  mov [edi+24], ecx
  sub eax, edx
  mov [ebp+24], eax
  mov eax, [ebx+28]
  mov edx, [esi+28]
  mov ecx, eax
  add ecx, edx
  mov [edi+28], ecx
  sub eax, edx
  mov [ebp+28], eax
  mov eax, [ebx+32]
  mov edx, [esi+32]
  mov ecx, eax
  add ecx, edx
  mov [edi+32], ecx
  sub eax, edx
  mov [ebp+32], eax
  mov eax, [ebx+36]
  mov edx, [esi+36]
  mov ecx, eax
  add ecx, edx
  mov [edi+36], ecx
  sub eax, edx
  mov [ebp+36], eax
  pop ebp
  pop edi
  pop esi
  pop ebx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_CSWAP}
  neg ebx
  mov eax, [esi+0]
  mov edx, [edi+0]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+0], eax
  mov [edi+0], edx
  mov eax, [esi+4]
  mov edx, [edi+4]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+4], eax
  mov [edi+4], edx
  mov eax, [esi+8]
  mov edx, [edi+8]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+8], eax
  mov [edi+8], edx
  mov eax, [esi+12]
  mov edx, [edi+12]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+12], eax
  mov [edi+12], edx
  mov eax, [esi+16]
  mov edx, [edi+16]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+16], eax
  mov [edi+16], edx
  mov eax, [esi+20]
  mov edx, [edi+20]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+20], eax
  mov [edi+20], edx
  mov eax, [esi+24]
  mov edx, [edi+24]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+24], eax
  mov [edi+24], edx
  mov eax, [esi+28]
  mov edx, [edi+28]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+28], eax
  mov [edi+28], edx
  mov eax, [esi+32]
  mov edx, [edi+32]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+32], eax
  mov [edi+32], edx
  mov eax, [esi+36]
  mov edx, [edi+36]
  mov ecx, eax
  xor ecx, edx
  and ecx, ebx
  xor eax, ecx
  xor edx, ecx
  mov [esi+36], eax
  mov [edi+36], edx
  pop edi
  pop esi
  pop ebx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_CARRY}
  mov eax, [ebx+4]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+4], eax
  add [ebx+8], ecx
  mov eax, [ebx+12]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+12], eax
  add [ebx+16], ecx
  mov eax, [ebx+24]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+24], eax
  add [ebx+28], ecx
  mov eax, [ebx+32]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+32], eax
  add [ebx+36], ecx
  mov eax, [ebx+8]
  mov ecx, eax
  sar ecx, 25
  and eax, $01FFFFFF
  mov [ebx+8], eax
  add [ebx+12], ecx
  mov eax, [ebx+16]
  mov ecx, eax
  sar ecx, 25
  and eax, $01FFFFFF
  mov [ebx+16], eax
  add [ebx+20], ecx
  mov eax, [ebx+28]
  mov ecx, eax
  sar ecx, 25
  and eax, $01FFFFFF
  mov [ebx+28], eax
  add [ebx+32], ecx
  mov eax, [ebx+36]
  mov ecx, eax
  sar ecx, 25
  imul ecx, ecx, 38
  and eax, $01FFFFFF
  mov [ebx+36], eax
  add [ebx+0], ecx
  mov eax, [ebx+0]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+0], eax
  add [ebx+4], ecx
  mov eax, [ebx+20]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+20], eax
  add [ebx+24], ecx
  mov eax, [ebx+4]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+4], eax
  add [ebx+8], ecx
  mov eax, [ebx+12]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+12], eax
  add [ebx+16], ecx
  mov eax, [ebx+24]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+24], eax
  add [ebx+28], ecx
  mov eax, [ebx+32]
  mov ecx, eax
  sar ecx, 26
  and eax, $03FFFFFF
  mov [ebx+32], eax
  add [ebx+36], ecx
  pop ebx
{$ELSE}
{$IFDEF CRYPTOLIB_CURVE25519_MULWORD}
  sub esp, 48
  mov eax, [ebx+8]
  imul esi
  mov ecx, eax
  and ecx, $01FFFFFF
  mov [esp+32], ecx
  shrd eax, edx, 25
  sar edx, 25
  mov [esp+0], eax
  mov [esp+4], edx
  mov eax, [ebx+16]
  imul esi
  mov ecx, eax
  and ecx, $01FFFFFF
  mov [esp+36], ecx
  shrd eax, edx, 25
  sar edx, 25
  mov [esp+8], eax
  mov [esp+12], edx
  mov eax, [ebx+28]
  imul esi
  mov ecx, eax
  and ecx, $01FFFFFF
  mov [esp+40], ecx
  shrd eax, edx, 25
  sar edx, 25
  mov [esp+16], eax
  mov [esp+20], edx
  mov eax, [ebx+36]
  imul esi
  mov ecx, eax
  and ecx, $01FFFFFF
  mov [esp+44], ecx
  shrd eax, edx, 25
  sar edx, 25
  mov ecx, edx
  mov edx, 38
  mul edx
  imul ecx, ecx, 38
  add edx, ecx
  mov [esp+24], eax
  mov [esp+28], edx
  mov eax, [ebx+0]
  imul esi
  add eax, [esp+24]
  adc edx, [esp+28]
  mov ecx, eax
  and ecx, $03FFFFFF
  mov [edi+0], ecx
  shrd eax, edx, 26
  sar edx, 26
  mov [esp+24], eax
  mov [esp+28], edx
  mov eax, [ebx+20]
  imul esi
  add eax, [esp+8]
  adc edx, [esp+12]
  mov ecx, eax
  and ecx, $03FFFFFF
  mov [edi+20], ecx
  shrd eax, edx, 26
  sar edx, 26
  mov [esp+8], eax
  mov [esp+12], edx
  mov eax, [ebx+4]
  imul esi
  add eax, [esp+24]
  adc edx, [esp+28]
  mov ecx, eax
  and ecx, $03FFFFFF
  mov [edi+4], ecx
  shrd eax, edx, 26
  sar edx, 26
  mov [esp+24], eax
  mov [esp+28], edx
  mov eax, [ebx+12]
  imul esi
  add eax, [esp+0]
  adc edx, [esp+4]
  mov ecx, eax
  and ecx, $03FFFFFF
  mov [edi+12], ecx
  shrd eax, edx, 26
  sar edx, 26
  mov [esp+0], eax
  mov [esp+4], edx
  mov eax, [ebx+24]
  imul esi
  add eax, [esp+8]
  adc edx, [esp+12]
  mov ecx, eax
  and ecx, $03FFFFFF
  mov [edi+24], ecx
  shrd eax, edx, 26
  sar edx, 26
  mov [esp+8], eax
  mov [esp+12], edx
  mov eax, [ebx+32]
  imul esi
  add eax, [esp+16]
  adc edx, [esp+20]
  mov ecx, eax
  and ecx, $03FFFFFF
  mov [edi+32], ecx
  shrd eax, edx, 26
  sar edx, 26
  mov [esp+16], eax
  mov [esp+20], edx
  mov eax, [esp+32]
  add eax, [esp+24]
  mov [edi+8], eax
  mov eax, [esp+36]
  add eax, [esp+0]
  mov [edi+16], eax
  mov eax, [esp+40]
  add eax, [esp+8]
  mov [edi+28], eax
  mov eax, [esp+44]
  add eax, [esp+16]
  mov [edi+36], eax
  add esp, 48
  pop edi
  pop esi
  pop ebx
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
