// V128 BinPoly medium multiply, odd limb count (x86-64).
// Entry (after ClpSimdProc4Begin_x86_64.inc):
//   rcx = ALen (UInt64 limb count, odd), rdx = PX, r8 = PY, r9 = PZz.
// ZZ is addressed as packed V128 slots (16-byte stride).

  push      rbx
  push      rbp
  push      rsi
  push      rdi
  push      r12
  push      r13
  push      r14
  push      r15
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileSave_x86_64.inc}

  mov       r12, rdx
  mov       r13, r8
  mov       r14, r9
  mov       r15, rcx
  shr       r15, 1                    // L = ALen >> 1

  // Diagonal full pairs: for i = 0..L-1
  xor       rbx, rbx
@@BinPolyMulOddDiagLoop:
  cmp       rbx, r15
  jge       @@BinPolyMulOddDiagDone

  mov       r10, rbx
  shl       r10, 4
  movdqu    xmm0, [r12 + r10]
  movdqu    xmm1, [r13 + r10]
  {$I ..\..\Include\Simd\BinPoly\BinPolyClmulMul2x2_x86_64.inc}

  mov       r11, rbx
  shl       r11, 5
  movdqu    [r14 + r11], xmm8
  movdqu    [r14 + r11 + 16], xmm9

  inc       rbx
  jmp       @@BinPolyMulOddDiagLoop
@@BinPolyMulOddDiagDone:

  // Tail diagonal at ZZ[2L]: Mul((x[2L],0), (y[2L],0)) with pclmul imm8=0x00.
  mov       r10, r15
  shl       r10, 4
  pxor      xmm0, xmm0
  pxor      xmm1, xmm1
  movq      xmm0, qword ptr [r12 + r10]
  movq      xmm1, qword ptr [r13 + r10]
  db $66, $0F, $3A, $44, $C8, $00
  mov       r11, r15
  shl       r11, 5
  movdqu    [r14 + r11], xmm1

  // ALen = 1 special case (L = 0): only tail diagonal exists.
  cmp       r15, 0
  je        @@BinPolyMulOddDone

  // Streak:
  // V0 = ZZ[0], V1 = ZZ[1]
  // for i = 1..L:
  //   V0 ^= ZZ[2i]
  //   ZZ[i] = V0 ^ V1                  (overwrite)
  //   if i <> L then V1 ^= ZZ[2i+1]
  movdqu    xmm2, [r14]
  movdqu    xmm3, [r14 + 16]
  mov       rbx, 1
@@BinPolyMulOddStreakLoop:
  cmp       rbx, r15
  jg        @@BinPolyMulOddStreakDone

  mov       r10, rbx
  shl       r10, 5
  movdqu    xmm4, [r14 + r10]      // ZZ[2i]
  pxor      xmm2, xmm4

  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  mov       r11, rbx
  shl       r11, 4
  movdqu    [r14 + r11], xmm5      // ZZ[i] = V0 ^ V1

  cmp       rbx, r15
  je        @@BinPolyMulOddStreakNoV1
  movdqu    xmm4, [r14 + r10 + 16] // ZZ[2i+1]
  pxor      xmm3, xmm4
@@BinPolyMulOddStreakNoV1:

  inc       rbx
  jmp       @@BinPolyMulOddStreakLoop
@@BinPolyMulOddStreakDone:

  // W = V0 ^ V1; ZZ[(L+1)+i] = ZZ[i] ^ W for i = 0..L-1.
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm3
  xor       rbx, rbx
@@BinPolyMulOddFoldLoop:
  cmp       rbx, r15
  jge       @@BinPolyMulOddFoldDone

  mov       r10, rbx
  shl       r10, 4
  movdqu    xmm4, [r14 + r10]
  pxor      xmm4, xmm7

  mov       r11, r15
  add       r11, rbx
  inc       r11
  shl       r11, 4
  movdqu    [r14 + r11], xmm4

  inc       rbx
  jmp       @@BinPolyMulOddFoldLoop
@@BinPolyMulOddFoldDone:

  // Cross products:
  // last = L; zPos = 1..2*last-1, using tail vectors when hi = last.
  mov       rbp, r15
  cmp       rbp, 0
  jle       @@BinPolyMulOddDone

  mov       rsi, rbp
  shl       rsi, 1
  dec       rsi                          // zPosMax = 2*last - 1
  mov       rdi, 1                       // zPos
@@BinPolyMulOddZPosLoop:
  cmp       rdi, rsi
  jg        @@BinPolyMulOddDone

  mov       rbx, rbp                     // hi = min(last, zPos)
  cmp       rdi, rbx
  cmovle    rbx, rdi
  mov       r10, rdi
  sub       r10, rbx                     // lo = zPos - hi

@@BinPolyMulOddPairLoop:
  cmp       r10, rbx
  jge       @@BinPolyMulOddNextZPos

  // Xxor = X[lo] xor X[hi] (tail-form when hi == last).
  mov       r11, r10
  shl       r11, 4
  movdqu    xmm0, [r12 + r11]
  cmp       rbx, rbp
  jne       @@BinPolyMulOddXHiFull
  pxor      xmm4, xmm4
  mov       rax, rbp
  shl       rax, 4
  movq      xmm4, qword ptr [r12 + rax]
  jmp       @@BinPolyMulOddXHiDone
@@BinPolyMulOddXHiFull:
  mov       rax, rbx
  shl       rax, 4
  movdqu    xmm4, [r12 + rax]
@@BinPolyMulOddXHiDone:
  pxor      xmm0, xmm4

  // Yxor = Y[lo] xor Y[hi] (tail-form when hi == last).
  movdqu    xmm1, [r13 + r11]
  cmp       rbx, rbp
  jne       @@BinPolyMulOddYHiFull
  pxor      xmm5, xmm5
  mov       rax, rbp
  shl       rax, 4
  movq      xmm5, qword ptr [r13 + rax]
  jmp       @@BinPolyMulOddYHiDone
@@BinPolyMulOddYHiFull:
  mov       rax, rbx
  shl       rax, 4
  movdqu    xmm5, [r13 + rax]
@@BinPolyMulOddYHiDone:
  pxor      xmm1, xmm5
  {$I ..\..\Include\Simd\BinPoly\BinPolyClmulMul2x2_x86_64.inc}

  mov       r11, rdi
  shl       r11, 4
  movdqu    xmm4, [r14 + r11]
  pxor      xmm4, xmm8
  movdqu    [r14 + r11], xmm4
  movdqu    xmm4, [r14 + r11 + 16]
  pxor      xmm4, xmm9
  movdqu    [r14 + r11 + 16], xmm4

  inc       r10
  dec       rbx
  jmp       @@BinPolyMulOddPairLoop

@@BinPolyMulOddNextZPos:
  inc       rdi
  jmp       @@BinPolyMulOddZPosLoop

@@BinPolyMulOddDone:
{$I ..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_x86_64.inc}
  pop       r15
  pop       r14
  pop       r13
  pop       r12
  pop       rdi
  pop       rsi
  pop       rbp
  pop       rbx
  ret

