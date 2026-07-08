// V128 BinPoly medium multiply, even limb count (x86-64).
// Entry (after ClpSimdProc4Begin_x86_64.inc):
//   rcx = ALen (UInt64 limb count, even), rdx = PX, r8 = PY, r9 = PZz.
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

  // Diagonal: for i = 0..L-1, ZZ[2i], ZZ[2i+1] = Mul2x2(X[i], Y[i]).
  xor       rbx, rbx
@@BinPolyMulEvenDiagLoop:
  cmp       rbx, r15
  jge       @@BinPolyMulEvenDiagDone

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
  jmp       @@BinPolyMulEvenDiagLoop
@@BinPolyMulEvenDiagDone:

  // Streak:
  // V0 = ZZ[0], V1 = ZZ[1]
  // for i = 1..L-1:
  //   V0 ^= ZZ[2i]
  //   ZZ[i] = V0 ^ V1                  (overwrite)
  //   V1 ^= ZZ[2i+1]
  movdqu    xmm2, [r14]
  movdqu    xmm3, [r14 + 16]
  mov       rbx, 1
@@BinPolyMulEvenStreakLoop:
  cmp       rbx, r15
  jge       @@BinPolyMulEvenStreakDone

  mov       r10, rbx
  shl       r10, 5
  movdqu    xmm4, [r14 + r10]      // ZZ[2i]
  pxor      xmm2, xmm4

  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  mov       r11, rbx
  shl       r11, 4
  movdqu    [r14 + r11], xmm5      // ZZ[i] = V0 ^ V1

  movdqu    xmm4, [r14 + r10 + 16] // ZZ[2i+1]
  pxor      xmm3, xmm4

  inc       rbx
  jmp       @@BinPolyMulEvenStreakLoop
@@BinPolyMulEvenStreakDone:

  // W = V0 ^ V1; ZZ[L+i] = ZZ[i] ^ W for i = 0..L-1.
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm3
  xor       rbx, rbx
@@BinPolyMulEvenFoldLoop:
  cmp       rbx, r15
  jge       @@BinPolyMulEvenFoldDone

  mov       r10, rbx
  shl       r10, 4
  movdqu    xmm4, [r14 + r10]
  pxor      xmm4, xmm7

  mov       r11, r15
  add       r11, rbx
  shl       r11, 4
  movdqu    [r14 + r11], xmm4

  inc       rbx
  jmp       @@BinPolyMulEvenFoldLoop
@@BinPolyMulEvenFoldDone:

  // Cross products:
  // last = L-1; zPos = 1..2*last-1.
  mov       rbp, r15
  dec       rbp                          // last
  cmp       rbp, 0
  jle       @@BinPolyMulEvenDone

  mov       rsi, rbp
  shl       rsi, 1
  dec       rsi                          // zPosMax = 2*last - 1
  mov       rdi, 1                       // zPos
@@BinPolyMulEvenZPosLoop:
  cmp       rdi, rsi
  jg        @@BinPolyMulEvenDone

  mov       rbx, rbp                     // hi = min(last, zPos)
  cmp       rdi, rbx
  cmovle    rbx, rdi
  mov       r10, rdi
  sub       r10, rbx                     // lo = zPos - hi

@@BinPolyMulEvenPairLoop:
  cmp       r10, rbx
  jge       @@BinPolyMulEvenNextZPos

  mov       r11, r10
  shl       r11, 4
  mov       rax, rbx
  shl       rax, 4

  movdqu    xmm0, [r12 + r11]
  movdqu    xmm4, [r12 + rax]
  pxor      xmm0, xmm4
  movdqu    xmm1, [r13 + r11]
  movdqu    xmm5, [r13 + rax]
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
  jmp       @@BinPolyMulEvenPairLoop

@@BinPolyMulEvenNextZPos:
  inc       rdi
  jmp       @@BinPolyMulEvenZPosLoop

@@BinPolyMulEvenDone:
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

