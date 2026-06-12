// V128 BinPoly medium multiply, even limb count (i386).
// Entry (after SimdProc4Begin_i386.inc):
//   ebx = ALen (UInt32 limb count, even), esi = PX, edi = PY, eax = PZz.
// ZZ is addressed as packed V128 slots (16-byte stride).
//
// Local stack layout (after push ebp/push edx/sub esp,24):
//   [esp +  0] = L
//   [esp +  4] = last
//   [esp +  8] = zPosMax
//   [esp + 12] = zPos
//   [esp + 16] = lo
//   [esp + 20] = hi

  push      ebp
  push      edx
  sub       esp, 24

  mov       ebp, eax
  mov       edx, ebx
  shr       edx, 1
  mov       dword ptr [esp], edx            // L = ALen >> 1

  // Diagonal: for i = 0..L-1, ZZ[2i], ZZ[2i+1] = Mul2x2(X[i], Y[i]).
  xor       ecx, ecx
@@BinPolyMulEvenDiagLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulEvenDiagDone

  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm0, [esi + edx]
  movdqu    xmm1, [edi + edx]
  {$I ..\..\Include\Simd\BinPoly\BinPolyClmulMul2x2_i386.inc}

  mov       eax, ecx
  shl       eax, 5
  movdqu    [ebp + eax], xmm6
  movdqu    [ebp + eax + 16], xmm7

  inc       ecx
  jmp       @@BinPolyMulEvenDiagLoop
@@BinPolyMulEvenDiagDone:

  // Streak:
  // V0 = ZZ[0], V1 = ZZ[1]
  // for i = 1..L-1:
  //   V0 ^= ZZ[2i]
  //   ZZ[i] = V0 ^ V1                  (overwrite)
  //   V1 ^= ZZ[2i+1]
  movdqu    xmm2, [ebp]
  movdqu    xmm3, [ebp + 16]
  mov       ecx, 1
@@BinPolyMulEvenStreakLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulEvenStreakDone

  mov       edx, ecx
  shl       edx, 5
  movdqu    xmm4, [ebp + edx]   // ZZ[2i]
  pxor      xmm2, xmm4

  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  mov       eax, ecx
  shl       eax, 4
  movdqu    [ebp + eax], xmm5   // ZZ[i] = V0 ^ V1

  movdqu    xmm4, [ebp + edx + 16] // ZZ[2i+1]
  pxor      xmm3, xmm4

  inc       ecx
  jmp       @@BinPolyMulEvenStreakLoop
@@BinPolyMulEvenStreakDone:

  // W = V0 ^ V1; ZZ[L+i] = ZZ[i] ^ W for i = 0..L-1.
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm3
  xor       ecx, ecx
@@BinPolyMulEvenFoldLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulEvenFoldDone

  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm4, [ebp + edx]
  pxor      xmm4, xmm7

  mov       eax, dword ptr [esp]
  add       eax, ecx
  shl       eax, 4
  movdqu    [ebp + eax], xmm4

  inc       ecx
  jmp       @@BinPolyMulEvenFoldLoop
@@BinPolyMulEvenFoldDone:

  // Cross products:
  // last = L-1; zPos = 1..2*last-1.
  mov       eax, dword ptr [esp]
  dec       eax
  mov       dword ptr [esp + 4], eax         // last
  cmp       eax, 0
  jle       @@BinPolyMulEvenDone

  mov       edx, eax
  shl       edx, 1
  dec       edx
  mov       dword ptr [esp + 8], edx         // zPosMax
  mov       dword ptr [esp + 12], 1          // zPos
@@BinPolyMulEvenZPosLoop:
  mov       ecx, dword ptr [esp + 12]        // zPos
  cmp       ecx, dword ptr [esp + 8]
  jg        @@BinPolyMulEvenDone

  // hi = min(last, zPos)
  mov       eax, dword ptr [esp + 4]         // last
  cmp       ecx, eax
  jle       @@BinPolyMulEvenSetHiFromZPos
  mov       dword ptr [esp + 20], eax
  jmp       @@BinPolyMulEvenHiDone
@@BinPolyMulEvenSetHiFromZPos:
  mov       dword ptr [esp + 20], ecx
@@BinPolyMulEvenHiDone:
  mov       eax, ecx
  sub       eax, dword ptr [esp + 20]
  mov       dword ptr [esp + 16], eax        // lo = zPos - hi

@@BinPolyMulEvenPairLoop:
  mov       ecx, dword ptr [esp + 16]        // lo
  cmp       ecx, dword ptr [esp + 20]        // hi
  jge       @@BinPolyMulEvenNextZPos

  mov       edx, ecx
  shl       edx, 4
  mov       eax, dword ptr [esp + 20]
  shl       eax, 4

  movdqu    xmm0, [esi + edx]
  movdqu    xmm4, [esi + eax]
  pxor      xmm0, xmm4
  movdqu    xmm1, [edi + edx]
  movdqu    xmm5, [edi + eax]
  pxor      xmm1, xmm5
  {$I ..\..\Include\Simd\BinPoly\BinPolyClmulMul2x2_i386.inc}

  mov       edx, dword ptr [esp + 12]        // zPos
  shl       edx, 4
  movdqu    xmm4, [ebp + edx]
  pxor      xmm4, xmm6
  movdqu    [ebp + edx], xmm4
  movdqu    xmm4, [ebp + edx + 16]
  pxor      xmm4, xmm7
  movdqu    [ebp + edx + 16], xmm4

  inc       dword ptr [esp + 16]             // lo++
  dec       dword ptr [esp + 20]             // hi--
  jmp       @@BinPolyMulEvenPairLoop

@@BinPolyMulEvenNextZPos:
  inc       dword ptr [esp + 12]
  jmp       @@BinPolyMulEvenZPosLoop

@@BinPolyMulEvenDone:
  add       esp, 24
  pop       edx
  pop       ebp
  pop       edi
  pop       esi
  pop       ebx

