// V128 BinPoly medium multiply, odd limb count (i386).
// Entry (after ClpSimdProc4Begin_i386.inc):
//   ebx = ALen (UInt32 limb count, odd), esi = PX, edi = PY, eax = PZz.
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

  // Diagonal full pairs: for i = 0..L-1.
  xor       ecx, ecx
@@BinPolyMulOddDiagLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulOddDiagDone

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
  jmp       @@BinPolyMulOddDiagLoop
@@BinPolyMulOddDiagDone:

  // Tail diagonal at ZZ[2L]: Mul((x[2L],0), (y[2L],0)) with pclmul imm8=0x00.
  mov       edx, dword ptr [esp]
  shl       edx, 4
  pxor      xmm0, xmm0
  pxor      xmm1, xmm1
  movq      xmm0, qword ptr [esi + edx]
  movq      xmm1, qword ptr [edi + edx]
  db $66, $0F, $3A, $44, $C8, $00
  mov       eax, dword ptr [esp]
  shl       eax, 5
  movdqu    [ebp + eax], xmm1

  // ALen = 1 special case (L = 0): only tail diagonal exists.
  cmp       dword ptr [esp], 0
  je        @@BinPolyMulOddDone

  // Streak:
  // V0 = ZZ[0], V1 = ZZ[1]
  // for i = 1..L:
  //   V0 ^= ZZ[2i]
  //   ZZ[i] = V0 ^ V1                  (overwrite)
  //   if i <> L then V1 ^= ZZ[2i+1]
  movdqu    xmm2, [ebp]
  movdqu    xmm3, [ebp + 16]
  mov       ecx, 1
@@BinPolyMulOddStreakLoop:
  cmp       ecx, dword ptr [esp]
  jg        @@BinPolyMulOddStreakDone

  mov       edx, ecx
  shl       edx, 5
  movdqu    xmm4, [ebp + edx]   // ZZ[2i]
  pxor      xmm2, xmm4

  movdqa    xmm5, xmm2
  pxor      xmm5, xmm3
  mov       eax, ecx
  shl       eax, 4
  movdqu    [ebp + eax], xmm5   // ZZ[i] = V0 ^ V1

  cmp       ecx, dword ptr [esp]
  je        @@BinPolyMulOddStreakNoV1
  movdqu    xmm4, [ebp + edx + 16] // ZZ[2i+1]
  pxor      xmm3, xmm4
@@BinPolyMulOddStreakNoV1:

  inc       ecx
  jmp       @@BinPolyMulOddStreakLoop
@@BinPolyMulOddStreakDone:

  // W = V0 ^ V1; ZZ[(L+1)+i] = ZZ[i] ^ W for i = 0..L-1.
  movdqa    xmm7, xmm2
  pxor      xmm7, xmm3
  xor       ecx, ecx
@@BinPolyMulOddFoldLoop:
  cmp       ecx, dword ptr [esp]
  jge       @@BinPolyMulOddFoldDone

  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm4, [ebp + edx]
  pxor      xmm4, xmm7

  mov       eax, dword ptr [esp]
  add       eax, ecx
  inc       eax
  shl       eax, 4
  movdqu    [ebp + eax], xmm4

  inc       ecx
  jmp       @@BinPolyMulOddFoldLoop
@@BinPolyMulOddFoldDone:

  // Cross products:
  // last = L; zPos = 1..2*last-1, using tail vectors when hi = last.
  mov       eax, dword ptr [esp]
  mov       dword ptr [esp + 4], eax         // last
  cmp       eax, 0
  jle       @@BinPolyMulOddDone

  mov       edx, eax
  shl       edx, 1
  dec       edx
  mov       dword ptr [esp + 8], edx         // zPosMax
  mov       dword ptr [esp + 12], 1          // zPos
@@BinPolyMulOddZPosLoop:
  mov       ecx, dword ptr [esp + 12]        // zPos
  cmp       ecx, dword ptr [esp + 8]
  jg        @@BinPolyMulOddDone

  // hi = min(last, zPos)
  mov       eax, dword ptr [esp + 4]         // last
  cmp       ecx, eax
  jle       @@BinPolyMulOddSetHiFromZPos
  mov       dword ptr [esp + 20], eax
  jmp       @@BinPolyMulOddHiDone
@@BinPolyMulOddSetHiFromZPos:
  mov       dword ptr [esp + 20], ecx
@@BinPolyMulOddHiDone:
  mov       eax, ecx
  sub       eax, dword ptr [esp + 20]
  mov       dword ptr [esp + 16], eax        // lo = zPos - hi

@@BinPolyMulOddPairLoop:
  mov       ecx, dword ptr [esp + 16]        // lo
  cmp       ecx, dword ptr [esp + 20]        // hi
  jge       @@BinPolyMulOddNextZPos

  // Xxor = X[lo] xor X[hi] (tail-form when hi == last).
  mov       edx, ecx
  shl       edx, 4
  movdqu    xmm0, [esi + edx]
  mov       eax, dword ptr [esp + 20]        // hi
  cmp       eax, dword ptr [esp + 4]         // last
  jne       @@BinPolyMulOddXHiFull
  pxor      xmm4, xmm4
  mov       eax, dword ptr [esp + 4]
  shl       eax, 4
  movq      xmm4, qword ptr [esi + eax]
  jmp       @@BinPolyMulOddXHiDone
@@BinPolyMulOddXHiFull:
  shl       eax, 4
  movdqu    xmm4, [esi + eax]
@@BinPolyMulOddXHiDone:
  pxor      xmm0, xmm4

  // Yxor = Y[lo] xor Y[hi] (tail-form when hi == last).
  movdqu    xmm1, [edi + edx]
  mov       eax, dword ptr [esp + 20]        // hi
  cmp       eax, dword ptr [esp + 4]         // last
  jne       @@BinPolyMulOddYHiFull
  pxor      xmm5, xmm5
  mov       eax, dword ptr [esp + 4]
  shl       eax, 4
  movq      xmm5, qword ptr [edi + eax]
  jmp       @@BinPolyMulOddYHiDone
@@BinPolyMulOddYHiFull:
  shl       eax, 4
  movdqu    xmm5, [edi + eax]
@@BinPolyMulOddYHiDone:
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
  jmp       @@BinPolyMulOddPairLoop

@@BinPolyMulOddNextZPos:
  inc       dword ptr [esp + 12]
  jmp       @@BinPolyMulOddZPosLoop

@@BinPolyMulOddDone:
  add       esp, 24
  pop       edx
  pop       ebp
  pop       edi
  pop       esi
  pop       ebx

