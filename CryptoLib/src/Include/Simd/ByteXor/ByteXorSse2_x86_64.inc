// SSE2 variable-length XOR utility (x86-64).
// After ClpSimdProc4Begin_x86_64.inc: rcx = ALen, rdx = PX, r8 = PY, r9 = PZ.
// Computes PZ[i] := PX[i] xor PY[i] for i in [0, ALen). PZ may alias PX or PY.
// 16-byte movdqu/pxor chunks, then a byte tail. Uses xmm0, xmm1, al - all
// volatile on both ABIs, so no register save is needed (leaf, nostackframe).
//
@@ByteXorLoop16:
  cmp       rcx, 16
  jb        @@ByteXorTail
  movdqu    xmm0, [rdx]
  movdqu    xmm1, [r8]
  pxor      xmm0, xmm1
  movdqu    [r9], xmm0
  add       rdx, 16
  add       r8, 16
  add       r9, 16
  sub       rcx, 16
  jmp       @@ByteXorLoop16
@@ByteXorTail:
  test      rcx, rcx
  jz        @@ByteXorDone
@@ByteXorTailLoop:
  mov       al, [rdx]
  xor       al, [r8]
  mov       [r9], al
  inc       rdx
  inc       r8
  inc       r9
  dec       rcx
  jnz       @@ByteXorTailLoop
@@ByteXorDone:
