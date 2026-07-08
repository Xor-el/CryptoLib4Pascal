// SSE2 variable-length XOR utility (i386).
// After ClpSimdProc4Begin_i386.inc: ebx = ALen, esi = PX, edi = PY, eax = PZ.
// Computes PZ[i] := PX[i] xor PY[i] for i in [0, ALen). PZ may alias PX or PY.
// 16-byte movdqu/pxor chunks, then a byte tail (dl scratch). Callee-saved
// EBX/ESI/EDI are popped in the epilogue below (pushed by ClpSimdProc4Begin_i386).
//
@@ByteXorLoop16:
  cmp       ebx, 16
  jb        @@ByteXorTail
  movdqu    xmm0, [esi]
  movdqu    xmm1, [edi]
  pxor      xmm0, xmm1
  movdqu    [eax], xmm0
  add       esi, 16
  add       edi, 16
  add       eax, 16
  sub       ebx, 16
  jmp       @@ByteXorLoop16
@@ByteXorTail:
  test      ebx, ebx
  jz        @@ByteXorDone
@@ByteXorTailLoop:
  mov       dl, [esi]
  xor       dl, [edi]
  mov       [eax], dl
  inc       esi
  inc       edi
  inc       eax
  dec       ebx
  jnz       @@ByteXorTailLoop
@@ByteXorDone:
  pop       edi
  pop       esi
  pop       ebx
