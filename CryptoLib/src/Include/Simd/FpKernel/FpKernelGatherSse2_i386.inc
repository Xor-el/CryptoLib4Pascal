// Constant-time table gather (SSE2, i386).
// After ClpSimdProc5Begin_i386.inc: ebx = dst, esi = table,
// edi = entryBytes, eax = count, ecx = index. Copies the index-th of
// count entries (each entryBytes wide) into dst, masking every entry by
// -(i == index) and xor-accumulating, so the read pattern is index-
// independent (constant time). 16-byte movdqu chunks + a 4-byte tail.
// count/index/i/16-len spill to a 16-byte frame (32-bit is register-
// starved); ebx/esi/edi popped in the epilogue, frame freed first.

  sub       esp, 16                  // count, index, i, 16-aligned-len slots
  mov       [esp], eax               // count
  mov       [esp + 4], ecx           // index
  mov       eax, edi
  and       eax, -16
  mov       [esp + 12], eax          // entryBytes rounded to a 16-byte multiple
  pxor      xmm0, xmm0
  // zero the accumulator dst[0 .. entryBytes)
  xor       eax, eax                 // offset
@@GatherZ16:
  cmp       eax, [esp + 12]
  jae       @@GatherZTail
  movdqu    [ebx + eax], xmm0
  add       eax, 16
  jmp       @@GatherZ16
@@GatherZTail:
  cmp       eax, edi
  jae       @@GatherEntries
  movd      [ebx + eax], xmm0        // zero 4-byte tail slot
  add       eax, 4
  jmp       @@GatherZTail
@@GatherEntries:
  xor       eax, eax
  mov       [esp + 8], eax           // i = 0
@@GatherLoop:
  mov       ecx, [esp + 8]           // i
  cmp       ecx, [esp]               // i vs count
  jae       @@GatherDone
  xor       ecx, [esp + 4]           // i xor index
  sub       ecx, 1
  sar       ecx, 31                  // all-ones iff i==index else 0
  movd      xmm1, ecx
  pshufd    xmm1, xmm1, 0            // broadcast mask across the lane
  xor       eax, eax                 // inner offset
@@GatherE16:
  cmp       eax, [esp + 12]
  jae       @@GatherETail
  movdqu    xmm0, [esi + eax]        // entry chunk
  pand      xmm0, xmm1               // & mask
  movdqu    xmm2, [ebx + eax]        // acc chunk
  pxor      xmm2, xmm0
  movdqu    [ebx + eax], xmm2        // acc ^= entry & mask
  add       eax, 16
  jmp       @@GatherE16
@@GatherETail:
  cmp       eax, edi
  jae       @@GatherEDone
  mov       edx, [esi + eax]         // 4-byte tail: entry dword
  and       edx, ecx                 // & mask
  xor       [ebx + eax], edx         // acc ^= entry & mask
  add       eax, 4
  jmp       @@GatherETail
@@GatherEDone:
  add       esi, edi                 // advance to next entry
  mov       eax, [esp + 8]
  add       eax, 1
  mov       [esp + 8], eax           // i++
  jmp       @@GatherLoop
@@GatherDone:
  add       esp, 16
  pop       edi
  pop       esi
  pop       ebx
