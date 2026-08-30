// Constant-time table gather (SSE2, x86-64).
// After ClpSimdProc5Begin_x86_64.inc: rcx = dst, rdx = table,
// r8 = entryBytes, r9 = count, r10 = index. Copies the index-th of count
// entries (each entryBytes wide) into dst, masking every entry by
// -(i == index) and xor-accumulating, so the read pattern is index-
// independent (constant time). 16-byte movdqu chunks + a 4-byte tail.
// Uses xmm0-2 (volatile) and callee-saved rbx/rsi/rdi (push/pop'd).

  push      rbx
  push      rsi
  push      rdi
  // rbx = entryBytes rounded down to a 16-byte multiple (16-chunk region end)
  mov       rbx, r8
  and       rbx, -16
  pxor      xmm0, xmm0
  // zero the accumulator dst[0 .. entryBytes)
  xor       rax, rax
@@GatherZ16:
  cmp       rax, rbx
  jae       @@GatherZTail
  movdqu    [rcx + rax], xmm0
  add       rax, 16
  jmp       @@GatherZ16
@@GatherZTail:
  cmp       rax, r8
  jae       @@GatherEntries
  movd      [rcx + rax], xmm0        // zero 4-byte tail slot
  add       rax, 4
  jmp       @@GatherZTail
@@GatherEntries:
  xor       r11, r11                 // i = 0
@@GatherLoop:
  cmp       r11, r9
  jae       @@GatherDone
  mov       esi, r11d
  xor       esi, r10d                // i xor index
  sub       esi, 1                   // -1 iff equal, >=0 otherwise
  sar       esi, 31                  // all-ones iff i==index else 0
  movd      xmm1, esi
  pshufd    xmm1, xmm1, 0            // broadcast mask across the lane
  xor       rax, rax                 // inner offset
@@GatherE16:
  cmp       rax, rbx
  jae       @@GatherETail
  movdqu    xmm0, [rdx + rax]        // entry chunk
  pand      xmm0, xmm1               // & mask
  movdqu    xmm2, [rcx + rax]        // acc chunk
  pxor      xmm2, xmm0
  movdqu    [rcx + rax], xmm2        // acc ^= entry & mask
  add       rax, 16
  jmp       @@GatherE16
@@GatherETail:
  cmp       rax, r8
  jae       @@GatherEDone
  mov       edi, [rdx + rax]         // 4-byte tail: entry dword
  and       edi, esi                 // & mask
  xor       [rcx + rax], edi         // acc ^= entry & mask
  add       rax, 4
  jmp       @@GatherETail
@@GatherEDone:
  add       rdx, r8                  // advance to next entry
  inc       r11
  jmp       @@GatherLoop
@@GatherDone:
  pop       rdi
  pop       rsi
  pop       rbx
