// Constant-time table gather (AVX2, x86-64).
// After ClpSimdProc5Begin_x86_64.inc: rcx = dst, rdx = table,
// r8 = entryBytes, r9 = count, r10 = index. Copies the index-th of count
// entries (each entryBytes wide) into dst, masking every entry by
// -(i == index) and xor-accumulating, so the read pattern is index-
// independent (constant time). 32-byte vmovdqu chunks + a 4-byte tail.
// Uses ymm0-2 (volatile) and callee-saved rbx/rsi/rdi (push/pop'd);
// vzeroupper before return.
//
// VEX instructions are db-encoded for broad assembler compatibility.

  push      rbx
  push      rsi
  push      rdi
  // rbx = entryBytes rounded down to a 32-byte multiple (ymm-chunk region end)
  mov       rbx, r8
  and       rbx, -32
  db $C5, $FD, $EF, $C0 // vpxor ymm0, ymm0, ymm0
  // zero the accumulator dst[0 .. entryBytes)
  xor       rax, rax
@@GatherZ32:
  cmp       rax, rbx
  jae       @@GatherZTail
  db $C5, $FE, $7F, $04, $01 // vmovdqu ymmword ptr [rcx + rax], ymm0
  add       rax, 32
  jmp       @@GatherZ32
@@GatherZTail:
  cmp       rax, r8
  jae       @@GatherEntries
  db $C5, $F9, $7E, $04, $01 // vmovd dword ptr [rcx + rax], xmm0
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
  db $C5, $F9, $6E, $CE // vmovd xmm1, esi
  db $C4, $E2, $7D, $58, $C9 // vpbroadcastd ymm1, xmm1
  xor       rax, rax                 // inner offset
@@GatherE32:
  cmp       rax, rbx
  jae       @@GatherETail
  db $C5, $FE, $6F, $04, $02 // vmovdqu ymm0, ymmword ptr [rdx + rax]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $FE, $6F, $14, $01 // vmovdqu ymm2, ymmword ptr [rcx + rax]
  db $C5, $ED, $EF, $D0 // vpxor ymm2, ymm2, ymm0
  db $C5, $FE, $7F, $14, $01 // vmovdqu ymmword ptr [rcx + rax], ymm2
  add       rax, 32
  jmp       @@GatherE32
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
  db $C5, $F8, $77 // vzeroupper
  pop       rdi
  pop       rsi
  pop       rbx
