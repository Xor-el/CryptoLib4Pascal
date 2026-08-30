// Constant-time table gather (AVX2, i386).
// After ClpSimdProc5Begin_i386.inc: ebx = dst, esi = table,
// edi = entryBytes, eax = count, ecx = index. Copies the index-th of
// count entries (each entryBytes wide) into dst, masking every entry by
// -(i == index) and xor-accumulating, so the read pattern is index-
// independent (constant time). 32-byte vmovdqu chunks + a 4-byte tail.
// count/index/i/32-len spill to a 16-byte frame; ebx/esi/edi popped in the
// epilogue, frame freed first; vzeroupper before return.
//
// VEX instructions are db-encoded for broad assembler compatibility.

  sub       esp, 16                  // count, index, i, 32-aligned-len slots
  mov       [esp], eax               // count
  mov       [esp + 4], ecx           // index
  mov       eax, edi
  and       eax, -32
  mov       [esp + 12], eax          // entryBytes rounded to a 32-byte multiple
  db $C5, $FD, $EF, $C0 // vpxor ymm0, ymm0, ymm0
  // zero the accumulator dst[0 .. entryBytes)
  xor       eax, eax
@@GatherZ32:
  cmp       eax, [esp + 12]
  jae       @@GatherZTail
  db $C5, $FE, $7F, $04, $03 // vmovdqu ymmword ptr [ebx + eax], ymm0
  add       eax, 32
  jmp       @@GatherZ32
@@GatherZTail:
  cmp       eax, edi
  jae       @@GatherEntries
  db $C5, $F9, $7E, $04, $03 // vmovd dword ptr [ebx + eax], xmm0
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
  db $C5, $F9, $6E, $C9 // vmovd xmm1, ecx
  db $C4, $E2, $7D, $58, $C9 // vpbroadcastd ymm1, xmm1
  xor       eax, eax                 // inner offset
@@GatherE32:
  cmp       eax, [esp + 12]
  jae       @@GatherETail
  db $C5, $FE, $6F, $04, $06 // vmovdqu ymm0, ymmword ptr [esi + eax]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $FE, $6F, $14, $03 // vmovdqu ymm2, ymmword ptr [ebx + eax]
  db $C5, $ED, $EF, $D0 // vpxor ymm2, ymm2, ymm0
  db $C5, $FE, $7F, $14, $03 // vmovdqu ymmword ptr [ebx + eax], ymm2
  add       eax, 32
  jmp       @@GatherE32
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
  db $C5, $F8, $77 // vzeroupper
  add       esp, 16
  pop       edi
  pop       esi
  pop       ebx
