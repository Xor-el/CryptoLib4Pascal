// Constant-time table gather (AVX2, x86-64).
// After ClpSimdProc5Begin_x86_64.inc: rcx = dst, rdx = table,
// r8 = entryBytes, r9 = count, r10 = index. Copies the index-th of count
// entries (each entryBytes wide) into dst, masking every entry by
// -(i == index) and xor-accumulating, so the read pattern is index-
// independent (constant time). The fixed TFePoint (216B) / TFeAffine
// (144B) shapes take register-resident fast paths (accumulator held in
// ymm2.. + GP tail registers across the whole scan, no acc memory RMW);
// other sizes use the width-general 32-byte-chunk + 4-byte-tail path.
// Dispatch branches only on the public entryBytes/count. Callee-saved
// rbx/rsi/rdi/rbp (and xmm6/7 lows on the 216B path) are saved/restored;
// vzeroupper before return.
//
// VEX instructions are db-encoded for broad assembler compatibility.

  push      rbx
  push      rsi
  push      rdi
  push      rbp
  // register-resident fast paths for the two fixed gather shapes
  cmp       r8, 216
  je        @@GatherPoint216
  cmp       r8, 144
  je        @@GatherAffine144
  // ---- width-general fallback (any entryBytes) ----
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
  jmp       @@GatherOut
@@GatherPoint216:
  sub       rsp, 40
  db $C5, $FA, $7F, $34, $24 // vmovdqu xmmword ptr [rsp], xmm6
  db $C5, $FA, $7F, $7C, $24, $10 // vmovdqu xmmword ptr [rsp + 0x10], xmm7
  db $C5, $ED, $EF, $D2 // vpxor ymm2, ymm2, ymm2
  db $C5, $E5, $EF, $DB // vpxor ymm3, ymm3, ymm3
  db $C5, $DD, $EF, $E4 // vpxor ymm4, ymm4, ymm4
  db $C5, $D5, $EF, $ED // vpxor ymm5, ymm5, ymm5
  db $C5, $CD, $EF, $F6 // vpxor ymm6, ymm6, ymm6
  db $C5, $C5, $EF, $FF // vpxor ymm7, ymm7, ymm7
  xor       rbx, rbx
  xor       rsi, rsi
  xor       rdi, rdi
  xor       r11, r11                 // i = 0
@@GPoint216Loop:
  cmp       r11, r9
  jae       @@GPoint216Done
  // mask = -(i == index), 64-bit in rax, broadcast to ymm1
  mov       rax, r11
  xor       rax, r10
  sub       rax, 1
  sar       rax, 63
  db $C5, $F9, $6E, $C8 // vmovd xmm1, eax
  db $C4, $E2, $7D, $58, $C9 // vpbroadcastd ymm1, xmm1
  db $C5, $FE, $6F, $02 // vmovdqu ymm0, ymmword ptr [rdx]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $ED, $EF, $D0 // vpxor ymm2, ymm2, ymm0
  db $C5, $FE, $6F, $42, $20 // vmovdqu ymm0, ymmword ptr [rdx + 0x20]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8 // vpxor ymm3, ymm3, ymm0
  db $C5, $FE, $6F, $42, $40 // vmovdqu ymm0, ymmword ptr [rdx + 0x40]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $DD, $EF, $E0 // vpxor ymm4, ymm4, ymm0
  db $C5, $FE, $6F, $42, $60 // vmovdqu ymm0, ymmword ptr [rdx + 0x60]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $D5, $EF, $E8 // vpxor ymm5, ymm5, ymm0
  db $C5, $FE, $6F, $82, $80, $00, $00, $00 // vmovdqu ymm0, ymmword ptr [rdx + 0x80]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $CD, $EF, $F0 // vpxor ymm6, ymm6, ymm0
  db $C5, $FE, $6F, $82, $A0, $00, $00, $00 // vmovdqu ymm0, ymmword ptr [rdx + 0xa0]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $C5, $EF, $F8 // vpxor ymm7, ymm7, ymm0
  mov       rbp, [rdx + 192]
  and       rbp, rax
  xor       rbx, rbp
  mov       rbp, [rdx + 200]
  and       rbp, rax
  xor       rsi, rbp
  mov       rbp, [rdx + 208]
  and       rbp, rax
  xor       rdi, rbp
  add       rdx, r8                  // next entry
  inc       r11
  jmp       @@GPoint216Loop
@@GPoint216Done:
  db $C5, $FE, $7F, $11 // vmovdqu ymmword ptr [rcx], ymm2
  db $C5, $FE, $7F, $59, $20 // vmovdqu ymmword ptr [rcx + 0x20], ymm3
  db $C5, $FE, $7F, $61, $40 // vmovdqu ymmword ptr [rcx + 0x40], ymm4
  db $C5, $FE, $7F, $69, $60 // vmovdqu ymmword ptr [rcx + 0x60], ymm5
  db $C5, $FE, $7F, $B1, $80, $00, $00, $00 // vmovdqu ymmword ptr [rcx + 0x80], ymm6
  db $C5, $FE, $7F, $B9, $A0, $00, $00, $00 // vmovdqu ymmword ptr [rcx + 0xa0], ymm7
  mov       [rcx + 192], rbx
  mov       [rcx + 200], rsi
  mov       [rcx + 208], rdi
  db $C5, $FA, $6F, $34, $24 // vmovdqu xmm6, xmmword ptr [rsp]
  db $C5, $FA, $6F, $7C, $24, $10 // vmovdqu xmm7, xmmword ptr [rsp + 0x10]
  add       rsp, 40
  db $C5, $F8, $77 // vzeroupper
  jmp       @@GatherOut
@@GatherAffine144:
  db $C5, $ED, $EF, $D2 // vpxor ymm2, ymm2, ymm2
  db $C5, $E5, $EF, $DB // vpxor ymm3, ymm3, ymm3
  db $C5, $DD, $EF, $E4 // vpxor ymm4, ymm4, ymm4
  db $C5, $D5, $EF, $ED // vpxor ymm5, ymm5, ymm5
  xor       rbx, rbx
  xor       rsi, rsi
  xor       r11, r11                 // i = 0
@@GAffine144Loop:
  cmp       r11, r9
  jae       @@GAffine144Done
  // mask = -(i == index), 64-bit in rax, broadcast to ymm1
  mov       rax, r11
  xor       rax, r10
  sub       rax, 1
  sar       rax, 63
  db $C5, $F9, $6E, $C8 // vmovd xmm1, eax
  db $C4, $E2, $7D, $58, $C9 // vpbroadcastd ymm1, xmm1
  db $C5, $FE, $6F, $02 // vmovdqu ymm0, ymmword ptr [rdx]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $ED, $EF, $D0 // vpxor ymm2, ymm2, ymm0
  db $C5, $FE, $6F, $42, $20 // vmovdqu ymm0, ymmword ptr [rdx + 0x20]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $E5, $EF, $D8 // vpxor ymm3, ymm3, ymm0
  db $C5, $FE, $6F, $42, $40 // vmovdqu ymm0, ymmword ptr [rdx + 0x40]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $DD, $EF, $E0 // vpxor ymm4, ymm4, ymm0
  db $C5, $FE, $6F, $42, $60 // vmovdqu ymm0, ymmword ptr [rdx + 0x60]
  db $C5, $FD, $DB, $C1 // vpand ymm0, ymm0, ymm1
  db $C5, $D5, $EF, $E8 // vpxor ymm5, ymm5, ymm0
  mov       rbp, [rdx + 128]
  and       rbp, rax
  xor       rbx, rbp
  mov       rbp, [rdx + 136]
  and       rbp, rax
  xor       rsi, rbp
  add       rdx, r8                  // next entry
  inc       r11
  jmp       @@GAffine144Loop
@@GAffine144Done:
  db $C5, $FE, $7F, $11 // vmovdqu ymmword ptr [rcx], ymm2
  db $C5, $FE, $7F, $59, $20 // vmovdqu ymmword ptr [rcx + 0x20], ymm3
  db $C5, $FE, $7F, $61, $40 // vmovdqu ymmword ptr [rcx + 0x40], ymm4
  db $C5, $FE, $7F, $69, $60 // vmovdqu ymmword ptr [rcx + 0x60], ymm5
  mov       [rcx + 128], rbx
  mov       [rcx + 136], rsi
  db $C5, $F8, $77 // vzeroupper
  jmp       @@GatherOut
@@GatherOut:
  pop       rbp
  pop       rdi
  pop       rsi
  pop       rbx
