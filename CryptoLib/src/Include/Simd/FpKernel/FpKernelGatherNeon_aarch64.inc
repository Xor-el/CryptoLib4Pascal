// Constant-time table gather (NEON, aarch64), matching the contract of
// FpKernelGatherSse2_x86_64.inc.
// After ClpSimdProc5Begin_aarch64.inc: x0 = dst, x1 = table, x2 = entryBytes,
// x3 = count, x4 = index. Copies the index-th of count entries (each entryBytes
// wide) into dst, masking every entry by -(i == index) and xor-accumulating, so
// the read pattern is index-independent (constant time). 16-byte vector chunks +
// a 4-byte tail. Uses v0-v2 and x5-x10 only - no callee-saved registers, no frame.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  and x7, x2, #-16
  .long 0x4f00e400                    // movi v0.16b, #0
  mov x6, #0
.Lgather_neon_z16:
  cmp x6, x7
  b.hs .Lgather_neon_ztail
  .long 0x3ca66800                    // str q0, [x0, x6]
  add x6, x6, #16
  b .Lgather_neon_z16
.Lgather_neon_ztail:
  cmp x6, x2
  b.hs .Lgather_neon_entries
  str wzr, [x0, x6]
  add x6, x6, #4
  b .Lgather_neon_ztail
.Lgather_neon_entries:
  mov x5, #0
.Lgather_neon_loop:
  cmp x5, x3
  b.hs .Lgather_neon_done
  eor w8, w5, w4
  sub w8, w8, #1
  asr w8, w8, #31
  .long 0x4e040d01                    // dup v1.4s, w8
  mov x6, #0
.Lgather_neon_e16:
  cmp x6, x7
  b.hs .Lgather_neon_etail
  .long 0x3ce66820                    // ldr q0, [x1, x6]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x3ce66802                    // ldr q2, [x0, x6]
  .long 0x6e201c42                    // eor v2.16b, v2.16b, v0.16b
  .long 0x3ca66802                    // str q2, [x0, x6]
  add x6, x6, #16
  b .Lgather_neon_e16
.Lgather_neon_etail:
  cmp x6, x2
  b.hs .Lgather_neon_edone
  ldr w9, [x1, x6]
  and w9, w9, w8
  ldr w10, [x0, x6]
  eor w10, w10, w9
  str w10, [x0, x6]
  add x6, x6, #4
  b .Lgather_neon_etail
.Lgather_neon_edone:
  add x1, x1, x2
  add x5, x5, #1
  b .Lgather_neon_loop
.Lgather_neon_done:
  ret
