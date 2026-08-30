// Constant-time table gather (NEON, aarch64), matching the contract of
// FpKernelGatherSse2_x86_64.inc.
// After ClpSimdProc5Begin_aarch64.inc: x0 = dst, x1 = table, x2 = entryBytes,
// x3 = count, x4 = index. Copies the index-th of count entries (each entryBytes
// wide) into dst, masking every entry by -(i == index) and xor-accumulating, so
// the read pattern is index-independent (constant time). The fixed TFePoint
// (216B) / TFeAffine (144B) shapes take register-resident fast paths (the whole
// accumulator held in v16.. + one GP tail register across the scan, no
// accumulator memory RMW); other sizes use the width-general 16-byte-chunk +
// 4-byte-tail path. Dispatch branches only on the public entryBytes/count.
// Uses v0-v1, v16-v28 and x5-x10 only - all caller-saved on the AArch64 PCS,
// so no callee-saved registers and no frame.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  cmp x2, #216
  b.eq .Lgather_neon_p216
  cmp x2, #144
  b.eq .Lgather_neon_a144
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
.Lgather_neon_p216:
  .long 0x4f00e410                    // movi v16.16b, #0
  .long 0x4f00e411                    // movi v17.16b, #0
  .long 0x4f00e412                    // movi v18.16b, #0
  .long 0x4f00e413                    // movi v19.16b, #0
  .long 0x4f00e414                    // movi v20.16b, #0
  .long 0x4f00e415                    // movi v21.16b, #0
  .long 0x4f00e416                    // movi v22.16b, #0
  .long 0x4f00e417                    // movi v23.16b, #0
  .long 0x4f00e418                    // movi v24.16b, #0
  .long 0x4f00e419                    // movi v25.16b, #0
  .long 0x4f00e41a                    // movi v26.16b, #0
  .long 0x4f00e41b                    // movi v27.16b, #0
  .long 0x4f00e41c                    // movi v28.16b, #0
  mov x10, #0
  mov x5, #0
.Lg_p216_loop:
  cmp x5, x3
  b.hs .Lg_p216_done
  eor x8, x5, x4
  sub x8, x8, #1
  asr x8, x8, #63
  .long 0x4e040d01                    // dup v1.4s, w8
  .long 0x3dc00020                    // ldr q0, [x1, #0]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e10                    // eor v16.16b, v16.16b, v0.16b
  .long 0x3dc00420                    // ldr q0, [x1, #16]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e31                    // eor v17.16b, v17.16b, v0.16b
  .long 0x3dc00820                    // ldr q0, [x1, #32]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e52                    // eor v18.16b, v18.16b, v0.16b
  .long 0x3dc00c20                    // ldr q0, [x1, #48]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e73                    // eor v19.16b, v19.16b, v0.16b
  .long 0x3dc01020                    // ldr q0, [x1, #64]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e94                    // eor v20.16b, v20.16b, v0.16b
  .long 0x3dc01420                    // ldr q0, [x1, #80]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x3dc01820                    // ldr q0, [x1, #96]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x3dc01c20                    // ldr q0, [x1, #112]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201ef7                    // eor v23.16b, v23.16b, v0.16b
  .long 0x3dc02020                    // ldr q0, [x1, #128]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201f18                    // eor v24.16b, v24.16b, v0.16b
  .long 0x3dc02420                    // ldr q0, [x1, #144]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201f39                    // eor v25.16b, v25.16b, v0.16b
  .long 0x3dc02820                    // ldr q0, [x1, #160]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201f5a                    // eor v26.16b, v26.16b, v0.16b
  .long 0x3dc02c20                    // ldr q0, [x1, #176]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201f7b                    // eor v27.16b, v27.16b, v0.16b
  .long 0x3dc03020                    // ldr q0, [x1, #192]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201f9c                    // eor v28.16b, v28.16b, v0.16b
  ldr x9, [x1, #208]
  and x9, x9, x8
  eor x10, x10, x9
  add x1, x1, x2
  add x5, x5, #1
  b .Lg_p216_loop
.Lg_p216_done:
  .long 0x3d800010                    // str q16, [x0, #0]
  .long 0x3d800411                    // str q17, [x0, #16]
  .long 0x3d800812                    // str q18, [x0, #32]
  .long 0x3d800c13                    // str q19, [x0, #48]
  .long 0x3d801014                    // str q20, [x0, #64]
  .long 0x3d801415                    // str q21, [x0, #80]
  .long 0x3d801816                    // str q22, [x0, #96]
  .long 0x3d801c17                    // str q23, [x0, #112]
  .long 0x3d802018                    // str q24, [x0, #128]
  .long 0x3d802419                    // str q25, [x0, #144]
  .long 0x3d80281a                    // str q26, [x0, #160]
  .long 0x3d802c1b                    // str q27, [x0, #176]
  .long 0x3d80301c                    // str q28, [x0, #192]
  str x10, [x0, #208]
  ret
.Lgather_neon_a144:
  .long 0x4f00e410                    // movi v16.16b, #0
  .long 0x4f00e411                    // movi v17.16b, #0
  .long 0x4f00e412                    // movi v18.16b, #0
  .long 0x4f00e413                    // movi v19.16b, #0
  .long 0x4f00e414                    // movi v20.16b, #0
  .long 0x4f00e415                    // movi v21.16b, #0
  .long 0x4f00e416                    // movi v22.16b, #0
  .long 0x4f00e417                    // movi v23.16b, #0
  .long 0x4f00e418                    // movi v24.16b, #0
  mov x5, #0
.Lg_a144_loop:
  cmp x5, x3
  b.hs .Lg_a144_done
  eor x8, x5, x4
  sub x8, x8, #1
  asr x8, x8, #63
  .long 0x4e040d01                    // dup v1.4s, w8
  .long 0x3dc00020                    // ldr q0, [x1, #0]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e10                    // eor v16.16b, v16.16b, v0.16b
  .long 0x3dc00420                    // ldr q0, [x1, #16]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e31                    // eor v17.16b, v17.16b, v0.16b
  .long 0x3dc00820                    // ldr q0, [x1, #32]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e52                    // eor v18.16b, v18.16b, v0.16b
  .long 0x3dc00c20                    // ldr q0, [x1, #48]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e73                    // eor v19.16b, v19.16b, v0.16b
  .long 0x3dc01020                    // ldr q0, [x1, #64]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201e94                    // eor v20.16b, v20.16b, v0.16b
  .long 0x3dc01420                    // ldr q0, [x1, #80]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201eb5                    // eor v21.16b, v21.16b, v0.16b
  .long 0x3dc01820                    // ldr q0, [x1, #96]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201ed6                    // eor v22.16b, v22.16b, v0.16b
  .long 0x3dc01c20                    // ldr q0, [x1, #112]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201ef7                    // eor v23.16b, v23.16b, v0.16b
  .long 0x3dc02020                    // ldr q0, [x1, #128]
  .long 0x4e211c00                    // and v0.16b, v0.16b, v1.16b
  .long 0x6e201f18                    // eor v24.16b, v24.16b, v0.16b
  add x1, x1, x2
  add x5, x5, #1
  b .Lg_a144_loop
.Lg_a144_done:
  .long 0x3d800010                    // str q16, [x0, #0]
  .long 0x3d800411                    // str q17, [x0, #16]
  .long 0x3d800812                    // str q18, [x0, #32]
  .long 0x3d800c13                    // str q19, [x0, #48]
  .long 0x3d801014                    // str q20, [x0, #64]
  .long 0x3d801415                    // str q21, [x0, #80]
  .long 0x3d801816                    // str q22, [x0, #96]
  .long 0x3d801c17                    // str q23, [x0, #112]
  .long 0x3d802018                    // str q24, [x0, #128]
  ret
