// ChaCha 128B (two 64B blocks), fused I/O, NEON (aarch64), matching the
// contract of ChaCha7539Blocks2Sse2_x86_64.inc.
// -------------------------------------------------------------------
// Little-endian state in [x1], reloaded per block so the counter advance
// carries over. Fused I/O xor: read plaintext at AIn, xor with the ChaCha
// output, write to AOut - no keystream temp in Pascal. Horizontal layout
// as in ChaCha20BlockNeon_aarch64.inc (rows v0..v3, originals v16..v19,
// v4 scratch).
//
// Variant selection:
//   CHACHA_CTR64  -> the per-block counter advance is a 64-bit add
//     spanning words 12/13 (DJB legacy layout; no wrap check). Otherwise
//     word 12 is advanced 32-bit (RFC 7539) and on wrap to 0 the kernel
//     calls ChaChaArmRaiseCounter7539 after the state store, exactly like
//     the x86 kernel (the wrap after block 1 raises before block 2 runs).
//
// On entry (after ClpSimdProc4Begin_aarch64.inc):
//   x0 = ARounds, x1 = AState (R/W, 16 UInt32), x2 = AIn, x3 = AOut.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  // --- block 1 (counter from AState) ---
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00421                    // ldr q1, [x1, #16]
  .long 0x3dc00822                    // ldr q2, [x1, #32]
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
  .long 0x4ea01c10                    // orr v16.16b, v0.16b, v0.16b
  .long 0x4ea11c31                    // orr v17.16b, v1.16b, v1.16b
  .long 0x4ea21c52                    // orr v18.16b, v2.16b, v2.16b
  .long 0x4ea31c73                    // orr v19.16b, v3.16b, v3.16b
  mov w5, w0
.Lc7539_neon_b2r1:
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f2c5481                    // shl v1.4s, v4.4s, #12
  .long 0x6f2c4481                    // sri v1.4s, v4.4s, #20
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c64                    // eor v4.16b, v3.16b, v0.16b
  .long 0x4f285483                    // shl v3.4s, v4.4s, #8
  .long 0x6f284483                    // sri v3.4s, v4.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f275481                    // shl v1.4s, v4.4s, #7
  .long 0x6f274481                    // sri v1.4s, v4.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e036063                    // ext v3.16b, v3.16b, v3.16b, #12
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f2c5481                    // shl v1.4s, v4.4s, #12
  .long 0x6f2c4481                    // sri v1.4s, v4.4s, #20
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c64                    // eor v4.16b, v3.16b, v0.16b
  .long 0x4f285483                    // shl v3.4s, v4.4s, #8
  .long 0x6f284483                    // sri v3.4s, v4.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f275481                    // shl v1.4s, v4.4s, #7
  .long 0x6f274481                    // sri v1.4s, v4.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  subs w5, w5, #2
  b.gt .Lc7539_neon_b2r1
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x4eb18421                    // add v1.4s, v1.4s, v17.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x3dc00044                    // ldr q4, [x2]
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3dc00444                    // ldr q4, [x2, #16]
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x3d800461                    // str q1, [x3, #16]
  .long 0x3dc00844                    // ldr q4, [x2, #32]
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x3d800862                    // str q2, [x3, #32]
  .long 0x3dc00c44                    // ldr q4, [x2, #48]
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x3d800c63                    // str q3, [x3, #48]
{$IFDEF CHACHA_CTR64}
  .long 0xf9401826                    // ldr x6, [x1, #48]
  add x6, x6, #1
  .long 0xf9001826                    // str x6, [x1, #48]
{$ELSE}
  .long 0xb9403026                    // ldr w6, [x1, #48]
  add w6, w6, #1
  .long 0xb9003026                    // str w6, [x1, #48]
  cbz w6, .Lc7539_neon_b2bad
{$ENDIF}
  // --- block 2 (counter from AState) ---
  .long 0x3dc00020                    // ldr q0, [x1]
  .long 0x3dc00421                    // ldr q1, [x1, #16]
  .long 0x3dc00822                    // ldr q2, [x1, #32]
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
  .long 0x4ea01c10                    // orr v16.16b, v0.16b, v0.16b
  .long 0x4ea11c31                    // orr v17.16b, v1.16b, v1.16b
  .long 0x4ea21c52                    // orr v18.16b, v2.16b, v2.16b
  .long 0x4ea31c73                    // orr v19.16b, v3.16b, v3.16b
  mov w5, w0
.Lc7539_neon_b2r2:
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f2c5481                    // shl v1.4s, v4.4s, #12
  .long 0x6f2c4481                    // sri v1.4s, v4.4s, #20
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c64                    // eor v4.16b, v3.16b, v0.16b
  .long 0x4f285483                    // shl v3.4s, v4.4s, #8
  .long 0x6f284483                    // sri v3.4s, v4.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f275481                    // shl v1.4s, v4.4s, #7
  .long 0x6f274481                    // sri v1.4s, v4.4s, #25
  .long 0x6e012021                    // ext v1.16b, v1.16b, v1.16b, #4
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e036063                    // ext v3.16b, v3.16b, v3.16b, #12
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x6e600863                    // rev32 v3.8h, v3.8h
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f2c5481                    // shl v1.4s, v4.4s, #12
  .long 0x6f2c4481                    // sri v1.4s, v4.4s, #20
  .long 0x4ea18400                    // add v0.4s, v0.4s, v1.4s
  .long 0x6e201c64                    // eor v4.16b, v3.16b, v0.16b
  .long 0x4f285483                    // shl v3.4s, v4.4s, #8
  .long 0x6f284483                    // sri v3.4s, v4.4s, #24
  .long 0x4ea38442                    // add v2.4s, v2.4s, v3.4s
  .long 0x6e221c24                    // eor v4.16b, v1.16b, v2.16b
  .long 0x4f275481                    // shl v1.4s, v4.4s, #7
  .long 0x6f274481                    // sri v1.4s, v4.4s, #25
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  subs w5, w5, #2
  b.gt .Lc7539_neon_b2r2
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x4eb18421                    // add v1.4s, v1.4s, v17.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x3d801060                    // str q0, [x3, #64]
  .long 0x3dc01444                    // ldr q4, [x2, #80]
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x3d801461                    // str q1, [x3, #80]
  .long 0x3dc01844                    // ldr q4, [x2, #96]
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x3d801862                    // str q2, [x3, #96]
  .long 0x3dc01c44                    // ldr q4, [x2, #112]
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x3d801c63                    // str q3, [x3, #112]
{$IFDEF CHACHA_CTR64}
  .long 0xf9401826                    // ldr x6, [x1, #48]
  add x6, x6, #1
  .long 0xf9001826                    // str x6, [x1, #48]
{$ELSE}
  .long 0xb9403026                    // ldr w6, [x1, #48]
  add w6, w6, #1
  .long 0xb9003026                    // str w6, [x1, #48]
  cbz w6, .Lc7539_neon_b2bad
{$ENDIF}
{$IFNDEF CHACHA_CTR64}
  b .Lc7539_neon_b2done
.Lc7539_neon_b2bad:
  bl ChaChaArmRaiseCounter7539
.Lc7539_neon_b2done:
{$ENDIF}
  ret
