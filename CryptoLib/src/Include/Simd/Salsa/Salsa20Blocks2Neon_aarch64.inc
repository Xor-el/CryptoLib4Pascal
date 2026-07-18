// Salsa20 128B (two 64B blocks), fused I/O, NEON (aarch64), matching the
// contract of Salsa20Blocks2Sse2_x86_64.inc.
// -------------------------------------------------------------------
// Two 64B blocks, fused I/O xor, diagonal layout and gather as in
// Salsa20BlockNeon_aarch64.inc (the fused path scatters with
// umov+ldr+eor+str per word). The per-block counter advance over state
// words 8/9 is a single 64-bit add (replacing the x86 inc/branch/inc
// carry sequence; Salsa's counter is 64-bit, so there is no wrap error
// path).
//
// On entry (after ClpSimdProc4Begin_aarch64.inc):
//   x0 = ARounds, x1 = AState (R/W, 16 UInt32), x2 = AIn, x3 = AOut.
//   Counter words: FEngineState[8]@[x1+32], FEngineState[9]@[x1+36].
//
// Reference: D.J. Bernstein, "Salsa20 specification" (cr.yp.to/salsa20/) -
// the quarterround/rowround/columnround arithmetic that this kernel's
// rounds implement.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
  // -------- block 1 (64B) at I/O offset 0 --------
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e041cc0                    // ins v0.s[0], w6
  .long 0xb9401426                    // ldr w6, [x1, #20]
  .long 0x4e0c1cc0                    // ins v0.s[1], w6
  .long 0xb9402826                    // ldr w6, [x1, #40]
  .long 0x4e141cc0                    // ins v0.s[2], w6
  .long 0xb9403c26                    // ldr w6, [x1, #60]
  .long 0x4e1c1cc0                    // ins v0.s[3], w6
  .long 0xb9403026                    // ldr w6, [x1, #48]
  .long 0x4e041cc1                    // ins v1.s[0], w6
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e0c1cc1                    // ins v1.s[1], w6
  .long 0xb9401826                    // ldr w6, [x1, #24]
  .long 0x4e141cc1                    // ins v1.s[2], w6
  .long 0xb9402c26                    // ldr w6, [x1, #44]
  .long 0x4e1c1cc1                    // ins v1.s[3], w6
  .long 0xb9402026                    // ldr w6, [x1, #32]
  .long 0x4e041cc2                    // ins v2.s[0], w6
  .long 0xb9403426                    // ldr w6, [x1, #52]
  .long 0x4e0c1cc2                    // ins v2.s[1], w6
  .long 0xb9400826                    // ldr w6, [x1, #8]
  .long 0x4e141cc2                    // ins v2.s[2], w6
  .long 0xb9401c26                    // ldr w6, [x1, #28]
  .long 0x4e1c1cc2                    // ins v2.s[3], w6
  .long 0xb9401026                    // ldr w6, [x1, #16]
  .long 0x4e041cc3                    // ins v3.s[0], w6
  .long 0xb9402426                    // ldr w6, [x1, #36]
  .long 0x4e0c1cc3                    // ins v3.s[1], w6
  .long 0xb9403826                    // ldr w6, [x1, #56]
  .long 0x4e141cc3                    // ins v3.s[2], w6
  .long 0xb9400c26                    // ldr w6, [x1, #12]
  .long 0x4e1c1cc3                    // ins v3.s[3], w6
  .long 0x4ea01c10                    // orr v16.16b, v0.16b, v0.16b
  .long 0x4ea11c31                    // orr v17.16b, v1.16b, v1.16b
  .long 0x4ea21c52                    // orr v18.16b, v2.16b, v2.16b
  .long 0x4ea31c73                    // orr v19.16b, v3.16b, v3.16b
  mov w5, w0
.Lsalsa_neon_b2r1:
  .long 0x4ea11c24                    // orr v4.16b, v1.16b, v1.16b
  .long 0x4ea31c61                    // orr v1.16b, v3.16b, v3.16b
  .long 0x4ea41c83                    // orr v3.16b, v4.16b, v4.16b
  .long 0x4ea38404                    // add v4.4s, v0.4s, v3.4s
  .long 0x6f270485                    // ushr v5.4s, v4.4s, #25
  .long 0x4f275484                    // shl v4.4s, v4.4s, #7
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x4ea08424                    // add v4.4s, v1.4s, v0.4s
  .long 0x6f290485                    // ushr v5.4s, v4.4s, #23
  .long 0x4f295484                    // shl v4.4s, v4.4s, #9
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x4ea18444                    // add v4.4s, v2.4s, v1.4s
  .long 0x6f2d0485                    // ushr v5.4s, v4.4s, #19
  .long 0x4f2d5484                    // shl v4.4s, v4.4s, #13
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x4ea28464                    // add v4.4s, v3.4s, v2.4s
  .long 0x6f320485                    // ushr v5.4s, v4.4s, #14
  .long 0x4f325484                    // shl v4.4s, v4.4s, #18
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  .long 0x4ea11c24                    // orr v4.16b, v1.16b, v1.16b
  .long 0x4ea31c61                    // orr v1.16b, v3.16b, v3.16b
  .long 0x4ea41c83                    // orr v3.16b, v4.16b, v4.16b
  .long 0x4ea38404                    // add v4.4s, v0.4s, v3.4s
  .long 0x6f270485                    // ushr v5.4s, v4.4s, #25
  .long 0x4f275484                    // shl v4.4s, v4.4s, #7
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x4ea08424                    // add v4.4s, v1.4s, v0.4s
  .long 0x6f290485                    // ushr v5.4s, v4.4s, #23
  .long 0x4f295484                    // shl v4.4s, v4.4s, #9
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x4ea18444                    // add v4.4s, v2.4s, v1.4s
  .long 0x6f2d0485                    // ushr v5.4s, v4.4s, #19
  .long 0x4f2d5484                    // shl v4.4s, v4.4s, #13
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x4ea28464                    // add v4.4s, v3.4s, v2.4s
  .long 0x6f320485                    // ushr v5.4s, v4.4s, #14
  .long 0x4f325484                    // shl v4.4s, v4.4s, #18
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  subs w5, w5, #2
  b.gt .Lsalsa_neon_b2r1
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x4eb18421                    // add v1.4s, v1.4s, v17.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x0e043c06                    // umov w6, v0.s[0]
  .long 0xb9400047                    // ldr w7, [x2]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9000066                    // str w6, [x3]
  .long 0x0e0c3c06                    // umov w6, v0.s[1]
  .long 0xb9401447                    // ldr w7, [x2, #20]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9001466                    // str w6, [x3, #20]
  .long 0x0e143c06                    // umov w6, v0.s[2]
  .long 0xb9402847                    // ldr w7, [x2, #40]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9002866                    // str w6, [x3, #40]
  .long 0x0e1c3c06                    // umov w6, v0.s[3]
  .long 0xb9403c47                    // ldr w7, [x2, #60]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9003c66                    // str w6, [x3, #60]
  .long 0x0e043c26                    // umov w6, v1.s[0]
  .long 0xb9403047                    // ldr w7, [x2, #48]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9003066                    // str w6, [x3, #48]
  .long 0x0e0c3c26                    // umov w6, v1.s[1]
  .long 0xb9400447                    // ldr w7, [x2, #4]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9000466                    // str w6, [x3, #4]
  .long 0x0e143c26                    // umov w6, v1.s[2]
  .long 0xb9401847                    // ldr w7, [x2, #24]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9001866                    // str w6, [x3, #24]
  .long 0x0e1c3c26                    // umov w6, v1.s[3]
  .long 0xb9402c47                    // ldr w7, [x2, #44]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9002c66                    // str w6, [x3, #44]
  .long 0x0e043c46                    // umov w6, v2.s[0]
  .long 0xb9402047                    // ldr w7, [x2, #32]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9002066                    // str w6, [x3, #32]
  .long 0x0e0c3c46                    // umov w6, v2.s[1]
  .long 0xb9403447                    // ldr w7, [x2, #52]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9003466                    // str w6, [x3, #52]
  .long 0x0e143c46                    // umov w6, v2.s[2]
  .long 0xb9400847                    // ldr w7, [x2, #8]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9000866                    // str w6, [x3, #8]
  .long 0x0e1c3c46                    // umov w6, v2.s[3]
  .long 0xb9401c47                    // ldr w7, [x2, #28]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9001c66                    // str w6, [x3, #28]
  .long 0x0e043c66                    // umov w6, v3.s[0]
  .long 0xb9401047                    // ldr w7, [x2, #16]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9001066                    // str w6, [x3, #16]
  .long 0x0e0c3c66                    // umov w6, v3.s[1]
  .long 0xb9402447                    // ldr w7, [x2, #36]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9002466                    // str w6, [x3, #36]
  .long 0x0e143c66                    // umov w6, v3.s[2]
  .long 0xb9403847                    // ldr w7, [x2, #56]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9003866                    // str w6, [x3, #56]
  .long 0x0e1c3c66                    // umov w6, v3.s[3]
  .long 0xb9400c47                    // ldr w7, [x2, #12]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9000c66                    // str w6, [x3, #12]
  // AdvanceCounter: state words 8/9 as one 64-bit add
  .long 0xf9401026                    // ldr x6, [x1, #32]
  add x6, x6, #1
  .long 0xf9001026                    // str x6, [x1, #32]
  // -------- block 2 (64B) at I/O offset 64 --------
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e041cc0                    // ins v0.s[0], w6
  .long 0xb9401426                    // ldr w6, [x1, #20]
  .long 0x4e0c1cc0                    // ins v0.s[1], w6
  .long 0xb9402826                    // ldr w6, [x1, #40]
  .long 0x4e141cc0                    // ins v0.s[2], w6
  .long 0xb9403c26                    // ldr w6, [x1, #60]
  .long 0x4e1c1cc0                    // ins v0.s[3], w6
  .long 0xb9403026                    // ldr w6, [x1, #48]
  .long 0x4e041cc1                    // ins v1.s[0], w6
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e0c1cc1                    // ins v1.s[1], w6
  .long 0xb9401826                    // ldr w6, [x1, #24]
  .long 0x4e141cc1                    // ins v1.s[2], w6
  .long 0xb9402c26                    // ldr w6, [x1, #44]
  .long 0x4e1c1cc1                    // ins v1.s[3], w6
  .long 0xb9402026                    // ldr w6, [x1, #32]
  .long 0x4e041cc2                    // ins v2.s[0], w6
  .long 0xb9403426                    // ldr w6, [x1, #52]
  .long 0x4e0c1cc2                    // ins v2.s[1], w6
  .long 0xb9400826                    // ldr w6, [x1, #8]
  .long 0x4e141cc2                    // ins v2.s[2], w6
  .long 0xb9401c26                    // ldr w6, [x1, #28]
  .long 0x4e1c1cc2                    // ins v2.s[3], w6
  .long 0xb9401026                    // ldr w6, [x1, #16]
  .long 0x4e041cc3                    // ins v3.s[0], w6
  .long 0xb9402426                    // ldr w6, [x1, #36]
  .long 0x4e0c1cc3                    // ins v3.s[1], w6
  .long 0xb9403826                    // ldr w6, [x1, #56]
  .long 0x4e141cc3                    // ins v3.s[2], w6
  .long 0xb9400c26                    // ldr w6, [x1, #12]
  .long 0x4e1c1cc3                    // ins v3.s[3], w6
  .long 0x4ea01c10                    // orr v16.16b, v0.16b, v0.16b
  .long 0x4ea11c31                    // orr v17.16b, v1.16b, v1.16b
  .long 0x4ea21c52                    // orr v18.16b, v2.16b, v2.16b
  .long 0x4ea31c73                    // orr v19.16b, v3.16b, v3.16b
  mov w5, w0
.Lsalsa_neon_b2r2:
  .long 0x4ea11c24                    // orr v4.16b, v1.16b, v1.16b
  .long 0x4ea31c61                    // orr v1.16b, v3.16b, v3.16b
  .long 0x4ea41c83                    // orr v3.16b, v4.16b, v4.16b
  .long 0x4ea38404                    // add v4.4s, v0.4s, v3.4s
  .long 0x6f270485                    // ushr v5.4s, v4.4s, #25
  .long 0x4f275484                    // shl v4.4s, v4.4s, #7
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x4ea08424                    // add v4.4s, v1.4s, v0.4s
  .long 0x6f290485                    // ushr v5.4s, v4.4s, #23
  .long 0x4f295484                    // shl v4.4s, v4.4s, #9
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x4ea18444                    // add v4.4s, v2.4s, v1.4s
  .long 0x6f2d0485                    // ushr v5.4s, v4.4s, #19
  .long 0x4f2d5484                    // shl v4.4s, v4.4s, #13
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x4ea28464                    // add v4.4s, v3.4s, v2.4s
  .long 0x6f320485                    // ushr v5.4s, v4.4s, #14
  .long 0x4f325484                    // shl v4.4s, v4.4s, #18
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  .long 0x4ea11c24                    // orr v4.16b, v1.16b, v1.16b
  .long 0x4ea31c61                    // orr v1.16b, v3.16b, v3.16b
  .long 0x4ea41c83                    // orr v3.16b, v4.16b, v4.16b
  .long 0x4ea38404                    // add v4.4s, v0.4s, v3.4s
  .long 0x6f270485                    // ushr v5.4s, v4.4s, #25
  .long 0x4f275484                    // shl v4.4s, v4.4s, #7
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c21                    // eor v1.16b, v1.16b, v4.16b
  .long 0x4ea08424                    // add v4.4s, v1.4s, v0.4s
  .long 0x6f290485                    // ushr v5.4s, v4.4s, #23
  .long 0x4f295484                    // shl v4.4s, v4.4s, #9
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c42                    // eor v2.16b, v2.16b, v4.16b
  .long 0x4ea18444                    // add v4.4s, v2.4s, v1.4s
  .long 0x6f2d0485                    // ushr v5.4s, v4.4s, #19
  .long 0x4f2d5484                    // shl v4.4s, v4.4s, #13
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c63                    // eor v3.16b, v3.16b, v4.16b
  .long 0x4ea28464                    // add v4.4s, v3.4s, v2.4s
  .long 0x6f320485                    // ushr v5.4s, v4.4s, #14
  .long 0x4f325484                    // shl v4.4s, v4.4s, #18
  .long 0x4ea51c84                    // orr v4.16b, v4.16b, v5.16b
  .long 0x6e241c00                    // eor v0.16b, v0.16b, v4.16b
  .long 0x6e016021                    // ext v1.16b, v1.16b, v1.16b, #12
  .long 0x6e024042                    // ext v2.16b, v2.16b, v2.16b, #8
  .long 0x6e032063                    // ext v3.16b, v3.16b, v3.16b, #4
  subs w5, w5, #2
  b.gt .Lsalsa_neon_b2r2
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x4eb18421                    // add v1.4s, v1.4s, v17.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x0e043c06                    // umov w6, v0.s[0]
  .long 0xb9404047                    // ldr w7, [x2, #64]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9004066                    // str w6, [x3, #64]
  .long 0x0e0c3c06                    // umov w6, v0.s[1]
  .long 0xb9405447                    // ldr w7, [x2, #84]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9005466                    // str w6, [x3, #84]
  .long 0x0e143c06                    // umov w6, v0.s[2]
  .long 0xb9406847                    // ldr w7, [x2, #104]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9006866                    // str w6, [x3, #104]
  .long 0x0e1c3c06                    // umov w6, v0.s[3]
  .long 0xb9407c47                    // ldr w7, [x2, #124]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9007c66                    // str w6, [x3, #124]
  .long 0x0e043c26                    // umov w6, v1.s[0]
  .long 0xb9407047                    // ldr w7, [x2, #112]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9007066                    // str w6, [x3, #112]
  .long 0x0e0c3c26                    // umov w6, v1.s[1]
  .long 0xb9404447                    // ldr w7, [x2, #68]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9004466                    // str w6, [x3, #68]
  .long 0x0e143c26                    // umov w6, v1.s[2]
  .long 0xb9405847                    // ldr w7, [x2, #88]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9005866                    // str w6, [x3, #88]
  .long 0x0e1c3c26                    // umov w6, v1.s[3]
  .long 0xb9406c47                    // ldr w7, [x2, #108]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9006c66                    // str w6, [x3, #108]
  .long 0x0e043c46                    // umov w6, v2.s[0]
  .long 0xb9406047                    // ldr w7, [x2, #96]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9006066                    // str w6, [x3, #96]
  .long 0x0e0c3c46                    // umov w6, v2.s[1]
  .long 0xb9407447                    // ldr w7, [x2, #116]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9007466                    // str w6, [x3, #116]
  .long 0x0e143c46                    // umov w6, v2.s[2]
  .long 0xb9404847                    // ldr w7, [x2, #72]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9004866                    // str w6, [x3, #72]
  .long 0x0e1c3c46                    // umov w6, v2.s[3]
  .long 0xb9405c47                    // ldr w7, [x2, #92]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9005c66                    // str w6, [x3, #92]
  .long 0x0e043c66                    // umov w6, v3.s[0]
  .long 0xb9405047                    // ldr w7, [x2, #80]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9005066                    // str w6, [x3, #80]
  .long 0x0e0c3c66                    // umov w6, v3.s[1]
  .long 0xb9406447                    // ldr w7, [x2, #100]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9006466                    // str w6, [x3, #100]
  .long 0x0e143c66                    // umov w6, v3.s[2]
  .long 0xb9407847                    // ldr w7, [x2, #120]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9007866                    // str w6, [x3, #120]
  .long 0x0e1c3c66                    // umov w6, v3.s[3]
  .long 0xb9404c47                    // ldr w7, [x2, #76]
  .long 0x4a0700c6                    // eor w6, w6, w7
  .long 0xb9004c66                    // str w6, [x3, #76]
  // AdvanceCounter: state words 8/9 as one 64-bit add
  .long 0xf9401026                    // ldr x6, [x1, #32]
  add x6, x6, #1
  .long 0xf9001026                    // str x6, [x1, #32]
  ret
