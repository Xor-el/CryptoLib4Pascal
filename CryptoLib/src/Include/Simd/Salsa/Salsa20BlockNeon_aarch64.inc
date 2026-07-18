// Salsa20 one-block (16*UInt32) core, NEON (aarch64), matching the
// contract of Salsa20BlockSse2_x86_64.inc.
// -------------------------------------------------------------------
// LE state in, LE state+input out. The 4-lane quarter round works on the
// diagonal layout
//   b0=[s0,s5,s10,s15] b1=[s12,s1,s6,s11] b2=[s8,s13,s2,s7] b3=[s4,s9,s14,s3].
// The diagonal transpose is an ldr+ins gather on the way in and an
// umov+str scatter on the way out (the NEON analogue of the x86 kernel's
// scalar dword gather/scatter). Originals are parked in v16..v19 (no
// stack copy needed); rotations use shl+ushr+orr into v4/v5 scratch and
// the diagonal re-indexing uses ext lane rotations.
//
// On entry (after ClpSimdProc3Begin_aarch64.inc):
//   x0 = ARounds, x1 = AIn (16 UInt32), x2 = AOut (16 UInt32).
//
// Reference: D.J. Bernstein, "Salsa20 specification" (cr.yp.to/salsa20/) -
// the quarterround/rowround/columnround arithmetic that this kernel's
// rounds implement.
//
// AArch64 vector instructions are .long-encoded for broad assembler
// compatibility.
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
.Lsalsa_neon_core_rd:
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
  b.gt .Lsalsa_neon_core_rd
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0x4eb18421                    // add v1.4s, v1.4s, v17.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x0e043c06                    // umov w6, v0.s[0]
  .long 0xb9000046                    // str w6, [x2]
  .long 0x0e0c3c06                    // umov w6, v0.s[1]
  .long 0xb9001446                    // str w6, [x2, #20]
  .long 0x0e143c06                    // umov w6, v0.s[2]
  .long 0xb9002846                    // str w6, [x2, #40]
  .long 0x0e1c3c06                    // umov w6, v0.s[3]
  .long 0xb9003c46                    // str w6, [x2, #60]
  .long 0x0e043c26                    // umov w6, v1.s[0]
  .long 0xb9003046                    // str w6, [x2, #48]
  .long 0x0e0c3c26                    // umov w6, v1.s[1]
  .long 0xb9000446                    // str w6, [x2, #4]
  .long 0x0e143c26                    // umov w6, v1.s[2]
  .long 0xb9001846                    // str w6, [x2, #24]
  .long 0x0e1c3c26                    // umov w6, v1.s[3]
  .long 0xb9002c46                    // str w6, [x2, #44]
  .long 0x0e043c46                    // umov w6, v2.s[0]
  .long 0xb9002046                    // str w6, [x2, #32]
  .long 0x0e0c3c46                    // umov w6, v2.s[1]
  .long 0xb9003446                    // str w6, [x2, #52]
  .long 0x0e143c46                    // umov w6, v2.s[2]
  .long 0xb9000846                    // str w6, [x2, #8]
  .long 0x0e1c3c46                    // umov w6, v2.s[3]
  .long 0xb9001c46                    // str w6, [x2, #28]
  .long 0x0e043c66                    // umov w6, v3.s[0]
  .long 0xb9001046                    // str w6, [x2, #16]
  .long 0x0e0c3c66                    // umov w6, v3.s[1]
  .long 0xb9002446                    // str w6, [x2, #36]
  .long 0x0e143c66                    // umov w6, v3.s[2]
  .long 0xb9003846                    // str w6, [x2, #56]
  .long 0x0e1c3c66                    // umov w6, v3.s[3]
  .long 0xb9000c46                    // str w6, [x2, #12]
  ret
