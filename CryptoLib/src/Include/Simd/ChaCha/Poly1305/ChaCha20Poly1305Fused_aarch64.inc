// ChaCha20-Poly1305 fused kernel (aarch64), the twin of the x86-64 kernel.
// -------------------------------------------------------------------
// Radix-2^64 scalar Poly1305, sharing one .inc with two selectors: the bare
// block loop and the AEAD kernel that interleaves it with 4-way NEON ChaCha20.
// The 2^64 accumulator step is a0 = h0*r0 + h1*s1 ; a1 = h1*r0 + h0*r1 + h2*s1
// + (a0>>64) ; a2 = h2*r0 + (a1>>64) ; h2' = a2 & 3 ; fold 5*(a2>>2) into h0'.
// r1 has its low 2 bits clear (clamp) so s1 = 5*r1/4. Products come from
// mul/umulh; the column carries ride the single aarch64 carry flag (adds/adcs).
//
// Variant selection (set EXACTLY ONE):
//   CRYPTOLIB_CHACHAPOLY_POLY_ONLY - the block loop alone. Absorbs ABlockCount
//     full 16-byte blocks (padbit = 1) from ASrc into the accumulator. On entry
//     (after ClpSimdProc3Begin_aarch64.inc): x0 = @State (r0,r1,s1,h0,h1,h2,
//     pad0,pad1 : consecutive UInt64) ; x1 = ASrc (16*ABlockCount bytes) ;
//     x2 = ABlockCount. h0/h1/h2 written back on exit. GPR: x10=r0 x11=r1
//     x12=s1 ; x7=h0 x8=h1 x9=h2 ; x21=src ; x13 x14 x15 x19 x20 = scratch
//     (x19/x20/x21 callee-saved, stp/ldp-preserved; no vector register touched,
//     so the d8..d15 save frame is omitted).
//   CRYPTOLIB_CHACHAPOLY_FUSED - the AEAD kernel over N 256-byte (4-block)
//     groups. Generates ChaCha20 keystream 4 blocks at a time (identical bytes
//     to the standalone ChaCha7539Blocks4Neon kernel, rounds unrolled), xors it
//     against AIn into AOut, and folds the ciphertext into the accumulator with
//     the poly GPR multiply interleaved into the vector rounds so the integer
//     and vector pipes overlap. ChaCha keeps all of v0..v31 + x0..x6; poly keeps
//     h0/h1/h2 in x7/x8/x9, r0/r1/s1 in x10/x11/x12, src in x21, and
//     x13/x14/x15/x19/x20 as scratch - register-disjoint from ChaCha. On entry
//     (after ClpSimdProc6Begin_aarch64.inc): x0 = ARounds (20, ignored: rounds
//     unrolled) ; x1 = AState (16 UInt32 engine words, word12@byte48 = block
//     counter) ; x2 = AIn ; x3 = AOut ; x4 = AGroups (>= 1, Int32) ; x5 =
//     APolyState (9 UInt64: r0,r1,s1,h0,h1,h2,pad0,pad1,FoldFromInput). h0/h1/h2
//     in on entry, out on exit ; word12 advanced by 4 per group (IETF 32-bit,
//     no CHACHA_CTR64) ; pad0/pad1 untouched (final reduce+tag is separate) ;
//     FoldFromInput@byte64 selects 0 = ENCRYPT (lagged: peel group 0, fold the
//     previous group's [x3-256], scalar drain) / 1 = DECRYPT (fold the current
//     [x2], no lag/peel/drain - AIn==AOut safe).
//
// NEON vector instructions are .long-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_CHACHAPOLY_POLY_ONLY}
  // ---- save callee-saved GPRs (x19/x20/x21) ----
  stp x19, x20, [sp, #-32]!
  str x21, [sp, #16]
  mov x21, x1
  // ---- load constants r0/r1/s1 and accumulator h0/h1/h2 ----
  ldr x10, [x0, #0]
  ldr x11, [x0, #8]
  ldr x12, [x0, #16]
  ldr x7,  [x0, #24]
  ldr x8,  [x0, #32]
  ldr x9,  [x0, #40]
  cbz x2, .Lcp_poly_done
.Lcp_poly_loop:
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  sub x2, x2, #1
  cbnz x2, .Lcp_poly_loop
.Lcp_poly_done:
  // ---- store accumulator back to @State ----
  str x7, [x0, #24]
  str x8, [x0, #32]
  str x9, [x0, #40]
  // ---- restore callee-saved GPRs ----
  ldr x21, [sp, #16]
  ldp x19, x20, [sp], #32
  ret
{$ENDIF}

{$IFDEF CRYPTOLIB_CHACHAPOLY_FUSED}
  mov w4, w4
  // AGroups is Int32: zero-extend before use as a counter
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileSave_aarch64.inc}
  // broadcast originals of words 2..15 into v18..v31
  .long 0xb9400826                    // ldr w6, [x1, #8]
  .long 0x4e040cd2                    // dup v18.4s, w6
  .long 0xb9400c26                    // ldr w6, [x1, #12]
  .long 0x4e040cd3                    // dup v19.4s, w6
  .long 0xb9401026                    // ldr w6, [x1, #16]
  .long 0x4e040cd4                    // dup v20.4s, w6
  .long 0xb9401426                    // ldr w6, [x1, #20]
  .long 0x4e040cd5                    // dup v21.4s, w6
  .long 0xb9401826                    // ldr w6, [x1, #24]
  .long 0x4e040cd6                    // dup v22.4s, w6
  .long 0xb9401c26                    // ldr w6, [x1, #28]
  .long 0x4e040cd7                    // dup v23.4s, w6
  .long 0xb9402026                    // ldr w6, [x1, #32]
  .long 0x4e040cd8                    // dup v24.4s, w6
  .long 0xb9402426                    // ldr w6, [x1, #36]
  .long 0x4e040cd9                    // dup v25.4s, w6
  .long 0xb9402826                    // ldr w6, [x1, #40]
  .long 0x4e040cda                    // dup v26.4s, w6
  .long 0xb9402c26                    // ldr w6, [x1, #44]
  .long 0x4e040cdb                    // dup v27.4s, w6
  .long 0xb9403026                    // ldr w6, [x1, #48]
  .long 0x4e040cdc                    // dup v28.4s, w6
  .long 0xb9403426                    // ldr w6, [x1, #52]
  .long 0x4e040cdd                    // dup v29.4s, w6
  .long 0xb9403826                    // ldr w6, [x1, #56]
  .long 0x4e040cde                    // dup v30.4s, w6
  .long 0xb9403c26                    // ldr w6, [x1, #60]
  .long 0x4e040cdf                    // dup v31.4s, w6
  // counter lanes: orig word 12 += (0, 1, 2, 3)
  .long 0x4f000410                    // movi v16.4s, #0
  mov w6, #1
  .long 0x4e0c1cd0                    // ins v16.s[1], w6
  mov w6, #2
  .long 0x4e141cd0                    // ins v16.s[2], w6
  mov w6, #3
  .long 0x4e1c1cd0                    // ins v16.s[3], w6
  .long 0x4eb0879c                    // add v28.4s, v28.4s, v16.4s
  // ---- save callee-saved poly GPRs (nested in the d8..d15 frame) ----
  stp x19, x20, [sp, #-32]!
  str x21, [sp, #16]
  // ---- load poly constants r0/r1/s1 and accumulator h0/h1/h2 ----
  ldr x10, [x5, #0]
  ldr x11, [x5, #8]
  ldr x12, [x5, #16]
  ldr x7,  [x5, #24]
  ldr x8,  [x5, #32]
  ldr x9,  [x5, #40]
  // ---- select path on FoldFromInput (0=encrypt lagged, 1=decrypt) ----
  ldr x13, [x5, #64]
  cbnz x13, .Lcp_decrypt
  // ================= ENCRYPT (lagged: fold ciphertext at [x3-256]) =
  // ---- peel group 0: keystream only, no poly (no ciphertext yet) ----
  // seed the working state (sigma words re-broadcast)
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cc0                    // dup v0.4s, w6
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cc1                    // dup v1.4s, w6
  .long 0x4eb21e42                    // orr v2.16b, v18.16b, v18.16b
  .long 0x4eb31e63                    // orr v3.16b, v19.16b, v19.16b
  .long 0x4eb41e84                    // orr v4.16b, v20.16b, v20.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x4eb61ec6                    // orr v6.16b, v22.16b, v22.16b
  .long 0x4eb71ee7                    // orr v7.16b, v23.16b, v23.16b
  .long 0x4eb81f08                    // orr v8.16b, v24.16b, v24.16b
  .long 0x4eb91f29                    // orr v9.16b, v25.16b, v25.16b
  .long 0x4eba1f4a                    // orr v10.16b, v26.16b, v26.16b
  .long 0x4ebb1f6b                    // orr v11.16b, v27.16b, v27.16b
  .long 0x4ebc1f8c                    // orr v12.16b, v28.16b, v28.16b
  .long 0x4ebd1fad                    // orr v13.16b, v29.16b, v29.16b
  .long 0x4ebe1fce                    // orr v14.16b, v30.16b, v30.16b
  .long 0x4ebf1fef                    // orr v15.16b, v31.16b, v31.16b
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  // advance the state block counter (word 12) by 4
  .long 0xb9403026                    // ldr w6, [x1, #48]
  add w6, w6, #4
  .long 0xb9003026                    // str w6, [x1, #48]
  // quad 0 (words 0..3): accumulate, transpose, xor
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08421                    // add v1.4s, v1.4s, v16.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x4e813810                    // zip1 v16.4s, v0.4s, v1.4s
  .long 0x4e817811                    // zip2 v17.4s, v0.4s, v1.4s
  .long 0x4e833840                    // zip1 v0.4s, v2.4s, v3.4s
  .long 0x4e837841                    // zip2 v1.4s, v2.4s, v3.4s
  .long 0x4ec03a02                    // zip1 v2.2d, v16.2d, v0.2d
  .long 0x4ec07a03                    // zip2 v3.2d, v16.2d, v0.2d
  .long 0x4ec13a30                    // zip1 v16.2d, v17.2d, v1.2d
  .long 0x4ec17a31                    // zip2 v17.2d, v17.2d, v1.2d
  .long 0x3dc00040                    // ldr q0, [x2]
  .long 0x6e201c40                    // eor v0.16b, v2.16b, v0.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3dc01040                    // ldr q0, [x2, #64]
  .long 0x6e201c60                    // eor v0.16b, v3.16b, v0.16b
  .long 0x3d801060                    // str q0, [x3, #64]
  .long 0x3dc02040                    // ldr q0, [x2, #128]
  .long 0x6e201e00                    // eor v0.16b, v16.16b, v0.16b
  .long 0x3d802060                    // str q0, [x3, #128]
  .long 0x3dc03040                    // ldr q0, [x2, #192]
  .long 0x6e201e20                    // eor v0.16b, v17.16b, v0.16b
  .long 0x3d803060                    // str q0, [x3, #192]
  // quad 1 (words 4..7): accumulate, transpose, xor
  .long 0x4eb48484                    // add v4.4s, v4.4s, v20.4s
  .long 0x4eb584a5                    // add v5.4s, v5.4s, v21.4s
  .long 0x4eb684c6                    // add v6.4s, v6.4s, v22.4s
  .long 0x4eb784e7                    // add v7.4s, v7.4s, v23.4s
  .long 0x4e853890                    // zip1 v16.4s, v4.4s, v5.4s
  .long 0x4e857891                    // zip2 v17.4s, v4.4s, v5.4s
  .long 0x4e8738c4                    // zip1 v4.4s, v6.4s, v7.4s
  .long 0x4e8778c5                    // zip2 v5.4s, v6.4s, v7.4s
  .long 0x4ec43a06                    // zip1 v6.2d, v16.2d, v4.2d
  .long 0x4ec47a07                    // zip2 v7.2d, v16.2d, v4.2d
  .long 0x4ec53a30                    // zip1 v16.2d, v17.2d, v5.2d
  .long 0x4ec57a31                    // zip2 v17.2d, v17.2d, v5.2d
  .long 0x3dc00444                    // ldr q4, [x2, #16]
  .long 0x6e241cc4                    // eor v4.16b, v6.16b, v4.16b
  .long 0x3d800464                    // str q4, [x3, #16]
  .long 0x3dc01444                    // ldr q4, [x2, #80]
  .long 0x6e241ce4                    // eor v4.16b, v7.16b, v4.16b
  .long 0x3d801464                    // str q4, [x3, #80]
  .long 0x3dc02444                    // ldr q4, [x2, #144]
  .long 0x6e241e04                    // eor v4.16b, v16.16b, v4.16b
  .long 0x3d802464                    // str q4, [x3, #144]
  .long 0x3dc03444                    // ldr q4, [x2, #208]
  .long 0x6e241e24                    // eor v4.16b, v17.16b, v4.16b
  .long 0x3d803464                    // str q4, [x3, #208]
  // quad 2 (words 8..11): accumulate, transpose, xor
  .long 0x4eb88508                    // add v8.4s, v8.4s, v24.4s
  .long 0x4eb98529                    // add v9.4s, v9.4s, v25.4s
  .long 0x4eba854a                    // add v10.4s, v10.4s, v26.4s
  .long 0x4ebb856b                    // add v11.4s, v11.4s, v27.4s
  .long 0x4e893910                    // zip1 v16.4s, v8.4s, v9.4s
  .long 0x4e897911                    // zip2 v17.4s, v8.4s, v9.4s
  .long 0x4e8b3948                    // zip1 v8.4s, v10.4s, v11.4s
  .long 0x4e8b7949                    // zip2 v9.4s, v10.4s, v11.4s
  .long 0x4ec83a0a                    // zip1 v10.2d, v16.2d, v8.2d
  .long 0x4ec87a0b                    // zip2 v11.2d, v16.2d, v8.2d
  .long 0x4ec93a30                    // zip1 v16.2d, v17.2d, v9.2d
  .long 0x4ec97a31                    // zip2 v17.2d, v17.2d, v9.2d
  .long 0x3dc00848                    // ldr q8, [x2, #32]
  .long 0x6e281d48                    // eor v8.16b, v10.16b, v8.16b
  .long 0x3d800868                    // str q8, [x3, #32]
  .long 0x3dc01848                    // ldr q8, [x2, #96]
  .long 0x6e281d68                    // eor v8.16b, v11.16b, v8.16b
  .long 0x3d801868                    // str q8, [x3, #96]
  .long 0x3dc02848                    // ldr q8, [x2, #160]
  .long 0x6e281e08                    // eor v8.16b, v16.16b, v8.16b
  .long 0x3d802868                    // str q8, [x3, #160]
  .long 0x3dc03848                    // ldr q8, [x2, #224]
  .long 0x6e281e28                    // eor v8.16b, v17.16b, v8.16b
  .long 0x3d803868                    // str q8, [x3, #224]
  // quad 3 (words 12..15): accumulate, transpose, xor
  .long 0x4ebc858c                    // add v12.4s, v12.4s, v28.4s
  .long 0x4ebd85ad                    // add v13.4s, v13.4s, v29.4s
  .long 0x4ebe85ce                    // add v14.4s, v14.4s, v30.4s
  .long 0x4ebf85ef                    // add v15.4s, v15.4s, v31.4s
  .long 0x4e8d3990                    // zip1 v16.4s, v12.4s, v13.4s
  .long 0x4e8d7991                    // zip2 v17.4s, v12.4s, v13.4s
  .long 0x4e8f39cc                    // zip1 v12.4s, v14.4s, v15.4s
  .long 0x4e8f79cd                    // zip2 v13.4s, v14.4s, v15.4s
  .long 0x4ecc3a0e                    // zip1 v14.2d, v16.2d, v12.2d
  .long 0x4ecc7a0f                    // zip2 v15.2d, v16.2d, v12.2d
  .long 0x4ecd3a30                    // zip1 v16.2d, v17.2d, v13.2d
  .long 0x4ecd7a31                    // zip2 v17.2d, v17.2d, v13.2d
  .long 0x3dc00c4c                    // ldr q12, [x2, #48]
  .long 0x6e2c1dcc                    // eor v12.16b, v14.16b, v12.16b
  .long 0x3d800c6c                    // str q12, [x3, #48]
  .long 0x3dc01c4c                    // ldr q12, [x2, #112]
  .long 0x6e2c1dec                    // eor v12.16b, v15.16b, v12.16b
  .long 0x3d801c6c                    // str q12, [x3, #112]
  .long 0x3dc02c4c                    // ldr q12, [x2, #176]
  .long 0x6e2c1e0c                    // eor v12.16b, v16.16b, v12.16b
  .long 0x3d802c6c                    // str q12, [x3, #176]
  .long 0x3dc03c4c                    // ldr q12, [x2, #240]
  .long 0x6e2c1e2c                    // eor v12.16b, v17.16b, v12.16b
  .long 0x3d803c6c                    // str q12, [x3, #240]
  add x2, x2, #256
  add x3, x3, #256
  sub x4, x4, #1
  cbz x4, .Lcp_enc_drain
.Lcp_enc_loop:
  // next group: counter lanes += 4
  .long 0x4f000490                    // movi v16.4s, #4
  .long 0x4eb0879c                    // add v28.4s, v28.4s, v16.4s
  // seed the working state (sigma words re-broadcast)
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cc0                    // dup v0.4s, w6
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cc1                    // dup v1.4s, w6
  .long 0x4eb21e42                    // orr v2.16b, v18.16b, v18.16b
  .long 0x4eb31e63                    // orr v3.16b, v19.16b, v19.16b
  .long 0x4eb41e84                    // orr v4.16b, v20.16b, v20.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x4eb61ec6                    // orr v6.16b, v22.16b, v22.16b
  .long 0x4eb71ee7                    // orr v7.16b, v23.16b, v23.16b
  .long 0x4eb81f08                    // orr v8.16b, v24.16b, v24.16b
  .long 0x4eb91f29                    // orr v9.16b, v25.16b, v25.16b
  .long 0x4eba1f4a                    // orr v10.16b, v26.16b, v26.16b
  .long 0x4ebb1f6b                    // orr v11.16b, v27.16b, v27.16b
  .long 0x4ebc1f8c                    // orr v12.16b, v28.16b, v28.16b
  .long 0x4ebd1fad                    // orr v13.16b, v29.16b, v29.16b
  .long 0x4ebe1fce                    // orr v14.16b, v30.16b, v30.16b
  .long 0x4ebf1fef                    // orr v15.16b, v31.16b, v31.16b
  // ---- fold the PREVIOUS group's ciphertext (output) while encrypting ----
  sub x21, x3, #256
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // advance the state block counter (word 12) by 4
  .long 0xb9403026                    // ldr w6, [x1, #48]
  add w6, w6, #4
  .long 0xb9003026                    // str w6, [x1, #48]
  // quad 0 (words 0..3): accumulate, transpose, xor
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08421                    // add v1.4s, v1.4s, v16.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x4e813810                    // zip1 v16.4s, v0.4s, v1.4s
  .long 0x4e817811                    // zip2 v17.4s, v0.4s, v1.4s
  .long 0x4e833840                    // zip1 v0.4s, v2.4s, v3.4s
  .long 0x4e837841                    // zip2 v1.4s, v2.4s, v3.4s
  .long 0x4ec03a02                    // zip1 v2.2d, v16.2d, v0.2d
  .long 0x4ec07a03                    // zip2 v3.2d, v16.2d, v0.2d
  .long 0x4ec13a30                    // zip1 v16.2d, v17.2d, v1.2d
  .long 0x4ec17a31                    // zip2 v17.2d, v17.2d, v1.2d
  .long 0x3dc00040                    // ldr q0, [x2]
  .long 0x6e201c40                    // eor v0.16b, v2.16b, v0.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3dc01040                    // ldr q0, [x2, #64]
  .long 0x6e201c60                    // eor v0.16b, v3.16b, v0.16b
  .long 0x3d801060                    // str q0, [x3, #64]
  .long 0x3dc02040                    // ldr q0, [x2, #128]
  .long 0x6e201e00                    // eor v0.16b, v16.16b, v0.16b
  .long 0x3d802060                    // str q0, [x3, #128]
  .long 0x3dc03040                    // ldr q0, [x2, #192]
  .long 0x6e201e20                    // eor v0.16b, v17.16b, v0.16b
  .long 0x3d803060                    // str q0, [x3, #192]
  // quad 1 (words 4..7): accumulate, transpose, xor
  .long 0x4eb48484                    // add v4.4s, v4.4s, v20.4s
  .long 0x4eb584a5                    // add v5.4s, v5.4s, v21.4s
  .long 0x4eb684c6                    // add v6.4s, v6.4s, v22.4s
  .long 0x4eb784e7                    // add v7.4s, v7.4s, v23.4s
  .long 0x4e853890                    // zip1 v16.4s, v4.4s, v5.4s
  .long 0x4e857891                    // zip2 v17.4s, v4.4s, v5.4s
  .long 0x4e8738c4                    // zip1 v4.4s, v6.4s, v7.4s
  .long 0x4e8778c5                    // zip2 v5.4s, v6.4s, v7.4s
  .long 0x4ec43a06                    // zip1 v6.2d, v16.2d, v4.2d
  .long 0x4ec47a07                    // zip2 v7.2d, v16.2d, v4.2d
  .long 0x4ec53a30                    // zip1 v16.2d, v17.2d, v5.2d
  .long 0x4ec57a31                    // zip2 v17.2d, v17.2d, v5.2d
  .long 0x3dc00444                    // ldr q4, [x2, #16]
  .long 0x6e241cc4                    // eor v4.16b, v6.16b, v4.16b
  .long 0x3d800464                    // str q4, [x3, #16]
  .long 0x3dc01444                    // ldr q4, [x2, #80]
  .long 0x6e241ce4                    // eor v4.16b, v7.16b, v4.16b
  .long 0x3d801464                    // str q4, [x3, #80]
  .long 0x3dc02444                    // ldr q4, [x2, #144]
  .long 0x6e241e04                    // eor v4.16b, v16.16b, v4.16b
  .long 0x3d802464                    // str q4, [x3, #144]
  .long 0x3dc03444                    // ldr q4, [x2, #208]
  .long 0x6e241e24                    // eor v4.16b, v17.16b, v4.16b
  .long 0x3d803464                    // str q4, [x3, #208]
  // quad 2 (words 8..11): accumulate, transpose, xor
  .long 0x4eb88508                    // add v8.4s, v8.4s, v24.4s
  .long 0x4eb98529                    // add v9.4s, v9.4s, v25.4s
  .long 0x4eba854a                    // add v10.4s, v10.4s, v26.4s
  .long 0x4ebb856b                    // add v11.4s, v11.4s, v27.4s
  .long 0x4e893910                    // zip1 v16.4s, v8.4s, v9.4s
  .long 0x4e897911                    // zip2 v17.4s, v8.4s, v9.4s
  .long 0x4e8b3948                    // zip1 v8.4s, v10.4s, v11.4s
  .long 0x4e8b7949                    // zip2 v9.4s, v10.4s, v11.4s
  .long 0x4ec83a0a                    // zip1 v10.2d, v16.2d, v8.2d
  .long 0x4ec87a0b                    // zip2 v11.2d, v16.2d, v8.2d
  .long 0x4ec93a30                    // zip1 v16.2d, v17.2d, v9.2d
  .long 0x4ec97a31                    // zip2 v17.2d, v17.2d, v9.2d
  .long 0x3dc00848                    // ldr q8, [x2, #32]
  .long 0x6e281d48                    // eor v8.16b, v10.16b, v8.16b
  .long 0x3d800868                    // str q8, [x3, #32]
  .long 0x3dc01848                    // ldr q8, [x2, #96]
  .long 0x6e281d68                    // eor v8.16b, v11.16b, v8.16b
  .long 0x3d801868                    // str q8, [x3, #96]
  .long 0x3dc02848                    // ldr q8, [x2, #160]
  .long 0x6e281e08                    // eor v8.16b, v16.16b, v8.16b
  .long 0x3d802868                    // str q8, [x3, #160]
  .long 0x3dc03848                    // ldr q8, [x2, #224]
  .long 0x6e281e28                    // eor v8.16b, v17.16b, v8.16b
  .long 0x3d803868                    // str q8, [x3, #224]
  // quad 3 (words 12..15): accumulate, transpose, xor
  .long 0x4ebc858c                    // add v12.4s, v12.4s, v28.4s
  .long 0x4ebd85ad                    // add v13.4s, v13.4s, v29.4s
  .long 0x4ebe85ce                    // add v14.4s, v14.4s, v30.4s
  .long 0x4ebf85ef                    // add v15.4s, v15.4s, v31.4s
  .long 0x4e8d3990                    // zip1 v16.4s, v12.4s, v13.4s
  .long 0x4e8d7991                    // zip2 v17.4s, v12.4s, v13.4s
  .long 0x4e8f39cc                    // zip1 v12.4s, v14.4s, v15.4s
  .long 0x4e8f79cd                    // zip2 v13.4s, v14.4s, v15.4s
  .long 0x4ecc3a0e                    // zip1 v14.2d, v16.2d, v12.2d
  .long 0x4ecc7a0f                    // zip2 v15.2d, v16.2d, v12.2d
  .long 0x4ecd3a30                    // zip1 v16.2d, v17.2d, v13.2d
  .long 0x4ecd7a31                    // zip2 v17.2d, v17.2d, v13.2d
  .long 0x3dc00c4c                    // ldr q12, [x2, #48]
  .long 0x6e2c1dcc                    // eor v12.16b, v14.16b, v12.16b
  .long 0x3d800c6c                    // str q12, [x3, #48]
  .long 0x3dc01c4c                    // ldr q12, [x2, #112]
  .long 0x6e2c1dec                    // eor v12.16b, v15.16b, v12.16b
  .long 0x3d801c6c                    // str q12, [x3, #112]
  .long 0x3dc02c4c                    // ldr q12, [x2, #176]
  .long 0x6e2c1e0c                    // eor v12.16b, v16.16b, v12.16b
  .long 0x3d802c6c                    // str q12, [x3, #176]
  .long 0x3dc03c4c                    // ldr q12, [x2, #240]
  .long 0x6e2c1e2c                    // eor v12.16b, v17.16b, v12.16b
  .long 0x3d803c6c                    // str q12, [x3, #240]
  add x2, x2, #256
  add x3, x3, #256
  sub x4, x4, #1
  cbnz x4, .Lcp_enc_loop
.Lcp_enc_drain:
  // ---- drain: fold the last group's ciphertext at [x3-256] ----
  sub x21, x3, #256
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  b .Lcp_done
.Lcp_decrypt:
  // ================= DECRYPT (current: fold ciphertext at [x2]) ====
  b .Lcp_dec_enter
.Lcp_dec_outer:
  // next group: counter lanes += 4
  .long 0x4f000490                    // movi v16.4s, #4
  .long 0x4eb0879c                    // add v28.4s, v28.4s, v16.4s
.Lcp_dec_enter:
  // seed the working state (sigma words re-broadcast)
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cc0                    // dup v0.4s, w6
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cc1                    // dup v1.4s, w6
  .long 0x4eb21e42                    // orr v2.16b, v18.16b, v18.16b
  .long 0x4eb31e63                    // orr v3.16b, v19.16b, v19.16b
  .long 0x4eb41e84                    // orr v4.16b, v20.16b, v20.16b
  .long 0x4eb51ea5                    // orr v5.16b, v21.16b, v21.16b
  .long 0x4eb61ec6                    // orr v6.16b, v22.16b, v22.16b
  .long 0x4eb71ee7                    // orr v7.16b, v23.16b, v23.16b
  .long 0x4eb81f08                    // orr v8.16b, v24.16b, v24.16b
  .long 0x4eb91f29                    // orr v9.16b, v25.16b, v25.16b
  .long 0x4eba1f4a                    // orr v10.16b, v26.16b, v26.16b
  .long 0x4ebb1f6b                    // orr v11.16b, v27.16b, v27.16b
  .long 0x4ebc1f8c                    // orr v12.16b, v28.16b, v28.16b
  .long 0x4ebd1fad                    // orr v13.16b, v29.16b, v29.16b
  .long 0x4ebe1fce                    // orr v14.16b, v30.16b, v30.16b
  .long 0x4ebf1fef                    // orr v15.16b, v31.16b, v31.16b
  // ---- fold the CURRENT group's input ciphertext (read before the tail) ----
  mov x21, x2
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // column quarter-rounds
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d8c                    // eor v12.16b, v12.16b, v0.16b
  .long 0x6e211dad                    // eor v13.16b, v13.16b, v1.16b
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f2c5604                    // shl v4.4s, v16.4s, #12
  .long 0x4f2c5625                    // shl v5.4s, v17.4s, #12
  .long 0x6f2c4604                    // sri v4.4s, v16.4s, #20
  .long 0x6f2c4625                    // sri v5.4s, v17.4s, #20
  .long 0x4ea48400                    // add v0.4s, v0.4s, v4.4s
  .long 0x4ea58421                    // add v1.4s, v1.4s, v5.4s
  .long 0x6e201d90                    // eor v16.16b, v12.16b, v0.16b
  .long 0x6e211db1                    // eor v17.16b, v13.16b, v1.16b
  .long 0x4f28560c                    // shl v12.4s, v16.4s, #8
  .long 0x4f28562d                    // shl v13.4s, v17.4s, #8
  .long 0x6f28460c                    // sri v12.4s, v16.4s, #24
  .long 0x6f28462d                    // sri v13.4s, v17.4s, #24
  .long 0x4eac8508                    // add v8.4s, v8.4s, v12.4s
  .long 0x4ead8529                    // add v9.4s, v9.4s, v13.4s
  .long 0x6e281c90                    // eor v16.16b, v4.16b, v8.16b
  .long 0x6e291cb1                    // eor v17.16b, v5.16b, v9.16b
  .long 0x4f275604                    // shl v4.4s, v16.4s, #7
  .long 0x4f275625                    // shl v5.4s, v17.4s, #7
  .long 0x6f274604                    // sri v4.4s, v16.4s, #25
  .long 0x6f274625                    // sri v5.4s, v17.4s, #25
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dce                    // eor v14.16b, v14.16b, v2.16b
  .long 0x6e231def                    // eor v15.16b, v15.16b, v3.16b
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f2c5606                    // shl v6.4s, v16.4s, #12
  .long 0x4f2c5627                    // shl v7.4s, v17.4s, #12
  .long 0x6f2c4606                    // sri v6.4s, v16.4s, #20
  .long 0x6f2c4627                    // sri v7.4s, v17.4s, #20
  .long 0x4ea68442                    // add v2.4s, v2.4s, v6.4s
  .long 0x4ea78463                    // add v3.4s, v3.4s, v7.4s
  .long 0x6e221dd0                    // eor v16.16b, v14.16b, v2.16b
  .long 0x6e231df1                    // eor v17.16b, v15.16b, v3.16b
  .long 0x4f28560e                    // shl v14.4s, v16.4s, #8
  .long 0x4f28562f                    // shl v15.4s, v17.4s, #8
  .long 0x6f28460e                    // sri v14.4s, v16.4s, #24
  .long 0x6f28462f                    // sri v15.4s, v17.4s, #24
  .long 0x4eae854a                    // add v10.4s, v10.4s, v14.4s
  .long 0x4eaf856b                    // add v11.4s, v11.4s, v15.4s
  .long 0x6e2a1cd0                    // eor v16.16b, v6.16b, v10.16b
  .long 0x6e2b1cf1                    // eor v17.16b, v7.16b, v11.16b
  .long 0x4f275606                    // shl v6.4s, v16.4s, #7
  .long 0x4f275627                    // shl v7.4s, v17.4s, #7
  .long 0x6f274606                    // sri v6.4s, v16.4s, #25
  .long 0x6f274627                    // sri v7.4s, v17.4s, #25
  // diagonal quarter-rounds
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201def                    // eor v15.16b, v15.16b, v0.16b
  .long 0x6e211d8c                    // eor v12.16b, v12.16b, v1.16b
  .long 0x6e6009ef                    // rev32 v15.8h, v15.8h
  .long 0x6e60098c                    // rev32 v12.8h, v12.8h
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f2c5605                    // shl v5.4s, v16.4s, #12
  .long 0x4f2c5626                    // shl v6.4s, v17.4s, #12
  .long 0x6f2c4605                    // sri v5.4s, v16.4s, #20
  .long 0x6f2c4626                    // sri v6.4s, v17.4s, #20
  .long 0x4ea58400                    // add v0.4s, v0.4s, v5.4s
  .long 0x4ea68421                    // add v1.4s, v1.4s, v6.4s
  .long 0x6e201df0                    // eor v16.16b, v15.16b, v0.16b
  .long 0x6e211d91                    // eor v17.16b, v12.16b, v1.16b
  .long 0x4f28560f                    // shl v15.4s, v16.4s, #8
  .long 0x4f28562c                    // shl v12.4s, v17.4s, #8
  .long 0x6f28460f                    // sri v15.4s, v16.4s, #24
  .long 0x6f28462c                    // sri v12.4s, v17.4s, #24
  .long 0x4eaf854a                    // add v10.4s, v10.4s, v15.4s
  .long 0x4eac856b                    // add v11.4s, v11.4s, v12.4s
  .long 0x6e2a1cb0                    // eor v16.16b, v5.16b, v10.16b
  .long 0x6e2b1cd1                    // eor v17.16b, v6.16b, v11.16b
  .long 0x4f275605                    // shl v5.4s, v16.4s, #7
  .long 0x4f275626                    // shl v6.4s, v17.4s, #7
  .long 0x6f274605                    // sri v5.4s, v16.4s, #25
  .long 0x6f274626                    // sri v6.4s, v17.4s, #25
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221dad                    // eor v13.16b, v13.16b, v2.16b
  .long 0x6e231dce                    // eor v14.16b, v14.16b, v3.16b
  .long 0x6e6009ad                    // rev32 v13.8h, v13.8h
  .long 0x6e6009ce                    // rev32 v14.8h, v14.8h
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f2c5607                    // shl v7.4s, v16.4s, #12
  .long 0x4f2c5624                    // shl v4.4s, v17.4s, #12
  .long 0x6f2c4607                    // sri v7.4s, v16.4s, #20
  .long 0x6f2c4624                    // sri v4.4s, v17.4s, #20
  .long 0x4ea78442                    // add v2.4s, v2.4s, v7.4s
  .long 0x4ea48463                    // add v3.4s, v3.4s, v4.4s
  .long 0x6e221db0                    // eor v16.16b, v13.16b, v2.16b
  .long 0x6e231dd1                    // eor v17.16b, v14.16b, v3.16b
  .long 0x4f28560d                    // shl v13.4s, v16.4s, #8
  .long 0x4f28562e                    // shl v14.4s, v17.4s, #8
  .long 0x6f28460d                    // sri v13.4s, v16.4s, #24
  .long 0x6f28462e                    // sri v14.4s, v17.4s, #24
  .long 0x4ead8508                    // add v8.4s, v8.4s, v13.4s
  .long 0x4eae8529                    // add v9.4s, v9.4s, v14.4s
  .long 0x6e281cf0                    // eor v16.16b, v7.16b, v8.16b
  .long 0x6e291c91                    // eor v17.16b, v4.16b, v9.16b
  .long 0x4f275607                    // shl v7.4s, v16.4s, #7
  .long 0x4f275624                    // shl v4.4s, v17.4s, #7
  .long 0x6f274607                    // sri v7.4s, v16.4s, #25
  .long 0x6f274624                    // sri v4.4s, v17.4s, #25
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  ldr   x13, [x21]                 // m0
  ldr   x14, [x21, #8]             // m1
  adds  x7, x7, x13                // h0 += m0
  adcs  x8, x8, x14                // h1 += m1 + c
  adc   x9, x9, xzr                // h2 += c
  add   x9, x9, #1                 // h2 += padbit
  mul   x15, x7, x10
  umulh x19, x7, x10
  mul   x13, x7, x11
  umulh x14, x7, x11
  mul   x7, x8, x12
  umulh x20, x8, x12
  adds  x15, x15, x7
  adcs  x19, x19, x20
  mul   x7, x8, x10
  umulh x20, x8, x10
  mov   x8, xzr
  adds  x19, x19, x7
  adcs  x8, x8, x20
  adds  x19, x19, x13
  adcs  x8, x8, x14
  mul   x7, x9, x12
  umulh x20, x9, x12
  adds  x19, x19, x7
  adcs  x8, x8, x20
  mul   x7, x9, x10
  umulh x20, x9, x10
  adds  x7, x7, x8
  mov   x9, x7
  and   x9, x9, #3                 // h2' = a2 & 3
  lsr   x7, x7, #2                 // a2 >> 2
  add   x7, x7, x7, lsl #2         // 5*(a2>>2)
  adds  x15, x15, x7
  adcs  x19, x19, xzr
  adcs  x9, x9, xzr
  mov   x7, x15
  mov   x8, x19
  add   x21, x21, #16              // next block
  // advance the state block counter (word 12) by 4
  .long 0xb9403026                    // ldr w6, [x1, #48]
  add w6, w6, #4
  .long 0xb9003026                    // str w6, [x1, #48]
  // quad 0 (words 0..3): accumulate, transpose, xor
  .long 0xb9400026                    // ldr w6, [x1]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08400                    // add v0.4s, v0.4s, v16.4s
  .long 0xb9400426                    // ldr w6, [x1, #4]
  .long 0x4e040cd0                    // dup v16.4s, w6
  .long 0x4eb08421                    // add v1.4s, v1.4s, v16.4s
  .long 0x4eb28442                    // add v2.4s, v2.4s, v18.4s
  .long 0x4eb38463                    // add v3.4s, v3.4s, v19.4s
  .long 0x4e813810                    // zip1 v16.4s, v0.4s, v1.4s
  .long 0x4e817811                    // zip2 v17.4s, v0.4s, v1.4s
  .long 0x4e833840                    // zip1 v0.4s, v2.4s, v3.4s
  .long 0x4e837841                    // zip2 v1.4s, v2.4s, v3.4s
  .long 0x4ec03a02                    // zip1 v2.2d, v16.2d, v0.2d
  .long 0x4ec07a03                    // zip2 v3.2d, v16.2d, v0.2d
  .long 0x4ec13a30                    // zip1 v16.2d, v17.2d, v1.2d
  .long 0x4ec17a31                    // zip2 v17.2d, v17.2d, v1.2d
  .long 0x3dc00040                    // ldr q0, [x2]
  .long 0x6e201c40                    // eor v0.16b, v2.16b, v0.16b
  .long 0x3d800060                    // str q0, [x3]
  .long 0x3dc01040                    // ldr q0, [x2, #64]
  .long 0x6e201c60                    // eor v0.16b, v3.16b, v0.16b
  .long 0x3d801060                    // str q0, [x3, #64]
  .long 0x3dc02040                    // ldr q0, [x2, #128]
  .long 0x6e201e00                    // eor v0.16b, v16.16b, v0.16b
  .long 0x3d802060                    // str q0, [x3, #128]
  .long 0x3dc03040                    // ldr q0, [x2, #192]
  .long 0x6e201e20                    // eor v0.16b, v17.16b, v0.16b
  .long 0x3d803060                    // str q0, [x3, #192]
  // quad 1 (words 4..7): accumulate, transpose, xor
  .long 0x4eb48484                    // add v4.4s, v4.4s, v20.4s
  .long 0x4eb584a5                    // add v5.4s, v5.4s, v21.4s
  .long 0x4eb684c6                    // add v6.4s, v6.4s, v22.4s
  .long 0x4eb784e7                    // add v7.4s, v7.4s, v23.4s
  .long 0x4e853890                    // zip1 v16.4s, v4.4s, v5.4s
  .long 0x4e857891                    // zip2 v17.4s, v4.4s, v5.4s
  .long 0x4e8738c4                    // zip1 v4.4s, v6.4s, v7.4s
  .long 0x4e8778c5                    // zip2 v5.4s, v6.4s, v7.4s
  .long 0x4ec43a06                    // zip1 v6.2d, v16.2d, v4.2d
  .long 0x4ec47a07                    // zip2 v7.2d, v16.2d, v4.2d
  .long 0x4ec53a30                    // zip1 v16.2d, v17.2d, v5.2d
  .long 0x4ec57a31                    // zip2 v17.2d, v17.2d, v5.2d
  .long 0x3dc00444                    // ldr q4, [x2, #16]
  .long 0x6e241cc4                    // eor v4.16b, v6.16b, v4.16b
  .long 0x3d800464                    // str q4, [x3, #16]
  .long 0x3dc01444                    // ldr q4, [x2, #80]
  .long 0x6e241ce4                    // eor v4.16b, v7.16b, v4.16b
  .long 0x3d801464                    // str q4, [x3, #80]
  .long 0x3dc02444                    // ldr q4, [x2, #144]
  .long 0x6e241e04                    // eor v4.16b, v16.16b, v4.16b
  .long 0x3d802464                    // str q4, [x3, #144]
  .long 0x3dc03444                    // ldr q4, [x2, #208]
  .long 0x6e241e24                    // eor v4.16b, v17.16b, v4.16b
  .long 0x3d803464                    // str q4, [x3, #208]
  // quad 2 (words 8..11): accumulate, transpose, xor
  .long 0x4eb88508                    // add v8.4s, v8.4s, v24.4s
  .long 0x4eb98529                    // add v9.4s, v9.4s, v25.4s
  .long 0x4eba854a                    // add v10.4s, v10.4s, v26.4s
  .long 0x4ebb856b                    // add v11.4s, v11.4s, v27.4s
  .long 0x4e893910                    // zip1 v16.4s, v8.4s, v9.4s
  .long 0x4e897911                    // zip2 v17.4s, v8.4s, v9.4s
  .long 0x4e8b3948                    // zip1 v8.4s, v10.4s, v11.4s
  .long 0x4e8b7949                    // zip2 v9.4s, v10.4s, v11.4s
  .long 0x4ec83a0a                    // zip1 v10.2d, v16.2d, v8.2d
  .long 0x4ec87a0b                    // zip2 v11.2d, v16.2d, v8.2d
  .long 0x4ec93a30                    // zip1 v16.2d, v17.2d, v9.2d
  .long 0x4ec97a31                    // zip2 v17.2d, v17.2d, v9.2d
  .long 0x3dc00848                    // ldr q8, [x2, #32]
  .long 0x6e281d48                    // eor v8.16b, v10.16b, v8.16b
  .long 0x3d800868                    // str q8, [x3, #32]
  .long 0x3dc01848                    // ldr q8, [x2, #96]
  .long 0x6e281d68                    // eor v8.16b, v11.16b, v8.16b
  .long 0x3d801868                    // str q8, [x3, #96]
  .long 0x3dc02848                    // ldr q8, [x2, #160]
  .long 0x6e281e08                    // eor v8.16b, v16.16b, v8.16b
  .long 0x3d802868                    // str q8, [x3, #160]
  .long 0x3dc03848                    // ldr q8, [x2, #224]
  .long 0x6e281e28                    // eor v8.16b, v17.16b, v8.16b
  .long 0x3d803868                    // str q8, [x3, #224]
  // quad 3 (words 12..15): accumulate, transpose, xor
  .long 0x4ebc858c                    // add v12.4s, v12.4s, v28.4s
  .long 0x4ebd85ad                    // add v13.4s, v13.4s, v29.4s
  .long 0x4ebe85ce                    // add v14.4s, v14.4s, v30.4s
  .long 0x4ebf85ef                    // add v15.4s, v15.4s, v31.4s
  .long 0x4e8d3990                    // zip1 v16.4s, v12.4s, v13.4s
  .long 0x4e8d7991                    // zip2 v17.4s, v12.4s, v13.4s
  .long 0x4e8f39cc                    // zip1 v12.4s, v14.4s, v15.4s
  .long 0x4e8f79cd                    // zip2 v13.4s, v14.4s, v15.4s
  .long 0x4ecc3a0e                    // zip1 v14.2d, v16.2d, v12.2d
  .long 0x4ecc7a0f                    // zip2 v15.2d, v16.2d, v12.2d
  .long 0x4ecd3a30                    // zip1 v16.2d, v17.2d, v13.2d
  .long 0x4ecd7a31                    // zip2 v17.2d, v17.2d, v13.2d
  .long 0x3dc00c4c                    // ldr q12, [x2, #48]
  .long 0x6e2c1dcc                    // eor v12.16b, v14.16b, v12.16b
  .long 0x3d800c6c                    // str q12, [x3, #48]
  .long 0x3dc01c4c                    // ldr q12, [x2, #112]
  .long 0x6e2c1dec                    // eor v12.16b, v15.16b, v12.16b
  .long 0x3d801c6c                    // str q12, [x3, #112]
  .long 0x3dc02c4c                    // ldr q12, [x2, #176]
  .long 0x6e2c1e0c                    // eor v12.16b, v16.16b, v12.16b
  .long 0x3d802c6c                    // str q12, [x3, #176]
  .long 0x3dc03c4c                    // ldr q12, [x2, #240]
  .long 0x6e2c1e2c                    // eor v12.16b, v17.16b, v12.16b
  .long 0x3d803c6c                    // str q12, [x3, #240]
  add x2, x2, #256
  add x3, x3, #256
  sub x4, x4, #1
  cbnz x4, .Lcp_dec_outer
.Lcp_done:
  // ---- write the accumulator back to APolyState ----
  str x7, [x5, #24]
  str x8, [x5, #32]
  str x9, [x5, #40]
  // ---- restore callee-saved poly GPRs ----
  ldr x21, [sp, #16]
  ldp x19, x20, [sp], #32
{$I ..\..\..\Include\Simd\Common\ClpSimdNonVolatileRestore_aarch64.inc}
  ret
{$ENDIF}
