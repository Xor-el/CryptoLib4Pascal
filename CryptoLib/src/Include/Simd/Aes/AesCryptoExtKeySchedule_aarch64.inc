// AES CryptoExt (FEAT_AES) key-schedule kernel, merged expansion +
// decrypt-prep, merged key sizes (aarch64).
// -------------------------------------------------------------------
//
// Expansion: constant-time vector ladder producing the N_R + 1 round keys
// (16 bytes each) per the AES-128 / 192 / 256 schedules; N_R = 10 / 12 / 14.
// SubWord = aese against a zero key on a lane-broadcast word (ShiftRows is
// the identity when all columns are equal), RotWord = ext #1 on the periodic
// byte pattern, rcon = movi lane splat, prefix XOR fold via the two-step
// doubling shift (ext #12 / ext #8). No table lookups, no GPR data flow.
// Decrypt-prep: aesimc on the middle round keys (1..N_R - 1) in place, then
// reverses the key order to produce a schedule consumed front-to-back by
// aesd / aesimc chains.
//
// Variant selection:
//   CRYPTOLIB_AESCRYPTOEXT_KEYSCHEDULE_INVERT  -> decrypt-prep; else expansion
//   with exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128 / KEY192 / KEY256.
//
// Entry (after ClpSimdProc2Begin_aarch64.inc):
//   expansion:    x0 = user key (16 / 24 / 32 bytes),
//                 x1 = KeysOut (16 * (N_R + 1) bytes).
//   decrypt-prep: x0 = round keys (in place), w1 = NRounds in {10, 12, 14}.
//
// Scratch: expansion v0..v5; decrypt-prep v0..v1 and x5..x7. v8..v15
// untouched (only d8..d15 are callee-saved under AAPCS64).
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEYSCHEDULE_INVERT}
  mov w1, w1
  .long 0xd37cec26                    // lsl x6, x1, #4
  sub w7, w1, #1
  add x5, x0, #16
.Laescryptoext_imc_loop:
  .long 0x3dc000a0                    // ldr q0, [x5]
  .long 0x4e287800                    // aesimc v0.16b, v0.16b
  .long 0x3d8000a0                    // str q0, [x5]
  add x5, x5, #16
  sub w7, w7, #1
  cbnz w7, .Laescryptoext_imc_loop
  mov x5, x0
  add x6, x0, x6
.Laescryptoext_swap_loop:
  .long 0x3dc000a0                    // ldr q0, [x5]
  .long 0x3dc000c1                    // ldr q1, [x6]
  .long 0x3d8000a1                    // str q1, [x5]
  .long 0x3d8000c0                    // str q0, [x6]
  add x5, x5, #16
  sub x6, x6, #16
  cmp x5, x6
  b.lo .Laescryptoext_swap_loop
  ret
{$ELSE}
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x3d800020                    // str q0, [x1]

  // ----- K[1], rcon 1 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000425                    // movi v5.4s, #1
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800420                    // str q0, [x1, #16]

  // ----- K[2], rcon 2 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000445                    // movi v5.4s, #2
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800820                    // str q0, [x1, #32]

  // ----- K[3], rcon 4 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000485                    // movi v5.4s, #4
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800c20                    // str q0, [x1, #48]

  // ----- K[4], rcon 8 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000505                    // movi v5.4s, #8
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d801020                    // str q0, [x1, #64]

  // ----- K[5], rcon 16 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000605                    // movi v5.4s, #16
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d801420                    // str q0, [x1, #80]

  // ----- K[6], rcon 32 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f010405                    // movi v5.4s, #32
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d801820                    // str q0, [x1, #96]

  // ----- K[7], rcon 64 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f020405                    // movi v5.4s, #64
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d801c20                    // str q0, [x1, #112]

  // ----- K[8], rcon 128 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f040405                    // movi v5.4s, #128
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d802020                    // str q0, [x1, #128]

  // ----- K[9], rcon 27 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000765                    // movi v5.4s, #27
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d802420                    // str q0, [x1, #144]

  // ----- K[10], rcon 54 -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f0106c5                    // movi v5.4s, #54
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d802820                    // str q0, [x1, #160]
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0xfd400801                    // ldr d1, [x0, #16]
  .long 0x3d800020                    // str q0, [x1]
  .long 0xfd000821                    // str d1, [x1, #16]

  // ----- W[6..11], rcon 1 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000425                    // movi v5.4s, #1
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c818020                    // stur q0, [x1, #24]
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0xfd001421                    // str d1, [x1, #40]

  // ----- W[12..17], rcon 2 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000445                    // movi v5.4s, #2
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c830020                    // stur q0, [x1, #48]
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0xfd002021                    // str d1, [x1, #64]

  // ----- W[18..23], rcon 4 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000485                    // movi v5.4s, #4
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c848020                    // stur q0, [x1, #72]
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0xfd002c21                    // str d1, [x1, #88]

  // ----- W[24..29], rcon 8 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000505                    // movi v5.4s, #8
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c860020                    // stur q0, [x1, #96]
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0xfd003821                    // str d1, [x1, #112]

  // ----- W[30..35], rcon 16 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000605                    // movi v5.4s, #16
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c878020                    // stur q0, [x1, #120]
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0xfd004421                    // str d1, [x1, #136]

  // ----- W[36..41], rcon 32 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f010405                    // movi v5.4s, #32
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c890020                    // stur q0, [x1, #144]
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0xfd005021                    // str d1, [x1, #160]

  // ----- W[42..47], rcon 64 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f020405                    // movi v5.4s, #64
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c8a8020                    // stur q0, [x1, #168]
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0xfd005c21                    // str d1, [x1, #184]

  // ----- W[48..51], rcon 128 -----
  .long 0x4e0c0422                    // dup v2.4s, v1.s[1]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f040405                    // movi v5.4s, #128
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3c8c0020                    // stur q0, [x1, #192]
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0x4f00e404                    // movi v4.16b, #0
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x3dc00401                    // ldr q1, [x0, #16]
  .long 0x3d800020                    // str q0, [x1]
  .long 0x3d800421                    // str q1, [x1, #16]

  // ----- K[2], rcon 1 -----
  .long 0x4e1c0422                    // dup v2.4s, v1.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000425                    // movi v5.4s, #1
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800820                    // str q0, [x1, #32]

  // ----- K[3], SubWord only -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e014083                    // ext v3.16b, v4.16b, v1.16b, #8
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x3d800c21                    // str q1, [x1, #48]

  // ----- K[4], rcon 2 -----
  .long 0x4e1c0422                    // dup v2.4s, v1.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000445                    // movi v5.4s, #2
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d801020                    // str q0, [x1, #64]

  // ----- K[5], SubWord only -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e014083                    // ext v3.16b, v4.16b, v1.16b, #8
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x3d801421                    // str q1, [x1, #80]

  // ----- K[6], rcon 4 -----
  .long 0x4e1c0422                    // dup v2.4s, v1.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000485                    // movi v5.4s, #4
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d801820                    // str q0, [x1, #96]

  // ----- K[7], SubWord only -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e014083                    // ext v3.16b, v4.16b, v1.16b, #8
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x3d801c21                    // str q1, [x1, #112]

  // ----- K[8], rcon 8 -----
  .long 0x4e1c0422                    // dup v2.4s, v1.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000505                    // movi v5.4s, #8
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d802020                    // str q0, [x1, #128]

  // ----- K[9], SubWord only -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e014083                    // ext v3.16b, v4.16b, v1.16b, #8
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x3d802421                    // str q1, [x1, #144]

  // ----- K[10], rcon 16 -----
  .long 0x4e1c0422                    // dup v2.4s, v1.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f000605                    // movi v5.4s, #16
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d802820                    // str q0, [x1, #160]

  // ----- K[11], SubWord only -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e014083                    // ext v3.16b, v4.16b, v1.16b, #8
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x3d802c21                    // str q1, [x1, #176]

  // ----- K[12], rcon 32 -----
  .long 0x4e1c0422                    // dup v2.4s, v1.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f010405                    // movi v5.4s, #32
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d803020                    // str q0, [x1, #192]

  // ----- K[13], SubWord only -----
  .long 0x4e1c0402                    // dup v2.4s, v0.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e016083                    // ext v3.16b, v4.16b, v1.16b, #12
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e014083                    // ext v3.16b, v4.16b, v1.16b, #8
  .long 0x6e231c21                    // eor v1.16b, v1.16b, v3.16b
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x3d803421                    // str q1, [x1, #208]

  // ----- K[14], rcon 64 -----
  .long 0x4e1c0422                    // dup v2.4s, v1.s[3]
  .long 0x4e284882                    // aese v2.16b, v4.16b
  .long 0x6e020842                    // ext v2.16b, v2.16b, v2.16b, #1
  .long 0x4f020405                    // movi v5.4s, #64
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x6e006083                    // ext v3.16b, v4.16b, v0.16b, #12
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e004083                    // ext v3.16b, v4.16b, v0.16b, #8
  .long 0x6e231c00                    // eor v0.16b, v0.16b, v3.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d803820                    // str q0, [x1, #224]
  ret
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
{$ENDIF}
