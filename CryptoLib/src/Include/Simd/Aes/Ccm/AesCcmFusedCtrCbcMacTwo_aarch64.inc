// CCM fused AES CryptoExt CTR+CBC-MAC kernel (aarch64), matching the
// two-lane chain in AesCcmFusedCtrCbcMacTwo_x86_64.inc.
// -------------------------------------------------------------------
// Two lanes (CTR / MAC) share each round: the extra aese fills pipeline
// slots that would otherwise idle behind the serial CBC-MAC chain
// (M_i <- E_K(M_{i-1} XOR P_i)), which is the structural source of the
// CCM speed-up; CCM is MAC-bound, so going wider than 2 lanes cannot
// help. The counter is kept LE-canonical in v6 (one byte-reverse per
// block via rev64 + ext #8; no shuffle mask needed on AArch64) and
// advanced with a 64-bit lane add of the increment constant. A 2x pair
// unroll issues three aese lanes per round (CTR_i, CTR_{i+1}, MAC)
// followed by a single-lane MAC chain for the second block; a
// single-block tail handles odd counts. Both directions consume the
// forward (encrypt) schedule. On decrypt the MAC lags the CTR lane by
// one block (cold-start block 0, trailing fold at the end).
//
// Variant selection:
//   CRYPTOLIB_CCM_DECRYPT  -> decrypt variant (MAC lags CTR by 1).
//   Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128 / KEY192 / KEY256
//                          selects N_R.
//
// On entry (after ClpSimdProc1Begin_aarch64.inc): x0 = PCtx.
// Context layout: see TCcmFusedTwoCtx in ClpAesCryptoExtCcmKernel.pas
// (identical to the x86_64 kernel's; PMask at +40 is unused on AArch64).
// BlockCount >= 1. OutPtr may alias InPtr.
//
// Register map: v0 CTR A, v1 MAC lane, v2/v3 data caches, v4 increment,
// v5 CTR B / prev-output stash, v6 LE canonical counter, v16..v(16+N_R)
// resident round keys; v8..v15 and x18+ untouched. GPR: x1 = InPtr,
// x2 = OutPtr, x3 = Keys, x4 = block countdown, x5 = state-pointer
// scratch.
//
// AArch64 vector/crypto instructions are .long-encoded for broad
// assembler compatibility.
{$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY128}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9401c04                    // ldr x4, [x0, #56]
  // x1 = InPtr, x2 = OutPtr, x3 = Keys, x4 = block countdown
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0x3dc0287a                    // ldr q26, [x3, #160]
  .long 0xf9400c05                    // ldr x5, [x0, #24]
  .long 0x3dc000a6                    // ldr q6, [x5]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  .long 0x3dc000a1                    // ldr q1, [x5]
  .long 0xf9401805                    // ldr x5, [x0, #48]
  .long 0x3dc000a4                    // ldr q4, [x5]
  // v6 = counter (BE) -> LE canonical, v1 = MAC state,
  // v4 = CTR increment
  .long 0x4e2008c6                    // rev64 v6.16b, v6.16b
  .long 0x6e0640c6                    // ext v6.16b, v6.16b, v6.16b, #8
{$IFDEF CRYPTOLIB_CCM_DECRYPT}

  // Pass 1: block 0 CTR-only cold start
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // stash prev output = out_0 in v5
  .long 0x4ea01c05                    // orr v5.16b, v0.16b, v0.16b
  add x1, x1, #16
  add x2, x2, #16
  sub x4, x4, #1
  cbz x4, .Laesce_ccmdec128_trail
  cmp x4, #2
  b.lo .Laesce_ccmdec128_stail
.Laesce_ccmdec128_pair:
  // load blocks i / i+1, fold prev output into the MAC lane
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x3dc00423                    // ldr q3, [x1, #16]
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  // stage CTR A (v0) / CTR B (v5, prev consumed above)
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4ea61cc5                    // orr v5.16b, v6.16b, v6.16b
  .long 0x4e2008a5                    // rev64 v5.16b, v5.16b
  .long 0x6e0540a5                    // ext v5.16b, v5.16b, v5.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  // 3-wide braid: CTR A, CTR B, MAC
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  // out_i (kept in v0 for the serial MAC fold)
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // out_{i+1} lands in v5 = the new prev output
  .long 0x6e231ca5                    // eor v5.16b, v5.16b, v3.16b
  .long 0x3d800445                    // str q5, [x2, #16]
  // serial MAC fold of out_i
  .long 0x6e201c21                    // eor v1.16b, v1.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  add x1, x1, #32
  add x2, x2, #32
  sub x4, x4, #2
  cmp x4, #2
  b.hs .Laesce_ccmdec128_pair
.Laesce_ccmdec128_stail:
  cbz x4, .Laesce_ccmdec128_trail
  // single-block 2-wide tail; v5 becomes this block's output
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ea01c05                    // orr v5.16b, v0.16b, v0.16b
.Laesce_ccmdec128_trail:
  // Pass 3: trailing MAC fold of the last output block
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b

{$ELSE}

  cmp x4, #2
  b.lo .Laesce_ccmenc128_tail
.Laesce_ccmenc128_pair:
  // stage CTR A (v0) / CTR B (v5); advance canonical counter
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4ea61cc5                    // orr v5.16b, v6.16b, v6.16b
  .long 0x4e2008a5                    // rev64 v5.16b, v5.16b
  .long 0x6e0540a5                    // ext v5.16b, v5.16b, v5.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  // load block i, fold into the MAC lane
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  // 3-wide braid: CTR A, CTR B, MAC
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1ca5                    // eor v5.16b, v5.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  // out_i = keystream_i XOR block_i
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // block i+1: out, then serial MAC fold
  .long 0x3dc00422                    // ldr q2, [x1, #16]
  .long 0x6e221ca5                    // eor v5.16b, v5.16b, v2.16b
  .long 0x3d800445                    // str q5, [x2, #16]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  add x1, x1, #32
  add x2, x2, #32
  sub x4, x4, #2
  cmp x4, #2
  b.hs .Laesce_ccmenc128_pair
.Laesce_ccmenc128_tail:
  cbz x4, .Laesce_ccmenc128_done
  // single-block 2-wide tail
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x6e3a1c00                    // eor v0.16b, v0.16b, v26.16b
  .long 0x6e3a1c21                    // eor v1.16b, v1.16b, v26.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
.Laesce_ccmenc128_done:

{$ENDIF}
  // flush: counter LE -> BE, write back counter + MAC state
  .long 0x4e2008c6                    // rev64 v6.16b, v6.16b
  .long 0x6e0640c6                    // ext v6.16b, v6.16b, v6.16b, #8
  .long 0xf9400c05                    // ldr x5, [x0, #24]
  .long 0x3d8000a6                    // str q6, [x5]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  .long 0x3d8000a1                    // str q1, [x5]
  ret
{$ELSE}
  {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY192}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9401c04                    // ldr x4, [x0, #56]
  // x1 = InPtr, x2 = OutPtr, x3 = Keys, x4 = block countdown
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0x3dc0307c                    // ldr q28, [x3, #192]
  .long 0xf9400c05                    // ldr x5, [x0, #24]
  .long 0x3dc000a6                    // ldr q6, [x5]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  .long 0x3dc000a1                    // ldr q1, [x5]
  .long 0xf9401805                    // ldr x5, [x0, #48]
  .long 0x3dc000a4                    // ldr q4, [x5]
  // v6 = counter (BE) -> LE canonical, v1 = MAC state,
  // v4 = CTR increment
  .long 0x4e2008c6                    // rev64 v6.16b, v6.16b
  .long 0x6e0640c6                    // ext v6.16b, v6.16b, v6.16b, #8
{$IFDEF CRYPTOLIB_CCM_DECRYPT}

  // Pass 1: block 0 CTR-only cold start
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // stash prev output = out_0 in v5
  .long 0x4ea01c05                    // orr v5.16b, v0.16b, v0.16b
  add x1, x1, #16
  add x2, x2, #16
  sub x4, x4, #1
  cbz x4, .Laesce_ccmdec192_trail
  cmp x4, #2
  b.lo .Laesce_ccmdec192_stail
.Laesce_ccmdec192_pair:
  // load blocks i / i+1, fold prev output into the MAC lane
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x3dc00423                    // ldr q3, [x1, #16]
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  // stage CTR A (v0) / CTR B (v5, prev consumed above)
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4ea61cc5                    // orr v5.16b, v6.16b, v6.16b
  .long 0x4e2008a5                    // rev64 v5.16b, v5.16b
  .long 0x6e0540a5                    // ext v5.16b, v5.16b, v5.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  // 3-wide braid: CTR A, CTR B, MAC
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  // out_i (kept in v0 for the serial MAC fold)
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // out_{i+1} lands in v5 = the new prev output
  .long 0x6e231ca5                    // eor v5.16b, v5.16b, v3.16b
  .long 0x3d800445                    // str q5, [x2, #16]
  // serial MAC fold of out_i
  .long 0x6e201c21                    // eor v1.16b, v1.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  add x1, x1, #32
  add x2, x2, #32
  sub x4, x4, #2
  cmp x4, #2
  b.hs .Laesce_ccmdec192_pair
.Laesce_ccmdec192_stail:
  cbz x4, .Laesce_ccmdec192_trail
  // single-block 2-wide tail; v5 becomes this block's output
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ea01c05                    // orr v5.16b, v0.16b, v0.16b
.Laesce_ccmdec192_trail:
  // Pass 3: trailing MAC fold of the last output block
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b

{$ELSE}

  cmp x4, #2
  b.lo .Laesce_ccmenc192_tail
.Laesce_ccmenc192_pair:
  // stage CTR A (v0) / CTR B (v5); advance canonical counter
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4ea61cc5                    // orr v5.16b, v6.16b, v6.16b
  .long 0x4e2008a5                    // rev64 v5.16b, v5.16b
  .long 0x6e0540a5                    // ext v5.16b, v5.16b, v5.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  // load block i, fold into the MAC lane
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  // 3-wide braid: CTR A, CTR B, MAC
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1ca5                    // eor v5.16b, v5.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  // out_i = keystream_i XOR block_i
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // block i+1: out, then serial MAC fold
  .long 0x3dc00422                    // ldr q2, [x1, #16]
  .long 0x6e221ca5                    // eor v5.16b, v5.16b, v2.16b
  .long 0x3d800445                    // str q5, [x2, #16]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  add x1, x1, #32
  add x2, x2, #32
  sub x4, x4, #2
  cmp x4, #2
  b.hs .Laesce_ccmenc192_pair
.Laesce_ccmenc192_tail:
  cbz x4, .Laesce_ccmenc192_done
  // single-block 2-wide tail
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x6e3c1c00                    // eor v0.16b, v0.16b, v28.16b
  .long 0x6e3c1c21                    // eor v1.16b, v1.16b, v28.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
.Laesce_ccmenc192_done:

{$ENDIF}
  // flush: counter LE -> BE, write back counter + MAC state
  .long 0x4e2008c6                    // rev64 v6.16b, v6.16b
  .long 0x6e0640c6                    // ext v6.16b, v6.16b, v6.16b, #8
  .long 0xf9400c05                    // ldr x5, [x0, #24]
  .long 0x3d8000a6                    // str q6, [x5]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  .long 0x3d8000a1                    // str q1, [x5]
  ret
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESCRYPTOEXT_KEY256}
  .long 0xf9400001                    // ldr x1, [x0]
  .long 0xf9400402                    // ldr x2, [x0, #8]
  .long 0xf9400803                    // ldr x3, [x0, #16]
  .long 0xf9401c04                    // ldr x4, [x0, #56]
  // x1 = InPtr, x2 = OutPtr, x3 = Keys, x4 = block countdown
  .long 0xad404470                    // ldp q16, q17, [x3]
  .long 0xad414c72                    // ldp q18, q19, [x3, #32]
  .long 0xad425474                    // ldp q20, q21, [x3, #64]
  .long 0xad435c76                    // ldp q22, q23, [x3, #96]
  .long 0xad446478                    // ldp q24, q25, [x3, #128]
  .long 0xad456c7a                    // ldp q26, q27, [x3, #160]
  .long 0xad46747c                    // ldp q28, q29, [x3, #192]
  .long 0x3dc0387e                    // ldr q30, [x3, #224]
  .long 0xf9400c05                    // ldr x5, [x0, #24]
  .long 0x3dc000a6                    // ldr q6, [x5]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  .long 0x3dc000a1                    // ldr q1, [x5]
  .long 0xf9401805                    // ldr x5, [x0, #48]
  .long 0x3dc000a4                    // ldr q4, [x5]
  // v6 = counter (BE) -> LE canonical, v1 = MAC state,
  // v4 = CTR increment
  .long 0x4e2008c6                    // rev64 v6.16b, v6.16b
  .long 0x6e0640c6                    // ext v6.16b, v6.16b, v6.16b, #8
{$IFDEF CRYPTOLIB_CCM_DECRYPT}

  // Pass 1: block 0 CTR-only cold start
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // stash prev output = out_0 in v5
  .long 0x4ea01c05                    // orr v5.16b, v0.16b, v0.16b
  add x1, x1, #16
  add x2, x2, #16
  sub x4, x4, #1
  cbz x4, .Laesce_ccmdec256_trail
  cmp x4, #2
  b.lo .Laesce_ccmdec256_stail
.Laesce_ccmdec256_pair:
  // load blocks i / i+1, fold prev output into the MAC lane
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x3dc00423                    // ldr q3, [x1, #16]
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  // stage CTR A (v0) / CTR B (v5, prev consumed above)
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4ea61cc5                    // orr v5.16b, v6.16b, v6.16b
  .long 0x4e2008a5                    // rev64 v5.16b, v5.16b
  .long 0x6e0540a5                    // ext v5.16b, v5.16b, v5.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  // 3-wide braid: CTR A, CTR B, MAC
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b85                    // aese v5.16b, v28.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba5                    // aese v5.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  // out_i (kept in v0 for the serial MAC fold)
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // out_{i+1} lands in v5 = the new prev output
  .long 0x6e231ca5                    // eor v5.16b, v5.16b, v3.16b
  .long 0x3d800445                    // str q5, [x2, #16]
  // serial MAC fold of out_i
  .long 0x6e201c21                    // eor v1.16b, v1.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  add x1, x1, #32
  add x2, x2, #32
  sub x4, x4, #2
  cmp x4, #2
  b.hs .Laesce_ccmdec256_pair
.Laesce_ccmdec256_stail:
  cbz x4, .Laesce_ccmdec256_trail
  // single-block 2-wide tail; v5 becomes this block's output
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  .long 0x4ea01c05                    // orr v5.16b, v0.16b, v0.16b
.Laesce_ccmdec256_trail:
  // Pass 3: trailing MAC fold of the last output block
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b

{$ELSE}

  cmp x4, #2
  b.lo .Laesce_ccmenc256_tail
.Laesce_ccmenc256_pair:
  // stage CTR A (v0) / CTR B (v5); advance canonical counter
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4ea61cc5                    // orr v5.16b, v6.16b, v6.16b
  .long 0x4e2008a5                    // rev64 v5.16b, v5.16b
  .long 0x6e0540a5                    // ext v5.16b, v5.16b, v5.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  // load block i, fold into the MAC lane
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  // 3-wide braid: CTR A, CTR B, MAC
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a05                    // aese v5.16b, v16.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a25                    // aese v5.16b, v17.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a45                    // aese v5.16b, v18.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a65                    // aese v5.16b, v19.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a85                    // aese v5.16b, v20.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa5                    // aese v5.16b, v21.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac5                    // aese v5.16b, v22.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae5                    // aese v5.16b, v23.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b05                    // aese v5.16b, v24.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b25                    // aese v5.16b, v25.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b45                    // aese v5.16b, v26.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b65                    // aese v5.16b, v27.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b85                    // aese v5.16b, v28.16b
  .long 0x4e2868a5                    // aesmc v5.16b, v5.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba5                    // aese v5.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1ca5                    // eor v5.16b, v5.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  // out_i = keystream_i XOR block_i
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
  // block i+1: out, then serial MAC fold
  .long 0x3dc00422                    // ldr q2, [x1, #16]
  .long 0x6e221ca5                    // eor v5.16b, v5.16b, v2.16b
  .long 0x3d800445                    // str q5, [x2, #16]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  add x1, x1, #32
  add x2, x2, #32
  sub x4, x4, #2
  cmp x4, #2
  b.hs .Laesce_ccmenc256_pair
.Laesce_ccmenc256_tail:
  cbz x4, .Laesce_ccmenc256_done
  // single-block 2-wide tail
  .long 0x3dc00022                    // ldr q2, [x1]
  .long 0x6e221c21                    // eor v1.16b, v1.16b, v2.16b
  .long 0x4ea61cc0                    // orr v0.16b, v6.16b, v6.16b
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x4ee484c6                    // add v6.2d, v6.2d, v4.2d
  .long 0x4e284a00                    // aese v0.16b, v16.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a01                    // aese v1.16b, v16.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a20                    // aese v0.16b, v17.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a21                    // aese v1.16b, v17.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a40                    // aese v0.16b, v18.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a41                    // aese v1.16b, v18.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a60                    // aese v0.16b, v19.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a61                    // aese v1.16b, v19.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284a80                    // aese v0.16b, v20.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284a81                    // aese v1.16b, v20.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284aa0                    // aese v0.16b, v21.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284aa1                    // aese v1.16b, v21.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ac0                    // aese v0.16b, v22.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ac1                    // aese v1.16b, v22.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ae0                    // aese v0.16b, v23.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284ae1                    // aese v1.16b, v23.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b00                    // aese v0.16b, v24.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b01                    // aese v1.16b, v24.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b20                    // aese v0.16b, v25.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b21                    // aese v1.16b, v25.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b40                    // aese v0.16b, v26.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b41                    // aese v1.16b, v26.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b60                    // aese v0.16b, v27.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b61                    // aese v1.16b, v27.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284b80                    // aese v0.16b, v28.16b
  .long 0x4e286800                    // aesmc v0.16b, v0.16b
  .long 0x4e284b81                    // aese v1.16b, v28.16b
  .long 0x4e286821                    // aesmc v1.16b, v1.16b
  .long 0x4e284ba0                    // aese v0.16b, v29.16b
  .long 0x4e284ba1                    // aese v1.16b, v29.16b
  .long 0x6e3e1c00                    // eor v0.16b, v0.16b, v30.16b
  .long 0x6e3e1c21                    // eor v1.16b, v1.16b, v30.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  .long 0x3d800040                    // str q0, [x2]
.Laesce_ccmenc256_done:

{$ENDIF}
  // flush: counter LE -> BE, write back counter + MAC state
  .long 0x4e2008c6                    // rev64 v6.16b, v6.16b
  .long 0x6e0640c6                    // ext v6.16b, v6.16b, v6.16b, #8
  .long 0xf9400c05                    // ldr x5, [x0, #24]
  .long 0x3d8000a6                    // str q6, [x5]
  .long 0xf9401005                    // ldr x5, [x0, #32]
  .long 0x3d8000a1                    // str q1, [x5]
  ret
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESCRYPTOEXT_KEY128, CRYPTOLIB_AESCRYPTOEXT_KEY192, CRYPTOLIB_AESCRYPTOEXT_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
