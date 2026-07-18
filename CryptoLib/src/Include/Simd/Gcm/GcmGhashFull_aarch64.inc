// PMULL N-way GHASH batch kernel (aarch64).
// -------------------------------------------------------------------
// Loops over ABatchCount batches inside the asm body. Per batch: for each
// block loads the (byte-reversed) data, XORs the running state into
// block 0, multiplies by the matching H power via four PMULL products,
// accumulates across blocks into three 128-bit limbs Z0/Z1/Z2, then folds
// Z1 and reduces with two carry-less multiplies by the folded constant
// 0xC2000000_00000000 (PHPow holds the powers PRE-MULTIPLIED BY x in the
// reflected representation - see TGcmUtilities.InitEightWayHPowFromH - so
// no bit-shift correction is needed). The running state stays reflected
// across batches; the canonical byte order is only touched at entry/exit
// (rev64 + half swap - no shuffle mask needed on AArch64), and the
// reduction constant is built once per call.
//
// Variant selection (set EXACTLY ONE of the block counts):
//   GCM_GHASH_FULL_BLOCKS_4  -> 4-block (64-byte) batches, H^4..H^1.
//   GCM_GHASH_FULL_BLOCKS_8  -> 8-block (128-byte) batches, H^8..H^1.
// Optional:
//   GCM_GHASH_RAW_INPUT      -> the data blocks are already in field form, so
//                              skip the per-block input byte-reverse. Used by the
//                              GCM-SIV POLYVAL kernel, which supplies raw blocks;
//                              the running-state load and the final store are
//                              still byte-reversed. Unset for GCM (canonical
//                              input), leaving that path byte-identical.
//
// On entry (after ClpSimdProc4Begin_aarch64.inc):
//   x0 = PFS    (16-byte running GHASH state, canonical; in/out)
//   x1 = PC0    (data blocks; canonical, or field form with RAW_INPUT; advances)
//   x2 = PHPow  (H^N..H^1 as 16-byte limbs, x-pre-multiplied)
//   x3 = ABatchCount (> 0)
//
// Register map: v0/v1/v2 = Z0/Z1/Z2 accumulators (v0 doubles as the
// reflected running state carried across batches), v3 = data block,
// v4 = H-power limb, v5 = halves-swap scratch, v6 = product scratch,
// v7 = zero, v16 = reduction constant; x5 GPR scratch. v8..v15 untouched.
//
// AArch64 vector/crypto instructions are .long-encoded for broad assembler
// compatibility.
{$IFDEF GCM_GHASH_FULL_BLOCKS_4}
  .long 0xd2f84005                    // movz x5, #0xc200, lsl #48
  .long 0x4f00e410                    // movi v16.16b, #0
  .long 0x4e081cb0                    // ins v16.d[0], x5
  .long 0x4f00e407                    // movi v7.16b, #0
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
.Lghash4_batch_loop:
  .long 0x3dc00023                    // ldr q3, [x1]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x3dc00044                    // ldr q4, [x2]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e060                    // pmull v0.1q, v3.1d, v4.1d
  .long 0x4ee4e062                    // pmull2 v2.1q, v3.2d, v4.2d
  .long 0x0ee4e0a1                    // pmull v1.1q, v5.1d, v4.1d
  .long 0x4ee4e0a5                    // pmull2 v5.1q, v5.2d, v4.2d
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x3dc00423                    // ldr q3, [x1, #16]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc00444                    // ldr q4, [x2, #16]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc00823                    // ldr q3, [x1, #32]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc00844                    // ldr q4, [x2, #32]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc00c44                    // ldr q4, [x2, #48]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x6e0140e5                    // ext v5.16b, v7.16b, v1.16b, #8
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e074025                    // ext v5.16b, v1.16b, v7.16b, #8
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x0ef0e005                    // pmull v5.1q, v0.1d, v16.1d
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x0ef0e005                    // pmull v5.1q, v0.1d, v16.1d
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  add x1, x1, #64
  sub x3, x3, #1
  cbnz x3, .Lghash4_batch_loop
  .long 0x4ea01c03                    // orr v3.16b, v0.16b, v0.16b
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
  .long 0x3d800003                    // str q3, [x0]
  ret
{$ELSE}
  {$IFDEF GCM_GHASH_FULL_BLOCKS_8}
  .long 0xd2f84005                    // movz x5, #0xc200, lsl #48
  .long 0x4f00e410                    // movi v16.16b, #0
  .long 0x4e081cb0                    // ins v16.d[0], x5
  .long 0x4f00e407                    // movi v7.16b, #0
  .long 0x3dc00000                    // ldr q0, [x0]
  .long 0x4e200800                    // rev64 v0.16b, v0.16b
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
.Lghash8_batch_loop:
  .long 0x3dc00023                    // ldr q3, [x1]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x6e201c63                    // eor v3.16b, v3.16b, v0.16b
  .long 0x3dc00044                    // ldr q4, [x2]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e060                    // pmull v0.1q, v3.1d, v4.1d
  .long 0x4ee4e062                    // pmull2 v2.1q, v3.2d, v4.2d
  .long 0x0ee4e0a1                    // pmull v1.1q, v5.1d, v4.1d
  .long 0x4ee4e0a5                    // pmull2 v5.1q, v5.2d, v4.2d
  .long 0x6e251c21                    // eor v1.16b, v1.16b, v5.16b
  .long 0x3dc00423                    // ldr q3, [x1, #16]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc00444                    // ldr q4, [x2, #16]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc00823                    // ldr q3, [x1, #32]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc00844                    // ldr q4, [x2, #32]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc00c23                    // ldr q3, [x1, #48]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc00c44                    // ldr q4, [x2, #48]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc01023                    // ldr q3, [x1, #64]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc01044                    // ldr q4, [x2, #64]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc01423                    // ldr q3, [x1, #80]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc01444                    // ldr q4, [x2, #80]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc01823                    // ldr q3, [x1, #96]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc01844                    // ldr q4, [x2, #96]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x3dc01c23                    // ldr q3, [x1, #112]
{$IFNDEF GCM_GHASH_RAW_INPUT}
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
{$ENDIF}
  .long 0x3dc01c44                    // ldr q4, [x2, #112]
  .long 0x6e034065                    // ext v5.16b, v3.16b, v3.16b, #8
  .long 0x0ee4e066                    // pmull v6.1q, v3.1d, v4.1d
  .long 0x6e261c00                    // eor v0.16b, v0.16b, v6.16b
  .long 0x4ee4e066                    // pmull2 v6.1q, v3.2d, v4.2d
  .long 0x6e261c42                    // eor v2.16b, v2.16b, v6.16b
  .long 0x0ee4e0a6                    // pmull v6.1q, v5.1d, v4.1d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x4ee4e0a6                    // pmull2 v6.1q, v5.2d, v4.2d
  .long 0x6e261c21                    // eor v1.16b, v1.16b, v6.16b
  .long 0x6e0140e5                    // ext v5.16b, v7.16b, v1.16b, #8
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e074025                    // ext v5.16b, v1.16b, v7.16b, #8
  .long 0x6e251c42                    // eor v2.16b, v2.16b, v5.16b
  .long 0x0ef0e005                    // pmull v5.1q, v0.1d, v16.1d
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x0ef0e005                    // pmull v5.1q, v0.1d, v16.1d
  .long 0x6e004000                    // ext v0.16b, v0.16b, v0.16b, #8
  .long 0x6e251c00                    // eor v0.16b, v0.16b, v5.16b
  .long 0x6e221c00                    // eor v0.16b, v0.16b, v2.16b
  add x1, x1, #128
  sub x3, x3, #1
  cbnz x3, .Lghash8_batch_loop
  .long 0x4ea01c03                    // orr v3.16b, v0.16b, v0.16b
  .long 0x4e200863                    // rev64 v3.16b, v3.16b
  .long 0x6e034063                    // ext v3.16b, v3.16b, v3.16b, #8
  .long 0x3d800003                    // str q3, [x0]
  ret
  {$ELSE}
  {$FATAL Exactly one of GCM_GHASH_FULL_BLOCKS_4, GCM_GHASH_FULL_BLOCKS_8 must be defined before including this file}
  {$ENDIF}
{$ENDIF}
