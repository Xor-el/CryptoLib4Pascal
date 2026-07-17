// PMULL POLYVAL Horner-by-8 body (aarch64).
// -------------------------------------------------------------------
// RFC 8452 Appendix A identity:
//   POLYVAL(H, X_1..X_n) =
//     ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//                       ByteReverse(X_1), ..., ByteReverse(X_n)))
// lets this kernel delegate byte-for-byte to the 8-way GHASH Horner
// body (GcmGhashFull_aarch64.inc with GCM_GHASH_FULL_BLOCKS_8).
//
// Caller preconditions (TGcmSivBlockCipher.DeriveKeys):
//   * PHPow128 holds H^8..H^1 in GHASH canonical form, precomputed
//     from the POLYVAL H via TGcmSivBlockCipher.FillReverse followed
//     by TGcmSivUtilities.MulX and fed through the standard
//     TGcmUtilities.InitEightWayHPowFromH (i.e.
//     mulX_GHASH(ByteReverse(H_polyval))).
//   * PFS (running hash state) is kept in GHASH canonical
//     (byte-reversed) form across calls.
//   * PC0 points to 128 bytes of data blocks in natural memory order. The kernel
//     folds them to the same field element the scalar POLYVAL path does: the
//     scalar path byte-reverses each block (FillReverse) before the GHASH
//     multiply, and the kernel reaches the identical operand by consuming the
//     raw block with the per-block input byte-reverse skipped
//     (GCM_GHASH_RAW_INPUT). The running-state load and final store stay
//     byte-reversed via rev64 + ext (no shuffle mask on AArch64, so there is
//     no PMask argument).
//
// The delegated body touches only caller-saved registers, so no save frame
// is inherited; this shell adds no asm of its own.
{$DEFINE GCM_GHASH_FULL_BLOCKS_8}
{$DEFINE GCM_GHASH_RAW_INPUT}
{$I ..\..\Include\Simd\Gcm\GcmGhashFull_aarch64.inc}
{$UNDEF GCM_GHASH_RAW_INPUT}
{$UNDEF GCM_GHASH_FULL_BLOCKS_8}
