// SSE2 + PCLMULQDQ POLYVAL Horner-by-8 body (i386).
// -------------------------------------------------------------------
// RFC 8452 Appendix A identity:
//   POLYVAL(H, X_1..X_n) =
//     ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//                       ByteReverse(X_1), ..., ByteReverse(X_n)))
// lets this kernel delegate byte-for-byte to the 8-way Karatsuba GHASH
// Horner body (GcmGhashFull_i386.inc with GCM_GHASH_FULL_BLOCKS_8).
// POLYVAL's live set equals GHASH's, so the i386 8-xmm budget and its
// stack spills transfer unchanged.
//
// Caller preconditions (TGcmSivBlockCipher.DeriveKeys):
//   * PHPow128 holds H^8..H^1 in GHASH canonical form, precomputed
//     from the POLYVAL H via TGcmSivBlockCipher.FillReverse followed
//     by TGcmSivUtilities.MulX and fed through the standard
//     TGcmUtilities.InitEightWayHPowFromH (i.e.
//     mulX_GHASH(ByteReverse(H_polyval))).
//   * PFS (running hash state) is kept in GHASH canonical
//     (byte-reversed) form across calls.
//   * PC0 points to 128 bytes of plaintext in natural memory order;
//     the PSHUFB pair inside the delegated body supplies the POLYVAL
//     ByteReverse on load and the inverse on final store.
//
{$DEFINE GCM_GHASH_FULL_BLOCKS_8}
{$I ..\..\..\Include\Simd\Gcm\GcmGhashFull_i386.inc}
{$UNDEF GCM_GHASH_FULL_BLOCKS_8}
