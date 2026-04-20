// POLYVAL Horner-by-8 body (RFC 8452 section 3 / section 6), i386.
//
// Implementation: RFC 8452 Appendix A identity
//
//   POLYVAL(H, X_1..X_n) = ByteReverse(GHASH(mulX_GHASH(ByteReverse(H)),
//                                            ByteReverse(X_1), ...,
//                                            ByteReverse(X_n)))
//
// lets this kernel delegate byte-for-byte to the existing 8-way Karatsuba
// GHASH Horner body (GcmGhashFull_i386.inc with GCM_GHASH_FULL_BLOCKS_8).
//
// Preconditions the caller (TGcmSivUtilities / TGcmSivBlockCipher) has
// already met so the delegation is valid:
//
//   * PHPow128 holds H^8..H^1 in GHASH canonical form, precomputed from the
//     POLYVAL H via TGcmSivUtilities.InitEightWayHPowFromHPolyval (which is
//     just MulX(FillReverse(H_polyval)) fed through
//     TGcmUtilities.InitEightWayHPowFromH -- i.e. the mulX_GHASH(ByteReverse)
//     conditioning the identity requires).
//
//   * PFS (running hash state) is kept in GHASH canonical (byte-reversed)
//     form across calls -- the same convention TGcmSivBlockCipher.FTheGHash
//     already maintained for the scalar path.
//
//   * PC0 points to 128 bytes of plaintext in natural memory order; the
//     PSHUFB pair inside the delegated body supplies the POLYVAL-side
//     ByteReverse on load and the inverse on final store.
//
// Under those preconditions the delegated body produces exactly the
// POLYVAL Horner-by-8 fold the caller expects, with no new assembly and
// no correctness risk (the body is the same one GCM's fused kernel uses
// in production).
//
// i386 note: the delegated i386 body spills through the stack for its
// Horner intermediates (only 8 xmm are available); POLYVAL's live set is
// identical to GHASH's so nothing in this identity changes the xmm
// pressure calculus.
//
{$DEFINE GCM_GHASH_FULL_BLOCKS_8}
{$I ..\..\..\Include\Simd\Gcm\GcmGhashFull_i386.inc}
{$UNDEF GCM_GHASH_FULL_BLOCKS_8}
