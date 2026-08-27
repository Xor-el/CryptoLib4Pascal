{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCTFieldValue;

{$I ..\..\..\Include\CryptoLib.inc}

interface

const
  /// <summary>Widest field this value-type layer serves. P-521's 17 real uint32
  /// limbs are padded to 18 (= 9 uint64) so the even-width Fp kernel can multiply
  /// it; the 18th limb is kept zero. Smaller curves use W[0..N-1] and leave the
  /// tail zero.</summary>
  MAX_CT_FE_LIMBS = 18;

type
  /// <summary>
  /// One prime-field element as a fixed-size, allocation-free stack record (the
  /// same little-endian 32-bit-limb representation as the heap arrays, just
  /// inline). Sized for the widest curve; a given curve uses W[0..N-1]. Passed
  /// <c>const</c>/<c>var</c> only — never returned by value on a secret-bearing
  /// path (a by-value copy scatters unscrubbable secrets on the stack).
  /// </summary>
  TFe = record
    W: array [0 .. MAX_CT_FE_LIMBS - 1] of UInt32;
  end;

  /// <summary>
  /// Double-width (2N) multiply/square scratch, stack-resident. Reused across a
  /// whole point formula rather than allocated per field op.
  /// </summary>
  TFeExt = record
    W: array [0 .. 2 * MAX_CT_FE_LIMBS - 1] of UInt32;
  end;

  /// <summary>
  /// A point in homogeneous projective coordinates with inline field-element
  /// coordinates (no heap). Value aggregate over three <see cref="TFe"/>.
  /// </summary>
  TFePoint = record
    X, Y, Z: TFe;
  end;

  /// <summary>
  /// An affine point (Montgomery-domain X,Y, implicit Z=1) as an inline value
  /// aggregate. The flat per-window entries of the fixed-base affine comb table
  /// are stored as these; the mixed addition supplies the unit Z.
  /// </summary>
  TFeAffine = record
    X, Y: TFe;
  end;

  /// <summary>
  /// Output of a fused incomplete-Jacobian addition: the masked-infinity-completed
  /// sum <c>R</c> plus the two predicate operands <c>H</c> (= U2-U1) and <c>RS</c>
  /// (= S2-S1). The layout is pinned (R.X/Y/Z at +0/+72/+144, H at +216, RS at
  /// +288) so the generated kernel can write it by fixed offset; the wrapper reads
  /// H/RS to drive the P=Q detect-and-double.
  /// </summary>
  TJacAddScratch = record
    R: TFePoint;
    H, RS: TFe;
  end;

implementation

end.
