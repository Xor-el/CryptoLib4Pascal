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

unit ClpFpCombMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpNat,
  ClpBitOperations,
  ClpMultipliers,
  ClpFixedPointUtilities,
  ClpIFixedPointPreCompInfo,
  ClpIFpFieldOps,
  ClpIECFieldElement,
  ClpIECCommon,
  ClpCTFieldValue,
  ClpCTFieldArith,
  ClpCTPoint,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SFixedPointCombNotSupported =
    'fixed-point comb doesn''t support scalars larger than the curve order';

type
  /// <summary>
  /// Value-type constant-time fixed-base (comb) multiplier for Fp short-Weierstrass
  /// curves. Same comb structure, recoding and masked table lookup as the
  /// array-based <c>TFixedPointCombMultiplier</c>, but the per-column point
  /// arithmetic runs over stack <see cref="TFePoint"/> records via the RCB complete
  /// formulas (<c>TCTPoint&lt;TOps&gt;</c>) - no per-operation heap allocation.
  /// The precomputed generator table (public) is reused via
  /// <c>TFixedPointUtilities</c>; only the online phase touches the secret scalar.
  /// </summary>
  TFpCombMultiplier<TOps: TCTFieldArithBase> = class sealed(TAbstractECMultiplier,
    IECMultiplier)
  strict private
    FFieldOps: IFpFieldOps;
    FCachedInfo: IFixedPointPreCompInfo;
    FTable: TCryptoLibGenericArray<TFePoint>;
    FOffset: TFePoint;
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  public
    constructor Create(const AFieldOps: IFpFieldOps);
  end;

implementation

{ TFpCombMultiplier<TOps> }

constructor TFpCombMultiplier<TOps>.Create(const AFieldOps: IFpFieldOps);
begin
  Inherited Create;
  FFieldOps := AFieldOps;
end;

function TFpCombMultiplier<TOps>.MultiplyPositive(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
var
  LC: IECCurve;
  LSize, LWidth, LD, LFullComb, LN, LI, LJ: Int32;
  LInfo: IFixedPointPreCompInfo;
  LLookup: IECLookupTable;
  LR, LSel: TFePoint;
  LK, LXa, LYa: TCryptoLibUInt32Array;
  LSecretIndex, LSecretBit: UInt32;
  LIsInfinity: Boolean;
  LAff: IECPoint;
begin
  LC := AP.Curve;
  LSize := TFixedPointUtilities.GetCombSize(LC);

  if AK.BitLength > LSize then
    raise EInvalidOperationCryptoLibException.CreateRes(@SFixedPointCombNotSupported);

  LInfo := TFixedPointUtilities.Precompute(AP);
  LWidth := LInfo.Width;
  LD := (LSize + LWidth - 1) div LWidth;
  LFullComb := LD * LWidth;

  if LInfo <> FCachedInfo then
  begin
    // Build the value-type table once per base point. The precomp info is cached
    // on the point, so this rebuilds only when the base point changes (never for
    // the reused generator). LookupVar is fine - the table contents are public;
    // only the online index is secret.
    LLookup := LInfo.LookupTable;
    LN := LLookup.GetSize;
    SetLength(FTable, LN);
    for LI := 0 to LN - 1 do
    begin
      LAff := LLookup.LookupVar(LI);
      TCTPoint<TOps>.FromAffineElt(FFieldOps, LAff.RawXCoord, LAff.RawYCoord, FTable[LI]);
    end;
    LAff := LInfo.Offset.Normalize();
    TCTPoint<TOps>.FromAffineElt(FFieldOps, LAff.AffineXCoord, LAff.AffineYCoord, FOffset);
    FCachedInfo := LInfo;
  end;
  LN := System.Length(FTable);

  LK := TNat.FromBigInteger(LFullComb, AK);

  TCTPoint<TOps>.Infinity(FFieldOps, LR);
  for LI := 1 to LD do
  begin
    LSecretIndex := 0;

    LJ := LFullComb - LI;
    while LJ >= 0 do
    begin
      LSecretBit := LK[TBitOperations.Asr32(LJ, 5)] shr (LJ and $1F);
      LSecretIndex := LSecretIndex xor (LSecretBit shr 1);
      LSecretIndex := LSecretIndex shl 1;
      LSecretIndex := LSecretIndex xor LSecretBit;
      LJ := LJ - LD;
    end;

    TCTPoint<TOps>.SelectEntry(FFieldOps, FTable, LN, Int32(LSecretIndex), LSel);
    // R := 2*R + Sel
    TCTPoint<TOps>.PointDouble(LR, LR);
    TCTPoint<TOps>.PointAdd(LR, LSel, LR);
  end;

  // R := R + Offset
  TCTPoint<TOps>.PointAdd(LR, FOffset, LR);

  LXa := TNat.Create(FFieldOps.GetFieldInts);
  LYa := TNat.Create(FFieldOps.GetFieldInts);
  TCTPoint<TOps>.ToAffine(FFieldOps, LR, LXa, LYa, LIsInfinity);
  if LIsInfinity then
    Exit(AP.Curve.Infinity);

  Result := AP.Curve.CreateRawPoint(FFieldOps.CreateFieldElement(LXa),
    FFieldOps.CreateFieldElement(LYa));
end;

end.
