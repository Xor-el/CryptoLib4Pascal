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

unit ClpFpVarBaseVerifier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpNat,
  ClpWNafUtilities,
  ClpIFpFieldOps,
  ClpIECFieldElement,
  ClpIECCommon,
  ClpIECVarBaseVerifier,
  ClpCTFieldValue,
  ClpCTFieldArith,
  ClpCTJacPoint,
  ClpCryptoLibTypes;

type
  /// <summary>Builds the per-curve <see cref="IFpFieldOps"/> for a verifier lazily
  /// from the point's curve.</summary>
  TFpFieldOpsFactory = function(const ACurve: IECCurve): IFpFieldOps;

  /// <summary>
  /// Variable-time double-scalar multiply AU1*AP + AU2*AQ re-hosted onto the fast
  /// value-type Montgomery field. Interleaved width-w wNAF. Public inputs only -
  /// reached only from <c>SumOfTwoMultiplies</c>, never a secret-scalar path - so it
  /// runs the faster incomplete-Jacobian group law from <c>TCTJacPoint&lt;TOps&gt;</c>;
  /// its masked-infinity completion plus the P=Q detect-and-double backstop discharge
  /// the identity, P=Q and P=-Q joins (H=0 => Z3=0 gives P=-Q for free), so no vartime
  /// exceptional-case wrapper is needed.
  /// </summary>
  TFpVarBaseVerifier<TOps: TCTFieldArithBase> = class sealed(TInterfacedObject, IECVarBaseVerifier)
  strict private
  const
    WINDOW = Int32(5);
    TABLE_SIZE = Int32(1 shl (WINDOW - 2)); // odd multiples 1,3,..,2^(w-1)-1
  var
    FFactory: TFpFieldOpsFactory;
    FFieldOps: IFpFieldOps;
    function GetFieldOps(const ACurve: IECCurve): IFpFieldOps;
    procedure NegateY(var AP: TFePoint);
    procedure BuildOddMultiples(const AFieldOps: IFpFieldOps;
      const AXa, AYa: TCryptoLibUInt32Array; var ATable: array of TFePoint);
  public
    constructor Create(AFactory: TFpFieldOpsFactory);
    function SumOfTwoMultiplies(const AP: IECPoint; const AU1: TBigInteger;
      const AQ: IECPoint; const AU2: TBigInteger): IECPoint;
  end;

implementation

{ TFpVarBaseVerifier<TOps> }

constructor TFpVarBaseVerifier<TOps>.Create(AFactory: TFpFieldOpsFactory);
begin
  inherited Create;
  FFactory := AFactory;
end;

function TFpVarBaseVerifier<TOps>.GetFieldOps(const ACurve: IECCurve): IFpFieldOps;
begin
  // Idempotent lazy build (a benign concurrent double-build yields equal ops).
  if FFieldOps = nil then
    FFieldOps := FFactory(ACurve);
  Result := FFieldOps;
end;

procedure TFpVarBaseVerifier<TOps>.NegateY(var AP: TFePoint);
var
  LZero: TFe;
begin
  FillChar(LZero, SizeOf(LZero), 0);
  TOps.Sub(LZero, AP.Y, AP.Y); // Y := (0 - Y) mod p = -Y (Montgomery domain)
end;

procedure TFpVarBaseVerifier<TOps>.BuildOddMultiples(const AFieldOps: IFpFieldOps;
  const AXa, AYa: TCryptoLibUInt32Array; var ATable: array of TFePoint);
var
  LTwo: TFePoint;
  LI: Int32;
begin
  TCTJacPoint<TOps>.FromAffine(AFieldOps, AXa, AYa, ATable[0]); // 1*P (Z = MontOne)
  TCTJacPoint<TOps>.PointDouble(ATable[0], LTwo);               // 2*P
  for LI := 1 to TABLE_SIZE - 1 do
    TCTJacPoint<TOps>.PointAdd(ATable[LI - 1], LTwo, ATable[LI]); // (2i+1)*P
  FillChar(LTwo, SizeOf(LTwo), 0);
end;

function TFpVarBaseVerifier<TOps>.SumOfTwoMultiplies(const AP: IECPoint;
  const AU1: TBigInteger; const AQ: IECPoint; const AU2: TBigInteger): IECPoint;
var
  LFieldOps: IFpFieldOps;
  LCurve: IECCurve;
  LFieldInts, LLen, LLenP, LLenQ, LI, LWiP, LWiQ, LIdx: Int32;
  LTableP, LTableQ: array of TFePoint;
  LAcc, LAdd: TFePoint;
  LXa, LYa, LPx, LPy, LQx, LQy: TCryptoLibUInt32Array;
  LWnafP, LWnafQ: TCryptoLibByteArray;
  LPn, LQn: IECPoint;
  LIsInfinity: Boolean;
  LXfe, LYfe: IECFieldElement;
begin
  LCurve := AP.Curve;
  LFieldOps := GetFieldOps(LCurve);
  LFieldInts := LFieldOps.GetFieldInts;

  // affine coordinates of the (public) input points, normal domain
  LPn := AP.Normalize();
  LQn := AQ.Normalize();
  LPx := TNat.Create(LFieldInts);
  LPy := TNat.Create(LFieldInts);
  LQx := TNat.Create(LFieldInts);
  LQy := TNat.Create(LFieldInts);
  LFieldOps.FieldFromBigInteger(LPn.AffineXCoord.ToBigInteger(), LPx);
  LFieldOps.FieldFromBigInteger(LPn.AffineYCoord.ToBigInteger(), LPy);
  LFieldOps.FieldFromBigInteger(LQn.AffineXCoord.ToBigInteger(), LQx);
  LFieldOps.FieldFromBigInteger(LQn.AffineYCoord.ToBigInteger(), LQy);

  SetLength(LTableP, TABLE_SIZE);
  SetLength(LTableQ, TABLE_SIZE);
  BuildOddMultiples(LFieldOps, LPx, LPy, LTableP);
  BuildOddMultiples(LFieldOps, LQx, LQy, LTableQ);

  LWnafP := TWNafUtilities.GenerateWindowNaf(WINDOW, AU1);
  LWnafQ := TWNafUtilities.GenerateWindowNaf(WINDOW, AU2);
  LLenP := Length(LWnafP);
  LLenQ := Length(LWnafQ);
  if LLenP > LLenQ then
    LLen := LLenP
  else
    LLen := LLenQ;

  TCTJacPoint<TOps>.Infinity(LFieldOps, LAcc);
  LI := LLen;
  while LI > 0 do
  begin
    Dec(LI);
    TCTJacPoint<TOps>.PointDouble(LAcc, LAcc);

    if LI < LLenP then
      LWiP := Int32(ShortInt(LWnafP[LI]))
    else
      LWiP := 0;
    if LI < LLenQ then
      LWiQ := Int32(ShortInt(LWnafQ[LI]))
    else
      LWiQ := 0;

    if LWiP <> 0 then
    begin
      LIdx := Abs(LWiP) shr 1;
      LAdd := LTableP[LIdx];
      if LWiP < 0 then
        NegateY(LAdd);
      TCTJacPoint<TOps>.PointAdd(LAcc, LAdd, LAcc);
    end;
    if LWiQ <> 0 then
    begin
      LIdx := Abs(LWiQ) shr 1;
      LAdd := LTableQ[LIdx];
      if LWiQ < 0 then
        NegateY(LAdd);
      TCTJacPoint<TOps>.PointAdd(LAcc, LAdd, LAcc);
    end;
  end;

  LXa := TNat.Create(LFieldInts);
  LYa := TNat.Create(LFieldInts);
  TCTJacPoint<TOps>.ToAffine(LFieldOps, LAcc, LXa, LYa, LIsInfinity);
  if LIsInfinity then
  begin
    Result := LCurve.Infinity;
    Exit;
  end;

  // Box through the curve's own field so the result is valid on ANY curve that
  // shares this prime (the generic TFpCurve as well as the custom curve) - the
  // order-keyed registry can hand us either for the same group order.
  LXfe := LCurve.FromBigInteger(LFieldOps.CreateFieldElement(LXa).ToBigInteger());
  LYfe := LCurve.FromBigInteger(LFieldOps.CreateFieldElement(LYa).ToBigInteger());
  Result := LCurve.CreateRawPoint(LXfe, LYfe);
end;

end.
