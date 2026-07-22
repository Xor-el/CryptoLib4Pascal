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

unit ClpF2mMontgomeryLadderCTMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpNat,
  ClpPack,
  ClpMultipliers,
  ClpIF2mFieldOps,
  ClpLopezDahabLadder,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIECFieldElement,
  ClpIECCommon,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

type
  /// <summary>
  /// Constant-time single-scalar variable-point multiplier for binary (GF(2^m))
  /// curves — a plain López–Dahab Montgomery ladder (x-only), with a branch-free
  /// conditional swap, a batched single field inversion for y-recovery, scalar
  /// blinding by the group cardinality, independent randomized projective
  /// coordinates, and a fixed processing length.
  /// </summary>
  TF2mMontgomeryLadderCTMultiplier = class sealed(TAbstractECMultiplier, IECMultiplier)
  strict private
  const
    BLIND_BITS = Int32(64);
  var
    FFieldOps: IF2mFieldOps;
    FRandom: ISecureRandom;
    function GetRandom: ISecureRandom;
    procedure GenerateBlind(const ARandom: ISecureRandom; const AZ: TCryptoLibUInt32Array);
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  public
    constructor Create(const AFieldOps: IF2mFieldOps); overload;
    constructor Create(const AFieldOps: IF2mFieldOps; const ARandom: ISecureRandom); overload;
  end;

implementation

resourcestring
  SPointNotOnCurve = 'point is not a valid subgroup point for constant-time multiplication';

{ TF2mMontgomeryLadderCTMultiplier }

constructor TF2mMontgomeryLadderCTMultiplier.Create(const AFieldOps: IF2mFieldOps);
begin
  Inherited Create;
  FFieldOps := AFieldOps;
end;

constructor TF2mMontgomeryLadderCTMultiplier.Create(const AFieldOps: IF2mFieldOps;
  const ARandom: ISecureRandom);
begin
  Inherited Create;
  FFieldOps := AFieldOps;
  FRandom := ARandom;
end;

function TF2mMontgomeryLadderCTMultiplier.GetRandom: ISecureRandom;
begin
  if FRandom = nil then
    FRandom := TSecureRandom.Create() as ISecureRandom;
  Result := FRandom;
end;

procedure TF2mMontgomeryLadderCTMultiplier.GenerateBlind(const ARandom: ISecureRandom;
  const AZ: TCryptoLibUInt32Array);
var
  LBytes: TCryptoLibByteArray;
begin
  System.SetLength(LBytes, BLIND_BITS div 8);
  ARandom.NextBytes(LBytes);
  TPack.LE_To_UInt32(LBytes, 0, AZ, 0, BLIND_BITS div 32);
end;

function TF2mMontgomeryLadderCTMultiplier.MultiplyPositive(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
var
  LN, LScalarBits, LScalarInts, LI, LKbit, LPbit: Int32;
  LRandom: ISecureRandom;
  LAffine: IECPoint;
  LBaseX, LBaseY, LLambda1, LLambda2, LXOut, LLOut: TCryptoLibUInt64Array;
  LCard, LR, LProd, LK, LKPrime: TCryptoLibUInt32Array;
  LQ1, LQ2: TLDPoint;
  LIsInfinity: Boolean;
  LXfe, LLfe: IECFieldElement;
begin
  if not AP.IsValid then
    raise EInvalidOperationCryptoLibException.CreateRes(@SPointNotOnCurve);

  LN := FFieldOps.GetFieldLongs;
  LRandom := GetRandom;

  // --- affine coordinates of the (public) input point ---
  LAffine := AP.Normalize();
  LBaseX := TNat.Create64(LN);
  LBaseY := TNat.Create64(LN);
  FFieldOps.FieldFromBigInteger(LAffine.AffineXCoord.ToBigInteger(), LBaseX);
  FFieldOps.FieldFromBigInteger(LAffine.AffineYCoord.ToBigInteger(), LBaseY);
  // defensive: x = 0 is the 2-torsion point, not in the odd-order subgroup
  if FFieldOps.IsZeroMask(LBaseX) <> 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SPointNotOnCurve);

  // --- scalar blinding by the cardinality: k' = k + r*(h*n) ---
  LScalarBits := FFieldOps.GetCardinalityBits + BLIND_BITS + 1;
  LScalarInts := TNat.GetLengthForBits(LScalarBits) + 1;
  LCard := TNat.Create(LScalarInts);
  LR := TNat.Create(LScalarInts);
  LProd := TNat.Create(LScalarInts * 2);
  FFieldOps.GetCardinality(LCard, LScalarInts);
  GenerateBlind(LRandom, LR);
  TNat.Mul(LScalarInts, LR, LCard, LProd);
  LK := TNat.FromBigInteger(LScalarInts * 32, AK);
  LKPrime := TNat.Create(LScalarInts);
  TNat.Add(LScalarInts, LK, LProd, LKPrime);

  try
    // --- randomized projective init: Q1 = infinity = (lambda1 : 0), Q2 = P = (lambda2*x : lambda2) ---
    LLambda1 := TNat.Create64(LN);
    LLambda2 := TNat.Create64(LN);
    FFieldOps.RandomNonZero(LRandom, LLambda1);
    FFieldOps.RandomNonZero(LRandom, LLambda2);

    LQ1.X := TNat.Create64(LN); LQ1.Z := TNat.Create64(LN);
    LQ2.X := TNat.Create64(LN); LQ2.Z := TNat.Create64(LN);
    TNat.Copy64(LN, LLambda1, LQ1.X);        // Q1.X = lambda1, Q1.Z = 0  (infinity)
    FFieldOps.Mul(LLambda2, LBaseX, LQ2.X);  // Q2.X = lambda2 * x
    TNat.Copy64(LN, LLambda2, LQ2.Z);        // Q2.Z = lambda2

    // --- fixed-length Montgomery ladder with branch-free conditional swap ---
    LPbit := 0;
    for LI := LScalarBits - 1 downto 0 do
    begin
      LKbit := Int32(TNat.GetBit(LKPrime, LI)) xor LPbit;
      TNat.CSwap64(LN, LKbit, LQ1.X, LQ2.X);
      TNat.CSwap64(LN, LKbit, LQ1.Z, LQ2.Z);
      LQ2 := TLopezDahabLadder.MAdd(FFieldOps, LQ1, LQ2, LBaseX);
      LQ1 := TLopezDahabLadder.MDouble(FFieldOps, LQ1);
      LPbit := Int32(TNat.GetBit(LKPrime, LI));
    end;
    TNat.CSwap64(LN, LPbit, LQ1.X, LQ2.X);
    TNat.CSwap64(LN, LPbit, LQ1.Z, LQ2.Z);

    // --- y-recovery (batched single inversion) ---
    LXOut := TNat.Create64(LN);
    LLOut := TNat.Create64(LN);
    TLopezDahabLadder.Recover(FFieldOps, LQ1, LQ2, LBaseX, LBaseY, LXOut, LLOut, LIsInfinity);
    if LIsInfinity then
      Exit(AP.Curve.Infinity);

    LXfe := FFieldOps.CreateFieldElement(LXOut);
    LLfe := FFieldOps.CreateFieldElement(LLOut);
    Result := AP.Curve.CreateRawPoint(LXfe, LLfe);
  finally
    TNat.Zero(LScalarInts, LKPrime);
    TNat.Zero(LScalarInts, LK);
    TNat.Zero(LScalarInts, LR);
    TNat.Zero(LScalarInts * 2, LProd);
  end;
end;

end.
