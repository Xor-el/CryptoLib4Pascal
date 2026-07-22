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

unit ClpFixedWindowCTMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpNat,
  ClpPack,
  ClpBitOperations,
  ClpMultipliers,
  ClpICTFieldOps,
  ClpHomogeneousPoint,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIECFieldElement,
  ClpIECCommon,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

type
  /// <summary>
  /// Constant-time single-scalar variable-point multiplier for prime-order
  /// NIST curves (P-256/384/521). Unsigned fixed window over homogeneous
  /// complete formulas, masked table lookups only, one unconditional addition
  /// per window; scalar blinding, randomized projective coordinates and a fixed
  /// processing length as countermeasures.
  /// </summary>
  TFixedWindowCTMultiplier = class sealed(TAbstractECMultiplier, IECMultiplier)
  strict private
  const
    WINDOW_BITS = Int32(4);
    TABLE_SIZE = Int32(16);
    BLIND_BITS = Int32(64);
  var
    FFieldOps: ICTFieldOps;
    FRandom: ISecureRandom;
    function GetRandom: ISecureRandom;
    procedure GenerateBlind(const ARandom: ISecureRandom; const AZ: TCryptoLibUInt32Array);
    function SelectEntry(const ATable: TCryptoLibGenericArray<TCTHomogPoint>;
      AIndex: Int32): TCTHomogPoint;
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  public
    constructor Create(const AFieldOps: ICTFieldOps); overload;
    constructor Create(const AFieldOps: ICTFieldOps; const ARandom: ISecureRandom); overload;
  end;

implementation

resourcestring
  SPointNotOnCurve = 'point is not a valid point on the curve for constant-time multiplication';

{ TFixedWindowCTMultiplier }

constructor TFixedWindowCTMultiplier.Create(const AFieldOps: ICTFieldOps);
begin
  Inherited Create;
  FFieldOps := AFieldOps;
end;

constructor TFixedWindowCTMultiplier.Create(const AFieldOps: ICTFieldOps;
  const ARandom: ISecureRandom);
begin
  Inherited Create;
  FFieldOps := AFieldOps;
  FRandom := ARandom;
end;

function TFixedWindowCTMultiplier.GetRandom: ISecureRandom;
begin
  if FRandom = nil then
    FRandom := TSecureRandom.Create() as ISecureRandom;
  Result := FRandom;
end;

procedure TFixedWindowCTMultiplier.GenerateBlind(const ARandom: ISecureRandom;
  const AZ: TCryptoLibUInt32Array);
var
  LBytes: TCryptoLibByteArray;
begin
  // BLIND_BITS of fresh randomness in the low limbs of AZ
  System.SetLength(LBytes, BLIND_BITS div 8);
  ARandom.NextBytes(LBytes);
  TPack.LE_To_UInt32(LBytes, 0, AZ, 0, BLIND_BITS div 32);
end;

function TFixedWindowCTMultiplier.SelectEntry(
  const ATable: TCryptoLibGenericArray<TCTHomogPoint>; AIndex: Int32): TCTHomogPoint;
var
  LN, LI, LJ: Int32;
  LMask: UInt32;
begin
  LN := FFieldOps.GetFieldInts;
  Result.X := TNat.Create(LN);
  Result.Y := TNat.Create(LN);
  Result.Z := TNat.Create(LN);
  for LI := 0 to TABLE_SIZE - 1 do
  begin
    LMask := UInt32(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));
    for LJ := 0 to LN - 1 do
    begin
      Result.X[LJ] := Result.X[LJ] xor (ATable[LI].X[LJ] and LMask);
      Result.Y[LJ] := Result.Y[LJ] xor (ATable[LI].Y[LJ] and LMask);
      Result.Z[LJ] := Result.Z[LJ] xor (ATable[LI].Z[LJ] and LMask);
    end;
  end;
end;

function TFixedWindowCTMultiplier.MultiplyPositive(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
var
  LFieldInts, LScalarBits, LScalarInts, LWindows, LI, LJ, LBit, LLimb, LShift, LDigit: Int32;
  LTable: TCryptoLibGenericArray<TCTHomogPoint>;
  LBase, LAcc, LSel: TCTHomogPoint;
  LLambda, LXa, LYa, LN, LR, LProd, LK, LKPrime: TCryptoLibUInt32Array;
  LIsInfinity: Boolean;
  LXfe, LYfe: IECFieldElement;
  LAffine: IECPoint;
  LRandom: ISecureRandom;
begin
  if not AP.IsValid then
    raise EInvalidOperationCryptoLibException.CreateRes(@SPointNotOnCurve);

  LFieldInts := FFieldOps.GetFieldInts;
  LRandom := GetRandom;

  // --- affine coordinates of the (public) input point ---
  LAffine := AP.Normalize();
  LXa := TNat.Create(LFieldInts);
  LYa := TNat.Create(LFieldInts);
  FFieldOps.FieldFromBigInteger(LAffine.AffineXCoord.ToBigInteger(), LXa);
  FFieldOps.FieldFromBigInteger(LAffine.AffineYCoord.ToBigInteger(), LYa);

  // --- randomized projective coordinates: base = (lambda*x, lambda*y, lambda) ---
  LLambda := TNat.Create(LFieldInts);
  FFieldOps.RandomMult(LRandom, LLambda);
  LBase := TCTHomogeneousMath.ScaleRandom(FFieldOps,
    TCTHomogeneousMath.FromAffine(FFieldOps, LXa, LYa), LLambda);

  // --- projective precomputation table [0]=O, [i]=[i]*base ---
  System.SetLength(LTable, TABLE_SIZE);
  LTable[0] := TCTHomogeneousMath.Infinity(FFieldOps);
  LTable[1] := LBase;
  for LI := 2 to TABLE_SIZE - 1 do
    LTable[LI] := TCTHomogeneousMath.Add(FFieldOps, LTable[LI - 1], LBase);

  // --- scalar blinding in fixed-width Nat: k' = k + r*n ---
  LScalarBits := FFieldOps.GetOrderBits + BLIND_BITS + 1;
  LScalarInts := TNat.GetLengthForBits(LScalarBits) + 1;
  LN := TNat.Create(LScalarInts);
  LR := TNat.Create(LScalarInts);
  LProd := TNat.Create(LScalarInts * 2);
  FFieldOps.GetOrder(LN, LScalarInts);
  GenerateBlind(LRandom, LR);
  TNat.Mul(LScalarInts, LR, LN, LProd);
  LK := TNat.FromBigInteger(LScalarInts * 32, AK);
  LKPrime := TNat.Create(LScalarInts);
  TNat.Add(LScalarInts, LK, LProd, LKPrime);

  try
    // --- fixed-length windowed ladder ---
    LWindows := (LScalarBits + WINDOW_BITS - 1) div WINDOW_BITS;
    LAcc := TCTHomogeneousMath.Infinity(FFieldOps);
    for LI := LWindows - 1 downto 0 do
    begin
      for LJ := 0 to WINDOW_BITS - 1 do
        LAcc := TCTHomogeneousMath.Double(FFieldOps, LAcc);

      // WINDOW_BITS divides 32, so a digit never spans a limb boundary
      LBit := LI * WINDOW_BITS;
      LLimb := TBitOperations.Asr32(LBit, 5);
      LShift := LBit and 31;
      LDigit := Int32((LKPrime[LLimb] shr LShift) and UInt32(TABLE_SIZE - 1));

      LSel := SelectEntry(LTable, LDigit);
      LAcc := TCTHomogeneousMath.Add(FFieldOps, LAcc, LSel);
    end;

    TCTHomogeneousMath.ToAffine(FFieldOps, LAcc, LXa, LYa, LIsInfinity);
    if LIsInfinity then
      Exit(AP.Curve.Infinity);

    LXfe := FFieldOps.CreateFieldElement(LXa);
    LYfe := FFieldOps.CreateFieldElement(LYa);
    Result := AP.Curve.CreateRawPoint(LXfe, LYfe);
  finally
    TNat.Zero(LScalarInts, LKPrime);
    TNat.Zero(LScalarInts, LK);
    TNat.Zero(LScalarInts, LR);
    TNat.Zero(LScalarInts * 2, LProd);
  end;
end;

end.
