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

unit ClpFpCTMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpNat,
  ClpPack,
  ClpBitOperations,
  ClpMultipliers,
  ClpIFpFieldOps,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIECFieldElement,
  ClpIECCommon,
  ClpCTFieldValue,
  ClpCTFieldArith,
  ClpCTJacPoint,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SPointNotOnCurve = 'point is not a valid point on the curve for constant-time multiplication';
  SScalarTooLarge = 'scalar is larger than the curve order';
  SInvalidBlindBits = 'blinding length must be 0 or 32 (ephemeral) or a multiple of 32 between 64 and 512';

type
  /// <summary>
  /// Value-type constant-time single-scalar variable-point multiplier for Fp
  /// short-Weierstrass curves. Countermeasures: scalar blinding, randomized
  /// projective coordinates,
  /// fixed processing length, masked table lookups, one unconditional add per
  /// window), but the hot loop runs over stack <see cref="TFePoint"/> records via
  /// the generic <c>TCTJacPoint&lt;TOps&gt;</c> — no per-operation heap allocation
  /// and no interface dispatch. The curve context (order, affine conversion,
  /// inverse, field-element boxing) comes from the <c>IFpFieldOps</c> adapter.
  /// </summary>
  TFpCTMultiplier<TOps: TCTFieldArithBase> = class sealed(TAbstractECMultiplier, IECMultiplier)
  strict private
  const
    WINDOW_BITS = Int32(4);
    TABLE_SIZE = Int32(16);
    DEFAULT_BLIND_BITS = Int32(64);
    MAX_BLIND_BITS = Int32(512);
  var
    FFieldOps: IFpFieldOps;
    FRandom: ISecureRandom;
    FBlindBits: Int32;
    class function ValidBlindBits(ABlindBits: Int32): Boolean; static;
    function GetRandom: ISecureRandom;
    procedure GenerateBlind(const ARandom: ISecureRandom; const AZ: TCryptoLibUInt32Array);
    procedure ScaleRandomJac(const AP: TFePoint; const ALambda: TFe; var AR: TFePoint);
    function MultiplyJacobian(const AP: IECPoint; const AK: TBigInteger): IECPoint;
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  public
    constructor Create(const AFieldOps: IFpFieldOps;
      ABlindBits: Int32 = DEFAULT_BLIND_BITS); overload;
    constructor Create(const AFieldOps: IFpFieldOps; const ARandom: ISecureRandom;
      ABlindBits: Int32 = DEFAULT_BLIND_BITS); overload;
  end;

implementation

{ TFpCTMultiplier<TOps> }

class function TFpCTMultiplier<TOps>.ValidBlindBits(ABlindBits: Int32): Boolean;
begin
  // 0/32 are the distinguished ephemeral opt-in (single-use ECDHE [d]Q runs the
  // exact-length unblinded ladder); every other construction keeps the full blind.
  Result := ((ABlindBits and 31) = 0) and
    ((ABlindBits = 0) or (ABlindBits = 32) or
    ((ABlindBits >= DEFAULT_BLIND_BITS) and (ABlindBits <= MAX_BLIND_BITS)));
end;

constructor TFpCTMultiplier<TOps>.Create(const AFieldOps: IFpFieldOps; ABlindBits: Int32);
begin
  Inherited Create;
  if not ValidBlindBits(ABlindBits) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBlindBits);
  FFieldOps := AFieldOps;
  FBlindBits := ABlindBits;
end;

constructor TFpCTMultiplier<TOps>.Create(const AFieldOps: IFpFieldOps;
  const ARandom: ISecureRandom; ABlindBits: Int32);
begin
  Inherited Create;
  if not ValidBlindBits(ABlindBits) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBlindBits);
  FFieldOps := AFieldOps;
  FRandom := ARandom;
  FBlindBits := ABlindBits;
end;

function TFpCTMultiplier<TOps>.GetRandom: ISecureRandom;
begin
  if FRandom = nil then
    FRandom := TSecureRandom.Create() as ISecureRandom;
  Result := FRandom;
end;

procedure TFpCTMultiplier<TOps>.GenerateBlind(const ARandom: ISecureRandom;
  const AZ: TCryptoLibUInt32Array);
var
  LBytes: TCryptoLibByteArray;
begin
  SetLength(LBytes, FBlindBits div 8);
  ARandom.NextBytes(LBytes);
  TPack.LE_To_UInt32(LBytes, 0, AZ, 0, FBlindBits div 32);
end;

procedure TFpCTMultiplier<TOps>.ScaleRandomJac(const AP: TFePoint; const ALambda: TFe;
  var AR: TFePoint);
begin
  TCTJacPoint<TOps>.ScaleRandom(AP, ALambda, AR);
end;

function TFpCTMultiplier<TOps>.MultiplyJacobian(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
var
  LFieldInts, LScalarBits, LScalarInts, LWindows, LI, LJ, LBit, LLimb, LShift, LDigit: Int32;
  LTable: array of TFePoint;
  LBase, LAcc, LSel: TFePoint;
  LLambda: TFe;
  LLTT: TFeExt;
  LLambdaArr, LXa, LYa, LN, LR, LProd, LK, LKPrime: TCryptoLibUInt32Array;
  LIsInfinity: Boolean;
  LXfe, LYfe: IECFieldElement;
  LAffine: IECPoint;
  LRandom: ISecureRandom;
begin
  LFieldInts := FFieldOps.GetFieldInts;
  LRandom := GetRandom;

  LAffine := AP.Normalize();
  LXa := TNat.Create(LFieldInts);
  LYa := TNat.Create(LFieldInts);
  FFieldOps.FieldFromBigInteger(LAffine.AffineXCoord.ToBigInteger(), LXa);
  FFieldOps.FieldFromBigInteger(LAffine.AffineYCoord.ToBigInteger(), LYa);

  // randomized projective (Jacobian) coordinates: base = (x*l^2, y*l^3, l)
  LLambdaArr := TNat.Create(LFieldInts);
  FFieldOps.RandomMult(LRandom, LLambdaArr);
  FillChar(LLambda, SizeOf(LLambda), 0);
  Move(LLambdaArr[0], LLambda.W[0], LFieldInts * SizeOf(UInt32));
  TOps.ToMont(LLambda, LLambda, LLTT);
  TCTJacPoint<TOps>.FromAffine(FFieldOps, LXa, LYa, LBase);
  ScaleRandomJac(LBase, LLambda, LBase);

  // table build that never presents equal points to the incomplete add: even
  // entries via the dedicated double, odd entries via a provably-distinct add
  // ((i-1)*B + B with (i-1) >= 2 so the operands differ).
  SetLength(LTable, TABLE_SIZE);
  TCTJacPoint<TOps>.Infinity(FFieldOps, LTable[0]);
  LTable[1] := LBase;
  for LI := 2 to TABLE_SIZE - 1 do
    if (LI and 1) = 0 then
      TCTJacPoint<TOps>.PointDouble(LTable[LI shr 1], LTable[LI])
    else
      TCTJacPoint<TOps>.PointAdd(LTable[LI - 1], LBase, LTable[LI]);

  // scalar blinding in fixed-width Nat: k' = k + r*n (r is empty for the ephemeral
  // unblinded configuration, giving the exact-length ladder)
  LScalarBits := FFieldOps.GetOrderBits + FBlindBits + 1;
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
    LWindows := (LScalarBits + WINDOW_BITS - 1) div WINDOW_BITS;
    TCTJacPoint<TOps>.Infinity(FFieldOps, LAcc);
    for LI := LWindows - 1 downto 0 do
    begin
      for LJ := 0 to WINDOW_BITS - 1 do
        TCTJacPoint<TOps>.PointDouble(LAcc, LAcc);

      LBit := LI * WINDOW_BITS;
      LLimb := TBitOperations.Asr32(LBit, 5);
      LShift := LBit and 31;
      LDigit := Int32((LKPrime[LLimb] shr LShift) and UInt32(TABLE_SIZE - 1));

      TCTJacPoint<TOps>.SelectEntry(FFieldOps, LTable, TABLE_SIZE, LDigit, LSel);
      TCTJacPoint<TOps>.PointAdd(LAcc, LSel, LAcc);
    end;

    TCTJacPoint<TOps>.ToAffine(FFieldOps, LAcc, LXa, LYa, LIsInfinity);
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
    FillChar(LLambda, SizeOf(LLambda), 0);
    FillChar(LBase, SizeOf(LBase), 0);
    FillChar(LAcc, SizeOf(LAcc), 0);
    FillChar(LSel, SizeOf(LSel), 0);
    for LI := 0 to TABLE_SIZE - 1 do
      FillChar(LTable[LI], SizeOf(LTable[LI]), 0);
  end;
end;

function TFpCTMultiplier<TOps>.MultiplyPositive(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
begin
  if not AP.IsValid then
    raise EInvalidOperationCryptoLibException.CreateRes(@SPointNotOnCurve);

  if AK.BitLength > FFieldOps.GetOrderBits then
    raise EInvalidOperationCryptoLibException.CreateRes(@SScalarTooLarge);

  Result := MultiplyJacobian(AP, AK);
end;

end.
