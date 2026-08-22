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
  ClpCTPoint,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SPointNotOnCurve = 'point is not a valid point on the curve for constant-time multiplication';
  SScalarTooLarge = 'scalar is larger than the curve order';
  SInvalidBlindBits = 'blinding length must be a multiple of 32 between 64 and 512';

type
  /// <summary>
  /// Value-type constant-time single-scalar variable-point multiplier for Fp
  /// short-Weierstrass curves. Countermeasures: scalar blinding, randomized
  /// projective coordinates,
  /// fixed processing length, masked table lookups, one unconditional add per
  /// window), but the hot loop runs over stack <see cref="TFePoint"/> records via
  /// the generic <c>TCTPoint&lt;TOps&gt;</c> — no per-operation heap allocation
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
    function GetRandom: ISecureRandom;
    procedure GenerateBlind(const ARandom: ISecureRandom; const AZ: TCryptoLibUInt32Array);
    procedure ScaleRandom(const AP: TFePoint; const ALambda: TFe; var AR: TFePoint);
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

constructor TFpCTMultiplier<TOps>.Create(const AFieldOps: IFpFieldOps; ABlindBits: Int32);
begin
  Inherited Create;
  if (ABlindBits < DEFAULT_BLIND_BITS) or (ABlindBits > MAX_BLIND_BITS)
    or ((ABlindBits and 31) <> 0) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBlindBits);
  FFieldOps := AFieldOps;
  FBlindBits := ABlindBits;
end;

constructor TFpCTMultiplier<TOps>.Create(const AFieldOps: IFpFieldOps;
  const ARandom: ISecureRandom; ABlindBits: Int32);
begin
  Inherited Create;
  if (ABlindBits < DEFAULT_BLIND_BITS) or (ABlindBits > MAX_BLIND_BITS)
    or ((ABlindBits and 31) <> 0) then
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

procedure TFpCTMultiplier<TOps>.ScaleRandom(const AP: TFePoint; const ALambda: TFe;
  var AR: TFePoint);
var
  LTT: TFeExt;
begin
  TOps.Mul(AP.X, ALambda, AR.X, LTT);
  TOps.Mul(AP.Y, ALambda, AR.Y, LTT);
  TOps.Mul(AP.Z, ALambda, AR.Z, LTT);
end;

function TFpCTMultiplier<TOps>.MultiplyPositive(const AP: IECPoint;
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
  if not AP.IsValid then
    raise EInvalidOperationCryptoLibException.CreateRes(@SPointNotOnCurve);

  if AK.BitLength > FFieldOps.GetOrderBits then
    raise EInvalidOperationCryptoLibException.CreateRes(@SScalarTooLarge);

  LFieldInts := FFieldOps.GetFieldInts;
  LRandom := GetRandom;

  // affine coordinates of the (public) input point
  LAffine := AP.Normalize();
  LXa := TNat.Create(LFieldInts);
  LYa := TNat.Create(LFieldInts);
  FFieldOps.FieldFromBigInteger(LAffine.AffineXCoord.ToBigInteger(), LXa);
  FFieldOps.FieldFromBigInteger(LAffine.AffineYCoord.ToBigInteger(), LYa);

  // randomized projective coordinates: base = (lambda*x, lambda*y, lambda)
  LLambdaArr := TNat.Create(LFieldInts);
  FFieldOps.RandomMult(LRandom, LLambdaArr);
  FillChar(LLambda, SizeOf(LLambda), 0);
  Move(LLambdaArr[0], LLambda.W[0], LFieldInts * SizeOf(UInt32));
  // ladder runs in the Montgomery domain: the random blinding scalar must be there too
  TOps.ToMont(LLambda, LLambda, LLTT);
  TCTPoint<TOps>.FromAffine(FFieldOps, LXa, LYa, LBase);
  ScaleRandom(LBase, LLambda, LBase);

  // projective precomputation table [0]=O, [i]=[i]*base
  SetLength(LTable, TABLE_SIZE);
  TCTPoint<TOps>.Infinity(FFieldOps, LTable[0]);
  LTable[1] := LBase;
  for LI := 2 to TABLE_SIZE - 1 do
    TCTPoint<TOps>.PointAdd(LTable[LI - 1], LBase, LTable[LI]);

  // scalar blinding in fixed-width Nat: k' = k + r*n
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
    // fixed-length windowed ladder
    LWindows := (LScalarBits + WINDOW_BITS - 1) div WINDOW_BITS;
    TCTPoint<TOps>.Infinity(FFieldOps, LAcc);
    for LI := LWindows - 1 downto 0 do
    begin
      for LJ := 0 to WINDOW_BITS - 1 do
        TCTPoint<TOps>.PointDouble(LAcc, LAcc);

      // WINDOW_BITS divides 32, so a digit never spans a limb boundary
      LBit := LI * WINDOW_BITS;
      LLimb := TBitOperations.Asr32(LBit, 5);
      LShift := LBit and 31;
      LDigit := Int32((LKPrime[LLimb] shr LShift) and UInt32(TABLE_SIZE - 1));

      TCTPoint<TOps>.SelectEntry(FFieldOps, LTable, TABLE_SIZE, LDigit, LSel);
      TCTPoint<TOps>.PointAdd(LAcc, LSel, LAcc);
    end;

    TCTPoint<TOps>.ToAffine(FFieldOps, LAcc, LXa, LYa, LIsInfinity);
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

end.
