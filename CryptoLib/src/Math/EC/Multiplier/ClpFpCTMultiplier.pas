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
    // signed width-5 Booth windowing: digits in [-16, 15] over a 17-entry table
    // (index 0 = infinity, index m = m*B), sign applied by a masked field negation.
    WINDOW_BITS = Int32(5);
    TABLE_SIZE = Int32(17);
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
  // The ephemeral opt-in for single-use ECDHE [d]Q: 0 runs the exact-length
  // unblinded ladder, 32 adds only a minimal one-word blind; every other
  // construction keeps the full blind (>= 64).
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
  LFieldInts, LScalarBits, LScalarInts, LWindows, LI, LJ, LBit, LLimb, LShift, LDigit, LOrderBits, LSignInt, LMag: Int32;
  LTopBit, LCarry, LWin, LLo, LSignMask: UInt32;
  LDigits: TCryptoLibInt32Array;
  LTable: array of TFePoint;
  LBase, LAcc, LSel: TFePoint;
  LLambda, LNegY, LZeroFe: TFe;
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

  // table of B..16*B (index 0 = infinity for the digit-zero window), built so no
  // step presents equal points to the incomplete add: even entries via the
  // dedicated double, odd entries via a provably-distinct add ((i-1)*B + B with
  // (i-1) >= 2 so the operands differ).
  LTable := nil;
  SetLength(LTable, TABLE_SIZE);
  TCTJacPoint<TOps>.Infinity(FFieldOps, LTable[0]);
  LTable[1] := LBase;
  for LI := 2 to TABLE_SIZE - 1 do
    if (LI and 1) = 0 then
      TCTJacPoint<TOps>.PointDouble(LTable[LI shr 1], LTable[LI])
    else
      TCTJacPoint<TOps>.PointAdd(LTable[LI - 1], LBase, LTable[LI]);

  // Fixed-width scalar prep, two postures (both give a fixed ladder length and a
  // non-zero top window so no window count leaks the secret):
  //   FBlindBits > 0: randomized scalar blinding k' = k + r*n (long-term keys).
  //   FBlindBits = 0: deterministic fixed-length k' = k + n or k + 2n, constant-time
  //     selected on the top bit, for single-use ephemeral scalars. k' * P = k * P
  //     since n*P = O, and k' always has bit GetOrderBits set (exact-length ladder,
  //     top window never zero -> no leading-zero side channel).
  LScalarBits := FFieldOps.GetOrderBits + FBlindBits + 1;
  LScalarInts := TNat.GetLengthForBits(LScalarBits) + 1;
  LN := TNat.Create(LScalarInts);
  LR := TNat.Create(LScalarInts);
  LProd := TNat.Create(LScalarInts * 2);
  FFieldOps.GetOrder(LN, LScalarInts);
  LK := TNat.FromBigInteger(LScalarInts * 32, AK);
  LKPrime := TNat.Create(LScalarInts);
  if FBlindBits = 0 then
  begin
    LOrderBits := FFieldOps.GetOrderBits;
    TNat.Add(LScalarInts, LK, LN, LKPrime);            // k + n
    LTopBit := (LKPrime[LOrderBits shr 5] shr (LOrderBits and 31)) and 1;
    TNat.CAdd(LScalarInts, Int32(1 - LTopBit), LKPrime, LN, LKPrime); // +n iff top clear -> k+2n
  end
  else
  begin
    GenerateBlind(LRandom, LR);
    TNat.Mul(LScalarInts, LR, LN, LProd);
    TNat.Add(LScalarInts, LK, LProd, LKPrime);         // k + r*n
  end;

  try
    // Signed width-5 Booth recode of the fixed-length scalar (one extra window of
    // headroom absorbs the final carry). Each window's low 5 bits plus the running
    // carry give a digit in [-16, 15]; a set top bit borrows from the next window.
    // All extraction is on public window indices, so the pattern is scalar-independent.
    LWindows := (LScalarBits + WINDOW_BITS) div WINDOW_BITS + 1;
    SetLength(LDigits, LWindows);
    LCarry := 0;
    for LI := 0 to LWindows - 1 do
    begin
      LBit := LI * WINDOW_BITS;
      LLimb := TBitOperations.Asr32(LBit, 5);
      LShift := LBit and 31;
      LLo := LKPrime[LLimb] shr LShift;
      if LShift > (32 - WINDOW_BITS) then
        LLo := LLo or (LKPrime[LLimb + 1] shl (32 - LShift));
      LWin := (LLo and UInt32((1 shl WINDOW_BITS) - 1)) + LCarry;
      LCarry := (LWin + UInt32(1 shl (WINDOW_BITS - 1))) shr WINDOW_BITS; // 1 iff LWin >= 16
      LDigits[LI] := Int32(LWin) - Int32(LCarry shl WINDOW_BITS);        // LWin - 32*carry
    end;

    FillChar(LZeroFe, SizeOf(LZeroFe), 0); // Montgomery zero, for the masked -Y
    TCTJacPoint<TOps>.Infinity(FFieldOps, LAcc);
    for LI := LWindows - 1 downto 0 do
    begin
      for LJ := 0 to WINDOW_BITS - 1 do
        TCTJacPoint<TOps>.PointDouble(LAcc, LAcc);

      LDigit := LDigits[LI];
      LSignInt := TBitOperations.Asr32(LDigit, 31); // -1 iff digit < 0, else 0
      LSignMask := UInt32(LSignInt);
      LMag := (LDigit xor LSignInt) - LSignInt;     // |digit| in [0, 16]

      TCTJacPoint<TOps>.SelectEntry(FFieldOps, LTable, TABLE_SIZE, LMag, LSel);
      // apply the digit sign by a masked field negation of Y (-P = (X, -Y, Z))
      TOps.Sub(LZeroFe, LSel.Y, LNegY);
      for LJ := 0 to LFieldInts - 1 do
        LSel.Y.W[LJ] := (LNegY.W[LJ] and LSignMask) or (LSel.Y.W[LJ] and (not LSignMask));
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
    FillChar(LNegY, SizeOf(LNegY), 0);
    FillChar(LBase, SizeOf(LBase), 0);
    FillChar(LAcc, SizeOf(LAcc), 0);
    FillChar(LSel, SizeOf(LSel), 0);
    for LI := 0 to TABLE_SIZE - 1 do
      FillChar(LTable[LI], SizeOf(LTable[LI]), 0);
    if LDigits <> nil then
      FillChar(LDigits[0], Length(LDigits) * SizeOf(Int32), 0);
  end;
end;

function TFpCTMultiplier<TOps>.MultiplyPositive(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
var
  LK: TBigInteger;
begin
  if not AP.IsValid then
    raise EInvalidOperationCryptoLibException.CreateRes(@SPointNotOnCurve);

  // reduce into the prime-order group ([k]P = [k mod n]P) so the ladder always runs
  // on k < n: this keeps the fixed-length ladder exact and the incomplete-add P=Q
  // backstop unreachable, and gives the same "any scalar" contract as the general
  // multiplier. The compare and the (out-of-range-only) reduction sit in the variable
  // -time BigInteger stage that precedes the constant-time ladder; an in-range secret
  // takes neither. A scalar that reduces to zero yields infinity, as elsewhere.
  LK := AK;
  if LK.CompareTo(AP.Curve.Order) >= 0 then
    LK := LK.&Mod(AP.Curve.Order);
  if LK.SignValue = 0 then
    Exit(AP.Curve.Infinity);

  Result := MultiplyJacobian(AP, LK);
end;

end.
