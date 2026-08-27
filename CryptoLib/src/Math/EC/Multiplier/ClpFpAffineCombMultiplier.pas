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

unit ClpFpAffineCombMultiplier;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpNat,
  ClpPack,
  ClpBitOperations,
  ClpMultipliers,
  ClpIPreCompInfo,
  ClpIPreCompCallback,
  ClpIAffineCombPreCompInfo,
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

type
  /// <summary>Cached fixed-base affine comb table (see
  /// <see cref="IAffineCombPreCompInfo"/>).</summary>
  TAffineCombPreCompInfo = class sealed(TInterfacedObject, IPreCompInfo,
    IAffineCombPreCompInfo)
  strict private
    FWindow, FNumWindows, FEntriesPerWindow: Int32;
    FTable: TCryptoLibGenericArray<TFeAffine>;
  public
    function GetWindow: Int32;
    function GetNumWindows: Int32;
    function GetEntriesPerWindow: Int32;
    function GetTable: TCryptoLibGenericArray<TFeAffine>;
    procedure SetData(AWindow, ANumWindows, AEntriesPerWindow: Int32;
      const ATable: TCryptoLibGenericArray<TFeAffine>);
  end;

  /// <summary>
  /// Value-type constant-time fixed-base multiplier that eliminates the online
  /// doublings entirely: the scalar is recoded into signed Booth windows and each
  /// window contributes a single mixed addition of a precomputed affine multiple
  /// <c>(digit * 2^(w*i)) * G</c>, so <c>[k]G</c> is <c>NumWindows</c> mixed adds
  /// with no doublings. Constant-time countermeasures mirror the variable-point
  /// path: the scalar is blinded to a fixed width (<c>k' = k + r*n</c>) so the
  /// timing is independent of k's magnitude, the per-window table gather scans
  /// every entry, the Booth-sign negation and the zero-digit skip are masked, and
  /// a zero digit still gathers a real entry so the mixed-add operands are never
  /// scalar-dependent zeros. The per-window multiples are batch-built once per base
  /// point and cached (public data). Generic over the curve field arithmetic
  /// <c>TOps</c>; a curve opts in by returning this from its
  /// <c>CreateBasePointMultiplier</c>.
  /// </summary>
  TFpAffineCombMultiplier<TOps: TCTFieldArithBase> = class sealed(TAbstractECMultiplier,
    IECMultiplier)
  strict private
  const
    WINDOW = Int32(7);
    BLIND_BITS = Int32(64);
    PRECOMP_NAME = 'bc_fixed_point_affine_comb';
  var
    FFieldOps: IFpFieldOps;
    FRandom: ISecureRandom;
    FScalarBits: Int32;
    function GetRandom: ISecureRandom;
    procedure GenerateBlind(const ARandom: ISecureRandom;
      const AZ: TCryptoLibUInt32Array);
    class function BoothRecodeW7(AIn: UInt32): UInt32; static; inline;
    class function GetBoothWindow(const AK: TCryptoLibUInt32Array;
      AWin: Int32): UInt32; static; inline;
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  public
    constructor Create(const AFieldOps: IFpFieldOps);
  end;

  /// <summary>Builds the per-window affine table for a base point on first use
  /// and caches it in the point's precomputation store.</summary>
  TAffineCombPreCompCallback<TOps: TCTFieldArithBase> = class sealed(TInterfacedObject,
    IPreCompCallback)
  strict private
    FPoint: IECPoint;
    FFieldOps: IFpFieldOps;
    FScalarBits, FWindow: Int32;
  public
    constructor Create(const APoint: IECPoint; const AFieldOps: IFpFieldOps;
      AScalarBits, AWindow: Int32);
    function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
  end;

implementation

{ TAffineCombPreCompInfo }

function TAffineCombPreCompInfo.GetWindow: Int32;
begin
  Result := FWindow;
end;

function TAffineCombPreCompInfo.GetNumWindows: Int32;
begin
  Result := FNumWindows;
end;

function TAffineCombPreCompInfo.GetEntriesPerWindow: Int32;
begin
  Result := FEntriesPerWindow;
end;

function TAffineCombPreCompInfo.GetTable: TCryptoLibGenericArray<TFeAffine>;
begin
  Result := FTable;
end;

procedure TAffineCombPreCompInfo.SetData(AWindow, ANumWindows, AEntriesPerWindow: Int32;
  const ATable: TCryptoLibGenericArray<TFeAffine>);
begin
  FWindow := AWindow;
  FNumWindows := ANumWindows;
  FEntriesPerWindow := AEntriesPerWindow;
  FTable := ATable;
end;

{ TAffineCombPreCompCallback<TOps> }

constructor TAffineCombPreCompCallback<TOps>.Create(const APoint: IECPoint;
  const AFieldOps: IFpFieldOps; AScalarBits, AWindow: Int32);
begin
  Inherited Create;
  FPoint := APoint;
  FFieldOps := AFieldOps;
  FScalarBits := AScalarBits;
  FWindow := AWindow;
end;

function TAffineCombPreCompCallback<TOps>.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LExisting: IAffineCombPreCompInfo;
  LInfo: TAffineCombPreCompInfo;
  LNumWin, LEntries, LI, LJ, LD: Int32;
  LBase, LAcc, LNorm: IECPoint;
  LTable: TCryptoLibGenericArray<TFeAffine>;
  LPt: TFePoint;
begin
  if Supports(AExisting, IAffineCombPreCompInfo, LExisting) and
    (LExisting.Window = FWindow) and (LExisting.NumWindows * FWindow >= FScalarBits) then
    Exit(LExisting);

  LEntries := 1 shl (FWindow - 1);            // magnitudes 1 .. 2^(w-1)
  LNumWin := (FScalarBits + FWindow) div FWindow; // covers the blinded scalar + Booth carry
  System.SetLength(LTable, LNumWin * LEntries);

  LBase := FPoint.Normalize();                // 2^(w*0) * G
  for LI := 0 to LNumWin - 1 do
  begin
    LAcc := LBase;                            // 1 * LBase
    for LJ := 0 to LEntries - 1 do
    begin
      LNorm := LAcc.Normalize();
      TCTJacPoint<TOps>.FromAffineElt(FFieldOps, LNorm.AffineXCoord,
        LNorm.AffineYCoord, LPt);
      LTable[LI * LEntries + LJ].X := LPt.X;
      LTable[LI * LEntries + LJ].Y := LPt.Y;
      LAcc := LAcc.Add(LBase);               // (j+2) * LBase
    end;
    for LD := 1 to FWindow do
      LBase := LBase.Twice();                // LBase := 2^w * LBase
  end;

  LInfo := TAffineCombPreCompInfo.Create;
  LInfo.SetData(FWindow, LNumWin, LEntries, LTable);
  Result := LInfo;
end;

{ TFpAffineCombMultiplier<TOps> }

constructor TFpAffineCombMultiplier<TOps>.Create(const AFieldOps: IFpFieldOps);
begin
  Inherited Create;
  FFieldOps := AFieldOps;
  // process a blinded, fixed-width scalar k' = k + r*n so the timing is
  // independent of k's magnitude (same posture as the [d]Q path)
  FScalarBits := AFieldOps.GetOrderBits + BLIND_BITS + 1;
end;

function TFpAffineCombMultiplier<TOps>.GetRandom: ISecureRandom;
begin
  if FRandom = nil then
    FRandom := TSecureRandom.Create() as ISecureRandom;
  Result := FRandom;
end;

procedure TFpAffineCombMultiplier<TOps>.GenerateBlind(const ARandom: ISecureRandom;
  const AZ: TCryptoLibUInt32Array);
var
  LBytes: TCryptoLibByteArray;
begin
  SetLength(LBytes, BLIND_BITS div 8);
  ARandom.NextBytes(LBytes);
  TPack.LE_To_UInt32(LBytes, 0, AZ, 0, BLIND_BITS div 32);
end;

class function TFpAffineCombMultiplier<TOps>.BoothRecodeW7(AIn: UInt32): UInt32;
var
  LS, LD: UInt32;
begin
  LS := not ((AIn shr 7) - 1);               // all-ones if bit 7 set (negative)
  LD := (UInt32(1) shl 8) - AIn - 1;         // 255 - AIn
  LD := (LD and LS) or (AIn and (not LS));
  LD := (LD shr 1) + (LD and 1);
  Result := (LD shl 1) + (LS and 1);         // magnitude in bits>=1, sign in bit 0
end;

class function TFpAffineCombMultiplier<TOps>.GetBoothWindow(
  const AK: TCryptoLibUInt32Array; AWin: Int32): UInt32;
var
  LPos, LLimb, LOfs: Int32;
  LV: UInt32;
begin
  LPos := AWin * WINDOW - 1;
  if LPos < 0 then
    Result := (AK[0] shl 1) and $FF
  else
  begin
    LLimb := LPos shr 5;
    LOfs := LPos and 31;
    LV := AK[LLimb] shr LOfs;
    if LOfs > 24 then                        // 8-bit window straddles into next limb
      LV := LV or (AK[LLimb + 1] shl (32 - LOfs));
    Result := LV and $FF;
  end;
end;

function TFpAffineCombMultiplier<TOps>.MultiplyPositive(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
var
  LInfo: IAffineCombPreCompInfo;
  LCallback: IPreCompCallback;
  LTable: TCryptoLibGenericArray<TFeAffine>;
  LNumWin, LEntries, LN, LI, LJ, LScalarInts: Int32;
  LKPrime, LKn, LBlind, LProd, LNn, LXa, LYa, LLambdaArr: TCryptoLibUInt32Array;
  LR, LRnew: TFePoint;
  LSel: TFeAffine;
  LZero, LNegY, LLambda: TFe;
  LTT: TFeExt;
  LWin, LBooth, LMag, LSign, LNegMask, LSkipMask: UInt32;
  LGatherIdx: Int32;
  LIsInfinity: Boolean;
begin
  // The online masked mixed-adds run on the incomplete-Jacobian engine; the Booth
  // recode, masked gather, masked sign and masked skip-cmov are coordinate-neutral.
  LCallback := TAffineCombPreCompCallback<TOps>.Create(AP, FFieldOps, FScalarBits, WINDOW);
  if not Supports(AP.Precompute(PRECOMP_NAME, LCallback), IAffineCombPreCompInfo, LInfo) then
    raise EInvalidOperationCryptoLibException.Create('affine comb precompute failed');

  // one shared reference read (never interleave a managed getter with allocations)
  LTable := LInfo.Table;
  LNumWin := LInfo.NumWindows;
  LEntries := LInfo.EntriesPerWindow;
  LN := FFieldOps.GetFieldInts;
  FillChar(LZero, SizeOf(LZero), 0);

  // scalar blinding in fixed-width Nat: k' = k + r*n (r is BLIND_BITS wide), so the
  // processing width is constant and independent of k's magnitude
  LScalarInts := TNat.GetLengthForBits(FScalarBits) + 1;
  LNn := TNat.Create(LScalarInts);
  LBlind := TNat.Create(LScalarInts);
  LProd := TNat.Create(LScalarInts * 2);
  FFieldOps.GetOrder(LNn, LScalarInts);
  GenerateBlind(GetRandom, LBlind);
  TNat.Mul(LScalarInts, LBlind, LNn, LProd);
  LKn := TNat.FromBigInteger(LScalarInts * 32, AK);
  LKPrime := TNat.Create(LScalarInts);
  TNat.Add(LScalarInts, LKn, LProd, LKPrime);

  try
    TCTJacPoint<TOps>.Infinity(FFieldOps, LR);
    for LI := 0 to LNumWin - 1 do
    begin
      LWin := GetBoothWindow(LKPrime, LI);
      LBooth := BoothRecodeW7(LWin);
      LMag := LBooth shr 1;                   // 0 .. LEntries
      LSign := LBooth and 1;                  // 1 => negate the looked-up Y
      LSkipMask := UInt32(TBitOperations.Asr32((Int32(LMag) - 1), 31)); // all-ones if LMag=0

      // a zero digit still gathers a real entry (index 0), so the mixed-add
      // operands are never scalar-dependent zeros; the result is dropped below
      LGatherIdx := Int32((UInt32(Int32(LMag) - 1)) and (not LSkipMask));
      TCTPointCommon.SelectAffineEntry(FFieldOps, LTable, LI * LEntries, LEntries,
        LGatherIdx, LSel);

      // masked Y-negation by the Booth sign (branch-free)
      TOps.Sub(LZero, LSel.Y, LNegY);
      LNegMask := UInt32(0) - LSign;
      for LJ := 0 to LN - 1 do
        LSel.Y.W[LJ] := (LSel.Y.W[LJ] and (not LNegMask)) or (LNegY.W[LJ] and LNegMask);

      // R' := R + affine(sel); keep R when the digit is zero (masked point-cmov)
      TCTJacPoint<TOps>.PointAddMixed(LR, LSel, LRnew);
      for LJ := 0 to LN - 1 do
      begin
        LR.X.W[LJ] := (LR.X.W[LJ] and LSkipMask) or (LRnew.X.W[LJ] and (not LSkipMask));
        LR.Y.W[LJ] := (LR.Y.W[LJ] and LSkipMask) or (LRnew.Y.W[LJ] and (not LSkipMask));
        LR.Z.W[LJ] := (LR.Z.W[LJ] and LSkipMask) or (LRnew.Z.W[LJ] and (not LSkipMask));
      end;
    end;

    // randomized projective coordinates: scale R by a random lambda so the Z fed
    // to the inversion is scalar-independent (same countermeasure as the [d]Q path)
    LLambdaArr := TNat.Create(LN);
    FFieldOps.RandomMult(GetRandom, LLambdaArr);
    FillChar(LLambda, SizeOf(LLambda), 0);
    Move(LLambdaArr[0], LLambda.W[0], LN * SizeOf(UInt32));
    TOps.ToMont(LLambda, LLambda, LTT);
    // Jacobian rescale keeps the affine point: (X*l^2, Y*l^3, Z*l).
    TCTJacPoint<TOps>.ScaleRandom(LR, LLambda, LR);

    LXa := TNat.Create(LN);
    LYa := TNat.Create(LN);
    TCTJacPoint<TOps>.ToAffine(FFieldOps, LR, LXa, LYa, LIsInfinity);
    if LIsInfinity then
      Exit(AP.Curve.Infinity);

    Result := AP.Curve.CreateRawPoint(FFieldOps.CreateFieldElement(LXa),
      FFieldOps.CreateFieldElement(LYa));
  finally
    TNat.Zero(LScalarInts, LKPrime);
    TNat.Zero(LScalarInts, LKn);
    TNat.Zero(LScalarInts, LBlind);
    TNat.Zero(LScalarInts * 2, LProd);
    FillChar(LR, SizeOf(LR), 0);
    FillChar(LRnew, SizeOf(LRnew), 0);
    FillChar(LSel, SizeOf(LSel), 0);
    FillChar(LNegY, SizeOf(LNegY), 0);
    FillChar(LLambda, SizeOf(LLambda), 0);
  end;
end;

end.
