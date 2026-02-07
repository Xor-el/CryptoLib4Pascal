{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpMultipliers;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIECCore,
  ClpIECFieldElement,
  ClpIZTauElement,
  ClpIWNafPreCompInfo,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpWNafUtilities,
  ClpCryptoLibTypes;

type
  TAbstractECMultiplier = class abstract(TInterfacedObject, IECMultiplier)
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; virtual; abstract;
    function CheckResult(const AP: IECPoint): IECPoint; virtual;
  public
    function Multiply(const APoint: IECPoint; const AK: TBigInteger): IECPoint; virtual;
  end;

  TWNafL2RMultiplier = class sealed(TAbstractECMultiplier, IECMultiplier, IWNafL2RMultiplier)
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  end;

  TGlvMultiplier = class sealed(TAbstractECMultiplier, IECMultiplier)
  strict protected
    FCurve: IECCurve;
    FGlvEndomorphism: IGlvEndomorphism;
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  public
    constructor Create(const ACurve: IECCurve; const AGlvEndomorphism: IGlvEndomorphism);
  end;

  TWTauNafMultiplier = class sealed(TAbstractECMultiplier, IECMultiplier)
  strict private
    class var PRECOMP_NAME: String;
    function MultiplyWTnaf(const AP: IAbstractF2mPoint; const ALambda: IZTauElement;
      AA, AMu: ShortInt): IAbstractF2mPoint;
    class function MultiplyFromWTnaf(const AP: IAbstractF2mPoint;
      const AU: TCryptoLibShortIntArray): IAbstractF2mPoint; static;
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  public
    class constructor Create;
  end;

  TFixedPointCombMultiplier = class sealed(TAbstractECMultiplier, IECMultiplier)
  strict protected
    function MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint; override;
  end;

implementation

uses
  System.Math,
  ClpCryptoLibTypes,
  ClpECAlgorithms,
  ClpECPoint,
  ClpEndoUtilities,
  ClpFixedPointUtilities,
  ClpIFixedPointPreCompInfo,
  ClpNat,
  ClpBitOperations,
  ClpTnaf,
  ClpIWTauNafPreCompInfo,
  ClpWTauNafPreCompInfo;

{ TAbstractECMultiplier }

function TAbstractECMultiplier.CheckResult(const AP: IECPoint): IECPoint;
begin
  Result := TECAlgorithms.ImplCheckResult(AP);
end;

function TAbstractECMultiplier.Multiply(const APoint: IECPoint; const AK: TBigInteger): IECPoint;
var
  LSign: Int32;
  LPositive, LResult: IECPoint;
begin
  LSign := AK.SignValue;
  if (LSign = 0) or APoint.IsInfinity then
    Exit(APoint.Curve.Infinity);
  LPositive := MultiplyPositive(APoint, AK.Abs());
  if LSign > 0 then
    LResult := LPositive
  else
    LResult := LPositive.Negate();
  Result := CheckResult(LResult);
end;

{ TWNafL2RMultiplier }

function TWNafL2RMultiplier.MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint;
var
  LMinWidth, LWidth, LI, LWi, LDigit, LZeroes, LN, LHighest, LScale, LLowBits, LI1, LI2: Int32;
  LInfo: IWNafPreCompInfo;
  LPreComp, LPreCompNeg: TCryptoLibGenericArray<IECPoint>;
  LWnaf: TCryptoLibInt32Array;
  LTable: TCryptoLibGenericArray<IECPoint>;
  LR, LSmallR: IECPoint;
begin
  LMinWidth := TWNafUtilities.GetWindowSize(AK.BitLength);
  LInfo := TWNafUtilities.Precompute(AP, LMinWidth, True);
  LPreComp := LInfo.PreComp;
  LPreCompNeg := LInfo.PreCompNeg;
  LWidth := LInfo.Width;

  LWnaf := TWNafUtilities.GenerateCompactWindowNaf(LWidth, AK);
  LR := AP.Curve.Infinity;
  LI := System.Length(LWnaf);

  if LI > 1 then
  begin
    Dec(LI);
    LWi := LWnaf[LI];
    LDigit := TBitOperations.Asr32(LWi, 16);
    LZeroes := LWi and $FFFF;

    LN := System.Math.Abs(LDigit);
    if LDigit < 0 then
      LTable := LPreCompNeg
    else
      LTable := LPreComp;

    if (LN shl 2) < (1 shl LWidth) then
    begin
      LHighest := 32 - TBitOperations.NumberOfLeadingZeros32(UInt32(LN));
      LScale := LWidth - LHighest;
      LLowBits := LN xor (1 shl (LHighest - 1));
      LI1 := (1 shl (LWidth - 1)) - 1;
      LI2 := (LLowBits shl LScale) + 1;
      LR := LTable[TBitOperations.Asr32(LI1, 1)].Add(LTable[TBitOperations.Asr32(LI2, 1)]);
      Dec(LZeroes, LScale);
    end
    else
      LR := LTable[TBitOperations.Asr32(LN, 1)];

    LR := LR.TimesPow2(LZeroes);
  end;

  while LI > 0 do
  begin
    Dec(LI);
    LWi := LWnaf[LI];
    LDigit := TBitOperations.Asr32(LWi, 16);
    LZeroes := LWi and $FFFF;

    LN := System.Math.Abs(LDigit);
    if LDigit < 0 then
      LTable := LPreCompNeg
    else
      LTable := LPreComp;
    LSmallR := LTable[TBitOperations.Asr32(LN, 1)];

    LR := LR.TwicePlus(LSmallR);
    LR := LR.TimesPow2(LZeroes);
  end;

  Result := LR;
end;

{ TGlvMultiplier }

constructor TGlvMultiplier.Create(const ACurve: IECCurve; const AGlvEndomorphism: IGlvEndomorphism);
begin
  Inherited Create;
  if (ACurve = nil) or (not ACurve.Order.IsInitialized) then
    raise EArgumentCryptoLibException.Create('Need curve with known group order');
  FCurve := ACurve;
  FGlvEndomorphism := AGlvEndomorphism;
end;

function TGlvMultiplier.MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint;
var
  LN: TBigInteger;
  LAB: TCryptoLibGenericArray<TBigInteger>;
  LA, LB: TBigInteger;
  LQ: IECPoint;
begin
  if not FCurve.Equals(AP.Curve) then
    raise EInvalidOperationCryptoLibException.Create('');
  LN := AP.Curve.Order;
  LAB := FGlvEndomorphism.DecomposeScalar(AK.Mod(LN));
  LA := LAB[0];
  LB := LAB[1];
  if FGlvEndomorphism.HasEfficientPointMap then
    Result := TECAlgorithms.ImplShamirsTrickWNaf(FGlvEndomorphism as IECEndomorphism, AP, LA, LB)
  else
  begin
    LQ := TEndoUtilities.MapPoint(FGlvEndomorphism as IECEndomorphism, AP);
    Result := TECAlgorithms.ImplShamirsTrickWNaf(AP, LA, LQ, LB);
  end;
end;

{ TWTauNafMultiplier }

type
  TWTauNafCallback = class sealed(TInterfacedObject, IPreCompCallback)
  strict private
    FP: IAbstractF2mPoint;
    FA: ShortInt;
  public
    constructor Create(const AP: IAbstractF2mPoint; AA: ShortInt);
    function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
  end;

constructor TWTauNafCallback.Create(const AP: IAbstractF2mPoint; AA: ShortInt);
begin
  inherited Create;
  FP := AP;
  FA := AA;
end;

function TWTauNafCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LExisting: IWTauNafPreCompInfo;
  LResult: TWTauNafPreCompInfo;
begin
  if Supports(AExisting, IWTauNafPreCompInfo, LExisting) then
    Exit(AExisting);

  LResult := TWTauNafPreCompInfo.Create;
  LResult.PreComp := TTnaf.GetPreComp(FP, FA);
  Result := LResult;
end;

class constructor TWTauNafMultiplier.Create;
begin
  PRECOMP_NAME := 'bc_wtnaf';
end;

function TWTauNafMultiplier.MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint;
var
  LP: IAbstractF2mPoint;
  LCurve: IAbstractF2mCurve;
  LA, LMu: ShortInt;
  LRho: IZTauElement;
begin
  if not Supports(AP, IAbstractF2mPoint, LP) then
    raise EArgumentCryptoLibException.Create('Only AbstractF2mPoint can be used in WTauNafMultiplier');

  LCurve := LP.Curve as IAbstractF2mCurve;
  LA := ShortInt(LCurve.A.ToBigInteger().Int32Value);
  LMu := TTnaf.GetMu(LA);

  LRho := TTnaf.PartModReduction(LCurve, AK, LA, LMu, ShortInt(10));

  Result := MultiplyWTnaf(LP, LRho, LA, LMu);
end;

function TWTauNafMultiplier.MultiplyWTnaf(const AP: IAbstractF2mPoint;
  const ALambda: IZTauElement; AA, AMu: ShortInt): IAbstractF2mPoint;
var
  LAlpha: TCryptoLibGenericArray<IZTauElement>;
  LTw: TBigInteger;
  LU: TCryptoLibShortIntArray;
begin
  if AA = 0 then
    LAlpha := TTnaf.Alpha0
  else
    LAlpha := TTnaf.Alpha1;

  LTw := TTnaf.GetTw(AMu, TTnaf.Width);

  LU := TTnaf.TauAdicWNaf(AMu, ALambda, TTnaf.Width, LTw.Int32Value, LAlpha);

  Result := MultiplyFromWTnaf(AP, LU);
end;

class function TWTauNafMultiplier.MultiplyFromWTnaf(const AP: IAbstractF2mPoint;
  const AU: TCryptoLibShortIntArray): IAbstractF2mPoint;
var
  LCurve: IAbstractF2mCurve;
  LA: ShortInt;
  LCallback: IPreCompCallback;
  LPreCompInfo: IWTauNafPreCompInfo;
  LPu, LPuNeg: TCryptoLibGenericArray<IAbstractF2mPoint>;
  LQ: IAbstractF2mPoint;
  LTauCount, LI, LUi: Int32;
  LX: IECPoint;
begin
  LCurve := AP.Curve as IAbstractF2mCurve;
  LA := ShortInt(LCurve.A.ToBigInteger().Int32Value);

  LCallback := TWTauNafCallback.Create(AP, LA);
  LPreCompInfo := LCurve.Precompute(AP, PRECOMP_NAME, LCallback) as IWTauNafPreCompInfo;
  LPu := LPreCompInfo.PreComp;

  // TODO Include negations in precomp (optionally) and use from here
  SetLength(LPuNeg, System.Length(LPu));
  for LI := 0 to System.Length(LPu) - 1 do
    LPuNeg[LI] := LPu[LI].Negate() as IAbstractF2mPoint;

  // q = infinity
  LQ := AP.Curve.Infinity as IAbstractF2mPoint;

  LTauCount := 0;
  for LI := System.Length(AU) - 1 downto 0 do
  begin
    System.Inc(LTauCount);
    LUi := AU[LI];
    if LUi <> 0 then
    begin
      LQ := LQ.TauPow(LTauCount);
      LTauCount := 0;

      if LUi > 0 then
        LX := LPu[TBitOperations.Asr32(LUi, 1)]
      else
        LX := LPuNeg[TBitOperations.Asr32(-LUi, 1)];
      LQ := LQ.Add(LX) as IAbstractF2mPoint;
    end;
  end;
  if LTauCount > 0 then
    LQ := LQ.TauPow(LTauCount);

  Result := LQ;
end;

{ TFixedPointCombMultiplier }

function TFixedPointCombMultiplier.MultiplyPositive(const AP: IECPoint; const AK: TBigInteger): IECPoint;
var
  LC: IECCurve;
  LSize, LWidth, LD, LFullComb, LI, LJ: Int32;
  LInfo: IFixedPointPreCompInfo;
  LLookupTable: IECLookupTable;
  LK: TCryptoLibUInt32Array;
  LSecretIndex: UInt32;
  LSecretBit: UInt32;
  LR, LAdd: IECPoint;
begin
  LC := AP.Curve;
  LSize := TFixedPointUtilities.GetCombSize(LC);

  if AK.BitLength > LSize then
    raise EInvalidOperationCryptoLibException.Create(
      'fixed-point comb doesn''t support scalars larger than the curve order');

  LInfo := TFixedPointUtilities.Precompute(AP);
  LLookupTable := LInfo.LookupTable;
  LWidth := LInfo.Width;
  LD := (LSize + LWidth - 1) div LWidth;
  LFullComb := LD * LWidth;

  LK := TNat.FromBigInteger(LFullComb, AK);

  LR := LC.Infinity;

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

    LAdd := LLookupTable.Lookup(Int32(LSecretIndex));

    LR := LR.TwicePlus(LAdd);
  end;

  Result := LR.Add(LInfo.Offset);
end;

end.
