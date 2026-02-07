{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpECAlgorithms;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIECCore,
  ClpIECFieldElement,
  ClpIFiniteField,
  ClpIPolynomialExtensionField,
  ClpCryptoLibTypes;

type
  TECAlgorithms = class(TObject)
  public
    class procedure MontgomeryTrick(const AZs: TCryptoLibGenericArray<IECFieldElement>;
      AOff, ALen: Int32); overload; static;
    class procedure MontgomeryTrick(const AZs: TCryptoLibGenericArray<IECFieldElement>;
      AOff, ALen: Int32; const AScale: IECFieldElement); overload; static;  // AZs modified in place
    class function ReferenceMultiply(const AP: IECPoint; const AK: TBigInteger): IECPoint; static;
    class function ValidatePoint(const AP: IECPoint): IECPoint; static;
    class function CleanPoint(const AC: IECCurve; const AP: IECPoint): IECPoint; static;
    class function ImportPoint(const AC: IECCurve; const AP: IECPoint): IECPoint; static;
    class function SumOfMultiplies(const APs: TCryptoLibGenericArray<IECPoint>;
      const AKs: TCryptoLibGenericArray<TBigInteger>): IECPoint; static;
    class function SumOfTwoMultiplies(const AP: IECPoint; const AK: TBigInteger;
      const AQ: IECPoint; const AL: TBigInteger): IECPoint; static;
    class function ShamirsTrick(const AP: IECPoint; const AK: TBigInteger;
      const AQ: IECPoint; const AL: TBigInteger): IECPoint; static;
    class function IsFpCurve(const AC: IECCurve): Boolean; static;
    class function IsFpField(const AField: IFiniteField): Boolean; static;
    class function IsF2mCurve(const AC: IECCurve): Boolean; static;
    class function IsF2mField(const AField: IFiniteField): Boolean; static;
    class function ImplCheckResult(const AP: IECPoint): IECPoint; static;
    class function ImplShamirsTrickJsf(const AP: IECPoint; const AK: TBigInteger;
      const AQ: IECPoint; const AL: TBigInteger): IECPoint; static;
    class function ImplShamirsTrickWNaf(const AP: IECPoint; const AK: TBigInteger;
      const AQ: IECPoint; const AL: TBigInteger): IECPoint; overload; static;
    class function ImplShamirsTrickWNaf(const AEndomorphism: IECEndomorphism;
      const AP: IECPoint; const AK: TBigInteger; const AL: TBigInteger): IECPoint; overload; static;
    class function ImplShamirsTrickWNaf(
      const APreCompP, APreCompNegP: TCryptoLibGenericArray<IECPoint>;
      const AWnafP: TCryptoLibByteArray;
      const APreCompQ, APreCompNegQ: TCryptoLibGenericArray<IECPoint>;
      const AWnafQ: TCryptoLibByteArray): IECPoint; overload; static;
    class function ImplShamirsTrickFixedPoint(const AP: IECPoint; const AK: TBigInteger;
      const AQ: IECPoint; const AL: TBigInteger): IECPoint; static;
    class function ImplSumOfMultiplies(const APs: TCryptoLibGenericArray<IECPoint>;
      const AKs: TCryptoLibGenericArray<TBigInteger>): IECPoint; overload; static;
    class function ImplSumOfMultiplies(const AEndomorphism: IECEndomorphism;
      const APs: TCryptoLibGenericArray<IECPoint>;
      const AKs: TCryptoLibGenericArray<TBigInteger>): IECPoint; overload; static;
    class function ImplSumOfMultiplies(
      const ANegs: TCryptoLibBooleanArray;
      const AInfos: TCryptoLibGenericArray<IWNafPreCompInfo>;
      const AWnafs: TCryptoLibGenericArray<TCryptoLibByteArray>): IECPoint; overload; static;
    class function ImplSumOfMultipliesGlv(const APs: TCryptoLibGenericArray<IECPoint>;
      const AKs: TCryptoLibGenericArray<TBigInteger>;
      const AGlvEndomorphism: IGlvEndomorphism): IECPoint; static;
  end;

implementation

uses
  System.Math,
  ClpBitOperations,
  ClpECCurve,
  ClpFixedPointUtilities,
  ClpIFixedPointPreCompInfo,
  ClpFixedPointPreCompInfo,
  ClpMultipliers,
  ClpWNafUtilities,
  ClpWNafPreCompInfo,
  ClpEndoUtilities,
  ClpNat,
  ClpCryptoLibTypes;

{ TECAlgorithms }

class procedure TECAlgorithms.MontgomeryTrick(
  const AZs: TCryptoLibGenericArray<IECFieldElement>; AOff, ALen: Int32);
begin
  MontgomeryTrick(AZs, AOff, ALen, nil);
end;

class procedure TECAlgorithms.MontgomeryTrick(
  const AZs: TCryptoLibGenericArray<IECFieldElement>; AOff, ALen: Int32;
  const AScale: IECFieldElement);
var
  LC: TCryptoLibGenericArray<IECFieldElement>;
  I, J: Int32;
  LU: IECFieldElement;
  LTmp: IECFieldElement;
begin
  System.SetLength(LC, ALen);
  LC[0] := AZs[AOff];

  I := 0;
  while I + 1 < ALen do
  begin
    Inc(I);
    LC[I] := LC[I - 1].Multiply(AZs[AOff + I]);
  end;

  if AScale <> nil then
    LC[I] := LC[I].Multiply(AScale);

  LU := LC[I].Invert();

  while I > 0 do
  begin
    J := AOff + I;
    Dec(I);
    LTmp := AZs[J];
    AZs[J] := LC[I].Multiply(LU);
    LU := LU.Multiply(LTmp);
  end;

  AZs[AOff] := LU;
end;

class function TECAlgorithms.ReferenceMultiply(const AP: IECPoint;
  const AK: TBigInteger): IECPoint;
var
  LX: TBigInteger;
  LP, LQ: IECPoint;
  LT, LI: Int32;
begin
  LX := AK.Abs();
  LQ := AP.Curve.Infinity;
  LT := LX.BitLength;
  if LT > 0 then
  begin
    if LX.TestBit(0) then
      LQ := AP;
    LP := AP;
    LI := 1;
    while LI < LT do
    begin
      LP := LP.Twice();
      if LX.TestBit(LI) then
        LQ := LQ.Add(LP);
      Inc(LI);
    end;
  end;
  if AK.SignValue < 0 then
    Result := LQ.Negate()
  else
    Result := LQ;
end;

class function TECAlgorithms.ValidatePoint(const AP: IECPoint): IECPoint;
begin
  if not AP.IsValid() then
    raise EInvalidOperationCryptoLibException.Create('Invalid point');
  Result := AP;
end;

class function TECAlgorithms.CleanPoint(const AC: IECCurve; const AP: IECPoint): IECPoint;
var
  LEncoded: TCryptoLibByteArray;
  LCurve: IECCurve;
begin
  LCurve := AP.Curve;
  if not AC.Equals(LCurve) then
    raise EArgumentCryptoLibException.Create('Point must be on the same curve');
  LEncoded := AP.GetEncoded(False);
  Result := AC.DecodePoint(LEncoded);
end;

class function TECAlgorithms.ImportPoint(const AC: IECCurve; const AP: IECPoint): IECPoint;
var
  LCurve: IECCurve;
begin
  LCurve := AP.Curve;
  if not AC.Equals(LCurve) then
    raise EArgumentCryptoLibException.Create('Point must be on the same curve');
  Result := AC.ImportPoint(AP);
end;

class function TECAlgorithms.SumOfMultiplies(const APs: TCryptoLibGenericArray<IECPoint>;
  const AKs: TCryptoLibGenericArray<TBigInteger>): IECPoint;
var
  LCount, I: Int32;
  LP: IECPoint;
  LC: IECCurve;
  LImported: TCryptoLibGenericArray<IECPoint>;
  LGlv: IGlvEndomorphism;
begin
  if (APs = nil) or (AKs = nil) or (System.Length(APs) <> System.Length(AKs)) or
    (System.Length(APs) < 1) then
    raise EArgumentCryptoLibException.Create(
      'point and scalar arrays should be non-null, and of equal, non-zero, length');
  LCount := System.Length(APs);
  case LCount of
    1:
      Exit(APs[0].Multiply(AKs[0]));
    2:
      Exit(SumOfTwoMultiplies(APs[0], AKs[0], APs[1], AKs[1]));
  else
    ;
  end;
  LP := APs[0];
  LC := LP.Curve;
  System.SetLength(LImported, LCount);
  LImported[0] := LP;
  I := 1;
  while I < LCount do
  begin
    LImported[I] := ImportPoint(LC, APs[I]);
    Inc(I);
  end;
  if Supports(LC.GetEndomorphism(), IGlvEndomorphism, LGlv) then
    Result := ImplCheckResult(ImplSumOfMultipliesGlv(LImported, AKs, LGlv))
  else
    Result := ImplCheckResult(ImplSumOfMultiplies(LImported, AKs));
end;

class function TECAlgorithms.ShamirsTrick(const AP: IECPoint; const AK: TBigInteger;
  const AQ: IECPoint; const AL: TBigInteger): IECPoint;
var
  LCp: IECCurve;
  LQ: IECPoint;
begin
  LCp := AP.Curve;
  LQ := ImportPoint(LCp, AQ);
  Result := ImplCheckResult(ImplShamirsTrickJsf(AP, AK, LQ, AL));
end;

class function TECAlgorithms.SumOfTwoMultiplies(const AP: IECPoint; const AK: TBigInteger;
  const AQ: IECPoint; const AL: TBigInteger): IECPoint;
var
  LCurve: IECCurve;
  LQ: IECPoint;
  LF2mCurve: IAbstractF2mCurve;
  LGlv: IGlvEndomorphism;
begin
  LCurve := AP.Curve;
  LQ := ImportPoint(LCurve, AQ);

  if Supports(LCurve, IAbstractF2mCurve, LF2mCurve) and LF2mCurve.IsKoblitz then
  begin
    Result := ImplCheckResult(AP.Multiply(AK).Add(LQ.Multiply(AL)));
    Exit;
  end;
  if Supports(LCurve.GetEndomorphism(), IGlvEndomorphism, LGlv) then
  begin
    Result := ImplCheckResult(ImplSumOfMultipliesGlv(
      TCryptoLibGenericArray<IECPoint>.Create(AP, LQ),
      TCryptoLibGenericArray<TBigInteger>.Create(AK, AL), LGlv));
    Exit;
  end;

  Result := ImplCheckResult(ImplShamirsTrickWNaf(AP, AK, LQ, AL));
end;

class function TECAlgorithms.IsFpCurve(const AC: IECCurve): Boolean;
begin
  Result := IsFpField(AC.Field);
end;

class function TECAlgorithms.IsFpField(const AField: IFiniteField): Boolean;
begin
  Result := AField.Dimension = 1;
end;

class function TECAlgorithms.IsF2mCurve(const AC: IECCurve): Boolean;
begin
  Result := IsF2mField(AC.Field);
end;

class function TECAlgorithms.IsF2mField(const AField: IFiniteField): Boolean;
begin
  Result := (AField.Dimension > 1) and
    AField.Characteristic.Equals(TBigInteger.Two) and
    Supports(AField, IPolynomialExtensionField);
end;

class function TECAlgorithms.ImplCheckResult(const AP: IECPoint): IECPoint;
begin
  if not AP.IsValidPartial() then
    raise EInvalidOperationCryptoLibException.Create('Invalid result');
  Result := AP;
end;

class function TECAlgorithms.ImplShamirsTrickJsf(const AP: IECPoint; const AK: TBigInteger;
  const AQ: IECPoint; const AL: TBigInteger): IECPoint;
var
  LCurve: IECCurve;
  LInfinity, LPaddQ, LPsubQ: IECPoint;
  LPoints: TCryptoLibGenericArray<IECPoint>;
  LTable: TCryptoLibGenericArray<IECPoint>;
  LJsf: TCryptoLibByteArray;
  LI, LJsfi, LKDigit, LLDigit, LIndex: Int32;
  LR: IECPoint;
begin
  LCurve := AP.Curve;
  LInfinity := LCurve.Infinity;
  LPaddQ := AP.Add(AQ);
  LPsubQ := AP.Subtract(AQ);
  LPoints := TCryptoLibGenericArray<IECPoint>.Create(AQ, LPsubQ, AP, LPaddQ);
  LCurve.NormalizeAll(LPoints);
  LTable := TCryptoLibGenericArray<IECPoint>.Create(
    LPoints[3].Negate(), LPoints[2].Negate(), LPoints[1].Negate(),
    LPoints[0].Negate(), LInfinity, LPoints[0],
    LPoints[1], LPoints[2], LPoints[3]);
  LJsf := TWNafUtilities.GenerateJsf(AK, AL);
  LR := LInfinity;
  LI := System.Length(LJsf);
  while LI > 0 do
  begin
    Dec(LI);
    LJsfi := Int32(LJsf[LI]);
    LKDigit := TBitOperations.Asr32(Int32(LJsfi shl 24), 28);
    LLDigit := TBitOperations.Asr32(Int32(LJsfi shl 28), 28);
    LIndex := 4 + (LKDigit * 3) + LLDigit;
    LR := LR.TwicePlus(LTable[LIndex]);
  end;
  Result := LR;
end;

class function TECAlgorithms.ImplShamirsTrickWNaf(const AP: IECPoint; const AK: TBigInteger;
  const AQ: IECPoint; const AL: TBigInteger): IECPoint;
var
  LNegK, LNegL: Boolean;
  LKAbs, LLAbs: TBigInteger;
  LCombSize, LMinWidthP, LMinWidthQ, LWidthP, LWidthQ: Int32;
  LInfoP, LInfoQ: IWNafPreCompInfo;
  LPreCompP, LPreCompQ, LPreCompNegP, LPreCompNegQ: TCryptoLibGenericArray<IECPoint>;
  LWnafP, LWnafQ: TCryptoLibByteArray;
begin
  LNegK := AK.SignValue < 0;
  LNegL := AL.SignValue < 0;
  LKAbs := AK.Abs();
  LLAbs := AL.Abs();
  LMinWidthP := TWNafUtilities.GetWindowSize(LKAbs.BitLength, 8);
  LMinWidthQ := TWNafUtilities.GetWindowSize(LLAbs.BitLength, 8);
  LInfoP := TWNafUtilities.Precompute(AP, LMinWidthP, True);
  LInfoQ := TWNafUtilities.Precompute(AQ, LMinWidthQ, True);
  LCombSize := TFixedPointUtilities.GetCombSize(AP.Curve);
  if (not LNegK) and (not LNegL) and (AK.BitLength <= LCombSize) and (AL.BitLength <= LCombSize)
    and LInfoP.IsPromoted and LInfoQ.IsPromoted then
    Exit(ImplShamirsTrickFixedPoint(AP, AK, AQ, AL));
  LWidthP := System.Math.Min(8, LInfoP.Width);
  LWidthQ := System.Math.Min(8, LInfoQ.Width);
  if LNegK then
  begin
    LPreCompP := LInfoP.PreCompNeg;
    LPreCompNegP := LInfoP.PreComp;
  end
  else
  begin
    LPreCompP := LInfoP.PreComp;
    LPreCompNegP := LInfoP.PreCompNeg;
  end;
  if LNegL then
  begin
    LPreCompQ := LInfoQ.PreCompNeg;
    LPreCompNegQ := LInfoQ.PreComp;
  end
  else
  begin
    LPreCompQ := LInfoQ.PreComp;
    LPreCompNegQ := LInfoQ.PreCompNeg;
  end;
  LWnafP := TWNafUtilities.GenerateWindowNaf(LWidthP, LKAbs);
  LWnafQ := TWNafUtilities.GenerateWindowNaf(LWidthQ, LLAbs);
  Result := ImplShamirsTrickWNaf(LPreCompP, LPreCompNegP, LWnafP, LPreCompQ, LPreCompNegQ, LWnafQ);
end;

class function TECAlgorithms.ImplShamirsTrickFixedPoint(const AP: IECPoint; const AK: TBigInteger;
  const AQ: IECPoint; const AL: TBigInteger): IECPoint;
var
  LC: IECCurve;
  LCombSize, LWidthP, LWidthQ, LWidth, LD, LFullComb, LI, LJ: Int32;
  LInfoP, LInfoQ: IFixedPointPreCompInfo;
  LLookupTableP, LLookupTableQ: IECLookupTable;
  LK, LL: TCryptoLibUInt32Array;
  LSecretIndexK, LSecretIndexL: UInt32;
  LSecretBitK, LSecretBitL: UInt32;
  LR, LAddP, LAddQ, LT: IECPoint;
  LMultiplier: IECMultiplier;
begin
  LC := AP.Curve;
  LCombSize := TFixedPointUtilities.GetCombSize(LC);
  if (AK.BitLength > LCombSize) or (AL.BitLength > LCombSize) then
    raise EInvalidOperationCryptoLibException.Create(
      'fixed-point comb doesn''t support scalars larger than the curve order');
  LInfoP := TFixedPointUtilities.Precompute(AP);
  LInfoQ := TFixedPointUtilities.Precompute(AQ);
  LLookupTableP := LInfoP.LookupTable;
  LLookupTableQ := LInfoQ.LookupTable;
  LWidthP := LInfoP.Width;
  LWidthQ := LInfoQ.Width;
  if LWidthP <> LWidthQ then
  begin
    LMultiplier := TFixedPointCombMultiplier.Create() as IECMultiplier;
    Result := LMultiplier.Multiply(AP, AK).Add(LMultiplier.Multiply(AQ, AL));
    Exit;
  end;
  LWidth := LWidthP;
  LD := (LCombSize + LWidth - 1) div LWidth;
  LFullComb := LD * LWidth;
  LK := TNat.FromBigInteger(LFullComb, AK);
  LL := TNat.FromBigInteger(LFullComb, AL);
  LR := LC.Infinity;
  for LI := 1 to LD do
  begin
    LSecretIndexK := 0;
    LSecretIndexL := 0;
    LJ := LFullComb - LI;
    while LJ >= 0 do
    begin
      LSecretBitK := LK[TBitOperations.Asr32(LJ, 5)] shr (LJ and $1F);
      LSecretIndexK := LSecretIndexK xor (LSecretBitK shr 1);
      LSecretIndexK := LSecretIndexK shl 1;
      LSecretIndexK := LSecretIndexK xor LSecretBitK;

      LSecretBitL := LL[TBitOperations.Asr32(LJ, 5)] shr (LJ and $1F);
      LSecretIndexL := LSecretIndexL xor (LSecretBitL shr 1);
      LSecretIndexL := LSecretIndexL shl 1;
      LSecretIndexL := LSecretIndexL xor LSecretBitL;
      LJ := LJ - LD;
    end;
    LAddP := LLookupTableP.LookupVar(Int32(LSecretIndexK));
    LAddQ := LLookupTableQ.LookupVar(Int32(LSecretIndexL));
    LT := LAddP.Add(LAddQ);
    LR := LR.TwicePlus(LT);
  end;
  Result := LR.Add(LInfoP.Offset).Add(LInfoQ.Offset);
end;

class function TECAlgorithms.ImplShamirsTrickWNaf(const AEndomorphism: IECEndomorphism;
  const AP: IECPoint; const AK: TBigInteger; const AL: TBigInteger): IECPoint;
var
  LNegK, LNegL: Boolean;
  LK, LL: TBigInteger;
  LMinWidth, LWidthP, LWidthQ: Int32;
  LInfoP, LInfoQ: IWNafPreCompInfo;
  LQ: IECPoint;
  LPreCompP, LPreCompQ, LPreCompNegP, LPreCompNegQ: TCryptoLibGenericArray<IECPoint>;
  LWnafP, LWnafQ: TCryptoLibByteArray;
begin
  LNegK := AK.SignValue < 0;
  LNegL := AL.SignValue < 0;
  LK := AK.Abs();
  LL := AL.Abs();
  LMinWidth := TWNafUtilities.GetWindowSize(System.Math.Max(LK.BitLength, LL.BitLength), 8);
  LInfoP := TWNafUtilities.Precompute(AP, LMinWidth, True);
  LQ := TEndoUtilities.MapPoint(AEndomorphism, AP);
  LInfoQ := TWNafUtilities.PrecomputeWithPointMap(LQ, AEndomorphism.PointMap, LInfoP, True);
  LWidthP := System.Math.Min(8, LInfoP.Width);
  LWidthQ := System.Math.Min(8, LInfoQ.Width);
  if LNegK then
  begin
    LPreCompP := LInfoP.PreCompNeg;
    LPreCompNegP := LInfoP.PreComp;
  end
  else
  begin
    LPreCompP := LInfoP.PreComp;
    LPreCompNegP := LInfoP.PreCompNeg;
  end;
  if LNegL then
  begin
    LPreCompQ := LInfoQ.PreCompNeg;
    LPreCompNegQ := LInfoQ.PreComp;
  end
  else
  begin
    LPreCompQ := LInfoQ.PreComp;
    LPreCompNegQ := LInfoQ.PreCompNeg;
  end;
  LWnafP := TWNafUtilities.GenerateWindowNaf(LWidthP, LK);
  LWnafQ := TWNafUtilities.GenerateWindowNaf(LWidthQ, LL);
  Result := ImplShamirsTrickWNaf(LPreCompP, LPreCompNegP, LWnafP, LPreCompQ, LPreCompNegQ, LWnafQ);
end;

class function TECAlgorithms.ImplShamirsTrickWNaf(
  const APreCompP, APreCompNegP: TCryptoLibGenericArray<IECPoint>;
  const AWnafP: TCryptoLibByteArray;
  const APreCompQ, APreCompNegQ: TCryptoLibGenericArray<IECPoint>;
  const AWnafQ: TCryptoLibByteArray): IECPoint;
var
  LLen, LI, LWiP, LWiQ, LZeroes, LnP, LnQ: Int32;
  LCurve: IECCurve;
  LInfinity, LR, LSmallR: IECPoint;
  LTableP, LTableQ: TCryptoLibGenericArray<IECPoint>;
begin
  LLen := System.Math.Max(System.Length(AWnafP), System.Length(AWnafQ));
  LCurve := APreCompP[0].Curve;
  LInfinity := LCurve.Infinity;
  LR := LInfinity;
  LZeroes := 0;
  LI := LLen;
  while LI > 0 do
  begin
    Dec(LI);
    if LI < System.Length(AWnafP) then
      LWiP := Int32(ShortInt(AWnafP[LI]))
    else
      LWiP := 0;
    if LI < System.Length(AWnafQ) then
      LWiQ := Int32(ShortInt(AWnafQ[LI]))
    else
      LWiQ := 0;
    if (LWiP or LWiQ) = 0 then
    begin
      Inc(LZeroes);
      continue;
    end;
    LSmallR := LInfinity;
    if LWiP <> 0 then
    begin
      LnP := System.Math.Abs(LWiP);
      if LWiP < 0 then
        LTableP := APreCompNegP
      else
        LTableP := APreCompP;
      LSmallR := LSmallR.Add(LTableP[TBitOperations.Asr32(LnP, 1)]);
    end;
    if LWiQ <> 0 then
    begin
      LnQ := System.Math.Abs(LWiQ);
      if LWiQ < 0 then
        LTableQ := APreCompNegQ
      else
        LTableQ := APreCompQ;
      LSmallR := LSmallR.Add(LTableQ[TBitOperations.Asr32(LnQ, 1)]);
    end;
    if LZeroes > 0 then
    begin
      LR := LR.TimesPow2(LZeroes);
      LZeroes := 0;
    end;
    LR := LR.TwicePlus(LSmallR);
  end;
  if LZeroes > 0 then
    LR := LR.TimesPow2(LZeroes);
  Result := LR;
end;

class function TECAlgorithms.ImplSumOfMultiplies(const APs: TCryptoLibGenericArray<IECPoint>;
  const AKs: TCryptoLibGenericArray<TBigInteger>): IECPoint;
var
  LCount, I, LMinWidth, LWidth: Int32;
  LKi: TBigInteger;
  LNegs: TCryptoLibBooleanArray;
  LInfos: TCryptoLibGenericArray<IWNafPreCompInfo>;
  LWnafs: TCryptoLibGenericArray<TCryptoLibByteArray>;
begin
  LCount := System.Length(APs);
  System.SetLength(LNegs, LCount);
  System.SetLength(LInfos, LCount);
  System.SetLength(LWnafs, LCount);
  for I := 0 to LCount - 1 do
  begin
    LKi := AKs[I];
    LNegs[I] := LKi.SignValue < 0;
    LKi := LKi.Abs();
    LMinWidth := TWNafUtilities.GetWindowSize(LKi.BitLength, 8);
    LInfos[I] := TWNafUtilities.Precompute(APs[I], LMinWidth, True);
    LWidth := System.Math.Min(8, LInfos[I].Width);
    LWnafs[I] := TWNafUtilities.GenerateWindowNaf(LWidth, LKi);
  end;
  Result := ImplSumOfMultiplies(LNegs, LInfos, LWnafs);
end;

class function TECAlgorithms.ImplSumOfMultipliesGlv(const APs: TCryptoLibGenericArray<IECPoint>;
  const AKs: TCryptoLibGenericArray<TBigInteger>;
  const AGlvEndomorphism: IGlvEndomorphism): IECPoint;
var
  LN: TBigInteger;
  LLen, I, J: Int32;
  LAbs: TCryptoLibGenericArray<TBigInteger>;
  LAbPair: TCryptoLibGenericArray<TBigInteger>;
  LPqs: TCryptoLibGenericArray<IECPoint>;
  LP: IECPoint;
begin
  LN := APs[0].Curve.Order;
  LLen := System.Length(APs);
  System.SetLength(LAbs, LLen shl 1);
  J := 0;
  for I := 0 to LLen - 1 do
  begin
    LAbPair := AGlvEndomorphism.DecomposeScalar(AKs[I].Mod(LN));
    LAbs[J] := LAbPair[0];
    Inc(J);
    LAbs[J] := LAbPair[1];
    Inc(J);
  end;
  if AGlvEndomorphism.HasEfficientPointMap then
    Result := ImplSumOfMultiplies(AGlvEndomorphism as IECEndomorphism, APs, LAbs)
  else
  begin
    System.SetLength(LPqs, LLen shl 1);
    J := 0;
    for I := 0 to LLen - 1 do
    begin
      LP := APs[I];
      LPqs[J] := LP;
      Inc(J);
      LPqs[J] := TEndoUtilities.MapPoint(AGlvEndomorphism as IECEndomorphism, LP);
      Inc(J);
    end;
    Result := ImplSumOfMultiplies(LPqs, LAbs);
  end;
end;

class function TECAlgorithms.ImplSumOfMultiplies(const AEndomorphism: IECEndomorphism;
  const APs: TCryptoLibGenericArray<IECPoint>;
  const AKs: TCryptoLibGenericArray<TBigInteger>): IECPoint;
var
  LHalfCount, LFullCount, I, J0, J1: Int32;
  LKj0, LKj1: TBigInteger;
  LNegs: TCryptoLibBooleanArray;
  LInfos: TCryptoLibGenericArray<IWNafPreCompInfo>;
  LWnafs: TCryptoLibGenericArray<TCryptoLibByteArray>;
  LMinWidth, LWidthP, LWidthQ: Int32;
  LP, LQ: IECPoint;
  LPointMap: IECPointMap;
  LInfoP, LInfoQ: IWNafPreCompInfo;
begin
  LHalfCount := System.Length(APs);
  LFullCount := LHalfCount shl 1;
  System.SetLength(LNegs, LFullCount);
  System.SetLength(LInfos, LFullCount);
  System.SetLength(LWnafs, LFullCount);
  for I := 0 to LHalfCount - 1 do
  begin
    J0 := I shl 1;
    J1 := J0 + 1;
    LKj0 := AKs[J0];
    LNegs[J0] := LKj0.SignValue < 0;
    LKj0 := LKj0.Abs();
    LKj1 := AKs[J1];
    LNegs[J1] := LKj1.SignValue < 0;
    LKj1 := LKj1.Abs();
    LMinWidth := TWNafUtilities.GetWindowSize(
      System.Math.Max(LKj0.BitLength, LKj1.BitLength), 8);
    LP := APs[I];
    LInfoP := TWNafUtilities.Precompute(LP, LMinWidth, True);
    LQ := TEndoUtilities.MapPoint(AEndomorphism, LP);
    LPointMap := AEndomorphism.PointMap;
    LInfoQ := TWNafUtilities.PrecomputeWithPointMap(LQ, LPointMap, LInfoP, True);
    LWidthP := System.Math.Min(8, LInfoP.Width);
    LWidthQ := System.Math.Min(8, LInfoQ.Width);
    LInfos[J0] := LInfoP;
    LInfos[J1] := LInfoQ;
    LWnafs[J0] := TWNafUtilities.GenerateWindowNaf(LWidthP, LKj0);
    LWnafs[J1] := TWNafUtilities.GenerateWindowNaf(LWidthQ, LKj1);
  end;
  Result := ImplSumOfMultiplies(LNegs, LInfos, LWnafs);
end;

class function TECAlgorithms.ImplSumOfMultiplies(
  const ANegs: TCryptoLibBooleanArray;
  const AInfos: TCryptoLibGenericArray<IWNafPreCompInfo>;
  const AWnafs: TCryptoLibGenericArray<TCryptoLibByteArray>): IECPoint;
var
  LLen, LCount, I, J, LWi, LN, LZeroes: Int32;
  LCurve: IECCurve;
  LInfinity, LR, LSmallR: IECPoint;
  LWnaf: TCryptoLibByteArray;
  LInfo: IWNafPreCompInfo;
  LTable: TCryptoLibGenericArray<IECPoint>;
begin
  LLen := 0;
  LCount := System.Length(AWnafs);
  for I := 0 to LCount - 1 do
    LLen := System.Math.Max(LLen, System.Length(AWnafs[I]));
  LCurve := AInfos[0].PreComp[0].Curve;
  LInfinity := LCurve.Infinity;
  LR := LInfinity;
  LZeroes := 0;
  I := LLen;
  while I > 0 do
  begin
    Dec(I);
    LSmallR := LInfinity;
    for J := 0 to LCount - 1 do
    begin
      LWnaf := AWnafs[J];
      if I < System.Length(LWnaf) then
        LWi := Int32(ShortInt(LWnaf[I]))
      else
        LWi := 0;
      if LWi <> 0 then
      begin
        LN := System.Math.Abs(LWi);
        LInfo := AInfos[J];
        if (LWi < 0) = ANegs[J] then
          LTable := LInfo.PreComp
        else
          LTable := LInfo.PreCompNeg;
        LSmallR := LSmallR.Add(LTable[TBitOperations.Asr32(LN, 1)]);
      end;
    end;
    if LSmallR = LInfinity then
    begin
      Inc(LZeroes);
      continue;
    end;
    if LZeroes > 0 then
    begin
      LR := LR.TimesPow2(LZeroes);
      LZeroes := 0;
    end;
    LR := LR.TwicePlus(LSmallR);
  end;
  if LZeroes > 0 then
    LR := LR.TimesPow2(LZeroes);
  Result := LR;
end;

end.
