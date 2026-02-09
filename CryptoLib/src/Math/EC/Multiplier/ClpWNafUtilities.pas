{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpWNafUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpBigInteger,
  ClpIECCommon,
  ClpECCurve,
  ClpECCurveConstants,
  ClpECAlgorithms,
  ClpECPoint,
  ClpIECFieldElement,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpIWNafPreCompInfo,
  ClpWNafPreCompInfo,
  ClpCryptoLibTypes;

type
  TWNafUtilities = class sealed(TObject)
  strict private
    type
      TConfigureBasepointCallback = class sealed(TInterfacedObject, IPreCompCallback)
      strict private
        FCurve: IECCurve;
        FConfWidth: Int32;
      public
        constructor Create(const ACurve: IECCurve; AConfWidth: Int32);
        function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
      end;

      TMapPointCallback = class sealed(TInterfacedObject, IPreCompCallback)
      strict private
        FInfoP: IWNafPreCompInfo;
        FIncludeNegated: Boolean;
        FPointMap: IECPointMap;
      public
        constructor Create(const AInfoP: IWNafPreCompInfo; AIncludeNegated: Boolean;
          const APointMap: IECPointMap);
        function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
      end;

      TPrecomputeCallback = class sealed(TInterfacedObject, IPreCompCallback)
      strict private
        FP: IECPoint;
        FMinWidth: Int32;
        FIncludeNegated: Boolean;
        function CheckExisting(const AExistingWNaf: IWNafPreCompInfo; AWidth, AReqPreCompLen: Int32;
          AIncludeNegated: Boolean): Boolean;
        function CheckTable(const ATable: TCryptoLibGenericArray<IECPoint>; AReqLen: Int32): Boolean;
      public
        constructor Create(const AP: IECPoint; AMinWidth: Int32; AIncludeNegated: Boolean);
        function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
      end;

      TPrecomputeWithPointMapCallback = class sealed(TInterfacedObject, IPreCompCallback)
      strict private
        FPoint: IECPoint;
        FPointMap: IECPointMap;
        FFromWNaf: IWNafPreCompInfo;
        FIncludeNegated: Boolean;
        function CheckTable(const ATable: TCryptoLibGenericArray<IECPoint>; AReqLen: Int32): Boolean;
        function CheckExisting(const AExistingWNaf: IWNafPreCompInfo; AWidth, AReqPreCompLen: Int32;
          AIncludeNegated: Boolean): Boolean;
      public
        constructor Create(const APoint: IECPoint; const APointMap: IECPointMap;
          const AFromWNaf: IWNafPreCompInfo; AIncludeNegated: Boolean);
        function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
      end;

    class var
      FDefaultWindowSizeCutoffs: TCryptoLibInt32Array;
    class function GetWindowSize(ABits: Int32; const AWindowSizeCutoffs: TCryptoLibInt32Array;
      AMaxWidth: Int32): Int32; overload; static;
    class function Trim(const AArray: TCryptoLibInt32Array; ALength: Int32): TCryptoLibInt32Array; overload; static;
    class function Trim(const AArray: TCryptoLibByteArray; ALength: Int32): TCryptoLibByteArray; overload; static;
    class function ResizeTable(const AArray: TCryptoLibGenericArray<IECPoint>; ALength: Int32): TCryptoLibGenericArray<IECPoint>; static;
  public
    const
      PRECOMP_NAME = 'bc_wnaf';
      MAX_WIDTH = 16;
    class procedure ConfigureBasepoint(const AP: IECPoint); static;
    class function GetWindowSize(ABits: Int32): Int32; overload; static;
    class function GetWindowSize(ABits: Int32; AMaxWidth: Int32): Int32; overload; static;
    class function GetWindowSize(ABits: Int32; const AWindowSizeCutoffs: TCryptoLibInt32Array): Int32; overload; static;
    class function GenerateNaf(const AK: TBigInteger): TCryptoLibByteArray; static;
    class function GenerateCompactNaf(const AK: TBigInteger): TCryptoLibInt32Array; static;
    class function GenerateCompactWindowNaf(AWidth: Int32;
      const AK: TBigInteger): TCryptoLibInt32Array; static;
    class function GenerateWindowNaf(AWidth: Int32; const AK: TBigInteger): TCryptoLibByteArray; static;
    class function GenerateJsf(const AG, AH: TBigInteger): TCryptoLibByteArray; static;
    class function GetNafWeight(const AK: TBigInteger): Int32; static;
    class function GetWNafPreCompInfo(const AP: IECPoint): IWNafPreCompInfo; overload; static;
    class function GetWNafPreCompInfo(const APreCompInfo: IPreCompInfo): IWNafPreCompInfo; overload; static;
    class function Precompute(const AP: IECPoint; AMinWidth: Int32;
      AIncludeNegated: Boolean): IWNafPreCompInfo; static;
    class function PrecomputeWithPointMap(const AP: IECPoint; const APointMap: IECPointMap;
      const AFromWNaf: IWNafPreCompInfo; AIncludeNegated: Boolean): IWNafPreCompInfo; static;
  end;

implementation

constructor TWNafUtilities.TConfigureBasepointCallback.Create(const ACurve: IECCurve; AConfWidth: Int32);
begin
  Inherited Create;
  FCurve := ACurve;
  FConfWidth := AConfWidth;
end;

function TWNafUtilities.TConfigureBasepointCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LExistingWNaf: IWNafPreCompInfo;
  LResult: IWNafPreCompInfo;
begin
  if not Supports(AExisting, IWNafPreCompInfo, LExistingWNaf) then
    LExistingWNaf := nil;

  if (LExistingWNaf <> nil) and (LExistingWNaf.ConfWidth = FConfWidth) then
  begin
    LExistingWNaf.PromotionCountdown := 0;
    Result := LExistingWNaf;
    Exit;
  end;

  LResult := TWNafPreCompInfo.Create;
  LResult.PromotionCountdown := 0;
  LResult.ConfWidth := FConfWidth;

  if LExistingWNaf <> nil then
  begin
    LResult.PreComp := LExistingWNaf.PreComp;
    LResult.PreCompNeg := LExistingWNaf.PreCompNeg;
    LResult.Twice := LExistingWNaf.Twice;
    LResult.Width := LExistingWNaf.Width;
  end;

  Result := LResult;
end;

constructor TWNafUtilities.TMapPointCallback.Create(const AInfoP: IWNafPreCompInfo;
  AIncludeNegated: Boolean; const APointMap: IECPointMap);
begin
  Inherited Create;
  FInfoP := AInfoP;
  FIncludeNegated := AIncludeNegated;
  FPointMap := APointMap;
end;

function TWNafUtilities.TMapPointCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LResult: IWNafPreCompInfo;
  LTwiceP: IECPoint;
  LPreCompP, LPreCompQ, LPreCompNegQ: TCryptoLibGenericArray<IECPoint>;
  LI: Int32;
begin
  LResult := TWNafPreCompInfo.Create;
  LResult.ConfWidth := FInfoP.ConfWidth;

  LTwiceP := FInfoP.Twice;
  if LTwiceP <> nil then
    LResult.Twice := FPointMap.Map(LTwiceP);

  LPreCompP := FInfoP.PreComp;
  System.SetLength(LPreCompQ, System.Length(LPreCompP));
  for LI := 0 to System.Length(LPreCompP) - 1 do
    LPreCompQ[LI] := FPointMap.Map(LPreCompP[LI]);
  LResult.PreComp := LPreCompQ;
  LResult.Width := FInfoP.Width;

  if FIncludeNegated then
  begin
    System.SetLength(LPreCompNegQ, System.Length(LPreCompQ));
    for LI := 0 to System.Length(LPreCompNegQ) - 1 do
      LPreCompNegQ[LI] := LPreCompQ[LI].Negate();
    LResult.PreCompNeg := LPreCompNegQ;
  end;

  Result := LResult;
end;

constructor TWNafUtilities.TPrecomputeCallback.Create(const AP: IECPoint; AMinWidth: Int32; AIncludeNegated: Boolean);
begin
  inherited Create;
  FP := AP;
  FMinWidth := AMinWidth;
  FIncludeNegated := AIncludeNegated;
end;

function TWNafUtilities.TPrecomputeCallback.CheckTable(const ATable: TCryptoLibGenericArray<IECPoint>;
  AReqLen: Int32): Boolean;
begin
  Result := (ATable <> nil) and (System.Length(ATable) >= AReqLen);
end;

function TWNafUtilities.TPrecomputeCallback.CheckExisting(const AExistingWNaf: IWNafPreCompInfo;
  AWidth, AReqPreCompLen: Int32; AIncludeNegated: Boolean): Boolean;
var
  LConfWidth: Int32;
begin
  if AExistingWNaf = nil then
    Exit(False);
  LConfWidth := AExistingWNaf.ConfWidth;
  Result := (AExistingWNaf.Width >= Math.Max(LConfWidth, AWidth)) and
    CheckTable(AExistingWNaf.PreComp, AReqPreCompLen) and
    (not AIncludeNegated or CheckTable(AExistingWNaf.PreCompNeg, AReqPreCompLen));
end;

function TWNafUtilities.TPrecomputeCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LExistingWNaf: IWNafPreCompInfo;
  LResultInfo: IWNafPreCompInfo;
  LC: IECCurve;
  LPreComp, LPreCompNeg: TCryptoLibGenericArray<IECPoint>;
  LTwiceP: IECPoint;
  LWidth, LReqPreCompLen, LIniPreCompLen, LCurPreCompLen, LPos: Int32;
  LLast, LIsoTwiceP: IECPoint;
  LIso, LIso2, LIso3: IECFieldElement;
begin
  if not Supports(AExisting, IWNafPreCompInfo, LExistingWNaf) then
    LExistingWNaf := nil;

  LWidth := Math.Max(2, Math.Min(TWNafUtilities.MAX_WIDTH, FMinWidth));
  LReqPreCompLen := 1 shl (LWidth - 2);

  if CheckExisting(LExistingWNaf, LWidth, LReqPreCompLen, FIncludeNegated) then
  begin
    LExistingWNaf.DecrementPromotionCountdown;
    Result := LExistingWNaf;
    Exit;
  end;

  LResultInfo := TWNafPreCompInfo.Create;
  LC := FP.Curve;
  LPreComp := nil;
  LPreCompNeg := nil;
  LTwiceP := nil;

  if LExistingWNaf <> nil then
  begin
    LResultInfo.PromotionCountdown := LExistingWNaf.DecrementPromotionCountdown;
    LResultInfo.ConfWidth := LExistingWNaf.ConfWidth;
    LPreComp := LExistingWNaf.PreComp;
    LPreCompNeg := LExistingWNaf.PreCompNeg;
    LTwiceP := LExistingWNaf.Twice;
  end;

  LWidth := Math.Min(TWNafUtilities.MAX_WIDTH, Math.Max(LResultInfo.ConfWidth, LWidth));
  LReqPreCompLen := 1 shl (LWidth - 2);

  LIniPreCompLen := 0;
  if LPreComp <> nil then
    LIniPreCompLen := System.Length(LPreComp);

  LIso := nil;
  if LIniPreCompLen < LReqPreCompLen then
  begin
    LPreComp := TWNafUtilities.ResizeTable(LPreComp, LReqPreCompLen);

    if LReqPreCompLen = 1 then
      LPreComp[0] := FP.Normalize()
    else
    begin
      LCurPreCompLen := LIniPreCompLen;
      if LCurPreCompLen = 0 then
      begin
        LPreComp[0] := FP;
        LCurPreCompLen := 1;
      end;

      if LReqPreCompLen = 2 then
        LPreComp[1] := FP.ThreeTimes()
      else
      begin
        LLast := LPreComp[LCurPreCompLen - 1];
        if LTwiceP = nil then
        begin
          LIsoTwiceP := LPreComp[0].Twice();
          LTwiceP := LIsoTwiceP;
          { Fp quasi-isomorphism: affine twiceP and scale last for cheaper additions }
          if (not LIsoTwiceP.IsInfinity) and TECAlgorithms.IsFpCurve(LC) and
            (LC.FieldSize >= 64) then
            case LC.CoordinateSystem of
              TECCurveConstants.COORD_JACOBIAN, TECCurveConstants.COORD_JACOBIAN_CHUDNOVSKY,
              TECCurveConstants.COORD_JACOBIAN_MODIFIED:
                begin
                  LIso := LIsoTwiceP.GetZCoord(0);
                  LIsoTwiceP := LC.CreatePoint(LIsoTwiceP.XCoord.ToBigInteger(),
                    LIsoTwiceP.YCoord.ToBigInteger());
                  LIso2 := LIso.Square();
                  LIso3 := LIso2.Multiply(LIso);
                  LLast := LLast.ScaleX(LIso2).ScaleY(LIso3);
                  if LIniPreCompLen = 0 then
                    LPreComp[0] := LLast;
                end;
            end;
        end
        else
          LIsoTwiceP := LTwiceP;
        while LCurPreCompLen < LReqPreCompLen do
        begin
          LPreComp[LCurPreCompLen] := LLast.Add(LIsoTwiceP);
          LLast := LPreComp[LCurPreCompLen];
          Inc(LCurPreCompLen);
        end;
      end;

      LC.NormalizeAll(LPreComp, LIniPreCompLen, LReqPreCompLen - LIniPreCompLen, LIso);
    end;
  end;

  if FIncludeNegated then
  begin
    if LPreCompNeg = nil then
      LPos := 0
    else
      LPos := System.Length(LPreCompNeg);
    if LPos < LReqPreCompLen then
    begin
      SetLength(LPreCompNeg, LReqPreCompLen);
      while LPos < LReqPreCompLen do
      begin
        LPreCompNeg[LPos] := LPreComp[LPos].Negate();
        Inc(LPos);
      end;
    end;
  end;

  LResultInfo.PreComp := LPreComp;
  LResultInfo.PreCompNeg := LPreCompNeg;
  LResultInfo.Twice := LTwiceP;
  LResultInfo.Width := LWidth;
  Result := LResultInfo;
end;

constructor TWNafUtilities.TPrecomputeWithPointMapCallback.Create(const APoint: IECPoint;
  const APointMap: IECPointMap; const AFromWNaf: IWNafPreCompInfo; AIncludeNegated: Boolean);
begin
  inherited Create;
  FPoint := APoint;
  FPointMap := APointMap;
  FFromWNaf := AFromWNaf;
  FIncludeNegated := AIncludeNegated;
end;

function TWNafUtilities.TPrecomputeWithPointMapCallback.CheckTable(
  const ATable: TCryptoLibGenericArray<IECPoint>; AReqLen: Int32): Boolean;
begin
  Result := (ATable <> nil) and (System.Length(ATable) >= AReqLen);
end;

function TWNafUtilities.TPrecomputeWithPointMapCallback.CheckExisting(
  const AExistingWNaf: IWNafPreCompInfo; AWidth, AReqPreCompLen: Int32;
  AIncludeNegated: Boolean): Boolean;
begin
  Result := (AExistingWNaf <> nil) and (AExistingWNaf.Width >= AWidth) and
    CheckTable(AExistingWNaf.PreComp, AReqPreCompLen) and
    (not AIncludeNegated or CheckTable(AExistingWNaf.PreCompNeg, AReqPreCompLen));
end;

function TWNafUtilities.TPrecomputeWithPointMapCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LExistingWNaf: IWNafPreCompInfo;
  LResultInfo: IWNafPreCompInfo;
  LWidth, LReqPreCompLen, LI: Int32;
  LPreCompFrom, LPreComp, LPreCompNeg: TCryptoLibGenericArray<IECPoint>;
  LTwiceFrom: IECPoint;
begin
  if not Supports(AExisting, IWNafPreCompInfo, LExistingWNaf) then
    LExistingWNaf := nil;

  LWidth := FFromWNaf.Width;
  LReqPreCompLen := System.Length(FFromWNaf.PreComp);

  if CheckExisting(LExistingWNaf, LWidth, LReqPreCompLen, FIncludeNegated) then
  begin
    LExistingWNaf.DecrementPromotionCountdown;
    Result := LExistingWNaf;
    Exit;
  end;

  LResultInfo := TWNafPreCompInfo.Create;
  LResultInfo.PromotionCountdown := FFromWNaf.PromotionCountdown;

  LTwiceFrom := FFromWNaf.Twice;
  if LTwiceFrom <> nil then
    LResultInfo.Twice := FPointMap.Map(LTwiceFrom);

  LPreCompFrom := FFromWNaf.PreComp;
  System.SetLength(LPreComp, System.Length(LPreCompFrom));
  for LI := 0 to System.High(LPreCompFrom) do
    LPreComp[LI] := FPointMap.Map(LPreCompFrom[LI]);
  LResultInfo.PreComp := LPreComp;
  LResultInfo.Width := LWidth;

  if FIncludeNegated then
  begin
    System.SetLength(LPreCompNeg, System.Length(LPreComp));
    for LI := 0 to System.High(LPreComp) do
      LPreCompNeg[LI] := LPreComp[LI].Negate();
    LResultInfo.PreCompNeg := LPreCompNeg;
  end;

  Result := LResultInfo;
end;

{ TWNafUtilities }

class procedure TWNafUtilities.ConfigureBasepoint(const AP: IECPoint);
var
  LC: IECCurve;
  LBits: Int32;
  LConfWidth: Int32;
  LOrder: TBigInteger;
begin
  LC := AP.Curve;
  if LC = nil then
    Exit;

  LOrder := LC.Order;
  if not LOrder.IsInitialized then
    LBits := LC.FieldSize + 1
  else
    LBits := LOrder.BitLength;

  LConfWidth := Math.Min(MAX_WIDTH, GetWindowSize(LBits) + 3);
  LC.Precompute(AP, PRECOMP_NAME,
    TWNafUtilities.TConfigureBasepointCallback.Create(LC, LConfWidth) as IPreCompCallback);
end;

class function TWNafUtilities.GetWindowSize(ABits: Int32): Int32;
begin
  if FDefaultWindowSizeCutoffs = nil then
    FDefaultWindowSizeCutoffs := TCryptoLibInt32Array.Create(13, 41, 121, 337, 897, 2305);
  Result := GetWindowSize(ABits, FDefaultWindowSizeCutoffs, MAX_WIDTH);
end;

class function TWNafUtilities.GetWindowSize(ABits: Int32; AMaxWidth: Int32): Int32;
begin
  if FDefaultWindowSizeCutoffs = nil then
    FDefaultWindowSizeCutoffs := TCryptoLibInt32Array.Create(13, 41, 121, 337, 897, 2305);
  Result := GetWindowSize(ABits, FDefaultWindowSizeCutoffs, AMaxWidth);
end;

class function TWNafUtilities.GetWindowSize(ABits: Int32; const AWindowSizeCutoffs: TCryptoLibInt32Array): Int32;
begin
  Result := GetWindowSize(ABits, AWindowSizeCutoffs, MAX_WIDTH);
end;

class function TWNafUtilities.GetWindowSize(ABits: Int32;
  const AWindowSizeCutoffs: TCryptoLibInt32Array; AMaxWidth: Int32): Int32;
var
  LW: Int32;
begin
  LW := 0;
  while (LW < System.Length(AWindowSizeCutoffs)) and (ABits >= AWindowSizeCutoffs[LW]) do
    Inc(LW);
  Result := Math.Max(2, Math.Min(AMaxWidth, LW + 2));
end;

class function TWNafUtilities.Trim(const AArray: TCryptoLibInt32Array;
  ALength: Int32): TCryptoLibInt32Array;
var
  LI: Int32;
begin
  System.SetLength(Result, ALength);
  for LI := 0 to ALength - 1 do
    Result[LI] := AArray[LI];
end;

class function TWNafUtilities.Trim(const AArray: TCryptoLibByteArray;
  ALength: Int32): TCryptoLibByteArray;
var
  LI: Int32;
begin
  System.SetLength(Result, ALength);
  for LI := 0 to ALength - 1 do
    Result[LI] := AArray[LI];
end;

class function TWNafUtilities.ResizeTable(const AArray: TCryptoLibGenericArray<IECPoint>;
  ALength: Int32): TCryptoLibGenericArray<IECPoint>;
var
  LI, LLen: Int32;
begin
  System.SetLength(Result, ALength);
  if AArray <> nil then
  begin
    LLen := Math.Min(System.Length(AArray), ALength);
    for LI := 0 to LLen - 1 do
      Result[LI] := AArray[LI];
  end;
end;

class function TWNafUtilities.GenerateNaf(const AK: TBigInteger): TCryptoLibByteArray;
var
  L3k, LDiff: TBigInteger;
  LDigits, LI: Int32;
  LDigit: ShortInt;
begin
  if AK.SignValue = 0 then
  begin
    Result := nil;
    Exit;
  end;
  L3k := AK.ShiftLeft(1).Add(AK);
  LDigits := L3k.BitLength - 1;
  System.SetLength(Result, LDigits);
  TArrayUtilities.Fill<Byte>(Result, 0, LDigits, Byte(0));
  LDiff := L3k.&Xor(AK);
  LI := 1;
  while LI < LDigits do
  begin
    if LDiff.TestBit(LI) then
    begin
      if AK.TestBit(LI) then
        LDigit := -1
      else
        LDigit := 1;
      Result[LI - 1] := Byte(LDigit);
      Inc(LI);
    end;
    Inc(LI);
  end;
  Result[LDigits - 1] := 1;
end;

class function TWNafUtilities.GenerateWindowNaf(AWidth: Int32;
  const AK: TBigInteger): TCryptoLibByteArray;
var
  LPow2, LMask, LSign, LLength, LPos: Int32;
  LK: TBigInteger;
  LDigit, LResultLength: Int32;
  LCarry: Boolean;
begin
  if AWidth = 2 then
  begin
    Result := GenerateNaf(AK);
    Exit;
  end;
  if (AWidth < 2) or (AWidth > 8) then
    raise EArgumentCryptoLibException.Create('must be in the range [2, 8]');
  if AK.SignValue = 0 then
  begin
    Result := nil;
    Exit;
  end;
  LResultLength := AK.BitLength + 1;
  System.SetLength(Result, LResultLength);
  TArrayUtilities.Fill<Byte>(Result, 0, LResultLength, Byte(0));
  LPow2 := 1 shl AWidth;
  LMask := LPow2 - 1;
  LSign := TBitOperations.Asr32(LPow2, 1);
  LCarry := False;
  LLength := 0;
  LPos := 0;
  LK := AK;
  while LPos <= LK.BitLength do
  begin
    if (LK.TestBit(LPos) = LCarry) then
    begin
      Inc(LPos);
      continue;
    end;
    LK := LK.ShiftRight(LPos);
    LDigit := LK.Int32Value and LMask;
    if LCarry then
      Inc(LDigit);
    LCarry := (LDigit and LSign) <> 0;
    if LCarry then
      LDigit := LDigit - LPow2;
    if LLength > 0 then
      Inc(LLength, LPos - 1)
    else
      Inc(LLength, LPos);
    Result[LLength] := Byte(LDigit);
    Inc(LLength);
    LPos := AWidth;
  end;
  if System.Length(Result) > LLength then
    Result := Trim(Result, LLength);
end;

class function TWNafUtilities.GenerateJsf(const AG, AH: TBigInteger): TCryptoLibByteArray;
var
  LDigits, LJ, Ld0, Ld1, LOffset, Ln0, Ln1, Lu0, Lu1: Int32;
  LJsf: TCryptoLibByteArray;
  LK0, LK1: TBigInteger;
begin
  LDigits := Math.Max(AG.BitLength, AH.BitLength) + 1;
  System.SetLength(LJsf, LDigits);
  TArrayUtilities.Fill<Byte>(LJsf, 0, LDigits, Byte(0));
  LK0 := AG;
  LK1 := AH;
  LJ := 0;
  Ld0 := 0;
  Ld1 := 0;
  LOffset := 0;
  while ((Ld0 or Ld1) <> 0) or (LK0.BitLength > LOffset) or (LK1.BitLength > LOffset) do
  begin
    Ln0 := (Int32(UInt32(LK0.Int32Value) shr LOffset) + Ld0) and 7;
    Ln1 := (Int32(UInt32(LK1.Int32Value) shr LOffset) + Ld1) and 7;
    Lu0 := Ln0 and 1;
    if Lu0 <> 0 then
    begin
      Lu0 := Lu0 - (Ln0 and 2);
      if (Ln0 + Lu0 = 4) and (Ln1 and 3 = 2) then
        Lu0 := -Lu0;
    end;
    Lu1 := Ln1 and 1;
    if Lu1 <> 0 then
    begin
      Lu1 := Lu1 - (Ln1 and 2);
      if (Ln1 + Lu1 = 4) and (Ln0 and 3 = 2) then
        Lu1 := -Lu1;
    end;
    if (Ld0 shl 1) = 1 + Lu0 then
      Ld0 := Ld0 xor 1;
    if (Ld1 shl 1) = 1 + Lu1 then
      Ld1 := Ld1 xor 1;
    Inc(LOffset);
    if LOffset = 30 then
    begin
      LOffset := 0;
      LK0 := LK0.ShiftRight(30);
      LK1 := LK1.ShiftRight(30);
    end;
    LJsf[LJ] := Byte((Lu0 shl 4) or (Lu1 and $0F));
    Inc(LJ);
  end;
  if System.Length(LJsf) > LJ then
    Result := Trim(LJsf, LJ)
  else
    Result := LJsf;
end;

class function TWNafUtilities.GetNafWeight(const AK: TBigInteger): Int32;
var
  L3k, LDiff: TBigInteger;
begin
  if AK.SignValue = 0 then
    Exit(0);
  L3k := AK.ShiftLeft(1).Add(AK);
  LDiff := L3k.&Xor(AK);
  Result := LDiff.BitCount;
end;

class function TWNafUtilities.GetWNafPreCompInfo(const AP: IECPoint): IWNafPreCompInfo;
begin
  Result := GetWNafPreCompInfo(AP.Curve.GetPreCompInfo(AP, PRECOMP_NAME));
end;

class function TWNafUtilities.GetWNafPreCompInfo(const APreCompInfo: IPreCompInfo): IWNafPreCompInfo;
var
  LWNaf: IWNafPreCompInfo;
begin
  if Supports(APreCompInfo, IWNafPreCompInfo, LWNaf) then
    Result := LWNaf
  else
    Result := nil;
end;

class function TWNafUtilities.GenerateCompactNaf(const AK: TBigInteger): TCryptoLibInt32Array;
var
  L3k, LDiff: TBigInteger;
  LBits, LHighBit, LLength, LZeroes, LI: Int32;
  LDigit, LResultLength: Int32;
begin
  if TBitOperations.Asr32(AK.BitLength, 16) <> 0 then
    raise EArgumentCryptoLibException.Create('must have bitlength < 2^16');
  if AK.SignValue = 0 then
  begin
    Result := nil;
    Exit;
  end;
  L3k := AK.ShiftLeft(1).Add(AK);
  LBits := L3k.BitLength;
  LResultLength := TBitOperations.Asr32(LBits, 1);
  System.SetLength(Result, LResultLength);
  TArrayUtilities.Fill<Int32>(Result, 0, LResultLength, Int32(0));
  LDiff := L3k.&Xor(AK);
  LHighBit := LBits - 1;
  LLength := 0;
  LZeroes := 0;
  LI := 1;
  while LI < LHighBit do
  begin
    if not LDiff.TestBit(LI) then
    begin
      Inc(LZeroes);
      Inc(LI);
      continue;
    end;
    if AK.TestBit(LI) then
      LDigit := -1
    else
      LDigit := 1;
    Result[LLength] := (LDigit shl 16) or LZeroes;
    Inc(LLength);
    LZeroes := 1;
    Inc(LI, 2);
  end;
  Result[LLength] := (1 shl 16) or LZeroes;
  Inc(LLength);
  if System.Length(Result) > LLength then
    Result := Trim(Result, LLength);
end;

class function TWNafUtilities.GenerateCompactWindowNaf(AWidth: Int32;
  const AK: TBigInteger): TCryptoLibInt32Array;
var
  LPow2, LMask, LSign, LLength, LPos, LDigit, LZeroes, LResultLength: Int32;
  LK: TBigInteger;
  LCarry: Boolean;
begin
  if AWidth = 2 then
  begin
    Result := GenerateCompactNaf(AK);
    Exit;
  end;
  if (AWidth < 2) or (AWidth > 16) then
    raise EArgumentCryptoLibException.Create('must be in the range [2, 16]');
  if TBitOperations.Asr32(AK.BitLength, 16) <> 0 then
    raise EArgumentCryptoLibException.Create('must have bitlength < 2^16');
  if AK.SignValue = 0 then
  begin
    Result := nil;
    Exit;
  end;
  LResultLength := AK.BitLength div AWidth + 1;
  System.SetLength(Result, LResultLength);
  TArrayUtilities.Fill<Int32>(Result, 0, LResultLength, Int32(0));
  LPow2 := 1 shl AWidth;
  LMask := LPow2 - 1;
  LSign := TBitOperations.Asr32(LPow2, 1);
  LCarry := False;
  LLength := 0;
  LPos := 0;
  LK := AK;

  while LPos <= LK.BitLength do
  begin
    if LK.TestBit(LPos) = LCarry then
    begin
      Inc(LPos);
      continue;
    end;
    LK := LK.ShiftRight(LPos);
    LDigit := LK.Int32Value and LMask;
    if LCarry then
      Inc(LDigit);
    LCarry := (LDigit and LSign) <> 0;
    if LCarry then
      LDigit := LDigit - LPow2;
    if LLength > 0 then
      LZeroes := LPos - 1
    else
      LZeroes := LPos;
    Result[LLength] := (LDigit shl 16) or LZeroes;
    Inc(LLength);
    LPos := AWidth;
  end;

  if System.Length(Result) > LLength then
    Result := Trim(Result, LLength);
end;

class function TWNafUtilities.PrecomputeWithPointMap(const AP: IECPoint;
  const APointMap: IECPointMap; const AFromWNaf: IWNafPreCompInfo;
  AIncludeNegated: Boolean): IWNafPreCompInfo;
var
  LResult: IPreCompInfo;
  LPreCompCallback: IPreCompCallback;
  LWNaf: IWNafPreCompInfo;
begin
  LPreCompCallback := TWNafUtilities.TPrecomputeWithPointMapCallback.Create(AP, APointMap, AFromWNaf, AIncludeNegated);
  LResult := AP.Curve.Precompute(AP, PRECOMP_NAME, LPreCompCallback);
  if not Supports(LResult, IWNafPreCompInfo, LWNaf) then
    raise EInvalidCastCryptoLibException.Create('Expected IWNafPreCompInfo');
  Result := LWNaf;
end;

class function TWNafUtilities.Precompute(const AP: IECPoint; AMinWidth: Int32;
  AIncludeNegated: Boolean): IWNafPreCompInfo;
var
  LResult: IPreCompInfo;
  LPreCompCallback: IPreCompCallback;
  LWNaf: IWNafPreCompInfo;
begin
  LPreCompCallback := TWNafUtilities.TPrecomputeCallback.Create(AP, AMinWidth, AIncludeNegated);
  LResult := AP.Curve.Precompute(AP, PRECOMP_NAME, LPreCompCallback);
  if not Supports(LResult, IWNafPreCompInfo, LWNaf) then
    raise EInvalidCastCryptoLibException.Create('Expected IWNafPreCompInfo');
  Result := LWNaf;
end;

end.
