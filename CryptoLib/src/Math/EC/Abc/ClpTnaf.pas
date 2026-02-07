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

unit ClpTnaf;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIZTauElement,
  ClpZTauElement,
  ClpSimpleBigDecimal,
  ClpECPoint,
  ClpIECCore,
  ClpIECFieldElement,
  ClpIPreCompCallback,
  ClpIPreCompInfo,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes;

resourcestring
  SMuMustBe1OrMinus1 = 'mu must be 1 or -1';
  SNoKoblitzCurve = 'No Koblitz curve (ABC), TNAF multiplication not possible';
  SSiDefinedForKoblitzOnly = 'si is defined for Koblitz curves only';
  SCofactorMustBe2Or4 = 'h (Cofactor) must be 2 or 4';
  SOnlyAbstractF2mPointAllowed = 'Only AbstractF2mPoint can be used in WTauNafMultiplier';

type
  TTnaf = class sealed(TObject)
  strict private
    type
      IPartModPreCompInfo = interface(IPreCompInfo)
        ['{B1C2D3E4-F5A6-7890-BCDE-F23456789012}']
        function GetLucas: TBigInteger;
        function GetS0: TBigInteger;
        function GetS1: TBigInteger;
        property Lucas: TBigInteger read GetLucas;
        property S0: TBigInteger read GetS0;
        property S1: TBigInteger read GetS1;
      end;

      TPartModPreCompInfo = class sealed(TInterfacedObject, IPreCompInfo, IPartModPreCompInfo)
      strict private
        FLucas: TBigInteger;
        FS0: TBigInteger;
        FS1: TBigInteger;
        function GetLucas: TBigInteger;
        function GetS0: TBigInteger;
        function GetS1: TBigInteger;
      public
        constructor Create(const ALucas, AS0, AS1: TBigInteger);
      end;

      TPartModPreCompCallback = class sealed(TInterfacedObject, IPreCompCallback)
      strict private
        FCurve: IAbstractF2mCurve;
        FMu: ShortInt;
        FDoV: Boolean;
      public
        constructor Create(const ACurve: IAbstractF2mCurve; AMu: ShortInt; ADoV: Boolean);
        function Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
      end;

    class var
      FMinusOne: TBigInteger;
      FMinusTwo: TBigInteger;
      FMinusThree: TBigInteger;
      FFour: TBigInteger;

    class function GetShiftsForCofactor(const AH: TBigInteger): Int32; static;
  public
    const
      Width: ShortInt = 4;
      PRECOMP_NAME = 'bc_tnaf_partmod';

    class var
      Alpha0: TCryptoLibGenericArray<IZTauElement>;
      Alpha0Tnaf: TCryptoLibMatrixShortIntArray;
      Alpha1: TCryptoLibGenericArray<IZTauElement>;
      Alpha1Tnaf: TCryptoLibMatrixShortIntArray;

    class constructor Create;

    class function Norm(AMu: ShortInt; const ALambda: IZTauElement): TBigInteger; overload; static;
    class function Norm(AMu: ShortInt; const AU, AV: TSimpleBigDecimal): TSimpleBigDecimal; overload; static;

    class function Round(const ALambda0, ALambda1: TSimpleBigDecimal;
      AMu: ShortInt): IZTauElement; static;

    class function ApproximateDivisionByN(const AK, AS_, AVm: TBigInteger;
      AA: ShortInt; AM, AC: Int32): TSimpleBigDecimal; static;

    class function TauAdicNaf(AMu: ShortInt; const ALambda: IZTauElement): TCryptoLibShortIntArray; static;

    class function Tau(const AP: IAbstractF2mPoint): IAbstractF2mPoint; static;

    class function GetMu(const ACurve: IAbstractF2mCurve): ShortInt; overload; static;
    class function GetMu(const ACurveA: IECFieldElement): ShortInt; overload; static;
    class function GetMu(ACurveA: Int32): ShortInt; overload; static;

    class function GetLucas(AMu: ShortInt; AK: Int32; ADoV: Boolean): TCryptoLibGenericArray<TBigInteger>; static;

    class function GetTw(AMu: ShortInt; AW: Int32): TBigInteger; static;

    class function GetSi(const ACurve: IAbstractF2mCurve): TCryptoLibGenericArray<TBigInteger>; overload; static;
    class function GetSi(AFieldSize, ACurveA: Int32; const ACofactor: TBigInteger): TCryptoLibGenericArray<TBigInteger>; overload; static;

    class function PartModReduction(const ACurve: IAbstractF2mCurve;
      const AK: TBigInteger; AA, AMu, AC: ShortInt): IZTauElement; static;

    class function MultiplyRTnaf(const AP: IAbstractF2mPoint;
      const AK: TBigInteger): IAbstractF2mPoint; static;

    class function MultiplyTnaf(const AP: IAbstractF2mPoint;
      const ALambda: IZTauElement): IAbstractF2mPoint; static;

    class function MultiplyFromTnaf(const AP, APNeg: IAbstractF2mPoint;
      const AU: TCryptoLibShortIntArray): IAbstractF2mPoint; static;

    class function TauAdicWNaf(AMu: ShortInt; const ALambda: IZTauElement;
      AWidth, ATw: Int32; const AAlpha: TCryptoLibGenericArray<IZTauElement>): TCryptoLibShortIntArray; static;

    class function GetPreComp(const AP: IAbstractF2mPoint;
      AA: ShortInt): TCryptoLibGenericArray<IAbstractF2mPoint>; static;
  end;

implementation

{ TTnaf.TPartModPreCompInfo }

constructor TTnaf.TPartModPreCompInfo.Create(const ALucas, AS0, AS1: TBigInteger);
begin
  inherited Create;
  FLucas := ALucas;
  FS0 := AS0;
  FS1 := AS1;
end;

function TTnaf.TPartModPreCompInfo.GetLucas: TBigInteger;
begin
  Result := FLucas;
end;

function TTnaf.TPartModPreCompInfo.GetS0: TBigInteger;
begin
  Result := FS0;
end;

function TTnaf.TPartModPreCompInfo.GetS1: TBigInteger;
begin
  Result := FS1;
end;

{ TTnaf.TPartModPreCompCallback }

constructor TTnaf.TPartModPreCompCallback.Create(const ACurve: IAbstractF2mCurve;
  AMu: ShortInt; ADoV: Boolean);
begin
  inherited Create;
  FCurve := ACurve;
  FMu := AMu;
  FDoV := ADoV;
end;

function TTnaf.TPartModPreCompCallback.Precompute(const AExisting: IPreCompInfo): IPreCompInfo;
var
  LPartMod: IPartModPreCompInfo;
  LLucas: TBigInteger;
  LSi: TCryptoLibGenericArray<TBigInteger>;
begin
  if Supports(AExisting, IPartModPreCompInfo, LPartMod) then
    Exit(LPartMod);

  if FCurve.IsKoblitz then
  begin
    // Koblitz path -- Jerome A. Solinas, (21)
    LLucas := TBigInteger.One.ShiftLeft(FCurve.FieldSize)
      .Add(TBigInteger.One)
      .Subtract(FCurve.Order.Multiply(FCurve.Cofactor));
  end
  else
  begin
    LLucas := TTnaf.GetLucas(FMu, FCurve.FieldSize, FDoV)[1];
  end;

  LSi := TTnaf.GetSi(FCurve);

  Result := TTnaf.TPartModPreCompInfo.Create(LLucas, LSi[0], LSi[1]);
end;

{ TTnaf }

class constructor TTnaf.Create;
begin
  FMinusOne := TBigInteger.One.Negate();
  FMinusTwo := TBigInteger.Two.Negate();
  FMinusThree := TBigInteger.Three.Negate();
  FFour := TBigInteger.Four;

  Alpha0 := TCryptoLibGenericArray<IZTauElement>.Create(
    nil, TZTauElement.Create(TBigInteger.One, TBigInteger.Zero) as IZTauElement,
    nil, TZTauElement.Create(FMinusThree, FMinusOne) as IZTauElement,
    nil, TZTauElement.Create(FMinusOne, FMinusOne) as IZTauElement,
    nil, TZTauElement.Create(TBigInteger.One, FMinusOne) as IZTauElement,
    nil, TZTauElement.Create(FMinusOne, TBigInteger.One) as IZTauElement,
    nil, TZTauElement.Create(TBigInteger.One, TBigInteger.One) as IZTauElement,
    nil, TZTauElement.Create(TBigInteger.Three, TBigInteger.One) as IZTauElement,
    nil, TZTauElement.Create(FMinusOne, TBigInteger.Zero) as IZTauElement
  );

  Alpha0Tnaf := TCryptoLibMatrixShortIntArray.Create(
    nil, TCryptoLibShortIntArray.Create(1),
    nil, TCryptoLibShortIntArray.Create(-1, 0, 1),
    nil, TCryptoLibShortIntArray.Create(1, 0, 1),
    nil, TCryptoLibShortIntArray.Create(-1, 0, 0, 1)
  );

  Alpha1 := TCryptoLibGenericArray<IZTauElement>.Create(
    nil, TZTauElement.Create(TBigInteger.One, TBigInteger.Zero) as IZTauElement,
    nil, TZTauElement.Create(FMinusThree, TBigInteger.One) as IZTauElement,
    nil, TZTauElement.Create(FMinusOne, TBigInteger.One) as IZTauElement,
    nil, TZTauElement.Create(TBigInteger.One, TBigInteger.One) as IZTauElement,
    nil, TZTauElement.Create(FMinusOne, FMinusOne) as IZTauElement,
    nil, TZTauElement.Create(TBigInteger.One, FMinusOne) as IZTauElement,
    nil, TZTauElement.Create(TBigInteger.Three, FMinusOne) as IZTauElement,
    nil, TZTauElement.Create(FMinusOne, TBigInteger.Zero) as IZTauElement
  );

  Alpha1Tnaf := TCryptoLibMatrixShortIntArray.Create(
    nil, TCryptoLibShortIntArray.Create(1),
    nil, TCryptoLibShortIntArray.Create(-1, 0, 1),
    nil, TCryptoLibShortIntArray.Create(1, 0, 1),
    nil, TCryptoLibShortIntArray.Create(-1, 0, 0, -1)
  );
end;

class function TTnaf.Norm(AMu: ShortInt; const ALambda: IZTauElement): TBigInteger;
var
  LS1: TBigInteger;
begin
  // s1 = u^2
  LS1 := ALambda.U.Square();

  if AMu = 1 then
  begin
    Result := ALambda.V.ShiftLeft(1).Add(ALambda.U).Multiply(ALambda.V).Add(LS1);
  end
  else if AMu = -1 then
  begin
    Result := ALambda.V.ShiftLeft(1).Subtract(ALambda.U).Multiply(ALambda.V).Add(LS1);
  end
  else
    raise EArgumentCryptoLibException.Create(SMuMustBe1OrMinus1);
end;

class function TTnaf.Norm(AMu: ShortInt; const AU, AV: TSimpleBigDecimal): TSimpleBigDecimal;
var
  LS1, LS2, LS3, LNorm: TSimpleBigDecimal;
begin
  // s1 = u^2
  LS1 := AU.Multiply(AU);
  // s2 = u * v
  LS2 := AU.Multiply(AV);
  // s3 = 2 * v^2
  LS3 := AV.Multiply(AV).ShiftLeft(1);

  if AMu = 1 then
  begin
    LNorm := LS1.Add(LS2).Add(LS3);
  end
  else if AMu = -1 then
  begin
    LNorm := LS1.Subtract(LS2).Add(LS3);
  end
  else
    raise EArgumentCryptoLibException.Create(SMuMustBe1OrMinus1);

  Result := LNorm;
end;

class function TTnaf.Round(const ALambda0, ALambda1: TSimpleBigDecimal;
  AMu: ShortInt): IZTauElement;
var
  LScale: Int32;
  LF0, LF1: TBigInteger;
  LEta0, LEta1, LEta: TSimpleBigDecimal;
  LThreeEta1, LFourEta1, LCheck1, LCheck2: TSimpleBigDecimal;
  LH0, LH1: ShortInt;
  LQ0, LQ1: TBigInteger;
begin
  LScale := ALambda0.Scale;
  if ALambda1.Scale <> LScale then
    raise EArgumentCryptoLibException.Create('lambda0 and lambda1 do not have same scale');

  if not ((AMu = 1) or (AMu = -1)) then
    raise EArgumentCryptoLibException.Create(SMuMustBe1OrMinus1);

  LF0 := ALambda0.Round();
  LF1 := ALambda1.Round();

  LEta0 := ALambda0.Subtract(LF0);
  LEta1 := ALambda1.Subtract(LF1);

  // eta = 2*eta0 + mu*eta1
  LEta := LEta0.Add(LEta0);
  if AMu = 1 then
    LEta := LEta.Add(LEta1)
  else
    LEta := LEta.Subtract(LEta1);

  // check1 = eta0 - 3*mu*eta1
  // check2 = eta0 + 4*mu*eta1
  LThreeEta1 := LEta1.Add(LEta1).Add(LEta1);
  LFourEta1 := LThreeEta1.Add(LEta1);
  if AMu = 1 then
  begin
    LCheck1 := LEta0.Subtract(LThreeEta1);
    LCheck2 := LEta0.Add(LFourEta1);
  end
  else
  begin
    LCheck1 := LEta0.Add(LThreeEta1);
    LCheck2 := LEta0.Subtract(LFourEta1);
  end;

  LH0 := 0;
  LH1 := 0;

  // if eta >= 1
  if LEta.CompareTo(TBigInteger.One) >= 0 then
  begin
    if LCheck1.CompareTo(FMinusOne) < 0 then
      LH1 := AMu
    else
      LH0 := 1;
  end
  else
  begin
    // eta < 1
    if LCheck2.CompareTo(TBigInteger.Two) >= 0 then
      LH1 := AMu;
  end;

  // if eta < -1
  if LEta.CompareTo(FMinusOne) < 0 then
  begin
    if LCheck1.CompareTo(TBigInteger.One) >= 0 then
      LH1 := ShortInt(-AMu)
    else
      LH0 := -1;
  end
  else
  begin
    // eta >= -1
    if LCheck2.CompareTo(FMinusTwo) < 0 then
      LH1 := ShortInt(-AMu);
  end;

  LQ0 := LF0.Add(TBigInteger.ValueOf(LH0));
  LQ1 := LF1.Add(TBigInteger.ValueOf(LH1));
  Result := TZTauElement.Create(LQ0, LQ1) as IZTauElement;
end;

class function TTnaf.ApproximateDivisionByN(const AK, AS_, AVm: TBigInteger;
  AA: ShortInt; AM, AC: Int32): TSimpleBigDecimal;
var
  L_K: Int32;
  LNs, LGs, LHs, LJs, LGsPlusJs, LLs: TBigInteger;
begin
  L_K := (AM + 5) div 2 + AC;
  LNs := AK.ShiftRight(AM - L_K - 2 + AA);

  LGs := AS_.Multiply(LNs);

  LHs := LGs.ShiftRight(AM);

  LJs := AVm.Multiply(LHs);

  LGsPlusJs := LGs.Add(LJs);
  LLs := LGsPlusJs.ShiftRight(L_K - AC);
  if LGsPlusJs.TestBit(L_K - AC - 1) then
  begin
    // round up
    LLs := LLs.Add(TBigInteger.One);
  end;

  Result := TSimpleBigDecimal.Create(LLs, AC);
end;

class function TTnaf.TauAdicNaf(AMu: ShortInt; const ALambda: IZTauElement): TCryptoLibShortIntArray;
var
  LNorm: TBigInteger;
  LLog2Norm, LMaxLength, LI, LLength: Int32;
  LU: TCryptoLibShortIntArray;
  LR0, LR1, LT, LS: TBigInteger;
  LTnaf: TCryptoLibShortIntArray;
begin
  if not ((AMu = 1) or (AMu = -1)) then
    raise EArgumentCryptoLibException.Create(SMuMustBe1OrMinus1);

  LNorm := Norm(AMu, ALambda);

  // Ceiling of log2 of the norm
  LLog2Norm := LNorm.BitLength;

  // If length(TNAF) > 30, then length(TNAF) < log2Norm + 3.52
  if LLog2Norm > 30 then
    LMaxLength := LLog2Norm + 4
  else
    LMaxLength := 34;

  SetLength(LU, LMaxLength);
  LI := 0;

  LLength := 0;

  LR0 := ALambda.U;
  LR1 := ALambda.V;

  while not (LR0.Equals(TBigInteger.Zero) and LR1.Equals(TBigInteger.Zero)) do
  begin
    // If r0 is odd
    if LR0.TestBit(0) then
    begin
      LU[LI] := ShortInt(TBigInteger.Two.Subtract(
        (LR0.Subtract(LR1.ShiftLeft(1))).&Mod(FFour)).Int32Value);

      // r0 = r0 - u[i]
      if LU[LI] = 1 then
        LR0 := LR0.ClearBit(0)
      else
        // u[i] == -1
        LR0 := LR0.Add(TBigInteger.One);

      LLength := LI;
    end
    else
    begin
      LU[LI] := 0;
    end;

    LT := LR0;
    LS := LR0.ShiftRight(1);
    if AMu = 1 then
      LR0 := LR1.Add(LS)
    else
      LR0 := LR1.Subtract(LS);

    LR1 := LT.ShiftRight(1).Negate();
    System.Inc(LI);
  end;

  System.Inc(LLength);

  // Reduce the TNAF array to its actual length
  SetLength(LTnaf, LLength);
  System.Move(LU[0], LTnaf[0], LLength * SizeOf(ShortInt));
  Result := LTnaf;
end;

class function TTnaf.Tau(const AP: IAbstractF2mPoint): IAbstractF2mPoint;
begin
  Result := AP.Tau();
end;

class function TTnaf.GetMu(const ACurve: IAbstractF2mCurve): ShortInt;
var
  LA: TBigInteger;
begin
  LA := ACurve.A.ToBigInteger();

  if LA.SignValue = 0 then
    Result := -1
  else if LA.Equals(TBigInteger.One) then
    Result := 1
  else
    raise EArgumentCryptoLibException.Create(SNoKoblitzCurve);
end;

class function TTnaf.GetMu(const ACurveA: IECFieldElement): ShortInt;
begin
  if ACurveA.IsZero then
    Result := -1
  else
    Result := 1;
end;

class function TTnaf.GetMu(ACurveA: Int32): ShortInt;
begin
  if ACurveA = 0 then
    Result := -1
  else
    Result := 1;
end;

class function TTnaf.GetLucas(AMu: ShortInt; AK: Int32; ADoV: Boolean): TCryptoLibGenericArray<TBigInteger>;
var
  LU0, LU1, LU2, LS: TBigInteger;
  LI: Int32;
begin
  if not ((AMu = 1) or (AMu = -1)) then
    raise EArgumentCryptoLibException.Create(SMuMustBe1OrMinus1);

  if ADoV then
  begin
    LU0 := TBigInteger.Two;
    LU1 := TBigInteger.ValueOf(AMu);
  end
  else
  begin
    LU0 := TBigInteger.Zero;
    LU1 := TBigInteger.One;
  end;

  for LI := 1 to AK - 1 do
  begin
    // u2 = mu*u1 - 2*u0
    LS := LU1;
    if AMu < 0 then
      LS := LS.Negate();

    LU2 := LS.Subtract(LU0.ShiftLeft(1));
    LU0 := LU1;
    LU1 := LU2;
  end;

  Result := TCryptoLibGenericArray<TBigInteger>.Create(LU0, LU1);
end;

class function TTnaf.GetTw(AMu: ShortInt; AW: Int32): TBigInteger;
var
  LUs: TCryptoLibGenericArray<TBigInteger>;
begin
  if AW = 4 then
  begin
    if AMu = 1 then
      Result := TBigInteger.Six
    else
      Result := TBigInteger.Ten;
  end
  else
  begin
    LUs := GetLucas(AMu, AW, False);
    Result := LUs[0].ShiftLeft(1).ModDivide(LUs[1], TBigInteger.One.ShiftLeft(AW));
  end;
end;

class function TTnaf.GetSi(const ACurve: IAbstractF2mCurve): TCryptoLibGenericArray<TBigInteger>;
begin
  if not ACurve.IsKoblitz then
    raise EArgumentCryptoLibException.Create(SSiDefinedForKoblitzOnly);

  Result := GetSi(ACurve.FieldSize,
    ACurve.A.ToBigInteger().Int32Value,
    ACurve.Cofactor);
end;

class function TTnaf.GetSi(AFieldSize, ACurveA: Int32;
  const ACofactor: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
var
  LMu: ShortInt;
  LShifts, LIndex: Int32;
  LUi: TCryptoLibGenericArray<TBigInteger>;
  LDividend0, LDividend1: TBigInteger;
begin
  LMu := GetMu(ACurveA);
  LShifts := GetShiftsForCofactor(ACofactor);
  LIndex := AFieldSize + 3 - ACurveA;
  LUi := GetLucas(LMu, LIndex, False);
  if LMu = 1 then
  begin
    LUi[0] := LUi[0].Negate();
    LUi[1] := LUi[1].Negate();
  end;

  LDividend0 := TBigInteger.One.Add(LUi[1]).ShiftRight(LShifts);
  LDividend1 := TBigInteger.One.Add(LUi[0]).ShiftRight(LShifts).Negate();

  Result := TCryptoLibGenericArray<TBigInteger>.Create(LDividend0, LDividend1);
end;

class function TTnaf.GetShiftsForCofactor(const AH: TBigInteger): Int32;
var
  LHi: Int32;
begin
  if (AH.IsInitialized) and (AH.BitLength < 4) then
  begin
    LHi := AH.Int32Value;
    if LHi = 2 then
      Exit(1);
    if LHi = 4 then
      Exit(2);
  end;

  raise EArgumentCryptoLibException.Create(SCofactorMustBe2Or4);
end;

class function TTnaf.PartModReduction(const ACurve: IAbstractF2mCurve;
  const AK: TBigInteger; AA, AMu, AC: ShortInt): IZTauElement;
var
  LCallback: IPreCompCallback;
  LPreCompInfo: IPartModPreCompInfo;
  LVm, LS0, LS1, LD0: TBigInteger;
  LM: Int32;
  LLambda0, LLambda1: TSimpleBigDecimal;
  LQ: IZTauElement;
  LR0, LR1: TBigInteger;
begin
  LCallback := TTnaf.TPartModPreCompCallback.Create(ACurve, AMu, True);
  if not Supports(ACurve.Precompute(PRECOMP_NAME, LCallback), IPartModPreCompInfo, LPreCompInfo) then
    raise EInvalidOperationCryptoLibException.Create('PartMod precomp failed');

  LVm := LPreCompInfo.Lucas;
  LS0 := LPreCompInfo.S0;
  LS1 := LPreCompInfo.S1;

  // d0 = s[0] + mu*s[1]; mu is either 1 or -1
  if AMu = 1 then
    LD0 := LS0.Add(LS1)
  else
    LD0 := LS0.Subtract(LS1);

  LM := ACurve.FieldSize;
  LLambda0 := ApproximateDivisionByN(AK, LS0, LVm, AA, LM, AC);
  LLambda1 := ApproximateDivisionByN(AK, LS1, LVm, AA, LM, AC);

  LQ := Round(LLambda0, LLambda1, AMu);

  // r0 = n - d0*q0 - 2*s1*q1
  LR0 := AK.Subtract(LD0.Multiply(LQ.U)).Subtract(
    LS1.Multiply(LQ.V).ShiftLeft(1));

  // r1 = s1*q0 - s0*q1
  LR1 := LS1.Multiply(LQ.U).Subtract(LS0.Multiply(LQ.V));

  Result := TZTauElement.Create(LR0, LR1) as IZTauElement;
end;

class function TTnaf.MultiplyRTnaf(const AP: IAbstractF2mPoint;
  const AK: TBigInteger): IAbstractF2mPoint;
var
  LCurve: IAbstractF2mCurve;
  LA: Int32;
  LMu: ShortInt;
  LRho: IZTauElement;
begin
  LCurve := AP.Curve as IAbstractF2mCurve;
  LA := LCurve.A.ToBigInteger().Int32Value;
  LMu := GetMu(LA);

  LRho := PartModReduction(LCurve, AK, ShortInt(LA), LMu, ShortInt(10));

  Result := MultiplyTnaf(AP, LRho);
end;

class function TTnaf.MultiplyTnaf(const AP: IAbstractF2mPoint;
  const ALambda: IZTauElement): IAbstractF2mPoint;
var
  LCurve: IAbstractF2mCurve;
  LPNeg: IAbstractF2mPoint;
  LMu: ShortInt;
  LU: TCryptoLibShortIntArray;
begin
  LCurve := AP.Curve as IAbstractF2mCurve;
  LPNeg := AP.Negate() as IAbstractF2mPoint;
  LMu := GetMu(LCurve.A);
  LU := TauAdicNaf(LMu, ALambda);

  Result := MultiplyFromTnaf(AP, LPNeg, LU);
end;

class function TTnaf.MultiplyFromTnaf(const AP, APNeg: IAbstractF2mPoint;
  const AU: TCryptoLibShortIntArray): IAbstractF2mPoint;
var
  LCurve: IECCurve;
  LQ: IAbstractF2mPoint;
  LTauCount, LI: Int32;
  LUi: ShortInt;
  LX: IECPoint;
begin
  LCurve := AP.Curve;
  LQ := LCurve.Infinity as IAbstractF2mPoint;
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
        LX := AP
      else
        LX := APNeg;
      LQ := LQ.Add(LX) as IAbstractF2mPoint;
    end;
  end;
  if LTauCount > 0 then
    LQ := LQ.TauPow(LTauCount);

  Result := LQ;
end;

class function TTnaf.TauAdicWNaf(AMu: ShortInt; const ALambda: IZTauElement;
  AWidth, ATw: Int32; const AAlpha: TCryptoLibGenericArray<IZTauElement>): TCryptoLibShortIntArray;
var
  LNorm: TBigInteger;
  LLog2Norm, LMaxLength: Int32;
  LU: TCryptoLibShortIntArray;
  LPow2Width, LPow2Mask, LS: Int32;
  LR0, LR1: TBigInteger;
  LUPos: Int32;
  LR0_64, LR1_64, LT_64: Int64;
  LAlphaUs, LAlphaVs: TCryptoLibInt32Array;
  LI, LUVal, LAlphaPos: Int32;
  LT: TBigInteger;
begin
  if not ((AMu = 1) or (AMu = -1)) then
    raise EArgumentCryptoLibException.Create(SMuMustBe1OrMinus1);

  LNorm := Norm(AMu, ALambda);

  // Ceiling of log2 of the norm
  LLog2Norm := LNorm.BitLength;

  // If length(TNAF) > 30, then length(TNAF) < log2Norm + 3.52
  if LLog2Norm > 30 then
    LMaxLength := LLog2Norm + 4 + AWidth
  else
    LMaxLength := 34 + AWidth;

  SetLength(LU, LMaxLength);

  LPow2Width := 1 shl AWidth;
  LPow2Mask := LPow2Width - 1;
  LS := 32 - AWidth;

  // Split lambda into two BigIntegers
  LR0 := ALambda.U;
  LR1 := ALambda.V;
  LUPos := 0;

  SetLength(LAlphaUs, System.Length(AAlpha));
  SetLength(LAlphaVs, System.Length(AAlpha));
  LI := 1;
  while LI < System.Length(AAlpha) do
  begin
    LAlphaUs[LI] := AAlpha[LI].U.Int32ValueExact();
    LAlphaVs[LI] := AAlpha[LI].V.Int32ValueExact();
    System.Inc(LI, 2);
  end;

  // BigInteger path: while lambda <> (0, 0)
  while (LR0.BitLength > 62) or (LR1.BitLength > 62) do
  begin
    if LR0.TestBit(0) then
    begin
      LUVal := LR0.Int32Value + (LR1.Int32Value * ATw);
      LAlphaPos := LUVal and LPow2Mask;

      LU[LUPos] := ShortInt(TBitOperations.Asr32(LUVal shl LS, LS));
      LR0 := LR0.Subtract(AAlpha[LAlphaPos].U);
      LR1 := LR1.Subtract(AAlpha[LAlphaPos].V);
    end;

    System.Inc(LUPos);

    LT := LR0.ShiftRight(1);
    if AMu = 1 then
      LR0 := LR1.Add(LT)
    else
      LR0 := LR1.Subtract(LT);

    LR1 := LT.Negate();
  end;

  LR0_64 := LR0.Int64ValueExact();
  LR1_64 := LR1.Int64ValueExact();

  // Small-value loop using Int64 arithmetic
  while (LR0_64 or LR1_64) <> Int64(0) do
  begin
    if (LR0_64 and Int64(1)) <> Int64(0) then
    begin
      LUVal := Int32(LR0_64) + (Int32(LR1_64) * ATw);
      LAlphaPos := LUVal and LPow2Mask;

      LU[LUPos] := ShortInt(TBitOperations.Asr32(LUVal shl LS, LS));
      LR0_64 := LR0_64 - LAlphaUs[LAlphaPos];
      LR1_64 := LR1_64 - LAlphaVs[LAlphaPos];
    end;

    System.Inc(LUPos);

    LT_64 := TBitOperations.Asr64(LR0_64, 1);
    if AMu = 1 then
      LR0_64 := LR1_64 + LT_64
    else
      LR0_64 := LR1_64 - LT_64;

    LR1_64 := -LT_64;
  end;

  Result := LU;
end;

class function TTnaf.GetPreComp(const AP: IAbstractF2mPoint;
  AA: ShortInt): TCryptoLibGenericArray<IAbstractF2mPoint>;
var
  LPNeg: IAbstractF2mPoint;
  LAlphaTnaf: TCryptoLibMatrixShortIntArray;
  LPu: TCryptoLibGenericArray<IECPoint>;
  LPrecompLen: Int32;
  LI: UInt32;
begin
  LPNeg := AP.Negate() as IAbstractF2mPoint;
  if AA = 0 then
    LAlphaTnaf := Alpha0Tnaf
  else
    LAlphaTnaf := Alpha1Tnaf;

  SetLength(LPu, (UInt32(System.Length(LAlphaTnaf)) + 1) shr 1);
  LPu[0] := AP;

  LPrecompLen := System.Length(LAlphaTnaf);
  LI := 3;
  while LI < UInt32(LPrecompLen) do
  begin
    LPu[LI shr 1] := MultiplyFromTnaf(AP, LPNeg, LAlphaTnaf[LI]);
    System.Inc(LI, 2);
  end;

  AP.Curve.NormalizeAll(LPu);

  Result := TArrayUtilities.Map<IECPoint, IAbstractF2mPoint>(LPu,
    function(APoint: IECPoint): IAbstractF2mPoint
    begin
      Result := APoint as IAbstractF2mPoint;
    end);
end;

end.
