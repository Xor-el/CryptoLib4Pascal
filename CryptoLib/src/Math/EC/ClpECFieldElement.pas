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

unit ClpECFieldElement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegerUtilities,
  ClpIECFieldElement,
  ClpLongArray,
  ClpBitOperations,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SF2mFieldElementsNotBothInstances = 'Field elements are not both instances of F2mFieldElement';
  SF2mFieldElementIncorrectRepresentation = 'One of the F2m field elements has incorrect representation';
  SF2mFieldElementsNotSameField = 'Field elements are not elements of the same field F2m';
  SHalfTraceOnlyDefinedForOddM = 'Half-trace only defined for odd m';
  SInternalErrorInTraceCalculation = 'Internal error in trace calculation';

type
  TECFieldElement = class abstract(TInterfacedObject, IECFieldElement)
  public
    function GetBitLength: Int32; virtual;
    function GetIsOne: Boolean; virtual;
    function GetIsZero: Boolean; virtual;

    function GetFieldName: String; virtual; abstract;
    function GetFieldSize: Int32; virtual; abstract;
    function ToBigInteger: TBigInteger; virtual; abstract;
    function Add(const AB: IECFieldElement): IECFieldElement; virtual; abstract;
    function AddOne: IECFieldElement; virtual; abstract;
    function Subtract(const AB: IECFieldElement): IECFieldElement; virtual; abstract;
    function Multiply(const AB: IECFieldElement): IECFieldElement; virtual; abstract;
    function Divide(const AB: IECFieldElement): IECFieldElement; virtual; abstract;
    function Negate: IECFieldElement; virtual; abstract;
    function Square: IECFieldElement; virtual; abstract;
    function Invert: IECFieldElement; virtual; abstract;
    function Sqrt: IECFieldElement; virtual; abstract;

    function MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement; virtual;
    function MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement; virtual;
    function SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement; virtual;
    function SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement; virtual;
    function SquarePow(APow: Int32): IECFieldElement; virtual;
    function TestBitZero: Boolean; virtual;

    function Equals(const AOther: IECFieldElement): Boolean; reintroduce; virtual;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
    function ToString: String; override;
    function GetEncoded: TCryptoLibByteArray; virtual;
    function GetEncodedLength: Int32; virtual;
    procedure EncodeTo(var ABuf: TCryptoLibByteArray; AOff: Int32); virtual;

    property BitLength: Int32 read GetBitLength;
    property IsOne: Boolean read GetIsOne;
    property IsZero: Boolean read GetIsZero;
  end;

  TAbstractFpFieldElement = class abstract(TECFieldElement, IAbstractFpFieldElement)
  end;

  TFpFieldElement = class sealed(TAbstractFpFieldElement, IECFieldElement, IFpFieldElement)
  strict private
    FQ, FR, FX: TBigInteger;
    function CheckSqrt(const AZ: IECFieldElement): IECFieldElement;
    function LucasSequence(const AP, AQ, AK: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
  strict protected
    function ModAdd(const AX1, AX2: TBigInteger): TBigInteger; virtual;
    function ModDouble(const AX: TBigInteger): TBigInteger; virtual;
    function ModHalf(const AX: TBigInteger): TBigInteger; virtual;
    function ModHalfAbs(const AX: TBigInteger): TBigInteger; virtual;
    function ModInverse(const AX: TBigInteger): TBigInteger; virtual;
    function ModMult(const AX1, AX2: TBigInteger): TBigInteger; virtual;
    function ModReduce(const AX: TBigInteger): TBigInteger; virtual;
    function ModSubtract(const AX1, AX2: TBigInteger): TBigInteger; virtual;
  public
    class function CalculateResidue(const AP: TBigInteger): TBigInteger; static;
    constructor Create(const AQ, AR, AX: TBigInteger);

    function GetFieldName: String; override;
    function GetFieldSize: Int32; override;
    function ToBigInteger: TBigInteger; override;
    function Add(const AB: IECFieldElement): IECFieldElement; override;
    function AddOne: IECFieldElement; override;
    function Subtract(const AB: IECFieldElement): IECFieldElement; override;
    function Multiply(const AB: IECFieldElement): IECFieldElement; override;
    function MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement; override;
    function MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement; override;
    function Divide(const AB: IECFieldElement): IECFieldElement; override;
    function Negate: IECFieldElement; override;
    function Square: IECFieldElement; override;
    function SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement; override;
    function SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement; override;
    function Invert: IECFieldElement; override;
    function Sqrt: IECFieldElement; override;

    function Equals(const AOther: IECFieldElement): Boolean; override;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    function GetQ: TBigInteger;

    property Q: TBigInteger read GetQ;
  end;

  TAbstractF2mFieldElement = class abstract(TECFieldElement, IECFieldElement, IAbstractF2mFieldElement)
  public
    function HalfTrace: IECFieldElement; virtual;
    function GetHasFastTrace: Boolean; virtual;
    function Trace: Int32; virtual;

    property HasFastTrace: Boolean read GetHasFastTrace;
  end;

  TF2mFieldElement = class sealed(TAbstractF2mFieldElement, IECFieldElement, IAbstractF2mFieldElement, IF2mFieldElement)
  public
    const
      Gnb = 1;
      Tpb = 2;
      Ppb = 3;
  strict private
    FRepresentation: Int32;
    FM: Int32;
    FKs: TCryptoLibInt32Array;
    FX: TLongArray;
  public
    class procedure CheckFieldElements(const AA, AB: IECFieldElement); static;

    constructor Create(AM: Int32; const AKs: TCryptoLibInt32Array; const AX: TLongArray);

    function GetBitLength: Int32; override;
    function GetIsOne: Boolean; override;
    function GetIsZero: Boolean; override;
    function TestBitZero: Boolean; override;

    function GetFieldName: String; override;
    function GetFieldSize: Int32; override;
    function ToBigInteger: TBigInteger; override;
    function Add(const AB: IECFieldElement): IECFieldElement; override;
    function AddOne: IECFieldElement; override;
    function Subtract(const AB: IECFieldElement): IECFieldElement; override;
    function Multiply(const AB: IECFieldElement): IECFieldElement; override;
    function MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement; override;
    function MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement; override;
    function Divide(const AB: IECFieldElement): IECFieldElement; override;
    function Negate: IECFieldElement; override;
    function Square: IECFieldElement; override;
    function SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement; override;
    function SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement; override;
    function SquarePow(APow: Int32): IECFieldElement; override;
    function Invert: IECFieldElement; override;
    function Sqrt: IECFieldElement; override;

    function Equals(const AOther: IECFieldElement): Boolean; override;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    function GetRepresentation: Int32;
    function GetM: Int32;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;
    function GetX: TLongArray;

    property Representation: Int32 read GetRepresentation;
    property M: Int32 read GetM;
    property K1: Int32 read GetK1;
    property K2: Int32 read GetK2;
    property K3: Int32 read GetK3;
    property X: TLongArray read GetX;
  end;

implementation

function TECFieldElement.GetBitLength: Int32;
begin
  Result := ToBigInteger.BitLength;
end;

function TECFieldElement.GetIsOne: Boolean;
begin
  Result := BitLength = 1;
end;

function TECFieldElement.GetIsZero: Boolean;
begin
  Result := ToBigInteger.SignValue = 0;
end;

function TECFieldElement.MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := Multiply(AB).Subtract(AX.Multiply(AY));
end;

function TECFieldElement.MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := Multiply(AB).Add(AX.Multiply(AY));
end;

function TECFieldElement.SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := Square().Subtract(AX.Multiply(AY));
end;

function TECFieldElement.SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := Square().Add(AX.Multiply(AY));
end;

function TECFieldElement.SquarePow(APow: Int32): IECFieldElement;
var
  LR: IECFieldElement;
  I: Int32;
begin
  LR := Self as IECFieldElement;
  I := 0;
  while I < APow do
  begin
    LR := LR.Square();
    System.Inc(I);
  end;
  Result := LR;
end;

function TECFieldElement.TestBitZero: Boolean;
begin
  Result := ToBigInteger.TestBit(0);
end;

function TECFieldElement.GetHashCode: {$IFDEF DELPHI}Int32{$ELSE}PtrInt{$ENDIF};
begin
  Result := ToBigInteger.GetHashCode();
end;

function TECFieldElement.ToString: String;
begin
  Result := ToBigInteger.ToString(16);
end;

function TECFieldElement.Equals(const AOther: IECFieldElement): Boolean;
begin
  if AOther = nil then
    Exit(False);
  if (Self as IECFieldElement) = AOther then
    Exit(True);
  Result := ToBigInteger.Equals(AOther.ToBigInteger);
end;

function TECFieldElement.GetEncoded: TCryptoLibByteArray;
begin
  Result := TBigIntegerUtilities.AsUnsignedByteArray(GetEncodedLength(), ToBigInteger);
end;

function TECFieldElement.GetEncodedLength: Int32;
begin
  Result := (GetFieldSize + 7) div 8;
end;

procedure TECFieldElement.EncodeTo(var ABuf: TCryptoLibByteArray; AOff: Int32);
begin
  TBigIntegerUtilities.AsUnsignedByteArray(ToBigInteger, ABuf, AOff, GetEncodedLength());
end;

{ TFpFieldElement }

class function TFpFieldElement.CalculateResidue(const AP: TBigInteger): TBigInteger;
var
  LBitLength: Int32;
  LFirstWord: TBigInteger;
begin
  LBitLength := AP.BitLength;
  if LBitLength >= 96 then
  begin
    LFirstWord := AP.ShiftRight(LBitLength - 64);
    if LFirstWord.Int64Value = -1 then
    begin
      Result := TBigInteger.One.ShiftLeft(LBitLength).Subtract(AP);
      Exit;
    end;
    if (LBitLength and 7) = 0 then
    begin
      Result := TBigInteger.One.ShiftLeft(LBitLength shl 1).Divide(AP).Negate();
      Exit;
    end;
  end;
  Result := TBigInteger.GetDefault();
end;

constructor TFpFieldElement.Create(const AQ, AR, AX: TBigInteger);
begin
  Inherited Create;
  FQ := AQ;
  FR := AR;
  FX := AX;
end;

function TFpFieldElement.ModAdd(const AX1, AX2: TBigInteger): TBigInteger;
var
  LX3: TBigInteger;
begin
  LX3 := AX1.Add(AX2);
  if LX3.CompareTo(FQ) >= 0 then
    LX3 := LX3.Subtract(FQ);
  Result := LX3;
end;

function TFpFieldElement.ModDouble(const AX: TBigInteger): TBigInteger;
var
  L2x: TBigInteger;
begin
  L2x := AX.ShiftLeft(1);
  if L2x.CompareTo(FQ) >= 0 then
    L2x := L2x.Subtract(FQ);
  Result := L2x;
end;

function TFpFieldElement.ModHalf(const AX: TBigInteger): TBigInteger;
var
  LX: TBigInteger;
begin
  LX := AX;
  if LX.TestBit(0) then
    LX := FQ.Add(LX);
  Result := LX.ShiftRight(1);
end;

function TFpFieldElement.ModHalfAbs(const AX: TBigInteger): TBigInteger;
var
  LX: TBigInteger;
begin
  LX := AX;
  if LX.TestBit(0) then
    LX := FQ.Subtract(LX);
  Result := LX.ShiftRight(1);
end;

function TFpFieldElement.ModInverse(const AX: TBigInteger): TBigInteger;
begin
  Result := TBigIntegerUtilities.ModOddInverse(FQ, AX);
end;

function TFpFieldElement.ModMult(const AX1, AX2: TBigInteger): TBigInteger;
begin
  Result := ModReduce(AX1.Multiply(AX2));
end;

function TFpFieldElement.ModReduce(const AX: TBigInteger): TBigInteger;
var
  LNegative: Boolean;
  LQLen, LD, LQLenD: Int32;
  LX, LQMod, LU, LV, LMu, LQuot, LBk1: TBigInteger;
  LRIsOne: Boolean;
begin
  if not FR.IsInitialized then
    Result := AX.&Mod(FQ)
  else
  begin
    LNegative := AX.SignValue < 0;
    LX := AX;
    if LNegative then
      LX := LX.Abs();
    LQLen := FQ.BitLength;
    if FR.SignValue > 0 then
    begin
      LQMod := TBigInteger.One.ShiftLeft(LQLen);
      LRIsOne := FR.Equals(TBigInteger.One);
      while LX.BitLength > (LQLen + 1) do
      begin
        LU := LX.ShiftRight(LQLen);
        LV := LX.Remainder(LQMod);
        if not LRIsOne then
          LU := LU.Multiply(FR);
        LX := LU.Add(LV);
      end;
    end
    else
    begin
      LD := ((LQLen - 1) and 31) + 1;
      LQLenD := LQLen + LD;
      LMu := FR.Negate();
      LU := LMu.Multiply(LX.ShiftRight(LQLen - LD));
      LQuot := LU.ShiftRight(LQLenD);
      LV := LQuot.Multiply(FQ);
      LBk1 := TBigInteger.One.ShiftLeft(LQLenD);
      LV := LV.Remainder(LBk1);
      LX := LX.Remainder(LBk1);
      LX := LX.Subtract(LV);
      if LX.SignValue < 0 then
        LX := LX.Add(LBk1);
    end;
    while LX.CompareTo(FQ) >= 0 do
      LX := LX.Subtract(FQ);
    if LNegative and (LX.SignValue <> 0) then
      LX := FQ.Subtract(LX);
    Result := LX;
  end;
end;

function TFpFieldElement.ModSubtract(const AX1, AX2: TBigInteger): TBigInteger;
var
  LX3: TBigInteger;
begin
  LX3 := AX1.Subtract(AX2);
  if LX3.SignValue < 0 then
    LX3 := LX3.Add(FQ);
  Result := LX3;
end;

function TFpFieldElement.GetFieldName: String;
begin
  Result := 'Fp';
end;

function TFpFieldElement.GetFieldSize: Int32;
begin
  Result := FQ.BitLength;
end;

function TFpFieldElement.ToBigInteger: TBigInteger;
begin
  Result := FX;
end;

function TFpFieldElement.Add(const AB: IECFieldElement): IECFieldElement;
begin
  Result := TFpFieldElement.Create(FQ, FR, ModAdd(FX, AB.ToBigInteger()));
end;

function TFpFieldElement.AddOne: IECFieldElement;
var
  LX2: TBigInteger;
begin
  LX2 := FX.Add(TBigInteger.One);
  if LX2.CompareTo(FQ) = 0 then
    LX2 := TBigInteger.Zero;
  Result := TFpFieldElement.Create(FQ, FR, LX2);
end;

function TFpFieldElement.Subtract(const AB: IECFieldElement): IECFieldElement;
begin
  Result := TFpFieldElement.Create(FQ, FR, ModSubtract(FX, AB.ToBigInteger()));
end;

function TFpFieldElement.Multiply(const AB: IECFieldElement): IECFieldElement;
begin
  Result := TFpFieldElement.Create(FQ, FR, ModMult(FX, AB.ToBigInteger()));
end;

function TFpFieldElement.MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
var
  LAx, LBx, LXx, LYx, LAb, LXy: TBigInteger;
begin
  LAx := FX;
  LBx := AB.ToBigInteger();
  LXx := AX.ToBigInteger();
  LYx := AY.ToBigInteger();
  LAb := LAx.Multiply(LBx);
  LXy := LXx.Multiply(LYx);
  Result := TFpFieldElement.Create(FQ, FR, ModReduce(LAb.Subtract(LXy)));
end;

function TFpFieldElement.MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
var
  LAx, LBx, LXx, LYx, LAb, LXy, LSum: TBigInteger;
begin
  LAx := FX;
  LBx := AB.ToBigInteger();
  LXx := AX.ToBigInteger();
  LYx := AY.ToBigInteger();
  LAb := LAx.Multiply(LBx);
  LXy := LXx.Multiply(LYx);
  LSum := LAb.Add(LXy);
  if FR.IsInitialized and (FR.SignValue < 0) and (LSum.BitLength > (FQ.BitLength shl 1)) then
    LSum := LSum.Subtract(FQ.ShiftLeft(FQ.BitLength));
  Result := TFpFieldElement.Create(FQ, FR, ModReduce(LSum));
end;

function TFpFieldElement.Divide(const AB: IECFieldElement): IECFieldElement;
begin
  Result := TFpFieldElement.Create(FQ, FR, ModMult(FX, ModInverse(AB.ToBigInteger())));
end;

function TFpFieldElement.Negate: IECFieldElement;
begin
  if FX.SignValue = 0 then
    Result := Self as IECFieldElement
  else
    Result := TFpFieldElement.Create(FQ, FR, FQ.Subtract(FX));
end;

function TFpFieldElement.Square: IECFieldElement;
begin
  Result := TFpFieldElement.Create(FQ, FR, ModMult(FX, FX));
end;

function TFpFieldElement.SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement;
var
  LAx, LXx, LYx, LAa, LXy: TBigInteger;
begin
  LAx := FX;
  LXx := AX.ToBigInteger();
  LYx := AY.ToBigInteger();
  LAa := LAx.Multiply(LAx);
  LXy := LXx.Multiply(LYx);
  Result := TFpFieldElement.Create(FQ, FR, ModReduce(LAa.Subtract(LXy)));
end;

function TFpFieldElement.SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement;
var
  LAx, LXx, LYx, LAa, LXy, LSum: TBigInteger;
begin
  LAx := FX;
  LXx := AX.ToBigInteger();
  LYx := AY.ToBigInteger();
  LAa := LAx.Multiply(LAx);
  LXy := LXx.Multiply(LYx);
  LSum := LAa.Add(LXy);
  if FR.IsInitialized and (FR.SignValue < 0) and (LSum.BitLength > (FQ.BitLength shl 1)) then
    LSum := LSum.Subtract(FQ.ShiftLeft(FQ.BitLength));
  Result := TFpFieldElement.Create(FQ, FR, ModReduce(LSum));
end;

function TFpFieldElement.Invert: IECFieldElement;
begin
  Result := TFpFieldElement.Create(FQ, FR, ModInverse(FX));
end;

function TFpFieldElement.CheckSqrt(const AZ: IECFieldElement): IECFieldElement;
begin
  if AZ.Square().Equals(Self as IECFieldElement) then
    Result := AZ
  else
    Result := nil;
end;

function TFpFieldElement.LucasSequence(const AP, AQ, AK: TBigInteger): TCryptoLibGenericArray<TBigInteger>;
var
  LN, LS, LJ: Int32;
  LUh, LVl, LVh, LQl, LQh: TBigInteger;
  LResult: TCryptoLibGenericArray<TBigInteger>;
begin
  LN := AK.BitLength;
  LS := AK.GetLowestSetBit();
  {$IFDEF DEBUG}
  System.Assert(AK.TestBit(LS));
  {$ENDIF}
  LUh := TBigInteger.One;
  LVl := TBigInteger.Two;
  LVh := AP;
  LQl := TBigInteger.One;
  LQh := TBigInteger.One;
  LJ := LN - 1;
  while LJ >= LS + 1 do
  begin
    LQl := ModMult(LQl, LQh);
    if AK.TestBit(LJ) then
    begin
      LQh := ModMult(LQl, AQ);
      LUh := ModMult(LUh, LVh);
      LVl := ModReduce(LVh.Multiply(LVl).Subtract(AP.Multiply(LQl)));
      LVh := ModReduce(LVh.Multiply(LVh).Subtract(LQh.ShiftLeft(1)));
    end
    else
    begin
      LQh := LQl;
      LUh := ModReduce(LUh.Multiply(LVl).Subtract(LQl));
      LVh := ModReduce(LVh.Multiply(LVl).Subtract(AP.Multiply(LQl)));
      LVl := ModReduce(LVl.Multiply(LVl).Subtract(LQl.ShiftLeft(1)));
    end;
    System.Dec(LJ);
  end;
  LQl := ModMult(LQl, LQh);
  LQh := ModMult(LQl, AQ);
  LUh := ModReduce(LUh.Multiply(LVl).Subtract(LQl));
  LVl := ModReduce(LVh.Multiply(LVl).Subtract(AP.Multiply(LQl)));
  LQl := ModMult(LQl, LQh);
  for LJ := 1 to LS do
  begin
    LUh := ModMult(LUh, LVl);
    LVl := ModReduce(LVl.Multiply(LVl).Subtract(LQl.ShiftLeft(1)));
    LQl := ModMult(LQl, LQl);
  end;
  SetLength(LResult, 2);
  LResult[0] := LUh;
  LResult[1] := LVl;
  Result := LResult;
end;

function TFpFieldElement.Sqrt: IECFieldElement;
var
  LE, LT1, LT2, LT3, LT4, LY, LLegendreExponent, LFourX, LK, LQMinusOne: TBigInteger;
  LP: TBigInteger;
  LLucasResult: TCryptoLibGenericArray<TBigInteger>;
  LU, LV: TBigInteger;
  LZ: IECFieldElement;
begin
  if IsZero or IsOne then
    Exit(Self as IECFieldElement);
  if not FQ.TestBit(0) then
    raise ENotImplementedCryptoLibException.Create('even value of q');
  if FQ.TestBit(1) then
  begin
    LE := FQ.ShiftRight(2).Add(TBigInteger.One);
    LZ := TFpFieldElement.Create(FQ, FR, FX.ModPow(LE, FQ));
    Exit(CheckSqrt(LZ));
  end;
  if FQ.TestBit(2) then
  begin
    LT1 := FX.ModPow(FQ.ShiftRight(3), FQ);
    LT2 := ModMult(LT1, FX);
    LT3 := ModMult(LT2, LT1);
    if LT3.Equals(TBigInteger.One) then
      Exit(CheckSqrt(TFpFieldElement.Create(FQ, FR, LT2) as IFpFieldElement));
    LT4 := TBigInteger.Two.ModPow(FQ.ShiftRight(2), FQ);
    LY := ModMult(LT2, LT4);
    Exit(CheckSqrt(TFpFieldElement.Create(FQ, FR, LY) as IFpFieldElement));
  end;
  LLegendreExponent := FQ.ShiftRight(1);
  if not FX.ModPow(LLegendreExponent, FQ).Equals(TBigInteger.One) then
    Exit(nil);
  LFourX := ModDouble(ModDouble(FX));
  LK := LLegendreExponent.Add(TBigInteger.One);
  LQMinusOne := FQ.Subtract(TBigInteger.One);
  repeat
    repeat
      LP := TBigInteger.Arbitrary(FQ.BitLength);
    until (LP.CompareTo(FQ) < 0) and
      ModReduce(LP.Multiply(LP).Subtract(LFourX)).ModPow(LLegendreExponent, FQ).Equals(LQMinusOne);
    LLucasResult := LucasSequence(LP, FX, LK);
    LU := LLucasResult[0];
    LV := LLucasResult[1];
    if ModMult(LV, LV).Equals(LFourX) then
      Exit(TFpFieldElement.Create(FQ, FR, ModHalfAbs(LV)));
  until (not LU.Equals(TBigInteger.One)) and (not LU.Equals(LQMinusOne));
  Result := nil;
end;

function TFpFieldElement.GetQ: TBigInteger;
begin
  Result := FQ;
end;

function TFpFieldElement.Equals(const AOther: IECFieldElement): Boolean;
var
  LOtherFp: IFpFieldElement;
begin
  if AOther = nil then
    Exit(False);
  if (Self as IECFieldElement) = AOther then
    Exit(True);
  if not Supports(AOther, IFpFieldElement, LOtherFp) then
    Exit(False);
  Result := FQ.Equals(LOtherFp.Q) and FX.Equals(AOther.ToBigInteger());
end;

function TFpFieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FQ.GetHashCode() xor FX.GetHashCode();
end;

{ TAbstractF2mFieldElement }

function TAbstractF2mFieldElement.HalfTrace: IECFieldElement;
var
  LM, LN, LK, LNk: Int32;
  LHt: IECFieldElement;
begin
  LM := GetFieldSize;
  if (LM and 1) = 0 then
    raise EInvalidOperationCryptoLibException.Create(SHalfTraceOnlyDefinedForOddM);
  LN := TBitOperations.Asr32(LM + 1, 1);
  LK := 31 - TBitOperations.NumberOfLeadingZeros32(UInt32(LN));
  LNk := 1;
  LHt := Self as IECFieldElement;
  while LK > 0 do
  begin
    LHt := LHt.SquarePow(LNk shl 1).Add(LHt);
    System.Dec(LK);
    LNk := TBitOperations.Asr32(LN, LK);
    if (LNk and 1) <> 0 then
      LHt := LHt.SquarePow(2).Add(Self as IECFieldElement);
  end;
  Result := LHt;
end;

function TAbstractF2mFieldElement.GetHasFastTrace: Boolean;
begin
  Result := False;
end;

function TAbstractF2mFieldElement.Trace: Int32;
var
  LM, LK, LMk: Int32;
  LTr: IECFieldElement;
begin
  LM := GetFieldSize;
  LK := 31 - TBitOperations.NumberOfLeadingZeros32(UInt32(LM));
  LMk := 1;
  LTr := Self as IECFieldElement;
  while LK > 0 do
  begin
    LTr := LTr.SquarePow(LMk).Add(LTr);
    System.Dec(LK);
    LMk := TBitOperations.Asr32(LM, LK);
    if (LMk and 1) <> 0 then
      LTr := LTr.Square().Add(Self as IECFieldElement);
  end;
  if LTr.IsZero then
    Result := 0
  else if LTr.IsOne then
    Result := 1
  else
    raise EInvalidOperationCryptoLibException.Create(SInternalErrorInTraceCalculation);
end;

{ TF2mFieldElement }

class procedure TF2mFieldElement.CheckFieldElements(const AA, AB: IECFieldElement);
var
  LAIntf, LBIntf: IF2mFieldElement;
begin
  if not Supports(AA, IF2mFieldElement, LAIntf) or not Supports(AB, IF2mFieldElement, LBIntf) then
    raise EArgumentCryptoLibException.Create(SF2mFieldElementsNotBothInstances);
  if LAIntf.Representation <> LBIntf.Representation then
    raise EArgumentCryptoLibException.Create(SF2mFieldElementIncorrectRepresentation);
  if (LAIntf.M <> LBIntf.M) or (LAIntf.K1 <> LBIntf.K1) or (LAIntf.K2 <> LBIntf.K2) or (LAIntf.K3 <> LBIntf.K3) then
    raise EArgumentCryptoLibException.Create(SF2mFieldElementsNotSameField);
end;

constructor TF2mFieldElement.Create(AM: Int32; const AKs: TCryptoLibInt32Array; const AX: TLongArray);
begin
  Inherited Create;
  FM := AM;
  if System.Length(AKs) = 1 then
    FRepresentation := Tpb
  else
    FRepresentation := Ppb;
  FKs := AKs;
  FX := AX;
end;

function TF2mFieldElement.GetX: TLongArray;
begin
  Result := FX;
end;

function TF2mFieldElement.GetBitLength: Int32;
begin
  Result := FX.Degree();
end;

function TF2mFieldElement.GetIsOne: Boolean;
begin
  Result := FX.IsOne();
end;

function TF2mFieldElement.GetIsZero: Boolean;
begin
  Result := FX.IsZero();
end;

function TF2mFieldElement.TestBitZero: Boolean;
begin
  Result := FX.TestBitZero();
end;

function TF2mFieldElement.GetFieldName: String;
begin
  Result := 'F2m';
end;

function TF2mFieldElement.GetFieldSize: Int32;
begin
  Result := FM;
end;

function TF2mFieldElement.ToBigInteger: TBigInteger;
begin
  Result := FX.ToBigInteger();
end;

function TF2mFieldElement.Add(const AB: IECFieldElement): IECFieldElement;
var
  LIarrClone: TLongArray;
  LBIntf: IF2mFieldElement;
begin
  if not Supports(AB, IF2mFieldElement, LBIntf) then
    raise EArgumentCryptoLibException.Create(SF2mFieldElementsNotBothInstances);
  LIarrClone := FX.Copy();
  LIarrClone.AddShiftedByWords(LBIntf.X, 0);
  Result := TF2mFieldElement.Create(FM, FKs, LIarrClone);
end;

function TF2mFieldElement.AddOne: IECFieldElement;
begin
  Result := TF2mFieldElement.Create(FM, FKs, FX.AddOne());
end;

function TF2mFieldElement.Subtract(const AB: IECFieldElement): IECFieldElement;
begin
  Result := Add(AB);
end;

function TF2mFieldElement.Multiply(const AB: IECFieldElement): IECFieldElement;
var
  LBIntf: IF2mFieldElement;
begin
  if not Supports(AB, IF2mFieldElement, LBIntf) then
    raise EArgumentCryptoLibException.Create(SF2mFieldElementsNotBothInstances);
  Result := TF2mFieldElement.Create(FM, FKs, FX.ModMultiply(LBIntf.X, FM, FKs));
end;

function TF2mFieldElement.MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := MultiplyPlusProduct(AB, AX, AY);
end;

function TF2mFieldElement.MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
var
  LAx, LBx, LXx, LYx: TLongArray;
  LAb, LXy: TLongArray;
  LBIntf, LXIntf, LYIntf: IF2mFieldElement;
begin
  if not Supports(AB, IF2mFieldElement, LBIntf) or not Supports(AX, IF2mFieldElement, LXIntf) or not Supports(AY, IF2mFieldElement, LYIntf) then
    raise EArgumentCryptoLibException.Create(SF2mFieldElementsNotBothInstances);
  LAx := FX;
  LBx := LBIntf.X;
  LXx := LXIntf.X;
  LYx := LYIntf.X;
  LAb := LAx.Multiply(LBx, FM, FKs);
  LXy := LXx.Multiply(LYx, FM, FKs);
  if TLongArray.AreAliased(LAb, LAx) or TLongArray.AreAliased(LAb, LBx) then
    LAb := LAb.Copy();
  LAb.AddShiftedByWords(LXy, 0);
  LAb.Reduce(FM, FKs);
  Result := TF2mFieldElement.Create(FM, FKs, LAb);
end;

function TF2mFieldElement.Divide(const AB: IECFieldElement): IECFieldElement;
var
  LBInv: IECFieldElement;
begin
  LBInv := AB.Invert();
  Result := Multiply(LBInv);
end;

function TF2mFieldElement.Negate: IECFieldElement;
begin
  Result := Self as IECFieldElement;
end;

function TF2mFieldElement.Square: IECFieldElement;
begin
  Result := TF2mFieldElement.Create(FM, FKs, FX.ModSquare(FM, FKs));
end;

function TF2mFieldElement.SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := SquarePlusProduct(AX, AY);
end;

function TF2mFieldElement.SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement;
var
  LAx, LXx, LYx: TLongArray;
  LAA, LXy: TLongArray;
  LXIntf, LYIntf: IF2mFieldElement;
begin
  if not Supports(AX, IF2mFieldElement, LXIntf) or not Supports(AY, IF2mFieldElement, LYIntf) then
    raise EArgumentCryptoLibException.Create(SF2mFieldElementsNotBothInstances);
  LAx := FX;
  LXx := LXIntf.X;
  LYx := LYIntf.X;
  LAA := LAx.Square(FM, FKs);
  LXy := LXx.Multiply(LYx, FM, FKs);
  if TLongArray.AreAliased(LAA, LAx) then
    LAA := LAA.Copy();
  LAA.AddShiftedByWords(LXy, 0);
  LAA.Reduce(FM, FKs);
  Result := TF2mFieldElement.Create(FM, FKs, LAA);
end;

function TF2mFieldElement.SquarePow(APow: Int32): IECFieldElement;
begin
  if APow < 1 then
    Result := Self as IECFieldElement
  else
    Result := TF2mFieldElement.Create(FM, FKs, FX.ModSquareN(APow, FM, FKs));
end;

function TF2mFieldElement.Invert: IECFieldElement;
begin
  Result := TF2mFieldElement.Create(FM, FKs, FX.ModInverse(FM, FKs));
end;

function TF2mFieldElement.Sqrt: IECFieldElement;
begin
  if FX.IsZero() or FX.IsOne() then
    Result := Self as IECFieldElement
  else
    Result := SquarePow(FM - 1);
end;

function TF2mFieldElement.Equals(const AOther: IECFieldElement): Boolean;
var
  LOtherF2m: IF2mFieldElement;
begin
  if AOther = nil then
    Exit(False);
  if (Self as IECFieldElement) = AOther then
    Exit(True);
  if not Supports(AOther, IF2mFieldElement, LOtherF2m) then
    Exit(False);
  Result := (FM = LOtherF2m.M) and (FRepresentation = LOtherF2m.Representation)
    and (GetK1 = LOtherF2m.K1) and (GetK2 = LOtherF2m.K2) and (GetK3 = LOtherF2m.K3)
    and FX.Equals(LOtherF2m.X);
end;

function TF2mFieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FX.GetHashCode() xor FM xor TArrayUtilities.GetArrayHashCode(FKs);
end;

function TF2mFieldElement.GetRepresentation: Int32;
begin
  Result := FRepresentation;
end;

function TF2mFieldElement.GetM: Int32;
begin
  Result := FM;
end;

function TF2mFieldElement.GetK1: Int32;
begin
  Result := FKs[0];
end;

function TF2mFieldElement.GetK2: Int32;
begin
  if System.Length(FKs) >= 2 then
    Result := FKs[1]
  else
    Result := 0;
end;

function TF2mFieldElement.GetK3: Int32;
begin
  if System.Length(FKs) >= 3 then
    Result := FKs[2]
  else
    Result := 0;
end;

end.
