{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ * ******************************************************************************* * }

unit ClpSimpleBigDecimal;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpCryptoLibTypes;

resourcestring
  SScaleMayNotBeNegative = 'scale may not be negative';
  SSameScaleRequired = 'Only SimpleBigDecimal of same scale allowed in arithmetic operations';

type
  /// <summary>
  /// Class representing a simple version of a big decimal. A
  /// SimpleBigDecimal is basically a BigInteger with a few digits on the
  /// right of the decimal point. The number of (binary) digits on the right
  /// of the decimal point is called the scale of the SimpleBigDecimal.
  /// </summary>
  TSimpleBigDecimal = record
  strict private
    FBigInt: TBigInteger;
    FScale: Int32;
    procedure CheckScale(const AB: TSimpleBigDecimal);
  public
    constructor Create(const ABigInt: TBigInteger; AScale: Int32);

    class function GetInstance(const AVal: TBigInteger; AScale: Int32): TSimpleBigDecimal; static;

    function AdjustScale(ANewScale: Int32): TSimpleBigDecimal;

    function Add(const AB: TSimpleBigDecimal): TSimpleBigDecimal; overload;
    function Add(const AB: TBigInteger): TSimpleBigDecimal; overload;
    function Negate: TSimpleBigDecimal;
    function Subtract(const AB: TSimpleBigDecimal): TSimpleBigDecimal; overload;
    function Subtract(const AB: TBigInteger): TSimpleBigDecimal; overload;
    function Multiply(const AB: TSimpleBigDecimal): TSimpleBigDecimal; overload;
    function Multiply(const AB: TBigInteger): TSimpleBigDecimal; overload;
    function Divide(const AB: TSimpleBigDecimal): TSimpleBigDecimal; overload;
    function Divide(const AB: TBigInteger): TSimpleBigDecimal; overload;
    function ShiftLeft(AN: Int32): TSimpleBigDecimal;

    function CompareTo(const AVal: TSimpleBigDecimal): Int32; overload;
    function CompareTo(const AVal: TBigInteger): Int32; overload;

    function Floor: TBigInteger;
    function Round: TBigInteger;

    function GetBigInt: TBigInteger;
    function GetIntValue: Int32;
    function GetLongValue: Int64;
    function GetScale: Int32;

    function ToString: String;
    function Equals(const AOther: TSimpleBigDecimal): Boolean;
    function GetHashCode: Int32;

    property BigInt: TBigInteger read GetBigInt;
    property IntValue: Int32 read GetIntValue;
    property LongValue: Int64 read GetLongValue;
    property Scale: Int32 read GetScale;
  end;

implementation

{ TSimpleBigDecimal }

constructor TSimpleBigDecimal.Create(const ABigInt: TBigInteger; AScale: Int32);
begin
  if AScale < 0 then
    raise EArgumentCryptoLibException.Create(SScaleMayNotBeNegative);
  FBigInt := ABigInt;
  FScale := AScale;
end;

class function TSimpleBigDecimal.GetInstance(const AVal: TBigInteger; AScale: Int32): TSimpleBigDecimal;
begin
  Result := TSimpleBigDecimal.Create(AVal.ShiftLeft(AScale), AScale);
end;

procedure TSimpleBigDecimal.CheckScale(const AB: TSimpleBigDecimal);
begin
  if FScale <> AB.FScale then
    raise EArgumentCryptoLibException.Create(SSameScaleRequired);
end;

function TSimpleBigDecimal.AdjustScale(ANewScale: Int32): TSimpleBigDecimal;
begin
  if ANewScale < 0 then
    raise EArgumentCryptoLibException.Create(SScaleMayNotBeNegative);
  if ANewScale = FScale then
    Exit(Self);
  Result := TSimpleBigDecimal.Create(FBigInt.ShiftLeft(ANewScale - FScale), ANewScale);
end;

function TSimpleBigDecimal.Add(const AB: TSimpleBigDecimal): TSimpleBigDecimal;
begin
  CheckScale(AB);
  Result := TSimpleBigDecimal.Create(FBigInt.Add(AB.FBigInt), FScale);
end;

function TSimpleBigDecimal.Add(const AB: TBigInteger): TSimpleBigDecimal;
begin
  Result := TSimpleBigDecimal.Create(FBigInt.Add(AB.ShiftLeft(FScale)), FScale);
end;

function TSimpleBigDecimal.Negate: TSimpleBigDecimal;
begin
  Result := TSimpleBigDecimal.Create(FBigInt.Negate(), FScale);
end;

function TSimpleBigDecimal.Subtract(const AB: TSimpleBigDecimal): TSimpleBigDecimal;
begin
  Result := Add(AB.Negate());
end;

function TSimpleBigDecimal.Subtract(const AB: TBigInteger): TSimpleBigDecimal;
begin
  Result := TSimpleBigDecimal.Create(FBigInt.Subtract(AB.ShiftLeft(FScale)), FScale);
end;

function TSimpleBigDecimal.Multiply(const AB: TSimpleBigDecimal): TSimpleBigDecimal;
begin
  CheckScale(AB);
  Result := TSimpleBigDecimal.Create(FBigInt.Multiply(AB.FBigInt), FScale + FScale);
end;

function TSimpleBigDecimal.Multiply(const AB: TBigInteger): TSimpleBigDecimal;
begin
  Result := TSimpleBigDecimal.Create(FBigInt.Multiply(AB), FScale);
end;

function TSimpleBigDecimal.Divide(const AB: TSimpleBigDecimal): TSimpleBigDecimal;
var
  LDividend: TBigInteger;
begin
  CheckScale(AB);
  LDividend := FBigInt.ShiftLeft(FScale);
  Result := TSimpleBigDecimal.Create(LDividend.Divide(AB.FBigInt), FScale);
end;

function TSimpleBigDecimal.Divide(const AB: TBigInteger): TSimpleBigDecimal;
begin
  Result := TSimpleBigDecimal.Create(FBigInt.Divide(AB), FScale);
end;

function TSimpleBigDecimal.ShiftLeft(AN: Int32): TSimpleBigDecimal;
begin
  Result := TSimpleBigDecimal.Create(FBigInt.ShiftLeft(AN), FScale);
end;

function TSimpleBigDecimal.CompareTo(const AVal: TSimpleBigDecimal): Int32;
begin
  CheckScale(AVal);
  Result := FBigInt.CompareTo(AVal.FBigInt);
end;

function TSimpleBigDecimal.CompareTo(const AVal: TBigInteger): Int32;
begin
  Result := FBigInt.CompareTo(AVal.ShiftLeft(FScale));
end;

function TSimpleBigDecimal.Floor: TBigInteger;
begin
  Result := FBigInt.ShiftRight(FScale);
end;

function TSimpleBigDecimal.Round: TBigInteger;
var
  LOneHalf: TSimpleBigDecimal;
begin
  LOneHalf := TSimpleBigDecimal.Create(TBigInteger.One, 1);
  Result := Add(LOneHalf.AdjustScale(FScale)).Floor();
end;

function TSimpleBigDecimal.GetBigInt: TBigInteger;
begin
  Result := FBigInt;
end;

function TSimpleBigDecimal.GetIntValue: Int32;
begin
  Result := Floor().Int32Value;
end;

function TSimpleBigDecimal.GetLongValue: Int64;
begin
  Result := Floor().Int64Value;
end;

function TSimpleBigDecimal.GetScale: Int32;
begin
  Result := FScale;
end;

function TSimpleBigDecimal.ToString: String;
var
  LFloorBigInt, LFract: TBigInteger;
  LLeftOfPoint, LFractStr: String;
  LRightOfPoint: String;
  LFractLen, LZeroes, LI: Int32;
begin
  if FScale = 0 then
    Exit(FBigInt.ToString());

  LFloorBigInt := Floor();
  LFract := FBigInt.Subtract(LFloorBigInt.ShiftLeft(FScale));
  if FBigInt.SignValue = -1 then
    LFract := TBigInteger.One.ShiftLeft(FScale).Subtract(LFract);

  if (LFloorBigInt.SignValue = -1) and (not LFract.Equals(TBigInteger.Zero)) then
    LFloorBigInt := LFloorBigInt.Add(TBigInteger.One);

  LLeftOfPoint := LFloorBigInt.ToString();

  LFractStr := LFract.ToString(2);
  LFractLen := System.Length(LFractStr);
  LZeroes := FScale - LFractLen;

  LRightOfPoint := '';
  for LI := 1 to LZeroes do
    LRightOfPoint := LRightOfPoint + '0';
  LRightOfPoint := LRightOfPoint + LFractStr;

  Result := LLeftOfPoint + '.' + LRightOfPoint;
end;

function TSimpleBigDecimal.Equals(const AOther: TSimpleBigDecimal): Boolean;
begin
  Result := FBigInt.Equals(AOther.BigInt) and (FScale = AOther.Scale);
end;

function TSimpleBigDecimal.GetHashCode: Int32;
begin
  Result := FBigInt.GetHashCode() xor FScale;
end;

end.
