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

unit ClpSecT283K1Custom;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpBitOperations,
  ClpNat,
  ClpNat320,
  ClpInterleave,
  ClpEncoders,
  ClpECCurve,
  ClpECCurveConstants,
  ClpECFieldElement,
  ClpECPoint,
  ClpECLookupTables,
  ClpMultipliers,
  ClpIECCore,
  ClpIECFieldElement,
  ClpISecT283K1Custom,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidSecT283FieldElement = 'value invalid for SecT283FieldElement';

type
  TSecT283Field = class sealed(TObject)
  strict private
  const
    M27: UInt64 = UInt64.MaxValue shr 37;
    M57: UInt64 = UInt64.MaxValue shr 7;
  class var
    FRootZ: TCryptoLibUInt64Array;
  class procedure Boot; static;
  class procedure ImplCompactExt(const AZz: TCryptoLibUInt64Array); static;
  class procedure ImplExpand(const AX: TCryptoLibUInt64Array;
    const AZ: TCryptoLibUInt64Array); static;
  class procedure ImplMulw(const AU: TCryptoLibUInt64Array; AX, AY: UInt64;
    const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
  class procedure ImplMultiply(const AX, AY, AZZ: TCryptoLibUInt64Array); static;
  class procedure ImplSquare(const AX, AZZ: TCryptoLibUInt64Array); static;
  class constructor Create;
  public
    class procedure Add(const AX, AY, AZ: TCryptoLibUInt64Array); static;
    class procedure AddBothTo(const AX, AY, AZ: TCryptoLibUInt64Array); static;
    class procedure AddExt(const AXX, AYY, AZZ: TCryptoLibUInt64Array); static;
    class procedure AddOne(const AX, AZ: TCryptoLibUInt64Array); static;
    class procedure AddTo(const AX, AZ: TCryptoLibUInt64Array); static;
    class function FromBigInteger(const AX: TBigInteger): TCryptoLibUInt64Array; static;
    class procedure HalfTrace(const AX, AZ: TCryptoLibUInt64Array); static;
    class procedure Invert(const AX, AZ: TCryptoLibUInt64Array); static;
    class procedure Multiply(const AX, AY, AZ: TCryptoLibUInt64Array); static;
    class procedure MultiplyAddToExt(const AX, AY, AZZ: TCryptoLibUInt64Array); static;
    class procedure MultiplyExt(const AX, AY, AZZ: TCryptoLibUInt64Array); static;
    class procedure Reduce(const AXX, AZ: TCryptoLibUInt64Array); static;
    class procedure Reduce37(const AZ: TCryptoLibUInt64Array; AZOff: Int32); static;
    class procedure Sqrt(const AX, AZ: TCryptoLibUInt64Array); static;
    class procedure Square(const AX, AZ: TCryptoLibUInt64Array); static;
    class procedure SquareAddToExt(const AX, AZZ: TCryptoLibUInt64Array); static;
    class procedure SquareExt(const AX, AZZ: TCryptoLibUInt64Array); static;
    class procedure SquareN(const AX: TCryptoLibUInt64Array; AN: Int32;
      const AZ: TCryptoLibUInt64Array); static;
    class function Trace(const AX: TCryptoLibUInt64Array): UInt32; static;
  end;

type
  TSecT283FieldElement = class sealed(TAbstractF2mFieldElement,
    IAbstractF2mFieldElement, IECFieldElement, ISecT283FieldElement)
  strict private
    FX: TCryptoLibUInt64Array;
    function GetX: TCryptoLibUInt64Array; inline;
  public
    constructor Create(const AX: TBigInteger); overload;
    constructor Create(); overload;
    constructor Create(const AX: TCryptoLibUInt64Array); overload;

    function GetFieldName: String; override;
    function GetFieldSize: Int32; override;
    function GetIsOne: Boolean; override;
    function GetIsZero: Boolean; override;
    function ToBigInteger: TBigInteger; override;
    function TestBitZero: Boolean; override;

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
    function HalfTrace: IECFieldElement; override;
    function GetHasFastTrace: Boolean; override;
    function Trace: Int32; override;
    function Invert: IECFieldElement; override;
    function Sqrt: IECFieldElement; override;

    function GetRepresentation: Int32;
    function GetM: Int32;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;

    function Equals(const AOther: IECFieldElement): Boolean; override;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property X: TCryptoLibUInt64Array read GetX;
  end;

type
  TSecT283K1Point = class sealed(TAbstractF2mPoint, IAbstractF2mPoint, IECPoint,
    ISecT283K1Point)
  strict protected
    function GetCompressionYTilde: Boolean; override;
  public
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement); overload;
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>); overload;

    function GetYCoord: IECFieldElement; override;
    function Detach: IECPoint; override;

    function Add(const AB: IECPoint): IECPoint; override;
    function Twice: IECPoint; override;
    function TwicePlus(const AB: IECPoint): IECPoint; override;
    function Negate: IECPoint; override;
  end;

type
  TSecT283K1Curve = class sealed(TAbstractF2mCurve, IAbstractF2mCurve, IECCurve,
    ISecT283K1Curve)
  strict private
  const
    SECT283K1_DEFAULT_COORDS = TECCurveConstants.COORD_LAMBDA_PROJECTIVE;
    SECT283K1_FE_LONGS = 5;
  strict private
  type
    TSecT283K1LookupTable = class sealed(TAbstractECLookupTable, IECLookupTable,
      ISecT283K1LookupTable)
    strict private
      FOuter: ISecT283K1Curve;
      FTable: TCryptoLibUInt64Array;
      FSize: Int32;
      function CreatePoint(const AX, AY: TCryptoLibUInt64Array): IECPoint;
    public
      constructor Create(const AOuter: ISecT283K1Curve;
        const ATable: TCryptoLibUInt64Array; ASize: Int32);
      function GetSize: Int32; override;
      function Lookup(AIndex: Int32): IECPoint; override;
      function LookupVar(AIndex: Int32): IECPoint; override;
    end;
  class var
    FSecT283K1AffineZs: TCryptoLibGenericArray<IECFieldElement>;
  class procedure Boot; static;
  class constructor Create;
  var
    FInfinity: TSecT283K1Point;
  strict protected
    function GetIsKoblitz: Boolean; override;
    function CreateDefaultMultiplier: IECMultiplier; override;
  public
    constructor Create;

    function CloneCurve: IECCurve; override;
    function GetFieldSize: Int32; override;
    function GetInfinity: IECPoint; override;
    function FromBigInteger(const AX: TBigInteger): IECFieldElement; override;
    function CreateRawPoint(const AX, AY: IECFieldElement): IECPoint; override;
    function CreateRawPoint(const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint; override;
    function CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
      AOff, ALen: Int32): IECLookupTable; override;
    function SupportsCoordinateSystem(ACoord: Int32): Boolean; override;
    function GetM: Int32;
    function GetIsTrinomial: Boolean;
    function GetK1: Int32;
    function GetK2: Int32;
    function GetK3: Int32;

    class property SecT283K1AffineZs: TCryptoLibGenericArray<IECFieldElement> read FSecT283K1AffineZs;
  end;

implementation

{ TSecT283Field }

class procedure TSecT283Field.Boot;
begin
  FRootZ := TCryptoLibUInt64Array.Create($0C30C30C30C30808, $30C30C30C30C30C3,
    $820820820820830C, $0820820820820820, $2082082);
end;

class constructor TSecT283Field.Create;
begin
  Boot;
end;

class procedure TSecT283Field.ImplCompactExt(const AZz: TCryptoLibUInt64Array);
var
  LZ0, LZ1, LZ2, LZ3, LZ4, LZ5, LZ6, LZ7, LZ8, LZ9: UInt64;
begin
  LZ0 := AZz[0]; LZ1 := AZz[1]; LZ2 := AZz[2]; LZ3 := AZz[3]; LZ4 := AZz[4];
  LZ5 := AZz[5]; LZ6 := AZz[6]; LZ7 := AZz[7]; LZ8 := AZz[8]; LZ9 := AZz[9];
  AZz[0] := LZ0 xor (LZ1 shl 57);
  AZz[1] := (LZ1 shr 7) xor (LZ2 shl 50);
  AZz[2] := (LZ2 shr 14) xor (LZ3 shl 43);
  AZz[3] := (LZ3 shr 21) xor (LZ4 shl 36);
  AZz[4] := (LZ4 shr 28) xor (LZ5 shl 29);
  AZz[5] := (LZ5 shr 35) xor (LZ6 shl 22);
  AZz[6] := (LZ6 shr 42) xor (LZ7 shl 15);
  AZz[7] := (LZ7 shr 49) xor (LZ8 shl 8);
  AZz[8] := (LZ8 shr 56) xor (LZ9 shl 1);
  AZz[9] := (LZ9 shr 63);
end;

class procedure TSecT283Field.ImplExpand(const AX: TCryptoLibUInt64Array;
  const AZ: TCryptoLibUInt64Array);
var
  LX0, LX1, LX2, LX3, LX4: UInt64;
begin
  LX0 := AX[0]; LX1 := AX[1]; LX2 := AX[2]; LX3 := AX[3]; LX4 := AX[4];
  AZ[0] := LX0 and M57;
  AZ[1] := ((LX0 shr 57) xor (LX1 shl 7)) and M57;
  AZ[2] := ((LX1 shr 50) xor (LX2 shl 14)) and M57;
  AZ[3] := ((LX2 shr 43) xor (LX3 shl 21)) and M57;
  AZ[4] := (LX3 shr 36) xor (LX4 shl 28);
end;

class procedure TSecT283Field.ImplMulw(const AU: TCryptoLibUInt64Array; AX, AY: UInt64;
  const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LJ: UInt32;
  LG, LH, LL: UInt64;
  LK: Int32;
begin
  {$IFDEF DEBUG}
  Assert(AX shr 57 = 0);
  Assert(AY shr 57 = 0);
  {$ENDIF DEBUG}
  AU[1] := AY;
  AU[2] := AU[1] shl 1;
  AU[3] := AU[2] xor AY;
  AU[4] := AU[2] shl 1;
  AU[5] := AU[4] xor AY;
  AU[6] := AU[3] shl 1;
  AU[7] := AU[6] xor AY;

  LJ := UInt32(AX);
  LH := 0;
  LL := AU[Int32(LJ) and 7];
  LK := 48;
  repeat
    LJ := UInt32(AX shr LK);
    LG := AU[Int32(LJ) and 7]
      xor (AU[Int32(LJ shr 3) and 7] shl 3)
      xor (AU[Int32(LJ shr 6) and 7] shl 6);
    LL := LL xor (LG shl LK);
    LH := LH xor (UInt64(Int64(LG) shr (64 - LK)));
    Dec(LK, 9);
  until LK <= 0;

  LH := LH xor ((UInt64(TBitOperations.Asr64(Int64(AY) shl 7, 63)) and (AX and $0100804020100800)) shr 8);

  {$IFDEF DEBUG}
  Assert(LH shr 49 = 0);
  {$ENDIF DEBUG}
  AZ[AZOff] := LL and M57;
  AZ[AZOff + 1] := (LL shr 57) xor (LH shl 7);
end;

class procedure TSecT283Field.ImplMultiply(const AX, AY, AZZ: TCryptoLibUInt64Array);
var
  LA, LB: TCryptoLibUInt64Array;
  LP: TCryptoLibUInt64Array;
  LU0, LV0, LU1, LV1, LU2, LV2, LU3, LV3, LA4, LB4, LA5, LB5: UInt64;
  LT1, LT2, LT3, LT4, LT5, LT6, LT7, LT8, LT9, LT10, LT11, LT12, LT13, LT14, LT15, LT16: UInt64;
  LT17, LT18, LT19, LT20, LT21, LT22, LT23, LT24, LT25, LT26, LT27, LT28, LT29: UInt64;
  LT30, LT31, LT32, LT33, LT34, LT35, LT36, LT37, LT38, LT39: UInt64;
  LI: Int32;
begin
  SetLength(LA, 5);
  SetLength(LB, 5);
  SetLength(LP, 26);
  ImplExpand(AX, LA);
  ImplExpand(AY, LB);

  for LI := 0 to 9 do
    AZZ[LI] := 0;

  ImplMulw(AZZ, LA[0], LB[0], LP, 0);
  ImplMulw(AZZ, LA[1], LB[1], LP, 2);
  ImplMulw(AZZ, LA[2], LB[2], LP, 4);
  ImplMulw(AZZ, LA[3], LB[3], LP, 6);
  ImplMulw(AZZ, LA[4], LB[4], LP, 8);

  LU0 := LA[0] xor LA[1]; LV0 := LB[0] xor LB[1];
  LU1 := LA[0] xor LA[2]; LV1 := LB[0] xor LB[2];
  LU2 := LA[2] xor LA[4]; LV2 := LB[2] xor LB[4];
  LU3 := LA[3] xor LA[4]; LV3 := LB[3] xor LB[4];

  ImplMulw(AZZ, LU1 xor LA[3], LV1 xor LB[3], LP, 18);
  ImplMulw(AZZ, LU2 xor LA[1], LV2 xor LB[1], LP, 20);

  LA4 := LU0 xor LU3; LB4 := LV0 xor LV3;
  LA5 := LA4 xor LA[2]; LB5 := LB4 xor LB[2];

  ImplMulw(AZZ, LA4, LB4, LP, 22);
  ImplMulw(AZZ, LA5, LB5, LP, 24);

  ImplMulw(AZZ, LU0, LV0, LP, 10);
  ImplMulw(AZZ, LU1, LV1, LP, 12);
  ImplMulw(AZZ, LU2, LV2, LP, 14);
  ImplMulw(AZZ, LU3, LV3, LP, 16);

  AZZ[0] := LP[0];
  AZZ[9] := LP[9];

  LT1 := LP[0] xor LP[1];
  LT2 := LT1 xor LP[2];
  LT3 := LT2 xor LP[10];
  AZZ[1] := LT3;

  LT4 := LP[3] xor LP[4];
  LT5 := LP[11] xor LP[12];
  LT6 := LT4 xor LT5;
  LT7 := LT2 xor LT6;
  AZZ[2] := LT7;

  LT8 := LT1 xor LT4;
  LT9 := LP[5] xor LP[6];
  LT10 := LT8 xor LT9;
  LT11 := LT10 xor LP[8];
  LT12 := LP[13] xor LP[14];
  LT13 := LT11 xor LT12;
  LT14 := LP[18] xor LP[22];
  LT15 := LT14 xor LP[24];
  LT16 := LT13 xor LT15;
  AZZ[3] := LT16;

  LT17 := LP[7] xor LP[8];
  LT18 := LT17 xor LP[9];
  LT19 := LT18 xor LP[17];
  AZZ[8] := LT19;

  LT20 := LT18 xor LT9;
  LT21 := LP[15] xor LP[16];
  LT22 := LT20 xor LT21;
  AZZ[7] := LT22;

  LT23 := LT22 xor LT3;
  LT24 := LP[19] xor LP[20];
  LT25 := LP[25] xor LP[24];
  LT26 := LP[18] xor LP[23];
  LT27 := LT24 xor LT25;
  LT28 := LT27 xor LT26;
  LT29 := LT28 xor LT23;
  AZZ[4] := LT29;

  LT30 := LT7 xor LT19;
  LT31 := LT27 xor LT30;
  LT32 := LP[21] xor LP[22];
  LT33 := LT31 xor LT32;
  AZZ[5] := LT33;

  LT34 := LT11 xor LP[0];
  LT35 := LT34 xor LP[9];
  LT36 := LT35 xor LT12;
  LT37 := LT36 xor LP[21];
  LT38 := LT37 xor LP[23];
  LT39 := LT38 xor LP[25];
  AZZ[6] := LT39;

  ImplCompactExt(AZZ);
end;

class procedure TSecT283Field.ImplSquare(const AX, AZZ: TCryptoLibUInt64Array);
begin
  TInterleave.Expand64To128(AX, 0, 4, AZZ, 0);
  AZZ[8] := TInterleave.Expand32to64(UInt32(AX[4]));
end;

class procedure TSecT283Field.Add(const AX, AY, AZ: TCryptoLibUInt64Array);
begin
  AZ[0] := AX[0] xor AY[0];
  AZ[1] := AX[1] xor AY[1];
  AZ[2] := AX[2] xor AY[2];
  AZ[3] := AX[3] xor AY[3];
  AZ[4] := AX[4] xor AY[4];
end;

class procedure TSecT283Field.AddBothTo(const AX, AY, AZ: TCryptoLibUInt64Array);
begin
  AZ[0] := AZ[0] xor AX[0] xor AY[0];
  AZ[1] := AZ[1] xor AX[1] xor AY[1];
  AZ[2] := AZ[2] xor AX[2] xor AY[2];
  AZ[3] := AZ[3] xor AX[3] xor AY[3];
  AZ[4] := AZ[4] xor AX[4] xor AY[4];
end;

class procedure TSecT283Field.AddExt(const AXX, AYY, AZZ: TCryptoLibUInt64Array);
begin
  AZZ[0] := AXX[0] xor AYY[0];
  AZZ[1] := AXX[1] xor AYY[1];
  AZZ[2] := AXX[2] xor AYY[2];
  AZZ[3] := AXX[3] xor AYY[3];
  AZZ[4] := AXX[4] xor AYY[4];
  AZZ[5] := AXX[5] xor AYY[5];
  AZZ[6] := AXX[6] xor AYY[6];
  AZZ[7] := AXX[7] xor AYY[7];
  AZZ[8] := AXX[8] xor AYY[8];
end;

class procedure TSecT283Field.AddOne(const AX, AZ: TCryptoLibUInt64Array);
begin
  AZ[0] := AX[0] xor 1;
  AZ[1] := AX[1];
  AZ[2] := AX[2];
  AZ[3] := AX[3];
  AZ[4] := AX[4];
end;

class procedure TSecT283Field.AddTo(const AX, AZ: TCryptoLibUInt64Array);
begin
  AZ[0] := AZ[0] xor AX[0];
  AZ[1] := AZ[1] xor AX[1];
  AZ[2] := AZ[2] xor AX[2];
  AZ[3] := AZ[3] xor AX[3];
  AZ[4] := AZ[4] xor AX[4];
end;

class function TSecT283Field.FromBigInteger(const AX: TBigInteger): TCryptoLibUInt64Array;
begin
  Result := TNat.FromBigInteger64(283, AX);
end;

class procedure TSecT283Field.HalfTrace(const AX, AZ: TCryptoLibUInt64Array);
var
  LTT: TCryptoLibUInt64Array;
  LI: Int32;
begin
  LTT := TNat.Create64(9);
  TNat320.Copy64(AX, AZ);
  LI := 1;
  while LI < 283 do
  begin
    ImplSquare(AZ, LTT);
    Reduce(LTT, AZ);
    ImplSquare(AZ, LTT);
    Reduce(LTT, AZ);
    AddTo(AX, AZ);
    Inc(LI, 2);
  end;
end;

class procedure TSecT283Field.Invert(const AX, AZ: TCryptoLibUInt64Array);
var
  LT0, LT1: TCryptoLibUInt64Array;
begin
  if TNat320.IsZero64(AX) then
    raise EInvalidOperationCryptoLibException.Create('');
  SetLength(LT0, 5);
  SetLength(LT1, 5);
  Square(AX, LT0);
  Multiply(LT0, AX, LT0);
  SquareN(LT0, 2, LT1);
  Multiply(LT1, LT0, LT1);
  SquareN(LT1, 4, LT0);
  Multiply(LT0, LT1, LT0);
  SquareN(LT0, 8, LT1);
  Multiply(LT1, LT0, LT1);
  Square(LT1, LT1);
  Multiply(LT1, AX, LT1);
  SquareN(LT1, 17, LT0);
  Multiply(LT0, LT1, LT0);
  Square(LT0, LT0);
  Multiply(LT0, AX, LT0);
  SquareN(LT0, 35, LT1);
  Multiply(LT1, LT0, LT1);
  SquareN(LT1, 70, LT0);
  Multiply(LT0, LT1, LT0);
  Square(LT0, LT0);
  Multiply(LT0, AX, LT0);
  SquareN(LT0, 141, LT1);
  Multiply(LT1, LT0, LT1);
  Square(LT1, AZ);
end;

class procedure TSecT283Field.Multiply(const AX, AY, AZ: TCryptoLibUInt64Array);
var
  LTT: TCryptoLibUInt64Array;
begin
  LTT := TNat320.CreateExt64();
  ImplMultiply(AX, AY, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecT283Field.MultiplyAddToExt(const AX, AY, AZZ: TCryptoLibUInt64Array);
var
  LTT: TCryptoLibUInt64Array;
begin
  LTT := TNat320.CreateExt64();
  ImplMultiply(AX, AY, LTT);
  AddExt(AZZ, LTT, AZZ);
end;

class procedure TSecT283Field.MultiplyExt(const AX, AY, AZZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  for LI := 0 to 9 do
    AZZ[LI] := 0;
  ImplMultiply(AX, AY, AZZ);
end;

class procedure TSecT283Field.Reduce(const AXX, AZ: TCryptoLibUInt64Array);
var
  LX0, LX1, LX2, LX3, LX4, LX5, LX6, LX7, LX8: UInt64;
  LT: UInt64;
begin
  LX0 := AXX[0]; LX1 := AXX[1]; LX2 := AXX[2]; LX3 := AXX[3]; LX4 := AXX[4];
  LX5 := AXX[5]; LX6 := AXX[6]; LX7 := AXX[7]; LX8 := AXX[8];

  LX3 := LX3 xor (LX8 shl 37) xor (LX8 shl 42) xor (LX8 shl 44) xor (LX8 shl 49);
  LX4 := LX4 xor (LX8 shr 27) xor (LX8 shr 22) xor (LX8 shr 20) xor (LX8 shr 15);

  LX2 := LX2 xor (LX7 shl 37) xor (LX7 shl 42) xor (LX7 shl 44) xor (LX7 shl 49);
  LX3 := LX3 xor (LX7 shr 27) xor (LX7 shr 22) xor (LX7 shr 20) xor (LX7 shr 15);

  LX1 := LX1 xor (LX6 shl 37) xor (LX6 shl 42) xor (LX6 shl 44) xor (LX6 shl 49);
  LX2 := LX2 xor (LX6 shr 27) xor (LX6 shr 22) xor (LX6 shr 20) xor (LX6 shr 15);

  LX0 := LX0 xor (LX5 shl 37) xor (LX5 shl 42) xor (LX5 shl 44) xor (LX5 shl 49);
  LX1 := LX1 xor (LX5 shr 27) xor (LX5 shr 22) xor (LX5 shr 20) xor (LX5 shr 15);

  LT := LX4 shr 27;
  AZ[0] := LX0 xor LT xor (LT shl 5) xor (LT shl 7) xor (LT shl 12);
  AZ[1] := LX1;
  AZ[2] := LX2;
  AZ[3] := LX3;
  AZ[4] := LX4 and M27;
end;

class procedure TSecT283Field.Reduce37(const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LZ4: UInt64;
  LT: UInt64;
begin
  LZ4 := AZ[AZOff + 4];
  LT := LZ4 shr 27;
  AZ[AZOff] := AZ[AZOff] xor LT xor (LT shl 5) xor (LT shl 7) xor (LT shl 12);
  AZ[AZOff + 4] := LZ4 and M27;
end;

class procedure TSecT283Field.Sqrt(const AX, AZ: TCryptoLibUInt64Array);
var
  LOdd: TCryptoLibUInt64Array;
  LE0, LE1, LE2: UInt64;
begin
  LOdd := TNat320.Create64();
  LOdd[0] := TInterleave.Unshuffle(AX[0], AX[1], LE0);
  LOdd[1] := TInterleave.Unshuffle(AX[2], AX[3], LE1);
  LOdd[2] := UInt64(TInterleave.Unshuffle(AX[4], LE2));
  Multiply(LOdd, FRootZ, AZ);
  AZ[0] := AZ[0] xor LE0;
  AZ[1] := AZ[1] xor LE1;
  AZ[2] := AZ[2] xor LE2;
end;

class procedure TSecT283Field.Square(const AX, AZ: TCryptoLibUInt64Array);
var
  LTT: TCryptoLibUInt64Array;
begin
  LTT := TNat.Create64(9);
  ImplSquare(AX, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecT283Field.SquareAddToExt(const AX, AZZ: TCryptoLibUInt64Array);
var
  LTT: TCryptoLibUInt64Array;
begin
  LTT := TNat.Create64(9);
  ImplSquare(AX, LTT);
  AddExt(AZZ, LTT, AZZ);
end;

class procedure TSecT283Field.SquareExt(const AX, AZZ: TCryptoLibUInt64Array);
begin
  ImplSquare(AX, AZZ);
end;

class procedure TSecT283Field.SquareN(const AX: TCryptoLibUInt64Array; AN: Int32;
  const AZ: TCryptoLibUInt64Array);
var
  LTT: TCryptoLibUInt64Array;
begin
  {$IFDEF DEBUG}
  Assert(AN > 0);
  {$ENDIF DEBUG}
  LTT := TNat.Create64(9);
  ImplSquare(AX, LTT);
  Reduce(LTT, AZ);
  Dec(AN);
  while AN > 0 do
  begin
    ImplSquare(AZ, LTT);
    Reduce(LTT, AZ);
    Dec(AN);
  end;
end;

class function TSecT283Field.Trace(const AX: TCryptoLibUInt64Array): UInt32;
begin
  Result := UInt32(AX[0] xor (AX[4] shr 15)) and 1;
end;

{ TSecT283FieldElement }

constructor TSecT283FieldElement.Create(const AX: TBigInteger);
begin
  Inherited Create;
  if (not AX.IsInitialized) or (AX.SignValue < 0) or (AX.BitLength > 283) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSecT283FieldElement);
  FX := TSecT283Field.FromBigInteger(AX);
end;

constructor TSecT283FieldElement.Create();
begin
  Inherited Create;
  FX := TNat320.Create64();
end;

constructor TSecT283FieldElement.Create(const AX: TCryptoLibUInt64Array);
begin
  Inherited Create;
  FX := AX;
end;

function TSecT283FieldElement.GetX: TCryptoLibUInt64Array;
begin
  Result := FX;
end;

function TSecT283FieldElement.GetFieldName: String;
begin
  Result := 'SecT283Field';
end;

function TSecT283FieldElement.GetFieldSize: Int32;
begin
  Result := 283;
end;

function TSecT283FieldElement.GetIsOne: Boolean;
begin
  Result := TNat320.IsOne64(FX);
end;

function TSecT283FieldElement.GetIsZero: Boolean;
begin
  Result := TNat320.IsZero64(FX);
end;

function TSecT283FieldElement.ToBigInteger: TBigInteger;
begin
  Result := TNat320.ToBigInteger64(FX);
end;

function TSecT283FieldElement.TestBitZero: Boolean;
begin
  Result := (FX[0] and 1) <> 0;
end;

function TSecT283FieldElement.Add(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  LZ := TNat320.Create64();
  TSecT283Field.Add(FX, (AB as ISecT283FieldElement).X, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.AddOne: IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  LZ := TNat320.Create64();
  TSecT283Field.AddOne(FX, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.Subtract(const AB: IECFieldElement): IECFieldElement;
begin
  Result := Add(AB);
end;

function TSecT283FieldElement.Multiply(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  LZ := TNat320.Create64();
  TSecT283Field.Multiply(FX, (AB as ISecT283FieldElement).X, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.MultiplyMinusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := MultiplyPlusProduct(AB, AX, AY);
end;

function TSecT283FieldElement.MultiplyPlusProduct(const AB, AX, AY: IECFieldElement): IECFieldElement;
var
  LAX, LBX, LXX, LYX: TCryptoLibUInt64Array;
  LTT: TCryptoLibUInt64Array;
  LZ: TCryptoLibUInt64Array;
begin
  LAX := FX;
  LBX := (AB as ISecT283FieldElement).X;
  LXX := (AX as ISecT283FieldElement).X;
  LYX := (AY as ISecT283FieldElement).X;
  LTT := TNat.Create64(9);
  TSecT283Field.MultiplyAddToExt(LAX, LBX, LTT);
  TSecT283Field.MultiplyAddToExt(LXX, LYX, LTT);
  LZ := TNat320.Create64();
  TSecT283Field.Reduce(LTT, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.Divide(const AB: IECFieldElement): IECFieldElement;
begin
  Result := Multiply(AB.Invert());
end;

function TSecT283FieldElement.Negate: IECFieldElement;
begin
  Result := Self as IECFieldElement;
end;

function TSecT283FieldElement.Square: IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  LZ := TNat320.Create64();
  TSecT283Field.Square(FX, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.SquareMinusProduct(const AX, AY: IECFieldElement): IECFieldElement;
begin
  Result := SquarePlusProduct(AX, AY);
end;

function TSecT283FieldElement.SquarePlusProduct(const AX, AY: IECFieldElement): IECFieldElement;
var
  LAX, LXX, LYX: TCryptoLibUInt64Array;
  LTT: TCryptoLibUInt64Array;
  LZ: TCryptoLibUInt64Array;
begin
  LAX := FX;
  LXX := (AX as ISecT283FieldElement).X;
  LYX := (AY as ISecT283FieldElement).X;
  LTT := TNat.Create64(9);
  TSecT283Field.SquareExt(LAX, LTT);
  TSecT283Field.MultiplyAddToExt(LXX, LYX, LTT);
  LZ := TNat320.Create64();
  TSecT283Field.Reduce(LTT, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.SquarePow(APow: Int32): IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  if APow < 1 then
    Exit(Self as IECFieldElement);
  LZ := TNat320.Create64();
  TSecT283Field.SquareN(FX, APow, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.HalfTrace: IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  LZ := TNat320.Create64();
  TSecT283Field.HalfTrace(FX, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.GetHasFastTrace: Boolean;
begin
  Result := True;
end;

function TSecT283FieldElement.Trace: Int32;
begin
  Result := Int32(TSecT283Field.Trace(FX));
end;

function TSecT283FieldElement.Invert: IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  LZ := TNat320.Create64();
  TSecT283Field.Invert(FX, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.Sqrt: IECFieldElement;
var
  LZ: TCryptoLibUInt64Array;
begin
  LZ := TNat320.Create64();
  TSecT283Field.Sqrt(FX, LZ);
  Result := TSecT283FieldElement.Create(LZ);
end;

function TSecT283FieldElement.GetRepresentation: Int32;
begin
  Result := TF2mFieldElement.Ppb;
end;

function TSecT283FieldElement.GetM: Int32;
begin
  Result := 283;
end;

function TSecT283FieldElement.GetK1: Int32;
begin
  Result := 5;
end;

function TSecT283FieldElement.GetK2: Int32;
begin
  Result := 7;
end;

function TSecT283FieldElement.GetK3: Int32;
begin
  Result := 12;
end;

function TSecT283FieldElement.Equals(const AOther: IECFieldElement): Boolean;
begin
  if (Self as IECFieldElement) = AOther then
    Exit(True);
  if AOther = nil then
    Exit(False);
  Result := TNat320.Eq64(FX, (AOther as ISecT283FieldElement).X);
end;

function TSecT283FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := 2831275 xor TArrayUtilities.GetArrayHashCode(FX, 0, 5);
end;

{ TSecT283K1Point }

constructor TSecT283K1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  Inherited Create(ACurve, AX, AY);
end;

constructor TSecT283K1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  Inherited Create(ACurve, AX, AY, AZs);
end;

function TSecT283K1Point.GetYCoord: IECFieldElement;
var
  LX, LL, LZ: IECFieldElement;
  LY: IECFieldElement;
begin
  LX := RawXCoord;
  LL := RawYCoord;
  if IsInfinity or LX.IsZero then
    Exit(LL);
  LY := LL.Add(LX).Multiply(LX);
  LZ := RawZCoords[0];
  if not LZ.IsOne then
    LY := LY.Divide(LZ);
  Result := LY;
end;

function TSecT283K1Point.GetCompressionYTilde: Boolean;
var
  LX, LY: IECFieldElement;
begin
  LX := RawXCoord;
  if LX.IsZero then
    Exit(False);
  LY := RawYCoord;
  Result := LY.TestBitZero <> LX.TestBitZero;
end;

function TSecT283K1Point.Detach: IECPoint;
begin
  Result := TSecT283K1Point.Create(nil, AffineXCoord, AffineYCoord);
end;

function TSecT283K1Point.Add(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LX1, LX2: ISecT283FieldElement;
  LL1, LZ1, LL2, LZ2: ISecT283FieldElement;
  LTT0: TCryptoLibUInt64Array;
  LT1, LT2, LT3: TCryptoLibUInt64Array;
  LZ1IsOne, LZ2IsOne: Boolean;
  LU2, LS2, LU1, LS1: TCryptoLibUInt64Array;
  LA, LB: TCryptoLibUInt64Array;
  LX3Arr, LZ3Arr, LL3Arr: TCryptoLibUInt64Array;
  LX3, LL3, LZ3: ISecT283FieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
  LNorm: IECPoint;
  LY1, LY2, LL, LX3Fe, LY3Fe, LZ3Fe: IECFieldElement;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Self as IECPoint);

  LCurve := Curve;
  LX1 := RawXCoord as ISecT283FieldElement;
  LX2 := AB.RawXCoord as ISecT283FieldElement;

  if LX1.IsZero then
  begin
    if LX2.IsZero then
      Exit(LCurve.Infinity);
    Exit(AB.Add(Self as IECPoint));
  end;

  LL1 := RawYCoord as ISecT283FieldElement;
  LZ1 := RawZCoords[0] as ISecT283FieldElement;
  LL2 := AB.RawYCoord as ISecT283FieldElement;
  LZ2 := AB.GetZCoord(0) as ISecT283FieldElement;

  LTT0 := TNat.Create64(9);
  LT1 := TNat320.Create64();
  LT2 := TNat320.Create64();
  LT3 := TNat320.Create64();

  LZ1IsOne := LZ1.IsOne;
  if LZ1IsOne then
  begin
    TNat320.Copy64(LX2.X, LT1);
    TNat320.Copy64(LL2.X, LT2);
  end
  else
  begin
    TSecT283Field.Multiply(LX2.X, LZ1.X, LT1);
    TSecT283Field.Multiply(LL2.X, LZ1.X, LT2);
  end;

  LZ2IsOne := LZ2.IsOne;
  if LZ2IsOne then
  begin
    TNat320.Copy64(LX1.X, LT3);
    TNat320.Copy64(LL1.X, LTT0);
  end
  else
  begin
    TSecT283Field.Multiply(LX1.X, LZ2.X, LT3);
    TSecT283Field.Multiply(LL1.X, LZ2.X, LTT0);
  end;

  TSecT283Field.AddTo(LTT0, LT2);
  TSecT283Field.Add(LT3, LT1, LTT0);

  if TNat320.IsZero64(LTT0) then
  begin
    if TNat320.IsZero64(LT2) then
      Exit(Twice());
    Exit(LCurve.Infinity);
  end;

  if LX2.IsZero then
  begin
    LNorm := Normalize();
    LX1 := LNorm.RawXCoord as ISecT283FieldElement;
    LY1 := LNorm.GetYCoord;
    LY2 := LL2;
    LL := LY1.Add(LY2).Divide(LX1 as IECFieldElement);
    LX3Fe := LL.Square().Add(LL).Add(LX1 as IECFieldElement);
    if LX3Fe.IsZero then
      Exit(TSecT283K1Point.Create(LCurve, LX3Fe, LCurve.B));
    LY3Fe := LL.Multiply((LX1 as IECFieldElement).Add(LX3Fe)).Add(LX3Fe).Add(LY1);
    LZ3Fe := LCurve.FromBigInteger(TBigInteger.One);
    Result := TSecT283K1Point.Create(LCurve, LX3Fe, LY3Fe.Divide(LX3Fe).Add(LX3Fe),
      TCryptoLibGenericArray<IECFieldElement>.Create(LZ3Fe));
    Exit;
  end;

  TSecT283Field.Square(LTT0, LTT0);
  TSecT283Field.Multiply(LT3, LT2, LT3);
  TSecT283Field.Multiply(LT1, LT2, LT1);
  LX3Arr := LT3;
  TSecT283Field.Multiply(LX3Arr, LT1, LX3Arr);
  if TNat320.IsZero64(LX3Arr) then
    Exit(TSecT283K1Point.Create(LCurve, TSecT283FieldElement.Create(LX3Arr),
      LCurve.B));
  LZ3Arr := LT2;
  TSecT283Field.Multiply(LZ3Arr, LTT0, LZ3Arr);
  if not LZ2IsOne then
    TSecT283Field.Multiply(LZ3Arr, LZ2.X, LZ3Arr);
  LL3Arr := LT1;
  TSecT283Field.AddTo(LTT0, LL3Arr);
  TSecT283Field.SquareExt(LL3Arr, LTT0);
  TSecT283Field.Add(LL1.X, LZ1.X, LL3Arr);
  TSecT283Field.MultiplyAddToExt(LZ3Arr, LL3Arr, LTT0);
  TSecT283Field.Reduce(LTT0, LL3Arr);
  if not LZ1IsOne then
    TSecT283Field.Multiply(LZ3Arr, LZ1.X, LZ3Arr);
  LX3 := TSecT283FieldElement.Create(LX3Arr);
  LL3 := TSecT283FieldElement.Create(LL3Arr);
  LZ3 := TSecT283FieldElement.Create(LZ3Arr);
  LZs := TCryptoLibGenericArray<IECFieldElement>.Create(LZ3 as IECFieldElement);
  Result := TSecT283K1Point.Create(LCurve, LX3 as IECFieldElement, LL3 as IECFieldElement, LZs);
end;

function TSecT283K1Point.Twice: IECPoint;
var
  LCurve: IECCurve;
  LX1, LL1, LZ1: IECFieldElement;
  LZ1IsOne: Boolean;
  LZ1Sq, LT, LX3, LZ3, LT1, LT2, LL3: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);
  LCurve := Curve;
  LX1 := RawXCoord;
  if LX1.IsZero then
    Exit(LCurve.Infinity);
  LL1 := RawYCoord;
  LZ1 := RawZCoords[0];
  LZ1IsOne := LZ1.IsOne;
  if LZ1IsOne then
    LZ1Sq := LZ1
  else
    LZ1Sq := LZ1.Square();
  if LZ1IsOne then
    LT := LL1.Square().Add(LL1)
  else
    LT := LL1.Add(LZ1).Multiply(LL1);
  if LT.IsZero then
    Exit(TSecT283K1Point.Create(LCurve, LT, LCurve.B));
  LX3 := LT.Square();
  if LZ1IsOne then
    LZ3 := LT
  else
    LZ3 := LT.Multiply(LZ1Sq);
  if LZ1IsOne then
    LT1 := LL1.Add(LX1).Square()
  else
    LT1 := LL1.Add(LX1).Square();
  if LZ1IsOne then
    LT2 := LZ1
  else
    LT2 := LZ1Sq.Square();
  LL3 := LT1.Add(LT).Add(LZ1Sq).Multiply(LT1).Add(LT2).Add(LX3).Add(LZ3);
  Result := TSecT283K1Point.Create(LCurve, LX3, LL3,
    TCryptoLibGenericArray<IECFieldElement>.Create(LZ3));
end;

function TSecT283K1Point.TwicePlus(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LX1, LX2, LZ2, LL1, LZ1, LL2: IECFieldElement;
  LX1Sq, LL1Sq, LZ1Sq, LL1Z1, LT, LL2Plus1, LA, LX2Z1Sq, LB: IECFieldElement;
  LX3, LZ3, LL3: IECFieldElement;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Twice());
  LCurve := Curve;
  LX1 := RawXCoord;
  if LX1.IsZero then
    Exit(AB);
  LX2 := AB.RawXCoord;
  LZ2 := AB.GetZCoord(0);
  if LX2.IsZero or not LZ2.IsOne then
    Exit(Twice().Add(AB));
  LL1 := RawYCoord;
  LZ1 := RawZCoords[0];
  LL2 := AB.RawYCoord;
  LX1Sq := LX1.Square();
  LL1Sq := LL1.Square();
  LZ1Sq := LZ1.Square();
  LL1Z1 := LL1.Multiply(LZ1);
  LT := LL1Sq.Add(LL1Z1);
  LL2Plus1 := LL2.AddOne();
  LA := LL2Plus1.Multiply(LZ1Sq).Add(LL1Sq).MultiplyPlusProduct(LT, LX1Sq, LZ1Sq);
  LX2Z1Sq := LX2.Multiply(LZ1Sq);
  LB := LX2Z1Sq.Add(LT).Square();
  if LB.IsZero then
  begin
    if LA.IsZero then
      Exit(AB.Twice());
    Exit(LCurve.Infinity);
  end;
  if LA.IsZero then
    Exit(TSecT283K1Point.Create(LCurve, LA, LCurve.B));
  LX3 := LA.Square().Multiply(LX2Z1Sq);
  LZ3 := LA.Multiply(LB).Multiply(LZ1Sq);
  LL3 := LA.Add(LB).Square().MultiplyPlusProduct(LT, LL2Plus1, LZ3);
  Result := TSecT283K1Point.Create(LCurve, LX3, LL3,
    TCryptoLibGenericArray<IECFieldElement>.Create(LZ3));
end;

function TSecT283K1Point.Negate: IECPoint;
var
  LX, LL, LZ: IECFieldElement;
begin
  if IsInfinity then
    Exit(Self as IECPoint);
  LX := RawXCoord;
  if LX.IsZero then
    Exit(Self as IECPoint);
  LL := RawYCoord;
  LZ := RawZCoords[0];
  Result := TSecT283K1Point.Create(Curve, LX, LL.Add(LZ),
    TCryptoLibGenericArray<IECFieldElement>.Create(LZ));
end;

{ TSecT283K1Curve.TSecT283K1LookupTable }

constructor TSecT283K1Curve.TSecT283K1LookupTable.Create(const AOuter: ISecT283K1Curve;
  const ATable: TCryptoLibUInt64Array; ASize: Int32);
begin
  Inherited Create;
  FOuter := AOuter;
  FTable := ATable;
  FSize := ASize;
end;

function TSecT283K1Curve.TSecT283K1LookupTable.GetSize: Int32;
begin
  Result := FSize;
end;

function TSecT283K1Curve.TSecT283K1LookupTable.CreatePoint(const AX, AY: TCryptoLibUInt64Array): IECPoint;
begin
  Result := FOuter.CreateRawPoint(TSecT283FieldElement.Create(AX) as IECFieldElement,
    TSecT283FieldElement.Create(AY) as IECFieldElement, TSecT283K1Curve.SecT283K1AffineZs);
end;

function TSecT283K1Curve.TSecT283K1LookupTable.Lookup(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt64Array;
  LPos, LI, LJ: Int32;
  LMask: UInt64;
begin
  LX := TNat320.Create64();
  LY := TNat320.Create64();
  LPos := 0;
  for LI := 0 to System.Pred(FSize) do
  begin
    LMask := UInt64(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));
    for LJ := 0 to System.Pred(SECT283K1_FE_LONGS) do
    begin
      LX[LJ] := LX[LJ] xor (FTable[LPos + LJ] and LMask);
      LY[LJ] := LY[LJ] xor (FTable[LPos + SECT283K1_FE_LONGS + LJ] and LMask);
    end;
    LPos := LPos + (SECT283K1_FE_LONGS * 2);
  end;
  Result := CreatePoint(LX, LY);
end;

function TSecT283K1Curve.TSecT283K1LookupTable.LookupVar(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt64Array;
  LPos, LJ: Int32;
begin
  LX := TNat320.Create64();
  LY := TNat320.Create64();
  LPos := AIndex * SECT283K1_FE_LONGS * 2;
  for LJ := 0 to System.Pred(SECT283K1_FE_LONGS) do
  begin
    LX[LJ] := FTable[LPos + LJ];
    LY[LJ] := FTable[LPos + SECT283K1_FE_LONGS + LJ];
  end;
  Result := CreatePoint(LX, LY);
end;

{ TSecT283K1Curve }

class procedure TSecT283K1Curve.Boot;
begin
  FSecT283K1AffineZs := TCryptoLibGenericArray<IECFieldElement>.Create(
    TSecT283FieldElement.Create(TBigInteger.One) as IECFieldElement);
end;

class constructor TSecT283K1Curve.Create;
begin
  Boot;
end;

constructor TSecT283K1Curve.Create;
begin
  Inherited Create(283, 5, 7, 12);
  FInfinity := TSecT283K1Point.Create(Self as IECCurve, nil, nil);
  FA := FromBigInteger(TBigInteger.Zero);
  FB := FromBigInteger(TBigInteger.One);
  FOrder := TBigInteger.Create(1, THex.Decode('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE9AE2ED07577265DFF7F94451E061E163C61'));
  FCofactor := TBigInteger.Four;
  FCoord := SECT283K1_DEFAULT_COORDS;
end;

function TSecT283K1Curve.GetIsKoblitz: Boolean;
begin
  Result := True;
end;

function TSecT283K1Curve.CreateDefaultMultiplier: IECMultiplier;
begin
  Result := TWTauNafMultiplier.Create() as IECMultiplier;
end;

function TSecT283K1Curve.CloneCurve: IECCurve;
begin
  Result := TSecT283K1Curve.Create;
end;

function TSecT283K1Curve.GetFieldSize: Int32;
begin
  Result := 283;
end;

function TSecT283K1Curve.GetInfinity: IECPoint;
begin
  Result := FInfinity;
end;

function TSecT283K1Curve.FromBigInteger(const AX: TBigInteger): IECFieldElement;
begin
  Result := TSecT283FieldElement.Create(AX);
end;

function TSecT283K1Curve.CreateRawPoint(const AX, AY: IECFieldElement): IECPoint;
begin
  Result := TSecT283K1Point.Create(Self as IECCurve, AX, AY);
end;

function TSecT283K1Curve.CreateRawPoint(const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint;
begin
  Result := TSecT283K1Point.Create(Self as IECCurve, AX, AY, AZs);
end;

function TSecT283K1Curve.CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32): IECLookupTable;
var
  LTable: TCryptoLibUInt64Array;
  LPos, LI: Int32;
  LP: IECPoint;
begin
  System.SetLength(LTable, ALen * SECT283K1_FE_LONGS * 2);
  LPos := 0;
  for LI := 0 to System.Pred(ALen) do
  begin
    LP := APoints[AOff + LI];
    TNat320.Copy64((LP.RawXCoord as ISecT283FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECT283K1_FE_LONGS;
    TNat320.Copy64((LP.RawYCoord as ISecT283FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECT283K1_FE_LONGS;
  end;
  Result := TSecT283K1LookupTable.Create(Self as ISecT283K1Curve, LTable, ALen);
end;

function TSecT283K1Curve.SupportsCoordinateSystem(ACoord: Int32): Boolean;
begin
  Result := ACoord = TECCurveConstants.COORD_LAMBDA_PROJECTIVE;
end;

function TSecT283K1Curve.GetM: Int32;
begin
  Result := 283;
end;

function TSecT283K1Curve.GetIsTrinomial: Boolean;
begin
  Result := False;
end;

function TSecT283K1Curve.GetK1: Int32;
begin
  Result := 5;
end;

function TSecT283K1Curve.GetK2: Int32;
begin
  Result := 7;
end;

function TSecT283K1Curve.GetK3: Int32;
begin
  Result := 12;
end;

end.
