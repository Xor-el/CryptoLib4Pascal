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

unit ClpSecP521R1Custom;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpNat512,
  ClpNat,
  ClpMod,
  ClpPack,
  ClpEncoders,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpECCurve,
  ClpECCurveConstants,
  ClpECFieldElement,
  ClpECPoint,
  ClpECLookupTables,
  ClpFiniteFields,
  ClpIECCore,
  ClpIECFieldElement,
  ClpISecP521R1Custom,
  ClpCryptoLibTypes;

resourcestring
  SInvalidSecP521R1FieldElement = 'value invalid for SecP521R1FieldElement';

type
  TSecP521R1Field = class sealed(TObject)
  strict private
  const
    P16 = UInt32($1FF);
  class var
    FP: TCryptoLibUInt32Array;
  class procedure Boot; static;
  class procedure ImplMultiply(const AX, AY, AZZ: TCryptoLibUInt32Array); static;
  class procedure ImplSquare(const AX, AZZ: TCryptoLibUInt32Array); static;
  class constructor Create;
  public
    class procedure Add(const AX, AY, AZ: TCryptoLibUInt32Array); static;
    class procedure AddOne(const AX, AZ: TCryptoLibUInt32Array); static;
    class function FromBigInteger(const AX: TBigInteger): TCryptoLibUInt32Array; static;
    class procedure Half(const AX, AZ: TCryptoLibUInt32Array); static;
    class procedure Inv(const AX, AZ: TCryptoLibUInt32Array); static;
    class function IsZero(const AX: TCryptoLibUInt32Array): Int32; static;
    class procedure Multiply(const AX, AY, AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Multiply(const AX, AY, AZ, ATT: TCryptoLibUInt32Array); overload; static;
    class procedure Negate(const AX, AZ: TCryptoLibUInt32Array); static;
    class procedure Random(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array); static;
    class procedure RandomMult(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array); static;
    class procedure Reduce(const AXX, AZ: TCryptoLibUInt32Array); static;
    class procedure Reduce23(const AZ: TCryptoLibUInt32Array); static;
    class procedure Square(const AX, AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Square(const AX, AZ, ATT: TCryptoLibUInt32Array); overload; static;
    class procedure SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
      const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
      const AZ, ATT: TCryptoLibUInt32Array); overload; static;
    class procedure Subtract(const AX, AY, AZ: TCryptoLibUInt32Array); static;
    class procedure Twice(const AX, AZ: TCryptoLibUInt32Array); static;

    class property P: TCryptoLibUInt32Array read FP;
  end;

type
  TSecP521R1FieldElement = class sealed(TAbstractFpFieldElement,
    IAbstractFpFieldElement, IECFieldElement, ISecP521R1FieldElement)
  strict private
  class var
    FQ: TBigInteger;
  class procedure Boot; static;
  class constructor Create;
  strict protected
    FX: TCryptoLibUInt32Array;
    function GetX: TCryptoLibUInt32Array; inline;
  public
    class function GetQ: TBigInteger; static;
    class property Q: TBigInteger read GetQ;
    constructor Create(const AX: TBigInteger); overload;
    constructor Create(); overload;
    constructor Create(const AX: TCryptoLibUInt32Array); overload;

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
    function Divide(const AB: IECFieldElement): IECFieldElement; override;
    function Negate: IECFieldElement; override;
    function Square: IECFieldElement; override;
    function Invert: IECFieldElement; override;
    function Sqrt: IECFieldElement; override;

    function Equals(const AOther: IECFieldElement): Boolean; override;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property X: TCryptoLibUInt32Array read GetX;
  end;

type
  TSecP521R1Point = class sealed(TAbstractFpPoint, IAbstractFpPoint, IECPoint,
    ISecP521R1Point)
  strict protected
    function Detach: IECPoint; override;
  public
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement); overload;
    constructor Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>); overload;

    function Add(const AB: IECPoint): IECPoint; override;
    function Twice: IECPoint; override;
    function TwicePlus(const AB: IECPoint): IECPoint; override;
    function ThreeTimes: IECPoint; override;
    function Negate: IECPoint; override;
  end;

type
  TSecP521R1Curve = class sealed(TAbstractFpCurve, IAbstractFpCurve, IECCurve,
    ISecP521R1Curve)
  strict private
  const
    SECP521R1_DEFAULT_COORDS = TECCurveConstants.COORD_JACOBIAN;
    SECP521R1_FE_INTS = 17;
  strict private
  type
    TSecP521R1LookupTable = class sealed(TAbstractECLookupTable, IECLookupTable,
      ISecP521R1LookupTable)
    strict private
      FOuter: ISecP521R1Curve;
      FTable: TCryptoLibUInt32Array;
      FSize: Int32;
      function CreatePoint(const AX, AY: TCryptoLibUInt32Array): IECPoint;
    public
      constructor Create(const AOuter: ISecP521R1Curve;
        const ATable: TCryptoLibUInt32Array; ASize: Int32);
      function GetSize: Int32; override;
      function Lookup(AIndex: Int32): IECPoint; override;
      function LookupVar(AIndex: Int32): IECPoint; override;
    end;
  class var
    FQ: TBigInteger;
    FSecP521R1AffineZs: TCryptoLibGenericArray<IECFieldElement>;
  class procedure Boot; static;
  class constructor Create;
  var
    FInfinity: TSecP521R1Point;
  strict protected
    function GetQ: TBigInteger;
  public
    constructor Create;
    destructor Destroy; override;

    function CloneCurve: IECCurve; override;
    function GetFieldSize: Int32; override;
    function GetInfinity: IECPoint; override;
    function FromBigInteger(const AX: TBigInteger): IECFieldElement; override;
    function CreateRawPoint(const AX, AY: IECFieldElement): IECPoint; override;
    function CreateRawPoint(const AX, AY: IECFieldElement;
      const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint; override;
    function CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
      AOff, ALen: Int32): IECLookupTable; override;
    function RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement; override;
    function RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement; override;
    function SupportsCoordinateSystem(ACoord: Int32): Boolean; override;

    class property Q: TBigInteger read FQ;
    class property SecP521R1AffineZs: TCryptoLibGenericArray<IECFieldElement> read FSecP521R1AffineZs;
  end;

implementation

{ TSecP521R1Field }

class procedure TSecP521R1Field.Boot;
begin
  FP := TCryptoLibUInt32Array.Create($FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $1FF);
end;

class constructor TSecP521R1Field.Create;
begin
  Boot;
end;

class procedure TSecP521R1Field.ImplMultiply(const AX, AY, AZZ: TCryptoLibUInt32Array);
var
  LX16, LY16: UInt32;
begin
  TNat512.Mul(AX, AY, AZZ);
  LX16 := AX[16];
  LY16 := AY[16];
  AZZ[32] := TNat.Mul31BothAdd(16, LX16, AY, LY16, AX, AZZ, 16) + (LX16 * LY16);
end;

class procedure TSecP521R1Field.ImplSquare(const AX, AZZ: TCryptoLibUInt32Array);
var
  LX16: UInt32;
begin
  TNat512.Square(AX, AZZ);
  LX16 := AX[16];
  AZZ[32] := TNat.MulWordAddTo(16, LX16 shl 1, AX, 0, AZZ, 16) + (LX16 * LX16);
end;

class procedure TSecP521R1Field.Add(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.Add(16, AX, AY, AZ) + AX[16] + AY[16];
  if (LC > P16) or ((LC = P16) and TNat.Eq(16, AZ, FP)) then
  begin
    LC := LC + TNat.Inc(16, AZ);
    LC := LC and P16;
  end;
  AZ[16] := LC;
end;

class procedure TSecP521R1Field.AddOne(const AX, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.Inc(16, AX, AZ) + AX[16];
  if (LC > P16) or ((LC = P16) and TNat.Eq(16, AZ, FP)) then
  begin
    LC := LC + TNat.Inc(16, AZ);
    LC := LC and P16;
  end;
  AZ[16] := LC;
end;

class function TSecP521R1Field.FromBigInteger(const AX: TBigInteger): TCryptoLibUInt32Array;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.FromBigInteger(521, AX);
  if TNat.Eq(17, LZ, FP) then
    TNat.Zero(17, LZ);
  Result := LZ;
end;

class procedure TSecP521R1Field.Half(const AX, AZ: TCryptoLibUInt32Array);
var
  LX16: UInt32;
  LC: UInt32;
begin
  LX16 := AX[16];
  LC := TNat.ShiftDownBit(16, AX, LX16, AZ);
  AZ[16] := (LX16 shr 1) or (LC shr 23);
end;

class procedure TSecP521R1Field.Inv(const AX, AZ: TCryptoLibUInt32Array);
begin
  TMod.CheckedModOddInverse(FP, AX, AZ);
end;

class function TSecP521R1Field.IsZero(const AX: TCryptoLibUInt32Array): Int32;
var
  LD: UInt32;
  LI: Int32;
begin
  LD := 0;
  for LI := 0 to 16 do
    LD := LD or AX[LI];
  LD := (LD shr 1) or (LD and 1);
  Result := TBitOperations.Asr32(Int32(LD) - 1, 31);
end;

class procedure TSecP521R1Field.Multiply(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  LTT := TNat.Create(33);
  ImplMultiply(AX, AY, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecP521R1Field.Multiply(const AX, AY, AZ, ATT: TCryptoLibUInt32Array);
begin
  ImplMultiply(AX, AY, ATT);
  Reduce(ATT, AZ);
end;

class procedure TSecP521R1Field.Negate(const AX, AZ: TCryptoLibUInt32Array);
begin
  if IsZero(AX) <> 0 then
    TNat.Sub(17, FP, FP, AZ)
  else
    TNat.Sub(17, FP, AX, AZ);
end;

class procedure TSecP521R1Field.Random(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array);
var
  LBB: TCryptoLibByteArray;
begin
  System.SetLength(LBB, 17 * 4);
  repeat
    AR.NextBytes(LBB);
    TPack.LE_To_UInt32(LBB, 0, AZ, 0, 17);
    AZ[16] := AZ[16] and P16;
  until TNat.LessThan(17, AZ, FP) <> 0;
end;

class procedure TSecP521R1Field.RandomMult(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array);
begin
  repeat
    Random(AR, AZ);
  until IsZero(AZ) <> 0;
end;

class procedure TSecP521R1Field.Reduce(const AXX, AZ: TCryptoLibUInt32Array);
var
  LXX32: UInt32;
  LC: UInt32;
begin
  {$IFDEF DEBUG}
  Assert(AXX[32] shr 18 = 0);
  {$ENDIF DEBUG}
  LXX32 := AXX[32];
  LC := TNat.ShiftDownBits(16, AXX, 16, 9, LXX32, AZ, 0) shr 23;
  LC := LC + (LXX32 shr 9);
  LC := LC + TNat.AddTo(16, AXX, AZ);
  if (LC > P16) or ((LC = P16) and TNat.Eq(16, AZ, FP)) then
  begin
    LC := LC + TNat.Inc(16, AZ);
    LC := LC and P16;
  end;
  AZ[16] := LC;
end;

class procedure TSecP521R1Field.Reduce23(const AZ: TCryptoLibUInt32Array);
var
  LZ16: UInt32;
  LC: UInt32;
begin
  LZ16 := AZ[16];
  LC := TNat.AddWordTo(16, LZ16 shr 9, AZ) + (LZ16 and P16);
  if (LC > P16) or ((LC = P16) and TNat.Eq(16, AZ, FP)) then
  begin
    LC := LC + TNat.Inc(16, AZ);
    LC := LC and P16;
  end;
  AZ[16] := LC;
end;

class procedure TSecP521R1Field.Square(const AX, AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  LTT := TNat.Create(33);
  ImplSquare(AX, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecP521R1Field.Square(const AX, AZ, ATT: TCryptoLibUInt32Array);
begin
  ImplSquare(AX, ATT);
  Reduce(ATT, AZ);
end;

class procedure TSecP521R1Field.SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
  const AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  {$IFDEF DEBUG}
  Assert(AN > 0);
  {$ENDIF DEBUG}
  LTT := TNat.Create(33);
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

class procedure TSecP521R1Field.SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
  const AZ, ATT: TCryptoLibUInt32Array);
begin
  {$IFDEF DEBUG}
  Assert(AN > 0);
  {$ENDIF DEBUG}
  ImplSquare(AX, ATT);
  Reduce(ATT, AZ);
  Dec(AN);
  while AN > 0 do
  begin
    ImplSquare(AZ, ATT);
    Reduce(ATT, AZ);
    Dec(AN);
  end;
end;

class procedure TSecP521R1Field.Subtract(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LC: Int32;
begin
  LC := Int32(TNat.Sub(16, AX, AY, AZ)) + Int32(AX[16] - AY[16]);
  if LC < 0 then
  begin
    LC := LC + Int32(TNat.Dec(16, AZ));
    LC := LC and Int32(P16);
  end;
  AZ[16] := UInt32(LC);
end;

class procedure TSecP521R1Field.Twice(const AX, AZ: TCryptoLibUInt32Array);
var
  LX16: UInt32;
  LC: UInt32;
begin
  LX16 := AX[16];
  LC := TNat.ShiftUpBit(16, AX, LX16 shl 23, AZ) or (LX16 shl 1);
  AZ[16] := LC and P16;
end;

{ TSecP521R1FieldElement }

class procedure TSecP521R1FieldElement.Boot;
begin
  FQ := TBigInteger.Create(1, THex.Decode('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'));
end;

class constructor TSecP521R1FieldElement.Create;
begin
  Boot;
end;

class function TSecP521R1FieldElement.GetQ: TBigInteger;
begin
  Result := FQ;
end;

constructor TSecP521R1FieldElement.Create(const AX: TBigInteger);
begin
  Inherited Create;
  if (not AX.IsInitialized) or (AX.SignValue < 0) or (AX.CompareTo(FQ) >= 0) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSecP521R1FieldElement);
  FX := TSecP521R1Field.FromBigInteger(AX);
end;

constructor TSecP521R1FieldElement.Create();
begin
  Inherited Create;
  FX := TNat.Create(17);
end;

constructor TSecP521R1FieldElement.Create(const AX: TCryptoLibUInt32Array);
begin
  Inherited Create;
  FX := AX;
end;

function TSecP521R1FieldElement.GetX: TCryptoLibUInt32Array;
begin
  Result := FX;
end;

function TSecP521R1FieldElement.GetFieldName: String;
begin
  Result := 'SecP521R1Field';
end;

function TSecP521R1FieldElement.GetFieldSize: Int32;
begin
  Result := FQ.BitLength;
end;

function TSecP521R1FieldElement.GetIsOne: Boolean;
begin
  Result := TNat.IsOne(17, FX);
end;

function TSecP521R1FieldElement.GetIsZero: Boolean;
begin
  Result := TNat.IsZero(17, FX);
end;

function TSecP521R1FieldElement.ToBigInteger: TBigInteger;
begin
  Result := TNat.ToBigInteger(17, FX);
end;

function TSecP521R1FieldElement.TestBitZero: Boolean;
begin
  Result := TNat.GetBit(FX, 0) = 1;
end;

function TSecP521R1FieldElement.Add(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.Add(FX, (AB as ISecP521R1FieldElement).X, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.AddOne: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.AddOne(FX, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.Subtract(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.Subtract(FX, (AB as ISecP521R1FieldElement).X, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.Multiply(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.Multiply(FX, (AB as ISecP521R1FieldElement).X, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.Divide(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.Inv((AB as ISecP521R1FieldElement).X, LZ);
  TSecP521R1Field.Multiply(LZ, FX, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.Negate: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.Negate(FX, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.Square: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.Square(FX, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.Invert: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(17);
  TSecP521R1Field.Inv(FX, LZ);
  Result := TSecP521R1FieldElement.Create(LZ);
end;

function TSecP521R1FieldElement.Sqrt: IECFieldElement;
var
  LX1, LTT0, LT1, LT2: TCryptoLibUInt32Array;
begin
  LX1 := FX;
  if TNat.IsZero(17, LX1) or TNat.IsOne(17, LX1) then
    Exit(Self as IECFieldElement);

  LTT0 := TNat.Create(33);
  LT1 := TNat.Create(17);
  LT2 := TNat.Create(17);

  TSecP521R1Field.SquareN(LX1, 519, LT1, LTT0);
  TSecP521R1Field.Square(LT1, LT2, LTT0);

  if TNat.Eq(17, LX1, LT2) then
    Result := TSecP521R1FieldElement.Create(LT1)
  else
    Result := nil;
end;

function TSecP521R1FieldElement.Equals(const AOther: IECFieldElement): Boolean;
begin
  if (Self as IECFieldElement) = AOther then
    Exit(True);
  if AOther = nil then
    Exit(False);
  Result := TNat.Eq(17, FX, (AOther as ISecP521R1FieldElement).X);
end;

function TSecP521R1FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FQ.GetHashCode() xor TArrayUtilities.GetArrayHashCode(FX, 0, 17);
end;

{ TSecP521R1Point }

constructor TSecP521R1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  Inherited Create(ACurve, AX, AY);
end;

constructor TSecP521R1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  Inherited Create(ACurve, AX, AY, AZs);
end;

function TSecP521R1Point.Detach: IECPoint;
begin
  Result := TSecP521R1Point.Create(nil, AffineXCoord, AffineYCoord);
end;

function TSecP521R1Point.Add(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LX1, LY1, LX2, LY2, LZ1, LZ2: ISecP521R1FieldElement;
  LTT0: TCryptoLibUInt32Array;
  LT1, LT2, LT3, LT4: TCryptoLibUInt32Array;
  LZ1IsOne, LZ2IsOne: Boolean;
  LU2, LS2, LU1, LS1: TCryptoLibUInt32Array;
  LH, LR, LHSquared, LG, LV: TCryptoLibUInt32Array;
  LX3, LY3, LZ3: ISecP521R1FieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Self as IECPoint);
  if (Self as IECPoint) = AB then
    Exit(Twice());

  LCurve := Curve;
  LX1 := RawXCoord as ISecP521R1FieldElement;
  LY1 := RawYCoord as ISecP521R1FieldElement;
  LX2 := AB.RawXCoord as ISecP521R1FieldElement;
  LY2 := AB.RawYCoord as ISecP521R1FieldElement;
  LZ1 := RawZCoords[0] as ISecP521R1FieldElement;
  LZ2 := AB.GetZCoord(0) as ISecP521R1FieldElement;

  LTT0 := TNat.Create(33);
  LT1 := TNat.Create(17);
  LT2 := TNat.Create(17);
  LT3 := TNat.Create(17);
  LT4 := TNat.Create(17);

  LZ1IsOne := LZ1.IsOne;
  if LZ1IsOne then
  begin
    LU2 := LX2.X;
    LS2 := LY2.X;
  end
  else
  begin
    LS2 := LT3;
    TSecP521R1Field.Square(LZ1.X, LS2, LTT0);
    LU2 := LT2;
    TSecP521R1Field.Multiply(LS2, LX2.X, LU2, LTT0);
    TSecP521R1Field.Multiply(LS2, LZ1.X, LS2, LTT0);
    TSecP521R1Field.Multiply(LS2, LY2.X, LS2, LTT0);
  end;

  LZ2IsOne := LZ2.IsOne;
  if LZ2IsOne then
  begin
    LU1 := LX1.X;
    LS1 := LY1.X;
  end
  else
  begin
    LS1 := LT4;
    TSecP521R1Field.Square(LZ2.X, LS1, LTT0);
    LU1 := LT1;
    TSecP521R1Field.Multiply(LS1, LX1.X, LU1, LTT0);
    TSecP521R1Field.Multiply(LS1, LZ2.X, LS1, LTT0);
    TSecP521R1Field.Multiply(LS1, LY1.X, LS1, LTT0);
  end;

  LH := TNat.Create(17);
  TSecP521R1Field.Subtract(LU1, LU2, LH);

  LR := LT2;
  TSecP521R1Field.Subtract(LS1, LS2, LR);

  if TNat.IsZero(17, LH) then
  begin
    if TNat.IsZero(17, LR) then
      Exit(Twice());
    Exit(LCurve.Infinity);
  end;

  LHSquared := LT3;
  TSecP521R1Field.Square(LH, LHSquared, LTT0);

  LG := TNat.Create(17);
  TSecP521R1Field.Multiply(LHSquared, LH, LG, LTT0);

  LV := LT3;
  TSecP521R1Field.Multiply(LHSquared, LU1, LV, LTT0);

  TSecP521R1Field.Multiply(LS1, LG, LT1, LTT0);

  LX3 := TSecP521R1FieldElement.Create(LT4);
  TSecP521R1Field.Square(LR, LX3.X, LTT0);
  TSecP521R1Field.Add(LX3.X, LG, LX3.X);
  TSecP521R1Field.Subtract(LX3.X, LV, LX3.X);
  TSecP521R1Field.Subtract(LX3.X, LV, LX3.X);

  LY3 := TSecP521R1FieldElement.Create(LG);
  TSecP521R1Field.Subtract(LV, LX3.X, LY3.X);
  TSecP521R1Field.Multiply(LY3.X, LR, LT2, LTT0);
  TSecP521R1Field.Subtract(LT2, LT1, LY3.X);

  LZ3 := TSecP521R1FieldElement.Create(LH);
  if not LZ1IsOne then
    TSecP521R1Field.Multiply(LZ3.X, LZ1.X, LZ3.X, LTT0);
  if not LZ2IsOne then
    TSecP521R1Field.Multiply(LZ3.X, LZ2.X, LZ3.X, LTT0);

  LZs := TCryptoLibGenericArray<IECFieldElement>.Create(LZ3 as IECFieldElement);
  Result := TSecP521R1Point.Create(LCurve, LX3 as IECFieldElement, LY3 as IECFieldElement, LZs);
end;

function TSecP521R1Point.Twice: IECPoint;
var
  LCurve: IECCurve;
  LY1, LX1, LZ1: ISecP521R1FieldElement;
  LTT0: TCryptoLibUInt32Array;
  LY1Squared, LT, LT1, LT2: TCryptoLibUInt32Array;
  LZ1Squared, LM, LS: TCryptoLibUInt32Array;
  LZ1IsOne: Boolean;
  LX3, LY3, LZ3: ISecP521R1FieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  LCurve := Curve;
  LY1 := RawYCoord as ISecP521R1FieldElement;
  if LY1.IsZero then
    Exit(LCurve.Infinity);

  LX1 := RawXCoord as ISecP521R1FieldElement;
  LZ1 := RawZCoords[0] as ISecP521R1FieldElement;

  LTT0 := TNat.Create(33);
  LT1 := TNat.Create(17);
  LT2 := TNat.Create(17);

  LY1Squared := TNat.Create(17);
  TSecP521R1Field.Square(LY1.X, LY1Squared, LTT0);

  LT := TNat.Create(17);
  TSecP521R1Field.Square(LY1Squared, LT, LTT0);

  LZ1IsOne := LZ1.IsOne;
  if LZ1IsOne then
    LZ1Squared := LZ1.X
  else
  begin
    LZ1Squared := LT2;
    TSecP521R1Field.Square(LZ1.X, LZ1Squared, LTT0);
  end;

  TSecP521R1Field.Subtract(LX1.X, LZ1Squared, LT1);

  LM := LT2;
  TSecP521R1Field.Add(LX1.X, LZ1Squared, LM);
  TSecP521R1Field.Multiply(LM, LT1, LM, LTT0);
  TNat.AddBothTo(17, LM, LM, LM);
  TSecP521R1Field.Reduce23(LM);

  LS := LY1Squared;
  TSecP521R1Field.Multiply(LY1Squared, LX1.X, LS, LTT0);
  TNat.ShiftUpBits(17, LS, 2, 0);
  TSecP521R1Field.Reduce23(LS);

  TNat.ShiftUpBits(17, LT, 3, 0, LT1);
  TSecP521R1Field.Reduce23(LT1);

  LX3 := TSecP521R1FieldElement.Create(LT);
  TSecP521R1Field.Square(LM, LX3.X, LTT0);
  TSecP521R1Field.Subtract(LX3.X, LS, LX3.X);
  TSecP521R1Field.Subtract(LX3.X, LS, LX3.X);

  LY3 := TSecP521R1FieldElement.Create(LS);
  TSecP521R1Field.Subtract(LS, LX3.X, LY3.X);
  TSecP521R1Field.Multiply(LY3.X, LM, LY3.X, LTT0);
  TSecP521R1Field.Subtract(LY3.X, LT1, LY3.X);

  LZ3 := TSecP521R1FieldElement.Create(LM);
  TSecP521R1Field.Twice(LY1.X, LZ3.X);
  if not LZ1IsOne then
    TSecP521R1Field.Multiply(LZ3.X, LZ1.X, LZ3.X, LTT0);

  LZs := TCryptoLibGenericArray<IECFieldElement>.Create(LZ3 as IECFieldElement);
  Result := TSecP521R1Point.Create(LCurve, LX3 as IECFieldElement, LY3 as IECFieldElement, LZs);
end;

function TSecP521R1Point.TwicePlus(const AB: IECPoint): IECPoint;
begin
  if (Self as IECPoint) = AB then
    Exit(ThreeTimes());
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Twice());
  if RawYCoord.IsZero then
    Exit(AB);
  Result := Twice().Add(AB);
end;

function TSecP521R1Point.ThreeTimes: IECPoint;
begin
  if IsInfinity or RawYCoord.IsZero then
    Exit(Self as IECPoint);
  Result := Twice().Add(Self as IECPoint);
end;

function TSecP521R1Point.Negate: IECPoint;
begin
  if IsInfinity then
    Exit(Self as IECPoint);
  Result := TSecP521R1Point.Create(Curve, RawXCoord, RawYCoord.Negate(), RawZCoords);
end;

{ TSecP521R1Curve.TSecP521R1LookupTable }

constructor TSecP521R1Curve.TSecP521R1LookupTable.Create(const AOuter: ISecP521R1Curve;
  const ATable: TCryptoLibUInt32Array; ASize: Int32);
begin
  Inherited Create;
  FOuter := AOuter;
  FTable := ATable;
  FSize := ASize;
end;

function TSecP521R1Curve.TSecP521R1LookupTable.GetSize: Int32;
begin
  Result := FSize;
end;

function TSecP521R1Curve.TSecP521R1LookupTable.CreatePoint(const AX, AY: TCryptoLibUInt32Array): IECPoint;
begin
  Result := FOuter.CreateRawPoint(TSecP521R1FieldElement.Create(AX) as IECFieldElement,
    TSecP521R1FieldElement.Create(AY) as IECFieldElement, TSecP521R1Curve.SecP521R1AffineZs);
end;

function TSecP521R1Curve.TSecP521R1LookupTable.Lookup(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt32Array;
  LPos, LI, LJ: Int32;
  LMask: UInt32;
begin
  LX := TNat.Create(SECP521R1_FE_INTS);
  LY := TNat.Create(SECP521R1_FE_INTS);
  LPos := 0;

  for LI := 0 to System.Pred(FSize) do
  begin
    LMask := UInt32(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));

    for LJ := 0 to System.Pred(SECP521R1_FE_INTS) do
    begin
      LX[LJ] := LX[LJ] xor (FTable[LPos + LJ] and LMask);
      LY[LJ] := LY[LJ] xor (FTable[LPos + SECP521R1_FE_INTS + LJ] and LMask);
    end;

    LPos := LPos + (SECP521R1_FE_INTS * 2);
  end;

  Result := CreatePoint(LX, LY);
end;

function TSecP521R1Curve.TSecP521R1LookupTable.LookupVar(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt32Array;
  LPos, LJ: Int32;
begin
  LX := TNat.Create(SECP521R1_FE_INTS);
  LY := TNat.Create(SECP521R1_FE_INTS);
  LPos := AIndex * SECP521R1_FE_INTS * 2;

  for LJ := 0 to System.Pred(SECP521R1_FE_INTS) do
  begin
    LX[LJ] := FTable[LPos + LJ];
    LY[LJ] := FTable[LPos + SECP521R1_FE_INTS + LJ];
  end;

  Result := CreatePoint(LX, LY);
end;

{ TSecP521R1Curve }

class procedure TSecP521R1Curve.Boot;
begin
  FQ := TSecP521R1FieldElement.Q;
  FSecP521R1AffineZs := TCryptoLibGenericArray<IECFieldElement>.Create(
    TSecP521R1FieldElement.Create(TBigInteger.One) as IECFieldElement);
end;

class constructor TSecP521R1Curve.Create;
begin
  Boot;
end;

constructor TSecP521R1Curve.Create;
begin
  Inherited Create(TSecP521R1Curve.Q, True);
  FInfinity := TSecP521R1Point.Create(Self as IECCurve, nil, nil);
  FA := FromBigInteger(TBigInteger.Create(1, THex.Decode('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC')));
  FB := FromBigInteger(TBigInteger.Create(1, THex.Decode('0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00')));
  FOrder := TBigInteger.Create(1, THex.Decode('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409'));
  FCofactor := TBigInteger.One;
  FCoord := SECP521R1_DEFAULT_COORDS;
end;

destructor TSecP521R1Curve.Destroy;
begin
  FInfinity := nil;
  inherited Destroy;
end;

function TSecP521R1Curve.GetQ: TBigInteger;
begin
  Result := TSecP521R1Curve.Q;
end;

function TSecP521R1Curve.CloneCurve: IECCurve;
begin
  Result := TSecP521R1Curve.Create;
end;

function TSecP521R1Curve.GetFieldSize: Int32;
begin
  Result := TSecP521R1Curve.Q.BitLength;
end;

function TSecP521R1Curve.GetInfinity: IECPoint;
begin
  Result := FInfinity;
end;

function TSecP521R1Curve.FromBigInteger(const AX: TBigInteger): IECFieldElement;
begin
  Result := TSecP521R1FieldElement.Create(AX);
end;

function TSecP521R1Curve.CreateRawPoint(const AX, AY: IECFieldElement): IECPoint;
begin
  Result := TSecP521R1Point.Create(Self as IECCurve, AX, AY);
end;

function TSecP521R1Curve.CreateRawPoint(const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint;
begin
  Result := TSecP521R1Point.Create(Self as IECCurve, AX, AY, AZs);
end;

function TSecP521R1Curve.CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32): IECLookupTable;
var
  LTable: TCryptoLibUInt32Array;
  LPos, LI: Int32;
  LP: IECPoint;
begin
  System.SetLength(LTable, ALen * SECP521R1_FE_INTS * 2);
  LPos := 0;
  for LI := 0 to System.Pred(ALen) do
  begin
    LP := APoints[AOff + LI];
    TNat.Copy(SECP521R1_FE_INTS, (LP.RawXCoord as ISecP521R1FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECP521R1_FE_INTS;
    TNat.Copy(SECP521R1_FE_INTS, (LP.RawYCoord as ISecP521R1FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECP521R1_FE_INTS;
  end;
  Result := TSecP521R1LookupTable.Create(Self as ISecP521R1Curve, LTable, ALen);
end;

function TSecP521R1Curve.RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement;
var
  LX: TCryptoLibUInt32Array;
begin
  LX := TNat.Create(17);
  TSecP521R1Field.Random(ARandom, LX);
  Result := TSecP521R1FieldElement.Create(LX);
end;

function TSecP521R1Curve.RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement;
var
  LX: TCryptoLibUInt32Array;
begin
  LX := TNat.Create(17);
  TSecP521R1Field.RandomMult(ARandom, LX);
  Result := TSecP521R1FieldElement.Create(LX);
end;

function TSecP521R1Curve.SupportsCoordinateSystem(ACoord: Int32): Boolean;
begin
  case ACoord of
    TECCurveConstants.COORD_JACOBIAN:
      Result := True;
  else
    Result := False;
  end;
end;

end.
