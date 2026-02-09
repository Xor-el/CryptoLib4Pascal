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

unit ClpSecP256K1Custom;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpNat256,
  ClpNat,
  ClpMod,
  ClpPack,
  ClpEncoders,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpECCurve,
  ClpECCurveConstants,
  ClpECFieldElement,
  ClpECPoint,
  ClpECLookupTables,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpISecP256K1Custom,
  ClpCryptoLibTypes;

resourcestring
  SInvalidSecP256K1FieldElement = 'value invalid for SecP256K1FieldElement';

type
  TSecP256K1Field = class sealed(TObject)
  strict private
  const
    P7 = UInt32($FFFFFFFF);
    PExt15 = UInt32($FFFFFFFF);
    PInv33 = UInt32($3D1);
  class var
    FP, FPExt, FPExtInv: TCryptoLibUInt32Array;
  class procedure Boot; static;
  class constructor Create;
  public
    class procedure Add(const AX, AY, AZ: TCryptoLibUInt32Array); static;
    class procedure AddExt(const AXX, AYY, AZZ: TCryptoLibUInt32Array); static;
    class procedure AddOne(const AX, AZ: TCryptoLibUInt32Array); static;
    class function FromBigInteger(const AX: TBigInteger): TCryptoLibUInt32Array; static;
    class procedure Half(const AX, AZ: TCryptoLibUInt32Array); static;
    class procedure Inv(const AX, AZ: TCryptoLibUInt32Array); static;
    class function IsZero(const AX: TCryptoLibUInt32Array): Int32; static;
    class procedure Multiply(const AX, AY, AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Multiply(const AX, AY, AZ, ATT: TCryptoLibUInt32Array); overload; static;
    class procedure MultiplyAddToExt(const AX, AY, AZZ: TCryptoLibUInt32Array); static;
    class procedure Negate(const AX, AZ: TCryptoLibUInt32Array); static;
    class procedure Random(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array); static;
    class procedure RandomMult(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array); static;
    class procedure Reduce(const AXX, AZ: TCryptoLibUInt32Array); static;
    class procedure Reduce32(AX: UInt32; const AZ: TCryptoLibUInt32Array); static;
    class procedure Square(const AX, AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Square(const AX, AZ, ATT: TCryptoLibUInt32Array); overload; static;
    class procedure SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
      const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
      const AZ, ATT: TCryptoLibUInt32Array); overload; static;
    class procedure Subtract(const AX, AY, AZ: TCryptoLibUInt32Array); static;
    class procedure SubtractExt(const AXX, AYY, AZZ: TCryptoLibUInt32Array); static;
    class procedure Twice(const AX, AZ: TCryptoLibUInt32Array); static;

    class property P: TCryptoLibUInt32Array read FP;
  end;

type
  TSecP256K1FieldElement = class sealed(TAbstractFpFieldElement,
    IAbstractFpFieldElement, IECFieldElement, ISecP256K1FieldElement)
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
  TSecP256K1Point = class sealed(TAbstractFpPoint, IAbstractFpPoint, IECPoint,
    ISecP256K1Point)
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
  TSecP256K1Curve = class sealed(TAbstractFpCurve, IAbstractFpCurve, IECCurve,
    ISecP256K1Curve)
  strict private
  const
    SECP256K1_DEFAULT_COORDS = TECCurveConstants.COORD_JACOBIAN;
    SECP256K1_FE_INTS = 8;
  strict private
  type
    TSecP256K1LookupTable = class sealed(TAbstractECLookupTable, IECLookupTable,
      ISecP256K1LookupTable)
    strict private
      FOuter: ISecP256K1Curve;
      FTable: TCryptoLibUInt32Array;
      FSize: Int32;
      function CreatePoint(const AX, AY: TCryptoLibUInt32Array): IECPoint;
    public
      constructor Create(const AOuter: ISecP256K1Curve;
        const ATable: TCryptoLibUInt32Array; ASize: Int32);
      function GetSize: Int32; override;
      function Lookup(AIndex: Int32): IECPoint; override;
      function LookupVar(AIndex: Int32): IECPoint; override;
    end;
  class var
    FQ: TBigInteger;
    FSecP256K1AffineZs: TCryptoLibGenericArray<IECFieldElement>;
  class procedure Boot; static;
  class constructor Create;
  var
    FInfinity: ISecP256K1Point;
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
    class property SecP256K1AffineZs: TCryptoLibGenericArray<IECFieldElement> read FSecP256K1AffineZs;
  end;

implementation

{ TSecP256K1Field }

class procedure TSecP256K1Field.Boot;
begin
  FP := TCryptoLibUInt32Array.Create($FFFFFC2F, $FFFFFFFE, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
  FPExt := TCryptoLibUInt32Array.Create($000E90A1, $000007A2, $00000001, $00000000,
    $00000000, $00000000, $00000000, $00000000, $FFFFF85E, $FFFFFFFD, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
  FPExtInv := TCryptoLibUInt32Array.Create($FFF16F5F, $FFFFF85D, $FFFFFFFE, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $000007A1, $00000002);
end;

class constructor TSecP256K1Field.Create;
begin
  Boot;
end;

class procedure TSecP256K1Field.Add(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat256.Add(AX, AY, AZ);
  if (LC <> 0) or ((AZ[7] = P7) and TNat256.Gte(AZ, FP)) then
    TNat.Add33To(8, PInv33, AZ);
end;

class procedure TSecP256K1Field.AddExt(const AXX, AYY, AZZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.Add(16, AXX, AYY, AZZ);
  if (LC <> 0) or ((AZZ[15] = PExt15) and TNat.Gte(16, AZZ, FPExt)) then
    if TNat.AddTo(System.Length(FPExtInv), FPExtInv, AZZ) <> 0 then
      TNat.IncAt(16, AZZ, System.Length(FPExtInv));
end;

class procedure TSecP256K1Field.AddOne(const AX, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.Inc(8, AX, AZ);
  if (LC <> 0) or ((AZ[7] = P7) and TNat256.Gte(AZ, FP)) then
    TNat.Add33To(8, PInv33, AZ);
end;

class function TSecP256K1Field.FromBigInteger(const AX: TBigInteger): TCryptoLibUInt32Array;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.FromBigInteger(256, AX);
  if (LZ[7] = P7) and TNat256.Gte(LZ, FP) then
    TNat256.SubFrom(FP, LZ, 0);
  Result := LZ;
end;

class procedure TSecP256K1Field.Half(const AX, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  if (AX[0] and 1) = 0 then
    TNat.ShiftDownBit(8, AX, 0, AZ)
  else
  begin
    LC := TNat256.Add(AX, FP, AZ);
    TNat.ShiftDownBit(8, AZ, LC);
  end;
end;

class procedure TSecP256K1Field.Inv(const AX, AZ: TCryptoLibUInt32Array);
begin
  TMod.CheckedModOddInverse(FP, AX, AZ);
end;

class function TSecP256K1Field.IsZero(const AX: TCryptoLibUInt32Array): Int32;
var
  LD: UInt32;
  LI: Int32;
begin
  LD := 0;
  for LI := 0 to 7 do
    LD := LD or AX[LI];
  LD := (LD shr 1) or (LD and 1);
  Result := TBitOperations.Asr32(Int32(LD) - 1, 31);
end;

class procedure TSecP256K1Field.Multiply(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  LTT := TNat256.CreateExt();
  TNat256.Mul(AX, AY, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecP256K1Field.Multiply(const AX, AY, AZ, ATT: TCryptoLibUInt32Array);
begin
  TNat256.Mul(AX, AY, ATT);
  Reduce(ATT, AZ);
end;

class procedure TSecP256K1Field.MultiplyAddToExt(const AX, AY, AZZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat256.MulAddTo(AX, AY, AZZ);
  if (LC <> 0) or ((AZZ[15] = PExt15) and TNat.Gte(16, AZZ, FPExt)) then
    if TNat.AddTo(System.Length(FPExtInv), FPExtInv, AZZ) <> 0 then
      TNat.IncAt(16, AZZ, System.Length(FPExtInv));
end;

class procedure TSecP256K1Field.Negate(const AX, AZ: TCryptoLibUInt32Array);
begin
  if IsZero(AX) <> 0 then
    TNat256.Sub(FP, FP, AZ)
  else
    TNat256.Sub(FP, AX, AZ);
end;

class procedure TSecP256K1Field.Random(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array);
var
  LBB: TCryptoLibByteArray;
begin
  System.SetLength(LBB, 8 * 4);
  repeat
    AR.NextBytes(LBB);
    TPack.LE_To_UInt32(LBB, 0, AZ, 0, 8);
  until TNat.LessThan(8, AZ, FP) <> 0;
end;

class procedure TSecP256K1Field.RandomMult(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array);
begin
  repeat
    Random(AR, AZ);
  until IsZero(AZ) = 0;
end;

class procedure TSecP256K1Field.Reduce(const AXX, AZ: TCryptoLibUInt32Array);
var
  LCc: UInt64;
  LC: UInt32;
begin
  LCc := TNat256.Mul33Add(PInv33, AXX, 8, AXX, 0, AZ, 0);
  LC := TNat256.Mul33DWordAdd(PInv33, LCc, AZ, 0);
  {$IFDEF DEBUG}
  System.Assert((LC = 0) or (LC = 1));
  {$ENDIF DEBUG}
  if (LC <> 0) or ((AZ[7] = P7) and TNat256.Gte(AZ, FP)) then
    TNat.Add33To(8, PInv33, AZ);
end;

class procedure TSecP256K1Field.Reduce32(AX: UInt32; const AZ: TCryptoLibUInt32Array);
begin
  if ((AX <> 0) and (TNat256.Mul33WordAdd(PInv33, AX, AZ, 0) <> 0)) or
    ((AZ[7] = P7) and TNat256.Gte(AZ, FP)) then
    TNat.Add33To(8, PInv33, AZ);
end;

class procedure TSecP256K1Field.Square(const AX, AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  LTT := TNat256.CreateExt();
  TNat256.Square(AX, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecP256K1Field.Square(const AX, AZ, ATT: TCryptoLibUInt32Array);
begin
  TNat256.Square(AX, ATT);
  Reduce(ATT, AZ);
end;

class procedure TSecP256K1Field.SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
  const AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  {$IFDEF DEBUG}
  System.Assert(AN > 0);
  {$ENDIF DEBUG}
  LTT := TNat256.CreateExt();
  TNat256.Square(AX, LTT);
  Reduce(LTT, AZ);
  Dec(AN);
  while AN > 0 do
  begin
    TNat256.Square(AZ, LTT);
    Reduce(LTT, AZ);
    Dec(AN);
  end;
end;

class procedure TSecP256K1Field.SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
  const AZ, ATT: TCryptoLibUInt32Array);
begin
  {$IFDEF DEBUG}
  System.Assert(AN > 0);
  {$ENDIF DEBUG}
  TNat256.Square(AX, ATT);
  Reduce(ATT, AZ);
  Dec(AN);
  while AN > 0 do
  begin
    TNat256.Square(AZ, ATT);
    Reduce(ATT, AZ);
    Dec(AN);
  end;
end;

class procedure TSecP256K1Field.Subtract(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LC: Int32;
begin
  LC := TNat256.Sub(AX, AY, AZ);
  if LC <> 0 then
    TNat.Sub33From(8, PInv33, AZ);
end;

class procedure TSecP256K1Field.SubtractExt(const AXX, AYY, AZZ: TCryptoLibUInt32Array);
var
  LC: Int32;
begin
  LC := TNat.Sub(16, AXX, AYY, AZZ);
  if LC <> 0 then
    if TNat.SubFrom(System.Length(FPExtInv), FPExtInv, AZZ) <> 0 then
      TNat.DecAt(16, AZZ, System.Length(FPExtInv));
end;

class procedure TSecP256K1Field.Twice(const AX, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.ShiftUpBit(8, AX, 0, AZ);
  if (LC <> 0) or ((AZ[7] = P7) and TNat256.Gte(AZ, FP)) then
    TNat.Add33To(8, PInv33, AZ);
end;

{ TSecP256K1FieldElement }

class procedure TSecP256K1FieldElement.Boot;
begin
  FQ := TBigInteger.Create(1, THex.Decode('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F'));
end;

class constructor TSecP256K1FieldElement.Create;
begin
  Boot;
end;

constructor TSecP256K1FieldElement.Create(const AX: TBigInteger);
begin
  Inherited Create;
  if (not AX.IsInitialized) or (AX.SignValue < 0) or (AX.CompareTo(FQ) >= 0) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSecP256K1FieldElement);
  FX := TSecP256K1Field.FromBigInteger(AX);
end;

constructor TSecP256K1FieldElement.Create();
begin
  Inherited Create;
  FX := TNat256.Create();
end;

constructor TSecP256K1FieldElement.Create(const AX: TCryptoLibUInt32Array);
begin
  Inherited Create;
  FX := AX;
end;

function TSecP256K1FieldElement.GetX: TCryptoLibUInt32Array;
begin
  Result := FX;
end;

function TSecP256K1FieldElement.GetFieldName: String;
begin
  Result := 'SecP256K1Field';
end;

function TSecP256K1FieldElement.GetFieldSize: Int32;
begin
  Result := FQ.BitLength;
end;

function TSecP256K1FieldElement.GetIsOne: Boolean;
begin
  Result := TNat256.IsOne(FX);
end;

function TSecP256K1FieldElement.GetIsZero: Boolean;
begin
  Result := TNat256.IsZero(FX);
end;

function TSecP256K1FieldElement.ToBigInteger: TBigInteger;
begin
  Result := TNat256.ToBigInteger(FX);
end;

function TSecP256K1FieldElement.TestBitZero: Boolean;
begin
  Result := TNat256.GetBit(FX, 0) = 1;
end;

function TSecP256K1FieldElement.Add(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.Add(FX, (AB as ISecP256K1FieldElement).X, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.AddOne: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.AddOne(FX, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.Subtract(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.Subtract(FX, (AB as ISecP256K1FieldElement).X, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.Multiply(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.Multiply(FX, (AB as ISecP256K1FieldElement).X, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.Divide(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.Inv((AB as ISecP256K1FieldElement).X, LZ);
  TSecP256K1Field.Multiply(LZ, FX, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.Negate: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.Negate(FX, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.Square: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.Square(FX, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.Invert: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat256.Create();
  TSecP256K1Field.Inv(FX, LZ);
  Result := TSecP256K1FieldElement.Create(LZ);
end;

function TSecP256K1FieldElement.Sqrt: IECFieldElement;
var
  LX1, LTT0, LX2, LX3, LX6, LX9, LX11, LX22, LX44, LX88, LX176, LX220, LX223: TCryptoLibUInt32Array;
  LT1, LT2: TCryptoLibUInt32Array;
begin
  LX1 := FX;
  if TNat256.IsZero(LX1) or TNat256.IsOne(LX1) then
    Exit(Self as IECFieldElement);

  LTT0 := TNat256.CreateExt();

  LX2 := TNat256.Create();
  TSecP256K1Field.Square(LX1, LX2, LTT0);
  TSecP256K1Field.Multiply(LX2, LX1, LX2, LTT0);
  LX3 := TNat256.Create();
  TSecP256K1Field.Square(LX2, LX3, LTT0);
  TSecP256K1Field.Multiply(LX3, LX1, LX3, LTT0);
  LX6 := TNat256.Create();
  TSecP256K1Field.SquareN(LX3, 3, LX6, LTT0);
  TSecP256K1Field.Multiply(LX6, LX3, LX6, LTT0);
  LX9 := LX6;
  TSecP256K1Field.SquareN(LX6, 3, LX9, LTT0);
  TSecP256K1Field.Multiply(LX9, LX3, LX9, LTT0);
  LX11 := LX9;
  TSecP256K1Field.SquareN(LX9, 2, LX11, LTT0);
  TSecP256K1Field.Multiply(LX11, LX2, LX11, LTT0);
  LX22 := TNat256.Create();
  TSecP256K1Field.SquareN(LX11, 11, LX22, LTT0);
  TSecP256K1Field.Multiply(LX22, LX11, LX22, LTT0);
  LX44 := LX11;
  TSecP256K1Field.SquareN(LX22, 22, LX44, LTT0);
  TSecP256K1Field.Multiply(LX44, LX22, LX44, LTT0);
  LX88 := TNat256.Create();
  TSecP256K1Field.SquareN(LX44, 44, LX88, LTT0);
  TSecP256K1Field.Multiply(LX88, LX44, LX88, LTT0);
  LX176 := TNat256.Create();
  TSecP256K1Field.SquareN(LX88, 88, LX176, LTT0);
  TSecP256K1Field.Multiply(LX176, LX88, LX176, LTT0);
  LX220 := LX88;
  TSecP256K1Field.SquareN(LX176, 44, LX220, LTT0);
  TSecP256K1Field.Multiply(LX220, LX44, LX220, LTT0);
  LX223 := LX44;
  TSecP256K1Field.SquareN(LX220, 3, LX223, LTT0);
  TSecP256K1Field.Multiply(LX223, LX3, LX223, LTT0);

  LT1 := LX223;
  TSecP256K1Field.SquareN(LT1, 23, LT1, LTT0);
  TSecP256K1Field.Multiply(LT1, LX22, LT1, LTT0);
  TSecP256K1Field.SquareN(LT1, 6, LT1, LTT0);
  TSecP256K1Field.Multiply(LT1, LX2, LT1, LTT0);
  TSecP256K1Field.SquareN(LT1, 2, LT1, LTT0);

  LT2 := LX2;
  TSecP256K1Field.Square(LT1, LT2, LTT0);

  if TNat256.Eq(LX1, LT2) then
    Result := TSecP256K1FieldElement.Create(LT1)
  else
    Result := nil;
end;

function TSecP256K1FieldElement.Equals(const AOther: IECFieldElement): Boolean;
begin
  if (Self as IECFieldElement) = AOther then
    Exit(True);
  if AOther = nil then
    Exit(False);
  Result := TNat256.Eq(FX, (AOther as ISecP256K1FieldElement).X);
end;

function TSecP256K1FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FQ.GetHashCode() xor TArrayUtilities.GetArrayHashCode(FX, 0, 8);
end;

{ TSecP256K1Point }

constructor TSecP256K1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  Inherited Create(ACurve, AX, AY);
end;

constructor TSecP256K1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  Inherited Create(ACurve, AX, AY, AZs);
end;

function TSecP256K1Point.Detach: IECPoint;
begin
  Result := TSecP256K1Point.Create(nil, AffineXCoord, AffineYCoord);
end;

function TSecP256K1Point.Add(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LX1, LY1, LX2, LY2, LZ1, LZ2: ISecP256K1FieldElement;
  LTT0, LTT1: TCryptoLibUInt32Array;
  LT2, LT3, LT4: TCryptoLibUInt32Array;
  LZ1IsOne, LZ2IsOne: Boolean;
  LU2, LS2, LU1, LS1: TCryptoLibUInt32Array;
  LH, LR, LHSquared, LG, LV: TCryptoLibUInt32Array;
  LC: UInt32;
  LX3, LY3, LZ3: ISecP256K1FieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Self as IECPoint);
  if (Self as IECPoint) = AB then
    Exit(Twice());

  LCurve := Curve;
  LX1 := RawXCoord as ISecP256K1FieldElement;
  LY1 := RawYCoord as ISecP256K1FieldElement;
  LX2 := AB.RawXCoord as ISecP256K1FieldElement;
  LY2 := AB.RawYCoord as ISecP256K1FieldElement;
  LZ1 := RawZCoords[0] as ISecP256K1FieldElement;
  LZ2 := AB.GetZCoord(0) as ISecP256K1FieldElement;

  LTT0 := TNat256.CreateExt();
  LTT1 := TNat256.CreateExt();
  LT2 := TNat256.Create();
  LT3 := TNat256.Create();
  LT4 := TNat256.Create();

  LZ1IsOne := LZ1.IsOne;
  if LZ1IsOne then
  begin
    LU2 := LX2.X;
    LS2 := LY2.X;
  end
  else
  begin
    LS2 := LT3;
    TSecP256K1Field.Square(LZ1.X, LS2, LTT0);
    LU2 := LT2;
    TSecP256K1Field.Multiply(LS2, LX2.X, LU2, LTT0);
    TSecP256K1Field.Multiply(LS2, LZ1.X, LS2, LTT0);
    TSecP256K1Field.Multiply(LS2, LY2.X, LS2, LTT0);
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
    TSecP256K1Field.Square(LZ2.X, LS1, LTT0);
    LU1 := LTT1;
    TSecP256K1Field.Multiply(LS1, LX1.X, LU1, LTT0);
    TSecP256K1Field.Multiply(LS1, LZ2.X, LS1, LTT0);
    TSecP256K1Field.Multiply(LS1, LY1.X, LS1, LTT0);
  end;

  LH := TNat256.Create();
  TSecP256K1Field.Subtract(LU1, LU2, LH);

  LR := LT2;
  TSecP256K1Field.Subtract(LS1, LS2, LR);

  if TNat256.IsZero(LH) then
  begin
    if TNat256.IsZero(LR) then
      Exit(Twice());
    Exit(LCurve.Infinity);
  end;

  LHSquared := LT3;
  TSecP256K1Field.Square(LH, LHSquared, LTT0);

  LG := TNat256.Create();
  TSecP256K1Field.Multiply(LHSquared, LH, LG, LTT0);

  LV := LT3;
  TSecP256K1Field.Multiply(LHSquared, LU1, LV, LTT0);

  TSecP256K1Field.Negate(LG, LG);
  TNat256.Mul(LS1, LG, LTT1);

  LC := TNat256.AddBothTo(LV, LV, LG);
  TSecP256K1Field.Reduce32(LC, LG);

  LX3 := TSecP256K1FieldElement.Create(LT4);
  TSecP256K1Field.Square(LR, LX3.X, LTT0);
  TSecP256K1Field.Subtract(LX3.X, LG, LX3.X);

  LY3 := TSecP256K1FieldElement.Create(LG);
  TSecP256K1Field.Subtract(LV, LX3.X, LY3.X);
  TSecP256K1Field.MultiplyAddToExt(LY3.X, LR, LTT1);
  TSecP256K1Field.Reduce(LTT1, LY3.X);

  LZ3 := TSecP256K1FieldElement.Create(LH);
  if not LZ1IsOne then
    TSecP256K1Field.Multiply(LZ3.X, LZ1.X, LZ3.X, LTT0);
  if not LZ2IsOne then
    TSecP256K1Field.Multiply(LZ3.X, LZ2.X, LZ3.X, LTT0);

  LZs := TCryptoLibGenericArray<IECFieldElement>.Create(LZ3 as IECFieldElement);
  Result := TSecP256K1Point.Create(LCurve, LX3 as IECFieldElement, LY3 as IECFieldElement, LZs);
end;

function TSecP256K1Point.Twice: IECPoint;
var
  LCurve: IECCurve;
  LY1, LX1, LZ1: ISecP256K1FieldElement;
  LTT0: TCryptoLibUInt32Array;
  LY1Squared, LT, LM, LS: TCryptoLibUInt32Array;
  LT1: TCryptoLibUInt32Array;
  LC: UInt32;
  LX3, LY3, LZ3: ISecP256K1FieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  LCurve := Curve;
  LY1 := RawYCoord as ISecP256K1FieldElement;
  if LY1.IsZero then
    Exit(LCurve.Infinity);

  LX1 := RawXCoord as ISecP256K1FieldElement;
  LZ1 := RawZCoords[0] as ISecP256K1FieldElement;

  LTT0 := TNat256.CreateExt();

  LY1Squared := TNat256.Create();
  TSecP256K1Field.Square(LY1.X, LY1Squared, LTT0);

  LT := TNat256.Create();
  TSecP256K1Field.Square(LY1Squared, LT, LTT0);

  LM := TNat256.Create();
  TSecP256K1Field.Square(LX1.X, LM, LTT0);
  LC := TNat256.AddBothTo(LM, LM, LM);
  TSecP256K1Field.Reduce32(LC, LM);

  LS := LY1Squared;
  TSecP256K1Field.Multiply(LY1Squared, LX1.X, LS, LTT0);
  LC := TNat.ShiftUpBits(8, LS, 2, 0, LS);
  TSecP256K1Field.Reduce32(LC, LS);

  LT1 := TNat256.Create();
  LC := TNat.ShiftUpBits(8, LT, 3, 0, LT1);
  TSecP256K1Field.Reduce32(LC, LT1);

  LX3 := TSecP256K1FieldElement.Create(LT);
  TSecP256K1Field.Square(LM, LX3.X, LTT0);
  TSecP256K1Field.Subtract(LX3.X, LS, LX3.X);
  TSecP256K1Field.Subtract(LX3.X, LS, LX3.X);

  LY3 := TSecP256K1FieldElement.Create(LS);
  TSecP256K1Field.Subtract(LS, LX3.X, LY3.X);
  TSecP256K1Field.Multiply(LY3.X, LM, LY3.X, LTT0);
  TSecP256K1Field.Subtract(LY3.X, LT1, LY3.X);

  LZ3 := TSecP256K1FieldElement.Create(LM);
  TSecP256K1Field.Twice(LY1.X, LZ3.X);
  if not LZ1.IsOne then
    TSecP256K1Field.Multiply(LZ3.X, LZ1.X, LZ3.X, LTT0);

  LZs := TCryptoLibGenericArray<IECFieldElement>.Create(LZ3 as IECFieldElement);
  Result := TSecP256K1Point.Create(LCurve, LX3 as IECFieldElement, LY3 as IECFieldElement, LZs);
end;

function TSecP256K1Point.TwicePlus(const AB: IECPoint): IECPoint;
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

function TSecP256K1Point.ThreeTimes: IECPoint;
begin
  if IsInfinity or RawYCoord.IsZero then
    Exit(Self as IECPoint);
  Result := Twice().Add(Self as IECPoint);
end;

function TSecP256K1Point.Negate: IECPoint;
begin
  if IsInfinity then
    Exit(Self as IECPoint);
  Result := TSecP256K1Point.Create(Curve, RawXCoord, RawYCoord.Negate(), RawZCoords);
end;

{ TSecP256K1Curve.TSecP256K1LookupTable }

constructor TSecP256K1Curve.TSecP256K1LookupTable.Create(const AOuter: ISecP256K1Curve;
  const ATable: TCryptoLibUInt32Array; ASize: Int32);
begin
  Inherited Create;
  FOuter := AOuter;
  FTable := ATable;
  FSize := ASize;
end;

function TSecP256K1Curve.TSecP256K1LookupTable.GetSize: Int32;
begin
  Result := FSize;
end;

function TSecP256K1Curve.TSecP256K1LookupTable.CreatePoint(const AX, AY: TCryptoLibUInt32Array): IECPoint;
begin
  Result := FOuter.CreateRawPoint(TSecP256K1FieldElement.Create(AX) as IECFieldElement,
    TSecP256K1FieldElement.Create(AY) as IECFieldElement, TSecP256K1Curve.SecP256K1AffineZs);
end;

function TSecP256K1Curve.TSecP256K1LookupTable.Lookup(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt32Array;
  LPos, LI, LJ: Int32;
  LMask: UInt32;
begin
  LX := TNat256.Create();
  LY := TNat256.Create();
  LPos := 0;

  for LI := 0 to System.Pred(FSize) do
  begin
    LMask := UInt32(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));

    for LJ := 0 to System.Pred(SECP256K1_FE_INTS) do
    begin
      LX[LJ] := LX[LJ] xor (FTable[LPos + LJ] and LMask);
      LY[LJ] := LY[LJ] xor (FTable[LPos + SECP256K1_FE_INTS + LJ] and LMask);
    end;

    LPos := LPos + (SECP256K1_FE_INTS * 2);
  end;

  Result := CreatePoint(LX, LY);
end;

function TSecP256K1Curve.TSecP256K1LookupTable.LookupVar(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt32Array;
  LPos, LJ: Int32;
begin
  LX := TNat256.Create();
  LY := TNat256.Create();
  LPos := AIndex * SECP256K1_FE_INTS * 2;

  for LJ := 0 to System.Pred(SECP256K1_FE_INTS) do
  begin
    LX[LJ] := FTable[LPos + LJ];
    LY[LJ] := FTable[LPos + SECP256K1_FE_INTS + LJ];
  end;

  Result := CreatePoint(LX, LY);
end;

{ TSecP256K1Curve }

class procedure TSecP256K1Curve.Boot;
begin
  FQ := TSecP256K1FieldElement.Q;
  FSecP256K1AffineZs := TCryptoLibGenericArray<IECFieldElement>.Create(
    TSecP256K1FieldElement.Create(TBigInteger.One) as IECFieldElement);
end;

class constructor TSecP256K1Curve.Create;
begin
  Boot;
end;

constructor TSecP256K1Curve.Create;
begin
  Inherited Create(TSecP256K1Curve.Q, True);
  FInfinity := TSecP256K1Point.Create(Self as IECCurve, nil, nil);
  FA := FromBigInteger(TBigInteger.Zero);
  FB := FromBigInteger(TBigInteger.Seven);
  FOrder := TBigInteger.Create(1, THex.Decode('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141'));
  FCofactor := TBigInteger.One;
  FCoord := SECP256K1_DEFAULT_COORDS;
end;

destructor TSecP256K1Curve.Destroy;
begin
  FInfinity := nil;
  inherited Destroy;
end;

function TSecP256K1Curve.GetQ: TBigInteger;
begin
  Result := TSecP256K1Curve.Q;
end;

function TSecP256K1Curve.CloneCurve: IECCurve;
begin
  Result := TSecP256K1Curve.Create;
end;

function TSecP256K1Curve.GetFieldSize: Int32;
begin
  Result := TSecP256K1Curve.Q.BitLength;
end;

function TSecP256K1Curve.GetInfinity: IECPoint;
begin
  Result := FInfinity;
end;

function TSecP256K1Curve.FromBigInteger(const AX: TBigInteger): IECFieldElement;
begin
  Result := TSecP256K1FieldElement.Create(AX);
end;

function TSecP256K1Curve.CreateRawPoint(const AX, AY: IECFieldElement): IECPoint;
begin
  Result := TSecP256K1Point.Create(Self as IECCurve, AX, AY);
end;

function TSecP256K1Curve.CreateRawPoint(const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint;
begin
  Result := TSecP256K1Point.Create(Self as IECCurve, AX, AY, AZs);
end;

function TSecP256K1Curve.CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32): IECLookupTable;
var
  LTable: TCryptoLibUInt32Array;
  LPos, LI: Int32;
  LP: IECPoint;
begin
  System.SetLength(LTable, ALen * SECP256K1_FE_INTS * 2);
  LPos := 0;
  for LI := 0 to System.Pred(ALen) do
  begin
    LP := APoints[AOff + LI];
    TNat256.Copy((LP.RawXCoord as ISecP256K1FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECP256K1_FE_INTS;
    TNat256.Copy((LP.RawYCoord as ISecP256K1FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECP256K1_FE_INTS;
  end;
  Result := TSecP256K1LookupTable.Create(Self as ISecP256K1Curve, LTable, ALen);
end;

function TSecP256K1Curve.RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement;
var
  LX: TCryptoLibUInt32Array;
begin
  LX := TNat256.Create();
  TSecP256K1Field.Random(ARandom, LX);
  Result := TSecP256K1FieldElement.Create(LX);
end;

function TSecP256K1Curve.RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement;
var
  LX: TCryptoLibUInt32Array;
begin
  LX := TNat256.Create();
  TSecP256K1Field.RandomMult(ARandom, LX);
  Result := TSecP256K1FieldElement.Create(LX);
end;

function TSecP256K1Curve.SupportsCoordinateSystem(ACoord: Int32): Boolean;
begin
  case ACoord of
    TECCurveConstants.COORD_JACOBIAN:
      Result := True;
  else
    Result := False;
  end;
end;

class function TSecP256K1FieldElement.GetQ: TBigInteger;
begin
  Result := FQ;
end;

end.
