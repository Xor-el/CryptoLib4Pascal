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

unit ClpSecP384R1Custom;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpBigIntegers,
  ClpNat384,
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
  ClpIECCommon,
  ClpIECFieldElement,
  ClpISecP384R1Custom,
  ClpCryptoLibTypes;

resourcestring
  SInvalidSecP384R1FieldElement = 'value invalid for SecP384R1FieldElement';

type
  TSecP384R1Field = class sealed(TObject)
  strict private
  const
    P11 = UInt32($FFFFFFFF);
    PExt23 = UInt32($FFFFFFFF);
  class var
    FP, FPExt, FPExtInv: TCryptoLibUInt32Array;
  class procedure Boot; static;
  class procedure AddPInvTo(const AZ: TCryptoLibUInt32Array); static;
  class procedure SubPInvFrom(const AZ: TCryptoLibUInt32Array); static;
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
  TSecP384R1FieldElement = class sealed(TAbstractFpFieldElement,
    IAbstractFpFieldElement, IECFieldElement, ISecP384R1FieldElement)
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
  TSecP384R1Point = class sealed(TAbstractFpPoint, IAbstractFpPoint, IECPoint,
    ISecP384R1Point)
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
  TSecP384R1Curve = class sealed(TAbstractFpCurve, IAbstractFpCurve, IECCurve,
    ISecP384R1Curve)
  strict private
  const
    SECP384R1_DEFAULT_COORDS = TECCurveConstants.COORD_JACOBIAN;
    SECP384R1_FE_INTS = 12;
  strict private
  type
    TSecP384R1LookupTable = class sealed(TAbstractECLookupTable, IECLookupTable,
      ISecP384R1LookupTable)
    strict private
      FOuter: ISecP384R1Curve;
      FTable: TCryptoLibUInt32Array;
      FSize: Int32;
      function CreatePoint(const AX, AY: TCryptoLibUInt32Array): IECPoint;
    public
      constructor Create(const AOuter: ISecP384R1Curve;
        const ATable: TCryptoLibUInt32Array; ASize: Int32);
      function GetSize: Int32; override;
      function Lookup(AIndex: Int32): IECPoint; override;
      function LookupVar(AIndex: Int32): IECPoint; override;
    end;
  class var
    FQ: TBigInteger;
    FSecP384R1AffineZs: TCryptoLibGenericArray<IECFieldElement>;
  class procedure Boot; static;
  class constructor Create;
  var
    FInfinity: ISecP384R1Point;
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
    class property SecP384R1AffineZs: TCryptoLibGenericArray<IECFieldElement> read FSecP384R1AffineZs;
  end;

implementation

{ TSecP384R1Field }

class procedure TSecP384R1Field.Boot;
begin
  FP := TCryptoLibUInt32Array.Create($FFFFFFFF, $00000000, $00000000, $FFFFFFFF,
    $FFFFFFFE, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
  FPExt := TCryptoLibUInt32Array.Create($00000001, $FFFFFFFE, $00000000, $00000002,
    $00000000, $FFFFFFFE, $00000000, $00000002, $00000001, $00000000, $00000000, $00000000,
    $FFFFFFFE, $00000001, $00000000, $FFFFFFFE, $FFFFFFFD, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
  FPExtInv := TCryptoLibUInt32Array.Create($FFFFFFFF, $00000001, $FFFFFFFF, $FFFFFFFD,
    $FFFFFFFF, $00000001, $FFFFFFFF, $FFFFFFFD, $FFFFFFFE, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $00000001, $FFFFFFFE, $FFFFFFFF, $00000001, $00000002);
end;

class constructor TSecP384R1Field.Create;
begin
  Boot;
end;

class procedure TSecP384R1Field.AddPInvTo(const AZ: TCryptoLibUInt32Array);
var
  LC: Int64;
begin
  LC := Int64(AZ[0]) + 1;
  AZ[0] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + (Int64(AZ[1]) - 1);
  AZ[1] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  if LC <> 0 then
  begin
    LC := LC + Int64(AZ[2]);
    AZ[2] := UInt32(LC);
    LC := TBitOperations.Asr64(LC, 32);
  end;
  LC := LC + (Int64(AZ[3]) + 1);
  AZ[3] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + (Int64(AZ[4]) + 1);
  AZ[4] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  if LC <> 0 then
    TNat.IncAt(12, AZ, 5);
end;

class procedure TSecP384R1Field.SubPInvFrom(const AZ: TCryptoLibUInt32Array);
var
  LC: Int64;
begin
  LC := Int64(AZ[0]) - 1;
  AZ[0] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + (Int64(AZ[1]) + 1);
  AZ[1] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  if LC <> 0 then
  begin
    LC := LC + Int64(AZ[2]);
    AZ[2] := UInt32(LC);
    LC := TBitOperations.Asr64(LC, 32);
  end;
  LC := LC + (Int64(AZ[3]) - 1);
  AZ[3] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + (Int64(AZ[4]) - 1);
  AZ[4] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  if LC <> 0 then
    TNat.DecAt(12, AZ, 5);
end;

class procedure TSecP384R1Field.Add(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.Add(12, AX, AY, AZ);
  if (LC <> 0) or ((AZ[11] = P11) and TNat.Gte(12, AZ, FP)) then
    AddPInvTo(AZ);
end;

class procedure TSecP384R1Field.AddExt(const AXX, AYY, AZZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.Add(24, AXX, AYY, AZZ);
  if (LC <> 0) or ((AZZ[23] = PExt23) and TNat.Gte(24, AZZ, FPExt)) then
    if TNat.AddTo(System.Length(FPExtInv), FPExtInv, AZZ) <> 0 then
      TNat.IncAt(24, AZZ, System.Length(FPExtInv));
end;

class procedure TSecP384R1Field.AddOne(const AX, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.Inc(12, AX, AZ);
  if (LC <> 0) or ((AZ[11] = P11) and TNat.Gte(12, AZ, FP)) then
    AddPInvTo(AZ);
end;

class function TSecP384R1Field.FromBigInteger(const AX: TBigInteger): TCryptoLibUInt32Array;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.FromBigInteger(384, AX);
  if (LZ[11] = P11) and TNat.Gte(12, LZ, FP) then
    TNat.SubFrom(12, FP, LZ);
  Result := LZ;
end;

class procedure TSecP384R1Field.Half(const AX, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  if (AX[0] and 1) = 0 then
    TNat.ShiftDownBit(12, AX, 0, AZ)
  else
  begin
    LC := TNat.Add(12, AX, FP, AZ);
    TNat.ShiftDownBit(12, AZ, LC);
  end;
end;

class procedure TSecP384R1Field.Inv(const AX, AZ: TCryptoLibUInt32Array);
begin
  TMod.CheckedModOddInverse(FP, AX, AZ);
end;

class function TSecP384R1Field.IsZero(const AX: TCryptoLibUInt32Array): Int32;
var
  LD: UInt32;
  LI: Int32;
begin
  LD := 0;
  for LI := 0 to 11 do
    LD := LD or AX[LI];
  LD := (LD shr 1) or (LD and 1);
  Result := TBitOperations.Asr32(Int32(LD) - 1, 31);
end;

class procedure TSecP384R1Field.Multiply(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  LTT := TNat.Create(24);
  TNat384.Mul(AX, AY, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecP384R1Field.Multiply(const AX, AY, AZ, ATT: TCryptoLibUInt32Array);
begin
  TNat384.Mul(AX, AY, ATT);
  Reduce(ATT, AZ);
end;

class procedure TSecP384R1Field.Negate(const AX, AZ: TCryptoLibUInt32Array);
begin
  if IsZero(AX) <> 0 then
    TNat.Sub(12, FP, FP, AZ)
  else
    TNat.Sub(12, FP, AX, AZ);
end;

class procedure TSecP384R1Field.Random(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array);
var
  LBB: TCryptoLibByteArray;
begin
  System.SetLength(LBB, 12 * 4);
  repeat
    AR.NextBytes(LBB);
    TPack.LE_To_UInt32(LBB, 0, AZ, 0, 12);
  until TNat.LessThan(12, AZ, FP) <> 0;
end;

class procedure TSecP384R1Field.RandomMult(const AR: ISecureRandom; const AZ: TCryptoLibUInt32Array);
begin
  repeat
    Random(AR, AZ);
  until IsZero(AZ) = 0;
end;

class procedure TSecP384R1Field.Reduce(const AXX, AZ: TCryptoLibUInt32Array);
var
  LXX16, LXX17, LXX18, LXX19, LXX20, LXX21, LXX22, LXX23: Int64;
  LT0, LT1, LT2, LT3, LT4, LT5, LT6, LT7: Int64;
  LCc: Int64;
  LN: Int64;
begin
  LN := 1;
  LXX16 := Int64(UInt32(AXX[16]));
  LXX17 := Int64(UInt32(AXX[17]));
  LXX18 := Int64(UInt32(AXX[18]));
  LXX19 := Int64(UInt32(AXX[19]));
  LXX20 := Int64(UInt32(AXX[20]));
  LXX21 := Int64(UInt32(AXX[21]));
  LXX22 := Int64(UInt32(AXX[22]));
  LXX23 := Int64(UInt32(AXX[23]));

  LT0 := Int64(AXX[12]) + LXX20 - LN;
  LT1 := Int64(AXX[13]) + LXX22;
  LT2 := Int64(AXX[14]) + LXX22 + LXX23;
  LT3 := Int64(AXX[15]) + LXX23;
  LT4 := LXX17 + LXX21;
  LT5 := LXX21 - LXX23;
  LT6 := LXX22 - LXX23;
  LT7 := LT0 + LT5;

  LCc := 0;
  LCc := LCc + (Int64(AXX[0]) + LT7);
  AZ[0] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[1]) + LXX23 - LT0 + LT1);
  AZ[1] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[2]) - LXX21 - LT1 + LT2);
  AZ[2] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[3]) - LT2 + LT3 + LT7);
  AZ[3] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[4]) + LXX16 + LXX21 + LT1 - LT3 + LT7);
  AZ[4] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[5]) - LXX16 + LT1 + LT2 + LT4);
  AZ[5] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[6]) + LXX18 - LXX17 + LT2 + LT3);
  AZ[6] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[7]) + LXX16 + LXX19 - LXX18 + LT3);
  AZ[7] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[8]) + LXX16 + LXX17 + LXX20 - LXX19);
  AZ[8] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[9]) + LXX18 - LXX20 + LT4);
  AZ[9] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[10]) + LXX18 + LXX19 - LT5 + LT6);
  AZ[10] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + (Int64(AXX[11]) + LXX19 + LXX20 - LT6);
  AZ[11] := UInt32(LCc);
  LCc := TBitOperations.Asr64(LCc, 32);
  LCc := LCc + LN;

  {$IFDEF DEBUG}
  Assert(LCc >= 0);
  {$ENDIF DEBUG}

  Reduce32(UInt32(LCc), AZ);
end;

class procedure TSecP384R1Field.Reduce32(AX: UInt32; const AZ: TCryptoLibUInt32Array);
var
  LCc: Int64;
  LXX12: Int64;
begin
  LCc := 0;

  if AX <> 0 then
  begin
    LXX12 := Int64(AX);

    LCc := LCc + (Int64(AZ[0]) + LXX12);
    AZ[0] := UInt32(LCc);
    LCc := TBitOperations.Asr64(LCc, 32);
    LCc := LCc + (Int64(AZ[1]) - LXX12);
    AZ[1] := UInt32(LCc);
    LCc := TBitOperations.Asr64(LCc, 32);
    if LCc <> 0 then
    begin
      LCc := LCc + Int64(AZ[2]);
      AZ[2] := UInt32(LCc);
      LCc := TBitOperations.Asr64(LCc, 32);
    end;
    LCc := LCc + (Int64(AZ[3]) + LXX12);
    AZ[3] := UInt32(LCc);
    LCc := TBitOperations.Asr64(LCc, 32);
    LCc := LCc + (Int64(AZ[4]) + LXX12);
    AZ[4] := UInt32(LCc);
    LCc := TBitOperations.Asr64(LCc, 32);

    {$IFDEF DEBUG}
    Assert((LCc = 0) or (LCc = 1));
    {$ENDIF DEBUG}
  end;

  if ((LCc <> 0) and (TNat.IncAt(12, AZ, 5) <> 0)) or
    ((AZ[11] = P11) and TNat.Gte(12, AZ, FP)) then
    AddPInvTo(AZ);
end;

class procedure TSecP384R1Field.Square(const AX, AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  LTT := TNat.Create(24);
  TNat384.Square(AX, LTT);
  Reduce(LTT, AZ);
end;

class procedure TSecP384R1Field.Square(const AX, AZ, ATT: TCryptoLibUInt32Array);
begin
  TNat384.Square(AX, ATT);
  Reduce(ATT, AZ);
end;

class procedure TSecP384R1Field.SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
  const AZ: TCryptoLibUInt32Array);
var
  LTT: TCryptoLibUInt32Array;
begin
  {$IFDEF DEBUG}
  Assert(AN > 0);
  {$ENDIF DEBUG}
  LTT := TNat.Create(24);
  TNat384.Square(AX, LTT);
  Reduce(LTT, AZ);
  Dec(AN);
  while AN > 0 do
  begin
    TNat384.Square(AZ, LTT);
    Reduce(LTT, AZ);
    Dec(AN);
  end;
end;

class procedure TSecP384R1Field.SquareN(const AX: TCryptoLibUInt32Array; AN: Int32;
  const AZ, ATT: TCryptoLibUInt32Array);
begin
  {$IFDEF DEBUG}
  Assert(AN > 0);
  {$ENDIF DEBUG}
  TNat384.Square(AX, ATT);
  Reduce(ATT, AZ);
  Dec(AN);
  while AN > 0 do
  begin
    TNat384.Square(AZ, ATT);
    Reduce(ATT, AZ);
    Dec(AN);
  end;
end;

class procedure TSecP384R1Field.Subtract(const AX, AY, AZ: TCryptoLibUInt32Array);
var
  LC: Int32;
begin
  LC := TNat.Sub(12, AX, AY, AZ);
  if LC <> 0 then
    SubPInvFrom(AZ);
end;

class procedure TSecP384R1Field.SubtractExt(const AXX, AYY, AZZ: TCryptoLibUInt32Array);
var
  LC: Int32;
begin
  LC := TNat.Sub(24, AXX, AYY, AZZ);
  if LC <> 0 then
    if TNat.SubFrom(System.Length(FPExtInv), FPExtInv, AZZ) <> 0 then
      TNat.DecAt(24, AZZ, System.Length(FPExtInv));
end;

class procedure TSecP384R1Field.Twice(const AX, AZ: TCryptoLibUInt32Array);
var
  LC: UInt32;
begin
  LC := TNat.ShiftUpBit(12, AX, 0, AZ);
  if (LC <> 0) or ((AZ[11] = P11) and TNat.Gte(12, AZ, FP)) then
    AddPInvTo(AZ);
end;

{ TSecP384R1FieldElement }

class procedure TSecP384R1FieldElement.Boot;
begin
  FQ := TBigInteger.Create(1, THex.Decode('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF'));
end;

class constructor TSecP384R1FieldElement.Create;
begin
  Boot;
end;

class function TSecP384R1FieldElement.GetQ: TBigInteger;
begin
  Result := FQ;
end;

constructor TSecP384R1FieldElement.Create(const AX: TBigInteger);
begin
  Inherited Create;
  if (not AX.IsInitialized) or (AX.SignValue < 0) or (AX.CompareTo(FQ) >= 0) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidSecP384R1FieldElement);
  FX := TSecP384R1Field.FromBigInteger(AX);
end;

constructor TSecP384R1FieldElement.Create();
begin
  Inherited Create;
  FX := TNat.Create(12);
end;

constructor TSecP384R1FieldElement.Create(const AX: TCryptoLibUInt32Array);
begin
  Inherited Create;
  FX := AX;
end;

function TSecP384R1FieldElement.GetX: TCryptoLibUInt32Array;
begin
  Result := FX;
end;

function TSecP384R1FieldElement.GetFieldName: String;
begin
  Result := 'SecP384R1Field';
end;

function TSecP384R1FieldElement.GetFieldSize: Int32;
begin
  Result := FQ.BitLength;
end;

function TSecP384R1FieldElement.GetIsOne: Boolean;
begin
  Result := TNat.IsOne(12, FX);
end;

function TSecP384R1FieldElement.GetIsZero: Boolean;
begin
  Result := TNat.IsZero(12, FX);
end;

function TSecP384R1FieldElement.ToBigInteger: TBigInteger;
begin
  Result := TNat.ToBigInteger(12, FX);
end;

function TSecP384R1FieldElement.TestBitZero: Boolean;
begin
  Result := TNat.GetBit(FX, 0) = 1;
end;

function TSecP384R1FieldElement.Add(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.Add(FX, (AB as ISecP384R1FieldElement).X, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.AddOne: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.AddOne(FX, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.Subtract(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.Subtract(FX, (AB as ISecP384R1FieldElement).X, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.Multiply(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.Multiply(FX, (AB as ISecP384R1FieldElement).X, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.Divide(const AB: IECFieldElement): IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.Inv((AB as ISecP384R1FieldElement).X, LZ);
  TSecP384R1Field.Multiply(LZ, FX, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.Negate: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.Negate(FX, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.Square: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.Square(FX, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.Invert: IECFieldElement;
var
  LZ: TCryptoLibUInt32Array;
begin
  LZ := TNat.Create(12);
  TSecP384R1Field.Inv(FX, LZ);
  Result := TSecP384R1FieldElement.Create(LZ);
end;

function TSecP384R1FieldElement.Sqrt: IECFieldElement;
var
  LX1, LTT0, LT1, LT2, LT3, LT4: TCryptoLibUInt32Array;
  LR: TCryptoLibUInt32Array;
begin
  LX1 := FX;
  if TNat.IsZero(12, LX1) or TNat.IsOne(12, LX1) then
    Exit(Self as IECFieldElement);

  LTT0 := TNat.Create(24);
  LT1 := TNat.Create(12);
  LT2 := TNat.Create(12);
  LT3 := TNat.Create(12);
  LT4 := TNat.Create(12);

  TSecP384R1Field.Square(LX1, LT1, LTT0);
  TSecP384R1Field.Multiply(LT1, LX1, LT1, LTT0);

  TSecP384R1Field.SquareN(LT1, 2, LT2, LTT0);
  TSecP384R1Field.Multiply(LT2, LT1, LT2, LTT0);

  TSecP384R1Field.Square(LT2, LT2, LTT0);
  TSecP384R1Field.Multiply(LT2, LX1, LT2, LTT0);

  TSecP384R1Field.SquareN(LT2, 5, LT3, LTT0);
  TSecP384R1Field.Multiply(LT3, LT2, LT3, LTT0);

  TSecP384R1Field.SquareN(LT3, 5, LT4, LTT0);
  TSecP384R1Field.Multiply(LT4, LT2, LT4, LTT0);

  TSecP384R1Field.SquareN(LT4, 15, LT2, LTT0);
  TSecP384R1Field.Multiply(LT2, LT4, LT2, LTT0);

  TSecP384R1Field.SquareN(LT2, 2, LT3, LTT0);
  TSecP384R1Field.Multiply(LT1, LT3, LT1, LTT0);

  TSecP384R1Field.SquareN(LT3, 28, LT3, LTT0);
  TSecP384R1Field.Multiply(LT2, LT3, LT2, LTT0);

  TSecP384R1Field.SquareN(LT2, 60, LT3, LTT0);
  TSecP384R1Field.Multiply(LT3, LT2, LT3, LTT0);

  LR := LT2;

  TSecP384R1Field.SquareN(LT3, 120, LR, LTT0);
  TSecP384R1Field.Multiply(LR, LT3, LR, LTT0);

  TSecP384R1Field.SquareN(LR, 15, LR, LTT0);
  TSecP384R1Field.Multiply(LR, LT4, LR, LTT0);

  TSecP384R1Field.SquareN(LR, 33, LR, LTT0);
  TSecP384R1Field.Multiply(LR, LT1, LR, LTT0);

  TSecP384R1Field.SquareN(LR, 64, LR, LTT0);
  TSecP384R1Field.Multiply(LR, LX1, LR, LTT0);

  TSecP384R1Field.SquareN(LR, 30, LT1, LTT0);
  TSecP384R1Field.Square(LT1, LT2, LTT0);

  if TNat.Eq(12, LX1, LT2) then
    Result := TSecP384R1FieldElement.Create(LT1)
  else
    Result := nil;
end;

function TSecP384R1FieldElement.Equals(const AOther: IECFieldElement): Boolean;
begin
  if (Self as IECFieldElement) = AOther then
    Exit(True);
  if AOther = nil then
    Exit(False);
  Result := TNat.Eq(12, FX, (AOther as ISecP384R1FieldElement).X);
end;

function TSecP384R1FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FQ.GetHashCode() xor TArrayUtilities.GetArrayHashCode(FX, 0, 12);
end;

{ TSecP384R1Point }

constructor TSecP384R1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement);
begin
  Inherited Create(ACurve, AX, AY);
end;

constructor TSecP384R1Point.Create(const ACurve: IECCurve; const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>);
begin
  Inherited Create(ACurve, AX, AY, AZs);
end;

function TSecP384R1Point.Detach: IECPoint;
begin
  Result := TSecP384R1Point.Create(nil, AffineXCoord, AffineYCoord);
end;

function TSecP384R1Point.Add(const AB: IECPoint): IECPoint;
var
  LCurve: IECCurve;
  LX1, LY1, LX2, LY2, LZ1, LZ2: ISecP384R1FieldElement;
  LTT0, LTT1, LTT2: TCryptoLibUInt32Array;
  LT3, LT4: TCryptoLibUInt32Array;
  LZ1IsOne, LZ2IsOne: Boolean;
  LU2, LS2, LU1, LS1: TCryptoLibUInt32Array;
  LH, LR, LHSquared, LG, LV: TCryptoLibUInt32Array;
  LC: UInt32;
  LX3, LY3, LZ3: ISecP384R1FieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if IsInfinity then
    Exit(AB);
  if AB.IsInfinity then
    Exit(Self as IECPoint);
  if (Self as IECPoint) = AB then
    Exit(Twice());

  LCurve := Curve;
  LX1 := RawXCoord as ISecP384R1FieldElement;
  LY1 := RawYCoord as ISecP384R1FieldElement;
  LX2 := AB.RawXCoord as ISecP384R1FieldElement;
  LY2 := AB.RawYCoord as ISecP384R1FieldElement;
  LZ1 := RawZCoords[0] as ISecP384R1FieldElement;
  LZ2 := AB.GetZCoord(0) as ISecP384R1FieldElement;

  LTT0 := TNat.Create(24);
  LTT1 := TNat.Create(24);
  LTT2 := TNat.Create(24);
  LT3 := TNat.Create(12);
  LT4 := TNat.Create(12);

  LZ1IsOne := LZ1.IsOne;
  if LZ1IsOne then
  begin
    LU2 := LX2.X;
    LS2 := LY2.X;
  end
  else
  begin
    LS2 := LT3;
    TSecP384R1Field.Square(LZ1.X, LS2, LTT0);
    LU2 := LTT2;
    TSecP384R1Field.Multiply(LS2, LX2.X, LU2, LTT0);
    TSecP384R1Field.Multiply(LS2, LZ1.X, LS2, LTT0);
    TSecP384R1Field.Multiply(LS2, LY2.X, LS2, LTT0);
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
    TSecP384R1Field.Square(LZ2.X, LS1, LTT0);
    LU1 := LTT1;
    TSecP384R1Field.Multiply(LS1, LX1.X, LU1, LTT0);
    TSecP384R1Field.Multiply(LS1, LZ2.X, LS1, LTT0);
    TSecP384R1Field.Multiply(LS1, LY1.X, LS1, LTT0);
  end;

  LH := TNat.Create(12);
  TSecP384R1Field.Subtract(LU1, LU2, LH);

  LR := TNat.Create(12);
  TSecP384R1Field.Subtract(LS1, LS2, LR);

  if TNat.IsZero(12, LH) then
  begin
    if TNat.IsZero(12, LR) then
      Exit(Twice());
    Exit(LCurve.Infinity);
  end;

  LHSquared := LT3;
  TSecP384R1Field.Square(LH, LHSquared, LTT0);

  LG := TNat.Create(12);
  TSecP384R1Field.Multiply(LHSquared, LH, LG, LTT0);

  LV := LT3;
  TSecP384R1Field.Multiply(LHSquared, LU1, LV, LTT0);

  TSecP384R1Field.Negate(LG, LG);
  TNat384.Mul(LS1, LG, LTT1);

  LC := TNat.AddBothTo(12, LV, LV, LG);
  TSecP384R1Field.Reduce32(LC, LG);

  LX3 := TSecP384R1FieldElement.Create(LT4);
  TSecP384R1Field.Square(LR, LX3.X, LTT0);
  TSecP384R1Field.Subtract(LX3.X, LG, LX3.X);

  LY3 := TSecP384R1FieldElement.Create(LG);
  TSecP384R1Field.Subtract(LV, LX3.X, LY3.X);
  TNat384.Mul(LY3.X, LR, LTT2);
  TSecP384R1Field.AddExt(LTT1, LTT2, LTT1);
  TSecP384R1Field.Reduce(LTT1, LY3.X);

  LZ3 := TSecP384R1FieldElement.Create(LH);
  if not LZ1IsOne then
    TSecP384R1Field.Multiply(LZ3.X, LZ1.X, LZ3.X, LTT0);
  if not LZ2IsOne then
    TSecP384R1Field.Multiply(LZ3.X, LZ2.X, LZ3.X, LTT0);

  LZs := TCryptoLibGenericArray<IECFieldElement>.Create(LZ3 as IECFieldElement);
  Result := TSecP384R1Point.Create(LCurve, LX3 as IECFieldElement, LY3 as IECFieldElement, LZs);
end;

function TSecP384R1Point.Twice: IECPoint;
var
  LCurve: IECCurve;
  LY1, LX1, LZ1: ISecP384R1FieldElement;
  LTT0: TCryptoLibUInt32Array;
  LY1Squared, LT, LT1, LT2: TCryptoLibUInt32Array;
  LZ1Squared, LM, LS: TCryptoLibUInt32Array;
  LZ1IsOne: Boolean;
  LC: UInt32;
  LX3, LY3, LZ3: ISecP384R1FieldElement;
  LZs: TCryptoLibGenericArray<IECFieldElement>;
begin
  if IsInfinity then
    Exit(Self as IECPoint);

  LCurve := Curve;
  LY1 := RawYCoord as ISecP384R1FieldElement;
  if LY1.IsZero then
    Exit(LCurve.Infinity);

  LX1 := RawXCoord as ISecP384R1FieldElement;
  LZ1 := RawZCoords[0] as ISecP384R1FieldElement;

  LTT0 := TNat.Create(24);
  LT1 := TNat.Create(12);
  LT2 := TNat.Create(12);

  LY1Squared := TNat.Create(12);
  TSecP384R1Field.Square(LY1.X, LY1Squared, LTT0);

  LT := TNat.Create(12);
  TSecP384R1Field.Square(LY1Squared, LT, LTT0);

  LZ1IsOne := LZ1.IsOne;
  if LZ1IsOne then
    LZ1Squared := LZ1.X
  else
  begin
    LZ1Squared := LT2;
    TSecP384R1Field.Square(LZ1.X, LZ1Squared, LTT0);
  end;

  TSecP384R1Field.Subtract(LX1.X, LZ1Squared, LT1);

  LM := LT2;
  TSecP384R1Field.Add(LX1.X, LZ1Squared, LM);
  TSecP384R1Field.Multiply(LM, LT1, LM, LTT0);
  LC := TNat.AddBothTo(12, LM, LM, LM);
  TSecP384R1Field.Reduce32(LC, LM);

  LS := LY1Squared;
  TSecP384R1Field.Multiply(LY1Squared, LX1.X, LS, LTT0);
  LC := TNat.ShiftUpBits(12, LS, 2, 0, LS);
  TSecP384R1Field.Reduce32(LC, LS);

  LC := TNat.ShiftUpBits(12, LT, 3, 0, LT1);
  TSecP384R1Field.Reduce32(LC, LT1);

  LX3 := TSecP384R1FieldElement.Create(LT);
  TSecP384R1Field.Square(LM, LX3.X, LTT0);
  TSecP384R1Field.Subtract(LX3.X, LS, LX3.X);
  TSecP384R1Field.Subtract(LX3.X, LS, LX3.X);

  LY3 := TSecP384R1FieldElement.Create(LS);
  TSecP384R1Field.Subtract(LS, LX3.X, LY3.X);
  TSecP384R1Field.Multiply(LY3.X, LM, LY3.X, LTT0);
  TSecP384R1Field.Subtract(LY3.X, LT1, LY3.X);

  LZ3 := TSecP384R1FieldElement.Create(LM);
  TSecP384R1Field.Twice(LY1.X, LZ3.X);
  if not LZ1IsOne then
    TSecP384R1Field.Multiply(LZ3.X, LZ1.X, LZ3.X, LTT0);

  LZs := TCryptoLibGenericArray<IECFieldElement>.Create(LZ3 as IECFieldElement);
  Result := TSecP384R1Point.Create(LCurve, LX3 as IECFieldElement, LY3 as IECFieldElement, LZs);
end;

function TSecP384R1Point.TwicePlus(const AB: IECPoint): IECPoint;
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

function TSecP384R1Point.ThreeTimes: IECPoint;
begin
  if IsInfinity or RawYCoord.IsZero then
    Exit(Self as IECPoint);
  Result := Twice().Add(Self as IECPoint);
end;

function TSecP384R1Point.Negate: IECPoint;
begin
  if IsInfinity then
    Exit(Self as IECPoint);
  Result := TSecP384R1Point.Create(Curve, RawXCoord, RawYCoord.Negate(), RawZCoords);
end;

{ TSecP384R1Curve.TSecP384R1LookupTable }

constructor TSecP384R1Curve.TSecP384R1LookupTable.Create(const AOuter: ISecP384R1Curve;
  const ATable: TCryptoLibUInt32Array; ASize: Int32);
begin
  Inherited Create;
  FOuter := AOuter;
  FTable := ATable;
  FSize := ASize;
end;

function TSecP384R1Curve.TSecP384R1LookupTable.GetSize: Int32;
begin
  Result := FSize;
end;

function TSecP384R1Curve.TSecP384R1LookupTable.CreatePoint(const AX, AY: TCryptoLibUInt32Array): IECPoint;
begin
  Result := FOuter.CreateRawPoint(TSecP384R1FieldElement.Create(AX) as IECFieldElement,
    TSecP384R1FieldElement.Create(AY) as IECFieldElement, TSecP384R1Curve.SecP384R1AffineZs);
end;

function TSecP384R1Curve.TSecP384R1LookupTable.Lookup(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt32Array;
  LPos, LI, LJ: Int32;
  LMask: UInt32;
begin
  LX := TNat.Create(SECP384R1_FE_INTS);
  LY := TNat.Create(SECP384R1_FE_INTS);
  LPos := 0;

  for LI := 0 to System.Pred(FSize) do
  begin
    LMask := UInt32(TBitOperations.Asr32(((LI xor AIndex) - 1), 31));

    for LJ := 0 to System.Pred(SECP384R1_FE_INTS) do
    begin
      LX[LJ] := LX[LJ] xor (FTable[LPos + LJ] and LMask);
      LY[LJ] := LY[LJ] xor (FTable[LPos + SECP384R1_FE_INTS + LJ] and LMask);
    end;

    LPos := LPos + (SECP384R1_FE_INTS * 2);
  end;

  Result := CreatePoint(LX, LY);
end;

function TSecP384R1Curve.TSecP384R1LookupTable.LookupVar(AIndex: Int32): IECPoint;
var
  LX, LY: TCryptoLibUInt32Array;
  LPos, LJ: Int32;
begin
  LX := TNat.Create(SECP384R1_FE_INTS);
  LY := TNat.Create(SECP384R1_FE_INTS);
  LPos := AIndex * SECP384R1_FE_INTS * 2;

  for LJ := 0 to System.Pred(SECP384R1_FE_INTS) do
  begin
    LX[LJ] := FTable[LPos + LJ];
    LY[LJ] := FTable[LPos + SECP384R1_FE_INTS + LJ];
  end;

  Result := CreatePoint(LX, LY);
end;

{ TSecP384R1Curve }

class procedure TSecP384R1Curve.Boot;
begin
  FQ := TSecP384R1FieldElement.Q;
  FSecP384R1AffineZs := TCryptoLibGenericArray<IECFieldElement>.Create(
    TSecP384R1FieldElement.Create(TBigInteger.One) as IECFieldElement);
end;

class constructor TSecP384R1Curve.Create;
begin
  Boot;
end;

constructor TSecP384R1Curve.Create;
begin
  Inherited Create(TSecP384R1Curve.Q, True);
  FInfinity := TSecP384R1Point.Create(Self as IECCurve, nil, nil);
  FA := FromBigInteger(TBigInteger.Create(1, THex.Decode('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC')));
  FB := FromBigInteger(TBigInteger.Create(1, THex.Decode('B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF')));
  FOrder := TBigInteger.Create(1, THex.Decode('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973'));
  FCofactor := TBigInteger.One;
  FCoord := SECP384R1_DEFAULT_COORDS;
end;

destructor TSecP384R1Curve.Destroy;
begin
  FInfinity := nil;
  inherited Destroy;
end;

function TSecP384R1Curve.GetQ: TBigInteger;
begin
  Result := TSecP384R1Curve.Q;
end;

function TSecP384R1Curve.CloneCurve: IECCurve;
begin
  Result := TSecP384R1Curve.Create;
end;

function TSecP384R1Curve.GetFieldSize: Int32;
begin
  Result := TSecP384R1Curve.Q.BitLength;
end;

function TSecP384R1Curve.GetInfinity: IECPoint;
begin
  Result := FInfinity;
end;

function TSecP384R1Curve.FromBigInteger(const AX: TBigInteger): IECFieldElement;
begin
  Result := TSecP384R1FieldElement.Create(AX);
end;

function TSecP384R1Curve.CreateRawPoint(const AX, AY: IECFieldElement): IECPoint;
begin
  Result := TSecP384R1Point.Create(Self as IECCurve, AX, AY);
end;

function TSecP384R1Curve.CreateRawPoint(const AX, AY: IECFieldElement;
  const AZs: TCryptoLibGenericArray<IECFieldElement>): IECPoint;
begin
  Result := TSecP384R1Point.Create(Self as IECCurve, AX, AY, AZs);
end;

function TSecP384R1Curve.CreateCacheSafeLookupTable(const APoints: TCryptoLibGenericArray<IECPoint>;
  AOff, ALen: Int32): IECLookupTable;
var
  LTable: TCryptoLibUInt32Array;
  LPos, LI: Int32;
  LP: IECPoint;
begin
  System.SetLength(LTable, ALen * SECP384R1_FE_INTS * 2);
  LPos := 0;
  for LI := 0 to System.Pred(ALen) do
  begin
    LP := APoints[AOff + LI];
    TNat.Copy(SECP384R1_FE_INTS, (LP.RawXCoord as ISecP384R1FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECP384R1_FE_INTS;
    TNat.Copy(SECP384R1_FE_INTS, (LP.RawYCoord as ISecP384R1FieldElement).X, 0, LTable, LPos);
    LPos := LPos + SECP384R1_FE_INTS;
  end;
  Result := TSecP384R1LookupTable.Create(Self as ISecP384R1Curve, LTable, ALen);
end;

function TSecP384R1Curve.RandomFieldElement(const ARandom: ISecureRandom): IECFieldElement;
var
  LX: TCryptoLibUInt32Array;
begin
  LX := TNat.Create(12);
  TSecP384R1Field.Random(ARandom, LX);
  Result := TSecP384R1FieldElement.Create(LX);
end;

function TSecP384R1Curve.RandomFieldElementMult(const ARandom: ISecureRandom): IECFieldElement;
var
  LX: TCryptoLibUInt32Array;
begin
  LX := TNat.Create(12);
  TSecP384R1Field.RandomMult(ARandom, LX);
  Result := TSecP384R1FieldElement.Create(LX);
end;

function TSecP384R1Curve.SupportsCoordinateSystem(ACoord: Int32): Boolean;
begin
  case ACoord of
    TECCurveConstants.COORD_JACOBIAN:
      Result := True;
  else
    Result := False;
  end;
end;

end.
