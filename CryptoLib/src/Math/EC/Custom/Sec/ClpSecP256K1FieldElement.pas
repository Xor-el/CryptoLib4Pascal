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

unit ClpSecP256K1FieldElement;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat256,
  ClpMod,
  ClpSecP256K1Curve,
  ClpECFieldElement,
  ClpIECFieldElement,
  ClpSecP256K1Field,
  ClpISecP256K1FieldElement,
  ClpBigInteger,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SInvalidValueForSecP256K1FieldElement =
    'Value Invalid for SecP256K1FieldElement "%s"';

type
  TSecP256K1FieldElement = class(TAbstractFpFieldElement,
    ISecP256K1FieldElement)

  strict private

    function Equals(const other: ISecP256K1FieldElement): Boolean;
      reintroduce; overload;

    class function GetQ: TBigInteger; static; inline;

  strict protected
  var
    Fx: TCryptoLibUInt32Array;

    function GetFieldName: string; override;
    function GetFieldSize: Int32; override;
    function GetIsOne: Boolean; override;
    function GetIsZero: Boolean; override;

    function GetX: TCryptoLibUInt32Array; inline;
    property X: TCryptoLibUInt32Array read GetX;

  public
    constructor Create(); overload;
    constructor Create(const X: TBigInteger); overload;
    constructor Create(const X: TCryptoLibUInt32Array); overload;

    function TestBitZero: Boolean; override;
    function ToBigInteger(): TBigInteger; override;

    function Add(const b: IECFieldElement): IECFieldElement; override;
    function AddOne(): IECFieldElement; override;
    function Subtract(const b: IECFieldElement): IECFieldElement; override;

    function Multiply(const b: IECFieldElement): IECFieldElement; override;
    function Divide(const b: IECFieldElement): IECFieldElement; override;
    function Negate(): IECFieldElement; override;
    function Square(): IECFieldElement; override;

    function Invert(): IECFieldElement; override;

    /// <summary>
    /// return a sqrt root - the routine verifies that the calculation
    /// returns the right value - if <br />none exists it returns null.
    /// </summary>
    function Sqrt(): IECFieldElement; override;

    function Equals(const other: IECFieldElement): Boolean; overload; override;

    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}override;

    property IsZero: Boolean read GetIsZero;
    property IsOne: Boolean read GetIsOne;
    property FieldName: string read GetFieldName;
    property FieldSize: Int32 read GetFieldSize;

    class property Q: TBigInteger read GetQ;
  end;

implementation

{ TSecP256K1FieldElement }

class function TSecP256K1FieldElement.GetQ: TBigInteger;
begin
  result := TSecP256K1Curve.SecP256K1Curve_Q;
end;

function TSecP256K1FieldElement.GetX: TCryptoLibUInt32Array;
begin
  result := Fx;
end;

constructor TSecP256K1FieldElement.Create;
begin
  Inherited Create();
  Fx := TNat256.Create();
end;

constructor TSecP256K1FieldElement.Create(const X: TBigInteger);
begin
  if ((not(X.IsInitialized)) or (X.SignValue < 0) or (X.CompareTo(Q) >= 0)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SInvalidValueForSecP256K1FieldElement, ['x']);
  end;
  Inherited Create();
  Fx := TSecP256K1Field.FromBigInteger(X);
end;

constructor TSecP256K1FieldElement.Create(const X: TCryptoLibUInt32Array);
begin
  Inherited Create();
  Fx := X;
end;

function TSecP256K1FieldElement.GetFieldName: string;
begin
  result := 'SecP256K1Field';
end;

function TSecP256K1FieldElement.GetFieldSize: Int32;
begin
  result := Q.BitLength;
end;

function TSecP256K1FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := Q.GetHashCode() xor TArrayUtils.GetArrayHashCode(Fx, 0, 8);
end;

function TSecP256K1FieldElement.GetIsOne: Boolean;
begin
  result := TNat256.IsOne(Fx);
end;

function TSecP256K1FieldElement.GetIsZero: Boolean;
begin
  result := TNat256.IsZero(Fx);
end;

function TSecP256K1FieldElement.Invert: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TMod.Invert(TSecP256K1Field.P, Fx, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.Multiply(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256K1Field.Multiply(Fx, (b as ISecP256K1FieldElement).X, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.Negate: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256K1Field.Negate(Fx, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.Sqrt: IECFieldElement;
var
  x1, x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1,
    t2: TCryptoLibUInt32Array;
begin
  { *
    * Raise this element to the exponent 2^254 - 2^30 - 2^7 - 2^6 - 2^5 - 2^4 - 2^2
    *
    * Breaking up the exponent's binary representation into "repunits", we get:
    * ( 223 1s ) ( 1 0s ) ( 22 1s ) ( 4 0s ) ( 2 1s ) ( 2 0s)
    *
    * Therefore we need an addition chain containing 2, 22, 223 (the lengths of the repunits)
    * We use: 1, [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
    * }

  x1 := Fx;
  if ((TNat256.IsZero(x1)) or (TNat256.IsOne(x1))) then
  begin
    result := Self as IECFieldElement;
    Exit;
  end;

  x2 := TNat256.Create();
  TSecP256K1Field.Square(x1, x2);
  TSecP256K1Field.Multiply(x2, x1, x2);
  x3 := TNat256.Create();
  TSecP256K1Field.Square(x2, x3);
  TSecP256K1Field.Multiply(x3, x1, x3);
  x6 := TNat256.Create();
  TSecP256K1Field.SquareN(x3, 3, x6);
  TSecP256K1Field.Multiply(x6, x3, x6);
  x9 := x6;
  TSecP256K1Field.SquareN(x6, 3, x9);
  TSecP256K1Field.Multiply(x9, x3, x9);
  x11 := x9;
  TSecP256K1Field.SquareN(x9, 2, x11);
  TSecP256K1Field.Multiply(x11, x2, x11);
  x22 := TNat256.Create();
  TSecP256K1Field.SquareN(x11, 11, x22);
  TSecP256K1Field.Multiply(x22, x11, x22);
  x44 := x11;
  TSecP256K1Field.SquareN(x22, 22, x44);
  TSecP256K1Field.Multiply(x44, x22, x44);
  x88 := TNat256.Create();
  TSecP256K1Field.SquareN(x44, 44, x88);
  TSecP256K1Field.Multiply(x88, x44, x88);
  x176 := TNat256.Create();
  TSecP256K1Field.SquareN(x88, 88, x176);
  TSecP256K1Field.Multiply(x176, x88, x176);
  x220 := x88;
  TSecP256K1Field.SquareN(x176, 44, x220);
  TSecP256K1Field.Multiply(x220, x44, x220);
  x223 := x44;
  TSecP256K1Field.SquareN(x220, 3, x223);
  TSecP256K1Field.Multiply(x223, x3, x223);

  t1 := x223;
  TSecP256K1Field.SquareN(t1, 23, t1);
  TSecP256K1Field.Multiply(t1, x22, t1);
  TSecP256K1Field.SquareN(t1, 6, t1);
  TSecP256K1Field.Multiply(t1, x2, t1);
  TSecP256K1Field.SquareN(t1, 2, t1);

  t2 := x2;
  TSecP256K1Field.Square(t1, t2);

  if TNat256.Eq(x1, t2) then
  begin
    result := TSecP256K1FieldElement.Create(t1);
  end
  else
  begin
    result := Nil;
  end;
end;

function TSecP256K1FieldElement.Square: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256K1Field.Square(Fx, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.Subtract(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256K1Field.Subtract(Fx, (b as ISecP256K1FieldElement).X, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.TestBitZero: Boolean;
begin
  result := TNat256.GetBit(Fx, 0) = 1;
end;

function TSecP256K1FieldElement.ToBigInteger: TBigInteger;
begin
  result := TNat256.ToBigInteger(Fx);
end;

function TSecP256K1FieldElement.Add(const b: IECFieldElement): IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256K1Field.Add(Fx, (b as ISecP256K1FieldElement).X, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.AddOne: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256K1Field.AddOne(Fx, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.Divide(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TMod.Invert(TSecP256K1Field.P, (b as ISecP256K1FieldElement).X, z);
  TSecP256K1Field.Multiply(z, Fx, z);
  result := TSecP256K1FieldElement.Create(z);
end;

function TSecP256K1FieldElement.Equals(const other
  : ISecP256K1FieldElement): Boolean;
begin
  if ((Self as ISecP256K1FieldElement) = other) then
  begin
    result := true;
    Exit;
  end;
  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;
  result := TNat256.Eq(Fx, other.X);
end;

function TSecP256K1FieldElement.Equals(const other: IECFieldElement): Boolean;
begin
  result := Equals(other as ISecP256K1FieldElement);
end;

end.
