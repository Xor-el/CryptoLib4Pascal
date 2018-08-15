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

unit ClpSecT283FieldElement;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpNat320,
  ClpECFieldElement,
  ClpIECFieldElement,
  ClpSecT283Field,
  ClpISecT283FieldElement,
  ClpBigInteger,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SInvalidValueForSecT283FieldElement =
    'Value Invalid for SecT283FieldElement "%s"';

type
  TSecT283FieldElement = class(TAbstractF2mFieldElement, ISecT283FieldElement)

  strict private

    function GetM: Int32; inline;

    function GetRepresentation: Int32; inline;

    function GetK1: Int32; inline;
    function GetK2: Int32; inline;
    function GetK3: Int32; inline;

    function Equals(const other: ISecT283FieldElement): Boolean;
      reintroduce; overload;

  strict protected
  var
    Fx: TCryptoLibUInt64Array;

    function GetFieldName: string; override;
    function GetFieldSize: Int32; override;
    function GetIsOne: Boolean; override;
    function GetIsZero: Boolean; override;

    function GetX: TCryptoLibUInt64Array; inline;
    property X: TCryptoLibUInt64Array read GetX;

  public
    constructor Create(); overload;
    constructor Create(const X: TBigInteger); overload;
    constructor Create(const X: TCryptoLibUInt64Array); overload;

    function TestBitZero: Boolean; override;
    function ToBigInteger(): TBigInteger; override;

    function Add(const b: IECFieldElement): IECFieldElement; override;
    function AddOne(): IECFieldElement; override;
    function Subtract(const b: IECFieldElement): IECFieldElement; override;

    function Multiply(const b: IECFieldElement): IECFieldElement; override;
    function MultiplyMinusProduct(const b, X, y: IECFieldElement)
      : IECFieldElement; override;
    function MultiplyPlusProduct(const b, X, y: IECFieldElement)
      : IECFieldElement; override;
    function Divide(const b: IECFieldElement): IECFieldElement; override;
    function Negate(): IECFieldElement; override;
    function Square(): IECFieldElement; override;
    function SquareMinusProduct(const X, y: IECFieldElement)
      : IECFieldElement; override;
    function SquarePlusProduct(const X, y: IECFieldElement)
      : IECFieldElement; override;

    function SquarePow(pow: Int32): IECFieldElement; override;

    function Trace(): Int32; override;

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

    property Representation: Int32 read GetRepresentation;

    property M: Int32 read GetM;

    property k1: Int32 read GetK1;

    property k2: Int32 read GetK2;

    property k3: Int32 read GetK3;

  end;

implementation

{ TSecT283FieldElement }

function TSecT283FieldElement.Add(const b: IECFieldElement): IECFieldElement;
var
  z: TCryptoLibUInt64Array;
begin
  z := TNat320.Create64();
  TSecT283Field.Add(Fx, (b as ISecT283FieldElement).X, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.AddOne: IECFieldElement;
var
  z: TCryptoLibUInt64Array;
begin
  z := TNat320.Create64();
  TSecT283Field.AddOne(Fx, z);
  result := TSecT283FieldElement.Create(z);
end;

constructor TSecT283FieldElement.Create(const X: TBigInteger);
begin
  if ((not(X.IsInitialized)) or (X.SignValue < 0) or (X.BitLength > 283)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SInvalidValueForSecT283FieldElement, ['x']);
  end;
  Inherited Create();
  Fx := TSecT283Field.FromBigInteger(X);
end;

constructor TSecT283FieldElement.Create;
begin
  Inherited Create();
  Fx := TNat320.Create64();
end;

constructor TSecT283FieldElement.Create(const X: TCryptoLibUInt64Array);
begin
  Inherited Create();
  Fx := X;
end;

function TSecT283FieldElement.Divide(const b: IECFieldElement): IECFieldElement;
begin
  result := Multiply(b.Invert());
end;

function TSecT283FieldElement.Equals(const other: ISecT283FieldElement)
  : Boolean;
begin
  if ((Self as ISecT283FieldElement) = other) then
  begin
    result := true;
    Exit;
  end;
  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;
  result := TNat320.Eq64(Fx, other.X);
end;

function TSecT283FieldElement.Equals(const other: IECFieldElement): Boolean;
begin
  result := Equals(other as ISecT283FieldElement);
end;

function TSecT283FieldElement.GetFieldName: string;
begin
  result := 'SecT283Field';
end;

function TSecT283FieldElement.GetFieldSize: Int32;
begin
  result := 283;
end;

function TSecT283FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := 2831275 xor TArrayUtils.GetArrayHashCode(Fx, 0, 5);
end;

function TSecT283FieldElement.GetIsOne: Boolean;
begin
  result := TNat320.IsOne64(Fx);
end;

function TSecT283FieldElement.GetIsZero: Boolean;
begin
  result := TNat320.IsZero64(Fx);
end;

function TSecT283FieldElement.GetK1: Int32;
begin
  result := 5;
end;

function TSecT283FieldElement.GetK2: Int32;
begin
  result := 7;
end;

function TSecT283FieldElement.GetK3: Int32;
begin
  result := 12;
end;

function TSecT283FieldElement.GetM: Int32;
begin
  result := 283;
end;

function TSecT283FieldElement.GetRepresentation: Int32;
begin
  result := TF2mFieldElement.Ppb;
end;

function TSecT283FieldElement.GetX: TCryptoLibUInt64Array;
begin
  result := Fx;
end;

function TSecT283FieldElement.Invert: IECFieldElement;
var
  z: TCryptoLibUInt64Array;
begin
  z := TNat320.Create64();
  TSecT283Field.Invert(Fx, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.Multiply(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt64Array;
begin
  z := TNat320.Create64();
  TSecT283Field.Multiply(Fx, (b as ISecT283FieldElement).X, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.MultiplyMinusProduct(const b, X,
  y: IECFieldElement): IECFieldElement;
begin
  result := MultiplyPlusProduct(b, X, y);
end;

function TSecT283FieldElement.MultiplyPlusProduct(const b, X,
  y: IECFieldElement): IECFieldElement;
var
  ax, bx, xx, yx, tt, z: TCryptoLibUInt64Array;
begin
  ax := Fx;
  bx := (b as ISecT283FieldElement).X;
  xx := (X as ISecT283FieldElement).X;
  yx := (y as ISecT283FieldElement).X;

  tt := TNat.Create64(9);
  TSecT283Field.MultiplyAddToExt(ax, bx, tt);
  TSecT283Field.MultiplyAddToExt(xx, yx, tt);

  z := TNat320.Create64();
  TSecT283Field.Reduce(tt, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.Negate: IECFieldElement;
begin
  result := Self as IECFieldElement;
end;

function TSecT283FieldElement.Sqrt: IECFieldElement;
var
  z: TCryptoLibUInt64Array;
begin
  z := TNat320.Create64();
  TSecT283Field.Sqrt(Fx, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.Square: IECFieldElement;
var
  z: TCryptoLibUInt64Array;
begin
  z := TNat320.Create64();
  TSecT283Field.Square(Fx, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.SquareMinusProduct(const X, y: IECFieldElement)
  : IECFieldElement;
begin
  result := SquarePlusProduct(X, y);
end;

function TSecT283FieldElement.SquarePlusProduct(const X, y: IECFieldElement)
  : IECFieldElement;
var
  ax, xx, yx, tt, z: TCryptoLibUInt64Array;
begin
  ax := Fx;
  xx := (X as ISecT283FieldElement).X;
  yx := (y as ISecT283FieldElement).X;

  tt := TNat.Create64(9);
  TSecT283Field.SquareAddToExt(ax, tt);
  TSecT283Field.MultiplyAddToExt(xx, yx, tt);

  z := TNat320.Create64();
  TSecT283Field.Reduce(tt, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.SquarePow(pow: Int32): IECFieldElement;
var
  z: TCryptoLibUInt64Array;
begin
  if (pow < 1) then
  begin
    result := Self as IECFieldElement;
    Exit;
  end;

  z := TNat320.Create64();
  TSecT283Field.SquareN(Fx, pow, z);
  result := TSecT283FieldElement.Create(z);
end;

function TSecT283FieldElement.Subtract(const b: IECFieldElement)
  : IECFieldElement;
begin
  // Addition and subtraction are the same in F2m
  result := Add(b);
end;

function TSecT283FieldElement.TestBitZero: Boolean;
begin
  result := (Fx[0] and UInt64(1)) <> UInt64(0);
end;

function TSecT283FieldElement.ToBigInteger: TBigInteger;
begin
  result := TNat320.ToBigInteger64(Fx);
end;

function TSecT283FieldElement.Trace: Int32;
begin
  result := Int32(TSecT283Field.Trace(Fx));
end;

end.
