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

unit ClpSecP384R1FieldElement;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpMod,
  ClpSecP384R1Curve,
  ClpECFieldElement,
  ClpIECFieldElement,
  ClpSecP384R1Field,
  ClpISecP384R1FieldElement,
  ClpBigInteger,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SInvalidValueForSecP384R1FieldElement =
    'Value Invalid for SecP384R1FieldElement "%s"';

type
  TSecP384R1FieldElement = class(TAbstractFpFieldElement,
    ISecP384R1FieldElement)

  strict private

    function Equals(const other: ISecP384R1FieldElement): Boolean;
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

{ TSecP384R1FieldElement }

class function TSecP384R1FieldElement.GetQ: TBigInteger;
begin
  result := TSecP384R1Curve.SecP384R1Curve_Q;
end;

function TSecP384R1FieldElement.GetX: TCryptoLibUInt32Array;
begin
  result := Fx;
end;

constructor TSecP384R1FieldElement.Create;
begin
  Inherited Create();
  Fx := TNat.Create(12);
end;

constructor TSecP384R1FieldElement.Create(const X: TBigInteger);
begin
  if ((not(X.IsInitialized)) or (X.SignValue < 0) or (X.CompareTo(Q) >= 0)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SInvalidValueForSecP384R1FieldElement, ['x']);
  end;
  Inherited Create();
  Fx := TSecP384R1Field.FromBigInteger(X);
end;

constructor TSecP384R1FieldElement.Create(const X: TCryptoLibUInt32Array);
begin
  Inherited Create();
  Fx := X;
end;

function TSecP384R1FieldElement.GetFieldName: string;
begin
  result := 'SecP384R1Field';
end;

function TSecP384R1FieldElement.GetFieldSize: Int32;
begin
  result := Q.BitLength;
end;

function TSecP384R1FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := Q.GetHashCode() xor TArrayUtils.GetArrayHashCode(Fx, 0, 12);
end;

function TSecP384R1FieldElement.GetIsOne: Boolean;
begin
  result := TNat.IsOne(12, Fx);
end;

function TSecP384R1FieldElement.GetIsZero: Boolean;
begin
  result := TNat.IsZero(12, Fx);
end;

function TSecP384R1FieldElement.Sqrt: IECFieldElement;
var
  x1, t1, t2, t3, t4, r: TCryptoLibUInt32Array;
begin
  // Raise this element to the exponent 2^382 - 2^126 - 2^94 + 2^30
  x1 := Fx;
  if ((TNat.IsZero(12, x1)) or (TNat.IsOne(12, x1))) then
  begin
    result := Self as IECFieldElement;
    Exit;
  end;

  t1 := TNat.Create(12);
  t2 := TNat.Create(12);
  t3 := TNat.Create(12);
  t4 := TNat.Create(12);

  TSecP384R1Field.Square(x1, t1);
  TSecP384R1Field.Multiply(t1, x1, t1);

  TSecP384R1Field.SquareN(t1, 2, t2);
  TSecP384R1Field.Multiply(t2, t1, t2);

  TSecP384R1Field.Square(t2, t2);
  TSecP384R1Field.Multiply(t2, x1, t2);

  TSecP384R1Field.SquareN(t2, 5, t3);
  TSecP384R1Field.Multiply(t3, t2, t3);

  TSecP384R1Field.SquareN(t3, 5, t4);
  TSecP384R1Field.Multiply(t4, t2, t4);

  TSecP384R1Field.SquareN(t4, 15, t2);
  TSecP384R1Field.Multiply(t2, t4, t2);

  TSecP384R1Field.SquareN(t2, 2, t3);
  TSecP384R1Field.Multiply(t1, t3, t1);

  TSecP384R1Field.SquareN(t3, 28, t3);
  TSecP384R1Field.Multiply(t2, t3, t2);

  TSecP384R1Field.SquareN(t2, 60, t3);
  TSecP384R1Field.Multiply(t3, t2, t3);

  r := t2;

  TSecP384R1Field.SquareN(t3, 120, r);
  TSecP384R1Field.Multiply(r, t3, r);

  TSecP384R1Field.SquareN(r, 15, r);
  TSecP384R1Field.Multiply(r, t4, r);

  TSecP384R1Field.SquareN(r, 33, r);
  TSecP384R1Field.Multiply(r, t1, r);

  TSecP384R1Field.SquareN(r, 64, r);
  TSecP384R1Field.Multiply(r, x1, r);

  TSecP384R1Field.SquareN(r, 30, t1);
  TSecP384R1Field.Square(t1, t2);

  if TNat.Eq(12, x1, t2) then
  begin
    result := TSecP384R1FieldElement.Create(t1);
  end
  else
  begin
    result := Nil;
  end;
end;

function TSecP384R1FieldElement.TestBitZero: Boolean;
begin
  result := TNat.GetBit(Fx, 0) = 1;
end;

function TSecP384R1FieldElement.ToBigInteger: TBigInteger;
begin
  result := TNat.ToBigInteger(12, Fx);
end;

function TSecP384R1FieldElement.Add(const b: IECFieldElement): IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TSecP384R1Field.Add(Fx, (b as ISecP384R1FieldElement).X, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.AddOne: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TSecP384R1Field.AddOne(Fx, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.Subtract(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TSecP384R1Field.Subtract(Fx, (b as ISecP384R1FieldElement).X, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.Multiply(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TSecP384R1Field.Multiply(Fx, (b as ISecP384R1FieldElement).X, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.Divide(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TMod.Invert(TSecP384R1Field.P, (b as ISecP384R1FieldElement).X, z);
  TSecP384R1Field.Multiply(z, Fx, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.Negate: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TSecP384R1Field.Negate(Fx, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.Square: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TSecP384R1Field.Square(Fx, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.Invert: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(12);
  TMod.Invert(TSecP384R1Field.P, Fx, z);
  result := TSecP384R1FieldElement.Create(z);
end;

function TSecP384R1FieldElement.Equals(const other
  : ISecP384R1FieldElement): Boolean;
begin
  if ((Self as ISecP384R1FieldElement) = other) then
  begin
    result := true;
    Exit;
  end;
  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;
  result := TNat.Eq(12, Fx, other.X);
end;

function TSecP384R1FieldElement.Equals(const other: IECFieldElement): Boolean;
begin
  result := Equals(other as ISecP384R1FieldElement);
end;

end.
