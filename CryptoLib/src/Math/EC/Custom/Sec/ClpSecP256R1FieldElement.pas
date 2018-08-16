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

unit ClpSecP256R1FieldElement;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat256,
  ClpMod,
  ClpSecP256R1Curve,
  ClpECFieldElement,
  ClpIECFieldElement,
  ClpSecP256R1Field,
  ClpISecP256R1FieldElement,
  ClpBigInteger,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SInvalidValueForSecP256R1FieldElement =
    'Value Invalid for SecP256R1FieldElement "%s"';

type
  TSecP256R1FieldElement = class(TAbstractFpFieldElement,
    ISecP256R1FieldElement)

  strict private

    function Equals(const other: ISecP256R1FieldElement): Boolean;
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

{ TSecP256R1FieldElement }

class function TSecP256R1FieldElement.GetQ: TBigInteger;
begin
  result := TSecP256R1Curve.SecP256R1Curve_Q;
end;

function TSecP256R1FieldElement.GetX: TCryptoLibUInt32Array;
begin
  result := Fx;
end;

constructor TSecP256R1FieldElement.Create;
begin
  Inherited Create();
  Fx := TNat256.Create();
end;

constructor TSecP256R1FieldElement.Create(const X: TBigInteger);
begin
  if ((not(X.IsInitialized)) or (X.SignValue < 0) or (X.CompareTo(Q) >= 0)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SInvalidValueForSecP256R1FieldElement, ['x']);
  end;
  Inherited Create();
  Fx := TSecP256R1Field.FromBigInteger(X);
end;

constructor TSecP256R1FieldElement.Create(const X: TCryptoLibUInt32Array);
begin
  Inherited Create();
  Fx := X;
end;

function TSecP256R1FieldElement.GetFieldName: string;
begin
  result := 'SecP256R1Field';
end;

function TSecP256R1FieldElement.GetFieldSize: Int32;
begin
  result := Q.BitLength;
end;

function TSecP256R1FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := Q.GetHashCode() xor TArrayUtils.GetArrayHashCode(Fx, 0, 8);
end;

function TSecP256R1FieldElement.GetIsOne: Boolean;
begin
  result := TNat256.IsOne(Fx);
end;

function TSecP256R1FieldElement.GetIsZero: Boolean;
begin
  result := TNat256.IsZero(Fx);
end;

function TSecP256R1FieldElement.Invert: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TMod.Invert(TSecP256R1Field.P, Fx, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.Multiply(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256R1Field.Multiply(Fx, (b as ISecP256R1FieldElement).X, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.Negate: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256R1Field.Negate(Fx, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.Sqrt: IECFieldElement;
var
  x1, t1, t2: TCryptoLibUInt32Array;
begin
  // Raise this element to the exponent 2^254 - 2^222 + 2^190 + 2^94

  x1 := Fx;
  if ((TNat256.IsZero(x1)) or (TNat256.IsOne(x1))) then
  begin
    result := Self as IECFieldElement;
    Exit;
  end;

  t1 := TNat256.Create();
  t2 := TNat256.Create();

  TSecP256R1Field.Square(x1, t1);
  TSecP256R1Field.Multiply(t1, x1, t1);

  TSecP256R1Field.SquareN(t1, 2, t2);
  TSecP256R1Field.Multiply(t2, t1, t2);

  TSecP256R1Field.SquareN(t2, 4, t1);
  TSecP256R1Field.Multiply(t1, t2, t1);

  TSecP256R1Field.SquareN(t1, 8, t2);
  TSecP256R1Field.Multiply(t2, t1, t2);

  TSecP256R1Field.SquareN(t2, 16, t1);
  TSecP256R1Field.Multiply(t1, t2, t1);

  TSecP256R1Field.SquareN(t1, 32, t1);
  TSecP256R1Field.Multiply(t1, x1, t1);

  TSecP256R1Field.SquareN(t1, 96, t1);
  TSecP256R1Field.Multiply(t1, x1, t1);

  TSecP256R1Field.SquareN(t1, 94, t1);
  TSecP256R1Field.Multiply(t1, t1, t2);

  if TNat256.Eq(x1, t2) then
  begin
    result := TSecP256R1FieldElement.Create(t1);
  end
  else
  begin
    result := Nil;
  end;
end;

function TSecP256R1FieldElement.Square: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256R1Field.Square(Fx, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.Subtract(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256R1Field.Subtract(Fx, (b as ISecP256R1FieldElement).X, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.TestBitZero: Boolean;
begin
  result := TNat256.GetBit(Fx, 0) = 1;
end;

function TSecP256R1FieldElement.ToBigInteger: TBigInteger;
begin
  result := TNat256.ToBigInteger(Fx);
end;

function TSecP256R1FieldElement.Add(const b: IECFieldElement): IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256R1Field.Add(Fx, (b as ISecP256R1FieldElement).X, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.AddOne: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TSecP256R1Field.AddOne(Fx, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.Divide(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.Create();
  TMod.Invert(TSecP256R1Field.P, (b as ISecP256R1FieldElement).X, z);
  TSecP256R1Field.Multiply(z, Fx, z);
  result := TSecP256R1FieldElement.Create(z);
end;

function TSecP256R1FieldElement.Equals(const other
  : ISecP256R1FieldElement): Boolean;
begin
  if ((Self as ISecP256R1FieldElement) = other) then
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

function TSecP256R1FieldElement.Equals(const other: IECFieldElement): Boolean;
begin
  result := Equals(other as ISecP256R1FieldElement);
end;

end.
