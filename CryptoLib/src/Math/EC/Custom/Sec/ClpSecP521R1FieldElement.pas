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

unit ClpSecP521R1FieldElement;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpMod,
  ClpSecP521R1Curve,
  ClpECFieldElement,
  ClpIECFieldElement,
  ClpSecP521R1Field,
  ClpISecP521R1FieldElement,
  ClpBigInteger,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SInvalidValueForSecP521R1FieldElement =
    'Value Invalid for SecP521R1FieldElement "%s"';

type
  TSecP521R1FieldElement = class(TAbstractFpFieldElement,
    ISecP521R1FieldElement)

  strict private

    function Equals(const other: ISecP521R1FieldElement): Boolean;
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

{ TSecP521R1FieldElement }

class function TSecP521R1FieldElement.GetQ: TBigInteger;
begin
  result := TSecP521R1Curve.SecP521R1Curve_Q;
end;

function TSecP521R1FieldElement.GetX: TCryptoLibUInt32Array;
begin
  result := Fx;
end;

constructor TSecP521R1FieldElement.Create;
begin
  Inherited Create();
  Fx := TNat.Create(17);
end;

constructor TSecP521R1FieldElement.Create(const X: TBigInteger);
begin
  if ((not(X.IsInitialized)) or (X.SignValue < 0) or (X.CompareTo(Q) >= 0)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt
      (@SInvalidValueForSecP521R1FieldElement, ['x']);
  end;
  Inherited Create();
  Fx := TSecP521R1Field.FromBigInteger(X);
end;

constructor TSecP521R1FieldElement.Create(const X: TCryptoLibUInt32Array);
begin
  Inherited Create();
  Fx := X;
end;

function TSecP521R1FieldElement.GetFieldName: string;
begin
  result := 'SecP521R1Field';
end;

function TSecP521R1FieldElement.GetFieldSize: Int32;
begin
  result := Q.BitLength;
end;

function TSecP521R1FieldElement.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt;
{$ENDIF DELPHI}
begin
  result := Q.GetHashCode() xor TArrayUtils.GetArrayHashCode(Fx, 0, 17);
end;

function TSecP521R1FieldElement.GetIsOne: Boolean;
begin
  result := TNat.IsOne(17, Fx);
end;

function TSecP521R1FieldElement.GetIsZero: Boolean;
begin
  result := TNat.IsZero(17, Fx);
end;

function TSecP521R1FieldElement.Sqrt: IECFieldElement;
var
  x1, t1, t2: TCryptoLibUInt32Array;
begin
  // Raise this element to the exponent 2^519
  x1 := Fx;
  if ((TNat.IsZero(17, x1)) or (TNat.IsOne(17, x1))) then
  begin
    result := Self as IECFieldElement;
    Exit;
  end;

  t1 := TNat.Create(17);
  t2 := TNat.Create(17);

  TSecP521R1Field.SquareN(x1, 519, t1);
  TSecP521R1Field.Square(t1, t2);

  if TNat.Eq(17, x1, t2) then
  begin
    result := TSecP521R1FieldElement.Create(t1);
  end
  else
  begin
    result := Nil;
  end;
end;

function TSecP521R1FieldElement.TestBitZero: Boolean;
begin
  result := TNat.GetBit(Fx, 0) = 1;
end;

function TSecP521R1FieldElement.ToBigInteger: TBigInteger;
begin
  result := TNat.ToBigInteger(17, Fx);
end;

function TSecP521R1FieldElement.Add(const b: IECFieldElement): IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TSecP521R1Field.Add(Fx, (b as ISecP521R1FieldElement).X, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.AddOne: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TSecP521R1Field.AddOne(Fx, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.Subtract(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TSecP521R1Field.Subtract(Fx, (b as ISecP521R1FieldElement).X, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.Multiply(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TSecP521R1Field.Multiply(Fx, (b as ISecP521R1FieldElement).X, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.Divide(const b: IECFieldElement)
  : IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TMod.Invert(TSecP521R1Field.P, (b as ISecP521R1FieldElement).X, z);
  TSecP521R1Field.Multiply(z, Fx, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.Negate: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TSecP521R1Field.Negate(Fx, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.Square: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TSecP521R1Field.Square(Fx, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.Invert: IECFieldElement;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.Create(17);
  TMod.Invert(TSecP521R1Field.P, Fx, z);
  result := TSecP521R1FieldElement.Create(z);
end;

function TSecP521R1FieldElement.Equals(const other
  : ISecP521R1FieldElement): Boolean;
begin
  if ((Self as ISecP521R1FieldElement) = other) then
  begin
    result := true;
    Exit;
  end;
  if (other = Nil) then
  begin
    result := false;
    Exit;
  end;
  result := TNat.Eq(17, Fx, other.X);
end;

function TSecP521R1FieldElement.Equals(const other: IECFieldElement): Boolean;
begin
  result := Equals(other as ISecP521R1FieldElement);
end;

end.
