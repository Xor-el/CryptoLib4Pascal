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

unit ClpSecP521R1Field;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpNat512,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  // 2^521 - 1
  TSecP521R1Field = class sealed(TObject)

  strict private
  const
    P16 = UInt32($1FF);

    class var

      FP: TCryptoLibUInt32Array;

    class function GetP: TCryptoLibUInt32Array; static; inline;

    class procedure ImplMultiply(const x, y, zz: TCryptoLibUInt32Array);
      static; inline;
    class procedure ImplSquare(const x, zz: TCryptoLibUInt32Array);
      static; inline;

    class constructor SecP521R1Field();

  public
    class procedure Add(const x, y, z: TCryptoLibUInt32Array); static; inline;
    class procedure AddOne(const x, z: TCryptoLibUInt32Array); static; inline;
    class function FromBigInteger(const x: TBigInteger): TCryptoLibUInt32Array;
      static; inline;
    class procedure Half(const x, z: TCryptoLibUInt32Array); static; inline;
    class procedure Multiply(const x, y, z: TCryptoLibUInt32Array);
      static; inline;
    class procedure Negate(const x, z: TCryptoLibUInt32Array); static; inline;
    class procedure Reduce(const xx, z: TCryptoLibUInt32Array); static; inline;
    class procedure Reduce23(const z: TCryptoLibUInt32Array); static; inline;
    class procedure Square(const x, z: TCryptoLibUInt32Array); static; inline;
    class procedure SquareN(const x: TCryptoLibUInt32Array; n: Int32;
      const z: TCryptoLibUInt32Array); static; inline;
    class procedure Subtract(const x, y, z: TCryptoLibUInt32Array);
      static; inline;
    class procedure Twice(const x, z: TCryptoLibUInt32Array); static; inline;

    class property P: TCryptoLibUInt32Array read GetP;
  end;

implementation

{ TSecP521R1Field }

class constructor TSecP521R1Field.SecP521R1Field;
begin
  FP := TCryptoLibUInt32Array.Create($FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $1FF);
end;

class function TSecP521R1Field.GetP: TCryptoLibUInt32Array;
begin
  result := FP;
end;

class procedure TSecP521R1Field.Add(const x, y, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Add(16, x, y, z) + x[16] + y[16];
  if ((c > P16) or ((c = P16) and (TNat.Eq(16, z, FP)))) then
  begin
    c := c + (TNat.Inc(16, z));
    c := c and P16;
  end;
  z[16] := c;
end;

class procedure TSecP521R1Field.AddOne(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Inc(16, x, z) + x[16];
  if ((c > P16) or ((c = P16) and (TNat.Eq(16, z, FP)))) then
  begin
    c := c + TNat.Inc(16, z);
    c := c and P16;
  end;
  z[16] := c;
end;

class function TSecP521R1Field.FromBigInteger(const x: TBigInteger)
  : TCryptoLibUInt32Array;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.FromBigInteger(521, x);
  if (TNat.Eq(17, z, FP)) then
  begin
    TNat.Zero(17, z);
  end;
  result := z;
end;

class procedure TSecP521R1Field.Half(const x, z: TCryptoLibUInt32Array);
var
  x16, c: UInt32;
begin
  x16 := x[16];
  c := TNat.ShiftDownBit(16, x, x16, z);
  z[16] := (x16 shr 1) or (c shr 23);
end;

class procedure TSecP521R1Field.ImplMultiply(const x, y,
  zz: TCryptoLibUInt32Array);
var
  x16, y16: UInt32;
begin
  TNat512.Mul(x, y, zz);
  x16 := x[16];
  y16 := y[16];
  zz[32] := TNat.Mul31BothAdd(16, x16, y, y16, x, zz, 16) + (x16 * y16);
end;

class procedure TSecP521R1Field.ImplSquare(const x, zz: TCryptoLibUInt32Array);
var
  x16: UInt32;
begin
  TNat512.Square(x, zz);
  x16 := x[16];
  zz[32] := TNat.MulWordAddTo(16, (x16 shl 1), x, 0, zz, 16) + (x16 * x16);
end;

class procedure TSecP521R1Field.Reduce23(const z: TCryptoLibUInt32Array);
var
  z16, c: UInt32;
begin
  z16 := z[16];
  c := TNat.AddWordTo(16, (z16 shr 9), z) + (z16 and P16);
  if ((c > P16) or ((c = P16) and (TNat.Eq(16, z, FP)))) then
  begin
    c := c + (TNat.Inc(16, z));
    c := c and P16;
  end;
  z[16] := c;
end;

class procedure TSecP521R1Field.Reduce(const xx, z: TCryptoLibUInt32Array);
var
  xx32, c: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((xx[32] shr 18) = 0);
{$ENDIF DEBUG}
  xx32 := xx[32];
  c := TNat.ShiftDownBits(16, xx, 16, 9, xx32, z, 0) shr 23;
  c := c + (xx32 shr 9);
  c := c + (TNat.AddTo(16, xx, z));
  if ((c > P16) or ((c = P16) and (TNat.Eq(16, z, FP)))) then
  begin
    c := c + (TNat.Inc(16, z));
    c := c and P16;
  end;
  z[16] := c;
end;

class procedure TSecP521R1Field.Multiply(const x, y, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat.Create(33);
  ImplMultiply(x, y, tt);
  Reduce(tt, z);
end;

class procedure TSecP521R1Field.Negate(const x, z: TCryptoLibUInt32Array);
begin
  if (TNat.IsZero(17, x)) then
  begin
    TNat.Zero(17, z);
  end
  else
  begin
    TNat.Sub(17, FP, x, z);
  end;
end;

class procedure TSecP521R1Field.Square(const x, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat.Create(33);
  ImplSquare(x, tt);
  Reduce(tt, z);
end;

class procedure TSecP521R1Field.SquareN(const x: TCryptoLibUInt32Array;
  n: Int32; const z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
{$IFDEF DEBUG}
  System.Assert(n > 0);
{$ENDIF DEBUG}
  tt := TNat.Create(33);
  ImplSquare(x, tt);
  Reduce(tt, z);

  System.Dec(n);
  while (n > 0) do
  begin
    ImplSquare(z, tt);
    Reduce(tt, z);
    System.Dec(n);
  end;
end;

class procedure TSecP521R1Field.Subtract(const x, y, z: TCryptoLibUInt32Array);
var
  c: Int32;
begin
  c := TNat.Sub(16, x, y, z) + Int32(x[16] - y[16]);
  if (c < 0) then
  begin
    c := c + TNat.Dec(16, z);
    c := c and P16;
  end;
  z[16] := UInt32(c);
end;

class procedure TSecP521R1Field.Twice(const x, z: TCryptoLibUInt32Array);
var
  x16, c: UInt32;
begin
  x16 := x[16];
  c := TNat.ShiftUpBit(16, x, x16 shl 23, z) or (x16 shl 1);
  z[16] := c and P16;
end;

end.
