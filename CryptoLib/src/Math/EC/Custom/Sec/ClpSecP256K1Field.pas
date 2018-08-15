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

unit ClpSecP256K1Field;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpNat256,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  // 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
  TSecP256K1Field = class sealed(TObject)

  strict private
  const
    P7 = UInt32($FFFFFFFF);
    PExt15 = UInt32($FFFFFFFF);
    PInv33 = UInt32($3D1);

    class var

      FP, FPExt, FPExtInv: TCryptoLibUInt32Array;

    class function GetP: TCryptoLibUInt32Array; static; inline;

    class constructor SecP256K1Field();

  public
    class procedure Add(const x, y, z: TCryptoLibUInt32Array); static; inline;
    class procedure AddExt(const xx, yy, zz: TCryptoLibUInt32Array);
      static; inline;
    class procedure AddOne(const x, z: TCryptoLibUInt32Array); static; inline;
    class function FromBigInteger(const x: TBigInteger): TCryptoLibUInt32Array;
      static; inline;
    class procedure Half(const x, z: TCryptoLibUInt32Array); static; inline;
    class procedure Multiply(const x, y, z: TCryptoLibUInt32Array);
      static; inline;
    class procedure MultiplyAddToExt(const x, y, zz: TCryptoLibUInt32Array);
      static; inline;
    class procedure Negate(const x, z: TCryptoLibUInt32Array); static; inline;
    class procedure Reduce(const xx, z: TCryptoLibUInt32Array); static; inline;
    class procedure Reduce32(x: UInt32; const z: TCryptoLibUInt32Array);
      static; inline;
    class procedure Square(const x, z: TCryptoLibUInt32Array); static; inline;
    class procedure SquareN(const x: TCryptoLibUInt32Array; n: Int32;
      const z: TCryptoLibUInt32Array); static; inline;
    class procedure Subtract(const x, y, z: TCryptoLibUInt32Array);
      static; inline;
    class procedure SubtractExt(const xx, yy, zz: TCryptoLibUInt32Array);
      static; inline;
    class procedure Twice(const x, z: TCryptoLibUInt32Array); static; inline;

    class property P: TCryptoLibUInt32Array read GetP;
  end;

implementation

{ TSecP256K1Field }

class constructor TSecP256K1Field.SecP256K1Field;
begin
  FP := TCryptoLibUInt32Array.Create($FFFFFC2F, $FFFFFFFE, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
  FPExt := TCryptoLibUInt32Array.Create($000E90A1, $000007A2, $00000001,
    $00000000, $00000000, $00000000, $00000000, $00000000, $FFFFF85E, $FFFFFFFD,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF);
  FPExtInv := TCryptoLibUInt32Array.Create($FFF16F5F, $FFFFF85D, $FFFFFFFE,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $000007A1,
    $00000002);
end;

class function TSecP256K1Field.GetP: TCryptoLibUInt32Array;
begin
  result := FP;
end;

class procedure TSecP256K1Field.Add(const x, y, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat256.Add(x, y, z);
  if ((c <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    TNat.Add33To(8, PInv33, z);
  end;
end;

class procedure TSecP256K1Field.AddExt(const xx, yy, zz: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Add(16, xx, yy, zz);
  if ((c <> 0) or ((zz[15] = PExt15) and (TNat.Gte(16, zz, FPExt)))) then
  begin
    if (TNat.AddTo(System.Length(FPExtInv), FPExtInv, zz) <> 0) then
    begin
      TNat.IncAt(16, zz, System.Length(FPExtInv));
    end;
  end;
end;

class procedure TSecP256K1Field.AddOne(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Inc(8, x, z);
  if ((c <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    TNat.Add33To(8, PInv33, z);
  end;
end;

class function TSecP256K1Field.FromBigInteger(const x: TBigInteger)
  : TCryptoLibUInt32Array;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat256.FromBigInteger(x);
  if ((z[7] = P7) and (TNat256.Gte(z, FP))) then
  begin
    TNat256.SubFrom(FP, z);
  end;
  result := z;
end;

class procedure TSecP256K1Field.Half(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  if ((x[0] and 1) = 0) then
  begin
    TNat.ShiftDownBit(8, x, 0, z);
  end
  else
  begin
    c := TNat256.Add(x, FP, z);
    TNat.ShiftDownBit(8, z, c);
  end;
end;

class procedure TSecP256K1Field.Reduce(const xx, z: TCryptoLibUInt32Array);
var
  cc: UInt64;
  c: UInt32;
begin
  cc := TNat256.Mul33Add(PInv33, xx, 8, xx, 0, z, 0);
  c := TNat256.Mul33DWordAdd(PInv33, cc, z, 0);
{$IFDEF DEBUG}
  System.Assert((c = 0) or (c = 1));
{$ENDIF DEBUG}
  if ((c <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    TNat.Add33To(8, PInv33, z);
  end;
end;

class procedure TSecP256K1Field.Multiply(const x, y, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat256.CreateExt();
  TNat256.Mul(x, y, tt);
  Reduce(tt, z);
end;

class procedure TSecP256K1Field.MultiplyAddToExt(const x, y,
  zz: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat256.MulAddTo(x, y, zz);
  if ((c <> 0) or ((zz[15] = PExt15) and (TNat.Gte(16, zz, FPExt)))) then
  begin
    if (TNat.AddTo(System.Length(FPExtInv), FPExtInv, zz) <> 0) then
    begin
      TNat.IncAt(16, zz, System.Length(FPExtInv));
    end;
  end;
end;

class procedure TSecP256K1Field.Negate(const x, z: TCryptoLibUInt32Array);
begin
  if (TNat256.IsZero(x)) then
  begin
    TNat256.Zero(z);
  end
  else
  begin
    TNat256.Sub(FP, x, z);
  end;
end;

class procedure TSecP256K1Field.Reduce32(x: UInt32;
  const z: TCryptoLibUInt32Array);
begin
  if (((x <> 0) and (TNat256.Mul33WordAdd(PInv33, x, z, 0) <> 0)) or
    ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    TNat.Add33To(8, PInv33, z);
  end;
end;

class procedure TSecP256K1Field.Square(const x, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat256.CreateExt();
  TNat256.Square(x, tt);
  Reduce(tt, z);
end;

class procedure TSecP256K1Field.SquareN(const x: TCryptoLibUInt32Array;
  n: Int32; const z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
{$IFDEF DEBUG}
  System.Assert(n > 0);
{$ENDIF DEBUG}
  tt := TNat256.CreateExt();
  TNat256.Square(x, tt);
  Reduce(tt, z);

  System.Dec(n);
  while (n > 0) do
  begin
    TNat256.Square(z, tt);
    Reduce(tt, z);
    System.Dec(n);
  end;
end;

class procedure TSecP256K1Field.Subtract(const x, y, z: TCryptoLibUInt32Array);
var
  c: Int32;
begin
  c := TNat256.Sub(x, y, z);
  if (c <> 0) then
  begin
    TNat.Sub33From(8, PInv33, z);
  end;
end;

class procedure TSecP256K1Field.SubtractExt(const xx, yy,
  zz: TCryptoLibUInt32Array);
var
  c: Int32;
begin
  c := TNat.Sub(16, xx, yy, zz);
  if (c <> 0) then
  begin
    if (TNat.SubFrom(System.Length(FPExtInv), FPExtInv, zz) <> 0) then
    begin
      TNat.DecAt(16, zz, System.Length(FPExtInv));
    end;
  end;
end;

class procedure TSecP256K1Field.Twice(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.ShiftUpBit(8, x, 0, z);
  if ((c <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    TNat.Add33To(8, PInv33, z);
  end;
end;

end.
