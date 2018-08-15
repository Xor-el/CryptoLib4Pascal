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

unit ClpSecP384R1Field;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpNat384,
  ClpBits,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  // 2^384 - 2^128 - 2^96 + 2^32 - 1
  TSecP384R1Field = class sealed(TObject)

  strict private
  const
    P11 = UInt32($FFFFFFFF);
    PExt23 = UInt32($FFFFFFFF);

    class var

      FP, FPExt, FPExtInv: TCryptoLibUInt32Array;

    class function GetP: TCryptoLibUInt32Array; static; inline;

    class procedure AddPInvTo(const z: TCryptoLibUInt32Array); static;
    class procedure SubPInvFrom(const z: TCryptoLibUInt32Array); static;

    class constructor SecP384R1Field();

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
    class procedure Negate(const x, z: TCryptoLibUInt32Array); static; inline;
    class procedure Reduce(const xx, z: TCryptoLibUInt32Array); static;
    class procedure Reduce32(x: UInt32; const z: TCryptoLibUInt32Array); static;
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

{ TSecP384R1Field }

class constructor TSecP384R1Field.SecP384R1Field;
begin
  FP := TCryptoLibUInt32Array.Create($FFFFFFFF, $00000000, $00000000, $FFFFFFFF,
    $FFFFFFFE, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF);
  FPExt := TCryptoLibUInt32Array.Create($00000001, $FFFFFFFE, $00000000,
    $00000002, $00000000, $FFFFFFFE, $00000000, $00000002, $00000001, $00000000,
    $00000000, $00000000, $FFFFFFFE, $00000001, $00000000, $FFFFFFFE, $FFFFFFFD,
    $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $FFFFFFFF,
    $FFFFFFFF);
  FPExtInv := TCryptoLibUInt32Array.Create($FFFFFFFF, $00000001, $FFFFFFFF,
    $FFFFFFFD, $FFFFFFFF, $00000001, $FFFFFFFF, $FFFFFFFD, $FFFFFFFE, $FFFFFFFF,
    $FFFFFFFF, $FFFFFFFF, $00000001, $FFFFFFFE, $FFFFFFFF, $00000001,
    $00000002);
end;

class function TSecP384R1Field.GetP: TCryptoLibUInt32Array;
begin
  result := FP;
end;

class procedure TSecP384R1Field.AddPInvTo(const z: TCryptoLibUInt32Array);
var
  c: Int64;
begin
  c := Int64(z[0]) + 1;
  z[0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[1]) - 1);
  z[1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    c := c + Int64(z[2]);
    z[2] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  c := c + (Int64(z[3]) + 1);
  z[3] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[4]) + 1);
  z[4] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    TNat.IncAt(12, z, 5);
  end;
end;

class procedure TSecP384R1Field.SubPInvFrom(const z: TCryptoLibUInt32Array);
var
  c: Int64;
begin
  c := Int64(z[0]) - 1;
  z[0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[1]) + 1);
  z[1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    c := c + Int64(z[2]);
    z[2] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  c := c + (Int64(z[3]) - 1);
  z[3] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[4]) - 1);
  z[4] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    TNat.DecAt(12, z, 5);
  end;
end;

class procedure TSecP384R1Field.Add(const x, y, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Add(12, x, y, z);
  if ((c <> 0) or ((z[11] = P11) and (TNat.Gte(12, z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

class procedure TSecP384R1Field.AddExt(const xx, yy, zz: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Add(24, xx, yy, zz);
  if ((c <> 0) or ((zz[23] = PExt23) and (TNat.Gte(24, zz, FPExt)))) then
  begin
    if (TNat.AddTo(System.Length(FPExtInv), FPExtInv, zz) <> 0) then
    begin
      TNat.IncAt(24, zz, System.Length(FPExtInv));
    end;
  end;
end;

class procedure TSecP384R1Field.AddOne(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Inc(12, x, z);
  if ((c <> 0) or ((z[11] = P11) and (TNat.Gte(12, z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

class function TSecP384R1Field.FromBigInteger(const x: TBigInteger)
  : TCryptoLibUInt32Array;
var
  z: TCryptoLibUInt32Array;
begin
  z := TNat.FromBigInteger(384, x);
  if ((z[11] = P11) and (TNat.Gte(12, z, FP))) then
  begin
    TNat.SubFrom(12, FP, z);
  end;
  result := z;
end;

class procedure TSecP384R1Field.Half(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  if ((x[0] and 1) = 0) then
  begin
    TNat.ShiftDownBit(12, x, 0, z);
  end
  else
  begin
    c := TNat.Add(12, x, FP, z);
    TNat.ShiftDownBit(12, z, c);
  end;
end;

class procedure TSecP384R1Field.Reduce32(x: UInt32;
  const z: TCryptoLibUInt32Array);
var
  cc, xx12: Int64;
begin
  cc := 0;

  if (x <> 0) then
  begin
    xx12 := x;

    cc := cc + (Int64(z[0]) + xx12);
    z[0] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);
    cc := cc + (Int64(z[1]) - xx12);
    z[1] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);
    if (cc <> 0) then
    begin
      cc := cc + Int64(z[2]);
      z[2] := UInt32(cc);
      cc := TBits.Asr64(cc, 32);
    end;
    cc := cc + (Int64(z[3]) + xx12);
    z[3] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);
    cc := cc + (Int64(z[4]) + xx12);
    z[4] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);

{$IFDEF DEBUG}
    System.Assert((cc = 0) or (cc = 1));
{$ENDIF DEBUG}
  end;

  if (((cc <> 0) and (TNat.IncAt(12, z, 5) <> 0)) or
    ((z[11] = P11) and (TNat.Gte(12, z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

class procedure TSecP384R1Field.Reduce(const xx, z: TCryptoLibUInt32Array);
const
  n: Int64 = 1;
var
  cc, xx16, xx17, xx18, xx19, xx20, xx21, xx22, xx23, t0, t1, t2, t3, t4, t5,
    t6, t7: Int64;

begin
  xx16 := xx[16];
  xx17 := xx[17];
  xx18 := xx[18];
  xx19 := xx[19];
  xx20 := xx[20];
  xx21 := xx[21];
  xx22 := xx[22];
  xx23 := xx[23];

  t0 := Int64(xx[12]) + xx20 - n;
  t1 := Int64(xx[13]) + xx22;
  t2 := Int64(xx[14]) + xx22 + xx23;
  t3 := Int64(xx[15]) + xx23;
  t4 := xx17 + xx21;
  t5 := xx21 - xx23;
  t6 := xx22 - xx23;
  t7 := t0 + t5;

  cc := 0;
  cc := cc + (Int64(xx[0]) + t7);
  z[0] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[1]) + xx23 - t0 + t1);
  z[1] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[2]) - xx21 - t1 + t2);
  z[2] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[3]) - t2 + t3 + t7);
  z[3] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[4]) + xx16 + xx21 + t1 - t3 + t7);
  z[4] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[5]) - xx16 + t1 + t2 + t4);
  z[5] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[6]) + xx18 - xx17 + t2 + t3);
  z[6] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[7]) + xx16 + xx19 - xx18 + t3);
  z[7] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[8]) + xx16 + xx17 + xx20 - xx19);
  z[8] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[9]) + xx18 - xx20 + t4);
  z[9] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[10]) + xx18 + xx19 - t5 + t6);
  z[10] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[11]) + xx19 + xx20 - t6);
  z[11] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (n);

{$IFDEF DEBUG}
  System.Assert(cc >= 0);
{$ENDIF DEBUG}
  Reduce32(UInt32(cc), z);
end;

class procedure TSecP384R1Field.Multiply(const x, y, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat.Create(24);
  TNat384.Mul(x, y, tt);
  Reduce(tt, z);
end;

class procedure TSecP384R1Field.Negate(const x, z: TCryptoLibUInt32Array);
begin
  if (TNat.IsZero(12, x)) then
  begin
    TNat.Zero(12, z);
  end
  else
  begin
    TNat.Sub(12, FP, x, z);
  end;
end;

class procedure TSecP384R1Field.Square(const x, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat.Create(24);
  TNat384.Square(x, tt);
  Reduce(tt, z);
end;

class procedure TSecP384R1Field.SquareN(const x: TCryptoLibUInt32Array;
  n: Int32; const z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
{$IFDEF DEBUG}
  System.Assert(n > 0);
{$ENDIF DEBUG}
  tt := TNat.Create(24);
  TNat384.Square(x, tt);
  Reduce(tt, z);

  System.Dec(n);
  while (n > 0) do
  begin
    TNat384.Square(z, tt);
    Reduce(tt, z);
    System.Dec(n);
  end;
end;

class procedure TSecP384R1Field.Subtract(const x, y, z: TCryptoLibUInt32Array);
var
  c: Int32;
begin
  c := TNat.Sub(12, x, y, z);
  if (c <> 0) then
  begin
    SubPInvFrom(z);
  end;
end;

class procedure TSecP384R1Field.SubtractExt(const xx, yy,
  zz: TCryptoLibUInt32Array);
var
  c: Int32;
begin
  c := TNat.Sub(24, xx, yy, zz);
  if (c <> 0) then
  begin
    if (TNat.SubFrom(System.Length(FPExtInv), FPExtInv, zz) <> 0) then
    begin
      TNat.DecAt(24, zz, System.Length(FPExtInv));
    end;
  end;
end;

class procedure TSecP384R1Field.Twice(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.ShiftUpBit(12, x, 0, z);
  if ((c <> 0) or ((z[11] = P11) and (TNat.Gte(12, z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

end.
