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

unit ClpSecP256R1Field;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpBits,
  ClpNat256,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  // 2^256 - 2^224 + 2^192 + 2^96 - 1
  TSecP256R1Field = class sealed(TObject)

  strict private
  const
    P7 = UInt32($FFFFFFFF);
    PExt15 = UInt32($FFFFFFFE);

    class var

      FP, FPExt: TCryptoLibUInt32Array;

    class function GetP: TCryptoLibUInt32Array; static; inline;

    class procedure AddPInvTo(const z: TCryptoLibUInt32Array); static;
    class procedure SubPInvFrom(const z: TCryptoLibUInt32Array); static;

    class constructor SecP256R1Field();

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

{ TSecP256R1Field }

class constructor TSecP256R1Field.SecP256R1Field;
begin
  FP := TCryptoLibUInt32Array.Create($FFFFFFFF, $FFFFFFFF, $FFFFFFFF, $00000000,
    $00000000, $00000000, $00000001, $FFFFFFFF);
  FPExt := TCryptoLibUInt32Array.Create($00000001, $00000000, $00000000,
    $FFFFFFFE, $FFFFFFFF, $FFFFFFFF, $FFFFFFFE, $00000001, $FFFFFFFE, $00000001,
    $FFFFFFFE, $00000001, $00000001, $FFFFFFFE, $00000002, $FFFFFFFE);

end;

class function TSecP256R1Field.GetP: TCryptoLibUInt32Array;
begin
  result := FP;
end;

class procedure TSecP256R1Field.Add(const x, y, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat256.Add(x, y, z);
  if ((c <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

class procedure TSecP256R1Field.AddExt(const xx, yy, zz: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Add(16, xx, yy, zz);
  if ((c <> 0) or ((zz[15] >= PExt15) and (TNat.Gte(16, zz, FPExt)))) then
  begin
    TNat.SubFrom(16, FPExt, zz);
  end;
end;

class procedure TSecP256R1Field.AddOne(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.Inc(8, x, z);
  if ((c <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

class procedure TSecP256R1Field.AddPInvTo(const z: TCryptoLibUInt32Array);
var
  c: Int64;
begin
  c := Int64(z[0]) + 1;
  z[0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    c := c + Int64(z[1]);
    z[1] := UInt32(c);
    c := TBits.Asr64(c, 32);
    c := c + Int64(z[2]);
    z[2] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  c := c + (Int64(z[3]) - 1);
  z[3] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    c := c + Int64(z[4]);
    z[4] := UInt32(c);
    c := TBits.Asr64(c, 32);
    c := c + Int64(z[5]);
    z[5] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  c := c + (Int64(z[6]) - 1);
  z[6] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[7]) + 1);
  z[7] := UInt32(c);
  // c := TBits.Asr64(c, 32);
end;

class function TSecP256R1Field.FromBigInteger(const x: TBigInteger)
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

class procedure TSecP256R1Field.Half(const x, z: TCryptoLibUInt32Array);
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

class procedure TSecP256R1Field.Reduce(const xx, z: TCryptoLibUInt32Array);
const
  n = Int64(6);
var
  cc, xx08, xx09, xx10, xx11, xx12, xx13, xx14, xx15, t0, t1, t2, t3, t4, t5,
    t6, t7: Int64;
begin

  xx08 := xx[8];
  xx09 := xx[9];
  xx10 := xx[10];
  xx11 := xx[11];
  xx12 := xx[12];
  xx13 := xx[13];
  xx14 := xx[14];
  xx15 := xx[15];

  xx08 := xx08 - n;

  t0 := xx08 + xx09;
  t1 := xx09 + xx10;
  t2 := xx10 + xx11 - xx15;
  t3 := xx11 + xx12;
  t4 := xx12 + xx13;
  t5 := xx13 + xx14;
  t6 := xx14 + xx15;
  t7 := t5 - t0;

  cc := 0;

  cc := cc + (Int64(xx[0]) - t3 - t7);
  z[0] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[1]) + t1 - t4 - t6);
  z[1] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[2]) + t2 - t5);
  z[2] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[3]) + (t3 shl 1) + t7 - t6);
  z[3] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[4]) + (t4 shl 1) + xx14 - t1);
  z[4] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[5]) + (t5 shl 1) - t2);
  z[5] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[6]) + (t6 shl 1) + t7);
  z[6] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + (Int64(xx[7]) + (xx15 shl 1) + xx08 - t2 - t4);
  z[7] := UInt32(cc);
  cc := TBits.Asr64(cc, 32);
  cc := cc + n;

{$IFDEF DEBUG}
  System.Assert((cc >= 0));
{$ENDIF DEBUG}
  Reduce32(UInt32(cc), z);
end;

class procedure TSecP256R1Field.Multiply(const x, y, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat256.CreateExt();
  TNat256.Mul(x, y, tt);
  Reduce(tt, z);
end;

class procedure TSecP256R1Field.MultiplyAddToExt(const x, y,
  zz: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat256.MulAddTo(x, y, zz);
  if ((c <> 0) or ((zz[15] >= PExt15) and (TNat.Gte(16, zz, FPExt)))) then
  begin
    TNat.SubFrom(16, FPExt, zz);
  end;
end;

class procedure TSecP256R1Field.Negate(const x, z: TCryptoLibUInt32Array);
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

class procedure TSecP256R1Field.Reduce32(x: UInt32;
  const z: TCryptoLibUInt32Array);
var
  cc, xx08: Int64;
begin
  cc := 0;

  if (x <> 0) then
  begin
    xx08 := x;

    cc := cc + (Int64(z[0]) + xx08);
    z[0] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);
    if (cc <> 0) then
    begin
      cc := cc + Int64(z[1]);
      z[1] := UInt32(cc);
      cc := TBits.Asr64(cc, 32);
      cc := cc + Int64(z[2]);
      z[2] := UInt32(cc);
      cc := TBits.Asr64(cc, 32);
    end;
    cc := cc + (Int64(z[3]) - xx08);
    z[3] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);
    if (cc <> 0) then
    begin
      cc := cc + Int64(z[4]);
      z[4] := UInt32(cc);
      cc := TBits.Asr64(cc, 32);
      cc := cc + Int64(z[5]);
      z[5] := UInt32(cc);
      cc := TBits.Asr64(cc, 32);
    end;
    cc := cc + (Int64(z[6]) - xx08);
    z[6] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);
    cc := cc + (Int64(z[7]) + xx08);
    z[7] := UInt32(cc);
    cc := TBits.Asr64(cc, 32);

{$IFDEF DEBUG}
    System.Assert((cc = 0) or (cc = 1));
{$ENDIF DEBUG}
  end;

  if ((cc <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

class procedure TSecP256R1Field.Square(const x, z: TCryptoLibUInt32Array);
var
  tt: TCryptoLibUInt32Array;
begin
  tt := TNat256.CreateExt();
  TNat256.Square(x, tt);
  Reduce(tt, z);
end;

class procedure TSecP256R1Field.SquareN(const x: TCryptoLibUInt32Array;
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

class procedure TSecP256R1Field.SubPInvFrom(const z: TCryptoLibUInt32Array);
var
  c: Int64;
begin
  c := Int64(z[0]) - 1;
  z[0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    c := c + Int64(z[1]);
    z[1] := UInt32(c);
    c := TBits.Asr64(c, 32);
    c := c + Int64(z[2]);
    z[2] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  c := c + (Int64(z[3]) + 1);
  z[3] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if (c <> 0) then
  begin
    c := c + Int64(z[4]);
    z[4] := UInt32(c);
    c := TBits.Asr64(c, 32);
    c := c + Int64(z[5]);
    z[5] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  c := c + (Int64(z[6]) + 1);
  z[6] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[7]) - 1);
  z[7] := UInt32(c);
  // c := TBits.Asr64(c, 32);
end;

class procedure TSecP256R1Field.Subtract(const x, y, z: TCryptoLibUInt32Array);
var
  c: Int32;
begin
  c := TNat256.Sub(x, y, z);
  if (c <> 0) then
  begin
    SubPInvFrom(z);
  end;
end;

class procedure TSecP256R1Field.SubtractExt(const xx, yy,
  zz: TCryptoLibUInt32Array);
var
  c: Int32;
begin
  c := TNat.Sub(16, xx, yy, zz);
  if (c <> 0) then
  begin
    TNat.AddTo(16, FPExt, zz);
  end;
end;

class procedure TSecP256R1Field.Twice(const x, z: TCryptoLibUInt32Array);
var
  c: UInt32;
begin
  c := TNat.ShiftUpBit(8, x, 0, z);
  if ((c <> 0) or ((z[7] = P7) and (TNat256.Gte(z, FP)))) then
  begin
    AddPInvTo(z);
  end;
end;

end.
