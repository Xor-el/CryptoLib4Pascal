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

unit ClpSecT283Field;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpBits,
  ClpNat,
  ClpNat320,
  ClpInterleave,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TSecT283Field = class sealed(TObject)

  strict private
  const
    M27 = UInt64(System.High(UInt64) shr 37);
    M57 = UInt64(System.High(UInt64) shr 7);

    class var

      FROOT_Z: TCryptoLibUInt64Array;

    class procedure ImplCompactExt(const zz: TCryptoLibUInt64Array); static;
    class procedure ImplExpand(const x, z: TCryptoLibUInt64Array);
      static; inline;
    class procedure ImplMultiply(const x, y, zz: TCryptoLibUInt64Array); static;
    class procedure ImplMulw(x, y: UInt64; const z: TCryptoLibUInt64Array;
      zOff: Int32); static;

    class procedure ImplSquare(const x, zz: TCryptoLibUInt64Array);
      static; inline;

    class constructor SecT283Field();

  public
    class procedure Add(const x, y, z: TCryptoLibUInt64Array); static; inline;
    class procedure AddExt(const xx, yy, zz: TCryptoLibUInt64Array);
      static; inline;
    class procedure AddOne(const x, z: TCryptoLibUInt64Array); static; inline;
    class function FromBigInteger(const x: TBigInteger): TCryptoLibUInt64Array;
      static; inline;

    class procedure Invert(const x, z: TCryptoLibUInt64Array); static;
    class procedure Multiply(const x, y, z: TCryptoLibUInt64Array);
      static; inline;
    class procedure MultiplyAddToExt(const x, y, zz: TCryptoLibUInt64Array);
      static; inline;
    class procedure Reduce(const xx, z: TCryptoLibUInt64Array); static;
    class procedure Reduce37(const z: TCryptoLibUInt64Array; zOff: Int32);
      static; inline;
    class procedure Sqrt(const x, z: TCryptoLibUInt64Array); static;

    class procedure Square(const x, z: TCryptoLibUInt64Array); static; inline;
    class procedure SquareAddToExt(const x, zz: TCryptoLibUInt64Array);
      static; inline;
    class procedure SquareN(const x: TCryptoLibUInt64Array; n: Int32;
      const z: TCryptoLibUInt64Array); static; inline;

    class function Trace(const x: TCryptoLibUInt64Array): UInt32;
      static; inline;

  end;

implementation

{ TSecT283Field }

class constructor TSecT283Field.SecT283Field;
begin
  FROOT_Z := TCryptoLibUInt64Array.Create(UInt64($0C30C30C30C30808),
    UInt64($30C30C30C30C30C3), UInt64($820820820820830C),
    UInt64($0820820820820820), UInt64($2082082));
end;

class procedure TSecT283Field.Reduce37(const z: TCryptoLibUInt64Array;
  zOff: Int32);
var
  z4, t: UInt64;
begin
  z4 := z[zOff + 4];
  t := z4 shr 27;
  z[zOff] := z[zOff] xor (t xor (t shl 5) xor (t shl 7) xor (t shl 12));
  z[zOff + 4] := z4 and M27;
end;

class procedure TSecT283Field.Add(const x, y, z: TCryptoLibUInt64Array);
begin
  z[0] := x[0] xor y[0];
  z[1] := x[1] xor y[1];
  z[2] := x[2] xor y[2];
  z[3] := x[3] xor y[3];
  z[4] := x[4] xor y[4];
end;

class procedure TSecT283Field.AddExt(const xx, yy, zz: TCryptoLibUInt64Array);
begin
  zz[0] := xx[0] xor yy[0];
  zz[1] := xx[1] xor yy[1];
  zz[2] := xx[2] xor yy[2];
  zz[3] := xx[3] xor yy[3];
  zz[4] := xx[4] xor yy[4];
  zz[5] := xx[5] xor yy[5];
  zz[6] := xx[6] xor yy[6];
  zz[7] := xx[7] xor yy[7];
  zz[8] := xx[8] xor yy[8];
end;

class procedure TSecT283Field.AddOne(const x, z: TCryptoLibUInt64Array);
begin
  z[0] := x[0] xor UInt64(1);
  z[1] := x[1];
  z[2] := x[2];
  z[3] := x[3];
  z[4] := x[4];
end;

class function TSecT283Field.FromBigInteger(const x: TBigInteger)
  : TCryptoLibUInt64Array;
var
  z: TCryptoLibUInt64Array;
begin
  z := TNat320.FromBigInteger64(x);
  Reduce37(z, 0);
  result := z;
end;

class procedure TSecT283Field.Multiply(const x, y, z: TCryptoLibUInt64Array);
var
  tt: TCryptoLibUInt64Array;
begin
  tt := TNat320.CreateExt64();
  ImplMultiply(x, y, tt);
  Reduce(tt, z);
end;

class procedure TSecT283Field.ImplSquare(const x, zz: TCryptoLibUInt64Array);
var
  i: Int32;
begin
  for i := 0 to System.Pred(4) do
  begin
    TInterleave.Expand64To128(x[i], zz, i shl 1);
  end;

  zz[8] := TInterleave.Expand32to64(UInt32(x[4]));
end;

class procedure TSecT283Field.Square(const x, z: TCryptoLibUInt64Array);
var
  tt: TCryptoLibUInt64Array;
begin
  tt := TNat.Create64(9);
  ImplSquare(x, tt);
  Reduce(tt, z);
end;

class procedure TSecT283Field.SquareN(const x: TCryptoLibUInt64Array; n: Int32;
  const z: TCryptoLibUInt64Array);
var
  tt: TCryptoLibUInt64Array;
begin
{$IFDEF DEBUG}
  System.Assert(n > 0);
{$ENDIF DEBUG}
  tt := TNat.Create64(9);
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

class procedure TSecT283Field.Invert(const x, z: TCryptoLibUInt64Array);
var
  t0, t1: TCryptoLibUInt64Array;
begin
  if TNat320.IsZero64(x) then
  begin
    raise EInvalidOperationCryptoLibException.Create('');
  end;

  // Itoh-Tsujii inversion

  t0 := TNat320.Create64();
  t1 := TNat320.Create64();

  Square(x, t0);
  Multiply(t0, x, t0);
  SquareN(t0, 2, t1);
  Multiply(t1, t0, t1);
  SquareN(t1, 4, t0);
  Multiply(t0, t1, t0);
  SquareN(t0, 8, t1);
  Multiply(t1, t0, t1);
  Square(t1, t1);
  Multiply(t1, x, t1);
  SquareN(t1, 17, t0);
  Multiply(t0, t1, t0);
  Square(t0, t0);
  Multiply(t0, x, t0);
  SquareN(t0, 35, t1);
  Multiply(t1, t0, t1);
  SquareN(t1, 70, t0);
  Multiply(t0, t1, t0);
  Square(t0, t0);
  Multiply(t0, x, t0);
  SquareN(t0, 141, t1);
  Multiply(t1, t0, t1);
  Square(t1, z);
end;

class procedure TSecT283Field.ImplCompactExt(const zz: TCryptoLibUInt64Array);
var
  z0, z1, z2, z3, z4, z5, z6, z7, z8, z9: UInt64;
begin
  z0 := zz[0];
  z1 := zz[1];
  z2 := zz[2];
  z3 := zz[3];
  z4 := zz[4];
  z5 := zz[5];
  z6 := zz[6];
  z7 := zz[7];
  z8 := zz[8];
  z9 := zz[9];
  zz[0] := z0 xor (z1 shl 57);
  zz[1] := (z1 shr 7) xor (z2 shl 50);
  zz[2] := (z2 shr 14) xor (z3 shl 43);
  zz[3] := (z3 shr 21) xor (z4 shl 36);
  zz[4] := (z4 shr 28) xor (z5 shl 29);
  zz[5] := (z5 shr 35) xor (z6 shl 22);
  zz[6] := (z6 shr 42) xor (z7 shl 15);
  zz[7] := (z7 shr 49) xor (z8 shl 8);
  zz[8] := (z8 shr 56) xor (z9 shl 1);
  zz[9] := (z9 shr 63); // Zero!
end;

class procedure TSecT283Field.ImplExpand(const x, z: TCryptoLibUInt64Array);
var
  x0, x1, x2, x3, x4: UInt64;
begin
  x0 := x[0];
  x1 := x[1];
  x2 := x[2];
  x3 := x[3];
  x4 := x[4];
  z[0] := x0 and M57;
  z[1] := ((x0 shr 57) xor (x1 shl 7)) and M57;
  z[2] := ((x1 shr 50) xor (x2 shl 14)) and M57;
  z[3] := ((x2 shr 43) xor (x3 shl 21)) and M57;
  z[4] := ((x3 shr 36) xor (x4 shl 28));
end;

class procedure TSecT283Field.ImplMultiply(const x, y,
  zz: TCryptoLibUInt64Array);
var
  a, b, p: TCryptoLibUInt64Array;
  u0, u1, u2, u3, v0, v1, v2, v3, A4, A5, B4, B5, t1, t2, t3, t4, t5, t6, t7,
    t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22,
    t23, t24, t25, t26, t27, t28, t29, t30, t31, t32, t33, t34, t35, t36, t37,
    t38, t39: UInt64;
begin
  // /*
  // * Formula (17) from "Some New Results on Binary Polynomial Multiplication",
  // * Murat Cenk and M. Anwar Hasan.
  // *
  // * The formula as given contained an error in the term t25, as noted below
  // */
  System.SetLength(a, 5);
  System.SetLength(b, 5);
  ImplExpand(x, a);
  ImplExpand(y, b);

  System.SetLength(p, 26);

  ImplMulw(a[0], b[0], p, 0); // m1
  ImplMulw(a[1], b[1], p, 2); // m2
  ImplMulw(a[2], b[2], p, 4); // m3
  ImplMulw(a[3], b[3], p, 6); // m4
  ImplMulw(a[4], b[4], p, 8); // m5

  u0 := a[0] xor a[1];
  v0 := b[0] xor b[1];
  u1 := a[0] xor a[2];
  v1 := b[0] xor b[2];
  u2 := a[2] xor a[4];
  v2 := b[2] xor b[4];
  u3 := a[3] xor a[4];
  v3 := b[3] xor b[4];

  ImplMulw(u1 xor a[3], v1 xor b[3], p, 18); // m10
  ImplMulw(u2 xor a[1], v2 xor b[1], p, 20); // m11

  A4 := u0 xor u3;
  B4 := v0 xor v3;
  A5 := A4 xor a[2];
  B5 := B4 xor b[2];

  ImplMulw(A4, B4, p, 22); // m12
  ImplMulw(A5, B5, p, 24); // m13

  ImplMulw(u0, v0, p, 10); // m6
  ImplMulw(u1, v1, p, 12); // m7
  ImplMulw(u2, v2, p, 14); // m8
  ImplMulw(u3, v3, p, 16); // m9


  // Improved method factors out common single-word terms
  // NOTE: p1,...,p26 in the paper maps to p[0],...,p[25] here

  zz[0] := p[0];
  zz[9] := p[9];

  t1 := p[0] xor p[1];
  t2 := t1 xor p[2];
  t3 := t2 xor p[10];

  zz[1] := t3;

  t4 := p[3] xor p[4];
  t5 := p[11] xor p[12];
  t6 := t4 xor t5;
  t7 := t2 xor t6;

  zz[2] := t7;

  t8 := t1 xor t4;
  t9 := p[5] xor p[6];
  t10 := t8 xor t9;
  t11 := t10 xor p[8];
  t12 := p[13] xor p[14];
  t13 := t11 xor t12;
  t14 := p[18] xor p[22];
  t15 := t14 xor p[24];
  t16 := t13 xor t15;

  zz[3] := t16;

  t17 := p[7] xor p[8];
  t18 := t17 xor p[9];
  t19 := t18 xor p[17];

  zz[8] := t19;

  t20 := t18 xor t9;
  t21 := p[15] xor p[16];
  t22 := t20 xor t21;

  zz[7] := t22;

  t23 := t22 xor t3;
  t24 := p[19] xor p[20];
  // t25 := p[23] xor  p[24];
  t25 := p[25] xor p[24]; // Fixes an error in the paper: p[23] -> p{25]
  t26 := p[18] xor p[23];
  t27 := t24 xor t25;
  t28 := t27 xor t26;
  t29 := t28 xor t23;

  zz[4] := t29;

  t30 := t7 xor t19;
  t31 := t27 xor t30;
  t32 := p[21] xor p[22];
  t33 := t31 xor t32;

  zz[5] := t33;

  t34 := t11 xor p[0];
  t35 := t34 xor p[9];
  t36 := t35 xor t12;
  t37 := t36 xor p[21];
  t38 := t37 xor p[23];
  t39 := t38 xor p[25];

  zz[6] := t39;

  ImplCompactExt(zz);
end;

class procedure TSecT283Field.ImplMulw(x, y: UInt64;
  const z: TCryptoLibUInt64Array; zOff: Int32);
var
  u: TCryptoLibUInt64Array;
  j: UInt32;
  g, h, l: UInt64;
  k: Int32;
begin
{$IFDEF DEBUG}
  System.Assert((x shr 57) = 0);
  System.Assert((y shr 57) = 0);
{$ENDIF DEBUG}
  System.SetLength(u, 8);
  // u[0] := 0;
  u[1] := y;
  u[2] := u[1] shl 1;
  u[3] := u[2] xor y;
  u[4] := u[2] shl 1;
  u[5] := u[4] xor y;
  u[6] := u[3] shl 1;
  u[7] := u[6] xor y;

  j := UInt32(x);
  h := 0;
  l := u[j and 7];
  k := 48;

  repeat

    j := UInt32(x shr k);
    g := u[j and 7] xor u[(j shr 3) and 7] shl 3 xor u[(j shr 6) and 7] shl 6;
    l := l xor ((g shl k));
    h := h xor TBits.NegativeRightShift64(g, -k);

    System.Dec(k, 9);
  until not(k > 0);

  h := h xor (((x and Int64($0100804020100800)) and
    UInt64(TBits.Asr64(Int64(y) shl 7, 63))) shr 8);

{$IFDEF DEBUG}
  System.Assert((h shr 49) = 0);
{$ENDIF DEBUG}
  z[zOff] := l and M57;
  z[zOff + 1] := (l shr 57) xor (h shl 7);
end;

class procedure TSecT283Field.MultiplyAddToExt(const x, y,
  zz: TCryptoLibUInt64Array);
var
  tt: TCryptoLibUInt64Array;
begin
  tt := TNat320.CreateExt64();
  ImplMultiply(x, y, tt);
  AddExt(zz, tt, zz);
end;

class procedure TSecT283Field.Reduce(const xx, z: TCryptoLibUInt64Array);
var
  x0, x1, x2, x3, x4, x5, x6, x7, x8, t: UInt64;
begin
  x0 := xx[0];
  x1 := xx[1];
  x2 := xx[2];
  x3 := xx[3];
  x4 := xx[4];
  x5 := xx[5];
  x6 := xx[6];
  x7 := xx[7];
  x8 := xx[8];

  x3 := x3 xor ((x8 shl 37) xor (x8 shl 42) xor (x8 shl 44) xor (x8 shl 49));
  x4 := x4 xor ((x8 shr 27) xor (x8 shr 22) xor (x8 shr 20) xor (x8 shr 15));

  x2 := x2 xor ((x7 shl 37) xor (x7 shl 42) xor (x7 shl 44) xor (x7 shl 49));
  x3 := x3 xor ((x7 shr 27) xor (x7 shr 22) xor (x7 shr 20) xor (x7 shr 15));

  x1 := x1 xor ((x6 shl 37) xor (x6 shl 42) xor (x6 shl 44) xor (x6 shl 49));
  x2 := x2 xor ((x6 shr 27) xor (x6 shr 22) xor (x6 shr 20) xor (x6 shr 15));

  x0 := x0 xor ((x5 shl 37) xor (x5 shl 42) xor (x5 shl 44) xor (x5 shl 49));
  x1 := x1 xor ((x5 shr 27) xor (x5 shr 22) xor (x5 shr 20) xor (x5 shr 15));

  t := x4 shr 27;
  z[0] := x0 xor t xor (t shl 5) xor (t shl 7) xor (t shl 12);
  z[1] := x1;
  z[2] := x2;
  z[3] := x3;
  z[4] := x4 and M27;
end;

class procedure TSecT283Field.Sqrt(const x, z: TCryptoLibUInt64Array);
var
  u0, u1, e0, e1, e2: UInt64;
  odd: TCryptoLibUInt64Array;
begin
  odd := TNat320.Create64();

  u0 := TInterleave.Unshuffle(x[0]);
  u1 := TInterleave.Unshuffle(x[1]);
  e0 := (u0 and UInt64($00000000FFFFFFFF)) or (u1 shl 32);
  odd[0] := (u0 shr 32) or (u1 and UInt64($FFFFFFFF00000000));

  u0 := TInterleave.Unshuffle(x[2]);
  u1 := TInterleave.Unshuffle(x[3]);
  e1 := (u0 and UInt64($00000000FFFFFFFF)) or (u1 shl 32);
  odd[1] := (u0 shr 32) or (u1 and UInt64($FFFFFFFF00000000));

  u0 := TInterleave.Unshuffle(x[4]);
  e2 := (u0 and UInt64($00000000FFFFFFFF));
  odd[2] := (u0 shr 32);

  Multiply(odd, FROOT_Z, z);

  z[0] := z[0] xor e0;
  z[1] := z[1] xor e1;
  z[2] := z[2] xor e2;
end;

class procedure TSecT283Field.SquareAddToExt(const x,
  zz: TCryptoLibUInt64Array);
var
  tt: TCryptoLibUInt64Array;
begin
  tt := TNat.Create64(9);
  ImplSquare(x, tt);
  AddExt(zz, tt, zz);
end;

class function TSecT283Field.Trace(const x: TCryptoLibUInt64Array): UInt32;
begin
  // Non-zero-trace bits: 0, 271
  result := UInt32(x[0] xor (x[4] shr 15)) and UInt32(1);
end;

end.
