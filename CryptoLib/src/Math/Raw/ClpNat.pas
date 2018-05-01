{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpNat;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpConverters,
  ClpBits,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  TNat = class abstract(TObject)

  strict private
  const
    M = UInt64($FFFFFFFF);

  public

    class function Add(len: Int32; x, y, z: TCryptoLibUInt32Array): UInt32;
      static; inline;

    class function Add33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zPos: Int32): UInt32; overload; static; inline;

    class function Add33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): UInt32; overload; static; inline;

    class function Add33To(len: Int32; x: UInt32; z: TCryptoLibUInt32Array)
      : UInt32; overload; static; inline;

    class function Add33To(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff: Int32): UInt32; overload; static; inline;

    class function AddBothTo(len: Int32; x, y, z: TCryptoLibUInt32Array)
      : UInt32; overload; static; inline;

    class function AddBothTo(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      y: TCryptoLibUInt32Array; yOff: Int32; z: TCryptoLibUInt32Array;
      zOff: Int32): UInt32; overload; static; inline;

    class function AddDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
      zPos: Int32): UInt32; overload; static; inline;

    class function AddDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): UInt32; overload; static; inline;

    class function AddDWordTo(len: Int32; x: UInt64; z: TCryptoLibUInt32Array)
      : UInt32; overload; static; inline;

    class function AddDWordTo(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
      zOff: Int32): UInt32; overload; static; inline;

    class function AddTo(len: Int32; x, z: TCryptoLibUInt32Array): UInt32;
      overload; static; inline;

    class function AddTo(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      z: TCryptoLibUInt32Array; zOff: Int32): UInt32; overload; static; inline;

    class function AddWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zPos: Int32): UInt32; overload; static; inline;

    class function AddWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): UInt32; overload; static; inline;

    class function AddWordTo(len: Int32; x: UInt32; z: TCryptoLibUInt32Array)
      : UInt32; overload; static; inline;

    class function AddWordTo(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff: Int32): UInt32; overload; static; inline;

    class procedure Copy(len: Int32; x, z: TCryptoLibUInt32Array); overload;
      static; inline;

    class function Copy(len: Int32; x: TCryptoLibUInt32Array)
      : TCryptoLibUInt32Array; overload; static; inline;

    class procedure Copy(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      z: TCryptoLibUInt32Array; zOff: Int32); overload; static;

    class function Create(len: Int32): TCryptoLibUInt32Array; static; inline;

    class function Create64(len: Int32): TCryptoLibUInt64Array; static; inline;

    class function Dec(len: Int32; z: TCryptoLibUInt32Array): Int32; overload;
      static; inline;

    class function Dec(len: Int32; x, z: TCryptoLibUInt32Array): Int32;
      overload; static; inline;

    class function DecAt(len: Int32; z: TCryptoLibUInt32Array; zPos: Int32)
      : Int32; overload; static; inline;

    class function DecAt(len: Int32; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): Int32; overload; static; inline;

    class function Eq(len: Int32; x, y: TCryptoLibUInt32Array): Boolean;
      static; inline;

    class function FromBigInteger(bits: Int32; x: TBigInteger)
      : TCryptoLibUInt32Array; static;

    class function GetBit(x: TCryptoLibUInt32Array; bit: Int32): UInt32;
      static; inline;

    class function Gte(len: Int32; x, y: TCryptoLibUInt32Array): Boolean;
      static; inline;

    class function Inc(len: Int32; z: TCryptoLibUInt32Array): UInt32; overload;
      static; inline;

    class function Inc(len: Int32; x, z: TCryptoLibUInt32Array): UInt32;
      overload; static; inline;

    class function IncAt(len: Int32; z: TCryptoLibUInt32Array; zPos: Int32)
      : UInt32; overload; static; inline;

    class function IncAt(len: Int32; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): UInt32; overload; static; inline;

    class function IsOne(len: Int32; x: TCryptoLibUInt32Array): Boolean;
      static; inline;

    class function IsZero(len: Int32; x: TCryptoLibUInt32Array): Boolean;
      static; inline;

    class procedure Mul(len: Int32; x, y, zz: TCryptoLibUInt32Array); overload;
      static; inline;

    class procedure Mul(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      y: TCryptoLibUInt32Array; yOff: Int32; zz: TCryptoLibUInt32Array;
      zzOff: Int32); overload; static; inline;

    class function Mul31BothAdd(len: Int32; a: UInt32; x: TCryptoLibUInt32Array;
      b: UInt32; y, z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
      static; inline;

    class function MulWord(len: Int32; x: UInt32; y, z: TCryptoLibUInt32Array)
      : UInt32; overload; static; inline;

    class function MulWord(len: Int32; x: UInt32; y: TCryptoLibUInt32Array;
      yOff: Int32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32; overload;
      static; inline;

    class function MulWordAddTo(len: Int32; x: UInt32; y: TCryptoLibUInt32Array;
      yOff: Int32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
      static; inline;

    class function MulWordDwordAddAt(len: Int32; x: UInt32; y: UInt64;
      z: TCryptoLibUInt32Array; zPos: Int32): UInt32; static; inline;

    class function ShiftDownBit(len: Int32; z: TCryptoLibUInt32Array; c: UInt32)
      : UInt32; overload; static; inline;

    class function ShiftDownBit(len: Int32; z: TCryptoLibUInt32Array;
      zOff: Int32; c: UInt32): UInt32; overload; static; inline;

    class function ShiftDownBit(len: Int32; x: TCryptoLibUInt32Array; c: UInt32;
      z: TCryptoLibUInt32Array): UInt32; overload; static; inline;

    class function ShiftDownBit(len: Int32; x: TCryptoLibUInt32Array;
      xOff: UInt32; c: UInt32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
      overload; static; inline;

    class function ShiftDownBits(len: Int32; z: TCryptoLibUInt32Array;
      bits: Int32; c: UInt32): UInt32; overload; static; inline;

    class function ShiftDownBits(len: Int32; z: TCryptoLibUInt32Array;
      zOff: Int32; bits: Int32; c: UInt32): UInt32; overload; static; inline;

    class function ShiftDownBits(len: Int32; x: TCryptoLibUInt32Array;
      bits: Int32; c: UInt32; z: TCryptoLibUInt32Array): UInt32; overload;
      static; inline;

    class function ShiftDownBits(len: Int32; x: TCryptoLibUInt32Array;
      xOff, bits: Int32; c: UInt32; z: TCryptoLibUInt32Array; zOff: Int32)
      : UInt32; overload; static; inline;

    class function ShiftDownWord(len: Int32; z: TCryptoLibUInt32Array;
      c: UInt32): UInt32; static; inline;

    class function ShiftUpBit(len: Int32; z: TCryptoLibUInt32Array; c: UInt32)
      : UInt32; overload; static; inline;

    class function ShiftUpBit(len: Int32; z: TCryptoLibUInt32Array; zOff: Int32;
      c: UInt32): UInt32; overload; static; inline;

    class function ShiftUpBit(len: Int32; x: TCryptoLibUInt32Array; c: UInt32;
      z: TCryptoLibUInt32Array): UInt32; overload; static; inline;

    class function ShiftUpBit(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      c: UInt32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32; overload;
      static; inline;

    class function ShiftUpBit64(len: Int32; x: TCryptoLibUInt64Array;
      xOff: Int32; c: UInt64; z: TCryptoLibUInt64Array; zOff: Int32): UInt64;
      static; inline;

    class function ShiftUpBits(len: Int32; z: TCryptoLibUInt32Array;
      bits: Int32; c: UInt32): UInt32; overload; static; inline;

    class function ShiftUpBits(len: Int32; z: TCryptoLibUInt32Array;
      zOff: Int32; bits: Int32; c: UInt32): UInt32; overload; static; inline;

    class function ShiftUpBits64(len: Int32; z: TCryptoLibUInt64Array;
      zOff: Int32; bits: Int32; c: UInt64): UInt64; overload; static; inline;

    class function ShiftUpBits(len: Int32; x: TCryptoLibUInt32Array;
      bits: Int32; c: UInt32; z: TCryptoLibUInt32Array): UInt32; overload;
      static; inline;

    class function ShiftUpBits(len: Int32; x: TCryptoLibUInt32Array;
      xOff: Int32; bits: Int32; c: UInt32; z: TCryptoLibUInt32Array;
      zOff: Int32): UInt32; overload; static; inline;

    class function ShiftUpBits64(len: Int32; x: TCryptoLibUInt64Array;
      xOff, bits: Int32; c: UInt64; z: TCryptoLibUInt64Array; zOff: Int32)
      : UInt64; overload; static; inline;

    class procedure Square(len: Int32; x, zz: TCryptoLibUInt32Array);
      overload; static;

    class procedure Square(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      zz: TCryptoLibUInt32Array; zzOff: Int32); overload; static;

    class function SquareWordAdd(x: TCryptoLibUInt32Array; xPos: Int32;
      z: TCryptoLibUInt32Array): UInt32; overload; static; inline;

    class function SquareWordAdd(x: TCryptoLibUInt32Array; xOff, xPos: Int32;
      z: TCryptoLibUInt32Array; zOff: Int32): UInt32; overload; static; inline;

    class function Sub(len: Int32; x, y, z: TCryptoLibUInt32Array): Int32;
      overload; static; inline;

    class function Sub(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      y: TCryptoLibUInt32Array; yOff: Int32; z: TCryptoLibUInt32Array;
      zOff: Int32): Int32; overload; static; inline;

    class function Sub33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zPos: Int32): Int32; overload; static; inline;

    class function Sub33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): Int32; overload; static; inline;

    class function Sub33From(len: Int32; x: UInt32; z: TCryptoLibUInt32Array)
      : Int32; overload; static; inline;

    class function Sub33From(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff: Int32): Int32; overload; static; inline;

    class function SubBothFrom(len: Int32; x, y, z: TCryptoLibUInt32Array)
      : Int32; overload; static; inline;

    class function SubBothFrom(len: Int32; x: TCryptoLibUInt32Array;
      xOff: Int32; y: TCryptoLibUInt32Array; yOff: Int32;
      z: TCryptoLibUInt32Array; zOff: Int32): Int32; overload; static; inline;

    class function SubDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
      zPos: Int32): Int32; overload; static; inline;

    class function SubDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): Int32; overload; static; inline;

    class function SubDWordFrom(len: Int32; x: UInt64; z: TCryptoLibUInt32Array)
      : Int32; overload; static; inline;

    class function SubDWordFrom(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
      zOff: Int32): Int32; overload; static; inline;

    class function SubFrom(len: Int32; x, z: TCryptoLibUInt32Array): Int32;
      overload; static; inline;

    class function SubFrom(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
      z: TCryptoLibUInt32Array; zOff: Int32): Int32; overload; static; inline;

    class function SubWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zPos: Int32): Int32; overload; static; inline;

    class function SubWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff, zPos: Int32): Int32; overload; static; inline;

    class function SubWordFrom(len: Int32; x: UInt32; z: TCryptoLibUInt32Array)
      : Int32; overload; static; inline;

    class function SubWordFrom(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
      zOff: Int32): Int32; overload; static; inline;

    class function ToBigInteger(len: Int32; x: TCryptoLibUInt32Array)
      : TBigInteger; static; inline;

    class procedure Zero(len: Int32; z: TCryptoLibUInt32Array); static; inline;

  end;

implementation

{ TNat }

class function TNat.IncAt(len: Int32; z: TCryptoLibUInt32Array;
  zPos: Int32): UInt32;
var
  I: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= len);
{$ENDIF DEBUG}
  for I := zPos to System.Pred(len) do
  begin
    z[I] := z[I] + 1;
    if (z[I] <> System.Low(UInt32)) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.IncAt(len: Int32; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): UInt32;
var
  I: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= len);
{$ENDIF DEBUG}
  for I := zPos to System.Pred(len) do
  begin
    z[zOff + I] := z[zOff + I] + 1;
    if (z[zOff + I] <> System.Low(UInt32)) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.MulWordAddTo(len: Int32; x: UInt32;
  y: TCryptoLibUInt32Array; yOff: Int32; z: TCryptoLibUInt32Array;
  zOff: Int32): UInt32;
var
  c, xVal: UInt64;
  I: Int32;
begin
  c := 0;
  xVal := UInt64(x);
  I := 0;

  repeat

    c := c + (xVal * y[yOff + I] + z[zOff + I]);
    z[zOff + I] := UInt32(c);
    c := c shr 32;

    System.Inc(I);
  until (not(I < len));

  Result := UInt32(c);
end;

class function TNat.MulWordDwordAddAt(len: Int32; x: UInt32; y: UInt64;
  z: TCryptoLibUInt32Array; zPos: Int32): UInt32;
var
  c, xVal: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 3));
{$ENDIF DEBUG}
  c := 0;
  xVal := UInt64(x);
  c := c + (xVal * UInt32(y) + z[zPos + 0]);
  z[zPos + 0] := UInt32(c);
  c := c shr 32;
  c := c + (xVal * (y shr 32) + z[zPos + 1]);
  z[zPos + 1] := UInt32(c);
  c := c shr 32;
  c := c + UInt64(z[zPos + 2]);
  z[zPos + 2] := UInt32(c);
  c := c shr 32;
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zPos + 3);
  end;
end;

class function TNat.MulWord(len: Int32; x: UInt32;
  y, z: TCryptoLibUInt32Array): UInt32;
var
  c, xVal: UInt64;
  I: Int32;
begin
  c := 0;
  xVal := UInt64(x);
  I := 0;

  repeat

    c := c + (xVal * y[I]);
    z[I] := UInt32(c);
    c := c shr 32;

    System.Inc(I);
  until (not(I < len));

  Result := UInt32(c);
end;

class function TNat.MulWord(len: Int32; x: UInt32; y: TCryptoLibUInt32Array;
  yOff: Int32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
var
  c, xVal: UInt64;
  I: Int32;
begin
  c := 0;
  xVal := UInt64(x);
  I := 0;

  repeat

    c := c + (xVal * y[yOff + I]);
    z[zOff + I] := UInt32(c);
    c := c shr 32;

    System.Inc(I);
  until (not(I < len));

  Result := UInt32(c);
end;

class function TNat.SquareWordAdd(x: TCryptoLibUInt32Array; xOff, xPos: Int32;
  z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
var
  c, xVal: UInt64;
  I: Int32;
begin
  c := 0;
  xVal := UInt64(x[xOff + xPos]);
  I := 0;

  repeat
    c := c + (xVal * (x[xOff + I] and M) + (z[xPos + zOff] and M));
    z[xPos + zOff] := UInt32(c);
    c := c shr 32;
    System.Inc(zOff);
    System.Inc(I);
  until (not(I < xPos));

  Result := UInt32(c);
end;

class function TNat.SquareWordAdd(x: TCryptoLibUInt32Array; xPos: Int32;
  z: TCryptoLibUInt32Array): UInt32;
var
  c, xVal: UInt64;
  I: Int32;
begin
  c := 0;
  xVal := UInt64(x[xPos]);
  I := 0;

  repeat
    c := c + (xVal * x[I] + z[xPos + I]);
    z[xPos + I] := UInt32(c);
    c := c shr 32;
    System.Inc(I);
  until (not(I < xPos));

  Result := UInt32(c);
end;

class function TNat.Add(len: Int32; x, y, z: TCryptoLibUInt32Array): UInt32;
var
  c: UInt64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do
  begin
    c := c + (UInt64(x[I]) + y[I]);
    z[I] := UInt32(c);
    c := c shr 32;
  end;
  Result := UInt32(c);
end;

class function TNat.Add33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zPos: Int32): UInt32;
var
  c: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := UInt64(z[zPos + 0]) + x;
  z[zPos + 0] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[zPos + 1]) + 1);
  z[zPos + 1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zPos + 2);
  end;

end;

class function TNat.Add33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): UInt32;
var
  c: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := UInt64(z[zOff + zPos]) + x;
  z[zOff + zPos] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[zOff + zPos + 1]) + 1);
  z[zOff + zPos + 1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zOff, zPos + 2);
  end;

end;

class function TNat.Add33To(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff: Int32): UInt32;
var
  c: UInt64;
begin
  c := UInt64(z[zOff + 0]) + x;
  z[zOff + 0] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[zOff + 1]) + 1);
  z[zOff + 1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zOff, 2);
  end;

end;

class function TNat.Add33To(len: Int32; x: UInt32;
  z: TCryptoLibUInt32Array): UInt32;
var
  c: UInt64;
begin
  c := UInt64(z[0]) + x;
  z[0] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[1]) + 1);
  z[1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, 2);
  end;

end;

class function TNat.AddBothTo(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
  y: TCryptoLibUInt32Array; yOff: Int32; z: TCryptoLibUInt32Array;
  zOff: Int32): UInt32;
var
  c: UInt64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do
  begin
    c := c + (UInt64(x[xOff + I]) + y[yOff + I] + z[zOff + I]);
    z[zOff + I] := UInt32(c);
    c := c shr 32;
  end;
  Result := UInt32(c);
end;

class function TNat.AddBothTo(len: Int32;
  x, y, z: TCryptoLibUInt32Array): UInt32;
var
  c: UInt64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do

  begin
    c := c + (UInt64(x[I]) + y[I] + z[I]);
    z[I] := UInt32(c);
    c := c shr 32;
  end;
  Result := UInt32(c);
end;

class function TNat.AddDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
  zPos: Int32): UInt32;
var
  c: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := UInt64(z[zPos + 0]) + (x and M);
  z[zPos + 0] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[zPos + 1]) + (x shr 32));
  z[zPos + 1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zPos + 2);
  end;

end;

class function TNat.AddDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): UInt32;
var
  c: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := UInt64(z[zOff + zPos]) + (x and M);
  z[zOff + zPos] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[zOff + zPos + 1]) + (x shr 32));
  z[zOff + zPos + 1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zOff, zPos + 2);
  end;

end;

class function TNat.AddDWordTo(len: Int32; x: UInt64;
  z: TCryptoLibUInt32Array): UInt32;
var
  c: UInt64;
begin
  c := UInt64(z[0]) + (x and M);
  z[0] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[1]) + (x shr 32));
  z[1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, 2);
  end;

end;

class function TNat.AddDWordTo(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
  zOff: Int32): UInt32;
var
  c: UInt64;
begin
  c := UInt64(z[zOff + 0]) + (x and M);
  z[zOff + 0] := UInt32(c);
  c := c shr 32;
  c := c + (UInt64(z[zOff + 1]) + (x shr 32));
  z[zOff + 1] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zOff, 2);
  end;

end;

class function TNat.AddTo(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
  z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
var
  c: UInt64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do
  begin
    c := c + (UInt64(x[xOff + I]) + z[zOff + I]);
    z[zOff + I] := UInt32(c);
    c := c shr 32;
  end;
  Result := UInt32(c);
end;

class function TNat.AddTo(len: Int32; x, z: TCryptoLibUInt32Array): UInt32;
var
  c: UInt64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do
  begin
    c := c + (UInt64(x[I]) + z[I]);
    z[I] := UInt32(c);
    c := c shr 32;
  end;
  Result := UInt32(c);
end;

class function TNat.AddWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zPos: Int32): UInt32;
var
  c: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 1));
{$ENDIF DEBUG}
  c := UInt64(x) + z[zPos];
  z[zPos] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zPos + 1);
  end;

end;

class function TNat.AddWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): UInt32;
var
  c: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 1));
{$ENDIF DEBUG}
  c := UInt64(x) + z[zOff + zPos];
  z[zOff + zPos] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zOff, zPos + 1);
  end;

end;

class function TNat.AddWordTo(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff: Int32): UInt32;
var
  c: UInt64;
begin
  c := UInt64(x) + z[zOff];
  z[zOff] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, zOff, 1);
  end;

end;

class function TNat.AddWordTo(len: Int32; x: UInt32;
  z: TCryptoLibUInt32Array): UInt32;
var
  c: UInt64;
begin
  c := UInt64(x) + z[0];
  z[0] := UInt32(c);
  c := c shr 32;

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := IncAt(len, z, 1);
  end;

end;

class function TNat.Copy(len: Int32; x: TCryptoLibUInt32Array)
  : TCryptoLibUInt32Array;
begin
  System.SetLength(Result, len);
  System.Move(x[0], Result[0], len * System.SizeOf(UInt32));
end;

class procedure TNat.Copy(len: Int32; x, z: TCryptoLibUInt32Array);
begin
  System.Move(x[0], z[0], len * System.SizeOf(UInt32));
end;

class procedure TNat.Copy(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
  z: TCryptoLibUInt32Array; zOff: Int32);
begin
  System.Move(x[xOff], z[zOff], len * System.SizeOf(UInt32));
end;

class function TNat.Create(len: Int32): TCryptoLibUInt32Array;
begin
  System.SetLength(Result, len);
end;

class function TNat.Create64(len: Int32): TCryptoLibUInt64Array;
begin
  System.SetLength(Result, len);
end;

class function TNat.Dec(len: Int32; z: TCryptoLibUInt32Array): Int32;
var
  I: Int32;
begin
  for I := 0 to System.Pred(len) do
  begin
    z[I] := z[I] - 1;
    if (z[I] <> System.High(UInt32)) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.Dec(len: Int32; x, z: TCryptoLibUInt32Array): Int32;
var
  I: Int32;
  c: UInt32;
begin
  I := 0;
  while (I < len) do
  begin
    c := x[I] - 1;
    z[I] := c;
    System.Inc(I);
    if (c <> System.High(UInt32)) then
    begin
      while (I < len) do
      begin
        z[I] := x[I];
        System.Inc(I);

      end;
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.DecAt(len: Int32; z: TCryptoLibUInt32Array;
  zPos: Int32): Int32;
var
  I: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= len);
{$ENDIF DEBUG}
  for I := zPos to System.Pred(len) do
  begin
    z[I] := z[I] - 1;
    if (z[I] <> System.High(UInt32)) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.DecAt(len: Int32; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): Int32;
var
  I: Int32;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= len);
{$ENDIF DEBUG}
  for I := zPos to System.Pred(len) do
  begin
    z[zOff + I] := z[zOff + I] - 1;
    if (z[zOff + I] <> System.High(UInt32)) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := -1;
end;

class function TNat.Eq(len: Int32; x, y: TCryptoLibUInt32Array): Boolean;
var
  I: Int32;
begin
  I := len - 1;
  while I >= 0 do

  begin
    if (x[I] <> y[I]) then
    begin
      Result := false;
      Exit;
    end;
    System.Dec(I);
  end;
  Result := true;
end;

class function TNat.FromBigInteger(bits: Int32; x: TBigInteger)
  : TCryptoLibUInt32Array;
var
  len, I: Int32;
begin
  if ((x.SignValue < 0) or (x.BitLength > bits)) then
  begin
    raise EArgumentCryptoLibException.Create('');
  end;

  // len := (bits + 31) shr 5;
  len := TBits.Asr32((bits + 31), 5);
  Result := Create(len);
  I := 0;
  while (x.SignValue <> 0) do
  begin
    Result[I] := UInt32(x.Int32Value);
    System.Inc(I);
    x := x.ShiftRight(32);
  end;
end;

class function TNat.GetBit(x: TCryptoLibUInt32Array; bit: Int32): UInt32;
var
  w, b: Int32;
begin
  if (bit = 0) then
  begin
    Result := x[0] and 1;
    Exit;
  end;
  // w := bit shr 5;
  w := TBits.Asr32(bit, 5);
  if ((w < 0) or (w >= System.Length(x))) then
  begin
    Result := 0;
    Exit;
  end;
  b := bit and 31;
  Result := (x[w] shr b) and 1;
end;

class function TNat.Gte(len: Int32; x, y: TCryptoLibUInt32Array): Boolean;
var
  I: Int32;
  x_i, y_i: UInt32;
begin
  I := len - 1;
  while I >= 0 do
  begin
    x_i := x[I];
    y_i := y[I];
    if (x_i < y_i) then
    begin
      Result := false;
      Exit;
    end;
    if (x_i > y_i) then
    begin
      Result := true;
      Exit;
    end;
    System.Dec(I);
  end;
  Result := true;
end;

class function TNat.Inc(len: Int32; z: TCryptoLibUInt32Array): UInt32;
var
  I: Int32;
begin
  for I := 0 to System.Pred(len) do
  begin
    z[I] := z[I] + 1;
    if (z[I] <> System.High(UInt32)) then
    begin
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.Inc(len: Int32; x, z: TCryptoLibUInt32Array): UInt32;
var
  I: Int32;
  c: UInt32;
begin
  I := 0;
  while (I < len) do
  begin
    c := x[I] + 1;
    z[I] := c;
    System.Inc(I);
    if (c <> System.Low(UInt32)) then
    begin
      while (I < len) do
      begin
        z[I] := x[I];
        System.Inc(I);

      end;
      Result := 0;
      Exit;
    end;
  end;
  Result := 1;
end;

class function TNat.IsOne(len: Int32; x: TCryptoLibUInt32Array): Boolean;
var
  I: Int32;
begin
  if (x[0] <> 1) then
  begin
    Result := false;
    Exit;
  end;
  for I := 1 to System.Pred(len) do
  begin
    if (x[I] <> 0) then
    begin
      Result := false;
      Exit;
    end;
  end;
  Result := true;
end;

class function TNat.IsZero(len: Int32; x: TCryptoLibUInt32Array): Boolean;
var
  I: Int32;
begin
  if (x[0] <> 0) then
  begin
    Result := false;
    Exit;
  end;
  for I := 1 to System.Pred(len) do
  begin
    if (x[I] <> 0) then
    begin
      Result := false;
      Exit;
    end;
  end;
  Result := true;
end;

class procedure TNat.Mul(len: Int32; x, y, zz: TCryptoLibUInt32Array);
var
  I: Int32;
begin
  zz[len] := UInt32(MulWord(len, x[0], y, zz));

  for I := 1 to System.Pred(len) do

  begin
    zz[I + len] := UInt32(MulWordAddTo(len, x[I], y, 0, zz, I));
  end;
end;

class procedure TNat.Mul(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
  y: TCryptoLibUInt32Array; yOff: Int32; zz: TCryptoLibUInt32Array;
  zzOff: Int32);
var
  I: Int32;
begin
  zz[zzOff + len] := UInt32(MulWord(len, x[xOff], y, yOff, zz, zzOff));

  for I := 1 to System.Pred(len) do
  begin
    zz[zzOff + I + len] := UInt32(MulWordAddTo(len, x[xOff + I], y, yOff, zz,
      zzOff + I));
  end;
end;

class function TNat.Mul31BothAdd(len: Int32; a: UInt32;
  x: TCryptoLibUInt32Array; b: UInt32; y, z: TCryptoLibUInt32Array;
  zOff: Int32): UInt32;
var
  c, aVal, bVal: UInt64;
  I: Int32;
begin
  c := 0;
  aVal := UInt64(a);
  bVal := UInt64(b);
  I := 0;

  repeat

    c := c + (aVal * x[I] + bVal * y[I] + z[zOff + I]);
    z[zOff + I] := UInt32(c);
    c := c shr 32;

    System.Inc(I);
  until (not(I < len));

  Result := UInt32(c);
end;

class function TNat.ShiftDownBit(len: Int32; z: TCryptoLibUInt32Array;
  zOff: Int32; c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := z[zOff + I];
    z[zOff + I] := (next shr 1) or (c shl 31);
    c := next;
    System.Dec(I);
  end;
  Result := c shl 31;
end;

class function TNat.ShiftDownBit(len: Int32; x: TCryptoLibUInt32Array;
  xOff, c: UInt32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := x[Int64(xOff) + I];
    z[zOff + I] := (next shr 1) or (c shl 31);
    c := next;
  end;
  Result := c shl 31;
end;

class function TNat.ShiftDownBit(len: Int32; x: TCryptoLibUInt32Array;
  c: UInt32; z: TCryptoLibUInt32Array): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := x[I];
    z[I] := (next shr 1) or (c shl 31);
    c := next;
    System.Dec(I);
  end;
  Result := c shl 31;
end;

class function TNat.ShiftDownBit(len: Int32; z: TCryptoLibUInt32Array;
  c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := z[I];
    z[I] := (next shr 1) or (c shl 31);
    c := next;
    System.Dec(I);
  end;
  Result := c shl 31;
end;

class function TNat.ShiftDownBits(len: Int32; x: TCryptoLibUInt32Array;
  xOff, bits: Int32; c: UInt32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := x[xOff + I];
    z[zOff + I] := (next shr (bits)) or (c shl (-bits));
    c := next;
  end;
  Result := c shl (-bits);
end;

class function TNat.ShiftDownBits(len: Int32; z: TCryptoLibUInt32Array;
  bits: Int32; c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := z[I];
    z[I] := (next shr bits) or (c shl (-bits));
    c := next;
    System.Dec(I);
  end;
  Result := c shl (-bits);
end;

class function TNat.ShiftDownBits(len: Int32; x: TCryptoLibUInt32Array;
  bits: Int32; c: UInt32; z: TCryptoLibUInt32Array): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := x[I];
    z[I] := (next shr bits) or (c shl (-bits));
    c := next;
    System.Dec(I);
  end;
  Result := c shl (-bits);
end;

class function TNat.ShiftDownBits(len: Int32; z: TCryptoLibUInt32Array;
  zOff, bits: Int32; c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := z[zOff + I];
    z[zOff + I] := (next shr bits) or (c shl (-bits));
    c := next;
    System.Dec(I);
  end;
  Result := c shl (-bits);
end;

class function TNat.ShiftDownWord(len: Int32; z: TCryptoLibUInt32Array;
  c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  I := len;
  System.Dec(I);
  while (I >= 0) do
  begin
    next := z[I];
    z[I] := c;
    c := next;
    System.Dec(I);
  end;
  Result := c;
end;

class function TNat.ShiftUpBit(len: Int32; x: TCryptoLibUInt32Array; c: UInt32;
  z: TCryptoLibUInt32Array): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  for I := 0 to System.Pred(len) do

  begin
    next := x[I];
    z[I] := (next shl 1) or (c shr 31);
    c := next;
  end;
  Result := c shr 31;
end;

class function TNat.ShiftUpBit(len: Int32; x: TCryptoLibUInt32Array;
  xOff: Int32; c: UInt32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  for I := 0 to System.Pred(len) do

  begin
    next := x[xOff + I];
    z[zOff + I] := (next shl 1) or (c shr 31);
    c := next;
  end;
  Result := c shr 31;
end;

class function TNat.ShiftUpBit(len: Int32; z: TCryptoLibUInt32Array;
  c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  for I := 0 to System.Pred(len) do

  begin
    next := z[I];
    z[I] := (next shl 1) or (c shr 31);
    c := next;
  end;
  Result := c shr 31;
end;

class function TNat.ShiftUpBit(len: Int32; z: TCryptoLibUInt32Array;
  zOff: Int32; c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
  for I := 0 to System.Pred(len) do

  begin
    next := z[zOff + I];
    z[zOff + I] := (next shl 1) or (c shr 31);
    c := next;
  end;
  Result := c shr 31;
end;

class function TNat.ShiftUpBit64(len: Int32; x: TCryptoLibUInt64Array;
  xOff: Int32; c: UInt64; z: TCryptoLibUInt64Array; zOff: Int32): UInt64;
var
  I: Int32;
  next: UInt64;
begin
  for I := 0 to System.Pred(len) do

  begin
    next := x[xOff + I];
    z[zOff + I] := (next shl 1) or (c shr 63);
    c := next;
  end;
  Result := c shr 63;
end;

class function TNat.ShiftUpBits(len: Int32; x: TCryptoLibUInt32Array;
  xOff, bits: Int32; c: UInt32; z: TCryptoLibUInt32Array; zOff: Int32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  for I := 0 to System.Pred(len) do
  begin
    next := x[xOff + I];
    z[zOff + I] := (next shl bits) or (c shr (-bits));
    c := next;
  end;
  Result := c shr (-bits);
end;

class function TNat.ShiftUpBits(len: Int32; x: TCryptoLibUInt32Array;
  bits: Int32; c: UInt32; z: TCryptoLibUInt32Array): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  for I := 0 to System.Pred(len) do
  begin
    next := x[I];
    z[I] := (next shl bits) or (c shr (-bits));
    c := next;
  end;
  Result := c shr (-bits);
end;

class function TNat.ShiftUpBits(len: Int32; z: TCryptoLibUInt32Array;
  bits: Int32; c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  for I := 0 to System.Pred(len) do
  begin
    next := z[I];
    z[I] := (next shl bits) or (c shr (-bits));
    c := next;
  end;
  Result := c shr (-bits);
end;

class function TNat.ShiftUpBits(len: Int32; z: TCryptoLibUInt32Array;
  zOff, bits: Int32; c: UInt32): UInt32;
var
  I: Int32;
  next: UInt32;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 32));
{$ENDIF DEBUG}
  for I := 0 to System.Pred(len) do
  begin
    next := z[zOff + I];
    z[zOff + I] := (next shl bits) or (c shr (-bits));
    c := next;
  end;
  Result := c shr (-bits);
end;

class function TNat.ShiftUpBits64(len: Int32; x: TCryptoLibUInt64Array;
  xOff, bits: Int32; c: UInt64; z: TCryptoLibUInt64Array; zOff: Int32): UInt64;
var
  I: Int32;
  next: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 64));
{$ENDIF DEBUG}
  for I := 0 to System.Pred(len) do
  begin
    next := x[xOff + I];
    z[zOff + I] := (next shl bits) or (c shr (-bits));
    c := next;
  end;
  Result := c shr (-bits);
end;

class function TNat.ShiftUpBits64(len: Int32; z: TCryptoLibUInt64Array;
  zOff, bits: Int32; c: UInt64): UInt64;
var
  I: Int32;
  next: UInt64;
begin
{$IFDEF DEBUG}
  System.Assert((bits > 0) and (bits < 64));
{$ENDIF DEBUG}
  for I := 0 to System.Pred(len) do
  begin
    next := z[zOff + I];
    z[zOff + I] := (next shl bits) or (c shr (-bits));
    c := next;
  end;
  Result := c shr (-bits);
end;

class procedure TNat.Square(len: Int32; x, zz: TCryptoLibUInt32Array);
var
  extLen, j, k, I: Int32;
  c: UInt32;
  xVal, p: UInt64;
begin
  extLen := len shl 1;
  c := 0;
  j := len;
  k := extLen;

  repeat
    System.Dec(j);
    xVal := UInt64(x[j]);
    p := xVal * xVal;
    System.Dec(k);
    zz[k] := (c shl 31) or UInt32((p shr 33));
    System.Dec(k);
    zz[k] := UInt32((p shr 1));
    c := UInt32(p);
  until (not(j > 0));

  for I := 1 to System.Pred(len) do
  begin
    c := SquareWordAdd(x, I, zz);
    AddWordAt(extLen, c, zz, I shl 1);
  end;

  ShiftUpBit(extLen, zz, x[0] shl 31);
end;

class procedure TNat.Square(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
  zz: TCryptoLibUInt32Array; zzOff: Int32);
var
  extLen, j, k, I: Int32;
  c: UInt32;
  xVal, p: UInt64;
begin
  extLen := len shl 1;
  c := 0;
  j := len;
  k := extLen;

  repeat
    System.Dec(j);
    xVal := UInt64(x[xOff + j]);
    p := xVal * xVal;
    System.Dec(k);
    zz[zzOff + k] := (c shl 31) or UInt32((p shr 33));
    System.Dec(k);
    zz[zzOff + k] := UInt32((p shr 1));
    c := UInt32(p);
  until (not(j > 0));

  for I := 1 to System.Pred(len) do
  begin
    c := SquareWordAdd(x, xOff, I, zz, zzOff);
    AddWordAt(extLen, c, zz, zzOff, I shl 1);
  end;

  ShiftUpBit(extLen, zz, zzOff, x[xOff] shl 31);
end;

class function TNat.Sub(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
  y: TCryptoLibUInt32Array; yOff: Int32; z: TCryptoLibUInt32Array;
  zOff: Int32): Int32;
var
  c: Int64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do

  begin
    c := c + (Int64(x[xOff + I]) - y[yOff + I]);
    z[zOff + I] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  Result := Int32(c);
end;

class function TNat.Sub(len: Int32; x, y, z: TCryptoLibUInt32Array): Int32;
var
  c: Int64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do

  begin
    c := c + (Int64(x[I]) - y[I]);
    z[I] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  Result := Int32(c);
end;

class function TNat.Sub33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zPos: Int32): Int32;
var
  c: Int64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := Int64(z[zPos + 0]) - x;
  z[zPos + 0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[zPos + 1]) - 1);
  z[zPos + 1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zPos + 2);
  end;
end;

class function TNat.Sub33At(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): Int32;
var
  c: Int64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := Int64(z[zOff + zPos]) - x;
  z[zOff + zPos] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[zOff + zPos + 1]) - 1);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zOff, zPos + 2);
  end;
end;

class function TNat.Sub33From(len: Int32; x: UInt32;
  z: TCryptoLibUInt32Array): Int32;
var
  c: Int64;
begin
  c := Int64(z[0]) - x;
  z[0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[1]) - 1);
  z[1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, 2);
  end;

end;

class function TNat.Sub33From(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff: Int32): Int32;
var
  c: Int64;
begin
  c := Int64(z[zOff + 0]) - x;
  z[zOff + 0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[zOff + 1]) - 1);
  z[zOff + 1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zOff, 2);
  end;
end;

class function TNat.SubBothFrom(len: Int32;
  x, y, z: TCryptoLibUInt32Array): Int32;
var
  c: Int64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do

  begin
    c := c + (Int64(z[I]) - x[I] - y[I]);
    z[I] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  Result := Int32(c);
end;

class function TNat.SubBothFrom(len: Int32; x: TCryptoLibUInt32Array;
  xOff: Int32; y: TCryptoLibUInt32Array; yOff: Int32; z: TCryptoLibUInt32Array;
  zOff: Int32): Int32;
var
  c: Int64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do

  begin
    c := c + (Int64(z[zOff + I]) - x[xOff + I] - y[yOff + I]);
    z[zOff + I] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  Result := Int32(c);
end;

class function TNat.SubDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): Int32;
var
  c: Int64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := Int64(z[zOff + zPos]) - Int64(x and M);
  z[zOff + zPos] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[zOff + zPos + 1]) - Int64(x shr 32));
  z[zOff + zPos + 1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zOff, zPos + 2);
  end;
end;

class function TNat.SubDWordAt(len: Int32; x: UInt64; z: TCryptoLibUInt32Array;
  zPos: Int32): Int32;
var
  c: Int64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 2));
{$ENDIF DEBUG}
  c := Int64(z[zPos + 0]) - Int64(x and M);
  z[zPos + 0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[zPos + 1]) - Int64(x shr 32));
  z[zPos + 1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zPos + 2);
  end;

end;

class function TNat.SubDWordFrom(len: Int32; x: UInt64;
  z: TCryptoLibUInt32Array; zOff: Int32): Int32;
var
  c: Int64;
begin
  c := Int64(z[zOff + 0]) - Int64(x and M);
  z[zOff + 0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[zOff + 1]) - Int64(x shr 32));
  z[zOff + 1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zOff, 2);
  end;
end;

class function TNat.SubDWordFrom(len: Int32; x: UInt64;
  z: TCryptoLibUInt32Array): Int32;
var
  c: Int64;
begin
  c := Int64(z[0]) - Int64(x and M);
  z[0] := UInt32(c);
  c := TBits.Asr64(c, 32);
  c := c + (Int64(z[1]) - Int64(x shr 32));
  z[1] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, 2);
  end;
end;

class function TNat.SubFrom(len: Int32; x, z: TCryptoLibUInt32Array): Int32;
var
  c: Int64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do

  begin
    c := c + (Int64(z[I]) - x[I]);
    z[I] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  Result := Int32(c);
end;

class function TNat.SubFrom(len: Int32; x: TCryptoLibUInt32Array; xOff: Int32;
  z: TCryptoLibUInt32Array; zOff: Int32): Int32;
var
  c: Int64;
  I: Int32;
begin
  c := 0;
  for I := 0 to System.Pred(len) do

  begin
    c := c + (Int64(z[zOff + I]) - x[xOff + I]);
    z[zOff + I] := UInt32(c);
    c := TBits.Asr64(c, 32);
  end;
  Result := Int32(c);
end;

class function TNat.SubWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zPos: Int32): Int32;
var
  c: Int64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 1));
{$ENDIF DEBUG}
  c := Int64(z[zPos]) - x;
  z[zPos] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zPos + 1);
  end;

end;

class function TNat.SubWordAt(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff, zPos: Int32): Int32;
var
  c: Int64;
begin
{$IFDEF DEBUG}
  System.Assert(zPos <= (len - 1));
{$ENDIF DEBUG}
  c := Int64(z[zOff + zPos]) - x;
  z[zOff + zPos] := UInt32(c);
  c := TBits.Asr64(c, 32);
  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zOff, zPos + 1);
  end;

end;

class function TNat.SubWordFrom(len: Int32; x: UInt32; z: TCryptoLibUInt32Array;
  zOff: Int32): Int32;
var
  c: Int64;
begin
  c := Int64(z[zOff + 0]) - x;
  z[zOff + 0] := UInt32(c);
  c := TBits.Asr64(c, 32);

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, zOff, 1);
  end;

end;

class function TNat.SubWordFrom(len: Int32; x: UInt32;
  z: TCryptoLibUInt32Array): Int32;
var
  c: Int64;
begin
  c := Int64(z[0]) - x;
  z[0] := UInt32(c);
  c := TBits.Asr64(c, 32);

  if c = 0 then
  begin
    Result := 0;
  end
  else
  begin
    Result := DecAt(len, z, 1);
  end;

end;

class function TNat.ToBigInteger(len: Int32; x: TCryptoLibUInt32Array)
  : TBigInteger;
var
  bs, temp: TCryptoLibByteArray;
  I: Int32;
  x_i: UInt32;
begin
  System.SetLength(bs, len shl 2);
  for I := 0 to System.Pred(len) do

  begin
    x_i := x[I];
    if (x_i <> 0) then
    begin
      temp := TConverters.ReadUInt32AsBytesBE(x_i);
      System.Move(temp[0], bs[(len - 1 - I) shl 2], System.Length(temp) *
        System.SizeOf(Byte))
    end;
  end;
  Result := TBigInteger.Create(1, bs);
end;

class procedure TNat.Zero(len: Int32; z: TCryptoLibUInt32Array);
begin
  System.FillChar(z[0], len * System.SizeOf(UInt32), UInt32(0));
end;

end.
