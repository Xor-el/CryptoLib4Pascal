{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpNat512;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpNat,
  ClpNat256,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  TNat512 = class sealed
  public
    class procedure Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); static;
    class procedure Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); static;

    class procedure &Xor(const AX: TCryptoLibUInt32Array; AY: UInt32; AZ: TCryptoLibUInt32Array); overload; static;
    class procedure &Xor(const AX: TCryptoLibUInt32Array; AXOff: Int32; AY: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;

    class procedure &Xor(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array); overload; static;
    class procedure &Xor(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;

    class procedure Xor64(const AX: TCryptoLibUInt64Array; AY: UInt64; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Xor64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AY: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;

    class procedure Xor64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Xor64(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;

    class procedure XorBothTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array); overload; static;
    class procedure XorBothTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;

    class procedure XorBothTo64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure XorBothTo64(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;

    class procedure XorTo(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array); overload; static;
    class procedure XorTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;

    class procedure XorTo64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure XorTo64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;

    class procedure XorToEachOther(AU: TCryptoLibUInt32Array; AV: TCryptoLibUInt32Array); overload; static;
    class procedure XorToEachOther(AU: TCryptoLibUInt32Array; AUOff: Int32; AV: TCryptoLibUInt32Array; AVOff: Int32); overload; static;
    class procedure XorToEachOther64(AU: TCryptoLibUInt64Array; AV: TCryptoLibUInt64Array); overload; static;
    class procedure XorToEachOther64(AU: TCryptoLibUInt64Array; AUOff: Int32; AV: TCryptoLibUInt64Array; AVOff: Int32); overload; static;

    class procedure Zero(AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Zero(AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure Zero64(AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Zero64(AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
  end;

implementation

{ TNat512 }

class procedure TNat512.Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LC24, LC16: UInt32;
  LDx, LDy, LTt: TCryptoLibUInt32Array;
  LNeg: Boolean;
begin
  TNat256.Mul(AX, AY, AZz);
  TNat256.Mul(AX, 8, AY, 8, AZz, 16);

  LC24 := TNat256.AddToEachOther(AZz, 8, AZz, 16);
  LC16 := LC24 + TNat256.AddTo(AZz, 0, AZz, 8, 0);
  LC24 := LC24 + TNat256.AddTo(AZz, 24, AZz, 16, LC16);

  LDx := TNat256.Create();
  LDy := TNat256.Create();
  LNeg := TNat256.Diff(AX, 8, AX, 0, LDx, 0) <> TNat256.Diff(AY, 8, AY, 0, LDy, 0);

  LTt := TNat256.CreateExt();
  TNat256.Mul(LDx, LDy, LTt);

  if LNeg then
  begin
    LC24 := LC24 + TNat.AddTo(16, LTt, 0, AZz, 8);
  end
  else
  begin
    LC24 := LC24 + UInt32(TNat.SubFrom(16, LTt, 0, AZz, 8));
  end;

  TNat.AddWordAt(32, LC24, AZz, 24);
end;

class procedure TNat512.Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LC24, LC16: UInt32;
  LDx, LM: TCryptoLibUInt32Array;
begin
  TNat256.Square(AX, AZz);
  TNat256.Square(AX, 8, AZz, 16);

  LC24 := TNat256.AddToEachOther(AZz, 8, AZz, 16);
  LC16 := LC24 + TNat256.AddTo(AZz, 0, AZz, 8, 0);
  LC24 := LC24 + TNat256.AddTo(AZz, 24, AZz, 16, LC16);

  LDx := TNat256.Create();
  TNat256.Diff(AX, 8, AX, 0, LDx, 0);

  LM := TNat256.CreateExt();
  TNat256.Square(LDx, LM);

  LC24 := LC24 + UInt32(TNat.SubFrom(16, LM, 0, AZz, 8));
  TNat.AddWordAt(32, LC24, AZz, 24);
end;

class procedure TNat512.&Xor(const AX: TCryptoLibUInt32Array; AY: UInt32; AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[LI + 0] := AX[LI + 0] xor AY;
    AZ[LI + 1] := AX[LI + 1] xor AY;
    AZ[LI + 2] := AX[LI + 2] xor AY;
    AZ[LI + 3] := AX[LI + 3] xor AY;
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.&Xor(const AX: TCryptoLibUInt32Array; AXOff: Int32; AY: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[AZOff + LI + 0] := AX[AXOff + LI + 0] xor AY;
    AZ[AZOff + LI + 1] := AX[AXOff + LI + 1] xor AY;
    AZ[AZOff + LI + 2] := AX[AXOff + LI + 2] xor AY;
    AZ[AZOff + LI + 3] := AX[AXOff + LI + 3] xor AY;
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.&Xor(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[LI + 0] := AX[LI + 0] xor AY[LI + 0];
    AZ[LI + 1] := AX[LI + 1] xor AY[LI + 1];
    AZ[LI + 2] := AX[LI + 2] xor AY[LI + 2];
    AZ[LI + 3] := AX[LI + 3] xor AY[LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.&Xor(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[AZOff + LI + 0] := AX[AXOff + LI + 0] xor AY[AYOff + LI + 0];
    AZ[AZOff + LI + 1] := AX[AXOff + LI + 1] xor AY[AYOff + LI + 1];
    AZ[AZOff + LI + 2] := AX[AXOff + LI + 2] xor AY[AYOff + LI + 2];
    AZ[AZOff + LI + 3] := AX[AXOff + LI + 3] xor AY[AYOff + LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.Xor64(const AX: TCryptoLibUInt64Array; AY: UInt64; AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[LI + 0] := AX[LI + 0] xor AY;
    AZ[LI + 1] := AX[LI + 1] xor AY;
    AZ[LI + 2] := AX[LI + 2] xor AY;
    AZ[LI + 3] := AX[LI + 3] xor AY;
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.Xor64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AY: UInt64; AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[AZOff + LI + 0] := AX[AXOff + LI + 0] xor AY;
    AZ[AZOff + LI + 1] := AX[AXOff + LI + 1] xor AY;
    AZ[AZOff + LI + 2] := AX[AXOff + LI + 2] xor AY;
    AZ[AZOff + LI + 3] := AX[AXOff + LI + 3] xor AY;
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.Xor64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[LI + 0] := AX[LI + 0] xor AY[LI + 0];
    AZ[LI + 1] := AX[LI + 1] xor AY[LI + 1];
    AZ[LI + 2] := AX[LI + 2] xor AY[LI + 2];
    AZ[LI + 3] := AX[LI + 3] xor AY[LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.Xor64(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[AZOff + LI + 0] := AX[AXOff + LI + 0] xor AY[AYOff + LI + 0];
    AZ[AZOff + LI + 1] := AX[AXOff + LI + 1] xor AY[AYOff + LI + 1];
    AZ[AZOff + LI + 2] := AX[AXOff + LI + 2] xor AY[AYOff + LI + 2];
    AZ[AZOff + LI + 3] := AX[AXOff + LI + 3] xor AY[AYOff + LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorBothTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[LI + 0] := AZ[LI + 0] xor AX[LI + 0] xor AY[LI + 0];
    AZ[LI + 1] := AZ[LI + 1] xor AX[LI + 1] xor AY[LI + 1];
    AZ[LI + 2] := AZ[LI + 2] xor AX[LI + 2] xor AY[LI + 2];
    AZ[LI + 3] := AZ[LI + 3] xor AX[LI + 3] xor AY[LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorBothTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[AZOff + LI + 0] := AZ[AZOff + LI + 0] xor AX[AXOff + LI + 0] xor AY[AYOff + LI + 0];
    AZ[AZOff + LI + 1] := AZ[AZOff + LI + 1] xor AX[AXOff + LI + 1] xor AY[AYOff + LI + 1];
    AZ[AZOff + LI + 2] := AZ[AZOff + LI + 2] xor AX[AXOff + LI + 2] xor AY[AYOff + LI + 2];
    AZ[AZOff + LI + 3] := AZ[AZOff + LI + 3] xor AX[AXOff + LI + 3] xor AY[AYOff + LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorBothTo64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[LI + 0] := AZ[LI + 0] xor AX[LI + 0] xor AY[LI + 0];
    AZ[LI + 1] := AZ[LI + 1] xor AX[LI + 1] xor AY[LI + 1];
    AZ[LI + 2] := AZ[LI + 2] xor AX[LI + 2] xor AY[LI + 2];
    AZ[LI + 3] := AZ[LI + 3] xor AX[LI + 3] xor AY[LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorBothTo64(const AX: TCryptoLibUInt64Array; AXOff: Int32; const AY: TCryptoLibUInt64Array; AYOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[AZOff + LI + 0] := AZ[AZOff + LI + 0] xor AX[AXOff + LI + 0] xor AY[AYOff + LI + 0];
    AZ[AZOff + LI + 1] := AZ[AZOff + LI + 1] xor AX[AXOff + LI + 1] xor AY[AYOff + LI + 1];
    AZ[AZOff + LI + 2] := AZ[AZOff + LI + 2] xor AX[AXOff + LI + 2] xor AY[AYOff + LI + 2];
    AZ[AZOff + LI + 3] := AZ[AZOff + LI + 3] xor AX[AXOff + LI + 3] xor AY[AYOff + LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorTo(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[LI + 0] := AZ[LI + 0] xor AX[LI + 0];
    AZ[LI + 1] := AZ[LI + 1] xor AX[LI + 1];
    AZ[LI + 2] := AZ[LI + 2] xor AX[LI + 2];
    AZ[LI + 3] := AZ[LI + 3] xor AX[LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 16 do
  begin
    AZ[AZOff + LI + 0] := AZ[AZOff + LI + 0] xor AX[AXOff + LI + 0];
    AZ[AZOff + LI + 1] := AZ[AZOff + LI + 1] xor AX[AXOff + LI + 1];
    AZ[AZOff + LI + 2] := AZ[AZOff + LI + 2] xor AX[AXOff + LI + 2];
    AZ[AZOff + LI + 3] := AZ[AZOff + LI + 3] xor AX[AXOff + LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorTo64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[LI + 0] := AZ[LI + 0] xor AX[LI + 0];
    AZ[LI + 1] := AZ[LI + 1] xor AX[LI + 1];
    AZ[LI + 2] := AZ[LI + 2] xor AX[LI + 2];
    AZ[LI + 3] := AZ[LI + 3] xor AX[LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorTo64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < 8 do
  begin
    AZ[AZOff + LI + 0] := AZ[AZOff + LI + 0] xor AX[AXOff + LI + 0];
    AZ[AZOff + LI + 1] := AZ[AZOff + LI + 1] xor AX[AXOff + LI + 1];
    AZ[AZOff + LI + 2] := AZ[AZOff + LI + 2] xor AX[AXOff + LI + 2];
    AZ[AZOff + LI + 3] := AZ[AZOff + LI + 3] xor AX[AXOff + LI + 3];
    System.Inc(LI, 4);
  end;
end;

class procedure TNat512.XorToEachOther(AU: TCryptoLibUInt32Array; AV: TCryptoLibUInt32Array);
begin
  TNat512.XorToEachOther(AU, 0, AV, 0);
end;

class procedure TNat512.XorToEachOther(AU: TCryptoLibUInt32Array; AUOff: Int32; AV: TCryptoLibUInt32Array; AVOff: Int32);
var
  LI: Int32;
  LT: UInt32;
begin
  for LI := 0 to 15 do
  begin
    LT := AU[AUOff + LI] xor AV[AVOff + LI];
    AU[AUOff + LI] := LT;
    AV[AVOff + LI] := LT;
  end;
end;

class procedure TNat512.XorToEachOther64(AU: TCryptoLibUInt64Array; AV: TCryptoLibUInt64Array);
begin
  TNat512.XorToEachOther64(AU, 0, AV, 0);
end;

class procedure TNat512.XorToEachOther64(AU: TCryptoLibUInt64Array; AUOff: Int32; AV: TCryptoLibUInt64Array; AVOff: Int32);
var
  LI: Int32;
  LT: UInt64;
begin
  for LI := 0 to 7 do
  begin
    LT := AU[AUOff + LI] xor AV[AVOff + LI];
    AU[AUOff + LI] := LT;
    AV[AVOff + LI] := LT;
  end;
end;

class procedure TNat512.Zero(AZ: TCryptoLibUInt32Array);
begin
  TArrayUtilities.Fill<UInt32>(AZ, 0, 16, UInt32(0));
end;

class procedure TNat512.Zero(AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  TArrayUtilities.Fill<UInt32>(AZ, AZOff, AZOff + 16, UInt32(0));
end;

class procedure TNat512.Zero64(AZ: TCryptoLibUInt64Array);
begin
  TArrayUtilities.Fill<UInt64>(AZ, 0, 8, UInt64(0));
end;

class procedure TNat512.Zero64(AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  TArrayUtilities.Fill<UInt64>(AZ, AZOff, AZOff + 8, UInt64(0));
end;

end.
