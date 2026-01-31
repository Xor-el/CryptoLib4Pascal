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

unit ClpNat192;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtilities,
  ClpNat,
  ClpPack,
  ClpBigInteger,
  ClpBitUtilities,
  ClpCryptoLibTypes;

type
  TNat192 = class sealed
  strict private
    const M: UInt64 = $FFFFFFFF;
  public
    class function Add(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; static;
    class function AddBothTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; static;
    class function AddTo(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function AddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: UInt32): UInt32; overload; static;
    class function AddToEachOther(AU: TCryptoLibUInt32Array; AUOff: Int32; AV: TCryptoLibUInt32Array; AVOff: Int32): UInt32; static;
    class procedure Copy(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class function Create(): TCryptoLibUInt32Array; static;
    class function Create64(): TCryptoLibUInt64Array; static;
    class function CreateExt(): TCryptoLibUInt32Array; static;
    class function CreateExt64(): TCryptoLibUInt64Array; static;
    class function Diff(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): Boolean; static;
    class function Eq(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean; static;
    class function Eq64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array): Boolean; static;
    class function GetBit(const AX: TCryptoLibUInt32Array; ABit: Int32): UInt32; static;
    class function Gte(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean; overload; static;
    class function Gte(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Boolean; overload; static;
    class function IsOne(const AX: TCryptoLibUInt32Array): Boolean; static;
    class function IsOne64(const AX: TCryptoLibUInt64Array): Boolean; static;
    class function IsZero(const AX: TCryptoLibUInt32Array): Boolean; static;
    class procedure Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); overload; static;
    class procedure Mul(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32); overload; static;
    class function MulAddTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array): UInt32; overload; static;
    class function MulAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32; overload; static;
    class function Mul33Add(AW: UInt32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt64; static;
    class function MulWordAddExt(AX: UInt32; const AYy: TCryptoLibUInt32Array; AYyOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32; static;
    class function Mul33DWordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function Mul33WordAdd(AX: UInt32; AY: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function MulWordDwordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWord(AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class procedure Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); overload; static;
    class procedure Square(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32); overload; static;
    class function Sub(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function Sub(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function SubBothFrom(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; static;
    class function SubFrom(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function SubFrom(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function ToBigInteger(const AX: TCryptoLibUInt32Array): TBigInteger; static;
    class function ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger; static;
    class procedure Zero(AZ: TCryptoLibUInt32Array); static;
  end;

implementation

class function TNat192.Add(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + UInt64(AX[0]) + AY[0];
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[1]) + AY[1];
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[2]) + AY[2];
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[3]) + AY[3];
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[4]) + AY[4];
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[5]) + AY[5];
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat192.AddBothTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + UInt64(AX[0]) + AY[0] + AZ[0];
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[1]) + AY[1] + AZ[1];
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[2]) + AY[2] + AZ[2];
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[3]) + AY[3] + AZ[3];
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[4]) + AY[4] + AZ[4];
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[5]) + AY[5] + AZ[5];
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat192.AddTo(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + UInt64(AX[0]) + AZ[0];
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[1]) + AZ[1];
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[2]) + AZ[2];
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[3]) + AZ[3];
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[4]) + AZ[4];
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[5]) + AZ[5];
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat192.AddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: UInt32): UInt32;
var
  LC: UInt64;
begin
  LC := ACIn;
  LC := LC + UInt64(AX[AXOff + 0]) + AZ[AZOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[AXOff + 1]) + AZ[AZOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[AXOff + 2]) + AZ[AZOff + 2];
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[AXOff + 3]) + AZ[AZOff + 3];
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[AXOff + 4]) + AZ[AZOff + 4];
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AX[AXOff + 5]) + AZ[AZOff + 5];
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat192.AddToEachOther(AU: TCryptoLibUInt32Array; AUOff: Int32; AV: TCryptoLibUInt32Array; AVOff: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + UInt64(AU[AUOff + 0]) + AV[AVOff + 0];
  AU[AUOff + 0] := UInt32(LC);
  AV[AVOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AU[AUOff + 1]) + AV[AVOff + 1];
  AU[AUOff + 1] := UInt32(LC);
  AV[AVOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AU[AUOff + 2]) + AV[AVOff + 2];
  AU[AUOff + 2] := UInt32(LC);
  AV[AVOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AU[AUOff + 3]) + AV[AVOff + 3];
  AU[AUOff + 3] := UInt32(LC);
  AV[AVOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AU[AUOff + 4]) + AV[AVOff + 4];
  AU[AUOff + 4] := UInt32(LC);
  AV[AVOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + UInt64(AU[AUOff + 5]) + AV[AVOff + 5];
  AU[AUOff + 5] := UInt32(LC);
  AV[AVOff + 5] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class procedure TNat192.Copy(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
begin
  System.Move(AX[0], AZ[0], 6 * System.SizeOf(UInt32));
end;

class procedure TNat192.Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], 6 * System.SizeOf(UInt32));
end;

class procedure TNat192.Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
begin
  System.Move(AX[0], AZ[0], 3 * System.SizeOf(UInt64));
end;

class procedure TNat192.Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], 3 * System.SizeOf(UInt64));
end;

class function TNat192.Create(): TCryptoLibUInt32Array;
begin
  SetLength(Result, 6);
  Exit;
end;

class function TNat192.Create64(): TCryptoLibUInt64Array;
begin
  SetLength(Result, 3);
  Exit;
end;

class function TNat192.CreateExt(): TCryptoLibUInt32Array;
begin
  SetLength(Result, 12);
  Exit;
end;

class function TNat192.CreateExt64(): TCryptoLibUInt64Array;
begin
  SetLength(Result, 6);
  Exit;
end;

class function TNat192.Diff(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): Boolean;
var
  LPos: Boolean;
begin
  LPos := Gte(AX, AXOff, AY, AYOff);
  if LPos then
  Sub(AX, AXOff, AY, AYOff, AZ, AZOff)
  else
  Sub(AY, AYOff, AX, AXOff, AZ, AZOff);
  Result := LPos;
end;

class function TNat192.Eq(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  for LI := 5 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat192.Eq64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  for LI := 2 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat192.GetBit(const AX: TCryptoLibUInt32Array; ABit: Int32): UInt32;
var
  LW: Int32;
  LB: Int32;
begin
  if ABit = 0 then
  begin
    Result := AX[0] and 1;
    Exit;
  end;
  LW := TBitUtilities.Asr32(ABit, 5);
  if (LW < 0) or (LW >= 6) then
  begin
    Result := 0;
    Exit;
  end;
  LB := ABit and 31;
  Result := (AX[LW] shr LB) and 1;
end;

class function TNat192.Gte(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
  LXI: UInt32;
  LYI: UInt32;
begin
  for LI := 5 downto 0 do
  begin
    LXI := AX[LI];
    LYI := AY[LI];
    if LXI < LYI then
    begin
      Result := False;
      Exit;
    end;
    if LXI > LYI then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat192.Gte(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Boolean;
var
  LI: Int32;
  LXI: UInt32;
  LYI: UInt32;
begin
  for LI := 5 downto 0 do
  begin
    LXI := AX[AXOff + LI];
    LYI := AY[AYOff + LI];
    if LXI < LYI then
    begin
      Result := False;
      Exit;
    end;
    if LXI > LYI then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat192.IsOne(const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> 1 then
  begin
    Result := False;
    Exit;
  end;
  for LI := 1 to 5 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat192.IsOne64(const AX: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> UInt64(1) then
  begin
    Result := False;
    Exit;
  end;
  for LI := 1 to 2 do
  begin
    if AX[LI] <> UInt64(0) then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat192.IsZero(const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to 5 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class procedure TNat192.Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LY0: UInt64;
  LY1: UInt64;
  LY2: UInt64;
  LY3: UInt64;
  LY4: UInt64;
  LY5: UInt64;
  LC: UInt64;
  LX0: UInt64;
  LI: Int32;
  LXI: UInt64;
begin
  LY0 := AY[0];
  LY1 := AY[1];
  LY2 := AY[2];
  LY3 := AY[3];
  LY4 := AY[4];
  LY5 := AY[5];
  LC := 0;
  LX0 := AX[0];
  LC := LC + (LX0 * LY0);
  AZz[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY1);
  AZz[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY2);
  AZz[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY3);
  AZz[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY4);
  AZz[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY5);
  AZz[5] := UInt32(LC);
  LC := LC shr 32;
  AZz[6] := UInt32(LC);
  for LI := 1 to 5 do
  begin
    LC := 0;
    LXI := AX[LI];
    LC := LC + (LXI * LY0 + AZz[LI + 0]);
    AZz[LI + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY1 + AZz[LI + 1]);
    AZz[LI + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY2 + AZz[LI + 2]);
    AZz[LI + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY3 + AZz[LI + 3]);
    AZz[LI + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY4 + AZz[LI + 4]);
    AZz[LI + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY5 + AZz[LI + 5]);
    AZz[LI + 5] := UInt32(LC);
    LC := LC shr 32;
    AZz[LI + 6] := UInt32(LC);
  end;
end;

class procedure TNat192.Mul(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32);
var
  LY0: UInt64;
  LY1: UInt64;
  LY2: UInt64;
  LY3: UInt64;
  LY4: UInt64;
  LY5: UInt64;
  LC: UInt64;
  LX0: UInt64;
  LI: Int32;
  LXI: UInt64;
begin
  LY0 := AY[AYOff + 0];
  LY1 := AY[AYOff + 1];
  LY2 := AY[AYOff + 2];
  LY3 := AY[AYOff + 3];
  LY4 := AY[AYOff + 4];
  LY5 := AY[AYOff + 5];
  LC := 0;
  LX0 := AX[AXOff + 0];
  LC := LC + (LX0 * LY0);
  AZz[AZzOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY1);
  AZz[AZzOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY2);
  AZz[AZzOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY3);
  AZz[AZzOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY4);
  AZz[AZzOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX0 * LY5);
  AZz[AZzOff + 5] := UInt32(LC);
  LC := LC shr 32;
  AZz[AZzOff + 6] := UInt32(LC);
  for LI := 1 to 5 do
  begin
    Inc(AZzOff);
    LC := 0;
    LXI := AX[AXOff + LI];
    LC := LC + (LXI * LY0 + AZz[AZzOff + 0]);
    AZz[AZzOff + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY1 + AZz[AZzOff + 1]);
    AZz[AZzOff + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY2 + AZz[AZzOff + 2]);
    AZz[AZzOff + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY3 + AZz[AZzOff + 3]);
    AZz[AZzOff + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY4 + AZz[AZzOff + 4]);
    AZz[AZzOff + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY5 + AZz[AZzOff + 5]);
    AZz[AZzOff + 5] := UInt32(LC);
    LC := LC shr 32;
    AZz[AZzOff + 6] := UInt32(LC);
  end;
end;

class function TNat192.MulAddTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array): UInt32;
var
  LY0: UInt64;
  LY1: UInt64;
  LY2: UInt64;
  LY3: UInt64;
  LY4: UInt64;
  LY5: UInt64;
  LZc: UInt64;
  LI: Int32;
  LC: UInt64;
  LXI: UInt64;
begin
  LY0 := AY[0];
  LY1 := AY[1];
  LY2 := AY[2];
  LY3 := AY[3];
  LY4 := AY[4];
  LY5 := AY[5];
  LZc := 0;
  for LI := 0 to 5 do
  begin
    LC := 0;
    LXI := AX[LI];
    LC := LC + (LXI * LY0 + AZz[LI + 0]);
    AZz[LI + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY1 + AZz[LI + 1]);
    AZz[LI + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY2 + AZz[LI + 2]);
    AZz[LI + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY3 + AZz[LI + 3]);
    AZz[LI + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY4 + AZz[LI + 4]);
    AZz[LI + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY5 + AZz[LI + 5]);
    AZz[LI + 5] := UInt32(LC);
    LC := LC shr 32;
    LZc := LZc + (LC + AZz[LI + 6]);
    AZz[LI + 6] := UInt32(LZc);
    LZc := LZc shr 32;
  end;
  Result := UInt32(LZc);
end;

class function TNat192.MulAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32;
var
  LY0: UInt64;
  LY1: UInt64;
  LY2: UInt64;
  LY3: UInt64;
  LY4: UInt64;
  LY5: UInt64;
  LZc: UInt64;
  LI: Int32;
  LC: UInt64;
  LXI: UInt64;
begin
  LY0 := AY[AYOff + 0];
  LY1 := AY[AYOff + 1];
  LY2 := AY[AYOff + 2];
  LY3 := AY[AYOff + 3];
  LY4 := AY[AYOff + 4];
  LY5 := AY[AYOff + 5];
  LZc := 0;
  for LI := 0 to 5 do
  begin
    LC := 0;
    LXI := AX[AXOff + LI];
    LC := LC + (LXI * LY0 + AZz[AZzOff + 0]);
    AZz[AZzOff + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY1 + AZz[AZzOff + 1]);
    AZz[AZzOff + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY2 + AZz[AZzOff + 2]);
    AZz[AZzOff + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY3 + AZz[AZzOff + 3]);
    AZz[AZzOff + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY4 + AZz[AZzOff + 4]);
    AZz[AZzOff + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LXI * LY5 + AZz[AZzOff + 5]);
    AZz[AZzOff + 5] := UInt32(LC);
    LC := LC shr 32;
    LZc := LZc + (LC + AZz[AZzOff + 6]);
    AZz[AZzOff + 6] := UInt32(LZc);
    LZc := LZc shr 32;
    Inc(AZzOff);
  end;
  Result := UInt32(LZc);
end;

class function TNat192.Mul33Add(AW: UInt32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt64;
var
  LC: UInt64;
  LWVal: UInt64;
  LX0: UInt64;
  LX1: UInt64;
  LX2: UInt64;
  LX3: UInt64;
  LX4: UInt64;
  LX5: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AW shr 31 = 0);
  {$ENDIF}
  LC := 0;
  LWVal := AW;
  LX0 := AX[AXOff + 0];
  LC := LC + (LWVal * LX0 + AY[AYOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LX1 := AX[AXOff + 1];
  LC := LC + (LWVal * LX1 + LX0 + AY[AYOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LX2 := AX[AXOff + 2];
  LC := LC + (LWVal * LX2 + LX1 + AY[AYOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LX3 := AX[AXOff + 3];
  LC := LC + (LWVal * LX3 + LX2 + AY[AYOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LX4 := AX[AXOff + 4];
  LC := LC + (LWVal * LX4 + LX3 + AY[AYOff + 4]);
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LX5 := AX[AXOff + 5];
  LC := LC + (LWVal * LX5 + LX4 + AY[AYOff + 5]);
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX5);
  Result := LC;
end;

class function TNat192.MulWordAddExt(AX: UInt32; const AYy: TCryptoLibUInt32Array; AYyOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AYyOff <= 6);
  System.Assert(AZzOff <= 6);
  {$ENDIF}
  LC := 0;
  LXVal := AX;
  LC := LC + (LXVal * AYy[AYyOff + 0] + AZz[AZzOff + 0]);
  AZz[AZzOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AYy[AYyOff + 1] + AZz[AZzOff + 1]);
  AZz[AZzOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AYy[AYyOff + 2] + AZz[AZzOff + 2]);
  AZz[AZzOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AYy[AYyOff + 3] + AZz[AZzOff + 3]);
  AZz[AZzOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AYy[AYyOff + 4] + AZz[AZzOff + 4]);
  AZz[AZzOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AYy[AYyOff + 5] + AZz[AZzOff + 5]);
  AZz[AZzOff + 5] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat192.Mul33DWordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LY00: UInt64;
  LY01: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AX shr 31 = 0);
  System.Assert(AZOff <= 2);
  {$ENDIF}
  LC := 0;
  LXVal := AX;
  LY00 := AY and M;
  LC := LC + (LXVal * LY00 + AZ[AZOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LY01 := AY shr 32;
  LC := LC + (LXVal * LY01 + LY00 + AZ[AZOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LY01 + AZ[AZOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (AZ[AZOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  if LC = 0 then
    Result := 0
  else
    Result := TNat.IncAt(6, AZ, AZOff, 4);
end;

class function TNat192.Mul33WordAdd(AX: UInt32; AY: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LYVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AX shr 31 = 0);
  System.Assert(AZOff <= 3);
  {$ENDIF}
  LC := 0;
  LYVal := AY;
  LC := LC + (LYVal * AX + AZ[AZOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LYVal + AZ[AZOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (AZ[AZOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  if LC = 0 then
    Result := 0
  else
    Result := TNat.IncAt(6, AZ, AZOff, 3);
end;

class function TNat192.MulWordDwordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AZOff <= 3);
  {$ENDIF}
  LC := 0;
  LXVal := AX;
  LC := LC + (LXVal * AY + AZ[AZOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * (AY shr 32) + AZ[AZOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (AZ[AZOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  if LC = 0 then
    Result := 0
  else
    Result := TNat.IncAt(6, AZ, AZOff, 3);
end;

class function TNat192.MulWord(AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LXVal := AX;
  LI := 0;
  repeat
    LC := LC + (LXVal * AY[LI]);
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
    Inc(LI);
  until not (LI < 6);
  Result := UInt32(LC);
end;

class procedure TNat192.Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LX0: UInt64;
  LZz1: UInt64;
  LC: UInt32;
  LW: UInt32;
  LI: Int32;
  LJ: Int32;
  LXVal: UInt64;
  LP: UInt64;
  LX1: UInt64;
  LZz2: UInt64;
  LX2: UInt64;
  LZz3: UInt64;
  LZz4: UInt64;
  LX3: UInt64;
  LZz5: UInt64;
  LZz6: UInt64;
  LX4: UInt64;
  LZz7: UInt64;
  LZz8: UInt64;
  LX5: UInt64;
  LZz9: UInt64;
  LZz10: UInt64;
begin
  LX0 := AX[0];
  LC := 0;
  LI := 5;
  LJ := 12;
  repeat
    LXVal := AX[LI];
    Dec(LI);
    LP := LXVal * LXVal;
    Dec(LJ);
    AZz[LJ] := (LC shl 31) or UInt32((LP ) shr 33);
    Dec(LJ);
    AZz[LJ] := UInt32((LP ) shr 1);
    LC := UInt32(LP);
  until not (LI > 0);
  LP := LX0 * LX0;
  LZz1 := UInt64((LC ) shl 31) or (LP shr 33);
  AZz[0] := UInt32(LP);
  LC := UInt32((LP ) shr 32) and 1;
  LX1 := AX[1];
  LZz2 := AZz[2];
  LZz1 := LZz1 + (LX1 * LX0);
  LW := UInt32(LZz1);
  AZz[1] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz2 := LZz2 + (LZz1 shr 32);
  LX2 := AX[2];
  LZz3 := AZz[3];
  LZz4 := AZz[4];
  LZz2 := LZz2 + (LX2 * LX0);
  LW := UInt32(LZz2);
  AZz[2] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz3 := LZz3 + ((LZz2 shr 32) + LX2 * LX1);
  LZz4 := LZz4 + (LZz3 shr 32);
  LZz3 := LZz3 and M;
  LX3 := AX[3];
  LZz5 := AZz[5] + (LZz4 shr 32);
  LZz4 := LZz4 and M;
  LZz6 := AZz[6] + (LZz5 shr 32);
  LZz5 := LZz5 and M;
  LZz3 := LZz3 + (LX3 * LX0);
  LW := UInt32(LZz3);
  AZz[3] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz4 := LZz4 + ((LZz3 shr 32) + LX3 * LX1);
  LZz5 := LZz5 + ((LZz4 shr 32) + LX3 * LX2);
  LZz4 := LZz4 and M;
  LZz6 := LZz6 + (LZz5 shr 32);
  LZz5 := LZz5 and M;
  LX4 := AX[4];
  LZz7 := AZz[7] + (LZz6 shr 32);
  LZz6 := LZz6 and M;
  LZz8 := AZz[8] + (LZz7 shr 32);
  LZz7 := LZz7 and M;
  LZz4 := LZz4 + (LX4 * LX0);
  LW := UInt32(LZz4);
  AZz[4] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz5 := LZz5 + ((LZz4 shr 32) + LX4 * LX1);
  LZz6 := LZz6 + ((LZz5 shr 32) + LX4 * LX2);
  LZz5 := LZz5 and M;
  LZz7 := LZz7 + ((LZz6 shr 32) + LX4 * LX3);
  LZz6 := LZz6 and M;
  LZz8 := LZz8 + (LZz7 shr 32);
  LZz7 := LZz7 and M;
  LX5 := AX[5];
  LZz9 := AZz[9] + (LZz8 shr 32);
  LZz8 := LZz8 and M;
  LZz10 := AZz[10] + (LZz9 shr 32);
  LZz9 := LZz9 and M;
  LZz5 := LZz5 + (LX5 * LX0);
  LW := UInt32(LZz5);
  AZz[5] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz6 := LZz6 + ((LZz5 shr 32) + LX5 * LX1);
  LZz7 := LZz7 + ((LZz6 shr 32) + LX5 * LX2);
  LZz8 := LZz8 + ((LZz7 shr 32) + LX5 * LX3);
  LZz9 := LZz9 + ((LZz8 shr 32) + LX5 * LX4);
  LZz10 := LZz10 + (LZz9 shr 32);
  LW := UInt32(LZz6);
  AZz[6] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz7);
  AZz[7] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz8);
  AZz[8] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz9);
  AZz[9] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz10);
  AZz[10] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := AZz[11] + UInt32((LZz10 ) shr 32);
  AZz[11] := (LW shl 1) or LC;
end;

class procedure TNat192.Square(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32);
var
  LX0: UInt64;
  LZz1: UInt64;
  LC: UInt32;
  LW: UInt32;
  LI: Int32;
  LJ: Int32;
  LXVal: UInt64;
  LP: UInt64;
  LX1: UInt64;
  LZz2: UInt64;
  LX2: UInt64;
  LZz3: UInt64;
  LZz4: UInt64;
  LX3: UInt64;
  LZz5: UInt64;
  LZz6: UInt64;
  LX4: UInt64;
  LZz7: UInt64;
  LZz8: UInt64;
  LX5: UInt64;
  LZz9: UInt64;
  LZz10: UInt64;
begin
  LX0 := AX[AXOff + 0];
  LC := 0;
  LI := 5;
  LJ := 12;
  repeat
    LXVal := AX[AXOff + LI];
    Dec(LI);
    LP := LXVal * LXVal;
    Dec(LJ);
    AZz[AZzOff + LJ] := (LC shl 31) or UInt32((LP ) shr 33);
    Dec(LJ);
    AZz[AZzOff + LJ] := UInt32((LP ) shr 1);
    LC := UInt32(LP);
  until not (LI > 0);
  LP := LX0 * LX0;
  LZz1 := UInt64((LC ) shl 31) or (LP shr 33);
  AZz[AZzOff + 0] := UInt32(LP);
  LC := UInt32((LP ) shr 32) and 1;
  LX1 := AX[AXOff + 1];
  LZz2 := AZz[AZzOff + 2];
  LZz1 := LZz1 + (LX1 * LX0);
  LW := UInt32(LZz1);
  AZz[AZzOff + 1] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz2 := LZz2 + (LZz1 shr 32);
  LX2 := AX[AXOff + 2];
  LZz3 := AZz[AZzOff + 3];
  LZz4 := AZz[AZzOff + 4];
  LZz2 := LZz2 + (LX2 * LX0);
  LW := UInt32(LZz2);
  AZz[AZzOff + 2] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz3 := LZz3 + ((LZz2 shr 32) + LX2 * LX1);
  LZz4 := LZz4 + (LZz3 shr 32);
  LZz3 := LZz3 and M;
  LX3 := AX[AXOff + 3];
  LZz5 := AZz[AZzOff + 5] + (LZz4 shr 32);
  LZz4 := LZz4 and M;
  LZz6 := AZz[AZzOff + 6] + (LZz5 shr 32);
  LZz5 := LZz5 and M;
  LZz3 := LZz3 + (LX3 * LX0);
  LW := UInt32(LZz3);
  AZz[AZzOff + 3] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz4 := LZz4 + ((LZz3 shr 32) + LX3 * LX1);
  LZz5 := LZz5 + ((LZz4 shr 32) + LX3 * LX2);
  LZz4 := LZz4 and M;
  LZz6 := LZz6 + (LZz5 shr 32);
  LZz5 := LZz5 and M;
  LX4 := AX[AXOff + 4];
  LZz7 := AZz[AZzOff + 7] + (LZz6 shr 32);
  LZz6 := LZz6 and M;
  LZz8 := AZz[AZzOff + 8] + (LZz7 shr 32);
  LZz7 := LZz7 and M;
  LZz4 := LZz4 + (LX4 * LX0);
  LW := UInt32(LZz4);
  AZz[AZzOff + 4] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz5 := LZz5 + ((LZz4 shr 32) + LX4 * LX1);
  LZz6 := LZz6 + ((LZz5 shr 32) + LX4 * LX2);
  LZz5 := LZz5 and M;
  LZz7 := LZz7 + ((LZz6 shr 32) + LX4 * LX3);
  LZz6 := LZz6 and M;
  LZz8 := LZz8 + (LZz7 shr 32);
  LZz7 := LZz7 and M;
  LX5 := AX[AXOff + 5];
  LZz9 := AZz[AZzOff + 9] + (LZz8 shr 32);
  LZz8 := LZz8 and M;
  LZz10 := AZz[AZzOff + 10] + (LZz9 shr 32);
  LZz9 := LZz9 and M;
  LZz5 := LZz5 + (LX5 * LX0);
  LW := UInt32(LZz5);
  AZz[AZzOff + 5] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZz6 := LZz6 + ((LZz5 shr 32) + LX5 * LX1);
  LZz7 := LZz7 + ((LZz6 shr 32) + LX5 * LX2);
  LZz8 := LZz8 + ((LZz7 shr 32) + LX5 * LX3);
  LZz9 := LZz9 + ((LZz8 shr 32) + LX5 * LX4);
  LZz10 := LZz10 + (LZz9 shr 32);
  LW := UInt32(LZz6);
  AZz[AZzOff + 6] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz7);
  AZz[AZzOff + 7] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz8);
  AZz[AZzOff + 8] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz9);
  AZz[AZzOff + 9] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZz10);
  AZz[AZzOff + 10] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := AZz[AZzOff + 11] + UInt32((LZz10 ) shr 32);
  AZz[AZzOff + 11] := (LW shl 1) or LC;
end;

class function TNat192.Sub(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AX[0]) - Int64(AY[0]));
  AZ[0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[1]) - Int64(AY[1]));
  AZ[1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[2]) - Int64(AY[2]));
  AZ[2] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[3]) - Int64(AY[3]));
  AZ[3] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[4]) - Int64(AY[4]));
  AZ[4] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[5]) - Int64(AY[5]));
  AZ[5] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat192.Sub(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AX[AXOff + 0]) - Int64(AY[AYOff + 0]));
  AZ[AZOff + 0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[AXOff + 1]) - Int64(AY[AYOff + 1]));
  AZ[AZOff + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[AXOff + 2]) - Int64(AY[AYOff + 2]));
  AZ[AZOff + 2] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[AXOff + 3]) - Int64(AY[AYOff + 3]));
  AZ[AZOff + 3] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[AXOff + 4]) - Int64(AY[AYOff + 4]));
  AZ[AZOff + 4] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AX[AXOff + 5]) - Int64(AY[AYOff + 5]));
  AZ[AZOff + 5] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat192.SubBothFrom(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AZ[0]) - Int64(AX[0]) - Int64(AY[0]));
  AZ[0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[1]) - Int64(AX[1]) - Int64(AY[1]));
  AZ[1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[2]) - Int64(AX[2]) - Int64(AY[2]));
  AZ[2] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[3]) - Int64(AX[3]) - Int64(AY[3]));
  AZ[3] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[4]) - Int64(AX[4]) - Int64(AY[4]));
  AZ[4] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[5]) - Int64(AX[5]) - Int64(AY[5]));
  AZ[5] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat192.SubFrom(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AZ[0]) - Int64(AX[0]));
  AZ[0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[1]) - Int64(AX[1]));
  AZ[1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[2]) - Int64(AX[2]));
  AZ[2] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[3]) - Int64(AX[3]));
  AZ[3] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[4]) - Int64(AX[4]));
  AZ[4] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[5]) - Int64(AX[5]));
  AZ[5] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat192.SubFrom(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AZ[AZOff + 0]) - Int64(AX[AXOff + 0]));
  AZ[AZOff + 0] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZOff + 1]) - Int64(AX[AXOff + 1]));
  AZ[AZOff + 1] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZOff + 2]) - Int64(AX[AXOff + 2]));
  AZ[AZOff + 2] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZOff + 3]) - Int64(AX[AXOff + 3]));
  AZ[AZOff + 3] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZOff + 4]) - Int64(AX[AXOff + 4]));
  AZ[AZOff + 4] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  LC := LC + (Int64(AZ[AZOff + 5]) - Int64(AX[AXOff + 5]));
  AZ[AZOff + 5] := UInt32(LC);
  LC := TBitUtilities.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat192.ToBigInteger(const AX: TCryptoLibUInt32Array): TBigInteger;
var
  LBs: TCryptoLibByteArray;
  LI: Int32;
  LXI: UInt32;
begin
  SetLength(LBs, 24);
  for LI := 0 to 5 do
  begin
    LXI := AX[LI];
    if LXI <> 0 then
    TPack.UInt32_To_BE(LXI, LBs, (5 - LI) shl 2);
  end;
  Result := TBigInteger.Create(1, LBs);
end;

class function TNat192.ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger;
var
  LBs: TCryptoLibByteArray;
  LI: Int32;
  LXI: UInt64;
begin
  SetLength(LBs, 24);
  for LI := 0 to 2 do
  begin
    LXI := AX[LI];
    if LXI <> Int64(0) then
    TPack.UInt64_To_BE(LXI, LBs, (2 - LI) shl 3);
  end;
  Result := TBigInteger.Create(1, LBs);
end;

class procedure TNat192.Zero(AZ: TCryptoLibUInt32Array);
begin
  TArrayUtilities.Fill<UInt32>(AZ, 0, 6, UInt32(0));
end;

end.
