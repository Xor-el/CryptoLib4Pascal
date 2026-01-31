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

unit ClpNat256;

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
  TNat256 = class sealed
  strict private
  const
    M: UInt64 = $FFFFFFFF;
  public
    class function Add(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function Add(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function AddBothTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function AddBothTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; overload; static;
    class function AddTo(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; ACIn: UInt32): UInt32; overload; static;
    class function AddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: UInt32): UInt32; overload; static;
    class function AddToEachOther(const AU: TCryptoLibUInt32Array; AUOff: Int32; const AV: TCryptoLibUInt32Array; AVOff: Int32): UInt32; static;
    class procedure Copy(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array); overload; static;
    class procedure Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class function Create(): TCryptoLibUInt32Array; static;
    class function Create64(): TCryptoLibUInt64Array; static;
    class function CreateExt(): TCryptoLibUInt32Array; static;
    class function CreateExt64(): TCryptoLibUInt64Array; static;
    class function Diff(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Boolean; static;
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
    class procedure Mul128(const AX: TCryptoLibUInt32Array; const AY128: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); static;
    class function MulAddTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array): UInt32; overload; static;
    class function MulAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32; overload; static;
    class function Mul33Add(AW: UInt32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt64; static;
    class function MulByWord(AX: UInt32; AZ: TCryptoLibUInt32Array): UInt32; static;
    class function MulByWordAddTo(AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32; static;
    class function MulWordAddTo(AX: UInt32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function Mul33DWordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function Mul33WordAdd(AX: UInt32; AY: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWordDwordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWord(AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class procedure Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array); overload; static;
    class procedure Square(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32); overload; static;
    class function Sub(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function Sub(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;
    class function SubBothFrom(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32; static;
    class function SubFrom(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; ACIn: Int32): Int32; overload; static;
    class function SubFrom(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: Int32): Int32; overload; static;
    class function ToBigInteger(const AX: TCryptoLibUInt32Array): TBigInteger; static;
    class function ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger; static;
    class procedure &Xor(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32); static;
    class procedure Zero(AZ: TCryptoLibUInt32Array); static;
  end;

implementation

class function TNat256.Add(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + (UInt64(AX[0]) + AY[0]);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[1]) + AY[1]);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[2]) + AY[2]);
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[3]) + AY[3]);
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[4]) + AY[4]);
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[5]) + AY[5]);
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[6]) + AY[6]);
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[7]) + AY[7]);
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.Add(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + (UInt64(AX[AXOff + 0]) + AY[AYOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 1]) + AY[AYOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 2]) + AY[AYOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 3]) + AY[AYOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 4]) + AY[AYOff + 4]);
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 5]) + AY[AYOff + 5]);
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 6]) + AY[AYOff + 6]);
  AZ[AZOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 7]) + AY[AYOff + 7]);
  AZ[AZOff + 7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.AddBothTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + (UInt64(AX[0]) + AY[0] + AZ[0]);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[1]) + AY[1] + AZ[1]);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[2]) + AY[2] + AZ[2]);
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[3]) + AY[3] + AZ[3]);
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[4]) + AY[4] + AZ[4]);
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[5]) + AY[5] + AZ[5]);
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[6]) + AY[6] + AZ[6]);
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[7]) + AY[7] + AZ[7]);
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.AddBothTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + (UInt64(AX[AXOff + 0]) + AY[AYOff + 0] + AZ[AZOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 1]) + AY[AYOff + 1] + AZ[AZOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 2]) + AY[AYOff + 2] + AZ[AZOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 3]) + AY[AYOff + 3] + AZ[AZOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 4]) + AY[AYOff + 4] + AZ[AZOff + 4]);
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 5]) + AY[AYOff + 5] + AZ[AZOff + 5]);
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 6]) + AY[AYOff + 6] + AZ[AZOff + 6]);
  AZ[AZOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 7]) + AY[AYOff + 7] + AZ[AZOff + 7]);
  AZ[AZOff + 7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.AddTo(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; ACIn: UInt32): UInt32;
var
  LC: UInt64;
begin
  LC := ACIn;
  LC := LC + (UInt64(AX[0]) + AZ[0]);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[1]) + AZ[1]);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[2]) + AZ[2]);
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[3]) + AZ[3]);
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[4]) + AZ[4]);
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[5]) + AZ[5]);
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[6]) + AZ[6]);
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[7]) + AZ[7]);
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.AddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: UInt32): UInt32;
var
  LC: UInt64;
begin
  LC := ACIn;
  LC := LC + (UInt64(AX[AXOff + 0]) + AZ[AZOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 1]) + AZ[AZOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 2]) + AZ[AZOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 3]) + AZ[AZOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 4]) + AZ[AZOff + 4]);
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 5]) + AZ[AZOff + 5]);
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 6]) + AZ[AZOff + 6]);
  AZ[AZOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AX[AXOff + 7]) + AZ[AZOff + 7]);
  AZ[AZOff + 7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.AddToEachOther(const AU: TCryptoLibUInt32Array; AUOff: Int32; const AV: TCryptoLibUInt32Array; AVOff: Int32): UInt32;
var
  LC: UInt64;
begin
  LC := 0;
  LC := LC + (UInt64(AU[AUOff + 0]) + AV[AVOff + 0]);
  AU[AUOff + 0] := UInt32(LC);
  AV[AVOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AU[AUOff + 1]) + AV[AVOff + 1]);
  AU[AUOff + 1] := UInt32(LC);
  AV[AVOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AU[AUOff + 2]) + AV[AVOff + 2]);
  AU[AUOff + 2] := UInt32(LC);
  AV[AVOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AU[AUOff + 3]) + AV[AVOff + 3]);
  AU[AUOff + 3] := UInt32(LC);
  AV[AVOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AU[AUOff + 4]) + AV[AVOff + 4]);
  AU[AUOff + 4] := UInt32(LC);
  AV[AVOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AU[AUOff + 5]) + AV[AVOff + 5]);
  AU[AUOff + 5] := UInt32(LC);
  AV[AVOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AU[AUOff + 6]) + AV[AVOff + 6]);
  AU[AUOff + 6] := UInt32(LC);
  AV[AVOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (UInt64(AU[AUOff + 7]) + AV[AVOff + 7]);
  AU[AUOff + 7] := UInt32(LC);
  AV[AVOff + 7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class procedure TNat256.Copy(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array);
begin
  System.Move(AX[0], AZ[0], 8 * System.SizeOf(UInt32));
end;

class procedure TNat256.Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], 8 * System.SizeOf(UInt32));
end;

class procedure TNat256.Copy64(const AX: TCryptoLibUInt64Array; AZ: TCryptoLibUInt64Array);
begin
  System.Move(AX[0], AZ[0], 4 * System.SizeOf(UInt64));
end;

class procedure TNat256.Copy64(const AX: TCryptoLibUInt64Array; AXOff: Int32; AZ: TCryptoLibUInt64Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], 4 * System.SizeOf(UInt64));
end;

class function TNat256.Create(): TCryptoLibUInt32Array;
begin
  SetLength(Result, 8);
  Exit;
end;

class function TNat256.Create64(): TCryptoLibUInt64Array;
begin
  SetLength(Result, 4);
  Exit;
end;

class function TNat256.CreateExt(): TCryptoLibUInt32Array;
begin
  SetLength(Result, 16);
  Exit;
end;

class function TNat256.CreateExt64(): TCryptoLibUInt64Array;
begin
  SetLength(Result, 8);
  Exit;
end;

class function TNat256.Diff(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Boolean;
var
  LPos: Boolean;
begin
  LPos := Gte(AX, AXOff, AY, AYOff);
  if LPos then
  begin
    Sub(AX, AXOff, AY, AYOff, AZ, AZOff);
  end
  else
  begin
    Sub(AY, AYOff, AX, AXOff, AZ, AZOff);
  end;
  Result := LPos;
end;

class function TNat256.Eq(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  for LI := 7 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat256.Eq64(const AX: TCryptoLibUInt64Array; const AY: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  for LI := 3 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat256.GetBit(const AX: TCryptoLibUInt32Array; ABit: Int32): UInt32;
var
  LW: Int32;
  LB: Int32;
begin
  if ABit = 0 then
  begin
    Result := AX[0] and 1;
    Exit;
  end;
  if (ABit and 255) <> ABit then
  begin
    Result := 0;
    Exit;
  end;
  LW := TBitUtilities.Asr32(ABit, 5);
  LB := ABit and 31;
  Result := (AX[LW] shr LB) and 1;
end;

class function TNat256.Gte(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array): Boolean;
var
  LX_i: UInt32;
  LY_i: UInt32;
  LI: Int32;
begin
  for LI := 7 downto 0 do
  begin
    LX_i := AX[LI];
    LY_i := AY[LI];
    if LX_i < LY_i then
    begin
      Result := False;
      Exit;
    end;
    if LX_i > LY_i then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat256.Gte(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Boolean;
var
  LX_i: UInt32;
  LY_i: UInt32;
  LI: Int32;
begin
  for LI := 7 downto 0 do
  begin
    LX_i := AX[AXOff + LI];
    LY_i := AY[AYOff + LI];
    if LX_i < LY_i then
    begin
      Result := False;
      Exit;
    end;
    if LX_i > LY_i then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat256.IsOne(const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> 1 then
  begin
    Result := False;
    Exit;
  end;
  for LI := 1 to 7 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat256.IsOne64(const AX: TCryptoLibUInt64Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> UInt64(1) then
  begin
    Result := False;
    Exit;
  end;
  for LI := 1 to 3 do
  begin
    if AX[LI] <> UInt64(0) then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat256.IsZero(const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to 7 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class procedure TNat256.Mul(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LY_0: UInt64;
  LY_1: UInt64;
  LY_2: UInt64;
  LY_3: UInt64;
  LY_4: UInt64;
  LY_5: UInt64;
  LY_6: UInt64;
  LY_7: UInt64;
  LC: UInt64;
  LX_0: UInt64;
  LX_i: UInt64;
  LI: Int32;
begin
  LY_0 := AY[0];
  LY_1 := AY[1];
  LY_2 := AY[2];
  LY_3 := AY[3];
  LY_4 := AY[4];
  LY_5 := AY[5];
  LY_6 := AY[6];
  LY_7 := AY[7];
  begin
    LC := 0;
    LX_0 := AX[0];
    LC := LC + (LX_0 * LY_0);
    AZz[0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_1);
    AZz[1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_2);
    AZz[2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_3);
    AZz[3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_4);
    AZz[4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_5);
    AZz[5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_6);
    AZz[6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_7);
    AZz[7] := UInt32(LC);
    LC := LC shr 32;
    AZz[8] := UInt32(LC);
  end;
  for LI := 1 to 7 do
  begin
    LC := 0;
    LX_i := AX[LI];
    LC := LC + (LX_i * LY_0 + AZz[LI + 0]);
    AZz[LI + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_1 + AZz[LI + 1]);
    AZz[LI + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_2 + AZz[LI + 2]);
    AZz[LI + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_3 + AZz[LI + 3]);
    AZz[LI + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_4 + AZz[LI + 4]);
    AZz[LI + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_5 + AZz[LI + 5]);
    AZz[LI + 5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_6 + AZz[LI + 6]);
    AZz[LI + 6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_7 + AZz[LI + 7]);
    AZz[LI + 7] := UInt32(LC);
    LC := LC shr 32;
    AZz[LI + 8] := UInt32(LC);
  end;
end;

class procedure TNat256.Mul(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32);
var
  LY_0: UInt64;
  LY_1: UInt64;
  LY_2: UInt64;
  LY_3: UInt64;
  LY_4: UInt64;
  LY_5: UInt64;
  LY_6: UInt64;
  LY_7: UInt64;
  LC: UInt64;
  LX_0: UInt64;
  LX_i: UInt64;
  LI: Int32;
begin
  LY_0 := AY[AYOff + 0];
  LY_1 := AY[AYOff + 1];
  LY_2 := AY[AYOff + 2];
  LY_3 := AY[AYOff + 3];
  LY_4 := AY[AYOff + 4];
  LY_5 := AY[AYOff + 5];
  LY_6 := AY[AYOff + 6];
  LY_7 := AY[AYOff + 7];
  begin
    LC := 0;
    LX_0 := AX[AXOff + 0];
    LC := LC + (LX_0 * LY_0);
    AZz[AZzOff + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_1);
    AZz[AZzOff + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_2);
    AZz[AZzOff + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_3);
    AZz[AZzOff + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_4);
    AZz[AZzOff + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_5);
    AZz[AZzOff + 5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_6);
    AZz[AZzOff + 6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_0 * LY_7);
    AZz[AZzOff + 7] := UInt32(LC);
    LC := LC shr 32;
    AZz[AZzOff + 8] := UInt32(LC);
  end;
  for LI := 1 to 7 do
  begin
    Inc(AZzOff);
    LC := 0;
    LX_i := AX[AXOff + LI];
    LC := LC + (LX_i * LY_0 + AZz[AZzOff + 0]);
    AZz[AZzOff + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_1 + AZz[AZzOff + 1]);
    AZz[AZzOff + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_2 + AZz[AZzOff + 2]);
    AZz[AZzOff + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_3 + AZz[AZzOff + 3]);
    AZz[AZzOff + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_4 + AZz[AZzOff + 4]);
    AZz[AZzOff + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_5 + AZz[AZzOff + 5]);
    AZz[AZzOff + 5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_6 + AZz[AZzOff + 6]);
    AZz[AZzOff + 6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_7 + AZz[AZzOff + 7]);
    AZz[AZzOff + 7] := UInt32(LC);
    LC := LC shr 32;
    AZz[AZzOff + 8] := UInt32(LC);
  end;
end;

class procedure TNat256.Mul128(const AX: TCryptoLibUInt32Array; const AY128: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LX_0: UInt64;
  LX_1: UInt64;
  LX_2: UInt64;
  LX_3: UInt64;
  LX_4: UInt64;
  LX_5: UInt64;
  LX_6: UInt64;
  LX_7: UInt64;
  LC: UInt64;
  LY_0: UInt64;
  LY_i: UInt64;
  LI: Int32;
begin
  LX_0 := AX[0];
  LX_1 := AX[1];
  LX_2 := AX[2];
  LX_3 := AX[3];
  LX_4 := AX[4];
  LX_5 := AX[5];
  LX_6 := AX[6];
  LX_7 := AX[7];
  begin
    LC := 0;
    LY_0 := AY128[0];
    LC := LC + (LY_0 * LX_0);
    AZz[0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_0 * LX_1);
    AZz[1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_0 * LX_2);
    AZz[2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_0 * LX_3);
    AZz[3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_0 * LX_4);
    AZz[4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_0 * LX_5);
    AZz[5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_0 * LX_6);
    AZz[6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_0 * LX_7);
    AZz[7] := UInt32(LC);
    LC := LC shr 32;
    AZz[8] := UInt32(LC);
  end;
  for LI := 1 to 3 do
  begin
    LC := 0;
    LY_i := AY128[LI];
    LC := LC + (LY_i * LX_0 + AZz[LI + 0]);
    AZz[LI + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_i * LX_1 + AZz[LI + 1]);
    AZz[LI + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_i * LX_2 + AZz[LI + 2]);
    AZz[LI + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_i * LX_3 + AZz[LI + 3]);
    AZz[LI + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_i * LX_4 + AZz[LI + 4]);
    AZz[LI + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_i * LX_5 + AZz[LI + 5]);
    AZz[LI + 5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_i * LX_6 + AZz[LI + 6]);
    AZz[LI + 6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LY_i * LX_7 + AZz[LI + 7]);
    AZz[LI + 7] := UInt32(LC);
    LC := LC shr 32;
    AZz[LI + 8] := UInt32(LC);
  end;
end;

class function TNat256.MulAddTo(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array): UInt32;
var
  LY_0: UInt64;
  LY_1: UInt64;
  LY_2: UInt64;
  LY_3: UInt64;
  LY_4: UInt64;
  LY_5: UInt64;
  LY_6: UInt64;
  LY_7: UInt64;
  LZc: UInt64;
  LC: UInt64;
  LX_i: UInt64;
  LI: Int32;
begin
  LY_0 := AY[0];
  LY_1 := AY[1];
  LY_2 := AY[2];
  LY_3 := AY[3];
  LY_4 := AY[4];
  LY_5 := AY[5];
  LY_6 := AY[6];
  LY_7 := AY[7];
  LZc := 0;
  for LI := 0 to 7 do
  begin
    LC := 0;
    LX_i := AX[LI];
    LC := LC + (LX_i * LY_0 + AZz[LI + 0]);
    AZz[LI + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_1 + AZz[LI + 1]);
    AZz[LI + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_2 + AZz[LI + 2]);
    AZz[LI + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_3 + AZz[LI + 3]);
    AZz[LI + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_4 + AZz[LI + 4]);
    AZz[LI + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_5 + AZz[LI + 5]);
    AZz[LI + 5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_6 + AZz[LI + 6]);
    AZz[LI + 6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_7 + AZz[LI + 7]);
    AZz[LI + 7] := UInt32(LC);
    LC := LC shr 32;
    LZc := LZc + (LC + AZz[LI + 8]);
    AZz[LI + 8] := UInt32(LZc);
    LZc := LZc shr (32);
  end;
  Result := UInt32(LZc);
end;

class function TNat256.MulAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32): UInt32;
var
  LY_0: UInt64;
  LY_1: UInt64;
  LY_2: UInt64;
  LY_3: UInt64;
  LY_4: UInt64;
  LY_5: UInt64;
  LY_6: UInt64;
  LY_7: UInt64;
  LZc: UInt64;
  LC: UInt64;
  LX_i: UInt64;
  LI: Int32;
begin
  LY_0 := AY[AYOff + 0];
  LY_1 := AY[AYOff + 1];
  LY_2 := AY[AYOff + 2];
  LY_3 := AY[AYOff + 3];
  LY_4 := AY[AYOff + 4];
  LY_5 := AY[AYOff + 5];
  LY_6 := AY[AYOff + 6];
  LY_7 := AY[AYOff + 7];
  LZc := 0;
  for LI := 0 to 7 do
  begin
    LC := 0;
    LX_i := AX[AXOff + LI];
    LC := LC + (LX_i * LY_0 + AZz[AZzOff + 0]);
    AZz[AZzOff + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_1 + AZz[AZzOff + 1]);
    AZz[AZzOff + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_2 + AZz[AZzOff + 2]);
    AZz[AZzOff + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_3 + AZz[AZzOff + 3]);
    AZz[AZzOff + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_4 + AZz[AZzOff + 4]);
    AZz[AZzOff + 4] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_5 + AZz[AZzOff + 5]);
    AZz[AZzOff + 5] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_6 + AZz[AZzOff + 6]);
    AZz[AZzOff + 6] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + (LX_i * LY_7 + AZz[AZzOff + 7]);
    AZz[AZzOff + 7] := UInt32(LC);
    LC := LC shr 32;
    LZc := LZc + (LC + AZz[AZzOff + 8]);
    AZz[AZzOff + 8] := UInt32(LZc);
    LZc := LZc shr (32);
    Inc(AZzOff);
  end;
  Result := UInt32(LZc);
end;

class function TNat256.Mul33Add(AW: UInt32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt64;
var
  LC: UInt64;
  LWVal: UInt64;
  LX0: UInt64;
  LX1: UInt64;
  LX2: UInt64;
  LX3: UInt64;
  LX4: UInt64;
  LX5: UInt64;
  LX6: UInt64;
  LX7: UInt64;
begin
  System.Assert(AW shr 31 = 0);
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
  LX6 := AX[AXOff + 6];
  LC := LC + (LWVal * LX6 + LX5 + AY[AYOff + 6]);
  AZ[AZOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LX7 := AX[AXOff + 7];
  LC := LC + (LWVal * LX7 + LX6 + AY[AYOff + 7]);
  AZ[AZOff + 7] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LX7);
  Result := LC;
end;

class function TNat256.MulByWord(AX: UInt32; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
begin
  LC := 0;
  LXVal := AX;
  LC := LC + (LXVal * UInt64(AZ[0]));
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[1]));
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[2]));
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[3]));
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[4]));
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[5]));
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[6]));
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[7]));
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.MulByWordAddTo(AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
begin
  LC := 0;
  LXVal := AX;
  LC := LC + (LXVal * UInt64(AZ[0]) + AY[0]);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[1]) + AY[1]);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[2]) + AY[2]);
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[3]) + AY[3]);
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[4]) + AY[4]);
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[5]) + AY[5]);
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[6]) + AY[6]);
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * UInt64(AZ[7]) + AY[7]);
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.MulWordAddTo(AX: UInt32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
begin
  LC := 0;
  LXVal := AX;
  LC := LC + (LXVal * AY[AYOff + 0] + AZ[AZOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AY[AYOff + 1] + AZ[AZOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AY[AYOff + 2] + AZ[AZOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AY[AYOff + 3] + AZ[AZOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AY[AYOff + 4] + AZ[AZOff + 4]);
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AY[AYOff + 5] + AZ[AZOff + 5]);
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AY[AYOff + 6] + AZ[AZOff + 6]);
  AZ[AZOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (LXVal * AY[AYOff + 7] + AZ[AZOff + 7]);
  AZ[AZOff + 7] := UInt32(LC);
  LC := LC shr 32;
  Result := UInt32(LC);
end;

class function TNat256.Mul33DWordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LY00: UInt64;
  LY01: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AX shr 31 = 0);
  System.Assert(AZOff <= 4);
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
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := TNat.IncAt(8, AZ, AZOff, 4);
  end;
end;

class function TNat256.Mul33WordAdd(AX: UInt32; AY: UInt32; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LYVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AX shr 31 = 0);
  System.Assert(AZOff <= 5);
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
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := TNat.IncAt(8, AZ, AZOff, 3);
  end;
end;

class function TNat256.MulWordDwordAdd(AX: UInt32; AY: UInt64; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AZOff <= 5);
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
  if (LC = 0) then
  begin
    Result := 0;
  end
  else
  begin
    Result := TNat.IncAt(8, AZ, AZOff, 3);
  end;
end;

class function TNat256.MulWord(AX: UInt32; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC: UInt64;
  LXVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LXVal := AX;
  LI := 0;
  while LI < 8 do
  begin
    LC := LC + (LXVal * AY[LI]);
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
    Inc(LI);
  end;
  Result := UInt32(LC);
end;

class procedure TNat256.Square(const AX: TCryptoLibUInt32Array; AZz: TCryptoLibUInt32Array);
var
  LX_0: UInt64;
  LZz_1: UInt64;
  LC: UInt32;
  LW: UInt32;
  LI: Int32;
  LJ: Int32;
  LXVal: UInt64;
  LP: UInt64;
  LX_1: UInt64;
  LZz_2: UInt64;
  LX_2: UInt64;
  LZz_3: UInt64;
  LZz_4: UInt64;
  LX_3: UInt64;
  LZz_5: UInt64;
  LZz_6: UInt64;
  LX_4: UInt64;
  LZz_7: UInt64;
  LZz_8: UInt64;
  LX_5: UInt64;
  LZz_9: UInt64;
  LZz_10: UInt64;
  LX_6: UInt64;
  LZz_11: UInt64;
  LZz_12: UInt64;
  LX_7: UInt64;
  LZz_13: UInt64;
  LZz_14: UInt64;
begin
  LX_0 := AX[0];
  LC := 0;
  LI := 7;
  LJ := 16;
  while LI > 0 do
  begin
    LXVal := AX[LI];
    Dec(LI);
    LP := LXVal * LXVal;
    Dec(LJ);
    AZz[LJ] := (LC shl 31) or UInt32(LP shr 33);
    Dec(LJ);
    AZz[LJ] := UInt32(LP shr 1);
    LC := UInt32(LP);
  end;
  LP := LX_0 * LX_0;
  LZz_1 := UInt64(LC shl 31) or (LP shr 33);
  AZz[0] := UInt32(LP);
  LC := UInt32(LP shr 32) and 1;
  LX_1 := AX[1];
  LZz_2 := AZz[2];

  LZz_1 := LZz_1 + (LX_1 * LX_0);
  LW := UInt32(LZz_1);
  AZz[1] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_2 := LZz_2 + (LZz_1  shr 32);

  LX_2 := AX[2];
  LZz_3 := AZz[3];
  LZz_4 := AZz[4];

  LZz_2 := LZz_2 + (LX_2 * LX_0);
  LW := UInt32(LZz_2);
  AZz[2] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_3 := LZz_3 + ((LZz_2  shr 32) + LX_2 * LX_1);
  LZz_4 := LZz_4 + (LZz_3  shr 32);
  LZz_3 := LZz_3 and M;

  LX_3 := AX[3];
  LZz_5 := AZz[5] + (LZz_4 shr 32); LZz_4 := LZz_4 and M;
  LZz_6 := AZz[6] + (LZz_5 shr 32); LZz_5 := LZz_5 and M;

  LZz_3 := LZz_3 + (LX_3 * LX_0);
  LW := UInt32(LZz_3);
  AZz[3] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_4 := LZz_4 + ((LZz_3  shr 32) + LX_3 * LX_1);
  LZz_5 := LZz_5 + ((LZz_4  shr 32) + LX_3 * LX_2);
  LZz_4 := LZz_4 and M;
  LZz_6 := LZz_6 + (LZz_5  shr 32);
  LZz_5 := LZz_5 and M;

  LX_4 := AX[4];
  LZz_7 := AZz[7] + (LZz_6 shr 32); LZz_6 := LZz_6 and M;
  LZz_8 := AZz[8] + (LZz_7 shr 32); LZz_7 := LZz_7 and M;

  LZz_4 := LZz_4 + (LX_4 * LX_0);
  LW := UInt32(LZz_4);
  AZz[4] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_5 := LZz_5 + ((LZz_4  shr 32) + LX_4 * LX_1);
  LZz_6 := LZz_6 + ((LZz_5  shr 32) + LX_4 * LX_2);
  LZz_5 := LZz_5 and M;
  LZz_7 := LZz_7 + ((LZz_6  shr 32) + LX_4 * LX_3);
  LZz_6 := LZz_6 and M;
  LZz_8 := LZz_8 + (LZz_7  shr 32);
  LZz_7 := LZz_7 and M;

  LX_5 := AX[5];
  LZz_9 := AZz[9] + (LZz_8 shr 32); LZz_8 := LZz_8 and M;
  LZz_10 := AZz[10] + (LZz_9 shr 32); LZz_9 := LZz_9 and M;

  LZz_5 := LZz_5 + (LX_5 * LX_0);
  LW := UInt32(LZz_5);
  AZz[5] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_6 := LZz_6 + ((LZz_5  shr 32) + LX_5 * LX_1);
  LZz_7 := LZz_7 + ((LZz_6  shr 32) + LX_5 * LX_2);
  LZz_6 := LZz_6 and M;
  LZz_8 := LZz_8 + ((LZz_7  shr 32) + LX_5 * LX_3);
  LZz_7 := LZz_7 and M;
  LZz_9 := LZz_9 + ((LZz_8  shr 32) + LX_5 * LX_4);
  LZz_8 := LZz_8 and M;
  LZz_10 := LZz_10 + (LZz_9  shr 32);
  LZz_9 := LZz_9 and M;

  LX_6 := AX[6];
  LZz_11 := AZz[11] + (LZz_10 shr 32); LZz_10 := LZz_10 and M;
  LZz_12 := AZz[12] + (LZz_11 shr 32); LZz_11 := LZz_11 and M;

  LZz_6 := LZz_6 + (LX_6 * LX_0);
  LW := UInt32(LZz_6);
  AZz[6] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_7 := LZz_7 + ((LZz_6  shr 32) + LX_6 * LX_1);
  LZz_8 := LZz_8 + ((LZz_7  shr 32) + LX_6 * LX_2);
  LZz_7 := LZz_7 and M;
  LZz_9 := LZz_9 + ((LZz_8  shr 32) + LX_6 * LX_3);
  LZz_8 := LZz_8 and M;
  LZz_10 := LZz_10 + ((LZz_9  shr 32) + LX_6 * LX_4);
  LZz_9 := LZz_9 and M;
  LZz_11 := LZz_11 + ((LZz_10  shr 32) + LX_6 * LX_5);
  LZz_10 := LZz_10 and M;
  LZz_12 := LZz_12 + (LZz_11  shr 32);
  LZz_11 := LZz_11 and M;

  LX_7 := AX[7];
  LZz_13 := AZz[13] + (LZz_12 shr 32); LZz_12 := LZz_12 and M;
  LZz_14 := AZz[14] + (LZz_13 shr 32); LZz_13 := LZz_13 and M;

  LZz_7 := LZz_7 + (LX_7 * LX_0);
  LW := UInt32(LZz_7);
  AZz[7] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_8 := LZz_8 + ((LZz_7  shr 32) + LX_7 * LX_1);
  LZz_9 := LZz_9 + ((LZz_8  shr 32) + LX_7 * LX_2);
  LZz_10 := LZz_10 + ((LZz_9  shr 32) + LX_7 * LX_3);
  LZz_11 := LZz_11 + ((LZz_10  shr 32) + LX_7 * LX_4);
  LZz_12 := LZz_12 + ((LZz_11  shr 32) + LX_7 * LX_5);
  LZz_13 := LZz_13 + ((LZz_12  shr 32) + LX_7 * LX_6);
  LZz_14 := LZz_14 + (LZz_13  shr 32);

  LW := UInt32(LZz_8);
  AZz[8] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_9);
  AZz[9] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_10);
  AZz[10] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_11);
  AZz[11] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_12);
  AZz[12] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_13);
  AZz[13] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_14);
  AZz[14] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := AZz[15] + UInt32(LZz_14  shr 32);
  AZz[15] := (LW  shl 1)  or LC;
end;

class procedure TNat256.Square(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZz: TCryptoLibUInt32Array; AZzOff: Int32);
var
  LX_0: UInt64;
  LZz_1: UInt64;
  LC: UInt32;
  LW: UInt32;
  LI: Int32;
  LJ: Int32;
  LXVal: UInt64;
  LP: UInt64;
  LX_1: UInt64;
  LZz_2: UInt64;
  LX_2: UInt64;
  LZz_3: UInt64;
  LZz_4: UInt64;
  LX_3: UInt64;
  LZz_5: UInt64;
  LZz_6: UInt64;
  LX_4: UInt64;
  LZz_7: UInt64;
  LZz_8: UInt64;
  LX_5: UInt64;
  LZz_9: UInt64;
  LZz_10: UInt64;
  LX_6: UInt64;
  LZz_11: UInt64;
  LZz_12: UInt64;
  LX_7: UInt64;
  LZz_13: UInt64;
  LZz_14: UInt64;
begin
  LX_0 := AX[AXOff + 0];
  LC := 0;
  LI := 7;
  LJ := 16;
  while LI > 0 do
  begin
    LXVal := AX[AXOff + LI];
    Dec(LI);
    LP := LXVal * LXVal;
    Dec(LJ);
    AZz[AZzOff + LJ] := (LC shl 31) or UInt32(LP shr 33);
    Dec(LJ);
    AZz[AZzOff + LJ] := UInt32(LP shr 1);
    LC := UInt32(LP);
  end;

  LP := LX_0 * LX_0;
  LZz_1 := UInt64(LC shl 31) or (LP shr 33);
  AZz[AZzOff + 0] := UInt32(LP);
  LC := UInt32(LP shr 32) and 1;
  LX_1 := AX[AXOff + 1];
  LZz_2 := AZz[AZzOff + 2];

  LZz_1 := LZz_1 + (LX_1 * LX_0);
  LW := UInt32(LZz_1);
  AZz[AZzOff + 1] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_2 := LZz_2 + (LZz_1  shr 32);

  LX_2 := AX[AXOff + 2];
  LZz_3 := AZz[AZzOff + 3];
  LZz_4 := AZz[AZzOff + 4];

  LZz_2 := LZz_2 + (LX_2 * LX_0);
  LW := UInt32(LZz_2);
  AZz[AZzOff + 2] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_3 := LZz_3 + ((LZz_2  shr 32) + LX_2 * LX_1);
  LZz_4 := LZz_4 + (LZz_3  shr 32);
  LZz_3 := LZz_3 and M;

  LX_3 := AX[AXOff + 3];
  LZz_5 := AZz[AZzOff + 5] + (LZz_4 shr 32); LZz_4 := LZz_4 and M;
  LZz_6 := AZz[AZzOff + 6] + (LZz_5 shr 32); LZz_5 := LZz_5 and M;

  LZz_3 := LZz_3 + (LX_3 * LX_0);
  LW := UInt32(LZz_3);
  AZz[AZzOff + 3] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_4 := LZz_4 + ((LZz_3  shr 32) + LX_3 * LX_1);
  LZz_5 := LZz_5 + ((LZz_4  shr 32) + LX_3 * LX_2);
  LZz_4 := LZz_4 and M;
  LZz_6 := LZz_6 + (LZz_5  shr 32);
  LZz_5 := LZz_5 and M;

  LX_4 := AX[AXOff + 4];
  LZz_7 := AZz[AZzOff + 7] + (LZz_6 shr 32); LZz_6 := LZz_6 and M;
  LZz_8 := AZz[AZzOff + 8] + (LZz_7 shr 32); LZz_7 := LZz_7 and M;

  LZz_4 := LZz_4 + (LX_4 * LX_0);
  LW := UInt32(LZz_4);
  AZz[AZzOff + 4] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_5 := LZz_5 + ((LZz_4  shr 32) + LX_4 * LX_1);
  LZz_6 := LZz_6 + ((LZz_5  shr 32) + LX_4 * LX_2);
  LZz_5 := LZz_5 and M;
  LZz_7 := LZz_7 + ((LZz_6  shr 32) + LX_4 * LX_3);
  LZz_6 := LZz_6 and M;
  LZz_8 := LZz_8 + (LZz_7  shr 32);
  LZz_7 := LZz_7 and M;

  LX_5 := AX[AXOff + 5];
  LZz_9 := AZz[AZzOff + 9] + (LZz_8 shr 32); LZz_8 := LZz_8 and M;
  LZz_10 := AZz[AZzOff + 10] + (LZz_9 shr 32); LZz_9 := LZz_9 and M;

  LZz_5 := LZz_5 + (LX_5 * LX_0);
  LW := UInt32(LZz_5);
  AZz[AZzOff + 5] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_6 := LZz_6 + ((LZz_5  shr 32) + LX_5 * LX_1);
  LZz_7 := LZz_7 + ((LZz_6  shr 32) + LX_5 * LX_2);
  LZz_6 := LZz_6 and M;
  LZz_8 := LZz_8 + ((LZz_7  shr 32) + LX_5 * LX_3);
  LZz_7 := LZz_7 and M;
  LZz_9 := LZz_9 + ((LZz_8  shr 32) + LX_5 * LX_4);
  LZz_8 := LZz_8 and M;
  LZz_10 := LZz_10 + (LZz_9  shr 32);
  LZz_9 := LZz_9 and M;

  LX_6 := AX[AXOff + 6];
  LZz_11 := AZz[AZzOff + 11] + (LZz_10 shr 32); LZz_10 := LZz_10 and M;
  LZz_12 := AZz[AZzOff + 12] + (LZz_11 shr 32); LZz_11 := LZz_11 and M;

  LZz_6 := LZz_6 + (LX_6 * LX_0);
  LW := UInt32(LZz_6);
  AZz[AZzOff + 6] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_7 := LZz_7 + ((LZz_6  shr 32) + LX_6 * LX_1);
  LZz_8 := LZz_8 + ((LZz_7  shr 32) + LX_6 * LX_2);
  LZz_7 := LZz_7 and M;
  LZz_9 := LZz_9 + ((LZz_8  shr 32) + LX_6 * LX_3);
  LZz_8 := LZz_8 and M;
  LZz_10 := LZz_10 + ((LZz_9  shr 32) + LX_6 * LX_4);
  LZz_9 := LZz_9 and M;
  LZz_11 := LZz_11 + ((LZz_10  shr 32) + LX_6 * LX_5);
  LZz_10 := LZz_10 and M;
  LZz_12 := LZz_12 + (LZz_11  shr 32);
  LZz_11 := LZz_11 and M;

  LX_7 := AX[AXOff + 7];
  LZz_13 := AZz[AZzOff + 13] + (LZz_12 shr 32); LZz_12 := LZz_12 and M;
  LZz_14 := AZz[AZzOff + 14] + (LZz_13 shr 32); LZz_13 := LZz_13 and M;

  LZz_7 := LZz_7 + (LX_7 * LX_0);
  LW := UInt32(LZz_7);
  AZz[AZzOff + 7] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LZz_8 := LZz_8 + ((LZz_7  shr 32) + LX_7 * LX_1);
  LZz_9 := LZz_9 + ((LZz_8  shr 32) + LX_7 * LX_2);
  LZz_10 := LZz_10 + ((LZz_9  shr 32) + LX_7 * LX_3);
  LZz_11 := LZz_11 + ((LZz_10  shr 32) + LX_7 * LX_4);
  LZz_12 := LZz_12 + ((LZz_11  shr 32) + LX_7 * LX_5);
  LZz_13 := LZz_13 + ((LZz_12  shr 32) + LX_7 * LX_6);
  LZz_14 := LZz_14 + (LZz_13  shr 32);

  LW := UInt32(LZz_8);
  AZz[AZzOff + 8] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_9);
  AZz[AZzOff + 9] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_10);
  AZz[AZzOff + 10] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_11);
  AZz[AZzOff + 11] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_12);
  AZz[AZzOff + 12] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_13);
  AZz[AZzOff + 13] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := UInt32(LZz_14);
  AZz[AZzOff + 14] := (LW  shl 1)  or LC;
  LC := LW  shr 31;
  LW := AZz[AZzOff + 15] + UInt32(LZz_14  shr 32);
  AZz[AZzOff + 15] := (LW  shl 1)  or LC;
end;

class function TNat256.Sub(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AX[0]) - AY[0]);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[1]) - AY[1]);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[2]) - AY[2]);
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[3]) - AY[3]);
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[4]) - AY[4]);
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[5]) - AY[5]);
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[6]) - AY[6]);
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[7]) - AY[7]);
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := Int32(LC);
end;

class function TNat256.Sub(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AX[AXOff + 0]) - AY[AYOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[AXOff + 1]) - AY[AYOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[AXOff + 2]) - AY[AYOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[AXOff + 3]) - AY[AYOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[AXOff + 4]) - AY[AYOff + 4]);
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[AXOff + 5]) - AY[AYOff + 5]);
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[AXOff + 6]) - AY[AYOff + 6]);
  AZ[AZOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AX[AXOff + 7]) - AY[AYOff + 7]);
  AZ[AZOff + 7] := UInt32(LC);
  LC := LC shr 32;
  Result := Int32(LC);
end;

class function TNat256.SubBothFrom(const AX: TCryptoLibUInt32Array; const AY: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + (Int64(AZ[0]) - AX[0] - AY[0]);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[1]) - AX[1] - AY[1]);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[2]) - AX[2] - AY[2]);
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[3]) - AX[3] - AY[3]);
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[4]) - AX[4] - AY[4]);
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[5]) - AX[5] - AY[5]);
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[6]) - AX[6] - AY[6]);
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[7]) - AX[7] - AY[7]);
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := Int32(LC);
end;

class function TNat256.SubFrom(const AX: TCryptoLibUInt32Array; AZ: TCryptoLibUInt32Array; ACIn: Int32): Int32;
var
  LC: Int64;
begin
  LC := ACIn;
  LC := LC + (Int64(AZ[0]) - AX[0]);
  AZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[1]) - AX[1]);
  AZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[2]) - AX[2]);
  AZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[3]) - AX[3]);
  AZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[4]) - AX[4]);
  AZ[4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[5]) - AX[5]);
  AZ[5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[6]) - AX[6]);
  AZ[6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[7]) - AX[7]);
  AZ[7] := UInt32(LC);
  LC := LC shr 32;
  Result := Int32(LC);
end;

class function TNat256.SubFrom(const AX: TCryptoLibUInt32Array; AXOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32; ACIn: Int32): Int32;
var
  LC: Int64;
begin
  LC := ACIn;
  LC := LC + (Int64(AZ[AZOff + 0]) - AX[AXOff + 0]);
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[AZOff + 1]) - AX[AXOff + 1]);
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[AZOff + 2]) - AX[AXOff + 2]);
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[AZOff + 3]) - AX[AXOff + 3]);
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[AZOff + 4]) - AX[AXOff + 4]);
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[AZOff + 5]) - AX[AXOff + 5]);
  AZ[AZOff + 5] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[AZOff + 6]) - AX[AXOff + 6]);
  AZ[AZOff + 6] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + (Int64(AZ[AZOff + 7]) - AX[AXOff + 7]);
  AZ[AZOff + 7] := UInt32(LC);
  LC := LC shr 32;
  Result := Int32(LC);
end;

class function TNat256.ToBigInteger(const AX: TCryptoLibUInt32Array): TBigInteger;
var
  LBs: TCryptoLibByteArray;
  LX_i: UInt32;
  LI: Int32;
begin
  SetLength(LBs, 32);
  for LI := 0 to 7 do
  begin
    LX_i := AX[LI];
    if (LX_i <> 0) then
    begin
      TPack.UInt32_To_BE(LX_i, LBs, (7 - LI)  shl 2);
    end;
  end;
  Result := TBigInteger.Create(1, LBs);
end;

class function TNat256.ToBigInteger64(const AX: TCryptoLibUInt64Array): TBigInteger;
var
  LBs: TCryptoLibByteArray;
  LX_i: UInt64;
  LI: Int32;
begin
  SetLength(LBs, 32);
  for LI := 0 to 3 do
  begin
    LX_i := AX[LI];
    if (LX_i <> Int64(0)) then
    begin
      TPack.UInt64_To_BE(LX_i, LBs, (3 - LI) shl 3);
    end;
  end;
  Result := TBigInteger.Create(1, LBs);
end;

class procedure TNat256.&Xor(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32; AZ: TCryptoLibUInt32Array; AZOff: Int32);
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
    Inc(LI, 4);
  end;
end;

class procedure TNat256.Zero(AZ: TCryptoLibUInt32Array);
begin
  TArrayUtilities.Fill<UInt32>(AZ, 0, 8, UInt32(0));
end;

end.
