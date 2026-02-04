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

unit ClpNat160;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpBigInteger,
  ClpPack,
  ClpNat,
  ClpCryptoLibTypes;

type
  TNat160 = class sealed
  strict private
    const M: UInt64 = UInt64($FFFFFFFF);
  public
    class function Add(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): UInt32; static;
    class function AddBothTo(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): UInt32; static;
    class function AddTo(const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function AddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32;
      ACIn: UInt32): UInt32; overload; static;
    class function AddToEachOther(const AU: TCryptoLibUInt32Array; AUOff: Int32; const AV: TCryptoLibUInt32Array;
      AVOff: Int32): UInt32; static;

    class procedure Copy(const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array); overload; static;
    class procedure Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32); overload; static;

    class function Create: TCryptoLibUInt32Array; static;
    class function CreateExt: TCryptoLibUInt32Array; static;

    class function Diff(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
      const AZ: TCryptoLibUInt32Array; AZOff: Int32): Boolean; static;

    class function Eq(const AX, AY: TCryptoLibUInt32Array): Boolean; static;
    class function GetBit(const AX: TCryptoLibUInt32Array; ABit: Int32): UInt32; static;

    class function Gte(const AX, AY: TCryptoLibUInt32Array): Boolean; overload; static;
    class function Gte(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Boolean; overload; static;

    class function IsOne(const AX: TCryptoLibUInt32Array): Boolean; static;
    class function IsZero(const AX: TCryptoLibUInt32Array): Boolean; static;

    class procedure Mul(const AX, AY: TCryptoLibUInt32Array; const AZZ: TCryptoLibUInt32Array); overload; static;
    class procedure Mul(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
      const AZZ: TCryptoLibUInt32Array; AZZOff: Int32); overload; static;

    class function MulAddTo(const AX, AY: TCryptoLibUInt32Array; const AZZ: TCryptoLibUInt32Array): UInt32; overload; static;
    class function MulAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
      const AZZ: TCryptoLibUInt32Array; AZZOff: Int32): UInt32; overload; static;

    class function Mul33Add(AW: UInt32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array;
      AYOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt64; static;

    class function MulWordAddExt(AX: UInt32; const AYY: TCryptoLibUInt32Array; AYYOff: Int32; const AZZ: TCryptoLibUInt32Array;
      AZZOff: Int32): UInt32; static;

    class function Mul33DWordAdd(AX: UInt32; AY: UInt64; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function Mul33WordAdd(AX, AY: UInt32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWordDwordAdd(AX: UInt32; AY: UInt64; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWordsAdd(AX, AY: UInt32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;
    class function MulWord(AX: UInt32; const AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32; static;

    class procedure Square(const AX: TCryptoLibUInt32Array; const AZZ: TCryptoLibUInt32Array); overload; static;
    class procedure Square(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZZ: TCryptoLibUInt32Array; AZZOff: Int32); overload; static;

    class function Sub(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function Sub(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
      const AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;

    class function SubBothFrom(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): Int32; static;
    class function SubFrom(const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): Int32; overload; static;
    class function SubFrom(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32; overload; static;

    class function ToBigInteger(const AX: TCryptoLibUInt32Array): TBigInteger; static;
    class procedure Zero(const AZ: TCryptoLibUInt32Array); static;
  end;

implementation

class function TNat160.Add(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): UInt32;
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
  Result := UInt32(LC);
end;

class function TNat160.AddBothTo(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): UInt32;
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
  Result := UInt32(LC);
end;

class function TNat160.AddTo(const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): UInt32;
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
  Result := UInt32(LC);
end;

class function TNat160.AddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32;
  ACIn: UInt32): UInt32;
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
  //LC := LC + UInt64(AX[AXOff + 5]) + AZ[AZOff + 5];
  Result := UInt32(LC);
end;

class function TNat160.AddToEachOther(const AU: TCryptoLibUInt32Array; AUOff: Int32; const AV: TCryptoLibUInt32Array;
  AVOff: Int32): UInt32;
var
  LC: UInt64;
  LTmp: UInt32;
begin
  LC := 0;
  LC := LC + UInt64(AU[AUOff + 0]) + AV[AVOff + 0];
  LTmp := UInt32(LC);
  AU[AUOff + 0] := LTmp;
  AV[AVOff + 0] := LTmp;
  LC := LC shr 32;

  LC := LC + UInt64(AU[AUOff + 1]) + AV[AVOff + 1];
  LTmp := UInt32(LC);
  AU[AUOff + 1] := LTmp;
  AV[AVOff + 1] := LTmp;
  LC := LC shr 32;

  LC := LC + UInt64(AU[AUOff + 2]) + AV[AVOff + 2];
  LTmp := UInt32(LC);
  AU[AUOff + 2] := LTmp;
  AV[AVOff + 2] := LTmp;
  LC := LC shr 32;

  LC := LC + UInt64(AU[AUOff + 3]) + AV[AVOff + 3];
  LTmp := UInt32(LC);
  AU[AUOff + 3] := LTmp;
  AV[AVOff + 3] := LTmp;
  LC := LC shr 32;

  LC := LC + UInt64(AU[AUOff + 4]) + AV[AVOff + 4];
  LTmp := UInt32(LC);
  AU[AUOff + 4] := LTmp;
  AV[AVOff + 4] := LTmp;
  LC := LC shr 32;

  Result := UInt32(LC);
end;

class procedure TNat160.Copy(const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array);
begin
  System.Move(AX[0], AZ[0], 5 * System.SizeOf(UInt32));
end;

class procedure TNat160.Copy(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32);
begin
  System.Move(AX[AXOff], AZ[AZOff], 5 * System.SizeOf(UInt32));
end;

class function TNat160.Create: TCryptoLibUInt32Array;
begin
  System.SetLength(Result, 5);
end;

class function TNat160.CreateExt: TCryptoLibUInt32Array;
begin
  System.SetLength(Result, 10);
end;

class function TNat160.Diff(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32): Boolean;
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

class function TNat160.Eq(const AX, AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  for LI := 4 downto 0 do
  begin
    if AX[LI] <> AY[LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat160.GetBit(const AX: TCryptoLibUInt32Array; ABit: Int32): UInt32;
var
  LW, LB: Int32;
begin
  if ABit = 0 then
  begin
    Result := AX[0] and 1;
    Exit;
  end;

  LW := TBitOperations.Asr32(ABit, 5);
  if (LW < 0) or (LW >= 5) then
  begin
    Result := 0;
    Exit;
  end;

  LB := ABit and 31;
  Result := (AX[LW] shr LB) and 1;
end;

class function TNat160.Gte(const AX, AY: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
  LX, LY: UInt32;
begin
  for LI := 4 downto 0 do
  begin
    LX := AX[LI];
    LY := AY[LI];
    if LX < LY then
    begin
      Result := False;
      Exit;
    end;
    if LX > LY then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat160.Gte(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32): Boolean;
var
  LI: Int32;
  LX, LY: UInt32;
begin
  for LI := 4 downto 0 do
  begin
    LX := AX[AXOff + LI];
    LY := AY[AYOff + LI];
    if LX < LY then
    begin
      Result := False;
      Exit;
    end;
    if LX > LY then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := True;
end;

class function TNat160.IsOne(const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  if AX[0] <> 1 then
  begin
    Result := False;
    Exit;
  end;

  for LI := 1 to 4 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

class function TNat160.IsZero(const AX: TCryptoLibUInt32Array): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to 4 do
  begin
    if AX[LI] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class procedure TNat160.Mul(const AX, AY: TCryptoLibUInt32Array; const AZZ: TCryptoLibUInt32Array);
var
  LY0, LY1, LY2, LY3, LY4: UInt64;
  LC, LXI: UInt64;
  LI: Int32;
begin
  LY0 := AY[0];
  LY1 := AY[1];
  LY2 := AY[2];
  LY3 := AY[3];
  LY4 := AY[4];

  // i = 0
  LC := 0;
  LXI := AX[0];
  LC := LC + LXI * LY0;
  AZZ[0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY1;
  AZZ[1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY2;
  AZZ[2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY3;
  AZZ[3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY4;
  AZZ[4] := UInt32(LC);
  LC := LC shr 32;
  AZZ[5] := UInt32(LC);

  for LI := 1 to 4 do
  begin
    LC := 0;
    LXI := AX[LI];
    LC := LC + LXI * LY0 + AZZ[LI + 0];
    AZZ[LI + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY1 + AZZ[LI + 1];
    AZZ[LI + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY2 + AZZ[LI + 2];
    AZZ[LI + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY3 + AZZ[LI + 3];
    AZZ[LI + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY4 + AZZ[LI + 4];
    AZZ[LI + 4] := UInt32(LC);
    LC := LC shr 32;
    AZZ[LI + 5] := UInt32(LC);
  end;
end;

class procedure TNat160.Mul(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
  const AZZ: TCryptoLibUInt32Array; AZZOff: Int32);
var
  LY0, LY1, LY2, LY3, LY4: UInt64;
  LC, LXI: UInt64;
  LI: Int32;
begin
  LY0 := AY[AYOff + 0];
  LY1 := AY[AYOff + 1];
  LY2 := AY[AYOff + 2];
  LY3 := AY[AYOff + 3];
  LY4 := AY[AYOff + 4];

  // i = 0
  LC := 0;
  LXI := AX[AXOff + 0];
  LC := LC + LXI * LY0;
  AZZ[AZZOff + 0] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY1;
  AZZ[AZZOff + 1] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY2;
  AZZ[AZZOff + 2] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY3;
  AZZ[AZZOff + 3] := UInt32(LC);
  LC := LC shr 32;
  LC := LC + LXI * LY4;
  AZZ[AZZOff + 4] := UInt32(LC);
  LC := LC shr 32;
  AZZ[AZZOff + 5] := UInt32(LC);

  for LI := 1 to 4 do
  begin
    Inc(AZZOff);
    LC := 0;
    LXI := AX[AXOff + LI];
    LC := LC + LXI * LY0 + AZZ[AZZOff + 0];
    AZZ[AZZOff + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY1 + AZZ[AZZOff + 1];
    AZZ[AZZOff + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY2 + AZZ[AZZOff + 2];
    AZZ[AZZOff + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY3 + AZZ[AZZOff + 3];
    AZZ[AZZOff + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY4 + AZZ[AZZOff + 4];
    AZZ[AZZOff + 4] := UInt32(LC);
    LC := LC shr 32;
    AZZ[AZZOff + 5] := UInt32(LC);
  end;
end;

class function TNat160.MulAddTo(const AX, AY: TCryptoLibUInt32Array; const AZZ: TCryptoLibUInt32Array): UInt32;
var
  LY0, LY1, LY2, LY3, LY4: UInt64;
  LZC, LC, LXI: UInt64;
  LI: Int32;
begin
  LY0 := AY[0];
  LY1 := AY[1];
  LY2 := AY[2];
  LY3 := AY[3];
  LY4 := AY[4];

  LZC := 0;
  for LI := 0 to 4 do
  begin
    LC := 0;
    LXI := AX[LI];
    LC := LC + LXI * LY0 + AZZ[LI + 0];
    AZZ[LI + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY1 + AZZ[LI + 1];
    AZZ[LI + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY2 + AZZ[LI + 2];
    AZZ[LI + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY3 + AZZ[LI + 3];
    AZZ[LI + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY4 + AZZ[LI + 4];
    AZZ[LI + 4] := UInt32(LC);
    LC := LC shr 32;

    LZC := LZC + LC + AZZ[LI + 5];
    AZZ[LI + 5] := UInt32(LZC);
    LZC := LZC shr 32;
  end;

  Result := UInt32(LZC);
end;

class function TNat160.MulAddTo(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
  const AZZ: TCryptoLibUInt32Array; AZZOff: Int32): UInt32;
var
  LY0, LY1, LY2, LY3, LY4: UInt64;
  LZC, LC, LXI: UInt64;
  LI: Int32;
begin
  LY0 := AY[AYOff + 0];
  LY1 := AY[AYOff + 1];
  LY2 := AY[AYOff + 2];
  LY3 := AY[AYOff + 3];
  LY4 := AY[AYOff + 4];

  LZC := 0;
  for LI := 0 to 4 do
  begin
    LC := 0;
    LXI := AX[AXOff + LI];
    LC := LC + LXI * LY0 + AZZ[AZZOff + 0];
    AZZ[AZZOff + 0] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY1 + AZZ[AZZOff + 1];
    AZZ[AZZOff + 1] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY2 + AZZ[AZZOff + 2];
    AZZ[AZZOff + 2] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY3 + AZZ[AZZOff + 3];
    AZZ[AZZOff + 3] := UInt32(LC);
    LC := LC shr 32;
    LC := LC + LXI * LY4 + AZZ[AZZOff + 4];
    AZZ[AZZOff + 4] := UInt32(LC);
    LC := LC shr 32;

    LZC := LZC + LC + AZZ[AZZOff + 5];
    AZZ[AZZOff + 5] := UInt32(LZC);
    LZC := LZC shr 32;
    Inc(AZZOff);
  end;

  Result := UInt32(LZC);
end;

class function TNat160.Mul33Add(AW: UInt32; const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array;
  AYOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt64;
var
  LC, LWVal: UInt64;
  LX0, LX1, LX2, LX3, LX4: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert((AW shr 31) = 0);
  {$ENDIF}

  LC := 0;
  LWVal := AW;

  LX0 := AX[AXOff + 0];
  LC := LC + LWVal * LX0 + AY[AYOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;

  LX1 := AX[AXOff + 1];
  LC := LC + LWVal * LX1 + LX0 + AY[AYOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;

  LX2 := AX[AXOff + 2];
  LC := LC + LWVal * LX2 + LX1 + AY[AYOff + 2];
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;

  LX3 := AX[AXOff + 3];
  LC := LC + LWVal * LX3 + LX2 + AY[AYOff + 3];
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;

  LX4 := AX[AXOff + 4];
  LC := LC + LWVal * LX4 + LX3 + AY[AYOff + 4];
  AZ[AZOff + 4] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LX4;
  Result := LC;
end;

class function TNat160.MulWordAddExt(AX: UInt32; const AYY: TCryptoLibUInt32Array; AYYOff: Int32; const AZZ: TCryptoLibUInt32Array;
  AZZOff: Int32): UInt32;
var
  LC, LXVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AYYOff <= 5);
  System.Assert(AZZOff <= 5);
  {$ENDIF}

  LC := 0;
  LXVal := AX;

  LC := LC + LXVal * AYY[AYYOff + 0] + AZZ[AZZOff + 0];
  AZZ[AZZOff + 0] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LXVal * AYY[AYYOff + 1] + AZZ[AZZOff + 1];
  AZZ[AZZOff + 1] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LXVal * AYY[AYYOff + 2] + AZZ[AZZOff + 2];
  AZZ[AZZOff + 2] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LXVal * AYY[AYYOff + 3] + AZZ[AZZOff + 3];
  AZZ[AZZOff + 3] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LXVal * AYY[AYYOff + 4] + AZZ[AZZOff + 4];
  AZZ[AZZOff + 4] := UInt32(LC);
  LC := LC shr 32;

  Result := UInt32(LC);
end;

class function TNat160.Mul33DWordAdd(AX: UInt32; AY: UInt64; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC, LXVal, LY00, LY01: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert((AX shr 31) = 0);
  System.Assert(AZOff <= 1);
  {$ENDIF}

  LC := 0;
  LXVal := AX;
  LY00 := AY and M;

  LC := LC + LXVal * LY00 + AZ[AZOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;

  LY01 := AY shr 32;
  LC := LC + LXVal * LY01 + LY00 + AZ[AZOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LY01 + AZ[AZOff + 2];
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + AZ[AZOff + 3];
  AZ[AZOff + 3] := UInt32(LC);
  LC := LC shr 32;

  if LC = 0 then
    Result := 0
  else
    Result := TNat.IncAt(5, AZ, AZOff, 4);
end;

class function TNat160.Mul33WordAdd(AX, AY: UInt32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC, LYVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert((AX shr 31) = 0);
  System.Assert(AZOff <= 2);
  {$ENDIF}

  LC := 0;
  LYVal := AY;

  LC := LC + LYVal * AX + AZ[AZOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LYVal + AZ[AZOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + AZ[AZOff + 2];
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;

  if LC = 0 then
    Result := 0
  else
    Result := TNat.IncAt(5, AZ, AZOff, 3);
end;

class function TNat160.MulWordDwordAdd(AX: UInt32; AY: UInt64; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC, LXVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AZOff <= 2);
  {$ENDIF}

  LC := 0;
  LXVal := AX;

  LC := LC + LXVal * AY + AZ[AZOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + LXVal * (AY shr 32) + AZ[AZOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + AZ[AZOff + 2];
  AZ[AZOff + 2] := UInt32(LC);
  LC := LC shr 32;

  if LC = 0 then
    Result := 0
  else
    Result := TNat.IncAt(5, AZ, AZOff, 3);
end;

class function TNat160.MulWordsAdd(AX, AY: UInt32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC, LXVal, LYVal: UInt64;
begin
  {$IFDEF DEBUG}
  System.Assert(AZOff <= 3);
  {$ENDIF}
  LC := 0;
  LXVal := AX;
  LYVal := AY;

  LC := LC + LYVal * LXVal + AZ[AZOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := LC shr 32;

  LC := LC + AZ[AZOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := LC shr 32;

  if LC = 0 then
    Result := 0
  else
    Result := TNat.IncAt(5, AZ, AZOff, 2);
end;

class function TNat160.MulWord(AX: UInt32; const AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array; AZOff: Int32): UInt32;
var
  LC, LXVal: UInt64;
  LI: Int32;
begin
  LC := 0;
  LXVal := AX;
  LI := 0;
  repeat
    LC := LC + LXVal * AY[LI];
    AZ[AZOff + LI] := UInt32(LC);
    LC := LC shr 32;
    Inc(LI);
  until LI >= 5;

  Result := UInt32(LC);
end;

class procedure TNat160.Square(const AX: TCryptoLibUInt32Array; const AZZ: TCryptoLibUInt32Array);
var
  LX0, LX1, LX2, LX3, LX4: UInt64;
  LZZ1, LZZ2, LZZ3, LZZ4, LZZ5, LZZ6, LZZ7, LZZ8: UInt64;
  LC: UInt32;
  LW: UInt32;
  LI, LJ: Int32;
  LXVal, LP: UInt64;
begin
  LX0 := AX[0];

  LC := 0;
  // Fill high words of square
  LI := 4;
  LJ := 10;
  repeat
    LXVal := AX[LI];
    Dec(LI);
    LP := LXVal * LXVal;
    Dec(LJ);
    AZZ[LJ] := (LC shl 31) or UInt32(LP shr 33);
    Dec(LJ);
    AZZ[LJ] := UInt32(LP shr 1);
    LC := UInt32(LP);
  until LI <= 0;

  // i = 0
  LP := LX0 * LX0;
  LZZ1 := UInt64(LC shl 31) or (LP shr 33);
  AZZ[0] := UInt32(LP);
  LC := UInt32(LP shr 32) and 1;

  LX1 := AX[1];
  LZZ2 := AZZ[2];

  // x1 * x0
  LZZ1 := LZZ1 + LX1 * LX0;
  LW := UInt32(LZZ1);
  AZZ[1] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ2 := LZZ2 + (LZZ1 shr 32);

  LX2 := AX[2];
  LZZ3 := AZZ[3];
  LZZ4 := AZZ[4];

  // x2 * x0, x2 * x1
  LZZ2 := LZZ2 + LX2 * LX0;
  LW := UInt32(LZZ2);
  AZZ[2] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ3 := LZZ3 + (LZZ2 shr 32) + LX2 * LX1;
  LZZ4 := LZZ4 + (LZZ3 shr 32);
  LZZ3 := LZZ3 and M;

  LX3 := AX[3];
  LZZ5 := AZZ[5] + (LZZ4 shr 32);
  LZZ4 := LZZ4 and M;
  LZZ6 := AZZ[6] + (LZZ5 shr 32);
  LZZ5 := LZZ5 and M;

  // x3 terms
  LZZ3 := LZZ3 + LX3 * LX0;
  LW := UInt32(LZZ3);
  AZZ[3] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ4 := LZZ4 + (LZZ3 shr 32) + LX3 * LX1;
  LZZ5 := LZZ5 + (LZZ4 shr 32) + LX3 * LX2;
  LZZ4 := LZZ4 and M;
  LZZ6 := LZZ6 + (LZZ5 shr 32);
  LZZ5 := LZZ5 and M;

  LX4 := AX[4];
  LZZ7 := AZZ[7] + (LZZ6 shr 32);
  LZZ6 := LZZ6 and M;
  LZZ8 := AZZ[8] + (LZZ7 shr 32);
  LZZ7 := LZZ7 and M;

  // x4 terms
  LZZ4 := LZZ4 + LX4 * LX0;
  LW := UInt32(LZZ4);
  AZZ[4] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ5 := LZZ5 + (LZZ4 shr 32) + LX4 * LX1;
  LZZ6 := LZZ6 + (LZZ5 shr 32) + LX4 * LX2;
  LZZ7 := LZZ7 + (LZZ6 shr 32) + LX4 * LX3;
  LZZ8 := LZZ8 + (LZZ7 shr 32);

  LW := UInt32(LZZ5);
  AZZ[5] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZZ6);
  AZZ[6] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZZ7);
  AZZ[7] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZZ8);
  AZZ[8] := (LW shl 1) or LC;
  LC := LW shr 31;

  LW := AZZ[9] + UInt32(LZZ8 shr 32);
  AZZ[9] := (LW shl 1) or LC;
end;

class procedure TNat160.Square(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZZ: TCryptoLibUInt32Array; AZZOff: Int32);
var
  LX0, LX1, LX2, LX3, LX4: UInt64;
  LZZ1, LZZ2, LZZ3, LZZ4, LZZ5, LZZ6, LZZ7, LZZ8: UInt64;
  LC: UInt32;
  LW: UInt32;
  LI, LJ: Int32;
  LXVal, LP: UInt64;
begin
  LX0 := AX[AXOff + 0];

  LC := 0;
  LI := 4;
  LJ := 10;
  repeat
    LXVal := AX[AXOff + LI];
    Dec(LI);
    LP := LXVal * LXVal;
    Dec(LJ);
    AZZ[AZZOff + LJ] := (LC shl 31) or UInt32(LP shr 33);
    Dec(LJ);
    AZZ[AZZOff + LJ] := UInt32(LP shr 1);
    LC := UInt32(LP);
  until LI <= 0;

  LP := LX0 * LX0;
  LZZ1 := UInt64(LC shl 31) or (LP shr 33);
  AZZ[AZZOff + 0] := UInt32(LP);
  LC := UInt32(LP shr 32) and 1;

  LX1 := AX[AXOff + 1];
  LZZ2 := AZZ[AZZOff + 2];

  LZZ1 := LZZ1 + LX1 * LX0;
  LW := UInt32(LZZ1);
  AZZ[AZZOff + 1] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ2 := LZZ2 + (LZZ1 shr 32);

  LX2 := AX[AXOff + 2];
  LZZ3 := AZZ[AZZOff + 3];
  LZZ4 := AZZ[AZZOff + 4];

  LZZ2 := LZZ2 + LX2 * LX0;
  LW := UInt32(LZZ2);
  AZZ[AZZOff + 2] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ3 := LZZ3 + (LZZ2 shr 32) + LX2 * LX1;
  LZZ4 := LZZ4 + (LZZ3 shr 32);
  LZZ3 := LZZ3 and M;

  LX3 := AX[AXOff + 3];
  LZZ5 := AZZ[AZZOff + 5] + (LZZ4 shr 32);
  LZZ4 := LZZ4 and M;
  LZZ6 := AZZ[AZZOff + 6] + (LZZ5 shr 32);
  LZZ5 := LZZ5 and M;

  LZZ3 := LZZ3 + LX3 * LX0;
  LW := UInt32(LZZ3);
  AZZ[AZZOff + 3] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ4 := LZZ4 + (LZZ3 shr 32) + LX3 * LX1;
  LZZ5 := LZZ5 + (LZZ4 shr 32) + LX3 * LX2;
  LZZ4 := LZZ4 and M;
  LZZ6 := LZZ6 + (LZZ5 shr 32);
  LZZ5 := LZZ5 and M;

  LX4 := AX[AXOff + 4];
  LZZ7 := AZZ[AZZOff + 7] + (LZZ6 shr 32);
  LZZ6 := LZZ6 and M;
  LZZ8 := AZZ[AZZOff + 8] + (LZZ7 shr 32);
  LZZ7 := LZZ7 and M;

  LZZ4 := LZZ4 + LX4 * LX0;
  LW := UInt32(LZZ4);
  AZZ[AZZOff + 4] := (LW shl 1) or LC;
  LC := LW shr 31;
  LZZ5 := LZZ5 + (LZZ4 shr 32) + LX4 * LX1;
  LZZ6 := LZZ6 + (LZZ5 shr 32) + LX4 * LX2;
  LZZ7 := LZZ7 + (LZZ6 shr 32) + LX4 * LX3;
  LZZ8 := LZZ8 + (LZZ7 shr 32);

  LW := UInt32(LZZ5);
  AZZ[AZZOff + 5] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZZ6);
  AZZ[AZZOff + 6] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZZ7);
  AZZ[AZZOff + 7] := (LW shl 1) or LC;
  LC := LW shr 31;
  LW := UInt32(LZZ8);
  AZZ[AZZOff + 8] := (LW shl 1) or LC;
  LC := LW shr 31;

  LW := AZZ[AZZOff + 9] + UInt32(LZZ8 shr 32);
  AZZ[AZZOff + 9] := (LW shl 1) or LC;
end;

class function TNat160.Sub(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + Int64(AX[0]) - AY[0];
  AZ[0] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[1]) - AY[1];
  AZ[1] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[2]) - AY[2];
  AZ[2] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[3]) - AY[3];
  AZ[3] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[4]) - AY[4];
  AZ[4] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat160.Sub(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AY: TCryptoLibUInt32Array; AYOff: Int32;
  const AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + Int64(AX[AXOff + 0]) - AY[AYOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[AXOff + 1]) - AY[AYOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[AXOff + 2]) - AY[AYOff + 2];
  AZ[AZOff + 2] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[AXOff + 3]) - AY[AYOff + 3];
  AZ[AZOff + 3] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AX[AXOff + 4]) - AY[AYOff + 4];
  AZ[AZOff + 4] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat160.SubBothFrom(const AX, AY: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + Int64(AZ[0]) - AX[0] - AY[0];
  AZ[0] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[1]) - AX[1] - AY[1];
  AZ[1] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[2]) - AX[2] - AY[2];
  AZ[2] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[3]) - AX[3] - AY[3];
  AZ[3] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[4]) - AX[4] - AY[4];
  AZ[4] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat160.SubFrom(const AX: TCryptoLibUInt32Array; const AZ: TCryptoLibUInt32Array): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + Int64(AZ[0]) - AX[0];
  AZ[0] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[1]) - AX[1];
  AZ[1] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[2]) - AX[2];
  AZ[2] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[3]) - AX[3];
  AZ[3] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[4]) - AX[4];
  AZ[4] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat160.SubFrom(const AX: TCryptoLibUInt32Array; AXOff: Int32; const AZ: TCryptoLibUInt32Array; AZOff: Int32): Int32;
var
  LC: Int64;
begin
  LC := 0;
  LC := LC + Int64(AZ[AZOff + 0]) - AX[AXOff + 0];
  AZ[AZOff + 0] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[AZOff + 1]) - AX[AXOff + 1];
  AZ[AZOff + 1] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[AZOff + 2]) - AX[AXOff + 2];
  AZ[AZOff + 2] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[AZOff + 3]) - AX[AXOff + 3];
  AZ[AZOff + 3] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  LC := LC + Int64(AZ[AZOff + 4]) - AX[AXOff + 4];
  AZ[AZOff + 4] := UInt32(LC);
  LC := TBitOperations.Asr64(LC, 32);
  Result := Int32(LC);
end;

class function TNat160.ToBigInteger(const AX: TCryptoLibUInt32Array): TBigInteger;
var
  LBs: TCryptoLibByteArray;
  LI: Int32;
  LXI: UInt32;
begin
  System.SetLength(LBs, 20);
  for LI := 0 to 4 do
  begin
    LXI := AX[LI];
    if LXI <> 0 then
      TPack.UInt32_To_BE(LXI, LBs, (4 - LI) shl 2);
  end;

  Result := TBigInteger.Create(1, LBs);
end;

class procedure TNat160.Zero(const AZ: TCryptoLibUInt32Array);
begin
  TArrayUtilities.Fill<UInt32>(AZ, 0, 5, UInt32(0));
end;

end.
