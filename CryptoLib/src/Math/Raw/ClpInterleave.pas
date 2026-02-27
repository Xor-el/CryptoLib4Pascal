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

unit ClpInterleave;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBits,
  ClpCryptoLibTypes;

type
  TInterleave = class sealed
  private
    const M32: UInt64 = UInt64($55555555);
    const M64: UInt64 = UInt64($5555555555555555);
    const M64R: UInt64 = UInt64($AAAAAAAAAAAAAAAA);
  public
    class function Expand8to16(AX: Byte): UInt32; static;
    class function Expand16to32(AX: UInt16): UInt32; static;
    class function Expand32to64(AX: UInt32): UInt64; static;

    class procedure Expand64To128(AX: UInt64; const AZ: TCryptoLibUInt64Array; AZOff: Int32); overload; static;
    class procedure Expand64To128(const AXs: TCryptoLibUInt64Array; AXsOff: Int32; AXsLen: Int32;
      const AZs: TCryptoLibUInt64Array; AZsOff: Int32); overload; static;

    class function Expand64To128Rev(AX: UInt64; out ALow: UInt64): UInt64; static;

    class function Shuffle(AX: UInt32): UInt32; overload; static;
    class function Shuffle(AX: UInt64): UInt64; overload; static;

    class function Shuffle2(AX: UInt32): UInt32; overload; static;
    class function Shuffle2(AX: UInt64): UInt64; overload; static;

    class function Unshuffle(AX: UInt32): UInt32; overload; static;
    class function Unshuffle(AX: UInt64): UInt64; overload; static;
    class function Unshuffle(AX: UInt64; out AEven: UInt64): UInt64; overload; static;
    class function Unshuffle(AX0, AX1: UInt64; out AEven: UInt64): UInt64; overload; static;

    class function Unshuffle2(AX: UInt32): UInt32; overload; static;
    class function Unshuffle2(AX: UInt64): UInt64; overload; static;

    class function Transpose(AX: UInt64): UInt64; static;
  end;

implementation

{ TInterleave }

class function TInterleave.Expand8to16(AX: Byte): UInt32;
var
  LT: UInt32;
begin
  LT := AX;
  LT := (LT or (LT shl 4)) and $0F0F;
  LT := (LT or (LT shl 2)) and $3333;
  LT := (LT or (LT shl 1)) and $5555;
  Result := LT;
end;

class function TInterleave.Expand16to32(AX: UInt16): UInt32;
var
  LT: UInt32;
begin
  LT := AX;
  LT := (LT or (LT shl 8)) and $00FF00FF;
  LT := (LT or (LT shl 4)) and $0F0F0F0F;
  LT := (LT or (LT shl 2)) and $33333333;
  LT := (LT or (LT shl 1)) and $55555555;
  Result := LT;
end;

class function TInterleave.Expand32to64(AX: UInt32): UInt64;
var
  LX: UInt32;
begin
  // "shuffle" low half to even bits and high half to odd bits
  LX := AX;
  LX := TBits.BitPermuteStep(LX, $0000FF00, 8);
  LX := TBits.BitPermuteStep(LX, $00F000F0, 4);
  LX := TBits.BitPermuteStep(LX, $0C0C0C0C, 2);
  LX := TBits.BitPermuteStep(LX, $22222222, 1);

  Result := (UInt64((LX shr 1) and UInt32(M32)) shl 32) or UInt64(LX and UInt32(M32));
end;

class procedure TInterleave.Expand64To128(AX: UInt64; const AZ: TCryptoLibUInt64Array; AZOff: Int32);
var
  LX: UInt64;
begin
  LX := AX;

  // "shuffle" low half to even bits and high half to odd bits
  LX := TBits.BitPermuteStep(LX, UInt64($00000000FFFF0000), 16);
  LX := TBits.BitPermuteStep(LX, UInt64($0000FF000000FF00), 8);
  LX := TBits.BitPermuteStep(LX, UInt64($00F000F000F000F0), 4);
  LX := TBits.BitPermuteStep(LX, UInt64($0C0C0C0C0C0C0C0C), 2);
  LX := TBits.BitPermuteStep(LX, UInt64($2222222222222222), 1);

  AZ[AZOff] := LX and M64;
  AZ[AZOff + 1] := (LX shr 1) and M64;
end;

class procedure TInterleave.Expand64To128(const AXs: TCryptoLibUInt64Array; AXsOff: Int32; AXsLen: Int32;
  const AZs: TCryptoLibUInt64Array; AZsOff: Int32);
var
  LXsPos, LZsPos: Int32;
begin
  LXsPos := AXsLen;
  LZsPos := AZsOff + (AXsLen shl 1);
  while True do
  begin
    System.Dec(LXsPos);
    if LXsPos < 0 then
      Break;

    System.Dec(LZsPos, 2);
    Expand64To128(AXs[AXsOff + LXsPos], AZs, LZsPos);
  end;
end;

class function TInterleave.Expand64To128Rev(AX: UInt64; out ALow: UInt64): UInt64;
var
  LX: UInt64;
begin
  LX := AX;

  // "shuffle" low half to even bits and high half to odd bits
  LX := TBits.BitPermuteStep(LX, UInt64($00000000FFFF0000), 16);
  LX := TBits.BitPermuteStep(LX, UInt64($0000FF000000FF00), 8);
  LX := TBits.BitPermuteStep(LX, UInt64($00F000F000F000F0), 4);
  LX := TBits.BitPermuteStep(LX, UInt64($0C0C0C0C0C0C0C0C), 2);
  LX := TBits.BitPermuteStep(LX, UInt64($2222222222222222), 1);

  ALow := LX and M64R;
  Result := (LX shl 1) and M64R;
end;

class function TInterleave.Shuffle(AX: UInt32): UInt32;
var
  LX: UInt32;
begin
  LX := AX;

  // "shuffle" low half to even bits and high half to odd bits
  LX := TBits.BitPermuteStep(LX, $0000FF00, 8);
  LX := TBits.BitPermuteStep(LX, $00F000F0, 4);
  LX := TBits.BitPermuteStep(LX, $0C0C0C0C, 2);
  LX := TBits.BitPermuteStep(LX, $22222222, 1);
  Result := LX;
end;

class function TInterleave.Shuffle(AX: UInt64): UInt64;
var
  LX: UInt64;
begin
  LX := AX;

  // "shuffle" low half to even bits and high half to odd bits
  LX := TBits.BitPermuteStep(LX, UInt64($00000000FFFF0000), 16);
  LX := TBits.BitPermuteStep(LX, UInt64($0000FF000000FF00), 8);
  LX := TBits.BitPermuteStep(LX, UInt64($00F000F000F000F0), 4);
  LX := TBits.BitPermuteStep(LX, UInt64($0C0C0C0C0C0C0C0C), 2);
  LX := TBits.BitPermuteStep(LX, UInt64($2222222222222222), 1);
  Result := LX;
end;

class function TInterleave.Shuffle2(AX: UInt32): UInt32;
var
  LX: UInt32;
begin
  LX := AX;

  // 4 3 2 1 0 => 2 1 4 3 0
  LX := TBits.BitPermuteStep(LX, $0000F0F0, 12);
  LX := TBits.BitPermuteStep(LX, $00CC00CC, 6);

  // 2 1 4 3 0 => 2 1 4 0 3
  LX := TBits.BitPermuteStep(LX, $22222222, 1);

  // 2 1 4 0 3 => 2 1 0 4 3
  LX := TBits.BitPermuteStep(LX, $0C0C0C0C, 2);

  Result := LX;
end;

class function TInterleave.Shuffle2(AX: UInt64): UInt64;
var
  LX: UInt64;
begin
  LX := AX;

  // 5 4 3 2 1 0 => 3 2 5 4 1 0
  LX := TBits.BitPermuteStep(LX, UInt64($00000000FF00FF00), 24);
  LX := TBits.BitPermuteStep(LX, UInt64($0000F0F00000F0F0), 12);

  // 3 2 5 4 1 0 => 3 2 1 0 5 4
  LX := TBits.BitPermuteStep(LX, UInt64($00CC00CC00CC00CC), 6);
  LX := TBits.BitPermuteStep(LX, UInt64($0A0A0A0A0A0A0A0A), 3);

  Result := LX;
end;

class function TInterleave.Unshuffle(AX: UInt32): UInt32;
var
  LX: UInt32;
begin
  LX := AX;

  // "unshuffle" even bits to low half and odd bits to high half
  LX := TBits.BitPermuteStep(LX, $22222222, 1);
  LX := TBits.BitPermuteStep(LX, $0C0C0C0C, 2);
  LX := TBits.BitPermuteStep(LX, $00F000F0, 4);
  LX := TBits.BitPermuteStep(LX, $0000FF00, 8);

  Result := LX;
end;

class function TInterleave.Unshuffle(AX: UInt64): UInt64;
var
  LX: UInt64;
begin
  LX := AX;

  // "unshuffle" even bits to low half and odd bits to high half
  LX := TBits.BitPermuteStep(LX, UInt64($2222222222222222), 1);
  LX := TBits.BitPermuteStep(LX, UInt64($0C0C0C0C0C0C0C0C), 2);
  LX := TBits.BitPermuteStep(LX, UInt64($00F000F000F000F0), 4);
  LX := TBits.BitPermuteStep(LX, UInt64($0000FF000000FF00), 8);
  LX := TBits.BitPermuteStep(LX, UInt64($00000000FFFF0000), 16);

  Result := LX;
end;

class function TInterleave.Unshuffle(AX: UInt64; out AEven: UInt64): UInt64;
var
  LU0: UInt64;
begin
  LU0 := Unshuffle(AX);
  AEven := LU0 and UInt64($00000000FFFFFFFF);
  Result := LU0 shr 32;
end;

class function TInterleave.Unshuffle(AX0, AX1: UInt64; out AEven: UInt64): UInt64;
var
  LU0, LU1: UInt64;
begin
  LU0 := Unshuffle(AX0);
  LU1 := Unshuffle(AX1);
  AEven := (LU1 shl 32) or (LU0 and UInt64($00000000FFFFFFFF));
  Result := (LU0 shr 32) or (LU1 and UInt64($FFFFFFFF00000000));
end;

class function TInterleave.Unshuffle2(AX: UInt32): UInt32;
var
  LX: UInt32;
begin
  LX := AX;

  // 4 3 2 1 0 => 4 3 1 2 0
  LX := TBits.BitPermuteStep(LX, $0C0C0C0C, 2);

  // 4 3 1 2 0 => 4 3 1 0 2
  LX := TBits.BitPermuteStep(LX, $22222222, 1);

  // 4 3 1 0 2 => 1 0 4 3 2
  LX := TBits.BitPermuteStep(LX, $0000F0F0, 12);
  LX := TBits.BitPermuteStep(LX, $00CC00CC, 6);

  Result := LX;
end;

class function TInterleave.Unshuffle2(AX: UInt64): UInt64;
var
  LX: UInt64;
begin
  LX := AX;

  // 5 4 3 2 1 0 => 5 4 1 0 3 2
  LX := TBits.BitPermuteStep(LX, UInt64($00CC00CC00CC00CC), 6);
  LX := TBits.BitPermuteStep(LX, UInt64($0A0A0A0A0A0A0A0A), 3);

  // 5 4 1 0 3 2 => 1 0 5 4 3 2
  LX := TBits.BitPermuteStep(LX, UInt64($00000000FF00FF00), 24);
  LX := TBits.BitPermuteStep(LX, UInt64($0000F0F00000F0F0), 12);

  Result := LX;
end;

class function TInterleave.Transpose(AX: UInt64): UInt64;
var
  LX: UInt64;
begin
  LX := AX;
  LX := TBits.BitPermuteStep(LX, UInt64($00000000F0F0F0F0), 28);
  LX := TBits.BitPermuteStep(LX, UInt64($0000CCCC0000CCCC), 14);
  LX := TBits.BitPermuteStep(LX, UInt64($00AA00AA00AA00AA), 7);
  Result := LX;
end;

end.
