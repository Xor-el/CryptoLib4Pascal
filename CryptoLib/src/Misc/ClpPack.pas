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

unit ClpPack;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBinaryPrimitives,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Endian Conversion Utilities.
  /// </summary>
  TPack = class sealed
  public
    class procedure UInt16_To_BE(AN: UInt16; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt16_To_BE(AN: UInt16; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt16_To_BE(const ANs: TCryptoLibUInt16Array; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt16_To_BE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class function UInt16_To_BE(AN: UInt16): TCryptoLibByteArray; overload; static;
    class function UInt16_To_BE(const ANs: TCryptoLibUInt16Array): TCryptoLibByteArray; overload; static;
    class function UInt16_To_BE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray; overload; static;

    class function BE_To_UInt16(const ABs: TCryptoLibByteArray): UInt16; overload; static;
    class function BE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32): UInt16; overload; static;
    class procedure BE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array; ANsOff: Int32); overload; static;
    class procedure BE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt16Array); overload; static;
    class procedure BE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array;
      ANsOff: Int32; ANsLen: Int32); overload; static;
    class function BE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt16Array; overload; static;

    class procedure UInt24_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt24_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class function BE_To_UInt24(const ABs: TCryptoLibByteArray): UInt32; overload; static;
    class function BE_To_UInt24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; overload; static;

    class procedure UInt32_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt32_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt32_To_BE(const ANs: TCryptoLibUInt32Array; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt32_To_BE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class function UInt32_To_BE(AN: UInt32): TCryptoLibByteArray; overload; static;
    class function UInt32_To_BE(const ANs: TCryptoLibUInt32Array): TCryptoLibByteArray; overload; static;
    class function UInt32_To_BE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray; overload; static;

    class procedure UInt32_To_BE_High(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;
    class procedure UInt32_To_BE_Low(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;

    class function BE_To_UInt32(const ABs: TCryptoLibByteArray): UInt32; overload; static;
    class function BE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; overload; static;
    class procedure BE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt32Array); overload; static;
    class procedure BE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array; ANsOff: Int32); overload; static;
    class procedure BE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array;
      ANsOff: Int32; ANsLen: Int32); overload; static;
    class function BE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt32Array; overload; static;

    class function BE_To_UInt32_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32; static;
    class function BE_To_UInt32_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32; static;

    class procedure UInt64_To_BE(AN: UInt64; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt64_To_BE(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt64_To_BE(const ANs: TCryptoLibUInt64Array; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt64_To_BE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class function UInt64_To_BE(AN: UInt64): TCryptoLibByteArray; overload; static;
    class function UInt64_To_BE(const ANs: TCryptoLibUInt64Array): TCryptoLibByteArray; overload; static;
    class function UInt64_To_BE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray; overload; static;

    class procedure UInt64_To_BE_High(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;
    class procedure UInt64_To_BE_Low(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;

    class function BE_To_UInt64(const ABs: TCryptoLibByteArray): UInt64; overload; static;
    class function BE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32): UInt64; overload; static;
    class procedure BE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt64Array); overload; static;
    class procedure BE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array; ANsOff: Int32); overload; static;
    class procedure BE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array;
      ANsOff: Int32; ANsLen: Int32); overload; static;
    class function BE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt64Array; overload; static;

    class function BE_To_UInt64_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64; static;
    class function BE_To_UInt64_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64; static;

    // Little-endian variants
    class procedure UInt16_To_LE(AN: UInt16; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt16_To_LE(AN: UInt16; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt16_To_LE(const ANs: TCryptoLibUInt16Array; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt16_To_LE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class function UInt16_To_LE(AN: UInt16): TCryptoLibByteArray; overload; static;
    class function UInt16_To_LE(const ANs: TCryptoLibUInt16Array): TCryptoLibByteArray; overload; static;
    class function UInt16_To_LE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray; overload; static;

    class function LE_To_UInt16(const ABs: TCryptoLibByteArray): UInt16; overload; static;
    class function LE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32): UInt16; overload; static;
    class procedure LE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array; ANsOff: Int32); overload; static;
    class procedure LE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt16Array); overload; static;
    class procedure LE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array;
      ANsOff: Int32; ANsLen: Int32); overload; static;
    class function LE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt16Array; overload; static;

    class procedure UInt24_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt24_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class function LE_To_UInt24(const ABs: TCryptoLibByteArray): UInt32; overload; static;
    class function LE_To_UInt24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; overload; static;

    class procedure UInt32_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt32_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt32_To_LE(const ANs: TCryptoLibUInt32Array; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt32_To_LE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class function UInt32_To_LE(AN: UInt32): TCryptoLibByteArray; overload; static;
    class function UInt32_To_LE(const ANs: TCryptoLibUInt32Array): TCryptoLibByteArray; overload; static;
    class function UInt32_To_LE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray; overload; static;

    class procedure UInt32_To_LE_High(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;
    class procedure UInt32_To_LE_Low(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;

    class function LE_To_UInt32(const ABs: TCryptoLibByteArray): UInt32; overload; static;
    class function LE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; overload; static;
    class procedure LE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt32Array); overload; static;
    class procedure LE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array; ANsOff: Int32); overload; static;
    class procedure LE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array;
      ANsOff: Int32; ANsLen: Int32); overload; static;
    class function LE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt32Array; overload; static;

    class function LE_To_UInt32_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32; static;
    class function LE_To_UInt32_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32; static;

    class procedure UInt64_To_LE(AN: UInt64; const ABs: TCryptoLibByteArray); overload; static;
    class procedure UInt64_To_LE(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt64_To_LE(const ANs: TCryptoLibUInt64Array; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure UInt64_To_LE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class function UInt64_To_LE(AN: UInt64): TCryptoLibByteArray; overload; static;
    class function UInt64_To_LE(const ANs: TCryptoLibUInt64Array): TCryptoLibByteArray; overload; static;
    class function UInt64_To_LE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray; overload; static;

    class procedure UInt64_To_LE_High(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;
    class procedure UInt64_To_LE_Low(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32); static;

    class function LE_To_UInt64(const ABs: TCryptoLibByteArray): UInt64; overload; static;
    class function LE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32): UInt64; overload; static;
    class procedure LE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt64Array); overload; static;
    class procedure LE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array; ANsOff: Int32); overload; static;
    class procedure LE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array;
      ANsOff: Int32; ANsLen: Int32); overload; static;
    class function LE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt64Array; overload; static;

    class function LE_To_UInt64_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64; static;
    class function LE_To_UInt64_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64; static;
  end;

implementation

{ TPack }

class procedure TPack.UInt16_To_BE(AN: UInt16; const ABs: TCryptoLibByteArray);
begin
  TBinaryPrimitives.WriteUInt16BigEndian(ABs, 0, AN);
  //ABs[0] := Byte(AN shr 8);
  //ABs[1] := Byte(AN);
end;

class procedure TPack.UInt16_To_BE(AN: UInt16; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  TBinaryPrimitives.WriteUInt16BigEndian(ABs, AOff, AN);
  //ABs[AOff] := Byte(AN shr 8);
  //ABs[AOff + 1] := Byte(AN);
end;

class procedure TPack.UInt16_To_BE(const ANs: TCryptoLibUInt16Array; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(ANs) - 1 do
  begin
    UInt16_To_BE(ANs[LI], ABs, AOff);
    System.Inc(AOff, 2);
  end;
end;

class procedure TPack.UInt16_To_BE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    UInt16_To_BE(ANs[ANsOff + LI], ABs, ABsOff);
    System.Inc(ABsOff, 2);
  end;
end;

class function TPack.UInt16_To_BE(AN: UInt16): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 2);
  UInt16_To_BE(AN, LBs);
  Result := LBs;
end;

class function TPack.UInt16_To_BE(const ANs: TCryptoLibUInt16Array): TCryptoLibByteArray;
begin
  Result := UInt16_To_BE(ANs, 0, System.Length(ANs));
end;

class function TPack.UInt16_To_BE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 2 * ANsLen);
  UInt16_To_BE(ANs, ANsOff, ANsLen, LBs, 0);
  Result := LBs;
end;

class function TPack.BE_To_UInt16(const ABs: TCryptoLibByteArray): UInt16;
begin
  Result := TBinaryPrimitives.ReadUInt16BigEndian(ABs, 0);
  //Result := BE_To_UInt16(ABs, 0);
end;

class function TPack.BE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32): UInt16;
begin
  Result := TBinaryPrimitives.ReadUInt16BigEndian(ABs, AOff);
  //Result := (UInt16(ABs[AOff]) shl 8) or UInt16(ABs[AOff + 1]);
end;

class procedure TPack.BE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array; ANsOff: Int32);
begin
  ANs[ANsOff] := BE_To_UInt16(ABs, ABsOff);
end;

class procedure TPack.BE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt16Array);
begin
  BE_To_UInt16(ABs, AOff, ANs, 0, System.Length(ANs));
end;

class procedure TPack.BE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    ANs[ANsOff + LI] := BE_To_UInt16(ABs, ABsOff);
    System.Inc(ABsOff, 2);
  end;
end;

class function TPack.BE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt16Array;
var
  LNs: TCryptoLibUInt16Array;
begin
  System.SetLength(LNs, ACount);
  BE_To_UInt16(ABs, AOff, LNs);
  Result := LNs;
end;

class procedure TPack.UInt24_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray);
begin
  ABs[0] := Byte(AN shr 16);
  ABs[1] := Byte(AN shr 8);
  ABs[2] := Byte(AN);
end;

class procedure TPack.UInt24_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  ABs[AOff] := Byte(AN shr 16);
  ABs[AOff + 1] := Byte(AN shr 8);
  ABs[AOff + 2] := Byte(AN);
end;

class function TPack.BE_To_UInt24(const ABs: TCryptoLibByteArray): UInt32;
begin
  Result := BE_To_UInt24(ABs, 0);
end;

class function TPack.BE_To_UInt24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
begin
  Result := (UInt32(ABs[AOff]) shl 16) or (UInt32(ABs[AOff + 1]) shl 8) or UInt32(ABs[AOff + 2]);
end;

class procedure TPack.UInt32_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray);
begin
  TBinaryPrimitives.WriteUInt32BigEndian(ABs, 0, AN);
  //UInt32_To_BE(AN, ABs, 0);
end;

class procedure TPack.UInt32_To_BE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  TBinaryPrimitives.WriteUInt32BigEndian(ABs, AOff, AN);
  //ABs[AOff] := Byte(AN shr 24);
  //ABs[AOff + 1] := Byte(AN shr 16);
  //ABs[AOff + 2] := Byte(AN shr 8);
  //ABs[AOff + 3] := Byte(AN);
end;

class procedure TPack.UInt32_To_BE(const ANs: TCryptoLibUInt32Array; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(ANs) - 1 do
  begin
    UInt32_To_BE(ANs[LI], ABs, AOff);
    System.Inc(AOff, 4);
  end;
end;

class procedure TPack.UInt32_To_BE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    UInt32_To_BE(ANs[ANsOff + LI], ABs, ABsOff);
    System.Inc(ABsOff, 4);
  end;
end;

class function TPack.UInt32_To_BE(AN: UInt32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 4);
  UInt32_To_BE(AN, LBs);
  Result := LBs;
end;

class function TPack.UInt32_To_BE(const ANs: TCryptoLibUInt32Array): TCryptoLibByteArray;
begin
  Result := UInt32_To_BE(ANs, 0, System.Length(ANs));
end;

class function TPack.UInt32_To_BE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 4 * ANsLen);
  UInt32_To_BE(ANs, ANsOff, ANsLen, LBs, 0);
  Result := LBs;
end;

class procedure TPack.UInt32_To_BE_High(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 4 - ALen;
  while LPos < 4 do
  begin
    ABs[AOff] := Byte(AN shr ((3 - LPos) * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class procedure TPack.UInt32_To_BE_Low(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 0;
  while LPos < ALen do
  begin
    ABs[AOff] := Byte(AN shr ((ALen - 1 - LPos) * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class function TPack.BE_To_UInt32(const ABs: TCryptoLibByteArray): UInt32;
begin
  Result := TBinaryPrimitives.ReadUInt32BigEndian(ABs, 0);
  //Result := BE_To_UInt32(ABs, 0);
end;

class function TPack.BE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
begin
  Result := TBinaryPrimitives.ReadUInt32BigEndian(ABs, AOff);
  //Result := (UInt32(ABs[AOff]) shl 24) or (UInt32(ABs[AOff + 1]) shl 16) or
  //          (UInt32(ABs[AOff + 2]) shl 8) or UInt32(ABs[AOff + 3]);
end;

class procedure TPack.BE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt32Array);
begin
  BE_To_UInt32(ABs, AOff, ANs, 0, System.Length(ANs));
end;

class procedure TPack.BE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array; ANsOff: Int32);
begin
  ANs[ANsOff] := BE_To_UInt32(ABs, ABsOff);
end;

class procedure TPack.BE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array;
  ANsOff: Int32; ANsLen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    ANs[ANsOff + LI] := BE_To_UInt32(ABs, ABsOff);
    System.Inc(ABsOff, 4);
  end;
end;

class function TPack.BE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt32Array;
var
  LNs: TCryptoLibUInt32Array;
begin
  System.SetLength(LNs, ACount);
  BE_To_UInt32(ABs, AOff, LNs);
  Result := LNs;
end;

class function TPack.BE_To_UInt32_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32;
var
  LResult: UInt32;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := (LResult shl 8) or UInt32(ABs[AOff + LPos]);
    System.Inc(LPos);
  end;

  Result := LResult shl ((4 - ALen) * 8);
end;

class function TPack.BE_To_UInt32_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32;
var
  LResult: UInt32;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := (LResult shl 8) or UInt32(ABs[AOff + LPos]);
    System.Inc(LPos);
  end;

  Result := LResult;
end;

class procedure TPack.UInt64_To_BE(AN: UInt64; const ABs: TCryptoLibByteArray);
begin
  TBinaryPrimitives.WriteUInt64BigEndian(ABs, 0, AN);
  //UInt64_To_BE(AN, ABs, 0);
end;

class procedure TPack.UInt64_To_BE(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  TBinaryPrimitives.WriteUInt64BigEndian(ABs, AOff, AN);
  //UInt32_To_BE(UInt32(AN shr 32), ABs, AOff);
  //UInt32_To_BE(UInt32(AN), ABs, AOff + 4);
end;

class procedure TPack.UInt64_To_BE(const ANs: TCryptoLibUInt64Array; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(ANs) - 1 do
  begin
    UInt64_To_BE(ANs[LI], ABs, AOff);
    System.Inc(AOff, 8);
  end;
end;

class procedure TPack.UInt64_To_BE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    UInt64_To_BE(ANs[ANsOff + LI], ABs, ABsOff);
    System.Inc(ABsOff, 8);
  end;
end;

class function TPack.UInt64_To_BE(AN: UInt64): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 8);
  UInt64_To_BE(AN, LBs);
  Result := LBs;
end;

class function TPack.UInt64_To_BE(const ANs: TCryptoLibUInt64Array): TCryptoLibByteArray;
begin
  Result := UInt64_To_BE(ANs, 0, System.Length(ANs));
end;

class function TPack.UInt64_To_BE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 8 * ANsLen);
  UInt64_To_BE(ANs, ANsOff, ANsLen, LBs, 0);
  Result := LBs;
end;

class procedure TPack.UInt64_To_BE_High(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 8 - ALen;
  while LPos < 8 do
  begin
    ABs[AOff] := Byte(AN shr ((7 - LPos) * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class procedure TPack.UInt64_To_BE_Low(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 0;
  while LPos < ALen do
  begin
    ABs[AOff] := Byte(AN shr ((ALen - 1 - LPos) * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class function TPack.BE_To_UInt64(const ABs: TCryptoLibByteArray): UInt64;
begin
  Result := TBinaryPrimitives.ReadUInt64BigEndian(ABs, 0);
  //Result := BE_To_UInt64(ABs, 0);
end;

class function TPack.BE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32): UInt64;
begin
  Result := (UInt64(BE_To_UInt32(ABs, AOff)) shl 32) or UInt64(BE_To_UInt32(ABs, AOff + 4));
end;

class procedure TPack.BE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt64Array);
begin
  BE_To_UInt64(ABs, AOff, ANs, 0, System.Length(ANs));
end;

class procedure TPack.BE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array; ANsOff: Int32);
begin
  ANs[ANsOff] := BE_To_UInt64(ABs, ABsOff);
end;

class procedure TPack.BE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array;
  ANsOff: Int32; ANsLen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    ANs[ANsOff + LI] := BE_To_UInt64(ABs, ABsOff);
    System.Inc(ABsOff, 8);
  end;
end;

class function TPack.BE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt64Array;
var
  LNs: TCryptoLibUInt64Array;
begin
  System.SetLength(LNs, ACount);
  BE_To_UInt64(ABs, AOff, LNs);
  Result := LNs;
end;

class function TPack.BE_To_UInt64_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64;
var
  LResult: UInt64;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := (LResult shl 8) or UInt64(ABs[AOff + LPos]);
    System.Inc(LPos);
  end;

  Result := LResult shl ((8 - ALen) * 8);
end;

class function TPack.BE_To_UInt64_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64;
var
  LResult: UInt64;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := (LResult shl 8) or UInt64(ABs[AOff + LPos]);
    System.Inc(LPos);
  end;

  Result := LResult;
end;

// ---------------- Little-endian ----------------

class procedure TPack.UInt16_To_LE(AN: UInt16; const ABs: TCryptoLibByteArray);
begin
  TBinaryPrimitives.WriteUInt16LittleEndian(ABs, 0, AN);
  //ABs[0] := Byte(AN);
  //ABs[1] := Byte(AN shr 8);
end;

class procedure TPack.UInt16_To_LE(AN: UInt16; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  TBinaryPrimitives.WriteUInt16LittleEndian(ABs, AOff, AN);
  //ABs[AOff] := Byte(AN);
  //ABs[AOff + 1] := Byte(AN shr 8);
end;

class procedure TPack.UInt16_To_LE(const ANs: TCryptoLibUInt16Array; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(ANs) - 1 do
  begin
    UInt16_To_LE(ANs[LI], ABs, AOff);
    System.Inc(AOff, 2);
  end;
end;

class procedure TPack.UInt16_To_LE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    UInt16_To_LE(ANs[ANsOff + LI], ABs, ABsOff);
    System.Inc(ABsOff, 2);
  end;
end;

class function TPack.UInt16_To_LE(AN: UInt16): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 2);
  UInt16_To_LE(AN, LBs);
  Result := LBs;
end;

class function TPack.UInt16_To_LE(const ANs: TCryptoLibUInt16Array): TCryptoLibByteArray;
begin
  Result := UInt16_To_LE(ANs, 0, System.Length(ANs));
end;

class function TPack.UInt16_To_LE(const ANs: TCryptoLibUInt16Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 2 * ANsLen);
  UInt16_To_LE(ANs, ANsOff, ANsLen, LBs, 0);
  Result := LBs;
end;

class function TPack.LE_To_UInt16(const ABs: TCryptoLibByteArray): UInt16;
begin
  Result := TBinaryPrimitives.ReadUInt16LittleEndian(ABs, 0);
  //Result := LE_To_UInt16(ABs, 0);
end;

class function TPack.LE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32): UInt16;
begin
  Result := TBinaryPrimitives.ReadUInt16LittleEndian(ABs, AOff);
  //Result := UInt16(ABs[AOff]) or (UInt16(ABs[AOff + 1]) shl 8);
end;

class procedure TPack.LE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array; ANsOff: Int32);
begin
  ANs[ANsOff] := LE_To_UInt16(ABs, ABsOff);
end;

class procedure TPack.LE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt16Array);
begin
  LE_To_UInt16(ABs, AOff, ANs, 0, System.Length(ANs));
end;

class procedure TPack.LE_To_UInt16(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt16Array;
  ANsOff: Int32; ANsLen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    ANs[ANsOff + LI] := LE_To_UInt16(ABs, ABsOff);
    System.Inc(ABsOff, 2);
  end;
end;

class function TPack.LE_To_UInt16(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt16Array;
var
  LNs: TCryptoLibUInt16Array;
begin
  System.SetLength(LNs, ACount);
  LE_To_UInt16(ABs, AOff, LNs);
  Result := LNs;
end;

class procedure TPack.UInt24_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray);
begin
  ABs[0] := Byte(AN);
  ABs[1] := Byte(AN shr 8);
  ABs[2] := Byte(AN shr 16);
end;

class procedure TPack.UInt24_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  ABs[AOff] := Byte(AN);
  ABs[AOff + 1] := Byte(AN shr 8);
  ABs[AOff + 2] := Byte(AN shr 16);
end;

class function TPack.LE_To_UInt24(const ABs: TCryptoLibByteArray): UInt32;
begin
  Result := LE_To_UInt24(ABs, 0);
end;

class function TPack.LE_To_UInt24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
begin
  Result := UInt32(ABs[AOff]) or (UInt32(ABs[AOff + 1]) shl 8) or (UInt32(ABs[AOff + 2]) shl 16);
end;

class procedure TPack.UInt32_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray);
begin
  TBinaryPrimitives.WriteUInt32LittleEndian(ABs, 0, AN);
  //UInt32_To_LE(AN, ABs, 0);
end;

class procedure TPack.UInt32_To_LE(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  TBinaryPrimitives.WriteUInt32LittleEndian(ABs, AOff, AN);
  //ABs[AOff] := Byte(AN);
  //ABs[AOff + 1] := Byte(AN shr 8);
  //ABs[AOff + 2] := Byte(AN shr 16);
  //ABs[AOff + 3] := Byte(AN shr 24);
end;

class procedure TPack.UInt32_To_LE(const ANs: TCryptoLibUInt32Array; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(ANs) - 1 do
  begin
    UInt32_To_LE(ANs[LI], ABs, AOff);
    System.Inc(AOff, 4);
  end;
end;

class procedure TPack.UInt32_To_LE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    UInt32_To_LE(ANs[ANsOff + LI], ABs, ABsOff);
    System.Inc(ABsOff, 4);
  end;
end;

class function TPack.UInt32_To_LE(AN: UInt32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 4);
  UInt32_To_LE(AN, LBs);
  Result := LBs;
end;

class function TPack.UInt32_To_LE(const ANs: TCryptoLibUInt32Array): TCryptoLibByteArray;
begin
  Result := UInt32_To_LE(ANs, 0, System.Length(ANs));
end;

class function TPack.UInt32_To_LE(const ANs: TCryptoLibUInt32Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 4 * ANsLen);
  UInt32_To_LE(ANs, ANsOff, ANsLen, LBs, 0);
  Result := LBs;
end;

class procedure TPack.UInt32_To_LE_High(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 4 - ALen;
  while LPos < 4 do
  begin
    ABs[AOff] := Byte(AN shr (LPos * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class procedure TPack.UInt32_To_LE_Low(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 0;
  while LPos < ALen do
  begin
    ABs[AOff] := Byte(AN shr (LPos * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class function TPack.LE_To_UInt32(const ABs: TCryptoLibByteArray): UInt32;
begin
  Result := TBinaryPrimitives.ReadUInt32LittleEndian(ABs, 0);
  //Result := LE_To_UInt32(ABs, 0);
end;

class function TPack.LE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
begin
  Result := TBinaryPrimitives.ReadUInt32LittleEndian(ABs, AOff);
  //Result := UInt32(ABs[AOff]) or (UInt32(ABs[AOff + 1]) shl 8) or
  //          (UInt32(ABs[AOff + 2]) shl 16) or (UInt32(ABs[AOff + 3]) shl 24);
end;

class procedure TPack.LE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt32Array);
begin
  LE_To_UInt32(ABs, AOff, ANs, 0, System.Length(ANs));
end;

class procedure TPack.LE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array; ANsOff: Int32);
begin
  ANs[ANsOff] := LE_To_UInt32(ABs, ABsOff);
end;

class procedure TPack.LE_To_UInt32(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt32Array;
  ANsOff: Int32; ANsLen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    ANs[ANsOff + LI] := LE_To_UInt32(ABs, ABsOff);
    System.Inc(ABsOff, 4);
  end;
end;

class function TPack.LE_To_UInt32(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt32Array;
var
  LNs: TCryptoLibUInt32Array;
begin
  System.SetLength(LNs, ACount);
  LE_To_UInt32(ABs, AOff, LNs);
  Result := LNs;
end;

class function TPack.LE_To_UInt32_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32;
var
  LResult: UInt32;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := LResult or (UInt32(ABs[AOff + LPos]) shl (LPos * 8));
    System.Inc(LPos);
  end;

  Result := LResult shl ((4 - ALen) * 8);
end;

class function TPack.LE_To_UInt32_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt32;
var
  LResult: UInt32;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 4) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := LResult or (UInt32(ABs[AOff + LPos]) shl (LPos * 8));
    System.Inc(LPos);
  end;

  Result := LResult;
end;

class procedure TPack.UInt64_To_LE(AN: UInt64; const ABs: TCryptoLibByteArray);
begin
  TBinaryPrimitives.WriteUInt64LittleEndian(ABs, 0, AN);
  //UInt64_To_LE(AN, ABs, 0);
end;

class procedure TPack.UInt64_To_LE(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32);
begin
  TBinaryPrimitives.WriteUInt64LittleEndian(ABs, AOff, AN);
  //UInt32_To_LE(UInt32(AN), ABs, AOff);
  //UInt32_To_LE(UInt32(AN shr 32), ABs, AOff + 4);
end;

class procedure TPack.UInt64_To_LE(const ANs: TCryptoLibUInt64Array; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Length(ANs) - 1 do
  begin
    UInt64_To_LE(ANs[LI], ABs, AOff);
    System.Inc(AOff, 8);
  end;
end;

class procedure TPack.UInt64_To_LE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    UInt64_To_LE(ANs[ANsOff + LI], ABs, ABsOff);
    System.Inc(ABsOff, 8);
  end;
end;

class function TPack.UInt64_To_LE(AN: UInt64): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 8);
  UInt64_To_LE(AN, LBs);
  Result := LBs;
end;

class function TPack.UInt64_To_LE(const ANs: TCryptoLibUInt64Array): TCryptoLibByteArray;
begin
  Result := UInt64_To_LE(ANs, 0, System.Length(ANs));
end;

class function TPack.UInt64_To_LE(const ANs: TCryptoLibUInt64Array; ANsOff: Int32; ANsLen: Int32): TCryptoLibByteArray;
var
  LBs: TCryptoLibByteArray;
begin
  System.SetLength(LBs, 8 * ANsLen);
  UInt64_To_LE(ANs, ANsOff, ANsLen, LBs, 0);
  Result := LBs;
end;

class procedure TPack.UInt64_To_LE_High(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 8 - ALen;
  while LPos < 8 do
  begin
    ABs[AOff] := Byte(AN shr (LPos * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class procedure TPack.UInt64_To_LE_Low(AN: UInt64; const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32);
var
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LPos := 0;
  while LPos < ALen do
  begin
    ABs[AOff] := Byte(AN shr (LPos * 8));
    System.Inc(AOff);
    System.Inc(LPos);
  end;
end;

class function TPack.LE_To_UInt64(const ABs: TCryptoLibByteArray): UInt64;
begin
  Result := TBinaryPrimitives.ReadUInt64LittleEndian(ABs, 0);
  //Result := LE_To_UInt64(ABs, 0);
end;

class function TPack.LE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32): UInt64;
begin
  Result := TBinaryPrimitives.ReadUInt64LittleEndian(ABs, AOff);
  //Result := UInt64(LE_To_UInt32(ABs, AOff)) or (UInt64(LE_To_UInt32(ABs, AOff + 4)) shl 32);
end;

class procedure TPack.LE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; const ANs: TCryptoLibUInt64Array);
begin
  LE_To_UInt64(ABs, AOff, ANs, 0, System.Length(ANs));
end;

class procedure TPack.LE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array; ANsOff: Int32);
begin
  ANs[ANsOff] := LE_To_UInt64(ABs, ABsOff);
end;

class procedure TPack.LE_To_UInt64(const ABs: TCryptoLibByteArray; ABsOff: Int32; const ANs: TCryptoLibUInt64Array;
  ANsOff: Int32; ANsLen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ANsLen - 1 do
  begin
    ANs[ANsOff + LI] := LE_To_UInt64(ABs, ABsOff);
    System.Inc(ABsOff, 8);
  end;
end;

class function TPack.LE_To_UInt64(const ABs: TCryptoLibByteArray; AOff: Int32; ACount: Int32): TCryptoLibUInt64Array;
var
  LNs: TCryptoLibUInt64Array;
begin
  System.SetLength(LNs, ACount);
  LE_To_UInt64(ABs, AOff, LNs);
  Result := LNs;
end;

class function TPack.LE_To_UInt64_High(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64;
var
  LResult: UInt64;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := LResult or (UInt64(ABs[AOff + LPos]) shl (LPos * 8));
    System.Inc(LPos);
  end;

  Result := LResult shl ((8 - ALen) * 8);
end;

class function TPack.LE_To_UInt64_Low(const ABs: TCryptoLibByteArray; AOff: Int32; ALen: Int32): UInt64;
var
  LResult: UInt64;
  LPos: Int32;
begin
  if (ALen < 1) or (ALen > 8) then
    raise EArgumentOutOfRangeCryptoLibException.Create('len');

  LResult := 0;
  LPos := 0;
  while LPos < ALen do
  begin
    LResult := LResult or (UInt64(ABs[AOff + LPos]) shl (LPos * 8));
    System.Inc(LPos);
  end;

  Result := LResult;
end;

end.

