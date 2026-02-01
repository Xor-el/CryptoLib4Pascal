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

unit ClpCodec;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  TCodec = class sealed
  public
    class function Decode16(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
    class function Decode24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; static;
    class function Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32; overload; static;
    class procedure Decode32(const ABs: TCryptoLibByteArray; ABsOff: Int32;
      AN: TCryptoLibUInt32Array; ANOff: Int32; ANLen: Int32); overload; static;
    class procedure Encode24(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); static;
    class procedure Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32); overload; static;
    class procedure Encode32(const AN: TCryptoLibUInt32Array; ANOff: Int32; ANLen: Int32;
      const ABs: TCryptoLibByteArray; ABsOff: Int32); overload; static;
    class procedure Encode56(AN: UInt64; ABs: TCryptoLibByteArray; AOff: Int32); static;
  end;

implementation

{ TCodec }

class function TCodec.Decode16(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
var
  LOff: Int32;
begin
  LOff := AOff;
  Result := UInt32(ABs[LOff]);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 8);
end;

class function TCodec.Decode24(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
var
  LOff: Int32;
begin
  LOff := AOff;
  Result := UInt32(ABs[LOff]);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 8);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 16);
end;

class function TCodec.Decode32(const ABs: TCryptoLibByteArray; AOff: Int32): UInt32;
var
  LOff: Int32;
begin
  LOff := AOff;
  Result := UInt32(ABs[LOff]);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 8);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 16);
  System.Inc(LOff);
  Result := Result or (UInt32(ABs[LOff]) shl 24);
end;

class procedure TCodec.Decode32(const ABs: TCryptoLibByteArray; ABsOff: Int32;
  AN: TCryptoLibUInt32Array; ANOff: Int32; ANLen: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < ANLen do
  begin
    AN[ANOff + LI] := Decode32(ABs, ABsOff + LI * 4);
    System.Inc(LI);
  end;
end;

class procedure TCodec.Encode24(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LOff: Int32;
begin
  LOff := AOff;
  ABs[LOff] := Byte(AN);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 8);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 16);
end;

class procedure TCodec.Encode32(AN: UInt32; const ABs: TCryptoLibByteArray; AOff: Int32);
var
  LOff: Int32;
begin
  LOff := AOff;
  ABs[LOff] := Byte(AN);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 8);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 16);
  System.Inc(LOff);
  ABs[LOff] := Byte(AN shr 24);
end;

class procedure TCodec.Encode32(const AN: TCryptoLibUInt32Array; ANOff: Int32; ANLen: Int32;
  const ABs: TCryptoLibByteArray; ABsOff: Int32);
var
  LI: Int32;
begin
  LI := 0;
  while LI < ANLen do
  begin
    TCodec.Encode32(AN[ANOff + LI], ABs, ABsOff + LI * 4);
    System.Inc(LI);
  end;
end;

class procedure TCodec.Encode56(AN: UInt64; ABs: TCryptoLibByteArray; AOff: Int32);
begin
  Encode32(UInt32(AN), ABs, AOff);
  Encode24(UInt32(AN shr 32), ABs, AOff + 4);
end;

end.
