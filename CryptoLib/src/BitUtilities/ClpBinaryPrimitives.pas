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

unit ClpBinaryPrimitives;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes;

type
  TBinaryPrimitives = class
  private
    class procedure CheckBounds(const AData: TCryptoLibByteArray; AOffset, ANeeded: Integer); static; inline;

    // UInt16 helpers
    class procedure WriteUInt16LEInternal(AValue: UInt16; const AData: TCryptoLibByteArray; AOffset: Integer); static; inline;
    class procedure WriteUInt16BEInternal(AValue: UInt16; const AData: TCryptoLibByteArray; AOffset: Integer); static; inline;
    class function ReadUInt16LEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16; static; inline;
    class function ReadUInt16BEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16; static; inline;

    // UInt32 helpers
    class procedure WriteUInt32LEInternal(AValue: UInt32; const AData: TCryptoLibByteArray; AOffset: Integer); static; inline;
    class procedure WriteUInt32BEInternal(AValue: UInt32; const AData: TCryptoLibByteArray; AOffset: Integer); static; inline;
    class function ReadUInt32LEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32; static; inline;
    class function ReadUInt32BEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32; static; inline;

    // UInt64 helpers
    class procedure WriteUInt64LEInternal(AValue: UInt64; const AData: TCryptoLibByteArray; AOffset: Integer); static; inline;
    class procedure WriteUInt64BEInternal(AValue: UInt64; const AData: TCryptoLibByteArray; AOffset: Integer); static; inline;
    class function ReadUInt64LEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64; static; inline;
    class function ReadUInt64BEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64; static; inline;

  public
    class procedure WriteUInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt16); static;
    class procedure WriteUInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt32); static;
    class procedure WriteUInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt64); static;

    class procedure WriteInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int16); static;
    class procedure WriteInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int32); static;
    class procedure WriteInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int64); static;

    class procedure WriteSingleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Single); static;
    class procedure WriteDoubleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Double); static;

    class procedure WriteUInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt16); static;
    class procedure WriteUInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt32); static;
    class procedure WriteUInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt64); static;

    class procedure WriteInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int16); static;
    class procedure WriteInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int32); static;
    class procedure WriteInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int64); static;

    class procedure WriteSingleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Single); static;
    class procedure WriteDoubleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Double); static;

    class function ReadUInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16; static;
    class function ReadUInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32; static;
    class function ReadUInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64; static;

    class function ReadInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int16; static;
    class function ReadInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int32; static;
    class function ReadInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int64; static;

    class function ReadSingleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Single; static;
    class function ReadDoubleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Double; static;

    class function ReadUInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16; static;
    class function ReadUInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32; static;
    class function ReadUInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64; static;

    class function ReadInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int16; static;
    class function ReadInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int32; static;
    class function ReadInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int64; static;

    class function ReadSingleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Single; static;
    class function ReadDoubleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Double; static;
  end;

implementation

{ TBinaryPrimitives }

class procedure TBinaryPrimitives.CheckBounds(const AData: TCryptoLibByteArray; AOffset, ANeeded: Integer);
begin
  if (AOffset < 0) or (AOffset + ANeeded > Length(AData)) then
    raise EArgumentOutOfRangeException.Create('AOffset');
end;

// ============================================================================
// UInt16 Internal Helpers
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt16LEInternal(AValue: UInt16; const AData: TCryptoLibByteArray; AOffset: Integer);
begin
  AData[AOffset]     := Byte(AValue);
  AData[AOffset + 1] := Byte(AValue shr 8);
end;

class procedure TBinaryPrimitives.WriteUInt16BEInternal(AValue: UInt16; const AData: TCryptoLibByteArray; AOffset: Integer);
begin
  AData[AOffset]     := Byte(AValue shr 8);
  AData[AOffset + 1] := Byte(AValue);
end;

class function TBinaryPrimitives.ReadUInt16LEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16;
begin
  Result := UInt16(AData[AOffset]) or (UInt16(AData[AOffset + 1]) shl 8);
end;

class function TBinaryPrimitives.ReadUInt16BEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16;
begin
  Result := (UInt16(AData[AOffset]) shl 8) or UInt16(AData[AOffset + 1]);
end;

// ============================================================================
// UInt32 Internal Helpers
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt32LEInternal(AValue: UInt32; const AData: TCryptoLibByteArray; AOffset: Integer);
begin
  AData[AOffset]     := Byte(AValue);
  AData[AOffset + 1] := Byte(AValue shr 8);
  AData[AOffset + 2] := Byte(AValue shr 16);
  AData[AOffset + 3] := Byte(AValue shr 24);
end;

class procedure TBinaryPrimitives.WriteUInt32BEInternal(AValue: UInt32; const AData: TCryptoLibByteArray; AOffset: Integer);
begin
  AData[AOffset]     := Byte(AValue shr 24);
  AData[AOffset + 1] := Byte(AValue shr 16);
  AData[AOffset + 2] := Byte(AValue shr 8);
  AData[AOffset + 3] := Byte(AValue);
end;

class function TBinaryPrimitives.ReadUInt32LEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32;
begin
  Result := UInt32(AData[AOffset]) or
            (UInt32(AData[AOffset + 1]) shl 8) or
            (UInt32(AData[AOffset + 2]) shl 16) or
            (UInt32(AData[AOffset + 3]) shl 24);
end;

class function TBinaryPrimitives.ReadUInt32BEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32;
begin
  Result := (UInt32(AData[AOffset]) shl 24) or
            (UInt32(AData[AOffset + 1]) shl 16) or
            (UInt32(AData[AOffset + 2]) shl 8) or
            UInt32(AData[AOffset + 3]);
end;

// ============================================================================
// UInt64 Internal Helpers
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt64LEInternal(AValue: UInt64; const AData: TCryptoLibByteArray; AOffset: Integer);
begin
  AData[AOffset]     := Byte(AValue);
  AData[AOffset + 1] := Byte(AValue shr 8);
  AData[AOffset + 2] := Byte(AValue shr 16);
  AData[AOffset + 3] := Byte(AValue shr 24);
  AData[AOffset + 4] := Byte(AValue shr 32);
  AData[AOffset + 5] := Byte(AValue shr 40);
  AData[AOffset + 6] := Byte(AValue shr 48);
  AData[AOffset + 7] := Byte(AValue shr 56);
end;

class procedure TBinaryPrimitives.WriteUInt64BEInternal(AValue: UInt64; const AData: TCryptoLibByteArray; AOffset: Integer);
begin
  AData[AOffset]     := Byte(AValue shr 56);
  AData[AOffset + 1] := Byte(AValue shr 48);
  AData[AOffset + 2] := Byte(AValue shr 40);
  AData[AOffset + 3] := Byte(AValue shr 32);
  AData[AOffset + 4] := Byte(AValue shr 24);
  AData[AOffset + 5] := Byte(AValue shr 16);
  AData[AOffset + 6] := Byte(AValue shr 8);
  AData[AOffset + 7] := Byte(AValue);
end;

class function TBinaryPrimitives.ReadUInt64LEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64;
begin
  Result := UInt64(AData[AOffset]) or
            (UInt64(AData[AOffset + 1]) shl 8) or
            (UInt64(AData[AOffset + 2]) shl 16) or
            (UInt64(AData[AOffset + 3]) shl 24) or
            (UInt64(AData[AOffset + 4]) shl 32) or
            (UInt64(AData[AOffset + 5]) shl 40) or
            (UInt64(AData[AOffset + 6]) shl 48) or
            (UInt64(AData[AOffset + 7]) shl 56);
end;

class function TBinaryPrimitives.ReadUInt64BEInternal(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64;
begin
  Result := (UInt64(AData[AOffset]) shl 56) or
            (UInt64(AData[AOffset + 1]) shl 48) or
            (UInt64(AData[AOffset + 2]) shl 40) or
            (UInt64(AData[AOffset + 3]) shl 32) or
            (UInt64(AData[AOffset + 4]) shl 24) or
            (UInt64(AData[AOffset + 5]) shl 16) or
            (UInt64(AData[AOffset + 6]) shl 8) or
            UInt64(AData[AOffset + 7]);
end;

// ============================================================================
// Public Write Methods - Little Endian
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt16);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  WriteUInt16LEInternal(AValue, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteUInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt32);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  WriteUInt32LEInternal(AValue, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteUInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt64);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  WriteUInt64LEInternal(AValue, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int16);
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  WriteUInt16LEInternal(UInt16(AValue), AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int32);
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  WriteUInt32LEInternal(UInt32(AValue), AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int64);
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  WriteUInt64LEInternal(UInt64(AValue), AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteSingleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Single);
var
  bits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  Move(AValue, bits, SizeOf(Single));
  WriteUInt32LEInternal(bits, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteDoubleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Double);
var
  bits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  Move(AValue, bits, SizeOf(Double));
  WriteUInt64LEInternal(bits, AData, AOffset);
end;

// ============================================================================
// Public Write Methods - Big Endian
// ============================================================================

class procedure TBinaryPrimitives.WriteUInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt16);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  WriteUInt16BEInternal(AValue, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteUInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt32);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  WriteUInt32BEInternal(AValue, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteUInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: UInt64);
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  WriteUInt64BEInternal(AValue, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int16);
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  WriteUInt16BEInternal(UInt16(AValue), AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int32);
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  WriteUInt32BEInternal(UInt32(AValue), AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Int64);
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  WriteUInt64BEInternal(UInt64(AValue), AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteSingleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Single);
var
  bits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  Move(AValue, bits, SizeOf(Single));
  WriteUInt32BEInternal(bits, AData, AOffset);
end;

class procedure TBinaryPrimitives.WriteDoubleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer; AValue: Double);
var
  bits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  Move(AValue, bits, SizeOf(Double));
  WriteUInt64BEInternal(bits, AData, AOffset);
end;

// ============================================================================
// Public Read Methods - Little Endian
// ============================================================================

class function TBinaryPrimitives.ReadUInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  Result := ReadUInt16LEInternal(AData, AOffset);
end;

class function TBinaryPrimitives.ReadUInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  Result := ReadUInt32LEInternal(AData, AOffset);
end;

class function TBinaryPrimitives.ReadUInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  Result := ReadUInt64LEInternal(AData, AOffset);
end;

class function TBinaryPrimitives.ReadInt16LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int16;
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  Result := Int16(ReadUInt16LEInternal(AData, AOffset));
end;

class function TBinaryPrimitives.ReadInt32LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int32;
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  Result := Int32(ReadUInt32LEInternal(AData, AOffset));
end;

class function TBinaryPrimitives.ReadInt64LittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int64;
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  Result := Int64(ReadUInt64LEInternal(AData, AOffset));
end;

class function TBinaryPrimitives.ReadSingleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Single;
var
  bits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  bits := ReadUInt32LEInternal(AData, AOffset);
  Move(bits, Result, SizeOf(Single));
end;

class function TBinaryPrimitives.ReadDoubleLittleEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Double;
var
  bits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  bits := ReadUInt64LEInternal(AData, AOffset);
  Move(bits, Result, SizeOf(Double));
end;

// ============================================================================
// Public Read Methods - Big Endian
// ============================================================================

class function TBinaryPrimitives.ReadUInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt16;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt16));
  Result := ReadUInt16BEInternal(AData, AOffset);
end;

class function TBinaryPrimitives.ReadUInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt32));
  Result := ReadUInt32BEInternal(AData, AOffset);
end;

class function TBinaryPrimitives.ReadUInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(UInt64));
  Result := ReadUInt64BEInternal(AData, AOffset);
end;

class function TBinaryPrimitives.ReadInt16BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int16;
begin
  CheckBounds(AData, AOffset, SizeOf(Int16));
  Result := Int16(ReadUInt16BEInternal(AData, AOffset));
end;

class function TBinaryPrimitives.ReadInt32BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int32;
begin
  CheckBounds(AData, AOffset, SizeOf(Int32));
  Result := Int32(ReadUInt32BEInternal(AData, AOffset));
end;

class function TBinaryPrimitives.ReadInt64BigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Int64;
begin
  CheckBounds(AData, AOffset, SizeOf(Int64));
  Result := Int64(ReadUInt64BEInternal(AData, AOffset));
end;

class function TBinaryPrimitives.ReadSingleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Single;
var
  bits: UInt32;
begin
  CheckBounds(AData, AOffset, SizeOf(Single));
  bits := ReadUInt32BEInternal(AData, AOffset);
  Move(bits, Result, SizeOf(Single));
end;

class function TBinaryPrimitives.ReadDoubleBigEndian(const AData: TCryptoLibByteArray; AOffset: Integer): Double;
var
  bits: UInt64;
begin
  CheckBounds(AData, AOffset, SizeOf(Double));
  bits := ReadUInt64BEInternal(AData, AOffset);
  Move(bits, Result, SizeOf(Double));
end;

end.

