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

unit ClpBitOperations;

{$I ..\Include\CryptoLib.inc}

interface

type
  TBitOperations = class sealed(TObject)

  public

    class function ReverseBytesInt32(AValue: Int32): Int32; static; inline;
    class function ReverseBitsUInt8(AValue: UInt8): UInt8; static; inline;
    class function ReverseBytesUInt16(AValue: UInt16): UInt16; static; inline;
    class function ReverseBytesUInt32(AValue: UInt32): UInt32; static; inline;
    class function ReverseBytesUInt64(AValue: UInt64): UInt64; static; inline;

    /// <summary>
    /// Calculates Arithmetic shift right.
    /// </summary>
    /// <param name="AValue">Int32 value to compute 'Asr' on.</param>
    /// <param name="AShiftBits">Byte, number of bits to shift value to.</param>
    /// <returns>Shifted value.</returns>
    /// <remarks>
    /// Emulated Implementation was gotten from FreePascal sources
    /// </remarks>

    class function Asr32(AValue: Int32; AShiftBits: Byte): Int32; static; inline;

    /// <summary>
    /// Calculates Arithmetic shift right.
    /// </summary>
    /// <param name="AValue">Int64 value to compute 'Asr' on.</param>
    /// <param name="AShiftBits">Byte, number of bits to shift value to.</param>
    /// <returns>Shifted value.</returns>
    /// <remarks>
    /// Emulated Implementation was gotten from FreePascal sources
    /// </remarks>

    class function Asr64(AValue: Int64; AShiftBits: Byte): Int64; static; inline;

    /// <summary>
    /// Calculates Negative Left Shift. This was implemented to circumvent a
    /// bug in FPC ARM when performing Shift Left on certain values with a
    /// Negative Shift Bits. For example UInt32(1948415963) shl Int32(-2)
    /// should give "3221225472" but in FPC ARM, It gives "0". In some C
    /// Compilers, this is "Undefined"
    /// </summary>
    /// <param name="AValue">
    /// Value to Perform Shift On
    /// </param>
    /// <param name="AShiftBits">
    /// Integer, number of bits to shift value to. This Number <b>Must be
    /// Negative</b>
    /// </param>
    /// <returns>
    /// Shifted value.
    /// </returns>

    class function NegativeLeftShift32(AValue: UInt32; AShiftBits: Int32): UInt32; static; inline;

    /// <summary>
    /// Calculates Negative Left Shift for 64-bit (same semantics as NegativeLeftShift32).
    /// </summary>
    class function NegativeLeftShift64(AValue: UInt64; AShiftBits: Int32): UInt64; static; inline;

    /// <summary>
    /// Calculates Negative Right Shift. This was implemented to circumvent a
    /// compiler issue when performing Shift Right on certain values with a
    /// Negative Shift Bits. In some C Compilers, this is "Undefined"
    /// </summary>
    /// <param name="AValue">
    /// Value to Perform Shift On
    /// </param>
    /// <param name="AShiftBits">
    /// Integer, number of bits to shift value to. This Number <b>Must be
    /// Negative</b>
    /// </param>
    /// <returns>
    /// Shifted value.
    /// </returns>

    class function NegativeRightShift32(AValue: UInt32; AShiftBits: Int32): UInt32; static; inline;

    /// <summary>
    /// Calculates Negative Right Shift. This was implemented to circumvent a
    /// compiler issue when performing Shift Right on certain values with a
    /// Negative Shift Bits. In some C Compilers, this is "Undefined"
    /// </summary>
    /// <param name="AValue">
    /// Value to Perform Shift On
    /// </param>
    /// <param name="AShiftBits">
    /// Integer, number of bits to shift value to. This Number <b>Must be
    /// Negative</b>
    /// </param>
    /// <returns>
    /// Shifted value.
    /// </returns>

    class function NegativeRightShift64(AValue: UInt64; AShiftBits: Int32): UInt64; static; inline;

    class function RotateLeft8(AValue: Byte; AN: Int32): Byte; static; inline;
    class function RotateLeft32(AValue: UInt32; AN: Int32): UInt32; static; inline;
    class function RotateLeft64(AValue: UInt64; AN: Int32): UInt64; static; inline;
    class function RotateRight8(AValue: Byte; AN: Int32): Byte; static; inline;
    class function RotateRight32(AValue: UInt32; AN: Int32): UInt32; static; inline;
    class function RotateRight64(AValue: UInt64; AN: Int32): UInt64; static; inline;

    class function NumberOfLeadingZeros32(AValue: UInt32): Int32; static;
    class function NumberOfLeadingZeros64(AValue: UInt64): Int32; static;

    class function NumberOfTrailingZeros32(AValue: UInt32): Int32; static;
    class function NumberOfTrailingZeros64(AValue: UInt64): Int32; static;

    class function PopCount32(AValue: UInt32): Int32; static;
    class function PopCount64(AValue: UInt64): Int32; static;
  end;

implementation

{ TBitUtilities }

class function TBitOperations.ReverseBytesInt32(AValue: Int32): Int32;
{$IFNDEF FPC}
var
  LI1, LI2, LI3, LI4: Int32;
{$ENDIF FPC}
begin
{$IFDEF FPC}
  Result := SwapEndian(AValue);
{$ELSE}
  LI1 := AValue and $FF;
  LI2 := TBitOperations.Asr32(AValue, 8) and $FF;
  LI3 := TBitOperations.Asr32(AValue, 16) and $FF;
  LI4 := TBitOperations.Asr32(AValue, 24) and $FF;

  Result := (LI1 shl 24) or (LI2 shl 16) or (LI3 shl 8) or (LI4 shl 0);
{$ENDIF FPC}
end;

class function TBitOperations.ReverseBitsUInt8(AValue: UInt8): UInt8;
begin
  AValue := ((AValue shr 1) and $55) or ((AValue shl 1) and $AA);
  AValue := ((AValue shr 2) and $33) or ((AValue shl 2) and $CC);
  AValue := ((AValue shr 4) and $0F) or ((AValue shl 4) and $F0);
  Result := AValue;
end;

class function TBitOperations.ReverseBytesUInt16(AValue: UInt16): UInt16;
begin
{$IFDEF FPC}
  Result := SwapEndian(AValue);
{$ELSE}
  Result := UInt16((AValue and UInt32($FF)) shl 8 or
    (AValue and UInt32($FF00)) shr 8);
{$ENDIF FPC}
end;

class function TBitOperations.ReverseBytesUInt32(AValue: UInt32): UInt32;
begin
{$IFDEF FPC}
  Result := SwapEndian(AValue);
{$ELSE}
  Result := (AValue and UInt32($000000FF)) shl 24 or (AValue and UInt32($0000FF00)
    ) shl 8 or (AValue and UInt32($00FF0000)) shr 8 or
    (AValue and UInt32($FF000000)) shr 24;
{$ENDIF FPC}
end;

class function TBitOperations.ReverseBytesUInt64(AValue: UInt64): UInt64;
begin
{$IFDEF FPC}
  Result := SwapEndian(AValue);
{$ELSE}
  Result := (AValue and UInt64($00000000000000FF)) shl 56 or
    (AValue and UInt64($000000000000FF00)) shl 40 or
    (AValue and UInt64($0000000000FF0000)) shl 24 or
    (AValue and UInt64($00000000FF000000)) shl 8 or
    (AValue and UInt64($000000FF00000000)) shr 8 or
    (AValue and UInt64($0000FF0000000000)) shr 24 or
    (AValue and UInt64($00FF000000000000)) shr 40 or
    (AValue and UInt64($FF00000000000000)) shr 56;
{$ENDIF FPC}
end;

class function TBitOperations.Asr32(AValue: Int32; AShiftBits: Byte): Int32;
begin
{$IFDEF FPC}
  Result := SarLongInt(AValue, AShiftBits);
{$ELSE}
  Result := Int32(UInt32(UInt32(UInt32(AValue) shr (AShiftBits and 31)) or
    (UInt32(Int32(UInt32(0 - UInt32(UInt32(AValue) shr 31)) and
    UInt32(Int32(0 - (Ord((AShiftBits and 31) <> 0) { and 1 } )))))
    shl (32 - (AShiftBits and 31)))));
{$ENDIF FPC}
end;

class function TBitOperations.Asr64(AValue: Int64; AShiftBits: Byte): Int64;
begin
{$IFDEF FPC}
  Result := SarInt64(AValue, AShiftBits);
{$ELSE}
  Result := Int64(UInt64(UInt64(UInt64(AValue) shr (AShiftBits and 63)) or
    (UInt64(Int64(UInt64(0 - UInt64(UInt64(AValue) shr 63)) and
    UInt64(Int64(0 - (Ord((AShiftBits and 63) <> 0) { and 1 } )))))
    shl (64 - (AShiftBits and 63)))));
{$ENDIF FPC}
end;

class function TBitOperations.NegativeLeftShift32(AValue: UInt32; AShiftBits: Int32): UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(AShiftBits < 0);
{$ENDIF DEBUG}
  Result := AValue shl (32 + AShiftBits);
end;

class function TBitOperations.NegativeRightShift32(AValue: UInt32; AShiftBits: Int32): UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(AShiftBits < 0);
{$ENDIF DEBUG}
  Result := AValue shr (32 + AShiftBits);
end;

class function TBitOperations.NegativeLeftShift64(AValue: UInt64; AShiftBits: Int32): UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(AShiftBits < 0);
{$ENDIF DEBUG}
  Result := AValue shl (64 + AShiftBits);
end;

class function TBitOperations.NegativeRightShift64(AValue: UInt64; AShiftBits: Int32): UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(AShiftBits < 0);
{$ENDIF DEBUG}
  Result := AValue shr (64 + AShiftBits);
end;

class function TBitOperations.RotateLeft8(AValue: Byte; AN: Int32): Byte;
begin
{$IFDEF DEBUG}
  System.Assert(AN >= 0);
{$ENDIF DEBUG}
{$IFDEF FPC}
  Result := RolByte(AValue, AN);
{$ELSE}
{$IFNDEF SHIFT_OVERFLOW_BUG_FIXED}
  AN := AN and 7;
{$ENDIF SHIFT_OVERFLOW_BUG_FIXED}
  Result := (AValue shl AN) or (AValue shr (8 - AN));
{$ENDIF FPC}
end;

class function TBitOperations.RotateLeft32(AValue: UInt32; AN: Int32): UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(AN >= 0);
{$ENDIF DEBUG}
{$IFDEF FPC}
  Result := RolDWord(AValue, AN);
{$ELSE}
{$IFNDEF SHIFT_OVERFLOW_BUG_FIXED}
  AN := AN and 31;
{$ENDIF SHIFT_OVERFLOW_BUG_FIXED}
  Result := (AValue shl AN) or (AValue shr (32 - AN));
{$ENDIF FPC}
end;

class function TBitOperations.RotateLeft64(AValue: UInt64; AN: Int32): UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(AN >= 0);
{$ENDIF DEBUG}
{$IFDEF FPC}
  Result := RolQWord(AValue, AN);
{$ELSE}
{$IFNDEF SHIFT_OVERFLOW_BUG_FIXED}
  AN := AN and 63;
{$ENDIF SHIFT_OVERFLOW_BUG_FIXED}
  Result := (AValue shl AN) or (AValue shr (64 - AN));
{$ENDIF FPC}
end;

class function TBitOperations.RotateRight8(AValue: Byte; AN: Int32): Byte;
begin
{$IFDEF DEBUG}
  System.Assert(AN >= 0);
{$ENDIF DEBUG}
{$IFDEF FPC}
  Result := RorByte(AValue, AN);
{$ELSE}
{$IFNDEF SHIFT_OVERFLOW_BUG_FIXED}
  AN := AN and 7;
{$ENDIF SHIFT_OVERFLOW_BUG_FIXED}
  Result := (AValue shr AN) or (AValue shl (8 - AN));
{$ENDIF FPC}
end;

class function TBitOperations.RotateRight32(AValue: UInt32; AN: Int32): UInt32;
begin
{$IFDEF DEBUG}
  System.Assert(AN >= 0);
{$ENDIF DEBUG}
{$IFDEF FPC}
  Result := RorDWord(AValue, AN);
{$ELSE}
{$IFNDEF SHIFT_OVERFLOW_BUG_FIXED}
  AN := AN and 31;
{$ENDIF SHIFT_OVERFLOW_BUG_FIXED}
  Result := (AValue shr AN) or (AValue shl (32 - AN));
{$ENDIF FPC}
end;

class function TBitOperations.RotateRight64(AValue: UInt64; AN: Int32): UInt64;
begin
{$IFDEF DEBUG}
  System.Assert(AN >= 0);
{$ENDIF DEBUG}
{$IFDEF FPC}
  Result := RorQWord(AValue, AN);
{$ELSE}
{$IFNDEF SHIFT_OVERFLOW_BUG_FIXED}
  AN := AN and 63;
{$ENDIF SHIFT_OVERFLOW_BUG_FIXED}
  Result := (AValue shr AN) or (AValue shl (64 - AN));
{$ENDIF FPC}
end;

class function TBitOperations.NumberOfLeadingZeros32(AValue: UInt32): Int32;
{$IFNDEF FPC}
var
  LN: UInt32;
{$ENDIF FPC}
begin
  if (AValue = 0) then
  begin
    Result := ((not AValue) shr (31 - 5)) and (1 shl 5);
    Exit;
  end;
{$IFDEF FPC}
  Result := BsrDWord(AValue) xor ((System.SizeOf(UInt32) * 8) - 1);
  // this also works
  // Result := ((System.SizeOf(UInt32) * 8) - 1) - BsrDWord(AValue);
{$ELSE}
  LN := 1;

  if ((AValue shr 16) = 0) then
  begin
    LN := LN + 16;
    AValue := AValue shl 16;
  end;

  if ((AValue shr 24) = 0) then
  begin
    LN := LN + 8;
    AValue := AValue shl 8;
  end;

  if ((AValue shr 28) = 0) then
  begin
    LN := LN + 4;
    AValue := AValue shl 4;
  end;

  if ((AValue shr 30) = 0) then
  begin
    LN := LN + 2;
    AValue := AValue shl 2;
  end;

  Result := Int32(LN) - Int32(AValue shr 31);
{$ENDIF FPC}
end;

class function TBitOperations.NumberOfLeadingZeros64(AValue: UInt64): Int32;
{$IFNDEF FPC}
var
  LX: UInt32;
  LN: Int32;
{$ENDIF FPC}
begin
  if (AValue = 0) then
  begin
    Result := Int32(((not AValue) shr (63 - 6)) and (UInt64(1) shl 6));
    Exit;
  end;

{$IFDEF FPC}
  Result := Int32(BsrQWord(AValue) xor ((System.SizeOf(UInt64) * 8) - 1));
  // also works:
  // Result := Int32(((System.SizeOf(UInt64) * 8) - 1) - BsrQWord(AValue));
{$ELSE}
  LX := UInt32(AValue shr 32);
  LN := 0;
  if (LX = 0) then
  begin
    LN := 32;
    LX := UInt32(AValue);
  end;
  Result := LN + NumberOfLeadingZeros32(LX);
{$ENDIF FPC}
end;

class function TBitOperations.NumberOfTrailingZeros32(AValue: UInt32): Int32;
{$IFNDEF FPC}
var
  LN: UInt32;
{$ENDIF FPC}
begin
  if (AValue = 0) then
  begin
    Result := ((not AValue) shr (31 - 5)) and (1 shl 5);
    Exit;
  end;
{$IFDEF FPC}
  Result := BsfDWord(AValue);
{$ELSE}
  LN := 0;

  if ((AValue and $0000FFFF) = 0) then
  begin
    LN := LN + 16;
    AValue := AValue shr 16;
  end;

  if ((AValue and $000000FF) = 0) then
  begin
    LN := LN + 8;
    AValue := AValue shr 8;
  end;

  if ((AValue and $0000000F) = 0) then
  begin
    LN := LN + 4;
    AValue := AValue shr 4;
  end;

  if ((AValue and $00000003) = 0) then
  begin
    LN := LN + 2;
    AValue := AValue shr 2;
  end;

  Result := Int32(LN + (AValue and 1) xor 1);
{$ENDIF FPC}
end;

class function TBitOperations.NumberOfTrailingZeros64(AValue: UInt64): Int32;
{$IFNDEF FPC}
var
  LN: UInt32;
{$ENDIF FPC}
begin
  if (AValue = 0) then
  begin
    Result := Int32(((not AValue) shr (63 - 6)) and (UInt64(1) shl 6));
    Exit;
  end;

{$IFDEF FPC}
  Result := BsfQWord(AValue);
{$ELSE}
  LN := 0;

  if ((AValue and UInt64($00000000FFFFFFFF)) = 0) then
  begin
    LN := LN + 32;
    AValue := AValue shr 32;
  end;

  if ((AValue and UInt64($000000000000FFFF)) = 0) then
  begin
    LN := LN + 16;
    AValue := AValue shr 16;
  end;

  if ((AValue and UInt64($00000000000000FF)) = 0) then
  begin
    LN := LN + 8;
    AValue := AValue shr 8;
  end;

  if ((AValue and UInt64($000000000000000F)) = 0) then
  begin
    LN := LN + 4;
    AValue := AValue shr 4;
  end;

  if ((AValue and UInt64($0000000000000003)) = 0) then
  begin
    LN := LN + 2;
    AValue := AValue shr 2;
  end;

  Result := Int32(LN + (UInt32(AValue) and 1) xor 1);
{$ENDIF FPC}
end;

class function TBitOperations.PopCount32(AValue: UInt32): Int32;
begin
{$IFDEF FPC}
  Result := PopCnt(AValue);
{$ELSE}
  AValue := AValue - ((AValue shr 1) and UInt32($55555555));
  AValue := (AValue and UInt32($33333333)) + ((AValue shr 2) and UInt32($33333333));
  AValue := (AValue + (AValue shr 4)) and UInt32($0F0F0F0F);
  AValue := AValue + (AValue shr 8);
  AValue := AValue + (AValue shr 16);
  AValue := AValue and UInt32($3F);
  Result := Int32(AValue);
{$ENDIF FPC}
end;

class function TBitOperations.PopCount64(AValue: UInt64): Int32;
begin
{$IFDEF FPC}
  Result := PopCnt(AValue);
{$ELSE}
  AValue := AValue - ((AValue shr 1) and UInt64($5555555555555555));
  AValue := (AValue and UInt64($3333333333333333)) + ((AValue shr 2) and UInt64($3333333333333333));
  AValue := (AValue + (AValue shr 4)) and UInt64($0F0F0F0F0F0F0F0F);
  AValue := AValue + (AValue shr 8);
  AValue := AValue + (AValue shr 16);
  AValue := AValue + (AValue shr 32);
  AValue := AValue and UInt64($7F);
  Result := Int32(AValue);
{$ENDIF FPC}
end;

end.
