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

unit ClpIPAddressUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpPlatform;

type
  /// <summary>
  /// IP Address utility class for validating IPv4 and IPv6 addresses.
  /// </summary>
  TIPAddressUtilities = class sealed(TObject)
  strict private
    class function IsParseableIPv4Octet(const AStr: String; APos, AEnd: Int32): Boolean; static;
    class function IsParseableIPv4Mask(const AStr: String): Boolean; static;
    class function IsParseableIPv6Segment(const AStr: String; APos, AEnd: Int32): Boolean; static;
    class function IsParseableIPv6Mask(const AStr: String): Boolean; static;
    class function IsParseableDecimal(const AStr: String; APos, AEnd, AMaxLength: Int32;
      AAllowLeadingZero: Boolean; AMinValue, AMaxValue: Int32): Boolean; static;
    class function IsParseableHexadecimal(const AStr: String; APos, AEnd, AMaxLength: Int32;
      AAllowLeadingZero: Boolean; AMinValue, AMaxValue: Int32): Boolean; static;
    class function GetDigitDecimal(const AStr: String; APos: Int32): Int32; static;
    class function GetDigitHexadecimal(const AStr: String; APos: Int32): Int32; static;

  public
    /// <summary>
    /// Validate the given IPv4 or IPv6 address.
    /// </summary>
    class function IsValid(const AAddress: String): Boolean; static;
    /// <summary>
    /// Validate the given IPv4 or IPv6 address and netmask.
    /// </summary>
    class function IsValidWithNetMask(const AAddress: String): Boolean; static;
    /// <summary>
    /// Validate the given IPv4 address.
    /// </summary>
    class function IsValidIPv4(const AAddress: String): Boolean; static;
    /// <summary>
    /// Validate the given IPv4 address with netmask.
    /// </summary>
    class function IsValidIPv4WithNetmask(const AAddress: String): Boolean; static;
    /// <summary>
    /// Validate the given IPv6 address.
    /// </summary>
    class function IsValidIPv6(const AAddress: String): Boolean; static;
    /// <summary>
    /// Validate the given IPv6 address with netmask.
    /// </summary>
    class function IsValidIPv6WithNetmask(const AAddress: String): Boolean; static;
  end;

implementation

{ TIPAddressUtilities }

class function TIPAddressUtilities.IsValid(const AAddress: String): Boolean;
begin
  Result := IsValidIPv4(AAddress) or IsValidIPv6(AAddress);
end;

class function TIPAddressUtilities.IsValidWithNetMask(const AAddress: String): Boolean;
begin
  Result := IsValidIPv4WithNetmask(AAddress) or IsValidIPv6WithNetmask(AAddress);
end;

class function TIPAddressUtilities.IsValidIPv4(const AAddress: String): Boolean;
var
  LLength, LPos, LEnd, LOctetIndex: Int32;
begin
  LLength := System.Length(AAddress);
  if (LLength < 7) or (LLength > 15) then
  begin
    Result := False;
    Exit;
  end;

  LPos := 1; // 1-based position
  for LOctetIndex := 0 to 2 do
  begin
    // TPlatform.IndexOf returns 1-based index (0 if not found)
    LEnd := TPlatform.IndexOf(AAddress, '.', LPos);
    if LEnd = 0 then
    begin
      Result := False;
      Exit;
    end;

    // IsParseableIPv4Octet expects 1-based positions
    if not IsParseableIPv4Octet(AAddress, LPos, LEnd) then
    begin
      Result := False;
      Exit;
    end;

    LPos := LEnd + 1; // Skip the '.' character
  end;

  // Check last octet
  Result := IsParseableIPv4Octet(AAddress, LPos, LLength + 1);
end;

class function TIPAddressUtilities.IsValidIPv4WithNetmask(const AAddress: String): Boolean;
var
  LIndex: Int32;
  LBefore, LAfter: String;
begin
  LIndex := TPlatform.IndexOf(AAddress, '/');
  if LIndex = 0 then
  begin
    Result := False;
    Exit;
  end;

  // LIndex is 1-based position of '/'
  LBefore := System.Copy(AAddress, 1, LIndex - 1);
  LAfter := System.Copy(AAddress, LIndex + 1, System.Length(AAddress) - LIndex);

  Result := IsValidIPv4(LBefore) and (IsValidIPv4(LAfter) or IsParseableIPv4Mask(LAfter));
end;

class function TIPAddressUtilities.IsValidIPv6(const AAddress: String): Boolean;
var
  LLength, LPos, LEnd, LSegmentCount: Int32;
  LTemp, LValue: String;
  LDoubleColonFound: Boolean;
begin
  LLength := System.Length(AAddress);
  if LLength = 0 then
  begin
    Result := False;
    Exit;
  end;

  // Check first character
  if (AAddress[1] <> ':') and (GetDigitHexadecimal(AAddress, 1) < 0) then
  begin
    Result := False;
    Exit;
  end;

  LSegmentCount := 0;
  LTemp := AAddress + ':';
  LDoubleColonFound := False;

  LPos := 1; // 1-based position
  while LPos <= System.Length(LTemp) do
  begin
    LEnd := TPlatform.IndexOf(LTemp, ':', LPos);
    if LEnd = 0 then
      Break;

    if LSegmentCount = 8 then
    begin
      Result := False;
      Exit;
    end;

    if LPos <> LEnd then
    begin
      // Extract segment (1-based positions)
      LValue := System.Copy(LTemp, LPos, LEnd - LPos);

      // Check if this is the last segment and contains IPv4 notation
      if (LEnd = System.Length(LTemp)) and (TPlatform.IndexOf(LValue, '.') > 0) then
      begin
        // Add an extra one as address covers 2 words
        System.Inc(LSegmentCount);
        if LSegmentCount = 8 then
        begin
          Result := False;
          Exit;
        end;

        if not IsValidIPv4(LValue) then
        begin
          Result := False;
          Exit;
        end;
      end
      else if not IsParseableIPv6Segment(LTemp, LPos, LEnd) then
      begin
        Result := False;
        Exit;
      end;
    end
    else
    begin
      // Empty segment (double colon)
      if (LEnd <> 2) and (LEnd <> System.Length(LTemp)) and LDoubleColonFound then
      begin
        Result := False;
        Exit;
      end;

      LDoubleColonFound := True;
    end;

    LPos := LEnd + 1; // Skip the ':' character
    System.Inc(LSegmentCount);
  end;

  Result := (LSegmentCount = 8) or LDoubleColonFound;
end;

class function TIPAddressUtilities.IsValidIPv6WithNetmask(const AAddress: String): Boolean;
var
  LIndex: Int32;
  LBefore, LAfter: String;
begin
  LIndex := TPlatform.IndexOf(AAddress, '/');
  if LIndex = 0 then
  begin
    Result := False;
    Exit;
  end;

  // LIndex is 1-based position of '/'
  LBefore := System.Copy(AAddress, 1, LIndex - 1);
  LAfter := System.Copy(AAddress, LIndex + 1, System.Length(AAddress) - LIndex);

  Result := IsValidIPv6(LBefore) and (IsValidIPv6(LAfter) or IsParseableIPv6Mask(LAfter));
end;

class function TIPAddressUtilities.IsParseableIPv4Mask(const AStr: String): Boolean;
begin
  Result := IsParseableDecimal(AStr, 1, System.Length(AStr) + 1, 2, False, 0, 32);
end;

class function TIPAddressUtilities.IsParseableIPv4Octet(const AStr: String; APos, AEnd: Int32): Boolean;
begin
  // APos and AEnd are 1-based
  Result := IsParseableDecimal(AStr, APos, AEnd, 3, True, 0, 255);
end;

class function TIPAddressUtilities.IsParseableIPv6Mask(const AStr: String): Boolean;
begin
  Result := IsParseableDecimal(AStr, 1, System.Length(AStr) + 1, 3, False, 1, 128);
end;

class function TIPAddressUtilities.IsParseableIPv6Segment(const AStr: String; APos, AEnd: Int32): Boolean;
begin
  // APos and AEnd are 1-based
  Result := IsParseableHexadecimal(AStr, APos, AEnd, 4, True, $0000, $FFFF);
end;

class function TIPAddressUtilities.IsParseableDecimal(const AStr: String; APos, AEnd, AMaxLength: Int32;
  AAllowLeadingZero: Boolean; AMinValue, AMaxValue: Int32): Boolean;
var
  LLength, LValue: Int32;
  LD: Int32;
begin
  // APos and AEnd are 1-based
  LLength := AEnd - APos;
  if (LLength < 1) or (LLength > AMaxLength) then
  begin
    Result := False;
    Exit;
  end;

  // Check for leading zero
  if (LLength > 1) and (not AAllowLeadingZero) and (AStr[APos] = '0') then
  begin
    Result := False;
    Exit;
  end;

  LValue := 0;
  while APos < AEnd do
  begin
    LD := GetDigitDecimal(AStr, APos);
    if LD < 0 then
    begin
      Result := False;
      Exit;
    end;

    LValue := LValue * 10;
    LValue := LValue + LD;
    System.Inc(APos);
  end;

  Result := (LValue >= AMinValue) and (LValue <= AMaxValue);
end;

class function TIPAddressUtilities.IsParseableHexadecimal(const AStr: String; APos, AEnd, AMaxLength: Int32;
  AAllowLeadingZero: Boolean; AMinValue, AMaxValue: Int32): Boolean;
var
  LLength, LValue: Int32;
  LD: Int32;
begin
  // APos and AEnd are 1-based
  LLength := AEnd - APos;
  if (LLength < 1) or (LLength > AMaxLength) then
  begin
    Result := False;
    Exit;
  end;

  // Check for leading zero
  if (LLength > 1) and (not AAllowLeadingZero) and (AStr[APos] = '0') then
  begin
    Result := False;
    Exit;
  end;

  LValue := 0;
  while APos < AEnd do
  begin
    LD := GetDigitHexadecimal(AStr, APos);
    if LD < 0 then
    begin
      Result := False;
      Exit;
    end;

    LValue := LValue * 16;
    LValue := LValue + LD;
    System.Inc(APos);
  end;

  Result := (LValue >= AMinValue) and (LValue <= AMaxValue);
end;

class function TIPAddressUtilities.GetDigitDecimal(const AStr: String; APos: Int32): Int32;
var
  LC: Char;
  LD: UInt32;
begin
  // APos is 1-based
  LC := AStr[APos];
  LD := UInt32(Ord(LC) - Ord('0'));
  if LD <= 9 then
    Result := Int32(LD)
  else
    Result := -1;
end;

class function TIPAddressUtilities.GetDigitHexadecimal(const AStr: String; APos: Int32): Int32;
var
  LC: Char;
  LD: UInt32;
begin
  // APos is 1-based
  LC := AStr[APos];
  // Convert to lowercase for comparison
  LD := UInt32(Ord(LC)) or $20;
  if LD >= UInt32(Ord('a')) then
    LD := LD - (UInt32(Ord('a')) - 10)
  else
    LD := LD - UInt32(Ord('0'));
  
  if LD <= 16 then
    Result := Int32(LD)
  else
    Result := -1;
end;

end.
