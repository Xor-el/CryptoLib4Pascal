{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpIetfUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  ClpConverters,
  ClpStreamUtilities,
  ClpStringUtilities,
  ClpEncoders;

resourcestring
  SInvalidHexEscapeInDirectoryString = 'invalid hex escape in directory string';
  SOtherValueHasNoEncodedForm = 'other value has no encoded form';
  SUnknownEncodingInName = 'unknown encoding in name: %s';

type
  /// <summary>
  /// IETF utilities for X.500 name handling.
  /// </summary>
  TIetfUtilities = class sealed(TObject)
  strict private
    class function IsHexDigit(AC: Char): Boolean; static;
    /// <summary>
    /// Convert a hexadecimal character to its integer value.
    /// </summary>
    class function ConvertHex(AC: Char): Int32; static;
    class function DecodeObject(const AOValue: String): IAsn1Object; static;
    class procedure FlushHexBytes(ABuf: TStringBuilder; AHexBytes: TMemoryStream;
      var ALastEscaped: Int32); static;
    class procedure CheckCompleteHexPair(AHex1: Int32); static;
    class procedure AppendValue(ABuf: TStringBuilder; const AAttrValue: String); static;

  public
    /// <summary>
    /// Unescape a string value, handling quotes, escapes, and hex encoding.
    /// </summary>
    class function Unescape(const AElt: String): String; static;
    /// <summary>
    /// Convert an ASN.1 encodable value to a string representation.
    /// </summary>
    class function ValueToString(const AValue: IAsn1Encodable): String; static;
    /// <summary>
    /// Canonicalize a string value.
    /// </summary>
    class function Canonicalize(const AStr: String): String; static;
    /// <summary>
    /// Get canonical string representation of an ASN.1 encodable value.
    /// </summary>
    class function CanonicalString(const AValue: IAsn1Encodable): String; static;
    /// <summary>
    /// Strip internal spaces from a string (collapse multiple spaces to single).
    /// </summary>
    class function StripInternalSpaces(const AStr: String): String; static;
  end;

implementation

{ TIetfUtilities }

class procedure TIetfUtilities.FlushHexBytes(ABuf: TStringBuilder;
  AHexBytes: TMemoryStream; var ALastEscaped: Int32);
var
  LHexSlice: TCryptoLibByteArray;
  LLength: Int32;
begin
  LLength := AHexBytes.Position;
  if LLength > 0 then
  begin
    SetLength(LHexSlice, LLength);
    AHexBytes.Position := 0;
    AHexBytes.Read(LHexSlice[0], LLength);
    AHexBytes.Position := 0;
    ABuf.Append(TConverters.ConvertBytesToString(LHexSlice, TEncoding.UTF8));
    ALastEscaped := ABuf.Length - 1;
  end;
end;

class procedure TIetfUtilities.CheckCompleteHexPair(AHex1: Int32);
begin
  if AHex1 >= 0 then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidHexEscapeInDirectoryString);
end;

class function TIetfUtilities.IsHexDigit(AC: Char): Boolean;
begin
  Result := (('0' <= AC) and (AC <= '9')) or (('a' <= AC) and (AC <= 'f')) or (('A' <= AC) and (AC <= 'F'));
end;

class function TIetfUtilities.ConvertHex(AC: Char): Int32;
begin
  if ('0' <= AC) and (AC <= '9') then
    Result := Ord(AC) - Ord('0')
  else if ('a' <= AC) and (AC <= 'f') then
    Result := Ord(AC) - Ord('a') + 10
  else
    Result := Ord(AC) - Ord('A') + 10;
end;

class function TIetfUtilities.DecodeObject(const AOValue: String): IAsn1Object;
var
  LHexStr: String;
  LBytes: TCryptoLibByteArray;
begin
  try
    LHexStr := System.Copy(AOValue, 2, System.Length(AOValue) - 1);

    LBytes := THexEncoder.Decode(LHexStr);
    Result := TAsn1Object.FromByteArray(LBytes);
  except
    on E: Exception do
      raise EInvalidOperationCryptoLibException.CreateResFmt(@SUnknownEncodingInName, [E.Message]);
  end;
end;

class function TIetfUtilities.Unescape(const AElt: String): String;
var
  LSb: TStringBuilder;
  LHexBytes: TMemoryStream;
  LStart, LI, LLastEscaped, LHex1, LHexDigit: Int32;
  LEscaped, LQuoted, LNonWhiteSpaceEncountered: Boolean;
  LC: Char;
begin
  if System.Length(AElt) < 1 then
  begin
    Result := AElt;
    Exit;
  end;

  if (TStringUtilities.IndexOf(AElt, '\') = 0) and (TStringUtilities.IndexOf(AElt, '"') = 0) then
  begin
    Result := TStringUtilities.Trim(AElt);
    Exit;
  end;

  LEscaped := False;
  LQuoted := False;
  LSb := TStringBuilder.Create(System.Length(AElt));
  LHexBytes := TMemoryStream.Create;
  try
    LStart := 1;
    if (System.Length(AElt) > 0) and (AElt[1] = '\') then
    begin
      if (System.Length(AElt) > 1) and (AElt[2] = '#') then
      begin
        LStart := 3;
        LSb.Append('\#');
      end;
    end;

    LNonWhiteSpaceEncountered := False;
    LLastEscaped := -1;
    LHex1 := -1;

    for LI := LStart to System.Length(AElt) do
    begin
      LC := AElt[LI];

      if LC <> ' ' then
        LNonWhiteSpaceEncountered := True;

      if LC = '"' then
      begin
        if not LEscaped then
          LQuoted := not LQuoted
        else
        begin
          CheckCompleteHexPair(LHex1);
          FlushHexBytes(LSb, LHexBytes, LLastEscaped);
          LSb.Append(LC);
          LEscaped := False;
        end;
      end
      else if (LC = '\') and (not LEscaped) and (not LQuoted) then
      begin
        LEscaped := True;
        LLastEscaped := LSb.Length;
      end
      else if (LC = ' ') and (not LEscaped) and (not LNonWhiteSpaceEncountered) then
      begin
        Continue;
      end
      else if LEscaped and IsHexDigit(LC) then
      begin
        LHexDigit := ConvertHex(LC);
        if LHex1 < 0 then
          LHex1 := LHexDigit
        else
        begin
          LHexBytes.WriteByte(Byte(LHex1 * 16 + LHexDigit));
          LEscaped := False;
          LHex1 := -1;
        end;
      end
      else
      begin
        // A '\' followed by a single hex digit and then a non-hex char is an
        // incomplete hexpair (RFC 4514 sec. 2.4 requires two), not a literal.
        CheckCompleteHexPair(LHex1);
        FlushHexBytes(LSb, LHexBytes, LLastEscaped);
        LSb.Append(LC);
        LEscaped := False;
      end;
    end;

    // A '\' followed by a single hex digit at end of input is likewise incomplete.
    CheckCompleteHexPair(LHex1);
    FlushHexBytes(LSb, LHexBytes, LLastEscaped);

    if LSb.Length > 0 then
    begin
      while (LSb.Length > 0) and (LSb.Chars[LSb.Length - 1] = ' ') and
        (LLastEscaped < LSb.Length - 1) do
      begin
        LSb.Length := LSb.Length - 1;
      end;
      Result := LSb.ToString();
    end
    else
      Result := '';
  finally
    LHexBytes.Free;
    LSb.Free;
  end;
end;

class procedure TIetfUtilities.AppendValue(ABuf: TStringBuilder; const AAttrValue: String);
var
  LLen, LFirstNonSpace, LLastNonSpace, LIndex: Int32;
  LHashPrefix, LEscape: Boolean;
  LC: Char;
begin
  LLen := System.Length(AAttrValue);

  LHashPrefix := (LLen >= 2) and (AAttrValue[1] = '\') and (AAttrValue[2] = '#');

  LFirstNonSpace := 1;
  while (LFirstNonSpace <= LLen) and (AAttrValue[LFirstNonSpace] = ' ') do
    System.Inc(LFirstNonSpace);

  if LFirstNonSpace <= LLen then
  begin
    LLastNonSpace := LLen;
    while AAttrValue[LLastNonSpace] = ' ' do
      System.Dec(LLastNonSpace);
  end
  else
    LLastNonSpace := 0;

  LIndex := 1;
  if LHashPrefix then
  begin
    ABuf.Append('\#');
    LIndex := 3;
  end;

  while LIndex <= LLen do
  begin
    LC := AAttrValue[LIndex];
    case LC of
      ',', '"', '\', '+', '=', '<', '>', ';':
        LEscape := True;
      ' ':
        LEscape := (not LHashPrefix) and (LIndex < LFirstNonSpace) or (LIndex > LLastNonSpace);
    else
      LEscape := False;
    end;

    if LEscape then
      ABuf.Append('\');
    ABuf.Append(LC);
    System.Inc(LIndex);
  end;
end;

class function TIetfUtilities.ValueToString(const AValue: IAsn1Encodable): String;
var
  LVBuf, LResultBuf: TStringBuilder;
  LV: String;
  LStr: IAsn1String;
begin
  LVBuf := TStringBuilder.Create();
  LResultBuf := TStringBuilder.Create(64);
  try
    if Supports(AValue, IAsn1String, LStr) and (not Supports(AValue, IDerUniversalString)) then
    begin
      LV := LStr.GetString();
      if (System.Length(LV) > 0) and (LV[1] = '#') then
        LVBuf.Append('\');
      LVBuf.Append(LV);
    end
    else
    begin
      try
        LVBuf.Append('#');
        LVBuf.Append(THexEncoder.Encode(AValue.ToAsn1Object().GetEncoded(TAsn1Encodable.Der), False));
      except
        on E: Exception do
          raise EArgumentCryptoLibException.CreateRes(@SOtherValueHasNoEncodedForm);
      end;
    end;

    AppendValue(LResultBuf, LVBuf.ToString());
    Result := LResultBuf.ToString();
  finally
    LResultBuf.Free;
    LVBuf.Free;
  end;
end;

class function TIetfUtilities.Canonicalize(const AStr: String): String;
var
  LV: String;
  LObj: IAsn1Object;
  LStr: IAsn1String;
  LStart, LEnd: Int32;
begin
  LV := TStringUtilities.Trim(TStringUtilities.ToLowerInvariant(AStr));

  if (System.Length(LV) > 0) and (LV[1] = '#') then
  begin
    LObj := DecodeObject(LV);
    if Supports(LObj, IAsn1String, LStr) then
    begin
      LV := TStringUtilities.Trim(TStringUtilities.ToLowerInvariant(LStr.GetString()));
    end;
  end;

  if System.Length(LV) > 1 then
  begin
    LStart := 1;
    while (LStart + 1 <= System.Length(LV)) and (LV[LStart] = '\') and (LV[LStart + 1] = ' ') do
    begin
      System.Inc(LStart, 2);
    end;

    LEnd := System.Length(LV);
    while (LEnd - 1 >= 1) and (LV[LEnd - 1] = '\') and (LV[LEnd] = ' ') do
    begin
      System.Dec(LEnd, 2);
    end;

    if (LStart > 1) or (LEnd < System.Length(LV)) then
    begin
      LV := System.Copy(LV, LStart, LEnd - LStart + 1);
    end;
  end;

  Result := StripInternalSpaces(LV);
end;

class function TIetfUtilities.CanonicalString(const AValue: IAsn1Encodable): String;
begin
  Result := Canonicalize(ValueToString(AValue));
end;

class function TIetfUtilities.StripInternalSpaces(const AStr: String): String;
var
  LSb: TStringBuilder;
  LI, LFirst: Int32;
  LC2: Char;
  LB1, LB2: Boolean;
begin
  if System.Length(AStr) = 0 then
  begin
    Result := '';
    Exit;
  end;

  LFirst := TStringUtilities.IndexOf(AStr, ' ');
  if LFirst = 0 then
  begin
    Result := AStr;
    Exit;
  end;

  LSb := TStringBuilder.Create(System.Copy(AStr, 1, LFirst),
    System.Length(AStr) - 1);
  try
    LB1 := False;
    for LI := LFirst + 1 to System.Length(AStr) do
    begin
      LC2 := AStr[LI];
      LB2 := LC2 <> ' ';
      if LB1 or LB2 then
      begin
        LSb.Append(LC2);
        LB1 := LB2;
      end;
    end;

    Result := LSb.ToString();
  finally
    LSb.Free;
  end;
end;

end.
