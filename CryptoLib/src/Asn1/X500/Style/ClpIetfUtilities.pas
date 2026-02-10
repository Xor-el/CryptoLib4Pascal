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

unit ClpIetfUtilities;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  ClpStringUtilities,

  ClpEncoders;

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
      raise EInvalidOperationCryptoLibException.Create('unknown encoding in name: ' + E.Message);
  end;
end;

class function TIetfUtilities.Unescape(const AElt: String): String;
var
  LSb: TStringBuilder;
  LStart, I, LLastEscaped: Int32;
  LEscaped, LQuoted, LNonWhiteSpaceEncountered: Boolean;
  LC: Char;
  LHex1: Int32;
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
  try

    LStart := 1;
    if (System.Length(AElt) > 0) and (AElt[1] = '\') then
    begin
      if (System.Length(AElt) > 1) and (AElt[2] = '#') then
      begin
        LStart := 3; // Skip '\#' (positions 1 and 2)
        LSb.Append('\#');
      end;
    end;

    LNonWhiteSpaceEncountered := False;
    LLastEscaped := 0;
    LHex1 := 0; // Store as Int32 (0 = no hex digit waiting)

    for I := LStart to System.Length(AElt) do
    begin
      LC := AElt[I];

      // nonWhiteSpaceEncountered = true;
      if LC <> ' ' then
        LNonWhiteSpaceEncountered := True;

      if LC = '"' then
      begin
        if not LEscaped then
        begin
          LQuoted := not LQuoted;
        end
        else
        begin
          LSb.Append(LC);
          LEscaped := False;
        end;
      end
      else if (LC = '\') and (not LEscaped) and (not LQuoted) then
      begin
        LEscaped := True;
        LLastEscaped := LSb.Length;
      end
      else
      begin
        if (LC = ' ') and (not LEscaped) and (not LNonWhiteSpaceEncountered) then
        begin
          Continue;
        end;
        if LEscaped and IsHexDigit(LC) then
        begin
          if LHex1 <> 0 then
          begin
            LSb.Append(Chr(ConvertHex(Chr(LHex1)) * 16 + ConvertHex(LC)));
            LEscaped := False;
            LHex1 := 0;
            Continue;
          end;
          LHex1 := Ord(LC);
          Continue;
        end;
        LSb.Append(LC);
        LEscaped := False;
      end;
    end;

    if LSb.Length > 0 then
    begin
      while (LSb.Length > 0) and 
            (LSb.Chars[LSb.Length - 1] = ' ') and 
            (LLastEscaped <> LSb.Length - 1) do
      begin
        LSb.Length := LSb.Length - 1;
      end;
      Result := LSb.ToString();
    end
    else
      Result := '';
  finally
    LSb.Free;
  end;
end;

class function TIetfUtilities.ValueToString(const AValue: IAsn1Encodable): String;
var
  LVBuf: TStringBuilder;
  LV: String;
  LStr: IAsn1String;
  LEnd, LIndex, LStart, LEndBuf: Int32;
begin
  LVBuf := TStringBuilder.Create();
  try
    if Supports(AValue, IAsn1String, LStr) and (not Supports(AValue, IDerUniversalString)) then
    begin
      LV := LStr.GetString();
      if (System.Length(LV) > 0) and (LV[1] = '#') then
      begin
        LVBuf.Append('\');
      end;
      LVBuf.Append(LV);
    end
    else
    begin
      try
        LVBuf.Append('#');
        LVBuf.Append(THexEncoder.Encode(AValue.ToAsn1Object().GetEncoded(TAsn1Encodable.Der), False));
      except
        on E: Exception do
          raise EArgumentCryptoLibException.Create('Other value has no encoded form');
      end;
    end;

    LEnd := LVBuf.Length;
    LIndex := 0; // TStringBuilder.Chars uses 0-based indexing

    if (LVBuf.Length >= 2) and (LVBuf.Chars[0] = '\') and (LVBuf.Chars[1] = '#') then
    begin
      System.Inc(LIndex, 2);
    end;

    while LIndex < LEnd do
    begin
      case LVBuf.Chars[LIndex] of
        ',', '"', '\', '+', '=', '<', '>', ';':
          begin
            LVBuf.Insert(LIndex, '\');
            System.Inc(LIndex, 2);
            System.Inc(LEnd);
          end;
      else
        System.Inc(LIndex);
      end;
    end;

    LStart := 0;
    if LVBuf.Length > 0 then
    begin
      while (LVBuf.Length > LStart) and (LVBuf.Chars[LStart] = ' ') do
      begin
        LVBuf.Insert(LStart, '\');
        System.Inc(LStart, 2);
      end;
    end;

    LEndBuf := LVBuf.Length - 1;

    while (LEndBuf >= 0) and (LVBuf.Chars[LEndBuf] = ' ') do
    begin
      LVBuf.Insert(LEndBuf, '\');
      System.Dec(LEndBuf);
    end;

    Result := LVBuf.ToString();
  finally
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
  I: Int32;
  LC1, LC2: Char;
begin
  if System.Length(AStr) = 0 then
  begin
    Result := '';
    Exit;
  end;

  LSb := TStringBuilder.Create();
  try
    LC1 := AStr[1];
    LSb.Append(LC1);

    for I := 2 to System.Length(AStr) do
    begin
      LC2 := AStr[I];
      if not ((LC1 = ' ') and (LC2 = ' ')) then
      begin
        LSb.Append(LC2);
      end;
      LC1 := LC2;
    end;

    Result := LSb.ToString();
  finally
    LSb.Free;
  end;
end;

end.
