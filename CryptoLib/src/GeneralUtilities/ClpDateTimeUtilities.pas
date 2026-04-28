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

unit ClpDateTimeUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  DateUtils,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// Parse flags mirroring .NET DateTimeStyles (time zone interpretation and conversion).
  /// </summary>
  TDateTimeParseFlag = (
    /// <summary>No zone in input: treat as local. UTC conversion only with AdjustToUniversal.</summary>
    AssumeLocal,
    /// <summary>No zone in input: treat as UTC. Conversion only with AdjustToUniversal.</summary>
    AssumeUniversal,
    /// <summary>Convert result to UTC using explicit or assumed offset.</summary>
    AdjustToUniversal
  );

  /// <summary>
  /// Flags for time zone interpretation and optional UTC conversion; mirrors .NET DateTimeStyles.
  /// </summary>
  TDateTimeParseStyle = set of TDateTimeParseFlag;

  /// <summary>Converts .NET-style date/time format strings to Delphi FormatDateTime form.</summary>
  TDateTimeFormatTransformer = class sealed
  strict private
    class var FTransforms: TCryptoLibGenericArray<TCryptoLibFunc<String, String>>;
    class constructor Create;

    class function StripUnsupportedTokens(AFormat: String): String; static;
    class function MapMilliseconds(AFormat: String): String; static;
    class function MapMonthMinute(AFormat: String): String; static;
    class function Map24Hour(AFormat: String): String; static;

  public
    /// <summary>Append a transform to the chain.</summary>
    class procedure Register(const ATransform: TCryptoLibFunc<String, String>);
    /// <summary>Run all registered transforms on the format string.</summary>
    class function Apply(const AFormat: String): String;
    /// <summary>Normalize \Z, "Z", 'Z' to plain Z.</summary>
    class function NormalizeLiteralZ(const AFormat: String): String;
    /// <summary>True if format contains any of the given tokens.</summary>
    class function HasAnyToken(const AFormat: String; const ATokens: array of String): Boolean;
  end;

  /// <summary>Helpers for strict date/time substring parsing.</summary>
  TDateTimeParseHelper = class sealed
  public
    /// <summary>Read integer from substring; returns False if invalid.</summary>
    class function ReadInt(const S: String; AIndex, ACount: Int32; out AValue: Int32): Boolean;
    /// <summary>Read Word from substring; returns False if invalid.</summary>
    class function ReadWord(const S: String; AIndex, ACount: Int32; out AValue: Word): Boolean;
    /// <summary>Number of 'f' characters after the dot in the format.</summary>
    class function CountFracDigits(const AFormat: String): Int32;
    /// <summary>True if format is yy (two-digit year) but not yyyy.</summary>
    class function IsTwoDigitYearFormat(const AFormat: String): Boolean;
    /// <summary>Expand two-digit year using .NET TwoDigitYearMax rollover.</summary>
    class function ExpandTwoDigitYear(ATwoDigitYear, ATwoDigitMax: Int32): Word;
  end;

  /// <summary>Static date/time helpers (Unix ms, ticks, parse/format for ASN.1 time).</summary>
  TDateTimeUtilities = class sealed(TObject)
  strict private
    class var
      FUnixEpoch: TDateTime;
      FMaxUnixMs: Int64;
      FMinUnixMs: Int64;
      FTwoDigitYearMax: Int32;

    class function ParseExact(
      const AStr, AFormat: String;
      const AStyles: TDateTimeParseStyle;
      const AFormatSettings: TFormatSettings;
      const ATwoDigitYearMax: Int32): TDateTime; overload; static;

  public
    /// <summary>Milliseconds since Unix epoch (1 Jan 1970 UTC); converts to UTC first.</summary>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">ADateTime before epoch.</exception>
    class function DateTimeToUnixMs(const ADateTime: TDateTime): Int64; static;

    /// <summary>DateTime from milliseconds since Unix epoch.</summary>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">AUnixMs outside MinUnixMs..MaxUnixMs.</exception>
    class function UnixMsToDateTime(const AUnixMs: Int64): TDateTime; static;

    /// <summary>Current time as milliseconds since Unix epoch.</summary>
    class function CurrentUnixMs(): Int64; static;

    /// <summary>Ticks (100-ns) since 1 Jan 0001 00:00:00.</summary>
    class function DateTimeToTicks(const ADateTime: TDateTime): Int64; static;

    /// <summary>DateTime from ticks since 1 Jan 0001 00:00:00.</summary>
    class function TicksToDateTime(const ATicks: Int64): TDateTime; static;

    /// <summary>Round to 10 ms (centisecond).</summary>
    class function WithPrecisionCentisecond(const ADateTime: TDateTime): TDateTime; static;
    /// <summary>Round to 100 ms (decisecond).</summary>
    class function WithPrecisionDecisecond(const ADateTime: TDateTime): TDateTime; static;
    /// <summary>Round to millisecond.</summary>
    class function WithPrecisionMillisecond(const ADateTime: TDateTime): TDateTime; static;
    /// <summary>Round to second (fraction discarded).</summary>
    class function WithPrecisionSecond(const ADateTime: TDateTime): TDateTime; static;

    /// <summary>
    /// Strict parse equivalent to .NET DateTime.ParseExact for ASN.1 UTCTime/GeneralizedTime.
    /// Input must match <paramref name="AFormat"/> exactly (length, literals, fraction).
    /// Supports yy(yy)MMddHH[mm][ss][.f...] with Z, zz, or zzz; two-digit year uses default TwoDigitYearMax; <paramref name="AStyles"/> control time zone (AssumeLocal, AssumeUniversal, AdjustToUniversal).
    /// </summary>
    /// <exception cref="EFormatCryptoLibException">Input does not match format.</exception>
    class function ParseExact(
      const AInput, AFormat: String;
      const AStyles: TDateTimeParseStyle;
      const AFormatSettings: TFormatSettings): TDateTime; overload; static;

    /// <summary>
    /// Format TDateTime for ASN.1 UTCTime/GeneralizedTime (yyyy/yy, MM, dd, HH, mm, ss, .FFFFFFF, Z/K).
    /// If <paramref name="AConvertToUtc"/> is True, value is converted to UTC first.
    /// </summary>
    class function FormatCanonical(
      const ADateTime: TDateTime;
      const AFormat: String;
      const AFormatSettings: TFormatSettings;
      const AConvertToUtc: Boolean): String;

    /// <summary>Convert local DateTime to UTC.</summary>
    class function ToUniversalTime(const ALocalDateTime: TDateTime): TDateTime; static;

    /// <summary>1 Jan 1970 00:00:00 UTC.</summary>
    class property UnixEpoch: TDateTime read FUnixEpoch;
    /// <summary>Maximum allowed Unix milliseconds.</summary>
    class property MaxUnixMs: Int64 read FMaxUnixMs;
    /// <summary>Minimum allowed Unix milliseconds (0).</summary>
    class property MinUnixMs: Int64 read FMinUnixMs;
    /// <summary>TwoDigitYearMax for yy expansion (2049).</summary>
    class property TwoDigitYearMax: Int32 read FTwoDigitYearMax;

    class constructor Create;
  end;

implementation

{ TDateTimeFormatTransformer }

class function TDateTimeFormatTransformer.StripUnsupportedTokens(AFormat: String): String;
begin
  Result := StringReplace(AFormat, '.FFFFFFF', '', [rfReplaceAll]);
  Result := StringReplace(Result, 'K', '', [rfReplaceAll]);
  Result := StringReplace(Result, '"Z"', '', [rfReplaceAll]);
  Result := StringReplace(Result, '''Z''', '', [rfReplaceAll]);
  Result := StringReplace(Result, '\Z', '', [rfReplaceAll]);
end;

class function TDateTimeFormatTransformer.MapMilliseconds(AFormat: String): String;
begin
  Result := StringReplace(AFormat, 'fff', 'zzz', [rfReplaceAll]);
  Result := StringReplace(Result, 'ff', 'zz', [rfReplaceAll]);
  Result := StringReplace(Result, 'f', 'z', [rfReplaceAll]);
end;

class function TDateTimeFormatTransformer.MapMonthMinute(AFormat: String): String;
const
  MonthPlaceholder = #1; // Control char as placeholder
begin
  Result := StringReplace(AFormat, 'MM', MonthPlaceholder, [rfReplaceAll]);
  Result := StringReplace(Result, 'mm', 'nn', [rfReplaceAll]);
  Result := StringReplace(Result, MonthPlaceholder, 'mm', [rfReplaceAll]);
end;

class function TDateTimeFormatTransformer.Map24Hour(AFormat: String): String;
begin
  Result := StringReplace(AFormat, 'HH', 'hh', [rfReplaceAll]);
end;

class constructor TDateTimeFormatTransformer.Create;
begin
  // Register built-in transforms in order of precedence
  Register(StripUnsupportedTokens);
  Register(MapMilliseconds);
  Register(MapMonthMinute);
  Register(Map24Hour);
end;

class procedure TDateTimeFormatTransformer.Register(const ATransform: TCryptoLibFunc<String, String>);
begin
  SetLength(FTransforms, System.Length(FTransforms) + 1);
  FTransforms[High(FTransforms)] := ATransform;
end;

class function TDateTimeFormatTransformer.Apply(const AFormat: String): String;
var
  LI: Integer;
begin
  Result := AFormat;
  for LI := Low(FTransforms) to High(FTransforms) do
    Result := FTransforms[LI](Result);
end;

class function TDateTimeFormatTransformer.NormalizeLiteralZ(const AFormat: String): String;
begin
  Result := AFormat;

  // C# style literal: \Z (single backslash)
  Result := StringReplace(Result, '\Z', 'Z', [rfReplaceAll]);

  // In case someone passed "\\Z" literally (rare, but harmless)
  Result := StringReplace(Result, '\\Z', 'Z', [rfReplaceAll]);

  // Allow Delphi-style quoted literal Z
  Result := StringReplace(Result, '"Z"', 'Z', [rfReplaceAll]);
  Result := StringReplace(Result, '''Z''', 'Z', [rfReplaceAll]);
end;

class function TDateTimeFormatTransformer.HasAnyToken(
  const AFormat: String; const ATokens: array of String): Boolean;
var
  LI: Integer;
begin
  Result := False;
  for LI := Low(ATokens) to High(ATokens) do
  begin
    if Pos(ATokens[LI], AFormat) > 0 then
      Exit(True);
  end;
end;

{ TDateTimeParseHelper }

class function TDateTimeParseHelper.ReadInt(
  const S: String; AIndex, ACount: Int32; out AValue: Int32): Boolean;
var
  LPart: String;
begin
  Result := False;
  if (AIndex < 1) or (ACount < 1) then
    Exit;
  if (AIndex + ACount - 1) > System.Length(S) then
    Exit;

  LPart := System.Copy(S, AIndex, ACount);
  Result := TryStrToInt(LPart, AValue);
end;

class function TDateTimeParseHelper.ReadWord(
  const S: String; AIndex, ACount: Int32; out AValue: Word): Boolean;
var
  LI: Int32;
begin
  Result := ReadInt(S, AIndex, ACount, LI);
  if Result then
    AValue := Word(LI);
end;

class function TDateTimeParseHelper.CountFracDigits(const AFormat: String): Int32;
var
  LP, LI: Int32;
begin
  Result := 0;
  LP := Pos('.', AFormat);
  if LP = 0 then
    Exit;

  LI := LP + 1;
  while (LI <= System.Length(AFormat)) and (AFormat[LI] = 'f') do
  begin
    Inc(Result);
    Inc(LI);
  end;

  if Result = 0 then
    raise EFormatCryptoLibException.Create('Invalid format (fraction dot without f)');
end;

class function TDateTimeParseHelper.IsTwoDigitYearFormat(const AFormat: String): Boolean;
begin
  // Treat "yyyy" as 4-digit year; treat leading "yy" otherwise as 2-digit.
  Result := (System.Length(AFormat) >= 2) and (System.Copy(AFormat, 1, 2) = 'yy') and
            not ((System.Length(AFormat) >= 4) and (System.Copy(AFormat, 1, 4) = 'yyyy'));
end;

class function TDateTimeParseHelper.ExpandTwoDigitYear(
  ATwoDigitYear, ATwoDigitMax: Int32): Word;
var
  LCenturyBase: Int32;
begin
  // Same rollover mapping as .NET calendars.
  LCenturyBase := ATwoDigitMax div 100;
  if ATwoDigitYear > (ATwoDigitMax mod 100) then
    Dec(LCenturyBase);

  Result := Word(LCenturyBase * 100 + ATwoDigitYear);
end;

{ TDateTimeUtilities }

class constructor TDateTimeUtilities.Create;
var
  LMaxDateTime: TDateTime;
  LMaxMs, LUnixEpochMs: Int64;
begin
  // Unix epoch: January 1, 1970 00:00:00 UTC
  FUnixEpoch := EncodeDate(1970, 1, 1);

  FMinUnixMs := 0;

  // Calculate MaxUnixMs: (DateTime.MaxValue.Ticks - UnixEpoch.Ticks) / TicksPerMillisecond
  LMaxDateTime := MaxDateTime;
  LUnixEpochMs := MilliSecondsBetween(UnixEpoch, 0);
  LMaxMs := MilliSecondsBetween(LMaxDateTime, 0);
  FMaxUnixMs := LMaxMs - LUnixEpochMs;
  // GregorianCalendar TwoDigitYearMax value (2049)
  FTwoDigitYearMax := 2049;
end;

class function TDateTimeUtilities.DateTimeToUnixMs(const ADateTime: TDateTime): Int64;
var
  LUtc: TDateTime;
  LMsSinceEpoch: Int64;
begin
  LUtc := ToUniversalTime(ADateTime);
  if LUtc < UnixEpoch then
    raise EArgumentOutOfRangeCryptoLibException.Create('DateTime value may not be before the epoch');

  // Calculate milliseconds since Unix epoch
  LMsSinceEpoch := MilliSecondsBetween(LUtc, UnixEpoch);
  Result := LMsSinceEpoch;
end;

class function TDateTimeUtilities.UnixMsToDateTime(const AUnixMs: Int64): TDateTime;
var
  LMsSinceEpoch: Int64;
begin
  if (AUnixMs < MinUnixMs) or (AUnixMs > MaxUnixMs) then
    raise EArgumentOutOfRangeCryptoLibException.Create('UnixMs value out of range');

  LMsSinceEpoch := AUnixMs;
  Result := IncMilliSecond(UnixEpoch, LMsSinceEpoch);
end;

class function TDateTimeUtilities.CurrentUnixMs(): Int64;
begin
  Result := DateTimeToUnixMs(ToUniversalTime(Now));
end;

class function TDateTimeUtilities.DateTimeToTicks(const ADateTime: TDateTime): Int64;
var
  LEpoch: TDateTime;
  LMsSinceEpoch: Int64;
begin
  // Epoch: January 1, 0001 12:00am
  LEpoch := EncodeDateTime(1, 1, 1, 0, 0, 0, 0);
  
  // Calculate milliseconds since epoch (preserving sign)
  if ADateTime >= LEpoch then
    LMsSinceEpoch := MilliSecondsBetween(ADateTime, LEpoch)
  else
    LMsSinceEpoch := -MilliSecondsBetween(ADateTime, LEpoch);
  
  // Convert milliseconds to ticks (1 millisecond = 10,000 ticks)
  Result := LMsSinceEpoch * Int64(10000);
end;

class function TDateTimeUtilities.TicksToDateTime(const ATicks: Int64): TDateTime;
var
  LEpoch: TDateTime;
  LMsSinceEpoch: Int64;
begin
  // Epoch: January 1, 0001 12:00am
  LEpoch := EncodeDateTime(1, 1, 1, 0, 0, 0, 0);
  
  // Convert ticks to milliseconds (1 millisecond = 10,000 ticks)
  LMsSinceEpoch := ATicks div Int64(10000);
  
  // Add milliseconds to epoch to get the DateTime
  Result := IncMilliSecond(LEpoch, LMsSinceEpoch);
end;

class function TDateTimeUtilities.WithPrecisionCentisecond(const ADateTime: TDateTime): TDateTime;
var
  LMs: Int64;
begin
  LMs := DateTimeToUnixMs(ADateTime);
  LMs := LMs - (LMs mod 10); // Round to 10ms (centisecond)
  Result := UnixMsToDateTime(LMs);
end;

class function TDateTimeUtilities.WithPrecisionDecisecond(const ADateTime: TDateTime): TDateTime;
var
  LMs: Int64;
begin
  LMs := DateTimeToUnixMs(ADateTime);
  LMs := LMs - (LMs mod 100); // Round to 100ms (decisecond)
  Result := UnixMsToDateTime(LMs);
end;

class function TDateTimeUtilities.WithPrecisionMillisecond(const ADateTime: TDateTime): TDateTime;
var
  LMs: Int64;
begin
  LMs := DateTimeToUnixMs(ADateTime);
  // Already at millisecond precision, just return as-is
  Result := UnixMsToDateTime(LMs);
end;

class function TDateTimeUtilities.WithPrecisionSecond(const ADateTime: TDateTime): TDateTime;
var
  LYear, LMonth, LDay, LHour, LMinute, LSecond, LMillisecond: Word;
begin
  DecodeDateTime(ADateTime, LYear, LMonth, LDay, LHour, LMinute, LSecond, LMillisecond);
  Result := EncodeDateTime(LYear, LMonth, LDay, LHour, LMinute, LSecond, 0);
end;

class function TDateTimeUtilities.FormatCanonical(
  const ADateTime: TDateTime;
  const AFormat: String;
  const AFormatSettings: TFormatSettings;
  const AConvertToUtc: Boolean): String;
var
  LDT: TDateTime;
  LDelphiFmt, LFracStr: String;
  LHour, LMinute, LSecond, LMillisecond: Word;
  LFrac7: UInt32;
begin
  LDT := ADateTime;
  if AConvertToUtc then
    LDT := ToUniversalTime(LDT);

  // Transform .NET format to Delphi format
  LDelphiFmt := TDateTimeFormatTransformer.Apply(AFormat);
  Result := FormatDateTime(LDelphiFmt, LDT, AFormatSettings);

  // Append fraction if FFFFFFF token present
  if Pos('FFFFFFF', AFormat) > 0 then
  begin
    DecodeTime(LDT, LHour, LMinute, LSecond, LMillisecond);
    if LMillisecond > 0 then
    begin
      LFrac7 := UInt32(LMillisecond) * 10000; // ms -> 7-digit ticks
      LFracStr := Format('%.7d', [LFrac7]);

      // trim trailing zeros
      while (LFracStr <> '') and (LFracStr[Length(LFracStr)] = '0') do
        Delete(LFracStr, Length(LFracStr), 1);

      if LFracStr <> '' then
        Result := Result + '.' + LFracStr;
    end;
  end;

  // Append UTC suffix if needed (K, \Z, "Z", 'Z')
  if TDateTimeFormatTransformer.HasAnyToken(AFormat, ['K', '\Z', '"Z"', '''Z''']) then
    Result := Result + 'Z';
end;

class function TDateTimeUtilities.ParseExact(
  const AInput, AFormat: String;
  const AStyles: TDateTimeParseStyle;
  const AFormatSettings: TFormatSettings): TDateTime;
begin
  Result := ParseExact(AInput, AFormat, AStyles, AFormatSettings, TwoDigitYearMax);
end;

class function TDateTimeUtilities.ParseExact(
  const AStr, AFormat: String;
  const AStyles: TDateTimeParseStyle;
  const AFormatSettings: TFormatSettings;
  const ATwoDigitYearMax: Int32): TDateTime;
var
  LFmt: String;
  LLen, LExpectedLen: Int32;
  LIsTwoDigitYear: Boolean;
  LYearWidth: Int32;

  LYearI32: Int32;
  LYearW: Word;
  LMonth, LDay, LHour, LMinute, LSecond, LMillisecond: Word;

  LFracDigits: Int32;
  LHasMinutes, LHasSeconds, LHasFrac, LHasZ, LHasTZ2, LHasTZ3: Boolean;
  LDotExpectedPos: Int32;
  LFracStr: String;
  LTmp: Int32;

  LSignPos: Int32;
  LSign: Char;
  LOffsetHours, LOffsetMinutes: Int32;
begin
  LLen := System.Length(AStr);
  LFmt := TDateTimeFormatTransformer.NormalizeLiteralZ(AFormat);

  LIsTwoDigitYear := TDateTimeParseHelper.IsTwoDigitYearFormat(LFmt);
  if LIsTwoDigitYear then
    LYearWidth := 2
  else
    LYearWidth := 4;

  // --- Determine what the format requires (subset used in ASN.1 time parsing) ---
  LHasMinutes := Pos('mm', LFmt) > 0;
  LHasSeconds := Pos('ss', LFmt) > 0;

  LFracDigits := TDateTimeParseHelper.CountFracDigits(LFmt);
  LHasFrac := LFracDigits > 0;

  // Suffix tokens we support:
  LHasZ := (System.Length(LFmt) > 0) and (LFmt[System.Length(LFmt)] = 'Z');

  // "zz" and "zzz" at the end.
  LHasTZ3 := (System.Length(LFmt) >= 3) and
             (System.Copy(LFmt, System.Length(LFmt) - 2, 3) = 'zzz');
  LHasTZ2 := (System.Length(LFmt) >= 2) and
             (System.Copy(LFmt, System.Length(LFmt) - 1, 2) = 'zz') and
             (not LHasTZ3);

  if LHasZ and (LHasTZ2 or LHasTZ3) then
    raise EFormatCryptoLibException.Create('Invalid format (Z and timezone both present)');

  // --- Compute expected length exactly ---
  // Base: (yy|yyyy)MMddHH = yearWidth + 6
  LExpectedLen := LYearWidth + 6;

  if LHasMinutes then
    Inc(LExpectedLen, 2);
  if LHasSeconds then
    Inc(LExpectedLen, 2);

  if LHasFrac then
    Inc(LExpectedLen, 1 + LFracDigits); // '.' + digits

  if LHasZ then
    Inc(LExpectedLen, 1); // 'Z'
  if LHasTZ3 then
    Inc(LExpectedLen, 5); // +/-HHMM
  if LHasTZ2 then
    Inc(LExpectedLen, 3); // +/-HH

  if LLen <> LExpectedLen then
    raise EFormatCryptoLibException.Create('Input does not match format length');

  // --- Enforce literal suffix if present ---
  if LHasZ then
  begin
    if (LLen = 0) or (AStr[LLen] <> 'Z') then
      raise EFormatCryptoLibException.Create('Missing UTC (Z) designator');
  end;

  // --- Parse mandatory components (1-based indices) ---
  if LIsTwoDigitYear then
  begin
    if not TDateTimeParseHelper.ReadInt(AStr, 1, 2, LYearI32) then
      raise EFormatCryptoLibException.Create('Invalid year');
    LYearW := TDateTimeParseHelper.ExpandTwoDigitYear(LYearI32, ATwoDigitYearMax);

    if not TDateTimeParseHelper.ReadWord(AStr, 3, 2, LMonth) then
      raise EFormatCryptoLibException.Create('Invalid month');
    if not TDateTimeParseHelper.ReadWord(AStr, 5, 2, LDay) then
      raise EFormatCryptoLibException.Create('Invalid day');
    if not TDateTimeParseHelper.ReadWord(AStr, 7, 2, LHour) then
      raise EFormatCryptoLibException.Create('Invalid hour');
  end
  else
  begin
    if not TDateTimeParseHelper.ReadWord(AStr, 1, 4, LYearW) then
      raise EFormatCryptoLibException.Create('Invalid year');

    if not TDateTimeParseHelper.ReadWord(AStr, 1 + LYearWidth, 2, LMonth) then
      raise EFormatCryptoLibException.Create('Invalid month');
    if not TDateTimeParseHelper.ReadWord(AStr, 3 + LYearWidth, 2, LDay) then
      raise EFormatCryptoLibException.Create('Invalid day');
    if not TDateTimeParseHelper.ReadWord(AStr, 5 + LYearWidth, 2, LHour) then
      raise EFormatCryptoLibException.Create('Invalid hour');
  end;

  LMinute := 0;
  LSecond := 0;
  LMillisecond := 0;

  if LHasMinutes then
    if not TDateTimeParseHelper.ReadWord(AStr, 7 + LYearWidth, 2, LMinute) then
      raise EFormatCryptoLibException.Create('Invalid minute');

  if LHasSeconds then
    if not TDateTimeParseHelper.ReadWord(AStr, 9 + LYearWidth, 2, LSecond) then
      raise EFormatCryptoLibException.Create('Invalid second');

  // --- Fraction must be exactly where expected ---
  if LHasFrac then
  begin
    if LHasSeconds then
      LDotExpectedPos := 11 + LYearWidth
    else if LHasMinutes then
      LDotExpectedPos := 9 + LYearWidth
    else
      LDotExpectedPos := 7 + LYearWidth;

    if (LDotExpectedPos > LLen) or (AStr[LDotExpectedPos] <> '.') then
      raise EFormatCryptoLibException.Create('Missing fractional dot');

    LFracStr := System.Copy(AStr, LDotExpectedPos + 1, LFracDigits);
    if not TryStrToInt(LFracStr, LTmp) then
      raise EFormatCryptoLibException.Create('Invalid fractional seconds');

    // Convert fraction to milliseconds.
    if LFracDigits = 1 then
      LMillisecond := Word(LTmp * 100)
    else if LFracDigits = 2 then
      LMillisecond := Word(LTmp * 10)
    else
    begin
      if LFracDigits > 3 then
        LFracStr := System.Copy(LFracStr, 1, 3);
      if not TryStrToInt(LFracStr, LTmp) then
        raise EFormatCryptoLibException.Create('Invalid fractional milliseconds');
      LMillisecond := Word(LTmp);
    end;
  end;

  // --- Base datetime value ---
  Result := EncodeDateTime(LYearW, LMonth, LDay, LHour, LMinute, LSecond, LMillisecond);

  // --- Timezone parsing if format includes zz/zzz ---
  if LHasTZ3 or LHasTZ2 then
  begin
    if LHasTZ3 then
      LSignPos := LLen - 4 // 1-based position of sign for last 5 chars
    else
      LSignPos := LLen - 2; // 1-based position of sign for last 3 chars

    LSign := AStr[LSignPos];
    if (LSign <> '+') and (LSign <> '-') then
      raise EFormatCryptoLibException.Create('Invalid timezone sign');

    LOffsetHours := StrToIntDef(System.Copy(AStr, LSignPos + 1, 2), -1);
    if LOffsetHours < 0 then
      raise EFormatCryptoLibException.Create('Invalid timezone hours');

    if LHasTZ3 then
    begin
      LOffsetMinutes := StrToIntDef(System.Copy(AStr, LSignPos + 3, 2), -1);
      if LOffsetMinutes < 0 then
        raise EFormatCryptoLibException.Create('Invalid timezone minutes');
    end
    else
      LOffsetMinutes := 0;

    // C# AdjustToUniversal: convert to UTC based on offset.
    if TDateTimeParseFlag.AdjustToUniversal in AStyles then
    begin
      if LSign = '+' then
        Result := IncMinute(Result, -(LOffsetHours * 60 + LOffsetMinutes))
      else
        Result := IncMinute(Result,  (LOffsetHours * 60 + LOffsetMinutes));
    end;
  end;

  // --- AssumeUniversal/AssumeLocal when no suffix exists ---
  if (not (LHasZ or LHasTZ2 or LHasTZ3)) then
  begin
    if TDateTimeParseFlag.AdjustToUniversal in AStyles then
    begin
      if TDateTimeParseFlag.AssumeLocal in AStyles then
      begin
        // interpret as local then convert to UTC
        Result := ToUniversalTime(Result);
      end
      else if TDateTimeParseFlag.AssumeUniversal in AStyles then
      begin
        // already UTC, no-op
      end;
    end;
  end;
end;

class function TDateTimeUtilities.ToUniversalTime(const ALocalDateTime: TDateTime): TDateTime;
begin
{$IFDEF FPC}
  Result := LocalTimeToUniversal(ALocalDateTime);
{$ELSE}
  Result := TTimeZone.Local.ToUniversalTime(ALocalDateTime);
{$ENDIF}
end;

end.
