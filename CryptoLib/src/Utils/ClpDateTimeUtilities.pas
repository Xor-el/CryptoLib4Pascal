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

unit ClpDateTimeUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  DateUtils,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// DateTime parse behavior flags, mirroring .NET DateTimeStyles semantics.
  /// </summary>
  TDateTimeParseFlag = (
    /// <summary>
    /// Interprets the parsed value as local time when no explicit time zone
    /// designator (<c>Z</c>, <c>zz</c>, <c>zzz</c>) is present in the input.
    /// </summary>
    /// <remarks>
    /// This flag does not perform any time zone conversion by itself.
    /// Conversion to UTC occurs only when combined with
    /// <see cref="AdjustToUniversal"/>.
    /// </remarks>
    AssumeLocal,

    /// <summary>
    /// Interprets the parsed value as Coordinated Universal Time (UTC)
    /// when no explicit time zone designator is present in the input.
    /// </summary>
    /// <remarks>
    /// This flag affects interpretation only; no conversion is performed
    /// unless <see cref="AdjustToUniversal"/> is also specified.
    /// </remarks>
    AssumeUniversal,

    /// <summary>
    /// Converts the parsed value to Coordinated Universal Time (UTC)
    /// after applying any explicit or assumed time zone offset.
    /// </summary>
    /// <remarks>
    /// When combined with <see cref="AssumeLocal"/>, the value is treated as
    /// local time and converted to UTC. When combined with
    /// <see cref="AssumeUniversal"/>, the value is treated as already in UTC.
    /// If an explicit offset (<c>zz</c> or <c>zzz</c>) is present, that offset
    /// is applied before conversion.
    /// </remarks>
    AdjustToUniversal
  );

  /// <summary>
  /// Set of flags that control how date/time strings are interpreted and
  /// optionally converted during parsing.
  /// </summary>
  /// <remarks>
  /// This set mirrors the behavior of .NET <c>DateTimeStyles</c> for
  /// <c>DateTime.ParseExact</c>, adapted to Delphi's <c>TDateTime</c>
  /// representation (which has no intrinsic time-zone kind).
  ///
  /// Interpretation flags (<see cref="AssumeLocal"/>, <see cref="AssumeUniversal"/>)
  /// define how values without an explicit time-zone designator are treated.
  /// Conversion occurs only when combined with <see cref="AdjustToUniversal"/>.
  /// </remarks>
  /// <example>
  /// <code>
  /// // Equivalent to:
  /// // DateTime.ParseExact(s, format, provider,
  /// //   DateTimeStyles.AssumeLocal);
  /// Dt := TDateTimeUtilities.ParseExact(
  ///   S,
  ///   Format,
  ///   [TDateTimeParseFlag.AssumeLocal],
  ///   TFormatSettings.Invariant
  /// );
  ///
  /// // Equivalent to:
  /// // DateTime.ParseExact(s, format, provider,
  /// //   DateTimeStyles.AdjustToUniversal);
  /// Dt := TDateTimeUtilities.ParseExact(
  ///   S,
  ///   Format,
  ///   [TDateTimeParseFlag.AdjustToUniversal],
  ///   TFormatSettings.Invariant
  /// );
  ///
  /// // Equivalent to:
  /// // DateTime.ParseExact(s, format, provider,
  /// //   DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal);
  /// Dt := TDateTimeUtilities.ParseExact(
  ///   S,
  ///   Format,
  ///   [TDateTimeParseFlag.AssumeUniversal,
  ///    TDateTimeParseFlag.AdjustToUniversal],
  ///   TFormatSettings.Invariant
  /// );
  /// </code>
  /// </example>
  TDateTimeParseStyle = set of TDateTimeParseFlag;

  /// <summary>
  /// Function type for format string transformations.
  /// </summary>
  TTokenTransformFunc = reference to function(const AFormat: String): String;

  /// <summary>
  /// Transforms .NET-style format strings to Delphi FormatDateTime-compatible forms.
  /// </summary>
  TDateTimeFormatTransformer = class sealed
  strict private
    class var FTransforms: TCryptoLibGenericArray<TTokenTransformFunc>;
    class constructor Create;

    constructor Create;
  public
    /// <summary>
    /// Register a new transform function (appended to the chain).
    /// </summary>
    class procedure Register(const ATransform: TTokenTransformFunc);

    /// <summary>
    /// Apply all registered transforms in order.
    /// </summary>
    class function Apply(const AFormat: String): String;

    /// <summary>
    /// Normalize literal Z variants (\\Z, "Z", 'Z') to plain Z.
    /// </summary>
    class function NormalizeLiteralZ(const AFormat: String): String;

    /// <summary>
    /// Check if format contains any of the specified tokens.
    /// </summary>
    class function HasAnyToken(const AFormat: String; const ATokens: array of String): Boolean;
  end;

  /// <summary>
  /// Reusable parsing utilities for strict date/time string parsing.
  /// </summary>
  TDateTimeParseHelper = class sealed
  strict private
    constructor Create;
  public
    /// <summary>
    /// Read an integer from a substring with strict validation.
    /// </summary>
    class function ReadInt(const S: String; AIndex, ACount: Int32; out AValue: Int32): Boolean;

    /// <summary>
    /// Read a Word from a substring with strict validation.
    /// </summary>
    class function ReadWord(const S: String; AIndex, ACount: Int32; out AValue: Word): Boolean;

    /// <summary>
    /// Count fractional digits (f characters) after the dot in format.
    /// </summary>
    class function CountFracDigits(const AFormat: String): Int32;

    /// <summary>
    /// Check if format uses two-digit year (yy but not yyyy).
    /// </summary>
    class function IsTwoDigitYearFormat(const AFormat: String): Boolean;

    /// <summary>
    /// Expand two-digit year using .NET Calendar.TwoDigitYearMax rollover logic.
    /// </summary>
    class function ExpandTwoDigitYear(ATwoDigitYear, ATwoDigitMax: Int32): Word;
  end;

  /// <summary>
  /// DateTime utility class with static methods.
  /// </summary>
  TDateTimeUtilities = class sealed(TObject)
  strict private
    constructor Create;

    class var
      /// <summary>
      /// Unix epoch: January 1, 1970 00:00:00 UTC
      /// </summary>
      FUnixEpoch: TDateTime;
      /// <summary>
      /// Maximum Unix milliseconds value.
      /// </summary>
      FMaxUnixMs: Int64;
      /// <summary>
      /// Minimum Unix milliseconds value.
      /// </summary>
      FMinUnixMs: Int64;
      /// <summary>
      /// GregorianCalendar TwoDigitYearMax value (2049).
      /// </summary>
      FTwoDigitYearMax: Int32;

    class function ParseExact(
      const AStr, AFormat: String;
      const AStyles: TDateTimeParseStyle;
      const AFormatSettings: TFormatSettings;
      const ATwoDigitYearMax: Int32): TDateTime; overload; static;

  public
    /// <summary>
    /// Return the number of milliseconds since the Unix epoch (1 Jan., 1970 UTC) for a given DateTime value.
    /// </summary>
    /// <remarks>The DateTime value will be converted to UTC before conversion.</remarks>
    /// <param name="ADateTime">A DateTime value not before the epoch.</param>
    /// <returns>Number of whole milliseconds after epoch.</returns>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">'ADateTime' is before the epoch.</exception>
    class function DateTimeToUnixMs(const ADateTime: TDateTime): Int64; static;

    /// <summary>
    /// Create a UTC DateTime value from the number of milliseconds since the Unix epoch (1 Jan., 1970 UTC).
    /// </summary>
    /// <param name="AUnixMs">Number of milliseconds since the epoch.</param>
    /// <returns>A UTC DateTime value</returns>
    /// <exception cref="EArgumentOutOfRangeCryptoLibException">'AUnixMs' is before 'MinUnixMs' or after 'MaxUnixMs'.</exception>
    class function UnixMsToDateTime(const AUnixMs: Int64): TDateTime; static;

    /// <summary>
    /// Return the current number of milliseconds since the Unix epoch (1 Jan., 1970 UTC).
    /// </summary>
    class function CurrentUnixMs(): Int64; static;

    /// <summary>
    /// Round DateTime to centisecond precision (10 milliseconds).
    /// </summary>
    class function WithPrecisionCentisecond(const ADateTime: TDateTime): TDateTime; static;

    /// <summary>
    /// Round DateTime to decisecond precision (100 milliseconds).
    /// </summary>
    class function WithPrecisionDecisecond(const ADateTime: TDateTime): TDateTime; static;

    /// <summary>
    /// Round DateTime to millisecond precision.
    /// </summary>
    class function WithPrecisionMillisecond(const ADateTime: TDateTime): TDateTime; static;

    /// <summary>
    /// Round DateTime to second precision.
    /// </summary>
    class function WithPrecisionSecond(const ADateTime: TDateTime): TDateTime; static;

    /// <summary>
    /// Parses a date/time string using exact, invariant rules equivalent to
    /// .NET DateTime.ParseExact for ASN.1 UTCTime and GeneralizedTime values.
    /// </summary>
    /// <remarks>
    /// This method is a strict parser: the input string must match the supplied
    /// <paramref name="AFormat"/> exactly in length, numeric placement, literals,
    /// and fractional precision.
    /// <para>
    /// The following format families are supported:
    /// </para>
    /// <list type="bullet">
    ///   <item><description>
    ///     UTCTime formats (<c>yyMMddHHmm[ss]</c> with <c>Z</c> or <c>zzz</c>)
    ///   </description></item>
    ///   <item><description>
    ///     GeneralizedTime formats (<c>yyyyMMddHH[mm][ss][.f..fffffff]</c>
    ///     with optional <c>Z</c>, <c>zz</c>, or <c>zzz</c>)
    ///   </description></item>
    /// </list>
    /// <para>
    /// When parsing two-digit years (<c>yy</c>), the value is expanded using
    /// <paramref name="ATwoDigitYearMax"/>, matching .NET Calendar.TwoDigitYearMax
    /// rollover behavior.
    /// </para>
    /// <para>
    /// Time zone behavior is controlled via <paramref name="AStyles"/> and mirrors
    /// .NET DateTimeStyles:
    /// </para>
    /// <list type="bullet">
    ///   <item><description><c>AssumeLocal</c></description></item>
    ///   <item><description><c>AssumeUniversal</c></description></item>
    ///   <item><description><c>AdjustToUniversal</c></description></item>
    /// </list>
    /// <para>
    /// Any mismatch in format, length, or required literals results in a format exception.
    /// No heuristic or culture-dependent parsing is performed.
    /// </para>
    /// </remarks>
    /// <param name="AStr">The input string to parse.</param>
    /// <param name="AFormat">
    /// The exact expected format string (Delphi-safe; <c>\Z</c> is normalized to literal <c>Z</c>).
    /// </param>
    /// <param name="AStyles">
    /// A set of parse-style flags controlling time zone interpretation and conversion.
    /// </param>
    /// <param name="AFormatSettings">
    /// The format settings to use; typically <see cref="TFormatSettings.Invariant"/>.
    /// </param>
    /// <param name="ATwoDigitYearMax">
    /// The maximum year used when expanding two-digit years; ignored for four-digit formats.
    /// </param>
    /// <returns>
    /// The parsed <see cref="TDateTime"/> value.
    /// </returns>
    /// <exception cref="EFormatCryptoLibException">
    /// Raised when the input does not exactly match the specified format.
    /// </exception>
    class function ParseExact(
      const AStr, AFormat: String;
      const AStyles: TDateTimeParseStyle;
      const AFormatSettings: TFormatSettings): TDateTime; overload; static;

    /// <summary>
    /// Formats a <see cref="TDateTime"/> into a canonical, invariant string representation,
    /// emulating .NET DateTime.ToString(format, InvariantInfo) semantics for ASN.1 time values.
    /// </summary>
    /// <remarks>
    /// This method supports a restricted, explicit subset of .NET-style format tokens:
    /// <list type="bullet">
    ///   <item><description><c>yyyy</c> or <c>yy</c> year fields</description></item>
    ///   <item><description><c>MM</c>, <c>dd</c>, <c>HH</c>, <c>mm</c>, <c>ss</c> numeric fields</description></item>
    ///   <item><description><c>.FFFFFFF</c> fractional seconds (validated and trimmed to available precision)</description></item>
    ///   <item><description><c>Z</c> or <c>K</c> UTC designator (emitted as literal <c>Z</c>)</description></item>
    /// </list>
    /// <para>
    /// If <paramref name="AConvertToUtc"/> is <c>True</c>, the value is first converted from
    /// local time to UTC using <see cref="TTimeZone.Local.ToUniversalTime"/>.
    /// </para>
    /// <para>
    /// Due to <see cref="TDateTime"/> precision limits, fractional seconds beyond milliseconds
    /// are validated and emitted as zeroes where applicable.
    /// </para>
    /// </remarks>
    /// <param name="ADateTime">The date and time value to format.</param>
    /// <param name="AFormat">
    /// The canonical format string (Delphi-safe), e.g.
    /// <c>yyyyMMddHHmmss.FFFFFFFK</c> or <c>yyMMddHHmmssZ</c>.
    /// </param>
    /// <param name="AFormatSettings">
    /// The format settings to use; typically <see cref="TFormatSettings.Invariant"/>.
    /// </param>
    /// <param name="AConvertToUtc">
    /// If <c>True</c>, converts <paramref name="ADateTime"/> to UTC before formatting.
    /// </param>
    /// <returns>
    /// A canonical string representation suitable for ASN.1 UTCTime or GeneralizedTime.
    /// </returns>
    class function FormatCanonical(
      const ADateTime: TDateTime;
      const AFormat: String;
      const AFormatSettings: TFormatSettings;
      const AConvertToUtc: Boolean): String;

    /// <summary>
    /// Unix epoch: January 1, 1970 00:00:00 UTC
    /// </summary>
    class property UnixEpoch: TDateTime read FUnixEpoch;
    /// <summary>
    /// Maximum Unix milliseconds value.
    /// </summary>
    class property MaxUnixMs: Int64 read FMaxUnixMs;
    /// <summary>
    /// Minimum Unix milliseconds value.
    /// </summary>
    class property MinUnixMs: Int64 read FMinUnixMs;
    /// <summary>
    /// GregorianCalendar TwoDigitYearMax value (2049).
    /// </summary>
    class property TwoDigitYearMax: Int32 read FTwoDigitYearMax;

    class constructor Create;
  end;

implementation

{ TDateTimeFormatTransformer }

class constructor TDateTimeFormatTransformer.Create;
const
  MonthPlaceholder = #1; // Control char as placeholder
begin
  // Register built-in transforms in order of precedence

  // Strip unsupported tokens
  Register(function(const F: String): String
  begin
    Result := StringReplace(F, '.FFFFFFF', '', [rfReplaceAll]);
    Result := StringReplace(Result, 'K', '', [rfReplaceAll]);
    Result := StringReplace(Result, '"Z"', '', [rfReplaceAll]);
    Result := StringReplace(Result, '''Z''', '', [rfReplaceAll]);
    Result := StringReplace(Result, '\Z', '', [rfReplaceAll]);
  end);

  // Map milliseconds (process longest first)
  Register(function(const F: String): String
  begin
    Result := StringReplace(F, 'fff', 'zzz', [rfReplaceAll]);
    Result := StringReplace(Result, 'ff', 'zz', [rfReplaceAll]);
    Result := StringReplace(Result, 'f', 'z', [rfReplaceAll]);
  end);

  // Map month/minute (protect month first)
  Register(function(const F: String): String
  begin
    Result := StringReplace(F, 'MM', MonthPlaceholder, [rfReplaceAll]);
    Result := StringReplace(Result, 'mm', 'nn', [rfReplaceAll]);
    Result := StringReplace(Result, MonthPlaceholder, 'mm', [rfReplaceAll]);
  end);

  // Map 24-hour format
  Register(function(const F: String): String
  begin
    Result := StringReplace(F, 'HH', 'hh', [rfReplaceAll]);
  end);
end;

constructor TDateTimeFormatTransformer.Create;
begin
  raise ENotSupportedException.Create('TDateTimeFormatTransformer is a static class');
end;

class procedure TDateTimeFormatTransformer.Register(const ATransform: TTokenTransformFunc);
begin
  SetLength(FTransforms, System.Length(FTransforms) + 1);
  FTransforms[High(FTransforms)] := ATransform;
end;

class function TDateTimeFormatTransformer.Apply(const AFormat: String): String;
var
  I: Integer;
begin
  Result := AFormat;
  for I := Low(FTransforms) to High(FTransforms) do
    Result := FTransforms[I](Result);
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
  I: Integer;
begin
  Result := False;
  for I := Low(ATokens) to High(ATokens) do
  begin
    if Pos(ATokens[I], AFormat) > 0 then
      Exit(True);
  end;
end;

{ TDateTimeParseHelper }

constructor TDateTimeParseHelper.Create;
begin
  raise ENotSupportedException.Create('TDateTimeParseHelper is a static class');
end;

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
  P, I: Int32;
begin
  Result := 0;
  P := Pos('.', AFormat);
  if P = 0 then
    Exit;

  I := P + 1;
  while (I <= System.Length(AFormat)) and (AFormat[I] = 'f') do
  begin
    Inc(Result);
    Inc(I);
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

constructor TDateTimeUtilities.Create;
begin
  raise ENotSupportedException.Create('TDateTimeUtilities is a static class');
end;

class function TDateTimeUtilities.DateTimeToUnixMs(const ADateTime: TDateTime): Int64;
var
  LUtc: TDateTime;
  LMsSinceEpoch: Int64;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(ADateTime);
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
  Result := DateTimeToUnixMs(TTimeZone.Local.ToUniversalTime(Now));
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
    LDT := TTimeZone.Local.ToUniversalTime(LDT);

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
  const AStr, AFormat: String;
  const AStyles: TDateTimeParseStyle;
  const AFormatSettings: TFormatSettings): TDateTime;
begin
  Result := ParseExact(AStr, AFormat, AStyles, AFormatSettings, TwoDigitYearMax);
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
        Result := TTimeZone.Local.ToUniversalTime(Result);
      end
      else if TDateTimeParseFlag.AssumeUniversal in AStyles then
      begin
        // already UTC, no-op
      end;
    end;
  end;
end;

end.
