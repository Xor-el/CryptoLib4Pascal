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

unit ClpEnumUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  TypInfo,
  ClpDateTimeUtilities,
  ClpStringUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Utility class for enum operations.
  /// Works with ordinals; callers cast to their enum type e.g. TMyEnum(ordinal).
  /// </summary>
  TEnumUtilities = class sealed(TObject)
  strict private
    class function DefaultReplacer(const AInput: String): String; static;
  public
    /// <summary>
    /// Returns an array of ordinals for all defined values of the enum.
    /// For enums with gaps, only ordinals that have a name are included.
    /// Note: iterates MinValue..MaxValue calling GetEnumName, so enums with
    /// large gaps between values will be slower.
    /// Caller casts: TMyEnum(GetEnumValues(TypeInfo(TMyEnum))[i]).
    /// </summary>
    class function GetEnumValues(ATypeInfo: PTypeInfo): TCryptoLibInt32Array; overload; static;

    /// <summary>
    /// Returns an arbitrary (pseudo-random) ordinal of the enum, based on
    /// CurrentUnixMs. If the enum has no values, returns 0.
    /// Caller casts: TMyEnum(GetArbitraryValue(TypeInfo(TMyEnum))).
    /// </summary>
    class function GetArbitraryValue(ATypeInfo: PTypeInfo): Int32; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum ordinal. Only parses single named
    /// constants: non-empty, first character a letter, no comma.
    /// the input is normalized by replacing '-' and '/' with '_'.
    /// Returns True and the ordinal in AResult when successful; otherwise
    /// False and AResult is 0.
    /// </summary>
    class function TryGetEnumValue(ATypeInfo: PTypeInfo; const AInput: String;
      out AResult: Int32): Boolean; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum ordinal. Only parses single named
    /// constants: non-empty, first character a letter, no comma. When AReplacer
    /// is nil, the input is normalized by replacing '-' and '/' with '_'
    /// before parsing; when AReplacer is assigned, it is applied to the input.
    /// Returns True and the ordinal in AResult when successful; otherwise
    /// False and AResult is 0.
    /// </summary>
    class function TryGetEnumValue(ATypeInfo: PTypeInfo; const AInput: String;
      out AResult: Int32;
      const AReplacer: TCryptoLibFunc<String, String>): Boolean; overload; static;

    /// <summary>
    /// Converts an enum ordinal to its declared name string.
    /// Returns empty string if ATypeInfo is nil, not an enum, or ordinal has no name.
    /// </summary>
    class function ToString(ATypeInfo: PTypeInfo; AOrdinal: Int32): String; overload; static;

    // Generic overloads (T must be an enum); delegate to PTypeInfo versions.

    /// <summary>
    /// Returns an array of all defined values of the enum.
    /// </summary>
    class function GetEnumValues<T>: TCryptoLibGenericArray<T>; overload; static;

    /// <summary>
    /// Returns an arbitrary (pseudo-random) value of the enum.
    /// If the enum has no values, returns Default(T).
    /// </summary>
    class function GetArbitraryValue<T>: T; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum value. Default normalization ('-', '/' to '_') is used.
    /// On failure, AResult is Default(T).
    /// </summary>
    class function TryGetEnumValue<T>(const AInput: String; out AResult: T): Boolean; overload; static;

    /// <summary>
    /// Tries to parse a string as an enum value. When AReplacer is nil, default
    /// normalization ('-', '/' to '_') is used.
    /// On failure, AResult is Default(T).
    /// </summary>
    class function TryGetEnumValue<T>(const AInput: String; out AResult: T;
      const AReplacer: TCryptoLibFunc<String, String>): Boolean; overload; static;

    /// <summary>
    /// Tries to interpret an ordinal as a valid named value of the enum.
    /// On success sets AResult to T(AOrdinal) and returns True;
    /// otherwise AResult is Default(T) and returns False.
    /// </summary>
    class function TryGetEnumFromOrdinal<T>(AOrdinal: Int32; out AResult: T): Boolean; static;

    /// <summary>
    /// Converts an enum value to its declared name string.
    /// </summary>
    class function ToString<T>(const AValue: T): String; overload; static;
  end;

implementation

{ TEnumUtilities }

class function TEnumUtilities.DefaultReplacer(const AInput: String): String;
begin
  Result := StringReplace(AInput, '-', '_', [rfReplaceAll]);
  Result := StringReplace(Result, '/', '_', [rfReplaceAll]);
end;

class function TEnumUtilities.GetEnumValues(ATypeInfo: PTypeInfo): TCryptoLibInt32Array;
var
  LTypeData: PTypeData;
  LI, LCount: Int32;
begin
  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
  begin
    Result := nil;
    Exit;
  end;

  LTypeData := GetTypeData(ATypeInfo);
  SetLength(Result, LTypeData^.MaxValue - LTypeData^.MinValue + 1);
  LCount := 0;
  for LI := LTypeData^.MinValue to LTypeData^.MaxValue do
    if GetEnumName(ATypeInfo, LI) <> '' then
    begin
      Result[LCount] := LI;
      Inc(LCount);
    end;
  SetLength(Result, LCount);
end;

class function TEnumUtilities.GetArbitraryValue(ATypeInfo: PTypeInfo): Int32;
var
  LValues: TCryptoLibInt32Array;
  LMs: Int64;
begin
  LValues := GetEnumValues(ATypeInfo);
  if System.Length(LValues) = 0 then
    Exit(0);
  LMs := TDateTimeUtilities.CurrentUnixMs() and Int64($7FFFFFFF);
  Result := LValues[Int32(LMs mod System.Length(LValues))];
end;

class function TEnumUtilities.TryGetEnumValue(ATypeInfo: PTypeInfo;
  const AInput: String; out AResult: Int32): Boolean;
begin
  Result := TryGetEnumValue(ATypeInfo, AInput, AResult, nil);
end;

class function TEnumUtilities.TryGetEnumValue(ATypeInfo: PTypeInfo;
  const AInput: String; out AResult: Int32;
  const AReplacer: TCryptoLibFunc<String, String>): Boolean;
var
  LProcessed: String;
  LOrd: Int32;
begin
  AResult := 0;

  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
    Exit(False);

  // Only parse single named constants: non-empty, first char a letter, no comma
  if (System.Length(AInput) = 0) or (TStringUtilities.IndexOf(AInput, ',') > 0) then
    Exit(False);

  if not CharInSet(AInput[1], ['A'..'Z', 'a'..'z']) then
    Exit(False);

  if Assigned(AReplacer) then
    LProcessed := AReplacer(AInput)
  else
    LProcessed := DefaultReplacer(AInput);

  LOrd := GetEnumValue(ATypeInfo, LProcessed);
  if LOrd < 0 then
    Exit(False);

  AResult := LOrd;
  Result := True;
end;

class function TEnumUtilities.ToString(ATypeInfo: PTypeInfo; AOrdinal: Int32): String;
begin
  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
    Exit('');
  Result := GetEnumName(ATypeInfo, AOrdinal);
end;

class function TEnumUtilities.GetEnumValues<T>: TCryptoLibGenericArray<T>;
var
  LOrds: TCryptoLibInt32Array;
  LI: Int32;
begin
  LOrds := GetEnumValues(TypeInfo(T));
  SetLength(Result, System.Length(LOrds));
  for LI := 0 to System.High(LOrds) do
    Move(LOrds[LI], Result[LI], SizeOf(T));
end;

class function TEnumUtilities.GetArbitraryValue<T>: T;
var
  LOrd: Int32;
begin
  LOrd := GetArbitraryValue(TypeInfo(T));
  Move(LOrd, Result, SizeOf(T));
end;

class function TEnumUtilities.TryGetEnumValue<T>(const AInput: String; out AResult: T): Boolean;
var
  LOrd: Int32;
begin
  // TODO: FPC 3.2.x fails when compiling TryGetEnumValue<T>(...), when upgrading minimum FPC to a version
  // that compiles it, remove this inlined implementation and forward to TryGetEnumValue<T>(AInput, AResult, nil).
  Result := TryGetEnumValue(TypeInfo(T), AInput, LOrd, nil);
  if Result then
    Move(LOrd, AResult, SizeOf(T))
  else
    AResult := Default(T);
end;

class function TEnumUtilities.TryGetEnumValue<T>(const AInput: String;
  out AResult: T; const AReplacer: TCryptoLibFunc<String, String>): Boolean;
var
  LOrd: Int32;
begin
  Result := TryGetEnumValue(TypeInfo(T), AInput, LOrd, AReplacer);
  if Result then
    Move(LOrd, AResult, SizeOf(T))
  else
    AResult := Default(T);
end;

class function TEnumUtilities.TryGetEnumFromOrdinal<T>(AOrdinal: Int32;
  out AResult: T): Boolean;
begin
  // We use GetEnumName to validate the ordinal rather than a simple MinValue/MaxValue
  // range check because Delphi supports non-contiguous enums (e.g., A = 0, B = 5, C = 10).
  // GetEnumName returns an empty string for ordinals that fall in gaps between valid values,
  // correctly rejecting them, whereas a range check would incorrectly accept them.
  Result := ToString(TypeInfo(T), AOrdinal) <> '';
  if Result then
    Move(AOrdinal, AResult, SizeOf(T))
  else
    AResult := Default(T);
end;

class function TEnumUtilities.ToString<T>(const AValue: T): String;
var
  LOrd: Int32;
begin
  LOrd := 0;
  Move(AValue, LOrd, SizeOf(T));
  Result := ToString(TypeInfo(T), LOrd);
end;

end.
