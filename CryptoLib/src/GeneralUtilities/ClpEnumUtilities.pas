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
  ClpPlatformUtilities,
  ClpStringUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Utility class for enum operations, ported from Bouncy Castle Enums.
  /// Works with ordinals; callers cast to their enum type e.g. TMyEnum(ordinal).
  /// </summary>
  TEnumUtilities = class sealed(TObject)
  public
    /// <summary>
    /// Returns an array of ordinals for all defined values of the enum.
    /// For enums with gaps, only ordinals that have a name are included.
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
    /// constants: non-empty, first character a letter, no comma. Replaces
    /// '-' and '/' with '_' before parsing. Returns True and the ordinal
    /// in AResult when successful; otherwise False and AResult is undefined.
    /// Caller casts: TMyEnum(AResult).
    /// </summary>
    class function TryGetEnumValue(ATypeInfo: PTypeInfo; const S: String; out AResult: Int32): Boolean; overload; static;

    // Generic overloads (T must be an enum); delegate to PTypeInfo versions.

    /// <summary>
    /// Returns an array of all defined values of the enum. Delegates to
    /// GetEnumValues(PTypeInfo).
    /// </summary>
    class function GetEnumValues<T>: TCryptoLibGenericArray<T>; overload; static;
    /// <summary>
    /// Returns an arbitrary (pseudo-random) value of the enum. Delegates to
    /// GetArbitraryValue(PTypeInfo). If the enum has no values, returns Default(T).
    /// </summary>
    class function GetArbitraryValue<T>: T; overload; static;
    /// <summary>
    /// Tries to parse a string as an enum value. Delegates to
    /// TryGetEnumValue(PTypeInfo, S, out Int32). On failure, AResult is Default(T).
    /// </summary>
    class function TryGetEnumValue<T>(const S: String; out AResult: T): Boolean; overload; static;
  end;

implementation

{ TEnumUtilities }

class function TEnumUtilities.GetEnumValues(ATypeInfo: PTypeInfo): TCryptoLibInt32Array;
var
  LTypeData: PTypeData;
  I, LOrd: Int32;
  LList: TCryptoLibInt32Array;
  LCount: Int32;
begin
  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
  begin
    SetLength(Result, 0);
    Exit;
  end;
  LTypeData := GetTypeData(ATypeInfo);
  LCount := 0;
  SetLength(LList, LTypeData^.MaxValue - LTypeData^.MinValue + 1);
  for I := LTypeData^.MinValue to LTypeData^.MaxValue do
  begin
    if GetEnumName(ATypeInfo, I) <> '' then
    begin
      LList[LCount] := I;
      Inc(LCount);
    end;
  end;
  SetLength(Result, LCount);
  for LOrd := 0 to LCount - 1 do
    Result[LOrd] := LList[LOrd];
end;

class function TEnumUtilities.GetArbitraryValue(ATypeInfo: PTypeInfo): Int32;
var
  LValues: TCryptoLibInt32Array;
  LPos: Int32;
  LMs: Int64;
begin
  LValues := GetEnumValues(ATypeInfo);
  if System.Length(LValues) = 0 then
  begin
    Result := 0;
    Exit;
  end;
  LMs := TDateTimeUtilities.CurrentUnixMs() and Int64($7FFFFFFF);
  LPos := Int32(LMs mod System.Length(LValues));
  Result := LValues[LPos];
end;

class function TEnumUtilities.TryGetEnumValue(ATypeInfo: PTypeInfo; const S: String;
  out AResult: Int32): Boolean;
var
  LProcessed: String;
  LOrd: LongInt;
begin
  AResult := 0;
  if (ATypeInfo = nil) or (ATypeInfo^.Kind <> tkEnumeration) then
  begin
    Result := False;
    Exit;
  end;
  // Only parse single named constants: non-empty, first char a letter, no comma
  if (System.Length(S) = 0) or (TStringUtilities.IndexOf(S, ',') > 0) then
  begin
    Result := False;
    Exit;
  end;
  if not (S[1] in ['A'..'Z', 'a'..'z']) then
  begin
    Result := False;
    Exit;
  end;
  LProcessed := StringReplace(S, '-', '_', [rfReplaceAll, rfIgnoreCase]);
  LProcessed := StringReplace(LProcessed, '/', '_', [rfReplaceAll, rfIgnoreCase]);
  LOrd := GetEnumValue(ATypeInfo, LProcessed);
  if LOrd >= 0 then
  begin
    AResult := LOrd;
    Result := True;
  end
  else
    Result := False;
end;

class function TEnumUtilities.GetEnumValues<T>: TCryptoLibGenericArray<T>;
var
  LOrds: TCryptoLibInt32Array;
  I: Int32;
begin
  LOrds := GetEnumValues(TypeInfo(T));
  SetLength(Result, System.Length(LOrds));
  for I := 0 to System.High(LOrds) do
    Move(LOrds[I], Result[I], SizeOf(T));
end;

class function TEnumUtilities.GetArbitraryValue<T>: T;
var
  LOrd: Int32;
begin
  LOrd := GetArbitraryValue(TypeInfo(T));
  Move(LOrd, Result, SizeOf(T));
end;

class function TEnumUtilities.TryGetEnumValue<T>(const S: String;
  out AResult: T): Boolean;
var
  LOrd: Int32;
begin
  Result := TryGetEnumValue(TypeInfo(T), S, LOrd);
  if Result then
    Move(LOrd, AResult, SizeOf(T))
  else
    AResult := Default(T);
end;

end.
