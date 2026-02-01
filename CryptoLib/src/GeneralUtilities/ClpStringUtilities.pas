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

unit ClpStringUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  StrUtils,
  ClpBitUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// String utility class with static methods.
  /// </summary>
  TStringUtilities = class sealed(TObject)
  public
    /// <summary>
    /// Get hash code for a string.
    /// </summary>
    class function GetStringHashCode(const AInput: string): Int32; static;
    /// <summary>
    /// Split a string by delimiter into an array.
    /// </summary>
    class function SplitString(const AInput: string; ADelimiter: Char)
      : TCryptoLibStringArray; overload; static;
    /// <summary>
    /// Split a string by delimiter into an array, with a maximum number of parts.
    /// When AMaxCount is greater than 0, returns at most AMaxCount parts; the last
    /// part contains the remainder of the string (including any remaining delimiters).
    /// String indices are 1-based.
    /// </summary>
    class function SplitString(const AInput: string; ADelimiter: Char;
      AMaxCount: Int32): TCryptoLibStringArray; overload; static;
    /// <summary>
    /// Compare two strings ignoring case.
    /// </summary>
    class function EqualsIgnoreCase(const A, B: String): Boolean; static;
    /// <summary>
    /// Trim whitespace from both ends of a string.
    /// </summary>
    class function Trim(const AStr: String): String; static;
    /// <summary>
    /// Check if a string starts with a specified value (case-sensitive).
    /// </summary>
    class function StartsWith(const ASource: String; const APrefix: String): Boolean; overload; static;
    /// <summary>
    /// Check if a string starts with a specified value (optionally case-insensitive).
    /// </summary>
    class function StartsWith(const ASource, APrefix: String; AIgnoreCase: Boolean): Boolean; overload; static;
    /// <summary>
    /// Convert string to lowercase using invariant culture.
    /// </summary>
    class function ToLowerInvariant(const AStr: String): String; static;
    /// <summary>
    /// Convert string to uppercase using invariant culture.
    /// </summary>
    class function ToUpperInvariant(const AStr: String): String; static;
    /// <summary>
    /// Find the index of a character in a string (1-based, returns 0 if not found).
    /// </summary>
    class function IndexOf(const ASource: String; AValue: Char): Int32; overload; static;
    /// <summary>
    /// Find the index of a character in a string starting from a position (1-based, returns 0 if not found).
    /// </summary>
    class function IndexOf(const ASource: String; AValue: Char; AStartIndex: Int32): Int32; overload; static;
    /// <summary>
    /// Find the index of a substring in a string (1-based, returns 0 if not found).
    /// </summary>
    class function IndexOf(const ASource: String; const AValue: String): Int32; overload; static;
    /// <summary>
    /// Find the index of a substring in a string starting from a position (1-based, returns 0 if not found).
    /// </summary>
    class function IndexOf(const ASource: String; const AValue: String; AStartIndex: Int32): Int32; overload; static;
    /// <summary>
    /// Check if a string ends with a specified value (case-sensitive).
    /// </summary>
    class function EndsWith(const ASource: String; const ASuffix: String): Boolean; overload; static;
    /// <summary>
    /// Check if a string ends with a specified value (optionally case-insensitive).
    /// </summary>
    class function EndsWith(const ASource: String; const ASuffix: String; AIgnoreCase: Boolean): Boolean; overload; static;
    /// <summary>
    /// Find the last index of a substring in a string (1-based, returns 0 if not found).
    /// </summary>
    class function LastIndexOf(const ASource: String; const AValue: String): Int32; static;
    /// <summary>
    /// Returns a substring from AStartIndex (1-based) to the end of the string.
    /// If AStartIndex is less than 1, it is treated as 1. If AStartIndex is greater
    /// than the string length, returns an empty string.
    /// </summary>
    class function Substring(const AStr: String; AStartIndex: Int32): String; overload; static;
    /// <summary>
    /// Returns a substring of ACount characters starting at AStartIndex (1-based).
    /// If AStartIndex is less than 1, it is treated as 1. If AStartIndex is greater
    /// than the string length, returns an empty string. If ACount would exceed the
    /// remaining characters, returns from AStartIndex to the end of the string.
    /// If ACount is less than or equal to 0, returns an empty string.
    /// </summary>
    class function Substring(const AStr: String; AStartIndex: Int32; ACount: Int32): String; overload; static;
  end;

implementation

{ TStringUtilities }

class function TStringUtilities.GetStringHashCode(const AInput: string): Int32;
var
  LStart, LEnd: Int32;
  LResult: UInt32;
begin
  LResult := 0;

  LStart := 1;
  LEnd := System.Length(AInput);

  while LStart <= LEnd do
  begin
    LResult := TBitUtilities.RotateLeft32(LResult, 5);
    LResult := LResult xor UInt32(AInput[LStart]);
    System.Inc(LStart);
  end;
  Result := Int32(LResult);
end;

class function TStringUtilities.SplitString(const AInput: string; ADelimiter: Char)
  : TCryptoLibStringArray;
var
  LPosStart, LPosDel, LSplitPoints, I, LLowPoint, LHighPoint, LLen: Int32;
begin
  Result := nil;
  if AInput <> '' then
  begin
    { Determine the length of the resulting array }
    LLowPoint := 1;
    LHighPoint := System.Length(AInput);

    LSplitPoints := 0;
    for I := LLowPoint to LHighPoint do
    begin
      if (ADelimiter = AInput[I]) then
        System.Inc(LSplitPoints);
    end;

    System.SetLength(Result, LSplitPoints + 1);

    { Split the string and fill the resulting array }

    I := 0;
    LLen := 1;
    LPosStart := 1;
    LPosDel := System.Pos(ADelimiter, AInput);
    while LPosDel > 0 do
    begin
      Result[I] := System.Copy(AInput, LPosStart, LPosDel - LPosStart);
      LPosStart := LPosDel + LLen;
      LPosDel := PosEx(ADelimiter, AInput, LPosStart);
      System.Inc(I);
    end;
    Result[I] := System.Copy(AInput, LPosStart, System.Length(AInput));
  end;
end;

class function TStringUtilities.SplitString(const AInput: string; ADelimiter: Char;
  AMaxCount: Int32): TCryptoLibStringArray;
var
  LPosStart, LPosDel, J, K: Int32;
begin
  Result := nil;
  if AMaxCount <= 0 then
  begin
    Result := SplitString(AInput, ADelimiter);
    Exit;
  end;
  if AInput = '' then
  begin
    System.SetLength(Result, 1);
    Result[0] := '';
    Exit;
  end;
  System.SetLength(Result, AMaxCount);
  LPosStart := 1;
  for J := 0 to AMaxCount - 2 do
  begin
    LPosDel := PosEx(ADelimiter, AInput, LPosStart);
    if LPosDel < 1 then
    begin
      Result[J] := System.Copy(AInput, LPosStart, System.Length(AInput));
      for K := J + 1 to AMaxCount - 1 do
        Result[K] := '';
      System.SetLength(Result, J + 1);
      Exit;
    end;
    Result[J] := System.Copy(AInput, LPosStart, LPosDel - LPosStart);
    LPosStart := LPosDel + 1;
  end;
  Result[AMaxCount - 1] := System.Copy(AInput, LPosStart, System.Length(AInput));
end;

class function TStringUtilities.EqualsIgnoreCase(const A, B: String): Boolean;
begin
  Result := SameText(A, B);
end;

class function TStringUtilities.Trim(const AStr: String): String;
begin
  Result := SysUtils.Trim(AStr);
end;

class function TStringUtilities.StartsWith(const ASource: String; const APrefix: String): Boolean;
begin
  Result := StartsWith(ASource, APrefix, False);
end;

class function TStringUtilities.StartsWith(const ASource, APrefix: String; AIgnoreCase: Boolean): Boolean;
var
  LPrefixLen, LSourceLen: Int32;
  LSubStr: String;
begin
  LPrefixLen := System.Length(APrefix);
  LSourceLen := System.Length(ASource);

  if (LPrefixLen = 0) or (LPrefixLen > LSourceLen) then
    Exit(False);

  LSubStr := System.Copy(ASource, 1, LPrefixLen);

  if AIgnoreCase then
    Result := SameText(LSubStr, APrefix)
  else
    Result := (LSubStr = APrefix);
end;

class function TStringUtilities.ToLowerInvariant(const AStr: String): String;
begin
  Result := LowerCase(AStr);
end;

class function TStringUtilities.ToUpperInvariant(const AStr: String): String;
begin
  Result := UpperCase(AStr);
end;

class function TStringUtilities.IndexOf(const ASource: String; AValue: Char): Int32;
begin
  Result := System.Pos(AValue, ASource);
end;

class function TStringUtilities.IndexOf(const ASource: String; AValue: Char; AStartIndex: Int32): Int32;
var
  LPos: Int32;
  LSubStr: String;
begin
  // AStartIndex is 1-based for Pascal strings
  if (AStartIndex < 1) or (AStartIndex > System.Length(ASource)) then
  begin
    Result := 0;
    Exit;
  end;
  
  // Search in substring starting from AStartIndex (1-based)
  LSubStr := System.Copy(ASource, AStartIndex, System.Length(ASource) - AStartIndex + 1);
  LPos := System.Pos(AValue, LSubStr);
  if LPos > 0 then
    Result := AStartIndex + (LPos - 1)  // Convert relative position to absolute (1-based)
  else
    Result := 0;
end;

class function TStringUtilities.IndexOf(const ASource: String; const AValue: String): Int32;
begin
  Result := System.Pos(AValue, ASource);
end;

class function TStringUtilities.IndexOf(const ASource: String; const AValue: String; AStartIndex: Int32): Int32;
var
  LPos: Int32;
  LSubStr: String;
begin
  // AStartIndex is 1-based for Pascal strings
  if (AStartIndex < 1) or (AStartIndex > System.Length(ASource)) then
  begin
    Result := 0;
    Exit;
  end;
  
  // Search in substring starting from AStartIndex (1-based)
  LSubStr := System.Copy(ASource, AStartIndex, System.Length(ASource) - AStartIndex + 1);
  LPos := System.Pos(AValue, LSubStr);
  if LPos > 0 then
    Result := AStartIndex + (LPos - 1)  // Convert relative position to absolute (1-based)
  else
    Result := 0;
end;

class function TStringUtilities.EndsWith(const ASource: String; const ASuffix: String): Boolean;
begin
  Result := EndsWith(ASource, ASuffix, False);
end;

class function TStringUtilities.EndsWith(const ASource: String; const ASuffix: String; AIgnoreCase: Boolean): Boolean;
var
  LSourceLen, LSuffixLen: Int32;
  LSubStr: String;
begin
  LSourceLen := System.Length(ASource);
  LSuffixLen := System.Length(ASuffix);
  if (LSuffixLen = 0) or (LSourceLen < LSuffixLen) then
  begin
    Result := False;
    Exit;
  end;
  LSubStr := System.Copy(ASource, LSourceLen - LSuffixLen + 1, LSuffixLen);
  if AIgnoreCase then
    Result := SameText(LSubStr, ASuffix)
  else
    Result := (LSubStr = ASuffix);
end;

class function TStringUtilities.LastIndexOf(const ASource: String; const AValue: String): Int32;
var
  I, LSourceLen, LValueLen: Int32;
  LSubStr: String;
begin
  LSourceLen := System.Length(ASource);
  LValueLen := System.Length(AValue);
  
  if (LValueLen = 0) or (LSourceLen < LValueLen) then
  begin
    Result := 0;
    Exit;
  end;
  
  // Search backwards from the end
  for I := LSourceLen - LValueLen + 1 downto 1 do
  begin
    LSubStr := System.Copy(ASource, I, LValueLen);
    if LSubStr = AValue then
    begin
      Result := I;  // 1-based position
      Exit;
    end;
  end;
  
  Result := 0;  // Not found
end;

class function TStringUtilities.Substring(const AStr: String; AStartIndex: Int32): String;
var
  LLen: Int32;
begin
  LLen := System.Length(AStr);
  Result := Substring(AStr, AStartIndex, LLen - AStartIndex + 1);
end;

class function TStringUtilities.Substring(const AStr: String; AStartIndex: Int32;
  ACount: Int32): String;
var
  LLen: Int32;
  LActualCount: Int32;
begin
  LLen := System.Length(AStr);
  if (LLen = 0) or (ACount <= 0) then
  begin
    Result := '';
    Exit;
  end;
  if AStartIndex < 1 then
    AStartIndex := 1;
  if AStartIndex > LLen then
  begin
    Result := '';
    Exit;
  end;
  LActualCount := ACount;
  if AStartIndex + LActualCount - 1 > LLen then
    LActualCount := LLen - AStartIndex + 1;
  Result := System.Copy(AStr, AStartIndex, LActualCount);
end;

end.
