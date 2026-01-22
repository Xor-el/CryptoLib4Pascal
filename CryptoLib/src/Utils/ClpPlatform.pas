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

unit ClpPlatform;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// Platform utility class with static methods.
  /// </summary>
  TPlatform = class sealed(TObject)
  public
    /// <summary>
    /// Get the type name of an object.
    /// </summary>
    class function GetTypeName(AObj: TObject): String; overload; static;
    class function GetTypeName(AClass: TClass): String; overload; static;
    /// <summary>
    /// Get an environment variable value.
    /// </summary>
    class function GetEnvironmentVariable(const AVariable: String): String; static;
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
    class function StartsWith(const AValue: String; const AStr: String): Boolean; overload; static;
    /// <summary>
    /// Check if a string starts with a specified value (optionally case-insensitive).
    /// </summary>
    class function StartsWith(const AValue: String; const AStr: String; AIgnoreCase: Boolean): Boolean; overload; static;
    /// <summary>
    /// Convert string to lowercase using invariant culture.
    /// </summary>
    class function ToLowerInvariant(const AStr: String): String; static;
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
    /// Check if the current process is 64-bit.
    /// </summary>
    class function Is64BitProcess: Boolean; static;
  end;

implementation

{ TPlatform }

class function TPlatform.GetTypeName(AObj: TObject): String;
begin
  if AObj = nil then
    Result := 'nil'
  else
    Result := AObj.ClassName;
end;

class function TPlatform.GetTypeName(AClass: TClass): String;
begin
  if AClass = nil then
    Result := 'nil'
  else
    Result := AClass.ClassName;
end;

class function TPlatform.GetEnvironmentVariable(const AVariable: String): String;
begin
  try
    Result := SysUtils.GetEnvironmentVariable(AVariable);
  except
    // We don't have the required permission to read this environment variable,
    // which is fine, just act as if it's not set
    Result := '';
  end;
end;

class function TPlatform.EqualsIgnoreCase(const A, B: String): Boolean;
begin
  Result := SameText(A, B);
end;

class function TPlatform.Trim(const AStr: String): String;
begin
  Result := SysUtils.Trim(AStr);
end;

class function TPlatform.StartsWith(const AValue: String; const AStr: String): Boolean;
begin
  Result := StartsWith(AValue, AStr, False);
end;

class function TPlatform.StartsWith(const AValue: String; const AStr: String; AIgnoreCase: Boolean): Boolean;
var
  LValueLen, LStrLen: Int32;
  LSubStr: String;
begin
  LValueLen := System.Length(AValue);
  LStrLen := System.Length(AStr);
  if (LValueLen = 0) or (LStrLen < LValueLen) then
  begin
    Result := False;
    Exit;
  end;
  LSubStr := System.Copy(AStr, 1, LValueLen);
  if AIgnoreCase then
    Result := SameText(LSubStr, AValue)
  else
    Result := (LSubStr = AValue);
end;

class function TPlatform.ToLowerInvariant(const AStr: String): String;
begin
  Result := LowerCase(AStr);
end;

class function TPlatform.IndexOf(const ASource: String; AValue: Char): Int32;
begin
  Result := System.Pos(AValue, ASource);
end;

class function TPlatform.IndexOf(const ASource: String; AValue: Char; AStartIndex: Int32): Int32;
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

class function TPlatform.IndexOf(const ASource: String; const AValue: String): Int32;
begin
  Result := System.Pos(AValue, ASource);
end;

class function TPlatform.IndexOf(const ASource: String; const AValue: String; AStartIndex: Int32): Int32;
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

class function TPlatform.EndsWith(const ASource: String; const ASuffix: String): Boolean;
begin
  Result := EndsWith(ASource, ASuffix, False);
end;

class function TPlatform.EndsWith(const ASource: String; const ASuffix: String; AIgnoreCase: Boolean): Boolean;
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

class function TPlatform.LastIndexOf(const ASource: String; const AValue: String): Int32;
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

class function TPlatform.Is64BitProcess: Boolean;
begin
  // Check if SizeOf(Pointer) is 8 bytes (64-bit) or 4 bytes (32-bit)
  Result := SizeOf(Pointer) = 8;
end;

end.
