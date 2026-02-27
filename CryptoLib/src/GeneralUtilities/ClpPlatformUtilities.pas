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

unit ClpPlatformUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils;

type
  /// <summary>
  /// Platform utility class with static methods.
  /// </summary>
  TPlatformUtilities = class sealed(TObject)
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
    /// Check if the current process is 64-bit.
    /// </summary>
    class function Is64BitProcess: Boolean; static;
  end;

implementation

{ TPlatformUtilities }

class function TPlatformUtilities.GetTypeName(AObj: TObject): String;
begin
  if AObj = nil then
    Result := 'nil'
  else
    Result := AObj.ClassName;
end;

class function TPlatformUtilities.GetTypeName(AClass: TClass): String;
begin
  if AClass = nil then
    Result := 'nil'
  else
    Result := AClass.ClassName;
end;

class function TPlatformUtilities.GetEnvironmentVariable(const AVariable: String): String;
begin
  try
    Result := SysUtils.GetEnvironmentVariable(AVariable);
  except
    // We don't have the required permission to read this environment variable,
    // which is fine, just act as if it's not set
    Result := '';
  end;
end;

class function TPlatformUtilities.Is64BitProcess: Boolean;
begin
  // Check if SizeOf(Pointer) is 8 bytes (64-bit) or 4 bytes (32-bit)
  Result := SizeOf(Pointer) = 8;
end;

end.
