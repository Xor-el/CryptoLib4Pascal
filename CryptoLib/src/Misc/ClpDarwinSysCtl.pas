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

unit ClpDarwinSysCtl;

{$I ..\Include\CryptoLib.inc}

interface

{$IF DEFINED(CRYPTOLIB_ARM)}
{$IF DEFINED(CRYPTOLIB_MACOS) OR DEFINED(CRYPTOLIB_IOS)}

uses
{$IFDEF FPC}
  dl
{$ELSE}
  Posix.Dlfcn
{$ENDIF}
  ;

type
  /// <summary>
  /// Resolves sysctlbyname from the already-loaded process image via
  /// dlopen(nil) + dlsym, avoiding any static import of Posix.SysSysctl.
  /// Provides a simple Boolean query for ARM feature detection on Darwin
  /// (macOS and iOS).
  /// </summary>
  TDarwinSysCtl = class sealed
  strict private
  type
    TSysCtlByNameFunc = function(AName: PAnsiChar; AOldP: Pointer;
      AOldLenP: Pointer; ANewP: Pointer; ANewLen: NativeUInt): Int32; cdecl;

  strict private
  class var
    FSysCtlByName: TSysCtlByNameFunc;

  private
    class procedure ResolveDynamicImports(); static;

  strict private
    /// <summary>
    /// Queries a single sysctl key. Returns True if the key exists and
    /// its integer value is >= 1.
    /// </summary>
    class function QueryKey(const AName: PAnsiChar): Boolean; static;

  public
    /// <summary>
    /// Returns True if the named sysctl feature is available.
    /// Tries AModernName first (macOS 12+ FEAT_* keys). If that key does
    /// not exist or returns 0, falls back to ALegacyName (macOS 11 keys).
    /// If ALegacyName is nil, no fallback is attempted.
    /// </summary>
    class function HasFeature(const AModernName: PAnsiChar;
      const ALegacyName: PAnsiChar = nil): Boolean; static;
  end;

{$IFEND} // CRYPTOLIB_MACOS OR CRYPTOLIB_IOS
{$IFEND} // CRYPTOLIB_ARM

implementation

{$IF DEFINED(CRYPTOLIB_ARM)}
{$IF DEFINED(CRYPTOLIB_MACOS) OR DEFINED(CRYPTOLIB_IOS)}

{ TDarwinSysCtl }

class procedure TDarwinSysCtl.ResolveDynamicImports();
var
  LHandle: Pointer;
begin
  FSysCtlByName := nil;

  LHandle := dlopen(nil, RTLD_NOW);
  if LHandle = nil then
    Exit;

  try
    FSysCtlByName := TSysCtlByNameFunc(dlsym(LHandle, 'sysctlbyname'));
  finally
    dlclose(LHandle);
  end;
end;

class function TDarwinSysCtl.QueryKey(const AName: PAnsiChar): Boolean;
var
  LValue: Int32;
  LLen: NativeUInt;
begin
  if (AName = nil) or (not System.Assigned(FSysCtlByName)) then
  begin
    Result := False;
    Exit;
  end;

  LValue := 0;
  LLen := SizeOf(LValue);

  if FSysCtlByName(AName, @LValue, @LLen, nil, 0) = 0 then
    Result := LValue >= 1
  else
    Result := False;
end;

class function TDarwinSysCtl.HasFeature(const AModernName: PAnsiChar;
  const ALegacyName: PAnsiChar): Boolean;
begin
  if not System.Assigned(FSysCtlByName) then
  begin
    Result := False;
    Exit;
  end;

  // Try the modern FEAT_* key first (available on macOS 12+)
  Result := QueryKey(AModernName);

  // If the modern key was not found or returned 0, try the legacy key
  if (not Result) and (ALegacyName <> nil) then
    Result := QueryKey(ALegacyName);
end;

initialization
  TDarwinSysCtl.ResolveDynamicImports;

{$IFEND} // CRYPTOLIB_MACOS OR CRYPTOLIB_IOS
{$IFEND} // CRYPTOLIB_ARM

end.
