{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpOSRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpIRandomSourceProvider
{$IFDEF CRYPTOLIB_MSWINDOWS}
  , ClpWindowsRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_IOS}
  , ClpIOSRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_MACOS}
  , ClpMacOSRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_ANDROID}
  , ClpAndroidRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_LINUX}
  , ClpLinuxRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_SOLARIS}
  , ClpSolarisRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_BSD}
  , ClpBsdRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_UNIX}
  , ClpUnixLikeRandomProvider
{$ENDIF}
  ;

type
  /// <summary>
  /// Factory class for OS-specific random source providers.
  /// Provides a singleton instance of the appropriate platform-specific implementation.
  /// </summary>
  TOSRandomProvider = class sealed(TObject)

  strict private
  class var
    FInstance: IRandomSourceProvider;
    FLock: TCriticalSection;
    FIsBooted: Boolean;

    class function GetInstance: IRandomSourceProvider; static;
    class function CreateProvider: IRandomSourceProvider; static;

  public
    class property Instance: IRandomSourceProvider read GetInstance;

    class procedure Boot(); static;

    class constructor Create();

    class destructor Destroy();

  end;

implementation

{ TOSRandomProvider }

class constructor TOSRandomProvider.Create();
begin
  Boot();
end;

class destructor TOSRandomProvider.Destroy();
begin
  FLock.Free;
  FInstance := nil;
end;

class function TOSRandomProvider.CreateProvider: IRandomSourceProvider;
begin
{$IF DEFINED(CRYPTOLIB_MSWINDOWS)}
  Result := TWindowsRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_IOS)}
  Result := TIOSRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_MACOS)}
  Result := TMacOSRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_ANDROID)}
  Result := TAndroidRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_LINUX)}
  Result := TLinuxRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_SOLARIS)}
  Result := TSolarisRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_BSD)}
  Result := TBsdRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_UNIX)}
  Result := TUnixLikeRandomProvider.Create();
{$ELSE}
{$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
  Result := nil;
{$IFEND}
end;

class function TOSRandomProvider.GetInstance: IRandomSourceProvider;
begin
  Result := FInstance;
end;

class procedure TOSRandomProvider.Boot;
begin
  if not FIsBooted then
  begin
    FLock := TCriticalSection.Create;
    FLock.Enter;
    try
      FInstance := CreateProvider();
    finally
      FLock.Leave;
    end;
    FIsBooted := True;
  end;
end;

end.
