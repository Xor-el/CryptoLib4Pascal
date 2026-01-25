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

unit ClpOSRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SyncObjs,
  ClpIRandomSourceProvider
{$IFDEF CRYPTOLIB_MSWINDOWS}
  , ClpWindowsRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_APPLE}
  , ClpAppleRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_LINUX}
  , ClpLinuxRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_SOLARIS}
  , ClpSolarisRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_GENERIC_BSD}
  , ClpGenericBSDRandomProvider
{$ENDIF}
{$IFDEF CRYPTOLIB_UNIX}
  , ClpUnixRandomProvider
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
{$ELSEIF DEFINED(CRYPTOLIB_APPLE)}
  Result := TAppleRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_LINUX)}
  Result := TLinuxRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_SOLARIS)}
  Result := TSolarisRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_GENERIC_BSD)}
  Result := TGenericBSDRandomProvider.Create();
{$ELSEIF DEFINED(CRYPTOLIB_UNIX)}
  Result := TUnixRandomProvider.Create();
{$ELSE}
{$MESSAGE ERROR 'UNSUPPORTED TARGET.'}
  Result := nil;
{$IFEND}
end;

class function TOSRandomProvider.GetInstance: IRandomSourceProvider;
begin
  if FInstance = nil then
  begin
    FLock.Enter;
    try
      if FInstance = nil then
      begin
        FInstance := CreateProvider();
      end;
    finally
      FLock.Leave;
    end;
  end;
  result := FInstance;
end;

class procedure TOSRandomProvider.Boot;
begin
  if FLock = nil then
  begin
    FLock := TCriticalSection.Create;
  end;
  // Trigger instance creation
  GetInstance;
end;

end.
