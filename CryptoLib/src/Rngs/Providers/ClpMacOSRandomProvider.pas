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

unit ClpMacOSRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_MACOS}
uses
{$IFDEF FPC}
  CocoaAll,
{$ELSE}
  Macapi.AppKit,
{$ENDIF}
  SysUtils,
{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  ClpSecRandomCopyBytesReader,
{$ENDIF}
  ClpCryptoLibTypes,
  ClpBaseRandomProvider;

resourcestring
  SMacOSRandomError =
    'An Error Occurred while generating random data using macOS random APIs.';

  /// <summary>
  /// macOS random source provider.
  /// Implements SecRandomCopyBytes on OS X 10.7+ when available, else /dev/urandom.
  /// </summary>
type
  TMacOSRandomProvider = class sealed(TBaseRandomProvider)

  strict private

{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  var
    FHasSecRandomCopyBytes: Boolean;
    FSecRandomCopyBytes: TSecRandomCopyBytesFunc;
    FSecRandomDefault: SecRandomRef;

{$ENDIF}
    function GenRandomBytesMacOS(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray); override;
    function GetIsAvailable: Boolean; override;
    function GetName: String; override;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_MACOS}
uses
  ClpDevRandomReader;

const
  // https://man7.org/linux/man-pages/man4/random.4.html
  DevRandomMaxChunk = 32 * 1024 * 1024;

{ TMacOSRandomProvider }

constructor TMacOSRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  FHasSecRandomCopyBytes := TSecRandomCopyBytesReader.TryResolve(
    FSecRandomCopyBytes, FSecRandomDefault);
{$ENDIF}
end;

function TMacOSRandomProvider.GenRandomBytesMacOS(ALen: Int32;
  AData: PByte): Int32;
var
  LUseSec: Boolean;
begin
{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  LUseSec := FHasSecRandomCopyBytes;
  if NSAppKitVersionNumber < NSAppKitVersionNumber10_7 then
  begin
    LUseSec := False;
  end;
  if LUseSec then
  begin
    Result := TSecRandomCopyBytesReader.Read(FSecRandomCopyBytes,
      FSecRandomDefault, ALen, AData);
  end
  else
  begin
    Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
  end;
{$ELSE}
  Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
{$ENDIF}
end;

procedure TMacOSRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesMacOS(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SMacOSRandomError);
  end;
end;

function TMacOSRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TMacOSRandomProvider.GetName: String;
begin
  Result := 'macOS';
end;

{$ENDIF}

end.
