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

unit ClpIOSRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_IOS}
uses
  SysUtils,
{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  ClpSecRandomCopyBytesReader,
{$ENDIF}
  ClpCryptoLibTypes,
  ClpBaseRandomProvider;

resourcestring
  SiOSRandomError =
    'An Error Occurred while generating random data using iOS random APIs.';

  /// <summary>
  /// iOS random source provider.
  /// Implements SecRandomCopyBytes when available, else /dev/urandom.
  /// </summary>
type
  TIOSRandomProvider = class sealed(TBaseRandomProvider)

  strict private
{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  var
    FHasSecRandomCopyBytes: Boolean;
    FSecRandomCopyBytes: TSecRandomCopyBytesFunc;
    FSecRandomDefault: SecRandomRef;

{$ENDIF}
    function GenRandomBytesIOS(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray); override;
    function GetIsAvailable: Boolean; override;
    function GetName: String; override;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_IOS}
uses
  ClpDevRandomReader;

const
  // https://man7.org/linux/man-pages/man4/random.4.html
  DevRandomMaxChunk = 32 * 1024 * 1024;

{ TIOSRandomProvider }

constructor TIOSRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  FHasSecRandomCopyBytes := TSecRandomCopyBytesReader.TryResolve(
    FSecRandomCopyBytes, FSecRandomDefault);
{$ENDIF}
end;

function TIOSRandomProvider.GenRandomBytesIOS(ALen: Int32;
  AData: PByte): Int32;
begin
{$IFDEF CRYPTOLIB_HAS_SECRANDOMCOPYBYTES}
  if FHasSecRandomCopyBytes then
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

procedure TIOSRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesIOS(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SiOSRandomError);
  end;
end;

function TIOSRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TIOSRandomProvider.GetName: String;
begin
  Result := 'iOS';
end;

{$ENDIF}

end.
