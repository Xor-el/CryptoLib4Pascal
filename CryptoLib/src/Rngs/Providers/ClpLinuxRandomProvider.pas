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

unit ClpLinuxRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_LINUX}
uses
  SysUtils,
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  ClpGetRandomReader,
{$ENDIF}
  ClpCryptoLibTypes,
  ClpBaseRandomProvider;

resourcestring
  SLinuxGetRandomError =
    'An Error Occurred while generating random data using getRandom API';

  /// <summary>
  /// Linux OS random source provider.
  /// Implements Linux getrandom and /dev/urandom fallback
  /// </summary>
type
  TLinuxRandomProvider = class sealed(TBaseRandomProvider)

  strict private
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  var
    FHasGetRandom: Boolean;
    FGetRandom: TGetRandomFunc;

{$ENDIF}
    function GenRandomBytesLinux(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray); override;
    function GetIsAvailable: Boolean; override;
    function GetName: String; override;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_LINUX}
uses
  ClpDevRandomReader;

const
  // https://man7.org/linux/man-pages/man2/getrandom.2.html
  GetRandomMaxChunk = (32 * 1024 * 1024) - 1;
  // https://man7.org/linux/man-pages/man4/random.4.html
  DevRandomMaxChunk = 32 * 1024 * 1024;

{ TLinuxRandomProvider }

constructor TLinuxRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  FHasGetRandom := TGetRandomReader.TryResolve(FGetRandom);
{$ENDIF}
end;

function TLinuxRandomProvider.GenRandomBytesLinux(ALen: Int32;
  AData: PByte): Int32;
begin
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  if FHasGetRandom then
  begin
    Result := TGetRandomReader.Read(FGetRandom, GetRandomMaxChunk, GRND_NONBLOCK,
      ALen, AData, False);
  end
  else
  begin
    Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
  end;
{$ELSE}
  Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
{$ENDIF}
end;

procedure TLinuxRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesLinux(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SLinuxGetRandomError);
  end;
end;

function TLinuxRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TLinuxRandomProvider.GetName: String;
begin
  Result := 'Linux';
end;

{$ENDIF}

end.
