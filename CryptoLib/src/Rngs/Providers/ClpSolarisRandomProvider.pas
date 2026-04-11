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

unit ClpSolarisRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_SOLARIS}
uses
  SysUtils,
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  ClpGetRandomReader,
{$ENDIF}
  ClpCryptoLibTypes,
  ClpBaseRandomProvider;

resourcestring
  SSolarisGetRandomError =
    'An Error Occurred while generating random data using getRandom API';

  /// <summary>
  /// Solaris OS random source provider.
  /// Implements Solaris getrandom and /dev/urandom fallback
  /// </summary>
type
  TSolarisRandomProvider = class sealed(TBaseRandomProvider)

  strict private
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  var
    FHasGetRandom: Boolean;
    FGetRandom: TGetRandomFunc;

{$ENDIF}
    function GenRandomBytesSolaris(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray); override;
    function GetIsAvailable: Boolean; override;
    function GetName: String; override;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_SOLARIS}
uses
  ClpDevRandomReader;

const
  // Oracle getrandom(2): EINVAL if GRND_RANDOM is not set and bufsize > 133120.
  // https://docs.oracle.com/cd/E88353_01/html/E37841/getrandom-2.html
  GetRandomMaxChunk = 133120;
  // https://docs.oracle.com/cd/E88353_01/html/E37851/urandom-4d.html
  DevRandomMaxChunk = 128 * 1040;

{ TSolarisRandomProvider }

constructor TSolarisRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  FHasGetRandom := TGetRandomReader.TryResolve(FGetRandom);
{$ENDIF}
end;

function TSolarisRandomProvider.GenRandomBytesSolaris(ALen: Int32;
  AData: PByte): Int32;
begin
{$IFDEF CRYPTOLIB_HAS_GETRANDOM}
  if FHasGetRandom then
  begin
    Result := TGetRandomReader.Read(FGetRandom, GetRandomMaxChunk, GRND_NONBLOCK,
      ALen, AData, True);
  end
  else
  begin
    Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
  end;
{$ELSE}
  Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
{$ENDIF}
end;

procedure TSolarisRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesSolaris(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SSolarisGetRandomError);
  end;
end;

function TSolarisRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TSolarisRandomProvider.GetName: String;
begin
  Result := 'Solaris';
end;

{$ENDIF}

end.
