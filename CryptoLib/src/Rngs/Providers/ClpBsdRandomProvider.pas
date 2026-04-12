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

unit ClpBsdRandomProvider;

{$I ..\..\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_BSD}
uses
  SysUtils,
{$IFDEF CRYPTOLIB_HAS_ARC4RANDOM_BUF}
  ClpArc4RandomBufReader,
{$ENDIF}
  ClpCryptoLibTypes,
  ClpBaseRandomProvider;

resourcestring
  SArc4RandomBufGenerationError =
    'An Error Occurred while generating random data from the OS random source.';

  /// <summary>
  /// Bsd OS random source provider.
  /// Implements Bsd variants using arc4random_buf when available, else /dev/urandom.
  /// </summary>
type
  TBsdRandomProvider = class sealed(TBaseRandomProvider)

  strict private
{$IFDEF CRYPTOLIB_HAS_ARC4RANDOM_BUF}
  var
    FHasArc4RandomBuf: Boolean;
    FArc4RandomBuf: TArc4RandomBufProc;

{$ENDIF}
    function GenRandomBytesBsd(ALen: Int32; AData: PByte): Int32;

  public
    constructor Create();

    procedure GetBytes(const AData: TCryptoLibByteArray); override;
    function GetIsAvailable: Boolean; override;
    function GetName: String; override;

  end;

{$ENDIF}

implementation

{$IFDEF CRYPTOLIB_BSD}
uses
  ClpDevRandomReader;

const
  // https://man7.org/linux/man-pages/man4/random.4.html
  DevRandomMaxChunk = 32 * 1024 * 1024;

{ TBsdRandomProvider }

constructor TBsdRandomProvider.Create;
begin
  inherited Create();
{$IFDEF CRYPTOLIB_HAS_ARC4RANDOM_BUF}
  FHasArc4RandomBuf := TArc4RandomBufReader.TryResolve(FArc4RandomBuf);
{$ENDIF}
end;

function TBsdRandomProvider.GenRandomBytesBsd(ALen: Int32;
  AData: PByte): Int32;
begin
{$IFDEF CRYPTOLIB_HAS_ARC4RANDOM_BUF}
  if FHasArc4RandomBuf then
  begin
    Result := TArc4RandomBufReader.Read(FArc4RandomBuf, ALen, AData);
  end
  else
  begin
    Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
  end;
{$ELSE}
  Result := TDevRandomReader.Read(ALen, AData, DevRandomMaxChunk);
{$ENDIF}
end;

procedure TBsdRandomProvider.GetBytes(const AData: TCryptoLibByteArray);
var
  LCount: Int32;
begin
  LCount := System.Length(AData);

  if LCount <= 0 then
  begin
    Exit;
  end;

  if GenRandomBytesBsd(LCount, PByte(AData)) <> 0 then
  begin
    raise EOSRandomCryptoLibException.CreateRes(@SArc4RandomBufGenerationError);
  end;
end;

function TBsdRandomProvider.GetIsAvailable: Boolean;
begin
  Result := True;
end;

function TBsdRandomProvider.GetName: String;
begin
  Result := 'Bsd';
end;

{$ENDIF}

end.
