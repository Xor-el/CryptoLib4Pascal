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

unit ClpDigestSink;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIDigest,
  ClpStreams,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A stream that writes data to an IDigest for digest calculation.
  /// </summary>
  TDigestSink = class sealed(TBaseStream)

  strict private
  var
    FDigest: IDigest;

  protected
    function GetSize: Int64; override;
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    constructor Create(const ADigest: IDigest);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
    procedure SetSize(const ANewSize: Int64); override;

    property Digest: IDigest read FDigest;
  end;

implementation

{ TDigestSink }

constructor TDigestSink.Create(const ADigest: IDigest);
begin
  inherited Create();
  if ADigest = nil then
    raise EArgumentNilCryptoLibException.Create('digest');
  FDigest := ADigest;
end;

function TDigestSink.GetSize: Int64;
begin
  raise ENotSupportedCryptoLibException.Create('GetSize not supported');
end;

function TDigestSink.GetCanRead: Boolean;
begin
  Result := False;
end;

function TDigestSink.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TDigestSink.GetCanWrite: Boolean;
begin
  Result := True;
end;

function TDigestSink.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  raise ENotSupportedCryptoLibException.Create('Read not supported');
end;

function TDigestSink.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
  LOffset: Int32;
begin
  if ACount > 0 then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    LOffset := 0;
    FDigest.BlockUpdate(LBuffer, LOffset, ACount);
  end;
  Result := ACount;
end;

function TDigestSink.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  raise ENotSupportedCryptoLibException.Create('Seek not supported');
end;

procedure TDigestSink.SetSize(const ANewSize: Int64);
begin
  raise ENotSupportedCryptoLibException.Create('SetSize not supported');
end;

end.
