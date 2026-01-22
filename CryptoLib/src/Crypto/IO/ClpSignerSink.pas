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

unit ClpSignerSink;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpISigner,
  ClpStreams,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A stream that writes data to an ISigner for signature calculation.
  /// </summary>
  TSignerSink = class sealed(TBaseStream)

  strict private
  var
    FSigner: ISigner;

  protected
    function GetSize: Int64; override;
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    constructor Create(const ASigner: ISigner);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
    procedure SetSize(const ANewSize: Int64); override;

    property Signer: ISigner read FSigner;
  end;

implementation

{ TSignerSink }

constructor TSignerSink.Create(const ASigner: ISigner);
begin
  inherited Create();
  if ASigner = nil then
    raise EArgumentNilCryptoLibException.Create('signer');
  FSigner := ASigner;
end;

function TSignerSink.GetSize: Int64;
begin
  raise ENotSupportedCryptoLibException.Create('GetSize not supported');
end;

function TSignerSink.GetCanRead: Boolean;
begin
  Result := False;
end;

function TSignerSink.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TSignerSink.GetCanWrite: Boolean;
begin
  Result := True;
end;

function TSignerSink.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  raise ENotSupportedCryptoLibException.Create('Read not supported');
end;

function TSignerSink.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
  LOffset: Int32;
begin
  if ACount > 0 then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    LOffset := 0;
    FSigner.BlockUpdate(LBuffer, LOffset, ACount);
  end;
  Result := ACount;
end;

function TSignerSink.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  raise ENotSupportedCryptoLibException.Create('Seek not supported');
end;

procedure TSignerSink.SetSize(const ANewSize: Int64);
begin
  raise ENotSupportedCryptoLibException.Create('SetSize not supported');
end;

end.
