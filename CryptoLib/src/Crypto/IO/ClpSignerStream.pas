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

unit ClpSignerStream;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpStreams,
  ClpStreamUtilities,
  ClpISigner,
  ClpCryptoLibTypes;

resourcestring
  SSizeNotSupported = 'size not supported';
  SSeekNotSupported = 'seek not supported';
  SSetSizeNotSupported = 'set size not supported';

type
  /// <summary>
  /// A stream that updates signers on read and write operations.
  /// </summary>
  TSignerStream = class sealed(TBaseStream)
  strict private
    FStream: TStream;
    FReadSigner: ISigner;
    FWriteSigner: ISigner;
    FLeaveOpen: Boolean;

  protected
    function GetSize: Int64; override;
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    constructor Create(const AStream: TStream; const AReadSigner, AWriteSigner: ISigner;
      ALeaveOpen: Boolean);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
    procedure SetSize(const ANewSize: Int64); override;

    function ReadByte: Int32; override;
    procedure WriteByte(AValue: Byte); override;

    procedure Flush; override;

    destructor Destroy; override;

    property Stream: TStream read FStream;
    property ReadSigner: ISigner read FReadSigner;
    property WriteSigner: ISigner read FWriteSigner;
  end;

implementation

{ TSignerStream }

constructor TSignerStream.Create(const AStream: TStream; const AReadSigner,
  AWriteSigner: ISigner; ALeaveOpen: Boolean);
begin
  inherited Create();
  FStream := AStream;
  FReadSigner := AReadSigner;
  FWriteSigner := AWriteSigner;
  FLeaveOpen := ALeaveOpen;
end;

function TSignerStream.GetSize: Int64;
begin
  raise ENotSupportedCryptoLibException.CreateRes(@SSizeNotSupported);
end;

function TSignerStream.GetCanRead: Boolean;
begin
  Result := FStream.CanRead;
end;

function TSignerStream.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TSignerStream.GetCanWrite: Boolean;
begin
  Result := FStream.CanWrite;
end;

function TSignerStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  Result := FStream.Read(ABuffer, ACount);

  if (FReadSigner <> nil) and (Result > 0) then
  begin
    System.SetLength(LBuffer, Result);
    System.Move(ABuffer, LBuffer[0], Result);
    FReadSigner.BlockUpdate(LBuffer, 0, Result);
  end;
end;

function TSignerStream.ReadByte: Int32;
begin
  Result := FStream.ReadByte();

  if (FReadSigner <> nil) and (Result >= 0) then
    FReadSigner.Update(Byte(Result));
end;

function TSignerStream.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  if (FWriteSigner <> nil) and (ACount > 0) then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    FWriteSigner.BlockUpdate(LBuffer, 0, ACount);
  end;

  Result := FStream.Write(ABuffer, ACount);
end;

procedure TSignerStream.WriteByte(AValue: Byte);
begin
  if FWriteSigner <> nil then
    FWriteSigner.Update(AValue);

  FStream.WriteByte(AValue);
end;

function TSignerStream.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  raise ENotSupportedCryptoLibException.CreateRes(@SSeekNotSupported);
end;

procedure TSignerStream.SetSize(const ANewSize: Int64);
begin
  raise ENotSupportedCryptoLibException.CreateRes(@SSetSizeNotSupported);
end;

procedure TSignerStream.Flush;
begin
  FStream.Flush();
end;

destructor TSignerStream.Destroy;
begin
  if not FLeaveOpen then
    FStream.Free;
  inherited Destroy;
end;

end.
