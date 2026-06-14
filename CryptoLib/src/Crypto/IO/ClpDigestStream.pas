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

unit ClpDigestStream;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpStreams,
  ClpStreamUtilities,
  ClpIDigest,
  ClpCryptoLibTypes;

resourcestring
  SSizeNotSupported = 'size not supported';
  SSeekNotSupported = 'seek not supported';
  SSetSizeNotSupported = 'set size not supported';

type
  /// <summary>
  /// A stream that updates digests on read and write operations.
  /// </summary>
  TDigestStream = class sealed(TBaseStream)
  strict private
    FStream: TStream;
    FReadDigest: IDigest;
    FWriteDigest: IDigest;
    FLeaveOpen: Boolean;

  protected
    function GetSize: Int64; override;
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    constructor Create(const AStream: TStream; const AReadDigest, AWriteDigest: IDigest;
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
    property ReadDigest: IDigest read FReadDigest;
    property WriteDigest: IDigest read FWriteDigest;
  end;

implementation

{ TDigestStream }

constructor TDigestStream.Create(const AStream: TStream; const AReadDigest,
  AWriteDigest: IDigest; ALeaveOpen: Boolean);
begin
  inherited Create();
  FStream := AStream;
  FReadDigest := AReadDigest;
  FWriteDigest := AWriteDigest;
  FLeaveOpen := ALeaveOpen;
end;

function TDigestStream.GetSize: Int64;
begin
  raise ENotSupportedCryptoLibException.CreateRes(@SSizeNotSupported);
end;

function TDigestStream.GetCanRead: Boolean;
begin
  Result := FStream.CanRead;
end;

function TDigestStream.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TDigestStream.GetCanWrite: Boolean;
begin
  Result := FStream.CanWrite;
end;

function TDigestStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  Result := FStream.Read(ABuffer, ACount);

  if (FReadDigest <> nil) and (Result > 0) then
  begin
    System.SetLength(LBuffer, Result);
    System.Move(ABuffer, LBuffer[0], Result);
    FReadDigest.BlockUpdate(LBuffer, 0, Result);
  end;
end;

function TDigestStream.ReadByte: Int32;
begin
  Result := FStream.ReadByte();

  if (FReadDigest <> nil) and (Result >= 0) then
    FReadDigest.Update(Byte(Result));
end;

function TDigestStream.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  if (FWriteDigest <> nil) and (ACount > 0) then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    FWriteDigest.BlockUpdate(LBuffer, 0, ACount);
  end;

  Result := FStream.Write(ABuffer, ACount);
end;

procedure TDigestStream.WriteByte(AValue: Byte);
begin
  if FWriteDigest <> nil then
    FWriteDigest.Update(AValue);

  FStream.WriteByte(AValue);
end;

function TDigestStream.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  raise ENotSupportedCryptoLibException.CreateRes(@SSeekNotSupported);
end;

procedure TDigestStream.SetSize(const ANewSize: Int64);
begin
  raise ENotSupportedCryptoLibException.CreateRes(@SSetSizeNotSupported);
end;

procedure TDigestStream.Flush;
begin
  FStream.Flush();
end;

destructor TDigestStream.Destroy;
begin
  if not FLeaveOpen then
    FStream.Free;
  inherited Destroy;
end;

end.
