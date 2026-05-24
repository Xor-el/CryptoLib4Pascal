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

unit ClpMacStream;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpStreams,
  ClpStreamUtilities,
  ClpIMac,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A stream that updates MACs on read and write operations.
  /// </summary>
  TMacStream = class sealed(TBaseStream)
  strict private
    FStream: TStream;
    FReadMac: IMac;
    FWriteMac: IMac;
    FLeaveOpen: Boolean;

  protected
    function GetSize: Int64; override;
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    constructor Create(const AStream: TStream; const AReadMac, AWriteMac: IMac;
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
    property ReadMac: IMac read FReadMac;
    property WriteMac: IMac read FWriteMac;
  end;

implementation

{ TMacStream }

constructor TMacStream.Create(const AStream: TStream; const AReadMac, AWriteMac: IMac;
  ALeaveOpen: Boolean);
begin
  inherited Create();
  FStream := AStream;
  FReadMac := AReadMac;
  FWriteMac := AWriteMac;
  FLeaveOpen := ALeaveOpen;
end;

function TMacStream.GetSize: Int64;
begin
  raise ENotSupportedCryptoLibException.Create('GetSize not supported');
end;

function TMacStream.GetCanRead: Boolean;
begin
  Result := FStream.CanRead;
end;

function TMacStream.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TMacStream.GetCanWrite: Boolean;
begin
  Result := FStream.CanWrite;
end;

function TMacStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  Result := FStream.Read(ABuffer, ACount);

  if (FReadMac <> nil) and (Result > 0) then
  begin
    System.SetLength(LBuffer, Result);
    System.Move(ABuffer, LBuffer[0], Result);
    FReadMac.BlockUpdate(LBuffer, 0, Result);
  end;
end;

function TMacStream.ReadByte: Int32;
begin
  Result := FStream.ReadByte();

  if (FReadMac <> nil) and (Result >= 0) then
    FReadMac.Update(Byte(Result));
end;

function TMacStream.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: TCryptoLibByteArray;
begin
  if (FWriteMac <> nil) and (ACount > 0) then
  begin
    System.SetLength(LBuffer, ACount);
    System.Move(ABuffer, LBuffer[0], ACount);
    FWriteMac.BlockUpdate(LBuffer, 0, ACount);
  end;

  Result := FStream.Write(ABuffer, ACount);
end;

procedure TMacStream.WriteByte(AValue: Byte);
begin
  if FWriteMac <> nil then
    FWriteMac.Update(AValue);

  FStream.WriteByte(AValue);
end;

function TMacStream.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
begin
  raise ENotSupportedCryptoLibException.Create('Seek not supported');
end;

procedure TMacStream.SetSize(const ANewSize: Int64);
begin
  raise ENotSupportedCryptoLibException.Create('SetSize not supported');
end;

procedure TMacStream.Flush;
begin
  FStream.Flush();
end;

destructor TMacStream.Destroy;
begin
  if not FLeaveOpen then
    FStream.Free;
  inherited Destroy;
end;

end.
