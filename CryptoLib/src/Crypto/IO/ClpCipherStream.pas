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

unit ClpCipherStream;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  Math,
  ClpStreams,
  ClpIBufferedCipher,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A stream that applies cipher transformations on read/write operations.
  /// </summary>
  TCipherStream = class sealed(TBaseStream)
  strict private
    FStream: TStream;
    FReadCipher: IBufferedCipher;
    FWriteCipher: IBufferedCipher;
    FReadBuf: TCryptoLibByteArray;
    FReadBufPos: Int32;
    FReadEnded: Boolean;
    FLeaveOpen: Boolean;

    function FillInBuf: Boolean;
    function ReadAndProcessBlock: TCryptoLibByteArray;

  protected
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    constructor Create(const AStream: TStream; const AReadCipher: IBufferedCipher;
      const AWriteCipher: IBufferedCipher; ALeaveOpen: Boolean);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;

    function ReadByte: Int32; override;
    procedure WriteByte(AValue: Byte); override;

    procedure Flush; override;

    destructor Destroy; override;

    property ReadCipher: IBufferedCipher read FReadCipher;
    property WriteCipher: IBufferedCipher read FWriteCipher;
  end;

implementation

{ TCipherStream }

constructor TCipherStream.Create(const AStream: TStream; const AReadCipher: IBufferedCipher;
  const AWriteCipher: IBufferedCipher; ALeaveOpen: Boolean);
begin
  inherited Create();
  FStream := AStream;
  FLeaveOpen := ALeaveOpen;

  if AReadCipher <> nil then
  begin
    FReadCipher := AReadCipher;
    FReadBuf := nil;
  end;

  if AWriteCipher <> nil then
  begin
    FWriteCipher := AWriteCipher;
  end;
end;

function TCipherStream.GetCanRead: Boolean;
begin
  Result := FStream.CanRead;
end;

function TCipherStream.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TCipherStream.GetCanWrite: Boolean;
begin
  Result := FStream.CanWrite;
end;

function TCipherStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LNum, LNumToCopy: Int32;
  LDest: PByte;
begin
  if FReadCipher = nil then
  begin
    Result := FStream.Read(ABuffer, ACount);
    Exit;
  end;

  LDest := PByte(@ABuffer);
  LNum := 0;
  while LNum < ACount do
  begin
    if (FReadBuf = nil) or (FReadBufPos >= System.Length(FReadBuf)) then
    begin
      if not FillInBuf() then
        Break;
    end;

    LNumToCopy := Min(ACount - LNum, System.Length(FReadBuf) - FReadBufPos);
    System.Move(FReadBuf[FReadBufPos], LDest^, LNumToCopy);
    Inc(FReadBufPos, LNumToCopy);
    Inc(LDest, LNumToCopy);
    Inc(LNum, LNumToCopy);
  end;

  Result := LNum;
end;

function TCipherStream.ReadByte: Int32;
begin
  if FReadCipher = nil then
  begin
    Result := FStream.ReadByte();
    Exit;
  end;

  if (FReadBuf = nil) or (FReadBufPos >= System.Length(FReadBuf)) then
  begin
    if not FillInBuf() then
    begin
      Result := -1;
      Exit;
    end;
  end;

  Result := Int32(FReadBuf[FReadBufPos]);
  Inc(FReadBufPos);
end;

function TCipherStream.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LOutputSize, LLength: Int32;
  LOutput: TCryptoLibByteArray;
  LSrc: PByte;
  LInput: TCryptoLibByteArray;
begin
  if FWriteCipher = nil then
  begin
    Result := FStream.Write(ABuffer, ACount);
    Exit;
  end;

  if ACount > 0 then
  begin
    LOutputSize := FWriteCipher.GetUpdateOutputSize(ACount);
    System.SetLength(LOutput, LOutputSize);

    LSrc := PByte(@ABuffer);
    System.SetLength(LInput, ACount);
    System.Move(LSrc^, LInput[0], ACount);

    LLength := FWriteCipher.ProcessBytes(LInput, 0, ACount, LOutput, 0);
    if LLength > 0 then
    begin
      try
        FStream.Write(LOutput[0], LLength);
      finally
        TArrayUtilities.Fill<Byte>(LOutput, 0, System.Length(LOutput), Byte(0));
      end;
    end;
  end;

  Result := ACount;
end;

procedure TCipherStream.WriteByte(AValue: Byte);
var
  LOutput: TCryptoLibByteArray;
begin
  if FWriteCipher = nil then
  begin
    FStream.WriteByte(AValue);
    Exit;
  end;

  LOutput := FWriteCipher.ProcessByte(AValue);
  if LOutput <> nil then
  begin
    try
      FStream.Write(LOutput[0], System.Length(LOutput));
    finally
      TArrayUtilities.Fill<Byte>(LOutput, 0, System.Length(LOutput), Byte(0));
    end;
  end;
end;

procedure TCipherStream.Flush;
begin
  FStream.Flush();
end;

destructor TCipherStream.Destroy;
var
  LOutputSize, LLen: Int32;
  LOutput: TCryptoLibByteArray;
begin
  if FWriteCipher <> nil then
  begin
    LOutputSize := FWriteCipher.GetOutputSize(0);
    System.SetLength(LOutput, LOutputSize);
    LLen := FWriteCipher.DoFinal(LOutput, 0);
    if LLen > 0 then
      FStream.Write(LOutput[0], LLen);
    TArrayUtilities.Fill<Byte>(LOutput, 0, System.Length(LOutput), Byte(0));
  end;
  if not FLeaveOpen then
    FStream.Free;
  inherited Destroy;
end;

function TCipherStream.FillInBuf: Boolean;
begin
  if FReadEnded then
  begin
    Result := False;
    Exit;
  end;

  FReadBufPos := 0;

  repeat
    FReadBuf := ReadAndProcessBlock();
  until FReadEnded or (FReadBuf <> nil);

  Result := FReadBuf <> nil;
end;

function TCipherStream.ReadAndProcessBlock: TCryptoLibByteArray;
var
  LBlockSize, LReadSize, LNumRead, LCount: Int32;
  LBlock, LBytes: TCryptoLibByteArray;
begin
  LBlockSize := FReadCipher.GetBlockSize();
  if LBlockSize = 0 then
    LReadSize := 256
  else
    LReadSize := LBlockSize;

  System.SetLength(LBlock, LReadSize);
  LNumRead := 0;
  repeat
    LCount := FStream.Read(LBlock[LNumRead], System.Length(LBlock) - LNumRead);
    if LCount < 1 then
    begin
      FReadEnded := True;
      Break;
    end;
    Inc(LNumRead, LCount);
  until LNumRead >= System.Length(LBlock);

  if FReadEnded then
    LBytes := FReadCipher.DoFinal(LBlock, 0, LNumRead)
  else
    LBytes := FReadCipher.ProcessBytes(LBlock);

  if (LBytes <> nil) and (System.Length(LBytes) = 0) then
    LBytes := nil;

  Result := LBytes;
end;

end.
