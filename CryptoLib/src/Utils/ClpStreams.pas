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

unit ClpStreams;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Class helper for TStream to add ReadByte, WriteByte, Flush, and capability properties.
  /// </summary>
  TStreamHelper = class helper for TStream
  public
    function ReadByte(): Int32;
    procedure WriteByte(AValue: Byte);
    procedure Flush;

    function GetCanRead: Boolean;
    function GetCanSeek: Boolean;
    function GetCanWrite: Boolean;

    property CanRead: Boolean read GetCanRead;
    property CanSeek: Boolean read GetCanSeek;
    property CanWrite: Boolean read GetCanWrite;
  end;

type
  /// <summary>
  /// Base abstract class for streams.
  /// </summary>
  TBaseStream = class abstract(TStream)

  strict private
    FCanRead: Boolean;
    FCanWrite: Boolean;
    FCanSeek: Boolean;

  protected
    function GetCanRead: Boolean; virtual;
    function GetCanSeek: Boolean; virtual;
    function GetCanWrite: Boolean; virtual;

  public
    constructor Create();

    function ReadByte: Int32; virtual;
    procedure WriteByte(AValue: Byte); virtual;
    procedure Flush; virtual;

    property CanRead: Boolean read GetCanRead;
    property CanSeek: Boolean read GetCanSeek;
    property CanWrite: Boolean read GetCanWrite;

  end;

type
  /// <summary>
  /// Stream that wraps a byte array buffer directly at a specific offset with fixed size.
  /// Supports both read and write operations. Similar to C# MemoryStream(buffer, index, count, writable: true/false).
  /// </summary>
  TFixedBufferStream = class sealed(TBaseStream)
  strict private
    FWritable: Boolean;
    FBuffer: TCryptoLibByteArray;
    FBufferIndex: Int32;
    FBufferCount: Int32;
    FPosition: Int64;

    procedure SetPosition(const AValue: Int64);

  protected
    function GetSize: Int64; override;
    function GetCanWrite: Boolean; virtual;

  public
    constructor Create(const ABuffer: TCryptoLibByteArray; AIndex, ACount: Int32); overload;
    constructor Create(const ABuffer: TCryptoLibByteArray; AIndex, ACount: Int32; AWritable: Boolean); overload;

    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;

    function ReadByte: Int32; override;
    procedure WriteByte(AValue: Byte); override;
    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;

    property Size: Int64 read GetSize;
    property Position: Int64 read FPosition write SetPosition;
  end;

type
  /// <summary>
  /// Base abstract class for input-only streams.
  /// </summary>
  TBaseInputStream = class abstract(TBaseStream)

  protected
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; overload; {$IFDEF TSTREAM_HAS_VIRTUAL_READ_BYTES} override {$ELSE} virtual {$ENDIF};

    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; overload; {$IFDEF TSTREAM_HAS_VIRTUAL_WRITE_BYTES} override {$ELSE} virtual {$ENDIF};

    procedure WriteByte(AValue: Byte); override;

  end;

type
  /// <summary>
  /// Base abstract class for output-only streams.
  /// </summary>
  TBaseOutputStream = class abstract(TBaseStream)

  protected
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; overload; {$IFDEF TSTREAM_HAS_VIRTUAL_READ_BYTES} override {$ELSE} virtual {$ENDIF};

    function Write(const ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; overload; {$IFDEF TSTREAM_HAS_VIRTUAL_WRITE_BYTES} override {$ELSE} virtual {$ENDIF};

    function ReadByte: Int32; override;

  end;

type
  /// <summary>
  /// Filter stream that wraps another stream and delegates all operations.
  /// </summary>
  TFilterStream = class(TBaseStream)

  strict private

    function GetPosition: Int64;
    procedure SetPosition(const AValue: Int64);

  strict protected
  var
    FStream: TStream;

    function GetSize: Int64; override;
    function GetCanRead: Boolean; override;
    function GetCanSeek: Boolean; override;
    function GetCanWrite: Boolean; override;

  public
    constructor Create(const AStream: TStream);

    property Size: Int64 read GetSize;
    property Position: Int64 read GetPosition write SetPosition;

    function Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64; override;
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Write(const ABuffer; ACount: LongInt): LongInt; override;

    function ReadByte: Int32; virtual;
    procedure WriteByte(AValue: Byte); virtual;
    procedure Flush; virtual;

    destructor Destroy; override;

  end;

type
  /// <summary>
  /// Buffered filter stream that wraps a stream with buffering.
  /// </summary>
  TBufferedFilterStream = class sealed(TFilterStream)

  public
    constructor Create(const AStream: TStream); overload;
    constructor Create(const AStream: TStream; ABufferSize: Int32); overload;

  end;

type
  /// <summary>
  /// Limited input stream that limits the number of bytes that can be read.
  /// </summary>
  TLimitedInputStream = class sealed(TBaseInputStream)

  strict private
  var
    FLimit: Int64;
    FStream: TStream;

  public
    constructor Create(const AStream: TStream; ALimit: Int64);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;

    function ReadByte(): Int32; override;

    property CurrentLimit: Int64 read FLimit;

  end;

type
  /// <summary>
  /// Pushback stream that allows pushing back one byte.
  /// </summary>
  TPushbackStream = class(TFilterStream)

  strict private
  var
    FBuffer: Int32;

  public
    constructor Create(const AStream: TStream);

    function Read(var ABuffer; ACount: LongInt): LongInt; override;

    function ReadByte(): Int32; override;
    procedure UnRead(AByte: Int32); virtual;

  end;

type
  /// <summary>
  /// Utility class with static methods for stream operations.
  /// </summary>
  TStreamUtils = class sealed(TObject)

  strict private
  const
    MaxStackAlloc = Int32(4096);

  public
    class function DefaultBufferSize: Int32; static; inline;

    class procedure CopyTo(const ASource: TStream; const ADestination: TStream;
      ABufferSize: Int32); overload; static;
    class procedure CopyTo(const ASource: TStream;
      const ADestination: TStream); overload; static;

    class procedure Drain(const AInStr: TStream); static;

    class procedure PipeAll(const AInStr: TStream; const AOutStr: TStream;
      ABufferSize: Int32); overload; static;
    class procedure PipeAll(const AInStr: TStream;
      AOutStr: TStream); overload; static;

    class function PipeAllLimited(const AInStr: TStream; ALimit: Int64;
      const AOutStr: TStream; ABufferSize: Int32): Int64; overload; static;
    class function PipeAllLimited(const AInStr: TStream; ALimit: Int64;
      const AOutStr: TStream): Int64; overload; static;

    class function ReadAll(const AInStr: TStream): TCryptoLibByteArray; static;

    class function ReadAllLimited(const AInStr: TStream;
      ALimit: Int32): TCryptoLibByteArray; static;

    class function ReadFully(const AInStr: TStream;
      const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): Int32; overload; static;
    class function ReadFully(const AInStr: TStream;
      const ABuf: TCryptoLibByteArray): Int32; overload; static;

    class procedure ValidateBufferArguments(const ABuffer: TCryptoLibByteArray;
      AOffset, ACount: Int32); static;

    class function WriteBufTo(const ABuf: TMemoryStream;
      const AOutput: TCryptoLibByteArray; AOffset: Int32): Int32; static;

  end;

implementation

{ TStreamHelper }

function TStreamHelper.ReadByte(): Int32;
var
  LBuffer: TCryptoLibByteArray;
begin
  LBuffer := nil;
  if Self is TBaseStream then
    Result := (Self as TBaseStream).ReadByte
  else
  begin
    System.SetLength(LBuffer, 1);
    if Self.Read(LBuffer, 0, 1) = 0 then
      Result := -1
    else
      Result := Int32(LBuffer[0]);
  end;
end;

procedure TStreamHelper.WriteByte(AValue: Byte);
var
  LOneByteArray: TCryptoLibByteArray;
begin
  if Self is TBaseStream then
   (Self as TBaseStream).WriteByte(AValue)
  else
  begin
    System.SetLength(LOneByteArray, 1);
    LOneByteArray[0] := AValue;
    Self.Write(LOneByteArray, 0, 1);
  end;
end;

procedure TStreamHelper.Flush;
begin
  if Self is TBaseStream then
    (Self as TBaseStream).Flush
  else
  begin
   // For plain TStream, Flush is a no-op (do nothing)
  end;
end;

function TStreamHelper.GetCanRead: Boolean;
begin
  if Self is TBaseStream then
    Result := (Self as TBaseStream).CanRead
  else
    Result := True; // Default for TStream
end;

function TStreamHelper.GetCanSeek: Boolean;
begin
  if Self is TBaseStream then
    Result := (Self as TBaseStream).CanSeek
  else
    Result := True; // Default for TStream
end;

function TStreamHelper.GetCanWrite: Boolean;
begin
  if Self is TBaseStream then
    Result := (Self as TBaseStream).CanWrite
  else
    Result := True; // Default for TStream
end;

{ TBaseStream }

constructor TBaseStream.Create();
begin
  inherited Create();
  FCanRead := True;
  FCanWrite := True;
  FCanSeek := True;
end;

function TBaseStream.GetCanRead: Boolean;
begin
  Result := FCanRead;
end;

function TBaseStream.GetCanSeek: Boolean;
begin
  Result := FCanSeek;
end;

function TBaseStream.GetCanWrite: Boolean;
begin
  Result := FCanWrite;
end;

procedure TBaseStream.Flush;
begin
  // to be overriden by child classes
end;

function TBaseStream.ReadByte: Int32;
var
  LBuffer: TCryptoLibByteArray;
  LBytesRead: Int32;
begin
  System.SetLength(LBuffer, 1);
  LBytesRead := Read(LBuffer, 0, 1);
  if LBytesRead = 0 then
  begin
    Result := -1;
  end
  else
  begin
    Result := Int32(LBuffer[0]);
  end;
end;

procedure TBaseStream.WriteByte(AValue: Byte);
var
  LOneByteArray: TCryptoLibByteArray;
begin
  System.SetLength(LOneByteArray, 1);
  LOneByteArray[0] := AValue;
  Write(LOneByteArray[0], 1);
end;

{ TFixedBufferStream }

constructor TFixedBufferStream.Create(const ABuffer: TCryptoLibByteArray; AIndex, ACount: Int32);
begin
  Create(ABuffer, AIndex, ACount, True);
end;

constructor TFixedBufferStream.Create(const ABuffer: TCryptoLibByteArray; AIndex, ACount: Int32;
  AWritable: Boolean);
begin
  inherited Create();
  FBuffer := ABuffer;
  FBufferIndex := AIndex;
  FBufferCount := ACount;
  FWritable := AWritable;
  FPosition := 0;
end;

function TFixedBufferStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LRemaining: Int32;
begin
  if ACount < 0 then
    raise EArgumentOutOfRangeCryptoLibException.Create('Count cannot be negative');

  LRemaining := FBufferCount - FPosition;
  if LRemaining <= 0 then
  begin
    Result := 0;
    Exit;
  end;

  if ACount > LRemaining then
    ACount := LRemaining;

  System.Move(FBuffer[FBufferIndex + FPosition], ABuffer, ACount);
  System.Inc(FPosition, ACount);
  Result := ACount;
end;

function TFixedBufferStream.ReadByte: Int32;
var
  LRemaining: Int32;
begin
  LRemaining := FBufferCount - FPosition;
  if LRemaining <= 0 then
  begin
    Result := -1;
    Exit;
  end;

  Result := Int32(FBuffer[FBufferIndex + FPosition]);
  System.Inc(FPosition);
end;

procedure TFixedBufferStream.WriteByte(AValue: Byte);
var
  LRemaining: Int32;
begin
  if not CanWrite then
    raise ENotSupportedCryptoLibException.Create('Stream does not support writing');

  LRemaining := FBufferCount - FPosition;
  if LRemaining <= 0 then
    raise EStreamOverflowCryptoLibException.Create('Cannot write beyond buffer capacity');

  FBuffer[FBufferIndex + FPosition] := AValue;
  System.Inc(FPosition);
end;

function TFixedBufferStream.Write(const ABuffer; ACount: LongInt): LongInt;
var
  LRemaining: Int32;
begin
  if not CanWrite then
    raise ENotSupportedCryptoLibException.Create('Stream does not support writing');

  if ACount < 0 then
    raise EArgumentOutOfRangeCryptoLibException.Create('Count cannot be negative');

  LRemaining := FBufferCount - FPosition;
  if LRemaining <= 0 then
    raise EStreamOverflowCryptoLibException.Create('Cannot write beyond buffer capacity');

  if ACount > LRemaining then
    raise EStreamOverflowCryptoLibException.CreateFmt('Cannot write %d bytes, only %d bytes remaining', [ACount, LRemaining]);

  System.Move(ABuffer, FBuffer[FBufferIndex + FPosition], ACount);
  System.Inc(FPosition, ACount);
  Result := ACount;
end;

function TFixedBufferStream.Seek(const AOffset: Int64; AOrigin: TSeekOrigin): Int64;
var
  LNewPosition: Int64;
begin
  case AOrigin of
    soBeginning: LNewPosition := AOffset;
    soCurrent: LNewPosition := FPosition + AOffset;
    soEnd: LNewPosition := FBufferCount + AOffset;
  else
    LNewPosition := FPosition;
  end;

  if LNewPosition < 0 then
    raise EArgumentOutOfRangeCryptoLibException.CreateFmt('Cannot seek to negative position: %d', [LNewPosition]);

  if LNewPosition > FBufferCount then
    raise EArgumentOutOfRangeCryptoLibException.CreateFmt('Cannot seek beyond buffer capacity: %d > %d', [LNewPosition, FBufferCount]);

  FPosition := LNewPosition;
  Result := FPosition;
end;

function TFixedBufferStream.GetCanWrite: Boolean;
begin
  Result := FWritable;
end;

function TFixedBufferStream.GetSize: Int64;
begin
  Result := FBufferCount;
end;

procedure TFixedBufferStream.SetPosition(const AValue: Int64);
begin
  if AValue < 0 then
    raise EArgumentOutOfRangeCryptoLibException.CreateFmt('Cannot set position to negative value: %d', [AValue]);

  if AValue > FBufferCount then
    raise EArgumentOutOfRangeCryptoLibException.CreateFmt('Cannot set position beyond buffer capacity: %d > %d', [AValue, FBufferCount]);

  FPosition := AValue;
end;

{ TBaseInputStream }

function TBaseInputStream.GetCanRead: Boolean;
begin
  Result := True;
end;

function TBaseInputStream.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TBaseInputStream.GetCanWrite: Boolean;
begin
  Result := False;
end;

function TBaseInputStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LPos, LEndPoint, LB: Int32;
  LBuffer: PByte;
begin
  LBuffer := PByte(@ABuffer);
  LPos := 0;
  try
    LEndPoint := ACount;
    while (LPos < LEndPoint) do
    begin
      LB := ReadByte();
      if (LB = -1) then
      begin
        break;
      end;
      LBuffer^ := Byte(LB);
      System.Inc(LBuffer);
      System.Inc(LPos);
    end;
  except
    on e: EIOCryptoLibException do
    begin
      if (LPos = 0) then
        raise;
    end;
  end;
  Result := LPos;
end;

function TBaseInputStream.Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtils.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

function TBaseInputStream.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  raise ENotSupportedCryptoLibException.Create('Write not supported on input stream');
end;

function TBaseInputStream.Write(const ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt;
begin
  Result := Write(ABuffer[AOffset], ACount);
end;

procedure TBaseInputStream.WriteByte(AValue: Byte);
begin
  raise ENotSupportedCryptoLibException.Create('WriteByte not supported on input stream');
end;

{ TBaseOutputStream }

function TBaseOutputStream.GetCanRead: Boolean;
begin
  Result := False;
end;

function TBaseOutputStream.GetCanSeek: Boolean;
begin
  Result := False;
end;

function TBaseOutputStream.GetCanWrite: Boolean;
begin
  Result := True;
end;

function TBaseOutputStream.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  raise ENotSupportedCryptoLibException.Create('Read not supported on output stream');
end;

function TBaseOutputStream.Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt;
begin
  Result := Read(ABuffer[AOffset], ACount);
end;

function TBaseOutputStream.Write(const ABuffer; ACount: LongInt): LongInt;
var
  I: Int32;
  LBuffer: PByte;
begin
  LBuffer := PByte(@ABuffer);
  for I := 0 to ACount - 1 do
  begin
    WriteByte(LBuffer^);
    System.Inc(LBuffer);
  end;
  Result := ACount;
end;

function TBaseOutputStream.Write(const ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtils.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Write(ABuffer[AOffset], ACount);
end;

function TBaseOutputStream.ReadByte: Int32;
begin
  raise ENotSupportedCryptoLibException.Create('ReadByte not supported on output stream');
end;

{ TFilterStream }

constructor TFilterStream.Create(const AStream: TStream);
begin
  inherited Create();
  if AStream = nil then
    raise EArgumentNilCryptoLibException.Create('Stream cannot be nil');
  FStream := AStream;
end;


function TFilterStream.GetPosition: Int64;
begin
  Result := FStream.Position;
end;

procedure TFilterStream.SetPosition(const AValue: Int64);
begin
  FStream.Position := AValue;
end;

function TFilterStream.GetSize: Int64;
begin
  Result := FStream.Size;
end;

function TFilterStream.GetCanRead: Boolean;
begin
  Result := FStream.CanRead;
end;

function TFilterStream.GetCanSeek: Boolean;
begin
  Result := FStream.CanSeek;
end;

function TFilterStream.GetCanWrite: Boolean;
begin
  Result := FStream.CanWrite;
end;

function TFilterStream.Seek(const AOffset: Int64;
  AOrigin: TSeekOrigin): Int64;
begin
  Result := FStream.Seek(AOffset, AOrigin);
end;

function TFilterStream.Read(var ABuffer; ACount: LongInt): LongInt;
begin
  Result := FStream.Read(ABuffer, ACount);
end;

function TFilterStream.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  Result := FStream.Write(ABuffer, ACount);
end;

function TFilterStream.ReadByte(): Int32;
begin
  Result := FStream.ReadByte();
end;

procedure TFilterStream.WriteByte(AValue: Byte);
begin
  FStream.WriteByte(AValue);
end;

procedure TFilterStream.Flush;
begin
  FStream.Flush();
end;

destructor TFilterStream.Destroy;
begin
  inherited Destroy;
end;

{ TBufferedFilterStream }

constructor TBufferedFilterStream.Create(const AStream: TStream);
begin
  Create(AStream, TStreamUtils.DefaultBufferSize);
end;

constructor TBufferedFilterStream.Create(const AStream: TStream;
  ABufferSize: Int32);
begin
  inherited Create(AStream);
end;

{ TLimitedInputStream }

constructor TLimitedInputStream.Create(const AStream: TStream; ALimit: Int64);
begin
  inherited Create();
  FStream := AStream;
  FLimit := ALimit;
end;

function TLimitedInputStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LNumRead: Int32;
begin
  LNumRead := FStream.Read(ABuffer, ACount);
  if LNumRead > 0 then
  begin
    FLimit := FLimit - LNumRead;
    if FLimit < 0 then
      raise EStreamOverflowCryptoLibException.Create('Data Overflow');
  end;
  Result := LNumRead;
end;

function TLimitedInputStream.ReadByte(): Int32;
var
  LB: Int32;
begin
  LB := FStream.ReadByte();
  if LB >= 0 then
  begin
    System.Dec(FLimit);
    if FLimit < 0 then
      raise EStreamOverflowCryptoLibException.Create('Data Overflow');
  end;
  Result := LB;
end;

{ TPushbackStream }

constructor TPushbackStream.Create(const AStream: TStream);
begin
  inherited Create(AStream);
  FBuffer := -1;
end;

function TPushbackStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LBuffer: PByte;
begin
  if FBuffer <> -1 then
  begin
    if ACount < 1 then
    begin
      Result := 0;
      Exit;
    end;

    LBuffer := PByte(@ABuffer);
    LBuffer^ := Byte(FBuffer);
    FBuffer := -1;
    Result := 1;
  end
  else
  begin
    Result := FStream.Read(ABuffer, ACount);
  end;
end;

function TPushbackStream.ReadByte(): Int32;
var
  LTmp: Int32;
begin
  if FBuffer <> -1 then
  begin
    LTmp := FBuffer;
    FBuffer := -1;
    Result := LTmp;
  end
  else
  begin
    Result := FStream.ReadByte();
  end;
end;

procedure TPushbackStream.UnRead(AByte: Int32);
begin
  if FBuffer <> -1 then
    raise EInvalidOperationCryptoLibException.Create
      ('Can only push back one byte');

  FBuffer := AByte and $FF;
end;

{ TStreamUtils }

class function TStreamUtils.DefaultBufferSize: Int32;
begin
  Result := MaxStackAlloc;
end;

class procedure TStreamUtils.CopyTo(const ASource: TStream;
  const ADestination: TStream; ABufferSize: Int32);
var
  LBytesRead: Int32;
  LBuffer: TCryptoLibByteArray;
begin
  System.SetLength(LBuffer, ABufferSize);
  LBytesRead := ASource.Read(LBuffer, 0, ABufferSize);
  while LBytesRead <> 0 do
  begin
    ADestination.Write(LBuffer, 0, LBytesRead);
    LBytesRead := ASource.Read(LBuffer, 0, ABufferSize);
  end;
end;

class procedure TStreamUtils.CopyTo(const ASource: TStream;
  const ADestination: TStream);
begin
  CopyTo(ASource, ADestination, DefaultBufferSize);
end;

class procedure TStreamUtils.Drain(const AInStr: TStream);
var
  LBuffer: TCryptoLibByteArray;
  LBytesRead: Int32;
begin
  System.SetLength(LBuffer, DefaultBufferSize);
  LBytesRead := AInStr.Read(LBuffer, 0, DefaultBufferSize);
  while LBytesRead > 0 do
  begin
    // Discard the data
    LBytesRead := AInStr.Read(LBuffer, 0, DefaultBufferSize);
  end;
end;

class procedure TStreamUtils.PipeAll(const AInStr: TStream; const AOutStr: TStream;
  ABufferSize: Int32);
begin
  CopyTo(AInStr, AOutStr, ABufferSize);
end;

class procedure TStreamUtils.PipeAll(const AInStr: TStream;
  AOutStr: TStream);
begin
  PipeAll(AInStr, AOutStr, DefaultBufferSize);
end;

class function TStreamUtils.PipeAllLimited(const AInStr: TStream;
  ALimit: Int64; const AOutStr: TStream; ABufferSize: Int32): Int64;
var
  LLimited: TLimitedInputStream;
begin
  LLimited := TLimitedInputStream.Create(AInStr, ALimit);
  try
    CopyTo(LLimited, AOutStr, ABufferSize);
    Result := ALimit - LLimited.CurrentLimit;
  finally
    LLimited.Free;
  end;
end;

class function TStreamUtils.PipeAllLimited(const AInStr: TStream;
  ALimit: Int64; const AOutStr: TStream): Int64;
begin
  Result := PipeAllLimited(AInStr, ALimit, AOutStr, DefaultBufferSize);
end;

class function TStreamUtils.ReadAll(const AInStr: TStream): TCryptoLibByteArray;
var
  LBuf: TMemoryStream;
begin
  LBuf := TMemoryStream.Create();
  try
    PipeAll(AInStr, LBuf);
    System.SetLength(Result, LBuf.Size);
    LBuf.Position := 0;
    LBuf.Read(Result, 0, LBuf.Size);
  finally
    LBuf.Free;
  end;
end;

class function TStreamUtils.ReadAllLimited(const AInStr: TStream;
  ALimit: Int32): TCryptoLibByteArray;
var
  LBuf: TMemoryStream;
begin
  LBuf := TMemoryStream.Create();
  try
    PipeAllLimited(AInStr, ALimit, LBuf);
    System.SetLength(Result, LBuf.Size);
    LBuf.Position := 0;
    LBuf.Read(Result, 0, LBuf.Size);
  finally
    LBuf.Free;
  end;
end;

class function TStreamUtils.ReadFully(const AInStr: TStream;
  const ABuf: TCryptoLibByteArray; AOff, ALen: Int32): Int32;
var
  LTotalRead, LNumRead: Int32;
begin
  LTotalRead := 0;
  while LTotalRead < ALen do
  begin
    LNumRead := AInStr.Read(ABuf, AOff + LTotalRead, ALen - LTotalRead);
    if LNumRead < 1 then
      break;
    LTotalRead := LTotalRead + LNumRead;
  end;
  Result := LTotalRead;
end;

class function TStreamUtils.ReadFully(const AInStr: TStream;
  const ABuf: TCryptoLibByteArray): Int32;
begin
  Result := ReadFully(AInStr, ABuf, 0, System.Length(ABuf));
end;

class procedure TStreamUtils.ValidateBufferArguments(const ABuffer
  : TCryptoLibByteArray; AOffset, ACount: Int32);
var
  LAvailable, LRemaining: Int32;
begin
  if ABuffer = nil then
    raise EArgumentNilCryptoLibException.Create('Buffer cannot be nil');
  LAvailable := System.Length(ABuffer) - AOffset;
  if ((AOffset or LAvailable) < 0) then
    raise EArgumentOutOfRangeCryptoLibException.Create('Offset out of range');
  LRemaining := LAvailable - ACount;
  if ((ACount or LRemaining) < 0) then
    raise EArgumentOutOfRangeCryptoLibException.Create('Count out of range');
end;

class function TStreamUtils.WriteBufTo(const ABuf: TMemoryStream;
  const AOutput: TBytes; AOffset: Integer): Integer;
begin
  Result := ABuf.Size;

  if (AOffset < 0) or (AOffset + Result > Length(AOutput)) then
    raise ERangeError.Create('Output buffer too small');

  // Copy directly from stream buffer into the byte array
  Move(PByte(ABuf.Memory)^, AOutput[AOffset], Result);
end;

end.
