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

unit ClpAsn1Streams;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Math,
  SysUtils,
  ClpIAsn1Core,
  ClpIAsn1Encodings,
  ClpIAsn1Objects,
  ClpIAsn1Parsers,
  ClpAsn1Tags,
  ClpBitOperations,
  ClpPlatformUtilities,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes,
  ClpStreams,
  ClpStreamUtilities;

resourcestring
  SNegativeLengthsNotAllowed = 'negative lengths not allowed';
  SBufferLengthNotSufficientForData = 'buffer length not sufficient for data';
  SMalformedEndOfContentsMarker = 'malformed end-of-contents marker';
  SUnexpectedEndOfStream = 'unexpected end of stream';
  SAsn1EncodableNil = 'ASN.1 encodable cannot be nil';
  SAsn1ObjectNil = 'ASN.1 object cannot be nil';
  SStreamCannotBeNil = 'stream cannot be nil';
  SStreamMustBeAnAsn1OutputStream = 'stream must be a TAsn1OutputStream';
  SBufNil = 'buffer cannot be nil';
  SExpectedStreamToBeReadable = 'expected stream to be readable';
  STagNumberMoreThan31Bits = 'tag number more than 31 bits';
  SInvalidLongFormDefiniteLengthFF = 'invalid long form definite-length 0xFF';
  SEofFoundReadingLength = 'EOF found reading length';
  SUnknownObjectEncountered = 'unknown object encountered: %s';
  SUnknownBerObjectEncountered = 'unknown BER object encountered: %d';
  SUnknownTagEncountered = 'unknown tag %d encountered';
  SUnknownObjectEncounteredInConstructed = 'unknown object encountered in constructed %s: %s';
  SUnsupportedTagEncountered = 'unsupported tag %d encountered';
  SCorruptedStreamDetected = 'corrupted stream detected: %s';
  SCorruptedStreamOutOfBoundsLength = 'corrupted stream - out of bounds length found: %d > %d';
  SMaximumNestedConstructionLevelReached = 'maximum nested construction level reached';
  SDefLengthObjectTruncated = 'DEF length %d object truncated by %d';
  SExpectedOctetAlignedBitStringButFound = 'expected octet-aligned bitstring, but found padBits: %d';
  SOnlyTheLastNestedBitStringCanHavePadding = 'only the last nested bitstring can have padding';
  SEofFoundInsideTagValue = 'EOF found inside tag value';
  SCorruptedStreamHighTagNumber31 = 'corrupted stream - high tag number < 31 found';
  SCorruptedStreamInvalidHighTagNumber = 'corrupted stream - invalid high tag number found';
  SEofFoundWhenLengthExpected = 'EOF found when length expected';
  SLongFormDefiniteLengthMoreThan31Bits = 'long form definite-length more than 31 bits';
  SUnexpectedEndOfContentsMarker = 'unexpected end-of-contents marker';
  SIndefiniteLengthPrimitiveEncodingEncountered = 'indefinite-length primitive encoding encountered';

type
  /// <summary>
  /// Abstract base class for ASN.1 limited input streams.
  /// </summary>
  TAsn1LimitedInputStream = class abstract(TBaseInputStream)
  strict protected
    FIn: TStream;
    FLimit: Int32;

  strict protected
    /// <summary>
    /// Sets EOF detection on parent IndefiniteLengthInputStream if applicable.
    /// </summary>
    procedure SetParentEofDetect; virtual;

  public
    /// <summary>
    /// Creates a new TAsn1LimitedInputStream.
    /// </summary>
    constructor Create(const AInStream: TStream; ALimit: Int32);

    /// <summary>
    /// Gets the limit of bytes that can be read.
    /// </summary>
    property Limit: Int32 read FLimit;

  end;

  /// <summary>
  /// Input stream for ASN.1 definite length encoding.
  /// </summary>
  TAsn1DefiniteLengthInputStream = class sealed(TAsn1LimitedInputStream)
  strict private
    FOriginalLength: Int32;
    FRemaining: Int32;

  public
    /// <summary>
    /// Creates a new TAsn1DefiniteLengthInputStream.
    /// </summary>
    constructor Create(const AInStream: TStream; ALength: Int32; ALimit: Int32);

    /// <summary>
    /// Gets the number of remaining bytes.
    /// </summary>
    property Remaining: Int32 read FRemaining;

    /// <summary>
    /// Reads a single byte from the stream.
    /// </summary>
    function ReadByte: Int32; override;

    /// <summary>
    /// Reads bytes from the stream into a buffer.
    /// </summary>
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt)
      : LongInt; override;

    procedure ReadAllIntoByteArray(const ABuf: TCryptoLibByteArray);

    /// <summary>
    /// Reads all remaining bytes into a byte array.
    /// </summary>
    function ToArray: TCryptoLibByteArray;

  end;

  /// <summary>
  /// Input stream for ASN.1 indefinite length encoding.
  /// </summary>
  TAsn1IndefiniteLengthInputStream = class sealed(TAsn1LimitedInputStream)
  strict private
    FLookAhead: Int32;
    FEofOn00: Boolean;

    procedure CheckEndOfContents;
    function RequireByte: Int32;

  public
    /// <summary>
    /// Creates a new TAsn1IndefiniteLengthInputStream.
    /// </summary>
    constructor Create(const AInStream: TStream; ALimit: Int32);

    /// <summary>
    /// Sets whether to treat 00 as EOF.
    /// </summary>
    procedure SetEofOn00(AEofOn00: Boolean);

    /// <summary>
    /// Reads a single byte from the stream.
    /// </summary>
    function ReadByte: Int32; override;

    /// <summary>
    /// Reads bytes from the stream into a buffer.
    /// </summary>
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt)
      : LongInt; override;

  end;

  /// <summary>
  /// Base class for ASN.1 output streams.
  /// </summary>
  TAsn1OutputStream = class(TFilterStream)
  strict private
    FLeaveOpen: Boolean;
    FStream: TStream;

  strict protected

    /// <summary>
    /// Create an ASN.1 output stream.
    /// </summary>
    constructor Create(const AOutput: TStream; ALeaveOpen: Boolean); overload;

    procedure FlushInternal; virtual;

    function GetEncoding: Int32; virtual;

  public
    const
      EncodingBer = 1;
      EncodingDL = 2;
      EncodingDer = 3;

    /// <summary>
    /// Create an ASN.1 output stream.
    /// </summary>
    class function CreateInstance(const AOutput: TStream): TAsn1OutputStream; overload; static;
    /// <summary>
    /// Create an ASN.1 output stream with encoding.
    /// </summary>
    class function CreateInstance(const AOutput: TStream; const AEncoding: String): TAsn1OutputStream; overload; static;
    /// <summary>
    /// Create an ASN.1 output stream from byte array.
    /// </summary>
    class function CreateInstance(const ABuffer: TCryptoLibByteArray; AIndex, ACount: Int32; const AEncoding: String; ALeaveOpen: Boolean): TAsn1OutputStream; overload; static;

    /// <summary>
    /// Create an ASN.1 output stream with encoding and leaveOpen (factory method).
    /// </summary>
    class function CreateInstance(const AOutput: TStream; const AEncoding: String; ALeaveOpen: Boolean): TAsn1OutputStream; overload; static;

    /// <summary>
    /// Destructor.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Write an ASN.1 encodable object.
    /// </summary>
    procedure WriteObject(const AAsn1Encodable: IAsn1Encodable); overload; virtual;
    /// <summary>
    /// Write an ASN.1 object.
    /// </summary>
    procedure WriteObject(const AAsn1Object: IAsn1Object); overload; virtual;

    /// <summary>
    /// Encode contents using the given encodings.
    /// </summary>
    procedure EncodeContents(const AContentsEncodings: TCryptoLibGenericArray<IAsn1Encoding>);

    /// <summary>
    /// Write a definite length value.
    /// </summary>
    procedure WriteDL(ADl: Int32); overload;

    /// <summary>
    /// Write an identifier with flags and tag number.
    /// </summary>
    procedure WriteIdentifier(AFlags, ATagNo: Int32); overload;

    /// <summary>
    /// Write a definite length value to a stream.
    /// </summary>
    class procedure WriteDL(const AOutput: TStream; ADl: Int32); overload; static;

    /// <summary>
    /// Write an identifier with flags and tag number to a stream.
    /// </summary>
    class procedure WriteIdentifier(const AOutput: TStream; AFlags, ATagNo: Int32); overload; static;

    /// <summary>
    /// Get encoding type from string.
    /// </summary>
    class function GetEncodingType(const AEncoding: String): Int32; static;

    /// <summary>
    /// Get length of definite length encoding.
    /// </summary>
    class function GetLengthOfDL(ADl: Int32): Int32; static;

    /// <summary>
    /// Get length of identifier.
    /// </summary>
    class function GetLengthOfIdentifier(ATagNo: Int32): Int32; static;

    /// <summary>
    /// Get length of encoding with definite length.
    /// </summary>
    class function GetLengthOfEncodingDL(ATagNo, AContentsLength: Int32): Int32; static;

    /// <summary>
    /// Get length of encoding with indefinite length.
    /// </summary>
    class function GetLengthOfEncodingIL(ATagNo: Int32;
      const AContentsEncoding: IAsn1Encoding): Int32; overload; static;
    class function GetLengthOfEncodingIL(ATagNo: Int32;
      const AContentsEncodings: TCryptoLibGenericArray<IAsn1Encoding>): Int32; overload; static;

    /// <summary>
    /// Get encodings for contents with specified encoding type.
    /// </summary>
    class function GetContentsEncodings(AEncoding: Int32; const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IAsn1Encoding>; static;
    /// <summary>
    /// Get DER encodings for contents.
    /// </summary>
    class function GetContentsEncodingsDer(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IDerEncoding>; static;
    /// <summary>
    /// Get length of contents.
    /// </summary>
    class function GetLengthOfContents(const AContentsEncodings
      : TCryptoLibGenericArray<IAsn1Encoding>): Int32; static;

    /// <summary>
    /// Validate that the stream is a TAsn1OutputStream and return it.
    /// </summary>
    class function ValidateAsn1OutputStream(const AOut: TStream): TAsn1OutputStream; static;

    /// <summary>
    /// Get encoding type.
    /// </summary>
    property Encoding: Int32 read GetEncoding;
  end;

  /// <summary>
  /// DER output stream.
  /// </summary>
  TAsn1DerOutputStream = class sealed(TAsn1OutputStream)
  strict protected
    function GetEncoding: Int32; override;
  public
    /// <summary>
    /// Create a DER output stream.
    /// </summary>
    constructor Create(const AOs: TStream; ALeaveOpen: Boolean);
  end;

  /// <summary>
  /// DL output stream.
  /// </summary>
  TAsn1DLOutputStream = class sealed(TAsn1OutputStream)
  strict protected
    function GetEncoding: Int32; override;
  public
    /// <summary>
    /// Create a DL output stream.
    /// </summary>
    constructor Create(const AOs: TStream; ALeaveOpen: Boolean);
  end;

  /// <summary>
  /// Buffered BER octet string stream.
  /// </summary>
  TAsn1BufferedBerOctetStream = class(TBaseOutputStream)
  strict private
    FBuf: TCryptoLibByteArray;
    FOff: Int32;
    FAsn1Out: TAsn1OutputStream;
  public
    /// <summary>
    /// Create a buffered BER octet string stream.
    /// </summary>
    constructor Create(const AOutStream: TStream; const ABuf: TCryptoLibByteArray);
    /// <summary>
    /// Destructor.
    /// </summary>
    destructor Destroy; override;
    /// <summary>
    /// Write bytes to the stream.
    /// </summary>
    function Write(const ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt): LongInt; override;
    /// <summary>
    /// Write a single byte to the stream.
    /// </summary>
    procedure WriteByte(AValue: Byte); override;
  end;

  /// <summary>
  /// Constructed bit string stream.
  /// </summary>
  TAsn1ConstructedBitStream = class(TBaseInputStream)
  strict private
    FParser: IAsn1StreamParser;
    FOctetAligned: Boolean;
    FFirst: Boolean;
    FPadBits: Int32;
    FCurrentParser: IAsn1BitStringParser;
    FCurrentStream: TStream;

    function GetNextParser(): IAsn1BitStringParser;
    function GetPadBits(): Int32;

  public
    /// <summary>
    /// Create a constructed bit string stream.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser; AOctetAligned: Boolean);
    /// <summary>
    /// Destructor.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Read bytes from the stream.
    /// </summary>
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt)
      : LongInt; override;

    /// <summary>
    /// Read a single byte from the stream.
    /// </summary>
    function ReadByte: Int32; override;

    /// <summary>
    /// Get the number of pad bits.
    /// </summary>
    property PadBits: Int32 read GetPadBits;
  end;

  /// <summary>
  /// Constructed octet string stream.
  /// </summary>
  TAsn1ConstructedOctetStream = class(TBaseInputStream)
  strict private
    FParser: IAsn1StreamParser;
    FFirst: Boolean;
    FCurrentParser: IAsn1OctetStringParser;
    FCurrentStream: TStream;

    function GetNextParser(): IAsn1OctetStringParser;

  public
    /// <summary>
    /// Create a constructed octet string stream.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);
    /// <summary>
    /// Destructor.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Read bytes from the stream.
    /// </summary>
    function Read(var ABuffer; ACount: LongInt): LongInt; override;
    function Read(ABuffer: TCryptoLibByteArray; AOffset, ACount: LongInt)
      : LongInt; override;

    /// <summary>
    /// Read a single byte from the stream.
    /// </summary>
    function ReadByte: Int32; override;
  end;

  /// <summary>
  /// ASN.1 input stream for reading ASN.1 objects.
  /// </summary>
  TAsn1InputStream = class(TFilterStream)
  strict private
    var
      FDepth: Int32;
      FLimit: Int32;
      FLeaveOpen: Boolean;
      FTmp: TCryptoLibByteArray;
      FStream: TStream;

    function BuildObject(ATagHdr, ATagNo, ALength: Int32): IAsn1Object;
    function ReadTaggedObjectDL(ATagClass, ATagNo: Int32;
      AConstructed: Boolean; const ADefIn: TAsn1DefiniteLengthInputStream)
      : IAsn1Object;
    function ReadVector(): IAsn1EncodableVector; overload;
    function ReadVector(const ADefIn: TAsn1DefiniteLengthInputStream)
      : IAsn1EncodableVector; overload;
    function CreateSubStream(const ASub: TStream; ALimit: Int32): TAsn1InputStream;
    function BuildConstructedBitString(const AContentsElements
      : IAsn1EncodableVector): IAsn1Object;

    class function BuildConstructedOctetString(const AContentsElements
      : IAsn1EncodableVector): IAsn1Object; static;

  public
    /// <summary>
    /// Create an ASN.1 input stream from a byte array.
    /// </summary>
    constructor Create(const AInput: TCryptoLibByteArray); overload;
    /// <summary>
    /// Create an ASN.1 input stream from a stream.
    /// </summary>
    constructor Create(const AInput: TStream); overload;
    /// <summary>
    /// Create from stream with inferred limit (<see cref="FindLimit"/>) and leave-open behaviour.
    /// </summary>
    constructor Create(const AInput: TStream; ALeaveOpen: Boolean); overload;
    /// <summary>
    /// Create an ASN.1 input stream from a stream with a limit.
    /// </summary>
    constructor Create(const AInput: TStream; ALimit: Int32); overload;
    /// <summary>
    /// Create an ASN.1 input stream from a stream with a limit and leaveOpen flag.
    /// </summary>
    constructor Create(const AInput: TStream; ALimit: Int32;
      ALeaveOpen: Boolean); overload;
    constructor Create(const AInput: TStream; ADepth, ALimit: Int32;
      ALeaveOpen: Boolean; const ATmp: TCryptoLibByteArray);
      overload;

    /// <summary>
    /// Destructor.
    /// </summary>
    destructor Destroy; override;

    /// <summary>
    /// Maximum number of bytes that may be read through this stream.
    /// </summary>
    property Limit: Int32 read FLimit;

    /// <summary>
    /// Effective root recursion budget for nested constructed values (used when creating streams
    /// and parsers). Reflects <c>TCryptoLibConfig.Asn1.MaxDepth</c>.
    /// </summary>
    class function FindDepth: Int32; static;

    /// <summary>
    /// Returns the parent's decremented recursion budget or raises <see cref="EAsn1ParsingCryptoLibException"/> when the budget is exhausted.
    /// </summary>
    class function DecrementDepth(AParentDepth: Int32): Int32; static;

    /// <summary>
    /// Read the next ASN.1 object from the stream.
    /// </summary>
    function ReadObject(): IAsn1Object;

    /// <summary>
    /// Find the limit for a stream.
    /// </summary>
    class function FindLimit(const AInput: TStream): Int32; static;

    /// <summary>
    /// Read tag number from stream.
    /// </summary>
    class function ReadTagNumber(const AInput: TStream; ATagHdr: Int32): Int32;
      static;

    /// <summary>
    /// Validates that <paramref name="ALength"/> is not greater than <paramref name="ALimit"/>.
    /// </summary>
    class procedure CheckLength(ALength, ALimit: Int32); static;

    /// <summary>
    /// Read length from stream (no parent-limit check — use <see cref="CheckLength"/>).
    /// </summary>
    class function ReadLength(const AInput: TStream): Int32; static;

    class function CreatePrimitiveDerObject(ATagNo: Int32;
      const ADefIn: TAsn1DefiniteLengthInputStream;
      const ATmp: TCryptoLibByteArray): IAsn1Object; static;
  end;

implementation

uses
  ClpAsn1Objects,
  ClpAsn1Parsers,
  ClpAsn1Core;

type
  TLimitedCapacityMemoryStream = class(TMemoryStream)
  strict private
    FLimitedCapacity: Int32;
  strict protected
{$IFDEF FPC}
    function Realloc(var NewCapacity: PtrInt): Pointer; override;
{$ELSE}
    procedure SetCapacity(NewCapacity: NativeInt); override;
{$ENDIF}
  public
    constructor Create(ALimitedCapacity: Int32);
    function GetBuffer: TCryptoLibByteArray;
  end;

{ TLimitedCapacityMemoryStream }

constructor TLimitedCapacityMemoryStream.Create(ALimitedCapacity: Int32);
begin
  inherited Create;
  FLimitedCapacity := ALimitedCapacity;
end;

{$IFDEF FPC}
function TLimitedCapacityMemoryStream.Realloc(var NewCapacity: PtrInt): Pointer;
begin
  NewCapacity := Min(NewCapacity * 2, FLimitedCapacity);
  Result := inherited Realloc(NewCapacity);
end;
{$ELSE}
procedure TLimitedCapacityMemoryStream.SetCapacity(NewCapacity: NativeInt);
begin
  inherited SetCapacity(Min(NewCapacity * 2, FLimitedCapacity));
end;
{$ENDIF}

function TLimitedCapacityMemoryStream.GetBuffer: TCryptoLibByteArray;
begin
  System.SetLength(Result, Size);
  if Size > 0 then
    Move(Memory^, Result[0], Size);
end;

{ TAsn1InputStream }

class function TAsn1InputStream.FindDepth: Int32;
begin
  Result := Max(0, TCryptoLibConfig.Asn1.MaxDepth);
end;

class function TAsn1InputStream.DecrementDepth(AParentDepth: Int32): Int32;
begin
  if AParentDepth <= 0 then
    raise EAsn1ParsingCryptoLibException.CreateRes(@SMaximumNestedConstructionLevelReached);
  Result := AParentDepth - 1;
end;

class procedure TAsn1InputStream.CheckLength(ALength, ALimit: Int32);
begin
  if ALength > ALimit then
    raise EIOCryptoLibException.CreateResFmt(@SCorruptedStreamOutOfBoundsLength, [ALength, ALimit]);
end;

function TAsn1InputStream.CreateSubStream(const ASub: TStream;
  ALimit: Int32): TAsn1InputStream;
begin
  Result := TAsn1InputStream.Create(ASub, TAsn1InputStream.DecrementDepth(FDepth),
    ALimit, True, FTmp);
end;

{ TAsn1LimitedInputStream }

constructor TAsn1LimitedInputStream.Create(const AInStream: TStream;
  ALimit: Int32);
begin
  inherited Create();
  FIn := AInStream;
  FLimit := ALimit;
end;

procedure TAsn1LimitedInputStream.SetParentEofDetect;
var
  LIndefiniteLengthInputStream: TAsn1IndefiniteLengthInputStream;
begin
  if FIn is TAsn1IndefiniteLengthInputStream then
  begin
    LIndefiniteLengthInputStream := FIn as TAsn1IndefiniteLengthInputStream;
    LIndefiniteLengthInputStream.SetEofOn00(True);
  end;
end;

{ TAsn1DefiniteLengthInputStream }

constructor TAsn1DefiniteLengthInputStream.Create(const AInStream: TStream;
  ALength: Int32; ALimit: Int32);
begin
  inherited Create(AInStream, ALimit);
  if ALength <= 0 then
  begin
    if ALength < 0 then
      raise EArgumentCryptoLibException.CreateRes(@SNegativeLengthsNotAllowed);
    SetParentEofDetect();
  end;
  FOriginalLength := ALength;
  FRemaining := ALength;
end;

function TAsn1DefiniteLengthInputStream.ReadByte: Int32;
var
  LB: Int32;
begin
  if FRemaining < 2 then
  begin
    if FRemaining = 0 then
    begin
      Result := -1;
      Exit;
    end;

    LB := FIn.ReadByte();
    if LB < 0 then
      raise EEndOfStreamCryptoLibException.CreateResFmt(@SDefLengthObjectTruncated, [FOriginalLength, FRemaining]);

    FRemaining := 0;
    SetParentEofDetect();

    Result := LB;
  end
  else
  begin
    LB := FIn.ReadByte();
    if LB < 0 then
      raise EEndOfStreamCryptoLibException.CreateResFmt(@SDefLengthObjectTruncated, [FOriginalLength, FRemaining]);

    System.Dec(FRemaining);
    Result := LB;
  end;
end;

function TAsn1DefiniteLengthInputStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LToRead, LNumRead: Int32;
begin
  if FRemaining = 0 then
  begin
    Result := 0;
    Exit;
  end;

  LToRead := Min(ACount, FRemaining);
  LNumRead := FIn.Read(ABuffer, LToRead);

  if LNumRead < 1 then
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SDefLengthObjectTruncated, [FOriginalLength, FRemaining]);

  FRemaining := FRemaining - LNumRead;
  if FRemaining = 0 then
  begin
    SetParentEofDetect();
  end;

  Result := LNumRead;
end;

function TAsn1DefiniteLengthInputStream.Read(ABuffer: TCryptoLibByteArray;
  AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

procedure TAsn1DefiniteLengthInputStream.ReadAllIntoByteArray
  (const ABuf: TCryptoLibByteArray);
var
  LToRead: Int32;
begin
  if FRemaining = 0 then
    Exit;

  LToRead := FRemaining;

  if System.Length(ABuf) < LToRead then
    raise EArgumentCryptoLibException.CreateRes(@SBufferLengthNotSufficientForData);

  TAsn1InputStream.CheckLength(LToRead, Limit);

  FRemaining := FRemaining - TStreamUtilities.ReadFully(FIn, ABuf, 0,
    LToRead);
  if FRemaining <> 0 then
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SDefLengthObjectTruncated, [FOriginalLength, FRemaining]);
  SetParentEofDetect();
end;

function TAsn1DefiniteLengthInputStream.ToArray: TCryptoLibByteArray;
var
  LBuf: TLimitedCapacityMemoryStream;
  LThreshold: Int32;
begin
  Result := nil;
  if FRemaining = 0 then
  begin
    Exit;
  end;

  TAsn1InputStream.CheckLength(FRemaining, Limit);

  LThreshold := TStreamUtilities.DefaultBufferSize * 8;
  if FRemaining > LThreshold then
  begin
    LBuf := TLimitedCapacityMemoryStream.Create(FRemaining);
    try
      TStreamUtilities.CopyTo(Self, LBuf);
      Result := LBuf.GetBuffer();
    finally
      LBuf.Free;
    end;
    Exit;
  end;

  System.SetLength(Result, FRemaining);
  FRemaining := FRemaining - TStreamUtilities.ReadFully(FIn, Result, 0,
    System.Length(Result));
  if FRemaining <> 0 then
    raise EEndOfStreamCryptoLibException.CreateResFmt(@SDefLengthObjectTruncated, [FOriginalLength, FRemaining]);
  SetParentEofDetect();
end;

{ TAsn1IndefiniteLengthInputStream }

constructor TAsn1IndefiniteLengthInputStream.Create(const AInStream: TStream;
  ALimit: Int32);
begin
  inherited Create(AInStream, ALimit);
  FEofOn00 := True;
  FLookAhead := RequireByte();

  if FLookAhead = 0 then
  begin
    CheckEndOfContents();
  end;
end;

procedure TAsn1IndefiniteLengthInputStream.SetEofOn00(AEofOn00: Boolean);
begin
  FEofOn00 := AEofOn00;
  if FEofOn00 and (FLookAhead = 0) then
  begin
    CheckEndOfContents();
  end;
end;

procedure TAsn1IndefiniteLengthInputStream.CheckEndOfContents;
var
  LByte: Int32;
begin
  LByte := RequireByte();
  if LByte <> 0 then
    raise EIOCryptoLibException.CreateRes(@SMalformedEndOfContentsMarker);

  FLookAhead := -1;
  SetParentEofDetect();
end;

function TAsn1IndefiniteLengthInputStream.ReadByte: Int32;
begin
  if FEofOn00 and (FLookAhead <= 0) then
  begin
    if FLookAhead = 0 then
    begin
      CheckEndOfContents();
    end;
    Result := -1;
    Exit;
  end;

  Result := FLookAhead;
  FLookAhead := RequireByte();
end;

function TAsn1IndefiniteLengthInputStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LNumRead: Int32;
begin
  if FEofOn00 or (ACount <= 1) then
  begin
    Result := inherited Read(ABuffer, ACount);
    Exit;
  end;

  if FLookAhead < 0 then
  begin
    Result := 0;
    Exit;
  end;

  LNumRead := FIn.Read(PByte(@ABuffer)[1], ACount - 1);
  if LNumRead <= 0 then
    raise EEndOfStreamCryptoLibException.CreateRes(@SUnexpectedEndOfStream);

  PByte(@ABuffer)[0] := Byte(FLookAhead);
  FLookAhead := RequireByte();

  Result := LNumRead + 1;
end;

function TAsn1IndefiniteLengthInputStream.Read(ABuffer: TCryptoLibByteArray;
  AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

function TAsn1IndefiniteLengthInputStream.RequireByte: Int32;
var
  LB: Int32;
begin
  LB := FIn.ReadByte();
  if LB < 0 then
    raise EEndOfStreamCryptoLibException.CreateRes(@SUnexpectedEndOfStream);

  Result := LB;
end;

{ TAsn1OutputStream }

constructor TAsn1OutputStream.Create(const AOutput: TStream; ALeaveOpen: Boolean);
begin
  inherited Create(AOutput);

  FLeaveOpen := ALeaveOpen;
  FStream := AOutput;
end;

destructor TAsn1OutputStream.Destroy;
begin
  FlushInternal();

  if not FLeaveOpen then
  begin
   if FStream <> nil then
    FStream.Free;
  end;

  inherited Destroy;
end;

class function TAsn1OutputStream.CreateInstance(const AOutput: TStream): TAsn1OutputStream;
begin
  Result := TAsn1OutputStream.Create(AOutput, False);
end;

class function TAsn1OutputStream.CreateInstance(const AOutput: TStream; const AEncoding: String): TAsn1OutputStream;
begin
  Result := TAsn1OutputStream.CreateInstance(AOutput, AEncoding, False);
end;

class function TAsn1OutputStream.CreateInstance(const AOutput: TStream; const AEncoding: String; ALeaveOpen: Boolean): TAsn1OutputStream;
begin
  if SameText(AEncoding, TAsn1Encodable.Der) then
    Result := TAsn1DerOutputStream.Create(AOutput, ALeaveOpen)
  else if SameText(AEncoding, TAsn1Encodable.DL) then
    Result := TAsn1DLOutputStream.Create(AOutput, ALeaveOpen)
  else
    Result := TAsn1OutputStream.Create(AOutput, ALeaveOpen);
end;

class function TAsn1OutputStream.CreateInstance(const ABuffer: TCryptoLibByteArray; AIndex, ACount: Int32; const AEncoding: String; ALeaveOpen: Boolean): TAsn1OutputStream;
begin
  Result := TAsn1OutputStream.CreateInstance(TFixedBufferStream.Create(ABuffer, AIndex, ACount, True), AEncoding, ALeaveOpen);
end;

procedure TAsn1OutputStream.FlushInternal;
begin
  // Placeholder to support future internal buffering
end;

function TAsn1OutputStream.GetEncoding: Int32;
begin
  Result := EncodingBer;
end;

procedure TAsn1OutputStream.WriteObject(const AAsn1Encodable: IAsn1Encodable);
var
  LAsn1Encoding: IAsn1Encoding;
begin
  if AAsn1Encodable = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAsn1EncodableNil);

  LAsn1Encoding := AAsn1Encodable.ToAsn1Object().GetEncoding(Self.Encoding);
  LAsn1Encoding.Encode(Self);
  FlushInternal();
end;

procedure TAsn1OutputStream.WriteObject(const AAsn1Object: IAsn1Object);
var
  LAsn1Encoding: IAsn1Encoding;
begin
  if AAsn1Object = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SAsn1ObjectNil);

  LAsn1Encoding := AAsn1Object.GetEncoding(Self.Encoding);
  LAsn1Encoding.Encode(Self);
  FlushInternal();
end;

procedure TAsn1OutputStream.EncodeContents(const AContentsEncodings
  : TCryptoLibGenericArray<IAsn1Encoding>);
var
  LI, LCount: Int32;
begin
  LCount := System.Length(AContentsEncodings);
  for LI := 0 to LCount - 1 do
  begin
    AContentsEncodings[LI].Encode(Self);
  end;
end;

procedure TAsn1OutputStream.WriteDL(ADl: Int32);
begin
  WriteDL(FStream, ADl);
end;

procedure TAsn1OutputStream.WriteIdentifier(AFlags, ATagNo: Int32);
begin
  WriteIdentifier(FStream, AFlags, ATagNo);
end;

class procedure TAsn1OutputStream.WriteDL(const AOutput: TStream; ADl: Int32);
var
  LStack: TCryptoLibByteArray;
  LPos, LCount: Int32;
begin
  if ADl < 128 then
  begin
    AOutput.WriteByte(Byte(ADl));
    Exit;
  end;

  System.SetLength(LStack, 5);
  LPos := System.Length(LStack);

  repeat
    System.Dec(LPos);
    LStack[LPos] := Byte(ADl);
    ADl := TBitOperations.Asr32(ADl, 8);
  until ADl = 0;

  LCount := System.Length(LStack) - LPos;
  System.Dec(LPos);
  LStack[LPos] := Byte($80 or LCount);

  AOutput.Write(LStack[LPos], LCount + 1);
end;

class procedure TAsn1OutputStream.WriteIdentifier(const AOutput: TStream; AFlags, ATagNo: Int32);
var
  LStack: TCryptoLibByteArray;
  LPos: Int32;
begin
  if ATagNo < 31 then
  begin
    AOutput.WriteByte(Byte(AFlags or ATagNo));
    Exit;
  end;

  System.SetLength(LStack, 6);
  LPos := System.Length(LStack);

  System.Dec(LPos);
  LStack[LPos] := Byte(ATagNo and $7F);
  while ATagNo > 127 do
  begin
    ATagNo := TBitOperations.Asr32(ATagNo, 7);
    System.Dec(LPos);
    LStack[LPos] := Byte((ATagNo and $7F) or $80);
  end;

  System.Dec(LPos);
  LStack[LPos] := Byte(AFlags or $1F);

  AOutput.Write(LStack[LPos], System.Length(LStack) - LPos);
end;

class function TAsn1OutputStream.GetEncodingType(const AEncoding: String): Int32;
begin
  if SameText(AEncoding, TAsn1Encodable.Der) then
    Result := EncodingDer
  else if SameText(AEncoding, TAsn1Encodable.DL) then
    Result := EncodingDL
  else
    Result := EncodingBer;
end;

class function TAsn1OutputStream.GetLengthOfDL(ADl: Int32): Int32;
begin
  if ADl < 128 then
  begin
    Result := 1;
    Exit;
  end;

  Result := 2;
  while TBitOperations.Asr32(ADl, 8) > 0 do
  begin
    ADl := TBitOperations.Asr32(ADl, 8);
    System.Inc(Result);
  end;
end;

class function TAsn1OutputStream.GetLengthOfIdentifier(ATagNo: Int32): Int32;
begin
  if ATagNo < 31 then
  begin
    Result := 1;
    Exit;
  end;

  Result := 2;
  while TBitOperations.Asr32(ATagNo, 7) > 0 do
  begin
    ATagNo := TBitOperations.Asr32(ATagNo, 7);
    System.Inc(Result);
  end;
end;

class function TAsn1OutputStream.GetLengthOfEncodingDL(ATagNo,
  AContentsLength: Int32): Int32;
begin
  Result := GetLengthOfIdentifier(ATagNo) + GetLengthOfDL(AContentsLength) +
    AContentsLength;
end;

class function TAsn1OutputStream.GetLengthOfEncodingIL(ATagNo: Int32;
  const AContentsEncoding: IAsn1Encoding): Int32;
begin
  Result := GetLengthOfIdentifier(ATagNo) + 3 + AContentsEncoding.GetLength();
end;

class function TAsn1OutputStream.GetLengthOfEncodingIL(ATagNo: Int32;
  const AContentsEncodings: TCryptoLibGenericArray<IAsn1Encoding>): Int32;
begin
  Result := GetLengthOfIdentifier(ATagNo) + 3 +
    GetLengthOfContents(AContentsEncodings);
end;

class function TAsn1OutputStream.GetContentsEncodings(AEncoding: Int32; const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IAsn1Encoding>;
var
  LI, LCount: Int32;
  LObj: IAsn1Object;
begin
  LCount := System.Length(AElements);
  System.SetLength(Result, LCount);
  for LI := 0 to LCount - 1 do
  begin
    LObj := AElements[LI].ToAsn1Object();
    Result[LI] := LObj.GetEncoding(AEncoding);
  end;
end;

class function TAsn1OutputStream.GetContentsEncodingsDer(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IDerEncoding>;
var
  LI, LCount: Int32;
  LObj: IAsn1Object;
begin
  LCount := System.Length(AElements);
  System.SetLength(Result, LCount);
  for LI := 0 to LCount - 1 do
  begin
    LObj := AElements[LI].ToAsn1Object();
    Result[LI] := LObj.GetEncodingDer();
  end;
end;

class function TAsn1OutputStream.ValidateAsn1OutputStream(const AOut: TStream): TAsn1OutputStream;
begin
  if AOut = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SStreamCannotBeNil);

  if not (AOut is TAsn1OutputStream) then
    raise EArgumentCryptoLibException.CreateRes(@SStreamMustBeAnAsn1OutputStream);

  Result := AOut as TAsn1OutputStream;
end;

class function TAsn1OutputStream.GetLengthOfContents(const AContentsEncodings
  : TCryptoLibGenericArray<IAsn1Encoding>): Int32;
var
  LI, LCount: Int32;
begin
  Result := 0;
  LCount := System.Length(AContentsEncodings);
  for LI := 0 to LCount - 1 do
  begin
    Result := Result + AContentsEncodings[LI].GetLength();
  end;
end;

{ TAsn1DerOutputStream }

constructor TAsn1DerOutputStream.Create(const AOs: TStream; ALeaveOpen: Boolean);
begin
  inherited Create(AOs, ALeaveOpen);
end;

function TAsn1DerOutputStream.GetEncoding: Int32;
begin
  Result := EncodingDer;
end;

{ TAsn1DLOutputStream }

constructor TAsn1DLOutputStream.Create(const AOs: TStream; ALeaveOpen: Boolean);
begin
  inherited Create(AOs, ALeaveOpen);
end;

function TAsn1DLOutputStream.GetEncoding: Int32;
begin
  Result := EncodingDL;
end;

{ TAsn1BufferedBerOctetStream }

constructor TAsn1BufferedBerOctetStream.Create(const AOutStream: TStream;
  const ABuf: TCryptoLibByteArray);
begin
  inherited Create();
  if ABuf = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SBufNil);
  FBuf := ABuf;
  FOff := 0;
  FAsn1Out := TAsn1OutputStream.CreateInstance(AOutStream, TAsn1Encodable.Ber, True);
end;

destructor TAsn1BufferedBerOctetStream.Destroy;
begin
  if FOff <> 0 then
  begin
    TDerOctetString.Encode(FAsn1Out, FBuf, 0, FOff);
    FOff := 0;
  end;

  if FAsn1Out <> nil then
  begin
    FAsn1Out.Free;
  end;
  inherited Destroy;
end;

function TAsn1BufferedBerOctetStream.Write(const ABuffer: TCryptoLibByteArray;
  AOffset, ACount: LongInt): LongInt;
var
  LBufLen, LAvailable, LPos, LRemaining: Int32;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  LBufLen := System.Length(FBuf);
  LAvailable := LBufLen - FOff;
  
  if ACount < LAvailable then
  begin
    System.Move(ABuffer[AOffset], FBuf[FOff], ACount);
    FOff := FOff + ACount;
    Result := ACount;
    Exit;
  end;
  
  LPos := 0;
  if FOff > 0 then
  begin
    System.Move(ABuffer[AOffset], FBuf[FOff], LAvailable);
    LPos := LAvailable;
    TDerOctetString.Encode(FAsn1Out, FBuf, 0, LBufLen);
  end;
  
  LRemaining := ACount - LPos;
  while LRemaining >= LBufLen do
  begin
    TDerOctetString.Encode(FAsn1Out, ABuffer, AOffset + LPos, LBufLen);
    LPos := LPos + LBufLen;
    LRemaining := LRemaining - LBufLen;
  end;
  
  if LRemaining > 0 then
  begin
    System.Move(ABuffer[AOffset + LPos], FBuf[0], LRemaining);
    FOff := LRemaining;
  end
  else
  begin
    FOff := 0;
  end;
  
  Result := ACount;
end;

procedure TAsn1BufferedBerOctetStream.WriteByte(AValue: Byte);
begin
  FBuf[FOff] := AValue;
  System.Inc(FOff);
  
  if FOff = System.Length(FBuf) then
  begin
    TDerOctetString.Encode(FAsn1Out, FBuf, 0, FOff);
    FOff := 0;
  end;
end;

{ TAsn1ConstructedBitStream }

constructor TAsn1ConstructedBitStream.Create(const AParser: IAsn1StreamParser;
  AOctetAligned: Boolean);
begin
  inherited Create();
  FParser := AParser;
  FOctetAligned := AOctetAligned;
  FFirst := True;
  FPadBits := 0;
  FCurrentParser := nil;
  FCurrentStream := nil;
end;

destructor TAsn1ConstructedBitStream.Destroy;
begin
  // We own FCurrentStream (transferred ownership) - must free it
  if FCurrentStream <> nil then
  begin
    FCurrentStream.Free;
    FCurrentStream := nil;
  end;
  FCurrentParser := nil;
  inherited Destroy;
end;

function TAsn1ConstructedBitStream.GetPadBits(): Int32;
begin
  Result := FPadBits;
end;

function TAsn1ConstructedBitStream.GetNextParser(): IAsn1BitStringParser;
var
  LAsn1Obj: IAsn1Convertible;
begin
  LAsn1Obj := FParser.ReadObject();
  if LAsn1Obj = nil then
  begin
    if FOctetAligned and (FPadBits <> 0) then
      raise EIOCryptoLibException.CreateResFmt(@SExpectedOctetAlignedBitStringButFound, [FPadBits]);

    Result := nil;
    Exit;
  end;

  if Supports(LAsn1Obj, IAsn1BitStringParser, Result) then
  begin
    if FPadBits <> 0 then
      raise EIOCryptoLibException.CreateRes(@SOnlyTheLastNestedBitStringCanHavePadding);
  end
  else
  begin
    raise EIOCryptoLibException.CreateResFmt(@SUnknownObjectEncountered, [TPlatformUtilities.GetTypeName(LAsn1Obj as TObject)]);
  end;
end;

function TAsn1ConstructedBitStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LTotalRead, LNumRead: Int32;
begin
  if ACount < 1 then
  begin
    Result := 0;
    Exit;
  end;

  if FCurrentStream = nil then
  begin
    if not FFirst then
    begin
      Result := 0;
      Exit;
    end;

    FCurrentParser := GetNextParser();
    if FCurrentParser = nil then
    begin
      Result := 0;
      Exit;
    end;

    FFirst := False;
    FCurrentStream := FCurrentParser.GetBitStream();
  end;

  LTotalRead := 0;

  while True do
  begin
    LNumRead := FCurrentStream.Read(PByte(@ABuffer)[LTotalRead], ACount - LTotalRead);

    if LNumRead > 0 then
    begin
      LTotalRead := LTotalRead + LNumRead;

      if LTotalRead = ACount then
      begin
        Result := LTotalRead;
        Exit;
      end;
    end
    else
    begin
      FPadBits := FCurrentParser.PadBits;
      FCurrentParser := GetNextParser();
      if FCurrentParser = nil then
      begin
        FreeAndNil(FCurrentStream);  // Free owned stream
        Result := LTotalRead;
        Exit;
      end;

      FreeAndNil(FCurrentStream);  // Free old stream before getting new one
      FCurrentStream := FCurrentParser.GetBitStream();
    end;
  end;
end;

function TAsn1ConstructedBitStream.Read(ABuffer: TCryptoLibByteArray;
  AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

function TAsn1ConstructedBitStream.ReadByte: Int32;
var
  LB: Int32;
begin
  if FCurrentStream = nil then
  begin
    if not FFirst then
    begin
      Result := -1;
      Exit;
    end;

    FCurrentParser := GetNextParser();
    if FCurrentParser = nil then
    begin
      Result := -1;
      Exit;
    end;

    FFirst := False;
    FCurrentStream := FCurrentParser.GetBitStream();
  end;

  while True do
  begin
    LB := FCurrentStream.ReadByte();

    if LB >= 0 then
    begin
      Result := LB;
      Exit;
    end;

    FPadBits := FCurrentParser.PadBits;
    FCurrentParser := GetNextParser();
    if FCurrentParser = nil then
    begin
      FreeAndNil(FCurrentStream);  // Free owned stream
      Result := -1;
      Exit;
    end;

    FreeAndNil(FCurrentStream);  // Free old stream before getting new one
    FCurrentStream := FCurrentParser.GetBitStream();
  end;
end;

{ TAsn1ConstructedOctetStream }

constructor TAsn1ConstructedOctetStream.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create();
  FParser := AParser;
  FFirst := True;
  FCurrentParser := nil;
  FCurrentStream := nil;
end;

destructor TAsn1ConstructedOctetStream.Destroy;
begin
  // We own FCurrentStream (transferred ownership) - must free it
  if FCurrentStream <> nil then
  begin
    FCurrentStream.Free;
    FCurrentStream := nil;
  end;
  FCurrentParser := nil;
  inherited Destroy;
end;

function TAsn1ConstructedOctetStream.GetNextParser(): IAsn1OctetStringParser;
var
  LAsn1Obj: IAsn1Convertible;
begin
  LAsn1Obj := FParser.ReadObject();
  if LAsn1Obj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if not Supports(LAsn1Obj, IAsn1OctetStringParser, Result) then
  begin
    raise EIOCryptoLibException.CreateResFmt(@SUnknownObjectEncountered, [TPlatformUtilities.GetTypeName(LAsn1Obj as TObject)]);
  end;
end;

function TAsn1ConstructedOctetStream.Read(var ABuffer; ACount: LongInt): LongInt;
var
  LTotalRead, LNumRead: Int32;
begin
  if ACount < 1 then
  begin
    Result := 0;
    Exit;
  end;

  if FCurrentStream = nil then
  begin
    if not FFirst then
    begin
      Result := 0;
      Exit;
    end;

    FCurrentParser := GetNextParser();
    if FCurrentParser = nil then
    begin
      Result := 0;
      Exit;
    end;

    FFirst := False;
    FCurrentStream := FCurrentParser.GetOctetStream();
  end;

  LTotalRead := 0;

  while True do
  begin
    LNumRead := FCurrentStream.Read(PByte(@ABuffer)[LTotalRead], ACount - LTotalRead);

    if LNumRead > 0 then
    begin
      LTotalRead := LTotalRead + LNumRead;

      if LTotalRead = ACount then
      begin
        Result := LTotalRead;
        Exit;
      end;
    end
    else
    begin
      FCurrentParser := GetNextParser();
      if FCurrentParser = nil then
      begin
        FreeAndNil(FCurrentStream);  // Free owned stream
        Result := LTotalRead;
        Exit;
      end;

      FreeAndNil(FCurrentStream);  // Free old stream before getting new one
      FCurrentStream := FCurrentParser.GetOctetStream();
    end;
  end;
end;

function TAsn1ConstructedOctetStream.Read(ABuffer: TCryptoLibByteArray;
  AOffset, ACount: LongInt): LongInt;
begin
  TStreamUtilities.ValidateBufferArguments(ABuffer, AOffset, ACount);
  Result := Read(ABuffer[AOffset], ACount);
end;

function TAsn1ConstructedOctetStream.ReadByte: Int32;
var
  LB: Int32;
begin
  if FCurrentStream = nil then
  begin
    if not FFirst then
    begin
      Result := -1;
      Exit;
    end;

    FCurrentParser := GetNextParser();
    if FCurrentParser = nil then
    begin
      Result := -1;
      Exit;
    end;

    FFirst := False;
    FCurrentStream := FCurrentParser.GetOctetStream();
  end;

  while True do
  begin
    LB := FCurrentStream.ReadByte();

    if LB >= 0 then
    begin
      Result := LB;
      Exit;
    end;

    FCurrentParser := GetNextParser();
    if FCurrentParser = nil then
    begin
      FreeAndNil(FCurrentStream);  // Free owned stream
      Result := -1;
      Exit;
    end;

    FreeAndNil(FCurrentStream);  // Free old stream before getting new one
    FCurrentStream := FCurrentParser.GetOctetStream();
  end;
end;

{ TAsn1InputStream }

constructor TAsn1InputStream.Create(const AInput: TCryptoLibByteArray);
begin
  Create(TFixedBufferStream.Create(AInput, 0, System.Length(AInput), False), System.Length(AInput));
end;

constructor TAsn1InputStream.Create(const AInput: TStream);
begin
  Create(AInput, FindLimit(AInput));
end;

constructor TAsn1InputStream.Create(const AInput: TStream; ALeaveOpen: Boolean);
begin
  Create(AInput, FindLimit(AInput), ALeaveOpen);
end;

constructor TAsn1InputStream.Create(const AInput: TStream; ALimit: Int32);
begin
  Create(AInput, ALimit, False);
end;

constructor TAsn1InputStream.Create(const AInput: TStream; ALimit: Int32;
  ALeaveOpen: Boolean);
begin
  System.SetLength(FTmp, 16);
  Create(AInput, TAsn1InputStream.FindDepth(), ALimit, ALeaveOpen, FTmp);
end;

constructor TAsn1InputStream.Create(const AInput: TStream; ADepth, ALimit: Int32;
  ALeaveOpen: Boolean; const ATmp: TCryptoLibByteArray);
begin
  inherited Create(AInput);
  if not AInput.CanRead then
    raise EArgumentCryptoLibException.CreateRes(@SExpectedStreamToBeReadable);

  FDepth := ADepth;
  FLimit := ALimit;
  FLeaveOpen := ALeaveOpen;
  FTmp := ATmp;
  FStream := AInput;
end;

destructor TAsn1InputStream.Destroy;
begin
  if not FLeaveOpen then
  begin
   if FStream <> nil then
    FStream.Free;
  end;

  inherited Destroy;
end;

class function TAsn1InputStream.FindLimit(const AInput: TStream): Int32;
var
  LAsn1LimitedInputStream: TAsn1LimitedInputStream;
  LAsn1InputStream: TAsn1InputStream;
  LAvailable: Int64;
begin
  if AInput is TAsn1LimitedInputStream then
  begin
    LAsn1LimitedInputStream := AInput as TAsn1LimitedInputStream;
    Result := LAsn1LimitedInputStream.Limit;
    Exit;
  end;

  if AInput is TAsn1InputStream then
  begin
    LAsn1InputStream := AInput as TAsn1InputStream;
    Result := LAsn1InputStream.Limit;
    Exit;
  end;

  if TStreamUtilities.TryGetAvailable(AInput, LAvailable) then
  begin
    if LAvailable > Int32.MaxValue then
      Result := Int32.MaxValue
    else
      Result := Int32(LAvailable);
    Exit;
  end;

  Result := Max(0, TCryptoLibConfig.Asn1.MaxLimit);
end;

class function TAsn1InputStream.ReadTagNumber(const AInput: TStream;
  ATagHdr: Int32): Int32;
var
  LTagNo, LB: Int32;
begin
  LTagNo := ATagHdr and $1F;

  // with tagged object tag number is bottom 5 bits, or stored at the start of the content
  if LTagNo = $1F then
  begin
    LB := AInput.ReadByte();
    if LB < 31 then
    begin
      if LB < 0 then
        raise EEndOfStreamCryptoLibException.CreateRes(@SEofFoundInsideTagValue);

      raise EIOCryptoLibException.CreateRes(@SCorruptedStreamHighTagNumber31);
    end;

    LTagNo := LB and $7F;

    // X.690-0207 8.1.2.4.2
    // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
    if 0 = LTagNo then
      raise EIOCryptoLibException.CreateRes(@SCorruptedStreamInvalidHighTagNumber);

    while (LB and $80) <> 0 do
    begin
      if ((UInt32(LTagNo) shr 24) <> 0) then
        raise EIOCryptoLibException.CreateRes(@STagNumberMoreThan31Bits);

      LTagNo := LTagNo shl 7;

      LB := AInput.ReadByte();
      if LB < 0 then
        raise EEndOfStreamCryptoLibException.CreateRes(@SEofFoundInsideTagValue);

      LTagNo := LTagNo or (LB and $7F);
    end;
  end;

  Result := LTagNo;
end;

class function TAsn1InputStream.ReadLength(const AInput: TStream): Int32;
var
  LLength, LOctetsCount, LOctetsPos, LOctet: Int32;
begin
  LLength := AInput.ReadByte();
  if (UInt32(LLength) shr 7) = 0 then
  begin
    Result := LLength;
    Exit;
  end;
  if $80 = LLength then
  begin
    Result := -1;
    Exit;
  end;
  if LLength < 0 then
  begin
    raise EEndOfStreamCryptoLibException.CreateRes(@SEofFoundWhenLengthExpected);
  end;
  if $FF = LLength then
  begin
    raise EIOCryptoLibException.CreateRes(@SInvalidLongFormDefiniteLengthFF);
  end;

  LOctetsCount := LLength and $7F;
  LOctetsPos := 0;

  LLength := 0;
  repeat
    LOctet := AInput.ReadByte();
    if LOctet < 0 then
      raise EEndOfStreamCryptoLibException.CreateRes(@SEofFoundReadingLength);

    if ((UInt32(LLength) shr 23) <> 0) then
      raise EIOCryptoLibException.CreateRes(@SLongFormDefiniteLengthMoreThan31Bits);

    LLength := (LLength shl 8) + LOctet;
    System.Inc(LOctetsPos);
  until LOctetsPos >= LOctetsCount;

  Result := LLength;
end;

function TAsn1InputStream.ReadObject(): IAsn1Object;
var
  LTagHdr, LTagNo, LLength, LTagClass: Int32;
  LIndIn: TAsn1IndefiniteLengthInputStream;
  LSp: IAsn1StreamParser;
begin
  LTagHdr := FStream.ReadByte();
  if LTagHdr <= 0 then
  begin
    if LTagHdr = 0 then
      raise EIOCryptoLibException.CreateRes(@SUnexpectedEndOfContentsMarker);

    Result := nil;
    Exit;
  end;

  LTagNo := ReadTagNumber(FStream, LTagHdr);
  LLength := ReadLength(FStream);

  if LLength >= 0 then
  begin
    // definite-length
    try
      Result := BuildObject(LTagHdr, LTagNo, LLength);
    except
      on E: EArgumentCryptoLibException do
        raise EAsn1CryptoLibException.CreateResFmt(@SCorruptedStreamDetected, [E.Message]);
      on E: EInvalidOperationCryptoLibException do
        raise EAsn1CryptoLibException.CreateResFmt(@SCorruptedStreamDetected, [E.Message]);
      on E: EIndexOutOfRangeCryptoLibException do
        raise EAsn1CryptoLibException.CreateResFmt(@SCorruptedStreamDetected, [E.Message]);
    end;
  end
  else
  begin
    // indefinite-length
    if 0 = (LTagHdr and TAsn1Tags.Constructed) then
      raise EIOCryptoLibException.CreateRes(@SIndefiniteLengthPrimitiveEncodingEncountered);

    LIndIn := TAsn1IndefiniteLengthInputStream.Create(FStream, FLimit);
    LSp := TAsn1StreamParser.CreateSubParser(LIndIn, FDepth, FLimit, FTmp);

    LTagClass := LTagHdr and TAsn1Tags.Private;
    if 0 <> LTagClass then
    begin
      Result := LSp.LoadTaggedIL(LTagClass, LTagNo);
      Exit;
    end;

    // Handle switch cases for indefinite-length
    case LTagNo of
      TAsn1Tags.BitString:
        Result := TBerBitStringParser.Parse(LSp);
      TAsn1Tags.OctetString:
        Result := TBerOctetStringParser.Parse(LSp);
      TAsn1Tags.Sequence:
        Result := TBerSequenceParser.Parse(LSp);
      TAsn1Tags.&Set:
        Result := TBerSetParser.Parse(LSp);
      TAsn1Tags.External:
        Result := TDerExternalParser.Parse(LSp);
    else
      raise EIOCryptoLibException.CreateResFmt(@SUnknownBerObjectEncountered, [LTagNo]);
    end;
  end;
end;

function TAsn1InputStream.BuildObject(ATagHdr, ATagNo, ALength: Int32)
  : IAsn1Object;
var
  LDefIn: TAsn1DefiniteLengthInputStream;
  LTagClass: Int32;
  LIsConstructed: Boolean;
begin
  CheckLength(ALength, FLimit);
  LDefIn := TAsn1DefiniteLengthInputStream.Create(FStream, ALength, ALength);
  try
    if 0 = (ATagHdr and TAsn1Tags.Flags) then
    begin
      Result := CreatePrimitiveDerObject(ATagNo, LDefIn, FTmp);
      Exit;
    end;

    LTagClass := ATagHdr and TAsn1Tags.Private;
    if 0 <> LTagClass then
    begin
      LIsConstructed := (ATagHdr and TAsn1Tags.Constructed) <> 0;
      Result := ReadTaggedObjectDL(LTagClass, ATagNo, LIsConstructed, LDefIn);
      Exit;
    end;

    case ATagNo of
      TAsn1Tags.BitString:
        Result := BuildConstructedBitString(ReadVector(LDefIn));
      TAsn1Tags.OctetString:
        Result := BuildConstructedOctetString(ReadVector(LDefIn));
      TAsn1Tags.Sequence:
        begin
          Result := TDLSequence.FromVector(ReadVector(LDefIn));
        end;
      TAsn1Tags.&Set:
        begin
          Result := TDLSet.FromVector(ReadVector(LDefIn));
        end;
      TAsn1Tags.External:
        begin
          Result := TDLSequence.FromVector(ReadVector(LDefIn)).ToAsn1External();
        end;
    else
      raise EIOCryptoLibException.CreateResFmt(@SUnknownTagEncountered, [ATagNo]);
    end;
  finally
    LDefIn.Free;
  end;
end;

function TAsn1InputStream.ReadTaggedObjectDL(ATagClass, ATagNo: Int32;
  AConstructed: Boolean; const ADefIn: TAsn1DefiniteLengthInputStream)
  : IAsn1Object;
var
  LContentsOctets: TCryptoLibByteArray;
  LContentsElements: IAsn1EncodableVector;
begin
  if not AConstructed then
  begin
    // Primitive - read contents as octets
    LContentsOctets := ADefIn.ToArray();
    Result := TAsn1TaggedObject.CreatePrimitive(ATagClass, ATagNo, LContentsOctets);
  end
  else
  begin
    // Constructed - read contents as elements
    LContentsElements := ReadVector(ADefIn);
    Result := TAsn1TaggedObject.CreateConstructedDL(ATagClass, ATagNo, LContentsElements);
  end;
end;

function TAsn1InputStream.ReadVector(): IAsn1EncodableVector;
var
  LO: IAsn1Object;
  LV: IAsn1EncodableVector;
begin
  LO := ReadObject();
  if LO = nil then
  begin
    Result := TAsn1EncodableVector.Create(0);
    Exit;
  end;

  LV := TAsn1EncodableVector.Create();
  repeat
    LV.Add(LO);
    LO := ReadObject();
  until LO = nil;

  Result := LV;
end;

function TAsn1InputStream.ReadVector(const ADefIn: TAsn1DefiniteLengthInputStream)
  : IAsn1EncodableVector;
var
  LRemaining: Int32;
  LSub: TAsn1InputStream;
begin
  LRemaining := ADefIn.Remaining;
  if LRemaining < 1 then
  begin
    Result := TAsn1EncodableVector.Create(0);
    Exit;
  end;

  LSub := CreateSubStream(ADefIn, LRemaining);
  try
    Result := LSub.ReadVector();
  finally
    LSub.Free;
  end;
end;

function TAsn1InputStream.BuildConstructedBitString(const AContentsElements
  : IAsn1EncodableVector): IAsn1Object;
var
  LBitStrings: TCryptoLibGenericArray<IDerBitString>;
  LCount, LI: Int32;
  LBitString: IDerBitString;
begin
  LCount := AContentsElements.Count;
  System.SetLength(LBitStrings, LCount);
  for LI := 0 to LCount - 1 do
  begin
    if not Supports(AContentsElements[LI], IDerBitString, LBitString) then
      raise EAsn1CryptoLibException.CreateResFmt(@SUnknownObjectEncounteredInConstructed, ['BIT STRING', TPlatformUtilities.GetTypeName(AContentsElements[LI] as TObject)]);
    LBitStrings[LI] := LBitString;
  end;

  Result := TDLBitString.Create(TBerBitString.FlattenBitStrings(LBitStrings), False);
end;

class function TAsn1InputStream.BuildConstructedOctetString(const AContentsElements
  : IAsn1EncodableVector): IAsn1Object;
var
  LOctetStrings: TCryptoLibGenericArray<IAsn1OctetString>;
  LCount, LI: Int32;
  LOctetString: IAsn1OctetString;
begin
  LCount := AContentsElements.Count;
  System.SetLength(LOctetStrings, LCount);
  for LI := 0 to LCount - 1 do
  begin
    if not Supports(AContentsElements[LI], IAsn1OctetString, LOctetString) then
      raise EAsn1CryptoLibException.CreateResFmt(@SUnknownObjectEncounteredInConstructed, ['OCTET STRING', TPlatformUtilities.GetTypeName(AContentsElements[LI] as TObject)]);
    LOctetStrings[LI] := LOctetString;
  end;

  // Note: No DLOctetString available, use TDerOctetString.WithContents
  Result := TDerOctetString.WithContents(TBerOctetString.FlattenOctetStrings(LOctetStrings));
end;

class function TAsn1InputStream.CreatePrimitiveDerObject(ATagNo: Int32;
  const ADefIn: TAsn1DefiniteLengthInputStream;
  const ATmp: TCryptoLibByteArray): IAsn1Object;
var
  LBytes: TCryptoLibByteArray;
begin
  case ATagNo of
    TAsn1Tags.BmpString:
      begin
        Result := TDerBmpString.CreatePrimitive(ADefIn);
        Exit;
      end;
    TAsn1Tags.Boolean:
      begin
        Result := TDerBoolean.CreatePrimitive(ADefIn);
        Exit;
      end;
    TAsn1Tags.Enumerated:
      begin
        Result := TDerEnumerated.CreatePrimitive(ADefIn);
        Exit;
      end;
    TAsn1Tags.Null:
      begin
        Result := TAsn1Null.CreatePrimitive(ADefIn);
        Exit;
      end;
    TAsn1Tags.ObjectIdentifier:
      begin
        Result := TDerObjectIdentifier.CreatePrimitive(ADefIn, ATmp);
        Exit;
      end;
    TAsn1Tags.RelativeOid:
      begin
        Result := TAsn1RelativeOid.CreatePrimitive(ADefIn, ATmp);
        Exit;
      end;
  end;

  LBytes := ADefIn.ToArray();

  case ATagNo of
    TAsn1Tags.BitString:
      Result := TDerBitString.CreatePrimitive(LBytes);
    TAsn1Tags.GeneralizedTime:
      Result := TAsn1GeneralizedTime.CreatePrimitive(LBytes);
    TAsn1Tags.GeneralString:
      Result := TDerGeneralString.CreatePrimitive(LBytes);
    TAsn1Tags.GraphicString:
      Result := TDerGraphicString.CreatePrimitive(LBytes);
    TAsn1Tags.IA5String:
      Result := TDerIA5String.CreatePrimitive(LBytes);
    TAsn1Tags.Integer:
      Result := TDerInteger.CreatePrimitive(LBytes);
    TAsn1Tags.NumericString:
      Result := TDerNumericString.CreatePrimitive(LBytes);
    TAsn1Tags.ObjectDescriptor:
      Result := TAsn1ObjectDescriptor.CreatePrimitive(LBytes);
    TAsn1Tags.OctetString:
      Result := TAsn1OctetString.CreatePrimitive(LBytes);
    TAsn1Tags.PrintableString:
      Result := TDerPrintableString.CreatePrimitive(LBytes);
    TAsn1Tags.T61String:
      Result := TDerT61String.CreatePrimitive(LBytes);
    TAsn1Tags.UniversalString:
      Result := TDerUniversalString.CreatePrimitive(LBytes);
    TAsn1Tags.UtcTime:
      Result := TAsn1UtcTime.CreatePrimitive(LBytes);
    TAsn1Tags.Utf8String:
      Result := TDerUtf8String.CreatePrimitive(LBytes);
    TAsn1Tags.VideotexString:
      Result := TDerVideotexString.CreatePrimitive(LBytes);
    TAsn1Tags.VisibleString:
      Result := TDerVisibleString.CreatePrimitive(LBytes);

    TAsn1Tags.Real,
    TAsn1Tags.EmbeddedPdv,
    TAsn1Tags.Time,
    TAsn1Tags.UnrestrictedString,
    TAsn1Tags.Date,
    TAsn1Tags.TimeOfDay,
    TAsn1Tags.DateTime,
    TAsn1Tags.Duration,
    TAsn1Tags.ObjectIdentifierIri,
    TAsn1Tags.RelativeOidIri:
      raise EIOCryptoLibException.CreateResFmt(@SUnsupportedTagEncountered, [ATagNo]);
  else
    raise EIOCryptoLibException.CreateResFmt(@SUnknownTagEncountered, [ATagNo]);
  end;
end;

end.
