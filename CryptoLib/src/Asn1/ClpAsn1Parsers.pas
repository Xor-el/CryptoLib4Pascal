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

unit ClpAsn1Parsers;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes,
  ClpAsn1Tags,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpIAsn1Parsers,
  ClpAsn1Core,
  ClpAsn1Streams;

type
  /// <summary>
  /// ASN.1 stream parser for reading ASN.1 objects from a stream.
  /// </summary>
  TAsn1StreamParser = class sealed(TInterfacedObject, IAsn1StreamParser)
  strict private
    FIn: TStream;
    FLimit: Int32;
    FTmpBuffers: TCryptoLibMatrixByteArray;

    procedure Set00Check(AEnabled: Boolean);
    function ImplParseObject(ATagHdr: Int32): IAsn1Convertible;
    function ParseImplicitPrimitive(AUnivTagNo: Int32;
      const ADefIn: TAsn1DefiniteLengthInputStream): IAsn1Convertible; overload;

  public
    /// <summary>
    /// Create an ASN.1 stream parser from a stream.
    /// </summary>
    constructor Create(const AInput: TStream); overload;
    /// <summary>
    /// Create an ASN.1 stream parser from a byte array.
    /// </summary>
    constructor Create(const AEncoding: TCryptoLibByteArray); overload;
    /// <summary>
    /// Create an ASN.1 stream parser from a stream with a limit.
    /// </summary>
    constructor Create(const AInput: TStream; ALimit: Int32); overload;
    /// <summary>
    /// Public constructor with TmpBuffers.
    /// </summary>
    constructor Create(const AInput: TStream; ALimit: Int32;
      const ATmpBuffers: TCryptoLibMatrixByteArray); overload;

    destructor Destroy; override;

    /// <summary>
    /// Read the next object from the stream.
    /// </summary>
    function ReadObject(): IAsn1Convertible; virtual;
    /// <summary>
    /// Parse an object with a specific universal tag number.
    /// </summary>
    function ParseObject(AUnivTagNo: Int32): IAsn1Convertible;
    /// <summary>
    /// Parse an implicit constructed indefinite-length object.
    /// </summary>
    function ParseImplicitConstructedIL(AUnivTagNo: Int32): IAsn1Convertible;
    /// <summary>
    /// Parse an implicit constructed definite-length object.
    /// </summary>
    function ParseImplicitConstructedDL(AUnivTagNo: Int32): IAsn1Convertible;
    /// <summary>
    /// Parse an implicit primitive object.
    /// </summary>
    function ParseImplicitPrimitive(AUnivTagNo: Int32): IAsn1Convertible; overload;
    /// <summary>
    /// Parse a tagged object.
    /// </summary>
    function ParseTaggedObject(): IAsn1TaggedObjectParser;
    /// <summary>
    /// Load a tagged object with definite length.
    /// </summary>
    function LoadTaggedDL(ATagClass, ATagNo: Int32; AConstructed: Boolean): IAsn1Object;
    /// <summary>
    /// Load a tagged object with indefinite length.
    /// </summary>
    function LoadTaggedIL(ATagClass, ATagNo: Int32): IAsn1Object;

  strict private
    /// <summary>
    /// Read a vector of ASN.1 objects.
    /// </summary>
    function ReadVector(): IAsn1EncodableVector;
  end;


  /// <summary>
  /// Base class for ASN.1 bit string parsers.
  /// </summary>
  TAsn1BitStringParser = class abstract(TInterfacedObject, IAsn1BitStringParser)
  public
    /// <summary>
    /// Return a stream representing the contents of the BIT STRING.
    /// </summary>
    function GetBitStream(): TStream; virtual; abstract;
    /// <summary>
    /// Return a stream representing the contents of the BIT STRING, where the content is
    /// expected to be octet-aligned.
    /// </summary>
    function GetOctetStream(): TStream; virtual; abstract;
    /// <summary>
    /// Return the number of pad bits in the final byte.
    /// </summary>
    function GetPadBits(): Int32; virtual; abstract;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; virtual; abstract;

    property PadBits: Int32 read GetPadBits;
  end;

  /// <summary>
  /// Base class for ASN.1 octet string parsers.
  /// </summary>
  TAsn1OctetStringParser = class abstract(TInterfacedObject, IAsn1OctetStringParser)
  public
    /// <summary>
    /// Return the content of the OCTET STRING as a stream.
    /// </summary>
    function GetOctetStream(): TStream; virtual; abstract;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; virtual; abstract;
  end;

  /// <summary>
  /// Parser for BER bit strings.
  /// </summary>
  TBerBitStringParser = class sealed(TAsn1BitStringParser, IAsn1Convertible, IAsn1BitStringParser, IBerBitStringParser)
  strict private
    FParser: IAsn1StreamParser;
    FBitStream: TAsn1ConstructedBitStream;

  public
    /// <summary>
    /// Create a BER bit string parser.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);

    /// <summary>
    /// Return a <see cref="Stream"/> representing the contents of the BIT STRING. The final byte, if any,
    /// may include pad bits. See <see cref="PadBits"/>.
    /// </summary>
    /// <remarks>
    ///  Returns NEW stream - caller owns it and MUST free it.
    /// </remarks>
    /// <returns>A <see cref="Stream"/> with its source as the BIT STRING content.</returns>
    function GetBitStream(): TStream; override;
    /// <summary>Return a <see cref="Stream"/> representing the contents of the BIT STRING, where the content is
    /// expected to be octet-aligned (this will be automatically checked during parsing).
    ///</summary>
    /// <remarks>
    ///  Returns NEW stream - caller owns it and MUST free it.
    /// </remarks>
    /// <returns>A <see cref="Stream"/> with its source as the BIT STRING content.</returns>
    function GetOctetStream(): TStream; override;
    /// <summary>
    /// Return the number of pad bits, if any, in the final byte, if any, read from
    /// <see cref="GetBitStream"/>.
    /// </summary>
    /// <remarks>
    /// This number is in the range zero to seven. That number of the least significant bits of the final byte, if
    /// any, are not part of the contents and should be ignored. NOTE: Must be called AFTER the stream has been
    /// fully processed (before it is freed). (Does not need to be called if <see cref="GetOctetStream"/> was used instead of
    /// <see cref="GetBitStream"/>.
    /// </remarks>
    /// <returns>The number of pad bits. In the range zero to seven.</returns>
    function GetPadBits(): Int32; override;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;
    /// <summary>
    /// Parse a BER bit string from a stream parser.
    /// </summary>
    class function Parse(const ASp: IAsn1StreamParser): IBerBitString; static;
  end;

  /// <summary>
  /// Parser for BER octet strings.
  /// </summary>
  TBerOctetStringParser = class sealed(TAsn1OctetStringParser, IAsn1Convertible, IAsn1OctetStringParser, IBerOctetStringParser)
  strict private
    FParser: IAsn1StreamParser;

  public
    /// <summary>
    /// Create a BER octet string parser.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);

    /// <summary>
    /// Get the octet stream. Returns a NEW stream - caller owns it.
    /// </summary>
    function GetOctetStream(): TStream; override;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;
    /// <summary>
    /// Parse a BER octet string from a stream parser.
    /// </summary>
    class function Parse(const ASp: IAsn1StreamParser): IBerOctetString; static;
  end;

  /// <summary>
  /// Parser for DER octet strings.
  /// </summary>
  TDerOctetStringParser = class sealed(TAsn1OctetStringParser, IAsn1Convertible, IAsn1OctetStringParser)
  strict private
    FStream: TAsn1DefiniteLengthInputStream;

  public
    /// <summary>
    /// Create a DER octet string parser.
    /// </summary>
    constructor Create(const AStream: TAsn1DefiniteLengthInputStream);

    destructor Destroy; override;

    /// <summary>
    /// Get the octet stream.
    /// </summary>
    function GetOctetStream(): TStream; override;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;
  end;

  /// <summary>
  /// Parser for DL bit strings.
  /// </summary>
  TDLBitStringParser = class sealed(TAsn1BitStringParser, IAsn1Convertible, IAsn1BitStringParser)
  strict private
    FStream: TAsn1DefiniteLengthInputStream;
    FPadBits: Int32;

    function GetBitStreamInternal(AOctetAligned: Boolean): TStream;

  public
    /// <summary>
    /// Create a DL bit string parser.
    /// </summary>
    constructor Create(const AStream: TAsn1DefiniteLengthInputStream);

    destructor Destroy; override;

    /// <summary>
    /// Get the bit stream.
    /// </summary>
    function GetBitStream(): TStream; override;
    /// <summary>
    /// Get the octet stream.
    /// </summary>
    function GetOctetStream(): TStream; override;
    /// <summary>
    /// Get the number of pad bits.
    /// </summary>
    function GetPadBits(): Int32; override;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;
  end;

  /// <summary>
  /// Parser for DER sequences.
  /// </summary>
  TDerSequenceParser = class sealed(TInterfacedObject, IAsn1Convertible, IAsn1SequenceParser, IDerSequenceParser)
  strict private
    FParser: IAsn1StreamParser;

  public
    /// <summary>
    /// Create a DER sequence parser.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);

    /// <summary>
    /// Read the next object from the sequence.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object;
  end;

  /// <summary>
  /// Parser for DER sets.
  /// </summary>
  TDerSetParser = class sealed(TInterfacedObject, IAsn1Convertible, IAsn1SetParser, IDerSetParser)
  strict private
    FParser: IAsn1StreamParser;

  public
    /// <summary>
    /// Create a DER set parser.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);

    /// <summary>
    /// Read the next object from the set.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object;
  end;

  /// <summary>
  /// Parser for BER sequences.
  /// </summary>
  TBerSequenceParser = class sealed(TInterfacedObject, IAsn1Convertible, IAsn1SequenceParser, IBerSequenceParser)
  strict private
    FParser: IAsn1StreamParser;

  public
    /// <summary>
    /// Create a BER sequence parser.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);

    /// <summary>
    /// Read the next object from the sequence.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object;
    /// <summary>
    /// Parse a BER sequence from a stream parser.
    /// </summary>
    class function Parse(const ASp: IAsn1StreamParser): IBerSequence; static;
  end;

  /// <summary>
  /// Parser for BER sets.
  /// </summary>
  TBerSetParser = class sealed(TInterfacedObject, IAsn1Convertible, IAsn1SetParser, IBerSetParser)
  strict private
    FParser: IAsn1StreamParser;

  public
    /// <summary>
    /// Create a BER set parser.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);

    /// <summary>
    /// Read the next object from the set.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object;
    /// <summary>
    /// Parse a BER set from a stream parser.
    /// </summary>
    class function Parse(const ASp: IAsn1StreamParser): IBerSet; static;
  end;

  /// <summary>
  /// Parser for DER external objects.
  /// </summary>
  TDerExternalParser = class sealed(TAsn1Encodable, IDerExternalParser)
  strict private
    FParser: IAsn1StreamParser;

  public
    /// <summary>
    /// Create a DER external parser.
    /// </summary>
    constructor Create(const AParser: IAsn1StreamParser);

    /// <summary>
    /// Read the next object.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;
    /// <summary>
    /// Parse a DER external from a stream parser.
    /// </summary>
    class function Parse(const ASp: IAsn1StreamParser): IDerExternal; static;
  end;

  /// <summary>
  /// Parser for BER tagged objects.
  /// </summary>
  TBerTaggedObjectParser = class(TInterfacedObject, IAsn1Convertible, IAsn1TaggedObjectParser, IBerTaggedObjectParser)
  strict protected
    FTagClass: Int32;
    FTagNo: Int32;
    FParser: IAsn1StreamParser;

  public
    /// <summary>
    /// Create a BER tagged object parser.
    /// </summary>
    constructor Create(ATagClass, ATagNo: Int32; const AParser: IAsn1StreamParser);

    /// <summary>
    /// Get the tag class.
    /// </summary>
    function GetTagClass(): Int32;
    /// <summary>
    /// Get the tag number.
    /// </summary>
    function GetTagNo(): Int32;
    /// <summary>
    /// Check if this is a constructed object.
    /// </summary>
    function GetIsConstructed(): Boolean; virtual;
    /// <summary>
    /// Check if this has a context tag.
    /// </summary>
    function HasContextTag(ATagNo: Int32): Boolean;
    /// <summary>
    /// Check if this has the specified tag.
    /// </summary>
    function HasTag(ATagClass, ATagNo: Int32): Boolean; virtual;
    /// <summary>
    /// Parse a base universal object.
    /// </summary>
    function ParseBaseUniversal(ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible; virtual;
    /// <summary>
    /// Parse an explicit base object.
    /// </summary>
    function ParseExplicitBaseObject(): IAsn1Convertible; virtual;
    /// <summary>
    /// Parse an explicit base tagged object.
    /// </summary>
    function ParseExplicitBaseTagged(): IAsn1TaggedObjectParser; virtual;
    /// <summary>
    /// Parse an implicit base tagged object.
    /// </summary>
    function ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser; virtual;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; virtual;

    property TagClass: Int32 read GetTagClass;
    property TagNo: Int32 read GetTagNo;
  end;

  /// <summary>
  /// Parser for DL tagged objects.
  /// </summary>
  TDLTaggedObjectParser = class sealed(TBerTaggedObjectParser, IAsn1TaggedObjectParser, IDLTaggedObjectParser)
  strict private
    FConstructed: Boolean;

    function CheckConstructed(): IAsn1StreamParser;

  public
    /// <summary>
    /// Check if this is a constructed object.
    /// </summary>
    function GetIsConstructed(): Boolean; override;
    /// <summary>
    /// Create a DL tagged object parser.
    /// </summary>
    constructor Create(ATagClass, ATagNo: Int32; AConstructed: Boolean;
      const AParser: IAsn1StreamParser);

    /// <summary>
    /// Parse a base universal object.
    /// </summary>
    function ParseBaseUniversal(ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible; override;
    /// <summary>
    /// Parse an explicit base object.
    /// </summary>
    function ParseExplicitBaseObject(): IAsn1Convertible; override;
    /// <summary>
    /// Parse an explicit base tagged object.
    /// </summary>
    function ParseExplicitBaseTagged(): IAsn1TaggedObjectParser; override;
    /// <summary>
    /// Parse an implicit base tagged object.
    /// </summary>
    function ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser; override;
    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;
  end;

implementation

uses
  ClpAsn1Objects,
  ClpStreamUtilities,

  ClpStreams;

{ TAsn1StreamParser }

constructor TAsn1StreamParser.Create(const AInput: TStream);
begin
  Create(AInput, TAsn1InputStream.FindLimit(AInput));
end;

constructor TAsn1StreamParser.Create(const AEncoding: TCryptoLibByteArray);
begin
  Create(TFixedBufferStream.Create(AEncoding, 0, System.Length(AEncoding), False), System.Length(AEncoding));
end;

constructor TAsn1StreamParser.Create(const AInput: TStream; ALimit: Int32);
var
  LTmpBuffers: TCryptoLibMatrixByteArray;
  I: Int32;
begin
  System.SetLength(LTmpBuffers, 16);
  for I := 0 to System.Length(LTmpBuffers) - 1 do
    System.SetLength(LTmpBuffers[I], 0);
  Create(AInput, ALimit, LTmpBuffers);
end;

constructor TAsn1StreamParser.Create(const AInput: TStream; ALimit: Int32;
  const ATmpBuffers: TCryptoLibMatrixByteArray);
begin
  inherited Create;
  if not AInput.CanRead then
    raise EArgumentCryptoLibException.Create('Expected stream to be readable');

  FIn := AInput;
  FLimit := ALimit;
  FTmpBuffers := ATmpBuffers;
end;

destructor TAsn1StreamParser.Destroy;
begin
  // Parser ALWAYS owns and frees its stream
  if FIn <> nil then
  begin
    FIn.Free;
    FIn := nil;
  end;
  inherited Destroy;
end;

function TAsn1StreamParser.ReadObject(): IAsn1Convertible;
var
  LTagHdr: Int32;
begin
  LTagHdr := FIn.ReadByte();
  if LTagHdr < 0 then
  begin
    Result := nil;
    Exit;
  end;

  Result := ImplParseObject(LTagHdr);
end;

procedure TAsn1StreamParser.Set00Check(AEnabled: Boolean);
var
  LIndefiniteLengthInputStream: TAsn1IndefiniteLengthInputStream;
begin
  if FIn is TAsn1IndefiniteLengthInputStream then
  begin
    LIndefiniteLengthInputStream := FIn as TAsn1IndefiniteLengthInputStream;
    LIndefiniteLengthInputStream.SetEofOn00(AEnabled);
  end;
end;

function TAsn1StreamParser.ImplParseObject(ATagHdr: Int32): IAsn1Convertible;
var
  LTagNo, LLength, LTagClass: Int32;
  LIndIn: TAsn1IndefiniteLengthInputStream;
  LDefIn: TAsn1DefiniteLengthInputStream;
  LSp: IAsn1StreamParser;
  LIsConstructed: Boolean;
begin
  // turn off looking for "00" while we resolve the tag
  Set00Check(False);

  // calculate tag number
  LTagNo := TAsn1InputStream.ReadTagNumber(FIn, ATagHdr);

  // calculate length
  LLength := TAsn1InputStream.ReadLength(FIn, FLimit,
    (LTagNo = TAsn1Tags.BitString) or (LTagNo = TAsn1Tags.OctetString) or
    (LTagNo = TAsn1Tags.Sequence) or (LTagNo = TAsn1Tags.&Set) or
    (LTagNo = TAsn1Tags.External));

  if LLength < 0 then // indefinite-length method
  begin
    if 0 = (ATagHdr and TAsn1Tags.Constructed) then
      raise EIOCryptoLibException.Create
        ('indefinite-length primitive encoding encountered');

    LIndIn := TAsn1IndefiniteLengthInputStream.Create(FIn, FLimit);
    try
      LSp := TAsn1StreamParser.Create(LIndIn, FLimit, FTmpBuffers);
    except
      LIndIn.Free;
      raise;
    end;

    LTagClass := ATagHdr and TAsn1Tags.Private;
    if 0 <> LTagClass then
    begin
      Result := TBerTaggedObjectParser.Create(LTagClass, LTagNo, LSp);
      Exit;
    end;

    Result := LSp.ParseImplicitConstructedIL(LTagNo);
  end
  else
  begin
    LDefIn := TAsn1DefiniteLengthInputStream.Create(FIn, LLength, FLimit);

    if 0 = (ATagHdr and TAsn1Tags.Flags) then
    begin
      try
        Result := ParseImplicitPrimitive(LTagNo, LDefIn);
      except
        LDefIn.Free;
        raise;
      end;
      Exit;
    end;

    try
      LSp := TAsn1StreamParser.Create(LDefIn, LDefIn.Remaining, FTmpBuffers);
    except
      LDefIn.Free;
      raise;
    end;

    LTagClass := ATagHdr and TAsn1Tags.Private;
    if 0 <> LTagClass then
    begin
      LIsConstructed := (ATagHdr and TAsn1Tags.Constructed) <> 0;
      Result := TDLTaggedObjectParser.Create(LTagClass, LTagNo, LIsConstructed, LSp);
      Exit;
    end;

    Result := LSp.ParseImplicitConstructedDL(LTagNo);
  end;
end;

function TAsn1StreamParser.ParseImplicitConstructedDL(AUnivTagNo: Int32)
  : IAsn1Convertible;
begin
  case AUnivTagNo of
    TAsn1Tags.BitString:
      // TODO[asn1] DLConstructedBitStringParser
      Result := TBerBitStringParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.External:
      // TODO[asn1] DLExternalParser
      Result := TDerExternalParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.OctetString:
      // TODO[asn1] DLConstructedOctetStringParser
      Result := TBerOctetStringParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.&Set:
      // TODO[asn1] DLSetParser
      Result := TDerSetParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.Sequence:
      // TODO[asn1] DLSequenceParser
      Result := TDerSequenceParser.Create(Self as IAsn1StreamParser);
  else
    raise EAsn1CryptoLibException.CreateFmt
      ('unknown DL object encountered: 0x%x', [AUnivTagNo]);
  end;
end;

function TAsn1StreamParser.ParseImplicitConstructedIL(AUnivTagNo: Int32)
  : IAsn1Convertible;
begin
  case AUnivTagNo of
    TAsn1Tags.BitString:
      Result := TBerBitStringParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.External:
      // TODO[asn1] BERExternalParser
      Result := TDerExternalParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.OctetString:
      Result := TBerOctetStringParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.Sequence:
      Result := TBerSequenceParser.Create(Self as IAsn1StreamParser);
    TAsn1Tags.&Set:
      Result := TBerSetParser.Create(Self as IAsn1StreamParser);
  else
    raise EAsn1CryptoLibException.CreateFmt
      ('unknown BER object encountered: 0x%x', [AUnivTagNo]);
  end;
end;

function TAsn1StreamParser.ParseImplicitPrimitive(AUnivTagNo: Int32)
  : IAsn1Convertible;
begin
  if FIn is TAsn1DefiniteLengthInputStream then
    Result := ParseImplicitPrimitive(AUnivTagNo,
      FIn as TAsn1DefiniteLengthInputStream)
  else
    raise EAsn1CryptoLibException.Create
      ('ParseImplicitPrimitive requires DefiniteLengthInputStream');
end;

function TAsn1StreamParser.ParseImplicitPrimitive(AUnivTagNo: Int32;
  const ADefIn: TAsn1DefiniteLengthInputStream): IAsn1Convertible;
begin
  // Some primitive encodings can be handled by parsers too...
  case AUnivTagNo of
    TAsn1Tags.BitString:
      Result := TDLBitStringParser.Create(ADefIn);
    TAsn1Tags.External:
      raise EAsn1CryptoLibException.Create
        ('externals must use constructed encoding (see X.690 8.18)');
    TAsn1Tags.OctetString:
      Result := TDerOctetStringParser.Create(ADefIn);
    TAsn1Tags.&Set:
      raise EAsn1CryptoLibException.Create
        ('sequences must use constructed encoding (see X.690 8.9.1/8.10.1)');
    TAsn1Tags.Sequence:
      raise EAsn1CryptoLibException.Create
        ('sets must use constructed encoding (see X.690 8.11.1/8.12.1)');
  else
    begin
      try
        Result := TAsn1InputStream.CreatePrimitiveDerObject(AUnivTagNo, ADefIn, FTmpBuffers);
        ADefIn.Free;
      except
        on e: EArgumentCryptoLibException do
          raise EAsn1CryptoLibException.Create('corrupted stream detected: ' + e.Message);
      end;
    end;
  end;
end;

function TAsn1StreamParser.LoadTaggedDL(ATagClass, ATagNo: Int32; AConstructed: Boolean): IAsn1Object;
var
  LContentsOctets: TCryptoLibByteArray;
  LDefIn: TAsn1DefiniteLengthInputStream;
  LContentsElements: IAsn1EncodableVector;
begin
  if not AConstructed then
  begin
    LDefIn := FIn as TAsn1DefiniteLengthInputStream;
    LContentsOctets := LDefIn.ToArray();
    Result := TAsn1TaggedObject.CreatePrimitive(ATagClass, ATagNo, LContentsOctets);
  end
  else
  begin
    LContentsElements := ReadVector();
    Result := TAsn1TaggedObject.CreateConstructedDL(ATagClass, ATagNo, LContentsElements);
  end;
end;

function TAsn1StreamParser.LoadTaggedIL(ATagClass, ATagNo: Int32): IAsn1Object;
var
  LContentsElements: IAsn1EncodableVector;
begin
  LContentsElements := ReadVector();
  Result := TAsn1TaggedObject.CreateConstructedIL(ATagClass, ATagNo, LContentsElements);
end;

function TAsn1StreamParser.ReadVector(): IAsn1EncodableVector;
var
  LTagHdr: Int32;
  LObj: IAsn1Convertible;
  LV: TAsn1EncodableVector;
begin
  LTagHdr := FIn.ReadByte();
  if LTagHdr < 0 then
  begin
    Result := TAsn1EncodableVector.Create(0);
    Exit;
  end;

  LV := TAsn1EncodableVector.Create();
  try
    repeat
      LObj := ImplParseObject(LTagHdr);
      LV.Add(LObj.ToAsn1Object());
      LTagHdr := FIn.ReadByte();
    until LTagHdr < 0;
    Result := LV;
    LV := nil; // Don't free, interface owns it
  finally
    if LV <> nil then
      LV.Free;
  end;
end;

function TAsn1StreamParser.ParseObject(AUnivTagNo: Int32): IAsn1Convertible;
var
  LTagHdr: Int32;
begin
  if (AUnivTagNo < 0) or (AUnivTagNo > 30) then
    raise EArgumentCryptoLibException.CreateFmt('invalid universal tag number: %d', [AUnivTagNo]);

  LTagHdr := FIn.ReadByte();
  if LTagHdr < 0 then
  begin
    Result := nil;
    Exit;
  end;

  if ((LTagHdr and not TAsn1Tags.Constructed) <> AUnivTagNo) then
    raise EIOCryptoLibException.CreateFmt('unexpected identifier encountered: %d', [LTagHdr]);

  Result := ImplParseObject(LTagHdr);
end;

function TAsn1StreamParser.ParseTaggedObject(): IAsn1TaggedObjectParser;
var
  LTagHdr, LTagClass: Int32;
  LResult: IAsn1Convertible;
begin
  LTagHdr := FIn.ReadByte();
  if LTagHdr < 0 then
  begin
    Result := nil;
    Exit;
  end;

  LTagClass := LTagHdr and TAsn1Tags.Private;
  if LTagClass = 0 then
    raise EAsn1CryptoLibException.Create('no tagged object found');

  LResult := ImplParseObject(LTagHdr);
  Result := LResult as IAsn1TaggedObjectParser;
end;

{ TBerBitStringParser }

constructor TBerBitStringParser.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FParser := AParser;
  FBitStream := nil;
end;

function TBerBitStringParser.GetBitStream(): TStream;
begin
  FBitStream := TAsn1ConstructedBitStream.Create(FParser, False);
  Result := FBitStream;
end;

function TBerBitStringParser.GetOctetStream(): TStream;
begin
  FBitStream := TAsn1ConstructedBitStream.Create(FParser, True);
  Result := FBitStream;
end;

function TBerBitStringParser.GetPadBits(): Int32;
begin
  Result := FBitStream.PadBits;
end;


function TBerBitStringParser.ToAsn1Object(): IAsn1Object;
begin
  try
    Result := Parse(FParser);
  except
    on E: EIOCryptoLibException do
      raise EAsn1ParsingCryptoLibException.Create('IOException converting stream to byte array: ' + E.Message);
  end;
end;

class function TBerBitStringParser.Parse(const ASp: IAsn1StreamParser): IBerBitString;
var
  LBitStream: TAsn1ConstructedBitStream;
  LData: TCryptoLibByteArray;
  LPadBits: Int32;
begin
  LBitStream := TAsn1ConstructedBitStream.Create(ASp, False);
  try
    LData := TStreamUtilities.ReadAll(LBitStream);
    LPadBits := LBitStream.PadBits;
    Result := TBerBitString.Create(LData, LPadBits);
  finally
    LBitStream.Free;
  end;
end;

{ TBerOctetStringParser }

constructor TBerOctetStringParser.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FParser := AParser;
end;

function TBerOctetStringParser.GetOctetStream(): TStream;
begin
  Result := TAsn1ConstructedOctetStream.Create(FParser);
end;

function TBerOctetStringParser.ToAsn1Object(): IAsn1Object;
begin
  try
    Result := Parse(FParser);
  except
    on E: EIOCryptoLibException do
      raise EAsn1ParsingCryptoLibException.Create('IOException converting stream to byte array: ' + E.Message);
  end;
end;

class function TBerOctetStringParser.Parse(const ASp: IAsn1StreamParser): IBerOctetString;
var
  LOctetStream: TAsn1ConstructedOctetStream;
begin
  LOctetStream := TAsn1ConstructedOctetStream.Create(ASp);
  try
    Result := TBerOctetString.Create(TStreamUtilities.ReadAll(LOctetStream));
  finally
    LOctetStream.Free;
  end;
end;

{ TDerOctetStringParser }

constructor TDerOctetStringParser.Create(const AStream: TAsn1DefiniteLengthInputStream);
begin
  inherited Create;
  FStream := AStream;
end;

destructor TDerOctetStringParser.Destroy;
begin
  // Parser OWNS the stream and always frees it
  if FStream <> nil then
  begin
    FStream.Free;
    FStream := nil;
  end;
  inherited Destroy;
end;

function TDerOctetStringParser.GetOctetStream(): TStream;
begin
  // Transfers ownership to caller - caller MUST free the stream
  Result := FStream;
  FStream := nil;  // Transfer ownership, destructor won't free
end;

function TDerOctetStringParser.ToAsn1Object(): IAsn1Object;
begin
  try
    Result := TDerOctetString.WithContents(FStream.ToArray());
  except
    on E: EIOCryptoLibException do
      raise EInvalidOperationCryptoLibException.Create('IOException converting stream to byte array: ' + E.Message);
  end;
end;

{ TDLBitStringParser }

constructor TDLBitStringParser.Create(const AStream: TAsn1DefiniteLengthInputStream);
begin
  inherited Create;
  FStream := AStream;
  FPadBits := 0;
end;

destructor TDLBitStringParser.Destroy;
begin
  // Parser OWNS the stream and always frees it
  if FStream <> nil then
  begin
    FStream.Free;
    FStream := nil;
  end;
  inherited Destroy;
end;

function TDLBitStringParser.GetBitStreamInternal(AOctetAligned: Boolean): TStream;
var
  LLength: Int32;
begin
  LLength := FStream.Remaining;
  if LLength < 1 then
    raise EInvalidOperationCryptoLibException.Create('content octets cannot be empty');

  FPadBits := FStream.ReadByte();
  if FPadBits > 0 then
  begin
    if LLength < 2 then
      raise EInvalidOperationCryptoLibException.Create('zero length data with non-zero pad bits');
    if FPadBits > 7 then
      raise EInvalidOperationCryptoLibException.Create('pad bits cannot be greater than 7 or less than 0');
    if AOctetAligned then
      raise EIOCryptoLibException.CreateFmt('expected octet-aligned bitstring, but found padBits: %d', [FPadBits]);
  end;

  // Transfers ownership to caller - caller MUST free the stream
  Result := FStream;
  FStream := nil;  // Transfer ownership, destructor won't free
end;

function TDLBitStringParser.GetBitStream(): TStream;
begin
  Result := GetBitStreamInternal(False);
end;

function TDLBitStringParser.GetOctetStream(): TStream;
begin
  Result := GetBitStreamInternal(True);
end;

function TDLBitStringParser.GetPadBits(): Int32;
begin
  Result := FPadBits;
end;

function TDLBitStringParser.ToAsn1Object(): IAsn1Object;
begin
  try
    Result := TDerBitString.CreatePrimitive(FStream.ToArray());
  except
    on E: EIOCryptoLibException do
      raise EAsn1ParsingCryptoLibException.Create('IOException converting stream to byte array: ' + E.Message);
  end;
end;

{ TDerSequenceParser }

constructor TDerSequenceParser.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FParser := AParser;
end;

function TDerSequenceParser.ReadObject(): IAsn1Convertible;
begin
  Result := FParser.ReadObject();
end;

function TDerSequenceParser.ToAsn1Object(): IAsn1Object;
begin
  Result := TDLSequence.FromVector(FParser.ReadVector());
end;

{ TDerSetParser }

constructor TDerSetParser.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FParser := AParser;
end;

function TDerSetParser.ReadObject(): IAsn1Convertible;
begin
  Result := FParser.ReadObject();
end;

function TDerSetParser.ToAsn1Object(): IAsn1Object;
begin
  Result := TDLSet.FromVector(FParser.ReadVector());
end;

{ TBerSequenceParser }

constructor TBerSequenceParser.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FParser := AParser;
end;

function TBerSequenceParser.ReadObject(): IAsn1Convertible;
begin
  Result := FParser.ReadObject();
end;

function TBerSequenceParser.ToAsn1Object(): IAsn1Object;
begin
  Result := Parse(FParser);
end;

class function TBerSequenceParser.Parse(const ASp: IAsn1StreamParser): IBerSequence;
begin
  Result := TBerSequence.FromVector(ASp.ReadVector());
end;

{ TBerSetParser }

constructor TBerSetParser.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FParser := AParser;
end;

function TBerSetParser.ReadObject(): IAsn1Convertible;
begin
  Result := FParser.ReadObject();
end;

function TBerSetParser.ToAsn1Object(): IAsn1Object;
begin
  Result := Parse(FParser);
end;

class function TBerSetParser.Parse(const ASp: IAsn1StreamParser): IBerSet;
begin
  Result := TBerSet.FromVector(ASp.ReadVector());
end;

{ TDerExternalParser }

constructor TDerExternalParser.Create(const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FParser := AParser;
end;

function TDerExternalParser.ReadObject(): IAsn1Convertible;
begin
  Result := FParser.ReadObject();
end;

function TDerExternalParser.ToAsn1Object(): IAsn1Object;
begin
  Result := Parse(FParser);
end;

class function TDerExternalParser.Parse(const ASp: IAsn1StreamParser): IDerExternal;
begin
  Result := TDLExternal.Create(TDLSequence.FromVector(ASp.ReadVector()));
end;

{ TBerTaggedObjectParser }

constructor TBerTaggedObjectParser.Create(ATagClass, ATagNo: Int32; const AParser: IAsn1StreamParser);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FParser := AParser;
end;

function TBerTaggedObjectParser.GetTagClass(): Int32;
begin
  Result := FTagClass;
end;

function TBerTaggedObjectParser.GetTagNo(): Int32;
begin
  Result := FTagNo;
end;

function TBerTaggedObjectParser.GetIsConstructed(): Boolean;
begin
  Result := True; // BER tagged objects are always constructed
end;

function TBerTaggedObjectParser.HasContextTag(ATagNo: Int32): Boolean;
begin
  Result := (FTagClass = TAsn1Tags.ContextSpecific) and (FTagNo = ATagNo);
end;

function TBerTaggedObjectParser.HasTag(ATagClass, ATagNo: Int32): Boolean;
begin
  Result := (FTagClass = ATagClass) and (FTagNo = ATagNo);
end;

function TBerTaggedObjectParser.ParseBaseUniversal(ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible;
begin
  if ADeclaredExplicit then
    Result := FParser.ParseObject(ABaseTagNo)
  else
    Result := FParser.ParseImplicitConstructedIL(ABaseTagNo);
end;

function TBerTaggedObjectParser.ParseExplicitBaseObject(): IAsn1Convertible;
begin
  Result := FParser.ReadObject();
end;

function TBerTaggedObjectParser.ParseExplicitBaseTagged(): IAsn1TaggedObjectParser;
begin
  Result := FParser.ParseTaggedObject();
end;

function TBerTaggedObjectParser.ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser;
begin
  Result := TBerTaggedObjectParser.Create(ABaseTagClass, ABaseTagNo, FParser);
end;

function TBerTaggedObjectParser.ToAsn1Object(): IAsn1Object;
begin
  try
    Result := FParser.LoadTaggedIL(FTagClass, FTagNo);
  except
    on E: EIOCryptoLibException do
      raise EAsn1ParsingCryptoLibException.Create(E.Message);
  end;
end;

{ TDLTaggedObjectParser }

constructor TDLTaggedObjectParser.Create(ATagClass, ATagNo: Int32; AConstructed: Boolean;
  const AParser: IAsn1StreamParser);
begin
  inherited Create(ATagClass, ATagNo, AParser);
  FConstructed := AConstructed;
end;

function TDLTaggedObjectParser.ParseBaseUniversal(ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible;
var
  LSp: IAsn1StreamParser;
begin
  if ADeclaredExplicit then
  begin
    LSp := CheckConstructed();
    Result := LSp.ParseObject(ABaseTagNo);
  end
  else
  begin
    if FConstructed then
      Result := FParser.ParseImplicitConstructedDL(ABaseTagNo)
    else
      Result := FParser.ParseImplicitPrimitive(ABaseTagNo);
  end;
end;

function TDLTaggedObjectParser.ParseExplicitBaseObject(): IAsn1Convertible;
var
  LSp: IAsn1StreamParser;
begin
  LSp := CheckConstructed();
  Result := LSp.ReadObject();
end;

function TDLTaggedObjectParser.ParseExplicitBaseTagged(): IAsn1TaggedObjectParser;
var
  LSp: IAsn1StreamParser;
begin
  LSp := CheckConstructed();
  Result := LSp.ParseTaggedObject();
end;

function TDLTaggedObjectParser.ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser;
begin
  Result := TDLTaggedObjectParser.Create(ABaseTagClass, ABaseTagNo, FConstructed, FParser);
end;

function TDLTaggedObjectParser.ToAsn1Object(): IAsn1Object;
begin
  try
    Result := FParser.LoadTaggedDL(FTagClass, FTagNo, FConstructed);
  except
    on E: EIOCryptoLibException do
      raise EAsn1ParsingCryptoLibException.Create(E.Message);
  end;
end;

function TDLTaggedObjectParser.GetIsConstructed(): Boolean;
begin
  Result := FConstructed;
end;

function TDLTaggedObjectParser.CheckConstructed(): IAsn1StreamParser;
begin
  if not FConstructed then
    raise EIOCryptoLibException.Create('Explicit tags must be constructed (see X.690 8.14.2)');
  Result := FParser;
end;

end.
