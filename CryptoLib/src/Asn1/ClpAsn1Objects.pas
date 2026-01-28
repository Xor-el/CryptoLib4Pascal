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

unit ClpAsn1Objects;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  Math,
  DateUtils,
  ClpBitUtilities,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpBigIntegers,
  ClpIAsn1Objects,
  ClpAsn1Streams,
  ClpAsn1Utilities,
  ClpPlatformUtilities,
  ClpStreams,
  ClpStreamUtilities,
  ClpArrayUtilities,
  ClpStringUtilities,
  ClpEncoders,
  ClpConverters,
  ClpCollectionUtilities,
  ClpDateTimeUtilities,
  ClpOidTokenizer,
  ClpIOidTokenizer;

type
  /// <summary>
  /// ASN.1 tags constants.
  /// </summary>
  TAsn1Tags = class sealed(TObject)
  public
    // 0x00: Reserved for use by the encoding rules
    const
      Boolean = $01;
      Integer = $02;
      BitString = $03;
      OctetString = $04;
      Null = $05;
      ObjectIdentifier = $06;
      ObjectDescriptor = $07;
      &External = $08;
      Real = $09;
      Enumerated = $0A;
      EmbeddedPdv = $0B;
      Utf8String = $0C;
      RelativeOid = $0D;
      Time = $0E;
      // 0x0f: Reserved for future editions of this Recommendation | International Standard
      Sequence = $10;
      SequenceOf = $10; // for completeness
      &Set = $11;
      SetOf = $11; // for completeness
      NumericString = $12;
      PrintableString = $13;
      T61String = $14;
      VideotexString = $15;
      IA5String = $16;
      UtcTime = $17;
      GeneralizedTime = $18;
      GraphicString = $19;
      VisibleString = $1A;
      GeneralString = $1B;
      UniversalString = $1C;
      UnrestrictedString = $1D;
      BmpString = $1E;
      Date = $1F;
      TimeOfDay = $20;
      DateTime = $21;
      Duration = $22;
      ObjectIdentifierIri = $23;
      RelativeOidIri = $24;
      // 0x25..: Reserved for addenda to this Recommendation | International Standard

      Constructed = $20;

      Universal = $00;
      Application = $40;
      ContextSpecific = $80;
      &Private = $C0;

      Flags = $E0;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 types.
  /// </summary>
  TAsn1Type = class abstract(TInterfacedObject, IAsn1Type)
  strict protected
    FPlatformType: TClass;
  public
    constructor Create(APlatformType: TClass);
    function GetPlatformType(): TClass;
    property PlatformType: TClass read FPlatformType;
  end;

  /// <summary>
  /// ASN.1 tag representation.
  /// </summary>
  TAsn1Tag = class sealed(TInterfacedObject, IAsn1Tag)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    constructor Create(ATagClass, ATagNo: Int32);
  public
    class function CreateTag(ATagClass, ATagNo: Int32): IAsn1Tag; static;
    function GetTagClass(): Int32;
    function GetTagNo(): Int32;
    function GetExplicitness(): Int32;
    property TagClass: Int32 read FTagClass;
    property TagNo: Int32 read FTagNo;
  end;

  /// <summary>
  /// Abstract base class for universal ASN.1 types.
  /// </summary>
  TAsn1UniversalType = class abstract(TAsn1Type, IAsn1UniversalType, IAsn1Type)
  strict private
    FTag: IAsn1Tag;
  protected
    function CheckedCast(const AAsn1Object: IAsn1Object): IAsn1Object; virtual;
    function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; virtual;
    function FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object; virtual;
  public
    constructor Create(APlatformType: TClass; ATagNo: Int32);
    destructor Destroy; override;
    function FromByteArray(const ABytes: TCryptoLibByteArray): IAsn1Object;
    function GetContextTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Object;
    function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Object;
    property Tag: IAsn1Tag read FTag;
  end;

  /// <summary>
  /// Factory for ASN.1 universal types.
  /// </summary>
  TAsn1UniversalTypes = class sealed(TObject)
  public
    class function Get(ATagNo: Int32): IAsn1UniversalType; static;
  end;

  /// <summary>
  /// Abstract base class for DER encoding.
  /// </summary>
  TDerEncoding = class abstract(TInterfacedObject, IDerEncoding, IAsn1Encoding)
  strict protected
    FTagClass: Int32;
    FTagNo: Int32;

  strict protected
    /// <summary>
    /// Compare length and contents with another DER encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; virtual; abstract;

  public
    /// <summary>
    /// Create a DER encoding.
    /// </summary>
    constructor Create(ATagClass, ATagNo: Int32);

    /// <summary>
    /// Get the tag class.
    /// </summary>
    function GetTagClass(): Int32;
    /// <summary>
    /// Get the tag number.
    /// </summary>
    function GetTagNo(): Int32;
    /// <summary>
    /// Compare this encoding with another.
    /// </summary>
    function CompareTo(const AOther: IDerEncoding): Int32;

    /// <summary>
    /// Encode to the given stream (must be a TAsn1OutputStream).
    /// </summary>
    procedure Encode(const AOut: TStream); virtual; abstract;

    /// <summary>
    /// Get the length of the encoded data.
    /// </summary>
    function GetLength(): Int32; virtual; abstract;

    property TagClass: Int32 read FTagClass;
    property TagNo: Int32 read FTagNo;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 encodable objects.
  /// </summary>
  TAsn1Encodable = class abstract(TInterfacedObject, IAsn1Encodable, IAsn1Convertible)
  public
    const
      Ber = 'BER';
      Der = 'DER';
      DL = 'DL';

  public
    /// <summary>
    /// Encode this object to a stream using BER encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream); overload; virtual;
    /// <summary>
    /// Encode this object to a stream using the specified encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); overload; virtual;
    /// <summary>
    /// Get the encoded representation of this object.
    /// </summary>
    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String): TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray; overload; virtual;
    /// <summary>
    /// Get the DER encoding of the object, nil if the DER encoding cannot be made.
    /// </summary>
    function GetDerEncoded(): TCryptoLibByteArray;
    /// <summary>
    /// Check if this object equals another.
    /// </summary>
    function Equals(const AObj: IAsn1Convertible): Boolean; reintroduce; overload;
    /// <summary>
    /// Get the hash code for this object.
    /// </summary>
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
    /// <summary>
    /// Convert this object to an ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; virtual; abstract;
  end;

  /// <summary>
  /// Vector for ASN.1 encodable objects.
  /// </summary>
  TAsn1EncodableVector = class(TInterfacedObject, IAsn1EncodableVector)
  strict private
    const
      DefaultCapacity = 10;

    class var
      FEmptyElements: TCryptoLibGenericArray<IAsn1Encodable>;
  
  public
    class property EmptyElements: TCryptoLibGenericArray<IAsn1Encodable> read FEmptyElements;

  strict private
    FElements: TCryptoLibGenericArray<IAsn1Encodable>;
    FElementCount: Int32;
    FCopyOnWrite: Boolean;

    function PrepareCapacity(ARequiredCapacity: Int32): Int32;
    procedure Reallocate(AMinCapacity: Int32);
    class function CopyElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>;
      AElementCount: Int32): TCryptoLibGenericArray<IAsn1Encodable>; overload; static;

  public
    /// <summary>
    /// Create an empty vector with default capacity.
    /// </summary>
    constructor Create(); overload;
    /// <summary>
    /// Create an empty vector with specified initial capacity.
    /// </summary>
    constructor Create(AInitialCapacity: Int32); overload;
    /// <summary>
    /// Create a vector with a single element.
    /// </summary>
    constructor Create(const AElement: IAsn1Encodable); overload;
    /// <summary>
    /// Create a vector with two elements.
    /// </summary>
    constructor Create(const AElement1, AElement2: IAsn1Encodable); overload;
    /// <summary>
    /// Create a vector with multiple elements.
    /// </summary>
    constructor Create(const AElements: array of IAsn1Encodable); overload;

    /// <summary>
    /// Add an element to the vector.
    /// </summary>
    procedure Add(const AElement: IAsn1Encodable); overload;
    /// <summary>
    /// Add two elements to the vector.
    /// </summary>
    procedure Add(const AElement1, AElement2: IAsn1Encodable); overload;
    /// <summary>
    /// Add multiple elements to the vector.
    /// </summary>
    procedure Add(const AObjs: array of IAsn1Encodable); overload;
    /// <summary>
    /// Add an optional element (if not nil).
    /// </summary>
    procedure AddOptional(const AElement: IAsn1Encodable); overload;
    /// <summary>
    /// Add two optional elements.
    /// </summary>
    procedure AddOptional(const AElement1, AElement2: IAsn1Encodable); overload;
    /// <summary>
    /// Add multiple optional elements.
    /// </summary>
    procedure AddOptional(const AElements: array of IAsn1Encodable); overload;
    /// <summary>
    /// Add an optional tagged element.
    /// </summary>
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Add an optional tagged element with tag class.
    /// </summary>
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Add all elements from an enumerable.
    /// </summary>
    procedure AddAll(const AE: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    /// <summary>
    /// Add all elements from another vector.
    /// </summary>
    procedure AddAll(const AOther: IAsn1EncodableVector); overload;

    /// <summary>
    /// Get an element by index.
    /// </summary>
    function GetItem(AIndex: Int32): IAsn1Encodable;
    /// <summary>
    /// Get the number of elements.
    /// </summary>
    function GetCount(): Int32;
    /// <summary>
    /// Copy all elements to a new array.
    /// </summary>
    function CopyElements(): TCryptoLibGenericArray<IAsn1Encodable>; overload;
    /// <summary>
    /// Take all elements (may return internal array if count matches capacity).
    /// </summary>
    function TakeElements(): TCryptoLibGenericArray<IAsn1Encodable>;

    /// <summary>
    /// Create a vector from a collection.
    /// </summary>
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector; static;
    /// <summary>
    /// Create a vector from a single element.
    /// </summary>
    class function FromElement(const AElement: IAsn1Encodable): IAsn1EncodableVector; static;
    /// <summary>
    /// Create a vector from an enumerable.
    /// </summary>
    class function FromEnumerable(const AE: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector; static;
    /// <summary>
    /// Clone elements from an array.
    /// </summary>
    class function CloneElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IAsn1Encodable>; static;

    /// <summary>
    /// Class constructor to initialize static fields.
    /// </summary>
    class constructor Create;

    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Count: Int32 read GetCount;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 objects.
  /// </summary>
  TAsn1Object = class abstract(TAsn1Encodable, IAsn1Object)
  strict protected
    /// <summary>
    /// Compare this object with another ASN.1 object.
    /// </summary>
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; virtual; abstract;
    /// <summary>
    /// Get the hash code for this ASN.1 object.
    /// </summary>
    function Asn1GetHashCode(): Int32; virtual; abstract;

  public
    /// <summary>
    /// Encode this object to a stream using BER encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream); override;
    /// <summary>
    /// Encode this object to a stream using the specified encoding.
    /// </summary>
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); override;
    /// <summary>
    /// Get the encoded representation of this object.
    /// </summary>
    function GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray; override;
    /// <summary>
    /// Check if this object equals another.
    /// </summary>
    function Equals(const AOther: IAsn1Object): Boolean; reintroduce; overload;
    /// <summary>
    /// Create an ASN.1 object from a byte array.
    /// </summary>
    class function FromByteArray(const AData: TCryptoLibByteArray): IAsn1Object; static;
    /// <summary>
    /// Create an ASN.1 object from a stream.
    /// </summary>
    class function FromStream(const AInStr: TStream): IAsn1Object; static;
    /// <summary>
    /// Get encoding for the specified encoding type.
    /// </summary>
    function GetEncoding(AEncoding: Int32): IAsn1Encoding; virtual; abstract;
    /// <summary>
    /// Get encoding for the specified encoding type with implicit tagging.
    /// </summary>
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; virtual; abstract;
    /// <summary>
    /// Get DER encoding.
    /// </summary>
    function GetEncodingDer(): IDerEncoding; virtual; abstract;
    /// <summary>
    /// Get DER encoding with implicit tagging.
    /// </summary>
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; virtual; abstract;
    /// <summary>
    /// Convert this object to an ASN.1 object (returns self).
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;

  private
    /// <summary>
    /// Create an ASN.1 object from a fixed buffer stream.
    /// </summary>
    class function FromBufferStream(const ABufferStream: TFixedBufferStream): IAsn1Object; static;

    /// <summary>
    /// Call Asn1Equals (internal method).
    /// </summary>
    function CallAsn1Equals(const AObj: IAsn1Object): Boolean;
    /// <summary>
    /// Call Asn1GetHashCode (internal method).
    /// </summary>
    function CallAsn1GetHashCode(): Int32;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 octet strings.
  /// </summary>
  TAsn1OctetString = class abstract(TAsn1Object, IAsn1OctetString, IAsn1OctetStringParser)
  strict protected
    class var
      FEmptyOctets: TCryptoLibByteArray;
  
  public
    type
      /// <summary>
      /// Meta class for TAsn1OctetString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  
  public
    class property EmptyOctets: TCryptoLibByteArray read FEmptyOctets;

  strict protected
    FContents: TCryptoLibByteArray;

    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;

  public
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IAsn1OctetString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1OctetString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IAsn1OctetString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1OctetString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1OctetString; overload; static;
    /// <summary>
    /// Get optional octet string from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1OctetString; static;
    /// <summary>
    /// Get tagged octet string from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1OctetString; static;

    /// <summary>
    /// Create an octet string from contents.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray);

    /// <summary>
    /// Get the octet stream.
    /// </summary>
    function GetOctetStream(): TStream; virtual;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray; virtual;

    /// <summary>
    /// Get the octets length.
    /// </summary>
    function GetOctetsLength(): Int32; virtual;

    /// <summary>
    /// Convert to ASN.1 object.
    /// </summary>
    function ToAsn1Object(): IAsn1Object; override;

    /// <summary>
    /// Convert to string representation.
    /// </summary>
    function ToString(): String; override;

    /// <summary>
    /// Create a primitive octet string from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;

    /// <summary>
    /// Class constructor to initialize static fields.
    /// </summary>
    class constructor Create;
  end;

  /// <summary>
  /// DER octet string implementation.
  /// </summary>
  TDerOctetString = class(TAsn1OctetString, IDerOctetString)
  strict private
    class var
      FEmpty: IDerOctetString;
    class function GetEmpty(): IDerOctetString; static;

    /// <summary>
    /// Create a DER octet string with `empty` contents.
    /// </summary>
    constructor CreateEmpty();

  public
    /// <summary>
    /// Create a DER octet string from contents.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Create a DER octet string from an ASN.1 convertible object.
    /// </summary>
    constructor Create(const AObj: IAsn1Convertible); overload;
    /// <summary>
    /// Create a DER octet string from an ASN.1 encodable object.
    /// </summary>
    constructor Create(const AObj: IAsn1Encodable); overload;

    /// <summary>
    /// Create from contents (copies the array).
    /// </summary>
    class function FromContents(const AContents: TCryptoLibByteArray): IDerOctetString; static;
    /// <summary>
    /// Create from contents optional (copies the array).
    /// </summary>
    class function FromContentsOptional(const AContents: TCryptoLibByteArray): IDerOctetString; static;
    /// <summary>
    /// Create from contents (does not copy, uses the array directly).
    /// </summary>
    class function WithContents(const AContents: TCryptoLibByteArray): IDerOctetString; static;
    /// <summary>
    /// Get encoding for the specified encoding type with implicit tagging.
    /// </summary>
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    /// <summary>
    /// Get DER encoding.
    /// </summary>
    function GetEncodingDer(): IDerEncoding; override;

    /// <summary>
    /// Get encoding for the specified encoding type.
    /// </summary>
    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    /// <summary>
    /// Get DER encoding with implicit tagging.
    /// </summary>
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;

    class procedure Encode(const AAsn1Out: TAsn1OutputStream; const ABuffer: TCryptoLibByteArray; AOffset, ALength: Int32); static;

    /// <summary>
    /// Empty DER octet string.
    /// </summary>
    class property Empty: IDerOctetString read GetEmpty;

    /// <summary>
    /// Class constructor to initialize static fields.
    /// </summary>
    class constructor Create;
  end;

  /// <summary>
  /// BER octet string implementation.
  /// </summary>
  TBerOctetString = class(TDerOctetString, IBerOctetString)
  strict private
    FElements: TCryptoLibGenericArray<IAsn1OctetString>;
    class function GetEmpty(): IBerOctetString; static;

  public
    /// <summary>
    /// Empty BER octet string.
    /// </summary>
    class property Empty: IBerOctetString read GetEmpty;
    /// <summary>
    /// Flatten an array of octet strings into a single byte array.
    /// </summary>
    class function FlattenOctetStrings(const AOctetStrings: TCryptoLibGenericArray<IAsn1OctetString>): TCryptoLibByteArray; static;
    /// <summary>
    /// Create from contents (copies the array).
    /// </summary>
    class function FromContents(const AContents: TCryptoLibByteArray): IBerOctetString; static;
    /// <summary>
    /// Create from contents optional (copies the array).
    /// </summary>
    class function FromContentsOptional(const AContents: TCryptoLibByteArray): IBerOctetString; static;
    /// <summary>
    /// Create a BER octet string from a sequence.
    /// </summary>
    class function FromSequence(const ASequence: IAsn1Sequence): IBerOctetString; static;

    class function WithContents(const AContents: TCryptoLibByteArray): IBerOctetString; static;
    /// <summary>
    /// Create a BER octet string from an array of octet strings.
    /// </summary>
    constructor Create(const AOctetStrings: TCryptoLibGenericArray<IAsn1OctetString>); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;

    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

  /// <summary>
  /// Abstract base class for DER string objects.
  /// </summary>
  TDerStringBase = class abstract(TAsn1Object, IDerStringBase, IAsn1String)
  strict protected
    constructor Create();
    function Asn1GetHashCode(): Int32; override;
    /// <summary>
    /// Get the tag number for this string type (to be implemented by derived classes).
    /// </summary>
    function GetTagNo(): Int32; virtual; abstract;
    /// <summary>
    /// Get the contents as byte array (to be implemented by derived classes).
    /// </summary>
    function GetContents(): TCryptoLibByteArray; virtual; abstract;
  public
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; virtual; abstract;
    /// <summary>
    /// Convert to string.
    /// </summary>
    function ToString(): String; override;
    /// <summary>
    /// Get encoding for the specified encoding type.
    /// </summary>
    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    /// <summary>
    /// Get encoding for the specified encoding type with implicit tagging.
    /// </summary>
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    /// <summary>
    /// Get DER encoding.
    /// </summary>
    function GetEncodingDer(): IDerEncoding; override;
    /// <summary>
    /// Get DER encoding with implicit tagging.
    /// </summary>
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// DER bit string implementation.
  /// </summary>
  TDerBitString = class(TDerStringBase, IDerBitString, IAsn1BitStringParser)
  strict private
    class var FEmptyOctetsContents: TCryptoLibByteArray;
    class constructor Create;
    class function GetEmptyOctetsContents: TCryptoLibByteArray; static;
  strict protected
    FContents: TCryptoLibByteArray; // First byte is padBits, rest is data
    FBufferStream: TFixedBufferStream;

  public
    class property EmptyOctetsContents: TCryptoLibByteArray read GetEmptyOctetsContents;

    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;

    function GetTagNo(): Int32; override;
    function GetPadBits(): Int32;
    function GetContents(): TCryptoLibByteArray; override;
    function GetString(): String; override;
    function GetOctets(): TCryptoLibByteArray; virtual;
    function GetBytes(): TCryptoLibByteArray; virtual;
    function GetInt32Value(): Int32;
    function GetBytesLength(): Int32;
    function IsOctetAligned(): Boolean;
    function GetBitStream(): TStream;
    function GetOctetStream(): TStream;
    function GetBufferStream(): TFixedBufferStream;
    function GetParser(): IAsn1BitStringParser;
    procedure CheckOctetAligned();

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  public
    type
      /// <summary>
      /// Meta class for TDerBitString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
        function FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a DER bit string with `empty` data.
    /// </summary>
    constructor CreateEmpty();
    /// <summary>
    /// Create a DER bit string from data.
    /// </summary>
    constructor Create(const AData: TCryptoLibByteArray); overload;
    /// <summary>
    /// Create a DER bit string from contents (contents format: [padBits, data...]).
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray; ACheck: Boolean); overload;
    /// <summary>
    /// Create a DER bit string from data and pad bits.
    /// </summary>
    constructor Create(const AData: TCryptoLibByteArray; APadBits: Int32); overload;
    /// <summary>
    /// Create a DER bit string from a single byte and pad bits.
    /// </summary>
    constructor Create(AData: Byte; APadBits: Int32); overload;
    /// <summary>
    /// Create a DER bit string from named bits (Int32).
    /// </summary>
    constructor Create(ANamedBits: Int32); overload;
    /// <summary>
    /// Create a DER bit string from an IAsn1Convertible object.
    /// </summary>
    constructor Create(const AObj: IAsn1Convertible); overload;
    /// <summary>
    /// Create a DER bit string from an IAsn1Encodable object.
    /// </summary>
    constructor Create(const AObj: IAsn1Encodable); overload;

    destructor Destroy; override;
    /// <summary>
    /// Create a primitive DER bit string from contents (contents format: [padBits, data...]).
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IDerBitString; static;
    /// <summary>
    /// Create a DER bit string from contents (optional, returns nil if contents is nil).
    /// </summary>
    class function FromContentsOptional(const AContents: TCryptoLibByteArray): IDerBitString; static;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerBitString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerBitString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerBitString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerBitString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; AIsExplicit: Boolean): IDerBitString; overload; static;
    /// <summary>
    /// Get optional bit string from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerBitString; static;
    /// <summary>
    /// Get tagged bit string from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBitString; static;

    property PadBits: Int32 read GetPadBits;
    property Int32Value: Int32 read GetInt32Value;
    property Parser: IAsn1BitStringParser read GetParser;
    property Contents: TCryptoLibByteArray read GetContents;
  end;

  /// <summary>
  /// DL bit string implementation.
  /// </summary>
  TDLBitString = class(TDerBitString, IDLBitString)

  public
    /// <summary>
    /// Create a DL bit string from contents (m_contents format: [padBits, data...]).
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray; ACheck: Boolean = True); overload;
    /// <summary>
    /// Create a DL bit string from data and pad bits.
    /// </summary>
    constructor Create(const AData: TCryptoLibByteArray; APadBits: Int32); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

  /// <summary>
  /// BER bit string implementation.
  /// </summary>
  TBerBitString = class(TDerBitString, IBerBitString)
  strict private
    FElements: TCryptoLibGenericArray<IDerBitString>;

  public
    /// <summary>
    /// Flatten an array of bit strings into a single m_contents byte array.
    /// </summary>
    class function FlattenBitStrings(const ABitStrings: TCryptoLibGenericArray<IDerBitString>): TCryptoLibByteArray; static;
    /// <summary>
    /// Create a BER bit string from a sequence.
    /// </summary>
    class function FromSequence(const ASequence: IAsn1Sequence): IBerBitString; static;
    /// <summary>
    /// Create a BER bit string from an array of bit strings.
    /// </summary>
    constructor Create(const ABitStrings: TCryptoLibGenericArray<IDerBitString>); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

  /// <summary>
  /// DER BMP string implementation.
  /// </summary>
  TDerBmpString = class(TDerStringBase, IDerBmpString)
  strict private
    FStr: String;

  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;

  public
    type
      /// <summary>
      /// Meta class for TDerBmpString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a DER BMP string from byte array.
    /// </summary>
    constructor Create(const AStr: TCryptoLibByteArray); overload;
    /// <summary>
    /// Create a DER BMP string from string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Create a primitive DER BMP string from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IDerBmpString; overload; static;
    class function CreatePrimitive(const AStr: TCryptoLibCharArray): IDerBmpString; overload; static;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerBmpString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerBmpString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerBmpString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerBmpString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBmpString; overload; static;
    /// <summary>
    /// Get optional BMP string from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerBmpString; static;
    /// <summary>
    /// Get tagged BMP string from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBmpString; static;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 tagged objects.
  /// </summary>
  TAsn1TaggedObject = class abstract(TAsn1Object, IAsn1TaggedObject, IAsn1TaggedObjectParser)
  strict private
    const
      DeclaredExplicit = 1;
      DeclaredImplicit = 2;
      ParsedExplicit = 3;
      ParsedImplicit = 4;

  private
    var
      FExplicitness: Int32;
      FTagClass: Int32;
      FTagNo: Int32;
      FObject: IAsn1Encodable;

  strict protected

    /// <summary>
    /// Protected constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Protected constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Protected constructor.
    /// </summary>
    constructor Create(AExplicitness, ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;

    /// <summary>
    /// Compare this object with another ASN.1 object.
    /// </summary>
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    /// <summary>
    /// Get the hash code for this ASN.1 object.
    /// </summary>
    function Asn1GetHashCode(): Int32; override;

    /// <summary>
    /// Rebuild a constructed object.
    /// </summary>
    function RebuildConstructed(const AAsn1Object: IAsn1Object): IAsn1Sequence; virtual; abstract;
    /// <summary>
    /// Replace tag.
    /// </summary>
    function ReplaceTag(ATagClass, ATagNo: Int32): IAsn1TaggedObject; virtual; abstract;

  strict private
    /// <summary>
    /// Check instance helper.
    /// </summary>
    class function CheckInstance(const AObj: TObject): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Check instance helper.
    /// </summary>
    class function CheckInstance(const AObj: IAsn1Object): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Check instance helper.
    /// </summary>
    class function CheckInstance(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Checked cast helper.
    /// </summary>
    class function CheckedCast(const AAsn1Object: IAsn1Object): IAsn1TaggedObject; static;

  public
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from object with tag class.
    /// </summary>
    class function GetInstance(const AObj: TObject; ATagClass: Int32): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object with tag class.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object; ATagClass: Int32): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from object with tag class and tag number.
    /// </summary>
    class function GetInstance(const AObj: TObject; ATagClass, ATagNo: Int32): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object with tag class and tag number.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object; ATagClass, ATagNo: Int32): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from tagged object with tag class.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject;
      ATagClass: Int32; ADeclaredExplicit: Boolean): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get instance from tagged object with tag class and tag number.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject;
      ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get optional tagged object.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get optional tagged object with tag class.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable;
      ATagClass: Int32): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get optional tagged object with tag class and tag number.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable;
      ATagClass, ATagNo: Int32): IAsn1TaggedObject; overload; static;
    /// <summary>
    /// Get tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAsn1TaggedObject; static;
    /// <summary>
    /// Create a primitive tagged object.
    /// </summary>
    class function CreatePrimitive(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray): IAsn1Object; static;
    /// <summary>
    /// Create a constructed DL tagged object.
    /// </summary>
    class function CreateConstructedDL(ATagClass, ATagNo: Int32;
      const AContentsElements: IAsn1EncodableVector): IAsn1Object; static;
    /// <summary>
    /// Create a constructed IL tagged object.
    /// </summary>
    class function CreateConstructedIL(ATagClass, ATagNo: Int32;
      const AContentsElements: IAsn1EncodableVector): IAsn1Object; static;

    // IAsn1TaggedObject methods
    /// <summary>
    /// Get the tag number.
    /// </summary>
    function GetTagNo(): Int32; virtual;
    /// <summary>
    /// Get the tag class.
    /// </summary>
    function GetTagClass(): Int32; virtual;
    /// <summary>
    /// Get the explicitness value.
    /// </summary>
    function GetExplicitness(): Int32; virtual;
    /// <summary>
    /// Check if this has a context tag (no parameter).
    /// </summary>
    function HasContextTag(): Boolean; overload; virtual;
    /// <summary>
    /// Check if this has a context tag.
    /// </summary>
    function HasContextTag(ATagNo: Int32): Boolean; overload; virtual;
    /// <summary>
    /// Check if this has the specified tag.
    /// </summary>
    function HasTag(ATagClass, ATagNo: Int32): Boolean; virtual;
    /// <summary>
    /// Check if this has the specified tag class.
    /// </summary>
    function HasTagClass(ATagClass: Int32): Boolean; virtual;
    /// <summary>
    /// Check if this is explicitly tagged.
    /// </summary>
    function IsExplicit(): Boolean; virtual;
    /// <summary>
    /// Check if this is parsed.
    /// </summary>
    function IsParsed(): Boolean;
    /// <summary>
    /// Get the object following the tag.
    /// </summary>
    function GetObject(): IAsn1Object; virtual;
    /// <summary>
    /// Get the base encodable object (needed for open types).
    /// </summary>
    function GetBaseObject(): IAsn1Encodable;
    /// <summary>
    /// Get the explicit base encodable object.
    /// </summary>
    function GetExplicitBaseObject(): IAsn1Encodable;
    /// <summary>
    /// Get the explicit base tagged object.
    /// </summary>
    function GetExplicitBaseTagged(): IAsn1TaggedObject;
    /// <summary>
    /// Get the implicit base tagged object.
    /// </summary>
    function GetImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObject;
    /// <summary>
    /// Get base universal object.
    /// </summary>
    function GetBaseUniversal(ADeclaredExplicit: Boolean; ATagNo: Int32): IAsn1Object; overload;
    /// <summary>
    /// Get base universal object.
    /// </summary>
    function GetBaseUniversal(ADeclaredExplicit: Boolean; const AUniversalType: IAsn1UniversalType): IAsn1Object; overload;
    /// <summary>
    /// Get an object parser for the specified tag.
    /// </summary>
    function GetObjectParser(ATag: Int32; AIsExplicit: Boolean): IAsn1Convertible; virtual;
    /// <summary>
    /// Get string representation.
    /// </summary>
    function ToString(): String; override;

    // IAsn1TaggedObjectParser methods
    /// <summary>
    /// Check if this is a constructed object.
    /// </summary>
    function GetIsConstructed(): Boolean; virtual; abstract;
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
  end;

  /// <summary>
  /// DER tagged object implementation.
  /// </summary>
  TDerTaggedObject = class(TAsn1TaggedObject, IDerTaggedObject)
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function RebuildConstructed(const AAsn1Object: IAsn1Object): IAsn1Sequence; override;
    function ReplaceTag(ATagClass, ATagNo: Int32): IAsn1TaggedObject; override;

  public
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AExplicitness, ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    function GetIsConstructed(): Boolean; override;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// DL tagged object implementation.
  /// </summary>
  TDLTaggedObject = class(TDerTaggedObject, IDLTaggedObject)
  strict protected
    function RebuildConstructed(const AAsn1Object: IAsn1Object): IAsn1Sequence; override;
    function ReplaceTag(ATagClass, ATagNo: Int32): IAsn1TaggedObject; override;

  public
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AExplicitness, ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 sequence objects.
  /// </summary>
  TAsn1Sequence = class abstract(TAsn1Object, IAsn1Sequence)
  strict private
    FElements: TCryptoLibGenericArray<IAsn1Encodable>;
    
    type
      /// <summary>
      /// Internal parser implementation for sequences.
      /// </summary>
      TAsn1SequenceParserImpl = class sealed(TInterfacedObject, IAsn1Convertible, IAsn1SequenceParser)
      strict private
        FOuter: IAsn1Sequence;
        FIndex: Int32;
      public
        constructor Create(const AOuter: IAsn1Sequence);
        function ReadObject(): IAsn1Convertible;
        function ToAsn1Object(): IAsn1Object;
      end;

  strict protected
    function GetCount(): Int32; virtual;
    function GetParser(): IAsn1SequenceParser; virtual;
    function GetItem(AIndex: Int32): IAsn1Encodable; virtual;
    function GetElements(): TCryptoLibGenericArray<IAsn1Encodable>; virtual;
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetConstructedBitStrings(): TCryptoLibGenericArray<IDerBitString>;
    function GetConstructedOctetStrings(): TCryptoLibGenericArray<IAsn1OctetString>;
  public
    function ToAsn1BitString(): IDerBitString; virtual; abstract;
    function ToAsn1External(): IDerExternal; virtual; abstract;
    function ToAsn1OctetString(): IAsn1OctetString; virtual; abstract;
    function ToAsn1Set(): IAsn1Set; virtual; abstract;
  public
    type
      /// <summary>
      /// Meta class for TAsn1Sequence universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;

  strict protected
    /// <summary>
    /// Concatenate elements from multiple sequences.
    /// </summary>
    class function ConcatenateElements(const ASequences: TCryptoLibGenericArray<IAsn1Sequence>): TCryptoLibGenericArray<IAsn1Encodable>; static;
  public
    /// <summary>
    /// Map elements using a function.
    /// </summary>
    function MapElements<TResult>(const AFunc: TFunc<IAsn1Encodable, TResult>): TCryptoLibGenericArray<TResult>;
    /// <summary>
    /// Get a cloned array of elements.
    /// </summary>
    function ToArray(): TCryptoLibGenericArray<IAsn1Encodable>; virtual;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IAsn1Sequence; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IAsn1Sequence; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1Sequence; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Sequence; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1Sequence; overload; static;
    /// <summary>
    /// Get optional sequence from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1Sequence; static;
    /// <summary>
    /// Get tagged sequence from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Sequence; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElement1, AElement2: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    destructor Destroy(); override;

    function ToString(): String; override;

    property Count: Int32 read GetCount;
    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Parser: IAsn1SequenceParser read GetParser;
    property Elements: TCryptoLibGenericArray<IAsn1Encodable> read GetElements;
  end;

  /// <summary>
  /// DER sequence class implementation.
  /// </summary>
  TDerSequence = class(TAsn1Sequence, IDerSequence)
  strict private
    class function GetEmpty(): IDerSequence; static;
    class function WithElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): IDerSequence; static;

  public
    function ToAsn1BitString(): IDerBitString; override;
    function ToAsn1External(): IDerExternal; override;
    function ToAsn1OctetString(): IAsn1OctetString; override;
    function ToAsn1Set(): IAsn1Set; override;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
    
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDerSequence; static;
    class function FromElement(const AElement: IAsn1Encodable): IDerSequence; static;
    class function FromElements(const AElement1, AElement2: IAsn1Encodable): IDerSequence; overload; static;
    class function FromElements(const AElements: array of IAsn1Encodable): IDerSequence; overload; static;
    class function FromElementsOptional(const AElements: array of IAsn1Encodable): IDerSequence; static;
    class function FromSequence(const ASequence: IAsn1Sequence): IDerSequence; static;
    class function FromVector(const AElementVector: IAsn1EncodableVector): IDerSequence; static;
    class function Map(const ASequence: IAsn1Sequence; const AFunc: TFunc<IAsn1Encodable, IAsn1Encodable>): IDerSequence; overload; static;
    class function Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDerSequence; overload; static;
    class function Concatenate(const ASequences: array of IAsn1Sequence): IDerSequence; static;
    /// <summary>
    /// Get encoding length for a given contents length.
    /// </summary>
    class function GetEncodingLength(AContentsLength: Int32): Int32; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElement1, AElement2: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ASet: IAsn1Set); overload;

    class property Empty: IDerSequence read GetEmpty;
  end;

  /// <summary>
  /// DL sequence class implementation.
  /// </summary>
  TDLSequence = class(TDerSequence, IDLSequence)
  strict private
    class function GetEmpty(): IDLSequence; static;
    class function WithElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): IDLSequence; static;

  public
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDLSequence; static;
    class function FromElement(const AElement: IAsn1Encodable): IDLSequence; static;
    class function FromElements(const AElement1, AElement2: IAsn1Encodable): IDLSequence; overload; static;
    class function FromElements(const AElements: array of IAsn1Encodable): IDLSequence; overload; static;
    class function FromElementsOptional(const AElements: array of IAsn1Encodable): IDLSequence; static;
    class function FromSequence(const ASequence: IAsn1Sequence): IDLSequence; static;
    class function FromVector(const AElementVector: IAsn1EncodableVector): IDLSequence; static;
    class function Map(const ASequence: IAsn1Sequence; const AFunc: TFunc<IAsn1Encodable, IAsn1Encodable>): IDLSequence; overload; static;
    class function Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDLSequence; overload; static;
    class function Concatenate(const ASequences: array of IAsn1Sequence): IDLSequence; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElement1, AElement2: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ASet: IAsn1Set); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;

    /// <summary>
    /// Convert to ASN.1 external.
    /// </summary>
    function ToAsn1External(): IDerExternal; override;
    /// <summary>
    /// Convert to ASN.1 bit string.
    /// </summary>
    function ToAsn1BitString(): IDerBitString; override;
    /// <summary>
    /// Convert to ASN.1 set.
    /// </summary>
    function ToAsn1Set(): IAsn1Set; override;

    class property Empty: IDLSequence read GetEmpty;
  end;

  /// <summary>
  /// Abstract base class for ASN.1 set objects.
  /// </summary>
  TAsn1Set = class abstract(TAsn1Object, IAsn1Set)
  strict private
    FElements: TCryptoLibGenericArray<IAsn1Encodable>;
    type
      /// <summary>
      /// Internal parser implementation for sets.
      /// </summary>
      TAsn1SetParserImpl = class sealed(TInterfacedObject, IAsn1Convertible, IAsn1SetParser)
      strict private
        FOuter: TAsn1Set;
        FIndex: Int32;
      public
        constructor Create(const AOuter: TAsn1Set);
        function ReadObject(): IAsn1Convertible;
        function ToAsn1Object(): IAsn1Object;
      end;

    /// <summary>
    /// Sort elements based on their DER encodings.
    /// Returns the sorted DER encodings array.
    /// </summary>
    class function SortElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IDerEncoding>; static;

  strict protected
    FSortedDerEncodings: TCryptoLibGenericArray<IDerEncoding>;
    function GetCount(): Int32; virtual;
  public
    type
      /// <summary>
      /// Meta class for TAsn1Set universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
    function GetParser(): IAsn1SetParser; virtual;
    function GetItem(AIndex: Int32): IAsn1Encodable; virtual;
    function GetElements(): TCryptoLibGenericArray<IAsn1Encodable>; virtual;
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    /// <summary>
    /// Map elements using a function.
    /// </summary>
    function MapElements<TResult>(const AFunc: TFunc<IAsn1Encodable, TResult>): TCryptoLibGenericArray<TResult>;
    /// <summary>
    /// Get a cloned array of elements.
    /// </summary>
    function ToArray(): TCryptoLibGenericArray<IAsn1Encodable>;

  public
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IAsn1Set; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IAsn1Set; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1Set; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1Set; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Set; overload; static;
    /// <summary>
    /// Get optional set from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1Set; static;
    /// <summary>
    /// Get tagged set from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Set; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable; ADoSort: Boolean); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector; ADoSort: Boolean); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>; ADoSort: Boolean); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ASet: IAsn1Set); overload;
    constructor Create(AIsSorted: Boolean; const AElements: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    destructor Destroy(); override;

    function ToString(): String; override;

    property Count: Int32 read GetCount;
    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Parser: IAsn1SetParser read GetParser;
    property Elements: TCryptoLibGenericArray<IAsn1Encodable> read GetElements;
  end;

  /// <summary>
  /// DER set class implementation.
  /// </summary>
  TDerSet = class(TAsn1Set, IDerSet)
  strict private
    class function GetEmpty(): IDerSet; static;
    function GetSortedDerEncodings(): TCryptoLibGenericArray<IDerEncoding>;
    class function CreateSortedDerEncodings(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IDerEncoding>; static;

  public
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDerSet; static;
    class function FromElement(const AElement: IAsn1Encodable): IDerSet; static;
    class function FromVector(const AElementVector: IAsn1EncodableVector): IDerSet; static;
    class function Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDerSet; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ASet: IAsn1Set); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;

    class property Empty: IDerSet read GetEmpty;
  end;

  /// <summary>
  /// DL set class implementation.
  /// </summary>
  TDLSet = class(TDerSet, IDLSet)
  strict private
    class function GetEmpty(): IDLSet; static;

  public
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDLSet; static;
    class function FromElement(const AElement: IAsn1Encodable): IDLSet; static;
    class function FromVector(const AElementVector: IAsn1EncodableVector): IDLSet; static;
    class function Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDLSet; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ASet: IAsn1Set); overload;
    constructor Create(AIsSorted: Boolean; const AElements: TCryptoLibGenericArray<IAsn1Encodable>); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;

    class property Empty: IDLSet read GetEmpty;
  end;

  /// <summary>
  /// BER sequence class implementation.
  /// </summary>
  TBerSequence = class(TDLSequence, IBerSequence)
  strict private
    class function GetEmpty(): IBerSequence; static;
    class function WithElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): IBerSequence; static;

  public
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IBerSequence; static;
    class function FromElement(const AElement: IAsn1Encodable): IBerSequence; static;
    class function FromElements(const AElement1, AElement2: IAsn1Encodable): IBerSequence; overload; static;
    class function FromElements(const AElements: array of IAsn1Encodable): IBerSequence; overload; static;
    class function FromElementsOptional(const AElements: array of IAsn1Encodable): IBerSequence; static;
    class function FromSequence(const ASequence: IAsn1Sequence): IBerSequence; static;
    class function FromVector(const AElementVector: IAsn1EncodableVector): IBerSequence; static;
    class function Map(const ASequence: IAsn1Sequence; const AFunc: TFunc<IAsn1Encodable, IAsn1Encodable>): IBerSequence; overload; static;
    class function Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IBerSequence; overload; static;
    class function Concatenate(const ASequences: array of IAsn1Sequence): IBerSequence; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElement1, AElement2: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ASet: IAsn1Set); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;

    function ToAsn1BitString(): IDerBitString; override;
    function ToAsn1External(): IDerExternal; override;
    function ToAsn1OctetString(): IAsn1OctetString; override;
    function ToAsn1Set(): IAsn1Set; override;

    class property Empty: IBerSequence read GetEmpty;
  end;

  /// <summary>
  /// BER set class implementation.
  /// </summary>
  TBerSet = class(TDLSet, IBerSet)
  strict private
    class function GetEmpty(): IBerSet; static;

  public
    class function FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IBerSet; static;
    class function FromElement(const AElement: IAsn1Encodable): IBerSet; static;
    class function FromVector(const AElementVector: IAsn1EncodableVector): IBerSet; static;
    class function Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IBerSet; static;

    constructor Create(); overload;
    constructor Create(const AElement: IAsn1Encodable); overload;
    constructor Create(const AElements: array of IAsn1Encodable); overload;
    constructor Create(const AElementVector: IAsn1EncodableVector); overload;
    constructor Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ASet: IAsn1Set); overload;
    constructor Create(AIsSorted: Boolean; const AElements: TCryptoLibGenericArray<IAsn1Encodable>); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;

    class property Empty: IBerSet read GetEmpty;
  end;

  /// <summary>
  /// BER tagged object class implementation.
  /// </summary>
  TBerTaggedObject = class(TDLTaggedObject, IBerTaggedObject)
  strict protected
    function RebuildConstructed(const AAsn1Object: IAsn1Object): IAsn1Sequence; override;
    function ReplaceTag(ATagClass, ATagNo: Int32): IAsn1TaggedObject; override;

  public
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable); overload;
    /// <summary>
    /// Public constructor.
    /// </summary>
    constructor Create(AExplicitness, ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

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
  /// Abstract base class for ASN.1 generators.
  /// </summary>
  TAsn1Generator = class abstract(TInterfacedObject, IAsn1Generator)
  strict private
    FOut: TStream;
    FClosed: Boolean;
  strict protected
    constructor Create(AOutStream: TStream);
    function GetOut: TStream; inline;
    function GetIsClosed: Boolean; inline;
    property &Out: TStream read GetOut;
    procedure Finish(); virtual; abstract;
    procedure DoClose();
  public
    destructor Destroy(); override;
    procedure AddObject(const AObj: IAsn1Encodable); overload; virtual; abstract;
    procedure AddObject(const AObj: IAsn1Object); overload; virtual; abstract;
    function GetRawOutputStream(): TStream; virtual; abstract;
    procedure Close(); virtual; abstract;
    property IsClosed: Boolean read GetIsClosed;
    class function InheritConstructedFlag(AIntoTag, AFromTag: Int32): Int32; static;
  end;

  /// <summary>
  /// Abstract base class for BER generators.
  /// </summary>
  TBerGenerator = class abstract(TAsn1Generator, IBerGenerator)
  strict private
    FTagged, FIsExplicit: Boolean;
    FTagNo: Int32;
  strict protected
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;

    procedure WriteHdr(ATag: Int32);
    procedure WriteBerHeader(ATag: Int32);
    procedure WriteBerBody(AContentStream: TStream);
    procedure WriteBerEnd();
    procedure Finish(); override;
  public
    procedure AddObject(const AObj: IAsn1Encodable); override;
    procedure AddObject(const AObj: IAsn1Object); override;
    function GetRawOutputStream(): TStream; override;
    procedure Close(); override;
  end;

  /// <summary>
  /// BER sequence generator.
  /// </summary>
  TBerSequenceGenerator = class(TBerGenerator, IBerSequenceGenerator)
  public
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
  end;

  /// <summary>
  /// BER octet string generator.
  /// </summary>
  TBerOctetStringGenerator = class(TBerGenerator, IBerOctetStringGenerator)
  public
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
    function GetOctetOutputStream(): TStream; overload;
    function GetOctetOutputStream(ABufSize: Int32): TStream; overload;
    function GetOctetOutputStream(const ABuf: TCryptoLibByteArray): TStream; overload;
  end;

  /// <summary>
  /// Abstract base class for DER generators.
  /// </summary>
  TDerGenerator = class abstract(TAsn1Generator, IDerGenerator)
  strict private
    FTagged, FIsExplicit: Boolean;
    FTagNo: Int32;
    class procedure WriteLength(const AOutStr: TStream; ALength: Int32); static;
  strict protected
    constructor Create(const AOutStream: TStream); overload;
    constructor Create(const AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
  public
    procedure WriteDerEncoded(ATag: Int32; const ABytes: TCryptoLibByteArray); overload;
    class procedure WriteDerEncoded(const AOutStream: TStream; ATag: Int32; const ABytes: TCryptoLibByteArray); overload; static;
    class procedure WriteDerEncoded(const AOutStr: TStream; ATag: Int32; const AInStr: TStream); overload; static;
  end;

  /// <summary>
  /// DER sequence generator.
  /// </summary>
  TDerSequenceGenerator = class(TDerGenerator, IDerSequenceGenerator)
  strict private
    FBOut: TMemoryStream;
  strict protected
    procedure Finish(); override;
  public
    constructor Create(AOutStream: TStream); overload;
    constructor Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean); overload;
    destructor Destroy(); override;
    procedure AddObject(const AObj: IAsn1Encodable); overload; override;
    procedure AddObject(const AObj: IAsn1Object); overload; override;
    function GetRawOutputStream(): TStream; override;
    procedure Close(); override;
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

  /// <summary>
  /// DER external class.
  /// </summary>
  TDerExternal = class(TAsn1Object, IDerExternal)
  strict private
    class function GetObjFromSequence(const ASequence: IAsn1Sequence; AIndex: Int32): IAsn1Object; static;
    class function CheckEncoding(AEncoding: Int32): Int32; static;
    class function CheckExternalContent(ATagNo: Int32; const AExternalContent: IAsn1Object): IAsn1Object; static;
    class function GetExternalContent(const AEncoding: IAsn1TaggedObject): IAsn1Object; overload; static;
    class function CheckDataValueDescriptor(const ADataValueDescriptor: IAsn1Object): IAsn1ObjectDescriptor; static;
  strict protected
    FDirectReference: IDerObjectIdentifier;
    FIndirectReference: IDerInteger;
    FDataValueDescriptor: IAsn1ObjectDescriptor;
    FEncoding: Int32;
    FExternalContent: IAsn1Object;
    
    function BuildSequence(): IAsn1Sequence; virtual;

    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;

  public
    type
      /// <summary>
      /// Meta class for TDerExternal universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create(const AVector: IAsn1EncodableVector); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ADirectReference: IDerObjectIdentifier;
      const AIndirectReference: IDerInteger;
      const ADataValueDescriptor: IAsn1ObjectDescriptor;
      const AExternalData: IAsn1TaggedObject); overload;
    constructor Create(const ADirectReference: IDerObjectIdentifier;
      const AIndirectReference: IDerInteger;
      const ADataValueDescriptor: IAsn1ObjectDescriptor;
      AEncoding: Int32; const AExternalData: IAsn1Object); overload;
    function GetSequence(): IAsn1Sequence;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding;  overload; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;

    function GetEncoding(): Int32; reintroduce; overload;

    // Interface methods for IDerExternal
    function GetDataValueDescriptor(): IAsn1Object;
    function GetDirectReference(): IDerObjectIdentifier;
    function GetExternalContent(): IAsn1Object; overload;
    function GetIndirectReference(): IDerInteger;
  end;

  /// <summary>
  /// DL external class.
  /// </summary>
  TDLExternal = class sealed(TDerExternal, IDLExternal)
  protected
    function BuildSequence(): IAsn1Sequence; override;

  public
    constructor Create(const AVector: IAsn1EncodableVector); overload;
    constructor Create(const ASequence: IAsn1Sequence); overload;
    constructor Create(const ADirectReference: IDerObjectIdentifier;
      const AIndirectReference: IDerInteger;
      const ADataValueDescriptor: IAsn1ObjectDescriptor;
      const AExternalData: IAsn1TaggedObject); overload;
    constructor Create(const ADirectReference: IDerObjectIdentifier;
      const AIndirectReference: IDerInteger;
      const ADataValueDescriptor: IAsn1ObjectDescriptor;
      AEncoding: Int32; const AExternalData: IAsn1Object); overload;

      function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

  /// <summary>
  /// DER boolean implementation.
  /// </summary>
  TDerBoolean = class(TAsn1Object, IAsn1Object, IDerBoolean)
  strict private
    FValue: Byte;
    class var FFalse: IDerBoolean;
    class var FTrue: IDerBoolean;
    class function GetFalse: IDerBoolean; static;
    class function GetTrue: IDerBoolean; static;
    constructor Create(AValue: Boolean); overload;
    function GetContents(AEncoding: Int32): TCryptoLibByteArray;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TDerBoolean universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    class function FromOctetString(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    class function GetInstance(const AObj: TObject): IDerBoolean; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IDerBoolean; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IDerBoolean; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerBoolean; overload; static;
    class function GetInstance(AValue: Boolean): IDerBoolean; overload; static;
    class function GetInstance(AValue: Int32): IDerBoolean; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBoolean; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IDerBoolean; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBoolean; static;
    function GetValue(): Byte;
    function GetIsTrue(): Boolean;
    function ToString(): String; override;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;

    class property False: IDerBoolean read GetFalse;
    class property True: IDerBoolean read GetTrue;
  end;

  /// <summary>
  /// DER enumerated object implementation.
  /// </summary>
  TDerEnumerated = class(TAsn1Object, IAsn1Object, IDerEnumerated)
  strict private
    class var
      FCache: TCryptoLibGenericArray<IDerEnumerated>;
    var
      FContents: TCryptoLibByteArray;
      FStart: Int32;
    function GetValue(): TBigInteger;
    function GetIntValueExact(): Int32;
    /// <summary>
    /// Class constructor to initialize static fields.
    /// </summary>
    class constructor Create;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TDerEnumerated universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create(AVal: Int32); overload;
    constructor Create(AVal: Int64); overload;
    constructor Create(const AVal: TBigInteger); overload;
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
    class function GetInstance(const AObj: TObject): IDerEnumerated; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IDerEnumerated; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IDerEnumerated; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerEnumerated; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerEnumerated; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IDerEnumerated; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerEnumerated; static;
    class function FromOctetString(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    class function CreatePrimitive(const AContents: TCryptoLibByteArray; AClone: Boolean): IAsn1Object; static;
    function GetBytes(): TCryptoLibByteArray;
    function HasValue(AX: Int32): Boolean; overload;
    function HasValue(const AX: TBigInteger): Boolean; overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// ASN.1 null object base class.
  /// </summary>
  TAsn1Null = class abstract(TAsn1Object, IAsn1Null)
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TAsn1Null universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create;
    class procedure CheckContentsLength(AContentsLength: Int32); static;
    class function CreatePrimitive(): IAsn1Object; static;
    class function GetInstance(const AObj: TObject): IAsn1Null; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IAsn1Null; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1Null; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1Null; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Null; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1Null; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Null; static;
  end;

  /// <summary>
  /// DER null object implementation.
  /// </summary>
  TDerNull = class(TAsn1Null, IDerNull)
  strict private
    class var FInstance: IDerNull;
    class function GetInstance: IDerNull; static;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    constructor Create;
    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;

    class property Instance: IDerNull read GetInstance;
  end;

  /// <summary>
  /// DER Object Identifier implementation.
  /// </summary>
  TDerObjectIdentifier = class(TAsn1Object, IAsn1Object, IDerObjectIdentifier)
  strict private
    const
      MaxContentsLength = 4096;
      MaxIdentifierLength = MaxContentsLength * 4 + 1;
      LongLimit = Int64((Int64.MaxValue shr 7) - $7F);
    class var
      FCache: TCryptoLibGenericArray<IDerObjectIdentifier>;
    var
      FContents: TCryptoLibByteArray;
      FIdentifier: String;
    class function IsValidIdentifier(const AIdentifier: String): Boolean; static;
    class function ParseIdentifier(const AIdentifier: String): TCryptoLibByteArray; static;
    class function ParseContents(const AContents: TCryptoLibByteArray): String; static;
    class procedure CheckIdentifier(const AIdentifier: String); static;
    class procedure WriteField(const AOutputStream: TStream; AFieldValue: Int64); overload; static;
    class procedure WriteField(const AOutputStream: TStream; const AFieldValue: TBigInteger); overload; static;
    constructor Create(const AContents: TCryptoLibByteArray; const AIdentifier: String); overload;
    function GetID(): String;
    class constructor Create;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TDerObjectIdentifier universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
    constructor Create(const AIdentifier: String); overload;
    class function FromContents(const AContents: TCryptoLibByteArray): IDerObjectIdentifier; static;
    class function GetInstance(const AObj: TObject): IDerObjectIdentifier; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IDerObjectIdentifier; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IDerObjectIdentifier; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerObjectIdentifier; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerObjectIdentifier; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IDerObjectIdentifier; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerObjectIdentifier; static;
    class function TryFromID(const AIdentifier: String; out AOid: IDerObjectIdentifier): Boolean; static;
    class procedure CheckContentsLength(AContentsLength: Int32); static;
    class function CreatePrimitive(const AContents: TCryptoLibByteArray; AClone: Boolean): IAsn1Object; static;
    class function FromOctetString(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    function GetContents(): TCryptoLibByteArray;
    function Branch(const ABranchID: String): IDerObjectIdentifier;
    function &On(const AStem: IDerObjectIdentifier): Boolean;
    function ToString(): String; override;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// ASN.1 relative OID implementation.
  /// </summary>
  TAsn1RelativeOid = class(TAsn1Object, IAsn1RelativeOid)
  strict private
    const
      MaxContentsLength = 4096;
      MaxIdentifierLength = MaxContentsLength * 4 - 1;
      LongLimit = Int64((Int64.MaxValue shr 7) - $7F);
    class var
      FCache: TCryptoLibGenericArray<IAsn1RelativeOid>;
    var
      FContents: TCryptoLibByteArray;
      FIdentifier: String;
    function GetID(): String;
    constructor Create(const AContents: TCryptoLibByteArray; const AIdentifier: String); overload;
  protected
    class function IsValidIdentifier(const AIdentifier: String; AFrom: Int32): Boolean; static;
    class function IsValidContents(const AContents: TCryptoLibByteArray): Boolean; static;
    class function ParseContents(const AContents: TCryptoLibByteArray): String; static;
    class function ParseIdentifier(const AIdentifier: String): TCryptoLibByteArray; static;
    class procedure WriteField(const AOutputStream: TStream; AFieldValue: Int64); overload; static;
    class procedure WriteField(const AOutputStream: TStream; const AFieldValue: TBigInteger); overload; static;
    class procedure CheckIdentifier(const AIdentifier: String); static;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TAsn1RelativeOid universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    class constructor Create;
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
    constructor Create(const AIdentifier: String); overload;
    class function FromContents(const AContents: TCryptoLibByteArray): IAsn1RelativeOid; static;
    class function GetInstance(const AObj: TObject): IAsn1RelativeOid; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IAsn1RelativeOid; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1RelativeOid; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1RelativeOid; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1RelativeOid; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1RelativeOid; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1RelativeOid; static;
    class function TryFromID(const AIdentifier: String; out AOid: IAsn1RelativeOid): Boolean; static;
    class procedure CheckContentsLength(AContentsLength: Int32); static;
    class function CreatePrimitive(const AContents: TCryptoLibByteArray; AClone: Boolean): IAsn1Object; static;
    function Branch(const ABranchID: String): IAsn1RelativeOid;
    function GetContents(): TCryptoLibByteArray;
    function ToString(): String; override;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// ASN.1 generalized time implementation.
  /// </summary>
  TAsn1GeneralizedTime = class(TAsn1Object, IAsn1GeneralizedTime)
  strict private
    FTimeString: String;
    FTimeStringCanonical: Boolean;
    FDateTime: TDateTime;
    class function FromString(const AStr: String): TDateTime; static;
    class function IndexOfSign(const AStr: String; AStartIndex: Int32): Int32; static;
    class function ParseLocal(const AStr, AFormat: String): TDateTime; static;
    class function ParseTimeZone(const AStr, AFormat: String): TDateTime; static;
    class function ParseUtc(const AStr, AFormat: String): TDateTime; static;
    class function ToStringCanonical(const ADateTime: TDateTime): String; static;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TAsn1GeneralizedTime universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    constructor Create(const ATimeString: String); overload;
    constructor Create(const ADateTime: TDateTime); overload;
    class function GetInstance(const AObj: TObject): IAsn1GeneralizedTime; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IAsn1GeneralizedTime; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1GeneralizedTime; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1GeneralizedTime; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1GeneralizedTime; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1GeneralizedTime; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1GeneralizedTime; static;
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    function GetContents(AEncoding: Int32): TCryptoLibByteArray;
    function GetTimeString: String;
    function ToDateTime: TDateTime;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// ASN.1 UTC time implementation.
  /// </summary>
  TAsn1UtcTime = class(TAsn1Object, IAsn1UtcTime)
  strict private
    FTimeString: String;
    FDateTime: TDateTime;
    FDateTimeLocked: Boolean;
    FTwoDigitYearMax: Int32;
    class function FromString(const AStr: String; out ATwoDigitYearMax: Int32): TDateTime; static;
    class function InRange(const ADateTime: TDateTime; ATwoDigitYearMax: Int32): Boolean; static;
    class function ToStringCanonical(const ADateTime: TDateTime; out ATwoDigitYearMax: Int32): String; overload; static;
    class function ToStringCanonical(const ADateTime: TDateTime): String; overload; static;
    class procedure Validate(const ADateTime: TDateTime; ATwoDigitYearMax: Int32); static;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TAsn1UtcTime universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    constructor Create(const ATimeString: String); overload;
    constructor Create(const ADateTime: TDateTime); overload; deprecated 'Use Create(DateTime, Int32) instead';
    constructor Create(const ADateTime: TDateTime; ATwoDigitYearMax: Int32); overload;
    class function GetInstance(const AObj: TObject): IAsn1UtcTime; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IAsn1UtcTime; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1UtcTime; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1UtcTime; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1UtcTime; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1UtcTime; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1UtcTime; static;
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    function GetContents(AEncoding: Int32): TCryptoLibByteArray;
    function GetTimeString: String;
    function GetTwoDigitYearMax: Int32;
    function ToString(): String; override;
    function ToDateTime: TDateTime; overload;
    function ToDateTime(ATwoDigitYearMax: Int32): TDateTime; overload;
    function ToAdjustedDateTime: TDateTime; deprecated 'Use ToDateTime(2049) instead';

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// DER UTC time implementation.
  /// </summary>
  TDerUtcTime = class(TAsn1UtcTime, IDerUtcTime)
  public
    constructor Create(const ATimeString: String); overload;
    constructor Create(const ADateTime: TDateTime); overload; deprecated 'Use Create(DateTime, Int32) instead';
    constructor Create(const ADateTime: TDateTime; ATwoDigitYearMax: Int32); overload;
    constructor Create(const AContents: TCryptoLibByteArray); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

  /// <summary>
  /// DER generalized time implementation.
  /// </summary>
  TDerGeneralizedTime = class(TAsn1GeneralizedTime, IDerGeneralizedTime)
  public
    constructor Create(const ATimeString: String); overload;
    constructor Create(const ADateTime: TDateTime); overload;
    constructor Create(const AContents: TCryptoLibByteArray); overload;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
  end;

  /// <summary>
  /// ASN.1 object descriptor implementation.
  /// </summary>
  TAsn1ObjectDescriptor = class(TAsn1Object, IAsn1ObjectDescriptor)
  strict private
    FGraphicString: IAsn1Object;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    type
      /// <summary>
      /// Meta class for TAsn1ObjectDescriptor universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
        function FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    constructor Create(const AGraphicString: IAsn1Object);
    class function GetInstance(const AObj: TObject): IAsn1ObjectDescriptor; overload; static;
    class function GetInstance(const AObj: IAsn1Object): IAsn1ObjectDescriptor; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAsn1ObjectDescriptor; overload; static;
    class function GetInstance(const ABytes: TCryptoLibByteArray): IAsn1ObjectDescriptor; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1ObjectDescriptor; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IAsn1ObjectDescriptor; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1ObjectDescriptor; static;
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    function GetGraphicString(): IAsn1Object;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
  end;

  /// <summary>
  /// DER GeneralString object.
  /// </summary>
  TDerGeneralString = class(TDerStringBase, IDerGeneralString)
  strict private
    FContents: TCryptoLibByteArray;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerGeneralString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a GeneralString from a string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Create a GeneralString from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerGeneralString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerGeneralString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerGeneralString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerGeneralString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGeneralString; overload; static;
    /// <summary>
    /// Get optional GeneralString from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerGeneralString; static;
    /// <summary>
    /// Get tagged GeneralString from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGeneralString; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  strict private
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  end;

  /// <summary>
  /// DER GraphicString object.
  /// </summary>
  TDerGraphicString = class(TDerStringBase, IDerGraphicString)
  strict private
    FContents: TCryptoLibByteArray;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerGraphicString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a GraphicString from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerGraphicString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerGraphicString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerGraphicString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerGraphicString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGraphicString; overload; static;
    /// <summary>
    /// Get optional GraphicString from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerGraphicString; static;
    /// <summary>
    /// Get tagged GraphicString from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGraphicString; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  strict private
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  end;

  /// <summary>
  /// DER IA5String object.
  /// </summary>
  TDerIA5String = class(TDerStringBase, IDerIA5String)
  strict private
    FContents: TCryptoLibByteArray;
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerIA5String universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create an IA5String from a string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Create an IA5String from a string with optional validation.
    /// </summary>
    constructor Create(const AStr: String; AValidate: Boolean); overload;
    /// <summary>
    /// Create an IA5String from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Check if string can be represented as IA5String.
    /// </summary>
    class function IsIA5String(const AStr: String): Boolean; static;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerIA5String; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerIA5String; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerIA5String; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerIA5String; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerIA5String; overload; static;
    /// <summary>
    /// Get optional IA5String from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerIA5String; static;
    /// <summary>
    /// Get tagged IA5String from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerIA5String; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  end;

  /// <summary>
  /// DER integer implementation.
  /// </summary>
  TDerInteger = class(TAsn1Object, IAsn1Object, IDerInteger)
  strict private
    FBytes: TCryptoLibByteArray;
    FStart: Int32;
    class var
      FSmallConstants: TCryptoLibGenericArray<IDerInteger>;
      FZero: IDerInteger;
      FOne: IDerInteger;
      FTwo: IDerInteger;
      FThree: IDerInteger;
      FFour: IDerInteger;
      FFive: IDerInteger;
      FAllowUnsafeInteger: Boolean;
    class function GetZero(): IDerInteger; static;
    class function GetOne(): IDerInteger; static;
    class function GetTwo(): IDerInteger; static;
    class function GetThree(): IDerInteger; static;
    class function GetFour(): IDerInteger; static;
    class function GetFive(): IDerInteger; static;
    class function GetAllowUnsafeInteger(): Boolean; static;
    class procedure SetAllowUnsafeInteger(const AValue: Boolean); static;
    class function AllowUnsafe(): Boolean; static;
    class constructor Create;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
  public
    const
      SignExtSigned = Int32(-1);
      SignExtUnsigned = Int32($FF);
    type
      /// <summary>
      /// Meta class for TDerInteger universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create from Int32 value.
    /// </summary>
    constructor Create(AValue: Int32); overload;
    /// <summary>
    /// Create from Int64 value.
    /// </summary>
    constructor Create(AValue: Int64); overload;
    /// <summary>
    /// Create from BigInteger value.
    /// </summary>
    constructor Create(const AValue: TBigInteger); overload;
    /// <summary>
    /// Create from byte array.
    /// </summary>
    constructor Create(const ABytes: TCryptoLibByteArray); overload;
    /// <summary>
    /// Create from byte array with clone option.
    /// </summary>
    constructor Create(const ABytes: TCryptoLibByteArray; AClone: Boolean); overload;

    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
    
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerInteger; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerInteger; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerInteger; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerInteger; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerInteger; overload; static;
    /// <summary>
    /// Get optional integer from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerInteger; static;
    /// <summary>
    /// Get tagged integer from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerInteger; static;
    /// <summary>
    /// Get or create integer from value (uses cached small constants).
    /// </summary>
    class function ValueOf(AValue: Int64): IDerInteger; static;
    /// <summary>
    /// Get encoding length for a BigInteger.
    /// </summary>
    class function GetEncodingLength(const AX: TBigInteger): Int32; static;
    /// <summary>
    /// Extract Int64 value from bytes with sign extension.
    /// </summary>
    class function LongValue(const ABytes: TCryptoLibByteArray; AStart, ASignExt: Int32): Int64; static;
    
    /// <summary>
    /// Static constants.
    /// </summary>
    class property Zero: IDerInteger read GetZero;
    class property One: IDerInteger read GetOne;
    class property Two: IDerInteger read GetTwo;
    class property Three: IDerInteger read GetThree;
    class property Four: IDerInteger read GetFour;
    class property Five: IDerInteger read GetFive;
    /// <summary>
    /// Allow unsafe integer operations (bypasses some validation).
    /// </summary>
    class property AllowUnsafeInteger: Boolean read GetAllowUnsafeInteger write SetAllowUnsafeInteger;
    
    function GetBytes(): TCryptoLibByteArray;
    /// <summary>
    /// Get the BigInteger value.
    /// </summary>
    function GetValue(): TBigInteger;
    /// <summary>
    /// Get the positive BigInteger value.
    /// </summary>
    function GetPositiveValue(): TBigInteger;
    /// <summary>
    /// Check if this integer has a specific Int32 value.
    /// </summary>
    function HasValue(AX: Int32): Boolean; overload;
    /// <summary>
    /// Check if this integer has a specific Int64 value.
    /// </summary>
    function HasValue(AX: Int64): Boolean; overload;
    /// <summary>
    /// Check if this integer has a specific BigInteger value.
    /// </summary>
    function HasValue(const AX: TBigInteger): Boolean; overload;
    /// <summary>
    /// Get Int32 value, throwing if out of range.
    /// </summary>
    function GetIntValueExact(): Int32;
    /// <summary>
    /// Get positive Int32 value, throwing if out of range.
    /// </summary>
    function GetIntPositiveValueExact(): Int32;
    /// <summary>
    /// Get Int64 value, throwing if out of range.
    /// </summary>
    function GetLongValueExact(): Int64;
    /// <summary>
    /// Try to get Int32 value, returning false if out of range.
    /// </summary>
    function TryGetIntValueExact(out AValue: Int32): Boolean;
    /// <summary>
    /// Try to get positive Int32 value, returning false if out of range.
    /// </summary>
    function TryGetIntPositiveValueExact(out AValue: Int32): Boolean;
    /// <summary>
    /// Try to get Int64 value, returning false if out of range.
    /// </summary>
    function TryGetLongValueExact(out AValue: Int64): Boolean;
    /// <summary>
    /// Check if bytes are malformed (invalid INTEGER encoding).
    /// </summary>
    class function IsMalformed(const ABytes: TCryptoLibByteArray): Boolean; static;
    /// <summary>
    /// Calculate number of sign extension bytes to skip.
    /// </summary>
    class function SignBytesToSkip(const ABytes: TCryptoLibByteArray): Int32; static;
    /// <summary>
    /// Extract Int32 value from bytes with sign extension.
    /// </summary>
    class function IntValue(const ABytes: TCryptoLibByteArray; AStart, ASignExt: Int32): Int32; static;
    
    function ToString(): String; override;

    function GetEncoding(AEncoding: Int32): IAsn1Encoding; override;
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding; override;
    function GetEncodingDer(): IDerEncoding; override;
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding; override;
    
    property Value: TBigInteger read GetValue;
    property PositiveValue: TBigInteger read GetPositiveValue;
    property IntValueExact: Int32 read GetIntValueExact;
    property IntPositiveValueExact: Int32 read GetIntPositiveValueExact;
    property LongValueExact: Int64 read GetLongValueExact;
  end;

  /// <summary>
  /// DER NumericString object.
  /// </summary>
  TDerNumericString = class(TDerStringBase, IDerNumericString)
  strict private
    FContents: TCryptoLibByteArray;
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerNumericString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a NumericString from a string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Create a NumericString from a string with optional validation.
    /// </summary>
    constructor Create(const AStr: String; AValidate: Boolean); overload;
    /// <summary>
    /// Create a NumericString from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Check if string can be represented as NumericString.
    /// </summary>
    class function IsNumericString(const AStr: String): Boolean;  overload; static;
    /// <summary>
    /// Check if byte array can be represented as NumericString.
    /// </summary>
    class function IsNumericString(const AContents: TCryptoLibByteArray): Boolean;  overload; static;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerNumericString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerNumericString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerNumericString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerNumericString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerNumericString; overload; static;
    /// <summary>
    /// Get optional NumericString from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerNumericString; static;
    /// <summary>
    /// Get tagged NumericString from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerNumericString; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  end;

  /// <summary>
  /// DER PrintableString object.
  /// </summary>
  TDerPrintableString = class(TDerStringBase, IDerPrintableString)
  strict private
    FContents: TCryptoLibByteArray;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerPrintableString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a PrintableString from a string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Create a PrintableString from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerPrintableString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerPrintableString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerPrintableString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerPrintableString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerPrintableString; overload; static;
    /// <summary>
    /// Get optional PrintableString from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerPrintableString; static;
    /// <summary>
    /// Get tagged PrintableString from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerPrintableString; static;
    /// <summary>
    /// Check if string can be represented as PrintableString.
    /// </summary>
    class function IsPrintableString(const AStr: String): Boolean; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  strict private
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  end;

  /// <summary>
  /// DER T61String object.
  /// </summary>
  TDerT61String = class(TDerStringBase, IDerT61String)
  strict private
    class var FEncoding: TEncoding;

    var
     FContents: TCryptoLibByteArray;

    class constructor Create;
    class destructor Destroy;

    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;

  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerT61String universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a T61String from a string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Create a T61String from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerT61String; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerT61String; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerT61String; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerT61String; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerT61String; overload; static;
    /// <summary>
    /// Get optional T61String from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerT61String; static;
    /// <summary>
    /// Get tagged T61String from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerT61String; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  end;

  /// <summary>
  /// DER UniversalString object.
  /// </summary>
  TDerUniversalString = class(TDerStringBase, IDerUniversalString)
  strict private
    FContents: TCryptoLibByteArray;
    procedure EncodeHexByte(ABuf: TStringBuilder; AByte: Byte; const ATable: array of Char);
    procedure EncodeHexDL(ABuf: TStringBuilder; ADl: Int32; const ATable: array of Char);
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerUniversalString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a UniversalString from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerUniversalString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerUniversalString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerUniversalString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerUniversalString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUniversalString; overload; static;
    /// <summary>
    /// Get optional UniversalString from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerUniversalString; static;
    /// <summary>
    /// Get tagged UniversalString from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUniversalString; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  strict private
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  end;

  /// <summary>
  /// DER UTF8String object.
  /// </summary>
  TDerUtf8String = class(TDerStringBase, IDerUtf8String)
  strict private
    FContents: TCryptoLibByteArray;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerUtf8String universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a UTF8 string from a string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Create a UTF8 string from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerUtf8String; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerUtf8String; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerUtf8String; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerUtf8String; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUtf8String; overload; static;
    /// <summary>
    /// Get optional UTF8 string from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerUtf8String; static;
    /// <summary>
    /// Get tagged UTF8 string from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUtf8String; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  strict private
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  end;

  /// <summary>
  /// DER VideotexString object.
  /// </summary>
  TDerVideotexString = class(TDerStringBase, IDerVideotexString)
  strict private
    FContents: TCryptoLibByteArray;
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerVideotexString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a VideotexString from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerVideotexString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerVideotexString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerVideotexString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerVideotexString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVideotexString; overload; static;
    /// <summary>
    /// Get optional VideotexString from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerVideotexString; static;
    /// <summary>
    /// Get tagged VideotexString from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVideotexString; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  end;

  /// <summary>
  /// DER VisibleString object.
  /// </summary>
  TDerVisibleString = class(TDerStringBase, IDerVisibleString)
  strict private
    FContents: TCryptoLibByteArray;
  strict protected
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;
    function GetTagNo(): Int32; override;
    function GetContents(): TCryptoLibByteArray; override;
  public
    type
      /// <summary>
      /// Meta class for TDerVisibleString universal type.
      /// </summary>
      Meta = class sealed(TAsn1UniversalType, IAsn1UniversalType)
      strict private
        class var FInstance: IAsn1UniversalType;
        class function GetInstance: IAsn1UniversalType; static;
        constructor Create;
      strict protected
        function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object; override;
      public
        class property Instance: IAsn1UniversalType read GetInstance;
      end;
  public
    /// <summary>
    /// Create a VisibleString from a string.
    /// </summary>
    constructor Create(const AStr: String); overload;
    /// <summary>
    /// Create a VisibleString from byte array.
    /// </summary>
    constructor Create(const AContents: TCryptoLibByteArray); overload;
    /// <summary>
    /// Get instance from object.
    /// </summary>
    class function GetInstance(const AObj: TObject): IDerVisibleString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Object): IDerVisibleString; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDerVisibleString; overload; static;
    /// <summary>
    /// Get instance from byte array.
    /// </summary>
    class function GetInstance(const ABytes: TCryptoLibByteArray): IDerVisibleString; overload; static;
    /// <summary>
    /// Get instance from tagged object.
    /// </summary>
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVisibleString; overload; static;
    /// <summary>
    /// Get optional VisibleString from element.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IDerVisibleString; static;
    /// <summary>
    /// Get tagged VisibleString from tagged object.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVisibleString; static;
    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String; override;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Create primitive from contents.
    /// </summary>
    class function CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object; static;
  strict private
    constructor Create(const AContents: TCryptoLibByteArray; AClone: Boolean); overload;
  end;

  /// <summary>
  /// DL (Definite Length) constructed encoding.
  /// </summary>
  TConstructedDLEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElements: TCryptoLibGenericArray<IAsn1Encoding>;
    FContentsLength: Int32;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DL tagged encoding.
  /// </summary>
  TTaggedDLEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElement: IAsn1Encoding;
    FContentsLength: Int32;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElement: IAsn1Encoding);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DER constructed encoding.
  /// </summary>
  TConstructedDerEncoding = class sealed(TDerEncoding, IConstructedDerEncoding)
  strict private
    FContentsElements: TCryptoLibGenericArray<IDerEncoding>;
    FContentsLength: Int32;
  strict protected
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElements: TCryptoLibGenericArray<IDerEncoding>);
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsLength(): Int32;
    function GetContentsElements(): TCryptoLibGenericArray<IDerEncoding>;
  end;

  /// <summary>
  /// DER tagged encoding.
  /// </summary>
  TTaggedDerEncoding = class sealed(TDerEncoding, ITaggedDerEncoding)
  strict private
    FContentsElement: IDerEncoding;
    FContentsLength: Int32;
  strict protected
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElement: IDerEncoding);
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsLength(): Int32;
    function GetContentsElement(): IDerEncoding;
  end;

  /// <summary>
  /// IL (Indefinite Length) constructed encoding.
  /// </summary>
  TConstructedILEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElements: TCryptoLibGenericArray<IAsn1Encoding>;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// IL tagged encoding.
  /// </summary>
  TTaggedILEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsElement: IAsn1Encoding;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsElement: IAsn1Encoding);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// Primitive encoding.
  /// </summary>
  TPrimitiveEncoding = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsOctets: TCryptoLibByteArray;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DER primitive encoding.
  /// </summary>
  TPrimitiveDerEncoding = class sealed(TDerEncoding, IPrimitiveDerEncoding)
  protected
    FContentsOctets: TCryptoLibByteArray;
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray); overload;
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Primitive encoding with suffix.
  /// </summary>
  TPrimitiveEncodingSuffixed = class sealed(TInterfacedObject, IAsn1Encoding)
  strict private
    FTagClass: Int32;
    FTagNo: Int32;
    FContentsOctets: TCryptoLibByteArray;
    FContentsSuffix: Byte;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
    procedure Encode(const AOut: TStream);
    function GetLength(): Int32;
  end;

  /// <summary>
  /// DER primitive encoding with suffix.
  /// </summary>
  TPrimitiveDerEncodingSuffixed = class sealed(TDerEncoding, IPrimitiveDerEncodingSuffixed)
  protected
    FContentsOctets: TCryptoLibByteArray;
    FContentsSuffix: Byte;
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32; override;
    class function CompareSuffixed(const AOctetsA: TCryptoLibByteArray;
      ASuffixA: Byte; const AOctetsB: TCryptoLibByteArray; ASuffixB: Byte): Int32; static;
  public
    constructor Create(ATagClass, ATagNo: Int32;
      const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
    procedure Encode(const AOut: TStream); override;
    function GetLength(): Int32; override;
    function GetContentsOctets(): TCryptoLibByteArray;
    function GetContentsSuffix(): Byte;
  end;

implementation

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

{ TAsn1Encodable }

procedure TAsn1Encodable.EncodeTo(const AOutput: TStream);
begin
  ToAsn1Object().EncodeTo(AOutput);
end;

procedure TAsn1Encodable.EncodeTo(const AOutput: TStream; const AEncoding: String);
begin
  ToAsn1Object().EncodeTo(AOutput, AEncoding);
end;

function TAsn1Encodable.GetEncoded(): TCryptoLibByteArray;
begin
  Result := GetEncoded(Ber, 0, 0);
end;

function TAsn1Encodable.GetEncoded(const AEncoding: String): TCryptoLibByteArray;
begin
  Result := GetEncoded(AEncoding, 0, 0);
end;

function TAsn1Encodable.GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray;
begin
  Result := ToAsn1Object().GetEncoded(AEncoding, APreAlloc, APostAlloc);
end;

function TAsn1Encodable.GetDerEncoded(): TCryptoLibByteArray;
begin
  try
    Result := GetEncoded(Der);
  except
    on E: EIOCryptoLibException do
      Result := nil;
  end;
end;

function TAsn1Encodable.Equals(const AObj: IAsn1Convertible): Boolean;
var
  LO1, LO2: IAsn1Object;
begin
  if (Self as IAsn1Convertible) = AObj then
  begin
    Result := True;
    Exit;
  end;

  if AObj = nil then
  begin
    Result := False;
    Exit;
  end;

  LO1 := ToAsn1Object();
  LO2 := AObj.ToAsn1Object();
  Result := (LO1 = LO2) or ((LO2 <> nil) and LO1.CallAsn1Equals(LO2));
end;

function TAsn1Encodable.GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := ToAsn1Object().CallAsn1GetHashCode();
end;

{ TDerEncoding }

constructor TDerEncoding.Create(ATagClass, ATagNo: Int32);
begin
  inherited Create;
  // Assert((ATagClass and TAsn1Tags.Private) = ATagClass);
  // Assert(ATagNo >= 0);
  FTagClass := ATagClass;
  FTagNo := ATagNo;
end;

function TDerEncoding.GetTagClass(): Int32;
begin
  Result := FTagClass;
end;

function TDerEncoding.GetTagNo(): Int32;
begin
  Result := FTagNo;
end;

function TDerEncoding.CompareTo(const AOther: IDerEncoding): Int32;
begin
  if AOther = nil then
  begin
    Result := 1;
    Exit;
  end;

  if FTagClass <> AOther.TagClass then
  begin
    Result := FTagClass - AOther.TagClass;
    Exit;
  end;

  if FTagNo <> AOther.TagNo then
  begin
    Result := FTagNo - AOther.TagNo;
    Exit;
  end;

  Result := CompareLengthAndContents(AOther);
end;

{ TAsn1EncodableVector }

class function TAsn1EncodableVector.CopyElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>;
  AElementCount: Int32): TCryptoLibGenericArray<IAsn1Encodable>;
var
  I: Int32;
begin
  if AElementCount < 1 then
  begin
    Result := FEmptyElements;
    Exit;
  end;

  System.SetLength(Result, AElementCount);
  for I := 0 to AElementCount - 1 do
    Result[I] := AElements[I];
end;

constructor TAsn1EncodableVector.Create();
begin
  Create(DefaultCapacity);
end;

constructor TAsn1EncodableVector.Create(AInitialCapacity: Int32);
begin
  inherited Create;
  if AInitialCapacity < 0 then
    raise EArgumentCryptoLibException.Create('must not be negative');

  if AInitialCapacity = 0 then
    FElements := FEmptyElements
  else
    System.SetLength(FElements, AInitialCapacity);
  FElementCount := 0;
  FCopyOnWrite := False;
end;

constructor TAsn1EncodableVector.Create(const AElement: IAsn1Encodable);
begin
  Create();
  Add(AElement);
end;

constructor TAsn1EncodableVector.Create(const AElement1, AElement2: IAsn1Encodable);
begin
  Create();
  Add(AElement1);
  Add(AElement2);
end;

constructor TAsn1EncodableVector.Create(const AElements: array of IAsn1Encodable);
var
  I: Int32;
begin
  Create();
  for I := 0 to System.Length(AElements) - 1 do
    Add(AElements[I]);
end;

procedure TAsn1EncodableVector.Add(const AElement: IAsn1Encodable);
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  PrepareCapacity(1);
  FElements[FElementCount] := AElement;
  System.Inc(FElementCount);
end;

procedure TAsn1EncodableVector.Add(const AElement1, AElement2: IAsn1Encodable);
begin
  Add(AElement1);
  Add(AElement2);
end;

procedure TAsn1EncodableVector.Add(const AObjs: array of IAsn1Encodable);
var
  I: Int32;
begin
  for I := 0 to System.Length(AObjs) - 1 do
    Add(AObjs[I]);
end;

procedure TAsn1EncodableVector.AddOptional(const AElement: IAsn1Encodable);
begin
  if AElement <> nil then
    Add(AElement);
end;

procedure TAsn1EncodableVector.AddOptional(const AElement1, AElement2: IAsn1Encodable);
begin
  AddOptional(AElement1);
  AddOptional(AElement2);
end;

procedure TAsn1EncodableVector.AddOptional(const AElements: array of IAsn1Encodable);
var
  I: Int32;
begin
  if System.Length(AElements) > 0 then
  begin
    for I := 0 to System.Length(AElements) - 1 do
      AddOptional(AElements[I]);
  end;
end;

procedure TAsn1EncodableVector.AddOptionalTagged(AIsExplicit: Boolean; ATagNo: Int32;
  const AObj: IAsn1Encodable);
var
  LExplicitness: Int32;
begin
  if AObj <> nil then
  begin
    if AIsExplicit then
      LExplicitness := 1  // DeclaredExplicit
    else
      LExplicitness := 2; // DeclaredImplicit
    Add(TDerTaggedObject.Create(LExplicitness, TAsn1Tags.ContextSpecific, ATagNo, AObj));
  end;
end;

procedure TAsn1EncodableVector.AddOptionalTagged(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
  const AObj: IAsn1Encodable);
var
  LExplicitness: Int32;
begin
  if AObj <> nil then
  begin
    if AIsExplicit then
      LExplicitness := 1  // DeclaredExplicit
    else
      LExplicitness := 2; // DeclaredImplicit
    Add(TDerTaggedObject.Create(LExplicitness, ATagClass, ATagNo, AObj));
  end;
end;

procedure TAsn1EncodableVector.AddAll(const AE: TCryptoLibGenericArray<IAsn1Encodable>);
var
  I: Int32;
begin
  if AE = nil then
    raise EArgumentNilCryptoLibException.Create('e');

  for I := 0 to System.Length(AE) - 1 do
    Add(AE[I]);
end;

procedure TAsn1EncodableVector.AddAll(const AOther: IAsn1EncodableVector);
var
  I: Int32;
  LOtherElementCount: Int32;
begin
  if AOther = nil then
    raise EArgumentNilCryptoLibException.Create('other');

  LOtherElementCount := AOther.Count;
  if LOtherElementCount < 1 then
    Exit;

  PrepareCapacity(LOtherElementCount);
  for I := 0 to LOtherElementCount - 1 do
  begin
    FElements[FElementCount] := AOther[I];
    System.Inc(FElementCount);
  end;
end;

function TAsn1EncodableVector.GetItem(AIndex: Int32): IAsn1Encodable;
begin
  if AIndex >= FElementCount then
    raise EArgumentOutOfRangeCryptoLibException.CreateFmt('%d >= %d', [AIndex, FElementCount]);

  Result := FElements[AIndex];
end;

function TAsn1EncodableVector.GetCount(): Int32;
begin
  Result := FElementCount;
end;

function TAsn1EncodableVector.CopyElements(): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := CopyElements(FElements, FElementCount);
end;

function TAsn1EncodableVector.TakeElements(): TCryptoLibGenericArray<IAsn1Encodable>;
var
  I: Int32;
begin
  if FElementCount = 0 then
  begin
    Result := FEmptyElements;
    Exit;
  end;

  if System.Length(FElements) = FElementCount then
  begin
    FCopyOnWrite := True;
    Result := FElements;
    Exit;
  end;

  System.SetLength(Result, FElementCount);

  for I := 0 to FElementCount - 1 do
    Result[I] := FElements[I];
end;

function TAsn1EncodableVector.PrepareCapacity(ARequiredCapacity: Int32): Int32;
var
  LCapacity, LMinCapacity: Int32;
begin
  LCapacity := System.Length(FElements);
  LMinCapacity := FElementCount + ARequiredCapacity;
  if (LMinCapacity > LCapacity) or FCopyOnWrite then
    Reallocate(LMinCapacity);
  Result := LMinCapacity;
end;

procedure TAsn1EncodableVector.Reallocate(AMinCapacity: Int32);
var
  I: Int32;
  LOldCapacity, LNewCapacity: Int32;
  LCopy: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  LOldCapacity := System.Length(FElements);
  LNewCapacity := Math.Max(LOldCapacity, AMinCapacity + (TBitUtilities.Asr32(AMinCapacity, 1)));

  System.SetLength(LCopy, LNewCapacity);
  for I := 0 to FElementCount - 1 do
    LCopy[I] := FElements[I];

  FElements := LCopy;
  FCopyOnWrite := False;
end;

class function TAsn1EncodableVector.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector;
var
  LV: TAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(System.Length(AC));
  LV.AddAll(AC);
  Result := LV;
end;

class function TAsn1EncodableVector.FromElement(const AElement: IAsn1Encodable): IAsn1EncodableVector;
var
  LV: TAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(1);
  LV.Add(AElement);
  Result := LV;
end;

class function TAsn1EncodableVector.FromEnumerable(const AE: TCryptoLibGenericArray<IAsn1Encodable>): IAsn1EncodableVector;
var
  LV: TAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create();
  LV.AddAll(AE);
  Result := LV;
end;

class function TAsn1EncodableVector.CloneElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := CopyElements(AElements, System.Length(AElements));
end;

class constructor TAsn1EncodableVector.Create;
begin
  FEmptyElements := nil;
end;

{ TAsn1Object }

procedure TAsn1Object.EncodeTo(const AOutput: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.CreateInstance(AOutput, TAsn1Encodable.Ber, True);
  try
    GetEncoding(LAsn1Out.Encoding).Encode(LAsn1Out);
  finally
    LAsn1Out.Free;
  end;
end;

procedure TAsn1Object.EncodeTo(const AOutput: TStream; const AEncoding: String);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.CreateInstance(AOutput, AEncoding, True);
  try
    GetEncoding(LAsn1Out.Encoding).Encode(LAsn1Out);
  finally
    LAsn1Out.Free;
  end;
end;

function TAsn1Object.GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray;
var
  LEncodingType, LLength: Int32;
  LAsn1Encoding: IAsn1Encoding;
  LAsn1Out: TAsn1OutputStream;
begin
  LEncodingType := TAsn1OutputStream.GetEncodingType(AEncoding);
  LAsn1Encoding := GetEncoding(LEncodingType);
  LLength := LAsn1Encoding.GetLength();
  System.SetLength(Result, APreAlloc + LLength + APostAlloc);
  LAsn1Out := TAsn1OutputStream.CreateInstance(Result, APreAlloc, LLength, AEncoding, False);
  try
    LAsn1Encoding.Encode(LAsn1Out);
    // Assert(LAsn1Out.Length = LAsn1Out.Position);
  finally
    LAsn1Out.Free;
  end;
end;

function TAsn1Object.Equals(const AOther: IAsn1Object): Boolean;
begin
  Result := (Self as IAsn1Object) = AOther;
  if not Result and (AOther <> nil) then
    Result := Asn1Equals(AOther);
end;

class function TAsn1Object.FromByteArray(const AData: TCryptoLibByteArray): IAsn1Object;
begin
  Result := FromBufferStream(TFixedBufferStream.Create(AData, 0, System.Length(AData), False));
end;

class function TAsn1Object.FromBufferStream(const ABufferStream: TFixedBufferStream): IAsn1Object;
var
  LAsn1In: TAsn1InputStream;
begin
  LAsn1In := TAsn1InputStream.Create(ABufferStream);
  try
    Result := LAsn1In.ReadObject();
    if LAsn1In.Position <> LAsn1In.Size then
      raise EIOCryptoLibException.Create('extra data found after object');
  finally
    LAsn1In.Free;
  end;
end;

class function TAsn1Object.FromStream(const AInStr: TStream): IAsn1Object;
var
  LLimit: Int32;
  LAsn1In: TAsn1InputStream;
begin
  LLimit := TAsn1InputStream.FindLimit(AInStr);
  LAsn1In := TAsn1InputStream.Create(AInStr, LLimit, True);
  try
    Result := LAsn1In.ReadObject();
  finally
    LAsn1In.Free;
  end;
end;

function TAsn1Object.ToAsn1Object(): IAsn1Object;
begin
  Result := Self as IAsn1Object;
end;

function TAsn1Object.CallAsn1Equals(const AObj: IAsn1Object): Boolean;
begin
  Result := Asn1Equals(AObj);
end;

function TAsn1Object.CallAsn1GetHashCode(): Int32;
begin
  Result := Asn1GetHashCode();
end;


{ TAsn1TaggedObject }

constructor TAsn1TaggedObject.Create(AIsExplicit: Boolean; ATagNo: Int32;
  const AObj: IAsn1Encodable);
begin
  Create(AIsExplicit, TAsn1Tags.ContextSpecific, ATagNo, AObj);
end;

constructor TAsn1TaggedObject.Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
  const AObj: IAsn1Encodable);
begin
  if AIsExplicit then
    Create(DeclaredExplicit, ATagClass, ATagNo, AObj)
  else
    Create(DeclaredImplicit, ATagClass, ATagNo, AObj);
end;

constructor TAsn1TaggedObject.Create(AExplicitness, ATagClass, ATagNo: Int32;
  const AObj: IAsn1Encodable);
var
  LChoice: IAsn1Choice;
begin
  inherited Create;
  if AObj = nil then
    raise EArgumentNilCryptoLibException.Create('obj');
  if (TAsn1Tags.Universal = ATagClass) or ((ATagClass and TAsn1Tags.Private) <> ATagClass) then
    raise EArgumentCryptoLibException.Create('invalid tag class: ' + IntToStr(ATagClass));
  
  // IAsn1Choice marker interface 'insists' on explicit tagging
  if Supports(AObj, IAsn1Choice, LChoice) then
    FExplicitness := DeclaredExplicit
  else
    FExplicitness := AExplicitness;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FObject := AObj;
end;

function TAsn1TaggedObject.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1TaggedObject;
  LP1, LP2: IAsn1Object;
  LD1, LD2: TCryptoLibByteArray;
begin
  if not Supports(AAsn1Object, IAsn1TaggedObject, LThat) then
  begin
    Result := False;
    Exit;
  end;

  if (FTagNo <> LThat.TagNo) or (FTagClass <> LThat.TagClass) then
  begin
    Result := False;
    Exit;
  end;

  // Check explicitness
  if FExplicitness <> LThat.Explicitness then
  begin
    // If explicitness differs, check if IsExplicit() differs
    if IsExplicit() <> LThat.IsExplicit() then
    begin
      Result := False;
      Exit;
    end;
  end;

  LP1 := FObject.ToAsn1Object();
  LP2 := LThat.GetBaseObject().ToAsn1Object();

  if LP1 = LP2 then
  begin
    Result := True;
    Exit;
  end;

  if not IsExplicit() then
  begin
    try
      LD1 := GetEncoded();
      LD2 := AAsn1Object.GetEncoded();
      Result := TArrayUtilities.AreEqual<Byte>(LD1, LD2);
      Exit;
    except
      on E: Exception do
      begin
        Result := False;
        Exit;
      end;
    end;
  end;

  Result := LP1.CallAsn1Equals(LP2);
end;

function TAsn1TaggedObject.Asn1GetHashCode(): Int32;
begin
  Result := (FTagClass * 7919) xor FTagNo;
  if IsExplicit() then
    Result := Result xor $0F
  else
    Result := Result xor $F0;
  Result := Result xor FObject.ToAsn1Object().CallAsn1GetHashCode();
end;

function TAsn1TaggedObject.GetTagClass(): Int32;
begin
  Result := FTagClass;
end;

function TAsn1TaggedObject.GetTagNo(): Int32;
begin
  Result := FTagNo;
end;

function TAsn1TaggedObject.GetExplicitness(): Int32;
begin
  Result := FExplicitness;
end;

function TAsn1TaggedObject.IsExplicit(): Boolean;
begin
  case FExplicitness of
    DeclaredExplicit, ParsedExplicit:
      Result := True;
  else
    Result := False;
  end;
end;

function TAsn1TaggedObject.IsParsed(): Boolean;
begin
  case FExplicitness of
    ParsedExplicit, ParsedImplicit:
      Result := True;
  else
    Result := False;
  end;
end;

function TAsn1TaggedObject.GetObject(): IAsn1Object;
var
  LTagged: IAsn1TaggedObject;
begin
  // Check that tag class is ContextSpecific using TAsn1Utilities
  LTagged := Self as IAsn1TaggedObject;
  TAsn1Utilities.CheckContextTagClass(LTagged);
  Result := FObject.ToAsn1Object();
end;

function TAsn1TaggedObject.GetObjectParser(ATag: Int32; AIsExplicit: Boolean): IAsn1Convertible;
var
  LTagged: IAsn1TaggedObject;
begin
  LTagged := Self as IAsn1TaggedObject;
  
  // Handle specific tag types first
  case ATag of
    TAsn1Tags.&Set:
      begin
        Result := TAsn1Set.GetInstance(LTagged, AIsExplicit).Parser;
        Exit;
      end;
    TAsn1Tags.Sequence:
      begin
        Result := TAsn1Sequence.GetInstance(LTagged, AIsExplicit).Parser;
        Exit;
      end;
    TAsn1Tags.OctetString:
      begin
        Result := TAsn1OctetString.GetInstance(LTagged, AIsExplicit);
        Exit;
      end;
  end;

  // If explicit, return the object itself
  if AIsExplicit then
  begin
    Result := GetObject();
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateFmt('implicit tagging not implemented for tag %d', [ATag]);
end;

function TAsn1TaggedObject.ToString(): String;
var
  LTagText: String;
  LObj: IAsn1Object;
  LTagged: IAsn1TaggedObject;
begin
  LTagged := Self as IAsn1TaggedObject;
  LTagText := TAsn1Utilities.GetTagText(LTagged);

  LObj := FObject.ToAsn1Object();
  Result := LTagText + LObj.ToString();
end;

function TAsn1TaggedObject.HasContextTag(): Boolean;
begin
  Result := FTagClass = TAsn1Tags.ContextSpecific;
end;

function TAsn1TaggedObject.HasContextTag(ATagNo: Int32): Boolean;
begin
  Result := (FTagClass = TAsn1Tags.ContextSpecific) and (FTagNo = ATagNo);
end;

function TAsn1TaggedObject.HasTag(ATagClass, ATagNo: Int32): Boolean;
begin
  Result := (FTagClass = ATagClass) and (FTagNo = ATagNo);
end;

function TAsn1TaggedObject.HasTagClass(ATagClass: Int32): Boolean;
begin
  Result := FTagClass = ATagClass;
end;

function TAsn1TaggedObject.ParseBaseUniversal(ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible;
var
  LAsn1Object: IAsn1Object;
  LBitString: IDerBitString;
  LOctetString: IAsn1OctetString;
  LSequence: IAsn1Sequence;
  LSet: IAsn1Set;
begin
  LAsn1Object := GetBaseUniversal(ADeclaredExplicit, ABaseTagNo);
  
  case ABaseTagNo of
    TAsn1Tags.BitString:
      begin
        if Supports(LAsn1Object, IDerBitString, LBitString) then
          Result := LBitString.Parser
        else
          Result := LAsn1Object;
      end;
    TAsn1Tags.OctetString:
      begin
        if Supports(LAsn1Object, IAsn1OctetString, LOctetString) then
          Result := LOctetString as IAsn1Convertible
        else
          Result := LAsn1Object;
      end;
    TAsn1Tags.Sequence:
      begin
        if Supports(LAsn1Object, IAsn1Sequence, LSequence) then
          Result := LSequence.Parser
        else
          Result := LAsn1Object;
      end;
    TAsn1Tags.&Set:
      begin
        if Supports(LAsn1Object, IAsn1Set, LSet) then
          Result := LSet.Parser
        else
          Result := LAsn1Object;
      end;
  else
    Result := LAsn1Object;
  end;
end;

function TAsn1TaggedObject.GetBaseObject(): IAsn1Encodable;
begin
  Result := FObject;
end;

function TAsn1TaggedObject.GetExplicitBaseObject(): IAsn1Encodable;
begin
  if not IsExplicit() then
    raise EInvalidOperationCryptoLibException.Create('object implicit - explicit expected.');
  Result := FObject;
end;

function TAsn1TaggedObject.GetExplicitBaseTagged(): IAsn1TaggedObject;
begin
  if not IsExplicit() then
    raise EInvalidOperationCryptoLibException.Create('object implicit - explicit expected.');

  Result := CheckedCast(FObject.ToAsn1Object());
end;

function TAsn1TaggedObject.GetImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObject;
var
  LTagged: IAsn1TaggedObject;
begin
  if (TAsn1Tags.Universal = ABaseTagClass) or ((ABaseTagClass and TAsn1Tags.Private) <> ABaseTagClass) then
    raise EArgumentCryptoLibException.Create('invalid base tag class: ' + IntToStr(ABaseTagClass));

  case FExplicitness of
    DeclaredExplicit:
      raise EInvalidOperationCryptoLibException.Create('object explicit - implicit expected.');
    DeclaredImplicit:
      begin
        LTagged := CheckedCast(FObject.ToAsn1Object());
        // Check tag using TAsn1Utilities
        Result := TAsn1Utilities.CheckTag(LTagged, ABaseTagClass, ABaseTagNo);
      end;
  else
    // Parsed; return a virtual tag (i.e. that couldn't have been present in the encoding)
    Result := ReplaceTag(ABaseTagClass, ABaseTagNo);
  end;
end;

function TAsn1TaggedObject.GetBaseUniversal(ADeclaredExplicit: Boolean; ATagNo: Int32): IAsn1Object;
var
  LUniversalType: IAsn1UniversalType;
begin
  LUniversalType := TAsn1UniversalTypes.Get(ATagNo);
  if LUniversalType = nil then
    raise EArgumentCryptoLibException.CreateFmt('unsupported UNIVERSAL tag number: %d', [ATagNo]);
  
  Result := GetBaseUniversal(ADeclaredExplicit, LUniversalType);
end;

function TAsn1TaggedObject.GetBaseUniversal(ADeclaredExplicit: Boolean; const AUniversalType: IAsn1UniversalType): IAsn1Object;
var
  LBaseObject: IAsn1Object;
  LSequence: IAsn1Sequence;
  LOctetString: IDerOctetString;
  LRebuiltSequence: IAsn1Sequence;
begin
  if ADeclaredExplicit then
  begin
    if not IsExplicit() then
      raise EInvalidOperationCryptoLibException.Create('object implicit - explicit expected.');
    
    Result := AUniversalType.CheckedCast(GetBaseObject().ToAsn1Object());
    Exit;
  end;
  
  if FExplicitness = DeclaredExplicit then
    raise EInvalidOperationCryptoLibException.Create('object explicit - implicit expected.');
  
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  case FExplicitness of
    ParsedExplicit:
      begin
        LRebuiltSequence := RebuildConstructed(LBaseObject);
        Result := AUniversalType.FromImplicitConstructed(LRebuiltSequence);
      end;
    ParsedImplicit:
      begin
        if Supports(LBaseObject, IAsn1Sequence, LSequence) then
          Result := AUniversalType.FromImplicitConstructed(LSequence)
        else if Supports(LBaseObject, IDerOctetString, LOctetString) then
        begin
          Result := AUniversalType.FromImplicitPrimitive(LOctetString);
        end
        else
          raise EInvalidOperationCryptoLibException.Create('unexpected object type in ParsedImplicit');
      end;
  else
    Result := AUniversalType.CheckedCast(LBaseObject);
  end;
end;

function TAsn1TaggedObject.ParseExplicitBaseObject(): IAsn1Convertible;
begin
  Result := GetExplicitBaseObject();
end;

function TAsn1TaggedObject.ParseExplicitBaseTagged(): IAsn1TaggedObjectParser;
var
  LTagged: IAsn1TaggedObject;
begin
  LTagged := GetExplicitBaseTagged();
  if Supports(LTagged, IAsn1TaggedObjectParser, Result) then
    // Already a parser
  else
    raise EInvalidOperationCryptoLibException.Create('Cannot convert to parser');
end;

function TAsn1TaggedObject.ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser;
var
  LTagged: IAsn1TaggedObject;
begin
  LTagged := GetImplicitBaseTagged(ABaseTagClass, ABaseTagNo);
  if Supports(LTagged, IAsn1TaggedObjectParser, Result) then
    // Already a parser
  else
    raise EInvalidOperationCryptoLibException.Create('Cannot convert to parser');
end;

// Static methods

class function TAsn1TaggedObject.CheckInstance(const AObj: TObject): IAsn1TaggedObject;
begin
  Result := GetInstance(AObj);
  if Result = nil then
    raise EArgumentNilCryptoLibException.Create('obj');
end;

class function TAsn1TaggedObject.CheckInstance(const AObj: IAsn1Object): IAsn1TaggedObject;
begin
  Result := GetInstance(AObj);
  if Result = nil then
    raise EArgumentNilCryptoLibException.Create('obj');
end;

class function TAsn1TaggedObject.CheckInstance(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAsn1TaggedObject;
begin
  if not ADeclaredExplicit then
    raise EArgumentCryptoLibException.Create('this method not valid for implicitly tagged tagged objects');
  if ATaggedObject = nil then
    raise EArgumentNilCryptoLibException.Create('taggedObject');
  Result := ATaggedObject;
end;

class function TAsn1TaggedObject.CheckedCast(const AAsn1Object: IAsn1Object): IAsn1TaggedObject;
begin
  if not Supports(AAsn1Object, IAsn1TaggedObject, Result) then
    raise EInvalidOperationCryptoLibException.Create('unexpected object type');
end;

class function TAsn1TaggedObject.GetInstance(const AObj: TObject): IAsn1TaggedObject;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1TaggedObject.GetInstance(const AObj: IAsn1Object): IAsn1TaggedObject;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IAsn1TaggedObject, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TAsn1TaggedObject.GetInstance(const AObj: IAsn1Convertible): IAsn1TaggedObject;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1TaggedObject, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1TaggedObject.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1TaggedObject;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    Result := CheckedCast(TAsn1Object.FromByteArray(ABytes));
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct tagged object from byte[]: ' + E.Message);
  end;
end;

class function TAsn1TaggedObject.GetInstance(const AObj: TObject; ATagClass: Int32): IAsn1TaggedObject;
begin
  Result := TAsn1Utilities.CheckTagClass(CheckInstance(AObj), ATagClass);
end;

class function TAsn1TaggedObject.GetInstance(const AObj: IAsn1Object; ATagClass: Int32): IAsn1TaggedObject;
begin
  Result := TAsn1Utilities.CheckTagClass(CheckInstance(AObj), ATagClass);
end;

class function TAsn1TaggedObject.GetInstance(const AObj: TObject; ATagClass, ATagNo: Int32): IAsn1TaggedObject;
begin
  Result := TAsn1Utilities.CheckTag(CheckInstance(AObj), ATagClass, ATagNo);
end;

class function TAsn1TaggedObject.GetInstance(const AObj: IAsn1Object; ATagClass, ATagNo: Int32): IAsn1TaggedObject;
begin
  Result := TAsn1Utilities.CheckTag(CheckInstance(AObj), ATagClass, ATagNo);
end;

class function TAsn1TaggedObject.GetInstance(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAsn1TaggedObject;
begin
  Result := TAsn1Utilities.GetExplicitContextBaseTagged(CheckInstance(ATaggedObject, ADeclaredExplicit));
end;

class function TAsn1TaggedObject.GetInstance(const ATaggedObject: IAsn1TaggedObject;
  ATagClass: Int32; ADeclaredExplicit: Boolean): IAsn1TaggedObject;
begin
  Result := TAsn1Utilities.GetExplicitBaseTagged(CheckInstance(ATaggedObject, ADeclaredExplicit), ATagClass);
end;

class function TAsn1TaggedObject.GetInstance(const ATaggedObject: IAsn1TaggedObject;
  ATagClass, ATagNo: Int32; ADeclaredExplicit: Boolean): IAsn1TaggedObject;
begin
  Result := TAsn1Utilities.GetExplicitBaseTagged(CheckInstance(ATaggedObject, ADeclaredExplicit), ATagClass, ATagNo);
end;

class function TAsn1TaggedObject.GetOptional(const AElement: IAsn1Encodable): IAsn1TaggedObject;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IAsn1TaggedObject, Result) then
    Exit;
  Result := nil;
end;

class function TAsn1TaggedObject.GetOptional(const AElement: IAsn1Encodable;
  ATagClass: Int32): IAsn1TaggedObject;
begin
  Result := GetOptional(AElement);
  if (Result <> nil) and Result.HasTagClass(ATagClass) then
    Exit;
  Result := nil;
end;

class function TAsn1TaggedObject.GetOptional(const AElement: IAsn1Encodable;
  ATagClass, ATagNo: Int32): IAsn1TaggedObject;
begin
  Result := GetOptional(AElement);
  if (Result <> nil) and Result.HasTag(ATagClass, ATagNo) then
    Exit;
  Result := nil;
end;

class function TAsn1TaggedObject.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAsn1TaggedObject;
begin
  Result := CheckInstance(ATaggedObject, ADeclaredExplicit).GetExplicitBaseTagged();
end;

{ TDerTaggedObject }

constructor TDerTaggedObject.Create(ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(True, ATagNo, AObj);
end;

constructor TDerTaggedObject.Create(ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(True, ATagClass, ATagNo, AObj);
end;

constructor TDerTaggedObject.Create(AIsExplicit: Boolean; ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(AIsExplicit, ATagNo, AObj);
end;

constructor TDerTaggedObject.Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(AIsExplicit, ATagClass, ATagNo, AObj);
end;

constructor TDerTaggedObject.Create(AExplicitness, ATagClass, ATagNo: Int32;
  const AObj: IAsn1Encodable);
begin
  inherited Create(AExplicitness, ATagClass, ATagNo, AObj);
end;

function TDerTaggedObject.GetIsConstructed(): Boolean;
begin
  // DER tagged objects are always constructed
  Result := True;
end;

function TDerTaggedObject.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
begin
  // TDerTaggedObject inherits Asn1Equals from TAsn1TaggedObject
  Result := inherited Asn1Equals(AAsn1Object);
end;

function TDerTaggedObject.Asn1GetHashCode(): Int32;
begin
  // TDerTaggedObject inherits Asn1GetHashCode from TAsn1TaggedObject
  Result := inherited Asn1GetHashCode();
end;

function TDerTaggedObject.GetEncoding(AEncoding: Int32): IAsn1Encoding;
var
  LBaseObject: IAsn1Object;
begin
  AEncoding := TAsn1OutputStream.EncodingDer;
  
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingImplicit(AEncoding, GetTagClass(), GetTagNo());
    Exit;
  end;
  
  Result := TTaggedDLEncoding.Create(GetTagClass(), GetTagNo(), LBaseObject.GetEncoding(AEncoding));
end;

function TDerTaggedObject.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
var
  LBaseObject: IAsn1Object;
begin
  AEncoding := TAsn1OutputStream.EncodingDer;
  
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TTaggedDLEncoding.Create(ATagClass, ATagNo, LBaseObject.GetEncoding(AEncoding));
end;

function TDerTaggedObject.GetEncodingDer(): IDerEncoding;
var
  LBaseObject: IAsn1Object;
begin
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingDerImplicit(GetTagClass(), GetTagNo());
    Exit;
  end;
  
  Result := TTaggedDerEncoding.Create(GetTagClass(), GetTagNo(), LBaseObject.GetEncodingDer());
end;

function TDerTaggedObject.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
var
  LBaseObject: IAsn1Object;
begin
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingDerImplicit(ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TTaggedDerEncoding.Create(ATagClass, ATagNo, LBaseObject.GetEncodingDer());
end;

function TDerTaggedObject.RebuildConstructed(const AAsn1Object: IAsn1Object): IAsn1Sequence;
begin
  Result := TDerSequence.Create(AAsn1Object as IAsn1Encodable);
end;

function TDerTaggedObject.ReplaceTag(ATagClass, ATagNo: Int32): IAsn1TaggedObject;
var
  LExplicitness: Int32;
begin
  if IsExplicit() then
    LExplicitness := 1  // DeclaredExplicit
  else
    LExplicitness := 2; // DeclaredImplicit
  Result := TDerTaggedObject.Create(LExplicitness, ATagClass, ATagNo, FObject);
end;

{ TDLTaggedObject }

constructor TDLTaggedObject.Create(ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(ATagNo, AObj);
end;

constructor TDLTaggedObject.Create(ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(ATagClass, ATagNo, AObj);
end;

constructor TDLTaggedObject.Create(AIsExplicit: Boolean; ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(AIsExplicit, ATagNo, AObj);
end;

constructor TDLTaggedObject.Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(AIsExplicit, ATagClass, ATagNo, AObj);
end;

constructor TDLTaggedObject.Create(AExplicitness, ATagClass, ATagNo: Int32;
  const AObj: IAsn1Encodable);
begin
  inherited Create(AExplicitness, ATagClass, ATagNo, AObj);
end;

function TDLTaggedObject.GetEncoding(AEncoding: Int32): IAsn1Encoding;
var
  LBaseObject: IAsn1Object;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;
  
  AEncoding := TAsn1OutputStream.EncodingDL;
  
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingImplicit(AEncoding, GetTagClass(), GetTagNo());
    Exit;
  end;
  
  Result := TTaggedDLEncoding.Create(GetTagClass(), GetTagNo(), LBaseObject.GetEncoding(AEncoding));
end;

function TDLTaggedObject.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
var
  LBaseObject: IAsn1Object;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  AEncoding := TAsn1OutputStream.EncodingDL;
  
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TTaggedDLEncoding.Create(ATagClass, ATagNo, LBaseObject.GetEncoding(AEncoding));
end;

function TDLTaggedObject.RebuildConstructed(const AAsn1Object: IAsn1Object): IAsn1Sequence;
begin
  Result := TDLSequence.Create(AAsn1Object as IAsn1Encodable);
end;

function TDLTaggedObject.ReplaceTag(ATagClass, ATagNo: Int32): IAsn1TaggedObject;
var
  LExplicitness: Int32;
begin
  if IsExplicit() then
    LExplicitness := 1  // DeclaredExplicit
  else
    LExplicitness := 2; // DeclaredImplicit
  Result := TDLTaggedObject.Create(LExplicitness, ATagClass, ATagNo, FObject);
end;

{ TAsn1Sequence }

constructor TAsn1Sequence.Create();
begin
  inherited Create;
  FElements := TAsn1EncodableVector.EmptyElements;
end;

constructor TAsn1Sequence.Create(const AElement: IAsn1Encodable);
begin
  inherited Create;
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  System.SetLength(FElements, 1);
  FElements[0] := AElement;
end;

constructor TAsn1Sequence.Create(const AElement1, AElement2: IAsn1Encodable);
begin
  inherited Create;
  if AElement1 = nil then
    raise EArgumentNilCryptoLibException.Create('element1');
  if AElement2 = nil then
    raise EArgumentNilCryptoLibException.Create('element2');
  System.SetLength(FElements, 2);
  FElements[0] := AElement1;
  FElements[1] := AElement2;
end;

constructor TAsn1Sequence.Create(const AElements: array of IAsn1Encodable);
var
  I: Int32;
begin
  inherited Create;
  // Check for null elements
  for I := 0 to System.Length(AElements) - 1 do
    if AElements[I] = nil then
      raise ENullReferenceCryptoLibException.Create('elements cannot contain null');
  System.SetLength(FElements, System.Length(AElements));
  for I := 0 to System.Length(AElements) - 1 do
    FElements[I] := AElements[I];
end;

constructor TAsn1Sequence.Create(const AElementVector: IAsn1EncodableVector);
begin
  inherited Create;
  if AElementVector = nil then
    raise EArgumentNilCryptoLibException.Create('elementVector');
  FElements := AElementVector.TakeElements();
end;

constructor TAsn1Sequence.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>);
var
  I: Int32;
begin
  inherited Create;
  if AC = nil then
    raise EArgumentNilCryptoLibException.Create('elements');
  System.SetLength(FElements, System.Length(AC));
  for I := 0 to System.Length(AC) - 1 do
    FElements[I] := AC[I];
end;

destructor TAsn1Sequence.Destroy;
begin
  inherited Destroy;
end;

function TAsn1Sequence.GetCount(): Int32;
begin
  Result := System.Length(FElements);
end;

function TAsn1Sequence.GetParser(): IAsn1SequenceParser;
begin
  Result := TAsn1SequenceParserImpl.Create(Self);
end;

function TAsn1Sequence.GetItem(AIndex: Int32): IAsn1Encodable;
begin
  if (AIndex < 0) or (AIndex >= System.Length(FElements)) then
    raise EIndexOutOfRangeCryptoLibException.Create('Index out of range');
  Result := FElements[AIndex];
end;

function TAsn1Sequence.GetElements(): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := System.Copy(FElements);
end;

function TAsn1Sequence.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1Sequence;
  I: Int32;
begin
  if not Supports(AAsn1Object, IAsn1Sequence, LThat) then
  begin
    Result := False;
    Exit;
  end;

  if GetCount() <> LThat.Count then
  begin
    Result := False;
    Exit;
  end;

  for I := 0 to GetCount() - 1 do
  begin
    if not FElements[I].ToAsn1Object().Equals(LThat[I].ToAsn1Object()) then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

function TAsn1Sequence.Asn1GetHashCode(): Int32;
var
  I: Int32;
begin
  I := GetCount();
  Result := I + 1;
  while I > 0 do
  begin
    Dec(I);
    Result := Result * 257;
    Result := Result xor FElements[I].ToAsn1Object().CallAsn1GetHashCode();
  end;
end;

function TAsn1Sequence.GetConstructedBitStrings(): TCryptoLibGenericArray<IDerBitString>;
var
  I: Int32;
  LObj: IAsn1Object;
begin
  System.SetLength(Result, GetCount());
  for I := 0 to GetCount() - 1 do
  begin
    LObj := FElements[I].ToAsn1Object();
    Result[I] := TDerBitString.GetInstance(LObj);
  end;
end;

function TAsn1Sequence.GetConstructedOctetStrings(): TCryptoLibGenericArray<IAsn1OctetString>;
var
  I: Int32;
  LObj: IAsn1Object;
begin
  System.SetLength(Result, GetCount());
  for I := 0 to GetCount() - 1 do
  begin
    LObj := FElements[I].ToAsn1Object();
    Result[I] := TAsn1OctetString.GetInstance(LObj);
  end;
end;

function TAsn1Sequence.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Sequence,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

function TAsn1Sequence.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

function TAsn1Sequence.ToArray(): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := TAsn1EncodableVector.CloneElements(FElements);
end;

function TAsn1Sequence.ToString(): String;
begin
  Result := TArrayUtilities.ToString<IAsn1Encodable>(FElements,
    function(AElement: IAsn1Encodable): String
    var
      LObj: IAsn1Object;
    begin
      if AElement <> nil then
      begin
        LObj := AElement.ToAsn1Object();
        Result := LObj.ToString();
      end
      else
        Result := '[null]';
    end);
end;

class function TAsn1Sequence.ConcatenateElements(const ASequences: TCryptoLibGenericArray<IAsn1Sequence>): TCryptoLibGenericArray<IAsn1Encodable>;
var
  LCount, I, J, LPos, LTotalElements, LElementCount: Int32;
  LSequence: IAsn1Sequence;
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  LCount := System.Length(ASequences);
  LTotalElements := 0;
  for I := 0 to LCount - 1 do
  begin
    LTotalElements := LTotalElements + ASequences[I].Count;
  end;

  System.SetLength(Result, LTotalElements);
  LPos := 0;
  for I := 0 to LCount - 1 do
  begin
    LSequence := ASequences[I];
    LElements := LSequence.Elements;
    LElementCount := System.Length(LElements);
    for J := 0 to LElementCount - 1 do
    begin
      Result[LPos] := LElements[J];
      System.Inc(LPos);
    end;
  end;
end;

function TAsn1Sequence.MapElements<TResult>(const AFunc: TFunc<IAsn1Encodable, TResult>): TCryptoLibGenericArray<TResult>;
begin
  Result := TArrayUtilities.Map<IAsn1Encodable, TResult>(FElements, AFunc);
end;

class function TAsn1Sequence.GetInstance(const AObj: TObject): IAsn1Sequence;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateFmt('illegal object in GetInstance: %s', [TPlatformUtilities.GetTypeName(AObj)]);
end;

class function TAsn1Sequence.GetInstance(const AObj: IAsn1Object): IAsn1Sequence;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IAsn1Sequence, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TAsn1Sequence.GetInstance(const AObj: IAsn1Convertible): IAsn1Sequence;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1Sequence, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1Sequence.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Sequence;
begin
  Result := TAsn1Sequence.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1Sequence;
end;

class function TAsn1Sequence.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1Sequence;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TAsn1Sequence.Meta.Instance.FromByteArray(ABytes) as IAsn1Sequence;
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct sequence from byte[]: ' + E.Message);
  end;
end;

class function TAsn1Sequence.GetOptional(const AElement: IAsn1Encodable): IAsn1Sequence;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAsn1Sequence, LSequence) then
    Result := LSequence
  else
    Result := nil;
end;

class function TAsn1Sequence.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Sequence;
begin
  Result := TAsn1Sequence.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1Sequence;
end;

{ TDerSequence }

class function TDerSequence.GetEmpty(): IDerSequence;
begin
  Result := TDerSequence.Create();
end;

constructor TDerSequence.Create();
begin
  inherited Create();
end;

constructor TDerSequence.Create(const AElement: IAsn1Encodable);
begin
  inherited Create(AElement);
end;

constructor TDerSequence.Create(const AElements: array of IAsn1Encodable);
begin
  inherited Create(AElements);
end;

constructor TDerSequence.Create(const AElementVector: IAsn1EncodableVector);
begin
  inherited Create(AElementVector);
end;

class function TDerSequence.FromVector(const AElementVector: IAsn1EncodableVector): IDerSequence;
begin
  if (AElementVector = nil) or (AElementVector.Count < 1) then
    Result := GetEmpty()
  else
    Result := TDerSequence.Create(AElementVector);
end;

function TDerSequence.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Sequence,
    TAsn1OutputStream.GetContentsEncodings(TAsn1OutputStream.EncodingDer, Elements));
end;

function TDerSequence.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodings(TAsn1OutputStream.EncodingDer, Elements));
end;

function TDerSequence.GetEncodingDer(): IDerEncoding;
begin
  Result := TConstructedDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Sequence,
    TAsn1OutputStream.GetContentsEncodingsDer(Elements));
end;

function TDerSequence.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TConstructedDerEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodingsDer(Elements));
end;

function TDerSequence.ToAsn1BitString(): IDerBitString;
var
  LBitStrings: TCryptoLibGenericArray<IDerBitString>;
begin
  LBitStrings := GetConstructedBitStrings();
  Result := TDerBitString.Create(TBerBitString.FlattenBitStrings(LBitStrings), False);
end;

function TDerSequence.ToAsn1External(): IDerExternal;
begin
  Result := TDerExternal.Create(Self);
end;

function TDerSequence.ToAsn1OctetString(): IAsn1OctetString;
var
  LOctetStrings: TCryptoLibGenericArray<IAsn1OctetString>;
begin
  LOctetStrings := GetConstructedOctetStrings();
  Result := TDerOctetString.WithContents(TBerOctetString.FlattenOctetStrings(LOctetStrings));
end;

function TDerSequence.ToAsn1Set(): IAsn1Set;
begin
  // NOTE: DLSet is intentional, we don't want sorting
  Result := TDLSet.Create(False, Elements);
end;

class function TDerSequence.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDerSequence;
begin
  if (AC = nil) or (System.Length(AC) < 1) then
    Result := GetEmpty()
  else
    Result := TDerSequence.Create(AC);
end;

class function TDerSequence.FromElement(const AElement: IAsn1Encodable): IDerSequence;
begin
  Result := TDerSequence.Create(AElement);
end;

class function TDerSequence.FromElements(const AElement1, AElement2: IAsn1Encodable): IDerSequence;
begin
  Result := TDerSequence.Create(AElement1, AElement2);
end;

class function TDerSequence.FromElements(const AElements: array of IAsn1Encodable): IDerSequence;
begin
  if System.Length(AElements) < 1 then
    Result := GetEmpty()
  else
    Result := TDerSequence.Create(AElements);
end;

class function TDerSequence.FromElementsOptional(const AElements: array of IAsn1Encodable): IDerSequence;
begin
  if System.Length(AElements) < 1 then
  begin
    Result := nil;
    Exit;
  end;
  Result := TDerSequence.Create(AElements);
end;

class function TDerSequence.FromSequence(const ASequence: IAsn1Sequence): IDerSequence;
var
  LDerSequence: IDerSequence;
begin
  if ASequence = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(ASequence, IDerSequence, LDerSequence) then
  begin
    Result := LDerSequence;
    Exit;
  end;
  Result := WithElements(ASequence.Elements);
end;

class function TDerSequence.Map(const ASequence: IAsn1Sequence; const AFunc: TFunc<IAsn1Encodable, IAsn1Encodable>): IDerSequence;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ASequence = nil) or (ASequence.Count < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<IAsn1Encodable, IAsn1Encodable>(ASequence.Elements, AFunc);
  Result := WithElements(LMapped);
end;

class function TDerSequence.Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDerSequence;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ATs = nil) or (System.Length(ATs) < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<T, IAsn1Encodable>(ATs, AFunc);
  Result := WithElements(LMapped);
end;

class function TDerSequence.Concatenate(const ASequences: array of IAsn1Sequence): IDerSequence;
var
  LSequences: TCryptoLibGenericArray<IAsn1Sequence>;
  I: Int32;
begin
  if System.Length(ASequences) = 0 then
  begin
    Result := GetEmpty();
    Exit;
  end;
  
  System.SetLength(LSequences, System.Length(ASequences));
  for I := 0 to System.Length(ASequences) - 1 do
    LSequences[I] := ASequences[I];
  
  case System.Length(LSequences) of
    0:
      Result := GetEmpty();
    1:
      Result := FromSequence(LSequences[0]);
  else
    Result := WithElements(ConcatenateElements(LSequences));
  end;
end;

class function TDerSequence.WithElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): IDerSequence;
begin
  if (AElements = nil) or (System.Length(AElements) < 1) then
    Result := GetEmpty()
  else
    Result := TDerSequence.Create(AElements);
end;

class function TDerSequence.GetEncodingLength(AContentsLength: Int32): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(TAsn1Tags.Sequence, AContentsLength);
end;

constructor TDerSequence.Create(const AElement1, AElement2: IAsn1Encodable);
begin
  inherited Create(AElement1, AElement2);
end;

constructor TDerSequence.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AC);
end;

constructor TDerSequence.Create(const ASequence: IAsn1Sequence);
begin
  inherited Create(ASequence as IAsn1Encodable);
end;

constructor TDerSequence.Create(const ASet: IAsn1Set);
begin
  inherited Create(ASet as IAsn1Encodable);
end;

{ TDLSequence }

class function TDLSequence.GetEmpty(): IDLSequence;
begin
  Result := TDLSequence.Create();
end;

constructor TDLSequence.Create();
begin
  inherited Create();
end;

constructor TDLSequence.Create(const AElement: IAsn1Encodable);
begin
  inherited Create(AElement);
end;

constructor TDLSequence.Create(const AElements: array of IAsn1Encodable);
begin
  inherited Create(AElements);
end;

constructor TDLSequence.Create(const AElementVector: IAsn1EncodableVector);
begin
  inherited Create(AElementVector);
end;

class function TDLSequence.FromVector(const AElementVector: IAsn1EncodableVector): IDLSequence;
begin
  if (AElementVector = nil) or (AElementVector.Count < 1) then
    Result := GetEmpty()
  else
    Result := TDLSequence.Create(AElementVector);
end;

function TDLSequence.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;
  
  Result := TConstructedDLEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Sequence,
    TAsn1OutputStream.GetContentsEncodings(TAsn1OutputStream.EncodingDL, Elements));
end;

function TDLSequence.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TConstructedDLEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodings(TAsn1OutputStream.EncodingDL, Elements));
end;

function TDLSequence.ToAsn1External(): IDerExternal;
begin
  Result := TDLExternal.Create(Self);
end;

function TDLSequence.ToAsn1BitString(): IDerBitString;
var
  LBitStrings: TCryptoLibGenericArray<IDerBitString>;
begin
  LBitStrings := GetConstructedBitStrings();
  Result := TDLBitString.Create(TBerBitString.FlattenBitStrings(LBitStrings), False);
end;

function TDLSequence.ToAsn1Set(): IAsn1Set;
begin
  // NOTE: DLSet is intentional, we don't want sorting
  Result := TDLSet.Create(False, Elements);
end;

class function TDLSequence.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDLSequence;
begin
  if (AC = nil) or (System.Length(AC) < 1) then
    Result := GetEmpty()
  else
    Result := TDLSequence.Create(AC);
end;

class function TDLSequence.FromElement(const AElement: IAsn1Encodable): IDLSequence;
begin
  Result := TDLSequence.Create(AElement);
end;

class function TDLSequence.FromElements(const AElement1, AElement2: IAsn1Encodable): IDLSequence;
begin
  Result := TDLSequence.Create(AElement1, AElement2);
end;

class function TDLSequence.FromElements(const AElements: array of IAsn1Encodable): IDLSequence;
begin
  if System.Length(AElements) < 1 then
    Result := GetEmpty()
  else
    Result := TDLSequence.Create(AElements);
end;

class function TDLSequence.FromElementsOptional(const AElements: array of IAsn1Encodable): IDLSequence;
begin
  if System.Length(AElements) < 1 then
  begin
    Result := nil;
    Exit;
  end;
  Result := TDLSequence.Create(AElements);
end;

class function TDLSequence.FromSequence(const ASequence: IAsn1Sequence): IDLSequence;
var
  LDLSequence: IDLSequence;
begin
  if ASequence = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(ASequence, IDLSequence, LDLSequence) then
  begin
    Result := LDLSequence;
    Exit;
  end;
  Result := WithElements(ASequence.Elements);
end;

class function TDLSequence.Map(const ASequence: IAsn1Sequence; const AFunc: TFunc<IAsn1Encodable, IAsn1Encodable>): IDLSequence;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ASequence = nil) or (ASequence.Count < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<IAsn1Encodable, IAsn1Encodable>(ASequence.Elements, AFunc);
  Result := WithElements(LMapped);
end;

class function TDLSequence.Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDLSequence;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ATs = nil) or (System.Length(ATs) < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<T, IAsn1Encodable>(ATs, AFunc);
  Result := WithElements(LMapped);
end;

class function TDLSequence.Concatenate(const ASequences: array of IAsn1Sequence): IDLSequence;
var
  LSequences: TCryptoLibGenericArray<IAsn1Sequence>;
  I: Int32;
begin
  if System.Length(ASequences) = 0 then
  begin
    Result := GetEmpty();
    Exit;
  end;
  
  System.SetLength(LSequences, System.Length(ASequences));
  for I := 0 to System.Length(ASequences) - 1 do
    LSequences[I] := ASequences[I];
  
  case System.Length(LSequences) of
    0:
      Result := GetEmpty();
    1:
      Result := FromSequence(LSequences[0]);
  else
    Result := WithElements(ConcatenateElements(LSequences));
  end;
end;

class function TDLSequence.WithElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): IDLSequence;
begin
  if (AElements = nil) or (System.Length(AElements) < 1) then
    Result := GetEmpty()
  else
    Result := TDLSequence.Create(AElements);
end;

constructor TDLSequence.Create(const AElement1, AElement2: IAsn1Encodable);
begin
  inherited Create(AElement1, AElement2);
end;

constructor TDLSequence.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AC);
end;

constructor TDLSequence.Create(const ASequence: IAsn1Sequence);
begin
  inherited Create(ASequence);
end;

constructor TDLSequence.Create(const ASet: IAsn1Set);
begin
  inherited Create(ASet);
end;

{ TAsn1Set }

constructor TAsn1Set.Create();
begin
  inherited Create;
  FElements := TAsn1EncodableVector.EmptyElements;
  FSortedDerEncodings := nil;
end;

constructor TAsn1Set.Create(const AElement: IAsn1Encodable);
begin
  inherited Create;
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  System.SetLength(FElements, 1);
  FElements[0] := AElement;
  FSortedDerEncodings := nil;
end;

constructor TAsn1Set.Create(const AElements: array of IAsn1Encodable; ADoSort: Boolean);
var
  I: Int32;
begin
  inherited Create;
  // Check for null elements
  for I := 0 to System.Length(AElements) - 1 do
    if AElements[I] = nil then
      raise ENullReferenceCryptoLibException.Create('elements cannot contain null');
  System.SetLength(FElements, System.Length(AElements));
  for I := 0 to System.Length(AElements) - 1 do
    FElements[I] := AElements[I];
  if ADoSort and (System.Length(FElements) > 1) then
    FSortedDerEncodings := SortElements(FElements)
  else
    FSortedDerEncodings := nil;
end;

constructor TAsn1Set.Create(const AElementVector: IAsn1EncodableVector; ADoSort: Boolean);
begin
  inherited Create;
  if AElementVector = nil then
    raise EArgumentNilCryptoLibException.Create('elementVector');
  if ADoSort and (AElementVector.Count > 1) then
  begin
    FElements := AElementVector.CopyElements();
    FSortedDerEncodings := SortElements(FElements);
  end
  else
  begin
    FElements := AElementVector.TakeElements();
    FSortedDerEncodings := nil;
  end;
end;

constructor TAsn1Set.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>; ADoSort: Boolean);
var
  I: Int32;
begin
  inherited Create;
  if AC = nil then
    raise EArgumentNilCryptoLibException.Create('elements');
  System.SetLength(FElements, System.Length(AC));
  for I := 0 to System.Length(AC) - 1 do
    FElements[I] := AC[I];
  if ADoSort and (System.Length(FElements) > 1) then
    FSortedDerEncodings := SortElements(FElements)
  else
    FSortedDerEncodings := nil;
end;

constructor TAsn1Set.Create(const ASequence: IAsn1Sequence);
var
  I: Int32;
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  inherited Create;
  if ASequence = nil then
    raise EArgumentNilCryptoLibException.Create('sequence');
  LElements := ASequence.Elements;
  System.SetLength(FElements, System.Length(LElements));
  for I := 0 to System.Length(LElements) - 1 do
    FElements[I] := LElements[I];
  FSortedDerEncodings := nil;
end;

constructor TAsn1Set.Create(const ASet: IAsn1Set);
var
  I: Int32;
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  inherited Create;
  if ASet = nil then
    raise EArgumentNilCryptoLibException.Create('set');
  LElements := ASet.Elements;
  System.SetLength(FElements, System.Length(LElements));
  for I := 0 to System.Length(LElements) - 1 do
    FElements[I] := LElements[I];
  FSortedDerEncodings := nil;
end;

constructor TAsn1Set.Create(AIsSorted: Boolean; const AElements: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create;
  System.Assert(not AIsSorted);
  FElements := AElements;
  FSortedDerEncodings := nil;
end;

destructor TAsn1Set.Destroy;
begin
  inherited Destroy;
end;

function TAsn1Set.GetCount(): Int32;
begin
  Result := System.Length(FElements);
end;

function TAsn1Set.GetParser(): IAsn1SetParser;
begin
  Result := TAsn1SetParserImpl.Create(Self);
end;

function TAsn1Set.GetItem(AIndex: Int32): IAsn1Encodable;
begin
  if (AIndex < 0) or (AIndex >= System.Length(FElements)) then
    raise EIndexOutOfRangeCryptoLibException.Create('Index out of range');
  Result := FElements[AIndex];
end;

function TAsn1Set.GetElements(): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := System.Copy(FElements);
end;

function TAsn1Set.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1Set;
  I: Int32;
begin
  if not Supports(AAsn1Object, IAsn1Set, LThat) then
  begin
    Result := False;
    Exit;
  end;

  if GetCount() <> LThat.Count then
  begin
    Result := False;
    Exit;
  end;

  for I := 0 to GetCount() - 1 do
  begin
    if not FElements[I].ToAsn1Object().Equals(LThat[I].ToAsn1Object()) then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

function TAsn1Set.Asn1GetHashCode(): Int32;
var
  I: Int32;
begin
  I := GetCount();
  Result := I + 1;
  while I > 0 do
  begin
    Dec(I);
    Result := Result * 257;
    Result := Result xor FElements[I].ToAsn1Object().CallAsn1GetHashCode();
  end;
end;

function TAsn1Set.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.&Set,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

function TAsn1Set.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

function TAsn1Set.MapElements<TResult>(const AFunc: TFunc<IAsn1Encodable, TResult>): TCryptoLibGenericArray<TResult>;
begin
  Result := TArrayUtilities.Map<IAsn1Encodable, TResult>(FElements, AFunc);
end;

function TAsn1Set.ToArray(): TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := TAsn1EncodableVector.CloneElements(FElements);
end;

function TAsn1Set.ToString(): String;
begin
  Result := TArrayUtilities.ToString<IAsn1Encodable>(FElements,
    function(AElement: IAsn1Encodable): String
    var
      LObj: IAsn1Object;
    begin
      if AElement <> nil then
      begin
        LObj := AElement.ToAsn1Object();
        Result := LObj.ToString();
      end
      else
        Result := '[null]';
    end);
end;

class function TAsn1Set.GetInstance(const AObj: TObject): IAsn1Set;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1Set.GetInstance(const AObj: IAsn1Object): IAsn1Set;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IAsn1Set, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TAsn1Set.GetInstance(const AObj: IAsn1Convertible): IAsn1Set;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1Set, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1Set.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1Set;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    Result := TAsn1Set.Meta.Instance.FromByteArray(ABytes) as IAsn1Set;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct set from byte[]: ' + E.Message);
  end;
end;

class function TAsn1Set.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Set;
begin
  Result := TAsn1Set.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1Set;
end;

class function TAsn1Set.GetOptional(const AElement: IAsn1Encodable): IAsn1Set;
var
  LSet: IAsn1Set;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAsn1Set, LSet) then
    Result := LSet
  else
    Result := nil;
end;

class function TAsn1Set.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Set;
begin
  Result := TAsn1Set.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1Set;
end;

class function TAsn1Set.SortElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IDerEncoding>;
var
  LCount, I, J: Int32;
  LDerEncodings: TCryptoLibGenericArray<IDerEncoding>;
  LTemp: IAsn1Encodable;
  LTempEncoding: IDerEncoding;
begin
  // Get DER encodings for each element
  LDerEncodings := TAsn1OutputStream.GetContentsEncodingsDer(AElements);
  LCount := System.Length(LDerEncodings);

  // Sort elements based on DER encodings using insertion sort
  // (handles 0 or 1 elements gracefully - loop simply doesn't execute)
  for I := 1 to LCount - 1 do
  begin
    J := I;
    while (J > 0) and (LDerEncodings[J].CompareTo(LDerEncodings[J - 1]) < 0) do
    begin
      // Swap encodings
      LTempEncoding := LDerEncodings[J];
      LDerEncodings[J] := LDerEncodings[J - 1];
      LDerEncodings[J - 1] := LTempEncoding;
      // Swap elements
      LTemp := AElements[J];
      AElements[J] := AElements[J - 1];
      AElements[J - 1] := LTemp;
      System.Dec(J);
    end;
  end;

  Result := LDerEncodings;
end;

{ TDerSet }

class function TDerSet.GetEmpty(): IDerSet;
begin
  Result := TDerSet.Create();
end;

constructor TDerSet.Create();
begin
  inherited Create();
end;

constructor TDerSet.Create(const AElement: IAsn1Encodable);
begin
  inherited Create(AElement);
end;

constructor TDerSet.Create(const AElements: array of IAsn1Encodable);
begin
  inherited Create(AElements, True); // doSort = True for DER
end;

constructor TDerSet.Create(const AElementVector: IAsn1EncodableVector);
begin
  inherited Create(AElementVector, True); // doSort = True for DER
end;

constructor TDerSet.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AC, True); // doSort = True for DER
end;

constructor TDerSet.Create(const ASequence: IAsn1Sequence);
begin
  inherited Create(ASequence);
end;

constructor TDerSet.Create(const ASet: IAsn1Set);
begin
  inherited Create(ASet);
end;

class function TDerSet.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDerSet;
begin
  if (AC = nil) or (System.Length(AC) < 1) then
    Result := GetEmpty()
  else
    Result := TDerSet.Create(AC);
end;

class function TDerSet.FromElement(const AElement: IAsn1Encodable): IDerSet;
begin
  Result := TDerSet.Create(AElement);
end;

class function TDerSet.FromVector(const AElementVector: IAsn1EncodableVector): IDerSet;
begin
  if (AElementVector = nil) or (AElementVector.Count < 1) then
    Result := GetEmpty()
  else
    Result := TDerSet.Create(AElementVector);
end;

class function TDerSet.Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDerSet;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ATs = nil) or (System.Length(ATs) < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<T, IAsn1Encodable>(ATs, AFunc);
  Result := TDerSet.Create(LMapped);
end;


function TDerSet.GetSortedDerEncodings(): TCryptoLibGenericArray<IDerEncoding>;
begin
  if FSortedDerEncodings = nil then
  begin
    FSortedDerEncodings := CreateSortedDerEncodings(Elements);
  end;
  Result := FSortedDerEncodings;
end;

class function TDerSet.CreateSortedDerEncodings(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): TCryptoLibGenericArray<IDerEncoding>;
var
  LDerEncodings: TCryptoLibGenericArray<IDerEncoding>;
  LCount, I, J: Int32;
  LTemp: IDerEncoding;
begin
  LDerEncodings := TAsn1OutputStream.GetContentsEncodingsDer(AElements);
  LCount := System.Length(LDerEncodings);
  
  if LCount > 1 then
  begin
    // Sort using insertion sort
    for I := 1 to LCount - 1 do
    begin
      J := I;
      while (J > 0) and (LDerEncodings[J].CompareTo(LDerEncodings[J - 1]) < 0) do
      begin
        LTemp := LDerEncodings[J];
        LDerEncodings[J] := LDerEncodings[J - 1];
        LDerEncodings[J - 1] := LTemp;
        System.Dec(J);
      end;
    end;
  end;
  
  Result := LDerEncodings;
end;

function TDerSet.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.&Set,
    TCryptoLibGenericArray<IAsn1Encoding>(GetSortedDerEncodings()));
end;

function TDerSet.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TConstructedDLEncoding.Create(ATagClass, ATagNo,
    TCryptoLibGenericArray<IAsn1Encoding>(GetSortedDerEncodings()));
end;

function TDerSet.GetEncodingDer(): IDerEncoding;
begin
  Result := TConstructedDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.&Set,
    GetSortedDerEncodings());
end;

function TDerSet.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TConstructedDerEncoding.Create(ATagClass, ATagNo,
    GetSortedDerEncodings());
end;


{ TDLSet }

class function TDLSet.GetEmpty(): IDLSet;
begin
  Result := TDLSet.Create();
end;

constructor TDLSet.Create();
begin
  inherited Create();
end;

constructor TDLSet.Create(const AElement: IAsn1Encodable);
begin
  inherited Create(AElement);
end;

constructor TDLSet.Create(const AElements: array of IAsn1Encodable);
begin
  inherited Create(AElements, False); // doSort = False for DL
end;

constructor TDLSet.Create(const AElementVector: IAsn1EncodableVector);
begin
  inherited Create(AElementVector, False); // doSort = False for DL
end;

class function TDLSet.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IDLSet;
begin
  if (AC = nil) or (System.Length(AC) < 1) then
    Result := GetEmpty()
  else
    Result := TDLSet.Create(AC);
end;

class function TDLSet.FromElement(const AElement: IAsn1Encodable): IDLSet;
begin
  Result := TDLSet.Create(AElement);
end;

class function TDLSet.FromVector(const AElementVector: IAsn1EncodableVector): IDLSet;
begin
  if (AElementVector = nil) or (AElementVector.Count < 1) then
    Result := GetEmpty()
  else
    Result := TDLSet.Create(AElementVector);
end;

class function TDLSet.Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IDLSet;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ATs = nil) or (System.Length(ATs) < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<T, IAsn1Encodable>(ATs, AFunc);
  Result := TDLSet.Create(False, LMapped); // isSorted = False, need to sort
end;

constructor TDLSet.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AC, False); // doSort = False for DL
end;

constructor TDLSet.Create(const ASequence: IAsn1Sequence);
begin
  inherited Create(ASequence);
end;

constructor TDLSet.Create(const ASet: IAsn1Set);
begin
  inherited Create(ASet);
end;

constructor TDLSet.Create(AIsSorted: Boolean; const AElements: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AIsSorted, AElements);
end;

function TDLSet.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;
  
  Result := TConstructedDLEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.&Set,
    TAsn1OutputStream.GetContentsEncodings(TAsn1OutputStream.EncodingDL, Elements));
end;

function TDLSet.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TConstructedDLEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodings(TAsn1OutputStream.EncodingDL, Elements));
end;

{ TBerSequence }

class function TBerSequence.GetEmpty(): IBerSequence;
begin
  Result := TBerSequence.Create();
end;

constructor TBerSequence.Create();
begin
  inherited Create();
end;

constructor TBerSequence.Create(const AElement: IAsn1Encodable);
begin
  inherited Create(AElement);
end;

constructor TBerSequence.Create(const AElement1, AElement2: IAsn1Encodable);
begin
  inherited Create(AElement1, AElement2);
end;

constructor TBerSequence.Create(const AElements: array of IAsn1Encodable);
begin
  inherited Create(AElements);
end;

constructor TBerSequence.Create(const AElementVector: IAsn1EncodableVector);
begin
  inherited Create(AElementVector);
end;

constructor TBerSequence.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AC);
end;

constructor TBerSequence.Create(const ASequence: IAsn1Sequence);
begin
  inherited Create(ASequence);
end;

constructor TBerSequence.Create(const ASet: IAsn1Set);
begin
  inherited Create(ASet);
end;

class function TBerSequence.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IBerSequence;
begin
  if (AC = nil) or (System.Length(AC) < 1) then
    Result := GetEmpty()
  else
    Result := TBerSequence.Create(AC);
end;

class function TBerSequence.FromElement(const AElement: IAsn1Encodable): IBerSequence;
begin
  Result := TBerSequence.Create(AElement);
end;

class function TBerSequence.FromElements(const AElement1, AElement2: IAsn1Encodable): IBerSequence;
begin
  Result := TBerSequence.Create(AElement1, AElement2);
end;

class function TBerSequence.FromElements(const AElements: array of IAsn1Encodable): IBerSequence;
begin
  if System.Length(AElements) < 1 then
    Result := GetEmpty()
  else
    Result := TBerSequence.Create(AElements);
end;

class function TBerSequence.FromElementsOptional(const AElements: array of IAsn1Encodable): IBerSequence;
begin
  if System.Length(AElements) < 1 then
  begin
    Result := nil;
    Exit;
  end;
  if System.Length(AElements) < 1 then
    Result := GetEmpty()
  else
    Result := TBerSequence.Create(AElements);
end;

class function TBerSequence.FromSequence(const ASequence: IAsn1Sequence): IBerSequence;
var
  LBerSequence: IBerSequence;
begin
  if ASequence = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(ASequence, IBerSequence, LBerSequence) then
  begin
    Result := LBerSequence;
    Exit;
  end;
  Result := WithElements(ASequence.Elements);
end;

class function TBerSequence.FromVector(const AElementVector: IAsn1EncodableVector): IBerSequence;
begin
  if (AElementVector = nil) or (AElementVector.Count < 1) then
    Result := GetEmpty()
  else
    Result := TBerSequence.Create(AElementVector);
end;

class function TBerSequence.Map(const ASequence: IAsn1Sequence; const AFunc: TFunc<IAsn1Encodable, IAsn1Encodable>): IBerSequence;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ASequence = nil) or (ASequence.Count < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<IAsn1Encodable, IAsn1Encodable>(ASequence.Elements, AFunc);
  Result := WithElements(LMapped);
end;

class function TBerSequence.Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IBerSequence;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ATs = nil) or (System.Length(ATs) < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<T, IAsn1Encodable>(ATs, AFunc);
  Result := WithElements(LMapped);
end;

class function TBerSequence.Concatenate(const ASequences: array of IAsn1Sequence): IBerSequence;
var
  LSequences: TCryptoLibGenericArray<IAsn1Sequence>;
  I: Int32;
begin
  if System.Length(ASequences) = 0 then
  begin
    Result := GetEmpty();
    Exit;
  end;
  
  System.SetLength(LSequences, System.Length(ASequences));
  for I := 0 to System.Length(ASequences) - 1 do
    LSequences[I] := ASequences[I];
  
  case System.Length(LSequences) of
    0:
      Result := GetEmpty();
    1:
      Result := FromSequence(LSequences[0]);
  else
    Result := WithElements(ConcatenateElements(LSequences));
  end;
end;

class function TBerSequence.WithElements(const AElements: TCryptoLibGenericArray<IAsn1Encodable>): IBerSequence;
begin
  if (AElements = nil) or (System.Length(AElements) < 1) then
    Result := GetEmpty()
  else
    Result := TBerSequence.Create(AElements);
end;

function TBerSequence.ToAsn1BitString(): IDerBitString;
var
  LBitStrings: TCryptoLibGenericArray<IDerBitString>;
begin
  LBitStrings := GetConstructedBitStrings();
  Result := TBerBitString.Create(LBitStrings);
end;

function TBerSequence.ToAsn1External(): IDerExternal;
begin
  // TODO[asn1] There is currently no BerExternal (or Asn1External)
  Result := TDLExternal.Create(Self);
end;

function TBerSequence.ToAsn1OctetString(): IAsn1OctetString;
var
  LOctetStrings: TCryptoLibGenericArray<IAsn1OctetString>;
begin
  LOctetStrings := GetConstructedOctetStrings();
  Result := TBerOctetString.Create(LOctetStrings);
end;

function TBerSequence.ToAsn1Set(): IAsn1Set;
begin
  Result := TBerSet.Create(False, Elements);
end;

function TBerSequence.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;
  
  Result := TConstructedILEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Sequence,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

function TBerSequence.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TConstructedILEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

{ TBerSet }

class function TBerSet.GetEmpty(): IBerSet;
begin
  Result := TBerSet.Create();
end;

constructor TBerSet.Create();
begin
  inherited Create();
end;

constructor TBerSet.Create(const AElement: IAsn1Encodable);
begin
  inherited Create(AElement);
end;

constructor TBerSet.Create(const AElements: array of IAsn1Encodable);
begin
  inherited Create(AElements, False); // doSort = False for BER
end;

constructor TBerSet.Create(const AElementVector: IAsn1EncodableVector);
begin
  inherited Create(AElementVector, False); // doSort = False for BER
end;

class function TBerSet.FromCollection(const AC: TCryptoLibGenericArray<IAsn1Encodable>): IBerSet;
begin
  if (AC = nil) or (System.Length(AC) < 1) then
    Result := GetEmpty()
  else
    Result := TBerSet.Create(AC);
end;

class function TBerSet.FromElement(const AElement: IAsn1Encodable): IBerSet;
begin
  Result := TBerSet.Create(AElement);
end;

class function TBerSet.FromVector(const AElementVector: IAsn1EncodableVector): IBerSet;
begin
  if (AElementVector = nil) or (AElementVector.Count < 1) then
    Result := GetEmpty()
  else
    Result := TBerSet.Create(AElementVector);
end;

class function TBerSet.Map<T>(const ATs: TCryptoLibGenericArray<T>; const AFunc: TFunc<T, IAsn1Encodable>): IBerSet;
var
  LMapped: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if (ATs = nil) or (System.Length(ATs) < 1) then
  begin
    Result := GetEmpty();
    Exit;
  end;
  LMapped := TArrayUtilities.Map<T, IAsn1Encodable>(ATs, AFunc);
  Result := TBerSet.Create(False, LMapped); // isSorted = False
end;

constructor TBerSet.Create(const AC: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AC, False); // doSort = False for BER
end;

constructor TBerSet.Create(const ASequence: IAsn1Sequence);
begin
  inherited Create(ASequence);
end;

constructor TBerSet.Create(const ASet: IAsn1Set);
begin
  inherited Create(ASet);
end;

constructor TBerSet.Create(AIsSorted: Boolean; const AElements: TCryptoLibGenericArray<IAsn1Encodable>);
begin
  inherited Create(AIsSorted, AElements);
end;

function TBerSet.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;
  
  Result := TConstructedILEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.&Set,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

function TBerSet.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TConstructedILEncoding.Create(ATagClass, ATagNo,
    TAsn1OutputStream.GetContentsEncodings(AEncoding, Elements));
end;

{ TBerTaggedObject }

constructor TBerTaggedObject.Create(ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  Create(True, TAsn1Tags.ContextSpecific, ATagNo, AObj);
end;

constructor TBerTaggedObject.Create(AIsExplicit: Boolean; ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  Create(AIsExplicit, TAsn1Tags.ContextSpecific, ATagNo, AObj);
end;

constructor TBerTaggedObject.Create(ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  Create(True, ATagClass, ATagNo, AObj);
end;

constructor TBerTaggedObject.Create(AIsExplicit: Boolean; ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable);
var
  LExplicitness: Int32;
begin
  if AIsExplicit then
    LExplicitness := 3  // ParsedExplicit
  else
    LExplicitness := 4;  // ParsedImplicit
  Create(LExplicitness, ATagClass, ATagNo, AObj);
end;

constructor TBerTaggedObject.Create(AExplicitness, ATagClass, ATagNo: Int32; const AObj: IAsn1Encodable);
begin
  inherited Create(AExplicitness, ATagClass, ATagNo, AObj);
end;

function TBerTaggedObject.GetEncoding(AEncoding: Int32): IAsn1Encoding;
var
  LBaseObject: IAsn1Object;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;
  
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingImplicit(AEncoding, GetTagClass(), GetTagNo());
    Exit;
  end;
  
  Result := TTaggedILEncoding.Create(GetTagClass(), GetTagNo(), LBaseObject.GetEncoding(AEncoding));
end;

function TBerTaggedObject.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
var
  LBaseObject: IAsn1Object;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  LBaseObject := GetBaseObject().ToAsn1Object();
  
  if not IsExplicit() then
  begin
    Result := LBaseObject.GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TTaggedILEncoding.Create(ATagClass, ATagNo, LBaseObject.GetEncoding(AEncoding));
end;

function TBerTaggedObject.RebuildConstructed(const AAsn1Object: IAsn1Object): IAsn1Sequence;
begin
  Result := TBerSequence.Create(AAsn1Object as IAsn1Encodable);
end;

function TBerTaggedObject.ReplaceTag(ATagClass, ATagNo: Int32): IAsn1TaggedObject;
begin
  Result := TBerTaggedObject.Create(FExplicitness, ATagClass, ATagNo, FObject);
end;

class function TAsn1TaggedObject.CreatePrimitive(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray): IAsn1Object;
begin
  // Note: !CONSTRUCTED => IMPLICIT
  Result := TDLTaggedObject.Create(ParsedImplicit, ATagClass, ATagNo,
    TDerOctetString.WithContents(AContentsOctets));
end;

class function TAsn1TaggedObject.CreateConstructedDL(ATagClass, ATagNo: Int32;
  const AContentsElements: IAsn1EncodableVector): IAsn1Object;
var
  LMaybeExplicit: Boolean;
begin
  if AContentsElements = nil then
    raise EArgumentNilCryptoLibException.Create('contentsElements');
  LMaybeExplicit := (AContentsElements.Count = 1);
  if LMaybeExplicit then
    Result := TDLTaggedObject.Create(ParsedExplicit, ATagClass, ATagNo,
      AContentsElements[0])
  else
    Result := TDLTaggedObject.Create(ParsedImplicit, ATagClass, ATagNo,
      TDLSequence.FromVector(AContentsElements));
end;

class function TAsn1TaggedObject.CreateConstructedIL(ATagClass, ATagNo: Int32;
  const AContentsElements: IAsn1EncodableVector): IAsn1Object;
var
  LMaybeExplicit: Boolean;
begin
  if AContentsElements = nil then
    raise EArgumentNilCryptoLibException.Create('contentsElements');
  LMaybeExplicit := (AContentsElements.Count = 1);
  if LMaybeExplicit then
    Result := TBerTaggedObject.Create(ParsedExplicit, ATagClass, ATagNo,
      AContentsElements[0])
  else
    Result := TBerTaggedObject.Create(ParsedImplicit, ATagClass, ATagNo,
      TBerSequence.FromVector(AContentsElements));
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

{ TAsn1Generator }

constructor TAsn1Generator.Create(AOutStream: TStream);
begin
  inherited Create;
  if AOutStream = nil then
    raise EArgumentNilCryptoLibException.Create('outStream');
  FOut := AOutStream;
  FClosed := False;
end;

destructor TAsn1Generator.Destroy;
begin
  DoClose();
  inherited Destroy;
end;

procedure TAsn1Generator.DoClose();
begin
  if (FOut <> nil) and (not FClosed) then
  begin
    FClosed := True;
    try
      Finish();
    finally
      FOut := nil;  // Prevent any further access to the stream
    end;
  end;
end;

function TAsn1Generator.GetIsClosed: Boolean;
begin
  Result := FClosed;
end;

function TAsn1Generator.GetOut: TStream;
begin
  if FOut = nil then
    raise EInvalidOperationCryptoLibException.Create('Stream is null');
  Result := FOut;
end;

class function TAsn1Generator.InheritConstructedFlag(AIntoTag, AFromTag: Int32): Int32;
begin
  if ((AFromTag and TAsn1Tags.Constructed) <> 0) then
    Result := AIntoTag or TAsn1Tags.Constructed
  else
    Result := AIntoTag and (not TAsn1Tags.Constructed);
end;

{ TBerGenerator }

constructor TBerGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
end;

constructor TBerGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream);
  FTagged := True;
  FIsExplicit := AIsExplicit;
  FTagNo := ATagNo;
end;

procedure TBerGenerator.AddObject(const AObj: IAsn1Encodable);
begin
  AObj.EncodeTo(&Out);
end;

procedure TBerGenerator.AddObject(const AObj: IAsn1Object);
begin
  AObj.EncodeTo(&Out);
end;

procedure TBerGenerator.Finish();
begin
  WriteBerEnd();
end;

procedure TBerGenerator.Close();
begin
  DoClose();
end;

function TBerGenerator.GetRawOutputStream(): TStream;
begin
  Result := &Out;
end;

procedure TBerGenerator.WriteBerBody(AContentStream: TStream);
begin
  TStreamUtilities.PipeAll(AContentStream, &Out);
end;

procedure TBerGenerator.WriteBerEnd();
begin
  &Out.WriteByte($00);
  &Out.WriteByte($00);

  if (FTagged and FIsExplicit) then // write extra end for tag header
  begin
    &Out.WriteByte($00);
    &Out.WriteByte($00);
  end;
end;

procedure TBerGenerator.WriteBerHeader(ATag: Int32);
begin
  if not FTagged then
  begin
    WriteHdr(ATag);
  end
  else if FIsExplicit then
  begin
    {
     * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
     * and the contents octets shall be the complete base encoding.
     }
    WriteHdr(FTagNo or TAsn1Tags.ContextSpecific or TAsn1Tags.Constructed);
    WriteHdr(ATag);
  end
  else
  begin
    {
     * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
     * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
     * shall be [..] the contents octets of the base encoding.
     }
    WriteHdr(InheritConstructedFlag(FTagNo or TAsn1Tags.ContextSpecific, ATag));
  end;
end;

procedure TBerGenerator.WriteHdr(ATag: Int32);
begin
  &Out.WriteByte(Byte(ATag));
  &Out.WriteByte($80);
end;

{ TBerSequenceGenerator }

constructor TBerSequenceGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.Sequence);
end;

constructor TBerSequenceGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream, ATagNo, AIsExplicit);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.Sequence);
end;

{ TBerOctetStringGenerator }

constructor TBerOctetStringGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.OctetString);
end;

constructor TBerOctetStringGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream, ATagNo, AIsExplicit);
  WriteBerHeader(TAsn1Tags.Constructed or TAsn1Tags.OctetString);
end;

function TBerOctetStringGenerator.GetOctetOutputStream(): TStream;
var
  LBuf: TCryptoLibByteArray;
begin
  System.SetLength(LBuf, 1000);
  Result := GetOctetOutputStream(LBuf); // limit for CER encoding.
end;

function TBerOctetStringGenerator.GetOctetOutputStream(ABufSize: Int32): TStream;
var
  LBuf: TCryptoLibByteArray;
begin
  if ABufSize < 1 then
    Result := GetOctetOutputStream()
  else
  begin
    System.SetLength(LBuf, ABufSize);
    Result := GetOctetOutputStream(LBuf);
  end;
end;

function TBerOctetStringGenerator.GetOctetOutputStream(const ABuf: TCryptoLibByteArray): TStream;
begin
  Result := TAsn1BufferedBerOctetStream.Create(GetRawOutputStream(), ABuf);
end;

{ TDerGenerator }

constructor TDerGenerator.Create(const AOutStream: TStream);
begin
  inherited Create(AOutStream);
end;

constructor TDerGenerator.Create(const AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream);
  FTagged := True;
  FIsExplicit := AIsExplicit;
  FTagNo := ATagNo;
end;

class procedure TDerGenerator.WriteDerEncoded(const AOutStream: TStream; ATag: Int32; const ABytes: TCryptoLibByteArray);
begin
  AOutStream.WriteByte(Byte(ATag));
  WriteLength(AOutStream, System.Length(ABytes));
  if System.Length(ABytes) > 0 then
    AOutStream.Write(ABytes[0], System.Length(ABytes));
end;

class procedure TDerGenerator.WriteDerEncoded(const AOutStr: TStream; ATag: Int32; const AInStr: TStream);
begin
  WriteDerEncoded(AOutStr, ATag, TStreamUtilities.ReadAll(AInStr));
end;

class procedure TDerGenerator.WriteLength(const AOutStr: TStream; ALength: Int32);
var
  LSize, LVal, I: Int32;
begin
  if ALength > 127 then
  begin
    LSize := 1;
    LVal := ALength;
    LVal := TBitUtilities.Asr32(LVal, 8);
    while LVal <> 0 do
    begin
      System.Inc(LSize);
      LVal := TBitUtilities.Asr32(LVal, 8);
    end;
    AOutStr.WriteByte(Byte(LSize or $80));
    I := (LSize - 1) * 8;
    while I >= 0 do
    begin
      AOutStr.WriteByte(Byte(TBitUtilities.Asr32(ALength, I)));
      System.Dec(I, 8);
    end;
  end
  else
  begin
    AOutStr.WriteByte(Byte(ALength));
  end;
end;

procedure TDerGenerator.WriteDerEncoded(ATag: Int32; const ABytes: TCryptoLibByteArray);
var
  LBOut: TMemoryStream;
  LTemp: TCryptoLibByteArray;
begin
  if not FTagged then
  begin
    WriteDerEncoded(&Out, ATag, ABytes);
  end
  else if FIsExplicit then
  begin
    {
     * X.690-0207 8.14.2. If implicit tagging [..] was not used [..], the encoding shall be constructed
     * and the contents octets shall be the complete base encoding.
     }
    LBOut := TMemoryStream.Create();
    try
      WriteDerEncoded(LBOut, ATag, ABytes);
      LBOut.Position := 0;
      System.SetLength(LTemp, LBOut.Size);
      LBOut.Read(LTemp[0], LBOut.Size);
      WriteDerEncoded(&Out, FTagNo or TAsn1Tags.ContextSpecific or TAsn1Tags.Constructed, LTemp);
    finally
      LBOut.Free;
    end;
  end
  else
  begin
    {
     * X.690-0207 8.14.3. If implicit tagging was used [..], then: a) the encoding shall be constructed
     * if the base encoding is constructed, and shall be primitive otherwise; and b) the contents octets
     * shall be [..] the contents octets of the base encoding.
     }
    WriteDerEncoded(&Out, InheritConstructedFlag(FTagNo or TAsn1Tags.ContextSpecific, ATag), ABytes);
  end;
end;

{ TDerSequenceGenerator }

constructor TDerSequenceGenerator.Create(AOutStream: TStream);
begin
  inherited Create(AOutStream);
  FBOut := TMemoryStream.Create();
end;

constructor TDerSequenceGenerator.Create(AOutStream: TStream; ATagNo: Int32; AIsExplicit: Boolean);
begin
  inherited Create(AOutStream, ATagNo, AIsExplicit);
  FBOut := TMemoryStream.Create();
end;

destructor TDerSequenceGenerator.Destroy;
begin
  FBOut.Free;
  inherited Destroy;
end;

procedure TDerSequenceGenerator.AddObject(const AObj: IAsn1Encodable);
begin
  AObj.EncodeTo(FBOut, TAsn1Encodable.Der);
end;

procedure TDerSequenceGenerator.AddObject(const AObj: IAsn1Object);
begin
  (AObj as IAsn1Encodable).EncodeTo(FBOut, TAsn1Encodable.Der);
end;

function TDerSequenceGenerator.GetRawOutputStream(): TStream;
begin
  Result := FBOut;
end;

procedure TDerSequenceGenerator.Finish();
var
  LTemp: TCryptoLibByteArray;
begin
  FBOut.Position := 0;
  System.SetLength(LTemp, FBOut.Size);
  FBOut.Read(LTemp[0], FBOut.Size);
  WriteDerEncoded(TAsn1Tags.Constructed or TAsn1Tags.Sequence, LTemp);
end;

procedure TDerSequenceGenerator.Close();
begin
  DoClose();
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

{ TAsn1OctetString }

class constructor TAsn1OctetString.Create;
begin
  FEmptyOctets := nil;
end;

constructor TAsn1OctetString.Create(const AContents: TCryptoLibByteArray);
begin
  inherited Create;
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  FContents := AContents;
end;

function TAsn1OctetString.GetOctetStream(): TStream;
var
  LMemStream: TMemoryStream;
begin
  LMemStream := TMemoryStream.Create;
  LMemStream.Write(FContents[0], System.Length(FContents));
  LMemStream.Position := 0;
  Result := LMemStream;
end;

function TAsn1OctetString.GetOctets(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TAsn1OctetString.GetOctetsLength(): Int32;
begin
  Result := System.Length(FContents);
end;

function TAsn1OctetString.ToAsn1Object(): IAsn1Object;
begin
  Result := Self as IAsn1Object;
end;

function TAsn1OctetString.ToString(): String;
begin
  Result := '#' + THex.Encode(FContents);
end;

function TAsn1OctetString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1OctetString;
begin
  if not Supports(AAsn1Object, IAsn1OctetString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(GetOctets(), LThat.GetOctets());
end;

function TAsn1OctetString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(GetOctets());
end;

class function TAsn1OctetString.GetInstance(const AObj: TObject): IAsn1OctetString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateFmt('illegal object in GetInstance: %s', [TPlatformUtilities.GetTypeName(AObj)]);
end;

class function TAsn1OctetString.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1OctetString;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    Result := TAsn1OctetString.Meta.Instance.FromByteArray(ABytes) as IAsn1OctetString;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct OCTET STRING from byte[]: ' + E.Message);
  end;
end;

class function TAsn1OctetString.GetInstance(const AObj: IAsn1Object): IAsn1OctetString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IAsn1OctetString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TAsn1OctetString.GetInstance(const AObj: IAsn1Convertible): IAsn1OctetString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1OctetString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1OctetString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1OctetString;
begin
  Result := TAsn1OctetString.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1OctetString;
end;

class function TAsn1OctetString.GetOptional(const AElement: IAsn1Encodable): IAsn1OctetString;
var
  LOctetString: IAsn1OctetString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAsn1OctetString, LOctetString) then
    Result := LOctetString
  else
    Result := nil;
end;

class function TAsn1OctetString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1OctetString;
begin
  Result := TAsn1OctetString.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1OctetString;
end;

class function TAsn1OctetString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerOctetString.WithContents(AContents);
end;

{ TDerOctetString }

constructor TDerOctetString.CreateEmpty;
begin
  FContents := TAsn1OctetString.EmptyOctets;
end;

class constructor TDerOctetString.Create;
begin
  FEmpty := TDerOctetString.CreateEmpty;
end;

class function TDerOctetString.GetEmpty(): IDerOctetString;
begin
  Result := FEmpty;
end;

constructor TDerOctetString.Create(const AContents: TCryptoLibByteArray);
begin
  inherited Create(AContents);
end;

constructor TDerOctetString.Create(const AObj: IAsn1Convertible);
begin
  Create(AObj.ToAsn1Object());
end;

constructor TDerOctetString.Create(const AObj: IAsn1Encodable);
begin
  inherited Create(AObj.GetEncoded(TAsn1Encodable.Der));
end;

class function TDerOctetString.FromContents(const AContents: TCryptoLibByteArray): IDerOctetString;
begin
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if System.Length(AContents) < 1 then
    Result := FEmpty
  else
    Result := TDerOctetString.Create(TArrayUtilities.CopyOf<Byte>(AContents, System.Length(AContents)));
end;

class function TDerOctetString.FromContentsOptional(const AContents: TCryptoLibByteArray): IDerOctetString;
begin
  if AContents = nil then
  begin
    Result := nil;
    Exit;
  end;
  if System.Length(AContents) < 1 then
    Result := FEmpty
  else
    Result := TDerOctetString.Create(TArrayUtilities.CopyOf<Byte>(AContents, System.Length(AContents)));
end;

class function TDerOctetString.WithContents(const AContents: TCryptoLibByteArray): IDerOctetString;
begin
  if System.Length(AContents) < 1 then
    Result := FEmpty
  else
    Result := TDerOctetString.Create(AContents);
end;

function TDerOctetString.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.OctetString, FContents);
end;

function TDerOctetString.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents);
end;

function TDerOctetString.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.OctetString, FContents);
end;

function TDerOctetString.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, FContents);
end;

class procedure TDerOctetString.Encode(const AAsn1Out: TAsn1OutputStream;
  const ABuffer: TCryptoLibByteArray; AOffset, ALength: Int32);
begin
  AAsn1Out.WriteIdentifier(TAsn1Tags.Universal, TAsn1Tags.OctetString);
  AAsn1Out.WriteDL(ALength);
  AAsn1Out.Write(ABuffer, AOffset, ALength);
end;

{ TBerOctetString }

function MapElementToOctetString(const AElement: IAsn1Encodable): IAsn1OctetString;
var
  LObj: IAsn1Object;
begin
  LObj := AElement.ToAsn1Object();
  Result := TAsn1OctetString.GetInstance(LObj);
end;

function MapElementToBitString(const AElement: IAsn1Encodable): IDerBitString;
var
  LObj: IAsn1Object;
begin
  LObj := AElement.ToAsn1Object();
  Result := TDerBitString.GetInstance(LObj);
end;

class function TBerOctetString.GetEmpty(): IBerOctetString;
begin
  Result := TBerOctetString.Create(TAsn1OctetString.EmptyOctets);
end;

class function TBerOctetString.FromContents(const AContents: TCryptoLibByteArray): IBerOctetString;
begin
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if System.Length(AContents) < 1 then
    Result := GetEmpty()
  else
    Result := TBerOctetString.Create(System.Copy(AContents));
end;

class function TBerOctetString.FromContentsOptional(const AContents: TCryptoLibByteArray): IBerOctetString;
begin
  if AContents = nil then
  begin
    Result := nil;
    Exit;
  end;
  if System.Length(AContents) < 1 then
    Result := GetEmpty()
  else
    Result := TBerOctetString.Create(System.Copy(AContents));
end;

class function TBerOctetString.FromSequence(const ASequence: IAsn1Sequence): IBerOctetString;
var
  LMapped: TCryptoLibGenericArray<IAsn1OctetString>;
  LSequence: TAsn1Sequence;
begin
  if ASequence = nil then
  begin
    Result := nil;
    Exit;
  end;
  // Cast to class to access MapElements (interfaces can't have generic methods in Pascal)
  if ASequence is TAsn1Sequence then
  begin
    LSequence := ASequence as TAsn1Sequence;
    LMapped := LSequence.MapElements<IAsn1OctetString>(
      function(AElement: IAsn1Encodable): IAsn1OctetString
      var
        LObj: IAsn1Object;
      begin
        LObj := AElement.ToAsn1Object();
        Result := TAsn1OctetString.GetInstance(LObj);
      end);
  end
  else
  begin
    raise EArgumentCryptoLibException.Create('sequence must be a TAsn1Sequence instance');
  end;
  Result := TBerOctetString.Create(LMapped);
end;

class function TBerOctetString.WithContents(const AContents: TCryptoLibByteArray): IBerOctetString;
begin
  if System.Length(AContents) < 1 then
    Result := GetEmpty()
  else
    Result := TBerOctetString.Create(AContents);
end;

constructor TBerOctetString.Create(const AOctetStrings: TCryptoLibGenericArray<IAsn1OctetString>);
begin
  inherited Create(FlattenOctetStrings(AOctetStrings));
  FElements := AOctetStrings;
end;

function TBerOctetString.GetEncoding(AEncoding: Int32): IAsn1Encoding;
var
  LEncodableElements: TCryptoLibGenericArray<IAsn1Encodable>;
  I: Int32;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;

  if FElements = nil then
    Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.OctetString, FContents)
  else
  begin
    System.SetLength(LEncodableElements, System.Length(FElements));
    for I := 0 to System.Length(FElements) - 1 do
      LEncodableElements[I] := FElements[I];
    Result := TConstructedILEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.OctetString,
      TAsn1OutputStream.GetContentsEncodings(AEncoding, LEncodableElements));
  end;
end;

function TBerOctetString.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
var
  LEncodableElements: TCryptoLibGenericArray<IAsn1Encodable>;
  I: Int32;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;

  if FElements = nil then
    Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents)
  else
  begin
    System.SetLength(LEncodableElements, System.Length(FElements));
    for I := 0 to System.Length(FElements) - 1 do
      LEncodableElements[I] := FElements[I];
    Result := TConstructedILEncoding.Create(ATagClass, ATagNo,
      TAsn1OutputStream.GetContentsEncodings(AEncoding, LEncodableElements));
  end;
end;

class function TBerOctetString.FlattenOctetStrings(const AOctetStrings: TCryptoLibGenericArray<IAsn1OctetString>): TCryptoLibByteArray;
var
  LCount, I, LTotalOctets, LPos: Int32;
  LOctets: TCryptoLibByteArray;
begin
  LCount := System.Length(AOctetStrings);
  case LCount of
    0:
      Result := TAsn1OctetString.EmptyOctets;
    1:
      Result := AOctetStrings[0].GetOctets();
  else
    begin
      LTotalOctets := 0;
      for I := 0 to LCount - 1 do
        LTotalOctets := LTotalOctets + System.Length(AOctetStrings[I].GetOctets());

      System.SetLength(Result, LTotalOctets);
      LPos := 0;
      for I := 0 to LCount - 1 do
      begin
        LOctets := AOctetStrings[I].GetOctets();
        System.Move(LOctets[0], Result[LPos], System.Length(LOctets) * SizeOf(Byte));
        LPos := LPos + System.Length(LOctets);
      end;
    end;
  end;
end;

{ TDerStringBase }

constructor TDerStringBase.Create();
begin
  inherited Create();
end;

function TDerStringBase.Asn1GetHashCode(): Int32;
begin
  Result := GetString().GetHashCode();
end;

function TDerStringBase.ToString(): String;
begin
  Result := GetString();
end;

function TDerStringBase.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, GetTagNo(), GetContents());
end;

function TDerStringBase.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, GetContents());
end;

function TDerStringBase.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, GetTagNo(), GetContents());
end;

function TDerStringBase.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, GetContents());
end;

{ TDerBitString }

constructor TDerBitString.CreateEmpty();
begin
  inherited Create;
  FContents := TArrayUtilities.Prepend<Byte>(nil, Byte(0));
end;

constructor TDerBitString.Create(const AData: TCryptoLibByteArray);
begin
  Create(AData, 0);
end;

constructor TDerBitString.Create(const AContents: TCryptoLibByteArray; ACheck: Boolean);
var
  LPadBits: Int32;
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if System.Length(AContents) < 1 then
    raise EArgumentCryptoLibException.Create('zero length data with non-zero pad bits');
  if ACheck then
  begin
    LPadBits := AContents[0];
    if (System.Length(AContents) = 1) and (LPadBits > 0) then
      raise EArgumentCryptoLibException.Create('zero length data with non-zero pad bits');
    if LPadBits > 7 then
      raise EArgumentCryptoLibException.Create('pad bits cannot be greater than 7 or less than 0');
  end;
  FContents := System.Copy(AContents);
end;

constructor TDerBitString.Create(const AData: TCryptoLibByteArray; APadBits: Int32);
begin
  inherited Create();
  if AData = nil then
    raise EArgumentNilCryptoLibException.Create('data');
  if (APadBits < 0) or (APadBits > 7) then
    raise EArgumentCryptoLibException.Create('must be in the range 0 to 7');
  if (System.Length(AData) = 0) and (APadBits <> 0) then
    raise EArgumentCryptoLibException.Create('if ''data'' is empty, ''padBits'' must be 0');
  FContents := TArrayUtilities.Prepend<Byte>(AData, Byte(APadBits));
end;

function TDerBitString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerBitString;
  LThisContents, LThatContents: TCryptoLibByteArray;
  LLength, I, LLast, LPadBits: Int32;
  LThisLastDer, LThatLastDer: Byte;
begin
  if not Supports(AAsn1Object, IDerBitString, LThat) then
  begin
    Result := False;
    Exit;
  end;

  LThisContents := FContents;
  LThatContents := LThat.Contents;
  LLength := System.Length(LThisContents);

  if System.Length(LThatContents) <> LLength then
  begin
    Result := False;
    Exit;
  end;

  if LLength = 1 then
  begin
    Result := True;
    Exit;
  end;

  LLast := LLength - 1;
  // Compare all bytes except the last one
  for I := 0 to LLast - 1 do
  begin
    if LThisContents[I] <> LThatContents[I] then
    begin
      Result := False;
      Exit;
    end;
  end;

  // For the last byte, mask with pad bits before comparing (DER requires pad bits be zero)
  LPadBits := LThisContents[0];
  LThisLastDer := Byte(LThisContents[LLast] and ($FF shl LPadBits));
  LThatLastDer := Byte(LThatContents[LLast] and ($FF shl LPadBits));
  Result := LThisLastDer = LThatLastDer;
end;

function TDerBitString.Asn1GetHashCode(): Int32;
var
  LLast: Int32;
  LPadBits: Byte;
  LLastDer: Byte;
begin
  if System.Length(FContents) < 2 then
  begin
    Result := 1;
    Exit;
  end;

  LPadBits := FContents[0];
  LLast := System.Length(FContents) - 1;
  LLastDer := Byte(FContents[LLast] and ($FF shl LPadBits));

  // Calculate hash code for bytes 0 to LLast-1
  Result := TArrayUtilities.GetArrayHashCode(FContents, 0, LLast);
  
  // Add the masked last byte
  Result := Result * 257;
  Result := Result xor LLastDer;
end;

function TDerBitString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.BitString;
end;

function TDerBitString.GetPadBits(): Int32;
begin
  Result := FContents[0];
end;

function TDerBitString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerBitString.GetString(): String;
var
  LStr: TCryptoLibByteArray;
begin
  LStr := GetDerEncoded();
  Result := Format('#%s', [UpperCase(TConverters.ConvertBytesToHexString(LStr, False))]);
end;

function TDerBitString.GetOctets(): TCryptoLibByteArray;
begin
  if System.Length(FContents) = 1 then
    Result := TAsn1OctetString.EmptyOctets
  else
    Result := TArrayUtilities.CopyOfRange<Byte>(FContents, 1, System.Length(FContents));
end;

function TDerBitString.GetBytes(): TCryptoLibByteArray;
var
  LPadBits: Int32;
begin
  if System.Length(FContents) = 1 then
    Result := TAsn1OctetString.EmptyOctets
  else
  begin
    Result := TArrayUtilities.CopyOfRange<Byte>(FContents, 1, System.Length(FContents));
    LPadBits := FContents[0];
    if LPadBits > 0 then
      Result[System.Length(Result) - 1] := Result[System.Length(Result) - 1] and Byte($FF shl LPadBits);
  end;
end;

function TDerBitString.GetInt32Value(): Int32;
var
  LEnd, I, LPadBits: Int32;
  LDer: Byte;
begin
  LEnd := Math.Min(5, System.Length(FContents) - 1);
  Result := 0;
  
  // Process bytes 1 to end-1 (excluding pad bits byte and last byte)
  for I := 1 to LEnd - 1 do
  begin
    Result := Result or (Int32(FContents[I]) shl (8 * (I - 1)));
  end;
  
  // Handle the last byte with pad bits masking (if end < 5)
  if (1 <= LEnd) and (LEnd < 5) then
  begin
    LPadBits := FContents[0];
    LDer := Byte(FContents[LEnd] and ($FF shl LPadBits));
    Result := Result or (Int32(LDer) shl (8 * (LEnd - 1)));
  end;
end;


class function TDerBitString.CreatePrimitive(const AContents: TCryptoLibByteArray): IDerBitString;
var
  LLength, LPadBits: Int32;
  LFinalOctet, LFinalOctetDer: Byte;
begin
  LLength := System.Length(AContents);
  if LLength < 1 then
    raise EArgumentCryptoLibException.Create('truncated BIT STRING detected');

  LPadBits := AContents[0];
  if LPadBits > 0 then
  begin
    if (LPadBits > 7) or (LLength < 2) then
      raise EArgumentCryptoLibException.Create('invalid pad bits detected');

    LFinalOctet := AContents[LLength - 1];
    LFinalOctetDer := Byte(LFinalOctet and ($FF shl LPadBits));
    if LFinalOctet <> LFinalOctetDer then
    begin
      // Pad bits not properly masked - return DLBitString
      Result := TDLBitString.Create(AContents, False);
      Exit;
    end;
  end;

  Result := TDerBitString.Create(AContents, False);
end;

constructor TDerBitString.Create(AData: Byte; APadBits: Int32);
begin
  inherited Create();
  if (APadBits > 7) or (APadBits < 0) then
    raise EArgumentCryptoLibException.Create('pad bits cannot be greater than 7 or less than 0');
  System.SetLength(FContents, 2);
  FContents[0] := Byte(APadBits);
  FContents[1] := AData;
end;

constructor TDerBitString.Create(ANamedBits: Int32);
var
  LBits, LBytes, I, LPadBits: Int32;
  LData: TCryptoLibByteArray;
begin
  inherited Create();
  if ANamedBits = 0 then
  begin
    System.SetLength(FContents, 1);
    FContents[0] := 0;
    Exit;
  end;
  LBits := 32 - TBitUtilities.NumberOfLeadingZeros(UInt32(ANamedBits));
  LBytes := (LBits + 7) div 8;
  System.SetLength(LData, 1 + LBytes);
  for I := 1 to LBytes - 1 do
  begin
    LData[I] := Byte(ANamedBits);
    ANamedBits := TBitUtilities.Asr32(ANamedBits, 8);
  end;
  LData[LBytes] := Byte(ANamedBits);
  LPadBits := 0;
  while ((ANamedBits and (1 shl LPadBits)) = 0) do
    System.Inc(LPadBits);
  LData[0] := Byte(LPadBits);
  FContents := LData;
end;

constructor TDerBitString.Create(const AObj: IAsn1Convertible);
begin
  Create(AObj.ToAsn1Object());
end;

constructor TDerBitString.Create(const AObj: IAsn1Encodable);
var
  LContents: TCryptoLibByteArray;
begin
  inherited Create();
  LContents := AObj.GetEncoded(TAsn1Encodable.Der);
  if System.Length(LContents) > 0 then
    LContents[0] := $00;
  FContents := LContents;
end;

destructor TDerBitString.Destroy;
begin
  if FBufferStream <> nil then
  begin
    FBufferStream.Free;
    FBufferStream := nil;
  end;
  inherited Destroy;
end;

class function TDerBitString.FromContentsOptional(const AContents: TCryptoLibByteArray): IDerBitString;
begin
  if AContents = nil then
    Result := nil
  else
    Result := TDerBitString.Create(AContents);
end;

class function TDerBitString.GetInstance(const AObj: TObject): IDerBitString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerBitString.GetInstance(const AObj: IAsn1Object): IDerBitString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerBitString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerBitString.GetInstance(const AObj: IAsn1Convertible): IDerBitString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerBitString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerBitString.GetInstance(const ABytes: TCryptoLibByteArray): IDerBitString;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TDerBitString.Meta.Instance.FromByteArray(ABytes) as IDerBitString;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct BIT STRING from byte[]: ' + E.Message);
  end;
end;

class function TDerBitString.GetInstance(const ATaggedObject: IAsn1TaggedObject; AIsExplicit: Boolean): IDerBitString;
begin
  Result := TDerBitString.Meta.Instance.GetContextTagged(ATaggedObject, AIsExplicit) as IDerBitString;
end;

class function TDerBitString.GetOptional(const AElement: IAsn1Encodable): IDerBitString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerBitString, Result) then
    // Found
  else
    Result := nil;
end;

class function TDerBitString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBitString;
begin
  Result := TDerBitString.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IDerBitString;
end;

function TDerBitString.GetBytesLength(): Int32;
begin
  Result := System.Length(FContents) - 1;
end;

function TDerBitString.IsOctetAligned(): Boolean;
begin
  Result := PadBits = 0;
end;

function TDerBitString.GetBitStream(): TStream;
begin
  Result := GetBufferStream();
end;

function TDerBitString.GetOctetStream(): TStream;
begin
  CheckOctetAligned();
  Result := GetBufferStream();
end;

function TDerBitString.GetBufferStream(): TFixedBufferStream;
begin
 if FBufferStream = nil then
  FBufferStream := TFixedBufferStream.Create(FContents, 1, System.Length(FContents) - 1, False);

  Result := FBufferStream;
end;

function TDerBitString.GetParser(): IAsn1BitStringParser;
begin
  Result := Self as IAsn1BitStringParser;
end;

procedure TDerBitString.CheckOctetAligned();
begin
  if FContents[0] <> $00 then
    raise EIOCryptoLibException.Create('expected octet-aligned bitstring, but found padBits: ' + IntToStr(FContents[0]));
end;

function TDerBitString.GetEncoding(AEncoding: Int32): IAsn1Encoding;
var
  LPadBits: Int32;
  LLast: Int32;
  LLastBer, LLastDer: Byte;
begin
  LPadBits := FContents[0];
  if LPadBits <> 0 then
  begin
    LLast := System.Length(FContents) - 1;
    LLastBer := FContents[LLast];
    LLastDer := Byte(LLastBer and ($FF shl LPadBits));
    
    if LLastBer <> LLastDer then
    begin
      Result := TPrimitiveEncodingSuffixed.Create(TAsn1Tags.Universal, TAsn1Tags.BitString, FContents, LLastDer);
      Exit;
    end;
  end;
  
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.BitString, FContents);
end;

function TDerBitString.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
var
  LPadBits: Int32;
  LLast: Int32;
  LLastBer, LLastDer: Byte;
begin
  LPadBits := FContents[0];
  if LPadBits <> 0 then
  begin
    LLast := System.Length(FContents) - 1;
    LLastBer := FContents[LLast];
    LLastDer := Byte(LLastBer and ($FF shl LPadBits));
    
    if LLastBer <> LLastDer then
    begin
      Result := TPrimitiveEncodingSuffixed.Create(ATagClass, ATagNo, FContents, LLastDer);
      Exit;
    end;
  end;
  
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents);
end;

function TDerBitString.GetEncodingDer(): IDerEncoding;
var
  LPadBits: Int32;
  LLast: Int32;
  LLastBer, LLastDer: Byte;
begin
  LPadBits := FContents[0];
  if LPadBits <> 0 then
  begin
    LLast := System.Length(FContents) - 1;
    LLastBer := FContents[LLast];
    LLastDer := Byte(LLastBer and ($FF shl LPadBits));
    
    if LLastBer <> LLastDer then
    begin
      Result := TPrimitiveDerEncodingSuffixed.Create(TAsn1Tags.Universal, TAsn1Tags.BitString, FContents, LLastDer);
      Exit;
    end;
  end;
  
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.BitString, FContents);
end;

function TDerBitString.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
var
  LPadBits: Int32;
  LLast: Int32;
  LLastBer, LLastDer: Byte;
begin
  LPadBits := FContents[0];
  if LPadBits <> 0 then
  begin
    LLast := System.Length(FContents) - 1;
    LLastBer := FContents[LLast];
    LLastDer := Byte(LLastBer and ($FF shl LPadBits));
    
    if LLastBer <> LLastDer then
    begin
      Result := TPrimitiveDerEncodingSuffixed.Create(ATagClass, ATagNo, FContents, LLastDer);
      Exit;
    end;
  end;
  
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, FContents);
end;

{ TDLBitString }

constructor TDLBitString.Create(const AContents: TCryptoLibByteArray; ACheck: Boolean);
begin
  inherited Create(AContents, ACheck);
end;

constructor TDLBitString.Create(const AData: TCryptoLibByteArray; APadBits: Int32);
begin
  inherited Create(AData, APadBits);
end;

function TDLBitString.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;
  
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.BitString, FContents);
end;

function TDLBitString.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents);
end;

{ TBerBitString }

class function TBerBitString.FromSequence(const ASequence: IAsn1Sequence): IBerBitString;
var
  LMapped: TCryptoLibGenericArray<IDerBitString>;
  LSequence: TAsn1Sequence;
begin
  if ASequence = nil then
  begin
    Result := nil;
    Exit;
  end;
  // Cast to class to access MapElements (interfaces can't have generic methods in Pascal)
  if ASequence is TAsn1Sequence then
  begin
    LSequence := ASequence as TAsn1Sequence;
    LMapped := LSequence.MapElements<IDerBitString>(
      function(AElement: IAsn1Encodable): IDerBitString
      var
        LObj: IAsn1Object;
      begin
        LObj := AElement.ToAsn1Object();
        Result := TDerBitString.GetInstance(LObj);
      end);
  end
  else
  begin
    raise EArgumentCryptoLibException.Create('sequence must be a TAsn1Sequence instance');
  end;
  Result := TBerBitString.Create(LMapped);
end;

constructor TBerBitString.Create(const ABitStrings: TCryptoLibGenericArray<IDerBitString>);
begin
  inherited Create(FlattenBitStrings(ABitStrings), False);
  FElements := ABitStrings;
end;

function TBerBitString.GetEncoding(AEncoding: Int32): IAsn1Encoding;
var
  LEncodableElements: TCryptoLibGenericArray<IAsn1Encodable>;
  I: Int32;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncoding(AEncoding);
    Exit;
  end;

  if FElements = nil then
    Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.BitString, FContents)
  else
  begin
    System.SetLength(LEncodableElements, System.Length(FElements));
    for I := 0 to System.Length(FElements) - 1 do
      LEncodableElements[I] := FElements[I];
    Result := TConstructedILEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.BitString,
      TAsn1OutputStream.GetContentsEncodings(AEncoding, LEncodableElements));
  end;
end;

function TBerBitString.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
var
  LEncodableElements: TCryptoLibGenericArray<IAsn1Encodable>;
  I: Int32;
begin
  if AEncoding <> TAsn1OutputStream.EncodingBer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;

  if FElements = nil then
    Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents)
  else
  begin
    System.SetLength(LEncodableElements, System.Length(FElements));
    for I := 0 to System.Length(FElements) - 1 do
      LEncodableElements[I] := FElements[I];
    Result := TConstructedILEncoding.Create(ATagClass, ATagNo,
      TAsn1OutputStream.GetContentsEncodings(AEncoding, LEncodableElements));
  end;
end;

class function TBerBitString.FlattenBitStrings(const ABitStrings: TCryptoLibGenericArray<IDerBitString>): TCryptoLibByteArray;
var
  LCount, I, LLast, LTotalLength, LPos, LLength: Int32;
  LElementContents, LLastElementContents: TCryptoLibByteArray;
  LPadBits: Byte;
begin
  LCount := System.Length(ABitStrings);
  case LCount of
    0:
      Result := TDerBitString.EmptyOctetsContents;
    1:
      Result := ABitStrings[0].Contents;
  else
    begin
      LLast := LCount - 1;
      LTotalLength := 0;
      for I := 0 to LLast - 1 do
      begin
        LElementContents := ABitStrings[I].Contents;
        if LElementContents[0] <> 0 then
          raise EArgumentCryptoLibException.Create('only the last nested bitstring can have padding');
        LTotalLength := LTotalLength + System.Length(LElementContents) - 1;
      end;
      // Last one can have padding
      LLastElementContents := ABitStrings[LLast].Contents;
      LPadBits := LLastElementContents[0];
      LTotalLength := LTotalLength + System.Length(LLastElementContents);

      System.SetLength(Result, LTotalLength);
      Result[0] := LPadBits;
      LPos := 1;
      for I := 0 to LCount - 1 do
      begin
        LElementContents := ABitStrings[I].Contents;
        LLength := System.Length(LElementContents) - 1;
        System.Move(LElementContents[1], Result[LPos], LLength * SizeOf(Byte));
        LPos := LPos + LLength;
      end;
    end;
  end;
end;

{ TDerExternal }

class function TDerExternal.GetObjFromSequence(const ASequence: IAsn1Sequence; AIndex: Int32): IAsn1Object;
begin
  if ASequence.Count <= AIndex then
    raise EArgumentCryptoLibException.Create('too few objects in input sequence');
  Result := ASequence[AIndex].ToAsn1Object();
end;

class function TDerExternal.CheckEncoding(AEncoding: Int32): Int32;
begin
  if (AEncoding < 0) or (AEncoding > 2) then
    raise EInvalidOperationCryptoLibException.CreateFmt('invalid encoding value: %d', [AEncoding]);
  Result := AEncoding;
end;

class function TDerExternal.CheckExternalContent(ATagNo: Int32; const AExternalContent: IAsn1Object): IAsn1Object;
begin
  case ATagNo of
    1:
      Result := TAsn1OctetString.Meta.Instance.CheckedCast(AExternalContent);
    2:
      Result := TDerBitString.Meta.Instance.CheckedCast(AExternalContent);
  else
    Result := AExternalContent;
  end;
end;

class function TDerExternal.GetExternalContent(const AEncoding: IAsn1TaggedObject): IAsn1Object;
begin
  TAsn1Utilities.CheckContextTagClass(AEncoding);
  
  case AEncoding.TagNo of
    0:
      Result := AEncoding.GetExplicitBaseObject().ToAsn1Object();
    1:
      Result := TAsn1OctetString.GetTagged(AEncoding, False);
    2:
      Result := TDerBitString.GetTagged(AEncoding, False);
  else
    raise EArgumentCryptoLibException.CreateFmt('unknown tag: %s', [TAsn1Utilities.GetTagText(AEncoding)]);
  end;
end;

class function TDerExternal.CheckDataValueDescriptor(const ADataValueDescriptor: IAsn1Object): IAsn1ObjectDescriptor;
var
  LObjDesc: IAsn1ObjectDescriptor;
  LGraphicString: IDerGraphicString;
begin
  if Supports(ADataValueDescriptor, IAsn1ObjectDescriptor, LObjDesc) then
    Result := LObjDesc
  else if Supports(ADataValueDescriptor, IDerGraphicString, LGraphicString) then
    Result := TAsn1ObjectDescriptor.Create(ADataValueDescriptor)
  else
    raise EArgumentCryptoLibException.Create('incompatible type for data-value-descriptor');
end;

constructor TDerExternal.Create(const AVector: IAsn1EncodableVector);
begin
  Create(TBerSequence.Create(AVector));
end;

constructor TDerExternal.Create(const ASequence: IAsn1Sequence);
var
  LOffset: Int32;
  LAsn1: IAsn1Object;
  LDerObjectIdentifier: IDerObjectIdentifier;
  LDerInteger: IDerInteger;
  LObj: IAsn1TaggedObject;
begin
  inherited Create();
  if ASequence = nil then
    raise EArgumentNilCryptoLibException.Create('sequence');
  
  LOffset := 0;
  LAsn1 := GetObjFromSequence(ASequence, LOffset);
  
  if Supports(LAsn1, IDerObjectIdentifier, LDerObjectIdentifier) then
  begin
    FDirectReference := LDerObjectIdentifier;
    System.Inc(LOffset);
    LAsn1 := GetObjFromSequence(ASequence, LOffset);
  end;
  
  if Supports(LAsn1, IDerInteger, LDerInteger) then
  begin
    FIndirectReference := LDerInteger;
    System.Inc(LOffset);
    LAsn1 := GetObjFromSequence(ASequence, LOffset);
  end;
  
  if not Supports(LAsn1, IAsn1TaggedObject) then
  begin
    FDataValueDescriptor := CheckDataValueDescriptor(LAsn1);
    System.Inc(LOffset);
    LAsn1 := GetObjFromSequence(ASequence, LOffset);
  end;
  
  if ASequence.Count <> LOffset + 1 then
    raise EArgumentCryptoLibException.Create('input sequence too large');
  
  if not Supports(LAsn1, IAsn1TaggedObject, LObj) then
    raise EArgumentCryptoLibException.Create('No tagged object found in sequence. Structure doesn''t seem to be of type External');
  
  FEncoding := CheckEncoding(LObj.TagNo);
  FExternalContent := GetExternalContent(LObj);
end;

constructor TDerExternal.Create(const ADirectReference: IDerObjectIdentifier;
  const AIndirectReference: IDerInteger;
  const ADataValueDescriptor: IAsn1ObjectDescriptor;
  const AExternalData: IAsn1TaggedObject);
begin
  inherited Create();
  FDirectReference := ADirectReference;
  FIndirectReference := AIndirectReference;
  FDataValueDescriptor := ADataValueDescriptor;
  FEncoding := CheckEncoding(AExternalData.TagNo);
  FExternalContent := GetExternalContent(AExternalData);
end;

constructor TDerExternal.Create(const ADirectReference: IDerObjectIdentifier;
  const AIndirectReference: IDerInteger;
  const ADataValueDescriptor: IAsn1ObjectDescriptor;
  AEncoding: Int32; const AExternalData: IAsn1Object);
begin
  inherited Create();
  FDirectReference := ADirectReference;
  FIndirectReference := AIndirectReference;
  FDataValueDescriptor := ADataValueDescriptor;
  FEncoding := CheckEncoding(AEncoding);
  FExternalContent := CheckExternalContent(AEncoding, AExternalData);
end;

function TDerExternal.BuildSequence(): IAsn1Sequence;
var
  LV: IAsn1EncodableVector;
  LIsExplicit: Boolean;
begin
  LV := TAsn1EncodableVector.Create(4);
  LV.AddOptional([FDirectReference, FIndirectReference, FDataValueDescriptor]);
  LIsExplicit := (FEncoding = 0);
  LV.Add(TDerTaggedObject.Create(LIsExplicit, FEncoding, FExternalContent));
  Result := TDerSequence.Create(LV);
end;

function TDerExternal.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerExternal;
begin
  if not Supports(AAsn1Object, IDerExternal, LThat) then
  begin
    Result := False;
    Exit;
  end;
  
  Result := ((FDirectReference = nil) = (LThat.DirectReference = nil)) and
    ((FDirectReference = nil) or FDirectReference.Equals(LThat.DirectReference)) and
    ((FIndirectReference = nil) = (LThat.IndirectReference = nil)) and
    ((FIndirectReference = nil) or FIndirectReference.Equals(LThat.IndirectReference)) and
    ((FDataValueDescriptor = nil) = (LThat.DataValueDescriptor = nil)) and
    ((FDataValueDescriptor = nil) or FDataValueDescriptor.Equals(LThat.DataValueDescriptor)) and
    (FEncoding = LThat.Encoding) and
    FExternalContent.Equals(LThat.ExternalContent);
end;

function TDerExternal.Asn1GetHashCode(): Int32;
var
  LHash: Int32;
begin
  if FDirectReference <> nil then
    LHash := FDirectReference.GetHashCode()
  else
    LHash := 0;
  
  if FIndirectReference <> nil then
    LHash := LHash xor FIndirectReference.GetHashCode();
  
  if FDataValueDescriptor <> nil then
    LHash := LHash xor FDataValueDescriptor.GetHashCode();
  
  LHash := LHash xor FEncoding;
  LHash := LHash xor FExternalContent.GetHashCode();
  
  Result := LHash;
end;

function TDerExternal.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := GetEncodingImplicit(AEncoding, TAsn1Tags.Universal, TAsn1Tags.External);
end;

function TDerExternal.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := BuildSequence().GetEncodingImplicit(TAsn1OutputStream.EncodingDer, ATagClass, ATagNo);
end;

function TDerExternal.GetEncodingDer(): IDerEncoding;
begin
  Result := GetEncodingDerImplicit(TAsn1Tags.Universal, TAsn1Tags.External);
end;

function TDerExternal.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := BuildSequence().GetEncodingDerImplicit(ATagClass, ATagNo);
end;

function TDerExternal.GetDataValueDescriptor(): IAsn1Object;
begin
  Result := FDataValueDescriptor;
end;

function TDerExternal.GetDirectReference(): IDerObjectIdentifier;
begin
  Result := FDirectReference;
end;

function TDerExternal.GetEncoding(): Int32;
begin
  Result := FEncoding;
end;

function TDerExternal.GetExternalContent(): IAsn1Object;
begin
  Result := FExternalContent;
end;

function TDerExternal.GetIndirectReference(): IDerInteger;
begin
  Result := FIndirectReference;
end;

function TDerExternal.GetSequence(): IAsn1Sequence;
begin
  Result := BuildSequence();
end;

{ TDLExternal }

constructor TDLExternal.Create(const AVector: IAsn1EncodableVector);
begin
  inherited Create(AVector);
end;

constructor TDLExternal.Create(const ASequence: IAsn1Sequence);
begin
  inherited Create(ASequence);
end;

constructor TDLExternal.Create(const ADirectReference: IDerObjectIdentifier;
  const AIndirectReference: IDerInteger;
  const ADataValueDescriptor: IAsn1ObjectDescriptor;
  const AExternalData: IAsn1TaggedObject);
begin
  inherited Create(ADirectReference, AIndirectReference, ADataValueDescriptor, AExternalData);
end;

constructor TDLExternal.Create(const ADirectReference: IDerObjectIdentifier;
  const AIndirectReference: IDerInteger;
  const ADataValueDescriptor: IAsn1ObjectDescriptor;
  AEncoding: Int32; const AExternalData: IAsn1Object);
begin
  inherited Create(ADirectReference, AIndirectReference, ADataValueDescriptor, AEncoding, AExternalData);
end;

function TDLExternal.BuildSequence(): IAsn1Sequence;
var
  LV: IAsn1EncodableVector;
  LIsExplicit: Boolean;
begin
  LV := TAsn1EncodableVector.Create(4);
  LV.AddOptional([FDirectReference, FIndirectReference, FDataValueDescriptor]);
  LIsExplicit := (FEncoding = 0);
  LV.Add(TDLTaggedObject.Create(LIsExplicit, FEncoding, FExternalContent));
  Result := TDLSequence.Create(LV);
end;

function TDLExternal.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := GetEncodingImplicit(AEncoding, TAsn1Tags.Universal, TAsn1Tags.External);
end;

function TDLExternal.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  // If encoding is DER, use base class implementation
  if AEncoding = TAsn1OutputStream.EncodingDer then
  begin
    Result := inherited GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
    Exit;
  end;
  // Otherwise use DL encoding
  Result := BuildSequence().GetEncodingImplicit(TAsn1OutputStream.EncodingDL, ATagClass, ATagNo);
end;

{ TDerBmpString }

constructor TDerBmpString.Create(const AStr: TCryptoLibByteArray);
var
  LByteLen, LCharLen, I: Int32;
  LCs: TCryptoLibCharArray;
begin
  inherited Create();
  if AStr = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  LByteLen := System.Length(AStr);
  if (LByteLen and 1) <> 0 then
    raise EArgumentCryptoLibException.Create('malformed BMPString encoding encountered');
  LCharLen := TBitUtilities.Asr32(LByteLen, 1);
  System.SetLength(LCs, LCharLen);
  for I := 0 to LCharLen - 1 do
    LCs[I] := Char((AStr[2 * I] shl 8) or (AStr[2 * I + 1] and $FF));
  System.SetString(FStr, PChar(@LCs[0]), LCharLen);
end;

constructor TDerBmpString.Create(const AStr: String);
begin
  inherited Create();
  if AStr = '' then
    raise EArgumentNilCryptoLibException.Create('str');
  FStr := AStr;
end;

function TDerBmpString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.BmpString;
end;

function TDerBmpString.GetContents(): TCryptoLibByteArray;
var
  LCount, I: Int32;
  LChar: Char;
begin
  LCount := System.Length(FStr);
  System.SetLength(Result, LCount * 2); // BMP string uses 2 bytes per character
  for I := 0 to LCount - 1 do
  begin
    LChar := FStr[I + 1]; // Pascal strings are 1-indexed
    Result[I * 2] := Byte((Ord(LChar) shr 8) and $FF); // High byte
    Result[I * 2 + 1] := Byte(Ord(LChar) and $FF); // Low byte
  end;
end;

function TDerBmpString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerBmpString;
begin
  if not Supports(AAsn1Object, IDerBmpString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := FStr = LThat.GetString();
end;

function TDerBmpString.Asn1GetHashCode(): Int32;
begin
  Result := FStr.GetHashCode();
end;

function TDerBmpString.GetString(): String;
begin
  Result := FStr;
end;

class function TDerBmpString.CreatePrimitive(const AContents: TCryptoLibByteArray): IDerBmpString;
begin
  Result := TDerBmpString.Create(AContents);
end;

class function TDerBmpString.CreatePrimitive(const AStr: TCryptoLibCharArray): IDerBmpString;
var
  LStr: String;
begin
  System.SetString(LStr, PChar(@AStr[0]), System.Length(AStr));
  Result := TDerBmpString.Create(LStr);
end;

class function TDerBmpString.GetInstance(const AObj: TObject): IDerBmpString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerBmpString.GetInstance(const AObj: IAsn1Object): IDerBmpString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerBmpString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerBmpString.GetInstance(const AObj: IAsn1Convertible): IDerBmpString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerBmpString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerBmpString.GetInstance(const ABytes: TCryptoLibByteArray): IDerBmpString;
var
  LObj: IAsn1Object;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    LObj := TDerBmpString.Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerBmpString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct BMP string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct BMP string from byte[]: ' + E.Message);
  end;
end;

class function TDerBmpString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBmpString;
begin
  Result := TDerBmpString.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IDerBmpString;
end;

class function TDerBmpString.GetOptional(const AElement: IAsn1Encodable): IDerBmpString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerBmpString, Result) then
    Exit;
  Result := nil;
end;

class function TDerBmpString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBmpString;
begin
  Result := TDerBmpString.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IDerBmpString;
end;

{ TDerBoolean }

class function TDerBoolean.GetFalse: IDerBoolean;
var
  LInstance: TDerBoolean;
begin
  if FFalse = nil then
  begin
    LInstance := TDerBoolean.Create(System.False);
    if not Supports(LInstance, IDerBoolean, FFalse) then
      raise EInvalidOperationCryptoLibException.Create('failed to get IDerBoolean interface');
  end;
  Result := FFalse;
end;

class function TDerBoolean.GetTrue: IDerBoolean;
var
  LInstance: TDerBoolean;
begin
  if FTrue = nil then
  begin
    LInstance := TDerBoolean.Create(System.True);
    if not Supports(LInstance, IDerBoolean, FTrue) then
      raise EInvalidOperationCryptoLibException.Create('failed to get IDerBoolean interface');
  end;
  Result := FTrue;
end;

constructor TDerBoolean.Create(AValue: Boolean);
begin
  inherited Create();
  if AValue then
    FValue := $FF
  else
    FValue := 0;
end;

constructor TDerBoolean.Create(const AContents: TCryptoLibByteArray);
begin
  inherited Create();
  if System.Length(AContents) <> 1 then
    raise EArgumentCryptoLibException.Create('byte value should have 1 byte in it');
  // TODO Are there any constraints on the possible byte values?
  FValue := AContents[0];
end;

class function TDerBoolean.FromOctetString(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerBoolean.Create(AContents);
end;

class function TDerBoolean.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
var
  LB: Byte;
begin
  if System.Length(AContents) <> 1 then
    raise EArgumentCryptoLibException.Create('BOOLEAN value should have 1 byte in it');
  LB := AContents[0];

  if LB = 0 then
    Result := TDerBoolean.False
  else if LB = $FF then
    Result := TDerBoolean.True
  else
    Result := TDerBoolean.Create(AContents);
end;

class function TDerBoolean.GetInstance(AValue: Boolean): IDerBoolean;
begin
  if AValue then
    Result := TDerBoolean.True
  else
    Result := TDerBoolean.False;
end;

class function TDerBoolean.GetInstance(AValue: Int32): IDerBoolean;
begin
  if AValue <> 0 then
    Result := TDerBoolean.True
  else
    Result := TDerBoolean.False;
end;

class function TDerBoolean.GetInstance(const AObj: TObject): IDerBoolean;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerBoolean.GetInstance(const AObj: IAsn1Convertible): IDerBoolean;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerBoolean, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerBoolean.GetInstance(const AObj: IAsn1Object): IDerBoolean;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerBoolean, Result) then
    Exit;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj as TObject));
end;

class function TDerBoolean.GetInstance(const ABytes: TCryptoLibByteArray): IDerBoolean;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TDerBoolean.Meta.Instance.FromByteArray(ABytes) as IDerBoolean;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct boolean from byte[]: ' + E.Message);
  end;
end;

class function TDerBoolean.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBoolean;
begin
  Result := TDerBoolean.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IDerBoolean;
end;

class function TDerBoolean.GetOptional(const AElement: IAsn1Encodable): IDerBoolean;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IDerBoolean, Result) then
    Exit;

  Result := nil;
end;

class function TDerBoolean.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerBoolean;
begin
  Result := TDerBoolean.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IDerBoolean;
end;

function TDerBoolean.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerBoolean;
begin
  if not Supports(AAsn1Object, IDerBoolean, LThat) then
  begin
    Result := System.False;
    Exit;
  end;
  Result := GetIsTrue() = LThat.IsTrue;
end;

function TDerBoolean.Asn1GetHashCode(): Int32;
begin
  Result := Ord(GetIsTrue());
end;

function TDerBoolean.GetValue(): Byte;
begin
  Result := FValue;
end;

function TDerBoolean.GetIsTrue(): Boolean;
begin
  Result := FValue <> 0;
end;

function TDerBoolean.ToString(): String;
begin
  if GetIsTrue() then
    Result := 'TRUE'
  else
    Result := 'FALSE';
end;

function TDerBoolean.GetContents(AEncoding: Int32): TCryptoLibByteArray;
var
  LContents: Byte;
begin
  LContents := FValue;
  // if DER encoding and IsTrue, use 0xFF
  if (TAsn1OutputStream.EncodingDer = AEncoding) and GetIsTrue() then
    LContents := $FF;
  Result := TCryptoLibByteArray.Create(LContents);
end;

function TDerBoolean.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Boolean, GetContents(AEncoding));
end;

function TDerBoolean.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, GetContents(AEncoding));
end;

function TDerBoolean.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Boolean,
    GetContents(TAsn1OutputStream.EncodingDer));
end;

function TDerBoolean.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, GetContents(TAsn1OutputStream.EncodingDer));
end;

{ TDerEnumerated }

class constructor TDerEnumerated.Create;
begin
  System.SetLength(FCache, 12);
end;

class function TDerEnumerated.GetInstance(const AObj: TObject): IDerEnumerated;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerEnumerated.GetInstance(const AObj: IAsn1Object): IDerEnumerated;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerEnumerated, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerEnumerated.GetInstance(const AObj: IAsn1Convertible): IDerEnumerated;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerEnumerated, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerEnumerated.GetInstance(const ABytes: TCryptoLibByteArray): IDerEnumerated;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    Result := TDerEnumerated.Meta.Instance.FromByteArray(ABytes) as IDerEnumerated;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct enumerated from byte[]: ' + E.Message);
  end;
end;

class function TDerEnumerated.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerEnumerated;
begin
  Result := TDerEnumerated.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IDerEnumerated;
end;

class function TDerEnumerated.GetOptional(const AElement: IAsn1Encodable): IDerEnumerated;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IDerEnumerated, Result) then
    Exit;

  Result := nil;
end;

class function TDerEnumerated.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerEnumerated;
begin
  Result := TDerEnumerated.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IDerEnumerated;
end;

constructor TDerEnumerated.Create(AVal: Int32);
var
  LBytes: TCryptoLibByteArray;
begin
  inherited Create();
  if AVal < 0 then
    raise EArgumentCryptoLibException.Create('enumerated must be non-negative');

  LBytes := TBigInteger.ValueOf(AVal).ToByteArray();
  FContents := LBytes;
  FStart := 0;
end;

constructor TDerEnumerated.Create(AVal: Int64);
var
  LBytes: TCryptoLibByteArray;
begin
  inherited Create();
  if AVal < 0 then
    raise EArgumentCryptoLibException.Create('enumerated must be non-negative');

  LBytes := TBigInteger.ValueOf(AVal).ToByteArray();
  FContents := LBytes;
  FStart := 0;
end;

constructor TDerEnumerated.Create(const AVal: TBigInteger);
var
  LBytes: TCryptoLibByteArray;
begin
  inherited Create();
  if AVal.SignValue < 0 then
    raise EArgumentCryptoLibException.Create('enumerated must be non-negative');

  LBytes := AVal.ToByteArray();
  FContents := LBytes;
  FStart := 0;
end;

constructor TDerEnumerated.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerEnumerated.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if TDerInteger.IsMalformed(AContents) then
    raise EArgumentCryptoLibException.Create('malformed enumerated');
  if (AContents[0] and $80) <> 0 then
    raise EArgumentCryptoLibException.Create('enumerated must be non-negative');

  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
  FStart := TDerInteger.SignBytesToSkip(FContents);
end;

function TDerEnumerated.GetValue(): TBigInteger;
begin
  Result := TBigInteger.Create(FContents);
end;

function TDerEnumerated.HasValue(AX: Int32): Boolean;
var
  LLength: Int32;
begin
  LLength := System.Length(FContents) - FStart;
  Result := (LLength <= 4) and
    (TDerInteger.IntValue(FContents, FStart, TDerInteger.SignExtSigned) = AX);
end;

function TDerEnumerated.HasValue(const AX: TBigInteger): Boolean;
var
  LValue: TBigInteger;
begin
  if not AX.IsInitialized then
  begin
    Result := False;
    Exit;
  end;

  // Fast check to avoid allocation
  if TDerInteger.IntValue(FContents, FStart, TDerInteger.SignExtSigned) <> AX.Int32Value then
  begin
    Result := False;
    Exit;
  end;

  LValue := GetValue();
  Result := LValue.Equals(AX);
end;

function TDerEnumerated.GetIntValueExact(): Int32;
var
  LCount: Int32;
begin
  LCount := System.Length(FContents) - FStart;
  if LCount > 4 then
    raise EArithmeticCryptoLibException.Create('ASN.1 Enumerated out of int range');

  Result := TDerInteger.IntValue(FContents, FStart, TDerInteger.SignExtSigned);
end;

function TDerEnumerated.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Enumerated, FContents);
end;

function TDerEnumerated.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents);
end;

function TDerEnumerated.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Enumerated, FContents);
end;

function TDerEnumerated.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, FContents);
end;

function TDerEnumerated.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerEnumerated;
  LThatContents: TCryptoLibByteArray;
begin
  if not Supports(AAsn1Object, IDerEnumerated, LThat) then
  begin
    Result := False;
    Exit;
  end;
  LThatContents := LThat.Bytes;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThatContents);
end;

function TDerEnumerated.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerEnumerated.FromOctetString(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerEnumerated.Create(AContents);
end;

class function TDerEnumerated.CreatePrimitive(const AContents: TCryptoLibByteArray; AClone: Boolean): IAsn1Object;
var
  LLength, LValue: Int32;
  LPossibleMatch: IDerEnumerated;
begin
  LLength := System.Length(AContents);
  if LLength > 1 then
  begin
    Result := TDerEnumerated.Create(AContents, AClone);
    Exit;
  end;
  if LLength = 0 then
    raise EArgumentCryptoLibException.Create('ENUMERATED has zero length');

  LValue := AContents[0];
  if LValue >= System.Length(FCache) then
  begin
    Result := TDerEnumerated.Create(AContents, AClone);
    Exit;
  end;

  LPossibleMatch := FCache[LValue];
  if LPossibleMatch = nil then
  begin
    LPossibleMatch := TDerEnumerated.Create(AContents, AClone);
    FCache[LValue] := LPossibleMatch;
  end;
  Result := LPossibleMatch;
end;

function TDerEnumerated.GetBytes(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

{ TAsn1Null }

constructor TAsn1Null.Create;
begin
  inherited Create();
end;

class procedure TAsn1Null.CheckContentsLength(AContentsLength: Int32);
begin
  if AContentsLength <> 0 then
    raise EInvalidOperationCryptoLibException.Create('malformed NULL encoding encountered');
end;

class function TAsn1Null.CreatePrimitive(): IAsn1Object;
begin
  Result := TDerNull.Instance;
end;

class function TAsn1Null.GetInstance(const AObj: TObject): IAsn1Null;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1Null.GetInstance(const AObj: IAsn1Object): IAsn1Null;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IAsn1Null, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TAsn1Null.GetInstance(const AObj: IAsn1Convertible): IAsn1Null;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1Null, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1Null.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1Null;
var
  LObj: IAsn1Object;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    LObj := TAsn1Null.Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IAsn1Null, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct NULL from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct NULL from byte[]: ' + E.Message);
  end;
end;

class function TAsn1Null.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Null;
begin
  Result := TAsn1Null.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1Null;
end;

class function TAsn1Null.GetOptional(const AElement: IAsn1Encodable): IAsn1Null;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IAsn1Null, Result) then
    Exit;
  Result := nil;
end;

class function TAsn1Null.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Null;
begin
  Result := TAsn1Null.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1Null;
end;

function TAsn1Null.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LNull: IAsn1Null;
begin
  Result := Supports(AAsn1Object, IAsn1Null, LNull);
end;

function TAsn1Null.Asn1GetHashCode(): Int32;
begin
  Result := -1;
end;

{ TDerNull }

constructor TDerNull.Create;
begin
  inherited Create();
end;

class function TDerNull.GetInstance: IDerNull;
begin
  if FInstance = nil then
    FInstance := TDerNull.Create;
  Result := FInstance;
end;

function TDerNull.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LNull: IDerNull;
begin
  Result := Supports(AAsn1Object, IDerNull, LNull);
end;

function TDerNull.Asn1GetHashCode(): Int32;
begin
  Result := -1;
end;

function TDerNull.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Null, TAsn1OctetString.EmptyOctets);
end;

function TDerNull.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, TAsn1OctetString.EmptyOctets);
end;

function TDerNull.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Null, TAsn1OctetString.EmptyOctets);
end;

function TDerNull.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, TAsn1OctetString.EmptyOctets);
end;

{ TDerObjectIdentifier }

constructor TDerObjectIdentifier.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerObjectIdentifier.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  CheckContentsLength(System.Length(AContents));
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class procedure TDerObjectIdentifier.CheckContentsLength(AContentsLength: Int32);
begin
  if AContentsLength > 4096 then
    raise EArgumentCryptoLibException.Create('exceeded OID contents length limit');
end;

class function TDerObjectIdentifier.CreatePrimitive(const AContents: TCryptoLibByteArray; AClone: Boolean): IAsn1Object;
var
  LIndex: UInt32;
  LOriginalEntry, LNewEntry: IDerObjectIdentifier;
  LExchangedEntry: IDerObjectIdentifier;
begin
  CheckContentsLength(System.Length(AContents));

  LIndex := UInt32(TArrayUtilities.GetArrayHashCode(AContents));
  LIndex := LIndex xor (LIndex shr 20);
  LIndex := LIndex xor (LIndex shr 10);
  LIndex := LIndex and 1023;

  if System.Length(FCache) = 0 then
    System.SetLength(FCache, 1024);

  LOriginalEntry := FCache[LIndex];
  if (LOriginalEntry <> nil) and TArrayUtilities.AreEqual<Byte>(AContents, LOriginalEntry.Contents) then
  begin
    Result := LOriginalEntry;
    Exit;
  end;

  if not TAsn1RelativeOid.IsValidContents(AContents) then
    raise EArgumentCryptoLibException.Create('invalid OID contents');

  if AClone then
    LNewEntry := TDerObjectIdentifier.Create(System.Copy(AContents), '')
  else
    LNewEntry := TDerObjectIdentifier.Create(AContents, '');

  LExchangedEntry := FCache[LIndex];
  if LExchangedEntry <> LOriginalEntry then
  begin
    if (LExchangedEntry <> nil) and TArrayUtilities.AreEqual<Byte>(AContents, LExchangedEntry.Contents) then
    begin
      Result := LExchangedEntry;
      Exit;
    end;
  end;

  FCache[LIndex] := LNewEntry;
  Result := LNewEntry;
end;

class constructor TDerObjectIdentifier.Create;
begin
  System.SetLength(FCache, 1024);
end;

constructor TDerObjectIdentifier.Create(const AContents: TCryptoLibByteArray; const AIdentifier: String);
begin
  inherited Create();
  FContents := AContents;
  FIdentifier := AIdentifier;
end;

class function TDerObjectIdentifier.FromOctetString(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerObjectIdentifier.Create(AContents);
end;

class function TDerObjectIdentifier.FromContents(const AContents: TCryptoLibByteArray): IDerObjectIdentifier;
begin
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  Result := CreatePrimitive(AContents, True) as IDerObjectIdentifier;
end;

class function TDerObjectIdentifier.GetInstance(const AObj: TObject): IDerObjectIdentifier;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerObjectIdentifier.GetInstance(const AObj: IAsn1Object): IDerObjectIdentifier;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerObjectIdentifier, Result) then
    Exit;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj as TObject));
end;

class function TDerObjectIdentifier.GetInstance(const AObj: IAsn1Convertible): IDerObjectIdentifier;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerObjectIdentifier, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerObjectIdentifier.GetInstance(const ABytes: TCryptoLibByteArray): IDerObjectIdentifier;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TDerObjectIdentifier.Meta.Instance.FromByteArray(ABytes) as IDerObjectIdentifier;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct object identifier from byte[]: ' + E.Message);
  end;
end;

class function TDerObjectIdentifier.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerObjectIdentifier;
begin
  Result := TDerObjectIdentifier.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IDerObjectIdentifier;
end;

class function TDerObjectIdentifier.GetOptional(const AElement: IAsn1Encodable): IDerObjectIdentifier;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IDerObjectIdentifier, Result) then
    Exit;

  Result := nil;
end;

class function TDerObjectIdentifier.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerObjectIdentifier;
begin
  Result := TDerObjectIdentifier.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IDerObjectIdentifier;
end;

class function TDerObjectIdentifier.TryFromID(const AIdentifier: String; out AOid: IDerObjectIdentifier): Boolean;
var
  LContents: TCryptoLibByteArray;
begin
  if AIdentifier = '' then
    raise EArgumentNilCryptoLibException.Create('identifier');

  if (System.Length(AIdentifier) <= MaxIdentifierLength) and IsValidIdentifier(AIdentifier) then
  begin
    LContents := ParseIdentifier(AIdentifier);
    if System.Length(LContents) <= MaxContentsLength then
    begin
      AOid := TDerObjectIdentifier.Create(LContents, AIdentifier) as IDerObjectIdentifier;
      Result := True;
      Exit;
    end;
  end;

  AOid := nil;
  Result := False;
end;

constructor TDerObjectIdentifier.Create(const AIdentifier: String);
var
  LContents: TCryptoLibByteArray;
begin
  inherited Create();
  CheckIdentifier(AIdentifier);
  LContents := ParseIdentifier(AIdentifier);
  CheckContentsLength(System.Length(LContents));
  FContents := LContents;
  FIdentifier := AIdentifier;
end;

function TDerObjectIdentifier.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerObjectIdentifier;
begin
  if not Supports(AAsn1Object, IDerObjectIdentifier, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerObjectIdentifier.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

function TDerObjectIdentifier.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerObjectIdentifier.GetID(): String;
begin
  if FIdentifier = '' then
    FIdentifier := ParseContents(FContents);
  Result := FIdentifier;
end;

function TDerObjectIdentifier.Branch(const ABranchID: String): IDerObjectIdentifier;
var
  LContents: TCryptoLibByteArray;
  LSubID: Int32;
  LRootID, LIdentifier: String;
begin
  TAsn1RelativeOid.CheckIdentifier(ABranchID);

  if System.Length(ABranchID) <= 2 then
  begin
    CheckContentsLength(System.Length(FContents) + 1);
    LSubID := Ord(ABranchID[1]) - Ord('0');
    if System.Length(ABranchID) = 2 then
    begin
      LSubID := LSubID * 10;
      LSubID := LSubID + (Ord(ABranchID[2]) - Ord('0'));
    end;
    LContents := TArrayUtilities.Append<Byte>(FContents, Byte(LSubID));
  end
  else
  begin
    LContents := TAsn1RelativeOid.ParseIdentifier(ABranchID);
    CheckContentsLength(System.Length(FContents) + System.Length(LContents));
    LContents := TArrayUtilities.Concatenate<Byte>(FContents, LContents);
  end;

  LRootID := GetID();
  LIdentifier := LRootID + '.' + ABranchID;
  Result := TDerObjectIdentifier.Create(LContents, LIdentifier);
end;

function TDerObjectIdentifier.On(const AStem: IDerObjectIdentifier): Boolean;
var
  LStemContents: TCryptoLibByteArray;
  LStemLength: Int32;
begin
  LStemContents := AStem.Contents;
  LStemLength := System.Length(LStemContents);
  // Compare the first LStemLength bytes of both arrays
  Result := (System.Length(FContents) > LStemLength) and
    TArrayUtilities.AreEqual<Byte>(System.Copy(FContents, 0, LStemLength), System.Copy(LStemContents, 0, LStemLength));
end;

function TDerObjectIdentifier.ToString(): String;
begin
  Result := GetID();
end;

function TDerObjectIdentifier.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.ObjectIdentifier, FContents);
end;

function TDerObjectIdentifier.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents);
end;

function TDerObjectIdentifier.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.ObjectIdentifier, FContents);
end;

function TDerObjectIdentifier.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, FContents);
end;

class procedure TDerObjectIdentifier.CheckIdentifier(const AIdentifier: String);
begin
  if AIdentifier = '' then
    raise EArgumentNilCryptoLibException.Create('identifier');
  if System.Length(AIdentifier) > MaxIdentifierLength then
    raise EArgumentCryptoLibException.Create('exceeded OID contents length limit');
  if not IsValidIdentifier(AIdentifier) then
    raise EFormatCryptoLibException.Create('string ' + AIdentifier + ' not a valid OID');
end;

class function TDerObjectIdentifier.IsValidIdentifier(const AIdentifier: String): Boolean;
var
  LFirst: Char;
begin
  if (System.Length(AIdentifier) < 3) or (AIdentifier[2] <> '.') then
  begin
    Result := False;
    Exit;
  end;

  LFirst := AIdentifier[1];
  if (LFirst < '0') or (LFirst > '2') then
  begin
    Result := False;
    Exit;
  end;

  if not TAsn1RelativeOid.IsValidIdentifier(AIdentifier, 2) then
  begin
    Result := False;
    Exit;
  end;

  if LFirst = '2' then
  begin
    Result := True;
    Exit;
  end;

  if (System.Length(AIdentifier) = 3) or (AIdentifier[4] = '.') then
  begin
    Result := True;
    Exit;
  end;

  if (System.Length(AIdentifier) = 4) or (AIdentifier[5] = '.') then
  begin
    Result := AIdentifier[3] < '4';
    Exit;
  end;

  Result := False;
end;

class function TDerObjectIdentifier.ParseContents(const AContents: TCryptoLibByteArray): String;
var
  LObjId: String;
  LValue: Int64;
  LBigValue: TBigInteger;
  I, LB: Int32;
  LFirst: Boolean;
begin
  LObjId := '';
  LValue := 0;
  LBigValue := Default(TBigInteger);
  LFirst := True;

  for I := 0 to System.Length(AContents) - 1 do
  begin
    LB := AContents[I];

    if LValue <= LongLimit then
    begin
      LValue := LValue + (LB and $7F);
      if (LB and $80) = 0 then
      begin
        if LFirst then
        begin
          if LValue < 40 then
            LObjId := LObjId + '0'
          else if LValue < 80 then
          begin
            LObjId := LObjId + '1';
            LValue := LValue - 40;
          end
          else
          begin
            LObjId := LObjId + '2';
            LValue := LValue - 80;
          end;
          LFirst := False;
        end;

        LObjId := LObjId + '.' + IntToStr(LValue);
        LValue := 0;
      end
      else
      begin
        LValue := LValue shl 7;
      end;
    end
    else
    begin
      if not LBigValue.IsInitialized then
        LBigValue := TBigInteger.ValueOf(LValue);
      LBigValue := LBigValue.&Or(TBigInteger.ValueOf(LB and $7F));
      if (LB and $80) = 0 then
      begin
        if LFirst then
        begin
          LObjId := LObjId + '2';
          LBigValue := LBigValue.Subtract(TBigInteger.ValueOf(80));
          LFirst := False;
        end;

        LObjId := LObjId + '.' + LBigValue.ToString();
        LBigValue := Default(TBigInteger);
        LValue := 0;
      end
      else
      begin
        LBigValue := LBigValue.ShiftLeft(7);
      end;
    end;
  end;

  Result := LObjId;
end;

class function TDerObjectIdentifier.ParseIdentifier(const AIdentifier: String): TCryptoLibByteArray;
var
  LBOut: TMemoryStream;
  LTok: IOidTokenizer;
  LToken: String;
  LFirst: Int32;
  LBytes: TCryptoLibByteArray;
begin
  LBOut := TMemoryStream.Create();
  try
    LTok := TOidTokenizer.Create(AIdentifier);
    LToken := LTok.NextToken();
    LFirst := StrToInt(LToken) * 40;

    LToken := LTok.NextToken();
    if System.Length(LToken) <= 18 then
      WriteField(LBOut, Int64(LFirst + StrToInt64(LToken)))
    else
      WriteField(LBOut, TBigInteger.Create(LToken).Add(TBigInteger.ValueOf(LFirst)));

    while LTok.HasMoreTokens do
    begin
      LToken := LTok.NextToken();
      if System.Length(LToken) <= 18 then
        WriteField(LBOut, StrToInt64(LToken))
      else
        WriteField(LBOut, TBigInteger.Create(LToken));
    end;

    System.SetLength(LBytes, LBOut.Size);
    LBOut.Position := 0;
    LBOut.Read(LBytes[0], LBOut.Size);
    Result := LBytes;
  finally
    LBOut.Free();
  end;
end;

class procedure TDerObjectIdentifier.WriteField(const AOutputStream: TStream; AFieldValue: Int64);
var
  LResult: TCryptoLibByteArray;
  LPos: Int32;
begin
  System.SetLength(LResult, 9);
  LPos := 8;
  LResult[LPos] := Byte(AFieldValue and $7F);
  while AFieldValue >= (Int64(1) shl 7) do
  begin
    AFieldValue := AFieldValue shr 7;
    System.Dec(LPos);
    LResult[LPos] := Byte(AFieldValue or $80);
  end;
  AOutputStream.Write(LResult[LPos], 9 - LPos);
end;

class procedure TDerObjectIdentifier.WriteField(const AOutputStream: TStream; const AFieldValue: TBigInteger);
var
  LByteCount, I: Int32;
  LTmp: TCryptoLibByteArray;
  LTmpValue: TBigInteger;
begin
  LByteCount := (AFieldValue.BitLength + 6) div 7;
  if LByteCount = 0 then
  begin
    AOutputStream.WriteByte(0);
  end
  else
  begin
    LTmpValue := AFieldValue;
    System.SetLength(LTmp, LByteCount);
    for I := LByteCount - 1 downto 0 do
    begin
      LTmp[I] := Byte(LTmpValue.Int32Value or $80);
      LTmpValue := LTmpValue.ShiftRight(7);
    end;
    LTmp[LByteCount - 1] := LTmp[LByteCount - 1] and $7F;
    AOutputStream.Write(LTmp[0], System.Length(LTmp));
  end;
end;


{ TAsn1RelativeOid }

constructor TAsn1RelativeOid.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TAsn1RelativeOid.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  CheckContentsLength(System.Length(AContents));
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class procedure TAsn1RelativeOid.CheckContentsLength(AContentsLength: Int32);
begin
  if AContentsLength > 4096 then
    raise EArgumentCryptoLibException.Create('exceeded relative OID contents length limit');
end;

function TAsn1RelativeOid.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1RelativeOid;
begin
  if not Supports(AAsn1Object, IAsn1RelativeOid, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TAsn1RelativeOid.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class constructor TAsn1RelativeOid.Create;
begin
  System.SetLength(FCache, 64);
end;

function TAsn1RelativeOid.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

constructor TAsn1RelativeOid.Create(const AIdentifier: String);
var
  LContents: TCryptoLibByteArray;
begin
  inherited Create();
  CheckIdentifier(AIdentifier);
  LContents := ParseIdentifier(AIdentifier);
  CheckContentsLength(System.Length(LContents));
  FContents := LContents;
  FIdentifier := AIdentifier;
end;

constructor TAsn1RelativeOid.Create(const AContents: TCryptoLibByteArray; const AIdentifier: String);
begin
  FContents := AContents;
  FIdentifier := AIdentifier;
end;

class function TAsn1RelativeOid.FromContents(const AContents: TCryptoLibByteArray): IAsn1RelativeOid;
begin
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  Result := CreatePrimitive(AContents, True) as IAsn1RelativeOid;
end;

class function TAsn1RelativeOid.GetInstance(const AObj: TObject): IAsn1RelativeOid;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1RelativeOid.GetInstance(const AObj: IAsn1Object): IAsn1RelativeOid;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IAsn1RelativeOid, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TAsn1RelativeOid.GetInstance(const AObj: IAsn1Convertible): IAsn1RelativeOid;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1RelativeOid, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1RelativeOid.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1RelativeOid;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    Result := TAsn1RelativeOid.Meta.Instance.FromByteArray(ABytes) as IAsn1RelativeOid;
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct relative OID from byte[]: ' + E.Message);
  end;
end;

class function TAsn1RelativeOid.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1RelativeOid;
begin
  Result := TAsn1RelativeOid.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1RelativeOid;
end;

class function TAsn1RelativeOid.GetOptional(const AElement: IAsn1Encodable): IAsn1RelativeOid;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAsn1RelativeOid, Result) then
    Exit;

  Result := nil;
end;

class function TAsn1RelativeOid.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1RelativeOid;
begin
  Result := TAsn1RelativeOid.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1RelativeOid;
end;

class function TAsn1RelativeOid.TryFromID(const AIdentifier: String; out AOid: IAsn1RelativeOid): Boolean;
var
  LContents: TCryptoLibByteArray;
begin
  if AIdentifier = '' then
    raise EArgumentNilCryptoLibException.Create('identifier');

  if (System.Length(AIdentifier) <= MaxIdentifierLength) and IsValidIdentifier(AIdentifier, 0) then
  begin
    LContents := ParseIdentifier(AIdentifier);
    if System.Length(LContents) <= MaxContentsLength then
    begin
      AOid := TAsn1RelativeOid.Create(LContents, False);
      (AOid as TAsn1RelativeOid).FIdentifier := AIdentifier;
      Result := True;
      Exit;
    end;
  end;

  AOid := nil;
  Result := False;
end;

class procedure TAsn1RelativeOid.CheckIdentifier(const AIdentifier: String);
begin
  if AIdentifier = '' then
    raise EArgumentNilCryptoLibException.Create('identifier');
  if System.Length(AIdentifier) > MaxIdentifierLength then
    raise EArgumentCryptoLibException.Create('exceeded relative OID contents length limit');
  if not IsValidIdentifier(AIdentifier, 0) then
    raise EFormatCryptoLibException.Create('string ' + AIdentifier + ' not a valid relative OID');
end;

class function TAsn1RelativeOid.IsValidIdentifier(const AIdentifier: String; AFrom: Int32): Boolean;
var
  LDigitCount, LPos: Int32;
  LCh: Char;
begin
  LDigitCount := 0;
  LPos := System.Length(AIdentifier);
  while LPos > AFrom do
  begin
    System.Dec(LPos);
    LCh := AIdentifier[LPos + 1];

    if LCh = '.' then
    begin
      if (LDigitCount = 0) or ((LDigitCount > 1) and (AIdentifier[LPos + 2] = '0')) then
      begin
        Result := False;
        Exit;
      end;
      LDigitCount := 0;
    end
    else if (LCh >= '0') and (LCh <= '9') then
    begin
      System.Inc(LDigitCount);
    end
    else
    begin
      Result := False;
      Exit;
    end;
  end;

  if (LDigitCount = 0) or ((LDigitCount > 1) and (AIdentifier[AFrom + 1] = '0')) then
  begin
    Result := False;
    Exit;
  end;

  Result := True;
end;

class function TAsn1RelativeOid.IsValidContents(const AContents: TCryptoLibByteArray): Boolean;
var
  I: Int32;
  LSubIDStart: Boolean;
begin
  if System.Length(AContents) < 1 then
  begin
    Result := False;
    Exit;
  end;

  LSubIDStart := True;
  for I := 0 to System.Length(AContents) - 1 do
  begin
    if LSubIDStart and (AContents[I] = $80) then
    begin
      Result := False;
      Exit;
    end;
    LSubIDStart := (AContents[I] and $80) = 0;
  end;

  Result := LSubIDStart;
end;

class function TAsn1RelativeOid.ParseContents(const AContents: TCryptoLibByteArray): String;
var
  LObjId: String;
  LValue: Int64;
  LBigValue: TBigInteger;
  I, LB: Int32;
  LFirst: Boolean;
begin
  LObjId := '';
  LValue := 0;
  LBigValue := Default(TBigInteger);
  LFirst := True;

  for I := 0 to System.Length(AContents) - 1 do
  begin
    LB := AContents[I];

    if LValue <= LongLimit then
    begin
      LValue := LValue + (LB and $7F);
      if (LB and $80) = 0 then
      begin
        if LFirst then
        begin
          LFirst := False;
        end
        else
        begin
          LObjId := LObjId + '.';
        end;
        LObjId := LObjId + IntToStr(LValue);
        LValue := 0;
      end
      else
      begin
        LValue := LValue shl 7;
      end;
    end
    else
    begin
      if not LBigValue.IsInitialized then
      begin
        LBigValue := TBigInteger.ValueOf(LValue);
      end;
      LBigValue := LBigValue.&Or(TBigInteger.ValueOf(LB and $7F));
      if (LB and $80) = 0 then
      begin
        if LFirst then
        begin
          LFirst := False;
        end
        else
        begin
          LObjId := LObjId + '.';
        end;
        LObjId := LObjId + LBigValue.ToString();
        LBigValue := Default(TBigInteger);
        LValue := 0;
      end
      else
      begin
        LBigValue := LBigValue.ShiftLeft(7);
      end;
    end;
  end;

  Result := LObjId;
end;

class function TAsn1RelativeOid.ParseIdentifier(const AIdentifier: String): TCryptoLibByteArray;
var
  LBOut: TMemoryStream;
  LTok: IOidTokenizer;
  LToken: String;
  LBytes: TCryptoLibByteArray;
begin
  LBOut := TMemoryStream.Create();
  try
    LTok := TOidTokenizer.Create(AIdentifier);
    while LTok.HasMoreTokens do
    begin
      LToken := LTok.NextToken();
      if System.Length(LToken) <= 18 then
      begin
        WriteField(LBOut, StrToInt64(LToken));
      end
      else
      begin
        WriteField(LBOut, TBigInteger.Create(LToken));
      end;
    end;
    System.SetLength(LBytes, LBOut.Size);
    LBOut.Position := 0;
    LBOut.Read(LBytes[0], LBOut.Size);
    Result := LBytes;
  finally
    LBOut.Free();
  end;
end;

class procedure TAsn1RelativeOid.WriteField(const AOutputStream: TStream; AFieldValue: Int64);
var
  LResult: TCryptoLibByteArray;
  LPos: Int32;
begin
  System.SetLength(LResult, 9);
  LPos := 8;
  LResult[LPos] := Byte(AFieldValue and $7F);
  while AFieldValue >= (Int64(1) shl 7) do
  begin
    AFieldValue := AFieldValue shr 7;
    System.Dec(LPos);
    LResult[LPos] := Byte(AFieldValue or $80);
  end;
  AOutputStream.Write(LResult[LPos], 9 - LPos);
end;

class procedure TAsn1RelativeOid.WriteField(const AOutputStream: TStream; const AFieldValue: TBigInteger);
var
  LByteCount, I: Int32;
  LTmp: TCryptoLibByteArray;
  LTmpValue: TBigInteger;
begin
  LByteCount := (AFieldValue.BitLength + 6) div 7;
  if LByteCount = 0 then
  begin
    AOutputStream.WriteByte(0);
  end
  else
  begin
    LTmpValue := AFieldValue;
    System.SetLength(LTmp, LByteCount);
    for I := LByteCount - 1 downto 0 do
    begin
      LTmp[I] := Byte(LTmpValue.Int32Value or $80);
      LTmpValue := LTmpValue.ShiftRight(7);
    end;
    LTmp[LByteCount - 1] := LTmp[LByteCount - 1] and $7F;
    AOutputStream.Write(LTmp[0], System.Length(LTmp));
  end;
end;

function TAsn1RelativeOid.GetID(): String;
begin
  if FIdentifier = '' then
  begin
    FIdentifier := ParseContents(FContents);
  end;
  Result := FIdentifier;
end;

function TAsn1RelativeOid.Branch(const ABranchID: String): IAsn1RelativeOid;
var
  LContents: TCryptoLibByteArray;
  LRootID, LIdentifier: String;
  LSubID: Int32;
  LBranchContents: TCryptoLibByteArray;
begin
  CheckIdentifier(ABranchID);

  if System.Length(ABranchID) <= 2 then
  begin
    CheckContentsLength(System.Length(FContents) + 1);
    LSubID := Ord(ABranchID[1]) - Ord('0');
    if System.Length(ABranchID) = 2 then
    begin
      LSubID := LSubID * 10;
      LSubID := LSubID + (Ord(ABranchID[2]) - Ord('0'));
    end;
    LContents := TArrayUtilities.Append<Byte>(FContents, Byte(LSubID));
  end
  else
  begin
    LBranchContents := ParseIdentifier(ABranchID);
    CheckContentsLength(System.Length(FContents) + System.Length(LBranchContents));
    LContents := TArrayUtilities.Concatenate<Byte>(FContents, LBranchContents);
  end;

  LRootID := GetID();
  LIdentifier := LRootID + '.' + ABranchID;
  Result := TAsn1RelativeOid.Create(LContents, LIdentifier);
end;

function TAsn1RelativeOid.ToString(): String;
begin
  Result := GetID();
end;

function TAsn1RelativeOid.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.RelativeOid, FContents);
end;

function TAsn1RelativeOid.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FContents);
end;

function TAsn1RelativeOid.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.RelativeOid, FContents);
end;

function TAsn1RelativeOid.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, FContents);
end;

class function TAsn1RelativeOid.CreatePrimitive(const AContents: TCryptoLibByteArray; AClone: Boolean): IAsn1Object;
var
  LIndex: UInt32;
  LOriginalEntry: IAsn1RelativeOid;
  LNewEntry: IAsn1RelativeOid;
  LExchangedEntry: IAsn1RelativeOid;
begin
  CheckContentsLength(System.Length(AContents));

  LIndex := UInt32(TArrayUtilities.GetArrayHashCode(AContents));
  LIndex := LIndex xor (LIndex shr 24);
  LIndex := LIndex xor (LIndex shr 12);
  LIndex := LIndex xor (LIndex shr 6);
  LIndex := LIndex and 63;

  if System.Length(FCache) = 0 then
    System.SetLength(FCache, 64);

  LOriginalEntry := FCache[LIndex];
  if (LOriginalEntry <> nil) and TArrayUtilities.AreEqual<Byte>(AContents, LOriginalEntry.Contents) then
  begin
    Result := LOriginalEntry;
    Exit;
  end;

  if not IsValidContents(AContents) then
    raise EArgumentCryptoLibException.Create('invalid relative OID contents');

  if AClone then
    LNewEntry := TAsn1RelativeOid.Create(AContents, True)
  else
    LNewEntry := TAsn1RelativeOid.Create(AContents, False);

  LExchangedEntry := FCache[LIndex];
  if LExchangedEntry <> LOriginalEntry then
  begin
    if (LExchangedEntry <> nil) and TArrayUtilities.AreEqual<Byte>(AContents, LExchangedEntry.Contents) then
    begin
      Result := LExchangedEntry;
      Exit;
    end;
  end;

  FCache[LIndex] := LNewEntry;
  Result := LNewEntry;
end;

{ TAsn1GeneralizedTime }

constructor TAsn1GeneralizedTime.Create(const AContents: TCryptoLibByteArray);
var
  LTimeString: String;
begin
  inherited Create();
  LTimeString := TConverters.ConvertBytesToString(AContents, TEncoding.ASCII);
  Create(LTimeString);
end;

constructor TAsn1GeneralizedTime.Create(const ATimeString: String);
begin
  inherited Create();
  if ATimeString = '' then
    raise EArgumentNilCryptoLibException.Create('timeString');
  
  FTimeString := ATimeString;
  FTimeStringCanonical := False; // TODO Dynamic check?
  
  try
    FDateTime := FromString(ATimeString);
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('invalid date string: ' + E.Message);
  end;
end;

constructor TAsn1GeneralizedTime.Create(const ADateTime: TDateTime);
var
  LUtc: TDateTime;
begin
  inherited Create();
  // Convert to UTC
  LUtc := TTimeZone.Local.ToUniversalTime(ADateTime);
  
  FDateTime := LUtc;
  FTimeString := ToStringCanonical(LUtc);
  FTimeStringCanonical := True;
end;

class function TAsn1GeneralizedTime.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TAsn1GeneralizedTime.Create(AContents);
end;

class function TAsn1GeneralizedTime.GetInstance(const AObj: TObject): IAsn1GeneralizedTime;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1GeneralizedTime.GetInstance(const AObj: IAsn1Object): IAsn1GeneralizedTime;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1GeneralizedTime, Result) then
    Exit;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj as TObject));
end;

class function TAsn1GeneralizedTime.GetInstance(const AObj: IAsn1Convertible): IAsn1GeneralizedTime;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1GeneralizedTime, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1GeneralizedTime.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1GeneralizedTime;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TAsn1GeneralizedTime.Meta.Instance.FromByteArray(ABytes) as IAsn1GeneralizedTime;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct generalized time from byte[]: ' + E.Message);
  end;
end;

class function TAsn1GeneralizedTime.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1GeneralizedTime;
begin
  Result := TAsn1GeneralizedTime.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1GeneralizedTime;
end;

class function TAsn1GeneralizedTime.GetOptional(const AElement: IAsn1Encodable): IAsn1GeneralizedTime;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAsn1GeneralizedTime, Result) then
    Exit;

  Result := nil;
end;

class function TAsn1GeneralizedTime.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1GeneralizedTime;
begin
  Result := TAsn1GeneralizedTime.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1GeneralizedTime;
end;

function TAsn1GeneralizedTime.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1GeneralizedTime;
  LThisContents, LThatContents: TCryptoLibByteArray;
begin
  if not Supports(AAsn1Object, IAsn1GeneralizedTime, LThat) then
  begin
    Result := False;
    Exit;
  end;
  // TODO Performance
  LThisContents := GetContents(TAsn1OutputStream.EncodingDer);
  LThatContents := LThat.GetContents(TAsn1OutputStream.EncodingDer);
  Result := TArrayUtilities.AreEqual<Byte>(LThisContents, LThatContents);
end;

function TAsn1GeneralizedTime.Asn1GetHashCode(): Int32;
var
  LContents: TCryptoLibByteArray;
begin
  // TODO Performance
  LContents := GetContents(TAsn1OutputStream.EncodingDer);
  Result := TArrayUtilities.GetArrayHashCode(LContents);
end;

function TAsn1GeneralizedTime.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.GeneralizedTime, GetContents(AEncoding));
end;

function TAsn1GeneralizedTime.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, GetContents(AEncoding));
end;

function TAsn1GeneralizedTime.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.GeneralizedTime,
    GetContents(TAsn1OutputStream.EncodingDer));
end;

function TAsn1GeneralizedTime.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, GetContents(TAsn1OutputStream.EncodingDer));
end;

function TAsn1GeneralizedTime.GetContents(AEncoding: Int32): TCryptoLibByteArray;
begin
  if (AEncoding = TAsn1OutputStream.EncodingDer) and (not FTimeStringCanonical) then
    Result := TConverters.ConvertStringToBytes(ToStringCanonical(FDateTime), TEncoding.ASCII)
  else
    Result := TConverters.ConvertStringToBytes(FTimeString, TEncoding.ASCII);
end;

function TAsn1GeneralizedTime.GetTimeString: String;
begin
  Result := FTimeString;
end;

function TAsn1GeneralizedTime.ToDateTime: TDateTime;
begin
  Result := FDateTime;
end;

class function TAsn1GeneralizedTime.FromString(const AStr: String): TDateTime;
var
  LS: String;
  LSignIndex: Int32;
begin
  if System.Length(AStr) < 10 then
    raise EFormatCryptoLibException.Create('Invalid time string length');

  LS := StringReplace(AStr, ',', '.', [rfReplaceAll]);

  // Check if string ends with 'Z' (UTC indicator)
  if (System.Length(LS) > 0) and (LS[System.Length(LS)] = 'Z') then
  begin
    case System.Length(LS) of
      11: Result := ParseUtc(LS, 'yyyyMMddHH"Z"');
      13: Result := ParseUtc(LS, 'yyyyMMddHHmm"Z"');
      15: Result := ParseUtc(LS, 'yyyyMMddHHmmss"Z"');
      17: Result := ParseUtc(LS, 'yyyyMMddHHmmss.f"Z"');
      18: Result := ParseUtc(LS, 'yyyyMMddHHmmss.ff"Z"');
      19: Result := ParseUtc(LS, 'yyyyMMddHHmmss.fff"Z"');
      20: Result := ParseUtc(LS, 'yyyyMMddHHmmss.ffff"Z"');
      21: Result := ParseUtc(LS, 'yyyyMMddHHmmss.fffff"Z"');
      22: Result := ParseUtc(LS, 'yyyyMMddHHmmss.ffffff"Z"');
      23: Result := ParseUtc(LS, 'yyyyMMddHHmmss.fffffff"Z"');
    else
      raise EFormatCryptoLibException.Create('Invalid UTC time format');
    end;
    Exit;
  end;

  LSignIndex := IndexOfSign(LS, Math.Max(11, System.Length(LS) - 4));

  if LSignIndex = 0 then
  begin
    case System.Length(LS) of
      10: Result := ParseLocal(LS, 'yyyyMMddHH');
      12: Result := ParseLocal(LS, 'yyyyMMddHHmm');
      14: Result := ParseLocal(LS, 'yyyyMMddHHmmss');
      16: Result := ParseLocal(LS, 'yyyyMMddHHmmss.f');
      17: Result := ParseLocal(LS, 'yyyyMMddHHmmss.ff');
      18: Result := ParseLocal(LS, 'yyyyMMddHHmmss.fff');
      19: Result := ParseLocal(LS, 'yyyyMMddHHmmss.ffff');
      20: Result := ParseLocal(LS, 'yyyyMMddHHmmss.fffff');
      21: Result := ParseLocal(LS, 'yyyyMMddHHmmss.ffffff');
      22: Result := ParseLocal(LS, 'yyyyMMddHHmmss.fffffff');
    else
      raise EFormatCryptoLibException.Create('Invalid local time format');
    end;
    Exit;
  end;

  if LSignIndex = System.Length(LS) - 4 then
  begin
    case System.Length(LS) of
      15: Result := ParseTimeZone(LS, 'yyyyMMddHHzzz');
      17: Result := ParseTimeZone(LS, 'yyyyMMddHHmmzzz');
      19: Result := ParseTimeZone(LS, 'yyyyMMddHHmmsszzz');
      21: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fzzz');
      22: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.ffzzz');
      23: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fffzzz');
      24: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.ffffzzz');
      25: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fffffzzz');
      26: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.ffffffzzz');
      27: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fffffffzzz');
    else
      raise EFormatCryptoLibException.Create('Invalid timezone format (5 chars)');
    end;
    Exit;
  end;

  if LSignIndex = System.Length(LS) - 2 then
  begin
    case System.Length(LS) of
      13: Result := ParseTimeZone(LS, 'yyyyMMddHHzz');
      15: Result := ParseTimeZone(LS, 'yyyyMMddHHmmzz');
      17: Result := ParseTimeZone(LS, 'yyyyMMddHHmmsszz');
      19: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fzz');
      20: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.ffzz');
      21: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fffzz');
      22: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.ffffzz');
      23: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fffffzz');
      24: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.ffffffzz');
      25: Result := ParseTimeZone(LS, 'yyyyMMddHHmmss.fffffffzz');
    else
      raise EFormatCryptoLibException.Create('Invalid timezone format (3 chars)');
    end;
    Exit;
  end;

  raise EFormatCryptoLibException.Create('Invalid time format');
end;

class function TAsn1GeneralizedTime.IndexOfSign(const AStr: String; AStartIndex: Int32): Int32;
var
  LIndex: Int32;
begin
  LIndex := TStringUtilities.IndexOf(AStr, '+', AStartIndex);
  if LIndex = 0 then
    LIndex := TStringUtilities.IndexOf(AStr, '-', AStartIndex);
    Result := LIndex;
end;

class function TAsn1GeneralizedTime.ParseLocal(const AStr, AFormat: String): TDateTime;
begin
  Result := TDateTimeUtilities.ParseExact(
    AStr,
    AFormat,
    [TDateTimeParseFlag.AssumeLocal],
    TFormatSettings.Invariant
  );
end;

class function TAsn1GeneralizedTime.ParseTimeZone(const AStr, AFormat: String): TDateTime;
begin
  Result := TDateTimeUtilities.ParseExact(
    AStr,
    AFormat,
    [TDateTimeParseFlag.AdjustToUniversal],
    TFormatSettings.Invariant
  );
end;

class function TAsn1GeneralizedTime.ParseUtc(const AStr, AFormat: String): TDateTime;
begin
  Result := TDateTimeUtilities.ParseExact(
    AStr,
    AFormat,
    [TDateTimeParseFlag.AdjustToUniversal, TDateTimeParseFlag.AssumeUniversal],
    TFormatSettings.Invariant
  );
end;

class function TAsn1GeneralizedTime.ToStringCanonical(const ADateTime: TDateTime): String;
begin
  Result := TDateTimeUtilities.FormatCanonical(
    ADateTime,
    'yyyyMMddHHmmss.FFFFFFFK',
    TFormatSettings.Invariant,
    False
  );
end;

{ TAsn1UtcTime }

constructor TAsn1UtcTime.Create(const AContents: TCryptoLibByteArray);
var
  LTimeString: String;
begin
  inherited Create();
  LTimeString := TConverters.ConvertBytesToString(AContents, TEncoding.ASCII);
  Create(LTimeString);
end;

constructor TAsn1UtcTime.Create(const ATimeString: String);
begin
  inherited Create();
  if ATimeString = '' then
    raise EArgumentNilCryptoLibException.Create('timeString');
  
  FTimeString := ATimeString;
  try
    FDateTime := FromString(ATimeString, FTwoDigitYearMax);
    FDateTimeLocked := False;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('invalid date string: ' + E.Message);
  end;
end;

constructor TAsn1UtcTime.Create(const ADateTime: TDateTime);
var
  LUtc: TDateTime;
  LTwoDigitYearMax: Int32;
begin
  inherited Create();
  // Convert to UTC and truncate to seconds precision
  LUtc := TDateTimeUtilities.WithPrecisionSecond(TTimeZone.Local.ToUniversalTime(ADateTime));
  
  FDateTime := LUtc;
  FDateTimeLocked := True;
  FTimeString := ToStringCanonical(LUtc, LTwoDigitYearMax);
  FTwoDigitYearMax := LTwoDigitYearMax;
end;

constructor TAsn1UtcTime.Create(const ADateTime: TDateTime; ATwoDigitYearMax: Int32);
var
  LUtc: TDateTime;
begin
  inherited Create();
  // Convert to UTC and truncate to seconds precision
  LUtc := TDateTimeUtilities.WithPrecisionSecond(TTimeZone.Local.ToUniversalTime(ADateTime));
  
  Validate(LUtc, ATwoDigitYearMax);
  
  FDateTime := LUtc;
  FDateTimeLocked := True;
  FTimeString := ToStringCanonical(LUtc);
  FTwoDigitYearMax := ATwoDigitYearMax;
end;

class function TAsn1UtcTime.GetInstance(const AObj: TObject): IAsn1UtcTime;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1UtcTime.GetInstance(const AObj: IAsn1Object): IAsn1UtcTime;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1UtcTime, Result) then
    Exit;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj as TObject));
end;

class function TAsn1UtcTime.GetInstance(const AObj: IAsn1Convertible): IAsn1UtcTime;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1UtcTime, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1UtcTime.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1UtcTime;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TAsn1UtcTime.Meta.Instance.FromByteArray(ABytes) as IAsn1UtcTime;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct UTC time from byte[]: ' + E.Message);
  end;
end;

class function TAsn1UtcTime.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1UtcTime;
begin
  Result := TAsn1UtcTime.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1UtcTime;
end;

class function TAsn1UtcTime.GetOptional(const AElement: IAsn1Encodable): IAsn1UtcTime;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAsn1UtcTime, Result) then
    Exit;

  Result := nil;
end;

class function TAsn1UtcTime.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1UtcTime;
begin
  Result := TAsn1UtcTime.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1UtcTime;
end;

class function TAsn1UtcTime.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TAsn1UtcTime.Create(AContents);
end;

function TAsn1UtcTime.GetContents(AEncoding: Int32): TCryptoLibByteArray;
var
  LCanonical: String;
begin
  if (AEncoding = TAsn1OutputStream.EncodingDer) and (System.Length(FTimeString) <> 13) then
  begin
    LCanonical := ToStringCanonical(FDateTime);
    Result := TConverters.ConvertStringToBytes(LCanonical, TEncoding.ASCII);
  end
  else
    Result := TConverters.ConvertStringToBytes(FTimeString, TEncoding.ASCII);
end;

function TAsn1UtcTime.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1UtcTime;
  LThisContents, LThatContents: TCryptoLibByteArray;
begin
  if not Supports(AAsn1Object, IAsn1UtcTime, LThat) then
  begin
    Result := False;
    Exit;
  end;
  // TODO Performance
  LThisContents := GetContents(TAsn1OutputStream.EncodingDer);
  LThatContents := LThat.GetContents(TAsn1OutputStream.EncodingDer);
  Result := TArrayUtilities.AreEqual<Byte>(LThisContents, LThatContents);
end;

function TAsn1UtcTime.Asn1GetHashCode(): Int32;
var
  LContents: TCryptoLibByteArray;
begin
  // TODO Performance
  LContents := GetContents(TAsn1OutputStream.EncodingDer);
  Result := TArrayUtilities.GetArrayHashCode(LContents);
end;

function TAsn1UtcTime.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.UtcTime, GetContents(AEncoding));
end;

function TAsn1UtcTime.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, GetContents(AEncoding));
end;

function TAsn1UtcTime.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.UtcTime,
    GetContents(TAsn1OutputStream.EncodingDer));
end;

function TAsn1UtcTime.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, GetContents(TAsn1OutputStream.EncodingDer));
end;

function TAsn1UtcTime.GetTimeString: String;
begin
  Result := FTimeString;
end;

function TAsn1UtcTime.GetTwoDigitYearMax: Int32;
begin
  Result := FTwoDigitYearMax;
end;

function TAsn1UtcTime.ToString(): String;
begin
  Result := FTimeString;
end;

function TAsn1UtcTime.ToDateTime: TDateTime;
begin
  Result := FDateTime;
end;

{ TDerUtcTime }

constructor TDerUtcTime.Create(const ATimeString: String);
begin
  inherited Create(ATimeString);
end;

constructor TDerUtcTime.Create(const ADateTime: TDateTime);
begin
  inherited Create(ADateTime);
end;

constructor TDerUtcTime.Create(const ADateTime: TDateTime; ATwoDigitYearMax: Int32);
begin
  inherited Create(ADateTime, ATwoDigitYearMax);
end;

constructor TDerUtcTime.Create(const AContents: TCryptoLibByteArray);
begin
  inherited Create(AContents);
end;

function TDerUtcTime.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.UtcTime,
    GetContents(TAsn1OutputStream.EncodingDer));
end;

function TDerUtcTime.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, GetContents(TAsn1OutputStream.EncodingDer));
end;

{ TDerGeneralizedTime }

constructor TDerGeneralizedTime.Create(const ATimeString: String);
begin
  inherited Create(ATimeString);
end;

constructor TDerGeneralizedTime.Create(const ADateTime: TDateTime);
begin
  inherited Create(ADateTime);
end;

constructor TDerGeneralizedTime.Create(const AContents: TCryptoLibByteArray);
begin
  inherited Create(AContents);
end;

function TDerGeneralizedTime.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.GeneralizedTime,
    GetContents(TAsn1OutputStream.EncodingDer));
end;

function TDerGeneralizedTime.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, GetContents(TAsn1OutputStream.EncodingDer));
end;

function TAsn1UtcTime.ToDateTime(ATwoDigitYearMax: Int32): TDateTime;
var
  LTwoDigitYear, LTwoDigitYearCutoff, LDiff, LNewYear: Int32;
begin
  if InRange(FDateTime, ATwoDigitYearMax) then
  begin
    Result := FDateTime;
    Exit;
  end;
  
  if FDateTimeLocked then
    raise EInvalidOperationCryptoLibException.Create('DateTime is locked');
  
  LTwoDigitYear := YearOf(FDateTime) mod 100;
  LTwoDigitYearCutoff := ATwoDigitYearMax mod 100;
  
  LDiff := LTwoDigitYear - LTwoDigitYearCutoff;
  LNewYear := ATwoDigitYearMax + LDiff;
  if LDiff > 0 then
    LNewYear := LNewYear - 100;
  
  Result := IncYear(FDateTime, LNewYear - YearOf(FDateTime));
end;

function TAsn1UtcTime.ToAdjustedDateTime: TDateTime;
begin
  Result := ToDateTime(2049);
end;

class function TAsn1UtcTime.InRange(const ADateTime: TDateTime; ATwoDigitYearMax: Int32): Boolean;
var
  LYear: Int32;
begin
  LYear := YearOf(ADateTime);
  Result := (UInt32(ATwoDigitYearMax - LYear) < 100);
end;

class function TAsn1UtcTime.FromString(const AStr: String; out ATwoDigitYearMax: Int32): TDateTime;
var
  LFormatSettings: TFormatSettings;
begin
  LFormatSettings := TFormatSettings.Invariant;

  ATwoDigitYearMax := TDateTimeUtilities.TwoDigitYearMax;

  case System.Length(AStr) of
    11:
      begin
        // yyMMddHHmm"Z"
        Result := TDateTimeUtilities.ParseExact(
          AStr,
          'yyMMddHHmm"Z"',
          [TDateTimeParseFlag.AdjustToUniversal, TDateTimeParseFlag.AssumeUniversal],
          LFormatSettings
        );
      end;

    13:
      begin
        // yyMMddHHmmss"Z"
        Result := TDateTimeUtilities.ParseExact(
          AStr,
          'yyMMddHHmmss"Z"',
          [TDateTimeParseFlag.AdjustToUniversal, TDateTimeParseFlag.AssumeUniversal],
          LFormatSettings
        );
      end;

    15:
      begin
        // yyMMddHHmmzzz  (HHMM)
        Result := TDateTimeUtilities.ParseExact(
          AStr,
          'yyMMddHHmmzzz',
          [TDateTimeParseFlag.AdjustToUniversal],
          LFormatSettings
        );
      end;

    17:
      begin
        // yyMMddHHmmsszzz (HHMM)
        Result := TDateTimeUtilities.ParseExact(
          AStr,
          'yyMMddHHmmsszzz',
          [TDateTimeParseFlag.AdjustToUniversal],
          LFormatSettings
        );
      end;
  else
    raise EFormatCryptoLibException.Create('Invalid UTC time string length');
  end;
end;

class function TAsn1UtcTime.ToStringCanonical(
  const ADateTime: TDateTime; out ATwoDigitYearMax: Int32): String;
begin
  ATwoDigitYearMax := TDateTimeUtilities.TwoDigitYearMax;
  Validate(ADateTime, ATwoDigitYearMax);

  Result := TDateTimeUtilities.FormatCanonical(
    ADateTime,
    'yyMMddHHmmss"Z"',
    TFormatSettings.Invariant,
    False
  );
end;


class function TAsn1UtcTime.ToStringCanonical(const ADateTime: TDateTime): String;
begin
  Result := TDateTimeUtilities.FormatCanonical(
    ADateTime,
    'yyMMddHHmmss"Z"',
    TFormatSettings.Invariant,
    False
  );
end;

class procedure TAsn1UtcTime.Validate(const ADateTime: TDateTime; ATwoDigitYearMax: Int32);
begin
  if not InRange(ADateTime, ATwoDigitYearMax) then
    raise EArgumentOutOfRangeCryptoLibException.Create('DateTime value out of range');
end;

{ TAsn1ObjectDescriptor }

constructor TAsn1ObjectDescriptor.Create(const AGraphicString: IAsn1Object);
begin
  inherited Create();
  FGraphicString := AGraphicString;
end;

class function TAsn1ObjectDescriptor.GetInstance(const AObj: TObject): IAsn1ObjectDescriptor;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TAsn1ObjectDescriptor.GetInstance(const AObj: IAsn1Object): IAsn1ObjectDescriptor;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1ObjectDescriptor, Result) then
    Exit;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj as TObject));
end;

class function TAsn1ObjectDescriptor.GetInstance(const AObj: IAsn1Convertible): IAsn1ObjectDescriptor;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAsn1ObjectDescriptor, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TAsn1ObjectDescriptor.GetInstance(const ABytes: TCryptoLibByteArray): IAsn1ObjectDescriptor;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  try
    Result := TAsn1ObjectDescriptor.Meta.Instance.FromByteArray(ABytes) as IAsn1ObjectDescriptor;
  except
    on E: Exception do
      raise EArgumentCryptoLibException.Create('failed to construct object descriptor from byte[]: ' + E.Message);
  end;
end;

class function TAsn1ObjectDescriptor.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1ObjectDescriptor;
begin
  Result := TAsn1ObjectDescriptor.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IAsn1ObjectDescriptor;
end;

class function TAsn1ObjectDescriptor.GetOptional(const AElement: IAsn1Encodable): IAsn1ObjectDescriptor;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAsn1ObjectDescriptor, Result) then
    Exit;

  Result := nil;
end;

class function TAsn1ObjectDescriptor.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1ObjectDescriptor;
begin
  Result := TAsn1ObjectDescriptor.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IAsn1ObjectDescriptor;
end;

class function TAsn1ObjectDescriptor.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
var
  LGraphicString: IAsn1Object;
begin
  LGraphicString := TDerGraphicString.CreatePrimitive(AContents);
  Result := TAsn1ObjectDescriptor.Create(LGraphicString);
end;

function TAsn1ObjectDescriptor.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IAsn1ObjectDescriptor;
begin
  if not Supports(AAsn1Object, IAsn1ObjectDescriptor, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := FGraphicString.Equals(LThat.GraphicString);
end;

function TAsn1ObjectDescriptor.Asn1GetHashCode(): Int32;
begin
  Result := not FGraphicString.CallAsn1GetHashCode();
end;

function TAsn1ObjectDescriptor.GetGraphicString(): IAsn1Object;
begin
  Result := FGraphicString;
end;

function TAsn1ObjectDescriptor.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := FGraphicString.GetEncodingImplicit(AEncoding, TAsn1Tags.Universal, TAsn1Tags.ObjectDescriptor);
end;

function TAsn1ObjectDescriptor.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := FGraphicString.GetEncodingImplicit(AEncoding, ATagClass, ATagNo);
end;

function TAsn1ObjectDescriptor.GetEncodingDer(): IDerEncoding;
begin
  Result := FGraphicString.GetEncodingDerImplicit(TAsn1Tags.Universal, TAsn1Tags.ObjectDescriptor);
end;

function TAsn1ObjectDescriptor.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := FGraphicString.GetEncodingDerImplicit(ATagClass, ATagNo);
end;

{ TDerUtf8String }

constructor TDerUtf8String.Create(const AStr: String);
begin
  Create(TConverters.ConvertStringToBytes(AStr, TEncoding.UTF8), False);
end;

constructor TDerUtf8String.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerUtf8String.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerUtf8String.GetInstance(const AObj: TObject): IDerUtf8String;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerUtf8String.GetInstance(const AObj: IAsn1Object): IDerUtf8String;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerUtf8String, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerUtf8String.GetInstance(const AObj: IAsn1Convertible): IDerUtf8String;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerUtf8String, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerUtf8String.GetInstance(const ABytes: TCryptoLibByteArray): IDerUtf8String;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerUtf8String, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct UTF8 string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct UTF8 string from byte[]: ' + E.Message);
  end;
end;

class function TDerUtf8String.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUtf8String;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerUtf8String, Result) then
    raise EArgumentCryptoLibException.Create('failed to get UTF8 string from tagged object');
end;

class function TDerUtf8String.GetOptional(const AElement: IAsn1Encodable): IDerUtf8String;
var
  LUtf8String: IDerUtf8String;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerUtf8String, LUtf8String) then
    Result := LUtf8String
  else
    Result := nil;
end;

class function TDerUtf8String.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUtf8String;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerUtf8String, Result) then
    raise EArgumentCryptoLibException.Create('failed to get UTF8 string from tagged object');
end;

function TDerUtf8String.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.UTF8);
end;

function TDerUtf8String.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerUtf8String.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerUtf8String.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.Utf8String;
end;

function TDerUtf8String.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerUtf8String;
begin
  if not Supports(AAsn1Object, IDerUtf8String, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerUtf8String.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerUtf8String.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerUtf8String.Create(AContents, False);
end;

{ TDerGeneralString }

constructor TDerGeneralString.Create(const AStr: String);
begin
  inherited Create();
  if AStr = '' then
    raise EArgumentNilCryptoLibException.Create('str');
  FContents := TConverters.ConvertStringToBytes(AStr, TEncoding.ASCII);
end;

constructor TDerGeneralString.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerGeneralString.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerGeneralString.GetInstance(const AObj: TObject): IDerGeneralString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerGeneralString.GetInstance(const AObj: IAsn1Object): IDerGeneralString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerGeneralString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerGeneralString.GetInstance(const AObj: IAsn1Convertible): IDerGeneralString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerGeneralString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerGeneralString.GetInstance(const ABytes: TCryptoLibByteArray): IDerGeneralString;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerGeneralString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct general string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct general string from byte[]: ' + E.Message);
  end;
end;

class function TDerGeneralString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGeneralString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerGeneralString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get general string from tagged object');
end;

class function TDerGeneralString.GetOptional(const AElement: IAsn1Encodable): IDerGeneralString;
var
  LGeneralString: IDerGeneralString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerGeneralString, LGeneralString) then
    Result := LGeneralString
  else
    Result := nil;
end;

class function TDerGeneralString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGeneralString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerGeneralString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get general string from tagged object');
end;

function TDerGeneralString.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.ASCII);
end;

function TDerGeneralString.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerGeneralString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerGeneralString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.GeneralString;
end;

function TDerGeneralString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerGeneralString;
begin
  if not Supports(AAsn1Object, IDerGeneralString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerGeneralString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerGeneralString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerGeneralString.Create(AContents, False);
end;

{ TDerGraphicString }

constructor TDerGraphicString.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerGraphicString.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerGraphicString.GetInstance(const AObj: TObject): IDerGraphicString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerGraphicString.GetInstance(const AObj: IAsn1Object): IDerGraphicString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerGraphicString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerGraphicString.GetInstance(const AObj: IAsn1Convertible): IDerGraphicString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerGraphicString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerGraphicString.GetInstance(const ABytes: TCryptoLibByteArray): IDerGraphicString;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerGraphicString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct graphic string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct graphic string from byte[]: ' + E.Message);
  end;
end;

class function TDerGraphicString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGraphicString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerGraphicString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get graphic string from tagged object');
end;

class function TDerGraphicString.GetOptional(const AElement: IAsn1Encodable): IDerGraphicString;
var
  LGraphicString: IDerGraphicString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerGraphicString, LGraphicString) then
    Result := LGraphicString
  else
    Result := nil;
end;

class function TDerGraphicString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerGraphicString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerGraphicString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get graphic string from tagged object');
end;

function TDerGraphicString.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.ANSI);
end;

function TDerGraphicString.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerGraphicString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerGraphicString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.GraphicString;
end;

function TDerGraphicString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerGraphicString;
begin
  if not Supports(AAsn1Object, IDerGraphicString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerGraphicString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerGraphicString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerGraphicString.Create(AContents, False);
end;

{ TDerIA5String }

constructor TDerIA5String.Create(const AStr: String);
begin
  Create(AStr, False);
end;

constructor TDerIA5String.Create(const AStr: String; AValidate: Boolean);
begin
  inherited Create();
  if AStr = '' then
    raise EArgumentNilCryptoLibException.Create('str');
  if AValidate and not IsIA5String(AStr) then
    raise EArgumentCryptoLibException.Create('string contains illegal characters');
  FContents := TConverters.ConvertStringToBytes(AStr, TEncoding.ASCII);
end;

constructor TDerIA5String.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerIA5String.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerIA5String.IsIA5String(const AStr: String): Boolean;
var
  I: Int32;
  LCh: Char;
begin
  for I := 1 to System.Length(AStr) do
  begin
    LCh := AStr[I];
    if Ord(LCh) > $007F then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TDerIA5String.GetInstance(const AObj: TObject): IDerIA5String;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerIA5String.GetInstance(const AObj: IAsn1Object): IDerIA5String;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerIA5String, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerIA5String.GetInstance(const AObj: IAsn1Convertible): IDerIA5String;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerIA5String, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerIA5String.GetInstance(const ABytes: TCryptoLibByteArray): IDerIA5String;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerIA5String, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct IA5 string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct IA5 string from byte[]: ' + E.Message);
  end;
end;

class function TDerIA5String.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerIA5String;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerIA5String, Result) then
    raise EArgumentCryptoLibException.Create('failed to get IA5 string from tagged object');
end;

class function TDerIA5String.GetOptional(const AElement: IAsn1Encodable): IDerIA5String;
var
  LIA5String: IDerIA5String;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerIA5String, LIA5String) then
    Result := LIA5String
  else
    Result := nil;
end;

class function TDerIA5String.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerIA5String;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerIA5String, Result) then
    raise EArgumentCryptoLibException.Create('failed to get IA5 string from tagged object');
end;

function TDerIA5String.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.ASCII);
end;

function TDerIA5String.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerIA5String.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerIA5String.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.IA5String;
end;

function TDerIA5String.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerIA5String;
begin
  if not Supports(AAsn1Object, IDerIA5String, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerIA5String.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerIA5String.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerIA5String.Create(AContents, False);
end;

{ TDerNumericString }

constructor TDerNumericString.Create(const AStr: String);
begin
  Create(AStr, False);
end;

constructor TDerNumericString.Create(const AStr: String; AValidate: Boolean);
begin
  inherited Create();
  if AStr = '' then
    raise EArgumentNilCryptoLibException.Create('str');
  if AValidate and not IsNumericString(AStr) then
    raise EArgumentCryptoLibException.Create('string contains illegal characters');
  FContents := TConverters.ConvertStringToBytes(AStr, TEncoding.ASCII);
end;

constructor TDerNumericString.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerNumericString.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerNumericString.IsNumericString(const AStr: String): Boolean;
var
  I: Int32;
  LCh: Char;
  LOrd: Int32;
begin
  for I := 1 to System.Length(AStr) do
  begin
    LCh := AStr[I];
    LOrd := Ord(LCh);
    if (LOrd > $007F) or ((LCh <> ' ') and ((LOrd < Ord('0')) or (LOrd > Ord('9')))) then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TDerNumericString.IsNumericString(const AContents: TCryptoLibByteArray): Boolean;
var
  I: Int32;
  LB: Byte;
begin
  for I := 0 to System.Length(AContents) - 1 do
  begin
    LB := AContents[I];
    case LB of
      $20, $30, $31, $32, $33, $34, $35, $36, $37, $38, $39:
        // Valid character
        ;
    else
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

class function TDerNumericString.GetInstance(const AObj: TObject): IDerNumericString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerNumericString.GetInstance(const AObj: IAsn1Object): IDerNumericString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerNumericString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerNumericString.GetInstance(const AObj: IAsn1Convertible): IDerNumericString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerNumericString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerNumericString.GetInstance(const ABytes: TCryptoLibByteArray): IDerNumericString;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerNumericString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct numeric string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct numeric string from byte[]: ' + E.Message);
  end;
end;

class function TDerNumericString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerNumericString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerNumericString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get numeric string from tagged object');
end;

class function TDerNumericString.GetOptional(const AElement: IAsn1Encodable): IDerNumericString;
var
  LNumericString: IDerNumericString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerNumericString, LNumericString) then
    Result := LNumericString
  else
    Result := nil;
end;

class function TDerNumericString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerNumericString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerNumericString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get numeric string from tagged object');
end;

function TDerNumericString.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.ASCII);
end;

function TDerNumericString.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerNumericString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerNumericString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.NumericString;
end;

function TDerNumericString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerNumericString;
begin
  if not Supports(AAsn1Object, IDerNumericString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerNumericString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerNumericString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerNumericString.Create(AContents, False);
end;

{ TDerPrintableString }

constructor TDerPrintableString.Create(const AStr: String);
begin
  inherited Create();
  if AStr = '' then
    raise EArgumentNilCryptoLibException.Create('str');
  FContents := TConverters.ConvertStringToBytes(AStr, TEncoding.ASCII);
end;

constructor TDerPrintableString.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerPrintableString.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerPrintableString.GetInstance(const AObj: TObject): IDerPrintableString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerPrintableString.GetInstance(const AObj: IAsn1Object): IDerPrintableString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerPrintableString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerPrintableString.GetInstance(const AObj: IAsn1Convertible): IDerPrintableString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerPrintableString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerPrintableString.GetInstance(const ABytes: TCryptoLibByteArray): IDerPrintableString;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerPrintableString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct printable string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct printable string from byte[]: ' + E.Message);
  end;
end;

class function TDerPrintableString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerPrintableString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerPrintableString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get printable string from tagged object');
end;

class function TDerPrintableString.GetOptional(const AElement: IAsn1Encodable): IDerPrintableString;
var
  LPrintableString: IDerPrintableString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerPrintableString, LPrintableString) then
    Result := LPrintableString
  else
    Result := nil;
end;

class function TDerPrintableString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerPrintableString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerPrintableString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get printable string from tagged object');
end;

function TDerPrintableString.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.ASCII);
end;

function TDerPrintableString.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerPrintableString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerPrintableString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.PrintableString;
end;

function TDerPrintableString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerPrintableString;
begin
  if not Supports(AAsn1Object, IDerPrintableString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerPrintableString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerPrintableString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerPrintableString.Create(AContents, False);
end;

class function TDerPrintableString.IsPrintableString(const AStr: String): Boolean;
var
  I: Int32;
  LCh: Char;
  LOrd: Int32;
begin
  for I := 1 to System.Length(AStr) do
  begin
    LCh := AStr[I];
    LOrd := Ord(LCh);
    if LOrd > $007F then
    begin
      Result := False;
      Exit;
    end;
    
    // Check if letter or digit
    if ((LOrd >= Ord('A')) and (LOrd <= Ord('Z'))) or
       ((LOrd >= Ord('a')) and (LOrd <= Ord('z'))) or
       ((LOrd >= Ord('0')) and (LOrd <= Ord('9'))) then
      Continue;

    // Check allowed special characters
    case LCh of
      ' ', '''', '(', ')', '+', '-', '.', ':', '=', '?', '/', ',':
        Continue;
    else
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

{ TDerT61String }

class constructor TDerT61String.Create;
begin
  FEncoding := TEncoding.GetEncoding('iso-8859-1');
end;

class destructor TDerT61String.Destroy;
begin
  FEncoding.Free;
  FEncoding := nil;
end;

constructor TDerT61String.Create(const AStr: String);
begin
  inherited Create();
  if AStr = '' then
    raise EArgumentNilCryptoLibException.Create('str');
  FContents := TConverters.ConvertStringToBytes(AStr, FEncoding);
end;

constructor TDerT61String.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerT61String.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerT61String.GetInstance(const AObj: TObject): IDerT61String;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerT61String.GetInstance(const AObj: IAsn1Object): IDerT61String;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerT61String, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerT61String.GetInstance(const AObj: IAsn1Convertible): IDerT61String;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerT61String, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerT61String.GetInstance(const ABytes: TCryptoLibByteArray): IDerT61String;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerT61String, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct T61 string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct T61 string from byte[]: ' + E.Message);
  end;
end;

class function TDerT61String.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerT61String;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerT61String, Result) then
    raise EArgumentCryptoLibException.Create('failed to get T61 string from tagged object');
end;

class function TDerT61String.GetOptional(const AElement: IAsn1Encodable): IDerT61String;
var
  LT61String: IDerT61String;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerT61String, LT61String) then
    Result := LT61String
  else
    Result := nil;
end;

class function TDerT61String.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerT61String;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerT61String, Result) then
    raise EArgumentCryptoLibException.Create('failed to get T61 string from tagged object');
end;

function TDerT61String.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, FEncoding);
end;

function TDerT61String.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerT61String.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerT61String.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.T61String;
end;

function TDerT61String.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerT61String;
begin
  if not Supports(AAsn1Object, IDerT61String, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerT61String.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerT61String.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerT61String.Create(AContents, False);
end;

{ TDerUniversalString }

constructor TDerUniversalString.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerUniversalString.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerUniversalString.GetInstance(const AObj: TObject): IDerUniversalString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerUniversalString.GetInstance(const AObj: IAsn1Object): IDerUniversalString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerUniversalString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerUniversalString.GetInstance(const AObj: IAsn1Convertible): IDerUniversalString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerUniversalString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerUniversalString.GetInstance(const ABytes: TCryptoLibByteArray): IDerUniversalString;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerUniversalString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct universal string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct universal string from byte[]: ' + E.Message);
  end;
end;

class function TDerUniversalString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUniversalString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerUniversalString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get universal string from tagged object');
end;

class function TDerUniversalString.GetOptional(const AElement: IAsn1Encodable): IDerUniversalString;
var
  LUniversalString: IDerUniversalString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerUniversalString, LUniversalString) then
    Result := LUniversalString
  else
    Result := nil;
end;

class function TDerUniversalString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerUniversalString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerUniversalString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get universal string from tagged object');
end;

function TDerUniversalString.GetString(): String;
const
  LTable: array[0..15] of Char = ('0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
var
  LDl, LCapacity, I: Int32;
  LBuf: TStringBuilder;
begin
  LDl := System.Length(FContents);
  LCapacity := 3 + 2 * (TAsn1OutputStream.GetLengthOfDL(LDl) + LDl);
  LBuf := TStringBuilder.Create('#1C', LCapacity);
  try
    EncodeHexDL(LBuf, LDl, LTable);
    for I := 0 to LDl - 1 do
      EncodeHexByte(LBuf, FContents[I], LTable);
    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

function TDerUniversalString.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerUniversalString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerUniversalString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.UniversalString;
end;

function TDerUniversalString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerUniversalString;
begin
  if not Supports(AAsn1Object, IDerUniversalString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerUniversalString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerUniversalString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerUniversalString.Create(AContents, False);
end;

procedure TDerUniversalString.EncodeHexByte(ABuf: TStringBuilder; AByte: Byte; const ATable: array of Char);
begin
  ABuf.Append(ATable[(AByte shr 4) and $F]);
  ABuf.Append(ATable[AByte and $F]);
end;

procedure TDerUniversalString.EncodeHexDL(ABuf: TStringBuilder; ADl: Int32; const ATable: array of Char);
var
  LStack: array[0..4] of Byte;
  LPos, LCount: Int32;
begin
  if ADl < 128 then
  begin
    EncodeHexByte(ABuf, ADl, ATable);
    Exit;
  end;

  LPos := 5;
  repeat
    System.Dec(LPos);
    LStack[LPos] := Byte(ADl);
    ADl := ADl shr 8;
  until ADl = 0;

  LCount := 5 - LPos;
  System.Dec(LPos);
  LStack[LPos] := Byte($80 or LCount);

  repeat
    EncodeHexByte(ABuf, LStack[LPos], ATable);
    System.Inc(LPos);
  until LPos >= 5;
end;

{ TDerVideotexString }

constructor TDerVideotexString.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerVideotexString.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerVideotexString.GetInstance(const AObj: TObject): IDerVideotexString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerVideotexString.GetInstance(const AObj: IAsn1Object): IDerVideotexString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerVideotexString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerVideotexString.GetInstance(const AObj: IAsn1Convertible): IDerVideotexString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerVideotexString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerVideotexString.GetInstance(const ABytes: TCryptoLibByteArray): IDerVideotexString;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerVideotexString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct videotex string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct videotex string from byte[]: ' + E.Message);
  end;
end;

class function TDerVideotexString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVideotexString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerVideotexString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get videotex string from tagged object');
end;

class function TDerVideotexString.GetOptional(const AElement: IAsn1Encodable): IDerVideotexString;
var
  LVideotexString: IDerVideotexString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerVideotexString, LVideotexString) then
    Result := LVideotexString
  else
    Result := nil;
end;

class function TDerVideotexString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVideotexString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerVideotexString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get videotex string from tagged object');
end;

function TDerVideotexString.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.ANSI);
end;

function TDerVideotexString.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerVideotexString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerVideotexString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.VideotexString;
end;

function TDerVideotexString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerVideotexString;
begin
  if not Supports(AAsn1Object, IDerVideotexString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerVideotexString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerVideotexString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerVideotexString.Create(AContents, False);
end;

{ TDerVisibleString }

constructor TDerVisibleString.Create(const AStr: String);
begin
  inherited Create();
  if AStr = '' then
    raise EArgumentNilCryptoLibException.Create('str');
  FContents := TConverters.ConvertStringToBytes(AStr, TEncoding.ASCII);
end;

constructor TDerVisibleString.Create(const AContents: TCryptoLibByteArray);
begin
  Create(AContents, True);
end;

constructor TDerVisibleString.Create(const AContents: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if AContents = nil then
    raise EArgumentNilCryptoLibException.Create('contents');
  if AClone then
    FContents := System.Copy(AContents)
  else
    FContents := AContents;
end;

class function TDerVisibleString.GetInstance(const AObj: TObject): IDerVisibleString;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('illegal object in GetInstance: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TDerVisibleString.GetInstance(const AObj: IAsn1Object): IDerVisibleString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerVisibleString, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerVisibleString.GetInstance(const AObj: IAsn1Convertible): IDerVisibleString;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerVisibleString, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerVisibleString.GetInstance(const ABytes: TCryptoLibByteArray): IDerVisibleString;
var
  LObj: IAsn1Object;
begin
  try
    LObj := Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerVisibleString, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct visible string from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct visible string from byte[]: ' + E.Message);
  end;
end;

class function TDerVisibleString.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVisibleString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerVisibleString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get visible string from tagged object');
end;

class function TDerVisibleString.GetOptional(const AElement: IAsn1Encodable): IDerVisibleString;
var
  LVisibleString: IDerVisibleString;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerVisibleString, LVisibleString) then
    Result := LVisibleString
  else
    Result := nil;
end;

class function TDerVisibleString.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerVisibleString;
var
  LObj: IAsn1Object;
begin
  LObj := Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit);
  if not Supports(LObj, IDerVisibleString, Result) then
    raise EArgumentCryptoLibException.Create('failed to get visible string from tagged object');
end;

function TDerVisibleString.GetString(): String;
begin
  Result := TConverters.ConvertBytesToString(FContents, TEncoding.ASCII);
end;

function TDerVisibleString.GetOctets(): TCryptoLibByteArray;
begin
  Result := System.Copy(FContents);
end;

function TDerVisibleString.GetContents(): TCryptoLibByteArray;
begin
  Result := FContents;
end;

function TDerVisibleString.GetTagNo(): Int32;
begin
  Result := TAsn1Tags.VisibleString;
end;

function TDerVisibleString.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerVisibleString;
begin
  if not Supports(AAsn1Object, IDerVisibleString, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FContents, LThat.Contents);
end;

function TDerVisibleString.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FContents);
end;

class function TDerVisibleString.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerVisibleString.Create(AContents, False);
end;

{ TDerInteger }

class constructor TDerInteger.Create;
var
  I: Int32;
begin
  System.SetLength(FSmallConstants, 17);
  for I := 0 to System.Length(FSmallConstants) - 1 do
  begin
    FSmallConstants[I] := TDerInteger.Create(I);
  end;
  
  FZero := FSmallConstants[0];
  FOne := FSmallConstants[1];
  FTwo := FSmallConstants[2];
  FThree := FSmallConstants[3];
  FFour := FSmallConstants[4];
  FFive := FSmallConstants[5];
  FAllowUnsafeInteger := False;
end;

class function TDerInteger.GetZero(): IDerInteger;
begin
  Result := FZero;
end;

class function TDerInteger.GetOne(): IDerInteger;
begin
  Result := FOne;
end;

class function TDerInteger.GetTwo(): IDerInteger;
begin
  Result := FTwo;
end;

class function TDerInteger.GetThree(): IDerInteger;
begin
  Result := FThree;
end;

class function TDerInteger.GetFour(): IDerInteger;
begin
  Result := FFour;
end;

class function TDerInteger.GetFive(): IDerInteger;
begin
  Result := FFive;
end;

constructor TDerInteger.Create(AValue: Int32);
begin
  inherited Create();
  FBytes := TBigInteger.ValueOf(AValue).ToByteArray();
  FStart := 0;
end;

constructor TDerInteger.Create(AValue: Int64);
begin
  inherited Create();
  FBytes := TBigInteger.ValueOf(AValue).ToByteArray();
  FStart := 0;
end;

constructor TDerInteger.Create(const AValue: TBigInteger);
begin
  inherited Create();
  if not AValue.IsInitialized then
    raise EArgumentNilCryptoLibException.Create('value');
  FBytes := AValue.ToByteArray();
  FStart := 0;
end;

constructor TDerInteger.Create(const ABytes: TCryptoLibByteArray);
begin
  Create(ABytes, True);
end;

constructor TDerInteger.Create(const ABytes: TCryptoLibByteArray; AClone: Boolean);
begin
  inherited Create();
  if IsMalformed(ABytes) then
    raise EArgumentCryptoLibException.Create('malformed integer');
  if AClone then
    FBytes := System.Copy(ABytes)
  else
    FBytes := ABytes;
  FStart := SignBytesToSkip(FBytes);
end;

function TDerInteger.Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
var
  LThat: IDerInteger;
begin
  if not Supports(AAsn1Object, IDerInteger, LThat) then
  begin
    Result := False;
    Exit;
  end;
  Result := TArrayUtilities.AreEqual<Byte>(FBytes, LThat.Bytes);
end;

function TDerInteger.Asn1GetHashCode(): Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FBytes);
end;

function TDerInteger.GetBytes(): TCryptoLibByteArray;
begin
  Result := FBytes;
end;

class function TDerInteger.CreatePrimitive(const AContents: TCryptoLibByteArray): IAsn1Object;
begin
  Result := TDerInteger.Create(AContents, False);
end;

class function TDerInteger.GetAllowUnsafeInteger(): Boolean;
begin
  Result := FAllowUnsafeInteger;
end;

class procedure TDerInteger.SetAllowUnsafeInteger(const AValue: Boolean);
begin
  FAllowUnsafeInteger := AValue;
end;

class function TDerInteger.AllowUnsafe(): Boolean;
begin
  Result := AllowUnsafeInteger;
end;

class function TDerInteger.IsMalformed(const ABytes: TCryptoLibByteArray): Boolean;
var
  LLength: Int32;
begin
  LLength := System.Length(ABytes);
  case LLength of
    0:
      Result := True;
    1:
      Result := False;
  else
    Result := (ShortInt(ABytes[0]) = TBitUtilities.Asr32(ShortInt(ABytes[1]), 7)) and (not AllowUnsafe());
  end;
end;

class function TDerInteger.SignBytesToSkip(const ABytes: TCryptoLibByteArray): Int32;
var
  LPos, LLast: Int32;
begin
  LPos := 0;
  LLast := System.Length(ABytes) - 1;
  while (LPos < LLast) and (ShortInt(ABytes[LPos]) = TBitUtilities.Asr32(ShortInt(ABytes[LPos + 1]), 7)) do
  begin
    System.Inc(LPos);
  end;
  Result := LPos;
end;

class function TDerInteger.IntValue(const ABytes: TCryptoLibByteArray; AStart, ASignExt: Int32): Int32;
var
  LLength, LPos, LVal: Int32;
begin
  LLength := System.Length(ABytes);
  LPos := Math.Max(AStart, LLength - 4);
  
  LVal := ShortInt(ABytes[LPos]) and ASignExt;
  System.Inc(LPos);
  while LPos < LLength do
  begin
    LVal := (LVal shl 8) or ABytes[LPos];
    System.Inc(LPos);
  end;
  Result := LVal;
end;

class function TDerInteger.LongValue(const ABytes: TCryptoLibByteArray; AStart, ASignExt: Int32): Int64;
var
  LLength, LPos: Int32;
  LVal: Int64;
begin
  LLength := System.Length(ABytes);
  LPos := Math.Max(AStart, LLength - 8);
  
  LVal := Int64(ShortInt(ABytes[LPos])) and ASignExt;
  System.Inc(LPos);
  while LPos < LLength do
  begin
    LVal := (LVal shl 8) or ABytes[LPos];
    System.Inc(LPos);
  end;
  Result := LVal;
end;

class function TDerInteger.GetEncodingLength(const AX: TBigInteger): Int32;
var
  LByteLength: Int32;
begin
  LByteLength := TBigIntegers.GetByteLength(AX);
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(TAsn1Tags.Integer, LByteLength);
end;

class function TDerInteger.ValueOf(AValue: Int64): IDerInteger;
begin
  if (AValue >= 0) and (AValue < Int64(System.Length(FSmallConstants))) then
    Result := FSmallConstants[Int32(AValue)]
  else
    Result := TDerInteger.Create(AValue);
end;

class function TDerInteger.GetInstance(const AObj: TObject): IDerInteger;
var
  LAsn1Obj: IAsn1Object;
  LConvertible: IAsn1Convertible;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  // If it's already IAsn1Object, forward directly
  if Supports(AObj, IAsn1Object, LAsn1Obj) then
  begin
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  // Handle IAsn1Convertible conversion
  if Supports(AObj, IAsn1Convertible, LConvertible) then
  begin
    LAsn1Obj := LConvertible.ToAsn1Object();
    Result := GetInstance(LAsn1Obj);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateFmt('illegal object in GetInstance: %s', [TPlatformUtilities.GetTypeName(AObj)]);
end;

class function TDerInteger.GetInstance(const AObj: IAsn1Object): IDerInteger;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if not Supports(AObj, IDerInteger, Result) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
end;

class function TDerInteger.GetInstance(const AObj: IAsn1Convertible): IDerInteger;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDerInteger, Result) then
    Exit;
  
  if Supports(AObj, IAsn1Object) then
    raise EArgumentCryptoLibException.Create('illegal object in GetInstance');
    
  Result := GetInstance(AObj.ToAsn1Object());
end;

class function TDerInteger.GetInstance(const ABytes: TCryptoLibByteArray): IDerInteger;
var
  LObj: IAsn1Object;
begin
  if ABytes = nil then
  begin
    Result := nil;
    Exit;
  end;
  try
    LObj := TDerInteger.Meta.Instance.FromByteArray(ABytes);
    if not Supports(LObj, IDerInteger, Result) then
      raise EArgumentCryptoLibException.Create('failed to construct integer from byte[]');
  except
    on E: EIOCryptoLibException do
      raise EArgumentCryptoLibException.Create('failed to construct integer from byte[]: ' + E.Message);
  end;
end;

class function TDerInteger.GetInstance(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerInteger;
begin
  Result := TDerInteger.Meta.Instance.GetContextTagged(ATaggedObject, ADeclaredExplicit) as IDerInteger;
end;

class function TDerInteger.GetOptional(const AElement: IAsn1Encodable): IDerInteger;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');
  if Supports(AElement, IDerInteger, Result) then
    Exit;
  Result := nil;
end;

class function TDerInteger.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IDerInteger;
begin
  Result := TDerInteger.Meta.Instance.GetTagged(ATaggedObject, ADeclaredExplicit) as IDerInteger;
end;

function TDerInteger.GetValue(): TBigInteger;
begin
  Result := TBigInteger.Create(FBytes);
end;

function TDerInteger.GetPositiveValue(): TBigInteger;
begin
  Result := TBigInteger.Create(1, FBytes);
end;

function TDerInteger.HasValue(AX: Int32): Boolean;
var
  LIntVal: Int32;
begin
  if (System.Length(FBytes) - FStart) > 4 then
  begin
    Result := False;
    Exit;
  end;
  LIntVal := TDerInteger.IntValue(FBytes, FStart, SignExtSigned);
  Result := (LIntVal = AX);
end;

function TDerInteger.HasValue(AX: Int64): Boolean;
var
  LLongVal: Int64;
begin
  if (System.Length(FBytes) - FStart) > 8 then
  begin
    Result := False;
    Exit;
  end;
  LLongVal := TDerInteger.LongValue(FBytes, FStart, SignExtSigned);
  Result := (LLongVal = AX);
end;

function TDerInteger.HasValue(const AX: TBigInteger): Boolean;
var
  LIntValue: Int32;
  LValue: TBigInteger;
begin
  if not AX.IsInitialized then
  begin
    Result := False;
    Exit;
  end;
  // Fast check to avoid allocation
  LIntValue := TDerInteger.IntValue(FBytes, FStart, SignExtSigned);
  LValue := GetValue();
  Result := (LIntValue = AX.Int32Value) and LValue.Equals(AX);
end;

function TDerInteger.GetIntValueExact(): Int32;
var
  LCount: Int32;
begin
  LCount := System.Length(FBytes) - FStart;
  if LCount > 4 then
    raise EArithmeticCryptoLibException.Create('ASN.1 Integer out of int range');
  Result := TDerInteger.IntValue(FBytes, FStart, SignExtSigned);
end;

function TDerInteger.GetIntPositiveValueExact(): Int32;
var
  LCount: Int32;
begin
  LCount := System.Length(FBytes) - FStart;
  if (LCount > 4) or ((LCount = 4) and ((FBytes[FStart] and $80) <> 0)) then
    raise EArithmeticCryptoLibException.Create('ASN.1 Integer out of positive int range');
  Result := TDerInteger.IntValue(FBytes, FStart, SignExtUnsigned);
end;

function TDerInteger.GetLongValueExact(): Int64;
var
  LCount: Int32;
begin
  LCount := System.Length(FBytes) - FStart;
  if LCount > 8 then
    raise EArithmeticCryptoLibException.Create('ASN.1 Integer out of long range');
  Result := TDerInteger.LongValue(FBytes, FStart, SignExtSigned);
end;

function TDerInteger.TryGetIntValueExact(out AValue: Int32): Boolean;
var
  LCount: Int32;
begin
  LCount := System.Length(FBytes) - FStart;
  if LCount > 4 then
  begin
    AValue := 0;
    Result := False;
    Exit;
  end;
  AValue := TDerInteger.IntValue(FBytes, FStart, SignExtSigned);
  Result := True;
end;

function TDerInteger.TryGetIntPositiveValueExact(out AValue: Int32): Boolean;
var
  LCount: Int32;
begin
  LCount := System.Length(FBytes) - FStart;
  if (LCount > 4) or ((LCount = 4) and ((FBytes[FStart] and $80) <> 0)) then
  begin
    AValue := 0;
    Result := False;
    Exit;
  end;
  AValue := TDerInteger.IntValue(FBytes, FStart, SignExtUnsigned);
  Result := True;
end;

function TDerInteger.TryGetLongValueExact(out AValue: Int64): Boolean;
var
  LCount: Int32;
begin
  LCount := System.Length(FBytes) - FStart;
  if LCount > 8 then
  begin
    AValue := 0;
    Result := False;
    Exit;
  end;
  AValue := TDerInteger.LongValue(FBytes, FStart, SignExtSigned);
  Result := True;
end;

function TDerInteger.GetEncoding(AEncoding: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Integer, FBytes);
end;

function TDerInteger.GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
begin
  Result := TPrimitiveEncoding.Create(ATagClass, ATagNo, FBytes);
end;

function TDerInteger.GetEncodingDer(): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(TAsn1Tags.Universal, TAsn1Tags.Integer, FBytes);
end;

function TDerInteger.GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
begin
  Result := TPrimitiveDerEncoding.Create(ATagClass, ATagNo, FBytes);
end;

function TDerInteger.ToString(): String;
var
  LValue: TBigInteger;
begin
  LValue := GetValue();
  Result := LValue.ToString();
end;

{ TConstructedDLEncoding }

constructor TConstructedDLEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElements := AContentsElements;
  FContentsLength := TAsn1OutputStream.GetLengthOfContents(AContentsElements);
end;

procedure TConstructedDLEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(TAsn1Tags.Constructed or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  LAsn1Out.EncodeContents(FContentsElements);
end;

function TConstructedDLEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

{ TTaggedDLEncoding }

constructor TTaggedDLEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElement: IAsn1Encoding);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElement := AContentsElement;
  FContentsLength := AContentsElement.GetLength();
end;

procedure TTaggedDLEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(TAsn1Tags.Constructed or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  FContentsElement.Encode(AOut);
end;

function TTaggedDLEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

{ TConstructedDerEncoding }

constructor TConstructedDerEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElements: TCryptoLibGenericArray<IDerEncoding>);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsElements = nil then
    raise EArgumentNilCryptoLibException.Create('contentsElements');
  FContentsElements := AContentsElements;
  FContentsLength := TAsn1OutputStream.GetLengthOfContents(TCryptoLibGenericArray<IAsn1Encoding>(AContentsElements));
end;

function TConstructedDerEncoding.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LThat: IConstructedDerEncoding;
  I, LLength: Int32;
begin
  if not Supports(AOther, IConstructedDerEncoding, LThat) then
    raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');

  if FContentsLength <> LThat.ContentsLength then
  begin
    Result := FContentsLength - LThat.ContentsLength;
    Exit;
  end;

  LLength := Math.Min(System.Length(FContentsElements), System.Length(LThat.ContentsElements));
  for I := 0 to LLength - 1 do
  begin
    Result := FContentsElements[I].CompareTo(LThat.ContentsElements[I]);
    if Result <> 0 then
      Exit;
  end;

  Result := System.Length(FContentsElements) - System.Length(LThat.ContentsElements);
end;

procedure TConstructedDerEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(TAsn1Tags.Constructed or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  LAsn1Out.EncodeContents(TCryptoLibGenericArray<IAsn1Encoding>(FContentsElements));
end;

function TConstructedDerEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

function TConstructedDerEncoding.GetContentsLength(): Int32;
begin
  Result := FContentsLength;
end;

function TConstructedDerEncoding.GetContentsElements(): TCryptoLibGenericArray<IDerEncoding>;
begin
  Result := FContentsElements;
end;

{ TTaggedDerEncoding }

constructor TTaggedDerEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElement: IDerEncoding);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsElement = nil then
    raise EArgumentNilCryptoLibException.Create('contentsElement');
  FContentsElement := AContentsElement;
  FContentsLength := AContentsElement.GetLength();
end;

function TTaggedDerEncoding.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LThat: ITaggedDerEncoding;
begin
  if not Supports(AOther, ITaggedDerEncoding, LThat) then
    raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');

  if FContentsLength <> LThat.ContentsLength then
  begin
    Result := FContentsLength - LThat.ContentsLength;
    Exit;
  end;

  Result := FContentsElement.CompareTo(LThat.ContentsElement);
end;

procedure TTaggedDerEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(TAsn1Tags.Constructed or FTagClass, FTagNo);
  LAsn1Out.WriteDL(FContentsLength);
  FContentsElement.Encode(AOut);
end;

function TTaggedDerEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, FContentsLength);
end;

function TTaggedDerEncoding.GetContentsLength(): Int32;
begin
  Result := FContentsLength;
end;

function TTaggedDerEncoding.GetContentsElement(): IDerEncoding;
begin
  Result := FContentsElement;
end;

{ TConstructedILEncoding }

constructor TConstructedILEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElements: TCryptoLibGenericArray<IAsn1Encoding>);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElements := AContentsElements;
end;

procedure TConstructedILEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(TAsn1Tags.Constructed or FTagClass, FTagNo);
  LAsn1Out.WriteByte($80);
  LAsn1Out.EncodeContents(FContentsElements);
  LAsn1Out.WriteByte($00);
  LAsn1Out.WriteByte($00);
end;

function TConstructedILEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingIL(FTagNo, FContentsElements);
end;

{ TTaggedILEncoding }

constructor TTaggedILEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsElement: IAsn1Encoding);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsElement := AContentsElement;
end;

procedure TTaggedILEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(TAsn1Tags.Constructed or FTagClass, FTagNo);
  LAsn1Out.WriteByte($80);
  FContentsElement.Encode(AOut);
  LAsn1Out.WriteByte($00);
  LAsn1Out.WriteByte($00);
end;

function TTaggedILEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingIL(FTagNo, FContentsElement);
end;

{ TPrimitiveEncoding }

constructor TPrimitiveEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsOctets := AContentsOctets;
end;

procedure TPrimitiveEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 0 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets));
end;

function TPrimitiveEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

{ TPrimitiveDerEncoding }

constructor TPrimitiveDerEncoding.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsOctets = nil then
    raise EArgumentNilCryptoLibException.Create('contentsOctets');
  FContentsOctets := AContentsOctets;
end;

function TPrimitiveDerEncoding.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LThat: IPrimitiveDerEncoding;
  LSuffixed: IPrimitiveDerEncodingSuffixed;
  I, LLength: Int32;
  LThatOctets: TCryptoLibByteArray;
begin
  if Supports(AOther, IPrimitiveDerEncodingSuffixed, LSuffixed) then
  begin
    // Call the overridden method on the suffixed instance, passing Self
    Result := -LSuffixed.CompareLengthAndContents(Self as IDerEncoding);
    Exit;
  end;

  if not Supports(AOther, IPrimitiveDerEncoding, LThat) then
    raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');

  LThatOctets := LThat.ContentsOctets;
  LLength := System.Length(FContentsOctets);
  if LLength <> System.Length(LThatOctets) then
  begin
    Result := LLength - System.Length(LThatOctets);
    Exit;
  end;

  for I := 0 to LLength - 1 do
  begin
    if FContentsOctets[I] <> LThatOctets[I] then
    begin
      Result := Int32(FContentsOctets[I]) - Int32(LThatOctets[I]);
      Exit;
    end;
  end;

  Result := 0;
end;

procedure TPrimitiveDerEncoding.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 0 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets));
end;

function TPrimitiveDerEncoding.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

function TPrimitiveDerEncoding.GetContentsOctets(): TCryptoLibByteArray;
begin
  Result := FContentsOctets;
end;

{ TPrimitiveEncodingSuffixed }

constructor TPrimitiveEncodingSuffixed.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
  FContentsOctets := AContentsOctets;
  FContentsSuffix := AContentsSuffix;
end;

procedure TPrimitiveEncodingSuffixed.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 1 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets) - 1);
  LAsn1Out.WriteByte(FContentsSuffix);
end;

function TPrimitiveEncodingSuffixed.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

{ TPrimitiveDerEncodingSuffixed }

constructor TPrimitiveDerEncodingSuffixed.Create(ATagClass, ATagNo: Int32;
  const AContentsOctets: TCryptoLibByteArray; AContentsSuffix: Byte);
begin
  inherited Create(ATagClass, ATagNo);
  if AContentsOctets = nil then
    raise EArgumentNilCryptoLibException.Create('contentsOctets');
  if System.Length(AContentsOctets) = 0 then
    raise EArgumentCryptoLibException.Create('contentsOctets length must be > 0');
  FContentsOctets := AContentsOctets;
  FContentsSuffix := AContentsSuffix;
end;

function TPrimitiveDerEncodingSuffixed.CompareLengthAndContents(const AOther: IDerEncoding): Int32;
var
  LSuff: IPrimitiveDerEncodingSuffixed;
  LThat: IPrimitiveDerEncoding;
  LThatOctets: TCryptoLibByteArray;
  LLength: Int32;
begin
  if Supports(AOther, IPrimitiveDerEncodingSuffixed, LSuff) then
  begin
    Result := CompareSuffixed(FContentsOctets, FContentsSuffix,
      LSuff.ContentsOctets, LSuff.ContentsSuffix);
    Exit;
  end;

  if Supports(AOther, IPrimitiveDerEncoding, LThat) then
  begin
    LThatOctets := LThat.ContentsOctets;
    LLength := System.Length(LThatOctets);
    if LLength = 0 then
    begin
      Result := System.Length(FContentsOctets);
      Exit;
    end;

    Result := CompareSuffixed(FContentsOctets, FContentsSuffix,
      LThatOctets, LThatOctets[LLength - 1]);
    Exit;
  end;

  raise EInvalidOperationCryptoLibException.Create('Invalid type for comparison');
end;

class function TPrimitiveDerEncodingSuffixed.CompareSuffixed(const AOctetsA: TCryptoLibByteArray;
  ASuffixA: Byte; const AOctetsB: TCryptoLibByteArray; ASuffixB: Byte): Int32;
var
  LLength, I, LLast: Int32;
begin
  if (System.Length(AOctetsA) = 0) or (System.Length(AOctetsB) = 0) then
    raise EArgumentCryptoLibException.Create('Octets length must be > 0');

  LLength := System.Length(AOctetsA);
  if LLength <> System.Length(AOctetsB) then
  begin
    Result := LLength - System.Length(AOctetsB);
    Exit;
  end;

  LLast := LLength - 1;
  for I := 0 to LLast - 1 do
  begin
    if AOctetsA[I] <> AOctetsB[I] then
    begin
      Result := Int32(AOctetsA[I]) - Int32(AOctetsB[I]);
      Exit;
    end;
  end;

  Result := Int32(ASuffixA) - Int32(ASuffixB);
end;

procedure TPrimitiveDerEncodingSuffixed.Encode(const AOut: TStream);
var
  LAsn1Out: TAsn1OutputStream;
begin
  LAsn1Out := TAsn1OutputStream.ValidateAsn1OutputStream(AOut);
  LAsn1Out.WriteIdentifier(FTagClass, FTagNo);
  LAsn1Out.WriteDL(System.Length(FContentsOctets));
  if System.Length(FContentsOctets) > 1 then
    LAsn1Out.Write(FContentsOctets[0], System.Length(FContentsOctets) - 1);
  LAsn1Out.WriteByte(FContentsSuffix);
end;

function TPrimitiveDerEncodingSuffixed.GetLength(): Int32;
begin
  Result := TAsn1OutputStream.GetLengthOfEncodingDL(FTagNo, System.Length(FContentsOctets));
end;

function TPrimitiveDerEncodingSuffixed.GetContentsOctets(): TCryptoLibByteArray;
begin
  Result := FContentsOctets;
end;

function TPrimitiveDerEncodingSuffixed.GetContentsSuffix(): Byte;
begin
  Result := FContentsSuffix;
end;

{ TAsn1Type }

constructor TAsn1Type.Create(APlatformType: TClass);
begin
  inherited Create;
  FPlatformType := APlatformType;
end;

function TAsn1Type.GetPlatformType(): TClass;
begin
  Result := FPlatformType;
end;

{ TAsn1Tag }

constructor TAsn1Tag.Create(ATagClass, ATagNo: Int32);
begin
  inherited Create;
  FTagClass := ATagClass;
  FTagNo := ATagNo;
end;

class function TAsn1Tag.CreateTag(ATagClass, ATagNo: Int32): IAsn1Tag;
var
  LTag: TAsn1Tag;
begin
  LTag := TAsn1Tag.Create(ATagClass, ATagNo);
  if not Supports(LTag, IAsn1Tag, Result) then
    raise EInvalidOperationCryptoLibException.Create('failed to get IAsn1Tag interface');
end;

function TAsn1Tag.GetTagClass(): Int32;
begin
  Result := FTagClass;
end;

function TAsn1Tag.GetTagNo(): Int32;
begin
  Result := FTagNo;
end;

function TAsn1Tag.GetExplicitness(): Int32;
begin
  // TAsn1Tag doesn't have explicitness - return a default value
  // This method exists because IAsn1Tag interface may require it
  Result := 0;
end;

{ TAsn1UniversalType }

constructor TAsn1UniversalType.Create(APlatformType: TClass; ATagNo: Int32);
begin
  inherited Create(APlatformType);
  FTag := TAsn1Tag.CreateTag(TAsn1Tags.Universal, ATagNo);
end;

destructor TAsn1UniversalType.Destroy;
begin
  FTag := nil; // Release reference
  inherited Destroy();
end;

function TAsn1UniversalType.CheckedCast(const AAsn1Object: IAsn1Object): IAsn1Object;
var
  LObj: TAsn1Object;
begin
  if AAsn1Object = nil then
  begin
    Result := nil;
    Exit;
  end;

  LObj := AAsn1Object as TAsn1Object;
  // Check if the object is an instance of the platform type
  if (FPlatformType <> nil) and LObj.InheritsFrom(FPlatformType) then
    Result := AAsn1Object
  else
    raise EInvalidOperationCryptoLibException.CreateFmt('unexpected object: %s', [TPlatformUtilities.GetTypeName(LObj)]);
end;

function TAsn1UniversalType.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  raise EInvalidOperationCryptoLibException.Create('unexpected implicit primitive encoding');
end;

function TAsn1UniversalType.FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object;
begin
  raise EInvalidOperationCryptoLibException.Create('unexpected implicit constructed encoding');
end;

function TAsn1UniversalType.FromByteArray(const ABytes: TCryptoLibByteArray): IAsn1Object;
begin
  Result := CheckedCast(TAsn1Object.FromByteArray(ABytes));
end;

function TAsn1UniversalType.GetContextTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Object;
begin
  Result := CheckedCast(TAsn1Utilities.CheckContextTagClass(ATaggedObject).GetBaseUniversal(ADeclaredExplicit, Self));
end;

function TAsn1UniversalType.GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Object;
begin
  Result := CheckedCast(ATaggedObject.GetBaseUniversal(ADeclaredExplicit, Self));
end;

{ TAsn1UniversalTypes }

class function TAsn1UniversalTypes.Get(ATagNo: Int32): IAsn1UniversalType;
begin
  case ATagNo of
    TAsn1Tags.Boolean:
      Result := TDerBoolean.Meta.Instance;
    TAsn1Tags.Integer:
      Result := TDerInteger.Meta.Instance;
    TAsn1Tags.BitString:
      Result := TDerBitString.Meta.Instance;
    TAsn1Tags.OctetString:
      Result := TAsn1OctetString.Meta.Instance;
    TAsn1Tags.Null:
      Result := TAsn1Null.Meta.Instance;
    TAsn1Tags.ObjectIdentifier:
      Result := TDerObjectIdentifier.Meta.Instance;
    TAsn1Tags.ObjectDescriptor:
      Result := TAsn1ObjectDescriptor.Meta.Instance;
    TAsn1Tags.External:
      Result := TDerExternal.Meta.Instance;
    TAsn1Tags.Enumerated:
      Result := TDerEnumerated.Meta.Instance;
    TAsn1Tags.Utf8String:
      Result := TDerUtf8String.Meta.Instance;
    TAsn1Tags.RelativeOid:
      Result := TAsn1RelativeOid.Meta.Instance;
    TAsn1Tags.Sequence:
      Result := TAsn1Sequence.Meta.Instance;
    TAsn1Tags.&Set:
      Result := TAsn1Set.Meta.Instance;
    TAsn1Tags.NumericString:
      Result := TDerNumericString.Meta.Instance;
    TAsn1Tags.PrintableString:
      Result := TDerPrintableString.Meta.Instance;
    TAsn1Tags.T61String:
      Result := TDerT61String.Meta.Instance;
    TAsn1Tags.VideotexString:
      Result := TDerVideotexString.Meta.Instance;
    TAsn1Tags.IA5String:
      Result := TDerIA5String.Meta.Instance;
    TAsn1Tags.UtcTime:
      Result := TAsn1UtcTime.Meta.Instance;
    TAsn1Tags.GeneralizedTime:
      Result := TAsn1GeneralizedTime.Meta.Instance;
    TAsn1Tags.GraphicString:
      Result := TDerGraphicString.Meta.Instance;
    TAsn1Tags.VisibleString:
      Result := TDerVisibleString.Meta.Instance;
    TAsn1Tags.GeneralString:
      Result := TDerGeneralString.Meta.Instance;
    TAsn1Tags.UniversalString:
      Result := TDerUniversalString.Meta.Instance;
    TAsn1Tags.BmpString:
      Result := TDerBmpString.Meta.Instance;
  else
    Result := nil;
  end;
end;

{ TDerBoolean.Meta }

constructor TDerBoolean.Meta.Create;
begin
  inherited Create(TDerBoolean, TAsn1Tags.Boolean);
end;

class function TDerBoolean.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerBoolean.Meta.Create;
  Result := FInstance;
end;

function TDerBoolean.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerBoolean.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerInteger.Meta }

constructor TDerInteger.Meta.Create;
begin
  inherited Create(TDerInteger, TAsn1Tags.Integer);
end;

class function TDerInteger.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerInteger.Meta.Create;
  Result := FInstance;
end;

function TDerInteger.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerInteger.CreatePrimitive(AOctetString.GetOctets());
end;

{ TAsn1Null.Meta }

constructor TAsn1Null.Meta.Create;
begin
  inherited Create(TAsn1Null, TAsn1Tags.Null);
end;

class function TAsn1Null.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1Null.Meta.Create;
  Result := FInstance;
end;

function TAsn1Null.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  TAsn1Null.CheckContentsLength(AOctetString.GetOctetsLength());
  Result := TAsn1Null.CreatePrimitive();
end;

{ TDerObjectIdentifier.Meta }

constructor TDerObjectIdentifier.Meta.Create;
begin
  inherited Create(TDerObjectIdentifier, TAsn1Tags.ObjectIdentifier);
end;

class function TDerObjectIdentifier.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerObjectIdentifier.Meta.Create;
  Result := FInstance;
end;

function TDerObjectIdentifier.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerObjectIdentifier.CreatePrimitive(AOctetString.GetOctets(), False);
end;

{ TDerEnumerated.Meta }

constructor TDerEnumerated.Meta.Create;
begin
  inherited Create(TDerEnumerated, TAsn1Tags.Enumerated);
end;

class function TDerEnumerated.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerEnumerated.Meta.Create;
  Result := FInstance;
end;

function TDerEnumerated.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerEnumerated.CreatePrimitive(AOctetString.GetOctets(), False);
end;

{ TAsn1RelativeOid.Meta }

constructor TAsn1RelativeOid.Meta.Create;
begin
  inherited Create(TAsn1RelativeOid, TAsn1Tags.RelativeOid);
end;

class function TAsn1RelativeOid.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1RelativeOid.Meta.Create;
  Result := FInstance;
end;

function TAsn1RelativeOid.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TAsn1RelativeOid.CreatePrimitive(AOctetString.GetOctets(), False);
end;

{ TAsn1OctetString.Meta }

constructor TAsn1OctetString.Meta.Create;
begin
  inherited Create(TAsn1OctetString, TAsn1Tags.OctetString);
end;

class function TAsn1OctetString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1OctetString.Meta.Create;
  Result := FInstance;
end;

function TAsn1OctetString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := AOctetString as IAsn1Object;
end;

{ TAsn1Sequence.Meta }

constructor TAsn1Sequence.Meta.Create;
begin
  inherited Create(TAsn1Sequence, TAsn1Tags.Sequence);
end;

class function TAsn1Sequence.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1Sequence.Meta.Create;
  Result := FInstance;
end;

function TAsn1Sequence.Meta.FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object;
begin
  Result := ASequence as IAsn1Object;
end;

{ TAsn1Set.Meta }

constructor TAsn1Set.Meta.Create;
begin
  inherited Create(TAsn1Set, TAsn1Tags.&Set);
end;

class function TAsn1Set.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1Set.Meta.Create;
  Result := FInstance;
end;

function TAsn1Set.Meta.FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object;
begin
  // For Set, we need to convert the sequence to a set
  // Set can be constructed from a Sequence
  Result := ASequence.ToAsn1Set();
end;

{ TAsn1Sequence.TAsn1SequenceParserImpl }

constructor TAsn1Sequence.TAsn1SequenceParserImpl.Create(const AOuter: IAsn1Sequence);
begin
  inherited Create();
  FOuter := AOuter;
  FIndex := 0;
end;

function TAsn1Sequence.TAsn1SequenceParserImpl.ReadObject(): IAsn1Convertible;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LObj: IAsn1Encodable;
  LSequence: IAsn1Sequence;
  LSet: IAsn1Set;
  LOctetString: IAsn1OctetString;
begin
  LElements := FOuter.Elements;
  if FIndex >= System.Length(LElements) then
  begin
    Result := nil;
    Exit;
  end;

  LObj := LElements[FIndex];
  Inc(FIndex);

  if Supports(LObj, IAsn1Sequence, LSequence) then
    Result := LSequence.Parser
  else if Supports(LObj, IAsn1Set, LSet) then
    Result := LSet.Parser
  else if Supports(LObj, IAsn1OctetString, LOctetString) then
    // NB: Asn1OctetString implements Asn1OctetStringParser directly
    Result := LOctetString as IAsn1Convertible
  else
    Result := LObj as IAsn1Convertible;
end;

function TAsn1Sequence.TAsn1SequenceParserImpl.ToAsn1Object(): IAsn1Object;
begin
  Result := FOuter;
end;

{ TAsn1Set.TAsn1SetParserImpl }

constructor TAsn1Set.TAsn1SetParserImpl.Create(const AOuter: TAsn1Set);
begin
  inherited Create();
  FOuter := AOuter;
  FIndex := 0;
end;

function TAsn1Set.TAsn1SetParserImpl.ReadObject(): IAsn1Convertible;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LObj: IAsn1Encodable;
  LSequence: IAsn1Sequence;
  LSet: IAsn1Set;
  LOctetString: IAsn1OctetString;
begin
  LElements := FOuter.FElements;
  if FIndex >= System.Length(LElements) then
  begin
    Result := nil;
    Exit;
  end;

  LObj := LElements[FIndex];
  Inc(FIndex);

  if Supports(LObj, IAsn1Sequence, LSequence) then
    Result := LSequence.Parser
  else if Supports(LObj, IAsn1Set, LSet) then
    Result := LSet.Parser
  else if Supports(LObj, IAsn1OctetString, LOctetString) then
    // NB: Asn1OctetString implements Asn1OctetStringParser directly
    Result := LOctetString as IAsn1Convertible
  else
    Result := LObj as IAsn1Convertible;
end;

function TAsn1Set.TAsn1SetParserImpl.ToAsn1Object(): IAsn1Object;
begin
  Result := FOuter;
end;

{ TDerBitString }

class constructor TDerBitString.Create;
begin
  System.SetLength(FEmptyOctetsContents, 1);
  FEmptyOctetsContents[0] := $00;
end;

class function TDerBitString.GetEmptyOctetsContents: TCryptoLibByteArray;
begin
  Result := FEmptyOctetsContents;
end;

{ TDerBitString.Meta }

constructor TDerBitString.Meta.Create;
begin
  inherited Create(TDerBitString, TAsn1Tags.BitString);
end;

class function TDerBitString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerBitString.Meta.Create;
  Result := FInstance;
end;

function TDerBitString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerBitString.CreatePrimitive(AOctetString.GetOctets());
end;

function TDerBitString.Meta.FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object;
var
  LBitString: IDerBitString;
begin
  LBitString := ASequence.ToAsn1BitString();
  Result := LBitString as IAsn1Object;
end;

{ TAsn1GeneralizedTime.Meta }

constructor TAsn1GeneralizedTime.Meta.Create;
begin
  inherited Create(TAsn1GeneralizedTime, TAsn1Tags.GeneralizedTime);
end;

class function TAsn1GeneralizedTime.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1GeneralizedTime.Meta.Create;
  Result := FInstance;
end;

function TAsn1GeneralizedTime.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TAsn1GeneralizedTime.CreatePrimitive(AOctetString.GetOctets());
end;

{ TAsn1UtcTime.Meta }

constructor TAsn1UtcTime.Meta.Create;
begin
  inherited Create(TAsn1UtcTime, TAsn1Tags.UtcTime);
end;

class function TAsn1UtcTime.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1UtcTime.Meta.Create;
  Result := FInstance;
end;

function TAsn1UtcTime.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TAsn1UtcTime.CreatePrimitive(AOctetString.GetOctets());
end;

{ TAsn1ObjectDescriptor.Meta }

constructor TAsn1ObjectDescriptor.Meta.Create;
begin
  inherited Create(TAsn1ObjectDescriptor, TAsn1Tags.ObjectDescriptor);
end;

class function TAsn1ObjectDescriptor.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TAsn1ObjectDescriptor.Meta.Create;
  Result := FInstance;
end;

function TAsn1ObjectDescriptor.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TAsn1ObjectDescriptor.CreatePrimitive(AOctetString.GetOctets());
end;

function TAsn1ObjectDescriptor.Meta.FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object;
var
  LGraphicString: IAsn1Object;
begin
  LGraphicString := TDerGraphicString.Meta.Instance.FromImplicitConstructed(ASequence);
  Result := TAsn1ObjectDescriptor.Create(LGraphicString);
end;

{ TDerExternal.Meta }

constructor TDerExternal.Meta.Create;
begin
  inherited Create(TDerExternal, TAsn1Tags.External);
end;

class function TDerExternal.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerExternal.Meta.Create;
  Result := FInstance;
end;

function TDerExternal.Meta.FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object;
var
  LExternal: IDerExternal;
begin
  LExternal := ASequence.ToAsn1External();
  Result := LExternal as IAsn1Object;
end;

{ TDerUtf8String.Meta }

constructor TDerUtf8String.Meta.Create;
begin
  inherited Create(TDerUtf8String, TAsn1Tags.Utf8String);
end;

class function TDerUtf8String.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerUtf8String.Meta.Create;
  Result := FInstance;
end;

function TDerUtf8String.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerUtf8String.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerNumericString.Meta }

constructor TDerNumericString.Meta.Create;
begin
  inherited Create(TDerNumericString, TAsn1Tags.NumericString);
end;

class function TDerNumericString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerNumericString.Meta.Create;
  Result := FInstance;
end;

function TDerNumericString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerNumericString.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerPrintableString.Meta }

constructor TDerPrintableString.Meta.Create;
begin
  inherited Create(TDerPrintableString, TAsn1Tags.PrintableString);
end;

class function TDerPrintableString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerPrintableString.Meta.Create;
  Result := FInstance;
end;

function TDerPrintableString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerPrintableString.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerT61String.Meta }

constructor TDerT61String.Meta.Create;
begin
  inherited Create(TDerT61String, TAsn1Tags.T61String);
end;

class function TDerT61String.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerT61String.Meta.Create;
  Result := FInstance;
end;

function TDerT61String.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerT61String.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerVideotexString.Meta }

constructor TDerVideotexString.Meta.Create;
begin
  inherited Create(TDerVideotexString, TAsn1Tags.VideotexString);
end;

class function TDerVideotexString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerVideotexString.Meta.Create;
  Result := FInstance;
end;

function TDerVideotexString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerVideotexString.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerIA5String.Meta }

constructor TDerIA5String.Meta.Create;
begin
  inherited Create(TDerIA5String, TAsn1Tags.IA5String);
end;

class function TDerIA5String.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerIA5String.Meta.Create;
  Result := FInstance;
end;

function TDerIA5String.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerIA5String.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerGraphicString.Meta }

constructor TDerGraphicString.Meta.Create;
begin
  inherited Create(TDerGraphicString, TAsn1Tags.GraphicString);
end;

class function TDerGraphicString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerGraphicString.Meta.Create;
  Result := FInstance;
end;

function TDerGraphicString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerGraphicString.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerVisibleString.Meta }

constructor TDerVisibleString.Meta.Create;
begin
  inherited Create(TDerVisibleString, TAsn1Tags.VisibleString);
end;

class function TDerVisibleString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerVisibleString.Meta.Create;
  Result := FInstance;
end;

function TDerVisibleString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerVisibleString.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerGeneralString.Meta }

constructor TDerGeneralString.Meta.Create;
begin
  inherited Create(TDerGeneralString, TAsn1Tags.GeneralString);
end;

class function TDerGeneralString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerGeneralString.Meta.Create;
  Result := FInstance;
end;

function TDerGeneralString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerGeneralString.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerUniversalString.Meta }

constructor TDerUniversalString.Meta.Create;
begin
  inherited Create(TDerUniversalString, TAsn1Tags.UniversalString);
end;

class function TDerUniversalString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerUniversalString.Meta.Create;
  Result := FInstance;
end;

function TDerUniversalString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerUniversalString.CreatePrimitive(AOctetString.GetOctets());
end;

{ TDerBmpString.Meta }

constructor TDerBmpString.Meta.Create;
begin
  inherited Create(TDerBmpString, TAsn1Tags.BmpString);
end;

class function TDerBmpString.Meta.GetInstance: IAsn1UniversalType;
begin
  if FInstance = nil then
    FInstance := TDerBmpString.Meta.Create;
  Result := FInstance;
end;

function TDerBmpString.Meta.FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
begin
  Result := TDerBmpString.CreatePrimitive(AOctetString.GetOctets());
end;

end.

