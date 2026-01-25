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

unit ClpIAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpBigInteger;

type
  IAsn1Object = interface;
  IAsn1Sequence = interface;
  IAsn1UniversalType = interface;
  IAsn1Set = interface;

  /// <summary>
  /// Interface for ASN.1 encoding operations.
  /// </summary>
  IAsn1Encoding = interface(IInterface)
    ['{C4D5E6F7-8901-2345-6789-ABCDEF012345}']

    /// <summary>
    /// Encode to the given stream (must be a TAsn1OutputStream).
    /// </summary>
    procedure Encode(const AOut: TStream);

    /// <summary>
    /// Get the length of the encoded data.
    /// </summary>
    function GetLength(): Int32;
  end;

  /// <summary>
  /// Interface for ASN.1 convertible objects.
  /// </summary>
  IAsn1Convertible = interface(IInterface)
    ['{13104D9E-9DF1-4CCE-B48C-1ACC2AC362B1}']

    function ToAsn1Object(): IAsn1Object;
  end;

  /// <summary>
  /// Interface for ASN.1 encodable objects.
  /// </summary>
  IAsn1Encodable = interface(IAsn1Convertible)
    ['{E6F78901-2345-6789-ABCD-EF0123456789}']

    procedure EncodeTo(const AOutput: TStream); overload;
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); overload;
    function GetEncoded(): TCryptoLibByteArray; overload;
    function GetEncoded(const AEncoding: String): TCryptoLibByteArray; overload;
    function GetDerEncoded(): TCryptoLibByteArray;
    function Equals(const AObj: IAsn1Convertible): Boolean; overload;
    function GetHashCode(): {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
  end;

  /// <summary>
  /// Interface for DER encoding.
  /// </summary>
  IDerEncoding = interface(IAsn1Encoding)
    ['{3456789A-BCDE-F012-3456-789ABCDEF012}']

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

    property TagClass: Int32 read GetTagClass;
    property TagNo: Int32 read GetTagNo;
  end;

  /// <summary>
  /// Interface for constructed DER encoding.
  /// </summary>
  IConstructedDerEncoding = interface(IDerEncoding)
    ['{E1F2A3B4-C5D6-E7F8-9A0B-1C2D3E4F5A6B}']

    /// <summary>
    /// Get the contents length.
    /// </summary>
    function GetContentsLength(): Int32;
    /// <summary>
    /// Get the contents elements.
    /// </summary>
    function GetContentsElements(): TCryptoLibGenericArray<IDerEncoding>;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsLength: Int32 read GetContentsLength;
    property ContentsElements: TCryptoLibGenericArray<IDerEncoding> read GetContentsElements;
  end;

  /// <summary>
  /// Interface for tagged DER encoding.
  /// </summary>
  ITaggedDerEncoding = interface(IDerEncoding)
    ['{F2A3B4C5-D6E7-F8A9-0B1C-2D3E4F5A6B7C}']

    /// <summary>
    /// Get the contents length.
    /// </summary>
    function GetContentsLength(): Int32;
    /// <summary>
    /// Get the contents element.
    /// </summary>
    function GetContentsElement(): IDerEncoding;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsLength: Int32 read GetContentsLength;
    property ContentsElement: IDerEncoding read GetContentsElement;
  end;

  /// <summary>
  /// Interface for primitive DER encoding.
  /// </summary>
  IPrimitiveDerEncoding = interface(IDerEncoding)
    ['{A3B4C5D6-E7F8-A9B0-1C2D-3E4F5A6B7C8D}']

    /// <summary>
    /// Get the contents octets.
    /// </summary>
    function GetContentsOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsOctets: TCryptoLibByteArray read GetContentsOctets;
  end;

  /// <summary>
  /// Interface for primitive DER encoding with suffix.
  /// </summary>
  IPrimitiveDerEncodingSuffixed = interface(IPrimitiveDerEncoding)
    ['{B4C5D6E7-F8A9-B0C1-2D3E-4F5A6B7C8D9E}']

    /// <summary>
    /// Get the contents suffix.
    /// </summary>
    function GetContentsSuffix(): Byte;
    /// <summary>
    /// Compare length and contents with another encoding.
    /// </summary>
    function CompareLengthAndContents(const AOther: IDerEncoding): Int32;

    property ContentsSuffix: Byte read GetContentsSuffix;
  end;

  /// <summary>
  /// Interface for ASN.1 objects.
  /// </summary>
  IAsn1Object = interface(IAsn1Encodable)
    ['{F7890123-4567-89AB-CDEF-0123456789AB}']

    procedure EncodeTo(const AOutput: TStream); overload;
    procedure EncodeTo(const AOutput: TStream; const AEncoding: String); overload;
    function GetEncoded(const AEncoding: String; APreAlloc, APostAlloc: Int32): TCryptoLibByteArray; overload;
    function Equals(const AOther: IAsn1Object): Boolean; overload;
    function Asn1Equals(const AAsn1Object: IAsn1Object): Boolean;
    function Asn1GetHashCode(): Int32;
    function CallAsn1Equals(const AObj: IAsn1Object): Boolean;
    function CallAsn1GetHashCode(): Int32;
    /// <summary>
    /// Get string representation of the object.
    /// </summary>
    function ToString(): String;
    /// <summary>
    /// Get encoding for the specified encoding type.
    /// </summary>
    function GetEncoding(AEncoding: Int32): IAsn1Encoding;
    /// <summary>
    /// Get encoding for the specified encoding type with implicit tagging.
    /// </summary>
    function GetEncodingImplicit(AEncoding, ATagClass, ATagNo: Int32): IAsn1Encoding;
    /// <summary>
    /// Get DER encoding.
    /// </summary>
    function GetEncodingDer(): IDerEncoding;
    /// <summary>
    /// Get DER encoding with implicit tagging.
    /// </summary>
    function GetEncodingDerImplicit(ATagClass, ATagNo: Int32): IDerEncoding;
  end;

  /// <summary>
  /// Interface for ASN.1 bit string parsers.
  /// </summary>
  IAsn1BitStringParser = interface(IAsn1Convertible)
    ['{A2B3C4D5-E6F7-8901-2345-6789ABCDEF01}']

    /// <summary>
    /// Return a stream representing the contents of the BIT STRING.
    /// </summary>
    function GetBitStream(): TStream;

    /// <summary>
    /// Return a stream representing the contents of the BIT STRING, where the content is
    /// expected to be octet-aligned.
    /// </summary>
    function GetOctetStream(): TStream;

    /// <summary>
    /// Return the number of pad bits in the final byte.
    /// </summary>
    function GetPadBits(): Int32;
    property PadBits: Int32 read GetPadBits;
  end;

  /// <summary>
  /// Interface for ASN.1 octet string parsers.
  /// </summary>
  IAsn1OctetStringParser = interface(IAsn1Convertible)
    ['{B3C4D5E6-F789-0123-4567-89ABCDEF0123}']

    /// <summary>
    /// Return the content of the OCTET STRING as a stream.
    /// </summary>
    function GetOctetStream(): TStream;
  end;

  /// <summary>
  /// Interface for BER octet string parsers.
  /// </summary>
  IBerOctetStringParser = interface(IAsn1OctetStringParser)
    ['{C4D5E6F7-089A-1234-5678-9ABCDEF01234}']
  end;

  /// <summary>
  /// Interface for BER bit string parsers.
  /// </summary>
  IBerBitStringParser = interface(IAsn1BitStringParser)
    ['{D5E6F789-01AB-2345-6789-ABCDEF012345}']
  end;

  /// <summary>
  /// Interface for ASN.1 octet string objects.
  /// </summary>
  IAsn1OctetString = interface(IAsn1Object)
    ['{7F7FE981-DD88-4076-8A99-F24DA1005475}']

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Get the octets length.
    /// </summary>
    function GetOctetsLength(): Int32;
  end;

  /// <summary>
  /// Interface for DER octet string objects.
  /// </summary>
  IDerOctetString = interface(IAsn1OctetString)
    ['{0FFF8858-026C-49B5-A600-7F746FE6BCF7}']
  end;

  /// <summary>
  /// Interface for BER octet string objects.
  /// </summary>
  IBerOctetString = interface(IDerOctetString)
    ['{B9D96DA7-623C-491C-9304-7B67A6DBCFA6}']
  end;

  /// <summary>
  /// Interface for ASN.1 string objects (basic interface for DER string objects).
  /// </summary>
  IAsn1String = interface(IInterface)
    ['{E1F2A3B4-C5D6-E7F8-9A0B-1C2D3E4F5A6B}']

    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String;
  end;

  /// <summary>
  /// Interface for DER string base objects.
  /// </summary>
  IDerStringBase = interface(IAsn1Object)
    ['{710E6D65-28DE-4BFE-9C62-3CFC0E909DD9}']

    /// <summary>
    /// Get the string representation.
    /// </summary>
    function GetString(): String;
    /// <summary>
    /// Get the contents.
    /// </summary>
    function GetContents(): TCryptoLibByteArray;
    property Contents: TCryptoLibByteArray read GetContents;
  end;

  /// <summary>
  /// Interface for DER BMP string objects.
  /// </summary>
  IDerBmpString = interface(IDerStringBase)
    ['{8BC8ED8F-DE72-5E45-BF26-AF16A7F7E8C8}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;
  end;

  /// <summary>
  /// Interface for DER UTF8 string objects.
  /// </summary>
  IDerUtf8String = interface(IDerStringBase)
    ['{C4ACD432-807D-4A27-B3FC-0694000EB995}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;
  end;

  /// <summary>
  /// Interface for DER Numeric string objects.
  /// </summary>
  IDerNumericString = interface(IDerStringBase)
    ['{58BB62CA-16C5-4696-AC0B-E83628182740}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER Printable string objects.
  /// </summary>
  IDerPrintableString = interface(IDerStringBase)
    ['{119C220A-2672-48E3-A24A-11128B5F599B}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER T61 string objects.
  /// </summary>
  IDerT61String = interface(IDerStringBase)
    ['{A3B8C316-F349-4A5A-96CB-4655581A0308}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER Videotex string objects.
  /// </summary>
  IDerVideotexString = interface(IDerStringBase)
    ['{9484AEC5-5667-4C14-8441-4447B0B29F1B}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER IA5 string objects.
  /// </summary>
  IDerIA5String = interface(IDerStringBase)
    ['{F7BAC857-74F7-4660-95E1-F849B5D77F6C}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER General string objects.
  /// </summary>
  IDerGeneralString = interface(IDerStringBase)
    ['{E1C5097C-2FA1-4236-85D9-30784E6AA46D}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER Graphic string objects.
  /// </summary>
  IDerGraphicString = interface(IDerStringBase)
    ['{649B8C31-F349-4A5A-96CB-4655581A0309}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER Visible string objects.
  /// </summary>
  IDerVisibleString = interface(IDerStringBase)
    ['{0540C649-B50B-45DA-9FC9-1248BD3F73F1}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for DER Universal string objects.
  /// </summary>
  IDerUniversalString = interface(IDerStringBase)
    ['{60EC8C9A-B672-44E4-9C5B-B4022D937002}']

    /// <summary>
    /// Get the string value.
    /// </summary>
    function GetString(): String;

    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for ASN.1 UTC Time object.
  /// </summary>
  IAsn1UtcTime = interface(IAsn1Object)
    ['{B1C2D3E4-F5A6-7890-BCDE-F12345678901}']

    function GetTimeString: String;
    function GetTwoDigitYearMax: Int32;
    function GetContents(AEncoding: Int32): TCryptoLibByteArray;

    function ToDateTime: TDateTime; overload;
    function ToDateTime(twoDigitYearMax: Int32): TDateTime; overload;
    /// <summary>Return an adjusted date in the range of 1950 - 2049.</summary>
    function ToAdjustedDateTime: TDateTime; deprecated 'Use ToDateTime(2049) instead';

    property TimeString: String read GetTimeString;
    property TwoDigitYearMax: Int32 read GetTwoDigitYearMax;
  end;

  /// <summary>
  /// Interface for ASN.1 Generalized Time object.
  /// </summary>
  IAsn1GeneralizedTime = interface(IAsn1Object)
    ['{D3E4F5A6-B7C8-9012-DEF0-234567890123}']

    function GetTimeString: String;
    function GetContents(AEncoding: Int32): TCryptoLibByteArray;

    function ToDateTime: TDateTime;

    property TimeString: String read GetTimeString;
  end;

  /// <summary>
  /// Interface for DER UTC time objects.
  /// </summary>
  IDerUtcTime = interface(IAsn1UtcTime)
    ['{656789AB-CDEF-0123-4567-89ABCDEF0124}']
  end;

  /// <summary>
  /// Interface for DER generalized time objects.
  /// </summary>
  IDerGeneralizedTime = interface(IAsn1GeneralizedTime)
    ['{756789AB-CDEF-0123-4567-89ABCDEF0125}']
  end;

  /// <summary>
  /// Interface for DER bit string objects.
  /// </summary>
  IDerBitString = interface(IDerStringBase)
    ['{2EBCCC24-BF14-4EB1-BADA-C521439682BE}']

    /// <summary>
    /// Get the pad bits.
    /// </summary>
    function GetPadBits(): Int32;
    /// <summary>
    /// Get the contents (contents format: [padBits, data...]).
    /// </summary>
    function GetContents(): TCryptoLibByteArray;
    /// <summary>
    /// Get the octets.
    /// </summary>
    function GetOctets(): TCryptoLibByteArray;
    /// <summary>
    /// Get the bytes.
    /// </summary>
    function GetBytes(): TCryptoLibByteArray;
    /// <summary>
    /// Get the bytes length.
    /// </summary>
    function GetBytesLength(): Int32;
    /// <summary>
    /// Check if octet aligned.
    /// </summary>
    function IsOctetAligned(): Boolean;
    /// <summary>
    /// Get the Int32 value.
    /// </summary>
    function GetInt32Value(): Int32;
    /// <summary>
    /// Get the bit stream.
    /// </summary>
    function GetBitStream(): TStream;
    /// <summary>
    /// Get the octet stream.
    /// </summary>
    function GetOctetStream(): TStream;
    /// <summary>
    /// Get the parser.
    /// </summary>
    function GetParser(): IAsn1BitStringParser;

    property PadBits: Int32 read GetPadBits;
    property Contents: TCryptoLibByteArray read GetContents;
    property Int32Value: Int32 read GetInt32Value;
    property Parser: IAsn1BitStringParser read GetParser;
  end;

  /// <summary>
  /// Interface for DL bit string objects.
  /// </summary>
  IDLBitString = interface(IDerBitString)
    ['{8BC8ED8F-DE72-5E45-BF26-AF16A7F7E8C8}']
  end;

  /// <summary>
  /// Interface for BER bit string objects.
  /// </summary>
  IBerBitString = interface(IDerBitString)
    ['{6AB7DC7E-CD61-4D34-AE15-99E036688C77}']
  end;

  /// <summary>
  /// Interface for ASN.1 tagged object parsers.
  /// </summary>
  IAsn1TaggedObjectParser = interface(IAsn1Convertible)
    ['{23456789-ABCD-EF01-2345-6789ABCDEF01}']

    /// <summary>
    /// Get the tag class.
    /// </summary>
    function GetTagClass(): Int32;
    /// <summary>
    /// Get the tag number.
    /// </summary>
    function GetTagNo(): Int32;
    /// <summary>
    /// Check if this has a context tag.
    /// </summary>
    function HasContextTag(ATagNo: Int32): Boolean;
    /// <summary>
    /// Check if this has the specified tag.
    /// </summary>
    function HasTag(ATagClass, ATagNo: Int32): Boolean;
    /// <summary>
    /// Parse a base universal object.
    /// </summary>
    function ParseBaseUniversal(ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible;
    /// <summary>
    /// Parse an explicit base object.
    /// </summary>
    function ParseExplicitBaseObject(): IAsn1Convertible;
    /// <summary>
    /// Parse an explicit base tagged object.
    /// </summary>
    function ParseExplicitBaseTagged(): IAsn1TaggedObjectParser;
    /// <summary>
    /// Parse an implicit base tagged object.
    /// </summary>
    function ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser;

    property TagClass: Int32 read GetTagClass;
    property TagNo: Int32 read GetTagNo;
  end;

  /// <summary>
  /// Interface for ASN.1 tagged objects.
  /// </summary>
  IAsn1TaggedObject = interface(IAsn1Object)
    ['{2EBA68BE-CEC6-4030-BB9C-E8310C9B7D5F}']

    function GetTagNo(): Int32;
    function GetTagClass(): Int32;
    function GetExplicitness(): Int32;

    property TagNo: Int32 read GetTagNo;
    property TagClass: Int32 read GetTagClass;
    property Explicitness: Int32 read GetExplicitness;

    function HasContextTag(): Boolean; overload;
    function HasContextTag(ATagNo: Int32): Boolean; overload;
    function HasTag(ATagClass, ATagNo: Int32): Boolean;
    function HasTagClass(ATagClass: Int32): Boolean;
    function IsExplicit(): Boolean;
    function IsParsed(): Boolean;
    function GetObject(): IAsn1Object;
    function GetObjectParser(ATag: Int32; AIsExplicit: Boolean): IAsn1Convertible;
    function ToString(): String;

    /// <summary>
    /// Get the base encodable object
    /// </summary>
    function GetBaseObject(): IAsn1Encodable;
    /// <summary>
    /// Get the explicit base encodable object
    /// </summary>
    function GetExplicitBaseObject(): IAsn1Encodable;
    /// <summary>
    /// Get the explicit base tagged object
    /// </summary>
    function GetExplicitBaseTagged(): IAsn1TaggedObject;
    /// <summary>
    /// Get the implicit base tagged object
    /// </summary>
    function GetImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObject;
    /// <summary>
    /// Get base universal object
    /// </summary>
    function GetBaseUniversal(ADeclaredExplicit: Boolean; ATagNo: Int32): IAsn1Object; overload;
    /// <summary>
    /// Get base universal object with universal type.
    /// </summary>
    function GetBaseUniversal(ADeclaredExplicit: Boolean; const AUniversalType: IAsn1UniversalType): IAsn1Object; overload;

    // Methods from IAsn1TaggedObjectParser (since TAsn1TaggedObject implements both interfaces)
    /// <summary>
    /// Parse a base universal object
    /// </summary>
    function ParseBaseUniversal(ADeclaredExplicit: Boolean; ABaseTagNo: Int32): IAsn1Convertible;
    /// <summary>
    /// Parse an explicit base object
    /// </summary>
    function ParseExplicitBaseObject(): IAsn1Convertible;
    /// <summary>
    /// Parse an explicit base tagged object
    /// </summary>
    function ParseExplicitBaseTagged(): IAsn1TaggedObjectParser;
    /// <summary>
    /// Parse an implicit base tagged object
    /// </summary>
    function ParseImplicitBaseTagged(ABaseTagClass, ABaseTagNo: Int32): IAsn1TaggedObjectParser;
  end;

   /// <summary>
  /// Interface for DER tagged objects.
  /// </summary>
  IDerTaggedObject = interface(IAsn1TaggedObject)
    ['{CC77CFAB-8FCF-43E6-8FE4-95EFD99B9731}']
  end;

  /// <summary>
  /// Interface for DL tagged object objects.
  /// </summary>
  IDLTaggedObject = interface(IDerTaggedObject)
    ['{8BC8ED8F-DE72-5E45-BF26-AF16A7F7E8C8}']
  end;

   /// <summary>
  /// Interface for ASN.1 encodable vector.
  /// </summary>
  IAsn1EncodableVector = interface(IInterface)
    ['{A78E22EB-DB67-472E-A55F-CD710BCBDBFA}']

    function GetCount(): Int32;
    function GetItem(AIndex: Int32): IAsn1Encodable;

    procedure Add(const AElement: IAsn1Encodable); overload;
    procedure Add(const AElement1, AElement2: IAsn1Encodable); overload;
    procedure Add(const AObjs: array of IAsn1Encodable); overload;
    procedure AddOptional(const AElement: IAsn1Encodable); overload;
    procedure AddOptional(const AElement1, AElement2: IAsn1Encodable); overload;
    procedure AddOptional(const AElements: array of IAsn1Encodable); overload;
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    procedure AddOptionalTagged(AIsExplicit: Boolean; ATagClass, ATagNo: Int32;
      const AObj: IAsn1Encodable); overload;
    procedure AddAll(const AE: TCryptoLibGenericArray<IAsn1Encodable>); overload;
    procedure AddAll(const AOther: IAsn1EncodableVector); overload;

    function CopyElements(): TCryptoLibGenericArray<IAsn1Encodable>;
    function TakeElements(): TCryptoLibGenericArray<IAsn1Encodable>;

    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Count: Int32 read GetCount;
  end;

  /// <summary>
  /// Interface for ASN.1 stream parsers.
  /// </summary>
  IAsn1StreamParser = interface(IInterface)
    ['{D5E6F789-0123-4567-89AB-CDEF01234567}']

    /// <summary>
    /// Read the next object from the stream.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
    /// <summary>
    /// Parse an object with the given universal tag number.
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
    function ParseImplicitPrimitive(AUnivTagNo: Int32): IAsn1Convertible;
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
    /// <summary>
    /// Read a vector of ASN.1 objects.
    /// </summary>
    function ReadVector(): IAsn1EncodableVector;
  end;

  /// <summary>
  /// Interface for ASN.1 sequence parsers.
  /// </summary>
  IAsn1SequenceParser = interface(IAsn1Convertible)
    ['{01234567-89AB-CDEF-0123-456789ABCDEF}']

    /// <summary>
    /// Read the next object from the sequence.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
  end;

  /// <summary>
  /// Interface for ASN.1 set parsers.
  /// </summary>
  IAsn1SetParser = interface(IAsn1Convertible)
    ['{12345678-9ABC-DEF0-1234-56789ABCDEF0}']

    /// <summary>
    /// Read the next object from the set.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
  end;

  /// <summary>
  /// Interface for DER object identifier objects.
  /// </summary>
  IDerObjectIdentifier = interface(IAsn1Object)
    ['{D4E5F6A7-B8C9-0123-DEF0-234567890123}']
    /// <summary>
    /// Get the contents.
    /// </summary>
    function GetContents(): TCryptoLibByteArray;
    /// <summary>
    /// Get the identifier string.
    /// </summary>
    function GetID(): String;
    /// <summary>
    /// Create a new OID by appending a branch ID.
    /// </summary>
    function Branch(const ABranchID: String): IDerObjectIdentifier;
    /// <summary>
    /// Check if this OID is an extension of the passed in stem.
    /// </summary>
    function &On(const AStem: IDerObjectIdentifier): Boolean;
    property Contents: TCryptoLibByteArray read GetContents;
    property ID: String read GetID;
  end;

  /// <summary>
  /// Interface for DER integer objects.
  /// </summary>
  IDerInteger = interface(IAsn1Object)
    ['{B2C3D4E5-F6A7-8901-BCDE-F12345678901}']
    /// <summary>
    /// Get the bytes.
    /// </summary>
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
    property Bytes: TCryptoLibByteArray read GetBytes;
    property Value: TBigInteger read GetValue;
    property PositiveValue: TBigInteger read GetPositiveValue;
    property IntValueExact: Int32 read GetIntValueExact;
    property IntPositiveValueExact: Int32 read GetIntPositiveValueExact;
    property LongValueExact: Int64 read GetLongValueExact;
  end;

  /// <summary>
  /// Interface for DER external objects.
  /// </summary>
  IDerExternal = interface(IAsn1Object)
    ['{9AC333C2-0F64-4A5F-BE0A-EBCC2A4E2A00}']
    /// <summary>
    /// Get the sequence.
    /// </summary>
    function GetSequence(): IAsn1Sequence;
    /// <summary>
    /// Get the data value descriptor.
    /// </summary>
    function GetDataValueDescriptor(): IAsn1Object;
    /// <summary>
    /// Get the direct reference.
    /// </summary>
    function GetDirectReference(): IDerObjectIdentifier;
    /// <summary>
    /// Get the encoding value.
    /// </summary>
    function GetEncoding(): Int32;
    /// <summary>
    /// Get the external content.
    /// </summary>
    function GetExternalContent(): IAsn1Object;
    /// <summary>
    /// Get the indirect reference.
    /// </summary>
    function GetIndirectReference(): IDerInteger;
    property Sequence: IAsn1Sequence read GetSequence;
    property DataValueDescriptor: IAsn1Object read GetDataValueDescriptor;
    property DirectReference: IDerObjectIdentifier read GetDirectReference;
    property Encoding: Int32 read GetEncoding;
    property ExternalContent: IAsn1Object read GetExternalContent;
    property IndirectReference: IDerInteger read GetIndirectReference;
  end;

  /// <summary>
  /// Interface for ASN.1 sequence objects.
  /// </summary>
  IAsn1Sequence = interface(IAsn1Object)
    ['{37A263B7-6724-422B-9B4C-08EBA272045F}']

    /// <summary>
    /// Get the count of elements.
    /// </summary>
    function GetCount(): Int32;
    /// <summary>
    /// Get the parser for this sequence.
    /// </summary>
    function GetParser(): IAsn1SequenceParser;
    /// <summary>
    /// Get an element by index.
    /// </summary>
    function GetItem(AIndex: Int32): IAsn1Encodable;
    /// <summary>
    /// Get all elements.
    /// </summary>
    function GetElements(): TCryptoLibGenericArray<IAsn1Encodable>;
    /// <summary>
    /// Convert to ASN.1 bit string.
    /// </summary>
    function ToAsn1BitString(): IDerBitString;
    /// <summary>
    /// Convert to ASN.1 external.
    /// </summary>
    function ToAsn1External(): IDerExternal;
    /// <summary>
    /// Convert to ASN.1 set.
    /// </summary>
    function ToAsn1Set(): IAsn1Set;
    /// <summary>
    /// Convert to string representation.
    /// </summary>
    function ToString(): String;

    property Count: Int32 read GetCount;
    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Parser: IAsn1SequenceParser read GetParser;
    property Elements: TCryptoLibGenericArray<IAsn1Encodable> read GetElements;
  end;

  /// <summary>
  /// Interface for DER boolean objects.
  /// </summary>
  IDerBoolean = interface(IAsn1Object)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']
    /// <summary>
    /// Get the boolean value.
    /// </summary>
    function GetValue(): Byte;
    /// <summary>
    /// Check if this boolean is true.
    /// </summary>
    function GetIsTrue(): Boolean;
    property Value: Byte read GetValue;
    property IsTrue: Boolean read GetIsTrue;
  end;

  /// <summary>
  /// Interface for DER enumerated objects.
  /// </summary>
  IDerEnumerated = interface(IAsn1Object)
    ['{C3D4E5F6-A7B8-9012-CDEF-123456789012}']
    /// <summary>
    /// Get the bytes.
    /// </summary>
    function GetBytes(): TCryptoLibByteArray;
    /// <summary>
    /// Get the value as BigInteger.
    /// </summary>
    function GetValue(): TBigInteger;
    /// <summary>
    /// Check if this enumerated has a specific integer value.
    /// </summary>
    function HasValue(AX: Int32): Boolean; overload;
    /// <summary>
    /// Check if this enumerated has a specific BigInteger value.
    /// </summary>
    function HasValue(const AX: TBigInteger): Boolean; overload;
    /// <summary>
    /// Get the exact Int32 value, throwing if out of range.
    /// </summary>
    function GetIntValueExact(): Int32;
    property Bytes: TCryptoLibByteArray read GetBytes;
    property Value: TBigInteger read GetValue;
    property IntValueExact: Int32 read GetIntValueExact;
  end;

  /// <summary>
  /// Interface for ASN.1 relative OID objects.
  /// </summary>
  IAsn1RelativeOid = interface(IAsn1Object)
    ['{E5F6A7B8-C9D0-1234-EF01-345678901234}']
    /// <summary>
    /// Get the contents.
    /// </summary>
    function GetContents(): TCryptoLibByteArray;
    /// <summary>
    /// Get the identifier string.
    /// </summary>
    function GetID(): String;
    /// <summary>
    /// Create a new relative OID by appending a branch ID.
    /// </summary>
    function Branch(const ABranchID: String): IAsn1RelativeOid;
    property Contents: TCryptoLibByteArray read GetContents;
    property ID: String read GetID;
  end;

  /// <summary>
  /// Interface for ASN.1 null objects.
  /// </summary>
  IAsn1Null = interface(IAsn1Object)
    ['{5BA79253-4596-4384-9B67-1F3589BD9D24}']
  end;

  /// <summary>
  /// Interface for DER null objects.
  /// </summary>
  IDerNull = interface(IAsn1Null)
    ['{0B4ABCBF-DF52-4934-8A43-218D948E1841}']
  end;

  /// <summary>
  /// Interface for ASN.1 object descriptor objects.
  /// </summary>
  IAsn1ObjectDescriptor = interface(IAsn1Object)
    ['{E5F6A7B8-C9D0-1234-EF01-345678901234}']
    /// <summary>
    /// Get the graphic string.
    /// </summary>
    function GetGraphicString(): IAsn1Object;
    property GraphicString: IAsn1Object read GetGraphicString;
  end;

  /// <summary>
  /// Interface for ASN.1 set objects.
  /// </summary>
  IAsn1Set = interface(IAsn1Object)
    ['{0BA9633A-73D2-4F5E-A1C0-0FCF2623847C}']

    /// <summary>
    /// Get the count of elements.
    /// </summary>
    function GetCount(): Int32;
    /// <summary>
    /// Get the parser for this set.
    /// </summary>
    function GetParser(): IAsn1SetParser;
    /// <summary>
    /// Get an element by index.
    /// </summary>
    function GetItem(AIndex: Int32): IAsn1Encodable;
    /// <summary>
    /// Get all elements.
    /// </summary>
    function GetElements(): TCryptoLibGenericArray<IAsn1Encodable>;
    /// <summary>
    /// Convert to string representation.
    /// </summary>
    function ToString(): String;

    property Count: Int32 read GetCount;
    property Items[AIndex: Int32]: IAsn1Encodable read GetItem; default;
    property Parser: IAsn1SetParser read GetParser;
    property Elements: TCryptoLibGenericArray<IAsn1Encodable> read GetElements;
  end;

  /// <summary>
  /// Interface for DER sequence objects.
  /// </summary>
  IDerSequence = interface(IAsn1Sequence)
    ['{ED1E13E2-6604-4FDE-BDB2-862704A9C90C}']
  end;

  /// <summary>
  /// Interface for DL sequence objects.
  /// </summary>
  IDLSequence = interface(IDerSequence)
    ['{F1E2D3C4-B5A6-9708-1920-213141516171}']

    function ToAsn1External(): IDerExternal;
  end;

  /// <summary>
  /// Interface for BER sequence objects.
  /// </summary>
  IBerSequence = interface(IDerSequence)
    ['{B78E91BF-DB39-4033-8A7A-F0D024C5322A}']
  end;

  /// <summary>
  /// Interface for DER set objects.
  /// </summary>
  IDerSet = interface(IAsn1Set)
    ['{592C8E57-5B00-4927-AD34-EA4481D436BE}']
  end;

  /// <summary>
  /// Interface for DL set objects.
  /// </summary>
  IDLSet = interface(IDerSet)
    ['{A2B3C4D5-E6F7-8901-2345-6789ABCDEF01}']
  end;

  /// <summary>
  /// Interface for BER set objects.
  /// </summary>
  IBerSet = interface(IDerSet)
    ['{FD8838BB-8905-409A-AB93-136EEC6A05E4}']
  end;

  /// <summary>
  /// Interface for DL external objects.
  /// </summary>
  IDLExternal = interface(IDerExternal)
    ['{8BC8ED8F-DE72-5E45-BF26-AF16A7F7E8C8}']
  end;

  /// <summary>
  /// Marker interface for CHOICE objects - if you implement this in a roll-your-own
  /// object, any attempt to tag the object implicitly will convert the tag to an
  /// explicit one as the encoding rules require.
  /// </summary>
  IAsn1Choice = interface(IInterface)
    ['{9C12BE01-9579-48F2-A5B0-4FA5DD807B32}']
    // marker interface
  end;

  /// <summary>
  /// Interface for DER external parsers.
  /// </summary>
  IDerExternalParser = interface(IAsn1Encodable)
    ['{6BF2AB32-0307-4E49-BC4C-844ADCD884E0}']

    /// <summary>
    /// Read the next object.
    /// </summary>
    function ReadObject(): IAsn1Convertible;
  end;

  /// <summary>
  /// Interface for BER tagged object parsers.
  /// </summary>
  IBerTaggedObjectParser = interface(IAsn1TaggedObjectParser)
    ['{7BF3BC43-1418-5F5A-CD5D-955BEDED9951}']
  end;

  /// <summary>
  /// Interface for DL tagged object parsers.
  /// </summary>
  IDLTaggedObjectParser = interface(IAsn1TaggedObjectParser)
    ['{8CF4CD54-2529-6F6B-DE6E-A66CFEFEAA62}']
  end;

  /// <summary>
  /// Interface for BER tagged objects.
  /// </summary>
  IBerTaggedObject = interface(IDLTaggedObject)
    ['{EE7B113E-81ED-5539-930A-73E9930A84CB}']
  end;

  /// <summary>
  /// Interface for BER sequence parsers.
  /// </summary>
  IBerSequenceParser = interface(IAsn1SequenceParser)
    ['{A1AD456A-BE9F-481D-87CA-40B84C32050D}']
  end;

  /// <summary>
  /// Interface for ASN.1 generators.
  /// </summary>
  IAsn1Generator = interface(IInterface)
    ['{B1C2D3E4-F5A6-B7C8-D9E0-F1A2B3C4D5E6}']
    procedure AddObject(const AObj: IAsn1Encodable);
    function GetRawOutputStream(): TStream;
    procedure Close();
  end;

  /// <summary>
  /// Interface for BER generators.
  /// </summary>
  IBerGenerator = interface(IAsn1Generator)
    ['{C2D3E4F5-A6B7-C8D9-E0F1-A2B3C4D5E6F7}']
    procedure WriteHdr(ATag: Int32);
    procedure WriteBerHeader(ATag: Int32);
    procedure WriteBerBody(AContentStream: TStream);
    procedure WriteBerEnd();
  end;

  /// <summary>
  /// Interface for BER sequence generators.
  /// </summary>
  IBerSequenceGenerator = interface(IBerGenerator)
    ['{5FF489CE-2A51-4FE5-A961-99AE423537CE}']
  end;

  /// <summary>
  /// Interface for BER octet string generators.
  /// </summary>
  IBerOctetStringGenerator = interface(IBerGenerator)
    ['{D3E4F5A6-B7C8-D9E0-F1A2-B3C4D5E6F7A8}']
    function GetOctetOutputStream(): TStream; overload;
    function GetOctetOutputStream(ABufSize: Int32): TStream; overload;
    function GetOctetOutputStream(const ABuf: TCryptoLibByteArray): TStream; overload;
  end;

  /// <summary>
  /// Interface for DER generators.
  /// </summary>
  IDerGenerator = interface(IAsn1Generator)
    ['{E4F5A6B7-C8D9-E0F1-A2B3-C4D5E6F7A8B9}']
    procedure WriteDerEncoded(ATag: Int32; const ABytes: TCryptoLibByteArray);
  end;

  /// <summary>
  /// Interface for DER sequence generators.
  /// </summary>
  IDerSequenceGenerator = interface(IDerGenerator)
    ['{F5A6B7C8-D9E0-F1A2-B3C4-D5E6F7A8B9C0}']
    procedure AddObject(const AObj: IAsn1Object); overload;
  end;

  /// <summary>
  /// Interface for BER set parsers.
  /// </summary>
  IBerSetParser = interface(IAsn1SetParser)
    ['{024F6BF0-6503-4452-B7A2-42D1E53D254D}']
  end;

  /// <summary>
  /// Interface for DER sequence parsers.
  /// </summary>
  IDerSequenceParser = interface(IAsn1SequenceParser)
    ['{148A0382-C536-44FC-8AE2-4836E6BE0E5C}']
  end;

  /// <summary>
  /// Interface for DER set parsers.
  /// </summary>
  IDerSetParser = interface(IAsn1SetParser)
    ['{8BA4C05B-5E75-4F2A-B5D1-DCFDF19366EE}']
  end;

  /// <summary>
  /// Interface for ASN.1 types.
  /// </summary>
  IAsn1Type = interface(IInterface)
    ['{D5E6F7A8-9012-3456-789A-BCDEF0123456}']
    /// <summary>
    /// Get the platform type.
    /// </summary>
    function GetPlatformType(): TClass;
    property PlatformType: TClass read GetPlatformType;
  end;

  /// <summary>
  /// Interface for ASN.1 tags.
  /// </summary>
  IAsn1Tag = interface(IInterface)
    ['{E6F7A8B9-0123-4567-89AB-CDEF01234567}']
    /// <summary>
    /// Get the tag class.
    /// </summary>
    function GetTagClass(): Int32;
    /// <summary>
    /// Get the tag number.
    /// </summary>
    function GetTagNo(): Int32;
    property TagClass: Int32 read GetTagClass;
    property TagNo: Int32 read GetTagNo;
  end;

  /// <summary>
  /// Interface for ASN.1 universal types.
  /// </summary>
  IAsn1UniversalType = interface(IAsn1Type)
    ['{C5D6E7F8-9012-3456-789A-BCDEF0123456}']
    /// <summary>
    /// Check and cast an ASN.1 object to the expected type.
    /// </summary>
    function CheckedCast(const AAsn1Object: IAsn1Object): IAsn1Object;
    /// <summary>
    /// Convert from implicit primitive encoding.
    /// </summary>
    function FromImplicitPrimitive(const AOctetString: IDerOctetString): IAsn1Object;
    /// <summary>
    /// Convert from implicit constructed encoding.
    /// </summary>
    function FromImplicitConstructed(const ASequence: IAsn1Sequence): IAsn1Object;
    /// <summary>
    /// Create from byte array.
    /// </summary>
    function FromByteArray(const ABytes: TCryptoLibByteArray): IAsn1Object;
    /// <summary>
    /// Get context tagged object.
    /// </summary>
    function GetContextTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Object;
    /// <summary>
    /// Get tagged object.
    /// </summary>
    function GetTagged(const ATaggedObject: IAsn1TaggedObject; ADeclaredExplicit: Boolean): IAsn1Object;
  end;

implementation

end.
