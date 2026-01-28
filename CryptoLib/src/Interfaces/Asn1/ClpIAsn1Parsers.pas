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

unit ClpIAsn1Parsers;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpIAsn1Core;

type
  IAsn1TaggedObjectParser = interface;

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
  /// Interface for BER sequence parsers.
  /// </summary>
  IBerSequenceParser = interface(IAsn1SequenceParser)
    ['{A1AD456A-BE9F-481D-87CA-40B84C32050D}']
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

implementation

end.
