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

unit ClpICmsAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes;

type
  // Forward declarations
  ICmsContentInfo = interface;
  ICmsIssuerAndSerialNumber = interface;
  ICmsSignerIdentifier = interface;
  ICmsSignedData = interface;
  ICmsSignerInfo = interface;

  /// <summary>
  /// Interface for CMS ContentInfo (EncapsulatedContentInfo).
  /// </summary>
  ICmsContentInfo = interface(IAsn1Encodable)
    ['{96013FE8-A604-4F2F-9C6C-179EE04F096B}']

    function GetContentType: IDerObjectIdentifier;
    function GetContent: IAsn1Encodable;
    function GetIsDefiniteLength: Boolean;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property Content: IAsn1Encodable read GetContent;
    property IsDefiniteLength: Boolean read GetIsDefiniteLength;
  end;

  /// <summary>
  /// Interface for CMS SignedData (RFC 3852).
  /// </summary>
  ICmsSignedData = interface(IAsn1Encodable)
    ['{A71B2C39-D805-4E10-B8F1-28A1E53C3D4F}']

    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1Set;
    function GetEncapContentInfo: ICmsContentInfo;
    function GetCertificates: IAsn1Set;
    function GetCrls: IAsn1Set;
    function GetSignerInfos: IAsn1Set;

    property Version: IDerInteger read GetVersion;
    property DigestAlgorithms: IAsn1Set read GetDigestAlgorithms;
    property EncapContentInfo: ICmsContentInfo read GetEncapContentInfo;
    property Certificates: IAsn1Set read GetCertificates;
    property Crls: IAsn1Set read GetCrls;
    property SignerInfos: IAsn1Set read GetSignerInfos;
  end;

  /// <summary>
  /// Interface for CMS IssuerAndSerialNumber (issuer Name + serialNumber).
  /// </summary>
  ICmsIssuerAndSerialNumber = interface(IAsn1Encodable)
    ['{E1A2B3C4-D5E6-4F78-9012-3456789ABCDE}']

    function GetIssuer: IX509Name;
    function GetSerialNumber: IDerInteger;

    property Issuer: IX509Name read GetIssuer;
    property SerialNumber: IDerInteger read GetSerialNumber;
  end;

  /// <summary>
  /// Interface for CMS SignerIdentifier (CHOICE: IssuerAndSerialNumber or [0] SubjectKeyIdentifier).
  /// </summary>
  ICmsSignerIdentifier = interface(IAsn1Encodable)
    ['{F2B3C4D5-E6A7-4B89-0123-456789ABCDEF}']

    function GetIsTagged: Boolean;
    function GetID: IAsn1Encodable;

    property IsTagged: Boolean read GetIsTagged;
    property ID: IAsn1Encodable read GetID;
  end;

  /// <summary>
  /// Interface for CMS SignerInfo (per-signer information in SignedData).
  /// </summary>
  ICmsSignerInfo = interface(IAsn1Encodable)
    ['{B82D4E5A-E916-4F31-9D72-3B0F5C4E6A7D}']

    function GetVersion: IDerInteger;
    function GetSignerID: ICmsSignerIdentifier;
    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetSignedAttrs: IAsn1Set;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IAsn1OctetString;
    function GetUnsignedAttrs: IAsn1Set;

    property Version: IDerInteger read GetVersion;
    property SignerID: ICmsSignerIdentifier read GetSignerID;
    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property SignedAttrs: IAsn1Set read GetSignedAttrs;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IAsn1OctetString read GetSignature;
    property UnsignedAttrs: IAsn1Set read GetUnsignedAttrs;
  end;

implementation

end.
