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

unit ClpIPkcsAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  // Forward declarations
  IAttributePkcs = interface;
  ICertificationRequest = interface;
  ICertificationRequestInfo = interface;
  IContentInfo = interface;
  IPrivateKeyInfo = interface;
  IPkcsSignedData = interface;

  /// <summary>
  /// Interface for AttributePkcs.
  /// </summary>
  IAttributePkcs = interface(IAsn1Encodable)
    ['{6F46BA6D-376C-4DB9-A85F-88A443FA3666}']

    function GetAttrType: IDerObjectIdentifier;
    function GetAttrValues: IAsn1Set;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property AttrValues: IAsn1Set read GetAttrValues;
  end;

  /// <summary>
  /// Interface for CertificationRequest.
  /// </summary>
  ICertificationRequest = interface(IAsn1Encodable)
    ['{2FD51313-14E1-414E-A648-2AD4BCBA997F}']

    function GetCertificationRequestInfo: ICertificationRequestInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;

    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
  end;

  /// <summary>
  /// Interface for CertificationRequestInfo.
  /// </summary>
  ICertificationRequestInfo = interface(IAsn1Encodable)
    ['{4405808E-2B24-4F6A-BFC6-92212D567D29}']

    function GetVersion: IDerInteger;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetAttributes: IAsn1Set;

    property Version: IDerInteger read GetVersion;
    property Subject: IX509Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
    property Attributes: IAsn1Set read GetAttributes;
  end;

  /// <summary>
  /// Interface for PrivateKeyInfo.
  /// </summary>
  IPrivateKeyInfo = interface(IAsn1Encodable)
    ['{B118BDBB-DDA9-446F-A2FC-E8350620E054}']

    function GetVersion: IDerInteger;
    function GetPrivateKeyAlgorithm: IAlgorithmIdentifier;
    function GetPrivateKey: IAsn1OctetString;
    function GetPrivateKeyLength: Int32;
    function GetAttributes: IAsn1Set;
    function GetPublicKey: IDerBitString;
    function HasPublicKey: Boolean;
    function ParsePrivateKey: IAsn1Object;
    function ParsePublicKey: IAsn1Object;

    property Version: IDerInteger read GetVersion;
    property PrivateKeyAlgorithm: IAlgorithmIdentifier read GetPrivateKeyAlgorithm;
    property PrivateKey: IAsn1OctetString read GetPrivateKey;
    property PrivateKeyLength: Int32 read GetPrivateKeyLength;
    property Attributes: IAsn1Set read GetAttributes;
    property PublicKey: IDerBitString read GetPublicKey;
  end;

  /// <summary>
  /// Interface for RsaPrivateKeyStructure.
  /// </summary>
  IRsaPrivateKeyStructure = interface(IAsn1Encodable)
    ['{2F80DE02-A5DF-4F82-8011-A6A658DF5473}']

    function GetModulus: TBigInteger;
    function GetPublicExponent: TBigInteger;
    function GetPrivateExponent: TBigInteger;
    function GetPrime1: TBigInteger;
    function GetPrime2: TBigInteger;
    function GetExponent1: TBigInteger;
    function GetExponent2: TBigInteger;
    function GetCoefficient: TBigInteger;

    property Modulus: TBigInteger read GetModulus;
    property PublicExponent: TBigInteger read GetPublicExponent;
    property PrivateExponent: TBigInteger read GetPrivateExponent;
    property Prime1: TBigInteger read GetPrime1;
    property Prime2: TBigInteger read GetPrime2;
    property Exponent1: TBigInteger read GetExponent1;
    property Exponent2: TBigInteger read GetExponent2;
    property Coefficient: TBigInteger read GetCoefficient;
  end;

  /// <summary>
  /// Interface for ContentInfo.
  /// </summary>
  IContentInfo = interface(IAsn1Encodable)
    ['{B9C0D1E2-F3A4-5678-9012-3456789ABCDE}']

    function GetContentType: IDerObjectIdentifier;
    function GetContent: IAsn1Encodable;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property Content: IAsn1Encodable read GetContent;
  end;

  /// <summary>
  /// Interface for SignedData (PKCS#7).
  /// </summary>
  IPkcsSignedData = interface(IAsn1Encodable)
    ['{C0D1E2F3-A4B5-6789-0123-456789ABCDEF}']

    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1Set;
    function GetContentInfo: IContentInfo;
    function GetCertificates: IAsn1Set;
    function GetCrls: IAsn1Set;
    function GetSignerInfos: IAsn1Set;

    property Version: IDerInteger read GetVersion;
    property DigestAlgorithms: IAsn1Set read GetDigestAlgorithms;
    property ContentInfo: IContentInfo read GetContentInfo;
    property Certificates: IAsn1Set read GetCertificates;
    property Crls: IAsn1Set read GetCrls;
    property SignerInfos: IAsn1Set read GetSignerInfos;
  end;

implementation

end.
