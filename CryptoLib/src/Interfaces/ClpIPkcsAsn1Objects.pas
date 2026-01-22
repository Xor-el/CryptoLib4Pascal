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

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
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
  IRsassaPssParameters = interface;
  ISignedData = interface;

  /// <summary>
  /// Interface for AttributePkcs.
  /// </summary>
  IAttributePkcs = interface(IAsn1Encodable)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF0123456789}']

    function GetAttrType: IDerObjectIdentifier;
    function GetAttrValues: IAsn1Set;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property AttrValues: IAsn1Set read GetAttrValues;
  end;

  /// <summary>
  /// Interface for CertificationRequest.
  /// </summary>
  ICertificationRequest = interface(IAsn1Encodable)
    ['{B2C3D4E5-F6A7-8901-BCDE-F0123456789A}']

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
    ['{C3D4E5F6-A7B8-9012-CDEF-0123456789AB}']

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
    ['{E6F7A8B9-C0D1-E2F3-A4B5-C6D7E8F9A0B1}']

    function GetVersion: IDerInteger;
    function GetPrivateKeyAlgorithm: IAlgorithmIdentifier;
    function GetPrivateKey: IAsn1OctetString;
    function GetAttributes: IAsn1Set;
    function GetPublicKey: IDerBitString;
    function HasPublicKey: Boolean;
    function ParsePrivateKey: IAsn1Object;
    function ParsePublicKey: IAsn1Object;

    property Version: IDerInteger read GetVersion;
    property PrivateKeyAlgorithm: IAlgorithmIdentifier read GetPrivateKeyAlgorithm;
    property PrivateKey: IAsn1OctetString read GetPrivateKey;
    property Attributes: IAsn1Set read GetAttributes;
    property PublicKey: IDerBitString read GetPublicKey;
  end;

  /// <summary>
  /// Interface for RsaPrivateKeyStructure.
  /// </summary>
  IRsaPrivateKeyStructure = interface(IAsn1Encodable)
    ['{F7A8B9C0-D1E2-F345-A6B7-C8D9E0F1A2B3}']

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
  /// Interface for RsassaPssParameters.
  /// </summary>
  IRsassaPssParameters = interface(IAsn1Encodable)
    ['{A8B9C0D1-E2F3-4567-8901-23456789ABCD}']

    function GetHashAlgorithm: IAlgorithmIdentifier;
    function GetMaskGenAlgorithm: IAlgorithmIdentifier;
    function GetSaltLength: IDerInteger;
    function GetTrailerField: IDerInteger;

    property HashAlgorithm: IAlgorithmIdentifier read GetHashAlgorithm;
    property MaskGenAlgorithm: IAlgorithmIdentifier read GetMaskGenAlgorithm;
    property SaltLength: IDerInteger read GetSaltLength;
    property TrailerField: IDerInteger read GetTrailerField;
  end;

  /// <summary>
  /// Interface for SignedData (PKCS#7).
  /// </summary>
  ISignedData = interface(IAsn1Encodable)
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
