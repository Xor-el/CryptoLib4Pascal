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

unit ClpIX509Asn1Objects;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIX509Extension,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpArrayUtils;

type
  // Forward declarations
  IAlgorithmIdentifier = interface;
  IDigestInfo = interface;
  IAltSignatureAlgorithm = interface;
  IAltSignatureValue = interface;
  IAuthorityKeyIdentifier = interface;
  IBasicConstraints = interface;
  IExtendedKeyUsage = interface;
  IGeneralName = interface;
  IGeneralNames = interface;
  IKeyUsage = interface;
  IRsaPublicKeyStructure = interface;
  ISubjectAltPublicKeyInfo = interface;
  ISubjectKeyIdentifier = interface;
  ISubjectPublicKeyInfo = interface;
  ITbsCertificateStructure = interface;
  ITime = interface;
  IValidity = interface;
  IX509CertificateStructure = interface;
  IX509Extensions = interface;
  IX509Name = interface;
  IIssuerSerial = interface;
  IObjectDigestInfo = interface;
  IDistributionPoint = interface;
  IV2Form = interface;
  IDistributionPointName = interface;
  IReasonFlags = interface;
  IAttributeX509 = interface;
  IAttCertIssuer = interface;
  IAttCertValidityPeriod = interface;
  IHolder = interface;
  IAttributeCertificate = interface;
  IAttributeCertificateInfo = interface;
  IPolicyInformation = interface;
  ICrlDistPoint = interface;

  /// <summary>
  /// Interface for the AlgorithmIdentifier object.
  /// <code>
  /// AlgorithmIdentifier ::= SEQUENCE {
  ///   algorithm OBJECT IDENTIFIER,
  ///   parameters ANY DEFINED BY algorithm OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IAlgorithmIdentifier = interface(IAsn1Encodable)
    ['{E7F8A9B0-C1D2-E3F4-A5B6-C7D8E9F0A1B2}']

    function GetAlgorithm: IDerObjectIdentifier;
    function GetParameters: IAsn1Encodable;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Parameters: IAsn1Encodable read GetParameters;
  end;

  /// <summary>
  /// Interface for the DigestInfo object.
  /// DigestInfo ::= SEQUENCE {
  ///   digestAlgorithm AlgorithmIdentifier,
  ///   digest OCTET STRING
  /// }
  /// </summary>
  IDigestInfo = interface(IAsn1Encodable)
    ['{A1B2C3D4-E5F6-7890-ABCD-0123456789AB}']

    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetDigest: IAsn1OctetString;
    function GetDigestBytes: TCryptoLibByteArray;

    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property Digest: IAsn1OctetString read GetDigest;
  end;

  /// <summary>
  /// Interface for AltSignatureAlgorithm.
  /// </summary>
  IAltSignatureAlgorithm = interface(IAsn1Encodable)
    ['{B2C3D4E5-F6A7-8901-BCDE-F0123456789A}']

    function GetAlgorithm: IAlgorithmIdentifier;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;
  end;

  /// <summary>
  /// Interface for AltSignatureValue.
  /// </summary>
  IAltSignatureValue = interface(IAsn1Encodable)
    ['{C3D4E5F6-A7B8-9012-CDEF-0123456789AB}']

    function GetSignature: IDerBitString;

    property Signature: IDerBitString read GetSignature;
  end;

  /// <summary>
  /// Interface for BasicConstraints.
  /// </summary>
  IBasicConstraints = interface(IAsn1Encodable)
    ['{D4E5F6A7-B8C9-0123-DEF0-123456789ABC}']

    function IsCA: Boolean;
    function GetPathLenConstraint: TBigInteger;

    function ToString: String;

    property PathLenConstraint: TBigInteger read GetPathLenConstraint;
  end;

  /// <summary>
  /// Interface for GeneralName.
  /// </summary>
  IGeneralName = interface(IAsn1Encodable)
    ['{E5F6A7B8-C9D0-1234-EF01-23456789ABCD}']

    function GetTagNo: Int32;
    function GetName: IAsn1Encodable;

    function ToString: String;

    property TagNo: Int32 read GetTagNo;
    property Name: IAsn1Encodable read GetName;
  end;

  /// <summary>
  /// Interface for GeneralNames.
  /// </summary>
  IGeneralNames = interface(IAsn1Encodable)
    ['{F6A7B8C9-D0E1-2345-F012-3456789ABCDE}']

    function GetCount: Int32;
    function GetNames: TCryptoLibGenericArray<IGeneralName>;

    property Count: Int32 read GetCount;
  end;

  /// <summary>
  /// Interface for AuthorityKeyIdentifier.
  /// </summary>
  IAuthorityKeyIdentifier = interface(IAsn1Encodable)
    ['{F1A2B3C4-D5E6-789A-5678-9ABCDEF01234}']

    function GetKeyIdentifier: IAsn1OctetString;
    function GetAuthorityCertIssuer: IGeneralNames;
    function GetAuthorityCertSerialNumber: IDerInteger;

    property KeyIdentifier: IAsn1OctetString read GetKeyIdentifier;
    property AuthorityCertIssuer: IGeneralNames read GetAuthorityCertIssuer;
    property AuthorityCertSerialNumber: IDerInteger read GetAuthorityCertSerialNumber;
  end;

  /// <summary>
  /// Interface for ExtendedKeyUsage.
  /// </summary>
  IExtendedKeyUsage = interface(IAsn1Encodable)
    ['{A2B3C4D5-E6F7-890A-6789-ABCDEF012345}']

    function HasKeyPurposeId(const AKeyPurposeId: IDerObjectIdentifier): Boolean;
    function GetAllUsages: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetCount: Int32;

    property Count: Int32 read GetCount;
  end;

  /// <summary>
  /// Interface for KeyUsage.
  /// </summary>
  IKeyUsage = interface(IDerBitString)
    ['{A7B8C9D0-E1F2-3456-0123-456789ABCDEF}']
  end;

  /// <summary>
  /// Interface for RsaPublicKeyStructure.
  /// </summary>
  IRsaPublicKeyStructure = interface(IAsn1Encodable)
    ['{B8C9D0E1-F2A3-4567-1234-56789ABCDEF0}']

    function GetModulus: TBigInteger;
    function GetPublicExponent: TBigInteger;

    property Modulus: TBigInteger read GetModulus;
    property PublicExponent: TBigInteger read GetPublicExponent;
  end;

  /// <summary>
  /// Interface for SubjectAltPublicKeyInfo.
  /// </summary>
  ISubjectAltPublicKeyInfo = interface(IAsn1Encodable)
    ['{C9D0E1F2-A3B4-5678-2345-6789ABCDEF01}']

    function GetAlgorithm: IAlgorithmIdentifier;
    function GetSubjectAltPublicKey: IDerBitString;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;
    property SubjectAltPublicKey: IDerBitString read GetSubjectAltPublicKey;
  end;

  /// <summary>
  /// Interface for SubjectKeyIdentifier.
  /// </summary>
  ISubjectKeyIdentifier = interface(IAsn1Encodable)
    ['{D0E1F2A3-B4C5-6789-3456-789ABCDEF012}']

    function GetKeyIdentifier: TCryptoLibByteArray;
  end;

  /// <summary>
  /// Interface for SubjectPublicKeyInfo.
  /// </summary>
  ISubjectPublicKeyInfo = interface(IAsn1Encodable)
    ['{E1F2A3B4-C5D6-789A-4567-89ABCDEF0123}']

    function GetAlgorithm: IAlgorithmIdentifier;
    function GetPublicKey: IDerBitString;
    function ParsePublicKey: IAsn1Object;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;
    property PublicKey: IDerBitString read GetPublicKey;
  end;

  /// <summary>
  /// Interface for TbsCertificateStructure.
  /// </summary>
  ITbsCertificateStructure = interface(IAsn1Encodable)
    ['{F2A3B4C5-D6E7-89AB-5678-9ABCDEF01234}']

    function GetVersion: Int32;
    function GetVersionNumber: IDerInteger;
    function GetSerialNumber: IDerInteger;
    function GetSignature: IAlgorithmIdentifier;
    function GetIssuer: IX509Name;
    function GetValidity: IValidity;
    function GetStartDate: ITime;
    function GetEndDate: ITime;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetIssuerUniqueID: IDerBitString;
    function GetSubjectUniqueID: IDerBitString;
    function GetExtensions: IX509Extensions;

    property Version: Int32 read GetVersion;
    property VersionNumber: IDerInteger read GetVersionNumber;
    property SerialNumber: IDerInteger read GetSerialNumber;
    property Signature: IAlgorithmIdentifier read GetSignature;
    property Issuer: IX509Name read GetIssuer;
    property Validity: IValidity read GetValidity;
    property StartDate: ITime read GetStartDate;
    property EndDate: ITime read GetEndDate;
    property Subject: IX509Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
    property IssuerUniqueID: IDerBitString read GetIssuerUniqueID;
    property SubjectUniqueID: IDerBitString read GetSubjectUniqueID;
    property Extensions: IX509Extensions read GetExtensions;
  end;

  /// <summary>
  /// Interface for Time (CHOICE type: Asn1UtcTime or Asn1GeneralizedTime).
  /// </summary>
  ITime = interface(IAsn1Encodable)
    ['{B4C5D6E7-F8A9-0BCD-789A-BCDEF0123456}']

    function ToDateTime: TDateTime;
    function ToAsn1Object: IAsn1Object;
  end;

  /// <summary>
  /// Interface for Validity.
  /// </summary>
  IValidity = interface(IAsn1Encodable)
    ['{A3B4C5D6-E7F8-9ABC-6789-ABCDEF012345}']

    function GetNotBefore: ITime;
    function GetNotAfter: ITime;

    property NotBefore: ITime read GetNotBefore;
    property NotAfter: ITime read GetNotAfter;
  end;

  /// <summary>
  /// Interface for X509CertificateStructure.
  /// </summary>
  IX509CertificateStructure = interface(IAsn1Encodable)
    ['{B4C5D6E7-F8A9-BCDE-789A-BCDEF0123456}']

    function GetTbsCertificate: ITbsCertificateStructure;
    function GetVersion: Int32;
    function GetSerialNumber: IDerInteger;
    function GetIssuer: IX509Name;
    function GetValidity: IValidity;
    function GetStartDate: ITime;
    function GetEndDate: ITime;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetIssuerUniqueID: IDerBitString;
    function GetSubjectUniqueID: IDerBitString;
    function GetExtensions: IX509Extensions;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;

    property TbsCertificate: ITbsCertificateStructure read GetTbsCertificate;
    property Version: Int32 read GetVersion;
    property SerialNumber: IDerInteger read GetSerialNumber;
    property Issuer: IX509Name read GetIssuer;
    property Validity: IValidity read GetValidity;
    property StartDate: ITime read GetStartDate;
    property EndDate: ITime read GetEndDate;
    property Subject: IX509Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
    property IssuerUniqueID: IDerBitString read GetIssuerUniqueID;
    property SubjectUniqueID: IDerBitString read GetSubjectUniqueID;
    property Extensions: IX509Extensions read GetExtensions;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
  end;

  /// <summary>
  /// Interface for X509Extensions.
  /// </summary>
  IX509Extensions = interface(IAsn1Encodable)
    ['{C5D6E7F8-A9B0-CDEF-89AB-CDEF01234567}']

    function GetCount: Int32;
    function GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
    function GetExtensionParsedValue(const AOid: IDerObjectIdentifier): IAsn1Object;
    function GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString;
    function GetExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetNonCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function HasAnyCriticalExtensions: Boolean;
    function Equivalent(const AOther: IX509Extensions): Boolean;
    function ToAsn1ObjectTrimmed: IAsn1Sequence;

    property Count: Int32 read GetCount;
  end;

  /// <summary>
  /// Interface for X509Name.
  /// </summary>
  IX509Name = interface(IAsn1Encodable)
    ['{D6E7F8A9-B0C1-DEF0-9ABC-DEF012345678}']

    function GetOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetValues: TCryptoLibStringArray; overload;
    function GetValueList: TCryptoLibStringArray; overload;
    function ToString: String; overload;
    function ToString(const AOid: IDerObjectIdentifier): String; overload;
    function GetValue(const AOid: IDerObjectIdentifier): String; overload;
    function GetValues(const AOid: IDerObjectIdentifier): TCryptoLibStringArray; overload;
    function GetValueList(const AOid: IDerObjectIdentifier): TCryptoLibStringArray; overload;
    function Equivalent(const AOther: IX509Name; AInOrder: Boolean = False): Boolean;

    property Oids: TCryptoLibGenericArray<IDerObjectIdentifier> read GetOids;
    property Values: TCryptoLibStringArray read GetValues;
  end;

  /// <summary>
  /// Interface for AttributeX509.
  /// </summary>
  IAttributeX509 = interface(IAsn1Encodable)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}']
    function GetAttrType: IDerObjectIdentifier;
    function GetAttrValues: IAsn1Set;
    function GetAttributeValues: TCryptoLibGenericArray<IAsn1Encodable>;
    property AttrType: IDerObjectIdentifier read GetAttrType;
    property AttrValues: IAsn1Set read GetAttrValues;
  end;

  /// <summary>
  /// Interface for AttCertIssuer.
  /// </summary>
  IAttCertIssuer = interface(IAsn1Encodable)
    ['{B2C3D4E5-F6A7-8901-BCDE-F01234567890}']
    function GetIssuer: IAsn1Encodable;
    property Issuer: IAsn1Encodable read GetIssuer;
  end;

  /// <summary>
  /// Interface for AttCertValidityPeriod.
  /// </summary>
  IAttCertValidityPeriod = interface(IAsn1Encodable)
    ['{C3D4E5F6-A7B8-9012-CDEF-012345678901}']
    function GetNotBeforeTime: IAsn1GeneralizedTime;
    function GetNotAfterTime: IAsn1GeneralizedTime;
    property NotBeforeTime: IAsn1GeneralizedTime read GetNotBeforeTime;
    property NotAfterTime: IAsn1GeneralizedTime read GetNotAfterTime;
  end;

  /// <summary>
  /// Interface for Holder.
  /// </summary>
  IHolder = interface(IAsn1Encodable)
    ['{D4E5F6A7-B8C9-0123-DEF0-123456789012}']
    function GetVersion: Int32;
    function GetBaseCertificateID: IIssuerSerial;
    function GetEntityName: IGeneralNames;
    function GetObjectDigestInfo: IObjectDigestInfo;
    property Version: Int32 read GetVersion;
    property BaseCertificateID: IIssuerSerial read GetBaseCertificateID;
    property EntityName: IGeneralNames read GetEntityName;
    property ObjectDigestInfo: IObjectDigestInfo read GetObjectDigestInfo;
  end;

  /// <summary>
  /// Interface for AttributeCertificate.
  /// </summary>
  IAttributeCertificate = interface(IAsn1Encodable)
    ['{E5F6A7B8-C9D0-1234-EF01-234567890123}']
    function GetACInfo: IAttributeCertificateInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignatureValue: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;
    property ACInfo: IAttributeCertificateInfo read GetACInfo;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SignatureValue: IDerBitString read GetSignatureValue;
  end;

  /// <summary>
  /// Interface for AttributeCertificateInfo.
  /// </summary>
  IAttributeCertificateInfo = interface(IAsn1Encodable)
    ['{F6A7B8C9-D0E1-2345-F012-345678901234}']
    function GetVersion: IDerInteger;
    function GetHolder: IHolder;
    function GetIssuer: IAttCertIssuer;
    function GetSignature: IAlgorithmIdentifier;
    function GetSerialNumber: IDerInteger;
    function GetAttrCertValidityPeriod: IAttCertValidityPeriod;
    function GetAttributes: IAsn1Sequence;
    function GetIssuerUniqueID: IDerBitString;
    function GetExtensions: IX509Extensions;
    property Version: IDerInteger read GetVersion;
    property Holder: IHolder read GetHolder;
    property Issuer: IAttCertIssuer read GetIssuer;
    property Signature: IAlgorithmIdentifier read GetSignature;
    property SerialNumber: IDerInteger read GetSerialNumber;
    property AttrCertValidityPeriod: IAttCertValidityPeriod read GetAttrCertValidityPeriod;
    property Attributes: IAsn1Sequence read GetAttributes;
    property IssuerUniqueID: IDerBitString read GetIssuerUniqueID;
    property Extensions: IX509Extensions read GetExtensions;
  end;

  /// <summary>
  /// Interface for PolicyInformation.
  /// </summary>
  IPolicyInformation = interface(IAsn1Encodable)
    ['{A7B8C9D0-E1F2-3456-0123-456789012345}']
    function GetPolicyIdentifier: IDerObjectIdentifier;
    function GetPolicyQualifiers: IAsn1Sequence;
    property PolicyIdentifier: IDerObjectIdentifier read GetPolicyIdentifier;
    property PolicyQualifiers: IAsn1Sequence read GetPolicyQualifiers;
  end;

  /// <summary>
  /// Interface for CrlDistPoint.
  /// </summary>
  ICrlDistPoint = interface(IAsn1Encodable)
    ['{B8C9D0E1-F2A3-4567-1234-567890123456}']
    function GetDistributionPoints: TCryptoLibGenericArray<IDistributionPoint>;
  end;

  /// <summary>
  /// Interface for IssuerSerial.
  /// </summary>
  IIssuerSerial = interface(IAsn1Encodable)
    ['{C9D0E1F2-A3B4-5678-0123-456789012345}']
    function GetIssuer: IGeneralNames;
    function GetSerial: IDerInteger;
    function GetIssuerUid: IDerBitString;
    property Issuer: IGeneralNames read GetIssuer;
    property Serial: IDerInteger read GetSerial;
    property IssuerUid: IDerBitString read GetIssuerUid;
  end;

  /// <summary>
  /// Interface for V2Form.
  /// </summary>
  IV2Form = interface(IAsn1Encodable)
    ['{D0E1F2A3-B4C5-6789-1234-567890123456}']
    function GetIssuerName: IGeneralNames;
    function GetBaseCertificateID: IIssuerSerial;
    function GetObjectDigestInfo: IObjectDigestInfo;
    property IssuerName: IGeneralNames read GetIssuerName;
    property BaseCertificateID: IIssuerSerial read GetBaseCertificateID;
    property ObjectDigestInfo: IObjectDigestInfo read GetObjectDigestInfo;
  end;

  /// <summary>
  /// Interface for ObjectDigestInfo.
  /// </summary>
  IObjectDigestInfo = interface(IAsn1Encodable)
    ['{E1F2A3B4-C5D6-7890-2345-678901234567}']
    function GetDigestedObjectType: IDerEnumerated;
    function GetOtherObjectTypeID: IDerObjectIdentifier;
    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetObjectDigest: IDerBitString;
    property DigestedObjectType: IDerEnumerated read GetDigestedObjectType;
    property OtherObjectTypeID: IDerObjectIdentifier read GetOtherObjectTypeID;
    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property ObjectDigest: IDerBitString read GetObjectDigest;
  end;

  /// <summary>
  /// Interface for DistributionPoint.
  /// </summary>
  IDistributionPoint = interface(IAsn1Encodable)
    ['{F2A3B4C5-D6E7-8901-3456-789012345678}']
    function GetDistributionPointName: IDistributionPointName;
    function GetReasons: IReasonFlags;
    function GetCrlIssuer: IGeneralNames;
    property DistributionPointName: IDistributionPointName read GetDistributionPointName;
    property Reasons: IReasonFlags read GetReasons;
    property CrlIssuer: IGeneralNames read GetCrlIssuer;
  end;

  /// <summary>
  /// Interface for DistributionPointName.
  /// </summary>
  IDistributionPointName = interface(IAsn1Choice)
    ['{A3B4C5D6-E7F8-9012-4567-890123456789}']
  end;

  /// <summary>
  /// Interface for ReasonFlags.
  /// </summary>
  IReasonFlags = interface(IAsn1Encodable)
    ['{B4C5D6E7-F8A9-0123-5678-901234567890}']
  end;

implementation

end.
