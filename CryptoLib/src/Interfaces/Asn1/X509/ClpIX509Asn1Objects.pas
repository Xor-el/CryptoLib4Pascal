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

unit ClpIX509Asn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Extension,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  // Forward declarations
  IAlgorithmIdentifier = interface;
  IDigestInfo = interface;
  IAltSignatureAlgorithm = interface;
  IAltSignatureValue = interface;
  IAuthorityKeyIdentifier = interface;
  IBasicConstraints = interface;
  IExtendedKeyUsage = interface;
  IOtherName = interface;
  IGeneralName = interface;
  IGeneralNames = interface;
  IKeyUsage = interface;
  ISubjectAltPublicKeyInfo = interface;
  ISubjectKeyIdentifier = interface;
  ISubjectPublicKeyInfo = interface;
  ITbsCertificateStructure = interface;
  ITime = interface;
  IValidity = interface;
  IExtension = interface;
  IExtensions = interface;
  ICertificatePair = interface;
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
  IPolicyQualifierInfo = interface;
  ICrlDistPoint = interface;
  IDeltaCertificateDescriptor = interface;
  ICrlEntry = interface;
  ITbsCertificateList = interface;
  ICrlReason = interface;
  IIssuingDistributionPoint = interface;
  ICertificateList = interface;
  IGeneralSubtree = interface;
  IGeneralSubtrees = interface;
  INameConstraints = interface;
  IPrivateKeyUsagePeriod = interface;
  ITarget = interface;
  ITargets = interface;
  ITargetInformation = interface;
  IAccessDescription = interface;
  IAuthorityInformationAccess = interface;

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
  /// Interface for OtherName.
  /// <code>
  /// OtherName ::= SEQUENCE {
  ///   type-id    OBJECT IDENTIFIER,
  ///   value  [0] EXPLICIT ANY DEFINED BY type-id
  /// }
  /// </code>
  /// </summary>
  IOtherName = interface(IAsn1Encodable)
    ['{A476B3A7-C76E-4AEC-B7D2-2DC018C2F76C}']

    function GetTypeID: IDerObjectIdentifier;
    function GetValue: IAsn1Encodable;

    property TypeID: IDerObjectIdentifier read GetTypeID;
    property Value: IAsn1Encodable read GetValue;
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

    function ToString: String;

    property Count: Int32 read GetCount;
  end;

  /// <summary>
  /// Interface for GeneralSubtree.
  /// <code>
  /// GeneralSubtree ::= SEQUENCE {
  ///   base        GeneralName,
  ///   minimum [0] BaseDistance DEFAULT 0,
  ///   maximum [1] BaseDistance OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IGeneralSubtree = interface(IAsn1Encodable)
    ['{1A2B3C4D-5E6F-4071-8291-A3B4C5D6E7F8}']

    function GetBase: IGeneralName;
    function GetMinimum: IDerInteger;
    function GetMaximum: IDerInteger;

    property Base: IGeneralName read GetBase;
    property Minimum: IDerInteger read GetMinimum;
    property Maximum: IDerInteger read GetMaximum;
  end;

  /// <summary>
  /// Interface for GeneralSubtrees.
  /// <code>
  /// GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
  /// </code>
  /// </summary>
  IGeneralSubtrees = interface(IAsn1Encodable)
    ['{2B3C4D5E-6F70-4182-93A4-B5C6D7E8F901}']

    function GetElements: IAsn1Sequence;
    function GetSubtrees: TCryptoLibGenericArray<IGeneralSubtree>;

    property Elements: IAsn1Sequence read GetElements;
  end;

  /// <summary>
  /// Interface for NameConstraints.
  /// <code>
  /// NameConstraints ::= SEQUENCE {
  ///   permittedSubtrees [0] GeneralSubtrees OPTIONAL,
  ///   excludedSubtrees  [1] GeneralSubtrees OPTIONAL
  /// }
  /// </code>
  /// </summary>
  INameConstraints = interface(IAsn1Encodable)
    ['{3C4D5E6F-7081-4293-A4B5-C6D7E8F9021A}']

    function GetPermittedSubtrees: IGeneralSubtrees;
    function GetExcludedSubtrees: IGeneralSubtrees;

    property PermittedSubtrees: IGeneralSubtrees read GetPermittedSubtrees;
    property ExcludedSubtrees: IGeneralSubtrees read GetExcludedSubtrees;
  end;

  /// <summary>
  /// Interface for PrivateKeyUsagePeriod.
  /// <code>
  /// PrivateKeyUsagePeriod ::= SEQUENCE {
  ///   notBefore [0] GeneralizedTime OPTIONAL,
  ///   notAfter  [1] GeneralizedTime OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IPrivateKeyUsagePeriod = interface(IAsn1Encodable)
    ['{4D5E6F70-8192-43A4-B5C6-D7E8F9012B3C}']

    function GetNotBefore: IAsn1GeneralizedTime;
    function GetNotAfter: IAsn1GeneralizedTime;

    property NotBefore: IAsn1GeneralizedTime read GetNotBefore;
    property NotAfter: IAsn1GeneralizedTime read GetNotAfter;
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
  /// Key purpose ID (OID for extended key usage).
  /// </summary>
  IKeyPurposeId = interface(IDerObjectIdentifier)
    ['{E8A9B0C1-D2E3-F4A5-B6C7-D8E9F0A1B2C3}']
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
  /// Interface for CertificatePair (crossCertificatePair, RFC 2587).
  /// CertificatePair ::= SEQUENCE { forward [0] Certificate OPTIONAL, reverse [1] Certificate OPTIONAL }
  /// </summary>
  ICertificatePair = interface(IAsn1Encodable)
    ['{F1A2B3C4-D5E6-47F8-90AB-CDEF12345678}']

    function GetForward: IX509CertificateStructure;
    function GetReverse: IX509CertificateStructure;

    property Forward: IX509CertificateStructure read GetForward;
    property Reverse: IX509CertificateStructure read GetReverse;
  end;

  /// <summary>
  /// RFC 5280 Extension ::= SEQUENCE { extnID, critical DEFAULT FALSE, extnValue }.
  /// </summary>
  IExtension = interface(IAsn1Encodable)
    ['{E4F5A6B7-C8D9-4E0F-A1B2-C3D4E5F60718}']

    function GetExtnID: IDerObjectIdentifier;
    function GetCritical: IDerBoolean;
    function GetExtnValue: IAsn1OctetString;
    function GetParsedValue: IAsn1Object;
    function GetX509Extension: IX509Extension;

    property ExtnID: IDerObjectIdentifier read GetExtnID;
    property Critical: IDerBoolean read GetCritical;
    property ExtnValue: IAsn1OctetString read GetExtnValue;
  end;

  /// <summary>
  /// RFC 5280 Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension.
  /// </summary>
  IExtensions = interface(IAsn1Encodable)
    ['{F5A6B7C8-D9E0-4F1A-B2C3-D4E5F6071829}']

    function GetCount: Int32;
    function GetExtension(const AOid: IDerObjectIdentifier): IExtension;
    function GetExtensionParsedValue(const AOid: IDerObjectIdentifier): IAsn1Object;
    function GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString;
    function GetExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetNonCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function HasAnyCriticalExtensions: Boolean;
    function Equivalent(const AOther: IExtensions): Boolean;

    property Count: Int32 read GetCount;
    property ExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier> read GetExtensionOids;
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
    property ExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier> read GetExtensionOids;
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
    ['{8BE434FF-8DCC-4323-80E0-8DECC8B1B6A2}']
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
  /// Interface for PolicyQualifierInfo.
  /// </summary>
  IPolicyQualifierInfo = interface(IAsn1Encodable)
    ['{B0C1D2E3-F4A5-6789-BCDE-F01234567890}']
    function GetPolicyQualifierId: IDerObjectIdentifier;
    function GetQualifier: IAsn1Encodable;
    property PolicyQualifierId: IDerObjectIdentifier read GetPolicyQualifierId;
    property Qualifier: IAsn1Encodable read GetQualifier;
  end;

  /// <summary>
  /// Interface for CrlDistPoint.
  /// </summary>
  ICrlDistPoint = interface(IAsn1Encodable)
    ['{B8C9D0E1-F2A3-4567-1234-567890123456}']
    function GetDistributionPoints: TCryptoLibGenericArray<IDistributionPoint>;

    function ToString: String;
  end;

  /// <summary>
  /// Interface for DeltaCertificateDescriptor (draft-bonnell-lamps-chameleon-certs).
  /// DeltaCertificateDescriptor ::= SEQUENCE { serialNumber, signature [0] OPTIONAL,
  ///   issuer [1] OPTIONAL, validity [2] OPTIONAL, subject [3] OPTIONAL,
  ///   subjectPublicKeyInfo, extensions [4] OPTIONAL, signatureValue }
  /// </summary>
  IDeltaCertificateDescriptor = interface(IAsn1Encodable)
    ['{A1B2C3D4-E5F6-7890-ABCD-EF0123456789}']

    function GetSerialNumber: IDerInteger;
    function GetSignature: IAlgorithmIdentifier;
    function GetIssuer: IX509Name;
    function GetValidity: IValidity;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetExtensions: IX509Extensions;
    function GetSignatureValue: IDerBitString;

    property SerialNumber: IDerInteger read GetSerialNumber;
    property Signature: IAlgorithmIdentifier read GetSignature;
    property Issuer: IX509Name read GetIssuer;
    property Validity: IValidity read GetValidity;
    property Subject: IX509Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
    property Extensions: IX509Extensions read GetExtensions;
    property SignatureValue: IDerBitString read GetSignatureValue;
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
  /// Interface for Target (RFC 3281).
  /// <code>
  /// Target ::= CHOICE {
  ///   targetName  [0] GeneralName,
  ///   targetGroup [1] GeneralName,
  ///   targetCert  [2] TargetCert
  /// }
  /// </code>
  /// </summary>
  ITarget = interface(IAsn1Choice)
    ['{5E6F7081-92A3-44B5-C6D7-E8F9012A3B4C}']

    function GetTargetName: IGeneralName;
    function GetTargetGroup: IGeneralName;

    property TargetName: IGeneralName read GetTargetName;
    property TargetGroup: IGeneralName read GetTargetGroup;
  end;

  /// <summary>
  /// Interface for Targets (RFC 3281).
  /// <code>
  /// Targets ::= SEQUENCE OF Target
  /// </code>
  /// </summary>
  ITargets = interface(IAsn1Encodable)
    ['{6F708192-A3B4-45C6-D7E8-F9012A3B4C5D}']

    function GetTargets: TCryptoLibGenericArray<ITarget>;
  end;

  /// <summary>
  /// Interface for TargetInformation (RFC 3281).
  /// <code>
  /// TargetInformation ::= SEQUENCE OF Targets
  /// </code>
  /// </summary>
  ITargetInformation = interface(IAsn1Encodable)
    ['{7081920A-B4C5-46D7-E8F9-012A3B4C5D6E}']

    function GetTargetsObjects: TCryptoLibGenericArray<ITargets>;
  end;

  /// <summary>
  /// Interface for DistributionPoint.
  /// </summary>
  IDistributionPoint = interface(IAsn1Encodable)
    ['{F2A3B4C5-D6E7-8901-3456-789012345678}']
    function GetDistributionPointName: IDistributionPointName;
    function GetReasons: IReasonFlags;
    function GetCrlIssuer: IGeneralNames;
    function ToString: String;
    property DistributionPointName: IDistributionPointName read GetDistributionPointName;
    property Reasons: IReasonFlags read GetReasons;
    property CrlIssuer: IGeneralNames read GetCrlIssuer;
  end;

  /// <summary>
  /// Interface for DistributionPointName.
  /// </summary>
  IDistributionPointName = interface(IAsn1Choice)
    ['{A3B4C5D6-E7F8-9012-4567-890123456789}']

    /// <summary>The CHOICE alternative: fullName or nameRelativeToCRLIssuer.</summary>
    function GetType: Int32;
    function GetName: IAsn1Encodable;

    function ToString: String;
  end;

  /// <summary>
  /// Interface for ReasonFlags.
  /// </summary>
  IReasonFlags = interface(IAsn1Encodable)
    ['{B4C5D6E7-F8A9-0123-5678-901234567890}']

    function ToString: String;
  end;

  /// <summary>
  /// Interface for CrlEntry (revoked certificate entry in a CRL).
  /// </summary>
  ICrlEntry = interface(IAsn1Encodable)
    ['{E8F9A0B1-C2D3-E4F5-A6B7-C8D9E0F1A2B3}']

    function GetUserCertificate: IDerInteger;
    function GetRevocationDate: ITime;
    function GetExtensions: IX509Extensions;

    property UserCertificate: IDerInteger read GetUserCertificate;
    property RevocationDate: ITime read GetRevocationDate;
    property Extensions: IX509Extensions read GetExtensions;
  end;

  /// <summary>
  /// Interface for TbsCertificateList (TBSCertList).
  /// </summary>
  ITbsCertificateList = interface(IAsn1Encodable)
    ['{F9A0B1C2-D3E4-F5A6-B7C8-D9E0F1A2B3C4}']

    function GetVersion: Int32;
    function GetVersionNumber: IDerInteger;
    function GetSignature: IAlgorithmIdentifier;
    function GetIssuer: IX509Name;
    function GetThisUpdate: ITime;
    function GetNextUpdate: ITime;
    function GetRevokedCertificates: TCryptoLibGenericArray<ICrlEntry>;
    function GetExtensions: IX509Extensions;

    property Version: Int32 read GetVersion;
    property VersionNumber: IDerInteger read GetVersionNumber;
    property Signature: IAlgorithmIdentifier read GetSignature;
    property Issuer: IX509Name read GetIssuer;
    property ThisUpdate: ITime read GetThisUpdate;
    property NextUpdate: ITime read GetNextUpdate;
    property Extensions: IX509Extensions read GetExtensions;
  end;

  /// <summary>
  /// Interface for CrlReason (CRL reason enumeration).
  /// </summary>
  ICrlReason = interface(IDerEnumerated)
    ['{A0B1C2D3-E4F5-A6B7-C8D9-E0F1A2B3C4D5}']

    function ToString: String;
  end;

  /// <summary>
  /// Interface for IssuingDistributionPoint.
  /// </summary>
  IIssuingDistributionPoint = interface(IAsn1Encodable)
    ['{B1C2D3E4-F5A6-B7C8-D9E0-F1A2B3C4D5E6}']

    function GetDistributionPoint: IDistributionPointName;
    function GetOnlyContainsUserCerts: Boolean;
    function GetOnlyContainsCACerts: Boolean;
    function GetOnlySomeReasons: IReasonFlags;
    function GetIsIndirectCrl: Boolean;
    function GetOnlyContainsAttributeCerts: Boolean;

    function ToString: String;

    property DistributionPoint: IDistributionPointName read GetDistributionPoint;
    property OnlyContainsUserCerts: Boolean read GetOnlyContainsUserCerts;
    property OnlyContainsCACerts: Boolean read GetOnlyContainsCACerts;
    property OnlySomeReasons: IReasonFlags read GetOnlySomeReasons;
    property IsIndirectCrl: Boolean read GetIsIndirectCrl;
    property OnlyContainsAttributeCerts: Boolean read GetOnlyContainsAttributeCerts;
  end;

  /// <summary>
  /// Interface for CertificateList (X.509 CRL).
  /// </summary>
  ICertificateList = interface(IAsn1Encodable)
    ['{C2D3E4F5-A6B7-C8D9-E0F1-A2B3C4D5E6F7}']

    function GetTbsCertList: ITbsCertificateList;
    function GetRevokedCertificates: TCryptoLibGenericArray<ICrlEntry>;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;
    function GetVersion: Int32;
    function GetIssuer: IX509Name;
    function GetThisUpdate: ITime;
    function GetNextUpdate: ITime;
    function GetExtensions: IX509Extensions;

    property TbsCertList: ITbsCertificateList read GetTbsCertList;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
    property Version: Int32 read GetVersion;
    property Issuer: IX509Name read GetIssuer;
    property ThisUpdate: ITime read GetThisUpdate;
    property NextUpdate: ITime read GetNextUpdate;
    property Extensions: IX509Extensions read GetExtensions;
  end;

  /// <summary>
  /// Interface for AccessDescription (RFC 5280 sec. 4.2.2.1).
  /// <code>
  /// AccessDescription ::= SEQUENCE {
  ///   accessMethod   OBJECT IDENTIFIER,
  ///   accessLocation GeneralName
  /// }
  /// </code>
  /// </summary>
  IAccessDescription = interface(IAsn1Encodable)
    ['{6D1F0A54-3C7B-4A2E-9E11-5B8C0D3F7A61}']

    function GetAccessMethod: IDerObjectIdentifier;
    function GetAccessLocation: IGeneralName;

    function ToString: String;

    property AccessMethod: IDerObjectIdentifier read GetAccessMethod;
    property AccessLocation: IGeneralName read GetAccessLocation;
  end;

  /// <summary>
  /// Interface for AuthorityInfoAccessSyntax (RFC 5280 sec. 4.2.2.1).
  /// <code>
  /// AuthorityInfoAccessSyntax ::= SEQUENCE SIZE (1..MAX) OF AccessDescription
  /// </code>
  /// </summary>
  IAuthorityInformationAccess = interface(IAsn1Encodable)
    ['{9A4E2C77-8B05-4D6F-BC13-2E7A9F04D5B8}']

    function GetAccessDescriptions: TCryptoLibGenericArray<IAccessDescription>;

    function ToString: String;
  end;

implementation

end.
