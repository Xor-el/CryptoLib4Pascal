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

unit ClpX509Asn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  DateUtils,
  Generics.Collections,
  SyncObjs,
  ClpAsn1Tags,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpX509Extension,
  ClpIX509NameEntryConverter,
  ClpIX509NameTokenizer,
  ClpX509NameTokenizer,
  ClpX509ObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  ClpAsn1Utilities,
  ClpCollectionUtilities,
  ClpStringUtilities,
  ClpPlatformUtilities,
  ClpIPAddressUtilities,
  ClpRfc5280Asn1Utilities,
  ClpDateTimeUtilities,
  ClpIetfUtilities,
  ClpEncoders,
  ClpAsn1Comparers,
  ClpCryptoLibComparers;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SAlgorithmNil = 'algorithm';
  SDigestAlgorithmNil = 'digestAlgorithm';
  SDigestNil = 'digest';
  SAlgorithmNilAlt = 'algorithm';
  SSignatureNil = 'signature';
  SNotCA = 'Not a valid RSA modulus';
  SNotValidPublicExponent = 'Not a valid RSA public exponent';
  SSubjectPublicKeyInfoNil = 'subjectPublicKeyInfo';
  SNotBeforeNil = 'notBefore';
  SNotAfterNil = 'notAfter';
  STbsCertNil = 'tbsCert';
  SSigAlgIDNil = 'sigAlgID';
  SSigNil = 'sig';
  SVersionNumberNotRecognised = 'version number not recognised';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';
  SInvalidKeyIdentifier = 'keyID';
  SInvalidKeyID = 'keyID';
  SDeltaCertDescSerialNil = 'serialNumber';
  SDeltaCertDescSpkiNil = 'subjectPublicKeyInfo';
  SDeltaCertDescSigValNil = 'signatureValue';
  SInvalidDsaParameter = 'Invalid DsaParameter: %s';

type
  /// <summary>
  /// The AlgorithmIdentifier object.
  /// <code>
  /// AlgorithmIdentifier ::= SEQUENCE {
  ///   algorithm OBJECT IDENTIFIER,
  ///   parameters ANY DEFINED BY algorithm OPTIONAL
  /// }
  /// </code>
  /// </summary>
  TAlgorithmIdentifier = class(TAsn1Encodable, IAlgorithmIdentifier)

  strict private
  var
    FAlgorithm: IDerObjectIdentifier;
    FParameters: IAsn1Encodable;

  strict protected
    function GetAlgorithm: IDerObjectIdentifier;
    function GetParameters: IAsn1Encodable;

  public
    /// <summary>
    /// Parse an AlgorithmIdentifier from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IAlgorithmIdentifier; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAlgorithmIdentifier; overload; static;
    /// <summary>
    /// Parse an AlgorithmIdentifier from a byte array.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAlgorithmIdentifier; overload; static;
    /// <summary>
    /// Parse an AlgorithmIdentifier from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAlgorithmIdentifier; overload; static;
    /// <summary>
    /// Get optional AlgorithmIdentifier.
    /// </summary>
    class function GetOptional(const AElement: IAsn1Encodable): IAlgorithmIdentifier; static;
    /// <summary>
    /// Get tagged AlgorithmIdentifier.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAlgorithmIdentifier; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAlgorithm: IDerObjectIdentifier); overload;
    constructor Create(const AAlgorithm: IDerObjectIdentifier;
      const AParameters: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Algorithm: IDerObjectIdentifier read GetAlgorithm;
    property Parameters: IAsn1Encodable read GetParameters;

  end;

  /// <summary>
  /// The DigestInfo object.
  /// DigestInfo ::= SEQUENCE {
  ///   digestAlgorithm AlgorithmIdentifier,
  ///   digest OCTET STRING
  /// }
  /// </summary>
  TDigestInfo = class(TAsn1Encodable, IDigestInfo)

  strict private
  var
    FDigestAlgorithm: IAlgorithmIdentifier;
    FDigest: IAsn1OctetString;

  strict protected
    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetDigest: IAsn1OctetString;
    function GetDigestBytes: TCryptoLibByteArray;

  public
    /// <summary>
    /// Parse a DigestInfo from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IDigestInfo; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDigestInfo; overload; static;
    /// <summary>
    /// Parse a DigestInfo from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDigestInfo; overload; static;
    /// <summary>
    /// Parse a DigestInfo from a tagged object.
    /// </summary>
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDigestInfo; overload; static;
    /// <summary>
    /// Get tagged DigestInfo.
    /// </summary>
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDigestInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAlgId: IAlgorithmIdentifier;
      const ADigest: TCryptoLibByteArray); overload;
    constructor Create(const ADigestAlgorithm: IAlgorithmIdentifier;
      const ADigest: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property Digest: IAsn1OctetString read GetDigest;

  end;

  /// <summary>
  /// DeltaCertificateDescriptor (draft-bonnell-lamps-chameleon-certs).
  /// DeltaCertificateDescriptor ::= SEQUENCE { serialNumber, signature [0] OPTIONAL,
  ///   issuer [1] OPTIONAL, validity [2] OPTIONAL, subject [3] OPTIONAL,
  ///   subjectPublicKeyInfo, extensions [4] OPTIONAL, signatureValue }
  /// </summary>
  TDeltaCertificateDescriptor = class(TAsn1Encodable, IAsn1Encodable,
    IDeltaCertificateDescriptor)

  strict private
  var
    FSerialNumber: IDerInteger;
    FSignature: IAlgorithmIdentifier;
    FIssuer: IX509Name;
    FValidity: IValidity;
    FSubject: IX509Name;
    FSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    FExtensions: IX509Extensions;
    FSignatureValue: IDerBitString;

  strict private
    procedure ImplCreate(const ASeq: IAsn1Sequence);

  strict protected
    function GetSerialNumber: IDerInteger;
    function GetSignature: IAlgorithmIdentifier;
    function GetIssuer: IX509Name;
    function GetValidity: IValidity;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetExtensions: IX509Extensions;
    function GetSignatureValue: IDerBitString;

  public
  /// <summary>
    /// Parse a DeltaCertificateDescriptor from an object.
    /// </summary>
    class function GetInstance(AObj: TObject): IDeltaCertificateDescriptor; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDeltaCertificateDescriptor; overload; static;
    /// <summary>
    /// Parse a DeltaCertificateDescriptor from DER-encoded bytes.
    /// </summary>
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDeltaCertificateDescriptor; overload; static;

    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDeltaCertificateDescriptor; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDeltaCertificateDescriptor; static;
    class function FromExtensions(const AExtensions: IX509Extensions): IDeltaCertificateDescriptor; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASerialNumber: IDerInteger;
      const ASignature: IAlgorithmIdentifier; const AIssuer: IX509Name;
      const AValidity: IValidity; const ASubject: IX509Name;
      const ASubjectPublicKeyInfo: ISubjectPublicKeyInfo;
      const AExtensions: IX509Extensions;
      const ASignatureValue: IDerBitString); overload;

    function ToAsn1Object: IAsn1Object; override;

  end;

  /// <summary>
  /// The GeneralName object.
  /// </summary>
  TGeneralName = class(TAsn1Encodable, IGeneralName, IAsn1Choice)

  strict private
  var
    FTag: Int32;
    FName: IAsn1Encodable;

  strict private
    class function ToGeneralNameEncoding(const AIp: String): TCryptoLibByteArray; static;
    class procedure CopyInts(const AParsedIp: TCryptoLibInt32Array; var AAddr: TCryptoLibByteArray; AOffset: Int32); static;
    class procedure ParseIPv4(const AIp: String; var AAddr: TCryptoLibByteArray; AOffset: Int32); static;
    class procedure ParseIPv4Mask(const AMask: String; var AAddr: TCryptoLibByteArray; AOffset: Int32); static;
    class function ParseIPv6(const AIp: String): TCryptoLibInt32Array; static;
    class function ParseIPv6Mask(const AMask: String): TCryptoLibInt32Array; static;

  strict protected
    function GetTagNo: Int32;
    function GetName: IAsn1Encodable;

  public
    const
      OtherName = 0;
      Rfc822Name = 1;
      DnsName = 2;
      X400Address = 3;
      DirectoryName = 4;
      EdiPartyName = 5;
      UniformResourceIdentifier = 6;
      IPAddress = 7;
      RegisteredID = 8;

    class function GetInstance(AObj: TObject): IGeneralName; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IGeneralName; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IGeneralName; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IGeneralName; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IGeneralName; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IGeneralName; static;
    class function GetOptionalBaseObject(const ATaggedObject: IAsn1TaggedObject): IAsn1Encodable; static;

    constructor Create(const ADirectoryName: IX509Name); overload;
    constructor Create(const AName: IAsn1Object; ATag: Int32); overload;
    constructor Create(ATag: Int32; const AName: IAsn1Encodable); overload;
    constructor Create(ATag: Int32; const AName: String); overload;

    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

    property TagNo: Int32 read GetTagNo;
    property Name: IAsn1Encodable read GetName;

  end;

  /// <summary>
  /// The GeneralNames object.
  /// </summary>
  TGeneralNames = class(TAsn1Encodable, IGeneralNames)

  strict private
  var
    FNames: TCryptoLibGenericArray<IGeneralName>;

  strict protected
    function GetCount: Int32;
    function GetNames: TCryptoLibGenericArray<IGeneralName>;

  public
    class function GetInstance(AObj: TObject): IGeneralNames; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IGeneralNames; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IGeneralNames; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IGeneralNames; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IGeneralNames; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IGeneralNames; static;

    constructor Create(const AName: IGeneralName); overload;
    constructor Create(const ANames: TCryptoLibGenericArray<IGeneralName>); overload;
    constructor Create(const ASeq: IAsn1Sequence); overload;

    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

    property Count: Int32 read GetCount;

  end;

  /// <summary>
  /// The KeyUsage object (extends TDerBitString).
  /// </summary>
  TKeyUsage = class(TDerBitString, IKeyUsage)

  public
    const
      DigitalSignature = (1 shl 7);
      NonRepudiation = (1 shl 6);
      KeyEncipherment = (1 shl 5);
      DataEncipherment = (1 shl 4);
      KeyAgreement = (1 shl 3);
      KeyCertSign = (1 shl 2);
      CrlSign = (1 shl 1);
      EncipherOnly = (1 shl 0);
      DecipherOnly = (1 shl 15);

    class function GetKeyUsageInstance(AObj: TObject): IKeyUsage; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetKeyUsageInstance(const AObj: IAsn1Convertible): IKeyUsage; overload; static;
    class function GetKeyUsageInstance(const AEncoded: TCryptoLibByteArray): IKeyUsage; overload; static;

    constructor Create(AUsage: Int32); overload;
    constructor Create(const AUsage: IDerBitString); overload;

    function ToString: String; override;

  end;

  /// <summary>
  /// The AuthorityKeyIdentifier object.
  /// </summary>
  TAuthorityKeyIdentifier = class(TAsn1Encodable, IAuthorityKeyIdentifier)

  strict private
  var
    FKeyIdentifier: IAsn1OctetString;
    FAuthorityCertIssuer: IGeneralNames;
    FAuthorityCertSerialNumber: IDerInteger;

  strict protected
    function GetKeyIdentifier: IAsn1OctetString;
    function GetAuthorityCertIssuer: IGeneralNames;
    function GetAuthorityCertSerialNumber: IDerInteger;

  public
    class function GetInstance(AObj: TObject): IAuthorityKeyIdentifier; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAuthorityKeyIdentifier; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAuthorityKeyIdentifier; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAuthorityKeyIdentifier; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAuthorityKeyIdentifier; static;
    class function FromExtensions(const AExtensions: IX509Extensions): IAuthorityKeyIdentifier; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AKeyIdentifier: TCryptoLibByteArray); overload;
    constructor Create(const AKeyIdentifier: TCryptoLibByteArray;
      const AAuthorityCertIssuer: IGeneralNames;
      const AAuthorityCertSerialNumber: TBigInteger); overload;
    constructor Create(const AKeyIdentifier: IAsn1OctetString); overload;
    constructor Create(const AKeyIdentifier: IAsn1OctetString;
      const AAuthorityCertIssuer: IGeneralNames;
      const AAuthorityCertSerialNumber: IDerInteger); overload;
    constructor Create(const AAuthorityCertIssuer: IGeneralNames;
      const AAuthorityCertSerialNumber: TBigInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property KeyIdentifier: IAsn1OctetString read GetKeyIdentifier;
    property AuthorityCertIssuer: IGeneralNames read GetAuthorityCertIssuer;
    property AuthorityCertSerialNumber: IDerInteger read GetAuthorityCertSerialNumber;

  end;

  /// <summary>
  /// The ExtendedKeyUsage object.
  /// </summary>
  TExtendedKeyUsage = class(TAsn1Encodable, IExtendedKeyUsage)

  strict private
  var
    FUsageTable: TDictionary<IDerObjectIdentifier, Boolean>;
    FSeq: IAsn1Sequence;

  strict protected
    function HasKeyPurposeId(const AKeyPurposeId: IDerObjectIdentifier): Boolean;
    function GetAllUsages: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetCount: Int32;

  public
    class function GetInstance(AObj: TObject): IExtendedKeyUsage; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IExtendedKeyUsage; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IExtendedKeyUsage; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IExtendedKeyUsage; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IExtendedKeyUsage; static;
    class function FromExtensions(const AExtensions: IX509Extensions): IExtendedKeyUsage; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AUsages: TCryptoLibGenericArray<IDerObjectIdentifier>); overload;
    constructor Create(const AUsages: array of IKeyPurposeId); overload;

    destructor Destroy; override;

    function ToAsn1Object: IAsn1Object; override;

    property Count: Int32 read GetCount;

  end;

  /// <summary>
  /// The X509Extensions object.
  /// </summary>
  TX509Extensions = class(TAsn1Encodable, IX509Extensions)

  strict private
  var
    FExtensions: TDictionary<IDerObjectIdentifier, IX509Extension>;
    FOrdering: TList<IDerObjectIdentifier>;

    class var
      FSubjectDirectoryAttributes: IDerObjectIdentifier;
      FSubjectKeyIdentifier: IDerObjectIdentifier;
      FKeyUsage: IDerObjectIdentifier;
      FPrivateKeyUsagePeriod: IDerObjectIdentifier;
      FSubjectAlternativeName: IDerObjectIdentifier;
      FIssuerAlternativeName: IDerObjectIdentifier;
      FBasicConstraints: IDerObjectIdentifier;
      FCrlNumber: IDerObjectIdentifier;
      FReasonCode: IDerObjectIdentifier;
      FInstructionCode: IDerObjectIdentifier;
      FInvalidityDate: IDerObjectIdentifier;
      FDeltaCrlIndicator: IDerObjectIdentifier;
      FIssuingDistributionPoint: IDerObjectIdentifier;
      FCertificateIssuer: IDerObjectIdentifier;
      FNameConstraints: IDerObjectIdentifier;
      FCrlDistributionPoints: IDerObjectIdentifier;
      FCertificatePolicies: IDerObjectIdentifier;
      FPolicyMappings: IDerObjectIdentifier;
      FAuthorityKeyIdentifier: IDerObjectIdentifier;
      FPolicyConstraints: IDerObjectIdentifier;
      FExtendedKeyUsage: IDerObjectIdentifier;
      FFreshestCrl: IDerObjectIdentifier;
      FInhibitAnyPolicy: IDerObjectIdentifier;
      FAuthorityInfoAccess: IDerObjectIdentifier;
      FBiometricInfo: IDerObjectIdentifier;
      FQCStatements: IDerObjectIdentifier;
      FAuditIdentity: IDerObjectIdentifier;
      FSubjectInfoAccess: IDerObjectIdentifier;
      FLogoType: IDerObjectIdentifier;
      FNoRevAvail: IDerObjectIdentifier;
      FTargetInformation: IDerObjectIdentifier;
      FExpiredCertsOnCrl: IDerObjectIdentifier;
      FSubjectAltPublicKeyInfo: IDerObjectIdentifier;
      FAltSignatureAlgorithm: IDerObjectIdentifier;
      FAltSignatureValue: IDerObjectIdentifier;
      FDraftDeltaCertificateDescriptor: IDerObjectIdentifier;

    class procedure Boot; static;
    class constructor Create;
    class destructor Destroy;

  strict protected
    function GetCount: Int32;
    function GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
    function GetExtensionParsedValue(const AOid: IDerObjectIdentifier): IAsn1Object; overload;
    function GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString;
    function GetExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetNonCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetExtensionOidsInternal(AIsCritical: Boolean): TCryptoLibGenericArray<IDerObjectIdentifier>;
    function HasAnyCriticalExtensions: Boolean;
    function Equivalent(const AOther: IX509Extensions): Boolean;

  public
    // Extension OID constants
    class property SubjectDirectoryAttributes: IDerObjectIdentifier read FSubjectDirectoryAttributes;
    class property SubjectKeyIdentifier: IDerObjectIdentifier read FSubjectKeyIdentifier;
    class property KeyUsage: IDerObjectIdentifier read FKeyUsage;
    class property PrivateKeyUsagePeriod: IDerObjectIdentifier read FPrivateKeyUsagePeriod;
    class property SubjectAlternativeName: IDerObjectIdentifier read FSubjectAlternativeName;
    class property IssuerAlternativeName: IDerObjectIdentifier read FIssuerAlternativeName;
    class property BasicConstraints: IDerObjectIdentifier read FBasicConstraints;
    class property CrlNumber: IDerObjectIdentifier read FCrlNumber;
    class property ReasonCode: IDerObjectIdentifier read FReasonCode;
    class property InstructionCode: IDerObjectIdentifier read FInstructionCode;
    class property InvalidityDate: IDerObjectIdentifier read FInvalidityDate;
    class property DeltaCrlIndicator: IDerObjectIdentifier read FDeltaCrlIndicator;
    class property IssuingDistributionPoint: IDerObjectIdentifier read FIssuingDistributionPoint;
    class property CertificateIssuer: IDerObjectIdentifier read FCertificateIssuer;
    class property NameConstraints: IDerObjectIdentifier read FNameConstraints;
    class property CrlDistributionPoints: IDerObjectIdentifier read FCrlDistributionPoints;
    class property CertificatePolicies: IDerObjectIdentifier read FCertificatePolicies;
    class property PolicyMappings: IDerObjectIdentifier read FPolicyMappings;
    class property AuthorityKeyIdentifier: IDerObjectIdentifier read FAuthorityKeyIdentifier;
    class property PolicyConstraints: IDerObjectIdentifier read FPolicyConstraints;
    class property ExtendedKeyUsage: IDerObjectIdentifier read FExtendedKeyUsage;
    class property FreshestCrl: IDerObjectIdentifier read FFreshestCrl;
    class property InhibitAnyPolicy: IDerObjectIdentifier read FInhibitAnyPolicy;
    class property AuthorityInfoAccess: IDerObjectIdentifier read FAuthorityInfoAccess;
    class property BiometricInfo: IDerObjectIdentifier read FBiometricInfo;
    class property QCStatements: IDerObjectIdentifier read FQCStatements;
    class property AuditIdentity: IDerObjectIdentifier read FAuditIdentity;
    class property SubjectInfoAccess: IDerObjectIdentifier read FSubjectInfoAccess;
    class property LogoType: IDerObjectIdentifier read FLogoType;
    class property NoRevAvail: IDerObjectIdentifier read FNoRevAvail;
    class property TargetInformation: IDerObjectIdentifier read FTargetInformation;
    class property ExpiredCertsOnCrl: IDerObjectIdentifier read FExpiredCertsOnCrl;
    class property SubjectAltPublicKeyInfo: IDerObjectIdentifier read FSubjectAltPublicKeyInfo;
    class property AltSignatureAlgorithm: IDerObjectIdentifier read FAltSignatureAlgorithm;
    class property AltSignatureValue: IDerObjectIdentifier read FAltSignatureValue;
    class property DraftDeltaCertificateDescriptor: IDerObjectIdentifier read FDraftDeltaCertificateDescriptor;

    class function GetInstance(AObj: TObject): IX509Extensions; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IX509Extensions; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IX509Extensions; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IX509Extensions; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IX509Extensions; static;
    class function GetExtensionParsedValue(const AExtensions: IX509Extensions;
      const AOid: IDerObjectIdentifier): IAsn1Object; overload; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AExtensions: TDictionary<IDerObjectIdentifier, IX509Extension>); overload;
    constructor Create(const AOrdering: TList<IDerObjectIdentifier>;
      const AExtensions: TDictionary<IDerObjectIdentifier, IX509Extension>); overload;
    constructor Create(const AOids: TList<IDerObjectIdentifier>;
      const AValues: TList<IX509Extension>); overload;

    destructor Destroy; override;

    function ToAsn1Object: IAsn1Object; override;
    function ToAsn1ObjectTrimmed: IAsn1Sequence;

    property Count: Int32 read GetCount;

  end;

  /// <summary>
  /// Key purpose ID registry (OIDs for extended key usage).
  /// KeyPurposeID ::= OBJECT IDENTIFIER
  /// </summary>
  TKeyPurposeId = class abstract(TObject)

  strict private
  class var
    FAnyExtendedKeyUsage: IDerObjectIdentifier;
    FIdKpServerAuth: IDerObjectIdentifier;
    FIdKpClientAuth: IDerObjectIdentifier;
    FIdKpCodeSigning: IDerObjectIdentifier;
    FIdKpEmailProtection: IDerObjectIdentifier;
    FIdKpIpsecEndSystem: IDerObjectIdentifier;
    FIdKpIpsecTunnel: IDerObjectIdentifier;
    FIdKpIpsecUser: IDerObjectIdentifier;
    FIdKpTimeStamping: IDerObjectIdentifier;
    FIdKpOcspSigning: IDerObjectIdentifier;
    FIdKpDvcs: IDerObjectIdentifier;
    FIdKpSbgpCertAaServerAuth: IDerObjectIdentifier;
    FIdKpScvpResponder: IDerObjectIdentifier;
    FIdKpEapOverPpp: IDerObjectIdentifier;
    FIdKpEapOverLan: IDerObjectIdentifier;
    FIdKpScvpServer: IDerObjectIdentifier;
    FIdKpScvpClient: IDerObjectIdentifier;
    FIdKpIpsecIke: IDerObjectIdentifier;
    FIdKpCapwapAc: IDerObjectIdentifier;
    FIdKpCapwapWtp: IDerObjectIdentifier;
    FIdKpCmcCa: IDerObjectIdentifier;
    FIdKpCmcRa: IDerObjectIdentifier;
    FIdKpCmKga: IDerObjectIdentifier;
    FIdKpSmartcardlogon: IDerObjectIdentifier;
    FIdKpMacAddress: IDerObjectIdentifier;
    FIdKpMsSgc: IDerObjectIdentifier;
    FScSysNodeNumber: IDerObjectIdentifier;
    FIdPkinitAuthData: IDerObjectIdentifier;
    FIdPkinitDHKeyData: IDerObjectIdentifier;
    FIdPkinitRkeyData: IDerObjectIdentifier;
    FKeyPurposeClientAuth: IDerObjectIdentifier;
    FKeyPurposeKdc: IDerObjectIdentifier;
    FIdKpNsSgc: IDerObjectIdentifier;

    class function GetAnyExtendedKeyUsage: IDerObjectIdentifier; static; inline;
    class function GetIdKpServerAuth: IDerObjectIdentifier; static; inline;
    class function GetIdKpClientAuth: IDerObjectIdentifier; static; inline;
    class function GetIdKpCodeSigning: IDerObjectIdentifier; static; inline;
    class function GetIdKpEmailProtection: IDerObjectIdentifier; static; inline;
    class function GetIdKpIpsecEndSystem: IDerObjectIdentifier; static; inline;
    class function GetIdKpIpsecTunnel: IDerObjectIdentifier; static; inline;
    class function GetIdKpIpsecUser: IDerObjectIdentifier; static; inline;
    class function GetIdKpTimeStamping: IDerObjectIdentifier; static; inline;
    class function GetIdKpOcspSigning: IDerObjectIdentifier; static; inline;
    class function GetIdKpDvcs: IDerObjectIdentifier; static; inline;
    class function GetIdKpSbgpCertAaServerAuth: IDerObjectIdentifier; static; inline;
    class function GetIdKpScvpResponder: IDerObjectIdentifier; static; inline;
    class function GetIdKpEapOverPpp: IDerObjectIdentifier; static; inline;
    class function GetIdKpEapOverLan: IDerObjectIdentifier; static; inline;
    class function GetIdKpScvpServer: IDerObjectIdentifier; static; inline;
    class function GetIdKpScvpClient: IDerObjectIdentifier; static; inline;
    class function GetIdKpIpsecIke: IDerObjectIdentifier; static; inline;
    class function GetIdKpCapwapAc: IDerObjectIdentifier; static; inline;
    class function GetIdKpCapwapWtp: IDerObjectIdentifier; static; inline;
    class function GetIdKpCmcCa: IDerObjectIdentifier; static; inline;
    class function GetIdKpCmcRa: IDerObjectIdentifier; static; inline;
    class function GetIdKpCmKga: IDerObjectIdentifier; static; inline;
    class function GetIdKpSmartcardlogon: IDerObjectIdentifier; static; inline;
    class function GetIdKpMacAddress: IDerObjectIdentifier; static; inline;
    class function GetIdKpMsSgc: IDerObjectIdentifier; static; inline;
    class function GetScSysNodeNumber: IDerObjectIdentifier; static; inline;
    class function GetIdPkinitAuthData: IDerObjectIdentifier; static; inline;
    class function GetIdPkinitDHKeyData: IDerObjectIdentifier; static; inline;
    class function GetIdPkinitRkeyData: IDerObjectIdentifier; static; inline;
    class function GetKeyPurposeClientAuth: IDerObjectIdentifier; static; inline;
    class function GetKeyPurposeKdc: IDerObjectIdentifier; static; inline;
    class function GetIdKpNsSgc: IDerObjectIdentifier; static; inline;

    class procedure Boot; static;
    class constructor Create;

  public
    class property AnyExtendedKeyUsage: IDerObjectIdentifier read GetAnyExtendedKeyUsage;
    class property IdKpServerAuth: IDerObjectIdentifier read GetIdKpServerAuth;
    class property IdKpClientAuth: IDerObjectIdentifier read GetIdKpClientAuth;
    class property IdKpCodeSigning: IDerObjectIdentifier read GetIdKpCodeSigning;
    class property IdKpEmailProtection: IDerObjectIdentifier read GetIdKpEmailProtection;
    class property IdKpIpsecEndSystem: IDerObjectIdentifier read GetIdKpIpsecEndSystem;
    class property IdKpIpsecTunnel: IDerObjectIdentifier read GetIdKpIpsecTunnel;
    class property IdKpIpsecUser: IDerObjectIdentifier read GetIdKpIpsecUser;
    class property IdKpTimeStamping: IDerObjectIdentifier read GetIdKpTimeStamping;
    class property IdKpOcspSigning: IDerObjectIdentifier read GetIdKpOcspSigning;
    class property IdKpDvcs: IDerObjectIdentifier read GetIdKpDvcs;
    class property IdKpSbgpCertAaServerAuth: IDerObjectIdentifier read GetIdKpSbgpCertAaServerAuth;
    class property IdKpScvpResponder: IDerObjectIdentifier read GetIdKpScvpResponder;
    class property IdKpEapOverPpp: IDerObjectIdentifier read GetIdKpEapOverPpp;
    class property IdKpEapOverLan: IDerObjectIdentifier read GetIdKpEapOverLan;
    class property IdKpScvpServer: IDerObjectIdentifier read GetIdKpScvpServer;
    class property IdKpScvpClient: IDerObjectIdentifier read GetIdKpScvpClient;
    class property IdKpIpsecIke: IDerObjectIdentifier read GetIdKpIpsecIke;
    class property IdKpCapwapAc: IDerObjectIdentifier read GetIdKpCapwapAc;
    class property IdKpCapwapWtp: IDerObjectIdentifier read GetIdKpCapwapWtp;
    class property IdKpCmcCa: IDerObjectIdentifier read GetIdKpCmcCa;
    class property IdKpCmcRa: IDerObjectIdentifier read GetIdKpCmcRa;
    class property IdKpCmKga: IDerObjectIdentifier read GetIdKpCmKga;
    class property IdKpSmartcardlogon: IDerObjectIdentifier read GetIdKpSmartcardlogon;
    class property IdKpMacAddress: IDerObjectIdentifier read GetIdKpMacAddress;
    class property IdKpMsSgc: IDerObjectIdentifier read GetIdKpMsSgc;
    class property ScSysNodeNumber: IDerObjectIdentifier read GetScSysNodeNumber;
    class property IdPkinitAuthData: IDerObjectIdentifier read GetIdPkinitAuthData;
    class property IdPkinitDHKeyData: IDerObjectIdentifier read GetIdPkinitDHKeyData;
    class property IdPkinitRkeyData: IDerObjectIdentifier read GetIdPkinitRkeyData;
    class property KeyPurposeClientAuth: IDerObjectIdentifier read GetKeyPurposeClientAuth;
    class property KeyPurposeKdc: IDerObjectIdentifier read GetKeyPurposeKdc;
    class property IdKpNsSgc: IDerObjectIdentifier read GetIdKpNsSgc;

  end;

  /// <summary>
  /// The X509Name object.
  /// </summary>
  TX509Name = class(TAsn1Encodable, IX509Name, IAsn1Choice)

  strict private
  var
    FOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    FValues: TCryptoLibStringArray;
    FValueList: TCryptoLibStringArray;
    FAdded: TCryptoLibBooleanArray; // Track which attributes are added to current RDN
    FSeq: IAsn1Sequence; // Cached sequence
    FConverter: IX509NameEntryConverter; // Converter for value encoding

  strict private
    class var
      FDefaultReverse: Boolean;
      FDefaultReverseLock: TCriticalSection;
      FDefaultSymbols: TDictionary<IDerObjectIdentifier, String>;
      FRFC2253Symbols: TDictionary<IDerObjectIdentifier, String>;
      FRFC1779Symbols: TDictionary<IDerObjectIdentifier, String>;
      FDefaultLookup: TDictionary<String, IDerObjectIdentifier>;
      FC: IDerObjectIdentifier;
      FO: IDerObjectIdentifier;
      FOU: IDerObjectIdentifier;
      FT: IDerObjectIdentifier;
      FCN: IDerObjectIdentifier;
      FStreet: IDerObjectIdentifier;
      FSerialNumber: IDerObjectIdentifier;
      FL: IDerObjectIdentifier;
      FST: IDerObjectIdentifier;
      FSurname: IDerObjectIdentifier;
      FGivenName: IDerObjectIdentifier;
      FInitials: IDerObjectIdentifier;
      FGeneration: IDerObjectIdentifier;
      FUniqueIdentifier: IDerObjectIdentifier;
      FDescription: IDerObjectIdentifier;
      FBusinessCategory: IDerObjectIdentifier;
      FPostalCode: IDerObjectIdentifier;
      FDnQualifier: IDerObjectIdentifier;
      FPseudonym: IDerObjectIdentifier;
      FRole: IDerObjectIdentifier;
      FDateOfBirth: IDerObjectIdentifier;
      FPlaceOfBirth: IDerObjectIdentifier;
      FGender: IDerObjectIdentifier;
      FCountryOfCitizenship: IDerObjectIdentifier;
      FCountryOfResidence: IDerObjectIdentifier;
      FNameAtBirth: IDerObjectIdentifier;
      FPostalAddress: IDerObjectIdentifier;
      FDmdName: IDerObjectIdentifier;
      FTelephoneNumber: IDerObjectIdentifier;
      FOrganizationIdentifier: IDerObjectIdentifier;
      FName: IDerObjectIdentifier;
      FEmailAddress: IDerObjectIdentifier;
      FUnstructuredName: IDerObjectIdentifier;
      FUnstructuredAddress: IDerObjectIdentifier;
      FE: IDerObjectIdentifier;
      FDC: IDerObjectIdentifier;
      FUID: IDerObjectIdentifier;
      FJurisdictionC: IDerObjectIdentifier;
      FJurisdictionST: IDerObjectIdentifier;
      FJurisdictionL: IDerObjectIdentifier;

    class procedure Boot; static;
    class function GetDefaultReverse: Boolean; static;
    class procedure SetDefaultReverse(const AValue: Boolean); static;
    class constructor Create;
    class destructor Destroy;

  strict protected
    function GetOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetValues: TCryptoLibStringArray; overload;
    function GetValueList: TCryptoLibStringArray; overload;
    function GetValue(const AOid: IDerObjectIdentifier): String;
    function GetValues(const AOid: IDerObjectIdentifier): TCryptoLibStringArray; overload;

  public
    // OID constants
    class property C: IDerObjectIdentifier read FC;
    class property O: IDerObjectIdentifier read FO;
    class property OU: IDerObjectIdentifier read FOU;
    class property T: IDerObjectIdentifier read FT;
    class property CN: IDerObjectIdentifier read FCN;
    class property Street: IDerObjectIdentifier read FStreet;
    class property SerialNumber: IDerObjectIdentifier read FSerialNumber;
    class property L: IDerObjectIdentifier read FL;
    class property ST: IDerObjectIdentifier read FST;
    class property Surname: IDerObjectIdentifier read FSurname;
    class property GivenName: IDerObjectIdentifier read FGivenName;
    class property Initials: IDerObjectIdentifier read FInitials;
    class property Generation: IDerObjectIdentifier read FGeneration;
    class property UniqueIdentifier: IDerObjectIdentifier read FUniqueIdentifier;
    class property Description: IDerObjectIdentifier read FDescription;
    class property BusinessCategory: IDerObjectIdentifier read FBusinessCategory;
    class property PostalCode: IDerObjectIdentifier read FPostalCode;
    class property DnQualifier: IDerObjectIdentifier read FDnQualifier;
    class property Pseudonym: IDerObjectIdentifier read FPseudonym;
    class property Role: IDerObjectIdentifier read FRole;
    class property DateOfBirth: IDerObjectIdentifier read FDateOfBirth;
    class property PlaceOfBirth: IDerObjectIdentifier read FPlaceOfBirth;
    class property Gender: IDerObjectIdentifier read FGender;
    class property CountryOfCitizenship: IDerObjectIdentifier read FCountryOfCitizenship;
    class property CountryOfResidence: IDerObjectIdentifier read FCountryOfResidence;
    class property NameAtBirth: IDerObjectIdentifier read FNameAtBirth;
    class property PostalAddress: IDerObjectIdentifier read FPostalAddress;
    class property DmdName: IDerObjectIdentifier read FDmdName;
    class property TelephoneNumber: IDerObjectIdentifier read FTelephoneNumber;
    class property OrganizationIdentifier: IDerObjectIdentifier read FOrganizationIdentifier;
    class property Name: IDerObjectIdentifier read FName;
    class property EmailAddress: IDerObjectIdentifier read FEmailAddress;
    class property UnstructuredName: IDerObjectIdentifier read FUnstructuredName;
    class property UnstructuredAddress: IDerObjectIdentifier read FUnstructuredAddress;
    class property E: IDerObjectIdentifier read FE;
    class property DC: IDerObjectIdentifier read FDC;
    class property UID: IDerObjectIdentifier read FUID;
    class property JurisdictionC: IDerObjectIdentifier read FJurisdictionC;
    class property JurisdictionST: IDerObjectIdentifier read FJurisdictionST;
    class property JurisdictionL: IDerObjectIdentifier read FJurisdictionL;

    class property DefaultReverse: Boolean read GetDefaultReverse write SetDefaultReverse;
    class property DefaultSymbols: TDictionary<IDerObjectIdentifier, String> read FDefaultSymbols;
    class property RFC2253Symbols: TDictionary<IDerObjectIdentifier, String> read FRFC2253Symbols;
    class property RFC1779Symbols: TDictionary<IDerObjectIdentifier, String> read FRFC1779Symbols;
    class property DefaultLookup: TDictionary<String, IDerObjectIdentifier> read FDefaultLookup;

    class function GetInstance(AObj: TObject): IX509Name; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IX509Name; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IX509Name; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IX509Name; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IX509Name; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IX509Name; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AName: String); overload;
    constructor Create(const AReverse: Boolean; const AName: String); overload;
    constructor Create(const AReverse: Boolean; const ATable: TDictionary<String, String>;
      const AName: String); overload;
    constructor Create(const AOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
      const AValues: TCryptoLibStringArray); overload;
    constructor Create(const AOrdering: TList<IDerObjectIdentifier>;
      const AAttributes: TDictionary<IDerObjectIdentifier, String>); overload;
    constructor Create(const AOrdering: TList<IDerObjectIdentifier>;
      const AAttributes: TDictionary<IDerObjectIdentifier, String>;
      const AConverter: IX509NameEntryConverter); overload;
    constructor Create(const AOids: TList<IDerObjectIdentifier>;
      const AValues: TList<String>); overload;
    constructor Create(const AOids: TList<IDerObjectIdentifier>;
      const AValues: TList<String>; const AConverter: IX509NameEntryConverter); overload;
    constructor Create(const ADirName: String; const AConverter: IX509NameEntryConverter); overload;
    constructor Create(const AReverse: Boolean; const ADirName: String;
      const AConverter: IX509NameEntryConverter); overload;
    constructor Create(const AReverse: Boolean; const ALookup: TDictionary<String, IDerObjectIdentifier>;
      const ADirName: String); overload;
    constructor Create(const AReverse: Boolean; const ALookup: TDictionary<String, IDerObjectIdentifier>;
      const ADirName: String; const AConverter: IX509NameEntryConverter); overload;

    function GetOidList: TCryptoLibGenericArray<IDerObjectIdentifier>;
    function GetValueList(const AOid: IDerObjectIdentifier = nil): TCryptoLibStringArray; overload;
    function Equivalent(const AOther: IX509Name; AInOrder: Boolean = False): Boolean;
    function ToString(AReverse: Boolean; const AOidSymbols: TDictionary<IDerObjectIdentifier, String>): String; reintroduce; overload;
    function ToString: String; overload; override;
    function ToString(const AOid: IDerObjectIdentifier): String; reintroduce; overload;

    function ToAsn1Object: IAsn1Object; override;

    property Oids: TCryptoLibGenericArray<IDerObjectIdentifier> read GetOids;
    property Values: TCryptoLibStringArray read GetValues;

  private
    class function CreateDefaultConverter: IX509NameEntryConverter; static;
    class function DecodeOid(const AName: String;
      const ALookup: TDictionary<String, IDerObjectIdentifier>): IDerObjectIdentifier; static;
    class procedure AppendValue(const ABuf: TStringBuilder;
      const AOidSymbols: TDictionary<IDerObjectIdentifier, String>;
      const AOid: IDerObjectIdentifier; const AVal: String); static;
    class function EquivalentStrings(const AS1, AS2: String): Boolean; static;
    class function NextToken(const ATokenizer: IX509NameTokenizer): String; overload; static;
    class function NextToken(const ATokenizer: IX509NameTokenizer; AExpectMoreTokens: Boolean): String; overload; static;
  strict private
    procedure AddAttribute(const ALookup: TDictionary<String, IDerObjectIdentifier>;
      const AToken: String; AAdded: Boolean; const AOidList: TList<IDerObjectIdentifier>;
      const AValueList: TList<String>; const AAddedList: TList<Boolean>);

  end;

  /// <summary>
  /// The Time object (CHOICE type: Asn1UtcTime or Asn1GeneralizedTime).
  /// <pre>
  /// Time ::= CHOICE {
  ///             utcTime        UTCTime,
  ///             generalTime    GeneralizedTime }
  /// </pre>
  /// </summary>
  TTime = class(TAsn1Encodable, ITime, IAsn1Choice)

  strict private
  var
    FTimeObject: IAsn1Object;

  strict protected
    function GetTimeObject: IAsn1Object;

  public
    class function GetInstance(AObj: TObject): ITime; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ITime; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ITime; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ITime; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): ITime; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ITime; static;

    constructor Create(const AGeneralizedTime: IAsn1GeneralizedTime); overload;
    constructor Create(const AUtcTime: IAsn1UtcTime); overload;
    constructor Create(const ADateTime: TDateTime); overload;
    constructor CreateFromUtc(const AUtcDateTime: TDateTime);

    function ToDateTime: TDateTime;
    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

    property TimeObject: IAsn1Object read GetTimeObject;

  end;

  /// <summary>
  /// The Validity object.
  /// </summary>
  TValidity = class(TAsn1Encodable, IValidity)

  strict private
  var
    FNotBefore: ITime;
    FNotAfter: ITime;

  strict protected
    function GetNotBefore: ITime;
    function GetNotAfter: ITime;

  public
    class function GetInstance(AObj: TObject): IValidity; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IValidity; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IValidity; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IValidity; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IValidity; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ANotBefore, ANotAfter: ITime); overload;

    function ToAsn1Object: IAsn1Object; override;

    property NotBefore: ITime read GetNotBefore;
    property NotAfter: ITime read GetNotAfter;

  end;

  /// <summary>
  /// CrlEntry - revoked certificate entry in a CRL.
  /// </summary>
  TCrlEntry = class(TAsn1Encodable, ICrlEntry)

  strict private
  var
    FSeq: IAsn1Sequence;
    FUserCertificate: IDerInteger;
    FRevocationDate: ITime;
    FCrlEntryExtensions: IX509Extensions;

  strict protected
    function GetUserCertificate: IDerInteger;
    function GetRevocationDate: ITime;
    function GetExtensions: IX509Extensions;

  public
    class function GetInstance(AObj: TObject): ICrlEntry; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICrlEntry; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICrlEntry; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICrlEntry; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICrlEntry; static;

    constructor Create(const ASeq: IAsn1Sequence);

    function ToAsn1Object: IAsn1Object; override;

    property UserCertificate: IDerInteger read GetUserCertificate;
    property RevocationDate: ITime read GetRevocationDate;
    property Extensions: IX509Extensions read GetExtensions;

  end;

  /// <summary>
  /// The AltSignatureAlgorithm object.
  /// </summary>
  TAltSignatureAlgorithm = class(TAsn1Encodable, IAltSignatureAlgorithm)

  strict private
  var
    FAlgorithm: IAlgorithmIdentifier;

  strict protected
    function GetAlgorithm: IAlgorithmIdentifier;

  public
    class function GetInstance(AObj: TObject): IAltSignatureAlgorithm; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAltSignatureAlgorithm; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAltSignatureAlgorithm; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAltSignatureAlgorithm; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAltSignatureAlgorithm; static;
    class function FromExtensions(const AExtensions: IX509Extensions): IAltSignatureAlgorithm; static;

    constructor Create(const AAlgorithm: IAlgorithmIdentifier); overload;
    constructor Create(const AAlgorithm: IDerObjectIdentifier); overload;
    constructor Create(const AAlgorithm: IDerObjectIdentifier;
      const AParameters: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;

  end;

  /// <summary>
  /// The AltSignatureValue object.
  /// </summary>
  TAltSignatureValue = class(TAsn1Encodable, IAltSignatureValue)

  strict private
  var
    FSignature: IDerBitString;

  strict protected
    function GetSignature: IDerBitString;

  public
    class function GetInstance(AObj: TObject): IAltSignatureValue; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAltSignatureValue; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAltSignatureValue; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAltSignatureValue; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAltSignatureValue; static;
    class function FromExtensions(const AExtensions: IX509Extensions): IAltSignatureValue; static;

    constructor Create(const ASignature: IDerBitString); overload;
    constructor Create(const ASignature: TCryptoLibByteArray); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Signature: IDerBitString read GetSignature;

  end;

  /// <summary>
  /// The SubjectKeyIdentifier object.
  /// </summary>
  TSubjectKeyIdentifier = class(TAsn1Encodable, ISubjectKeyIdentifier)

  strict private
  var
    FKeyIdentifier: TCryptoLibByteArray;

  strict protected
    function GetKeyIdentifier: TCryptoLibByteArray;

  public
    class function GetInstance(AObj: TObject): ISubjectKeyIdentifier; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ISubjectKeyIdentifier; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ISubjectKeyIdentifier; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ISubjectKeyIdentifier; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISubjectKeyIdentifier; static;

    constructor Create(const AKeyID: TCryptoLibByteArray); overload;
    constructor Create(const AKeyID: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

  end;

  /// <summary>
  /// The BasicConstraints object.
  /// </summary>
  TBasicConstraints = class(TAsn1Encodable, IBasicConstraints)

  strict private
  var
    FCA: IDerBoolean;
    FPathLenConstraint: IDerInteger;

  strict protected
    function IsCA: Boolean;
    function GetPathLenConstraint: TBigInteger;

  public
    class function GetInstance(AObj: TObject): IBasicConstraints; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IBasicConstraints; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IBasicConstraints; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IBasicConstraints; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IBasicConstraints; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(ACA: Boolean); overload;
    constructor Create(APathLenConstraint: Int32); overload;

    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

    property PathLenConstraint: TBigInteger read GetPathLenConstraint;

  end;

  /// <summary>
  /// The SubjectPublicKeyInfo object.
  /// </summary>
  TSubjectPublicKeyInfo = class(TAsn1Encodable, ISubjectPublicKeyInfo)

  strict private
  var
    FAlgorithm: IAlgorithmIdentifier;
    FPublicKey: IDerBitString;

  strict protected
    function GetAlgorithm: IAlgorithmIdentifier;
    function GetPublicKey: IDerBitString;

  public
    function ParsePublicKey: IAsn1Object;
    class function GetInstance(AObj: TObject): ISubjectPublicKeyInfo; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ISubjectPublicKeyInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ISubjectPublicKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ISubjectPublicKeyInfo; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): ISubjectPublicKeyInfo; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISubjectPublicKeyInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAlgID: IAlgorithmIdentifier;
      const APublicKey: IDerBitString); overload;
    constructor Create(const AAlgID: IAlgorithmIdentifier;
      const APublicKey: IAsn1Encodable); overload;
    constructor Create(const AAlgID: IAlgorithmIdentifier;
      const APublicKey: TCryptoLibByteArray); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;
    property PublicKey: IDerBitString read GetPublicKey;

  end;

  /// <summary>
  /// The SubjectAltPublicKeyInfo object.
  /// </summary>
  TSubjectAltPublicKeyInfo = class(TAsn1Encodable, ISubjectAltPublicKeyInfo)

  strict private
  var
    FAlgorithm: IAlgorithmIdentifier;
    FSubjectAltPublicKey: IDerBitString;

  strict protected
    function GetAlgorithm: IAlgorithmIdentifier;
    function GetSubjectAltPublicKey: IDerBitString;

  public
    class function GetInstance(AObj: TObject): ISubjectAltPublicKeyInfo; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ISubjectAltPublicKeyInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ISubjectAltPublicKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ISubjectAltPublicKeyInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISubjectAltPublicKeyInfo; static;
    class function FromExtensions(const AExtensions: IX509Extensions): ISubjectAltPublicKeyInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAlgorithm: IAlgorithmIdentifier;
      const ASubjectAltPublicKey: IDerBitString); overload;
    constructor Create(const ASubjectPublicKeyInfo: ISubjectPublicKeyInfo); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Algorithm: IAlgorithmIdentifier read GetAlgorithm;
    property SubjectAltPublicKey: IDerBitString read GetSubjectAltPublicKey;

  end;

  /// <summary>
  /// The TbsCertificateStructure object.
  /// </summary>
  TTbsCertificateStructure = class(TAsn1Encodable, ITbsCertificateStructure)

  strict private
  class var
    FAllowNonDERTbsCertificate: Boolean;
  var
    FVersion: IDerInteger;
    FSerialNumber: IDerInteger;
    FSignature: IAlgorithmIdentifier;
    FIssuer: IX509Name;
    FValidity: IValidity;
    FSubject: IX509Name;
    FSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    FIssuerUniqueID: IDerBitString;
    FSubjectUniqueID: IDerBitString;
    FExtensions: IX509Extensions;
    FSeq: IAsn1Sequence;

  strict protected
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

  public
    class constructor Create;
    
    class function GetInstance(AObj: TObject): ITbsCertificateStructure; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ITbsCertificateStructure; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ITbsCertificateStructure; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ITbsCertificateStructure; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ITbsCertificateStructure; static;
    
    class function GetAllowNonDERTbsCertificate: Boolean; static;
    class procedure SetAllowNonDERTbsCertificate(AValue: Boolean); static;
    
    class property AllowNonDERTbsCertificate: Boolean read GetAllowNonDERTbsCertificate write SetAllowNonDERTbsCertificate;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AVersion: IDerInteger; const ASerialNumber: IDerInteger;
      const ASignature: IAlgorithmIdentifier; const AIssuer: IX509Name;
      const AValidity: IValidity; const ASubject: IX509Name;
      const ASubjectPublicKeyInfo: ISubjectPublicKeyInfo;
      const AIssuerUniqueID: IDerBitString; const ASubjectUniqueID: IDerBitString;
      const AExtensions: IX509Extensions); overload;

    function ToAsn1Object: IAsn1Object; override;

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
  /// The X509CertificateStructure object.
  /// </summary>
  TX509CertificateStructure = class(TAsn1Encodable, IX509CertificateStructure)

  strict private
  var
    FTbsCertificate: ITbsCertificateStructure;
    FSignatureAlgorithm: IAlgorithmIdentifier;
    FSignature: IDerBitString;

  strict protected
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

  public
    class function GetInstance(AObj: TObject): IX509CertificateStructure; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IX509CertificateStructure; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IX509CertificateStructure; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IX509CertificateStructure; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IX509CertificateStructure; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IX509CertificateStructure; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ATbsCert: ITbsCertificateStructure;
      const ASigAlgID: IAlgorithmIdentifier; const ASig: IDerBitString); overload;

    function ToAsn1Object: IAsn1Object; override;

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
  /// The AttributeX509 object.
  /// </summary>
  TAttributeX509 = class(TAsn1Encodable, IAttributeX509)

  strict private
  var
    FAttrType: IDerObjectIdentifier;
    FAttrValues: IAsn1Set;

  strict protected
    function GetAttrType: IDerObjectIdentifier;
    function GetAttrValues: IAsn1Set;
    function GetAttributeValues: TCryptoLibGenericArray<IAsn1Encodable>;

  public
    class function GetInstance(AObj: TObject): IAttributeX509; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAttributeX509; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeX509; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributeX509; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributeX509; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAttrType: IDerObjectIdentifier; const AAttrValues: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property AttrValues: IAsn1Set read GetAttrValues;

  end;

  /// <summary>
  /// The AttCertValidityPeriod object.
  /// </summary>
  TAttCertValidityPeriod = class(TAsn1Encodable, IAttCertValidityPeriod)

  strict private
  var
    FNotBeforeTime: IAsn1GeneralizedTime;
    FNotAfterTime: IAsn1GeneralizedTime;

  strict protected
    function GetNotBeforeTime: IAsn1GeneralizedTime;
    function GetNotAfterTime: IAsn1GeneralizedTime;

  public
    class function GetInstance(AObj: TObject): IAttCertValidityPeriod; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAttCertValidityPeriod; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttCertValidityPeriod; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAttCertValidityPeriod; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttCertValidityPeriod; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ANotBeforeTime, ANotAfterTime: IAsn1GeneralizedTime); overload;

    function ToAsn1Object: IAsn1Object; override;

    property NotBeforeTime: IAsn1GeneralizedTime read GetNotBeforeTime;
    property NotAfterTime: IAsn1GeneralizedTime read GetNotAfterTime;

  end;

  /// <summary>
  /// The PolicyInformation object.
  /// </summary>
  TPolicyInformation = class(TAsn1Encodable, IPolicyInformation)

  strict private
  var
    FPolicyIdentifier: IDerObjectIdentifier;
    FPolicyQualifiers: IAsn1Sequence;

  strict protected
    function GetPolicyIdentifier: IDerObjectIdentifier;
    function GetPolicyQualifiers: IAsn1Sequence;

  public
    class function GetInstance(AObj: TObject): IPolicyInformation; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IPolicyInformation; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPolicyInformation; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPolicyInformation; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPolicyInformation; static;

    constructor Create(const APolicyIdentifier: IDerObjectIdentifier); overload;
    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const APolicyIdentifier: IDerObjectIdentifier;
      const APolicyQualifiers: IAsn1Sequence); overload;

    function ToAsn1Object: IAsn1Object; override;

    property PolicyIdentifier: IDerObjectIdentifier read GetPolicyIdentifier;
    property PolicyQualifiers: IAsn1Sequence read GetPolicyQualifiers;

  end;

  /// <summary>
  /// The IssuerSerial object.
  /// </summary>
  TIssuerSerial = class(TAsn1Encodable, IIssuerSerial)

  strict private
  var
    FIssuer: IGeneralNames;
    FSerial: IDerInteger;
    FIssuerUid: IDerBitString;

  strict protected
    function GetIssuer: IGeneralNames;
    function GetSerial: IDerInteger;
    function GetIssuerUid: IDerBitString;

  public
    class function GetInstance(AObj: TObject): IIssuerSerial; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IIssuerSerial; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IIssuerSerial; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IIssuerSerial; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IIssuerSerial; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IIssuerSerial; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AIssuer: IX509Name; const ASerial: IDerInteger); overload;
    constructor Create(const AIssuer: IGeneralNames; const ASerial: IDerInteger); overload;
    constructor Create(const AIssuer: IGeneralNames; const ASerial: IDerInteger;
      const AIssuerUid: IDerBitString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Issuer: IGeneralNames read GetIssuer;
    property Serial: IDerInteger read GetSerial;
    property IssuerUid: IDerBitString read GetIssuerUid;

  end;

  /// <summary>
  /// The V2Form object.
  /// </summary>
  TV2Form = class(TAsn1Encodable, IV2Form)

  strict private
  var
    FIssuerName: IGeneralNames;
    FBaseCertificateID: IIssuerSerial;
    FObjectDigestInfo: IObjectDigestInfo;

  strict protected
    function GetIssuerName: IGeneralNames;
    function GetBaseCertificateID: IIssuerSerial;
    function GetObjectDigestInfo: IObjectDigestInfo;

  public
    class function GetInstance(AObj: TObject): IV2Form; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IV2Form; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IV2Form; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IV2Form; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IV2Form; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IV2Form; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AIssuerName: IGeneralNames); overload;
    constructor Create(const AIssuerName: IGeneralNames; const ABaseCertificateID: IIssuerSerial); overload;
    constructor Create(const AIssuerName: IGeneralNames; const AObjectDigestInfo: IObjectDigestInfo); overload;
    constructor Create(const AIssuerName: IGeneralNames; const ABaseCertificateID: IIssuerSerial;
      const AObjectDigestInfo: IObjectDigestInfo); overload;

    function ToAsn1Object: IAsn1Object; override;

    property IssuerName: IGeneralNames read GetIssuerName;
    property BaseCertificateID: IIssuerSerial read GetBaseCertificateID;
    property ObjectDigestInfo: IObjectDigestInfo read GetObjectDigestInfo;

  end;

  /// <summary>
  /// The ObjectDigestInfo object.
  /// </summary>
  TObjectDigestInfo = class(TAsn1Encodable, IObjectDigestInfo)

  strict private
  var
    FDigestedObjectType: IDerEnumerated;
    FOtherObjectTypeID: IDerObjectIdentifier;
    FDigestAlgorithm: IAlgorithmIdentifier;
    FObjectDigest: IDerBitString;

  public
    const
      PublicKey = 0;
      PublicKeyCert = 1;
      OtherObjectDigest = 2;

  strict protected
    function GetDigestedObjectType: IDerEnumerated;
    function GetOtherObjectTypeID: IDerObjectIdentifier;
    function GetDigestAlgorithm: IAlgorithmIdentifier;
    function GetObjectDigest: IDerBitString;

  public
    class function GetInstance(AObj: TObject): IObjectDigestInfo; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IObjectDigestInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IObjectDigestInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AIsExplicit: Boolean): IObjectDigestInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IObjectDigestInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(ADigestedObjectType: Int32; const AOtherObjectTypeID: String;
      const ADigestAlgorithm: IAlgorithmIdentifier; const AObjectDigest: TCryptoLibByteArray); overload;

    function ToAsn1Object: IAsn1Object; override;

    property DigestedObjectType: IDerEnumerated read GetDigestedObjectType;
    property OtherObjectTypeID: IDerObjectIdentifier read GetOtherObjectTypeID;
    property DigestAlgorithm: IAlgorithmIdentifier read GetDigestAlgorithm;
    property ObjectDigest: IDerBitString read GetObjectDigest;

  end;

  /// <summary>
  /// The DistributionPointName object.
  /// </summary>
  TDistributionPointName = class(TAsn1Encodable, IDistributionPointName, IAsn1Choice)

  strict private
  var
    FType: Int32;
    FName: IAsn1Encodable;

  public
    const
      FullName = 0;
      NameRelativeToCrlIssuer = 1;

  strict protected
    class function GetOptionalBaseObject(const ATaggedObject: IAsn1TaggedObject): IAsn1Encodable; static;

  public
    class function GetInstance(AObj: TObject): IDistributionPointName; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDistributionPointName; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDistributionPointName; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDistributionPointName; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IDistributionPointName; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDistributionPointName; static;

    constructor Create(const AName: IGeneralNames); overload;
    constructor Create(AType: Int32; const AName: IAsn1Encodable); overload;

    function GetType: Int32;
    function GetName: IAsn1Encodable;

    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

  end;

  /// <summary>
  /// The ReasonFlags object.
  /// </summary>
  TReasonFlags = class(TDerBitString, IReasonFlags)

  public
    const
      Unused = (1 shl 7);
      KeyCompromise = (1 shl 6);
      CACompromise = (1 shl 5);
      AffiliationChanged = (1 shl 4);
      Superseded = (1 shl 3);
      CessationOfOperation = (1 shl 2);
      CertificateHold = (1 shl 1);
      PrivilegeWithdrawn = (1 shl 0);
      AACompromise = (1 shl 15);

  public
    constructor Create(AReasons: Int32); overload;
    constructor Create(const AReasons: IDerBitString); overload;

  end;

  /// <summary>
  /// CrlReason - CRL reason enumeration.
  /// </summary>
  /// <remarks>
  /// <para>
  /// Based on the X.509 CRLReason enumeration:
  /// </para>
  /// <code>
  /// CRLReason ::= Enumerated {
  ///   unspecified             (0),
  ///   keyCompromise           (1),
  ///   cACompromise            (2),
  ///   affiliationChanged      (3),
  ///   superseded              (4),
  ///   cessationOfOperation    (5),
  ///   certificateHold         (6),
  ///   removeFromCRL           (8),
  ///   privilegeWithdrawn      (9),
  ///   aACompromise           (10)
  /// }
  /// </code>
  /// </remarks>
  TCrlReason = class(TDerEnumerated, ICrlReason)

  public
  const
    Unspecified = 0;
    KeyCompromise = 1;
    CACompromise = 2;
    AffiliationChanged = 3;
    Superseded = 4;
    CessationOfOperation = 5;
    CertificateHold = 6;
    // 7 -> Unknown
    RemoveFromCrl = 8;
    PrivilegeWithdrawn = 9;
    AACompromise = 10;

    constructor Create(AReason: Int32); overload;
    constructor Create(const AReason: IDerEnumerated); overload;

    function ToString: String; override;

  end;

  /// <summary>
  /// TbsCertificateList - TBSCertList (RFC-2459).
  /// </summary>
  TTbsCertificateList = class(TAsn1Encodable, ITbsCertificateList)

  strict private
  var
    FSeq: IAsn1Sequence;
    FVersion: IDerInteger;
    FSignature: IAlgorithmIdentifier;
    FIssuer: IX509Name;
    FThisUpdate: ITime;
    FNextUpdate: ITime;
    FRevokedCertificates: IAsn1Sequence;
    FCrlExtensions: IX509Extensions;

  strict protected
    function GetVersion: Int32;
    function GetVersionNumber: IDerInteger;
    function GetSignature: IAlgorithmIdentifier;
    function GetIssuer: IX509Name;
    function GetThisUpdate: ITime;
    function GetNextUpdate: ITime;
    function GetExtensions: IX509Extensions;

  public
    class function GetInstance(AObj: TObject): ITbsCertificateList; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ITbsCertificateList; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ITbsCertificateList; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ITbsCertificateList; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ITbsCertificateList; static;

    constructor Create(const ASeq: IAsn1Sequence);

    function ToAsn1Object: IAsn1Object; override;
    function GetRevokedCertificates: TCryptoLibGenericArray<ICrlEntry>;

    property Version: Int32 read GetVersion;
    property VersionNumber: IDerInteger read GetVersionNumber;
    property Signature: IAlgorithmIdentifier read GetSignature;
    property Issuer: IX509Name read GetIssuer;
    property ThisUpdate: ITime read GetThisUpdate;
    property NextUpdate: ITime read GetNextUpdate;
    property Extensions: IX509Extensions read GetExtensions;

  end;

  /// <summary>
  /// The DistributionPoint object.
  /// </summary>
  TDistributionPoint = class(TAsn1Encodable, IDistributionPoint)

  strict private
  var
    FDistributionPointName: IDistributionPointName;
    FReasons: IReasonFlags;
    FCrlIssuer: IGeneralNames;

  strict protected
    function GetDistributionPointName: IDistributionPointName;
    function GetReasons: IReasonFlags;
    function GetCrlIssuer: IGeneralNames;

  public
    class function GetInstance(AObj: TObject): IDistributionPoint; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IDistributionPoint; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IDistributionPoint; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IDistributionPoint; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IDistributionPoint; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ADistributionPointName: IDistributionPointName;
      const AReasons: IReasonFlags; const ACrlIssuer: IGeneralNames); overload;

    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

    property DistributionPointName: IDistributionPointName read GetDistributionPointName;
    property Reasons: IReasonFlags read GetReasons;
    property CrlIssuer: IGeneralNames read GetCrlIssuer;

  end;

  /// <remarks>
  /// <code>
  /// IssuingDistributionPoint ::= SEQUENCE {
  ///   distributionPoint          [0] DistributionPointName OPTIONAL,
  ///   onlyContainsUserCerts      [1] BOOLEAN DEFAULT FALSE,
  ///   onlyContainsCACerts        [2] BOOLEAN DEFAULT FALSE,
  ///   onlySomeReasons            [3] ReasonFlags OPTIONAL,
  ///   indirectCRL                [4] BOOLEAN DEFAULT FALSE,
  ///   onlyContainsAttributeCerts [5] BOOLEAN DEFAULT FALSE
  /// }
  /// </code>
  /// </remarks>
  TIssuingDistributionPoint = class(TAsn1Encodable, IIssuingDistributionPoint)

  strict private
  var
    FDistributionPoint: IDistributionPointName;
    FOnlyContainsUserCerts: IDerBoolean;
    FOnlyContainsCACerts: IDerBoolean;
    FOnlySomeReasons: IReasonFlags;
    FIndirectCRL: IDerBoolean;
    FOnlyContainsAttributeCerts: IDerBoolean;
    FSeq: IAsn1Sequence;

  strict protected
    function GetDistributionPoint: IDistributionPointName;
    function GetOnlyContainsUserCerts: Boolean;
    function GetOnlyContainsCACerts: Boolean;
    function GetOnlySomeReasons: IReasonFlags;
    function GetIsIndirectCrl: Boolean;
    function GetOnlyContainsAttributeCerts: Boolean;

  public
    class function GetInstance(AObj: TObject): IIssuingDistributionPoint; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IIssuingDistributionPoint; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IIssuingDistributionPoint; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IIssuingDistributionPoint; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IIssuingDistributionPoint; static;

    constructor Create(const ADistributionPoint: IDistributionPointName;
      AOnlyContainsUserCerts, AOnlyContainsCACerts: Boolean;
      const AOnlySomeReasons: IReasonFlags; AIndirectCRL, AOnlyContainsAttributeCerts: Boolean); overload;
    constructor Create(const ASeq: IAsn1Sequence); overload;

    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

    property DistributionPoint: IDistributionPointName read GetDistributionPoint;
    property OnlyContainsUserCerts: Boolean read GetOnlyContainsUserCerts;
    property OnlyContainsCACerts: Boolean read GetOnlyContainsCACerts;
    property OnlySomeReasons: IReasonFlags read GetOnlySomeReasons;
    property IsIndirectCrl: Boolean read GetIsIndirectCrl;
    property OnlyContainsAttributeCerts: Boolean read GetOnlyContainsAttributeCerts;

  end;

  /// <summary>
  /// PKIX RFC-2459.
  /// </summary>
  /// <remarks>
  /// <para>
  /// The X.509 v2 CRL syntax is defined as follows. For signature calculation,
  /// the data that is to be signed is ASN.1 DER-encoded.
  /// </para>
  /// <code>
  /// CertificateList ::= SEQUENCE {
  ///     tbsCertList          TbsCertList,
  ///     signatureAlgorithm   AlgorithmIdentifier,
  ///     signatureValue       BIT STRING
  /// }
  /// </code>
  /// </remarks>
  TCertificateList = class(TAsn1Encodable, ICertificateList)

  strict private
  var
    FTbsCertList: ITbsCertificateList;
    FSignatureAlgorithm: IAlgorithmIdentifier;
    FSignatureValue: IDerBitString;

  strict protected
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

  public
    class function GetInstance(AObj: TObject): ICertificateList; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICertificateList; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICertificateList; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICertificateList; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): ICertificateList; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertificateList; static;

    constructor Create(const ASeq: IAsn1Sequence);

    function ToAsn1Object: IAsn1Object; override;

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
  /// The AttCertIssuer object.
  /// </summary>
  TAttCertIssuer = class(TAsn1Encodable, IAttCertIssuer, IAsn1Choice)

  strict private
  var
    FObj: IAsn1Encodable;
    FChoiceObj: IAsn1Object;

  strict protected
    function GetIssuer: IAsn1Encodable;

  public
    class function GetInstance(AObj: TObject): IAttCertIssuer; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAttCertIssuer; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttCertIssuer; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AIsExplicit: Boolean): IAttCertIssuer; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IAttCertIssuer; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttCertIssuer; static;

    constructor Create(const ANames: IGeneralNames); overload;
    constructor Create(const AV2Form: IV2Form); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Issuer: IAsn1Encodable read GetIssuer;

  end;

  /// <summary>
  /// The Holder object.
  /// </summary>
  THolder = class(TAsn1Encodable, IHolder)

  strict private
  var
    FBaseCertificateID: IIssuerSerial;
    FEntityName: IGeneralNames;
    FObjectDigestInfo: IObjectDigestInfo;
    FVersion: Int32;

  strict protected
    function GetVersion: Int32;
    function GetBaseCertificateID: IIssuerSerial;
    function GetEntityName: IGeneralNames;
    function GetObjectDigestInfo: IObjectDigestInfo;

  public
    class function GetInstance(AObj: TObject): IHolder; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IHolder; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IHolder; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IHolder; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IHolder; static;

    constructor Create(const ATagObj: IAsn1TaggedObject); overload;
    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ABaseCertificateID: IIssuerSerial); overload;
    constructor Create(const ABaseCertificateID: IIssuerSerial; AVersion: Int32); overload;
    constructor Create(const AEntityName: IGeneralNames); overload;
    constructor Create(const AEntityName: IGeneralNames; AVersion: Int32); overload;
    constructor Create(const AObjectDigestInfo: IObjectDigestInfo); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: Int32 read GetVersion;
    property BaseCertificateID: IIssuerSerial read GetBaseCertificateID;
    property EntityName: IGeneralNames read GetEntityName;
    property ObjectDigestInfo: IObjectDigestInfo read GetObjectDigestInfo;

  end;

  /// <summary>
  /// The AttributeCertificate object.
  /// </summary>
  TAttributeCertificate = class(TAsn1Encodable, IAttributeCertificate)

  strict private
  var
    FACInfo: IAttributeCertificateInfo;
    FSignatureAlgorithm: IAlgorithmIdentifier;
    FSignatureValue: IDerBitString;

  strict protected
    function GetACInfo: IAttributeCertificateInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignatureValue: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;

  public
    class function GetInstance(AObj: TObject): IAttributeCertificate; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAttributeCertificate; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeCertificate; overload; static;
    class function GetInstance(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributeCertificate; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributeCertificate; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AACInfo: IAttributeCertificateInfo;
      const ASignatureAlgorithm: IAlgorithmIdentifier; const ASignatureValue: IDerBitString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ACInfo: IAttributeCertificateInfo read GetACInfo;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SignatureValue: IDerBitString read GetSignatureValue;

  end;

  /// <summary>
  /// The AttributeCertificateInfo object.
  /// </summary>
  TAttributeCertificateInfo = class(TAsn1Encodable, IAttributeCertificateInfo)

  strict private
  var
    FVersion: IDerInteger;
    FHolder: IHolder;
    FIssuer: IAttCertIssuer;
    FSignature: IAlgorithmIdentifier;
    FSerialNumber: IDerInteger;
    FAttrCertValidityPeriod: IAttCertValidityPeriod;
    FAttributes: IAsn1Sequence;
    FIssuerUniqueID: IDerBitString;
    FExtensions: IX509Extensions;

  strict protected
    function GetVersion: IDerInteger;
    function GetHolder: IHolder;
    function GetIssuer: IAttCertIssuer;
    function GetSignature: IAlgorithmIdentifier;
    function GetSerialNumber: IDerInteger;
    function GetAttrCertValidityPeriod: IAttCertValidityPeriod;
    function GetAttributes: IAsn1Sequence;
    function GetIssuerUniqueID: IDerBitString;
    function GetExtensions: IX509Extensions;

  public
    class function GetInstance(AObj: TObject): IAttributeCertificateInfo; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IAttributeCertificateInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeCertificateInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AIsExplicit: Boolean): IAttributeCertificateInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributeCertificateInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;

    function ToAsn1Object: IAsn1Object; override;

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
  /// The CrlDistPoint object.
  /// </summary>
  TCrlDistPoint = class(TAsn1Encodable, ICrlDistPoint)

  strict private
  var
    FSeq: IAsn1Sequence;

  strict protected
    function GetDistributionPoints: TCryptoLibGenericArray<IDistributionPoint>;

  public
    class function GetInstance(AObj: TObject): ICrlDistPoint; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ICrlDistPoint; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICrlDistPoint; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICrlDistPoint; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICrlDistPoint; static;
    class function FromExtensions(const AExtensions: IX509Extensions): ICrlDistPoint; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const APoints: TCryptoLibGenericArray<IDistributionPoint>); overload;

    function ToAsn1Object: IAsn1Object; override;
    function ToString: String; override;

  end;

implementation

uses
  ClpX509DefaultEntryConverter;

{ TAlgorithmIdentifier }

class function TAlgorithmIdentifier.GetInstance(AObj: TObject): IAlgorithmIdentifier;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAlgorithmIdentifier, Result) then
    Exit;

  Result := TAlgorithmIdentifier.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAlgorithmIdentifier.GetInstance(const AObj: IAsn1Convertible): IAlgorithmIdentifier;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAlgorithmIdentifier, Result) then
    Exit;

  Result := TAlgorithmIdentifier.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAlgorithmIdentifier.GetInstance(const AEncoded: TCryptoLibByteArray): IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAlgorithmIdentifier.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TAlgorithmIdentifier.GetOptional(const AElement: IAsn1Encodable): IAlgorithmIdentifier;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAlgorithmIdentifier, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TAlgorithmIdentifier.Create(LSequence)
  else
    Result := nil;
end;

class function TAlgorithmIdentifier.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAlgorithmIdentifier.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if (LCount < 1) or (LCount > 2) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FAlgorithm := TDerObjectIdentifier.GetInstance(ASeq[0]);
  if LCount < 2 then
    FParameters := nil
  else
    FParameters := ASeq[1];
end;

constructor TAlgorithmIdentifier.Create(const AAlgorithm: IDerObjectIdentifier);
begin
  Create(AAlgorithm, nil);
end;

constructor TAlgorithmIdentifier.Create(const AAlgorithm: IDerObjectIdentifier;
  const AParameters: IAsn1Encodable);
begin
  inherited Create();

  if AAlgorithm = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SAlgorithmNil);
  end;

  FAlgorithm := AAlgorithm;
  FParameters := AParameters;
end;

function TAlgorithmIdentifier.GetAlgorithm: IDerObjectIdentifier;
begin
  Result := FAlgorithm;
end;

function TAlgorithmIdentifier.GetParameters: IAsn1Encodable;
begin
  Result := FParameters;
end;

function TAlgorithmIdentifier.ToAsn1Object: IAsn1Object;
begin
  if FParameters = nil then
    Result := TDerSequence.Create([FAlgorithm])
  else
    Result := TDerSequence.Create([FAlgorithm, FParameters]);
end;

{ TDigestInfo }

class function TDigestInfo.GetInstance(AObj: TObject): IDigestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDigestInfo, Result) then
    Exit;

  Result := TDigestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDigestInfo.GetInstance(const AObj: IAsn1Convertible): IDigestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDigestInfo, Result) then
    Exit;

  Result := TDigestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDigestInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IDigestInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TDigestInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDigestInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDigestInfo;
begin
  Result := TDigestInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDigestInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDigestInfo;
begin
  Result := TDigestInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDigestInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FDigestAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[0]);
  FDigest := TAsn1OctetString.GetInstance(ASeq[1]);
end;

constructor TDigestInfo.Create(const AAlgId: IAlgorithmIdentifier;
  const ADigest: TCryptoLibByteArray);
begin
  inherited Create();

  if AAlgId = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SDigestAlgorithmNil);
  end;

  FDigestAlgorithm := AAlgId;
  FDigest := TDerOctetString.Create(ADigest);
end;

constructor TDigestInfo.Create(const ADigestAlgorithm: IAlgorithmIdentifier;
  const ADigest: IAsn1OctetString);
begin
  inherited Create();

  if ADigestAlgorithm = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SDigestAlgorithmNil);
  end;

  if ADigest = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SDigestNil);
  end;

  FDigestAlgorithm := ADigestAlgorithm;
  FDigest := ADigest;
end;

function TDigestInfo.GetDigestAlgorithm: IAlgorithmIdentifier;
begin
  Result := FDigestAlgorithm;
end;

function TDigestInfo.GetDigest: IAsn1OctetString;
begin
  Result := FDigest;
end;

function TDigestInfo.GetDigestBytes: TCryptoLibByteArray;
begin
  Result := System.Copy(FDigest.GetOctets());
end;

function TDigestInfo.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FDigestAlgorithm, FDigest]);
end;

{ TDeltaCertificateDescriptor }

procedure TDeltaCertificateDescriptor.ImplCreate(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 8) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FSerialNumber := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FSignature := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAlgorithmIdentifier>(
    ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAlgorithmIdentifier
    begin
      Result := TAlgorithmIdentifier.GetTagged(ATagged, AState);
    end);

  FIssuer := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IX509Name>(ASeq, LPos, 1, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IX509Name
    begin
      Result := TX509Name.GetTagged(ATagged, AState);
    end);

  FValidity := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IValidity>(ASeq, LPos, 2, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IValidity
    begin
      Result := TValidity.GetTagged(ATagged, AState);
    end);

  FSubject := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IX509Name>(ASeq, LPos, 3, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IX509Name
    begin
      Result := TX509Name.GetTagged(ATagged, AState);
    end);

  FSubjectPublicKeyInfo := TSubjectPublicKeyInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FExtensions := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IX509Extensions>(ASeq, LPos, 4, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IX509Extensions
    begin
      Result := TX509Extensions.GetTagged(ATagged, AState);
    end);

  FSignatureValue := TDerBitString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.CreateRes(@SUnexpectedElementsInSequence);
end;

constructor TDeltaCertificateDescriptor.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create();
  ImplCreate(ASeq);
end;

constructor TDeltaCertificateDescriptor.Create(const ASerialNumber: IDerInteger;
  const ASignature: IAlgorithmIdentifier; const AIssuer: IX509Name;
  const AValidity: IValidity; const ASubject: IX509Name;
  const ASubjectPublicKeyInfo: ISubjectPublicKeyInfo;
  const AExtensions: IX509Extensions;
  const ASignatureValue: IDerBitString);
begin
  inherited Create();
  if ASerialNumber = nil then
    raise EArgumentNilCryptoLibException.Create(SDeltaCertDescSerialNil);
  if ASubjectPublicKeyInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SDeltaCertDescSpkiNil);
  if ASignatureValue = nil then
    raise EArgumentNilCryptoLibException.Create(SDeltaCertDescSigValNil);
  FSerialNumber := ASerialNumber;
  FSignature := ASignature;
  FIssuer := AIssuer;
  FValidity := AValidity;
  FSubject := ASubject;
  FSubjectPublicKeyInfo := ASubjectPublicKeyInfo;
  FExtensions := AExtensions;
  FSignatureValue := ASignatureValue;
end;

class function TDeltaCertificateDescriptor.FromExtensions(
  const AExtensions: IX509Extensions): IDeltaCertificateDescriptor;
begin
  Result := GetInstance(TX509Extensions.GetExtensionParsedValue(AExtensions,
    TX509Extensions.DraftDeltaCertificateDescriptor));
end;

class function TDeltaCertificateDescriptor.GetInstance(AObj: TObject): IDeltaCertificateDescriptor;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDeltaCertificateDescriptor, Result) then
    Exit;

  Result := TDeltaCertificateDescriptor.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDeltaCertificateDescriptor.GetInstance(const AObj: IAsn1Convertible): IDeltaCertificateDescriptor;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDeltaCertificateDescriptor, Result) then
    Exit;

  Result := TDeltaCertificateDescriptor.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDeltaCertificateDescriptor.GetInstance(const AEncoded: TCryptoLibByteArray): IDeltaCertificateDescriptor;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TDeltaCertificateDescriptor.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDeltaCertificateDescriptor.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDeltaCertificateDescriptor;
begin
  Result := TDeltaCertificateDescriptor.Create(
    TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TDeltaCertificateDescriptor.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDeltaCertificateDescriptor;
begin
  Result := TDeltaCertificateDescriptor.Create(
    TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

function TDeltaCertificateDescriptor.GetSerialNumber: IDerInteger;
begin
  Result := FSerialNumber;
end;

function TDeltaCertificateDescriptor.GetSignature: IAlgorithmIdentifier;
begin
  Result := FSignature;
end;

function TDeltaCertificateDescriptor.GetIssuer: IX509Name;
begin
  Result := FIssuer;
end;

function TDeltaCertificateDescriptor.GetValidity: IValidity;
begin
  Result := FValidity;
end;

function TDeltaCertificateDescriptor.GetSubject: IX509Name;
begin
  Result := FSubject;
end;

function TDeltaCertificateDescriptor.GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  Result := FSubjectPublicKeyInfo;
end;

function TDeltaCertificateDescriptor.GetExtensions: IX509Extensions;
begin
  Result := FExtensions;
end;

function TDeltaCertificateDescriptor.GetSignatureValue: IDerBitString;
begin
  Result := FSignatureValue;
end;

function TDeltaCertificateDescriptor.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create();
  LV.Add(FSerialNumber);
  LV.AddOptionalTagged(True, 0, FSignature);
  LV.AddOptionalTagged(True, 1, FIssuer);
  LV.AddOptionalTagged(True, 2, FValidity);
  LV.AddOptionalTagged(True, 3, FSubject);
  LV.Add(FSubjectPublicKeyInfo);
  LV.AddOptionalTagged(True, 4, FExtensions);
  LV.Add(FSignatureValue);
  Result := TDerSequence.Create(LV);
end;

{ TTime }

class function TTime.GetInstance(AObj: TObject): ITime;
begin
  Result := TAsn1Utilities.GetInstanceChoice<ITime>(AObj,
    function(AElement: IAsn1Encodable): ITime
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TTime.GetInstance(const AObj: IAsn1Convertible): ITime;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ITime, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<ITime>(AObj.ToAsn1Object(),
    function(AElement: IAsn1Encodable): ITime
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TTime.GetInstance(const AEncoded: TCryptoLibByteArray): ITime;
begin
  Result := TAsn1Utilities.GetInstanceChoice<ITime>(AEncoded,
    function(AElement: IAsn1Encodable): ITime
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TTime.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ITime;
begin
  Result := TAsn1Utilities.GetInstanceChoice<ITime>(AObj, AExplicitly,
    function(AElement: IAsn1Encodable): ITime
    begin
      Result := GetInstance(AElement);
    end);
end;

class function TTime.GetOptional(const AElement: IAsn1Encodable): ITime;
var
  LUtcTime: IAsn1UtcTime;
  LGeneralizedTime: IAsn1GeneralizedTime;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, ITime, Result) then
    Exit;

  LUtcTime := TAsn1UtcTime.GetOptional(AElement);
  if LUtcTime <> nil then
  begin
    Result := TTime.Create(LUtcTime);
    Exit;
  end;

  LGeneralizedTime := TAsn1GeneralizedTime.GetOptional(AElement);
  if LGeneralizedTime <> nil then
  begin
    Result := TTime.Create(LGeneralizedTime);
    Exit;
  end;

  Result := nil;
end;

class function TTime.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ITime;
begin
  Result := TAsn1Utilities.GetTaggedChoice<ITime>(ATaggedObject, ADeclaredExplicit,
    function(AElement: IAsn1Encodable): ITime
    begin
      Result := GetInstance(AElement);
    end);
end;

constructor TTime.Create(const AGeneralizedTime: IAsn1GeneralizedTime);
begin
  inherited Create();
  if AGeneralizedTime = nil then
    raise EArgumentNilCryptoLibException.Create('generalizedTime');
  FTimeObject := AGeneralizedTime;
end;

constructor TTime.Create(const AUtcTime: IAsn1UtcTime);
begin
  inherited Create();
  if AUtcTime = nil then
    raise EArgumentNilCryptoLibException.Create('utcTime');

  // Validate utcTime is in the appropriate year range
  AUtcTime.ToDateTime(2049);

  FTimeObject := AUtcTime;
end;

constructor TTime.Create(const ADateTime: TDateTime);
begin
  CreateFromUtc(TTimeZone.Local.ToUniversalTime(ADateTime));
end;

constructor TTime.CreateFromUtc(const AUtcDateTime: TDateTime);
var
  LYear, LMonth, LDay, LHour, LMinute, LSecond, LMillisecond: Word;
begin
  inherited Create();

  // creates a time object from a given date - if the date is between 1950
  // and 2049 a UTCTime object is Generated, otherwise a GeneralizedTime
  // is used.
  DecodeDateTime(AUtcDateTime, LYear, LMonth, LDay, LHour, LMinute, LSecond, LMillisecond);

  if (LYear < 1950) or (LYear > 2049) then
  begin
    FTimeObject := TRfc5280Asn1Utilities.CreateGeneralizedTimeFromUtc(AUtcDateTime);
  end
  else
  begin
    FTimeObject := TRfc5280Asn1Utilities.CreateUtcTimeFromUtc(AUtcDateTime);
  end;
end;

function TTime.GetTimeObject: IAsn1Object;
begin
  Result := FTimeObject;
end;

function TTime.ToDateTime: TDateTime;
var
  LUtcTime: IAsn1UtcTime;
  LGeneralizedTime: IAsn1GeneralizedTime;
begin
  try
    if Supports(FTimeObject, IAsn1UtcTime, LUtcTime) then
    begin
      Result := LUtcTime.ToDateTime(2049);
      Exit;
    end;

    if Supports(FTimeObject, IAsn1GeneralizedTime, LGeneralizedTime) then
    begin
      Result := LGeneralizedTime.ToDateTime();
      Exit;
    end;

    raise EInvalidOperationCryptoLibException.Create('invalid time object');
  except
    on E: Exception do
    begin
      // this should never happen
      raise EInvalidOperationCryptoLibException.CreateFmt('invalid date string: %s', [E.Message]);
    end;
  end;
end;

function TTime.ToAsn1Object: IAsn1Object;
begin
  Result := FTimeObject;
end;

function TTime.ToString: String;
var
  LUtcTime: IAsn1UtcTime;
  LGeneralizedTime: IAsn1GeneralizedTime;
  LDateTime: TDateTime;
begin
  if Supports(FTimeObject, IAsn1UtcTime, LUtcTime) then
  begin
    LDateTime := LUtcTime.ToDateTime(2049);
    Result := TDateTimeUtilities.FormatCanonical(
      LDateTime,
      'yyyyMMddHHmmssK',
      TFormatSettings.Invariant,
      False
    );
    Exit;
  end;

  if Supports(FTimeObject, IAsn1GeneralizedTime, LGeneralizedTime) then
  begin
    LDateTime := LGeneralizedTime.ToDateTime();
    Result := TDateTimeUtilities.FormatCanonical(
      LDateTime,
      'yyyyMMddHHmmss.FFFFFFFK',
      TFormatSettings.Invariant,
      False
    );
    Exit;
  end;

  raise EInvalidOperationCryptoLibException.Create('invalid time object');
end;

{ TValidity }

class function TValidity.GetInstance(AObj: TObject): IValidity;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IValidity, Result) then
    Exit;

  Result := TValidity.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TValidity.GetInstance(const AObj: IAsn1Convertible): IValidity;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IValidity, Result) then
    Exit;

  Result := TValidity.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TValidity.GetInstance(const AEncoded: TCryptoLibByteArray): IValidity;
begin
  Result := TValidity.Create(TAsn1Sequence.GetInstance(AEncoded));
end;


class function TValidity.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IValidity;
begin
  Result := TValidity.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TValidity.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IValidity;
begin
  Result := TValidity.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TValidity.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FNotBefore := TTime.GetInstance(ASeq[0]);
  FNotAfter := TTime.GetInstance(ASeq[1]);
end;

constructor TValidity.Create(const ANotBefore, ANotAfter: ITime);
begin
  inherited Create();

  if ANotBefore = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SNotBeforeNil);
  end;

  if ANotAfter = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SNotAfterNil);
  end;

  FNotBefore := ANotBefore;
  FNotAfter := ANotAfter;
end;

function TValidity.GetNotBefore: ITime;
begin
  Result := FNotBefore;
end;

function TValidity.GetNotAfter: ITime;
begin
  Result := FNotAfter;
end;

function TValidity.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FNotBefore, FNotAfter]);
end;

{ TCrlEntry }

class function TCrlEntry.GetInstance(AObj: TObject): ICrlEntry;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICrlEntry, Result) then
    Exit;

  Result := TCrlEntry.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCrlEntry.GetInstance(const AObj: IAsn1Convertible): ICrlEntry;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICrlEntry, Result) then
    Exit;

  Result := TCrlEntry.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCrlEntry.GetInstance(const AEncoded: TCryptoLibByteArray): ICrlEntry;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCrlEntry.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCrlEntry.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICrlEntry;
begin
  Result := TCrlEntry.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TCrlEntry.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICrlEntry;
begin
  Result := TCrlEntry.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCrlEntry.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FUserCertificate := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FRevocationDate := TTime.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FCrlEntryExtensions := TAsn1Utilities.ReadOptional<IX509Extensions>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IX509Extensions
    begin
      Result := TX509Extensions.GetOptional(AElement);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);

  FSeq := ASeq;
end;

function TCrlEntry.GetUserCertificate: IDerInteger;
begin
  Result := FUserCertificate;
end;

function TCrlEntry.GetRevocationDate: ITime;
begin
  Result := FRevocationDate;
end;

function TCrlEntry.GetExtensions: IX509Extensions;
begin
  Result := FCrlEntryExtensions;
end;

function TCrlEntry.ToAsn1Object: IAsn1Object;
begin
  Result := FSeq as IAsn1Object;
end;

{ TAltSignatureAlgorithm }

class function TAltSignatureAlgorithm.GetInstance(AObj: TObject): IAltSignatureAlgorithm;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAltSignatureAlgorithm, Result) then
    Exit;

  Result := TAltSignatureAlgorithm.Create(TAlgorithmIdentifier.GetInstance(AObj));
end;

class function TAltSignatureAlgorithm.GetInstance(const AObj: IAsn1Convertible): IAltSignatureAlgorithm;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAltSignatureAlgorithm, Result) then
    Exit;

  Result := TAltSignatureAlgorithm.Create(TAlgorithmIdentifier.GetInstance(AObj));
end;

class function TAltSignatureAlgorithm.GetInstance(const AEncoded: TCryptoLibByteArray): IAltSignatureAlgorithm;
begin
  Result := TAltSignatureAlgorithm.Create(TAlgorithmIdentifier.GetInstance(AEncoded));
end;

class function TAltSignatureAlgorithm.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAltSignatureAlgorithm;
begin
  Result := TAltSignatureAlgorithm.Create(TAlgorithmIdentifier.GetInstance(AObj, AExplicitly));
end;

class function TAltSignatureAlgorithm.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAltSignatureAlgorithm;
begin
  Result := TAltSignatureAlgorithm.Create(TAlgorithmIdentifier.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TAltSignatureAlgorithm.FromExtensions(const AExtensions: IX509Extensions): IAltSignatureAlgorithm;
begin
  Result := GetInstance(TX509Extensions.GetExtensionParsedValue(AExtensions, TX509Extensions.AltSignatureAlgorithm));
end;

constructor TAltSignatureAlgorithm.Create(const AAlgorithm: IAlgorithmIdentifier);
begin
  inherited Create();

  if AAlgorithm = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SAlgorithmNilAlt);
  end;

  FAlgorithm := AAlgorithm;
end;

constructor TAltSignatureAlgorithm.Create(const AAlgorithm: IDerObjectIdentifier);
begin
  Create(AAlgorithm, nil);
end;

constructor TAltSignatureAlgorithm.Create(const AAlgorithm: IDerObjectIdentifier;
  const AParameters: IAsn1Encodable);
begin
  inherited Create();

  FAlgorithm := TAlgorithmIdentifier.Create(AAlgorithm, AParameters);
end;

function TAltSignatureAlgorithm.GetAlgorithm: IAlgorithmIdentifier;
begin
  Result := FAlgorithm;
end;

function TAltSignatureAlgorithm.ToAsn1Object: IAsn1Object;
begin
  Result := FAlgorithm.ToAsn1Object();
end;

{ TAltSignatureValue }

class function TAltSignatureValue.GetInstance(AObj: TObject): IAltSignatureValue;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAltSignatureValue, Result) then
    Exit;

  Result := TAltSignatureValue.Create(TDerBitString.GetInstance(AObj));
end;

class function TAltSignatureValue.GetInstance(const AObj: IAsn1Convertible): IAltSignatureValue;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAltSignatureValue, Result) then
    Exit;

  Result := TAltSignatureValue.Create(TDerBitString.GetInstance(AObj));
end;

class function TAltSignatureValue.GetInstance(const AEncoded: TCryptoLibByteArray): IAltSignatureValue;
begin
  Result := TAltSignatureValue.Create(TDerBitString.GetInstance(AEncoded));
end;

class function TAltSignatureValue.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAltSignatureValue;
begin
  Result := TAltSignatureValue.Create(TDerBitString.GetInstance(AObj, AExplicitly));
end;

class function TAltSignatureValue.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAltSignatureValue;
begin
  Result := TAltSignatureValue.Create(TDerBitString.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TAltSignatureValue.FromExtensions(const AExtensions: IX509Extensions): IAltSignatureValue;
begin
  Result := GetInstance(TX509Extensions.GetExtensionParsedValue(AExtensions, TX509Extensions.AltSignatureValue));
end;

constructor TAltSignatureValue.Create(const ASignature: IDerBitString);
begin
  inherited Create();

  if ASignature = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SSignatureNil);
  end;

  FSignature := ASignature;
end;

constructor TAltSignatureValue.Create(const ASignature: TCryptoLibByteArray);
begin
  inherited Create();

  FSignature := TDerBitString.Create(ASignature);
end;

function TAltSignatureValue.GetSignature: IDerBitString;
begin
  Result := FSignature;
end;

function TAltSignatureValue.ToAsn1Object: IAsn1Object;
begin
  Result := FSignature;
end;

{ TSubjectKeyIdentifier }

class function TSubjectKeyIdentifier.GetInstance(AObj: TObject): ISubjectKeyIdentifier;
var
  LExtension: IX509Extension;
  LPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISubjectKeyIdentifier, Result) then
    Exit;

  if Supports(AObj, ISubjectPublicKeyInfo, LPublicKeyInfo) then
  begin
    // TODO: This constructor is obsolete - use X509ExtensionUtilities instead
    raise ENotImplementedCryptoLibException.Create('SubjectKeyIdentifier from SubjectPublicKeyInfo not yet implemented');
  end;

  if Supports(AObj, IX509Extension, LExtension) then
  begin
    Result := GetInstance(TX509Extension.ConvertValueToObject(LExtension));
    Exit;
  end;

  Result := TSubjectKeyIdentifier.Create(TAsn1OctetString.GetInstance(AObj));
end;

class function TSubjectKeyIdentifier.GetInstance(const AObj: IAsn1Convertible): ISubjectKeyIdentifier;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISubjectKeyIdentifier, Result) then
    Exit;

  Result := TSubjectKeyIdentifier.Create(TAsn1OctetString.GetInstance(AObj));
end;

class function TSubjectKeyIdentifier.GetInstance(const AEncoded: TCryptoLibByteArray): ISubjectKeyIdentifier;
begin
  Result := TSubjectKeyIdentifier.Create(TAsn1OctetString.GetInstance(AEncoded));
end;

class function TSubjectKeyIdentifier.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ISubjectKeyIdentifier;
begin
  Result := TSubjectKeyIdentifier.Create(TAsn1OctetString.GetInstance(AObj, AExplicitly));
end;

class function TSubjectKeyIdentifier.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISubjectKeyIdentifier;
begin
  Result := TSubjectKeyIdentifier.Create(TAsn1OctetString.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TSubjectKeyIdentifier.Create(const AKeyID: TCryptoLibByteArray);
begin
  inherited Create();

  if AKeyID = nil then
  begin
    raise EArgumentNilCryptoLibException.Create(SInvalidKeyIdentifier);
  end;

  FKeyIdentifier := System.Copy(AKeyID);
end;

constructor TSubjectKeyIdentifier.Create(const AKeyID: IAsn1OctetString);
begin
  Create(AKeyID.GetOctets());
end;

function TSubjectKeyIdentifier.GetKeyIdentifier: TCryptoLibByteArray;
begin
  Result := System.Copy(FKeyIdentifier);
end;

function TSubjectKeyIdentifier.ToAsn1Object: IAsn1Object;
begin
  Result := TDerOctetString.FromContents(FKeyIdentifier);
end;

{ TBasicConstraints }

class function TBasicConstraints.GetInstance(AObj: TObject): IBasicConstraints;
var
  LExtension: IX509Extension;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IBasicConstraints, Result) then
    Exit;

  if Supports(AObj, IX509Extension, LExtension) then
  begin
    Result := GetInstance(TX509Extension.ConvertValueToObject(LExtension));
    Exit;
  end;

  Result := TBasicConstraints.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TBasicConstraints.GetInstance(const AObj: IAsn1Convertible): IBasicConstraints;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IBasicConstraints, Result) then
    Exit;

  Result := TBasicConstraints.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TBasicConstraints.GetInstance(const AEncoded: TCryptoLibByteArray): IBasicConstraints;
begin
  Result := TBasicConstraints.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TBasicConstraints.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IBasicConstraints;
begin
  Result := TBasicConstraints.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TBasicConstraints.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IBasicConstraints;
begin
  Result := TBasicConstraints.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TBasicConstraints.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 2) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FCA := TAsn1Utilities.ReadOptional<IDerBoolean>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IDerBoolean
    begin
      Result := TDerBoolean.GetOptional(AElement);
    end);
  if FCA = nil then
    FCA := TDerBoolean.False;

  FPathLenConstraint := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IDerInteger
    begin
      Result := TDerInteger.GetOptional(AElement);
    end);

  if LPos <> LCount then
  begin
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
  end;
end;

constructor TBasicConstraints.Create(ACA: Boolean);
begin
  inherited Create();

  if ACA then
    FCA := TDerBoolean.True
  else
    FCA := TDerBoolean.False;
  FPathLenConstraint := nil;
end;

constructor TBasicConstraints.Create(APathLenConstraint: Int32);
begin
  inherited Create();

  FCA := TDerBoolean.True;
  FPathLenConstraint := TDerInteger.ValueOf(APathLenConstraint);
end;

function TBasicConstraints.IsCA: Boolean;
begin
  Result := FCA.IsTrue;
end;

function TBasicConstraints.GetPathLenConstraint: TBigInteger;
begin
  if FPathLenConstraint = nil then
    Result := TBigInteger.GetDefault
  else
    Result := FPathLenConstraint.Value;
end;

function TBasicConstraints.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(2);
  if FCA.IsTrue then
  begin
    LV.Add(FCA);
  end;
  if FPathLenConstraint <> nil then
  begin
    LV.Add(FPathLenConstraint);
  end;
  Result := TDerSequence.Create(LV);
end;

function TBasicConstraints.ToString: String;
begin
  if FPathLenConstraint = nil then
    Result := Format('BasicConstraints: isCa(%s)', [BoolToStr(IsCA, True)])
  else
    Result := Format('BasicConstraints: isCa(%s), pathLenConstraint = %s',
      [BoolToStr(IsCA, True), FPathLenConstraint.Value.ToString]);
end;

{ TSubjectPublicKeyInfo }

class function TSubjectPublicKeyInfo.GetInstance(AObj: TObject): ISubjectPublicKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISubjectPublicKeyInfo, Result) then
    Exit;

  Result := TSubjectPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSubjectPublicKeyInfo.GetInstance(const AObj: IAsn1Convertible): ISubjectPublicKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISubjectPublicKeyInfo, Result) then
    Exit;

  Result := TSubjectPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSubjectPublicKeyInfo.GetInstance(const AEncoded: TCryptoLibByteArray): ISubjectPublicKeyInfo;
begin
  Result := TSubjectPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TSubjectPublicKeyInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ISubjectPublicKeyInfo;
begin
  Result := TSubjectPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TSubjectPublicKeyInfo.GetOptional(const AElement: IAsn1Encodable): ISubjectPublicKeyInfo;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, ISubjectPublicKeyInfo, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TSubjectPublicKeyInfo.Create(LSequence)
  else
    Result := nil;
end;

class function TSubjectPublicKeyInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISubjectPublicKeyInfo;
begin
  Result := TSubjectPublicKeyInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TSubjectPublicKeyInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[0]);
  FPublicKey := TDerBitString.GetInstance(ASeq[1]);
end;

constructor TSubjectPublicKeyInfo.Create(const AAlgID: IAlgorithmIdentifier;
  const APublicKey: IDerBitString);
begin
  inherited Create();

  FAlgorithm := AAlgID;
  FPublicKey := APublicKey;
end;

constructor TSubjectPublicKeyInfo.Create(const AAlgID: IAlgorithmIdentifier;
  const APublicKey: IAsn1Encodable);
begin
  inherited Create();

  FAlgorithm := AAlgID;
  FPublicKey := TDerBitString.Create(APublicKey);
end;

constructor TSubjectPublicKeyInfo.Create(const AAlgID: IAlgorithmIdentifier;
  const APublicKey: TCryptoLibByteArray);
begin
  inherited Create();

  FAlgorithm := AAlgID;
  FPublicKey := TDerBitString.Create(APublicKey);
end;

function TSubjectPublicKeyInfo.GetAlgorithm: IAlgorithmIdentifier;
begin
  Result := FAlgorithm;
end;

function TSubjectPublicKeyInfo.GetPublicKey: IDerBitString;
begin
  Result := FPublicKey;
end;

function TSubjectPublicKeyInfo.ParsePublicKey: IAsn1Object;
begin
  Result := TAsn1Object.FromStream(FPublicKey.GetOctetStream());
end;

function TSubjectPublicKeyInfo.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FAlgorithm, FPublicKey]);
end;

{ TSubjectAltPublicKeyInfo }

class function TSubjectAltPublicKeyInfo.GetInstance(AObj: TObject): ISubjectAltPublicKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISubjectAltPublicKeyInfo, Result) then
    Exit;

  Result := TSubjectAltPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSubjectAltPublicKeyInfo.GetInstance(const AObj: IAsn1Convertible): ISubjectAltPublicKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISubjectAltPublicKeyInfo, Result) then
    Exit;

  Result := TSubjectAltPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSubjectAltPublicKeyInfo.GetInstance(const AEncoded: TCryptoLibByteArray): ISubjectAltPublicKeyInfo;
begin
  Result := TSubjectAltPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TSubjectAltPublicKeyInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ISubjectAltPublicKeyInfo;
begin
  Result := TSubjectAltPublicKeyInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TSubjectAltPublicKeyInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISubjectAltPublicKeyInfo;
begin
  Result := TSubjectAltPublicKeyInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TSubjectAltPublicKeyInfo.FromExtensions(const AExtensions: IX509Extensions): ISubjectAltPublicKeyInfo;
begin
  Result := GetInstance(TX509Extensions.GetExtensionParsedValue(AExtensions, TX509Extensions.SubjectAltPublicKeyInfo));
end;

constructor TSubjectAltPublicKeyInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[0]);
  FSubjectAltPublicKey := TDerBitString.GetInstance(ASeq[1]);
end;

constructor TSubjectAltPublicKeyInfo.Create(const AAlgorithm: IAlgorithmIdentifier;
  const ASubjectAltPublicKey: IDerBitString);
begin
  inherited Create();

  if AAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create(SAlgorithmNilAlt);
  if ASubjectAltPublicKey = nil then
    raise EArgumentNilCryptoLibException.Create('subjectAltPublicKey');

  FAlgorithm := AAlgorithm;
  FSubjectAltPublicKey := ASubjectAltPublicKey;
end;

constructor TSubjectAltPublicKeyInfo.Create(const ASubjectPublicKeyInfo: ISubjectPublicKeyInfo);
begin
  inherited Create();

  if ASubjectPublicKeyInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SSubjectPublicKeyInfoNil);

  FAlgorithm := ASubjectPublicKeyInfo.Algorithm;
  FSubjectAltPublicKey := ASubjectPublicKeyInfo.PublicKey;
end;

function TSubjectAltPublicKeyInfo.GetAlgorithm: IAlgorithmIdentifier;
begin
  Result := FAlgorithm;
end;

function TSubjectAltPublicKeyInfo.GetSubjectAltPublicKey: IDerBitString;
begin
  Result := FSubjectAltPublicKey;
end;

function TSubjectAltPublicKeyInfo.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FAlgorithm, FSubjectAltPublicKey]);
end;

{ TTbsCertificateStructure }

class function TTbsCertificateStructure.GetInstance(AObj: TObject): ITbsCertificateStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ITbsCertificateStructure, Result) then
    Exit;

  Result := TTbsCertificateStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TTbsCertificateStructure.GetInstance(const AObj: IAsn1Convertible): ITbsCertificateStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ITbsCertificateStructure, Result) then
    Exit;

  Result := TTbsCertificateStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TTbsCertificateStructure.GetInstance(const AEncoded: TCryptoLibByteArray): ITbsCertificateStructure;
begin
  Result := TTbsCertificateStructure.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TTbsCertificateStructure.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ITbsCertificateStructure;
begin
  Result := TTbsCertificateStructure.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TTbsCertificateStructure.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ITbsCertificateStructure;
begin
  Result := TTbsCertificateStructure.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TTbsCertificateStructure.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
  LIsV1, LIsV2: Boolean;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 6) or (LCount > 10) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FVersion := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerInteger>(ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerInteger
    begin
      Result := TDerInteger.GetTagged(ATagged, AState);
    end);
  if FVersion = nil then
    FVersion := TDerInteger.Zero;

  LIsV1 := False;
  LIsV2 := False;
  if FVersion.HasValue(0) then
  begin
    LIsV1 := True;
  end
  else if FVersion.HasValue(1) then
  begin
    LIsV2 := True;
  end
  else if not FVersion.HasValue(2) then
  begin
    raise EArgumentCryptoLibException.Create(SVersionNumberNotRecognised);
  end;

  FSerialNumber := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSignature := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FIssuer := TX509Name.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FValidity := TValidity.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSubject := TX509Name.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSubjectPublicKeyInfo := TSubjectPublicKeyInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  if not LIsV1 then
  begin
    FIssuerUniqueID := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBitString>(ASeq, LPos, 1, False,
      function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBitString
      begin
        Result := TDerBitString.GetTagged(ATagged, AState);
      end);

    FSubjectUniqueID := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBitString>(ASeq, LPos, 2, False,
      function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBitString
      begin
        Result := TDerBitString.GetTagged(ATagged, AState);
      end);

    if not LIsV2 then
    begin
      FExtensions := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IX509Extensions>(ASeq, LPos, 3, True,
        function(ATagged: IAsn1TaggedObject; AState: Boolean): IX509Extensions
        begin
          Result := TX509Extensions.GetTagged(ATagged, AState);
        end);
    end;
  end;

  if LPos <> LCount then
  begin
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
  end;

  FSeq := ASeq;
end;

constructor TTbsCertificateStructure.Create(const AVersion: IDerInteger; const ASerialNumber: IDerInteger;
  const ASignature: IAlgorithmIdentifier; const AIssuer: IX509Name;
  const AValidity: IValidity; const ASubject: IX509Name;
  const ASubjectPublicKeyInfo: ISubjectPublicKeyInfo;
  const AIssuerUniqueID: IDerBitString; const ASubjectUniqueID: IDerBitString;
  const AExtensions: IX509Extensions);
begin
  inherited Create();

  if AVersion = nil then
    FVersion := TDerInteger.Zero
  else
    FVersion := AVersion;
  if ASerialNumber = nil then
    raise EArgumentNilCryptoLibException.Create('serialNumber');
  if ASignature = nil then
    raise EArgumentNilCryptoLibException.Create('signature');
  if AIssuer = nil then
    raise EArgumentNilCryptoLibException.Create('issuer');
  if AValidity = nil then
    raise EArgumentNilCryptoLibException.Create('validity');
  if ASubject = nil then
    raise EArgumentNilCryptoLibException.Create('subject');
  if ASubjectPublicKeyInfo = nil then
    raise EArgumentNilCryptoLibException.Create('subjectPublicKeyInfo');

  FSerialNumber := ASerialNumber;
  FSignature := ASignature;
  FIssuer := AIssuer;
  FValidity := AValidity;
  FSubject := ASubject;
  FSubjectPublicKeyInfo := ASubjectPublicKeyInfo;
  FIssuerUniqueID := AIssuerUniqueID;
  FSubjectUniqueID := ASubjectUniqueID;
  FExtensions := AExtensions;
  FSeq := nil;
end;

function TTbsCertificateStructure.GetVersion: Int32;
begin
  Result := FVersion.IntValueExact + 1;
end;

function TTbsCertificateStructure.GetVersionNumber: IDerInteger;
begin
  Result := FVersion;
end;

function TTbsCertificateStructure.GetSerialNumber: IDerInteger;
begin
  Result := FSerialNumber;
end;

function TTbsCertificateStructure.GetSignature: IAlgorithmIdentifier;
begin
  Result := FSignature;
end;

function TTbsCertificateStructure.GetIssuer: IX509Name;
begin
  Result := FIssuer;
end;

function TTbsCertificateStructure.GetValidity: IValidity;
begin
  Result := FValidity;
end;

function TTbsCertificateStructure.GetStartDate: ITime;
begin
  Result := FValidity.NotBefore;
end;

function TTbsCertificateStructure.GetEndDate: ITime;
begin
  Result := FValidity.NotAfter;
end;

function TTbsCertificateStructure.GetSubject: IX509Name;
begin
  Result := FSubject;
end;

function TTbsCertificateStructure.GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  Result := FSubjectPublicKeyInfo;
end;

function TTbsCertificateStructure.GetIssuerUniqueID: IDerBitString;
begin
  Result := FIssuerUniqueID;
end;

function TTbsCertificateStructure.GetSubjectUniqueID: IDerBitString;
begin
  Result := FSubjectUniqueID;
end;

function TTbsCertificateStructure.GetExtensions: IX509Extensions;
begin
  Result := FExtensions;
end;

class constructor TTbsCertificateStructure.Create;
begin
  FAllowNonDERTbsCertificate := False;
end;

class function TTbsCertificateStructure.GetAllowNonDERTbsCertificate: Boolean;
begin
  Result := FAllowNonDERTbsCertificate;
end;

class procedure TTbsCertificateStructure.SetAllowNonDERTbsCertificate(AValue: Boolean);
begin
  FAllowNonDERTbsCertificate := AValue;
end;

function TTbsCertificateStructure.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  if FSeq <> nil then
  begin
    if AllowNonDERTbsCertificate then
    begin
      Result := FSeq;
      Exit;
    end;
  end;

  LV := TAsn1EncodableVector.Create(10);

  // DEFAULT Zero
  if not FVersion.HasValue(0) then
  begin
    LV.Add(TDerTaggedObject.Create(True, 0, FVersion));
  end;

  LV.Add([FSerialNumber, FSignature, FIssuer, FValidity, FSubject, FSubjectPublicKeyInfo]);

  // Note: implicit tag
  LV.AddOptionalTagged(False, 1, FIssuerUniqueID);

  // Note: implicit tag
  LV.AddOptionalTagged(False, 2, FSubjectUniqueID);

  LV.AddOptionalTagged(True, 3, FExtensions);

  Result := TDerSequence.Create(LV);
end;

{ TX509CertificateStructure }

class function TX509CertificateStructure.GetInstance(AObj: TObject): IX509CertificateStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX509CertificateStructure, Result) then
    Exit;

  Result := TX509CertificateStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TX509CertificateStructure.GetInstance(const AObj: IAsn1Convertible): IX509CertificateStructure;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX509CertificateStructure, Result) then
    Exit;

  Result := TX509CertificateStructure.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TX509CertificateStructure.GetInstance(const AEncoded: TCryptoLibByteArray): IX509CertificateStructure;
begin
  Result := TX509CertificateStructure.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TX509CertificateStructure.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IX509CertificateStructure;
begin
  Result := TX509CertificateStructure.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TX509CertificateStructure.GetOptional(const AElement: IAsn1Encodable): IX509CertificateStructure;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IX509CertificateStructure, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TX509CertificateStructure.Create(LSequence)
  else
    Result := nil;
end;

class function TX509CertificateStructure.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IX509CertificateStructure;
begin
  Result := TX509CertificateStructure.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TX509CertificateStructure.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 3 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  // correct x509 certificate
  FTbsCertificate := TTbsCertificateStructure.GetInstance(ASeq[0]);
  FSignatureAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[1]);
  FSignature := TDerBitString.GetInstance(ASeq[2]);
end;

constructor TX509CertificateStructure.Create(const ATbsCert: ITbsCertificateStructure;
  const ASigAlgID: IAlgorithmIdentifier; const ASig: IDerBitString);
begin
  inherited Create();

  if ATbsCert = nil then
    raise EArgumentNilCryptoLibException.Create(STbsCertNil);
  if ASigAlgID = nil then
    raise EArgumentNilCryptoLibException.Create(SSigAlgIDNil);
  if ASig = nil then
    raise EArgumentNilCryptoLibException.Create(SSigNil);

  FTbsCertificate := ATbsCert;
  FSignatureAlgorithm := ASigAlgID;
  FSignature := ASig;
end;

function TX509CertificateStructure.GetTbsCertificate: ITbsCertificateStructure;
begin
  Result := FTbsCertificate;
end;

function TX509CertificateStructure.GetVersion: Int32;
begin
  Result := FTbsCertificate.Version;
end;

function TX509CertificateStructure.GetSerialNumber: IDerInteger;
begin
  Result := FTbsCertificate.SerialNumber;
end;

function TX509CertificateStructure.GetIssuer: IX509Name;
begin
  Result := FTbsCertificate.Issuer;
end;

function TX509CertificateStructure.GetValidity: IValidity;
begin
  Result := FTbsCertificate.Validity;
end;

function TX509CertificateStructure.GetStartDate: ITime;
begin
  Result := FTbsCertificate.StartDate;
end;

function TX509CertificateStructure.GetEndDate: ITime;
begin
  Result := FTbsCertificate.EndDate;
end;

function TX509CertificateStructure.GetSubject: IX509Name;
begin
  Result := FTbsCertificate.Subject;
end;

function TX509CertificateStructure.GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  Result := FTbsCertificate.SubjectPublicKeyInfo;
end;

function TX509CertificateStructure.GetIssuerUniqueID: IDerBitString;
begin
  Result := FTbsCertificate.IssuerUniqueID;
end;

function TX509CertificateStructure.GetSubjectUniqueID: IDerBitString;
begin
  Result := FTbsCertificate.SubjectUniqueID;
end;

function TX509CertificateStructure.GetExtensions: IX509Extensions;
begin
  Result := FTbsCertificate.Extensions;
end;

function TX509CertificateStructure.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSignatureAlgorithm;
end;

function TX509CertificateStructure.GetSignature: IDerBitString;
begin
  Result := FSignature;
end;

function TX509CertificateStructure.GetSignatureOctets: TCryptoLibByteArray;
begin
  Result := FSignature.GetOctets();
end;

function TX509CertificateStructure.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FTbsCertificate, FSignatureAlgorithm, FSignature]);
end;

{ TGeneralName }

class function TGeneralName.GetInstance(AObj: TObject): IGeneralName;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IGeneralName>(AObj,
    function(AElement: IAsn1Encodable): IGeneralName
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TGeneralName.GetInstance(const AObj: IAsn1Convertible): IGeneralName;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IGeneralName, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<IGeneralName>(AObj.ToAsn1Object(),
    function(AElement: IAsn1Encodable): IGeneralName
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TGeneralName.GetInstance(const AEncoded: TCryptoLibByteArray): IGeneralName;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IGeneralName>(AEncoded,
    function(AElement: IAsn1Encodable): IGeneralName
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TGeneralName.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IGeneralName;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IGeneralName>(AObj, AExplicitly,
    function(AElement: IAsn1Encodable): IGeneralName
    begin
      Result := GetInstance(AElement);
    end);
end;

class function TGeneralName.GetOptional(const AElement: IAsn1Encodable): IGeneralName;
var
  LTagged: IAsn1TaggedObject;
  LBaseObject: IAsn1Encodable;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IGeneralName, Result) then
    Exit;

  LTagged := TAsn1TaggedObject.GetOptional(AElement);
  if LTagged <> nil then
  begin
    LBaseObject := GetOptionalBaseObject(LTagged);
    if LBaseObject <> nil then
    begin
      Result := TGeneralName.Create(LTagged.TagNo, LBaseObject);
      Exit;
    end;
  end;

  Result := nil;
end;

class function TGeneralName.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IGeneralName;
begin
  Result := TAsn1Utilities.GetTaggedChoice<IGeneralName>(ATaggedObject, ADeclaredExplicit,
    function(AElement: IAsn1Encodable): IGeneralName
    begin
      Result := GetInstance(AElement);
    end);
end;

class function TGeneralName.GetOptionalBaseObject(const ATaggedObject: IAsn1TaggedObject): IAsn1Encodable;
var
  LSeq: IAsn1Sequence;
begin
  if not ATaggedObject.HasContextTag() then
  begin
    Result := nil;
    Exit;
  end;

  case ATaggedObject.TagNo of
    EdiPartyName:
      begin
        LSeq := TAsn1Sequence.GetTagged(ATaggedObject, False);
        // TODO: Validate EdiPartyName
        Result := LSeq;
      end;
    OtherName, X400Address:
      Result := TAsn1Sequence.GetTagged(ATaggedObject, False);
    DnsName, Rfc822Name, UniformResourceIdentifier:
      Result := TDerIA5String.GetTagged(ATaggedObject, False);
    DirectoryName:
      Result := TX509Name.GetTagged(ATaggedObject, True);
    IPAddress:
      Result := TAsn1OctetString.GetTagged(ATaggedObject, False);
    RegisteredID:
      Result := TDerObjectIdentifier.GetTagged(ATaggedObject, False);
  else
    Result := nil;
  end;
end;

constructor TGeneralName.Create(const ADirectoryName: IX509Name);
begin
  inherited Create();
  FTag := DirectoryName;
  FName := ADirectoryName;
end;

constructor TGeneralName.Create(const AName: IAsn1Object; ATag: Int32);
begin
  inherited Create();
  FTag := ATag;
  FName := AName;
end;

constructor TGeneralName.Create(ATag: Int32; const AName: IAsn1Encodable);
begin
  inherited Create();
  FTag := ATag;
  FName := AName;
end;

constructor TGeneralName.Create(ATag: Int32; const AName: String);
var
  LEncoding: TCryptoLibByteArray;
begin
  inherited Create();
  FTag := ATag;

  case ATag of
    DnsName, Rfc822Name, UniformResourceIdentifier:
      FName := TDerIA5String.Create(AName);
    DirectoryName:
      FName := TX509Name.Create(AName);
    IPAddress:
      begin
        // Parse IP address (IPv4 or IPv6)
        LEncoding := TGeneralName.ToGeneralNameEncoding(AName);
        if LEncoding = nil then
          raise EArgumentCryptoLibException.Create('IP Address is invalid');
        FName := TDerOctetString.Create(LEncoding);
      end;
    RegisteredID:
      FName := TDerObjectIdentifier.Create(AName);
  else
    raise EArgumentCryptoLibException.CreateFmt('can''t process string for tag: %s',
      [TAsn1Utilities.GetTagText(TAsn1Tags.ContextSpecific, ATag)]);
  end;
end;

function TGeneralName.GetTagNo: Int32;
begin
  Result := FTag;
end;

function TGeneralName.GetName: IAsn1Encodable;
begin
  Result := FName;
end;

function TGeneralName.ToAsn1Object: IAsn1Object;
var
  LIsExplicit: Boolean;
begin
  // directoryName is explicitly tagged as it is a CHOICE
  LIsExplicit := (FTag = DirectoryName);
  Result := TDerTaggedObject.Create(LIsExplicit, FTag, FName);
end;

function TGeneralName.ToString: String;
var
  LIA5: IDerIA5String;
  LName: IX509Name;
  LObj: IAsn1Object;
begin
  Result := IntToStr(FTag) + ': ';

  case FTag of
    Rfc822Name, DnsName, UniformResourceIdentifier:
      begin
        if Supports(FName, IDerIA5String, LIA5) then
          Result := Result + LIA5.GetString();
      end;
    DirectoryName:
      begin
        if Supports(FName, IX509Name, LName) then
          Result := Result + LName.ToString();
      end;
  else
  begin
    if Supports(FName, IAsn1String, LIA5) then
      Result := Result + LIA5.GetString()
    else if Supports(FName, IAsn1Object, LObj) then
    begin
      Result := Result + LObj.ToString();
    end;
  end;
  end;
end;

class function TGeneralName.ToGeneralNameEncoding(const AIp: String): TCryptoLibByteArray;
var
  LSlashIndex: Int32;
  LAddr: TCryptoLibByteArray;
  LParsedIp: TCryptoLibInt32Array;
  LMask: String;
begin
  if TIPAddressUtilities.IsValidIPv6WithNetmask(AIp) or TIPAddressUtilities.IsValidIPv6(AIp) then
  begin
    LSlashIndex := TStringUtilities.IndexOf(AIp, '/');

    if LSlashIndex = 0 then
    begin
      System.SetLength(LAddr, 16);
      LParsedIp := ParseIPv6(AIp);
      CopyInts(LParsedIp, LAddr, 0);
      Result := LAddr;
    end
    else
    begin
      System.SetLength(LAddr, 32);
      // LSlashIndex is 1-based position of '/'
      LParsedIp := ParseIPv6(System.Copy(AIp, 1, LSlashIndex - 1));
      CopyInts(LParsedIp, LAddr, 0);
      LMask := System.Copy(AIp, LSlashIndex + 1, System.Length(AIp) - LSlashIndex);
      if TStringUtilities.IndexOf(LMask, ':') > 0 then
      begin
        LParsedIp := ParseIPv6(LMask);
      end
      else
      begin
        LParsedIp := ParseIPv6Mask(LMask);
      end;
      CopyInts(LParsedIp, LAddr, 16);
      Result := LAddr;
    end;
  end
  else if TIPAddressUtilities.IsValidIPv4WithNetmask(AIp) or TIPAddressUtilities.IsValidIPv4(AIp) then
  begin
    LSlashIndex := TStringUtilities.IndexOf(AIp, '/');

    if LSlashIndex = 0 then
    begin
      System.SetLength(LAddr, 4);
      ParseIPv4(AIp, LAddr, 0);
      Result := LAddr;
    end
    else
    begin
      System.SetLength(LAddr, 8);
      // LSlashIndex is 1-based position of '/', copy from start to slash (exclusive)
      ParseIPv4(System.Copy(AIp, 1, LSlashIndex - 1), LAddr, 0);
      LMask := System.Copy(AIp, LSlashIndex + 1, System.Length(AIp) - LSlashIndex);
      if TStringUtilities.IndexOf(LMask, '.') > 0 then
      begin
        ParseIPv4(LMask, LAddr, 4);
      end
      else
      begin
        ParseIPv4Mask(LMask, LAddr, 4);
      end;
      Result := LAddr;
    end;
  end
  else
  begin
    Result := nil;
  end;
end;

class procedure TGeneralName.CopyInts(const AParsedIp: TCryptoLibInt32Array; var AAddr: TCryptoLibByteArray; AOffset: Int32);
var
  I: Int32;
begin
  for I := 0 to System.Length(AParsedIp) - 1 do
  begin
    AAddr[(I * 2) + AOffset] := Byte((AParsedIp[I] shr 8) and $FF);
    AAddr[(I * 2 + 1) + AOffset] := Byte(AParsedIp[I] and $FF);
  end;
end;

class procedure TGeneralName.ParseIPv4(const AIp: String; var AAddr: TCryptoLibByteArray; AOffset: Int32);
var
  LTokens: TCryptoLibStringArray;
  I: Int32;
  LToken: String;
begin
  // Split by '.' and '/'
  System.SetLength(LTokens, 0);
  LToken := '';
  for I := 1 to System.Length(AIp) do
  begin
    if (AIp[I] = '.') or (AIp[I] = '/') then
    begin
      if LToken <> '' then
      begin
        System.SetLength(LTokens, System.Length(LTokens) + 1);
        LTokens[System.Length(LTokens) - 1] := LToken;
        LToken := '';
      end;
    end
    else
    begin
      LToken := LToken + AIp[I];
    end;
  end;
  if LToken <> '' then
  begin
    System.SetLength(LTokens, System.Length(LTokens) + 1);
    LTokens[System.Length(LTokens) - 1] := LToken;
  end;

  // Parse each token as byte
  for I := 0 to System.Length(LTokens) - 1 do
  begin
    AAddr[AOffset] := Byte(StrToInt(LTokens[I]));
    System.Inc(AOffset);
  end;
end;

class procedure TGeneralName.ParseIPv4Mask(const AMask: String; var AAddr: TCryptoLibByteArray; AOffset: Int32);
var
  LBits: Int32;
begin
  LBits := StrToInt(AMask);
  while LBits >= 8 do
  begin
    AAddr[AOffset] := $FF;
    System.Inc(AOffset);
    LBits := LBits - 8;
  end;
  if LBits > 0 then
  begin
    AAddr[AOffset] := Byte(($FF00 shr LBits) and $FF);
  end;
end;

class function TGeneralName.ParseIPv6(const AIp: String): TCryptoLibInt32Array;
var
  LProcessedIp: String;
  LIndex: Int32;
  LVal: TCryptoLibInt32Array;
  LDoubleColon: Int32;
  LSegments: TCryptoLibStringArray;
  I, J: Int32;
  LSegment: String;
  LTokens: TCryptoLibStringArray;
begin
  LProcessedIp := AIp;
  if TStringUtilities.StartsWith(LProcessedIp, '::') then
  begin
    LProcessedIp := System.Copy(LProcessedIp, 2, System.Length(LProcessedIp) - 1);
  end
  else if TStringUtilities.EndsWith(LProcessedIp, '::') then
  begin
    LProcessedIp := System.Copy(LProcessedIp, 1, System.Length(LProcessedIp) - 1);
  end;

  LIndex := 0;
  System.SetLength(LVal, 8);
  LDoubleColon := -1;

  // Split by ':'
  System.SetLength(LSegments, 0);
  LSegment := '';
  for I := 1 to System.Length(LProcessedIp) do
  begin
    if LProcessedIp[I] = ':' then
    begin
      System.SetLength(LSegments, System.Length(LSegments) + 1);
      LSegments[System.Length(LSegments) - 1] := LSegment;
      LSegment := '';
    end
    else
    begin
      LSegment := LSegment + LProcessedIp[I];
    end;
  end;
  if LSegment <> '' then
  begin
    System.SetLength(LSegments, System.Length(LSegments) + 1);
    LSegments[System.Length(LSegments) - 1] := LSegment;
  end;

  for I := 0 to System.Length(LSegments) - 1 do
  begin
    LSegment := LSegments[I];
    if System.Length(LSegment) = 0 then
    begin
      LDoubleColon := LIndex;
      LVal[LIndex] := 0;
      System.Inc(LIndex);
    end
    else
    begin
      if TStringUtilities.IndexOf(LSegment, '.') = 0 then
      begin
        // Parse as hex
        LVal[LIndex] := StrToInt('$' + LSegment);
        System.Inc(LIndex);
      end
      else
      begin
        // IPv4 embedded in IPv6 - split by '.'
        System.SetLength(LTokens, 0);
        for J := 1 to System.Length(LSegment) do
        begin
          if LSegment[J] = '.' then
          begin
            System.SetLength(LTokens, System.Length(LTokens) + 1);
            LTokens[System.Length(LTokens) - 1] := '';
          end
          else
          begin
            if System.Length(LTokens) = 0 then
            begin
              System.SetLength(LTokens, 1);
              LTokens[0] := '';
            end;
            LTokens[System.Length(LTokens) - 1] := LTokens[System.Length(LTokens) - 1] + LSegment[J];
          end;
        end;
        if System.Length(LTokens) < 4 then
        begin
          System.SetLength(LTokens, 4);
          for J := System.Length(LTokens) to 3 do
            LTokens[J] := '';
        end;

        LVal[LIndex] := (StrToInt(LTokens[0]) shl 8) or StrToInt(LTokens[1]);
        System.Inc(LIndex);
        LVal[LIndex] := (StrToInt(LTokens[2]) shl 8) or StrToInt(LTokens[3]);
        System.Inc(LIndex);
      end;
    end;
  end;

  if LIndex <> System.Length(LVal) then
  begin
    // Expand double colon
    // This copies elements from doubleColon to the end, shifting them right
    // Then zeros out the middle section
    if LDoubleColon >= 0 then
    begin
      // Copy elements from doubleColon to destination position
      System.Move(LVal[LDoubleColon], LVal[System.Length(LVal) - (LIndex - LDoubleColon)],
        (LIndex - LDoubleColon) * SizeOf(Int32));
      // Zero out the middle section
      for I := LDoubleColon to System.Length(LVal) - (LIndex - LDoubleColon) - 1 do
      begin
        LVal[I] := 0;
      end;
    end;
  end;

  Result := LVal;
end;

class function TGeneralName.ParseIPv6Mask(const AMask: String): TCryptoLibInt32Array;
var
  LRes: TCryptoLibInt32Array;
  LBits, LResPos: Int32;
begin
  System.SetLength(LRes, 8);
  LBits := StrToInt(AMask);
  LResPos := 0;
  while LBits >= 16 do
  begin
    LRes[LResPos] := $FFFF;
    System.Inc(LResPos);
    LBits := LBits - 16;
  end;
  if LBits > 0 then
  begin
    LRes[LResPos] := $FFFF shr (16 - LBits);
  end;
  Result := LRes;
end;

{ TGeneralNames }

class function TGeneralNames.GetInstance(AObj: TObject): IGeneralNames;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IGeneralNames, Result) then
    Exit;

  Result := TGeneralNames.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TGeneralNames.GetInstance(const AObj: IAsn1Convertible): IGeneralNames;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IGeneralNames, Result) then
    Exit;

  Result := TGeneralNames.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TGeneralNames.GetInstance(const AEncoded: TCryptoLibByteArray): IGeneralNames;
begin
  Result := TGeneralNames.Create(TAsn1Sequence.GetInstance(AEncoded));
end;


class function TGeneralNames.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IGeneralNames;
begin
  Result := TGeneralNames.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TGeneralNames.GetOptional(const AElement: IAsn1Encodable): IGeneralNames;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IGeneralNames, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TGeneralNames.Create(LSequence)
  else
    Result := nil;
end;

class function TGeneralNames.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IGeneralNames;
begin
  Result := TGeneralNames.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TGeneralNames.Create(const AName: IGeneralName);
begin
  inherited Create();
  if AName = nil then
    raise EArgumentNilCryptoLibException.Create('name');
  System.SetLength(FNames, 1);
  FNames[0] := AName;
end;

constructor TGeneralNames.Create(const ANames: TCryptoLibGenericArray<IGeneralName>);
var
  I: Int32;
begin
  inherited Create();
  if (ANames = nil) or (System.Length(ANames) = 0) then
    raise EArgumentNilCryptoLibException.Create('names cannot be null or empty');
  for I := 0 to System.Length(ANames) - 1 do
  begin
    if ANames[I] = nil then
      raise EArgumentNilCryptoLibException.Create('names cannot contain null');
  end;
  FNames := TArrayUtilities.Clone<IGeneralName>(ANames,
    function(A: IGeneralName): IGeneralName
    begin
      Result := A;
    end);
end;

constructor TGeneralNames.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create();
  FNames := TArrayUtilities.Map<IAsn1Encodable, IGeneralName>(ASeq.Elements,
    function(AElement: IAsn1Encodable): IGeneralName
    begin
      Result := TGeneralName.GetInstance(AElement);
    end);
end;

function TGeneralNames.GetCount: Int32;
begin
  Result := System.Length(FNames);
end;

function TGeneralNames.GetNames: TCryptoLibGenericArray<IGeneralName>;
begin
  Result := TArrayUtilities.Clone<IGeneralName>(FNames,
    function(A: IGeneralName): IGeneralName
    begin
      Result := A;
    end);
end;

function TGeneralNames.ToAsn1Object: IAsn1Object;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  I: Int32;
begin
  System.SetLength(LElements, System.Length(FNames));
  for I := 0 to System.Length(FNames) - 1 do
  begin
    LElements[I] := FNames[I];
  end;
  Result := TDerSequence.FromElements(LElements);
end;

function TGeneralNames.ToString: String;
var
  SB: TStringBuilder;
  I: Int32;
begin
  SB := TStringBuilder.Create;
  try
    SB.AppendLine('GeneralNames:');
    for I := 0 to System.Length(FNames) - 1 do
    begin
      SB.Append('    ');
      SB.AppendLine(FNames[I].ToString);
    end;
    Result := SB.ToString();
  finally
    SB.Free;
  end;
end;

{ TKeyUsage }

class function TKeyUsage.GetKeyUsageInstance(AObj: TObject): IKeyUsage;
var
  LExtension: IX509Extension;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IKeyUsage, Result) then
    Exit;

  if Supports(AObj, IX509Extension, LExtension) then
  begin
    Result := GetKeyUsageInstance(TX509Extension.ConvertValueToObject(LExtension));
    Exit;
  end;

  Result := TKeyUsage.Create(TDerBitString.GetInstance(AObj));
end;

class function TKeyUsage.GetKeyUsageInstance(const AObj: IAsn1Convertible): IKeyUsage;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IKeyUsage, Result) then
    Exit;

  Result := TKeyUsage.Create(TDerBitString.GetInstance(AObj));
end;

class function TKeyUsage.GetKeyUsageInstance(const AEncoded: TCryptoLibByteArray): IKeyUsage;
begin
  Result := TKeyUsage.Create(TDerBitString.GetInstance(AEncoded));
end;

constructor TKeyUsage.Create(AUsage: Int32);
begin
  inherited Create(AUsage);
end;

constructor TKeyUsage.Create(const AUsage: IDerBitString);
begin
  inherited Create(AUsage.GetBytes(), AUsage.PadBits);
end;

function TKeyUsage.ToString: String;
var
  LData: TCryptoLibByteArray;
  LValue: Int32;
begin
  LData := GetBytes();
  if System.Length(LData) = 1 then
  begin
    LValue := LData[0] and $FF;
    Result := Format('KeyUsage: 0x%s', [IntToHex(LValue, 2)]);
  end
  else
  begin
    LValue := ((LData[1] and $FF) shl 8) or (LData[0] and $FF);
    Result := Format('KeyUsage: 0x%s', [IntToHex(LValue, 4)]);
  end;
end;

{ TAuthorityKeyIdentifier }

class function TAuthorityKeyIdentifier.GetInstance(AObj: TObject): IAuthorityKeyIdentifier;
var
  LExtension: IX509Extension;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAuthorityKeyIdentifier, Result) then
    Exit;

  if Supports(AObj, IX509Extension, LExtension) then
  begin
    Result := GetInstance(TX509Extension.ConvertValueToObject(LExtension));
    Exit;
  end;

  Result := TAuthorityKeyIdentifier.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAuthorityKeyIdentifier.GetInstance(const AObj: IAsn1Convertible): IAuthorityKeyIdentifier;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAuthorityKeyIdentifier, Result) then
    Exit;

  Result := TAuthorityKeyIdentifier.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAuthorityKeyIdentifier.GetInstance(const AEncoded: TCryptoLibByteArray): IAuthorityKeyIdentifier;
begin
  Result := TAuthorityKeyIdentifier.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAuthorityKeyIdentifier.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAuthorityKeyIdentifier;
begin
  Result := TAuthorityKeyIdentifier.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TAuthorityKeyIdentifier.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAuthorityKeyIdentifier;
begin
  Result := TAuthorityKeyIdentifier.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TAuthorityKeyIdentifier.FromExtensions(const AExtensions: IX509Extensions): IAuthorityKeyIdentifier;
begin
  Result := GetInstance(TX509Extensions.GetExtensionParsedValue(AExtensions, TX509Extensions.AuthorityKeyIdentifier));
end;

constructor TAuthorityKeyIdentifier.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FKeyIdentifier := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1OctetString>(ASeq, LPos, 0, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1OctetString
    begin
      Result := TAsn1OctetString.GetTagged(ATagged, AState);
    end);

  FAuthorityCertIssuer := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IGeneralNames>(ASeq, LPos, 1, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IGeneralNames
    begin
      Result := TGeneralNames.GetTagged(ATagged, AState);
    end);

  FAuthorityCertSerialNumber := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerInteger>(ASeq, LPos, 2, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerInteger
    begin
      Result := TDerInteger.GetTagged(ATagged, AState);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create('Unexpected elements in sequence');
end;

constructor TAuthorityKeyIdentifier.Create(const AKeyIdentifier: TCryptoLibByteArray);
begin
  Create(AKeyIdentifier, nil, TBigInteger.GetDefault);
end;

constructor TAuthorityKeyIdentifier.Create(const AKeyIdentifier: TCryptoLibByteArray;
  const AAuthorityCertIssuer: IGeneralNames;
  const AAuthorityCertSerialNumber: TBigInteger);
var
  LSerialNumber: IDerInteger;
begin
  inherited Create();
  if AKeyIdentifier <> nil then
    FKeyIdentifier := TDerOctetString.FromContentsOptional(AKeyIdentifier)
  else
    FKeyIdentifier := nil;
  FAuthorityCertIssuer := AAuthorityCertIssuer;
  if AAuthorityCertSerialNumber.IsInitialized then
    LSerialNumber := TDerInteger.Create(AAuthorityCertSerialNumber)
  else
    LSerialNumber := nil;
  FAuthorityCertSerialNumber := LSerialNumber;
end;

constructor TAuthorityKeyIdentifier.Create(const AKeyIdentifier: IAsn1OctetString);
begin
  Create(AKeyIdentifier, nil, nil);
end;

constructor TAuthorityKeyIdentifier.Create(const AKeyIdentifier: IAsn1OctetString;
  const AAuthorityCertIssuer: IGeneralNames;
  const AAuthorityCertSerialNumber: IDerInteger);
begin
  inherited Create();
  FKeyIdentifier := AKeyIdentifier;
  FAuthorityCertIssuer := AAuthorityCertIssuer;
  FAuthorityCertSerialNumber := AAuthorityCertSerialNumber;
end;

constructor TAuthorityKeyIdentifier.Create(const AAuthorityCertIssuer: IGeneralNames;
  const AAuthorityCertSerialNumber: TBigInteger);
begin
  Create(nil, AAuthorityCertIssuer, AAuthorityCertSerialNumber);
end;

function TAuthorityKeyIdentifier.GetKeyIdentifier: IAsn1OctetString;
begin
  Result := FKeyIdentifier;
end;

function TAuthorityKeyIdentifier.GetAuthorityCertIssuer: IGeneralNames;
begin
  Result := FAuthorityCertIssuer;
end;

function TAuthorityKeyIdentifier.GetAuthorityCertSerialNumber: IDerInteger;
begin
  Result := FAuthorityCertSerialNumber;
end;

function TAuthorityKeyIdentifier.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create();
  LV.AddOptionalTagged(False, 0, FKeyIdentifier);
  LV.AddOptionalTagged(False, 1, FAuthorityCertIssuer);
  LV.AddOptionalTagged(False, 2, FAuthorityCertSerialNumber);
  Result := TDerSequence.Create(LV);
end;

{ TExtendedKeyUsage }

class function TExtendedKeyUsage.GetInstance(AObj: TObject): IExtendedKeyUsage;
var
  LExtension: IX509Extension;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IExtendedKeyUsage, Result) then
    Exit;

  if Supports(AObj, IX509Extension, LExtension) then
  begin
    Result := GetInstance(TX509Extension.ConvertValueToObject(LExtension));
    Exit;
  end;

  Result := TExtendedKeyUsage.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TExtendedKeyUsage.GetInstance(const AObj: IAsn1Convertible): IExtendedKeyUsage;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IExtendedKeyUsage, Result) then
    Exit;

  Result := TExtendedKeyUsage.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TExtendedKeyUsage.GetInstance(const AEncoded: TCryptoLibByteArray): IExtendedKeyUsage;
begin
  Result := TExtendedKeyUsage.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TExtendedKeyUsage.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IExtendedKeyUsage;
begin
  Result := TExtendedKeyUsage.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TExtendedKeyUsage.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IExtendedKeyUsage;
begin
  Result := TExtendedKeyUsage.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TExtendedKeyUsage.FromExtensions(const AExtensions: IX509Extensions): IExtendedKeyUsage;
begin
  Result := GetInstance(TX509Extensions.GetExtensionParsedValue(AExtensions, TX509Extensions.ExtendedKeyUsage));
end;

constructor TExtendedKeyUsage.Create(const ASeq: IAsn1Sequence);
var
  I: Int32;
  LOid: IDerObjectIdentifier;
begin
  inherited Create();
  FSeq := ASeq;
  FUsageTable := TDictionary<IDerObjectIdentifier, Boolean>.Create(TAsn1Comparers.OidEqualityComparer);

  for I := 0 to ASeq.Count - 1 do
  begin
    LOid := TDerObjectIdentifier.GetInstance(ASeq[I]);
    FUsageTable.Add(LOid, True);
  end;
end;

constructor TExtendedKeyUsage.Create(const AUsages: TCryptoLibGenericArray<IDerObjectIdentifier>);
var
  I: Int32;
  LV: IAsn1EncodableVector;
  LOid: IDerObjectIdentifier;
begin
  inherited Create();
  FUsageTable := TDictionary<IDerObjectIdentifier, Boolean>.Create(TAsn1Comparers.OidEqualityComparer);
  LV := TAsn1EncodableVector.Create();

  for I := 0 to System.Length(AUsages) - 1 do
  begin
    LOid := AUsages[I];
    LV.Add(LOid);
    FUsageTable.Add(LOid, True);
  end;

  FSeq := TDerSequence.Create(LV);
end;

constructor TExtendedKeyUsage.Create(const AUsages: array of IKeyPurposeId);
var
  I: Int32;
  LCount: Int32;
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  inherited Create();
  FUsageTable := TDictionary<IDerObjectIdentifier, Boolean>.Create(TAsn1Comparers.OidEqualityComparer);

  LCount := High(AUsages) - Low(AUsages) + 1;
  System.SetLength(LElements, LCount);
  for I := 0 to LCount - 1 do
    LElements[I] := AUsages[Low(AUsages) + I];

  FSeq := TDerSequence.Create(LElements);

  for I := Low(AUsages) to High(AUsages) do
  begin
    FUsageTable.Add(AUsages[I], True);
  end;
end;

destructor TExtendedKeyUsage.Destroy;
begin
  FUsageTable.Free;
  inherited Destroy;
end;

function TExtendedKeyUsage.HasKeyPurposeId(const AKeyPurposeId: IDerObjectIdentifier): Boolean;
begin
  Result := FUsageTable.ContainsKey(AKeyPurposeId);
end;

function TExtendedKeyUsage.GetAllUsages: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := TCollectionUtilities.Keys<IDerObjectIdentifier, Boolean>(FUsageTable);
end;

function TExtendedKeyUsage.GetCount: Int32;
begin
  Result := FUsageTable.Count;
end;

function TExtendedKeyUsage.ToAsn1Object: IAsn1Object;
begin
  Result := FSeq;
end;

{ TX509Extensions }

class constructor TX509Extensions.Create;
begin
  Boot;
end;

class destructor TX509Extensions.Destroy;
begin
  // Class vars are interface references, no cleanup needed
end;

class procedure TX509Extensions.Boot;
begin
  FSubjectDirectoryAttributes := TDerObjectIdentifier.Create('2.5.29.9');
  FSubjectKeyIdentifier := TDerObjectIdentifier.Create('2.5.29.14');
  FKeyUsage := TDerObjectIdentifier.Create('2.5.29.15');
  FPrivateKeyUsagePeriod := TDerObjectIdentifier.Create('2.5.29.16');
  FSubjectAlternativeName := TDerObjectIdentifier.Create('2.5.29.17');
  FIssuerAlternativeName := TDerObjectIdentifier.Create('2.5.29.18');
  FBasicConstraints := TDerObjectIdentifier.Create('2.5.29.19');
  FCrlNumber := TDerObjectIdentifier.Create('2.5.29.20');
  FReasonCode := TDerObjectIdentifier.Create('2.5.29.21');
  FInstructionCode := TDerObjectIdentifier.Create('2.5.29.23');
  FInvalidityDate := TDerObjectIdentifier.Create('2.5.29.24');
  FDeltaCrlIndicator := TDerObjectIdentifier.Create('2.5.29.27');
  FIssuingDistributionPoint := TDerObjectIdentifier.Create('2.5.29.28');
  FCertificateIssuer := TDerObjectIdentifier.Create('2.5.29.29');
  FNameConstraints := TDerObjectIdentifier.Create('2.5.29.30');
  FCrlDistributionPoints := TDerObjectIdentifier.Create('2.5.29.31');
  FCertificatePolicies := TDerObjectIdentifier.Create('2.5.29.32');
  FPolicyMappings := TDerObjectIdentifier.Create('2.5.29.33');
  FAuthorityKeyIdentifier := TDerObjectIdentifier.Create('2.5.29.35');
  FPolicyConstraints := TDerObjectIdentifier.Create('2.5.29.36');
  FExtendedKeyUsage := TDerObjectIdentifier.Create('2.5.29.37');
  FFreshestCrl := TDerObjectIdentifier.Create('2.5.29.46');
  FInhibitAnyPolicy := TDerObjectIdentifier.Create('2.5.29.54');
  FAuthorityInfoAccess := TX509ObjectIdentifiers.IdPE.Branch('1');
  FBiometricInfo := TX509ObjectIdentifiers.IdPE.Branch('2');
  FQCStatements := TX509ObjectIdentifiers.IdPE.Branch('3');
  FAuditIdentity := TX509ObjectIdentifiers.IdPE.Branch('4');
  FSubjectInfoAccess := TX509ObjectIdentifiers.IdPE.Branch('11');
  FLogoType := TX509ObjectIdentifiers.IdPE.Branch('12');
  FNoRevAvail := TDerObjectIdentifier.Create('2.5.29.56');
  FTargetInformation := TDerObjectIdentifier.Create('2.5.29.55');
  FExpiredCertsOnCrl := TDerObjectIdentifier.Create('2.5.29.60');
  FSubjectAltPublicKeyInfo := TDerObjectIdentifier.Create('2.5.29.72');
  FAltSignatureAlgorithm := TDerObjectIdentifier.Create('2.5.29.73');
  FAltSignatureValue := TDerObjectIdentifier.Create('2.5.29.74');
  FDraftDeltaCertificateDescriptor := TDerObjectIdentifier.Create('2.16.840.1.114027.80.6.1');
end;

{ TKeyPurposeId }

class constructor TKeyPurposeId.Create;
begin
  Boot;
end;

class procedure TKeyPurposeId.Boot;
var
  LIdKp: IDerObjectIdentifier;
  LIdPkinit: String;
begin
  LIdKp := TX509ObjectIdentifiers.IdPkix.Branch('3');
  FAnyExtendedKeyUsage := TDerObjectIdentifier.Create(TX509Extensions.ExtendedKeyUsage.ID + '.0');
  FIdKpServerAuth := TDerObjectIdentifier.Create(LIdKp.ID + '.1');
  FIdKpClientAuth := TDerObjectIdentifier.Create(LIdKp.ID + '.2');
  FIdKpCodeSigning := TDerObjectIdentifier.Create(LIdKp.ID + '.3');
  FIdKpEmailProtection := TDerObjectIdentifier.Create(LIdKp.ID + '.4');
  FIdKpIpsecEndSystem := TDerObjectIdentifier.Create(LIdKp.ID + '.5');
  FIdKpIpsecTunnel := TDerObjectIdentifier.Create(LIdKp.ID + '.6');
  FIdKpIpsecUser := TDerObjectIdentifier.Create(LIdKp.ID + '.7');
  FIdKpTimeStamping := TDerObjectIdentifier.Create(LIdKp.ID + '.8');
  FIdKpOcspSigning := TDerObjectIdentifier.Create(LIdKp.ID + '.9');
  FIdKpDvcs := TDerObjectIdentifier.Create(LIdKp.ID + '.10');
  FIdKpSbgpCertAaServerAuth := TDerObjectIdentifier.Create(LIdKp.ID + '.11');
  FIdKpScvpResponder := TDerObjectIdentifier.Create(LIdKp.ID + '.12');
  FIdKpEapOverPpp := TDerObjectIdentifier.Create(LIdKp.ID + '.13');
  FIdKpEapOverLan := TDerObjectIdentifier.Create(LIdKp.ID + '.14');
  FIdKpScvpServer := TDerObjectIdentifier.Create(LIdKp.ID + '.15');
  FIdKpScvpClient := TDerObjectIdentifier.Create(LIdKp.ID + '.16');
  FIdKpIpsecIke := TDerObjectIdentifier.Create(LIdKp.ID + '.17');
  FIdKpCapwapAc := TDerObjectIdentifier.Create(LIdKp.ID + '.18');
  FIdKpCapwapWtp := TDerObjectIdentifier.Create(LIdKp.ID + '.19');
  FIdKpCmcCa := TDerObjectIdentifier.Create(LIdKp.ID + '.27');
  FIdKpCmcRa := TDerObjectIdentifier.Create(LIdKp.ID + '.28');
  FIdKpCmKga := TDerObjectIdentifier.Create(LIdKp.ID + '.32');
  FIdKpSmartcardlogon := TDerObjectIdentifier.Create('1.3.6.1.4.1.311.20.2.2');
  FIdKpMacAddress := TDerObjectIdentifier.Create('1.3.6.1.1.1.1.22');
  FIdKpMsSgc := TDerObjectIdentifier.Create('1.3.6.1.4.1.311.10.3.3');
  LIdPkinit := '1.3.6.1.5.2.3';
  FScSysNodeNumber := TDerObjectIdentifier.Create(LIdPkinit + '.0');
  FIdPkinitAuthData := TDerObjectIdentifier.Create(LIdPkinit + '.1');
  FIdPkinitDHKeyData := TDerObjectIdentifier.Create(LIdPkinit + '.2');
  FIdPkinitRkeyData := TDerObjectIdentifier.Create(LIdPkinit + '.3');
  FKeyPurposeClientAuth := TDerObjectIdentifier.Create(LIdPkinit + '.4');
  FKeyPurposeKdc := TDerObjectIdentifier.Create(LIdPkinit + '.5');
  FIdKpNsSgc := TDerObjectIdentifier.Create('2.16.840.1.113730.4.1');
end;

class function TKeyPurposeId.GetAnyExtendedKeyUsage: IDerObjectIdentifier;
begin
  Result := FAnyExtendedKeyUsage;
end;

class function TKeyPurposeId.GetIdKpServerAuth: IDerObjectIdentifier;
begin
  Result := FIdKpServerAuth;
end;

class function TKeyPurposeId.GetIdKpClientAuth: IDerObjectIdentifier;
begin
  Result := FIdKpClientAuth;
end;

class function TKeyPurposeId.GetIdKpCodeSigning: IDerObjectIdentifier;
begin
  Result := FIdKpCodeSigning;
end;

class function TKeyPurposeId.GetIdKpEmailProtection: IDerObjectIdentifier;
begin
  Result := FIdKpEmailProtection;
end;

class function TKeyPurposeId.GetIdKpIpsecEndSystem: IDerObjectIdentifier;
begin
  Result := FIdKpIpsecEndSystem;
end;

class function TKeyPurposeId.GetIdKpIpsecTunnel: IDerObjectIdentifier;
begin
  Result := FIdKpIpsecTunnel;
end;

class function TKeyPurposeId.GetIdKpIpsecUser: IDerObjectIdentifier;
begin
  Result := FIdKpIpsecUser;
end;

class function TKeyPurposeId.GetIdKpTimeStamping: IDerObjectIdentifier;
begin
  Result := FIdKpTimeStamping;
end;

class function TKeyPurposeId.GetIdKpOcspSigning: IDerObjectIdentifier;
begin
  Result := FIdKpOcspSigning;
end;

class function TKeyPurposeId.GetIdKpDvcs: IDerObjectIdentifier;
begin
  Result := FIdKpDvcs;
end;

class function TKeyPurposeId.GetIdKpSbgpCertAaServerAuth: IDerObjectIdentifier;
begin
  Result := FIdKpSbgpCertAaServerAuth;
end;

class function TKeyPurposeId.GetIdKpScvpResponder: IDerObjectIdentifier;
begin
  Result := FIdKpScvpResponder;
end;

class function TKeyPurposeId.GetIdKpEapOverPpp: IDerObjectIdentifier;
begin
  Result := FIdKpEapOverPpp;
end;

class function TKeyPurposeId.GetIdKpEapOverLan: IDerObjectIdentifier;
begin
  Result := FIdKpEapOverLan;
end;

class function TKeyPurposeId.GetIdKpScvpServer: IDerObjectIdentifier;
begin
  Result := FIdKpScvpServer;
end;

class function TKeyPurposeId.GetIdKpScvpClient: IDerObjectIdentifier;
begin
  Result := FIdKpScvpClient;
end;

class function TKeyPurposeId.GetIdKpIpsecIke: IDerObjectIdentifier;
begin
  Result := FIdKpIpsecIke;
end;

class function TKeyPurposeId.GetIdKpCapwapAc: IDerObjectIdentifier;
begin
  Result := FIdKpCapwapAc;
end;

class function TKeyPurposeId.GetIdKpCapwapWtp: IDerObjectIdentifier;
begin
  Result := FIdKpCapwapWtp;
end;

class function TKeyPurposeId.GetIdKpCmcCa: IDerObjectIdentifier;
begin
  Result := FIdKpCmcCa;
end;

class function TKeyPurposeId.GetIdKpCmcRa: IDerObjectIdentifier;
begin
  Result := FIdKpCmcRa;
end;

class function TKeyPurposeId.GetIdKpCmKga: IDerObjectIdentifier;
begin
  Result := FIdKpCmKga;
end;

class function TKeyPurposeId.GetIdKpSmartcardlogon: IDerObjectIdentifier;
begin
  Result := FIdKpSmartcardlogon;
end;

class function TKeyPurposeId.GetIdKpMacAddress: IDerObjectIdentifier;
begin
  Result := FIdKpMacAddress;
end;

class function TKeyPurposeId.GetIdKpMsSgc: IDerObjectIdentifier;
begin
  Result := FIdKpMsSgc;
end;

class function TKeyPurposeId.GetScSysNodeNumber: IDerObjectIdentifier;
begin
  Result := FScSysNodeNumber;
end;

class function TKeyPurposeId.GetIdPkinitAuthData: IDerObjectIdentifier;
begin
  Result := FIdPkinitAuthData;
end;

class function TKeyPurposeId.GetIdPkinitDHKeyData: IDerObjectIdentifier;
begin
  Result := FIdPkinitDHKeyData;
end;

class function TKeyPurposeId.GetIdPkinitRkeyData: IDerObjectIdentifier;
begin
  Result := FIdPkinitRkeyData;
end;

class function TKeyPurposeId.GetKeyPurposeClientAuth: IDerObjectIdentifier;
begin
  Result := FKeyPurposeClientAuth;
end;

class function TKeyPurposeId.GetKeyPurposeKdc: IDerObjectIdentifier;
begin
  Result := FKeyPurposeKdc;
end;

class function TKeyPurposeId.GetIdKpNsSgc: IDerObjectIdentifier;
begin
  Result := FIdKpNsSgc;
end;

class function TX509Extensions.GetInstance(AObj: TObject): IX509Extensions;
var
  LSequence: IAsn1Sequence;
  LTagged: IAsn1TaggedObject;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX509Extensions, Result) then
    Exit;

  if Supports(AObj, IAsn1Sequence, LSequence) then
  begin
    Result := TX509Extensions.Create(LSequence);
    Exit;
  end;

  if Supports(AObj, IAsn1TaggedObject, LTagged) then
  begin
    Result := GetInstance(TAsn1Utilities.CheckContextTagClass(LTagged).GetBaseObject().ToAsn1Object());
    Exit;
  end;

  raise EArgumentCryptoLibException.Create('unknown object in factory: ' + TPlatformUtilities.GetTypeName(AObj));
end;

class function TX509Extensions.GetInstance(const AObj: IAsn1Convertible): IX509Extensions;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX509Extensions, Result) then
    Exit;

  Result := TX509Extensions.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TX509Extensions.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IX509Extensions;
begin
  Result := TX509Extensions.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TX509Extensions.GetOptional(const AElement: IAsn1Encodable): IX509Extensions;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IX509Extensions, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TX509Extensions.Create(LSequence)
  else
    Result := nil;
end;

class function TX509Extensions.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IX509Extensions;
begin
  Result := TX509Extensions.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TX509Extensions.GetExtensionParsedValue(const AExtensions: IX509Extensions;
  const AOid: IDerObjectIdentifier): IAsn1Object;
var
  LExt: IX509Extension;
begin
  if AExtensions = nil then
  begin
    Result := nil;
    Exit;
  end;

  LExt := AExtensions.GetExtension(AOid);
  if LExt = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := LExt.GetParsedValue();
end;

constructor TX509Extensions.Create(const ASeq: IAsn1Sequence);
var
  I: Int32;
  LS: IAsn1Sequence;
  LOid: IDerObjectIdentifier;
  LIsCritical: Boolean;
  LOctets: IAsn1OctetString;
  LExt: IX509Extension;
begin
  inherited Create();

  FOrdering := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
  FExtensions := TDictionary<IDerObjectIdentifier, IX509Extension>.Create(TAsn1Comparers.OidEqualityComparer);

  // Don't require non-empty sequence; we see empty extension blocks in the wild
  for I := 0 to ASeq.Count - 1 do
  begin
    LS := TAsn1Sequence.GetInstance(ASeq[I]);

    if (LS.Count < 2) or (LS.Count > 3) then
      raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LS.Count]);

    LOid := TDerObjectIdentifier.GetInstance(LS[0]);

    LIsCritical := (LS.Count = 3) and TDerBoolean.GetInstance(LS[1]).IsTrue;

    LOctets := TAsn1OctetString.GetInstance(LS[LS.Count - 1]);

    if FExtensions.ContainsKey(LOid) then
      raise EArgumentCryptoLibException.CreateFmt('repeated extension found: %s', [LOid.Id]);

    LExt := TX509Extension.Create(LIsCritical, LOctets);
    FExtensions.Add(LOid, LExt);
    FOrdering.Add(LOid);
  end;
end;

constructor TX509Extensions.Create(const AExtensions: TDictionary<IDerObjectIdentifier, IX509Extension>);
begin
  Create(nil, AExtensions);
end;

constructor TX509Extensions.Create(const AOrdering: TList<IDerObjectIdentifier>;
  const AExtensions: TDictionary<IDerObjectIdentifier, IX509Extension>);
var
  LOid: IDerObjectIdentifier;
begin
  inherited Create();

  if AOrdering = nil then
  begin
    FOrdering := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
    for LOid in AExtensions.Keys do
    begin
      FOrdering.Add(LOid);
    end;
  end
  else
  begin
    FOrdering := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
    FOrdering.AddRange(AOrdering);
  end;

  FExtensions := TDictionary<IDerObjectIdentifier, IX509Extension>.Create(TAsn1Comparers.OidEqualityComparer);
  for LOid in FOrdering do
  begin
    FExtensions.Add(LOid, AExtensions[LOid]);
  end;
end;

constructor TX509Extensions.Create(const AOids: TList<IDerObjectIdentifier>;
  const AValues: TList<IX509Extension>);
var
  I: Int32;
begin
  inherited Create();

  FOrdering := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
  FOrdering.AddRange(AOids);
  FExtensions := TDictionary<IDerObjectIdentifier, IX509Extension>.Create(TAsn1Comparers.OidEqualityComparer);

  for I := 0 to FOrdering.Count - 1 do
  begin
    FExtensions.Add(FOrdering[I], AValues[I]);
  end;
end;

destructor TX509Extensions.Destroy;
begin
  FExtensions.Free;
  FOrdering.Free;
  inherited Destroy;
end;

function TX509Extensions.GetCount: Int32;
begin
  Result := FOrdering.Count;
end;

function TX509Extensions.GetExtension(const AOid: IDerObjectIdentifier): IX509Extension;
begin
  if not FExtensions.TryGetValue(AOid, Result) then
    Result := nil;
end;

function TX509Extensions.GetExtensionParsedValue(const AOid: IDerObjectIdentifier): IAsn1Object;
var
  LExt: IX509Extension;
begin
  LExt := GetExtension(AOid);
  if LExt = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := LExt.GetParsedValue();
end;

function TX509Extensions.GetExtensionValue(const AOid: IDerObjectIdentifier): IAsn1OctetString;
var
  LExt: IX509Extension;
begin
  LExt := GetExtension(AOid);
  if LExt = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := LExt.Value;
end;

function TX509Extensions.GetExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := TCollectionUtilities.ToArray<IDerObjectIdentifier>(FOrdering);
end;

function TX509Extensions.GetNonCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := GetExtensionOidsInternal(False);
end;

function TX509Extensions.GetCriticalExtensionOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := GetExtensionOidsInternal(True);
end;

function TX509Extensions.GetExtensionOidsInternal(AIsCritical: Boolean): TCryptoLibGenericArray<IDerObjectIdentifier>;
var
  LOids: TList<IDerObjectIdentifier>;
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
begin
  LOids := TList<IDerObjectIdentifier>.Create();
  try
    for LOid in FOrdering do
    begin
      LExt := FExtensions[LOid];
      if LExt.IsCritical = AIsCritical then
      begin
        LOids.Add(LOid);
      end;
    end;
    Result := LOids.ToArray();
  finally
    LOids.Free;
  end;
end;

function TX509Extensions.HasAnyCriticalExtensions: Boolean;
var
  LOid: IDerObjectIdentifier;
begin
  for LOid in FOrdering do
  begin
    if FExtensions[LOid].IsCritical then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

function TX509Extensions.Equivalent(const AOther: IX509Extensions): Boolean;
var
  LOid: IDerObjectIdentifier;
  LOtherExt: IX509Extension;
begin
  if AOther.Count <> FExtensions.Count then
  begin
    Result := False;
    Exit;
  end;

  for LOid in FOrdering do
  begin
    LOtherExt := AOther.GetExtension(LOid);
    if (LOtherExt = nil) or (not FExtensions[LOid].Value.Equals(LOtherExt.Value)) or
      (FExtensions[LOid].IsCritical <> LOtherExt.IsCritical) then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

function TX509Extensions.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
begin
  LV := TAsn1EncodableVector.Create(FOrdering.Count);

  for LOid in FOrdering do
  begin
    LExt := FExtensions[LOid];
    if LExt.IsCritical then
    begin
      LV.Add(TDerSequence.Create([LOid, TDerBoolean.True, LExt.Value]));
    end
    else
    begin
      LV.Add(TDerSequence.Create([LOid, LExt.Value]));
    end;
  end;

  Result := TDerSequence.Create(LV);
end;

function TX509Extensions.ToAsn1ObjectTrimmed: IAsn1Sequence;
var
  LCount: Int32;
  LV: IAsn1EncodableVector;
  LOid: IDerObjectIdentifier;
  LExt: IX509Extension;
begin
  // Count excludes AltSignatureValue if present
  LCount := FOrdering.Count;
  if FExtensions.ContainsKey(TX509Extensions.AltSignatureValue) then
    System.Dec(LCount);

  LV := TAsn1EncodableVector.Create(LCount);

  for LOid in FOrdering do
  begin
    if TX509Extensions.AltSignatureValue.Equals(LOid) then
      Continue;

    LExt := FExtensions[LOid];
    if LExt.IsCritical then
    begin
      LV.Add(TDerSequence.Create([LOid, TDerBoolean.True, LExt.Value]));
    end
    else
    begin
      LV.Add(TDerSequence.Create([LOid, LExt.Value]));
    end;
  end;

  Result := TDerSequence.Create(LV);
end;

{ TX509Name }

class function TX509Name.GetInstance(AObj: TObject): IX509Name;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IX509Name>(AObj,
    function(AElement: IAsn1Encodable): IX509Name
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TX509Name.GetInstance(const AObj: IAsn1Convertible): IX509Name;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IX509Name, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<IX509Name>(AObj.ToAsn1Object(),
    function(AElement: IAsn1Encodable): IX509Name
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TX509Name.GetInstance(const AEncoded: TCryptoLibByteArray): IX509Name;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IX509Name>(AEncoded,
    function(AElement: IAsn1Encodable): IX509Name
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TX509Name.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IX509Name;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IX509Name>(AObj, AExplicitly,
    function(AElement: IAsn1Encodable): IX509Name
    begin
      Result := GetInstance(AElement);
    end);
end;

class function TX509Name.GetOptional(const AElement: IAsn1Encodable): IX509Name;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IX509Name, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TX509Name.Create(LSequence)
  else
    Result := nil;
end;

class function TX509Name.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IX509Name;
begin
  Result := TAsn1Utilities.GetTaggedChoice<IX509Name>(ATaggedObject, ADeclaredExplicit,
    function(AElement: IAsn1Encodable): IX509Name
    begin
      Result := GetOptional(AElement);
    end);
end;

constructor TX509Name.Create(const ASeq: IAsn1Sequence);
var
  I, J: Int32;
  LRdn: IAsn1Set;
  LAttrTypeAndValue: IAsn1Sequence;
  LType, LValue: IAsn1Object;
  LAsn1String: IAsn1String;
  LValueStr: String;
  LOidList: TList<IDerObjectIdentifier>;
  LValueList: TList<String>;
  LAddedList: TList<Boolean>;
begin
  inherited Create();
  FSeq := ASeq;
  FConverter := nil;

  LOidList := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
  LValueList := TList<String>.Create();
  LAddedList := TList<Boolean>.Create();
  try
    // RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
    for I := 0 to ASeq.Count - 1 do
    begin
      // RelativeDistinguishedName ::= SET SIZE(1..MAX) OF AttributeTypeAndValue
      LRdn := TAsn1Set.GetInstance(ASeq[I]);

      for J := 0 to LRdn.Count - 1 do
      begin
        // AttributeTypeAndValue ::= SEQUENCE { type OID, value ANY }
        LAttrTypeAndValue := TAsn1Sequence.GetInstance(LRdn[J]);
        if LAttrTypeAndValue.Count <> 2 then
          raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LAttrTypeAndValue.Count]);

        LType := LAttrTypeAndValue[0].ToAsn1Object();
        LValue := LAttrTypeAndValue[1].ToAsn1Object();

        LOidList.Add(TDerObjectIdentifier.GetInstance(LType));

        // Handle string values vs hex-encoded values
        if Supports(LValue, IAsn1String, LAsn1String) then
        begin
          // Check if it's DerUniversalString (which we don't treat as string)
          if not Supports(LValue, IDerUniversalString) then
          begin
            LValueStr := LAsn1String.GetString();
            if (System.Length(LValueStr) > 0) and (LValueStr[1] = '#') then
            begin
              LValueStr := '\' + LValueStr;
            end;
            LValueList.Add(LValueStr);
          end
          else
          begin
            // DerUniversalString - hex encode
            LValueStr := '#' + THexEncoder.Encode(LValue.GetEncoded(TAsn1Encodable.Der), False);
            LValueList.Add(LValueStr);
          end;
        end
        else
        begin
          // Hex-encode non-string values
          LValueStr := '#' + THexEncoder.Encode(LValue.GetEncoded(TAsn1Encodable.Der), False);
          LValueList.Add(LValueStr);
        end;

        // true if not first attribute in RDN
        LAddedList.Add(J <> 0);
      end;
    end;

    // Convert lists to arrays
    FOids := TCollectionUtilities.ToArray<IDerObjectIdentifier>(LOidList);
    FValues := TCollectionUtilities.ToArray<String>(LValueList);
    FAdded := TCollectionUtilities.ToArray<Boolean>(LAddedList);
    FValueList := TCollectionUtilities.ToArray<String>(LValueList);
  finally
    LOidList.Free;
    LValueList.Free;
    LAddedList.Free;
  end;
end;

constructor TX509Name.Create(const AName: String);
begin
  Create(False, AName);
end;

constructor TX509Name.Create(const AReverse: Boolean; const AName: String);
begin
  Create(AReverse, FDefaultLookup, AName);
end;

constructor TX509Name.Create(const AReverse: Boolean; const ATable: TDictionary<String, String>;
  const AName: String);
var
  LLookup: TDictionary<String, IDerObjectIdentifier>;
  LKey: String;
  LOid: IDerObjectIdentifier;
  LPair: TPair<String, IDerObjectIdentifier>;
begin
  inherited Create();
  FConverter := CreateDefaultConverter();

  if ATable <> nil then
  begin
    // This constructor takes TDictionary<String, String> which needs conversion
    // Convert string keys to OIDs using DefaultLookup, then merge with DefaultLookup
    LLookup := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);
    try
      // First, add entries from ATable (convert string keys to OIDs via DefaultLookup)
      for LKey in ATable.Keys do
      begin
        if FDefaultLookup.TryGetValue(LKey, LOid) then
        begin
          LLookup.Add(LKey, LOid);
        end;
      end;
      // Then add all entries from DefaultLookup
      for LPair in FDefaultLookup do
      begin
        if not LLookup.ContainsKey(LPair.Key) then
        begin
          LLookup.Add(LPair.Key, LPair.Value);
        end;
      end;
      Create(AReverse, LLookup, AName, FConverter);
    finally
      LLookup.Free;
    end;
  end
  else
  begin
    Create(AReverse, FDefaultLookup, AName, FConverter);
  end;
end;

constructor TX509Name.Create(const AOrdering: TList<IDerObjectIdentifier>;
  const AAttributes: TDictionary<IDerObjectIdentifier, String>);
begin
  Create(AOrdering, AAttributes, CreateDefaultConverter());
end;

constructor TX509Name.Create(const AOrdering: TList<IDerObjectIdentifier>;
  const AAttributes: TDictionary<IDerObjectIdentifier, String>;
  const AConverter: IX509NameEntryConverter);
var
  LOid: IDerObjectIdentifier;
  LAttribute: String;
  I: Int32;
begin
  inherited Create();
  FConverter := AConverter;

  FOids := TCollectionUtilities.ToArray<IDerObjectIdentifier>(AOrdering);
  System.SetLength(FValues, AOrdering.Count);
  System.SetLength(FAdded, AOrdering.Count);

  for I := 0 to AOrdering.Count - 1 do
  begin
    LOid := AOrdering[I];
    if not AAttributes.TryGetValue(LOid, LAttribute) then
      raise EArgumentCryptoLibException.CreateFmt('No attribute for object id - %s - passed to distinguished name', [LOid.Id]);

    FValues[I] := LAttribute;
    FAdded[I] := False;
  end;
end;

constructor TX509Name.Create(const AOids: TList<IDerObjectIdentifier>;
  const AValues: TList<String>);
begin
  Create(AOids, AValues, CreateDefaultConverter());
end;

constructor TX509Name.Create(const AOids: TList<IDerObjectIdentifier>;
  const AValues: TList<String>; const AConverter: IX509NameEntryConverter);
var
  I: Int32;
begin
  inherited Create();
  FConverter := AConverter;

  if AOids.Count <> AValues.Count then
    raise EArgumentCryptoLibException.Create('''oids'' must be same length as ''values''.');

  FOids := TCollectionUtilities.ToArray<IDerObjectIdentifier>(AOids);
  FValues := TCollectionUtilities.ToArray<String>(AValues);
  System.SetLength(FAdded, AOids.Count);
  for I := 0 to AOids.Count - 1 do
  begin
    FAdded[I] := False;
  end;
end;

constructor TX509Name.Create(const ADirName: String; const AConverter: IX509NameEntryConverter);
begin
  Create(FDefaultReverse, ADirName, AConverter);
end;

constructor TX509Name.Create(const AReverse: Boolean; const ADirName: String;
  const AConverter: IX509NameEntryConverter);
begin
  Create(AReverse, FDefaultLookup, ADirName, AConverter);
end;

constructor TX509Name.Create(const AReverse: Boolean; const ALookup: TDictionary<String, IDerObjectIdentifier>;
  const ADirName: String);
begin
  Create(AReverse, ALookup, ADirName, CreateDefaultConverter());
end;

constructor TX509Name.Create(const AReverse: Boolean; const ALookup: TDictionary<String, IDerObjectIdentifier>;
  const ADirName: String; const AConverter: IX509NameEntryConverter);
var
  LNameTokenizer, LRdnTokenizer: IX509NameTokenizer;
  LRdn: String;
  LOidList: TList<IDerObjectIdentifier>;
  LValueList: TList<String>;
  LAddedList: TList<Boolean>;
  I, LCount: Int32;
  LO: TList<IDerObjectIdentifier>;
  LV: TList<String>;
  LA: TList<Boolean>;
begin
  inherited Create();
  FConverter := AConverter;

  LOidList := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
  LValueList := TList<String>.Create();
  LAddedList := TList<Boolean>.Create();
  try
    LNameTokenizer := TX509NameTokenizer.Create(ADirName);
    while LNameTokenizer.HasMoreTokens() do
    begin
      LRdn := NextToken(LNameTokenizer);

      LRdnTokenizer := TX509NameTokenizer.Create(LRdn, '+');
      AddAttribute(ALookup, NextToken(LRdnTokenizer), False, LOidList, LValueList, LAddedList);

      while LRdnTokenizer.HasMoreTokens() do
      begin
        AddAttribute(ALookup, NextToken(LRdnTokenizer), True, LOidList, LValueList, LAddedList);
      end;
    end;

    if AReverse then
    begin
      // Reverse the order
      LO := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
      LV := TList<String>.Create();
      LA := TList<Boolean>.Create();
      try
        LCount := 1;
        for I := 0 to LOidList.Count - 1 do
        begin
          if LAddedList[I] then
            LCount := LCount and Int32(-1)
          else
            LCount := LCount and 0;  // Set to 0 (all bits clear)
          LO.Insert(LCount, LOidList[I]);
          LV.Insert(LCount, LValueList[I]);
          LA.Insert(LCount, LAddedList[I]);
          System.Inc(LCount);
        end;
        LOidList.Clear;
        LValueList.Clear;
        LAddedList.Clear;
        LOidList.AddRange(LO);
        LValueList.AddRange(LV);
        LAddedList.AddRange(LA);
      finally
        LO.Free;
        LV.Free;
        LA.Free;
      end;
    end;

    FOids := TCollectionUtilities.ToArray<IDerObjectIdentifier>(LOidList);
    FValues := TCollectionUtilities.ToArray<String>(LValueList);
    FAdded := TCollectionUtilities.ToArray<Boolean>(LAddedList);
    FValueList := TCollectionUtilities.ToArray<String>(LValueList);
  finally
    LOidList.Free;
    LValueList.Free;
    LAddedList.Free;
  end;
end;

constructor TX509Name.Create(const AOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  const AValues: TCryptoLibStringArray);
var
  I: Int32;
begin
  inherited Create();
  FConverter := CreateDefaultConverter();
  FOids := TArrayUtilities.Clone<IDerObjectIdentifier>(AOids,
    function(A: IDerObjectIdentifier): IDerObjectIdentifier
    begin
      Result := A;
    end);
  FValues := System.Copy(AValues);
  FValueList := System.Copy(AValues);
  // Initialize FAdded array - all false for direct constructor
  System.SetLength(FAdded, System.Length(FOids));
  for I := 0 to System.Length(FAdded) - 1 do
  begin
    FAdded[I] := False;
  end;
end;

function TX509Name.GetOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := TArrayUtilities.Clone<IDerObjectIdentifier>(FOids,
    function(A: IDerObjectIdentifier): IDerObjectIdentifier
    begin
      Result := A;
    end);
end;

function TX509Name.GetValues: TCryptoLibStringArray;
begin
  Result := System.Copy(FValues);
end;

function TX509Name.GetValueList: TCryptoLibStringArray;
begin
  Result := GetValueList(nil);
end;

function TX509Name.GetValue(const AOid: IDerObjectIdentifier): String;
var
  I: Int32;
begin
  for I := 0 to System.Length(FOids) - 1 do
  begin
    if FOids[I].Equals(AOid) then
    begin
      Result := FValues[I];
      Exit;
    end;
  end;
  Result := '';
end;

function TX509Name.GetValues(const AOid: IDerObjectIdentifier): TCryptoLibStringArray;
var
  LValues: TList<String>;
  I: Int32;
begin
  LValues := TList<String>.Create();
  try
    for I := 0 to System.Length(FOids) - 1 do
    begin
      if FOids[I].Equals(AOid) then
      begin
        LValues.Add(FValues[I]);
      end;
    end;
    Result := LValues.ToArray();
  finally
    LValues.Free;
  end;
end;

function TX509Name.ToString: String;
begin
  Result := ToString(FDefaultReverse, FDefaultSymbols);
end;

function TX509Name.ToString(AReverse: Boolean; const AOidSymbols: TDictionary<IDerObjectIdentifier, String>): String;
var
  LComponents: TList<TStringBuilder>;
  LAva: TStringBuilder;
  I: Int32;
  LBuf: TStringBuilder;
begin
  LComponents := TList<TStringBuilder>.Create();
  try
    LAva := nil;

    for I := 0 to System.Length(FOids) - 1 do
    begin
      if FAdded[I] then
      begin
        LAva.Append('+');
        AppendValue(LAva, AOidSymbols, FOids[I], FValues[I]);
      end
      else
      begin
        LAva := TStringBuilder.Create();
        AppendValue(LAva, AOidSymbols, FOids[I], FValues[I]);
        LComponents.Add(LAva);
      end;
    end;

    if AReverse then
    begin
      // Reverse components list
      for I := 0 to (LComponents.Count div 2) - 1 do
      begin
        LComponents.Exchange(I, LComponents.Count - 1 - I);
      end;
    end;

    LBuf := TStringBuilder.Create();
    try
      if LComponents.Count > 0 then
      begin
        LBuf.Append(LComponents[0].ToString());

        for I := 1 to LComponents.Count - 1 do
        begin
          LBuf.Append(',');
          LBuf.Append(LComponents[I].ToString());
        end;
      end;

      Result := LBuf.ToString();
    finally
      LBuf.Free;
    end;
  finally
    for I := 0 to LComponents.Count - 1 do
      LComponents[I].Free;
    LComponents.Free;
  end;
end;

function TX509Name.ToString(const AOid: IDerObjectIdentifier): String;
begin
  Result := GetValue(AOid);
end;

function TX509Name.ToAsn1Object: IAsn1Object;
var
  LVec, LSVec: IAsn1EncodableVector;
  LOid: IDerObjectIdentifier;
  I: Int32;
  LConvertedValue: IAsn1Object;
begin
  if FSeq <> nil then
  begin
    Result := FSeq;
    Exit;
  end;

  // Initialize converter if not already set
  if FConverter = nil then
  begin
    FConverter := CreateDefaultConverter();
  end;

  LVec := TAsn1EncodableVector.Create();
  LSVec := TAsn1EncodableVector.Create();
  LOid := nil;

  for I := 0 to System.Length(FOids) - 1 do
  begin
    // If previous OID exists and current is not added to current RDN, finalize RDN
    if (LOid <> nil) and (not FAdded[I]) then
    begin
      LVec.Add(TDerSet.FromVector(LSVec));
      LSVec := TAsn1EncodableVector.Create();
    end;

    LOid := FOids[I];
    LConvertedValue := FConverter.GetConvertedValue(LOid, FValues[I]);
    LSVec.Add(TDerSequence.Create([LOid, LConvertedValue]));
  end;

  // Add final RDN
  LVec.Add(TDerSet.FromVector(LSVec));

  FSeq := TDerSequence.Create(LVec);
  Result := FSeq;
end;

class constructor TX509Name.Create;
begin
  FDefaultReverseLock := TCriticalSection.Create();
  Boot;
end;

class destructor TX509Name.Destroy;
begin
  FDefaultSymbols.Free;
  FRFC2253Symbols.Free;
  FRFC1779Symbols.Free;
  FDefaultLookup.Free;
  FDefaultReverseLock.Free;
end;

class function TX509Name.GetDefaultReverse: Boolean;
begin
  FDefaultReverseLock.Acquire;
  try
    Result := FDefaultReverse;
  finally
    FDefaultReverseLock.Release;
  end;
end;

class procedure TX509Name.SetDefaultReverse(const AValue: Boolean);
begin
  FDefaultReverseLock.Acquire;
  try
    FDefaultReverse := AValue;
  finally
    FDefaultReverseLock.Release;
  end;
end;

class procedure TX509Name.Boot;
begin
  FDefaultReverse := False;
  FDefaultSymbols := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  FRFC2253Symbols := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  FRFC1779Symbols := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  FDefaultLookup := TDictionary<String, IDerObjectIdentifier>.Create(TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer);

  // OID constants
  FC := TDerObjectIdentifier.Create('2.5.4.6');
  FO := TDerObjectIdentifier.Create('2.5.4.10');
  FOU := TDerObjectIdentifier.Create('2.5.4.11');
  FT := TDerObjectIdentifier.Create('2.5.4.12');
  FCN := TDerObjectIdentifier.Create('2.5.4.3');
  FStreet := TDerObjectIdentifier.Create('2.5.4.9');
  FSerialNumber := TDerObjectIdentifier.Create('2.5.4.5');
  FL := TDerObjectIdentifier.Create('2.5.4.7');
  FST := TDerObjectIdentifier.Create('2.5.4.8');
  FSurname := TDerObjectIdentifier.Create('2.5.4.4');
  FGivenName := TDerObjectIdentifier.Create('2.5.4.42');
  FInitials := TDerObjectIdentifier.Create('2.5.4.43');
  FGeneration := TDerObjectIdentifier.Create('2.5.4.44');
  FUniqueIdentifier := TDerObjectIdentifier.Create('2.5.4.45');
  FDescription := TDerObjectIdentifier.Create('2.5.4.13');
  FBusinessCategory := TDerObjectIdentifier.Create('2.5.4.15');
  FPostalCode := TDerObjectIdentifier.Create('2.5.4.17');
  FDnQualifier := TDerObjectIdentifier.Create('2.5.4.46');
  FPseudonym := TDerObjectIdentifier.Create('2.5.4.65');
  FRole := TDerObjectIdentifier.Create('2.5.4.72');
  FDateOfBirth := TX509ObjectIdentifiers.IdPda.Branch('1');
  FPlaceOfBirth := TX509ObjectIdentifiers.IdPda.Branch('2');
  FGender := TX509ObjectIdentifiers.IdPda.Branch('3');
  FCountryOfCitizenship := TX509ObjectIdentifiers.IdPda.Branch('4');
  FCountryOfResidence := TX509ObjectIdentifiers.IdPda.Branch('5');
  FNameAtBirth := TDerObjectIdentifier.Create('1.3.36.8.3.14');
  FPostalAddress := TDerObjectIdentifier.Create('2.5.4.16');
  FDmdName := TDerObjectIdentifier.Create('2.5.4.54');
  FTelephoneNumber := TX509ObjectIdentifiers.IdAtTelephoneNumber;
  FOrganizationIdentifier := TX509ObjectIdentifiers.IdAtOrganizationIdentifier;
  FName := TX509ObjectIdentifiers.IdAtName;
  FEmailAddress := TPkcsObjectIdentifiers.Pkcs9AtEmailAddress;
  FUnstructuredName := TPkcsObjectIdentifiers.Pkcs9AtUnstructuredName;
  FUnstructuredAddress := TPkcsObjectIdentifiers.Pkcs9AtUnstructuredAddress;
  FE := FEmailAddress;
  FDC := TDerObjectIdentifier.Create('0.9.2342.19200300.100.1.25');
  FUID := TDerObjectIdentifier.Create('0.9.2342.19200300.100.1.1');
  FJurisdictionC := TDerObjectIdentifier.Create('1.3.6.1.4.1.311.60.2.1.3');
  FJurisdictionST := TDerObjectIdentifier.Create('1.3.6.1.4.1.311.60.2.1.2');
  FJurisdictionL := TDerObjectIdentifier.Create('1.3.6.1.4.1.311.60.2.1.1');

  // DefaultSymbols
  FDefaultSymbols.Add(FC, 'C');
  FDefaultSymbols.Add(FO, 'O');
  FDefaultSymbols.Add(FT, 'T');
  FDefaultSymbols.Add(FOU, 'OU');
  FDefaultSymbols.Add(FCN, 'CN');
  FDefaultSymbols.Add(FL, 'L');
  FDefaultSymbols.Add(FST, 'ST');
  FDefaultSymbols.Add(FSerialNumber, 'SERIALNUMBER');
  FDefaultSymbols.Add(FEmailAddress, 'E');
  FDefaultSymbols.Add(FDC, 'DC');
  FDefaultSymbols.Add(FUID, 'UID');
  FDefaultSymbols.Add(FStreet, 'STREET');
  FDefaultSymbols.Add(FSurname, 'SURNAME');
  FDefaultSymbols.Add(FGivenName, 'GIVENNAME');
  FDefaultSymbols.Add(FInitials, 'INITIALS');
  FDefaultSymbols.Add(FGeneration, 'GENERATION');
  FDefaultSymbols.Add(FDescription, 'DESCRIPTION');
  FDefaultSymbols.Add(FRole, 'ROLE');
  FDefaultSymbols.Add(FUnstructuredAddress, 'unstructuredAddress');
  FDefaultSymbols.Add(FUnstructuredName, 'unstructuredName');
  FDefaultSymbols.Add(FUniqueIdentifier, 'UniqueIdentifier');
  FDefaultSymbols.Add(FDnQualifier, 'DN');
  FDefaultSymbols.Add(FPseudonym, 'Pseudonym');
  FDefaultSymbols.Add(FPostalAddress, 'PostalAddress');
  FDefaultSymbols.Add(FNameAtBirth, 'NameAtBirth');
  FDefaultSymbols.Add(FCountryOfCitizenship, 'CountryOfCitizenship');
  FDefaultSymbols.Add(FCountryOfResidence, 'CountryOfResidence');
  FDefaultSymbols.Add(FGender, 'Gender');
  FDefaultSymbols.Add(FPlaceOfBirth, 'PlaceOfBirth');
  FDefaultSymbols.Add(FDateOfBirth, 'DateOfBirth');
  FDefaultSymbols.Add(FPostalCode, 'PostalCode');
  FDefaultSymbols.Add(FBusinessCategory, 'BusinessCategory');
  FDefaultSymbols.Add(FTelephoneNumber, 'TelephoneNumber');
  FDefaultSymbols.Add(FName, 'Name');
  FDefaultSymbols.Add(FOrganizationIdentifier, 'organizationIdentifier');
  FDefaultSymbols.Add(FJurisdictionC, 'jurisdictionCountry');
  FDefaultSymbols.Add(FJurisdictionST, 'jurisdictionState');
  FDefaultSymbols.Add(FJurisdictionL, 'jurisdictionLocality');

  // RFC2253Symbols
  FRFC2253Symbols.Add(FC, 'C');
  FRFC2253Symbols.Add(FO, 'O');
  FRFC2253Symbols.Add(FOU, 'OU');
  FRFC2253Symbols.Add(FCN, 'CN');
  FRFC2253Symbols.Add(FL, 'L');
  FRFC2253Symbols.Add(FST, 'ST');
  FRFC2253Symbols.Add(FStreet, 'STREET');
  FRFC2253Symbols.Add(FDC, 'DC');
  FRFC2253Symbols.Add(FUID, 'UID');

  // RFC1779Symbols
  FRFC1779Symbols.Add(FC, 'C');
  FRFC1779Symbols.Add(FO, 'O');
  FRFC1779Symbols.Add(FOU, 'OU');
  FRFC1779Symbols.Add(FCN, 'CN');
  FRFC1779Symbols.Add(FL, 'L');
  FRFC1779Symbols.Add(FST, 'ST');
  FRFC1779Symbols.Add(FStreet, 'STREET');

  // DefaultLookup
  FDefaultLookup.Add('c', FC);
  FDefaultLookup.Add('o', FO);
  FDefaultLookup.Add('t', FT);
  FDefaultLookup.Add('ou', FOU);
  FDefaultLookup.Add('cn', FCN);
  FDefaultLookup.Add('l', FL);
  FDefaultLookup.Add('st', FST);
  FDefaultLookup.Add('sn', FSurname);
  FDefaultLookup.Add('serialnumber', FSerialNumber);
  FDefaultLookup.Add('street', FStreet);
  FDefaultLookup.Add('emailaddress', FE);
  FDefaultLookup.Add('dc', FDC);
  FDefaultLookup.Add('e', FE);
  FDefaultLookup.Add('uid', FUID);
  FDefaultLookup.Add('surname', FSurname);
  FDefaultLookup.Add('givenname', FGivenName);
  FDefaultLookup.Add('initials', FInitials);
  FDefaultLookup.Add('generation', FGeneration);
  FDefaultLookup.Add('description', FDescription);
  FDefaultLookup.Add('role', FRole);
  FDefaultLookup.Add('unstructuredaddress', FUnstructuredAddress);
  FDefaultLookup.Add('unstructuredname', FUnstructuredName);
  FDefaultLookup.Add('uniqueidentifier', FUniqueIdentifier);
  FDefaultLookup.Add('dn', FDnQualifier);
  FDefaultLookup.Add('pseudonym', FPseudonym);
  FDefaultLookup.Add('postaladdress', FPostalAddress);
  FDefaultLookup.Add('nameatbirth', FNameAtBirth);
  FDefaultLookup.Add('countryofcitizenship', FCountryOfCitizenship);
  FDefaultLookup.Add('countryofresidence', FCountryOfResidence);
  FDefaultLookup.Add('gender', FGender);
  FDefaultLookup.Add('placeofbirth', FPlaceOfBirth);
  FDefaultLookup.Add('dateofbirth', FDateOfBirth);
  FDefaultLookup.Add('postalcode', FPostalCode);
  FDefaultLookup.Add('businesscategory', FBusinessCategory);
  FDefaultLookup.Add('telephonenumber', FTelephoneNumber);
  FDefaultLookup.Add('name', FName);
  FDefaultLookup.Add('organizationidentifier', FOrganizationIdentifier);
  FDefaultLookup.Add('jurisdictioncountry', FJurisdictionC);
  FDefaultLookup.Add('jurisdictionstate', FJurisdictionST);
  FDefaultLookup.Add('jurisdictionlocality', FJurisdictionL);
end;

class function TX509Name.CreateDefaultConverter: IX509NameEntryConverter;
begin
  Result := TX509DefaultEntryConverter.Create();
end;

class function TX509Name.DecodeOid(const AName: String;
  const ALookup: TDictionary<String, IDerObjectIdentifier>): IDerObjectIdentifier;
var
  LOid: IDerObjectIdentifier;
begin
  if (System.Length(AName) >= 4) and TStringUtilities.StartsWith(AName, 'OID.', True) then
  begin
    // Skip "OID." (4 characters), copy rest of string
    Result := TDerObjectIdentifier.Create(System.Copy(AName, 5, System.Length(AName) - 4));
    Exit;
  end;

  if TDerObjectIdentifier.TryFromID(AName, LOid) then
  begin
    Result := LOid;
    Exit;
  end;

  if ALookup.TryGetValue(AName, LOid) then
  begin
    Result := LOid;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateFmt('Unknown object id - %s - passed to distinguished name', [AName]);
end;

class function TX509Name.NextToken(const ATokenizer: IX509NameTokenizer): String;
var
  LToken: String;
begin
  LToken := ATokenizer.NextToken();
  if LToken = '' then
    raise EArgumentCryptoLibException.Create('badly formatted directory string');
  Result := LToken;
end;

class function TX509Name.NextToken(const ATokenizer: IX509NameTokenizer; AExpectMoreTokens: Boolean): String;
var
  LToken: String;
begin
  LToken := ATokenizer.NextToken();
  if (LToken = '') or (ATokenizer.HasMoreTokens() <> AExpectMoreTokens) then
    raise EArgumentCryptoLibException.Create('badly formatted directory string');
  Result := LToken;
end;


class function TX509Name.EquivalentStrings(const AS1, AS2: String): Boolean;
var
  LV1, LV2: String;
begin
  if AS1 = AS2 then
  begin
    Result := True;
    Exit;
  end;

  LV1 := TIetfUtilities.Canonicalize(AS1);
  LV2 := TIetfUtilities.Canonicalize(AS2);

  if LV1 <> LV2 then
  begin
    LV1 := TIetfUtilities.StripInternalSpaces(LV1);
    LV2 := TIetfUtilities.StripInternalSpaces(LV2);

    if LV1 <> LV2 then
    begin
      Result := False;
      Exit;
    end;
  end;

  Result := True;
end;

procedure TX509Name.AddAttribute(const ALookup: TDictionary<String, IDerObjectIdentifier>;
  const AToken: String; AAdded: Boolean; const AOidList: TList<IDerObjectIdentifier>;
  const AValueList: TList<String>; const AAddedList: TList<Boolean>);
var
  LTokenizer: IX509NameTokenizer;
  LTypeToken, LValueToken: String;
  LOid: IDerObjectIdentifier;
  LUnescapedValue: String;
begin
  LTokenizer := TX509NameTokenizer.Create(AToken, '=');
  LTypeToken := NextToken(LTokenizer, True);
  LValueToken := NextToken(LTokenizer, False);

  LOid := DecodeOid(Trim(LTypeToken), ALookup);
  LUnescapedValue := TIetfUtilities.Unescape(LValueToken);

  AOidList.Add(LOid);
  AValueList.Add(LUnescapedValue);
  AAddedList.Add(AAdded);
end;

class procedure TX509Name.AppendValue(const ABuf: TStringBuilder;
  const AOidSymbols: TDictionary<IDerObjectIdentifier, String>;
  const AOid: IDerObjectIdentifier; const AVal: String);
var
  LSym: String;
  LStart, LEnd, LIndex: Int32;
  LC: Char;
begin
  if AOidSymbols.TryGetValue(AOid, LSym) then
    ABuf.Append(LSym)
  else
    ABuf.Append(AOid.Id);

  ABuf.Append('=');
  LStart := ABuf.Length;

  ABuf.Append(AVal);
  LEnd := ABuf.Length;

  // Skip escaped hash prefix if present
  LIndex := LStart;
  if (LIndex + 1 < LEnd) and (ABuf.Chars[LIndex] = '\') and (ABuf.Chars[LIndex + 1] = '#') then
    System.Inc(LIndex, 2);

  // Escape special characters
  while LIndex <> LEnd do
  begin
    LC := ABuf.Chars[LIndex];
    case LC of
      ',', '"', '\', '+', '=', '<', '>', ';':
      begin
        ABuf.Insert(LIndex, '\');
        System.Inc(LIndex, 2);
        System.Inc(LEnd);
      end;
    else
      begin
        System.Inc(LIndex);
      end;
    end;
  end;

  while (LStart < LEnd) and (ABuf.Chars[LStart] = ' ') do
  begin
    ABuf.Insert(LStart, '\');
    System.Inc(LStart, 2);
    System.Inc(LEnd);
  end;

  // Escape trailing spaces
  // Pre-decrement end at start of each iteration, then check
  // First decrement before loop
  System.Dec(LEnd);
  while (LEnd > LStart) and (ABuf.Chars[LEnd] = ' ') do
  begin
    ABuf.Insert(LEnd, '\');
    // Decrement for next iteration (matches --end in while condition)
    System.Dec(LEnd);
  end;
end;

function TX509Name.GetOidList: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := TArrayUtilities.Clone<IDerObjectIdentifier>(FOids,
    function(A: IDerObjectIdentifier): IDerObjectIdentifier
    begin
      Result := A;
    end);
end;

function TX509Name.GetValueList(const AOid: IDerObjectIdentifier): TCryptoLibStringArray;
var
  LV: TList<String>;
  I: Int32;
  LValue: String;
begin
  LV := TList<String>.Create();
  try
    for I := 0 to System.Length(FValues) - 1 do
    begin
      if (AOid = nil) or AOid.Equals(FOids[I]) then
      begin
        LValue := FValues[I];
        if TStringUtilities.StartsWith(LValue, '\#') then
        begin
          // Skip '\' at position 1, copy rest of string
          LValue := System.Copy(LValue, 2, System.Length(LValue) - 1);
        end;
        LV.Add(LValue);
      end;
    end;
    Result := LV.ToArray();
  finally
    LV.Free;
  end;
end;

function TX509Name.Equivalent(const AOther: IX509Name; AInOrder: Boolean): Boolean;
var
  LOtherOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LOtherValues: TCryptoLibStringArray;
  I, LOrderingSize, LStart, LEnd, LDelta, J: Int32;
  LIndexes: TCryptoLibBooleanArray;
  LOid: IDerObjectIdentifier;
  LValue: String;
  LFound: Boolean;
begin
  if AOther = nil then
  begin
    Result := False;
    Exit;
  end;

  if AOther = Self as IX509Name then
  begin
    Result := True;
    Exit;
  end;

  LOtherOids := AOther.Oids;
  LOtherValues := AOther.Values;
  LOrderingSize := System.Length(FOids);

  if LOrderingSize <> System.Length(LOtherOids) then
  begin
    Result := False;
    Exit;
  end;

  if LOrderingSize = 0 then
  begin
    Result := True;
    Exit;
  end;

  if AInOrder then
  begin
    // In-order comparison
    for I := 0 to LOrderingSize - 1 do
    begin
      if not FOids[I].Equals(LOtherOids[I]) then
      begin
        Result := False;
        Exit;
      end;

      if not EquivalentStrings(FValues[I], LOtherValues[I]) then
      begin
        Result := False;
        Exit;
      end;
    end;
    Result := True;
  end
  else
  begin
    // Out-of-order comparison
    System.SetLength(LIndexes, LOrderingSize);

    if FOids[0].Equals(LOtherOids[0]) then
    begin
      // Guess forward
      LStart := 0;
      LEnd := LOrderingSize;
      LDelta := 1;
    end
    else
    begin
      // Guess reversed
      LStart := LOrderingSize - 1;
      LEnd := -1;
      LDelta := -1;
    end;

    I := LStart;
    while I <> LEnd do
    begin
      LOid := FOids[I];
      LValue := FValues[I];
      LFound := False;

      for J := 0 to LOrderingSize - 1 do
      begin
        if LIndexes[J] then
          Continue;

        if LOid.Equals(LOtherOids[J]) then
        begin
          if EquivalentStrings(LValue, LOtherValues[J]) then
          begin
            LIndexes[J] := True;
            LFound := True;
            Break;
          end;
        end;
      end;

      if not LFound then
      begin
        Result := False;
        Exit;
      end;

      System.Inc(I, LDelta);
    end;

    Result := True;
  end;
end;

{ TAttributeX509 }

class function TAttributeX509.GetInstance(AObj: TObject): IAttributeX509;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeX509, Result) then
    Exit;

  Result := TAttributeX509.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeX509.GetInstance(const AObj: IAsn1Convertible): IAttributeX509;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeX509, Result) then
    Exit;

  Result := TAttributeX509.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeX509.GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeX509;
begin
  Result := TAttributeX509.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAttributeX509.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributeX509;
begin
  Result := TAttributeX509.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TAttributeX509.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributeX509;
begin
  Result := TAttributeX509.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAttributeX509.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FAttrType := TDerObjectIdentifier.GetInstance(ASeq[0]);
  FAttrValues := TAsn1Set.GetInstance(ASeq[1]);
end;

constructor TAttributeX509.Create(const AAttrType: IDerObjectIdentifier; const AAttrValues: IAsn1Set);
begin
  inherited Create();
  if AAttrType = nil then
    raise EArgumentNilCryptoLibException.Create('attrType');
  if AAttrValues = nil then
    raise EArgumentNilCryptoLibException.Create('attrValues');
  FAttrType := AAttrType;
  FAttrValues := AAttrValues;
end;

function TAttributeX509.GetAttrType: IDerObjectIdentifier;
begin
  Result := FAttrType;
end;

function TAttributeX509.GetAttrValues: IAsn1Set;
begin
  Result := FAttrValues;
end;

function TAttributeX509.GetAttributeValues: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Result := FAttrValues.GetElements();
end;

function TAttributeX509.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FAttrType, FAttrValues);
end;

{ TAttCertValidityPeriod }

class function TAttCertValidityPeriod.GetInstance(AObj: TObject): IAttCertValidityPeriod;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttCertValidityPeriod, Result) then
    Exit;

  Result := TAttCertValidityPeriod.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttCertValidityPeriod.GetInstance(const AObj: IAsn1Convertible): IAttCertValidityPeriod;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttCertValidityPeriod, Result) then
    Exit;

  Result := TAttCertValidityPeriod.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttCertValidityPeriod.GetInstance(const AEncoded: TCryptoLibByteArray): IAttCertValidityPeriod;
begin
  Result := TAttCertValidityPeriod.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAttCertValidityPeriod.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAttCertValidityPeriod;
begin
  Result := TAttCertValidityPeriod.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TAttCertValidityPeriod.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttCertValidityPeriod;
begin
  Result := TAttCertValidityPeriod.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAttCertValidityPeriod.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FNotBeforeTime := TAsn1GeneralizedTime.GetInstance(ASeq[0]);
  FNotAfterTime := TAsn1GeneralizedTime.GetInstance(ASeq[1]);
end;

constructor TAttCertValidityPeriod.Create(const ANotBeforeTime, ANotAfterTime: IAsn1GeneralizedTime);
begin
  inherited Create();
  if ANotBeforeTime = nil then
    raise EArgumentNilCryptoLibException.Create('notBeforeTime');
  if ANotAfterTime = nil then
    raise EArgumentNilCryptoLibException.Create('notAfterTime');
  FNotBeforeTime := ANotBeforeTime;
  FNotAfterTime := ANotAfterTime;
end;

function TAttCertValidityPeriod.GetNotBeforeTime: IAsn1GeneralizedTime;
begin
  Result := FNotBeforeTime;
end;

function TAttCertValidityPeriod.GetNotAfterTime: IAsn1GeneralizedTime;
begin
  Result := FNotAfterTime;
end;

function TAttCertValidityPeriod.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FNotBeforeTime, FNotAfterTime);
end;

{ TPolicyInformation }

class function TPolicyInformation.GetInstance(AObj: TObject): IPolicyInformation;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPolicyInformation, Result) then
    Exit;

  Result := TPolicyInformation.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPolicyInformation.GetInstance(const AObj: IAsn1Convertible): IPolicyInformation;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPolicyInformation, Result) then
    Exit;

  Result := TPolicyInformation.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPolicyInformation.GetInstance(const AEncoded: TCryptoLibByteArray): IPolicyInformation;
begin
  Result := TPolicyInformation.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPolicyInformation.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPolicyInformation;
begin
  Result := TPolicyInformation.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TPolicyInformation.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPolicyInformation;
begin
  Result := TPolicyInformation.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPolicyInformation.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if (LCount < 1) or (LCount > 2) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FPolicyIdentifier := TDerObjectIdentifier.GetInstance(ASeq[0]);
  if LCount < 2 then
    FPolicyQualifiers := nil
  else
    FPolicyQualifiers := TAsn1Sequence.GetInstance(ASeq[1]);
end;

constructor TPolicyInformation.Create(const APolicyIdentifier: IDerObjectIdentifier);
begin
  Create(APolicyIdentifier, nil);
end;

constructor TPolicyInformation.Create(const APolicyIdentifier: IDerObjectIdentifier;
  const APolicyQualifiers: IAsn1Sequence);
begin
  inherited Create();
  if APolicyIdentifier = nil then
    raise EArgumentNilCryptoLibException.Create('policyIdentifier');
  FPolicyIdentifier := APolicyIdentifier;
  FPolicyQualifiers := APolicyQualifiers;
end;

function TPolicyInformation.GetPolicyIdentifier: IDerObjectIdentifier;
begin
  Result := FPolicyIdentifier;
end;

function TPolicyInformation.GetPolicyQualifiers: IAsn1Sequence;
begin
  Result := FPolicyQualifiers;
end;

function TPolicyInformation.ToAsn1Object: IAsn1Object;
begin
  if FPolicyQualifiers = nil then
    Result := TDerSequence.Create(FPolicyIdentifier)
  else
    Result := TDerSequence.Create(FPolicyIdentifier, FPolicyQualifiers);
end;

{ TIssuerSerial }

class function TIssuerSerial.GetInstance(AObj: TObject): IIssuerSerial;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IIssuerSerial, Result) then
    Exit;

  Result := TIssuerSerial.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TIssuerSerial.GetInstance(const AObj: IAsn1Convertible): IIssuerSerial;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IIssuerSerial, Result) then
    Exit;

  Result := TIssuerSerial.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TIssuerSerial.GetInstance(const AEncoded: TCryptoLibByteArray): IIssuerSerial;
begin
  Result := TIssuerSerial.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TIssuerSerial.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IIssuerSerial;
begin
  Result := TIssuerSerial.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TIssuerSerial.GetOptional(const AElement: IAsn1Encodable): IIssuerSerial;
var
  LSeq: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IIssuerSerial, Result) then
    Exit;

  LSeq := TAsn1Sequence.GetOptional(AElement);
  if LSeq <> nil then
  begin
    Result := TIssuerSerial.Create(LSeq);
    Exit;
  end;

  Result := nil;
end;

class function TIssuerSerial.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IIssuerSerial;
begin
  Result := TIssuerSerial.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TIssuerSerial.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FIssuer := TGeneralNames.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSerial := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FIssuerUid := TAsn1Utilities.ReadOptional<IDerBitString>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IDerBitString
    begin
      Result := TDerBitString.GetOptional(AElement);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

constructor TIssuerSerial.Create(const AIssuer: IX509Name; const ASerial: IDerInteger);
begin
  Create(TGeneralNames.Create(TGeneralName.Create(AIssuer)), ASerial);
end;

constructor TIssuerSerial.Create(const AIssuer: IGeneralNames; const ASerial: IDerInteger);
begin
  Create(AIssuer, ASerial, nil);
end;

constructor TIssuerSerial.Create(const AIssuer: IGeneralNames; const ASerial: IDerInteger;
  const AIssuerUid: IDerBitString);
begin
  inherited Create();
  if AIssuer = nil then
    raise EArgumentNilCryptoLibException.Create('issuer');
  if ASerial = nil then
    raise EArgumentNilCryptoLibException.Create('serial');
  FIssuer := AIssuer;
  FSerial := ASerial;
  FIssuerUid := AIssuerUid;
end;

function TIssuerSerial.GetIssuer: IGeneralNames;
begin
  Result := FIssuer;
end;

function TIssuerSerial.GetSerial: IDerInteger;
begin
  Result := FSerial;
end;

function TIssuerSerial.GetIssuerUid: IDerBitString;
begin
  Result := FIssuerUid;
end;

function TIssuerSerial.ToAsn1Object: IAsn1Object;
begin
  if FIssuerUid = nil then
    Result := TDerSequence.Create([FIssuer, FSerial])
  else
    Result := TDerSequence.Create([FIssuer, FSerial, FIssuerUid]);
end;

{ TV2Form }

class function TV2Form.GetInstance(AObj: TObject): IV2Form;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IV2Form, Result) then
    Exit;

  Result := TV2Form.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TV2Form.GetInstance(const AObj: IAsn1Convertible): IV2Form;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IV2Form, Result) then
    Exit;

  Result := TV2Form.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TV2Form.GetInstance(const AEncoded: TCryptoLibByteArray): IV2Form;
begin
  Result := TV2Form.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TV2Form.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IV2Form;
begin
  Result := TV2Form.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TV2Form.GetOptional(const AElement: IAsn1Encodable): IV2Form;
var
  LSeq: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IV2Form, Result) then
    Exit;

  LSeq := TAsn1Sequence.GetOptional(AElement);
  if LSeq <> nil then
  begin
    Result := TV2Form.Create(LSeq);
    Exit;
  end;

  Result := nil;
end;

class function TV2Form.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IV2Form;
begin
  Result := TV2Form.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TV2Form.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FIssuerName := TAsn1Utilities.ReadOptional<IGeneralNames>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IGeneralNames
    begin
      Result := TGeneralNames.GetOptional(AElement);
    end);
  FBaseCertificateID := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IIssuerSerial>(ASeq, LPos, 0, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IIssuerSerial
    begin
      Result := TIssuerSerial.GetTagged(ATagged, AState);
    end);
  FObjectDigestInfo := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IObjectDigestInfo>(ASeq, LPos, 1, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IObjectDigestInfo
    begin
      Result := TObjectDigestInfo.GetTagged(ATagged, AState);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

constructor TV2Form.Create(const AIssuerName: IGeneralNames);
begin
  Create(AIssuerName, nil, nil);
end;

constructor TV2Form.Create(const AIssuerName: IGeneralNames; const ABaseCertificateID: IIssuerSerial);
begin
  Create(AIssuerName, ABaseCertificateID, nil);
end;

constructor TV2Form.Create(const AIssuerName: IGeneralNames; const AObjectDigestInfo: IObjectDigestInfo);
begin
  Create(AIssuerName, nil, AObjectDigestInfo);
end;

constructor TV2Form.Create(const AIssuerName: IGeneralNames; const ABaseCertificateID: IIssuerSerial;
  const AObjectDigestInfo: IObjectDigestInfo);
begin
  inherited Create();
  FIssuerName := AIssuerName;
  FBaseCertificateID := ABaseCertificateID;
  FObjectDigestInfo := AObjectDigestInfo;
end;

function TV2Form.GetIssuerName: IGeneralNames;
begin
  Result := FIssuerName;
end;

function TV2Form.GetBaseCertificateID: IIssuerSerial;
begin
  Result := FBaseCertificateID;
end;

function TV2Form.GetObjectDigestInfo: IObjectDigestInfo;
begin
  Result := FObjectDigestInfo;
end;

function TV2Form.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  LV.AddOptional(FIssuerName);
  LV.AddOptionalTagged(False, 0, FBaseCertificateID);
  LV.AddOptionalTagged(False, 1, FObjectDigestInfo);
  Result := TDerSequence.Create(LV);
end;

{ TObjectDigestInfo }

class function TObjectDigestInfo.GetInstance(AObj: TObject): IObjectDigestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IObjectDigestInfo, Result) then
    Exit;

  Result := TObjectDigestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TObjectDigestInfo.GetInstance(const AObj: IAsn1Convertible): IObjectDigestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IObjectDigestInfo, Result) then
    Exit;

  Result := TObjectDigestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TObjectDigestInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IObjectDigestInfo;
begin
  Result := TObjectDigestInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TObjectDigestInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AIsExplicit: Boolean): IObjectDigestInfo;
begin
  Result := TObjectDigestInfo.Create(TAsn1Sequence.GetInstance(AObj, AIsExplicit));
end;

class function TObjectDigestInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IObjectDigestInfo;
begin
  Result := TObjectDigestInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TObjectDigestInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 4) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FDigestedObjectType := TDerEnumerated.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FOtherObjectTypeID := TAsn1Utilities.ReadOptional<IDerObjectIdentifier>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IDerObjectIdentifier
    begin
      Result := TDerObjectIdentifier.GetOptional(AElement);
    end);
  FDigestAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FObjectDigest := TDerBitString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

constructor TObjectDigestInfo.Create(ADigestedObjectType: Int32; const AOtherObjectTypeID: String;
  const ADigestAlgorithm: IAlgorithmIdentifier; const AObjectDigest: TCryptoLibByteArray);
begin
  inherited Create();
  FDigestedObjectType := TDerEnumerated.Create(ADigestedObjectType);

  if ADigestedObjectType = OtherObjectDigest then
    FOtherObjectTypeID := TDerObjectIdentifier.Create(AOtherObjectTypeID);

  if ADigestAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('digestAlgorithm');
  FDigestAlgorithm := ADigestAlgorithm;
  FObjectDigest := TDerBitString.Create(AObjectDigest);
end;

function TObjectDigestInfo.GetDigestedObjectType: IDerEnumerated;
begin
  Result := FDigestedObjectType;
end;

function TObjectDigestInfo.GetOtherObjectTypeID: IDerObjectIdentifier;
begin
  Result := FOtherObjectTypeID;
end;

function TObjectDigestInfo.GetDigestAlgorithm: IAlgorithmIdentifier;
begin
  Result := FDigestAlgorithm;
end;

function TObjectDigestInfo.GetObjectDigest: IDerBitString;
begin
  Result := FObjectDigest;
end;

function TObjectDigestInfo.ToAsn1Object: IAsn1Object;
begin
  if FOtherObjectTypeID = nil then
    Result := TDerSequence.Create([FDigestedObjectType, FDigestAlgorithm, FObjectDigest])
  else
    Result := TDerSequence.Create([FDigestedObjectType, FOtherObjectTypeID, FDigestAlgorithm, FObjectDigest]);
end;

{ TDistributionPoint }

class function TDistributionPoint.GetInstance(AObj: TObject): IDistributionPoint;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDistributionPoint, Result) then
    Exit;

  Result := TDistributionPoint.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDistributionPoint.GetInstance(const AObj: IAsn1Convertible): IDistributionPoint;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDistributionPoint, Result) then
    Exit;

  Result := TDistributionPoint.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TDistributionPoint.GetInstance(const AEncoded: TCryptoLibByteArray): IDistributionPoint;
begin
  Result := TDistributionPoint.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TDistributionPoint.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDistributionPoint;
begin
  Result := TDistributionPoint.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TDistributionPoint.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDistributionPoint;
begin
  Result := TDistributionPoint.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TDistributionPoint.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FDistributionPointName := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDistributionPointName>(ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDistributionPointName
    begin
      Result := TDistributionPointName.GetTagged(ATagged, AState);
    end);
  FReasons := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IReasonFlags>(ASeq, LPos, 1, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IReasonFlags
    begin
      Result := TReasonFlags.Create(TDerBitString.GetTagged(ATagged, AState));
    end);
  FCrlIssuer := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IGeneralNames>(ASeq, LPos, 2, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IGeneralNames
    begin
      Result := TGeneralNames.GetTagged(ATagged, AState);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

constructor TDistributionPoint.Create(const ADistributionPointName: IDistributionPointName;
  const AReasons: IReasonFlags; const ACrlIssuer: IGeneralNames);
begin
  inherited Create();
  FDistributionPointName := ADistributionPointName;
  FReasons := AReasons;
  FCrlIssuer := ACrlIssuer;
end;

function TDistributionPoint.GetDistributionPointName: IDistributionPointName;
begin
  Result := FDistributionPointName;
end;

function TDistributionPoint.GetReasons: IReasonFlags;
begin
  Result := FReasons;
end;

function TDistributionPoint.GetCrlIssuer: IGeneralNames;
begin
  Result := FCrlIssuer;
end;

function TDistributionPoint.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  if FDistributionPointName <> nil then
    LV.AddOptionalTagged(True, 0, FDistributionPointName as IAsn1Encodable);
  if FReasons <> nil then
    LV.AddOptionalTagged(False, 1, FReasons as IAsn1Encodable);
  if FCrlIssuer <> nil then
    LV.AddOptionalTagged(False, 2, FCrlIssuer as IAsn1Encodable);
  Result := TDerSequence.Create(LV);
end;

function TDistributionPoint.ToString: String;
var
  LBuf: TStringBuilder;
  LIndent: String;
begin
  LBuf := TStringBuilder.Create();
  try
    LBuf.AppendLine('DistributionPoint: [');
    LIndent := '    ';
    if FDistributionPointName <> nil then
    begin
      LBuf.Append(LIndent).Append('distributionPoint:').AppendLine();
      LBuf.Append(LIndent).Append(LIndent).Append((FDistributionPointName as TDistributionPointName).ToString()).AppendLine();
    end;
    if FReasons <> nil then
    begin
      LBuf.Append(LIndent).Append('reasons:').AppendLine();
      LBuf.Append(LIndent).Append(LIndent).Append(FReasons.ToAsn1Object().ToString()).AppendLine();
    end;
    if FCrlIssuer <> nil then
    begin
      LBuf.Append(LIndent).Append('cRLIssuer:').AppendLine();
      LBuf.Append(LIndent).Append(LIndent).Append((FCrlIssuer as TGeneralNames).ToString()).AppendLine();
    end;
    LBuf.AppendLine(']');
    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

{ TIssuingDistributionPoint }

class function TIssuingDistributionPoint.GetInstance(AObj: TObject): IIssuingDistributionPoint;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IIssuingDistributionPoint, Result) then
    Exit;

  Result := TIssuingDistributionPoint.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TIssuingDistributionPoint.GetInstance(const AObj: IAsn1Convertible): IIssuingDistributionPoint;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IIssuingDistributionPoint, Result) then
    Exit;

  Result := TIssuingDistributionPoint.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TIssuingDistributionPoint.GetInstance(const AEncoded: TCryptoLibByteArray): IIssuingDistributionPoint;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TIssuingDistributionPoint.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TIssuingDistributionPoint.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IIssuingDistributionPoint;
begin
  Result := TIssuingDistributionPoint.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TIssuingDistributionPoint.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IIssuingDistributionPoint;
begin
  Result := TIssuingDistributionPoint.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TIssuingDistributionPoint.Create(const ADistributionPoint: IDistributionPointName;
  AOnlyContainsUserCerts, AOnlyContainsCACerts: Boolean;
  const AOnlySomeReasons: IReasonFlags; AIndirectCRL, AOnlyContainsAttributeCerts: Boolean);
var
  LCount: Int32;
  LV: IAsn1EncodableVector;
begin
  inherited Create();

  LCount := Ord(AOnlyContainsUserCerts) + Ord(AOnlyContainsCACerts) + Ord(AOnlyContainsAttributeCerts);
  if LCount > 1 then
    raise EArgumentCryptoLibException.Create(
      'only one of onlyContainsCACerts, onlyContainsUserCerts, or onlyContainsAttributeCerts can be true');

  FDistributionPoint := ADistributionPoint;
  FOnlyContainsUserCerts := TDerBoolean.GetInstance(AOnlyContainsUserCerts);
  FOnlyContainsCACerts := TDerBoolean.GetInstance(AOnlyContainsCACerts);
  FOnlySomeReasons := AOnlySomeReasons;
  FIndirectCRL := TDerBoolean.GetInstance(AIndirectCRL);
  FOnlyContainsAttributeCerts := TDerBoolean.GetInstance(AOnlyContainsAttributeCerts);

  LV := TAsn1EncodableVector.Create(6);
  if ADistributionPoint <> nil then
    LV.Add(TDerTaggedObject.Create(True, 0, ADistributionPoint as IAsn1Encodable));
  if AOnlyContainsUserCerts then
    LV.Add(TDerTaggedObject.Create(False, 1, TDerBoolean.True as IAsn1Encodable));
  if AOnlyContainsCACerts then
    LV.Add(TDerTaggedObject.Create(False, 2, TDerBoolean.True as IAsn1Encodable));
  if AOnlySomeReasons <> nil then
    LV.Add(TDerTaggedObject.Create(False, 3, AOnlySomeReasons as IAsn1Encodable));
  if AIndirectCRL then
    LV.Add(TDerTaggedObject.Create(False, 4, TDerBoolean.True as IAsn1Encodable));
  if AOnlyContainsAttributeCerts then
    LV.Add(TDerTaggedObject.Create(False, 5, TDerBoolean.True as IAsn1Encodable));

  FSeq := TDerSequence.Create(LV);
end;

constructor TIssuingDistributionPoint.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
  LOnlyContainsUserCerts, LOnlyContainsCACerts, LIndirectCRL, LOnlyContainsAttributeCerts: IDerBoolean;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 6) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FDistributionPoint := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDistributionPointName>(ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDistributionPointName
    begin
      Result := TDistributionPointName.GetTagged(ATagged, AState);
    end);

  LOnlyContainsUserCerts := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBoolean>(ASeq, LPos, 1, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBoolean
    begin
      Result := TDerBoolean.GetTagged(ATagged, AState);
    end);

  if LOnlyContainsUserCerts <> nil then
    FOnlyContainsUserCerts := LOnlyContainsUserCerts
  else
    FOnlyContainsUserCerts := TDerBoolean.False;

  LOnlyContainsCACerts := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBoolean>(ASeq, LPos, 2, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBoolean
    begin
      Result := TDerBoolean.GetTagged(ATagged, AState);
    end);

  if LOnlyContainsCACerts <> nil then
    FOnlyContainsCACerts := LOnlyContainsCACerts
  else
    FOnlyContainsCACerts := TDerBoolean.False;

  FOnlySomeReasons := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IReasonFlags>(ASeq, LPos, 3, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IReasonFlags
    begin
      Result := TReasonFlags.Create(TDerBitString.GetTagged(ATagged, AState));
    end);

  LIndirectCRL := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBoolean>(ASeq, LPos, 4, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBoolean
    begin
      Result := TDerBoolean.GetTagged(ATagged, AState);
    end);

  if LIndirectCRL <> nil then
    FIndirectCRL := LIndirectCRL
  else
    FIndirectCRL := TDerBoolean.False;

  LOnlyContainsAttributeCerts := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBoolean>(ASeq, LPos, 5, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBoolean
    begin
      Result := TDerBoolean.GetTagged(ATagged, AState);
    end);

  if LOnlyContainsAttributeCerts <> nil then
    FOnlyContainsAttributeCerts := LOnlyContainsAttributeCerts
  else
    FOnlyContainsAttributeCerts := TDerBoolean.False;

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);

  FSeq := ASeq;
end;

function TIssuingDistributionPoint.GetDistributionPoint: IDistributionPointName;
begin
  Result := FDistributionPoint;
end;

function TIssuingDistributionPoint.GetOnlyContainsUserCerts: Boolean;
begin
  Result := FOnlyContainsUserCerts.IsTrue;
end;

function TIssuingDistributionPoint.GetOnlyContainsCACerts: Boolean;
begin
  Result := FOnlyContainsCACerts.IsTrue;
end;

function TIssuingDistributionPoint.GetOnlySomeReasons: IReasonFlags;
begin
  Result := FOnlySomeReasons;
end;

function TIssuingDistributionPoint.GetIsIndirectCrl: Boolean;
begin
  Result := FIndirectCRL.IsTrue;
end;

function TIssuingDistributionPoint.GetOnlyContainsAttributeCerts: Boolean;
begin
  Result := FOnlyContainsAttributeCerts.IsTrue;
end;

function TIssuingDistributionPoint.ToAsn1Object: IAsn1Object;
begin
  Result := FSeq as IAsn1Object;
end;

function TIssuingDistributionPoint.ToString: String;
var
  LBuf: TStringBuilder;
  LIndent: String;

  procedure AppendObject(const AName, AVal: String);
  begin
    LBuf.Append(LIndent).Append(AName).Append(':').AppendLine();
    LBuf.Append(LIndent).Append(LIndent).Append(AVal).AppendLine();
  end;
begin
  LBuf := TStringBuilder.Create();
  try
    LBuf.AppendLine('IssuingDistributionPoint: [');
    LIndent := '    ';
    if FDistributionPoint <> nil then
      AppendObject('distributionPoint', FDistributionPoint.ToString());
    if FOnlyContainsUserCerts.IsTrue then
      AppendObject('onlyContainsUserCerts', FOnlyContainsUserCerts.ToString());
    if FOnlyContainsCACerts.IsTrue then
      AppendObject('onlyContainsCACerts', FOnlyContainsCACerts.ToString());
    if FOnlySomeReasons <> nil then
      AppendObject('onlySomeReasons', FOnlySomeReasons.ToString());
    if FOnlyContainsAttributeCerts.IsTrue then
      AppendObject('onlyContainsAttributeCerts', FOnlyContainsAttributeCerts.ToString());
    if FIndirectCRL.IsTrue then
      AppendObject('indirectCRL', FIndirectCRL.ToString());
    LBuf.AppendLine(']');
    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

{ TCertificateList }

class function TCertificateList.GetInstance(AObj: TObject): ICertificateList;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificateList, Result) then
    Exit;

  Result := TCertificateList.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificateList.GetInstance(const AObj: IAsn1Convertible): ICertificateList;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificateList, Result) then
    Exit;

  Result := TCertificateList.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificateList.GetInstance(const AEncoded: TCryptoLibByteArray): ICertificateList;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCertificateList.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCertificateList.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICertificateList;
begin
  Result := TCertificateList.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCertificateList.GetOptional(const AElement: IAsn1Encodable): ICertificateList;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, ICertificateList, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TCertificateList.Create(LSequence)
  else
    Result := nil;
end;

class function TCertificateList.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertificateList;
begin
  Result := TCertificateList.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCertificateList.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 3 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FTbsCertList := TTbsCertificateList.GetInstance(ASeq[0]);
  FSignatureAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[1]);
  FSignatureValue := TDerBitString.GetInstance(ASeq[2]);
end;

function TCertificateList.GetTbsCertList: ITbsCertificateList;
begin
  Result := FTbsCertList;
end;

function TCertificateList.GetRevokedCertificates: TCryptoLibGenericArray<ICrlEntry>;
begin
  Result := FTbsCertList.GetRevokedCertificates();
end;

function TCertificateList.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSignatureAlgorithm;
end;

function TCertificateList.GetSignature: IDerBitString;
begin
  Result := FSignatureValue;
end;

function TCertificateList.GetSignatureOctets: TCryptoLibByteArray;
begin
  Result := FSignatureValue.GetOctets();
end;

function TCertificateList.GetVersion: Int32;
begin
  Result := FTbsCertList.Version;
end;

function TCertificateList.GetIssuer: IX509Name;
begin
  Result := FTbsCertList.Issuer;
end;

function TCertificateList.GetThisUpdate: ITime;
begin
  Result := FTbsCertList.ThisUpdate;
end;

function TCertificateList.GetNextUpdate: ITime;
begin
  Result := FTbsCertList.NextUpdate;
end;

function TCertificateList.GetExtensions: IX509Extensions;
begin
  Result := FTbsCertList.Extensions;
end;

function TCertificateList.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  LV.Add(FTbsCertList as IAsn1Encodable);
  LV.Add(FSignatureAlgorithm as IAsn1Encodable);
  LV.Add(FSignatureValue as IAsn1Encodable);
  Result := TDerSequence.Create(LV);
end;

{ TDistributionPointName }

class function TDistributionPointName.GetInstance(AObj: TObject): IDistributionPointName;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IDistributionPointName>(AObj,
    function(AElement: IAsn1Encodable): IDistributionPointName
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TDistributionPointName.GetInstance(const AObj: IAsn1Convertible): IDistributionPointName;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IDistributionPointName, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<IDistributionPointName>(AObj.ToAsn1Object(),
    function(AElement: IAsn1Encodable): IDistributionPointName
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TDistributionPointName.GetInstance(const AEncoded: TCryptoLibByteArray): IDistributionPointName;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IDistributionPointName>(AEncoded,
    function(AElement: IAsn1Encodable): IDistributionPointName
    begin
      Result := GetOptional(AElement);
    end);
end;

class function TDistributionPointName.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IDistributionPointName;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IDistributionPointName>(AObj, AExplicitly,
    function(AElement: IAsn1Encodable): IDistributionPointName
    begin
      Result := GetInstance(AElement);
    end);
end;

class function TDistributionPointName.GetOptional(const AElement: IAsn1Encodable): IDistributionPointName;
var
  LTaggedObject: IAsn1TaggedObject;
  LBaseObject: IAsn1Encodable;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IDistributionPointName, Result) then
    Exit;

  LTaggedObject := TAsn1TaggedObject.GetOptional(AElement);
  if LTaggedObject <> nil then
  begin
    LBaseObject := GetOptionalBaseObject(LTaggedObject);
    if LBaseObject <> nil then
    begin
      Result := TDistributionPointName.Create(LTaggedObject.TagNo, LBaseObject);
      Exit;
    end;
  end;

  Result := nil;
end;

class function TDistributionPointName.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IDistributionPointName;
begin
  Result := TAsn1Utilities.GetTaggedChoice<IDistributionPointName>(ATaggedObject, ADeclaredExplicit,
    function(AElement: IAsn1Encodable): IDistributionPointName
    begin
      Result := GetInstance(AElement);
    end);
end;

class function TDistributionPointName.GetOptionalBaseObject(const ATaggedObject: IAsn1TaggedObject): IAsn1Encodable;
begin
  if ATaggedObject.HasContextTag() then
  begin
    case ATaggedObject.TagNo of
      FullName:
        Result := TGeneralNames.GetTagged(ATaggedObject, False);
      NameRelativeToCrlIssuer:
        Result := TAsn1Set.GetTagged(ATaggedObject, False);
    else
      Result := nil;
    end;
  end
  else
    Result := nil;
end;

constructor TDistributionPointName.Create(const AName: IGeneralNames);
begin
  Create(FullName, AName);
end;

constructor TDistributionPointName.Create(AType: Int32; const AName: IAsn1Encodable);
begin
  inherited Create();
  FType := AType;
  FName := AName;
end;

function TDistributionPointName.GetType: Int32;
begin
  Result := FType;
end;

function TDistributionPointName.GetName: IAsn1Encodable;
begin
  Result := FName;
end;

function TDistributionPointName.ToAsn1Object: IAsn1Object;
begin
  Result := TDerTaggedObject.Create(False, FType, FName);
end;

function TDistributionPointName.ToString: String;
var
  LBuf: TStringBuilder;
  LIndent: String;
begin
  LBuf := TStringBuilder.Create();
  try
    LBuf.AppendLine('DistributionPointName: [');
    LIndent := '    ';
    if FType = FullName then
    begin
      LBuf.Append(LIndent).Append('fullName:').AppendLine();
      LBuf.Append(LIndent).Append(LIndent).Append(FName.ToAsn1Object().ToString()).AppendLine();
    end
    else
    begin
      LBuf.Append(LIndent).Append('nameRelativeToCRLIssuer:').AppendLine();
      LBuf.Append(LIndent).Append(LIndent).Append(FName.ToAsn1Object().ToString()).AppendLine();
    end;
    LBuf.AppendLine(']');
    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

{ TReasonFlags }

constructor TReasonFlags.Create(AReasons: Int32);
begin
  inherited Create(AReasons);
end;

constructor TReasonFlags.Create(const AReasons: IDerBitString);
begin
  inherited Create(AReasons.GetBytes(), AReasons.PadBits);
end;

{ TCrlReason }

constructor TCrlReason.Create(AReason: Int32);
begin
  inherited Create(AReason);
end;

constructor TCrlReason.Create(const AReason: IDerEnumerated);
begin
  inherited Create(AReason.IntValueExact);
end;

function TCrlReason.ToString: String;
const
  ReasonString: array [0 .. 10] of String = (
    'Unspecified', 'KeyCompromise', 'CACompromise', 'AffiliationChanged',
    'Superseded', 'CessationOfOperation', 'CertificateHold', 'Unknown',
    'RemoveFromCrl', 'PrivilegeWithdrawn', 'AACompromise');
var
  LReason: Int32;
  LStr: String;
begin
  LReason := IntValueExact;
  if (LReason < 0) or (LReason > 10) then
    LStr := 'Invalid'
  else
    LStr := ReasonString[LReason];
  Result := 'CrlReason: ' + LStr;
end;

{ TTbsCertificateList }

class function TTbsCertificateList.GetInstance(AObj: TObject): ITbsCertificateList;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ITbsCertificateList, Result) then
    Exit;

  Result := TTbsCertificateList.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TTbsCertificateList.GetInstance(const AObj: IAsn1Convertible): ITbsCertificateList;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ITbsCertificateList, Result) then
    Exit;

  Result := TTbsCertificateList.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TTbsCertificateList.GetInstance(const AEncoded: TCryptoLibByteArray): ITbsCertificateList;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TTbsCertificateList.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TTbsCertificateList.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ITbsCertificateList;
begin
  Result := TTbsCertificateList.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TTbsCertificateList.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ITbsCertificateList;
begin
  Result := TTbsCertificateList.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TTbsCertificateList.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
  LVersion: IDerInteger;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 7) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  LVersion := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IDerInteger
    begin
      Result := TDerInteger.GetOptional(AElement);
    end);
  if LVersion <> nil then
    FVersion := LVersion
  else
    FVersion := TDerInteger.Zero;

  FSignature := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FIssuer := TX509Name.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FThisUpdate := TTime.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FNextUpdate := TAsn1Utilities.ReadOptional<ITime>(ASeq, LPos,
    function(AElement: IAsn1Encodable): ITime
    begin
      Result := TTime.GetOptional(AElement);
    end);
  FRevokedCertificates := TAsn1Utilities.ReadOptional<IAsn1Sequence>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IAsn1Sequence
    begin
      Result := TAsn1Sequence.GetOptional(AElement);
    end);
  FCrlExtensions := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IX509Extensions>(ASeq, LPos, 0, True,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IX509Extensions
    begin
      Result := TX509Extensions.GetTagged(ATagged, AState);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);

  FSeq := ASeq;
end;

function TTbsCertificateList.GetVersion: Int32;
begin
  Result := FVersion.IntValueExact + 1;
end;

function TTbsCertificateList.GetVersionNumber: IDerInteger;
begin
  Result := FVersion;
end;

function TTbsCertificateList.GetSignature: IAlgorithmIdentifier;
begin
  Result := FSignature;
end;

function TTbsCertificateList.GetIssuer: IX509Name;
begin
  Result := FIssuer;
end;

function TTbsCertificateList.GetThisUpdate: ITime;
begin
  Result := FThisUpdate;
end;

function TTbsCertificateList.GetNextUpdate: ITime;
begin
  Result := FNextUpdate;
end;

function TTbsCertificateList.GetRevokedCertificates: TCryptoLibGenericArray<ICrlEntry>;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if FRevokedCertificates = nil then
  begin
    System.SetLength(Result, 0);
    Exit;
  end;
  LElements := FRevokedCertificates.GetElements();
  Result := TArrayUtilities.Map<IAsn1Encodable, ICrlEntry>(LElements,
    function(A: IAsn1Encodable): ICrlEntry
    begin
      Result := TCrlEntry.GetInstance(A);
    end);
end;

function TTbsCertificateList.GetExtensions: IX509Extensions;
begin
  Result := FCrlExtensions;
end;

function TTbsCertificateList.ToAsn1Object: IAsn1Object;
begin
  Result := FSeq as IAsn1Object;
end;

{ TAttCertIssuer }

class function TAttCertIssuer.GetInstance(AObj: TObject): IAttCertIssuer;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IAttCertIssuer>(AObj,
    function(AElement: IAsn1Encodable): IAttCertIssuer
    begin
      Exit(GetOptional(AElement));
    end);
end;

class function TAttCertIssuer.GetInstance(const AObj: IAsn1Convertible): IAttCertIssuer;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttCertIssuer, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<IAttCertIssuer>(AObj.ToAsn1Object(),
    function(AElement: IAsn1Encodable): IAttCertIssuer
    begin
      Exit(GetOptional(AElement));
    end);
end;

class function TAttCertIssuer.GetInstance(const AEncoded: TCryptoLibByteArray): IAttCertIssuer;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IAttCertIssuer>(AEncoded,
    function(AElement: IAsn1Encodable): IAttCertIssuer
    begin
      Exit(GetOptional(AElement));
    end);
end;

class function TAttCertIssuer.GetInstance(const AObj: IAsn1TaggedObject;
  AIsExplicit: Boolean): IAttCertIssuer;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IAttCertIssuer>(AObj, AIsExplicit,
    function(AElement: IAsn1Encodable): IAttCertIssuer
    begin
      Exit(GetInstance(AElement));
    end);
end;

class function TAttCertIssuer.GetOptional(const AElement: IAsn1Encodable): IAttCertIssuer;
var
  LV1Form: IGeneralNames;
  LTaggedObject: IAsn1TaggedObject;
  LV2Form: IV2Form;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IAttCertIssuer, Result) then
    Exit;

  LV1Form := TGeneralNames.GetOptional(AElement);
  if LV1Form <> nil then
  begin
    Result := TAttCertIssuer.Create(LV1Form);
    Exit;
  end;

  LTaggedObject := TAsn1TaggedObject.GetOptional(AElement);
  if (LTaggedObject <> nil) and LTaggedObject.HasContextTag(0) then
  begin
    Result := TAttCertIssuer.Create(TV2Form.GetTagged(LTaggedObject, False));
    Exit;
  end;

  LV2Form := TV2Form.GetOptional(AElement);
  if LV2Form <> nil then
  begin
    Result := TAttCertIssuer.Create(LV2Form);
    Exit;
  end;

  Result := nil;
end;

class function TAttCertIssuer.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttCertIssuer;
begin
  Result := TAsn1Utilities.GetTaggedChoice<IAttCertIssuer>(ATaggedObject, ADeclaredExplicit,
    function(AElement: IAsn1Encodable): IAttCertIssuer
    begin
      Result := GetInstance(AElement);
    end);
end;

constructor TAttCertIssuer.Create(const ANames: IGeneralNames);
begin
  inherited Create();
  FObj := ANames;
  FChoiceObj := FObj.ToAsn1Object();
end;

constructor TAttCertIssuer.Create(const AV2Form: IV2Form);
begin
  inherited Create();
  FObj := AV2Form;
  FChoiceObj := TDerTaggedObject.Create(False, 0, FObj);
end;

function TAttCertIssuer.GetIssuer: IAsn1Encodable;
begin
  Result := FObj;
end;

function TAttCertIssuer.ToAsn1Object: IAsn1Object;
begin
  Result := FChoiceObj;
end;

{ THolder }

class function THolder.GetInstance(AObj: TObject): IHolder;
var
  LTaggedObject: IAsn1TaggedObject;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IHolder, Result) then
    Exit;

  if Supports(AObj, IAsn1TaggedObject, LTaggedObject) then
  begin
    Result := THolder.Create(LTaggedObject);
    Exit;
  end;

  Result := THolder.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function THolder.GetInstance(const AObj: IAsn1Convertible): IHolder;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IHolder, Result) then
    Exit;

  Result := THolder.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function THolder.GetInstance(const AEncoded: TCryptoLibByteArray): IHolder;
begin
  Result := THolder.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function THolder.GetInstance(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IHolder;
begin
  Result := THolder.Create(TAsn1Sequence.GetInstance(ATaggedObject, ADeclaredExplicit));
end;

class function THolder.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IHolder;
begin
  Result := THolder.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor THolder.Create(const ATagObj: IAsn1TaggedObject);
begin
  inherited Create();
  if ATagObj.HasContextTag(0) then
    FBaseCertificateID := TIssuerSerial.GetTagged(ATagObj, True)
  else if ATagObj.HasContextTag(1) then
    FEntityName := TGeneralNames.GetTagged(ATagObj, True)
  else
    raise EArgumentCryptoLibException.Create('unknown tag in Holder');
  FVersion := 0;
end;

constructor THolder.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 0) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FBaseCertificateID := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IIssuerSerial>(ASeq, LPos, 0, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IIssuerSerial
    begin
      Result := TIssuerSerial.GetTagged(ATagged, AState);
    end);
  FEntityName := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IGeneralNames>(ASeq, LPos, 1, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IGeneralNames
    begin
      Result := TGeneralNames.GetTagged(ATagged, AState);
    end);
  FObjectDigestInfo := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IObjectDigestInfo>(ASeq, LPos, 2, False,
    function(ATagged: IAsn1TaggedObject; AState: Boolean): IObjectDigestInfo
    begin
      Result := TObjectDigestInfo.GetTagged(ATagged, AState);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);

  FVersion := 1;
end;

constructor THolder.Create(const ABaseCertificateID: IIssuerSerial);
begin
  Create(ABaseCertificateID, 1);
end;

constructor THolder.Create(const ABaseCertificateID: IIssuerSerial; AVersion: Int32);
begin
  inherited Create();
  FBaseCertificateID := ABaseCertificateID;
  FVersion := AVersion;
end;

constructor THolder.Create(const AEntityName: IGeneralNames);
begin
  Create(AEntityName, 1);
end;

constructor THolder.Create(const AEntityName: IGeneralNames; AVersion: Int32);
begin
  inherited Create();
  FEntityName := AEntityName;
  FVersion := AVersion;
end;

constructor THolder.Create(const AObjectDigestInfo: IObjectDigestInfo);
begin
  inherited Create();
  FObjectDigestInfo := AObjectDigestInfo;
  FVersion := 1;
end;

function THolder.GetVersion: Int32;
begin
  Result := FVersion;
end;

function THolder.GetBaseCertificateID: IIssuerSerial;
begin
  Result := FBaseCertificateID;
end;

function THolder.GetEntityName: IGeneralNames;
begin
  Result := FEntityName;
end;

function THolder.GetObjectDigestInfo: IObjectDigestInfo;
begin
  Result := FObjectDigestInfo;
end;

function THolder.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  if FVersion = 1 then
  begin
    LV := TAsn1EncodableVector.Create(3);
    LV.AddOptionalTagged(False, 0, FBaseCertificateID);
    LV.AddOptionalTagged(False, 1, FEntityName);
    LV.AddOptionalTagged(False, 2, FObjectDigestInfo);
    Result := TDerSequence.Create(LV);
  end
  else
  begin
    if FEntityName <> nil then
      Result := TDerTaggedObject.Create(True, 1, FEntityName)
    else
      Result := TDerTaggedObject.Create(True, 0, FBaseCertificateID);
  end;
end;

{ TAttributeCertificate }

class function TAttributeCertificate.GetInstance(AObj: TObject): IAttributeCertificate;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeCertificate, Result) then
    Exit;

  Result := TAttributeCertificate.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeCertificate.GetInstance(const AObj: IAsn1Convertible): IAttributeCertificate;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeCertificate, Result) then
    Exit;

  Result := TAttributeCertificate.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeCertificate.GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeCertificate;
begin
  Result := TAttributeCertificate.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAttributeCertificate.GetInstance(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributeCertificate;
begin
  Result := TAttributeCertificate.Create(TAsn1Sequence.GetInstance(ATaggedObject, ADeclaredExplicit));
end;

class function TAttributeCertificate.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributeCertificate;
begin
  Result := TAttributeCertificate.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAttributeCertificate.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if LCount <> 3 then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FACInfo := TAttributeCertificateInfo.GetInstance(ASeq[0]);
  FSignatureAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[1]);
  FSignatureValue := TDerBitString.GetInstance(ASeq[2]);
end;

constructor TAttributeCertificate.Create(const AACInfo: IAttributeCertificateInfo;
  const ASignatureAlgorithm: IAlgorithmIdentifier; const ASignatureValue: IDerBitString);
begin
  inherited Create();
  if AACInfo = nil then
    raise EArgumentNilCryptoLibException.Create('acinfo');
  if ASignatureAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('signatureAlgorithm');
  if ASignatureValue = nil then
    raise EArgumentNilCryptoLibException.Create('signatureValue');
  FACInfo := AACInfo;
  FSignatureAlgorithm := ASignatureAlgorithm;
  FSignatureValue := ASignatureValue;
end;

function TAttributeCertificate.GetACInfo: IAttributeCertificateInfo;
begin
  Result := FACInfo;
end;

function TAttributeCertificate.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSignatureAlgorithm;
end;

function TAttributeCertificate.GetSignatureValue: IDerBitString;
begin
  Result := FSignatureValue;
end;

function TAttributeCertificate.GetSignatureOctets: TCryptoLibByteArray;
begin
  Result := FSignatureValue.GetOctets();
end;

function TAttributeCertificate.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FACInfo, FSignatureAlgorithm, FSignatureValue]);
end;

{ TAttributeCertificateInfo }

class function TAttributeCertificateInfo.GetInstance(AObj: TObject): IAttributeCertificateInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeCertificateInfo, Result) then
    Exit;

  Result := TAttributeCertificateInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeCertificateInfo.GetInstance(const AObj: IAsn1Convertible): IAttributeCertificateInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributeCertificateInfo, Result) then
    Exit;

  Result := TAttributeCertificateInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributeCertificateInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IAttributeCertificateInfo;
begin
  Result := TAttributeCertificateInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAttributeCertificateInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AIsExplicit: Boolean): IAttributeCertificateInfo;
begin
  Result := TAttributeCertificateInfo.Create(TAsn1Sequence.GetInstance(AObj, AIsExplicit));
end;

class function TAttributeCertificateInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributeCertificateInfo;
begin
  Result := TAttributeCertificateInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAttributeCertificateInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 6) or (LCount > 9) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FVersion := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IDerInteger
    begin
      Result := TDerInteger.GetOptional(AElement);
    end);
  if FVersion = nil then
    FVersion := TDerInteger.Zero;
  FHolder := THolder.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FIssuer := TAttCertIssuer.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSignature := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSerialNumber := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FAttrCertValidityPeriod := TAttCertValidityPeriod.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FAttributes := TAsn1Sequence.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FIssuerUniqueID := TAsn1Utilities.ReadOptional<IDerBitString>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IDerBitString
    begin
      Result := TDerBitString.GetOptional(AElement);
    end);
  FExtensions := TAsn1Utilities.ReadOptional<IX509Extensions>(ASeq, LPos,
    function(AElement: IAsn1Encodable): IX509Extensions
    begin
      Result := TX509Extensions.GetOptional(AElement);
    end);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

function TAttributeCertificateInfo.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TAttributeCertificateInfo.GetHolder: IHolder;
begin
  Result := FHolder;
end;

function TAttributeCertificateInfo.GetIssuer: IAttCertIssuer;
begin
  Result := FIssuer;
end;

function TAttributeCertificateInfo.GetSignature: IAlgorithmIdentifier;
begin
  Result := FSignature;
end;

function TAttributeCertificateInfo.GetSerialNumber: IDerInteger;
begin
  Result := FSerialNumber;
end;

function TAttributeCertificateInfo.GetAttrCertValidityPeriod: IAttCertValidityPeriod;
begin
  Result := FAttrCertValidityPeriod;
end;

function TAttributeCertificateInfo.GetAttributes: IAsn1Sequence;
begin
  Result := FAttributes;
end;

function TAttributeCertificateInfo.GetIssuerUniqueID: IDerBitString;
begin
  Result := FIssuerUniqueID;
end;

function TAttributeCertificateInfo.GetExtensions: IX509Extensions;
begin
  Result := FExtensions;
end;

function TAttributeCertificateInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(9);
  if not FVersion.HasValue(0) then
  begin
    LV.Add(FVersion);
  end;
  LV.Add([FHolder, FIssuer, FSignature, FSerialNumber, FAttrCertValidityPeriod, FAttributes]);
  LV.AddOptional(FIssuerUniqueID, FExtensions);
  Result := TDerSequence.Create(LV);
end;

{ TCrlDistPoint }

class function TCrlDistPoint.GetInstance(AObj: TObject): ICrlDistPoint;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICrlDistPoint, Result) then
    Exit;

  Result := TCrlDistPoint.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCrlDistPoint.GetInstance(const AObj: IAsn1Convertible): ICrlDistPoint;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICrlDistPoint, Result) then
    Exit;

  Result := TCrlDistPoint.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCrlDistPoint.GetInstance(const AEncoded: TCryptoLibByteArray): ICrlDistPoint;
begin
  Result := TCrlDistPoint.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCrlDistPoint.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICrlDistPoint;
begin
  Result := TCrlDistPoint.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCrlDistPoint.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICrlDistPoint;
begin
  Result := TCrlDistPoint.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

class function TCrlDistPoint.FromExtensions(const AExtensions: IX509Extensions): ICrlDistPoint;
begin
  Result := GetInstance(TX509Extensions.GetExtensionParsedValue(AExtensions, TX509Extensions.CrlDistributionPoints));
end;

constructor TCrlDistPoint.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create();
  FSeq := ASeq;
end;

constructor TCrlDistPoint.Create(const APoints: TCryptoLibGenericArray<IDistributionPoint>);
var
  LV: IAsn1EncodableVector;
  I: Int32;
begin
  inherited Create();
  LV := TAsn1EncodableVector.Create();
  for I := 0 to System.Length(APoints) - 1 do
  begin
    LV.Add(APoints[I]);
  end;
  FSeq := TDerSequence.Create(LV);
end;

function TCrlDistPoint.GetDistributionPoints: TCryptoLibGenericArray<IDistributionPoint>;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LResult: TList<IDistributionPoint>;
  I: Int32;
begin
  LElements := FSeq.GetElements();
  LResult := TList<IDistributionPoint>.Create();
  try
    for I := 0 to System.Length(LElements) - 1 do
    begin
      LResult.Add(TDistributionPoint.GetInstance(LElements[I]));
    end;
    Result := LResult.ToArray();
  finally
    LResult.Free;
  end;
end;

function TCrlDistPoint.ToAsn1Object: IAsn1Object;
begin
  Result := FSeq;
end;

function TCrlDistPoint.ToString: String;
var
  LBuf: TStringBuilder;
  LDps: TCryptoLibGenericArray<IDistributionPoint>;
  I: Int32;
begin
  LBuf := TStringBuilder.Create();
  try
    LBuf.AppendLine('CRLDistPoint:');
    LDps := GetDistributionPoints();
    for I := 0 to System.Length(LDps) - 1 do
    begin
      LBuf.Append('    ').Append((LDps[I] as TDistributionPoint).ToString()).AppendLine();
    end;
    Result := LBuf.ToString();
  finally
    LBuf.Free;
  end;
end;

end.
