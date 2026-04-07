{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpPkcsAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpAsn1Tags,
  ClpIPkcsAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpAsn1Utilities,
  ClpArrayUtilities,
  ClpPlatformUtilities;

resourcestring
  SBadSequenceSize = 'Bad sequence size: %d';
  SAttrTypeNil = 'attrType';
  SAttrValuesNil = 'attrValues';
  SWrongNumberOfElements = 'Wrong number of elements in sequence';
  SRequestInfoNil = 'requestInfo';
  SAlgorithmNil = 'algorithm';
  SSignatureNil = 'signature';
  SSubjectNil = 'subject';
  SSubjectPKInfoNil = 'subjectPKInfo';
  SUnexpectedElementsInSequence = 'Unexpected elements in sequence';
  SChallengePasswordMustHaveSingleValue = 'challengePassword attribute must have exactly one value';
  SPrivateKeyAlgorithmNil = 'privateKeyAlgorithm';
  SPrivateKeyNil = 'privateKey';
  SVersionNil = 'version';
  SWrongVersionForPfxPdu = 'wrong version for PFX PDU';
  SContentInfoNil = 'contentInfo';
  SMacNil = 'mac';
  SMacSaltNil = 'macSalt';
  SIterationsNil = 'iterations';
  SEncryptedDataVersionNotZero = 'sequence not version 0';

type
  /// <summary>
  /// The ContentInfo object (PKCS#7).
  /// </summary>
  TPkcsContentInfo = class(TAsn1Encodable, IPkcsContentInfo)
  strict private
  var
    FContentType: IDerObjectIdentifier;
    FContent: IAsn1Encodable;

  strict protected
    function GetContentType: IDerObjectIdentifier;
    function GetContent: IAsn1Encodable;

  public
    class function GetInstance(AObj: TObject): IPkcsContentInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPkcsContentInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPkcsContentInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPkcsContentInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPkcsContentInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AContentType: IDerObjectIdentifier;
      const AContent: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property Content: IAsn1Encodable read GetContent;
  end;

  /// <summary>
  /// The SignedData object (PKCS#7).
  /// </summary>
  TPkcsSignedData = class(TAsn1Encodable, IPkcsSignedData)
  strict private
  var
    FVersion: IDerInteger;
    FDigestAlgorithms: IAsn1Set;
    FContentInfo: IPkcsContentInfo;
    FCertificates: IAsn1Set;
    FCrls: IAsn1Set;
    FSignerInfos: IAsn1Set;

    class function GetTaggedAsn1SetFromSeq(ATagged: IAsn1TaggedObject; AState: IAsn1Sequence): IAsn1Set; static;

  strict protected
    function GetVersion: IDerInteger;
    function GetDigestAlgorithms: IAsn1Set;
    function GetContentInfo: IPkcsContentInfo;
    function GetCertificates: IAsn1Set;
    function GetCrls: IAsn1Set;
    function GetSignerInfos: IAsn1Set;

  public
    class function GetInstance(AObj: TObject): IPkcsSignedData; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPkcsSignedData; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPkcsSignedData; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPkcsSignedData; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPkcsSignedData; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AVersion: IDerInteger;
      const ADigestAlgorithms: IAsn1Set; const AContentInfo: IPkcsContentInfo;
      const ACertificates: IAsn1Set; const ACrls: IAsn1Set;
      const ASignerInfos: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property DigestAlgorithms: IAsn1Set read GetDigestAlgorithms;
    property ContentInfo: IPkcsContentInfo read GetContentInfo;
    property Certificates: IAsn1Set read GetCertificates;
    property Crls: IAsn1Set read GetCrls;
    property SignerInfos: IAsn1Set read GetSignerInfos;
  end;

  /// <summary>
  /// The AttributePkcs object.
  /// </summary>
  TAttributePkcs = class(TAsn1Encodable, IAttributePkcs)

  strict private
  var
    FAttrType: IDerObjectIdentifier;
    FAttrValues: IAsn1Set;

  strict protected
    function GetAttrType: IDerObjectIdentifier;
    function GetAttrValues: IAsn1Set;

  public
    class function GetInstance(AObj: TObject): IAttributePkcs; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IAttributePkcs; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAttributePkcs; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IAttributePkcs; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAttributePkcs; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAttrType: IDerObjectIdentifier;
      const AAttrValues: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property AttrType: IDerObjectIdentifier read GetAttrType;
    property AttrValues: IAsn1Set read GetAttrValues;

  end;

  /// <summary>
  /// The CertificationRequestInfo object.
  /// </summary>
  TCertificationRequestInfo = class(TAsn1Encodable, ICertificationRequestInfo)

  strict private
  var
    FVersion: IDerInteger;
    FSubject: IX509Name;
    FSubjectPKInfo: ISubjectPublicKeyInfo;
    FAttributes: IAsn1Set;

    class function GetTaggedAsn1Set(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set; static;

  strict protected
    function GetVersion: IDerInteger;
    function GetSubject: IX509Name;
    function GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
    function GetAttributes: IAsn1Set;

  public
    class function ValidateAttributes(const AAttributes: IAsn1Set): IAsn1Set; static;

    class function GetInstance(AObj: TObject): ICertificationRequestInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICertificationRequestInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequestInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICertificationRequestInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertificationRequestInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASubject: IX509Name;
      const APkInfo: ISubjectPublicKeyInfo; const AAttributes: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property Subject: IX509Name read GetSubject;
    property SubjectPublicKeyInfo: ISubjectPublicKeyInfo read GetSubjectPublicKeyInfo;
    property Attributes: IAsn1Set read GetAttributes;

  end;

  /// <summary>
  /// The CertificationRequest object.
  /// </summary>
  TCertificationRequest = class(TAsn1Encodable, ICertificationRequest)

  strict protected
  var
    FReqInfo: ICertificationRequestInfo;
    FSigAlgId: IAlgorithmIdentifier;
    FSigBits: IDerBitString;

  strict protected
    function GetCertificationRequestInfo: ICertificationRequestInfo;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;

    /// <summary>Protected parameterless constructor for TPkcs10CertificationRequest.Init.</summary>
    constructor Create; overload;

  public
    class function GetInstance(AObj: TObject): ICertificationRequest; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICertificationRequest; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequest; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICertificationRequest; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertificationRequest; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ARequestInfo: ICertificationRequestInfo;
      const AAlgorithm: IAlgorithmIdentifier; const ASignature: IDerBitString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;

  end;

  /// <summary>
  /// The PrivateKeyInfo object.
  /// </summary>
  TPrivateKeyInfo = class(TAsn1Encodable, IPrivateKeyInfo)

  strict private
  var
    FVersion: IDerInteger;
    FPrivateKeyAlgorithm: IAlgorithmIdentifier;
    FPrivateKey: IAsn1OctetString;
    FAttributes: IAsn1Set;
    FPublicKey: IDerBitString;

    class function GetTaggedAsn1Set(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set; static;
    class function GetTaggedDerBitString(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBitString; static;

  strict protected
    function GetVersion: IDerInteger;
    function GetPrivateKeyAlgorithm: IAlgorithmIdentifier;
    function GetPrivateKey: IAsn1OctetString;
    function GetPrivateKeyLength: Int32;
    function GetAttributes: IAsn1Set;
    function GetPublicKey: IDerBitString;
    function HasPublicKey: Boolean;
    function ParsePrivateKey: IAsn1Object;
    function ParsePublicKey: IAsn1Object;

  public
    class function GetInstance(AObj: TObject): IPrivateKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPrivateKeyInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPrivateKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPrivateKeyInfo; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IPrivateKeyInfo; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPrivateKeyInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsn1Encodable); overload;
    constructor Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set); overload;
    constructor Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
      const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set;
      const APublicKey: TCryptoLibByteArray); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property PrivateKeyAlgorithm: IAlgorithmIdentifier read GetPrivateKeyAlgorithm;
    property PrivateKey: IAsn1OctetString read GetPrivateKey;
    property PrivateKeyLength: Int32 read GetPrivateKeyLength;
    property Attributes: IAsn1Set read GetAttributes;
    property PublicKey: IDerBitString read GetPublicKey;

  end;

  /// <summary>
  /// EncryptedPrivateKeyInfo (PKCS#8).
  /// </summary>
  TEncryptedPrivateKeyInfo = class(TAsn1Encodable, IEncryptedPrivateKeyInfo)
  strict private
  var
    FEncryptionAlgorithm: IAlgorithmIdentifier;
    FEncryptedData: IAsn1OctetString;

  strict protected
    function GetEncryptionAlgorithm: IAlgorithmIdentifier;
    function GetEncryptedData: IAsn1OctetString;
    function GetEncryptedDataBytes: TCryptoLibByteArray;

  public
    class function GetInstance(AObj: TObject): IEncryptedPrivateKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IEncryptedPrivateKeyInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IEncryptedPrivateKeyInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IEncryptedPrivateKeyInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IEncryptedPrivateKeyInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AAlgId: IAlgorithmIdentifier;
      const AEncoding: TCryptoLibByteArray); overload;
    constructor Create(const AEncryptionAlgorithm: IAlgorithmIdentifier;
      const AEncryptedData: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property EncryptionAlgorithm: IAlgorithmIdentifier read GetEncryptionAlgorithm;
    property EncryptedData: IAsn1OctetString read GetEncryptedData;
  end;

  /// <summary>
  /// KeyDerivationFunc (PKCS#5 Scheme 2) - extends AlgorithmIdentifier.
  /// </summary>
  TKeyDerivationFunc = class(TAlgorithmIdentifier, IKeyDerivationFunc)
  public
    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AId: IDerObjectIdentifier;
      const AParameters: IAsn1Encodable); overload;
  end;

  /// <summary>
  /// EncryptionScheme (PKCS#5 Scheme 2) - extends AlgorithmIdentifier.
  /// </summary>
  TEncryptionScheme = class(TAlgorithmIdentifier, IEncryptionScheme)
  strict protected
    function GetParametersAsn1Object: IAsn1Object;
  public
    class function GetEncryptionSchemeInstance(AObj: TObject): IEncryptionScheme; overload; static;
    class function GetEncryptionSchemeInstance(const AObj: IAsn1Convertible): IEncryptionScheme; overload; static;
    class function GetEncryptionSchemeInstance(const AEncoded: TCryptoLibByteArray): IEncryptionScheme; overload; static;
    class function GetEncryptionSchemeInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IEncryptionScheme; overload; static;
    class function GetEncryptionSchemeTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IEncryptionScheme; static;

    constructor Create(const AObjectID: IDerObjectIdentifier); overload;
    constructor Create(const AObjectID: IDerObjectIdentifier;
      const AParameters: IAsn1Encodable); overload;
    constructor Create(const ASeq: IAsn1Sequence); overload;

    property ParametersAsn1Object: IAsn1Object read GetParametersAsn1Object;
  end;

  /// <summary>
  /// PbeParameter (PKCS5 S1).
  /// </summary>
  TPbeParameter = class(TAsn1Encodable, IPbeParameter)
  strict private
  var
    FSalt: IAsn1OctetString;
    FIterationCount: IDerInteger;

  strict protected
    function GetSalt: IAsn1OctetString;
    function GetIterationCountObject: IDerInteger;
    function GetSaltBytes: TCryptoLibByteArray;

  public
    class function GetInstance(AObj: TObject): IPbeParameter; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPbeParameter; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPbeParameter; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPbeParameter; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPbeParameter; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Salt: IAsn1OctetString read GetSalt;
    property IterationCountObject: IDerInteger read GetIterationCountObject;
  end;

  /// <summary>
  /// PbeS2Parameters (PKCS#5 Scheme 2).
  /// </summary>
  TPbeS2Parameters = class(TAsn1Encodable, IPbeS2Parameters)
  strict private
  var
    FKeyDerivationFunc: IKeyDerivationFunc;
    FEncryptionScheme: IEncryptionScheme;

  strict protected
    function GetKeyDerivationFunc: IKeyDerivationFunc;
    function GetEncryptionScheme: IEncryptionScheme;

  public
    class function GetInstance(AObj: TObject): IPbeS2Parameters; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPbeS2Parameters; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPbeS2Parameters; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPbeS2Parameters; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPbeS2Parameters; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AKeyDerivationFunc: IKeyDerivationFunc;
      const AEncryptionScheme: IEncryptionScheme); overload;

    function ToAsn1Object: IAsn1Object; override;

    property KeyDerivationFunc: IKeyDerivationFunc read GetKeyDerivationFunc;
    property EncryptionScheme: IEncryptionScheme read GetEncryptionScheme;
  end;

  /// <summary>
  /// Pbkdf2Params.
  /// </summary>
  TPbkdf2Params = class(TAsn1Encodable, IPbkdf2Params)
  strict private
  var
    FOctStr: IAsn1OctetString;
    FIterationCount: IDerInteger;
    FKeyLength: IDerInteger;
    FPrf: IAlgorithmIdentifier;
  class var
    FDefaultPrf: IAlgorithmIdentifier;

   class constructor Create(); overload;
    class function ReadOptionalDerInteger(AEnc: IAsn1Encodable): IDerInteger; static;
    class function ReadOptionalAlgorithmIdentifier(AEnc: IAsn1Encodable): IAlgorithmIdentifier; static;

  strict protected
    function GetSalt: IAsn1OctetString;
    function GetIterationCountObject: IDerInteger;
    function GetKeyLengthObject: IDerInteger;
    function GetPrf: IAlgorithmIdentifier;
    function GetSaltBytes: TCryptoLibByteArray;
    function GetIterationCount: TBigInteger;
    function GetKeyLength: TBigInteger;
    function GetIsDefaultPrf: Boolean;

  public
    class function GetDefaultPrf: IAlgorithmIdentifier; static;
    class function GetInstance(AObj: TObject): IPbkdf2Params; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPbkdf2Params; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPbkdf2Params; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPbkdf2Params; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32); overload;
    constructor Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
      AKeyLength: Int32); overload;
    constructor Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
      const APrf: IAlgorithmIdentifier); overload;
    constructor Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
      AKeyLength: Int32; const APrf: IAlgorithmIdentifier); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Salt: IAsn1OctetString read GetSalt;
    property IterationCountObject: IDerInteger read GetIterationCountObject;
    property KeyLengthObject: IDerInteger read GetKeyLengthObject;
    property Prf: IAlgorithmIdentifier read GetPrf;
    property IsDefaultPrf: Boolean read GetIsDefaultPrf;
    class property DefaultPrf: IAlgorithmIdentifier read GetDefaultPrf;
  end;

  /// <summary>
  /// Pkcs12PbeParams.
  /// </summary>
  TPkcs12PbeParams = class(TAsn1Encodable, IPkcs12PbeParams)
  strict private
  var
    FIV: IAsn1OctetString;
    FIterations: IDerInteger;

  strict protected
    function GetIV: IAsn1OctetString;
    function GetIterationsObject: IDerInteger;
    function GetIVBytes: TCryptoLibByteArray;
    function GetIterations: TBigInteger;

  public
    class function GetInstance(AObj: TObject): IPkcs12PbeParams; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPkcs12PbeParams; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPkcs12PbeParams; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPkcs12PbeParams; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPkcs12PbeParams; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASalt: TCryptoLibByteArray; AIterations: Int32); overload;

    function ToAsn1Object: IAsn1Object; override;

    property IV: IAsn1OctetString read GetIV;
    property IterationsObject: IDerInteger read GetIterationsObject;
  end;

  /// <summary>
  /// MacData (PKCS#12).
  /// </summary>
  TMacData = class(TAsn1Encodable, IMacData)
  strict private
  var
    FMac: IDigestInfo;
    FMacSalt: IAsn1OctetString;
    FIterations: IDerInteger;

    class function ReadOptionalDerInteger(AEnc: IAsn1Encodable): IDerInteger; static;

  strict protected
    function GetMac: IDigestInfo;
    function GetSalt: TCryptoLibByteArray;
    function GetIterationCount: TBigInteger;
    function GetIterations: IDerInteger;
    function GetMacSalt: IAsn1OctetString;

  public
    class function GetInstance(AObj: TObject): IMacData; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IMacData; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IMacData; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IMacData; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IMacData; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ADigInfo: IDigestInfo;
      const ASalt: TCryptoLibByteArray; AIterationCount: Int32); overload;
    constructor Create(const AMac: IDigestInfo; const AMacSalt: IAsn1OctetString;
      const AIterations: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Mac: IDigestInfo read GetMac;
    property IterationCount: TBigInteger read GetIterationCount;
    property Iterations: IDerInteger read GetIterations;
    property MacSalt: IAsn1OctetString read GetMacSalt;
  end;

  /// <summary>
  /// SafeBag (PKCS#12).
  /// </summary>
  TSafeBag = class(TAsn1Encodable, ISafeBag)
  strict private
  var
    FBagID: IDerObjectIdentifier;
    FBagValue: IAsn1Encodable;
    FBagAttributes: IAsn1Set;

    class function ReadOptionalAsn1Set(AElement: IAsn1Encodable): IAsn1Set; static;

  strict protected
    function GetBagID: IDerObjectIdentifier;
    function GetBagValue: IAsn1Object;
    function GetBagValueEncodable: IAsn1Encodable;
    function GetBagAttributes: IAsn1Set;

  public
    class function GetInstance(AObj: TObject): ISafeBag; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ISafeBag; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ISafeBag; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISafeBag; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISafeBag; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ABagID: IDerObjectIdentifier;
      const ABagValue: IAsn1Encodable); overload;
    constructor Create(const ABagID: IDerObjectIdentifier;
      const ABagValue: IAsn1Encodable; const ABagAttributes: IAsn1Set); overload;

    function ToAsn1Object: IAsn1Object; override;

    property BagID: IDerObjectIdentifier read GetBagID;
    property BagValue: IAsn1Object read GetBagValue;
    property BagValueEncodable: IAsn1Encodable read GetBagValueEncodable;
    property BagAttributes: IAsn1Set read GetBagAttributes;
  end;

  /// <summary>
  /// CertBag (PKCS#12).
  /// </summary>
  TCertBag = class(TAsn1Encodable, ICertBag)
  strict private
  var
    FCertID: IDerObjectIdentifier;
    FCertValue: IAsn1Encodable;

  strict protected
    function GetCertID: IDerObjectIdentifier;
    function GetCertValue: IAsn1Object;
    function GetCertValueEncodable: IAsn1Encodable;

  public
    class function GetInstance(AObj: TObject): ICertBag; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): ICertBag; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICertBag; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertBag; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertBag; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ACertID: IDerObjectIdentifier;
      const ACertValue: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property CertID: IDerObjectIdentifier read GetCertID;
    property CertValue: IAsn1Object read GetCertValue;
    property CertValueEncodable: IAsn1Encodable read GetCertValueEncodable;
  end;

  /// <summary>
  /// AuthenticatedSafe (PKCS#12).
  /// </summary>
  TAuthenticatedSafe = class(TAsn1Encodable, IAuthenticatedSafe)
  strict private
  var
    FInfo: TCryptoLibGenericArray<IPkcsContentInfo>;
    FIsBer: Boolean;

    class function ElementToPkcsContentInfo(AElement: IAsn1Encodable): IPkcsContentInfo; static;
    class function PkcsContentInfoToAsn1Encodable(AElement: IPkcsContentInfo): IAsn1Encodable; static;

  strict protected
    function GetContentInfo: TCryptoLibGenericArray<IPkcsContentInfo>;

  public
    class function GetInstance(AObj: TObject): IAuthenticatedSafe; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IAuthenticatedSafe; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IAuthenticatedSafe; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAuthenticatedSafe; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IAuthenticatedSafe; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AInfo: TCryptoLibGenericArray<IPkcsContentInfo>); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ContentInfo: TCryptoLibGenericArray<IPkcsContentInfo> read GetContentInfo;
  end;

  /// <summary>
  /// EncryptedData (PKCS#7).
  /// </summary>
  TPkcsEncryptedData = class(TAsn1Encodable, IPkcsEncryptedData)
  strict private
  var
    FData: IAsn1Sequence;

  strict protected
    function GetContentType: IDerObjectIdentifier;
    function GetEncryptionAlgorithm: IAlgorithmIdentifier;
    function GetContent: IAsn1OctetString;

  public
    class function GetInstance(AObj: TObject): IPkcsEncryptedData; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPkcsEncryptedData; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPkcsEncryptedData; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPkcsEncryptedData; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPkcsEncryptedData; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AContentType: IDerObjectIdentifier;
      const AEncryptionAlgorithm: IAlgorithmIdentifier;
      const AContent: IAsn1Encodable); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ContentType: IDerObjectIdentifier read GetContentType;
    property EncryptionAlgorithm: IAlgorithmIdentifier read GetEncryptionAlgorithm;
    property Content: IAsn1OctetString read GetContent;
  end;

  /// <summary>
  /// The infamous Pfx from Pkcs12.
  /// </summary>
  TPfx = class(TAsn1Encodable, IPfx)
  strict private
  var
    FContentInfo: IPkcsContentInfo;
    FMacData: IMacData;

  strict protected
    function GetAuthSafe: IPkcsContentInfo;
    function GetMacData: IMacData;

  public
    class function GetInstance(AObj: TObject): IPfx; overload; static;
    class function GetInstance(const AObj: IAsn1Convertible): IPfx; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IPfx; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IPfx; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IPfx; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AContentInfo: IPkcsContentInfo;
      const AMacData: IMacData); overload;

    function ToAsn1Object: IAsn1Object; override;

    property AuthSafe: IPkcsContentInfo read GetAuthSafe;
    property MacData: IMacData read GetMacData;
  end;

implementation

{ TAttributePkcs }

class function TAttributePkcs.GetInstance(AObj: TObject): IAttributePkcs;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributePkcs, Result) then
    Exit;

  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributePkcs.GetInstance(const AObj: IAsn1Convertible): IAttributePkcs;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAttributePkcs, Result) then
    Exit;

  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAttributePkcs.GetInstance(const AEncoded: TCryptoLibByteArray): IAttributePkcs;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAttributePkcs.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IAttributePkcs;
begin
  Result := TAttributePkcs.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TAttributePkcs.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAttributePkcs;
begin
  Result := TAttributePkcs.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAttributePkcs.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FAttrType := TDerObjectIdentifier.GetInstance(ASeq[0]);
  FAttrValues := TAsn1Set.GetInstance(ASeq[1]);
end;

constructor TAttributePkcs.Create(const AAttrType: IDerObjectIdentifier;
  const AAttrValues: IAsn1Set);
begin
  inherited Create();

  if AAttrType = nil then
    raise EArgumentNilCryptoLibException.Create(SAttrTypeNil);
  if AAttrValues = nil then
    raise EArgumentNilCryptoLibException.Create(SAttrValuesNil);

  FAttrType := AAttrType;
  FAttrValues := AAttrValues;
end;

function TAttributePkcs.GetAttrType: IDerObjectIdentifier;
begin
  Result := FAttrType;
end;

function TAttributePkcs.GetAttrValues: IAsn1Set;
begin
  Result := FAttrValues;
end;

function TAttributePkcs.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FAttrType, FAttrValues]);
end;

{ TCertificationRequestInfo }

class function TCertificationRequestInfo.GetInstance(AObj: TObject): ICertificationRequestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequestInfo, Result) then
    Exit;

  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequestInfo.GetInstance(const AObj: IAsn1Convertible): ICertificationRequestInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequestInfo, Result) then
    Exit;

  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequestInfo.GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequestInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCertificationRequestInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICertificationRequestInfo;
begin
  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCertificationRequestInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertificationRequestInfo;
begin
  Result := TCertificationRequestInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCertificationRequestInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 4) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSubject := TX509Name.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FSubjectPKInfo := TSubjectPublicKeyInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  // NOTE: some CertificationRequestInfo objects seem to treat this field as optional.
  FAttributes := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1Set>(ASeq, LPos, 0, False,
    GetTaggedAsn1Set);

  if LPos <> LCount then
  begin
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
  end;

  ValidateAttributes(FAttributes);
end;

class function TCertificationRequestInfo.GetTaggedAsn1Set(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set;
begin
  Result := TAsn1Set.GetTagged(ATagged, AState);
end;

constructor TCertificationRequestInfo.Create(const ASubject: IX509Name;
  const APkInfo: ISubjectPublicKeyInfo; const AAttributes: IAsn1Set);
begin
  inherited Create();

  FVersion := TDerInteger.Zero;
  if ASubject = nil then
    raise EArgumentNilCryptoLibException.Create(SSubjectNil);
  if APkInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SSubjectPKInfoNil);

  FSubject := ASubject;
  FSubjectPKInfo := APkInfo;
  FAttributes := ValidateAttributes(AAttributes);
end;

class function TCertificationRequestInfo.ValidateAttributes(const AAttributes: IAsn1Set): IAsn1Set;
var
  LI: Int32;
  LAttr: IAttributePkcs;
begin
  if AAttributes <> nil then
  begin
    for LI := 0 to AAttributes.Count - 1 do
    begin
      LAttr := TAttributePkcs.GetInstance(AAttributes[LI]);
      if TPkcsObjectIdentifiers.Pkcs9AtChallengePassword.Equals(LAttr.AttrType) then
      begin
        if LAttr.AttrValues.Count <> 1 then
        begin
          raise EArgumentCryptoLibException.Create(SChallengePasswordMustHaveSingleValue);
        end;
      end;
    end;
  end;
  Result := AAttributes;
end;

function TCertificationRequestInfo.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TCertificationRequestInfo.GetSubject: IX509Name;
begin
  Result := FSubject;
end;

function TCertificationRequestInfo.GetSubjectPublicKeyInfo: ISubjectPublicKeyInfo;
begin
  Result := FSubjectPKInfo;
end;

function TCertificationRequestInfo.GetAttributes: IAsn1Set;
begin
  Result := FAttributes;
end;

function TCertificationRequestInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);
  LV.Add([FVersion, FSubject, FSubjectPKInfo]);
  LV.AddOptionalTagged(False, 0, FAttributes);
  Result := TDerSequence.Create(LV);
end;

{ TCertificationRequest }

class function TCertificationRequest.GetInstance(AObj: TObject): ICertificationRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequest, Result) then
    Exit;

  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequest.GetInstance(const AObj: IAsn1Convertible): ICertificationRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertificationRequest, Result) then
    Exit;

  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertificationRequest.GetInstance(const AEncoded: TCryptoLibByteArray): ICertificationRequest;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCertificationRequest.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ICertificationRequest;
begin
  Result := TCertificationRequest.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCertificationRequest.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertificationRequest;
begin
  Result := TCertificationRequest.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCertificationRequest.Create;
begin
  inherited Create();
end;

constructor TCertificationRequest.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 3 then
  begin
    raise EArgumentCryptoLibException.Create(SWrongNumberOfElements);
  end;

  FReqInfo := TCertificationRequestInfo.GetInstance(ASeq[0]);
  FSigAlgId := TAlgorithmIdentifier.GetInstance(ASeq[1]);
  FSigBits := TDerBitString.GetInstance(ASeq[2]);
end;

constructor TCertificationRequest.Create(const ARequestInfo: ICertificationRequestInfo;
  const AAlgorithm: IAlgorithmIdentifier; const ASignature: IDerBitString);
begin
  inherited Create();

  if ARequestInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SRequestInfoNil);
  if AAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create(SAlgorithmNil);
  if ASignature = nil then
    raise EArgumentNilCryptoLibException.Create(SSignatureNil);

  FReqInfo := ARequestInfo;
  FSigAlgId := AAlgorithm;
  FSigBits := ASignature;
end;

function TCertificationRequest.GetCertificationRequestInfo: ICertificationRequestInfo;
begin
  Result := FReqInfo;
end;

function TCertificationRequest.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSigAlgId;
end;

function TCertificationRequest.GetSignature: IDerBitString;
begin
  Result := FSigBits;
end;

function TCertificationRequest.GetSignatureOctets: TCryptoLibByteArray;
begin
  Result := FSigBits.GetOctets();
end;

function TCertificationRequest.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create([FReqInfo, FSigAlgId, FSigBits]);
end;

{ TPrivateKeyInfo }

class function TPrivateKeyInfo.GetInstance(AObj: TObject): IPrivateKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPrivateKeyInfo, Result) then
    Exit;

  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPrivateKeyInfo.GetInstance(const AObj: IAsn1Convertible): IPrivateKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPrivateKeyInfo, Result) then
    Exit;

  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPrivateKeyInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IPrivateKeyInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPrivateKeyInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPrivateKeyInfo;
begin
  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPrivateKeyInfo.GetOptional(const AElement: IAsn1Encodable): IPrivateKeyInfo;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.Create('element');

  if Supports(AElement, IPrivateKeyInfo, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TPrivateKeyInfo.Create(LSequence)
  else
    Result := nil;
end;

class function TPrivateKeyInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPrivateKeyInfo;
begin
  Result := TPrivateKeyInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPrivateKeyInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos, LVersionValue: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 3) or (LCount > 5) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  end;

  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FPrivateKeyAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FPrivateKey := TAsn1OctetString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  FAttributes := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IAsn1Set>(ASeq, LPos, 0, False,
    GetTaggedAsn1Set);

  FPublicKey := TAsn1Utilities.ReadOptionalContextTagged<Boolean, IDerBitString>(ASeq, LPos, 1, False,
    GetTaggedDerBitString);

  if LPos <> LCount then
  begin
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
  end;

  LVersionValue := FVersion.IntValueExact;
  if (FPublicKey <> nil) and (LVersionValue < 1) then
  begin
    raise EArgumentCryptoLibException.Create('''publicKey'' requires version v2(1) or later');
  end;
end;

class function TPrivateKeyInfo.GetTaggedAsn1Set(ATagged: IAsn1TaggedObject; AState: Boolean): IAsn1Set;
begin
  Result := TAsn1Set.GetTagged(ATagged, AState);
end;

class function TPrivateKeyInfo.GetTaggedDerBitString(ATagged: IAsn1TaggedObject; AState: Boolean): IDerBitString;
begin
  Result := TDerBitString.GetTagged(ATagged, AState);
end;

constructor TPrivateKeyInfo.Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsn1Encodable);
begin
  Create(APrivateKeyAlgorithm, APrivateKey, nil, nil);
end;

constructor TPrivateKeyInfo.Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set);
begin
  Create(APrivateKeyAlgorithm, APrivateKey, AAttributes, nil);
end;

constructor TPrivateKeyInfo.Create(const APrivateKeyAlgorithm: IAlgorithmIdentifier;
  const APrivateKey: IAsn1Encodable; const AAttributes: IAsn1Set;
  const APublicKey: TCryptoLibByteArray);
begin
  inherited Create();

  if APublicKey <> nil then
    FVersion := TDerInteger.ValueOf(1)
  else
    FVersion := TDerInteger.Zero;

  if APrivateKeyAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('privateKeyAlgorithm');
  if APrivateKey = nil then
    raise EArgumentNilCryptoLibException.Create('privateKey');

  FPrivateKeyAlgorithm := APrivateKeyAlgorithm;
  FPrivateKey := TDerOctetString.Create(APrivateKey);
  FAttributes := AAttributes;
  if APublicKey <> nil then
    FPublicKey := TDerBitString.FromContentsOptional(APublicKey)
  else
    FPublicKey := nil;
end;

function TPrivateKeyInfo.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TPrivateKeyInfo.GetPrivateKeyAlgorithm: IAlgorithmIdentifier;
begin
  Result := FPrivateKeyAlgorithm;
end;

function TPrivateKeyInfo.GetPrivateKeyLength: Int32;
begin
  Result := FPrivateKey.GetOctetsLength;
end;

function TPrivateKeyInfo.GetPrivateKey: IAsn1OctetString;
begin
  Result := FPrivateKey;
end;

function TPrivateKeyInfo.GetAttributes: IAsn1Set;
begin
  Result := FAttributes;
end;

function TPrivateKeyInfo.GetPublicKey: IDerBitString;
begin
  Result := FPublicKey;
end;

function TPrivateKeyInfo.HasPublicKey: Boolean;
begin
  Result := FPublicKey <> nil;
end;

function TPrivateKeyInfo.ParsePrivateKey: IAsn1Object;
begin
  Result := TAsn1Object.FromByteArray(FPrivateKey.GetOctets());
end;

function TPrivateKeyInfo.ParsePublicKey: IAsn1Object;
begin
  if FPublicKey = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TAsn1Object.FromStream(FPublicKey.GetOctetStream());
end;

function TPrivateKeyInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(5);
  LV.Add([FVersion, FPrivateKeyAlgorithm, FPrivateKey]);
  LV.AddOptionalTagged(False, 0, FAttributes);
  LV.AddOptionalTagged(False, 1, FPublicKey);
  Result := TDerSequence.Create(LV);
end;

{ TEncryptedPrivateKeyInfo }

class function TEncryptedPrivateKeyInfo.GetInstance(AObj: TObject): IEncryptedPrivateKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IEncryptedPrivateKeyInfo, Result) then
    Exit;

  Result := TEncryptedPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TEncryptedPrivateKeyInfo.GetInstance(const AObj: IAsn1Convertible): IEncryptedPrivateKeyInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IEncryptedPrivateKeyInfo, Result) then
    Exit;

  Result := TEncryptedPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TEncryptedPrivateKeyInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IEncryptedPrivateKeyInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TEncryptedPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TEncryptedPrivateKeyInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IEncryptedPrivateKeyInfo;
begin
  Result := TEncryptedPrivateKeyInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TEncryptedPrivateKeyInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IEncryptedPrivateKeyInfo;
begin
  Result := TEncryptedPrivateKeyInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TEncryptedPrivateKeyInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FEncryptionAlgorithm := TAlgorithmIdentifier.GetInstance(ASeq[0]);
  FEncryptedData := TAsn1OctetString.GetInstance(ASeq[1]);
end;

constructor TEncryptedPrivateKeyInfo.Create(const AAlgId: IAlgorithmIdentifier;
  const AEncoding: TCryptoLibByteArray);
begin
  inherited Create();

  if AAlgId = nil then
    raise EArgumentNilCryptoLibException.Create('algId');

  FEncryptionAlgorithm := AAlgId;
  FEncryptedData := TDerOctetString.FromContents(AEncoding);
end;

constructor TEncryptedPrivateKeyInfo.Create(const AEncryptionAlgorithm: IAlgorithmIdentifier;
  const AEncryptedData: IAsn1OctetString);
begin
  inherited Create();

  if AEncryptionAlgorithm = nil then
    raise EArgumentNilCryptoLibException.Create('encryptionAlgorithm');
  if AEncryptedData = nil then
    raise EArgumentNilCryptoLibException.Create('encryptedData');

  FEncryptionAlgorithm := AEncryptionAlgorithm;
  FEncryptedData := AEncryptedData;
end;

function TEncryptedPrivateKeyInfo.GetEncryptionAlgorithm: IAlgorithmIdentifier;
begin
  Result := FEncryptionAlgorithm;
end;

function TEncryptedPrivateKeyInfo.GetEncryptedData: IAsn1OctetString;
begin
  Result := FEncryptedData;
end;

function TEncryptedPrivateKeyInfo.GetEncryptedDataBytes: TCryptoLibByteArray;
begin
  Result := FEncryptedData.GetOctets();
end;

function TEncryptedPrivateKeyInfo.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FEncryptionAlgorithm, FEncryptedData);
end;

{ TKeyDerivationFunc }

constructor TKeyDerivationFunc.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create(ASeq);
end;

constructor TKeyDerivationFunc.Create(const AId: IDerObjectIdentifier;
  const AParameters: IAsn1Encodable);
begin
  inherited Create(AId, AParameters);
end;

{ TEncryptionScheme }

class function TEncryptionScheme.GetEncryptionSchemeInstance(AObj: TObject): IEncryptionScheme;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IEncryptionScheme, Result) then
    Exit;

  Result := TEncryptionScheme.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TEncryptionScheme.GetEncryptionSchemeInstance(const AObj: IAsn1Convertible): IEncryptionScheme;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IEncryptionScheme, Result) then
    Exit;

  Result := TEncryptionScheme.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TEncryptionScheme.GetEncryptionSchemeInstance(const AEncoded: TCryptoLibByteArray): IEncryptionScheme;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TEncryptionScheme.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TEncryptionScheme.GetEncryptionSchemeInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IEncryptionScheme;
begin
  Result := TEncryptionScheme.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TEncryptionScheme.GetEncryptionSchemeTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IEncryptionScheme;
begin
  Result := TEncryptionScheme.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TEncryptionScheme.Create(const AObjectID: IDerObjectIdentifier);
begin
  inherited Create(AObjectID);
end;

constructor TEncryptionScheme.Create(const AObjectID: IDerObjectIdentifier;
  const AParameters: IAsn1Encodable);
begin
  inherited Create(AObjectID, AParameters);
end;

constructor TEncryptionScheme.Create(const ASeq: IAsn1Sequence);
begin
  Create(TDerObjectIdentifier.GetInstance(ASeq[0]), ASeq[1]);
end;

function TEncryptionScheme.GetParametersAsn1Object: IAsn1Object;
begin
  if Parameters = nil then
    Result := nil
  else
    Result := Parameters.ToAsn1Object();
end;

{ TPbeParameter }

class function TPbeParameter.GetInstance(AObj: TObject): IPbeParameter;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPbeParameter, Result) then
    Exit;
  Result := TPbeParameter.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPbeParameter.GetInstance(const AObj: IAsn1Convertible): IPbeParameter;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPbeParameter, Result) then
    Exit;
  Result := TPbeParameter.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPbeParameter.GetInstance(const AEncoded: TCryptoLibByteArray): IPbeParameter;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := TPbeParameter.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPbeParameter.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPbeParameter;
begin
  Result := TPbeParameter.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPbeParameter.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPbeParameter;
begin
  Result := TPbeParameter.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPbeParameter.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  FSalt := TAsn1OctetString.GetInstance(ASeq[0]);
  FIterationCount := TDerInteger.GetInstance(ASeq[1]);
end;

constructor TPbeParameter.Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32);
begin
  inherited Create();
  FSalt := TDerOctetString.FromContents(ASalt);
  FIterationCount := TDerInteger.ValueOf(AIterationCount);
end;

function TPbeParameter.GetSalt: IAsn1OctetString;
begin
  Result := FSalt;
end;

function TPbeParameter.GetIterationCountObject: IDerInteger;
begin
  Result := FIterationCount;
end;

function TPbeParameter.GetSaltBytes: TCryptoLibByteArray;
begin
  Result := FSalt.GetOctets();
end;

function TPbeParameter.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FSalt, FIterationCount);
end;

{ TPbeS2Parameters }

class function TPbeS2Parameters.GetInstance(AObj: TObject): IPbeS2Parameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPbeS2Parameters, Result) then
    Exit;
  Result := TPbeS2Parameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPbeS2Parameters.GetInstance(const AObj: IAsn1Convertible): IPbeS2Parameters;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPbeS2Parameters, Result) then
    Exit;
  Result := TPbeS2Parameters.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPbeS2Parameters.GetInstance(const AEncoded: TCryptoLibByteArray): IPbeS2Parameters;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := TPbeS2Parameters.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPbeS2Parameters.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPbeS2Parameters;
begin
  Result := TPbeS2Parameters.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPbeS2Parameters.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPbeS2Parameters;
begin
  Result := TPbeS2Parameters.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPbeS2Parameters.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LFunc: IAlgorithmIdentifier;
begin
  inherited Create();
  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  LFunc := TAlgorithmIdentifier.GetInstance(ASeq[0]);
  FKeyDerivationFunc := TKeyDerivationFunc.Create(LFunc.Algorithm, LFunc.Parameters);
  FEncryptionScheme := TEncryptionScheme.GetEncryptionSchemeInstance(ASeq[1]);
end;

constructor TPbeS2Parameters.Create(const AKeyDerivationFunc: IKeyDerivationFunc;
  const AEncryptionScheme: IEncryptionScheme);
begin
  inherited Create();
  if AKeyDerivationFunc = nil then
    raise EArgumentNilCryptoLibException.Create('keyDevFunc');
  if AEncryptionScheme = nil then
    raise EArgumentNilCryptoLibException.Create('encScheme');
  FKeyDerivationFunc := AKeyDerivationFunc;
  FEncryptionScheme := AEncryptionScheme;
end;

function TPbeS2Parameters.GetKeyDerivationFunc: IKeyDerivationFunc;
begin
  Result := FKeyDerivationFunc;
end;

function TPbeS2Parameters.GetEncryptionScheme: IEncryptionScheme;
begin
  Result := FEncryptionScheme;
end;

function TPbeS2Parameters.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FKeyDerivationFunc, FEncryptionScheme);
end;

{ TPbkdf2Params }

class constructor TPbkdf2Params.Create;
begin
  FDefaultPrf := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdHmacWithSha1, TDerNull.Instance);
end;

class function TPbkdf2Params.GetDefaultPrf: IAlgorithmIdentifier;
begin
  Result := FDefaultPrf;
end;

class function TPbkdf2Params.GetInstance(AObj: TObject): IPbkdf2Params;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPbkdf2Params, Result) then
    Exit;
  Result := TPbkdf2Params.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPbkdf2Params.GetInstance(const AObj: IAsn1Convertible): IPbkdf2Params;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPbkdf2Params, Result) then
    Exit;
  Result := TPbkdf2Params.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPbkdf2Params.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPbkdf2Params;
begin
  Result := TPbkdf2Params.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPbkdf2Params.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPbkdf2Params;
begin
  Result := TPbkdf2Params.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPbkdf2Params.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 2) or (LCount > 4) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  FOctStr := TAsn1OctetString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FIterationCount := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FKeyLength := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, ReadOptionalDerInteger);
  FPrf := TAsn1Utilities.ReadOptional<IAlgorithmIdentifier>(ASeq, LPos, ReadOptionalAlgorithmIdentifier);
  if FPrf = nil then
    FPrf := DefaultPrf;
  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

class function TPbkdf2Params.ReadOptionalDerInteger(AEnc: IAsn1Encodable): IDerInteger;
begin
  Result := TDerInteger.GetOptional(AEnc);
end;

class function TPbkdf2Params.ReadOptionalAlgorithmIdentifier(AEnc: IAsn1Encodable): IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.GetOptional(AEnc);
end;

constructor TPbkdf2Params.Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32);
begin
  Create(ASalt, AIterationCount, nil);
end;

constructor TPbkdf2Params.Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
  AKeyLength: Int32);
begin
  Create(ASalt, AIterationCount, AKeyLength, nil);
end;

constructor TPbkdf2Params.Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
  const APrf: IAlgorithmIdentifier);
begin
  inherited Create();
  FOctStr := TDerOctetString.FromContents(ASalt);
  FIterationCount := TDerInteger.ValueOf(AIterationCount);
  FKeyLength := nil;
  if APrf <> nil then
    FPrf := APrf
  else
    FPrf := DefaultPrf;
end;

constructor TPbkdf2Params.Create(const ASalt: TCryptoLibByteArray; AIterationCount: Int32;
  AKeyLength: Int32; const APrf: IAlgorithmIdentifier);
begin
  inherited Create();
  FOctStr := TDerOctetString.FromContents(ASalt);
  FIterationCount := TDerInteger.ValueOf(AIterationCount);
  FKeyLength := TDerInteger.ValueOf(AKeyLength);
  if APrf <> nil then
    FPrf := APrf
  else
    FPrf := DefaultPrf;
end;

function TPbkdf2Params.GetSalt: IAsn1OctetString;
begin
  Result := FOctStr;
end;

function TPbkdf2Params.GetIterationCountObject: IDerInteger;
begin
  Result := FIterationCount;
end;

function TPbkdf2Params.GetKeyLengthObject: IDerInteger;
begin
  Result := FKeyLength;
end;

function TPbkdf2Params.GetPrf: IAlgorithmIdentifier;
begin
  Result := FPrf;
end;

function TPbkdf2Params.GetSaltBytes: TCryptoLibByteArray;
begin
  Result := FOctStr.GetOctets();
end;

function TPbkdf2Params.GetIterationCount: TBigInteger;
begin
  Result := FIterationCount.Value;
end;

function TPbkdf2Params.GetKeyLength: TBigInteger;
begin
  if FKeyLength = nil then
    Result := TBigInteger.GetDefault
  else
    Result := FKeyLength.Value;
end;

function TPbkdf2Params.GetIsDefaultPrf: Boolean;
begin
  Result := DefaultPrf.Equals(FPrf);
end;

function TPbkdf2Params.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);
  LV.Add(FOctStr, FIterationCount);
  LV.AddOptional(FKeyLength);
  if not IsDefaultPrf then
    LV.Add(FPrf);
  Result := TDerSequence.Create(LV);
end;

{ TPkcs12PbeParams }

class function TPkcs12PbeParams.GetInstance(AObj: TObject): IPkcs12PbeParams;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPkcs12PbeParams, Result) then
    Exit;
  Result := TPkcs12PbeParams.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPkcs12PbeParams.GetInstance(const AObj: IAsn1Convertible): IPkcs12PbeParams;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;
  if Supports(AObj, IPkcs12PbeParams, Result) then
    Exit;
  Result := TPkcs12PbeParams.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPkcs12PbeParams.GetInstance(const AEncoded: TCryptoLibByteArray): IPkcs12PbeParams;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;
  Result := TPkcs12PbeParams.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPkcs12PbeParams.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPkcs12PbeParams;
begin
  Result := TPkcs12PbeParams.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPkcs12PbeParams.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPkcs12PbeParams;
begin
  Result := TPkcs12PbeParams.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPkcs12PbeParams.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
begin
  inherited Create();
  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);
  FIV := TAsn1OctetString.GetInstance(ASeq[0]);
  FIterations := TDerInteger.GetInstance(ASeq[1]);
end;

constructor TPkcs12PbeParams.Create(const ASalt: TCryptoLibByteArray; AIterations: Int32);
begin
  inherited Create();
  FIV := TDerOctetString.FromContents(ASalt);
  FIterations := TDerInteger.ValueOf(AIterations);
end;

function TPkcs12PbeParams.GetIV: IAsn1OctetString;
begin
  Result := FIV;
end;

function TPkcs12PbeParams.GetIterationsObject: IDerInteger;
begin
  Result := FIterations;
end;

function TPkcs12PbeParams.GetIVBytes: TCryptoLibByteArray;
begin
  Result := FIV.GetOctets();
end;

function TPkcs12PbeParams.GetIterations: TBigInteger;
begin
  Result := FIterations.Value;
end;

function TPkcs12PbeParams.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FIV, FIterations);
end;

{ TPkcsContentInfo }

class function TPkcsContentInfo.GetInstance(AObj: TObject): IPkcsContentInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPkcsContentInfo, Result) then
    Exit;

  raise EArgumentCryptoLibException.CreateFmt('illegal object in GetInstance: %s', [TPlatformUtilities.GetTypeName(AObj)]);
end;

class function TPkcsContentInfo.GetInstance(const AObj: IAsn1Convertible): IPkcsContentInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPkcsContentInfo, Result) then
    Exit;

  Result := TPkcsContentInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPkcsContentInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IPkcsContentInfo;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TPkcsContentInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPkcsContentInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPkcsContentInfo;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPkcsContentInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPkcsContentInfo;
begin
  Result := GetInstance(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPkcsContentInfo.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LTagged: IAsn1TaggedObject;
begin
  Inherited Create();
  LCount := ASeq.Count;
  if (LCount < 1) or (LCount > 2) then
    raise EArgumentCryptoLibException.CreateFmt('Bad sequence size: %d', [LCount]);

  FContentType := TDerObjectIdentifier.GetInstance(ASeq[0]);

  if ASeq.Count > 1 then
  begin
    LTagged := TAsn1TaggedObject.GetContextInstance(ASeq[1], 0);
    FContent := LTagged.GetExplicitBaseObject();
  end
  else
  begin
    FContent := nil;
  end;
end;

constructor TPkcsContentInfo.Create(const AContentType: IDerObjectIdentifier;
  const AContent: IAsn1Encodable);
begin
  Inherited Create();
  if AContentType = nil then
    raise EArgumentNilCryptoLibException.Create('contentType');
  FContentType := AContentType;
  FContent := AContent;
end;

function TPkcsContentInfo.GetContentType: IDerObjectIdentifier;
begin
  Result := FContentType;
end;

function TPkcsContentInfo.GetContent: IAsn1Encodable;
begin
  Result := FContent;
end;

function TPkcsContentInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(2);
  LV.Add(FContentType);
  if FContent <> nil then
  begin
    LV.Add(TBerTaggedObject.Create(True, 0, FContent));
  end;
  Result := TBerSequence.Create(LV);
end;

{ TPkcsSignedData }

class function TPkcsSignedData.GetInstance(AObj: TObject): IPkcsSignedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPkcsSignedData, Result) then
    Exit;

  raise EArgumentCryptoLibException.CreateFmt('illegal object in GetInstance: %s', [TPlatformUtilities.GetTypeName(AObj)]);
end;

class function TPkcsSignedData.GetInstance(const AObj: IAsn1Convertible): IPkcsSignedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPkcsSignedData, Result) then
    Exit;

  Result := TPkcsSignedData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPkcsSignedData.GetInstance(const AEncoded: TCryptoLibByteArray): IPkcsSignedData;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TPkcsSignedData.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPkcsSignedData.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPkcsSignedData;
begin
  Result := GetInstance(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPkcsSignedData.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPkcsSignedData;
begin
  Result := GetInstance(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPkcsSignedData.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  Inherited Create();
  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 4) or (LCount > 6) then
    raise EArgumentCryptoLibException.CreateFmt(SBadSequenceSize, [LCount]);

  FVersion := TDerInteger.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FDigestAlgorithms := TAsn1Set.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FContentInfo := TPkcsContentInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FCertificates := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Sequence, IAsn1Set>(
    ASeq, LPos, 0, ASeq,
    GetTaggedAsn1SetFromSeq);
  FCrls := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Sequence, IAsn1Set>(
    ASeq, LPos, 1, ASeq,
    GetTaggedAsn1SetFromSeq);
  FSignerInfos := TAsn1Set.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

class function TPkcsSignedData.GetTaggedAsn1SetFromSeq(ATagged: IAsn1TaggedObject; AState: IAsn1Sequence): IAsn1Set;
begin
  Result := TAsn1Set.GetTagged(ATagged, False);
end;

constructor TPkcsSignedData.Create(const AVersion: IDerInteger;
  const ADigestAlgorithms: IAsn1Set; const AContentInfo: IPkcsContentInfo;
  const ACertificates: IAsn1Set; const ACrls: IAsn1Set;
  const ASignerInfos: IAsn1Set);
begin
  Inherited Create();
  if AVersion = nil then
    raise EArgumentNilCryptoLibException.Create(SVersionNil);
  if ADigestAlgorithms = nil then
    raise EArgumentNilCryptoLibException.Create('digestAlgorithms');
  if AContentInfo = nil then
    raise EArgumentNilCryptoLibException.Create('contentInfo');
  if ASignerInfos = nil then
    raise EArgumentNilCryptoLibException.Create('signerInfos');

  FVersion := AVersion;
  FDigestAlgorithms := ADigestAlgorithms;
  FContentInfo := AContentInfo;
  FCertificates := ACertificates;
  FCrls := ACrls;
  FSignerInfos := ASignerInfos;
end;

function TPkcsSignedData.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TPkcsSignedData.GetDigestAlgorithms: IAsn1Set;
begin
  Result := FDigestAlgorithms;
end;

function TPkcsSignedData.GetContentInfo: IPkcsContentInfo;
begin
  Result := FContentInfo;
end;

function TPkcsSignedData.GetCertificates: IAsn1Set;
begin
  Result := FCertificates;
end;

function TPkcsSignedData.GetCrls: IAsn1Set;
begin
  Result := FCrls;
end;

function TPkcsSignedData.GetSignerInfos: IAsn1Set;
begin
  Result := FSignerInfos;
end;

function TPkcsSignedData.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(6);
  LV.Add([FVersion, FDigestAlgorithms, FContentInfo]);
  LV.AddOptionalTagged(False, 0, FCertificates);
  LV.AddOptionalTagged(False, 1, FCrls);
  LV.Add(FSignerInfos);
  Result := TBerSequence.Create(LV);
end;

{ TMacData }

class function TMacData.GetInstance(AObj: TObject): IMacData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IMacData, Result) then
    Exit;

  Result := TMacData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TMacData.GetInstance(const AObj: IAsn1Convertible): IMacData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IMacData, Result) then
    Exit;

  Result := TMacData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TMacData.GetInstance(const AEncoded: TCryptoLibByteArray): IMacData;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TMacData.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TMacData.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IMacData;
begin
  Result := TMacData.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TMacData.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IMacData;
begin
  Result := TMacData.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TMacData.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FMac := TDigestInfo.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FMacSalt := TAsn1OctetString.GetInstance(ASeq[LPos]);
  System.Inc(LPos);
  FIterations := TAsn1Utilities.ReadOptional<IDerInteger>(ASeq, LPos, ReadOptionalDerInteger);
  if FIterations = nil then
    FIterations := TDerInteger.One;

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

class function TMacData.ReadOptionalDerInteger(AEnc: IAsn1Encodable): IDerInteger;
begin
  Result := TDerInteger.GetOptional(AEnc);
end;

constructor TMacData.Create(const ADigInfo: IDigestInfo;
  const ASalt: TCryptoLibByteArray; AIterationCount: Int32);
begin
  inherited Create();

  if ADigInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SMacNil);

  FMac := ADigInfo;
  FMacSalt := TDerOctetString.FromContents(ASalt);
  FIterations := TDerInteger.ValueOf(AIterationCount);
end;

constructor TMacData.Create(const AMac: IDigestInfo; const AMacSalt: IAsn1OctetString;
  const AIterations: IDerInteger);
begin
  inherited Create();

  if AMac = nil then
    raise EArgumentNilCryptoLibException.Create(SMacNil);
  if AMacSalt = nil then
    raise EArgumentNilCryptoLibException.Create(SMacSaltNil);
  if AIterations = nil then
    raise EArgumentNilCryptoLibException.Create(SIterationsNil);

  FMac := AMac;
  FMacSalt := AMacSalt;
  FIterations := AIterations;
end;

function TMacData.GetMac: IDigestInfo;
begin
  Result := FMac;
end;

function TMacData.GetSalt: TCryptoLibByteArray;
begin
  Result := System.Copy(FMacSalt.GetOctets());
end;

function TMacData.GetIterationCount: TBigInteger;
begin
  Result := FIterations.Value;
end;

function TMacData.GetIterations: IDerInteger;
begin
  Result := FIterations;
end;

function TMacData.GetMacSalt: IAsn1OctetString;
begin
  Result := FMacSalt;
end;

function TMacData.ToAsn1Object: IAsn1Object;
begin
  if FIterations.HasValue(1) then
    Result := TDerSequence.Create(FMac, FMacSalt)
  else
    Result := TDerSequence.Create([FMac, FMacSalt, FIterations]);
end;

{ TPfx }

class function TPfx.GetInstance(AObj: TObject): IPfx;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPfx, Result) then
    Exit;

  Result := TPfx.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPfx.GetInstance(const AObj: IAsn1Convertible): IPfx;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPfx, Result) then
    Exit;

  Result := TPfx.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPfx.GetInstance(const AEncoded: TCryptoLibByteArray): IPfx;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TPfx.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPfx.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IPfx;
begin
  Result := TPfx.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TPfx.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPfx;
begin
  Result := TPfx.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPfx.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LVersion: IDerInteger;
begin
  inherited Create();

  LCount := ASeq.Count;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  LVersion := TDerInteger.GetInstance(ASeq[0]);
  if not LVersion.HasValue(3) then
    raise EArgumentCryptoLibException.Create(SWrongVersionForPfxPdu);

  FContentInfo := TPkcsContentInfo.GetInstance(ASeq[1]);

  if LCount <= 2 then
    FMacData := nil
  else
    FMacData := TMacData.GetInstance(ASeq[2]);
end;

constructor TPfx.Create(const AContentInfo: IPkcsContentInfo;
  const AMacData: IMacData);
begin
  inherited Create();

  if AContentInfo = nil then
    raise EArgumentNilCryptoLibException.Create(SContentInfoNil);

  FContentInfo := AContentInfo;
  FMacData := AMacData;
end;

function TPfx.GetAuthSafe: IPkcsContentInfo;
begin
  Result := FContentInfo;
end;

function TPfx.GetMacData: IMacData;
begin
  Result := FMacData;
end;

function TPfx.ToAsn1Object: IAsn1Object;
begin
  if FMacData = nil then
    Result := TBerSequence.Create(TDerInteger.Three, FContentInfo)
  else
    Result := TBerSequence.Create([TDerInteger.Three, FContentInfo, FMacData]);
end;

{ TSafeBag }

class function TSafeBag.GetInstance(AObj: TObject): ISafeBag;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISafeBag, Result) then
    Exit;

  Result := TSafeBag.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSafeBag.GetInstance(const AObj: IAsn1Convertible): ISafeBag;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISafeBag, Result) then
    Exit;

  Result := TSafeBag.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSafeBag.GetInstance(const AEncoded: TCryptoLibByteArray): ISafeBag;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TSafeBag.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TSafeBag.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISafeBag;
begin
  Result := TSafeBag.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TSafeBag.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISafeBag;
begin
  Result := TSafeBag.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TSafeBag.Create(const ASeq: IAsn1Sequence);
var
  LCount, LPos: Int32;
  LTagged: IAsn1TaggedObject;
begin
  inherited Create();

  LCount := ASeq.Count;
  LPos := 0;
  if (LCount < 2) or (LCount > 3) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FBagID := TDerObjectIdentifier.GetInstance(ASeq[LPos]);
  System.Inc(LPos);

  LTagged := TAsn1TaggedObject.GetContextInstance(ASeq[LPos], 0);
  FBagValue := LTagged.GetExplicitBaseObject();
  System.Inc(LPos);

  FBagAttributes := TAsn1Utilities.ReadOptional<IAsn1Set>(ASeq, LPos, ReadOptionalAsn1Set);

  if LPos <> LCount then
    raise EArgumentCryptoLibException.Create(SUnexpectedElementsInSequence);
end;

class function TSafeBag.ReadOptionalAsn1Set(AElement: IAsn1Encodable): IAsn1Set;
begin
  Result := TAsn1Set.GetOptional(AElement);
end;

constructor TSafeBag.Create(const ABagID: IDerObjectIdentifier;
  const ABagValue: IAsn1Encodable);
begin
  Create(ABagID, ABagValue, nil);
end;

constructor TSafeBag.Create(const ABagID: IDerObjectIdentifier;
  const ABagValue: IAsn1Encodable; const ABagAttributes: IAsn1Set);
begin
  inherited Create();

  if ABagID = nil then
    raise EArgumentNilCryptoLibException.Create('bagID');
  if ABagValue = nil then
    raise EArgumentNilCryptoLibException.Create('bagValue');

  FBagID := ABagID;
  FBagValue := ABagValue;
  FBagAttributes := ABagAttributes;
end;

function TSafeBag.GetBagID: IDerObjectIdentifier;
begin
  Result := FBagID;
end;

function TSafeBag.GetBagValue: IAsn1Object;
begin
  Result := FBagValue.ToAsn1Object();
end;

function TSafeBag.GetBagValueEncodable: IAsn1Encodable;
begin
  Result := FBagValue;
end;

function TSafeBag.GetBagAttributes: IAsn1Set;
begin
  Result := FBagAttributes;
end;

function TSafeBag.ToAsn1Object: IAsn1Object;
var
  LTaggedBagValue: IAsn1TaggedObject;
begin
  LTaggedBagValue := TDerTaggedObject.Create(True, 0, FBagValue);
  if FBagAttributes = nil then
    Result := TDerSequence.Create(FBagID, LTaggedBagValue)
  else
    Result := TDerSequence.Create([FBagID, LTaggedBagValue, FBagAttributes]);
end;

{ TCertBag }

class function TCertBag.GetInstance(AObj: TObject): ICertBag;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertBag, Result) then
    Exit;

  Result := TCertBag.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertBag.GetInstance(const AObj: IAsn1Convertible): ICertBag;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertBag, Result) then
    Exit;

  Result := TCertBag.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertBag.GetInstance(const AEncoded: TCryptoLibByteArray): ICertBag;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TCertBag.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCertBag.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertBag;
begin
  Result := TCertBag.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TCertBag.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertBag;
begin
  Result := TCertBag.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCertBag.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LTagged: IAsn1TaggedObject;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  FCertID := TDerObjectIdentifier.GetInstance(ASeq[0]);
  LTagged := TAsn1TaggedObject.GetContextInstance(ASeq[1], 0);
  FCertValue := LTagged.GetExplicitBaseObject();
end;

constructor TCertBag.Create(const ACertID: IDerObjectIdentifier;
  const ACertValue: IAsn1Encodable);
begin
  inherited Create();

  if ACertID = nil then
    raise EArgumentNilCryptoLibException.Create('certID');
  if ACertValue = nil then
    raise EArgumentNilCryptoLibException.Create('certValue');

  FCertID := ACertID;
  FCertValue := ACertValue;
end;

function TCertBag.GetCertID: IDerObjectIdentifier;
begin
  Result := FCertID;
end;

function TCertBag.GetCertValue: IAsn1Object;
begin
  Result := FCertValue.ToAsn1Object();
end;

function TCertBag.GetCertValueEncodable: IAsn1Encodable;
begin
  Result := FCertValue;
end;

function TCertBag.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.Create(FCertID, TDerTaggedObject.Create(0, FCertValue) as IDerTaggedObject);
end;

{ TAuthenticatedSafe }

class function TAuthenticatedSafe.GetInstance(AObj: TObject): IAuthenticatedSafe;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAuthenticatedSafe, Result) then
    Exit;

  Result := TAuthenticatedSafe.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAuthenticatedSafe.GetInstance(const AObj: IAsn1Convertible): IAuthenticatedSafe;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IAuthenticatedSafe, Result) then
    Exit;

  Result := TAuthenticatedSafe.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TAuthenticatedSafe.GetInstance(const AEncoded: TCryptoLibByteArray): IAuthenticatedSafe;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TAuthenticatedSafe.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TAuthenticatedSafe.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAuthenticatedSafe;
begin
  Result := TAuthenticatedSafe.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TAuthenticatedSafe.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IAuthenticatedSafe;
begin
  Result := TAuthenticatedSafe.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TAuthenticatedSafe.Create(const ASeq: IAsn1Sequence);
begin
  inherited Create();

  FInfo := TArrayUtilities.Map<IAsn1Encodable, IPkcsContentInfo>(ASeq.Elements, ElementToPkcsContentInfo);
  FIsBer := Supports(ASeq, IBerSequence);
end;

class function TAuthenticatedSafe.ElementToPkcsContentInfo(AElement: IAsn1Encodable): IPkcsContentInfo;
begin
  Result := TPkcsContentInfo.GetInstance(AElement);
end;

class function TAuthenticatedSafe.PkcsContentInfoToAsn1Encodable(AElement: IPkcsContentInfo): IAsn1Encodable;
begin
  Result := AElement as IAsn1Encodable;
end;

constructor TAuthenticatedSafe.Create(const AInfo: TCryptoLibGenericArray<IPkcsContentInfo>);
begin
  inherited Create();
  FInfo := System.Copy(AInfo);
  FIsBer := True;
end;

function TAuthenticatedSafe.GetContentInfo: TCryptoLibGenericArray<IPkcsContentInfo>;
begin
  Result := System.Copy(FInfo);
end;

function TAuthenticatedSafe.ToAsn1Object: IAsn1Object;
var
 LInfo: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  LInfo := TArrayUtilities.Map<IPkcsContentInfo, IAsn1Encodable>(FInfo, PkcsContentInfoToAsn1Encodable);
  if FIsBer then
    Result := TBerSequence.Create(LInfo)
  else
    Result := TDLSequence.Create(LInfo);
end;

{ TEncryptedData }

class function TPkcsEncryptedData.GetInstance(AObj: TObject): IPkcsEncryptedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPkcsEncryptedData, Result) then
    Exit;

  Result := TPkcsEncryptedData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPkcsEncryptedData.GetInstance(const AObj: IAsn1Convertible): IPkcsEncryptedData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IPkcsEncryptedData, Result) then
    Exit;

  Result := TPkcsEncryptedData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TPkcsEncryptedData.GetInstance(const AEncoded: TCryptoLibByteArray): IPkcsEncryptedData;
begin
  if AEncoded = nil then
  begin
    Result := nil;
    Exit;
  end;

  Result := TPkcsEncryptedData.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TPkcsEncryptedData.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPkcsEncryptedData;
begin
  Result := TPkcsEncryptedData.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TPkcsEncryptedData.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IPkcsEncryptedData;
begin
  Result := TPkcsEncryptedData.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TPkcsEncryptedData.Create(const ASeq: IAsn1Sequence);
var
  LCount: Int32;
  LVersion: IDerInteger;
begin
  inherited Create();

  LCount := ASeq.Count;
  if LCount <> 2 then
    raise EArgumentCryptoLibException.CreateResFmt(@SBadSequenceSize, [LCount]);

  LVersion := TDerInteger.GetInstance(ASeq[0]);
  if not LVersion.HasValue(0) then
    raise EArgumentCryptoLibException.Create(SEncryptedDataVersionNotZero);

  FData := TAsn1Sequence.GetInstance(ASeq[1]);
end;

constructor TPkcsEncryptedData.Create(const AContentType: IDerObjectIdentifier;
  const AEncryptionAlgorithm: IAlgorithmIdentifier;
  const AContent: IAsn1Encodable);
begin
  inherited Create();

  FData := TBerSequence.Create([AContentType, AEncryptionAlgorithm,
    TBerTaggedObject.Create(False, 0, AContent) as IBerTaggedObject]);
end;

function TPkcsEncryptedData.GetContentType: IDerObjectIdentifier;
begin
  Result := TDerObjectIdentifier.GetInstance(FData[0]);
end;

function TPkcsEncryptedData.GetEncryptionAlgorithm: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.GetInstance(FData[1]);
end;

function TPkcsEncryptedData.GetContent: IAsn1OctetString;
var
  LTagged: IAsn1TaggedObject;
begin
  Result := nil;
  if FData.Count <> 3 then
    Exit;

  LTagged := TAsn1TaggedObject.GetContextInstance(FData[2], 0);
  Result := TAsn1OctetString.GetTagged(LTagged, False);
end;

function TPkcsEncryptedData.ToAsn1Object: IAsn1Object;
begin
  Result := TBerSequence.Create(TDerInteger.Zero, FData);
end;

end.
