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

unit ClpOcspAsn1Objects;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Objects,
  ClpAsn1Core,
  ClpAsn1Utilities,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIOcspAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SOcspAsn1ElementNil = 'ASN.1 encodable element cannot be nil';
  SOcspHashAlgorithmNil = 'hash algorithm cannot be nil';
  SOcspIssuerNameHashNil = 'issuer name hash cannot be nil';
  SOcspIssuerKeyHashNil = 'issuer key hash cannot be nil';
  SOcspSerialNumberNil = 'serial number cannot be nil';
  SOcspReqCertNil = 'request certificate ID cannot be nil';
  SOcspRequestListNil = 'request list cannot be nil';
  SOcspTbsRequestNil = 'TBSRequest cannot be nil';
  SOcspSignatureAlgorithmNil = 'signature algorithm cannot be nil';
  SOcspSignatureValueNil = 'signature value cannot be nil';
  SOcspResponseStatusNil = 'response status cannot be nil';
  SOcspResponseTypeNil = 'response type cannot be nil';
  SOcspResponseNil = 'response cannot be nil';
  SOcspTbsResponseDataNil = 'TBS response data cannot be nil';
  SOcspResponderIDNil = 'responder ID cannot be nil';
  SOcspProducedAtNil = 'produced at time cannot be nil';
  SOcspResponsesNil = 'responses cannot be nil';
  SOcspCertStatusNil = 'certificate status cannot be nil';
  SOcspThisUpdateNil = 'this update time cannot be nil';
  SOcspRevocationTimeNil = 'revocation time cannot be nil';
  SOcspIssuerNil = 'issuer cannot be nil';
  SOcspStatusValueNil = 'status value cannot be nil';
  SOcspUnknownTag = 'unknown tag: %s';

type
  /// <summary>The CertID ASN.1 type (RFC 6960 sec. 4.1.1).</summary>
  /// <remarks>
  /// <code>
  /// CertID ::= SEQUENCE {
  ///   hashAlgorithm  AlgorithmIdentifier,
  ///   issuerNameHash OCTET STRING,
  ///   issuerKeyHash  OCTET STRING,
  ///   serialNumber   CertificateSerialNumber
  /// }
  /// </code>
  /// </remarks>
  TCertID = class(TAsn1Encodable, ICertID)

  strict private
  var
    FHashAlgorithm: IAlgorithmIdentifier;
    FIssuerNameHash: IAsn1OctetString;
    FIssuerKeyHash: IAsn1OctetString;
    FSerialNumber: IDerInteger;

  strict protected
    function GetHashAlgorithm: IAlgorithmIdentifier;
    function GetIssuerNameHash: IAsn1OctetString;
    function GetIssuerKeyHash: IAsn1OctetString;
    function GetSerialNumber: IDerInteger;

  public
    class function GetInstance(AObj: TObject): ICertID; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ICertID; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICertID; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ICertID; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICertID; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AHashAlgorithm: IAlgorithmIdentifier;
      const AIssuerNameHash, AIssuerKeyHash: IAsn1OctetString;
      const ASerialNumber: IDerInteger); overload;

    function ToAsn1Object: IAsn1Object; override;

    property HashAlgorithm: IAlgorithmIdentifier read GetHashAlgorithm;
    property IssuerNameHash: IAsn1OctetString read GetIssuerNameHash;
    property IssuerKeyHash: IAsn1OctetString read GetIssuerKeyHash;
    property SerialNumber: IDerInteger read GetSerialNumber;

  end;

  /// <summary>The Request ASN.1 type, one entry of a TBSRequest request list (RFC 6960 sec. 4.1.1).</summary>
  /// <remarks>
  /// <code>
  /// Request ::= SEQUENCE {
  ///   reqCert                 CertID,
  ///   singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TRequest = class(TAsn1Encodable, IRequest)

  strict private
  var
    FReqCert: ICertID;
    FSingleRequestExtensions: IX509Extensions;

  strict protected
    function GetReqCert: ICertID;
    function GetSingleRequestExtensions: IX509Extensions;

  public
    class function GetInstance(AObj: TObject): IRequest; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IRequest; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRequest; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRequest; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRequest; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AReqCert: ICertID;
      const ASingleRequestExtensions: IX509Extensions); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ReqCert: ICertID read GetReqCert;
    property SingleRequestExtensions: IX509Extensions read GetSingleRequestExtensions;

  end;

  /// <summary>The TBSRequest ASN.1 type (RFC 6960 sec. 4.1.1).</summary>
  /// <remarks>
  /// <code>
  /// TBSRequest ::= SEQUENCE {
  ///   version           [0] EXPLICIT Version DEFAULT v1,
  ///   requestorName     [1] EXPLICIT GeneralName OPTIONAL,
  ///   requestList           SEQUENCE OF Request,
  ///   requestExtensions [2] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TTbsRequest = class(TAsn1Encodable, ITbsRequest)

  strict private
  var
    FVersion: IDerInteger;
    FVersionPresent: Boolean;
    FRequestorName: IGeneralName;
    FRequestList: IAsn1Sequence;
    FRequestExtensions: IX509Extensions;

  strict protected
    function GetVersion: IDerInteger;
    function GetRequestorName: IGeneralName;
    function GetRequestList: IAsn1Sequence;
    function GetRequestExtensions: IX509Extensions;

  public
    class function GetInstance(AObj: TObject): ITbsRequest; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ITbsRequest; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ITbsRequest; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ITbsRequest; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ITbsRequest; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ARequestorName: IGeneralName; const ARequestList: IAsn1Sequence;
      const ARequestExtensions: IX509Extensions); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property RequestorName: IGeneralName read GetRequestorName;
    property RequestList: IAsn1Sequence read GetRequestList;
    property RequestExtensions: IX509Extensions read GetRequestExtensions;

  end;

  /// <summary>The OCSP request Signature ASN.1 type (RFC 6960 sec. 4.1.1).</summary>
  /// <remarks>
  /// <code>
  /// Signature ::= SEQUENCE {
  ///   signatureAlgorithm AlgorithmIdentifier,
  ///   signature          BIT STRING,
  ///   certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TSignature = class(TAsn1Encodable, ISignature)

  strict private
  var
    FSignatureAlgorithm: IAlgorithmIdentifier;
    FSignatureValue: IDerBitString;
    FCerts: IAsn1Sequence;

  strict protected
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignatureValue: IDerBitString;
    function GetCerts: IAsn1Sequence;

  public
    class function GetInstance(AObj: TObject): ISignature; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ISignature; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ISignature; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ISignature; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISignature; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ASignatureAlgorithm: IAlgorithmIdentifier;
      const ASignatureValue: IDerBitString); overload;
    constructor Create(const ASignatureAlgorithm: IAlgorithmIdentifier;
      const ASignatureValue: IDerBitString; const ACerts: IAsn1Sequence); overload;

    function GetSignatureOctets: TCryptoLibByteArray;

    function ToAsn1Object: IAsn1Object; override;

    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SignatureValue: IDerBitString read GetSignatureValue;
    property Certs: IAsn1Sequence read GetCerts;

  end;

  /// <summary>The OCSPRequest ASN.1 type (RFC 6960 sec. 4.1.1).</summary>
  /// <remarks>
  /// <code>
  /// OCSPRequest ::= SEQUENCE {
  ///   tbsRequest            TBSRequest,
  ///   optionalSignature [0] EXPLICIT Signature OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TOcspRequest = class(TAsn1Encodable, IOcspRequest)

  strict private
  var
    FTbsRequest: ITbsRequest;
    FOptionalSignature: ISignature;

  strict protected
    function GetTbsRequest: ITbsRequest;
    function GetOptionalSignature: ISignature;

  public
    class function GetInstance(AObj: TObject): IOcspRequest; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IOcspRequest; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IOcspRequest; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IOcspRequest; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IOcspRequest; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ATbsRequest: ITbsRequest;
      const AOptionalSignature: ISignature); overload;

    function ToAsn1Object: IAsn1Object; override;

    property TbsRequest: ITbsRequest read GetTbsRequest;
    property OptionalSignature: ISignature read GetOptionalSignature;

  end;

  /// <summary>The OCSPResponseStatus ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// OCSPResponseStatus ::= ENUMERATED {
  ///   successful       (0),  --Response has valid confirmations
  ///   malformedRequest (1),  --Illegal confirmation request
  ///   internalError    (2),  --Internal error in issuer
  ///   tryLater         (3),  --Try again later
  ///                          --(4) is not used
  ///   sigRequired      (5),  --Must sign the request
  ///   unauthorized     (6)   --Request unauthorized
  /// }
  /// </code>
  /// </remarks>
  TOcspResponseStatus = class(TDerEnumerated, IOcspResponseStatus)

  public
  const
    Successful = 0;
    MalformedRequest = 1;
    InternalError = 2;
    TryLater = 3;
    // 4 is not used
    SignatureRequired = 5;
    Unauthorized = 6;

    constructor Create(AValue: Int32); overload;
    constructor Create(const AValue: IDerEnumerated); overload;

  end;

  /// <summary>The ResponseBytes ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// ResponseBytes ::= SEQUENCE {
  ///   responseType OBJECT IDENTIFIER,
  ///   response     OCTET STRING
  /// }
  /// </code>
  /// </remarks>
  TResponseBytes = class(TAsn1Encodable, IResponseBytes)

  strict private
  var
    FResponseType: IDerObjectIdentifier;
    FResponse: IAsn1OctetString;

  strict protected
    function GetResponseType: IDerObjectIdentifier;
    function GetResponse: IAsn1OctetString;

  public
    class function GetInstance(AObj: TObject): IResponseBytes; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IResponseBytes; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IResponseBytes; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IResponseBytes; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IResponseBytes; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IResponseBytes; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AResponseType: IDerObjectIdentifier;
      const AResponse: IAsn1OctetString); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ResponseType: IDerObjectIdentifier read GetResponseType;
    property Response: IAsn1OctetString read GetResponse;

  end;

  /// <summary>The OCSPResponse ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// OCSPResponse ::= SEQUENCE {
  ///   responseStatus     OCSPResponseStatus,
  ///   responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TOcspResponse = class(TAsn1Encodable, IOcspResponse)

  strict private
  var
    FResponseStatus: IOcspResponseStatus;
    FResponseBytes: IResponseBytes;

  strict protected
    function GetResponseStatus: IOcspResponseStatus;
    function GetResponseBytes: IResponseBytes;

  public
    class function GetInstance(AObj: TObject): IOcspResponse; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IOcspResponse; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IOcspResponse; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IOcspResponse; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IOcspResponse; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IOcspResponse; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AResponseStatus: IOcspResponseStatus;
      const AResponseBytes: IResponseBytes); overload;

    function ToAsn1Object: IAsn1Object; override;

    property ResponseStatus: IOcspResponseStatus read GetResponseStatus;
    property ResponseBytes: IResponseBytes read GetResponseBytes;

  end;

  /// <summary>The ResponderID CHOICE ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// ResponderID ::= CHOICE {
  ///   byName [1] Name,
  ///   byKey  [2] KeyHash
  /// }
  /// </code>
  /// </remarks>
  TResponderID = class(TAsn1Encodable, IResponderID, IAsn1Choice)

  strict private
  var
    FId: IAsn1Encodable;

    class function ChoiceGetOptional(AElement: IAsn1Encodable): IResponderID; static;
    class function ChoiceGetInstance(AElement: IAsn1Encodable): IResponderID; static;

  strict protected
    function GetName: IX509Name;

  public
    class function GetInstance(AObj: TObject): IResponderID; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IResponderID; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IResponderID; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AIsExplicit: Boolean): IResponderID; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IResponderID; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IResponderID; static;

    constructor Create(const AId: IAsn1OctetString); overload;
    constructor Create(const AId: IX509Name); overload;

    function GetKeyHash: TCryptoLibByteArray;

    function ToAsn1Object: IAsn1Object; override;

    property Name: IX509Name read GetName;

  end;

  /// <summary>The RevokedInfo ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// RevokedInfo ::= SEQUENCE {
  ///   revocationTime       GeneralizedTime,
  ///   revocationReason [0] EXPLICIT CRLReason OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TRevokedInfo = class(TAsn1Encodable, IRevokedInfo)

  strict private
  var
    FRevocationTime: IAsn1GeneralizedTime;
    FRevocationReason: ICrlReason;

    class function GetTaggedCrlReason(const ATagged: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICrlReason; static;

  strict protected
    function GetRevocationTime: IAsn1GeneralizedTime;
    function GetRevocationReason: ICrlReason;

  public
    class function GetInstance(AObj: TObject): IRevokedInfo; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IRevokedInfo; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IRevokedInfo; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IRevokedInfo; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IRevokedInfo; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ARevocationTime: IAsn1GeneralizedTime); overload;
    constructor Create(const ARevocationTime: IAsn1GeneralizedTime;
      const ARevocationReason: ICrlReason); overload;

    function ToAsn1Object: IAsn1Object; override;

    property RevocationTime: IAsn1GeneralizedTime read GetRevocationTime;
    property RevocationReason: ICrlReason read GetRevocationReason;

  end;

  /// <summary>The OCSP CertStatus CHOICE ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// CertStatus ::= CHOICE {
  ///   good    [0] IMPLICIT NULL,
  ///   revoked [1] IMPLICIT RevokedInfo,
  ///   unknown [2] IMPLICIT UnknownInfo
  /// }
  ///
  /// UnknownInfo ::= NULL
  /// </code>
  /// </remarks>
  TOcspCertStatus = class(TAsn1Encodable, IOcspCertStatus, IAsn1Choice)

  strict private
  var
    FTagNo: Int32;
    FValue: IAsn1Encodable;

    class function ChoiceGetOptional(AElement: IAsn1Encodable): IOcspCertStatus; static;
    class function ChoiceGetInstance(AElement: IAsn1Encodable): IOcspCertStatus; static;
    class function GetOptionalBaseObject(const ATaggedObject: IAsn1TaggedObject): IAsn1Encodable; static;

  strict protected
    function GetTagNo: Int32;
    function GetStatus: IAsn1Encodable;

  public
  const
    Good = 0;
    Revoked = 1;
    Unknown = 2;

    class function GetInstance(AObj: TObject): IOcspCertStatus; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IOcspCertStatus; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IOcspCertStatus; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IOcspCertStatus; overload; static;
    class function GetOptional(const AElement: IAsn1Encodable): IOcspCertStatus; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IOcspCertStatus; static;

    /// <summary>Create a "good" status, i.e. the CHOICE alternative tagged zero.</summary>
    constructor Create; overload;
    constructor Create(const AInfo: IRevokedInfo); overload;
    constructor Create(ATagNo: Int32; const AValue: IAsn1Encodable); overload;
    constructor Create(const AChoice: IAsn1TaggedObject); overload;

    function ToAsn1Object: IAsn1Object; override;

    property TagNo: Int32 read GetTagNo;
    property Status: IAsn1Encodable read GetStatus;

  end;

  /// <summary>The SingleResponse ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// SingleResponse ::= SEQUENCE {
  ///   certID               CertID,
  ///   certStatus           CertStatus,
  ///   thisUpdate           GeneralizedTime,
  ///   nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
  ///   singleExtensions [1] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TSingleResponse = class(TAsn1Encodable, ISingleResponse)

  strict private
  var
    FCertID: ICertID;
    FCertStatus: IOcspCertStatus;
    FThisUpdate: IAsn1GeneralizedTime;
    FNextUpdate: IAsn1GeneralizedTime;
    FSingleExtensions: IX509Extensions;

  strict protected
    function GetCertId: ICertID;
    function GetCertStatus: IOcspCertStatus;
    function GetThisUpdate: IAsn1GeneralizedTime;
    function GetNextUpdate: IAsn1GeneralizedTime;
    function GetSingleExtensions: IX509Extensions;

  public
    class function GetInstance(AObj: TObject): ISingleResponse; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ISingleResponse; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ISingleResponse; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): ISingleResponse; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ISingleResponse; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ACertID: ICertID; const ACertStatus: IOcspCertStatus;
      const AThisUpdate, ANextUpdate: IAsn1GeneralizedTime;
      const ASingleExtensions: IX509Extensions); overload;

    function ToAsn1Object: IAsn1Object; override;

    property CertId: ICertID read GetCertId;
    property CertStatus: IOcspCertStatus read GetCertStatus;
    property ThisUpdate: IAsn1GeneralizedTime read GetThisUpdate;
    property NextUpdate: IAsn1GeneralizedTime read GetNextUpdate;
    property SingleExtensions: IX509Extensions read GetSingleExtensions;

  end;

  /// <summary>The ResponseData ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// ResponseData ::= SEQUENCE {
  ///   version            [0] EXPLICIT Version DEFAULT v1,
  ///   responderID            ResponderID,
  ///   producedAt             GeneralizedTime,
  ///   responses              SEQUENCE OF SingleResponse,
  ///   responseExtensions [1] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TResponseData = class(TAsn1Encodable, IResponseData)

  strict private
  var
    FVersion: IDerInteger;
    FVersionPresent: Boolean;
    FResponderID: IResponderID;
    FProducedAt: IAsn1GeneralizedTime;
    FResponses: IAsn1Sequence;
    FResponseExtensions: IX509Extensions;

  strict protected
    function GetVersion: IDerInteger;
    function GetResponderID: IResponderID;
    function GetProducedAt: IAsn1GeneralizedTime;
    function GetResponses: IAsn1Sequence;
    function GetResponseExtensions: IX509Extensions;

  public
    class function GetInstance(AObj: TObject): IResponseData; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IResponseData; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IResponseData; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IResponseData; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IResponseData; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AResponderID: IResponderID; const AProducedAt: IAsn1GeneralizedTime;
      const AResponses: IAsn1Sequence; const AResponseExtensions: IX509Extensions); overload;
    constructor Create(const AVersion: IDerInteger; const AResponderID: IResponderID;
      const AProducedAt: IAsn1GeneralizedTime; const AResponses: IAsn1Sequence;
      const AResponseExtensions: IX509Extensions); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Version: IDerInteger read GetVersion;
    property ResponderID: IResponderID read GetResponderID;
    property ProducedAt: IAsn1GeneralizedTime read GetProducedAt;
    property Responses: IAsn1Sequence read GetResponses;
    property ResponseExtensions: IX509Extensions read GetResponseExtensions;

  end;

  /// <summary>The BasicOCSPResponse ASN.1 type (RFC 6960 sec. 4.2.1).</summary>
  /// <remarks>
  /// <code>
  /// BasicOCSPResponse ::= SEQUENCE {
  ///   tbsResponseData    ResponseData,
  ///   signatureAlgorithm AlgorithmIdentifier,
  ///   signature          BIT STRING,
  ///   certs          [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TBasicOcspResponse = class(TAsn1Encodable, IBasicOcspResponse)

  strict private
  var
    FTbsResponseData: IResponseData;
    FSignatureAlgorithm: IAlgorithmIdentifier;
    FSignature: IDerBitString;
    FCerts: IAsn1Sequence;

  strict protected
    function GetTbsResponseData: IResponseData;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetCerts: IAsn1Sequence;

  public
    class function GetInstance(AObj: TObject): IBasicOcspResponse; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IBasicOcspResponse; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IBasicOcspResponse; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IBasicOcspResponse; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IBasicOcspResponse; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const ATbsResponseData: IResponseData;
      const ASignatureAlgorithm: IAlgorithmIdentifier; const ASignature: IDerBitString;
      const ACerts: IAsn1Sequence); overload;

    function GetSignatureOctets: TCryptoLibByteArray;

    function ToAsn1Object: IAsn1Object; override;

    property TbsResponseData: IResponseData read GetTbsResponseData;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
    property Certs: IAsn1Sequence read GetCerts;

  end;

  /// <summary>The CrlID ASN.1 type, value of the id-pkix-ocsp-crl extension (RFC 6960 sec. 4.4.2).</summary>
  /// <remarks>
  /// <code>
  /// CrlID ::= SEQUENCE {
  ///   crlUrl  [0] EXPLICIT IA5String OPTIONAL,
  ///   crlNum  [1] EXPLICIT INTEGER OPTIONAL,
  ///   crlTime [2] EXPLICIT GeneralizedTime OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TCrlID = class(TAsn1Encodable, ICrlID)

  strict private
  var
    FCrlUrl: IDerIA5String;
    FCrlNum: IDerInteger;
    FCrlTime: IAsn1GeneralizedTime;

  strict protected
    function GetCrlUrl: IDerIA5String;
    function GetCrlNum: IDerInteger;
    function GetCrlTime: IAsn1GeneralizedTime;

  public
    class function GetInstance(AObj: TObject): ICrlID; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): ICrlID; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): ICrlID; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICrlID; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): ICrlID; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;

    function ToAsn1Object: IAsn1Object; override;

    property CrlUrl: IDerIA5String read GetCrlUrl;
    property CrlNum: IDerInteger read GetCrlNum;
    property CrlTime: IAsn1GeneralizedTime read GetCrlTime;

  end;

  /// <summary>The ServiceLocator ASN.1 type, value of the id-pkix-ocsp-service-locator
  /// extension (RFC 6960 sec. 4.4.6).</summary>
  /// <remarks>
  /// <code>
  /// ServiceLocator ::= SEQUENCE {
  ///   issuer  Name,
  ///   locator AuthorityInfoAccessSyntax OPTIONAL
  /// }
  /// </code>
  /// </remarks>
  TServiceLocator = class(TAsn1Encodable, IServiceLocator)

  strict private
  var
    FIssuer: IX509Name;
    FLocator: IAuthorityInformationAccess;

  strict protected
    function GetIssuer: IX509Name;
    function GetLocator: IAuthorityInformationAccess;

  public
    class function GetInstance(AObj: TObject): IServiceLocator; overload; static;
    /// <summary>
    /// Get instance from ASN.1 convertible.
    /// </summary>
    class function GetInstance(const AObj: IAsn1Convertible): IServiceLocator; overload; static;
    class function GetInstance(const AEncoded: TCryptoLibByteArray): IServiceLocator; overload; static;
    class function GetInstance(const AObj: IAsn1TaggedObject;
      AExplicitly: Boolean): IServiceLocator; overload; static;
    class function GetTagged(const ATaggedObject: IAsn1TaggedObject;
      ADeclaredExplicit: Boolean): IServiceLocator; static;

    constructor Create(const ASeq: IAsn1Sequence); overload;
    constructor Create(const AIssuer: IX509Name); overload;
    constructor Create(const AIssuer: IX509Name;
      const ALocator: IAuthorityInformationAccess); overload;

    function ToAsn1Object: IAsn1Object; override;

    property Issuer: IX509Name read GetIssuer;
    property Locator: IAuthorityInformationAccess read GetLocator;

  end;

implementation

{ TCertID }

class function TCertID.GetInstance(AObj: TObject): ICertID;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertID, Result) then
    Exit;

  Result := TCertID.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertID.GetInstance(const AObj: IAsn1Convertible): ICertID;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICertID, Result) then
    Exit;

  Result := TCertID.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCertID.GetInstance(const AEncoded: TCryptoLibByteArray): ICertID;
begin
  Result := TCertID.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCertID.GetInstance(const AObj: IAsn1TaggedObject; AExplicitly: Boolean): ICertID;
begin
  Result := TCertID.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TCertID.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICertID;
begin
  Result := TCertID.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCertID.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 4, 4);
  FHashAlgorithm := TAsn1Utilities.Read<IAlgorithmIdentifier>(ASeq, LPos, TAlgorithmIdentifier.GetInstance);
  FIssuerNameHash := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  FIssuerKeyHash := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  FSerialNumber := TAsn1Utilities.Read<IDerInteger>(ASeq, LPos, TDerInteger.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TCertID.Create(const AHashAlgorithm: IAlgorithmIdentifier;
  const AIssuerNameHash, AIssuerKeyHash: IAsn1OctetString; const ASerialNumber: IDerInteger);
begin
  inherited Create();
  if AHashAlgorithm = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspHashAlgorithmNil);
  if AIssuerNameHash = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspIssuerNameHashNil);
  if AIssuerKeyHash = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspIssuerKeyHashNil);
  if ASerialNumber = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspSerialNumberNil);
  FHashAlgorithm := AHashAlgorithm;
  FIssuerNameHash := AIssuerNameHash;
  FIssuerKeyHash := AIssuerKeyHash;
  FSerialNumber := ASerialNumber;
end;

function TCertID.GetHashAlgorithm: IAlgorithmIdentifier;
begin
  Result := FHashAlgorithm;
end;

function TCertID.GetIssuerNameHash: IAsn1OctetString;
begin
  Result := FIssuerNameHash;
end;

function TCertID.GetIssuerKeyHash: IAsn1OctetString;
begin
  Result := FIssuerKeyHash;
end;

function TCertID.GetSerialNumber: IDerInteger;
begin
  Result := FSerialNumber;
end;

function TCertID.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.FromElements([FHashAlgorithm as IAsn1Encodable,
    FIssuerNameHash as IAsn1Encodable, FIssuerKeyHash as IAsn1Encodable,
    FSerialNumber as IAsn1Encodable]);
end;

{ TRequest }

class function TRequest.GetInstance(AObj: TObject): IRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRequest, Result) then
    Exit;

  Result := TRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRequest.GetInstance(const AObj: IAsn1Convertible): IRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRequest, Result) then
    Exit;

  Result := TRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRequest.GetInstance(const AEncoded: TCryptoLibByteArray): IRequest;
begin
  Result := TRequest.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TRequest.GetInstance(const AObj: IAsn1TaggedObject; AExplicitly: Boolean): IRequest;
begin
  Result := TRequest.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TRequest.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRequest;
begin
  Result := TRequest.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRequest.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  FReqCert := TAsn1Utilities.Read<ICertID>(ASeq, LPos, TCertID.GetInstance);
  FSingleRequestExtensions := TAsn1Utilities.ReadOptionalContextTagged<IX509Extensions>(ASeq, LPos,
    0, True, TX509Extensions.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TRequest.Create(const AReqCert: ICertID; const ASingleRequestExtensions: IX509Extensions);
begin
  inherited Create();
  if AReqCert = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspReqCertNil);
  FReqCert := AReqCert;
  FSingleRequestExtensions := ASingleRequestExtensions;
end;

function TRequest.GetReqCert: ICertID;
begin
  Result := FReqCert;
end;

function TRequest.GetSingleRequestExtensions: IX509Extensions;
begin
  Result := FSingleRequestExtensions;
end;

function TRequest.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(2);
  LV.Add(FReqCert);
  LV.AddOptionalTagged(True, 0, FSingleRequestExtensions);
  Result := TDerSequence.Create(LV);
end;

{ TTbsRequest }

class function TTbsRequest.GetInstance(AObj: TObject): ITbsRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ITbsRequest, Result) then
    Exit;

  Result := TTbsRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TTbsRequest.GetInstance(const AObj: IAsn1Convertible): ITbsRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ITbsRequest, Result) then
    Exit;

  Result := TTbsRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TTbsRequest.GetInstance(const AEncoded: TCryptoLibByteArray): ITbsRequest;
begin
  Result := TTbsRequest.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TTbsRequest.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ITbsRequest;
begin
  Result := TTbsRequest.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TTbsRequest.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ITbsRequest;
begin
  Result := TTbsRequest.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TTbsRequest.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
  LVersion: IDerInteger;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 4);
  LVersion := TAsn1Utilities.ReadOptionalContextTagged<IDerInteger>(ASeq, LPos, 0, True,
    TDerInteger.GetTagged);
  if LVersion <> nil then
  begin
    FVersion := LVersion;
    FVersionPresent := True;
  end
  else
  begin
    FVersion := TDerInteger.Zero;
    FVersionPresent := False;
  end;
  FRequestorName := TAsn1Utilities.ReadOptionalContextTagged<IGeneralName>(ASeq, LPos, 1, True,
    TGeneralName.GetTagged);
  FRequestList := TAsn1Utilities.Read<IAsn1Sequence>(ASeq, LPos, TAsn1Sequence.GetInstance);
  FRequestExtensions := TAsn1Utilities.ReadOptionalContextTagged<IX509Extensions>(ASeq, LPos, 2,
    True, TX509Extensions.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TTbsRequest.Create(const ARequestorName: IGeneralName;
  const ARequestList: IAsn1Sequence; const ARequestExtensions: IX509Extensions);
begin
  inherited Create();
  if ARequestList = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspRequestListNil);
  FVersion := TDerInteger.Zero;
  FVersionPresent := False;
  FRequestorName := ARequestorName;
  FRequestList := ARequestList;
  FRequestExtensions := ARequestExtensions;
end;

function TTbsRequest.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TTbsRequest.GetRequestorName: IGeneralName;
begin
  Result := FRequestorName;
end;

function TTbsRequest.GetRequestList: IAsn1Sequence;
begin
  Result := FRequestList;
end;

function TTbsRequest.GetRequestExtensions: IX509Extensions;
begin
  Result := FRequestExtensions;
end;

function TTbsRequest.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);
  // emit the default version only when it was present on the wire; some requests require it
  if FVersionPresent or (not TDerInteger.Zero.Equals(FVersion)) then
    LV.Add(TDerTaggedObject.Create(True, 0, FVersion) as IDerTaggedObject);
  LV.AddOptionalTagged(True, 1, FRequestorName);
  LV.Add(FRequestList);
  LV.AddOptionalTagged(True, 2, FRequestExtensions);
  Result := TDerSequence.Create(LV);
end;

{ TSignature }

class function TSignature.GetInstance(AObj: TObject): ISignature;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISignature, Result) then
    Exit;

  Result := TSignature.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSignature.GetInstance(const AObj: IAsn1Convertible): ISignature;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISignature, Result) then
    Exit;

  Result := TSignature.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSignature.GetInstance(const AEncoded: TCryptoLibByteArray): ISignature;
begin
  Result := TSignature.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TSignature.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ISignature;
begin
  Result := TSignature.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TSignature.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISignature;
begin
  Result := TSignature.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TSignature.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 3);
  FSignatureAlgorithm := TAsn1Utilities.Read<IAlgorithmIdentifier>(ASeq, LPos,
    TAlgorithmIdentifier.GetInstance);
  FSignatureValue := TAsn1Utilities.Read<IDerBitString>(ASeq, LPos, TDerBitString.GetInstance);
  FCerts := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Sequence>(ASeq, LPos, 0, True,
    TAsn1Sequence.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TSignature.Create(const ASignatureAlgorithm: IAlgorithmIdentifier;
  const ASignatureValue: IDerBitString);
begin
  Create(ASignatureAlgorithm, ASignatureValue, nil);
end;

constructor TSignature.Create(const ASignatureAlgorithm: IAlgorithmIdentifier;
  const ASignatureValue: IDerBitString; const ACerts: IAsn1Sequence);
begin
  inherited Create();
  if ASignatureAlgorithm = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspSignatureAlgorithmNil);
  if ASignatureValue = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspSignatureValueNil);
  FSignatureAlgorithm := ASignatureAlgorithm;
  FSignatureValue := ASignatureValue;
  FCerts := ACerts;
end;

function TSignature.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSignatureAlgorithm;
end;

function TSignature.GetSignatureValue: IDerBitString;
begin
  Result := FSignatureValue;
end;

function TSignature.GetSignatureOctets: TCryptoLibByteArray;
begin
  Result := FSignatureValue.GetOctets();
end;

function TSignature.GetCerts: IAsn1Sequence;
begin
  Result := FCerts;
end;

function TSignature.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  LV.Add(FSignatureAlgorithm, FSignatureValue);
  LV.AddOptionalTagged(True, 0, FCerts);
  Result := TDerSequence.Create(LV);
end;

{ TOcspRequest }

class function TOcspRequest.GetInstance(AObj: TObject): IOcspRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOcspRequest, Result) then
    Exit;

  Result := TOcspRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOcspRequest.GetInstance(const AObj: IAsn1Convertible): IOcspRequest;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOcspRequest, Result) then
    Exit;

  Result := TOcspRequest.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOcspRequest.GetInstance(const AEncoded: TCryptoLibByteArray): IOcspRequest;
begin
  Result := TOcspRequest.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TOcspRequest.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IOcspRequest;
begin
  Result := TOcspRequest.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TOcspRequest.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IOcspRequest;
begin
  Result := TOcspRequest.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TOcspRequest.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  FTbsRequest := TAsn1Utilities.Read<ITbsRequest>(ASeq, LPos, TTbsRequest.GetInstance);
  FOptionalSignature := TAsn1Utilities.ReadOptionalContextTagged<ISignature>(ASeq, LPos, 0, True,
    TSignature.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TOcspRequest.Create(const ATbsRequest: ITbsRequest; const AOptionalSignature: ISignature);
begin
  inherited Create();
  if ATbsRequest = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspTbsRequestNil);
  FTbsRequest := ATbsRequest;
  FOptionalSignature := AOptionalSignature;
end;

function TOcspRequest.GetTbsRequest: ITbsRequest;
begin
  Result := FTbsRequest;
end;

function TOcspRequest.GetOptionalSignature: ISignature;
begin
  Result := FOptionalSignature;
end;

function TOcspRequest.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(2);
  LV.Add(FTbsRequest);
  LV.AddOptionalTagged(True, 0, FOptionalSignature);
  Result := TDerSequence.Create(LV);
end;

{ TOcspResponseStatus }

constructor TOcspResponseStatus.Create(AValue: Int32);
begin
  inherited Create(AValue);
end;

constructor TOcspResponseStatus.Create(const AValue: IDerEnumerated);
begin
  inherited Create(AValue.IntValueExact);
end;

{ TResponseBytes }

class function TResponseBytes.GetInstance(AObj: TObject): IResponseBytes;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IResponseBytes, Result) then
    Exit;

  Result := TResponseBytes.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TResponseBytes.GetInstance(const AObj: IAsn1Convertible): IResponseBytes;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IResponseBytes, Result) then
    Exit;

  Result := TResponseBytes.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TResponseBytes.GetInstance(const AEncoded: TCryptoLibByteArray): IResponseBytes;
begin
  Result := TResponseBytes.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TResponseBytes.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IResponseBytes;
begin
  Result := TResponseBytes.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TResponseBytes.GetOptional(const AElement: IAsn1Encodable): IResponseBytes;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspAsn1ElementNil);

  if Supports(AElement, IResponseBytes, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TResponseBytes.Create(LSequence)
  else
    Result := nil;
end;

class function TResponseBytes.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IResponseBytes;
begin
  Result := TResponseBytes.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TResponseBytes.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 2, 2);
  FResponseType := TAsn1Utilities.Read<IDerObjectIdentifier>(ASeq, LPos,
    TDerObjectIdentifier.GetInstance);
  FResponse := TAsn1Utilities.Read<IAsn1OctetString>(ASeq, LPos, TAsn1OctetString.GetInstance);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TResponseBytes.Create(const AResponseType: IDerObjectIdentifier;
  const AResponse: IAsn1OctetString);
begin
  inherited Create();
  if AResponseType = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponseTypeNil);
  if AResponse = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponseNil);
  FResponseType := AResponseType;
  FResponse := AResponse;
end;

function TResponseBytes.GetResponseType: IDerObjectIdentifier;
begin
  Result := FResponseType;
end;

function TResponseBytes.GetResponse: IAsn1OctetString;
begin
  Result := FResponse;
end;

function TResponseBytes.ToAsn1Object: IAsn1Object;
begin
  Result := TDerSequence.FromElements(FResponseType, FResponse);
end;

{ TOcspResponse }

class function TOcspResponse.GetInstance(AObj: TObject): IOcspResponse;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOcspResponse, Result) then
    Exit;

  Result := TOcspResponse.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOcspResponse.GetInstance(const AObj: IAsn1Convertible): IOcspResponse;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOcspResponse, Result) then
    Exit;

  Result := TOcspResponse.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TOcspResponse.GetInstance(const AEncoded: TCryptoLibByteArray): IOcspResponse;
begin
  Result := TOcspResponse.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TOcspResponse.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IOcspResponse;
begin
  Result := TOcspResponse.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TOcspResponse.GetOptional(const AElement: IAsn1Encodable): IOcspResponse;
var
  LSequence: IAsn1Sequence;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspAsn1ElementNil);

  if Supports(AElement, IOcspResponse, Result) then
    Exit;

  LSequence := TAsn1Sequence.GetOptional(AElement);
  if LSequence <> nil then
    Result := TOcspResponse.Create(LSequence)
  else
    Result := nil;
end;

class function TOcspResponse.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IOcspResponse;
begin
  Result := TOcspResponse.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TOcspResponse.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
  LStatus: IDerEnumerated;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  LStatus := TAsn1Utilities.Read<IDerEnumerated>(ASeq, LPos, TDerEnumerated.GetInstance);
  FResponseStatus := TOcspResponseStatus.Create(LStatus) as IOcspResponseStatus;
  FResponseBytes := TAsn1Utilities.ReadOptionalContextTagged<IResponseBytes>(ASeq, LPos, 0, True,
    TResponseBytes.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TOcspResponse.Create(const AResponseStatus: IOcspResponseStatus;
  const AResponseBytes: IResponseBytes);
begin
  inherited Create();
  if AResponseStatus = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponseStatusNil);
  FResponseStatus := AResponseStatus;
  FResponseBytes := AResponseBytes;
end;

function TOcspResponse.GetResponseStatus: IOcspResponseStatus;
begin
  Result := FResponseStatus;
end;

function TOcspResponse.GetResponseBytes: IResponseBytes;
begin
  Result := FResponseBytes;
end;

function TOcspResponse.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(2);
  LV.Add(FResponseStatus);
  LV.AddOptionalTagged(True, 0, FResponseBytes);
  Result := TDerSequence.Create(LV);
end;

{ TResponderID }

class function TResponderID.ChoiceGetOptional(AElement: IAsn1Encodable): IResponderID;
begin
  Result := GetOptional(AElement);
end;

class function TResponderID.ChoiceGetInstance(AElement: IAsn1Encodable): IResponderID;
begin
  Result := GetInstance(AElement);
end;

class function TResponderID.GetInstance(AObj: TObject): IResponderID;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IResponderID>(AObj, ChoiceGetOptional);
end;

class function TResponderID.GetInstance(const AObj: IAsn1Convertible): IResponderID;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IResponderID, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<IResponderID>(AObj.ToAsn1Object(), ChoiceGetOptional);
end;

class function TResponderID.GetInstance(const AEncoded: TCryptoLibByteArray): IResponderID;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IResponderID>(AEncoded, ChoiceGetOptional);
end;

class function TResponderID.GetInstance(const AObj: IAsn1TaggedObject;
  AIsExplicit: Boolean): IResponderID;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IResponderID>(AObj, AIsExplicit, ChoiceGetInstance);
end;

class function TResponderID.GetOptional(const AElement: IAsn1Encodable): IResponderID;
var
  LTaggedObject: IAsn1TaggedObject;
  LOctetString: IAsn1OctetString;
  LByName: IX509Name;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspAsn1ElementNil);

  if Supports(AElement, IResponderID, Result) then
    Exit;

  LTaggedObject := TAsn1TaggedObject.GetOptional(AElement);
  if LTaggedObject <> nil then
  begin
    if LTaggedObject.HasContextTag(1) then
    begin
      Result := TResponderID.Create(TX509Name.GetTagged(LTaggedObject, True));
      Exit;
    end;

    if LTaggedObject.HasContextTag(2) then
    begin
      Result := TResponderID.Create(TAsn1OctetString.GetTagged(LTaggedObject, True));
      Exit;
    end;
  end;

  if Supports(AElement, IAsn1OctetString, LOctetString) then
  begin
    Result := TResponderID.Create(LOctetString);
    Exit;
  end;

  LByName := TX509Name.GetOptional(AElement);
  if LByName <> nil then
  begin
    Result := TResponderID.Create(LByName);
    Exit;
  end;

  Result := nil;
end;

class function TResponderID.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IResponderID;
begin
  Result := TAsn1Utilities.GetTaggedChoice<IResponderID>(ATaggedObject, ADeclaredExplicit,
    ChoiceGetInstance);
end;

constructor TResponderID.Create(const AId: IAsn1OctetString);
begin
  inherited Create();
  if AId = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponderIDNil);
  FId := AId;
end;

constructor TResponderID.Create(const AId: IX509Name);
begin
  inherited Create();
  if AId = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponderIDNil);
  FId := AId;
end;

function TResponderID.GetKeyHash: TCryptoLibByteArray;
var
  LOctetString: IAsn1OctetString;
begin
  if Supports(FId, IAsn1OctetString, LOctetString) then
    Result := LOctetString.GetOctets()
  else
    Result := nil;
end;

function TResponderID.GetName: IX509Name;
begin
  if Supports(FId, IAsn1OctetString) then
    Result := nil
  else
    Result := TX509Name.GetInstance(FId);
end;

function TResponderID.ToAsn1Object: IAsn1Object;
var
  LOctetString: IAsn1OctetString;
begin
  if Supports(FId, IAsn1OctetString, LOctetString) then
    Result := TDerTaggedObject.Create(True, 2, LOctetString)
  else
    Result := TDerTaggedObject.Create(True, 1, FId);
end;

{ TRevokedInfo }

class function TRevokedInfo.GetTaggedCrlReason(const ATagged: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICrlReason;
begin
  Result := TCrlReason.Create(TDerEnumerated.GetTagged(ATagged, ADeclaredExplicit)) as ICrlReason;
end;

class function TRevokedInfo.GetInstance(AObj: TObject): IRevokedInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRevokedInfo, Result) then
    Exit;

  Result := TRevokedInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRevokedInfo.GetInstance(const AObj: IAsn1Convertible): IRevokedInfo;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IRevokedInfo, Result) then
    Exit;

  Result := TRevokedInfo.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TRevokedInfo.GetInstance(const AEncoded: TCryptoLibByteArray): IRevokedInfo;
begin
  Result := TRevokedInfo.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TRevokedInfo.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IRevokedInfo;
begin
  Result := TRevokedInfo.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TRevokedInfo.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IRevokedInfo;
begin
  Result := TRevokedInfo.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TRevokedInfo.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  FRevocationTime := TAsn1Utilities.Read<IAsn1GeneralizedTime>(ASeq, LPos,
    TAsn1GeneralizedTime.GetInstance);
  FRevocationReason := TAsn1Utilities.ReadOptionalContextTagged<ICrlReason>(ASeq, LPos, 0, True,
    GetTaggedCrlReason);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TRevokedInfo.Create(const ARevocationTime: IAsn1GeneralizedTime);
begin
  Create(ARevocationTime, nil);
end;

constructor TRevokedInfo.Create(const ARevocationTime: IAsn1GeneralizedTime;
  const ARevocationReason: ICrlReason);
begin
  inherited Create();
  if ARevocationTime = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspRevocationTimeNil);
  FRevocationTime := ARevocationTime;
  FRevocationReason := ARevocationReason;
end;

function TRevokedInfo.GetRevocationTime: IAsn1GeneralizedTime;
begin
  Result := FRevocationTime;
end;

function TRevokedInfo.GetRevocationReason: ICrlReason;
begin
  Result := FRevocationReason;
end;

function TRevokedInfo.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(2);
  LV.Add(FRevocationTime);
  LV.AddOptionalTagged(True, 0, FRevocationReason);
  Result := TDerSequence.Create(LV);
end;

{ TOcspCertStatus }

class function TOcspCertStatus.ChoiceGetOptional(AElement: IAsn1Encodable): IOcspCertStatus;
begin
  Result := GetOptional(AElement);
end;

class function TOcspCertStatus.ChoiceGetInstance(AElement: IAsn1Encodable): IOcspCertStatus;
begin
  Result := GetInstance(AElement);
end;

class function TOcspCertStatus.GetOptionalBaseObject(const ATaggedObject: IAsn1TaggedObject): IAsn1Encodable;
begin
  if ATaggedObject.HasContextTag() then
  begin
    case ATaggedObject.TagNo of
      Good:
        Result := TAsn1Null.GetTagged(ATaggedObject, False);
      Revoked:
        Result := TRevokedInfo.GetTagged(ATaggedObject, False);
      Unknown:
        Result := TAsn1Null.GetTagged(ATaggedObject, False);
    else
      Result := nil;
    end;
  end
  else
    Result := nil;
end;

class function TOcspCertStatus.GetInstance(AObj: TObject): IOcspCertStatus;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IOcspCertStatus>(AObj, ChoiceGetOptional);
end;

class function TOcspCertStatus.GetInstance(const AObj: IAsn1Convertible): IOcspCertStatus;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IOcspCertStatus, Result) then
    Exit;

  Result := TAsn1Utilities.GetInstanceChoice<IOcspCertStatus>(AObj.ToAsn1Object(), ChoiceGetOptional);
end;

class function TOcspCertStatus.GetInstance(const AEncoded: TCryptoLibByteArray): IOcspCertStatus;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IOcspCertStatus>(AEncoded, ChoiceGetOptional);
end;

class function TOcspCertStatus.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IOcspCertStatus;
begin
  Result := TAsn1Utilities.GetInstanceChoice<IOcspCertStatus>(AObj, ADeclaredExplicit,
    ChoiceGetInstance);
end;

class function TOcspCertStatus.GetOptional(const AElement: IAsn1Encodable): IOcspCertStatus;
var
  LTaggedObject: IAsn1TaggedObject;
  LBaseObject: IAsn1Encodable;
begin
  if AElement = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspAsn1ElementNil);

  if Supports(AElement, IOcspCertStatus, Result) then
    Exit;

  LTaggedObject := TAsn1TaggedObject.GetOptional(AElement);
  if LTaggedObject <> nil then
  begin
    LBaseObject := GetOptionalBaseObject(LTaggedObject);
    if LBaseObject <> nil then
    begin
      Result := TOcspCertStatus.Create(LTaggedObject.TagNo, LBaseObject);
      Exit;
    end;
  end;

  Result := nil;
end;

class function TOcspCertStatus.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IOcspCertStatus;
begin
  Result := TAsn1Utilities.GetTaggedChoice<IOcspCertStatus>(ATaggedObject, ADeclaredExplicit,
    ChoiceGetInstance);
end;

constructor TOcspCertStatus.Create;
begin
  inherited Create();
  FTagNo := Good;
  FValue := TDerNull.Instance;
end;

constructor TOcspCertStatus.Create(const AInfo: IRevokedInfo);
begin
  inherited Create();
  if AInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspStatusValueNil);
  FTagNo := Revoked;
  FValue := AInfo;
end;

constructor TOcspCertStatus.Create(ATagNo: Int32; const AValue: IAsn1Encodable);
begin
  inherited Create();
  if AValue = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspStatusValueNil);
  FTagNo := ATagNo;
  FValue := AValue;
end;

constructor TOcspCertStatus.Create(const AChoice: IAsn1TaggedObject);
var
  LBaseObject: IAsn1Encodable;
begin
  inherited Create();
  LBaseObject := GetOptionalBaseObject(AChoice);
  if LBaseObject = nil then
    raise EArgumentCryptoLibException.CreateResFmt(@SOcspUnknownTag,
      [TAsn1Utilities.GetTagText(AChoice)]);
  FTagNo := AChoice.TagNo;
  FValue := LBaseObject;
end;

function TOcspCertStatus.GetTagNo: Int32;
begin
  Result := FTagNo;
end;

function TOcspCertStatus.GetStatus: IAsn1Encodable;
begin
  Result := FValue;
end;

function TOcspCertStatus.ToAsn1Object: IAsn1Object;
begin
  Result := TDerTaggedObject.Create(False, FTagNo, FValue);
end;

{ TSingleResponse }

class function TSingleResponse.GetInstance(AObj: TObject): ISingleResponse;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISingleResponse, Result) then
    Exit;

  Result := TSingleResponse.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSingleResponse.GetInstance(const AObj: IAsn1Convertible): ISingleResponse;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ISingleResponse, Result) then
    Exit;

  Result := TSingleResponse.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TSingleResponse.GetInstance(const AEncoded: TCryptoLibByteArray): ISingleResponse;
begin
  Result := TSingleResponse.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TSingleResponse.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): ISingleResponse;
begin
  Result := TSingleResponse.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TSingleResponse.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ISingleResponse;
begin
  Result := TSingleResponse.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TSingleResponse.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 3, 5);
  FCertID := TAsn1Utilities.Read<ICertID>(ASeq, LPos, TCertID.GetInstance);
  FCertStatus := TAsn1Utilities.Read<IOcspCertStatus>(ASeq, LPos, TOcspCertStatus.GetInstance);
  FThisUpdate := TAsn1Utilities.Read<IAsn1GeneralizedTime>(ASeq, LPos,
    TAsn1GeneralizedTime.GetInstance);
  FNextUpdate := TAsn1Utilities.ReadOptionalContextTagged<IAsn1GeneralizedTime>(ASeq, LPos, 0, True,
    TAsn1GeneralizedTime.GetTagged);
  FSingleExtensions := TAsn1Utilities.ReadOptionalContextTagged<IX509Extensions>(ASeq, LPos, 1,
    True, TX509Extensions.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TSingleResponse.Create(const ACertID: ICertID; const ACertStatus: IOcspCertStatus;
  const AThisUpdate, ANextUpdate: IAsn1GeneralizedTime; const ASingleExtensions: IX509Extensions);
begin
  inherited Create();
  if ACertID = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspReqCertNil);
  if ACertStatus = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspCertStatusNil);
  if AThisUpdate = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspThisUpdateNil);
  FCertID := ACertID;
  FCertStatus := ACertStatus;
  FThisUpdate := AThisUpdate;
  FNextUpdate := ANextUpdate;
  FSingleExtensions := ASingleExtensions;
end;

function TSingleResponse.GetCertId: ICertID;
begin
  Result := FCertID;
end;

function TSingleResponse.GetCertStatus: IOcspCertStatus;
begin
  Result := FCertStatus;
end;

function TSingleResponse.GetThisUpdate: IAsn1GeneralizedTime;
begin
  Result := FThisUpdate;
end;

function TSingleResponse.GetNextUpdate: IAsn1GeneralizedTime;
begin
  Result := FNextUpdate;
end;

function TSingleResponse.GetSingleExtensions: IX509Extensions;
begin
  Result := FSingleExtensions;
end;

function TSingleResponse.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(5);
  LV.Add(FCertID);
  LV.Add(FCertStatus);
  LV.Add(FThisUpdate);
  LV.AddOptionalTagged(True, 0, FNextUpdate);
  LV.AddOptionalTagged(True, 1, FSingleExtensions);
  Result := TDerSequence.Create(LV);
end;

{ TResponseData }

class function TResponseData.GetInstance(AObj: TObject): IResponseData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IResponseData, Result) then
    Exit;

  Result := TResponseData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TResponseData.GetInstance(const AObj: IAsn1Convertible): IResponseData;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IResponseData, Result) then
    Exit;

  Result := TResponseData.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TResponseData.GetInstance(const AEncoded: TCryptoLibByteArray): IResponseData;
begin
  Result := TResponseData.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TResponseData.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IResponseData;
begin
  Result := TResponseData.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TResponseData.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IResponseData;
begin
  Result := TResponseData.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TResponseData.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
  LVersion: IDerInteger;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 3, 5);
  LVersion := TAsn1Utilities.ReadOptionalContextTagged<IDerInteger>(ASeq, LPos, 0, True,
    TDerInteger.GetTagged);
  if LVersion <> nil then
  begin
    FVersion := LVersion;
    FVersionPresent := True;
  end
  else
  begin
    FVersion := TDerInteger.Zero;
    FVersionPresent := False;
  end;
  FResponderID := TAsn1Utilities.Read<IResponderID>(ASeq, LPos, TResponderID.GetInstance);
  FProducedAt := TAsn1Utilities.Read<IAsn1GeneralizedTime>(ASeq, LPos,
    TAsn1GeneralizedTime.GetInstance);
  FResponses := TAsn1Utilities.Read<IAsn1Sequence>(ASeq, LPos, TAsn1Sequence.GetInstance);
  FResponseExtensions := TAsn1Utilities.ReadOptionalContextTagged<IX509Extensions>(ASeq, LPos, 1,
    True, TX509Extensions.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TResponseData.Create(const AResponderID: IResponderID;
  const AProducedAt: IAsn1GeneralizedTime; const AResponses: IAsn1Sequence;
  const AResponseExtensions: IX509Extensions);
begin
  Create(TDerInteger.Zero, AResponderID, AProducedAt, AResponses, AResponseExtensions);
end;

constructor TResponseData.Create(const AVersion: IDerInteger; const AResponderID: IResponderID;
  const AProducedAt: IAsn1GeneralizedTime; const AResponses: IAsn1Sequence;
  const AResponseExtensions: IX509Extensions);
begin
  inherited Create();
  if AResponderID = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponderIDNil);
  if AProducedAt = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspProducedAtNil);
  if AResponses = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponsesNil);
  if AVersion <> nil then
    FVersion := AVersion
  else
    FVersion := TDerInteger.Zero;
  FVersionPresent := False;
  FResponderID := AResponderID;
  FProducedAt := AProducedAt;
  FResponses := AResponses;
  FResponseExtensions := AResponseExtensions;
end;

function TResponseData.GetVersion: IDerInteger;
begin
  Result := FVersion;
end;

function TResponseData.GetResponderID: IResponderID;
begin
  Result := FResponderID;
end;

function TResponseData.GetProducedAt: IAsn1GeneralizedTime;
begin
  Result := FProducedAt;
end;

function TResponseData.GetResponses: IAsn1Sequence;
begin
  Result := FResponses;
end;

function TResponseData.GetResponseExtensions: IX509Extensions;
begin
  Result := FResponseExtensions;
end;

function TResponseData.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(5);
  if FVersionPresent or (not TDerInteger.Zero.Equals(FVersion)) then
    LV.Add(TDerTaggedObject.Create(True, 0, FVersion) as IDerTaggedObject);
  LV.Add(FResponderID);
  LV.Add(FProducedAt);
  LV.Add(FResponses);
  LV.AddOptionalTagged(True, 1, FResponseExtensions);
  Result := TDerSequence.Create(LV);
end;

{ TBasicOcspResponse }

class function TBasicOcspResponse.GetInstance(AObj: TObject): IBasicOcspResponse;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IBasicOcspResponse, Result) then
    Exit;

  Result := TBasicOcspResponse.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TBasicOcspResponse.GetInstance(const AObj: IAsn1Convertible): IBasicOcspResponse;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IBasicOcspResponse, Result) then
    Exit;

  Result := TBasicOcspResponse.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TBasicOcspResponse.GetInstance(const AEncoded: TCryptoLibByteArray): IBasicOcspResponse;
begin
  Result := TBasicOcspResponse.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TBasicOcspResponse.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IBasicOcspResponse;
begin
  Result := TBasicOcspResponse.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TBasicOcspResponse.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IBasicOcspResponse;
begin
  Result := TBasicOcspResponse.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TBasicOcspResponse.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 3, 4);
  FTbsResponseData := TAsn1Utilities.Read<IResponseData>(ASeq, LPos, TResponseData.GetInstance);
  FSignatureAlgorithm := TAsn1Utilities.Read<IAlgorithmIdentifier>(ASeq, LPos,
    TAlgorithmIdentifier.GetInstance);
  FSignature := TAsn1Utilities.Read<IDerBitString>(ASeq, LPos, TDerBitString.GetInstance);
  FCerts := TAsn1Utilities.ReadOptionalContextTagged<IAsn1Sequence>(ASeq, LPos, 0, True,
    TAsn1Sequence.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TBasicOcspResponse.Create(const ATbsResponseData: IResponseData;
  const ASignatureAlgorithm: IAlgorithmIdentifier; const ASignature: IDerBitString;
  const ACerts: IAsn1Sequence);
begin
  inherited Create();
  if ATbsResponseData = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspTbsResponseDataNil);
  if ASignatureAlgorithm = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspSignatureAlgorithmNil);
  if ASignature = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspSignatureValueNil);
  FTbsResponseData := ATbsResponseData;
  FSignatureAlgorithm := ASignatureAlgorithm;
  FSignature := ASignature;
  FCerts := ACerts;
end;

function TBasicOcspResponse.GetTbsResponseData: IResponseData;
begin
  Result := FTbsResponseData;
end;

function TBasicOcspResponse.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FSignatureAlgorithm;
end;

function TBasicOcspResponse.GetSignature: IDerBitString;
begin
  Result := FSignature;
end;

function TBasicOcspResponse.GetSignatureOctets: TCryptoLibByteArray;
begin
  Result := FSignature.GetOctets();
end;

function TBasicOcspResponse.GetCerts: IAsn1Sequence;
begin
  Result := FCerts;
end;

function TBasicOcspResponse.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(4);
  LV.Add(FTbsResponseData);
  LV.Add(FSignatureAlgorithm);
  LV.Add(FSignature);
  LV.AddOptionalTagged(True, 0, FCerts);
  Result := TDerSequence.Create(LV);
end;

{ TCrlID }

class function TCrlID.GetInstance(AObj: TObject): ICrlID;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICrlID, Result) then
    Exit;

  Result := TCrlID.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCrlID.GetInstance(const AObj: IAsn1Convertible): ICrlID;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, ICrlID, Result) then
    Exit;

  Result := TCrlID.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TCrlID.GetInstance(const AEncoded: TCryptoLibByteArray): ICrlID;
begin
  Result := TCrlID.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TCrlID.GetInstance(const AObj: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICrlID;
begin
  Result := TCrlID.Create(TAsn1Sequence.GetInstance(AObj, ADeclaredExplicit));
end;

class function TCrlID.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): ICrlID;
begin
  Result := TCrlID.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TCrlID.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 0, 3);
  FCrlUrl := TAsn1Utilities.ReadOptionalContextTagged<IDerIA5String>(ASeq, LPos, 0, True,
    TDerIA5String.GetTagged);
  FCrlNum := TAsn1Utilities.ReadOptionalContextTagged<IDerInteger>(ASeq, LPos, 1, True,
    TDerInteger.GetTagged);
  FCrlTime := TAsn1Utilities.ReadOptionalContextTagged<IAsn1GeneralizedTime>(ASeq, LPos, 2, True,
    TAsn1GeneralizedTime.GetTagged);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

function TCrlID.GetCrlUrl: IDerIA5String;
begin
  Result := FCrlUrl;
end;

function TCrlID.GetCrlNum: IDerInteger;
begin
  Result := FCrlNum;
end;

function TCrlID.GetCrlTime: IAsn1GeneralizedTime;
begin
  Result := FCrlTime;
end;

function TCrlID.ToAsn1Object: IAsn1Object;
var
  LV: IAsn1EncodableVector;
begin
  LV := TAsn1EncodableVector.Create(3);
  LV.AddOptionalTagged(True, 0, FCrlUrl);
  LV.AddOptionalTagged(True, 1, FCrlNum);
  LV.AddOptionalTagged(True, 2, FCrlTime);
  Result := TDerSequence.Create(LV);
end;

{ TServiceLocator }

class function TServiceLocator.GetInstance(AObj: TObject): IServiceLocator;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IServiceLocator, Result) then
    Exit;

  Result := TServiceLocator.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TServiceLocator.GetInstance(const AObj: IAsn1Convertible): IServiceLocator;
begin
  if AObj = nil then
  begin
    Result := nil;
    Exit;
  end;

  if Supports(AObj, IServiceLocator, Result) then
    Exit;

  Result := TServiceLocator.Create(TAsn1Sequence.GetInstance(AObj));
end;

class function TServiceLocator.GetInstance(const AEncoded: TCryptoLibByteArray): IServiceLocator;
begin
  Result := TServiceLocator.Create(TAsn1Sequence.GetInstance(AEncoded));
end;

class function TServiceLocator.GetInstance(const AObj: IAsn1TaggedObject;
  AExplicitly: Boolean): IServiceLocator;
begin
  Result := TServiceLocator.Create(TAsn1Sequence.GetInstance(AObj, AExplicitly));
end;

class function TServiceLocator.GetTagged(const ATaggedObject: IAsn1TaggedObject;
  ADeclaredExplicit: Boolean): IServiceLocator;
begin
  Result := TServiceLocator.Create(TAsn1Sequence.GetTagged(ATaggedObject, ADeclaredExplicit));
end;

constructor TServiceLocator.Create(const ASeq: IAsn1Sequence);
var
  LPos: Int32;
begin
  inherited Create();
  LPos := 0;
  TAsn1Utilities.CheckSequenceSize(ASeq, 1, 2);
  FIssuer := TAsn1Utilities.Read<IX509Name>(ASeq, LPos, TX509Name.GetInstance);
  FLocator := TAsn1Utilities.ReadOptional<IAuthorityInformationAccess>(ASeq, LPos,
    TAuthorityInformationAccess.GetOptional);
  TAsn1Utilities.RequireEndOfSequence(ASeq, LPos);
end;

constructor TServiceLocator.Create(const AIssuer: IX509Name);
begin
  Create(AIssuer, nil);
end;

constructor TServiceLocator.Create(const AIssuer: IX509Name;
  const ALocator: IAuthorityInformationAccess);
begin
  inherited Create();
  if AIssuer = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspIssuerNil);
  FIssuer := AIssuer;
  FLocator := ALocator;
end;

function TServiceLocator.GetIssuer: IX509Name;
begin
  Result := FIssuer;
end;

function TServiceLocator.GetLocator: IAuthorityInformationAccess;
begin
  Result := FLocator;
end;

function TServiceLocator.ToAsn1Object: IAsn1Object;
begin
  if FLocator = nil then
    Result := TDerSequence.FromElement(FIssuer)
  else
    Result := TDerSequence.FromElements(FIssuer, FLocator);
end;

end.
