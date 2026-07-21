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

unit ClpIOcspAsn1Objects;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpIX509Asn1Objects,
  ClpCryptoLibTypes;

type
  // Forward declarations
  IOcspRequest = interface;
  ITbsRequest = interface;
  IRequest = interface;
  ISignature = interface;
  IOcspResponse = interface;
  IOcspResponseStatus = interface;
  IResponseBytes = interface;
  IBasicOcspResponse = interface;
  IResponseData = interface;
  IResponderID = interface;
  ISingleResponse = interface;
  ICertID = interface;
  IOcspCertStatus = interface;
  IRevokedInfo = interface;
  ICrlID = interface;
  IServiceLocator = interface;

  /// <summary>
  /// Interface for CertID (RFC 6960 sec. 4.1.1).
  /// <code>
  /// CertID ::= SEQUENCE {
  ///   hashAlgorithm  AlgorithmIdentifier,
  ///   issuerNameHash OCTET STRING,
  ///   issuerKeyHash  OCTET STRING,
  ///   serialNumber   CertificateSerialNumber
  /// }
  /// </code>
  /// </summary>
  ICertID = interface(IAsn1Encodable)
    ['{2B7C4E10-9D53-4F81-A0C6-3E58D1F4A907}']

    function GetHashAlgorithm: IAlgorithmIdentifier;
    function GetIssuerNameHash: IAsn1OctetString;
    function GetIssuerKeyHash: IAsn1OctetString;
    function GetSerialNumber: IDerInteger;

    property HashAlgorithm: IAlgorithmIdentifier read GetHashAlgorithm;
    property IssuerNameHash: IAsn1OctetString read GetIssuerNameHash;
    property IssuerKeyHash: IAsn1OctetString read GetIssuerKeyHash;
    property SerialNumber: IDerInteger read GetSerialNumber;
  end;

  /// <summary>
  /// Interface for the OCSP Request entry of a request list (RFC 6960 sec. 4.1.1).
  /// <code>
  /// Request ::= SEQUENCE {
  ///   reqCert                 CertID,
  ///   singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IRequest = interface(IAsn1Encodable)
    ['{5F91A3C2-6E4D-4B07-8A19-C7D20B5E4F3A}']

    function GetReqCert: ICertID;
    function GetSingleRequestExtensions: IX509Extensions;

    property ReqCert: ICertID read GetReqCert;
    property SingleRequestExtensions: IX509Extensions read GetSingleRequestExtensions;
  end;

  /// <summary>
  /// Interface for TBSRequest (RFC 6960 sec. 4.1.1).
  /// <code>
  /// TBSRequest ::= SEQUENCE {
  ///   version           [0] EXPLICIT Version DEFAULT v1,
  ///   requestorName     [1] EXPLICIT GeneralName OPTIONAL,
  ///   requestList           SEQUENCE OF Request,
  ///   requestExtensions [2] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </summary>
  ITbsRequest = interface(IAsn1Encodable)
    ['{9C40D7B5-1A2E-4E63-B5F8-70D4C6A83E19}']

    function GetVersion: IDerInteger;
    function GetRequestorName: IGeneralName;
    function GetRequestList: IAsn1Sequence;
    function GetRequestExtensions: IX509Extensions;

    property Version: IDerInteger read GetVersion;
    property RequestorName: IGeneralName read GetRequestorName;
    property RequestList: IAsn1Sequence read GetRequestList;
    property RequestExtensions: IX509Extensions read GetRequestExtensions;
  end;

  /// <summary>
  /// Interface for the OCSP request Signature (RFC 6960 sec. 4.1.1).
  /// <code>
  /// Signature ::= SEQUENCE {
  ///   signatureAlgorithm AlgorithmIdentifier,
  ///   signature          BIT STRING,
  ///   certs              [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
  /// }
  /// </code>
  /// </summary>
  ISignature = interface(IAsn1Encodable)
    ['{A17B5D93-4C08-42EF-9B36-D5E1470A9C82}']

    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignatureValue: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;
    function GetCerts: IAsn1Sequence;

    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SignatureValue: IDerBitString read GetSignatureValue;
    property Certs: IAsn1Sequence read GetCerts;
  end;

  /// <summary>
  /// Interface for OCSPRequest (RFC 6960 sec. 4.1.1).
  /// <code>
  /// OCSPRequest ::= SEQUENCE {
  ///   tbsRequest            TBSRequest,
  ///   optionalSignature [0] EXPLICIT Signature OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IOcspRequest = interface(IAsn1Encodable)
    ['{3D6E82F1-0B54-4A9C-8127-EF5A9D3C6014}']

    function GetTbsRequest: ITbsRequest;
    function GetOptionalSignature: ISignature;

    property TbsRequest: ITbsRequest read GetTbsRequest;
    property OptionalSignature: ISignature read GetOptionalSignature;
  end;

  /// <summary>
  /// Interface for OCSPResponseStatus (RFC 6960 sec. 4.2.1).
  /// <code>
  /// OCSPResponseStatus ::= ENUMERATED {
  ///   successful       (0),
  ///   malformedRequest (1),
  ///   internalError    (2),
  ///   tryLater         (3),
  ///   sigRequired      (5),
  ///   unauthorized     (6)
  /// }
  /// </code>
  /// </summary>
  IOcspResponseStatus = interface(IDerEnumerated)
    ['{74C1B9E0-5A38-4D26-B0F7-1C93E6820D4B}']
  end;

  /// <summary>
  /// Interface for ResponseBytes (RFC 6960 sec. 4.2.1).
  /// <code>
  /// ResponseBytes ::= SEQUENCE {
  ///   responseType OBJECT IDENTIFIER,
  ///   response     OCTET STRING
  /// }
  /// </code>
  /// </summary>
  IResponseBytes = interface(IAsn1Encodable)
    ['{E05A93C7-2148-4B6D-9F30-8A7C41E5B296}']

    function GetResponseType: IDerObjectIdentifier;
    function GetResponse: IAsn1OctetString;

    property ResponseType: IDerObjectIdentifier read GetResponseType;
    property Response: IAsn1OctetString read GetResponse;
  end;

  /// <summary>
  /// Interface for OCSPResponse (RFC 6960 sec. 4.2.1).
  /// <code>
  /// OCSPResponse ::= SEQUENCE {
  ///   responseStatus     OCSPResponseStatus,
  ///   responseBytes  [0] EXPLICIT ResponseBytes OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IOcspResponse = interface(IAsn1Encodable)
    ['{B8271F4A-6D95-4E30-A1C8-0F3E7B9D5264}']

    function GetResponseStatus: IOcspResponseStatus;
    function GetResponseBytes: IResponseBytes;

    property ResponseStatus: IOcspResponseStatus read GetResponseStatus;
    property ResponseBytes: IResponseBytes read GetResponseBytes;
  end;

  /// <summary>
  /// Interface for ResponderID (RFC 6960 sec. 4.2.1).
  /// <code>
  /// ResponderID ::= CHOICE {
  ///   byName [1] Name,
  ///   byKey  [2] KeyHash
  /// }
  /// </code>
  /// </summary>
  IResponderID = interface(IAsn1Encodable)
    ['{C6934E01-7B52-48AF-92D6-4E10B85C3F7D}']

    function GetKeyHash: TCryptoLibByteArray;
    function GetName: IX509Name;

    property Name: IX509Name read GetName;
  end;

  /// <summary>
  /// Interface for RevokedInfo (RFC 6960 sec. 4.2.1).
  /// <code>
  /// RevokedInfo ::= SEQUENCE {
  ///   revocationTime       GeneralizedTime,
  ///   revocationReason [0] EXPLICIT CRLReason OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IRevokedInfo = interface(IAsn1Encodable)
    ['{1E7D6B0C-95A4-4238-8F51-72C0D4E9A36B}']

    function GetRevocationTime: IAsn1GeneralizedTime;
    function GetRevocationReason: ICrlReason;

    property RevocationTime: IAsn1GeneralizedTime read GetRevocationTime;
    property RevocationReason: ICrlReason read GetRevocationReason;
  end;

  /// <summary>
  /// Interface for the OCSP CertStatus CHOICE (RFC 6960 sec. 4.2.1). Named with an
  /// Ocsp prefix to avoid a clash with the PKIX revocation-status holder.
  /// <code>
  /// CertStatus ::= CHOICE {
  ///   good    [0] IMPLICIT NULL,
  ///   revoked [1] IMPLICIT RevokedInfo,
  ///   unknown [2] IMPLICIT UnknownInfo
  /// }
  /// </code>
  /// </summary>
  IOcspCertStatus = interface(IAsn1Encodable)
    ['{4A08E5D3-B71C-4629-90FE-8D25C3B7146F}']

    function GetTagNo: Int32;
    function GetStatus: IAsn1Encodable;

    property TagNo: Int32 read GetTagNo;
    property Status: IAsn1Encodable read GetStatus;
  end;

  /// <summary>
  /// Interface for SingleResponse (RFC 6960 sec. 4.2.1).
  /// <code>
  /// SingleResponse ::= SEQUENCE {
  ///   certID               CertID,
  ///   certStatus           CertStatus,
  ///   thisUpdate           GeneralizedTime,
  ///   nextUpdate       [0] EXPLICIT GeneralizedTime OPTIONAL,
  ///   singleExtensions [1] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </summary>
  ISingleResponse = interface(IAsn1Encodable)
    ['{7F2C48B6-E039-4D15-A8B7-52901C6ED3A4}']

    function GetCertId: ICertID;
    function GetCertStatus: IOcspCertStatus;
    function GetThisUpdate: IAsn1GeneralizedTime;
    function GetNextUpdate: IAsn1GeneralizedTime;
    function GetSingleExtensions: IX509Extensions;

    property CertId: ICertID read GetCertId;
    property CertStatus: IOcspCertStatus read GetCertStatus;
    property ThisUpdate: IAsn1GeneralizedTime read GetThisUpdate;
    property NextUpdate: IAsn1GeneralizedTime read GetNextUpdate;
    property SingleExtensions: IX509Extensions read GetSingleExtensions;
  end;

  /// <summary>
  /// Interface for ResponseData (RFC 6960 sec. 4.2.1).
  /// <code>
  /// ResponseData ::= SEQUENCE {
  ///   version            [0] EXPLICIT Version DEFAULT v1,
  ///   responderID            ResponderID,
  ///   producedAt             GeneralizedTime,
  ///   responses              SEQUENCE OF SingleResponse,
  ///   responseExtensions [1] EXPLICIT Extensions OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IResponseData = interface(IAsn1Encodable)
    ['{D3610FA8-4C97-4B2E-85D0-6E1B79C34285}']

    function GetVersion: IDerInteger;
    function GetResponderID: IResponderID;
    function GetProducedAt: IAsn1GeneralizedTime;
    function GetResponses: IAsn1Sequence;
    function GetResponseExtensions: IX509Extensions;

    property Version: IDerInteger read GetVersion;
    property ResponderID: IResponderID read GetResponderID;
    property ProducedAt: IAsn1GeneralizedTime read GetProducedAt;
    property Responses: IAsn1Sequence read GetResponses;
    property ResponseExtensions: IX509Extensions read GetResponseExtensions;
  end;

  /// <summary>
  /// Interface for BasicOCSPResponse (RFC 6960 sec. 4.2.1).
  /// <code>
  /// BasicOCSPResponse ::= SEQUENCE {
  ///   tbsResponseData    ResponseData,
  ///   signatureAlgorithm AlgorithmIdentifier,
  ///   signature          BIT STRING,
  ///   certs          [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IBasicOcspResponse = interface(IAsn1Encodable)
    ['{0F5D8B27-A346-41C9-B7E0-93412D6A85CF}']

    function GetTbsResponseData: IResponseData;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignature: IDerBitString;
    function GetSignatureOctets: TCryptoLibByteArray;
    function GetCerts: IAsn1Sequence;

    property TbsResponseData: IResponseData read GetTbsResponseData;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property Signature: IDerBitString read GetSignature;
    property Certs: IAsn1Sequence read GetCerts;
  end;

  /// <summary>
  /// Interface for CrlID, the value of the id-pkix-ocsp-crl extension (RFC 6960 sec. 4.4.2).
  /// <code>
  /// CrlID ::= SEQUENCE {
  ///   crlUrl  [0] EXPLICIT IA5String OPTIONAL,
  ///   crlNum  [1] EXPLICIT INTEGER OPTIONAL,
  ///   crlTime [2] EXPLICIT GeneralizedTime OPTIONAL
  /// }
  /// </code>
  /// </summary>
  ICrlID = interface(IAsn1Encodable)
    ['{8E43C905-2D7F-4A18-B36C-F0159E4D7B82}']

    function GetCrlUrl: IDerIA5String;
    function GetCrlNum: IDerInteger;
    function GetCrlTime: IAsn1GeneralizedTime;

    property CrlUrl: IDerIA5String read GetCrlUrl;
    property CrlNum: IDerInteger read GetCrlNum;
    property CrlTime: IAsn1GeneralizedTime read GetCrlTime;
  end;

  /// <summary>
  /// Interface for ServiceLocator, the value of the id-pkix-ocsp-service-locator
  /// extension (RFC 6960 sec. 4.4.6).
  /// <code>
  /// ServiceLocator ::= SEQUENCE {
  ///   issuer  Name,
  ///   locator AuthorityInfoAccessSyntax OPTIONAL
  /// }
  /// </code>
  /// </summary>
  IServiceLocator = interface(IAsn1Encodable)
    ['{6C21B7E4-903A-4F58-8D14-27EB0A9C563D}']

    function GetIssuer: IX509Name;
    function GetLocator: IAuthorityInformationAccess;

    property Issuer: IX509Name read GetIssuer;
    property Locator: IAuthorityInformationAccess read GetLocator;
  end;

implementation

end.
