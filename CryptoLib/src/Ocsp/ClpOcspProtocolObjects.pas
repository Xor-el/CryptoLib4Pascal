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

unit ClpOcspProtocolObjects;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpAsn1Core,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpRfc5280Asn1Utilities,
  ClpOcspAsn1Objects,
  ClpIOcspAsn1Objects,
  ClpOcspObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpX509Certificate,
  ClpIX509Certificate,
  ClpX509ExtensionBase,
  ClpX509Utilities,
  ClpDigestUtilities,
  ClpAsn1VerifierFactory,
  ClpIVerifierFactory,
  ClpIDigestFactory,
  ClpIAsymmetricKeyParameter,
  ClpSubjectPublicKeyInfoFactory,
  ClpCollectionStore,
  ClpIStore,
  ClpIOcspProtocolObjects,
  ClpBigInteger,
  ClpNullable,
  ClpCryptoLibTypes;

resourcestring
  SOcspCertIDNil = 'certificate ID cannot be nil';
  SOcspRevokedInfoNil = 'revoked info cannot be nil';
  SOcspResponderIDNil = 'responder ID cannot be nil';
  SOcspReqNil = 'request cannot be nil';
  SOcspSingleResponseNil = 'single response cannot be nil';
  SOcspResponseDataNil = 'response data cannot be nil';
  SOcspBasicResponseNil = 'basic response cannot be nil';
  SOcspResponseNil = 'response cannot be nil';
  SOcspRequestNil = 'request cannot be nil';
  SOcspNoRevocationReason = 'attempt to get a reason where none is available';
  SOcspCreateIDFailed = 'problem creating ID: %s';
  SOcspEncodeTbsRequestFailed = 'problem encoding tbsRequest: %s';
  SOcspEncodeTbsResponseDataFailed = 'problem encoding tbsResponseData: %s';
  SOcspVerifyUnsigned = 'attempt to verify signature on unsigned object';
  SOcspVerifyFailed = 'exception processing sig: %s';
  SOcspMalformedRequest = 'malformed request: %s';
  SOcspMalformedResponse = 'malformed response: %s';
  SOcspDecodeBasicFailed = 'problem decoding object: %s';
  SOcspUnexpectedResponseType = 'response type is not id-pkix-ocsp-basic: %s';
  SOcspDigestAlgorithmMismatch = 'digest factory does not match required digest algorithm';

type
  /// <summary>The OCSPResponseStatus values (RFC 6960 sec. 4.2.1).</summary>
  TOcspRespStatus = class abstract(TObject)
  public
  const
    /// <summary>Response has valid confirmations.</summary>
    Successful = Int32(0);
    /// <summary>Illegal confirmation request.</summary>
    MalformedRequest = Int32(1);
    /// <summary>Internal error in issuer.</summary>
    InternalError = Int32(2);
    /// <summary>Try again later.</summary>
    TryLater = Int32(3);
    // (4) is not used
    /// <summary>Must sign the request.</summary>
    SigRequired = Int32(5);
    /// <summary>Request unauthorized.</summary>
    Unauthorized = Int32(6);
  end;

  /// <summary>
  /// The "good" certificate status (RFC 6960 sec. 2.2), which the CHOICE encodes with no content.
  /// </summary>
  TCertificateStatus = class abstract(TInterfacedObject)
  public
    /// <summary>The "good" status, which is represented by a nil status object.</summary>
    class function Good: ICertificateStatus; static; inline;
  end;

  /// <summary>Wrapper for a RevokedInfo (RFC 6960 sec. 4.2.1).</summary>
  TRevokedStatus = class(TCertificateStatus, ICertificateStatus, IRevokedStatus)

  strict private
  var
    FRevokedInfo: IRevokedInfo;

  strict protected
    function GetRevocationTime: TDateTime;
    function GetHasRevocationReason: Boolean;
    function GetRevocationReason: Int32;

  public
    constructor Create(const ARevokedInfo: IRevokedInfo); overload;
    /// <summary>AUtcRevocationTime is a UTC time, as every date in this layer is.</summary>
    constructor Create(AUtcRevocationTime: TDateTime); overload;
    constructor Create(AUtcRevocationTime: TDateTime; ARevocationReason: Int32); overload;

    function ToAsn1Structure: IRevokedInfo;

    property RevocationTime: TDateTime read GetRevocationTime;
    property HasRevocationReason: Boolean read GetHasRevocationReason;
    property RevocationReason: Int32 read GetRevocationReason;
  end;

  /// <summary>Wrapper for an UnknownInfo (RFC 6960 sec. 4.2.1).</summary>
  TUnknownStatus = class(TCertificateStatus, ICertificateStatus, IUnknownStatus)
  public
    constructor Create();
  end;

  /// <summary>
  /// Identifier of the certificate a request or response is about (RFC 6960 sec. 4.1.1).
  /// </summary>
  TCertificateID = class(TInterfacedObject, ICertificateID)

  strict private
  var
    FId: ICertID;

    class function CreateCertID(const ADigestAlgorithm: IAlgorithmIdentifier;
      const AIssuerCert: IX509Certificate; const ASerialNumber: IDerInteger): ICertID;
      overload; static;
    class function CreateCertID(const ADigestFactory: IDigestFactory;
      const AIssuerCert: IX509Certificate; const ASerialNumber: IDerInteger): ICertID;
      overload; static;

  strict protected
    function GetHashAlgOid: String;
    function GetSerialNumber: TBigInteger;

  public
    /// <summary>The SHA-1 digest algorithm identifier, the one RFC 6960 sec. 4.3 requires.</summary>
    class function DigestSha1: IAlgorithmIdentifier; static;

    constructor Create(const AId: ICertID); overload;
    constructor Create(const ADigestAlgorithm: IAlgorithmIdentifier;
      const AIssuerCert: IX509Certificate; const ASerialNumber: TBigInteger); overload;
    constructor Create(const ADigestFactory: IDigestFactory;
      const AIssuerCert: IX509Certificate; const ASerialNumber: TBigInteger); overload;

    function GetIssuerNameHash: TCryptoLibByteArray;
    function GetIssuerKeyHash: TCryptoLibByteArray;

    function MatchesIssuer(const AIssuerCert: IX509Certificate): Boolean; overload;
    function MatchesIssuer(const ADigestFactory: IDigestFactory;
      const AIssuerCert: IX509Certificate): Boolean; overload;

    function ToAsn1Structure: ICertID;

    function Equals(const AOther: ICertificateID): Boolean; reintroduce; overload;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    /// <summary>
    /// Derive an identifier for another certificate of the same issuer, reusing the issuer
    /// hashes already calculated for AOriginal.
    /// </summary>
    class function DeriveCertificateID(const AOriginal: ICertificateID;
      const ANewSerialNumber: TBigInteger): ICertificateID; static;

    property HashAlgOid: String read GetHashAlgOid;
    property SerialNumber: TBigInteger read GetSerialNumber;
  end;

  /// <summary>Carrier for a ResponderID (RFC 6960 sec. 4.2.1).</summary>
  TRespID = class(TInterfacedObject, IRespID)

  strict private
  var
    FId: IResponderID;

  public
    constructor Create(const AId: IResponderID); overload;
    constructor Create(const AName: IX509Name); overload;
    /// <summary>Build a byKey responder ID from the SHA-1 hash of the public key bits.</summary>
    constructor Create(const APublicKey: IAsymmetricKeyParameter); overload;

    function ToAsn1Structure: IResponderID;

    function Equals(const AOther: IRespID): Boolean; reintroduce; overload;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;
  end;

  /// <summary>One entry of an OCSP request list (RFC 6960 sec. 4.1.1).</summary>
  TReq = class(TX509ExtensionBase, IOcspExtensions, IReq)

  strict private
  var
    FReq: IRequest;

  strict protected
    function GetX509Extensions: IX509Extensions; override;

  public
    constructor Create(const AReq: IRequest);

    function GetCertID: ICertificateID;
    function GetSingleRequestExtensions: IX509Extensions;

    property SingleRequestExtensions: IX509Extensions read GetSingleRequestExtensions;
  end;

  /// <summary>One entry of an OCSP response list (RFC 6960 sec. 4.2.1).</summary>
  TSingleResp = class(TX509ExtensionBase, IOcspExtensions, ISingleResp)

  strict private
  var
    FResp: ISingleResponse;

  strict protected
    function GetX509Extensions: IX509Extensions; override;
    function GetThisUpdate: TDateTime;
    function GetNextUpdate: TNullable<TDateTime>;

  public
    constructor Create(const AResp: ISingleResponse);

    function GetCertID: ICertificateID;
    function GetCertStatus: ICertificateStatus;
    function GetSingleExtensions: IX509Extensions;

    function ToAsn1Structure: ISingleResponse;

    property ThisUpdate: TDateTime read GetThisUpdate;
    property NextUpdate: TNullable<TDateTime> read GetNextUpdate;
    property SingleExtensions: IX509Extensions read GetSingleExtensions;
  end;

  /// <summary>The tbsResponseData of a basic OCSP response (RFC 6960 sec. 4.2.1).</summary>
  TRespData = class(TX509ExtensionBase, IOcspExtensions, IRespData)

  strict private
  var
    FData: IResponseData;

  strict protected
    function GetX509Extensions: IX509Extensions; override;
    function GetVersion: Int32;
    function GetProducedAt: TDateTime;
    function GetResponseExtensions: IX509Extensions;

  public
    constructor Create(const AData: IResponseData);

    function GetResponderId: IRespID;
    function GetResponses: TCryptoLibGenericArray<ISingleResp>;

    function ToAsn1Structure: IResponseData;

    property Version: Int32 read GetVersion;
    property ProducedAt: TDateTime read GetProducedAt;
    property ResponseExtensions: IX509Extensions read GetResponseExtensions;
  end;

  /// <summary>An OCSP request (RFC 6960 sec. 4.1.1).</summary>
  TOcspReq = class(TX509ExtensionBase, IOcspExtensions, IOcspReq)

  strict private
  var
    FReq: IOcspRequest;

    function GetCertList: TCryptoLibGenericArray<IX509Certificate>;

  strict protected
    function GetX509Extensions: IX509Extensions; override;
    function GetVersion: Int32;
    function GetRequestorName: IGeneralName;
    function GetRequestExtensions: IX509Extensions;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;
    function GetSignatureAlgOid: String;
    function GetIsSigned: Boolean;

  public
    constructor Create(const AReq: IOcspRequest); overload;
    constructor Create(const AEncoded: TCryptoLibByteArray); overload;
    constructor Create(const AStream: TStream); overload;

    function GetTbsRequest: TCryptoLibByteArray;
    function GetRequestList: TCryptoLibGenericArray<IReq>;
    function GetSignature: TCryptoLibByteArray;
    function GetCerts: TCryptoLibGenericArray<IX509Certificate>;
    function GetCertificates: IStore<IX509Certificate>;

    function Verify(const APublicKey: IAsymmetricKeyParameter): Boolean;

    function GetEncoded: TCryptoLibByteArray;
    function ToAsn1Structure: IOcspRequest;

    property Version: Int32 read GetVersion;
    property RequestorName: IGeneralName read GetRequestorName;
    property RequestExtensions: IX509Extensions read GetRequestExtensions;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
    property SignatureAlgOid: String read GetSignatureAlgOid;
    property IsSigned: Boolean read GetIsSigned;
  end;

  /// <summary>A basic OCSP response (RFC 6960 sec. 4.2.1).</summary>
  TBasicOcspResp = class(TX509ExtensionBase, IOcspExtensions, IBasicOcspResp)

  strict private
  var
    FResp: IBasicOcspResponse;
    FData: IResponseData;

  strict protected
    function GetX509Extensions: IX509Extensions; override;
    function GetVersion: Int32;
    function GetProducedAt: TDateTime;
    function GetResponseExtensions: IX509Extensions;
    function GetSignatureAlgorithm: IAlgorithmIdentifier;

  public
    constructor Create(const AResp: IBasicOcspResponse);

    function GetTbsResponseData: TCryptoLibByteArray;
    function GetResponderId: IRespID;
    function GetResponses: TCryptoLibGenericArray<ISingleResp>;
    function GetSignature: TCryptoLibByteArray;
    function GetCerts: TCryptoLibGenericArray<IX509Certificate>;
    function GetCertificates: IStore<IX509Certificate>;

    function Verify(const APublicKey: IAsymmetricKeyParameter): Boolean;

    function GetEncoded: TCryptoLibByteArray;
    function ToAsn1Structure: IBasicOcspResponse;

    function Equals(const AOther: IBasicOcspResp): Boolean; reintroduce; overload;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Version: Int32 read GetVersion;
    property ProducedAt: TDateTime read GetProducedAt;
    property ResponseExtensions: IX509Extensions read GetResponseExtensions;
    property SignatureAlgorithm: IAlgorithmIdentifier read GetSignatureAlgorithm;
  end;

  /// <summary>An OCSP response (RFC 6960 sec. 4.2.1).</summary>
  TOcspResp = class(TInterfacedObject, IOcspResp)

  strict private
  var
    FResp: IOcspResponse;

    class function ParseResponse(const AEncoded: TCryptoLibByteArray): IOcspResponse;
      overload; static;
    class function ParseResponse(const AStream: TStream): IOcspResponse; overload; static;

  strict protected
    function GetStatus: Int32;

  public
    constructor Create(const AResp: IOcspResponse); overload;
    constructor Create(const AEncoded: TCryptoLibByteArray); overload;
    constructor Create(const AStream: TStream); overload;

    function GetResponseObject: IBasicOcspResp;
    function GetRawResponse: IAsn1OctetString;

    function GetEncoded: TCryptoLibByteArray;
    function ToAsn1Structure: IOcspResponse;

    function Equals(const AOther: IOcspResp): Boolean; reintroduce; overload;
    function GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI} override;

    property Status: Int32 read GetStatus;
  end;

  /// <summary>Helpers for the OCSP extensions of RFC 6960 sec. 4.4.</summary>
  TOcspUtilities = class sealed(TObject)
  public
    /// <summary>The nonce extension value (RFC 6960 sec. 4.4.1), or nil when absent.</summary>
    class function GetNonce(const AExtensions: IOcspExtensions): IAsn1OctetString; static;
  end;

implementation

{ TCertificateStatus }

class function TCertificateStatus.Good: ICertificateStatus;
begin
  Result := nil;
end;

{ TRevokedStatus }

constructor TRevokedStatus.Create(const ARevokedInfo: IRevokedInfo);
begin
  inherited Create();
  if ARevokedInfo = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspRevokedInfoNil);
  FRevokedInfo := ARevokedInfo;
end;

constructor TRevokedStatus.Create(AUtcRevocationTime: TDateTime);
begin
  inherited Create();
  FRevokedInfo := TRevokedInfo.Create
    (TRfc5280Asn1Utilities.CreateGeneralizedTimeFromUtc(AUtcRevocationTime)) as IRevokedInfo;
end;

constructor TRevokedStatus.Create(AUtcRevocationTime: TDateTime; ARevocationReason: Int32);
begin
  inherited Create();
  FRevokedInfo := TRevokedInfo.Create
    (TRfc5280Asn1Utilities.CreateGeneralizedTimeFromUtc(AUtcRevocationTime),
    TCrlReason.Create(ARevocationReason) as ICrlReason) as IRevokedInfo;
end;

function TRevokedStatus.GetRevocationTime: TDateTime;
begin
  Result := FRevokedInfo.RevocationTime.ToDateTime();
end;

function TRevokedStatus.GetHasRevocationReason: Boolean;
begin
  Result := FRevokedInfo.RevocationReason <> nil;
end;

function TRevokedStatus.GetRevocationReason: Int32;
begin
  if FRevokedInfo.RevocationReason = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SOcspNoRevocationReason);
  Result := FRevokedInfo.RevocationReason.IntValueExact;
end;

function TRevokedStatus.ToAsn1Structure: IRevokedInfo;
begin
  Result := FRevokedInfo;
end;

{ TUnknownStatus }

constructor TUnknownStatus.Create();
begin
  inherited Create();
end;

{ TCertificateID }

class function TCertificateID.DigestSha1: IAlgorithmIdentifier;
begin
  Result := TAlgorithmIdentifier.Create(TOiwObjectIdentifiers.IdSha1,
    TDerNull.Instance as IAsn1Encodable) as IAlgorithmIdentifier;
end;

constructor TCertificateID.Create(const AId: ICertID);
begin
  inherited Create();
  if AId = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspCertIDNil);
  FId := AId;
end;

constructor TCertificateID.Create(const ADigestAlgorithm: IAlgorithmIdentifier;
  const AIssuerCert: IX509Certificate; const ASerialNumber: TBigInteger);
begin
  inherited Create();
  FId := CreateCertID(ADigestAlgorithm, AIssuerCert,
    TDerInteger.Create(ASerialNumber) as IDerInteger);
end;

constructor TCertificateID.Create(const ADigestFactory: IDigestFactory;
  const AIssuerCert: IX509Certificate; const ASerialNumber: TBigInteger);
begin
  inherited Create();
  FId := CreateCertID(ADigestFactory, AIssuerCert,
    TDerInteger.Create(ASerialNumber) as IDerInteger);
end;

class function TCertificateID.CreateCertID(const ADigestAlgorithm: IAlgorithmIdentifier;
  const AIssuerCert: IX509Certificate; const ASerialNumber: IDerInteger): ICertID;
var
  LIssuerNameHash, LIssuerKeyHash, LIssuerKey: TCryptoLibByteArray;
begin
  try
    LIssuerNameHash := TX509Utilities.CalculateDigest(ADigestAlgorithm,
      AIssuerCert.SubjectDN as IAsn1Encodable);
    LIssuerKey := AIssuerCert.SubjectPublicKeyInfo.GetPublicKey().GetBytes();
    LIssuerKeyHash := TDigestUtilities.CalculateDigest(ADigestAlgorithm.Algorithm, LIssuerKey);

    Result := TCertID.Create(ADigestAlgorithm,
      TDerOctetString.Create(LIssuerNameHash) as IAsn1OctetString,
      TDerOctetString.Create(LIssuerKeyHash) as IAsn1OctetString, ASerialNumber) as ICertID;
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspCreateIDFailed, [E.Message]);
  end;
end;

class function TCertificateID.CreateCertID(const ADigestFactory: IDigestFactory;
  const AIssuerCert: IX509Certificate; const ASerialNumber: IDerInteger): ICertID;
var
  LIssuerNameHash, LIssuerKeyHash, LIssuerKey: TCryptoLibByteArray;
begin
  try
    LIssuerNameHash := TX509Utilities.CalculateDigest(ADigestFactory,
      AIssuerCert.SubjectDN as IAsn1Encodable);
    LIssuerKey := AIssuerCert.SubjectPublicKeyInfo.GetPublicKey().GetBytes();
    LIssuerKeyHash := TX509Utilities.CalculateDigest(ADigestFactory, LIssuerKey, 0,
      System.Length(LIssuerKey));

    Result := TCertID.Create(ADigestFactory.AlgorithmDetails,
      TDerOctetString.Create(LIssuerNameHash) as IAsn1OctetString,
      TDerOctetString.Create(LIssuerKeyHash) as IAsn1OctetString, ASerialNumber) as ICertID;
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspCreateIDFailed, [E.Message]);
  end;
end;

function TCertificateID.GetHashAlgOid: String;
begin
  Result := FId.HashAlgorithm.Algorithm.Id;
end;

function TCertificateID.GetIssuerNameHash: TCryptoLibByteArray;
begin
  Result := FId.IssuerNameHash.GetOctets();
end;

function TCertificateID.GetIssuerKeyHash: TCryptoLibByteArray;
begin
  Result := FId.IssuerKeyHash.GetOctets();
end;

function TCertificateID.GetSerialNumber: TBigInteger;
begin
  Result := FId.SerialNumber.Value;
end;

function TCertificateID.MatchesIssuer(const AIssuerCert: IX509Certificate): Boolean;
begin
  Result := CreateCertID(FId.HashAlgorithm, AIssuerCert, FId.SerialNumber).Equals(FId);
end;

function TCertificateID.MatchesIssuer(const ADigestFactory: IDigestFactory;
  const AIssuerCert: IX509Certificate): Boolean;
begin
  if not FId.HashAlgorithm.Equals(ADigestFactory.AlgorithmDetails) then
    raise EArgumentCryptoLibException.CreateRes(@SOcspDigestAlgorithmMismatch);
  Result := CreateCertID(ADigestFactory, AIssuerCert, FId.SerialNumber).Equals(FId);
end;

function TCertificateID.ToAsn1Structure: ICertID;
begin
  Result := FId;
end;

function TCertificateID.Equals(const AOther: ICertificateID): Boolean;
begin
  if AOther = nil then
    Result := False
  else if (AOther as ICertificateID) = (Self as ICertificateID) then
    Result := True
  else
    Result := FId.Equals(AOther.ToAsn1Structure());
end;

function TCertificateID.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FId.GetHashCode();
end;

class function TCertificateID.DeriveCertificateID(const AOriginal: ICertificateID;
  const ANewSerialNumber: TBigInteger): ICertificateID;
var
  LOriginalID: ICertID;
begin
  LOriginalID := AOriginal.ToAsn1Structure();
  Result := TCertificateID.Create(TCertID.Create(LOriginalID.HashAlgorithm,
    LOriginalID.IssuerNameHash, LOriginalID.IssuerKeyHash,
    TDerInteger.Create(ANewSerialNumber) as IDerInteger) as ICertID) as ICertificateID;
end;

{ TRespID }

constructor TRespID.Create(const AId: IResponderID);
begin
  inherited Create();
  if AId = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponderIDNil);
  FId := AId;
end;

constructor TRespID.Create(const AName: IX509Name);
begin
  inherited Create();
  FId := TResponderID.Create(AName) as IResponderID;
end;

constructor TRespID.Create(const APublicKey: IAsymmetricKeyParameter);
var
  LInfo: ISubjectPublicKeyInfo;
  LKeyHash: TCryptoLibByteArray;
begin
  inherited Create();
  try
    LInfo := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(APublicKey);
    LKeyHash := TDigestUtilities.CalculateDigest(TOiwObjectIdentifiers.IdSha1,
      LInfo.GetPublicKey().GetBytes());
    FId := TResponderID.Create(TDerOctetString.Create(LKeyHash) as IAsn1OctetString)
      as IResponderID;
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspCreateIDFailed, [E.Message]);
  end;
end;

function TRespID.ToAsn1Structure: IResponderID;
begin
  Result := FId;
end;

function TRespID.Equals(const AOther: IRespID): Boolean;
begin
  if AOther = nil then
    Result := False
  else if (AOther as IRespID) = (Self as IRespID) then
    Result := True
  else
    Result := FId.Equals(AOther.ToAsn1Structure());
end;

function TRespID.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FId.GetHashCode();
end;

{ TReq }

constructor TReq.Create(const AReq: IRequest);
begin
  inherited Create();
  if AReq = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspReqNil);
  FReq := AReq;
end;

function TReq.GetX509Extensions: IX509Extensions;
begin
  Result := FReq.SingleRequestExtensions;
end;

function TReq.GetCertID: ICertificateID;
begin
  Result := TCertificateID.Create(FReq.ReqCert) as ICertificateID;
end;

function TReq.GetSingleRequestExtensions: IX509Extensions;
begin
  Result := FReq.SingleRequestExtensions;
end;

{ TSingleResp }

constructor TSingleResp.Create(const AResp: ISingleResponse);
begin
  inherited Create();
  if AResp = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspSingleResponseNil);
  FResp := AResp;
end;

function TSingleResp.GetX509Extensions: IX509Extensions;
begin
  Result := FResp.SingleExtensions;
end;

function TSingleResp.GetCertID: ICertificateID;
begin
  Result := TCertificateID.Create(FResp.CertId) as ICertificateID;
end;

function TSingleResp.GetCertStatus: ICertificateStatus;
var
  LStatus: IOcspCertStatus;
begin
  LStatus := FResp.CertStatus;
  case LStatus.TagNo of
    TOcspCertStatus.Good:
      Result := nil;
    TOcspCertStatus.Revoked:
      Result := TRevokedStatus.Create(TRevokedInfo.GetInstance(LStatus.Status))
        as ICertificateStatus;
  else
    Result := TUnknownStatus.Create() as ICertificateStatus;
  end;
end;

function TSingleResp.GetThisUpdate: TDateTime;
begin
  Result := FResp.ThisUpdate.ToDateTime();
end;

function TSingleResp.GetNextUpdate: TNullable<TDateTime>;
begin
  if FResp.NextUpdate = nil then
    Result := TNullable<TDateTime>.None
  else
    Result := TNullable<TDateTime>.Some(FResp.NextUpdate.ToDateTime());
end;

function TSingleResp.GetSingleExtensions: IX509Extensions;
begin
  Result := FResp.SingleExtensions;
end;

function TSingleResp.ToAsn1Structure: ISingleResponse;
begin
  Result := FResp;
end;

{ TRespData }

constructor TRespData.Create(const AData: IResponseData);
begin
  inherited Create();
  if AData = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponseDataNil);
  FData := AData;
end;

function TRespData.GetX509Extensions: IX509Extensions;
begin
  Result := FData.ResponseExtensions;
end;

function TRespData.GetVersion: Int32;
begin
  Result := FData.Version.IntValueExact + 1;
end;

function TRespData.GetResponderId: IRespID;
begin
  Result := TRespID.Create(FData.ResponderID) as IRespID;
end;

function TRespData.GetProducedAt: TDateTime;
begin
  Result := FData.ProducedAt.ToDateTime();
end;

function TRespData.GetResponses: TCryptoLibGenericArray<ISingleResp>;
var
  LResponses: IAsn1Sequence;
  LIdx: Int32;
begin
  LResponses := FData.Responses;
  System.SetLength(Result, LResponses.Count);
  for LIdx := 0 to LResponses.Count - 1 do
  begin
    Result[LIdx] := TSingleResp.Create(TSingleResponse.GetInstance(LResponses[LIdx]))
      as ISingleResp;
  end;
end;

function TRespData.GetResponseExtensions: IX509Extensions;
begin
  Result := FData.ResponseExtensions;
end;

function TRespData.ToAsn1Structure: IResponseData;
begin
  Result := FData;
end;

{ TOcspReq }

constructor TOcspReq.Create(const AReq: IOcspRequest);
begin
  inherited Create();
  if AReq = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspRequestNil);
  FReq := AReq;
end;

constructor TOcspReq.Create(const AEncoded: TCryptoLibByteArray);
begin
  inherited Create();
  try
    FReq := TOcspRequest.GetInstance(TAsn1Object.FromByteArray(AEncoded));
  except
    on E: Exception do
      raise EIOCryptoLibException.CreateResFmt(@SOcspMalformedRequest, [E.Message]);
  end;
end;

constructor TOcspReq.Create(const AStream: TStream);
begin
  inherited Create();
  try
    FReq := TOcspRequest.GetInstance(TAsn1Object.FromStream(AStream));
  except
    on E: Exception do
      raise EIOCryptoLibException.CreateResFmt(@SOcspMalformedRequest, [E.Message]);
  end;
end;

function TOcspReq.GetX509Extensions: IX509Extensions;
begin
  Result := FReq.TbsRequest.RequestExtensions;
end;

function TOcspReq.GetTbsRequest: TCryptoLibByteArray;
begin
  try
    Result := FReq.TbsRequest.GetEncoded(TAsn1Encodable.Der);
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspEncodeTbsRequestFailed, [E.Message]);
  end;
end;

function TOcspReq.GetVersion: Int32;
begin
  Result := FReq.TbsRequest.Version.IntValueExact + 1;
end;

function TOcspReq.GetRequestorName: IGeneralName;
begin
  Result := FReq.TbsRequest.RequestorName;
end;

function TOcspReq.GetRequestList: TCryptoLibGenericArray<IReq>;
var
  LList: IAsn1Sequence;
  LIdx: Int32;
begin
  LList := FReq.TbsRequest.RequestList;
  System.SetLength(Result, LList.Count);
  for LIdx := 0 to LList.Count - 1 do
  begin
    Result[LIdx] := TReq.Create(TRequest.GetInstance(LList[LIdx])) as IReq;
  end;
end;

function TOcspReq.GetRequestExtensions: IX509Extensions;
begin
  Result := FReq.TbsRequest.RequestExtensions;
end;

function TOcspReq.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  if FReq.OptionalSignature = nil then
    Result := nil
  else
    Result := FReq.OptionalSignature.SignatureAlgorithm;
end;

function TOcspReq.GetSignatureAlgOid: String;
begin
  if FReq.OptionalSignature = nil then
    Result := ''
  else
    Result := FReq.OptionalSignature.SignatureAlgorithm.Algorithm.Id;
end;

function TOcspReq.GetSignature: TCryptoLibByteArray;
begin
  if FReq.OptionalSignature = nil then
    Result := nil
  else
    Result := FReq.OptionalSignature.GetSignatureOctets();
end;

function TOcspReq.GetIsSigned: Boolean;
begin
  Result := FReq.OptionalSignature <> nil;
end;

function TOcspReq.GetCertList: TCryptoLibGenericArray<IX509Certificate>;
var
  LCerts: IAsn1Sequence;
  LIdx: Int32;
begin
  LCerts := FReq.OptionalSignature.Certs;
  if LCerts = nil then
  begin
    Result := nil;
    Exit;
  end;
  System.SetLength(Result, LCerts.Count);
  for LIdx := 0 to LCerts.Count - 1 do
  begin
    Result[LIdx] := TX509Certificate.Create(TX509CertificateStructure.GetInstance(LCerts[LIdx]))
      as IX509Certificate;
  end;
end;

function TOcspReq.GetCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  if not GetIsSigned() then
  begin
    Result := nil;
    Exit;
  end;
  Result := GetCertList();
end;

function TOcspReq.GetCertificates: IStore<IX509Certificate>;
begin
  if not GetIsSigned() then
  begin
    Result := nil;
    Exit;
  end;
  Result := TCollectionStore<IX509Certificate>.Create(GetCertList());
end;

function TOcspReq.Verify(const APublicKey: IAsymmetricKeyParameter): Boolean;
var
  LSignature: ISignature;
  LVerifierFactory: IVerifierFactory;
begin
  LSignature := FReq.OptionalSignature;
  if LSignature = nil then
    raise EOcspCryptoLibException.CreateRes(@SOcspVerifyUnsigned);

  try
    LVerifierFactory := TAsn1VerifierFactory.Create(LSignature.SignatureAlgorithm, APublicKey)
      as IVerifierFactory;
    Result := TX509Utilities.VerifySignature(LVerifierFactory,
      FReq.TbsRequest as IAsn1Encodable, LSignature.SignatureValue);
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspVerifyFailed, [E.Message]);
  end;
end;

function TOcspReq.GetEncoded: TCryptoLibByteArray;
begin
  Result := FReq.GetEncoded();
end;

function TOcspReq.ToAsn1Structure: IOcspRequest;
begin
  Result := FReq;
end;

{ TBasicOcspResp }

constructor TBasicOcspResp.Create(const AResp: IBasicOcspResponse);
begin
  inherited Create();
  if AResp = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspBasicResponseNil);
  FResp := AResp;
  FData := AResp.TbsResponseData;
end;

function TBasicOcspResp.GetX509Extensions: IX509Extensions;
begin
  Result := FData.ResponseExtensions;
end;

function TBasicOcspResp.GetTbsResponseData: TCryptoLibByteArray;
begin
  try
    Result := FData.GetEncoded(TAsn1Encodable.Der);
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspEncodeTbsResponseDataFailed, [E.Message]);
  end;
end;

function TBasicOcspResp.GetVersion: Int32;
begin
  Result := FData.Version.IntValueExact + 1;
end;

function TBasicOcspResp.GetResponderId: IRespID;
begin
  Result := TRespID.Create(FData.ResponderID) as IRespID;
end;

function TBasicOcspResp.GetProducedAt: TDateTime;
begin
  Result := FData.ProducedAt.ToDateTime();
end;

function TBasicOcspResp.GetResponses: TCryptoLibGenericArray<ISingleResp>;
var
  LResponses: IAsn1Sequence;
  LIdx: Int32;
begin
  LResponses := FData.Responses;
  System.SetLength(Result, LResponses.Count);
  for LIdx := 0 to LResponses.Count - 1 do
  begin
    Result[LIdx] := TSingleResp.Create(TSingleResponse.GetInstance(LResponses[LIdx]))
      as ISingleResp;
  end;
end;

function TBasicOcspResp.GetResponseExtensions: IX509Extensions;
begin
  Result := FData.ResponseExtensions;
end;

function TBasicOcspResp.GetSignatureAlgorithm: IAlgorithmIdentifier;
begin
  Result := FResp.SignatureAlgorithm;
end;

function TBasicOcspResp.GetSignature: TCryptoLibByteArray;
begin
  Result := FResp.GetSignatureOctets();
end;

function TBasicOcspResp.GetCerts: TCryptoLibGenericArray<IX509Certificate>;
var
  LCerts: IAsn1Sequence;
  LIdx: Int32;
begin
  LCerts := FResp.Certs;
  if LCerts = nil then
  begin
    Result := nil;
    Exit;
  end;
  System.SetLength(Result, LCerts.Count);
  for LIdx := 0 to LCerts.Count - 1 do
  begin
    Result[LIdx] := TX509Certificate.Create(TX509CertificateStructure.GetInstance(LCerts[LIdx]))
      as IX509Certificate;
  end;
end;

function TBasicOcspResp.GetCertificates: IStore<IX509Certificate>;
begin
  Result := TCollectionStore<IX509Certificate>.Create(GetCerts());
end;

function TBasicOcspResp.Verify(const APublicKey: IAsymmetricKeyParameter): Boolean;
var
  LVerifierFactory: IVerifierFactory;
begin
  try
    LVerifierFactory := TAsn1VerifierFactory.Create(FResp.SignatureAlgorithm, APublicKey)
      as IVerifierFactory;
    Result := TX509Utilities.VerifySignature(LVerifierFactory, FData as IAsn1Encodable,
      FResp.Signature);
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspVerifyFailed, [E.Message]);
  end;
end;

function TBasicOcspResp.GetEncoded: TCryptoLibByteArray;
begin
  Result := FResp.GetEncoded();
end;

function TBasicOcspResp.ToAsn1Structure: IBasicOcspResponse;
begin
  Result := FResp;
end;

function TBasicOcspResp.Equals(const AOther: IBasicOcspResp): Boolean;
begin
  if AOther = nil then
    Result := False
  else if (AOther as IBasicOcspResp) = (Self as IBasicOcspResp) then
    Result := True
  else
    Result := FResp.Equals(AOther.ToAsn1Structure());
end;

function TBasicOcspResp.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FResp.GetHashCode();
end;

{ TOcspResp }

class function TOcspResp.ParseResponse(const AEncoded: TCryptoLibByteArray): IOcspResponse;
begin
  try
    Result := TOcspResponse.GetInstance(TAsn1Object.FromByteArray(AEncoded));
  except
    on E: Exception do
      raise EIOCryptoLibException.CreateResFmt(@SOcspMalformedResponse, [E.Message]);
  end;
end;

class function TOcspResp.ParseResponse(const AStream: TStream): IOcspResponse;
begin
  try
    Result := TOcspResponse.GetInstance(TAsn1Object.FromStream(AStream));
  except
    on E: Exception do
      raise EIOCryptoLibException.CreateResFmt(@SOcspMalformedResponse, [E.Message]);
  end;
end;

constructor TOcspResp.Create(const AResp: IOcspResponse);
begin
  inherited Create();
  if AResp = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspResponseNil);
  FResp := AResp;
end;

constructor TOcspResp.Create(const AEncoded: TCryptoLibByteArray);
begin
  inherited Create();
  FResp := ParseResponse(AEncoded);
end;

constructor TOcspResp.Create(const AStream: TStream);
begin
  inherited Create();
  FResp := ParseResponse(AStream);
end;

function TOcspResp.GetStatus: Int32;
begin
  Result := FResp.ResponseStatus.IntValueExact;
end;

function TOcspResp.GetResponseObject: IBasicOcspResp;
var
  LBytes: IResponseBytes;
begin
  LBytes := FResp.ResponseBytes;
  if LBytes = nil then
  begin
    Result := nil;
    Exit;
  end;

  if not TOcspObjectIdentifiers.PkixOcspBasic.Equals(LBytes.ResponseType) then
    raise EOcspCryptoLibException.CreateResFmt(@SOcspUnexpectedResponseType,
      [LBytes.ResponseType.Id]);

  try
    Result := TBasicOcspResp.Create(TBasicOcspResponse.GetInstance(LBytes.Response.GetOctets()))
      as IBasicOcspResp;
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspDecodeBasicFailed, [E.Message]);
  end;
end;

function TOcspResp.GetRawResponse: IAsn1OctetString;
begin
  if FResp.ResponseBytes = nil then
    Result := nil
  else
    Result := FResp.ResponseBytes.Response;
end;

function TOcspResp.GetEncoded: TCryptoLibByteArray;
begin
  Result := FResp.GetEncoded();
end;

function TOcspResp.ToAsn1Structure: IOcspResponse;
begin
  Result := FResp;
end;

function TOcspResp.Equals(const AOther: IOcspResp): Boolean;
begin
  if AOther = nil then
    Result := False
  else if (AOther as IOcspResp) = (Self as IOcspResp) then
    Result := True
  else
    Result := FResp.Equals(AOther.ToAsn1Structure());
end;

function TOcspResp.GetHashCode: {$IFDEF DELPHI}Int32; {$ELSE}PtrInt; {$ENDIF DELPHI}
begin
  Result := FResp.GetHashCode();
end;

{ TOcspUtilities }

class function TOcspUtilities.GetNonce(const AExtensions: IOcspExtensions): IAsn1OctetString;
var
  LValue: IAsn1Object;
begin
  LValue := AExtensions.GetExtensionParsedValue(TOcspObjectIdentifiers.PkixOcspNonce);
  if LValue = nil then
    Result := nil
  else
    Result := TAsn1OctetString.GetInstance(LValue);
end;

end.
