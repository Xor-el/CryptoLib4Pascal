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

unit ClpOcspGenerators;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpDateTimeHelper,
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
  ClpOcspProtocolObjects,
  ClpIOcspProtocolObjects,
  ClpIOcspGenerators,
  ClpIX509Certificate,
  ClpX509Utilities,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpIAsymmetricKeyParameter,
  ClpISecureRandom,
  ClpNullable,
  ClpCryptoLibTypes;

resourcestring
  SOcspGenCertIdNil = 'certificate ID cannot be nil';
  SOcspGenSignatureFactoryNil = 'signature factory cannot be nil';
  SOcspGenSigningAlgorithmEmpty = 'signing algorithm cannot be empty';
  SOcspGenRequestorNameRequired = 'requestorName must be specified if request is signed';
  SOcspGenTbsRequestFailed = 'exception processing TBSRequest: %s';
  SOcspGenResponseDataFailed = 'exception processing ResponseData: %s';
  SOcspGenEncodeFailed = 'cannot encode the basic response: %s';

type
  /// <summary>Generator for OCSP requests (RFC 6960 sec. 4.1).</summary>
  TOcspReqGenerator = class(TInterfacedObject, IOcspReqGenerator)

  strict private
  var
    FRequests: TCryptoLibGenericArray<IRequest>;
    FRequestorName: IGeneralName;
    FRequestExtensions: IX509Extensions;

    function GenerateRequest(const ASignatureFactory: ISignatureFactory;
      const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq;

  public
    constructor Create();

    procedure AddRequest(const ACertId: ICertificateID); overload;
    procedure AddRequest(const ACertId: ICertificateID;
      const ASingleRequestExtensions: IX509Extensions); overload;

    procedure SetRequestorName(const ARequestorName: IX509Name); overload;
    procedure SetRequestorName(const ARequestorName: IGeneralName); overload;
    procedure SetRequestExtensions(const ARequestExtensions: IX509Extensions);

    function Generate: IOcspReq; overload;
    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq; overload;
    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>;
      const ARandom: ISecureRandom): IOcspReq; overload;
    function Generate(const ASignatureFactory: ISignatureFactory;
      const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq; overload;
  end;

  /// <summary>Generator for basic OCSP responses (RFC 6960 sec. 4.2).</summary>
  TBasicOcspRespGenerator = class(TInterfacedObject, IBasicOcspRespGenerator)

  strict private
  var
    FResponses: TCryptoLibGenericArray<ISingleResponse>;
    FResponseExtensions: IX509Extensions;
    FResponderID: IRespID;

    class function ToOcspCertStatus(const ACertStatus: ICertificateStatus): IOcspCertStatus; static;
    function GenerateResponse(const ASignatureFactory: ISignatureFactory;
      const AChain: TCryptoLibGenericArray<IX509Certificate>;
      AProducedAt: TDateTime): IBasicOcspResp;

  public
    constructor Create(const AResponderID: IRespID); overload;
    /// <summary>Use the SHA-1 keyHash of the passed in public key as the responder ID.</summary>
    constructor Create(const APublicKey: IAsymmetricKeyParameter); overload;

    procedure AddResponse(const ACertID: ICertificateID;
      const ACertStatus: ICertificateStatus); overload;
    procedure AddResponse(const ACertID: ICertificateID; const ACertStatus: ICertificateStatus;
      const ASingleExtensions: IX509Extensions); overload;
    procedure AddResponse(const ACertID: ICertificateID; const ACertStatus: ICertificateStatus;
      const ANextUpdate: TNullable<TDateTime>;
      const ASingleExtensions: IX509Extensions); overload;
    procedure AddResponse(const ACertID: ICertificateID; const ACertStatus: ICertificateStatus;
      AThisUpdate: TDateTime; const ANextUpdate: TNullable<TDateTime>;
      const ASingleExtensions: IX509Extensions); overload;

    procedure SetResponseExtensions(const AResponseExtensions: IX509Extensions);

    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>;
      AProducedAt: TDateTime): IBasicOcspResp; overload;
    function Generate(const ASigningAlgorithm: String; const APrivateKey: IAsymmetricKeyParameter;
      const AChain: TCryptoLibGenericArray<IX509Certificate>; AProducedAt: TDateTime;
      const ARandom: ISecureRandom): IBasicOcspResp; overload;
    function Generate(const ASignatureFactory: ISignatureFactory;
      const AChain: TCryptoLibGenericArray<IX509Certificate>;
      AProducedAt: TDateTime): IBasicOcspResp; overload;
  end;

  /// <summary>
  /// Generator for OCSP responses (RFC 6960 sec. 4.2). Only basic responses can be wrapped.
  /// </summary>
  TOcspRespGenerator = class(TInterfacedObject, IOcspRespGenerator)
  public
    constructor Create();

    function Generate(AStatus: Int32; const AResponse: IBasicOcspResp): IOcspResp;
  end;

implementation

// certificate chains reach the ASN.1 layer as a plain SEQUENCE OF Certificate; an empty chain
// leaves the optional field out altogether
function CertsToSequence(const AChain: TCryptoLibGenericArray<IX509Certificate>): IAsn1Sequence;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LIdx: Int32;
begin
  if System.Length(AChain) = 0 then
  begin
    Result := nil;
    Exit;
  end;

  System.SetLength(LElements, System.Length(AChain));
  for LIdx := 0 to System.High(AChain) do
  begin
    LElements[LIdx] := AChain[LIdx].CertificateStructure as IAsn1Encodable;
  end;
  Result := TDerSequence.FromCollection(LElements);
end;

{ TOcspReqGenerator }

constructor TOcspReqGenerator.Create();
begin
  inherited Create();
  FRequests := nil;
  FRequestorName := nil;
  FRequestExtensions := nil;
end;

procedure TOcspReqGenerator.AddRequest(const ACertId: ICertificateID);
begin
  AddRequest(ACertId, nil);
end;

procedure TOcspReqGenerator.AddRequest(const ACertId: ICertificateID;
  const ASingleRequestExtensions: IX509Extensions);
var
  LCount: Int32;
begin
  if ACertId = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspGenCertIdNil);

  LCount := System.Length(FRequests);
  System.SetLength(FRequests, LCount + 1);
  FRequests[LCount] := TRequest.Create(ACertId.ToAsn1Structure(), ASingleRequestExtensions)
    as IRequest;
end;

procedure TOcspReqGenerator.SetRequestorName(const ARequestorName: IX509Name);
begin
  FRequestorName := TGeneralName.Create(TGeneralName.DirectoryName,
    ARequestorName as IAsn1Encodable) as IGeneralName;
end;

procedure TOcspReqGenerator.SetRequestorName(const ARequestorName: IGeneralName);
begin
  FRequestorName := ARequestorName;
end;

procedure TOcspReqGenerator.SetRequestExtensions(const ARequestExtensions: IX509Extensions);
begin
  FRequestExtensions := ARequestExtensions;
end;

function TOcspReqGenerator.GenerateRequest(const ASignatureFactory: ISignatureFactory;
  const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LIdx: Int32;
  LTbsRequest: ITbsRequest;
  LSignature: ISignature;
  LSignatureValue: IDerBitString;
begin
  System.SetLength(LElements, System.Length(FRequests));
  for LIdx := 0 to System.High(FRequests) do
  begin
    LElements[LIdx] := FRequests[LIdx] as IAsn1Encodable;
  end;

  LTbsRequest := TTbsRequest.Create(FRequestorName, TDerSequence.FromCollection(LElements),
    FRequestExtensions) as ITbsRequest;

  LSignature := nil;
  if ASignatureFactory <> nil then
  begin
    if FRequestorName = nil then
      raise EOcspCryptoLibException.CreateRes(@SOcspGenRequestorNameRequired);

    try
      LSignatureValue := TX509Utilities.GenerateSignature(ASignatureFactory,
        LTbsRequest as IAsn1Encodable);
    except
      on E: Exception do
        raise EOcspCryptoLibException.CreateResFmt(@SOcspGenTbsRequestFailed, [E.Message]);
    end;

    LSignature := TSignature.Create(ASignatureFactory.AlgorithmDetails, LSignatureValue,
      CertsToSequence(AChain)) as ISignature;
  end;

  Result := TOcspReq.Create(TOcspRequest.Create(LTbsRequest, LSignature) as IOcspRequest)
    as IOcspReq;
end;

function TOcspReqGenerator.Generate: IOcspReq;
begin
  Result := GenerateRequest(nil, nil);
end;

function TOcspReqGenerator.Generate(const ASigningAlgorithm: String;
  const APrivateKey: IAsymmetricKeyParameter;
  const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq;
begin
  Result := Generate(ASigningAlgorithm, APrivateKey, AChain, nil);
end;

function TOcspReqGenerator.Generate(const ASigningAlgorithm: String;
  const APrivateKey: IAsymmetricKeyParameter;
  const AChain: TCryptoLibGenericArray<IX509Certificate>;
  const ARandom: ISecureRandom): IOcspReq;
begin
  if ASigningAlgorithm = '' then
    raise EArgumentCryptoLibException.CreateRes(@SOcspGenSigningAlgorithmEmpty);

  Result := GenerateRequest(TAsn1SignatureFactory.Create(ASigningAlgorithm, APrivateKey, ARandom)
    as ISignatureFactory, AChain);
end;

function TOcspReqGenerator.Generate(const ASignatureFactory: ISignatureFactory;
  const AChain: TCryptoLibGenericArray<IX509Certificate>): IOcspReq;
begin
  if ASignatureFactory = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspGenSignatureFactoryNil);

  Result := GenerateRequest(ASignatureFactory, AChain);
end;

{ TBasicOcspRespGenerator }

constructor TBasicOcspRespGenerator.Create(const AResponderID: IRespID);
begin
  inherited Create();
  FResponses := nil;
  FResponderID := AResponderID;
end;

constructor TBasicOcspRespGenerator.Create(const APublicKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  FResponses := nil;
  FResponderID := TRespID.Create(APublicKey) as IRespID;
end;

class function TBasicOcspRespGenerator.ToOcspCertStatus(const ACertStatus: ICertificateStatus)
  : IOcspCertStatus;
var
  LRevoked: IRevokedStatus;
  LReason: ICrlReason;
begin
  // a nil status is the "good" alternative of the CHOICE
  if ACertStatus = nil then
  begin
    Result := TOcspCertStatus.Create() as IOcspCertStatus;
    Exit;
  end;

  if Supports(ACertStatus, IRevokedStatus, LRevoked) then
  begin
    if LRevoked.HasRevocationReason then
      LReason := TCrlReason.Create(LRevoked.RevocationReason) as ICrlReason
    else
      LReason := nil;

    Result := TOcspCertStatus.Create(TRevokedInfo.Create
      (TRfc5280Asn1Utilities.CreateGeneralizedTimeFromUtc(LRevoked.RevocationTime), LReason)
      as IRevokedInfo) as IOcspCertStatus;
    Exit;
  end;

  Result := TOcspCertStatus.Create(TOcspCertStatus.Unknown, TDerNull.Instance as IAsn1Encodable)
    as IOcspCertStatus;
end;

procedure TBasicOcspRespGenerator.AddResponse(const ACertID: ICertificateID;
  const ACertStatus: ICertificateStatus);
begin
  AddResponse(ACertID, ACertStatus, Now.ToUniversalTime(), TNullable<TDateTime>.None, nil);
end;

procedure TBasicOcspRespGenerator.AddResponse(const ACertID: ICertificateID;
  const ACertStatus: ICertificateStatus; const ASingleExtensions: IX509Extensions);
begin
  AddResponse(ACertID, ACertStatus, Now.ToUniversalTime(), TNullable<TDateTime>.None, ASingleExtensions);
end;

procedure TBasicOcspRespGenerator.AddResponse(const ACertID: ICertificateID;
  const ACertStatus: ICertificateStatus; const ANextUpdate: TNullable<TDateTime>;
  const ASingleExtensions: IX509Extensions);
begin
  AddResponse(ACertID, ACertStatus, Now.ToUniversalTime(), ANextUpdate, ASingleExtensions);
end;

procedure TBasicOcspRespGenerator.AddResponse(const ACertID: ICertificateID;
  const ACertStatus: ICertificateStatus; AThisUpdate: TDateTime;
  const ANextUpdate: TNullable<TDateTime>; const ASingleExtensions: IX509Extensions);
var
  LCount: Int32;
  LNextUpdate: IAsn1GeneralizedTime;
begin
  if ACertID = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspGenCertIdNil);

  if ANextUpdate.HasValue then
    LNextUpdate := TRfc5280Asn1Utilities.CreateGeneralizedTimeFromUtc(ANextUpdate.Value)
  else
    LNextUpdate := nil;

  LCount := System.Length(FResponses);
  System.SetLength(FResponses, LCount + 1);
  FResponses[LCount] := TSingleResponse.Create(ACertID.ToAsn1Structure(),
    ToOcspCertStatus(ACertStatus), TRfc5280Asn1Utilities.CreateGeneralizedTimeFromUtc(AThisUpdate),
    LNextUpdate, ASingleExtensions) as ISingleResponse;
end;

procedure TBasicOcspRespGenerator.SetResponseExtensions(const AResponseExtensions: IX509Extensions);
begin
  FResponseExtensions := AResponseExtensions;
end;

function TBasicOcspRespGenerator.GenerateResponse(const ASignatureFactory: ISignatureFactory;
  const AChain: TCryptoLibGenericArray<IX509Certificate>;
  AProducedAt: TDateTime): IBasicOcspResp;
var
  LElements: TCryptoLibGenericArray<IAsn1Encodable>;
  LIdx: Int32;
  LResponseData: IResponseData;
  LSignatureValue: IDerBitString;
begin
  System.SetLength(LElements, System.Length(FResponses));
  for LIdx := 0 to System.High(FResponses) do
  begin
    LElements[LIdx] := FResponses[LIdx] as IAsn1Encodable;
  end;

  LResponseData := TResponseData.Create(FResponderID.ToAsn1Structure(),
    TRfc5280Asn1Utilities.CreateGeneralizedTimeFromUtc(AProducedAt),
    TDerSequence.FromCollection(LElements), FResponseExtensions) as IResponseData;

  try
    LSignatureValue := TX509Utilities.GenerateSignature(ASignatureFactory,
      LResponseData as IAsn1Encodable);
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspGenResponseDataFailed, [E.Message]);
  end;

  Result := TBasicOcspResp.Create(TBasicOcspResponse.Create(LResponseData,
    ASignatureFactory.AlgorithmDetails, LSignatureValue, CertsToSequence(AChain))
    as IBasicOcspResponse) as IBasicOcspResp;
end;

function TBasicOcspRespGenerator.Generate(const ASigningAlgorithm: String;
  const APrivateKey: IAsymmetricKeyParameter;
  const AChain: TCryptoLibGenericArray<IX509Certificate>;
  AProducedAt: TDateTime): IBasicOcspResp;
begin
  Result := Generate(ASigningAlgorithm, APrivateKey, AChain, AProducedAt, nil);
end;

function TBasicOcspRespGenerator.Generate(const ASigningAlgorithm: String;
  const APrivateKey: IAsymmetricKeyParameter;
  const AChain: TCryptoLibGenericArray<IX509Certificate>; AProducedAt: TDateTime;
  const ARandom: ISecureRandom): IBasicOcspResp;
begin
  if ASigningAlgorithm = '' then
    raise EArgumentCryptoLibException.CreateRes(@SOcspGenSigningAlgorithmEmpty);

  Result := GenerateResponse(TAsn1SignatureFactory.Create(ASigningAlgorithm, APrivateKey, ARandom)
    as ISignatureFactory, AChain, AProducedAt);
end;

function TBasicOcspRespGenerator.Generate(const ASignatureFactory: ISignatureFactory;
  const AChain: TCryptoLibGenericArray<IX509Certificate>;
  AProducedAt: TDateTime): IBasicOcspResp;
begin
  if ASignatureFactory = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SOcspGenSignatureFactoryNil);

  Result := GenerateResponse(ASignatureFactory, AChain, AProducedAt);
end;

{ TOcspRespGenerator }

constructor TOcspRespGenerator.Create();
begin
  inherited Create();
end;

function TOcspRespGenerator.Generate(AStatus: Int32; const AResponse: IBasicOcspResp): IOcspResp;
var
  LOctets: IAsn1OctetString;
  LResponseBytes: IResponseBytes;
begin
  if AResponse = nil then
  begin
    Result := TOcspResp.Create(TOcspResponse.Create(TOcspResponseStatus.Create(AStatus)
      as IOcspResponseStatus, nil) as IOcspResponse) as IOcspResp;
    Exit;
  end;

  try
    LOctets := TDerOctetString.Create(AResponse.GetEncoded()) as IAsn1OctetString;
  except
    on E: Exception do
      raise EOcspCryptoLibException.CreateResFmt(@SOcspGenEncodeFailed, [E.Message]);
  end;

  LResponseBytes := TResponseBytes.Create(TOcspObjectIdentifiers.PkixOcspBasic, LOctets)
    as IResponseBytes;

  Result := TOcspResp.Create(TOcspResponse.Create(TOcspResponseStatus.Create(AStatus)
    as IOcspResponseStatus, LResponseBytes) as IOcspResponse) as IOcspResp;
end;

end.
