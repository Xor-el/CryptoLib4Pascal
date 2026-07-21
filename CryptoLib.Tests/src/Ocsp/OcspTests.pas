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

unit OcspTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509Asn1Generators,
  ClpIX509Asn1Generators,
  ClpIOcspAsn1Objects,
  ClpOcspAsn1Objects,
  ClpOcspObjectIdentifiers,
  ClpIOcspProtocolObjects,
  ClpOcspProtocolObjects,
  ClpIOcspGenerators,
  ClpOcspGenerators,
  ClpIX509Certificate,
  ClpX509Certificate,
  ClpIX509Crl,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpIStore,
  ClpCollectionStore,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixCertPathValidator,
  ClpPkixCertRevocationCheckerParameters,
  ClpPkixOcspRevocationChecker,
  ClpPkixRevocationChecker,
  ClpDateTimeHelper,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpNullable,
  ClpCryptoLibTypes,
  CertTestUtilities,
  CertVectors,
  CryptoLibTestBase;

type

  /// <summary>
  /// Covers the OCSP protocol layer (RFC 6960): request and response generation, parsing of
  /// responses produced elsewhere, and the PKIX revocation checker fed by those responses.
  /// </summary>
  TOcspTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  const
    SigAlgorithm = 'SHA256withRSA';

  var
    FKeyPair: IAsymmetricCipherKeyPair;
    FSignerCert: IX509Certificate;
    FRandom: ISecureRandom;

    FRootKeyPair, FInterKeyPair, FEndKeyPair: IAsymmetricCipherKeyPair;
    FRootCert, FInterCert, FEndCert: IX509Certificate;
    // one reference instant for the whole chain, so a CRL rebuilt across calls is byte-identical
    FChainUtcNow: TDateTime;

    function SignerChain: TCryptoLibGenericArray<IX509Certificate>;
    function NewCertificateID(const ASerial: TBigInteger): ICertificateID;
    function NewSignedResponse(const ACertId: ICertificateID;
      const AStatus: ICertificateStatus): IBasicOcspResp;
    function NewParameters: IPkixParameters;
    /// <summary>An OCSP checker over AResponses, initialized against the signer certificate.</summary>
    function NewChecker(const AResponses: TCryptoLibGenericArray<IBasicOcspResp>)
      : IPkixCertRevocationChecker;
    /// <summary>True when the checker settled the status; False when it left it undecided.</summary>
    function Settles(const AChecker: IPkixCertRevocationChecker;
      const ACert: IX509Certificate): Boolean;
    function LoadResponse(const AVectorId: string): IOcspResp;

    /// <summary>
    /// Builds the root -> intermediate -> end entity chain and the CRLs that cover it, once per
    /// test. The private keys are kept because only the issuer of a certificate can sign an
    /// authoritative OCSP response about it (RFC 6960 sec. 4.2.2.2).
    /// </summary>
    procedure EnsureChain;
    function NewCrl(const AIssuerCert: IX509Certificate;
      const AIssuerKey: IAsymmetricKeyParameter; const ARevokedSerial: TBigInteger): IX509Crl;
    /// <summary>An OCSP response about ASerial as issued by AIssuerCert, signed by ASignerKey.</summary>
    function NewResponse(const AIssuerCert: IX509Certificate; const ASerial: TBigInteger;
      const AStatus: ICertificateStatus; const ASignerKey: IAsymmetricCipherKeyPair;
      const ASignerChain: TCryptoLibGenericArray<IX509Certificate>;
      AThisUpdateOffsetMinutes: Int32): IBasicOcspResp;
    /// <summary>Parameters over the generated chain; the CRLs revoke the end entity on request.</summary>
    function NewChainParameters(ACrlRevokesEndEntity: Boolean): IPkixParameters;
    /// <summary>A revocation checker over AResponses, ready to hand to the parameters.</summary>
    function NewPathChecker(const AResponses: TCryptoLibGenericArray<IBasicOcspResp>)
      : IPkixCertPathChecker;
    /// <summary>
    /// Runs the generated chain through the validator. True when the path validated; otherwise the
    /// out parameters describe the failure so two runs can be compared.
    /// </summary>
    function ValidateChain(const AParams: IPkixParameters; out AIndex: Int32;
      out AMessage: String; out ARecoverable: Boolean): Boolean;

  protected
    procedure SetUp; override;

  published
    procedure TestUnsignedRequestGeneration;
    procedure TestSignedRequestRoundTrip;
    procedure TestRequestNonceExtension;
    procedure TestSignedRequestNeedsRequestorName;
    procedure TestBasicResponseRoundTrip;
    procedure TestRevokedAndUnknownStatus;
    procedure TestNonSuccessfulResponseHasNoBytes;
    procedure TestCertificateIDMatchesIssuerAndDerives;
    procedure TestParseResponseWithResponderChain;
    procedure TestParseSecondResponseWithResponderChain;
    procedure TestIrregularVersionRequestVerifies;
    procedure TestRevocationCheckerIsInertWithoutResponses;
    procedure TestRevocationCheckerAcceptsGoodStatus;
    procedure TestRevocationCheckerRejectsRevokedStatus;
    procedure TestRevocationCheckerIgnoresUnrelatedResponse;
    procedure TestRevocationCheckerIgnoresUnauthorisedSigner;
    procedure TestPathRejectedOnRevokedOcspStatus;
    procedure TestSilentOcspLeavesOutcomeToCrls;
    procedure TestPathAcceptsDespiteUnauthorisedOcspSigner;
    procedure TestPathAcceptsDespiteStaleOcspResponse;
    procedure TestPathAcceptsDespiteUnrelatedOcspResponse;
    procedure TestTwoRevocationCheckersRejected;
    procedure TestDefaultRevocationCheckerRunsCrls;
  end;

implementation

{ TOcspTest }

procedure TOcspTest.SetUp;
begin
  inherited SetUp;
  FRandom := TSecureRandom.Create();
  FKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  FSignerCert := TCertTestUtilities.GenerateRootCert(FKeyPair);
end;

function TOcspTest.SignerChain: TCryptoLibGenericArray<IX509Certificate>;
begin
  Result := TCryptoLibGenericArray<IX509Certificate>.Create(FSignerCert);
end;

function TOcspTest.NewCertificateID(const ASerial: TBigInteger): ICertificateID;
begin
  Result := TCertificateID.Create(TCertificateID.DigestSha1, FSignerCert, ASerial)
    as ICertificateID;
end;

function TOcspTest.NewSignedResponse(const ACertId: ICertificateID;
  const AStatus: ICertificateStatus): IBasicOcspResp;
var
  LGen: IBasicOcspRespGenerator;
begin
  LGen := TBasicOcspRespGenerator.Create(FKeyPair.Public as IAsymmetricKeyParameter)
    as IBasicOcspRespGenerator;
  // a window that brackets "now" so the checker's currency test passes
  LGen.AddResponse(ACertId, AStatus, IncMinute(Now.ToUniversalTime(), -1),
    TNullable<TDateTime>.Some(IncMinute(Now.ToUniversalTime(), 10)), nil);
  Result := LGen.Generate(SigAlgorithm, FKeyPair.Private as IAsymmetricKeyParameter, SignerChain,
    Now.ToUniversalTime(), FRandom);
end;

function TOcspTest.NewParameters: IPkixParameters;
begin
  Result := TPkixParameters.Create(TCryptoLibGenericArray<ITrustAnchor>.Create
    (TTrustAnchor.Create(FSignerCert, nil) as ITrustAnchor));
end;

function TOcspTest.NewChecker(const AResponses: TCryptoLibGenericArray<IBasicOcspResp>)
  : IPkixCertRevocationChecker;
begin
  Result := TPkixOcspRevocationChecker.Create(AResponses) as IPkixCertRevocationChecker;
  Result.Initialize(TPkixCertRevocationCheckerParameters.Create(NewParameters,
    Now.ToUniversalTime(), nil, 0, FSignerCert, FKeyPair.Public as IAsymmetricKeyParameter)
    as IPkixCertRevocationCheckerParameters);
end;

function TOcspTest.Settles(const AChecker: IPkixCertRevocationChecker;
  const ACert: IX509Certificate): Boolean;
begin
  try
    AChecker.Check(ACert);
    Result := True;
  except
    on E: ERecoverablePkixCertPathValidatorCryptoLibException do
      Result := False;
  end;
end;

function TOcspTest.LoadResponse(const AVectorId: string): IOcspResp;
begin
  Result := TOcspResp.Create(TCertVectors.LoadDer(AVectorId)) as IOcspResp;
end;

procedure TOcspTest.TestUnsignedRequestGeneration;
var
  LGen: IOcspReqGenerator;
  LId: ICertificateID;
  LReq: IOcspReq;
  LRequests: TCryptoLibGenericArray<IReq>;
begin
  LId := NewCertificateID(TBigInteger.One);

  LGen := TOcspReqGenerator.Create() as IOcspReqGenerator;
  LGen.AddRequest(LId);
  LReq := LGen.Generate();

  CheckFalse(LReq.IsSigned, 'an unsigned request must not report a signature');
  CheckEquals(0, System.Length(LReq.GetCerts()), 'an unsigned request carries no certificates');
  CheckNull(LReq.GetCertificates(), 'an unsigned request has no certificate store');
  CheckEquals(1, LReq.Version, 'the default request version is v1');

  LRequests := LReq.GetRequestList();
  CheckEquals(1, System.Length(LRequests), 'the request list has the one entry added');
  CheckTrue(LRequests[0].GetCertID().Equals(LId), 'the request is for the identifier supplied');
end;

procedure TOcspTest.TestSignedRequestRoundTrip;
var
  LGen: IOcspReqGenerator;
  LId: ICertificateID;
  LReq, LDecoded: IOcspReq;
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  LId := NewCertificateID(TBigInteger.One);

  LGen := TOcspReqGenerator.Create() as IOcspReqGenerator;
  LGen.SetRequestorName(TX509Name.Create('CN=Test Requestor') as IX509Name);
  LGen.AddRequest(LId);
  LReq := LGen.Generate(SigAlgorithm, FKeyPair.Private as IAsymmetricKeyParameter, SignerChain,
    FRandom);

  CheckTrue(LReq.IsSigned, 'a signed request reports a signature');
  CheckTrue(LReq.Verify(FKeyPair.Public as IAsymmetricKeyParameter),
    'the signature verifies with the signer public key');
  CheckTrue(System.Length(LReq.GetSignature()) > 0, 'the signature octets are present');
  CheckEquals(FSignerCert.GetSigAlgOid(), LReq.SignatureAlgOid,
    'the signature algorithm OID is the one signed with');

  LCerts := LReq.GetCerts();
  CheckEquals(1, System.Length(LCerts), 'the signer certificate travels with the request');
  CheckTrue(LCerts[0].Equals(FSignerCert), 'the carried certificate is the signer certificate');
  CheckNotNull(LReq.GetCertificates(), 'a signed request exposes a certificate store');

  LDecoded := TOcspReq.Create(LReq.GetEncoded()) as IOcspReq;
  CheckTrue(LDecoded.Verify(FKeyPair.Public as IAsymmetricKeyParameter),
    'the re-decoded request still verifies');
  CheckTrue(LDecoded.GetRequestList()[0].GetCertID().Equals(LId),
    'the re-decoded request is for the same identifier');
end;

procedure TOcspTest.TestRequestNonceExtension;
var
  LGen: IOcspReqGenerator;
  LExtGen: IX509ExtensionsGenerator;
  LId: ICertificateID;
  LReq: IOcspReq;
  LNonce: TCryptoLibByteArray;
  LFound: IAsn1OctetString;
begin
  LId := NewCertificateID(TBigInteger.One);
  LNonce := FRandom.GenerateSeed(16);

  LExtGen := TX509ExtensionsGenerator.Create() as IX509ExtensionsGenerator;
  LExtGen.AddExtension(TOcspObjectIdentifiers.PkixOcspNonce, False,
    TDerOctetString.Create(LNonce) as IAsn1Encodable);

  LGen := TOcspReqGenerator.Create() as IOcspReqGenerator;
  LGen.SetRequestorName(TX509Name.Create('CN=Test Requestor') as IX509Name);
  LGen.SetRequestExtensions(LExtGen.Generate());
  LGen.AddRequest(LId);
  LReq := LGen.Generate(SigAlgorithm, FKeyPair.Private as IAsymmetricKeyParameter, SignerChain,
    FRandom);

  CheckEquals(0, System.Length(LReq.GetCriticalExtensionOids()),
    'the request carries no critical extensions');
  CheckEquals(1, System.Length(LReq.GetNonCriticalExtensionOids()),
    'the request carries exactly the nonce extension');

  LFound := TOcspUtilities.GetNonce(LReq);
  CheckNotNull(LFound, 'the nonce extension is found');
  CheckTrue(AreEqual(LNonce, LFound.GetOctets()), 'the nonce round-trips unchanged');
end;

procedure TOcspTest.TestSignedRequestNeedsRequestorName;
var
  LGen: IOcspReqGenerator;
begin
  LGen := TOcspReqGenerator.Create() as IOcspReqGenerator;
  LGen.AddRequest(NewCertificateID(TBigInteger.One));

  try
    LGen.Generate(SigAlgorithm, FKeyPair.Private as IAsymmetricKeyParameter, SignerChain,
      FRandom);
    Fail('signing without a requestor name must be rejected');
  except
    on E: EOcspCryptoLibException do
      CheckTrue(True);
  end;
end;

procedure TOcspTest.TestBasicResponseRoundTrip;
var
  LId: ICertificateID;
  LBasic, LDecodedBasic: IBasicOcspResp;
  LResp, LDecoded: IOcspResp;
  LSingles: TCryptoLibGenericArray<ISingleResp>;
begin
  LId := NewCertificateID(TBigInteger.One);
  LBasic := NewSignedResponse(LId, TCertificateStatus.Good);

  CheckTrue(LBasic.Verify(FKeyPair.Public as IAsymmetricKeyParameter),
    'the basic response verifies with the responder public key');
  CheckEquals(1, LBasic.Version, 'the default response version is v1');
  CheckEquals(1, System.Length(LBasic.GetCerts()),
    'the responder certificate travels with the response');
  CheckTrue(System.Length(LBasic.GetTbsResponseData()) > 0, 'the signed bytes are available');

  LSingles := LBasic.GetResponses();
  CheckEquals(1, System.Length(LSingles), 'the response has the one entry added');
  CheckNull(LSingles[0].GetCertStatus(), 'a good status is the nil status');
  CheckTrue(LSingles[0].NextUpdate.HasValue, 'the nextUpdate supplied is present');

  LResp := (TOcspRespGenerator.Create() as IOcspRespGenerator)
    .Generate(TOcspRespStatus.Successful, LBasic);
  CheckEquals(TOcspRespStatus.Successful, LResp.Status, 'the status is carried through');

  LDecoded := TOcspResp.Create(LResp.GetEncoded()) as IOcspResp;
  CheckEquals(TOcspRespStatus.Successful, LDecoded.Status,
    'the re-decoded response keeps its status');
  LDecodedBasic := LDecoded.GetResponseObject();
  CheckNotNull(LDecodedBasic, 'the re-decoded response carries a basic response');
  CheckTrue(LDecodedBasic.Equals(LBasic), 'the re-decoded basic response matches the original');
  CheckTrue(LDecoded.Equals(LResp), 'the re-decoded response matches the original');
end;

procedure TOcspTest.TestRevokedAndUnknownStatus;
var
  LRevokedAt: TDateTime;
  LBasic: IBasicOcspResp;
  LStatus: ICertificateStatus;
  LRevoked: IRevokedStatus;
begin
  LRevokedAt := IncDay(Now.ToUniversalTime(), -1);

  LBasic := NewSignedResponse(NewCertificateID(TBigInteger.Two),
    TRevokedStatus.Create(LRevokedAt, 1) as ICertificateStatus);
  LStatus := LBasic.GetResponses()[0].GetCertStatus();
  CheckTrue(Supports(LStatus, IRevokedStatus, LRevoked), 'a revoked status round-trips');
  CheckTrue(LRevoked.HasRevocationReason, 'the revocation reason is present');
  CheckEquals(1, LRevoked.RevocationReason, 'the revocation reason round-trips');
  // GeneralizedTime has second precision, so compare at that resolution
  CheckEquals(0, SecondsBetween(LRevokedAt, LRevoked.RevocationTime),
    'the revocation time round-trips');

  LBasic := NewSignedResponse(NewCertificateID(TBigInteger.Three),
    TUnknownStatus.Create() as ICertificateStatus);
  LStatus := LBasic.GetResponses()[0].GetCertStatus();
  CheckTrue(Supports(LStatus, IUnknownStatus), 'an unknown status round-trips');
end;

procedure TOcspTest.TestNonSuccessfulResponseHasNoBytes;
var
  LResp: IOcspResp;
begin
  LResp := (TOcspRespGenerator.Create() as IOcspRespGenerator)
    .Generate(TOcspRespStatus.TryLater, nil);

  CheckEquals(TOcspRespStatus.TryLater, LResp.Status, 'the non-successful status is carried');
  CheckNull(LResp.GetResponseObject(), 'a response with no bytes decodes to no object');
  CheckNull(LResp.GetRawResponse(), 'a response with no bytes has no raw octets');
end;

procedure TOcspTest.TestCertificateIDMatchesIssuerAndDerives;
var
  LId, LDerived: ICertificateID;
  LOtherCert: IX509Certificate;
begin
  LId := NewCertificateID(TBigInteger.One);

  CheckEquals('1.3.14.3.2.26', LId.HashAlgOid, 'RFC 6960 sec. 4.3 mandates the SHA-1 identifier');
  CheckTrue(LId.MatchesIssuer(FSignerCert), 'the identifier matches the issuer it came from');
  CheckTrue(System.Length(LId.GetIssuerNameHash()) > 0, 'the issuer name hash is present');
  CheckTrue(System.Length(LId.GetIssuerKeyHash()) > 0, 'the issuer key hash is present');

  LOtherCert := TCertTestUtilities.GenerateRootCert(TCertTestUtilities.GenerateRsaKeyPair(1024),
    TX509Name.Create('CN=Another Test CA') as IX509Name);
  CheckFalse(LId.MatchesIssuer(LOtherCert), 'the identifier does not match a different issuer');

  LDerived := TCertificateID.DeriveCertificateID(LId, TBigInteger.Two);
  CheckFalse(LDerived.Equals(LId), 'a different serial gives a different identifier');
  CheckTrue(LDerived.MatchesIssuer(FSignerCert), 'the derived identifier keeps the issuer hashes');
  CheckTrue(LDerived.SerialNumber.Equals(TBigInteger.Two), 'the derived serial is the new one');
end;

procedure TOcspTest.TestParseResponseWithResponderChain;
var
  LResp: IOcspResp;
  LBasic: IBasicOcspResp;
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  LResp := LoadResponse('OcspResponseTcsCa');
  CheckEquals(TOcspRespStatus.Successful, LResp.Status, 'the vector is a successful response');

  LBasic := LResp.GetResponseObject();
  CheckNotNull(LBasic, 'the vector carries a basic response');

  LCerts := LBasic.GetCerts();
  CheckTrue(System.Length(LCerts) > 0, 'the vector carries the responder certificate');
  CheckTrue(LBasic.Verify(LCerts[0].GetPublicKey()),
    'the response verifies with the responder key it carries');
  CheckTrue(System.Length(LBasic.GetResponses()) > 0, 'the vector has at least one entry');
  CheckNotNull(LBasic.GetResponderId(), 'the responder ID is present');
end;

procedure TOcspTest.TestParseSecondResponseWithResponderChain;
var
  LResp: IOcspResp;
  LBasic: IBasicOcspResp;
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LWrapped: IOcspResp;
begin
  LResp := LoadResponse('OcspResponseForumSystems');
  CheckEquals(TOcspRespStatus.Successful, LResp.Status, 'the vector is a successful response');

  LBasic := LResp.GetResponseObject();
  LCerts := LBasic.GetCerts();
  CheckTrue(System.Length(LCerts) > 0, 'the vector carries the responder certificate');
  CheckTrue(LBasic.Verify(LCerts[0].GetPublicKey()),
    'the response verifies with the responder key it carries');
  CheckTrue(System.Length(LBasic.GetResponses()) > 0, 'the vector has at least one entry');

  // re-wrapping a parsed basic response must give back an equal response object
  LWrapped := (TOcspRespGenerator.Create() as IOcspRespGenerator)
    .Generate(TOcspRespStatus.Successful, LBasic);
  CheckTrue(LWrapped.GetResponseObject().Equals(LBasic), 're-wrapping preserves the response');
end;

procedure TOcspTest.TestIrregularVersionRequestVerifies;
var
  LReq: IOcspReq;
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  // the vector spells out the DEFAULT version explicitly, which the decoder must accept
  LReq := TOcspReq.Create(TCertVectors.LoadDer('OcspRequestIrregularVersion')) as IOcspReq;

  LCerts := LReq.GetCerts();
  CheckTrue(System.Length(LCerts) > 0, 'the signed request carries certificates');
  CheckTrue(LReq.Verify(LCerts[0].GetPublicKey()),
    'the request verifies despite the explicit default version');
end;

procedure TOcspTest.TestRevocationCheckerIsInertWithoutResponses;
begin
  CheckFalse(Settles(NewChecker(nil), FSignerCert),
    'with no responses supplied the checker settles nothing and CRLs still run');
end;

procedure TOcspTest.TestRevocationCheckerAcceptsGoodStatus;
var
  LBasic: IBasicOcspResp;
begin
  LBasic := NewSignedResponse(NewCertificateID(FSignerCert.SerialNumber),
    TCertificateStatus.Good);

  CheckTrue(Settles(NewChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create(LBasic)), FSignerCert),
    'a good status settles the revocation check');
end;

procedure TOcspTest.TestRevocationCheckerRejectsRevokedStatus;
var
  LBasic: IBasicOcspResp;
  LChecker: IPkixCertRevocationChecker;
begin
  LBasic := NewSignedResponse(NewCertificateID(FSignerCert.SerialNumber),
    TRevokedStatus.Create(IncDay(Now.ToUniversalTime(), -1), 1) as ICertificateStatus);
  LChecker := NewChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create(LBasic));

  try
    LChecker.Check(FSignerCert);
    Fail('a revoked status must fail the path');
  except
    // a revoked status is decisive, never a recoverable one that would let CRLs answer instead
    on E: ERecoverablePkixCertPathValidatorCryptoLibException do
      Fail('a revoked status must fail the path');
    on E: EPkixCertPathValidatorCryptoLibException do
      CheckEquals(0, E.Index, 'the failure keeps the position of the certificate in the path');
  end;
end;

procedure TOcspTest.TestRevocationCheckerIgnoresUnrelatedResponse;
var
  LBasic: IBasicOcspResp;
  LOtherSerial: TBigInteger;
begin
  // a revoked status for some other serial number must not touch this certificate
  LOtherSerial := FSignerCert.SerialNumber.Add(TBigInteger.One);
  LBasic := NewSignedResponse(NewCertificateID(LOtherSerial),
    TRevokedStatus.Create(IncDay(Now.ToUniversalTime(), -1), 1) as ICertificateStatus);

  CheckFalse(Settles(NewChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create(LBasic)), FSignerCert),
    'a response about another certificate settles nothing');
end;

procedure TOcspTest.TestRevocationCheckerIgnoresUnauthorisedSigner;
var
  LBasic: IBasicOcspResp;
  LStrangerKey: IAsymmetricCipherKeyPair;
  LStrangerCert: IX509Certificate;
  LGen: IBasicOcspRespGenerator;
begin
  // a response signed by a key the issuer never delegated to is not authoritative
  LStrangerKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LStrangerCert := TCertTestUtilities.GenerateRootCert(LStrangerKey,
    TX509Name.Create('CN=Unrelated Responder') as IX509Name);

  LGen := TBasicOcspRespGenerator.Create(LStrangerKey.Public as IAsymmetricKeyParameter)
    as IBasicOcspRespGenerator;
  LGen.AddResponse(NewCertificateID(FSignerCert.SerialNumber),
    TRevokedStatus.Create(IncDay(Now.ToUniversalTime(), -1), 1) as ICertificateStatus, IncMinute(Now.ToUniversalTime(), -1),
    TNullable<TDateTime>.Some(IncMinute(Now.ToUniversalTime(), 10)), nil);
  LBasic := LGen.Generate(SigAlgorithm, LStrangerKey.Private as IAsymmetricKeyParameter,
    TCryptoLibGenericArray<IX509Certificate>.Create(LStrangerCert), Now.ToUniversalTime(), FRandom);

  CheckFalse(Settles(NewChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create(LBasic)), FSignerCert),
    'an unauthorised signer settles nothing, even when it claims revocation');
end;

procedure TOcspTest.EnsureChain;
begin
  if FRootCert <> nil then
    Exit;

  FChainUtcNow := Now.ToUniversalTime();

  FRootKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  FInterKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  FEndKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);

  FRootCert := TCertTestUtilities.GenerateRootCert(FRootKeyPair,
    TX509Name.Create('CN=Ocsp Path Root CA') as IX509Name);
  FInterCert := TCertTestUtilities.GenerateEndEntityCert
    (FInterKeyPair.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Ocsp Path Intermediate CA') as IX509Name,
    FRootKeyPair.Private as IAsymmetricKeyParameter, FRootCert);
  FEndCert := TCertTestUtilities.GenerateEndEntityCert
    (FEndKeyPair.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Ocsp Path End Entity') as IX509Name,
    FInterKeyPair.Private as IAsymmetricKeyParameter, FInterCert);
end;

function TOcspTest.NewCrl(const AIssuerCert: IX509Certificate;
  const AIssuerKey: IAsymmetricKeyParameter; const ARevokedSerial: TBigInteger): IX509Crl;
var
  LGen: IX509V2CrlGenerator;
  LUtcNow: TDateTime;
begin
  // the chain's reference instant, not a fresh clock read, so two builds of the same CRL match
  LUtcNow := FChainUtcNow;

  LGen := TX509V2CrlGenerator.Create() as IX509V2CrlGenerator;
  LGen.SetIssuerDN(AIssuerCert.SubjectDN);
  LGen.SetThisUpdateUtc(IncMinute(LUtcNow, -1));
  LGen.SetNextUpdateUtc(IncMinute(LUtcNow, 10));

  if ARevokedSerial.IsInitialized then
    LGen.AddCrlEntryUtc(ARevokedSerial, IncMinute(LUtcNow, -1), TCrlReason.KeyCompromise);

  Result := LGen.Generate(TAsn1SignatureFactory.Create(SigAlgorithm, AIssuerKey, FRandom)
    as ISignatureFactory);
end;

function TOcspTest.NewResponse(const AIssuerCert: IX509Certificate; const ASerial: TBigInteger;
  const AStatus: ICertificateStatus; const ASignerKey: IAsymmetricCipherKeyPair;
  const ASignerChain: TCryptoLibGenericArray<IX509Certificate>;
  AThisUpdateOffsetMinutes: Int32): IBasicOcspResp;
var
  LGen: IBasicOcspRespGenerator;
  LThisUpdate: TDateTime;
begin
  LThisUpdate := IncMinute(Now.ToUniversalTime(), AThisUpdateOffsetMinutes);

  LGen := TBasicOcspRespGenerator.Create(ASignerKey.Public as IAsymmetricKeyParameter)
    as IBasicOcspRespGenerator;
  LGen.AddResponse(TCertificateID.Create(TCertificateID.DigestSha1, AIssuerCert, ASerial)
    as ICertificateID, AStatus, LThisUpdate,
    TNullable<TDateTime>.Some(IncMinute(LThisUpdate, 10)), nil);
  Result := LGen.Generate(SigAlgorithm, ASignerKey.Private as IAsymmetricKeyParameter,
    ASignerChain, Now.ToUniversalTime(), FRandom);
end;

function TOcspTest.NewChainParameters(ACrlRevokesEndEntity: Boolean): IPkixParameters;
var
  LCertStore: IStore<IX509Certificate>;
  LCrlStore: IStore<IX509Crl>;
  LEndSerial: TBigInteger;
begin
  EnsureChain;

  if ACrlRevokesEndEntity then
    LEndSerial := FEndCert.SerialNumber
  else
    LEndSerial := Default(TBigInteger);

  // a generic interface carries no GUID, so these upcast through typed locals instead of "as"
  LCertStore := TCollectionStore<IX509Certificate>.Create
    (TCryptoLibGenericArray<IX509Certificate>.Create(FRootCert, FInterCert, FEndCert));
  LCrlStore := TCollectionStore<IX509Crl>.Create(TCryptoLibGenericArray<IX509Crl>.Create
    (NewCrl(FRootCert, FRootKeyPair.Private as IAsymmetricKeyParameter, Default(TBigInteger)),
    NewCrl(FInterCert, FInterKeyPair.Private as IAsymmetricKeyParameter, LEndSerial)));

  Result := TPkixParameters.Create(TCryptoLibGenericArray<ITrustAnchor>.Create
    (TTrustAnchor.Create(FRootCert, nil) as ITrustAnchor)) as IPkixParameters;
  Result.AddStoreCert(LCertStore);
  Result.AddStoreCrl(LCrlStore);
  Result.IsRevocationEnabled := True;
end;

function TOcspTest.NewPathChecker(const AResponses: TCryptoLibGenericArray<IBasicOcspResp>)
  : IPkixCertPathChecker;
begin
  Result := TPkixRevocationChecker.Create(AResponses) as IPkixCertPathChecker;
end;

function TOcspTest.ValidateChain(const AParams: IPkixParameters; out AIndex: Int32;
  out AMessage: String; out ARecoverable: Boolean): Boolean;
var
  LPath: IPkixCertPath;
  LValidator: IPkixCertPathValidator;
begin
  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(FEndCert,
    FInterCert)) as IPkixCertPath;

  AIndex := -1;
  AMessage := '';
  ARecoverable := False;

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  try
    LValidator.Validate(LPath, AParams);
    Result := True;
  except
    on E: EPkixCertPathValidatorCryptoLibException do
    begin
      Result := False;
      AIndex := E.Index;
      AMessage := E.Message;
      ARecoverable := E is ERecoverablePkixCertPathValidatorCryptoLibException;
    end;
  end;
end;

procedure TOcspTest.TestPathRejectedOnRevokedOcspStatus;
var
  LParams: IPkixParameters;
  LIndex: Int32;
  LMessage: String;
  LRecoverable: Boolean;
begin
  // the CRLs revoke nothing, so only the OCSP response can reject this path
  LParams := NewChainParameters(False);
  LParams.AddCertPathChecker(NewPathChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create
    (NewResponse(FRootCert, FInterCert.SerialNumber,
    TRevokedStatus.Create(IncDay(Now.ToUniversalTime(), -1), 1) as ICertificateStatus,
    FRootKeyPair, TCryptoLibGenericArray<IX509Certificate>.Create(FRootCert), -1))));

  CheckFalse(ValidateChain(LParams, LIndex, LMessage, LRecoverable),
    'an authoritative revoked status rejects the path');
  CheckFalse(LRecoverable,
    'a revoked status is decisive, never a recoverable failure that lets CRLs answer instead');
  CheckEquals(1, LIndex, 'the intermediate certificate is blamed');
end;

procedure TOcspTest.TestSilentOcspLeavesOutcomeToCrls;
var
  LParams: IPkixParameters;
  LSilentIndex, LBaselineIndex: Int32;
  LSilentMessage, LBaselineMessage: String;
  LRecoverable: Boolean;
begin
  // with no responses to offer, the OCSP mechanism must hand over rather than fail the path
  LParams := NewChainParameters(False);
  LParams.AddCertPathChecker(NewPathChecker(nil));
  CheckTrue(ValidateChain(LParams, LSilentIndex, LSilentMessage, LRecoverable),
    'a silent OCSP mechanism leaves the clean CRLs to accept the path');

  LParams := NewChainParameters(True);
  LParams.AddCertPathChecker(NewPathChecker(nil));
  CheckFalse(ValidateChain(LParams, LSilentIndex, LSilentMessage, LRecoverable),
    'a silent OCSP mechanism leaves the revoking CRL to reject the path');

  LParams := NewChainParameters(True);
  CheckFalse(ValidateChain(LParams, LBaselineIndex, LBaselineMessage, LRecoverable),
    'the same path with no checker supplied is rejected too');

  CheckEquals(LBaselineIndex, LSilentIndex, 'the silent mechanism changes nothing about the blame');
  CheckEquals(LBaselineMessage, LSilentMessage,
    'the silent mechanism changes nothing about the outcome');
end;

procedure TOcspTest.TestPathAcceptsDespiteUnauthorisedOcspSigner;
var
  LParams: IPkixParameters;
  LStrangerKeyPair: IAsymmetricCipherKeyPair;
  LStrangerCert: IX509Certificate;
  LIndex: Int32;
  LMessage: String;
  LRecoverable: Boolean;
begin
  EnsureChain;

  // a responder the issuer never delegated to is not authoritative (RFC 6960 sec. 4.2.2.2)
  LStrangerKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LStrangerCert := TCertTestUtilities.GenerateRootCert(LStrangerKeyPair,
    TX509Name.Create('CN=Ocsp Path Unrelated Responder') as IX509Name);

  LParams := NewChainParameters(False);
  LParams.AddCertPathChecker(NewPathChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create
    (NewResponse(FRootCert, FInterCert.SerialNumber,
    TRevokedStatus.Create(IncDay(Now.ToUniversalTime(), -1), 1) as ICertificateStatus,
    LStrangerKeyPair, TCryptoLibGenericArray<IX509Certificate>.Create(LStrangerCert), -1))));

  CheckTrue(ValidateChain(LParams, LIndex, LMessage, LRecoverable),
    'an unauthorised revoked status is ignored and the clean CRLs accept the path');
end;

procedure TOcspTest.TestPathAcceptsDespiteStaleOcspResponse;
var
  LParams: IPkixParameters;
  LIndex: Int32;
  LMessage: String;
  LRecoverable: Boolean;
begin
  EnsureChain;

  // a thisUpdate still in the future puts the response outside its currency window
  LParams := NewChainParameters(False);
  LParams.AddCertPathChecker(NewPathChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create
    (NewResponse(FRootCert, FInterCert.SerialNumber,
    TRevokedStatus.Create(IncDay(Now.ToUniversalTime(), -1), 1) as ICertificateStatus,
    FRootKeyPair, TCryptoLibGenericArray<IX509Certificate>.Create(FRootCert), 60))));

  CheckTrue(ValidateChain(LParams, LIndex, LMessage, LRecoverable),
    'a response outside its currency window is ignored and the clean CRLs accept the path');
end;

procedure TOcspTest.TestPathAcceptsDespiteUnrelatedOcspResponse;
var
  LParams: IPkixParameters;
  LIndex: Int32;
  LMessage: String;
  LRecoverable: Boolean;
begin
  EnsureChain;

  // an authoritative response, but about a serial number that is not in this path
  LParams := NewChainParameters(False);
  LParams.AddCertPathChecker(NewPathChecker(TCryptoLibGenericArray<IBasicOcspResp>.Create
    (NewResponse(FRootCert, FInterCert.SerialNumber.Add(TBigInteger.One),
    TRevokedStatus.Create(IncDay(Now.ToUniversalTime(), -1), 1) as ICertificateStatus,
    FRootKeyPair, TCryptoLibGenericArray<IX509Certificate>.Create(FRootCert), -1))));

  CheckTrue(ValidateChain(LParams, LIndex, LMessage, LRecoverable),
    'a response about another certificate is ignored and the clean CRLs accept the path');
end;

procedure TOcspTest.TestTwoRevocationCheckersRejected;
var
  LParams: IPkixParameters;
  LIndex: Int32;
  LMessage: String;
  LRecoverable: Boolean;
begin
  LParams := NewChainParameters(False);
  LParams.AddCertPathChecker(NewPathChecker(nil));
  LParams.AddCertPathChecker(NewPathChecker(nil));

  CheckFalse(ValidateChain(LParams, LIndex, LMessage, LRecoverable),
    'a second revocation checker among the path checkers is rejected');
  CheckEquals(SMultipleRevocationCheckers, LMessage,
    'the failure names the single revocation checker rule');
end;

procedure TOcspTest.TestDefaultRevocationCheckerRunsCrls;
var
  LParams: IPkixParameters;
  LIndex: Int32;
  LMessage: String;
  LRecoverable: Boolean;
begin
  // with revocation on and no checker supplied, the default one must still consult the CRLs
  LParams := NewChainParameters(True);
  CheckFalse(ValidateChain(LParams, LIndex, LMessage, LRecoverable),
    'the default revocation checker rejects a certificate the CRL revokes');
  CheckEquals(0, LIndex, 'the end entity certificate is blamed');

  // the same path passes once revocation checking is off, so the rejection came from the CRL
  LParams := NewChainParameters(True);
  LParams.IsRevocationEnabled := False;
  CheckTrue(ValidateChain(LParams, LIndex, LMessage, LRecoverable),
    'without revocation checking the very same path validates');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TOcspTest);
{$ELSE}
  RegisterTest(TOcspTest.Suite);
{$ENDIF FPC}

end.
