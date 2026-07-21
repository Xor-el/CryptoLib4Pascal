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

unit AttrCertPathTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
  Generics.Collections,
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
  ClpIX509Attribute,
  ClpX509Attribute,
  ClpIAttributeCertificateHolder,
  ClpAttributeCertificateHolder,
  ClpIAttributeCertificateIssuer,
  ClpAttributeCertificateIssuer,
  ClpIX509V2AttributeCertificate,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpIX509Certificate,
  ClpIStore,
  ClpCollectionStore,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixAttrCertPathValidator,
  ClpPkixAttrCertChecker,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpDateTimeHelper,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpCryptoLibTypes,
  CertTestUtilities,
  CryptoLibTestBase;

type

  /// <summary>
  /// A concrete attribute certificate checker for the tests: it resolves (removes) exactly one
  /// critical extension OID so ProcessAttrCert7 can be driven both with and without a resolver.
  /// </summary>
  TResolvingAttrCertChecker = class(TPkixAttrCertCheckerBase)
  strict private
    FOid: String;
  public
    constructor Create(const AOid: String);
    function GetSupportedExtensions: TCryptoLibStringArray; override;
    procedure Check(const AAttrCert: IX509V2AttributeCertificate; const ACertPath: IPkixCertPath;
      const AHolderCertPath: IPkixCertPath; const AUnresolvedCritExts: TList<String>); override;
    function Clone: IPkixAttrCertChecker; override;
  end;

  /// <summary>
  /// Exercises attribute certificate path validation (RFC 3281 sec. 5) through
  /// <see cref="TPkixAttrCertPathValidator.Validate"/>. Certificates, the attribute certificate and
  /// the issuer certification path are all minted at runtime because the checks need the private keys
  /// (the AC must be signed by the issuer key under test).
  /// </summary>
  TAttrCertPathTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  const
    SigAlgorithm = 'SHA256withRSA';
    // RFC 3281 sec. 4.4.5 role attribute OID; used only as an attribute the AC carries
    RoleAttrOid = '2.5.4.72';
    // an OID no checker understands, for the critical-extension tests
    UnknownCriticalOid = '1.3.6.1.4.1.99999.1.1';

  var
    FRandom: ISecureRandom;
    FSerialSeq: Int64;

    FRootKeyPair, FIssuerKeyPair, FHolderKeyPair: IAsymmetricCipherKeyPair;
    FRootCert, FIssuerCert, FHolderCert: IX509Certificate;

    procedure EnsureCerts;
    function NextSerial: TBigInteger;

    /// <summary>A non-CA leaf under the root asserting the given key usage bits; the RFC 3281 AC
    /// issuer must not itself be a public key certificate issuer, so no basic constraints are set.</summary>
    function BuildLeafCert(const ASubject: IX509Name; const APublicKey: IAsymmetricKeyParameter;
      const AIssuerKey: IAsymmetricKeyParameter; AKeyUsageBits: Int32): IX509Certificate;

    function BuildAttribute(const AOid: String): IX509Attribute;

    /// <summary>An attribute certificate for the given holder, signed by the given issuer key, valid
    /// over [ANotBefore, ANotAfter] (UTC), optionally carrying a critical extension.</summary>
    function BuildAttrCert(const AHolderCert, AIssuerCert: IX509Certificate;
      const AIssuerKey: IAsymmetricKeyParameter; ANotBefore, ANotAfter: TDateTime;
      const AAttrOid, ACritExtOid: String): IX509V2AttributeCertificate;

    /// <summary>The issuer certification path handed to Validate: the AC issuer leaf under the root
    /// trust anchor.</summary>
    function IssuerPath: IPkixCertPath;

    function BuildParams(const AAttrCert: IX509V2AttributeCertificate; ATrustIssuer: Boolean;
      const AProhibited: TCryptoLibStringArray;
      const ACheckers: TCryptoLibGenericArray<IPkixAttrCertChecker>): IPkixParameters;

    /// <summary>Runs Validate; returns True on success, else False with the failure message.</summary>
    function TryValidate(const AAttrCert: IX509V2AttributeCertificate;
      const AParams: IPkixParameters; out AMessage: String): Boolean;

  protected
    procedure SetUp; override;

  published
    procedure TestValidAcPathValidates;
    procedure TestHolderMismatchRejected;
    procedure TestExpiredAcRejected;
    procedure TestProhibitedAttributeRejected;
    procedure TestUntrustedIssuerRejected;
    procedure TestIssuerKeyUsageRejected;
    procedure TestUnknownCriticalExtensionRejected;
    procedure TestCheckerResolvesCriticalExtension;
  end;

implementation

{ TResolvingAttrCertChecker }

constructor TResolvingAttrCertChecker.Create(const AOid: String);
begin
  inherited Create();
  FOid := AOid;
end;

function TResolvingAttrCertChecker.GetSupportedExtensions: TCryptoLibStringArray;
begin
  Result := TCryptoLibStringArray.Create(FOid);
end;

procedure TResolvingAttrCertChecker.Check(const AAttrCert: IX509V2AttributeCertificate;
  const ACertPath: IPkixCertPath; const AHolderCertPath: IPkixCertPath;
  const AUnresolvedCritExts: TList<String>);
begin
  AUnresolvedCritExts.Remove(FOid);
end;

function TResolvingAttrCertChecker.Clone: IPkixAttrCertChecker;
begin
  Result := TResolvingAttrCertChecker.Create(FOid) as IPkixAttrCertChecker;
end;

{ TAttrCertPathTest }

procedure TAttrCertPathTest.SetUp;
begin
  inherited SetUp;
  FRandom := TSecureRandom.Create();
  FSerialSeq := 700000000;
end;

function TAttrCertPathTest.NextSerial: TBigInteger;
begin
  Inc(FSerialSeq);
  Result := TBigInteger.ValueOf(FSerialSeq);
end;

function TAttrCertPathTest.BuildLeafCert(const ASubject: IX509Name;
  const APublicKey: IAsymmetricKeyParameter; const AIssuerKey: IAsymmetricKeyParameter;
  AKeyUsageBits: Int32): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
  LUtcNow: TDateTime;
begin
  LUtcNow := Now.ToUniversalTime();
  LGen := TX509V3CertificateGenerator.Create;
  LGen.SetSerialNumber(NextSerial);
  LGen.SetIssuerDN(FRootCert.SubjectDN);
  LGen.SetNotBeforeUtc(IncSecond(LUtcNow, -5));
  LGen.SetNotAfterUtc(IncMinute(LUtcNow, 30));
  LGen.SetSubjectDN(ASubject);
  LGen.SetPublicKey(APublicKey);
  LGen.AddExtension(TX509Extensions.KeyUsage, True, TKeyUsage.Create(AKeyUsageBits) as IKeyUsage);
  Result := LGen.Generate(TAsn1SignatureFactory.Create(SigAlgorithm, AIssuerKey, FRandom)
    as ISignatureFactory);
end;

procedure TAttrCertPathTest.EnsureCerts;
begin
  if FRootCert <> nil then
    Exit;

  FRootKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  FRootCert := TCertTestUtilities.GenerateRootCert(FRootKeyPair,
    TX509Name.Create('CN=AC Test Root CA') as IX509Name);

  // the AC issuer: a non-CA leaf under the root that may sign digital signatures
  FIssuerKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  FIssuerCert := BuildLeafCert(TX509Name.Create('CN=AC Issuer') as IX509Name,
    FIssuerKeyPair.Public as IAsymmetricKeyParameter,
    FRootKeyPair.Private as IAsymmetricKeyParameter, TKeyUsage.DigitalSignature);

  // the holder public key certificate, also chaining to the root
  FHolderKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  FHolderCert := TCertTestUtilities.GenerateEndEntityCert
    (FHolderKeyPair.Public as IAsymmetricKeyParameter, TX509Name.Create('CN=AC Holder') as IX509Name,
    FRootKeyPair.Private as IAsymmetricKeyParameter, FRootCert);
end;

function TAttrCertPathTest.BuildAttribute(const AOid: String): IX509Attribute;
var
  LAttr: IAttributeX509;
begin
  LAttr := TAttributeX509.Create(TDerObjectIdentifier.Create(AOid) as IDerObjectIdentifier,
    TDerSet.Create(TDerUtf8String.Create('cryptolib-test') as IAsn1Encodable) as IAsn1Set);
  Result := TX509Attribute.Create(LAttr as IAsn1Encodable) as IX509Attribute;
end;

function TAttrCertPathTest.BuildAttrCert(const AHolderCert, AIssuerCert: IX509Certificate;
  const AIssuerKey: IAsymmetricKeyParameter; ANotBefore, ANotAfter: TDateTime;
  const AAttrOid, ACritExtOid: String): IX509V2AttributeCertificate;
var
  LGen: IX509V2AttributeCertificateGenerator;
begin
  LGen := TX509V2AttributeCertificateGenerator.Create;
  LGen.SetHolder(TAttributeCertificateHolder.Create(AHolderCert) as IAttributeCertificateHolder);
  LGen.SetIssuer(TAttributeCertificateIssuer.Create(AIssuerCert.SubjectDN)
    as IAttributeCertificateIssuer);
  LGen.SetSerialNumber(NextSerial);
  LGen.SetNotBeforeUtc(ANotBefore);
  LGen.SetNotAfterUtc(ANotAfter);
  LGen.AddAttribute(BuildAttribute(AAttrOid));

  if ACritExtOid <> '' then
    LGen.AddExtension(ACritExtOid, True,
      TDerOctetString.Create(TCryptoLibByteArray.Create(1, 2, 3)) as IAsn1Encodable);

  Result := LGen.Generate(TAsn1SignatureFactory.Create(SigAlgorithm, AIssuerKey, FRandom)
    as ISignatureFactory);
end;

function TAttrCertPathTest.IssuerPath: IPkixCertPath;
begin
  Result := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(FIssuerCert))
    as IPkixCertPath;
end;

function TAttrCertPathTest.BuildParams(const AAttrCert: IX509V2AttributeCertificate;
  ATrustIssuer: Boolean; const AProhibited: TCryptoLibStringArray;
  const ACheckers: TCryptoLibGenericArray<IPkixAttrCertChecker>): IPkixParameters;
var
  LCertStore: IStore<IX509Certificate>;
  LSelector: IX509AttrCertStoreSelector;
begin
  LCertStore := TCollectionStore<IX509Certificate>.Create
    (TCryptoLibGenericArray<IX509Certificate>.Create(FRootCert, FIssuerCert, FHolderCert));

  LSelector := TX509AttrCertStoreSelector.Create() as IX509AttrCertStoreSelector;
  LSelector.AttributeCert := AAttrCert;

  Result := TPkixParameters.Create(TCryptoLibGenericArray<ITrustAnchor>.Create
    (TTrustAnchor.Create(FRootCert, nil) as ITrustAnchor)) as IPkixParameters;
  Result.AddStoreCert(LCertStore);
  // keep the path checks self-contained: no CRLs are minted for the holder / issuer paths
  Result.IsRevocationEnabled := False;
  // IX509AttrCertStoreSelector derives from ISelector<IX509V2AttributeCertificate>
  Result.SetTargetConstraintsAttrCert(LSelector);

  if ATrustIssuer then
    Result.SetTrustedACIssuers(TCryptoLibGenericArray<ITrustAnchor>.Create
      (TTrustAnchor.Create(FIssuerCert, nil) as ITrustAnchor));

  if AProhibited <> nil then
    Result.SetProhibitedACAttributes(AProhibited);

  if ACheckers <> nil then
    Result.SetAttrCertCheckers(ACheckers);
end;

function TAttrCertPathTest.TryValidate(const AAttrCert: IX509V2AttributeCertificate;
  const AParams: IPkixParameters; out AMessage: String): Boolean;
var
  LResult: IPkixCertPathValidatorResult;
  LValidator: IPkixAttrCertPathValidator;
begin
  AMessage := '';
  try
    LValidator := TPkixAttrCertPathValidator.Create();
    LResult := LValidator.Validate(IssuerPath, AParams);
    Result := LResult <> nil;
  except
    on E: Exception do
    begin
      AMessage := E.Message;
      Result := False;
    end;
  end;
end;

procedure TAttrCertPathTest.TestValidAcPathValidates;
var
  LUtcNow: TDateTime;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();
  LAttrCert := BuildAttrCert(FHolderCert, FIssuerCert,
    FIssuerKeyPair.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -1),
    IncMinute(LUtcNow, 30), RoleAttrOid, '');

  LParams := BuildParams(LAttrCert, True, nil, nil);

  CheckTrue(TryValidate(LAttrCert, LParams, LMessage),
    'a well-formed attribute certificate path must validate: ' + LMessage);
end;

procedure TAttrCertPathTest.TestHolderMismatchRejected;
var
  LUtcNow: TDateTime;
  LStrangerKey: IAsymmetricCipherKeyPair;
  LStrangerCert: IX509Certificate;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();

  // the holder names a certificate that is not in the stores, so step 1 cannot bind it
  LStrangerKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LStrangerCert := TCertTestUtilities.GenerateEndEntityCert
    (LStrangerKey.Public as IAsymmetricKeyParameter, TX509Name.Create('CN=AC Stranger') as IX509Name,
    FRootKeyPair.Private as IAsymmetricKeyParameter, FRootCert);

  LAttrCert := BuildAttrCert(LStrangerCert, FIssuerCert,
    FIssuerKeyPair.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -1),
    IncMinute(LUtcNow, 30), RoleAttrOid, '');

  LParams := BuildParams(LAttrCert, True, nil, nil);

  CheckFalse(TryValidate(LAttrCert, LParams, LMessage),
    'an attribute certificate whose holder is absent from the stores must be rejected');
  CheckTrue(Pos('public key certificate', LMessage) > 0,
    'the rejection must come from locating the holder (step 1), got: ' + LMessage);
end;

procedure TAttrCertPathTest.TestExpiredAcRejected;
var
  LUtcNow: TDateTime;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();

  // validity window wholly in the past: only ProcessAttrCert5 can reject this
  LAttrCert := BuildAttrCert(FHolderCert, FIssuerCert,
    FIssuerKeyPair.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -60),
    IncMinute(LUtcNow, -30), RoleAttrOid, '');

  LParams := BuildParams(LAttrCert, True, nil, nil);

  CheckFalse(TryValidate(LAttrCert, LParams, LMessage),
    'an expired attribute certificate must be rejected');
  CheckTrue(Pos('not valid', LMessage) > 0,
    'the rejection must come from the validity check (step 5), got: ' + LMessage);
end;

procedure TAttrCertPathTest.TestProhibitedAttributeRejected;
var
  LUtcNow: TDateTime;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();
  LAttrCert := BuildAttrCert(FHolderCert, FIssuerCert,
    FIssuerKeyPair.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -1),
    IncMinute(LUtcNow, 30), RoleAttrOid, '');

  // the params forbid the exact attribute the AC carries (RFC 3281 sec. 4.3)
  LParams := BuildParams(LAttrCert, True, TCryptoLibStringArray.Create(RoleAttrOid), nil);

  CheckFalse(TryValidate(LAttrCert, LParams, LMessage),
    'an attribute certificate carrying a prohibited attribute must be rejected');
  CheckTrue(Pos('prohibited attribute', LMessage) > 0,
    'the rejection must name the prohibited attribute, got: ' + LMessage);
end;

procedure TAttrCertPathTest.TestUntrustedIssuerRejected;
var
  LUtcNow: TDateTime;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();
  LAttrCert := BuildAttrCert(FHolderCert, FIssuerCert,
    FIssuerKeyPair.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -1),
    IncMinute(LUtcNow, 30), RoleAttrOid, '');

  // no directly trusted AC issuers are configured, so step 4 must reject
  LParams := BuildParams(LAttrCert, False, nil, nil);

  CheckFalse(TryValidate(LAttrCert, LParams, LMessage),
    'an attribute certificate whose issuer is not directly trusted must be rejected');
  CheckTrue(Pos('not directly trusted', LMessage) > 0,
    'the rejection must come from the trusted-issuer check (step 4), got: ' + LMessage);
end;

procedure TAttrCertPathTest.TestIssuerKeyUsageRejected;
var
  LUtcNow: TDateTime;
  LBadIssuerKey: IAsymmetricCipherKeyPair;
  LBadIssuerCert: IX509Certificate;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
  LSavedIssuerCert: IX509Certificate;
  LSavedIssuerKey: IAsymmetricCipherKeyPair;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();

  // an AC issuer whose key usage asserts neither digitalSignature nor nonRepudiation (step 3)
  LBadIssuerKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LBadIssuerCert := BuildLeafCert(TX509Name.Create('CN=AC Issuer No DigSig') as IX509Name,
    LBadIssuerKey.Public as IAsymmetricKeyParameter,
    FRootKeyPair.Private as IAsymmetricKeyParameter, TKeyUsage.KeyEncipherment);

  // the issuer path handed to Validate and the signature must match this bad issuer
  LSavedIssuerCert := FIssuerCert;
  LSavedIssuerKey := FIssuerKeyPair;
  FIssuerCert := LBadIssuerCert;
  FIssuerKeyPair := LBadIssuerKey;
  try
    LAttrCert := BuildAttrCert(FHolderCert, LBadIssuerCert,
      LBadIssuerKey.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -1),
      IncMinute(LUtcNow, 30), RoleAttrOid, '');

    LParams := BuildParams(LAttrCert, True, nil, nil);

    CheckFalse(TryValidate(LAttrCert, LParams, LMessage),
      'an AC issuer that cannot sign digital signatures must be rejected');
    CheckTrue(Pos('digital signatures', LMessage) > 0,
      'the rejection must come from the issuer key-usage check (step 3), got: ' + LMessage);
  finally
    FIssuerCert := LSavedIssuerCert;
    FIssuerKeyPair := LSavedIssuerKey;
  end;
end;

procedure TAttrCertPathTest.TestUnknownCriticalExtensionRejected;
var
  LUtcNow: TDateTime;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();

  // a critical extension no checker understands must fail ProcessAttrCert7
  LAttrCert := BuildAttrCert(FHolderCert, FIssuerCert,
    FIssuerKeyPair.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -1),
    IncMinute(LUtcNow, 30), RoleAttrOid, UnknownCriticalOid);

  LParams := BuildParams(LAttrCert, True, nil, nil);

  CheckFalse(TryValidate(LAttrCert, LParams, LMessage),
    'an unresolved critical extension must be rejected');
  CheckTrue(Pos('unsupported critical', LMessage) > 0,
    'the rejection must name the unsupported critical extension (step 7), got: ' + LMessage);
end;

procedure TAttrCertPathTest.TestCheckerResolvesCriticalExtension;
var
  LUtcNow: TDateTime;
  LAttrCert: IX509V2AttributeCertificate;
  LParams: IPkixParameters;
  LMessage: String;
  LChecker: IPkixAttrCertChecker;
begin
  EnsureCerts;
  LUtcNow := Now.ToUniversalTime();

  LAttrCert := BuildAttrCert(FHolderCert, FIssuerCert,
    FIssuerKeyPair.Private as IAsymmetricKeyParameter, IncMinute(LUtcNow, -1),
    IncMinute(LUtcNow, 30), RoleAttrOid, UnknownCriticalOid);

  // a checker that resolves the very extension makes the same AC validate
  LChecker := TResolvingAttrCertChecker.Create(UnknownCriticalOid) as IPkixAttrCertChecker;
  LParams := BuildParams(LAttrCert, True, nil,
    TCryptoLibGenericArray<IPkixAttrCertChecker>.Create(LChecker));

  CheckTrue(TryValidate(LAttrCert, LParams, LMessage),
    'a registered checker that resolves the critical extension must let the AC validate: ' + LMessage);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TAttrCertPathTest);
{$ELSE}
  RegisterTest(TAttrCertPathTest.Suite);
{$ENDIF FPC}

end.
