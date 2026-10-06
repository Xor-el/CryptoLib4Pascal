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

unit CertPathHardeningTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
  ClpDateTimeHelper,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpIAsn1Core,
  ClpIStore,
  ClpCollectionStore,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpPkixBuilderParameters,
  ClpPkixCertPathBuilder,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509Generators,
  ClpX509Generators,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpX509ExtensionUtilities,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CertTestUtilities,
  CryptoLibTestBase;

type

  /// <summary>
  /// Certification path building terminates when two CAs sharing a CRL-issuer distinguished name are
  /// both trusted, rather than looping over the indistinguishable CRL signers.
  /// </summary>
  TCertPathLoopTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRandom: ISecureRandom;
    function BuildCA(out AAnchorCert, ACrlSignerCert: IX509Certificate; out ACrl: IX509Crl;
      out ACertSigningKey: IAsymmetricKeyParameter; out ASubject: IX509Name;
      var ACounter: Int32): Boolean;
    function LoopBuilder(const ASerial: TBigInteger; const AIssuer, ASubject: IX509Name;
      const APublicKey: IAsymmetricKeyParameter): IX509V3CertificateGenerator;
  protected
    procedure SetUp; override;
  published
    procedure TestSharedCrlIssuerDnDoesNotLoop;
  end;

  /// <summary>
  /// A CRL signed under a different trust anchor than the certificate being checked is rejected, the
  /// real reason is reported, and the CRL signer's own path honours the excluded set and the maximum
  /// path length.
  /// </summary>
  TIndirectCrlSignerTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  const
    SigAlgorithm = 'SHA256WITHRSA';
  type
    TPki = record
      Roots, Signers, Intermediates: TCryptoLibGenericArray<IX509Certificate>;
      SubCa: IX509Certificate;
      Crl: IX509Crl;
    end;
  var
    FRandom: ISecureRandom;
    FSerial: Int32;
    class procedure AppendCert(var AArr: TCryptoLibGenericArray<IX509Certificate>;
      const ACert: IX509Certificate); static;
    function NextSerial: TBigInteger;
    function SignerDp: ICrlDistPoint;
    function Builder(const AIssuer, ASubject: IX509Name;
      const APublicKey: IAsymmetricKeyParameter): IX509V3CertificateGenerator;
    function Sign(const AGen: IX509V3CertificateGenerator;
      const APrivateKey: IAsymmetricKeyParameter): IX509Certificate;
    function SelfSigned(const AKey: IAsymmetricCipherKeyPair; const ASubject: IX509Name): IX509Certificate;
    function SubCaCert(const APub: IAsymmetricKeyParameter; const ASubject: IX509Name;
      const ACaKey: IAsymmetricCipherKeyPair; const ACaCert: IX509Certificate;
      const ADp: ICrlDistPoint): IX509Certificate;
    function CrlSigner(const APub: IAsymmetricKeyParameter; const ASubject: IX509Name;
      const ACaKey: IAsymmetricCipherKeyPair; const ACaCert: IX509Certificate;
      const ADp: ICrlDistPoint): IX509Certificate;
    function IndirectCrl(const ASignerKey: IAsymmetricCipherKeyPair;
      const ASignerCert: IX509Certificate): IX509Crl;
    function BuildPki(AGenerations, ASignerDepth: Int32): TPki;
    function ValidatePki(const APki: TPki; AMaxPathLength: Int32;
      const AExcluded: TCryptoLibGenericArray<IX509Certificate>): IPkixCertPathBuilderResult;
    procedure ExpectSignerRejected(const AFailMessage: String; const APki: TPki;
      AMaxPathLength: Int32; const AExcluded: TCryptoLibGenericArray<IX509Certificate>);
  protected
    procedure SetUp; override;
  published
    procedure TestSingleGenerationValidates;
    procedure TestRolledRootReportsTheRealFailure;
    procedure TestExcludedSignerIsNotUsed;
    procedure TestMaxPathLengthBoundsSignerPath;
    procedure TestMaxPathLengthUnboundedAdmitsLongSignerPath;
  end;

  /// <summary>
  /// A trust anchor's name constraints, explicit or carried by its certificate, bound the names
  /// of every path that ends at it.
  /// </summary>
  TAnchorNameConstraintsTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  const
    SigAlgorithm = 'SHA256WITHRSA';
  var
    FRandom: ISecureRandom;
    function Constraints: INameConstraints;
    function Generator(const AIssuer, ASubject: IX509Name;
      const APublicKey: IAsymmetricKeyParameter; ASerial: Int32): IX509V3CertificateGenerator;
    function Root(const AKey: IAsymmetricCipherKeyPair; AWithConstraints: Boolean): IX509Certificate;
    function Leaf(const AKey: IAsymmetricCipherKeyPair; const ARoot: IX509Certificate;
      const AIssuerKey: IAsymmetricCipherKeyPair; const ADnsName: String): IX509Certificate;
    function Validates(const ARoot, ALeaf: IX509Certificate;
      const AAnchorConstraints: TCryptoLibByteArray): Boolean;
  protected
    procedure SetUp; override;
  published
    procedure TestCertificateExtensionIsEnforced;
    procedure TestExplicitAnchorConstraintsAreEnforced;
    procedure TestUnconstrainedAnchorAdmitsAnyName;
    procedure TestExplicitConstraintsCannotWidenTheCertificate;
  end;

implementation

{ TCertPathLoopTest }

procedure TCertPathLoopTest.SetUp;
begin
  inherited SetUp;
  FRandom := TSecureRandom.Create() as ISecureRandom;
end;

function TCertPathLoopTest.LoopBuilder(const ASerial: TBigInteger; const AIssuer, ASubject: IX509Name;
  const APublicKey: IAsymmetricKeyParameter): IX509V3CertificateGenerator;
var
  LNow: TDateTime;
begin
  LNow := Now.ToUniversalTime();
  Result := TX509V3CertificateGenerator.Create;
  Result.SetIssuerDN(AIssuer);
  Result.SetSerialNumber(ASerial);
  Result.SetNotBeforeUtc(LNow);
  Result.SetNotAfterUtc(IncDay(LNow, 1));
  Result.SetSubjectDN(ASubject);
  Result.SetPublicKey(APublicKey);
end;

function TCertPathLoopTest.BuildCA(out AAnchorCert, ACrlSignerCert: IX509Certificate; out ACrl: IX509Crl;
  out ACertSigningKey: IAsymmetricKeyParameter; out ASubject: IX509Name; var ACounter: Int32): Boolean;
var
  LCertKey, LCrlKey: IAsymmetricCipherKeyPair;
  LGen: IX509V3CertificateGenerator;
  LCrlGen: IX509V2CrlGenerator;
  LNow, LNotAfter: TDateTime;
  LSignFactory: ISignatureFactory;
begin
  LCertKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LCrlKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  ACertSigningKey := LCertKey.Private as IAsymmetricKeyParameter;
  ASubject := TX509Name.Create('CN=AC_0');

  LNow := Now.ToUniversalTime();
  LNotAfter := IncDay(LNow, 1);

  LGen := LoopBuilder(TBigInteger.ValueOf(ACounter), ASubject, ASubject,
    LCertKey.Public as IAsymmetricKeyParameter);
  System.Inc(ACounter);
  LGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(True) as IBasicConstraints);
  LGen.AddExtension(TX509Extensions.KeyUsage, True, TKeyUsage.Create(TKeyUsage.KeyCertSign) as IKeyUsage);
  LSignFactory := TAsn1SignatureFactory.Create('SHA256WITHRSA', ACertSigningKey, FRandom) as ISignatureFactory;
  AAnchorCert := LGen.Generate(LSignFactory);

  LGen := LoopBuilder(TBigInteger.ValueOf(ACounter), ASubject, ASubject,
    LCrlKey.Public as IAsymmetricKeyParameter);
  System.Inc(ACounter);
  LGen.AddExtension(TX509Extensions.BasicConstraints, False, TBasicConstraints.Create(False) as IBasicConstraints);
  LGen.AddExtension(TX509Extensions.KeyUsage, True, TKeyUsage.Create(TKeyUsage.CrlSign) as IKeyUsage);
  ACrlSignerCert := LGen.Generate(LSignFactory);

  LCrlGen := TX509V2CrlGenerator.Create() as IX509V2CrlGenerator;
  LCrlGen.SetIssuerDN(ASubject);
  LCrlGen.SetThisUpdateUtc(LNow);
  LCrlGen.SetNextUpdateUtc(LNotAfter);
  ACrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WITHRSA',
    LCrlKey.Private as IAsymmetricKeyParameter, FRandom) as ISignatureFactory);

  Result := True;
end;

procedure TCertPathLoopTest.TestSharedCrlIssuerDnDoesNotLoop;
var
  LCounterA, LCounterB: Int32;
  LAnchorA, LCrlSignerA, LAnchorB, LCrlSignerB, LTargetCert: IX509Certificate;
  LCrlA, LCrlB: IX509Crl;
  LKeyA, LKeyB: IAsymmetricKeyParameter;
  LSubjectA, LSubjectB: IX509Name;
  LTargetKey: IAsymmetricCipherKeyPair;
  LTargetGen: IX509V3CertificateGenerator;
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LCertStore: IStore<IX509Certificate>;
  LCrlStore: IStore<IX509Crl>;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
  LResult: IPkixCertPathBuilderResult;
begin
  LCounterA := 1;
  LCounterB := 1;
  BuildCA(LAnchorA, LCrlSignerA, LCrlA, LKeyA, LSubjectA, LCounterA);
  BuildCA(LAnchorB, LCrlSignerB, LCrlB, LKeyB, LSubjectB, LCounterB);

  // an end-entity issued by CA A, whose CRL signer shares its issuer DN with CA B's CRL signer
  LTargetKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LTargetGen := LoopBuilder(TBigInteger.ValueOf(LCounterA), LSubjectA,
    TX509Name.Create('CN=EU_' + IntToStr(LCounterA)) as IX509Name,
    LTargetKey.Public as IAsymmetricKeyParameter);
  LTargetGen.AddExtension(TX509Extensions.BasicConstraints, False,
    TBasicConstraints.Create(False) as IBasicConstraints);
  LTargetGen.AddExtension(TX509Extensions.KeyUsage, True,
    TKeyUsage.Create(TKeyUsage.DigitalSignature) as IKeyUsage);
  LTargetCert := LTargetGen.Generate(TAsn1SignatureFactory.Create('SHA256WITHRSA', LKeyA, FRandom)
    as ISignatureFactory);

  LAnchors := TCryptoLibGenericArray<ITrustAnchor>.Create(
    TTrustAnchor.Create(LAnchorA, nil) as ITrustAnchor,
    TTrustAnchor.Create(LAnchorB, nil) as ITrustAnchor);

  LCertStore := TCollectionStore<IX509Certificate>.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(LTargetCert, LCrlSignerA, LCrlSignerB));
  LCrlStore := TCollectionStore<IX509Crl>.Create(
    TCryptoLibGenericArray<IX509Crl>.Create(LCrlA, LCrlB));

  LSelector := TX509CertStoreSelector.Create();
  LSelector.Certificate := LTargetCert;
  LTarget := LSelector;

  LParams := TPkixBuilderParameters.Create(LAnchors, LTarget) as IPkixBuilderParameters;
  LParams.AddStoreCert(LCertStore);
  LParams.AddStoreCrl(LCrlStore);
  LParams.IsRevocationEnabled := True;

  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
  LResult := LBuilder.Build(LParams);

  CheckNotNull(LResult, 'the path builds and terminates despite the shared CRL-issuer name');
end;

{ TIndirectCrlSignerTest }

procedure TIndirectCrlSignerTest.SetUp;
begin
  inherited SetUp;
  FRandom := TSecureRandom.Create() as ISecureRandom;
  FSerial := 0;
end;

class procedure TIndirectCrlSignerTest.AppendCert(var AArr: TCryptoLibGenericArray<IX509Certificate>;
  const ACert: IX509Certificate);
begin
  System.SetLength(AArr, System.Length(AArr) + 1);
  AArr[System.High(AArr)] := ACert;
end;

function TIndirectCrlSignerTest.NextSerial: TBigInteger;
begin
  System.Inc(FSerial);
  Result := TBigInteger.ValueOf(FSerial);
end;

function TIndirectCrlSignerTest.SignerDp: ICrlDistPoint;
var
  LSignerDn: IX509Name;
begin
  LSignerDn := TX509Name.Create('CN=Test-Root.CRL-S, O=Test-PKI, C=DE');
  Result := TCrlDistPoint.Create(TCryptoLibGenericArray<IDistributionPoint>.Create(
    TDistributionPoint.Create(nil, nil,
    TGeneralNames.Create(TGeneralName.Create(LSignerDn) as IGeneralName) as IGeneralNames)
    as IDistributionPoint)) as ICrlDistPoint;
end;

function TIndirectCrlSignerTest.Builder(const AIssuer, ASubject: IX509Name;
  const APublicKey: IAsymmetricKeyParameter): IX509V3CertificateGenerator;
var
  LNow: TDateTime;
begin
  LNow := Now.ToUniversalTime();
  Result := TX509V3CertificateGenerator.Create;
  Result.SetIssuerDN(AIssuer);
  Result.SetSerialNumber(NextSerial);
  Result.SetNotBeforeUtc(IncDay(LNow, -1));
  Result.SetNotAfterUtc(IncYear(LNow, 1));
  Result.SetSubjectDN(ASubject);
  Result.SetPublicKey(APublicKey);
end;

function TIndirectCrlSignerTest.Sign(const AGen: IX509V3CertificateGenerator;
  const APrivateKey: IAsymmetricKeyParameter): IX509Certificate;
begin
  Result := AGen.Generate(TAsn1SignatureFactory.Create(SigAlgorithm, APrivateKey, FRandom)
    as ISignatureFactory);
end;

function TIndirectCrlSignerTest.SelfSigned(const AKey: IAsymmetricCipherKeyPair;
  const ASubject: IX509Name): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
  LPub: IAsymmetricKeyParameter;
begin
  LPub := AKey.Public as IAsymmetricKeyParameter;
  LGen := Builder(ASubject, ASubject, LPub);
  LGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(True) as IBasicConstraints);
  LGen.AddExtension(TX509Extensions.KeyUsage, True, TKeyUsage.Create(TKeyUsage.KeyCertSign) as IKeyUsage);
  LGen.AddExtension(TX509Extensions.SubjectKeyIdentifier, False,
    TX509ExtensionUtilities.CreateSubjectKeyIdentifier(LPub) as ISubjectKeyIdentifier);
  Result := Sign(LGen, AKey.Private as IAsymmetricKeyParameter);
end;

function TIndirectCrlSignerTest.SubCaCert(const APub: IAsymmetricKeyParameter; const ASubject: IX509Name;
  const ACaKey: IAsymmetricCipherKeyPair; const ACaCert: IX509Certificate;
  const ADp: ICrlDistPoint): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
begin
  LGen := Builder(ACaCert.SubjectDN, ASubject, APub);
  LGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(True) as IBasicConstraints);
  LGen.AddExtension(TX509Extensions.KeyUsage, True,
    TKeyUsage.Create(TKeyUsage.KeyCertSign or TKeyUsage.CrlSign) as IKeyUsage);
  LGen.AddExtension(TX509Extensions.SubjectKeyIdentifier, False,
    TX509ExtensionUtilities.CreateSubjectKeyIdentifier(APub) as ISubjectKeyIdentifier);
  LGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(ACaCert) as IAuthorityKeyIdentifier);
  LGen.AddExtension(TX509Extensions.CrlDistributionPoints, False, ADp as IAsn1Encodable);
  Result := Sign(LGen, ACaKey.Private as IAsymmetricKeyParameter);
end;

function TIndirectCrlSignerTest.CrlSigner(const APub: IAsymmetricKeyParameter; const ASubject: IX509Name;
  const ACaKey: IAsymmetricCipherKeyPair; const ACaCert: IX509Certificate;
  const ADp: ICrlDistPoint): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
begin
  LGen := Builder(ACaCert.SubjectDN, ASubject, APub);
  LGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(False) as IBasicConstraints);
  LGen.AddExtension(TX509Extensions.KeyUsage, True, TKeyUsage.Create(TKeyUsage.CrlSign) as IKeyUsage);
  LGen.AddExtension(TX509Extensions.SubjectKeyIdentifier, False,
    TX509ExtensionUtilities.CreateSubjectKeyIdentifier(APub) as ISubjectKeyIdentifier);
  LGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(ACaCert) as IAuthorityKeyIdentifier);
  LGen.AddExtension(TX509Extensions.CrlDistributionPoints, False, ADp as IAsn1Encodable);
  Result := Sign(LGen, ACaKey.Private as IAsymmetricKeyParameter);
end;

function TIndirectCrlSignerTest.IndirectCrl(const ASignerKey: IAsymmetricCipherKeyPair;
  const ASignerCert: IX509Certificate): IX509Crl;
var
  LGen: IX509V2CrlGenerator;
  LNow: TDateTime;
begin
  LNow := Now.ToUniversalTime();
  LGen := TX509V2CrlGenerator.Create() as IX509V2CrlGenerator;
  LGen.SetIssuerDN(ASignerCert.SubjectDN);
  LGen.SetThisUpdateUtc(IncHour(LNow, -1));
  LGen.SetNextUpdateUtc(IncMonth(LNow, 1));
  LGen.AddExtension(TX509Extensions.IssuingDistributionPoint, True,
    TIssuingDistributionPoint.Create(nil, False, False, nil, True, False) as IIssuingDistributionPoint);
  LGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(ASignerCert) as IAuthorityKeyIdentifier);
  Result := LGen.Generate(TAsn1SignatureFactory.Create(SigAlgorithm,
    ASignerKey.Private as IAsymmetricKeyParameter, FRandom) as ISignatureFactory);
end;

function TIndirectCrlSignerTest.BuildPki(AGenerations, ASignerDepth: Int32): TPki;
var
  LDp: ICrlDistPoint;
  LSignerDn: IX509Name;
  LRootKeys, LSignerKeys: TCryptoLibGenericArray<IAsymmetricCipherKeyPair>;
  LG, LD, LLast: Int32;
  LRootKey, LIssuerKey, LCaKey, LSignerKey: IAsymmetricCipherKeyPair;
  LRoot, LIssuer: IX509Certificate;
begin
  LDp := SignerDp;
  LSignerDn := TX509Name.Create('CN=Test-Root.CRL-S, O=Test-PKI, C=DE');

  Result.Roots := nil;
  Result.Signers := nil;
  Result.Intermediates := nil;
  LRootKeys := nil;
  LSignerKeys := nil;

  for LG := 1 to AGenerations do
  begin
    LRootKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
    LRoot := SelfSigned(LRootKey,
      TX509Name.Create('CN=Test-Root.CA, O=Test-PKI, C=DE, SERIALNUMBER=' + IntToStr(LG)) as IX509Name);

    System.SetLength(LRootKeys, System.Length(LRootKeys) + 1);
    LRootKeys[System.High(LRootKeys)] := LRootKey;
    System.SetLength(Result.Roots, System.Length(Result.Roots) + 1);
    Result.Roots[System.High(Result.Roots)] := LRoot;

    LIssuerKey := LRootKey;
    LIssuer := LRoot;
    for LD := 1 to ASignerDepth do
    begin
      LCaKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
      LIssuer := SubCaCert(LCaKey.Public as IAsymmetricKeyParameter,
        TX509Name.Create('CN=Test-Int' + IntToStr(LD) + '.CA, O=Test-PKI, C=DE, SERIALNUMBER=' + IntToStr(LG)) as IX509Name,
        LIssuerKey, LIssuer, LDp);
      LIssuerKey := LCaKey;
      System.SetLength(Result.Intermediates, System.Length(Result.Intermediates) + 1);
      Result.Intermediates[System.High(Result.Intermediates)] := LIssuer;
    end;

    LSignerKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
    System.SetLength(Result.Signers, System.Length(Result.Signers) + 1);
    Result.Signers[System.High(Result.Signers)] :=
      CrlSigner(LSignerKey.Public as IAsymmetricKeyParameter, LSignerDn, LIssuerKey, LIssuer, LDp);
    System.SetLength(LSignerKeys, System.Length(LSignerKeys) + 1);
    LSignerKeys[System.High(LSignerKeys)] := LSignerKey;
  end;

  Result.SubCa := SubCaCert(TCertTestUtilities.GenerateRsaKeyPair(1024).Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Test-Sub.CA, O=Test-PKI, C=DE') as IX509Name, LRootKeys[0], Result.Roots[0], LDp);

  LLast := System.High(Result.Signers);
  Result.Crl := IndirectCrl(LSignerKeys[LLast], Result.Signers[LLast]);
end;

function TIndirectCrlSignerTest.ValidatePki(const APki: TPki; AMaxPathLength: Int32;
  const AExcluded: TCryptoLibGenericArray<IX509Certificate>): IPkixCertPathBuilderResult;
var
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LIdx: Int32;
  LCertStore: IStore<IX509Certificate>;
  LCrlStore: IStore<IX509Crl>;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
begin
  System.SetLength(LAnchors, System.Length(APki.Roots));
  for LIdx := 0 to System.High(APki.Roots) do
    LAnchors[LIdx] := TTrustAnchor.Create(APki.Roots[LIdx], nil) as ITrustAnchor;

  LCerts := nil;
  for LIdx := 0 to System.High(APki.Signers) do
    AppendCert(LCerts, APki.Signers[LIdx]);
  for LIdx := 0 to System.High(APki.Intermediates) do
    AppendCert(LCerts, APki.Intermediates[LIdx]);
  AppendCert(LCerts, APki.SubCa);

  LCertStore := TCollectionStore<IX509Certificate>.Create(LCerts);
  LCrlStore := TCollectionStore<IX509Crl>.Create(TCryptoLibGenericArray<IX509Crl>.Create(APki.Crl));

  LSelector := TX509CertStoreSelector.Create();
  LSelector.Certificate := APki.SubCa;
  LTarget := LSelector;

  LParams := TPkixBuilderParameters.Create(LAnchors, LTarget) as IPkixBuilderParameters;
  LParams.AddStoreCert(LCertStore);
  LParams.AddStoreCrl(LCrlStore);
  LParams.IsRevocationEnabled := True;
  LParams.MaxPathLength := AMaxPathLength;
  if AExcluded <> nil then
    LParams.SetExcludedCerts(AExcluded);

  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
  Result := LBuilder.Build(LParams);
end;

procedure TIndirectCrlSignerTest.ExpectSignerRejected(const AFailMessage: String; const APki: TPki;
  AMaxPathLength: Int32; const AExcluded: TCryptoLibGenericArray<IX509Certificate>);
var
  LRaised: Boolean;
  LMessage: String;
begin
  LRaised := False;
  LMessage := '';
  try
    ValidatePki(APki, AMaxPathLength, AExcluded);
  except
    on E: EPkixCertPathBuilderCryptoLibException do
    begin
      LRaised := True;
      LMessage := E.Message;
    end;
  end;
  CheckTrue(LRaised, AFailMessage);
  CheckTrue(Pos('CertPath for CRL signer failed to validate', LMessage) > 0,
    Format('the CRL signer path failure was not reported: %s', [LMessage]));
end;

procedure TIndirectCrlSignerTest.TestSingleGenerationValidates;
begin
  CheckNotNull(ValidatePki(BuildPki(1, 0), 5, nil),
    'a path with a single root generation builds');
end;

procedure TIndirectCrlSignerTest.TestRolledRootReportsTheRealFailure;
var
  LPki: TPki;
  LRaised: Boolean;
  LMessage: String;
begin
  LPki := BuildPki(2, 0);
  LRaised := False;
  LMessage := '';
  try
    ValidatePki(LPki, 5, nil);
  except
    on E: EPkixCertPathBuilderCryptoLibException do
    begin
      LRaised := True;
      LMessage := E.Message;
    end;
  end;

  CheckTrue(LRaised, 'a CRL signed under a different trust anchor is rejected');
  CheckTrue(Pos('CertPath for CRL signer failed to validate', LMessage) > 0,
    Format('the CRL signer own-path failure was not reported: %s', [LMessage]));
  CheckTrue(Pos('The CRL distribution points of the certificate were tried first and failed', LMessage) > 0,
    Format('the distribution-point failure was not linked to the fallback: %s', [LMessage]));
end;

procedure TIndirectCrlSignerTest.TestExcludedSignerIsNotUsed;
var
  LPki: TPki;
begin
  LPki := BuildPki(1, 0);
  ExpectSignerRejected('an excluded CRL signer was used', LPki, 5,
    TCryptoLibGenericArray<IX509Certificate>.Create(LPki.Signers[0]));
end;

procedure TIndirectCrlSignerTest.TestMaxPathLengthBoundsSignerPath;
var
  LPki: TPki;
begin
  LPki := BuildPki(1, 2);
  CheckNotNull(ValidatePki(LPki, 2, nil),
    'a CRL signer path within the maximum path length validates');
  ExpectSignerRejected('a CRL signer path longer than the maximum path length was accepted', LPki, 1, nil);
end;

procedure TIndirectCrlSignerTest.TestMaxPathLengthUnboundedAdmitsLongSignerPath;
var
  LPki: TPki;
begin
  LPki := BuildPki(1, 6);
  CheckNotNull(ValidatePki(LPki, -1, nil),
    'a CRL signer path with an unlimited maximum path length validates');
  ExpectSignerRejected('a CRL signer path longer than the default maximum path length was accepted',
    LPki, 5, nil);
end;

{ TAnchorNameConstraintsTest }

procedure TAnchorNameConstraintsTest.SetUp;
begin
  inherited SetUp;
  FRandom := TSecureRandom.Create() as ISecureRandom;
end;

function TAnchorNameConstraintsTest.Constraints: INameConstraints;
begin
  Result := TNameConstraints.Create(
    TGeneralSubtrees.Create(TGeneralSubtree.Create(
      TGeneralName.Create(TGeneralName.DnsName, '.good.test') as IGeneralName) as IGeneralSubtree)
    as IGeneralSubtrees, nil) as INameConstraints;
end;

function TAnchorNameConstraintsTest.Generator(const AIssuer, ASubject: IX509Name;
  const APublicKey: IAsymmetricKeyParameter; ASerial: Int32): IX509V3CertificateGenerator;
var
  LNow: TDateTime;
begin
  LNow := Now.ToUniversalTime();
  Result := TX509V3CertificateGenerator.Create;
  Result.SetIssuerDN(AIssuer);
  Result.SetSerialNumber(TBigInteger.ValueOf(ASerial));
  Result.SetNotBeforeUtc(IncDay(LNow, -1));
  Result.SetNotAfterUtc(IncYear(LNow, 1));
  Result.SetSubjectDN(ASubject);
  Result.SetPublicKey(APublicKey);
end;

function TAnchorNameConstraintsTest.Root(const AKey: IAsymmetricCipherKeyPair;
  AWithConstraints: Boolean): IX509Certificate;
var
  LName: IX509Name;
  LPub: IAsymmetricKeyParameter;
  LGen: IX509V3CertificateGenerator;
begin
  LName := TX509Name.Create('CN=Constrained Root, O=Test-PKI, C=DE');
  LPub := AKey.Public as IAsymmetricKeyParameter;
  LGen := Generator(LName, LName, LPub, 1);
  LGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(True) as IBasicConstraints);
  LGen.AddExtension(TX509Extensions.KeyUsage, True, TKeyUsage.Create(TKeyUsage.KeyCertSign) as IKeyUsage);
  if AWithConstraints then
    LGen.AddExtension(TX509Extensions.NameConstraints, True, Constraints as IAsn1Encodable);
  Result := LGen.Generate(TAsn1SignatureFactory.Create(SigAlgorithm,
    AKey.Private as IAsymmetricKeyParameter, FRandom) as ISignatureFactory);
end;

function TAnchorNameConstraintsTest.Leaf(const AKey: IAsymmetricCipherKeyPair;
  const ARoot: IX509Certificate; const AIssuerKey: IAsymmetricCipherKeyPair;
  const ADnsName: String): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
begin
  LGen := Generator(ARoot.SubjectDN, TX509Name.Create('CN=' + ADnsName) as IX509Name,
    AKey.Public as IAsymmetricKeyParameter, 2);
  LGen.AddExtension(TX509Extensions.SubjectAlternativeName, False,
    TGeneralNames.Create(TGeneralName.Create(TGeneralName.DnsName, ADnsName) as IGeneralName)
    as IGeneralNames);
  Result := LGen.Generate(TAsn1SignatureFactory.Create(SigAlgorithm,
    AIssuerKey.Private as IAsymmetricKeyParameter, FRandom) as ISignatureFactory);
end;

function TAnchorNameConstraintsTest.Validates(const ARoot, ALeaf: IX509Certificate;
  const AAnchorConstraints: TCryptoLibByteArray): Boolean;
var
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LSelector: IX509CertStoreSelector;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
begin
  LAnchors := TCryptoLibGenericArray<ITrustAnchor>.Create(
    TTrustAnchor.Create(ARoot, AAnchorConstraints) as ITrustAnchor);
  LSelector := TX509CertStoreSelector.Create();
  LSelector.Certificate := ALeaf;
  LParams := TPkixBuilderParameters.Create(LAnchors, LSelector) as IPkixBuilderParameters;
  LParams.IsRevocationEnabled := False;
  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
  try
    LBuilder.Build(LParams);
    Result := True;
  except
    on E: EPkixCertPathBuilderCryptoLibException do
      Result := False;
  end;
end;

procedure TAnchorNameConstraintsTest.TestCertificateExtensionIsEnforced;
var
  LRootKey, LLeafKey: IAsymmetricCipherKeyPair;
  LRoot: IX509Certificate;
begin
  LRootKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LLeafKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := Root(LRootKey, True);
  CheckTrue(Validates(LRoot, Leaf(LLeafKey, LRoot, LRootKey, 'a.good.test'), nil),
    'a name inside the root''s permitted subtree validates');
  CheckFalse(Validates(LRoot, Leaf(LLeafKey, LRoot, LRootKey, 'evil.test'), nil),
    'a name outside the root''s permitted subtree is rejected');
end;

procedure TAnchorNameConstraintsTest.TestExplicitAnchorConstraintsAreEnforced;
var
  LRootKey, LLeafKey: IAsymmetricCipherKeyPair;
  LRoot: IX509Certificate;
  LDer: TCryptoLibByteArray;
begin
  LRootKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LLeafKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := Root(LRootKey, False);
  LDer := Constraints.GetDerEncoded();
  CheckTrue(Validates(LRoot, Leaf(LLeafKey, LRoot, LRootKey, 'a.good.test'), LDer),
    'a name inside the anchor''s permitted subtree validates');
  CheckFalse(Validates(LRoot, Leaf(LLeafKey, LRoot, LRootKey, 'evil.test'), LDer),
    'a name outside the anchor''s permitted subtree is rejected');
end;

procedure TAnchorNameConstraintsTest.TestUnconstrainedAnchorAdmitsAnyName;
var
  LRootKey, LLeafKey: IAsymmetricCipherKeyPair;
  LRoot: IX509Certificate;
begin
  LRootKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LLeafKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := Root(LRootKey, False);
  CheckTrue(Validates(LRoot, Leaf(LLeafKey, LRoot, LRootKey, 'evil.test'), nil),
    'an anchor with no name constraints leaves the names unconstrained');
end;

procedure TAnchorNameConstraintsTest.TestExplicitConstraintsCannotWidenTheCertificate;
var
  LRootKey, LLeafKey: IAsymmetricCipherKeyPair;
  LRoot: IX509Certificate;
  LWider: TCryptoLibByteArray;
begin
  LRootKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LLeafKey := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := Root(LRootKey, True);
  LWider := (TNameConstraints.Create(
    TGeneralSubtrees.Create(TGeneralSubtree.Create(
      TGeneralName.Create(TGeneralName.DnsName, '.evil.test') as IGeneralName) as IGeneralSubtree)
    as IGeneralSubtrees, nil) as INameConstraints).GetDerEncoded();
  CheckFalse(Validates(LRoot, Leaf(LLeafKey, LRoot, LRootKey, 'a.evil.test'), LWider),
    'explicit constraints do not lift the certificate''s own constraints');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCertPathLoopTest);
  RegisterTest(TIndirectCrlSignerTest);
  RegisterTest(TAnchorNameConstraintsTest);
{$ELSE}
  RegisterTest(TCertPathLoopTest.Suite);
  RegisterTest(TIndirectCrlSignerTest.Suite);
  RegisterTest(TAnchorNameConstraintsTest.Suite);
{$ENDIF FPC}

end.
