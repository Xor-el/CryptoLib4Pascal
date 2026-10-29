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

unit CertPathBuilderTests;

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
  ClpDateTimeHelper,
  ClpIStore,
  ClpCollectionStore,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpPkixBuilderParameters,
  ClpPkixCertPathBuilder,
  ClpIX509Certificate,
  ClpIX509Generators,
  ClpX509Generators,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpX509ObjectIdentifiers,
  ClpPkixCertPathValidatorReason,
  ClpBigInteger,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CertTestUtilities,
  CryptoLibTestBase;

type

  /// <summary>
  /// PKIX path builder features: unsigned certificate generation (id-alg-unsigned), specifying the
  /// target certificate through the selector's Certificate property, and the per-build node budget.
  /// </summary>
  TCertPathBuilderTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FBuilder: IPkixCertPathBuilder;

    function AnchorsOf(const ACert: IX509Certificate): TCryptoLibGenericArray<ITrustAnchor>;
    /// <summary>Builds with FBuilder towards AAnchor and returns the reason of the failure.</summary>
    function BuildFailureReason(const AAnchor: IX509Certificate; const ASubject: IX509Name;
      const AStoreCerts: TCryptoLibGenericArray<IX509Certificate>): TPkixCertPathValidatorReason;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestGenerateUnsignedCertificate;
    procedure TestBuildTargetInStore;
    procedure TestBuildTargetViaSelector;
    procedure TestBuildWithUnsignedTrustAnchor;
    procedure TestBuilderInstanceReuse;
    procedure TestNodeBudgetGuard;
    procedure TestBuilderExceptionReasonDefaultsToUnspecified;
    procedure TestBadSignatureUnderPooledIntermediate;
    procedure TestBadSignatureDirectlyUnderAnchor;
    procedure TestUnrecognizedCriticalExtensionOnLeaf;
    procedure TestUnrecognizedCriticalExtensionOnIntermediate;
    procedure TestExpiredOutranksCriticalExtension;
    procedure TestInvalidSignatureOutranksCriticalExtension;
    procedure TestCriticalExtensionOutranksNoIssuer;
  end;

implementation

{ TCertPathBuilderTest }

function TCertPathBuilderTest.AnchorsOf(const ACert: IX509Certificate)
  : TCryptoLibGenericArray<ITrustAnchor>;
begin
  Result := TCryptoLibGenericArray<ITrustAnchor>.Create(TTrustAnchor.Create(ACert, nil) as ITrustAnchor);
end;

procedure TCertPathBuilderTest.SetUp;
begin
  inherited SetUp;
  FBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
end;

function TCertPathBuilderTest.BuildFailureReason(const AAnchor: IX509Certificate; const ASubject: IX509Name;
  const AStoreCerts: TCryptoLibGenericArray<IX509Certificate>): TPkixCertPathValidatorReason;
var
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LStore: IStore<IX509Certificate>;
  LParams: IPkixBuilderParameters;
begin
  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := ASubject;
  LTarget := LSelector;
  LStore := TCollectionStore<IX509Certificate>.Create(AStoreCerts);
  LParams := TPkixBuilderParameters.Create(AnchorsOf(AAnchor), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  Result := TPkixCertPathValidatorReason.Unspecified;
  try
    FBuilder.Build(LParams);
  except
    on E: EPkixCertPathBuilderCryptoLibException do
    begin
      Result := E.Reason;
      Exit;
    end;
  end;
  Fail('the build was expected to fail');
end;

procedure TCertPathBuilderTest.TearDown;
begin
  // the node budget is a process-wide switch; restore it so a lowered value cannot leak to later tests
  TCryptoLibConfig.X509.ResetToDefaults();
  inherited TearDown;
end;

procedure TCertPathBuilderTest.TestGenerateUnsignedCertificate;
var
  LKeyPair: IAsymmetricCipherKeyPair;
  LDn: IX509Name;
  LUtcNow: TDateTime;
  LV1Gen: IX509V1CertificateGenerator;
  LV3Gen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
begin
  LKeyPair := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LDn := TX509Name.Create('CN=Unsigned Certificate');
  LUtcNow := Now.ToUniversalTime();

  LV1Gen := TX509V1CertificateGenerator.Create;
  LV1Gen.SetSerialNumber(TBigInteger.One);
  LV1Gen.SetIssuerDN(LDn);
  LV1Gen.SetNotBeforeUtc(IncSecond(LUtcNow, -5));
  LV1Gen.SetNotAfterUtc(IncMinute(LUtcNow, 30));
  LV1Gen.SetSubjectDN(LDn);
  LV1Gen.SetPublicKey(LKeyPair.Public as IAsymmetricKeyParameter);
  LCert := LV1Gen.GenerateUnsigned();

  CheckTrue(LCert.SignatureAlgorithm.Algorithm.Equals(TX509ObjectIdentifiers.IdAlgUnsigned),
    'the V1 unsigned certificate uses id-alg-unsigned');
  CheckEquals(0, System.Length(LCert.GetSignature), 'the V1 unsigned certificate has an empty signature');

  LV3Gen := TX509V3CertificateGenerator.Create;
  LV3Gen.SetSerialNumber(TBigInteger.One);
  LV3Gen.SetIssuerDN(LDn);
  LV3Gen.SetNotBeforeUtc(IncSecond(LUtcNow, -5));
  LV3Gen.SetNotAfterUtc(IncMinute(LUtcNow, 30));
  LV3Gen.SetSubjectDN(LDn);
  LV3Gen.SetPublicKey(LKeyPair.Public as IAsymmetricKeyParameter);
  LCert := LV3Gen.GenerateUnsigned();

  CheckTrue(LCert.SignatureAlgorithm.Algorithm.Equals(TX509ObjectIdentifiers.IdAlgUnsigned),
    'the V3 unsigned certificate uses id-alg-unsigned');
  CheckEquals(0, System.Length(LCert.GetSignature), 'the V3 unsigned certificate has an empty signature');
end;

procedure TCertPathBuilderTest.TestBuildTargetInStore;
var
  LRootKp, LEeKp: IAsymmetricCipherKeyPair;
  LRoot, LEe: IX509Certificate;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LStore: IStore<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
  LResult: IPkixCertPathBuilderResult;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LEeKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LEe := TCertTestUtilities.GenerateEndEntityCert(LEeKp.Public as IAsymmetricKeyParameter,
    LRootKp.Private as IAsymmetricKeyParameter, LRoot);

  // target located by its subject in the store
  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := LEe.SubjectDN;
  LTarget := LSelector;

  LStore := TCollectionStore<IX509Certificate>.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(LEe));
  LParams := TPkixBuilderParameters.Create(AnchorsOf(LRoot), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
  LResult := LBuilder.Build(LParams);

  CheckNotNull(LResult, 'a target found in the store yields a path');
  CheckEquals(1, System.Length(LResult.CertPath.Certificates),
    'the built path holds the single end-entity certificate below the trust anchor');
end;

procedure TCertPathBuilderTest.TestBuildTargetViaSelector;
var
  LRootKp, LEeKp: IAsymmetricCipherKeyPair;
  LRoot, LEe: IX509Certificate;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LStore: IStore<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
  LResult: IPkixCertPathBuilderResult;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LEeKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LEe := TCertTestUtilities.GenerateEndEntityCert(LEeKp.Public as IAsymmetricKeyParameter,
    LRootKp.Private as IAsymmetricKeyParameter, LRoot);

  // the end-entity is NOT in the store; it is named directly on the selector instead
  LSelector := TX509CertStoreSelector.Create();
  LSelector.Certificate := LEe;
  LTarget := LSelector;

  LStore := TCollectionStore<IX509Certificate>.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(LRoot));
  LParams := TPkixBuilderParameters.Create(AnchorsOf(LRoot), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
  LResult := LBuilder.Build(LParams);

  CheckNotNull(LResult, 'a target specified on the selector yields a path even when absent from the stores');
  CheckEquals(1, System.Length(LResult.CertPath.Certificates),
    'the built path holds the single end-entity certificate below the trust anchor');
end;

procedure TCertPathBuilderTest.TestBuildWithUnsignedTrustAnchor;
var
  LRootKp, LEeKp: IAsymmetricCipherKeyPair;
  LRootDn: IX509Name;
  LUtcNow: TDateTime;
  LRootGen: IX509V1CertificateGenerator;
  LRoot, LEe: IX509Certificate;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LStore: IStore<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
  LResult: IPkixCertPathBuilderResult;
begin
  // an unsigned (id-alg-unsigned) self-issued root, used as the trust anchor
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRootDn := TX509Name.Create('CN=Unsigned Root CA');
  LUtcNow := Now.ToUniversalTime();

  LRootGen := TX509V1CertificateGenerator.Create;
  LRootGen.SetSerialNumber(TBigInteger.One);
  LRootGen.SetIssuerDN(LRootDn);
  LRootGen.SetNotBeforeUtc(IncSecond(LUtcNow, -5));
  LRootGen.SetNotAfterUtc(IncMinute(LUtcNow, 30));
  LRootGen.SetSubjectDN(LRootDn);
  LRootGen.SetPublicKey(LRootKp.Public as IAsymmetricKeyParameter);
  LRoot := LRootGen.GenerateUnsigned();

  LEeKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LEe := TCertTestUtilities.GenerateEndEntityCert(LEeKp.Public as IAsymmetricKeyParameter,
    LRootKp.Private as IAsymmetricKeyParameter, LRoot);

  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := LEe.SubjectDN;
  LTarget := LSelector;

  LStore := TCollectionStore<IX509Certificate>.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(LEe));
  LParams := TPkixBuilderParameters.Create(AnchorsOf(LRoot), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
  LResult := LBuilder.Build(LParams);

  CheckNotNull(LResult, 'a chain anchored at an unsigned trust anchor builds and validates');
  CheckEquals(1, System.Length(LResult.CertPath.Certificates),
    'the built path holds the single end-entity certificate below the unsigned anchor');
end;

procedure TCertPathBuilderTest.TestBuilderInstanceReuse;
var
  LRootKp, LEeKp, LOtherKp: IAsymmetricCipherKeyPair;
  LRoot, LEe, LOther, LBadSignature: IX509Certificate;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LStore: IStore<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LResult: IPkixCertPathBuilderResult;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LEeKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LEe := TCertTestUtilities.GenerateEndEntityCert(LEeKp.Public as IAsymmetricKeyParameter,
    LRootKp.Private as IAsymmetricKeyParameter, LRoot);
  LOtherKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LOther := TCertTestUtilities.GenerateRootCert(LOtherKp, TX509Name.Create('CN=Unrelated CA') as IX509Name);
  LBadSignature := TCertTestUtilities.GenerateEndEntityCert(LEeKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Bad Signature') as IX509Name, LOtherKp.Private as IAsymmetricKeyParameter, LRoot);

  // one builder instance is reused across three builds

  // 0) a leaf the anchor it names did not sign leaves an invalid-signature failure behind
  CheckEquals(Ord(TPkixCertPathValidatorReason.InvalidSignature),
    Ord(BuildFailureReason(LRoot, LBadSignature.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LBadSignature))),
    'the first build reports the invalid signature');

  // 1) the end-entity does not chain to the (unrelated) trust anchor: no path, and the earlier
  // failure must not be reported
  CheckEquals(Ord(TPkixCertPathValidatorReason.NoTrustAnchor),
    Ord(BuildFailureReason(LOther, LEe.SubjectDN, TCryptoLibGenericArray<IX509Certificate>.Create(LEe))),
    'the second build finds no issuer for the end-entity');

  // 2) the SAME builder instance must still find a valid chain to the correct anchor
  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := LEe.SubjectDN;
  LTarget := LSelector;
  LStore := TCollectionStore<IX509Certificate>.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(LEe));
  LParams := TPkixBuilderParameters.Create(AnchorsOf(LRoot), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  LResult := FBuilder.Build(LParams);
  CheckNotNull(LResult, 'reusing the builder after a failed build still finds a valid chain');
  CheckEquals(1, System.Length(LResult.CertPath.Certificates),
    'the reused builder returns the single end-entity certificate below the trust anchor');
end;

procedure TCertPathBuilderTest.TestNodeBudgetGuard;
var
  LRootKp, LInterKp, LEeKp: IAsymmetricCipherKeyPair;
  LRoot, LInter, LEe: IX509Certificate;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LStore: IStore<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
  LRaised: Boolean;
  LMessage: String;
  LReason: TPkixCertPathValidatorReason;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LInterKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LInter := TCertTestUtilities.GenerateEndEntityCert(LInterKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Intermediate') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot);
  LEeKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LEe := TCertTestUtilities.GenerateEndEntityCert(LEeKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=EndEntity') as IX509Name, LInterKp.Private as IAsymmetricKeyParameter, LInter);

  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := LEe.SubjectDN;
  LTarget := LSelector;

  LStore := TCollectionStore<IX509Certificate>.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(LInter, LEe));
  LParams := TPkixBuilderParameters.Create(AnchorsOf(LRoot), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  // a budget of one is exceeded as soon as the search recurses past the target certificate
  TCryptoLibConfig.X509.MaxCertPathBuildNodes := 1;

  LRaised := False;
  LMessage := '';
  LReason := TPkixCertPathValidatorReason.Unspecified;
  try
    LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
    LBuilder.Build(LParams);
  except
    on E: EPkixCertPathBuilderCryptoLibException do
    begin
      LRaised := True;
      LMessage := E.Message;
      LReason := E.Reason;
    end;
  end;

  CheckTrue(LRaised, 'exceeding the node budget aborts the build');
  CheckTrue(Pos('node limit', LMessage) > 0,
    Format('the failure names the node limit, got "%s"', [LMessage]));
  CheckEquals(Ord(TPkixCertPathValidatorReason.LimitExceeded), Ord(LReason),
    'exceeding the node budget reports the limit');
end;

procedure TCertPathBuilderTest.TestBuilderExceptionReasonDefaultsToUnspecified;
var
  LPlain, LWithReason: EPkixCertPathBuilderCryptoLibException;
begin
  LPlain := EPkixCertPathBuilderCryptoLibException.Create('plain');
  try
    CheckEquals(Ord(TPkixCertPathValidatorReason.Unspecified), Ord(LPlain.Reason),
      'an exception built without a reason reports Unspecified');
  finally
    LPlain.Free;
  end;

  LWithReason := EPkixCertPathBuilderCryptoLibException.CreateReason(
    TPkixCertPathValidatorReason.Revoked, 'revoked');
  try
    CheckEquals(Ord(TPkixCertPathValidatorReason.Revoked), Ord(LWithReason.Reason),
      'the reason given at construction is kept');
    CheckEquals('revoked', LWithReason.Message, 'the message is kept');
  finally
    LWithReason.Free;
  end;
end;

procedure TCertPathBuilderTest.TestBadSignatureUnderPooledIntermediate;
var
  LRootKp, LInterKp, LLeafKp, LOtherKp: IAsymmetricCipherKeyPair;
  LRoot, LInter, LLeaf: IX509Certificate;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LInterKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LInter := TCertTestUtilities.GenerateEndEntityCert(LInterKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Intermediate') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot);
  LLeafKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LOtherKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  // the leaf names the intermediate as its issuer but is signed with another key
  LLeaf := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LOtherKp.Private as IAsymmetricKeyParameter, LInter);

  CheckEquals(Ord(TPkixCertPathValidatorReason.InvalidSignature),
    Ord(BuildFailureReason(LRoot, LLeaf.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LInter, LLeaf))),
    'a leaf not signed by its pooled issuer reports an invalid signature');
end;

procedure TCertPathBuilderTest.TestBadSignatureDirectlyUnderAnchor;
var
  LRootKp, LLeafKp, LOtherKp: IAsymmetricCipherKeyPair;
  LRoot, LLeaf: IX509Certificate;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LLeafKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LOtherKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  // the leaf names the trust anchor as its issuer but is signed with another key
  LLeaf := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LOtherKp.Private as IAsymmetricKeyParameter, LRoot);

  CheckEquals(Ord(TPkixCertPathValidatorReason.InvalidSignature),
    Ord(BuildFailureReason(LRoot, LLeaf.SubjectDN, TCryptoLibGenericArray<IX509Certificate>.Create(LLeaf))),
    'a leaf not signed by the anchor it names reports an invalid signature');
end;

procedure TCertPathBuilderTest.TestUnrecognizedCriticalExtensionOnLeaf;
var
  LRootKp, LLeafKp: IAsymmetricCipherKeyPair;
  LRoot, LLeaf: IX509Certificate;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LLeafKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LLeaf := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot,
    '2.999.1', False);

  CheckEquals(Ord(TPkixCertPathValidatorReason.UnrecognizedCriticalExtension),
    Ord(BuildFailureReason(LRoot, LLeaf.SubjectDN, TCryptoLibGenericArray<IX509Certificate>.Create(LLeaf))),
    'an unprocessed critical extension on the leaf is reported');
end;

procedure TCertPathBuilderTest.TestUnrecognizedCriticalExtensionOnIntermediate;
var
  LRootKp, LInterKp, LLeafKp: IAsymmetricCipherKeyPair;
  LRoot, LInter, LLeaf: IX509Certificate;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LInterKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LInter := TCertTestUtilities.GenerateEndEntityCert(LInterKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Intermediate') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot,
    '2.999.1', False);
  LLeafKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LLeaf := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LInterKp.Private as IAsymmetricKeyParameter, LInter);

  CheckEquals(Ord(TPkixCertPathValidatorReason.UnrecognizedCriticalExtension),
    Ord(BuildFailureReason(LRoot, LLeaf.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LInter, LLeaf))),
    'an unprocessed critical extension on an intermediate is reported');
end;

procedure TCertPathBuilderTest.TestExpiredOutranksCriticalExtension;
var
  LRootKp, LLeafKp: IAsymmetricCipherKeyPair;
  LRoot, LExpired, LCritical: IX509Certificate;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LLeafKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LExpired := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot, '', True);
  LCritical := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot,
    '2.999.1', False);

  // the winner must not depend on which candidate is tried last
  CheckEquals(Ord(TPkixCertPathValidatorReason.Expired),
    Ord(BuildFailureReason(LRoot, LExpired.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LExpired, LCritical))),
    'expired outranks an unprocessed critical extension when tried first');
  CheckEquals(Ord(TPkixCertPathValidatorReason.Expired),
    Ord(BuildFailureReason(LRoot, LExpired.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LCritical, LExpired))),
    'expired outranks an unprocessed critical extension when tried last');
end;

procedure TCertPathBuilderTest.TestInvalidSignatureOutranksCriticalExtension;
var
  LRootKp, LLeafKp, LOtherKp: IAsymmetricCipherKeyPair;
  LRoot, LBadSignature, LCritical: IX509Certificate;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LLeafKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LOtherKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LBadSignature := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LOtherKp.Private as IAsymmetricKeyParameter, LRoot);
  LCritical := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot,
    '2.999.1', False);

  CheckEquals(Ord(TPkixCertPathValidatorReason.InvalidSignature),
    Ord(BuildFailureReason(LRoot, LBadSignature.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LBadSignature, LCritical))),
    'an invalid signature outranks an unprocessed critical extension when tried first');
  CheckEquals(Ord(TPkixCertPathValidatorReason.InvalidSignature),
    Ord(BuildFailureReason(LRoot, LBadSignature.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LCritical, LBadSignature))),
    'an invalid signature outranks an unprocessed critical extension when tried last');
end;

procedure TCertPathBuilderTest.TestCriticalExtensionOutranksNoIssuer;
var
  LRootKp, LLeafKp, LAbsentKp: IAsymmetricCipherKeyPair;
  LRoot, LAbsent, LCritical, LOrphan: IX509Certificate;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LLeafKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LAbsentKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LAbsent := TCertTestUtilities.GenerateRootCert(LAbsentKp, TX509Name.Create('CN=Absent CA') as IX509Name);
  LCritical := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LRootKp.Private as IAsymmetricKeyParameter, LRoot,
    '2.999.1', False);
  // same subject, but its issuer is neither a trust anchor nor in the store
  LOrphan := TCertTestUtilities.GenerateEndEntityCert(LLeafKp.Public as IAsymmetricKeyParameter,
    TX509Name.Create('CN=Leaf') as IX509Name, LAbsentKp.Private as IAsymmetricKeyParameter, LAbsent);

  // the orphan is tried last, so only the ranking keeps the critical-extension failure
  CheckEquals(Ord(TPkixCertPathValidatorReason.UnrecognizedCriticalExtension),
    Ord(BuildFailureReason(LRoot, LCritical.SubjectDN,
    TCryptoLibGenericArray<IX509Certificate>.Create(LCritical, LOrphan))),
    'an unprocessed critical extension outranks a candidate with no issuer');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCertPathBuilderTest);
{$ELSE}
  RegisterTest(TCertPathBuilderTest.Suite);
{$ENDIF FPC}

end.
