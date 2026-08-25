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
    function AnchorsOf(const ACert: IX509Certificate): TCryptoLibGenericArray<ITrustAnchor>;

  protected
    procedure TearDown; override;

  published
    procedure TestGenerateUnsignedCertificate;
    procedure TestBuildTargetInStore;
    procedure TestBuildTargetViaSelector;
    procedure TestBuildWithUnsignedTrustAnchor;
    procedure TestBuilderInstanceReuse;
    procedure TestNodeBudgetGuard;
  end;

implementation

{ TCertPathBuilderTest }

function TCertPathBuilderTest.AnchorsOf(const ACert: IX509Certificate)
  : TCryptoLibGenericArray<ITrustAnchor>;
begin
  Result := TCryptoLibGenericArray<ITrustAnchor>.Create(TTrustAnchor.Create(ACert, nil) as ITrustAnchor);
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
  LRoot, LEe, LOther: IX509Certificate;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LStore: IStore<IX509Certificate>;
  LParams: IPkixBuilderParameters;
  LBuilder: IPkixCertPathBuilder;
  LResult: IPkixCertPathBuilderResult;
  LRaised: Boolean;
begin
  LRootKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LRoot := TCertTestUtilities.GenerateRootCert(LRootKp);
  LEeKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LEe := TCertTestUtilities.GenerateEndEntityCert(LEeKp.Public as IAsymmetricKeyParameter,
    LRootKp.Private as IAsymmetricKeyParameter, LRoot);
  LOtherKp := TCertTestUtilities.GenerateRsaKeyPair(1024);
  LOther := TCertTestUtilities.GenerateRootCert(LOtherKp, TX509Name.Create('CN=Unrelated CA') as IX509Name);

  // one builder instance is reused across two builds
  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;

  // 1) the end-entity does not chain to the (unrelated) trust anchor: no path
  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := LEe.SubjectDN;
  LTarget := LSelector;
  LStore := TCollectionStore<IX509Certificate>.Create(
    TCryptoLibGenericArray<IX509Certificate>.Create(LEe));
  LParams := TPkixBuilderParameters.Create(AnchorsOf(LOther), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  LRaised := False;
  try
    LBuilder.Build(LParams);
  except
    on E: EPkixCertPathBuilderCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'the first build finds no chain to the unrelated trust anchor');

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

  LResult := LBuilder.Build(LParams);
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
  try
    LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
    LBuilder.Build(LParams);
  except
    on E: EPkixCertPathBuilderCryptoLibException do
    begin
      LRaised := True;
      LMessage := E.Message;
    end;
  end;

  CheckTrue(LRaised, 'exceeding the node budget aborts the build');
  CheckTrue(Pos('node limit', LMessage) > 0,
    Format('the failure names the node limit, got "%s"', [LMessage]));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCertPathBuilderTest);
{$ELSE}
  RegisterTest(TCertPathBuilderTest.Suite);
{$ENDIF FPC}

end.
