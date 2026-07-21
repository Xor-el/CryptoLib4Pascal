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

unit CertPathValidatorTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIStore,
  ClpCollectionStore,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixBuilderParameters,
  ClpPkixCertPathValidator,
  ClpPkixCertPathChecker,
  ClpPkixNameConstraintValidator,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509CertificateParser,
  ClpX509CertificateParser,
  ClpIX509CrlParser,
  ClpX509CrlParser,
  ClpNullable,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpCryptoLibConfig,
  CertVectors,
  CryptoLibTestBase;

type

  /// <summary>
  /// A checker that only counts the certificates handed to it, so a test can assert that every
  /// certificate of the path was passed through the additional checks of RFC 5280 6.1.4 (f).
  /// </summary>
  /// <remarks>
  /// The count is shared by every instance because the parameters clone a checker on the way in and
  /// again on the way out, so the object the test holds is never the one that runs.
  /// </remarks>
  TCountingChecker = class(TPkixCertPathCheckerBase)
  strict private
    class var FCount: Int32;

  public
    class procedure Reset(); static;
    class function Count: Int32; static;

    procedure Init(AForward: Boolean); override;
    function IsForwardCheckingSupported: Boolean; override;
    function GetSupportedExtensions: TCryptoLibStringArray; override;
    procedure Check(const ACert: IX509Certificate;
      const AUnresolvedCritExts: TList<String>); override;
    function Clone: IPkixCertPathChecker; override;
  end;

  /// <summary>
  /// End to end certification path validation (RFC 5280 6.1) over complete certificate and CRL sets.
  /// </summary>
  TCertPathValidatorTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function ReadCert(const ACertId: String): IX509Certificate;
    function ReadCrl(const ACertId: String): IX509Crl;
    function AnchorsOf(const ACert: IX509Certificate): TCryptoLibGenericArray<ITrustAnchor>;
    /// <summary>Runs the SGP.22 chain, whose eUICC subject is not an RFC 5280 prefix of the EUM subtree.</summary>
    function ValidateSgp22Chain: IPkixCertPathValidatorResult;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestValidPath;
    procedure TestValidPathWithTrustAnchorIncluded;
    procedure TestInvalidPathContainingAValidOne;
    procedure TestCircularCrlIssuerProcessing;
    procedure TestPolicyProcessingAtDomainMatch;
    procedure TestSgp22NameConstraintsWithOverride;
    procedure TestSgp22NameConstraintsFromPolicyMarker;

  end;

implementation

{ TCountingChecker }

class procedure TCountingChecker.Reset();
begin
  FCount := 0;
end;

class function TCountingChecker.Count: Int32;
begin
  Result := FCount;
end;

procedure TCountingChecker.Init(AForward: Boolean);
begin
  // nothing to reset per run; the count is asserted across the whole validation
end;

function TCountingChecker.IsForwardCheckingSupported: Boolean;
begin
  Result := True;
end;

function TCountingChecker.GetSupportedExtensions: TCryptoLibStringArray;
begin
  Result := nil;
end;

procedure TCountingChecker.Check(const ACert: IX509Certificate;
  const AUnresolvedCritExts: TList<String>);
begin
  System.Inc(FCount);
end;

function TCountingChecker.Clone: IPkixCertPathChecker;
begin
  Result := TCountingChecker.Create() as IPkixCertPathChecker;
end;

{ TCertPathValidatorTest }

procedure TCertPathValidatorTest.SetUp;
begin
  inherited SetUp;
  TCountingChecker.Reset();
  TCryptoLibConfig.X509.Sgp22NameConstraints := False;
end;

procedure TCertPathValidatorTest.TearDown;
begin
  // the leniency switch is process wide, so it must never leak out of a test
  TCryptoLibConfig.X509.Sgp22NameConstraints := False;
  inherited TearDown;
end;

function TCertPathValidatorTest.ReadCert(const ACertId: String): IX509Certificate;
var
  LParser: IX509CertificateParser;
begin
  LParser := TX509CertificateParser.Create();
  Result := LParser.ReadCertificate(TCertVectors.LoadDer(ACertId));
end;

function TCertPathValidatorTest.ReadCrl(const ACertId: String): IX509Crl;
var
  LParser: IX509CrlParser;
begin
  LParser := TX509CrlParser.Create();
  Result := LParser.ReadCrl(TCertVectors.LoadDer(ACertId));
end;

function TCertPathValidatorTest.AnchorsOf(const ACert: IX509Certificate)
  : TCryptoLibGenericArray<ITrustAnchor>;
begin
  Result := TCryptoLibGenericArray<ITrustAnchor>.Create(TTrustAnchor.Create(ACert, nil)
    as ITrustAnchor);
end;

procedure TCertPathValidatorTest.TestValidPath;
var
  LRootCert, LInterCert, LFinalCert: IX509Certificate;
  LCertStore: IStore<IX509Certificate>;
  LCrlStore: IStore<IX509Crl>;
  LPath: IPkixCertPath;
  LParams: IPkixParameters;
  LValidator: IPkixCertPathValidator;
  LResult: IPkixCertPathValidatorResult;
begin
  LRootCert := ReadCert('PkixTestRootCa');
  LInterCert := ReadCert('PkixTestIntermediateCa');
  LFinalCert := ReadCert('PkixTestEndEntity');

  // a generic interface carries no GUID, so these upcast through typed locals instead of "as"
  LCertStore := TCollectionStore<IX509Certificate>.Create
    (TCryptoLibGenericArray<IX509Certificate>.Create(LRootCert, LInterCert, LFinalCert));
  LCrlStore := TCollectionStore<IX509Crl>.Create(TCryptoLibGenericArray<IX509Crl>.Create
    (ReadCrl('PkixTestRootCrl'), ReadCrl('PkixTestIntermediateCrl')));

  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(LFinalCert,
    LInterCert)) as IPkixCertPath;

  LParams := TPkixParameters.Create(AnchorsOf(LRootCert)) as IPkixParameters;
  LParams.AddStoreCert(LCertStore);
  LParams.AddStoreCrl(LCrlStore);
  LParams.Date := TNullable<TDateTime>.Some(EncodeDate(2008, 9, 4) + EncodeTime(5, 49, 10, 0));
  LParams.AddCertPathChecker(TCountingChecker.Create() as IPkixCertPathChecker);

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  LResult := LValidator.Validate(LPath, LParams);

  CheckEquals(2, TCountingChecker.Count, 'the checker runs once per certificate of the path');
  CheckTrue(LResult.SubjectPublicKey.Equals(LFinalCert.GetPublicKey()),
    'the end entity public key is returned');
  CheckTrue(LResult.TrustAnchor.TrustedCert.Equals(LRootCert), 'the trust anchor is reported back');
end;

procedure TCertPathValidatorTest.TestValidPathWithTrustAnchorIncluded;
var
  LRootCert, LInterCert, LFinalCert: IX509Certificate;
  LCertStore: IStore<IX509Certificate>;
  LCrlStore: IStore<IX509Crl>;
  LPath: IPkixCertPath;
  LParams: IPkixParameters;
  LValidator: IPkixCertPathValidator;
  LResult: IPkixCertPathValidatorResult;
begin
  LRootCert := ReadCert('PkixTestRootCa');
  LInterCert := ReadCert('PkixTestIntermediateCa');
  LFinalCert := ReadCert('PkixTestEndEntity');

  LCertStore := TCollectionStore<IX509Certificate>.Create
    (TCryptoLibGenericArray<IX509Certificate>.Create(LRootCert, LInterCert, LFinalCert));
  LCrlStore := TCollectionStore<IX509Crl>.Create(TCryptoLibGenericArray<IX509Crl>.Create
    (ReadCrl('PkixTestRootCrl'), ReadCrl('PkixTestIntermediateCrl')));

  // the anchor's own certificate is allowed to appear in the path
  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(LFinalCert,
    LInterCert, LRootCert)) as IPkixCertPath;

  LParams := TPkixParameters.Create(AnchorsOf(LRootCert)) as IPkixParameters;
  LParams.AddStoreCert(LCertStore);
  LParams.AddStoreCrl(LCrlStore);
  LParams.Date := TNullable<TDateTime>.Some(EncodeDate(2008, 9, 4) + EncodeTime(5, 49, 10, 0));
  LParams.AddCertPathChecker(TCountingChecker.Create() as IPkixCertPathChecker);

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  LResult := LValidator.Validate(LPath, LParams);

  CheckTrue(LResult.TrustAnchor.TrustedCert.Equals(LRootCert), 'the trust anchor is reported back');
end;

procedure TCertPathValidatorTest.TestInvalidPathContainingAValidOne;
var
  LRootCert, LInterCert, LFinalCert: IX509Certificate;
  LCertStore: IStore<IX509Certificate>;
  LPath: IPkixCertPath;
  LParams: IPkixParameters;
  LValidator: IPkixCertPathValidator;
  LRejected: Boolean;
  LIndex: Int32;
begin
  // the end entity is not issued by the intermediate, so its signature cannot verify
  LRootCert := ReadCert('PkixBrokenChainRootCa');
  LInterCert := ReadCert('PkixBrokenChainIntermediateCa');
  LFinalCert := ReadCert('PkixBrokenChainEndEntity');

  LCertStore := TCollectionStore<IX509Certificate>.Create
    (TCryptoLibGenericArray<IX509Certificate>.Create(LRootCert, LInterCert, LFinalCert));

  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(LFinalCert,
    LInterCert)) as IPkixCertPath;

  LParams := TPkixParameters.Create(AnchorsOf(LRootCert)) as IPkixParameters;
  LParams.AddStoreCert(LCertStore);
  LParams.IsRevocationEnabled := False;
  LParams.Date := TNullable<TDateTime>.Some(EncodeDate(2004, 3, 20) + EncodeTime(19, 21, 10, 0));

  LRejected := False;
  LIndex := -1;
  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  try
    LValidator.Validate(LPath, LParams);
  except
    on E: EPkixCertPathValidatorCryptoLibException do
    begin
      LRejected := True;
      LIndex := E.Index;
    end;
  end;

  CheckTrue(LRejected, 'a path whose end entity signature does not verify is rejected');
  if LIndex >= 0 then
    CheckEquals(0, LIndex, 'the end entity certificate is blamed');
end;

procedure TCertPathValidatorTest.TestCircularCrlIssuerProcessing;
var
  LCaCert, LCrlCaCert: IX509Certificate;
  LCrl: IX509Crl;
  LCertStore: IStore<IX509Certificate>;
  LCrlStore: IStore<IX509Crl>;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LPath: IPkixCertPath;
  LParams: IPkixBuilderParameters;
  LValidator: IPkixCertPathValidator;
  LResult: IPkixCertPathValidatorResult;
begin
  // the CRL that covers the CRL signer is itself issued by that signer, so the revocation check
  // must not recurse forever
  LCaCert := ReadCert('PkixCircularCrlRootCa');
  LCrlCaCert := ReadCert('PkixCircularCrlSignerCa');
  LCrl := ReadCrl('PkixCircularCrl');

  LCertStore := TCollectionStore<IX509Certificate>.Create
    (TCryptoLibGenericArray<IX509Certificate>.Create(LCaCert, LCrlCaCert));
  LCrlStore := TCollectionStore<IX509Crl>.Create(TCryptoLibGenericArray<IX509Crl>.Create(LCrl));

  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(LCrlCaCert))
    as IPkixCertPath;

  LSelector := TX509CertStoreSelector.Create();
  LSelector.Certificate := LCrlCaCert;
  LTarget := LSelector;

  LParams := TPkixBuilderParameters.Create(AnchorsOf(LCaCert), LTarget) as IPkixBuilderParameters;
  LParams.SetTargetConstraintsCert(LTarget);
  LParams.AddStoreCert(LCertStore);
  LParams.AddStoreCrl(LCrlStore);
  LParams.IsRevocationEnabled := True;
  LParams.Date := TNullable<TDateTime>.Some(LCrl.ThisUpdate + (1 / 24));

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  LResult := LValidator.Validate(LPath, LParams);
  CheckNotNull(LResult, 'the path validates without looping through the CRL issuer');
end;

procedure TCertPathValidatorTest.TestPolicyProcessingAtDomainMatch;
var
  LRoot, LCa1, LCa2, LEndEntity: IX509Certificate;
  LPath: IPkixCertPath;
  LParams: IPkixParameters;
  LValidator: IPkixCertPathValidator;
  LResult: IPkixCertPathValidatorResult;
begin
  LRoot := ReadCert('PkixDomainPolicyRootCa');
  LCa1 := ReadCert('PkixDomainPolicyCa1');
  LCa2 := ReadCert('PkixDomainPolicyCa2');
  LEndEntity := ReadCert('PkixDomainPolicyEndEntity');

  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(LEndEntity, LCa2,
    LCa1)) as IPkixCertPath;

  LParams := TPkixParameters.Create(AnchorsOf(LRoot)) as IPkixParameters;
  LParams.IsRevocationEnabled := False;
  LParams.Date := TNullable<TDateTime>.Some(EncodeDate(2016, 8, 1) + EncodeTime(4, 19, 35, 220));
  LParams.AddCertPathChecker(TCountingChecker.Create() as IPkixCertPathChecker);

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  LResult := LValidator.Validate(LPath, LParams);
  CheckNotNull(LResult, 'a three certificate policy domain chain validates');
end;

function TCertPathValidatorTest.ValidateSgp22Chain: IPkixCertPathValidatorResult;
var
  LRootCert, LInterCert, LFinalCert: IX509Certificate;
  LPath: IPkixCertPath;
  LParams: IPkixParameters;
  LValidator: IPkixCertPathValidator;
begin
  LRootCert := ReadCert('PkixSgp22CiRootCa');
  LInterCert := ReadCert('PkixSgp22EumCa');
  LFinalCert := ReadCert('PkixSgp22EuiccEndEntity');

  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(LInterCert,
    LFinalCert)) as IPkixCertPath;

  LParams := TPkixParameters.Create(AnchorsOf(LRootCert)) as IPkixParameters;
  LParams.IsRevocationEnabled := False;

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  Result := LValidator.Validate(LPath, LParams);
end;

procedure TCertPathValidatorTest.TestSgp22NameConstraintsWithOverride;
begin
  // the end entity subject is not an initial prefix of the intermediate's permitted subtree, so
  // only the relaxed directoryName matching accepts this chain
  TCryptoLibConfig.X509.Sgp22NameConstraints := True;
  CheckNotNull(ValidateSgp22Chain(), 'the relaxed directoryName matching accepts the chain');
end;

procedure TCertPathValidatorTest.TestSgp22NameConstraintsFromPolicyMarker;
begin
  // the chain names itself by its critical policy OIDs, which is meant to select the relaxed
  // directoryName matching without the manual override
  CheckNotNull(ValidateSgp22Chain(), 'the policy markers select the relaxed matching');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCertPathValidatorTest);
{$ELSE}
  RegisterTest(TCertPathValidatorTest.Suite);
{$ENDIF FPC}

end.
