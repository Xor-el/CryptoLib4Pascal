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

unit PkixFoundationTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
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
  ClpCertStatus,
  ClpReasonsMask,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixBuilderParameters,
  ClpIX509Certificate,
  ClpIX509CertificatePair,
  ClpX509CertificatePair,
  ClpIX509CertificateParser,
  ClpX509CertificateParser,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpNullable,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CertVectors,
  CryptoLibTestBase;

type

  TPkixFoundationTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRootCert: IX509Certificate;
    FInterCert: IX509Certificate;
    FFinalCert: IX509Certificate;

    procedure SetUpTestData;
    function AllCerts: TCryptoLibGenericArray<IX509Certificate>;
    function NewCertSelector: IX509CertStoreSelector;
    function NewTrustAnchor(const ACert: IX509Certificate): ITrustAnchor;

  protected
    procedure SetUp; override;

  published
    procedure TestCertStoreSelectorCriteria;
    procedure TestCertStoreSelectorClonesIndependently;
    procedure TestCollectionStoreEnumerateMatches;
    procedure TestCertPairStoreSelector;
    procedure TestCrlStoreSelectorRoundTrip;
    procedure TestTrustAnchor;
    procedure TestCertStatusAndReasonsMask;
    procedure TestPkixParametersCloneAndValidation;
    procedure TestPkixBuilderParameters;
    procedure TestPkixCertPathSortsAndEncodes;

  end;

implementation

{ TPkixFoundationTest }

procedure TPkixFoundationTest.SetUpTestData;
var
  LParser: IX509CertificateParser;
begin
  LParser := TX509CertificateParser.Create();
  FRootCert := LParser.ReadCertificate(TCertVectors.LoadDer('PkixTestRootCa'));
  FInterCert := LParser.ReadCertificate(TCertVectors.LoadDer('PkixTestIntermediateCa'));
  FFinalCert := LParser.ReadCertificate(TCertVectors.LoadDer('PkixTestEndEntity'));
end;

procedure TPkixFoundationTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

function TPkixFoundationTest.AllCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  Result := TCryptoLibGenericArray<IX509Certificate>.Create(FRootCert, FInterCert, FFinalCert);
end;

function TPkixFoundationTest.NewCertSelector: IX509CertStoreSelector;
begin
  Result := TX509CertStoreSelector.Create();
end;

function TPkixFoundationTest.NewTrustAnchor(const ACert: IX509Certificate): ITrustAnchor;
begin
  Result := TTrustAnchor.Create(ACert, nil);
end;

procedure TPkixFoundationTest.TestCertStoreSelectorCriteria;
var
  LSelector: IX509CertStoreSelector;
begin
  LSelector := NewCertSelector();
  CheckFalse(LSelector.Match(nil), 'a nil candidate never matches');
  CheckTrue(LSelector.Match(FRootCert), 'an unconstrained selector matches anything');

  LSelector := NewCertSelector();
  LSelector.Subject := FFinalCert.SubjectDN;
  CheckTrue(LSelector.Match(FFinalCert), 'subject criterion should match its own certificate');
  CheckFalse(LSelector.Match(FInterCert), 'subject criterion should reject a different subject');

  LSelector := NewCertSelector();
  LSelector.Issuer := FFinalCert.IssuerDN;
  CheckTrue(LSelector.Match(FFinalCert), 'issuer criterion should match');
  CheckFalse(LSelector.Match(FRootCert), 'issuer criterion should reject a different issuer');

  LSelector := NewCertSelector();
  LSelector.Certificate := FInterCert;
  CheckTrue(LSelector.Match(FInterCert), 'certificate criterion should match itself');
  CheckFalse(LSelector.Match(FFinalCert), 'certificate criterion should reject another certificate');

  LSelector := NewCertSelector();
  LSelector.SerialNumber := FInterCert.SerialNumber;
  CheckTrue(LSelector.Match(FInterCert), 'serial number criterion should match');

  // -2 selects only end-entity certificates
  LSelector := NewCertSelector();
  LSelector.BasicConstraints := -2;
  CheckTrue(LSelector.Match(FFinalCert), 'the end certificate is not a CA');
  CheckFalse(LSelector.Match(FInterCert), 'the intermediate certificate is a CA');

  LSelector := NewCertSelector();
  LSelector.CertificateValid := TNullable<TDateTime>.Some(FFinalCert.NotBefore);
  CheckTrue(LSelector.Match(FFinalCert), 'the certificate is valid at its own notBefore');
  LSelector.CertificateValid := TNullable<TDateTime>.Some(FFinalCert.NotAfter + 1);
  CheckFalse(LSelector.Match(FFinalCert), 'the certificate has expired by then');

  LSelector := NewCertSelector();
  LSelector.SubjectPublicKey := FRootCert.SubjectPublicKeyInfo;
  CheckTrue(LSelector.Match(FRootCert), 'public key criterion should match');
  CheckFalse(LSelector.Match(FInterCert), 'public key criterion should reject a different key');

  LSelector := NewCertSelector();
  LSelector.SubjectPublicKeyAlgID := FRootCert.SubjectPublicKeyInfo.Algorithm.Algorithm;
  CheckTrue(LSelector.Match(FInterCert), 'every test certificate uses the same key algorithm');

  // an empty policy set still demands a certificate policies extension
  LSelector := NewCertSelector();
  CheckFalse(LSelector.HasPolicy, 'no policy criterion by default');
  LSelector.Policy := nil;
  CheckTrue(LSelector.HasPolicy, 'setting the policy enables the criterion');
  CheckFalse(LSelector.Match(FFinalCert), 'the test certificates carry no policies extension');
  LSelector.ClearPolicy();
  CheckFalse(LSelector.HasPolicy, 'clearing the policy disables the criterion');
  CheckTrue(LSelector.Match(FFinalCert), 'without a policy criterion the certificate matches again');
end;

procedure TPkixFoundationTest.TestCertStoreSelectorClonesIndependently;
var
  LSelector, LClone: IX509CertStoreSelector;
  LBase: ISelector<IX509Certificate>;
  LCloned: ISelector<IX509Certificate>;
begin
  LSelector := NewCertSelector();
  LSelector.Subject := FFinalCert.SubjectDN;
  LSelector.BasicConstraints := -2;
  LSelector.IgnoreX509NameOrdering := True;

  LBase := LSelector;
  LCloned := LBase.Clone();
  CheckTrue(Supports(LCloned, IX509CertStoreSelector, LClone), 'a clone is still a cert selector');

  CheckEquals(-2, LClone.BasicConstraints, 'the clone keeps the basic constraints criterion');
  CheckTrue(LClone.IgnoreX509NameOrdering, 'the clone keeps the name ordering flag');
  CheckTrue(LClone.Match(FFinalCert), 'the clone matches what the original matched');

  LClone.BasicConstraints := -1;
  CheckEquals(-2, LSelector.BasicConstraints, 'mutating the clone must not touch the original');
end;

procedure TPkixFoundationTest.TestCollectionStoreEnumerateMatches;
var
  LStore: IStore<IX509Certificate>;
  LSelector: IX509CertStoreSelector;
  LBase: ISelector<IX509Certificate>;
  LMatches: TCryptoLibGenericArray<IX509Certificate>;
begin
  LStore := TCollectionStore<IX509Certificate>.Create(AllCerts());

  LMatches := LStore.EnumerateMatches(nil);
  CheckEquals(3, System.Length(LMatches), 'a nil selector matches everything in the store');

  LSelector := NewCertSelector();
  LSelector.Subject := FInterCert.SubjectDN;
  LBase := LSelector;
  LMatches := LStore.EnumerateMatches(LBase);
  CheckEquals(1, System.Length(LMatches), 'exactly one certificate carries that subject');
  CheckTrue(LMatches[0].Equals(FInterCert), 'the matched certificate is the intermediate one');

  LSelector := NewCertSelector();
  LSelector.BasicConstraints := -2;
  LBase := LSelector;
  LMatches := LStore.EnumerateMatches(LBase);
  // the v1 root carries no basic constraints extension, so it reads as an end-entity too
  CheckEquals(2, System.Length(LMatches), 'the end certificate and the v1 root are not CAs');
end;

procedure TPkixFoundationTest.TestCertPairStoreSelector;
var
  LPair, LOtherPair: IX509CertificatePair;
  LSelector: IX509CertPairStoreSelector;
  LForward: IX509CertStoreSelector;
begin
  LPair := TX509CertificatePair.Create(FRootCert, FInterCert);
  LOtherPair := TX509CertificatePair.Create(FInterCert, FFinalCert);

  LSelector := TX509CertPairStoreSelector.Create();
  CheckFalse(LSelector.Match(nil), 'a nil pair never matches');
  CheckTrue(LSelector.Match(LPair), 'an unconstrained pair selector matches anything');

  LSelector.CertPair := LPair;
  CheckTrue(LSelector.Match(LPair), 'the pair criterion matches itself');
  CheckFalse(LSelector.Match(LOtherPair), 'the pair criterion rejects a different pair');

  LForward := NewCertSelector();
  LForward.Subject := FRootCert.SubjectDN;

  LSelector := TX509CertPairStoreSelector.Create();
  LSelector.ForwardSelector := LForward;
  CheckTrue(LSelector.Match(LPair), 'the forward selector matches the forward certificate');
  CheckFalse(LSelector.Match(LOtherPair), 'the forward selector rejects the other pair');

  // the component selector is copied in, so later edits must not leak through
  LForward.Subject := FFinalCert.SubjectDN;
  CheckTrue(LSelector.Match(LPair), 'the stored forward selector is an independent copy');
end;

procedure TPkixFoundationTest.TestCrlStoreSelectorRoundTrip;
var
  LSelector: IX509CrlStoreSelector;
  LIssuers: TCryptoLibGenericArray<IX509Name>;
begin
  LSelector := TX509CrlStoreSelector.Create();
  CheckFalse(LSelector.Match(nil), 'a nil CRL never matches');

  LSelector.CertificateChecking := FFinalCert;
  LSelector.MinCrlNumber := TBigInteger.One;
  LSelector.MaxCrlNumber := TBigInteger.Two;
  LSelector.CompleteCrlEnabled := True;
  LSelector.IssuingDistributionPointEnabled := True;
  LSelector.IssuingDistributionPoint := TCryptoLibByteArray.Create(1, 2, 3);
  LIssuers := TCryptoLibGenericArray<IX509Name>.Create(FFinalCert.IssuerDN);
  LSelector.Issuers := LIssuers;

  CheckTrue(LSelector.CertificateChecking.Equals(FFinalCert), 'the checked certificate round-trips');
  CheckTrue(LSelector.MinCrlNumber.Equals(TBigInteger.One), 'the minimum CRL number round-trips');
  CheckTrue(LSelector.MaxCrlNumber.Equals(TBigInteger.Two), 'the maximum CRL number round-trips');
  CheckTrue(LSelector.CompleteCrlEnabled, 'the complete CRL flag round-trips');
  CheckEquals(1, System.Length(LSelector.Issuers), 'the issuers criterion round-trips');
  CheckTrue(AreEqual(TCryptoLibByteArray.Create(1, 2, 3), LSelector.IssuingDistributionPoint),
    'the issuing distribution point round-trips');

  // the byte array criterion is copied on the way out
  LSelector.IssuingDistributionPoint[0] := 9;
  CheckTrue(AreEqual(TCryptoLibByteArray.Create(1, 2, 3), LSelector.IssuingDistributionPoint),
    'the returned issuing distribution point is a copy');
end;

procedure TPkixFoundationTest.TestTrustAnchor;
var
  LAnchor: ITrustAnchor;
  LRaised: Boolean;
begin
  LAnchor := NewTrustAnchor(FRootCert);
  CheckTrue(LAnchor.TrustedCert.Equals(FRootCert), 'the trusted certificate round-trips');
  CheckNull(LAnchor.CAPublicKey, 'no public key was supplied separately');
  CheckNull(LAnchor.GetNameConstraintsObject, 'no name constraints were supplied');

  LAnchor := TTrustAnchor.Create(FRootCert.SubjectDN, FRootCert.GetPublicKey, nil);
  CheckNull(LAnchor.TrustedCert, 'no trusted certificate was supplied');
  CheckNotNull(LAnchor.CAPublicKey, 'the public key round-trips');
  CheckTrue(LAnchor.CA.Equivalent(FRootCert.SubjectDN, True), 'the CA name round-trips');
  CheckEquals(FRootCert.SubjectDN.ToString(), LAnchor.CAName, 'the CA name string round-trips');

  LRaised := False;
  try
    LAnchor := TTrustAnchor.Create(IX509Certificate(nil), nil);
  except
    on E: EArgumentNilCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a nil trusted certificate is rejected');
end;

procedure TPkixFoundationTest.TestCertStatusAndReasonsMask;
var
  LStatus: ICertStatus;
  LMask, LOther: IReasonsMask;
begin
  LStatus := TCertStatus.Create();
  CheckEquals(TCertStatus.Unrevoked, LStatus.Status, 'a fresh status is unrevoked');
  CheckFalse(LStatus.RevocationDate.HasValue, 'a fresh status has no revocation date');

  LStatus.Status := TCertStatus.Undetermined;
  LStatus.RevocationDate := TNullable<TDateTime>.Some(FRootCert.NotBefore);
  CheckEquals(TCertStatus.Undetermined, LStatus.Status, 'the status round-trips');
  CheckTrue(LStatus.RevocationDate.HasValue, 'the revocation date round-trips');

  LMask := TReasonsMask.Create();
  CheckFalse(LMask.IsAllReasons, 'an empty mask does not cover every reason');

  LOther := TReasonsMask.Create(TReasonFlags.KeyCompromise);
  CheckTrue(LMask.HasNewReasons(LOther), 'key compromise is new to an empty mask');
  LMask.AddReasons(LOther);
  CheckFalse(LMask.HasNewReasons(LOther), 'the reason is no longer new once added');
  CheckFalse(LMask.IsAllReasons, 'one reason is not every reason');

  LMask.AddReasons(TReasonsMask.Create(TReasonsMask.AllReasons) as IReasonsMask);
  CheckTrue(LMask.IsAllReasons, 'the mask now covers every reason');
end;

procedure TPkixFoundationTest.TestPkixParametersCloneAndValidation;
var
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LParams, LClone: IPkixParameters;
  LSelector: IX509CertStoreSelector;
  LStore: IStore<IX509Certificate>;
  LRaised: Boolean;
begin
  LAnchors := TCryptoLibGenericArray<ITrustAnchor>.Create(NewTrustAnchor(FRootCert));

  LParams := TPkixParameters.Create(LAnchors);
  CheckEquals(1, System.Length(LParams.GetTrustAnchors()), 'the trust anchor round-trips');
  CheckTrue(LParams.IsRevocationEnabled, 'revocation checking is on by default');
  CheckTrue(LParams.IsPolicyQualifiersRejected, 'policy qualifiers are rejected by default');
  CheckEquals(TPkixParameters.PkixValidityModel, LParams.ValidityModel, 'the PKIX validity model is the default');

  LSelector := NewCertSelector();
  LSelector.Subject := FFinalCert.SubjectDN;
  LParams.SetTargetConstraintsCert(LSelector);
  LStore := TCollectionStore<IX509Certificate>.Create(AllCerts());
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;
  LParams.ValidityModel := TPkixParameters.ChainValidityModel;
  LParams.Date := TNullable<TDateTime>.Some(FFinalCert.NotBefore);
  LParams.SetInitialPolicies(TCryptoLibStringArray.Create('2.5.29.32.0', ''));

  CheckEquals(1, System.Length(LParams.GetInitialPolicies()), 'empty policy OIDs are dropped');

  LClone := LParams.Clone();
  CheckFalse(LClone.IsRevocationEnabled, 'the clone keeps the revocation flag');
  CheckEquals(TPkixParameters.ChainValidityModel, LClone.ValidityModel, 'the clone keeps the validity model');
  CheckTrue(LClone.Date.HasValue, 'the clone keeps the validity date');
  CheckEquals(1, System.Length(LClone.GetStoresCert()), 'the clone keeps the certificate stores');
  CheckNotNull(LClone.GetTargetConstraintsCert(), 'the clone keeps the target constraints');

  LClone.IsRevocationEnabled := True;
  CheckFalse(LParams.IsRevocationEnabled, 'mutating the clone must not touch the original');

  LRaised := False;
  try
    LParams := TPkixParameters.Create(nil);
  except
    on E: EArgumentNilCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'nil trust anchors are rejected');

  LRaised := False;
  try
    LParams := TPkixParameters.Create(TCryptoLibGenericArray<ITrustAnchor>.Create(nil));
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty trust anchor set is rejected');
end;

procedure TPkixFoundationTest.TestPkixBuilderParameters;
var
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LSelector: IX509CertStoreSelector;
  LParams: IPkixParameters;
  LBuilderParams, LFromParams, LClone: IPkixBuilderParameters;
  LRaised: Boolean;
begin
  LAnchors := TCryptoLibGenericArray<ITrustAnchor>.Create(NewTrustAnchor(FRootCert));
  LSelector := NewCertSelector();
  LSelector.Subject := FFinalCert.SubjectDN;

  LBuilderParams := TPkixBuilderParameters.Create(LAnchors, LSelector);
  CheckEquals(5, LBuilderParams.MaxPathLength, 'the default maximum path length is 5');
  CheckNotNull(LBuilderParams.GetTargetConstraintsCert(), 'the target constraints round-trip');

  LBuilderParams.MaxPathLength := -1;
  CheckEquals(-1, LBuilderParams.MaxPathLength, 'an unlimited path length is allowed');

  LRaised := False;
  try
    LBuilderParams.MaxPathLength := -2;
  except
    on E: EInvalidParameterCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a maximum path length below -1 is rejected');

  LBuilderParams.MaxPathLength := 3;
  LBuilderParams.SetExcludedCerts(TCryptoLibGenericArray<IX509Certificate>.Create(FInterCert));
  CheckEquals(1, System.Length(LBuilderParams.GetExcludedCerts()), 'the excluded certificates round-trip');

  CheckTrue(Supports(LBuilderParams.Clone(), IPkixBuilderParameters, LClone),
    'cloning builder parameters yields builder parameters');
  CheckEquals(3, LClone.MaxPathLength, 'the clone keeps the maximum path length');
  CheckEquals(1, System.Length(LClone.GetExcludedCerts()), 'the clone keeps the excluded certificates');

  LParams := TPkixParameters.Create(LAnchors);
  LParams.IsExplicitPolicyRequired := True;
  LFromParams := TPkixBuilderParameters.GetInstance(LParams);
  CheckTrue(LFromParams.IsExplicitPolicyRequired, 'validation parameters are carried over');
  CheckEquals(5, LFromParams.MaxPathLength, 'plain parameters leave the default maximum path length');
end;

procedure TPkixFoundationTest.TestPkixCertPathSortsAndEncodes;
var
  LPath, LDecoded: IPkixCertPath;
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LEncoded: TCryptoLibByteArray;
  LStream: TMemoryStream;
begin
  // deliberately out of order: the path must come back end-entity first
  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(FRootCert, FFinalCert, FInterCert));

  LCerts := LPath.Certificates;
  CheckEquals(3, System.Length(LCerts), 'every certificate is kept');
  CheckTrue(LCerts[0].Equals(FFinalCert), 'the end certificate comes first');
  CheckTrue(LCerts[1].Equals(FInterCert), 'the intermediate certificate comes second');
  CheckTrue(LCerts[2].Equals(FRootCert), 'the root certificate comes last');

  CheckEquals(3, System.Length(LPath.GetEncodings()), 'three encodings are supported');

  LEncoded := LPath.GetEncoded();
  CheckTrue(System.Length(LEncoded) > 0, 'the default encoding produces bytes');

  LStream := TMemoryStream.Create();
  try
    LStream.WriteBuffer(LEncoded[0], System.Length(LEncoded));
    LStream.Position := 0;
    LDecoded := TPkixCertPath.Create(LStream);
  finally
    LStream.Free;
  end;

  CheckTrue(LDecoded.Equals(LPath), 'a PkiPath encoding round-trips');
  CheckEquals(LPath.GetHashCode, LDecoded.GetHashCode, 'equal paths hash alike');

  CheckTrue(System.Length(LPath.GetEncoded('PKCS7')) > 0, 'the PKCS7 encoding produces bytes');
  CheckTrue(System.Length(LPath.GetEncoded('PEM')) > 0, 'the PEM encoding produces bytes');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TPkixFoundationTest);
{$ELSE}
  RegisterTest(TPkixFoundationTest.Suite);
{$ENDIF FPC}

end.
