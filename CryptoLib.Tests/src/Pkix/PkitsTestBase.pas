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

unit PkitsTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIStore,
  ClpCollectionStore,
  ClpIPkixTypes,
  ClpPkixCertPath,
  ClpPkixParameters,
  ClpPkixCertPathValidator,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpNullable,
  ClpCryptoLibTypes,
  PkitsVectors,
  CryptoLibTestBase;

resourcestring
  SUnknownPolicyName = 'unknown PKITS policy name "%s"';

type
  /// <summary>
  /// One NIST PKITS path validation case, assembled fluently and then run through the certification
  /// path validator.
  /// </summary>
  /// <remarks>
  /// The trust anchor and its CRL are always present; a case adds the intermediate certificates and
  /// CRLs it needs, names the end entity, and optionally sets the policy inputs of RFC 5280 6.1.1.
  /// Validation runs at a fixed date so the corpus does not expire.
  ///
  /// Reference counted, so a case abandoned part way through its fluent chain - a bad vector name
  /// raising inside WithCerts, say - is still released. The arguments of a Check call are evaluated
  /// before the call that would otherwise take ownership.
  /// </remarks>
  IPkitsTest = interface(IInterface)
    ['{6B2F1A74-9C3D-4E85-A1F6-2D7B84C05E39}']

    function WithCerts(const ANames: array of String): IPkitsTest;

    /// <summary>
    /// Adds certificates to the certificate store only, so a CRL signer can be found without
    /// becoming a member of the certification path.
    /// </summary>
    /// <remarks>
    /// RFC 5280 6.1.4 (k) has no self-issued exemption - only (l) does - so a CRL signing
    /// certificate carrying no basicConstraints cA is correctly rejected as an intermediate.
    /// Exempting such certificates from (k) would be the wrong fix: they are not path members.
    /// </remarks>
    function WithCrlSignerCerts(const ANames: array of String): IPkitsTest;
    function WithCrls(const ANames: array of String): IPkitsTest;
    function WithEndEntity(const AName: String): IPkitsTest;
    function WithPoliciesByName(const ANames: array of String): IPkitsTest;
    function WithExplicitPolicyRequired(AValue: Boolean): IPkitsTest;
    function WithInhibitAnyPolicy(AValue: Boolean): IPkitsTest;
    function WithPolicyMappingInhibited(AValue: Boolean): IPkitsTest;
    function EnableDeltaCrls(AValue: Boolean): IPkitsTest;

    /// <summary>Runs the case, raising when the path is rejected.</summary>
    function Run(): IPkixCertPathValidatorResult;
  end;

  TPkitsTest = class(TInterfacedObject, IPkitsTest)

  strict private
  const
    /// <summary>The corpus is validated at a fixed date, well inside its certificates' lifetimes.</summary>
    ValidationYear = 2010;
    ValidationMonth = 1;
    ValidationDay = 1;

    /// <summary>The arc the NIST test policies hang off.</summary>
    NistTestPolicyArc = '2.16.840.1.101.3.2.1.48.';
    AnyPolicyOid = '2.5.29.32.0';

  var
    FCerts: TCryptoLibGenericArray<IX509Certificate>;
    // store only: CRL signers that must be findable without joining the path
    FStoreOnlyCerts: TCryptoLibGenericArray<IX509Certificate>;
    FCrls: TCryptoLibGenericArray<IX509Crl>;
    FPolicies: TCryptoLibStringArray;
    FEndCert: IX509Certificate;
    // unset means "leave the validator's default alone"
    FExplicitPolicyRequired: TNullable<Boolean>;
    FInhibitAnyPolicy: TNullable<Boolean>;
    FPolicyMappingInhibited: TNullable<Boolean>;
    FDeltaCrlsEnabled: Boolean;

    /// <summary>PKITS names carry spaces and hyphens that the file names drop.</summary>
    class function FixName(const AName: String): String; static;
    class function PolicyOid(const AName: String): String; static;

  public
    constructor Create();

    function WithCerts(const ANames: array of String): IPkitsTest;
    function WithCrlSignerCerts(const ANames: array of String): IPkitsTest;
    function WithCrls(const ANames: array of String): IPkitsTest;
    function WithEndEntity(const AName: String): IPkitsTest;
    function WithPoliciesByName(const ANames: array of String): IPkitsTest;
    function WithExplicitPolicyRequired(AValue: Boolean): IPkitsTest;
    function WithInhibitAnyPolicy(AValue: Boolean): IPkitsTest;
    function WithPolicyMappingInhibited(AValue: Boolean): IPkitsTest;
    function EnableDeltaCrls(AValue: Boolean): IPkitsTest;

    /// <summary>Runs the case, raising when the path is rejected.</summary>
    function Run(): IPkixCertPathValidatorResult;
  end;

  /// <summary>
  /// Base for the PKITS suites: builds a case and asserts the accept or reject outcome.
  /// </summary>
  TPkitsTestCase = class abstract(TCryptoLibAlgorithmTestCase)
  strict protected
    /// <summary>A case seeded with the trust anchor and its CRL.</summary>
    function NewTest(): IPkitsTest;

    /// <summary>Asserts the path validates.</summary>
    procedure CheckAccepted(const ATest: IPkitsTest);

    /// <summary>
    /// Asserts the path is rejected. AExpectedIndex is the position in the path the reference
    /// blames, counted from the end entity, or -1 when it blames no particular certificate.
    /// </summary>
    /// <remarks>
    /// The index is recorded but not yet asserted: our validator exception does not carry one, so
    /// only the accept or reject outcome is checked. Once the exception grows an index this method
    /// is the single place that has to start enforcing it.
    /// </remarks>
    procedure CheckRejected(const ATest: IPkitsTest; AExpectedIndex: Int32);
  end;

implementation

{ TPkitsTest }

constructor TPkitsTest.Create();
begin
  inherited Create();
  FCerts := nil;
  FStoreOnlyCerts := nil;
  FCrls := nil;
  FPolicies := nil;
  FDeltaCrlsEnabled := False;
  // every PKITS path chains to the one trust anchor, whose CRL is always in scope
  WithCrls(['TrustAnchorRootCRL']);
end;

class function TPkitsTest.FixName(const AName: String): String;
begin
  Result := StringReplace(AName, ' ', '', [rfReplaceAll]);
  Result := StringReplace(Result, '-', '', [rfReplaceAll]);
end;

class function TPkitsTest.PolicyOid(const AName: String): String;
const
  NistPrefix = 'NIST-test-policy-';
begin
  if AName = 'anyPolicy' then
  begin
    Result := AnyPolicyOid;
    Exit;
  end;

  if System.Pos(NistPrefix, AName) = 1 then
  begin
    Result := NistTestPolicyArc + System.Copy(AName, System.Length(NistPrefix) + 1,
      System.Length(AName));
    Exit;
  end;

  // anything else is expected to already be an OID
  if (AName <> '') and (System.Pos('.', AName) > 0) then
  begin
    Result := AName;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SUnknownPolicyName, [AName]);
end;

function TPkitsTest.WithCerts(const ANames: array of String): IPkitsTest;
var
  LIdx, LBase: Int32;
begin
  LBase := System.Length(FCerts);
  System.SetLength(FCerts, LBase + System.Length(ANames));
  for LIdx := 0 to System.High(ANames) do
  begin
    FCerts[LBase + LIdx] := TPkitsVectors.GetCertificate(FixName(ANames[LIdx]));
  end;
  Result := Self;
end;

function TPkitsTest.WithCrlSignerCerts(const ANames: array of String): IPkitsTest;
var
  LIdx, LBase: Int32;
begin
  LBase := System.Length(FStoreOnlyCerts);
  System.SetLength(FStoreOnlyCerts, LBase + System.Length(ANames));
  for LIdx := 0 to System.High(ANames) do
  begin
    FStoreOnlyCerts[LBase + LIdx] := TPkitsVectors.GetCertificate(FixName(ANames[LIdx]));
  end;
  Result := Self;
end;

function TPkitsTest.WithCrls(const ANames: array of String): IPkitsTest;
var
  LIdx, LBase: Int32;
begin
  LBase := System.Length(FCrls);
  System.SetLength(FCrls, LBase + System.Length(ANames));
  for LIdx := 0 to System.High(ANames) do
  begin
    FCrls[LBase + LIdx] := TPkitsVectors.GetCrl(FixName(ANames[LIdx]));
  end;
  Result := Self;
end;

function TPkitsTest.WithEndEntity(const AName: String): IPkitsTest;
begin
  FEndCert := TPkitsVectors.GetCertificate(FixName(AName));
  Result := Self;
end;

function TPkitsTest.WithPoliciesByName(const ANames: array of String): IPkitsTest;
var
  LIdx, LBase: Int32;
begin
  LBase := System.Length(FPolicies);
  System.SetLength(FPolicies, LBase + System.Length(ANames));
  for LIdx := 0 to System.High(ANames) do
  begin
    FPolicies[LBase + LIdx] := PolicyOid(ANames[LIdx]);
  end;
  Result := Self;
end;

function TPkitsTest.WithExplicitPolicyRequired(AValue: Boolean): IPkitsTest;
begin
  FExplicitPolicyRequired := AValue;
  Result := Self;
end;

function TPkitsTest.WithInhibitAnyPolicy(AValue: Boolean): IPkitsTest;
begin
  FInhibitAnyPolicy := AValue;
  Result := Self;
end;

function TPkitsTest.WithPolicyMappingInhibited(AValue: Boolean): IPkitsTest;
begin
  FPolicyMappingInhibited := AValue;
  Result := Self;
end;

function TPkitsTest.EnableDeltaCrls(AValue: Boolean): IPkitsTest;
begin
  FDeltaCrlsEnabled := AValue;
  Result := Self;
end;

function TPkitsTest.Run(): IPkixCertPathValidatorResult;
var
  LPathCerts, LStoreCerts: TCryptoLibGenericArray<IX509Certificate>;
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LCertPath: IPkixCertPath;
  LParams: IPkixParameters;
  LValidator: IPkixCertPathValidator;
  LCertStore: IStore<IX509Certificate>;
  LCrlStore: IStore<IX509Crl>;
  LIdx: Int32;
begin
  // the path runs end entity first, towards the trust anchor
  System.SetLength(LPathCerts, System.Length(FCerts) + 1);
  LPathCerts[0] := FEndCert;
  for LIdx := 0 to System.High(FCerts) do
  begin
    LPathCerts[LIdx + 1] := FCerts[LIdx];
  end;

  // the store also holds CRL signers, which are findable but never path members
  System.SetLength(LStoreCerts, System.Length(LPathCerts) + System.Length(FStoreOnlyCerts));
  for LIdx := 0 to System.High(LPathCerts) do
  begin
    LStoreCerts[LIdx] := LPathCerts[LIdx];
  end;
  for LIdx := 0 to System.High(FStoreOnlyCerts) do
  begin
    LStoreCerts[System.Length(LPathCerts) + LIdx] := FStoreOnlyCerts[LIdx];
  end;

  LAnchors := TCryptoLibGenericArray<ITrustAnchor>.Create
    (TPkitsVectors.GetTrustAnchor('TrustAnchorRootCertificate'));

  LCertPath := TPkixCertPath.Create(LPathCerts) as IPkixCertPath;
  LParams := TPkixParameters.Create(LAnchors) as IPkixParameters;

  // a generic interface carries no GUID, so these upcast through a typed local instead of "as"
  LCertStore := TCollectionStore<IX509Certificate>.Create(LStoreCerts);
  LCrlStore := TCollectionStore<IX509Crl>.Create(FCrls);
  LParams.AddStoreCert(LCertStore);
  LParams.AddStoreCrl(LCrlStore);
  LParams.IsRevocationEnabled := True;
  LParams.Date := TNullable<TDateTime>.Some(EncodeDate(ValidationYear, ValidationMonth,
    ValidationDay));

  if FExplicitPolicyRequired.HasValue then
    LParams.IsExplicitPolicyRequired := FExplicitPolicyRequired.Value;

  if FInhibitAnyPolicy.HasValue then
    LParams.IsAnyPolicyInhibited := FInhibitAnyPolicy.Value;

  if FPolicyMappingInhibited.HasValue then
    LParams.IsPolicyMappingInhibited := FPolicyMappingInhibited.Value;

  // naming initial policies is only meaningful when the policy set must be non-empty
  if System.Length(FPolicies) > 0 then
  begin
    LParams.IsExplicitPolicyRequired := True;
    LParams.SetInitialPolicies(FPolicies);
  end;

  LParams.IsUseDeltasEnabled := FDeltaCrlsEnabled;

  LValidator := TPkixCertPathValidator.Create() as IPkixCertPathValidator;
  Result := LValidator.Validate(LCertPath, LParams);
end;

{ TPkitsTestCase }

function TPkitsTestCase.NewTest(): IPkitsTest;
begin
  Result := TPkitsTest.Create() as IPkitsTest;
end;

procedure TPkitsTestCase.CheckAccepted(const ATest: IPkitsTest);
var
  LResult: IPkixCertPathValidatorResult;
begin
  try
    LResult := ATest.Run();
  except
    on E: Exception do
      Fail(Format('path rejected when it should validate: %s: %s', [E.ClassName, E.Message]));
  end;
  CheckNotNull(LResult, 'a validated path must produce a result');
end;

procedure TPkitsTestCase.CheckRejected(const ATest: IPkitsTest; AExpectedIndex: Int32);
var
  LRejected: Boolean;
  LActualIndex: Int32;
  LMessage: String;
begin
  LRejected := False;
  LActualIndex := -1;
  LMessage := '';
  try
    ATest.Run();
  except
    on E: EPkixCertPathValidatorCryptoLibException do
    begin
      LRejected := True;
      LActualIndex := E.Index;
      LMessage := E.Message;
    end;
  end;
  CheckTrue(LRejected, 'path accepted when it should be rejected');

  // a raise site that does not know its position reports -1; only enforce where one was recorded
  if LActualIndex >= 0 then
  begin
    CheckEquals(AExpectedIndex, LActualIndex,
      Format('rejected at the wrong certificate (%s)', [LMessage]));
  end;
end;

end.
