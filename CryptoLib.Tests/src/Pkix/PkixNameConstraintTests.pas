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

unit PkixNameConstraintTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIPkixTypes,
  ClpPkixNameConstraintValidator,
  ClpNameConstraintIP,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpCryptoLibTypes,
  ClpCryptoLibConfig,
  CryptoLibTestBase;

type

  TPkixNameConstraintTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function NameOf(ATag: Int32; const AValue: String): IGeneralName;
    function IpName(const AOctets: TCryptoLibByteArray): IGeneralName;
    function DnName(const AValue: String): IGeneralName;
    function SubtreeOf(const AName: IGeneralName): IGeneralSubtree;

    /// <summary>True when ATested is caught by an excluded subtree built from AConstraint.</summary>
    function IsExcluded(const AConstraint, ATested: IGeneralName): Boolean;
    /// <summary>True when ATested is inside a permitted subtree built from AConstraint.</summary>
    function IsPermitted(const AConstraint, ATested: IGeneralName): Boolean;
    /// <summary>True when building the name or constraint is rejected outright.</summary>
    function ConstructionRejected(ATag: Int32; const AValue: String): Boolean;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestEmailConstraintForms;
    procedure TestDnsConstraintForms;
    procedure TestUriConstraintForms;
    procedure TestDirectoryNameIsPrefixMatched;
    procedure TestIPAddressRanges;
    procedure TestOtherNameExactMatch;
    procedure TestTrailingDotCannotBypassExclusion;
    procedure TestEmptyLabelRejected;
    procedure TestAmbiguousEmailRejected;
    procedure TestUriHostExtractionCannotBypassExclusion;
    procedure TestIPv4MappedAddressCannotBypassExclusion;
    procedure TestEmptyPermittedSubtreePermitsNothing;
    procedure TestIntersectionNarrowsPermittedSet;
    procedure TestUnionDropsCoveredConstraint;
    procedure TestNonContiguousMaskRejected;

  end;

implementation

{ TPkixNameConstraintTest }

procedure TPkixNameConstraintTest.SetUp;
begin
  inherited SetUp;
  // these settings are process-wide, so pin them to the strict defaults
  TCryptoLibConfig.X509.ResetToDefaults();
end;

procedure TPkixNameConstraintTest.TearDown;
begin
  // restore, or a setting changed here leaks into every later test in the run
  TCryptoLibConfig.X509.ResetToDefaults();
  inherited TearDown;
end;

function TPkixNameConstraintTest.NameOf(ATag: Int32; const AValue: String): IGeneralName;
begin
  Result := TGeneralName.Create(ATag, AValue);
end;

function TPkixNameConstraintTest.DnName(const AValue: String): IGeneralName;
begin
  Result := TGeneralName.Create(TX509Name.Create(True, AValue) as IX509Name);
end;

function TPkixNameConstraintTest.IpName(const AOctets: TCryptoLibByteArray): IGeneralName;
begin
  Result := TGeneralName.Create(TGeneralName.IPAddress,
    TDerOctetString.Create(AOctets) as IAsn1Encodable);
end;

function TPkixNameConstraintTest.SubtreeOf(const AName: IGeneralName): IGeneralSubtree;
begin
  Result := TGeneralSubtree.Create(AName);
end;

function TPkixNameConstraintTest.IsExcluded(const AConstraint, ATested: IGeneralName): Boolean;
var
  LValidator: IPkixNameConstraintValidator;
begin
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.AddExcludedSubtree(SubtreeOf(AConstraint));
  try
    LValidator.CheckExcludedName(ATested);
    Result := False;
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      Result := True;
  end;
end;

function TPkixNameConstraintTest.IsPermitted(const AConstraint, ATested: IGeneralName): Boolean;
var
  LValidator: IPkixNameConstraintValidator;
begin
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.IntersectPermittedSubtree(SubtreeOf(AConstraint));
  try
    LValidator.CheckPermittedName(ATested);
    Result := True;
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      Result := False;
  end;
end;

function TPkixNameConstraintTest.ConstructionRejected(ATag: Int32; const AValue: String): Boolean;
var
  LValidator: IPkixNameConstraintValidator;
begin
  LValidator := TPkixNameConstraintValidator.Create();
  try
    LValidator.AddExcludedSubtree(SubtreeOf(NameOf(ATag, AValue)));
    Result := False;
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      Result := True;
  end;
end;

procedure TPkixNameConstraintTest.TestEmailConstraintForms;
const
  Tested = 'test@abc.test.com';
begin
  // the three constraint forms of RFC 5280 4.2.1.10 that must catch this address
  CheckTrue(IsExcluded(NameOf(TGeneralName.Rfc822Name, 'test@abc.test.com'),
    NameOf(TGeneralName.Rfc822Name, Tested)), 'a particular mailbox matches itself');
  CheckTrue(IsExcluded(NameOf(TGeneralName.Rfc822Name, 'abc.test.com'),
    NameOf(TGeneralName.Rfc822Name, Tested)), 'a host constraint matches the mail host');
  CheckTrue(IsExcluded(NameOf(TGeneralName.Rfc822Name, '.test.com'),
    NameOf(TGeneralName.Rfc822Name, Tested)), 'a domain constraint matches a subdomain host');

  // and the forms that must not
  CheckFalse(IsExcluded(NameOf(TGeneralName.Rfc822Name, '.abc.test.com'),
    NameOf(TGeneralName.Rfc822Name, Tested)), 'a domain constraint excludes its own apex');
  CheckFalse(IsExcluded(NameOf(TGeneralName.Rfc822Name, 'www.test.com'),
    NameOf(TGeneralName.Rfc822Name, Tested)), 'an unrelated host does not match');
  CheckFalse(IsExcluded(NameOf(TGeneralName.Rfc822Name, 'test1@abc.test.com'),
    NameOf(TGeneralName.Rfc822Name, Tested)), 'a different mailbox does not match');
  CheckFalse(IsExcluded(NameOf(TGeneralName.Rfc822Name, 'bc.test.com'),
    NameOf(TGeneralName.Rfc822Name, Tested)), 'a suffix that is not a label boundary does not match');
end;

procedure TPkixNameConstraintTest.TestDnsConstraintForms;
begin
  CheckTrue(IsExcluded(NameOf(TGeneralName.DnsName, 'test.com'),
    NameOf(TGeneralName.DnsName, 'abc.test.com')), 'a dNSName constraint covers its subdomains');
  CheckTrue(IsExcluded(NameOf(TGeneralName.DnsName, 'test.com'),
    NameOf(TGeneralName.DnsName, 'test.com')), 'an undotted dNSName constraint covers its own apex');
  CheckFalse(IsExcluded(NameOf(TGeneralName.DnsName, '.test.com'),
    NameOf(TGeneralName.DnsName, 'test.com')), 'a dot-prefixed constraint excludes the apex');
  CheckTrue(IsExcluded(NameOf(TGeneralName.DnsName, '.test.com'),
    NameOf(TGeneralName.DnsName, 'abc.test.com')), 'a dot-prefixed constraint still covers subdomains');
  CheckFalse(IsExcluded(NameOf(TGeneralName.DnsName, 'test.com'),
    NameOf(TGeneralName.DnsName, 'nottest.com')), 'a sibling domain is not covered');
end;

procedure TPkixNameConstraintTest.TestUriConstraintForms;
begin
  CheckTrue(IsExcluded(NameOf(TGeneralName.UniformResourceIdentifier, 'test.com'),
    NameOf(TGeneralName.UniformResourceIdentifier, 'http://test.com/path')),
    'a URI host constraint matches the authority host');
  CheckTrue(IsExcluded(NameOf(TGeneralName.UniformResourceIdentifier, '.test.com'),
    NameOf(TGeneralName.UniformResourceIdentifier, 'http://abc.test.com')),
    'a URI domain constraint matches a subdomain');
  CheckFalse(IsExcluded(NameOf(TGeneralName.UniformResourceIdentifier, '.test.com'),
    NameOf(TGeneralName.UniformResourceIdentifier, 'http://test.com')),
    'a dot-prefixed URI constraint excludes the apex');
end;

procedure TPkixNameConstraintTest.TestDirectoryNameIsPrefixMatched;
begin
  CheckTrue(IsPermitted(DnName('o=Test Certificates, c=US'),
    DnName('cn=Valid EE, ou=permittedSubtree1, o=Test Certificates, c=US')),
    'a constraint that is an initial prefix of the subject matches');

  // RFC 5280 7.1 is an initial-prefix match; matching at an arbitrary offset would let an
  // attacker prepend RDNs ahead of the permitted sequence
  CheckFalse(IsPermitted(DnName('o=Trusted Org, c=US'),
    DnName('cn=Leaf, o=Trusted Org, c=US, o=Attacker, c=FR')),
    'a constraint appearing at a non-initial position must not match');
end;

procedure TPkixNameConstraintTest.TestIPAddressRanges;
var
  LConstraint: IGeneralName;
begin
  // 10.0.0.0/8
  LConstraint := IpName(TCryptoLibByteArray.Create(10, 0, 0, 0, $FF, $00, $00, $00));

  CheckTrue(IsExcluded(LConstraint, IpName(TCryptoLibByteArray.Create(10, 9, 8, 7))),
    'an address inside the range is caught');
  CheckFalse(IsExcluded(LConstraint, IpName(TCryptoLibByteArray.Create(11, 0, 0, 1))),
    'an address outside the range is not caught');
end;

procedure TPkixNameConstraintTest.TestOtherNameExactMatch;
var
  LName, LOther: IGeneralName;
begin
  LName := TGeneralName.Create(TGeneralName.OtherName,
    TOtherName.Create(TDerObjectIdentifier.Create('1.1') as IDerObjectIdentifier,
      TDerNull.Instance as IAsn1Encodable)
    as IAsn1Encodable);
  LOther := TGeneralName.Create(TGeneralName.OtherName,
    TOtherName.Create(TDerObjectIdentifier.Create('1.2') as IDerObjectIdentifier,
      TDerNull.Instance as IAsn1Encodable)
    as IAsn1Encodable);

  CheckTrue(IsExcluded(LName, LName), 'an otherName matches an equal otherName');
  CheckFalse(IsExcluded(LName, LOther), 'an otherName does not match a different type id');
end;

procedure TPkixNameConstraintTest.TestTrailingDotCannotBypassExclusion;
begin
  // the RFC 1034 root-label dot must be canonicalized away on every string-host family, or a name
  // slips past an excluded subtree
  CheckTrue(IsExcluded(NameOf(TGeneralName.Rfc822Name, 'bank.com'),
    NameOf(TGeneralName.Rfc822Name, 'ceo@bank.com.')), 'trailing-dot email is still caught');
  CheckTrue(IsExcluded(NameOf(TGeneralName.DnsName, 'example.com'),
    NameOf(TGeneralName.DnsName, 'example.com.')), 'trailing-dot exact host is still caught');
  CheckTrue(IsExcluded(NameOf(TGeneralName.DnsName, 'example.com'),
    NameOf(TGeneralName.DnsName, 'foo.example.com.')), 'trailing-dot subdomain is still caught');
  CheckTrue(IsExcluded(NameOf(TGeneralName.DnsName, '.example.com'),
    NameOf(TGeneralName.DnsName, 'foo.example.com.')),
    'trailing-dot subdomain is caught by a dot-prefixed constraint');
  CheckFalse(IsExcluded(NameOf(TGeneralName.DnsName, 'example.com'),
    NameOf(TGeneralName.DnsName, 'notexample.com.')), 'a sibling domain is still not caught');
  CheckTrue(IsExcluded(NameOf(TGeneralName.UniformResourceIdentifier, 'competitor.example'),
    NameOf(TGeneralName.UniformResourceIdentifier, 'https://competitor.example./')),
    'trailing-dot URI host is still caught');
end;

procedure TPkixNameConstraintTest.TestEmptyLabelRejected;
begin
  // an empty label misaligns the per-label compare, so it fails closed at construction
  CheckTrue(ConstructionRejected(TGeneralName.DnsName, 'a..example.com'), 'a doubled dot is rejected');
  CheckTrue(ConstructionRejected(TGeneralName.DnsName, 'a.example.com..'),
    'a repeated trailing dot is rejected');
  CheckTrue(ConstructionRejected(TGeneralName.DnsName, '..example.com'),
    'a dot after the constraint-form leading dot is rejected');
  CheckTrue(ConstructionRejected(TGeneralName.Rfc822Name, 'user@a..example.com'),
    'an empty label in a mail host is rejected');
  CheckTrue(ConstructionRejected(TGeneralName.UniformResourceIdentifier, 'a..example.com'),
    'an empty label in a URI constraint is rejected');
end;

procedure TPkixNameConstraintTest.TestAmbiguousEmailRejected;
var
  LValidator: IPkixNameConstraintValidator;
  LRaised: Boolean;
begin
  // a quoted local part may legally contain '@' (RFC 5321 4.1.2), so the host split is ambiguous
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.AddExcludedSubtree(SubtreeOf(NameOf(TGeneralName.Rfc822Name, 'bank.com')));

  LRaised := False;
  try
    LValidator.CheckExcludedName(NameOf(TGeneralName.Rfc822Name, '"a@b"@bank.com'));
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an address with more than one @ is rejected by default');

  // the opt-in restores the legacy first-@ split
  TCryptoLibConfig.X509.AllowLenientRfc822Name := True;
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.AddExcludedSubtree(SubtreeOf(NameOf(TGeneralName.Rfc822Name, 'nomatch.example')));
  LValidator.CheckExcludedName(NameOf(TGeneralName.Rfc822Name, '"a@b"@bank.com'));
end;

procedure TPkixNameConstraintTest.TestUriHostExtractionCannotBypassExclusion;
begin
  // userinfo, port and path must not shift which host is compared
  CheckTrue(IsExcluded(NameOf(TGeneralName.UniformResourceIdentifier, 'bank.com'),
    NameOf(TGeneralName.UniformResourceIdentifier, 'http://user@bank.com/path')),
    'userinfo does not hide the authority host');
  CheckTrue(IsExcluded(NameOf(TGeneralName.UniformResourceIdentifier, 'bank.com'),
    NameOf(TGeneralName.UniformResourceIdentifier, 'http://bank.com:8080/')),
    'a port does not hide the authority host');
  CheckFalse(IsExcluded(NameOf(TGeneralName.UniformResourceIdentifier, 'bank.com'),
    NameOf(TGeneralName.UniformResourceIdentifier, 'http://evil.example/?x=bank.com')),
    'the host is taken from the authority, not the query');
end;

procedure TPkixNameConstraintTest.TestIPv4MappedAddressCannotBypassExclusion;
var
  LConstraint, LMapped: IGeneralName;
begin
  // 10.0.0.0/8, tested with ::ffff:10.9.8.7 (RFC 4291 2.5.5.2)
  LConstraint := IpName(TCryptoLibByteArray.Create(10, 0, 0, 0, $FF, $00, $00, $00));
  LMapped := IpName(TCryptoLibByteArray.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, $FF, $FF, 10, 9, 8, 7));

  CheckTrue(IsExcluded(LConstraint, LMapped),
    'an IPv4-mapped IPv6 address is canonicalized and still caught');
end;

procedure TPkixNameConstraintTest.TestEmptyPermittedSubtreePermitsNothing;
var
  LValidator: IPkixNameConstraintValidator;
  LRaised: Boolean;
begin
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.IntersectEmptyPermittedSubtree(TGeneralName.DnsName);

  LRaised := False;
  try
    LValidator.CheckPermittedName(NameOf(TGeneralName.DnsName, 'anything.example'));
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'an empty permitted set permits nothing of that family');

  // a different family stays unconstrained
  LValidator.CheckPermittedName(NameOf(TGeneralName.Rfc822Name, 'user@anything.example'));
end;

procedure TPkixNameConstraintTest.TestIntersectionNarrowsPermittedSet;
var
  LValidator: IPkixNameConstraintValidator;
  LRaised: Boolean;
begin
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.IntersectPermittedSubtree(SubtreeOf(NameOf(TGeneralName.DnsName, 'test.com')));
  LValidator.IntersectPermittedSubtree(SubtreeOf(NameOf(TGeneralName.DnsName, 'abc.test.com')));

  // the intersection of the two subtrees is the narrower one
  LValidator.CheckPermittedName(NameOf(TGeneralName.DnsName, 'x.abc.test.com'));

  LRaised := False;
  try
    LValidator.CheckPermittedName(NameOf(TGeneralName.DnsName, 'other.test.com'));
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a name only in the broader subtree is no longer permitted');
end;

procedure TPkixNameConstraintTest.TestUnionDropsCoveredConstraint;
var
  LValidator: IPkixNameConstraintValidator;
begin
  // adding the broader subtree second must absorb the narrower one, leaving the set non-nested
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.AddExcludedSubtree(SubtreeOf(NameOf(TGeneralName.DnsName, 'abc.test.com')));
  LValidator.AddExcludedSubtree(SubtreeOf(NameOf(TGeneralName.DnsName, 'test.com')));

  CheckTrue(IsExcluded(NameOf(TGeneralName.DnsName, 'test.com'),
    NameOf(TGeneralName.DnsName, 'abc.test.com')), 'the broader subtree still covers the narrower');

  // both the absorbed name and an unrelated subdomain remain excluded
  try
    LValidator.CheckExcludedName(NameOf(TGeneralName.DnsName, 'x.abc.test.com'));
    Fail('the absorbed subtree must still be excluded');
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      ; // expected
  end;

  try
    LValidator.CheckExcludedName(NameOf(TGeneralName.DnsName, 'other.test.com'));
    Fail('the broader subtree must be excluded');
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      ; // expected
  end;
end;

procedure TPkixNameConstraintTest.TestNonContiguousMaskRejected;
var
  LValidator: IPkixNameConstraintValidator;
  LNonContiguous: IGeneralName;
  LRaised: Boolean;
begin
  // 255.0.255.0 is not valid CIDR and cannot be represented as a range
  LNonContiguous := IpName(TCryptoLibByteArray.Create(10, 0, 0, 0, $FF, $00, $FF, $00));

  LValidator := TPkixNameConstraintValidator.Create();
  LRaised := False;
  try
    LValidator.AddExcludedSubtree(SubtreeOf(LNonContiguous));
  except
    on E: EPkixNameConstraintValidatorCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a non-contiguous subnet mask is rejected by default');

  // the opt-in rounds it to a contiguous mask instead of failing
  TCryptoLibConfig.X509.AllowLenientIPAddressMask := True;
  LValidator := TPkixNameConstraintValidator.Create();
  LValidator.AddExcludedSubtree(SubtreeOf(LNonContiguous));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TPkixNameConstraintTest);
{$ELSE}
  RegisterTest(TPkixNameConstraintTest.Suite);
{$ENDIF FPC}

end.
