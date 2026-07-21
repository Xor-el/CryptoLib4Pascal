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

unit PkixComparerTests;

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
  ClpCryptoLibHashSet,
  ClpIPkixTypes,
  ClpPkixComparers,
  ClpX509Comparers,
  ClpNameConstraintTypes,
  ClpNameConstraintIP,
  ClpNameConstraintDN,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Certificate,
  ClpIX509CertificateParser,
  ClpX509CertificateParser,
  ClpCryptoLibTypes,
  CertVectors,
  CryptoLibTestBase;

type
  /// <summary>
  /// The equality comparers handed to <see cref="TCryptoLibHashSet&lt;T&gt;" /> must agree with the
  /// value equality of the type they compare.
  /// </summary>
  /// <remarks>
  /// Each test adds two equal but distinct instances and asserts the set holds one, then adds a
  /// genuinely different instance and asserts it holds two. The first half fails when GetHashCode
  /// disagrees with Equals (equal items land in different buckets and both survive); the second half
  /// fails when the comparer is degenerate and reports everything equal. Neither shows up in any
  /// other operation, so nothing else would catch it.
  /// </remarks>
  TPkixComparerTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    function DnOf(const AValue: String): INameConstraintDN;
    function OtherNameOf(const AOid: String): IOtherName;
    function SubtreeOf(const AHost: String): IGeneralSubtree;
    function CertOf(const ACertId: String): IX509Certificate;

  published
    procedure TestHostNameComparerMatchesRecordEquality;
    procedure TestIPRangeComparerMatchesRecordEquality;
    procedure TestNameConstraintDNComparerMatchesValueEquality;
    procedure TestOtherNameComparerMatchesValueEquality;
    procedure TestGeneralSubtreeComparerMatchesValueEquality;
    procedure TestCertificateComparerMatchesEncodedEquality;
  end;

implementation

{ TPkixComparerTest }

function TPkixComparerTest.DnOf(const AValue: String): INameConstraintDN;
var
  LName: IX509Name;
begin
  LName := TX509Name.Create(True, AValue) as IX509Name;
  Result := TNameConstraintDN.Create(TAsn1Sequence.GetInstance(LName.ToAsn1Object()))
    as INameConstraintDN;
end;

function TPkixComparerTest.OtherNameOf(const AOid: String): IOtherName;
begin
  Result := TOtherName.Create(TDerObjectIdentifier.Create(AOid) as IDerObjectIdentifier,
    TDerNull.Instance as IAsn1Encodable) as IOtherName;
end;

function TPkixComparerTest.SubtreeOf(const AHost: String): IGeneralSubtree;
begin
  Result := TGeneralSubtree.Create(TGeneralName.Create(TGeneralName.DnsName, AHost)
    as IGeneralName) as IGeneralSubtree;
end;

// parsed fresh each call so two equal certificates are never the same instance
function TPkixComparerTest.CertOf(const ACertId: String): IX509Certificate;
var
  LParser: IX509CertificateParser;
begin
  LParser := TX509CertificateParser.Create() as IX509CertificateParser;
  Result := LParser.ReadCertificate(TCertVectors.LoadDer(ACertId));
end;

procedure TPkixComparerTest.TestHostNameComparerMatchesRecordEquality;
var
  LSet: TCryptoLibHashSet<TNameConstraintHostName>;
begin
  LSet := TCryptoLibHashSet<TNameConstraintHostName>.Create
    (TPkixComparers.NameConstraintHostNameEqualityComparer);
  try
    // equality is case-insensitive, so the hash has to fold case as well
    LSet.Add(TNameConstraintHostName.Create(TNameConstraintHostNameKind.Domain,
      '.Example.COM', '.Example.COM'));
    LSet.Add(TNameConstraintHostName.Create(TNameConstraintHostNameKind.Domain,
      '.example.com', '.example.com'));
    CheckEquals(1, LSet.Count, 'host names differing only in case are one entry');

    LSet.Add(TNameConstraintHostName.Create(TNameConstraintHostNameKind.Domain,
      '.other.com', '.other.com'));
    CheckEquals(2, LSet.Count, 'a different host name is a separate entry');
  finally
    LSet.Free;
  end;
end;

procedure TPkixComparerTest.TestIPRangeComparerMatchesRecordEquality;
var
  LSet: TCryptoLibHashSet<TNameConstraintIPRange>;
begin
  LSet := TCryptoLibHashSet<TNameConstraintIPRange>.Create
    (TPkixComparers.NameConstraintIPRangeEqualityComparer);
  try
    // 10.0.0.0/8 built twice, from two separate byte arrays
    LSet.Add(TNameConstraintIPRange.CreatePermitted(TCryptoLibByteArray.Create(10, 0, 0, 0,
      $FF, $00, $00, $00)));
    LSet.Add(TNameConstraintIPRange.CreatePermitted(TCryptoLibByteArray.Create(10, 0, 0, 0,
      $FF, $00, $00, $00)));
    CheckEquals(1, LSet.Count, 'equal ranges from distinct arrays are one entry');

    LSet.Add(TNameConstraintIPRange.CreatePermitted(TCryptoLibByteArray.Create(192, 168, 0, 0,
      $FF, $FF, $00, $00)));
    CheckEquals(2, LSet.Count, 'a different range is a separate entry');
  finally
    LSet.Free;
  end;
end;

procedure TPkixComparerTest.TestNameConstraintDNComparerMatchesValueEquality;
var
  LSet: TCryptoLibHashSet<INameConstraintDN>;
begin
  LSet := TCryptoLibHashSet<INameConstraintDN>.Create
    (TPkixComparers.NameConstraintDNEqualityComparer);
  try
    LSet.Add(DnOf('CN=Test, O=Example'));
    LSet.Add(DnOf('CN=Test, O=Example'));
    CheckEquals(1, LSet.Count, 'equal directory names are one entry');

    LSet.Add(DnOf('CN=Other, O=Example'));
    CheckEquals(2, LSet.Count, 'a different directory name is a separate entry');
  finally
    LSet.Free;
  end;
end;

procedure TPkixComparerTest.TestOtherNameComparerMatchesValueEquality;
var
  LSet: TCryptoLibHashSet<IOtherName>;
begin
  LSet := TCryptoLibHashSet<IOtherName>.Create(TPkixComparers.OtherNameEqualityComparer);
  try
    LSet.Add(OtherNameOf('1.1'));
    LSet.Add(OtherNameOf('1.1'));
    CheckEquals(1, LSet.Count, 'equal otherNames are one entry');

    LSet.Add(OtherNameOf('1.2'));
    CheckEquals(2, LSet.Count, 'a different type id is a separate entry');
  finally
    LSet.Free;
  end;
end;

procedure TPkixComparerTest.TestGeneralSubtreeComparerMatchesValueEquality;
var
  LSet: TCryptoLibHashSet<IGeneralSubtree>;
begin
  LSet := TCryptoLibHashSet<IGeneralSubtree>.Create(TPkixComparers.GeneralSubtreeEqualityComparer);
  try
    LSet.Add(SubtreeOf('example.com'));
    LSet.Add(SubtreeOf('example.com'));
    CheckEquals(1, LSet.Count, 'equal subtrees are one entry');

    LSet.Add(SubtreeOf('other.com'));
    CheckEquals(2, LSet.Count, 'a different subtree is a separate entry');
  finally
    LSet.Free;
  end;
end;

procedure TPkixComparerTest.TestCertificateComparerMatchesEncodedEquality;
var
  LSet: TCryptoLibHashSet<IX509Certificate>;
  LFirst, LSecond: IX509Certificate;
begin
  LFirst := CertOf('PkixTestRootCa');
  LSecond := CertOf('PkixTestRootCa');
  CheckFalse(LFirst = LSecond, 'the two certificates must be distinct instances');

  LSet := TCryptoLibHashSet<IX509Certificate>.Create(TX509Comparers.CertificateEqualityComparer);
  try
    LSet.Add(LFirst);
    LSet.Add(LSecond);
    // the same certificate reaching the set from two stores must not be counted twice
    CheckEquals(1, LSet.Count, 'the same certificate parsed twice is one entry');

    LSet.Add(CertOf('PkixTestIntermediateCa'));
    CheckEquals(2, LSet.Count, 'a different certificate is a separate entry');
  finally
    LSet.Free;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TPkixComparerTest);
{$ELSE}
  RegisterTest(TPkixComparerTest.Suite);
{$ENDIF FPC}

end.
