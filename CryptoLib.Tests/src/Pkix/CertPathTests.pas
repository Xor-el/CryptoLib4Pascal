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

unit CertPathTests;

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
  ClpPkixCertPath,
  ClpPkixBuilderParameters,
  ClpPkixCertPathBuilder,
  ClpIX509Certificate,
  ClpIX509CertificateParser,
  ClpX509CertificateParser,
  ClpCryptoLibTypes,
  CertVectors,
  CryptoLibTestBase;

type

  /// <summary>
  /// Certification path assembly, encoding and decoding (RFC 5280 6.1), plus the path builder's
  /// refusal to loop through a set of mutually issuing certificates.
  /// </summary>
  TCertPathTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRootCert: IX509Certificate;
    FInterCert: IX509Certificate;
    FFinalCert: IX509Certificate;

    function ReadCert(const ACertId: String): IX509Certificate;
    /// <summary>The four certificates of a mutually issuing Inter1 -> Inter2 -> Inter3 -> Inter1 loop.</summary>
    function LoopCerts: TCryptoLibGenericArray<IX509Certificate>;
    procedure CheckEncodingRoundTrips(const APath: IPkixCertPath; const AEncoding: String);

  protected
    procedure SetUp; override;

  published
    procedure TestEncodingRoundTrips;
    procedure TestEmptyPathHasNoCertificates;
    procedure TestGarbageEncodingRejected;
    procedure TestNoPathThroughCircularSet;

  end;

implementation

{ TCertPathTest }

function TCertPathTest.ReadCert(const ACertId: String): IX509Certificate;
var
  LParser: IX509CertificateParser;
begin
  LParser := TX509CertificateParser.Create();
  Result := LParser.ReadCertificate(TCertVectors.LoadDer(ACertId));
end;

procedure TCertPathTest.SetUp;
begin
  inherited SetUp;
  FRootCert := ReadCert('PkixTestRootCa');
  FInterCert := ReadCert('PkixTestIntermediateCa');
  FFinalCert := ReadCert('PkixTestEndEntity');
end;

function TCertPathTest.LoopCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  Result := TCryptoLibGenericArray<IX509Certificate>.Create(ReadCert('PkixLoopEndEntity'),
    ReadCert('PkixLoopIntermediate3'), ReadCert('PkixLoopIntermediate2'),
    ReadCert('PkixLoopIntermediate1'));
end;

procedure TCertPathTest.CheckEncodingRoundTrips(const APath: IPkixCertPath;
  const AEncoding: String);
var
  LEncoded: TCryptoLibByteArray;
  LStream: TMemoryStream;
  LDecoded: IPkixCertPath;
begin
  LEncoded := APath.GetEncoded(AEncoding);
  CheckTrue(System.Length(LEncoded) > 0, Format('the %s encoding produces bytes', [AEncoding]));

  LStream := TMemoryStream.Create();
  try
    LStream.WriteBuffer(LEncoded[0], System.Length(LEncoded));
    LStream.Position := 0;
    LDecoded := TPkixCertPath.Create(LStream, AEncoding) as IPkixCertPath;
  finally
    LStream.Free;
  end;

  CheckTrue(LDecoded.Equals(APath), Format('the %s encoding round-trips', [AEncoding]));
end;

procedure TCertPathTest.TestEncodingRoundTrips;
var
  LPath: IPkixCertPath;
begin
  LPath := TPkixCertPath.Create(TCryptoLibGenericArray<IX509Certificate>.Create(FInterCert))
    as IPkixCertPath;

  CheckEncodingRoundTrips(LPath, 'PkiPath');
  CheckEncodingRoundTrips(LPath, 'PKCS7');
  CheckEncodingRoundTrips(LPath, 'PEM');
end;

procedure TCertPathTest.TestEmptyPathHasNoCertificates;
var
  LEmpty: TCryptoLibGenericArray<IX509Certificate>;
  LPath: IPkixCertPath;
begin
  LEmpty := nil;
  LPath := TPkixCertPath.Create(LEmpty) as IPkixCertPath;
  CheckEquals(0, System.Length(LPath.Certificates), 'an empty path carries no certificates');
end;

procedure TCertPathTest.TestGarbageEncodingRejected;
var
  LStream: TMemoryStream;
  LGarbage: TCryptoLibByteArray;
  LPath: IPkixCertPath;
  LRaised: Boolean;
begin
  LStream := TMemoryStream.Create();
  try
    try
      LPath := TPkixCertPath.Create(LStream) as IPkixCertPath;
      // an empty stream decoding to an empty path is also an acceptable outcome
      LRaised := System.Length(LPath.Certificates) = 0;
    except
      on E: Exception do
        LRaised := True;
    end;
  finally
    LStream.Free;
  end;
  CheckTrue(LRaised, 'an empty encoding yields no certification path');

  LGarbage := TCryptoLibByteArray.Create(0, 2, 3, 4, 5);
  LRaised := False;
  LStream := TMemoryStream.Create();
  try
    LStream.WriteBuffer(LGarbage[0], System.Length(LGarbage));
    LStream.Position := 0;
    try
      LPath := TPkixCertPath.Create(LStream) as IPkixCertPath;
    except
      on E: Exception do
        LRaised := True;
    end;
  finally
    LStream.Free;
  end;
  CheckTrue(LRaised, 'a malformed encoding is rejected');
end;

procedure TCertPathTest.TestNoPathThroughCircularSet;
var
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LParams: IPkixBuilderParameters;
  LStore: IStore<IX509Certificate>;
  LBuilder: IPkixCertPathBuilder;
  LRaised: Boolean;
begin
  LCerts := LoopCerts();

  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := LCerts[0].SubjectDN;
  // a generic interface carries no GUID, so this upcasts through a typed local instead of "as"
  LTarget := LSelector;

  LAnchors := TCryptoLibGenericArray<ITrustAnchor>.Create(TTrustAnchor.Create(FRootCert, nil)
    as ITrustAnchor);

  LParams := TPkixBuilderParameters.Create(LAnchors, LTarget) as IPkixBuilderParameters;
  LStore := TCollectionStore<IX509Certificate>.Create(LCerts);
  LParams.AddStoreCert(LStore);

  LRaised := False;
  try
    LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
    LBuilder.Build(LParams);
  except
    on E: EPkixCertPathBuilderCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a set of mutually issuing certificates yields no path to the trust anchor');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCertPathTest);
{$ELSE}
  RegisterTest(TCertPathTest.Suite);
{$ENDIF FPC}

end.
