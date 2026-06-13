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

unit AlgorithmFinderTests;

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
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpNistObjectIdentifiers,
  ClpOiwObjectIdentifiers,
  ClpEdECObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpPkcsRsaAsn1Objects,
  ClpIPkcsRsaAsn1Objects,
  ClpDefaultDigestAlgorithmFinder,
  ClpIDigestAlgorithmFinder,
  ClpDefaultMacAlgorithmFinder,
  ClpIMacAlgorithmFinder,
  ClpDefaultSignatureAlgorithmFinder,
  ClpISignatureAlgorithmFinder,
  ClpX509Utilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TAlgorithmFinderTest = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestDigestFindByName;
    procedure TestDigestFindBySignatureAlgorithm;
    procedure TestDigestFindByOid;
    procedure TestDigestFindPssDelegation;
    procedure TestDigestFindUnknownName;
    procedure TestDigestFindNilOid;
    procedure TestMacFindKnown;
    procedure TestMacFindUnknown;
    procedure TestSignatureFindKnown;
    procedure TestSignatureFindPss;
    procedure TestSignatureFindEd25519;
    procedure TestSignatureFindEcdsa;
    procedure TestSignatureFindUnknown;
  end;

implementation

{ TAlgorithmFinderTest }

procedure TAlgorithmFinderTest.TestDigestFindByName;
var
  LDigestAlg: IAlgorithmIdentifier;
begin
  LDigestAlg := TDefaultDigestAlgorithmFinder.Instance.Find('SHA-256');
  CheckNotNull(LDigestAlg, 'digest algorithm should not be nil');
  CheckTrue(LDigestAlg.Algorithm.Equals(TNistObjectIdentifiers.IdSha256),
    'SHA-256 digest OID mismatch');
end;

procedure TAlgorithmFinderTest.TestDigestFindBySignatureAlgorithm;
var
  LSignatureAlg, LDigestAlg: IAlgorithmIdentifier;
begin
  LSignatureAlg := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.Sha256WithRsaEncryption,
    TDerNull.Instance);
  LDigestAlg := TDefaultDigestAlgorithmFinder.Instance.Find(LSignatureAlg);
  CheckNotNull(LDigestAlg, 'digest algorithm should not be nil');
  CheckTrue(LDigestAlg.Algorithm.Equals(TNistObjectIdentifiers.IdSha256),
    'signature-to-digest OID mismatch');
end;

procedure TAlgorithmFinderTest.TestDigestFindByOid;
var
  LDigestAlg: IAlgorithmIdentifier;
begin
  LDigestAlg := TDefaultDigestAlgorithmFinder.Instance.Find(TNistObjectIdentifiers.IdSha384);
  CheckNotNull(LDigestAlg, 'digest algorithm should not be nil');
  CheckTrue(LDigestAlg.Algorithm.Equals(TNistObjectIdentifiers.IdSha384),
    'digest OID mismatch');
end;

procedure TAlgorithmFinderTest.TestDigestFindPssDelegation;
var
  LHashAlgId, LSignatureAlg, LDigestAlg: IAlgorithmIdentifier;
  LPssParams: IRsassaPssParameters;
begin
  LHashAlgId := TAlgorithmIdentifier.Create(TNistObjectIdentifiers.IdSha256, TDerNull.Instance);
  LPssParams := TRsassaPssParameters.Create(LHashAlgId,
    TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdMgf1, LHashAlgId) as IAlgorithmIdentifier,
    TDerInteger.ValueOf(32), TRsassaPssParameters.DefaultTrailerField);
  LSignatureAlg := TAlgorithmIdentifier.Create(TPkcsObjectIdentifiers.IdRsassaPss, LPssParams);
  LDigestAlg := TDefaultDigestAlgorithmFinder.Instance.Find(LSignatureAlg);
  CheckNotNull(LDigestAlg, 'PSS digest algorithm should not be nil');
  CheckTrue(LDigestAlg.Algorithm.Equals(TNistObjectIdentifiers.IdSha256),
    'PSS digest OID mismatch');
end;

procedure TAlgorithmFinderTest.TestDigestFindUnknownName;
var
  LDigestAlg: IAlgorithmIdentifier;
begin
  LDigestAlg := TDefaultDigestAlgorithmFinder.Instance.Find('UNKNOWN-DIGEST-NAME');
  CheckNull(LDigestAlg, 'unknown digest name should return nil');
end;

procedure TAlgorithmFinderTest.TestDigestFindNilOid;
var
  LNilOid: IDerObjectIdentifier;
begin
  LNilOid := nil;
  try
    TDefaultDigestAlgorithmFinder.Instance.Find(LNilOid);
    Fail('expected EArgumentNilCryptoLibException');
  except
    on E: EArgumentNilCryptoLibException do
      CheckEquals('digest OID cannot be nil', E.Message);
  end;
end;

procedure TAlgorithmFinderTest.TestMacFindKnown;
var
  LMacAlg: IAlgorithmIdentifier;
begin
  LMacAlg := TDefaultMacAlgorithmFinder.Instance.Find('HMACSHA256');
  CheckNotNull(LMacAlg, 'HMACSHA256 should not be nil');
  CheckTrue(LMacAlg.Algorithm.Equals(TPkcsObjectIdentifiers.IdHmacWithSha256),
    'HMACSHA256 OID mismatch');
  CheckTrue(LMacAlg.Parameters.Equals(TDerNull.Instance), 'HMACSHA256 params should be NULL');

  LMacAlg := TDefaultMacAlgorithmFinder.Instance.Find('HMACSHA1');
  CheckNotNull(LMacAlg, 'HMACSHA1 should not be nil');
  CheckTrue(LMacAlg.Algorithm.Equals(TOiwObjectIdentifiers.IdSha1),
    'HMACSHA1 OID mismatch');
  CheckTrue(TX509Utilities.IsAbsentParameters(LMacAlg.Parameters),
    'HMACSHA1 params should be absent');

  LMacAlg := TDefaultMacAlgorithmFinder.Instance.Find('HMACSHA3-512');
  CheckNotNull(LMacAlg, 'HMACSHA3-512 should not be nil');
  CheckTrue(LMacAlg.Algorithm.Equals(TNistObjectIdentifiers.IdHMacWithSha3_512),
    'HMACSHA3-512 OID mismatch');
  CheckTrue(TX509Utilities.IsAbsentParameters(LMacAlg.Parameters),
    'HMACSHA3-512 params should be absent');
end;

procedure TAlgorithmFinderTest.TestMacFindUnknown;
var
  LMacAlg: IAlgorithmIdentifier;
begin
  LMacAlg := TDefaultMacAlgorithmFinder.Instance.Find('HMACUNKNOWN');
  CheckNull(LMacAlg, 'unknown MAC name should return nil');
end;

procedure TAlgorithmFinderTest.TestSignatureFindKnown;
var
  LSignatureAlg: IAlgorithmIdentifier;
begin
  LSignatureAlg := TDefaultSignatureAlgorithmFinder.Instance.Find('SHA256WITHRSA');
  CheckNotNull(LSignatureAlg, 'SHA256WITHRSA should not be nil');
  CheckTrue(LSignatureAlg.Algorithm.Equals(TPkcsObjectIdentifiers.Sha256WithRsaEncryption),
    'SHA256WITHRSA OID mismatch');
  CheckTrue(LSignatureAlg.Parameters.Equals(TDerNull.Instance),
    'SHA256WITHRSA params should be NULL');
end;

procedure TAlgorithmFinderTest.TestSignatureFindPss;
var
  LSignatureAlg: IAlgorithmIdentifier;
  LPssParams: IRsassaPssParameters;
begin
  LSignatureAlg := TDefaultSignatureAlgorithmFinder.Instance.Find('SHA256WITHRSAANDMGF1');
  CheckNotNull(LSignatureAlg, 'SHA256WITHRSAANDMGF1 should not be nil');
  CheckTrue(LSignatureAlg.Algorithm.Equals(TPkcsObjectIdentifiers.IdRsassaPss),
    'SHA256WITHRSAANDMGF1 OID mismatch');
  LPssParams := TRsassaPssParameters.GetInstance(LSignatureAlg.Parameters);
  CheckNotNull(LPssParams, 'PSS parameters should not be nil');
  CheckTrue(LPssParams.HashAlgorithm.Algorithm.Equals(TNistObjectIdentifiers.IdSha256),
    'PSS hash algorithm mismatch');
  CheckEquals(32, LPssParams.SaltLength.IntValueExact, 'PSS salt length mismatch');
end;

procedure TAlgorithmFinderTest.TestSignatureFindEd25519;
var
  LSignatureAlg: IAlgorithmIdentifier;
begin
  LSignatureAlg := TDefaultSignatureAlgorithmFinder.Instance.Find('Ed25519');
  CheckNotNull(LSignatureAlg, 'Ed25519 should not be nil');
  CheckTrue(LSignatureAlg.Algorithm.Equals(TEdECObjectIdentifiers.IdEd25519),
    'Ed25519 OID mismatch');
  CheckTrue(TX509Utilities.IsAbsentParameters(LSignatureAlg.Parameters),
    'Ed25519 params should be absent');
end;

procedure TAlgorithmFinderTest.TestSignatureFindEcdsa;
var
  LSignatureAlg: IAlgorithmIdentifier;
begin
  LSignatureAlg := TDefaultSignatureAlgorithmFinder.Instance.Find('SHA256WITHECDSA');
  CheckNotNull(LSignatureAlg, 'SHA256WITHECDSA should not be nil');
  CheckTrue(LSignatureAlg.Algorithm.Equals(TX9ObjectIdentifiers.ECDsaWithSha256),
    'SHA256WITHECDSA OID mismatch');
  CheckTrue(TX509Utilities.IsAbsentParameters(LSignatureAlg.Parameters),
    'SHA256WITHECDSA params should be absent');
end;

procedure TAlgorithmFinderTest.TestSignatureFindUnknown;
begin
  try
    TDefaultSignatureAlgorithmFinder.Instance.Find('UNKNOWN-SIGNATURE-NAME');
    Fail('expected EArgumentCryptoLibException');
  except
    on E: EArgumentCryptoLibException do
      CheckTrue(Pos('unknown signature name:', E.Message) > 0,
        'Wrong exception message: ' + E.Message);
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TAlgorithmFinderTest);
{$ELSE}
  RegisterTest(TAlgorithmFinderTest.Suite);
{$ENDIF FPC}

end.
