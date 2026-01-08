{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit Pkcs10CertificationRequestTests;

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
  ClpBigInteger,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDigestUtilities,
  ClpIDigest,
  ClpAsn1Objects,
  ClpIAsn1Objects,
  ClpIX9ECParameters,
  ClpIECDomainParameters,
  ClpECDomainParameters,
  ClpIECKeyPairGenerator,
  ClpECKeyPairGenerator,
  ClpIECKeyGenerationParameters,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpCustomNamedCurves,
  ClpX500Name,
  ClpIX500Name,
  ClpPkcs10CertificationRequest,
  ClpIPkcs10CertificationRequest,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpHMacDsaKCalculator,
  ClpIHMacDsaKCalculator,
  ClpSignersEncodings,
  ClpISignersEncodings,
  // Ed25519 support
  ClpEd25519KeyPairGenerator,
  ClpIEd25519KeyPairGenerator,
  ClpEd25519KeyGenerationParameters,
  ClpIEd25519KeyGenerationParameters,
  ClpIEd25519PublicKeyParameters,
  ClpIEd25519PrivateKeyParameters,
  ClpEd25519,
  ClpIEd25519,
  ClpEd25519Signer,
  ClpIEd25519Signer,
  CryptoLibTestBase,
  ClpCryptoLibTypes;

  type
  TTestPkcs10CertificationRequest = class(TCryptoLibAlgorithmTestCase)
  private
    FRandom: ISecureRandom;

    function GenerateECKeyPairForCurve(const curveName: string): IAsymmetricCipherKeyPair;
    function GenerateEd25519KeyPair: IAsymmetricCipherKeyPair;
    procedure DoTestCSRForCurve(const curveName, digestName: string);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    // Test different hash algorithms with secp256k1
    procedure TestBuildCSRWithSHA256;
    procedure TestBuildCSRWithSHA384;
    procedure TestBuildCSRWithSHA512;

    // Test different curves with SHA-256
    procedure TestCSRWithP256;
    procedure TestCSRWithP384;
    procedure TestCSRWithP521;
    procedure TestCSRWithSecp256k1;

    // Ed25519 tests
    procedure TestCSRWithEd25519;
    procedure TestEd25519SignatureVerification;

    // Extension tests
    procedure TestCSRWithSubjectKeyIdentifier;
    procedure TestCSRWithCustomExtension;

    // Other tests
    procedure TestCSRSignatureVerification;
    procedure TestX500NameBuilder;
    procedure TestCSRDerEncoding;
  end;

implementation

{ TTestPkcs10CertificationRequest }

procedure TTestPkcs10CertificationRequest.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestPkcs10CertificationRequest.TearDown;
begin
  inherited;
end;

function TTestPkcs10CertificationRequest.GenerateECKeyPairForCurve(
  const curveName: string): IAsymmetricCipherKeyPair;
var
  curve: IX9ECParameters;
  domain: IECDomainParameters;
  generator: IECKeyPairGenerator;
  keygenParams: IECKeyGenerationParameters;
begin
  curve := TCustomNamedCurves.GetByName(curveName);
  CheckNotNull(curve, 'Curve ' + curveName + ' not found');

  domain := TECDomainParameters.Create(curve.Curve, curve.G, curve.N,
    curve.H, curve.GetSeed);
  generator := TECKeyPairGenerator.Create('ECDSA');
  keygenParams := TECKeyGenerationParameters.Create(domain, FRandom);
  generator.Init(keygenParams);
  Result := generator.GenerateKeyPair();
end;

function TTestPkcs10CertificationRequest.GenerateEd25519KeyPair: IAsymmetricCipherKeyPair;
var
  ed25519Instance: IEd25519;
  generator: IEd25519KeyPairGenerator;
  keygenParams: IEd25519KeyGenerationParameters;
begin
  ed25519Instance := TEd25519.Create();
  generator := TEd25519KeyPairGenerator.Create(ed25519Instance);
  keygenParams := TEd25519KeyGenerationParameters.Create(FRandom);
  generator.Init(keygenParams);
  Result := generator.GenerateKeyPair();
end;

procedure TTestPkcs10CertificationRequest.DoTestCSRForCurve(
  const curveName, digestName: string);
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  digest: IDigest;
  derBytes: TCryptoLibByteArray;
  pubKey: IECPublicKeyParameters;
  privKey: IECPrivateKeyParameters;
begin
  keyPair := GenerateECKeyPairForCurve(curveName);
  pubKey := keyPair.Public as IECPublicKeyParameters;
  privKey := keyPair.Private as IECPrivateKeyParameters;

  subject := TX500NameBuilder.Create
    .AddCommonName('Test ' + curveName)
    .AddOrganization('CryptoLib4Pascal')
    .AddCountry('US')
    .Build;

  digest := TDigestUtilities.GetDigest(digestName);

  // digest passed to constructor
  builder := TECDSACertificationRequestBuilder.Create(digest);
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(pubKey)
    .AddSubjectKeyIdentifier()
    .Build(privKey);

  // Verify CSR was created
  CheckNotNull(csr, 'CSR for ' + curveName + ' should not be nil');
  CheckNotNull(csr.CertificationRequestInfo, 'CertificationRequestInfo should not be nil');
  CheckNotNull(csr.SignatureAlgorithm, 'SignatureAlgorithm should not be nil');
  CheckNotNull(csr.Signature, 'Signature should not be nil');

  // Verify DER encoding works
  derBytes := csr.GetEncoded;
  CheckTrue(Length(derBytes) > 0, 'DER encoded CSR should not be empty');
end;

procedure TTestPkcs10CertificationRequest.TestBuildCSRWithSHA256;
begin
  DoTestCSRForCurve('secp256k1', 'SHA-256');
end;

procedure TTestPkcs10CertificationRequest.TestBuildCSRWithSHA384;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  digest: IDigest;
begin
  keyPair := GenerateECKeyPairForCurve('secp256k1');

  subject := TX500NameBuilder.Create
    .AddCommonName('SHA384 Test')
    .Build;

  digest := TDigestUtilities.GetDigest('SHA-384');

  builder := TECDSACertificationRequestBuilder.Create(digest);
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(keyPair.Public as IECPublicKeyParameters)
    .Build(keyPair.Private as IECPrivateKeyParameters);

  CheckNotNull(csr, 'CSR with SHA-384 should not be nil');

  // Check algorithm OID contains SHA384
  CheckTrue(csr.SignatureAlgorithm.Algorithm.Id = '1.2.840.10045.4.3.3',
    'Signature algorithm should be ecdsa-with-SHA384');
end;

procedure TTestPkcs10CertificationRequest.TestBuildCSRWithSHA512;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  digest: IDigest;
begin
  keyPair := GenerateECKeyPairForCurve('secp256k1');

  subject := TX500NameBuilder.Create
    .AddCommonName('SHA512 Test')
    .Build;

  digest := TDigestUtilities.GetDigest('SHA-512');

  builder := TECDSACertificationRequestBuilder.Create(digest);
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(keyPair.Public as IECPublicKeyParameters)
    .Build(keyPair.Private as IECPrivateKeyParameters);

  CheckNotNull(csr, 'CSR with SHA-512 should not be nil');

  // Check algorithm OID contains SHA512
  CheckTrue(csr.SignatureAlgorithm.Algorithm.Id = '1.2.840.10045.4.3.4',
    'Signature algorithm should be ecdsa-with-SHA512');
end;

procedure TTestPkcs10CertificationRequest.TestCSRWithP256;
begin
  DoTestCSRForCurve('P-256', 'SHA-256');
end;

procedure TTestPkcs10CertificationRequest.TestCSRWithP384;
begin
  DoTestCSRForCurve('P-384', 'SHA-384');
end;

procedure TTestPkcs10CertificationRequest.TestCSRWithP521;
begin
  DoTestCSRForCurve('P-521', 'SHA-512');
end;

procedure TTestPkcs10CertificationRequest.TestCSRWithSecp256k1;
begin
  DoTestCSRForCurve('secp256k1', 'SHA-256');
end;

procedure TTestPkcs10CertificationRequest.TestCSRSignatureVerification;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  digest: IDigest;
  tbsBytes, hashBytes, sigBytes: TCryptoLibByteArray;
  signer: IECDsaSigner;
  sigValues: TCryptoLibGenericArray<TBigInteger>;
  privKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  verifyResult: Boolean;
begin
  keyPair := GenerateECKeyPairForCurve('secp256k1');
  privKey := keyPair.Private as IECPrivateKeyParameters;
  pubKey := keyPair.Public as IECPublicKeyParameters;

  subject := TX500NameBuilder.Create
    .AddCommonName('Verify Test')
    .AddOrganization('CryptoLib4Pascal')
    .Build;

  digest := TDigestUtilities.GetDigest('SHA-256');

  builder := TECDSACertificationRequestBuilder.Create(digest);
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(pubKey)
    .Build(privKey);

  // Get the TBS (to-be-signed) data
  tbsBytes := csr.CertificationRequestInfo.ToAsn1Object.GetEncoded(TAsn1Encodable.Der);

  // Hash it with SHA-256
  digest.Reset;
  System.SetLength(hashBytes, digest.GetDigestSize);
  digest.BlockUpdate(tbsBytes, 0, Length(tbsBytes));
  digest.DoFinal(hashBytes, 0);

  // Get signature bytes and decode
  sigBytes := csr.Signature.GetOctets;
  sigValues := TStandardDsaEncoding.Instance.Decode(privKey.Parameters.N, sigBytes);

  // Verify signature
  signer := TECDsaSigner.Create();
  signer.Init(False, pubKey);
  verifyResult := signer.VerifySignature(hashBytes, sigValues[0], sigValues[1]);

  CheckTrue(verifyResult, 'CSR signature verification should pass');
end;

procedure TTestPkcs10CertificationRequest.TestX500NameBuilder;
var
  subject: IX500Name;
  derBytes: TCryptoLibByteArray;
begin
  subject := TX500NameBuilder.Create
    .AddCommonName('Test Common Name')
    .AddOrganization('Test Organization')
    .AddOrganizationalUnit('Test OU')
    .AddCountry('US')
    .AddState('California')
    .AddLocality('San Francisco')
    .AddEmailAddress('test@example.com')
    .Build;

  CheckNotNull(subject, 'X500Name should not be nil');

  // Verify it can be DER encoded
  derBytes := subject.ToAsn1Object.GetEncoded(TAsn1Encodable.Der);
  CheckTrue(Length(derBytes) > 0, 'X500Name DER encoding should not be empty');
end;

procedure TTestPkcs10CertificationRequest.TestCSRDerEncoding;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  digest: IDigest;
  derBytes: TCryptoLibByteArray;
  pemString: string;
  seq: IAsn1Sequence;
begin
  keyPair := GenerateECKeyPairForCurve('secp256k1');

  subject := TX500NameBuilder.Create
    .AddCommonName('DER Test')
    .Build;

  digest := TDigestUtilities.GetDigest('SHA-256');

  builder := TECDSACertificationRequestBuilder.Create(digest);
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(keyPair.Public as IECPublicKeyParameters)
    .Build(keyPair.Private as IECPrivateKeyParameters);

  // Test DER encoding
  derBytes := csr.GetEncoded;
  CheckTrue(Length(derBytes) > 0, 'DER bytes should not be empty');

  // Verify it can be parsed back as ASN1 sequence
  seq := TAsn1Sequence.GetInstance(derBytes);
  CheckNotNull(seq, 'Should be able to parse CSR as ASN1 sequence');
  CheckEquals(3, seq.Count, 'CSR should have 3 elements');

  // Test PEM encoding
  pemString := csr.GetPemEncoded;
  CheckTrue(Length(pemString) > 0, 'PEM string should not be empty');
  CheckTrue(Pos('-----BEGIN CERTIFICATE REQUEST-----', pemString) > 0,
    'PEM should contain BEGIN header');
  CheckTrue(Pos('-----END CERTIFICATE REQUEST-----', pemString) > 0,
    'PEM should contain END footer');
end;

procedure TTestPkcs10CertificationRequest.TestCSRWithEd25519;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  derBytes: TCryptoLibByteArray;
  pemString: string;
begin
  keyPair := GenerateEd25519KeyPair;

  subject := TX500NameBuilder.Create
    .AddCommonName('Ed25519 Test')
    .AddOrganization('CryptoLib4Pascal')
    .AddCountry('US')
    .Build;

  // TEdDSACertificationRequestBuilder, no digest needed
  builder := TEdDSACertificationRequestBuilder.Create;
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(keyPair.Public as IEd25519PublicKeyParameters)
    .AddSubjectKeyIdentifier()
    .Build(keyPair.Private as IEd25519PrivateKeyParameters);

  // Verify CSR was created
  CheckNotNull(csr, 'CSR with Ed25519 should not be nil');
  CheckNotNull(csr.CertificationRequestInfo, 'CertificationRequestInfo should not be nil');
  CheckNotNull(csr.SignatureAlgorithm, 'SignatureAlgorithm should not be nil');
  CheckNotNull(csr.Signature, 'Signature should not be nil');

  // Check signature algorithm OID is Ed25519 (1.3.101.112)
  CheckTrue(csr.SignatureAlgorithm.Algorithm.Id = '1.3.101.112',
    'Signature algorithm should be Ed25519');

  // Verify DER encoding works
  derBytes := csr.GetEncoded;
  CheckTrue(Length(derBytes) > 0, 'DER encoded CSR should not be empty');

  // Verify PEM encoding works
  pemString := csr.GetPemEncoded;
  CheckTrue(Length(pemString) > 0, 'PEM string should not be empty');
  CheckTrue(Pos('-----BEGIN CERTIFICATE REQUEST-----', pemString) > 0,
    'PEM should contain BEGIN header');
end;

procedure TTestPkcs10CertificationRequest.TestEd25519SignatureVerification;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  tbsBytes, sigBytes: TCryptoLibByteArray;
  signer: IEd25519Signer;
  ed25519Instance: IEd25519;
  privKey: IEd25519PrivateKeyParameters;
  pubKey: IEd25519PublicKeyParameters;
  verifyResult: Boolean;
begin
  keyPair := GenerateEd25519KeyPair;
  privKey := keyPair.Private as IEd25519PrivateKeyParameters;
  pubKey := keyPair.Public as IEd25519PublicKeyParameters;

  subject := TX500NameBuilder.Create
    .AddCommonName('Ed25519 Verify Test')
    .AddOrganization('CryptoLib4Pascal')
    .Build;

  builder := TEdDSACertificationRequestBuilder.Create;
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(pubKey)
    .Build(privKey);

  // Get the TBS (to-be-signed) data
  tbsBytes := csr.CertificationRequestInfo.ToAsn1Object.GetEncoded(TAsn1Encodable.Der);

  // Get signature bytes
  sigBytes := csr.Signature.GetOctets;

  // Verify signature using Ed25519Signer
  ed25519Instance := TEd25519.Create();
  signer := TEd25519Signer.Create(ed25519Instance);
  signer.Init(False, pubKey);
  signer.BlockUpdate(tbsBytes, 0, Length(tbsBytes));
  verifyResult := signer.VerifySignature(sigBytes);

  CheckTrue(verifyResult, 'Ed25519 CSR signature verification should pass');
end;

procedure TTestPkcs10CertificationRequest.TestCSRWithSubjectKeyIdentifier;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  digest: IDigest;
  derBytes: TCryptoLibByteArray;
  pemString: string;
begin
  keyPair := GenerateECKeyPairForCurve('secp256k1');

  subject := TX500NameBuilder.Create
    .AddCommonName('Extension Test')
    .AddOrganization('CryptoLib4Pascal')
    .AddCountry('US')
    .Build;

  digest := TDigestUtilities.GetDigest('SHA-256');

  // Build CSR with Subject Key Identifier extension
  builder := TECDSACertificationRequestBuilder.Create(digest);
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(keyPair.Public as IECPublicKeyParameters)
    .AddSubjectKeyIdentifier()  // Add Subject Key Identifier extension
    .Build(keyPair.Private as IECPrivateKeyParameters);

  // Verify CSR was created
  CheckNotNull(csr, 'CSR with SKI should not be nil');
  CheckNotNull(csr.CertificationRequestInfo, 'CertificationRequestInfo should not be nil');

  // Verify DER encoding works
  derBytes := csr.GetEncoded;
  CheckTrue(Length(derBytes) > 0, 'DER encoded CSR should not be empty');

  // Verify PEM encoding works
  pemString := csr.GetPemEncoded;
  CheckTrue(Length(pemString) > 0, 'PEM string should not be empty');
  CheckTrue(Pos('-----BEGIN CERTIFICATE REQUEST-----', pemString) > 0,
    'PEM should contain BEGIN header');
end;

procedure TTestPkcs10CertificationRequest.TestCSRWithCustomExtension;
var
  keyPair: IAsymmetricCipherKeyPair;
  subject: IX500Name;
  builder: IPkcs10CertificationRequestBuilder;
  csr: IPkcs10CertificationRequest;
  digest: IDigest;
  derBytes: TCryptoLibByteArray;
  customOid: IDerObjectIdentifier;
  customValue: IDerUtf8String;
begin
  keyPair := GenerateECKeyPairForCurve('secp256k1');

  subject := TX500NameBuilder.Create
    .AddCommonName('Custom Extension Test')
    .AddOrganization('CryptoLib4Pascal')
    .Build;

  digest := TDigestUtilities.GetDigest('SHA-256');

  // Create custom extension OID and value
  // Using a test OID: 1.2.3.4.5.6.7.8.9
  customOid := TDerObjectIdentifier.Create('1.2.3.4.5.6.7.8.9');
  customValue := TDerUtf8String.Create('Test Extension Value');

  // Build CSR with custom extension
  builder := TECDSACertificationRequestBuilder.Create(digest);
  csr := builder
    .SetSubject(subject)
    .SetPublicKey(keyPair.Public as IECPublicKeyParameters)
    .AddExtension(customOid, False, customValue)  // Non-critical custom extension
    .AddSubjectKeyIdentifier()  // Also add SKI
    .Build(keyPair.Private as IECPrivateKeyParameters);

  // Verify CSR was created
  CheckNotNull(csr, 'CSR with custom extension should not be nil');
  CheckNotNull(csr.CertificationRequestInfo, 'CertificationRequestInfo should not be nil');

  // Verify DER encoding works
  derBytes := csr.GetEncoded;
  CheckTrue(Length(derBytes) > 0, 'DER encoded CSR should not be empty');
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestPkcs10CertificationRequest);
{$ELSE}
  RegisterTest(TTestPkcs10CertificationRequest.Suite);
{$ENDIF FPC}

end.
