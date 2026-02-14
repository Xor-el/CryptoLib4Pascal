program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  consoletestrunner, Asn1SequenceParserTests, EqualsAndHashCodeTests, OIDTests,
  EnumeratedTests, ParsingTests, ParseTests, StringTests, TagTests,
  BigIntegerTests, ECAlgorithmsTests, ECPointTests, SecP256R1FieldTests,
  SecP384R1FieldTests, ECDsa5Tests, ECTests, NamedCurveTests,
  SignerUtilitiesTests, SecureRandomTests, DigestRandomNumberTests,
  FixedPointTests, AESTests, BlockCipherVectorTests, BlockCipherMonteCarloTests,
  AESTestVectors, BlowfishTestVectors, SpeckTestVectors, RijndaelTestVectors,
  AESSICTests, SPECKTests, IESCipherTests, MD5HMacTests, SHA1HMacTests,
  SHA224HMacTests, SHA256HMacTests, SHA384HMacTests, SHA512HMacTests,
  RIPEMD128HMacTests, RIPEMD160HMacTests, HMacTests, Pkcs5Tests,
  HkdfGeneratorTests, ECIESTests, PascalCoinECIESTests, ECNRTests, PrimesTests,
  PaddingTests, DSATests, DeterministicDsaTests, Salsa20Tests, XSalsa20Tests,
  ChaChaTests, StreamCipherResetTests, CTSTests, X25519Tests, Ed25519Tests,
  X25519HigherLevelTests, Ed25519HigherLevelTests, ShortenedDigestTests,
  Kdf1GeneratorTests, Kdf2GeneratorTests, Argon2Tests, ScryptTests, DigestTests,
  CertTests, DigestUtilitiesTests, DHTests, Asn1IntegerTests,
  GeneralizedTimeTests, BitStringTests, InputStreamTests,
  UtcTimeTests, RelativeOidTests, OctetStringTests, SetTests, X9Tests,
  PrivateKeyInfoTests, Pkcs10CertRequestTests, DeltaCertificateTests,
  CertificateTests, X509AltTests, X509ExtensionsTests, X509NameTests,
  SubjectKeyIdentifierTests, KeyUsageTests, GeneralNameTests, KMacTests,
  PssTests, ISO9796Tests, RSABlindedTests, RSADigestSignerTests, RSATests,
  X931SignerTests, CryptoLibTestBase, X509CertGenTests, ClpFixedSecureRandom,
  ClpShortenedDigest, IPAddressUtilitiesTests, PemReaderTests;

type

  { TCryptoLibConsoleTestRunner }

  TCryptoLibConsoleTestRunner = class(TTestRunner)
  protected
  // override the protected methods of TTestRunner to customize its behaviour
  end;

var
  Application: TCryptoLibConsoleTestRunner;

begin
  Application := TCryptoLibConsoleTestRunner.Create(nil);
  Application.Initialize;
  Application.Run;
  Application.Free;
end.
