program CryptoLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces, Forms, GuiTestRunner,
  Asn1SequenceParserTests, EqualsAndHashCodeTests, OIDTests, EnumeratedTests,
  ParsingTests, ParseTests, StringTests, TagTests, BigIntegerTests,
  ECAlgorithmsTests, ECPointTests, SecP256R1FieldTests, SecP384R1FieldTests,
  ECDsa5Tests, ECTests, NamedCurveTests, SignerUtilitiesTests,
  SecureRandomTests, DigestRandomNumberTests, FixedPointTests, AESTests,
  BlockCipherVectorTests, BlockCipherMonteCarloTests, AESTestVectors,
  BlowfishTestVectors, SpeckTestVectors, RijndaelTestVectors, AESSICTests,
  SPECKTests, IESCipherTests, MD5HMacTests, SHA1HMacTests, SHA224HMacTests,
  SHA256HMacTests, SHA384HMacTests, SHA512HMacTests, RIPEMD128HMacTests,
  RIPEMD160HMacTests, HMacTests, Pkcs5Tests, HkdfGeneratorTests, ECIESTests,
  PascalCoinECIESTests, ECNRTests, PrimesTests, PaddingTests, DSATests,
  DeterministicDsaTests, Salsa20Tests, XSalsa20Tests, ChaChaTests,
  StreamCipherResetTests, CTSTests, X25519Tests, Ed25519Tests,
  X25519HigherLevelTests, Ed25519HigherLevelTests, ShortenedDigestTests,
  Kdf1GeneratorTests, Kdf2GeneratorTests, Argon2Tests, ScryptTests, DigestTests,
  CertTests, DigestUtilitiesTests, DHTests, Asn1IntegerTests, BitStringTests,
  GeneralizedTimeTests, OctetStringTests, RelativeOidTests,
  UtcTimeTests, InputStreamTests, SetTests, X9Tests, PrivateKeyInfoTests,
  Pkcs10CertRequestTests, DeltaCertificateTests, CertificateTests, X509AltTests,
  X509ExtensionsTests, X509NameTests, SubjectKeyIdentifierTests, KeyUsageTests,
  GeneralNameTests, KMacTests, RSATests, PssTests, ISO9796Tests,
  RSABlindedTests, RSADigestSignerTests, X931SignerTests, CryptoLibTestBase,
  X509CertGenTests, ClpFixedSecureRandom, ClpShortenedDigest,
  IPAddressUtilitiesTests, PemReaderTests;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

