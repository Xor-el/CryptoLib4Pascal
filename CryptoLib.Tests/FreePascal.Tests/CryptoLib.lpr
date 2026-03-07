program CryptoLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces, Forms, GuiTestRunner, Asn1SequenceParserTests,
  EqualsAndHashCodeTests, OIDTests, EnumeratedTests, ParsingTests, ParseTests,
  StringTests, TagTests, BigIntegerTests, ECAlgorithmsTests, ECPointTests,
  SecP256R1FieldTests, SecP384R1FieldTests, ECDsa5Tests, ECTests,
  NamedCurveTests, SignerUtilitiesTests, SecureRandomTests,
  DigestRandomNumberTests, FixedPointTests, AESTests, AESSICTests, SPECKTests,
  IESCipherTests, MD5HMacTests, SHA1HMacTests, SHA224HMacTests, SHA256HMacTests,
  SHA384HMacTests, SHA512HMacTests, RIPEMD128HMacTests, RIPEMD160HMacTests,
  HMacTests, Pkcs5Tests, HkdfGeneratorTests, ECIESTests, PascalCoinECIESTests,
  ECNRTests, PrimesTests, ECEncodingTests, PaddingTests, DSATests,
  DeterministicDsaTests, Salsa20Tests, XSalsa20Tests, ChaChaTests,
  StreamCipherResetTests, CTSTests, X25519Tests, X448Tests, Ed25519Tests,
  Ed448Tests, X25519HigherLevelTests, Ed25519HigherLevelTests,
  ShortenedDigestTests, Kdf1GeneratorTests, Kdf2GeneratorTests, Argon2Tests,
  ScryptTests, DigestTests, CertTests, Curve25519KeyUtilitiesTests,
  Ed448HigherLevelTests, X448HigherLevelTests, Curve448KeyUtilitiesTests,
  DigestUtilitiesTests, ParameterUtilitiesTests, DHTests, Asn1IntegerTests,
  BitStringTests, GeneralizedTimeTests, OctetStringTests, RelativeOidTests,
  UtcTimeTests, InputStreamTests, SetTests, X9Tests, PrivateKeyInfoTests,
  DerUtf8StringTests, EncryptedPrivateKeyInfoTests, Pkcs10CertRequestTests,
  DeltaCertificateTests, CertificateTests, X509AltTests, X509ExtensionsTests,
  X509NameTests, SubjectKeyIdentifierTests, KeyUsageTests, GeneralNameTests,
  KMacTests, RSATests, PssTests, ISO9796Tests, RSABlindedTests,
  RSADigestSignerTests, X931SignerTests, CipherStreamTests, OaepTests,
  RijndaelTests, BlowfishTests, Poly1305Tests, MacTests, ChaCha20Poly1305Tests,
  OcbTests, CcmTests, EaxTests, CMacTests, AeadTestUtilities, GcmReorderTests,
  GCMTests, GcmSivTests, GMacTests, Pkcs12Tests, ClpBip340SchnorrTests,
  CryptoLibTestBase, PkcsEncryptedPrivateKeyInfoTests, Pkcs12StoreTests,
  OpenSslReaderTests, OpenSslWriterTests, X509CertGenTests,
  X509CertificatePairTests, ClpFixedSecureRandom, ClpShortenedDigest,
  Int32Tests, Int64Tests, IPAddressUtilitiesTests, PemReaderTests;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

