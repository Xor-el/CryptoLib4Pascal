program CryptoLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces, Forms, GuiTestRunner, Asn1GeneratorTests, Asn1SequenceParserTests,
  Asn1TimeFormatTests, EqualsAndHashCodeTests, OIDTests, EnumeratedTests,
  ExternalTests, ParsingTests, ParseTests, StringTests, TagTests,
  BigIntegerTests, ECAlgorithmsTests, ECPointTests, BinPolyTests,
  SecP256R1FieldTests, SecP384R1FieldTests, ECDsa5Tests, ECTests,
  NamedCurveTests, SignerUtilitiesTests, SecureRandomTests,
  DigestRandomNumberTests, FixedPointTests, AESTests, AesLightTests,
  FusedExternalRegistrationTests, AesHardwareEngineTests, AESSICTests,
  SicBulkParityTests, EcbBulkParityTests, CbcBulkParityTests,
  GcmSivBulkParityTests, SpeckBlockCipherTestBase, SpeckLegacyTests, SpeckTests,
  IESCipherTests, HMacTests, Pkcs5Tests, HkdfGeneratorTests, ECIESTests,
  PascalCoinECIESTests, ECNRTests, PrimesTests, ECEncodingTests, GF256AesTests,
  PaddingTests, DSATests, DeterministicDsaTests, Salsa20Tests, XSalsa20Tests,
  ChaChaTests, ChaCha7539ProcessBlocks2Tests, HChaCha20Tests, XChaCha20Tests,
  XChaCha20Poly1305Tests, StreamCipherResetTests, CTSTests, X25519Tests,
  X448Tests, Ed25519Tests, Ed448Tests, X25519HigherLevelTests,
  Ed25519HigherLevelTests, ShortenedDigestTests, Kdf1GeneratorTests,
  Kdf2GeneratorTests, DHKekGeneratorTests, ECDHKekGeneratorTests, Argon2Tests,
  ScryptTests, DigestTests, CertTests, PqcCertCredentialsTests,
  Curve25519KeyUtilitiesTests, Ed448HigherLevelTests, X448HigherLevelTests,
  Curve448KeyUtilitiesTests, DigestUtilitiesTests, ParameterUtilitiesTests,
  DHTests, Asn1IntegerTests, BitStringTests, GeneralizedTimeTests,
  OctetStringTests, RelativeOidTests, UtcTimeTests, InputStreamTests, SetTests,
  X9Tests, PrivateKeyInfoTests, DerUtf8StringTests,
  EncryptedPrivateKeyInfoTests, DefiniteLengthAllocationTests,
  Asn1StreamReadTests, Pkcs10CertRequestTests, DeltaCertificateTests,
  RelatedCertificateTests, CcmParametersTests, GcmParametersTests,
  CertificateTests, X509AltTests, X509ExtensionsTests,
  AuthorityKeyIdentifierTests, IdpRelativeNameTests, IetfUtilitiesTests,
  X509NameTests, SubjectKeyIdentifierTests, KeyUsageTests, GeneralNameTests,
  KeyPurposeIDTests, KMacTests, RSATests, PssTests, ISO9796Tests,
  RSABlindedTests, RSADigestSignerTests, X931SignerTests, CryptoIOStreamTests,
  CryptoIOSinkTests, OaepTests, RijndaelTests, BlowfishTests, Poly1305Tests,
  MacTests, ChaCha20Poly1305Tests, OcbTests, CcmTests, EaxTests, CMacTests,
  AeadTestUtilities, GcmReorderTests, GCMTests, GcmSivTests, GMacTests,
  Pkcs12Tests, Bip327MuSig2Tests, Bip340SchnorrTests, AlgorithmFinderTests,
  MlKemTests, MlDsaTests, PqcPkcsTests, SlhDsaTests, Lib25519Tests,
  Asn1CipherBuilderWithKeyTests, CryptoLibTestBase, CtrDrbgTests,
  DrbgTestSupport, HashDrbgTests, HMacDrbgTests, SimdSelectSlotTests,
  BinaryPrimitivesTests, PkcsEncryptedPrivateKeyInfoTests, Pkcs12StoreTests,
  OpenSslReaderTests, OpenSslWriterTests, X509CertGenTests,
  X509CertificatePairTests, X509UtilitiesTests, FixedSecureRandom,
  ShortenedDigest, CertTestUtilities, FusedKernelToggle,
  CryptoLibTestResourceLoader, CryptoTestKeys, NistSecureRandom, PqcTestSampler,
  CsvVectorParser, JsonVectorParser, RspTxtVectorParser,
  RspTxtVectorParserTests, Bip327Vectors, Bip340Vectors, HmacVectors,
  Argon2Vectors, AsymmetricTestVectors, SymmetricBlockVectors,
  ChaChaPoly1305Vectors, OpenSslVectors, PemReaderVectors, PkcsVectors,
  CertVectors, PqcSampleCredentials, TestKeyBuilders, PemDerCodec,
  PqcTestVectors, DrbgTestVectors, Int32Tests, Int64Tests, ByteUtilitiesTests,
  IPAddressUtilitiesTests, PemReaderTests;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

