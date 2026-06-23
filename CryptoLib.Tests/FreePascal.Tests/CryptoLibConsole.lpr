program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cwstring,{$ENDIF}
  consoletestrunner, Asn1GeneratorTests, Asn1SequenceParserTests,
  Asn1TimeFormatTests, EqualsAndHashCodeTests, OIDTests, EnumeratedTests,
  ExternalTests, ParsingTests, ParseTests, StringTests, TagTests,
  BigIntegerTests, ECAlgorithmsTests, ECPointTests, BinPolyTests,
  SecP256R1FieldTests, SecP384R1FieldTests, ECDsa5Tests, ECTests,
  NamedCurveTests, SignerUtilitiesTests, SecureRandomTests,
  DigestRandomNumberTests, FixedPointTests, AESTests, AesLightTests,
  FusedExternalRegistrationTests, AesX86Tests, AESSICTests, SicBulkParityTests,
  EcbBulkParityTests, CbcBulkParityTests, SpeckBlockCipherTestBase,
  SpeckLegacyTests, SpeckTests, IESCipherTests, MD5HMacTests, SHA1HMacTests,
  SHA224HMacTests, SHA256HMacTests, SHA384HMacTests, SHA512HMacTests,
  RIPEMD128HMacTests, RIPEMD160HMacTests, HMacTests, Pkcs5Tests,
  HkdfGeneratorTests, ECIESTests, PascalCoinECIESTests, ECNRTests, PrimesTests,
  ECEncodingTests, PaddingTests, DSATests, DeterministicDsaTests, Salsa20Tests,
  XSalsa20Tests, ChaChaTests, ChaCha7539ProcessBlocks2Tests, HChaCha20Tests,
  XChaCha20Tests, XChaCha20Poly1305Tests, StreamCipherResetTests, CTSTests,
  X25519Tests, X448Tests, Ed25519Tests, Ed448Tests, X25519HigherLevelTests,
  Ed25519HigherLevelTests, Curve25519KeyUtilitiesTests, ShortenedDigestTests,
  Kdf1GeneratorTests, Kdf2GeneratorTests, DHKekGeneratorTests,
  ECDHKekGeneratorTests, Argon2Tests, ScryptTests, DigestTests, CertTests,
  PqcCertCredentialsTests, Ed448HigherLevelTests, X448HigherLevelTests,
  Curve448KeyUtilitiesTests, DigestUtilitiesTests, ParameterUtilitiesTests,
  DHTests, Asn1IntegerTests, GeneralizedTimeTests, BitStringTests,
  InputStreamTests, UtcTimeTests, RelativeOidTests, OctetStringTests, SetTests,
  X9Tests, PrivateKeyInfoTests, DerUtf8StringTests,
  EncryptedPrivateKeyInfoTests, Pkcs10CertRequestTests, DeltaCertificateTests,
  RelatedCertificateTests, CertificateTests, X509AltTests, X509ExtensionsTests,
  AuthorityKeyIdentifierTests, IdpRelativeNameTests, X509NameTests,
  SubjectKeyIdentifierTests, KeyUsageTests, GeneralNameTests, KMacTests,
  PssTests, ISO9796Tests, RSABlindedTests, RSADigestSignerTests, RSATests,
  X931SignerTests, CryptoIOStreamTests, CryptoIOSinkTests, OaepTests,
  RijndaelTests, BlowfishTests, CcmTests, ChaCha20Poly1305Tests, CMacTests,
  EaxTests, OcbTests, MacTests, Poly1305Tests, AeadTestUtilities,
  GcmReorderTests, GCMTests, GcmSivTests, GMacTests, Pkcs12Tests,
  Bip327MuSig2Tests, Bip340SchnorrTests, AlgorithmFinderTests, MlKemTests,
  MlDsaTests, SlhDsaTests, PqcTestSampler, PqcPkcsTests, Lib25519Tests,
  CryptoLibTestBase, SimdSelectSlotTests, BinaryPrimitivesTests,
  PkcsEncryptedPrivateKeyInfoTests, Pkcs12StoreTests, OpenSslReaderTests,
  OpenSslWriterTests, X509CertGenTests, X509CertificatePairTests,
  X509UtilitiesTests, FixedSecureRandom, ShortenedDigest, CertTestUtilities,
  CryptoTestKeys, FusedKernelToggle, CryptoLibTestResourceLoader,
  NistSecureRandom, CsvVectorParser, JsonVectorParser, RspTxtVectorParser,
  RspTxtVectorParserTests, Bip327Vectors, Bip340Vectors, HmacVectors,
  AsymmetricTestVectors, SymmetricBlockVectors, ChaChaPoly1305Vectors,
  OpenSslVectors, PkcsVectors, CertVectors, PqcSampleCredentials,
  CsvVectorLoaderBase, TestKeyBuilders, PemDerCodec, PemReaderVectors,
  Argon2Vectors, PqcTestVectors, Int32Tests, Int64Tests, ByteUtilitiesTests,
  IPAddressUtilitiesTests, PemReaderTests;

type

  { TCryptoLibConsoleTestRunner }

  TCryptoLibConsoleTestRunner = class(TTestRunner)
  protected
  // override the protected methods of TTestRunner to customize its behaviour
  end;

var
  Application: TCryptoLibConsoleTestRunner;

begin
  DefaultRunAllTests:= True;
  DefaultFormat:= TFormat.fPlain;
  Application := TCryptoLibConsoleTestRunner.Create(nil);
  Application.Initialize;
  Application.Run;
  Application.Free;
end.
