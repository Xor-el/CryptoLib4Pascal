program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}cwstring,{$ENDIF}
  consoletestrunner, Asn1SequenceParserTests, EqualsAndHashCodeTests, OIDTests,
  EnumeratedTests, ParsingTests, ParseTests, StringTests, TagTests,
  BigIntegerTests, ECAlgorithmsTests, ECPointTests, SecP256R1FieldTests,
  SecP384R1FieldTests, ECDsa5Tests, ECTests, NamedCurveTests,
  SignerUtilitiesTests, SecureRandomTests, DigestRandomNumberTests,
  FixedPointTests, NistSp80038aAesTestData, AESTests, AesLightTests,
  AesX86Tests, AESSICTests, SicBulkParityTests, EcbBulkParityTests,
  CbcBulkParityTests, SpeckCryptoPPTestData, SpeckBlockCipherTestBase,
  SpeckLegacyTests, SpeckTests, IESCipherTests,
  MD5HMacTests, SHA1HMacTests, SHA224HMacTests, SHA256HMacTests,
  SHA384HMacTests, SHA512HMacTests, RIPEMD128HMacTests, RIPEMD160HMacTests,
  HMacTests, Pkcs5Tests, HkdfGeneratorTests, ECIESTests, PascalCoinECIESTests,
  ECNRTests, PrimesTests, ECEncodingTests, PaddingTests, DSATests,
  DeterministicDsaTests, Salsa20Tests, XSalsa20Tests, ChaChaTests,
  StreamCipherResetTests, CTSTests, X25519Tests, X448Tests, Ed25519Tests,
  Ed448Tests, X25519HigherLevelTests, Ed25519HigherLevelTests,
  Curve25519KeyUtilitiesTests, ShortenedDigestTests, Kdf1GeneratorTests,
  Kdf2GeneratorTests, DHKekGeneratorTests, ECDHKekGeneratorTests, Argon2Tests,
  ScryptTests, DigestTests,
  CertTests,
  Ed448HigherLevelTests, X448HigherLevelTests, Curve448KeyUtilitiesTests,
  DigestUtilitiesTests, ParameterUtilitiesTests, DHTests, Asn1IntegerTests,
  GeneralizedTimeTests, BitStringTests, InputStreamTests, UtcTimeTests,
  RelativeOidTests, OctetStringTests, SetTests, X9Tests, PrivateKeyInfoTests,
  DerUtf8StringTests, EncryptedPrivateKeyInfoTests, Pkcs10CertRequestTests,
  DeltaCertificateTests, CertificateTests, X509AltTests, X509ExtensionsTests,
  X509NameTests, SubjectKeyIdentifierTests, KeyUsageTests, GeneralNameTests,
  KMacTests, PssTests, ISO9796Tests, RSABlindedTests, RSADigestSignerTests,
  RSATests, X931SignerTests, CipherStreamTests, OaepTests, RijndaelTests,
  BlowfishTests, CcmTests, ChaCha20Poly1305Tests, CMacTests, EaxTests, OcbTests,
  MacTests, Poly1305Tests, AeadTestUtilities, GcmReorderTests, GCMTests,
  GcmSivTests, GMacTests, Pkcs12Tests, Bip327MuSig2Tests, Bip340SchnorrTests,
  CryptoLibTestBase, PkcsEncryptedPrivateKeyInfoTests,
  Pkcs12StoreTests, OpenSslReaderTests, OpenSslWriterTests, X509CertGenTests,
  X509CertificatePairTests, ClpFixedSecureRandom, ClpShortenedDigest,
  ClpCertTestUtilities, ClpFusedKernelToggle, Int32Tests, Int64Tests,
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
