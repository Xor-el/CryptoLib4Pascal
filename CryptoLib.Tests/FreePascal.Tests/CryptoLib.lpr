program CryptoLib.Tests;

{$mode objfpc}{$H+}

uses
  Interfaces,
  Forms,
  GuiTestRunner,
  Asn1SequenceParserTests,
  DerApplicationSpecificTests,
  EqualsAndHashCodeTests,
  OIDTests,
  EnumeratedTests,
  ParsingTests,
  ParseTests,
  StringTests,
  TagTests,
  BigIntegerTests,
  ECAlgorithmsTests,
  ECPointTests,
  SecP256R1FieldTests,
  SecP384R1FieldTests,
  ECDsa5Tests,
  ECTests,
  NamedCurveTests,
  ECSchnorrTests,
  SignerUtilitiesTests,
  SecureRandomTests,
  DigestRandomNumberTests,
  FixedPointTests,
  AESTests,
  BlockCipherVectorTests,
  BlockCipherMonteCarloTests,
  AESTestVectors,
  AESSICTests,
  IESCipherTests,
  MD5HMacTests,
  SHA1HMacTests,
  SHA224HMacTests,
  SHA256HMacTests,
  SHA384HMacTests,
  SHA512HMacTests,
  RIPEMD128HMacTests,
  RIPEMD160HMacTests,
  HMacTests,
  Pkcs5Tests,
  HkdfGeneratorTests,
  ECIESTests,
  ECNRTests,
  PaddingTests,
  DSATests,
  DeterministicDsaTests,
  ClpFixedSecureRandom,
  ClpIFixedSecureRandom;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

