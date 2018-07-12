program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
  Asn1SequenceParserTests, // pass x64, pass arm
  DerApplicationSpecificTests, // pass x64, pass arm
  EqualsAndHashCodeTests, // pass x64, pass arm
  OIDTests, // pass x64, pass arm
  BigIntegerTests, // pass x64, pass arm
  ECAlgorithmsTests, // pass x64, pass arm
  ECPointTests, // pass x64, pass arm
  SecP384R1FieldTests, // pass x64, pass arm
  ECDsa5Tests, // pass x64, pass arm
  ECTests, // pass x64, pass arm
  NamedCurveTests, // pass x64, pass arm
  ECSchnorrTests, // pass x64, pass arm
  SignerUtilitiesTests, // pass x64, pass arm
  SecureRandomTests, // pass x64, pass arm
  DigestRandomNumberTests, // pass x64, pass arm
  FixedPointTests, // pass x64, pass arm
  AESTests, // pass x64, pass arm
  BlockCipherVectorTests, // pass x64, pass arm
  AESTestVectors,
  AESSICTests,
  IESCipherTests,
  MD5HMacTests,
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
