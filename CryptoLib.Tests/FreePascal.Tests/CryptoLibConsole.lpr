program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
  Asn1SequenceParserTests, // pass x64, pass arm
  DerApplicationSpecificTests, // pass x64, pass arm
  EqualsAndHashCodeTests, // pass x64, pass arm
  OIDTests, // pass x64, pass arm
  BigIntegerTests, // pass x64, pass arm
 // ECAlgorithmsTests, // pass x64, arm stalling
 // ECPointTests, // pass x64, arm stalling
  SecP384R1FieldTests, // pass x64, pass arm
 // ECDsa5Tests, // pass x64, arm stalling
 // ECTests, // pass x64, arm stalling
  NamedCurveTests, // pass x64, pass arm, arm raises exception
  ECSchnorrTests, // pass x64, pass arm, arm raises exception
  SignerUtilitiesTests, // pass x64, pass arm, arm raises exception
  SecureRandomTests, // pass x64, pass arm
  DigestRandomNumberTests, // pass x64, pass arm
  FixedPointTests, // pass x64, pass arm, arm raises exception
  AESTests, // pass x64, pass arm
 BlockCipherVectorTests, // pass x64, pass arm
  AESTestVectors,
  IESCipherTests, // pass x64, pass arm, arm raises exception
  AESSICTests, // pass x64, pass arm
  MD5HMacTests, // pass x64, pass arm
 // HMacTests, // pass arm, x64 stalling
  Pkcs5Tests, // pass x64, pass arm
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
