program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
 // Asn1SequenceParserTests, // pass x64, pass arm
 // DerApplicationSpecificTests, // pass x64, pass arm
 // EqualsAndHashCodeTests, // pass x64, pass arm
 // OIDTests, // pass x64, pass arm
 // BigIntegerTests, // pass x64, pass arm
 // ECAlgorithmsTests,
 // ECPointTests,
 // SecP384R1FieldTests,
 // ECDsa5Tests,
 // ECTests,
 // NamedCurveTests,
//  ECSchnorrTests, // pass x64, pass arm, arm raises exception
  SignerUtilitiesTests, 
 // SecureRandomTests, // pass x64, pass arm
  DigestRandomNumberTests,
 // FixedPointTests,
 // AESTests, // pass x64, pass arm
  BlockCipherVectorTests, // pass x64
  AESTestVectors,
 // IESCipherTests, // pass x64, pass arm, arm raises exception
 // AESSICTests, // pass x64, pass arm
 // MD5HMacTests, // pass x64, pass arm
 // HMacTests,
 // Pkcs5Tests, // pass x64, pass arm
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
