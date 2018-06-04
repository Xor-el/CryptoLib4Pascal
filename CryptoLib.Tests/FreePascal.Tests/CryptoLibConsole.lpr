program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
 // Asn1SequenceParserTests, // pass x64
 // DerApplicationSpecificTests, // pass x64
 // EqualsAndHashCodeTests, // pass x64
 // OIDTests, // pass x64
 // BigIntegerTests,
 // ECAlgorithmsTests,
//  ECPointTests,
 // SecP384R1FieldTests,
 // ECDsa5Tests,
 // ECTests,
 // NamedCurveTests,
 // ECSchnorrTests,
//  SignerUtilitiesTests,
  SecureRandomTests,
 // DigestRandomNumberTests,
 // FixedPointTests,
 // AESTests, // pass x64
 // BlockCipherVectorTests, // pass x64
  AESTestVectors,
 // IESCipherTests,
 // AESSICTests, // pass x64
 // MD5HMacTests, // pass x64
 // HMacTests,
 // Pkcs5Tests,
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
