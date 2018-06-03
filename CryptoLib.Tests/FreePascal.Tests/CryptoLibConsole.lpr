program CryptoLibConsole;

{$mode objfpc}{$H+}

uses
  consoletestrunner,
  Asn1SequenceParserTests,
  DerApplicationSpecificTests,
  EqualsAndHashCodeTests,
  OIDTests,
 // BigIntegerTests,
 // ECAlgorithmsTests,
 // ECPointTests,
 // SecP384R1FieldTests,
 // ECDsa5Tests,
 // ECTests,
 // NamedCurveTests,
 // ECSchnorrTests,
 // SignerUtilitiesTests,
  SecureRandomTests,
  DigestRandomNumberTests,
 // FixedPointTests,
  AESTests,
  BlockCipherVectorTests,
  AESTestVectors,
  IESCipherTests,
  AESSICTests,
  MD5HMacTests,
  HMacTests,
  Pkcs5Tests,
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
