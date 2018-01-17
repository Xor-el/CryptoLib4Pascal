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
  BigIntegerTests,
  ECAlgorithmsTests,
  ECPointTests,
  SecP384R1FieldTests,
  ECDsa5Tests,
  ECTests,
  NamedCurveTests,
  SignerUtilitiesTests,
  SecureRandomTests,
  ClpFixedSecureRandom,
  ClpIFixedSecureRandom;

{$R *.res}

begin
  Application.Initialize;
  Application.CreateForm(TGuiTestRunner, TestRunner);
  Application.Run;
end.

