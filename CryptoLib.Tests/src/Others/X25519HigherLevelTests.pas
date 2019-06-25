{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit X25519HigherLevelTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpSecureRandom,
  ClpISecureRandom,
  ClpX25519Agreement,
  ClpIX25519Agreement,
  ClpIAsymmetricCipherKeyPair,
  ClpX25519KeyPairGenerator,
  ClpIX25519KeyPairGenerator,
  ClpX25519KeyGenerationParameters,
  ClpIX25519KeyGenerationParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  CryptoLibTestBase;

type

  TTestX25519HigherLevel = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;

    procedure DoTestAgreement();
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestAgreement();

  end;

implementation

{ TTestX25519HigherLevel }

procedure TTestX25519HigherLevel.DoTestAgreement;
var
  kpGen: IAsymmetricCipherKeyPairGenerator;
  kpA, kpB: IAsymmetricCipherKeyPair;
  agreeA, agreeB: IX25519Agreement;
  secretA, secretB: TBytes;
begin
  kpGen := TX25519KeyPairGenerator.Create() as IX25519KeyPairGenerator;
  kpGen.Init(TX25519KeyGenerationParameters.Create(FRandom)
    as IX25519KeyGenerationParameters);

  kpA := kpGen.GenerateKeyPair();
  kpB := kpGen.GenerateKeyPair();

  agreeA := TX25519Agreement.Create();
  agreeA.Init(kpA.Private);
  System.SetLength(secretA, agreeA.AgreementSize);
  agreeA.CalculateAgreement(kpB.Public, secretA, 0);

  agreeB := TX25519Agreement.Create();
  agreeB.Init(kpB.Private);
  System.SetLength(secretB, agreeB.AgreementSize);
  agreeB.CalculateAgreement(kpA.Public, secretB, 0);

  if (not AreEqual(secretA, secretB)) then
  begin
    Fail('X25519 agreement failed');
  end;
end;

procedure TTestX25519HigherLevel.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestX25519HigherLevel.TearDown;
begin
  inherited;

end;

procedure TTestX25519HigherLevel.TestAgreement;
var
  i: Int32;
begin
  i := 0;
  while i < 10 do
  begin
    DoTestAgreement();
    System.Inc(i);
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestX25519HigherLevel);
{$ELSE}
  RegisterTest(TTestX25519HigherLevel.Suite);
{$ENDIF FPC}

end.
