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
  ClpX25519Generators,
  ClpIX25519Generators,
  ClpX25519Parameters,
  ClpIX25519Parameters,
  ClpX25519Agreement,
  ClpIX25519Agreement,
  ClpIAsymmetricCipherKeyPair,
  ClpSecureRandom,
  ClpISecureRandom,
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
    procedure TestFunction();
  end;

implementation

{ TTestX25519HigherLevel }

procedure TTestX25519HigherLevel.DoTestAgreement();
var
  LKpGen: IX25519KeyPairGenerator;
  LKpA, LKpB: IAsymmetricCipherKeyPair;
  LAgreeA, LAgreeB: IX25519Agreement;
  LSecretA, LSecretB: TBytes;
begin
  LKpGen := TX25519KeyPairGenerator.Create() as IX25519KeyPairGenerator;
  LKpGen.Init(TX25519KeyGenerationParameters.Create(FRandom)
    as IX25519KeyGenerationParameters);

  LKpA := LKpGen.GenerateKeyPair();
  LKpB := LKpGen.GenerateKeyPair();

  LAgreeA := TX25519Agreement.Create() as IX25519Agreement;
  LAgreeA.Init(LKpA.Private);
  System.SetLength(LSecretA, LAgreeA.AgreementSize);
  LAgreeA.CalculateAgreement(LKpB.Public, LSecretA, 0);

  LAgreeB := TX25519Agreement.Create() as IX25519Agreement;
  LAgreeB.Init(LKpB.Private);
  System.SetLength(LSecretB, LAgreeB.AgreementSize);
  LAgreeB.CalculateAgreement(LKpA.Public, LSecretB, 0);

  if not AreEqual(LSecretA, LSecretB) then
    Fail('X25519 agreement failed');
end;

procedure TTestX25519HigherLevel.SetUp;
begin
  inherited SetUp();
  FRandom := TSecureRandom.Create();
end;

procedure TTestX25519HigherLevel.TearDown;
begin
  FRandom := nil;
  inherited TearDown();
end;

procedure TTestX25519HigherLevel.TestFunction();
var
  LI: Int32;
begin
  for LI := 0 to 9 do
    DoTestAgreement();
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX25519HigherLevel);
{$ELSE}
  RegisterTest(TTestX25519HigherLevel.Suite);
{$ENDIF FPC}

end.
