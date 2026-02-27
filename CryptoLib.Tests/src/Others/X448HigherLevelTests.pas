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

unit X448HigherLevelTests;

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
  ClpX448Generators,
  ClpIX448Generators,
  ClpX448Parameters,
  ClpIX448Parameters,
  ClpX448Agreement,
  ClpIX448Agreement,
  ClpIAsymmetricCipherKeyPair,
  ClpSecureRandom,
  ClpISecureRandom,
  CryptoLibTestBase;

type

  TTestX448HigherLevel = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;

    procedure DoTestAgreement();
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestKeyAgreement;
  end;

implementation

{ TTestX448HigherLevel }

procedure TTestX448HigherLevel.DoTestAgreement();
var
  LKpGen: IX448KeyPairGenerator;
  LKpA, LKpB: IAsymmetricCipherKeyPair;
  LAgreeA, LAgreeB: IX448Agreement;
  LSecretA, LSecretB: TBytes;
begin
  LKpGen := TX448KeyPairGenerator.Create() as IX448KeyPairGenerator;
  LKpGen.Init(TX448KeyGenerationParameters.Create(FRandom)
    as IX448KeyGenerationParameters);

  LKpA := LKpGen.GenerateKeyPair();
  LKpB := LKpGen.GenerateKeyPair();

  LAgreeA := TX448Agreement.Create() as IX448Agreement;
  LAgreeA.Init(LKpA.Private);
  System.SetLength(LSecretA, LAgreeA.AgreementSize);
  LAgreeA.CalculateAgreement(LKpB.Public, LSecretA, 0);

  LAgreeB := TX448Agreement.Create() as IX448Agreement;
  LAgreeB.Init(LKpB.Private);
  System.SetLength(LSecretB, LAgreeB.AgreementSize);
  LAgreeB.CalculateAgreement(LKpA.Public, LSecretB, 0);

  if not AreEqual(LSecretA, LSecretB) then
    Fail('X448 agreement failed');
end;

procedure TTestX448HigherLevel.SetUp;
begin
  inherited SetUp();
  FRandom := TSecureRandom.Create();
end;

procedure TTestX448HigherLevel.TearDown;
begin
  FRandom := nil;
  inherited TearDown();
end;

procedure TTestX448HigherLevel.TestKeyAgreement;
var
  LI: Int32;
begin
  for LI := 0 to 9 do
    DoTestAgreement();
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestX448HigherLevel);
{$ELSE}
  RegisterTest(TTestX448HigherLevel.Suite);
{$ENDIF FPC}

end.
