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

unit NamedCurveTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpISigner,
  ClpIBasicAgreement,
  ClpSecNamedCurves,
  ClpTeleTrusTNamedCurves,
  ClpIX9ECParameters,
  ClpECDomainParameters,
  ClpECNamedCurveTable,
  ClpECGost3410NamedCurves,
  ClpIECDomainParameters,
  ClpSignerUtilities,
  ClpECKeyPairGenerator,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIECKeyGenerationParameters,
  ClpGeneratorUtilities,
  ClpAgreementUtilities,
  ClpConverters,
  CryptoLibTestBase;

resourcestring
  SUnknownCurveName = 'Unknown Curve Name: %s';

type

  TTestNamedCurve = class(TCryptoLibAlgorithmTestCase)
  private
    function GetCurveParameters(const name: String): IECDomainParameters;
    procedure DoTestECDsa(const name: String);
    procedure DoTestCurve(const name: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestPerform;
  end;

implementation

{ TTestNamedCurve }

procedure TTestNamedCurve.DoTestECDsa(const name: String);
var
  ecSpec: IECDomainParameters;
  g: IAsymmetricCipherKeyPairGenerator;
  sgr: ISigner;
  pair: IAsymmetricCipherKeyPair;
  sKey, vKey: IAsymmetricKeyParameter;
  &message, sigBytes: TBytes;
begin
  ecSpec := GetCurveParameters(name);

  g := TECKeyPairGenerator.Create('ECDSA');

  g.Init(TECKeyGenerationParameters.Create(ecSpec, TSecureRandom.Create()
    as ISecureRandom) as IECKeyGenerationParameters);

  sgr := TSignerUtilities.GetSigner('ECDSA');
  pair := g.GenerateKeyPair();
  sKey := pair.Private;
  vKey := pair.Public;

  sgr.Init(true, sKey);

  &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not sgr.VerifySignature(sigBytes)) then
  begin
    Fail(Format('%s verification failed', [name]));
  end;
end;

procedure TTestNamedCurve.DoTestCurve(const name: String);
var
  ecSpec: IECDomainParameters;
  g: IAsymmetricCipherKeyPairGenerator;
  aKeyPair, bKeyPair: IAsymmetricCipherKeyPair;
  aKeyAgree, bKeyAgree: IBasicAgreement;
  k1, k2: TBigInteger;
begin
  ecSpec := GetCurveParameters(name);

  g := TGeneratorUtilities.GetKeyPairGenerator('ECDH');

  g.Init(TECKeyGenerationParameters.Create(ecSpec, TSecureRandom.Create()
    as ISecureRandom) as IECKeyGenerationParameters);

  //
  // a side
  //
  aKeyPair := g.GenerateKeyPair();

  aKeyAgree := TAgreementUtilities.GetBasicAgreement('ECDHC');

  aKeyAgree.Init(aKeyPair.Private);

  //
  // b side
  //
  bKeyPair := g.GenerateKeyPair();

  bKeyAgree := TAgreementUtilities.GetBasicAgreement('ECDHC');

  bKeyAgree.Init(bKeyPair.Private);

  //
  // agreement
  //

  k1 := aKeyAgree.CalculateAgreement(bKeyPair.Public);
  k2 := bKeyAgree.CalculateAgreement(aKeyPair.Public);

  if (not k1.Equals(k2)) then
  begin
    Fail('2-way test failed');
  end;
end;

function TTestNamedCurve.GetCurveParameters(const name: String)
  : IECDomainParameters;
var
  ecdp: IECDomainParameters;
  ecP: IX9ECParameters;
begin
  ecdp := TECGost3410NamedCurves.GetByName(name);

  if (ecdp <> Nil) then
  begin
    result := ecdp;
    Exit;
  end;

  ecP := TECNamedCurveTable.GetByName(name);

  if (ecP = Nil) then
  begin
    raise Exception.CreateResFmt(@SUnknownCurveName, [name]);
  end;

  result := TECDomainParameters.Create(ecP.Curve, ecP.g, ecP.N, ecP.H,
    ecP.GetSeed());
end;

procedure TTestNamedCurve.SetUp;
begin
  inherited;

end;

procedure TTestNamedCurve.TearDown;
begin
  inherited;

end;

procedure TTestNamedCurve.TestPerform;
var
  name: string;
begin
  DoTestCurve('sect571r1'); // sec
  DoTestCurve('secp224r1');
  DoTestCurve('B-409'); // nist
  DoTestCurve('P-521');
  DoTestCurve('brainpoolp160r1'); // TeleTrusT

  for name in TSecNamedCurves.Names do
  begin
    DoTestECDsa(name);
  end;

  for name in TTeleTrusTNamedCurves.Names do
  begin
    DoTestECDsa(name);
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestNamedCurve);
{$ELSE}
  RegisterTest(TTestNamedCurve.Suite);
{$ENDIF FPC}

end.
