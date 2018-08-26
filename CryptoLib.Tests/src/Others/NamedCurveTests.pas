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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpISigner,
  ClpSecNamedCurves,
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
  ClpConverters,
  ClpCryptoLibTypes;

resourcestring
  SUnknownCurveName = 'Unknown Curve Name: %s';

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  TTestNamedCurve = class(TCryptoLibTestCase)
  private
    function GetCurveParameters(const name: String): IECDomainParameters;
    procedure doTestECDsa(const name: String);
    // procedure doTestECGost(const name: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestPerform;
  end;

implementation

{ TTestNamedCurve }

procedure TTestNamedCurve.doTestECDsa(const name: String);
var
  ecSpec: IECDomainParameters;
  g: IAsymmetricCipherKeyPairGenerator;
  sgr: ISigner;
  pair: IAsymmetricCipherKeyPair;
  sKey, vKey: IAsymmetricKeyParameter;
  &message, sigBytes: TCryptoLibByteArray;
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
    Fail(name + ' verification failed');
  end;
end;

// procedure TTestNamedCurve.doTestECGost(const name: String);
// var
// sgr: ISigner;
// keyAlgorithm: String;
// ecSpec: IECDomainParameters;
// g: IAsymmetricCipherKeyPairGenerator;
// pair: IAsymmetricCipherKeyPair;
// sKey, vKey: IAsymmetricKeyParameter;
// &message, sigBytes: TCryptoLibByteArray;
// begin
// if System.Pos('Tc26-Gost-3410', name) > 0 then
// begin
// // TODO Implement ECGOST3410-2012 in SignerUtilies/GeneratorUtilities etc.
// // Current test cases don't work for GOST34.10 2012
// Exit;
// end
// else
// begin
// keyAlgorithm := 'ECGOST3410';
//
// sgr := TSignerUtilities.GetSigner('ECGOST3410');
// end;
//
// ecSpec := GetCurveParameters(name);
//
// g := TECKeyPairGenerator.Create(keyAlgorithm);
//
// g.Init(TECKeyGenerationParameters.Create(ecSpec, TSecureRandom.Create() as ISecureRandom) as IECKeyGenerationParameters);
//
// pair := g.GenerateKeyPair();
// sKey := pair.Private;
// vKey := pair.Public;
//
// sgr.Init(true, sKey);
//
// &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);
//
// sgr.BlockUpdate(&message, 0, System.Length(&message));
//
// sigBytes := sgr.GenerateSignature();
//
// sgr.Init(false, vKey);
//
// sgr.BlockUpdate(&message, 0, System.Length(&message));
//
// if (not sgr.VerifySignature(sigBytes)) then
// begin
// Fail(name + ' verification failed');
// end;
//
// end;

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
  for name in TSecNamedCurves.Names do
  begin
    doTestECDsa(name);
  end;

  // for name in TECGost3410NamedCurves.Names do
  // begin
  // doTestECGost(name);
  // end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestNamedCurve);
{$ELSE}
  RegisterTest(TTestNamedCurve.Suite);
{$ENDIF FPC}

end.
