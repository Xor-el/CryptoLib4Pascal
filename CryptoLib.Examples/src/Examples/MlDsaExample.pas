{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit MlDsaExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIAsymmetricCipherKeyPair,
  ClpConverters,
  ExampleBase,
  PqcExampleUtilities,
  KeyEncodingExampleUtilities;

type
  TMlDsaExample = class(TExampleBase)
  private
    procedure RunSignVerify(const AParameterSetName, ASignatureAlgorithm, AMessageText: string);
    procedure RunContextSignVerify(const AParameterSetName, ASignatureAlgorithm: string);
    procedure RunDerRoundtrip(const AParameterSetName: string);
    procedure RunPemRoundtrip(const AParameterSetName: string);
    procedure RunParameterSetDemos(const AParameterSetName, AMessageText: string);
  public
    procedure Run; override;
  end;

implementation

procedure TMlDsaExample.RunSignVerify(const AParameterSetName, ASignatureAlgorithm, AMessageText: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg: TBytes;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  LMsg := TConverters.ConvertStringToBytes(AMessageText, TEncoding.UTF8);
  TPqcExampleUtilities.RunSignVerify(ASignatureAlgorithm, LKp, LMsg);
end;

procedure TMlDsaExample.RunContextSignVerify(const AParameterSetName, ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg, LContext: TBytes;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  LMsg := TConverters.ConvertStringToBytes('PascalMlDsaCtx', TEncoding.UTF8);
  LContext := TConverters.ConvertStringToBytes('CryptoLib4Pascal-ctx', TEncoding.UTF8);
  TPqcExampleUtilities.RunContextSignVerify(ASignatureAlgorithm, LKp, LMsg, LContext);
end;

procedure TMlDsaExample.RunDerRoundtrip(const AParameterSetName: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyDerRoundtrip(LKp, AParameterSetName);
end;

procedure TMlDsaExample.RunPemRoundtrip(const AParameterSetName: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyPemRoundtrip(LKp, AParameterSetName);
end;

procedure TMlDsaExample.RunParameterSetDemos(const AParameterSetName, AMessageText: string);
begin
  LogWithLineBreak(Format('--- ML-DSA example: pure sign/verify (%s) ---', [AParameterSetName]));
  RunSignVerify(AParameterSetName, AParameterSetName, AMessageText);

  LogWithLineBreak(Format('--- ML-DSA example: context sign/verify (%s) ---', [AParameterSetName]));
  RunContextSignVerify(AParameterSetName, AParameterSetName);

  LogWithLineBreak(Format('--- ML-DSA example: DER round-trip (%s) ---', [AParameterSetName]));
  RunDerRoundtrip(AParameterSetName);

  LogWithLineBreak(Format('--- ML-DSA example: PEM round-trip (%s) ---', [AParameterSetName]));
  RunPemRoundtrip(AParameterSetName);
end;

procedure TMlDsaExample.Run;
begin
  RunParameterSetDemos('ML-DSA-65', 'PascalMlDsa65');
  RunParameterSetDemos('ML-DSA-44-WITH-SHA512', 'PascalHashMlDsa44');
end;

end.
