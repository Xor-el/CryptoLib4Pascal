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
  ClpISecureRandom,
  ClpConverters,
  ExampleBase,
  PqcExampleUtilities,
  KeyEncodingExampleUtilities,
  SecureRandomExampleUtilities;

type
  TMlDsaExample = class(TExampleBase)
  private
    procedure RunSignVerify(const AParameterSetName, ASignatureAlgorithm, AMessageText: string;
      const AKeyGenRandom: ISecureRandom = nil;
      const ASigningRandom: ISecureRandom = nil;
      ADeterministic: Boolean = False);
    procedure RunContextSignVerify(const AParameterSetName, ASignatureAlgorithm: string;
      const AKeyGenRandom: ISecureRandom = nil;
      const ASigningRandom: ISecureRandom = nil);
    procedure RunDerRoundtrip(const AParameterSetName: string;
      const AKeyGenRandom: ISecureRandom = nil);
    procedure RunPemRoundtrip(const AParameterSetName: string;
      const AKeyGenRandom: ISecureRandom = nil);
    procedure RunParameterSetDemos(const AParameterSetName, AMessageText: string;
      const AKeyGenRandom: ISecureRandom = nil;
      const ASigningRandom: ISecureRandom = nil);
    procedure RunSp80090ADemo(const AParameterSetName, AMessageText: string);
  public
    procedure Run; override;
  end;

implementation

procedure TMlDsaExample.RunSignVerify(const AParameterSetName, ASignatureAlgorithm,
  AMessageText: string; const AKeyGenRandom, ASigningRandom: ISecureRandom;
  ADeterministic: Boolean);
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg: TBytes;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName, AKeyGenRandom);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  LMsg := TConverters.ConvertStringToBytes(AMessageText, TEncoding.UTF8);
  TPqcExampleUtilities.RunSignVerify(ASignatureAlgorithm, LKp, LMsg, ASigningRandom,
    ADeterministic);
end;

procedure TMlDsaExample.RunContextSignVerify(const AParameterSetName,
  ASignatureAlgorithm: string; const AKeyGenRandom, ASigningRandom: ISecureRandom);
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg, LContext: TBytes;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName, AKeyGenRandom);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  LMsg := TConverters.ConvertStringToBytes('PascalMlDsaCtx', TEncoding.UTF8);
  LContext := TConverters.ConvertStringToBytes('CryptoLib4Pascal-ctx', TEncoding.UTF8);
  TPqcExampleUtilities.RunContextSignVerify(ASignatureAlgorithm, LKp, LMsg, LContext,
    ASigningRandom);
end;

procedure TMlDsaExample.RunDerRoundtrip(const AParameterSetName: string;
  const AKeyGenRandom: ISecureRandom);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName, AKeyGenRandom);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyDerRoundtrip(LKp, AParameterSetName);
end;

procedure TMlDsaExample.RunPemRoundtrip(const AParameterSetName: string;
  const AKeyGenRandom: ISecureRandom);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName, AKeyGenRandom);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyPemRoundtrip(LKp, AParameterSetName);
end;

procedure TMlDsaExample.RunParameterSetDemos(const AParameterSetName, AMessageText: string;
  const AKeyGenRandom, ASigningRandom: ISecureRandom);
begin
  LogWithLineBreak(Format('--- ML-DSA example: pure sign/verify (%s) ---', [AParameterSetName]));
  if ASigningRandom <> nil then
    Logger.LogInformation('Hedged signing with a dedicated CTR_DRBG instance.', []);
  RunSignVerify(AParameterSetName, AParameterSetName, AMessageText, AKeyGenRandom,
    ASigningRandom, False);

  LogWithLineBreak(Format('--- ML-DSA example: context sign/verify (%s) ---', [AParameterSetName]));
  RunContextSignVerify(AParameterSetName, AParameterSetName, AKeyGenRandom, ASigningRandom);

  LogWithLineBreak(Format('--- ML-DSA example: DER round-trip (%s) ---', [AParameterSetName]));
  RunDerRoundtrip(AParameterSetName, AKeyGenRandom);

  LogWithLineBreak(Format('--- ML-DSA example: PEM round-trip (%s) ---', [AParameterSetName]));
  RunPemRoundtrip(AParameterSetName, AKeyGenRandom);

  LogWithLineBreak(Format('--- ML-DSA example: deterministic sign/verify (%s) ---',
    [AParameterSetName]));
  Logger.LogInformation('Deterministic signing variant (FIPS 204 section 5.2).', []);
  RunSignVerify(AParameterSetName, AParameterSetName, AMessageText, AKeyGenRandom, nil, True);
end;

procedure TMlDsaExample.RunSp80090ADemo(const AParameterSetName, AMessageText: string);
var
  LKeyGenRandom, LSigningRandom: ISecureRandom;
begin
  LKeyGenRandom := TSecureRandomExampleUtilities.CreateCtrDrbgSecureRandom(
    TSecureRandomExampleUtilities.DemoBuildUniqueNonce('mldsa-keygen'));
  LSigningRandom := TSecureRandomExampleUtilities.CreateCtrDrbgSecureRandom(
    TSecureRandomExampleUtilities.DemoBuildUniqueNonce('mldsa-sign'));

  LogWithLineBreak(Format('--- ML-DSA example: SP 800-90A DRBG (%s) ---', [AParameterSetName]));
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  Logger.LogInformation('Key generation uses a dedicated CTR_DRBG instance.', []);

  RunParameterSetDemos(AParameterSetName, AMessageText, LKeyGenRandom, LSigningRandom);
end;

procedure TMlDsaExample.Run;
begin
  RunParameterSetDemos('ML-DSA-65', 'PascalMlDsa65');
  RunParameterSetDemos('ML-DSA-44-WITH-SHA512', 'PascalHashMlDsa44');
  RunSp80090ADemo('ML-DSA-65', 'Hello from ML-DSA!');
end;

end.
