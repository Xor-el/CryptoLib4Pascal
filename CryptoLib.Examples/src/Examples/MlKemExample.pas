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

unit MlKemExample;

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
  ExampleBase,
  PqcExampleUtilities,
  KeyEncodingExampleUtilities,
  SecureRandomExampleUtilities;

type
  TMlKemExample = class(TExampleBase)
  private
    procedure RunKemRoundtrip(const AParameterSetName: string;
      const AKeyGenRandom: ISecureRandom = nil;
      const AEncapsRandom: ISecureRandom = nil);
    procedure RunDerRoundtrip(const AParameterSetName: string;
      const AKeyGenRandom: ISecureRandom = nil);
    procedure RunPemRoundtrip(const AParameterSetName: string;
      const AKeyGenRandom: ISecureRandom = nil);
    procedure RunParameterSetDemos(const AParameterSetName: string;
      const AKeyGenRandom: ISecureRandom = nil;
      const AEncapsRandom: ISecureRandom = nil);
    procedure RunSp80090ADemo(const AParameterSetName: string);
  public
    procedure Run; override;
  end;

implementation

procedure TMlKemExample.RunKemRoundtrip(const AParameterSetName: string;
  const AKeyGenRandom, AEncapsRandom: ISecureRandom);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName, AKeyGenRandom);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TPqcExampleUtilities.RunKemRoundtrip(AParameterSetName, LKp, AEncapsRandom);
end;

procedure TMlKemExample.RunDerRoundtrip(const AParameterSetName: string;
  const AKeyGenRandom: ISecureRandom);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName, AKeyGenRandom);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyDerRoundtrip(LKp, AParameterSetName);
end;

procedure TMlKemExample.RunPemRoundtrip(const AParameterSetName: string;
  const AKeyGenRandom: ISecureRandom);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TPqcExampleUtilities.GenerateKeyPair(AParameterSetName, AKeyGenRandom);
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  TKeyEncodingExampleUtilities.VerifyPemRoundtrip(LKp, AParameterSetName);
end;

procedure TMlKemExample.RunParameterSetDemos(const AParameterSetName: string;
  const AKeyGenRandom, AEncapsRandom: ISecureRandom);
begin
  LogWithLineBreak(Format('--- ML-KEM example: encaps/decaps (%s) ---', [AParameterSetName]));
  RunKemRoundtrip(AParameterSetName, AKeyGenRandom, AEncapsRandom);

  LogWithLineBreak(Format('--- ML-KEM example: DER round-trip (%s) ---', [AParameterSetName]));
  RunDerRoundtrip(AParameterSetName, AKeyGenRandom);

  LogWithLineBreak(Format('--- ML-KEM example: PEM round-trip (%s) ---', [AParameterSetName]));
  RunPemRoundtrip(AParameterSetName, AKeyGenRandom);
end;

procedure TMlKemExample.RunSp80090ADemo(const AParameterSetName: string);
var
  LKeyGenRandom, LEncapsRandom: ISecureRandom;
begin
  LKeyGenRandom := TSecureRandomExampleUtilities.CreateHMacDrbgSecureRandom(
    TSecureRandomExampleUtilities.DemoBuildUniqueNonce('mlkem-keygen'));
  LEncapsRandom := TSecureRandomExampleUtilities.CreateHMacDrbgSecureRandom(
    TSecureRandomExampleUtilities.DemoBuildUniqueNonce('mlkem-encaps'));

  LogWithLineBreak(Format('--- ML-KEM example: SP 800-90A DRBG (%s) ---', [AParameterSetName]));
  Logger.LogInformation('Parameter set: {0}', [AParameterSetName]);
  Logger.LogInformation('Key generation uses a dedicated HMAC_DRBG instance.', []);

  RunParameterSetDemos(AParameterSetName, LKeyGenRandom, LEncapsRandom);
end;

procedure TMlKemExample.Run;
begin
  RunParameterSetDemos('ML-KEM-768');
  RunParameterSetDemos('ML-KEM-512');
  RunSp80090ADemo('ML-KEM-768');
end;

end.
