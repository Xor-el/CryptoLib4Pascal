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

unit ClpRsaExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpGeneratorUtilities,
  ClpSecureRandom,
  ClpBigInteger,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpSignerUtilities,
  ClpEncoders,
  ClpConverters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpISecureRandom,
  ClpISigner,
  ClpExampleBase;

type
  TRsaExample = class(TExampleBase)
  private
    procedure RunRsaSignVerify(const ASignatureAlgorithm: string);
  public
    procedure Run; override;
  end;

implementation

procedure TRsaExample.RunRsaSignVerify(const ASignatureAlgorithm: string);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LMsg, LSig: TBytes;
begin
  Logger.LogInformation('Algorithm: ' + ASignatureAlgorithm);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(65537),
    TSecureRandom.Create() as ISecureRandom, 2048, 25) as IRsaKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LSigner := TSignerUtilities.GetSigner(ASignatureAlgorithm);
  if LSigner = nil then
  begin
    Logger.LogWarning('Signer "' + ASignatureAlgorithm + '" not available.');
    Exit;
  end;
  LMsg := TConverters.ConvertStringToBytes('Message to sign', TEncoding.UTF8);
  LSigner.Init(True, LKp.Private);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LSig := LSigner.GenerateSignature();
  Logger.LogInformation(ASignatureAlgorithm + ' signature (hex): ' + THexEncoder.Encode(LSig, False));
  LSigner.Init(False, LKp.Public);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  if LSigner.VerifySignature(LSig) then
    Logger.LogInformation(ASignatureAlgorithm + ' verification passed.')
  else
    Logger.LogWarning(ASignatureAlgorithm + ' verification failed.');
end;

procedure TRsaExample.Run;
begin
  Logger.LogInformation('--- RSA example: Sign and verify ---');
  RunRsaSignVerify('SHA-256withRSA');
  RunRsaSignVerify('SHA256WITHRSAANDMGF1');
end;

end.
