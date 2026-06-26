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

unit SecureRandomExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpConverters,
  ClpEncoders,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ExampleBase,
  ExampleLogger,
  SecureRandomExampleUtilities;

type
  TSecureRandomExample = class(TExampleBase)
  strict private
    class procedure RunDrbgDemo(const ATitle: string; const ARandom: ISecureRandom); static;
    procedure RunSp80090ADemos;
  public
    procedure Run; override;
  end;

implementation

{ TSecureRandomExample }

class procedure TSecureRandomExample.RunDrbgDemo(const ATitle: string;
  const ARandom: ISecureRandom);
var
  LFirst, LSecond: TCryptoLibByteArray;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LLogger.LogInformation('--- {0} ---', [ATitle]);
  System.SetLength(LFirst, 32);
  System.SetLength(LSecond, 32);
  ARandom.NextBytes(LFirst);
  ARandom.NextBytes(LSecond);
  LLogger.LogInformation('Sample 1:{0}{1}', [sLineBreak, THexEncoder.Encode(LFirst, False)]);
  LLogger.LogInformation('Sample 2:{0}{1}', [sLineBreak, THexEncoder.Encode(LSecond, False)]);
  if not TArrayUtilities.AreEqual(LFirst, LSecond) then
    LLogger.LogInformation('Smoke check: consecutive outputs differ.', [])
  else
    LLogger.LogWarning('Smoke check: consecutive outputs were identical.', []);
end;

procedure TSecureRandomExample.RunSp80090ADemos;
var
  LLabelNonce, LRandomNonce: TCryptoLibByteArray;
  LOsEntropy: ISecureRandom;
begin
  LogWithLineBreak('--- SecureRandom example: SP 800-90A DRBG (caller-supplied nonce) ---');

  LLabelNonce := TConverters.ConvertStringToBytes(
    'CryptoLibExamples::SessionKeyGen::v1', TEncoding.UTF8);

  LOsEntropy := TSecureRandomExampleUtilities.CreateOsEntropySource;
  System.SetLength(LRandomNonce, 32);
  LOsEntropy.NextBytes(LRandomNonce);

  LogWithLineBreak('Nonce pattern 1: stable application label (UTF-8 bytes)');
  RunDrbgDemo('Hash_DRBG (SHA-256)',
    TSecureRandomExampleUtilities.CreateHashDrbgSecureRandom(LLabelNonce));
  RunDrbgDemo('HMAC_DRBG (HMAC-SHA-256)',
    TSecureRandomExampleUtilities.CreateHMacDrbgSecureRandom(LLabelNonce));
  RunDrbgDemo('CTR_DRBG (AES-256)',
    TSecureRandomExampleUtilities.CreateCtrDrbgSecureRandom(LLabelNonce));

  LogWithLineBreak('Nonce pattern 2: demo nonce helper and OS CSPRNG random bytes');
  RunDrbgDemo('Hash_DRBG with demo nonce helper',
    TSecureRandomExampleUtilities.CreateHashDrbgSecureRandom(
      TSecureRandomExampleUtilities.DemoBuildUniqueNonce('HashDrbg')));
  RunDrbgDemo('HMAC_DRBG with demo nonce helper',
    TSecureRandomExampleUtilities.CreateHMacDrbgSecureRandom(
      TSecureRandomExampleUtilities.DemoBuildUniqueNonce('HMacDrbg')));
  RunDrbgDemo('CTR_DRBG with random nonce bytes',
    TSecureRandomExampleUtilities.CreateCtrDrbgSecureRandom(LRandomNonce));
end;

procedure TSecureRandomExample.Run;
begin
  RunSp80090ADemos;
end;

end.
