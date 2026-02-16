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

unit ClpCipherExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpParameterUtilities,
  ClpParametersWithIV,
  ClpConverters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpICipherParameters,
  ClpExampleBase;

type
  TCipherExample = class(TExampleBase)
  private
    function GetKeyAlgorithmName(const ACipherAlgorithm: string): string;
    procedure RunCipherEncryptDecrypt(const ACipherAlgorithm: string;
      const AParams: ICipherParameters);
    procedure RunAesEncryptDecrypt(const ACipherAlgorithm: string;
      AKeySizeBytes: Int32);
  public
    procedure Run; override;
  end;

implementation

function TCipherExample.GetKeyAlgorithmName(const ACipherAlgorithm: string): string;
var
  LSlash: Int32;
begin
  LSlash := Pos('/', ACipherAlgorithm);
  if LSlash > 0 then
    Result := Copy(ACipherAlgorithm, 1, LSlash - 1)
  else
    Result := ACipherAlgorithm;
end;

procedure TCipherExample.RunCipherEncryptDecrypt(const ACipherAlgorithm: string;
  const AParams: ICipherParameters);
var
  LCipher: IBufferedCipher;
  LPlain, LCipherText, LDecrypted: TBytes;
  LBlockSize, LOutOff, LCount: Int32;
begin
  Logger.LogInformation('Cipher: ' + ACipherAlgorithm);
  LCipher := TCipherUtilities.GetCipher(ACipherAlgorithm);
  if LCipher = nil then
  begin
    Logger.LogWarning('Cipher "' + ACipherAlgorithm + '" not available.');
    Exit;
  end;
  LPlain := TConverters.ConvertStringToBytes('Secret message', TEncoding.UTF8);

  LCipher.Init(True, AParams);
  LBlockSize := LCipher.GetBlockSize();
  System.SetLength(LCipherText, System.Length(LPlain) + LBlockSize);
  LOutOff := 0;
  LCount := LCipher.ProcessBytes(LPlain, 0, System.Length(LPlain), LCipherText, LOutOff);
  System.Inc(LOutOff, LCount);
  LCount := LCipher.DoFinal(LCipherText, LOutOff);
  System.Inc(LOutOff, LCount);
  System.SetLength(LCipherText, LOutOff);
  Logger.LogInformation(Format('%s encrypted length: %d', [ACipherAlgorithm, System.Length(LCipherText)]));

  LCipher.Init(False, AParams);
  System.SetLength(LDecrypted, System.Length(LCipherText));
  LOutOff := 0;
  LCount := LCipher.ProcessBytes(LCipherText, 0, System.Length(LCipherText), LDecrypted, LOutOff);
  System.Inc(LOutOff, LCount);
  LCount := LCipher.DoFinal(LDecrypted, LOutOff);
  System.Inc(LOutOff, LCount);
  System.SetLength(LDecrypted, LOutOff);
  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation(ACipherAlgorithm + ' decrypt match: success.')
  else
    Logger.LogWarning(ACipherAlgorithm + ' decrypt match: failed.');
end;

function GetAesKeySizeLabel(AKeySizeBytes: Int32): string;
begin
  case AKeySizeBytes of
    16: Result := 'AES-128';
    24: Result := 'AES-192';
    32: Result := 'AES-256';
  else
    raise EArgumentException.Create(Format('Invalid AES key size: %d bytes. Valid sizes are 16, 24, 32.', [AKeySizeBytes]));
  end;
end;

procedure TCipherExample.RunAesEncryptDecrypt(const ACipherAlgorithm: string;
  AKeySizeBytes: Int32);
var
  LKey, LIV: TBytes;
  LSecureRandom: ISecureRandom;
  LParams: ICipherParameters;
  LKeyAlg: string;
begin
  Logger.LogInformation(Format('%s %s (%d-byte key)', [GetAesKeySizeLabel(AKeySizeBytes), ACipherAlgorithm, AKeySizeBytes]));
  LSecureRandom := TSecureRandom.Create();
  System.SetLength(LKey, AKeySizeBytes);
  System.SetLength(LIV, 16);
  LSecureRandom.NextBytes(LKey);
  LSecureRandom.NextBytes(LIV);
  LKeyAlg := GetKeyAlgorithmName(ACipherAlgorithm);
  LParams := TParametersWithIV.Create(TParameterUtilities.CreateKeyParameter(LKeyAlg, LKey), LIV) as ICipherParameters;
  RunCipherEncryptDecrypt(ACipherAlgorithm, LParams);
end;

procedure TCipherExample.Run;
begin
  Logger.LogInformation('--- Cipher example: encrypt/decrypt ---');
  RunAesEncryptDecrypt('AES/CBC/PKCS7PADDING', 16);
  RunAesEncryptDecrypt('AES/CBC/PKCS7PADDING', 24);
  RunAesEncryptDecrypt('AES/CBC/PKCS7PADDING', 32);
end;

end.
