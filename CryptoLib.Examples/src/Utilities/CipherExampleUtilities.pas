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

unit CipherExampleUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Math,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpParameterUtilities,
  ClpParametersWithIV,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpICipherParameters;

type
  TCipherExampleUtilities = class sealed
  strict private
    class function GetKeyAlgorithmName(const ACipherAlgorithm: string): string; static;
    class function ProcessIncrementally(const ACipher: IBufferedCipher;
      const AInput: TBytes): TBytes; static;
  public
    class function EncryptDecryptRoundtripMatches(const ACipherAlgorithm: string;
      const AParams: ICipherParameters; const APlain: TBytes;
      out ACipherTextLen: Int32): Boolean; static;
    class function AesEncryptDecryptRoundtripMatches(const ACipherAlgorithm: string;
      AKeySizeBytes: Int32; const APlain: TBytes; out ACipherTextLen: Int32): Boolean; static;
  end;

implementation

class function TCipherExampleUtilities.GetKeyAlgorithmName(const ACipherAlgorithm: string): string;
var
  LSlash: Int32;
begin
  LSlash := Pos('/', ACipherAlgorithm);
  if LSlash > 0 then
    Result := Copy(ACipherAlgorithm, 1, LSlash - 1)
  else
    Result := ACipherAlgorithm;
end;

class function TCipherExampleUtilities.ProcessIncrementally(const ACipher: IBufferedCipher;
  const AInput: TBytes): TBytes;
const
  BufferSize = 1024;
var
  LInOff, LOutOff, LChunk, LCount, LInputLen: Int32;
begin
  LInputLen := System.Length(AInput);
  System.SetLength(Result, ACipher.GetOutputSize(LInputLen));
  LInOff := 0;
  LOutOff := 0;
  while LInOff < LInputLen do
  begin
    LChunk := Min(BufferSize, LInputLen - LInOff);
    LCount := ACipher.ProcessBytes(AInput, LInOff, LChunk, Result, LOutOff);
    System.Inc(LOutOff, LCount);
    System.Inc(LInOff, LChunk);
  end;
  LCount := ACipher.DoFinal(Result, LOutOff);
  System.Inc(LOutOff, LCount);
  System.SetLength(Result, LOutOff);
end;

class function TCipherExampleUtilities.EncryptDecryptRoundtripMatches(
  const ACipherAlgorithm: string; const AParams: ICipherParameters; const APlain: TBytes;
  out ACipherTextLen: Int32): Boolean;
var
  LCipher: IBufferedCipher;
  LCipherText, LDecrypted: TBytes;
begin
  ACipherTextLen := 0;
  Result := False;
  LCipher := TCipherUtilities.GetCipher(ACipherAlgorithm);
  if LCipher = nil then
    Exit;

  LCipher.Init(True, AParams);
  LCipherText := ProcessIncrementally(LCipher, APlain);
  ACipherTextLen := System.Length(LCipherText);

  LCipher.Init(False, AParams);
  LDecrypted := ProcessIncrementally(LCipher, LCipherText);
  Result := TArrayUtilities.AreEqual(APlain, LDecrypted);
end;

class function TCipherExampleUtilities.AesEncryptDecryptRoundtripMatches(
  const ACipherAlgorithm: string; AKeySizeBytes: Int32; const APlain: TBytes;
  out ACipherTextLen: Int32): Boolean;
var
  LKey, LIV: TBytes;
  LSecureRandom: ISecureRandom;
  LParams: ICipherParameters;
  LKeyAlg: string;
begin
  ACipherTextLen := 0;
  Result := False;
  if not (AKeySizeBytes in [16, 24, 32]) then
    raise EArgumentException.Create(Format('Invalid AES key size: %d bytes. Valid sizes are 16, 24, 32.', [AKeySizeBytes]));

  LSecureRandom := TSecureRandom.Create();
  System.SetLength(LKey, AKeySizeBytes);
  System.SetLength(LIV, 16);
  LSecureRandom.NextBytes(LKey);
  LSecureRandom.NextBytes(LIV);
  LKeyAlg := GetKeyAlgorithmName(ACipherAlgorithm);
  LParams := TParametersWithIV.Create(TParameterUtilities.CreateKeyParameter(LKeyAlg, LKey), LIV) as ICipherParameters;
  Result := EncryptDecryptRoundtripMatches(ACipherAlgorithm, LParams, APlain, ACipherTextLen);
end;

end.
