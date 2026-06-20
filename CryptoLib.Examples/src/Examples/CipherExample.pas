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

unit CipherExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpConverters,
  ExampleBase,
  CipherExampleUtilities;

type
  TCipherExample = class(TExampleBase)
  private
    procedure RunAesDemo(const ACipherAlgorithm: string; AKeySizeBytes: Int32;
      const APlain: TBytes);
    procedure RunCipherDemos;
  public
    procedure Run; override;
  end;

implementation

procedure TCipherExample.RunAesDemo(const ACipherAlgorithm: string; AKeySizeBytes: Int32;
  const APlain: TBytes);
var
  LCipherTextLen: Int32;
  LKeyLabel: string;
begin
  case AKeySizeBytes of
    16: LKeyLabel := 'AES-128';
    24: LKeyLabel := 'AES-192';
    32: LKeyLabel := 'AES-256';
  else
    LKeyLabel := Format('AES (%d-byte key)', [AKeySizeBytes]);
  end;
  Logger.LogInformation('Cipher: {0} {1} ({2}-byte key)', [LKeyLabel, ACipherAlgorithm, IntToStr(AKeySizeBytes)]);
  if TCipherExampleUtilities.AesEncryptDecryptRoundtripMatches(ACipherAlgorithm, AKeySizeBytes, APlain,
    LCipherTextLen) then
  begin
    Logger.LogInformation('{0} encrypted length: {1}', [ACipherAlgorithm, IntToStr(LCipherTextLen)]);
    Logger.LogInformation('{0} decrypt match: success.', [ACipherAlgorithm]);
  end
  else
    Logger.LogError('{0} encrypt/decrypt roundtrip failed.', [ACipherAlgorithm]);
end;

procedure TCipherExample.RunCipherDemos;
var
  LPlain: TBytes;
begin
  LPlain := TConverters.ConvertStringToBytes('Secret message', TEncoding.UTF8);
  LogWithLineBreak('--- Cipher example: encrypt/decrypt ---');
  RunAesDemo('AES/CBC/PKCS7PADDING', 16, LPlain);
  RunAesDemo('AES/CBC/PKCS7PADDING', 24, LPlain);
  RunAesDemo('AES/CBC/PKCS7PADDING', 32, LPlain);
end;

procedure TCipherExample.Run;
begin
  RunCipherDemos;
end;

end.
