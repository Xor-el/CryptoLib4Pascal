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

unit RsaExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  ClpConverters,
  ClpIAsymmetricCipherKeyPair,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpArrayUtilities,
  ClpEncoders,
  ExampleBase,
  AsymmetricExampleUtilities,
  HybridEncryption;

type
  TRsaExample = class(TExampleBase)
  private
    procedure DoRsaEncryptDecrypt(const ACipherAlgorithm: string;
      const AKeyPair: IAsymmetricCipherKeyPair);
    procedure DoRsaHybridRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
      const APlainText, AAadContext: string);
    procedure DoRsaHybridStreamRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
      const APlainText, AAadContext: string);
    procedure RunRsaEncryptDecrypt;
    procedure RunRsaDemos;
  public
    procedure Run; override;
  end;

implementation

procedure TRsaExample.DoRsaEncryptDecrypt(const ACipherAlgorithm: string;
  const AKeyPair: IAsymmetricCipherKeyPair);
var
  LCipher: IBufferedCipher;
  LPlain, LCipherText, LDecrypted: TBytes;
begin
  Logger.LogInformation('Cipher: {0}', [ACipherAlgorithm]);
  LCipher := TCipherUtilities.GetCipher(ACipherAlgorithm);
  if LCipher = nil then
  begin
    Logger.LogWarning('Cipher "{0}" not available.', [ACipherAlgorithm]);
    Exit;
  end;
  LPlain := TConverters.ConvertStringToBytes('Hello RSA encryption!', TEncoding.UTF8);

  LCipher.Init(True, AKeyPair.Public);
  LCipherText := LCipher.DoFinal(LPlain);
  Logger.LogInformation('Encrypted ({0} bytes):{1}{2}', [IntToStr(System.Length(LCipherText)), sLineBreak, THexEncoder.Encode(LCipherText, False)]);

  LCipher.Init(False, AKeyPair.Private);
  LDecrypted := LCipher.DoFinal(LCipherText);

  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('Decrypt roundtrip: success.', [])
  else
    Logger.LogError('Decrypt roundtrip: failed.', []);
end;

procedure TRsaExample.DoRsaHybridRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
  const APlainText, AAadContext: string);
var
  LPlain, LAad, LEnvelope, LDecrypted: TBytes;
begin
  LPlain := TConverters.ConvertStringToBytes(APlainText, TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes(AAadContext, TEncoding.UTF8);
  LEnvelope := TRsaHybridEncryption.Encrypt(AKeyPair.Public, LPlain, LAad);
  Logger.LogInformation('RSA hybrid envelope: {0} bytes', [IntToStr(System.Length(LEnvelope))]);
  LDecrypted := TRsaHybridEncryption.Decrypt(AKeyPair.Private, LEnvelope, LAad);
  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('RSA hybrid encrypt/decrypt roundtrip: success.', [])
  else
    Logger.LogError('RSA hybrid encrypt/decrypt roundtrip: failed.', []);
end;

procedure TRsaExample.DoRsaHybridStreamRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
  const APlainText, AAadContext: string);
var
  LPlainStream, LEncStream, LDecStream: TBytesStream;
  LPlain, LAad, LDecrypted: TBytes;
begin
  LPlain := TConverters.ConvertStringToBytes(APlainText, TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes(AAadContext, TEncoding.UTF8);
  LPlainStream := TBytesStream.Create(LPlain);
  try
    LEncStream := TBytesStream.Create(nil);
    try
      TRsaHybridEncryption.Encrypt(AKeyPair.Public, LPlainStream, LEncStream, LAad);
      Logger.LogInformation('RSA hybrid stream envelope: {0} bytes', [IntToStr(LEncStream.Size)]);
      LEncStream.Position := 0;
      LDecStream := TBytesStream.Create(nil);
      try
        TRsaHybridEncryption.Decrypt(AKeyPair.Private, LEncStream, LDecStream, LAad);
        LDecrypted := Copy(LDecStream.Bytes, 0, LDecStream.Size);
        if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
          Logger.LogInformation('RSA hybrid stream roundtrip: success.', [])
        else
          Logger.LogError('RSA hybrid stream roundtrip: failed.', []);
      finally
        LDecStream.Free;
      end;
    finally
      LEncStream.Free;
    end;
  finally
    LPlainStream.Free;
  end;
end;

procedure TRsaExample.RunRsaEncryptDecrypt;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('RSA');
  DoRsaEncryptDecrypt('RSA/NONE/PKCS1PADDING', LKp);
  DoRsaEncryptDecrypt('RSA/NONE/OAEPPADDING', LKp);
  DoRsaEncryptDecrypt('RSA/NONE/OAEPWITHSHA-256ANDMGF1PADDING', LKp);
end;

procedure TRsaExample.RunRsaDemos;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LogWithLineBreak('--- RSA example: Sign and verify ---');
  TAsymmetricExampleUtilities.RunSignVerify('RSA', 'SHA-256withRSA', 'Message to sign');
  TAsymmetricExampleUtilities.RunSignVerify('RSA', 'SHA256WITHRSAANDMGF1', 'Message to sign');

  LogWithLineBreak('--- RSA example: Key recreate from DER bytes ---');
  TAsymmetricExampleUtilities.RunDerRoundtrip('RSA', 'RSA');

  LogWithLineBreak('--- RSA example: PEM export/import ---');
  TAsymmetricExampleUtilities.RunPemRoundtrip('RSA', 'RSA');

  LogWithLineBreak('--- RSA example: Encrypt/decrypt ---');
  RunRsaEncryptDecrypt;

  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('RSA-3072');
  Logger.LogInformation('Key spec: {0}', ['RSA-3072']);

  LogWithLineBreak('--- RSA example: Hybrid encrypt/decrypt (RSA-OAEP + AES-256-GCM) ---');
  DoRsaHybridRoundtrip(LKp, 'Hello RSA Hybrid Encryption!', 'RH01-example-context');

  LogWithLineBreak('--- RSA example: Hybrid stream encrypt/decrypt ---');
  DoRsaHybridStreamRoundtrip(LKp, 'Hello RSA Hybrid Stream!', 'RH01-stream-context');
end;

procedure TRsaExample.Run;
begin
  RunRsaDemos;
end;

end.
