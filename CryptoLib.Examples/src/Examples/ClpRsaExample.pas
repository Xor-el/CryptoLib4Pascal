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
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  ClpSignerUtilities,
  ClpEncoders,
  ClpConverters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpISigner,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpArrayUtilities,
  ClpPrivateKeyInfoFactory,
  ClpPrivateKeyFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpPublicKeyFactory,
  ClpHybridEncryption,
  ClpExampleBase;

type
  TRsaExample = class(TExampleBase)
  private
    procedure RunRsaSignVerify(const ASignatureAlgorithm: string);
    procedure RunRsaKeyRecreateFromDEREncodedBytes;
    procedure RunRsaPemExportImport;
    procedure DoRsaEncryptDecrypt(const ACipherAlgorithm: string;
      const AKeyPair: IAsymmetricCipherKeyPair);
    procedure RunRsaEncryptDecrypt;
    procedure RunRsaHybridEncryptDecrypt;
    procedure RunRsaHybridStreamEncryptDecrypt;
  public
    procedure Run; override;
  end;

implementation

procedure TRsaExample.RunRsaSignVerify(const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LMsg, LSig: TBytes;
begin
  Logger.LogInformation('Algorithm: ' + ASignatureAlgorithm);
  LKp := GenerateRsaKeyPair;
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
  Logger.LogInformation(ASignatureAlgorithm + ' signature (hex):' + sLineBreak +
    THexEncoder.Encode(LSig, False));
  LSigner.Init(False, LKp.Public);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  if LSigner.VerifySignature(LSig) then
    Logger.LogInformation(ASignatureAlgorithm + ' verification passed.')
  else
    Logger.LogWarning(ASignatureAlgorithm + ' verification failed.');
end;

procedure TRsaExample.RunRsaKeyRecreateFromDEREncodedBytes;
var
  LKp: IAsymmetricCipherKeyPair;
  LPrivBytes, LPubBytes: TBytes;
  LRegenPriv, LRegenPub: IAsymmetricKeyParameter;
begin
  LKp := GenerateRsaKeyPair;

  LPrivBytes := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LKp.Private).GetEncoded();
  Logger.LogInformation(Format('Private key DER encoded: %d bytes', [System.Length(LPrivBytes)]));

  LPubBytes := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public).GetEncoded();
  Logger.LogInformation(Format('Public key DER encoded: %d bytes', [System.Length(LPubBytes)]));

  LRegenPriv := TPrivateKeyFactory.CreateKey(LPrivBytes);
  if LRegenPriv.Equals(LKp.Private) then
    Logger.LogInformation('Private key roundtrip: match.')
  else
    Logger.LogWarning('Private key roundtrip: mismatch.');

  LRegenPub := TPublicKeyFactory.CreateKey(LPubBytes);
  if LRegenPub.Equals(LKp.Public) then
    Logger.LogInformation('Public key roundtrip: match.')
  else
    Logger.LogWarning('Public key roundtrip: mismatch.');
end;

procedure TRsaExample.RunRsaPemExportImport;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := GenerateRsaKeyPair;
  VerifyPemRoundtrip(LKp, 'RSA');
end;

procedure TRsaExample.DoRsaEncryptDecrypt(const ACipherAlgorithm: string;
  const AKeyPair: IAsymmetricCipherKeyPair);
var
  LCipher: IBufferedCipher;
  LPlain, LCipherText, LDecrypted: TBytes;
begin
  Logger.LogInformation('Cipher: ' + ACipherAlgorithm);
  LCipher := TCipherUtilities.GetCipher(ACipherAlgorithm);
  if LCipher = nil then
  begin
    Logger.LogWarning('Cipher "' + ACipherAlgorithm + '" not available.');
    Exit;
  end;
  LPlain := TConverters.ConvertStringToBytes('Hello RSA encryption!', TEncoding.UTF8);

  LCipher.Init(True, AKeyPair.Public);
  LCipherText := LCipher.DoFinal(LPlain);
  Logger.LogInformation(Format('Encrypted (%d bytes):' + sLineBreak + '%s',
    [System.Length(LCipherText), THexEncoder.Encode(LCipherText, False)]));

  LCipher.Init(False, AKeyPair.Private);
  LDecrypted := LCipher.DoFinal(LCipherText);

  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('Decrypt roundtrip: success.')
  else
    Logger.LogWarning('Decrypt roundtrip: failed.');
end;

procedure TRsaExample.RunRsaEncryptDecrypt;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := GenerateRsaKeyPair;
  DoRsaEncryptDecrypt('RSA/NONE/PKCS1PADDING', LKp);
  DoRsaEncryptDecrypt('RSA/NONE/OAEPPADDING', LKp);
  DoRsaEncryptDecrypt('RSA/NONE/OAEPWITHSHA-256ANDMGF1PADDING', LKp);
end;

procedure TRsaExample.RunRsaHybridEncryptDecrypt;
var
  LKp: IAsymmetricCipherKeyPair;
  LPlain, LAad, LEnvelope, LDecrypted: TBytes;
begin
  LKp := GenerateRsaKeyPair(3072);
  LPlain := TConverters.ConvertStringToBytes('Hello RSA Hybrid Encryption!', TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes('RH01-example-context', TEncoding.UTF8);

  LEnvelope := TRsaHybridEncryption.Encrypt(LKp.Public, LPlain, LAad);
  Logger.LogInformation(Format('RSA hybrid envelope: %d bytes', [System.Length(LEnvelope)]));

  LDecrypted := TRsaHybridEncryption.Decrypt(LKp.Private, LEnvelope, LAad);
  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('RSA hybrid encrypt/decrypt roundtrip: success.')
  else
    Logger.LogWarning('RSA hybrid encrypt/decrypt roundtrip: failed.');
end;

procedure TRsaExample.RunRsaHybridStreamEncryptDecrypt;
var
  LKp: IAsymmetricCipherKeyPair;
  LPlainStream, LEncStream, LDecStream: TBytesStream;
  LPlain, LAad, LDecrypted: TBytes;
begin
  LKp := GenerateRsaKeyPair(3072);
  LPlain := TConverters.ConvertStringToBytes('Hello RSA Hybrid Stream!', TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes('RH01-stream-context', TEncoding.UTF8);

  LPlainStream := TBytesStream.Create(LPlain);
  try
    LEncStream := TBytesStream.Create(nil);
    try
      TRsaHybridEncryption.Encrypt(LKp.Public, LPlainStream, LEncStream, LAad);
      Logger.LogInformation(Format('RSA hybrid stream envelope: %d bytes', [LEncStream.Size]));

      LEncStream.Position := 0;
      LDecStream := TBytesStream.Create(nil);
      try
        TRsaHybridEncryption.Decrypt(LKp.Private, LEncStream, LDecStream, LAad);
        LDecrypted := Copy(LDecStream.Bytes, 0, LDecStream.Size);
        if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
          Logger.LogInformation('RSA hybrid stream roundtrip: success.')
        else
          Logger.LogWarning('RSA hybrid stream roundtrip: failed.');
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

procedure TRsaExample.Run;
begin
  LogWithLineBreak('--- RSA example: Sign and verify ---');
  RunRsaSignVerify('SHA-256withRSA');
  RunRsaSignVerify('SHA256WITHRSAANDMGF1');

  LogWithLineBreak('--- RSA example: Key recreate from DER bytes ---');
  RunRsaKeyRecreateFromDEREncodedBytes;

  LogWithLineBreak('--- RSA example: PEM export/import ---');
  RunRsaPemExportImport;

  LogWithLineBreak('--- RSA example: Encrypt/decrypt ---');
  RunRsaEncryptDecrypt;

  LogWithLineBreak('--- RSA example: Hybrid encrypt/decrypt (RSA-OAEP + AES-256-GCM) ---');
  RunRsaHybridEncryptDecrypt;

  LogWithLineBreak('--- RSA example: Hybrid stream encrypt/decrypt ---');
  RunRsaHybridStreamEncryptDecrypt;
end;

end.
