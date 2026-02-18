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

procedure TRsaExample.Run;
begin
  LogWithLineBreak('--- RSA example: Sign and verify ---');
  RunRsaSignVerify('SHA-256withRSA');
  RunRsaSignVerify('SHA256WITHRSAANDMGF1');

  LogWithLineBreak('--- RSA example: Key recreate from bytes ---');
  RunRsaKeyRecreateFromDEREncodedBytes;

  LogWithLineBreak('--- RSA example: PEM export/import ---');
  RunRsaPemExportImport;

  LogWithLineBreak('--- RSA example: Encrypt/decrypt ---');
  RunRsaEncryptDecrypt;
end;

end.
