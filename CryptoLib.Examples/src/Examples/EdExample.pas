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

unit EdExample;

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
  ClpArrayUtilities,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIEd25519Parameters,
  ClpIX25519Parameters,
  ClpIX25519Agreement,
  ClpX25519Agreement,
  ClpCurve25519KeyUtilities,
  HybridEncryption,
  ExampleBase,
  AsymmetricExampleUtilities,
  KeyEncodingExampleUtilities;

type
  TEdExample = class(TExampleBase)
  private
    procedure RunEd25519SignVerify;
    procedure RunEd25519CtxSignVerify;
    procedure RunEd25519PhSignVerify;
    procedure RunEd25519KeyRecreateFromDEREncodedBytes;
    procedure RunEd25519PemExportImport;
    procedure RunEd25519ToX25519KeyConversion;
    procedure RunX25519KeyAgreement;
    procedure RunX25519HybridEncryptDecrypt;
    procedure RunX25519HybridStreamEncryptDecrypt;
  public
    procedure Run; override;
  end;

implementation

procedure TEdExample.RunEd25519SignVerify;
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg: TBytes;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  LMsg := TConverters.ConvertStringToBytes('PascalEd25519', TEncoding.UTF8);
  TAsymmetricExampleUtilities.RunSignVerify('Ed25519', LKp, LMsg);
end;

procedure TEdExample.RunEd25519CtxSignVerify;
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg: TBytes;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  LMsg := TConverters.ConvertStringToBytes('PascalEd25519ctx', TEncoding.UTF8);
  TAsymmetricExampleUtilities.RunSignVerify('Ed25519ctx', LKp, LMsg);
end;

procedure TEdExample.RunEd25519PhSignVerify;
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg: TBytes;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  LMsg := TConverters.ConvertStringToBytes('PascalEd25519ph', TEncoding.UTF8);
  TAsymmetricExampleUtilities.RunSignVerify('Ed25519ph', LKp, LMsg);
end;

procedure TEdExample.RunEd25519KeyRecreateFromDEREncodedBytes;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  Logger.LogInformation('Key type: Ed25519', []);
  TKeyEncodingExampleUtilities.VerifyDerRoundtrip(LKp, 'Ed25519');
end;

procedure TEdExample.RunEd25519PemExportImport;
var
  LKp: IAsymmetricCipherKeyPair;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  Logger.LogInformation('Key type: Ed25519', []);
  TKeyEncodingExampleUtilities.VerifyPemRoundtrip(LKp, 'Ed25519');
end;

procedure TEdExample.RunEd25519ToX25519KeyConversion;
var
  LKp: IAsymmetricCipherKeyPair;
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX25519PubFromConversion, LX25519PubFromPriv: IX25519PublicKeyParameters;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  if not Supports(LKp.Private, IEd25519PrivateKeyParameters, LEdPriv) then
  begin
    Logger.LogError('Ed25519 private key type mismatch.', []);
    Exit;
  end;
  if not Supports(LKp.Public, IEd25519PublicKeyParameters, LEdPub) then
  begin
    Logger.LogError('Ed25519 public key type mismatch.', []);
    Exit;
  end;

  LX25519Priv := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPriv);
  LX25519PubFromConversion := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPub);
  LX25519PubFromPriv := LX25519Priv.GeneratePublicKey();

  Logger.LogInformation('Ed25519 public key (hex):{0}{1}', [sLineBreak, THexEncoder.Encode(LEdPub.GetEncoded(), False)]);
  Logger.LogInformation('X25519 public key from conversion (hex):{0}{1}', [sLineBreak, THexEncoder.Encode(LX25519PubFromConversion.GetEncoded(), False)]);
  Logger.LogInformation('X25519 public key from private (hex):{0}{1}', [sLineBreak, THexEncoder.Encode(LX25519PubFromPriv.GetEncoded(), False)]);

  if TArrayUtilities.AreEqual(LX25519PubFromConversion.GetEncoded(),
    LX25519PubFromPriv.GetEncoded()) then
    Logger.LogInformation('Ed25519 -> X25519 key conversion: consistent.', [])
  else
    Logger.LogError('Ed25519 -> X25519 key conversion: inconsistent.', []);
end;

procedure TEdExample.RunX25519KeyAgreement;
var
  LKpA, LKpB: IAsymmetricCipherKeyPair;
  LEdPrivA, LEdPrivB: IEd25519PrivateKeyParameters;
  LEdPubA, LEdPubB: IEd25519PublicKeyParameters;
  LX25519SkA, LX25519SkB: IX25519PrivateKeyParameters;
  LX25519PubA, LX25519PubB: IX25519PublicKeyParameters;
  LAgreeA, LAgreeB: IX25519Agreement;
  LSecretA, LSecretB: TBytes;
begin
  LKpA := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  LKpB := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');

  if not Supports(LKpA.Private, IEd25519PrivateKeyParameters, LEdPrivA) then
  begin
    Logger.LogError('Party A: Ed25519 private key type mismatch.', []);
    Exit;
  end;
  if not Supports(LKpA.Public, IEd25519PublicKeyParameters, LEdPubA) then
  begin
    Logger.LogError('Party A: Ed25519 public key type mismatch.', []);
    Exit;
  end;
  if not Supports(LKpB.Private, IEd25519PrivateKeyParameters, LEdPrivB) then
  begin
    Logger.LogError('Party B: Ed25519 private key type mismatch.', []);
    Exit;
  end;
  if not Supports(LKpB.Public, IEd25519PublicKeyParameters, LEdPubB) then
  begin
    Logger.LogError('Party B: Ed25519 public key type mismatch.', []);
    Exit;
  end;

  LX25519SkA := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPrivA);
  LX25519PubA := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPubA);
  LX25519SkB := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPrivB);
  LX25519PubB := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPubB);

  LAgreeA := TX25519Agreement.Create() as IX25519Agreement;
  LAgreeA.Init(LX25519SkA);
  System.SetLength(LSecretA, LAgreeA.AgreementSize);
  LAgreeA.CalculateAgreement(LX25519PubB, LSecretA, 0);

  LAgreeB := TX25519Agreement.Create() as IX25519Agreement;
  LAgreeB.Init(LX25519SkB);
  System.SetLength(LSecretB, LAgreeB.AgreementSize);
  LAgreeB.CalculateAgreement(LX25519PubA, LSecretB, 0);

  Logger.LogInformation('Party A shared secret (hex):{0}{1}', [sLineBreak, THexEncoder.Encode(LSecretA, False)]);
  Logger.LogInformation('Party B shared secret (hex):{0}{1}', [sLineBreak, THexEncoder.Encode(LSecretB, False)]);

  if TArrayUtilities.AreEqual(LSecretA, LSecretB) then
    Logger.LogInformation('X25519 key agreement: secrets match.', [])
  else
    Logger.LogError('X25519 key agreement: secrets do not match.', []);
end;

procedure TEdExample.RunX25519HybridEncryptDecrypt;
var
  LKp: IAsymmetricCipherKeyPair;
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX25519Pub: IX25519PublicKeyParameters;
  LPlain, LAad, LEnvelope, LDecrypted: TBytes;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  if not Supports(LKp.Private, IEd25519PrivateKeyParameters, LEdPriv) then
  begin
    Logger.LogError('Ed25519 private key type mismatch.', []);
    Exit;
  end;
  if not Supports(LKp.Public, IEd25519PublicKeyParameters, LEdPub) then
  begin
    Logger.LogError('Ed25519 public key type mismatch.', []);
    Exit;
  end;

  LX25519Priv := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPriv);
  LX25519Pub := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPub);

  LPlain := TConverters.ConvertStringToBytes('Hello X25519 Hybrid Encryption!', TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes('EX01-example-context', TEncoding.UTF8);

  LEnvelope := TX25519HybridEncryption.Encrypt(LX25519Pub, LPlain, LAad);
  Logger.LogInformation('X25519 hybrid envelope: {0} bytes', [IntToStr(System.Length(LEnvelope))]);

  LDecrypted := TX25519HybridEncryption.Decrypt(LX25519Priv, LEnvelope, LAad);
  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('X25519 hybrid encrypt/decrypt roundtrip: success.', [])
  else
    Logger.LogError('X25519 hybrid encrypt/decrypt roundtrip: failed.', []);
end;

procedure TEdExample.RunX25519HybridStreamEncryptDecrypt;
var
  LKp: IAsymmetricCipherKeyPair;
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX25519Pub: IX25519PublicKeyParameters;
  LPlainStream, LEncStream, LDecStream: TBytesStream;
  LPlain, LAad, LDecrypted: TBytes;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  if not Supports(LKp.Private, IEd25519PrivateKeyParameters, LEdPriv) then
  begin
    Logger.LogError('Ed25519 private key type mismatch.', []);
    Exit;
  end;
  if not Supports(LKp.Public, IEd25519PublicKeyParameters, LEdPub) then
  begin
    Logger.LogError('Ed25519 public key type mismatch.', []);
    Exit;
  end;

  LX25519Priv := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPriv);
  LX25519Pub := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPub);

  LPlain := TConverters.ConvertStringToBytes('Hello X25519 Hybrid Stream!', TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes('EX01-stream-context', TEncoding.UTF8);

  LPlainStream := TBytesStream.Create(LPlain);
  try
    LEncStream := TBytesStream.Create(nil);
    try
      TX25519HybridEncryption.Encrypt(LX25519Pub, LPlainStream, LEncStream, LAad);
      Logger.LogInformation('X25519 hybrid stream envelope: {0} bytes', [IntToStr(LEncStream.Size)]);

      LEncStream.Position := 0;
      LDecStream := TBytesStream.Create(nil);
      try
        TX25519HybridEncryption.Decrypt(LX25519Priv, LEncStream, LDecStream, LAad);
        LDecrypted := Copy(LDecStream.Bytes, 0, LDecStream.Size);
        if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
          Logger.LogInformation('X25519 hybrid stream roundtrip: success.', [])
        else
          Logger.LogError('X25519 hybrid stream roundtrip: failed.', []);
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

procedure TEdExample.Run;
begin
  LogWithLineBreak('--- Ed example: Ed25519 sign/verify ---');
  RunEd25519SignVerify;

  LogWithLineBreak('--- Ed example: Ed25519ctx sign/verify ---');
  RunEd25519CtxSignVerify;

  LogWithLineBreak('--- Ed example: Ed25519ph sign/verify ---');
  RunEd25519PhSignVerify;

  LogWithLineBreak('--- Ed example: Key recreate from DER bytes ---');
  RunEd25519KeyRecreateFromDEREncodedBytes;

  LogWithLineBreak('--- Ed example: PEM export/import ---');
  RunEd25519PemExportImport;

  LogWithLineBreak('--- Ed example: Ed25519 -> X25519 key conversion ---');
  RunEd25519ToX25519KeyConversion;

  LogWithLineBreak('--- Ed example: X25519 key agreement (via converted Ed25519 keys) ---');
  RunX25519KeyAgreement;

  LogWithLineBreak('--- Ed example: X25519 hybrid encrypt/decrypt (X25519 + HKDF + AES-256-GCM) ---');
  RunX25519HybridEncryptDecrypt;

  LogWithLineBreak('--- Ed example: X25519 hybrid stream encrypt/decrypt ---');
  RunX25519HybridStreamEncryptDecrypt;
end;

end.
