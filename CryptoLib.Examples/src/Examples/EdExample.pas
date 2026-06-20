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
  ClpEncoders,
  ClpArrayUtilities,
  ClpConverters,
  ClpIAsymmetricCipherKeyPair,
  ClpIEd25519Parameters,
  ClpIX25519Parameters,
  ClpIX25519Agreement,
  ClpX25519Agreement,
  ClpCurve25519KeyUtilities,
  ExampleBase,
  AsymmetricExampleUtilities,
  HybridEncryption;

type
  TEdExample = class(TExampleBase)
  private
    function TryGetX25519KeysFromEdKeyPair(const AKeyPair: IAsymmetricCipherKeyPair;
      out APriv: IX25519PrivateKeyParameters;
      out APub: IX25519PublicKeyParameters): Boolean;
    procedure DoX25519HybridRoundtrip(const APriv: IX25519PrivateKeyParameters;
      const APub: IX25519PublicKeyParameters; const APlainText, AAadContext: string);
    procedure DoX25519HybridStreamRoundtrip(const APriv: IX25519PrivateKeyParameters;
      const APub: IX25519PublicKeyParameters; const APlainText, AAadContext: string);
    procedure RunEd25519ToX25519KeyConversion;
    procedure RunX25519KeyAgreement;
    procedure RunX25519HybridEncryptDecrypt;
    procedure RunX25519HybridStreamEncryptDecrypt;
    procedure RunEd25519Demos;
  public
    procedure Run; override;
  end;

implementation

function TEdExample.TryGetX25519KeysFromEdKeyPair(const AKeyPair: IAsymmetricCipherKeyPair;
  out APriv: IX25519PrivateKeyParameters;
  out APub: IX25519PublicKeyParameters): Boolean;
var
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
begin
  APriv := nil;
  APub := nil;
  if not Supports(AKeyPair.Private, IEd25519PrivateKeyParameters, LEdPriv) then
  begin
    Logger.LogError('Ed25519 private key type mismatch.', []);
    Exit(False);
  end;
  if not Supports(AKeyPair.Public, IEd25519PublicKeyParameters, LEdPub) then
  begin
    Logger.LogError('Ed25519 public key type mismatch.', []);
    Exit(False);
  end;
  APriv := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPriv);
  APub := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPub);
  Result := True;
end;

procedure TEdExample.DoX25519HybridRoundtrip(const APriv: IX25519PrivateKeyParameters;
  const APub: IX25519PublicKeyParameters; const APlainText, AAadContext: string);
var
  LPlain, LAad, LEnvelope, LDecrypted: TBytes;
begin
  LPlain := TConverters.ConvertStringToBytes(APlainText, TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes(AAadContext, TEncoding.UTF8);
  LEnvelope := TX25519HybridEncryption.Encrypt(APub, LPlain, LAad);
  Logger.LogInformation('X25519 hybrid envelope: {0} bytes', [IntToStr(System.Length(LEnvelope))]);
  LDecrypted := TX25519HybridEncryption.Decrypt(APriv, LEnvelope, LAad);
  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('X25519 hybrid encrypt/decrypt roundtrip: success.', [])
  else
    Logger.LogError('X25519 hybrid encrypt/decrypt roundtrip: failed.', []);
end;

procedure TEdExample.DoX25519HybridStreamRoundtrip(const APriv: IX25519PrivateKeyParameters;
  const APub: IX25519PublicKeyParameters; const APlainText, AAadContext: string);
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
      TX25519HybridEncryption.Encrypt(APub, LPlainStream, LEncStream, LAad);
      Logger.LogInformation('X25519 hybrid stream envelope: {0} bytes', [IntToStr(LEncStream.Size)]);
      LEncStream.Position := 0;
      LDecStream := TBytesStream.Create(nil);
      try
        TX25519HybridEncryption.Decrypt(APriv, LEncStream, LDecStream, LAad);
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

procedure TEdExample.RunEd25519ToX25519KeyConversion;
var
  LKp: IAsymmetricCipherKeyPair;
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX25519PubFromConversion, LX25519PubFromPriv: IX25519PublicKeyParameters;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  Logger.LogInformation('Key spec: {0}', ['Ed25519']);
  if not TryGetX25519KeysFromEdKeyPair(LKp, LX25519Priv, LX25519PubFromConversion) then
    Exit;
  if not Supports(LKp.Private, IEd25519PrivateKeyParameters, LEdPriv) then
    Exit;
  if not Supports(LKp.Public, IEd25519PublicKeyParameters, LEdPub) then
    Exit;

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
  LX25519SkA, LX25519SkB: IX25519PrivateKeyParameters;
  LX25519PubA, LX25519PubB: IX25519PublicKeyParameters;
  LAgreeA, LAgreeB: IX25519Agreement;
  LSecretA, LSecretB: TBytes;
begin
  LKpA := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  LKpB := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  if not TryGetX25519KeysFromEdKeyPair(LKpA, LX25519SkA, LX25519PubA) then
    Exit;
  if not TryGetX25519KeysFromEdKeyPair(LKpB, LX25519SkB, LX25519PubB) then
    Exit;

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
  LX25519Priv: IX25519PrivateKeyParameters;
  LX25519Pub: IX25519PublicKeyParameters;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  if not TryGetX25519KeysFromEdKeyPair(LKp, LX25519Priv, LX25519Pub) then
    Exit;
  DoX25519HybridRoundtrip(LX25519Priv, LX25519Pub,
    'Hello X25519 Hybrid Encryption!', 'EX01-example-context');
end;

procedure TEdExample.RunX25519HybridStreamEncryptDecrypt;
var
  LKp: IAsymmetricCipherKeyPair;
  LX25519Priv: IX25519PrivateKeyParameters;
  LX25519Pub: IX25519PublicKeyParameters;
begin
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair('Ed25519');
  if not TryGetX25519KeysFromEdKeyPair(LKp, LX25519Priv, LX25519Pub) then
    Exit;
  DoX25519HybridStreamRoundtrip(LX25519Priv, LX25519Pub,
    'Hello X25519 Hybrid Stream!', 'EX01-stream-context');
end;

procedure TEdExample.RunEd25519Demos;
begin
  LogWithLineBreak('--- Ed example: Ed25519 sign/verify ---');
  TAsymmetricExampleUtilities.RunSignVerify('Ed25519', 'Ed25519', 'PascalEd25519');

  LogWithLineBreak('--- Ed example: Ed25519ctx sign/verify ---');
  TAsymmetricExampleUtilities.RunSignVerify('Ed25519', 'Ed25519ctx', 'PascalEd25519ctx');

  LogWithLineBreak('--- Ed example: Ed25519ph sign/verify ---');
  TAsymmetricExampleUtilities.RunSignVerify('Ed25519', 'Ed25519ph', 'PascalEd25519ph');

  LogWithLineBreak('--- Ed example: Key recreate from DER bytes ---');
  TAsymmetricExampleUtilities.RunDerRoundtrip('Ed25519', 'Ed25519');

  LogWithLineBreak('--- Ed example: PEM export/import ---');
  TAsymmetricExampleUtilities.RunPemRoundtrip('Ed25519', 'Ed25519');

  LogWithLineBreak('--- Ed example: Ed25519 -> X25519 key conversion ---');
  RunEd25519ToX25519KeyConversion;

  LogWithLineBreak('--- Ed example: X25519 key agreement (via converted Ed25519 keys) ---');
  RunX25519KeyAgreement;

  LogWithLineBreak('--- Ed example: X25519 hybrid encrypt/decrypt (X25519 + HKDF + AES-256-GCM) ---');
  RunX25519HybridEncryptDecrypt;

  LogWithLineBreak('--- Ed example: X25519 hybrid stream encrypt/decrypt ---');
  RunX25519HybridStreamEncryptDecrypt;
end;

procedure TEdExample.Run;
begin
  RunEd25519Demos;
end;

end.
