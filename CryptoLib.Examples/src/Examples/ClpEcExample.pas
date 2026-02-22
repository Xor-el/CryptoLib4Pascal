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

unit ClpEcExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  ClpECUtilities,
  ClpIX9ECParametersHolder,
  ClpIAsn1Objects,
  ClpBigInteger,
  ClpECParameters,
  ClpIECParameters,
  ClpSignerUtilities,
  ClpEncoders,
  ClpConverters,
  ClpArrayUtilities,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIX9ECAsn1Objects,
  ClpIECCommon,
  ClpISigner,
  ClpPrivateKeyInfoFactory,
  ClpPrivateKeyFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpPublicKeyFactory,
  ClpHybridEncryption,
  ClpExampleBase;

type
  TEcExample = class(TExampleBase)
  private
    function LookupEcDomain(const ACurveName: string): IECDomainParameters;
    procedure RunEcdsaSignVerify(const ACurveName: string;
      const ASignatureAlgorithm: string);
    procedure RunEcKeyRecreateFromDEREncodedBytes(const ACurveName: string);
    procedure RunPublicKeyFromXY(const ACurveName: string);
    procedure RunEcPemExportImport(const ACurveName: string);
    procedure RunEcHybridEncryptDecrypt(const ACurveName: string);
    procedure RunEcHybridStreamEncryptDecrypt(const ACurveName: string);
  public
    procedure Run; override;
  end;

implementation

function TEcExample.LookupEcDomain(const ACurveName: string): IECDomainParameters;
var
  LCurve: IX9ECParameters;
begin
  Result := nil;
  LCurve := TECUtilities.FindECCurveByName(ACurveName);
  if LCurve = nil then
  begin
    Logger.LogWarning('Curve "{0}" not found.', [ACurveName]);
    Exit;
  end;
  Result := TECDomainParameters.Create(LCurve.Curve, LCurve.G,
    LCurve.N, LCurve.H, LCurve.GetSeed);
end;

procedure TEcExample.RunEcdsaSignVerify(const ACurveName: string;
  const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
  LSigner: ISigner;
  LMsg, LSig: TBytes;
begin
  LDomain := LookupEcDomain(ACurveName);
  if LDomain = nil then
    Exit;
  LKp := GenerateEcKeyPair(LDomain);
  Logger.LogInformation('Curve: {0}, Algorithm: {1}', [ACurveName, ASignatureAlgorithm]);
  LSigner := TSignerUtilities.GetSigner(ASignatureAlgorithm);
  if LSigner = nil then
  begin
    Logger.LogWarning('Signer "{0}" not available.', [ASignatureAlgorithm]);
    Exit;
  end;
  LMsg := TConverters.ConvertStringToBytes('PascalECDSA', TEncoding.UTF8);
  LSigner.Init(True, LKp.Private);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LSig := LSigner.GenerateSignature();
  Logger.LogInformation('{0} signature (hex):{1}{2}', [ASignatureAlgorithm, sLineBreak, THexEncoder.Encode(LSig, False)]);
  LSigner.Init(False, LKp.Public);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  if LSigner.VerifySignature(LSig) then
    Logger.LogInformation('{0} verification passed.', [ASignatureAlgorithm])
  else
    Logger.LogError('{0} verification failed.', [ASignatureAlgorithm]);
end;

procedure TEcExample.RunEcKeyRecreateFromDEREncodedBytes(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
  LPrivBytes, LPubBytes: TBytes;
  LRegenPriv, LRegenPub: IAsymmetricKeyParameter;
begin
  LDomain := LookupEcDomain(ACurveName);
  if LDomain = nil then
    Exit;
  LKp := GenerateEcKeyPair(LDomain);
  Logger.LogInformation('Curve: {0}', [ACurveName]);

  LPrivBytes := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LKp.Private).GetEncoded();
  Logger.LogInformation('Private key DER encoded: {0} bytes', [IntToStr(System.Length(LPrivBytes))]);

  LPubBytes := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public).GetEncoded();
  Logger.LogInformation('Public key DER encoded: {0} bytes', [IntToStr(System.Length(LPubBytes))]);

  LRegenPriv := TPrivateKeyFactory.CreateKey(LPrivBytes);
  if LRegenPriv.Equals(LKp.Private) then
    Logger.LogInformation('Private key roundtrip: match.', [])
  else
    Logger.LogError('Private key roundtrip: mismatch.', []);

  LRegenPub := TPublicKeyFactory.CreateKey(LPubBytes);
  if LRegenPub.Equals(LKp.Public) then
    Logger.LogInformation('Public key roundtrip: match.', [])
  else
    Logger.LogError('Public key roundtrip: mismatch.', []);
end;

procedure TEcExample.RunPublicKeyFromXY(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
  LPub: IECPublicKeyParameters;
  LXBytes, LYBytes: TBytes;
  LBigX, LBigY: TBigInteger;
  LPoint: IECPoint;
  LRegenPub: IECPublicKeyParameters;
  LCurve: IX9ECParameters;
begin
  LDomain := LookupEcDomain(ACurveName);
  if LDomain = nil then
    Exit;
  LKp := GenerateEcKeyPair(LDomain);
  Logger.LogInformation('Curve: {0}', [ACurveName]);
  if not Supports(LKp.Public, IECPublicKeyParameters, LPub) then
  begin
    Logger.LogError('EC public key type mismatch.', []);
    Exit;
  end;
  LCurve := TECUtilities.FindECCurveByName(ACurveName);
  LXBytes := LPub.Q.Normalize.AffineXCoord.ToBigInteger.ToByteArray();
  LYBytes := LPub.Q.Normalize.AffineYCoord.ToBigInteger.ToByteArray();
  LBigX := TBigInteger.Create(1, LXBytes);
  LBigY := TBigInteger.Create(1, LYBytes);
  LPoint := LCurve.Curve.CreatePoint(LBigX, LBigY);
  LRegenPub := TECPublicKeyParameters.Create(LPoint, LDomain)
    as IECPublicKeyParameters;
  if LPub.Equals(LRegenPub) then
    Logger.LogInformation('Public key from X/Y recreation: match.', [])
  else
    Logger.LogError('Public key from X/Y recreation: mismatch.', []);
end;

procedure TEcExample.RunEcPemExportImport(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
begin
  LDomain := LookupEcDomain(ACurveName);
  if LDomain = nil then
    Exit;
  LKp := GenerateEcKeyPair(LDomain);
  Logger.LogInformation('Curve: {0}', [ACurveName]);
  VerifyPemRoundtrip(LKp, 'EC');
end;

procedure TEcExample.RunEcHybridEncryptDecrypt(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
  LPlain, LAad, LEnvelope, LDecrypted: TBytes;
begin
  LDomain := LookupEcDomain(ACurveName);
  if LDomain = nil then
    Exit;
  LKp := GenerateEcKeyPair(LDomain);
  Logger.LogInformation('Curve: {0}', [ACurveName]);

  LPlain := TConverters.ConvertStringToBytes('Hello EC Hybrid Encryption!', TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes('EH01-example-context', TEncoding.UTF8);

  LEnvelope := TEcHybridEncryption.Encrypt(LKp.Public, LDomain, LPlain, LAad);
  Logger.LogInformation('EC hybrid envelope: {0} bytes', [IntToStr(System.Length(LEnvelope))]);

  LDecrypted := TEcHybridEncryption.Decrypt(LKp.Private, LDomain, LEnvelope, LAad);
  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('EC hybrid encrypt/decrypt roundtrip: success.', [])
  else
    Logger.LogError('EC hybrid encrypt/decrypt roundtrip: failed.', []);
end;

procedure TEcExample.RunEcHybridStreamEncryptDecrypt(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
  LPlainStream, LEncStream, LDecStream: TBytesStream;
  LPlain, LAad, LDecrypted: TBytes;
begin
  LDomain := LookupEcDomain(ACurveName);
  if LDomain = nil then
    Exit;
  LKp := GenerateEcKeyPair(LDomain);
  Logger.LogInformation('Curve: {0}', [ACurveName]);

  LPlain := TConverters.ConvertStringToBytes('Hello EC Hybrid Stream!', TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes('EH01-stream-context', TEncoding.UTF8);

  LPlainStream := TBytesStream.Create(LPlain);
  try
    LEncStream := TBytesStream.Create(nil);
    try
      TEcHybridEncryption.Encrypt(LKp.Public, LDomain, LPlainStream, LEncStream, LAad);
      Logger.LogInformation('EC hybrid stream envelope: {0} bytes', [IntToStr(LEncStream.Size)]);

      LEncStream.Position := 0;
      LDecStream := TBytesStream.Create(nil);
      try
        TEcHybridEncryption.Decrypt(LKp.Private, LDomain, LEncStream, LDecStream, LAad);
        LDecrypted := Copy(LDecStream.Bytes, 0, LDecStream.Size);
        if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
          Logger.LogInformation('EC hybrid stream roundtrip: success.', [])
        else
          Logger.LogError('EC hybrid stream roundtrip: failed.', []);
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

procedure TEcExample.Run;
begin
  LogWithLineBreak('--- EC example: ECDSA sign/verify ---');
  RunEcdsaSignVerify('secp256k1', 'SHA-256withECDSA');

  LogWithLineBreak('--- EC example: Key recreate from DER bytes ---');
  RunEcKeyRecreateFromDEREncodedBytes('secp256k1');

  LogWithLineBreak('--- EC example: Public key from X/Y ---');
  RunPublicKeyFromXY('secp256k1');

  LogWithLineBreak('--- EC example: PEM export/import ---');
  RunEcPemExportImport('secp256k1');

  LogWithLineBreak('--- EC example: Hybrid encrypt/decrypt (ECDH + HKDF + AES-256-GCM) ---');
  RunEcHybridEncryptDecrypt('secp256r1');

  LogWithLineBreak('--- EC example: Hybrid stream encrypt/decrypt ---');
  RunEcHybridStreamEncryptDecrypt('secp256r1');
end;

end.
