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

unit EcExample;

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
  ClpIAsn1Objects,
  ClpBigInteger,
  ClpECParameters,
  ClpIECParameters,
  ClpEncoders,
  ClpConverters,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIX9ECAsn1Objects,
  ClpIECCommon,
  HybridEncryption,
  ExampleBase,
  AsymmetricExampleUtilities,
  KeyEncodingExampleUtilities;

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
  LMsg: TBytes;
begin
  try
    LKp := TAsymmetricExampleUtilities.GenerateKeyPair(ACurveName);
  except
    on E: EArgumentCryptoLibException do
    begin
      Logger.LogWarning('Curve "{0}" not found: {1}', [ACurveName, E.Message]);
      Exit;
    end;
    on E: EArgumentNilCryptoLibException do
    begin
      Logger.LogWarning('Curve name empty.', []);
      Exit;
    end;
  end;
  Logger.LogInformation('Curve: {0}', [ACurveName]);
  LMsg := TConverters.ConvertStringToBytes('PascalECDSA', TEncoding.UTF8);
  TAsymmetricExampleUtilities.RunSignVerify(ASignatureAlgorithm, LKp, LMsg);
end;

procedure TEcExample.RunEcKeyRecreateFromDEREncodedBytes(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  try
    LKp := TAsymmetricExampleUtilities.GenerateKeyPair(ACurveName);
  except
    on E: EArgumentCryptoLibException do
    begin
      Logger.LogWarning('Curve "{0}" not found: {1}', [ACurveName, E.Message]);
      Exit;
    end;
    on E: EArgumentNilCryptoLibException do
    begin
      Logger.LogWarning('Curve name empty.', []);
      Exit;
    end;
  end;
  Logger.LogInformation('Curve: {0}', [ACurveName]);
  TKeyEncodingExampleUtilities.VerifyDerRoundtrip(LKp, 'EC');
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
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair(ACurveName);
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
begin
  try
    LKp := TAsymmetricExampleUtilities.GenerateKeyPair(ACurveName);
  except
    on E: EArgumentCryptoLibException do
    begin
      Logger.LogWarning('Curve "{0}" not found: {1}', [ACurveName, E.Message]);
      Exit;
    end;
    on E: EArgumentNilCryptoLibException do
    begin
      Logger.LogWarning('Curve name empty.', []);
      Exit;
    end;
  end;
  Logger.LogInformation('Curve: {0}', [ACurveName]);
  TKeyEncodingExampleUtilities.VerifyPemRoundtrip(LKp, 'EC');
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
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair(ACurveName);
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
  LKp := TAsymmetricExampleUtilities.GenerateKeyPair(ACurveName);
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
