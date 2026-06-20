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
  ClpBigInteger,
  ClpECParameters,
  ClpIECParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIECCommon,
  ClpConverters,
  ClpArrayUtilities,
  ExampleBase,
  AsymmetricExampleUtilities,
  HybridEncryption;

type
  TEcExample = class(TExampleBase)
  private
    procedure DoEcHybridRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
      const ADomain: IECDomainParameters; const APlainText, AAadContext: string);
    procedure DoEcHybridStreamRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
      const ADomain: IECDomainParameters; const APlainText, AAadContext: string);
    procedure RunPublicKeyFromXY(const ACurveName: string);
    procedure RunCurveDemos(const ACurveName, ASignatureAlgorithm, AMessageText: string);
    procedure RunEcHybridDemos(const ACurveName: string);
  public
    procedure Run; override;
  end;

implementation

procedure TEcExample.DoEcHybridRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
  const ADomain: IECDomainParameters; const APlainText, AAadContext: string);
var
  LPlain, LAad, LEnvelope, LDecrypted: TBytes;
begin
  LPlain := TConverters.ConvertStringToBytes(APlainText, TEncoding.UTF8);
  LAad := TConverters.ConvertStringToBytes(AAadContext, TEncoding.UTF8);
  LEnvelope := TEcHybridEncryption.Encrypt(AKeyPair.Public, ADomain, LPlain, LAad);
  Logger.LogInformation('EC hybrid envelope: {0} bytes', [IntToStr(System.Length(LEnvelope))]);
  LDecrypted := TEcHybridEncryption.Decrypt(AKeyPair.Private, ADomain, LEnvelope, LAad);
  if TArrayUtilities.AreEqual(LPlain, LDecrypted) then
    Logger.LogInformation('EC hybrid encrypt/decrypt roundtrip: success.', [])
  else
    Logger.LogError('EC hybrid encrypt/decrypt roundtrip: failed.', []);
end;

procedure TEcExample.DoEcHybridStreamRoundtrip(const AKeyPair: IAsymmetricCipherKeyPair;
  const ADomain: IECDomainParameters; const APlainText, AAadContext: string);
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
      TEcHybridEncryption.Encrypt(AKeyPair.Public, ADomain, LPlainStream, LEncStream, LAad);
      Logger.LogInformation('EC hybrid stream envelope: {0} bytes', [IntToStr(LEncStream.Size)]);
      LEncStream.Position := 0;
      LDecStream := TBytesStream.Create(nil);
      try
        TEcHybridEncryption.Decrypt(AKeyPair.Private, ADomain, LEncStream, LDecStream, LAad);
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

procedure TEcExample.RunPublicKeyFromXY(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
  LPub: IECPublicKeyParameters;
  LRegenPub: IECPublicKeyParameters;
  LXBytes, LYBytes: TBytes;
  LBigX, LBigY: TBigInteger;
  LPoint: IECPoint;
begin
  if not TAsymmetricExampleUtilities.TryGenerateKeyPair(ACurveName, LKp) then
    Exit;
  if not Supports(LKp.Public, IECPublicKeyParameters, LPub) then
  begin
    Logger.LogError('EC public key type mismatch.', []);
    Exit;
  end;
  LDomain := LPub.Parameters;
  LXBytes := LPub.Q.Normalize.AffineXCoord.ToBigInteger.ToByteArray();
  LYBytes := LPub.Q.Normalize.AffineYCoord.ToBigInteger.ToByteArray();
  LBigX := TBigInteger.Create(1, LXBytes);
  LBigY := TBigInteger.Create(1, LYBytes);
  LPoint := LDomain.Curve.CreatePoint(LBigX, LBigY);
  LRegenPub := TECPublicKeyParameters.Create(LPoint, LDomain)
    as IECPublicKeyParameters;
  if LPub.Equals(LRegenPub) then
    Logger.LogInformation('Public key from X/Y recreation: match.', [])
  else
    Logger.LogError('Public key from X/Y recreation: mismatch.', []);
end;

procedure TEcExample.RunCurveDemos(const ACurveName, ASignatureAlgorithm,
  AMessageText: string);
begin
  LogWithLineBreak(Format('--- EC example: ECDSA sign/verify (%s) ---', [ACurveName]));
  TAsymmetricExampleUtilities.RunSignVerify(ACurveName, ASignatureAlgorithm, AMessageText);

  LogWithLineBreak(Format('--- EC example: Key recreate from DER bytes (%s) ---', [ACurveName]));
  TAsymmetricExampleUtilities.RunDerRoundtrip(ACurveName, 'EC');

  LogWithLineBreak(Format('--- EC example: Public key from X/Y (%s) ---', [ACurveName]));
  RunPublicKeyFromXY(ACurveName);

  LogWithLineBreak(Format('--- EC example: PEM export/import (%s) ---', [ACurveName]));
  TAsymmetricExampleUtilities.RunPemRoundtrip(ACurveName, 'EC');
end;

procedure TEcExample.RunEcHybridDemos(const ACurveName: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomain: IECDomainParameters;
  LPub: IECPublicKeyParameters;
begin
  if not TAsymmetricExampleUtilities.TryGenerateKeyPair(ACurveName, LKp) then
    Exit;
  if not Supports(LKp.Public, IECPublicKeyParameters, LPub) then
  begin
    Logger.LogError('EC public key type mismatch.', []);
    Exit;
  end;
  LDomain := LPub.Parameters;

  LogWithLineBreak('--- EC example: Hybrid encrypt/decrypt (ECDH + HKDF + AES-256-GCM) ---');
  DoEcHybridRoundtrip(LKp, LDomain, 'Hello EC Hybrid Encryption!', 'EH01-example-context');

  LogWithLineBreak('--- EC example: Hybrid stream encrypt/decrypt ---');
  DoEcHybridStreamRoundtrip(LKp, LDomain, 'Hello EC Hybrid Stream!', 'EH01-stream-context');
end;

procedure TEcExample.Run;
begin
  RunCurveDemos('secp256k1', 'SHA-256withECDSA', 'PascalECDSA');
  RunEcHybridDemos('secp256r1');
end;

end.
