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
{$ENDIF FPC}

uses
  SysUtils,
  ClpECUtilities,
  ClpIX9ECParametersHolder,
  ClpIAsn1Objects,
  ClpBigInteger,
  ClpECParameters,
  ClpIECParameters,
  ClpSignerUtilities,
  ClpEncoders,
  ClpConverters,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpIX9ECAsn1Objects,
  ClpIECCommon,
  ClpISigner,
  ClpPrivateKeyInfoFactory,
  ClpPrivateKeyFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpPublicKeyFactory,
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
    Logger.LogWarning('Curve "' + ACurveName + '" not found.');
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
  Logger.LogInformation('Curve: ' + ACurveName + ', Algorithm: ' + ASignatureAlgorithm);
  LSigner := TSignerUtilities.GetSigner(ASignatureAlgorithm);
  if LSigner = nil then
  begin
    Logger.LogWarning('Signer "' + ASignatureAlgorithm + '" not available.');
    Exit;
  end;
  LMsg := TConverters.ConvertStringToBytes('PascalECDSA', TEncoding.UTF8);
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
  Logger.LogInformation('Curve: ' + ACurveName);

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
  Logger.LogInformation('Curve: ' + ACurveName);
  if not Supports(LKp.Public, IECPublicKeyParameters, LPub) then
  begin
    Logger.LogError('EC public key type mismatch.');
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
    Logger.LogInformation('Public key from X/Y recreation: match.')
  else
    Logger.LogWarning('Public key from X/Y recreation: mismatch.');
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
  Logger.LogInformation('Curve: ' + ACurveName);
  VerifyPemRoundtrip(LKp, 'EC');
end;

procedure TEcExample.Run;
begin
  LogWithLineBreak('--- EC example: ECDSA sign/verify ---');
  RunEcdsaSignVerify('secp256k1', 'SHA-256withECDSA');

  LogWithLineBreak('--- EC example: Key recreate from bytes ---');
  RunEcKeyRecreateFromDEREncodedBytes('secp256k1');

  LogWithLineBreak('--- EC example: Public key from X/Y ---');
  RunPublicKeyFromXY('secp256k1');

  LogWithLineBreak('--- EC example: PEM export/import ---');
  RunEcPemExportImport('secp256k1');
end;

end.
