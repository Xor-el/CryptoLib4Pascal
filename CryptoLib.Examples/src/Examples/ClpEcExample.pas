unit ClpEcExample;

interface

uses
  SysUtils,
  ClpECUtilities,
  ClpIX9ECParametersHolder,
  ClpIAsn1Objects,
  ClpSecureRandom,
  ClpBigInteger,
  ClpECParameters,
  ClpIECParameters,
  ClpECGenerators,
  ClpIECGenerators,
  ClpSignerUtilities,
  ClpEncoders,
  ClpConverters,
  ClpIAsymmetricCipherKeyPair,
  ClpIX9ECAsn1Objects,
  ClpIECCommon,
  ClpISecureRandom,
  ClpISigner,
  ClpExampleBase;

type
  TEcExample = class(TExampleBase)
  private
    procedure RunEcdsaSignVerify(const ACurveName: string;
      const ASignatureAlgorithm: string);
    procedure RunKeyRecreateFromBytes(const ACurveName: string);
    procedure RunPublicKeyFromXY(const ACurveName: string);

    function GetCurveByName(const ACurveName: string): IX9ECParameters;
  public
    procedure Run; override;
  end;

implementation

function TEcExample.GetCurveByName(const ACurveName: string): IX9ECParameters;
begin
  Result := TECUtilities.FindECCurveByName(ACurveName);
end;

procedure TEcExample.RunEcdsaSignVerify(const ACurveName: string;
  const ASignatureAlgorithm: string);
var
  LCurve: IX9ECParameters;
  LDomain: IECDomainParameters;
  LGen: IECKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LMsg, LSig: TBytes;
begin
  LCurve := GetCurveByName(ACurveName);
  if LCurve = nil then
  begin
    Logger.LogWarning('Curve "' + ACurveName + '" not found.');
    Exit;
  end;
  Logger.LogInformation('Curve: ' + ACurveName + ', Algorithm: ' + ASignatureAlgorithm);
  LDomain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N, LCurve.H, LCurve.GetSeed);
  LGen := TECKeyPairGenerator.Create('ECDSA') as IECKeyPairGenerator;
  LGen.Init(TECKeyGenerationParameters.Create(LDomain, TSecureRandom.Create() as ISecureRandom) as IECKeyGenerationParameters);
  LKp := LGen.GenerateKeyPair();
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
  Logger.LogInformation(ASignatureAlgorithm + ' signature (hex): ' + THexEncoder.Encode(LSig, False));
  LSigner.Init(False, LKp.Public);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  if LSigner.VerifySignature(LSig) then
    Logger.LogInformation(ASignatureAlgorithm + ' verification passed.')
  else
    Logger.LogWarning(ASignatureAlgorithm + ' verification failed.');
end;

procedure TEcExample.RunKeyRecreateFromBytes(const ACurveName: string);
var
  LCurve: IX9ECParameters;
  LDomain: IECDomainParameters;
  LGen: IECKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPriv: IECPrivateKeyParameters;
  LPub: IECPublicKeyParameters;
  LPubBytes, LPrivBytes: TBytes;
  LRegenPub: IECPublicKeyParameters;
  LRegenPriv: IECPrivateKeyParameters;
  LD: TBigInteger;
begin
  LCurve := GetCurveByName(ACurveName);
  if LCurve = nil then
  begin
    Logger.LogWarning('Curve "' + ACurveName + '" not found.');
    Exit;
  end;
  Logger.LogInformation('Curve: ' + ACurveName);
  LDomain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N, LCurve.H, LCurve.GetSeed);
  LGen := TECKeyPairGenerator.Create('ECDSA') as IECKeyPairGenerator;
  LGen.Init(TECKeyGenerationParameters.Create(LDomain, TSecureRandom.Create() as ISecureRandom) as IECKeyGenerationParameters);
  LKp := LGen.GenerateKeyPair();
  if not Supports(LKp.Private, IECPrivateKeyParameters, LPriv) or not Supports(LKp.Public, IECPublicKeyParameters, LPub) then
  begin
    Logger.LogError('EC key pair type mismatch.');
    Exit;
  end;
  LPubBytes := LPub.Q.GetEncoded();
  LPrivBytes := LPriv.D.ToByteArray();
  LRegenPub := TECPublicKeyParameters.Create('ECDSA', LCurve.Curve.DecodePoint(LPubBytes), LDomain) as IECPublicKeyParameters;
  LD := TBigInteger.Create(1, LPrivBytes);
  LRegenPriv := TECPrivateKeyParameters.Create('ECDSA', LD, LDomain) as IECPrivateKeyParameters;
  if LPub.Equals(LRegenPub) then
    Logger.LogInformation('Public key recreation: match.')
  else
    Logger.LogWarning('Public key recreation: mismatch.');
  if LPriv.Equals(LRegenPriv) then
    Logger.LogInformation('Private key recreation: match.')
  else
    Logger.LogWarning('Private key recreation: mismatch.');
end;

procedure TEcExample.RunPublicKeyFromXY(const ACurveName: string);
var
  LCurve: IX9ECParameters;
  LDomain: IECDomainParameters;
  LGen: IECKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPub: IECPublicKeyParameters;
  LXBytes, LYBytes: TBytes;
  LBigX, LBigY: TBigInteger;
  LPoint: IECPoint;
  LRegenPub: IECPublicKeyParameters;
begin
  LCurve := GetCurveByName(ACurveName);
  if LCurve = nil then
  begin
    Logger.LogWarning('Curve "' + ACurveName + '" not found.');
    Exit;
  end;
  Logger.LogInformation('Curve: ' + ACurveName);
  LDomain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N, LCurve.H, LCurve.GetSeed);
  LGen := TECKeyPairGenerator.Create('ECDSA') as IECKeyPairGenerator;
  LGen.Init(TECKeyGenerationParameters.Create(LDomain, TSecureRandom.Create() as ISecureRandom) as IECKeyGenerationParameters);
  LKp := LGen.GenerateKeyPair();
  if not Supports(LKp.Public, IECPublicKeyParameters, LPub) then
  begin
    Logger.LogError('EC public key type mismatch.');
    Exit;
  end;
  LXBytes := LPub.Q.Normalize.AffineXCoord.ToBigInteger.ToByteArray();
  LYBytes := LPub.Q.Normalize.AffineYCoord.ToBigInteger.ToByteArray();
  LBigX := TBigInteger.Create(1, LXBytes);
  LBigY := TBigInteger.Create(1, LYBytes);
  LPoint := LCurve.Curve.CreatePoint(LBigX, LBigY);
  LRegenPub := TECPublicKeyParameters.Create(LPoint, LDomain) as IECPublicKeyParameters;
  if LPub.Equals(LRegenPub) then
    Logger.LogInformation('Public key from X/Y recreation: match.')
  else
    Logger.LogWarning('Public key from X/Y recreation: mismatch.');
end;

procedure TEcExample.Run;
begin
  Logger.LogInformation('--- EC example: ECDSA sign/verify ---');
  RunEcdsaSignVerify('secp256k1', 'SHA-256withECDSA');

  Logger.LogInformation('--- EC example: Key recreate from bytes ---');
  RunKeyRecreateFromBytes('secp256k1');

  Logger.LogInformation('--- EC example: Public key from X/Y ---');
  RunPublicKeyFromXY('secp256k1');
end;

end.
