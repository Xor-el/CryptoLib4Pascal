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

unit AsymmetricExampleUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyGenerationParameters,
  ClpISigner,
  ClpISecureRandom,
  ClpGeneratorUtilities,
  ClpSignerUtilities,
  ClpSecureRandom,
  ClpBigInteger,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpECParameters,
  ClpIECParameters,
  ClpEd25519Parameters,
  ClpIEd25519Parameters,
  ClpECGenerators,
  ClpIECGenerators,
  ClpEncoders,
  ClpConverters,
  ClpCryptoLibExceptions,
  ClpStringUtilities,
  ExampleBase,
  ExampleLogger,
  KeyEncodingExampleUtilities;

type
  TAsymmetricExampleUtilities = class sealed
  public
    /// <summary>
    /// Generate a classical key pair from a key spec: Ed25519, RSA/RSA-{size}, or EC curve name.
    /// </summary>
    class function GenerateKeyPair(const AKeySpec: string): IAsymmetricCipherKeyPair; static;
    class function TryGenerateKeyPair(const AKeySpec: string;
      out AKeyPair: IAsymmetricCipherKeyPair): Boolean; static;
    class procedure RunSignVerify(const AKeySpec, AAlgorithmName, AMessageText: string); overload; static;
    class procedure RunSignVerify(const AAlgorithmName: string;
      const AKeyPair: IAsymmetricCipherKeyPair; const AMessage: TBytes); overload; static;
    class procedure RunDerRoundtrip(const AKeySpec, AKeyType: string); static;
    class procedure RunPemRoundtrip(const AKeySpec, AKeyType: string); static;
  end;

implementation

class function TAsymmetricExampleUtilities.TryGenerateKeyPair(const AKeySpec: string;
  out AKeyPair: IAsymmetricCipherKeyPair): Boolean;
var
  LLogger: ILogger;
begin
  Result := False;
  AKeyPair := nil;
  LLogger := TExampleLogger.GetDefaultLogger;
  try
    AKeyPair := GenerateKeyPair(AKeySpec);
    LLogger.LogInformation('Key spec: {0}', [AKeySpec]);
    Result := True;
  except
    on E: EArgumentCryptoLibException do
      LLogger.LogWarning('Key spec "{0}" not found: {1}', [AKeySpec, E.Message]);
    on E: EArgumentNilCryptoLibException do
      LLogger.LogWarning('Key spec must not be empty.', []);
  end;
end;

class function TAsymmetricExampleUtilities.GenerateKeyPair(
  const AKeySpec: string): IAsymmetricCipherKeyPair;
var
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKeyGenParams: IKeyGenerationParameters;
  LDomain: IECDomainParameters;
  LKeySize: Int32;
  LKeySizeText: string;
begin
  if AKeySpec = '' then
    raise EArgumentNilCryptoLibException.Create('Key spec must not be empty.');

  if SameText(AKeySpec, 'Ed25519') then
  begin
    LRandom := TSecureRandom.Create() as ISecureRandom;
    LKpg := TGeneratorUtilities.GetKeyPairGenerator('Ed25519');
    LKeyGenParams := TEd25519KeyGenerationParameters.Create(LRandom) as IEd25519KeyGenerationParameters;
    LKpg.Init(LKeyGenParams);
    Result := LKpg.GenerateKeyPair();
    Exit;
  end;

  if SameText(AKeySpec, 'RSA') then
    LKeySize := 2048
  else if TStringUtilities.StartsWith(AKeySpec, 'RSA-', True) then
  begin
    LKeySizeText := Copy(AKeySpec, 5, MaxInt);
    if (LKeySizeText = '') or not TryStrToInt(LKeySizeText, LKeySize) or (LKeySize <= 0) then
      raise EArgumentCryptoLibException.CreateFmt('Invalid RSA key spec "%s".', [AKeySpec]);
  end
  else
    LKeySize := 0;

  if LKeySize > 0 then
  begin
    LRandom := TSecureRandom.Create() as ISecureRandom;
    LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
    LKeyGenParams := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(65537),
      LRandom, LKeySize, 25) as IRsaKeyGenerationParameters;
    LKpg.Init(LKeyGenParams);
    Result := LKpg.GenerateKeyPair();
    Exit;
  end;

  LDomain := TECDomainParameters.LookupName(AKeySpec);
  LRandom := TSecureRandom.Create() as ISecureRandom;
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  LKeyGenParams := TECKeyGenerationParameters.Create(LDomain, LRandom) as IECKeyGenerationParameters;
  LKpg.Init(LKeyGenParams);
  Result := LKpg.GenerateKeyPair();
end;

class procedure TAsymmetricExampleUtilities.RunSignVerify(const AKeySpec,
  AAlgorithmName, AMessageText: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LMsg: TBytes;
begin
  if not TryGenerateKeyPair(AKeySpec, LKp) then
    Exit;
  LMsg := TConverters.ConvertStringToBytes(AMessageText, TEncoding.UTF8);
  RunSignVerify(AAlgorithmName, LKp, LMsg);
end;

class procedure TAsymmetricExampleUtilities.RunSignVerify(const AAlgorithmName: string;
  const AKeyPair: IAsymmetricCipherKeyPair; const AMessage: TBytes);
var
  LSigner: ISigner;
  LSig: TBytes;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LLogger.LogInformation('Algorithm: {0}', [AAlgorithmName]);
  try
    LSigner := TSignerUtilities.GetSigner(AAlgorithmName);
    LSigner.Init(True, AKeyPair.Private);
    LSigner.BlockUpdate(AMessage, 0, System.Length(AMessage));
    LSig := LSigner.GenerateSignature();
    LLogger.LogInformation('{0} signature (hex):{1}{2}', [AAlgorithmName, sLineBreak, THexEncoder.Encode(LSig, False)]);

    LSigner.Init(False, AKeyPair.Public);
    LSigner.BlockUpdate(AMessage, 0, System.Length(AMessage));
    if LSigner.VerifySignature(LSig) then
      LLogger.LogInformation('{0} verification passed.', [AAlgorithmName])
    else
      LLogger.LogWarning('{0} verification failed.', [AAlgorithmName]);
  except
    on E: ESecurityUtilityCryptoLibException do
      LLogger.LogWarning('Signer "{0}" not available: {1}', [AAlgorithmName, E.Message]);
  end;
end;

class procedure TAsymmetricExampleUtilities.RunDerRoundtrip(const AKeySpec,
  AKeyType: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  if not TryGenerateKeyPair(AKeySpec, LKp) then
    Exit;
  TKeyEncodingExampleUtilities.VerifyDerRoundtrip(LKp, AKeyType);
end;

class procedure TAsymmetricExampleUtilities.RunPemRoundtrip(const AKeySpec,
  AKeyType: string);
var
  LKp: IAsymmetricCipherKeyPair;
begin
  if not TryGenerateKeyPair(AKeySpec, LKp) then
    Exit;
  TKeyEncodingExampleUtilities.VerifyPemRoundtrip(LKp, AKeyType);
end;

end.
