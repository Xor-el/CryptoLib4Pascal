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

unit PqcExampleUtilities;

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
  ClpICipherParameters,
  ClpIKeyGenerationParameters,
  ClpISigner,
  ClpIMlKemParameters,
  ClpIMlDsaParameters,
  ClpISlhDsaParameters,
  ClpIKemEncapsulator,
  ClpIKemDecapsulator,
  ClpIParametersWithRandom,
  ClpParametersWithRandom,
  ClpGeneratorUtilities,
  ClpSignerUtilities,
  ClpMlKemParameters,
  ClpMlDsaParameters,
  ClpSlhDsaParameters,
  ClpKemUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpArrayUtilities,
  ClpEncoders,
  ClpCryptoLibTypes,
  ExampleBase,
  ExampleLogger,
  ClpParameterUtilities;

type
  TPqcExampleUtilities = class sealed
  strict private
    class procedure DoRunSignVerify(const AAlgorithmName: string; const AMessage: TBytes;
      const ASignInitParams, AVerifyInitParams: ICipherParameters); static;
  public
    class function GenerateKeyPair(const AParameterSetName: string): IAsymmetricCipherKeyPair; static;
    class procedure RunKemRoundtrip(const AParameterSetName: string;
      const AKeyPair: IAsymmetricCipherKeyPair); static;
    class procedure RunSignVerify(const AAlgorithmName: string;
      const AKeyPair: IAsymmetricCipherKeyPair; const AMessage: TBytes); static;
    class procedure RunContextSignVerify(const AAlgorithmName: string;
      const AKeyPair: IAsymmetricCipherKeyPair; const AMessage, AContext: TBytes); static;
  end;

implementation

class procedure TPqcExampleUtilities.DoRunSignVerify(const AAlgorithmName: string;
  const AMessage: TBytes; const ASignInitParams, AVerifyInitParams: ICipherParameters);
var
  LSigner: ISigner;
  LSig: TBytes;
  LLogger: ILogger;
begin
  LLogger := TExampleLogger.GetDefaultLogger;
  LLogger.LogInformation('Algorithm: {0}', [AAlgorithmName]);
  try
    LSigner := TSignerUtilities.GetSigner(AAlgorithmName);
    LSigner.Init(True, ASignInitParams);
    LSigner.BlockUpdate(AMessage, 0, System.Length(AMessage));
    LSig := LSigner.GenerateSignature();
    LLogger.LogInformation('{0} signature (hex):{1}{2}', [AAlgorithmName, sLineBreak, THexEncoder.Encode(LSig, False)]);

    LSigner.Init(False, AVerifyInitParams);
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

class function TPqcExampleUtilities.GenerateKeyPair(
  const AParameterSetName: string): IAsymmetricCipherKeyPair;
var
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKeyGenParams: IKeyGenerationParameters;
  LMlKemParams: IMlKemParameters;
  LMlDsaParams: IMlDsaParameters;
  LSlhDsaParams: ISlhDsaParameters;
  LGeneratorName: string;
begin
  LRandom := TSecureRandom.Create() as ISecureRandom;
  LGeneratorName := '';
  LKeyGenParams := nil;

  LMlKemParams := TMlKemParameters.GetByName(AParameterSetName);
  if LMlKemParams <> nil then
  begin
    LGeneratorName := 'ML-KEM';
    LKeyGenParams := TMlKemKeyGenerationParameters.Create(LRandom, LMlKemParams)
      as IKeyGenerationParameters;
  end
  else
  begin
    LMlDsaParams := TMlDsaParameters.GetByName(AParameterSetName);
    if LMlDsaParams <> nil then
    begin
      LGeneratorName := 'ML-DSA';
      LKeyGenParams := TMlDsaKeyGenerationParameters.Create(LRandom, LMlDsaParams)
        as IKeyGenerationParameters;
    end
    else
    begin
      LSlhDsaParams := TSlhDsaParameters.GetByName(AParameterSetName);
      if LSlhDsaParams <> nil then
      begin
        LGeneratorName := 'SLH-DSA';
        LKeyGenParams := TSlhDsaKeyGenerationParameters.Create(LRandom, LSlhDsaParams)
          as IKeyGenerationParameters;
      end;
    end;
  end;

  if LKeyGenParams = nil then
    raise EArgumentCryptoLibException.CreateFmt('PQC parameter set "%s" not found.', [AParameterSetName]);

  LKpg := TGeneratorUtilities.GetKeyPairGenerator(LGeneratorName);
  LKpg.Init(LKeyGenParams);
  Result := LKpg.GenerateKeyPair();
end;

class procedure TPqcExampleUtilities.RunKemRoundtrip(const AParameterSetName: string;
  const AKeyPair: IAsymmetricCipherKeyPair);
var
  LRandom: ISecureRandom;
  LEnc: IKemEncapsulator;
  LDec: IKemDecapsulator;
  LEncBuf, LSec1, LSec2: TBytes;
  LLogger: ILogger;
begin
  // ML-KEM round-trip (Alice / Bob):
  //   Bob (or server) owns AKeyPair and publishes AKeyPair.Public.
  //   Alice (or client) encapsulates against that public key and learns a shared secret.
  //   Bob decapsulates the ciphertext with AKeyPair.Private and must recover the same secret.
  //
  // Buffers:
  //   LEncBuf  - output from Encapsulate, input to Decapsulate (KEM ciphertext / encapsulation).
  //   LSec1    - output from Encapsulate (Alice's shared secret).
  //   LSec2    - output from Decapsulate (Bob's shared secret; must match LSec1).
  LLogger := TExampleLogger.GetDefaultLogger;
  if not TKemUtilities.TryGetEncapsulator(AParameterSetName, LEnc) then
  begin
    LLogger.LogWarning('KEM parameter set "{0}" not found.', [AParameterSetName]);
    Exit;
  end;
  if not TKemUtilities.TryGetDecapsulator(AParameterSetName, LDec) then
  begin
    LLogger.LogWarning('KEM decapsulator for "{0}" not found.', [AParameterSetName]);
    Exit;
  end;

  LLogger.LogInformation('KEM via TKemUtilities: {0}', [AParameterSetName]);
  LRandom := TSecureRandom.Create() as ISecureRandom;

  // Alice: Init with Bob's public key (+ randomness for ML-KEM encapsulation).
  LEnc.Init(TParametersWithRandom.Create(AKeyPair.Public, LRandom) as IParametersWithRandom);
  System.SetLength(LEncBuf, LEnc.EncapsulationLength);
  System.SetLength(LSec1, LEnc.SecretLength);
  // Alice: Encapsulate writes ciphertext into LEncBuf and shared secret into LSec1.
  LEnc.Encapsulate(LEncBuf, 0, System.Length(LEncBuf), LSec1, 0, System.Length(LSec1));

  // Bob: Init with his private key; Decapsulate reads LEncBuf and writes shared secret into LSec2.
  LDec.Init(AKeyPair.Private);
  System.SetLength(LSec2, LDec.SecretLength);
  LDec.Decapsulate(LEncBuf, 0, System.Length(LEncBuf), LSec2, 0, System.Length(LSec2));

  LLogger.LogInformation('Shared secret (encapsulator, hex):{0}{1}',
    [sLineBreak, THexEncoder.Encode(LSec1, False)]);
  if TArrayUtilities.AreEqual(LSec1, LSec2) then
    LLogger.LogInformation('KEM shared secret roundtrip: match.', [])
  else
    LLogger.LogError('KEM shared secret roundtrip: mismatch.', []);
end;

class procedure TPqcExampleUtilities.RunSignVerify(const AAlgorithmName: string;
  const AKeyPair: IAsymmetricCipherKeyPair; const AMessage: TBytes);
begin
  DoRunSignVerify(AAlgorithmName, AMessage, AKeyPair.Private, AKeyPair.Public);
end;

class procedure TPqcExampleUtilities.RunContextSignVerify(const AAlgorithmName: string;
  const AKeyPair: IAsymmetricCipherKeyPair; const AMessage, AContext: TBytes);
var
  LSignInit, LVerifyInit: ICipherParameters;
begin
  LSignInit := TParameterUtilities.WithContext(AKeyPair.Private, AContext);
  LVerifyInit := TParameterUtilities.WithContext(AKeyPair.Public, AContext);
  DoRunSignVerify(AAlgorithmName, AMessage, LSignInit, LVerifyInit);
end;

end.
