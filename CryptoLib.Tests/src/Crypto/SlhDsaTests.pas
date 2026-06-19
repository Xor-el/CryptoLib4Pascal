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

unit SlhDsaTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyGenerationParameters,
  ClpISigner,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpParameterUtilities,
  ClpPrivateKeyFactory,
  ClpPublicKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpSubjectPublicKeyInfoFactory,
  PqcTestVectors,
  PqcTestSampler,
  RspTxtVectorParser,
  FixedSecureRandom,
  ClpSlhDsaParameters,
  ClpISlhDsaParameters,
  ClpSlhDsaGenerators,
  ClpSlhDsaSigner,
  ClpHashSlhDsaSigner,
  ClpParametersWithRandom,
  ClpGeneratorUtilities,
  ClpSignerUtilities,
  ClpNistObjectIdentifiers,
  ClpConverters,
  CryptoLibTestBase,
  ClpCryptoLibTypes;

type
  TTestSlhDsa = class(TCryptoLibAlgorithmTestCase)
  protected
  const
  // test vector courtesy the "Yawning Angel" GO implementation and the SUPERCOP reference implementation.
    SLH_DSA_RANDOM_MESSAGE =
    'Cthulhu Fthagn --What a wonderful phrase!Cthulhu Fthagn --Say it and you''re crazed!';
  var
    FRandom: ISecureRandom;
    procedure RunContextVectors(const ARelativePath: string; const AParameters: ISlhDsaParameters;
      ASampleOnly: Boolean);
    procedure RunKeyGenAcvp(const ARelativePath: string; const AParameters: ISlhDsaParameters);
    procedure RunSigGen(const ARelativePath: string; const AParameters: ISlhDsaParameters);
    procedure RunSigVer(const ARelativePath: string; const AParameters: ISlhDsaParameters);
    procedure ImplConsistency(const AParameters: ISlhDsaParameters);
    procedure ImplKeyGen(const AName: string; const AData: TRspTxtRecord;
      const AParameters: ISlhDsaParameters);
    procedure ImplContext(const AName: string; const AData: TRspTxtRecord;
      const AParameters: ISlhDsaParameters);
    procedure ImplSigGen(const AName: string; const AData: TRspTxtRecord;
      const AParameters: ISlhDsaParameters);
    procedure ImplSigVer(const AName: string; const AData: TRspTxtRecord;
      const AParameters: ISlhDsaParameters);
    function GetParameters(const AName: string): ISlhDsaParameters;
    function CreateSigner(const AParameters: ISlhDsaParameters;
      ADeterministic: Boolean): ISigner;
    procedure RunSignerKat(const ARelativePath: string);
    procedure ImplSignerKat(const AName: string; const AData: TRspTxtRecord);
  public
    procedure SetUp; override;
  end;

  TTestSlhDsaFast = class(TTestSlhDsa)
  published
    procedure Test02KeyGenAcvp192f;
    procedure Test04KeyGenAcvpShake256f;
    procedure Test10ContextFastSha2128f;
    procedure Test11ContextFastSha2128fSha256;
    procedure Test12ContextFastSha2192f;
    procedure Test13ContextFastSha2192fSha512;
    procedure Test16ContextFastShake128f;
    procedure Test17ContextFastShake128fShake128;
    procedure Test18ContextFastShake192f;
    procedure Test19ContextFastShake192fShake256;
    procedure Test20ContextFastShake256f;
    procedure Test95ConsistencySha2_128s;
    procedure Test95ConsistencyShake_128s;
    procedure Test95ConsistencySha2_128f;
    procedure Test95ConsistencyShake_128f;
    procedure Test95ConsistencyShake_192s;
    procedure Test95ConsistencySha2_192f;
    procedure Test95ConsistencyShake_192f;
    procedure Test95ConsistencyShake_256s;
    procedure Test95ConsistencySha2_256f;
    procedure Test95ConsistencyShake_256f;
    procedure Test95ConsistencySha2_128sWithSha256;
    procedure Test95ConsistencyShake_128sWithShake128;
    procedure Test95ConsistencySha2_128fWithSha256;
    procedure Test95ConsistencyShake_128fWithShake128;
    procedure Test95ConsistencyShake_192sWithShake256;
    procedure Test95ConsistencySha2_192fWithSha512;
    procedure Test95ConsistencyShake_192fWithShake256;
    procedure Test95ConsistencyShake_256sWithShake256;
    procedure Test95ConsistencySha2_256fWithSha512;
    procedure Test95ConsistencyShake_256fWithShake256;
    procedure TestHashSlhDsaKatSigSha2;
    procedure TestHashSlhDsaKatSigSha2WithContext;
    procedure TestHashSlhDsaRandomSigSha2;
    procedure TestHashSlhDsaRandomSigShake;
    procedure TestSlhDsaKatSigSha2;
    procedure TestSlhDsaKatSigSha2WithContext;
    procedure TestSlhDsaRandomSigSha2;
    procedure TestSlhDsaRandomSigShake;
  end;

  TTestSlhDsaSlow = class(TTestSlhDsa)
  published
    procedure Test01KeyGenAcvp128s;
    procedure Test03KeyGenAcvpShake192s;
    procedure Test14ContextFastSha2256f;
    procedure Test15ContextFastSha2256fSha512;
    procedure Test21ContextFastShake256fShake256;
    procedure Test95ConsistencySha2_192s;
    procedure Test95ConsistencySha2_256s;
    procedure Test95ConsistencySha2_192sWithSha512;
    procedure Test95ConsistencySha2_256sWithSha512;
    procedure Test30ContextSlowSha2128s;
    procedure Test31ContextSlowSha2128sSha256;
    procedure Test32ContextSlowSha2192s;
    procedure Test33ContextSlowSha2192sSha512;
    procedure Test34ContextSlowSha2256s;
    procedure Test35ContextSlowSha2256sSha512;
    procedure Test36ContextSlowShake128s;
    procedure Test37ContextSlowShake128sShake128;
    procedure Test38ContextSlowShake192s;
    procedure Test39ContextSlowShake192sShake256;
    procedure Test40ContextSlowShake256s;
    procedure Test41ContextSlowShake256sShake256;
    procedure Test98SigGen;
    procedure Test98SigGenAcvpSha2192s;
    procedure Test98SigGenAcvpSha2256f;
    procedure Test98SigGenAcvpShake128f;
    procedure Test98SigGenAcvpShake192s;
    procedure Test98SigGenAcvpShake256f;
    procedure Test98SigVer;
    procedure Test98SigVerAcvpSha2192s;
    procedure Test98SigVerAcvpSha2256f;
    procedure Test98SigVerAcvpShake128f;
    procedure Test98SigVerAcvpShake192s;
    procedure Test98SigVerAcvpShake256f;
    procedure Test99KeyGen;
  end;

  TSlhDsaSignerKatVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
  public
    constructor Create(ATest: TTestSlhDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSlhDsaKeyGenFileCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
  public
    constructor Create(ATest: TTestSlhDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSlhDsaKeyGenVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
    FParameters: ISlhDsaParameters;
  public
    constructor Create(ATest: TTestSlhDsa; const AParameters: ISlhDsaParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSlhDsaContextVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
    FParameters: ISlhDsaParameters;
    FSampler: TPqcTestSampler;
    FSampleOnly: Boolean;
  public
    constructor Create(ATest: TTestSlhDsa; const AParameters: ISlhDsaParameters;
      ASampleOnly: Boolean);
    destructor Destroy; override;
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSlhDsaSigGenFileCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
  public
    constructor Create(ATest: TTestSlhDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSlhDsaSigGenVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
    FParameters: ISlhDsaParameters;
  public
    constructor Create(ATest: TTestSlhDsa; const AParameters: ISlhDsaParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSlhDsaSigVerFileCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
  public
    constructor Create(ATest: TTestSlhDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSlhDsaSigVerVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestSlhDsa;
    FParameters: ISlhDsaParameters;
  public
    constructor Create(ATest: TTestSlhDsa; const AParameters: ISlhDsaParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

implementation

{ TSlhDsaSignerKatVectorCallback }

constructor TSlhDsaSignerKatVectorCallback.Create(ATest: TTestSlhDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TSlhDsaSignerKatVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSignerKat(AName, AData);
end;

{ TSlhDsaKeyGenFileCallback }

constructor TSlhDsaKeyGenFileCallback.Create(ATest: TTestSlhDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TSlhDsaKeyGenFileCallback.OnVector(const AName: string; const AData: TRspTxtRecord);
begin
  FTest.ImplKeyGen(AName, AData, FTest.GetParameters(AData['parameterSet']));
end;

{ TSlhDsaKeyGenVectorCallback }

constructor TSlhDsaKeyGenVectorCallback.Create(ATest: TTestSlhDsa;
  const AParameters: ISlhDsaParameters);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
end;

procedure TSlhDsaKeyGenVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplKeyGen(AName, AData, FParameters);
end;

{ TSlhDsaContextVectorCallback }

constructor TSlhDsaContextVectorCallback.Create(ATest: TTestSlhDsa;
  const AParameters: ISlhDsaParameters; ASampleOnly: Boolean);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
  FSampleOnly := ASampleOnly;
  if ASampleOnly then
    FSampler := TPqcTestSampler.Create
  else
    FSampler := nil;
end;

destructor TSlhDsaContextVectorCallback.Destroy;
begin
  FSampler.Free;
  inherited;
end;

procedure TSlhDsaContextVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  if FSampleOnly and FSampler.SkipTest(AData['count']) then
    Exit;
  FTest.ImplContext(AName, AData, FParameters);
end;

{ TSlhDsaSigGenFileCallback }

constructor TSlhDsaSigGenFileCallback.Create(ATest: TTestSlhDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TSlhDsaSigGenFileCallback.OnVector(const AName: string; const AData: TRspTxtRecord);
begin
  FTest.ImplSigGen(AName, AData, FTest.GetParameters(AData['parameterSet']));
end;

{ TSlhDsaSigGenVectorCallback }

constructor TSlhDsaSigGenVectorCallback.Create(ATest: TTestSlhDsa;
  const AParameters: ISlhDsaParameters);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
end;

procedure TSlhDsaSigGenVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSigGen(AName, AData, FParameters);
end;

{ TSlhDsaSigVerFileCallback }

constructor TSlhDsaSigVerFileCallback.Create(ATest: TTestSlhDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TSlhDsaSigVerFileCallback.OnVector(const AName: string; const AData: TRspTxtRecord);
begin
  FTest.ImplSigVer(AName, AData, FTest.GetParameters(AData['parameterSet']));
end;

{ TSlhDsaSigVerVectorCallback }

constructor TSlhDsaSigVerVectorCallback.Create(ATest: TTestSlhDsa;
  const AParameters: ISlhDsaParameters);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
end;

procedure TSlhDsaSigVerVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSigVer(AName, AData, FParameters);
end;

{ TTestSlhDsa }

procedure TTestSlhDsa.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create as ISecureRandom;
end;

function TTestSlhDsa.GetParameters(const AName: string): ISlhDsaParameters;
begin
  Result := TSlhDsaParameters.GetByName(AName);
  CheckNotNull(Result, 'unknown parameter set: ' + AName);
end;

function TTestSlhDsa.CreateSigner(const AParameters: ISlhDsaParameters;
  ADeterministic: Boolean): ISigner;
begin
  if AParameters.GetIsPreHash then
    Result := THashSlhDsaSigner.Create(AParameters, ADeterministic)
  else
    Result := TSlhDsaSigner.Create(AParameters, ADeterministic);
end;

procedure TTestSlhDsa.RunContextVectors(const ARelativePath: string;
  const AParameters: ISlhDsaParameters; ASampleOnly: Boolean);
var
  LCallback: TRspTxtVectorCallback;
begin
  LCallback := TSlhDsaContextVectorCallback.Create(Self, AParameters, ASampleOnly);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/SlhDsa/' + ARelativePath, LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestSlhDsa.RunKeyGenAcvp(const ARelativePath: string;
  const AParameters: ISlhDsaParameters);
var
  LCallback: TRspTxtVectorCallback;
begin
  LCallback := TSlhDsaKeyGenVectorCallback.Create(Self, AParameters);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/SlhDsa/Acvp/' + ARelativePath, LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestSlhDsa.RunSigGen(const ARelativePath: string;
  const AParameters: ISlhDsaParameters);
var
  LCallback: TRspTxtVectorCallback;
begin
  if AParameters <> nil then
    LCallback := TSlhDsaSigGenVectorCallback.Create(Self, AParameters)
  else
    LCallback := TSlhDsaSigGenFileCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors(ARelativePath, LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestSlhDsa.RunSigVer(const ARelativePath: string;
  const AParameters: ISlhDsaParameters);
var
  LCallback: TRspTxtVectorCallback;
begin
  if AParameters <> nil then
    LCallback := TSlhDsaSigVerVectorCallback.Create(Self, AParameters)
  else
    LCallback := TSlhDsaSigVerFileCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors(ARelativePath, LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestSlhDsa.ImplConsistency(const AParameters: ISlhDsaParameters);
var
  LMsg: TCryptoLibByteArray;
  LMsgLen: Int32;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LSigner: ISigner;
  LSignature: TCryptoLibByteArray;
begin
  SetLength(LMsg, 256);
  LKpg := TSlhDsaKeyPairGenerator.Create;
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(FRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LSigner := CreateSigner(AParameters, False);
  LMsgLen := (FRandom.NextInt32() and MaxInt) mod (System.Length(LMsg) + 1);
  FRandom.NextBytes(LMsg, 0, LMsgLen);
  LSigner.Init(True, TParametersWithRandom.Create(LKp.Private, FRandom) as IParametersWithRandom);
  LSigner.BlockUpdate(LMsg, 0, LMsgLen);
  LSignature := LSigner.GenerateSignature;
  LSigner.Init(False, LKp.Public);
  LSigner.BlockUpdate(LMsg, 0, LMsgLen);
  CheckTrue(LSigner.VerifySignature(LSignature), AParameters.Name + ': consistency verify failed');
end;

procedure TTestSlhDsa.ImplKeyGen(const AName: string; const AData: TRspTxtRecord;
  const AParameters: ISlhDsaParameters);
var
  LSkSeed, LSkPrf, LPkSeed, LPk, LSk: TCryptoLibByteArray;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: ISlhDsaPrivateKeyParameters;
  LPublicKey: ISlhDsaPublicKeyParameters;
  LPrivateKeyRT: ISlhDsaPrivateKeyParameters;
  LPublicKeyRT: ISlhDsaPublicKeyParameters;
begin
  LSkSeed := DecodeHex(AData['skSeed']);
  LSkPrf := DecodeHex(AData['skPrf']);
  LPkSeed := DecodeHex(AData['pkSeed']);
  LPk := DecodeHex(AData['pk']);
  LSk := DecodeHex(AData['sk']);

  LRandom := TFixedSecureRandom.From(
    TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LSkSeed, LSkPrf, LPkSeed));
  LKpg := TSlhDsaKeyPairGenerator.Create;
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(LRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LPrivateKey := LKp.Private as ISlhDsaPrivateKeyParameters;
  LPublicKey := LKp.Public as ISlhDsaPublicKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKey.GetEncoded), AName + ': pk');
  CheckTrue(AreEqual(LSk, LPrivateKey.GetEncoded), AName + ': sk');

  LPublicKeyRT := TPublicKeyFactory.CreateKey(
    TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey)) as ISlhDsaPublicKeyParameters;
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey)) as ISlhDsaPrivateKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKeyRT.GetEncoded), AName + ': pk (round-trip)');
  CheckTrue(AreEqual(LSk, LPrivateKeyRT.GetEncoded), AName + ': sk (round-trip)');
end;

procedure TTestSlhDsa.ImplContext(const AName: string; const AData: TRspTxtRecord;
  const AParameters: ISlhDsaParameters);
var
  LCount, LContextValue: string;
  LSeed, LMsg, LPk, LSk, LSm, LOptRand, LGenerated: TCryptoLibByteArray;
  LContext: TCryptoLibByteArray;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: ISlhDsaPrivateKeyParameters;
  LPublicKey: ISlhDsaPublicKeyParameters;
  LPrivateKeyRT: ISlhDsaPrivateKeyParameters;
  LPublicKeyRT: ISlhDsaPublicKeyParameters;
  LSigner: ISigner;
  LInitParams: ICipherParameters;
  LHasContext: Boolean;
begin
  LCount := AData['count'];
  LSeed := DecodeHex(AData['seed']);
  LMsg := DecodeHex(AData['msg']);
  LPk := DecodeHex(AData['pk']);
  LSk := DecodeHex(AData['sk']);
  LSm := DecodeHex(AData['sm']);
  LOptRand := DecodeHex(AData['optrand']);
  LContextValue := AData['context'];
  LHasContext := not SameText(LContextValue, 'none');
  if SameText(LContextValue, 'zero_length') then
    SetLength(LContext, 0)
  else if LHasContext then
    LContext := DecodeHex(LContextValue);

  LRandom := TFixedSecureRandom.From(TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LSeed));
  LKpg := TSlhDsaKeyPairGenerator.Create;
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(LRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LPrivateKey := LKp.Private as ISlhDsaPrivateKeyParameters;
  LPublicKey := LKp.Public as ISlhDsaPublicKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKey.GetEncoded), AName + ' ' + LCount + ': pk');
  CheckTrue(AreEqual(LSk, LPrivateKey.GetEncoded), AName + ' ' + LCount + ': sk');

  LPublicKeyRT := TPublicKeyFactory.CreateKey(
    TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey)) as ISlhDsaPublicKeyParameters;
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey)) as ISlhDsaPrivateKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKeyRT.GetEncoded), AName + ' ' + LCount + ': pk (round-trip)');
  CheckTrue(AreEqual(LSk, LPrivateKeyRT.GetEncoded), AName + ' ' + LCount + ': sk (round-trip)');

  if not LHasContext then
    Exit;

  LSigner := CreateSigner(AParameters, False);
  LInitParams := TParameterUtilities.WithContext(
    TParameterUtilities.WithRandom(LPrivateKey,
      TFixedSecureRandom.From(TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LOptRand))),
    LContext, SameText(LContextValue, 'zero_length'));
  LSigner.Init(True, LInitParams);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LGenerated := LSigner.GenerateSignature;
  CheckTrue(AreEqual(LSm, LGenerated), AName + ' ' + LCount + ': GenerateSignature');

  LInitParams := TParameterUtilities.WithContext(LPublicKey, LContext,
    SameText(LContextValue, 'zero_length'));
  LSigner := CreateSigner(AParameters, False);
  LSigner.Init(False, LInitParams);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckTrue(LSigner.VerifySignature(LSm), AName + ' ' + LCount + ': VerifySignature');
end;

procedure TTestSlhDsa.ImplSigGen(const AName: string; const AData: TRspTxtRecord;
  const AParameters: ISlhDsaParameters);
var
  LSk, LMessage, LSignature, LAdditionalRandomness, LGenerated: TCryptoLibByteArray;
  LPrivateKey: ISlhDsaPrivateKeyParameters;
  LPrivateKeyConcrete: TSlhDsaPrivateKeyParameters;
begin
  LSk := DecodeHex(AData['sk']);
  LMessage := DecodeHex(AData['message']);
  LSignature := DecodeHex(AData['signature']);
  if AData.ContainsKey('additionalRandomness') then
    LAdditionalRandomness := DecodeHex(AData['additionalRandomness'])
  else
    LAdditionalRandomness := nil;
  LPrivateKey := TSlhDsaPrivateKeyParameters.FromEncoding(AParameters, LSk);
  LPrivateKeyConcrete := LPrivateKey as TSlhDsaPrivateKeyParameters;
  LGenerated := LPrivateKeyConcrete.SignRaw(LAdditionalRandomness, LMessage, 0, System.Length(LMessage));
  CheckTrue(AreEqual(LGenerated, LSignature), AName + ': signature');
end;

procedure TTestSlhDsa.ImplSigVer(const AName: string; const AData: TRspTxtRecord;
  const AParameters: ISlhDsaParameters);
var
  LTestPassed: Boolean;
  LPk, LMessage, LSignature: TCryptoLibByteArray;
  LPublicKey: ISlhDsaPublicKeyParameters;
  LPublicKeyConcrete: TSlhDsaPublicKeyParameters;
  LVerified: Boolean;
begin
  LTestPassed := SameText(AData['testPassed'], 'true');
  LPk := DecodeHex(AData['pk']);
  LMessage := DecodeHex(AData['message']);
  LSignature := DecodeHex(AData['signature']);
  LPublicKey := TSlhDsaPublicKeyParameters.FromEncoding(AParameters, LPk);
  LPublicKeyConcrete := LPublicKey as TSlhDsaPublicKeyParameters;
  LVerified := LPublicKeyConcrete.VerifyRaw(LMessage, 0, System.Length(LMessage), LSignature);
  CheckTrue(LVerified = LTestPassed, AName + ': expected ' + SysUtils.BoolToStr(LTestPassed, True));
end;

procedure TTestSlhDsaFast.Test02KeyGenAcvp192f;
begin
  RunKeyGenAcvp('keyGen_SLH-DSA-SHA2-192f.txt', TSlhDsaParameters.SlhDsaSha2_192f);
end;

procedure TTestSlhDsaFast.Test04KeyGenAcvpShake256f;
begin
  RunKeyGenAcvp('keyGen_SLH-DSA-SHAKE-256f.txt', TSlhDsaParameters.SlhDsaShake_256f);
end;

procedure TTestSlhDsaFast.Test10ContextFastSha2128f;
begin
  RunContextVectors('sha2-128f.rsp', TSlhDsaParameters.SlhDsaSha2_128f, True);
end;

procedure TTestSlhDsaFast.Test11ContextFastSha2128fSha256;
begin
  RunContextVectors('sha2-128f-sha256.rsp', TSlhDsaParameters.SlhDsaSha2_128fWithSha256, True);
end;

procedure TTestSlhDsaFast.Test12ContextFastSha2192f;
begin
  RunContextVectors('sha2-192f.rsp', TSlhDsaParameters.SlhDsaSha2_192f, True);
end;

procedure TTestSlhDsaFast.Test13ContextFastSha2192fSha512;
begin
  RunContextVectors('sha2-192f-sha512.rsp', TSlhDsaParameters.SlhDsaSha2_192fWithSha512, True);
end;

procedure TTestSlhDsaFast.Test16ContextFastShake128f;
begin
  RunContextVectors('shake-128f.rsp', TSlhDsaParameters.SlhDsaShake_128f, True);
end;

procedure TTestSlhDsaFast.Test17ContextFastShake128fShake128;
begin
  RunContextVectors('shake-128f-shake128.rsp', TSlhDsaParameters.SlhDsaShake_128fWithShake128, True);
end;

procedure TTestSlhDsaFast.Test18ContextFastShake192f;
begin
  RunContextVectors('shake-192f.rsp', TSlhDsaParameters.SlhDsaShake_192f, True);
end;

procedure TTestSlhDsaFast.Test19ContextFastShake192fShake256;
begin
  RunContextVectors('shake-192f-shake256.rsp', TSlhDsaParameters.SlhDsaShake_192fWithShake256, True);
end;

procedure TTestSlhDsaFast.Test20ContextFastShake256f;
begin
  RunContextVectors('shake-256f.rsp', TSlhDsaParameters.SlhDsaShake_256f, True);
end;

procedure TTestSlhDsaSlow.Test01KeyGenAcvp128s;
begin
  RunKeyGenAcvp('keyGen_SLH-DSA-SHA2-128s.txt', TSlhDsaParameters.SlhDsaSha2_128s);
end;

procedure TTestSlhDsaSlow.Test03KeyGenAcvpShake192s;
begin
  RunKeyGenAcvp('keyGen_SLH-DSA-SHAKE-192s.txt', TSlhDsaParameters.SlhDsaShake_192s);
end;

procedure TTestSlhDsaSlow.Test14ContextFastSha2256f;
begin
  RunContextVectors('sha2-256f.rsp', TSlhDsaParameters.SlhDsaSha2_256f, True);
end;

procedure TTestSlhDsaSlow.Test15ContextFastSha2256fSha512;
begin
  RunContextVectors('sha2-256f-sha512.rsp', TSlhDsaParameters.SlhDsaSha2_256fWithSha512, True);
end;

procedure TTestSlhDsaSlow.Test21ContextFastShake256fShake256;
begin
  RunContextVectors('shake-256f-shake256.rsp', TSlhDsaParameters.SlhDsaShake_256fWithShake256, True);
end;

procedure TTestSlhDsaSlow.Test95ConsistencySha2_192s;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_192s);
end;

procedure TTestSlhDsaSlow.Test95ConsistencySha2_256s;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_256s);
end;

procedure TTestSlhDsaSlow.Test95ConsistencySha2_192sWithSha512;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_192sWithSha512);
end;

procedure TTestSlhDsaSlow.Test95ConsistencySha2_256sWithSha512;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_256sWithSha512);
end;

procedure TTestSlhDsaSlow.Test30ContextSlowSha2128s;
begin
  RunContextVectors('sha2-128s.rsp', TSlhDsaParameters.SlhDsaSha2_128s, True);
end;

procedure TTestSlhDsaSlow.Test31ContextSlowSha2128sSha256;
begin
  RunContextVectors('sha2-128s-sha256.rsp', TSlhDsaParameters.SlhDsaSha2_128sWithSha256, True);
end;

procedure TTestSlhDsaSlow.Test32ContextSlowSha2192s;
begin
  RunContextVectors('sha2-192s.rsp', TSlhDsaParameters.SlhDsaSha2_192s, True);
end;

procedure TTestSlhDsaSlow.Test33ContextSlowSha2192sSha512;
begin
  RunContextVectors('sha2-192s-sha512.rsp', TSlhDsaParameters.SlhDsaSha2_192sWithSha512, True);
end;

procedure TTestSlhDsaSlow.Test34ContextSlowSha2256s;
begin
  RunContextVectors('sha2-256s.rsp', TSlhDsaParameters.SlhDsaSha2_256s, True);
end;

procedure TTestSlhDsaSlow.Test35ContextSlowSha2256sSha512;
begin
  RunContextVectors('sha2-256s-sha512.rsp', TSlhDsaParameters.SlhDsaSha2_256sWithSha512, True);
end;

procedure TTestSlhDsaSlow.Test36ContextSlowShake128s;
begin
  RunContextVectors('shake-128s.rsp', TSlhDsaParameters.SlhDsaShake_128s, True);
end;

procedure TTestSlhDsaSlow.Test37ContextSlowShake128sShake128;
begin
  RunContextVectors('shake-128s-shake128.rsp', TSlhDsaParameters.SlhDsaShake_128sWithShake128, True);
end;

procedure TTestSlhDsaSlow.Test38ContextSlowShake192s;
begin
  RunContextVectors('shake-192s.rsp', TSlhDsaParameters.SlhDsaShake_192s, True);
end;

procedure TTestSlhDsaSlow.Test39ContextSlowShake192sShake256;
begin
  RunContextVectors('shake-192s-shake256.rsp', TSlhDsaParameters.SlhDsaShake_192sWithShake256, True);
end;

procedure TTestSlhDsaSlow.Test40ContextSlowShake256s;
begin
  RunContextVectors('shake-256s.rsp', TSlhDsaParameters.SlhDsaShake_256s, True);
end;

procedure TTestSlhDsaSlow.Test41ContextSlowShake256sShake256;
begin
  RunContextVectors('shake-256s-shake256.rsp', TSlhDsaParameters.SlhDsaShake_256sWithShake256, True);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_128s;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_128s);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_128s;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_128s);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_128f;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_128f);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_128f;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_128f);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_192s;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_192s);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_192f;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_192f);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_192f;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_192f);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_256s;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_256s);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_256f;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_256f);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_256f;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_256f);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_128sWithSha256;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_128sWithSha256);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_128sWithShake128;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_128sWithShake128);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_128fWithSha256;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_128fWithSha256);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_128fWithShake128;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_128fWithShake128);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_192sWithShake256;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_192sWithShake256);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_192fWithSha512;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_192fWithSha512);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_192fWithShake256;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_192fWithShake256);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_256sWithShake256;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_256sWithShake256);
end;

procedure TTestSlhDsaFast.Test95ConsistencySha2_256fWithSha512;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaSha2_256fWithSha512);
end;

procedure TTestSlhDsaFast.Test95ConsistencyShake_256fWithShake256;
begin
  ImplConsistency(TSlhDsaParameters.SlhDsaShake_256fWithShake256);
end;

procedure TTestSlhDsaSlow.Test98SigGen;
begin
  RunSigGen('Crypto/Pqc/SlhDsa/SLH-DSA-sigGen.txt', nil);
end;

procedure TTestSlhDsaSlow.Test98SigGenAcvpSha2192s;
begin
  RunSigGen('Crypto/Pqc/SlhDsa/Acvp/sigGen_SLH-DSA-SHA2-192s.txt', TSlhDsaParameters.SlhDsaSha2_192s);
end;

procedure TTestSlhDsaSlow.Test98SigGenAcvpSha2256f;
begin
  RunSigGen('Crypto/Pqc/SlhDsa/Acvp/sigGen_SLH-DSA-SHA2-256f.txt', TSlhDsaParameters.SlhDsaSha2_256f);
end;

procedure TTestSlhDsaSlow.Test98SigGenAcvpShake128f;
begin
  RunSigGen('Crypto/Pqc/SlhDsa/Acvp/sigGen_SLH-DSA-SHAKE-128f.txt', TSlhDsaParameters.SlhDsaShake_128f);
end;

procedure TTestSlhDsaSlow.Test98SigGenAcvpShake192s;
begin
  RunSigGen('Crypto/Pqc/SlhDsa/Acvp/sigGen_SLH-DSA-SHAKE-192s.txt', TSlhDsaParameters.SlhDsaShake_192s);
end;

procedure TTestSlhDsaSlow.Test98SigGenAcvpShake256f;
begin
  RunSigGen('Crypto/Pqc/SlhDsa/Acvp/sigGen_SLH-DSA-SHAKE-256f.txt', TSlhDsaParameters.SlhDsaShake_256f);
end;

procedure TTestSlhDsaSlow.Test98SigVer;
begin
  RunSigVer('Crypto/Pqc/SlhDsa/SLH-DSA-sigVer.txt', nil);
end;

procedure TTestSlhDsaSlow.Test98SigVerAcvpSha2192s;
begin
  RunSigVer('Crypto/Pqc/SlhDsa/Acvp/sigVer_SLH-DSA-SHA2-192s.txt', TSlhDsaParameters.SlhDsaSha2_192s);
end;

procedure TTestSlhDsaSlow.Test98SigVerAcvpSha2256f;
begin
  RunSigVer('Crypto/Pqc/SlhDsa/Acvp/sigVer_SLH-DSA-SHA2-256f.txt', TSlhDsaParameters.SlhDsaSha2_256f);
end;

procedure TTestSlhDsaSlow.Test98SigVerAcvpShake128f;
begin
  RunSigVer('Crypto/Pqc/SlhDsa/Acvp/sigVer_SLH-DSA-SHAKE-128f.txt', TSlhDsaParameters.SlhDsaShake_128f);
end;

procedure TTestSlhDsaSlow.Test98SigVerAcvpShake192s;
begin
  RunSigVer('Crypto/Pqc/SlhDsa/Acvp/sigVer_SLH-DSA-SHAKE-192s.txt', TSlhDsaParameters.SlhDsaShake_192s);
end;

procedure TTestSlhDsaSlow.Test98SigVerAcvpShake256f;
begin
  RunSigVer('Crypto/Pqc/SlhDsa/Acvp/sigVer_SLH-DSA-SHAKE-256f.txt', TSlhDsaParameters.SlhDsaShake_256f);
end;

procedure TTestSlhDsaSlow.Test99KeyGen;
var
  LCallback: TRspTxtVectorCallback;
begin
  LCallback := TSlhDsaKeyGenFileCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/SlhDsa/SLH-DSA-keyGen.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestSlhDsa.ImplSignerKat(const AName: string; const AData: TRspTxtRecord);
var
  LKeyGenParams, LSigParameters: ISlhDsaParameters;
  LKpgRandomSeed, LSigRandomSeed, LMsg, LExpectedSig, LContext, LGenerated: TCryptoLibByteArray;
  LUseContext: Boolean;
  LKpgRandom, LSigRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: ISlhDsaPrivateKeyParameters;
  LPublicKey: ISlhDsaPublicKeyParameters;
  LSigner: ISigner;
  LInitParams: ICipherParameters;
begin
  LKeyGenParams := GetParameters(AData['keyGenParameterSet']);
  LSigParameters := GetParameters(AData['sigParameterSet']);
  LKpgRandomSeed := DecodeHex(AData['kpgRandomSeed']);
  LSigRandomSeed := DecodeHex(AData['sigRandomSeed']);
  LMsg := DecodeHex(AData['msg']);
  LExpectedSig := DecodeHex(AData['sig']);
  LUseContext := AData.ContainsKey('context');
  if LUseContext then
    LContext := TConverters.ConvertStringToBytes(AData['context'], TEncoding.UTF8);

  LKpgRandom := TFixedSecureRandom.From(
    TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LKpgRandomSeed));
  LSigRandom := TFixedSecureRandom.From(
    TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LSigRandomSeed));

  LKpg := TGeneratorUtilities.GetKeyPairGenerator('SLH-DSA');
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(LKpgRandom, LKeyGenParams)
    as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LPrivateKey := LKp.Private as ISlhDsaPrivateKeyParameters;
  LPublicKey := LKp.Public as ISlhDsaPublicKeyParameters;

  if LUseContext then
  begin
    LSigner := TSignerUtilities.GetSigner(LSigParameters.Oid);
    LInitParams := TParameterUtilities.WithContext(
      TParameterUtilities.WithRandom(LPrivateKey, LSigRandom), LContext);
    LSigner.Init(True, LInitParams);
  end
  else
    LSigner := TSignerUtilities.InitSigner(LSigParameters.Oid, True, LPrivateKey, LSigRandom);

  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LGenerated := LSigner.GenerateSignature;
  CheckTrue(AreEqual(LExpectedSig, LGenerated), AName + ': GenerateSignature');

  if LUseContext then
  begin
    LSigner := TSignerUtilities.GetSigner(LSigParameters.Oid);
    LInitParams := TParameterUtilities.WithContext(LPublicKey, LContext);
    LSigner.Init(False, LInitParams);
  end
  else
    LSigner := TSignerUtilities.InitSigner(LSigParameters.Oid, False, LPublicKey, nil);

  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckTrue(LSigner.VerifySignature(LGenerated), AName + ': VerifySignature');
end;

procedure TTestSlhDsa.RunSignerKat(const ARelativePath: string);
var
  LCallback: TRspTxtVectorCallback;
begin
  LCallback := TSlhDsaSignerKatVectorCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors(ARelativePath, LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestSlhDsaFast.TestHashSlhDsaKatSigSha2;
begin
  RunSignerKat('Crypto/Pqc/SlhDsa/Kat/hashSlhDsa128fSha256.txt');
end;

procedure TTestSlhDsaFast.TestHashSlhDsaKatSigSha2WithContext;
begin
  RunSignerKat('Crypto/Pqc/SlhDsa/Kat/hashSlhDsa128fSha256WithContext.txt');
end;

procedure TTestSlhDsaFast.TestHashSlhDsaRandomSigSha2;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LMessage, LSignature: TCryptoLibByteArray;
  LSigner: ISigner;
begin
  LMessage := TConverters.ConvertStringToBytes(SLH_DSA_RANDOM_MESSAGE, TEncoding.UTF8);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('SLH-DSA');
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(FRandom,
    TSlhDsaParameters.SlhDsaSha2_256fWithSha512) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdHashSlhDsaSha2_256fWithSha512,
    True, LKp.Private, FRandom);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.GenerateSignature;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdHashSlhDsaSha2_256fWithSha512,
    False, LKp.Public, nil);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  CheckTrue(LSigner.VerifySignature(LSignature));
end;

procedure TTestSlhDsaFast.TestHashSlhDsaRandomSigShake;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LMessage, LSignature: TCryptoLibByteArray;
  LSigner: ISigner;
begin
  LMessage := TConverters.ConvertStringToBytes(SLH_DSA_RANDOM_MESSAGE, TEncoding.UTF8);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('SLH-DSA');
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(FRandom,
    TSlhDsaParameters.SlhDsaShake_256fWithShake256) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdHashSlhDsaShake_256fWithShake256,
    True, LKp.Private, FRandom);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.GenerateSignature;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdHashSlhDsaShake_256fWithShake256,
    False, LKp.Public, nil);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  CheckTrue(LSigner.VerifySignature(LSignature));
end;

procedure TTestSlhDsaFast.TestSlhDsaKatSigSha2;
begin
  RunSignerKat('Crypto/Pqc/SlhDsa/Kat/slhDsa128f.txt');
end;

procedure TTestSlhDsaFast.TestSlhDsaKatSigSha2WithContext;
begin
  RunSignerKat('Crypto/Pqc/SlhDsa/Kat/slhDsa128fWithContext.txt');
end;

procedure TTestSlhDsaFast.TestSlhDsaRandomSigSha2;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LMessage, LSignature: TCryptoLibByteArray;
  LSigner: ISigner;
begin
  LMessage := TConverters.ConvertStringToBytes(SLH_DSA_RANDOM_MESSAGE, TEncoding.UTF8);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('SLH-DSA');
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(FRandom, TSlhDsaParameters.SlhDsaSha2_256f)
    as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdSlhDsaSha2_256f,
    True, LKp.Private, FRandom);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.GenerateSignature;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdSlhDsaSha2_256f,
    False, LKp.Public, nil);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  CheckTrue(LSigner.VerifySignature(LSignature));
end;

procedure TTestSlhDsaFast.TestSlhDsaRandomSigShake;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LMessage, LSignature: TCryptoLibByteArray;
  LSigner: ISigner;
begin
  LMessage := TConverters.ConvertStringToBytes(SLH_DSA_RANDOM_MESSAGE, TEncoding.UTF8);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('SLH-DSA');
  LKpg.Init(TSlhDsaKeyGenerationParameters.Create(FRandom, TSlhDsaParameters.SlhDsaShake_256f)
    as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdSlhDsaShake_256f,
    True, LKp.Private, FRandom);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.GenerateSignature;
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdSlhDsaShake_256f,
    False, LKp.Public, nil);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  CheckTrue(LSigner.VerifySignature(LSignature));
end;

initialization

{$IFDEF FPC}
RegisterTest(TTestSlhDsaFast);
//RegisterTest(TTestSlhDsaSlow);
{$ELSE}
RegisterTest(TTestSlhDsaFast.Suite);
//RegisterTest(TTestSlhDsaSlow.Suite);
{$ENDIF FPC}

end.
