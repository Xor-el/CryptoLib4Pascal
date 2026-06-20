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

unit MlDsaTests;

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
  CryptoLibTestBase,
  PqcTestVectors,
  RspTxtVectorParser,
  FixedSecureRandom,
  ClpMlDsaParameters,
  ClpIMlDsaParameters,
  ClpMlDsaGenerators,
  ClpMlDsaSigner,
  ClpHashMlDsaSigner,
  ClpISigner,
  ClpSignerUtilities,
  ClpGeneratorUtilities,
  ClpNistObjectIdentifiers,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpConverters,
  ClpIX509Asn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPrivateKeyFactory,
  ClpPublicKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyGenerationParameters,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpParameterUtilities,
  ClpICipherParameters,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpCryptoLibTypes,
  NistSecureRandom;

type
  TTestMlDsa = class(TCryptoLibAlgorithmTestCase)
  private
    FRandom: ISecureRandom;
    procedure ImplConsistency(const AParameters: IMlDsaParameters);
    procedure ImplKeyGen(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlDsaParameters);
    procedure ImplContext(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlDsaParameters);
    procedure ImplSigGen(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlDsaParameters);
    procedure ImplSigVer(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlDsaParameters);
    function GetParameters(const AName: string): IMlDsaParameters;
    function CreateSigner(const AParameters: IMlDsaParameters;
      ADeterministic: Boolean): ISigner;
    procedure RunSignerKat(const ARelativePath: string);
    procedure ImplSignerKat(const AName: string; const AData: TRspTxtRecord);
  published
    procedure TestConsistency44;
    procedure TestConsistency65;
    procedure TestConsistency87;
    procedure TestKeyGen;
    procedure TestKeyGenAcvp44;
    procedure TestKeyGenAcvp65;
    procedure TestKeyGenAcvp87;
    procedure TestContext44;
    procedure TestContext65;
    procedure TestContext87;
    procedure TestContext44Sha512;
    procedure TestContext65Sha512;
    procedure TestContext87Sha512;
    procedure TestSigGen;
    procedure TestSigGenAcvp44;
    procedure TestSigGenAcvp65;
    procedure TestSigGenAcvp87;
    procedure TestSigVer;
    procedure TestSigVerAcvp44;
    procedure TestSigVerAcvp65;
    procedure TestSigVerAcvp87;
    procedure TestHashMlDsaKatSig;
    procedure TestHashMlDsaKatSigWithContext;
    procedure TestHashMlDsaRandomSig;
    procedure TestMlDsaKatSig;
    procedure TestMlDsaKatSigWithContext;
    procedure TestMlDsaRandomSig;
  public
    procedure SetUp; override;
  end;

  TSignerKatVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
  public
    constructor Create(ATest: TTestMlDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TKeyGenVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
    FParameters: IMlDsaParameters;
  public
    constructor Create(ATest: TTestMlDsa; const AParameters: IMlDsaParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TKeyGenFileCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
  public
    constructor Create(ATest: TTestMlDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TContextVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
    FParameters: IMlDsaParameters;
  public
    constructor Create(ATest: TTestMlDsa; const AParameters: IMlDsaParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSigGenVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
    FParameters: IMlDsaParameters;
  public
    constructor Create(ATest: TTestMlDsa; const AParameters: IMlDsaParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSigGenFileCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
  public
    constructor Create(ATest: TTestMlDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSigVerVectorCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
    FParameters: IMlDsaParameters;
  public
    constructor Create(ATest: TTestMlDsa; const AParameters: IMlDsaParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

  TSigVerFileCallback = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlDsa;
  public
    constructor Create(ATest: TTestMlDsa);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

implementation

{ TKeyGenVectorCallback }

constructor TKeyGenVectorCallback.Create(ATest: TTestMlDsa;
  const AParameters: IMlDsaParameters);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
end;

procedure TKeyGenVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplKeyGen(AName, AData, FParameters);
end;

{ TKeyGenFileCallback }

constructor TKeyGenFileCallback.Create(ATest: TTestMlDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TKeyGenFileCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplKeyGen(AName, AData, FTest.GetParameters(AData['parameterSet']));
end;

{ TContextVectorCallback }

constructor TContextVectorCallback.Create(ATest: TTestMlDsa;
  const AParameters: IMlDsaParameters);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
end;

procedure TContextVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplContext(AName, AData, FParameters);
end;

{ TSigGenVectorCallback }

constructor TSigGenVectorCallback.Create(ATest: TTestMlDsa;
  const AParameters: IMlDsaParameters);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
end;

procedure TSigGenVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSigGen(AName, AData, FParameters);
end;

{ TSigGenFileCallback }

constructor TSigGenFileCallback.Create(ATest: TTestMlDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TSigGenFileCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSigGen(AName, AData, FTest.GetParameters(AData['parameterSet']));
end;

{ TSigVerVectorCallback }

constructor TSigVerVectorCallback.Create(ATest: TTestMlDsa;
  const AParameters: IMlDsaParameters);
begin
  inherited Create;
  FTest := ATest;
  FParameters := AParameters;
end;

procedure TSigVerVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSigVer(AName, AData, FParameters);
end;

{ TSigVerFileCallback }

constructor TSigVerFileCallback.Create(ATest: TTestMlDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TSigVerFileCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSigVer(AName, AData, FTest.GetParameters(AData['parameterSet']));
end;

{ TSignerKatVectorCallback }

constructor TSignerKatVectorCallback.Create(ATest: TTestMlDsa);
begin
  inherited Create;
  FTest := ATest;
end;

procedure TSignerKatVectorCallback.OnVector(const AName: string;
  const AData: TRspTxtRecord);
begin
  FTest.ImplSignerKat(AName, AData);
end;

{ TTestMlDsa }

procedure TTestMlDsa.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create as ISecureRandom;
end;

function TTestMlDsa.GetParameters(const AName: string): IMlDsaParameters;
begin
  Result := TMlDsaParameters.GetByName(AName);
  CheckNotNull(Result, 'unknown parameter set: ' + AName);
end;

function TTestMlDsa.CreateSigner(const AParameters: IMlDsaParameters;
  ADeterministic: Boolean): ISigner;
begin
  if AParameters.IsPreHash then
    Result := THashMlDsaSigner.Create(AParameters, ADeterministic)
  else
    Result := TMlDsaSigner.Create(AParameters, ADeterministic);
end;

procedure TTestMlDsa.ImplConsistency(const AParameters: IMlDsaParameters);
var
  LMsg: TCryptoLibByteArray;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LSigner: ISigner;
  LMsgLen, LI, LJ: Int32;
  LKp: IAsymmetricCipherKeyPair;
  LSignature: TCryptoLibByteArray;
begin
  System.SetLength(LMsg, 2048);
  LKpg := TMlDsaKeyPairGenerator.Create;
  LKpg.Init(TMlDsaKeyGenerationParameters.Create(FRandom, AParameters) as IKeyGenerationParameters);
  LMsgLen := 0;
  repeat
    for LI := 0 to 1 do
    begin
      LKp := LKpg.GenerateKeyPair();
      LSigner := CreateSigner(AParameters, False);
      for LJ := 0 to 1 do
      begin
        FRandom.NextBytes(LMsg, 0, LMsgLen);
        LSigner.Init(True, TParametersWithRandom.Create(LKp.Private, FRandom) as IParametersWithRandom);
        LSigner.BlockUpdate(LMsg, 0, LMsgLen);
        LSignature := LSigner.GenerateSignature();
        LSigner.Init(False, LKp.Public);
        LSigner.BlockUpdate(LMsg, 0, LMsgLen);
        CheckTrue(LSigner.VerifySignature(LSignature), 'consistency verify failed');
      end;
    end;
    if LMsgLen < 128 then
      Inc(LMsgLen)
    else
      Inc(LMsgLen, 17);
  until LMsgLen > 2048;
end;

procedure TTestMlDsa.TestConsistency44;
begin
  ImplConsistency(TMlDsaParameters.MlDsa44);
end;

procedure TTestMlDsa.TestConsistency65;
begin
  ImplConsistency(TMlDsaParameters.MlDsa65);
end;

procedure TTestMlDsa.TestConsistency87;
begin
  ImplConsistency(TMlDsaParameters.MlDsa87);
end;

procedure TTestMlDsa.ImplKeyGen(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlDsaParameters);
var
  LSeed, LPk, LSk: TCryptoLibByteArray;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlDsaPrivateKeyParameters;
  LPublicKey: IMlDsaPublicKeyParameters;
  LPrivateKeyRT: IMlDsaPrivateKeyParameters;
  LPublicKeyRT: IMlDsaPublicKeyParameters;
begin
  LSeed := DecodeHex(AData['seed']);
  LPk := DecodeHex(AData['pk']);
  LSk := DecodeHex(AData['sk']);
  LRandom := TFixedSecureRandom.From(TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LSeed));
  LKpg := TMlDsaKeyPairGenerator.Create;
  LKpg.Init(TMlDsaKeyGenerationParameters.Create(LRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPrivateKey := LKp.Private as IMlDsaPrivateKeyParameters;
  LPublicKey := LKp.Public as IMlDsaPublicKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKey.GetEncoded()), AName + ': pk');
  CheckTrue(AreEqual(LSk, LPrivateKey.GetEncoded()), AName + ': sk');
  LPublicKeyRT := TPublicKeyFactory.CreateKey(
    TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey)) as IMlDsaPublicKeyParameters;
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey)) as IMlDsaPrivateKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKeyRT.GetEncoded()), AName + ': pk (round-trip)');
  CheckTrue(AreEqual(LSk, LPrivateKeyRT.GetEncoded()), AName + ': sk (round-trip)');
end;

procedure TTestMlDsa.ImplContext(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlDsaParameters);
var
  LCount, LContextValue: string;
  LSeed, LMsg, LPk, LSk, LSm, LRnd, LGenerated: TCryptoLibByteArray;
  LContext: TCryptoLibByteArray;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlDsaPrivateKeyParameters;
  LPublicKey: IMlDsaPublicKeyParameters;
  LPrivateKeyConcrete: TMlDsaPrivateKeyParameters;
  LPublicKeyConcrete: TMlDsaPublicKeyParameters;
  LPrivateKeyRT: IMlDsaPrivateKeyParameters;
  LPublicKeyRT: IMlDsaPublicKeyParameters;
  LSigner: ISigner;
  LInitParams: ICipherParameters;
begin
  LCount := AData['count'];
  LSeed := DecodeHex(AData['seed']);
  LMsg := DecodeHex(AData['msg']);
  LPk := DecodeHex(AData['pk']);
  LSk := DecodeHex(AData['sk']);
  LSm := DecodeHex(AData['sm']);
  LContextValue := AData['context'];
  if SameText(LContextValue, 'zero_length') then
    SetLength(LContext, 0)
  else if not SameText(LContextValue, 'none') then
    LContext := DecodeHex(LContextValue);

  LRandom := TFixedSecureRandom.From(TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LSeed));
  LKpg := TMlDsaKeyPairGenerator.Create;
  LKpg.Init(TMlDsaKeyGenerationParameters.Create(LRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPrivateKey := LKp.Private as IMlDsaPrivateKeyParameters;
  LPublicKey := LKp.Public as IMlDsaPublicKeyParameters;
  LPrivateKeyConcrete := LPrivateKey as TMlDsaPrivateKeyParameters;
  LPublicKeyConcrete := LPublicKey as TMlDsaPublicKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKey.GetEncoded()), AName + ' ' + LCount + ': pk');
  CheckTrue(AreEqual(LSk, LPrivateKey.GetEncoded()), AName + ' ' + LCount + ': sk');

  LPublicKeyRT := TPublicKeyFactory.CreateKey(
    TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey)) as IMlDsaPublicKeyParameters;
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey)) as IMlDsaPrivateKeyParameters;
  CheckTrue(AreEqual(LPk, LPublicKeyRT.GetEncoded()), AName + ' ' + LCount + ': pk (round-trip)');
  CheckTrue(AreEqual(LSk, LPrivateKeyRT.GetEncoded()), AName + ' ' + LCount + ': sk (round-trip)');

  if SameText(LContextValue, 'none') then
  begin
    SetLength(LRnd, 32);
    LGenerated := LPrivateKeyConcrete.SignRaw(LRnd, LMsg, 0, System.Length(LMsg));
    CheckTrue(AreEqual(LSm, LGenerated), AName + ' ' + LCount + ': SignRaw');
    CheckTrue(LPublicKeyConcrete.VerifyRaw(LMsg, 0, System.Length(LMsg), LSm),
      AName + ' ' + LCount + ': VerifyRaw');
    Exit;
  end;

  LSigner := TSignerUtilities.GetSigner(AParameters.Oid, True);
  LInitParams := TParameterUtilities.WithContext(LPrivateKey, LContext,
    SameText(LContextValue, 'zero_length'));
  LSigner.Init(True, LInitParams);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LGenerated := LSigner.GenerateSignature();
  CheckTrue(AreEqual(LSm, LGenerated), AName + ' ' + LCount + ': GenerateSignature');

  LInitParams := TParameterUtilities.WithContext(LPublicKey, LContext,
    SameText(LContextValue, 'zero_length'));
  LSigner := TSignerUtilities.GetSigner(AParameters.Oid, True);
  LSigner.Init(False, LInitParams);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckTrue(LSigner.VerifySignature(LSm), AName + ' ' + LCount + ': VerifySignature');
end;

procedure TTestMlDsa.ImplSigGen(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlDsaParameters);
var
  LSk, LMessage, LSignature, LRnd, LGenerated: TCryptoLibByteArray;
  LPrivateKey: IMlDsaPrivateKeyParameters;
  LPrivateKeyConcrete: TMlDsaPrivateKeyParameters;
begin
  LSk := DecodeHex(AData['sk']);
  LMessage := DecodeHex(AData['message']);
  LSignature := DecodeHex(AData['signature']);
  if AData.ContainsKey('rnd') then
    LRnd := DecodeHex(AData['rnd'])
  else
    SetLength(LRnd, 32);
  LPrivateKey := TMlDsaPrivateKeyParameters.FromEncoding(AParameters, LSk);
  LPrivateKeyConcrete := LPrivateKey as TMlDsaPrivateKeyParameters;
  LGenerated := LPrivateKeyConcrete.SignRaw(LRnd, LMessage, 0, System.Length(LMessage));
  CheckTrue(AreEqual(LGenerated, LSignature), AName + ': signature');
end;

procedure TTestMlDsa.ImplSigVer(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlDsaParameters);
var
  LTestPassed: Boolean;
  LPk, LMessage, LSignature: TCryptoLibByteArray;
  LPublicKey: IMlDsaPublicKeyParameters;
  LPublicKeyConcrete: TMlDsaPublicKeyParameters;
  LVerified: Boolean;
begin
  LTestPassed := SameText(AData['testPassed'], 'true');
  LPk := DecodeHex(AData['pk']);
  LMessage := DecodeHex(AData['message']);
  LSignature := DecodeHex(AData['signature']);
  LPublicKey := TMlDsaPublicKeyParameters.FromEncoding(AParameters, LPk);
  LPublicKeyConcrete := LPublicKey as TMlDsaPublicKeyParameters;
  LVerified := LPublicKeyConcrete.VerifyRaw(LMessage, 0, System.Length(LMessage), LSignature);
  CheckEquals(LTestPassed, LVerified, AName + ': expected ' + SysUtils.BoolToStr(LTestPassed, True));
end;

procedure TTestMlDsa.TestKeyGen;
var
  LCallback: TKeyGenFileCallback;
begin
  LCallback := TKeyGenFileCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/ML-DSA-keyGen.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestKeyGenAcvp44;
var
  LCallback: TKeyGenVectorCallback;
begin
  LCallback := TKeyGenVectorCallback.Create(Self, TMlDsaParameters.MlDsa44);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/keyGen_ML-DSA-44.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestKeyGenAcvp65;
var
  LCallback: TKeyGenVectorCallback;
begin
  LCallback := TKeyGenVectorCallback.Create(Self, TMlDsaParameters.MlDsa65);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/keyGen_ML-DSA-65.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestKeyGenAcvp87;
var
  LCallback: TKeyGenVectorCallback;
begin
  LCallback := TKeyGenVectorCallback.Create(Self, TMlDsaParameters.MlDsa87);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/keyGen_ML-DSA-87.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestContext44;
var
  LCallback: TContextVectorCallback;
begin
  LCallback := TContextVectorCallback.Create(Self, TMlDsaParameters.MlDsa44);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/mldsa44.rsp', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestContext65;
var
  LCallback: TContextVectorCallback;
begin
  LCallback := TContextVectorCallback.Create(Self, TMlDsaParameters.MlDsa65);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/mldsa65.rsp', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestContext87;
var
  LCallback: TContextVectorCallback;
begin
  LCallback := TContextVectorCallback.Create(Self, TMlDsaParameters.MlDsa87);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/mldsa87.rsp', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestContext44Sha512;
var
  LCallback: TContextVectorCallback;
begin
  LCallback := TContextVectorCallback.Create(Self, TMlDsaParameters.MlDsa44WithSha512);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/mldsa44sha512.rsp', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestContext65Sha512;
var
  LCallback: TContextVectorCallback;
begin
  LCallback := TContextVectorCallback.Create(Self, TMlDsaParameters.MlDsa65WithSha512);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/mldsa65sha512.rsp', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestContext87Sha512;
var
  LCallback: TContextVectorCallback;
begin
  LCallback := TContextVectorCallback.Create(Self, TMlDsaParameters.MlDsa87WithSha512);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/mldsa87sha512.rsp', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigGen;
var
  LCallback: TSigGenFileCallback;
begin
  LCallback := TSigGenFileCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/ML-DSA-sigGen.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigGenAcvp44;
var
  LCallback: TSigGenVectorCallback;
begin
  LCallback := TSigGenVectorCallback.Create(Self, TMlDsaParameters.MlDsa44);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/sigGen_ML-DSA-44.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigGenAcvp65;
var
  LCallback: TSigGenVectorCallback;
begin
  LCallback := TSigGenVectorCallback.Create(Self, TMlDsaParameters.MlDsa65);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/sigGen_ML-DSA-65.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigGenAcvp87;
var
  LCallback: TSigGenVectorCallback;
begin
  LCallback := TSigGenVectorCallback.Create(Self, TMlDsaParameters.MlDsa87);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/sigGen_ML-DSA-87.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigVer;
var
  LCallback: TSigVerFileCallback;
begin
  LCallback := TSigVerFileCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/ML-DSA-sigVer.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigVerAcvp44;
var
  LCallback: TSigVerVectorCallback;
begin
  LCallback := TSigVerVectorCallback.Create(Self, TMlDsaParameters.MlDsa44);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/sigVer_ML-DSA-44.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigVerAcvp65;
var
  LCallback: TSigVerVectorCallback;
begin
  LCallback := TSigVerVectorCallback.Create(Self, TMlDsaParameters.MlDsa65);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/sigVer_ML-DSA-65.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestSigVerAcvp87;
var
  LCallback: TSigVerVectorCallback;
begin
  LCallback := TSigVerVectorCallback.Create(Self, TMlDsaParameters.MlDsa87);
  try
    TPqcTestVectors.RunVectors('Crypto/Pqc/MlDsa/Acvp/sigVer_ML-DSA-87.txt', LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.ImplSignerKat(const AName: string; const AData: TRspTxtRecord);
var
  LKeyGenOid: IDerObjectIdentifier;
  LSigParameters: IMlDsaParameters;
  LKatRandomSeed, LPubK, LMsg, LExpectedSig, LSeed, LContext, LGenerated: TCryptoLibByteArray;
  LUseContext, LCheckRandomDistinct, LRepeatWithMlDsa44Key: Boolean;
  LKatRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlDsaPrivateKeyParameters;
  LPublicKey: IMlDsaPublicKeyParameters;
  LPubInfo: ISubjectPublicKeyInfo;
  LPrivInfo: IPrivateKeyInfo;
  LSeedAndEncodingSeq: IAsn1Sequence;
  LSeedOctetString: IAsn1OctetString;
  LSigDet, LSigRnd: ISigner;
  LInitParams: ICipherParameters;

  procedure RunKeyGenAndSign(const AOid: IDerObjectIdentifier);
  begin
    LKpg := TGeneratorUtilities.GetKeyPairGenerator('ML-DSA');
    LKpg.Init(TMlDsaKeyGenerationParameters.Create(LKatRandom, AOid) as IKeyGenerationParameters);
    LKp := LKpg.GenerateKeyPair();
    LPrivateKey := LKp.Private as IMlDsaPrivateKeyParameters;
    LPublicKey := LKp.Public as IMlDsaPublicKeyParameters;

    LPubInfo := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey);
    CheckTrue(AreEqual(LPubK, LPubInfo.PublicKey.GetOctets), AName + ': public key');

    LPrivInfo := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey);
    LSeedAndEncodingSeq := TAsn1Sequence.GetInstance(LPrivInfo.PrivateKey.GetOctets);
    LSeedOctetString := TAsn1OctetString.GetInstance(LSeedAndEncodingSeq[0]);
    CheckTrue(AreEqual(LSeed, LSeedOctetString.GetOctets), AName + ': seed');

    LSigDet := TSignerUtilities.GetSigner(LSigParameters.Oid, True);
    LSigRnd := TSignerUtilities.GetSigner(LSigParameters.Oid);

    if LUseContext then
      LInitParams := TParameterUtilities.WithContext(LPrivateKey, LContext)
    else
      LInitParams := LPrivateKey;
    LSigDet.Init(True, LInitParams);
    LSigDet.BlockUpdate(LMsg, 0, System.Length(LMsg));
    LGenerated := LSigDet.GenerateSignature();
    CheckTrue(AreEqual(LExpectedSig, LGenerated), AName + ': GenerateSignature');

    if LUseContext then
      LInitParams := TParameterUtilities.WithContext(LPublicKey, LContext)
    else
      LInitParams := LPublicKey;
    LSigDet.Init(False, LInitParams);
    LSigDet.BlockUpdate(LMsg, 0, System.Length(LMsg));
    CheckTrue(LSigDet.VerifySignature(LExpectedSig), AName + ': VerifySignature');

    if LCheckRandomDistinct then
    begin
      if LUseContext then
        LInitParams := TParameterUtilities.WithContext(
          TParametersWithRandom.Create(LPrivateKey, FRandom) as IParametersWithRandom, LContext)
      else
        LInitParams := TParametersWithRandom.Create(LPrivateKey, FRandom) as IParametersWithRandom;
      LSigRnd.Init(True, LInitParams);
      LSigRnd.BlockUpdate(LMsg, 0, System.Length(LMsg));
      LGenerated := LSigRnd.GenerateSignature();
      CheckFalse(AreEqual(LExpectedSig, LGenerated), AName + ': random signature must differ');

      if LUseContext then
        LInitParams := TParameterUtilities.WithContext(LPublicKey, LContext)
      else
        LInitParams := LPublicKey;
      LSigRnd.Init(False, LInitParams);
      LSigRnd.BlockUpdate(LMsg, 0, System.Length(LMsg));
      CheckTrue(LSigRnd.VerifySignature(LGenerated), AName + ': VerifySignature random');
    end;
  end;

begin
  LKeyGenOid := GetParameters(AData['keyGenParameterSet']).Oid;
  LSigParameters := GetParameters(AData['sigParameterSet']);
  LKatRandomSeed := DecodeHex(AData['katRandomSeed']);
  LPubK := DecodeHex(AData['pubK']);
  LMsg := DecodeHex(AData['msg']);
  LExpectedSig := DecodeHex(AData['sig']);
  LSeed := DecodeHex(AData['seed']);
  LUseContext := AData.ContainsKey('context');
  if LUseContext then
    LContext := TConverters.ConvertStringToBytes(AData['context'], TEncoding.UTF8);
  LCheckRandomDistinct := SameText(AData['checkRandomDistinct'], 'true');
  LRepeatWithMlDsa44Key := SameText(AData['repeatWithMlDsa44Key'], 'true');

  LKatRandom := TNistSecureRandom.Create(LKatRandomSeed, nil) as ISecureRandom;
  RunKeyGenAndSign(LKeyGenOid);

  if LRepeatWithMlDsa44Key then
  begin
    LKatRandom := TNistSecureRandom.Create(LKatRandomSeed, nil) as ISecureRandom;
    RunKeyGenAndSign(TNistObjectIdentifiers.IdMlDsa44);
  end;
end;

procedure TTestMlDsa.RunSignerKat(const ARelativePath: string);
var
  LCallback: TSignerKatVectorCallback;
begin
  LCallback := TSignerKatVectorCallback.Create(Self);
  try
    TPqcTestVectors.RunVectors(ARelativePath, LCallback);
  finally
    LCallback.Free;
  end;
end;

procedure TTestMlDsa.TestHashMlDsaKatSig;
begin
  RunSignerKat('Crypto/Pqc/MlDsa/Kat/hashMlDsa44.txt');
end;

procedure TTestMlDsa.TestHashMlDsaKatSigWithContext;
begin
  RunSignerKat('Crypto/Pqc/MlDsa/Kat/hashMlDsa44WithContext.txt');
end;

procedure TTestMlDsa.TestHashMlDsaRandomSig;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LMessage, LSignature: TCryptoLibByteArray;
  LSigner: ISigner;
begin
  LMessage := TConverters.ConvertStringToBytes('Hello World!', TEncoding.UTF8);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ML-DSA');
  LKpg.Init(TMlDsaKeyGenerationParameters.Create(FRandom, TNistObjectIdentifiers.IdHashMlDsa44WithSha512)
    as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdHashMlDsa44WithSha512, True, LKp.Private, FRandom);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.GenerateSignature();
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdHashMlDsa44WithSha512, False, LKp.Public, nil);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  CheckTrue(LSigner.VerifySignature(LSignature));
end;

procedure TTestMlDsa.TestMlDsaKatSig;
begin
  RunSignerKat('Crypto/Pqc/MlDsa/Kat/mlDsa44.txt');
end;

procedure TTestMlDsa.TestMlDsaKatSigWithContext;
begin
  RunSignerKat('Crypto/Pqc/MlDsa/Kat/mlDsa44WithContext.txt');
end;

procedure TTestMlDsa.TestMlDsaRandomSig;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LMessage, LSignature: TCryptoLibByteArray;
  LSigner: ISigner;
begin
  LMessage := TConverters.ConvertStringToBytes('Hello World!', TEncoding.UTF8);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('ML-DSA');
  LKpg.Init(TMlDsaKeyGenerationParameters.Create(FRandom, TNistObjectIdentifiers.IdMlDsa44)
    as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdMlDsa44, True, LKp.Private, FRandom);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  LSignature := LSigner.GenerateSignature();
  LSigner := TSignerUtilities.InitSigner(TNistObjectIdentifiers.IdMlDsa44, False, LKp.Public, nil);
  LSigner.BlockUpdate(LMessage, 0, System.Length(LMessage));
  CheckTrue(LSigner.VerifySignature(LSignature));
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestMlDsa);
{$ELSE}
  RegisterTest(TTestMlDsa.Suite);
{$ENDIF FPC}

end.
