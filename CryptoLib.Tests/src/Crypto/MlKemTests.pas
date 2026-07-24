unit MlKemTests;

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
  NistSecureRandom,
  ClpMlKemParameters,
  ClpIMlKemParameters,
  ClpMlKemGenerators,
  ClpMlKemEncapsulator,
  ClpMlKemDecapsulator,
  ClpIKemEncapsulator,
  ClpIKemDecapsulator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIKeyGenerationParameters,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIMlKemEngine,
  ClpKemUtilities,
  ClpNistObjectIdentifiers,
  ClpPrivateKeyFactory,
  ClpPublicKeyFactory,
  ClpPrivateKeyInfoFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpDigestUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

type
  // ML-KEM vector worker: (name, record, parameters). The adapter supplies the
  // parameters, either a fixed set or one derived from the record.
  TMlKemVectorImpl = procedure(const AName: string; const AData: TRspTxtRecord;
    const AParameters: IMlKemParameters) of object;

  TTestMlKem = class(TCryptoLibAlgorithmTestCase)
  private
    FRandom: ISecureRandom;
    procedure ImplDecap(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlKemParameters);
    procedure ImplEncap(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlKemParameters);
    procedure ImplKeyGen(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlKemParameters);
    procedure ImplKatRsp(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlKemParameters);
    procedure ImplWithPreferredFormat(const APrivateKey: IMlKemPrivateKeyParameters;
      AFormat: TMlKemPrivateKeyFormat);
    procedure ImplConsistency(const AParameters: IMlKemParameters);
    procedure ImplModulus(const ARelativePath: string;
      const AParameters: IMlKemParameters);
    function GetParameters(const AName: string): IMlKemParameters;
    function LoadHexTestResource(const ARelativePath: string): TCryptoLibByteArray;
    // Dispatch a combined encap/decap record by its 'function' field.
    procedure ImplEncapDecap(const AName: string; const AData: TRspTxtRecord;
      const AParameters: IMlKemParameters);
    // Run a vector file through AImpl. AParameters nil => derive per record.
    procedure RunParamVectors(const ARelativePath: string;
      AImpl: TMlKemVectorImpl; const AParameters: IMlKemParameters);
  published
    procedure TestConsistency512;
    procedure TestConsistency768;
    procedure TestConsistency1024;
    procedure TestKeyGen;
    procedure TestKeyGenAcvp512;
    procedure TestKeyGenAcvp768;
    procedure TestKeyGenAcvp1024;
    procedure TestDecapAcvp512;
    procedure TestDecapAcvp768;
    procedure TestDecapAcvp1024;
    procedure TestEncapAcvp512;
    procedure TestEncapAcvp768;
    procedure TestEncapAcvp1024;
    procedure TestEncapDecap;
    procedure TestModulus512;
    procedure TestModulus768;
    procedure TestModulus1024;
    procedure TestKeys;
    procedure TestMlKem;
    procedure TestKat512;
    procedure TestKat768;
    procedure TestKat1024;
    procedure TestWithPreferredFormat;
    procedure TestRng;
    procedure TestKemUtilities;
  public
    procedure SetUp; override;
  end;

  // One adapter for every parameterised ML-KEM vector file: forwards each
  // record to FImpl with either the fixed FParameters or, when that is nil,
  // the parameter set named by the record's 'parameterSet' field.
  TMlKemParamVectorAdapter = class(TRspTxtVectorCallback)
  strict private
    FTest: TTestMlKem;
    FImpl: TMlKemVectorImpl;
    FParameters: IMlKemParameters;
  public
    constructor Create(ATest: TTestMlKem; AImpl: TMlKemVectorImpl;
      const AParameters: IMlKemParameters);
    procedure OnVector(const AName: string; const AData: TRspTxtRecord); override;
  end;

implementation

{ TMlKemParamVectorAdapter }

constructor TMlKemParamVectorAdapter.Create(ATest: TTestMlKem;
  AImpl: TMlKemVectorImpl; const AParameters: IMlKemParameters);
begin
  inherited Create();
  FTest := ATest;
  FImpl := AImpl;
  FParameters := AParameters;
end;

procedure TMlKemParamVectorAdapter.OnVector(const AName: string;
  const AData: TRspTxtRecord);
var
  LParameters: IMlKemParameters;
begin
  if Assigned(FParameters) then
    LParameters := FParameters
  else
    LParameters := FTest.GetParameters(AData['parameterSet']);
  FImpl(AName, AData, LParameters);
end;

{ TTestMlKem }

procedure TTestMlKem.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create as ISecureRandom;
end;

function TTestMlKem.GetParameters(const AName: string): IMlKemParameters;
begin
  Result := TMlKemParameters.GetByName(AName);
  CheckNotNull(Result, 'unknown parameter set: ' + AName);
end;

procedure TTestMlKem.RunParamVectors(const ARelativePath: string;
  AImpl: TMlKemVectorImpl; const AParameters: IMlKemParameters);
var
  LAdapter: TMlKemParamVectorAdapter;
begin
  LAdapter := TMlKemParamVectorAdapter.Create(Self, AImpl, AParameters);
  try
    TPqcTestVectors.RunVectors(ARelativePath, LAdapter);
  finally
    LAdapter.Free;
  end;
end;

procedure TTestMlKem.ImplEncapDecap(const AName: string;
  const AData: TRspTxtRecord; const AParameters: IMlKemParameters);
begin
  if AData['function'] = 'encapsulation' then
    ImplEncap(AName, AData, AParameters)
  else
    ImplDecap(AName, AData, AParameters);
end;

procedure TTestMlKem.ImplConsistency(const AParameters: IMlKemParameters);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LEnc: IKemEncapsulator;
  LDec: IKemDecapsulator;
  LI: Int32;
  LKp: IAsymmetricCipherKeyPair;
  LEncBuf, LSec1, LSec2: TCryptoLibByteArray;
begin
  LKpg := TMlKemKeyPairGenerator.Create;
  LKpg.Init(TMlKemKeyGenerationParameters.Create(FRandom, AParameters) as IKeyGenerationParameters);
  for LI := 0 to 99 do
  begin
    LKp := LKpg.GenerateKeyPair();
    LEnc := TMlKemEncapsulator.Create(AParameters);
    LEnc.Init(TParametersWithRandom.Create(LKp.Public, FRandom) as IParametersWithRandom);
    System.SetLength(LEncBuf, LEnc.EncapsulationLength);
    System.SetLength(LSec1, LEnc.SecretLength);
    LEnc.Encapsulate(LEncBuf, 0, System.Length(LEncBuf), LSec1, 0, System.Length(LSec1));
    LDec := TMlKemDecapsulator.Create(AParameters);
    LDec.Init(LKp.Private);
    System.SetLength(LSec2, LDec.SecretLength);
    LDec.Decapsulate(LEncBuf, 0, System.Length(LEncBuf), LSec2, 0, System.Length(LSec2));
    CheckTrue(AreEqual(LSec1, LSec2), 'consistency shared secret mismatch');
  end;
end;

procedure TTestMlKem.TestConsistency512;
begin
  ImplConsistency(TMlKemParameters.MlKem512);
end;

procedure TTestMlKem.TestConsistency768;
begin
  ImplConsistency(TMlKemParameters.MlKem768);
end;

procedure TTestMlKem.TestConsistency1024;
begin
  ImplConsistency(TMlKemParameters.MlKem1024);
end;

procedure TTestMlKem.ImplDecap(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlKemParameters);
var
  LC, LK, LDk: TCryptoLibByteArray;
  LPrivateKey: IMlKemPrivateKeyParameters;
  LDec: IKemDecapsulator;
  LSec: TCryptoLibByteArray;
begin
  LC := DecodeHex(AData['c']);
  LK := DecodeHex(AData['k']);
  LDk := DecodeHex(AData['dk']);
  LPrivateKey := TMlKemPrivateKeyParameters.FromEncoding(AParameters, LDk);
  LDec := TMlKemDecapsulator.Create(AParameters);
  LDec.Init(LPrivateKey);
  System.SetLength(LSec, LDec.SecretLength);
  LDec.Decapsulate(LC, 0, System.Length(LC), LSec, 0, System.Length(LSec));
  CheckTrue(AreEqual(LK, LSec), AName + ': k');
end;

procedure TTestMlKem.ImplEncap(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlKemParameters);
var
  LM, LC, LK, LEk: TCryptoLibByteArray;
  LPublicKey: IMlKemPublicKeyParameters;
  LEnc, LSec: TCryptoLibByteArray;
begin
  LM := DecodeHex(AData['m']);
  LC := DecodeHex(AData['c']);
  LK := DecodeHex(AData['k']);
  LEk := DecodeHex(AData['ek']);
  LPublicKey := TMlKemPublicKeyParameters.FromEncoding(AParameters, LEk);
  System.SetLength(LEnc, AParameters.ParameterSet.EncapsulationLength);
  System.SetLength(LSec, AParameters.ParameterSet.SecretLength);
  LPublicKey.Parameters.ParameterSet.Engine.KemEncrypt(LPublicKey.Encoding, LM, LEnc, 0, LSec, 0);
  CheckTrue(AreEqual(LC, LEnc), AName + ': c');
  CheckTrue(AreEqual(LK, LSec), AName + ': k');
end;

procedure TTestMlKem.ImplKeyGen(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlKemParameters);
var
  LZ, LD, LEk, LDk: TCryptoLibByteArray;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlKemPrivateKeyParameters;
  LPublicKey: IMlKemPublicKeyParameters;
  LPrivateKeyRT: IMlKemPrivateKeyParameters;
  LPublicKeyRT: IMlKemPublicKeyParameters;
begin
  LZ := DecodeHex(AData['z']);
  LD := DecodeHex(AData['d']);
  LEk := DecodeHex(AData['ek']);
  LDk := DecodeHex(AData['dk']);
  LRandom := TFixedSecureRandom.From(TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LD, LZ));
  LKpg := TMlKemKeyPairGenerator.Create;
  LKpg.Init(TMlKemKeyGenerationParameters.Create(LRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPrivateKey := LKp.Private as IMlKemPrivateKeyParameters;
  LPublicKey := LKp.Public as IMlKemPublicKeyParameters;
  CheckTrue(AreEqual(LDk, LPrivateKey.GetEncoded()), AName + ': dk');
  CheckTrue(AreEqual(LEk, LPublicKey.GetEncoded()), AName + ': ek');
  LPrivateKeyRT := TPrivateKeyFactory.CreateKey(
    TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPrivateKey)) as IMlKemPrivateKeyParameters;
  LPublicKeyRT := TPublicKeyFactory.CreateKey(
    TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPublicKey)) as IMlKemPublicKeyParameters;
  CheckTrue(AreEqual(LDk, LPrivateKeyRT.GetEncoded()), AName + ': dk (round-trip)');
  CheckTrue(AreEqual(LEk, LPublicKeyRT.GetEncoded()), AName + ': ek (round-trip)');
end;

procedure TTestMlKem.ImplWithPreferredFormat(const APrivateKey: IMlKemPrivateKeyParameters;
  AFormat: TMlKemPrivateKeyFormat);
var
  LUpdated: IMlKemPrivateKeyParameters;
begin
  LUpdated := APrivateKey.WithPreferredFormat(AFormat);
  CheckEquals(Ord(AFormat), Ord(LUpdated.PreferredFormat));
  CheckTrue(AreEqual(APrivateKey.GetSeed(), LUpdated.GetSeed()));
  CheckTrue(AreEqual(APrivateKey.GetEncoded(), LUpdated.GetEncoded()));
  if AFormat = APrivateKey.PreferredFormat then
    CheckTrue(APrivateKey = LUpdated, 'same instance when format unchanged');
end;

procedure TTestMlKem.ImplKatRsp(const AName: string; const AData: TRspTxtRecord;
  const AParameters: IMlKemParameters);
const
  SymBytes = 32;
var
  LRandom, LD, LZ, LM, LPk, LSk, LCt, LSs, LEnc, LSec, LDecSec: TCryptoLibByteArray;
  LKeyRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey, LGeneratedPrivateKey: IMlKemPrivateKeyParameters;
  LPublicKey, LGeneratedPublicKey: IMlKemPublicKeyParameters;
  LDecaps: IKemDecapsulator;
begin
  LRandom := DecodeHex(AData['random']);
  CheckEquals(SymBytes * 3, System.Length(LRandom), AName + ': random length');
  LD := System.Copy(LRandom, 0, SymBytes);
  LZ := System.Copy(LRandom, SymBytes, SymBytes);
  LM := System.Copy(LRandom, 2 * SymBytes, SymBytes);

  LPk := DecodeHex(AData['pk']);
  LSk := DecodeHex(AData['sk']);
  LCt := DecodeHex(AData['ct']);
  LSs := DecodeHex(AData['ss']);

  LKeyRandom := TFixedSecureRandom.From(TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LD, LZ));
  LKpg := TMlKemKeyPairGenerator.Create;
  LKpg.Init(TMlKemKeyGenerationParameters.Create(LKeyRandom, AParameters) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LGeneratedPrivateKey := LKp.Private as IMlKemPrivateKeyParameters;
  LGeneratedPublicKey := LKp.Public as IMlKemPublicKeyParameters;
  CheckTrue(AreEqual(LPk, LGeneratedPublicKey.GetEncoded()), AName + ': pk');
  CheckTrue(AreEqual(LSk, LGeneratedPrivateKey.GetEncoded()), AName + ': sk');

  System.SetLength(LEnc, AParameters.ParameterSet.EncapsulationLength);
  System.SetLength(LSec, AParameters.ParameterSet.SecretLength);
  LGeneratedPublicKey.Parameters.ParameterSet.Engine.KemEncrypt(
    LGeneratedPublicKey.Encoding, LM, LEnc, 0, LSec, 0);
  CheckTrue(AreEqual(LCt, LEnc), AName + ': ct');
  CheckTrue(AreEqual(LSs, LSec), AName + ': ss');

  LPrivateKey := TMlKemPrivateKeyParameters.FromEncoding(AParameters, LSk);
  LPublicKey := TMlKemPublicKeyParameters.FromEncoding(AParameters, LPk);
  CheckTrue(AreEqual(LPk, LPublicKey.GetEncoded()), AName + ': pk (encoding)');
  CheckTrue(AreEqual(LSk, LPrivateKey.GetEncoded()), AName + ': sk (encoding)');

  LDecaps := TMlKemDecapsulator.Create(AParameters);
  LDecaps.Init(LPrivateKey);
  System.SetLength(LDecSec, LDecaps.SecretLength);
  LDecaps.Decapsulate(LCt, 0, System.Length(LCt), LDecSec, 0, System.Length(LDecSec));
  CheckTrue(AreEqual(LSs, LDecSec), AName + ': ss (decap)');
end;

procedure TTestMlKem.TestKat512;
begin
  RunParamVectors('Crypto/Pqc/MlKem/mlkem512.rsp', ImplKatRsp, TMlKemParameters.MlKem512);
end;

procedure TTestMlKem.TestKat768;
begin
  RunParamVectors('Crypto/Pqc/MlKem/mlkem768.rsp', ImplKatRsp, TMlKemParameters.MlKem768);
end;

procedure TTestMlKem.TestKat1024;
begin
  RunParamVectors('Crypto/Pqc/MlKem/mlkem1024.rsp', ImplKatRsp, TMlKemParameters.MlKem1024);
end;

procedure TTestMlKem.TestKeyGen;
begin
  RunParamVectors('Crypto/Pqc/MlKem/ML-KEM-keyGen.txt', ImplKeyGen, nil);
end;

procedure TTestMlKem.TestKeyGenAcvp512;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/keyGen_ML-KEM-512.txt', ImplKeyGen, TMlKemParameters.MlKem512);
end;

procedure TTestMlKem.TestKeyGenAcvp768;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/keyGen_ML-KEM-768.txt', ImplKeyGen, TMlKemParameters.MlKem768);
end;

procedure TTestMlKem.TestKeyGenAcvp1024;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/keyGen_ML-KEM-1024.txt', ImplKeyGen, TMlKemParameters.MlKem1024);
end;

procedure TTestMlKem.TestDecapAcvp512;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/encapDecap_decapsulation_ML-KEM-512.txt', ImplDecap, TMlKemParameters.MlKem512);
end;

procedure TTestMlKem.TestDecapAcvp768;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/encapDecap_decapsulation_ML-KEM-768.txt', ImplDecap, TMlKemParameters.MlKem768);
end;

procedure TTestMlKem.TestDecapAcvp1024;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/encapDecap_decapsulation_ML-KEM-1024.txt', ImplDecap, TMlKemParameters.MlKem1024);
end;

procedure TTestMlKem.TestEncapAcvp512;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/encapDecap_encapsulation_ML-KEM-512.txt', ImplEncap, TMlKemParameters.MlKem512);
end;

procedure TTestMlKem.TestEncapAcvp768;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/encapDecap_encapsulation_ML-KEM-768.txt', ImplEncap, TMlKemParameters.MlKem768);
end;

procedure TTestMlKem.TestEncapAcvp1024;
begin
  RunParamVectors('Crypto/Pqc/MlKem/Acvp/encapDecap_encapsulation_ML-KEM-1024.txt', ImplEncap, TMlKemParameters.MlKem1024);
end;

procedure TTestMlKem.TestEncapDecap;
begin
  RunParamVectors('Crypto/Pqc/MlKem/ML-KEM-encapDecap.txt', ImplEncapDecap, nil);
end;

procedure TTestMlKem.TestModulus512;
begin
  ImplModulus('Crypto/Pqc/MlKem/Modulus/ML-KEM-512.txt',
    TMlKemParameters.MlKem512);
end;

procedure TTestMlKem.TestModulus768;
begin
  ImplModulus('Crypto/Pqc/MlKem/Modulus/ML-KEM-768.txt',
    TMlKemParameters.MlKem768);
end;

procedure TTestMlKem.TestModulus1024;
begin
  ImplModulus('Crypto/Pqc/MlKem/Modulus/ML-KEM-1024.txt',
    TMlKemParameters.MlKem1024);
end;

procedure TTestMlKem.ImplModulus(const ARelativePath: string;
  const AParameters: IMlKemParameters);
var
  LContent, LLine: string;
  LReader: TStringList;
  LI: Int32;
  LKey: TCryptoLibByteArray;
begin
  LContent := LoadTestResource(ARelativePath);
  LReader := TStringList.Create;
  try
    LReader.Text := LContent;
    for LI := 0 to LReader.Count - 1 do
    begin
      LLine := Trim(LReader[LI]);
      if LLine = '' then
        Continue;
      LKey := DecodeHex(LLine);
      try
        TMlKemPublicKeyParameters.FromEncoding(AParameters, LKey);
        Fail('expected exception for invalid public key');
      except
        on E: EArgumentCryptoLibException do
          ;
      end;
    end;
  finally
    LReader.Free;
  end;
end;


function TTestMlKem.LoadHexTestResource(const ARelativePath: string): TCryptoLibByteArray;
begin
  Result := DecodeHex(Trim(LoadTestResource(ARelativePath)));
end;

procedure TTestMlKem.TestKeys;
var
  LOkayKey, LTooLargeKey, LFaultyPrivateKey: TCryptoLibByteArray;
begin
  LOkayKey := LoadHexTestResource('Crypto/Pqc/MlKem/Keys/valid-public-512.hex');
  LTooLargeKey := LoadHexTestResource('Crypto/Pqc/MlKem/Keys/too-large-public-512.hex');
  LFaultyPrivateKey := LoadHexTestResource('Crypto/Pqc/MlKem/Keys/faulty-private-512.hex');
  TMlKemPublicKeyParameters.FromEncoding(TMlKemParameters.MlKem512, LOkayKey);
  try
    TMlKemPublicKeyParameters.FromEncoding(TMlKemParameters.MlKem512, LTooLargeKey);
    Fail('no exception for invalid public key');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
  try
    TMlKemPrivateKeyParameters.FromEncoding(TMlKemParameters.MlKem512, LFaultyPrivateKey);
    Fail('no exception for invalid private key');
  except
    on E: EArgumentCryptoLibException do
      ;
  end;
end;

procedure TTestMlKem.TestMlKem;
var
  LZ, LD: TCryptoLibByteArray;
  LExpectedPubKey, LExpectedPrivKey: TCryptoLibByteArray;
  LRandom: ISecureRandom;
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlKemPrivateKeyParameters;
  LPublicKey: IMlKemPublicKeyParameters;
begin
  LZ := DecodeHex('99E3246884181F8E1DD44E0C7629093330221FD67D9B7D6E1510B2DBAD8762F7');
  LD := DecodeHex('49AC8B99BB1E6A8EA818261F8BE68BDEAA52897E7EC6C40B530BC760AB77DCE3');
  LExpectedPubKey := LoadHexTestResource('Crypto/Pqc/MlKem/Keys/mlkem1024-expected-public.hex');
  LExpectedPrivKey := LoadHexTestResource('Crypto/Pqc/MlKem/Keys/mlkem1024-expected-private.hex');
  LRandom := TFixedSecureRandom.From(TCryptoLibGenericArray<TCryptoLibByteArray>.Create(LD, LZ));
  LKpg := TMlKemKeyPairGenerator.Create;
  LKpg.Init(TMlKemKeyGenerationParameters.Create(LRandom, TMlKemParameters.MlKem1024) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPrivateKey := LKp.Private as IMlKemPrivateKeyParameters;
  LPublicKey := LKp.Public as IMlKemPublicKeyParameters;
  CheckTrue(AreEqual(LExpectedPubKey, LPublicKey.GetEncoded()));
  CheckTrue(AreEqual(LExpectedPrivKey, LPrivateKey.GetEncoded()));
end;

procedure TTestMlKem.TestWithPreferredFormat;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPrivateKey: IMlKemPrivateKeyParameters;
  LParams: TCryptoLibGenericArray<IMlKemParameters>;
  LI: Int32;
begin
  LParams := TCryptoLibGenericArray<IMlKemParameters>.Create(
    TMlKemParameters.MlKem512,
    TMlKemParameters.MlKem768,
    TMlKemParameters.MlKem1024);
  for LI := 0 to High(LParams) do
  begin
    LKpg := TMlKemKeyPairGenerator.Create;
    LKpg.Init(TMlKemKeyGenerationParameters.Create(FRandom, LParams[LI]) as IKeyGenerationParameters);
    LKp := LKpg.GenerateKeyPair();
    LPrivateKey := LKp.Private as IMlKemPrivateKeyParameters;
    ImplWithPreferredFormat(LPrivateKey, TMlKemPrivateKeyFormat.SeedOnly);
    ImplWithPreferredFormat(LPrivateKey, TMlKemPrivateKeyFormat.EncodingOnly);
    ImplWithPreferredFormat(LPrivateKey, TMlKemPrivateKeyFormat.SeedAndEncoding);
  end;
end;

procedure TTestMlKem.TestRng;
var
  LSeed, LExpected, LActual: TCryptoLibByteArray;
  LRng: TNistSecureRandom;
begin
  LSeed := DecodeHex('061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1');
  LExpected := DecodeHex('7C9935A0B07694AA0C6D10E4DB6B1ADD2FD81A25CCB148032DCD739936737F2DB505D7CFAD1B497499323C8686325E47');
  LRng := TNistSecureRandom.Create(LSeed, nil);
  try
    System.SetLength(LActual, 48);
    LRng.NextBytes(LActual);
    CheckTrue(AreEqual(LExpected, LActual));
  finally
    LRng.Free;
  end;
end;

procedure TTestMlKem.TestKemUtilities;
var
  LEnc: IKemEncapsulator;
  LDec: IKemDecapsulator;
begin
  LEnc := TKemUtilities.GetEncapsulator('ML-KEM-512');
  CheckNotNull(LEnc);
  CheckTrue(TKemUtilities.TryGetEncapsulator(TNistObjectIdentifiers.IdAlgMlKem512, LEnc));
  CheckNotNull(LEnc);
  LDec := TKemUtilities.GetDecapsulator('ML-KEM-768');
  CheckNotNull(LDec);
  CheckTrue(TKemUtilities.TryGetDecapsulator(TNistObjectIdentifiers.IdAlgMlKem768, LDec));
  CheckNotNull(LDec);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestMlKem);
{$ELSE}
  RegisterTest(TTestMlKem.Suite);
{$ENDIF FPC}

end.
