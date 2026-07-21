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

unit PkcsEncryptedPrivateKeyInfoTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpNistObjectIdentifiers,
  ClpPkcsObjectIdentifiers,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpGeneratorUtilities,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpEncryptedPrivateKeyInfoFactory,
  ClpPrivateKeyInfoFactory,
  ClpPrivateKeyFactory,
  ClpPbeUtilities,
  ClpCryptoLibConfig,
  ClpAsn1Objects,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  PkcsVectors;

type

  TTestPkcsEncryptedPrivateKeyInfo = class(TCryptoLibAlgorithmTestCase)

  strict private
    procedure DoTestOpensslKey(const AName: String;
      const AKeyData: TCryptoLibByteArray;
      const APassword: TCryptoLibCharArray);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestEncryptDecryptRoundTrip;
    procedure TestOpensslPbes2AesCbcKeys;
    procedure TestOpensslPbes2AesCfbKeys;
    procedure TestOpensslPbes2AesEcbKeys;
    procedure TestOpensslPbes2AesOfbKeys;
    procedure TestOpensslPbes2AesDefaultKeys;
    procedure TestPbkdf2IterationCountBound;
    procedure TestPkcs5V1PbeIterationCountBound;
    procedure TestPbeDefaultMaxIterationCount;
    procedure TestPbes2DefaultMaxIterationCountBound;

  end;

implementation

{ TTestPkcsEncryptedPrivateKeyInfo }

procedure TTestPkcsEncryptedPrivateKeyInfo.SetUp;
begin
  inherited;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TearDown;
begin
  TCryptoLibConfig.Pbe.ResetToDefaults();
  inherited;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestEncryptDecryptRoundTrip;
var
  LPGen: IAsymmetricCipherKeyPairGenerator;
  LGenParam: IRsaKeyGenerationParameters;
  LPair: IAsymmetricCipherKeyPair;
  LPlain, LDecrypted: IPrivateKeyInfo;
  LEncInfo: IEncryptedPrivateKeyInfo;
  LKey: IAsymmetricKeyParameter;
  LSalt: TCryptoLibByteArray;
  LPassword: TCryptoLibCharArray;
  LIterationCount: Int32;
begin
  LPGen := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LGenParam := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001), TSecureRandom.Create() as ISecureRandom,
    1024, 25);
  LPGen.Init(LGenParam);

  LPair := LPGen.GenerateKeyPair();

  LSalt := DecodeHex('0102030405060708090A');
  LIterationCount := 100;
  LPassword := StringToCharArray('hello');

  LPlain := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPair.Private);

  LEncInfo := TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
    TNistObjectIdentifiers.IdAes256Cbc, TPkcsObjectIdentifiers.IdHmacWithSha512,
    LPassword, LSalt, LIterationCount, TSecureRandom.Create() as ISecureRandom, LPlain);

  LDecrypted := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPassword, LEncInfo);

  CheckTrue(AreEqual(LPlain.GetDerEncoded(), LDecrypted.GetDerEncoded()),
    'Private key info mismatch after decrypt');

  LKey := TPrivateKeyFactory.CreateKey(LDecrypted);

  CheckTrue(Supports(LKey, IRsaPrivateCrtKeyParameters),
    'Decrypted key is not RSA private CRT key');
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.DoTestOpensslKey(
  const AName: String; const AKeyData: TCryptoLibByteArray;
  const APassword: TCryptoLibCharArray);
var
  LKey: IAsymmetricKeyParameter;
begin
  LKey := TPrivateKeyFactory.DecryptKey(APassword, AKeyData);
  CheckTrue(Supports(LKey, IRsaPrivateCrtKeyParameters),
    Format('Sample key could not be decrypted: %s', [AName]));
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesCbcKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray(TPkcsEncryptedPrivateKeyInfoVectors.GetPassword('Pbes2Aes128Cbc'));

  DoTestOpensslKey('pbes2.aes-128-cbc', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes128Cbc'), LPassword);

  DoTestOpensslKey('pbes2.aes-192-cbc', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes192Cbc'), LPassword);

  DoTestOpensslKey('pbes2.aes-256-cbc', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes256Cbc'), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesCfbKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray(TPkcsEncryptedPrivateKeyInfoVectors.GetPassword('Pbes2Aes128Cbc'));

  DoTestOpensslKey('pbes2.aes-128-cfb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes128Cfb'), LPassword);

  DoTestOpensslKey('pbes2.aes-192-cfb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes192Cfb'), LPassword);

  DoTestOpensslKey('pbes2.aes-256-cfb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes256Cfb'), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesEcbKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray(TPkcsEncryptedPrivateKeyInfoVectors.GetPassword('Pbes2Aes128Cbc'));

  DoTestOpensslKey('pbes2.aes-128-ecb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes128Ecb'), LPassword);

  DoTestOpensslKey('pbes2.aes-192-ecb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes192Ecb'), LPassword);

  DoTestOpensslKey('pbes2.aes-256-ecb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes256Ecb'), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesOfbKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray(TPkcsEncryptedPrivateKeyInfoVectors.GetPassword('Pbes2Aes128Cbc'));

  DoTestOpensslKey('pbes2.aes-128-ofb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes128Ofb'), LPassword);

  DoTestOpensslKey('pbes2.aes-192-ofb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes192Ofb'), LPassword);

  DoTestOpensslKey('pbes2.aes-256-ofb', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes256Ofb'), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestOpensslPbes2AesDefaultKeys;
var
  LPassword: TCryptoLibCharArray;
begin
  LPassword := StringToCharArray(TPkcsEncryptedPrivateKeyInfoVectors.GetPassword('Pbes2Aes128Cbc'));

  DoTestOpensslKey('pbes2.aes128', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes128'), LPassword);

  DoTestOpensslKey('pbes2.aes192', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes192'), LPassword);

  DoTestOpensslKey('pbes2.aes256', TPkcsEncryptedPrivateKeyInfoVectors.LoadKeyBytes('Pbes2Aes256'), LPassword);
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestPbkdf2IterationCountBound;
var
  LPGen: IAsymmetricCipherKeyPairGenerator;
  LGenParam: IRsaKeyGenerationParameters;
  LPair: IAsymmetricCipherKeyPair;
  LPlain: IPrivateKeyInfo;
  LEncInfo: IEncryptedPrivateKeyInfo;
  LSalt: TCryptoLibByteArray;
  LPassword: TCryptoLibCharArray;
  LOldMax: Int32;
begin
  LPGen := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LGenParam := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001), TSecureRandom.Create() as ISecureRandom,
    512, 25);
  LPGen.Init(LGenParam);
  LPair := LPGen.GenerateKeyPair();
  LPlain := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPair.Private);

  LPassword := StringToCharArray('hello');
  LSalt := DecodeHex('0102030405060708090A');

  LEncInfo := TEncryptedPrivateKeyInfoFactory.CreateEncryptedPrivateKeyInfo(
    TNistObjectIdentifiers.IdAes256Cbc, TPkcsObjectIdentifiers.IdHmacWithSha256,
    LPassword, LSalt, 2048, TSecureRandom.Create() as ISecureRandom, LPlain);

  LOldMax := TCryptoLibConfig.Pbe.MaxIterationCount;
  try
    TCryptoLibConfig.Pbe.MaxIterationCount := 1;
    try
      TPrivateKeyInfoFactory.CreatePrivateKeyInfo(LPassword, LEncInfo);
      Fail('excessive PBKDF2 iteration count accepted');
    except
      on E: EArgumentCryptoLibException do
        CheckTrue(Pos('greater than 1', E.Message) > 0,
          'unexpected message: ' + E.Message);
    end;
  finally
    TCryptoLibConfig.Pbe.MaxIterationCount := LOldMax;
  end;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestPkcs5V1PbeIterationCountBound;
const
  LPbeAlgorithm = 'PBEWITHMD5AND128BITAES-CBC-OPENSSL';
var
  LSalt: TCryptoLibByteArray;
  LPassword: TCryptoLibCharArray;
  LPbeParams: IPbeParameter;
  LOldMax: Int32;
begin
  LPassword := StringToCharArray('hello');
  LSalt := DecodeHex('0102030405060708');
  LPbeParams := TPbeParameter.Create(LSalt, 2048);

  LOldMax := TCryptoLibConfig.Pbe.MaxIterationCount;
  try
    TCryptoLibConfig.Pbe.MaxIterationCount := 1;
    try
      TPbeUtilities.GenerateCipherParameters(LPbeAlgorithm, LPassword, LPbeParams);
      Fail('excessive PBE iteration count accepted');
    except
      on E: EArgumentCryptoLibException do
        CheckTrue(Pos('greater than 1', E.Message) > 0,
          'unexpected message: ' + E.Message);
    end;
  finally
    TCryptoLibConfig.Pbe.MaxIterationCount := LOldMax;
  end;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestPbeDefaultMaxIterationCount;
var
  LOldMax: Int32;
  LCount: Int32;
begin
  LOldMax := TCryptoLibConfig.Pbe.MaxIterationCount;
  try
    TCryptoLibConfig.Pbe.ResetToDefaults();

    LCount := TPbeUtilities.CheckPbeIterationCount(TDerInteger.ValueOf(5000000));
    CheckEquals(5000000, LCount, 'default max iteration count should allow 5_000_000');

    try
      TPbeUtilities.CheckPbeIterationCount(TDerInteger.ValueOf(5000001));
      Fail('iteration count above default max accepted');
    except
      on E: EArgumentCryptoLibException do
        CheckTrue(Pos('greater than 5000000', E.Message) > 0,
          'unexpected message: ' + E.Message);
    end;
  finally
    TCryptoLibConfig.Pbe.MaxIterationCount := LOldMax;
  end;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TestPbes2DefaultMaxIterationCountBound;
const
  LExcessiveIterationCount = 5000001;
var
  LSalt, LIv: TCryptoLibByteArray;
  LPassword: TCryptoLibCharArray;
  LPbkdf2Params: IPbkdf2Params;
  LKeyDerivFunc: IKeyDerivationFunc;
  LEncScheme: IEncryptionScheme;
  LPbeS2Params: IPbeS2Parameters;
  LOldMax: Int32;
begin
  LPassword := StringToCharArray('password');
  LSalt := DecodeHex('0102030405060708090A0B0C0D0E0F1011121314');
  LIv := DecodeHex('0102030405060708090A0B0C0D0E0F10');

  LPbkdf2Params := TPbkdf2Params.Create(LSalt, LExcessiveIterationCount);
  LKeyDerivFunc := TKeyDerivationFunc.Create(TPkcsObjectIdentifiers.IdPbkdf2, LPbkdf2Params);
  LEncScheme := TEncryptionScheme.Create(TNistObjectIdentifiers.IdAes256Cbc,
    TDerOctetString.FromContents(LIv));
  LPbeS2Params := TPbeS2Parameters.Create(LKeyDerivFunc, LEncScheme);

  LOldMax := TCryptoLibConfig.Pbe.MaxIterationCount;
  try
    TCryptoLibConfig.Pbe.ResetToDefaults();
    try
      TPbeUtilities.GenerateCipherParameters(TPkcsObjectIdentifiers.IdPbeS2,
        LPassword, LPbeS2Params);
      Fail('PBES2 derivation accepted excessive default-max iteration count');
    except
      on E: EArgumentCryptoLibException do
        CheckTrue(Pos('greater than 5000000', E.Message) > 0,
          'unexpected message: ' + E.Message);
    end;
  finally
    TCryptoLibConfig.Pbe.MaxIterationCount := LOldMax;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcsEncryptedPrivateKeyInfo);
{$ELSE}
  RegisterTest(TTestPkcsEncryptedPrivateKeyInfo.Suite);
{$ENDIF FPC}

end.
