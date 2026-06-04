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
  ClpIPkcsAsn1Objects,
  ClpCryptoLibTypes,
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

  end;

implementation

{ TTestPkcsEncryptedPrivateKeyInfo }

procedure TTestPkcsEncryptedPrivateKeyInfo.SetUp;
begin
  inherited;
end;

procedure TTestPkcsEncryptedPrivateKeyInfo.TearDown;
begin
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestPkcsEncryptedPrivateKeyInfo);
{$ELSE}
  RegisterTest(TTestPkcsEncryptedPrivateKeyInfo.Suite);
{$ENDIF FPC}

end.
