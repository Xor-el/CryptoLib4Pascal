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

unit OpenSslWriterTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Rtti,
  ClpValueHelper,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpPemObject,
  ClpIPemObject,
  ClpConverters,
  ClpIOpenSslPemWriter,
  ClpOpenSslPemWriter,
  ClpIOpenSslPemReader,
  ClpOpenSslPemReader,
  ClpIOpenSslPasswordFinder,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpBigInteger,
  ClpRsaGenerators,
  ClpIRsaParameters,
  ClpIKeyGenerationParameters,
  ClpKeyGenerationParameters,
  ClpCryptoServicesRegistrar,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpDsaGenerators,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpECGenerators,
  ClpSecObjectIdentifiers,
  ClpPrivateKeyFactory,
  ClpIPkcsAsn1Objects,
  ClpPkcsAsn1Objects,
  ClpAsn1Objects,
  ClpECParameters,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  CryptoTestKeys,
  OpenSslVectors;

type

  TOpenSslWriterTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    const
      EncryptedAlgorithms: array[0..15] of string = (
        'AES-128-CBC', 'AES-128-CFB', 'AES-128-ECB', 'AES-128-OFB',
        'AES-192-CBC', 'AES-192-CFB', 'AES-192-ECB', 'AES-192-OFB',
        'AES-256-CBC', 'AES-256-CFB', 'AES-256-ECB', 'AES-256-OFB',
        'BF-CBC', 'BF-CFB', 'BF-ECB', 'BF-OFB'
      );
  strict private
    class function GetTestRsaKey: IRsaPrivateCrtKeyParameters; static;
    class function GetTestDsaParams: IDsaParameters; static;
    procedure DoWriteReadTest(const APrivateKey: IAsymmetricKeyParameter); overload;
    procedure DoWriteReadTest(const APrivateKey: IAsymmetricKeyParameter;
      const AAlgorithm: String); overload;
    procedure DoWriteReadTests(const APrivateKey: IAsymmetricKeyParameter;
      const AAlgorithms: array of string);
  published
    procedure TestWriteReadDsaKey;
    procedure TestWriteReadRsaKey;
    procedure TestWriteReadEcKeyFromBytes;
    procedure TestWriteReadEcKeyGenerated;
    procedure TestWritePemObjectOverride;
    procedure TestEncryptedWriteRead;
  end;

implementation

{ TOpenSslWriterTest }

class function TOpenSslWriterTest.GetTestRsaKey: IRsaPrivateCrtKeyParameters;
begin
  Result := TCryptoTestKeys.GetWriterRsaCrtPrivate;
end;

class function TOpenSslWriterTest.GetTestDsaParams: IDsaParameters;
begin
  Result := TCryptoTestKeys.GetWriterDsaParameters;
end;

procedure TOpenSslWriterTest.DoWriteReadTest(const APrivateKey: IAsymmetricKeyParameter);
var
  LStream: TStringStream;
  LWriter: IOpenSslPemWriter;
  LReader: IOpenSslPemReader;
  LReadVal: TValue;
  LReadPair: IAsymmetricCipherKeyPair;
  LPriv: IAsymmetricKeyParameter;
begin
  LStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TOpenSslPemWriter.Create(LStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APrivateKey));
    LStream.Position := 0;
    LReader := TOpenSslPemReader.Create(LStream);
    LReadVal := LReader.ReadObject();
    Check(not LReadVal.IsEmpty, 'ReadObject should return key');
    Check(LReadVal.TryGetAsType<IAsymmetricCipherKeyPair>(LReadPair), 'Should be key pair');
    Check(LReadPair <> nil, 'Key pair should not be nil');
    Check(Supports(LReadPair.Private, IAsymmetricKeyParameter, LPriv), 'Private should be IAsymmetricKeyParameter');
    Check(LPriv.Equals(APrivateKey), 'Failed to read back test key');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslWriterTest.DoWriteReadTest(
  const APrivateKey: IAsymmetricKeyParameter; const AAlgorithm: String);
const
  TestPassword = 'CryptoLib';
var
  LStream: TStringStream;
  LWriter: IOpenSslPemWriter;
  LReader: IOpenSslPemReader;
  LReadVal: TValue;
  LReadPair: IAsymmetricCipherKeyPair;
  LPriv: IAsymmetricKeyParameter;
  LPassword: TCryptoLibCharArray;
  LRandom: ISecureRandom;
  LPasswordFinder: IOpenSslPasswordFinder;
begin
  LPasswordFinder := TOpenSslPasswordFinder.Create(TestPassword);
  LPassword := LPasswordFinder.GetPassword();
  LRandom := TCryptoServicesRegistrar.GetSecureRandom();
  LStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TOpenSslPemWriter.Create(LStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APrivateKey),
      AAlgorithm, LPassword, LRandom);
    LStream.Position := 0;
    LPasswordFinder := TOpenSslPasswordFinder.Create(TestPassword);
    LReader := TOpenSslPemReader.Create(LStream, LPasswordFinder);
    LReadVal := LReader.ReadObject();
    Check(not LReadVal.IsEmpty, 'ReadObject should return key for ' + AAlgorithm);
    Check(LReadVal.TryGetAsType<IAsymmetricCipherKeyPair>(LReadPair),
      'Should be key pair for ' + AAlgorithm);
    Check(LReadPair <> nil, 'Key pair should not be nil for ' + AAlgorithm);
    Check(Supports(LReadPair.Private, IAsymmetricKeyParameter, LPriv),
      'Private should be IAsymmetricKeyParameter for ' + AAlgorithm);
    Check(LPriv.Equals(APrivateKey),
      'Failed to read back test key encoded with: ' + AAlgorithm);
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslWriterTest.DoWriteReadTests(
  const APrivateKey: IAsymmetricKeyParameter;
  const AAlgorithms: array of string);
var
  I: Int32;
begin
  for I := Low(AAlgorithms) to High(AAlgorithms) do
    DoWriteReadTest(APrivateKey, AAlgorithms[I]);
end;

procedure TOpenSslWriterTest.TestEncryptedWriteRead;
var
  LSecRandom: ISecureRandom;
  LDsaGen: IAsymmetricCipherKeyPairGenerator;
  LDsaKeyParams: IKeyGenerationParameters;
  LDsaPair: IAsymmetricCipherKeyPair;
  LDsaKey: IAsymmetricKeyParameter;
  LRsaKey: IRsaPrivateCrtKeyParameters;
  LEcKeyBytes: TCryptoLibByteArray;
  LEcPrivInfo: IPrivateKeyInfo;
  LEcPrivFromBytes: IAsymmetricKeyParameter;
  LEcGen: IAsymmetricCipherKeyPairGenerator;
  LEcPair: IAsymmetricCipherKeyPair;
  LEcPrivGenerated: IAsymmetricKeyParameter;
begin
  LSecRandom := TCryptoServicesRegistrar.GetSecureRandom();

  // DSA
  LDsaKeyParams := TDsaKeyGenerationParameters.Create(LSecRandom,
    GetTestDsaParams) as IKeyGenerationParameters;
  LDsaGen := TDsaKeyPairGenerator.Create();
  LDsaGen.Init(LDsaKeyParams);
  LDsaPair := LDsaGen.GenerateKeyPair();
  LDsaKey := LDsaPair.Private;
  DoWriteReadTests(LDsaKey, EncryptedAlgorithms);

  // RSA (static key)
  LRsaKey := GetTestRsaKey();
  DoWriteReadTests(LRsaKey, EncryptedAlgorithms);

  // EC (from bytes)
  LEcKeyBytes := TCryptoTestKeys.GetWriterEcDsaPkcs8Bytes;
  LEcPrivInfo := TPrivateKeyInfo.GetInstance(LEcKeyBytes);
  LEcPrivFromBytes := TPrivateKeyFactory.CreateKey(LEcPrivInfo);
  DoWriteReadTests(LEcPrivFromBytes, EncryptedAlgorithms);

  // EC (generated)
  LEcGen := TECKeyPairGenerator.Create();
  LEcGen.Init(TKeyGenerationParameters.Create(LSecRandom, 239)
    as IKeyGenerationParameters);
  LEcPair := LEcGen.GenerateKeyPair();
  LEcPrivGenerated := LEcPair.Private;
  DoWriteReadTests(LEcPrivGenerated, EncryptedAlgorithms);
end;

procedure TOpenSslWriterTest.TestWriteReadDsaKey;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LDsaKeyParams: IKeyGenerationParameters;
  LPair: IAsymmetricCipherKeyPair;
  LSecRandom: ISecureRandom;
begin
  LSecRandom := TSecureRandom.Create();
  LDsaKeyParams := TDsaKeyGenerationParameters.Create(LSecRandom, GetTestDsaParams);
  LGen := TDsaKeyPairGenerator.Create();
  LGen.Init(LDsaKeyParams);
  LPair := LGen.GenerateKeyPair();
  DoWriteReadTest(LPair.Private);
end;

procedure TOpenSslWriterTest.TestWriteReadRsaKey;
begin
  DoWriteReadTest(GetTestRsaKey);
end;

procedure TOpenSslWriterTest.TestWriteReadEcKeyFromBytes;
var
  LKeyBytes: TCryptoLibByteArray;
  LPrivKey: IAsymmetricKeyParameter;
  LPrivInfo: IPrivateKeyInfo;
begin
  LKeyBytes := TCryptoTestKeys.GetWriterEcDsaPkcs8Bytes;
  LPrivInfo := TPrivateKeyInfo.GetInstance(LKeyBytes);
  LPrivKey := TPrivateKeyFactory.CreateKey(LPrivInfo);
  DoWriteReadTest(LPrivKey);
end;

procedure TOpenSslWriterTest.TestWriteReadEcKeyGenerated;
var
  LEcGen: IAsymmetricCipherKeyPairGenerator;
  LPair: IAsymmetricCipherKeyPair;
  LSecRandom: ISecureRandom;
begin
  LSecRandom := TSecureRandom.Create();
  LEcGen := TECKeyPairGenerator.Create();
  LEcGen.Init(TKeyGenerationParameters.Create(LSecRandom, 239) as IKeyGenerationParameters);
  LPair := LEcGen.GenerateKeyPair();
  DoWriteReadTest(LPair.Private);
end;

procedure TOpenSslWriterTest.TestWritePemObjectOverride;
var
  LContent: TCryptoLibByteArray;
  LObj: IPemObjectGenerator;
  LStream: TStringStream;
  LWriter: IOpenSslPemWriter;
  I: Int32;
  LOut: String;
begin
  System.SetLength(LContent, 100);
  for I := 0 to 99 do
    LContent[I] := Byte(I mod 256);
  LObj := TPemObject.Create('FRED', LContent);

  LStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TOpenSslPemWriter.Create(LStream);
    LWriter.WriteObject(TValue.From<IPemObjectGenerator>(LObj));
    Check(LStream.Size > 0, 'PEM output should not be empty');
    LStream.Position := 0;
    LOut := LStream.DataString;
    Check(Pos('FRED', LOut) > 0, 'PEM should contain type FRED');
  finally
    LStream.Free;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TOpenSslWriterTest);
{$ELSE}
RegisterTest(TOpenSslWriterTest.Suite);
{$ENDIF FPC}

end.
