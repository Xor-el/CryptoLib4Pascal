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
  ClpRsaParameters,
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
  CryptoLibTestBase;

type

  TTestOpenSslWritePassword = class(TInterfacedObject, IOpenSslPasswordFinder)
  strict private
    FPassword: TCryptoLibCharArray;
  public
    constructor Create(const APassword: String);
    function GetPassword(): TCryptoLibCharArray;
  end;

  TOpenSslWriterTest = class(TCryptoLibAlgorithmTestCase)
  strict private
    const
      TestEcDsaKeyBytesBase64 =
        'MIG/AgEAMBAGByqGSM49AgEGBSuBBAAiBIGnMIGkAgEBBDCSBU3vo7ieeKs0ABQamy/ynxlde7Ylr8HmyfLaNnMr' +
        'jAwPp9R+KMUEhB7zxSAXv9KgBwYFK4EEACKhZANiAQQyyolMpg+TyB4o9kPWqafHIOe8o9K1glus+w2sY8OIPQQWGb5i5LdAyi' +
        '/SscwU24rZM0yiL3BHodp9ccwyhLrFYgXJUOQcCN2dno1GMols5497in5gL5+zn0yMsRtyv5o=';

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

{ TTestOpenSslWritePassword }

constructor TTestOpenSslWritePassword.Create(const APassword: String);
begin
  inherited Create();
  FPassword := TConverters.ConvertStringToCharArray(APassword);
end;

function TTestOpenSslWritePassword.GetPassword(): TCryptoLibCharArray;
begin
  Result := System.Copy(FPassword);
end;

{ TOpenSslWriterTest }

class function TOpenSslWriterTest.GetTestRsaKey: IRsaPrivateCrtKeyParameters;
var
  LModulus, LPubExp, LPrivExp, LP, LQ, LDP, LDQ, LQInv: TBigInteger;
begin
  LModulus := TBigInteger.Create('b4a7e46170574f16a97082b22be58b6a2a629798419be12872a4bdba626cfae9900f76abfb12139dce5de56564fab2b6543165a040c606887420e33d91ed7ed7', 16);
  LPubExp := TBigInteger.Create('11', 16);
  LPrivExp := TBigInteger.Create('9f66f6b05410cd503b2709e88115d55daced94d1a34d4e32bf824d0dde6028ae79c5f07b580f5dce240d7111f7ddb130a7945cd7d957d1920994da389f490c89', 16);
  LP := TBigInteger.Create('c0a0758cdf14256f78d4708c86becdead1b50ad4ad6c5c703e2168fbf37884cb', 16);
  LQ := TBigInteger.Create('f01734d7960ea60070f1b06f2bb81bfac48ff192ae18451d5e56c734a5aab8a5', 16);
  LDP := TBigInteger.Create('b54bb9edff22051d9ee60f9351a48591b6500a319429c069a3e335a1d6171391', 16);
  LDQ := TBigInteger.Create('d3d83daf2a0cecd3367ae6f8ae1aeb82e9ac2f816c6fc483533d8297dd7884cd', 16);
  LQInv := TBigInteger.Create('b8f52fc6f38593dabb661d3f50f8897f8106eee68b1bce78a95b132b4e5b5d19', 16);
  Result := TRsaPrivateCrtKeyParameters.Create(LModulus, LPubExp, LPrivExp, LP, LQ, LDP, LDQ, LQInv);
end;

class function TOpenSslWriterTest.GetTestDsaParams: IDsaParameters;
var
  LP, LQ, LG: TBigInteger;
begin
  LP := TBigInteger.Create('7434410770759874867539421675728577177024889699586189000788950934679315164676852047058354758883833299702695428196962057871264685291775577130504050839126673');
  LQ := TBigInteger.Create('1138656671590261728308283492178581223478058193247');
  LG := TBigInteger.Create('4182906737723181805517018315469082619513954319976782448649747742951189003482834321192692620856488639629011570381138542789803819092529658402611668375788410');
  Result := TDsaParameters.Create(LP, LQ, LG);
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
  LPasswordFinder := TTestOpenSslWritePassword.Create(TestPassword);
  LPassword := LPasswordFinder.GetPassword();
  LRandom := TCryptoServicesRegistrar.GetSecureRandom();
  LStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TOpenSslPemWriter.Create(LStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APrivateKey),
      AAlgorithm, LPassword, LRandom);
    LStream.Position := 0;
    LPasswordFinder := TTestOpenSslWritePassword.Create(TestPassword);
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
  LEcKeyBytes := DecodeBase64(TestEcDsaKeyBytesBase64);
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
  LKeyBytes := DecodeBase64(TestEcDsaKeyBytesBase64);
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
