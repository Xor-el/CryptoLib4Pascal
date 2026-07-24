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

unit OpenSslReaderTests;

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
  ClpIOpenSslPemWriter,
  ClpOpenSslPemWriter,
  ClpConverters,
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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpDsaGenerators,
  ClpIDsaGenerators,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpPkcsAsn1Objects,
  ClpICmsAsn1Objects,
  ClpCmsObjectIdentifiers,
  ClpIAsn1Objects,
  ClpIX9ECAsn1Objects,
  ClpX9ObjectIdentifiers,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  OpenSslVectors;

type

  TOpenSslReaderTest = class(TCryptoLibAlgorithmTestCase)
  strict private

  strict private
    function CreatePemReader(AStream: TStringStream): IOpenSslPemReader;
    function CreatePemWriter(AStream: TStringStream): IOpenSslPemWriter;
    procedure KeyPairTest(const AName: string; const APair: IAsymmetricCipherKeyPair);
    procedure DoOpenSslTestData(const APemData: string; AExpectDsa: Boolean);
    procedure DoOpenSslEncryptedTestData(const APemData, APassword: string; AExpectDsa: Boolean);
    procedure DoOpenSslDsaModesTest(const ABaseName: string);
    procedure DoOpenSslRsaModesTest(const ABaseName: string);
    procedure DoOpenSslTests(const ABaseName: string);
  published
    procedure TestPkcs7EnvelopedData;
    procedure TestKeyPairRsaRoundTrip;
    procedure TestKeyPairDsaRoundTrip;
    procedure TestPkcs7RoundTrip;
    procedure TestEcParametersRoundTrip;
    procedure TestOpenSslDsaUnencrypted;
    procedure TestOpenSslRsaUnencrypted;
    procedure TestOpenSslAes128;
    procedure TestOpenSslAes192;
    procedure TestOpenSslAes256;
    procedure TestOpenSslBlowfish;
    procedure TestEncryptedPrivateKey;
    procedure TestPkcs8;
  end;

implementation

{ TOpenSslReaderTest }

function TOpenSslReaderTest.CreatePemReader(AStream: TStringStream): IOpenSslPemReader;
begin
  AStream.Position := 0;
  Result := TOpenSslPemReader.Create(AStream);
end;

function TOpenSslReaderTest.CreatePemWriter(AStream: TStringStream): IOpenSslPemWriter;
begin
  Result := TOpenSslPemWriter.Create(AStream);
end;

procedure TOpenSslReaderTest.KeyPairTest(const AName: string;
  const APair: IAsymmetricCipherKeyPair);
var
  LWriteStream: TStringStream;
  LReadStream: TStringStream;
  LWriter: IOpenSslPemWriter;
  LReader: IOpenSslPemReader;
  LReadVal: TValue;
  LPubK: IAsymmetricKeyParameter;
  LReadPair: IAsymmetricCipherKeyPair;
begin
  LWriteStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := CreatePemWriter(LWriteStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APair.Public));

    LReadStream := TStringStream.Create(LWriteStream.DataString, TEncoding.ASCII);
    try
      LReader := CreatePemReader(LReadStream);
      LReadVal := LReader.ReadObject();
      Check(not LReadVal.IsEmpty, 'Public key should read back');
      Check(LReadVal.TryGetAsType<IAsymmetricKeyParameter>(LPubK), 'Should be public key');
      Check(LPubK.Equals(APair.Public), 'Failed public key read: ' + AName);
    finally
      LReadStream.Free;
    end;
  finally
    LWriteStream.Free;
  end;

  LWriteStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := CreatePemWriter(LWriteStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(APair.Private));

    LReadStream := TStringStream.Create(LWriteStream.DataString, TEncoding.ASCII);
    try
      LReader := CreatePemReader(LReadStream);
      LReadVal := LReader.ReadObject();
      Check(LReadVal.TryGetAsType<IAsymmetricCipherKeyPair>(LReadPair), 'Should be key pair');
      Check(LReadPair.Private.Equals(APair.Private), 'Failed private key read: ' + AName);
      Check(LReadPair.Public.Equals(APair.Public), 'Failed private key public read: ' + AName);
    finally
      LReadStream.Free;
    end;
  finally
    LWriteStream.Free;
  end;
end;

procedure TOpenSslReaderTest.DoOpenSslTestData(const APemData: string;
  AExpectDsa: Boolean);
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LKp: IAsymmetricCipherKeyPair;
  LDummy: IInterface;
begin
  LStream := TStringStream.Create(APemData, TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricCipherKeyPair>(LKp), 'Should be key pair');
    Check(LKp <> nil, 'Didn''t find OpenSSL key');
    if AExpectDsa then
      Check(Supports(LKp.Private, IDsaPrivateKeyParameters, LDummy), 'Returned key not DSA private')
    else
      Check(Supports(LKp.Private, IRsaPrivateCrtKeyParameters, LDummy), 'Returned key not RSA private');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestPkcs7EnvelopedData;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LCmsContent: ICmsContentInfo;
begin
  LStream := TStringStream.Create(TOpenSslVectors.LoadPemString('Pkcs7'), TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return PKCS7');
    Check(LVal.TryGetAsType<ICmsContentInfo>(LCmsContent), 'Should be CmsContentInfo');
    Check(LCmsContent <> nil, 'ContentInfo should not be nil');
    Check(LCmsContent.ContentType.Equals(TCmsObjectIdentifiers.EnvelopedData),
      'ContentType should be EnvelopedData');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestKeyPairRsaRoundTrip;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LPair: IAsymmetricCipherKeyPair;
  LSecRandom: ISecureRandom;
begin
  LSecRandom := TSecureRandom.Create();
  LGen := TRsaKeyPairGenerator.Create();
  LGen.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001),
    LSecRandom, 768, 25) as IKeyGenerationParameters);
  LPair := LGen.GenerateKeyPair();
  KeyPairTest('RSA', LPair);
end;

procedure TOpenSslReaderTest.TestKeyPairDsaRoundTrip;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LDsaParamsGen: IDsaParametersGenerator;
  LDsaParams: IDsaParameters;
  LDsaKeyParams: IKeyGenerationParameters;
  LPair: IAsymmetricCipherKeyPair;
  LSecRandom: ISecureRandom;
begin
  LSecRandom := TSecureRandom.Create();
  LDsaParamsGen := TDsaParametersGenerator.Create();
  LDsaParamsGen.Init(512, 80, LSecRandom);
  LDsaParams := LDsaParamsGen.GenerateParameters();
  LDsaKeyParams := TDsaKeyGenerationParameters.Create(LSecRandom, LDsaParams) as IKeyGenerationParameters;
  LGen := TDsaKeyPairGenerator.Create();
  LGen.Init(LDsaKeyParams);
  LPair := LGen.GenerateKeyPair();
  KeyPairTest('DSA', LPair);
end;

procedure TOpenSslReaderTest.TestPkcs7RoundTrip;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LCmsContent: ICmsContentInfo;
  LWriter: IOpenSslPemWriter;
  LOutStream: TStringStream;
  LReader2: IOpenSslPemReader;
  LVal2: TValue;
  LCmsContent2: ICmsContentInfo;
begin
  LStream := TStringStream.Create(TOpenSslVectors.LoadPemString('Pkcs7'), TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);
    LVal := LReader.ReadObject();
    Check(LVal.TryGetAsType<ICmsContentInfo>(LCmsContent), 'Should be CmsContentInfo');
    Check(LCmsContent <> nil, 'ContentInfo should not be nil');

    LOutStream := TStringStream.Create('', TEncoding.ASCII);
    try
      LWriter := CreatePemWriter(LOutStream);
      LWriter.WriteObject(TValue.From<ICmsContentInfo>(LCmsContent));
      LReader2 := CreatePemReader(LOutStream);
      LVal2 := LReader2.ReadObject();
      Check(LVal2.TryGetAsType<ICmsContentInfo>(LCmsContent2), 'Read back should be CmsContentInfo');
      Check(LCmsContent2.ContentType.Equals(TCmsObjectIdentifiers.EnvelopedData),
        'failed envelopedData recode check');
    finally
      LOutStream.Free;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestEcParametersRoundTrip;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LX962Params: IX962Parameters;
  LOid: IDerObjectIdentifier;
  LVal2: TValue;
  LKp: IAsymmetricCipherKeyPair;
  LWriter: IOpenSslPemWriter;
  LOutStream: TStringStream;
  LInStream: TStringStream;
  LReader2: IOpenSslPemReader;
  LVal3: TValue;
  LX962Params2: IX962Parameters;
  LOid2: IDerObjectIdentifier;
  LVal4: TValue;
  LKp2: IAsymmetricCipherKeyPair;
begin
  LStream := TStringStream.Create(TOpenSslVectors.LoadPemString('EcParametersWithPrivateKey'), TEncoding.ASCII);
  try
    LReader := CreatePemReader(LStream);

    // First object: EC PARAMETERS
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'First ReadObject should return EC PARAMETERS');
    Check(LVal.TryGetAsType<IX962Parameters>(LX962Params), 'First should be IX962Parameters');
    Check(LX962Params <> nil, 'EC PARAMETERS (X962Parameters) should not be nil');
    Check(LX962Params.IsNamedCurve, 'EC PARAMETERS should be a named curve');
    LOid := LX962Params.Parameters as IDerObjectIdentifier;
    Check(LOid <> nil, 'EC PARAMETERS named curve OID should not be nil');

    // Second object: EC PRIVATE KEY
    LVal2 := LReader.ReadObject();
    Check(not LVal2.IsEmpty, 'Second ReadObject should return EC PRIVATE KEY');
    Check(LVal2.TryGetAsType<IAsymmetricCipherKeyPair>(LKp), 'Second should be IAsymmetricCipherKeyPair');
    Check(LKp <> nil, 'EC key pair should not be nil');

    // Write roundtrip
    LOutStream := TStringStream.Create('', TEncoding.ASCII);
    try
      LWriter := CreatePemWriter(LOutStream);
      LWriter.WriteObject(TValue.From<IX962Parameters>(LX962Params));
      LWriter.WriteObject(TValue.From<IAsymmetricCipherKeyPair>(LKp));

      // Read back
      LInStream := TStringStream.Create(LOutStream.DataString, TEncoding.ASCII);
      try
        LReader2 := CreatePemReader(LInStream);

        LVal3 := LReader2.ReadObject();
        Check(not LVal3.IsEmpty, 'Roundtrip first ReadObject should return EC PARAMETERS');
        Check(LVal3.TryGetAsType<IX962Parameters>(LX962Params2), 'Roundtrip first should be IX962Parameters');
        Check(LX962Params2.IsNamedCurve, 'Roundtrip EC PARAMETERS should be a named curve');
        LOid2 := LX962Params2.Parameters as IDerObjectIdentifier;
        Check(LOid2 <> nil, 'Roundtrip EC PARAMETERS OID should not be nil');

        LVal4 := LReader2.ReadObject();
        Check(not LVal4.IsEmpty, 'Roundtrip second ReadObject should return EC PRIVATE KEY');
        Check(LVal4.TryGetAsType<IAsymmetricCipherKeyPair>(LKp2), 'Roundtrip second should be IAsymmetricCipherKeyPair');
        Check(LKp2.Private.Equals(LKp.Private), 'Roundtrip EC private key should match');
        Check(LKp2.Public.Equals(LKp.Public), 'Roundtrip EC public key should match');
      finally
        LInStream.Free;
      end;
    finally
      LOutStream.Free;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestOpenSslDsaUnencrypted;
begin
  DoOpenSslTestData(TOpenSslVectors.LoadPemString('DsaUnencrypted'), True);
end;

procedure TOpenSslReaderTest.TestOpenSslRsaUnencrypted;
begin
  DoOpenSslTestData(TOpenSslVectors.LoadPemString('RsaUnencrypted'), False);
end;

procedure TOpenSslReaderTest.DoOpenSslEncryptedTestData(const APemData, APassword: string;
  AExpectDsa: Boolean);
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LKp: IAsymmetricCipherKeyPair;
  LDummy: IInterface;
begin
  LStream := TStringStream.Create(APemData, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream, TOpenSslPasswordFinder.Create(APassword) as IOpenSslPasswordFinder);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricCipherKeyPair>(LKp), 'Should be key pair');
    Check(LKp <> nil, 'Didn''t find OpenSSL key');
    if AExpectDsa then
      Check(Supports(LKp.Private, IDsaPrivateKeyParameters, LDummy), 'Returned key not DSA private')
    else
      Check(Supports(LKp.Private, IRsaPrivateCrtKeyParameters, LDummy), 'Returned key not RSA private');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.DoOpenSslDsaModesTest(const ABaseName: string);
var
  LDsaIds: array[0..3] of string;
  LI: Integer;
begin
  if ABaseName = 'aes128' then
  begin
    LDsaIds[0] := 'DsaAes128Cbc';
    LDsaIds[1] := 'DsaAes128Cfb';
    LDsaIds[2] := 'DsaAes128Ecb';
    LDsaIds[3] := 'DsaAes128Ofb';
  end
  else if ABaseName = 'aes192' then
  begin
    LDsaIds[0] := 'DsaAes192Cbc';
    LDsaIds[1] := 'DsaAes192Cfb';
    LDsaIds[2] := 'DsaAes192Ecb';
    LDsaIds[3] := 'DsaAes192Ofb';
  end
  else if ABaseName = 'aes256' then
  begin
    LDsaIds[0] := 'DsaAes256Cbc';
    LDsaIds[1] := 'DsaAes256Cfb';
    LDsaIds[2] := 'DsaAes256Ecb';
    LDsaIds[3] := 'DsaAes256Ofb';
  end
  else if ABaseName = 'blowfish' then
  begin
    LDsaIds[0] := 'DsaBlowfishCbc';
    LDsaIds[1] := 'DsaBlowfishCfb';
    LDsaIds[2] := 'DsaBlowfishEcb';
    LDsaIds[3] := 'DsaBlowfishOfb';
  end;

  for LI := 0 to 3 do
    DoOpenSslEncryptedTestData(TOpenSslVectors.LoadPemString(LDsaIds[LI]), 'changeit', True);
end;

procedure TOpenSslReaderTest.DoOpenSslRsaModesTest(const ABaseName: string);
var
  LRsaIds: array[0..3] of string;
  LI: Integer;
begin
  if ABaseName = 'aes128' then
  begin
    LRsaIds[0] := 'RsaAes128Cbc';
    LRsaIds[1] := 'RsaAes128Cfb';
    LRsaIds[2] := 'RsaAes128Ecb';
    LRsaIds[3] := 'RsaAes128Ofb';
  end
  else if ABaseName = 'aes192' then
  begin
    LRsaIds[0] := 'RsaAes192Cbc';
    LRsaIds[1] := 'RsaAes192Cfb';
    LRsaIds[2] := 'RsaAes192Ecb';
    LRsaIds[3] := 'RsaAes192Ofb';
  end
  else if ABaseName = 'aes256' then
  begin
    LRsaIds[0] := 'RsaAes256Cbc';
    LRsaIds[1] := 'RsaAes256Cfb';
    LRsaIds[2] := 'RsaAes256Ecb';
    LRsaIds[3] := 'RsaAes256Ofb';
  end
  else if ABaseName = 'blowfish' then
  begin
    LRsaIds[0] := 'RsaBlowfishCbc';
    LRsaIds[1] := 'RsaBlowfishCfb';
    LRsaIds[2] := 'RsaBlowfishEcb';
    LRsaIds[3] := 'RsaBlowfishOfb';
  end;

  for LI := 0 to 3 do
    DoOpenSslEncryptedTestData(TOpenSslVectors.LoadPemString(LRsaIds[LI]), 'changeit', False);
end;

procedure TOpenSslReaderTest.DoOpenSslTests(const ABaseName: string);
begin
  DoOpenSslDsaModesTest(ABaseName);
  DoOpenSslRsaModesTest(ABaseName);
end;

procedure TOpenSslReaderTest.TestOpenSslAes128;
begin
  DoOpenSslTests('aes128');
end;

procedure TOpenSslReaderTest.TestOpenSslAes192;
begin
  DoOpenSslTests('aes192');
end;

procedure TOpenSslReaderTest.TestOpenSslAes256;
begin
  DoOpenSslTests('aes256');
end;

procedure TOpenSslReaderTest.TestOpenSslBlowfish;
begin
  DoOpenSslTests('blowfish');
end;

procedure TOpenSslReaderTest.TestEncryptedPrivateKey;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LPrivKey: IAsymmetricKeyParameter;
  LRsaKey: IRsaPrivateCrtKeyParameters;
begin
  LStream := TStringStream.Create(TOpenSslVectors.LoadPemString('EncKey'), TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream, TOpenSslPasswordFinder.Create(TOpenSslVectors.GetPassword('EncKey')) as IOpenSslPasswordFinder);
    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricKeyParameter>(LPrivKey), 'Should be IAsymmetricKeyParameter');
    Check(Supports(LPrivKey, IRsaPrivateCrtKeyParameters, LRsaKey),
      'Should be RSA private CRT key');
    Check(LRsaKey.PublicExponent.Equals(TBigInteger.Create('10001', 16)),
      'decryption of private key data check failed');
  finally
    LStream.Free;
  end;
end;

procedure TOpenSslReaderTest.TestPkcs8;
var
  LStream: TStringStream;
  LReader: IOpenSslPemReader;
  LVal: TValue;
  LPrivKey: IAsymmetricKeyParameter;
  LRsaKey: IRsaPrivateCrtKeyParameters;
  LPemData: string;
begin
  LPemData := TOpenSslVectors.LoadPemString('Pkcs8Unencrypted') + sLineBreak +
    TOpenSslVectors.LoadPemString('Pkcs8Aes256Encrypted');
  LStream := TStringStream.Create(LPemData, TEncoding.ASCII);
  try
    LReader := TOpenSslPemReader.Create(LStream,
      TOpenSslPasswordFinder.Create(TOpenSslVectors.GetPassword('Pkcs8Aes256Encrypted')) as IOpenSslPasswordFinder);

    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'First ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricKeyParameter>(LPrivKey), 'First should be IAsymmetricKeyParameter');
    Check(Supports(LPrivKey, IRsaPrivateCrtKeyParameters, LRsaKey),
      'First should be RSA private CRT key');
    Check(LRsaKey.PublicExponent.Equals(TBigInteger.Create('10001', 16)),
      'First key decryption check failed');

    LPrivKey := nil;

    LVal := LReader.ReadObject();
    Check(not LVal.IsEmpty, 'Second ReadObject should return key');
    Check(LVal.TryGetAsType<IAsymmetricKeyParameter>(LPrivKey), 'Second should be IAsymmetricKeyParameter');
    Check(Supports(LPrivKey, IRsaPrivateCrtKeyParameters, LRsaKey),
      'Second should be RSA private CRT key');
    Check(LRsaKey.PublicExponent.Equals(TBigInteger.Create('10001', 16)),
      'Second key decryption check failed');
  finally
    LStream.Free;
  end;
end;

initialization

{$IFDEF FPC}
RegisterTest(TOpenSslReaderTest);
{$ELSE}
RegisterTest(TOpenSslReaderTest.Suite);
{$ENDIF FPC}

end.
