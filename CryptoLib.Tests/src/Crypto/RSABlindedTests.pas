unit RSABlindedTests;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF}
  ClpBigInteger,
  ClpSecureRandom,
  ClpEncoders,
  ClpICipherParameters,
  ClpIAsymmetricBlockCipher,
  ClpIAsymmetricCipherKeyPair,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpRsaGenerators,
  ClpIRsaGenerators,
  ClpRsaBlindedEngine,
  ClpPkcs1Encoding,
  ClpIPkcs1Encoding,
  ClpOaepEncoding,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoTestKeys;

type
  TTestRSABlinded = class(TTestCase)
  private
    class var
      FOversizedSig: TCryptoLibByteArray;
      FDudBlock: TCryptoLibByteArray;
      FTruncatedDataBlock: TCryptoLibByteArray;
      FIncorrectPadding: TCryptoLibByteArray;
      FMissingDataBlock: TCryptoLibByteArray;

    class constructor Create;

    function GetPubParameters: IRsaKeyParameters;
    function GetPrivParameters: IRsaPrivateCrtKeyParameters;

    procedure DoTestOaep(const pubParameters: IRsaKeyParameters;
      const privParameters: IRsaPrivateCrtKeyParameters);

    procedure CheckForPkcs1Exception(const pubParameters: IRsaKeyParameters;
      const privParameters: IRsaPrivateCrtKeyParameters;
      const inputData: TCryptoLibByteArray; const expectedMessage: String);

  published
    procedure TestRawRSA;
    procedure TestRawRSAEdge;
    procedure TestPkcs1PublicPrivate;
    procedure TestPkcs1PrivatePublic;
    procedure TestPkcs1OutputBlockSize;
    procedure TestOaep;
    procedure TestKeyGeneration768;
    procedure TestKeyGeneration1024;
    procedure TestStrictPkcs1Length;
    procedure TestDudPkcs1Block;
    procedure TestMissingDataPkcs1Block;
    procedure TestTruncatedPkcs1Block;
    procedure TestWrongPaddingPkcs1Block;
    procedure TestUninitializedEngine;
  end;

implementation

const
  Input = '4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e';
  EdgeInput = 'ff6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e';

{ TTestRSABlinded }

class constructor TTestRSABlinded.Create;
begin
  // Test block data for PKCS1 padding validation
  FOversizedSig := THexEncoder.Decode('01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FDudBlock := THexEncoder.Decode('000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FTruncatedDataBlock := THexEncoder.Decode('0001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FIncorrectPadding := THexEncoder.Decode('0001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FMissingDataBlock := THexEncoder.Decode('0001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
end;

function TTestRSABlinded.GetPubParameters: IRsaKeyParameters;
begin
  Result := TCryptoTestKeys.GetRsaEngineDefaultPublic;
end;

function TTestRSABlinded.GetPrivParameters: IRsaPrivateCrtKeyParameters;
begin
  Result := TCryptoTestKeys.GetRsaEngineDefaultPrivate;
end;

procedure TTestRSABlinded.CheckForPkcs1Exception(
  const pubParameters: IRsaKeyParameters;
  const privParameters: IRsaPrivateCrtKeyParameters;
  const inputData: TCryptoLibByteArray; const expectedMessage: String);
var
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
  exceptionCaught: Boolean;
begin
  eng := TRsaBlindedEngine.Create();
  eng.Init(True, privParameters as ICipherParameters);
  data := eng.ProcessBlock(inputData, 0, System.Length(inputData));

  eng := TPkcs1Encoding.Create(eng);
  eng.Init(False, pubParameters as ICipherParameters);

  exceptionCaught := False;
  try
    data := eng.ProcessBlock(data, 0, System.Length(data));
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      exceptionCaught := True;
      Check(Pos(expectedMessage, E.Message) > 0,
        'Expected message containing "' + expectedMessage + '" but got: ' + E.Message);
    end;
  end;

  Check(exceptionCaught, 'Expected PKCS1 exception not thrown');
end;

procedure TTestRSABlinded.TestRawRSA;
var
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
begin
  pubParams := GetPubParameters;
  privParams := GetPrivParameters;

  data := THexEncoder.Decode(Input);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pubParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THexEncoder.Encode(data, False), 'Raw RSA test failed');
end;

procedure TTestRSABlinded.TestRawRSAEdge;
var
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
begin
  pubParams := GetPubParameters;
  privParams := GetPrivParameters;

  data := THexEncoder.Decode(EdgeInput);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pubParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(EdgeInput, THexEncoder.Encode(data, False), 'Raw RSA edge test failed');
end;

procedure TTestRSABlinded.TestPkcs1PublicPrivate;
var
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
begin
  pubParams := GetPubParameters;
  privParams := GetPrivParameters;

  data := THexEncoder.Decode(Input);

  eng := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  eng.Init(True, pubParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THexEncoder.Encode(data, False), 'PKCS1 public/private test failed');
end;

procedure TTestRSABlinded.TestPkcs1PrivatePublic;
var
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
begin
  pubParams := GetPubParameters;
  privParams := GetPrivParameters;

  data := THexEncoder.Decode(Input);

  eng := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  eng.Init(True, privParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, pubParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THexEncoder.Encode(data, False), 'PKCS1 private/public test failed');
end;

procedure TTestRSABlinded.TestPkcs1OutputBlockSize;
var
  pubParams: IRsaKeyParameters;
  eng: IPkcs1Encoding;
begin
  pubParams := GetPubParameters;

  eng := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  eng.Init(True, pubParams as ICipherParameters);

  // PKCS1 output block size should equal underlying cipher's output block size
  CheckEquals(eng.OutputBlockSize, eng.UnderlyingCipher.OutputBlockSize,
    'PKCS1 output block size incorrect');
end;

procedure TTestRSABlinded.DoTestOaep(const pubParameters: IRsaKeyParameters;
  const privParameters: IRsaPrivateCrtKeyParameters);
var
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
begin
  data := THexEncoder.Decode(Input);

  eng := TOaepEncoding.Create(TRsaBlindedEngine.Create());
  eng.Init(True, pubParameters as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParameters as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THexEncoder.Encode(data, False), 'OAEP test failed');
end;

procedure TTestRSABlinded.TestOaep;
begin
  DoTestOaep(GetPubParameters, GetPrivParameters);
end;

procedure TTestRSABlinded.TestKeyGeneration768;
var
  pGen: IRsaKeyPairGenerator;
  genParam: IRsaKeyGenerationParameters;
  pair: IAsymmetricCipherKeyPair;
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
  pubKey: IRsaKeyParameters;
begin
  pGen := TRsaKeyPairGenerator.Create();
  genParam := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($11),
    TSecureRandom.Create(), 768, 25);

  pGen.Init(genParam);
  pair := pGen.GenerateKeyPair();

  pubKey := pair.Public as IRsaKeyParameters;
  Check(pubKey.Modulus.BitLength >= 768, 'Key generation (768) length test failed');

  data := THexEncoder.Decode(Input);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pair.Public);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, pair.Private);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THexEncoder.Encode(data, False), 'Key generation (768) test failed');
end;

procedure TTestRSABlinded.TestKeyGeneration1024;
var
  pGen: IRsaKeyPairGenerator;
  genParam: IRsaKeyGenerationParameters;
  pair: IAsymmetricCipherKeyPair;
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
  pubKey: IRsaKeyParameters;
begin
  pGen := TRsaKeyPairGenerator.Create();
  genParam := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($11),
    TSecureRandom.Create(), 1024, 25);

  pGen.Init(genParam);
  pair := pGen.GenerateKeyPair();

  pubKey := pair.Public as IRsaKeyParameters;
  Check(pubKey.Modulus.BitLength >= 1024, 'Key generation (1024) length test failed');

  data := THexEncoder.Decode(Input);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pair.Public);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, pair.Private);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THexEncoder.Encode(data, False), 'Key generation (1024) test failed');
end;

procedure TTestRSABlinded.TestStrictPkcs1Length;
var
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
  exceptionCaught: Boolean;
  savedStrictLength: Boolean;
begin
  pubParams := GetPubParameters;
  privParams := GetPrivParameters;

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, privParams as ICipherParameters);
  data := eng.ProcessBlock(FOversizedSig, 0, System.Length(FOversizedSig));

  eng := TPkcs1Encoding.Create(eng);
  eng.Init(False, pubParams as ICipherParameters);

  // Test with strict length enabled (should throw)
  exceptionCaught := False;
  try
    data := eng.ProcessBlock(data, 0, System.Length(data));
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      exceptionCaught := True;
      Check(Pos('block incorrect size', E.Message) > 0,
        'Expected "block incorrect size" but got: ' + E.Message);
    end;
  end;

  Check(exceptionCaught, 'Oversized signature block not recognised');

  // Test with strict length disabled (should pass)
  savedStrictLength := TPkcs1Encoding.StrictLengthEnabled;
  try
    TPkcs1Encoding.StrictLengthEnabled := False;

    eng := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
    eng.Init(False, pubParams as ICipherParameters);

    // Re-encrypt the data first
    eng := TRsaBlindedEngine.Create();
    eng.Init(True, privParams as ICipherParameters);
    data := eng.ProcessBlock(FOversizedSig, 0, System.Length(FOversizedSig));

    eng := TPkcs1Encoding.Create(eng);
    eng.Init(False, pubParams as ICipherParameters);
    data := eng.ProcessBlock(data, 0, System.Length(data));
    // Should not throw
  finally
    TPkcs1Encoding.StrictLengthEnabled := savedStrictLength;
  end;
end;

procedure TTestRSABlinded.TestDudPkcs1Block;
begin
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FDudBlock, 'block incorrect');
end;

procedure TTestRSABlinded.TestMissingDataPkcs1Block;
begin
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FMissingDataBlock, 'block incorrect');
end;

procedure TTestRSABlinded.TestTruncatedPkcs1Block;
begin
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FTruncatedDataBlock, 'block incorrect');
end;

procedure TTestRSABlinded.TestWrongPaddingPkcs1Block;
begin
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FIncorrectPadding, 'block incorrect');
end;

procedure TTestRSABlinded.TestUninitializedEngine;
var
  eng: IAsymmetricBlockCipher;
  data: TCryptoLibByteArray;
  ExceptionCaught: Boolean;
begin
  ExceptionCaught := False;
  SetLength(data, 1);
  data[0] := 1;

  eng := TRsaBlindedEngine.Create();
  try
    eng.ProcessBlock(data, 0, 1);
  except
    on E: EInvalidOperationCryptoLibException do
      ExceptionCaught := True;
  end;

  Check(ExceptionCaught, 'Uninitialized engine should raise exception');
end;

initialization
  {$IFDEF FPC}
  RegisterTest(TTestRSABlinded);
  {$ELSE}
  RegisterTest(TTestRSABlinded.Suite);
  {$ENDIF}

end.
