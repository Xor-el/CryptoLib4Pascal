unit RSABlindedTests;

{$IFDEF FPC}
  {$MODE DELPHI}
{$ENDIF}

interface

uses
  SysUtils,
  Classes,
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
  ClpRsaKeyParameters,
  ClpIRsaKeyParameters,
  ClpRsaPrivateCrtKeyParameters,
  ClpIRsaPrivateCrtKeyParameters,
  ClpRsaKeyGenerationParameters,
  ClpIRsaKeyGenerationParameters,
  ClpRsaKeyPairGenerator,
  ClpIRsaKeyPairGenerator,
  ClpRsaBlindedEngine,
  ClpPkcs1Encoding,
  ClpIPkcs1Encoding,
  ClpOaepEncoding,
  ClpCryptoLibTypes;

type
  TTestRSABlinded = class(TTestCase)
  private
    class var
      FMod: TBigInteger;
      FPubExp: TBigInteger;
      FPrivExp: TBigInteger;
      FP: TBigInteger;
      FQ: TBigInteger;
      FPExp: TBigInteger;
      FQExp: TBigInteger;
      FCrtCoef: TBigInteger;

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
  FMod := TBigInteger.Create('b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6f7540d2509e7b9ffee0a70a6e26d56e' + '92d2edd7f85aba85600b69089f35f6bdbf3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5', 16);
  FPubExp := TBigInteger.Create('11', 16);
  FPrivExp := TBigInteger.Create('92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f56388f72652d8fafc65a4b9020896f2c' + 'de297080f2a540e7b7ce5af0b3446e1258d1dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f7487de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619', 16);
  FP := TBigInteger.Create('f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03', 16);
  FQ := TBigInteger.Create('b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb696fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947', 16);
  FPExp := TBigInteger.Create('1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5', 16);
  FQExp := TBigInteger.Create('6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded', 16);
  FCrtCoef := TBigInteger.Create('dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926d070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339', 16);

  // Test block data for PKCS1 padding validation
  FOversizedSig := THex.Decode('01fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FDudBlock := THex.Decode('000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FTruncatedDataBlock := THex.Decode('0001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff004e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FIncorrectPadding := THex.Decode('0001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');
  FMissingDataBlock := THex.Decode('0001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' + 'fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff');
end;

function TTestRSABlinded.GetPubParameters: IRsaKeyParameters;
begin
  Result := TRsaKeyParameters.Create(False, FMod, FPubExp);
end;

function TTestRSABlinded.GetPrivParameters: IRsaPrivateCrtKeyParameters;
begin
  Result := TRsaPrivateCrtKeyParameters.Create(FMod, FPubExp, FPrivExp, FP, FQ, FPExp, FQExp, FCrtCoef);
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

  data := THex.Decode(Input);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pubParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THex.Encode(data, False), 'Raw RSA test failed');
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

  data := THex.Decode(EdgeInput);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pubParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(EdgeInput, THex.Encode(data, False), 'Raw RSA edge test failed');
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

  data := THex.Decode(Input);

  eng := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  eng.Init(True, pubParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THex.Encode(data, False), 'PKCS1 public/private test failed');
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

  data := THex.Decode(Input);

  eng := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  eng.Init(True, privParams as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, pubParams as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THex.Encode(data, False), 'PKCS1 private/public test failed');
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
  data := THex.Decode(Input);

  eng := TOaepEncoding.Create(TRsaBlindedEngine.Create());
  eng.Init(True, pubParameters as ICipherParameters);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, privParameters as ICipherParameters);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THex.Encode(data, False), 'OAEP test failed');
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

  data := THex.Decode(Input);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pair.Public);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, pair.Private);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THex.Encode(data, False), 'Key generation (768) test failed');
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

  data := THex.Decode(Input);

  eng := TRsaBlindedEngine.Create();
  eng.Init(True, pair.Public);

  data := eng.ProcessBlock(data, 0, System.Length(data));

  eng.Init(False, pair.Private);
  data := eng.ProcessBlock(data, 0, System.Length(data));

  CheckEquals(Input, THex.Encode(data, False), 'Key generation (1024) test failed');
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
      Check(Pos('Block incorrect size', E.Message) > 0,
        'Expected "Block incorrect size" but got: ' + E.Message);
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
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FDudBlock, 'Block incorrect');
end;

procedure TTestRSABlinded.TestMissingDataPkcs1Block;
begin
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FMissingDataBlock, 'Block incorrect');
end;

procedure TTestRSABlinded.TestTruncatedPkcs1Block;
begin
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FTruncatedDataBlock, 'Block incorrect');
end;

procedure TTestRSABlinded.TestWrongPaddingPkcs1Block;
begin
  CheckForPkcs1Exception(GetPubParameters, GetPrivParameters, FIncorrectPadding, 'Block incorrect');
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
