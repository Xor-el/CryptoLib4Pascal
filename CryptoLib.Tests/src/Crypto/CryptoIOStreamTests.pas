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

unit CryptoIOStreamTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpCipherStream,
  ClpDigestStream,
  ClpMacStream,
  ClpSignerStream,
  ClpDigestUtilities,
  ClpMacUtilities,
  ClpSignerUtilities,
  ClpIDigest,
  ClpIMac,
  ClpISigner,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpRsaGenerators,
  ClpIRsaGenerators,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpBigInteger,
  ClpIAsymmetricCipherKeyPair,
  ClpICipherKeyGenerator,
  ClpIBufferedCipher,
  ClpBufferedBlockCipher,
  ClpCfbBlockCipher,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpAesUtilities,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpGeneratorUtilities,
  ClpCipherUtilities,
  ClpStreamUtilities,
  ClpStringUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Check that cipher input/output streams are working correctly.
  /// </summary>
  TTestCipherStream = class(TCryptoLibAlgorithmTestCase)

  strict private
  const
    FData = 'This will be encrypted and then decrypted and checked for correctness';

  strict private
    procedure DoRunTest(const AName: String; AIvLength: Int32);
    procedure DoTestAlgorithm(const AName: String;
      const AKeyBytes, AIv, APlainText, ACipherText: TCryptoLibByteArray);
    procedure DoTestException(const AName: String; AIvLength: Int32);

    function CreateAesCfbCipher(AForEncryption: Boolean): IBufferedCipher;
    function EncryptOnWrite(const ADataBytes: TCryptoLibByteArray): TCryptoLibByteArray;
    function EncryptOnRead(const ADataBytes: TCryptoLibByteArray): TCryptoLibByteArray;
    function DecryptOnRead(const AEncryptedDataBytes: TCryptoLibByteArray): TCryptoLibByteArray;
    function DecryptOnWrite(const AEncryptedDataBytes: TCryptoLibByteArray): TCryptoLibByteArray;

    function StreamToBytes(const AStream: TMemoryStream): TCryptoLibByteArray;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestSalsa20;
    procedure TestSalsa20Exception;
    procedure TestSalsa20Algorithm;

    procedure TestEncryptDecryptA;
    procedure TestEncryptDecryptB;
    procedure TestEncryptDecryptC;
    procedure TestEncryptDecryptD;

  end;

  TTestDigestStream = class(TCryptoLibAlgorithmTestCase)
  strict private
    function DigestReference(const AData: TCryptoLibByteArray): TCryptoLibByteArray;
  published
    procedure TestWriteSide;
    procedure TestReadSide;
    procedure TestReadWriteByte;
    procedure TestLeaveOpen;
  end;

  TTestMacStream = class(TCryptoLibAlgorithmTestCase)
  strict private
    function MacReference(const AKey, AData: TCryptoLibByteArray): TCryptoLibByteArray;
  published
    procedure TestWriteSide;
    procedure TestReadSide;
    procedure TestReadWriteByte;
    procedure TestLeaveOpen;
  end;

  TTestSignerStream = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestWriteSide;
    procedure TestReadSide;
    procedure TestReadWriteByte;
    procedure TestLeaveOpen;
  end;

implementation

{ TTestCipherStream }

procedure TTestCipherStream.SetUp;
begin
  inherited;
end;

procedure TTestCipherStream.TearDown;
begin
  inherited;
end;

function TTestCipherStream.StreamToBytes(const AStream: TMemoryStream): TCryptoLibByteArray;
begin
  System.SetLength(Result, AStream.Size);
  if AStream.Size > 0 then
  begin
    AStream.Position := 0;
    AStream.ReadBuffer(Result[0], AStream.Size);
  end;
end;

procedure TTestCipherStream.DoRunTest(const AName: String; AIvLength: Int32);
var
  LCode: String;
  LBaseName: String;
  LKGen: ICipherKeyGenerator;
  LInCipher, LOutCipher: IBufferedCipher;
  LKey: IKeyParameter;
  LCipherParams: ICipherParameters;
  LBIn: TBytesStream;
  LBOut: TMemoryStream;
  LCIn, LCOut: TCipherStream;
  LC: Int32;
  LBs: TCryptoLibByteArray;
  LRes: String;
begin
  LCode := 'ABCDEFGHIJKLMNOPQRSTUVWXY0123456789';

  LBaseName := TStringUtilities.SplitString(AName, '/', 2)[0];

  LKGen := TGeneratorUtilities.GetKeyGenerator(LBaseName);

  LInCipher := TCipherUtilities.GetCipher(AName);
  LOutCipher := TCipherUtilities.GetCipher(AName);
  LKey := TParameterUtilities.CreateKeyParameter(LBaseName, LKGen.GenerateKey());

  LCipherParams := LKey;
  if AIvLength > 0 then
  begin
    System.SetLength(LBs, AIvLength);
    LCipherParams := TParametersWithIV.Create(LCipherParams, LBs);
  end;

  LInCipher.Init(True, LCipherParams);
  LOutCipher.Init(False, LCipherParams);

  LBIn := TBytesStream.Create(TEncoding.ASCII.GetBytes(LCode));
  LBOut := TMemoryStream.Create;
  try
    LCIn := TCipherStream.Create(LBIn, LInCipher, nil, True);
    try
      LCOut := TCipherStream.Create(LBOut, nil, LOutCipher, True);
      try
        LC := LCIn.ReadByte();
        while LC >= 0 do
        begin
          LCOut.WriteByte(Byte(LC));
          LC := LCIn.ReadByte();
        end;
      finally
        LCOut.Free;
      end;
    finally
      LCIn.Free;
    end;

    LBs := StreamToBytes(LBOut);
    LRes := TEncoding.ASCII.GetString(LBs);

    if LRes <> LCode then
      Fail('Failed - decrypted data doesn''t match.');
  finally
    LBIn.Free;
    LBOut.Free;
  end;
end;

procedure TTestCipherStream.DoTestAlgorithm(const AName: String;
  const AKeyBytes, AIv, APlainText, ACipherText: TCryptoLibByteArray);
var
  LKey: IKeyParameter;
  LInCipher, LOutCipher: IBufferedCipher;
  LEnc, LDec: TCryptoLibByteArray;
begin
  LKey := TParameterUtilities.CreateKeyParameter(AName, AKeyBytes);

  LInCipher := TCipherUtilities.GetCipher(AName);
  LOutCipher := TCipherUtilities.GetCipher(AName);

  if AIv <> nil then
  begin
    LInCipher.Init(True, TParametersWithIV.Create(LKey, AIv) as IParametersWithIV);
    LOutCipher.Init(False, TParametersWithIV.Create(LKey, AIv) as IParametersWithIV);
  end
  else
  begin
    LInCipher.Init(True, LKey);
    LOutCipher.Init(False, LKey);
  end;

  LEnc := LInCipher.DoFinal(APlainText);
  if not AreEqual(LEnc, ACipherText) then
    Fail(AName + ': cipher text doesn''t match');

  LDec := LOutCipher.DoFinal(LEnc);
  if not AreEqual(LDec, APlainText) then
    Fail(AName + ': plain text doesn''t match');
end;

procedure TTestCipherStream.DoTestException(const AName: String; AIvLength: Int32);
var
  LKeyBytes: TCryptoLibByteArray;
  LCipherKey: IKeyParameter;
  LCipherParams: ICipherParameters;
  LECipher: IBufferedCipher;
  LCipherText: TCryptoLibByteArray;
begin
  LKeyBytes := TCryptoLibByteArray.Create(
    128, 131, 133, 134, 137, 138, 140, 143,
    128, 131, 133, 134, 137, 138, 140, 143);

  LCipherKey := TParameterUtilities.CreateKeyParameter(AName, LKeyBytes);

  LCipherParams := LCipherKey;
  if AIvLength > 0 then
  begin
    System.SetLength(LKeyBytes, AIvLength);
    FillChar(LKeyBytes[0], AIvLength, 0);
    LCipherParams := TParametersWithIV.Create(LCipherParams, LKeyBytes);
  end;

  LECipher := TCipherUtilities.GetCipher(AName);
  LECipher.Init(True, LCipherParams);

  System.SetLength(LCipherText, 0);
  try
    LECipher.ProcessBytes(TCryptoLibByteArray.Create(
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
      0, 20, LCipherText, 0);

    Fail('failed exception test - no DataLengthException thrown');
  except
    on E: EDataLengthCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestCipherStream.TestSalsa20;
begin
  DoRunTest('Salsa20', 8);
end;

procedure TTestCipherStream.TestSalsa20Exception;
begin
  DoTestException('Salsa20', 8);
end;

procedure TTestCipherStream.TestSalsa20Algorithm;
var
  LSIn, LSK, LSIv, LSOut: TCryptoLibByteArray;
begin
  LSIn := DecodeHex(
    '00000000000000000000000000000000'
    + '00000000000000000000000000000000'
    + '00000000000000000000000000000000'
    + '00000000000000000000000000000000');
  LSK := DecodeHex('80000000000000000000000000000000');
  LSIv := DecodeHex('0000000000000000');
  LSOut := DecodeHex(
    '4DFA5E481DA23EA09A31022050859936'
    + 'DA52FCEE218005164F267CB65F5CFD7F'
    + '2B4F97E0FF16924A52DF269515110A07'
    + 'F9E460BC65EF95DA58F740B7D1DBB0AA');

  DoTestAlgorithm('Salsa20', LSK, LSIv, LSIn, LSOut);
end;

// AES/CFB encrypt/decrypt combination tests

function TTestCipherStream.CreateAesCfbCipher(AForEncryption: Boolean): IBufferedCipher;
var
  LBlockCipher: IBlockCipher;
  LBits: Int32;
  LBlockCipherMode: IBlockCipherMode;
  LKeyBytes, LIv: TCryptoLibByteArray;
  LKey: IKeyParameter;
begin
  LBlockCipher := TAesUtilities.CreateEngine();
  LBits := 8 * LBlockCipher.GetBlockSize();
  LBlockCipherMode := TCfbBlockCipher.Create(LBlockCipher, LBits);
  Result := TBufferedBlockCipher.Create(LBlockCipherMode);

  System.SetLength(LKeyBytes, 32);
  LKey := TKeyParameter.Create(LKeyBytes);

  System.SetLength(LIv, Result.GetBlockSize());

  Result.Init(AForEncryption, TParametersWithIV.Create(LKey, LIv) as IParametersWithIV);
end;

function TTestCipherStream.EncryptOnWrite(const ADataBytes: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LEncryptedDataStream: TMemoryStream;
  LOutCipher: IBufferedCipher;
  LOutCipherStream: TCipherStream;
begin
  LEncryptedDataStream := TMemoryStream.Create;
  try
    LOutCipher := CreateAesCfbCipher(True);
    LOutCipherStream := TCipherStream.Create(LEncryptedDataStream, nil, LOutCipher, True);
    try
      LOutCipherStream.Write(ADataBytes[0], System.Length(ADataBytes));
      CheckEquals(0, LEncryptedDataStream.Position mod LOutCipher.GetBlockSize());
    finally
      LOutCipherStream.Free;
    end;

    Result := StreamToBytes(LEncryptedDataStream);
    CheckEquals(System.Length(ADataBytes), System.Length(Result));
  finally
    LEncryptedDataStream.Free;
  end;
end;

function TTestCipherStream.EncryptOnRead(const ADataBytes: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDataStream: TBytesStream;
  LEncryptedDataStream: TMemoryStream;
  LInCipher: IBufferedCipher;
  LInCipherStream: TCipherStream;
  LCh: Int32;
begin
  LDataStream := TBytesStream.Create(ADataBytes);
  LEncryptedDataStream := TMemoryStream.Create;
  try
    LInCipher := CreateAesCfbCipher(True);
    LInCipherStream := TCipherStream.Create(LDataStream, LInCipher, nil, True);
    try
      LCh := LInCipherStream.ReadByte();
      while LCh >= 0 do
      begin
        LEncryptedDataStream.WriteByte(Byte(LCh));
        LCh := LInCipherStream.ReadByte();
      end;
    finally
      LInCipherStream.Free;
    end;

    Result := StreamToBytes(LEncryptedDataStream);
    CheckEquals(System.Length(ADataBytes), System.Length(Result));
  finally
    LDataStream.Free;
    LEncryptedDataStream.Free;
  end;
end;

function TTestCipherStream.DecryptOnRead(const AEncryptedDataBytes: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LEncryptedDataStream: TBytesStream;
  LDataStream: TMemoryStream;
  LInCipher: IBufferedCipher;
  LInCipherStream: TCipherStream;
  LCh: Int32;
begin
  LEncryptedDataStream := TBytesStream.Create(AEncryptedDataBytes);
  LDataStream := TMemoryStream.Create;
  try
    LInCipher := CreateAesCfbCipher(False);
    LInCipherStream := TCipherStream.Create(LEncryptedDataStream, LInCipher, nil, True);
    try
      LCh := LInCipherStream.ReadByte();
      while LCh >= 0 do
      begin
        LDataStream.WriteByte(Byte(LCh));
        LCh := LInCipherStream.ReadByte();
      end;
    finally
      LInCipherStream.Free;
    end;

    Result := StreamToBytes(LDataStream);
    CheckEquals(System.Length(AEncryptedDataBytes), System.Length(Result));
  finally
    LEncryptedDataStream.Free;
    LDataStream.Free;
  end;
end;

function TTestCipherStream.DecryptOnWrite(const AEncryptedDataBytes: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LEncryptedDataStream: TBytesStream;
  LDataStream: TMemoryStream;
  LOutCipher: IBufferedCipher;
  LOutCipherStream: TCipherStream;
  LCh: Int32;
begin
  LEncryptedDataStream := TBytesStream.Create(AEncryptedDataBytes);
  LDataStream := TMemoryStream.Create;
  try
    LOutCipher := CreateAesCfbCipher(False);
    LOutCipherStream := TCipherStream.Create(LDataStream, nil, LOutCipher, True);
    try
      LCh := LEncryptedDataStream.ReadByte();
      while LCh >= 0 do
      begin
        LOutCipherStream.WriteByte(Byte(LCh));
        LCh := LEncryptedDataStream.ReadByte();
      end;
    finally
      LOutCipherStream.Free;
    end;

    Result := StreamToBytes(LDataStream);
    CheckEquals(System.Length(AEncryptedDataBytes), System.Length(Result));
  finally
    LEncryptedDataStream.Free;
    LDataStream.Free;
  end;
end;

procedure TTestCipherStream.TestEncryptDecryptA;
var
  LDataBytes, LEncryptedDataBytes, LDecryptedDataBytes: TCryptoLibByteArray;
  LDecryptedData: String;
begin
  LDataBytes := TEncoding.ASCII.GetBytes(FData);
  LEncryptedDataBytes := EncryptOnWrite(LDataBytes);
  LDecryptedDataBytes := DecryptOnRead(LEncryptedDataBytes);
  LDecryptedData := TEncoding.ASCII.GetString(LDecryptedDataBytes);
  CheckEquals(FData, LDecryptedData);
end;

procedure TTestCipherStream.TestEncryptDecryptB;
var
  LDataBytes, LEncryptedDataBytes, LDecryptedDataBytes: TCryptoLibByteArray;
  LDecryptedData: String;
begin
  LDataBytes := TEncoding.ASCII.GetBytes(FData);
  LEncryptedDataBytes := EncryptOnRead(LDataBytes);
  LDecryptedDataBytes := DecryptOnWrite(LEncryptedDataBytes);
  LDecryptedData := TEncoding.ASCII.GetString(LDecryptedDataBytes);
  CheckEquals(FData, LDecryptedData);
end;

procedure TTestCipherStream.TestEncryptDecryptC;
var
  LDataBytes, LEncryptedDataBytes, LDecryptedDataBytes: TCryptoLibByteArray;
  LDecryptedData: String;
begin
  LDataBytes := TEncoding.ASCII.GetBytes(FData);
  LEncryptedDataBytes := EncryptOnWrite(LDataBytes);
  LDecryptedDataBytes := DecryptOnWrite(LEncryptedDataBytes);
  LDecryptedData := TEncoding.ASCII.GetString(LDecryptedDataBytes);
  CheckEquals(FData, LDecryptedData);
end;

procedure TTestCipherStream.TestEncryptDecryptD;
var
  LDataBytes, LEncryptedDataBytes, LDecryptedDataBytes: TCryptoLibByteArray;
  LDecryptedData: String;
begin
  LDataBytes := TEncoding.ASCII.GetBytes(FData);
  LEncryptedDataBytes := EncryptOnRead(LDataBytes);
  LDecryptedDataBytes := DecryptOnRead(LEncryptedDataBytes);
  LDecryptedData := TEncoding.ASCII.GetString(LDecryptedDataBytes);
  CheckEquals(FData, LDecryptedData);
end;

{ TTestDigestStream }

function TTestDigestStream.DigestReference(const AData: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LDigest: IDigest;
begin
  LDigest := TDigestUtilities.GetDigest('SHA-256');
  LDigest.BlockUpdate(AData, 0, System.Length(AData));
  Result := LDigest.DoFinal();
end;

procedure TTestDigestStream.TestWriteSide;
var
  LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LMem: TMemoryStream;
  LWriteDigest: IDigest;
  LDigestStream: TDigestStream;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('digest stream write');
  LExpected := DigestReference(LDataBytes);

  LMem := TMemoryStream.Create;
  try
    LWriteDigest := TDigestUtilities.GetDigest('SHA-256');
    LDigestStream := TDigestStream.Create(LMem, nil, LWriteDigest, True);
    try
      LDigestStream.Write(LDataBytes[0], System.Length(LDataBytes));
      LActual := LDigestStream.WriteDigest.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
      CheckEquals(Int64(System.Length(LDataBytes)), LMem.Size);
    finally
      LDigestStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestDigestStream.TestReadSide;
var
  LDataBytes, LExpected, LActual, LBuffer: TCryptoLibByteArray;
  LMem: TBytesStream;
  LReadDigest: IDigest;
  LDigestStream: TDigestStream;
  LRead: Int32;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('digest stream read');
  LExpected := DigestReference(LDataBytes);

  LMem := TBytesStream.Create(LDataBytes);
  try
    LReadDigest := TDigestUtilities.GetDigest('SHA-256');
    LDigestStream := TDigestStream.Create(LMem, LReadDigest, nil, True);
    try
      System.SetLength(LBuffer, System.Length(LDataBytes));
      LRead := LDigestStream.Read(LBuffer[0], System.Length(LBuffer));
      CheckEquals(System.Length(LDataBytes), LRead);
      LActual := LDigestStream.ReadDigest.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
    finally
      LDigestStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestDigestStream.TestReadWriteByte;
var
  LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LMem: TMemoryStream;
  LWriteDigest, LReadDigest: IDigest;
  LDigestStream: TDigestStream;
  LI, LCh: Int32;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('xy');
  LExpected := DigestReference(LDataBytes);

  LMem := TMemoryStream.Create;
  try
    LWriteDigest := TDigestUtilities.GetDigest('SHA-256');
    LDigestStream := TDigestStream.Create(LMem, nil, LWriteDigest, True);
    try
      for LI := 0 to System.Length(LDataBytes) - 1 do
        LDigestStream.WriteByte(LDataBytes[LI]);
      LActual := LDigestStream.WriteDigest.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
    finally
      LDigestStream.Free;
    end;

    LMem.Position := 0;
    LReadDigest := TDigestUtilities.GetDigest('SHA-256');
    LDigestStream := TDigestStream.Create(LMem, LReadDigest, nil, True);
    try
      LCh := LDigestStream.ReadByte();
      while LCh >= 0 do
        LCh := LDigestStream.ReadByte();
      LActual := LDigestStream.ReadDigest.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
    finally
      LDigestStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestDigestStream.TestLeaveOpen;
var
  LMem: TMemoryStream;
  LWriteDigest: IDigest;
  LDigestStream: TDigestStream;
  LData: TCryptoLibByteArray;
begin
  LData := TEncoding.UTF8.GetBytes('leave open');
  LMem := TMemoryStream.Create;
  LWriteDigest := TDigestUtilities.GetDigest('SHA-256');
  LDigestStream := TDigestStream.Create(LMem, nil, LWriteDigest, True);
  try
    LDigestStream.Write(LData[0], System.Length(LData));
  finally
    LDigestStream.Free;
  end;

  CheckEquals(Int64(System.Length(LData)), LMem.Size);
  LMem.Free;
end;

{ TTestMacStream }

function TTestMacStream.MacReference(const AKey, AData: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LMac: IMac;
begin
  LMac := TMacUtilities.GetMac('HMAC/SHA-256');
  LMac.Init(TKeyParameter.Create(AKey) as IKeyParameter);
  LMac.BlockUpdate(AData, 0, System.Length(AData));
  Result := LMac.DoFinal();
end;

procedure TTestMacStream.TestWriteSide;
var
  LKey, LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LMem: TMemoryStream;
  LWriteMac: IMac;
  LMacStream: TMacStream;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LDataBytes := TEncoding.UTF8.GetBytes('mac stream write');
  LExpected := MacReference(LKey, LDataBytes);

  LMem := TMemoryStream.Create;
  try
    LWriteMac := TMacUtilities.GetMac('HMAC/SHA-256');
    LWriteMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    LMacStream := TMacStream.Create(LMem, nil, LWriteMac, True);
    try
      LMacStream.Write(LDataBytes[0], System.Length(LDataBytes));
      LActual := LMacStream.WriteMac.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
    finally
      LMacStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestMacStream.TestReadSide;
var
  LKey, LDataBytes, LExpected, LActual, LBuffer: TCryptoLibByteArray;
  LMem: TBytesStream;
  LReadMac: IMac;
  LMacStream: TMacStream;
  LRead: Int32;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LDataBytes := TEncoding.UTF8.GetBytes('mac stream read');
  LExpected := MacReference(LKey, LDataBytes);

  LMem := TBytesStream.Create(LDataBytes);
  try
    LReadMac := TMacUtilities.GetMac('HMAC/SHA-256');
    LReadMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    LMacStream := TMacStream.Create(LMem, LReadMac, nil, True);
    try
      System.SetLength(LBuffer, System.Length(LDataBytes));
      LRead := LMacStream.Read(LBuffer[0], System.Length(LBuffer));
      CheckEquals(System.Length(LDataBytes), LRead);
      LActual := LMacStream.ReadMac.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
    finally
      LMacStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestMacStream.TestReadWriteByte;
var
  LKey, LDataBytes, LExpected, LActual: TCryptoLibByteArray;
  LMem: TMemoryStream;
  LWriteMac, LReadMac: IMac;
  LMacStream: TMacStream;
  LI, LCh: Int32;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LDataBytes := TEncoding.UTF8.GetBytes('z');
  LExpected := MacReference(LKey, LDataBytes);

  LMem := TMemoryStream.Create;
  try
    LWriteMac := TMacUtilities.GetMac('HMAC/SHA-256');
    LWriteMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    LMacStream := TMacStream.Create(LMem, nil, LWriteMac, True);
    try
      for LI := 0 to System.Length(LDataBytes) - 1 do
        LMacStream.WriteByte(LDataBytes[LI]);
      LActual := LMacStream.WriteMac.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
    finally
      LMacStream.Free;
    end;

    LMem.Position := 0;
    LReadMac := TMacUtilities.GetMac('HMAC/SHA-256');
    LReadMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    LMacStream := TMacStream.Create(LMem, LReadMac, nil, True);
    try
      LCh := LMacStream.ReadByte();
      CheckTrue(LCh >= 0);
      LActual := LMacStream.ReadMac.DoFinal();
      CheckTrue(AreEqual(LExpected, LActual));
    finally
      LMacStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestMacStream.TestLeaveOpen;
var
  LMem: TMemoryStream;
  LWriteMac: IMac;
  LMacStream: TMacStream;
  LKey, LData: TCryptoLibByteArray;
begin
  LKey := TEncoding.ASCII.GetBytes('0123456789ABCDEF');
  LData := TEncoding.UTF8.GetBytes('open');
  LMem := TMemoryStream.Create;
  LWriteMac := TMacUtilities.GetMac('HMAC/SHA-256');
  LWriteMac.Init(TKeyParameter.Create(LKey) as IKeyParameter);
  LMacStream := TMacStream.Create(LMem, nil, LWriteMac, True);
  try
    LMacStream.Write(LData[0], System.Length(LData));
  finally
    LMacStream.Free;
  end;

  CheckEquals(Int64(System.Length(LData)), LMem.Size);
  LMem.Free;
end;

{ TTestSignerStream }

procedure TTestSignerStream.TestWriteSide;
var
  LDataBytes, LSignature: TCryptoLibByteArray;
  LMem: TMemoryStream;
  LKpGen: IRsaKeyPairGenerator;
  LKpParams: IRsaKeyGenerationParameters;
  LKeyPair: IAsymmetricCipherKeyPair;
  LWriteSigner: ISigner;
  LSignerStream: TSignerStream;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('signer stream write');

  LKpGen := TRsaKeyPairGenerator.Create();
  LKpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create() as ISecureRandom,
    1024,
    80);
  LKpGen.Init(LKpParams);
  LKeyPair := LKpGen.GenerateKeyPair();

  LMem := TMemoryStream.Create;
  try
    LWriteSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
    LWriteSigner.Init(True, LKeyPair.Private);
    LSignerStream := TSignerStream.Create(LMem, nil, LWriteSigner, True);
    try
      LSignerStream.Write(LDataBytes[0], System.Length(LDataBytes));
      LSignature := LSignerStream.WriteSigner.GenerateSignature();

      LWriteSigner.Init(False, LKeyPair.Public);
      LWriteSigner.BlockUpdate(LDataBytes, 0, System.Length(LDataBytes));
      CheckTrue(LWriteSigner.VerifySignature(LSignature));
    finally
      LSignerStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestSignerStream.TestReadSide;
var
  LDataBytes, LSignature, LBuffer: TCryptoLibByteArray;
  LMem: TBytesStream;
  LKpGen: IRsaKeyPairGenerator;
  LKpParams: IRsaKeyGenerationParameters;
  LKeyPair: IAsymmetricCipherKeyPair;
  LReadSigner: ISigner;
  LSignerStream: TSignerStream;
  LRead: Int32;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('signer stream read');

  LKpGen := TRsaKeyPairGenerator.Create();
  LKpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create() as ISecureRandom,
    1024,
    80);
  LKpGen.Init(LKpParams);
  LKeyPair := LKpGen.GenerateKeyPair();

  LMem := TBytesStream.Create(LDataBytes);
  try
    LReadSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
    LReadSigner.Init(True, LKeyPair.Private);
    LSignerStream := TSignerStream.Create(LMem, LReadSigner, nil, True);
    try
      System.SetLength(LBuffer, System.Length(LDataBytes));
      LRead := LSignerStream.Read(LBuffer[0], System.Length(LBuffer));
      CheckEquals(System.Length(LDataBytes), LRead);
      LSignature := LSignerStream.ReadSigner.GenerateSignature();

      LReadSigner.Init(False, LKeyPair.Public);
      LReadSigner.BlockUpdate(LDataBytes, 0, System.Length(LDataBytes));
      CheckTrue(LReadSigner.VerifySignature(LSignature));
    finally
      LSignerStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestSignerStream.TestReadWriteByte;
var
  LDataBytes, LSignature: TCryptoLibByteArray;
  LMem: TMemoryStream;
  LKpGen: IRsaKeyPairGenerator;
  LKpParams: IRsaKeyGenerationParameters;
  LKeyPair: IAsymmetricCipherKeyPair;
  LWriteSigner, LReadSigner: ISigner;
  LSignerStream: TSignerStream;
  LCh: Int32;
begin
  LDataBytes := TEncoding.UTF8.GetBytes('a');

  LKpGen := TRsaKeyPairGenerator.Create();
  LKpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create() as ISecureRandom,
    1024,
    80);
  LKpGen.Init(LKpParams);
  LKeyPair := LKpGen.GenerateKeyPair();

  LMem := TMemoryStream.Create;
  try
    LWriteSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
    LWriteSigner.Init(True, LKeyPair.Private);
    LSignerStream := TSignerStream.Create(LMem, nil, LWriteSigner, True);
    try
      LSignerStream.WriteByte(LDataBytes[0]);
      LSignature := LSignerStream.WriteSigner.GenerateSignature();
      LWriteSigner.Init(False, LKeyPair.Public);
      LWriteSigner.BlockUpdate(LDataBytes, 0, System.Length(LDataBytes));
      CheckTrue(LWriteSigner.VerifySignature(LSignature));
    finally
      LSignerStream.Free;
    end;

    LMem.Position := 0;
    LReadSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
    LReadSigner.Init(True, LKeyPair.Private);
    LSignerStream := TSignerStream.Create(LMem, LReadSigner, nil, True);
    try
      LCh := LSignerStream.ReadByte();
      CheckEquals(Int32(LDataBytes[0]), LCh);
      LSignature := LSignerStream.ReadSigner.GenerateSignature();
      LReadSigner.Init(False, LKeyPair.Public);
      LReadSigner.BlockUpdate(LDataBytes, 0, System.Length(LDataBytes));
      CheckTrue(LReadSigner.VerifySignature(LSignature));
    finally
      LSignerStream.Free;
    end;
  finally
    LMem.Free;
  end;
end;

procedure TTestSignerStream.TestLeaveOpen;
var
  LMem: TMemoryStream;
  LWriteSigner: ISigner;
  LSignerStream: TSignerStream;
  LKpGen: IRsaKeyPairGenerator;
  LKpParams: IRsaKeyGenerationParameters;
  LKeyPair: IAsymmetricCipherKeyPair;
  LData: TCryptoLibByteArray;
begin
  LData := TEncoding.UTF8.GetBytes('open');

  LKpGen := TRsaKeyPairGenerator.Create();
  LKpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create() as ISecureRandom,
    1024,
    80);
  LKpGen.Init(LKpParams);
  LKeyPair := LKpGen.GenerateKeyPair();

  LMem := TMemoryStream.Create;
  LWriteSigner := TSignerUtilities.GetSigner('SHA-256withRSA');
  LWriteSigner.Init(True, LKeyPair.Private);
  LSignerStream := TSignerStream.Create(LMem, nil, LWriteSigner, True);
  try
    LSignerStream.Write(LData[0], System.Length(LData));
  finally
    LSignerStream.Free;
  end;

  CheckEquals(Int64(System.Length(LData)), LMem.Size);
  LMem.Free;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestCipherStream);
  RegisterTest(TTestDigestStream);
  RegisterTest(TTestMacStream);
  RegisterTest(TTestSignerStream);
{$ELSE}
  RegisterTest(TTestCipherStream.Suite);
  RegisterTest(TTestDigestStream.Suite);
  RegisterTest(TTestMacStream.Suite);
  RegisterTest(TTestSignerStream.Suite);
{$ENDIF FPC}

end.
