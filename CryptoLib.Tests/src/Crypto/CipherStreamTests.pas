{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CipherStreamTests;

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
  ClpICipherKeyGenerator,
  ClpIBufferedCipher,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  ClpCfbBlockCipher,
  ClpICfbBlockCipher,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpAesEngine,
  ClpIAesEngine,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpParameterUtilities,
  ClpGeneratorUtilities,
  ClpCipherUtilities,
  ClpStreamUtilities,
  ClpConverters,
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
  LBlockCipher := TAesEngine.Create();
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

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestCipherStream);
{$ELSE}
  RegisterTest(TTestCipherStream.Suite);
{$ENDIF FPC}

end.
