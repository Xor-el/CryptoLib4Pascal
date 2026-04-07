{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit CcmTests;

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
  ClpIAeadBlockCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpCcmBlockCipher,
  ClpICcmBlockCipher,
  ClpBlowfishEngine,
  ClpIBlowfishEngine,
  ClpAesUtilities,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestCcm = class(TCryptoLibAlgorithmTestCase)
  strict private
    var
      FK1, FN1, FA1, FP1, FC1, FT1: TBytes;
      FK2, FN2, FA2, FP2, FC2, FT2: TBytes;
      FK3, FN3, FA3, FP3, FC3, FT3: TBytes;
      FK4, FN4, FA4, FP4, FC4, FT4: TBytes;
      FC5, FT5: TBytes;

  private
    procedure CheckVectors(ACount: Int32; const ACcm: ICcmBlockCipher;
      const AK: TBytes; AMacSize: Int32; const AN, AA, AP, AT, AC: TBytes); overload;

    procedure CheckVectors(ACount: Int32; const ACcm: ICcmBlockCipher;
      const AAdditionalDataType: string; const AK: TBytes; AMacSize: Int32;
      const AN, AA, ASA, AP, AT, AC: TBytes); overload;

    function IsEqual(const AExpected, AOther: TBytes; AOffset: Int32): Boolean;
    function CreateCcmCipher: ICcmBlockCipher;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestNistVectorsAndLongData;
    procedure TestCcmIvParameters;
    procedure TestOffsets;
    procedure TestExceptions;

  end;

implementation

{ TTestCcm }

function TTestCcm.CreateCcmCipher: ICcmBlockCipher;
begin
  Result := TCcmBlockCipher.Create(TAesUtilities.CreateEngine());
end;

procedure TTestCcm.CheckVectors(ACount: Int32; const ACcm: ICcmBlockCipher;
  const AK: TBytes; AMacSize: Int32; const AN, AA, AP, AT, AC: TBytes);
var
  LFirstA, LLastA: TBytes;
begin
  SetLength(LFirstA, Length(AA) div 2);
  SetLength(LLastA, Length(AA) - Length(LFirstA));
  if Length(LFirstA) > 0 then
  begin
    System.Move(AA[0], LFirstA[0], Length(LFirstA));
  end;
  if Length(LLastA) > 0 then
  begin
    System.Move(AA[Length(LFirstA)], LLastA[0], Length(LLastA));
  end;

  CheckVectors(ACount, ACcm, 'all initial associated data', AK, AMacSize,
    AN, AA, nil, AP, AT, AC);
  CheckVectors(ACount, ACcm, 'subsequent associated data', AK, AMacSize,
    AN, nil, AA, AP, AT, AC);
  CheckVectors(ACount, ACcm, 'split associated data', AK, AMacSize,
    AN, LFirstA, LLastA, AP, AT, AC);
end;

procedure TTestCcm.CheckVectors(ACount: Int32; const ACcm: ICcmBlockCipher;
  const AAdditionalDataType: string; const AK: TBytes; AMacSize: Int32;
  const AN, AA, ASA, AP, AT, AC: TBytes);
var
  LKeyParam: IKeyParameter;
  LParams: IAeadParameters;
  LEnc, LTmp, LDec: TBytes;
  LLen: Int32;
begin
  if AK = nil then
  begin
    LKeyParam := nil;
  end
  else
  begin
    LKeyParam := TKeyParameter.Create(AK) as IKeyParameter;
  end;

  LParams := TAeadParameters.Create(LKeyParam, AMacSize, AN, AA);
  ACcm.Init(True, LParams as ICipherParameters);

  SetLength(LEnc, Length(AC));

  if ASA <> nil then
  begin
    ACcm.ProcessAadBytes(ASA, 0, Length(ASA));
  end;

  LLen := ACcm.ProcessBytes(AP, 0, Length(AP), LEnc, 0);
  ACcm.DoFinal(LEnc, LLen);

  if not AreEqual(AC, LEnc) then
  begin
    Fail(Format('encrypted stream fails to match in test %d with %s',
      [ACount, AAdditionalDataType]));
  end;

  ACcm.Init(False, TAeadParameters.Create(TKeyParameter.Create(AK)
    as IKeyParameter, AMacSize, AN, AA) as ICipherParameters);

  SetLength(LTmp, Length(LEnc));
  if ASA <> nil then
  begin
    ACcm.ProcessAadBytes(ASA, 0, Length(ASA));
  end;

  LLen := ACcm.ProcessBytes(LEnc, 0, Length(LEnc), LTmp, 0);
  LLen := LLen + ACcm.DoFinal(LTmp, LLen);

  SetLength(LDec, LLen);
  if LLen > 0 then
  begin
    System.Move(LTmp[0], LDec[0], LLen);
  end;

  if not AreEqual(AP, LDec) then
  begin
    Fail(Format('decrypted stream fails to match in test %d with %s',
      [ACount, AAdditionalDataType]));
  end;

  if not AreEqual(AT, ACcm.GetMac) then
  begin
    Fail(Format('MAC fails to match in test %d with %s',
      [ACount, AAdditionalDataType]));
  end;
end;

function TTestCcm.IsEqual(const AExpected, AOther: TBytes;
  AOffset: Int32): Boolean;
var
  LI: Int32;
begin
  for LI := 0 to High(AExpected) do
  begin
    if AExpected[LI] <> AOther[AOffset + LI] then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := True;
end;

procedure TTestCcm.SetUp;
begin
  inherited;

  FK1 := DecodeHex('404142434445464748494a4b4c4d4e4f');
  FN1 := DecodeHex('10111213141516');
  FA1 := DecodeHex('0001020304050607');
  FP1 := DecodeHex('20212223');
  FC1 := DecodeHex('7162015b4dac255d');
  FT1 := DecodeHex('6084341b');

  FK2 := DecodeHex('404142434445464748494a4b4c4d4e4f');
  FN2 := DecodeHex('1011121314151617');
  FA2 := DecodeHex('000102030405060708090a0b0c0d0e0f');
  FP2 := DecodeHex('202122232425262728292a2b2c2d2e2f');
  FC2 := DecodeHex('d2a1f0e051ea5f62081a7792073d593d1fc64fbfaccd');
  FT2 := DecodeHex('7f479ffca464');

  FK3 := DecodeHex('404142434445464748494a4b4c4d4e4f');
  FN3 := DecodeHex('101112131415161718191a1b');
  FA3 := DecodeHex('000102030405060708090a0b0c0d0e0f10111213');
  FP3 := DecodeHex('202122232425262728292a2b2c2d2e2f3031323334353637');
  FC3 := DecodeHex('e3b201a9f5b71a7a9b1ceaeccd97e70b6176aad9a4428aa5484392fbc1b09951');
  FT3 := DecodeHex('67c99240c7d51048');

  FK4 := DecodeHex('404142434445464748494a4b4c4d4e4f');
  FN4 := DecodeHex('101112131415161718191a1b1c');
  FA4 := DecodeHex(
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f' +
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f' +
    '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f' +
    '606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f' +
    '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f' +
    'a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf' +
    'c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf' +
    'e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');
  FP4 := DecodeHex(
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f');
  FC4 := DecodeHex(
    '69915dad1e84c6376a68c2967e4dab615ae0fd1faec44cc484828529463ccf72' +
    'b4ac6bec93e8598e7f0dadbcea5b');
  FT4 := DecodeHex('f4dd5d0ee404617225ffe34fce91');

  FC5 := DecodeHex(
    '49b17d8d3ea4e6174a48e2b65e6d8b417ac0dd3f8ee46ce4a4a2a509661cef52' +
    '528c1cd9805333a5cfd482fa3f095a3c2fdd1cc47771c5e55fddd60b5c8d6d3f' +
    'a5c8dd79d08b16242b6642106e7c0c28bd1064b31e6d7c9800c8397dbc3fa807' +
    '1e6a38278b386c18d65d39c6ad1ef9501a5c8f68d38eb6474799f3cc898b4b9b' +
    '97e87f9c95ce5c51bc9d758f17119586663a5684e0a0daf6520ec572b87473eb' +
    '141d10471e4799ded9e607655402eca5176bbf792ef39dd135ac8d710da8e9e8' +
    '54fd3b95c681023f36b5ebe2fb213d0b62dd6e9e3cfe190b792ccb20c53423b2' +
    'dca128f861a61d306910e1af418839467e466f0ec361d2539eedd99d4724f1b5' +
    '1c07beb40e875a87491ec8b27cd1');
  FT5 := DecodeHex('5c768856796b627b13ec8641581b');
end;

procedure TTestCcm.TearDown;
begin
  inherited;
end;

procedure TTestCcm.TestNistVectorsAndLongData;
var
  LCcm: ICcmBlockCipher;
  LA4: TBytes;
  LLen: Int32;
begin
  LCcm := CreateCcmCipher;

  // K1..K3 short vectors
  CheckVectors(0, LCcm, FK1, 32, FN1, FA1, FP1, FT1, FC1);
  CheckVectors(1, LCcm, FK2, 48, FN2, FA2, FP2, FT2, FC2);
  CheckVectors(2, LCcm, FK3, 64, FN3, FA3, FP3, FT3, FC3);

  // reduced A4 replicated to long AAD
  SetLength(LA4, 65536);
  LLen := 0;
  while LLen < Length(LA4) do
  begin
    System.Move(FA4[0], LA4[LLen], Length(FA4));
    Inc(LLen, Length(FA4));
  end;

  CheckVectors(3, LCcm, FK4, 112, FN4, LA4, FP4, FT4, FC4);

  // long data case: AAD = A4, plaintext = A4, expected C5/T5
  CheckVectors(4, LCcm, FK4, 112, FN4, FA4, FA4, FT5, FC5);
end;

procedure TTestCcm.TestCcmIvParameters;
var
  LCcm: IAeadBlockCipher;
  LPlain, LEnc, LTmp, LDec: TBytes;
  LParams: IParametersWithIV;
  LLen: Int32;
begin
  LCcm := CreateCcmCipher;
  LPlain := TConverters.ConvertStringToBytes('hello world!!', TEncoding.ASCII);

  LParams := TParametersWithIV.Create(TKeyParameter.Create(FK1) as IKeyParameter,
    FN1);

  LCcm.Init(True, LParams as ICipherParameters);
  SetLength(LEnc, Length(LPlain) + 8);

  LLen := LCcm.ProcessBytes(LPlain, 0, Length(LPlain), LEnc, 0);
  LCcm.DoFinal(LEnc, LLen);

  LCcm.Init(False, LParams as ICipherParameters);
  SetLength(LTmp, Length(LEnc));

  LLen := LCcm.ProcessBytes(LEnc, 0, Length(LEnc), LTmp, 0);
  LLen := LLen + LCcm.DoFinal(LTmp, LLen);

  SetLength(LDec, LLen);
  if LLen > 0 then
  begin
    System.Move(LTmp[0], LDec[0], LLen);
  end;

  if not AreEqual(LPlain, LDec) then
  begin
    Fail('decrypted stream fails to match in IV param test');
  end;
end;

procedure TTestCcm.TestOffsets;
var
  LCcm: ICcmBlockCipher;
  LInBuf, LOutBuf, LOutput: TBytes;
  LLen, LInLen: Int32;
begin
  LCcm := CreateCcmCipher;

  // decryption with output specified, non-zero offset
  LCcm.Init(False,
    TAeadParameters.Create(TKeyParameter.Create(FK2) as IKeyParameter,
    48, FN2, FA2) as ICipherParameters);

  SetLength(LInBuf, Length(FC2) + 10);
  SetLength(LOutBuf, LCcm.GetOutputSize(Length(FC2)) + 10);

  if Length(FC2) > 0 then
  begin
    System.Move(FC2[0], LInBuf[10], Length(FC2));
  end;

  LLen := LCcm.ProcessPacket(LInBuf, 10, Length(FC2), LOutBuf, 10);
  LOutput := LCcm.ProcessPacket(FC2, 0, Length(FC2));

  if (LLen <> Length(LOutput)) or (not IsEqual(LOutput, LOutBuf, 10)) then
  begin
    Fail('decryption output incorrect');
  end;

  // encryption with output specified, non-zero offset
  LCcm.Init(True,
    TAeadParameters.Create(TKeyParameter.Create(FK2) as IKeyParameter,
    48, FN2, FA2) as ICipherParameters);

  LInLen := LLen;
  LInBuf := LOutBuf;
  SetLength(LOutBuf, LCcm.GetOutputSize(LInLen) + 10);

  LLen := LCcm.ProcessPacket(LInBuf, 10, LInLen, LOutBuf, 10);
  LOutput := LCcm.ProcessPacket(LInBuf, 10, LInLen);

  if (LLen <> Length(LOutput)) or (not IsEqual(LOutput, LOutBuf, 10)) then
  begin
    Fail('encryption output incorrect');
  end;
end;

procedure TTestCcm.TestExceptions;
var
  LCcm: ICcmBlockCipher;
  LBad: TBytes;
  LOutput: TBytes;
begin
  LCcm := CreateCcmCipher;

  // Wrong MAC size / ciphertext (truncated or tampered)
  LCcm.Init(False,
    TAeadParameters.Create(TKeyParameter.Create(FK1) as IKeyParameter,
    32, FN2, FA2) as ICipherParameters);

  try
    LOutput := LCcm.ProcessPacket(FC2, 0, Length(FC2));
    Fail('invalid cipher text not picked up');
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      // expected
    end;
  end;

  // Wrong block cipher (wrong block size) – constructor should fail
  try
    LCcm := TCcmBlockCipher.Create(TBlowfishEngine.Create() as IBlowfishEngine);
    Fail('incorrect block size not picked up');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  // Wrong parameter type (KeyParameter instead of AEAD)
  SetLength(LBad, Length(FK1));
  if Length(FK1) > 0 then
  begin
    System.Move(FK1[0], LBad[0], Length(FK1));
  end;
  try
    LCcm := CreateCcmCipher;
    LCcm.Init(False, TKeyParameter.Create(LBad) as IKeyParameter);
    Fail('illegal argument not picked up');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCcm);
{$ELSE}
  RegisterTest(TTestCcm.Suite);
{$ENDIF FPC}

end.

