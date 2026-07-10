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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  ClpIAeadCipher,
  AeadTestUtilities,
  AcceleratedKernelToggle,
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
    procedure CheckVectors(ACount: Int32;
      const AK: TBytes; AMacSize: Int32; const AN, AA, AP, AT, AC: TBytes); overload;

    procedure CheckVectors(ACount: Int32; const ACcm: ICcmBlockCipher;
      const AAdditionalDataType: string; const AK: TBytes; AMacSize: Int32;
      const AN, AA, ASA, AP, AT, AC: TBytes); overload;

    function IsEqual(const AExpected, AOther: TBytes; AOffset: Int32): Boolean;
    function CreateCcmCipher: ICcmBlockCipher;

    function NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;
    procedure RandomisedRoundTrip(const ARandom: ISecureRandom);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

    // Workers run twice via RunWithAcceleratedToggle (accelerated on / off).
    procedure DoTestNistVectorsAndLongData;
    procedure DoTestCcmIvParameters;
    procedure DoTestOffsets;
    procedure DoTestRandomised;
    procedure DoTestInvalidTagLength;
    procedure DoTestValidTagLength;
    procedure DoTestBoundaryLimits;
    procedure DoTestNoUnverifiedPlaintextOnFailure;

  published
    procedure TestNistVectorsAndLongData;
    procedure TestCcmIvParameters;
    procedure TestOffsets;
    procedure TestRandomised;
    procedure TestExceptions;
    procedure TestInvalidTagLength;
    procedure TestValidTagLength;
    procedure TestNoUnverifiedPlaintextOnFailure;

  end;

implementation

{ TTestCcm }

function TTestCcm.CreateCcmCipher: ICcmBlockCipher;
begin
  Result := TCcmBlockCipher.Create(TAesUtilities.CreateEngine());
end;

procedure TTestCcm.CheckVectors(ACount: Int32;
  const AK: TBytes; AMacSize: Int32; const AN, AA, AP, AT, AC: TBytes);
var
  LFirstA, LLastA: TBytes;
  LReuse: ICcmBlockCipher;
  LParams: IAeadParameters;
  LEnc: TBytes;
  LLen: Int32;
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

  CheckVectors(ACount, CreateCcmCipher, 'all initial associated data', AK, AMacSize,
    AN, AA, nil, AP, AT, AC);
  CheckVectors(ACount, CreateCcmCipher, 'subsequent associated data', AK, AMacSize,
    AN, nil, AA, AP, AT, AC);
  CheckVectors(ACount, CreateCcmCipher, 'split associated data', AK, AMacSize,
    AN, LFirstA, LLastA, AP, AT, AC);

  LReuse := CreateCcmCipher;
  LParams := TAeadParameters.Create(TKeyParameter.Create(AK) as IKeyParameter,
    AMacSize, AN, AA);
  LReuse.Init(True, LParams as ICipherParameters);
  SetLength(LEnc, LReuse.GetOutputSize(Length(AP)));
  LLen := LReuse.ProcessBytes(AP, 0, Length(AP), LEnc, 0);
  LReuse.DoFinal(LEnc, LLen);
  try
    LReuse.Init(True, TAeadParameters.Create(nil, AMacSize, AN, AA)
      as ICipherParameters);
    Fail(Format('CCM nonce reuse not detected on re-init for encryption in test %d',
      [ACount]));
  except
    on E: EArgumentCryptoLibException do
    begin
      if E.Message <> 'cannot reuse nonce for CCM encryption' then
        Fail('wrong CCM nonce-reuse message: ' + E.Message);
    end;
  end;
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

procedure TTestCcm.DoTestNistVectorsAndLongData;
var
  LA4: TBytes;
  LLen: Int32;
begin
  CheckVectors(0, FK1, 32, FN1, FA1, FP1, FT1, FC1);
  CheckVectors(1, FK2, 48, FN2, FA2, FP2, FT2, FC2);
  CheckVectors(2, FK3, 64, FN3, FA3, FP3, FT3, FC3);

  // reduced A4 replicated to long AAD
  SetLength(LA4, 65536);
  LLen := 0;
  while LLen < Length(LA4) do
  begin
    System.Move(FA4[0], LA4[LLen], Length(FA4));
    Inc(LLen, Length(FA4));
  end;

  CheckVectors(3, FK4, 112, FN4, LA4, FP4, FT4, FC4);

  // long data case: AAD = A4, plaintext = A4, expected C5/T5
  CheckVectors(4, FK4, 112, FN4, FA4, FA4, FT5, FC5);
end;

procedure TTestCcm.DoTestCcmIvParameters;
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

procedure TTestCcm.DoTestOffsets;
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
  LCcm := CreateCcmCipher;
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

function TTestCcm.NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;
begin
  if AN <= 0 then
  begin
    Result := 0;
    Exit;
  end;
  Result := Int32(UInt32(ARandom.NextInt32) and $7FFFFFFF) mod AN;
end;

procedure TTestCcm.RandomisedRoundTrip(const ARandom: ISecureRandom);
var
  LKey, LNonce, LAad, LPlain, LEnc, LDec, LTmp: TBytes;
  LKeyBits, LKeyBytes, LNonceLen, LAadLen, LPlainLen, LMacBytes,
    LMacBits, LIdx, LLen: Int32;
  LCcm: ICcmBlockCipher;
  LParams: IAeadParameters;
begin
  // Sweep key sizes, nonce / AAD / plaintext lengths covering every
  // branch of the fused vs scalar CCM body paths.
  for LIdx := 0 to 31 do
  begin
    case LIdx mod 3 of
      0:
        LKeyBits := 128;
      1:
        LKeyBits := 192;
      else
        LKeyBits := 256;
    end;
    LKeyBytes := LKeyBits div 8;
    SetLength(LKey, LKeyBytes);
    ARandom.NextBytes(LKey);

    LNonceLen := 7 + NextInt32(ARandom, 7); // 7..13
    SetLength(LNonce, LNonceLen);
    ARandom.NextBytes(LNonce);

    LAadLen := NextInt32(ARandom, 4097);
    SetLength(LAad, LAadLen);
    if LAadLen > 0 then
      ARandom.NextBytes(LAad);

    LPlainLen := NextInt32(ARandom, 4097);
    SetLength(LPlain, LPlainLen);
    if LPlainLen > 0 then
      ARandom.NextBytes(LPlain);

    // CCM allowed MAC lengths: 4, 6, 8, 10, 12, 14, 16 bytes.
    LMacBytes := 4 + 2 * NextInt32(ARandom, 7);
    LMacBits := LMacBytes * 8;

    LParams := TAeadParameters.Create(TKeyParameter.Create(LKey)
      as IKeyParameter, LMacBits, LNonce, LAad);

    LCcm := CreateCcmCipher;
    LCcm.Init(True, LParams as ICipherParameters);
    SetLength(LEnc, LCcm.GetOutputSize(LPlainLen));
    LLen := LCcm.ProcessBytes(LPlain, 0, LPlainLen, LEnc, 0);
    LLen := LLen + LCcm.DoFinal(LEnc, LLen);
    if LLen <> Length(LEnc) then
      Fail(Format('encrypt output length mismatch at iter %d (got %d, want %d)',
        [LIdx, LLen, Length(LEnc)]));

    LCcm.Init(False, LParams as ICipherParameters);
    SetLength(LTmp, LCcm.GetOutputSize(Length(LEnc)));
    LLen := LCcm.ProcessBytes(LEnc, 0, Length(LEnc), LTmp, 0);
    LLen := LLen + LCcm.DoFinal(LTmp, LLen);
    SetLength(LDec, LLen);
    if LLen > 0 then
      System.Move(LTmp[0], LDec[0], LLen);

    if not AreEqual(LPlain, LDec) then
      Fail(Format('round-trip plaintext mismatch at iter %d ' +
        '(keybits=%d nonce=%d aad=%d plain=%d mac=%d)',
        [LIdx, LKeyBits, LNonceLen, LAadLen, LPlainLen, LMacBytes]));
  end;
end;

procedure TTestCcm.DoTestRandomised;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.GetInstance('SHA256PRNG');
  LRandom.SetSeed(TConverters.ConvertStringToBytes('CcmDualModeRandomSeed-v1',
    TEncoding.ASCII));
  RandomisedRoundTrip(LRandom);
end;

procedure TTestCcm.TestNistVectorsAndLongData;
begin
  RunWithAcceleratedToggle(DoTestNistVectorsAndLongData);
end;

procedure TTestCcm.TestCcmIvParameters;
begin
  RunWithAcceleratedToggle(DoTestCcmIvParameters);
end;

procedure TTestCcm.TestOffsets;
begin
  RunWithAcceleratedToggle(DoTestOffsets);
end;

procedure TTestCcm.TestRandomised;
begin
  RunWithAcceleratedToggle(DoTestRandomised);
end;

procedure TTestCcm.TestExceptions;
var
  LCcm: ICcmBlockCipher;
  LBad: TBytes;
  LOutput: TBytes;
  LParams: IAeadParameters;
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

  DoTestBoundaryLimits;

  LParams := TAeadParameters.Create(TKeyParameter.Create(FK1) as IKeyParameter,
    32, FN2, FA2);
  TAeadTestUtilities.TestReset('CCM', CreateCcmCipher as IAeadCipher,
    CreateCcmCipher as IAeadCipher, LParams as ICipherParameters);
  TAeadTestUtilities.TestTampering('CCM', CreateCcmCipher as IAeadCipher,
    LParams as ICipherParameters);
  TAeadTestUtilities.TestOutputSizes('CCM', CreateCcmCipher as IAeadBlockCipher,
    LParams);
  TAeadTestUtilities.TestBufferSizeChecks('CCM',
    CreateCcmCipher as IAeadBlockCipher, LParams);
end;

procedure TTestCcm.DoTestBoundaryLimits;
const
  Offsets: array[0..5] of Int32 = (-10, -2, -1, 0, 1, 10);
  NonceLens: array[0..1] of Int32 = (13, 12);
var
  LI, LJ, LNonceLen, LOffset, LQ, LSize, LLen: Int32;
  LNonce, LInBuf, LOutBuf, LRecovered: TBytes;
  LCcm: ICcmBlockCipher;
begin
  for LI := 0 to High(NonceLens) do
  begin
    LNonceLen := NonceLens[LI];
    for LJ := 0 to High(Offsets) do
    begin
      LOffset := Offsets[LJ];
      try
        LCcm := CreateCcmCipher;
        SetLength(LNonce, LNonceLen);
        LCcm.Init(True, TAeadParameters.Create(
          TKeyParameter.Create(FK1) as IKeyParameter, 128, LNonce, nil)
          as ICipherParameters);

        LQ := 15 - LNonceLen;
        LSize := 1 shl (8 * LQ);
        SetLength(LInBuf, LSize + LOffset);
        SetLength(LOutBuf, LCcm.GetOutputSize(Length(LInBuf)));
        LLen := LCcm.ProcessPacket(LInBuf, 0, Length(LInBuf), LOutBuf, 0);

        if LOffset >= 0 then
          Fail(Format('expected to fail to encrypt boundary bytes n=%d size=%d offset=%d',
            [LNonceLen, LSize, LOffset]));

        LCcm.Init(False, TAeadParameters.Create(
          TKeyParameter.Create(FK1) as IKeyParameter, 128, LNonce, nil)
          as ICipherParameters);
        LRecovered := LCcm.ProcessPacket(LOutBuf, 0, LLen);

        if (Length(LRecovered) <> Length(LInBuf)) or
          (not AreEqual(LInBuf, LRecovered)) then
        begin
          Fail(Format('encryption output incorrect at boundary n=%d offset=%d',
            [LNonceLen, LOffset]));
        end;
      except
        on E: Exception do
        begin
          if LOffset < 0 then
            Fail(Format('unexpected failure to encrypt boundary bytes n=%d offset=%d msg=%s',
              [LNonceLen, LOffset, E.Message]));
        end;
      end;
    end;
  end;
end;

procedure TTestCcm.DoTestNoUnverifiedPlaintextOnFailure;
var
  LCcm: ICcmBlockCipher;
  LTampered, LOutput: TBytes;
  LI: Int32;
begin
  LCcm := CreateCcmCipher;
  LCcm.Init(False, TAeadParameters.Create(TKeyParameter.Create(FK2)
    as IKeyParameter, 48, FN2, FA2) as ICipherParameters);

  SetLength(LTampered, Length(FC2));
  System.Move(FC2[0], LTampered[0], Length(FC2));
  LTampered[High(LTampered)] := LTampered[High(LTampered)] xor $01;

  SetLength(LOutput, LCcm.GetOutputSize(Length(LTampered)));
  for LI := 0 to High(LOutput) do
    LOutput[LI] := $55;

  try
    LCcm.ProcessPacket(LTampered, 0, Length(LTampered), LOutput, 0);
    Fail('tampered CCM ciphertext must not verify');
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      for LI := 0 to High(LOutput) do
      begin
        if LOutput[LI] <> $55 then
          Fail('CCM left unverified plaintext in the output buffer on tag failure');
      end;
    end;
  end;
end;

procedure TTestCcm.TestNoUnverifiedPlaintextOnFailure;
begin
  RunWithAcceleratedToggle(DoTestNoUnverifiedPlaintextOnFailure);
end;

procedure TTestCcm.DoTestInvalidTagLength;
const
  InvalidMacSizeBits: array[0..9] of Int32 = (0, 8, 24, 40, 56, 72, 88, 104, 120, 136);
var
  LCcm: ICcmBlockCipher;
  LI: Int32;
begin
  for LI := 0 to High(InvalidMacSizeBits) do
  begin
    LCcm := CreateCcmCipher;
    try
      LCcm.Init(True,
        TAeadParameters.Create(TKeyParameter.Create(FK1) as IKeyParameter,
        InvalidMacSizeBits[LI], FN1, FA1) as ICipherParameters);
      Fail('invalid tag length not rejected on encryption');
    except
      on E: EArgumentCryptoLibException do
      begin
        // expected
      end;
    end;

    LCcm := CreateCcmCipher;
    try
      LCcm.Init(False,
        TAeadParameters.Create(TKeyParameter.Create(FK1) as IKeyParameter,
        InvalidMacSizeBits[LI], FN1, FA1) as ICipherParameters);
      Fail('invalid tag length not rejected on decryption');
    except
      on E: EArgumentCryptoLibException do
      begin
        // expected
      end;
    end;
  end;
end;

procedure TTestCcm.DoTestValidTagLength;
var
  LCcm: ICcmBlockCipher;
  LPlaintext, LCt, LRecovered: TBytes;
  LMacSizeBits: Int32;
begin
  LPlaintext := DecodeHex('202122232425262728292a2b2c2d2e2f3031323334353637');

  for LMacSizeBits := 32 to 128 do
  begin
    if (LMacSizeBits mod 16) <> 0 then
      Continue;

    LCcm := CreateCcmCipher;
    LCcm.Init(True,
      TAeadParameters.Create(TKeyParameter.Create(FK1) as IKeyParameter,
      LMacSizeBits, FN1, FA1) as ICipherParameters);
    LCt := LCcm.ProcessPacket(LPlaintext, 0, Length(LPlaintext));

    LCcm := CreateCcmCipher;
    LCcm.Init(False,
      TAeadParameters.Create(TKeyParameter.Create(FK1) as IKeyParameter,
      LMacSizeBits, FN1, FA1) as ICipherParameters);
    LRecovered := LCcm.ProcessPacket(LCt, 0, Length(LCt));

    if not AreEqual(LPlaintext, LRecovered) then
      Fail(Format('CCM round-trip failed for tag length %d bits', [LMacSizeBits]));
  end;
end;

procedure TTestCcm.TestInvalidTagLength;
begin
  RunWithAcceleratedToggle(DoTestInvalidTagLength);
end;

procedure TTestCcm.TestValidTagLength;
begin
  RunWithAcceleratedToggle(DoTestValidTagLength);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCcm);
{$ELSE}
  RegisterTest(TTestCcm.Suite);
{$ENDIF FPC}

end.

