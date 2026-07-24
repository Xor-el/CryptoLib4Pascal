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

unit GcmSivTests;

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
  ClpGcmSivBlockCipher,
  ClpIGcmSivBlockCipher,
  ClpAeadParameters,
  ClpIAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpConverters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpIAeadCipher,
  AeadModeTestBase,
  CipherKernelToggle,
  CryptoLibTestBase,
  SymmetricBlockVectors;

type

  TTestGcmSiv = class(TAeadModeTestBase)
  private
    procedure TestSivCipher(const AKey, ANonce, AAEAD, AData,
      AExpected: string);

    function NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;
    procedure RandomisedRoundTrip(const ARandom: ISecureRandom);

  protected
    function CreateAeadCipher: IAeadCipher; override;
    function ModeLabel: String; override;

    procedure SetUp; override;
    procedure TearDown; override;

    procedure DoTestSet(const ASetId: string);
    procedure DoTestAesGcmSiv128Set1;
    procedure DoTestAesGcmSiv128Set2;
    procedure DoTestAesGcmSiv128Set3;
    procedure DoTestAesGcmSiv256Set1;
    procedure DoTestAesGcmSiv256Set2;
    procedure DoTestAesGcmSiv256Set3;
    procedure DoTestAesGcmSiv256Set4;
    procedure DoTestRandomised;

  published
    procedure TestAesGcmSiv128Set1;
    procedure TestAesGcmSiv128Set2;
    procedure TestAesGcmSiv128Set3;
    procedure TestAesGcmSiv256Set1;
    procedure TestAesGcmSiv256Set2;
    procedure TestAesGcmSiv256Set3;
    procedure TestAesGcmSiv256Set4;
    procedure TestRandomised;

  end;

implementation

{ TTestGcmSiv }

function TTestGcmSiv.CreateAeadCipher: IAeadCipher;
begin
  Result := TGcmSivBlockCipher.Create(CurrentEngine) as IAeadCipher;
end;

function TTestGcmSiv.ModeLabel: String;
begin
  Result := 'GCM-SIV';
end;

procedure TTestGcmSiv.SetUp;
begin
  inherited;
end;

procedure TTestGcmSiv.TearDown;
begin
  inherited;
end;

procedure TTestGcmSiv.TestSivCipher(const AKey, ANonce, AAEAD, AData,
  AExpected: string);
var
  LCipher: IGcmSivBlockCipher;
  LKey: IKeyParameter;
  LNonce, LAead, LData, LOutput, LFinal, LExpected: TBytes;
  LParams: IAeadParameters;
  LI: Int32;
begin
  try
    LKey := TKeyParameter.Create(DecodeHex(AKey)) as IKeyParameter;
    LNonce := DecodeHex(ANonce);
    LAead := DecodeHex(AAEAD);
    LData := DecodeHex(AData);

    LParams := TAeadParameters.Create(LKey, 128, LNonce, LAead);

    LCipher := TGcmSivBlockCipher.Create(CurrentEngine) as IGcmSivBlockCipher;
    LCipher.Init(True, LParams as ICipherParameters);

    System.SetLength(LOutput, LCipher.GetOutputSize(System.Length(LData)));
    System.SetLength(LFinal, System.Length(LData));

    LCipher.ProcessBytes(LData, 0, System.Length(LData), nil, 0);
    LCipher.DoFinal(LOutput, 0);

    LExpected := DecodeHex(AExpected);
    if not AreEqual(LExpected, LOutput) then
    begin
      Fail('Encryption mismatch');
    end;

    // Repeat processing byte at a time
    for LI := 0 to System.Length(LData) - 1 do
    begin
      LCipher.ProcessByte(LData[LI], nil, 0);
    end;
    LCipher.DoFinal(LOutput, 0);
    if not AreEqual(LExpected, LOutput) then
    begin
      Fail('Encryption mismatch (byte-at-a-time)');
    end;

    if System.Length(LData) >= 2 then
    begin
      // Repeat processing checking processBytes with non-empty internal buffer
      LCipher.ProcessByte(LData[0], nil, 0);
      LCipher.ProcessBytes(LData, 1, System.Length(LData) - 1, nil, 0);
      LCipher.DoFinal(LOutput, 0);
      if not AreEqual(LExpected, LOutput) then
      begin
        Fail('Encryption mismatch (mixed processing)');
      end;
    end;

    // Decryption
    LCipher.Init(False, LParams as ICipherParameters);
    LCipher.ProcessBytes(LOutput, 0, System.Length(LOutput), nil, 0);
    LCipher.DoFinal(LFinal, 0);
    if not AreEqual(LData, LFinal) then
    begin
      Fail('Decryption mismatch');
    end;
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      Fail('Bad Text: ' + E.Message);
    end;
  end;
end;

procedure TTestGcmSiv.DoTestSet(const ASetId: string);
var
  LRows: TCryptoLibGenericArray<TGcmSivRow>;
  LI: Integer;
begin
  LRows := TGcmSivVectors.GetRows(ASetId);
  for LI := 0 to High(LRows) do
  begin
    TestSivCipher(LRows[LI].Key, LRows[LI].Nonce, LRows[LI].Aad,
      LRows[LI].Plaintext, LRows[LI].CiphertextTag);
  end;
end;

procedure TTestGcmSiv.DoTestAesGcmSiv128Set1;
begin
  DoTestSet('AesGcmSiv128Set1');
end;

procedure TTestGcmSiv.DoTestAesGcmSiv128Set2;
begin
  DoTestSet('AesGcmSiv128Set2');
end;

procedure TTestGcmSiv.DoTestAesGcmSiv128Set3;
begin
  DoTestSet('AesGcmSiv128Set3');
end;

procedure TTestGcmSiv.DoTestAesGcmSiv256Set1;
begin
  DoTestSet('AesGcmSiv256Set1');
end;

procedure TTestGcmSiv.DoTestAesGcmSiv256Set2;
begin
  DoTestSet('AesGcmSiv256Set2');
end;

procedure TTestGcmSiv.DoTestAesGcmSiv256Set3;
begin
  DoTestSet('AesGcmSiv256Set3');
end;

procedure TTestGcmSiv.DoTestAesGcmSiv256Set4;
begin
  DoTestSet('AesGcmSiv256Set4');
end;

function TTestGcmSiv.NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;
begin
  if AN <= 0 then
  begin
    Result := 0;
    Exit;
  end;
  Result := Int32(UInt32(ARandom.NextInt32) and $7FFFFFFF) mod AN;
end;

procedure TTestGcmSiv.RandomisedRoundTrip(const ARandom: ISecureRandom);
var
  LKey, LNonce, LAad, LPlain, LEnc, LDec, LTmp: TBytes;
  LKeyBits, LKeyBytes, LAadLen, LPlainLen, LIdx, LLen: Int32;
  LCipher: IGcmSivBlockCipher;
  LParams: IAeadParameters;
begin
  // Sweep key sizes and plaintext lengths covering both the fused
  // POLYVAL kernel (>=128 bytes) and the 16-byte scalar tail fold.
  for LIdx := 0 to 31 do
  begin
    if (LIdx and 1) = 0 then
      LKeyBits := 128
    else
      LKeyBits := 256;
    LKeyBytes := LKeyBits div 8;
    SetLength(LKey, LKeyBytes);
    ARandom.NextBytes(LKey);

    SetLength(LNonce, 12);
    ARandom.NextBytes(LNonce);

    LAadLen := NextInt32(ARandom, 4097);
    SetLength(LAad, LAadLen);
    if LAadLen > 0 then
      ARandom.NextBytes(LAad);

    LPlainLen := NextInt32(ARandom, 4097);
    SetLength(LPlain, LPlainLen);
    if LPlainLen > 0 then
      ARandom.NextBytes(LPlain);

    LParams := TAeadParameters.Create(TKeyParameter.Create(LKey)
      as IKeyParameter, 128, LNonce, LAad);

    LCipher := TGcmSivBlockCipher.Create(CurrentEngine) as IGcmSivBlockCipher;
    LCipher.Init(True, LParams as ICipherParameters);
    SetLength(LEnc, LCipher.GetOutputSize(LPlainLen));
    LLen := LCipher.ProcessBytes(LPlain, 0, LPlainLen, nil, 0);
    LLen := LLen + LCipher.DoFinal(LEnc, 0);
    if LLen <> Length(LEnc) then
      Fail(Format('encrypt output length mismatch at iter %d (got %d, want %d)',
        [LIdx, LLen, Length(LEnc)]));

    LCipher.Init(False, LParams as ICipherParameters);
    SetLength(LTmp, LCipher.GetOutputSize(Length(LEnc)));
    LLen := LCipher.ProcessBytes(LEnc, 0, Length(LEnc), nil, 0);
    LLen := LLen + LCipher.DoFinal(LTmp, 0);
    SetLength(LDec, LLen);
    if LLen > 0 then
      System.Move(LTmp[0], LDec[0], LLen);

    if not AreEqual(LPlain, LDec) then
      Fail(Format('round-trip plaintext mismatch at iter %d ' +
        '(keybits=%d aad=%d plain=%d)',
        [LIdx, LKeyBits, LAadLen, LPlainLen]));
  end;
end;

procedure TTestGcmSiv.DoTestRandomised;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.GetInstance('SHA256PRNG');
  LRandom.SetSeed(TConverters.ConvertStringToBytes('GcmSivDualModeRandomSeed-v1',
    TEncoding.ASCII));
  RandomisedRoundTrip(LRandom);
end;

procedure TTestGcmSiv.TestAesGcmSiv128Set1;
begin
  RunWithCipherKernelToggle(DoTestAesGcmSiv128Set1);
  // Pin the KAT set on the bit-sliced (and scalar) engines too.
  ForEachExtraEngine(DoTestAesGcmSiv128Set1);
end;

procedure TTestGcmSiv.TestAesGcmSiv128Set2;
begin
  RunWithCipherKernelToggle(DoTestAesGcmSiv128Set2);
  ForEachExtraEngine(DoTestAesGcmSiv128Set2);
end;

procedure TTestGcmSiv.TestAesGcmSiv128Set3;
begin
  RunWithCipherKernelToggle(DoTestAesGcmSiv128Set3);
  ForEachExtraEngine(DoTestAesGcmSiv128Set3);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set1;
begin
  RunWithCipherKernelToggle(DoTestAesGcmSiv256Set1);
  ForEachExtraEngine(DoTestAesGcmSiv256Set1);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set2;
begin
  RunWithCipherKernelToggle(DoTestAesGcmSiv256Set2);
  ForEachExtraEngine(DoTestAesGcmSiv256Set2);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set3;
begin
  RunWithCipherKernelToggle(DoTestAesGcmSiv256Set3);
  ForEachExtraEngine(DoTestAesGcmSiv256Set3);
end;

procedure TTestGcmSiv.TestAesGcmSiv256Set4;
begin
  RunWithCipherKernelToggle(DoTestAesGcmSiv256Set4);
  ForEachExtraEngine(DoTestAesGcmSiv256Set4);
end;

procedure TTestGcmSiv.TestRandomised;
begin
  RunWithCipherKernelToggle(DoTestRandomised);
  // Also exercise the round-trip over the bit-sliced (and scalar) engines.
  ForEachExtraEngine(DoTestRandomised);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGcmSiv);
{$ELSE}
  RegisterTest(TTestGcmSiv.Suite);
{$ENDIF FPC}

end.
