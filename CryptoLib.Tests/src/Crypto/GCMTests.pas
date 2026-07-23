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

unit GCMTests;

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
  ClpIBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpGcmBlockCipher,
  ClpIGcmBlockCipher,
  ClpIGcmMultiplier,
  ClpBasicGcmMultiplier,
  ClpTables4kGcmMultiplier,
  ClpTables8kGcmMultiplier,
  ClpTables64kGcmMultiplier,
  ClpAesUtilities,
  ClpBlowfishEngine,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDateTimeUtilities,
  ClpConverters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CipherKernelToggle,
  AeadTestUtilities,
  CryptoLibTestBase,
  SymmetricBlockVectors;

type

  TTestGcm = class(TCryptoLibAlgorithmTestCase)
  private
    function CreateAesEngine: IBlockCipher;
    function InitCipher(const AM: IGcmMultiplier; AForEncryption: Boolean;
      const AParameters: IAeadParameters): IGcmBlockCipher;
    procedure RunTestCase(const ARow: TAeadGcmRow); overload;
    procedure RunTestCase(const ARow: TAeadGcmRow; AMacLength: Int32); overload;
    procedure RunTestCase(const AEncM, ADecM: IGcmMultiplier;
      const ATestName: string; const AK, AIV, AA, AP, AC, AT: TBytes); overload;
    procedure RunTestCase(const AEncM, ADecM: IGcmMultiplier;
      const ATestName: string;
      const AK, AIV, AA, ASA, AP, AC, AT: TBytes); overload;
    procedure CheckTestCase(const AEncCipher, ADecCipher: IGcmBlockCipher;
      const ATestName: string; const ASA, AP, AC, AT: TBytes);
    procedure RandomTests;
    procedure RandomTestsWithMultiplier(const ARandom: ISecureRandom;
      const AM: IGcmMultiplier);
    procedure RandomTest(const ARandom: ISecureRandom;
      const AM: IGcmMultiplier);
    procedure OutputSizeTests;
    procedure DoTestExceptions;
    function NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;

    // Workers run twice via RunWithCipherKernelToggle (cipher kernel on / off).
    procedure DoTestRfcVectors;
    procedure DoTestRandomised;
    procedure DoTestOutputSizes;
    procedure DoTestExceptionsWrapper;
    procedure DoTestFourBlockFusedGcmPath;
    procedure DoTestEightBlockFusedGcmPath;
    procedure DoTestInPlace;
    // In-place (AOutput aliases AInput) round-trip at one length; returns '' on
    // success or a short description of the failing direction.
    function InPlaceCase(const ARandom: ISecureRandom; APlainLen, AKeyLen: Int32;
      const AAad: TBytes): String;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestRfcVectors;
    procedure TestRandomised;
    procedure TestOutputSizes;
    procedure TestExceptions;
    procedure TestFourBlockFusedGcmPath;
    procedure TestEightBlockFusedGcmPath;
    procedure TestInPlace;

  end;

implementation

{ TTestGcm }

procedure TTestGcm.SetUp;
begin
  inherited;
end;

procedure TTestGcm.TearDown;
begin
  inherited;
end;

function TTestGcm.CreateAesEngine: IBlockCipher;
begin
  Result := TAesUtilities.CreateEngine();
end;

function TTestGcm.InitCipher(const AM: IGcmMultiplier;
  AForEncryption: Boolean;
  const AParameters: IAeadParameters): IGcmBlockCipher;
begin
  Result := TGcmBlockCipher.Create(CreateAesEngine(), AM);
  Result.Init(AForEncryption, AParameters as ICipherParameters);
end;

function TTestGcm.NextInt32(const ARandom: ISecureRandom;
  AN: Int32): Int32;
var
  LBits, LValue: Int32;
begin
  if (AN and -AN) = AN then
  begin
    Result := Int32((UInt32(AN) *
      UInt64(UInt32(ARandom.NextInt32()) shr 1)) shr 31);
    Exit;
  end;

  repeat
    LBits := Int32(UInt32(ARandom.NextInt32()) shr 1);
    LValue := LBits mod AN;
  until not ((LBits - LValue + (AN - 1)) < 0);

  Result := LValue;
end;

procedure TTestGcm.RunTestCase(const ARow: TAeadGcmRow);
var
  LMacLength: Int32;
begin
  for LMacLength := 12 to 16 do
    RunTestCase(ARow, LMacLength);
end;

procedure TTestGcm.RunTestCase(const ARow: TAeadGcmRow; AMacLength: Int32);
var
  LTestName: string;
  LK, LP, LA, LIV, LC, LFullTag, LT: TBytes;
begin
  LTestName := ARow.Name;
  LK := DecodeHex(ARow.Key);
  LP := DecodeHex(ARow.Plaintext);
  LA := DecodeHex(ARow.Aad);
  LIV := DecodeHex(ARow.Iv);
  LC := DecodeHex(ARow.Ciphertext);
  LFullTag := DecodeHex(ARow.Tag);

  System.SetLength(LT, AMacLength);
  System.Move(LFullTag[0], LT[0], AMacLength);

  RunTestCase(nil, nil, LTestName, LK, LIV, LA, LP, LC, LT);

  RunTestCase(TBasicGcmMultiplier.Create() as IGcmMultiplier,
    TBasicGcmMultiplier.Create() as IGcmMultiplier, LTestName,
    LK, LIV, LA, LP, LC, LT);
  RunTestCase(TTables4kGcmMultiplier.Create() as IGcmMultiplier,
    TTables4kGcmMultiplier.Create() as IGcmMultiplier, LTestName,
    LK, LIV, LA, LP, LC, LT);
  RunTestCase(TTables8kGcmMultiplier.Create() as IGcmMultiplier,
    TTables8kGcmMultiplier.Create() as IGcmMultiplier, LTestName,
    LK, LIV, LA, LP, LC, LT);
  RunTestCase(TTables64kGcmMultiplier.Create() as IGcmMultiplier,
    TTables64kGcmMultiplier.Create() as IGcmMultiplier, LTestName,
    LK, LIV, LA, LP, LC, LT);
end;

procedure TTestGcm.RunTestCase(const AEncM, ADecM: IGcmMultiplier;
  const ATestName: string; const AK, AIV, AA, AP, AC, AT: TBytes);
var
  LFa, LLa: TBytes;
begin
  //LFa := nil;
  //LLa := nil;
  System.SetLength(LFa, System.Length(AA) div 2);
  System.SetLength(LLa, System.Length(AA) - (System.Length(AA) div 2));
  if System.Length(LFa) > 0 then
    System.Move(AA[0], LFa[0], System.Length(LFa));
  if System.Length(LLa) > 0 then
    System.Move(AA[System.Length(LFa)], LLa[0], System.Length(LLa));

  RunTestCase(AEncM, ADecM, ATestName + ' all initial associated data',
    AK, AIV, AA, nil, AP, AC, AT);
  RunTestCase(AEncM, ADecM, ATestName + ' all subsequent associated data',
    AK, AIV, nil, AA, AP, AC, AT);
  RunTestCase(AEncM, ADecM, ATestName + ' split associated data',
    AK, AIV, LFa, LLa, AP, AC, AT);
end;

procedure TTestGcm.RunTestCase(const AEncM, ADecM: IGcmMultiplier;
  const ATestName: string;
  const AK, AIV, AA, ASA, AP, AC, AT: TBytes);
var
  LParameters: IAeadParameters;
  LEncCipher, LDecCipher: IGcmBlockCipher;
  LKeyReuseParams: IAeadParameters;
begin
  LParameters := TAeadParameters.Create(
    TKeyParameter.Create(AK) as IKeyParameter,
    System.Length(AT) * 8, AIV, AA);

  LEncCipher := InitCipher(AEncM, True, LParameters);
  LDecCipher := InitCipher(ADecM, False, LParameters);
  CheckTestCase(LEncCipher, LDecCipher, ATestName, ASA, AP, AC, AT);

  LEncCipher := InitCipher(AEncM, True, LParameters);
  CheckTestCase(LEncCipher, LDecCipher, ATestName + ' (reused)',
    ASA, AP, AC, AT);

  // Key reuse
  LKeyReuseParams := TAeadTestUtilities.ReuseKey(LParameters);
  try
    LEncCipher.Init(True, LKeyReuseParams as ICipherParameters);
    Fail('no exception');
  except
    on E: EArgumentCryptoLibException do
    begin
      if E.Message <> 'cannot reuse nonce for GCM encryption' then
        Fail('wrong message');
    end;
  end;
end;

procedure TTestGcm.CheckTestCase(
  const AEncCipher, ADecCipher: IGcmBlockCipher;
  const ATestName: string; const ASA, AP, AC, AT: TBytes);
var
  LEnc, LMac, LData, LTail, LDec: TBytes;
  LLen: Int32;
begin
 (* LEnc := nil;
  LMac := nil;
  LData := nil;
  LTail := nil;
  LDec := nil; *)
  System.SetLength(LEnc, AEncCipher.GetOutputSize(System.Length(AP)));
  if ASA <> nil then
  begin
    AEncCipher.ProcessAadBytes(ASA, 0, System.Length(ASA));
  end;
  LLen := AEncCipher.ProcessBytes(AP, 0, System.Length(AP), LEnc, 0);
  LLen := LLen + AEncCipher.DoFinal(LEnc, LLen);

  if System.Length(LEnc) <> LLen then
  begin
    Fail('encryption reported incorrect length: ' + ATestName);
  end;

  LMac := AEncCipher.GetMac;

  System.SetLength(LData, System.Length(AP));
  if System.Length(LData) > 0 then
    System.Move(LEnc[0], LData[0], System.Length(LData));
  System.SetLength(LTail, System.Length(LEnc) - System.Length(AP));
  if System.Length(LTail) > 0 then
    System.Move(LEnc[System.Length(AP)], LTail[0], System.Length(LTail));

  if not AreEqual(AC, LData) then
  begin
    Fail('incorrect encrypt in: ' + ATestName);
  end;

  if not AreEqual(AT, LMac) then
  begin
    Fail('GetMac() returned wrong mac in: ' + ATestName);
  end;

  if not AreEqual(AT, LTail) then
  begin
    Fail('stream contained wrong mac in: ' + ATestName);
  end;

  System.SetLength(LDec, ADecCipher.GetOutputSize(System.Length(LEnc)));
  if ASA <> nil then
  begin
    ADecCipher.ProcessAadBytes(ASA, 0, System.Length(ASA));
  end;
  LLen := ADecCipher.ProcessBytes(LEnc, 0, System.Length(LEnc), LDec, 0);
  ADecCipher.DoFinal(LDec, LLen);
  LMac := ADecCipher.GetMac;

  System.SetLength(LData, System.Length(AC));
  if System.Length(LData) > 0 then
    System.Move(LDec[0], LData[0], System.Length(LData));

  if not AreEqual(AP, LData) then
  begin
    Fail('incorrect decrypt in: ' + ATestName);
  end;
end;

procedure TTestGcm.RandomTests;
var
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create();
  LRandom.SetSeed(TDateTimeUtilities.CurrentUnixMs);
  RandomTestsWithMultiplier(LRandom, nil);
  RandomTestsWithMultiplier(LRandom,
    TBasicGcmMultiplier.Create() as IGcmMultiplier);
  RandomTestsWithMultiplier(LRandom,
    TTables4kGcmMultiplier.Create() as IGcmMultiplier);
  RandomTestsWithMultiplier(LRandom,
    TTables8kGcmMultiplier.Create() as IGcmMultiplier);
  RandomTestsWithMultiplier(LRandom,
    TTables64kGcmMultiplier.Create() as IGcmMultiplier);
end;

procedure TTestGcm.RandomTestsWithMultiplier(const ARandom: ISecureRandom;
  const AM: IGcmMultiplier);
var
  LI: Int32;
begin
  for LI := 0 to 99 do
  begin
    RandomTest(ARandom, AM);
  end;
end;

procedure TTestGcm.RandomTest(const ARandom: ISecureRandom;
  const AM: IGcmMultiplier);
var
  LKLength, LPLength, LALength, LSALength, LIVLength: Int32;
  LK, LP, LA, LSA, LIV, LC, LDecP, LEncT, LDecT, LTail: TBytes;
  LParameters: IAeadParameters;
  LCipher: IGcmBlockCipher;
  LPredicted, LLen, LSplit: Int32;
  LKeyReuseParams: IAeadParameters;
begin
  LKLength := 16 + 8 * ARandom.Next(3);
  System.SetLength(LK, LKLength);
  ARandom.NextBytes(LK);

  LPLength := ARandom.Next(65536);
  System.SetLength(LP, LPLength);
  ARandom.NextBytes(LP);

  LALength := ARandom.Next(256);
  System.SetLength(LA, LALength);
  ARandom.NextBytes(LA);

  LSALength := ARandom.Next(256);
  System.SetLength(LSA, LSALength);
  ARandom.NextBytes(LSA);

  LIVLength := 1 + ARandom.Next(256);
  System.SetLength(LIV, LIVLength);
  ARandom.NextBytes(LIV);

  LParameters := TAeadParameters.Create(
    TKeyParameter.Create(LK) as IKeyParameter, 16 * 8, LIV, LA);
  LCipher := InitCipher(AM, True, LParameters);
  System.SetLength(LC, LCipher.GetOutputSize(System.Length(LP)));
  LPredicted := LCipher.GetUpdateOutputSize(System.Length(LP));

  LSplit := ARandom.Next(System.Length(LSA) + 1);
  LCipher.ProcessAadBytes(LSA, 0, LSplit);
  LLen := LCipher.ProcessBytes(LP, 0, System.Length(LP), LC, 0);
  LCipher.ProcessAadBytes(LSA, LSplit, System.Length(LSA) - LSplit);

  if LPredicted <> LLen then
  begin
    Fail('encryption reported incorrect update length in randomised test');
  end;

  LLen := LLen + LCipher.DoFinal(LC, LLen);

  if System.Length(LC) <> LLen then
  begin
    Fail('encryption reported incorrect length in randomised test');
  end;

  LEncT := LCipher.GetMac;
  System.SetLength(LTail, System.Length(LC) - System.Length(LP));
  System.Move(LC[System.Length(LP)], LTail[0], System.Length(LTail));

  if not AreEqual(LEncT, LTail) then
  begin
    Fail('stream contained wrong mac in randomised test');
  end;

  LCipher.Init(False, LParameters as ICipherParameters);
  System.SetLength(LDecP, LCipher.GetOutputSize(System.Length(LC)));
  LPredicted := LCipher.GetUpdateOutputSize(System.Length(LC));

  LSplit := ARandom.Next(System.Length(LSA) + 1);
  LCipher.ProcessAadBytes(LSA, 0, LSplit);
  LLen := LCipher.ProcessBytes(LC, 0, System.Length(LC), LDecP, 0);
  LCipher.ProcessAadBytes(LSA, LSplit, System.Length(LSA) - LSplit);

  if LPredicted <> LLen then
  begin
    Fail('decryption reported incorrect update length in randomised test');
  end;

  LCipher.DoFinal(LDecP, LLen);

  if not AreEqual(LP, LDecP) then
  begin
    Fail('incorrect decrypt in randomised test');
  end;

  LDecT := LCipher.GetMac;
  if not AreEqual(LEncT, LDecT) then
  begin
    Fail('decryption produced different mac from encryption');
  end;

  // Key reuse test
  LKeyReuseParams := TAeadTestUtilities.ReuseKey(LParameters);
  LCipher.Init(False, LKeyReuseParams as ICipherParameters);
  System.SetLength(LDecP, LCipher.GetOutputSize(System.Length(LC)));

  LSplit := NextInt32(ARandom, System.Length(LSA) + 1);
  LCipher.ProcessAadBytes(LSA, 0, LSplit);
  LLen := LCipher.ProcessBytes(LC, 0, System.Length(LC), LDecP, 0);
  LCipher.ProcessAadBytes(LSA, LSplit, System.Length(LSA) - LSplit);

  LCipher.DoFinal(LDecP, LLen);

  if not AreEqual(LP, LDecP) then
  begin
    Fail('incorrect decrypt in randomised test');
  end;

  LDecT := LCipher.GetMac;
  if not AreEqual(LEncT, LDecT) then
  begin
    Fail('decryption produced different mac from encryption');
  end;
end;

procedure TTestGcm.OutputSizeTests;
var
  LK, LIV: TBytes;
  LParameters: IAeadParameters;
  LCipher: IGcmBlockCipher;
begin
  System.SetLength(LK, 16);
  System.SetLength(LIV, 16);

  LParameters := TAeadParameters.Create(
    TKeyParameter.Create(LK) as IKeyParameter, 16 * 8, LIV, nil);
  LCipher := InitCipher(nil, True, LParameters);

  if LCipher.GetUpdateOutputSize(0) <> 0 then
  begin
    Fail('incorrect getUpdateOutputSize for initial 0 bytes encryption');
  end;

  if LCipher.GetOutputSize(0) <> 16 then
  begin
    Fail('incorrect getOutputSize for initial 0 bytes encryption');
  end;

  LCipher.Init(False, LParameters as ICipherParameters);

  if LCipher.GetUpdateOutputSize(0) <> 0 then
  begin
    Fail('incorrect getUpdateOutputSize for initial 0 bytes decryption');
  end;

  if LCipher.GetOutputSize(0) <> 0 then
  begin
    Fail('fragile getOutputSize for initial 0 bytes decryption');
  end;

  if LCipher.GetOutputSize(16) <> 0 then
  begin
    Fail('incorrect getOutputSize for initial MAC-size bytes decryption');
  end;
end;

procedure TTestGcm.DoTestExceptions;
var
  LGcm: IGcmBlockCipher;
  LP, LBuf: TBytes;
  LC: IGcmBlockCipher;
  LAeadParams: IAeadParameters;
begin
  LGcm := TGcmBlockCipher.Create(CreateAesEngine());

  // Incorrect block size
  try
    LGcm := TGcmBlockCipher.Create(TBlowfishEngine.Create() as IBlockCipher);
    Fail('incorrect block size not picked up');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  // bare KeyParameter without AeadParameters
  try
    LGcm.Init(False,
      TKeyParameter.Create(TBytes.Create(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
      as ICipherParameters);
    Fail('illegal argument not picked up');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  TAeadTestUtilities.TestTampering('GCM', LGcm as IAeadCipher,
    TAeadParameters.Create(
      TKeyParameter.Create(TBytes.Create(
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
      as IKeyParameter, 128,
      TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    as ICipherParameters);

  LP := TConverters.ConvertStringToBytes('Hello world!', TEncoding.ANSI);
  System.SetLength(LBuf, 100);

  LC := TGcmBlockCipher.Create(CreateAesEngine());
  LAeadParams := TAeadParameters.Create(
    TKeyParameter.Create(TBytes.Create(
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))
    as IKeyParameter, 128,
    TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
  LC.Init(True, LAeadParams as ICipherParameters);

  LC.ProcessBytes(LP, 0, System.Length(LP), LBuf, 0);
  LC.DoFinal(LBuf, 0);

  try
    LC.DoFinal(LBuf, 0);
    Fail('no exception on reuse');
  except
    on E: EInvalidOperationCryptoLibException do
    begin
      if E.Message <> 'GCM cipher cannot be reused for encryption' then
        Fail('wrong message');
    end;
  end;

  try
    LC.Init(True, LAeadParams as ICipherParameters);
    Fail('no exception on reuse');
  except
    on E: EArgumentCryptoLibException do
    begin
      if E.Message <> 'cannot reuse nonce for GCM encryption' then
        Fail('wrong message');
    end;
  end;
end;

procedure TTestGcm.TestRfcVectors;
begin
  RunWithCipherKernelToggle(DoTestRfcVectors);
end;

procedure TTestGcm.TestRandomised;
begin
  RunWithCipherKernelToggle(DoTestRandomised);
end;

procedure TTestGcm.TestOutputSizes;
begin
  RunWithCipherKernelToggle(DoTestOutputSizes);
end;

procedure TTestGcm.TestExceptions;
begin
  RunWithCipherKernelToggle(DoTestExceptionsWrapper);
end;

procedure TTestGcm.TestFourBlockFusedGcmPath;
begin
  RunWithCipherKernelToggle(DoTestFourBlockFusedGcmPath);
end;

procedure TTestGcm.TestEightBlockFusedGcmPath;
begin
  RunWithCipherKernelToggle(DoTestEightBlockFusedGcmPath);
end;

procedure TTestGcm.DoTestRfcVectors;
var
  LRows: TCryptoLibGenericArray<TAeadGcmRow>;
  LI: Int32;
begin
  LRows := TGcmVectors.GetMcGrewViegaRows;
  for LI := 0 to High(LRows) do
    RunTestCase(LRows[LI]);
end;

procedure TTestGcm.DoTestRandomised;
begin
  RandomTests;
end;

procedure TTestGcm.DoTestOutputSizes;
begin
  OutputSizeTests;
end;

procedure TTestGcm.DoTestExceptionsWrapper;
begin
  DoTestExceptions;
end;

procedure TTestGcm.DoTestFourBlockFusedGcmPath;
var
  LRnd: ISecureRandom;
  LI, LJ, LKeyLen, LPLen, LLen, LDecLen: Int32;
  LK, LIV, LP, LEnc, LDec: TBytes;
  LParams: IAeadParameters;
  LEncCipher, LDecCipher: IGcmBlockCipher;
begin
  if not TGcmBlockCipher.IsFourWaySupported then
    Exit;

  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(TDateTimeUtilities.CurrentUnixMs);

  for LI := 0 to 39 do
  begin
    LKeyLen := 16 + 8 * NextInt32(LRnd, 3);
    System.SetLength(LK, LKeyLen);
    LRnd.NextBytes(LK);
    System.SetLength(LIV, 12);
    LRnd.NextBytes(LIV);
    LPLen := 64 + NextInt32(LRnd, 16) * 64;
    System.SetLength(LP, LPLen);
    LRnd.NextBytes(LP);

    LParams := TAeadParameters.Create(
      TKeyParameter.Create(LK) as IKeyParameter, 16 * 8, LIV, nil);

    LEncCipher := TGcmBlockCipher.Create(CreateAesEngine(),
      TBasicGcmMultiplier.Create() as IGcmMultiplier);
    LEncCipher.Init(True, LParams as ICipherParameters);
    System.SetLength(LEnc, LEncCipher.GetOutputSize(LPLen));
    LLen := LEncCipher.ProcessBytes(LP, 0, LPLen, LEnc, 0);
    LLen := LLen + LEncCipher.DoFinal(LEnc, LLen);

    LDecCipher := TGcmBlockCipher.Create(CreateAesEngine(),
      TBasicGcmMultiplier.Create() as IGcmMultiplier);
    LDecCipher.Init(False, LParams as ICipherParameters);
    System.SetLength(LDec, LDecCipher.GetOutputSize(LLen));
    LDecLen := LDecCipher.ProcessBytes(LEnc, 0, LLen, LDec, 0);
    LDecLen := LDecLen + LDecCipher.DoFinal(LDec, LDecLen);

    if LDecLen <> LPLen then
      Fail('four-block GCM decrypt length mismatch');
    for LJ := 0 to LPLen - 1 do
      if LP[LJ] <> LDec[LJ] then
        Fail('four-block GCM round-trip mismatch');
  end;
end;

procedure TTestGcm.DoTestEightBlockFusedGcmPath;
var
  LRnd: ISecureRandom;
  LI, LJ, LKeyLen, LPLen, LLen, LDecLen: Int32;
  LK, LIV, LP, LEnc, LDec: TBytes;
  LParams: IAeadParameters;
  LEncCipher, LDecCipher: IGcmBlockCipher;
begin
  if not TGcmBlockCipher.IsEightWaySupported then
    Exit;

  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(TDateTimeUtilities.CurrentUnixMs);

  for LI := 0 to 39 do
  begin
    LKeyLen := 16 + 8 * NextInt32(LRnd, 3);
    System.SetLength(LK, LKeyLen);
    LRnd.NextBytes(LK);
    System.SetLength(LIV, 12);
    LRnd.NextBytes(LIV);
    LPLen := 128 + NextInt32(LRnd, 8) * 128;
    System.SetLength(LP, LPLen);
    LRnd.NextBytes(LP);

    LParams := TAeadParameters.Create(
      TKeyParameter.Create(LK) as IKeyParameter, 16 * 8, LIV, nil);

    LEncCipher := TGcmBlockCipher.Create(CreateAesEngine(),
      TBasicGcmMultiplier.Create() as IGcmMultiplier);
    LEncCipher.Init(True, LParams as ICipherParameters);
    System.SetLength(LEnc, LEncCipher.GetOutputSize(LPLen));
    LLen := LEncCipher.ProcessBytes(LP, 0, LPLen, LEnc, 0);
    LLen := LLen + LEncCipher.DoFinal(LEnc, LLen);

    LDecCipher := TGcmBlockCipher.Create(CreateAesEngine(),
      TBasicGcmMultiplier.Create() as IGcmMultiplier);
    LDecCipher.Init(False, LParams as ICipherParameters);
    System.SetLength(LDec, LDecCipher.GetOutputSize(LLen));
    LDecLen := LDecCipher.ProcessBytes(LEnc, 0, LLen, LDec, 0);
    LDecLen := LDecLen + LDecCipher.DoFinal(LDec, LDecLen);

    if LDecLen <> LPLen then
      Fail('eight-block GCM decrypt length mismatch');
    for LJ := 0 to LPLen - 1 do
      if LP[LJ] <> LDec[LJ] then
        Fail('eight-block GCM round-trip mismatch');
  end;
end;

function TTestGcm.InPlaceCase(const ARandom: ISecureRandom;
  APlainLen, AKeyLen: Int32; const AAad: TBytes): String;
var
  LK, LIV, LP, LRef, LBuf: TBytes;
  LParams: IAeadParameters;
  LCipher: IGcmBlockCipher;
  LLen, LTotal: Int32;
begin
  Result := '';
  System.SetLength(LK, AKeyLen);
  ARandom.NextBytes(LK);
  System.SetLength(LIV, 12);
  ARandom.NextBytes(LIV);
  System.SetLength(LP, APlainLen);
  if APlainLen > 0 then
    ARandom.NextBytes(LP);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LIV, AAad);

  // Reference ciphertext||tag, produced out of place.
  LCipher := TGcmBlockCipher.Create(CreateAesEngine(),
    TBasicGcmMultiplier.Create() as IGcmMultiplier);
  LCipher.Init(True, LParams as ICipherParameters);
  System.SetLength(LRef, LCipher.GetOutputSize(APlainLen));
  LLen := LCipher.ProcessBytes(LP, 0, APlainLen, LRef, 0);
  LLen := LLen + LCipher.DoFinal(LRef, LLen);
  System.SetLength(LRef, LLen);
  LTotal := LLen;

  // In-place encrypt: the buffer starts as plaintext and is encrypted over itself.
  System.SetLength(LBuf, LTotal);
  if APlainLen > 0 then
    System.Move(LP[0], LBuf[0], APlainLen);
  LCipher := TGcmBlockCipher.Create(CreateAesEngine(),
    TBasicGcmMultiplier.Create() as IGcmMultiplier);
  LCipher.Init(True, LParams as ICipherParameters);
  try
    LLen := LCipher.ProcessBytes(LBuf, 0, APlainLen, LBuf, 0);
    LLen := LLen + LCipher.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[enc len=%d exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if (LLen <> LTotal) or (not AreEqual(LBuf, LRef)) then
  begin
    Result := Format('[enc len=%d mismatch] ', [APlainLen]);
    Exit;
  end;

  // In-place decrypt: the buffer starts as ciphertext||tag, decrypted over itself.
  System.SetLength(LBuf, LTotal);
  System.Move(LRef[0], LBuf[0], LTotal);
  LCipher := TGcmBlockCipher.Create(CreateAesEngine(),
    TBasicGcmMultiplier.Create() as IGcmMultiplier);
  LCipher.Init(False, LParams as ICipherParameters);
  try
    LLen := LCipher.ProcessBytes(LBuf, 0, LTotal, LBuf, 0);
    LLen := LLen + LCipher.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[dec len=%d exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if LLen <> APlainLen then
  begin
    Result := Format('[dec len=%d got %d] ', [APlainLen, LLen]);
    Exit;
  end;
  System.SetLength(LBuf, LLen);
  if (APlainLen > 0) and (not AreEqual(LBuf, LP)) then
    Result := Format('[dec len=%d mismatch] ', [APlainLen]);
end;

procedure TTestGcm.DoTestInPlace;
const
  CLens: array [0 .. 10] of Int32 = (0, 16, 48, 64, 4 * 16 + 7, 17 * 16 + 9,
    22 * 16, 24 * 16, 33 * 16, 65 * 16, 100 * 16 + 3);
var
  LRnd: ISecureRandom;
  LFails: String;
  LI: Int32;
  LAad: TBytes;
begin
  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(TDateTimeUtilities.CurrentUnixMs);
  System.SetLength(LAad, 20);
  LRnd.NextBytes(LAad);
  LFails := '';
  for LI := 0 to High(CLens) do
    LFails := LFails + InPlaceCase(LRnd, CLens[LI], 16, nil);
  for LI := 0 to High(CLens) do
    LFails := LFails + InPlaceCase(LRnd, CLens[LI], 32, LAad);
  if LFails <> '' then
    Fail('in-place GCM: ' + LFails);
end;

procedure TTestGcm.TestInPlace;
begin
  RunWithCipherKernelToggle(DoTestInPlace);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGcm);
{$ELSE}
  RegisterTest(TTestGcm.Suite);
{$ENDIF FPC}

end.
