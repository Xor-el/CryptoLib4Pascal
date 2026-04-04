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
  ClpAesEngine,
  ClpBlowfishEngine,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDateTimeUtilities,
  ClpConverters,
  ClpCryptoLibTypes,
  AeadTestUtilities,
  CryptoLibTestBase;

type

  TTestGcm = class(TCryptoLibAlgorithmTestCase)
  strict private
    class var
      FTestVectors: TCryptoLibGenericArray<TCryptoLibStringArray>;

    class constructor CreateTestGcm;

  private
    function CreateAesEngine: IBlockCipher;
    function InitCipher(const AM: IGcmMultiplier; AForEncryption: Boolean;
      const AParameters: IAeadParameters): IGcmBlockCipher;
    procedure RunTestCase(const ATestVector: TCryptoLibStringArray); overload;
    procedure RunTestCase(const ATestVector: TCryptoLibStringArray;
      AMacLength: Int32); overload;
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

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestRfcVectors;
    procedure TestRandomised;
    procedure TestOutputSizes;
    procedure TestExceptions;

  end;

implementation

{ TTestGcm }

class constructor TTestGcm.CreateTestGcm;
begin
  // Test vectors from McGrew/Viega Appendix B
  // Format: [name, key, plaintext, aad, iv, ciphertext, tag]
  FTestVectors := TCryptoLibGenericArray<TCryptoLibStringArray>.Create(
    TCryptoLibStringArray.Create(
    'Test Case 1',
    '00000000000000000000000000000000',
    '', '',
    '000000000000000000000000',
    '',
    '58e2fccefa7e3061367f1d57a4e7455a'),
    TCryptoLibStringArray.Create(
    'Test Case 2',
    '00000000000000000000000000000000',
    '00000000000000000000000000000000',
    '',
    '000000000000000000000000',
    '0388dace60b6a392f328c2b971b2fe78',
    'ab6e47d42cec13bdf53a67b21257bddf'),
    TCryptoLibStringArray.Create(
    'Test Case 3',
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b391aafd255',
    '',
    'cafebabefacedbaddecaf888',
    '42831ec2217774244b7221b784d0d49c' +
    'e3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa05' +
    '1ba30b396a0aac973d58e091473f5985',
    '4d5c2af327cd64a62cf35abd2ba6fab4'),
    TCryptoLibStringArray.Create(
    'Test Case 4',
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    'cafebabefacedbaddecaf888',
    '42831ec2217774244b7221b784d0d49c' +
    'e3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa05' +
    '1ba30b396a0aac973d58e091',
    '5bc94fbc3221a5db94fae95ae7121a47'),
    TCryptoLibStringArray.Create(
    'Test Case 5',
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    'cafebabefacedbad',
    '61353b4c2806934a777ff51fa22a4755' +
    '699b2a714fcdc6f83766e5f97b6c7423' +
    '73806900e49f24b22b097544d4896b42' +
    '4989b5e1ebac0f07c23f4598',
    '3612d2e79e3b0785561be14aaca2fccb'),
    TCryptoLibStringArray.Create(
    'Test Case 6',
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    '9313225df88406e555909c5aff5269aa' +
    '6a7a9538534f7da1e4c303d2a318a728' +
    'c3c0c95156809539fcf0e2429a6b5254' +
    '16aedbf5a0de6a57a637b39b',
    '8ce24998625615b603a033aca13fb894' +
    'be9112a5c3a211a8ba262a3cca7e2ca7' +
    '01e4a9a4fba43c90ccdcb281d48c7c6f' +
    'd62875d2aca417034c34aee5',
    '619cc5aefffe0bfa462af43c1699d050'),
    TCryptoLibStringArray.Create(
    'Test Case 7',
    '00000000000000000000000000000000' + '0000000000000000',
    '', '',
    '000000000000000000000000',
    '',
    'cd33b28ac773f74ba00ed1f312572435'),
    TCryptoLibStringArray.Create(
    'Test Case 8',
    '00000000000000000000000000000000' + '0000000000000000',
    '00000000000000000000000000000000',
    '',
    '000000000000000000000000',
    '98e7247c07f0fe411c267e4384b0f600',
    '2ff58d80033927ab8ef4d4587514f0fb'),
    TCryptoLibStringArray.Create(
    'Test Case 9',
    'feffe9928665731c6d6a8f9467308308' + 'feffe9928665731c',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b391aafd255',
    '',
    'cafebabefacedbaddecaf888',
    '3980ca0b3c00e841eb06fac4872a2757' +
    '859e1ceaa6efd984628593b40ca1e19c' +
    '7d773d00c144c525ac619d18c84a3f47' +
    '18e2448b2fe324d9ccda2710acade256',
    '9924a7c8587336bfb118024db8674a14'),
    TCryptoLibStringArray.Create(
    'Test Case 10',
    'feffe9928665731c6d6a8f9467308308' + 'feffe9928665731c',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    'cafebabefacedbaddecaf888',
    '3980ca0b3c00e841eb06fac4872a2757' +
    '859e1ceaa6efd984628593b40ca1e19c' +
    '7d773d00c144c525ac619d18c84a3f47' +
    '18e2448b2fe324d9ccda2710',
    '2519498e80f1478f37ba55bd6d27618c'),
    TCryptoLibStringArray.Create(
    'Test Case 11',
    'feffe9928665731c6d6a8f9467308308' + 'feffe9928665731c',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    'cafebabefacedbad',
    '0f10f599ae14a154ed24b36e25324db8' +
    'c566632ef2bbb34f8347280fc4507057' +
    'fddc29df9a471f75c66541d4d4dad1c9' +
    'e93a19a58e8b473fa0f062f7',
    '65dcc57fcf623a24094fcca40d3533f8'),
    TCryptoLibStringArray.Create(
    'Test Case 12',
    'feffe9928665731c6d6a8f9467308308' + 'feffe9928665731c',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    '9313225df88406e555909c5aff5269aa' +
    '6a7a9538534f7da1e4c303d2a318a728' +
    'c3c0c95156809539fcf0e2429a6b5254' +
    '16aedbf5a0de6a57a637b39b',
    'd27e88681ce3243c4830165a8fdcf9ff' +
    '1de9a1d8e6b447ef6ef7b79828666e45' +
    '81e79012af34ddd9e2f037589b292db3' +
    'e67c036745fa22e7e9b7373b',
    'dcf566ff291c25bbb8568fc3d376a6d9'),
    TCryptoLibStringArray.Create(
    'Test Case 13',
    '00000000000000000000000000000000' +
    '00000000000000000000000000000000',
    '', '',
    '000000000000000000000000',
    '',
    '530f8afbc74536b9a963b4f1c4cb738b'),
    TCryptoLibStringArray.Create(
    'Test Case 14',
    '00000000000000000000000000000000' +
    '00000000000000000000000000000000',
    '00000000000000000000000000000000',
    '',
    '000000000000000000000000',
    'cea7403d4d606b6e074ec5d3baf39d18',
    'd0d1c8a799996bf0265b98b5d48ab919'),
    TCryptoLibStringArray.Create(
    'Test Case 15',
    'feffe9928665731c6d6a8f9467308308' +
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b391aafd255',
    '',
    'cafebabefacedbaddecaf888',
    '522dc1f099567d07f47f37a32a84427d' +
    '643a8cdcbfe5c0c97598a2bd2555d1aa' +
    '8cb08e48590dbb3da7b08b1056828838' +
    'c5f61e6393ba7a0abcc9f662898015ad',
    'b094dac5d93471bdec1a502270e3cc6c'),
    TCryptoLibStringArray.Create(
    'Test Case 16',
    'feffe9928665731c6d6a8f9467308308' +
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    'cafebabefacedbaddecaf888',
    '522dc1f099567d07f47f37a32a84427d' +
    '643a8cdcbfe5c0c97598a2bd2555d1aa' +
    '8cb08e48590dbb3da7b08b1056828838' +
    'c5f61e6393ba7a0abcc9f662',
    '76fc6ece0f4e1768cddf8853bb2d551b'),
    TCryptoLibStringArray.Create(
    'Test Case 17',
    'feffe9928665731c6d6a8f9467308308' +
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    'cafebabefacedbad',
    'c3762df1ca787d32ae47c13bf19844cb' +
    'af1ae14d0b976afac52ff7d79bba9de0' +
    'feb582d33934a4f0954cc2363bc73f78' +
    '62ac430e64abe499f47c9b1f',
    '3a337dbf46a792c45e454913fe2ea8f2'),
    TCryptoLibStringArray.Create(
    'Test Case 18',
    'feffe9928665731c6d6a8f9467308308' +
    'feffe9928665731c6d6a8f9467308308',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    'feedfacedeadbeeffeedfacedeadbeef' + 'abaddad2',
    '9313225df88406e555909c5aff5269aa' +
    '6a7a9538534f7da1e4c303d2a318a728' +
    'c3c0c95156809539fcf0e2429a6b5254' +
    '16aedbf5a0de6a57a637b39b',
    '5a8def2f0c9e53f1f75d7853659e2a20' +
    'eeb2b22aafde6419a058ab4f6f746bf4' +
    '0fc0c3b780f244452da3ebf1c5d82cde' +
    'a2418997200ef82e44ae7e3f',
    'a44a8266ee1c8eb0c8b5d4cf5ae9f19a')
  );
end;

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
  Result := TAesEngine.Create() as IBlockCipher;
end;

function TTestGcm.InitCipher(const AM: IGcmMultiplier;
  AForEncryption: Boolean;
  const AParameters: IAeadParameters): IGcmBlockCipher;
begin
  Result := TGcmBlockCipher.Create(CreateAesEngine(), AM) as IGcmBlockCipher;
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

procedure TTestGcm.RunTestCase(const ATestVector: TCryptoLibStringArray);
var
  LMacLength: Int32;
begin
  for LMacLength := 12 to 16 do
  begin
    RunTestCase(ATestVector, LMacLength);
  end;
end;

procedure TTestGcm.RunTestCase(const ATestVector: TCryptoLibStringArray;
  AMacLength: Int32);
var
  LPos: Int32;
  LTestName: string;
  LK, LP, LA, LIV, LC, LFullTag, LT: TBytes;
begin
  LPos := 0;
  LTestName := ATestVector[LPos]; Inc(LPos);
  LK := DecodeHex(ATestVector[LPos]); Inc(LPos);
  LP := DecodeHex(ATestVector[LPos]); Inc(LPos);
  LA := DecodeHex(ATestVector[LPos]); Inc(LPos);
  LIV := DecodeHex(ATestVector[LPos]); Inc(LPos);
  LC := DecodeHex(ATestVector[LPos]); Inc(LPos);

  LFullTag := DecodeHex(ATestVector[LPos]);

  //LT := nil;
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
  LGcm := TGcmBlockCipher.Create(CreateAesEngine()) as IGcmBlockCipher;

  // Incorrect block size
  try
    LGcm := TGcmBlockCipher.Create(
      TBlowfishEngine.Create() as IBlockCipher) as IGcmBlockCipher;
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

  LC := TGcmBlockCipher.Create(CreateAesEngine()) as IGcmBlockCipher;
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
var
  LI: Int32;
begin
  for LI := 0 to System.Length(FTestVectors) - 1 do
  begin
    RunTestCase(FTestVectors[LI]);
  end;
end;

procedure TTestGcm.TestRandomised;
begin
  RandomTests;
end;

procedure TTestGcm.TestOutputSizes;
begin
  OutputSizeTests;
end;

procedure TTestGcm.TestExceptions;
begin
  DoTestExceptions;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestGcm);
{$ELSE}
  RegisterTest(TTestGcm.Suite);
{$ENDIF FPC}

end.
