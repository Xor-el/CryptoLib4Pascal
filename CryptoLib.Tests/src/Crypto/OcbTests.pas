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

unit OcbTests;

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
  ClpIAeadBlockCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDateTimeUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpAesEngine,
  ClpIAesEngine,
  ClpOcbBlockCipher,
  CryptoLibTestBase,
  AeadTestUtilities;

type

  TTestOcb = class(TCryptoLibAlgorithmTestCase)
  strict private
    const
      CKey128 = '000102030405060708090A0B0C0D0E0F';
      CKey96 = '0F0E0D0C0B0A09080706050403020100';

  strict private
    class var
      FTestVectors128: TCryptoLibGenericArray<TCryptoLibStringArray>;
      FTestVectors96: TCryptoLibGenericArray<TCryptoLibStringArray>;

    class constructor CreateTestOcb;

  private
    function CreateUnderlyingCipher: IBlockCipher;
    function CreateOcbCipher: IAeadBlockCipher;
    function InitOcbCipher(AForEncryption: Boolean;
      const AParameters: IAeadParameters): IAeadBlockCipher;

    procedure CheckTestCase(const AEncCipher, ADecCipher: IAeadBlockCipher;
      const ATestName: string; AMacLengthBytes: Int32;
      const AP, AC: TBytes);

    procedure RunTestCase(const ATestName: string;
      const ATestVector: TCryptoLibStringArray; AMacLengthBits: Int32;
      const AK: TBytes); overload;

    procedure RunLongerTestCase(AKeyLen, ATagLen: Int32;
      const AExpectedOutputHex: string);

    function CreateNonce(AN: UInt32): TBytes;
    function UpdateCiphers(const AC1, AC2: IAeadBlockCipher;
      const AData: TBytes; AI: Int32; AIncludeAad, AIncludePlaintext: Boolean)
      : Int32;

    procedure RandomTest(const ARandom: ISecureRandom);
    function NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestRfcVectors128;
    procedure TestRfcVectors96;
    procedure TestOcbLongForm;
    procedure TestRandomised;
    procedure TestOutputSizes;
    procedure TestExceptions;

  end;

implementation

{ TTestOcb }

class constructor TTestOcb.CreateTestOcb;
begin
  // RFC 7253 TEST_VECTORS_128: N, A, P, C
  //SetLength(FTestVectors128, 0);

  FTestVectors128 := TCryptoLibGenericArray<TCryptoLibStringArray>.Create(
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221100',
    '',
    '',
    '785407BFFFC8AD9EDCC5520AC9111EE6'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221101',
    '0001020304050607',
    '0001020304050607',
    '6820B3657B6F615A5725BDA0D3B4EB3A257C9AF1F8F03009'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221102',
    '0001020304050607',
    '',
    '81017F8203F081277152FADE694A0A00'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221103',
    '',
    '0001020304050607',
    '45DD69F8F5AAE72414054CD1F35D82760B2CD00D2F99BFA9'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221104',
    '000102030405060708090A0B0C0D0E0F',
    '000102030405060708090A0B0C0D0E0F',
    '571D535B60B277188BE5147170A9A22C3AD7A4FF3835B8C5701C1CCEC8FC3358'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221105',
    '000102030405060708090A0B0C0D0E0F',
    '',
    '8CF761B6902EF764462AD86498CA6B97'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221106',
    '',
    '000102030405060708090A0B0C0D0E0F',
    '5CE88EC2E0692706A915C00AEB8B2396F40E1C743F52436BDF06D8FA1ECA343D'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221107',
    '000102030405060708090A0B0C0D0E0F1011121314151617',
    '000102030405060708090A0B0C0D0E0F1011121314151617',
    '1CA2207308C87C010756104D8840CE1952F09673A448A122C92C62241051F57356D7F3C90BB0E07F'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221108',
    '000102030405060708090A0B0C0D0E0F1011121314151617',
    '',
    '6DC225A071FC1B9F7C69F93B0F1E10DE'),
    TCryptoLibStringArray.Create(
    'BBAA99887766554433221109',
    '',
    '000102030405060708090A0B0C0D0E0F1011121314151617',
    '221BD0DE7FA6FE993ECCD769460A0AF2D6CDED0C395B1C3CE725F32494B9F914D85C0B1EB38357FF'),
    TCryptoLibStringArray.Create(
    'BBAA9988776655443322110A',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    'BD6F6C496201C69296C11EFD138A467ABD3C707924B964DEAFFC40319AF5A48540FBBA186C5553C68AD9F592A79A4240'),
    TCryptoLibStringArray.Create(
    'BBAA9988776655443322110B',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    '',
    'FE80690BEE8A485D11F32965BC9D2A32'),
    TCryptoLibStringArray.Create(
    'BBAA9988776655443322110C',
    '',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F',
    '2942BFC773BDA23CABC6ACFD9BFD5835BD300F0973792EF46040C53F1432BCDFB5E1DDE3BC18A5F840B52E653444D5DF'),
    TCryptoLibStringArray.Create(
    'BBAA9988776655443322110D',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
    'D5CA91748410C1751FF8A2F618255B68A0A12E093FF454606E59F9C1D0DDC54B65E8628E568BAD7AED07BA06A4A69483A7035490C5769E60'),
    TCryptoLibStringArray.Create(
    'BBAA9988776655443322110E',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
    '',
    'C5CD9D1850C141E358649994EE701B68'),
    TCryptoLibStringArray.Create(
    'BBAA9988776655443322110F',
    '',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
    '4412923493C57D5DE0D700F753CCE0D1D2D95060122E9F15A5DDBFC5787E50B5CC55EE507BCB084E479AD363AC366B95A98CA5F3000B1479')
    );

  // RFC 7253 TEST_VECTORS_96: N, A, P, C
  //SetLength(FTestVectors96, 0);
  FTestVectors96 := TCryptoLibGenericArray<TCryptoLibStringArray>.Create(
    TCryptoLibStringArray.Create(
    'BBAA9988776655443322110D',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
    '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F2021222324252627',
    '1792A4E31E0755FB03E31B22116E6C2DDF9EFD6E33D536F1A0124B0A55BAE884ED93481529C76B6AD0C515F4D1CDD4FDAC4F02AA')
    );
end;

function TTestOcb.CreateUnderlyingCipher: IBlockCipher;
begin
  Result := TAesEngine.Create() as IAesEngine;
end;

function TTestOcb.CreateOcbCipher: IAeadBlockCipher;
var
  LHashCipher, LMainCipher: IBlockCipher;
begin
  LHashCipher := CreateUnderlyingCipher;
  LMainCipher := CreateUnderlyingCipher;
  Result := TOcbBlockCipher.Create(LHashCipher, LMainCipher) as IAeadBlockCipher;
end;

function TTestOcb.InitOcbCipher(AForEncryption: Boolean;
  const AParameters: IAeadParameters): IAeadBlockCipher;
begin
  Result := CreateOcbCipher;
  Result.Init(AForEncryption, AParameters as ICipherParameters);
end;

procedure TTestOcb.CheckTestCase(const AEncCipher, ADecCipher: IAeadBlockCipher;
  const ATestName: string; AMacLengthBytes: Int32;
  const AP, AC: TBytes);
var
  LTag, LEnc, LDec, LStreamTag: TBytes;
  LLen: Int32;
begin
  LTag := Copy(AC, Length(AC) - AMacLengthBytes, AMacLengthBytes);

  // encryption
  SetLength(LEnc, AEncCipher.GetOutputSize(Length(AP)));
  LLen := AEncCipher.ProcessBytes(AP, 0, Length(AP), LEnc, 0);
  LLen := LLen + AEncCipher.DoFinal(LEnc, LLen);

  if Length(LEnc) <> LLen then
  begin
    Fail('encryption reported incorrect length: ' + ATestName);
  end;

  if not AreEqual(AC, LEnc) then
  begin
    Fail('incorrect encrypt in: ' + ATestName);
  end;

  if not AreEqual(LTag, AEncCipher.GetMac) then
  begin
    Fail('getMac() not the same as the appended tag: ' + ATestName);
  end;

  SetLength(LStreamTag, Length(AC) - Length(AP));
  if Length(LStreamTag) > 0 then
  begin
    System.Move(AC[Length(AP)], LStreamTag[0], Length(LStreamTag));
  end;
  if not AreEqual(LTag, LStreamTag) then
  begin
    Fail('stream tag mismatch in: ' + ATestName);
  end;

  // decryption
  SetLength(LDec, ADecCipher.GetOutputSize(Length(AC)));
  LLen := ADecCipher.ProcessBytes(AC, 0, Length(AC), LDec, 0);
  LLen := LLen + ADecCipher.DoFinal(LDec, LLen);

  if Length(LDec) <> LLen then
  begin
    Fail('decryption reported incorrect length: ' + ATestName);
  end;

  if not AreEqual(AP, LDec) then
  begin
    Fail('incorrect decrypt in: ' + ATestName);
  end;

  if not AreEqual(LTag, ADecCipher.GetMac) then
  begin
    Fail('getMac() not the same as the appended tag (decrypt): ' + ATestName);
  end;
end;

procedure TTestOcb.RunTestCase(const ATestName: string;
  const ATestVector: TCryptoLibStringArray; AMacLengthBits: Int32;
  const AK: TBytes);
var
  LPos, LMacLengthBytes: Int32;
  LN, LA, LP, LC: TBytes;
  LKeyParam: IKeyParameter;
  LParams, LKeyReuseParams: IAeadParameters;
  LEnc, LDec: IAeadBlockCipher;
begin
  LPos := 0;
  LN := DecodeHex(ATestVector[LPos]);
  Inc(LPos);
  LA := DecodeHex(ATestVector[LPos]);
  Inc(LPos);
  LP := DecodeHex(ATestVector[LPos]);
  Inc(LPos);
  LC := DecodeHex(ATestVector[LPos]);

  LMacLengthBytes := AMacLengthBits div 8;

  LKeyParam := TKeyParameter.Create(AK) as IKeyParameter;
  LParams := TAeadParameters.Create(LKeyParam, AMacLengthBits, LN, LA);

  LEnc := InitOcbCipher(True, LParams);
  LDec := InitOcbCipher(False, LParams);

  CheckTestCase(LEnc, LDec, ATestName, LMacLengthBytes, LP, LC);
  CheckTestCase(LEnc, LDec, ATestName + ' (reused)', LMacLengthBytes, LP, LC);

  // key reuse parameters (reuse key, new nonce)
  LKeyReuseParams := TAeadTestUtilities.ReuseKey(LParams);
  LEnc.Init(True, LKeyReuseParams as ICipherParameters);
  LDec.Init(False, LKeyReuseParams as ICipherParameters);
  CheckTestCase(LEnc, LDec, ATestName + ' (key reuse)', LMacLengthBytes, LP, LC);
end;

function TTestOcb.CreateNonce(AN: UInt32): TBytes;
begin
  SetLength(Result, 12);
  // first 10 bytes zero, last two hold n (big-endian, low 16 bits)
  Result[10] := Byte(AN shr 8);
  Result[11] := Byte(AN);
end;

function TTestOcb.UpdateCiphers(const AC1, AC2: IAeadBlockCipher;
  const AData: TBytes; AI: Int32; AIncludeAad, AIncludePlaintext: Boolean): Int32;
var
  LInputLen, LOutputLen, LLen: Int32;
  LOutput: TBytes;
begin
  if AIncludePlaintext then
  begin
    LInputLen := AI;
  end
  else
  begin
    LInputLen := 0;
  end;

  LOutputLen := AC2.GetOutputSize(LInputLen);
  SetLength(LOutput, LOutputLen);
  LLen := 0;

  if AIncludeAad then
  begin
    AC2.ProcessAadBytes(AData, 0, AI);
  end;

  if AIncludePlaintext then
  begin
    LLen := LLen + AC2.ProcessBytes(AData, 0, AI, LOutput, LLen);
  end;

  LLen := LLen + AC2.DoFinal(LOutput, LLen);

  AC1.ProcessAadBytes(LOutput, 0, LLen);
  Result := LLen;
end;

procedure TTestOcb.RunLongerTestCase(AKeyLen, ATagLen: Int32;
  const AExpectedOutputHex: string);
var
  LExpectedOutput, LKeyBytes, LS, LOutput: TBytes;
  LKey: IKeyParameter;
  LOcb1, LOcb2: IAeadBlockCipher;
  LTotal, LExpectedTotal: Int64;
  LN: UInt32;
  LI: Int32;
begin
  LExpectedOutput := DecodeHex(AExpectedOutputHex);
  SetLength(LKeyBytes, AKeyLen div 8);
  LKeyBytes[High(LKeyBytes)] := Byte(ATagLen);
  LKey := TKeyParameter.Create(LKeyBytes) as IKeyParameter;

  LOcb1 := InitOcbCipher(True,
    TAeadParameters.Create(LKey, ATagLen, CreateNonce(385), nil));
  LOcb2 := CreateOcbCipher;

  LTotal := 0;
  SetLength(LS, 128);

  LN := 0;
  for LI := 0 to 127 do
  begin
    Inc(LN);
    LOcb2.Init(True,
      TAeadParameters.Create(LKey, ATagLen, CreateNonce(LN), nil)
      as IAeadParameters as ICipherParameters);
    LTotal := LTotal + UpdateCiphers(LOcb1, LOcb2, LS, LI, True, True);

    Inc(LN);
    LOcb2.Init(True,
      TAeadParameters.Create(LKey, ATagLen, CreateNonce(LN), nil)
      as IAeadParameters as ICipherParameters);
    LTotal := LTotal + UpdateCiphers(LOcb1, LOcb2, LS, LI, False, True);

    Inc(LN);
    LOcb2.Init(True,
      TAeadParameters.Create(LKey, ATagLen, CreateNonce(LN), nil)
      as IAeadParameters as ICipherParameters);
    LTotal := LTotal + UpdateCiphers(LOcb1, LOcb2, LS, LI, True, False);
  end;

  LExpectedTotal := 16256 + (48 * ATagLen);
  if LTotal <> LExpectedTotal then
  begin
    Fail('test generated the wrong amount of input: ' + IntToStr(LTotal));
  end;

  SetLength(LOutput, LOcb1.GetOutputSize(0));
  LOcb1.DoFinal(LOutput, 0);

  if not AreEqual(LExpectedOutput, LOutput) then
  begin
    Fail('incorrect encrypt in long-form test');
  end;
end;

procedure TTestOcb.RandomTest(const ARandom: ISecureRandom);
var
  LK, LP, LA, LSA, LIV, LC, LDecP, LEncT, LDecT, LTail: TBytes;
  LKeyLen, LPLen, LALen, LSaLen, LIvLen: Int32;
  LParams: IAeadParameters;
  LCipher: IAeadBlockCipher;
  LPredicted, LLen, LSplit: Int32;
begin
  LKeyLen := 16 + 8 * (Abs(ARandom.NextInt32()) mod 3);
  SetLength(LK, LKeyLen);
  ARandom.NextBytes(LK);

  LPLen := UInt32(ARandom.NextInt32()) shr 16;
  SetLength(LP, LPLen);
  ARandom.NextBytes(LP);

  LALen := UInt32(ARandom.NextInt32()) shr 24;
  SetLength(LA, LALen);
  ARandom.NextBytes(LA);

  LSaLen := UInt32(ARandom.NextInt32()) shr 24;
  SetLength(LSA, LSaLen);
  ARandom.NextBytes(LSA);

  LIvLen := 1 + NextInt32(ARandom, 15);
  SetLength(LIV, LIvLen);
  ARandom.NextBytes(LIV);

  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LIV, LA);
  LCipher := InitOcbCipher(True, LParams);

  SetLength(LC, LCipher.GetOutputSize(LPLen));
  LPredicted := LCipher.GetUpdateOutputSize(LPLen);

  LSplit := NextInt32(ARandom, LSaLen + 1);
  LCipher.ProcessAadBytes(LSA, 0, LSplit);
  LLen := LCipher.ProcessBytes(LP, 0, LPLen, LC, 0);
  LCipher.ProcessAadBytes(LSA, LSplit, LSaLen - LSplit);

  if LPredicted <> LLen then
  begin
    Fail('encryption reported incorrect update length in randomised test');
  end;

  LLen := LLen + LCipher.DoFinal(LC, LLen);

  if Length(LC) <> LLen then
  begin
    Fail('encryption reported incorrect length in randomised test');
  end;

  LEncT := LCipher.GetMac;
  SetLength(LTail, Length(LC) - LPLen);
  if Length(LTail) > 0 then
  begin
    System.Move(LC[LPLen], LTail[0], Length(LTail));
  end;
  if not AreEqual(LEncT, LTail) then
  begin
    Fail('stream contained wrong mac in randomised test');
  end;

  // decrypt
  LCipher.Init(False, LParams as ICipherParameters);
  SetLength(LDecP, LCipher.GetOutputSize(Length(LC)));
  LPredicted := LCipher.GetUpdateOutputSize(Length(LC));

  LSplit := NextInt32(ARandom, LSaLen + 1);
  LCipher.ProcessAadBytes(LSA, 0, LSplit);
  LLen := LCipher.ProcessBytes(LC, 0, Length(LC), LDecP, 0);
  LCipher.ProcessAadBytes(LSA, LSplit, LSaLen - LSplit);

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

  // key reuse test
  LCipher.Init(False, TAeadTestUtilities.ReuseKey(LParams) as ICipherParameters);
  SetLength(LDecP, LCipher.GetOutputSize(Length(LC)));

  LSplit := NextInt32(ARandom, LSaLen + 1);
  LCipher.ProcessAadBytes(LSA, 0, LSplit);
  LLen := LCipher.ProcessBytes(LC, 0, Length(LC), LDecP, 0);
  LCipher.ProcessAadBytes(LSA, LSplit, LSaLen - LSplit);

  LCipher.DoFinal(LDecP, LLen);

  if not AreEqual(LP, LDecP) then
  begin
    Fail('incorrect decrypt in randomised test');
  end;

  LDecT := LCipher.GetMac;
  if not AreEqual(LEncT, LDecT) then
  begin
    Fail('decryption produced different mac from encryption (key reuse)');
  end;
end;

function TTestOcb.NextInt32(const ARandom: ISecureRandom; AN: Int32): Int32;
var
  LBits, LValue: Int32;
begin
  if (AN and -AN) = AN then
  begin
    Result := Int32((UInt32(AN) * UInt64(UInt32(ARandom.NextInt32()) shr 1)) shr 31);
    Exit;
  end;

  repeat
    LBits := Int32(UInt32(ARandom.NextInt32()) shr 1);
    LValue := LBits mod AN;
  until (LBits - LValue + (AN - 1)) >= 0;

  Result := LValue;
end;

procedure TTestOcb.SetUp;
begin
  inherited;
end;

procedure TTestOcb.TearDown;
begin
  inherited;
end;

procedure TTestOcb.TestRfcVectors128;
var
  LK: TBytes;
  LI: Int32;
begin
  LK := DecodeHex(CKey128);
  for LI := 0 to High(FTestVectors128) do
  begin
    RunTestCase(Format('Test Case %d', [LI]), FTestVectors128[LI], 128, LK);
  end;
end;

procedure TTestOcb.TestRfcVectors96;
var
  LK: TBytes;
  LI: Int32;
begin
  LK := DecodeHex(CKey96);
  for LI := 0 to High(FTestVectors96) do
  begin
    RunTestCase(Format('Test Case %d', [LI]), FTestVectors96[LI], 96, LK);
  end;
end;

procedure TTestOcb.TestOcbLongForm;
begin
  RunLongerTestCase(128, 128, '67E944D23256C5E0B6C61FA22FDF1EA2');
  RunLongerTestCase(192, 128, 'F673F2C3E7174AAE7BAE986CA9F29E17');
  RunLongerTestCase(256, 128, 'D90EB8E9C977C88B79DD793D7FFA161C');
  RunLongerTestCase(128, 96, '77A3D8E73589158D25D01209');
  RunLongerTestCase(192, 96, '05D56EAD2752C86BE6932C5E');
  RunLongerTestCase(256, 96, '5458359AC23B0CBA9E6330DD');
  RunLongerTestCase(128, 64, '192C9B7BD90BA06A');
  RunLongerTestCase(192, 64, '0066BC6E0EF34E24');
  RunLongerTestCase(256, 64, '7D4EA5D445501CBE');
end;

procedure TTestOcb.TestRandomised;
var
  LRandom: ISecureRandom;
  LI: Int32;
begin
  LRandom := TSecureRandom.Create();
  LRandom.SetSeed(TDateTimeUtilities.CurrentUnixMs);
  for LI := 0 to 9 do
  begin
    RandomTest(LRandom);
  end;
end;

procedure TTestOcb.TestOutputSizes;
var
  LK, LIV: TBytes;
  LParams: IAeadParameters;
  LCipher: IAeadBlockCipher;
begin
  SetLength(LK, 16);
  LIV := TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LIV, nil);
  LCipher := InitOcbCipher(True, LParams);

  if LCipher.GetUpdateOutputSize(0) <> 0 then
  begin
    Fail('incorrect getUpdateOutputSize for initial 0 bytes encryption');
  end;

  if LCipher.GetOutputSize(0) <> 16 then
  begin
    Fail('incorrect getOutputSize for initial 0 bytes encryption');
  end;

  LCipher.Init(False, LParams as ICipherParameters);

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

procedure TTestOcb.TestExceptions;
var
  LOcb: IAeadBlockCipher;
  LK: TBytes;
begin
  LOcb := CreateOcbCipher;

  // wrong parameters: bare KeyParameter vs AEAD parameters
  SetLength(LK, 16);
  try
    LOcb.Init(False, TKeyParameter.Create(LK) as IKeyParameter);
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
  RegisterTest(TTestOcb);
{$ELSE}
  RegisterTest(TTestOcb.Suite);
{$ENDIF FPC}

end.

