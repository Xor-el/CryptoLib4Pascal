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

unit Poly1305Tests;

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
  ClpIMac,
  ClpIPoly1305,
  ClpPoly1305,
  ClpPoly1305KeyGenerator,
  ClpCipherKeyGenerator,
  ClpICipherKeyGenerator,
  ClpKeyGenerationParameters,
  ClpIKeyGenerationParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpAesUtilities,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpEncoders,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestPoly1305 = class(TCryptoLibAlgorithmTestCase)
  strict private
  type
    TTestCase = record
      Key: TBytes;
      Nonce: TBytes;
      MessageToVerify: TBytes;
      ExpectedMac: TBytes;
    end;

  strict private
    class var
      FCases: array of TTestCase;

    class constructor CreateTestPoly1305;

  private
    procedure CheckEqual(const AName: string; const AExpected, AActual: TBytes);
    procedure CheckVector(const AKeyMaterial, AInput, ATag: TBytes);
    procedure RunCase(ACaseIndex: Int32);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestKeyGenerator;
    procedure TestInitParameters;
    procedure TestFixedCases;
    procedure TestSequential;
    procedure TestResetBehaviour;
    procedure TestRfc7539Vectors;
    procedure TestBlockUpdateOneShotVsChunked;
    procedure TestLcgMessageBulkLengths;

  end;

implementation

{ TTestPoly1305 }

class constructor TTestPoly1305.CreateTestPoly1305;
var
  LCase: TTestCase;
begin
  // Raw Poly1305 case (no nonce)
  SetLength(FCases, 0);

  // Case 0: Raw Poly1305 - onetimeauth.c from nacl-20110221
  LCase.Key := THexEncoder.Decode(
    'eea6a7251c1e72916d11c2cb214d3c25' +
    '2539121d8e234e652d651fa4c8cff880');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := nil;
  LCase.MessageToVerify := THexEncoder.Decode(
    '8e993b9f48681273c29650ba32fc76ce48332ea7164d96a4476fb8c531a1186a' +
    'c0dfc17c98dce87b4da7f011ec48c97271d2c20f9b928fe2270d6fb863d51738' +
    'b48eeee314a7cc8ab932164548e526ae90224368517acfeabd6bb3732bc0e9da' +
    '99832b61ca01b6de56244a9e88d5f9b37973f622a43d14a6599b1f654cb45a74e355a5');
  LCase.ExpectedMac := THexEncoder.Decode('f3ffc7703f9400e52a7dfb4b3d3305d9');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 1: Poly1305-AES - Loop 1 of test-poly1305aes from poly1305aes-20050218
  LCase.Key := THexEncoder.Decode(
    '0000000000000000000000000000000000000000000000000000000000000000');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := THexEncoder.Decode('00000000000000000000000000000000');
  LCase.MessageToVerify := THexEncoder.Decode('');
  LCase.ExpectedMac := THexEncoder.Decode('66e94bd4ef8a2c3b884cfa59ca342b2e');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 2: Poly1305-AES
  LCase.Key := THexEncoder.Decode(
    'f795bd0a50e29e0710d3130a20e98d0c' +
    'f795bd4a52e29ed713d313fa20e98dbc');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := THexEncoder.Decode('917cf69ebd68b2ec9b9fe9a3eadda692');
  LCase.MessageToVerify := THexEncoder.Decode('66f7');
  LCase.ExpectedMac := THexEncoder.Decode('5ca585c75e8f8f025e710cabc9a1508b');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 3: Poly1305-AES
  LCase.Key := THexEncoder.Decode(
    '3ef49901c8e11c000430d90ad45e7603' +
    'e69dae0aab9f91c03a325dcc9436fa90');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := THexEncoder.Decode('166450152e2394835606a9d1dd2cdc8b');
  LCase.MessageToVerify := THexEncoder.Decode('66f75c0e0c7a406586');
  LCase.ExpectedMac := THexEncoder.Decode('2924f51b9c2eff5df09db61dd03a9ca1');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 4: Poly1305-AES
  LCase.Key := THexEncoder.Decode(
    'da4afc035087d90e503f8f0ea08c3e0d' +
    '85a4ea91a7de0b0d96eed0d4bf6ecf1c');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := THexEncoder.Decode('0b6ef7a0b8f8c738b0f8d5995415271f');
  LCase.MessageToVerify := THexEncoder.Decode(
    '66f75c0e0c7a40658629e3392f7f8e3349a02191ffd49f39879a8d9d1d0e23ea');
  LCase.ExpectedMac := THexEncoder.Decode('3c5a13adb18d31c64cc29972030c917d');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 5: Poly1305-AES
  LCase.Key := THexEncoder.Decode(
    'ca3c6a0da0a864024ca3090628c28e0d' +
    '25eb69bac5cdf7d6bfcee4d9d5507b82');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := THexEncoder.Decode('046772a4f0a8de92e4f0d628cdb04484');
  LCase.MessageToVerify := THexEncoder.Decode(
    '66f75c0e0c7a40658629e3392f7f8e3349a02191ffd49f39879a8d9d1d0e23ea' +
    '3caa4d240bd2ab8a8c4a6bb8d3288d9de4b793f05e97646dd4d98055de');
  LCase.ExpectedMac := THexEncoder.Decode('fc5fb58dc65daf19b14d1d05da1064e8');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 6: Poly1305-AES - Specific test case that exposes unsigned integer problems
  LCase.Key := THexEncoder.Decode(
    '01bcb20bfc8b6e03609ddd09f44b060f' +
    '95cc0e44d0b79a8856afcae1bec4fe3c');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := nil;
  LCase.MessageToVerify := THexEncoder.Decode(
    '66f75c0e0c7a40658629e3392f7f8e3349a02191ffd49f39879a8d9d1d0e23ea' +
    '3caa4d240bd2ab8a8c4a6bb8d3288d9de4b793f05e97646dd4d98055de' +
    'fc3e0677d956b4c62664bac15962ab15d93ccbbc03aafdbde779162ed93b55361f0f8acaa41d50ef5175927fe79ea316186516eef15001cd04d3524a55' +
    'e4fa3c5ca479d3aaa8a897c21807f721b6270ffc68b6889d81a116799f6aaa35d8e04c7a7dd5e6da2519e8759f54e906696f5772fee093283bcef7b930' +
    'aed50323bcbc8c820c67422c1e16bdc022a9c0277c9d95fef0ea4ee11e2b27276da811523c5acb80154989f8a67ee9e3fa30b73b0c1c34bf46e3464d97' +
    '7cd7fcd0ac3b82721080bb0d9b982ee2c77feee983d7ba35da88ce86955002940652ab63bc56fb16f994da2b01d74356509d7d1b6d7956b0e5a557757b' +
    'd1ced2eef8650bc5b6d426108c1518abcbd0befb6a0d5fd57a3e2dbf31458eab63df66613653d4beae73f5c40eb438fbcfdcf4a4ba46320184b9ca0da4' +
    'dfae77de7ccc910356caea3243f33a3c81b064b3b7cedc7435c223f664227215715980e6e0bb570d459ba80d7512dbe458c8f0f3f52d659b6e8eef19ee' +
    '71aea2ced85c7a42ffca6522a62db49a2a46eff72bd7f7e0883acd087183f0627f3537a4d558754ed63358e8182bee196735b361dc9bd64d5e34e1074a' +
    '855655d2974cc6fa1653754cf40f561d8c7dc526aab2908ec2d2b977cde1a1fb1071e32f40e049ea20f30368ba1592b4fe57fb51595d23acbdace324cd' +
    'd78060a17187c662368854e915402d9b52fb21e984663e41c26a109437e162cfaf071b53f77e50000a5388ff183b82ce7a1af476c416d7d204157b3633' +
    'b2f4ec077b699b032816997e37bceded8d4a04976fd7d0c0b029f290794c3be504c5242287ea2f831f11ed5690d92775cd6e863d7731fd4da687ebfb13' +
    'df4c41dc0fb8');
  LCase.ExpectedMac := THexEncoder.Decode('ae345d555eb04d6947bb95c0965237e2');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 7: Poly1305-AES - Another unsigned integer problem test case
  LCase.Key := THexEncoder.Decode(
    'cd07fd0ef8c0be0afcbdb30af4af0009' +
    '76fb3635a2dc92a1f768163ab12f2187');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := nil;
  LCase.MessageToVerify := THexEncoder.Decode(
    'f05204a74f0f88a7fa1a95b84ec3d8ffb36fcdc7723ea65dfe7cd464e86e0abf6b9d51db3220cfd8496ad6e6d36ebee8d990f9ce0d3bb7f72b7ab5b3ab' +
    '0a73240d11efe772c857021ae859db4933cdde4387b471d2ce700fef4b81087f8f47c307881fd83017afcd15b8d21edf9b704677f46df97b07e5b83f87' +
    'c8abd90af9b1d0f9e2710e8ebd0d4d1c6a055abea861f42368bed94d9373e909c1d3715b221c16bc524c55c31ec3eab204850bb2474a84f9917038eff9' +
    'd921130951391b5c54f09b5e1de833ea2cd7d3b306740abb7096d1e173da83427da2adddd3631eda30b54dbf487f2b082e8646f07d6e0a87e97522ca38' +
    'd4ace4954bf3db6dd3a93b06fa18eb56856627ed6cffcd7ae26374554ca18ab8905f26331d323fe10e6e70624c7bc07a70f06ecd804b48f8f7e75e9101' +
    '65e1beb554f1f0ec7949c9c8d429a206b4d5c0653102249b6098e6b45fac2a07ff0220b0b8ae8f4c6bcc0c813a7cd141fa8b398b42575fc395747c5a02' +
    '57ac41d6c1f434cfbf5dfe8349f5347ef6b60e611f5d6c3cbc20ca2555274d1934325824cef4809da293ea13f181929e2af025bbd1c9abdc3af93afd4c' +
    '50a2854ade3887f4d2c8c225168052c16e74d76d2dd3e9467a2c5b8e15c06ffbffa42b8536384139f07e195a8c9f70f514f31dca4eb2cf262c0dcbde53' +
    '654b6250a29efe21d54e83c80e005a1cad36d5934ff01c32e4bc5fe06d03064ff4a268517df4a94c759289f323734318cfa5d859d4ce9c16e63d02dff0' +
    '896976f521607638535d2ee8dd3312e1ddc80a55d34fe829ab954c1ebd54d929954770f1be9d32b4c05003c5c9e97943b6431e2afe820b1e967b19843e' +
    '5985a131b1100517cdc363799104af91e2cf3f53cb8fd003653a6dd8a31a3f9d566a7124b0ffe9695bcb87c482eb60106f88198f766a40bc0f4873c236' +
    '53c5f9e7a8e446f770beb8034cf01d21028ba15ccee21a8db918c4829d61c88bfa927bc5def831501796c5b401a60a6b1b433c9fb905c8cd40412fffee81ab');
  LCase.ExpectedMac := THexEncoder.Decode('045be28cc52009f506bdbfabedacf0b4');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;

  // Case 8: Test case from JIRA issue BJA-620
  LCase.Key := THexEncoder.Decode(
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff');
  TPoly1305KeyGenerator.Clamp(LCase.Key);
  LCase.Nonce := nil;
  LCase.MessageToVerify := THexEncoder.Decode(
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffffff' +
    'ffffffffffffffffffffffffffffff');
  LCase.ExpectedMac := THexEncoder.Decode('c80cb43844f387946e5aa6085bdf67da');
  SetLength(FCases, Length(FCases) + 1);
  FCases[High(FCases)] := LCase;
end;

procedure TTestPoly1305.CheckEqual(const AName: string; const AExpected,
  AActual: TBytes);
begin
  if not AreEqual(AExpected, AActual) then
  begin
    Fail(Format('%s Failed - expected %s got %s',
      [AName, EncodeHex(AExpected), EncodeHex(AActual)]));
  end;
end;

procedure TTestPoly1305.CheckVector(const AKeyMaterial, AInput, ATag: TBytes);
var
  LMac: IMac;
  LActual: TBytes;
begin
  LMac := TPoly1305.Create() as IPoly1305;
  LMac.Init(TKeyParameter.Create(AKeyMaterial) as IKeyParameter);
  LMac.BlockUpdate(AInput, 0, Length(AInput));
  SetLength(LActual, LMac.GetMacSize);
  LMac.DoFinal(LActual, 0);
  if not AreEqual(ATag, LActual) then
    Fail(Format('rfc7539 Failed - expected %s got %s',
      [EncodeHex(ATag), EncodeHex(LActual)]));
end;

procedure TTestPoly1305.RunCase(ACaseIndex: Int32);
var
  LCase: TTestCase;
  LMac: IMac;
  LKeyParam: IKeyParameter;
  LParamsWithIv: IParametersWithIV;
  LOut: TBytes;
begin
  LCase := FCases[ACaseIndex];

  if LCase.Nonce = nil then
  begin
    LMac := TPoly1305.Create() as IPoly1305;
    LKeyParam := TKeyParameter.Create(LCase.Key) as IKeyParameter;
    LMac.Init(LKeyParam);
  end
  else
  begin
    LMac := TPoly1305.Create(TAesUtilities.CreateEngine()) as IPoly1305;
    LParamsWithIv := TParametersWithIV.Create
      (TKeyParameter.Create(LCase.Key) as IKeyParameter, LCase.Nonce);
    LMac.Init(LParamsWithIv as ICipherParameters);
  end;

  LMac.BlockUpdate(LCase.MessageToVerify, 0, Length(LCase.MessageToVerify));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual(Format('Poly1305 case %d', [ACaseIndex]), LCase.ExpectedMac, LOut);
end;

procedure TTestPoly1305.SetUp;
begin
  inherited;
end;

procedure TTestPoly1305.TearDown;
begin
  inherited;
end;

procedure TTestPoly1305.TestKeyGenerator;
var
  LGen: ICipherKeyGenerator;
  LParams: IKeyGenerationParameters;
  LRandom: ISecureRandom;
  LKey, LKeyCopy: TBytes;
begin
  LGen := TPoly1305KeyGenerator.Create() as ICipherKeyGenerator;
  LRandom := TSecureRandom.Create();
  LParams := TKeyGenerationParameters.Create(LRandom, 256);
  LGen.Init(LParams);

  LKey := LGen.GenerateKey;

  if Length(LKey) <> 32 then
  begin
    Fail('Poly1305 key should be 256 bits.');
  end;

  try
    TPoly1305KeyGenerator.CheckKey(LKey);
  except
    on E: EArgumentCryptoLibException do
    begin
      Fail('Poly1305 key should be clamped on generation.');
    end;
  end;

  LKeyCopy := Copy(LKey);
  TPoly1305KeyGenerator.Clamp(LKey);
  if not AreEqual(LKey, LKeyCopy) then
  begin
    Fail('Poly1305 key should be clamped on generation.');
  end;
end;

procedure TTestPoly1305.TestInitParameters;
var
  LGen: ICipherKeyGenerator;
  LRandom: ISecureRandom;
  LParams: IKeyGenerationParameters;
  LKey: TBytes;
  LMac: IMac;
begin
  LGen := TPoly1305KeyGenerator.Create() as ICipherKeyGenerator;
  LRandom := TSecureRandom.Create();
  LParams := TKeyGenerationParameters.Create(LRandom, 256);
  LGen.Init(LParams);
  LKey := LGen.GenerateKey;

  LMac := TPoly1305.Create(TAesUtilities.CreateEngine()) as IPoly1305;

  // correct IV size
  LMac.Init(TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as ICipherParameters);

  // wrong IV size
  try
    LMac.Init(TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
      TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as ICipherParameters);
    Fail('16 byte nonce required');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  // wrong key size
  try
    SetLength(LKey, Length(LKey) - 1);
    LMac.Init(TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
      TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as ICipherParameters);
    Fail('32 byte key required');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestPoly1305.TestFixedCases;
var
  LI: Int32;
begin
  for LI := 0 to High(FCases) do
  begin
    RunCase(LI);
  end;
end;

procedure TTestPoly1305.TestSequential;
const
  CMaxLen = 1000;
var
  LLen, LC, LLoop, LI: Int32;
  LKr, LM, LNBytes, LOutput: TBytes;
  LMac: IMac;
begin
  SetLength(LKr, 32);
  SetLength(LM, CMaxLen);
  SetLength(LNBytes, 16);
  SetLength(LOutput, 16);

  LC := 0;
  LMac := TPoly1305.Create(TAesUtilities.CreateEngine()) as IPoly1305;

  for LLoop := 0 to 12 do
  begin
    LLen := 0;
    while True do
    begin
      Inc(LC);
      LMac.Init(TParametersWithIV.Create(TKeyParameter.Create(LKr) as IKeyParameter,
        LNBytes) as ICipherParameters);
      LMac.BlockUpdate(LM, 0, LLen);
      LMac.DoFinal(LOutput, 0);

      if LLen >= CMaxLen then
      begin
        Break;
      end;

      LNBytes[0] := Byte(LNBytes[0] xor Byte(LLoop));
      for LI := 0 to 15 do
      begin
        LNBytes[LI] := LNBytes[LI] xor LOutput[LI];
      end;
      if (LLen and 1) <> 0 then
      begin
        for LI := 0 to 15 do
        begin
          LKr[LI] := LKr[LI] xor LOutput[LI];
        end;
      end;
      if (LLen mod 3) <> 0 then
      begin
        for LI := 0 to 15 do
        begin
          LKr[LI + 16] := LKr[LI + 16] xor LOutput[LI];
        end;
      end;
      TPoly1305KeyGenerator.Clamp(LKr);
      LM[LLen] := LM[LLen] xor LOutput[0];
      Inc(LLen);
    end;
  end;

  if not ((LC = 13013) and
    AreEqual(LOutput, THexEncoder.Decode('89824ddf0816481051f4a82731cd56d5'))) then
  begin
    Fail('Sequential Poly1305 ' + IntToStr(LC));
  end;
end;

procedure TTestPoly1305.TestResetBehaviour;
var
  LGen: ICipherKeyGenerator;
  LRandom: ISecureRandom;
  LParams: IKeyGenerationParameters;
  LKey: TBytes;
  LM: TBytes;
  LCheck, LOutput: TBytes;
  LPoly: IMac;
begin
  LGen := TPoly1305KeyGenerator.Create() as ICipherKeyGenerator;
  LRandom := TSecureRandom.Create();
  LParams := TKeyGenerationParameters.Create(LRandom, 256);
  LGen.Init(LParams);
  LKey := LGen.GenerateKey;

  SetLength(LM, 10000);
  SetLength(LCheck, 16);
  SetLength(LOutput, 16);

  LPoly := TPoly1305.Create(TAesUtilities.CreateEngine()) as IPoly1305;
  LPoly.Init(TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as ICipherParameters);

  // baseline
  LPoly.BlockUpdate(LM, 0, Length(LM));
  LPoly.DoFinal(LCheck, 0);

  // reset after doFinal
  LPoly.BlockUpdate(LM, 0, Length(LM));
  LPoly.DoFinal(LOutput, 0);
  CheckEqual('Poly1305 reset after doFinal #1', LCheck, LOutput);

  // Reset call
  LPoly.Update(Byte(1));
  LPoly.Update(Byte(2));
  LPoly.Reset;
  LPoly.BlockUpdate(LM, 0, Length(LM));
  LPoly.DoFinal(LOutput, 0);
  CheckEqual('Poly1305 reset after Reset', LCheck, LOutput);

  // Init resets
  LPoly.Update(Byte(1));
  LPoly.Update(Byte(2));
  LPoly.Init(TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as ICipherParameters);
  LPoly.BlockUpdate(LM, 0, Length(LM));
  LPoly.DoFinal(LOutput, 0);
  CheckEqual('Poly1305 reset after Init', LCheck, LOutput);
end;

procedure TTestPoly1305.TestBlockUpdateOneShotVsChunked;
const
  CKeyHex =
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  CChunk: array[0..4] of Int32 = (1, 5, 16, 32, 13);
  CLen: array[0..12] of Int32 =
    (0, 1, 15, 16, 17, 31, 32, 33, 255, 256, 257, 512, 2048);
var
  LKey, LMsg, T1, T2: TBytes;
  LM1, LM2: IMac;
  I, LLen, LPos, LPart, LCi: Int32;
  LSeed: UInt32;
begin
  LKey := THexEncoder.Decode(CKeyHex);
  for I := 0 to High(CLen) do
  begin
    LLen := CLen[I];
    SetLength(LMsg, LLen);
    LSeed := UInt32(2463534242 + (UInt32(LLen) * 17));
    for LPos := 0 to LLen - 1 do
    begin
      LSeed := LSeed * 1664525 + 1013904223;
      LMsg[LPos] := Byte(LSeed shr 17);
    end;
    LM1 := TPoly1305.Create();
    LM1.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    LM1.BlockUpdate(LMsg, 0, LLen);
    SetLength(T1, 16);
    LM1.DoFinal(T1, 0);
    LM2 := TPoly1305.Create();
    LM2.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    LPos := 0;
    LCi := 0;
    while LPos < LLen do
    begin
      LPart := CChunk[LCi mod (High(CChunk) + 1)];
      if LPos + LPart > LLen then
        LPart := LLen - LPos;
      LM2.BlockUpdate(LMsg, LPos, LPart);
      LPos := LPos + LPart;
      System.Inc(LCi);
    end;
    SetLength(T2, 16);
    LM2.DoFinal(T2, 0);
    CheckEqual(Format('Poly1305 one-shot vs chunked, len %d', [LLen]), T1, T2);
  end;
end;

procedure TTestPoly1305.TestLcgMessageBulkLengths;
const
  CKeyHex =
    '0f0e0d0c0b0a09080706050403020100' +
    '1f1e1d1c1b1a19181716151413121110';
  CChunk: array[0..4] of Int32 = (1, 5, 16, 32, 100);
  CSize: array[0..3] of Int32 = (240, 4000, 8000, 17 * 16);
var
  LKey, LMsg, T1, T2: TBytes;
  LM1, LM2: IMac;
  S, I, P, LPart, LCi: Int32;
  LSeed: UInt32;
begin
  LKey := THexEncoder.Decode(CKeyHex);
  for S := 0 to High(CSize) do
  begin
    SetLength(LMsg, CSize[S]);
    LSeed := UInt32(2654435761) xor UInt32(CSize[S] * 1315423911);
    for I := 0 to CSize[S] - 1 do
    begin
      LSeed := LSeed * 1103515245 + 12345;
      LMsg[I] := Byte((LSeed shr 16) xor (LSeed shr 24));
    end;
    LM1 := TPoly1305.Create();
    LM1.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    LM1.BlockUpdate(LMsg, 0, CSize[S]);
    SetLength(T1, 16);
    LM1.DoFinal(T1, 0);
    LM2 := TPoly1305.Create();
    LM2.Init(TKeyParameter.Create(LKey) as IKeyParameter);
    P := 0;
    LCi := 0;
    while P < CSize[S] do
    begin
      LPart := CChunk[LCi mod (High(CChunk) + 1)];
      if P + LPart > CSize[S] then
        LPart := CSize[S] - P;
      LM2.BlockUpdate(LMsg, P, LPart);
      P := P + LPart;
      System.Inc(LCi);
    end;
    SetLength(T2, 16);
    LM2.DoFinal(T2, 0);
    CheckEqual(Format('Poly1305 bulk LCG one vs chunked, %d B', [CSize[S]]), T1, T2);
  end;
end;

procedure TTestPoly1305.TestRfc7539Vectors;
var
  LKeyMaterial, LData, LExpected: TBytes;
begin
  // From RFC 7539 - Vector #1
  LKeyMaterial := THexEncoder.Decode(
    '85d6be7857556d337f4452fe42d506a8' +
    '0103808afb0db2fd4abff6af4149f51b');
  LData := THexEncoder.Decode(
    '43727970746f67726170686963' +
    '20466f72756d2052657365617263682047726f7570');
  LExpected := THexEncoder.Decode('a8061dc1305136c6c22b8baf0c0127a9');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 - Vector #2
  LData := THexEncoder.Decode('48656c6c6f20776f726c6421');
  LKeyMaterial := THexEncoder.Decode(
    '746869732069732033322d6279746520' +
    '6b657920666f7220506f6c7931333035');
  LExpected := THexEncoder.Decode('a6f745008f81c916a20dcc74eef2b2f0');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #1
  LKeyMaterial := THexEncoder.Decode(
    '00000000000000000000000000000000' +
    '00000000000000000000000000000000');
  LData := THexEncoder.Decode(
    '00000000000000000000000000000000' +
    '00000000000000000000000000000000' +
    '00000000000000000000000000000000' +
    '00000000000000000000000000000000');
  LExpected := THexEncoder.Decode('00000000000000000000000000000000');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #2
  LKeyMaterial := THexEncoder.Decode(
    '00000000000000000000000000000000' +
    '36e5f6b5c5e06070f0efca96227a863e');
  LData := THexEncoder.Decode(
    '416e79207375626d697373696f6e2074' +
    '6f20746865204945544620696e74656e' +
    '6465642062792074686520436f6e7472' +
    '696275746f7220666f72207075626c69' +
    '636174696f6e20617320616c6c206f72' +
    '2070617274206f6620616e2049455446' +
    '20496e7465726e65742d447261667420' +
    '6f722052464320616e6420616e792073' +
    '746174656d656e74206d616465207769' +
    '7468696e2074686520636f6e74657874' +
    '206f6620616e20494554462061637469' +
    '7669747920697320636f6e7369646572' +
    '656420616e20224945544620436f6e74' +
    '7269627574696f6e222e205375636820' +
    '73746174656d656e747320696e636c'   +
    '756465206f72616c2073746174656d65' +
    '6e747320696e20494554462073657373' +
    '696f6e732c2061732077656c6c206173' +
    '207772697474656e20616e6420656c65' +
    '6374726f6e696320636f6d6d756e6963' +
    '6174696f6e73206d6164652061742061' +
    '6e792074696d65206f7220706c616365' +
    '2c207768696368206172652061646472' +
    '657373656420746f');
  LExpected := THexEncoder.Decode('36e5f6b5c5e06070f0efca96227a863e');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #3
  LKeyMaterial := THexEncoder.Decode(
    '36e5f6b5c5e06070f0efca96227a863e' +
    '00000000000000000000000000000000');
  LExpected := THexEncoder.Decode('f3477e7cd95417af89a6b8794c310cf0');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #4
  LKeyMaterial := THexEncoder.Decode(
    '1c9240a5eb55d38af333888604f6b5f0' +
    '473917c1402b80099dca5cbc207075c0');
  LData := THexEncoder.Decode(
    '2754776173206272696c6c69672c2061' +
    '6e642074686520736c6974687920746f' +
    '7665730a446964206779726520616e64' +
    '2067696d626c6520696e207468652077' +
    '6162653a0a416c6c206d696d73792077' +
    '6572652074686520626f726f676f7665' +
    '732c0a416e6420746865206d6f6d6520' +
    '7261746873206f757467726162652e');
  LExpected := THexEncoder.Decode('4541669a7eaaee61e708dc7cbcc5eb62');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #5
  LKeyMaterial := THexEncoder.Decode(
    '02000000000000000000000000000000' +
    '00000000000000000000000000000000');
  LData := THexEncoder.Decode('ffffffffffffffffffffffffffffffff');
  LExpected := THexEncoder.Decode('03000000000000000000000000000000');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #6
  LKeyMaterial := THexEncoder.Decode(
    '02000000000000000000000000000000' +
    'ffffffffffffffffffffffffffffffff');
  LData := THexEncoder.Decode('02000000000000000000000000000000');
  LExpected := THexEncoder.Decode('03000000000000000000000000000000');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #7
  LKeyMaterial := THexEncoder.Decode(
    '01000000000000000000000000000000' +
    '00000000000000000000000000000000');
  LData := THexEncoder.Decode(
    'ffffffffffffffffffffffffffffffff' +
    'f0ffffffffffffffffffffffffffffff' +
    '11000000000000000000000000000000');
  LExpected := THexEncoder.Decode('05000000000000000000000000000000');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #8
  LKeyMaterial := THexEncoder.Decode(
    '01000000000000000000000000000000' +
    '00000000000000000000000000000000');
  LData := THexEncoder.Decode(
    'ffffffffffffffffffffffffffffffff' +
    'fbfefefefefefefefefefefefefefefe' +
    '01010101010101010101010101010101');
  LExpected := THexEncoder.Decode('00000000000000000000000000000000');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #9
  LKeyMaterial := THexEncoder.Decode(
    '02000000000000000000000000000000' +
    '00000000000000000000000000000000');
  LData := THexEncoder.Decode('fdffffffffffffffffffffffffffffff');
  LExpected := THexEncoder.Decode('faffffffffffffffffffffffffffffff');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #10
  LKeyMaterial := THexEncoder.Decode(
    '01000000000000000400000000000000' +
    '00000000000000000000000000000000');
  LData := THexEncoder.Decode(
    'e33594d7505e43b90000000000000000' +
    '3394d7505e4379cd0100000000000000' +
    '00000000000000000000000000000000' +
    '01000000000000000000000000000000');
  LExpected := THexEncoder.Decode('14000000000000005500000000000000');
  CheckVector(LKeyMaterial, LData, LExpected);

  // RFC 7539 A.3 #11
  LKeyMaterial := THexEncoder.Decode(
    '01000000000000000400000000000000' +
    '00000000000000000000000000000000');
  LData := THexEncoder.Decode(
    'e33594d7505e43b90000000000000000' +
    '3394d7505e4379cd0100000000000000' +
    '00000000000000000000000000000000');
  LExpected := THexEncoder.Decode('13000000000000000000000000000000');
  CheckVector(LKeyMaterial, LData, LExpected);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPoly1305);
{$ELSE}
  RegisterTest(TTestPoly1305.Suite);
{$ENDIF FPC}

end.

