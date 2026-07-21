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
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  ChaChaPoly1305Vectors;

type

  TTestPoly1305 = class(TCryptoLibAlgorithmTestCase)
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
  LRows: TCryptoLibGenericArray<TPoly1305NaClRow>;
  LRow: TPoly1305NaClRow;
  LKey, LNonce, LMessage, LExpectedMac: TBytes;
  LMac: IMac;
  LKeyParam: IKeyParameter;
  LParamsWithIv: IParametersWithIV;
  LOut: TBytes;
begin
  LRows := TPoly1305Vectors.GetNaClRows;
  LRow := LRows[ACaseIndex];
  LKey := THexEncoder.Decode(LRow.Key);
  if LRow.ClampKey then
    TPoly1305KeyGenerator.Clamp(LKey);
  if LRow.Nonce <> '' then
    LNonce := THexEncoder.Decode(LRow.Nonce)
  else
    LNonce := nil;
  LMessage := THexEncoder.Decode(LRow.Message);
  LExpectedMac := THexEncoder.Decode(LRow.ExpectedMac);

  if not LRow.UseAesNonce then
  begin
    LMac := TPoly1305.Create() as IPoly1305;
    LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;
    LMac.Init(LKeyParam);
  end
  else
  begin
    LMac := TPoly1305.Create(TAesUtilities.CreateEngine()) as IPoly1305;
    LParamsWithIv := TParametersWithIV.Create
      (TKeyParameter.Create(LKey) as IKeyParameter, LNonce);
    LMac.Init(LParamsWithIv as ICipherParameters);
  end;

  LMac.BlockUpdate(LMessage, 0, Length(LMessage));

  SetLength(LOut, LMac.GetMacSize);
  LMac.DoFinal(LOut, 0);

  CheckEqual(Format('Poly1305 case %d', [ACaseIndex]), LExpectedMac, LOut);
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
  LRows: TCryptoLibGenericArray<TPoly1305NaClRow>;
  LI: Int32;
begin
  LRows := TPoly1305Vectors.GetNaClRows;
  for LI := 0 to High(LRows) do
    RunCase(LI);
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
  LRows: TCryptoLibGenericArray<TPoly1305Rfc7539Row>;
  LRow: TPoly1305Rfc7539Row;
  LI: Int32;
begin
  LRows := TPoly1305Vectors.GetRfc7539Rows;
  for LI := 0 to High(LRows) do
  begin
    LRow := LRows[LI];
    CheckVector(THexEncoder.Decode(LRow.KeyMaterial),
      THexEncoder.Decode(LRow.Message), THexEncoder.Decode(LRow.ExpectedMac));
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestPoly1305);
{$ELSE}
  RegisterTest(TTestPoly1305.Suite);
{$ENDIF FPC}

end.

