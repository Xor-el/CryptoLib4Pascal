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

unit ChaCha20Poly1305Tests;

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
  ClpIChaCha20Poly1305,
  ClpChaCha20Poly1305,
  ClpIMac,
  ClpMacUtilities,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpAeadParameters,
  ClpIAeadParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpDateTimeUtilities,
  ClpCryptoLibExceptions,
  AeadTestUtilities,
  ClpEncoders,
  ClpConverters,
  CryptoLibTestBase,
  ChaChaPoly1305Vectors;

type

  TTestChaCha20Poly1305 = class(TCryptoLibAlgorithmTestCase)
  strict private
    function InitCipher(AForEncryption: Boolean;
      const AParams: IAeadParameters): IChaCha20Poly1305;

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestVector1;
    procedure TestOutputSizes;
    procedure TestRandomised;
    procedure TestExceptionsAndTampering;
    procedure TestAeadInputChunking;

  end;

implementation

{ TTestChaCha20Poly1305 }

function TTestChaCha20Poly1305.InitCipher(AForEncryption: Boolean;
  const AParams: IAeadParameters): IChaCha20Poly1305;
var
  LCipher: IChaCha20Poly1305;
begin
  LCipher := TChaCha20Poly1305.Create() as IChaCha20Poly1305;
  LCipher.Init(AForEncryption, AParams as ICipherParameters);
  Result := LCipher;
end;

procedure TTestChaCha20Poly1305.SetUp;
begin
  inherited;
end;

procedure TTestChaCha20Poly1305.TearDown;
begin
  inherited;
end;

procedure TTestChaCha20Poly1305.TestVector1;
var
  LRow: TChaChaAeadRow;
  LK, LP, LA, LN, LC, LT, LEnc, LMac, LPlain: TBytes;
  LParams: IAeadParameters;
  LEncCipher, LDecCipher: IChaCha20Poly1305;
  LLen: Int32;
begin
  LRow := TChaChaVectors.GetRfc7539Poly1305Rows[0];
  LK := DecodeHex(LRow.Key);
  LP := DecodeHex(LRow.Plaintext);
  LA := DecodeHex(LRow.Aad);
  LN := DecodeHex(LRow.Nonce);
  LC := DecodeHex(LRow.Ciphertext);
  LT := DecodeHex(LRow.Tag);

  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    Length(LT) * 8, LN, LA);

  // encryption
  LEncCipher := InitCipher(True, LParams);
  SetLength(LEnc, LEncCipher.GetOutputSize(Length(LP)));
  LLen := LEncCipher.ProcessBytes(LP, 0, Length(LP), LEnc, 0);
  LEncCipher.DoFinal(LEnc, LLen);

  // ciphertext
  CheckEqual('ChaCha20Poly1305 Vector1 Ciphertext', LC,
    CopyOfRange(LEnc, 0, Length(LC)));

  // tag
  LMac := LEncCipher.GetMac;
  CheckEqual('ChaCha20Poly1305 Vector1 Tag', LT, LMac);

  // decryption
  LDecCipher := InitCipher(False, LParams);
  SetLength(LPlain, LDecCipher.GetOutputSize(Length(LEnc)));
  LLen := LDecCipher.ProcessBytes(LEnc, 0, Length(LEnc), LPlain, 0);
  LDecCipher.DoFinal(LPlain, LLen);

  CheckEqual('ChaCha20Poly1305 Vector1 Plaintext', LP,
    CopyOfRange(LPlain, 0, Length(LP)));
end;

procedure TTestChaCha20Poly1305.TestOutputSizes;
var
  LK, LN: TBytes;
  LParams: IAeadParameters;
  LCipher: IChaCha20Poly1305;
begin
  SetLength(LK, 32);
  SetLength(LN, 12);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LN, nil);

  LCipher := InitCipher(True, LParams);

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

procedure TTestChaCha20Poly1305.TestRandomised;
var
  LRandom: ISecureRandom;
  LI: Int32;
  LK: TBytes;
  LP, LA, LSA, LNonce, LEnc, LDec, LEncTag, LDecTag: TBytes;
  LParams: IAeadParameters;
  LCipher: IChaCha20Poly1305;
  LSaLen, LSplit, LLen, LPHead, LPLen, LPTail, LBody, LHead, LTail,
    LPredicted, LCtLen: Int32;
begin
  LRandom := TSecureRandom.Create();
  LRandom.SetSeed(TDateTimeUtilities.CurrentUnixMs);

  for LI := 0 to 99 do
  begin
    SetLength(LK, 32);
    LRandom.NextBytes(LK);

    LHead := LRandom.Next(256);
    LBody := LRandom.Next(65536);
    LTail := LRandom.Next(256);
    SetLength(LP, LHead + LBody + LTail);
    LRandom.NextBytes(LP);

    SetLength(LA, LRandom.Next(256));
    LRandom.NextBytes(LA);

    LSaLen := LRandom.Next(256);
    SetLength(LSA, LSaLen);
    LRandom.NextBytes(LSA);

    SetLength(LNonce, 12);
    LRandom.NextBytes(LNonce);

    LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
      16 * 8, LNonce, LA);

    LCipher := InitCipher(True, LParams);
    LCtLen := LCipher.GetOutputSize(LBody);
    SetLength(LEnc, LSaLen + LCtLen);
    if LSaLen > 0 then
    begin
      System.Move(LSA[0], LEnc[0], LSaLen);
    end;

    LSplit := TAeadTestUtilities.NextInt32(LRandom, LSaLen + 1);
    LCipher.ProcessAadBytes(LEnc, 0, LSplit);
    LCipher.ProcessAadBytes(LEnc, LSplit, LSaLen - LSplit);

    LPredicted := LCipher.GetUpdateOutputSize(LBody);
    LLen := LCipher.ProcessBytes(LP, LHead, LBody, LEnc, LSaLen);
    if LPredicted <> LLen then
    begin
      Fail('encryption reported incorrect update length in randomised test');
    end;
    LLen := LLen + LCipher.DoFinal(LEnc, LSaLen + LLen);

    if LCtLen <> LLen then
    begin
      Fail('encryption reported incorrect length in randomised test');
    end;

    LEncTag := LCipher.GetMac;

    // check that the tag in the stream matches GetMac()
    CheckEqual('ChaCha20Poly1305 random stream tag',
      LEncTag, CopyOfRange(LEnc, LSaLen + LBody, LSaLen + LCtLen));

    // decrypt
    LCipher.Init(False, LParams as ICipherParameters);
    LPHead := LRandom.Next(256);
    LPLen := LCipher.GetOutputSize(LCtLen);
    LPTail := LRandom.Next(256);
    SetLength(LDec, LPHead + LPLen + LPTail);

    LSplit := TAeadTestUtilities.NextInt32(LRandom, LSaLen + 1);
    LCipher.ProcessAadBytes(LEnc, 0, LSplit);
    LCipher.ProcessAadBytes(LEnc, LSplit, LSaLen - LSplit);

    LPredicted := LCipher.GetUpdateOutputSize(LCtLen);
    LLen := LCipher.ProcessBytes(LEnc, LSaLen, LCtLen, LDec, LPHead);
    if LPredicted <> LLen then
    begin
      Fail('decryption reported incorrect update length in randomised test');
    end;
    LCipher.DoFinal(LDec, LPHead + LLen);

    CheckEqual('ChaCha20Poly1305 random plaintext',
      CopyOfRange(LP, LHead, LHead + LBody),
      CopyOfRange(LDec, LPHead, LPHead + LPLen));

    LDecTag := LCipher.GetMac;
    CheckEqual('ChaCha20Poly1305 random tag', LEncTag, LDecTag);

    // key reuse test (decrypt with parameters that reuse the key)
    LCipher.Init(False,
      TAeadTestUtilities.ReuseKey(LParams) as ICipherParameters);

    LPHead := LRandom.Next(256);
    LPLen := LCipher.GetOutputSize(LCtLen);
    LPTail := LRandom.Next(256);
    SetLength(LDec, LPHead + LPLen + LPTail);

    LSplit := TAeadTestUtilities.NextInt32(LRandom, LSaLen + 1);
    LCipher.ProcessAadBytes(LEnc, 0, LSplit);
    LCipher.ProcessAadBytes(LEnc, LSplit, LSaLen - LSplit);

    LLen := LCipher.ProcessBytes(LEnc, LSaLen, LCtLen, LDec, LPHead);
    LCipher.DoFinal(LDec, LPHead + LLen);

    CheckEqual('ChaCha20Poly1305 random plaintext (key reuse)',
      CopyOfRange(LP, LHead, LHead + LBody),
      CopyOfRange(LDec, LPHead, LPHead + LPLen));

    LDecTag := LCipher.GetMac;
    CheckEqual('ChaCha20Poly1305 random tag (key reuse)', LEncTag, LDecTag);
  end;
end;

procedure TTestChaCha20Poly1305.TestAeadInputChunking;
var
  LK, LN, LA, LPlain: TBytes;
  LParams: IAeadParameters;
  C1, C2: IChaCha20Poly1305;
  LO1, LO2: TBytes;
  I, LTot, P: Int32;
  LSeed: UInt32;
begin
  LK := THexEncoder.Decode(
    '9a0a4bed901cf51f1ec22db74ac7cb70' +
    'd4ebc12e4d18f69ccd46e0c0d060de45');
  LN := THexEncoder.Decode('0c0b0a090807060504030201');
  LA := THexEncoder.Decode('0201000306050407');
  SetLength(LPlain, 600);
  LSeed := $C0FEBEEF;
  for I := 0 to 599 do
  begin
    LSeed := LSeed * 1664525 + 1013904223;
    LPlain[I] := Byte(LSeed shr 9);
  end;
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LN, LA);
  C1 := InitCipher(True, LParams);
  LTot := C1.GetOutputSize(600);
  SetLength(LO1, LTot);
  P := C1.ProcessBytes(LPlain, 0, 600, LO1, 0);
  P := P + C1.DoFinal(LO1, P);
  if P <> LTot then
    Fail('one-shot ChaCha20-Poly1305 output size');
  C2 := InitCipher(True, LParams);
  SetLength(LO2, LTot);
  P := C2.ProcessBytes(LPlain, 0, 1, LO2, 0);
  P := P + C2.ProcessBytes(LPlain, 1, 255, LO2, P);
  P := P + C2.ProcessBytes(LPlain, 256, 256, LO2, P);
  P := P + C2.ProcessBytes(LPlain, 512, 88, LO2, P);
  P := P + C2.DoFinal(LO2, P);
  if P <> LTot then
    Fail('chunked ChaCha20-Poly1305 output size');
  CheckEqual('ChaCha20Poly1305 ciphertag 600B one vs chunks', LO1, LO2);
  CheckEqual('ChaCha20Poly1305 tag one vs chunks', C1.GetMac, C2.GetMac);
end;

procedure TTestChaCha20Poly1305.TestExceptionsAndTampering;
var
  LCipher: IChaCha20Poly1305;
  LBadMac: IMac;
  LK, LN, LP, LBuf: TBytes;
  LParams: IAeadParameters;
begin
  // incorrect MAC size on construction
  try
    LBadMac := TMacUtilities.GetMac('SIPHASH');
    LCipher := TChaCha20Poly1305.Create(LBadMac);
    Fail('incorrect mac size not picked up');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  // illegal parameter: KeyParameter only instead of AeadParameters
  LCipher := TChaCha20Poly1305.Create();
  try
    LCipher.Init(False,
      TKeyParameter.Create(TBytes.Create(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)) as IKeyParameter);
    Fail('illegal argument not picked up');
  except
    on E: EArgumentCryptoLibException do
    begin
      // expected
    end;
  end;

  // tampering tests via shared AEAD utilities
  SetLength(LK, 32);
  SetLength(LN, 12);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    128, LN, nil);
  TAeadTestUtilities.TestTampering('ChaCha20Poly1305', LCipher as IAeadCipher,
    LParams as ICipherParameters);

  // DoFinal reuse checks (encryption)
  LP := TConverters.ConvertStringToBytes('Hello world!', TEncoding.ANSI);
  SetLength(LBuf, 100);

  LCipher := TChaCha20Poly1305.Create();
  LCipher.Init(True, LParams as ICipherParameters);
  LCipher.ProcessBytes(LP, 0, Length(LP), LBuf, 0);
  LCipher.DoFinal(LBuf, 0);

  try
    LCipher.DoFinal(LBuf, 0);
    Fail('no exception on reuse');
  except
    on E: EInvalidOperationCryptoLibException do
    begin
      // expected and message must match the engine resources
      if not (E.Message = 'ChaCha20Poly1305 cannot be reused for encryption') then
      begin
        Fail('wrong message on reuse after DoFinal');
      end;
    end;
  end;

  // nonce reuse for encryption via parameters that reuse key and nonce
  try
    LCipher.Init(True,
      TAeadTestUtilities.ReuseKey(LParams) as ICipherParameters);
    Fail('no exception on nonce reuse');
  except
    on E: EArgumentCryptoLibException do
    begin
      if not (E.Message = 'cannot reuse nonce for ChaCha20Poly1305 encryption') then
      begin
        Fail('wrong message on nonce reuse');
      end;
    end;
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestChaCha20Poly1305);
{$ELSE}
  RegisterTest(TTestChaCha20Poly1305.Suite);
{$ENDIF FPC}

end.

