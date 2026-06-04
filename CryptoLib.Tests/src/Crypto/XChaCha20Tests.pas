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

unit XChaCha20Tests;

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
  ClpXChaCha20Engine,
  ClpIXChaCha20Engine,
  ClpChaCha7539Engine,
  ClpIChaCha7539Engine,
  ClpIStreamCipher,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpEncoders,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  ChaChaPoly1305Vectors;

type
  TTestXChaCha20 = class(TCryptoLibAlgorithmTestCase)
  published
    procedure TestAppendixA2_1KeystreamFirst288;
    procedure TestAppendixA3_2_1KeystreamFull304;
    procedure TestAppendixA3_2_1CiphertextCounter0;
    procedure TestAppendixA3_2_2KeystreamFromBlockCounter1;
    procedure TestAppendixA3_2_2CiphertextCounter1;
    procedure TestGetCipherXChaCha20Aliases;
    procedure TestRoundTrip1024;
    procedure TestHChaCha20Indirect;
    procedure TestDraftStreamVector;
    procedure TestRandomRoundTrip;
    procedure TestChunkedProcessing;
    procedure TestRejectShortNonce64Bits;
    procedure TestRejectShortNonce96Bits;
    procedure TestRejectShortNonce23Bytes;
    procedure TestRejectInvalidKeySize;
  end;

implementation

{ TTestXChaCha20 }

procedure TTestXChaCha20.TestAppendixA2_1KeystreamFirst288;
var
  LRow: TXChaChaStreamRow;
  LKey, LIv, LZero, LExpectedKs, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  LRow := TChaChaVectors.GetXChaChaStreamRow('AppendixA2_1');
  LKey := THexEncoder.Decode(LRow.Key);
  LIv := THexEncoder.Decode(LRow.Nonce);
  LExpectedKs := THexEncoder.Decode(LRow.ExpectedHex);
  System.SetLength(LZero, System.Length(LExpectedKs));
  System.FillChar(LZero[0], System.Length(LZero), 0);
  System.SetLength(LOut, System.Length(LExpectedKs));

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LZero, 0, System.Length(LZero), LOut, 0);

  if not AreEqual(LExpectedKs, LOut) then
    Fail(Format('XChaCha20 A.2.1 keystream mismatch: expected %s got %s',
      [EncodeHex(LExpectedKs), EncodeHex(LOut)]));
end;

procedure TTestXChaCha20.TestAppendixA3_2_1KeystreamFull304;
var
  LRow: TXChaChaStreamRow;
  LKey, LIv, LZero, LExpectedKs, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha Appendix A.3.2.1 - full 19 x 16 B keystream (counter 0). }
  LRow := TChaChaVectors.GetXChaChaStreamRow('AppendixA3_2_1_Keystream');
  LKey := THexEncoder.Decode(LRow.Key);
  LIv := THexEncoder.Decode(LRow.Nonce);
  LExpectedKs := THexEncoder.Decode(LRow.ExpectedHex);
  if System.Length(LExpectedKs) <> 304 then
    Fail('internal: expected 304-byte keystream constant');
  System.SetLength(LZero, 304);
  System.FillChar(LZero[0], 304, 0);
  System.SetLength(LOut, 304);

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LZero, 0, 304, LOut, 0);
  if not AreEqual(LExpectedKs, LOut) then
    Fail(Format('XChaCha20 A.3.2.1 full keystream mismatch: expected %s got %s',
      [EncodeHex(LExpectedKs), EncodeHex(LOut)]));
end;

procedure TTestXChaCha20.TestAppendixA3_2_1CiphertextCounter0;
var
  LRow: TXChaChaStreamRow;
  LKey, LIv, LPlain, LExpectedCt, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha Appendix A.3.2.1 ciphertext (same key/IV as A.3.2.1). }
  LRow := TChaChaVectors.GetXChaChaStreamRow('AppendixA3_2_1_Ciphertext');
  LKey := THexEncoder.Decode(LRow.Key);
  LIv := THexEncoder.Decode(LRow.Nonce);
  LPlain := THexEncoder.Decode(LRow.Plaintext);
  LExpectedCt := THexEncoder.Decode(LRow.ExpectedHex);
  System.SetLength(LOut, System.Length(LPlain));
  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LPlain, 0, System.Length(LPlain), LOut, 0);
  if not AreEqual(LExpectedCt, LOut) then
    Fail(Format('XChaCha20 A.3.2.1 ciphertext mismatch: expected %s got %s',
      [EncodeHex(LExpectedCt), EncodeHex(LOut)]));
end;

procedure TTestXChaCha20.TestAppendixA3_2_2KeystreamFromBlockCounter1;
var
  LRow: TXChaChaStreamRow;
  LKey, LIv, LZero, LBurn, LExpectedKs, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha A.3.2.2 - keystream with block counter 1 (skip first 64 B). }
  LRow := TChaChaVectors.GetXChaChaStreamRow('AppendixA3_2_2_Keystream');
  LKey := THexEncoder.Decode(LRow.Key);
  LIv := THexEncoder.Decode(LRow.Nonce);
  LExpectedKs := THexEncoder.Decode(LRow.ExpectedHex);
  System.SetLength(LBurn, LRow.SkipBytes);
  System.FillChar(LBurn[0], LRow.SkipBytes, 0);
  System.SetLength(LZero, System.Length(LExpectedKs));
  System.FillChar(LZero[0], System.Length(LZero), 0);
  System.SetLength(LOut, System.Length(LExpectedKs));

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  if LRow.SkipBytes > 0 then
    LEng.ProcessBytes(LBurn, 0, LRow.SkipBytes, LBurn, 0);
  LEng.ProcessBytes(LZero, 0, System.Length(LZero), LOut, 0);
  if not AreEqual(LExpectedKs, LOut) then
    Fail(Format('XChaCha20 A.3.2.2 keystream mismatch: expected %s got %s',
      [EncodeHex(LExpectedKs), EncodeHex(LOut)]));
end;

procedure TTestXChaCha20.TestAppendixA3_2_2CiphertextCounter1;
var
  LRow: TXChaChaStreamRow;
  LKey, LIv, LPlain, LBurn, LExpectedCt, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha A.3.2.2 ciphertext with block counter starting at 1. }
  LRow := TChaChaVectors.GetXChaChaStreamRow('AppendixA3_2_2_Ciphertext');
  LKey := THexEncoder.Decode(LRow.Key);
  LIv := THexEncoder.Decode(LRow.Nonce);
  LPlain := THexEncoder.Decode(LRow.Plaintext);
  LExpectedCt := THexEncoder.Decode(LRow.ExpectedHex);
  System.SetLength(LBurn, LRow.SkipBytes);
  System.FillChar(LBurn[0], LRow.SkipBytes, 0);
  System.SetLength(LOut, System.Length(LPlain));

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  if LRow.SkipBytes > 0 then
    LEng.ProcessBytes(LBurn, 0, LRow.SkipBytes, LBurn, 0);
  LEng.ProcessBytes(LPlain, 0, System.Length(LPlain), LOut, 0);
  if not AreEqual(LExpectedCt, LOut) then
    Fail(Format('XChaCha20 A.3.2.2 ciphertext mismatch: expected %s got %s',
      [EncodeHex(LExpectedCt), EncodeHex(LOut)]));
end;

procedure TTestXChaCha20.TestGetCipherXChaCha20Aliases;
var
  LCipher: IBufferedCipher;
begin
  LCipher := TCipherUtilities.GetCipher('XCHACHA20');
  if LCipher = nil then
    Fail('TCipherUtilities.GetCipher(XCHACHA20) returned nil');
  LCipher := TCipherUtilities.GetCipher('XChaCha20');
  if LCipher = nil then
    Fail('TCipherUtilities.GetCipher(XChaCha20) returned nil');
end;

procedure TTestXChaCha20.TestRoundTrip1024;
var
  LKey, LIv, LPlain, LCipher, LRecovered: TCryptoLibByteArray;
  LEnc, LDec: IXChaCha20Engine;
  LIdx: Int32;
  LParams: IParametersWithIV;
begin
  LKey := THexEncoder.Decode(
    '0001020304050607080910111213141516171819202122232425262728293031');
  LIv := THexEncoder.Decode('000102030405060708090a0b0c0d0e0f1011121314151617');

  System.SetLength(LPlain, 1024);
  for LIdx := 0 to 1023 do
    LPlain[LIdx] := Byte(LIdx and $FF);

  LEnc := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEnc.Init(True, LParams);
  System.SetLength(LCipher, 1024);
  LEnc.ProcessBytes(LPlain, 0, 1024, LCipher, 0);

  LDec := TXChaCha20Engine.Create;
  LDec.Init(False, LParams);
  System.SetLength(LRecovered, 1024);
  LDec.ProcessBytes(LCipher, 0, 1024, LRecovered, 0);

  if AreEqual(LPlain, LCipher) then
    Fail('XChaCha20 produced no keystream XOR (plain equals cipher)');
  if not AreEqual(LPlain, LRecovered) then
    Fail(Format('XChaCha20 round-trip mismatch: recovered %s',
      [EncodeHex(LRecovered)]));
end;

procedure TTestXChaCha20.TestRejectShortNonce64Bits;
var
  LKey, LIv8: TCryptoLibByteArray;
  LEngine: IXChaCha20Engine;
begin
  System.SetLength(LKey, 32);
  System.SetLength(LIv8, 8);
  System.FillChar(LIv8[0], 8, 0);
  try
    LEngine := TXChaCha20Engine.Create;
    LEngine.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LKey)
      as IKeyParameter, LIv8));
    Fail('XChaCha20 unexpectedly accepted an 8-byte nonce');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TTestXChaCha20.TestRejectShortNonce96Bits;
var
  LKey: TCryptoLibByteArray;
  LEngine: IXChaCha20Engine;
  LNonce12: TCryptoLibByteArray;
begin
  System.SetLength(LKey, 32);
  System.SetLength(LNonce12, 12);
  try
    LEngine := TXChaCha20Engine.Create;
    LEngine.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LKey)
      as IKeyParameter, LNonce12));
    Fail('XChaCha20 unexpectedly accepted a 12-byte nonce');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TTestXChaCha20.TestHChaCha20Indirect;
var
  LRow: TXChaChaStreamRow;
  LKey, LHNonce, LSubKey, LXNonce, LZeros, LStreamX, LStreamC: TCryptoLibByteArray;
  LXEng: IXChaCha20Engine;
  LCEng: IChaCha7539Engine;
  LXParams, LCParams: IParametersWithIV;
  LInnerNonce: TCryptoLibByteArray;
begin
  LRow := TChaChaVectors.GetXChaChaStreamRow('HChaChaSubkey');
  LKey := THexEncoder.Decode(LRow.Key);
  LHNonce := THexEncoder.Decode(LRow.Nonce);
  LSubKey := THexEncoder.Decode(LRow.ExpectedHex);
  System.SetLength(LXNonce, 24);
  System.Move(LHNonce[0], LXNonce[0], 16);
  System.FillChar(LXNonce[16], 8, 0);

  System.SetLength(LZeros, 256);
  System.FillChar(LZeros[0], 256, 0);
  System.SetLength(LStreamX, 256);
  System.SetLength(LStreamC, 256);

  LXEng := TXChaCha20Engine.Create;
  LXParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LXNonce);
  LXEng.Init(True, LXParams);
  LXEng.ProcessBytes(LZeros, 0, 256, LStreamX, 0);

  System.SetLength(LInnerNonce, 12);
  System.FillChar(LInnerNonce[0], 12, 0);
  LCEng := TChaCha7539Engine.Create;
  LCParams := TParametersWithIV.Create(TKeyParameter.Create(LSubKey) as IKeyParameter,
    LInnerNonce);
  LCEng.Init(True, LCParams);
  LCEng.ProcessBytes(LZeros, 0, 256, LStreamC, 0);

  if not AreEqual(LStreamX, LStreamC) then
    Fail('HChaCha20 subkey derivation does not match draft test vector');
end;

procedure TTestXChaCha20.TestDraftStreamVector;
var
  LRow: TXChaChaStreamRow;
  LKey, LNonce, LPlain, LExpectedCipher, LInput, LOutput, LActualCipher,
    LRoundTrip: TCryptoLibByteArray;
  LEng, LDecEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  LRow := TChaChaVectors.GetXChaChaStreamRow('DraftStreamVector');
  LKey := THexEncoder.Decode(LRow.Key);
  LNonce := THexEncoder.Decode(LRow.Nonce);
  LPlain := THexEncoder.Decode(LRow.Plaintext);
  LExpectedCipher := THexEncoder.Decode(LRow.ExpectedHex);

  System.SetLength(LInput, LRow.SkipBytes + System.Length(LPlain));
  System.FillChar(LInput[0], LRow.SkipBytes, 0);
  System.Move(LPlain[0], LInput[LRow.SkipBytes], System.Length(LPlain));
  System.SetLength(LOutput, System.Length(LInput));

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LNonce);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LInput, 0, System.Length(LInput), LOutput, 0);

  System.SetLength(LActualCipher, System.Length(LExpectedCipher));
  System.Move(LOutput[LRow.SkipBytes], LActualCipher[0], System.Length(LExpectedCipher));
  if not AreEqual(LExpectedCipher, LActualCipher) then
    Fail(Format('XChaCha20 keystream does not match draft AEAD vector: expected %s got %s',
      [EncodeHex(LExpectedCipher), EncodeHex(LActualCipher)]));

  System.SetLength(LRoundTrip, System.Length(LOutput));
  LDecEng := TXChaCha20Engine.Create;
  LDecEng.Init(False, LParams);
  LDecEng.ProcessBytes(LOutput, 0, System.Length(LOutput), LRoundTrip, 0);
  if not AreEqual(LInput, LRoundTrip) then
    Fail('XChaCha20 round-trip mismatch on draft stream vector');
end;

procedure TTestXChaCha20.TestRandomRoundTrip;
var
  LRandom: ISecureRandom;
  LI, LLen: Int32;
  LKey, LNonce, LPlain, LCipher, LBack: TCryptoLibByteArray;
  LEnc, LDec: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  LRandom := TSecureRandom.Create;
  for LI := 0 to 49 do
  begin
    System.SetLength(LKey, 32);
    LRandom.NextBytes(LKey);
    System.SetLength(LNonce, 24);
    LRandom.NextBytes(LNonce);
    LLen := LRandom.Next(1, 8192);
    System.SetLength(LPlain, LLen);
    if LLen > 0 then
      LRandom.NextBytes(LPlain);

    System.SetLength(LCipher, LLen);
    LEnc := TXChaCha20Engine.Create;
    LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
      LNonce);
    LEnc.Init(True, LParams);
    if LLen > 0 then
      LEnc.ProcessBytes(LPlain, 0, LLen, LCipher, 0);

    System.SetLength(LBack, LLen);
    LDec := TXChaCha20Engine.Create;
    LDec.Init(False, LParams);
    if LLen > 0 then
      LDec.ProcessBytes(LCipher, 0, LLen, LBack, 0);

    if not AreEqual(LPlain, LBack) then
      Fail(Format('XChaCha20 randomized round-trip failed at length %d', [LLen]));
  end;
end;

procedure TTestXChaCha20.TestChunkedProcessing;
const
  ChunkSizes: array[0..8] of Int32 = (1, 7, 32, 63, 64, 65, 127, 128, 129);
var
  LKey, LNonce, LPlain, LWhole, LPiecewise: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
  LRandom: ISecureRandom;
  LI, LChunk, LOff, LN: Int32;
begin
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LNonce := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555657');
  System.SetLength(LPlain, 1024);
  LRandom := TSecureRandom.Create;
  LRandom.NextBytes(LPlain);

  System.SetLength(LWhole, System.Length(LPlain));
  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LNonce);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LPlain, 0, System.Length(LPlain), LWhole, 0);

  for LI := Low(ChunkSizes) to High(ChunkSizes) do
  begin
    LChunk := ChunkSizes[LI];
    System.SetLength(LPiecewise, System.Length(LPlain));
    LEng := TXChaCha20Engine.Create;
    LEng.Init(True, LParams);
    LOff := 0;
    while LOff < System.Length(LPlain) do
    begin
      LN := LChunk;
      if LN > System.Length(LPlain) - LOff then
        LN := System.Length(LPlain) - LOff;
      LEng.ProcessBytes(LPlain, LOff, LN, LPiecewise, LOff);
      System.Inc(LOff, LN);
    end;
    if not AreEqual(LWhole, LPiecewise) then
      Fail(Format('chunked processing differs from bulk at chunk size %d', [LChunk]));
  end;
end;

procedure TTestXChaCha20.TestRejectShortNonce23Bytes;
var
  LKey, LNonce23: TCryptoLibByteArray;
  LEngine: IXChaCha20Engine;
begin
  System.SetLength(LKey, 32);
  System.SetLength(LNonce23, 23);
  try
    LEngine := TXChaCha20Engine.Create;
    LEngine.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LKey)
      as IKeyParameter, LNonce23));
    Fail('XChaCha20 unexpectedly accepted a 23-byte nonce');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

procedure TTestXChaCha20.TestRejectInvalidKeySize;
var
  LKey16, LNonce: TCryptoLibByteArray;
  LEngine: IXChaCha20Engine;
begin
  System.SetLength(LKey16, 16);
  System.SetLength(LNonce, 24);
  try
    LEngine := TXChaCha20Engine.Create;
    LEngine.Init(True, TParametersWithIV.Create(TKeyParameter.Create(LKey16)
      as IKeyParameter, LNonce));
    Fail('XChaCha20 unexpectedly accepted a 128-bit key');
  except
    on E: EArgumentCryptoLibException do
      ; // expected
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestXChaCha20);
{$ELSE}
  RegisterTest(TTestXChaCha20.Suite);
{$ENDIF FPC}

end.
