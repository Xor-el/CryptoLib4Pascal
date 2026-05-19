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
  CryptoLibTestBase;

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
  LKey, LIv, LZero, LExpectedKs, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LIv := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555658');
  LExpectedKs := THexEncoder.Decode(
    '1131ce9a2a20ae0d67c8935c7789fa10' +
    '25c9e5bb720fb96f11354fb97af0bd9a' +
    'adec0863ba60cac8582c48f86cdfc48e' +
    'dd46a48642c5de62ccf11c7b21bf337d' +
    '29624b4b1b140ace53740e405b216854' +
    '0fd7d630c1f536fecd722fc3cddba7f4' +
    'cca98cf9e47e5e64d115450f9b125b54' +
    '449ff76141ca620a1f9cfcab2a1a8a25' +
    '5e766a5266b878846120ea64ad99aa47' +
    '9471e63befcbd37cd1c22a221fe46221' +
    '5cf32c74895bf505863ccddd48f62916' +
    'dc6521f1ec50a5ae08903aa259d9bf60' +
    '7cd8026fba548604f1b6072d91bc9124' +
    '3a5b845f7fd171b02edc5a0a84cf28dd' +
    '241146bc376e3f48df5e7fee1d11048c' +
    '190a3d3deb0feb64b42d9c6fdeee290f' +
    'a0e6ae2c26c0249ea8c181f7e2ffd100' +
    'cbe5fd3c4f8271d62b15330cb8fdcf00');
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
  LKey, LIv, LZero, LExpectedKs, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha Appendix A.3.2.1 - full 19 x 16 B keystream (counter 0). }
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LIv := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555658');
  LExpectedKs := THexEncoder.Decode(
    '1131ce9a2a20ae0d67c8935c7789fa1025c9e5bb720fb96f11354fb97af0bd9a' +
    'adec0863ba60cac8582c48f86cdfc48edd46a48642c5de62ccf11c7b21bf337d' +
    '29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4' +
    'cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25' +
    '5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221' +
    '5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60' +
    '7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd' +
    '241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f' +
    'a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00' +
    'b3df507ca8c924f7017b7e712d15a2eb');
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
  LKey, LIv, LPlain, LExpectedCt, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha Appendix A.3.2.1 ciphertext (same key/IV as A.3.2.1). }
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LIv := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555658');
  LPlain := THexEncoder.Decode(
    '5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973' +
    '20616c736f206b6e6f776e2061732074686520417369617469632077696c6420' +
    '646f672c2072656420646f672c20616e642077686973746c696e6720646f672e' +
    '2049742069732061626f7574207468652073697a65206f662061204765726d61' +
    '6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061' +
    '206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c' +
    '757369766520616e6420736b696c6c6564206a756d70657220697320636c6173' +
    '736966696564207769746820776f6c7665732c20636f796f7465732c206a6163' +
    '6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963' +
    '2066616d696c792043616e696461652e');
  LExpectedCt := THexEncoder.Decode(
    '4559abba4e48c16102e8bb2c05e6947f50a786de162f9b0b7e592a9b53d0d4e9' +
    '8d8d6410d540a1a6375b26d80dace4fab52384c731acbf16a5923c0c48d3575d' +
    '4d0d2c673b666faa731061277701093a6bf7a158a8864292a41c48e3a9b4c0da' +
    'ece0f8d98d0d7e05b37a307bbb66333164ec9e1b24ea0d6c3ffddcec4f68e744' +
    '3056193a03c810e11344ca06d8ed8a2bfb1e8d48cfa6bc0eb4e2464b74814240' +
    '7c9f431aee769960e15ba8b96890466ef2457599852385c661f752ce20f9da0c' +
    '09ab6b19df74e76a95967446f8d0fd415e7bee2a12a114c20eb5292ae7a349ae' +
    '577820d5520a1f3fb62a17ce6a7e68fa7c79111d8860920bc048ef43fe84486c' +
    'cb87c25f0ae045f0cce1e7989a9aa220a28bdd4827e751a24a6d5c62d790a663' +
    '93b93111c1a55dd7421a10184974c7c5');
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
  LKey, LIv, LZero, LBurn, LExpectedKs, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha A.3.2.2 - keystream with block counter 1 (skip first 64 B). }
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LIv := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555658');
  LExpectedKs := THexEncoder.Decode(
    '29624b4b1b140ace53740e405b2168540fd7d630c1f536fecd722fc3cddba7f4' +
    'cca98cf9e47e5e64d115450f9b125b54449ff76141ca620a1f9cfcab2a1a8a25' +
    '5e766a5266b878846120ea64ad99aa479471e63befcbd37cd1c22a221fe46221' +
    '5cf32c74895bf505863ccddd48f62916dc6521f1ec50a5ae08903aa259d9bf60' +
    '7cd8026fba548604f1b6072d91bc91243a5b845f7fd171b02edc5a0a84cf28dd' +
    '241146bc376e3f48df5e7fee1d11048c190a3d3deb0feb64b42d9c6fdeee290f' +
    'a0e6ae2c26c0249ea8c181f7e2ffd100cbe5fd3c4f8271d62b15330cb8fdcf00' +
    'b3df507ca8c924f7017b7e712d15a2eb5c50484451e54e1b4b995bd8fdd94597' +
    'bb94d7af0b2c04df10ba0890899ed9293a0f55b8bafa999264035f1d4fbe7fe0' +
    'aafa109a62372027e50e10cdfecca127');
  System.SetLength(LBurn, 64);
  System.FillChar(LBurn[0], 64, 0);
  System.SetLength(LZero, 304);
  System.FillChar(LZero[0], 304, 0);
  System.SetLength(LOut, 304);

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LBurn, 0, 64, LBurn, 0);
  LEng.ProcessBytes(LZero, 0, 304, LOut, 0);
  if not AreEqual(LExpectedKs, LOut) then
    Fail(Format('XChaCha20 A.3.2.2 keystream mismatch: expected %s got %s',
      [EncodeHex(LExpectedKs), EncodeHex(LOut)]));
end;

procedure TTestXChaCha20.TestAppendixA3_2_2CiphertextCounter1;
var
  LKey, LIv, LPlain, LBurn, LExpectedCt, LOut: TCryptoLibByteArray;
  LEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  { draft-irtf-cfrg-xchacha A.3.2.2 ciphertext with block counter starting at 1. }
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LIv := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555658');
  LPlain := THexEncoder.Decode(
    '5468652064686f6c65202870726f6e6f756e6365642022646f6c652229206973' +
    '20616c736f206b6e6f776e2061732074686520417369617469632077696c6420' +
    '646f672c2072656420646f672c20616e642077686973746c696e6720646f672e' +
    '2049742069732061626f7574207468652073697a65206f662061204765726d61' +
    '6e20736865706865726420627574206c6f6f6b73206d6f7265206c696b652061' +
    '206c6f6e672d6c656767656420666f782e205468697320686967686c7920656c' +
    '757369766520616e6420736b696c6c6564206a756d70657220697320636c6173' +
    '736966696564207769746820776f6c7665732c20636f796f7465732c206a6163' +
    '6b616c732c20616e6420666f78657320696e20746865207461786f6e6f6d6963' +
    '2066616d696c792043616e696461652e');
  LExpectedCt := THexEncoder.Decode(
    '7d0a2e6b7f7c65a236542630294e063b7ab9b555a5d5149aa21e4ae1e4fbce87' +
    'ecc8e08a8b5e350abe622b2ffa617b202cfad72032a3037e76ffdcdc4376ee05' +
    '3a190d7e46ca1de04144850381b9cb29f051915386b8a710b8ac4d027b8b050f' +
    '7cba5854e028d564e453b8a968824173fc16488b8970cac828f11ae53cabd201' +
    '12f87107df24ee6183d2274fe4c8b1485534ef2c5fbc1ec24bfc3663efaa08bc' +
    '047d29d25043532db8391a8a3d776bf4372a6955827ccb0cdd4af403a7ce4c63' +
    'd595c75a43e045f0cce1f29c8b93bd65afc5974922f214a40b7c402cdb91ae73' +
    'c0b63615cdad0480680f16515a7ace9d39236464328a37743ffc28f4ddb324f4' +
    'd0f5bbdc270c65b1749a6efff1fbaa09536175ccd29fb9e6057b307320d31683' +
    '8a9c71f70b5b5907a66f7ea49aadc409');
  System.SetLength(LBurn, 64);
  System.FillChar(LBurn[0], 64, 0);
  System.SetLength(LOut, System.Length(LPlain));

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LIv);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LBurn, 0, 64, LBurn, 0);
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
const
  HChaChaKeyHex = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  HChaChaNonceHex = '000000090000004a0000000031415927';
  HChaChaOutHex = '82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc';
var
  LKey, LHNonce, LSubKey, LXNonce, LZeros, LStreamX, LStreamC: TCryptoLibByteArray;
  LXEng: IXChaCha20Engine;
  LCEng: IChaCha7539Engine;
  LXParams, LCParams: IParametersWithIV;
  LInnerNonce: TCryptoLibByteArray;
begin
  LKey := THexEncoder.Decode(HChaChaKeyHex);
  LHNonce := THexEncoder.Decode(HChaChaNonceHex);
  LSubKey := THexEncoder.Decode(HChaChaOutHex);
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
  LKey, LNonce, LPlain, LExpectedCipher, LInput, LOutput, LActualCipher,
    LRoundTrip: TCryptoLibByteArray;
  LEng, LDecEng: IXChaCha20Engine;
  LParams: IParametersWithIV;
begin
  LKey := THexEncoder.Decode(
    '808182838485868788898a8b8c8d8e8f' +
    '909192939495969798999a9b9c9d9e9f');
  LNonce := THexEncoder.Decode(
    '404142434445464748494a4b4c4d4e4f5051525354555657');
  LPlain := THexEncoder.Decode(
    '4c616469657320616e642047656e746c' +
    '656d656e206f662074686520636c6173' +
    '73206f66202739393a20496620492063' +
    '6f756c64206f6666657220796f75206f' +
    '6e6c79206f6e652074697020666f7220' +
    '746865206675747572652c2073756e73' +
    '637265656e20776f756c642062652069' +
    '742e');
  LExpectedCipher := THexEncoder.Decode(
    'bd6d179d3e83d43b9576579493c0e939' +
    '572a1700252bfaccbed2902c21396cbb' +
    '731c7f1b0b4aa6440bf3a82f4eda7e39' +
    'ae64c6708c54c216cb96b72e1213b452' +
    '2f8c9ba40db5d945b11b69b982c1bb9e' +
    '3f3fac2bc369488f76b2383565d3fff9' +
    '21f9664c97637da9768812f615c68b13' +
    'b52e');

  System.SetLength(LInput, 64 + System.Length(LPlain));
  System.FillChar(LInput[0], 64, 0);
  System.Move(LPlain[0], LInput[64], System.Length(LPlain));
  System.SetLength(LOutput, System.Length(LInput));

  LEng := TXChaCha20Engine.Create;
  LParams := TParametersWithIV.Create(TKeyParameter.Create(LKey) as IKeyParameter,
    LNonce);
  LEng.Init(True, LParams);
  LEng.ProcessBytes(LInput, 0, System.Length(LInput), LOutput, 0);

  System.SetLength(LActualCipher, System.Length(LExpectedCipher));
  System.Move(LOutput[64], LActualCipher[0], System.Length(LExpectedCipher));
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
    LLen := LRandom.Next(8192);
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
