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

unit AesBitSlicedTests;

{ Correctness tests for TAesBitSlicedEngine, the constant-time table-free AES.
  These MUST run with CRYPTOLIB_FORCE_SCALAR (CryptoLib.inc) so the AES-GCM leg
  exercises the software ImplMul64 GHASH path rather than hardware PCLMUL/PMULL. }

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
  ClpAesEngine,
  ClpAesBitSlicedEngine,
  ClpIBlockCipher,
  ClpIAeadCipher,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpAeadParameters,
  ClpGcmBlockCipher,
  ClpBasicGcmMultiplier,
  ClpIGcmMultiplier,
  ClpCbcBlockCipher,
  ClpBufferedBlockCipher,
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  CryptoLibTestBase,
  BlockCipherTestBase,
  AesBlockCipherTestBase;

type

  TTestAesBitSliced = class(TAesBlockCipherTestBase)
  strict protected
    function GetEngineFactory: TBlockCipherFactory; override;
    function EngineLabel: String; override;
  strict private
    // FIPS-197 Appendix C known-answer vectors (key / plaintext / ciphertext).
    procedure DoKatTest(const AKeyHex, APlainHex, ACipherHex: String);
    // Byte-for-byte parity of TAesBitSlicedEngine against TAesEngine over many
    // random keys and blocks, in both directions, for one key length.
    procedure DoParityTest(AKeyLen, AIterations: Int32);
    // End-to-end AES-GCM through the manually-composed constant-time stack.
    procedure DoGcmTest(const AKeyHex, ANonceHex, AAadHex, APlainHex,
      ACipherHex, ATagHex: String);
    function NewBitSlicedGcm(): IAeadCipher;
  published
    procedure TestFips197Kat;
    procedure TestParityWithTableEngine;
    procedure TestRoundTrip;
    procedure TestCbcRoundTripThroughMode;
    procedure TestAesGcmEndToEnd;
    procedure TestInvalidKeyLength;
    procedure TestResetAndReInit;
    procedure TestReInitDifferentKeySize;
    procedure TestCallerKeyPreserved;
  end;

implementation

const
  // FIPS-197 Appendix C vectors, one PT/CT pair per key size.
  KAT_KEY_128 = '000102030405060708090a0b0c0d0e0f';
  KAT_KEY_192 = '000102030405060708090a0b0c0d0e0f1011121314151617';
  KAT_KEY_256 = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f';
  KAT_PLAIN = '00112233445566778899aabbccddeeff';
  KAT_CIPHER_128 = '69c4e0d86a7b0430d8cdb78070b4c55a';
  KAT_CIPHER_192 = 'dda97ca4864cdfe06eaf70a0ec0d7191';
  KAT_CIPHER_256 = '8ea2b7ca516745bfeafc49904b496089';

function CreateBitSlicedEngine: IBlockCipher;
begin
  Result := TAesBitSlicedEngine.Create();
end;

{ TTestAesBitSliced }

function TTestAesBitSliced.GetEngineFactory: TBlockCipherFactory;
begin
  Result := @CreateBitSlicedEngine;
end;

function TTestAesBitSliced.EngineLabel: String;
begin
  Result := 'TAesBitSlicedEngine';
end;

function TTestAesBitSliced.NewBitSlicedGcm(): IAeadCipher;
begin
  // The intended constant-time-software AES-GCM recipe: bit-sliced AES engine
  // composed with the branchless software GHASH multiplier.
  Result := TGcmBlockCipher.Create(
    TAesBitSlicedEngine.Create() as IBlockCipher,
    TBasicGcmMultiplier.Create() as IGcmMultiplier) as IAeadCipher;
end;

procedure TTestAesBitSliced.DoKatTest(const AKeyHex, APlainHex,
  ACipherHex: String);
var
  LKey, LPlain, LCipher, LEnc, LDec: TBytes;
  LEngine: IBlockCipher;
  LKeyParam: IKeyParameter;
begin
  LKey := DecodeHex(AKeyHex);
  LPlain := DecodeHex(APlainHex);
  LCipher := DecodeHex(ACipherHex);
  LKeyParam := TKeyParameter.Create(LKey);

  System.SetLength(LEnc, 16);
  LEngine := TAesBitSlicedEngine.Create();
  LEngine.Init(True, LKeyParam as ICipherParameters);
  LEngine.ProcessBlock(LPlain, 0, LEnc, 0);
  if not AreEqual(LEnc, LCipher) then
    Fail(Format('FIPS-197 KAT encrypt failed for %d-bit key: expected %s got %s',
      [System.Length(LKey) * 8, EncodeHex(LCipher), EncodeHex(LEnc)]));

  System.SetLength(LDec, 16);
  LEngine := TAesBitSlicedEngine.Create();
  LEngine.Init(False, LKeyParam as ICipherParameters);
  LEngine.ProcessBlock(LCipher, 0, LDec, 0);
  if not AreEqual(LDec, LPlain) then
    Fail(Format('FIPS-197 KAT decrypt failed for %d-bit key: expected %s got %s',
      [System.Length(LKey) * 8, EncodeHex(LPlain), EncodeHex(LDec)]));
end;

procedure TTestAesBitSliced.DoParityTest(AKeyLen, AIterations: Int32);
var
  LI, LJ: Int32;
  LKey, LBlock, LRef, LBs: TBytes;
  LKeyParam: IKeyParameter;
  LTable, LSliced: IBlockCipher;
  LForEnc: Boolean;
  LDir: Int32;
begin
  System.SetLength(LKey, AKeyLen);
  System.SetLength(LBlock, 16);
  System.SetLength(LRef, 16);
  System.SetLength(LBs, 16);

  for LDir := 0 to 1 do
  begin
    LForEnc := LDir = 0;
    for LI := 0 to AIterations - 1 do
    begin
      for LJ := 0 to AKeyLen - 1 do
        LKey[LJ] := Byte(Random(256));
      for LJ := 0 to 15 do
        LBlock[LJ] := Byte(Random(256));

      LKeyParam := TKeyParameter.Create(LKey);

      LTable := TAesEngine.Create();
      LTable.Init(LForEnc, LKeyParam as ICipherParameters);
      LTable.ProcessBlock(LBlock, 0, LRef, 0);

      LSliced := TAesBitSlicedEngine.Create();
      LSliced.Init(LForEnc, LKeyParam as ICipherParameters);
      LSliced.ProcessBlock(LBlock, 0, LBs, 0);

      if not AreEqual(LRef, LBs) then
        Fail(Format('Parity failed (%d-bit key, %s, iter %d): table %s vs sliced %s',
          [AKeyLen * 8, SysUtils.BoolToStr(LForEnc, True), LI, EncodeHex(LRef),
          EncodeHex(LBs)]));
    end;
  end;
end;

procedure TTestAesBitSliced.DoGcmTest(const AKeyHex, ANonceHex, AAadHex,
  APlainHex, ACipherHex, ATagHex: String);
var
  LKey, LNonce, LAad, LPlain, LCipher, LTag, LExpected: TBytes;
  LKeyParam: IKeyParameter;
  LParams: ICipherParameters;
  LGcm: IAeadCipher;
  LOut, LDec: TBytes;
  LLen: Int32;
begin
  LKey := DecodeHex(AKeyHex);
  LNonce := DecodeHex(ANonceHex);
  if AAadHex <> '' then
    LAad := DecodeHex(AAadHex)
  else
    LAad := nil;
  LPlain := DecodeHex(APlainHex);
  LCipher := DecodeHex(ACipherHex);
  LTag := DecodeHex(ATagHex);
  LExpected := System.Copy(LCipher);
  LExpected := LExpected + LTag;

  LKeyParam := TKeyParameter.Create(LKey);
  LParams := TAeadParameters.Create(LKeyParam, System.Length(LTag) * 8, LNonce,
    LAad) as ICipherParameters;

  // Encrypt: output must equal ciphertext || tag.
  LGcm := NewBitSlicedGcm();
  LGcm.Init(True, LParams);
  System.SetLength(LOut, LGcm.GetOutputSize(System.Length(LPlain)));
  LLen := LGcm.ProcessBytes(LPlain, 0, System.Length(LPlain), LOut, 0);
  LLen := LLen + LGcm.DoFinal(LOut, LLen);
  System.SetLength(LOut, LLen);
  if not AreEqual(LOut, LExpected) then
    Fail(Format('AES-GCM encrypt mismatch: expected %s got %s',
      [EncodeHex(LExpected), EncodeHex(LOut)]));

  // Decrypt: recover plaintext and verify the tag (DoFinal raises on bad tag).
  LGcm := NewBitSlicedGcm();
  LGcm.Init(False, LParams);
  System.SetLength(LDec, LGcm.GetOutputSize(System.Length(LOut)));
  LLen := LGcm.ProcessBytes(LOut, 0, System.Length(LOut), LDec, 0);
  LLen := LLen + LGcm.DoFinal(LDec, LLen);
  System.SetLength(LDec, LLen);
  if not AreEqual(LDec, LPlain) then
    Fail(Format('AES-GCM decrypt mismatch: expected %s got %s',
      [EncodeHex(LPlain), EncodeHex(LDec)]));
end;

procedure TTestAesBitSliced.TestFips197Kat;
begin
  DoKatTest(KAT_KEY_128, KAT_PLAIN, KAT_CIPHER_128);
  DoKatTest(KAT_KEY_192, KAT_PLAIN, KAT_CIPHER_192);
  DoKatTest(KAT_KEY_256, KAT_PLAIN, KAT_CIPHER_256);
end;

procedure TTestAesBitSliced.TestParityWithTableEngine;
begin
  // Deterministic corpus: fixed seed so a failure reproduces.
  RandSeed := 20260722;
  DoParityTest(16, 256);
  DoParityTest(24, 256);
  DoParityTest(32, 256);
end;

procedure TTestAesBitSliced.TestRoundTrip;
var
  LKeyLens: array [0 .. 2] of Int32;
  LK, LJ: Int32;
  LKey, LBlock, LEnc, LDec, LReEnc: TBytes;
  LKeyParam: IKeyParameter;
  LEng: IBlockCipher;
begin
  RandSeed := 987654321;
  LKeyLens[0] := 16;
  LKeyLens[1] := 24;
  LKeyLens[2] := 32;
  System.SetLength(LBlock, 16);
  System.SetLength(LEnc, 16);
  System.SetLength(LDec, 16);
  System.SetLength(LReEnc, 16);

  for LK := 0 to High(LKeyLens) do
  begin
    System.SetLength(LKey, LKeyLens[LK]);
    for LJ := 0 to LKeyLens[LK] - 1 do
      LKey[LJ] := Byte(Random(256));
    for LJ := 0 to 15 do
      LBlock[LJ] := Byte(Random(256));
    LKeyParam := TKeyParameter.Create(LKey);

    // encrypt-then-decrypt returns the original block
    LEng := TAesBitSlicedEngine.Create();
    LEng.Init(True, LKeyParam as ICipherParameters);
    LEng.ProcessBlock(LBlock, 0, LEnc, 0);
    LEng := TAesBitSlicedEngine.Create();
    LEng.Init(False, LKeyParam as ICipherParameters);
    LEng.ProcessBlock(LEnc, 0, LDec, 0);
    if not AreEqual(LDec, LBlock) then
      Fail(Format('Round-trip enc->dec failed for %d-bit key', [LKeyLens[LK] * 8]));

    // decrypt-then-encrypt of an arbitrary block is also an identity
    LEng := TAesBitSlicedEngine.Create();
    LEng.Init(False, LKeyParam as ICipherParameters);
    LEng.ProcessBlock(LBlock, 0, LDec, 0);
    LEng := TAesBitSlicedEngine.Create();
    LEng.Init(True, LKeyParam as ICipherParameters);
    LEng.ProcessBlock(LDec, 0, LReEnc, 0);
    if not AreEqual(LReEnc, LBlock) then
      Fail(Format('Round-trip dec->enc failed for %d-bit key', [LKeyLens[LK] * 8]));
  end;
end;

procedure TTestAesBitSliced.TestCbcRoundTripThroughMode;
var
  LKey, LIv, LInput, LEnc, LDec: TBytes;
  LKeyParam: IKeyParameter;
  LParams: ICipherParameters;
  LEncCipher, LDecCipher: IBufferedCipher;
begin
  // Exercise the decrypt path through a real chaining mode.
  LKey := DecodeHex(KAT_KEY_256);
  System.SetLength(LIv, 16);
  FillChar(LIv[0], 16, 0);
  LIv[0] := $A5;
  LInput := DecodeHex(
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52ef' +
    'f69f2445df4f9b17ad2b417be66c3710');

  LKeyParam := TKeyParameter.Create(LKey);
  LParams := TParametersWithIV.Create(LKeyParam, LIv) as ICipherParameters;

  LEncCipher := TBufferedBlockCipher.Create(
    TCbcBlockCipher.Create(TAesBitSlicedEngine.Create()) as IBlockCipher);
  LEncCipher.Init(True, LParams);
  LEnc := LEncCipher.DoFinal(LInput);

  LDecCipher := TBufferedBlockCipher.Create(
    TCbcBlockCipher.Create(TAesBitSlicedEngine.Create()) as IBlockCipher);
  LDecCipher.Init(False, LParams);
  LDec := LDecCipher.DoFinal(LEnc);

  if not AreEqual(LDec, LInput) then
    Fail(Format('AES/CBC round-trip through bit-sliced engine failed: got %s',
      [EncodeHex(LDec)]));
end;

procedure TTestAesBitSliced.TestAesGcmEndToEnd;
begin
  // McGrew-Viega AES-GCM test vectors, exercised through the constant-time
  // software stack (bit-sliced AES + branchless GHASH).

  // Case 3: AES-128, no AAD, 64-byte plaintext.
  DoGcmTest(
    'feffe9928665731c6d6a8f9467308308',
    'cafebabefacedbaddecaf888',
    '',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b391aafd255',
    '42831ec2217774244b7221b784d0d49c' +
    'e3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa05' +
    '1ba30b396a0aac973d58e091473f5985',
    '4d5c2af327cd64a62cf35abd2ba6fab4');

  // Case 4: AES-128, with AAD, 60-byte plaintext.
  DoGcmTest(
    'feffe9928665731c6d6a8f9467308308',
    'cafebabefacedbaddecaf888',
    'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    '42831ec2217774244b7221b784d0d49c' +
    'e3aa212f2c02a4e035c17e2329aca12e' +
    '21d514b25466931c7d8f6a5aac84aa05' +
    '1ba30b396a0aac973d58e091',
    '5bc94fbc3221a5db94fae95ae7121a47');

  // Case 16: AES-256, with AAD, 60-byte plaintext.
  DoGcmTest(
    'feffe9928665731c6d6a8f9467308308' +
    'feffe9928665731c6d6a8f9467308308',
    'cafebabefacedbaddecaf888',
    'feedfacedeadbeeffeedfacedeadbeefabaddad2',
    'd9313225f88406e5a55909c5aff5269a' +
    '86a7a9531534f7da2e4c303d8a318a72' +
    '1c3c0c95956809532fcf0e2449a6b525' +
    'b16aedf5aa0de657ba637b39',
    '522dc1f099567d07f47f37a32a84427d' +
    '643a8cdcbfe5c0c97598a2bd2555d1aa' +
    '8cb08e48590dbb3da7b08b1056828838' +
    'c5f61e6393ba7a0abcc9f662',
    '76fc6ece0f4e1768cddf8853bb2d551b');
end;

procedure TTestAesBitSliced.TestInvalidKeyLength;
var
  LEngine: IBlockCipher;
  LBadKey: TBytes;
  LRaised: Boolean;
begin
  System.SetLength(LBadKey, 15); // not 128/192/256 bits
  LEngine := TAesBitSlicedEngine.Create();
  LRaised := False;
  try
    LEngine.Init(True, TKeyParameter.Create(LBadKey) as ICipherParameters);
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  if not LRaised then
    Fail('Expected EArgumentCryptoLibException for 15-byte key');
end;

procedure TTestAesBitSliced.TestResetAndReInit;
var
  LKey, LBlock, LFirst, LSecond, LThird: TBytes;
  LKeyParam: IKeyParameter;
  LObj: TAesBitSlicedEngine;
  LEngine: IBlockCipher;
begin
  LKey := DecodeHex(KAT_KEY_128);
  LBlock := DecodeHex(KAT_PLAIN);
  LKeyParam := TKeyParameter.Create(LKey);
  System.SetLength(LFirst, 16);
  System.SetLength(LSecond, 16);
  System.SetLength(LThird, 16);

  // Hold the concrete object so Reset (not part of IBlockCipher) is callable;
  // the interface reference keeps it alive.
  LObj := TAesBitSlicedEngine.Create();
  LEngine := LObj;
  LEngine.Init(True, LKeyParam as ICipherParameters);
  LEngine.ProcessBlock(LBlock, 0, LFirst, 0);

  // Reset must leave the keyed state intact.
  LObj.Reset();
  LEngine.ProcessBlock(LBlock, 0, LSecond, 0);
  if not AreEqual(LFirst, LSecond) then
    Fail('ProcessBlock after Reset produced a different result');

  // Re-Init with the same key must also reproduce the result.
  LEngine.Init(True, LKeyParam as ICipherParameters);
  LEngine.ProcessBlock(LBlock, 0, LThird, 0);
  if not AreEqual(LFirst, LThird) then
    Fail('ProcessBlock after re-Init produced a different result');
end;

procedure TTestAesBitSliced.TestReInitDifferentKeySize;
var
  LBlock, LOut: TBytes;
  LEngine: IBlockCipher;
begin
  LBlock := DecodeHex(KAT_PLAIN);
  System.SetLength(LOut, 16);
  LEngine := TAesBitSlicedEngine.Create();

  LEngine.Init(True, TKeyParameter.Create(DecodeHex(KAT_KEY_128)) as ICipherParameters);
  LEngine.ProcessBlock(LBlock, 0, LOut, 0);
  if not AreEqual(LOut, DecodeHex(KAT_CIPHER_128)) then
    Fail('AES-128 encrypt wrong before re-key');

  // Re-Init the same instance with a larger key: exercises the FSkey pre-wipe + realloc.
  LEngine.Init(True, TKeyParameter.Create(DecodeHex(KAT_KEY_256)) as ICipherParameters);
  LEngine.ProcessBlock(LBlock, 0, LOut, 0);
  if not AreEqual(LOut, DecodeHex(KAT_CIPHER_256)) then
    Fail('AES-256 encrypt wrong after cross-key-size re-Init');
end;

procedure TTestAesBitSliced.TestCallerKeyPreserved;
var
  LKey, LKeyBefore, LBad: TBytes;
  LEngine: IBlockCipher;
  LI: Int32;
  LRaised: Boolean;
begin
  // A successful Init must not mutate the caller's key bytes.
  LKey := DecodeHex(KAT_KEY_128);
  LKeyBefore := System.Copy(LKey);
  LEngine := TAesBitSlicedEngine.Create();
  LEngine.Init(True, TKeyParameter.Create(LKey) as ICipherParameters);
  if not AreEqual(LKey, LKeyBefore) then
    Fail('caller key buffer was mutated on a successful Init');

  // An invalid key length must raise (matching TAesEngine).
  System.SetLength(LBad, 20);
  for LI := 0 to System.Length(LBad) - 1 do
    LBad[LI] := Byte($AA);
  LRaised := False;
  try
    LEngine := TAesBitSlicedEngine.Create();
    LEngine.Init(True, TKeyParameter.Create(LBad) as ICipherParameters);
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'invalid key length did not raise');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAesBitSliced);
{$ELSE}
  RegisterTest(TTestAesBitSliced.Suite);
{$ENDIF FPC}

end.
