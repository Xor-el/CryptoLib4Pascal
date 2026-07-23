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
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpIAeadCipher,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpAeadParameters,
  ClpGcmBlockCipher,
  ClpGcmUtilities,
  ClpBasicGcmMultiplier,
  ClpIGcmMultiplier,
  ClpSicBlockCipher,
  ClpCbcBlockCipher,
  ClpBufferedBlockCipher,
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpPack,
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
    // Part A: ProcessBlocks (batched, incl. in-place) vs N sequential ProcessBlock.
    procedure DoProcessBlocksParity(AKeyLen: Int32; AForEnc: Boolean; ACount: Int32);
    // Parts B+C: GCM through bit-sliced (soft-bulk) vs table (per-block) engine.
    procedure DoGcmParity(APlainLen, AKeyLen: Int32; const AAad: TBytes);
    // In-place GCM (output buffer aliases input) round-trip + valid tag.
    // Returns '' on success, else a description of the failing length/direction.
    function DoGcmInPlace(APlainLen: Int32; const AAad: TBytes): String;
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
    procedure TestProcessBlocksParity;
    procedure TestProcessBlocksOverflowGuard;
    procedure TestCtrBatchedVsSingle;
    procedure TestGcmBatchedVsSingle;
    procedure TestAggregatedGhashParity;
    procedure TestChunkedStreamingParity;
    procedure TestGcmInPlaceStreaming;
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

procedure TTestAesBitSliced.DoProcessBlocksParity(AKeyLen: Int32;
  AForEnc: Boolean; ACount: Int32);
var
  LKey, LInput, LSeq, LBulkOut, LInPlace: TBytes;
  LKeyParam: IKeyParameter;
  LSeqEng, LBulkEng: IBlockCipher;
  LBulk: IBulkBlockCipher;
  LI: Int32;
begin
  System.SetLength(LKey, AKeyLen);
  for LI := 0 to AKeyLen - 1 do
    LKey[LI] := Byte(Random(256));
  System.SetLength(LInput, ACount * 16);
  for LI := 0 to System.Length(LInput) - 1 do
    LInput[LI] := Byte(Random(256));
  LKeyParam := TKeyParameter.Create(LKey);

  // Sequential reference: ACount separate ProcessBlock calls.
  System.SetLength(LSeq, ACount * 16);
  LSeqEng := TAesBitSlicedEngine.Create();
  LSeqEng.Init(AForEnc, LKeyParam as ICipherParameters);
  for LI := 0 to ACount - 1 do
    LSeqEng.ProcessBlock(LInput, LI * 16, LSeq, LI * 16);

  // Bulk (disjoint buffers).
  LBulkEng := TAesBitSlicedEngine.Create();
  LBulkEng.Init(AForEnc, LKeyParam as ICipherParameters);
  if not Supports(LBulkEng, IBulkBlockCipher, LBulk) then
    Fail('TAesBitSlicedEngine does not expose IBulkBlockCipher');
  System.SetLength(LBulkOut, ACount * 16);
  LBulk.ProcessBlocks(LInput, 0, ACount, LBulkOut, 0);
  if not AreEqual(LSeq, LBulkOut) then
    Fail(Format('ProcessBlocks parity (disjoint) failed (%d-bit, %s, %d blocks)',
      [AKeyLen * 8, SysUtils.BoolToStr(AForEnc, True), ACount]));

  // Bulk (in-place: identical pointers, the aliasing shape SIC/GCM use).
  LInPlace := System.Copy(LInput);
  LBulk.ProcessBlocks(LInPlace, 0, ACount, LInPlace, 0);
  if not AreEqual(LSeq, LInPlace) then
    Fail(Format('ProcessBlocks parity (in-place) failed (%d-bit, %s, %d blocks)',
      [AKeyLen * 8, SysUtils.BoolToStr(AForEnc, True), ACount]));
end;

procedure TTestAesBitSliced.TestProcessBlocksParity;
const
  CCounts: array [0 .. 8] of Int32 = (1, 2, 3, 4, 5, 7, 8, 13, 16);
var
  LKeyLens: array [0 .. 2] of Int32;
  LKL, LDir, LC: Int32;
begin
  RandSeed := 424242;
  LKeyLens[0] := 16;
  LKeyLens[1] := 24;
  LKeyLens[2] := 32;
  for LKL := 0 to High(LKeyLens) do
    for LDir := 0 to 1 do
      for LC := 0 to High(CCounts) do
        DoProcessBlocksParity(LKeyLens[LKL], LDir = 0, CCounts[LC]);
end;

procedure TTestAesBitSliced.TestProcessBlocksOverflowGuard;
var
  LBuf: TBytes;
  LEng: IBlockCipher;
  LBulk: IBulkBlockCipher;
  LRaised: Boolean;
begin
  // A block count whose byte total (*16) would wrap Int32 must be rejected by
  // the range check, not overflow it into an out-of-bounds transform.
  System.SetLength(LBuf, 16);
  LEng := TAesBitSlicedEngine.Create();
  LEng.Init(True, TKeyParameter.Create(DecodeHex(KAT_KEY_128))
    as ICipherParameters);
  if not Supports(LEng, IBulkBlockCipher, LBulk) then
    Fail('TAesBitSlicedEngine does not expose IBulkBlockCipher');
  LRaised := False;
  try
    LBulk.ProcessBlocks(LBuf, 0, Int32($08000000), LBuf, 0);
  except
    on E: EDataLengthCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'oversized block count must raise, not overflow the check');
end;

procedure TTestAesBitSliced.TestCtrBatchedVsSingle;
var
  LKey, LIv, LInput, LBatched, LPerBlock, LSplit: TBytes;
  LKeyParam: IKeyParameter;
  LParams: ICipherParameters;
  LSlicedMode, LTableMode, LSplitMode: IBulkBlockCipherMode;
  LCount, LI: Int32;
begin
  RandSeed := 13371337;
  LCount := 20; // 8 + 8 + 4-ish batching in SIC, plus a non-multiple-of-8 residue
  System.SetLength(LKey, 16);
  for LI := 0 to 15 do
    LKey[LI] := Byte(Random(256));
  System.SetLength(LIv, 16);
  for LI := 0 to 15 do
    LIv[LI] := Byte(Random(256));
  System.SetLength(LInput, LCount * 16);
  for LI := 0 to System.Length(LInput) - 1 do
    LInput[LI] := Byte(Random(256));

  LKeyParam := TKeyParameter.Create(LKey);
  LParams := TParametersWithIV.Create(LKeyParam, LIv) as ICipherParameters;

  // Batched: the bit-sliced engine exposes IBulkBlockCipher, so SIC batches.
  LSlicedMode := TSicBlockCipher.Create(TAesBitSlicedEngine.Create()
    as IBlockCipher) as IBulkBlockCipherMode;
  LSlicedMode.Init(True, LParams);
  System.SetLength(LBatched, LCount * 16);
  LSlicedMode.ProcessBlocks(LInput, 0, LCount, LBatched, 0);

  // Per-block reference: the table engine lacks IBulkBlockCipher, so SIC loops.
  LTableMode := TSicBlockCipher.Create(TAesEngine.Create() as IBlockCipher)
    as IBulkBlockCipherMode;
  LTableMode.Init(True, LParams);
  System.SetLength(LPerBlock, LCount * 16);
  LTableMode.ProcessBlocks(LInput, 0, LCount, LPerBlock, 0);

  if not AreEqual(LBatched, LPerBlock) then
    Fail('AES-CTR batched (bit-sliced) != per-block (table) keystream');

  // Two bulk calls split at a non-multiple-of-8 must equal one call: the
  // internal counter must carry across the batch boundary.
  LSplitMode := TSicBlockCipher.Create(TAesBitSlicedEngine.Create()
    as IBlockCipher) as IBulkBlockCipherMode;
  LSplitMode.Init(True, LParams);
  System.SetLength(LSplit, LCount * 16);
  LSplitMode.ProcessBlocks(LInput, 0, 5, LSplit, 0);
  LSplitMode.ProcessBlocks(LInput, 5 * 16, LCount - 5, LSplit, 5 * 16);
  if not AreEqual(LSplit, LBatched) then
    Fail('AES-CTR split bulk calls != single bulk call');
end;

procedure TTestAesBitSliced.DoGcmParity(APlainLen, AKeyLen: Int32;
  const AAad: TBytes);
var
  LKey, LNonce, LPlain, LRef, LTest, LDec: TBytes;
  LKeyParam: IKeyParameter;
  LParams: ICipherParameters;
  LRefGcm, LTestGcm, LDecGcm: IAeadCipher;
  LI, LLen: Int32;
begin
  System.SetLength(LKey, AKeyLen);
  for LI := 0 to AKeyLen - 1 do
    LKey[LI] := Byte(Random(256));
  System.SetLength(LNonce, 12);
  for LI := 0 to 11 do
    LNonce[LI] := Byte(Random(256));
  System.SetLength(LPlain, APlainLen);
  for LI := 0 to APlainLen - 1 do
    LPlain[LI] := Byte(Random(256));

  LKeyParam := TKeyParameter.Create(LKey);
  LParams := TAeadParameters.Create(LKeyParam, 128, LNonce, AAad)
    as ICipherParameters;

  // Reference: table engine + software multiplier -> per-block GHASH path.
  LRefGcm := TGcmBlockCipher.Create(TAesEngine.Create() as IBlockCipher,
    TBasicGcmMultiplier.Create() as IGcmMultiplier) as IAeadCipher;
  LRefGcm.Init(True, LParams);
  System.SetLength(LRef, LRefGcm.GetOutputSize(APlainLen));
  LLen := LRefGcm.ProcessBytes(LPlain, 0, APlainLen, LRef, 0);
  LLen := LLen + LRefGcm.DoFinal(LRef, LLen);
  System.SetLength(LRef, LLen);

  // Test: bit-sliced engine -> software-bulk aggregated GHASH path.
  LTestGcm := NewBitSlicedGcm();
  LTestGcm.Init(True, LParams);
  System.SetLength(LTest, LTestGcm.GetOutputSize(APlainLen));
  LLen := LTestGcm.ProcessBytes(LPlain, 0, APlainLen, LTest, 0);
  LLen := LLen + LTestGcm.DoFinal(LTest, LLen);
  System.SetLength(LTest, LLen);

  if not AreEqual(LRef, LTest) then
    Fail(Format('GCM batched vs per-block mismatch (plainlen=%d, key=%d, aadlen=%d)',
      [APlainLen, AKeyLen * 8, System.Length(AAad)]));

  // Decrypt through the bit-sliced stack; recover plaintext and verify the tag.
  LDecGcm := NewBitSlicedGcm();
  LDecGcm.Init(False, LParams);
  System.SetLength(LDec, LDecGcm.GetOutputSize(System.Length(LTest)));
  LLen := LDecGcm.ProcessBytes(LTest, 0, System.Length(LTest), LDec, 0);
  LLen := LLen + LDecGcm.DoFinal(LDec, LLen);
  System.SetLength(LDec, LLen);
  if not AreEqual(LDec, LPlain) then
    Fail(Format('GCM bit-sliced decrypt mismatch (plainlen=%d)', [APlainLen]));
end;

procedure TTestAesBitSliced.TestGcmBatchedVsSingle;
const
  CBlk: array [0 .. 7] of Int32 = (0, 1, 15, 16, 17, 63, 64, 65);
var
  LI: Int32;
  LAad: TBytes;
begin
  RandSeed := 55667788;
  System.SetLength(LAad, 20);
  for LI := 0 to 19 do
    LAad[LI] := Byte(LI * 7 + 1);
  for LI := 0 to High(CBlk) do
  begin
    DoGcmParity(CBlk[LI] * 16, 16, nil);  // whole blocks, no AAD, AES-128
    DoGcmParity(CBlk[LI] * 16, 32, LAad); // whole blocks, AAD, AES-256
  end;
  // Partial tails exercise ProcessPartial after the 4-block bulk path.
  DoGcmParity(16 * 4 + 7, 16, nil);
  DoGcmParity(16 * 17 + 9, 32, LAad);
  DoGcmParity(16 * 65 + 15, 24, LAad);
end;

procedure TTestAesBitSliced.TestAggregatedGhashParity;
var
  LH, LY1, LY2: TBytes;
  LMult: IGcmMultiplier;
  LH1, LH2, LH3, LH4, LYf, LX1, LX2, LX3, LX4, LTmp, LHc: TFieldElement;
  LTrial, LI, LNumBlocks, LBlk, LGroups, LTail, LOff: Int32;
  LBlocks: TBytes;
begin
  RandSeed := 909090;
  for LTrial := 0 to 40 do
  begin
    System.SetLength(LH, 16);
    for LI := 0 to 15 do
      LH[LI] := Byte(Random(256));
    LNumBlocks := LTrial mod 11; // 0..10 blocks: groups of 4 plus a 0..2 tail
    System.SetLength(LBlocks, LNumBlocks * 16);
    for LI := 0 to System.Length(LBlocks) - 1 do
      LBlocks[LI] := Byte(Random(256));

    LMult := TBasicGcmMultiplier.Create() as IGcmMultiplier;
    LMult.Init(LH);

    // Reference: per-block Y := (Y xor B) * H.
    System.SetLength(LY1, 16);
    System.FillChar(LY1[0], 16, 0);
    for LBlk := 0 to LNumBlocks - 1 do
    begin
      for LI := 0 to 15 do
        LY1[LI] := LY1[LI] xor LBlocks[LBlk * 16 + LI];
      LMult.MultiplyH(LY1);
    end;

    // Aggregated: groups of 4 via AggregateGhash4, tail per-block via Multiply.
    TGcmUtilities.ComputePowers1To4(LH, LH1, LH2, LH3, LH4);
    LYf.N0 := 0;
    LYf.N1 := 0;
    LGroups := LNumBlocks div 4;
    for LBlk := 0 to LGroups - 1 do
    begin
      LOff := LBlk * 64;
      LX1.N0 := TPack.BE_To_UInt64(LBlocks, LOff);
      LX1.N1 := TPack.BE_To_UInt64(LBlocks, LOff + 8);
      LX2.N0 := TPack.BE_To_UInt64(LBlocks, LOff + 16);
      LX2.N1 := TPack.BE_To_UInt64(LBlocks, LOff + 24);
      LX3.N0 := TPack.BE_To_UInt64(LBlocks, LOff + 32);
      LX3.N1 := TPack.BE_To_UInt64(LBlocks, LOff + 40);
      LX4.N0 := TPack.BE_To_UInt64(LBlocks, LOff + 48);
      LX4.N1 := TPack.BE_To_UInt64(LBlocks, LOff + 56);
      TGcmUtilities.AggregateGhash4(LYf, LX1, LX2, LX3, LX4, LH1, LH2, LH3, LH4);
    end;
    LTail := LNumBlocks mod 4;
    for LBlk := 0 to LTail - 1 do
    begin
      LOff := (LGroups * 4 + LBlk) * 16;
      LTmp.N0 := TPack.BE_To_UInt64(LBlocks, LOff);
      LTmp.N1 := TPack.BE_To_UInt64(LBlocks, LOff + 8);
      LYf.N0 := LYf.N0 xor LTmp.N0;
      LYf.N1 := LYf.N1 xor LTmp.N1;
      LHc := LH1;
      TGcmUtilities.Multiply(LYf, LHc);
    end;
    System.SetLength(LY2, 16);
    TGcmUtilities.AsBytes(LYf, LY2);

    if not AreEqual(LY1, LY2) then
      Fail(Format('Aggregated GHASH parity failed at trial %d (%d blocks)',
        [LTrial, LNumBlocks]));
  end;
end;

procedure TTestAesBitSliced.TestChunkedStreamingParity;
const
  CFrags: array [0 .. 8] of Int32 = (1, 7, 64, 3, 15, 128, 2, 100, 5);
var
  LKey, LNonce, LAad, LPlain, LOneShot, LChunked, LDec: TBytes;
  LKeyParam: IKeyParameter;
  LParams: ICipherParameters;
  LGcm: IAeadCipher;
  LTotal, LI, LOff, LFragIdx, LChunk, LOutOff, LLen: Int32;
begin
  RandSeed := 246810;
  LTotal := 777; // not block-aligned, spans several 4-block batches
  System.SetLength(LKey, 16);
  for LI := 0 to 15 do
    LKey[LI] := Byte(Random(256));
  System.SetLength(LNonce, 12);
  for LI := 0 to 11 do
    LNonce[LI] := Byte(Random(256));
  System.SetLength(LAad, 20);
  for LI := 0 to 19 do
    LAad[LI] := Byte(Random(256));
  System.SetLength(LPlain, LTotal);
  for LI := 0 to LTotal - 1 do
    LPlain[LI] := Byte(Random(256));
  LKeyParam := TKeyParameter.Create(LKey);
  LParams := TAeadParameters.Create(LKeyParam, 128, LNonce, LAad)
    as ICipherParameters;

  // One-shot ciphertext + tag.
  LGcm := NewBitSlicedGcm();
  LGcm.Init(True, LParams);
  System.SetLength(LOneShot, LGcm.GetOutputSize(LTotal));
  LLen := LGcm.ProcessBytes(LPlain, 0, LTotal, LOneShot, 0);
  LLen := LLen + LGcm.DoFinal(LOneShot, LLen);
  System.SetLength(LOneShot, LLen);

  // Chunked feed with pathological fragment sizes (some straddle batch edges).
  LGcm := NewBitSlicedGcm();
  LGcm.Init(True, LParams);
  System.SetLength(LChunked, LGcm.GetOutputSize(LTotal));
  LOff := 0;
  LFragIdx := 0;
  LOutOff := 0;
  while LOff < LTotal do
  begin
    LChunk := CFrags[LFragIdx mod System.Length(CFrags)];
    if LChunk > LTotal - LOff then
      LChunk := LTotal - LOff;
    LOutOff := LOutOff + LGcm.ProcessBytes(LPlain, LOff, LChunk, LChunked, LOutOff);
    LOff := LOff + LChunk;
    System.Inc(LFragIdx);
  end;
  LOutOff := LOutOff + LGcm.DoFinal(LChunked, LOutOff);
  System.SetLength(LChunked, LOutOff);

  if not AreEqual(LOneShot, LChunked) then
    Fail('GCM chunked-feed ciphertext/tag != one-shot');

  // Decrypt the chunked ciphertext with the same fragment pattern.
  LGcm := NewBitSlicedGcm();
  LGcm.Init(False, LParams);
  System.SetLength(LDec, LGcm.GetOutputSize(System.Length(LChunked)));
  LOff := 0;
  LFragIdx := 0;
  LOutOff := 0;
  while LOff < System.Length(LChunked) do
  begin
    LChunk := CFrags[LFragIdx mod System.Length(CFrags)];
    if LChunk > System.Length(LChunked) - LOff then
      LChunk := System.Length(LChunked) - LOff;
    LOutOff := LOutOff + LGcm.ProcessBytes(LChunked, LOff, LChunk, LDec, LOutOff);
    LOff := LOff + LChunk;
    System.Inc(LFragIdx);
  end;
  LOutOff := LOutOff + LGcm.DoFinal(LDec, LOutOff);
  System.SetLength(LDec, LOutOff);
  if not AreEqual(LDec, LPlain) then
    Fail('GCM chunked-feed decrypt != original plaintext');
end;

function TTestAesBitSliced.DoGcmInPlace(APlainLen: Int32;
  const AAad: TBytes): String;
var
  LKey, LNonce, LPlain, LRefCT, LBuf: TBytes;
  LKeyParam: IKeyParameter;
  LParams: ICipherParameters;
  LGcm: IAeadCipher;
  LI, LLen, LTotal: Int32;
begin
  Result := '';
  System.SetLength(LKey, 16);
  for LI := 0 to 15 do
    LKey[LI] := Byte(Random(256));
  System.SetLength(LNonce, 12);
  for LI := 0 to 11 do
    LNonce[LI] := Byte(Random(256));
  System.SetLength(LPlain, APlainLen);
  for LI := 0 to APlainLen - 1 do
    LPlain[LI] := Byte(Random(256));

  LKeyParam := TKeyParameter.Create(LKey);
  LParams := TAeadParameters.Create(LKeyParam, 128, LNonce, AAad)
    as ICipherParameters;

  // Reference ciphertext||tag, produced out of place.
  LGcm := NewBitSlicedGcm();
  LGcm.Init(True, LParams);
  System.SetLength(LRefCT, LGcm.GetOutputSize(APlainLen));
  LLen := LGcm.ProcessBytes(LPlain, 0, APlainLen, LRefCT, 0);
  LLen := LLen + LGcm.DoFinal(LRefCT, LLen);
  System.SetLength(LRefCT, LLen);
  LTotal := LLen;

  // In-place encrypt: the buffer starts as plaintext and is encrypted over itself.
  System.SetLength(LBuf, LTotal);
  System.Move(LPlain[0], LBuf[0], APlainLen);
  LGcm := NewBitSlicedGcm();
  LGcm.Init(True, LParams);
  try
    LLen := LGcm.ProcessBytes(LBuf, 0, APlainLen, LBuf, 0);
    LLen := LLen + LGcm.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[len=%d enc-exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if (LLen <> LTotal) or (not AreEqual(LBuf, LRefCT)) then
  begin
    Result := Format('[len=%d enc-mismatch] ', [APlainLen]);
    Exit;
  end;

  // In-place decrypt: the buffer starts as ciphertext||tag, decrypted over itself.
  System.SetLength(LBuf, LTotal);
  System.Move(LRefCT[0], LBuf[0], LTotal);
  LGcm := NewBitSlicedGcm();
  LGcm.Init(False, LParams);
  try
    LLen := LGcm.ProcessBytes(LBuf, 0, LTotal, LBuf, 0);
    LLen := LLen + LGcm.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[len=%d dec-exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if LLen <> APlainLen then
  begin
    Result := Format('[len=%d dec-len %d] ', [APlainLen, LLen]);
    Exit;
  end;
  System.SetLength(LBuf, LLen);
  if not AreEqual(LBuf, LPlain) then
    Result := Format('[len=%d dec-mismatch] ', [APlainLen]);
end;

procedure TTestAesBitSliced.TestGcmInPlaceStreaming;
var
  LAad: TBytes;
  LI: Int32;
  LFails: String;
  LLens: array [0 .. 7] of Int32;
begin
  RandSeed := 20260723;
  System.SetLength(LAad, 20);
  for LI := 0 to 19 do
    LAad[LI] := Byte(LI * 5 + 3);
  LLens[0] := 16;
  LLens[1] := 48;
  LLens[2] := 64;
  LLens[3] := 4 * 16 + 7;
  LLens[4] := 17 * 16 + 9;
  LLens[5] := 22 * 16;
  LLens[6] := 65 * 16;      // 8-way pipelined/fused GHASH (SIMD) or soft-bulk (scalar)
  LLens[7] := 100 * 16 + 3;
  LFails := '';
  for LI := 0 to High(LLens) do
    LFails := LFails + DoGcmInPlace(LLens[LI], nil);
  for LI := 0 to High(LLens) do
    LFails := LFails + DoGcmInPlace(LLens[LI], LAad);
  if LFails <> '' then
    Fail('in-place GCM: ' + LFails);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAesBitSliced);
{$ELSE}
  RegisterTest(TTestAesBitSliced.Suite);
{$ENDIF FPC}

end.
