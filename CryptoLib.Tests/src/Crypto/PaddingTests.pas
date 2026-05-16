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

unit PaddingTests;

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
  ClpSecureRandom,
  ClpISecureRandom,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpIBlockCipherPadding,
  ClpAesUtilities,
  ClpCbcBlockCipher,
  ClpIBlockCipherMode,
  ClpISO10126d2Padding,
  ClpISO7816d4Padding,
  ClpPkcs7Padding,
  ClpTBCPadding,
  ClpX923Padding,
  ClpZeroBytePadding,
  ClpIISO10126d2Padding,
  ClpIISO7816d4Padding,
  ClpIPkcs7Padding,
  ClpITBCPadding,
  ClpIX923Padding,
  ClpIZeroBytePadding,
  ClpPaddedBufferedBlockCipher,
  ClpIPaddedBufferedBlockCipher,
  ClpIBufferedCipher,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Padding tests.
  /// </summary>
  TTestPadding = class(TCryptoLibAlgorithmTestCase)
  private

    procedure DoBlockCheck(const cipher: IPaddedBufferedBlockCipher;
      const padding: IBlockCipherPadding; const key: IKeyParameter;
      const data: TBytes);
    procedure DoTestPadding(const padding: IBlockCipherPadding;
      const rand: ISecureRandom; const ffVector, ZeroVector: TBytes);

    procedure DoBlockAlignedRoundTrip(ALen: Int32);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published

    procedure TestOutputSizes();
    procedure TestPadding();
    /// <summary>
    /// RFC 5652 sec. 6.3: when plaintext length is a multiple of the block size,
    /// PKCS#7 padding must append a full additional block (16 bytes of value
    /// 0x10 for AES). Verifies the state-machine path in TPaddedBufferedBlockCipher
    /// where FBufOff = LBlockSize on entry to DoFinal and is reset to 0
    /// before AddPadding produces the mandatory full padding block.
    /// </summary>
    procedure TestBlockAlignedInputProducesFullPaddingBlock();

  end;

implementation

{ TTestPadding }

procedure TTestPadding.DoBlockCheck(const cipher: IPaddedBufferedBlockCipher;
  const padding: IBlockCipherPadding; const key: IKeyParameter;
  const data: TBytes);
var
  &out, dec: TBytes;
  len, decLen: Int32;
begin
  System.SetLength(&out, System.Length(data) + 16);
  System.SetLength(dec, System.Length(data));

  try

    cipher.Init(true, key);

    len := cipher.ProcessBytes(data, 0, System.Length(data), &out, 0);

    len := len + cipher.doFinal(&out, len);

    cipher.Init(false, key);

    decLen := cipher.ProcessBytes(&out, 0, len, dec, 0);

    // decLen := decLen + cipher.doFinal(dec, decLen);
    cipher.doFinal(dec, decLen);

    if (not AreEqual(data, dec)) then
    begin
      Fail('failed to decrypt - i = ' + IntToStr(System.Length(data)) +
        ', padding = ' + padding.PaddingName);
    end;

  except
    on e: ECryptoLibException do
    begin
      Fail('Exception - ' + e.ToString());
    end;

  end;

end;

procedure TTestPadding.SetUp;
begin
  inherited;

end;

procedure TTestPadding.TearDown;
begin
  inherited;

end;

procedure TTestPadding.TestOutputSizes;
var
  bc: IPaddedBufferedBlockCipher;
  key: IKeyParameter;
  i: Int32;
begin
  bc := TPaddedBufferedBlockCipher.Create(TAesUtilities.CreateEngine(),
    TPKCS7Padding.Create() as IPKCS7Padding);
  key := TKeyParameter.Create(DecodeHex('001122334455667788990A0B0C0D0E0F'));

  for i := 0 to (bc.GetBlockSize * 2) do
  begin
    bc.Init(true, key);
    if (bc.GetUpdateOutputSize(i) < 0) then
    begin
      Fail('Padded cipher encrypt negative update output size for input size ' +
        IntToStr(i));
    end;
    if (bc.GetOutputSize(i) < 0) then
    begin
      Fail('Padded cipher encrypt negative output size for input size ' +
        IntToStr(i));
    end;

    bc.Init(false, key);
    if (bc.GetUpdateOutputSize(i) < 0) then
    begin
      Fail('Padded cipher decrypt negative update output size for input size ' +
        IntToStr(i));
    end;
    if (bc.GetOutputSize(i) < 0) then
    begin
      Fail('Padded cipher decrypt negative output size for input size ' +
        IntToStr(i));
    end;
  end;

end;

procedure TTestPadding.TestPadding;
var
  rand: ISecureRandom;
  padder: IPKCS7Padding;
  temp: TBytes;
begin
  rand := TSecureRandom.GetInstance('SHA256PRNG');

  DoTestPadding(TPKCS7Padding.Create() as IPKCS7Padding, rand,
    DecodeHex('ffffff0505050505'), DecodeHex('0000000004040404'));

  padder := TPKCS7Padding.Create();
  try

    System.SetLength(temp, 8);
    padder.PadCount(temp);

    Fail('invalid padding not detected');

  except
    on e: EInvalidCipherTextCryptoLibException do
    begin
      if (not(e.Message = 'Pad Block Corrupted')) then
      begin
        Fail('wrong exception for corrupt padding: ' + e.Message);
      end;
    end;

  end;

  DoTestPadding(TISO10126d2Padding.Create() as IISO10126d2Padding, rand,
    Nil, Nil);

  DoTestPadding(TX923Padding.Create() as IX923Padding, rand, Nil, Nil);

  DoTestPadding(TTBCPadding.Create() as ITBCPadding, rand,
    DecodeHex('ffffff0000000000'), DecodeHex('00000000ffffffff'));

  DoTestPadding(TZeroBytePadding.Create() as IZeroBytePadding, rand,
    DecodeHex('ffffff0000000000'), Nil);

  DoTestPadding(TISO7816d4Padding.Create() as IISO7816d4Padding, rand,
    DecodeHex('ffffff8000000000'), DecodeHex('0000000080000000'));

  TestOutputSizes();
end;

procedure TTestPadding.DoTestPadding(const padding: IBlockCipherPadding;
  const rand: ISecureRandom; const ffVector, ZeroVector: TBytes);
var
  cipher: IPaddedBufferedBlockCipher;
  key: IKeyParameter;
  data: TBytes;
  i: Int32;
begin
  cipher := TPaddedBufferedBlockCipher.Create(TAesUtilities.CreateEngine(), padding);
  key := TKeyParameter.Create(DecodeHex('001122334455667788990A0B0C0D0E0F'));

  //
  // ff test
  //
  data := TBytes.Create($FF, $FF, $FF, $0, $0, $0, $0, $0);

  if (ffVector <> Nil) then
  begin
    padding.AddPadding(data, 3);

    if (not AreEqual(data, ffVector)) then
    begin
      Fail('failed ff test for ' + padding.PaddingName);
    end;
  end;

  //
  // zero test
  //
  if (ZeroVector <> Nil) then
  begin
    ZeroFill(data);
    padding.AddPadding(data, 4);

    if (not AreEqual(data, ZeroVector)) then
    begin
      Fail('failed zero test for ' + padding.PaddingName);
    end;
  end;

  for i := 1 to System.Pred(200) do
  begin
    System.SetLength(data, i);
    rand.NextBytes(data);
    DoBlockCheck(cipher, padding, key, data);
  end;

end;

procedure TTestPadding.DoBlockAlignedRoundTrip(ALen: Int32);
var
  cipher: IBufferedCipher;
  key: IKeyParameter;
  iv: TBytes;
  params: IParametersWithIV;
  plain, enc, dec: TBytes;
  expectedCt: Int32;
  i: Int32;
begin
  cipher := TPaddedBufferedBlockCipher.Create(
    TCbcBlockCipher.Create(TAesUtilities.CreateEngine()) as IBlockCipherMode,
    TPKCS7Padding.Create() as IPKCS7Padding);

  key := TKeyParameter.Create(DecodeHex('001122334455667788990A0B0C0D0E0F'));
  System.SetLength(iv, 16);
  for i := 0 to 15 do
    iv[i] := Byte(i);

  params := TParametersWithIV.Create(key as ICipherParameters, iv);

  System.SetLength(plain, ALen);
  for i := 0 to ALen - 1 do
    plain[i] := Byte($41); // 'A' * ALen, block-aligned content

  // Encrypt
  cipher.Init(true, params as ICipherParameters);
  enc := cipher.doFinal(plain, 0, ALen);

  expectedCt := ALen + 16; // block-aligned input must append one full padding block
  if (System.Length(enc) <> expectedCt) then
  begin
    Fail(Format('block-aligned PKCS#7 ciphertext length mismatch for %d-byte plaintext: expected %d got %d',
      [ALen, expectedCt, System.Length(enc)]));
  end;

  // Decrypt and verify round-trip
  cipher.Init(false, params as ICipherParameters);
  dec := cipher.doFinal(enc, 0, System.Length(enc));

  if (System.Length(dec) <> ALen) then
  begin
    Fail(Format('block-aligned PKCS#7 round-trip recovered wrong length for %d-byte plaintext: got %d',
      [ALen, System.Length(dec)]));
  end;
  if (not AreEqual(plain, dec)) then
  begin
    Fail(Format('block-aligned PKCS#7 round-trip plaintext mismatch for %d-byte plaintext',
      [ALen]));
  end;
end;

procedure TTestPadding.TestBlockAlignedInputProducesFullPaddingBlock;
begin
  // One full block - exercises FBufOff = LBlockSize on DoFinal entry,
  // which the if-branch resets to 0 before AddPadding writes the
  // mandatory full padding block.
  DoBlockAlignedRoundTrip(16);

  // Two full blocks - gap-fill flushes the first block, tail-store
  // completes the second, AfterTailStored is a no-op in TPaddedBufferedBlockCipher,
  // then DoFinal sees FBufOff = LBlockSize again.
  DoBlockAlignedRoundTrip(32);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestPadding);
{$ELSE}
  RegisterTest(TTestPadding.Suite);
{$ENDIF FPC}

end.
