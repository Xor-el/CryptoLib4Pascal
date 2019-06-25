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
  ClpIBlockCipherPadding,
  ClpAesEngine,
  ClpIAesEngine,
  ClpPaddingModes,
  ClpIPaddingModes,
  ClpPaddedBufferedBlockCipher,
  ClpIPaddedBufferedBlockCipher,
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

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published

    procedure TestOutputSizes();
    procedure TestPadding();

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
  bc := TPaddedBufferedBlockCipher.Create(TAESEngine.Create() as IAESEngine,
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
  cipher := TPaddedBufferedBlockCipher.Create(TAESEngine.Create()
    as IAESEngine, padding);
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

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestPadding);
{$ELSE}
  RegisterTest(TTestPadding.Suite);
{$ENDIF FPC}

end.
