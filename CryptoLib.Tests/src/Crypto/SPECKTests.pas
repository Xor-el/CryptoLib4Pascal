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

unit SPECKTests;

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
  SpeckTestVectors,
  ClpSpeckEngine,
  ClpISpeckEngine,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpICipherParameters,
  ClpBlockCipherModes,
  ClpIBlockCipherModes,
  ClpIBlockCipher,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  CryptoLibTestBase;

type

  TTestSPECK = class(TCryptoLibAlgorithmTestCase)
  private

    procedure DoSPECKTest(const cipher: IBufferedCipher;
      const param: ICipherParameters; const input, output: String;
      withpadding: Boolean = False);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestSPECK64_CBC_NOPADDING_WITH_IV;
    procedure TestSPECK128_CBC_NOPADDING_WITH_IV;
    procedure TestSPECK64_CTR_NOPADDING_WITH_IV;
    procedure TestSPECK128_CTR_NOPADDING_WITH_IV;
    procedure TestSPECK64_ECB_NOPADDING_NO_IV;
    procedure TestSPECK128_ECB_NOPADDING_NO_IV;

  end;

implementation

{ TTestSPECK }

procedure TTestSPECK.DoSPECKTest(const cipher: IBufferedCipher;
  const param: ICipherParameters; const input, output: String;
  withpadding: Boolean);
var
  LInput, LOutput, EncryptionResult, DecryptionResult: TBytes;
  // len1, len2: Int32;
begin
  LInput := DecodeHex(input);
  LOutput := DecodeHex(output);

  cipher.Init(True, param);

  // Encryption
  // Single Pass
  EncryptionResult := cipher.DoFinal(LInput);

  { *
    // Multi Pass
    System.SetLength(EncryptionResult,
    cipher.GetOutputSize(System.Length(LInput)));

    len1 := cipher.ProcessBytes(LInput, 0, System.Length(LInput),
    EncryptionResult, 0);

    len1 := len1 + cipher.DoFinal(EncryptionResult, len1);
    * }

  if not withpadding then
  begin
    if (not AreEqual(LOutput, EncryptionResult)) then
    begin
      Fail(Format('Encryption Failed - Expected %s but got %s',
        [EncodeHex(LOutput), EncodeHex(EncryptionResult)]));
    end;
  end;

  cipher.Init(False, param);

  // Decryption
  // Single Pass
  DecryptionResult := cipher.DoFinal(EncryptionResult);
  { *
    // Multi Pass
    System.SetLength(DecryptionResult,
    cipher.GetOutputSize(System.Length(EncryptionResult)));

    len2 := cipher.ProcessBytes(EncryptionResult, 0,
    System.Length(EncryptionResult), DecryptionResult, 0);

    len2 := len2 + cipher.DoFinal(DecryptionResult, len2);

    // remove padding important!!!
    System.SetLength(DecryptionResult, len2);
    * }

  if (not AreEqual(LInput, DecryptionResult)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(DecryptionResult)]));
  end;
end;

procedure TTestSPECK.SetUp;
begin
  inherited;
end;

procedure TTestSPECK.TearDown;
begin
  inherited;

end;

procedure TTestSPECK.TestSPECK64_CBC_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: ISpeckEngine;
  blockCipher: ICbcBlockCipher;
begin

  // // Set up
  engine := TSpeck64Engine.Create();
  blockCipher := TCbcBlockCipher.Create(engine); // CBC no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_CBC)
    to System.High(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_CBC) do
  begin
    keyBytes := DecodeHex(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_CBC[i]);
    IVBytes := DecodeHex(TSPECKTestVectors.FCryptoPPVectorIVs_SPECK64_CBC[i]);
    input := TSPECKTestVectors.FCryptoPPVectorInputs_SPECK64_CBC[i];
    output := TSPECKTestVectors.FCryptoPPVectorOutputs_SPECK64_CBC[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(keyBytes) as IKeyParameter, IVBytes);

    DoSPECKTest(cipher, KeyParametersWithIV as ICipherParameters,
      input, output);
  end;

end;

procedure TTestSPECK.TestSPECK128_CBC_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: ISpeckEngine;
  blockCipher: ICbcBlockCipher;
begin

  // // Set up
  engine := TSpeck128Engine.Create();
  blockCipher := TCbcBlockCipher.Create(engine); // CBC no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_CBC)
    to System.High(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_CBC) do
  begin
    keyBytes := DecodeHex
      (TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_CBC[i]);
    IVBytes := DecodeHex(TSPECKTestVectors.FCryptoPPVectorIVs_SPECK128_CBC[i]);
    input := TSPECKTestVectors.FCryptoPPVectorInputs_SPECK128_CBC[i];
    output := TSPECKTestVectors.FCryptoPPVectorOutputs_SPECK128_CBC[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(keyBytes) as IKeyParameter, IVBytes);

    DoSPECKTest(cipher, KeyParametersWithIV as ICipherParameters,
      input, output);
  end;

end;

procedure TTestSPECK.TestSPECK64_CTR_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: ISpeckEngine;
  blockCipher: ISicBlockCipher;
begin

  // // Set up
  engine := TSpeck64Engine.Create();
  blockCipher := TSicBlockCipher.Create(engine); // CTR no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_CTR)
    to System.High(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_CTR) do
  begin
    keyBytes := DecodeHex(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_CTR[i]);
    IVBytes := DecodeHex(TSPECKTestVectors.FCryptoPPVectorIVs_SPECK64_CTR[i]);
    input := TSPECKTestVectors.FCryptoPPVectorInputs_SPECK64_CTR[i];
    output := TSPECKTestVectors.FCryptoPPVectorOutputs_SPECK64_CTR[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(keyBytes) as IKeyParameter, IVBytes);

    DoSPECKTest(cipher, KeyParametersWithIV as ICipherParameters,
      input, output);
  end;

end;

procedure TTestSPECK.TestSPECK128_CTR_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: ISpeckEngine;
  blockCipher: ISicBlockCipher;
begin

  // // Set up
  engine := TSpeck128Engine.Create();
  blockCipher := TSicBlockCipher.Create(engine); // CTR no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_CTR)
    to System.High(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_CTR) do
  begin
    keyBytes := DecodeHex
      (TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_CTR[i]);
    IVBytes := DecodeHex(TSPECKTestVectors.FCryptoPPVectorIVs_SPECK128_CTR[i]);
    input := TSPECKTestVectors.FCryptoPPVectorInputs_SPECK128_CTR[i];
    output := TSPECKTestVectors.FCryptoPPVectorOutputs_SPECK128_CTR[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TKeyParameter.Create(keyBytes) as IKeyParameter, IVBytes);

    DoSPECKTest(cipher, KeyParametersWithIV as ICipherParameters,
      input, output);
  end;

end;

procedure TTestSPECK.TestSPECK64_ECB_NOPADDING_NO_IV;
var
  keyParameter: IKeyParameter;
  keyBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: ISpeckEngine;
  blockCipher: IBlockCipher;
begin

  // // Set up
  engine := TSpeck64Engine.Create();
  blockCipher := engine as IBlockCipher; // ECB no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_ECB)
    to System.High(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_ECB) do
  begin
    keyBytes := DecodeHex(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK64_ECB[i]);
    input := TSPECKTestVectors.FCryptoPPVectorInputs_SPECK64_ECB[i];
    output := TSPECKTestVectors.FCryptoPPVectorOutputs_SPECK64_ECB[i];

    keyParameter := TKeyParameter.Create(keyBytes);

    DoSPECKTest(cipher, keyParameter as ICipherParameters, input, output);
  end;

end;

procedure TTestSPECK.TestSPECK128_ECB_NOPADDING_NO_IV;
var
  keyParameter: IKeyParameter;
  keyBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: ISpeckEngine;
  blockCipher: IBlockCipher;
begin

  // // Set up
  engine := TSpeck128Engine.Create();
  blockCipher := engine as IBlockCipher; // ECB no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_ECB)
    to System.High(TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_ECB) do
  begin
    keyBytes := DecodeHex
      (TSPECKTestVectors.FCryptoPPVectorKeys_SPECK128_ECB[i]);
    input := TSPECKTestVectors.FCryptoPPVectorInputs_SPECK128_ECB[i];
    output := TSPECKTestVectors.FCryptoPPVectorOutputs_SPECK128_ECB[i];

    keyParameter := TKeyParameter.Create(keyBytes);

    DoSPECKTest(cipher, keyParameter as ICipherParameters, input, output);
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestSPECK);
{$ELSE}
  RegisterTest(TTestSPECK.Suite);
{$ENDIF FPC}

end.
