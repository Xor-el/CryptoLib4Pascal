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

unit AESTests;

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
  AESTestVectors,
  ClpAesEngine,
  ClpIAesEngine,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpICipherKeyGenerator,
  ClpICipherParameters,
  ClpGeneratorUtilities,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpNistObjectIdentifiers,
  ClpBlockCipherModes,
  ClpIBlockCipherModes,
  ClpIBlockCipher,
  ClpBufferedBlockCipher,
  ClpIBufferedBlockCipher,
  // ClpPaddedBufferedBlockCipher,
  // ClpIPaddedBufferedBlockCipher,
  // ClpPaddingModes,
  // ClpIPaddingModes,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestAES = class(TCryptoLibAlgorithmTestCase)
  private

    procedure DoOidTest(const oids, names: TCryptoLibStringArray;
      groupSize: Int32);

    procedure DoAESTest(const cipher: IBufferedCipher;
      const param: ICipherParameters; const input, output: String;
      withpadding: Boolean = False);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestOids;
    procedure TestAES_CBC_PKCS7PADDING_WITH_IV;
    procedure TestAES_CBC_NOPADDING_WITH_IV;
    procedure TestAES_CFB_NOPADDING_WITH_IV;
    procedure TestAES_OFB_NOPADDING_WITH_IV;
    procedure TestAES_CTR_NOPADDING_WITH_IV;
    procedure TestAES_ECB_NOPADDING_NO_IV;

  end;

implementation

{ TTestAES }

procedure TTestAES.DoAESTest(const cipher: IBufferedCipher;
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

procedure TTestAES.DoOidTest(const oids, names: TCryptoLibStringArray;
  groupSize: Int32);
var
  data, result, IV: TBytes;
  i: Int32;
  c1, c2: IBufferedCipher;
  kg: ICipherKeyGenerator;
  k: IKeyParameter;
  cp: ICipherParameters;
begin
  data := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16);
  i := 0;
  while i <> System.Length(oids) do
  begin
    c1 := TCipherUtilities.GetCipher(oids[i]);
    c2 := TCipherUtilities.GetCipher(names[i]);
    kg := TGeneratorUtilities.GetKeyGenerator(oids[i]);

    k := TParameterUtilities.CreateKeyParameter(oids[i], kg.GenerateKey());

    cp := k;

    if System.Pos('/ECB/', names[i]) = 0 then
    begin
      System.SetLength(IV, 16);
      cp := TParametersWithIV.Create(cp, IV);
    end;

    c1.Init(True, cp);
    c2.Init(False, cp);

    result := c2.DoFinal(c1.DoFinal(data));

    if (not AreEqual(data, result)) then
    begin
      Fail('failed OID test');
    end;

    if (System.Length(k.GetKey()) <> (16 + ((i div groupSize) * 8))) then
    begin
      Fail('failed key length test');
    end;
    System.Inc(i);
  end;

end;

procedure TTestAES.SetUp;
begin
  inherited;
end;

procedure TTestAES.TearDown;
begin
  inherited;

end;

procedure TTestAES.TestAES_CBC_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: IAesEngine;
  blockCipher: ICbcBlockCipher;
begin

  // // Set up
  engine := TAesEngine.Create();
  blockCipher := TCbcBlockCipher.Create(engine); // CBC no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TAESTestVectors.FOfficialVectorKeys_AES_CBC)
    to System.High(TAESTestVectors.FOfficialVectorKeys_AES_CBC) do
  begin
    keyBytes := DecodeHex(TAESTestVectors.FOfficialVectorKeys_AES_CBC[i]);
    IVBytes := DecodeHex(TAESTestVectors.FOfficialVectorIVs_AES_CBC[i]);
    input := TAESTestVectors.FOfficialVectorInputs_AES_CBC[i];
    output := TAESTestVectors.FOfficialVectorOutputs_AES_CBC[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', keyBytes), IVBytes);

    DoAESTest(cipher, KeyParametersWithIV as ICipherParameters, input, output);
  end;

end;

procedure TTestAES.TestAES_CBC_PKCS7PADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  // engine: IAesEngine;
  // blockCipher: ICbcBlockCipher;
begin

  // // Set up
  // engine := TAesEngine.Create();
  // blockCipher := TCbcBlockCipher.Create(engine); // CBC
  // cipher := TPaddedBufferedBlockCipher.Create(blockCipher, TPkcs7Padding.Create() as IPkcs7Padding); or
  // cipher := TPaddedBufferedBlockCipher.Create(blockCipher, TZeroBytePadding.Create() as IZeroBytePadding);
  // // Default scheme is PKCS5/PKCS7
  cipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');

  for i := System.Low(TAESTestVectors.FOfficialVectorKeys_AES_CBC)
    to System.High(TAESTestVectors.FOfficialVectorKeys_AES_CBC) do
  begin
    keyBytes := DecodeHex(TAESTestVectors.FOfficialVectorKeys_AES_CBC[i]);
    IVBytes := DecodeHex(TAESTestVectors.FOfficialVectorIVs_AES_CBC[i]);
    input := TAESTestVectors.FOfficialVectorInputs_AES_CBC[i];
    output := TAESTestVectors.FOfficialVectorOutputs_AES_CBC[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', keyBytes), IVBytes);

    DoAESTest(cipher, KeyParametersWithIV as ICipherParameters, input,
      output, True);
  end;

end;

procedure TTestAES.TestAES_CFB_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: IAesEngine;
  blockCipher: ICfbBlockCipher;
begin

  // // Set up
  engine := TAesEngine.Create();
  // CFB no padding
  blockCipher := TCfbBlockCipher.Create(engine, engine.GetBlockSize * 8);
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TAESTestVectors.FOfficialVectorKeys_AES_CFB)
    to System.High(TAESTestVectors.FOfficialVectorKeys_AES_CFB) do
  begin
    keyBytes := DecodeHex(TAESTestVectors.FOfficialVectorKeys_AES_CFB[i]);
    IVBytes := DecodeHex(TAESTestVectors.FOfficialVectorIVs_AES_CFB[i]);
    input := TAESTestVectors.FOfficialVectorInputs_AES_CFB[i];
    output := TAESTestVectors.FOfficialVectorOutputs_AES_CFB[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', keyBytes), IVBytes);

    DoAESTest(cipher, KeyParametersWithIV as ICipherParameters, input, output);
  end;

end;

procedure TTestAES.TestAES_CTR_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: IAesEngine;
  blockCipher: ISicBlockCipher;
begin

  // // Set up
  engine := TAesEngine.Create();
  blockCipher := TSicBlockCipher.Create(engine); // CTR no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TAESTestVectors.FOfficialVectorKeys_AES_CTR)
    to System.High(TAESTestVectors.FOfficialVectorKeys_AES_CTR) do
  begin
    keyBytes := DecodeHex(TAESTestVectors.FOfficialVectorKeys_AES_CTR[i]);
    IVBytes := DecodeHex(TAESTestVectors.FOfficialVectorIVs_AES_CTR[i]);
    input := TAESTestVectors.FOfficialVectorInputs_AES_CTR[i];
    output := TAESTestVectors.FOfficialVectorOutputs_AES_CTR[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', keyBytes), IVBytes);

    DoAESTest(cipher, KeyParametersWithIV as ICipherParameters, input, output);
  end;

end;

procedure TTestAES.TestAES_ECB_NOPADDING_NO_IV;
var
  keyParameter: IKeyParameter;
  keyBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: IAesEngine;
  blockCipher: IBlockCipher;
begin

  // // Set up
  engine := TAesEngine.Create();
  blockCipher := engine as IBlockCipher; // ECB no padding
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TAESTestVectors.FOfficialVectorKeys_AES_ECB)
    to System.High(TAESTestVectors.FOfficialVectorKeys_AES_ECB) do
  begin
    keyBytes := DecodeHex(TAESTestVectors.FOfficialVectorKeys_AES_ECB[i]);
    input := TAESTestVectors.FOfficialVectorInputs_AES_ECB[i];
    output := TAESTestVectors.FOfficialVectorOutputs_AES_ECB[i];

    keyParameter := TParameterUtilities.CreateKeyParameter('AES', keyBytes);

    DoAESTest(cipher, keyParameter as ICipherParameters, input, output);
  end;

end;

procedure TTestAES.TestAES_OFB_NOPADDING_WITH_IV;
var
  KeyParametersWithIV: IParametersWithIV;
  keyBytes, IVBytes: TBytes;
  cipher: IBufferedCipher;
  input, output: string;
  i: Int32;
  engine: IAesEngine;
  blockCipher: IOfbBlockCipher;
begin

  // // Set up
  engine := TAesEngine.Create();
  // OFB no padding
  blockCipher := TOfbBlockCipher.Create(engine, engine.GetBlockSize * 8);
  cipher := TBufferedBlockCipher.Create(blockCipher) as IBufferedBlockCipher;

  for i := System.Low(TAESTestVectors.FOfficialVectorKeys_AES_OFB)
    to System.High(TAESTestVectors.FOfficialVectorKeys_AES_OFB) do
  begin
    keyBytes := DecodeHex(TAESTestVectors.FOfficialVectorKeys_AES_OFB[i]);
    IVBytes := DecodeHex(TAESTestVectors.FOfficialVectorIVs_AES_OFB[i]);
    input := TAESTestVectors.FOfficialVectorInputs_AES_OFB[i];
    output := TAESTestVectors.FOfficialVectorOutputs_AES_OFB[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', keyBytes), IVBytes);

    DoAESTest(cipher, KeyParametersWithIV as ICipherParameters, input, output);
  end;

end;

procedure TTestAES.TestOids;
var
  oids, names: TCryptoLibStringArray;
begin
  oids := TCryptoLibStringArray.Create(TNistObjectIdentifiers.IdAes128Ecb.Id,
    TNistObjectIdentifiers.IdAes128Cbc.Id,
    TNistObjectIdentifiers.IdAes128Ofb.Id,
    TNistObjectIdentifiers.IdAes128Cfb.Id,
    TNistObjectIdentifiers.IdAes192Ecb.Id,
    TNistObjectIdentifiers.IdAes192Cbc.Id,
    TNistObjectIdentifiers.IdAes192Ofb.Id,
    TNistObjectIdentifiers.IdAes192Cfb.Id,
    TNistObjectIdentifiers.IdAes256Ecb.Id,
    TNistObjectIdentifiers.IdAes256Cbc.Id,
    TNistObjectIdentifiers.IdAes256Ofb.Id,
    TNistObjectIdentifiers.IdAes256Cfb.Id);

  names := TCryptoLibStringArray.Create('AES/ECB/PKCS7Padding',
    'AES/CBC/PKCS7Padding', 'AES/OFB/NoPadding', 'AES/CFB/NoPadding',
    'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding', 'AES/OFB/NoPadding',
    'AES/CFB/NoPadding', 'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding',
    'AES/OFB/NoPadding', 'AES/CFB/NoPadding');

  DoOidTest(oids, names, 4);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestAES);
{$ELSE}
  RegisterTest(TTestAES.Suite);
{$ENDIF FPC}

end.
