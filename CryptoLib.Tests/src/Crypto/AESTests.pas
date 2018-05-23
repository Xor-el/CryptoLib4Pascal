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
{$HINTS OFF}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  AESTestVectors,
  // ClpAesEngine,
  // ClpIAesEngine,
  ClpKeyParameter,
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
  // ClpCbcBlockCipher,
  // ClpICbcBlockCipher,
  // ClpPaddedBufferedBlockCipher,
  // ClpIPaddedBufferedBlockCipher,
  // ClpZeroBytePadding,
  // ClpIZeroBytePadding,
  ClpHex,
  ClpArrayUtils,
  ClpCryptoLibTypes;

type

  TCryptoLibTestCase = class abstract(TTestCase)

  end;

type

  TTestAES = class(TCryptoLibTestCase)
  private

    procedure dooidTest(oids, names: TCryptoLibStringArray; groupSize: Int32);

    procedure doAESTestWithIV(const cipher: IBufferedCipher;
      const param: IParametersWithIV; const input, output: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestOids;
    procedure TestAES256_CBC_PKCS7PADDING;

  end;

implementation

{ TTestAES }

procedure TTestAES.doAESTestWithIV(const cipher: IBufferedCipher;
  const param: IParametersWithIV; const input, output: String);
var
  len1, len2: Int32;
  LInput, LOutput, EncryptionResult, DecryptionResult: TBytes;
begin
  LInput := THex.Decode(input);
  LOutput := THex.Decode(output);

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

    len1 := cipher.DoFinal(EncryptionResult, len1);
    * }

  cipher.Init(false, param);

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
    System.Move(DecryptionResult[0], DecryptionResult[0],
    len2 * System.SizeOf(Byte));
    System.SetLength(DecryptionResult, len2);
    * }

  if (not TArrayUtils.AreEqual(LInput, DecryptionResult)) then
  begin
    Fail(Format('Decryption Failed - Expected %s but got %s',
      [THex.Encode(LInput), THex.Encode(DecryptionResult)]));
  end;
end;

procedure TTestAES.dooidTest(oids, names: TCryptoLibStringArray;
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
    c2.Init(false, cp);

    result := c2.DoFinal(c1.DoFinal(data));

    if (not TArrayUtils.AreEqual(data, result)) then
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

procedure TTestAES.TestAES256_CBC_PKCS7PADDING;
var
  keyParameter: IKeyParameter;
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

  for i := System.Low(TAESTestVectors.FOfficialVectorKeys__AES256_CBC)
    to System.Low(TAESTestVectors.FOfficialVectorKeys__AES256_CBC) do
  begin
    keyBytes := THex.Decode(TAESTestVectors.FOfficialVectorKeys__AES256_CBC[i]);
    IVBytes := THex.Decode(TAESTestVectors.FOfficialVectorIVs_AES256_CBC[i]);
    input := TAESTestVectors.FOfficialVectorInputs_AES256_CBC[i];
    output := TAESTestVectors.FOfficialVectorOutputs_AES256_CBC[i];

    KeyParametersWithIV := TParametersWithIV.Create
      (TParameterUtilities.CreateKeyParameter('AES', keyBytes), IVBytes);

    doAESTestWithIV(cipher, KeyParametersWithIV, input, output);
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

  dooidTest(oids, names, 4);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestAES);
{$ELSE}
  RegisterTest(TTestAES.Suite);
{$ENDIF FPC}

end.
