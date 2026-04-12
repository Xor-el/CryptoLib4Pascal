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
  ClpAesEngine,
  ClpIAesEngine,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpIBufferedCipher,
  ClpBufferedBlockCipher,
  ClpICipherParameters,
  ClpICipherKeyGenerator,
  ClpGeneratorUtilities,
  ClpParameterUtilities,
  ClpCipherUtilities,
  ClpNistObjectIdentifiers,
  ClpCbcBlockCipher,
  ClpCfbBlockCipher,
  ClpOfbBlockCipher,
  ClpSicBlockCipher,
  ClpICbcBlockCipher,
  ClpICfbBlockCipher,
  ClpIOfbBlockCipher,
  ClpISicBlockCipher,
  ClpWrapperUtilities,
  ClpIWrapper,
  ClpFixedSecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  AesBlockCipherTestBase,
  NistSp80038aAesTestData;

type

  TTestAES = class(TAesBlockCipherTestBase)
  strict private
  class var

    FCipherTestVectors: TCryptoLibStringArray;

    class constructor CreateTestVectors();

  private

    procedure DoAESTest(const ACipher: IBufferedCipher;
      const AParam: ICipherParameters; const AInput, AOutput: String;
      AWithPadding: Boolean = False; const AModeContext: String = '';
      AVectorIndex: Int32 = -1);

    procedure RunNist80038A_Vectors(const ACipher: IBufferedCipher;
      const AIVs, ACiphertexts: TCryptoLibStringArray;
      AWithIV, AWithPadding: Boolean; const AModeContext: String);

    procedure DoCipherUtilitiesAeadRoundTrip(const ATransformation: String;
      const AKey, ANonce, APlain, ACiphertext: TBytes;
      const AContext: String);

    procedure ExpectGetCipherSecurityFailure(const ATransformation,
      AContext: String);

    procedure DoOidTest(const AOids, ANames: TCryptoLibStringArray;
      AGroupSize: Int32);

    procedure DoCipherTest(AStrength: Int32; const AKeyBytes,
      AInput, AOutput: TBytes);

    procedure DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
      const AKek, AInput, AOutput: TBytes); overload;

    procedure DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
      const AKek, AIV: TBytes; const ARandom: IFixedSecureRandom;
      const AInput, AOutput: TBytes); overload;

    procedure DoWrapOidTest(const AOids: TCryptoLibStringArray;
      const AName: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestBlockCipherVector;
    procedure TestMonteCarloAES;
    procedure TestBadParameters;
    procedure TestOids;
    procedure TestCiphers;
    procedure TestAES_CBC_PKCS7PADDING_WITH_IV;
    procedure TestAES_CBC_NOPADDING_WITH_IV;
    procedure TestAES_CFB_NOPADDING_WITH_IV;
    procedure TestAES_OFB_NOPADDING_WITH_IV;
    procedure TestAES_CTR_NOPADDING_WITH_IV;
    procedure TestAES_ECB_NOPADDING_NO_IV;
    procedure TestWrap;
    procedure TestWrapRfc3211;
    procedure TestWrapRfc5649;
    procedure TestWrapOids;
    procedure TestWrapPadOids;
    procedure TestAesEax;
    procedure TestAesEaxBadPadding;
    procedure TestAesCcm;
    procedure TestAesCcmBadPadding;
    procedure TestAesOcb;
    procedure TestAesOcbBadPadding;
    procedure TestAesGcm;
    procedure TestAesGcmBadPadding;

  end;

implementation

function CreateAesEngine: IBlockCipher;
begin
  Result := TAesEngine.Create();
end;

{ TTestAES }

class constructor TTestAES.CreateTestVectors;
begin
  FCipherTestVectors := TCryptoLibStringArray.Create(
    '128',
    '000102030405060708090a0b0c0d0e0f',
    '00112233445566778899aabbccddeeff',
    '69c4e0d86a7b0430d8cdb78070b4c55a',
    '192',
    '000102030405060708090a0b0c0d0e0f1011121314151617',
    '00112233445566778899aabbccddeeff',
    'dda97ca4864cdfe06eaf70a0ec0d7191',
    '256',
    '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f',
    '00112233445566778899aabbccddeeff',
    '8ea2b7ca516745bfeafc49904b496089');
end;

procedure TTestAES.DoAESTest(const ACipher: IBufferedCipher;
  const AParam: ICipherParameters; const AInput, AOutput: String;
  AWithPadding: Boolean; const AModeContext: String; AVectorIndex: Int32);
var
  LInput, LOutput, LEncryptionResult, LDecryptionResult: TBytes;
  LPrefix: String;
begin
  LInput := DecodeHex(AInput);
  LOutput := DecodeHex(AOutput);

  if (AModeContext <> '') and (AVectorIndex >= 0) then
    LPrefix := Format('[%s] vector %d: ', [AModeContext, AVectorIndex])
  else if AModeContext <> '' then
    LPrefix := '[' + AModeContext + '] '
  else
    LPrefix := '';

  ACipher.Init(True, AParam);

  LEncryptionResult := ACipher.DoFinal(LInput);

  if not AWithPadding then
  begin
    if (not AreEqual(LOutput, LEncryptionResult)) then
    begin
      Fail(LPrefix + Format('Encryption Failed - Expected %s but got %s',
        [EncodeHex(LOutput), EncodeHex(LEncryptionResult)]));
    end;
  end;

  ACipher.Init(False, AParam);

  LDecryptionResult := ACipher.DoFinal(LEncryptionResult);

  if (not AreEqual(LInput, LDecryptionResult)) then
  begin
    Fail(LPrefix + Format('Decryption Failed - Expected %s but got %s',
      [EncodeHex(LInput), EncodeHex(LDecryptionResult)]));
  end;
end;

procedure TTestAES.RunNist80038A_Vectors(const ACipher: IBufferedCipher;
  const AIVs, ACiphertexts: TCryptoLibStringArray;
  AWithIV, AWithPadding: Boolean; const AModeContext: String);
var
  LI: Int32;
  LKeyBytes, LIVBytes: TBytes;
  LKeyParametersWithIV: IParametersWithIV;
  LKeyParameter: IKeyParameter;
begin
  for LI := System.Low(TNistSp80038aAesTestData.OfficialKeys)
    to System.High(TNistSp80038aAesTestData.OfficialKeys) do
  begin
    LKeyBytes := DecodeHex(TNistSp80038aAesTestData.OfficialKeys[LI]);
    if AWithIV then
    begin
      LIVBytes := DecodeHex(AIVs[LI]);
      LKeyParametersWithIV := TParametersWithIV.Create
        (TParameterUtilities.CreateKeyParameter('AES', LKeyBytes), LIVBytes);
      DoAESTest(ACipher, LKeyParametersWithIV as ICipherParameters,
        TNistSp80038aAesTestData.OfficialPlaintext[LI], ACiphertexts[LI],
        AWithPadding, AModeContext, LI);
    end
    else
    begin
      LKeyParameter := TParameterUtilities.CreateKeyParameter('AES', LKeyBytes);
      DoAESTest(ACipher, LKeyParameter as ICipherParameters,
        TNistSp80038aAesTestData.OfficialPlaintext[LI], ACiphertexts[LI],
        AWithPadding, AModeContext, LI);
    end;
  end;
end;

procedure TTestAES.DoCipherUtilitiesAeadRoundTrip(const ATransformation: String;
  const AKey, ANonce, APlain, ACiphertext: TBytes; const AContext: String);
var
  LKeyParam: IKeyParameter;
  LInCipher, LOutCipher: IBufferedCipher;
  LEnc, LDec: TBytes;
begin
  LKeyParam := TParameterUtilities.CreateKeyParameter('AES', AKey);

  LInCipher := TCipherUtilities.GetCipher(ATransformation);
  LOutCipher := TCipherUtilities.GetCipher(ATransformation);

  LInCipher.Init(True, TParametersWithIV.Create(LKeyParam, ANonce)
    as ICipherParameters);
  LEnc := LInCipher.DoFinal(APlain);
  if not AreEqual(LEnc, ACiphertext) then
  begin
    Fail(Format('[%s] ciphertext does not match', [AContext]));
  end;

  LOutCipher.Init(False, TParametersWithIV.Create(LKeyParam, ANonce)
    as ICipherParameters);
  LDec := LOutCipher.DoFinal(ACiphertext);
  if not AreEqual(LDec, APlain) then
  begin
    Fail(Format('[%s] plaintext does not match', [AContext]));
  end;
end;

procedure TTestAES.ExpectGetCipherSecurityFailure(const ATransformation,
  AContext: String);
begin
  try
    TCipherUtilities.GetCipher(ATransformation);
    Fail(Format('[%s] bad padding missed for %s', [AContext, ATransformation]));
  except
    on E: ESecurityUtilityCryptoLibException do
    begin
      // expected
    end;
  end;
end;

procedure TTestAES.DoOidTest(const AOids, ANames: TCryptoLibStringArray;
  AGroupSize: Int32);
var
  LData, LResult, LIV: TBytes;
  LI: Int32;
  LC1, LC2: IBufferedCipher;
  LKg: ICipherKeyGenerator;
  LK: IKeyParameter;
  LCp: ICipherParameters;
begin
  LData := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16);
  LI := 0;
  while LI <> System.Length(AOids) do
  begin
    LC1 := TCipherUtilities.GetCipher(AOids[LI]);
    LC2 := TCipherUtilities.GetCipher(ANames[LI]);
    LKg := TGeneratorUtilities.GetKeyGenerator(AOids[LI]);

    LK := TParameterUtilities.CreateKeyParameter(AOids[LI], LKg.GenerateKey());

    LCp := LK;

    if System.Pos('/ECB/', ANames[LI]) = 0 then
    begin
      System.SetLength(LIV, 16);
      LCp := TParametersWithIV.Create(LCp, LIV);
    end;

    LC1.Init(True, LCp);
    LC2.Init(False, LCp);

    LResult := LC2.DoFinal(LC1.DoFinal(LData));

    if (not AreEqual(LData, LResult)) then
    begin
      Fail('failed OID test');
    end;

    if (System.Length(LK.GetKey()) <> (16 + ((LI div AGroupSize) * 8))) then
    begin
      Fail('failed key length test');
    end;
    System.Inc(LI);
  end;
end;

procedure TTestAES.DoCipherTest(AStrength: Int32; const AKeyBytes,
  AInput, AOutput: TBytes);
var
  LKey: IKeyParameter;
  LInCipher, LOutCipher: IBufferedCipher;
  LEncBytes, LDecBytes: TBytes;
begin
  LKey := TParameterUtilities.CreateKeyParameter('AES', AKeyBytes);

  LOutCipher := TCipherUtilities.GetCipher('AES/ECB/NoPadding');
  LInCipher := TCipherUtilities.GetCipher('AES/ECB/NoPadding');

  LOutCipher.Init(True, LKey);
  LInCipher.Init(False, LKey);

  LEncBytes := LOutCipher.DoFinal(AInput);

  if (not AreEqual(LEncBytes, AOutput)) then
  begin
    Fail(Format('AES failed encryption - expected %s got %s',
      [EncodeHex(AOutput), EncodeHex(LEncBytes)]));
  end;

  LDecBytes := LInCipher.DoFinal(LEncBytes);

  if (not AreEqual(LDecBytes, AInput)) then
  begin
    Fail(Format('AES failed decryption - expected %s got %s',
      [EncodeHex(AInput), EncodeHex(LDecBytes)]));
  end;
end;

procedure TTestAES.DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
  const AKek, AInput, AOutput: TBytes);
begin
  DoWrapTest(AId, AWrappingAlgorithm, AKek, nil, nil, AInput, AOutput);
end;

procedure TTestAES.DoWrapTest(AId: Int32; const AWrappingAlgorithm: String;
  const AKek, AIV: TBytes; const ARandom: IFixedSecureRandom;
  const AInput, AOutput: TBytes);
var
  LWrapper: IWrapper;
  LCp, LUnwrapCp: ICipherParameters;
  LCText, LPText: TBytes;
begin
  LWrapper := TWrapperUtilities.GetWrapper(AWrappingAlgorithm);

  LCp := TParameterUtilities.CreateKeyParameter('AES', AKek);

  if AIV <> nil then
    LCp := TParametersWithIV.Create(LCp, AIV);

  LUnwrapCp := LCp;

  if ARandom <> nil then
    LCp := TParameterUtilities.WithRandom(LCp, ARandom);

  LWrapper.Init(True, LCp);

  LCText := LWrapper.Wrap(AInput, 0, System.Length(AInput));
  if (not AreEqual(LCText, AOutput)) then
  begin
    Fail(Format('failed wrap test %d expected %s got %s',
      [AId, EncodeHex(AOutput), EncodeHex(LCText)]));
  end;

  LWrapper.Init(False, LUnwrapCp);

  LPText := LWrapper.Unwrap(AOutput, 0, System.Length(AOutput));
  if (not AreEqual(LPText, AInput)) then
  begin
    Fail(Format('failed unwrap test %d expected %s got %s',
      [AId, EncodeHex(AInput), EncodeHex(LPText)]));
  end;
end;

procedure TTestAES.DoWrapOidTest(const AOids: TCryptoLibStringArray;
  const AName: String);
var
  LData: TBytes;
  LI: Int32;
  LC1, LC2: IWrapper;
  LKg: ICipherKeyGenerator;
  LK: IKeyParameter;
  LWrapped, LUnwrapped: TBytes;
begin
  LData := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16);

  for LI := 0 to System.Length(AOids) - 1 do
  begin
    LC1 := TWrapperUtilities.GetWrapper(AOids[LI]);
    LC2 := TWrapperUtilities.GetWrapper(AName);
    LKg := TGeneratorUtilities.GetKeyGenerator(AOids[LI]);

    LK := TParameterUtilities.CreateKeyParameter(AOids[LI], LKg.GenerateKey());

    LC1.Init(True, LK);
    LC2.Init(False, LK);

    LWrapped := LC1.Wrap(LData, 0, System.Length(LData));
    LUnwrapped := LC2.Unwrap(LWrapped, 0, System.Length(LWrapped));

    if (not AreEqual(LData, LUnwrapped)) then
    begin
      Fail('failed wrap OID test');
    end;

    if (System.Length(LK.GetKey()) <> (16 + (LI * 8))) then
    begin
      Fail('failed key length test');
    end;
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

procedure TTestAES.TestBlockCipherVector;
begin
  RunBlockCipherVectorTests(@CreateAesEngine, 'TAesEngine');
end;

procedure TTestAES.TestMonteCarloAES;
begin
  RunBlockCipherMonteCarloTests(@CreateAesEngine, 'TAesEngine');
end;

procedure TTestAES.TestBadParameters;
begin
  AssertEngineRejectsBadParameters(@CreateAesEngine, 'TAesEngine');
end;

procedure TTestAES.TestCiphers;
var
  LI: Int32;
begin
  LI := 0;
  while LI <> System.Length(FCipherTestVectors) do
  begin
    DoCipherTest(StrToInt(FCipherTestVectors[LI]),
      DecodeHex(FCipherTestVectors[LI + 1]),
      DecodeHex(FCipherTestVectors[LI + 2]),
      DecodeHex(FCipherTestVectors[LI + 3]));
    System.Inc(LI, 4);
  end;
end;

procedure TTestAES.TestOids;
var
  LOids, LNames: TCryptoLibStringArray;
begin
  LOids := TCryptoLibStringArray.Create(
    TNistObjectIdentifiers.IdAes128Ecb.Id,
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

  LNames := TCryptoLibStringArray.Create(
    'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding',
    'AES/OFB/NoPadding', 'AES/CFB/NoPadding',
    'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding',
    'AES/OFB/NoPadding', 'AES/CFB/NoPadding',
    'AES/ECB/PKCS7Padding', 'AES/CBC/PKCS7Padding',
    'AES/OFB/NoPadding', 'AES/CFB/NoPadding');

  DoOidTest(LOids, LNames, 4);
end;

procedure TTestAES.TestAES_CBC_NOPADDING_WITH_IV;
var
  LCipher: IBufferedCipher;
  LEngine: IAesEngine;
  LBlockCipher: ICbcBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TCbcBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher);

  RunNist80038A_Vectors(LCipher, TNistSp80038aAesTestData.OfficialIV_CBC,
    TNistSp80038aAesTestData.OfficialCT_CBC, True, False,
    'NIST SP 800-38A AES/CBC NoPadding');
end;

procedure TTestAES.TestAES_CBC_PKCS7PADDING_WITH_IV;
var
  LCipher: IBufferedCipher;
begin
  LCipher := TCipherUtilities.GetCipher('AES/CBC/PKCS7PADDING');

  RunNist80038A_Vectors(LCipher, TNistSp80038aAesTestData.OfficialIV_CBC,
    TNistSp80038aAesTestData.OfficialCT_CBC, True, True,
    'NIST SP 800-38A AES/CBC PKCS7Padding');
end;

procedure TTestAES.TestAES_CFB_NOPADDING_WITH_IV;
var
  LCipher: IBufferedCipher;
  LEngine: IAesEngine;
  LBlockCipher: ICfbBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TCfbBlockCipher.Create(LEngine, LEngine.GetBlockSize * 8);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher);

  RunNist80038A_Vectors(LCipher, TNistSp80038aAesTestData.OfficialIV_CFB,
    TNistSp80038aAesTestData.OfficialCT_CFB, True, False,
    'NIST SP 800-38A AES/CFB NoPadding');
end;

procedure TTestAES.TestAES_CTR_NOPADDING_WITH_IV;
var
  LCipher: IBufferedCipher;
  LEngine: IAesEngine;
  LBlockCipher: ISicBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TSicBlockCipher.Create(LEngine);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher);

  RunNist80038A_Vectors(LCipher, TNistSp80038aAesTestData.OfficialIV_CTR,
    TNistSp80038aAesTestData.OfficialCT_CTR, True, False,
    'NIST SP 800-38A AES/CTR NoPadding');
end;

procedure TTestAES.TestAES_ECB_NOPADDING_NO_IV;
var
  LCipher: IBufferedCipher;
  LEngine: IAesEngine;
  LBlockCipher: IBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := LEngine as IBlockCipher;
  LCipher := TBufferedBlockCipher.Create(LBlockCipher);

  RunNist80038A_Vectors(LCipher, nil, TNistSp80038aAesTestData.OfficialCT_ECB,
    False, False, 'NIST SP 800-38A AES/ECB NoPadding');
end;

procedure TTestAES.TestAES_OFB_NOPADDING_WITH_IV;
var
  LCipher: IBufferedCipher;
  LEngine: IAesEngine;
  LBlockCipher: IOfbBlockCipher;
begin
  LEngine := TAesEngine.Create();
  LBlockCipher := TOfbBlockCipher.Create(LEngine, LEngine.GetBlockSize * 8);
  LCipher := TBufferedBlockCipher.Create(LBlockCipher);

  RunNist80038A_Vectors(LCipher, TNistSp80038aAesTestData.OfficialIV_OFB,
    TNistSp80038aAesTestData.OfficialCT_OFB, True, False,
    'NIST SP 800-38A AES/OFB NoPadding');
end;

procedure TTestAES.TestWrap;
begin
  DoWrapTest(1, 'AESWrap',
    DecodeHex('000102030405060708090a0b0c0d0e0f'),
    DecodeHex('00112233445566778899aabbccddeeff'),
    DecodeHex('1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5'));
end;

procedure TTestAES.TestWrapRfc3211;
var
  LKek: TBytes;
begin
  LKek := DecodeHex('000102030405060708090a0b0c0d0e0f');
  DoWrapTest(2, 'AESRFC3211WRAP',
    LKek, LKek,
    TFixedSecureRandom.From(
      TCryptoLibMatrixByteArray.Create(
        DecodeHex('9688df2af1b7b1ac9688df2a'))),
    DecodeHex('00112233445566778899aabbccddeeff'),
    DecodeHex('7c8798dfc802553b3f00bb4315e3a087322725c92398b9c112c74d0925c63b61'));
end;

procedure TTestAES.TestWrapRfc5649;
begin
  DoWrapTest(3, 'AESWrapPad',
    DecodeHex('5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8'),
    DecodeHex('c37b7e6492584340bed12207808941155068f738'),
    DecodeHex('138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a'));
end;

procedure TTestAES.TestWrapOids;
var
  LWrapOids: TCryptoLibStringArray;
begin
  LWrapOids := TCryptoLibStringArray.Create(
    TNistObjectIdentifiers.IdAes128Wrap.Id,
    TNistObjectIdentifiers.IdAes192Wrap.Id,
    TNistObjectIdentifiers.IdAes256Wrap.Id);

  DoWrapOidTest(LWrapOids, 'AESWrap');
end;

procedure TTestAES.TestWrapPadOids;
var
  LWrapPadOids: TCryptoLibStringArray;
begin
  LWrapPadOids := TCryptoLibStringArray.Create(
    TNistObjectIdentifiers.IdAes128WrapPad.Id,
    TNistObjectIdentifiers.IdAes192WrapPad.Id,
    TNistObjectIdentifiers.IdAes256WrapPad.Id);

  DoWrapOidTest(LWrapPadOids, 'AESWrapPad');
end;

procedure TTestAES.TestAesEax;
begin
  DoCipherUtilitiesAeadRoundTrip('AES/EAX/NoPadding',
    DecodeHex('233952DEE4D5ED5F9B9C6D6FF80FF478'),
    DecodeHex('62EC67F9C3A4A407FCB2A8C49031A8B3'),
    DecodeHex('68656c6c6f20776f726c642121'),
    DecodeHex('2f9f76cb7659c70e4be11670a3e193ae1bc6b5762a'),
    'AES/EAX CipherUtilities smoke');
end;

procedure TTestAES.TestAesEaxBadPadding;
begin
  ExpectGetCipherSecurityFailure('AES/EAX/PKCS5Padding', 'AES/EAX');
end;

procedure TTestAES.TestAesCcm;
begin
  DoCipherUtilitiesAeadRoundTrip('AES/CCM/NoPadding',
    DecodeHex('404142434445464748494A4B4C4D4E4F'),
    DecodeHex('10111213141516'),
    DecodeHex('68656c6c6f20776f726c642121'),
    DecodeHex('39264f148b54c456035de0a531c8344f46db12b388'),
    'AES/CCM CipherUtilities smoke');
end;

procedure TTestAES.TestAesCcmBadPadding;
begin
  ExpectGetCipherSecurityFailure('AES/CCM/PKCS5Padding', 'AES/CCM');
end;

procedure TTestAES.TestAesOcb;
begin
  DoCipherUtilitiesAeadRoundTrip('AES/OCB/NoPadding',
    DecodeHex('000102030405060708090A0B0C0D0E0F'),
    DecodeHex('000102030405060708090A0B'),
    DecodeHex('000102030405060708090A0B0C0D0E0F'),
    DecodeHex('BEA5E8798DBE7110031C144DA0B2612213CC8B747807121A4CBB3E4BD6B456AF'),
    'AES/OCB CipherUtilities smoke');
end;

procedure TTestAES.TestAesOcbBadPadding;
begin
  ExpectGetCipherSecurityFailure('AES/OCB/PKCS5Padding', 'AES/OCB');
end;

procedure TTestAES.TestAesGcm;
begin
  DoCipherUtilitiesAeadRoundTrip('AES/GCM/NoPadding',
    DecodeHex(
      'feffe9928665731c6d6a8f9467308308' +
      'feffe9928665731c6d6a8f9467308308'),
    DecodeHex('cafebabefacedbaddecaf888'),
    DecodeHex(
      'd9313225f88406e5a55909c5aff5269a' +
      '86a7a9531534f7da2e4c303d8a318a72' +
      '1c3c0c95956809532fcf0e2449a6b525' +
      'b16aedf5aa0de657ba637b391aafd255'),
    DecodeHex(
      '522dc1f099567d07f47f37a32a84427d' +
      '643a8cdcbfe5c0c97598a2bd2555d1aa' +
      '8cb08e48590dbb3da7b08b1056828838' +
      'c5f61e6393ba7a0abcc9f662898015ad' +
      'b094dac5d93471bdec1a502270e3cc6c'),
    'AES/GCM CipherUtilities McGrew-Viega case 15');
end;

procedure TTestAES.TestAesGcmBadPadding;
begin
  ExpectGetCipherSecurityFailure('AES/GCM/PKCS5Padding', 'AES/GCM');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAES);
{$ELSE}
  RegisterTest(TTestAES.Suite);
{$ENDIF FPC}

end.
