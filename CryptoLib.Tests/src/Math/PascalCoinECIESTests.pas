unit PascalCoinECIESTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  TypInfo,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpECC,
  ClpIECC,
  ClpIESEngine,
  ClpIIESCipher,
  ClpIESCipher,
  ClpIECDHBasicAgreement,
  ClpECDHBasicAgreement,
  ClpECPrivateKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpECPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpECDomainParameters,
  ClpIECDomainParameters,
  ClpIBufferedBlockCipher,
  ClpPaddedBufferedBlockCipher,
  ClpBlockCipherModes,
  ClpIBlockCipherModes,
  ClpAesEngine,
  ClpIAesEngine,
  ClpBigInteger,
  ClpCustomNamedCurves,
  ClpDigestUtilities,
  ClpIIESParameterSpec,
  ClpIESParameterSpec,
  ClpIPascalCoinIESEngine,
  ClpPascalCoinIESEngine,
  ClpPascalCoinECIESKdfBytesGenerator,
  ClpIPascalCoinECIESKdfBytesGenerator,
  ClpPaddingModes,
  ClpIPaddingModes,
  ClpIMac,
  ClpMacUtilities,
  ClpIX9ECParameters,
  ClpConverters,
  CryptoLibTestBase;

type

  /// <summary>
  /// Test for PascalCoin ECIES - PascalCoin Elliptic Curve Integrated Encryption Scheme
  /// Test vectors were gotten from the PascalCoin TESTNET Wallet.
  /// </summary>
  TTestPascalCoinECIES = class(TCryptoLibAlgorithmTestCase)
  private

    type
{$SCOPEDENUMS ON}
    TKeyType = (SECP256K1, SECP384R1, SECP521R1, SECT283K1);
{$SCOPEDENUMS OFF}

  const
    SHORT_MESSAGE: String = 'shortmessage';
    LONG_MESSAGE
      : String =
      'longmessagelongmessagelongmessagelongmessagelongmessagelongmessage';

  var
    FRandom: ISecureRandom;

    function GetCurveFromKeyType(keyType: TKeyType): IX9ECParameters;
    function GetPascalCoinIESParameterSpec: IIESParameterSpec;
    function GetECIESPascalCoinCompatibilityEngine: IPascalCoinIESEngine;

    function RecreatePublicKeyFromAffineXandAffineYCoord(keyType: TKeyType;
      const RawAffineX, RawAffineY: TBytes): IECPublicKeyParameters;

    function RecreatePrivateKeyFromByteArray(keyType: TKeyType;
      const RawPrivateKey: TBytes): IECPrivateKeyParameters;

    function DoPascalCoinECIESEncrypt(keyType: TKeyType;
      const RawAffineXCoord, RawAffineYCoord, PayloadToEncrypt: String): String;

    function DoPascalCoinECIESDecrypt(keyType: TKeyType;
      const RawPrivateKey, PayloadToDecrypt: String): String;

    procedure DoTestPascalCoinECIESDecrypt(const id: String; keyType: TKeyType;
      const RawPrivateKey, PayloadToDecrypt, ExpectedOutput: String);

    procedure DoTestPascalCoinECIESEncryptDecrypt(const id: String;
      keyType: TKeyType; const RawPrivateKey, RawAffineXCoord, RawAffineYCoord,
      PayloadToEncrypt: String);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestPacalCoinECIESDecrypt;
    procedure TestPacalCoinECIESEncryptDecrypt;

  end;

implementation

{ TTestPascalCoinECIES }

procedure TTestPascalCoinECIES.SetUp;
begin
  inherited;
  FRandom := TSecureRandom.Create();
end;

procedure TTestPascalCoinECIES.TearDown;
begin
  inherited;
  FRandom := Nil;
end;

function TTestPascalCoinECIES.GetCurveFromKeyType(keyType: TKeyType)
  : IX9ECParameters;
var
  CurveName: string;
begin
  CurveName := GetEnumName(TypeInfo(TKeyType), Ord(keyType));
  Result := TCustomNamedCurves.GetByName(CurveName);
end;

function TTestPascalCoinECIES.GetPascalCoinIESParameterSpec: IIESParameterSpec;
var
  Derivation, Encoding, IVBytes: TBytes;
  MacKeySizeInBits, CipherKeySizeInBits: Int32;
  UsePointCompression: boolean;
begin
  // Set up IES Parameter Spec For Compatibility With PascalCoin Current Implementation

  // The derivation and encoding vectors are used when initialising the KDF and MAC.
  // They're optional but if used then they need to be known by the other user so that
  // they can decrypt the ciphertext and verify the MAC correctly. The security is based
  // on the shared secret coming from the (static-ephemeral) ECDH key agreement.
  Derivation := nil;

  Encoding := nil;

  System.SetLength(IVBytes, 16); // using Zero Initialized IV for compatibility

  MacKeySizeInBits := 32 * 8;

  // Since we are using AES256_CBC for compatibility
  CipherKeySizeInBits := 32 * 8;

  // whether to use point compression when deriving the octets string
  // from a point or not in the EphemeralKeyPairGenerator
  UsePointCompression := True; // for compatibility

  Result := TIESParameterSpec.Create(Derivation, Encoding, MacKeySizeInBits,
    CipherKeySizeInBits, IVBytes, UsePointCompression);
end;

function TTestPascalCoinECIES.GetECIESPascalCoinCompatibilityEngine
  : IPascalCoinIESEngine;
var
  cipher: IBufferedBlockCipher;
  AesEngine: IAesEngine;
  blockCipher: ICbcBlockCipher;
  ECDHBasicAgreementInstance: IECDHBasicAgreement;
  KDFInstance: IPascalCoinECIESKdfBytesGenerator;
  DigestMACInstance: IMac;

begin
  // Set up IES Cipher Engine For Compatibility With PascalCoin

  ECDHBasicAgreementInstance := TECDHBasicAgreement.Create();

  KDFInstance := TPascalCoinECIESKdfBytesGenerator.Create
    (TDigestUtilities.GetDigest('SHA-512'));

  DigestMACInstance := TMacUtilities.GetMac('HMAC-MD5');

  // Set Up Block Cipher
  AesEngine := TAesEngine.Create(); // AES Engine

  blockCipher := TCbcBlockCipher.Create(AesEngine); // CBC

  cipher := TPaddedBufferedBlockCipher.Create(blockCipher,
    TZeroBytePadding.Create() as IZeroBytePadding); // ZeroBytePadding

  Result := TPascalCoinIESEngine.Create(ECDHBasicAgreementInstance, KDFInstance,
    DigestMACInstance, cipher);
end;

function TTestPascalCoinECIES.RecreatePublicKeyFromAffineXandAffineYCoord
  (keyType: TKeyType; const RawAffineX, RawAffineY: TBytes)
  : IECPublicKeyParameters;
var
  domain: IECDomainParameters;
  LCurve: IX9ECParameters;
  point: IECPoint;
  BigXCoord, BigYCoord: TBigInteger;
begin
  LCurve := GetCurveFromKeyType(keyType);
  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  BigXCoord := TBigInteger.Create(1, RawAffineX);
  BigYCoord := TBigInteger.Create(1, RawAffineY);

  point := LCurve.Curve.CreatePoint(BigXCoord, BigYCoord);

  Result := TECPublicKeyParameters.Create('ECDSA', point, domain);
end;

function TTestPascalCoinECIES.RecreatePrivateKeyFromByteArray(keyType: TKeyType;
  const RawPrivateKey: TBytes): IECPrivateKeyParameters;
var
  domain: IECDomainParameters;
  LCurve: IX9ECParameters;
  PrivD: TBigInteger;
begin
  LCurve := GetCurveFromKeyType(keyType);
  domain := TECDomainParameters.Create(LCurve.Curve, LCurve.G, LCurve.N,
    LCurve.H, LCurve.GetSeed);

  PrivD := TBigInteger.Create(1, RawPrivateKey);

  Result := TECPrivateKeyParameters.Create('ECDSA', PrivD, domain);
end;

function TTestPascalCoinECIES.DoPascalCoinECIESEncrypt(keyType: TKeyType;
  const RawAffineXCoord, RawAffineYCoord, PayloadToEncrypt: String): String;
var
  CipherEncrypt: IIESCipher;
begin
  // Encryption
  CipherEncrypt := TIESCipher.Create(GetECIESPascalCoinCompatibilityEngine());
  CipherEncrypt.Init(True, RecreatePublicKeyFromAffineXandAffineYCoord(keyType,
    DecodeHex(RawAffineXCoord), DecodeHex(RawAffineYCoord)),
    GetPascalCoinIESParameterSpec(), FRandom);
  Result := EncodeHex(CipherEncrypt.DoFinal(TConverters.ConvertStringToBytes
    (PayloadToEncrypt, TEncoding.ASCII)));
end;

function TTestPascalCoinECIES.DoPascalCoinECIESDecrypt(keyType: TKeyType;
  const RawPrivateKey, PayloadToDecrypt: String): String;
var
  CipherDecrypt: IIESCipher;
begin
  try
    // Decryption
    CipherDecrypt := TIESCipher.Create(GetECIESPascalCoinCompatibilityEngine());
    CipherDecrypt.Init(False, RecreatePrivateKeyFromByteArray(keyType,
      DecodeHex(RawPrivateKey)), GetPascalCoinIESParameterSpec(), FRandom);

    Result := TConverters.ConvertBytesToString
      (CipherDecrypt.DoFinal(DecodeHex(PayloadToDecrypt)), TEncoding.ASCII);
  except
    // should only happen if decryption fails
    raise;
  end;
end;

procedure TTestPascalCoinECIES.DoTestPascalCoinECIESDecrypt(const id: String;
  keyType: TKeyType; const RawPrivateKey, PayloadToDecrypt,
  ExpectedOutput: String);
var
  DecryptedPayload: String;
begin
  DecryptedPayload := DoPascalCoinECIESDecrypt(keyType, RawPrivateKey,
    PayloadToDecrypt);
  CheckEquals(ExpectedOutput, DecryptedPayload,
    Format('Test %s Failed, Expected "%s" but got "%s"', [id + '_Decrypt',
    ExpectedOutput, DecryptedPayload]));
end;

procedure TTestPascalCoinECIES.DoTestPascalCoinECIESEncryptDecrypt
  (const id: String; keyType: TKeyType; const RawPrivateKey, RawAffineXCoord,
  RawAffineYCoord, PayloadToEncrypt: String);
var
  ActualOutput: String;
begin
  ActualOutput := DoPascalCoinECIESDecrypt(keyType, RawPrivateKey,
    DoPascalCoinECIESEncrypt(keyType, RawAffineXCoord, RawAffineYCoord,
    PayloadToEncrypt));

  CheckEquals(PayloadToEncrypt, ActualOutput,
    Format('Test %s Failed, Expected "%s" but got "%s"',
    [id + '_EncryptDecrypt', PayloadToEncrypt, ActualOutput]));
end;

procedure TTestPascalCoinECIES.TestPacalCoinECIESDecrypt;
begin
  DoTestPascalCoinECIESDecrypt('1', TKeyType.SECP256K1,
    '5EEBDD98BBD3F96A1A69020F58C147624AF27F9E9831F05EC42A190DD2FB0DF1',
    '21100C001000025ED19E944D69BA45269855B9F73042E0DCCB50C3EE5B103A2FF3762F9B3540B43D39F0DCA42C53C90F57BC15FED1E5E4490B59FD0E0657E7DBDE5C1C57E40411',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESDecrypt('2', TKeyType.SECP256K1,
    '5EEBDD98BBD3F96A1A69020F58C147624AF27F9E9831F05EC42A190DD2FB0DF1',
    '21104200500003CC2EFCBE845C6AF6DD27074DC283E5B118874F0A53BE634C509E6D2D9487E8281824CE68560A3C12D36D502DB5A55905F7DC3E67967E10D590F3EFBDE1F3A'
    + 'D0337ACE569F773C77A18B045B4D4285B5C3B52AAE0BD0C68169C4AB684DA7CF3B73D5C8643EFF99B6F00128B01255B08D83995C1A79C6B2AA0B412343C95CF30B0',
    LONG_MESSAGE);

  DoTestPascalCoinECIESDecrypt('3', TKeyType.SECP384R1,
    '889ED91943C05D599DA1CEF146D68495E650F800B74B6310AD9614DC55E2ABE01604E3398E548E0D4AD82A887070B787',
    '31100C001000021E6A7EBF798DEFF9411940BFFA3B82F8F555165B5BD5CCF8A7CA8E661E2057FB5E721E30D3CC187E97988524370560F8E85CAAF9B640FB277A92780BB2D34DDE49AD19FA53FE9A8CC867731846FE0C4F',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESDecrypt('4', TKeyType.SECP384R1,
    '889ED91943C05D599DA1CEF146D68495E650F800B74B6310AD9614DC55E2ABE01604E3398E548E0D4AD82A887070B787',
    '31104200500003C1CC4FCB1B6B32EACF9EBBFD22D4904055D454263A475261EB4F1BA8008F9E2C6D8B468B7A36BF3DE6D284C07C1CB431887'
    + '1F197A4CFC055E3312845BCFACB4F185EA02D5D443CE021B76F560D86209D44FF828B2905D4FA30B0873ADA758983F59E25E25598C85C2253B7BAC35B722CAD1F80545FB315C95016FB440559FF626086B7BA09A51481A7B77BF4B129E579',
    LONG_MESSAGE);

  DoTestPascalCoinECIESDecrypt('5', TKeyType.SECP521R1,
    '6316522337DA679C1EF338E54509C19793FC3C02D53F12AF79322086AAA4AA2BAD8108EDA2000763DC99C6DA1909712C2E96A9F2BAB7502BCD2DDD7B39880F0808',
    '43100C00100003013D32C1BACF719D45829502FAD8D7A5FBED41EF6E212E6D1FCC55B70552BF85B6F71A4A045221D36D47C1E538217A80B4918E76C9E84191359419BAE0FBDB3ADB56ABE37C5F02BEA79FDAEF3D5E5312B6A932F57973AF25D58CF42E0C7F2877C711',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESDecrypt('6', TKeyType.SECP521R1,
    '6316522337DA679C1EF338E54509C19793FC3C02D53F12AF79322086AAA4AA2BAD8108EDA2000763DC99C6DA1909712C2E96A9F2BAB7502BCD2DDD7B39880F0808',
    '4310420050000301838307131DF82CF6D23C07AA4A12261784399E2D011C87969E2388659A95A54C11E08C34F49D651D4E5C87106D367C01CB60C7146D20FE60098913074A78519DF182F3BA0A4A097FD11F11D9FC09D1C4586D178082AAC68B2A4BAC012992D3A'
    + '44ACBCC322E3C3F86BD728A3570B3C24696464088EAE8A82A6EAC5BB444DD28E322351C801D61673B9B8776C190E0FCD468C906448680B3094BD692EC0CA4700361',
    LONG_MESSAGE);

  DoTestPascalCoinECIESDecrypt('7', TKeyType.SECT283K1,
    '0121EFFE82FE34BA6D1B5635903924801CADD54EF2804B56624BB8C0BFBF9F33BB42EADD',
    '25100C00100002079DF758857C4CC50D10A94D25CBD219E752BBD08EB30D61158765200D54CEA6BB5157F95CEB540F0698AF56E7DBD2E612F9C7CBDBC4364C343661F0B4A50309FCA05303',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESDecrypt('8', TKeyType.SECT283K1,
    '0121EFFE82FE34BA6D1B5635903924801CADD54EF2804B56624BB8C0BFBF9F33BB42EADD',
    '25104200500003067C595E47EEC68264B1FD4AC181F5CB2632C88AC5F03ED2F532B5513F0EA7A274E6F53A4F16B6FC9341B79577C11E205F7BF12CEC5F339FA20163E8D6EDB4AD07595AEEDE9EAABDB'
    + '5468D9CA50F2667313024669580D67C532284A687A2C1172F656B5C144B8E7A4D8206A8D8266164963B74F846A00FDE4268CE7E41C6145ECB38F1DE',
    LONG_MESSAGE);

end;

procedure TTestPascalCoinECIES.TestPacalCoinECIESEncryptDecrypt;
begin
  DoTestPascalCoinECIESEncryptDecrypt('1', TKeyType.SECP256K1,
    '5EEBDD98BBD3F96A1A69020F58C147624AF27F9E9831F05EC42A190DD2FB0DF1',
    '327D9618E226B991E47BA2EF81CEC0AFC0436E3CC22F04454749FCA2AFBB52F7',
    'BE70064DAB4A2A0681889F1EE51B6BB2348A394317EAC2BEA38E6ABC2D78D307',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESEncryptDecrypt('2', TKeyType.SECP256K1,
    '5EEBDD98BBD3F96A1A69020F58C147624AF27F9E9831F05EC42A190DD2FB0DF1',
    '327D9618E226B991E47BA2EF81CEC0AFC0436E3CC22F04454749FCA2AFBB52F7',
    'BE70064DAB4A2A0681889F1EE51B6BB2348A394317EAC2BEA38E6ABC2D78D307',
    LONG_MESSAGE);

  DoTestPascalCoinECIESEncryptDecrypt('3', TKeyType.SECP384R1,
    '889ED91943C05D599DA1CEF146D68495E650F800B74B6310AD9614DC55E2ABE01604E3398E548E0D4AD82A887070B787',
    'F9BB6DD66F26E406AADDC666A65229904A22BA500EACC3D6FA2B7BD4E7D33204BBE87741462258CCD8FB32F43D52ABF0',
    'F7AB9F5D3676FC98946F35269BD73082A57ABF4B66864C703DACB238EA4FBEE2390399C655C6CDAABB26FCD34FD749D7',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESEncryptDecrypt('4', TKeyType.SECP384R1,
    '889ED91943C05D599DA1CEF146D68495E650F800B74B6310AD9614DC55E2ABE01604E3398E548E0D4AD82A887070B787',
    'F9BB6DD66F26E406AADDC666A65229904A22BA500EACC3D6FA2B7BD4E7D33204BBE87741462258CCD8FB32F43D52ABF0',
    'F7AB9F5D3676FC98946F35269BD73082A57ABF4B66864C703DACB238EA4FBEE2390399C655C6CDAABB26FCD34FD749D7',
    LONG_MESSAGE);

  DoTestPascalCoinECIESEncryptDecrypt('5', TKeyType.SECP521R1,
    '6316522337DA679C1EF338E54509C19793FC3C02D53F12AF79322086AAA4AA2BAD8108EDA2000763DC99C6DA1909712C2E96A9F2BAB7502BCD2DDD7B39880F0808',
    '014919D3527C3D31FF9EE84D5009E9BA4977B6E6C075EB454B2BA086E75605D88F895247F8E3968F3C26B840D806DB2A6FCFAE96D90A80A955BC277FEA0D69A086BE',
    '01FDA4AFC30977BF0B57CD3202497880D905AF6BF9CFD275EAE5CD6E68E639D4DEBE12C3EA3EA2ED13803D5751FED86C2F35952DBDC935A85C75FEBC371B01698097',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESEncryptDecrypt('6', TKeyType.SECP521R1,
    '6316522337DA679C1EF338E54509C19793FC3C02D53F12AF79322086AAA4AA2BAD8108EDA2000763DC99C6DA1909712C2E96A9F2BAB7502BCD2DDD7B39880F0808',
    '014919D3527C3D31FF9EE84D5009E9BA4977B6E6C075EB454B2BA086E75605D88F895247F8E3968F3C26B840D806DB2A6FCFAE96D90A80A955BC277FEA0D69A086BE',
    '01FDA4AFC30977BF0B57CD3202497880D905AF6BF9CFD275EAE5CD6E68E639D4DEBE12C3EA3EA2ED13803D5751FED86C2F35952DBDC935A85C75FEBC371B01698097',
    LONG_MESSAGE);

  DoTestPascalCoinECIESEncryptDecrypt('7', TKeyType.SECT283K1,
    '0121EFFE82FE34BA6D1B5635903924801CADD54EF2804B56624BB8C0BFBF9F33BB42EADD',
    '01747F38A49C099DA25231AE47F0820216EDEC6F6DB51A28280ABDCC65B652D76529BB88',
    '05535E7555704E2EAA1C3A29FCF50622D67F65DDB1EA294D92C4BDDEE403DE379E26B280',
    SHORT_MESSAGE);

  DoTestPascalCoinECIESEncryptDecrypt('8', TKeyType.SECT283K1,
    '0121EFFE82FE34BA6D1B5635903924801CADD54EF2804B56624BB8C0BFBF9F33BB42EADD',
    '01747F38A49C099DA25231AE47F0820216EDEC6F6DB51A28280ABDCC65B652D76529BB88',
    '05535E7555704E2EAA1C3A29FCF50622D67F65DDB1EA294D92C4BDDEE403DE379E26B280',
    LONG_MESSAGE);
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestPascalCoinECIES);
{$ELSE}
  RegisterTest(TTestPascalCoinECIES.Suite);
{$ENDIF FPC}

end.
