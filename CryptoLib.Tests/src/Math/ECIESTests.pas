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

unit ECIESTests;

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
  ClpECCurve,
  ClpIECCommon,
  ClpIHMac,
  ClpHMac,
  ClpIESEngine,
  ClpIIESEngine,
  ClpICipherParameters,
  ClpIECDHBasicAgreement,
  ClpECDHBasicAgreement,
  ClpParametersWithIV,
  ClpKDF2BytesGenerator,
  ClpIKDF2BytesGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpECGenerators,
  ClpIECGenerators,
  ClpECParameters,
  ClpIECParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIKeyGenerationParameters,
  ClpIesParameters,
  ClpIBufferedBlockCipher,
  ClpPaddedBufferedBlockCipher,
  ClpEphemeralKeyPairGenerator,
  ClpIEphemeralKeyPairGenerator,
  ClpECIESPublicKeyParser,
  ClpIECIESPublicKeyParser,
  ClpCbcBlockCipher,
  ClpICbcBlockCipher,
  ClpECKeyEncoder,
  ClpIKeyEncoder,
  ClpAesUtilities,
  ClpBigInteger,
  ClpDigestUtilities,
  ClpCryptoLibTypes,
  ClpArrayUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  CryptoLibTestBase;

type

  /// <summary>
  /// test for ECIES - Elliptic Curve Integrated Encryption Scheme
  /// </summary>
  TTestECIES = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FAES_IV: TBytes;

    procedure DoStaticTest(const iv: TBytes);
    procedure DoShortTest();
    procedure DoForgeryTest();
    procedure DoTest(const p1, p2: IAsymmetricCipherKeyPair);
    procedure DoEphemeralTest(const iv: TBytes; usePointCompression: Boolean);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestECIES;
    procedure TestForgery;

  end;

implementation

{ TTestECIES }

procedure TTestECIES.DoEphemeralTest(const iv: TBytes;
  usePointCompression: Boolean);
var
  n: TBigInteger;
  curve: IFpCurve;
  params: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  p1: IAsymmetricCipherKeyPair;
  p: ICipherParameters;
  i1, i2: IIesEngine;
  d, e, &message, out1, out2: TBytes;
  gen: IECKeyPairGenerator;
  ephKeyGen: IEphemeralKeyPairGenerator;
  c1, c2: IBufferedBlockCipher;
begin
  n := TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6277101735386680763835789423207666416083908700390324961279'), // q
    TBigInteger.Create('fffffffffffffffffffffffffffffffefffffffffffffffc', 16),
    // a
    TBigInteger.Create('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1', 16),
    // b
    n, TBigInteger.One);

  params := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012')), // G
    n);

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('651056770906015076056810763456358567190100156695615665659'), // d
    params);

  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex('0262b12d60690cdcf330babab6e69763b471f994dd702d16a5')), // Q
    params);

  p1 := TAsymmetricCipherKeyPair.Create(pubKey, priKey);


  // Generate the ephemeral key pair

  gen := TECKeyPairGenerator.Create();
  gen.Init(TECKeyGenerationParameters.Create(params, TSecureRandom.Create()
    as ISecureRandom) as IECKeyGenerationParameters);

  ephKeyGen := TEphemeralKeyPairGenerator.Create(gen,
    TECKeyEncoder.Create(usePointCompression) as IKeyEncoder);

  //
  // stream test
  //
  i1 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  i2 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  d := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  e := TBytes.Create(8, 7, 6, 5, 4, 3, 2, 1);
  p := TIesParameters.Create(d, e, 64);

  i1.Init(p1.Public, p, ephKeyGen);
  i2.Init(p1.Private, p, TECIESPublicKeyParser.Create(params)
    as IECIESPublicKeyParser);

  &message := DecodeHex('1234567890abcdef');

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));
  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('stream cipher test failed');
  end;

  //
  // AES with CBC
  //

  c1 := TPaddedBufferedBlockCipher.Create
    (TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher);

  c2 := TPaddedBufferedBlockCipher.Create
    (TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher);

  i1 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac, c1);

  i2 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac, c2);

  d := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  e := TBytes.Create(8, 7, 6, 5, 4, 3, 2, 1);
  p := TIesWithCipherParameters.Create(d, e, 64, 128);

  if (iv <> Nil) then
  begin
    p := TParametersWithIV.Create(p, iv);
  end;

  i1.Init(p1.Public, p, ephKeyGen);
  i2.Init(p1.Private, p, TECIESPublicKeyParser.Create(params)
    as IECIESPublicKeyParser);

  &message := DecodeHex('1234567890abcdef');

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));

  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('AES cipher test failed');
  end;
end;

procedure TTestECIES.DoShortTest();
var
  n: TBigInteger;
  curve: IFpCurve;
  params: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  p1, p2: IAsymmetricCipherKeyPair;
  p: ICipherParameters;
  i1, i2: IIesEngine;
  d, e, &message, out1, out2: TBytes;
  gen: IECKeyPairGenerator;
  ephKeyGen: IEphemeralKeyPairGenerator;
begin
  n := TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6277101735386680763835789423207666416083908700390324961279'), // q
    TBigInteger.Create('fffffffffffffffffffffffffffffffefffffffffffffffc', 16),
    // a
    TBigInteger.Create('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1', 16),
    // b
    n, TBigInteger.One);

  params := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012')), // G
    n);

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('651056770906015076056810763456358567190100156695615665659'), // d
    params);

  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex('0262b12d60690cdcf330babab6e69763b471f994dd702d16a5')), // Q
    params);

  p1 := TAsymmetricCipherKeyPair.Create(pubKey, priKey);
  p2 := TAsymmetricCipherKeyPair.Create(pubKey, priKey);

  //
  // stream test - V 0
  //
  i1 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  i2 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  d := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  e := TBytes.Create(8, 7, 6, 5, 4, 3, 2, 1);
  p := TIesParameters.Create(d, e, 64);

  i1.Init(true, p1.Private, p2.Public, p);
  i2.Init(false, p2.Private, p1.Public, p);

  &message := Nil;

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));
  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('stream cipher test failed');
  end;

  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  try

    i2.ProcessBlock(out1, 0, System.Length(out1) - 1);
    Fail('Expected EInvalidCipherTextCryptoLibException');

  except
    on e: EInvalidCipherTextCryptoLibException do
    begin
      if (e.Message <>
        'Length of Input Must be Greater than the MAC and V Combined') then
      begin
        Fail('Wrong Exception Message');
      end;

    end;

  end;


  // with ephemeral key pair

  // Generate the ephemeral key pair

  gen := TECKeyPairGenerator.Create();
  gen.Init(TECKeyGenerationParameters.Create(params, TSecureRandom.Create()
    as ISecureRandom) as IECKeyGenerationParameters);

  ephKeyGen := TEphemeralKeyPairGenerator.Create(gen, TECKeyEncoder.Create(false)
    as IKeyEncoder);

  i1.Init(p2.Public, p, ephKeyGen);
  i2.Init(p2.Private, p, TECIESPublicKeyParser.Create(params)
    as IECIESPublicKeyParser);

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));
  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('V cipher test failed');
  end;

  try

    i2.ProcessBlock(out1, 0, System.Length(out1) - 1);
    Fail('Expected EInvalidCipherTextCryptoLibException');

  except
    on e: EInvalidCipherTextCryptoLibException do
    begin
      if (e.Message <>
        'Length of Input Must be Greater than the MAC and V Combined') then
      begin
        Fail('Wrong Exception Message');
      end;

    end;

  end;

end;

procedure TTestECIES.DoStaticTest(const iv: TBytes);
var
  n: TBigInteger;
  curve: IFpCurve;
  params: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  p1, p2: IAsymmetricCipherKeyPair;
  p: ICipherParameters;
  i1, i2: IIesEngine;
  d, e, &message, out1, out2, compareValue: TBytes;
  c1, c2: IBufferedBlockCipher;
begin
  n := TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6277101735386680763835789423207666416083908700390324961279'), // q
    TBigInteger.Create('fffffffffffffffffffffffffffffffefffffffffffffffc', 16),
    // a
    TBigInteger.Create('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1', 16),
    // b
    n, TBigInteger.One);

  params := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012')), // G
    n, TBigInteger.One);

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('651056770906015076056810763456358567190100156695615665659'), // d
    params);

  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex('0262b12d60690cdcf330babab6e69763b471f994dd702d16a5')), // Q
    params);

  p1 := TAsymmetricCipherKeyPair.Create(pubKey, priKey);
  p2 := TAsymmetricCipherKeyPair.Create(pubKey, priKey);

  //
  // stream test
  //
  i1 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  i2 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  d := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  e := TBytes.Create(8, 7, 6, 5, 4, 3, 2, 1);
  p := TIesParameters.Create(d, e, 64);

  i1.Init(true, p1.Private, p2.Public, p);
  i2.Init(false, p2.Private, p1.Public, p);

  &message := DecodeHex('1234567890abcdef');

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));

  if (not AreEqual(out1,
    DecodeHex('609ae8fe2727572da30a1d04e3dd0530de24ee89e7313f6c400992a6'))) then
  begin
    Fail('stream cipher test failed on enc');
  end;

  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('stream cipher test failed');
  end;

  //
  // AES with CBC
  //

  c1 := TPaddedBufferedBlockCipher.Create
    (TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher);

  c2 := TPaddedBufferedBlockCipher.Create
    (TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher);

  i1 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac, c1);

  i2 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac, c2);

  d := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  e := TBytes.Create(8, 7, 6, 5, 4, 3, 2, 1);
  p := TIesWithCipherParameters.Create(d, e, 64, 128);

  if (iv <> Nil) then
  begin
    p := TParametersWithIV.Create(p, iv);
  end;

  i1.Init(true, p1.Private, p2.Public, p);
  i2.Init(false, p2.Private, p1.Public, p);

  &message := DecodeHex('1234567890abcdef');

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));

  if iv = Nil then
  begin
    compareValue :=
      DecodeHex(
      '33578c27c3c044a535d42b9fe77003c3c4c9a74b987adac5c21c920b4b878debdefdff1e');
  end
  else
  begin
    compareValue :=
      DecodeHex(
      'cae615459828884e5444a33a0271d763a8ca8affc60b8551a5fb2cc362409c0226e225e0');
  end;

  if (not AreEqual(out1, compareValue)) then
  begin
    Fail('AES cipher test failed on enc');
  end;

  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('AES cipher test failed');
  end;

end;

procedure TTestECIES.DoForgeryTest();
var
  n: TBigInteger;
  curve: IFpCurve;
  params: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  p1, p2: IAsymmetricCipherKeyPair;
  LMacKeyBytes, LForgeLen, LI: Int32;
  LParam: ICipherParameters;
  LEnc, LDec: IIesEngine;
  LKnownPt, LLeaked, LForgedPt, LForgedC, LForgedTag, LForged: TBytes;
  LHMac: IHMac;
begin
  // Regression for CVD ANT-2026-WZ2GJBGD: in static-key stream mode the MAC key must not be
  // recoverable from the keystream. The legacy layout placed the keystream K1 before the MAC key
  // K2, so a single known-plaintext leak of K1 (= M ^ C) also exposed the MAC key of any shorter
  // message - letting an attacker forge a valid ciphertext+tag from one observation. With K2 now
  // taken from a fixed prefix of the KDF output, that slice of the leaked keystream is no longer
  // the MAC key, so the constructed forgery must be rejected.

  n := TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6277101735386680763835789423207666416083908700390324961279'),
    TBigInteger.Create('fffffffffffffffffffffffffffffffefffffffffffffffc', 16),
    TBigInteger.Create('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1', 16),
    n, TBigInteger.One);

  params := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012')), n);

  priKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('651056770906015076056810763456358567190100156695615665659'), params);

  pubKey := TECPublicKeyParameters.Create
    (curve.DecodePoint
    (DecodeHex('0262b12d60690cdcf330babab6e69763b471f994dd702d16a5')), params);

  p1 := TAsymmetricCipherKeyPair.Create(pubKey, priKey);
  p2 := TAsymmetricCipherKeyPair.Create(pubKey, priKey);

  LMacKeyBytes := 8; // 64-bit MAC key
  // no encoding vector, so the MAC is taken over the ciphertext only (keeps the forgery construction simple)
  LParam := TIesParameters.Create(TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8), nil,
    LMacKeyBytes * 8);

  // 1. attacker observes one known-plaintext ciphertext of length L (>= macKeyBytes)
  LKnownPt := DecodeHex('000102030405060708090a0b0c0d0e0f10111213'); // L = 20
  LEnc := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);
  LEnc.Init(true, p1.Private, p2.Public, LParam);
  LForgedC := LEnc.ProcessBlock(LKnownPt, 0, System.Length(LKnownPt));

  SetLength(LLeaked, System.Length(LKnownPt)); // recovered keystream = M ^ C over the L plaintext bytes
  for LI := 0 to System.Pred(System.Length(LLeaked)) do
    LLeaked[LI] := LKnownPt[LI] xor LForgedC[LI];

  // 2. forge a shorter message, assuming the legacy keystream-then-MAC-key layout
  LForgeLen := System.Length(LKnownPt) - LMacKeyBytes; // L'
  LForgedPt := DecodeHex('ffffffffffffffffffffffff'); // 12 bytes (= L')
  SetLength(LForgedC, LForgeLen);
  for LI := 0 to System.Pred(LForgeLen) do
    LForgedC[LI] := LForgedPt[LI] xor LLeaked[LI]; // K1' = leaked[0..L']

  LHMac := THMac.Create(TDigestUtilities.GetDigest('SHA-1')) as IHMac;
  LHMac.Init(TKeyParameter.Create(TArrayUtilities.CopyOfRange<Byte>(LLeaked,
    LForgeLen, LForgeLen + LMacKeyBytes)) as IKeyParameter); // K2' = leaked[L'..]
  LHMac.BlockUpdate(LForgedC, 0, System.Length(LForgedC));
  LForgedTag := LHMac.DoFinal();

  LForged := TArrayUtilities.Concatenate<Byte>([LForgedC, LForgedTag]);

  // 3. the recipient must reject the forgery
  LDec := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);
  LDec.Init(false, p2.Private, p1.Public, LParam);
  try
    LDec.ProcessBlock(LForged, 0, System.Length(LForged));
    Fail('static-key stream IES accepted a cross-message MAC forgery');
  except
    on E: EInvalidCipherTextCryptoLibException do
    begin
      // expected: K2 is a fixed prefix of the KDF output, not a recoverable slice of the keystream
    end;
  end;
end;

procedure TTestECIES.DoTest(const p1, p2: IAsymmetricCipherKeyPair);
var
  p: ICipherParameters;
  i1, i2: IIesEngine;
  d, e, &message, out1, out2: TBytes;
  c1, c2: IBufferedBlockCipher;
begin
  //
  // stream test
  //
  i1 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  i2 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac);

  d := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  e := TBytes.Create(8, 7, 6, 5, 4, 3, 2, 1);
  p := TIesParameters.Create(d, e, 64);

  i1.Init(true, p1.Private, p2.Public, p);
  i2.Init(false, p2.Private, p1.Public, p);

  &message := DecodeHex('1234567890abcdef');

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));

  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('stream cipher test failed');
  end;

  //
  // AES with CBC
  //

  c1 := TPaddedBufferedBlockCipher.Create
    (TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher);

  c2 := TPaddedBufferedBlockCipher.Create
    (TCbcBlockCipher.Create(TAesUtilities.CreateEngine())
    as ICBCBlockCipher);

  i1 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac, c1);

  i2 := TIesEngine.Create(TECDHBasicAgreement.Create() as IECDHBasicAgreement,
    TKDF2BytesGenerator.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IKDF2BytesGenerator, THMac.Create(TDigestUtilities.GetDigest('SHA-1'))
    as IHMac, c2);

  d := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8);
  e := TBytes.Create(8, 7, 6, 5, 4, 3, 2, 1);
  p := TIesWithCipherParameters.Create(d, e, 64, 128);

  i1.Init(true, p1.Private, p2.Public, p);
  i2.Init(false, p2.Private, p1.Public, p);

  &message := DecodeHex('1234567890abcdef');

  out1 := i1.ProcessBlock(&message, 0, System.Length(&message));

  out2 := i2.ProcessBlock(out1, 0, System.Length(out1));

  if (not AreEqual(out2, &message)) then
  begin
    Fail('AES cipher test failed');
  end;
end;

procedure TTestECIES.SetUp;
begin
  inherited;
  FAES_IV := DecodeHex('000102030405060708090a0b0c0d0e0f');
end;

procedure TTestECIES.TearDown;
begin
  inherited;

end;

procedure TTestECIES.TestECIES;
var
  n: TBigInteger;
  curve: IFpCurve;
  params: IECDomainParameters;
  eGen: IECKeyPairGenerator;
  gParam: IKeyGenerationParameters;
  p1, p2: IAsymmetricCipherKeyPair;
begin
  DoStaticTest(Nil);
  DoStaticTest(FAES_IV);
  DoShortTest();
  DoForgeryTest();

  n := TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6277101735386680763835789423207666416083908700390324961279'), // q
    TBigInteger.Create('fffffffffffffffffffffffffffffffefffffffffffffffc', 16),
    // a
    TBigInteger.Create('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1', 16),
    // b
    n, TBigInteger.One);

  params := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012')), // G
    n, TBigInteger.One);

  eGen := TECKeyPairGenerator.Create();
  gParam := TECKeyGenerationParameters.Create(params, TSecureRandom.Create()
    as ISecureRandom);

  eGen.Init(gParam);

  p1 := eGen.GenerateKeyPair();
  p2 := eGen.GenerateKeyPair();

  DoTest(p1, p2);

  DoEphemeralTest(Nil, false);
  DoEphemeralTest(Nil, true);
  DoEphemeralTest(FAES_IV, false);
  DoEphemeralTest(FAES_IV, true);
end;

procedure TTestECIES.TestForgery;
begin
  DoForgeryTest();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestECIES);
{$ELSE}
  RegisterTest(TTestECIES.Suite);
{$ENDIF FPC}

end.
