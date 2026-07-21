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

unit RSATests;

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
  ClpBigInteger,
  ClpCryptoLibConfig,
  ClpIRsaParameters,
  ClpRsaParameters,
  ClpIRsaGenerators,
  ClpRsaGenerators,
  ClpRsaBlindedEngine,
  ClpPkcs1Encoding,
  ClpOaepEncoding,
  ClpIAsymmetricBlockCipher,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpISigner,
  ClpSignerUtilities,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpConverters,
  ClpEncoders,
  ClpCryptoLibTypes,
  ClpAsn1Core,
  ClpIAsn1Objects,
  ClpPkcsObjectIdentifiers,
  ClpSubjectPublicKeyInfoFactory,
  ClpIX509Asn1Objects,
  CryptoLibTestBase,
  CryptoTestKeys;

type

  TTestRSA = class(TCryptoLibAlgorithmTestCase)
  private
    class var
      FPubParams: IRsaKeyParameters;
      FPrivParams: IRsaPrivateCrtKeyParameters;
      FRandom: ISecureRandom;

    class constructor CreateTestRSA();

    procedure DoTestModPowRSA(BitLength: Integer);
    procedure DoTestRawRsa;
    procedure DoTestPkcs1Encoding;
    procedure DoTestOaepEncoding;
    procedure DoTestKeyGeneration;
    procedure DoTestRsaSignature;

  published
    procedure TestModPowRSA1024;
    procedure TestModPowRSA2048;
    procedure TestRawRsa;
    procedure TestPkcs1Encoding;
    procedure TestOaepEncoding;
    procedure TestKeyGeneration;
    procedure TestRsaSignature;
    procedure TestRsaPublicKeyInfoEncodingHasNullParameters;
    procedure TestSubjectPublicKeyInfoFactoryRsaConsistency;
    procedure TestMaxSizeRejectsOversizedModulus;
    procedure TestMaxMRTestsZeroSkipsCompositeCheck;
    procedure TestMaxSizeMaxMRTestsUnsetDefault;

  end;

implementation

{ TTestRSA }

class constructor TTestRSA.CreateTestRSA;
begin
  FPubParams := TCryptoTestKeys.GetRsaEngineDefaultPublic;
  FPrivParams := TCryptoTestKeys.GetRsaEngineDefaultPrivate;
  FRandom := TSecureRandom.Create();
end;

procedure TTestRSA.DoTestModPowRSA(BitLength: Integer);
var
  i: Integer;
  p, q, n, phi, e, d, m, c, m_dec, One: TBigInteger;
begin
  One := TBigInteger.One;
  e := TBigInteger.ValueOf(65537);

  for i := 1 to 5 do
  begin
    // Generate primes p, q
    repeat
      p := TBigInteger.ProbablePrime(BitLength div 2, FRandom);
    until (not p.Subtract(One).GCD(e).Equals(e)); // Ensure gcd(e, p-1) = 1

    repeat
      q := TBigInteger.ProbablePrime(BitLength div 2, FRandom);
    until (not q.Equals(p)) and (not q.Subtract(One).GCD(e).Equals(e));

    n := p.Multiply(q);
    phi := p.Subtract(One).Multiply(q.Subtract(One));

    d := e.ModInverse(phi);

    // Random message m < n
    repeat
      m := TBigInteger.Create(n.BitLength - 1, FRandom);
    until (m.CompareTo(n) < 0);

    // Encrypt: c = m^e mod n
    c := m.ModPow(e, n);

    // Decrypt: m' = c^d mod n
    m_dec := c.ModPow(d, n);

    if not m.Equals(m_dec) then
    begin
      Fail(Format('RSA ModPow Failure at Iteration %d' + sLineBreak +
                  'p: %s' + sLineBreak +
                  'q: %s' + sLineBreak +
                  'n: %s' + sLineBreak +
                  'e: %s' + sLineBreak +
                  'd: %s' + sLineBreak +
                  'm: %s' + sLineBreak +
                  'c: %s' + sLineBreak +
                  'm_dec: %s',
                  [i, p.ToString(16), q.ToString(16), n.ToString(16),
                   e.ToString(16), d.ToString(16), m.ToString(16),
                   c.ToString(16), m_dec.ToString(16)]));
    end;
  end;
end;

procedure TTestRSA.DoTestRawRsa;
var
  engine: IAsymmetricBlockCipher;
  input, encrypted, decrypted: TCryptoLibByteArray;
begin

  // Test input
  input := THexEncoder.Decode(
    '4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');

  // Encrypt with public key
  engine := TRsaBlindedEngine.Create();
  engine.Init(True, FPubParams);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  CheckTrue(System.Length(encrypted) > 0, 'Encryption produced empty output');

  // Decrypt with private key
  engine.Init(False, FPrivParams);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(AreEqual(input, decrypted), 'RSA round-trip failed');
end;

procedure TTestRSA.DoTestPkcs1Encoding;
var
  engine: IAsymmetricBlockCipher;
  input, encrypted, decrypted: TCryptoLibByteArray;
begin
  input := THexEncoder.Decode(
    '4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');

  // Encrypt with PKCS1 padding
  engine := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  engine.Init(True, FPubParams);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  // Decrypt
  engine.Init(False, FPrivParams);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(AreEqual(input, decrypted), 'PKCS1 round-trip failed');
end;

procedure TTestRSA.DoTestOaepEncoding;
var
  engine: IAsymmetricBlockCipher;
  input, encrypted, decrypted: TCryptoLibByteArray;
begin
  // Shorter input for OAEP (needs room for padding)
  input := THexEncoder.Decode('48656c6c6f20576f726c6421'); // "Hello World!"

  // Encrypt with OAEP padding
  engine := TOaepEncoding.Create(TRsaBlindedEngine.Create());
  engine.Init(True, FPubParams);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  // Decrypt
  engine.Init(False, FPrivParams);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(AreEqual(input, decrypted), 'OAEP round-trip failed');
end;

procedure TTestRSA.DoTestKeyGeneration;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  pubKey: IRsaKeyParameters;
  privKey: IRsaPrivateCrtKeyParameters;
  engine: IAsymmetricBlockCipher;
  input, encrypted, decrypted: TCryptoLibByteArray;
begin
  // Generate 1024-bit RSA key pair
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),  // 65537 public exponent
    TSecureRandom.Create(),
    1024,  // Key size
    80);   // Certainty

  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  pubKey := keyPair.Public as IRsaKeyParameters;
  privKey := keyPair.Private as IRsaPrivateCrtKeyParameters;

  CheckEquals(1024, pubKey.Modulus.BitLength, 'Key size mismatch');
  CheckTrue(not pubKey.IsPrivate, 'Public key marked as private');
  CheckTrue(privKey.IsPrivate, 'Private key not marked as private');

  // Test encryption/decryption with generated keys
  input := THexEncoder.Decode('48656c6c6f'); // "Hello"

  engine := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  engine.Init(True, pubKey);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  engine.Init(False, privKey);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(AreEqual(input, decrypted), 'Generated key round-trip failed');
end;

procedure TTestRSA.DoTestRsaSignature;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  signer: ISigner;
  &message, signature: TCryptoLibByteArray;
  verified: Boolean;
begin
  // Generate key pair
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf($10001),
    TSecureRandom.Create(),
    1024,
    80);

  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  &message := TConverters.ConvertStringToBytes('Test message for RSA signature',
    TEncoding.UTF8);

  // Sign with SHA-256
  signer := TSignerUtilities.GetSigner('SHA-256withRSA');
  signer.Init(True, keyPair.Private);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  signature := signer.GenerateSignature();

  CheckTrue(System.Length(signature) > 0, 'Signature is empty');

  // Verify
  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckTrue(verified, 'Signature verification failed');

  // Test with modified message (should fail)
  &message[0] := &message[0] xor $FF;
  signer.Init(False, keyPair.Public);
  signer.BlockUpdate(&message, 0, System.Length(&message));
  verified := signer.VerifySignature(signature);

  CheckFalse(verified, 'Modified message should fail verification');
end;

procedure TTestRSA.TestModPowRSA1024;
begin
  DoTestModPowRSA(1024);
end;

procedure TTestRSA.TestModPowRSA2048;
begin
  DoTestModPowRSA(2048);
end;

procedure TTestRSA.TestRawRsa;
begin
  DoTestRawRsa;
end;

procedure TTestRSA.TestPkcs1Encoding;
begin
  DoTestPkcs1Encoding;
end;

procedure TTestRSA.TestOaepEncoding;
begin
  DoTestOaepEncoding;
end;

procedure TTestRSA.TestKeyGeneration;
begin
  DoTestKeyGeneration;
end;

procedure TTestRSA.TestRsaSignature;
begin
  DoTestRsaSignature;
end;

procedure TTestRSA.TestRsaPublicKeyInfoEncodingHasNullParameters;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  pubKey: IRsaKeyParameters;
  info: ISubjectPublicKeyInfo;
  encoded: TCryptoLibByteArray;
  hexEncoded: string;
const
  ExpectedOidAndNull = '06092a864886f70d0101010500';
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create() as ISecureRandom, 1024, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();
  pubKey := keyPair.Public as IRsaKeyParameters;

  info := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(pubKey);
  encoded := info.GetEncoded(TAsn1Encodable.Der);
  hexEncoded := THexEncoder.Encode(encoded, False);

  CheckTrue(Pos(ExpectedOidAndNull, hexEncoded) > 0,
    'RSA AlgorithmIdentifier in SubjectPublicKeyInfo missing mandatory NULL parameters (05 00).');
end;

procedure TTestRSA.TestSubjectPublicKeyInfoFactoryRsaConsistency;
var
  kpGen: IRsaKeyPairGenerator;
  kpParams: IRsaKeyGenerationParameters;
  keyPair: IAsymmetricCipherKeyPair;
  info: ISubjectPublicKeyInfo;
  dn: IDerNull;
begin
  kpGen := TRsaKeyPairGenerator.Create();
  kpParams := TRsaKeyGenerationParameters.Create(
    TBigInteger.ValueOf(65537), TSecureRandom.Create() as ISecureRandom, 1024, 100);
  kpGen.Init(kpParams);
  keyPair := kpGen.GenerateKeyPair();

  info := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
    keyPair.Public as IAsymmetricKeyParameter);

  CheckTrue(info.Algorithm.Algorithm.Equals(TPkcsObjectIdentifiers.RsaEncryption),
    'RSA AlgorithmIdentifier OID should be rsaEncryption.');
  CheckTrue(Supports(info.Algorithm.Parameters, IDerNull, dn),
    'RSA AlgorithmIdentifier parameters should be DerNull.');
end;

procedure TTestRSA.TestMaxSizeRejectsOversizedModulus;
begin
  try
    TCryptoLibConfig.Rsa.MaxSize := 512;
    CheckTrue(FPubParams.Modulus.BitLength > 512, 'test modulus must exceed MaxSize cap');
    try
      TRsaKeyParameters.Create(False, FPubParams.Modulus, FPubParams.Exponent);
      Fail('expected EArgumentCryptoLibException for oversized modulus');
    except
      on E: EArgumentCryptoLibException do
        CheckEquals('RSA modulus out of range', E.Message);
    end;
  finally
    TCryptoLibConfig.Rsa.ResetToDefaults();
  end;
end;

procedure TTestRSA.TestMaxMRTestsZeroSkipsCompositeCheck;
var
  LParams: IRsaKeyParameters;
begin
  try
    TCryptoLibConfig.Rsa.MaxMRTests := 0;
    LParams := TRsaKeyParameters.Create(False, FPubParams.Modulus, FPubParams.Exponent);
    CheckTrue(LParams.Modulus.Equals(FPubParams.Modulus), 'modulus should be accepted when MR is disabled');
  finally
    TCryptoLibConfig.Rsa.ResetToDefaults();
  end;
end;

procedure TTestRSA.TestMaxSizeMaxMRTestsUnsetDefault;
var
  LParams: IRsaKeyParameters;
begin
  try
    TCryptoLibConfig.Rsa.ResetToDefaults();
    CheckFalse(TCryptoLibConfig.Rsa.MaxMRTests.HasValue,
      'unset MaxMRTests should have no value');
    LParams := TRsaKeyParameters.Create(False, FPubParams.Modulus, FPubParams.Exponent);
    CheckTrue(LParams.Modulus.Equals(FPubParams.Modulus),
      'default limits should accept standard test modulus');
  finally
    TCryptoLibConfig.Rsa.ResetToDefaults();
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestRSA);
{$ELSE}
  RegisterTest(TTestRSA.Suite);
{$ENDIF FPC}

end.
