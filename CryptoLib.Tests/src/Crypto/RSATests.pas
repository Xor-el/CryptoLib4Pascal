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
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestRSA = class(TCryptoLibAlgorithmTestCase)
  private
    class var
      FModulus: TBigInteger;
      FPubExp: TBigInteger;
      FPrivExp: TBigInteger;
      FP: TBigInteger;
      FQ: TBigInteger;
      FPExp: TBigInteger;
      FQExp: TBigInteger;
      FCrtCoef: TBigInteger;
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

  end;

implementation

{ TTestRSA }

class constructor TTestRSA.CreateTestRSA;
begin
  FModulus := TBigInteger.Create(
    'b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6' +
    'f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdb' +
    'f3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26' +
    'c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5', 16);

  FPubExp := TBigInteger.Create('11', 16);

  FPrivExp := TBigInteger.Create(
    '92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f5638' +
    '8f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1' +
    'dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f74' +
    '87de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619', 16);

  FP := TBigInteger.Create(
    'f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b' +
    '3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03', 16);

  FQ := TBigInteger.Create(
    'b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb69' +
    '6fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947', 16);

  FPExp := TBigInteger.Create(
    '1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4' +
    '257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5', 16);

  FQExp := TBigInteger.Create(
    '6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201' +
    'c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded', 16);

  FCrtCoef := TBigInteger.Create(
    'dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926' +
    'd070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339', 16);

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
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  engine: IAsymmetricBlockCipher;
  input, encrypted, decrypted: TCryptoLibByteArray;
begin
  // Create key parameters
  pubParams := TRsaKeyParameters.Create(False, FModulus, FPubExp);
  privParams := TRsaPrivateCrtKeyParameters.Create(
    FModulus, FPubExp, FPrivExp, FP, FQ, FPExp, FQExp, FCrtCoef);

  // Test input
  input := TConverters.ConvertHexStringToBytes(
    '4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');

  // Encrypt with public key
  engine := TRsaBlindedEngine.Create();
  engine.Init(True, pubParams);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  CheckTrue(System.Length(encrypted) > 0, 'Encryption produced empty output');

  // Decrypt with private key
  engine.Init(False, privParams);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(TArrayUtilities.AreEqual<Byte>(input, decrypted), 'RSA round-trip failed');
end;

procedure TTestRSA.DoTestPkcs1Encoding;
var
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  engine: IAsymmetricBlockCipher;
  input, encrypted, decrypted: TCryptoLibByteArray;
begin
  pubParams := TRsaKeyParameters.Create(False, FModulus, FPubExp);
  privParams := TRsaPrivateCrtKeyParameters.Create(
    FModulus, FPubExp, FPrivExp, FP, FQ, FPExp, FQExp, FCrtCoef);

  input := TConverters.ConvertHexStringToBytes(
    '4e6f77206973207468652074696d6520666f7220616c6c20676f6f64206d656e');

  // Encrypt with PKCS1 padding
  engine := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  engine.Init(True, pubParams);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  // Decrypt
  engine.Init(False, privParams);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(TArrayUtilities.AreEqual<Byte>(input, decrypted), 'PKCS1 round-trip failed');
end;

procedure TTestRSA.DoTestOaepEncoding;
var
  pubParams: IRsaKeyParameters;
  privParams: IRsaPrivateCrtKeyParameters;
  engine: IAsymmetricBlockCipher;
  input, encrypted, decrypted: TCryptoLibByteArray;
begin
  pubParams := TRsaKeyParameters.Create(False, FModulus, FPubExp);
  privParams := TRsaPrivateCrtKeyParameters.Create(
    FModulus, FPubExp, FPrivExp, FP, FQ, FPExp, FQExp, FCrtCoef);

  // Shorter input for OAEP (needs room for padding)
  input := TConverters.ConvertHexStringToBytes('48656c6c6f20576f726c6421'); // "Hello World!"

  // Encrypt with OAEP padding
  engine := TOaepEncoding.Create(TRsaBlindedEngine.Create());
  engine.Init(True, pubParams);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  // Decrypt
  engine.Init(False, privParams);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(TArrayUtilities.AreEqual<Byte>(input, decrypted), 'OAEP round-trip failed');
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
  input := TConverters.ConvertHexStringToBytes('48656c6c6f'); // "Hello"

  engine := TPkcs1Encoding.Create(TRsaBlindedEngine.Create());
  engine.Init(True, pubKey);
  encrypted := engine.ProcessBlock(input, 0, System.Length(input));

  engine.Init(False, privKey);
  decrypted := engine.ProcessBlock(encrypted, 0, System.Length(encrypted));

  CheckTrue(TArrayUtilities.AreEqual<Byte>(input, decrypted), 'Generated key round-trip failed');
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

initialization

{$IFDEF FPC}
  RegisterTest(TTestRSA);
{$ELSE}
  RegisterTest(TTestRSA.Suite);
{$ENDIF FPC}

end.
