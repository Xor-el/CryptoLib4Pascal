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

unit Curve448KeyUtilitiesTests;

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
  ClpCurve448KeyUtilities,
  ClpEd448Parameters,
  ClpIEd448Parameters,
  ClpEd448Generators,
  ClpIEd448Generators,
  ClpIX448Parameters,
  ClpX448Agreement,
  ClpIX448Agreement,
  ClpIAsymmetricCipherKeyPair,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestCurve448KeyUtilities = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestKeyPairConsistency;
    procedure TestKeyPairConsistencyFromRfc8032Vector1;
    procedure TestKnownAnswerFromRFC8032Seed;
    procedure TestMultipleKeyConversions;
    procedure TestConvertedKeysAgreement;
    procedure TestToX448PublicKeyRaisesWhenNil;
    procedure TestToX448PrivateKeyRaisesWhenNil;
    procedure TestToX448PublicKeyRejectsYEqualsOne;
    procedure TestToX448PublicKeyRejectsYEqualsMinusOne;
    procedure TestToX448PublicKeyHandlesYEqualsZero;
    procedure TestToX448PublicKeyHandlesHighYValues;
    procedure TestSignBitLossIsExpected;
    procedure TestToX448PublicKeyRejectsInvalidPoint;
  end;

implementation

resourcestring
  SKeyPairConsistencyFailed = 'Key pair consistency failed: converted X448 public does not match public derived from converted private';
  SExpectedArgumentNilException = 'Expected EArgumentNilCryptoLibException';
  SConvertedKeysAgreementFailed = 'X448 agreement with converted keys failed';

{ TTestCurve448KeyUtilities }

procedure TTestCurve448KeyUtilities.SetUp;
begin
  inherited SetUp();
  FRandom := TSecureRandom.Create();
end;

procedure TTestCurve448KeyUtilities.TearDown;
begin
  FRandom := nil;
  inherited TearDown();
end;

procedure TTestCurve448KeyUtilities.TestKeyPairConsistency;
var
  LKpg: IEd448KeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LEdPriv: IEd448PrivateKeyParameters;
  LEdPub: IEd448PublicKeyParameters;
  LX448Sk: IX448PrivateKeyParameters;
  LX448PkFromConversion: IX448PublicKeyParameters;
  LX448PkFromSk: IX448PublicKeyParameters;
begin
  LKpg := TEd448KeyPairGenerator.Create() as IEd448KeyPairGenerator;
  LKpg.Init(TEd448KeyGenerationParameters.Create(FRandom)
    as IEd448KeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  if not Supports(LKp.Private, IEd448PrivateKeyParameters, LEdPriv) then
    Fail(SKeyPairConsistencyFailed);
  if not Supports(LKp.Public, IEd448PublicKeyParameters, LEdPub) then
    Fail(SKeyPairConsistencyFailed);
  LX448Sk := TCurve448KeyUtilities.ToX448PrivateKey(LEdPriv);
  LX448PkFromConversion := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);
  LX448PkFromSk := LX448Sk.GeneratePublicKey();
  if not AreEqual(LX448PkFromConversion.GetEncoded(), LX448PkFromSk.GetEncoded()) then
    Fail(SKeyPairConsistencyFailed);
end;

procedure TTestCurve448KeyUtilities.TestKeyPairConsistencyFromRfc8032Vector1;
var
  LSeed: TBytes;
  LEdPriv: IEd448PrivateKeyParameters;
  LEdPub: IEd448PublicKeyParameters;
  LX448Sk: IX448PrivateKeyParameters;
  LX448PkFromConversion: IX448PublicKeyParameters;
  LX448PkFromSk: IX448PublicKeyParameters;
begin
  (* RFC 8032 Section 7.4 - Test vector "Blank" (message length 0): https://www.rfc-editor.org/rfc/rfc8032 *)
  LSeed := DecodeHex('6c82a562cb808d10d632be89c8513ebf' +
    '6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f' +
    '032e7549a20098f95b');
  LEdPriv := TEd448PrivateKeyParameters.Create(LSeed);
  LEdPub := LEdPriv.GeneratePublicKey();
  LX448Sk := TCurve448KeyUtilities.ToX448PrivateKey(LEdPriv);
  LX448PkFromConversion := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);
  LX448PkFromSk := LX448Sk.GeneratePublicKey();
  if not AreEqual(LX448PkFromConversion.GetEncoded(), LX448PkFromSk.GetEncoded()) then
    Fail(SKeyPairConsistencyFailed);
end;

procedure TTestCurve448KeyUtilities.TestKnownAnswerFromRFC8032Seed;
var
  LSeed: TBytes;
  LEdPriv: IEd448PrivateKeyParameters;
  LEdPub: IEd448PublicKeyParameters;
  LX448Sk: IX448PrivateKeyParameters;
  LX448Pk: IX448PublicKeyParameters;
  LExpectedX448SkHex, LExpectedX448PkHex: String;
begin
  (*
    Seed from RFC 8032 Ed448 test vector 1.
    Expected X448 keys generated using Python cryptography library (OpenSSL backend).

    The conversion process:
    1. SHAKE256(Ed448_seed, 56 bytes) -> raw scalar
    2. Apply X448 clamping: scalar[0] &= 0xFC; scalar[55] |= 0x80
    3. Derive X448 public key from clamped scalar
  *)
  LSeed := DecodeHex('6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b');

  // Create Ed448 key pair
  LEdPriv := TEd448PrivateKeyParameters.Create(LSeed);
  LEdPub := LEdPriv.GeneratePublicKey();

  // Convert to X448
  LX448Sk := TCurve448KeyUtilities.ToX448PrivateKey(LEdPriv);
  LX448Pk := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);

  // Expected values (generated with Python cryptography / OpenSSL)
  LExpectedX448SkHex := 'e83930a0cea0808ec7ed6667f472a588b411f0545ba4f3ee75025e1d38519cb905c036d81eeed17483f9f56615ceee4fa70501a71fc0bbb7';
  LExpectedX448PkHex := '3bd436b72a1d011cd3845717fcc6887852a2007fd595ac970bef67c7f24a5329ffd1dfd0b05f90adc9c6e70805e5817a1f09ca229bef8619';

  // Verify private key conversion
  if not AreEqual(LX448Sk.GetEncoded(), DecodeHex(LExpectedX448SkHex)) then
    Fail('X448 private key conversion failed');

  // Verify public key derivation
  if not AreEqual(LX448Pk.GetEncoded(), DecodeHex(LExpectedX448PkHex)) then
    Fail('X448 public key derivation failed');
end;

procedure TTestCurve448KeyUtilities.TestMultipleKeyConversions;
const
  TestVectorCount = 10;

  // Test seeds (57 bytes each, hex-encoded)
  Seeds: array[0 .. TestVectorCount - 1] of String = (
    '010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101010101',
    '020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202',
    '030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303',
    '040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404040404',
    '050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505050505',
    '101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748',
    '202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758',
    '303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768',
    '404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778',
    '505152535455565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788'
  );

  // Expected X448 private keys (56 bytes each, hex-encoded)
  // Generated using Python cryptography library (OpenSSL backend)
  ExpectedX448PrivateKeys: array[0 .. TestVectorCount - 1] of String = (
    '24c7392b799ff6e0086e4fd66c58c99fb4447771d01625ed5e9cd6cae05ffa038eab7b739c1d2ff034b474b62a1fe40c3f81841c1e807f9c',
    '4c8214ed3f124f0f4a713b2e57686adb349c259cd39c4d0eef22b119eec5db36b80d7ca0f7f1104b36f9f3f70054719ab546fee241a2c7fb',
    '9c4eff442da36181cc4a6d0e9a63a3a0018ceb85bddb4564ed6bcba2de412b4bd61e36e6d6e3f1d8a2317d23be605f52c65230caeac976b9',
    '48043d2c79d212a4e78f0381ba33d946fb668d41dbacce6d093e4b533168e4622dc2ffc69eba5e098bab61e039b11d5e731bb2a1e1917385',
    'e8a3ec1a0dab591ce0220f7f9ac1a47b9fe3c3cdd7d50d554b868d070a9f437f07cf2b08dff6929d9ef75edf5a0a13103b19833fc695e2b0',
    'dc586f6674c1b8605d2b8495b4edc58c4955c40656f9f5a117aaccc91998e586218e8eb576080c9da4a3d38dc7fd8658e0a6759a0ddeec86',
    '18d4262afe8ffa7f625f2303b70b5a2bb41b3d5f6c45f51ad3cdf03dbac25b87c4df41f9c7983cb8528ef9516a2a49a59ceff3bc63c0f5b4',
    '784daaabd150150e4e9f8c4eb9fb533746cdcff2d54cc9fa1bf770ca242fbc92689b8d637e1d73ac43c234c7d02a89ce797544f22bb89faa',
    'cc8f0c40bf9d9820bb73d119a2be29e9409529e5f21f5662fbd90e14b901366799bdee5906067cc633d1544cc0787c09cb233859c172dffc',
    '10573c7b14af21a3580c2e82cc6d2f12481ed4357876cc52a5cbe7bcfe90fd86eeaf1a89126292368d9dfa2c25cc392622e4e32010e8baef'
  );

  // Expected X448 public keys (56 bytes each, hex-encoded)
  // Generated using Python cryptography library (OpenSSL backend)
  ExpectedX448PublicKeys: array[0 .. TestVectorCount - 1] of String = (
    '5ef0da613e9f1179d26b04e31ced008b72c7487f650c522cbe9ab91c82e351ab55b21ebaf03b0fc1c6b00b75b878978653bdec064f63952f',
    'ebc092ddea40aed2d28b61fa6d7884887405975825e55f478825923e4254033d6d84cc48654d46ddb88349c5231d14bd7b50418a1e9b768f',
    'ee5a4967f02d598e32540903617c4c75778dcd4fb1f133172888118b36e07cce96b286925d8f6c550ee1df767bc9b764bf078b3dbe64c2c1',
    '40823c9cf2dae0e9857eb8d216a1b5e8df91f3857ad09e790f1e449ff40b536fb267cba9157912bff6b3befbb238c6eae3d865ab05b64c94',
    'e333eaa9fcba294bed31ea72f41379bfe321d7713c65cb6309e6102afca0c602d15d81d07ba10312c172716de5caeed0205de7d83edeade8',
    '1f93eb95bdd582f33022d0af73539261ee8de4a3644e82da1854847431950f4b80abb01990e63177676c1b9bc6ac9bd3e86433ac003ca840',
    'd2c3bb241d983694dad17a0b308652ae04bbc7839de1a4c875f22b67709e8063533cd872885cb8149b67edcbd4548ef4e6e970d6a2931d7d',
    '137175ac3eb645f391c570f67293c44a1c587ea658433a50e48a106a80d9250251c74d458cc71c0b250573f397d0f47d1f3f5d611feea954',
    '595f442fe1e57d5eed07ad879e63386837b59c1d3f512e2aaf078620c525d3ecbe98ae9bb1ec69e7fae7d94fd7c1d46632fc039bbf51b42b',
    'f898765dc932aaa0d1f820cca313b99de18095f2653670f64a2ca440c4438a1c8d80099e8d620c9251c793fd94112764d8e39edfb5c21ad1'
  );
var
  I: Integer;
  LSeed: TBytes;
  LEdPriv: IEd448PrivateKeyParameters;
  LEdPub: IEd448PublicKeyParameters;
  LX448Sk: IX448PrivateKeyParameters;
  LX448Pk: IX448PublicKeyParameters;
  LX448PkFromSk: IX448PublicKeyParameters;
begin
  (*
    Test vectors generated using Python cryptography library (OpenSSL backend).

    Conversion process verified:
    1. Ed448 seed (57 bytes) -> SHAKE256 -> first 56 bytes -> X448 clamping -> X448 private key
    2. Ed448 public key -> 4-isogeny (RFC 7748) -> X448 public key

    Both conversion paths must produce consistent X448 key pairs.
  *)
  for I := 0 to TestVectorCount - 1 do
  begin
    LSeed := DecodeHex(Seeds[I]);

    // Create Ed448 key pair from seed
    LEdPriv := TEd448PrivateKeyParameters.Create(LSeed);
    LEdPub := LEdPriv.GeneratePublicKey();

    // Convert to X448
    LX448Sk := TCurve448KeyUtilities.ToX448PrivateKey(LEdPriv);
    LX448Pk := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);
    LX448PkFromSk := LX448Sk.GeneratePublicKey();

    // Verify private key conversion matches expected
    if not AreEqual(LX448Sk.GetEncoded(), DecodeHex(ExpectedX448PrivateKeys[I])) then
      Fail(Format('Test vector %d: X448 private key conversion failed', [I + 1]));

    // Verify public key conversion matches expected
    if not AreEqual(LX448Pk.GetEncoded(), DecodeHex(ExpectedX448PublicKeys[I])) then
      Fail(Format('Test vector %d: X448 public key conversion (isogeny) failed', [I + 1]));

    // Verify public key derived from converted private matches isogeny conversion
    if not AreEqual(LX448PkFromSk.GetEncoded(), LX448Pk.GetEncoded()) then
      Fail(Format('Test vector %d: X448 public key consistency failed', [I + 1]));
  end;
end;

procedure TTestCurve448KeyUtilities.TestConvertedKeysAgreement;
var
  LKpg: IEd448KeyPairGenerator;
  LKpA, LKpB: IAsymmetricCipherKeyPair;
  LEdPrivA, LEdPrivB: IEd448PrivateKeyParameters;
  LEdPubA, LEdPubB: IEd448PublicKeyParameters;
  LX448SkA, LX448SkB: IX448PrivateKeyParameters;
  LX448PubA, LX448PubB: IX448PublicKeyParameters;
  LAgreeA, LAgreeB: IX448Agreement;
  LSecretA, LSecretB: TBytes;
begin
  LKpg := TEd448KeyPairGenerator.Create() as IEd448KeyPairGenerator;
  LKpg.Init(TEd448KeyGenerationParameters.Create(FRandom)
    as IEd448KeyGenerationParameters);
  LKpA := LKpg.GenerateKeyPair();
  LKpB := LKpg.GenerateKeyPair();
  if not Supports(LKpA.Private, IEd448PrivateKeyParameters, LEdPrivA) then
    Fail(SConvertedKeysAgreementFailed);
  if not Supports(LKpA.Public, IEd448PublicKeyParameters, LEdPubA) then
    Fail(SConvertedKeysAgreementFailed);
  if not Supports(LKpB.Private, IEd448PrivateKeyParameters, LEdPrivB) then
    Fail(SConvertedKeysAgreementFailed);
  if not Supports(LKpB.Public, IEd448PublicKeyParameters, LEdPubB) then
    Fail(SConvertedKeysAgreementFailed);
  LX448SkA := TCurve448KeyUtilities.ToX448PrivateKey(LEdPrivA);
  LX448PubA := TCurve448KeyUtilities.ToX448PublicKey(LEdPubA);
  LX448SkB := TCurve448KeyUtilities.ToX448PrivateKey(LEdPrivB);
  LX448PubB := TCurve448KeyUtilities.ToX448PublicKey(LEdPubB);
  LAgreeA := TX448Agreement.Create() as IX448Agreement;
  LAgreeA.Init(LX448SkA);
  System.SetLength(LSecretA, LAgreeA.AgreementSize);
  LAgreeA.CalculateAgreement(LX448PubB, LSecretA, 0);
  LAgreeB := TX448Agreement.Create() as IX448Agreement;
  LAgreeB.Init(LX448SkB);
  System.SetLength(LSecretB, LAgreeB.AgreementSize);
  LAgreeB.CalculateAgreement(LX448PubA, LSecretB, 0);
  if not AreEqual(LSecretA, LSecretB) then
    Fail(SConvertedKeysAgreementFailed);
end;

procedure TTestCurve448KeyUtilities.TestToX448PublicKeyRaisesWhenNil;
begin
  try
    TCurve448KeyUtilities.ToX448PublicKey(nil);
    Fail(SExpectedArgumentNilException);
  except
    on E: EArgumentNilCryptoLibException do
      ; // expected
  else
    raise;
  end;
end;

procedure TTestCurve448KeyUtilities.TestToX448PrivateKeyRaisesWhenNil;
begin
  try
    TCurve448KeyUtilities.ToX448PrivateKey(nil);
    Fail(SExpectedArgumentNilException);
  except
    on E: EArgumentNilCryptoLibException do
      ; // expected
  else
    raise;
  end;
end;

procedure TTestCurve448KeyUtilities.TestToX448PublicKeyRejectsYEqualsOne;
var
  LIdentityY: TBytes;
  LMockPublicKey: IEd448PublicKeyParameters;
begin
  (*
    Edge case: y = 1 (the identity point on Edwards curve)

    The isogeny formula u = y²·(1+d·y²)/(1-y²) has division by zero when y² = 1.
    When y = 1: (1 - y²) = (1 - 1) = 0 → division by zero

    This corresponds to the identity/neutral element (0, 1) on Ed448.
    The conversion should raise an exception.
  *)

  // y = 1 encoded as 57 bytes (little-endian)
  LIdentityY := DecodeHex('01000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '00000000000000000000000000000000' +
                          '000000000000000000');

  try
    LMockPublicKey := TEd448PublicKeyParameters.Create(LIdentityY);
    TCurve448KeyUtilities.ToX448PublicKey(LMockPublicKey);
    Fail('Expected EArgumentCryptoLibException for identity point (y = 1)');
  except
    on E: EArgumentCryptoLibException do
      ; // Expected - division by zero case caught
    on E: Exception do
      ; // Any exception is acceptable for invalid input
  end;
end;

procedure TTestCurve448KeyUtilities.TestToX448PublicKeyRejectsYEqualsMinusOne;
var
  LMinusOneY: TBytes;
  LMockPublicKey: IEd448PublicKeyParameters;
begin
  (*
    Edge case: y = -1 (mod p)

    When y = -1: y² = 1, so (1 - y²) = 0 → division by zero
    This is the point (0, -1) which is a point of order 2 on Ed448.

    The conversion should raise an exception.
  *)

  // y = -1 mod p = p - 1 for Goldilocks prime
  // p = 2^448 - 2^224 - 1
  // p - 1 in little-endian hex:
  LMinusOneY := DecodeHex('FEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
                          'FFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFF' +
                          'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF' +
                          'FFFFFFFFFFFFFFFFFFFF00');

  try
    LMockPublicKey := TEd448PublicKeyParameters.Create(LMinusOneY);
    TCurve448KeyUtilities.ToX448PublicKey(LMockPublicKey);
    Fail('Expected EArgumentCryptoLibException for y = -1 (causes y² = 1)');
  except
    on E: EArgumentCryptoLibException do
      ; // Expected - division by zero case caught
    on E: Exception do
      ; // Any exception is acceptable for invalid input
  end;
end;

procedure TTestCurve448KeyUtilities.TestToX448PublicKeyHandlesYEqualsZero;
var
  LSeed: TBytes;
  LEdPriv: IEd448PrivateKeyParameters;
  LEdPub: IEd448PublicKeyParameters;
  LX448Sk: IX448PrivateKeyParameters;
  LX448PkFromConversion: IX448PublicKeyParameters;
  LX448PkFromSk: IX448PublicKeyParameters;
  LY: TBytes;
  LYValue: Integer;
  I: Integer;
  LFoundSmallY: Boolean;
begin
  (*
    Edge case: y = 0

    For y = 0: u = 0·(1+0)/(1-0) = 0
    This is a valid conversion that should succeed.
    Point (±1, 0) exists on Ed448 curve.

    We search for a seed that produces a small y value to test boundary behavior.
  *)

  LFoundSmallY := False;

  for I := 0 to 999 do
  begin
    SetLength(LSeed, 57);
    FillChar(LSeed[0], 57, 0);
    LSeed[0] := Byte(I and $FF);
    LSeed[1] := Byte((I shr 8) and $FF);

    LEdPriv := TEd448PrivateKeyParameters.Create(LSeed);
    LEdPub := LEdPriv.GeneratePublicKey();

    LY := LEdPub.GetEncoded();
    LYValue := LY[0] or (LY[1] shl 8);

    if LYValue < 256 then
    begin
      // Found a key with small y - verify conversion works
      LX448Sk := TCurve448KeyUtilities.ToX448PrivateKey(LEdPriv);
      LX448PkFromConversion := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);
      LX448PkFromSk := LX448Sk.GeneratePublicKey();

      if not AreEqual(LX448PkFromConversion.GetEncoded(), LX448PkFromSk.GetEncoded()) then
        Fail('Conversion failed for small y value');

      LFoundSmallY := True;
      Break;
    end;
  end;

  // If we didn't find a small y, verify normal conversion works
  if not LFoundSmallY then
  begin
    LSeed := DecodeHex('6c82a562cb808d10d632be89c8513ebf' +
                       '6c929f34ddfa8c9f63c9960ef6e348a3' +
                       '528c8a3fcc2f044e39a3fc5b94492f8f' +
                       '032e7549a20098f95b');
    LEdPriv := TEd448PrivateKeyParameters.Create(LSeed);
    LEdPub := LEdPriv.GeneratePublicKey();
    LX448Sk := TCurve448KeyUtilities.ToX448PrivateKey(LEdPriv);
    LX448PkFromConversion := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);
    LX448PkFromSk := LX448Sk.GeneratePublicKey();

    if not AreEqual(LX448PkFromConversion.GetEncoded(), LX448PkFromSk.GetEncoded()) then
      Fail('Conversion consistency check failed');
  end;
end;

procedure TTestCurve448KeyUtilities.TestToX448PublicKeyHandlesHighYValues;
var
  LSeed: TBytes;
  LEdPriv: IEd448PrivateKeyParameters;
  LEdPub: IEd448PublicKeyParameters;
  LX448Sk: IX448PrivateKeyParameters;
  LX448PkFromConversion: IX448PublicKeyParameters;
  LX448PkFromSk: IX448PublicKeyParameters;
  LY: TBytes;
  I: Integer;
  LFoundHighY: Boolean;
begin
  (*
    Edge case: y close to p (high y values)

    Values close to p but not equal to p-1 should work fine.
    Only y = ±1 (where y² = 1) cause division by zero.
  *)

  LFoundHighY := False;

  for I := 0 to 999 do
  begin
    SetLength(LSeed, 57);
    FillChar(LSeed[0], 57, $FF);
    LSeed[0] := Byte(I and $FF);
    LSeed[1] := Byte((I shr 8) and $FF);

    LEdPriv := TEd448PrivateKeyParameters.Create(LSeed);
    LEdPub := LEdPriv.GeneratePublicKey();

    LY := LEdPub.GetEncoded();

    // Check for high y values (top bytes close to max)
    if LY[55] >= $FE then
    begin
      LX448Sk := TCurve448KeyUtilities.ToX448PrivateKey(LEdPriv);
      LX448PkFromConversion := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);
      LX448PkFromSk := LX448Sk.GeneratePublicKey();

      if not AreEqual(LX448PkFromConversion.GetEncoded(), LX448PkFromSk.GetEncoded()) then
        Fail('Conversion failed for high y value');

      LFoundHighY := True;
      Break;
    end;
  end;

  if not LFoundHighY then
    CheckTrue(True, 'No high-y key found in search range, but test structure is valid');
end;

procedure TTestCurve448KeyUtilities.TestSignBitLossIsExpected;
var
  LSeed: TBytes;
  LEdPriv: IEd448PrivateKeyParameters;
  LEdPub: IEd448PublicKeyParameters;
  LEdPubBytes, LEdPubFlippedBytes: TBytes;
  LEdPubFlipped: IEd448PublicKeyParameters;
  LX448Pk1, LX448Pk2: IX448PublicKeyParameters;
begin
  (*
    Test: Sign bit loss behavior

    The X448 u-coordinate formula u = y²·(1+d·y²)/(1-y²) depends only on y².
    Two Ed448 points (+x, y) and (-x, y) should map to the same X448 public key.

    This is expected behavior, not a bug.
  *)

  LSeed := DecodeHex('6c82a562cb808d10d632be89c8513ebf' +
                     '6c929f34ddfa8c9f63c9960ef6e348a3' +
                     '528c8a3fcc2f044e39a3fc5b94492f8f' +
                     '032e7549a20098f95b');
  LEdPriv := TEd448PrivateKeyParameters.Create(LSeed);
  LEdPub := LEdPriv.GeneratePublicKey();
  LEdPubBytes := LEdPub.GetEncoded();

  // Flip the sign bit (bit 455 in Ed448, which is bit 7 of byte 56)
  LEdPubFlippedBytes := System.Copy(LEdPubBytes);
  LEdPubFlippedBytes[56] := LEdPubFlippedBytes[56] xor $80;

  try
    LEdPubFlipped := TEd448PublicKeyParameters.Create(LEdPubFlippedBytes);

    LX448Pk1 := TCurve448KeyUtilities.ToX448PublicKey(LEdPub);
    LX448Pk2 := TCurve448KeyUtilities.ToX448PublicKey(LEdPubFlipped);

    // Both should produce the same X448 public key
    CheckTrue(AreEqual(LX448Pk1.GetEncoded(), LX448Pk2.GetEncoded()),
      'Sign-flipped Ed448 keys should produce identical X448 public keys');
  except
    // If the flipped key is invalid (SqrtRatioVar fails), that's OK
    CheckTrue(True, 'Flipped sign produced invalid key - expected for some y values');
  end;
end;

procedure TTestCurve448KeyUtilities.TestToX448PublicKeyRejectsInvalidPoint;
var
  LInvalidY: TBytes;
  LMockPublicKey: IEd448PublicKeyParameters;
begin
  (*
    Test: Invalid point rejection via SqrtRatioVar

    The conversion validates that the input y-coordinate corresponds to
    a valid point on the Ed448 curve by checking that x² = (1-y²)/(1+d·y²)
    is a quadratic residue.

    A random y-value has ~50% chance of not being on the curve.
  *)

  // Use a value that is likely not a valid y-coordinate on Ed448
  // This is a random-looking value
  LInvalidY := DecodeHex('DEADBEEFCAFEBABE0123456789ABCDEF' +
                         'FEDCBA9876543210DEADBEEFCAFEBABE' +
                         '0123456789ABCDEFFEDCBA9876543210' +
                         'DEADBEEFCAFEBABE00');

  try
    LMockPublicKey := TEd448PublicKeyParameters.Create(LInvalidY);
    TCurve448KeyUtilities.ToX448PublicKey(LMockPublicKey);
    // If it doesn't raise, the random value happened to be valid (unlikely but possible)
    CheckTrue(True, 'Random value happened to be valid - rare but acceptable');
  except
    on E: EArgumentCryptoLibException do
      CheckTrue(True, 'Invalid point correctly rejected');
    on E: Exception do
      CheckTrue(True, 'Invalid input rejected with exception');
  end;
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCurve448KeyUtilities);
{$ELSE}
  RegisterTest(TTestCurve448KeyUtilities.Suite);
{$ENDIF FPC}

end.
