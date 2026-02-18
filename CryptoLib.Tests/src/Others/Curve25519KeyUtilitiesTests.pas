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

unit Curve25519KeyUtilitiesTests;

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
  ClpCurve25519KeyUtilities,
  ClpEd25519Parameters,
  ClpIEd25519Parameters,
  ClpEd25519Generators,
  ClpIEd25519Generators,
  ClpIX25519Parameters,
  ClpX25519Agreement,
  ClpIX25519Agreement,
  ClpIAsymmetricCipherKeyPair,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestCurve25519KeyUtilities = class(TCryptoLibAlgorithmTestCase)
  private
  var
    FRandom: ISecureRandom;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestKeyPairConsistency;
    procedure TestKeyPairConsistencyFromRfc8032Vector1;
    procedure TestKnownAnswerFromLibsodiumSeed;
    procedure TestToX25519PublicKeyRaisesWhenNil;
    procedure TestToX25519PrivateKeyRaisesWhenNil;
    procedure TestConvertedKeysAgreement;
  end;

implementation

resourcestring
  SKeyPairConsistencyFailed = 'Key pair consistency failed: converted X25519 public does not match public derived from converted private';
  SExpectedArgumentNilException = 'Expected EArgumentNilCryptoLibException';
  SConvertedKeysAgreementFailed = 'X25519 agreement with converted keys failed';

{ TTestCurve25519KeyUtilities }

procedure TTestCurve25519KeyUtilities.SetUp;
begin
  inherited SetUp();
  FRandom := TSecureRandom.Create();
end;

procedure TTestCurve25519KeyUtilities.TearDown;
begin
  FRandom := nil;
  inherited TearDown();
end;

procedure TTestCurve25519KeyUtilities.TestKeyPairConsistency;
var
  LKpg: IEd25519KeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
  LX25519Sk: IX25519PrivateKeyParameters;
  LX25519PkFromConversion: IX25519PublicKeyParameters;
  LX25519PkFromSk: IX25519PublicKeyParameters;
begin
  LKpg := TEd25519KeyPairGenerator.Create() as IEd25519KeyPairGenerator;
  LKpg.Init(TEd25519KeyGenerationParameters.Create(FRandom)
    as IEd25519KeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  if not Supports(LKp.Private, IEd25519PrivateKeyParameters, LEdPriv) then
    Fail(SKeyPairConsistencyFailed);
  if not Supports(LKp.Public, IEd25519PublicKeyParameters, LEdPub) then
    Fail(SKeyPairConsistencyFailed);
  LX25519Sk := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPriv);
  LX25519PkFromConversion := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPub);
  LX25519PkFromSk := LX25519Sk.GeneratePublicKey();
  if not AreEqual(LX25519PkFromConversion.GetEncoded(), LX25519PkFromSk.GetEncoded()) then
    Fail(SKeyPairConsistencyFailed);
end;

procedure TTestCurve25519KeyUtilities.TestKeyPairConsistencyFromRfc8032Vector1;
var
  LSeed: TBytes;
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
  LX25519Sk: IX25519PrivateKeyParameters;
  LX25519PkFromConversion: IX25519PublicKeyParameters;
  LX25519PkFromSk: IX25519PublicKeyParameters;
begin
  LSeed := DecodeHex('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  LEdPriv := TEd25519PrivateKeyParameters.Create(LSeed);
  LEdPub := LEdPriv.GeneratePublicKey();
  LX25519Sk := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPriv);
  LX25519PkFromConversion := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPub);
  LX25519PkFromSk := LX25519Sk.GeneratePublicKey();
  if not AreEqual(LX25519PkFromConversion.GetEncoded(), LX25519PkFromSk.GetEncoded()) then
    Fail(SKeyPairConsistencyFailed);
end;

procedure TTestCurve25519KeyUtilities.TestKnownAnswerFromLibsodiumSeed;
var
  LSeed: TBytes;
  LEdPriv: IEd25519PrivateKeyParameters;
  LEdPub: IEd25519PublicKeyParameters;
  LX25519Sk: IX25519PrivateKeyParameters;
  LX25519Pk: IX25519PublicKeyParameters;
  LExpectedPkHex, LExpectedSkHex: String;
begin
  (*
    Seed and expected X25519 pk/sk from libsodium:
    keypair_seed -> https://github.com/jedisct1/libsodium/blob/master/test/default/ed25519_convert.c
    X25519 pk/sk -> https://github.com/jedisct1/libsodium/blob/master/test/default/ed25519_convert.exp
  *)
  LSeed := DecodeHex('421151a459faeade3d247115f94aedae42318124095afabe4d1451a559faedee');
  LEdPriv := TEd25519PrivateKeyParameters.Create(LSeed);
  LEdPub := LEdPriv.GeneratePublicKey();
  LX25519Sk := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPriv);
  LX25519Pk := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPub);
  LExpectedPkHex := 'f1814f0e8ff1043d8a44d25babff3cedcae6c22c3edaa48f857ae70de2baae50';
  LExpectedSkHex := '8052030376d47112be7f73ed7a019293dd12ad910b654455798b4667d73de166';
  if not AreEqual(LX25519Pk.GetEncoded(), DecodeHex(LExpectedPkHex)) then
    Fail(SKeyPairConsistencyFailed);
  if not AreEqual(LX25519Sk.GetEncoded(), DecodeHex(LExpectedSkHex)) then
    Fail(SKeyPairConsistencyFailed);
end;

procedure TTestCurve25519KeyUtilities.TestToX25519PublicKeyRaisesWhenNil;
begin
  try
    TCurve25519KeyUtilities.ToX25519PublicKey(nil);
    Fail(SExpectedArgumentNilException);
  except
    on E: EArgumentNilCryptoLibException do
      ; // expected
  else
    raise;
  end;
end;

procedure TTestCurve25519KeyUtilities.TestToX25519PrivateKeyRaisesWhenNil;
begin
  try
    TCurve25519KeyUtilities.ToX25519PrivateKey(nil);
    Fail(SExpectedArgumentNilException);
  except
    on E: EArgumentNilCryptoLibException do
      ; // expected
  else
    raise;
  end;
end;

procedure TTestCurve25519KeyUtilities.TestConvertedKeysAgreement;
var
  LKpg: IEd25519KeyPairGenerator;
  LKpA, LKpB: IAsymmetricCipherKeyPair;
  LEdPrivA, LEdPrivB: IEd25519PrivateKeyParameters;
  LEdPubA, LEdPubB: IEd25519PublicKeyParameters;
  LX25519SkA, LX25519SkB: IX25519PrivateKeyParameters;
  LX25519PubA, LX25519PubB: IX25519PublicKeyParameters;
  LAgreeA, LAgreeB: IX25519Agreement;
  LSecretA, LSecretB: TBytes;
begin
  LKpg := TEd25519KeyPairGenerator.Create() as IEd25519KeyPairGenerator;
  LKpg.Init(TEd25519KeyGenerationParameters.Create(FRandom)
    as IEd25519KeyGenerationParameters);
  LKpA := LKpg.GenerateKeyPair();
  LKpB := LKpg.GenerateKeyPair();
  if not Supports(LKpA.Private, IEd25519PrivateKeyParameters, LEdPrivA) then
    Fail(SConvertedKeysAgreementFailed);
  if not Supports(LKpA.Public, IEd25519PublicKeyParameters, LEdPubA) then
    Fail(SConvertedKeysAgreementFailed);
  if not Supports(LKpB.Private, IEd25519PrivateKeyParameters, LEdPrivB) then
    Fail(SConvertedKeysAgreementFailed);
  if not Supports(LKpB.Public, IEd25519PublicKeyParameters, LEdPubB) then
    Fail(SConvertedKeysAgreementFailed);
  LX25519SkA := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPrivA);
  LX25519PubA := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPubA);
  LX25519SkB := TCurve25519KeyUtilities.ToX25519PrivateKey(LEdPrivB);
  LX25519PubB := TCurve25519KeyUtilities.ToX25519PublicKey(LEdPubB);
  LAgreeA := TX25519Agreement.Create() as IX25519Agreement;
  LAgreeA.Init(LX25519SkA);
  System.SetLength(LSecretA, LAgreeA.AgreementSize);
  LAgreeA.CalculateAgreement(LX25519PubB, LSecretA, 0);
  LAgreeB := TX25519Agreement.Create() as IX25519Agreement;
  LAgreeB.Init(LX25519SkB);
  System.SetLength(LSecretB, LAgreeB.AgreementSize);
  LAgreeB.CalculateAgreement(LX25519PubA, LSecretB, 0);
  if not AreEqual(LSecretA, LSecretB) then
    Fail(SConvertedKeysAgreementFailed);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCurve25519KeyUtilities);
{$ELSE}
  RegisterTest(TTestCurve25519KeyUtilities.Suite);
{$ENDIF FPC}

end.
