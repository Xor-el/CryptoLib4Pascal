{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit DHTests;

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
  ClpISecureRandom,
  ClpSecureRandom,
  ClpIParametersWithRandom,
  ClpParametersWithRandom,
  ClpICipherParameters,
  ClpIBasicAgreement,
  ClpIKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpGeneratorUtilities,
  ClpAgreementUtilities,
  ClpIDHAgreement,
  ClpDHAgreement,
  ClpIDHBasicAgreement,
  ClpDHBasicAgreement,
  ClpIDHParameters,
  ClpDHParameters,
  ClpIDHGenerators,
  ClpDHGenerators,
  ClpIAsymmetricCipherKeyPair,
  ClpPublicKeyFactory,
  ClpPrivateKeyFactory,
  ClpSubjectPublicKeyInfoFactory,
  ClpPrivateKeyInfoFactory,
  ClpIAsymmetricKeyParameter,
  ClpPkcsObjectIdentifiers,
  ClpBigInteger,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TTestDH = class(TCryptoLibAlgorithmTestCase)

  private
  var
    Fg512, Fp512, Fg768, Fp768, Fg1024, Fp1024: TBigInteger;

    function GetDHBasicKeyPairGenerator(const g, p: TBigInteger;
      privateValueSize: Int32): IDHBasicKeyPairGenerator;

    function GetDHKeyPairGenerator(const g, p: TBigInteger)
      : IDHKeyPairGenerator;

    procedure DoTestDH(size: Int32; const g, p: TBigInteger);

    procedure DoTestDHBasic(size, privateValueSize: Int32;
      const g, p: TBigInteger);

    procedure DoCheckKeySize(privateValueSize: Int32;
      const priv: IDHPrivateKeyParameters);

    procedure DoTestGPWithRandom(const kpGen: IDHKeyPairGenerator);

    procedure DoTestSimpleWithRandom(const kpGen: IDHBasicKeyPairGenerator);

    // this test can take quiet a while
    procedure DoTestGeneration(size: Int32);

    { SPKI/PKCS#8 round-trip, 3-party. }
    procedure DoImplTestGP(const AlgName: string; size, privateValueSize: Int32;
      const g, p: TBigInteger);

    procedure DoImplTestExplicitWrapping(size, privateValueSize: Int32;
      const g, p: TBigInteger);

    class function Ike2048: IDHParameters; static;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestDHBasic;
    procedure TestDH;
    //
    // generation test.
    //
    procedure TestGeneration;
    //
    // with random test
    //
    procedure TestSimpleWithRandom;
    procedure TestGPWithRandom;
    //
    // parameter tests
    //
    procedure TestParameters;

    procedure TestDHUtilityPath;
    procedure TestExplicitWrapping;
    procedure TestDHEncodingVectors;
    procedure TestDHExceptions;
    (**
     * Tests whether a provider accepts invalid public keys that result in predictable shared secrets.
     * This test is based on RFC 2785, Section 4 and NIST SP 800-56A,
     * If an attacker can modify both public keys in an ephemeral-ephemeral key agreement scheme then
     * it may be possible to coerce both parties into computing the same predictable shared key.
     * <p/>
     * Note: the test is quite whimsical. If the prime p is not a safe prime then the provider itself
     * cannot prevent all small-subgroup attacks because of the missing parameter q in the
     * Diffie-Hellman parameters. Implementations must add additional countermeasures such as the ones
     * proposed in RFC 2785.
     *)
    procedure TestDHSubgroupConfinement;
  end;

implementation

type
  { Invalid Y with valid DH parameters }
  TDHWeakPublicKeyStub = class(TDHPublicKeyParameters, IDHPublicKeyParameters)
  strict private
    FWeakY: TBigInteger;
  strict protected
  function GetY: TBigInteger; override;
  public
    constructor Create(const AWeakY: TBigInteger; const AParams: IDHParameters);

  end;

{ TDHWeakPublicKeyStub }

constructor TDHWeakPublicKeyStub.Create(const AWeakY: TBigInteger;
  const AParams: IDHParameters);
begin
  inherited Create(TBigInteger.Two, AParams);
  FWeakY := AWeakY;
end;

function TDHWeakPublicKeyStub.GetY: TBigInteger;
begin
  Result := FWeakY;
end;

{ TTestDH }

class function TTestDH.Ike2048: IDHParameters;
var
  lp: TBigInteger;
begin
  lp := TBigInteger.Create(
    'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74' +
    '020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F1437' +
    '4FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
    'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF05' +
    '98DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB' +
    '9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
    'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF695581718' +
    '3995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF',
    16);
  Result := TDHParameters.Create(lp, TBigInteger.Two);
end;

procedure TTestDH.DoImplTestExplicitWrapping(size, privateValueSize: Int32;
  const g, p: TBigInteger);
var
  random: ISecureRandom;
  dhParams: IDHParameters;
  keyGen: IAsymmetricCipherKeyPairGenerator;
  aKeyPair, bKeyPair: IAsymmetricCipherKeyPair;
  aAgree, bAgree: IBasicAgreement;
  b1, b2: TBigInteger;
begin
  random := TSecureRandom.Create();
  dhParams := TDHParameters.Create(p, g, TBigInteger.GetDefault, privateValueSize);
  keyGen := TGeneratorUtilities.GetKeyPairGenerator('DH');
  keyGen.Init(TDHKeyGenerationParameters.Create(random, dhParams) as IKeyGenerationParameters);
  aKeyPair := keyGen.GenerateKeyPair;
  bKeyPair := keyGen.GenerateKeyPair;
  DoCheckKeySize(privateValueSize, aKeyPair.Private as IDHPrivateKeyParameters);
  DoCheckKeySize(privateValueSize, bKeyPair.Private as IDHPrivateKeyParameters);
  aAgree := TAgreementUtilities.GetBasicAgreement('DH');
  bAgree := TAgreementUtilities.GetBasicAgreement('DH');
  aAgree.Init(aKeyPair.Private as ICipherParameters);
  bAgree.Init(bKeyPair.Private as ICipherParameters);
  b1 := aAgree.CalculateAgreement(bKeyPair.Public as ICipherParameters);
  b2 := bAgree.CalculateAgreement(aKeyPair.Public as ICipherParameters);
  if not b1.Equals(b2) then
    Fail('Explicit wrapping test failed');
end;

procedure TTestDH.DoImplTestGP(const AlgName: string; size, privateValueSize: Int32;
  const g, p: TBigInteger);
var
  random: ISecureRandom;
  dhParams: IDHParameters;
  keyGen, aPairGen, bPairGen, cPairGen: IAsymmetricCipherKeyPairGenerator;
  aKeyPair, bKeyPair: IAsymmetricCipherKeyPair;
  aAgreeBasic, bAgreeBasic: IBasicAgreement;
  k1, k2: TBigInteger;
  pubEnc, privEnc: TBytes;
  pubKey: IDHPublicKeyParameters;
  privKey: IDHPrivateKeyParameters;
  spec: IDHParameters;
  aPair, bPair, cPair: IAsymmetricCipherKeyPair;
  aKeyAgree, bKeyAgree, cKeyAgree: IBasicAgreement;
  ac, ba, cb: IDHPublicKeyParameters;
  aShared, bShared, cShared: TBigInteger;
begin
  random := TSecureRandom.Create() as ISecureRandom;
  dhParams := TDHParameters.Create(p, g, TBigInteger.GetDefault, privateValueSize);
  keyGen := TGeneratorUtilities.GetKeyPairGenerator(AlgName);
  keyGen.Init(TDHKeyGenerationParameters.Create(random, dhParams) as IKeyGenerationParameters);

  aKeyPair := keyGen.GenerateKeyPair;
  aAgreeBasic := TAgreementUtilities.GetBasicAgreement(AlgName);
  DoCheckKeySize(privateValueSize, aKeyPair.Private as IDHPrivateKeyParameters);
  aAgreeBasic.Init(aKeyPair.Private as ICipherParameters);

  bKeyPair := keyGen.GenerateKeyPair;
  bAgreeBasic := TAgreementUtilities.GetBasicAgreement(AlgName);
  DoCheckKeySize(privateValueSize, bKeyPair.Private as IDHPrivateKeyParameters);
  bAgreeBasic.Init(bKeyPair.Private as ICipherParameters);

  k1 := aAgreeBasic.CalculateAgreement(bKeyPair.Public as ICipherParameters);
  k2 := bAgreeBasic.CalculateAgreement(aKeyPair.Public as ICipherParameters);
  if not k1.Equals(k2) then
    Fail(Format('%d bit 2-way test failed', [size]));

  pubEnc := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(
    aKeyPair.Public as IAsymmetricKeyParameter).GetDerEncoded;
  pubKey := TPublicKeyFactory.CreateKey(pubEnc) as IDHPublicKeyParameters;
  spec := pubKey.Parameters;
  if (not spec.G.Equals(dhParams.G)) or (not spec.P.Equals(dhParams.P)) then
    Fail(Format('%d bit public key encoding/decoding test failed on parameters', [size]));
  if not((aKeyPair.Public as IDHPublicKeyParameters).Y.Equals(pubKey.Y)) then
    Fail(Format('%d bit public key encoding/decoding test failed on y value', [size]));

  if (not spec.G.Equals(dhParams.G)) or (not spec.P.Equals(dhParams.P)) then
    Fail(Format('%d bit public key serialisation test failed on parameters', [size]));
  if not((aKeyPair.Public as IDHPublicKeyParameters).Y.Equals(pubKey.Y)) then
    Fail(Format('%d bit public key serialisation test failed on y value', [size]));

  privEnc := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(
    aKeyPair.Private as IAsymmetricKeyParameter).GetDerEncoded;
  privKey := TPrivateKeyFactory.CreateKey(privEnc) as IDHPrivateKeyParameters;
  spec := privKey.Parameters;
  if (not spec.G.Equals(dhParams.G)) or (not spec.P.Equals(dhParams.P)) then
    Fail(Format('%d bit private key encoding/decoding test failed on parameters', [size]));
  if not((aKeyPair.Private as IDHPrivateKeyParameters).X.Equals(privKey.X)) then
    Fail(Format('%d bit private key encoding/decoding test failed on x value', [size]));

  if (not spec.G.Equals(dhParams.G)) or (not spec.P.Equals(dhParams.P)) then
    Fail(Format('%d bit private key serialisation test failed on parameters', [size]));
  if not((aKeyPair.Private as IDHPrivateKeyParameters).X.Equals(privKey.X)) then
    Fail(Format('%d bit private key serialisation test failed on x value', [size]));

  aPairGen := TGeneratorUtilities.GetKeyPairGenerator(AlgName);
  aPairGen.Init(TDHKeyGenerationParameters.Create(random, spec) as IKeyGenerationParameters);
  aPair := aPairGen.GenerateKeyPair;
  bPairGen := TGeneratorUtilities.GetKeyPairGenerator(AlgName);
  bPairGen.Init(TDHKeyGenerationParameters.Create(random, spec) as IKeyGenerationParameters);
  bPair := bPairGen.GenerateKeyPair;
  cPairGen := TGeneratorUtilities.GetKeyPairGenerator(AlgName);
  cPairGen.Init(TDHKeyGenerationParameters.Create(random, spec) as IKeyGenerationParameters);
  cPair := cPairGen.GenerateKeyPair;

  aKeyAgree := TAgreementUtilities.GetBasicAgreement(AlgName);
  aKeyAgree.Init(aPair.Private as ICipherParameters);
  bKeyAgree := TAgreementUtilities.GetBasicAgreement(AlgName);
  bKeyAgree.Init(bPair.Private as ICipherParameters);
  cKeyAgree := TAgreementUtilities.GetBasicAgreement(AlgName);
  cKeyAgree.Init(cPair.Private as ICipherParameters);

  ac := TDHPublicKeyParameters.Create(
    aKeyAgree.CalculateAgreement(cPair.Public as ICipherParameters), spec);
  ba := TDHPublicKeyParameters.Create(
    bKeyAgree.CalculateAgreement(aPair.Public as ICipherParameters), spec);
  cb := TDHPublicKeyParameters.Create(
    cKeyAgree.CalculateAgreement(bPair.Public as ICipherParameters), spec);

  aShared := aKeyAgree.CalculateAgreement(cb as ICipherParameters);
  bShared := bKeyAgree.CalculateAgreement(ac as ICipherParameters);
  cShared := cKeyAgree.CalculateAgreement(ba as ICipherParameters);

  if not aShared.Equals(bShared) then
    Fail(Format('%d bit 3-way test failed (a and b differ)', [size]));
  if not cShared.Equals(bShared) then
    Fail(Format('%d bit 3-way test failed (c and b differ)', [size]));
end;

procedure TTestDH.TestDHUtilityPath;
begin
  DoImplTestGP('DH', 512, 0, Fg512, Fp512);
  DoImplTestGP('DiffieHellman', 768, 0, Fg768, Fp768);
  DoImplTestGP('DIFFIEHELLMAN', 1024, 0, Fg1024, Fp1024);
  DoImplTestGP('DH', 512, 64, Fg512, Fp512);
  DoImplTestGP('DiffieHellman', 768, 128, Fg768, Fp768);
  DoImplTestGP('DIFFIEHELLMAN', 1024, 256, Fg1024, Fp1024);
end;

procedure TTestDH.TestExplicitWrapping;
begin
  DoImplTestExplicitWrapping(512, 0, Fg512, Fp512);
end;

procedure TTestDH.TestDHEncodingVectors;
var
  k: IAsymmetricKeyParameter;
  encoded: TBytes;
  samplePrivEnc, samplePubEnc, oldPubEnc, oldFullParams: TBytes;
begin
  samplePrivEnc := DecodeBase64(
    'MIIBZgIBADCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YR' +
    't1I870QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZ' +
    'UKWkn5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOu' +
    'K2HXKu/yIgMZndFIAccCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0H' +
    'gmdRWVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuz' +
    'pnWRbqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7P' +
    'SSoCAgIABEICQAZYXnBHazxXUUdFP4NIf2Ipu7du0suJPZQKKff81wymi2zfCfHh' +
    'uhe9gQ9xdm4GpzeNtrQ8/MzpTy+ZVrtd29Q=');
  samplePubEnc := DecodeBase64(
    'MIIBpjCCARsGCSqGSIb3DQEDATCCAQwCgYEA/X9TgR11EilS30qcLuzk5/YRt1I8' +
    '70QAwx4/gLZRJmlFXUAiUftZPY1Y+r/F9bow9subVWzXgTuAHTRv8mZgt2uZUKWk' +
    'n5/oBHsQIsJPu6nX/rfGG/g7V+fGqKYVDwT7g/bTxR7DAjVUE1oWkTL2dfOuK2HX' +
    'Ku/yIgMZndFIAccCgYEA9+GghdabPd7LvKtcNrhXuXmUr7v6OuqC+VdMCz0HgmdR' +
    'WVeOutRZT+ZxBxCBgLRJFnEj6EwoFhO3zwkyjMim4TwWeotUfI0o4KOuHiuzpnWR' +
    'bqN/C/ohNWLx+2J6ASQ7zKTxvqhRkImog9/hWuWfBpKLZl6Ae1UlZAFMO/7PSSoC' +
    'AgIAA4GEAAKBgEIiqxoUW6E6GChoOgcfNbVFclW91ITf5MFSUGQwt2R0RHoOhxvO' +
    'lZhNs++d0VPATLAyXovjfgENT9SGCbuZttYcqqLdKTbMXBWPek+rfnAl9E4iEMED' +
    'IDd83FJTKs9hQcPAm7zmp0Xm1bGF9CbUFjP5G02265z7eBmHDaT0SNlB');
  oldPubEnc := DecodeBase64(
    'MIIBnzCCARQGByqGSM4+AgEwggEHAoGBAPxSrN417g43VAM9sZRf1dt6AocAf7D6' +
    'WVCtqEDcBJrMzt63+g+BNJzhXVtbZ9kp9vw8L/0PHgzv0Ot/kOLX7Khn+JalOECW' +
    'YlkyBhmOVbjR79TY5u2GAlvG6pqpizieQNBCEMlUuYuK1Iwseil6VoRuA13Zm7uw' +
    'WO1eZmaJtY7LAoGAQaPRCFKM5rEdkMrV9FNzeSsYRs8m3DqPnnJHpuySpyO9wUcX' +
    'OOJcJY5qvHbDO5SxHXu/+bMgXmVT6dXI5o0UeYqJR7fj6pR4E6T0FwG55RFr5Ok4' +
    '3C4cpXmaOu176SyWuoDqGs1RDGmYQjwbZUi23DjaaTFUly9LCYXMliKrQfEDgYQA' +
    'AoGAQUGCBN4TaBw1BpdBXdTvTfCU69XDB3eyU2FOBE3UWhpx9D8XJlx4f5DpA4Y6' +
    '6sQMuCbhfmjEph8W7/sbMurM/awR+PSR8tTY7jeQV0OkmAYdGK2nzh0ZSifMO1oE' +
    'NNhN2O62TLs67msxT28S4/S89+LMtc98mevQ2SX+JF3wEVU=');
  oldFullParams := DecodeBase64(
    'MIIBIzCCARgGByqGSM4+AgEwggELAoGBAP1/U4EddRIpUt9KnC7s5Of2EbdSPO9E' +
    'AMMeP4C2USZpRV1AIlH7WT2NWPq/xfW6MPbLm1Vs14E7gB00b/JmYLdrmVClpJ+f' +
    '6AR7ECLCT7up1/63xhv4O1fnxqimFQ8E+4P208UewwI1VBNaFpEy9nXzrith1yrv' +
    '8iIDGZ3RSAHHAoGBAPfhoIXWmz3ey7yrXDa4V7l5lK+7+jrqgvlXTAs9B4JnUVlX' +
    'jrrUWU/mcQcQgYC0SRZxI+hMKBYTt88JMozIpuE8FnqLVHyNKOCjrh4rs6Z1kW6j' +
    'fwv6ITVi8ftiegEkO8yk8b6oUZCJqIPf4VrlnwaSi2ZegHtVJWQBTDv+z0kqAgFk' +
    'AwUAAgIH0A==');

  k := TPrivateKeyFactory.CreateKey(samplePrivEnc);
  encoded := TPrivateKeyInfoFactory.CreatePrivateKeyInfo(k).GetDerEncoded;
  if not AreEqual(samplePrivEnc, encoded) then
    Fail('private key re-encode failed');

  k := TPublicKeyFactory.CreateKey(samplePubEnc);
  encoded := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(k).GetDerEncoded;
  if not AreEqual(samplePubEnc, encoded) then
    Fail('public key re-encode failed');

  k := TPublicKeyFactory.CreateKey(oldPubEnc);
  encoded := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(k).GetDerEncoded;
  if not AreEqual(oldPubEnc, encoded) then
    Fail('old public key re-encode failed');

  k := TPublicKeyFactory.CreateKey(oldFullParams);
  encoded := TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(k).GetDerEncoded;
  if not AreEqual(oldFullParams, encoded) then
    Fail('old full public key re-encode failed');
end;

procedure TTestDH.TestDHExceptions;
var
  caught: Boolean;
begin
  caught := False;
  try
    TAgreementUtilities.GetBasicAgreement('DH').CalculateAgreement(nil);
  except
    on EInvalidOperationCryptoLibException do
      caught := True;
  end;
  if not caught then
    Fail('Expected EInvalidOperationCryptoLibException when agreement not initialised');
end;

procedure TTestDH.TestDHSubgroupConfinement;
var
  parameters: IDHParameters;
  p: TBigInteger;
  keyGen: IAsymmetricCipherKeyPairGenerator;
  random: ISecureRandom;
  kp: IAsymmetricCipherKeyPair;
  priv: IDHPrivateKeyParameters;
  ka: IBasicAgreement;
  weakYs: array[0..5] of TBigInteger;
  i: Int32;
  weakKey: TBigInteger;
  ctorOk, agreeOk: Boolean;
  badPub: IDHPublicKeyParameters;
begin
  parameters := Ike2048;
  p := parameters.P;
  random := TSecureRandom.Create();
  keyGen := TGeneratorUtilities.GetKeyPairGenerator('DH');
  keyGen.Init(TDHKeyGenerationParameters.Create(random, parameters) as IKeyGenerationParameters);
  kp := keyGen.GenerateKeyPair;
  priv := kp.Private as IDHPrivateKeyParameters;
  ka := TAgreementUtilities.GetBasicAgreement('DH');

  weakYs[0] := TBigInteger.Zero;
  weakYs[1] := TBigInteger.One;
  weakYs[2] := p.Subtract(TBigInteger.One);
  weakYs[3] := p;
  weakYs[4] := p.Add(TBigInteger.One);
  weakYs[5] := TBigInteger.One.Negate;

  for i := 0 to High(weakYs) do
  begin
    weakKey := weakYs[i];
    ctorOk := False;
    badPub := nil;
    try
      badPub := TDHPublicKeyParameters.Create(weakKey, parameters);
      ctorOk := True;
    except
      on E: EArgumentCryptoLibException do
        if Pos('Invalid DH public key', E.Message) = 0 then
          Fail('wrong constructor exception message: ' + E.Message);
    end;
    if ctorOk then
      Fail(Format('Generated weak public key (Y bit length %d)',
        [badPub.Y.BitLength]));
    badPub := nil;

    ka.Init(priv as ICipherParameters);
    agreeOk := False;
    try
      ka.CalculateAgreement(TDHWeakPublicKeyStub.Create(weakKey, parameters) as ICipherParameters);
      agreeOk := True;
    except
      on E: EArgumentCryptoLibException do
        if Pos('Weak', E.Message) = 0 then
          Fail('wrong CalculateAgreement exception message: ' + E.Message);
    end;
    if agreeOk then
      Fail('Generated secrets with weak public key');
  end;
end;

function TTestDH.GetDHBasicKeyPairGenerator(const g, p: TBigInteger;
  privateValueSize: Int32): IDHBasicKeyPairGenerator;
var
  dhParams: IDHParameters;
  dhkgParams: IDHKeyGenerationParameters;
  kpGen: IDHBasicKeyPairGenerator;
begin
  dhParams := TDHParameters.Create(p, g, TBigInteger.GetDefault,
    privateValueSize);

  dhkgParams := TDHKeyGenerationParameters.Create(TSecureRandom.Create()
    as ISecureRandom, dhParams);

  kpGen := TDHBasicKeyPairGenerator.Create();

  kpGen.Init(dhkgParams);

  result := kpGen;
end;

function TTestDH.GetDHKeyPairGenerator(const g, p: TBigInteger)
  : IDHKeyPairGenerator;
var
  dhParams: IDHParameters;
  dhkgParams: IDHKeyGenerationParameters;
  kpGen: IDHKeyPairGenerator;
begin
  dhParams := TDHParameters.Create(p, g);

  dhkgParams := TDHKeyGenerationParameters.Create(TSecureRandom.Create()
    as ISecureRandom, dhParams);

  kpGen := TDHKeyPairGenerator.Create();

  kpGen.Init(dhkgParams);

  result := kpGen;
end;

procedure TTestDH.DoCheckKeySize(privateValueSize: Int32;
  const priv: IDHPrivateKeyParameters);
begin
  if (privateValueSize <> 0) then
  begin
    if (priv.X.BitLength <> privateValueSize) then
    begin
      Fail(Format('limited key check failed for key size %d',
        [privateValueSize]));
    end;
  end;
end;

procedure TTestDH.DoTestDH(size: Int32; const g, p: TBigInteger);
var
  kpGen: IDHKeyPairGenerator;
  pair: IAsymmetricCipherKeyPair;
  pu1, pu2: IDHPublicKeyParameters;
  pv1, pv2: IDHPrivateKeyParameters;
  e1, e2: IDHAgreement;
  m1, m2, k1, k2: TBigInteger;
begin
  kpGen := GetDHKeyPairGenerator(g, p);

  //
  // generate first pair
  //
  pair := kpGen.GenerateKeyPair();

  pu1 := pair.Public as IDHPublicKeyParameters;
  pv1 := pair.Private as IDHPrivateKeyParameters;
  //
  // generate second pair
  //
  pair := kpGen.GenerateKeyPair();

  pu2 := pair.Public as IDHPublicKeyParameters;
  pv2 := pair.Private as IDHPrivateKeyParameters;

  //
  // two way
  //
  e1 := TDHAgreement.Create();
  e2 := TDHAgreement.Create();

  e1.Init(pv1);
  e2.Init(pv2);

  m1 := e1.CalculateMessage();
  m2 := e2.CalculateMessage();

  k1 := e1.CalculateAgreement(pu2, m2);
  k2 := e2.CalculateAgreement(pu1, m1);

  if (not k1.Equals(k2)) then
  begin
    Fail(Format('" %d " bit 2-way test failed', [size]));
  end;
end;

procedure TTestDH.DoTestDHBasic(size, privateValueSize: Int32;
  const g, p: TBigInteger);
var
  kpGen: IDHBasicKeyPairGenerator;
  pair: IAsymmetricCipherKeyPair;
  pu1, pu2: IDHPublicKeyParameters;
  pv1, pv2: IDHPrivateKeyParameters;
  e1, e2: IDHBasicAgreement;
  k1, k2: TBigInteger;
begin
  kpGen := GetDHBasicKeyPairGenerator(g, p, privateValueSize);

  //
  // generate first pair
  //
  pair := kpGen.GenerateKeyPair();

  pu1 := pair.Public as IDHPublicKeyParameters;
  pv1 := pair.Private as IDHPrivateKeyParameters;

  DoCheckKeySize(privateValueSize, pv1);

  //
  // generate second pair
  //
  pair := kpGen.GenerateKeyPair();

  pu2 := pair.Public as IDHPublicKeyParameters;
  pv2 := pair.Private as IDHPrivateKeyParameters;

  DoCheckKeySize(privateValueSize, pv2);

  //
  // two way
  //
  e1 := TDHBasicAgreement.Create();
  e2 := TDHBasicAgreement.Create();

  e1.Init(pv1);
  e2.Init(pv2);

  k1 := e1.CalculateAgreement(pu2);
  k2 := e2.CalculateAgreement(pu1);

  if (not k1.Equals(k2)) then
  begin
    Fail(Format('basic " %d " bit 2-way test failed', [size]));
  end;
end;

procedure TTestDH.DoTestGeneration(size: Int32);
var
  kpGen: IDHBasicKeyPairGenerator;
  pGen: IDHParametersGenerator;
  dhParams: IDHParameters;
  dhkgParams: IDHKeyGenerationParameters;
  pair: IAsymmetricCipherKeyPair;
  pu1, pu2: IDHPublicKeyParameters;
  pv1, pv2: IDHPrivateKeyParameters;
  e1, e2: IDHBasicAgreement;
  k1, k2: TBigInteger;
begin

  pGen := TDHParametersGenerator.Create();

  pGen.Init(size, 10, TSecureRandom.Create() as ISecureRandom);

  dhParams := pGen.GenerateParameters();

  if (dhParams.L <> 0) then
  begin
    Fail('DHParametersGenerator failed to set J to 0 in generated DHParameters');
  end;

  dhkgParams := TDHKeyGenerationParameters.Create(TSecureRandom.Create()
    as ISecureRandom, dhParams);

  kpGen := TDHBasicKeyPairGenerator.Create();

  kpGen.Init(dhkgParams);

  //
  // generate first pair
  //
  pair := kpGen.GenerateKeyPair();

  pu1 := pair.Public as IDHPublicKeyParameters;
  pv1 := pair.Private as IDHPrivateKeyParameters;

  //
  // generate second pair
  //
  dhkgParams := TDHKeyGenerationParameters.Create(TSecureRandom.Create()
    as ISecureRandom, pu1.Parameters);

  kpGen.Init(dhkgParams);

  pair := kpGen.GenerateKeyPair();

  pu2 := pair.Public as IDHPublicKeyParameters;
  pv2 := pair.Private as IDHPrivateKeyParameters;

  //
  // two way
  //
  e1 := TDHBasicAgreement.Create();
  e2 := TDHBasicAgreement.Create();

  e1.Init(TParametersWithRandom.Create(pv1, TSecureRandom.Create()
    as ISecureRandom) as IParametersWithRandom);
  e2.Init(TParametersWithRandom.Create(pv2, TSecureRandom.Create()
    as ISecureRandom) as IParametersWithRandom);

  k1 := e1.CalculateAgreement(pu2);
  k2 := e2.CalculateAgreement(pu1);

  if (not k1.Equals(k2)) then
  begin
    Fail(Format('basic with " %d " bit 2-way test failed', [size]));
  end;
end;

procedure TTestDH.DoTestGPWithRandom(const kpGen: IDHKeyPairGenerator);
var
  pair: IAsymmetricCipherKeyPair;
  pu1, pu2: IDHPublicKeyParameters;
  pv1, pv2: IDHPrivateKeyParameters;
  e1, e2: IDHAgreement;
  m1, m2, k1, k2: TBigInteger;
begin

  //
  // generate first pair
  //
  pair := kpGen.GenerateKeyPair();

  pu1 := pair.Public as IDHPublicKeyParameters;
  pv1 := pair.Private as IDHPrivateKeyParameters;
  //
  // generate second pair
  //
  pair := kpGen.GenerateKeyPair();

  pu2 := pair.Public as IDHPublicKeyParameters;
  pv2 := pair.Private as IDHPrivateKeyParameters;

  //
  // two way
  //
  e1 := TDHAgreement.Create();
  e2 := TDHAgreement.Create();

  e1.Init(TParametersWithRandom.Create(pv1, TSecureRandom.Create()
    as ISecureRandom) as IParametersWithRandom);
  e2.Init(TParametersWithRandom.Create(pv2, TSecureRandom.Create()
    as ISecureRandom) as IParametersWithRandom);

  m1 := e1.CalculateMessage();
  m2 := e2.CalculateMessage();

  k1 := e1.CalculateAgreement(pu2, m2);
  k2 := e2.CalculateAgreement(pu1, m1);

  if (not k1.Equals(k2)) then
  begin
    Fail('full with random 2-way test failed');
  end;
end;

procedure TTestDH.DoTestSimpleWithRandom(const kpGen: IDHBasicKeyPairGenerator);
var
  pair: IAsymmetricCipherKeyPair;
  pu1, pu2: IDHPublicKeyParameters;
  pv1, pv2: IDHPrivateKeyParameters;
  e1, e2: IDHBasicAgreement;
  k1, k2: TBigInteger;
begin

  //
  // generate first pair
  //
  pair := kpGen.GenerateKeyPair();

  pu1 := pair.Public as IDHPublicKeyParameters;
  pv1 := pair.Private as IDHPrivateKeyParameters;

  //
  // generate second pair
  //
  pair := kpGen.GenerateKeyPair();

  pu2 := pair.Public as IDHPublicKeyParameters;
  pv2 := pair.Private as IDHPrivateKeyParameters;

  //
  // two way
  //
  e1 := TDHBasicAgreement.Create();
  e2 := TDHBasicAgreement.Create();

  e1.Init(TParametersWithRandom.Create(pv1, TSecureRandom.Create()
    as ISecureRandom) as IParametersWithRandom);
  e2.Init(TParametersWithRandom.Create(pv2, TSecureRandom.Create()
    as ISecureRandom) as IParametersWithRandom);

  k1 := e1.CalculateAgreement(pu2);
  k2 := e2.CalculateAgreement(pu1);

  if (not k1.Equals(k2)) then
  begin
    Fail('basic with random 2-way test failed');
  end;
end;

procedure TTestDH.TestDH;
begin
  DoTestDH(512, Fg512, Fp512);
  DoTestDH(768, Fg768, Fp768);
  DoTestDH(1024, Fg1024, Fp1024);
end;

procedure TTestDH.TestDHBasic;
begin
  DoTestDHBasic(512, 0, Fg512, Fp512);
  DoTestDHBasic(768, 0, Fg768, Fp768);
  DoTestDHBasic(1024, 0, Fg1024, Fp1024);

  DoTestDHBasic(512, 64, Fg512, Fp512);
  DoTestDHBasic(768, 128, Fg768, Fp768);
  DoTestDHBasic(1024, 256, Fg1024, Fp1024);
end;

procedure TTestDH.TestGeneration;
begin
  DoTestGeneration(256);
end;

procedure TTestDH.TestGPWithRandom;
var
  kpGen: IDHKeyPairGenerator;
begin
  kpGen := GetDHKeyPairGenerator(Fg512, Fp512);

  DoTestGPWithRandom(kpGen);
end;

procedure TTestDH.TestSimpleWithRandom;
var
  kpBasicGen: IDHBasicKeyPairGenerator;
begin
  kpBasicGen := GetDHBasicKeyPairGenerator(Fg512, Fp512, 0);

  DoTestSimpleWithRandom(kpBasicGen);
end;

procedure TTestDH.TestParameters;
var
  dh: IDHAgreement;
  dhBasic: IDHBasicAgreement;
  kpGen, kpGen768: IDHKeyPairGenerator;
  kpBasicGen, kpBasicGen768: IDHBasicKeyPairGenerator;
  dhPair, dhBasicPair: IAsymmetricCipherKeyPair;
begin

  dh := TDHAgreement.Create();
  kpGen := GetDHKeyPairGenerator(Fg512, Fp512);
  dhPair := kpGen.GenerateKeyPair();

  try
    dh.Init(dhPair.Public);
    Fail('DHAgreement key check failed');

  except
    on e: EArgumentCryptoLibException do
    begin
      // ignore
    end;

  end;

  kpGen768 := GetDHKeyPairGenerator(Fg768, Fp768);

  try
    dh.Init(dhPair.Private);

    dh.CalculateAgreement(kpGen768.GenerateKeyPair()
      .Public as IDHPublicKeyParameters, TBigInteger.ValueOf(100));

    Fail('DHAgreement agreement check failed');

  except
    on e: EArgumentCryptoLibException do
    begin
      // ignore
    end;

  end;

  dhBasic := TDHBasicAgreement.Create();
  kpBasicGen := GetDHBasicKeyPairGenerator(Fg512, Fp512, 0);
  dhBasicPair := kpBasicGen.GenerateKeyPair();

  try
    dhBasic.Init(dhBasicPair.Public);
    Fail('DHBasicAgreement key check failed');

  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

  kpBasicGen768 := GetDHBasicKeyPairGenerator(Fg768, Fp768, 0);

  try
    dhBasic.Init(dhPair.Private);

    dhBasic.CalculateAgreement(kpBasicGen768.GenerateKeyPair()
      .Public as IDHPublicKeyParameters);

    Fail('DHBasicAgreement agreement check failed');

  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;

end;

procedure TTestDH.SetUp;
begin
  inherited;
  Fg512 := TBigInteger.Create
    ('153D5D6172ADB43045B68AE8E1DE1070B6137005686D29D3D73A7749199681EE5B212C9B96BFDCFA5B20CD5E3FD2044895D609CF9B410B7A0F12CA1CB9A428CC',
    16);
  Fp512 := TBigInteger.Create
    ('9494FEC095F3B85EE286542B3836FC81A5DD0A0349B4C239DD38744D488CF8E31DB8BCB7D33B41ABB9E5A33CCA9144B1CEF332C94BF0573BF047A3ACA98CDF3B',
    16);

  Fg768 := TBigInteger.Create
    ('7C240073C1316C621DF461B71EBB0CDCC90A6E5527E5E126633D131F87461C4DC4AFC60C2CB0F053B6758871489A69613E2A8B4C8ACDE23954C08C81CBD36132CFD64D69E4ED9F8E51ED6E516297206672D5C0A69135DF0A5DCF010D289A9CA1',
    16);
  Fp768 := TBigInteger.Create
    ('8C9DD223DEBED1B80103B8B309715BE009D48860ED5AE9B9D5D8159508EFD802E3AD4501A7F7E1CFEC78844489148CD72DA24B21EDDD01AA624291C48393E277CFC529E37075ECCEF957F3616F962D15B44AEAB4039D01B817FDE9EAA12FD73F',
    16);

  Fg1024 := TBigInteger.Create
    ('1DB17639CDF96BC4EABBA19454F0B7E5BD4E14862889A725C96EB61048DCD676CEB303D586E30F060DBAFD8A571A39C4D823982117DA5CC4E0F89C77388B7A08896362429B94A18A327604EB7FF227BFFBC83459ADE299E5'
    + '7B5F77B50FB045250934938EFA145511166E3197373E1B5B1E52DE713EB49792BEDDE722C6717ABF',
    16);
  Fp1024 := TBigInteger.Create
    ('A00E283B3C624E5B2B4D9FBC2653B5185D99499B00FD1BF244C6F0BB817B4D1C451B2958D62A0F8A38CAEF059FB5ECD25D75ED9AF403F5B5BDAB97A642902F824E3C13789FED95FA106DDFE0FF4A707C85E2EB77D49E68F2'
    + '808BCEA18CE128B178CD287C6BC00EFA9A1AD2A673FE0DCEACE53166F75B81D6709D5F8AF7C66BB7',
    16);

end;

procedure TTestDH.TearDown;
begin
  inherited;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestDH);
{$ELSE}
  RegisterTest(TTestDH.Suite);
{$ENDIF FPC}

end.
