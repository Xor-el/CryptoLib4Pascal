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

unit ECDsa5Tests;

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
  ClpFixedSecureRandom,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpECC,
  ClpIECDomainParameters,
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpECPublicKeyParameters,
  ClpECKeyPairGenerator,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpIECC,
  ClpSignerUtilities,
  ClpECDomainParameters,
  ClpIAsn1Objects,
  ClpISigner,
  ClpAsn1Objects,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  TTestECDsa5 = class(TCryptoLibAlgorithmTestCase)

  private
    function derDecode(const encoding: TBytes)
      : TCryptoLibGenericArray<TBigInteger>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestDecode();

    /// <summary>
    /// X9.62 - 1998, <br />J.3.2, Page 155, ECDSA over the field Fp <br />an
    /// example with 239 bit prime
    /// </summary>
    procedure TestECDsa239BitPrime();

    /// <summary>
    /// X9.62 - 1998, <br />J.2.1, Page 100, ECDSA over the field F2m <br />
    /// an example with 191 bit binary field
    /// </summary>
    procedure TestECDsa239BitBinary();

    procedure TestGeneration();

  end;

implementation

{ TTestECDsa5 }

function TTestECDsa5.derDecode(const encoding: TBytes)
  : TCryptoLibGenericArray<TBigInteger>;
var
  s: IAsn1Sequence;
begin
  s := TAsn1Object.FromByteArray(encoding) as IAsn1Sequence;

  result := TCryptoLibGenericArray<TBigInteger>.Create
    ((s[0] as IDerInteger).Value, (s[1] as IDerInteger).Value);
end;

procedure TTestECDsa5.SetUp;
begin
  inherited;

end;

procedure TTestECDsa5.TearDown;
begin
  inherited;

end;

procedure TTestECDsa5.TestDecode;
var
  curve: IECCurve;
  p: IECPoint;
  x, y: TBigInteger;

begin
  curve := TFpCurve.Create
    (TBigInteger.Create
    ('6277101735386680763835789423207666416083908700390324961279'), // q
    TBigInteger.Create('fffffffffffffffffffffffffffffffefffffffffffffffc', 16),
    // a
    TBigInteger.Create('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1', 16),
    // b
    TBigInteger.Create
    ('6277101735386680763835789423176059013767194773182842284081'),
    TBigInteger.One);

  p := curve.DecodePoint
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'));

  x := p.XCoord.ToBigInteger(); // p.getAffineX();

  if (not x.Equals(TBigInteger.Create
    ('188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012', 16))) then
  begin
    Fail('x uncompressed incorrectly');
  end;

  y := p.YCoord.ToBigInteger(); // p.getAffineX();
  if (not y.Equals(TBigInteger.Create
    ('7192b95ffc8da78631011ed6b24cdd573f977a11e794811', 16))) then
  begin
    Fail('y uncompressed incorrectly');
  end;
end;

procedure TTestECDsa5.TestECDsa239BitBinary;
var
  r, s: TBigInteger;
  kData, &message, sigBytes: TBytes;
  k: ISecureRandom;
  curve: IECCurve;
  parameters: IECDomainParameters;
  sKey: IECPrivateKeyParameters;
  vKey: IECPublicKeyParameters;
  sgr: ISigner;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  r := TBigInteger.Create
    ('21596333210419611985018340039034612628818151486841789642455876922391552');
  s := TBigInteger.Create
    ('197030374000731686738334997654997227052849804072198819102649413465737174');

  kData := TBigInteger.Create
    ('171278725565216523967285789236956265265265235675811949404040041670216363')
    .ToByteArrayUnsigned();

  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  curve := TF2mCurve.Create(239, // m
    36, // k
    TBigInteger.Create
    ('32010857077C5431123A46B808906756F543423E8D27877578125778AC76', 16), // a
    TBigInteger.Create
    ('790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16', 16), // b
    TBigInteger.Create
    ('2000000000000000000000000000000F4D42FFE1492A4993F1CAD666E447', 16),
    TBigInteger.Four);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305')),
    // G
    TBigInteger.Create
    ('220855883097298041197912187592864814557886993776713230936715041207411783'),
    // n
    TBigInteger.ValueOf(4)); // 4); // h

  sKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('145642755521911534651321230007534120304391871461646461466464667494947990'),
    // d
    parameters);

  vKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex
    ('045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5')),
    // Q
    parameters);

  sgr := TSignerUtilities.GetSigner('ECDSA');

  sgr.Init(true, TParametersWithRandom.Create(sKey, k)
    as IParametersWithRandom);

  &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not sgr.VerifySignature(sigBytes)) then
  begin
    Fail('239 Bit EC verification failed');
  end;

  sig := derDecode(sigBytes);

  if (not r.Equals(sig[0])) then
  begin
    Fail('r component wrong.' + sLineBreak + ' expecting: ' + r.ToString +
      sLineBreak + ' got      : ' + sig[0].ToString);
  end;

  if (not s.Equals(sig[1])) then
  begin
    Fail('s component wrong.' + sLineBreak + ' expecting: ' + s.ToString +
      sLineBreak + ' got      : ' + sig[1].ToString);
  end;
end;

procedure TTestECDsa5.TestECDsa239BitPrime;
var
  r, s: TBigInteger;
  kData, &message, sigBytes: TBytes;
  k: ISecureRandom;
  curve: IECCurve;
  spec: IECDomainParameters;
  sKey: IECPrivateKeyParameters;
  vKey: IECPublicKeyParameters;
  sgr: ISigner;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  r := TBigInteger.Create
    ('308636143175167811492622547300668018854959378758531778147462058306432176');
  s := TBigInteger.Create
    ('323813553209797357708078776831250505931891051755007842781978505179448783');

  kData := TBigInteger.Create
    ('700000017569056646655505781757157107570501575775705779575555657156756655')
    .ToByteArrayUnsigned();

  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b', 16),
    TBigInteger.One);

  spec := TECDomainParameters.Create(curve,

    curve.DecodePoint
    (DecodeHex('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')
    ) as IECPoint, // G
    TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307'),
    // n
    TBigInteger.One); // h

  sKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('876300101507107567501066130761671078357010671067781776716671676178726717'),
    // d
    spec);

  vKey := TECPublicKeyParameters.Create('ECDSA',

    curve.DecodePoint
    (DecodeHex('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')
    ) as IECPoint, // Q
    spec);

  sgr := TSignerUtilities.GetSigner('ECDSA');

  sgr.Init(true, TParametersWithRandom.Create(sKey, k)
    as IParametersWithRandom);

  &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not sgr.VerifySignature(sigBytes)) then
  begin
    Fail('239 Bit EC verification failed');
  end;

  sig := derDecode(sigBytes);

  if (not r.Equals(sig[0])) then
  begin
    Fail('r component wrong.' + sLineBreak + ' expecting: ' + r.ToString +
      sLineBreak + ' got      : ' + sig[0].ToString);
  end;

  if (not s.Equals(sig[1])) then
  begin
    Fail('s component wrong.' + sLineBreak + ' expecting: ' + s.ToString +
      sLineBreak + ' got      : ' + sig[1].ToString);
  end;
end;

procedure TTestECDsa5.TestGeneration;
var
  data, sigBytes: TBytes;
  s: ISigner;
  g: IAsymmetricCipherKeyPairGenerator;
  curve: IECCurve;
  ecSpec: IECDomainParameters;
  p: IAsymmetricCipherKeyPair;
  sKey, vKey: IAsymmetricKeyParameter;

begin
  //
  // ECDSA generation test
  //
  data := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);
  s := TSignerUtilities.GetSigner('ECDSA');
  g := TECKeyPairGenerator.Create('ECDSA');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffff9e5e9a9f5d9071fbd1522688909d0b', 16),
    TBigInteger.One);

  ecSpec := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')
    ) as IECPoint, // G
    TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307'),
    // n
    TBigInteger.One); // 1); // h

  g.Init(TECKeyGenerationParameters.Create(ecSpec, TSecureRandom.Create()
    as ISecureRandom));

  p := g.GenerateKeyPair();

  sKey := p.Private;
  vKey := p.Public;

  s.Init(true, sKey);

  s.BlockUpdate(data, 0, System.Length(data));

  sigBytes := s.GenerateSignature();

  s := TSignerUtilities.GetSigner('ECDSA');

  s.Init(false, vKey);

  s.BlockUpdate(data, 0, System.Length(data));

  if (not s.VerifySignature(sigBytes)) then
  begin
    Fail('ECDSA verification failed');
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestECDsa5);
{$ELSE}
  RegisterTest(TTestECDsa5.Suite);
{$ENDIF FPC}

end.
