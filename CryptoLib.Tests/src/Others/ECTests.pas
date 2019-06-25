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

unit ECTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  Classes,
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpFixedSecureRandom,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpIX9ECParameters,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpIBasicAgreement,
  ClpECDHBasicAgreement,
  ClpECDHCBasicAgreement,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpECPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpECDomainParameters,
  ClpIECDomainParameters,
  ClpIECKeyPairGenerator,
  ClpECKeyPairGenerator,
  ClpIECKeyGenerationParameters,
  ClpECKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
  ClpCustomNamedCurves,
  ClpECC,
  ClpIECC,
  ClpBigInteger,
  ClpBigIntegers,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// ECDSA tests are taken from X9.62.
  /// </summary>
  TTestEC = class(TCryptoLibAlgorithmTestCase)
  private

  var

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    /// <summary>
    /// X9.62 - 1998, <br />J.3.1, Page 152, ECDSA over the field Fp <br />an
    /// example with 192 bit prime
    /// </summary>
    procedure TestECDsa192bitPrime;
    procedure TestDecode();

    /// <summary>
    /// X9.62 - 1998, J.3.2, Page 155, ECDSA over the field Fp <br />an
    /// example with 239 bit prime
    /// </summary>
    procedure TestECDsa239bitPrime();

    /// <summary>
    /// X9.62 - 1998, <br />J.2.1, Page 100, ECDSA over the field F2m <br />
    /// an example with 191 bit binary field
    /// </summary>
    procedure TestECDsa191bitBinary();

    /// <summary>
    /// X9.62 - 1998, <br />J.2.1, Page 100, ECDSA over the field F2m <br />
    /// an example with 191 bit binary field
    /// </summary>
    procedure TestECDsa239bitBinary();

    /// <summary>
    /// General test for long digest.
    /// </summary>
    procedure TestECDsa239bitBinaryAndLargeDigest();

    /// <summary>
    /// key generation test
    /// </summary>
    procedure TestECDsaKeyGen();

    /// <summary>
    /// Basic Key Agreement Test
    /// </summary>
    procedure TestECBasicAgreement();

    procedure TestECDHBasicAgreementCofactor();

  end;

implementation

{ TTestEC }

procedure TTestEC.SetUp;
begin
  inherited;

end;

procedure TTestEC.TearDown;
begin
  inherited;

end;

procedure TTestEC.TestDecode;
var
  curve: IFpCurve;
  p: IECPoint;
  encoding: TBytes;
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
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'))
    .Normalize();

  if (not p.AffineXCoord.ToBigInteger()
    .Equals(TBigInteger.Create
    ('188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012', 16))) then
  begin
    Fail('x uncompressed incorrectly');
  end;

  if (not p.AffineYCoord.ToBigInteger()
    .Equals(TBigInteger.Create
    ('7192b95ffc8da78631011ed6b24cdd573f977a11e794811', 16))) then
  begin
    Fail('y uncompressed incorrectly');
  end;

  encoding := p.GetEncoded(true);

  if (not AreEqual(encoding,
    DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'))) then
  begin
    Fail('point compressed incorrectly');
  end;
end;

procedure TTestEC.TestECDsa191bitBinary;
var
  r, s: TBigInteger;
  kData, &message: TBytes;
  k: ISecureRandom;
  curve: IF2mCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  ecdsa: IECDsaSigner;
  param: IParametersWithRandom;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  r := TBigInteger.Create
    ('87194383164871543355722284926904419997237591535066528048');
  s := TBigInteger.Create
    ('308992691965804947361541664549085895292153777025772063598');

  kData := TBigIntegers.AsUnsignedByteArray
    (TBigInteger.Create
    ('1542725565216523985789236956265265265235675811949404040041'));

  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  curve := TF2mCurve.Create(191, // m
    9, // k
    TBigInteger.Create('2866537B676752636A68F56554E12640276B649EF7526267', 16),
    // a
    TBigInteger.Create('2E45EF571F00786F67B0081B9495A3D95462F5DE0AA185EC', 16),
    // b
    TBigInteger.Create('40000000000000000000000004A20E90C39067C893BBB9A5', 16),
    TBigInteger.Two);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('0436B3DAF8A23206F9C4F299D7B21A9C369137F2C84AE1AA0D765BE73433B3F95E332932E70EA245CA2418EA0EF98018FB')
    ) as IECPoint, // G
    TBigInteger.Create
    ('1569275433846670190958947355803350458831205595451630533029'), // n
    TBigInteger.Two); // h

  priKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('1275552191113212300012030439187146164646146646466749494799'), // d
    parameters);

  ecdsa := TECDsaSigner.Create();
  param := TParametersWithRandom.Create(priKey, k);

  ecdsa.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517').ToByteArray();
  sig := ecdsa.GenerateSignature(&message);

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

  // Verify the signature
  pubKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex
    ('045DE37E756BD55D72E3768CB396FFEB962614DEA4CE28A2E755C0E0E02F5FB132CAF416EF85B229BBB8E1352003125BA1')
    ) as IECPoint, // Q
    parameters);

  ecdsa.Init(false, pubKey);
  if (not ecdsa.VerifySignature(&message, sig[0], sig[1])) then
  begin
    Fail('signature fails');
  end;
end;

procedure TTestEC.TestECDsa192bitPrime;
var
  r, s, n: TBigInteger;
  kData, &message: TBytes;
  k: ISecureRandom;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  param: IParametersWithRandom;
  ecdsa: IECDsaSigner;
  sig: TCryptoLibGenericArray<TBigInteger>;

begin
  r := TBigInteger.Create
    ('3342403536405981729393488334694600415596881826869351677613');
  s := TBigInteger.Create
    ('5735822328888155254683894997897571951568553642892029982342');

  kData := TBigIntegers.AsUnsignedByteArray
    (TBigInteger.Create
    ('6140507067065001063065065565667405560006161556565665656654'));

  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

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

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('03188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'))
    as IECPoint, // G
    n);

  priKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('651056770906015076056810763456358567190100156695615665659'), // d
    parameters);

  param := TParametersWithRandom.Create(priKey, k);

  ecdsa := TECDsaSigner.Create();

  ecdsa.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517').ToByteArray();
  sig := ecdsa.GenerateSignature(&message);

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

  // Verify the signature
  pubKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex('0262b12d60690cdcf330babab6e69763b471f994dd702d16a5'))
    as IECPoint, // Q
    parameters);

  ecdsa.Init(false, pubKey);
  if (not ecdsa.VerifySignature(&message, sig[0], sig[1])) then
  begin
    Fail('verification fails');
  end;
end;

procedure TTestEC.TestECDsa239bitBinary;
var
  sig: TCryptoLibGenericArray<TBigInteger>;
  k: ISecureRandom;
  r, s: TBigInteger;
  kData: TBytes;
  curve: IF2mCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  ecdsa: IECDsaSigner;
  param: IParametersWithRandom;
  &message: TBytes;
begin
  r := TBigInteger.Create
    ('21596333210419611985018340039034612628818151486841789642455876922391552');
  s := TBigInteger.Create
    ('197030374000731686738334997654997227052849804072198819102649413465737174');

  kData := TBigIntegers.AsUnsignedByteArray
    (TBigInteger.Create
    ('171278725565216523967285789236956265265265235675811949404040041670216363')
    );

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
    ('0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305')
    ) as IECPoint, // G
    TBigInteger.Create
    ('220855883097298041197912187592864814557886993776713230936715041207411783'),
    // n
    TBigInteger.ValueOf(4)); // h

  priKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('145642755521911534651321230007534120304391871461646461466464667494947990'),
    // d
    parameters);

  ecdsa := TECDsaSigner.Create();
  param := TParametersWithRandom.Create(priKey, k);

  ecdsa.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517').ToByteArray();
  sig := ecdsa.GenerateSignature(&message);

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

  // Verify the signature
  pubKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex
    ('045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5')
    ) as IECPoint, // Q
    parameters);

  ecdsa.Init(false, pubKey);
  if (not ecdsa.VerifySignature(&message, sig[0], sig[1])) then
  begin
    Fail('signature fails');
  end;
end;

procedure TTestEC.TestECDsa239bitBinaryAndLargeDigest;
var
  r, s: TBigInteger;
  kData, &message: TBytes;
  k: ISecureRandom;
  curve: IF2mCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  ecdsa: IECDsaSigner;
  param: IParametersWithRandom;
  sig: TCryptoLibGenericArray<TBigInteger>;
  pubKey: IECPublicKeyParameters;
begin
  r := TBigInteger.Create
    ('21596333210419611985018340039034612628818151486841789642455876922391552');
  s := TBigInteger.Create
    ('144940322424411242416373536877786566515839911620497068645600824084578597');

  kData := TBigIntegers.AsUnsignedByteArray
    (TBigInteger.Create
    ('171278725565216523967285789236956265265265235675811949404040041670216363')
    );

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
    ('0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305')
    ) as IECPoint, // G
    TBigInteger.Create
    ('220855883097298041197912187592864814557886993776713230936715041207411783'),
    // n
    TBigInteger.ValueOf(4)); // h

  priKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('145642755521911534651321230007534120304391871461646461466464667494947990'),
    // d
    parameters);

  ecdsa := TECDsaSigner.Create();
  param := TParametersWithRandom.Create(priKey, k);

  ecdsa.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517968236873715988614170569073515315707566766479517968236873715988614170569073515315707566766479517')
    .ToByteArray();
  sig := ecdsa.GenerateSignature(&message);

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

  // Verify the signature
  pubKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex
    ('045894609CCECF9A92533F630DE713A958E96C97CCB8F5ABB5A688A238DEED6DC2D9D0C94EBFB7D526BA6A61764175B99CB6011E2047F9F067293F57F5')
    ) as IECPoint, // Q
    parameters);

  ecdsa.Init(false, pubKey);
  if (not ecdsa.VerifySignature(&message, sig[0], sig[1])) then
  begin
    Fail('signature fails');
  end;
end;

procedure TTestEC.TestECDsa239bitPrime;
var
  &message, kData: TBytes;
  r, s, n: TBigInteger;
  k: ISecureRandom;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  ecdsa: IECDsaSigner;
  param: IParametersWithRandom;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  r := TBigInteger.Create
    ('308636143175167811492622547300668018854959378758531778147462058306432176');
  s := TBigInteger.Create
    ('323813553209797357708078776831250505931891051755007842781978505179448783');

  kData := TBigIntegers.AsUnsignedByteArray
    (TBigInteger.Create
    ('700000017569056646655505781757157107570501575775705779575555657156756655')
    );

  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  n := TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    n, TBigInteger.One);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')
    ) as IECPoint, // G
    n);

  priKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('876300101507107567501066130761671078357010671067781776716671676178726717'),
    // d
    parameters);

  ecdsa := TECDsaSigner.Create();
  param := TParametersWithRandom.Create(priKey, k);

  ecdsa.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517').ToByteArray();
  sig := ecdsa.GenerateSignature(&message);

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

  // Verify the signature
  pubKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')
    ) as IECPoint, // Q
    parameters);

  ecdsa.Init(false, pubKey);
  if (not ecdsa.VerifySignature(&message, sig[0], sig[1])) then
  begin
    Fail('signature fails');
  end;
end;

procedure TTestEC.TestECDsaKeyGen;
var
  random: ISecureRandom;
  n: TBigInteger;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  pGen: IECKeyPairGenerator;
  genParam: IECKeyGenerationParameters;
  pair: IAsymmetricCipherKeyPair;
  param: IParametersWithRandom;
  ecdsa: IECDsaSigner;
  &message: TBytes;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  random := TSecureRandom.Create();

  n := TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    n, TBigInteger.One);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')), // G
    n);

  pGen := TECKeyPairGenerator.Create();
  genParam := TECKeyGenerationParameters.Create(parameters, random);

  pGen.Init(genParam);

  pair := pGen.GenerateKeyPair();

  param := TParametersWithRandom.Create(pair.Private, random);

  ecdsa := TECDsaSigner.Create();

  ecdsa.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517').ToByteArray();
  sig := ecdsa.GenerateSignature(&message);

  ecdsa.Init(false, pair.Public);

  if (not ecdsa.VerifySignature(&message, sig[0], sig[1])) then
  begin
    Fail('signature fails');
  end;
end;

procedure TTestEC.TestECBasicAgreement;
var
  random: ISecureRandom;
  n, k1, k2: TBigInteger;
  curve: IFpCurve;
  parameters: IECDomainParameters;
  pGen: IECKeyPairGenerator;
  genParam: IECKeyGenerationParameters;
  p1, p2: IAsymmetricCipherKeyPair;
  e1, e2: IBasicAgreement;
begin
  random := TSecureRandom.Create();

  n := TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307');

  curve := TFpCurve.Create
    (TBigInteger.Create
    ('883423532389192164791648750360308885314476597252960362792450860609699839'),
    // q
    TBigInteger.Create
    ('7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc', 16), // a
    TBigInteger.Create
    ('6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a', 16), // b
    n, TBigInteger.One);

  parameters := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')), // G
    n);

  pGen := TECKeyPairGenerator.Create();
  genParam := TECKeyGenerationParameters.Create(parameters, random);

  pGen.Init(genParam);

  p1 := pGen.GenerateKeyPair();
  p2 := pGen.GenerateKeyPair();

  //
  // two way
  //
  e1 := TECDHBasicAgreement.Create();
  e2 := TECDHBasicAgreement.Create();

  e1.Init(p1.Private);
  e2.Init(p2.Private);

  k1 := e1.CalculateAgreement(p2.Public);
  k2 := e2.CalculateAgreement(p1.Public);

  if (not(k1.Equals(k2))) then
  begin
    Fail('calculated agreement test failed');
  end;

  //
  // two way
  //
  e1 := TECDHCBasicAgreement.Create();
  e2 := TECDHCBasicAgreement.Create();

  e1.Init(p1.Private);
  e2.Init(p2.Private);

  k1 := e1.CalculateAgreement(p2.Public);
  k2 := e2.CalculateAgreement(p1.Public);

  if (not(k1.Equals(k2))) then
  begin
    Fail('calculated agreement test failed');
  end;

end;

procedure TTestEC.TestECDHBasicAgreementCofactor;
var
  random: ISecureRandom;
  x9: IX9ECParameters;
  ec: IECDomainParameters;
  kpg: IECKeyPairGenerator;
  p1, p2: IAsymmetricCipherKeyPair;
  e1, e2: IBasicAgreement;
  k1, k2: TBigInteger;
begin
  random := TSecureRandom.Create();

  x9 := TCustomNamedCurves.GetByName('curve25519');
  ec := TECDomainParameters.Create(x9.curve, x9.G, x9.n, x9.H, x9.GetSeed());

  kpg := TECKeyPairGenerator.Create();
  kpg.Init(TECKeyGenerationParameters.Create(ec, random)
    as IECKeyGenerationParameters);

  p1 := kpg.GenerateKeyPair();
  p2 := kpg.GenerateKeyPair();

  e1 := TECDHBasicAgreement.Create();
  e2 := TECDHBasicAgreement.Create();

  e1.Init(p1.Private);
  e2.Init(p2.Private);

  k1 := e1.CalculateAgreement(p2.Public);
  k2 := e2.CalculateAgreement(p1.Public);

  if (not(k1.Equals(k2))) then
  begin
    Fail('calculated agreement test failed');
  end;
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestEC);
{$ELSE}
  RegisterTest(TTestEC.Suite);
{$ENDIF FPC}

end.
