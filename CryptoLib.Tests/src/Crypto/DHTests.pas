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
  ClpIDHAgreement,
  ClpDHAgreement,
  ClpIDHBasicAgreement,
  ClpDHBasicAgreement,
  ClpIDHParameters,
  ClpDHParameters,
  ClpIDHParametersGenerator,
  ClpDHParametersGenerator,
  ClpIDHKeyPairGenerator,
  ClpDHKeyPairGenerator,
  ClpIDHBasicKeyPairGenerator,
  ClpDHBasicKeyPairGenerator,
  ClpIDHPrivateKeyParameters,
  ClpIDHPublicKeyParameters,
  ClpIDHKeyGenerationParameters,
  ClpDHKeyGenerationParameters,
  ClpIAsymmetricCipherKeyPair,
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
  end;

implementation

{ TTestDH }

function TTestDH.GetDHBasicKeyPairGenerator(const g, p: TBigInteger;
  privateValueSize: Int32): IDHBasicKeyPairGenerator;
var
  dhParams: IDHParameters;
  dhkgParams: IDHKeyGenerationParameters;
  kpGen: IDHBasicKeyPairGenerator;
begin
  dhParams := TDHParameters.Create(p, g, Default (TBigInteger),
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
