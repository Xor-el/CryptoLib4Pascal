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

unit DeterministicDsaTests;

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
  ClpIDsa,
  ClpIDigest,
  ClpDsaSigner,
  ClpIDsaSigner,
  ClpECDsaSigner,
  ClpIECDsaSigner,
  ClpIDsaParameters,
  ClpDsaParameters,
  ClpHMacDsaKCalculator,
  ClpIHMacDsaKCalculator,
  ClpICipherParameters,
  ClpIX9ECParameters,
  ClpIECPrivateKeyParameters,
  ClpECPrivateKeyParameters,
  ClpIDsaPrivateKeyParameters,
  ClpDsaPrivateKeyParameters,
  ClpIECDomainParameters,
  ClpECDomainParameters,
  ClpBigInteger,
  ClpDigestUtilities,
  ClpSecNamedCurves,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type

  /// <summary>
  /// Tests are taken from RFC 6979 - "Deterministic Usage of the Digital
  /// Signature Algorithm (DSA) and Elliptic Curve Digital Signature
  /// Algorithm (ECDSA)".
  /// </summary>
  TTestDeterministicDsa = class(TCryptoLibAlgorithmTestCase)

  private
  var
    FSAMPLE, FTEST: TBytes;

    // test vectors from appendix in RFC 6979
    procedure DoTestHMacDeterministic;
    procedure DoTestECHMacDeterministic;

    procedure DoTestHMacDetDsaSample(const digest: IDigest;
      const privKey: IDsaPrivateKeyParameters; const r, s: TBigInteger);

    procedure DoTestHMacDetDsaTest(const digest: IDigest;
      const privKey: IDsaPrivateKeyParameters; const r, s: TBigInteger);

    procedure DoTestHMacDetECDsaSample(const digest: IDigest;
      const privKey: IECPrivateKeyParameters; const r, s: TBigInteger);

    procedure DoTestHMacDetECDsaTest(const digest: IDigest;
      const privKey: IECPrivateKeyParameters; const r, s: TBigInteger);

    procedure DoTestHMacDetECDsa(const detSigner: IDsa; const digest: IDigest;
      const data: TBytes; const privKey: ICipherParameters;
      const r, s: TBigInteger);

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestDsaDeterministic;

  end;

implementation

{ TTestDeterministicDsa }

procedure TTestDeterministicDsa.DoTestECHMacDeterministic;
var
  x9ECParameters: IX9ECParameters;
  ecDomainParameters: IECDomainParameters;
  privKey: IECPrivateKeyParameters;
begin
  x9ECParameters := TSecNamedCurves.GetByName('secp521r1');
  ecDomainParameters := TECDomainParameters.Create(x9ECParameters.Curve,
    x9ECParameters.G, x9ECParameters.N);

  privKey := TECPrivateKeyParameters.Create
    (TBigInteger.Create
    ('0FAD06DAA62BA3B25D2FB40133DA757205DE67F5BB0018FEE8C86E1B68C7E75C' +
    'AA896EB32F1F47C70855836A6D16FCC1466F6D8FBEC67DB89EC0C08B0E996B83' + '538',
    16), ecDomainParameters);

  DoTestHMacDetECDsaSample(TDigestUtilities.GetDigest('SHA-1'), privKey,
    TBigInteger.Create
    ('0343B6EC45728975EA5CBA6659BBB6062A5FF89EEA58BE3C80B619F322C87910' +
    'FE092F7D45BB0F8EEE01ED3F20BABEC079D202AE677B243AB40B5431D497C55D' + '75D',
    16), TBigInteger.Create
    ('0E7B0E675A9B24413D448B8CC119D2BF7B2D2DF032741C096634D6D65D0DBE3D' +
    '5694625FB9E8104D3B842C1B0E2D0B98BEA19341E8676AEF66AE4EBA3D5475D5' +
    'D16', 16));
  DoTestHMacDetECDsaSample(TDigestUtilities.GetDigest('SHA-224'), privKey,
    TBigInteger.Create
    ('1776331CFCDF927D666E032E00CF776187BC9FDD8E69D0DABB4109FFE1B5E2A3' +
    '0715F4CC923A4A5E94D2503E9ACFED92857B7F31D7152E0F8C00C15FF3D87E2E' + 'D2E',
    16), TBigInteger.Create
    ('050CB5265417FE2320BBB5A122B8E1A32BD699089851128E360E620A30C7E17B' +
    'A41A666AF126CE100E5799B153B60528D5300D08489CA9178FB610A2006C254B' +
    '41F', 16));
  DoTestHMacDetECDsaSample(TDigestUtilities.GetDigest('SHA-256'), privKey,
    TBigInteger.Create
    ('1511BB4D675114FE266FC4372B87682BAECC01D3CC62CF2303C92B3526012659' +
    'D16876E25C7C1E57648F23B73564D67F61C6F14D527D54972810421E7D87589E' + '1A7',
    16), TBigInteger.Create
    ('04A171143A83163D6DF460AAF61522695F207A58B95C0644D87E52AA1A347916' +
    'E4F7A72930B1BC06DBE22CE3F58264AFD23704CBB63B29B931F7DE6C9D949A7E' +
    'CFC', 16));
  DoTestHMacDetECDsaSample(TDigestUtilities.GetDigest('SHA-384'), privKey,
    TBigInteger.Create
    ('1EA842A0E17D2DE4F92C15315C63DDF72685C18195C2BB95E572B9C5136CA4B4' +
    'B576AD712A52BE9730627D16054BA40CC0B8D3FF035B12AE75168397F5D50C67' + '451',
    16), TBigInteger.Create
    ('1F21A3CEE066E1961025FB048BD5FE2B7924D0CD797BABE0A83B66F1E35EEAF5' +
    'FDE143FA85DC394A7DEE766523393784484BDF3E00114A1C857CDE1AA203DB65' +
    'D61', 16));
  DoTestHMacDetECDsaSample(TDigestUtilities.GetDigest('SHA-512'), privKey,
    TBigInteger.Create
    ('0C328FAFCBD79DD77850370C46325D987CB525569FB63C5D3BC53950E6D4C5F1' +
    '74E25A1EE9017B5D450606ADD152B534931D7D4E8455CC91F9B15BF05EC36E37' + '7FA',
    16), TBigInteger.Create
    ('0617CCE7CF5064806C467F678D3B4080D6F1CC50AF26CA209417308281B68AF2' +
    '82623EAA63E5B5C0723D8B8C37FF0777B1A20F8CCB1DCCC43997F1EE0E44DA4A' +
    '67A', 16));

  DoTestHMacDetECDsaTest(TDigestUtilities.GetDigest('SHA-1'), privKey,
    TBigInteger.Create
    ('13BAD9F29ABE20DE37EBEB823C252CA0F63361284015A3BF430A46AAA80B87B0' +
    '693F0694BD88AFE4E661FC33B094CD3B7963BED5A727ED8BD6A3A202ABE009D0' + '367',
    16), TBigInteger.Create
    ('1E9BB81FF7944CA409AD138DBBEE228E1AFCC0C890FC78EC8604639CB0DBDC90' +
    'F717A99EAD9D272855D00162EE9527567DD6A92CBD629805C0445282BBC91679' +
    '7FF', 16));
  DoTestHMacDetECDsaTest(TDigestUtilities.GetDigest('SHA-224'), privKey,
    TBigInteger.Create
    ('1C7ED902E123E6815546065A2C4AF977B22AA8EADDB68B2C1110E7EA44D42086' +
    'BFE4A34B67DDC0E17E96536E358219B23A706C6A6E16BA77B65E1C595D43CAE1' + '7FB',
    16), TBigInteger.Create
    ('177336676304FCB343CE028B38E7B4FBA76C1C1B277DA18CAD2A8478B2A9A9F5' +
    'BEC0F3BA04F35DB3E4263569EC6AADE8C92746E4C82F8299AE1B8F1739F8FD51' +
    '9A4', 16));
  DoTestHMacDetECDsaTest(TDigestUtilities.GetDigest('SHA-256'), privKey,
    TBigInteger.Create
    ('00E871C4A14F993C6C7369501900C4BC1E9C7B0B4BA44E04868B30B41D807104' +
    '2EB28C4C250411D0CE08CD197E4188EA4876F279F90B3D8D74A3C76E6F1E4656' + 'AA8',
    16), TBigInteger.Create
    ('0CD52DBAA33B063C3A6CD8058A1FB0A46A4754B034FCC644766CA14DA8CA5CA9' +
    'FDE00E88C1AD60CCBA759025299079D7A427EC3CC5B619BFBC828E7769BCD694' +
    'E86', 16));
  DoTestHMacDetECDsaTest(TDigestUtilities.GetDigest('SHA-384'), privKey,
    TBigInteger.Create
    ('14BEE21A18B6D8B3C93FAB08D43E739707953244FDBE924FA926D76669E7AC8C' +
    '89DF62ED8975C2D8397A65A49DCC09F6B0AC62272741924D479354D74FF60755' + '78C',
    16), TBigInteger.Create
    ('133330865C067A0EAF72362A65E2D7BC4E461E8C8995C3B6226A21BD1AA78F0E' +
    'D94FE536A0DCA35534F0CD1510C41525D163FE9D74D134881E35141ED5E8E95B' +
    '979', 16));
  DoTestHMacDetECDsaTest(TDigestUtilities.GetDigest('SHA-512'), privKey,
    TBigInteger.Create
    ('13E99020ABF5CEE7525D16B69B229652AB6BDF2AFFCAEF38773B4B7D08725F10' +
    'CDB93482FDCC54EDCEE91ECA4166B2A7C6265EF0CE2BD7051B7CEF945BABD47E' + 'E6D',
    16), TBigInteger.Create
    ('1FBD0013C674AA79CB39849527916CE301C66EA7CE8B80682786AD60F98F7E78' +
    'A19CA69EFF5C57400E3B3A0AD66CE0978214D13BAF4E9AC60752F7B155E2DE4D' +
    'CE3', 16));
end;

procedure TTestDeterministicDsa.DoTestHMacDetDsaSample(const digest: IDigest;
  const privKey: IDsaPrivateKeyParameters; const r, s: TBigInteger);
begin
  DoTestHMacDetECDsa(TDsaSigner.Create(THMacDsaKCalculator.Create(digest)
    as IHMacDsaKCalculator) as IDsaSigner, digest, FSAMPLE, privKey, r, s);
end;

procedure TTestDeterministicDsa.DoTestHMacDetDsaTest(const digest: IDigest;
  const privKey: IDsaPrivateKeyParameters; const r, s: TBigInteger);
begin
  DoTestHMacDetECDsa(TDsaSigner.Create(THMacDsaKCalculator.Create(digest)
    as IHMacDsaKCalculator) as IDsaSigner, digest, FTEST, privKey, r, s);
end;

procedure TTestDeterministicDsa.DoTestHMacDetECDsa(const detSigner: IDsa;
  const digest: IDigest; const data: TBytes; const privKey: ICipherParameters;
  const r, s: TBigInteger);
var
  m: TBytes;
  rs: TCryptoLibGenericArray<TBigInteger>;
begin
  System.SetLength(m, digest.GetDigestSize());

  digest.BlockUpdate(data, 0, System.Length(data));

  digest.DoFinal(m, 0);

  detSigner.Init(true, privKey);

  rs := detSigner.GenerateSignature(m);

  if (not r.Equals(rs[0])) then
  begin
    Fail('r value wrong');
  end;
  if (not s.Equals(rs[1])) then
  begin
    Fail('s value wrong');
  end;
end;

procedure TTestDeterministicDsa.DoTestHMacDetECDsaSample(const digest: IDigest;
  const privKey: IECPrivateKeyParameters; const r, s: TBigInteger);
begin
  DoTestHMacDetECDsa(TECDsaSigner.Create(THMacDsaKCalculator.Create(digest)
    as IHMacDsaKCalculator) as IECDsaSigner, digest, FSAMPLE, privKey, r, s);
end;

procedure TTestDeterministicDsa.DoTestHMacDetECDsaTest(const digest: IDigest;
  const privKey: IECPrivateKeyParameters; const r, s: TBigInteger);
begin
  DoTestHMacDetECDsa(TECDsaSigner.Create(THMacDsaKCalculator.Create(digest)
    as IHMacDsaKCalculator) as IECDsaSigner, digest, FTEST, privKey, r, s);
end;

procedure TTestDeterministicDsa.DoTestHMacDeterministic;
var
  dsaParameters: IDsaParameters;
  privKey: IDsaPrivateKeyParameters;
begin
  dsaParameters := TDsaParameters.Create
    (TBigInteger.Create
    ('86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447' +
    'E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88' +
    '73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C' +
    '881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779', 16),
    TBigInteger.Create('996F967F6C8E388D9E28D01E205FBA957A5698B1', 16),
    TBigInteger.Create
    ('07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D' +
    '89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD' +
    '87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4' +
    '17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD', 16));

  privKey := TDsaPrivateKeyParameters.Create
    (TBigInteger.Create('411602CB19A6CCC34494D79D98EF1E7ED5AF25F7', 16),
    dsaParameters);

  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-1'), privKey,
    TBigInteger.Create('2E1A0C2562B2912CAAF89186FB0F42001585DA55', 16),
    TBigInteger.Create('29EFB6B0AFF2D7A68EB70CA313022253B9A88DF5', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-224'), privKey,
    TBigInteger.Create('4BC3B686AEA70145856814A6F1BB53346F02101E', 16),
    TBigInteger.Create('410697B92295D994D21EDD2F4ADA85566F6F94C1', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-256'), privKey,
    TBigInteger.Create('81F2F5850BE5BC123C43F71A3033E9384611C545', 16),
    TBigInteger.Create('4CDD914B65EB6C66A8AAAD27299BEE6B035F5E89', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-384'), privKey,
    TBigInteger.Create('07F2108557EE0E3921BC1774F1CA9B410B4CE65A', 16),
    TBigInteger.Create('54DF70456C86FAC10FAB47C1949AB83F2C6F7595', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-512'), privKey,
    TBigInteger.Create('16C3491F9B8C3FBBDD5E7A7B667057F0D8EE8E1B', 16),
    TBigInteger.Create('02C36A127A7B89EDBB72E4FFBC71DABC7D4FC69C', 16));

  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-1'), privKey,
    TBigInteger.Create('42AB2052FD43E123F0607F115052A67DCD9C5C77', 16),
    TBigInteger.Create('183916B0230D45B9931491D4C6B0BD2FB4AAF088', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-224'), privKey,
    TBigInteger.Create('6868E9964E36C1689F6037F91F28D5F2C30610F2', 16),
    TBigInteger.Create('49CEC3ACDC83018C5BD2674ECAAD35B8CD22940F', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-256'), privKey,
    TBigInteger.Create('22518C127299B0F6FDC9872B282B9E70D0790812', 16),
    TBigInteger.Create('6837EC18F150D55DE95B5E29BE7AF5D01E4FE160', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-384'), privKey,
    TBigInteger.Create('854CF929B58D73C3CBFDC421E8D5430CD6DB5E66', 16),
    TBigInteger.Create('91D0E0F53E22F898D158380676A871A157CDA622', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-512'), privKey,
    TBigInteger.Create('8EA47E475BA8AC6F2D821DA3BD212D11A3DEB9A0', 16),
    TBigInteger.Create('7C670C7AD72B6C050C109E1790008097125433E8', 16));

  dsaParameters := TDsaParameters.Create
    (TBigInteger.Create
    ('9DB6FB5951B66BB6FE1E140F1D2CE5502374161FD6538DF1648218642F0B5C48' +
    'C8F7A41AADFA187324B87674FA1822B00F1ECF8136943D7C55757264E5A1A44F' +
    'FE012E9936E00C1D3E9310B01C7D179805D3058B2A9F4BB6F9716BFE6117C6B5' +
    'B3CC4D9BE341104AD4A80AD6C94E005F4B993E14F091EB51743BF33050C38DE2' +
    '35567E1B34C3D6A5C0CEAA1A0F368213C3D19843D0B4B09DCB9FC72D39C8DE41' +
    'F1BF14D4BB4563CA28371621CAD3324B6A2D392145BEBFAC748805236F5CA2FE' +
    '92B871CD8F9C36D3292B5509CA8CAA77A2ADFC7BFD77DDA6F71125A7456FEA15' +
    '3E433256A2261C6A06ED3693797E7995FAD5AABBCFBE3EDA2741E375404AE25B', 16),
    TBigInteger.Create
    ('F2C3119374CE76C9356990B465374A17F23F9ED35089BD969F61C6DDE9998C1F', 16),
    TBigInteger.Create
    ('5C7FF6B06F8F143FE8288433493E4769C4D988ACE5BE25A0E24809670716C613' +
    'D7B0CEE6932F8FAA7C44D2CB24523DA53FBE4F6EC3595892D1AA58C4328A06C4' +
    '6A15662E7EAA703A1DECF8BBB2D05DBE2EB956C142A338661D10461C0D135472' +
    '085057F3494309FFA73C611F78B32ADBB5740C361C9F35BE90997DB2014E2EF5' +
    'AA61782F52ABEB8BD6432C4DD097BC5423B285DAFB60DC364E8161F4A2A35ACA' +
    '3A10B1C4D203CC76A470A33AFDCBDD92959859ABD8B56E1725252D78EAC66E71' +
    'BA9AE3F1DD2487199874393CD4D832186800654760E1E34C09E4D155179F9EC0' +
    'DC4473F996BDCE6EED1CABED8B6F116F7AD9CF505DF0F998E34AB27514B0FFE7', 16));

  privKey := TDsaPrivateKeyParameters.Create
    (TBigInteger.Create
    ('69C7548C21D0DFEA6B9A51C9EAD4E27C33D3B3F180316E5BCAB92C933F0E4DBC', 16),
    dsaParameters);

  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-1'), privKey,
    TBigInteger.Create
    ('3A1B2DBD7489D6ED7E608FD036C83AF396E290DBD602408E8677DAABD6E7445A', 16),
    TBigInteger.Create
    ('D26FCBA19FA3E3058FFC02CA1596CDBB6E0D20CB37B06054F7E36DED0CDBBCCF', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-224'), privKey,
    TBigInteger.Create
    ('DC9F4DEADA8D8FF588E98FED0AB690FFCE858DC8C79376450EB6B76C24537E2C', 16),
    TBigInteger.Create
    ('A65A9C3BC7BABE286B195D5DA68616DA8D47FA0097F36DD19F517327DC848CEC', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-256'), privKey,
    TBigInteger.Create
    ('EACE8BDBBE353C432A795D9EC556C6D021F7A03F42C36E9BC87E4AC7932CC809', 16),
    TBigInteger.Create
    ('7081E175455F9247B812B74583E9E94F9EA79BD640DC962533B0680793A38D53', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-384'), privKey,
    TBigInteger.Create
    ('B2DA945E91858834FD9BF616EBAC151EDBC4B45D27D0DD4A7F6A22739F45C00B', 16),
    TBigInteger.Create
    ('19048B63D9FD6BCA1D9BAE3664E1BCB97F7276C306130969F63F38FA8319021B', 16));
  DoTestHMacDetDsaSample(TDigestUtilities.GetDigest('SHA-512'), privKey,
    TBigInteger.Create
    ('2016ED092DC5FB669B8EFB3D1F31A91EECB199879BE0CF78F02BA062CB4C942E', 16),
    TBigInteger.Create
    ('D0C76F84B5F091E141572A639A4FB8C230807EEA7D55C8A154A224400AFF2351', 16));

  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-1'), privKey,
    TBigInteger.Create
    ('C18270A93CFC6063F57A4DFA86024F700D980E4CF4E2CB65A504397273D98EA0', 16),
    TBigInteger.Create
    ('414F22E5F31A8B6D33295C7539C1C1BA3A6160D7D68D50AC0D3A5BEAC2884FAA', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-224'), privKey,
    TBigInteger.Create
    ('272ABA31572F6CC55E30BF616B7A265312018DD325BE031BE0CC82AA17870EA3', 16),
    TBigInteger.Create
    ('E9CC286A52CCE201586722D36D1E917EB96A4EBDB47932F9576AC645B3A60806', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-256'), privKey,
    TBigInteger.Create
    ('8190012A1969F9957D56FCCAAD223186F423398D58EF5B3CEFD5A4146A4476F0', 16),
    TBigInteger.Create
    ('7452A53F7075D417B4B013B278D1BB8BBD21863F5E7B1CEE679CF2188E1AB19E', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-384'), privKey,
    TBigInteger.Create
    ('239E66DDBE8F8C230A3D071D601B6FFBDFB5901F94D444C6AF56F732BEB954BE', 16),
    TBigInteger.Create
    ('6BD737513D5E72FE85D1C750E0F73921FE299B945AAD1C802F15C26A43D34961', 16));
  DoTestHMacDetDsaTest(TDigestUtilities.GetDigest('SHA-512'), privKey,
    TBigInteger.Create
    ('89EC4BB1400ECCFF8E7D9AA515CD1DE7803F2DAFF09693EE7FD1353E90A68307', 16),
    TBigInteger.Create
    ('C9F0BDABCC0D880BB137A994CC7F3980CE91CC10FAF529FC46565B15CEA854E1', 16));

end;

procedure TTestDeterministicDsa.SetUp;
begin
  inherited;
  FSAMPLE := DecodeHex('73616d706c65'); // "sample"
  FTEST := DecodeHex('74657374'); // "test"
end;

procedure TTestDeterministicDsa.TearDown;
begin
  inherited;

end;

procedure TTestDeterministicDsa.TestDsaDeterministic;
begin
  DoTestHMacDeterministic();
  DoTestECHMacDeterministic();
end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestDeterministicDsa);
{$ELSE}
  RegisterTest(TTestDeterministicDsa.Suite);
{$ENDIF FPC}

end.
