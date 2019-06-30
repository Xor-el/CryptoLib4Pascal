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

unit DSATests;

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
  ClpISigner,
  ClpIDsaSigner,
  ClpDsaSigner,
  ClpIDsaParameters,
  ClpDsaParameters,
  ClpIECC,
  ClpDsaParameter,
  ClpIDsaParameter,
  ClpECC,
  ClpECDomainParameters,
  ClpIECDomainParameters,
  ClpIAsn1Objects,
  ClpDsaParametersGenerator,
  ClpIDsaParametersGenerator,
  ClpIDsaValidationParameters,
  ClpIDsaKeyPairGenerator,
  ClpDsaKeyPairGenerator,
  ClpIDsaPublicKeyParameters,
  ClpDsaPublicKeyParameters,
  ClpDsaPrivateKeyParameters,
  ClpIDsaPrivateKeyParameters,
  ClpIDsaKeyGenerationParameters,
  ClpDsaKeyGenerationParameters,
  ClpDsaParameterGenerationParameters,
  ClpIDsaParameterGenerationParameters,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpECPrivateKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpECPublicKeyParameters,
  ClpIECPublicKeyParameters,
  ClpParametersWithRandom,
  ClpIParametersWithRandom,
  ClpSignerUtilities,
  ClpDigestUtilities,
  ClpGeneratorUtilities,
  ClpTeleTrusTObjectIdentifiers,
  ClpX9ObjectIdentifiers,
  ClpECKeyGenerationParameters,
  ClpIECKeyGenerationParameters,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpDSADigestSigner,
  ClpIDSADigestSigner,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpFixedSecureRandom,
  ClpIFixedSecureRandom,
  ClpConverters,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  IDSATestSecureRandom = interface(IFixedSecureRandom)
    ['{EE74B77E-4383-4C78-98FD-572482A5CAC3}']
  end;

type
  TDSATestSecureRandom = class(TFixedSecureRandom, IDSATestSecureRandom)

  strict private
    Ffirst: Boolean;

  public
    constructor Create(const value: TBytes);

    procedure NextBytes(const bytes: TBytes); override;

  end;

type

  /// <summary>
  /// Test based on FIPS 186-2, Appendix 5, an example of DSA, and FIPS 168-3 test vectors.
  /// </summary>
  TTestDSA = class(TCryptoLibAlgorithmTestCase)

  private

    procedure DoDSA2Test1();
    procedure DoDSA2Test2();
    procedure DoDSA2Test3();
    procedure DoDSA2Test4();
    procedure DoTestDSASHA3(size: Int32; const s: TBigInteger);
    procedure DoTestECDsa239BitBinary(const algorithm: String;
      const oid: IDerObjectIdentifier);

    procedure DoCheckMessage(const sgr: ISigner;
      const sKey: IECPrivateKeyParameters; const vKey: IECPublicKeyParameters;
      const &message, sig: TBytes);

    procedure DoTestKeyGeneration(keysize: Int32);
    procedure DoTestBadStrength(strength: Int32);

    function DoDerDecode(const encoding: TBytes)
      : TCryptoLibGenericArray<TBigInteger>;

  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published

    procedure TestDSA;
    procedure TestNONEwithDSA;
    procedure TestNONEwithECDSA239bitPrime;
    procedure TestECDsa239BitBinaryRipeMD160;
    procedure TestECDsa239BitBinarySha1;
    procedure TestECDsa239BitBinarySha224;
    procedure TestECDsa239BitBinarySha256;
    procedure TestECDsa239BitBinarySha384;
    procedure TestECDsa239BitBinarySha512;
    procedure TestGeneration;
    procedure TestDsa2Parameters;
    procedure TestKeyGenerationAll;
    procedure TestParameters;

    /// <summary>
    /// <para>
    /// X9.62 - 1998, J.3.2, Page 155, ECDSA over the field <c>Fp</c>
    /// </para>
    /// <para>
    /// <c>an example with 239 bit prime</c>
    /// </para>
    /// </summary>
    procedure TestECDsa239BitPrime;

    /// <summary>
    /// <para>
    /// X9.62 - 1998, J.2.1, Page 100, ECDSA over the field F2m
    /// </para>
    /// <para>
    /// an example with 191 bit binary field
    /// </para>
    /// </summary>
    procedure TestECDsa239BitBinary;

  end;

implementation

{ TTestDSA }

procedure TTestDSA.DoCheckMessage(const sgr: ISigner;
  const sKey: IECPrivateKeyParameters; const vKey: IECPublicKeyParameters;
  const &message, sig: TBytes);
var
  kData, sigBytes: TBytes;
  k: ISecureRandom;
begin

  kData := TBigInteger.Create
    ('700000017569056646655505781757157107570501575775705779575555657156756655')
    .ToByteArrayUnsigned;

  k := TFixedSecureRandom.From(TCryptoLibMatrixByteArray.Create(kData));

  sgr.Init(true, TParametersWithRandom.Create(sKey, k)
    as IParametersWithRandom);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  if (not AreEqual(sigBytes, sig)) then
  begin
    Fail(Format('%s %s', [TConverters.ConvertBytesToString(&message,
      TEncoding.UTF8), 'signature incorrect']));
  end;

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not(sgr.VerifySignature(sigBytes))) then
  begin
    Fail(Format('%s %s', [TConverters.ConvertBytesToString(&message,
      TEncoding.UTF8), 'verification failed']));
  end;
end;

function TTestDSA.DoDerDecode(const encoding: TBytes)
  : TCryptoLibGenericArray<TBigInteger>;
var
  s: IAsn1Sequence;
begin
  s := TAsn1Object.FromByteArray(encoding) as IAsn1Sequence;

  result := TCryptoLibGenericArray<TBigInteger>.Create
    ((s[0] as IDerInteger).value, (s[1] as IDerInteger).value);
end;

procedure TTestDSA.DoTestBadStrength(strength: Int32);
var
  rand: ISecureRandom;
  pGen: IDsaParametersGenerator;
begin
  try

    rand := TSecureRandom.Create();
    pGen := TDsaParametersGenerator.Create();
    pGen.Init(strength, 80, rand);
    Fail('illegal parameter ' + IntToStr(strength) + ' check failed.');

  except
    on e: EArgumentCryptoLibException do
    begin
      // expected
    end;

  end;
end;

procedure TTestDSA.DoDSA2Test1;
var
  seed, msg: TBytes;
  pGen: IDsaParametersGenerator;
  params: IDSAParameters;
  pv: IDSAValidationParameters;
  kpGen: IDSAKeyPairGenerator;
  kp: IAsymmetricCipherKeyPair;
  pub: IDSAPublicKeyParameters;
  priv: IDSAPrivateKeyParameters;
  signer: IDSASigner;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  seed := DecodeHex('ED8BEE8D1CB89229D2903CBF0E51EE7377F48698');

  pGen := TDsaParametersGenerator.Create();

  pGen.Init(TDSAParameterGenerationParameters.Create(1024, 160, 80,
    TDSATestSecureRandom.Create(seed)) as IDSAParameterGenerationParameters);

  params := pGen.GenerateParameters();

  pv := params.getValidationParameters();

  if (pv.GetCounter() <> 5) then
  begin
    Fail('counter incorrect');
  end;

  if (not AreEqual(seed, pv.seed)) then
  begin
    Fail('seed incorrect');
  end;

  if (not(params.Q.Equals(TBigInteger.Create
    ('E950511EAB424B9A19A2AEB4E159B7844C589C4F', 16)))) then
  begin
    Fail('Q incorrect');
  end;

  if (not(params.p.Equals(TBigInteger.Create('E0A67598CD1B763B' +
    'C98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338' +
    'FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3' +
    '307DED2299A0EE606DF035177A239C34A912C202AA5F83B9' +
    'C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440' +
    'F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B', 16)))) then
  begin
    Fail('P incorrect');
  end;

  if (not(params.G.Equals(TBigInteger.Create('D29D5121B0423C27' +
    '69AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15' +
    'C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A' +
    '9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B' +
    '76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA' +
    '3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75', 16)))) then
  begin
    Fail('G incorrect');
  end;

  kpGen := TDSAKeyPairGenerator.Create();

  kpGen.Init(TDSAKeyGenerationParameters.Create(TFixedSecureRandom.Create
    (TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create(TBigInteger.Create
    ('D0EC4E50BB290A42E9E355C73D8809345DE2E139', 16).ToByteArrayUnsigned))),
    params) as IDSAKeyGenerationParameters);

  kp := kpGen.GenerateKeyPair();

  pub := kp.Public as IDSAPublicKeyParameters;
  priv := kp.Private as IDSAPrivateKeyParameters;

  if (not(pub.Y.Equals(TBigInteger.Create('25282217F5730501' +
    'DD8DBA3EDFCF349AAFFEC20921128D70FAC44110332201BB' +
    'A3F10986140CBB97C726938060473C8EC97B4731DB004293' +
    'B5E730363609DF9780F8D883D8C4D41DED6A2F1E1BBBDC97' +
    '9E1B9D6D3C940301F4E978D65B19041FCF1E8B518F5C0576' +
    'C770FE5A7A485D8329EE2914A2DE1B5DA4A6128CEAB70F79', 16)))) then
  begin
    Fail('Y value incorrect');
  end;

  if (not(priv.X.Equals(TBigInteger.Create
    ('D0EC4E50BB290A42E9E355C73D8809345DE2E139', 16)))) then
  begin
    Fail('X value incorrect');
  end;

  signer := TDSASigner.Create();

  signer.Init(true, TParametersWithRandom.Create(kp.Private,
    TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create
    ('349C55648DCF992F3F33E8026CFAC87C1D2BA075'),
    TFixedSecureRandom.TData.Create(DecodeHex('01020304')))))
    as IParametersWithRandom);

  msg := DecodeHex('A9993E364706816ABA3E25717850C26C9CD0D89D');

  sig := signer.GenerateSignature(msg);

  if (not(sig[0].Equals(TBigInteger.Create
    ('636155AC9A4633B4665D179F9E4117DF68601F34', 16)))) then
  begin
    Fail('R value incorrect');
  end;

  if (not(sig[1].Equals(TBigInteger.Create
    ('6C540B02D9D4852F89DF8CFC99963204F4347704', 16)))) then
  begin
    Fail('S value incorrect');
  end;

  signer.Init(false, kp.Public);

  if (not(signer.VerifySignature(msg, sig[0], sig[1]))) then
  begin
    Fail('signature not verified');
  end;
end;

procedure TTestDSA.DoDSA2Test2;
var
  seed, msg: TBytes;
  pGen: IDsaParametersGenerator;
  params: IDSAParameters;
  pv: IDSAValidationParameters;
  kpGen: IDSAKeyPairGenerator;
  kp: IAsymmetricCipherKeyPair;
  pub: IDSAPublicKeyParameters;
  priv: IDSAPrivateKeyParameters;
  signer: IDSASigner;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  seed := DecodeHex('5AFCC1EFFC079A9CCA6ECA86D6E3CC3B18642D9BE1CC6207C84002A9');

  pGen := TDsaParametersGenerator.Create(TDigestUtilities.GetDigest('SHA-224'));

  pGen.Init(TDSAParameterGenerationParameters.Create(2048, 224, 80,
    TDSATestSecureRandom.Create(seed)) as IDSAParameterGenerationParameters);

  params := pGen.GenerateParameters();

  pv := params.getValidationParameters();

  if (pv.GetCounter() <> 21) then
  begin
    Fail('counter incorrect');
  end;

  if (not AreEqual(seed, pv.seed)) then
  begin
    Fail('seed incorrect');
  end;

  if (not(params.Q.Equals(TBigInteger.Create
    ('90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D', 16)))) then
  begin
    Fail('Q incorrect');
  end;

  if (not(params.p.Equals(TBigInteger.Create('C196BA05AC29E1F9C3C72D56DFFC6154'
    + 'A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A06' +
    '7CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE4' +
    '28782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE6' +
    '19ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1' +
    'E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD9' +
    '2D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BF' +
    'FAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E' +
    '5320121496DC65B3930E38047294FF877831A16D5228418D' +
    'E8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A040' +
    '2A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83', 16)))) then
  begin
    Fail('P incorrect');
  end;

  if (not(params.G.Equals(TBigInteger.Create('A59A749A11242C58C894E9E5A91804E8'
    + 'FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35F' +
    'C9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E50' +
    '48B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B' +
    '6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B715959' +
    '2E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E574' +
    '5EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDF' +
    'D049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E69' +
    '5515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE' +
    '7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED20' +
    '0AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085', 16)))) then
  begin
    Fail('G incorrect');
  end;

  kpGen := TDSAKeyPairGenerator.Create();

  kpGen.Init(TDSAKeyGenerationParameters.Create(TFixedSecureRandom.Create
    (TCryptoLibGenericArray<ISource>.Create(TFixedSecureRandom.TData.Create
    (DecodeHex('00D0F09ED3E2568F6CADF9224117DA2AEC5A4300E009DE1366023E17')))),
    params) as IDSAKeyGenerationParameters);

  kp := kpGen.GenerateKeyPair();

  pub := kp.Public as IDSAPublicKeyParameters;
  priv := kp.Private as IDSAPrivateKeyParameters;

  if (not(pub.Y.Equals(TBigInteger.Create('70035C9A3B225B258F16741F3941FBF0' +
    '6F3D056CD7BD864604CBB5EE9DD85304EE8E8E4ABD5E9032' +
    '11DDF25CE149075510ACE166970AFDC7DF552B7244F342FA' +
    '02F7A621405B754909D757F97290E1FE5036E904CF593446' +
    '0C046D95659821E1597ED9F2B1F0E20863A6BBD0CE74DACB' +
    'A5D8C68A90B29C2157CDEDB82EC12B81EE3068F9BF5F7F34' +
    '6ECA41ED174CCCD7D154FA4F42F80FFE1BF46AE9D8125DEB' +
    '5B4BA08A72BDD86596DBEDDC9550FDD650C58F5AE5133509' +
    'A702F79A31ECB490F7A3C5581631F7C5BE4FF7F9E9F27FA3' +
    '90E47347AD1183509FED6FCF198BA9A71AB3335B4F38BE8D' +
    '15496A00B6DC2263E20A5F6B662320A3A1EC033AA61E3B68', 16)))) then
  begin
    Fail('Y value incorrect');
  end;

  if (not(priv.X.Equals(TBigInteger.Create
    ('00D0F09ED3E2568F6CADF9224117DA2AEC5A4300E009DE1366023E17', 16)))) then
  begin
    Fail('X value incorrect');
  end;

  signer := TDSASigner.Create();

  signer.Init(true, TParametersWithRandom.Create(kp.Private,
    TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create
    ('735959CC4463B8B440E407EECA8A473BF6A6D1FE657546F67D401F05'),
    TFixedSecureRandom.TData.Create(DecodeHex('01020304')))))
    as IParametersWithRandom);

  msg := DecodeHex('23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7');

  sig := signer.GenerateSignature(msg);

  if (not(sig[0].Equals(TBigInteger.Create
    ('4400138D05F9639CAF54A583CAAF25D2B76D0C3EAD752CE17DBC85FE', 16)))) then
  begin
    Fail('R value incorrect');
  end;

  if (not(sig[1].Equals(TBigInteger.Create
    ('874D4F12CB13B61732D398445698CFA9D92381D938AA57EE2C9327B3', 16)))) then
  begin
    Fail('S value incorrect');
  end;

  signer.Init(false, kp.Public);

  if (not(signer.VerifySignature(msg, sig[0], sig[1]))) then
  begin
    Fail('signature not verified');
  end;
end;

procedure TTestDSA.DoDSA2Test3;
var
  seed, msg: TBytes;
  pGen: IDsaParametersGenerator;
  params: IDSAParameters;
  pv: IDSAValidationParameters;
  kpGen: IDSAKeyPairGenerator;
  kp: IAsymmetricCipherKeyPair;
  pub: IDSAPublicKeyParameters;
  priv: IDSAPrivateKeyParameters;
  signer: IDSASigner;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  seed := DecodeHex
    ('4783081972865EA95D43318AB2EAF9C61A2FC7BBF1B772A09017BDF5A58F4FF0');

  pGen := TDsaParametersGenerator.Create(TDigestUtilities.GetDigest('SHA-256'));

  pGen.Init(TDSAParameterGenerationParameters.Create(2048, 256, 80,
    TDSATestSecureRandom.Create(seed)) as IDSAParameterGenerationParameters);

  params := pGen.GenerateParameters();

  pv := params.getValidationParameters();

  if (pv.GetCounter() <> 12) then
  begin
    Fail('counter incorrect');
  end;

  if (not AreEqual(seed, pv.seed)) then
  begin
    Fail('seed incorrect');
  end;

  if (not(params.Q.Equals(TBigInteger.Create
    ('C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467', 16))))
  then
  begin
    Fail('Q incorrect');
  end;

  if (not(params.p.Equals(TBigInteger.Create('F56C2A7D366E3EBDEAA1891FD2A0D099'
    + '436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91' +
    'D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C' +
    '69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2' +
    '5909132627F51A0C866877E672E555342BDF9355347DBD43' +
    'B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431' +
    '31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A' +
    'EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD' +
    'F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF' +
    '1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D' +
    '531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75', 16)))) then
  begin
    Fail('P incorrect');
  end;

  if (not(params.G.Equals(TBigInteger.Create('8DC6CC814CAE4A1C05A3E186A6FE27EA'
    + 'BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1' +
    '29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB' +
    '6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2' +
    '513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869' +
    '7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0' +
    'A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403' +
    '45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8' +
    'FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E' +
    '428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC' +
    'EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279', 16)))) then
  begin
    Fail('G incorrect');
  end;

  kpGen := TDSAKeyPairGenerator.Create();

  kpGen.Init(TDSAKeyGenerationParameters.Create(TFixedSecureRandom.Create
    (TCryptoLibGenericArray<ISource>.Create(TFixedSecureRandom.TData.Create
    (DecodeHex
    ('0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C')))),
    params) as IDSAKeyGenerationParameters);

  kp := kpGen.GenerateKeyPair();

  pub := kp.Public as IDSAPublicKeyParameters;
  priv := kp.Private as IDSAPrivateKeyParameters;

  if (not(pub.Y.Equals(TBigInteger.Create('2828003D7C747199143C370FDD07A286' +
    '1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D' +
    '1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA' +
    'CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500' +
    'C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF' +
    '2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41' +
    '9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF' +
    '41566E26FAEE475137EC781A0DC088A26C8804A98C23140E' +
    '7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D' +
    'C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE' +
    'A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B', 16)))) then
  begin
    Fail('Y value incorrect');
  end;

  if (not(priv.X.Equals(TBigInteger.Create
    ('0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C', 16))))
  then
  begin
    Fail('X value incorrect');
  end;

  signer := TDSASigner.Create();

  signer.Init(true, TParametersWithRandom.Create(kp.Private,
    TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create
    ('0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C'),
    TFixedSecureRandom.TData.Create(DecodeHex('01020304')))))
    as IParametersWithRandom);

  msg := DecodeHex
    ('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD');

  sig := signer.GenerateSignature(msg);

  if (not(sig[0].Equals(TBigInteger.Create
    ('315C875DCD4850E948B8AC42824E9483A32D5BA5ABE0681B9B9448D444F2BE3C', 16))))
  then
  begin
    Fail('R value incorrect');
  end;

  if (not(sig[1].Equals(TBigInteger.Create
    ('89718D12E54A8D9ED066E4A55F7ED5A2229CD23B9A3CEE78F83ED6AA61F6BCB9', 16))))
  then
  begin
    Fail('S value incorrect');
  end;

  signer.Init(false, kp.Public);

  if (not(signer.VerifySignature(msg, sig[0], sig[1]))) then
  begin
    Fail('signature not verified');
  end;
end;

procedure TTestDSA.DoDSA2Test4;
var
  seed, msg: TBytes;
  pGen: IDsaParametersGenerator;
  params: IDSAParameters;
  pv: IDSAValidationParameters;
  kpGen: IDSAKeyPairGenerator;
  kp: IAsymmetricCipherKeyPair;
  pub: IDSAPublicKeyParameters;
  priv: IDSAPrivateKeyParameters;
  signer: IDSASigner;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin
  seed := DecodeHex
    ('193AFCA7C1E77B3C1ECC618C81322E47B8B8B997C9C83515C59CC446C2D9BD47');

  pGen := TDsaParametersGenerator.Create(TDigestUtilities.GetDigest('SHA-256'));

  pGen.Init(TDSAParameterGenerationParameters.Create(3072, 256, 80,
    TDSATestSecureRandom.Create(seed)) as IDSAParameterGenerationParameters);

  params := pGen.GenerateParameters();

  pv := params.getValidationParameters();

  if (pv.GetCounter() <> 20) then
  begin
    Fail('counter incorrect');
  end;

  if (not AreEqual(seed, pv.seed)) then
  begin
    Fail('seed incorrect');
  end;

  if (not(params.Q.Equals(TBigInteger.Create
    ('CFA0478A54717B08CE64805B76E5B14249A77A4838469DF7F7DC987EFCCFB11D', 16))))
  then
  begin
    Fail('Q incorrect');
  end;

  if (not(params.p.Equals(TBigInteger.Create
    ('90066455B5CFC38F9CAA4A48B4281F292C260FEEF01FD610' +
    '37E56258A7795A1C7AD46076982CE6BB956936C6AB4DCFE0' +
    '5E6784586940CA544B9B2140E1EB523F009D20A7E7880E4E' +
    '5BFA690F1B9004A27811CD9904AF70420EEFD6EA11EF7DA1' +
    '29F58835FF56B89FAA637BC9AC2EFAAB903402229F491D8D' +
    '3485261CD068699B6BA58A1DDBBEF6DB51E8FE34E8A78E54' +
    '2D7BA351C21EA8D8F1D29F5D5D15939487E27F4416B0CA63' +
    '2C59EFD1B1EB66511A5A0FBF615B766C5862D0BD8A3FE7A0' +
    'E0DA0FB2FE1FCB19E8F9996A8EA0FCCDE538175238FC8B0E' +
    'E6F29AF7F642773EBE8CD5402415A01451A840476B2FCEB0' +
    'E388D30D4B376C37FE401C2A2C2F941DAD179C540C1C8CE0' +
    '30D460C4D983BE9AB0B20F69144C1AE13F9383EA1C08504F' +
    'B0BF321503EFE43488310DD8DC77EC5B8349B8BFE97C2C56' +
    '0EA878DE87C11E3D597F1FEA742D73EEC7F37BE43949EF1A' +
    '0D15C3F3E3FC0A8335617055AC91328EC22B50FC15B941D3' +
    'D1624CD88BC25F3E941FDDC6200689581BFEC416B4B2CB73', 16)))) then
  begin
    Fail('P incorrect');
  end;

  if (not(params.G.Equals(TBigInteger.Create
    ('5E5CBA992E0A680D885EB903AEA78E4A45A469103D448EDE' +
    '3B7ACCC54D521E37F84A4BDD5B06B0970CC2D2BBB715F7B8' +
    '2846F9A0C393914C792E6A923E2117AB805276A975AADB52' +
    '61D91673EA9AAFFEECBFA6183DFCB5D3B7332AA19275AFA1' +
    'F8EC0B60FB6F66CC23AE4870791D5982AAD1AA9485FD8F4A' +
    '60126FEB2CF05DB8A7F0F09B3397F3937F2E90B9E5B9C9B6' +
    'EFEF642BC48351C46FB171B9BFA9EF17A961CE96C7E7A7CC' +
    '3D3D03DFAD1078BA21DA425198F07D2481622BCE45969D9C' +
    '4D6063D72AB7A0F08B2F49A7CC6AF335E08C4720E31476B6' +
    '7299E231F8BD90B39AC3AE3BE0C6B6CACEF8289A2E2873D5' +
    '8E51E029CAFBD55E6841489AB66B5B4B9BA6E2F784660896' +
    'AFF387D92844CCB8B69475496DE19DA2E58259B090489AC8' +
    'E62363CDF82CFD8EF2A427ABCD65750B506F56DDE3B98856' +
    '7A88126B914D7828E2B63A6D7ED0747EC59E0E0A23CE7D8A' +
    '74C1D2C2A7AFB6A29799620F00E11C33787F7DED3B30E1A2' +
    '2D09F1FBDA1ABBBFBF25CAE05A13F812E34563F99410E73B', 16)))) then
  begin
    Fail('G incorrect');
  end;

  kpGen := TDSAKeyPairGenerator.Create();

  kpGen.Init(TDSAKeyGenerationParameters.Create(TFixedSecureRandom.Create
    (TCryptoLibGenericArray<ISource>.Create(TFixedSecureRandom.TData.Create
    (DecodeHex
    ('3ABC1587297CE7B9EA1AD6651CF2BC4D7F92ED25CABC8553F567D1B40EBB8764')))
    ), params));

  kp := kpGen.GenerateKeyPair();

  pub := kp.Public as IDSAPublicKeyParameters;
  priv := kp.Private as IDSAPrivateKeyParameters;

  if (not(pub.Y.Equals(TBigInteger.Create
    ('8B891C8692D3DE875879390F2698B26FBECCA6B075535DCE' +
    '6B0C862577F9FA0DEF6074E7A7624121224A595896ABD4CD' +
    'A56B2CEFB942E025D2A4282FFAA98A48CDB47E1A6FCB5CFB' +
    '393EF35AF9DF913102BB303C2B5C36C3F8FC04ED7B8B69FE' +
    'FE0CF3E1FC05CFA713B3435B2656E913BA8874AEA9F93600' +
    '6AEB448BCD005D18EC3562A33D04CF25C8D3D69844343442' +
    'FA3DB7DE618C5E2DA064573E61E6D5581BFB694A23AC87FD' +
    '5B52D62E954E1376DB8DDB524FFC0D469DF978792EE44173' +
    '8E5DB05A7DC43E94C11A2E7A4FBE383071FA36D2A7EC8A93' +
    '88FE1C4F79888A99D3B6105697C2556B79BB4D7E781CEBB3' +
    'D4866AD825A5E830846072289FDBC941FA679CA82F5F78B7' +
    '461B2404DB883D215F4E0676CF5493950AC5591697BFEA8D' +
    '1EE6EC016B89BA51CAFB5F9C84C989FA117375E94578F28B' +
    'E0B34CE0545DA46266FD77F62D8F2CEE92AB77012AFEBC11' +
    '008985A821CD2D978C7E6FE7499D1AAF8DE632C21BB48CA5' +
    'CBF9F31098FD3FD3854C49A65D9201744AACE540354974F9', 16)))) then
  begin
    Fail('Y value incorrect');
  end;

  if (not(priv.X.Equals(TBigInteger.Create
    ('3ABC1587297CE7B9EA1AD6651CF2BC4D7F92ED25CABC8553F567D1B40EBB8764', 16))))
  then
  begin
    Fail('X value incorrect');
  end;

  signer := TDSASigner.Create();

  signer.Init(true, TParametersWithRandom.Create(kp.Private,
    TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create
    ('A6902C1E6E3943C5628061588A8B007BCCEA91DBF12915483F04B24AB0678BEE'),
    TFixedSecureRandom.TData.Create(DecodeHex('01020304')))))
    as IParametersWithRandom);

  msg := DecodeHex
    ('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD');

  sig := signer.GenerateSignature(msg);

  if (not(sig[0].Equals(TBigInteger.Create
    ('5F184E645A38BE8FB4A6871B6503A9D12924C7ABE04B71410066C2ECA6E3BE3E', 16))))
  then
  begin
    Fail('R value incorrect');
  end;

  if (not(sig[1].Equals(TBigInteger.Create
    ('91EB0C7BA3D4B9B60B825C3D9F2CADA8A2C9D7723267B033CBCDCF8803DB9C18', 16))))
  then
  begin
    Fail('S value incorrect');
  end;

  signer.Init(false, kp.Public);

  if (not(signer.VerifySignature(msg, sig[0], sig[1]))) then
  begin
    Fail('signature not verified');
  end;
end;

procedure TTestDSA.DoTestDSASHA3(size: Int32; const s: TBigInteger);
var
  dsaParams: IDSAParameters;
  X, Y, r: TBigInteger;
  priKey: IDSAPrivateKeyParameters;
  pubKey: IDSAPublicKeyParameters;
  k: ISecureRandom;
  M, encSig: TBytes;
  dsa: IDSADigestSigner;
  RS: TCryptoLibGenericArray<TBigInteger>;
begin
  dsaParams := TDSAParameters.Create
    (TBigInteger.Create('F56C2A7D366E3EBDEAA1891FD2A0D099' +
    '436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91' +
    'D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C' +
    '69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2' +
    '5909132627F51A0C866877E672E555342BDF9355347DBD43' +
    'B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431' +
    '31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A' +
    'EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD' +
    'F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF' +
    '1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D' +
    '531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75', 16),
    TBigInteger.Create
    ('C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467', 16),
    TBigInteger.Create('8DC6CC814CAE4A1C05A3E186A6FE27EA' +
    'BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1' +
    '29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB' +
    '6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2' +
    '513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869' +
    '7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0' +
    'A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403' +
    '45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8' +
    'FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E' +
    '428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC' +
    'EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279', 16));

  X := TBigInteger.Create
    ('0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C', 16);

  Y := TBigInteger.Create('2828003D7C747199143C370FDD07A286' +
    '1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D' +
    '1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA' +
    'CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500' +
    'C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF' +
    '2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41' +
    '9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF' +
    '41566E26FAEE475137EC781A0DC088A26C8804A98C23140E' +
    '7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D' +
    'C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE' +
    'A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B', 16);

  priKey := TDSAPrivateKeyParameters.Create(X, dsaParams);

  k := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TBigIntegerSource.Create(TBigInteger.Create
    ('72546832179840998877302529996971396893172522460793442785601695562409154906335')
    .ToByteArrayUnsigned), TFixedSecureRandom.TData.Create
    (DecodeHex('01020304'))));

  M := DecodeHex
    ('1BD4ED430B0F384B4E8D458EFF1A8A553286D7AC21CB2F6806172EF5F94A06AD');

  dsa := TDSADigestSigner.Create(TDSASigner.Create() as IDSASigner,
    TDigestUtilities.GetDigest('SHA3-' + IntToStr(size)));

  dsa.Init(true, TParametersWithRandom.Create(priKey, k)
    as IParametersWithRandom);

  dsa.BlockUpdate(M, 0, System.Length(M));

  encSig := dsa.GenerateSignature();

  RS := DoDerDecode(encSig);

  r := TBigInteger.Create
    ('4864074fe30e6601268ee663440e4d9b703f62673419864e91e9edb0338ce510', 16);

  if (not r.Equals(RS[0])) then
  begin
    Fail('r component wrong.' + sLineBreak + ' expecting: ' + r.toString(16) +
      sLineBreak + ' got      : ' + RS[0].toString(16));
  end;

  if (not s.Equals(RS[1])) then
  begin
    Fail('s component wrong.' + sLineBreak + ' expecting: ' + s.toString(16) +
      sLineBreak + ' got      : ' + RS[1].toString(16));
  end;

  // Verify the signature
  pubKey := TDSAPublicKeyParameters.Create(Y, dsaParams);

  dsa.Init(false, pubKey);

  dsa.BlockUpdate(M, 0, System.Length(M));

  if (not(dsa.VerifySignature(encSig))) then
  begin
    Fail('signature fails');
  end;
end;

procedure TTestDSA.DoTestECDsa239BitBinary(const algorithm: String;
  const oid: IDerObjectIdentifier);
var
  kData, &message, sigBytes: TBytes;
  k: ISecureRandom;
  curve: IECCurve;
  parameters: IECDomainParameters;
  sgr: ISigner;
  sKey, vKey: IAsymmetricKeyParameter;
begin

  kData := TBigInteger.Create
    ('171278725565216523967285789236956265265265235675811949404040041670216363')
    .ToByteArrayUnsigned;

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
    TBigInteger.ValueOf(4)); // h

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

  sgr := TSignerUtilities.GetSigner(algorithm);

  sgr.Init(true, TParametersWithRandom.Create(sKey, k)
    as IParametersWithRandom);

  &message := TConverters.ConvertStringToBytes('abc', TEncoding.ASCII);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  sgr := TSignerUtilities.GetSigner(oid.Id);

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not(sgr.VerifySignature(sigBytes))) then
  begin
    Fail('239 Bit ' + algorithm + ' verification failed');
  end;

end;

procedure TTestDSA.DoTestKeyGeneration(keysize: Int32);
var
  rand: ISecureRandom;
  generator: IDSAKeyPairGenerator;
  dsapGen: IDsaParametersGenerator;
  p: IAsymmetricCipherKeyPair;
  params: IDSAParameters;
  priv: IDSAPrivateKeyParameters;
  qsize: Int32;
begin
  rand := TSecureRandom.Create();
  generator := TGeneratorUtilities.GetKeyPairGenerator('DSA')
    as IDSAKeyPairGenerator;

  // The NIST standard does not fully specify the size of q that
  // must be used for a given key size. Hence there are differences.
  // For example if keysize = 2048, then OpenSSL uses 256 bit q's by default,
  // but the SUN provider uses 224 bits. Both are acceptable sizes.
  // The tests below simply asserts that the size of q does not decrease the
  // overall security of the DSA.

  // Also We Check the length of the private key.
  // For example GPG4Browsers or the KJUR library derived from it use
  // q.BitCount instead of q.BitLength to determine the size of the private key
  // and hence would generate keys that are much too small.
  case keysize of
    1024:
      begin
        dsapGen := TDsaParametersGenerator.Create(); // SHA-1 Default
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 160, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');
        qsize := params.Q.BitLength;

        CheckTrue(qsize = 160, 'Invalid qsize for 1024 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
      end;

    2048:
      begin
        dsapGen := TDsaParametersGenerator.Create
          (TDigestUtilities.GetDigest('SHA-224'));
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 224, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');

        qsize := params.Q.BitLength;
        CheckTrue(qsize = 224, 'Invalid qsize for 2048 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
        //
        // .....
        //
        dsapGen := TDsaParametersGenerator.Create
          (TDigestUtilities.GetDigest('SHA-256'));
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 256, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');

        qsize := params.Q.BitLength;
        CheckTrue(qsize = 256, 'Invalid qsize for 2048 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
      end;

    3072:
      begin

        dsapGen := TDsaParametersGenerator.Create
          (TDigestUtilities.GetDigest('SHA-256'));
        dsapGen.Init(TDSAParameterGenerationParameters.Create(keysize, 256, 80,
          rand) as IDSAParameterGenerationParameters);

        params := dsapGen.GenerateParameters();

        generator.Init(TDSAKeyGenerationParameters.Create(rand, params)
          as IDSAKeyGenerationParameters);

        p := generator.GenerateKeyPair();

        priv := p.Private as IDSAPrivateKeyParameters;
        params := priv.parameters;

        CheckTrue(keysize = params.p.BitLength, 'keysize mismatch');

        qsize := params.Q.BitLength;
        CheckTrue(qsize = 256, 'Invalid qsize for 3072 bit key: ' +
          IntToStr(qsize));

        CheckTrue(priv.X.BitLength >= (qsize - 32), 'privkey error');
      end

  else
    begin
      Fail('Invalid key size: ' + IntToStr(keysize));
    end;

  end;

end;

procedure TTestDSA.SetUp;
begin
  inherited;

end;

procedure TTestDSA.TearDown;
begin
  inherited;

end;

procedure TTestDSA.TestDSA;
var
  k1, k2, keyData, &message: TBytes;
  sig: TCryptoLibGenericArray<TBigInteger>;
  random, keyRandom: ISecureRandom;
  pValue, qValue, r, s: TBigInteger;
  pGen: IDsaParametersGenerator;
  params: IDSAParameters;
  pValid: IDSAValidationParameters;
  dsaKeyGen: IDSAKeyPairGenerator;
  genParam: IDSAKeyGenerationParameters;
  pair: IAsymmetricCipherKeyPair;
  param: IParametersWithRandom;
  dsa: IDSASigner;
begin
  k1 := DecodeHex('d5014e4b60ef2ba8b6211b4062ba3224e0427dd3');
  k2 := DecodeHex
    ('345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded');

  random := TFixedSecureRandom.Create(TCryptoLibGenericArray<ISource>.Create
    (TFixedSecureRandom.TData.Create(k1), TFixedSecureRandom.TData.Create(k2)));

  keyData := DecodeHex('b5014e4b60ef2ba8b6211b4062ba3224e0427dd3');

  keyRandom := TFixedSecureRandom.Create
    (TCryptoLibGenericArray<ISource>.Create(TFixedSecureRandom.TData.Create
    (keyData), TFixedSecureRandom.TData.Create(keyData),
    TFixedSecureRandom.TData.Create(DecodeHex('01020304'))));

  pValue := TBigInteger.Create
    ('8df2a494492276aa3d25759bb06869cbeac0d83afb8d0cf7cbb8324f0d7882e5d0762fc5b7210eafc2e9adac32ab7aac49693dfbf83724c2ec0736ee31c80291',
    16);
  qValue := TBigInteger.Create('c773218c737ec8ee993b4f2ded30f48edace915f', 16);

  r := TBigInteger.Create('68076202252361894315274692543577577550894681403');
  s := TBigInteger.Create('1089214853334067536215539335472893651470583479365');
  pGen := TDsaParametersGenerator.Create();

  pGen.Init(512, 80, random);

  params := pGen.GenerateParameters();
  pValid := params.ValidationParameters;

  if (pValid.GetCounter() <> 105) then
  begin
    Fail('Counter wrong');
  end;

  if ((not(pValue.Equals(params.p))) or (not(qValue.Equals(params.Q)))) then
  begin
    Fail('p or q wrong');
  end;

  dsaKeyGen := TDSAKeyPairGenerator.Create();
  genParam := TDSAKeyGenerationParameters.Create(keyRandom, params);

  dsaKeyGen.Init(genParam);

  pair := dsaKeyGen.GenerateKeyPair();

  param := TParametersWithRandom.Create(pair.Private, keyRandom);

  dsa := TDSASigner.Create();

  dsa.Init(true, param);

  &message := TBigInteger.Create
    ('968236873715988614170569073515315707566766479517').ToByteArrayUnsigned;
  sig := dsa.GenerateSignature(&message);

  if (not(r.Equals(sig[0]))) then
  begin
    Fail('r component wrong. expected ' + r.toString + ' but got ' +
      sig[0].toString);
  end;

  if (not(s.Equals(sig[1]))) then
  begin
    Fail('s component wrong. expected ' + s.toString + ' but got ' +
      sig[1].toString);
  end;

  dsa.Init(false, pair.Public);

  if (not(dsa.VerifySignature(&message, sig[0], sig[1]))) then
  begin
    Fail('verification fails');
  end;

  DoDSA2Test1();
  DoDSA2Test2();
  DoDSA2Test3();
  DoDSA2Test4();

  DoTestDSASHA3(224,
    TBigInteger.Create
    ('613202af2a7f77e02b11b5c3a5311cf6b412192bc0032aac3ec127faebfc6bd0', 16));
  DoTestDSASHA3(256,
    TBigInteger.Create
    ('2450755c5e15a691b121bc833b97864e34a61ee025ecec89289c949c1858091e', 16));
  DoTestDSASHA3(384,
    TBigInteger.Create
    ('7aad97c0b71bb1e1a6483b6948a03bbe952e4780b0cee699a11731f90d84ddd1', 16));
  DoTestDSASHA3(512,
    TBigInteger.Create
    ('725ad64d923c668e64e7c3898b5efde484cab49ce7f98c2885d2a13a9e355ad4', 16));
end;

procedure TTestDSA.TestDsa2Parameters;
var
  seed, encodeParams, encodeParams_2, data, sigBytes: TBytes;
  a: IDsaParametersGenerator;
  dsaP: IDSAParameters;
  G: IAsymmetricCipherKeyPairGenerator;
  p: IAsymmetricCipherKeyPair;
  sKey: IDSAPrivateKeyParameters;
  vKey: IDSAPublicKeyParameters;
  p2: IDSAParameters;
  s: ISigner;
begin
  seed := DecodeHex
    ('4783081972865EA95D43318AB2EAF9C61A2FC7BBF1B772A09017BDF5A58F4FF0');

  a := TDsaParametersGenerator.Create(TDigestUtilities.GetDigest('SHA-256'));
  a.Init(TDSAParameterGenerationParameters.Create(2048, 256, 80,
    TDSATestSecureRandom.Create(seed) as ISecureRandom)
    as IDSAParameterGenerationParameters);

  dsaP := a.GenerateParameters();

  if (not(dsaP.Q.Equals(TBigInteger.Create
    ('C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467', 16))))
  then
  begin
    Fail('Q incorrect');
  end;

  if (not(dsaP.p.Equals(TBigInteger.Create('F56C2A7D366E3EBDEAA1891FD2A0D099' +
    '436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91' +
    'D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C' +
    '69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A2' +
    '5909132627F51A0C866877E672E555342BDF9355347DBD43' +
    'B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC431' +
    '31BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782A' +
    'EB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCD' +
    'F00E48F2E8356BDB59D86114028F67B8E07B127744778AFF' +
    '1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D' +
    '531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75', 16)))) then
  begin
    Fail('P incorrect');
  end;

  if (not(dsaP.G.Equals(TBigInteger.Create('8DC6CC814CAE4A1C05A3E186A6FE27EA' +
    'BA8CDB133FDCE14A963A92E809790CBA096EAA26140550C1' +
    '29FA2B98C16E84236AA33BF919CD6F587E048C52666576DB' +
    '6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2' +
    '513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D61869' +
    '7B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0' +
    'A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A6403' +
    '45FA1298A16E85421B2208D00068A5A42915F82CF0B858C8' +
    'FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E' +
    '428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CC' +
    'EF5AF477AFED029F485B5597739F5D0240F67C2D948A6279', 16)))) then
  begin
    Fail('G incorrect');
  end;

  G := TGeneratorUtilities.GetKeyPairGenerator('DSA');

  G.Init(TDSAKeyGenerationParameters.Create(TFixedSecureRandom.From
    (TCryptoLibMatrixByteArray.Create(DecodeHex
    ('0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C'))),
    dsaP) as IDSAKeyGenerationParameters);

  p := G.GenerateKeyPair();

  sKey := p.Private as IDSAPrivateKeyParameters;
  vKey := p.Public as IDSAPublicKeyParameters;

  if (not(vKey.Y.Equals(TBigInteger.Create('2828003D7C747199143C370FDD07A286' +
    '1524514ACC57F63F80C38C2087C6B795B62DE1C224BF8D1D' +
    '1424E60CE3F5AE3F76C754A2464AF292286D873A7A30B7EA' +
    'CBBC75AAFDE7191D9157598CDB0B60E0C5AA3F6EBE425500' +
    'C611957DBF5ED35490714A42811FDCDEB19AF2AB30BEADFF' +
    '2907931CEE7F3B55532CFFAEB371F84F01347630EB227A41' +
    '9B1F3F558BC8A509D64A765D8987D493B007C4412C297CAF' +
    '41566E26FAEE475137EC781A0DC088A26C8804A98C23140E' +
    '7C936281864B99571EE95C416AA38CEEBB41FDBFF1EB1D1D' +
    'C97B63CE1355257627C8B0FD840DDB20ED35BE92F08C49AE' +
    'A5613957D7E5C7A6D5A5834B4CB069E0831753ECF65BA02B', 16)))) then
  begin
    Fail('Y value incorrect');
  end;

  if (not sKey.X.Equals(TBigInteger.Create
    ('0CAF2EF547EC49C4F3A6FE6DF4223A174D01F2C115D49A6F73437C29A2A8458C', 16)))
  then
  begin
    Fail('X value incorrect');
  end;

  encodeParams := TDsaParameter.Create(dsaP.p, dsaP.Q, dsaP.G).GetDerEncoded();

  p2 := TDSAParameters.Create(dsaP.p, dsaP.Q, dsaP.G);

  encodeParams_2 := TDsaParameter.Create(p2.p, p2.Q, p2.G).GetDerEncoded();

  if (not AreEqual(encodeParams, encodeParams_2)) then
  begin
    Fail('encode/decode parameters failed');
  end;

  s := TSignerUtilities.GetSigner('DSA');
  data := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);

  s.Init(true, sKey);

  s.BlockUpdate(data, 0, System.Length(data));

  sigBytes := s.GenerateSignature();

  s := TSignerUtilities.GetSigner('DSA');

  s.Init(false, vKey);

  s.BlockUpdate(data, 0, System.Length(data));

  if (not(s.VerifySignature(sigBytes))) then
  begin
    Fail('DSA verification failed');
  end;
end;

procedure TTestDSA.TestECDsa239BitPrime;
var
  r, s: TBigInteger;
  kData, &message, sigBytes: TBytes;
  k: ISecureRandom;
  curve: IECCurve;
  spec: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  sgr: ISigner;
  sKey, vKey: IAsymmetricKeyParameter;
  sig: TCryptoLibGenericArray<TBigInteger>;
begin

  r := TBigInteger.Create
    ('308636143175167811492622547300668018854959378758531778147462058306432176');
  s := TBigInteger.Create
    ('323813553209797357708078776831250505931891051755007842781978505179448783');

  kData := TBigInteger.Create
    ('700000017569056646655505781757157107570501575775705779575555657156756655')
    .ToByteArrayUnsigned;

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
    (DecodeHex
    ('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')), // G
    TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307')
    ); // n

  priKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('876300101507107567501066130761671078357010671067781776716671676178726717'),
    // d
    spec);

  pubKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex
    ('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')), // Q
    spec);

  sgr := TSignerUtilities.GetSigner('ECDSA');

  sKey := priKey;
  vKey := pubKey;

  sgr.Init(true, TParametersWithRandom.Create(sKey, k)
    as IParametersWithRandom);

  &message := TConverters.ConvertStringToBytes('abc', TEncoding.ASCII);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not(sgr.VerifySignature(sigBytes))) then
  begin
    Fail('239 Bit EC verification failed');
  end;

  sig := DoDerDecode(sigBytes);

  if (not(r.Equals(sig[0]))) then
  begin
    Fail('r component wrong.' + sLineBreak + ' expecting: ' + r.toString +
      sLineBreak + ' got      : ' + sig[0].toString);
  end;

  if (not(s.Equals(sig[1]))) then
  begin
    Fail('s component wrong.' + sLineBreak + ' expecting: ' + s.toString +
      sLineBreak + ' got      : ' + sig[1].toString);
  end;

end;

procedure TTestDSA.TestGeneration;
var
  s: ISigner;
  data, sigBytes: TBytes;
  rand: ISecureRandom;
  G: IAsymmetricCipherKeyPairGenerator;
  pGen: IDsaParametersGenerator;
  p: IAsymmetricCipherKeyPair;
  sKey, vKey: IAsymmetricKeyParameter;
  curve: IECCurve;
  ecSpec: IECDomainParameters;
begin

  // test exception
  //

  DoTestBadStrength(513);
  DoTestBadStrength(510);
  DoTestBadStrength(1025);

  s := TSignerUtilities.GetSigner('DSA');
  data := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);
  rand := TSecureRandom.Create();

  G := TGeneratorUtilities.GetKeyPairGenerator('DSA');

  pGen := TDsaParametersGenerator.Create();
  pGen.Init(512, 80, rand);

  G.Init(TDSAKeyGenerationParameters.Create(rand, pGen.GenerateParameters())
    as IDSAKeyGenerationParameters);

  p := G.GenerateKeyPair();

  sKey := p.Private;
  vKey := p.Public;

  s.Init(true, sKey);

  s.BlockUpdate(data, 0, System.Length(data));

  sigBytes := s.GenerateSignature();

  s := TSignerUtilities.GetSigner('DSA');

  s.Init(false, vKey);

  s.BlockUpdate(data, 0, System.Length(data));

  if (not(s.VerifySignature(sigBytes))) then
  begin
    Fail('DSA verification failed');
  end;

  //
  // ECDSA Fp generation test
  //
  s := TSignerUtilities.GetSigner('ECDSA');

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
    (DecodeHex
    ('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')), // G
    TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307')
    ); // n

  G := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  G.Init(TECKeyGenerationParameters.Create(ecSpec, rand)
    as IECKeyGenerationParameters);

  p := G.GenerateKeyPair();

  sKey := p.Private;
  vKey := p.Public;

  s.Init(true, sKey);

  s.BlockUpdate(data, 0, System.Length(data));

  sigBytes := s.GenerateSignature();

  s := TSignerUtilities.GetSigner('ECDSA');

  s.Init(false, vKey);

  s.BlockUpdate(data, 0, System.Length(data));

  if (not(s.VerifySignature(sigBytes))) then
  begin
    Fail('ECDSA verification failed');
  end;

  //
  // ECDSA F2m generation test
  //
  s := TSignerUtilities.GetSigner('ECDSA');

  curve := TF2mCurve.Create(239, // m
    36, // k
    TBigInteger.Create
    ('32010857077C5431123A46B808906756F543423E8D27877578125778AC76', 16), // a
    TBigInteger.Create
    ('790408F2EEDAF392B012EDEFB3392F30F4327C0CA3F31FC383C422AA8C16', 16), // b
    TBigInteger.Create
    ('2000000000000000000000000000000F4D42FFE1492A4993F1CAD666E447', 16),
    TBigInteger.Four);

  ecSpec := TECDomainParameters.Create(curve,
    curve.DecodePoint
    (DecodeHex
    ('0457927098FA932E7C0A96D3FD5B706EF7E5F5C156E16B7E7C86038552E91D61D8EE5077C33FECF6F1A16B268DE469C3C7744EA9A971649FC7A9616305')),
    // G
    TBigInteger.Create
    ('220855883097298041197912187592864814557886993776713230936715041207411783'),
    // n
    TBigInteger.ValueOf(4)); // h

  G := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  G.Init(TECKeyGenerationParameters.Create(ecSpec, rand)
    as IECKeyGenerationParameters);

  p := G.GenerateKeyPair();

  sKey := p.Private;
  vKey := p.Public;

  s.Init(true, sKey);

  s.BlockUpdate(data, 0, System.Length(data));

  sigBytes := s.GenerateSignature();

  s := TSignerUtilities.GetSigner('ECDSA');

  s.Init(false, vKey);

  s.BlockUpdate(data, 0, System.Length(data));

  if (not(s.VerifySignature(sigBytes))) then
  begin
    Fail('ECDSA verification failed');
  end;
end;

procedure TTestDSA.TestKeyGenerationAll;
begin
  DoTestKeyGeneration(1024);
  DoTestKeyGeneration(2048);
  DoTestKeyGeneration(3072);
end;

procedure TTestDSA.TestECDsa239BitBinary;
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
    .ToByteArrayUnsigned;

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
    TBigInteger.Four); // h

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

  &message := TConverters.ConvertStringToBytes('abc', TEncoding.ASCII);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  sigBytes := sgr.GenerateSignature();

  sgr.Init(false, vKey);

  sgr.BlockUpdate(&message, 0, System.Length(&message));

  if (not(sgr.VerifySignature(sigBytes))) then
  begin
    Fail('239 Bit EC verification failed');
  end;

  sig := DoDerDecode(sigBytes);

  if (not(r.Equals(sig[0]))) then
  begin
    Fail('r component wrong.' + sLineBreak + ' expecting: ' + r.toString +
      sLineBreak + ' got      : ' + sig[0].toString);
  end;

  if (not(s.Equals(sig[1]))) then
  begin
    Fail('s component wrong.' + sLineBreak + ' expecting: ' + s.toString +
      sLineBreak + ' got      : ' + sig[1].toString);
  end;

end;

procedure TTestDSA.TestECDsa239BitBinaryRipeMD160;
begin
  DoTestECDsa239BitBinary('RIPEMD160withECDSA',
    TTeleTrusTObjectIdentifiers.ECSignWithRipeMD160);
end;

procedure TTestDSA.TestECDsa239BitBinarySha1;
begin
  DoTestECDsa239BitBinary('SHA1withECDSA',
    TTeleTrusTObjectIdentifiers.ECSignWithSha1);
end;

procedure TTestDSA.TestECDsa239BitBinarySha224;
begin
  DoTestECDsa239BitBinary('SHA224withECDSA',
    TX9ObjectIdentifiers.ECDsaWithSha224);
end;

procedure TTestDSA.TestECDsa239BitBinarySha256;
begin
  DoTestECDsa239BitBinary('SHA256withECDSA',
    TX9ObjectIdentifiers.ECDsaWithSha256);
end;

procedure TTestDSA.TestECDsa239BitBinarySha384;
begin
  DoTestECDsa239BitBinary('SHA384withECDSA',
    TX9ObjectIdentifiers.ECDsaWithSha384);
end;

procedure TTestDSA.TestECDsa239BitBinarySha512;
begin
  DoTestECDsa239BitBinary('SHA512withECDSA',
    TX9ObjectIdentifiers.ECDsaWithSha512);
end;

procedure TTestDSA.TestNONEwithDSA;
var
  dummySha1, sigBytes: TBytes;
  rand: ISecureRandom;
  pGen: IDsaParametersGenerator;
  G: IAsymmetricCipherKeyPairGenerator;
  kp: IAsymmetricCipherKeyPair;
  sig: ISigner;
  signer: IDSASigner;
  RS: TCryptoLibGenericArray<TBigInteger>;
begin
  dummySha1 := DecodeHex('01020304050607080910111213141516');

  rand := TSecureRandom.Create();

  pGen := TDsaParametersGenerator.Create();
  pGen.Init(512, 80, rand);

  G := TGeneratorUtilities.GetKeyPairGenerator('DSA');
  G.Init(TDSAKeyGenerationParameters.Create(rand, pGen.GenerateParameters())
    as IDSAKeyGenerationParameters);

  kp := G.GenerateKeyPair();

  sig := TSignerUtilities.GetSigner('NONEwithDSA');
  sig.Init(true, kp.Private);
  sig.BlockUpdate(dummySha1, 0, System.Length(dummySha1));
  sigBytes := sig.GenerateSignature();

  sig.Init(false, kp.Public);
  sig.BlockUpdate(dummySha1, 0, System.Length(dummySha1));
  sig.VerifySignature(sigBytes);

  // reset test

  sig.BlockUpdate(dummySha1, 0, System.Length(dummySha1));

  if (not(sig.VerifySignature(sigBytes))) then
  begin
    Fail('NONEwithDSA failed to reset');
  end;

  // lightweight test
  signer := TDSASigner.Create();
  signer.Init(false, kp.Public);
  RS := DoDerDecode(sigBytes);

  if (not(signer.VerifySignature(dummySha1, RS[0], RS[1]))) then
  begin
    Fail('NONEwithDSA not really NONE!');
  end;
end;

procedure TTestDSA.TestNONEwithECDSA239bitPrime;
var
  &message, sig: TBytes;
  curve: IECCurve;
  spec: IECDomainParameters;
  priKey: IECPrivateKeyParameters;
  pubKey: IECPublicKeyParameters;
  sgr: ISigner;
begin

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
    (DecodeHex
    ('020ffa963cdca8816ccc33b8642bedf905c3d358573d3f27fbbd3b3cb9aaaf')), // G
    TBigInteger.Create
    ('883423532389192164791648750360308884807550341691627752275345424702807307')
    ); // n

  priKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create
    ('876300101507107567501066130761671078357010671067781776716671676178726717'),
    // d
    spec);

  pubKey := TECPublicKeyParameters.Create('ECDSA',
    curve.DecodePoint
    (DecodeHex
    ('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')), // Q
    spec);

  sgr := TSignerUtilities.GetSigner('NONEwithECDSA');

  &message := TConverters.ConvertStringToBytes('abc', TEncoding.UTF8);
  sig := DecodeHex
    ('3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e64cb19604be06c57e761b3de5518f71de0f6e0cd2df677cec8a6ffcb690d');

  DoCheckMessage(sgr, priKey, pubKey, &message, sig);

  &message := TConverters.ConvertStringToBytes('abcdefghijklmnopqrstuvwxyz',
    TEncoding.UTF8);
  sig := DecodeHex
    ('3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e43fd65b3363d76aabef8630572257dbb67c82818ad9fad31256539b1b02c');

  DoCheckMessage(sgr, priKey, pubKey, &message, sig);

  &message := TConverters.ConvertStringToBytes
    ('a very very long message gauranteed to cause an overflow',
    TEncoding.UTF8);
  sig := DecodeHex
    ('3040021e2cb7f36803ebb9c427c58d8265f11fc5084747133078fc279de874fbecb0021e7d5be84b22937a1691859a3c6fe45ed30b108574431d01b34025825ec17a');

  DoCheckMessage(sgr, priKey, pubKey, &message, sig);

end;

procedure TTestDSA.TestParameters;
var
  random: ISecureRandom;
  a: IDsaParametersGenerator;
  p: IDSAParameters;
  encodeParams, encodeParams_2, data, sigBytes: TBytes;
  dsaP: IDsaParameter;
  p2: IDSAParameters;
  G: IAsymmetricCipherKeyPairGenerator;
  pair: IAsymmetricCipherKeyPair;
  sKey, vKey: IAsymmetricKeyParameter;
  s: ISigner;
begin
  random := TFixedSecureRandom.From
    (TCryptoLibMatrixByteArray.Create
    (DecodeHex('d5014e4b60ef2ba8b6211b4062ba3224e0427dd3'),
    DecodeHex(
    '345e8d05c075c3a508df729a1685690e68fcfb8c8117847e89063bca1f85d968fd281540b6e13bd1af989a1fbf17e06462bf511f9d0b140fb48ac1b1baa5bded'))
    );

  a := TDsaParametersGenerator.Create();
  a.Init(512, 20, random);

  p := a.GenerateParameters();

  encodeParams := TDsaParameter.Create(p.p, p.Q, p.G).GetDerEncoded();

  dsaP := TDsaParameter.GetInstance(TAsn1Object.FromByteArray(encodeParams)
    as TAsn1Object);
  p2 := TDSAParameters.Create(dsaP.p, dsaP.Q, dsaP.G);

  // a and a2 should be equivalent!
  encodeParams_2 := TDsaParameter.Create(p2.p, p2.Q, p2.G).GetDerEncoded();

  if (not AreEqual(encodeParams, encodeParams_2)) then
  begin
    Fail('encode/Decode parameters failed');
  end;

  G := TGeneratorUtilities.GetKeyPairGenerator('DSA');

  G.Init(TDSAKeyGenerationParameters.Create(TSecureRandom.Create()
    as ISecureRandom, p) as IDSAKeyGenerationParameters);

  pair := G.GenerateKeyPair();

  sKey := pair.Private;
  vKey := pair.Public;

  s := TSignerUtilities.GetSigner('DSA');
  data := TBytes.Create(1, 2, 3, 4, 5, 6, 7, 8, 9, 0);

  s.Init(true, sKey);

  s.BlockUpdate(data, 0, System.Length(data));

  sigBytes := s.GenerateSignature();

  s := TSignerUtilities.GetSigner('DSA');

  s.Init(false, vKey);

  s.BlockUpdate(data, 0, System.Length(data));

  if (not(s.VerifySignature(sigBytes))) then
  begin
    Fail('dsa verification failed');
  end;
end;

{ TDSATestSecureRandom }

constructor TDSATestSecureRandom.Create(const value: TBytes);
begin
  Inherited Create(System.Copy(value));
  Ffirst := true;
end;

procedure TDSATestSecureRandom.NextBytes(const bytes: TBytes);
begin
  if (Ffirst) then
  begin
    Inherited NextBytes(bytes);
    Ffirst := false;
  end
  else
  begin
    bytes[System.Length(bytes) - 1] := 2;
  end;

end;

initialization

// Register any test cases with the test runner

{$IFDEF FPC}
  RegisterTest(TTestDSA);
{$ELSE}
  RegisterTest(TTestDSA.Suite);
{$ENDIF FPC}

end.
