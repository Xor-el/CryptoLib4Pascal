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

unit CertTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
  Classes,
  Rtti,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAsn1Core,
  ClpBigInteger,
  ClpIECCommon,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpIX509Certificate,
  ClpX509CertificateParser,
  ClpIX509CertificateParser,
  ClpX509CrlParser,
  ClpIX509CrlParser,
  ClpIX509Crl,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpDsaParameters,
  ClpIDsaParameters,
  ClpDsaGenerators,
  ClpIDsaGenerators,
  ClpIAsymmetricKeyParameter,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpAsymmetricCipherKeyPair,
  ClpAsymmetricKeyParameter,
  ClpSubjectPublicKeyInfoFactory,
  ClpGeneratorUtilities,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpX509ExtensionUtilities,
  ClpIX509CrlEntry,
  ClpIAsn1Objects,
  ClpIAsn1Core,
  ClpAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Comparers,
  ClpIX509NameBuilder,
  ClpX509NameBuilder,
  ClpCmsObjectIdentifiers,
  ClpCmsAsn1Objects,
  ClpICmsAsn1Objects,
  ClpX509Extension,
  ClpEncoders,
  ClpX9ObjectIdentifiers,
  ClpECNamedCurveTable,
  ClpIX9ECAsn1Objects,
  ClpECParameters,
  ClpIECParameters,
  ClpDateTimeHelper,
  ClpConverters,
  CryptoLibTestBase,
  CertVectors,
  CryptoTestKeys;

type

  TDudPublicKey = class(TAsymmetricKeyParameter)
  public
    constructor Create;
  end;

  TCertTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRsaPublic: IRsaKeyParameters;
    FRsaPrivate: IRsaPrivateCrtKeyParameters;
    FSecureRandom: ISecureRandom;

    procedure SetUpKeys;
    function CreateX509Name: IX509Name;
    function GenerateLongFixedKeys: IAsymmetricCipherKeyPair;
    procedure CheckCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckKeyUsage(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckSelfSignedCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckNameCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
    procedure CheckCrl(AId: Int32; const ACrlBytes: TCryptoLibByteArray);
    procedure CheckCertificateCriticalExtendedKeyUsage;
    procedure CheckCreation1;
    procedure CheckCreation2;
    procedure CheckCreation3;
    procedure CheckCreation5;
    procedure CheckCrlCreation1;
    procedure CheckCrlCreation2;
    procedure CheckCrlCreation3;
    procedure PemTest;
    procedure DoTestForgedSignature;
    procedure DoTestNullDerNullCert;
    procedure PemFileTest;
    procedure PemFileTestWithNl;
    procedure PemNoTrailingNewlineTest;
    procedure InvalidCrls;
    procedure Pkcs7Test;
    procedure CreatePssCert(const AAlgorithm: string);
    procedure CreateECCert(const AAlgorithm: string; const AAlgOid: IDerObjectIdentifier);

  protected
    procedure SetUp; override;

  published
  procedure TestX509NameBuilderMatchesRegular;
    procedure TestKeyUsage;
    procedure TestSelfSignedUncompressedPtEC;
    procedure TestNameCert;
    procedure TestSelfSignedProbSelfSignedCert;
    procedure TestCrl1;
    procedure TestEmptyDNCert;
    procedure TestCertificateCriticalExtendedKeyUsage;
    procedure TestCreation1;
    procedure TestCreation2;
    procedure TestCreation3;
    procedure TestCreation5;
    procedure TestCrlCreation1;
    procedure TestCrlCreation2;
    procedure TestCrlCreation3;
    procedure TestPem;
    procedure TestDoTestForgedSignature;
    procedure TestDoTestNullDerNullCert;
    procedure TestPemFileTest;
    procedure TestPemFileTestWithNl;
    procedure TestPemNoTrailingNewline;
    procedure TestInvalidCrls;
    procedure TestPkcs7Test;
    procedure TestCmsMalformedContentRejectedCleanly;
    procedure TestCmsOversizedDeclaredLengthRejected;
    procedure TestCreatePssCertSha1;
    procedure TestCreatePssCertSha224;
    procedure TestCreatePssCertSha256;
    procedure TestCreatePssCertSha384;
    procedure TestCreateECCertSha1;
    procedure TestCreateECCertSha224;
    procedure TestCreateECCertSha256;
    procedure TestCreateECCertSha384;
    procedure TestCreateECCertSha512;

  end;

implementation

{ TDudPublicKey }

constructor TDudPublicKey.Create;
begin
  inherited Create(False);
end;

{ TCertTest }

function TCertTest.GenerateLongFixedKeys: IAsymmetricCipherKeyPair;
var
  LPubMod, LPubExp: TBigInteger;
  LPrivMod, LPrivExp, LPrivP, LPrivQ, LPrivDP, LPrivDQ, LPrivQinv: TBigInteger;
  LPub: IRsaKeyParameters;
  LPriv: IRsaPrivateCrtKeyParameters;
begin
  LPubMod := TBigInteger.Create(
    'a56e4a0e701017589a5187dc7ea841d156f2ec0e36ad52a44dfeb1e61f7ad991d8c51056ffedb162b4c0f283a12a88a394dff526ab7291cbb307ceabfce0b1dfd5cd9508096d5b2b8b6df5d671ef6377c0921cb23c270a70e2598e6ff89d19f105acc2d3f0cb35f29280e1386b6f64c4ef22e1e1f20d0ce8cffb2249bd9a213' + '7', 16);
  LPubExp := TBigInteger.Create('010001', 16);
  LPrivMod := LPubMod;
  LPrivExp := TBigInteger.Create(
    '33a5042a90b27d4f5451ca9bbbd0b44771a101af884340aef9885f2a4bbe92e894a724ac3c568c8f97853ad07c0266c8c6a3ca0929f1e8f11231884429fc4d9ae55fee896a10ce707c3ed7e734e44727a39574501a532683109c2abacaba283c31b4bd2f53c3ee37e352cee34f9e503bd80c0622ad79c6dcee883547c6a3b32' + '5', 16);
  LPrivP := TBigInteger.Create('e7e8942720a877517273a356053ea2a1bc0c94aa72d55c6e86296b2dfc967948c0a72cbccca7eacb35706e09a1df55a1535bd9b3cc34160b3b6dcd3eda8e6443', 16);
  LPrivQ := TBigInteger.Create('b69dca1cf7d4d7ec81e75b90fcca874abcde123fd2700180aa90479b6e48de8d67ed24f9f19d85ba275874f542cd20dc723e6963364a1f9425452b269a6799fd', 16);
  LPrivDP := TBigInteger.Create('28fa13938655be1f8a159cbaca5a72ea190c30089e19cd274a556f36c4f6e19f554b34c077790427bbdd8dd3ede2448328f385d81b30e8e43b2fffa027861979', 16);
  LPrivDQ := TBigInteger.Create('1a8b38f398fa712049898d7fb79ee0a77668791299cdfa09efc0e507acb21ed74301ef5bfd48be455eaeb6e1678255827580a8e4e8e14151d1510a82a3f2e729', 16);
  LPrivQinv := TBigInteger.Create('27156aba4126d24a81f3a528cbfb27f56886f840a9f6e86e17a44b94fe9319584b8e22fdde1e5a2e3bd8aa5ba8d8584194eb2190acf832b847f13a3d24a79f4d', 16);
  LPub := TRsaKeyParameters.Create(False, LPubMod, LPubExp);
  LPriv := TRsaPrivateCrtKeyParameters.Create(LPrivMod, LPubExp, LPrivExp, LPrivP, LPrivQ, LPrivDP, LPrivDQ, LPrivQinv);
  Result := TAsymmetricCipherKeyPair.Create(LPub, LPriv);
end;

procedure TCertTest.SetUpKeys;
begin
  FRsaPublic := TCryptoTestKeys.GetWriterRsaCrtPublic;
  FRsaPrivate := TCryptoTestKeys.GetWriterRsaCrtPrivate;
end;

function TCertTest.CreateX509Name: IX509Name;
var
  LAttrs: TDictionary<IDerObjectIdentifier, String>;
  LOrd: TList<IDerObjectIdentifier>;
begin
  LAttrs := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  LOrd := TList<IDerObjectIdentifier>.Create;
  try
    LAttrs.Add(TX509Name.C, 'NG');
    LAttrs.Add(TX509Name.O, 'CryptoLib4Pascal');
    LAttrs.Add(TX509Name.L, 'Alausa');
    LAttrs.Add(TX509Name.ST, 'Lagos');
    LAttrs.Add(TX509Name.E, 'feedback-crypto@cryptolib4pascal.org');

    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    Result := TX509Name.Create(LOrd, LAttrs);
  finally
    LAttrs.Free;
    LOrd.Free;
  end;
end;

procedure TCertTest.CheckCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LPublicKey: IAsymmetricKeyParameter;
begin
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(ACertBytes);
    if LCert = nil then
      Fail(Format('CertTest: %d failed - null certificate', [AId]));
    LPublicKey := LCert.GetPublicKey();
  except
    on E: Exception do
      Fail(Format('CertTest: %d failed - exception %s', [AId, E.Message]));
  end;
end;

procedure TCertTest.CheckKeyUsage(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LKeyUsage: TCryptoLibBooleanArray;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertBytes);
  if LCert = nil then
    Fail(Format('CertTest: %d failed - null certificate', [AId]));
  LCert.GetPublicKey();
  LKeyUsage := LCert.GetKeyUsage();
  if (LKeyUsage <> nil) and (System.Length(LKeyUsage) > 7) and LKeyUsage[7] then
    Fail('error generating cert - key usage wrong.');
end;

procedure TCertTest.CheckSelfSignedCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertBytes);
  if LCert = nil then
    Fail(Format('CertTest: %d failed - null certificate', [AId]));
  LCert.Verify(LCert.GetPublicKey());
end;

procedure TCertTest.CheckNameCertificate(AId: Int32; const ACertBytes: TCryptoLibByteArray);
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LExpected: String;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(ACertBytes);
  if LCert = nil then
    Fail(Format('CertTest: %d failed - null certificate', [AId]));
  LCert.GetPublicKey();
  LExpected := 'C=DE,O=DATEV eG,0.2.262.1.10.7.20=1+CN=CA DATEV D03 1:PN';
  if LCert.IssuerDN.ToString <> LExpected then
    Fail(Format('CertTest: %d failed - name test', [AId]));
end;

procedure TCertTest.CheckCrl(AId: Int32; const ACrlBytes: TCryptoLibByteArray);
var
  LParser: IX509CrlParser;
  LCrl: IX509Crl;
begin
  LParser := TX509CrlParser.Create;
  LCrl := LParser.ReadCrl(ACrlBytes);
  if LCrl = nil then
    Fail(Format('CertTest CRL: %d failed - null CRL', [AId]));
end;

procedure TCertTest.SetUp;
begin
  inherited SetUp;
  FSecureRandom := TSecureRandom.Create;
  if FRsaPublic = nil then
    SetUpKeys;
end;

procedure TCertTest.TestX509NameBuilderMatchesRegular;
var
  LRegular: IX509Name;
  LBuilder: IX509NameBuilder;
  LViaBuilder: IX509Name;
begin
  LRegular := CreateX509Name;
  LBuilder := TX509NameBuilder.Create;
  LViaBuilder := LBuilder
    .AddCountry('NG')
    .AddOrganization('CryptoLib4Pascal')
    .AddLocality('Alausa')
    .AddState('Lagos')
    .AddEmailAddress('feedback-crypto@cryptolib4pascal.org')
    .Build();
  if not LRegular.Equivalent(LViaBuilder, True) then
    Fail('X509Name from builder did not match regular creation (Equivalent)');
  if LRegular.ToString <> LViaBuilder.ToString then
    Fail('X509Name from builder did not match regular creation (ToString)');
end;

procedure TCertTest.TestKeyUsage;
begin
  CheckKeyUsage(8, TCertVectors.LoadDer('KeyUsageEntrustClient'));
end;

procedure TCertTest.TestSelfSignedUncompressedPtEC;
begin
  CheckSelfSignedCertificate(9, TCertVectors.LoadDer('SelfSignedEcUncompressedPt'));
end;

procedure TCertTest.TestNameCert;
begin
  CheckNameCertificate(10, TCertVectors.LoadDer('NameCertDatev'));
end;

procedure TCertTest.TestSelfSignedProbSelfSignedCert;
begin
  CheckSelfSignedCertificate(11, TCertVectors.LoadDer('ProbSelfSignedCert'));
end;

procedure TCertTest.TestCrl1;
begin
  CheckCrl(1, TCertVectors.LoadDer('Crl1'));
end;

procedure TCertTest.TestEmptyDNCert;
begin
  CheckCertificate(18, TCertVectors.LoadDer('EmptyDnCert'));
end;

procedure TCertTest.TestCertificateCriticalExtendedKeyUsage;
begin
  CheckCertificateCriticalExtendedKeyUsage;
end;

// RFC 5280 section 4.2.1.12: extendedKeyUsage may be critical; assert OID listing and parsed usages.
procedure TCertTest.CheckCertificateCriticalExtendedKeyUsage;
var
  LParser: IX509CertificateParser;
  LCert: IX509Certificate;
  LCritical: TCryptoLibStringArray;
  LEku: TCryptoLibGenericArray<IDerObjectIdentifier>;
  I: Int32;
  LEkuOid: String;
  LFound: Boolean;
begin
  try
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(TCertVectors.LoadDer('CriticalExtendedKeyUsage'));
    if LCert = nil then
      Fail('critical extendedKeyUsage cert: null certificate');

    LEkuOid := TX509Extensions.ExtendedKeyUsage.ID;
    LCritical := LCert.GetCriticalExtensionOids;
    if LCritical = nil then
      Fail('EKU not in critical OIDs');

    LFound := False;
    for I := 0 to System.High(LCritical) do
      if LCritical[I] = LEkuOid then
      begin
        LFound := True;
        Break;
      end;

    if not LFound then
      Fail('EKU not in critical OIDs');

    LEku := LCert.GetExtendedKeyUsage;
    if (LEku = nil) or (System.Length(LEku) < 1) then
      Fail('extended key usage empty after parse');
  except
    on E: Exception do
      Fail('critical extendedKeyUsage cert: ' + E.Message);
  end;
end;

procedure TCertTest.CheckCreation1;
var
  LCertGen: IX509V3CertificateGenerator;
  LCertGen1: IX509V1CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LDummySet: TCryptoLibStringArray;
  LParser: IX509CertificateParser;
  LKeyUsage: TCryptoLibBooleanArray;
  LEkus: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LSanExt: IGeneralNames;
  LGns: TCryptoLibGenericArray<IGeneralName>;
  LAsn1Str: IAsn1String;
  LAltNames: TCryptoLibGenericArray<TCryptoLibGenericArray<TValue>>;
  I: Int32;
  LUtc: TDateTime;
begin
  LName := CreateX509Name;
  LUtc := Now.ToUniversalTime();

  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FRsaPublic);

  LSigner := TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(FRsaPublic);

  LDummySet := LCert.GetNonCriticalExtensionOids();
  if LDummySet <> nil then
    Fail('non-critical oid set should be null');
  LDummySet := LCert.GetCriticalExtensionOids();
  if LDummySet <> nil then
    Fail('critical oid set should be null');

  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FRsaPublic);
  LCertGen.AddExtension('2.5.29.15', True, TKeyUsage.Create(TKeyUsage.EncipherOnly) as IKeyUsage);
  LCertGen.AddExtension(TX509Extensions.ExtendedKeyUsage.ID, True, TDerSequence.Create(TKeyPurposeId.AnyExtendedKeyUsage) as IDerSequence);
  LCertGen.AddExtension('2.5.29.17', True, TGeneralNames.Create(TGeneralName.Create(TGeneralName.Rfc822Name, 'test@test.test') as IGeneralName) as IGeneralNames);

  LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(FRsaPublic);

  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(LCert.GetEncoded());

  LKeyUsage := LCert.GetKeyUsage();
  if (LKeyUsage = nil) or (System.Length(LKeyUsage) <= 7) or (not LKeyUsage[7]) then
    Fail('error generating cert - key usage wrong.');

  LEkus := LCert.GetExtendedKeyUsage();
  if (LEkus = nil) or (System.Length(LEkus) < 1) or (not TKeyPurposeId.AnyExtendedKeyUsage.Equals(LEkus[0])) then
    Fail('failed extended key usage test');

  LSanExt := LCert.GetSubjectAlternativeNameExtension();
  if LSanExt <> nil then
  begin
    LGns := LSanExt.GetNames();
    for I := 0 to System.High(LGns) do
    begin
      if LGns[I].TagNo <> TGeneralName.Rfc822Name then
        Fail('failed subject alternative name extension test');
      if not Supports(LGns[I].Name, IAsn1String, LAsn1Str) then
        Fail('failed subject alternative name extension test');
      if LAsn1Str.GetString() <> 'test@test.test' then
        Fail('failed subject alternative name extension test');
    end;
  end;

  LAltNames := LCert.GetSubjectAlternativeNames();
  if LAltNames <> nil then
    for I := 0 to System.High(LAltNames) do
      if (System.Length(LAltNames[I]) < 2) or (LAltNames[I][0].AsInteger <> TGeneralName.Rfc822Name) or (LAltNames[I][1].AsString <> 'test@test.test') then
        Fail('failed subject alternative names test');

  LCertGen1 := TX509V1CertificateGenerator.Create;
  LCertGen1.SetSerialNumber(TBigInteger.One);
  LCertGen1.SetIssuerDN(LName);
  LCertGen1.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen1.SetNotAfterUtc(IncMonth(LUtc, 6));
  LCertGen1.SetSubjectDN(LName);
  LCertGen1.SetPublicKey(FRsaPublic);

  LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen1.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(FRsaPublic);

  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(LCert.GetEncoded());
  if not LCert.IssuerDN.Equivalent(LCert.SubjectDN, True) then
    Fail('name comparison fails');
end;

procedure TCertTest.CheckCreation2;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LDpg: IDsaParametersGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LDpg := TDsaParametersGenerator.Create;
  LDpg.Init(512, 25, FSecureRandom);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('DSA');
  LKpg.Init(TDsaKeyGenerationParameters.Create(FSecureRandom, LDpg.GenerateParameters) as IDsaKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();

  LName := CreateX509Name;

  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(LKp.Public);

  LSigner := TAsn1SignatureFactory.Create('SHA1WITHDSA', LKp.Private, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity(LUtc);
  LCert.Verify(LKp.Public);
end;

procedure TCertTest.CheckCreation3;
var
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LSpec: IECDomainParameters;
  LPrivKey: IECPrivateKeyParameters;
  LPubKey: IECPublicKeyParameters;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LName: IX509Name;
  LS: String;
  LCertGen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
  LParser: IX509CertificateParser;
  LUtc: TDateTime;
  LQ: IECPoint;
  LPr: IX509Name;
begin
  LX9 := TECNamedCurveTable.GetByName('prime239v1');
  if LX9 = nil then
    Fail('prime239v1 curve not available (X962 named curves not found)');

  LCurve := LX9.Curve;
  LSpec := TECDomainParameters.FromX9ECParameters(LX9);

  LPrivKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create('876300101507107567501066130761671078357010671067781776716671676178726717'),
    LSpec);

  LPubKey := TECPublicKeyParameters.Create('ECDSA',
    LCurve.DecodePoint(THexEncoder.Decode('025b6dc53bc61a2548ffb0f671472de6c9521a9d2d2534e65abfcbd5fe0c70')),
    LSpec);

  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');

    LName := TX509Name.Create(LOrd, LValues);
    LS := LName.ToString();
    if LS <> 'C=NG,O=CryptoLib4Pascal,L=Alausa,ST=Lagos,E=feedback-crypto@cryptolib4pascal.org' then
      Fail('ordered X509Principal test failed - s = ' + LS + '.');

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LUtc := Now.ToUniversalTime();
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);

    try
      LCert := LCertGen.Generate(TAsn1SignatureFactory.Create('SHA1withECDSA', LPrivKey, nil) as ISignatureFactory);

      LCert.CheckValidity(LUtc);
      LCert.Verify(LPubKey);

      LParser := TX509CertificateParser.Create;
      LCert := LParser.ReadCertificate(LCert.GetEncoded());

      LQ := LPubKey.q.Normalize();
      LPubKey := TECPublicKeyParameters.Create(LPubKey.AlgorithmName,
        LCurve.CreatePoint(LQ.XCoord.ToBigInteger(), LQ.YCoord.ToBigInteger()),
        LPubKey.Parameters);

      LCertGen.SetPublicKey(LPubKey);
      LCert := LCertGen.Generate(TAsn1SignatureFactory.Create('SHA1withECDSA', LPrivKey, nil) as ISignatureFactory);

      LCert.CheckValidity(LUtc);
      LCert.Verify(LPubKey);

      LParser := TX509CertificateParser.Create;
      LCert := LParser.ReadCertificate(LCert.GetEncoded());
    except
      on E: Exception do
        Fail('error setting generating cert - ' + E.ClassName + ': ' + E.Message);
    end;

    LPr := TX509Name.Create('O="CryptoLib4Pascal, Demo",E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG');
    if LPr.ToString() <> 'O=CryptoLib4Pascal\, Demo,E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG' then
      Fail('string based X509Principal test failed.');

    LPr := TX509Name.Create('O=CryptoLib4Pascal\, Demo,E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG');
    if LPr.ToString() <> 'O=CryptoLib4Pascal\, Demo,E=feedback-crypto@cryptolib4pascal.org,ST=Lagos,L=Alausa,C=NG' then
      Fail('string based X509Principal test failed.');
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.CheckCreation5;
var
  LPubKey: IRsaKeyParameters;
  LPrivKey: IRsaPrivateCrtKeyParameters;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LBaseCert, LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LOid1, LOid2: IDerObjectIdentifier;
  LBaseVal, LCertVal: IAsn1OctetString;
  LDudKey: IAsymmetricKeyParameter;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LPubKey := TCryptoTestKeys.GetWriterRsaCrtPublic;
  LPrivKey := TCryptoTestKeys.GetWriterRsaCrtPrivate;

  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);
    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');
    LName := TX509Name.Create(LOrd, LValues);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);
    LCertGen.AddExtension('2.5.29.15', True, TKeyUsage.Create(TKeyUsage.EncipherOnly) as IKeyUsage);
    LCertGen.AddExtension(TX509Extensions.ExtendedKeyUsage.ID, True, TDerSequence.Create(TKeyPurposeId.AnyExtendedKeyUsage) as IDerSequence);
    LCertGen.AddExtension('2.5.29.17', True, TGeneralNames.Create(TGeneralName.Create(TGeneralName.Rfc822Name, 'test@test.test') as IGeneralName) as IGeneralNames);

    LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', LPrivKey, nil);
    LBaseCert := LCertGen.Generate(LSigner);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);
    LCertGen.CopyAndAddExtension(TDerObjectIdentifier.Create('2.5.29.15') as IDerObjectIdentifier, True, LBaseCert);
    LCertGen.CopyAndAddExtension(TX509Extensions.ExtendedKeyUsage, False, LBaseCert);

    LCert := LCertGen.Generate(LSigner);

    LCert.CheckValidity(LUtc);
    LCert.Verify(LPubKey);

    LOid1 := TDerObjectIdentifier.Create('2.5.29.15');
    LBaseVal := LBaseCert.CertificateStructure.Extensions.GetExtensionValue(LOid1);
    LCertVal := LCert.CertificateStructure.Extensions.GetExtensionValue(LOid1);
    if (LBaseVal = nil) <> (LCertVal = nil) then
      Fail('2.5.29.15 differs');
    if (LBaseVal <> nil) and (not AreEqual(LBaseVal.GetEncoded(), LCertVal.GetEncoded())) then
      Fail('2.5.29.15 differs');

    LOid2 := TX509Extensions.ExtendedKeyUsage;
    LBaseVal := LBaseCert.GetExtensionValue(LOid2);
    LCertVal := LCert.GetExtensionValue(LOid2);
    if (LBaseVal = nil) <> (LCertVal = nil) then
      Fail('2.5.29.37 differs');
    if (LBaseVal <> nil) and (not AreEqual(LBaseVal.GetEncoded(), LCertVal.GetEncoded())) then
      Fail('2.5.29.37 differs');

    { Exception test: same LCertGen - CopyAndAddExtension(unknown OID) raises "not present" }
    try
      LCertGen.CopyAndAddExtension(TDerObjectIdentifier.Create('2.5.99.99') as IDerObjectIdentifier, True, LBaseCert);
      Fail('exception not thrown on dud extension copy');
    except
      on E: EArgumentCryptoLibException do
        ; { expected }
    end;

    { Dud key test: same LCertGen, set dud key and Generate }
    LDudKey := TDudPublicKey.Create as IAsymmetricKeyParameter;
    try
      LCertGen.SetPublicKey(LDudKey);
      LCertGen.Generate(LSigner);
      Fail('key without encoding not detected in v3');
    except
      on E: EArgumentCryptoLibException do
        ; { expected }
    end;
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.CheckCrlCreation1;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCrlGen: IX509V2CrlGenerator;
  LCrl: IX509Crl;
  LEntry: IX509CrlEntry;
  LAuthKeyID: IAuthorityKeyIdentifier;
  LExt: IAsn1OctetString;
  LReasonCode: IDerEnumerated;
  LReason: ICrlReason;
  LRsaParams: IRsaKeyGenerationParameters;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LRsaParams := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001), FSecureRandom, 768, 25);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(LRsaParams);
  LKp := LKpg.GenerateKeyPair();

  LCrlGen := TX509V2CrlGenerator.Create;
  LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
  LCrlGen.SetThisUpdateUtc(LUtc);
  LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));
  LCrlGen.AddCrlEntryUtc(TBigInteger.One, LUtc, TCrlReason.PrivilegeWithdrawn);
  LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));

  LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

  if not LCrl.IssuerDN.Equivalent(TX509Name.Create('CN=Test CA') as IX509Name, True) then
    Fail('failed CRL issuer test');

  LAuthKeyID := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(LCrl.CertificateList.Extensions);
  if LAuthKeyID = nil then
    Fail('failed to find CRL extension');

  LEntry := LCrl.GetRevokedCertificate(TBigInteger.One);
  if LEntry = nil then
    Fail('failed to find CRL entry');

  if not LEntry.SerialNumber.Equals(TBigInteger.One) then
    Fail('CRL cert serial number does not match');

  if not LEntry.HasExtensions then
    Fail('CRL entry extension not found');

  LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
  if LExt <> nil then
  begin
    LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
    LReason := TCrlReason.Create(LReasonCode);
    if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
      Fail('CRL entry reasonCode wrong');
  end
  else
    Fail('CRL entry reasonCode not found');
end;

procedure TCertTest.CheckCrlCreation2;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCrlGen: IX509V2CrlGenerator;
  LCrl: IX509Crl;
  LEntry: IX509CrlEntry;
  LAuthKeyID: IAuthorityKeyIdentifier;
  LExt: IAsn1OctetString;
  LReasonCode: IDerEnumerated;
  LReason: ICrlReason;
  LRsaParams: IRsaKeyGenerationParameters;
  LExtOids: TList<IDerObjectIdentifier>;
  LExtValues: TList<IX509Extension>;
  LEntryExts: IX509Extensions;
  LCrlReason: ICrlReason;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LRsaParams := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001), FSecureRandom, 768, 25);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(LRsaParams);
  LKp := LKpg.GenerateKeyPair();

  LCrlGen := TX509V2CrlGenerator.Create;
  LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
  LCrlGen.SetThisUpdateUtc(LUtc);
  LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));

  LExtOids := TList<IDerObjectIdentifier>.Create;
  LExtValues := TList<IX509Extension>.Create;
  try
    LCrlReason := TCrlReason.Create(TCrlReason.PrivilegeWithdrawn);
    LExtOids.Add(TX509Extensions.ReasonCode);
    LExtValues.Add(TX509Extension.Create(False, TDerOctetString.Create(LCrlReason.GetEncoded()) as IDerOctetString) as IX509Extension);
    LEntryExts := TX509Extensions.Create(LExtOids, LExtValues);

    LCrlGen.AddCrlEntryUtc(TBigInteger.One, LUtc, LEntryExts);
    LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
      TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));

    LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

    if not LCrl.IssuerDN.Equivalent(TX509Name.Create('CN=Test CA') as IX509Name, True) then
      Fail('failed CRL issuer test');

    LAuthKeyID := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(LCrl.CertificateList.Extensions);
    if LAuthKeyID = nil then
      Fail('failed to find CRL extension');

    LEntry := LCrl.GetRevokedCertificate(TBigInteger.One);
    if LEntry = nil then
      Fail('failed to find CRL entry');

    if not LEntry.SerialNumber.Equals(TBigInteger.One) then
      Fail('CRL cert serial number does not match');

    if not LEntry.HasExtensions then
      Fail('CRL entry extension not found');

    LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
    if LExt <> nil then
    begin
      LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
      LReason := TCrlReason.Create(LReasonCode);
      if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
        Fail('CRL entry reasonCode wrong');
    end
    else
      Fail('CRL entry reasonCode not found');
  finally
    LExtOids.Free;
    LExtValues.Free;
  end;
end;

procedure TCertTest.CheckCrlCreation3;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LCrlGen: IX509V2CrlGenerator;
  LCrl, LNewCrl, LReadCrl: IX509Crl;
  LCrlParser: IX509CrlParser;
  LEntry: IX509CrlEntry;
  LExtOids: TList<IDerObjectIdentifier>;
  LExtValues: TList<IX509Extension>;
  LEntryExts: IX509Extensions;
  LCrlReason: ICrlReason;
  LRevoked: TCryptoLibGenericArray<IX509CrlEntry>;
  LExt: IAsn1OctetString;
  LReasonCode: IDerEnumerated;
  LReason: ICrlReason;
  LAuthKeyId: IAuthorityKeyIdentifier;
  LCol: TCryptoLibGenericArray<IX509Crl>;
  I: Int32;
  LCount: Int32;
  LOneFound, LTwoFound: Boolean;
  LUtc: TDateTime;
begin
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf($10001), FSecureRandom, 768, 25) as IRsaKeyGenerationParameters);
  LUtc := Now.ToUniversalTime();
  LKp := LKpg.GenerateKeyPair();

  LExtOids := TList<IDerObjectIdentifier>.Create;
  LExtValues := TList<IX509Extension>.Create;
  try
    LCrlReason := TCrlReason.Create(TCrlReason.PrivilegeWithdrawn);
    LExtOids.Add(TX509Extensions.ReasonCode);
    LExtValues.Add(TX509Extension.Create(False, TDerOctetString.Create(LCrlReason.GetEncoded()) as IDerOctetString) as IX509Extension);
    LEntryExts := TX509Extensions.Create(LExtOids, LExtValues);

    LCrlGen := TX509V2CrlGenerator.Create;
    LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
    LCrlGen.SetThisUpdateUtc(LUtc);
    LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));
    LCrlGen.AddCrlEntryUtc(TBigInteger.One, LUtc, LEntryExts);
    LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
      TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));
    LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

    if not LCrl.IssuerDN.Equivalent(TX509Name.Create('CN=Test CA') as IX509Name, True) then
      Fail('failed CRL issuer test');

    LAuthKeyId := TX509ExtensionUtilities.GetAuthorityKeyIdentifier(LCrl.GetCertificateList.Extensions);
    if LAuthKeyId = nil then
      Fail('failed to find CRL extension');

    LEntry := LCrl.GetRevokedCertificate(TBigInteger.One);
    if LEntry = nil then
      Fail('failed to find CRL entry');

    if not LEntry.SerialNumber.Equals(TBigInteger.One) then
      Fail('CRL cert serial number does not match');

    if not LEntry.HasExtensions then
      Fail('CRL entry extension not found');

    LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
    if LExt = nil then
      Fail('CRL entry reasonCode not found');
    LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
    LReason := TCrlReason.Create(LReasonCode);
    if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
      Fail('CRL entry reasonCode wrong');

    LUtc := Now.ToUniversalTime();
    LCrlGen := TX509V2CrlGenerator.Create;
    LCrlGen.SetIssuerDN(TX509Name.Create('CN=Test CA') as IX509Name);
    LCrlGen.SetThisUpdateUtc(LUtc);
    LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 100));
    LCrlGen.AddCrl(LCrl);
    LCrlGen.AddCrlEntryUtc(TBigInteger.Two, LUtc, LEntryExts);
    LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
      TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LKp.Public)));
    LNewCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create('SHA256WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

    LCount := 0;
    LOneFound := False;
    LTwoFound := False;
    LRevoked := LNewCrl.GetRevokedCertificates();
    if LRevoked <> nil then
      for I := 0 to System.High(LRevoked) do
      begin
        if LRevoked[I].SerialNumber.Equals(TBigInteger.One) then
        begin
          LOneFound := True;
          LExt := LEntry.GetExtensionValue(TX509Extensions.ReasonCode);
          if LExt = nil then
            Fail('CRL entry reasonCode not found');
          LReasonCode := TX509ExtensionUtilities.FromExtensionValue(LExt) as IDerEnumerated;
          LReason := TCrlReason.Create(LReasonCode);
          if not LReason.HasValue(TCrlReason.PrivilegeWithdrawn) then
            Fail('CRL entry reasonCode wrong');
        end
        else if LRevoked[I].SerialNumber.Equals(TBigInteger.Two) then
          LTwoFound := True;
        Inc(LCount);
      end;

    if LCount <> 2 then
      Fail('wrong number of CRLs found');

    if not (LOneFound and LTwoFound) then
      Fail('wrong CRLs found in copied list');

    LCrlParser := TX509CrlParser.Create;
    LReadCrl := LCrlParser.ReadCrl(LNewCrl.GetEncoded());
    if LReadCrl = nil then
      Fail('crl not returned!');

    LCol := LCrlParser.ReadCrls(LNewCrl.GetEncoded());
    if Length(LCol) <> 1 then
      Fail('wrong number of CRLs found in collection');
  finally
    LExtOids.Free;
    LExtValues.Free;
  end;
end;

procedure TCertTest.PemTest;
var
  LParser: IX509CertificateParser;
  LCrlParser: IX509CrlParser;
  LCert: IX509Certificate;
  LCrl: IX509Crl;
  LCertList: TCryptoLibGenericArray<IX509Certificate>;
  LCrlList: TCryptoLibGenericArray<IX509Crl>;
begin
  LParser := TX509CertificateParser.Create;
  LCert := LParser.ReadCertificate(TConverters.ConvertStringToBytes(
    TCertVectors.LoadPemString('Connect4ServerX509Armor'), TEncoding.ASCII));
  if LCert = nil then
    Fail('PEM cert not read');

  LCert := LParser.ReadCertificate(TConverters.ConvertStringToBytes(
    '-----BEGIN CERTIFICATE-----' + TCertVectors.LoadPemString('Connect4Server'), TEncoding.ASCII));
  if LCert = nil then
    Fail('PEM cert with extraneous header not read');

  LCrlParser := TX509CrlParser.Create;
  LCrl := LCrlParser.ReadCrl(TConverters.ConvertStringToBytes(
    TCertVectors.LoadPemString('Crl1'), TEncoding.ASCII));
  if LCrl = nil then
    Fail('PEM crl not read');

  LCertList := LParser.ReadCertificates(TConverters.ConvertStringToBytes(
    TCertVectors.LoadPemString('Connect4Server'), TEncoding.ASCII));
  if (System.Length(LCertList) <> 1) or (not AreEqual(LCert.GetEncoded(), LCertList[0].GetEncoded())) then
    Fail('PEM cert collection not right');

  LCrlList := LCrlParser.ReadCrls(TConverters.ConvertStringToBytes(
    TCertVectors.LoadPemString('Crl2'), TEncoding.ASCII));
  if (System.Length(LCrlList) <> 1) or (not AreEqual(LCrl.GetEncoded(), LCrlList[0].GetEncoded())) then
    Fail('PEM crl collection not right');
end;

procedure TCertTest.DoTestForgedSignature;
var
  LParser: IX509CertificateParser;
  LX509: IX509Certificate;
begin
  LParser := TX509CertificateParser.Create;
  LX509 := LParser.ReadCertificate(TCertVectors.LoadDer('ForgedRsa512'));
  try
    LX509.Verify(LX509.GetPublicKey());
    Fail('forged RSA signature passed');
  except
    { expected }
  end;
end;

procedure TCertTest.DoTestNullDerNullCert;
var
  LKp: IAsymmetricCipherKeyPair;
  LCertGen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
  LCertStruct: IX509CertificateStructure;
  LTbs: IAsn1Encodable;
  LSigAlg: IAlgorithmIdentifier;
  LSeq: IAsn1Sequence;
  LEncoded: TCryptoLibByteArray;
  LParser: IX509CertificateParser;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LKp := GenerateLongFixedKeys();
  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(TX509Name.Create('CN=Test') as IX509Name);
  LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
  LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
  LCertGen.SetSubjectDN(TX509Name.Create('CN=Test') as IX509Name);
  LCertGen.SetPublicKey(LKp.Public);
  LCert := LCertGen.Generate(TAsn1SignatureFactory.Create('MD5WithRSAEncryption', LKp.Private, nil) as ISignatureFactory);

  LCertStruct := TX509CertificateStructure.GetInstance(TAsn1Object.FromByteArray(LCert.GetEncoded()));
  LTbs := LCertStruct.TbsCertificate;
  LSigAlg := LCertStruct.SignatureAlgorithm;
  LSeq := TDerSequence.Create([LTbs, TAlgorithmIdentifier.Create(LSigAlg.Algorithm) as IAlgorithmIdentifier, LCertStruct.Signature]);
  try
    LEncoded := LSeq.GetEncoded();
    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(LEncoded);
    LCert.Verify(LCert.GetPublicKey());
  except
    on E: Exception do
      Fail('doTestNullDerNull failed - exception ' + E.ClassName + ': ' + E.Message);
  end;
end;

procedure TCertTest.PemFileTest;
var
  LFact: IX509CertificateParser;
  LCerts1: TCryptoLibGenericArray<IX509Certificate>;
  LStream: TStringStream;
  LC: IX509Certificate;
  I, J: Int32;
  LSet2: TList<IX509Certificate>;
  LEnc: TCryptoLibByteArray;
  LMatched: array of Boolean;
  LFound: Boolean;
begin
  LFact := TX509CertificateParser.Create;
  LStream := TStringStream.Create(TCertVectors.LoadPemString('CertChainCrlf'), TEncoding.ASCII);
  try
    LCerts1 := LFact.ReadCertificates(LStream);
    if System.Length(LCerts1) <> 2 then
      Fail('certs wrong <cr><nl>');
  finally
    LStream.Free;
  end;

  LStream := TStringStream.Create(TCertVectors.LoadPemString('CertChainCrlf'), TEncoding.ASCII);
  try
    LSet2 := TList<IX509Certificate>.Create;
    try
      repeat
        LC := LFact.ReadCertificate(LStream);
        if LC <> nil then
          LSet2.Add(LC);
      until LC = nil;
      if System.Length(LCerts1) <> LSet2.Count then
        Fail('certs size <cr><nl>');
      SetLength(LMatched, System.Length(LCerts1));
      for I := 0 to System.High(LMatched) do
        LMatched[I] := False;
      for J := 0 to LSet2.Count - 1 do
      begin
        LEnc := LSet2[J].GetEncoded();
        LFound := False;
        for I := 0 to System.High(LCerts1) do
          if (not LMatched[I]) and AreEqual(LCerts1[I].GetEncoded(), LEnc) then
          begin
            LMatched[I] := True;
            LFound := True;
            Break;
          end;
        if not LFound then
          Fail('collection not empty');
      end;
      for I := 0 to System.High(LMatched) do
        if not LMatched[I] then
          Fail('collection not empty');
    finally
      LSet2.Free;
    end;
  finally
    LStream.Free;
  end;
end;

procedure TCertTest.InvalidCrls;
var
  LCrlParser: IX509CrlParser;
  LCrls: TCryptoLibGenericArray<IX509Crl>;
  LCrl: IX509Crl;
  LStream: TStringStream;
begin
  LCrlParser := TX509CrlParser.Create;
  LStream := TStringStream.Create(TCertVectors.LoadPemString('CertChainCrlf'), TEncoding.ASCII);
  try
    LCrls := LCrlParser.ReadCrls(LStream);
    if System.Length(LCrls) <> 0 then
      Fail('multi crl');
  finally
    LStream.Free;
  end;
  LStream := TStringStream.Create(TCertVectors.LoadPemString('CertChainCrlf'), TEncoding.ASCII);
  try
    LCrl := LCrlParser.ReadCrl(LStream);
    if LCrl <> nil then
      Fail('single crl');
  finally
    LStream.Free;
  end;

  // thisUpdate/nextUpdate are 13-character UTCTime-shaped values tagged as GeneralizedTime
  // ("240123000000Z" reads as year 2401, month 23 - out of range), so the CRL must fail to parse.
  try
    LCrlParser.ReadCrl(TCertVectors.LoadDer('MalformedGeneralizedTimeCrl'));
    Fail('malformed GeneralizedTime CRL - no exception');
  except
    on E: ECrlCryptoLibException do
    begin
      if not E.Message.Contains('invalid GeneralizedTime format') then
        Fail('Wrong exception message: ' + E.Message);
    end
    else
      raise;
  end;
end;

procedure TCertTest.PemFileTestWithNl;
var
  LFact: IX509CertificateParser;
  LCerts1: TCryptoLibGenericArray<IX509Certificate>;
  LStream: TStringStream;
  LC: IX509Certificate;
  I, J: Int32;
  LSet2: TList<IX509Certificate>;
  LEnc: TCryptoLibByteArray;
  LMatched: array of Boolean;
  LFound: Boolean;
begin
  LFact := TX509CertificateParser.Create;
  LStream := TStringStream.Create(TCertVectors.LoadPemString('CertChainNl'), TEncoding.ASCII);
  try
    LCerts1 := LFact.ReadCertificates(LStream);
    if System.Length(LCerts1) <> 2 then
      Fail('certs wrong <nl>');
  finally
    LStream.Free;
  end;

  LStream := TStringStream.Create(TCertVectors.LoadPemString('CertChainNl'), TEncoding.ASCII);
  try
    LSet2 := TList<IX509Certificate>.Create;
    try
      repeat
        LC := LFact.ReadCertificate(LStream);
        if LC <> nil then
          LSet2.Add(LC);
      until LC = nil;
      if System.Length(LCerts1) <> LSet2.Count then
        Fail('certs size <nl>');
      SetLength(LMatched, System.Length(LCerts1));
      for I := 0 to System.High(LMatched) do
        LMatched[I] := False;
      for J := 0 to LSet2.Count - 1 do
      begin
        LEnc := LSet2[J].GetEncoded();
        LFound := False;
        for I := 0 to System.High(LCerts1) do
          if (not LMatched[I]) and AreEqual(LCerts1[I].GetEncoded(), LEnc) then
          begin
            LMatched[I] := True;
            LFound := True;
            Break;
          end;
        if not LFound then
          Fail('collection not empty');
      end;
      for I := 0 to System.High(LMatched) do
        if not LMatched[I] then
          Fail('collection not empty');
    finally
      LSet2.Free;
    end;
  finally
    LStream.Free;
  end;
end;

// Regression test: PEM input that ends immediately after the
// '-----END CERTIFICATE-----' footer, with no trailing CR or LF.
// Earlier ReadLine logic discarded any buffered characters when EOF
// was reached, so the footer line was silently dropped and
// ReadPemObject would fail to detect it, returning nil.
procedure TCertTest.PemNoTrailingNewlineTest;
var
  LParser: IX509CertificateParser;
  LCert, LCertRef: IX509Certificate;
begin
  LParser := TX509CertificateParser.Create;

  LCert := LParser.ReadCertificate(TConverters.ConvertStringToBytes(
    TCertVectors.LoadPemString('Connect4ServerNoTrailingNl'), TEncoding.ASCII));
  if LCert = nil then
    Fail('PEM cert without trailing newline not read');

  // Cross-check: parsing the same payload with a trailing newline must
  // produce a byte-identical certificate. This guards against a partial
  // or truncated decode that happens to return non-nil.
  LCertRef := LParser.ReadCertificate(TConverters.ConvertStringToBytes(
    TCertVectors.LoadPemString('Connect4Server'), TEncoding.ASCII));
  if LCertRef = nil then
    Fail('PEM cert reference (with trailing newline) not read');

  if not AreEqual(LCert.GetEncoded(), LCertRef.GetEncoded()) then
    Fail('PEM cert without trailing newline decoded differently from reference');
end;

procedure TCertTest.Pkcs7Test;
var
  LRootCertBin, LRootCrlBin, LAttrCert: TCryptoLibByteArray;
  LContentInfo: ICmsContentInfo;
  LSigData: ICmsSignedData;
  LCertSet, LCrlSet: IAsn1Set;
  LTaggedAttr: IAsn1Encodable;
  LInfoEnc: TCryptoLibByteArray;
  LCertParser: IX509CertificateParser;
  LCrlParser: IX509CrlParser;
  LCert: IX509Certificate;
  LCrl: IX509Crl;
  LCertList: TCryptoLibGenericArray<IX509Certificate>;
  LCrlList: TCryptoLibGenericArray<IX509Crl>;
  LCrlProblemBin: TCryptoLibByteArray;
  LRootCertObj, LRootCrlObj: IAsn1Encodable;
begin
  LRootCertBin := TCertVectors.LoadDer('Pkcs7RootCert');
  LRootCrlBin := TCertVectors.LoadDer('Pkcs7RootCrl');
  LAttrCert := TCertVectors.LoadDer('Pkcs7AttrCert');

  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.Data, nil);
  LRootCertObj := TAsn1Object.FromByteArray(LRootCertBin);
  LTaggedAttr := TDerTaggedObject.Create(False, 2, TAsn1Object.FromByteArray(LAttrCert));
  LCertSet := TDerSet.Create([LRootCertObj, LTaggedAttr]);
  LRootCrlObj := TAsn1Object.FromByteArray(LRootCrlBin);
  LCrlSet := TDerSet.Create(LRootCrlObj);
  LSigData := TCmsSignedData.Create(
    TDerSet.Empty,
    LContentInfo,
    LCertSet,
    LCrlSet,
    TDerSet.Empty);
  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.SignedData, LSigData);
  LInfoEnc := LContentInfo.GetEncoded();

  LCertParser := TX509CertificateParser.Create;
  LCrlParser := TX509CrlParser.Create;

  LCert := LCertParser.ReadCertificate(LInfoEnc);
  if (LCert = nil) or (not AreEqual(LCert.GetEncoded(), LRootCertBin)) then
    Fail('PKCS7 cert not read');

  LCrl := LCrlParser.ReadCrl(LInfoEnc);
  if (LCrl = nil) or (not AreEqual(LCrl.GetEncoded(), LRootCrlBin)) then
    Fail('PKCS7 crl not read');

  LCertList := LCertParser.ReadCertificates(LInfoEnc);
  if (System.Length(LCertList) <> 1) or (not AreEqual(LCertList[0].GetEncoded(), LRootCertBin)) then
    Fail('PKCS7 cert collection not right');

  LCrlList := LCrlParser.ReadCrls(LInfoEnc);
  if (System.Length(LCrlList) <> 1) or (not AreEqual(LCrlList[0].GetEncoded(), LRootCrlBin)) then
    Fail('PKCS7 crl collection not right');

  { empty certs and crls }
  LSigData := TCmsSignedData.Create(TDerSet.Empty, LContentInfo, TDerSet.Empty, TDerSet.Empty, TDerSet.Empty);
  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.SignedData, LSigData);
  LInfoEnc := LContentInfo.GetEncoded();
  LCert := LCertParser.ReadCertificate(LInfoEnc);
  if LCert <> nil then
    Fail('PKCS7 cert present');
  LCrl := LCrlParser.ReadCrl(LInfoEnc);
  if LCrl <> nil then
    Fail('PKCS7 crl present');

  { absent certs and crls - use nil for optional }
  LSigData := TCmsSignedData.Create(TDerSet.Empty, TCmsContentInfo.Create(TCmsObjectIdentifiers.Data, nil) as ICmsContentInfo, nil, nil, TDerSet.Empty);
  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.SignedData, LSigData);
  LInfoEnc := LContentInfo.GetEncoded();
  LCert := LCertParser.ReadCertificate(LInfoEnc);
  if LCert <> nil then
    Fail('PKCS7 cert present');
  LCrl := LCrlParser.ReadCrl(LInfoEnc);
  if LCrl <> nil then
    Fail('PKCS7 crl present');

  { sample message: pkcs7CrlProblem - expect 4 certs, 0 CRLs }
  LCrlProblemBin := TCertVectors.LoadDer('Pkcs7CrlProblem');
  LCertList := LCertParser.ReadCertificates(LCrlProblemBin);
  LCrlList := LCrlParser.ReadCrls(LCrlProblemBin);
  if System.Length(LCrlList) <> 0 then
    Fail(Format('wrong number of CRLs: %d', [System.Length(LCrlList)]));
  if System.Length(LCertList) <> 4 then
    Fail(Format('wrong number of Certs: %d', [System.Length(LCertList)]));
end;

procedure TCertTest.CreatePssCert(const AAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LName: IX509Name;
  LCertGen: IX509V3CertificateGenerator;
  LBaseCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LKp := GenerateLongFixedKeys();
  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');

    LName := TX509Name.Create(LOrd, LValues);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LKp.Public);
    LCertGen.AddExtension('2.5.29.15', True, TKeyUsage.Create(TKeyUsage.EncipherOnly) as IKeyUsage);
    LCertGen.AddExtension(TX509Extensions.ExtendedKeyUsage.ID, True, TDerSequence.Create(TKeyPurposeId.AnyExtendedKeyUsage) as IDerSequence);
    LCertGen.AddExtension('2.5.29.17', True, TGeneralNames.Create(TGeneralName.Create(TGeneralName.Rfc822Name, 'test@test.test') as IGeneralName) as IGeneralNames);

    LSigner := TAsn1SignatureFactory.Create(AAlgorithm, LKp.Private, nil);
    LBaseCert := LCertGen.Generate(LSigner);

    LBaseCert.Verify(LKp.Public);
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.CreateECCert(const AAlgorithm: string; const AAlgOid: IDerObjectIdentifier);
var
  LX9: IX9ECParameters;
  LCurve: IECCurve;
  LSpec: IECDomainParameters;
  LPrivKey: IECPrivateKeyParameters;
  LPubKey: IECPublicKeyParameters;
  LOrd: TList<IDerObjectIdentifier>;
  LValues: TList<String>;
  LName: IX509Name;
  LCertGen: IX509V3CertificateGenerator;
  LCert: IX509Certificate;
  LParser: IX509CertificateParser;
  LUtc: TDateTime;
  LQ: IECPoint;
begin
  LX9 := TECNamedCurveTable.GetByName('secp521r1');
  LCurve := LX9.Curve;
  LSpec := TECDomainParameters.FromX9ECParameters(LX9);

  LPrivKey := TECPrivateKeyParameters.Create('ECDSA',
    TBigInteger.Create('5769183828869504557786041598510887460263120754767955773309066354712783118202294874205844512909370791582896372147797293913785865682804434049019366394746072023'),
    LSpec);

  LPubKey := TECPublicKeyParameters.Create('ECDSA',
    LCurve.DecodePoint(THexEncoder.Decode('02006BFDD2C9278B63C92D6624F151C9D7A822CC75BD983B17D25D74C26740380022D3D8FAF304781E416175EADF4ED6E2B47142D2454A7AC7801DD803CF44A4D1F0AC')),
    LSpec);

  LOrd := TList<IDerObjectIdentifier>.Create;
  LValues := TList<String>.Create;
  try
    LOrd.Add(TX509Name.C);
    LOrd.Add(TX509Name.O);
    LOrd.Add(TX509Name.L);
    LOrd.Add(TX509Name.ST);
    LOrd.Add(TX509Name.E);

    LValues.Add('NG');
    LValues.Add('CryptoLib4Pascal');
    LValues.Add('Alausa');
    LValues.Add('Lagos');
    LValues.Add('feedback-crypto@cryptolib4pascal.org');

    LName := TX509Name.Create(LOrd, LValues);

    LCertGen := TX509V3CertificateGenerator.Create;
    LCertGen.SetSerialNumber(TBigInteger.One);
    LCertGen.SetIssuerDN(LName);
    LUtc := Now.ToUniversalTime();
    LCertGen.SetNotBeforeUtc(IncSecond(LUtc, -50));
    LCertGen.SetNotAfterUtc(IncMonth(LUtc, 6));
    LCertGen.SetSubjectDN(LName);
    LCertGen.SetPublicKey(LPubKey);

    LCert := LCertGen.Generate(TAsn1SignatureFactory.Create(AAlgorithm, LPrivKey, nil) as ISignatureFactory);

    LCert.CheckValidity(LUtc);
    LCert.Verify(LPubKey);

    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(LCert.GetEncoded());

    LQ := LPubKey.q.Normalize();
    LPubKey := TECPublicKeyParameters.Create(LPubKey.AlgorithmName,
      LCurve.CreatePoint(LQ.XCoord.ToBigInteger(), LQ.YCoord.ToBigInteger()),
      LPubKey.Parameters);

    LCertGen.SetPublicKey(LPubKey);
    LCert := LCertGen.Generate(TAsn1SignatureFactory.Create(AAlgorithm, LPrivKey, nil) as ISignatureFactory);

    LCert.CheckValidity(LUtc);
    LCert.Verify(LPubKey);

    LParser := TX509CertificateParser.Create;
    LCert := LParser.ReadCertificate(LCert.GetEncoded());

    if LCert.GetSigAlgOid <> AAlgOid.Id then
      Fail('ECDSA oid incorrect.');

    if LCert.GetSigAlgParams <> nil then
      Fail('sig parameters present');
  finally
    LOrd.Free;
    LValues.Free;
  end;
end;

procedure TCertTest.TestCreation1;
begin
  CheckCreation1;
end;

procedure TCertTest.TestCreation2;
begin
  CheckCreation2;
end;

procedure TCertTest.TestCreation3;
begin
  CheckCreation3;
end;

procedure TCertTest.TestCreation5;
begin
  CheckCreation5;
end;

procedure TCertTest.TestCrlCreation1;
begin
  CheckCrlCreation1;
end;

procedure TCertTest.TestCrlCreation2;
begin
  CheckCrlCreation2;
end;

procedure TCertTest.TestCrlCreation3;
begin
  CheckCrlCreation3;
end;

procedure TCertTest.TestPem;
begin
  PemTest;
end;

procedure TCertTest.TestDoTestForgedSignature;
begin
  DoTestForgedSignature;
end;

procedure TCertTest.TestDoTestNullDerNullCert;
begin
  DoTestNullDerNullCert;
end;

procedure TCertTest.TestPemFileTest;
begin
  PemFileTest;
end;

procedure TCertTest.TestPemFileTestWithNl;
begin
  PemFileTestWithNl;
end;

procedure TCertTest.TestPemNoTrailingNewline;
begin
  PemNoTrailingNewlineTest;
end;

procedure TCertTest.TestInvalidCrls;
begin
  InvalidCrls;
end;

procedure TCertTest.TestPkcs7Test;
begin
  Pkcs7Test;
end;

procedure TCertTest.TestCmsMalformedContentRejectedCleanly;
var
  LContentInfo: ICmsContentInfo;
  LEmpty: TCryptoLibByteArray;
begin
  // Empty input and content-less ContentInfo must be rejected with a declared exception,
  // not an access violation on the next field access.
  LEmpty := nil;
  try
    TCmsContentInfo.GetInstance(LEmpty);
    Fail('expected EArgumentCryptoLibException for empty CMS input');
  except
    on E: EArgumentCryptoLibException do
      CheckEquals('No content found.', E.Message);
  else
    raise;
  end;

  LContentInfo := TCmsContentInfo.Create(TCmsObjectIdentifiers.SignedData, nil);
  try
    TCmsSignedData.FromContentInfo(LContentInfo);
    Fail('expected EArgumentCryptoLibException for content-less SignedData');
  except
    on E: EArgumentCryptoLibException do
      CheckEquals('Malformed content.', E.Message);
  else
    raise;
  end;
end;

procedure TCertTest.TestCmsOversizedDeclaredLengthRejected;
var
  LTiny: TCryptoLibByteArray;
begin
  // A tiny input declaring an enormous definite length must be rejected at the length bound
  // before allocating the declared size — not allocated then truncated at EOF.
  LTiny := THexEncoder.Decode('3084000F4240010203');
  try
    TCmsContentInfo.GetInstance(LTiny);
    Fail('expected length-bound rejection');
  except
    on E: Exception do
      CheckTrue(Pos('out of bounds length found', E.Message) > 0,
        'expected length-bound rejection, got: ' + E.Message);
  end;
end;

procedure TCertTest.TestCreatePssCertSha1;
begin
  CreatePssCert('SHA1withRSAandMGF1');
end;

procedure TCertTest.TestCreatePssCertSha224;
begin
  CreatePssCert('SHA224withRSAandMGF1');
end;

procedure TCertTest.TestCreatePssCertSha256;
begin
  CreatePssCert('SHA256withRSAandMGF1');
end;

procedure TCertTest.TestCreatePssCertSha384;
begin
  CreatePssCert('SHA384withRSAandMGF1');
end;

procedure TCertTest.TestCreateECCertSha1;
begin
  CreateECCert('SHA1withECDSA', TX9ObjectIdentifiers.ECDsaWithSha1);
end;

procedure TCertTest.TestCreateECCertSha224;
begin
  CreateECCert('SHA224withECDSA', TX9ObjectIdentifiers.ECDsaWithSha224);
end;

procedure TCertTest.TestCreateECCertSha256;
begin
  CreateECCert('SHA256withECDSA', TX9ObjectIdentifiers.ECDsaWithSha256);
end;

procedure TCertTest.TestCreateECCertSha384;
begin
  CreateECCert('SHA384withECDSA', TX9ObjectIdentifiers.ECDsaWithSha384);
end;

procedure TCertTest.TestCreateECCertSha512;
begin
  CreateECCert('SHA512withECDSA', TX9ObjectIdentifiers.ECDsaWithSha512);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TCertTest);
{$ELSE}
  RegisterTest(TCertTest.Suite);
{$ENDIF FPC}

end.
