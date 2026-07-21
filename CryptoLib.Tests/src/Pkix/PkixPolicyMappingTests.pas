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

unit PkixPolicyMappingTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIStore,
  ClpCollectionStore,
  ClpIX509StoreSelectors,
  ClpX509StoreSelectors,
  ClpIPkixTypes,
  ClpTrustAnchor,
  ClpPkixBuilderParameters,
  ClpPkixCertPathBuilder,
  ClpBigInteger,
  ClpAsn1Objects,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpIX509Certificate,
  ClpIRsaParameters,
  ClpDateTimeHelper,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions,
  ClpCryptoLibConfig,
  TestKeyBuilders,
  CryptoTestKeys,
  CryptoLibTestBase;

type

  /// <summary>
  /// Policy mapping processing of RFC 5280 6.1.3 (a)(4) and 6.1.4 (a)(b), driven through the
  /// certification path builder over a freshly generated three certificate chain.
  /// </summary>
  /// <remarks>
  /// The intermediate maps one issuer domain policy onto another, and each case names a different
  /// set of acceptable initial policies. The valid policy tree either survives the mapping or the
  /// path is rejected on policy.
  /// </remarks>
  TPkixPolicyMappingTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  const
    AnyPolicyOid = '2.5.29.32.0';
    TestPolicyOid1 = '2.16.840.1.101.3.2.1.48.1';
    TestPolicyOid2 = '2.16.840.1.101.3.2.1.48.2';
    TestPolicyOid3 = '2.16.840.1.101.3.2.1.48.3';

    TrustDN = 'C=JP, O=policyMappingAdditionalTest, OU=trustAnchor';
    IntermediateDN = 'C=JP, O=policyMappingAdditionalTest, OU=intmedCA';
    EndEntityDN = 'C=JP, O=policyMappingAdditionalTest, OU=endEntity';
    EndEntityIssuerDN = 'C=JP, O=policyMappingAdditionalTest, OU=intMedCA';

  var
    FCaPublic: IRsaKeyParameters;
    FCaPrivate: IRsaPrivateCrtKeyParameters;
    FIntPublic: IRsaKeyParameters;
    FIntPrivate: IRsaPrivateCrtKeyParameters;
    FEndPublic: IRsaKeyParameters;
    FTrustCert: IX509Certificate;

    class function PolicySequence(const AOids: array of String): IAsn1Encodable; static;
    class function MappingSequence(const AIssuerDomainPolicy,
      ASubjectDomainPolicy: String): IAsn1Encodable; static;

    function CreateTrustCert: IX509Certificate;
    function CreateIntermediateCert(const APolicies, APolicyMap: IAsn1Encodable): IX509Certificate;
    function CreateEndEntityCert(const APolicies: IAsn1Encodable): IX509Certificate;

    /// <summary>Builds a path to AEndCert and asserts the accept or reject outcome.</summary>
    procedure CheckPolicies(AIndex: Int32; const AIntCert, AEndCert: IX509Certificate;
      const ARequirePolicies: TCryptoLibStringArray; AExpectOk: Boolean);

    /// <summary>The chain shared by most cases: anyPolicy at the intermediate, mapping 1 -> 2.</summary>
    procedure BuildMappedChain(const AIntPolicies: array of String;
      const AEndPolicy: String; out AIntCert, AEndCert: IX509Certificate);

  protected
    procedure SetUp; override;
    procedure TearDown; override;

  published
    procedure TestMappedPolicyWithoutInitialPolicies;
    procedure TestMappedPolicyWithIssuerDomainPolicy;
    procedure TestMappedPolicyWithAnyPolicy;
    procedure TestMappedPolicyWithExtraIntermediatePolicy;
    procedure TestUnmappedPolicyAcceptedDirectly;
    procedure TestSubjectDomainPolicyIsNotAcceptable;
    procedure TestIssuerDomainPolicyAtEndEntity;
    procedure TestUnrelatedInitialPolicyRejected;
    procedure TestUnrelatedEndEntityPolicyRejected;
    procedure TestPolicyTreeNodeCapRejectsChain;
    procedure TestPolicyTreeNodeCapRejectsNonPositive;

  end;

implementation

{ TPkixPolicyMappingTest }

class function TPkixPolicyMappingTest.PolicySequence(const AOids: array of String): IAsn1Encodable;
var
  LItems: TCryptoLibGenericArray<IAsn1Encodable>;
  LIdx: Int32;
begin
  System.SetLength(LItems, System.Length(AOids));
  for LIdx := 0 to System.High(AOids) do
  begin
    LItems[LIdx] := TPolicyInformation.Create(TDerObjectIdentifier.Create(AOids[LIdx])
      as IDerObjectIdentifier) as IAsn1Encodable;
  end;
  Result := TDerSequence.FromElements(LItems) as IAsn1Encodable;
end;

class function TPkixPolicyMappingTest.MappingSequence(const AIssuerDomainPolicy,
  ASubjectDomainPolicy: String): IAsn1Encodable;
var
  LMapping: IAsn1Encodable;
begin
  // PolicyMappings ::= SEQUENCE OF SEQUENCE { issuerDomainPolicy, subjectDomainPolicy }
  LMapping := TDerSequence.FromElements(TDerObjectIdentifier.Create(AIssuerDomainPolicy)
    as IAsn1Encodable, TDerObjectIdentifier.Create(ASubjectDomainPolicy) as IAsn1Encodable)
    as IAsn1Encodable;
  Result := TDerSequence.FromElements(TCryptoLibGenericArray<IAsn1Encodable>.Create(LMapping))
    as IAsn1Encodable;
end;

procedure TPkixPolicyMappingTest.TearDown;
begin
  // the ceiling is process-wide, so leaving it set would change every test that runs after this one
  TCryptoLibConfig.X509.ResetToDefaults();
  inherited TearDown;
end;

procedure TPkixPolicyMappingTest.SetUp;
const
  IntKey: TRsaCrtHexRecord = (Modulus:
    '8de0d113c5e736969c8d2b047a243f8fe18edad64cde9e842d3669230ca486f7' +
    'cfdde1f8eec54d1905fff04acc85e61093e180cadc6cea407f193d44bb0e9449' +
    'b8dbb49784cd9e36260c39e06a947299978c6ed8300724e887198cfede20f3fb' +
    'de658fa2bd078be946a392bd349f2b49c486e20c405588e306706c9017308e69';
    PubExp: 'ffff'; PrivExp:
    '7deb1b194a85bcfd29cf871411468adbc987650903e3bacc8338c449ca7b32ef' +
    'd39ffc33bc84412fcd7df18d23ce9d7c25ea910b1ae9985373e0273b4dca7f2e' +
    '0db3b7314056ac67fd277f8f89cf2fd73c34c6ca69f9ba477143d2b0e2445548' +
    'aa0b4a8473095182631da46844c356f5e5c7522eb54b5a33f11d730ead9c0cff';
    P: 'ef4cede573cea47f83699b814de4302edb60eefe426c52e17bd7870ec7c6b7a2' +
    '4fe55282ebb73775f369157726fcfb988def2b40350bdca9e5b418340288f649';
    Q: '97c7737d1b9a0088c3c7b528539247fd2a1593e7e01cef18848755be82f4a45a' +
    'a093276cb0cbf118cb41117540a78f3fc471ba5d69f0042274defc9161265721';
    DP: '6c641094e24d172728b8da3c2777e69adfd0839085be7e38c7c4a2dd00b1ae96' +
    '9f2ec9d23e7e37090fcd449a40af0ed463fe1c612d6810d6b4f58b7bfa31eb5f';
    DQ: '70b7123e8e69dfa76feb1236d0a686144b00e9232ed52b73847e74ef3af71fb4' +
    '5ccb24261f40d27f98101e230cf27b977a5d5f1f15f6cf48d5cb1da2a3a3b87f';
    QInv: 'e38f5750d97e270996a286df2e653fd26c242106436f5bab0f4c7a9e654ce026' +
    '65d5a281f2c412456f2d1fa26586ef04a9adac9004ca7f913162cb28e13bf40d');

  CaKey: TRsaCrtHexRecord = (Modulus:
    'b259d2d6e627a768c94be36164c2d9fc79d97aab9253140e5bf17751197731d6' +
    'f7540d2509e7b9ffee0a70a6e26d56e92d2edd7f85aba85600b69089f35f6bdb' +
    'f3c298e05842535d9f064e6b0391cb7d306e0a2d20c4dfb4e7b49a9640bdea26' +
    'c10ad69c3f05007ce2513cee44cfe01998e62b6c3637d3fc0391079b26ee36d5';
    PubExp: '11'; PrivExp:
    '92e08f83cc9920746989ca5034dcb384a094fb9c5a6288fcc4304424ab8f5638' +
    '8f72652d8fafc65a4b9020896f2cde297080f2a540e7b7ce5af0b3446e1258d1' +
    'dd7f245cf54124b4c6e17da21b90a0ebd22605e6f45c9f136d7a13eaac1c0f74' +
    '87de8bd6d924972408ebb58af71e76fd7b012a8d0e165f3ae2e5077a8648e619';
    P: 'f75e80839b9b9379f1cf1128f321639757dba514642c206bbbd99f9a4846208b' +
    '3e93fbbe5e0527cc59b1d4b929d9555853004c7c8b30ee6a213c3d1bb7415d03';
    Q: 'b892d9ebdbfc37e397256dd8a5d3123534d1f03726284743ddc6be3a709edb69' +
    '6fc40c7d902ed804c6eee730eee3d5b20bf6bd8d87a296813c87d3b3cc9d7947';
    DP: '1d1a2d3ca8e52068b3094d501c9a842fec37f54db16e9a67070a8b3f53cc03d4' +
    '257ad252a1a640eadd603724d7bf3737914b544ae332eedf4f34436cac25ceb5';
    DQ: '6c929e4e81672fef49d9c825163fec97c4b7ba7acb26c0824638ac22605d7201' +
    'c94625770984f78a56e6e25904fe7db407099cad9b14588841b94f5ab498dded';
    QInv: 'dae7651ee69ad1d081ec5e7188ae126f6004ff39556bde90e0b870962fa7b926' +
    'd070686d8244fe5a9aa709a95686a104614834b0ada4b10f53197a5cb4c97339');
begin
  inherited SetUp;

  FCaPublic := TTestKeyBuilders.CreateRsaPublicFromHexRecord(CaKey);
  FCaPrivate := TTestKeyBuilders.CreateRsaPrivateCrtFromHexRecord(CaKey);
  FIntPublic := TTestKeyBuilders.CreateRsaPublicFromHexRecord(IntKey);
  FIntPrivate := TTestKeyBuilders.CreateRsaPrivateCrtFromHexRecord(IntKey);
  FEndPublic := TCryptoTestKeys.GetWriterRsaCrtPublic;

  FTrustCert := CreateTrustCert();
end;

function TPkixPolicyMappingTest.CreateTrustCert: IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LGen := TX509V3CertificateGenerator.Create;
  LGen.SetSerialNumber(TBigInteger.Ten);
  LGen.SetIssuerDN(TX509Name.Create(TrustDN) as IX509Name);
  LGen.SetNotBeforeUtc(IncDay(LUtc, -30));
  LGen.SetNotAfterUtc(IncDay(LUtc, 30));
  LGen.SetSubjectDN(TX509Name.Create(TrustDN) as IX509Name);
  LGen.SetPublicKey(FCaPublic);
  Result := LGen.Generate(TAsn1SignatureFactory.Create('SHA1WithRSAEncryption', FCaPrivate, nil)
    as ISignatureFactory);
end;

function TPkixPolicyMappingTest.CreateIntermediateCert(const APolicies,
  APolicyMap: IAsn1Encodable): IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LGen := TX509V3CertificateGenerator.Create;
  LGen.SetSerialNumber(TBigInteger.ValueOf(20));
  LGen.SetIssuerDN(TX509Name.Create(TrustDN) as IX509Name);
  LGen.SetNotBeforeUtc(IncDay(LUtc, -30));
  LGen.SetNotAfterUtc(IncDay(LUtc, 30));
  LGen.SetSubjectDN(TX509Name.Create(IntermediateDN) as IX509Name);
  LGen.SetPublicKey(FIntPublic);
  LGen.AddExtension(TX509Extensions.CertificatePolicies, True, APolicies);
  LGen.AddExtension(TX509Extensions.BasicConstraints, True,
    TBasicConstraints.Create(True) as IAsn1Encodable);
  LGen.AddExtension(TX509Extensions.PolicyMappings, True, APolicyMap);
  Result := LGen.Generate(TAsn1SignatureFactory.Create('SHA1WithRSAEncryption', FCaPrivate, nil)
    as ISignatureFactory);
end;

function TPkixPolicyMappingTest.CreateEndEntityCert(const APolicies: IAsn1Encodable)
  : IX509Certificate;
var
  LGen: IX509V3CertificateGenerator;
  LUtc: TDateTime;
begin
  LUtc := Now.ToUniversalTime();
  LGen := TX509V3CertificateGenerator.Create;
  LGen.SetSerialNumber(TBigInteger.ValueOf(20));
  LGen.SetIssuerDN(TX509Name.Create(EndEntityIssuerDN) as IX509Name);
  LGen.SetNotBeforeUtc(IncDay(LUtc, -30));
  LGen.SetNotAfterUtc(IncDay(LUtc, 30));
  LGen.SetSubjectDN(TX509Name.Create(EndEntityDN) as IX509Name);
  LGen.SetPublicKey(FEndPublic);
  LGen.AddExtension(TX509Extensions.CertificatePolicies, True, APolicies);
  Result := LGen.Generate(TAsn1SignatureFactory.Create('SHA1WithRSAEncryption', FIntPrivate, nil)
    as ISignatureFactory);
end;

procedure TPkixPolicyMappingTest.BuildMappedChain(const AIntPolicies: array of String;
  const AEndPolicy: String; out AIntCert, AEndCert: IX509Certificate);
begin
  AIntCert := CreateIntermediateCert(PolicySequence(AIntPolicies),
    MappingSequence(TestPolicyOid1, TestPolicyOid2));
  AEndCert := CreateEndEntityCert(PolicySequence([AEndPolicy]));
end;

procedure TPkixPolicyMappingTest.CheckPolicies(AIndex: Int32; const AIntCert,
  AEndCert: IX509Certificate; const ARequirePolicies: TCryptoLibStringArray; AExpectOk: Boolean);
var
  LSelector: IX509CertStoreSelector;
  LTarget: ISelector<IX509Certificate>;
  LAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  LParams: IPkixBuilderParameters;
  LStore: IStore<IX509Certificate>;
  LBuilder: IPkixCertPathBuilder;
  LResult: IPkixCertPathBuilderResult;
  LBuilt: Boolean;
  LMessage: String;
begin
  LAnchors := TCryptoLibGenericArray<ITrustAnchor>.Create(TTrustAnchor.Create(FTrustCert, nil)
    as ITrustAnchor);

  LSelector := TX509CertStoreSelector.Create();
  LSelector.Subject := AEndCert.SubjectDN;
  // a generic interface carries no GUID, so this upcasts through a typed local instead of "as"
  LTarget := LSelector;

  LParams := TPkixBuilderParameters.Create(LAnchors, LTarget) as IPkixBuilderParameters;
  LStore := TCollectionStore<IX509Certificate>.Create
    (TCryptoLibGenericArray<IX509Certificate>.Create(AIntCert, AEndCert));
  LParams.AddStoreCert(LStore);
  LParams.IsRevocationEnabled := False;

  if ARequirePolicies <> nil then
  begin
    LParams.IsExplicitPolicyRequired := True;
    LParams.SetInitialPolicies(ARequirePolicies);
  end;

  LBuilt := False;
  LMessage := '';
  LBuilder := TPkixCertPathBuilder.Create() as IPkixCertPathBuilder;
  try
    LResult := LBuilder.Build(LParams);
    LBuilt := LResult <> nil;
  except
    on E: Exception do
      LMessage := Format('%s: %s', [E.ClassName, E.Message]);
  end;

  if AExpectOk then
    CheckTrue(LBuilt, Format('case %d: the path should validate (%s)', [AIndex, LMessage]))
  else
    CheckFalse(LBuilt, Format('case %d: the path should be rejected on policy', [AIndex]));
end;

procedure TPkixPolicyMappingTest.TestMappedPolicyWithoutInitialPolicies;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([AnyPolicyOid], TestPolicyOid2, LIntCert, LEndCert);
  CheckPolicies(0, LIntCert, LEndCert, nil, True);
end;

procedure TPkixPolicyMappingTest.TestMappedPolicyWithIssuerDomainPolicy;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([AnyPolicyOid], TestPolicyOid2, LIntCert, LEndCert);
  CheckPolicies(1, LIntCert, LEndCert, TCryptoLibStringArray.Create(TestPolicyOid1), True);
end;

procedure TPkixPolicyMappingTest.TestMappedPolicyWithAnyPolicy;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([AnyPolicyOid], TestPolicyOid2, LIntCert, LEndCert);
  CheckPolicies(2, LIntCert, LEndCert, TCryptoLibStringArray.Create(AnyPolicyOid), True);
end;

procedure TPkixPolicyMappingTest.TestMappedPolicyWithExtraIntermediatePolicy;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([TestPolicyOid3, AnyPolicyOid], TestPolicyOid2, LIntCert, LEndCert);
  CheckPolicies(3, LIntCert, LEndCert, TCryptoLibStringArray.Create(TestPolicyOid1), True);
end;

procedure TPkixPolicyMappingTest.TestUnmappedPolicyAcceptedDirectly;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([TestPolicyOid3, AnyPolicyOid], TestPolicyOid3, LIntCert, LEndCert);
  CheckPolicies(4, LIntCert, LEndCert, TCryptoLibStringArray.Create(TestPolicyOid3), True);
end;

procedure TPkixPolicyMappingTest.TestSubjectDomainPolicyIsNotAcceptable;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  // the mapping consumes policy 2, so naming it as an initial policy leaves nothing acceptable
  BuildMappedChain([AnyPolicyOid], TestPolicyOid2, LIntCert, LEndCert);
  CheckPolicies(5, LIntCert, LEndCert, TCryptoLibStringArray.Create(TestPolicyOid2), False);
end;

procedure TPkixPolicyMappingTest.TestIssuerDomainPolicyAtEndEntity;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([AnyPolicyOid], TestPolicyOid1, LIntCert, LEndCert);
  CheckPolicies(6, LIntCert, LEndCert, TCryptoLibStringArray.Create(TestPolicyOid1), True);
end;

procedure TPkixPolicyMappingTest.TestUnrelatedInitialPolicyRejected;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([AnyPolicyOid], TestPolicyOid2, LIntCert, LEndCert);
  CheckPolicies(7, LIntCert, LEndCert, TCryptoLibStringArray.Create(TestPolicyOid3), False);
end;

procedure TPkixPolicyMappingTest.TestUnrelatedEndEntityPolicyRejected;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([AnyPolicyOid], TestPolicyOid3, LIntCert, LEndCert);
  CheckPolicies(8, LIntCert, LEndCert, TCryptoLibStringArray.Create(TestPolicyOid1), False);
end;

procedure TPkixPolicyMappingTest.TestPolicyTreeNodeCapRejectsChain;
var
  LIntCert, LEndCert: IX509Certificate;
begin
  BuildMappedChain([AnyPolicyOid], TestPolicyOid2, LIntCert, LEndCert);

  // the control: at the default ceiling this chain validates, so a rejection below can only come
  // from the ceiling itself
  CheckPolicies(9, LIntCert, LEndCert, nil, True);

  // one node cannot hold any real policy tree, so the ceiling must bite
  TCryptoLibConfig.X509.MaxPolicyNodes := 1;
  CheckPolicies(9, LIntCert, LEndCert, nil, False);
end;

procedure TPkixPolicyMappingTest.TestPolicyTreeNodeCapRejectsNonPositive;
var
  LRaised: Boolean;
begin
  LRaised := False;
  try
    TCryptoLibConfig.X509.MaxPolicyNodes := 0;
  except
    on E: EArgumentCryptoLibException do
      LRaised := True;
  end;
  CheckTrue(LRaised, 'a ceiling below one must be refused, not silently ignored');

  // refusing the assignment must leave the setting untouched
  CheckEquals(8192, TCryptoLibConfig.X509.MaxPolicyNodes,
    'a refused assignment must not disturb the ceiling in force');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TPkixPolicyMappingTest);
{$ELSE}
  RegisterTest(TPkixPolicyMappingTest.Suite);
{$ENDIF FPC}

end.
