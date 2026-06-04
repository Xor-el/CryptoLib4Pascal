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

unit X509CertGenTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  DateUtils,
  Generics.Collections,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpBigInteger,
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Certificate,
  ClpX509CertificateParser,
  ClpX509Generators,
  ClpIX509Generators,
  ClpAsn1SignatureFactory,
  ClpISignatureFactory,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpIDsaParameters,
  ClpIECParameters,
  ClpECParameters,
  ClpRsaDigestSigner,
  ClpIRsaDigestSigner,
  ClpDigestUtilities,
  ClpIAsn1Objects,
  ClpCryptoLibTypes,
  ClpAsn1Comparers,
  ClpDateTimeHelper,
  CryptoLibTestBase,
  CertVectors,
  CryptoTestKeys;

type

  TX509CertGenTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FRsaPublic: IRsaKeyParameters;
    FRsaPrivate: IRsaPrivateCrtKeyParameters;
    FDsaPara: IDsaParameters;
    FDsaPriv: IDsaPrivateKeyParameters;
    FDsaPub: IDsaPublicKeyParameters;
    FEcDomain: IECDomainParameters;
    FEcPub: IECPublicKeyParameters;
    FEcPriv: IECPrivateKeyParameters;

    procedure SetUpKeys;
    function CreateX509Name: IX509Name;

  protected
    procedure SetUp; override;
  published
    procedure TestRsaDigestSigner;
    procedure TestCreationRSA;
    procedure TestCreationDSA;
    procedure TestCreationECDSA;

  end;

implementation

{ TX509CertGenTest }

procedure TX509CertGenTest.SetUpKeys;
begin
  FRsaPublic := TCryptoTestKeys.GetRsaDigestSignerPublic;
  FRsaPrivate := TCryptoTestKeys.GetRsaDigestSignerPrivate;
  FDsaPara := TCryptoTestKeys.GetDsaWolfParameters;
  FDsaPriv := TCryptoTestKeys.GetDsaWolfPrivate;
  FDsaPub := TCryptoTestKeys.GetDsaWolfPublic;
  FEcDomain := TCryptoTestKeys.GetEcPrime239v1Domain;
  FEcPub := TCryptoTestKeys.GetEcPrime239v1Public;
  FEcPriv := TCryptoTestKeys.GetEcPrime239v1Private;
end;

function TX509CertGenTest.CreateX509Name: IX509Name;
var
  LAttrs: TDictionary<IDerObjectIdentifier, String>;
  LOrd: TList<IDerObjectIdentifier>;
begin
  LAttrs := TDictionary<IDerObjectIdentifier, String>.Create(TAsn1Comparers.OidEqualityComparer);
  LOrd := TList<IDerObjectIdentifier>.Create(TAsn1Comparers.OidComparer);
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

procedure TX509CertGenTest.SetUp;
begin
  inherited SetUp;
  if FRsaPublic = nil then
    SetUpKeys;
end;

procedure TX509CertGenTest.TestRsaDigestSigner;
var
  LMsg, LSig: TCryptoLibByteArray;
  LSigner: IRsaDigestSigner;
begin
  LMsg := TCryptoLibByteArray.Create(1, 6, 3, 32, 7, 43, 2, 5, 7, 78, 4, 23);

  LSigner := TRsaDigestSigner.Create(TDigestUtilities.GetDigest('SHA-1'));
  LSigner.Init(True, FRsaPrivate);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  LSig := LSigner.GenerateSignature();

  LSigner.Init(False, FRsaPublic);
  LSigner.BlockUpdate(LMsg, 0, System.Length(LMsg));
  CheckTrue(LSigner.VerifySignature(LSig), 'RSA IDigest Signer failed.');
end;

procedure TX509CertGenTest.TestCreationRSA;
var
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  LName := CreateX509Name;
  LUtc := Now.ToUniversalTime();

  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncDay(LUtc, -1));
  LCertGen.SetNotAfterUtc(IncDay(LUtc, 1));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FRsaPublic);

  LSigner := TAsn1SignatureFactory.Create('MD5WithRSAEncryption', FRsaPrivate, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity();
  LCert.Verify(FRsaPublic);
end;

procedure TX509CertGenTest.TestCreationDSA;
var
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  LName := CreateX509Name;
  LUtc := Now.ToUniversalTime();

  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncDay(LUtc, -1));
  LCertGen.SetNotAfterUtc(IncDay(LUtc, 1));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FDsaPub);

  LSigner := TAsn1SignatureFactory.Create('SHA1WITHDSA', FDsaPriv, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity();
  LCert.Verify(FDsaPub);
end;

procedure TX509CertGenTest.TestCreationECDSA;
var
  LCertGen: IX509V3CertificateGenerator;
  LName: IX509Name;
  LCert: IX509Certificate;
  LSigner: ISignatureFactory;
  LExtOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LUtc: TDateTime;
begin
  LCertGen := TX509V3CertificateGenerator.Create;
  LName := CreateX509Name;
  LUtc := Now.ToUniversalTime();

  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(LName);
  LCertGen.SetNotBeforeUtc(IncDay(LUtc, -1));
  LCertGen.SetNotAfterUtc(IncDay(LUtc, 1));
  LCertGen.SetSubjectDN(LName);
  LCertGen.SetPublicKey(FEcPub);

  LCertGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(False) as IBasicConstraints);

  LSigner := TAsn1SignatureFactory.Create('SHA1WITHECDSA', FEcPriv, nil);
  LCert := LCertGen.Generate(LSigner);

  LCert.CheckValidity();
  LCert.Verify(FEcPub);

  LExtOids := LCert.CertificateStructure.Extensions.GetCriticalExtensionOids();
  if System.Length(LExtOids) <> 1 then
    Fail('wrong number of oids');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TX509CertGenTest);
{$ELSE}
  RegisterTest(TX509CertGenTest.Suite);
{$ENDIF FPC}

end.
