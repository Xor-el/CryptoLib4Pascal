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

unit DeltaCertificateTests;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  DateUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpX509Asn1Objects,
  ClpIX509Asn1Objects,
  ClpIX509Extension,
  ClpX509Certificate,
  ClpIX509Certificate,
  ClpDeltaCertificateTool,
  ClpIPemObject,
  ClpIPemReader,
  ClpPemReader,
  ClpCryptoLibExceptions,
  ClpBigInteger,
  ClpGeneratorUtilities,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpECParameters,
  ClpSecObjectIdentifiers,
  ClpCustomNamedCurves,
  ClpIX509Generators,
  ClpX509Generators,
  ClpAsn1SignatureFactory,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIX9ECAsn1Objects,
  ClpIECParameters,
  ClpISignatureFactory,
  ClpMlDsaParameters,
  ClpIMlDsaParameters,
  ClpSubjectPublicKeyInfoFactory,
  ClpIAsymmetricKeyParameter,
  ClpDateTimeUtilities,
  CryptoLibTestBase,
  CertVectors;

type

  TDeltaCertificateTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FSecureRandom: ISecureRandom;

    function ReadCert(const ACertId: string): IX509Certificate;

  protected
    procedure SetUp; override;

  published
    procedure TestDraftDualUseECDsaEndEntity;
    procedure TestDraftMlDsaRoot;
    procedure TestDraftMlDsaEndEntity;
    procedure TestSameName;
    procedure TestDeltaCertWithExtensions;
    procedure TestCheckCreationAltCertWithDelta;

  end;

implementation

{ TDeltaCertificateTest }

procedure TDeltaCertificateTest.SetUp;
begin
  inherited SetUp;
  FSecureRandom := TSecureRandom.Create();
end;

function TDeltaCertificateTest.ReadCert(const ACertId: string): IX509Certificate;
var
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPemObj: IPemObject;
  LStruct: IX509CertificateStructure;
begin
  LStream := TStringStream.Create(TCertVectors.LoadPemString(ACertId), TEncoding.ASCII);
  try
    LPemReader := TPemReader.Create(LStream);
    LPemObj := LPemReader.ReadPemObject();
    if LPemObj = nil then
      raise EIOCryptoLibException.Create('No PEM object in stream');
    LStruct := TX509CertificateStructure.GetInstance(LPemObj.Content);
    Result := TX509Certificate.Create(LStruct);
  finally
    LStream.Free;
  end;
end;

procedure TDeltaCertificateTest.TestDraftDualUseECDsaEndEntity;
var
  LEcRootCert, LBaseCert, LDeltaCert, LExtCert: IX509Certificate;
begin
  LEcRootCert := ReadCert('DeltaEcDsaRoot');
  LBaseCert := ReadCert('DeltaEcDsaDualXchEe');
  Check(LBaseCert.IsSignatureValid(LEcRootCert.GetPublicKey), 'base signed by ec_dsa_root');
  LDeltaCert := TDeltaCertificateTool.ExtractDeltaCertificate(LBaseCert);
  LExtCert := ReadCert('DeltaEcDsaDualSigEe');
  Check(AreEqual(LExtCert.GetEncoded, LDeltaCert.GetEncoded), 'delta equals ec_dsa_dual_sig_ee');
  Check(LDeltaCert.IsSignatureValid(LEcRootCert.GetPublicKey), 'delta signed by ec_dsa_root');
end;

procedure TDeltaCertificateTest.TestDraftMlDsaRoot;
var
  LBaseCert, LDeltaCert, LExtCert: IX509Certificate;
begin
  LBaseCert := ReadCert('DeltaMlDsaRoot');
  Check(LBaseCert.IsSignatureValid(LBaseCert.GetPublicKey), 'ml_dsa_root self-signed');
  LDeltaCert := TDeltaCertificateTool.ExtractDeltaCertificate(LBaseCert);
  Check(LDeltaCert.IsSignatureValid(LDeltaCert.GetPublicKey), 'extracted delta self-signed');
  LExtCert := ReadCert('DeltaEcDsaRoot');
  Check(LExtCert.Equals(LDeltaCert), 'extracted delta equals ec_dsa_root');
end;

procedure TDeltaCertificateTest.TestDraftMlDsaEndEntity;
var
  LRootCert, LEcRootCert, LBaseCert, LDeltaCert, LExtCert: IX509Certificate;
begin
  LRootCert := ReadCert('DeltaMlDsaRoot');
  LEcRootCert := ReadCert('DeltaEcDsaRoot');
  LBaseCert := ReadCert('DeltaEcDsaEe');
  Check(LBaseCert.IsSignatureValid(LEcRootCert.GetPublicKey), 'ec_dsa_ee signed by ec_dsa_root');
  LDeltaCert := TDeltaCertificateTool.ExtractDeltaCertificate(LBaseCert);
  Check(LDeltaCert.IsSignatureValid(LRootCert.GetPublicKey), 'delta signed by ml_dsa_root');
  LExtCert := ReadCert('DeltaMlDsaEe');
  Check(LExtCert.Equals(LDeltaCert), 'extracted delta equals ml_dsa_ee');
end;

procedure TDeltaCertificateTest.TestSameName;
var
  LRsaKpg: IAsymmetricCipherKeyPairGenerator;
  LDeltaKp, LBaseKp: IAsymmetricCipherKeyPair;
  LDeltaBldr, LBaseBldr: IX509V3CertificateGenerator;
  LDeltaCert, LBaseCert: IX509Certificate;
  LDeltaExt: IX509Extension;
  LRsaKgParams: IRsaKeyGenerationParameters;
  LSignerA, LSignerB: ISignatureFactory;
  LIssuerDN, LSubjectDN: IX509Name;
begin
  LRsaKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LRsaKgParams := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(65537), FSecureRandom, 2048, 80);
  LRsaKpg.Init(LRsaKgParams);
  LDeltaKp := LRsaKpg.GenerateKeyPair();
  LBaseKp := LRsaKpg.GenerateKeyPair();

  LDeltaBldr := TX509V3CertificateGenerator.Create;
  LIssuerDN := TX509Name.Create('CN=Issuer');
  LDeltaBldr.SetIssuerDN(LIssuerDN);
  LDeltaBldr.SetSerialNumber(TBigInteger.One);
  LDeltaBldr.SetNotBefore(Now);
  LDeltaBldr.SetNotAfter(IncYear(Now, 1));
  LSubjectDN := TX509Name.Create('CN=Subject');
  LDeltaBldr.SetSubjectDN(LSubjectDN);
  LDeltaBldr.SetPublicKey(LDeltaKp.Public);
  LSignerA := TAsn1SignatureFactory.Create('SHA256withRSA', LDeltaKp.Private);
  LDeltaCert := LDeltaBldr.Generate(LSignerA);

  LDeltaExt := TDeltaCertificateTool.CreateDeltaCertificateExtension(False, LDeltaCert);

  LBaseBldr := TX509V3CertificateGenerator.Create;
  LIssuerDN := TX509Name.Create('CN=Issuer');
  LBaseBldr.SetIssuerDN(LIssuerDN);
  LBaseBldr.SetSerialNumber(TBigInteger.Two);
  LBaseBldr.SetNotBefore(Now);
  LBaseBldr.SetNotAfter(IncYear(Now, 1));
  LSubjectDN := TX509Name.Create('CN=Subject');
  LBaseBldr.SetSubjectDN(LSubjectDN);
  LBaseBldr.SetPublicKey(LBaseKp.Public);
  LBaseBldr.AddExtension(TX509Extensions.DraftDeltaCertificateDescriptor, LDeltaExt);
  LSignerB := TAsn1SignatureFactory.Create('SHA256withRSA', LBaseKp.Private);
  LBaseCert := LBaseBldr.Generate(LSignerB);

  Check(LBaseCert <> nil, 'base cert generated');
  Check(System.Length(LBaseCert.GetEncoded) > 0, 'base cert encoded');
end;

procedure TDeltaCertificateTest.TestDeltaCertWithExtensions;
var
  LSubject: IX509Name;
  LKpgA, LKpgB: IAsymmetricCipherKeyPairGenerator;
  LKpA, LKpB: IAsymmetricCipherKeyPair;
  LRsaKgParams: IRsaKeyGenerationParameters;
  LEcP: IX9ECParameters;
  LDomainParams: IECDomainParameters;
  LSignerA, LSignerB: ISignatureFactory;
  LNotBefore, LNotAfter: TDateTime;
  LBldr, LDeltaBldr: IX509V3CertificateGenerator;
  LDeltaCert, LChameleonCert, LExDeltaCert: IX509Certificate;
  LDeltaExt: IX509Extension;
  LDeltaCertDesc: IDeltaCertificateDescriptor;
  LIssuerDN1, LIssuerDN2: IX509Name;
  LBasicConstraints1, LBasicConstraints2: IBasicConstraints;
begin
  LSubject := TX509Name.Create('CN=Test Subject');

  LKpgA := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LRsaKgParams := TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(65537), FSecureRandom, 2048, 80);
  LKpgA.Init(LRsaKgParams);
  LKpA := LKpgA.GenerateKeyPair();

  LEcP := TCustomNamedCurves.GetByOid(TSecObjectIdentifiers.SecP256r1);
  LDomainParams := TECDomainParameters.Create(LEcP.Curve, LEcP.G, LEcP.N, LEcP.H, LEcP.GetSeed());
  LKpgB := TGeneratorUtilities.GetKeyPairGenerator('EC');
  LKpgB.Init(TECKeyGenerationParameters.Create(LDomainParams, FSecureRandom));
  LKpB := LKpgB.GenerateKeyPair();

  LSignerA := TAsn1SignatureFactory.Create('SHA256withRSA', LKpA.Private);
  LSignerB := TAsn1SignatureFactory.Create('SHA256withECDSA', LKpB.Private);

  LNotBefore := IncSecond(Now, -5);
  LNotAfter := IncHour(Now, 1);

  LBldr := TX509V3CertificateGenerator.Create;
  LIssuerDN1 := TX509Name.Create('CN=Chameleon CA 1');
  LBldr.SetIssuerDN(LIssuerDN1);
  LBldr.SetSerialNumber(TBigInteger.ValueOf(1000));
  LBldr.SetNotBefore(LNotBefore);
  LBldr.SetNotAfter(LNotAfter);
  LBldr.SetSubjectDN(LSubject);
  LBldr.SetPublicKey(LKpA.Public);
  LBasicConstraints1 := TBasicConstraints.Create(False);
  LBldr.AddExtension(TX509Extensions.BasicConstraints, True, LBasicConstraints1);

  LDeltaBldr := TX509V3CertificateGenerator.Create;
  LIssuerDN2 := TX509Name.Create('CN=Chameleon CA 2');
  LDeltaBldr.SetIssuerDN(LIssuerDN2);
  LDeltaBldr.SetSerialNumber(TBigInteger.ValueOf(1001));
  LDeltaBldr.SetNotBefore(LNotBefore);
  LDeltaBldr.SetNotAfter(LNotAfter);
  LDeltaBldr.SetSubjectDN(LSubject);
  LDeltaBldr.SetPublicKey(LKpB.Public);
  LBasicConstraints2 := TBasicConstraints.Create(False);
  LDeltaBldr.AddExtension(TX509Extensions.BasicConstraints, True, LBasicConstraints2);
  LDeltaCert := LDeltaBldr.Generate(LSignerB);

  LDeltaExt := TDeltaCertificateTool.CreateDeltaCertificateExtension(False, LDeltaCert);
  LBldr.AddExtension(TX509Extensions.DraftDeltaCertificateDescriptor, LDeltaExt);
  LChameleonCert := LBldr.Generate(LSignerA);

  Check(LChameleonCert.IsSignatureValid(LKpA.Public), 'chameleon cert signature valid with kpA');

  LDeltaCertDesc := TDeltaCertificateDescriptor.FromExtensions(
    LChameleonCert.CertificateStructure.Extensions);
  Check(LDeltaCertDesc.Extensions = nil, 'DCD extensions nil');
  Check(LDeltaCertDesc.Subject = nil, 'DCD subject nil');
  Check(LDeltaCertDesc.Issuer <> nil, 'DCD issuer present');

  LExDeltaCert := TDeltaCertificateTool.ExtractDeltaCertificate(LChameleonCert);
  Check(LExDeltaCert.IsSignatureValid(LKpB.Public), 'extracted delta signature valid with kpB');
end;

procedure TDeltaCertificateTest.TestCheckCreationAltCertWithDelta;
var
  LKpgB, LKpGen, LEcKpGen: IAsymmetricCipherKeyPairGenerator;
  LKpB, LKp, LEcKp: IAsymmetricCipherKeyPair;
  LEcPrivKey, LEcPubKey, LPubKey: IAsymmetricKeyParameter;
  LNotBefore, LNotAfter: TDateTime;
  LIssuer, LSubject: IX509Name;
  LSigGen, LAltSigGen, LSignerB: ISignatureFactory;
  LCertGen, LDeltaBldr: IX509V3CertificateGenerator;
  LDeltaCert, LCert, LExDeltaCert: IX509Certificate;
  LDeltaExt: IX509Extension;
  LBasicConstraints: IBasicConstraints;
  LSubjectAltPubKeyInfo: ISubjectAltPublicKeyInfo;
  LEcP: IX9ECParameters;
  LDomainParams: IECDomainParameters;
begin
  LEcP := TCustomNamedCurves.GetByOid(TSecObjectIdentifiers.SecP256r1);
  LDomainParams := TECDomainParameters.Create(LEcP.Curve, LEcP.G, LEcP.N, LEcP.H, LEcP.GetSeed());

  LKpgB := TGeneratorUtilities.GetKeyPairGenerator('EC');
  LKpgB.Init(TECKeyGenerationParameters.Create(LDomainParams, FSecureRandom) as IECKeyGenerationParameters);
  LKpB := LKpgB.GenerateKeyPair();

  LKpGen := TGeneratorUtilities.GetKeyPairGenerator('ML-DSA');
  LKpGen.Init(TMlDsaKeyGenerationParameters.Create(FSecureRandom, TMlDsaParameters.MlDsa44) as IMlDsaKeyGenerationParameters);
  LKp := LKpGen.GenerateKeyPair();
  LPubKey := LKp.Public;

  LEcKpGen := TGeneratorUtilities.GetKeyPairGenerator('EC');
  LEcKpGen.Init(TECKeyGenerationParameters.Create(LDomainParams, FSecureRandom) as IECKeyGenerationParameters);
  LEcKp := LEcKpGen.GenerateKeyPair();
  LEcPrivKey := LEcKp.Private;
  LEcPubKey := LEcKp.Public;

  LNotBefore := IncSecond(Now, -5);
  LNotAfter := IncHour(Now, 1);

  LIssuer := TX509Name.Create('CN=Chameleon Base Issuer');
  LSubject := TX509Name.Create('CN=Chameleon Base Subject');

  LSigGen := TAsn1SignatureFactory.Create('SHA256withECDSA', LEcPrivKey);
  LAltSigGen := TAsn1SignatureFactory.Create('ML-DSA-44', LKp.Private);

  LCertGen := TX509V3CertificateGenerator.Create;
  LCertGen.SetIssuerDN(LIssuer);
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetNotBefore(LNotBefore);
  LCertGen.SetNotAfter(LNotAfter);
  LCertGen.SetSubjectDN(LSubject);
  LCertGen.SetPublicKey(LEcPubKey);
  LBasicConstraints := TBasicConstraints.Create(False);
  LCertGen.AddExtension(TX509Extensions.BasicConstraints, True, LBasicConstraints);
  LSubjectAltPubKeyInfo := TSubjectAltPublicKeyInfo.Create(
    TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(LPubKey));
  LCertGen.AddExtension(TX509Extensions.SubjectAltPublicKeyInfo, False, LSubjectAltPubKeyInfo);

  LSignerB := TAsn1SignatureFactory.Create('SHA256withECDSA', LKpB.Private);

  LDeltaBldr := TX509V3CertificateGenerator.Create;
  LDeltaBldr.SetIssuerDN(TX509Name.Create('CN=Chameleon CA 2'));
  LDeltaBldr.SetSerialNumber(TBigInteger.ValueOf(TDateTimeUtilities.CurrentUnixMs));
  LDeltaBldr.SetNotBefore(LNotBefore);
  LDeltaBldr.SetNotAfter(LNotAfter);
  LDeltaBldr.SetSubjectDN(LSubject);
  LDeltaBldr.SetPublicKey(LKpB.Public);
  LDeltaBldr.AddExtension(TX509Extensions.BasicConstraints, True, LBasicConstraints);
  LDeltaBldr.AddExtension(TX509Extensions.SubjectAltPublicKeyInfo, False, LSubjectAltPubKeyInfo);
  LDeltaCert := LDeltaBldr.Generate(LSignerB, False, LAltSigGen);

  Check(LDeltaCert.IsSignatureValid(LKpB.Public), 'delta cert primary signature valid');

  LDeltaExt := TDeltaCertificateTool.CreateDeltaCertificateExtension(False, LDeltaCert);
  LCertGen.AddExtension(TX509Extensions.DraftDeltaCertificateDescriptor, LDeltaExt);
  LCert := LCertGen.Generate(LSigGen, False, LAltSigGen);

  LCert.CheckValidity();
  LCert.Verify(LCert.GetPublicKey);
  Check(System.Length(LCert.GetEncoded) > 0, 'base cert encoded');
  Check(LCert.IsAlternativeSignatureValid(LPubKey), 'alt sig value wrong');

  LExDeltaCert := TDeltaCertificateTool.ExtractDeltaCertificate(LCert);
  Check(LExDeltaCert.IsSignatureValid(LKpB.Public), 'extracted delta primary signature valid');
  Check(LExDeltaCert.IsAlternativeSignatureValid(LPubKey), 'extracted delta alt signature valid');
  Check(LCert.IsSignatureValid(LEcPubKey), 'base cert primary signature valid with ec pub');
  Check(LCert.IsAlternativeSignatureValid(LPubKey), 'base cert alt signature valid with ml-dsa pub');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TDeltaCertificateTest);
{$ELSE}
  RegisterTest(TDeltaCertificateTest.Suite);
{$ENDIF FPC}

end.
