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
  ClpPemObjects,
  ClpIPemObjects,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpGeneratorUtilities,
  ClpRsaKeyGenerationParameters,
  ClpIRsaKeyGenerationParameters,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpECKeyGenerationParameters,
  ClpSecObjectIdentifiers,
  ClpCustomNamedCurves,
  ClpECDomainParameters,
  ClpX509V3CertificateGenerator,
  ClpAsn1SignatureFactory,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricCipherKeyPair,
  ClpIX9ECParameters,
  ClpIECDomainParameters,
  ClpISignatureFactory,
  CryptoLibTestBase;

type

  TDeltaCertificateTest = class(TCryptoLibAlgorithmTestCase)
  strict private
  var
    FDeltaEcDsaRoot, FDeltaEcDsaDualXchEe, FDeltaEcDsaDualSigEe: String;
    FSecureRandom: ISecureRandom;

    procedure SetUpTestData;
    function ReadCert(const APem: String): IX509Certificate;

  protected
    procedure SetUp; override;

  published
    procedure TestDraftDualUseECDsaEndEntity;
    procedure TestSameName;
    procedure TestDeltaCertWithExtensions;

  end;

implementation

{ TDeltaCertificateTest }

procedure TDeltaCertificateTest.SetUpTestData;
begin
  // ec_dsa_root.pem
  FDeltaEcDsaRoot := '-----BEGIN CERTIFICATE-----' + sLineBreak +
    'MIIDBDCCAmagAwIBAgIUDCQO4j68JeS6tggSujZ2W/+5RMAwCgYIKoZIzj0EAwQw' +
    'gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi' +
    'bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg' +
    'UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X' +
    'DTI0MTAxNzIzMzcyM1oXDTM0MTAxNTIzMzcyM1owgYsxCzAJBgNVBAYTAlhYMTUw' +
    'MwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVibGljIEtleSBJbmZyYXN0cnVj' +
    'dHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAgUmVzZWFyY2ggRGVwYXJ0bWVu' +
    'dDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMIGbMBAGByqGSM49AgEGBSuBBAAj' +
    'A4GGAAQBAFYGp79DhDUnJ+euhbWIqRMPC/YJyMcXp5xEF96cQji2rOckvcqQkhqE' +
    'K2upXcSLaclIkS16REFZgT0q3vO2m1wAhXxeKePsML2EiCMQIEArXsEwCDGu+qdx' +
    'mN2lHUQNuiisrkigRdXILHaAXdfTtAvpopsAchnm+vUbHNavcxVRjK2jYzBhMA8G' +
    'A1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBTro9CLUf4S' +
    '3MwhZoeFD5jHZ3OINDAfBgNVHSMEGDAWgBTro9CLUf4S3MwhZoeFD5jHZ3OINDAK' +
    'BggqhkjOPQQDBAOBiwAwgYcCQUnnSxI6X5NPGGetpBUkEh3HIDTrW24dPtx74wmW' +
    'ANwrejsbS0SvbipnQJPQXjTv8aXDlDAMiPKHado5qCJXMvU3AkIAmDbRmevtaNUQ' +
    '0k6e97CWc8tTPE7gXo5iqFD0NU9v20HV3z7voEU8fYD65A1Ay3VQ76nC8W8T4T1a' +
    'fvRCLit6wo0=' + sLineBreak + '-----END CERTIFICATE-----';

  // ec_dsa_dual_xch_ee.pem
  FDeltaEcDsaDualXchEe := '-----BEGIN CERTIFICATE-----' + sLineBreak +
    'MIIDzTCCAy6gAwIBAgIUczxcVsNa7M9uSs598vuGatGLDuIwCgYIKoZIzj0EAwQw' +
    'gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi' +
    'bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg' +
    'UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X' +
    'DTI0MTAxNzIzMzcyM1oXDTM0MTAxNTIzMzcyM1owLzELMAkGA1UEBhMCWFgxDzAN' +
    'BgNVBAoMBkhhbmFrbzEPMA0GA1UECwwGWWFtYWRhMHYwEAYHKoZIzj0CAQYFK4EE' +
    'ACIDYgAE+qm8IaZ5hVFufLvTuniWWnQoa9d0YCyNiOmQ2OrrcukSy0FgozyJq7hc' +
    'g8o2pJ5uRRLVysU1gHNfxL+TvwRRr6eWUJE8v0dCUccuCFPAVbxwf7Hjcp5NSsFn' +
    'J2lIrvzgo4IBrDCCAagwDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCAwgwHQYD' +
    'VR0OBBYEFAHprr1J3zZ7gG1ksEzN8BHM7tCzMB8GA1UdIwQYMBaAFOuj0ItR/hLc' +
    'zCFmh4UPmMdnc4g0MIIBRgYKYIZIAYb6a1AGAQSCATYwggEyAhRVxU1+JyiKlGzh' +
    'zokGIXvfVW0MsDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABG4OZivWg8PvaSAE' +
    'oMwgDXGEboF0n2lrUx9yoOrYf5vIcmz71x7BRhJ5uGbt2vkv+UT5iMO/FKATKSKk' +
    'fk356NekMTAvMA4GA1UdDwEB/wQEAwIHgDAdBgNVHQ4EFgQUqMbB+PJ2cSu0HM5U' +
    'yIvPmU/0mr8DgYsAMIGHAkE7d3yiPS2GlKZIjznEu68D3vD9ApGF0ZfA+3M7tVx4' +
    'fex4yI5GgIs8o7wZ93WWJEu3OeHPshuZVtLrhZvFB7hBrAJCAV5PVtpsfYwQEtP4' +
    '0ZcgoDRrOK0/XUsD+vKdigNuKd20/Ty3EhrzD07YyEbXvTqestz7P4+y1CpeBBDm' +
    'Fr9+f3s8MAoGCCqGSM49BAMEA4GMADCBiAJCAXrIaCetU/F7+TDkYBjEaHRZEujy' +
    'DL2Ic08Eu+iDBRvzuYjxulQKCJaRFrcbegcW8D8MTkrJW8b0j9PkIXuLB51wAkIB' +
    '0/4Tx4hhUQ6SCBNx70mG2kOeHpgZB62K3b3PtypOJtUWTZS5XgBhljUUTmdsaQtA' +
    'wi1V+cwAnegmu168l43lQz0=' + sLineBreak + '-----END CERTIFICATE-----';

  // ec_dsa_dual_sig_ee.pem
  FDeltaEcDsaDualSigEe := '-----BEGIN CERTIFICATE-----' + sLineBreak +
    'MIICYTCCAcOgAwIBAgIUVcVNficoipRs4c6JBiF731VtDLAwCgYIKoZIzj0EAwQw' +
    'gYsxCzAJBgNVBAYTAlhYMTUwMwYDVQQKDCxSb3lhbCBJbnN0aXR1dGUgb2YgUHVi' +
    'bGljIEtleSBJbmZyYXN0cnVjdHVyZTErMCkGA1UECwwiUG9zdC1IZWZmYWx1bXAg' +
    'UmVzZWFyY2ggRGVwYXJ0bWVudDEYMBYGA1UEAwwPRUNEU0EgUm9vdCAtIEcxMB4X' +
    'DTI0MTAxNzIzMzcyM1oXDTM0MTAxNTIzMzcyM1owLzELMAkGA1UEBhMCWFgxDzAN' +
    'BgNVBAoMBkhhbmFrbzEPMA0GA1UECwwGWWFtYWRhMFkwEwYHKoZIzj0CAQYIKoZI' +
    'zj0DAQcDQgAEbg5mK9aDw+9pIASgzCANcYRugXSfaWtTH3Kg6th/m8hybPvXHsFG' +
    'Enm4Zu3a+S/5RPmIw78UoBMpIqR+Tfno16NgMF4wDAYDVR0TAQH/BAIwADAOBgNV' +
    'HQ8BAf8EBAMCB4AwHQYDVR0OBBYEFKjGwfjydnErtBzOVMiLz5lP9Jq/MB8GA1Ud' +
    'IwQYMBaAFOuj0ItR/hLczCFmh4UPmMdnc4g0MAoGCCqGSM49BAMEA4GLADCBhwJB' +
    'O3d8oj0thpSmSI85xLuvA97w/QKRhdGXwPtzO7VceH3seMiORoCLPKO8Gfd1liRL' +
    'tznhz7IbmVbS64WbxQe4QawCQgFeT1babH2MEBLT+NGXIKA0azitP11LA/rynYoD' +
    'bindtP08txIa8w9O2MhG1706nrLc+z+PstQqXgQQ5ha/fn97PA==' + sLineBreak + '-----END CERTIFICATE-----';

   FSecureRandom := TSecureRandom.Create();
end;

procedure TDeltaCertificateTest.SetUp;
begin
  inherited SetUp;
  SetUpTestData;
end;

function TDeltaCertificateTest.ReadCert(const APem: String): IX509Certificate;
var
  LStream: TStringStream;
  LPemReader: IPemReader;
  LPemObj: IPemObject;
  LStruct: IX509CertificateStructure;
begin
  LStream := TStringStream.Create(APem, TEncoding.ASCII);
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
  LEcRootCert := ReadCert(FDeltaEcDsaRoot);
  LBaseCert := ReadCert(FDeltaEcDsaDualXchEe);
  Check(LBaseCert.IsSignatureValid(LEcRootCert.GetPublicKey), 'base signed by ec_dsa_root');
  LDeltaCert := TDeltaCertificateTool.ExtractDeltaCertificate(LBaseCert);
  LExtCert := ReadCert(FDeltaEcDsaDualSigEe);
  Check(TArrayUtilities.AreEqual<Byte>(LExtCert.GetEncoded, LDeltaCert.GetEncoded), 'delta equals ec_dsa_dual_sig_ee');
  Check(LDeltaCert.IsSignatureValid(LEcRootCert.GetPublicKey), 'delta signed by ec_dsa_root');
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

initialization

{$IFDEF FPC}
  RegisterTest(TDeltaCertificateTest);
{$ELSE}
  RegisterTest(TDeltaCertificateTest.Suite);
{$ENDIF FPC}

end.
