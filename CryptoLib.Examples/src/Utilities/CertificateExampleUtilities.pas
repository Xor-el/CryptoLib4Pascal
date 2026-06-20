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

unit CertificateExampleUtilities;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Rtti,
  DateUtils,
  ClpBigInteger,
  ClpIAsn1Objects,
  ClpX509NameBuilder,
  ClpIX509NameBuilder,
  ClpX509Generators,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Asn1Generators,
  ClpX509Asn1Generators,
  ClpAsn1SignatureFactory,
  ClpX509CrlParser,
  ClpIX509CrlParser,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509Generators,
  ClpX509Certificate,
  ClpX509ExtensionUtilities,
  ClpSubjectPublicKeyInfoFactory,
  ClpPkcs10CertificationRequestBuilder,
  ClpIPkcs10CertificationRequestBuilder,
  ClpIPkcs10CertificationRequest,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpISignatureFactory,
  ClpDateTimeHelper,
  KeyEncodingExampleUtilities;

type
  TCertificateArtifactsPem = record
    PrivateKeyPem: string;
    CertificateRequestPem: string;
    CertificatePem: string;
    CrlPem: string;
  end;

  TCertificateExampleUtilities = class sealed
  strict private
    class procedure GetValidityUtc(AValidDays: Integer; out ANotBefore, ANotAfter: TDateTime); static;
  public
    class function BuildX509Name(const ACommonName, ACountry, AOrganization, ALocality, AState,
      AEmail: string): IX509Name; static;
    class function BuildBasicEndEntityExtensions(const APublicKey: IAsymmetricKeyParameter): IX509Extensions; static;
    class function CreateCrl(const AKeyPair: IAsymmetricCipherKeyPair; const AIssuer: IX509Name;
      const ASignatureAlgorithm: String; AValidDays: Integer = 1): IX509Crl; static;
    class function CreateCertificationRequest(const AKeyPair: IAsymmetricCipherKeyPair;
      const ASubject: IX509Name; const ASignatureAlgorithm: String;
      const ADnsSanName: string): IPkcs10CertificationRequest; static;
    class function CreateSelfSignedCertificate(const AKeyPair: IAsymmetricCipherKeyPair;
      const ASubject: IX509Name; const ASignatureAlgorithm: String;
      AValidDays: Integer): IX509Certificate; static;
    class function CreateCertificateArtifacts(const AKeyPair: IAsymmetricCipherKeyPair;
      const ASubject: IX509Name; const ASignatureAlgorithm: String; const ADnsSanName: string;
      AValidDaysCert: Integer): TCertificateArtifactsPem; static;
    class function ParseCrl(const ACrlEncoded: TBytes): IX509Crl; static;
    class function VerifyCrl(const ACrl: IX509Crl;
      const AIssuerPublicKey: IAsymmetricKeyParameter): Boolean; static;
  end;

implementation

class procedure TCertificateExampleUtilities.GetValidityUtc(AValidDays: Integer;
  out ANotBefore, ANotAfter: TDateTime);
begin
  ANotBefore := Now.ToUniversalTime();
  ANotAfter := IncSecond(ANotBefore, AValidDays * 86400);
end;

class function TCertificateExampleUtilities.BuildX509Name(const ACommonName, ACountry,
  AOrganization, ALocality, AState, AEmail: string): IX509Name;
var
  LBuilder: IX509NameBuilder;
begin
  LBuilder := TX509NameBuilder.Create();
  Result := LBuilder
    .AddCommonName(ACommonName)
    .AddCountry(ACountry)
    .AddOrganization(AOrganization)
    .AddLocality(ALocality)
    .AddState(AState)
    .AddEmailAddress(AEmail)
    .Build();
end;

class function TCertificateExampleUtilities.BuildBasicEndEntityExtensions(
  const APublicKey: IAsymmetricKeyParameter): IX509Extensions;
var
  LExtGen: IX509ExtensionsGenerator;
begin
  LExtGen := TX509ExtensionsGenerator.Create();
  LExtGen.AddExtension(TX509Extensions.BasicConstraints, True,
    TBasicConstraints.Create(False) as IBasicConstraints);
  LExtGen.AddExtension(TX509Extensions.KeyUsage, True,
    TKeyUsage.Create(TKeyUsage.DigitalSignature or TKeyUsage.KeyEncipherment) as IKeyUsage);
  Result := LExtGen.Generate();
end;

class function TCertificateExampleUtilities.CreateCrl(const AKeyPair: IAsymmetricCipherKeyPair;
  const AIssuer: IX509Name; const ASignatureAlgorithm: String; AValidDays: Integer): IX509Crl;
var
  LCrlGen: IX509V2CrlGenerator;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  GetValidityUtc(AValidDays, LThisUpdate, LNextUpdate);
  LCrlGen := TX509V2CrlGenerator.Create();
  LCrlGen.SetIssuerDN(AIssuer);
  LCrlGen.SetThisUpdateUtc(LThisUpdate);
  LCrlGen.SetNextUpdateUtc(LNextUpdate);
  LCrlGen.AddCrlEntryUtc(TBigInteger.One, LThisUpdate, 0);
  LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(
      TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AKeyPair.Public)));
  Result := LCrlGen.Generate(TAsn1SignatureFactory.Create(ASignatureAlgorithm,
    AKeyPair.Private, nil) as ISignatureFactory);
end;

class function TCertificateExampleUtilities.CreateCertificationRequest(
  const AKeyPair: IAsymmetricCipherKeyPair; const ASubject: IX509Name;
  const ASignatureAlgorithm: String; const ADnsSanName: string): IPkcs10CertificationRequest;
var
  LBuilder: IPkcs10CertificationRequestBuilder;
  LDnsName: IGeneralName;
  LSanNames: IGeneralNames;
  LExtensions: IX509Extensions;
begin
  LExtensions := BuildBasicEndEntityExtensions(AKeyPair.Public);
  LDnsName := TGeneralName.Create(TGeneralName.DnsName, ADnsSanName);
  LSanNames := TGeneralNames.Create(LDnsName);

  LBuilder := TPkcs10CertificationRequestBuilder.Create();
  Result := LBuilder
    .SetSubject(ASubject)
    .SetKeyPair(AKeyPair)
    .SetSignatureAlgorithm(ASignatureAlgorithm)
    .AddExtensions(LExtensions)
    .AddExtension(TX509Extensions.SubjectAlternativeName, False, LSanNames)
    .AddSubjectKeyIdentifier(False)
    .Build();
end;

class function TCertificateExampleUtilities.CreateSelfSignedCertificate(
  const AKeyPair: IAsymmetricCipherKeyPair; const ASubject: IX509Name;
  const ASignatureAlgorithm: String; AValidDays: Integer): IX509Certificate;
var
  LCertGen: IX509V3CertificateGenerator;
  LNotBefore, LNotAfter: TDateTime;
  LExtensions: IX509Extensions;
begin
  GetValidityUtc(AValidDays, LNotBefore, LNotAfter);
  LCertGen := TX509V3CertificateGenerator.Create();
  LCertGen.SetSerialNumber(TBigInteger.One);
  LCertGen.SetIssuerDN(ASubject);
  LCertGen.SetSubjectDN(ASubject);
  LCertGen.SetNotBeforeUtc(LNotBefore);
  LCertGen.SetNotAfterUtc(LNotAfter);
  LCertGen.SetPublicKey(AKeyPair.Public);

  LExtensions := BuildBasicEndEntityExtensions(AKeyPair.Public);
  LCertGen.AddExtensions(LExtensions);
  LCertGen.AddExtension(TX509Extensions.SubjectKeyIdentifier, False,
    TX509ExtensionUtilities.CreateSubjectKeyIdentifier(AKeyPair.Public));
  LCertGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(AKeyPair.Public));

  Result := LCertGen.Generate(TAsn1SignatureFactory.Create(ASignatureAlgorithm,
    AKeyPair.Private, nil) as ISignatureFactory);
end;

class function TCertificateExampleUtilities.CreateCertificateArtifacts(
  const AKeyPair: IAsymmetricCipherKeyPair; const ASubject: IX509Name;
  const ASignatureAlgorithm: String; const ADnsSanName: string;
  AValidDaysCert: Integer): TCertificateArtifactsPem;
var
  LCrl: IX509Crl;
  LReq: IPkcs10CertificationRequest;
  LCert: IX509Certificate;
begin
  Result.PrivateKeyPem := TKeyEncodingExampleUtilities.ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Private));
  Result.CertificateRequestPem := '';
  Result.CertificatePem := '';
  Result.CrlPem := '';

  LCrl := CreateCrl(AKeyPair, ASubject, ASignatureAlgorithm);
  Result.CrlPem := TKeyEncodingExampleUtilities.ExportToPem(TValue.From<IX509Crl>(LCrl));

  LReq := CreateCertificationRequest(AKeyPair, ASubject, ASignatureAlgorithm, ADnsSanName);
  Result.CertificateRequestPem := TKeyEncodingExampleUtilities.ExportToPem(TValue.From<IPkcs10CertificationRequest>(LReq));

  LCert := CreateSelfSignedCertificate(AKeyPair, ASubject, ASignatureAlgorithm, AValidDaysCert);
  Result.CertificatePem := TKeyEncodingExampleUtilities.ExportToPem(TValue.From<IX509Certificate>(LCert));
end;

class function TCertificateExampleUtilities.ParseCrl(const ACrlEncoded: TBytes): IX509Crl;
var
  LParser: IX509CrlParser;
begin
  Result := nil;
  if (ACrlEncoded = nil) or (System.Length(ACrlEncoded) = 0) then
    Exit;
  LParser := TX509CrlParser.Create();
  Result := LParser.ReadCrl(ACrlEncoded);
end;

class function TCertificateExampleUtilities.VerifyCrl(const ACrl: IX509Crl;
  const AIssuerPublicKey: IAsymmetricKeyParameter): Boolean;
begin
  Result := False;
  if (ACrl = nil) or (AIssuerPublicKey = nil) then
    Exit;
  try
    ACrl.Verify(AIssuerPublicKey);
    Result := True;
  except
    Result := False;
  end;
end;

end.
