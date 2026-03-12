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

unit ClpCertificateExample;

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
  ClpDsaParameters,
  ClpDsaGenerators,
  ClpECParameters,
  ClpIECParameters,
  ClpIAsn1Objects,
  ClpSecObjectIdentifiers,
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
  ClpCryptoLibTypes,
  ClpIX509CrlEntry,
  ClpIX9ECAsn1Objects,
  ClpDateTimeUtilities,
  ClpExampleBase;

type
  TCertificateArtifactsPem = record
    PrivateKeyPem: string;
    CertificateRequestPem: string;
    CertificatePem: string;
    CrlPem: string;
  end;

  TCertificateExample = class(TExampleBase)
  public
    procedure Run; override;
  private
    procedure GetValidityUtc(AValidDays: Integer; out ANotBefore, ANotAfter: TDateTime);
    function BuildBasicEndEntityExtensions(const APublicKey: IAsymmetricKeyParameter): IX509Extensions;
    procedure LogCrlSummary(const ACrl: IX509Crl);
    procedure RunCrlImportVerify(const ACrlEncoded: TBytes;
      const AIssuerPublicKey: IAsymmetricKeyParameter);
    procedure RunCrlCreateExportVerifyRsa(const ASignatureAlgorithm: string);
    procedure RunCrlCreateExportVerifyEc(const ACurveName: string;
      const ASignatureAlgorithm: string);
    procedure RunCertificateArtifactsRsa(const ASignatureAlgorithm: string);
    procedure RunCertificateArtifactsEc(const ACurveName: string;
      const ASignatureAlgorithm: string);
    function BuildX509NameSubject: IX509Name;
    function CreateCrl(const AKeyPair: IAsymmetricCipherKeyPair;
      const AIssuer: IX509Name; const ASignatureAlgorithm: String): IX509Crl;
    function CreateCertificationRequest(const AKeyPair: IAsymmetricCipherKeyPair;
      const ASubject: IX509Name; const ASignatureAlgorithm: String): IPkcs10CertificationRequest;
    function CreateSelfSignedCertificate(const AKeyPair: IAsymmetricCipherKeyPair;
      const ASubject: IX509Name; const ASignatureAlgorithm: String;
      AValidDays: Integer): IX509Certificate;
    function CreateCertificateArtifacts(const AKeyPair: IAsymmetricCipherKeyPair;
      const ASubject: IX509Name; const ASignatureAlgorithm: String;
      AValidDaysCert: Integer): TCertificateArtifactsPem;
  end;

implementation

procedure TCertificateExample.GetValidityUtc(AValidDays: Integer; out ANotBefore, ANotAfter: TDateTime);
begin
  ANotBefore := TDateTimeUtilities.ToUniversalTime(Now);
  ANotAfter := IncSecond(ANotBefore, AValidDays * 86400);
end;

function TCertificateExample.BuildBasicEndEntityExtensions(const APublicKey: IAsymmetricKeyParameter): IX509Extensions;
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

function TCertificateExample.CreateCrl(const AKeyPair: IAsymmetricCipherKeyPair;
  const AIssuer: IX509Name; const ASignatureAlgorithm: String): IX509Crl;
var
  LCrlGen: IX509V2CrlGenerator;
  LThisUpdate, LNextUpdate: TDateTime;
begin
  GetValidityUtc(1, LThisUpdate, LNextUpdate);
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

procedure TCertificateExample.LogCrlSummary(const ACrl: IX509Crl);
var
  LRevoked: TCryptoLibGenericArray<IX509CrlEntry>;
  LRevokedCount: Int32;
begin
  if ACrl = nil then
    Exit;
  LRevoked := ACrl.GetRevokedCertificates();
  if LRevoked <> nil then
    LRevokedCount := System.Length(LRevoked)
  else
    LRevokedCount := 0;
  Logger.LogInformation('CRL issuer CN: {0}, revoked count: {1}',
    [ACrl.GetIssuerDN().ToString(TX509Name.CN), IntToStr(LRevokedCount)]);
end;

procedure TCertificateExample.RunCrlImportVerify(const ACrlEncoded: TBytes;
  const AIssuerPublicKey: IAsymmetricKeyParameter);
var
  LParser: IX509CrlParser;
  LCrl: IX509Crl;
begin
  Logger.LogInformation('--- Certificate example: CRL import and verify ---', []);
  if (ACrlEncoded = nil) or (System.Length(ACrlEncoded) = 0) then
  begin
    Logger.LogWarning('No CRL bytes to parse.', []);
    Exit;
  end;
  LParser := TX509CrlParser.Create();
  LCrl := LParser.ReadCrl(ACrlEncoded);
  if LCrl = nil then
  begin
    Logger.LogError('Failed to parse CRL.', []);
    Exit;
  end;
  try
    LCrl.Verify(AIssuerPublicKey);
    Logger.LogInformation('CRL signature verification passed.', []);
  except
    on E: Exception do
    begin
      Logger.LogError('CRL verify failed: {0}', [E.Message]);
      Exit;
    end;
  end;
  LogCrlSummary(LCrl);
  Logger.LogInformation('CRL this update: {0}{1}',
    [FormatDateTime('yyyy-mm-dd hh:nn:ss', LCrl.ThisUpdate), sLineBreak]);
end;

function TCertificateExample.BuildX509NameSubject: IX509Name;
var
  LBuilder: IX509NameBuilder;
begin
  LBuilder := TX509NameBuilder.Create();
  Result := LBuilder
    .AddCommonName('CryptoLib')
    .AddCountry('NG')
    .AddOrganization('CryptoLib4Pascal')
    .AddLocality('Alausa')
    .AddState('Lagos')
    .AddEmailAddress('feedback-crypto@cryptolib4pascal.org')
    .Build();
end;

function TCertificateExample.CreateCertificationRequest(const AKeyPair: IAsymmetricCipherKeyPair;
  const ASubject: IX509Name; const ASignatureAlgorithm: String): IPkcs10CertificationRequest;
var
  LBuilder: IPkcs10CertificationRequestBuilder;
  LDnsName: IGeneralName;
  LSanNames: IGeneralNames;
  LExtensions: IX509Extensions;
begin
  LExtensions := BuildBasicEndEntityExtensions(AKeyPair.Public);
  LDnsName := TGeneralName.Create(TGeneralName.DnsName, 'cryptolib4pascal.example.com');
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

function TCertificateExample.CreateSelfSignedCertificate(const AKeyPair: IAsymmetricCipherKeyPair;
  const ASubject: IX509Name; const ASignatureAlgorithm: String;
  AValidDays: Integer): IX509Certificate;
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

function TCertificateExample.CreateCertificateArtifacts(const AKeyPair: IAsymmetricCipherKeyPair;
  const ASubject: IX509Name; const ASignatureAlgorithm: String;
  AValidDaysCert: Integer): TCertificateArtifactsPem;
var
  LCrl: IX509Crl;
  LReq: IPkcs10CertificationRequest;
  LCert: IX509Certificate;
begin
  Result.PrivateKeyPem := ExportToPem(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Private));
  Result.CertificateRequestPem := '';
  Result.CertificatePem := '';
  Result.CrlPem := '';

  LCrl := CreateCrl(AKeyPair, ASubject, ASignatureAlgorithm);
  Result.CrlPem := ExportToPem(TValue.From<IX509Crl>(LCrl));

  LReq := CreateCertificationRequest(AKeyPair, ASubject, ASignatureAlgorithm);
  Result.CertificateRequestPem := ExportToPem(TValue.From<IPkcs10CertificationRequest>(LReq));

  LCert := CreateSelfSignedCertificate(AKeyPair, ASubject, ASignatureAlgorithm, AValidDaysCert);
  Result.CertificatePem := ExportToPem(TValue.From<IX509Certificate>(LCert));
end;

procedure TCertificateExample.RunCrlCreateExportVerifyRsa(const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LSubject: IX509Name;
  LCrl: IX509Crl;
  LCrlPem: string;
begin
  Logger.LogInformation('--- CRL: create, export to PEM, import and verify (RSA {0}) ---', [ASignatureAlgorithm]);
  LKp := GenerateRsaKeyPair();
  LSubject := BuildX509NameSubject();
  LCrl := CreateCrl(LKp, LSubject, ASignatureAlgorithm);
  LCrlPem := ExportToPem(TValue.From<IX509Crl>(LCrl));
  Logger.LogInformation('CRL PEM:{0}{1}', [sLineBreak, LCrlPem]);
  RunCrlImportVerify(LCrl.GetEncoded(), LKp.Public);
end;

procedure TCertificateExample.RunCrlCreateExportVerifyEc(const ACurveName: string;
  const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomainParams: IECDomainParameters;
  LSubject: IX509Name;
  LCrl: IX509Crl;
  LCrlPem: string;
begin
  Logger.LogInformation('--- CRL: create, export to PEM, import and verify (EC {0} {1}) ---', [ACurveName, ASignatureAlgorithm]);
  try
    LDomainParams := TECDomainParameters.LookupName(ACurveName);
  except
    on E: EArgumentCryptoLibException do
    begin
      Logger.LogWarning('Curve "{0}" not found: {1}', [ACurveName, E.Message]);
      Exit;
    end;
    on E: EArgumentNilCryptoLibException do
    begin
      Logger.LogWarning('Curve name empty.', []);
      Exit;
    end;
  end;
  LKp := GenerateEcKeyPair(LDomainParams);
  LSubject := BuildX509NameSubject();
  LCrl := CreateCrl(LKp, LSubject, ASignatureAlgorithm);
  LCrlPem := ExportToPem(TValue.From<IX509Crl>(LCrl));
  Logger.LogInformation('CRL PEM:{0}{1}', [sLineBreak, LCrlPem]);
  RunCrlImportVerify(LCrl.GetEncoded(), LKp.Public);
end;

procedure TCertificateExample.RunCertificateArtifactsRsa(const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LSubject: IX509Name;
  LArtifacts: TCertificateArtifactsPem;
begin
  Logger.LogInformation('--- Certificate artifacts: RSA ({0}) ---', [ASignatureAlgorithm]);
  LKp := GenerateRsaKeyPair();
  LSubject := BuildX509NameSubject();
  LArtifacts := CreateCertificateArtifacts(LKp, LSubject, ASignatureAlgorithm, 365);

  Logger.LogInformation('Private key PEM:{0}{1}', [sLineBreak, LArtifacts.PrivateKeyPem]);
  Logger.LogInformation('Certificate request PEM:{0}{1}', [sLineBreak, LArtifacts.CertificateRequestPem]);
  Logger.LogInformation('Certificate PEM:{0}{1}', [sLineBreak, LArtifacts.CertificatePem]);
  Logger.LogInformation('CRL PEM:{0}{1}', [sLineBreak, LArtifacts.CrlPem]);
end;

procedure TCertificateExample.RunCertificateArtifactsEc(const ACurveName: string;
  const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomainParams: IECDomainParameters;
  LSubject: IX509Name;
  LArtifacts: TCertificateArtifactsPem;
begin
  Logger.LogInformation('--- Certificate artifacts: EC {0} ({1}) ---', [ACurveName, ASignatureAlgorithm]);
  try
    LDomainParams := TECDomainParameters.LookupName(ACurveName);
  except
    on E: EArgumentCryptoLibException do
    begin
      Logger.LogWarning('Curve "{0}" not found: {1}', [ACurveName, E.Message]);
      Exit;
    end;
    on E: EArgumentNilCryptoLibException do
    begin
      Logger.LogWarning('Curve name empty.', []);
      Exit;
    end;
  end;
  LKp := GenerateEcKeyPair(LDomainParams);
  LSubject := BuildX509NameSubject();
  LArtifacts := CreateCertificateArtifacts(LKp, LSubject, ASignatureAlgorithm, 365);

  Logger.LogInformation('Private key PEM:{0}{1}', [sLineBreak, LArtifacts.PrivateKeyPem]);
  Logger.LogInformation('Certificate request PEM:{0}{1}', [sLineBreak, LArtifacts.CertificateRequestPem]);
  Logger.LogInformation('Certificate PEM:{0}{1}', [sLineBreak, LArtifacts.CertificatePem]);
  Logger.LogInformation('CRL PEM:{0}{1}', [sLineBreak, LArtifacts.CrlPem]);
end;

procedure TCertificateExample.Run;
begin
  LogWithLineBreak('--- Certificate example: CRL, CSR, self-signed cert (all to PEM) ---');

  RunCertificateArtifactsRsa('SHA256WithRSAEncryption');
  RunCertificateArtifactsEc('P-256', 'SHA256withECDSA');
  RunCertificateArtifactsEc('secp256k1', 'SHA256withECDSA');

  RunCrlCreateExportVerifyRsa('SHA256WithRSAEncryption');
  RunCrlCreateExportVerifyEc('P-256', 'SHA256withECDSA');
  RunCrlCreateExportVerifyEc('secp256k1', 'SHA256withECDSA');
end;

end.
