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
  ClpIX509Crl,
  ClpIX509Generators,
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
  ClpExampleBase;

type
  TCertRequestPem = record
    PrivateKeyPem: string;
    CertificateRequestPem: string;
  end;

  TCertificateExample = class(TExampleBase)
  public
    procedure Run; override;
  private
    procedure RunCrlCreateExport;
    procedure RunCrlRsa;
    procedure RunCrlImportVerify(const ACrlEncoded: TBytes;
      const AIssuerPublicKey: IAsymmetricKeyParameter);
    procedure RunCertRequestCreateExportPem;
    procedure RunCertRequestRsa(const ASignatureAlgorithm: string);
    procedure RunCertRequestEc(const ACurveName: string;
      const ASignatureAlgorithm: string);
    function BuildX509NameSubject: IX509Name;
    function CreateCrlEncoded(const AKeyPair: IAsymmetricCipherKeyPair;
      const AIssuer: IX509Name; const ASignatureAlgorithm: String): TBytes;
    function CreateCertRequestPem(const AKeyPair: IAsymmetricCipherKeyPair;
      const ASubject: IX509Name; const ASignatureAlgorithm: String): TCertRequestPem;
  end;

implementation

function TCertificateExample.CreateCrlEncoded(const AKeyPair: IAsymmetricCipherKeyPair;
  const AIssuer: IX509Name; const ASignatureAlgorithm: String): TBytes;
var
  LCrlGen: IX509V2CrlGenerator;
  LCrl: IX509Crl;
  LUtc: TDateTime;
begin
  LUtc := TTimeZone.Local.ToUniversalTime(Now);
  LCrlGen := TX509V2CrlGenerator.Create();
  LCrlGen.SetIssuerDN(AIssuer);
  LCrlGen.SetThisUpdateUtc(LUtc);
  LCrlGen.SetNextUpdateUtc(IncSecond(LUtc, 86400));
  LCrlGen.AddCrlEntryUtc(TBigInteger.One, LUtc, 0);
  LCrlGen.AddExtension(TX509Extensions.AuthorityKeyIdentifier, False,
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(
      TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AKeyPair.Public)));
  LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create(ASignatureAlgorithm,
    AKeyPair.Private, nil) as ISignatureFactory);
  Result := LCrl.GetEncoded();
end;

procedure TCertificateExample.RunCrlRsa;
var
  LKp: IAsymmetricCipherKeyPair;
  LIssuer: IX509Name;
  LEncoded: TBytes;
  LParser: IX509CrlParser;
  LCrl: IX509Crl;
  LRevoked: TCryptoLibGenericArray<IX509CrlEntry>;
  LRevokedCount: Int32;
begin
  Logger.LogInformation('--- CRL: RSA ---', []);
  LKp := GenerateRsaKeyPair;
  LIssuer := BuildX509NameSubject();
  LEncoded := CreateCrlEncoded(LKp, LIssuer, 'SHA256WithRSAEncryption');
  LParser := TX509CrlParser.Create();
  LCrl := LParser.ReadCrl(LEncoded);
  if LCrl <> nil then
  begin
    LRevoked := LCrl.GetRevokedCertificates();
    if LRevoked <> nil then
      LRevokedCount := System.Length(LRevoked)
    else
      LRevokedCount := 0;
    Logger.LogInformation('CRL created, common name {0}, revoked count={1}, encoded length={2}',
      [LCrl.GetIssuerDN().ToString(TX509Name.CN), IntToStr(LRevokedCount), IntToStr(System.Length(LEncoded))]);
  end
  else
    Logger.LogInformation('CRL created, encoded length={0}', [IntToStr(System.Length(LEncoded))]);
  RunCrlImportVerify(LEncoded, LKp.Public);
end;

procedure TCertificateExample.RunCrlCreateExport;
begin
  Logger.LogInformation('--- Certificate example: CRL create and export ---', []);
  RunCrlRsa;
end;

procedure TCertificateExample.RunCrlImportVerify(const ACrlEncoded: TBytes;
  const AIssuerPublicKey: IAsymmetricKeyParameter);
var
  LParser: IX509CrlParser;
  LCrl: IX509Crl;
  LRevoked: TCryptoLibGenericArray<IX509CrlEntry>;
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
  LRevoked := LCrl.GetRevokedCertificates();
  if LRevoked <> nil then
    Logger.LogInformation('CRL revoked certificates count: {0}', [IntToStr(System.Length(LRevoked))])
  else
    Logger.LogInformation('CRL revoked certificates count: 0', []);
  Logger.LogInformation('CRL this update: {0}',
    [FormatDateTime('yyyy-mm-dd hh:nn:ss', LCrl.ThisUpdate)]);
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

function TCertificateExample.CreateCertRequestPem(const AKeyPair: IAsymmetricCipherKeyPair;
  const ASubject: IX509Name; const ASignatureAlgorithm: String): TCertRequestPem;
var
  LBuilder: IPkcs10CertificationRequestBuilder;
  LReq: IPkcs10CertificationRequest;
  LDnsName: IGeneralName;
  LSanNames: IGeneralNames;
  LExtGen: IX509ExtensionsGenerator;
  LExtensions: IX509Extensions;
begin
  LDnsName := TGeneralName.Create(TGeneralName.DnsName, 'cryptolib4pascal.example.com');
  LSanNames := TGeneralNames.Create(LDnsName);

  LExtGen := TX509ExtensionsGenerator.Create();
  LExtGen.AddExtension(TX509Extensions.BasicConstraints, True,
    TBasicConstraints.Create(False) as IBasicConstraints);
  LExtGen.AddExtension(TX509Extensions.KeyUsage, True,
    TKeyUsage.Create(TKeyUsage.DigitalSignature or TKeyUsage.KeyEncipherment) as IKeyUsage);
  LExtensions := LExtGen.Generate();

  LBuilder := TPkcs10CertificationRequestBuilder.Create();
  LReq := LBuilder
    .SetSubject(ASubject)
    .SetKeyPair(AKeyPair)
    .SetSignatureAlgorithm(ASignatureAlgorithm)
    .AddExtensions(LExtensions)
    .AddExtension(TX509Extensions.SubjectAlternativeName, False, LSanNames)
    .AddSubjectKeyIdentifier(False)
    .Build();

  Result.PrivateKeyPem := ExportToPem(
    TValue.From<IAsymmetricKeyParameter>(AKeyPair.Private));
  Result.CertificateRequestPem := ExportToPem(
    TValue.From<IPkcs10CertificationRequest>(LReq));
end;

procedure TCertificateExample.RunCertRequestRsa(const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LPem: TCertRequestPem;
begin
  Logger.LogInformation('--- Certificate request: RSA ---', []);
  Logger.LogInformation('Algorithm: {0}', [ASignatureAlgorithm]);
  LKp := GenerateRsaKeyPair;
  LPem := CreateCertRequestPem(LKp, BuildX509NameSubject(), ASignatureAlgorithm);
  Logger.LogInformation('Private key PEM (RSA {0}):{1}{2}',
    [ASignatureAlgorithm, sLineBreak, LPem.PrivateKeyPem]);
  Logger.LogInformation('Certificate request PEM (RSA {0}):{1}{2}',
    [ASignatureAlgorithm, sLineBreak, LPem.CertificateRequestPem]);
end;

procedure TCertificateExample.RunCertRequestEc(const ACurveName: string;
  const ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LDomainParams: IECDomainParameters;
  LPem: TCertRequestPem;
begin
  Logger.LogInformation('--- Certificate request: EC ---', []);
  Logger.LogInformation('Curve: {0}, algorithm: {1}', [ACurveName, ASignatureAlgorithm]);
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
  LPem := CreateCertRequestPem(LKp, BuildX509NameSubject(), ASignatureAlgorithm);
  Logger.LogInformation('Private key PEM (EC {0} {1}):{2}{3}',
    [ACurveName, ASignatureAlgorithm, sLineBreak, LPem.PrivateKeyPem]);
  Logger.LogInformation('Certificate request PEM (EC {0} {1}):{2}{3}',
    [ACurveName, ASignatureAlgorithm, sLineBreak, LPem.CertificateRequestPem]);
end;

procedure TCertificateExample.RunCertRequestCreateExportPem;
begin
  LogWithLineBreak('--- Certificate example: Create and export certificate request as PEM ---');
  RunCertRequestRsa('SHA-256withRSA');
  RunCertRequestRsa('SHA256WITHRSAANDMGF1');

  RunCertRequestEc('P-256', 'SHA256withECDSA');
  RunCertRequestEc('secp256k1', 'SHA256withECDSA');
end;

procedure TCertificateExample.Run;
begin
  RunCrlCreateExport;
  RunCertRequestCreateExportPem;
end;

end.
