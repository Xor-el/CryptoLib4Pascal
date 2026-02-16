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
{$ENDIF FPC}

uses
  SysUtils,
  Classes,
  Rtti,
  DateUtils,
  ClpGeneratorUtilities,
  ClpSecureRandom,
  ClpBigInteger,
  ClpRsaParameters,
  ClpIRsaParameters,
  ClpDsaParameters,
  ClpDsaGenerators,
  ClpECParameters,
  ClpIECParameters,
  ClpECGenerators,
  ClpECUtilities,
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
  ClpIOpenSslPemWriter,
  ClpOpenSslPemWriter,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpIAsymmetricKeyParameter,
  ClpISignatureFactory,
  ClpIKeyGenerationParameters,
  ClpISecureRandom,
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
    procedure RunCrlImportVerify(const ACrlEncoded: TBytes; const AIssuerPublicKey: IAsymmetricKeyParameter);
    procedure RunCertRequestCreateExportPem;
    procedure RunCertRequestRsa(const ASignatureAlgorithm: string);
    procedure RunCertRequestEc(const ACurveName: string; const ASignatureAlgorithm: string);
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
    TX509ExtensionUtilities.CreateAuthorityKeyIdentifier(TSubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(AKeyPair.Public)));
  LCrl := LCrlGen.Generate(TAsn1SignatureFactory.Create(ASignatureAlgorithm, AKeyPair.Private, nil) as ISignatureFactory);
  Result := LCrl.GetEncoded();
end;

procedure TCertificateExample.RunCrlRsa;
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LIssuer: IX509Name;
  LEncoded: TBytes;
  LParser: IX509CrlParser;
  LCrl: IX509Crl;
  LRevoked: TCryptoLibGenericArray<IX509CrlEntry>;
  LRevokedCount: Int32;
begin
  Logger.LogInformation('--- CRL: RSA ---');
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(65537),
    TSecureRandom.Create() as ISecureRandom, 2048, 25) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
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
    Logger.LogInformation(Format('CRL created, common name %s, revoked count=%d, encoded length=%d',
      [LCrl.GetIssuerDN().ToString(TX509Name.CN), LRevokedCount, System.Length(LEncoded)]));
  end
  else
    Logger.LogInformation(Format('CRL created, encoded length=%d', [System.Length(LEncoded)]));
  RunCrlImportVerify(LEncoded, LKp.Public);
end;

procedure TCertificateExample.RunCrlCreateExport;
begin
  Logger.LogInformation('--- Certificate example: CRL create and export ---');
  RunCrlRsa;
end;

procedure TCertificateExample.RunCrlImportVerify(const ACrlEncoded: TBytes; const AIssuerPublicKey: IAsymmetricKeyParameter);
var
  LParser: IX509CrlParser;
  LCrl: IX509Crl;
  LRevoked: TCryptoLibGenericArray<IX509CrlEntry>;
begin
  Logger.LogInformation('--- Certificate example: CRL import and verify ---');
  if (ACrlEncoded = nil) or (System.Length(ACrlEncoded) = 0) then
  begin
    Logger.LogWarning('No CRL bytes to parse.');
    Exit;
  end;
  LParser := TX509CrlParser.Create();
  LCrl := LParser.ReadCrl(ACrlEncoded);
  if LCrl = nil then
  begin
    Logger.LogError('Failed to parse CRL.');
    Exit;
  end;
  try
    LCrl.Verify(AIssuerPublicKey);
    Logger.LogInformation('CRL signature verification passed.');
  except
    on E: Exception do
    begin
      Logger.LogError('CRL verify failed: ' + E.Message);
      Exit;
    end;
  end;
  LRevoked := LCrl.GetRevokedCertificates();
  if LRevoked <> nil then
    Logger.LogInformation(Format('CRL revoked certificates count: %d', [System.Length(LRevoked)]))
  else
    Logger.LogInformation('CRL revoked certificates count: 0');
  Logger.LogInformation(Format('CRL this update: %s', [FormatDateTime('yyyy-mm-dd hh:nn:ss', LCrl.ThisUpdate)]));
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
  LKeyStream, LReqStream: TStringStream;
  LWriter: IOpenSslPemWriter;
begin
  LDnsName := TGeneralName.Create(TGeneralName.DnsName, 'cryptolib4pascal.example.com');
  LSanNames := TGeneralNames.Create(LDnsName);

  // Build some extensions via TX509ExtensionsGenerator for AddExtensions demo
  LExtGen := TX509ExtensionsGenerator.Create();
  LExtGen.AddExtension(TX509Extensions.BasicConstraints, True, TBasicConstraints.Create(False) as IBasicConstraints);
  LExtGen.AddExtension(TX509Extensions.KeyUsage, True,
    TKeyUsage.Create(TKeyUsage.DigitalSignature or TKeyUsage.KeyEncipherment) as IKeyUsage);
  LExtensions := LExtGen.Generate();

  LBuilder := TPkcs10CertificationRequestBuilder.Create();
  LReq := LBuilder
    .SetSubject(ASubject)
    .SetKeyPair(AKeyPair)
    .SetSignatureAlgorithm(ASignatureAlgorithm)
    // Bulk: add BasicConstraints + KeyUsage from pre-built IX509Extensions
    .AddExtensions(LExtensions)
    // Generic: add SubjectAlternativeName via AddExtension(OID, critical, value)
    .AddExtension(TX509Extensions.SubjectAlternativeName, False, LSanNames)
    // Convenience: SubjectKeyIdentifier computed from public key
    .AddSubjectKeyIdentifier(False)
    .Build();

  LKeyStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TOpenSslPemWriter.Create(LKeyStream);
    LWriter.WriteObject(TValue.From<IAsymmetricKeyParameter>(AKeyPair.Private));
    Result.PrivateKeyPem := LKeyStream.DataString;
  finally
    LKeyStream.Free;
  end;

  LReqStream := TStringStream.Create('', TEncoding.ASCII);
  try
    LWriter := TOpenSslPemWriter.Create(LReqStream);
    LWriter.WriteObject(TValue.From<IPkcs10CertificationRequest>(LReq));
    Result.CertificateRequestPem := LReqStream.DataString;
  finally
    LReqStream.Free;
  end;
end;

procedure TCertificateExample.RunCertRequestRsa(const ASignatureAlgorithm: string);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LPem: TCertRequestPem;
begin
  Logger.LogInformation('--- Certificate request: RSA ---');
  Logger.LogInformation('Algorithm: ' + ASignatureAlgorithm);
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LKpg.Init(TRsaKeyGenerationParameters.Create(TBigInteger.ValueOf(65537),
    TSecureRandom.Create() as ISecureRandom, 2048, 25) as IKeyGenerationParameters);
  LKp := LKpg.GenerateKeyPair();
  LPem := CreateCertRequestPem(LKp, BuildX509NameSubject(), ASignatureAlgorithm);
  Logger.LogInformation('Private key PEM (RSA ' + ASignatureAlgorithm + '):');
  Logger.LogInformation(LPem.PrivateKeyPem);
  Logger.LogInformation('Certificate request PEM (RSA ' + ASignatureAlgorithm + '):');
  Logger.LogInformation(LPem.CertificateRequestPem);
end;

procedure TCertificateExample.RunCertRequestEc(const ACurveName: string; const ASignatureAlgorithm: string);
var
  LKpg: IAsymmetricCipherKeyPairGenerator;
  LKp: IAsymmetricCipherKeyPair;
  LSecRandom: ISecureRandom;
  LDomainParams: IECDomainParameters;
  LEcKeyParams: IKeyGenerationParameters;
  LPem: TCertRequestPem;
begin
  Logger.LogInformation('--- Certificate request: EC ---');
  Logger.LogInformation('Curve: ' + ACurveName + ', algorithm: ' + ASignatureAlgorithm);
  LSecRandom := TSecureRandom.Create();
  try
    LDomainParams := TECDomainParameters.LookupName(ACurveName);
  except
    on E: EArgumentCryptoLibException do
    begin
      Logger.LogWarning('Curve "' + ACurveName + '" not found: ' + E.Message);
      Exit;
    end;
    on E: EArgumentNilCryptoLibException do
    begin
      Logger.LogWarning('Curve name empty.');
      Exit;
    end;
  end;
  LEcKeyParams := TECKeyGenerationParameters.Create(LDomainParams, LSecRandom) as IKeyGenerationParameters;
  LKpg := TGeneratorUtilities.GetKeyPairGenerator('EC');
  LKpg.Init(LEcKeyParams);
  LKp := LKpg.GenerateKeyPair();
  LPem := CreateCertRequestPem(LKp, BuildX509NameSubject(), ASignatureAlgorithm);
  Logger.LogInformation('Private key PEM (EC ' + ACurveName + ' ' + ASignatureAlgorithm + '):');
  Logger.LogInformation(LPem.PrivateKeyPem);
  Logger.LogInformation('Certificate request PEM (EC ' + ACurveName + ' ' + ASignatureAlgorithm + '):');
  Logger.LogInformation(LPem.CertificateRequestPem);
end;

procedure TCertificateExample.RunCertRequestCreateExportPem;
begin
  Logger.LogInformation('--- Certificate example: Create and export certificate request as PEM ---');
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
