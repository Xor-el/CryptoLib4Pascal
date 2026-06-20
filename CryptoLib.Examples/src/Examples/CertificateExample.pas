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

unit CertificateExample;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$HINTS OFF}
{$WARNINGS OFF}
{$ENDIF FPC}

uses
  SysUtils,
  Rtti,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Crl,
  ClpIX509CrlEntry,
  ClpIX509Certificate,
  ClpIAsymmetricCipherKeyPair,
  ClpIAsymmetricKeyParameter,
  ClpX509Certificate,
  ClpCryptoLibTypes,
  ClpStringUtilities,
  ExampleBase,
  AsymmetricExampleUtilities,
  KeyEncodingExampleUtilities,
  CertificateExampleUtilities;

type
  TCertificateExample = class(TExampleBase)
  private
    function BuildDemoSubject: IX509Name;
    function IsRsaKeySpec(const AKeySpec: string): Boolean;
    procedure LogCrlSummary(const ACrl: IX509Crl);
    procedure LogCertificateArtifactsPem(const AArtifacts: TCertificateArtifactsPem);
    procedure RunCrlImportVerify(const ACrlEncoded: TBytes;
      const AIssuerPublicKey: IAsymmetricKeyParameter);
    procedure RunCrlCreateExportVerify(const AKeySpec, ASignatureAlgorithm: string);
    procedure RunCertificateArtifacts(const AKeySpec, ASignatureAlgorithm: string;
      AValidDaysCert: Integer);
    procedure RunCertificateDemos;
  public
    procedure Run; override;
  end;

implementation

function TCertificateExample.BuildDemoSubject: IX509Name;
begin
  Result := TCertificateExampleUtilities.BuildX509Name(
    'CryptoLib', 'NG', 'CryptoLib4Pascal', 'Alausa', 'Lagos',
    'feedback-crypto@cryptolib4pascal.org');
end;

function TCertificateExample.IsRsaKeySpec(const AKeySpec: string): Boolean;
begin
  Result := SameText(AKeySpec, 'RSA') or TStringUtilities.StartsWith(AKeySpec, 'RSA-', True);
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

procedure TCertificateExample.LogCertificateArtifactsPem(const AArtifacts: TCertificateArtifactsPem);
begin
  Logger.LogInformation('Private key PEM:{0}{1}', [sLineBreak, AArtifacts.PrivateKeyPem]);
  Logger.LogInformation('Certificate request PEM:{0}{1}', [sLineBreak, AArtifacts.CertificateRequestPem]);
  Logger.LogInformation('Certificate PEM:{0}{1}', [sLineBreak, AArtifacts.CertificatePem]);
  Logger.LogInformation('CRL PEM:{0}{1}', [sLineBreak, AArtifacts.CrlPem]);
end;

procedure TCertificateExample.RunCrlImportVerify(const ACrlEncoded: TBytes;
  const AIssuerPublicKey: IAsymmetricKeyParameter);
var
  LCrl: IX509Crl;
begin
  Logger.LogInformation('--- Certificate example: CRL import and verify ---', []);
  LCrl := TCertificateExampleUtilities.ParseCrl(ACrlEncoded);
  if LCrl = nil then
  begin
    Logger.LogError('Failed to parse CRL.', []);
    Exit;
  end;
  if TCertificateExampleUtilities.VerifyCrl(LCrl, AIssuerPublicKey) then
    Logger.LogInformation('CRL signature verification passed.', [])
  else
  begin
    Logger.LogError('CRL verify failed.', []);
    Exit;
  end;
  LogCrlSummary(LCrl);
  Logger.LogInformation('CRL this update: {0}{1}',
    [FormatDateTime('yyyy-mm-dd hh:nn:ss', LCrl.ThisUpdate), sLineBreak]);
end;

procedure TCertificateExample.RunCrlCreateExportVerify(const AKeySpec, ASignatureAlgorithm: string);
var
  LKp: IAsymmetricCipherKeyPair;
  LSubject: IX509Name;
  LCrl: IX509Crl;
  LCrlPem: string;
begin
  if IsRsaKeySpec(AKeySpec) then
    Logger.LogInformation('--- CRL: create, export to PEM, import and verify (RSA {0}) ---', [ASignatureAlgorithm])
  else
    Logger.LogInformation('--- CRL: create, export to PEM, import and verify (EC {0} {1}) ---', [AKeySpec, ASignatureAlgorithm]);
  if not TAsymmetricExampleUtilities.TryGenerateKeyPair(AKeySpec, LKp) then
    Exit;
  LSubject := BuildDemoSubject();
  LCrl := TCertificateExampleUtilities.CreateCrl(LKp, LSubject, ASignatureAlgorithm);
  LCrlPem := TKeyEncodingExampleUtilities.ExportToPem(TValue.From<IX509Crl>(LCrl));
  Logger.LogInformation('CRL PEM:{0}{1}', [sLineBreak, LCrlPem]);
  RunCrlImportVerify(LCrl.GetEncoded(), LKp.Public);
end;

procedure TCertificateExample.RunCertificateArtifacts(const AKeySpec, ASignatureAlgorithm: string;
  AValidDaysCert: Integer);
var
  LKp: IAsymmetricCipherKeyPair;
  LSubject: IX509Name;
  LArtifacts: TCertificateArtifactsPem;
const
  DemoDnsSan = 'cryptolib4pascal.example.com';
begin
  if IsRsaKeySpec(AKeySpec) then
    Logger.LogInformation('--- Certificate artifacts: RSA ({0}) ---', [ASignatureAlgorithm])
  else
    Logger.LogInformation('--- Certificate artifacts: EC {0} ({1}) ---', [AKeySpec, ASignatureAlgorithm]);
  if not TAsymmetricExampleUtilities.TryGenerateKeyPair(AKeySpec, LKp) then
    Exit;
  LSubject := BuildDemoSubject();
  LArtifacts := TCertificateExampleUtilities.CreateCertificateArtifacts(LKp, LSubject,
    ASignatureAlgorithm, DemoDnsSan, AValidDaysCert);
  LogCertificateArtifactsPem(LArtifacts);
end;

procedure TCertificateExample.RunCertificateDemos;
begin
  LogWithLineBreak('--- Certificate example: CRL, CSR, self-signed cert (all to PEM) ---');

  RunCertificateArtifacts('RSA', 'SHA256WithRSAEncryption', 365);
  RunCertificateArtifacts('P-256', 'SHA256withECDSA', 365);
  RunCertificateArtifacts('secp256k1', 'SHA256withECDSA', 365);

  RunCrlCreateExportVerify('RSA', 'SHA256WithRSAEncryption');
  RunCrlCreateExportVerify('P-256', 'SHA256withECDSA');
  RunCrlCreateExportVerify('secp256k1', 'SHA256withECDSA');
end;

procedure TCertificateExample.Run;
begin
  RunCertificateDemos;
end;

end.
