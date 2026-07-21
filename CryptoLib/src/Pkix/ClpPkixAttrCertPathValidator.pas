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

unit ClpPkixAttrCertPathValidator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIX509Certificate,
  ClpIX509V2AttributeCertificate,
  ClpIX509StoreSelectors,
  ClpIPkixTypes,
  ClpRfc3281CertPathUtilities,
  ClpPkixCertPathValidatorUtilities,
  ClpDateTimeHelper,
  ClpCryptoLibTypes;

resourcestring
  STargetConstraintsNotAttrCert =
    'the target constraints must be an attribute certificate store selector';

type
  /// <summary>
  /// Validates an X.509 attribute certificate against the certification path of its issuer public
  /// key certificate, following the attribute certificate validation algorithm of RFC 3281 5.
  /// </summary>
  TPkixAttrCertPathValidator = class(TInterfacedObject, IPkixAttrCertPathValidator)

  public
    /// <summary>
    /// Validate the attribute certificate named by the target constraints against ACertPath, the
    /// certification path belonging to the attribute certificate issuer public key certificate.
    /// </summary>
    function Validate(const ACertPath: IPkixCertPath; const AParams: IPkixParameters)
      : IPkixCertPathValidatorResult;
  end;

implementation

{ TPkixAttrCertPathValidator }

function TPkixAttrCertPathValidator.Validate(const ACertPath: IPkixCertPath;
  const AParams: IPkixParameters): IPkixCertPathValidatorResult;
var
  LAttrCertSelector: IX509AttrCertStoreSelector;
  LAttrCert: IX509V2AttributeCertificate;
  LHolderCertPath: IPkixCertPath;
  LCerts: TCryptoLibGenericArray<IX509Certificate>;
  LIssuerCert: IX509Certificate;
  LCurrentDate, LValidityDate: TDateTime;
begin
  if not Supports(AParams.GetTargetConstraintsAttrCert(), IX509AttrCertStoreSelector, LAttrCertSelector) then
    raise EArgumentCryptoLibException.CreateRes(@STargetConstraintsNotAttrCert);

  // dates in this layer are UTC
  LCurrentDate := Now.ToUniversalTime();
  LValidityDate := TPkixCertPathValidatorUtilities.GetValidityDate(AParams, LCurrentDate);

  LAttrCert := LAttrCertSelector.AttributeCert;

  // step 1: locate the holder public key certificate and build a validated path to it
  LHolderCertPath := TRfc3281CertPathUtilities.ProcessAttrCert1(LAttrCert, AParams);

  // step 2 (a): validate the certification path of the AC issuer certificate; its result is returned
  Result := TRfc3281CertPathUtilities.ProcessAttrCert2A(ACertPath, AParams);

  LCerts := ACertPath.Certificates;
  LIssuerCert := LCerts[0];

  // step 2 (b): the AC signature must verify under the issuer public key
  TRfc3281CertPathUtilities.ProcessAttrCert2B(LAttrCert, LIssuerCert);

  // step 3: the issuer key must permit digital signatures and not also be a public key CA
  TRfc3281CertPathUtilities.ProcessAttrCert3(LIssuerCert, AParams);

  // step 4: the issuer must be one of the directly trusted AC issuers
  TRfc3281CertPathUtilities.ProcessAttrCert4(LIssuerCert, AParams);

  // step 5: the attribute certificate must be within its validity period
  TRfc3281CertPathUtilities.ProcessAttrCert5(LAttrCert, LValidityDate);

  // step 6 is already satisfied by the attribute certificate store selector

  // step 7: process the AC extensions and run every configured checker
  TRfc3281CertPathUtilities.ProcessAttrCert7(LAttrCert, ACertPath, LHolderCertPath, AParams);

  // RFC 3281 4.3: reject a prohibited attribute or a missing necessary one
  TRfc3281CertPathUtilities.AdditionalChecks(LAttrCert, AParams);

  // revocation status of the attribute certificate
  TRfc3281CertPathUtilities.CheckCrls(LAttrCert, AParams, LCurrentDate, LValidityDate, LIssuerCert, LCerts);
end;

end.
