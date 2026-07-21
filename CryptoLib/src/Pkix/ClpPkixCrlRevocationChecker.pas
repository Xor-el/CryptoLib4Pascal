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

unit ClpPkixCrlRevocationChecker;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIX509Certificate,
  ClpIPkixTypes,
  ClpRfc3280CertPathUtilities,
  ClpDateTimeHelper,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCrlNotInitialized = 'the CRL revocation checker was not initialized';

type
  /// <summary>
  /// Settles the revocation status of a certificate from the CRLs reachable through the validation
  /// parameters (RFC 5280 6.3).
  /// </summary>
  TPkixCrlRevocationChecker = class sealed(TInterfacedObject, IPkixCertRevocationChecker)

  strict private
  var
    FParameters: IPkixCertRevocationCheckerParameters;
    FCurrentDate: TDateTime;

  public
    procedure Initialize(const AParameters: IPkixCertRevocationCheckerParameters);

    /// <exception cref="EPkixCertPathValidatorCryptoLibException">
    /// When the certificate is revoked or its status cannot be established. The failure always
    /// carries the position of the certificate in the path.
    /// </exception>
    procedure Check(const ACert: IX509Certificate);
  end;

implementation

{ TPkixCrlRevocationChecker }

procedure TPkixCrlRevocationChecker.Initialize(const AParameters
  : IPkixCertRevocationCheckerParameters);
begin
  FParameters := AParameters;
  FCurrentDate := Now.ToUniversalTime();
end;

procedure TPkixCrlRevocationChecker.Check(const ACert: IX509Certificate);
var
  LParameters: IPkixCertRevocationCheckerParameters;
  LCertPath: IPkixCertPath;
  LCertPathCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  LParameters := FParameters;
  if LParameters = nil then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SCrlNotInitialized);

  LCertPath := LParameters.CertPath;
  if LCertPath <> nil then
    LCertPathCerts := LCertPath.Certificates
  else
    LCertPathCerts := nil;

  try
    TRfc3280CertPathUtilities.CheckCrls(LParameters.PkixParameters, ACert, FCurrentDate,
      LParameters.ValidDate, LParameters.SigningCert, LParameters.WorkingPublicKey, LCertPathCerts);
  except
    // the CRL machinery works per certificate but does not track its position, so blame the
    // certificate being checked rather than letting the failure surface unattributed
    on E: EPkixCertPathValidatorCryptoLibException do
    begin
      if E.Index >= 0 then
        raise;
      raise EPkixCertPathValidatorCryptoLibException.CreateAt(LParameters.Index, E.Message);
    end;
  end;
end;

end.
