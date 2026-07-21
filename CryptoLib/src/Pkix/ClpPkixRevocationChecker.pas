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

unit ClpPkixRevocationChecker;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIX509Certificate,
  ClpIOcspProtocolObjects,
  ClpIPkixTypes,
  ClpPkixOcspRevocationChecker,
  ClpPkixCrlRevocationChecker,
  ClpCryptoLibTypes;

resourcestring
  SForwardCheckingUnsupported = 'forward checking is not supported by the revocation checker';

type
  /// <summary>
  /// The revocation status check of RFC 5280 6.1.3 (a)(3) over both mechanisms: the OCSP responses
  /// the caller already holds (RFC 6960) are consulted first, and the CRL path answers whenever
  /// they cannot settle the status.
  /// </summary>
  /// <remarks>
  /// Placing one of these among the certification path checkers is how a caller feeds OCSP
  /// responses into path validation; the validator takes it over as the revocation check rather
  /// than running it as an ordinary path checker.
  /// </remarks>
  TPkixRevocationChecker = class sealed(TInterfacedObject, IPkixCertPathChecker,
    IPkixCertRevocationChecker)

  strict private
  var
    FResponses: TCryptoLibGenericArray<IBasicOcspResp>;
    FOcspChecker, FCrlChecker: IPkixCertRevocationChecker;

  public
    /// <summary>
    /// Build a checker over the OCSP responses the caller already holds; an empty set leaves
    /// revocation checking on CRLs alone.
    /// </summary>
    constructor Create(const AResponses: TCryptoLibGenericArray<IBasicOcspResp>);

    // IPkixCertRevocationChecker
    procedure Initialize(const AParameters: IPkixCertRevocationCheckerParameters);
    procedure Check(const ACert: IX509Certificate); overload;

    // IPkixCertPathChecker
    procedure Init(AForward: Boolean);
    function IsForwardCheckingSupported: Boolean;
    function GetSupportedExtensions: TCryptoLibStringArray;
    procedure Check(const ACert: IX509Certificate;
      const AUnresolvedCritExts: TList<String>); overload;
    function Clone: IPkixCertPathChecker;
  end;

implementation

{ TPkixRevocationChecker }

constructor TPkixRevocationChecker.Create(const AResponses
  : TCryptoLibGenericArray<IBasicOcspResp>);
begin
  inherited Create();
  FResponses := System.Copy(AResponses);
  FOcspChecker := TPkixOcspRevocationChecker.Create(FResponses) as IPkixCertRevocationChecker;
  FCrlChecker := TPkixCrlRevocationChecker.Create() as IPkixCertRevocationChecker;
end;

procedure TPkixRevocationChecker.Initialize(const AParameters
  : IPkixCertRevocationCheckerParameters);
begin
  FOcspChecker.Initialize(AParameters);
  FCrlChecker.Initialize(AParameters);
end;

procedure TPkixRevocationChecker.Check(const ACert: IX509Certificate);
begin
  try
    FOcspChecker.Check(ACert);
  except
    // a mechanism that could not settle the status must not suppress its peer; a revoked status
    // from an authorised responder is not recoverable and ends the path here
    on E: ERecoverablePkixCertPathValidatorCryptoLibException do
      FCrlChecker.Check(ACert);
  end;
end;

procedure TPkixRevocationChecker.Init(AForward: Boolean);
begin
  if AForward then
    raise EPkixCertPathValidatorCryptoLibException.CreateRes(@SForwardCheckingUnsupported);
end;

function TPkixRevocationChecker.IsForwardCheckingSupported: Boolean;
begin
  Result := False;
end;

function TPkixRevocationChecker.GetSupportedExtensions: TCryptoLibStringArray;
begin
  Result := nil;
end;

procedure TPkixRevocationChecker.Check(const ACert: IX509Certificate;
  const AUnresolvedCritExts: TList<String>);
begin
  Check(ACert);
end;

function TPkixRevocationChecker.Clone: IPkixCertPathChecker;
begin
  Result := TPkixRevocationChecker.Create(FResponses) as IPkixCertPathChecker;
end;

end.
