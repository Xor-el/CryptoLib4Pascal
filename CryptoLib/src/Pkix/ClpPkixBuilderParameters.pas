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

unit ClpPkixBuilderParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIStore,
  ClpIPkixTypes,
  ClpPkixParameters,
  ClpIX509Certificate,
  ClpIX509V2AttributeCertificate,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SMaxPathLengthTooSmall = 'the maximum path length cannot be less than -1';

type
  /// <summary>
  /// Input parameters for PKIX certification path building: validation parameters plus a maximum
  /// path length and a set of certificates that must not be used.
  /// </summary>
  TPkixBuilderParameters = class(TPkixParameters, IPkixBuilderParameters)

  strict private
  var
    FMaxPathLength: Int32;
    FExcludedCerts: TCryptoLibGenericArray<IX509Certificate>;

  strict protected
    function GetMaxPathLength: Int32;
    procedure SetMaxPathLength(AValue: Int32);

  protected
    procedure SetParams(const AParameters: IPkixParameters); override;

  public
    constructor Create(const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
      const ATargetConstraintsCert: ISelector<IX509Certificate>); overload;
    constructor Create(const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
      const ATargetConstraintsCert: ISelector<IX509Certificate>;
      const ATargetConstraintsAttrCert: ISelector<IX509V2AttributeCertificate>); overload;

    /// <summary>Build builder parameters from any existing set of PKIX parameters.</summary>
    class function GetInstance(const AParameters: IPkixParameters): IPkixBuilderParameters; static;

    function GetExcludedCerts: TCryptoLibGenericArray<IX509Certificate>;
    procedure SetExcludedCerts(const AValue: TCryptoLibGenericArray<IX509Certificate>);

    function Clone: IPkixParameters; override;
    function ToString: String; override;
  end;

implementation

{ TPkixBuilderParameters }

constructor TPkixBuilderParameters.Create(const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  const ATargetConstraintsCert: ISelector<IX509Certificate>);
begin
  Create(ATrustAnchors, ATargetConstraintsCert, nil);
end;

constructor TPkixBuilderParameters.Create(const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
  const ATargetConstraintsCert: ISelector<IX509Certificate>;
  const ATargetConstraintsAttrCert: ISelector<IX509V2AttributeCertificate>);
begin
  inherited Create(ATrustAnchors);
  FMaxPathLength := 5;
  SetTargetConstraintsCert(ATargetConstraintsCert);
  SetTargetConstraintsAttrCert(ATargetConstraintsAttrCert);
end;

class function TPkixBuilderParameters.GetInstance(const AParameters: IPkixParameters): IPkixBuilderParameters;
var
  LResult: TPkixBuilderParameters;
begin
  LResult := TPkixBuilderParameters.Create(AParameters.GetTrustAnchors(),
    AParameters.GetTargetConstraintsCert(), AParameters.GetTargetConstraintsAttrCert());
  Result := LResult;
  LResult.SetParams(AParameters);
end;

function TPkixBuilderParameters.GetMaxPathLength: Int32;
begin
  Result := FMaxPathLength;
end;

procedure TPkixBuilderParameters.SetMaxPathLength(AValue: Int32);
begin
  if AValue < -1 then
    raise EInvalidParameterCryptoLibException.CreateRes(@SMaxPathLengthTooSmall);
  FMaxPathLength := AValue;
end;

function TPkixBuilderParameters.GetExcludedCerts: TCryptoLibGenericArray<IX509Certificate>;
begin
  Result := System.Copy(FExcludedCerts);
end;

procedure TPkixBuilderParameters.SetExcludedCerts(const AValue: TCryptoLibGenericArray<IX509Certificate>);
begin
  FExcludedCerts := System.Copy(AValue);
end;

procedure TPkixBuilderParameters.SetParams(const AParameters: IPkixParameters);
var
  LBuilderParams: IPkixBuilderParameters;
begin
  inherited SetParams(AParameters);
  if Supports(AParameters, IPkixBuilderParameters, LBuilderParams) then
  begin
    FMaxPathLength := LBuilderParams.GetMaxPathLength();
    FExcludedCerts := LBuilderParams.GetExcludedCerts();
  end;
end;

function TPkixBuilderParameters.Clone: IPkixParameters;
var
  LCopy: TPkixBuilderParameters;
begin
  LCopy := TPkixBuilderParameters.Create(GetTrustAnchors(), GetTargetConstraintsCert(),
    GetTargetConstraintsAttrCert());
  Result := LCopy;
  LCopy.SetParams(Self as IPkixParameters);
end;

function TPkixBuilderParameters.ToString: String;
var
  LBuilder: TStringBuilder;
begin
  LBuilder := TStringBuilder.Create();
  try
    LBuilder.AppendLine('PkixBuilderParameters [');
    LBuilder.Append(inherited ToString());
    LBuilder.AppendLine('  Maximum Path Length: ' + IntToStr(FMaxPathLength));
    LBuilder.AppendLine(']');
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

end.
