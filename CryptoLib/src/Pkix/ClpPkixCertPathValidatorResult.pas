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

unit ClpPkixCertPathValidatorResult;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPkixTypes,
  ClpIAsymmetricKeyParameter,
  ClpIX509Certificate,
  ClpCryptoLibTypes;

resourcestring
  STrustAnchorNil = 'trust anchor cannot be nil';
  SSubjectPublicKeyNil = 'subject public key cannot be nil';
  SCertPathNil = 'certification path cannot be nil';

type
  /// <summary>
  /// The outcome of a successful certification path validation (RFC 5280 6.1.6).
  /// </summary>
  TPkixCertPathValidatorResult = class(TInterfacedObject, IPkixCertPathValidatorResult)

  strict private
  var
    FTrustAnchor: ITrustAnchor;
    FPolicyTree: IPkixPolicyNode;
    FSubjectPublicKey: IAsymmetricKeyParameter;

  strict protected
    function GetTrustAnchor: ITrustAnchor;
    function GetPolicyTree: IPkixPolicyNode;
    function GetSubjectPublicKey: IAsymmetricKeyParameter;

  public
    constructor Create(const ATrustAnchor: ITrustAnchor; const APolicyTree: IPkixPolicyNode;
      const ASubjectPublicKey: IAsymmetricKeyParameter);

    function ToString: String; override;
  end;

  /// <summary>
  /// A validation result plus the path that was built to reach it.
  /// </summary>
  TPkixCertPathBuilderResult = class(TPkixCertPathValidatorResult, IPkixCertPathBuilderResult)

  strict private
  var
    FCertPath: IPkixCertPath;

  strict protected
    function GetCertPath: IPkixCertPath;

  public
    constructor Create(const ACertPath: IPkixCertPath; const ATrustAnchor: ITrustAnchor;
      const APolicyTree: IPkixPolicyNode; const ASubjectPublicKey: IAsymmetricKeyParameter);

    function ToString: String; override;
  end;

implementation

{ TPkixCertPathValidatorResult }

constructor TPkixCertPathValidatorResult.Create(const ATrustAnchor: ITrustAnchor;
  const APolicyTree: IPkixPolicyNode; const ASubjectPublicKey: IAsymmetricKeyParameter);
begin
  inherited Create();
  if ATrustAnchor = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@STrustAnchorNil);
  if ASubjectPublicKey = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SSubjectPublicKeyNil);

  FTrustAnchor := ATrustAnchor;
  FPolicyTree := APolicyTree; // nil when no policy was required
  FSubjectPublicKey := ASubjectPublicKey;
end;

function TPkixCertPathValidatorResult.GetTrustAnchor: ITrustAnchor;
begin
  Result := FTrustAnchor;
end;

function TPkixCertPathValidatorResult.GetPolicyTree: IPkixPolicyNode;
begin
  Result := FPolicyTree;
end;

function TPkixCertPathValidatorResult.GetSubjectPublicKey: IAsymmetricKeyParameter;
begin
  Result := FSubjectPublicKey;
end;

function TPkixCertPathValidatorResult.ToString: String;
var
  LBuilder: TStringBuilder;
begin
  LBuilder := TStringBuilder.Create();
  try
    LBuilder.AppendLine('PkixCertPathValidatorResult: [');
    LBuilder.Append('  Trust Anchor: ').AppendLine(FTrustAnchor.ToString());
    if FPolicyTree <> nil then
      LBuilder.Append('  Policy Tree: ').AppendLine(FPolicyTree.ToString());
    LBuilder.AppendLine(']');
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

{ TPkixCertPathBuilderResult }

constructor TPkixCertPathBuilderResult.Create(const ACertPath: IPkixCertPath;
  const ATrustAnchor: ITrustAnchor; const APolicyTree: IPkixPolicyNode;
  const ASubjectPublicKey: IAsymmetricKeyParameter);
begin
  inherited Create(ATrustAnchor, APolicyTree, ASubjectPublicKey);
  if ACertPath = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@SCertPathNil);
  FCertPath := ACertPath;
end;

function TPkixCertPathBuilderResult.GetCertPath: IPkixCertPath;
begin
  Result := FCertPath;
end;

function TPkixCertPathBuilderResult.ToString: String;
var
  LBuilder: TStringBuilder;
  LAnchorCert: IX509Certificate;
begin
  LBuilder := TStringBuilder.Create();
  try
    LBuilder.AppendLine('PkixCertPathBuilderResult: [');
    LBuilder.AppendLine('  Certification Path Length: ' + IntToStr(System.Length(FCertPath.Certificates)));
    LAnchorCert := GetTrustAnchor().TrustedCert;
    if LAnchorCert <> nil then
      LBuilder.Append('  Trust Anchor: ').AppendLine(LAnchorCert.IssuerDN.ToString())
    else
      LBuilder.Append('  Trust Anchor: ').AppendLine(GetTrustAnchor().CAName);
    LBuilder.AppendLine(']');
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

end.
