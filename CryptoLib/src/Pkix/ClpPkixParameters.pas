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

unit ClpPkixParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIStore,
  ClpIPkixTypes,
  ClpIX509Certificate,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpNullable,
  ClpCryptoLibTypes;

resourcestring
  STrustAnchorsNil = 'trust anchors cannot be nil';
  STrustAnchorsEmpty = 'trust anchors must be a non-empty set';

type
  /// <summary>
  /// Input parameters for PKIX certification path validation: the trust anchors, the validity
  /// date, policy and revocation switches, and the certificate, CRL and attribute certificate stores.
  /// </summary>
  TPkixParameters = class(TInterfacedObject, IPkixParameters)

  public const
    /// <summary>Every certificate in the path must be valid at the configured date.</summary>
    PkixValidityModel = Int32(0);
    /// <summary>Every certificate must have been valid when it was used to sign the next one.</summary>
    ChainValidityModel = Int32(1);

  strict private
  var
    FTrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
    FDate: TNullable<TDateTime>;
    FCheckers: TCryptoLibGenericArray<IPkixCertPathChecker>;
    FRevocationEnabled: Boolean;
    FInitialPolicies: TCryptoLibStringArray;
    FExplicitPolicyRequired: Boolean;
    FAnyPolicyInhibited: Boolean;
    FPolicyMappingInhibited: Boolean;
    FPolicyQualifiersRejected: Boolean;
    FStoresAttrCert: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>;
    FStoresCert: TCryptoLibGenericArray<IStore<IX509Certificate>>;
    FStoresCrl: TCryptoLibGenericArray<IStore<IX509Crl>>;
    FTargetConstraintsAttrCert: ISelector<IX509V2AttributeCertificate>;
    FTargetConstraintsCert: ISelector<IX509Certificate>;
    FAdditionalLocationsEnabled: Boolean;
    FTrustedACIssuers: TCryptoLibGenericArray<ITrustAnchor>;
    FNecessaryACAttributes: TCryptoLibStringArray;
    FProhibitedACAttributes: TCryptoLibStringArray;
    FAttrCertCheckers: TCryptoLibGenericArray<IPkixAttrCertChecker>;
    FValidityModel: Int32;
    FUseDeltas: Boolean;

  strict protected
    function GetIsRevocationEnabled: Boolean;
    procedure SetIsRevocationEnabled(AValue: Boolean);
    function GetIsExplicitPolicyRequired: Boolean;
    procedure SetIsExplicitPolicyRequired(AValue: Boolean);
    function GetIsAnyPolicyInhibited: Boolean;
    procedure SetIsAnyPolicyInhibited(AValue: Boolean);
    function GetIsPolicyMappingInhibited: Boolean;
    procedure SetIsPolicyMappingInhibited(AValue: Boolean);
    function GetIsPolicyQualifiersRejected: Boolean;
    procedure SetIsPolicyQualifiersRejected(AValue: Boolean);
    function GetIsUseDeltasEnabled: Boolean;
    procedure SetIsUseDeltasEnabled(AValue: Boolean);
    function GetIsAdditionalLocationsEnabled: Boolean;
    function GetValidityModel: Int32;
    procedure SetValidityModel(AValue: Int32);
    function GetDate: TNullable<TDateTime>;
    procedure SetDate(const AValue: TNullable<TDateTime>);

  protected
    /// <summary>Copy every parameter of AParameters into this instance. Used by Clone.</summary>
    procedure SetParams(const AParameters: IPkixParameters); virtual;

  public
    constructor Create(const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>);

    function GetTrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
    procedure SetTrustAnchors(const AValue: TCryptoLibGenericArray<ITrustAnchor>);

    function GetTargetConstraintsCert: ISelector<IX509Certificate>;
    procedure SetTargetConstraintsCert(const AValue: ISelector<IX509Certificate>);
    function GetTargetConstraintsAttrCert: ISelector<IX509V2AttributeCertificate>;
    procedure SetTargetConstraintsAttrCert(const AValue: ISelector<IX509V2AttributeCertificate>);

    function GetInitialPolicies: TCryptoLibStringArray;
    procedure SetInitialPolicies(const AValue: TCryptoLibStringArray);

    function GetCertPathCheckers: TCryptoLibGenericArray<IPkixCertPathChecker>;
    procedure SetCertPathCheckers(const AValue: TCryptoLibGenericArray<IPkixCertPathChecker>);
    procedure AddCertPathChecker(const AChecker: IPkixCertPathChecker);

    function GetStoresCert: TCryptoLibGenericArray<IStore<IX509Certificate>>;
    procedure SetStoresCert(const AValue: TCryptoLibGenericArray<IStore<IX509Certificate>>);
    procedure AddStoreCert(const AStore: IStore<IX509Certificate>);
    function GetStoresCrl: TCryptoLibGenericArray<IStore<IX509Crl>>;
    procedure SetStoresCrl(const AValue: TCryptoLibGenericArray<IStore<IX509Crl>>);
    procedure AddStoreCrl(const AStore: IStore<IX509Crl>);
    function GetStoresAttrCert: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>;
    procedure SetStoresAttrCert(const AValue: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>);
    procedure AddStoreAttrCert(const AStore: IStore<IX509V2AttributeCertificate>);

    procedure SetAdditionalLocationsEnabled(AValue: Boolean);

    function GetTrustedACIssuers: TCryptoLibGenericArray<ITrustAnchor>;
    procedure SetTrustedACIssuers(const AValue: TCryptoLibGenericArray<ITrustAnchor>);
    function GetNecessaryACAttributes: TCryptoLibStringArray;
    procedure SetNecessaryACAttributes(const AValue: TCryptoLibStringArray);
    function GetProhibitedACAttributes: TCryptoLibStringArray;
    procedure SetProhibitedACAttributes(const AValue: TCryptoLibStringArray);
    function GetAttrCertCheckers: TCryptoLibGenericArray<IPkixAttrCertChecker>;
    procedure SetAttrCertCheckers(const AValue: TCryptoLibGenericArray<IPkixAttrCertChecker>);


    function Clone: IPkixParameters; virtual;
    function ToString: String; override;
  end;

implementation

{ TPkixParameters }

constructor TPkixParameters.Create(const ATrustAnchors: TCryptoLibGenericArray<ITrustAnchor>);
begin
  inherited Create();
  FRevocationEnabled := True;
  FPolicyQualifiersRejected := True;
  FValidityModel := PkixValidityModel;
  FDate := TNullable<TDateTime>.None;
  SetTrustAnchors(ATrustAnchors);
end;

function TPkixParameters.GetIsRevocationEnabled: Boolean;
begin
  Result := FRevocationEnabled;
end;

procedure TPkixParameters.SetIsRevocationEnabled(AValue: Boolean);
begin
  FRevocationEnabled := AValue;
end;

function TPkixParameters.GetIsExplicitPolicyRequired: Boolean;
begin
  Result := FExplicitPolicyRequired;
end;

procedure TPkixParameters.SetIsExplicitPolicyRequired(AValue: Boolean);
begin
  FExplicitPolicyRequired := AValue;
end;

function TPkixParameters.GetIsAnyPolicyInhibited: Boolean;
begin
  Result := FAnyPolicyInhibited;
end;

procedure TPkixParameters.SetIsAnyPolicyInhibited(AValue: Boolean);
begin
  FAnyPolicyInhibited := AValue;
end;

function TPkixParameters.GetIsPolicyMappingInhibited: Boolean;
begin
  Result := FPolicyMappingInhibited;
end;

procedure TPkixParameters.SetIsPolicyMappingInhibited(AValue: Boolean);
begin
  FPolicyMappingInhibited := AValue;
end;

function TPkixParameters.GetIsPolicyQualifiersRejected: Boolean;
begin
  Result := FPolicyQualifiersRejected;
end;

procedure TPkixParameters.SetIsPolicyQualifiersRejected(AValue: Boolean);
begin
  FPolicyQualifiersRejected := AValue;
end;

function TPkixParameters.GetIsUseDeltasEnabled: Boolean;
begin
  Result := FUseDeltas;
end;

procedure TPkixParameters.SetIsUseDeltasEnabled(AValue: Boolean);
begin
  FUseDeltas := AValue;
end;

function TPkixParameters.GetIsAdditionalLocationsEnabled: Boolean;
begin
  Result := FAdditionalLocationsEnabled;
end;

procedure TPkixParameters.SetAdditionalLocationsEnabled(AValue: Boolean);
begin
  FAdditionalLocationsEnabled := AValue;
end;

function TPkixParameters.GetValidityModel: Int32;
begin
  Result := FValidityModel;
end;

procedure TPkixParameters.SetValidityModel(AValue: Int32);
begin
  FValidityModel := AValue;
end;

function TPkixParameters.GetDate: TNullable<TDateTime>;
begin
  Result := FDate;
end;

procedure TPkixParameters.SetDate(const AValue: TNullable<TDateTime>);
begin
  FDate := AValue;
end;

function TPkixParameters.GetTrustAnchors: TCryptoLibGenericArray<ITrustAnchor>;
begin
  Result := System.Copy(FTrustAnchors);
end;

procedure TPkixParameters.SetTrustAnchors(const AValue: TCryptoLibGenericArray<ITrustAnchor>);
var
  LIdx, LCount: Int32;
begin
  if AValue = nil then
    raise EArgumentNilCryptoLibException.CreateRes(@STrustAnchorsNil);

  System.SetLength(FTrustAnchors, System.Length(AValue));
  LCount := 0;
  for LIdx := 0 to System.High(AValue) do
  begin
    if AValue[LIdx] <> nil then
    begin
      FTrustAnchors[LCount] := AValue[LIdx];
      System.Inc(LCount);
    end;
  end;
  System.SetLength(FTrustAnchors, LCount);

  if LCount < 1 then
    raise EArgumentCryptoLibException.CreateRes(@STrustAnchorsEmpty);
end;

function TPkixParameters.GetTargetConstraintsCert: ISelector<IX509Certificate>;
begin
  if FTargetConstraintsCert = nil then
    Result := nil
  else
    Result := FTargetConstraintsCert.Clone();
end;

procedure TPkixParameters.SetTargetConstraintsCert(const AValue: ISelector<IX509Certificate>);
begin
  if AValue = nil then
    FTargetConstraintsCert := nil
  else
    FTargetConstraintsCert := AValue.Clone();
end;

function TPkixParameters.GetTargetConstraintsAttrCert: ISelector<IX509V2AttributeCertificate>;
begin
  if FTargetConstraintsAttrCert = nil then
    Result := nil
  else
    Result := FTargetConstraintsAttrCert.Clone();
end;

procedure TPkixParameters.SetTargetConstraintsAttrCert(const AValue: ISelector<IX509V2AttributeCertificate>);
begin
  if AValue = nil then
    FTargetConstraintsAttrCert := nil
  else
    FTargetConstraintsAttrCert := AValue.Clone();
end;

function TPkixParameters.GetInitialPolicies: TCryptoLibStringArray;
begin
  Result := System.Copy(FInitialPolicies);
end;

procedure TPkixParameters.SetInitialPolicies(const AValue: TCryptoLibStringArray);
var
  LIdx, LCount: Int32;
begin
  System.SetLength(FInitialPolicies, System.Length(AValue));
  LCount := 0;
  for LIdx := 0 to System.High(AValue) do
  begin
    if AValue[LIdx] <> '' then
    begin
      FInitialPolicies[LCount] := AValue[LIdx];
      System.Inc(LCount);
    end;
  end;
  System.SetLength(FInitialPolicies, LCount);
end;

function TPkixParameters.GetCertPathCheckers: TCryptoLibGenericArray<IPkixCertPathChecker>;
var
  LIdx: Int32;
begin
  System.SetLength(Result, System.Length(FCheckers));
  for LIdx := 0 to System.High(FCheckers) do
  begin
    Result[LIdx] := FCheckers[LIdx].Clone();
  end;
end;

procedure TPkixParameters.SetCertPathCheckers(const AValue: TCryptoLibGenericArray<IPkixCertPathChecker>);
var
  LIdx, LCount: Int32;
begin
  System.SetLength(FCheckers, System.Length(AValue));
  LCount := 0;
  for LIdx := 0 to System.High(AValue) do
  begin
    if AValue[LIdx] <> nil then
    begin
      FCheckers[LCount] := AValue[LIdx].Clone();
      System.Inc(LCount);
    end;
  end;
  System.SetLength(FCheckers, LCount);
end;

procedure TPkixParameters.AddCertPathChecker(const AChecker: IPkixCertPathChecker);
var
  LCount: Int32;
begin
  if AChecker = nil then
    Exit;
  LCount := System.Length(FCheckers);
  System.SetLength(FCheckers, LCount + 1);
  FCheckers[LCount] := AChecker.Clone();
end;

function TPkixParameters.GetStoresCert: TCryptoLibGenericArray<IStore<IX509Certificate>>;
begin
  Result := System.Copy(FStoresCert);
end;

procedure TPkixParameters.SetStoresCert(const AValue: TCryptoLibGenericArray<IStore<IX509Certificate>>);
begin
  FStoresCert := System.Copy(AValue);
end;

procedure TPkixParameters.AddStoreCert(const AStore: IStore<IX509Certificate>);
var
  LCount: Int32;
begin
  if AStore = nil then
    Exit;
  LCount := System.Length(FStoresCert);
  System.SetLength(FStoresCert, LCount + 1);
  FStoresCert[LCount] := AStore;
end;

function TPkixParameters.GetStoresCrl: TCryptoLibGenericArray<IStore<IX509Crl>>;
begin
  Result := System.Copy(FStoresCrl);
end;

procedure TPkixParameters.SetStoresCrl(const AValue: TCryptoLibGenericArray<IStore<IX509Crl>>);
begin
  FStoresCrl := System.Copy(AValue);
end;

procedure TPkixParameters.AddStoreCrl(const AStore: IStore<IX509Crl>);
var
  LCount: Int32;
begin
  if AStore = nil then
    Exit;
  LCount := System.Length(FStoresCrl);
  System.SetLength(FStoresCrl, LCount + 1);
  FStoresCrl[LCount] := AStore;
end;

function TPkixParameters.GetStoresAttrCert: TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>;
begin
  Result := System.Copy(FStoresAttrCert);
end;

procedure TPkixParameters.SetStoresAttrCert(const AValue
  : TCryptoLibGenericArray<IStore<IX509V2AttributeCertificate>>);
begin
  FStoresAttrCert := System.Copy(AValue);
end;

procedure TPkixParameters.AddStoreAttrCert(const AStore: IStore<IX509V2AttributeCertificate>);
var
  LCount: Int32;
begin
  if AStore = nil then
    Exit;
  LCount := System.Length(FStoresAttrCert);
  System.SetLength(FStoresAttrCert, LCount + 1);
  FStoresAttrCert[LCount] := AStore;
end;

function TPkixParameters.GetTrustedACIssuers: TCryptoLibGenericArray<ITrustAnchor>;
begin
  Result := System.Copy(FTrustedACIssuers);
end;

procedure TPkixParameters.SetTrustedACIssuers(const AValue: TCryptoLibGenericArray<ITrustAnchor>);
begin
  FTrustedACIssuers := System.Copy(AValue);
end;

function TPkixParameters.GetNecessaryACAttributes: TCryptoLibStringArray;
begin
  Result := System.Copy(FNecessaryACAttributes);
end;

procedure TPkixParameters.SetNecessaryACAttributes(const AValue: TCryptoLibStringArray);
begin
  FNecessaryACAttributes := System.Copy(AValue);
end;

function TPkixParameters.GetProhibitedACAttributes: TCryptoLibStringArray;
begin
  Result := System.Copy(FProhibitedACAttributes);
end;

procedure TPkixParameters.SetProhibitedACAttributes(const AValue: TCryptoLibStringArray);
begin
  FProhibitedACAttributes := System.Copy(AValue);
end;

function TPkixParameters.GetAttrCertCheckers: TCryptoLibGenericArray<IPkixAttrCertChecker>;
begin
  Result := System.Copy(FAttrCertCheckers);
end;

procedure TPkixParameters.SetAttrCertCheckers(const AValue: TCryptoLibGenericArray<IPkixAttrCertChecker>);
begin
  FAttrCertCheckers := System.Copy(AValue);
end;

procedure TPkixParameters.SetParams(const AParameters: IPkixParameters);
begin
  SetDate(AParameters.Date);
  SetCertPathCheckers(AParameters.GetCertPathCheckers());
  SetIsAnyPolicyInhibited(AParameters.IsAnyPolicyInhibited);
  SetIsExplicitPolicyRequired(AParameters.IsExplicitPolicyRequired);
  SetIsPolicyMappingInhibited(AParameters.IsPolicyMappingInhibited);
  SetIsRevocationEnabled(AParameters.IsRevocationEnabled);
  SetInitialPolicies(AParameters.GetInitialPolicies());
  SetIsPolicyQualifiersRejected(AParameters.IsPolicyQualifiersRejected);
  SetTrustAnchors(AParameters.GetTrustAnchors());

  SetStoresAttrCert(AParameters.GetStoresAttrCert());
  SetStoresCert(AParameters.GetStoresCert());
  SetStoresCrl(AParameters.GetStoresCrl());

  SetTargetConstraintsAttrCert(AParameters.GetTargetConstraintsAttrCert());
  SetTargetConstraintsCert(AParameters.GetTargetConstraintsCert());

  SetValidityModel(AParameters.ValidityModel);
  SetIsUseDeltasEnabled(AParameters.IsUseDeltasEnabled);
  SetAdditionalLocationsEnabled(AParameters.IsAdditionalLocationsEnabled);
  SetTrustedACIssuers(AParameters.GetTrustedACIssuers());
  SetProhibitedACAttributes(AParameters.GetProhibitedACAttributes());
  SetNecessaryACAttributes(AParameters.GetNecessaryACAttributes());
  SetAttrCertCheckers(AParameters.GetAttrCertCheckers());
end;

function TPkixParameters.Clone: IPkixParameters;
var
  LCopy: TPkixParameters;
begin
  LCopy := TPkixParameters.Create(GetTrustAnchors());
  Result := LCopy;
  LCopy.SetParams(Self as IPkixParameters);
end;

function TPkixParameters.ToString: String;
var
  LBuilder: TStringBuilder;
begin
  LBuilder := TStringBuilder.Create();
  try
    LBuilder.AppendLine('PkixParameters [');
    LBuilder.AppendLine('  Trust Anchors: ' + IntToStr(System.Length(FTrustAnchors)));
    LBuilder.AppendLine('  Revocation Enabled: ' + BoolToStr(FRevocationEnabled, True));
    LBuilder.AppendLine('  Validity Model: ' + IntToStr(FValidityModel));
    LBuilder.AppendLine(']');
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

end.
