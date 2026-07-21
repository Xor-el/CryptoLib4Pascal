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

unit ClpX509StoreSelectors;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIStore,
  ClpIX509StoreSelectors,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Core,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIX509Certificate,
  ClpIX509CertificatePair,
  ClpIX509Crl,
  ClpIX509V2AttributeCertificate,
  ClpIAttributeCertificateHolder,
  ClpIAttributeCertificateIssuer,
  ClpArrayUtilities,
  ClpNullable,
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SBasicConstraintsTooSmall = 'basic constraints cannot be less than -2';

type
  /// <summary>
  /// Selects X.509 certificates from configurable criteria. An unset criterion matches anything.
  /// </summary>
  TX509CertStoreSelector = class(TInterfacedObject, ISelector<IX509Certificate>, IX509CertStoreSelector)

  strict private
  var
    FAuthorityKeyIdentifier: TCryptoLibByteArray;
    FBasicConstraints: Int32;
    FCertificate: IX509Certificate;
    FCertificateValid: TNullable<TDateTime>;
    FExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier>;
    FIgnoreX509NameOrdering: Boolean;
    FIssuer: IX509Name;
    FKeyUsage: TCryptoLibBooleanArray;
    FMatchAllSubjectAltNames: Boolean;
    FHasPolicy: Boolean;
    FPolicy: TCryptoLibGenericArray<IDerObjectIdentifier>;
    FPrivateKeyValid: TNullable<TDateTime>;
    FSerialNumber: TBigInteger;
    FSubject: IX509Name;
    FSubjectAlternativeNames: TCryptoLibGenericArray<IGeneralName>;
    FSubjectKeyIdentifier: TCryptoLibByteArray;
    FSubjectPublicKey: ISubjectPublicKeyInfo;
    FSubjectPublicKeyAlgID: IDerObjectIdentifier;

    function MatchBasicConstraints(const ACert: IX509Certificate): Boolean;
    function MatchExtendedKeyUsage(const ACert: IX509Certificate): Boolean;
    function MatchKeyUsage(const ACert: IX509Certificate): Boolean;
    function MatchPolicy(const ACert: IX509Certificate): Boolean;
    function MatchPrivateKeyValid(const ACert: IX509Certificate): Boolean;
    function MatchSubjectAlternativeNames(const ACert: IX509Certificate): Boolean;

    class function CheckBasicConstraints(AValue: Int32): Int32; static;
    class function ContainsOid(const AOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
      const AOid: IDerObjectIdentifier): Boolean; static;
    class function ContainsGeneralName(const ANames: TCryptoLibGenericArray<IGeneralName>;
      const AName: IGeneralName): Boolean; static;
    class function IssuersMatch(const A, B: IX509Name): Boolean; static;
    class function MatchExtension(const AValue: TCryptoLibByteArray; const ACert: IX509Certificate;
      const AOid: IDerObjectIdentifier): Boolean; static;

  strict protected
    function GetAuthorityKeyIdentifier: TCryptoLibByteArray;
    procedure SetAuthorityKeyIdentifier(const AValue: TCryptoLibByteArray);
    function GetBasicConstraints: Int32;
    procedure SetBasicConstraints(AValue: Int32);
    function GetCertificate: IX509Certificate;
    procedure SetCertificate(const AValue: IX509Certificate);
    function GetCertificateValid: TNullable<TDateTime>;
    procedure SetCertificateValid(const AValue: TNullable<TDateTime>);
    function GetExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier>;
    procedure SetExtendedKeyUsage(const AValue: TCryptoLibGenericArray<IDerObjectIdentifier>);
    function GetIgnoreX509NameOrdering: Boolean;
    procedure SetIgnoreX509NameOrdering(AValue: Boolean);
    function GetIssuer: IX509Name;
    procedure SetIssuer(const AValue: IX509Name);
    function GetKeyUsage: TCryptoLibBooleanArray;
    procedure SetKeyUsage(const AValue: TCryptoLibBooleanArray);
    function GetMatchAllSubjectAltNames: Boolean;
    procedure SetMatchAllSubjectAltNames(AValue: Boolean);
    function GetHasPolicy: Boolean;
    function GetPolicy: TCryptoLibGenericArray<IDerObjectIdentifier>;
    procedure SetPolicy(const AValue: TCryptoLibGenericArray<IDerObjectIdentifier>);
    procedure ClearPolicy;
    function GetPrivateKeyValid: TNullable<TDateTime>;
    procedure SetPrivateKeyValid(const AValue: TNullable<TDateTime>);
    function GetSerialNumber: TBigInteger;
    procedure SetSerialNumber(const AValue: TBigInteger);
    function GetSubject: IX509Name;
    procedure SetSubject(const AValue: IX509Name);
    function GetSubjectAlternativeNames: TCryptoLibGenericArray<IGeneralName>;
    procedure SetSubjectAlternativeNames(const AValue: TCryptoLibGenericArray<IGeneralName>);
    function GetSubjectKeyIdentifier: TCryptoLibByteArray;
    procedure SetSubjectKeyIdentifier(const AValue: TCryptoLibByteArray);
    function GetSubjectPublicKey: ISubjectPublicKeyInfo;
    procedure SetSubjectPublicKey(const AValue: ISubjectPublicKeyInfo);
    function GetSubjectPublicKeyAlgID: IDerObjectIdentifier;
    procedure SetSubjectPublicKeyAlgID(const AValue: IDerObjectIdentifier);

  public
    constructor Create(); overload;
    constructor Create(const AOther: IX509CertStoreSelector); overload;

    function Match(const ACandidate: IX509Certificate): Boolean; virtual;
    function Clone: ISelector<IX509Certificate>;

    function GetHashCodeOfSubjectKeyIdentifier: Int32;
    function MatchesIssuer(const AOther: IX509CertStoreSelector): Boolean;
    function MatchesSerialNumber(const AOther: IX509CertStoreSelector): Boolean;
    function MatchesSubjectKeyIdentifier(const AOther: IX509CertStoreSelector): Boolean;
  end;

  /// <summary>
  /// Selects X.509 CRLs from configurable criteria. An unset criterion matches anything.
  /// </summary>
  TX509CrlStoreSelector = class(TInterfacedObject, ISelector<IX509Crl>, IX509CrlStoreSelector)

  strict private
  var
    FCertificateChecking: IX509Certificate;
    FDateAndTime: TNullable<TDateTime>;
    FIssuers: TCryptoLibGenericArray<IX509Name>;
    FMaxCrlNumber: TBigInteger;
    FMinCrlNumber: TBigInteger;
    FAttrCertChecking: IX509V2AttributeCertificate;
    FCompleteCrlEnabled: Boolean;
    FDeltaCrlIndicatorEnabled: Boolean;
    FIssuingDistributionPoint: TCryptoLibByteArray;
    FIssuingDistributionPointEnabled: Boolean;
    FMaxBaseCrlNumber: TBigInteger;

    function MatchDateAndTime(const ACrl: IX509Crl): Boolean;
    function MatchIssuers(const ACrl: IX509Crl): Boolean;
    function MatchCrlNumber(const ACrl: IX509Crl): Boolean;
    function MatchDeltaCrlIndicator(const ACrl: IX509Crl): Boolean;
    function MatchIssuingDistributionPoint(const ACrl: IX509Crl): Boolean;

    class function GetExtensionInteger(const ACrl: IX509Crl;
      const AOid: IDerObjectIdentifier): IDerInteger; static;

  strict protected
    function GetCertificateChecking: IX509Certificate;
    procedure SetCertificateChecking(const AValue: IX509Certificate);
    function GetDateAndTime: TNullable<TDateTime>;
    procedure SetDateAndTime(const AValue: TNullable<TDateTime>);
    function GetIssuers: TCryptoLibGenericArray<IX509Name>;
    procedure SetIssuers(const AValue: TCryptoLibGenericArray<IX509Name>);
    function GetMaxCrlNumber: TBigInteger;
    procedure SetMaxCrlNumber(const AValue: TBigInteger);
    function GetMinCrlNumber: TBigInteger;
    procedure SetMinCrlNumber(const AValue: TBigInteger);
    function GetAttrCertChecking: IX509V2AttributeCertificate;
    procedure SetAttrCertChecking(const AValue: IX509V2AttributeCertificate);
    function GetCompleteCrlEnabled: Boolean;
    procedure SetCompleteCrlEnabled(AValue: Boolean);
    function GetDeltaCrlIndicatorEnabled: Boolean;
    procedure SetDeltaCrlIndicatorEnabled(AValue: Boolean);
    function GetIssuingDistributionPoint: TCryptoLibByteArray;
    procedure SetIssuingDistributionPoint(const AValue: TCryptoLibByteArray);
    function GetIssuingDistributionPointEnabled: Boolean;
    procedure SetIssuingDistributionPointEnabled(AValue: Boolean);
    function GetMaxBaseCrlNumber: TBigInteger;
    procedure SetMaxBaseCrlNumber(const AValue: TBigInteger);

  public
    constructor Create(); overload;
    constructor Create(const AOther: IX509CrlStoreSelector); overload;

    function Match(const ACandidate: IX509Crl): Boolean; virtual;
    function Clone: ISelector<IX509Crl>;
  end;

  /// <summary>
  /// Selects X.509 attribute certificates from configurable criteria (RFC 3281).
  /// </summary>
  TX509AttrCertStoreSelector = class(TInterfacedObject, ISelector<IX509V2AttributeCertificate>,
    IX509AttrCertStoreSelector)

  strict private
  var
    FAttributeCert: IX509V2AttributeCertificate;
    FAttributeCertificateValid: TNullable<TDateTime>;
    FHolder: IAttributeCertificateHolder;
    FIssuer: IAttributeCertificateIssuer;
    FSerialNumber: TBigInteger;
    FTargetNames: TCryptoLibGenericArray<IGeneralName>;
    FTargetGroups: TCryptoLibGenericArray<IGeneralName>;

    function MatchTargets(const AAttrCert: IX509V2AttributeCertificate): Boolean;

    class function AddName(const ANames: TCryptoLibGenericArray<IGeneralName>;
      const AName: IGeneralName): TCryptoLibGenericArray<IGeneralName>; static;
    class function CopyNames(const ANames: TCryptoLibGenericArray<IGeneralName>)
      : TCryptoLibGenericArray<IGeneralName>; static;
    class function ContainsName(const ANames: TCryptoLibGenericArray<IGeneralName>;
      const AName: IGeneralName): Boolean; static;
    class function MatchTargetNames(const ATargets: TCryptoLibGenericArray<ITargets>;
      const AMatchValues: TCryptoLibGenericArray<IGeneralName>): Boolean; static;
    class function MatchTargetGroups(const ATargets: TCryptoLibGenericArray<ITargets>;
      const AMatchValues: TCryptoLibGenericArray<IGeneralName>): Boolean; static;

  strict protected
    function GetAttributeCert: IX509V2AttributeCertificate;
    procedure SetAttributeCert(const AValue: IX509V2AttributeCertificate);
    function GetAttributeCertificateValid: TNullable<TDateTime>;
    procedure SetAttributeCertificateValid(const AValue: TNullable<TDateTime>);
    function GetHolder: IAttributeCertificateHolder;
    procedure SetHolder(const AValue: IAttributeCertificateHolder);
    function GetIssuer: IAttributeCertificateIssuer;
    procedure SetIssuer(const AValue: IAttributeCertificateIssuer);
    function GetSerialNumber: TBigInteger;
    procedure SetSerialNumber(const AValue: TBigInteger);

  public
    constructor Create(); overload;
    constructor Create(const AOther: IX509AttrCertStoreSelector); overload;

    function Match(const ACandidate: IX509V2AttributeCertificate): Boolean; virtual;
    function Clone: ISelector<IX509V2AttributeCertificate>;

    procedure AddTargetName(const AName: IGeneralName); overload;
    procedure AddTargetName(const AEncodedName: TCryptoLibByteArray); overload;
    procedure SetTargetNames(const ANames: TCryptoLibGenericArray<IGeneralName>);
    function GetTargetNames: TCryptoLibGenericArray<IGeneralName>;
    procedure AddTargetGroup(const AGroup: IGeneralName); overload;
    procedure AddTargetGroup(const AEncodedGroup: TCryptoLibByteArray); overload;
    procedure SetTargetGroups(const AGroups: TCryptoLibGenericArray<IGeneralName>);
    function GetTargetGroups: TCryptoLibGenericArray<IGeneralName>;
  end;

  /// <summary>
  /// Selects cross-certificate pairs; each present component selector must match its side of the pair.
  /// </summary>
  TX509CertPairStoreSelector = class(TInterfacedObject, ISelector<IX509CertificatePair>,
    IX509CertPairStoreSelector)

  strict private
  var
    FCertPair: IX509CertificatePair;
    FForwardSelector: IX509CertStoreSelector;
    FReverseSelector: IX509CertStoreSelector;

    class function CloneSelector(const ASelector: IX509CertStoreSelector): IX509CertStoreSelector; static;

  strict protected
    function GetCertPair: IX509CertificatePair;
    procedure SetCertPair(const AValue: IX509CertificatePair);
    function GetForwardSelector: IX509CertStoreSelector;
    procedure SetForwardSelector(const AValue: IX509CertStoreSelector);
    function GetReverseSelector: IX509CertStoreSelector;
    procedure SetReverseSelector(const AValue: IX509CertStoreSelector);

  public
    constructor Create(); overload;
    constructor Create(const AOther: IX509CertPairStoreSelector); overload;

    function Match(const ACandidate: IX509CertificatePair): Boolean; virtual;
    function Clone: ISelector<IX509CertificatePair>;
  end;

implementation

{ TX509CertStoreSelector }

constructor TX509CertStoreSelector.Create();
begin
  inherited Create();
  FBasicConstraints := -1;
  FMatchAllSubjectAltNames := True;
end;

constructor TX509CertStoreSelector.Create(const AOther: IX509CertStoreSelector);
begin
  inherited Create();
  FAuthorityKeyIdentifier := System.Copy(AOther.AuthorityKeyIdentifier);
  FBasicConstraints := AOther.BasicConstraints;
  FCertificate := AOther.Certificate;
  FCertificateValid := AOther.CertificateValid;
  FExtendedKeyUsage := System.Copy(AOther.ExtendedKeyUsage);
  FIgnoreX509NameOrdering := AOther.IgnoreX509NameOrdering;
  FIssuer := AOther.Issuer;
  FKeyUsage := System.Copy(AOther.KeyUsage);
  FMatchAllSubjectAltNames := AOther.MatchAllSubjectAltNames;
  FHasPolicy := AOther.HasPolicy;
  FPolicy := System.Copy(AOther.Policy);
  FPrivateKeyValid := AOther.PrivateKeyValid;
  FSerialNumber := AOther.SerialNumber;
  FSubject := AOther.Subject;
  FSubjectAlternativeNames := System.Copy(AOther.SubjectAlternativeNames);
  FSubjectKeyIdentifier := System.Copy(AOther.SubjectKeyIdentifier);
  FSubjectPublicKey := AOther.SubjectPublicKey;
  FSubjectPublicKeyAlgID := AOther.SubjectPublicKeyAlgID;
end;

function TX509CertStoreSelector.Clone: ISelector<IX509Certificate>;
var
  LCopy: IX509CertStoreSelector;
begin
  LCopy := TX509CertStoreSelector.Create(Self as IX509CertStoreSelector);
  Result := LCopy;
end;

function TX509CertStoreSelector.GetAuthorityKeyIdentifier: TCryptoLibByteArray;
begin
  Result := System.Copy(FAuthorityKeyIdentifier);
end;

procedure TX509CertStoreSelector.SetAuthorityKeyIdentifier(const AValue: TCryptoLibByteArray);
begin
  FAuthorityKeyIdentifier := System.Copy(AValue);
end;

function TX509CertStoreSelector.GetBasicConstraints: Int32;
begin
  Result := FBasicConstraints;
end;

procedure TX509CertStoreSelector.SetBasicConstraints(AValue: Int32);
begin
  FBasicConstraints := CheckBasicConstraints(AValue);
end;

function TX509CertStoreSelector.GetCertificate: IX509Certificate;
begin
  Result := FCertificate;
end;

procedure TX509CertStoreSelector.SetCertificate(const AValue: IX509Certificate);
begin
  FCertificate := AValue;
end;

function TX509CertStoreSelector.GetCertificateValid: TNullable<TDateTime>;
begin
  Result := FCertificateValid;
end;

procedure TX509CertStoreSelector.SetCertificateValid(const AValue: TNullable<TDateTime>);
begin
  FCertificateValid := AValue;
end;

function TX509CertStoreSelector.GetExtendedKeyUsage: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := System.Copy(FExtendedKeyUsage);
end;

procedure TX509CertStoreSelector.SetExtendedKeyUsage(const AValue: TCryptoLibGenericArray<IDerObjectIdentifier>);
begin
  FExtendedKeyUsage := System.Copy(AValue);
end;

function TX509CertStoreSelector.GetIgnoreX509NameOrdering: Boolean;
begin
  Result := FIgnoreX509NameOrdering;
end;

procedure TX509CertStoreSelector.SetIgnoreX509NameOrdering(AValue: Boolean);
begin
  FIgnoreX509NameOrdering := AValue;
end;

function TX509CertStoreSelector.GetIssuer: IX509Name;
begin
  Result := FIssuer;
end;

procedure TX509CertStoreSelector.SetIssuer(const AValue: IX509Name);
begin
  FIssuer := AValue;
end;

function TX509CertStoreSelector.GetKeyUsage: TCryptoLibBooleanArray;
begin
  Result := System.Copy(FKeyUsage);
end;

procedure TX509CertStoreSelector.SetKeyUsage(const AValue: TCryptoLibBooleanArray);
begin
  FKeyUsage := System.Copy(AValue);
end;

function TX509CertStoreSelector.GetMatchAllSubjectAltNames: Boolean;
begin
  Result := FMatchAllSubjectAltNames;
end;

procedure TX509CertStoreSelector.SetMatchAllSubjectAltNames(AValue: Boolean);
begin
  FMatchAllSubjectAltNames := AValue;
end;

function TX509CertStoreSelector.GetHasPolicy: Boolean;
begin
  Result := FHasPolicy;
end;

function TX509CertStoreSelector.GetPolicy: TCryptoLibGenericArray<IDerObjectIdentifier>;
begin
  Result := System.Copy(FPolicy);
end;

procedure TX509CertStoreSelector.SetPolicy(const AValue: TCryptoLibGenericArray<IDerObjectIdentifier>);
begin
  FPolicy := System.Copy(AValue);
  FHasPolicy := True;
end;

procedure TX509CertStoreSelector.ClearPolicy;
begin
  FPolicy := nil;
  FHasPolicy := False;
end;

function TX509CertStoreSelector.GetPrivateKeyValid: TNullable<TDateTime>;
begin
  Result := FPrivateKeyValid;
end;

procedure TX509CertStoreSelector.SetPrivateKeyValid(const AValue: TNullable<TDateTime>);
begin
  FPrivateKeyValid := AValue;
end;

function TX509CertStoreSelector.GetSerialNumber: TBigInteger;
begin
  Result := FSerialNumber;
end;

procedure TX509CertStoreSelector.SetSerialNumber(const AValue: TBigInteger);
begin
  FSerialNumber := AValue;
end;

function TX509CertStoreSelector.GetSubject: IX509Name;
begin
  Result := FSubject;
end;

procedure TX509CertStoreSelector.SetSubject(const AValue: IX509Name);
begin
  FSubject := AValue;
end;

function TX509CertStoreSelector.GetSubjectAlternativeNames: TCryptoLibGenericArray<IGeneralName>;
begin
  Result := System.Copy(FSubjectAlternativeNames);
end;

procedure TX509CertStoreSelector.SetSubjectAlternativeNames(const AValue: TCryptoLibGenericArray<IGeneralName>);
begin
  FSubjectAlternativeNames := System.Copy(AValue);
end;

function TX509CertStoreSelector.GetSubjectKeyIdentifier: TCryptoLibByteArray;
begin
  Result := System.Copy(FSubjectKeyIdentifier);
end;

procedure TX509CertStoreSelector.SetSubjectKeyIdentifier(const AValue: TCryptoLibByteArray);
begin
  FSubjectKeyIdentifier := System.Copy(AValue);
end;

function TX509CertStoreSelector.GetSubjectPublicKey: ISubjectPublicKeyInfo;
begin
  Result := FSubjectPublicKey;
end;

procedure TX509CertStoreSelector.SetSubjectPublicKey(const AValue: ISubjectPublicKeyInfo);
begin
  FSubjectPublicKey := AValue;
end;

function TX509CertStoreSelector.GetSubjectPublicKeyAlgID: IDerObjectIdentifier;
begin
  Result := FSubjectPublicKeyAlgID;
end;

procedure TX509CertStoreSelector.SetSubjectPublicKeyAlgID(const AValue: IDerObjectIdentifier);
begin
  FSubjectPublicKeyAlgID := AValue;
end;

class function TX509CertStoreSelector.CheckBasicConstraints(AValue: Int32): Int32;
begin
  if AValue < -2 then
    raise EArgumentCryptoLibException.CreateRes(@SBasicConstraintsTooSmall);
  Result := AValue;
end;

function TX509CertStoreSelector.Match(const ACandidate: IX509Certificate): Boolean;
begin
  Result := False;

  if ACandidate = nil then
    Exit;

  if (FCertificate <> nil) and (not FCertificate.Equals(ACandidate)) then
    Exit;

  if FSerialNumber.IsInitialized and (not FSerialNumber.Equals(ACandidate.SerialNumber)) then
    Exit;

  if (FIssuer <> nil) and (not FIssuer.Equivalent(ACandidate.IssuerDN, not FIgnoreX509NameOrdering)) then
    Exit;

  if (FSubject <> nil) and (not FSubject.Equivalent(ACandidate.SubjectDN, not FIgnoreX509NameOrdering)) then
    Exit;

  if FCertificateValid.HasValue and (not ACandidate.IsValid(FCertificateValid.Value)) then
    Exit;

  if (FSubjectPublicKey <> nil) and (not FSubjectPublicKey.Equals(ACandidate.SubjectPublicKeyInfo)) then
    Exit;

  if (FBasicConstraints <> -1) and (not MatchBasicConstraints(ACandidate)) then
    Exit;

  if (FKeyUsage <> nil) and (not MatchKeyUsage(ACandidate)) then
    Exit;

  if (System.Length(FExtendedKeyUsage) > 0) and (not MatchExtendedKeyUsage(ACandidate)) then
    Exit;

  if not MatchExtension(FSubjectKeyIdentifier, ACandidate, TX509Extensions.SubjectKeyIdentifier) then
    Exit;

  if not MatchExtension(FAuthorityKeyIdentifier, ACandidate, TX509Extensions.AuthorityKeyIdentifier) then
    Exit;

  if FPrivateKeyValid.HasValue and (not MatchPrivateKeyValid(ACandidate)) then
    Exit;

  if (FSubjectPublicKeyAlgID <> nil) and
    (not FSubjectPublicKeyAlgID.Equals(ACandidate.SubjectPublicKeyInfo.Algorithm.Algorithm)) then
    Exit;

  if FHasPolicy and (not MatchPolicy(ACandidate)) then
    Exit;

  if (System.Length(FSubjectAlternativeNames) > 0) and (not MatchSubjectAlternativeNames(ACandidate)) then
    Exit;

  Result := True;
end;

function TX509CertStoreSelector.MatchBasicConstraints(const ACert: IX509Certificate): Boolean;
var
  LMaxPathLen: Int32;
begin
  LMaxPathLen := ACert.GetBasicConstraints();
  if FBasicConstraints = -2 then
    Result := LMaxPathLen = -1
  else
    Result := LMaxPathLen >= FBasicConstraints;
end;

function TX509CertStoreSelector.MatchExtendedKeyUsage(const ACert: IX509Certificate): Boolean;
var
  LEku: TCryptoLibGenericArray<IDerObjectIdentifier>;
  LIdx: Int32;
begin
  LEku := ACert.GetExtendedKeyUsage();
  if (LEku <> nil) and (not ContainsOid(LEku, TKeyPurposeId.AnyExtendedKeyUsage)) then
  begin
    for LIdx := 0 to System.High(FExtendedKeyUsage) do
    begin
      if not ContainsOid(LEku, FExtendedKeyUsage[LIdx]) then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
  Result := True;
end;

function TX509CertStoreSelector.MatchKeyUsage(const ACert: IX509Certificate): Boolean;
var
  LKu: TCryptoLibBooleanArray;
  LIdx: Int32;
begin
  LKu := ACert.GetKeyUsage();
  if LKu <> nil then
  begin
    for LIdx := 0 to System.High(FKeyUsage) do
    begin
      if FKeyUsage[LIdx] and ((LIdx >= System.Length(LKu)) or (not LKu[LIdx])) then
      begin
        Result := False;
        Exit;
      end;
    end;
  end;
  Result := True;
end;

function TX509CertStoreSelector.MatchPolicy(const ACert: IX509Certificate): Boolean;
var
  LOctets: IAsn1OctetString;
  LPolicies: IAsn1Sequence;
  LIdx: Int32;
  LInfo: IPolicyInformation;
begin
  Result := False;

  LOctets := ACert.GetExtensionValue(TX509Extensions.CertificatePolicies);
  if LOctets = nil then
    Exit;

  LPolicies := TAsn1Sequence.GetInstance(TAsn1Object.FromByteArray(LOctets.GetOctets()));
  if (LPolicies = nil) or (LPolicies.Count < 1) then
    Exit;

  // an empty policy criterion only requires the extension to be present
  if System.Length(FPolicy) < 1 then
  begin
    Result := True;
    Exit;
  end;

  for LIdx := 0 to LPolicies.Count - 1 do
  begin
    LInfo := TPolicyInformation.GetInstance(LPolicies[LIdx]);
    if ContainsOid(FPolicy, LInfo.PolicyIdentifier) then
    begin
      Result := True;
      Exit;
    end;
  end;
end;

function TX509CertStoreSelector.MatchPrivateKeyValid(const ACert: IX509Certificate): Boolean;
var
  LOctets: IAsn1OctetString;
  LPeriod: IPrivateKeyUsagePeriod;
  LValidity: TDateTime;
begin
  Result := False;

  LOctets := ACert.GetExtensionValue(TX509Extensions.PrivateKeyUsagePeriod);
  if LOctets <> nil then
  begin
    LValidity := FPrivateKeyValid.Value;
    LPeriod := TPrivateKeyUsagePeriod.GetInstance(TAsn1Object.FromByteArray(LOctets.GetOctets()));

    if (LPeriod.NotBefore <> nil) and (LPeriod.NotBefore.ToDateTime() > LValidity) then
      Exit;

    if (LPeriod.NotAfter <> nil) and (LPeriod.NotAfter.ToDateTime() < LValidity) then
      Exit;
  end;

  Result := True;
end;

function TX509CertStoreSelector.MatchSubjectAlternativeNames(const ACert: IX509Certificate): Boolean;
var
  LGeneralNames: IGeneralNames;
  LNames: TCryptoLibGenericArray<IGeneralName>;
  LIdx: Int32;
  LMatch: Boolean;
begin
  LGeneralNames := ACert.GetSubjectAlternativeNameExtension();
  if LGeneralNames = nil then
  begin
    Result := False;
    Exit;
  end;

  LNames := LGeneralNames.GetNames();

  for LIdx := 0 to System.High(FSubjectAlternativeNames) do
  begin
    LMatch := ContainsGeneralName(LNames, FSubjectAlternativeNames[LIdx]);
    if LMatch <> FMatchAllSubjectAltNames then
    begin
      Result := LMatch;
      Exit;
    end;
  end;

  Result := FMatchAllSubjectAltNames;
end;

function TX509CertStoreSelector.GetHashCodeOfSubjectKeyIdentifier: Int32;
begin
  Result := TArrayUtilities.GetArrayHashCode(FSubjectKeyIdentifier);
end;

function TX509CertStoreSelector.MatchesIssuer(const AOther: IX509CertStoreSelector): Boolean;
begin
  Result := IssuersMatch(FIssuer, AOther.Issuer);
end;

function TX509CertStoreSelector.MatchesSerialNumber(const AOther: IX509CertStoreSelector): Boolean;
var
  LOther: TBigInteger;
begin
  LOther := AOther.SerialNumber;
  if not FSerialNumber.IsInitialized then
    Result := not LOther.IsInitialized
  else
    Result := LOther.IsInitialized and FSerialNumber.Equals(LOther);
end;

function TX509CertStoreSelector.MatchesSubjectKeyIdentifier(const AOther: IX509CertStoreSelector): Boolean;
begin
  Result := TArrayUtilities.AreEqual(FSubjectKeyIdentifier, AOther.SubjectKeyIdentifier);
end;

class function TX509CertStoreSelector.ContainsOid(const AOids: TCryptoLibGenericArray<IDerObjectIdentifier>;
  const AOid: IDerObjectIdentifier): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(AOids) do
  begin
    if (AOids[LIdx] <> nil) and AOids[LIdx].Equals(AOid) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TX509CertStoreSelector.ContainsGeneralName(const ANames: TCryptoLibGenericArray<IGeneralName>;
  const AName: IGeneralName): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(ANames) do
  begin
    if (ANames[LIdx] <> nil) and ANames[LIdx].Equals(AName) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TX509CertStoreSelector.IssuersMatch(const A, B: IX509Name): Boolean;
begin
  if A = nil then
    Result := B = nil
  else
    Result := A.Equivalent(B, True);
end;

class function TX509CertStoreSelector.MatchExtension(const AValue: TCryptoLibByteArray;
  const ACert: IX509Certificate; const AOid: IDerObjectIdentifier): Boolean;
var
  LExtVal: IAsn1OctetString;
begin
  if AValue = nil then
  begin
    Result := True;
    Exit;
  end;

  LExtVal := ACert.GetExtensionValue(AOid);
  if LExtVal = nil then
  begin
    Result := False;
    Exit;
  end;

  Result := TArrayUtilities.AreEqual(AValue, LExtVal.GetOctets());
end;

{ TX509CrlStoreSelector }

constructor TX509CrlStoreSelector.Create();
begin
  inherited Create();
end;

constructor TX509CrlStoreSelector.Create(const AOther: IX509CrlStoreSelector);
begin
  inherited Create();
  FCertificateChecking := AOther.CertificateChecking;
  FDateAndTime := AOther.DateAndTime;
  FIssuers := System.Copy(AOther.Issuers);
  FMaxCrlNumber := AOther.MaxCrlNumber;
  FMinCrlNumber := AOther.MinCrlNumber;
  FAttrCertChecking := AOther.AttrCertChecking;
  FCompleteCrlEnabled := AOther.CompleteCrlEnabled;
  FDeltaCrlIndicatorEnabled := AOther.DeltaCrlIndicatorEnabled;
  FIssuingDistributionPoint := System.Copy(AOther.IssuingDistributionPoint);
  FIssuingDistributionPointEnabled := AOther.IssuingDistributionPointEnabled;
  FMaxBaseCrlNumber := AOther.MaxBaseCrlNumber;
end;

function TX509CrlStoreSelector.Clone: ISelector<IX509Crl>;
var
  LCopy: IX509CrlStoreSelector;
begin
  LCopy := TX509CrlStoreSelector.Create(Self as IX509CrlStoreSelector);
  Result := LCopy;
end;

function TX509CrlStoreSelector.GetCertificateChecking: IX509Certificate;
begin
  Result := FCertificateChecking;
end;

procedure TX509CrlStoreSelector.SetCertificateChecking(const AValue: IX509Certificate);
begin
  FCertificateChecking := AValue;
end;

function TX509CrlStoreSelector.GetDateAndTime: TNullable<TDateTime>;
begin
  Result := FDateAndTime;
end;

procedure TX509CrlStoreSelector.SetDateAndTime(const AValue: TNullable<TDateTime>);
begin
  FDateAndTime := AValue;
end;

function TX509CrlStoreSelector.GetIssuers: TCryptoLibGenericArray<IX509Name>;
begin
  Result := System.Copy(FIssuers);
end;

procedure TX509CrlStoreSelector.SetIssuers(const AValue: TCryptoLibGenericArray<IX509Name>);
begin
  FIssuers := System.Copy(AValue);
end;

function TX509CrlStoreSelector.GetMaxCrlNumber: TBigInteger;
begin
  Result := FMaxCrlNumber;
end;

procedure TX509CrlStoreSelector.SetMaxCrlNumber(const AValue: TBigInteger);
begin
  FMaxCrlNumber := AValue;
end;

function TX509CrlStoreSelector.GetMinCrlNumber: TBigInteger;
begin
  Result := FMinCrlNumber;
end;

procedure TX509CrlStoreSelector.SetMinCrlNumber(const AValue: TBigInteger);
begin
  FMinCrlNumber := AValue;
end;

function TX509CrlStoreSelector.GetAttrCertChecking: IX509V2AttributeCertificate;
begin
  Result := FAttrCertChecking;
end;

procedure TX509CrlStoreSelector.SetAttrCertChecking(const AValue: IX509V2AttributeCertificate);
begin
  FAttrCertChecking := AValue;
end;

function TX509CrlStoreSelector.GetCompleteCrlEnabled: Boolean;
begin
  Result := FCompleteCrlEnabled;
end;

procedure TX509CrlStoreSelector.SetCompleteCrlEnabled(AValue: Boolean);
begin
  FCompleteCrlEnabled := AValue;
end;

function TX509CrlStoreSelector.GetDeltaCrlIndicatorEnabled: Boolean;
begin
  Result := FDeltaCrlIndicatorEnabled;
end;

procedure TX509CrlStoreSelector.SetDeltaCrlIndicatorEnabled(AValue: Boolean);
begin
  FDeltaCrlIndicatorEnabled := AValue;
end;

function TX509CrlStoreSelector.GetIssuingDistributionPoint: TCryptoLibByteArray;
begin
  Result := System.Copy(FIssuingDistributionPoint);
end;

procedure TX509CrlStoreSelector.SetIssuingDistributionPoint(const AValue: TCryptoLibByteArray);
begin
  FIssuingDistributionPoint := System.Copy(AValue);
end;

function TX509CrlStoreSelector.GetIssuingDistributionPointEnabled: Boolean;
begin
  Result := FIssuingDistributionPointEnabled;
end;

procedure TX509CrlStoreSelector.SetIssuingDistributionPointEnabled(AValue: Boolean);
begin
  FIssuingDistributionPointEnabled := AValue;
end;

function TX509CrlStoreSelector.GetMaxBaseCrlNumber: TBigInteger;
begin
  Result := FMaxBaseCrlNumber;
end;

procedure TX509CrlStoreSelector.SetMaxBaseCrlNumber(const AValue: TBigInteger);
begin
  FMaxBaseCrlNumber := AValue;
end;

class function TX509CrlStoreSelector.GetExtensionInteger(const ACrl: IX509Crl;
  const AOid: IDerObjectIdentifier): IDerInteger;
var
  LOctets: IAsn1OctetString;
begin
  LOctets := ACrl.GetExtensionValue(AOid);
  if LOctets = nil then
    Result := nil
  else
    Result := TDerInteger.GetInstance(TAsn1Object.FromByteArray(LOctets.GetOctets()));
end;

function TX509CrlStoreSelector.MatchDateAndTime(const ACrl: IX509Crl): Boolean;
var
  LWhen, LThisUpdate: TDateTime;
  LNextUpdate: TNullable<TDateTime>;
begin
  LWhen := FDateAndTime.Value;
  LThisUpdate := ACrl.ThisUpdate;
  LNextUpdate := ACrl.NextUpdate;
  Result := (LWhen >= LThisUpdate) and LNextUpdate.HasValue and (LWhen < LNextUpdate.Value);
end;

function TX509CrlStoreSelector.MatchIssuers(const ACrl: IX509Crl): Boolean;
var
  LIssuer: IX509Name;
  LIdx: Int32;
begin
  LIssuer := ACrl.IssuerDN;
  for LIdx := 0 to System.High(FIssuers) do
  begin
    if FIssuers[LIdx].Equivalent(LIssuer, True) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

function TX509CrlStoreSelector.MatchCrlNumber(const ACrl: IX509Crl): Boolean;
var
  LCrlNumber: IDerInteger;
  LValue: TBigInteger;
begin
  Result := False;

  LCrlNumber := GetExtensionInteger(ACrl, TX509Extensions.CrlNumber);
  if LCrlNumber = nil then
    Exit;

  LValue := LCrlNumber.PositiveValue;

  if FMaxCrlNumber.IsInitialized and (LValue.CompareTo(FMaxCrlNumber) > 0) then
    Exit;

  if FMinCrlNumber.IsInitialized and (LValue.CompareTo(FMinCrlNumber) < 0) then
    Exit;

  Result := True;
end;

function TX509CrlStoreSelector.MatchDeltaCrlIndicator(const ACrl: IX509Crl): Boolean;
var
  LBaseCrlNumber: IDerInteger;
begin
  try
    LBaseCrlNumber := GetExtensionInteger(ACrl, TX509Extensions.DeltaCrlIndicator);
  except
    Result := False;
    Exit;
  end;

  if LBaseCrlNumber = nil then
  begin
    Result := not FDeltaCrlIndicatorEnabled;
    Exit;
  end;

  if FCompleteCrlEnabled then
  begin
    Result := False;
    Exit;
  end;

  Result := (not FMaxBaseCrlNumber.IsInitialized) or
    (LBaseCrlNumber.PositiveValue.CompareTo(FMaxBaseCrlNumber) <= 0);
end;

function TX509CrlStoreSelector.MatchIssuingDistributionPoint(const ACrl: IX509Crl): Boolean;
var
  LIdp: IAsn1OctetString;
begin
  LIdp := ACrl.GetExtensionValue(TX509Extensions.IssuingDistributionPoint);
  if FIssuingDistributionPoint = nil then
    Result := LIdp = nil
  else
    Result := (LIdp <> nil) and TArrayUtilities.AreEqual(LIdp.GetOctets(), FIssuingDistributionPoint);
end;

function TX509CrlStoreSelector.Match(const ACandidate: IX509Crl): Boolean;
begin
  Result := False;

  if ACandidate = nil then
    Exit;

  if FDateAndTime.HasValue and (not MatchDateAndTime(ACandidate)) then
    Exit;

  if (FIssuers <> nil) and (not MatchIssuers(ACandidate)) then
    Exit;

  if (FMaxCrlNumber.IsInitialized or FMinCrlNumber.IsInitialized) and (not MatchCrlNumber(ACandidate)) then
    Exit;

  if not MatchDeltaCrlIndicator(ACandidate) then
    Exit;

  if FIssuingDistributionPointEnabled and (not MatchIssuingDistributionPoint(ACandidate)) then
    Exit;

  Result := True;
end;

{ TX509AttrCertStoreSelector }

constructor TX509AttrCertStoreSelector.Create();
begin
  inherited Create();
end;

constructor TX509AttrCertStoreSelector.Create(const AOther: IX509AttrCertStoreSelector);
begin
  inherited Create();
  FAttributeCert := AOther.AttributeCert;
  FAttributeCertificateValid := AOther.AttributeCertificateValid;
  FHolder := AOther.Holder;
  FIssuer := AOther.Issuer;
  FSerialNumber := AOther.SerialNumber;
  FTargetNames := CopyNames(AOther.GetTargetNames());
  FTargetGroups := CopyNames(AOther.GetTargetGroups());
end;

function TX509AttrCertStoreSelector.Clone: ISelector<IX509V2AttributeCertificate>;
var
  LCopy: IX509AttrCertStoreSelector;
begin
  LCopy := TX509AttrCertStoreSelector.Create(Self as IX509AttrCertStoreSelector);
  Result := LCopy;
end;

function TX509AttrCertStoreSelector.GetAttributeCert: IX509V2AttributeCertificate;
begin
  Result := FAttributeCert;
end;

procedure TX509AttrCertStoreSelector.SetAttributeCert(const AValue: IX509V2AttributeCertificate);
begin
  FAttributeCert := AValue;
end;

function TX509AttrCertStoreSelector.GetAttributeCertificateValid: TNullable<TDateTime>;
begin
  Result := FAttributeCertificateValid;
end;

procedure TX509AttrCertStoreSelector.SetAttributeCertificateValid(const AValue: TNullable<TDateTime>);
begin
  FAttributeCertificateValid := AValue;
end;

function TX509AttrCertStoreSelector.GetHolder: IAttributeCertificateHolder;
begin
  Result := FHolder;
end;

procedure TX509AttrCertStoreSelector.SetHolder(const AValue: IAttributeCertificateHolder);
begin
  FHolder := AValue;
end;

function TX509AttrCertStoreSelector.GetIssuer: IAttributeCertificateIssuer;
begin
  Result := FIssuer;
end;

procedure TX509AttrCertStoreSelector.SetIssuer(const AValue: IAttributeCertificateIssuer);
begin
  FIssuer := AValue;
end;

function TX509AttrCertStoreSelector.GetSerialNumber: TBigInteger;
begin
  Result := FSerialNumber;
end;

procedure TX509AttrCertStoreSelector.SetSerialNumber(const AValue: TBigInteger);
begin
  FSerialNumber := AValue;
end;

class function TX509AttrCertStoreSelector.CopyNames(const ANames: TCryptoLibGenericArray<IGeneralName>)
  : TCryptoLibGenericArray<IGeneralName>;
begin
  Result := System.Copy(ANames);
end;

class function TX509AttrCertStoreSelector.ContainsName(const ANames: TCryptoLibGenericArray<IGeneralName>;
  const AName: IGeneralName): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(ANames) do
  begin
    if (ANames[LIdx] <> nil) and ANames[LIdx].Equals(AName) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TX509AttrCertStoreSelector.AddName(const ANames: TCryptoLibGenericArray<IGeneralName>;
  const AName: IGeneralName): TCryptoLibGenericArray<IGeneralName>;
begin
  if ContainsName(ANames, AName) then
  begin
    Result := ANames;
    Exit;
  end;
  Result := TArrayUtilities.Append<IGeneralName>(ANames, AName);
end;

procedure TX509AttrCertStoreSelector.AddTargetName(const AName: IGeneralName);
begin
  FTargetNames := AddName(FTargetNames, AName);
end;

procedure TX509AttrCertStoreSelector.AddTargetName(const AEncodedName: TCryptoLibByteArray);
begin
  AddTargetName(TGeneralName.GetInstance(TAsn1Object.FromByteArray(AEncodedName)));
end;

procedure TX509AttrCertStoreSelector.SetTargetNames(const ANames: TCryptoLibGenericArray<IGeneralName>);
begin
  FTargetNames := CopyNames(ANames);
end;

function TX509AttrCertStoreSelector.GetTargetNames: TCryptoLibGenericArray<IGeneralName>;
begin
  Result := CopyNames(FTargetNames);
end;

procedure TX509AttrCertStoreSelector.AddTargetGroup(const AGroup: IGeneralName);
begin
  FTargetGroups := AddName(FTargetGroups, AGroup);
end;

procedure TX509AttrCertStoreSelector.AddTargetGroup(const AEncodedGroup: TCryptoLibByteArray);
begin
  AddTargetGroup(TGeneralName.GetInstance(TAsn1Object.FromByteArray(AEncodedGroup)));
end;

procedure TX509AttrCertStoreSelector.SetTargetGroups(const AGroups: TCryptoLibGenericArray<IGeneralName>);
begin
  FTargetGroups := CopyNames(AGroups);
end;

function TX509AttrCertStoreSelector.GetTargetGroups: TCryptoLibGenericArray<IGeneralName>;
begin
  Result := CopyNames(FTargetGroups);
end;

class function TX509AttrCertStoreSelector.MatchTargetNames(const ATargets: TCryptoLibGenericArray<ITargets>;
  const AMatchValues: TCryptoLibGenericArray<IGeneralName>): Boolean;
var
  LOuter, LInner: Int32;
  LEntries: TCryptoLibGenericArray<ITarget>;
  LValue: IGeneralName;
begin
  for LOuter := 0 to System.High(ATargets) do
  begin
    LEntries := ATargets[LOuter].GetTargets();
    for LInner := 0 to System.High(LEntries) do
    begin
      LValue := LEntries[LInner].TargetName;
      if (LValue <> nil) and ContainsName(AMatchValues, LValue) then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
  Result := False;
end;

class function TX509AttrCertStoreSelector.MatchTargetGroups(const ATargets: TCryptoLibGenericArray<ITargets>;
  const AMatchValues: TCryptoLibGenericArray<IGeneralName>): Boolean;
var
  LOuter, LInner: Int32;
  LEntries: TCryptoLibGenericArray<ITarget>;
  LValue: IGeneralName;
begin
  for LOuter := 0 to System.High(ATargets) do
  begin
    LEntries := ATargets[LOuter].GetTargets();
    for LInner := 0 to System.High(LEntries) do
    begin
      LValue := LEntries[LInner].TargetGroup;
      if (LValue <> nil) and ContainsName(AMatchValues, LValue) then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
  Result := False;
end;

function TX509AttrCertStoreSelector.MatchTargets(const AAttrCert: IX509V2AttributeCertificate): Boolean;
var
  LOctets: IAsn1OctetString;
  LTargetInfo: ITargetInformation;
  LTargets: TCryptoLibGenericArray<ITargets>;
begin
  try
    LOctets := AAttrCert.GetExtensionValue(TX509Extensions.TargetInformation);
    if LOctets = nil then
      LTargetInfo := nil
    else
      LTargetInfo := TTargetInformation.GetInstance(TAsn1Object.FromByteArray(LOctets.GetOctets()));
  except
    Result := False;
    Exit;
  end;

  if LTargetInfo = nil then
  begin
    Result := True;
    Exit;
  end;

  LTargets := LTargetInfo.GetTargetsObjects();

  if (System.Length(FTargetNames) > 0) and (not MatchTargetNames(LTargets, FTargetNames)) then
  begin
    Result := False;
    Exit;
  end;

  if (System.Length(FTargetGroups) > 0) and (not MatchTargetGroups(LTargets, FTargetGroups)) then
  begin
    Result := False;
    Exit;
  end;

  Result := True;
end;

function TX509AttrCertStoreSelector.Match(const ACandidate: IX509V2AttributeCertificate): Boolean;
begin
  Result := False;

  if ACandidate = nil then
    Exit;

  if (FAttributeCert <> nil) and (not FAttributeCert.Equals(ACandidate)) then
    Exit;

  if FSerialNumber.IsInitialized and (not ACandidate.SerialNumber.Equals(FSerialNumber)) then
    Exit;

  if (FHolder <> nil) and (not FHolder.Equals(ACandidate.Holder)) then
    Exit;

  if (FIssuer <> nil) and (not FIssuer.Equals(ACandidate.Issuer)) then
    Exit;

  if FAttributeCertificateValid.HasValue and (not ACandidate.IsValid(FAttributeCertificateValid.Value)) then
    Exit;

  if ((System.Length(FTargetNames) > 0) or (System.Length(FTargetGroups) > 0)) and (not MatchTargets(ACandidate)) then
    Exit;

  Result := True;
end;

{ TX509CertPairStoreSelector }

constructor TX509CertPairStoreSelector.Create();
begin
  inherited Create();
end;

constructor TX509CertPairStoreSelector.Create(const AOther: IX509CertPairStoreSelector);
begin
  inherited Create();
  FCertPair := AOther.CertPair;
  FForwardSelector := AOther.ForwardSelector;
  FReverseSelector := AOther.ReverseSelector;
end;

class function TX509CertPairStoreSelector.CloneSelector(const ASelector: IX509CertStoreSelector)
  : IX509CertStoreSelector;
begin
  if ASelector = nil then
    Result := nil
  else
    Result := TX509CertStoreSelector.Create(ASelector);
end;

function TX509CertPairStoreSelector.Clone: ISelector<IX509CertificatePair>;
var
  LCopy: IX509CertPairStoreSelector;
begin
  LCopy := TX509CertPairStoreSelector.Create(Self as IX509CertPairStoreSelector);
  Result := LCopy;
end;

function TX509CertPairStoreSelector.GetCertPair: IX509CertificatePair;
begin
  Result := FCertPair;
end;

procedure TX509CertPairStoreSelector.SetCertPair(const AValue: IX509CertificatePair);
begin
  FCertPair := AValue;
end;

function TX509CertPairStoreSelector.GetForwardSelector: IX509CertStoreSelector;
begin
  Result := CloneSelector(FForwardSelector);
end;

procedure TX509CertPairStoreSelector.SetForwardSelector(const AValue: IX509CertStoreSelector);
begin
  FForwardSelector := CloneSelector(AValue);
end;

function TX509CertPairStoreSelector.GetReverseSelector: IX509CertStoreSelector;
begin
  Result := CloneSelector(FReverseSelector);
end;

procedure TX509CertPairStoreSelector.SetReverseSelector(const AValue: IX509CertStoreSelector);
begin
  FReverseSelector := CloneSelector(AValue);
end;

function TX509CertPairStoreSelector.Match(const ACandidate: IX509CertificatePair): Boolean;
begin
  Result := False;

  if ACandidate = nil then
    Exit;

  if (FCertPair <> nil) and (not FCertPair.Equals(ACandidate)) then
    Exit;

  if (FForwardSelector <> nil) and (not FForwardSelector.Match(ACandidate.Forward)) then
    Exit;

  if (FReverseSelector <> nil) and (not FReverseSelector.Match(ACandidate.Reverse)) then
    Exit;

  Result := True;
end;

end.
