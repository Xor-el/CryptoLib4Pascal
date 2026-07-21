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

unit ClpPkixNameConstraintValidator;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIPkixTypes,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpNameConstraintTypes,
  ClpNameConstraintDN,
  ClpNameConstraintIP,
  ClpPkixComparers,
  ClpCryptoLibHashSet,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes;

resourcestring
  SDNNotPermitted = 'subject distinguished name is not from a permitted subtree';
  SDNExcluded = 'subject distinguished name is from an excluded subtree';
  SOtherNameNotPermitted = 'subject other name is not from a permitted subtree';
  SOtherNameExcluded = 'other name is from an excluded subtree';
  SEmailAmbiguous = 'subject email address is ambiguous (multiple @)';
  SEmailNotPermitted = 'subject email address is not from a permitted subtree';
  SEmailExcluded = 'email address is from an excluded subtree';
  SDnsNotPermitted = 'DNS name is not from a permitted subtree';
  SDnsExcluded = 'DNS name is from an excluded subtree';
  SUriNotPermitted = 'URI is not from a permitted subtree';
  SUriExcluded = 'URI is from an excluded subtree';
  SIPNotPermitted = 'IP is not from a permitted subtree';
  SIPExcluded = 'IP is from an excluded subtree';
  SUnknownNameConstraintTag = 'unknown name constraint tag encountered: %d';

type
  /// <summary>
  /// Accumulates the permitted and excluded name subtrees of a certification path and tests names
  /// against them (RFC 5280 4.2.1.10, 6.1.4).
  /// </summary>
  /// <remarks>
  /// A permitted set is nil while its name family is unconstrained and empty when nothing of that family
  /// is permitted; an excluded set is nil until the first excluded subtree of that family is added.
  /// </remarks>
  TPkixNameConstraintValidator = class(TInterfacedObject, IPkixNameConstraintValidator)

  strict private
  class var

  strict private
  var
    FExcludedDN: TCryptoLibHashSet<INameConstraintDN>;
    FExcludedDns: TCryptoLibHashSet<TNameConstraintHostName>;
    FExcludedEmail: TCryptoLibHashSet<TNameConstraintHostName>;
    FExcludedUri: TCryptoLibHashSet<TNameConstraintHostName>;
    FExcludedIP: TCryptoLibHashSet<TNameConstraintIPRange>;
    FExcludedOtherName: TCryptoLibHashSet<IOtherName>;

    FPermittedDN: TCryptoLibHashSet<INameConstraintDN>;
    FPermittedDns: TCryptoLibHashSet<TNameConstraintHostName>;
    FPermittedEmail: TCryptoLibHashSet<TNameConstraintHostName>;
    FPermittedUri: TCryptoLibHashSet<TNameConstraintHostName>;
    FPermittedIP: TCryptoLibHashSet<TNameConstraintIPRange>;
    FPermittedOtherName: TCryptoLibHashSet<IOtherName>;


    procedure DoCheckDN(const APermitted, AExcluded: TCryptoLibHashSet<INameConstraintDN>;
      const ADirectory: IAsn1Sequence; AUseSgp22: Boolean);
    procedure DoCheckEmail(const APermitted, AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
      const AEmail: String);
    procedure DoCheckDns(const APermitted, AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
      const ADns: String);
    procedure DoCheckUri(const APermitted, AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
      const AUri: String);
    procedure DoCheckIP(const APermitted, AExcluded: TCryptoLibHashSet<TNameConstraintIPRange>;
      const AIP: TCryptoLibByteArray);
    procedure DoCheckOtherName(const APermitted, AExcluded: TCryptoLibHashSet<IOtherName>;
      const AOtherName: IOtherName);
    procedure DoCheckName(const AName: IGeneralName; ACheckPermitted, ACheckExcluded: Boolean);

    procedure IntersectSubtreeGroup(ANameType: Int32; const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>);

    class function IsOtherNameConstrained(const AConstraints: TCryptoLibHashSet<IOtherName>;
      const AOtherName: IOtherName): Boolean; static;
    class function IntersectOtherName(const APermitted: TCryptoLibHashSet<IOtherName>;
      const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<IOtherName>; static;
    class procedure UnionOtherName(var AExcluded: TCryptoLibHashSet<IOtherName>;
      const AOtherName: IOtherName); static;

  public
    constructor Create();
    destructor Destroy; override;

    procedure CheckName(const AName: IGeneralName);
    procedure CheckPermittedName(const AName: IGeneralName);
    procedure CheckExcludedName(const AName: IGeneralName);

    procedure CheckDN(const ADn: IX509Name); overload;
    procedure CheckDN(const ADn: IAsn1Sequence); overload;
    procedure CheckDNSgp22(const ADn: IX509Name);
    procedure CheckPermittedDN(const ADn: IAsn1Sequence);
    procedure CheckExcludedDN(const ADn: IAsn1Sequence);

    procedure CheckEmail(const AEmail: String);
    procedure CheckPermittedEmail(const AEmail: String);
    procedure CheckExcludedEmail(const AEmail: String);

    procedure IntersectPermittedSubtree(const APermitted: IGeneralSubtree); overload;
    procedure IntersectPermittedSubtree(const APermitted: IAsn1Sequence); overload;
    procedure IntersectEmptyPermittedSubtree(ANameType: Int32);
    procedure AddExcludedSubtree(const ASubtree: IGeneralSubtree);

    function ToString: String; override;
  end;

implementation

{ TPkixNameConstraintValidator }

constructor TPkixNameConstraintValidator.Create();
begin
  inherited Create();
end;

destructor TPkixNameConstraintValidator.Destroy;
begin
  FExcludedDN.Free;
  FExcludedDns.Free;
  FExcludedEmail.Free;
  FExcludedUri.Free;
  FExcludedIP.Free;
  FExcludedOtherName.Free;
  FPermittedDN.Free;
  FPermittedDns.Free;
  FPermittedEmail.Free;
  FPermittedUri.Free;
  FPermittedIP.Free;
  FPermittedOtherName.Free;
  inherited Destroy;
end;

procedure TPkixNameConstraintValidator.DoCheckDN(const APermitted,
  AExcluded: TCryptoLibHashSet<INameConstraintDN>; const ADirectory: IAsn1Sequence;
  AUseSgp22: Boolean);
var
  LCheckPermitted, LCheckExcluded, LConstrained: Boolean;
  LDn: INameConstraintDN;
begin
  LCheckPermitted := (APermitted <> nil) and not ((ADirectory.Count = 0) and (APermitted.Count < 1));
  LCheckExcluded := AExcluded <> nil;
  if not(LCheckPermitted or LCheckExcluded) then
    Exit;

  LDn := TNameConstraintDN.Create(ADirectory);

  // permitted before excluded (RFC 5280 6.1.4 (b),(c)): the order decides the reported violation
  if LCheckPermitted then
  begin
    if AUseSgp22 then
      LConstrained := TNameConstraintDNUtilities.IsConstrainedSgp22(APermitted, LDn)
    else
      LConstrained := TNameConstraintDNUtilities.IsConstrained(APermitted, LDn);

    if not LConstrained then
      raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SDNNotPermitted);
  end;

  if LCheckExcluded then
  begin
    if AUseSgp22 then
      LConstrained := TNameConstraintDNUtilities.IsConstrainedSgp22(AExcluded, LDn)
    else
      LConstrained := TNameConstraintDNUtilities.IsConstrained(AExcluded, LDn);

    if LConstrained then
      raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SDNExcluded);
  end;
end;

procedure TPkixNameConstraintValidator.DoCheckEmail(const APermitted,
  AExcluded: TCryptoLibHashSet<TNameConstraintHostName>; const AEmail: String);
var
  LCheckPermitted, LCheckExcluded: Boolean;
  LName: TNameConstraintHostName;
  LFirstAt, LLastAt, LIdx: Int32;
begin
  LCheckPermitted := (APermitted <> nil) and not ((System.Length(AEmail) = 0) and (APermitted.Count < 1));
  LCheckExcluded := AExcluded <> nil;
  if not(LCheckPermitted or LCheckExcluded) then
    Exit;

  // more than one '@' makes the host split ambiguous, so fail closed unless opted out of
  LFirstAt := System.Pos('@', AEmail);
  LLastAt := 0;
  for LIdx := 1 to System.Length(AEmail) do
  begin
    if AEmail[LIdx] = '@' then
      LLastAt := LIdx;
  end;
  if (LFirstAt <> LLastAt) and not TCryptoLibConfig.X509.AllowLenientRfc822Name then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SEmailAmbiguous);

  LName := TNameConstraintEmail.FromAddress(AEmail);

  if LCheckPermitted and not TNameConstraintEmail.IsConstrained(APermitted, LName) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SEmailNotPermitted);

  if LCheckExcluded and TNameConstraintEmail.IsConstrained(AExcluded, LName) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SEmailExcluded);
end;

procedure TPkixNameConstraintValidator.DoCheckDns(const APermitted,
  AExcluded: TCryptoLibHashSet<TNameConstraintHostName>; const ADns: String);
var
  LCheckPermitted, LCheckExcluded: Boolean;
  LName: TNameConstraintHostName;
begin
  LCheckPermitted := (APermitted <> nil) and not ((System.Length(ADns) = 0) and (APermitted.Count < 1));
  LCheckExcluded := AExcluded <> nil;
  if not(LCheckPermitted or LCheckExcluded) then
    Exit;

  LName := TNameConstraintDns.FromName(ADns);

  if LCheckPermitted and not TNameConstraintDns.IsConstrained(APermitted, LName) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SDnsNotPermitted);

  if LCheckExcluded and TNameConstraintDns.IsConstrained(AExcluded, LName) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SDnsExcluded);
end;

procedure TPkixNameConstraintValidator.DoCheckUri(const APermitted,
  AExcluded: TCryptoLibHashSet<TNameConstraintHostName>; const AUri: String);
var
  LCheckPermitted, LCheckExcluded: Boolean;
  LHost: TNameConstraintHostName;
begin
  // test the RAW uri: host extraction can reduce a non-empty URI to an empty host
  LCheckPermitted := (APermitted <> nil) and not ((System.Length(AUri) = 0) and (APermitted.Count < 1));
  LCheckExcluded := AExcluded <> nil;
  if not(LCheckPermitted or LCheckExcluded) then
    Exit;

  LHost := TNameConstraintUri.FromUri(AUri);

  if LCheckPermitted and not TNameConstraintUri.IsConstrained(APermitted, LHost) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SUriNotPermitted);

  if LCheckExcluded and TNameConstraintUri.IsConstrained(AExcluded, LHost) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SUriExcluded);
end;

procedure TPkixNameConstraintValidator.DoCheckIP(const APermitted,
  AExcluded: TCryptoLibHashSet<TNameConstraintIPRange>; const AIP: TCryptoLibByteArray);
var
  LAddress: TNameConstraintIPAddress;
begin
  // the name's structure is only validated once there are constraints to check it against
  if (APermitted = nil) and (AExcluded = nil) then
    Exit;

  LAddress := TNameConstraintIPAddress.Create(AIP);

  if (APermitted <> nil) and not TNameConstraintIPRange.IsConstrained(APermitted, LAddress) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SIPNotPermitted);

  if (AExcluded <> nil) and TNameConstraintIPRange.IsConstrained(AExcluded, LAddress) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SIPExcluded);
end;

class function TPkixNameConstraintValidator.IsOtherNameConstrained(const AConstraints: TCryptoLibHashSet<IOtherName>;
  const AOtherName: IOtherName): Boolean;
var
  LConstraint: IOtherName;
begin
  for LConstraint in AConstraints do
  begin
    if LConstraint.Equals(AOtherName) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

procedure TPkixNameConstraintValidator.DoCheckOtherName(const APermitted,
  AExcluded: TCryptoLibHashSet<IOtherName>; const AOtherName: IOtherName);
begin
  if (APermitted <> nil) and not IsOtherNameConstrained(APermitted, AOtherName) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SOtherNameNotPermitted);

  if (AExcluded <> nil) and IsOtherNameConstrained(AExcluded, AOtherName) then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SOtherNameExcluded);
end;

class function TPkixNameConstraintValidator.IntersectOtherName(const APermitted: TCryptoLibHashSet<IOtherName>;
  const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<IOtherName>;
var
  LSubtree: IGeneralSubtree;
  LPermitted, LOtherName: IOtherName;
begin
  Result := TCryptoLibHashSet<IOtherName>.Create(TPkixComparers.OtherNameEqualityComparer);
  try
    for LSubtree in ASubtrees do
    begin
      LOtherName := TOtherName.GetInstance(LSubtree.Base.Name);
      if LOtherName = nil then
        Continue;

      if APermitted = nil then
      begin
        Result.Add(LOtherName);
      end
      else
      begin
        for LPermitted in APermitted do
        begin
          if LPermitted.Equals(LOtherName) then
            Result.Add(LOtherName);
        end;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class procedure TPkixNameConstraintValidator.UnionOtherName(var AExcluded: TCryptoLibHashSet<IOtherName>;
  const AOtherName: IOtherName);
begin
  if AExcluded = nil then
    AExcluded := TCryptoLibHashSet<IOtherName>.Create(TPkixComparers.OtherNameEqualityComparer);

  AExcluded.Add(AOtherName);
end;

procedure TPkixNameConstraintValidator.DoCheckName(const AName: IGeneralName;
  ACheckPermitted, ACheckExcluded: Boolean);
var
  LNameValue: IAsn1Encodable;
  LPermittedDN, LExcludedDN: TCryptoLibHashSet<INameConstraintDN>;
  LPermittedHost, LExcludedHost: TCryptoLibHashSet<TNameConstraintHostName>;
  LPermittedIP, LExcludedIP: TCryptoLibHashSet<TNameConstraintIPRange>;
  LPermittedOther, LExcludedOther: TCryptoLibHashSet<IOtherName>;
begin
  LNameValue := AName.Name;

  case AName.TagNo of
    TGeneralName.OtherName:
      begin
        LPermittedOther := nil;
        LExcludedOther := nil;
        if ACheckPermitted then
          LPermittedOther := FPermittedOtherName;
        if ACheckExcluded then
          LExcludedOther := FExcludedOtherName;
        DoCheckOtherName(LPermittedOther, LExcludedOther, TOtherName.GetInstance(LNameValue));
      end;
    TGeneralName.Rfc822Name:
      begin
        LPermittedHost := nil;
        LExcludedHost := nil;
        if ACheckPermitted then
          LPermittedHost := FPermittedEmail;
        if ACheckExcluded then
          LExcludedHost := FExcludedEmail;
        DoCheckEmail(LPermittedHost, LExcludedHost, TNameConstraintUtilities.ExtractIA5String(LNameValue));
      end;
    TGeneralName.DnsName:
      begin
        LPermittedHost := nil;
        LExcludedHost := nil;
        if ACheckPermitted then
          LPermittedHost := FPermittedDns;
        if ACheckExcluded then
          LExcludedHost := FExcludedDns;
        DoCheckDns(LPermittedHost, LExcludedHost, TNameConstraintUtilities.ExtractIA5String(LNameValue));
      end;
    TGeneralName.DirectoryName:
      begin
        LPermittedDN := nil;
        LExcludedDN := nil;
        if ACheckPermitted then
          LPermittedDN := FPermittedDN;
        if ACheckExcluded then
          LExcludedDN := FExcludedDN;
        DoCheckDN(LPermittedDN, LExcludedDN, TAsn1Sequence.GetInstance(LNameValue),
          TCryptoLibConfig.X509.Sgp22NameConstraints);
      end;
    TGeneralName.UniformResourceIdentifier:
      begin
        LPermittedHost := nil;
        LExcludedHost := nil;
        if ACheckPermitted then
          LPermittedHost := FPermittedUri;
        if ACheckExcluded then
          LExcludedHost := FExcludedUri;
        DoCheckUri(LPermittedHost, LExcludedHost, TNameConstraintUtilities.ExtractIA5String(LNameValue));
      end;
    TGeneralName.IPAddress:
      begin
        LPermittedIP := nil;
        LExcludedIP := nil;
        if ACheckPermitted then
          LPermittedIP := FPermittedIP;
        if ACheckExcluded then
          LExcludedIP := FExcludedIP;
        DoCheckIP(LPermittedIP, LExcludedIP, TAsn1OctetString.GetInstance(LNameValue).GetOctets());
      end;
    // other tags carry no name constraints
  end;
end;

procedure TPkixNameConstraintValidator.CheckName(const AName: IGeneralName);
begin
  DoCheckName(AName, True, True);
end;

procedure TPkixNameConstraintValidator.CheckPermittedName(const AName: IGeneralName);
begin
  DoCheckName(AName, True, False);
end;

procedure TPkixNameConstraintValidator.CheckExcludedName(const AName: IGeneralName);
begin
  DoCheckName(AName, False, True);
end;

procedure TPkixNameConstraintValidator.CheckDN(const ADn: IX509Name);
begin
  CheckDN(TAsn1Sequence.GetInstance(ADn.ToAsn1Object()));
end;

procedure TPkixNameConstraintValidator.CheckDN(const ADn: IAsn1Sequence);
begin
  DoCheckDN(FPermittedDN, FExcludedDN, ADn, TCryptoLibConfig.X509.Sgp22NameConstraints);
end;

procedure TPkixNameConstraintValidator.CheckDNSgp22(const ADn: IX509Name);
begin
  DoCheckDN(FPermittedDN, FExcludedDN, TAsn1Sequence.GetInstance(ADn.ToAsn1Object()), True);
end;

procedure TPkixNameConstraintValidator.CheckPermittedDN(const ADn: IAsn1Sequence);
begin
  DoCheckDN(FPermittedDN, nil, ADn, TCryptoLibConfig.X509.Sgp22NameConstraints);
end;

procedure TPkixNameConstraintValidator.CheckExcludedDN(const ADn: IAsn1Sequence);
begin
  DoCheckDN(nil, FExcludedDN, ADn, TCryptoLibConfig.X509.Sgp22NameConstraints);
end;

procedure TPkixNameConstraintValidator.CheckEmail(const AEmail: String);
begin
  DoCheckEmail(FPermittedEmail, FExcludedEmail, AEmail);
end;

procedure TPkixNameConstraintValidator.CheckPermittedEmail(const AEmail: String);
begin
  DoCheckEmail(FPermittedEmail, nil, AEmail);
end;

procedure TPkixNameConstraintValidator.CheckExcludedEmail(const AEmail: String);
begin
  DoCheckEmail(nil, FExcludedEmail, AEmail);
end;

procedure TPkixNameConstraintValidator.IntersectSubtreeGroup(ANameType: Int32;
  const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>);
var
  LNewHostNames: TCryptoLibHashSet<TNameConstraintHostName>;
  LNewDN: TCryptoLibHashSet<INameConstraintDN>;
  LNewIP: TCryptoLibHashSet<TNameConstraintIPRange>;
  LNewOtherName: TCryptoLibHashSet<IOtherName>;
begin
  case ANameType of
    TGeneralName.OtherName:
      begin
        LNewOtherName := IntersectOtherName(FPermittedOtherName, ASubtrees);
        FPermittedOtherName.Free;
        FPermittedOtherName := LNewOtherName;
      end;
    TGeneralName.Rfc822Name:
      begin
        LNewHostNames := TNameConstraintEmail.Intersect(FPermittedEmail, ASubtrees);
        FPermittedEmail.Free;
        FPermittedEmail := LNewHostNames;
      end;
    TGeneralName.DnsName:
      begin
        LNewHostNames := TNameConstraintDns.Intersect(FPermittedDns, ASubtrees);
        FPermittedDns.Free;
        FPermittedDns := LNewHostNames;
      end;
    TGeneralName.DirectoryName:
      begin
        LNewDN := TNameConstraintDNUtilities.Intersect(FPermittedDN, ASubtrees);
        FPermittedDN.Free;
        FPermittedDN := LNewDN;
      end;
    TGeneralName.UniformResourceIdentifier:
      begin
        LNewHostNames := TNameConstraintUri.Intersect(FPermittedUri, ASubtrees);
        FPermittedUri.Free;
        FPermittedUri := LNewHostNames;
      end;
    TGeneralName.IPAddress:
      begin
        LNewIP := TNameConstraintIPRange.Intersect(FPermittedIP, ASubtrees);
        FPermittedIP.Free;
        FPermittedIP := LNewIP;
      end;
  else
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SUnknownNameConstraintTag, [ANameType]);
  end;
end;

procedure TPkixNameConstraintValidator.IntersectPermittedSubtree(const APermitted: IGeneralSubtree);
var
  LSubtrees: TCryptoLibHashSet<IGeneralSubtree>;
begin
  LSubtrees := TCryptoLibHashSet<IGeneralSubtree>.Create(TPkixComparers.GeneralSubtreeEqualityComparer);
  try
    LSubtrees.Add(APermitted);
    IntersectSubtreeGroup(APermitted.Base.TagNo, LSubtrees);
  finally
    LSubtrees.Free;
  end;
end;

procedure TPkixNameConstraintValidator.IntersectPermittedSubtree(const APermitted: IAsn1Sequence);
var
  LGroups: TObjectDictionary<Int32, TCryptoLibHashSet<IGeneralSubtree>>;
  LSubtree: IGeneralSubtree;
  LGroup: TCryptoLibHashSet<IGeneralSubtree>;
  LIdx, LTagNo: Int32;
  LTags: TCryptoLibInt32Array;
begin
  // group the subtrees by GeneralName tag, then fold each group into its permitted set
  LGroups := TObjectDictionary<Int32, TCryptoLibHashSet<IGeneralSubtree>>.Create([doOwnsValues]);
  try
    for LIdx := 0 to APermitted.Count - 1 do
    begin
      LSubtree := TGeneralSubtree.GetInstance(APermitted[LIdx]);
      LTagNo := LSubtree.Base.TagNo;
      if not LGroups.TryGetValue(LTagNo, LGroup) then
      begin
        LGroup := TCryptoLibHashSet<IGeneralSubtree>.Create
          (TPkixComparers.GeneralSubtreeEqualityComparer);
        LGroups.Add(LTagNo, LGroup);
      end;
      LGroup.Add(LSubtree);
    end;

    LTags := LGroups.Keys.ToArray();
    for LIdx := 0 to System.High(LTags) do
    begin
      IntersectSubtreeGroup(LTags[LIdx], LGroups[LTags[LIdx]]);
    end;
  finally
    LGroups.Free;
  end;
end;

procedure TPkixNameConstraintValidator.IntersectEmptyPermittedSubtree(ANameType: Int32);
begin
  case ANameType of
    TGeneralName.OtherName:
      begin
        FPermittedOtherName.Free;
        FPermittedOtherName := TCryptoLibHashSet<IOtherName>.Create
          (TPkixComparers.OtherNameEqualityComparer);
      end;
    TGeneralName.Rfc822Name:
      begin
        FPermittedEmail.Free;
        FPermittedEmail := TCryptoLibHashSet<TNameConstraintHostName>.Create
          (TPkixComparers.NameConstraintHostNameEqualityComparer);
      end;
    TGeneralName.DnsName:
      begin
        FPermittedDns.Free;
        FPermittedDns := TCryptoLibHashSet<TNameConstraintHostName>.Create
          (TPkixComparers.NameConstraintHostNameEqualityComparer);
      end;
    TGeneralName.DirectoryName:
      begin
        FPermittedDN.Free;
        FPermittedDN := TCryptoLibHashSet<INameConstraintDN>.Create
          (TPkixComparers.NameConstraintDNEqualityComparer);
      end;
    TGeneralName.UniformResourceIdentifier:
      begin
        FPermittedUri.Free;
        FPermittedUri := TCryptoLibHashSet<TNameConstraintHostName>.Create
          (TPkixComparers.NameConstraintHostNameEqualityComparer);
      end;
    TGeneralName.IPAddress:
      begin
        FPermittedIP.Free;
        FPermittedIP := TCryptoLibHashSet<TNameConstraintIPRange>.Create
          (TPkixComparers.NameConstraintIPRangeEqualityComparer);
      end;
  else
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SUnknownNameConstraintTag, [ANameType]);
  end;
end;

procedure TPkixNameConstraintValidator.AddExcludedSubtree(const ASubtree: IGeneralSubtree);
var
  LBase: IGeneralName;
  LNameValue: IAsn1Encodable;
begin
  LBase := ASubtree.Base;
  LNameValue := LBase.Name;

  case LBase.TagNo of
    TGeneralName.OtherName:
      UnionOtherName(FExcludedOtherName, TOtherName.GetInstance(LNameValue));
    TGeneralName.Rfc822Name:
      TNameConstraintEmail.Union(FExcludedEmail,
        TNameConstraintEmail.FromConstraint(TNameConstraintUtilities.ExtractIA5String(LNameValue)));
    TGeneralName.DnsName:
      TNameConstraintDns.Union(FExcludedDns,
        TNameConstraintDns.FromConstraint(TNameConstraintUtilities.ExtractIA5String(LNameValue)));
    TGeneralName.DirectoryName:
      TNameConstraintDNUtilities.Union(FExcludedDN,
        TNameConstraintDN.Create(TAsn1Sequence.GetInstance(LNameValue)) as INameConstraintDN);
    TGeneralName.UniformResourceIdentifier:
      TNameConstraintUri.Union(FExcludedUri,
        TNameConstraintUri.FromConstraint(TNameConstraintUtilities.ExtractIA5String(LNameValue)));
    TGeneralName.IPAddress:
      TNameConstraintIPRange.Union(FExcludedIP,
        TNameConstraintIPRange.CreateExcluded(TAsn1OctetString.GetInstance(LNameValue).GetOctets()));
  else
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SUnknownNameConstraintTag, [LBase.TagNo]);
  end;
end;

function TPkixNameConstraintValidator.ToString: String;
var
  LBuilder: TStringBuilder;

  // the sets are unordered, so the listing order is unspecified
  procedure AppendHostNames(const ACaption: String; const ASet: TCryptoLibHashSet<TNameConstraintHostName>);
  var
    LItem: TNameConstraintHostName;
    LFirst: Boolean;
  begin
    if ASet = nil then
      Exit;
    LBuilder.Append(ACaption).AppendLine(':');
    LBuilder.Append('[');
    LFirst := True;
    for LItem in ASet do
    begin
      if not LFirst then
        LBuilder.Append(', ');
      LFirst := False;
      LBuilder.Append(LItem.ToString());
    end;
    LBuilder.AppendLine(']');
  end;

  procedure AppendDNs(const ACaption: String; const ASet: TCryptoLibHashSet<INameConstraintDN>);
  var
    LItem: INameConstraintDN;
    LFirst: Boolean;
  begin
    if ASet = nil then
      Exit;
    LBuilder.Append(ACaption).AppendLine(':');
    LBuilder.Append('[');
    LFirst := True;
    for LItem in ASet do
    begin
      if not LFirst then
        LBuilder.Append(', ');
      LFirst := False;
      LBuilder.Append(LItem.ToString());
    end;
    LBuilder.AppendLine(']');
  end;

  procedure AppendIPs(const ACaption: String; const ASet: TCryptoLibHashSet<TNameConstraintIPRange>);
  var
    LItem: TNameConstraintIPRange;
    LFirst: Boolean;
  begin
    if ASet = nil then
      Exit;
    LBuilder.Append(ACaption).AppendLine(':');
    LBuilder.Append('[');
    LFirst := True;
    for LItem in ASet do
    begin
      if not LFirst then
        LBuilder.Append(', ');
      LFirst := False;
      LBuilder.Append(LItem.ToString());
    end;
    LBuilder.AppendLine(']');
  end;

begin
  LBuilder := TStringBuilder.Create();
  try
    LBuilder.AppendLine('permitted:');
    AppendDNs('DN', FPermittedDN);
    AppendHostNames('DNS', FPermittedDns);
    AppendHostNames('Email', FPermittedEmail);
    AppendHostNames('URI', FPermittedUri);
    AppendIPs('IP', FPermittedIP);
    LBuilder.AppendLine('excluded:');
    AppendDNs('DN', FExcludedDN);
    AppendHostNames('DNS', FExcludedDns);
    AppendHostNames('Email', FExcludedEmail);
    AppendHostNames('URI', FExcludedUri);
    AppendIPs('IP', FExcludedIP);
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

end.
