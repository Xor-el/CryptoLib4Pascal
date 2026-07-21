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

unit ClpNameConstraintTypes;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIAsn1Core,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpStringUtilities,
  ClpCryptoLibHashSet,
  ClpCryptoLibExceptions;

resourcestring
  SEmptyLabelInHost = '%s has an empty label in the host: %s';

type
  /// <summary>
  /// Shape of a string-host name-constraint value, fixed at construction. A '@' past index 0 is a
  /// particular mailbox; a leading '@' is the legacy exact-host form; a leading '.' is a domain.
  /// </summary>
  TNameConstraintHostNameKind = (Mailbox, AtHost, Host, Domain);

  /// <summary>
  /// The set relationship of a first name constraint to a second one. A host or mailbox is a point and
  /// a domain is a subtree, so two constraints never partially overlap - it is always exactly one of these.
  /// </summary>
  TNameConstraintRelation = (Disjoint, Equal, Subsumes, SubsumedBy);

  /// <summary>
  /// A canonical string-host name-constraint value: the identity string plus its shape and the derived
  /// host comparand. Shared by the rfc822Name, dNSName and uniformResourceIdentifier wrappers.
  /// </summary>
  TNameConstraintHostName = record

  strict private
  var
    FKind: TNameConstraintHostNameKind;
    FValue: String;
    FHost: String;

  public
    class function Create(AKind: TNameConstraintHostNameKind;
      const AValue, AHost: String): TNameConstraintHostName; static;

    function Kind: TNameConstraintHostNameKind; inline;
    function Value: String; inline;
    function Host: String; inline;

    /// <summary>Case-insensitive on the canonical value alone; kind and host derive from it.</summary>
    function Equals(const AOther: TNameConstraintHostName): Boolean;
    function ToString: String; inline;
  end;

  /// <summary>
  /// Canonicalization, matching and subtree set algebra shared by the string-host name constraints.
  /// </summary>
  TNameConstraintUtilities = class sealed(TObject)

  strict private
    class function SameSubstringIgnoreCase(const A: String; AOffA: Int32; const B: String;
      AOffB, ALength: Int32): Boolean; static;
    class function RelateDomains(const ADomain1, ADomain2: String): TNameConstraintRelation; static;
    class function IsParticularAddress(AKind: TNameConstraintHostNameKind): Boolean; static; inline;

  public
    /// <summary>The RFC 3986 authority host of AUrl, with userinfo, port and IPv6 brackets removed.</summary>
    class function ExtractHostFromURL(const AUrl: String): String; static;
    class function ExtractIA5String(const ANameValue: IAsn1Encodable): String; overload; static;
    class function ExtractIA5String(const ASubtree: IGeneralSubtree): String; overload; static;

    /// <summary>Strip the single RFC 1034 root-label trailing dot. Any dot still trailing is an empty label.</summary>
    class function StripTrailingDot(const AStr: String): String; static;
    /// <summary>Reject an empty label in the host tail of AStr from the zero-based AHostStart (fail closed).</summary>
    class procedure CheckHostLabels(const AStr: String; AHostStart: Int32;
      const AGeneralNameType: String); static;
    /// <summary>Is ATestDomain a PROPER subdomain of ADomain? The apex itself never matches.</summary>
    class function WithinDomain(const ATestDomain, ADomain: String): Boolean; static;
    /// <summary>Classify AValue into its shape, returning the derived host comparand in AHost.</summary>
    class function ClassifyHostName(const AValue: String; out AHost: String)
      : TNameConstraintHostNameKind; static;

    class function Relate(const AName1, AName2: TNameConstraintHostName): TNameConstraintRelation; static;
    /// <summary>Add the narrower of an overlapping pair to AIntersect; an equal pair keeps AName1.</summary>
    class procedure Intersect(const AName1, AName2: TNameConstraintHostName;
      const AIntersect: TCryptoLibHashSet<TNameConstraintHostName>); static;
    /// <summary>Union in place, keeping the set pairwise non-nested. Creates AExcluded when nil.</summary>
    class procedure Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
      const AName: TNameConstraintHostName); static;
  end;

  /// <summary>
  /// A dNSName in canonical form. Every dNSName denotes a subtree, so it always classifies as a domain;
  /// a constraint may carry the apex-excluding leading dot, a tested name may not.
  /// </summary>
  TNameConstraintDns = class sealed(TObject)
  public
    class function FromConstraint(const AConstraint: String): TNameConstraintHostName; static;
    class function FromName(const AName: String): TNameConstraintHostName; static;

    class function IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintHostName>;
      const ADns: TNameConstraintHostName): Boolean; static;
    class function Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintHostName>;
      const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>)
      : TCryptoLibHashSet<TNameConstraintHostName>; static;
    class procedure Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
      const ADns: TNameConstraintHostName); static;
  end;

  /// <summary>
  /// An rfc822Name in canonical form: a particular mailbox, the legacy exact-host form, a host or a
  /// domain (RFC 5280 4.2.1.10). The domain form's leading dot is constraint-only.
  /// </summary>
  TNameConstraintEmail = class sealed(TObject)
  strict private
    class function FromValue(const AValue: String; AIsConstraint: Boolean): TNameConstraintHostName; static;
  public
    class function FromConstraint(const AConstraint: String): TNameConstraintHostName; static;
    class function FromAddress(const AAddress: String): TNameConstraintHostName; static;

    class function IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintHostName>;
      const AEmail: TNameConstraintHostName): Boolean; static;
    class function Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintHostName>;
      const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>)
      : TCryptoLibHashSet<TNameConstraintHostName>; static;
    class procedure Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
      const AEmail: TNameConstraintHostName); static;
  end;

  /// <summary>
  /// A uniformResourceIdentifier in canonical form. A tested name is reduced to its authority host; a
  /// constraint is a host or a ".domain". Classified like an rfc822Name so the set algebra is shared.
  /// </summary>
  TNameConstraintUri = class sealed(TObject)
  strict private
    class function FromValue(const AValue: String; AIsConstraint: Boolean): TNameConstraintHostName; static;
  public
    class function FromConstraint(const AConstraint: String): TNameConstraintHostName; static;
    class function FromUri(const AUri: String): TNameConstraintHostName; static;

    class function IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintHostName>;
      const AUri: TNameConstraintHostName): Boolean; static;
    class function Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintHostName>;
      const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>)
      : TCryptoLibHashSet<TNameConstraintHostName>; static;
    class procedure Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
      const AUri: TNameConstraintHostName); static;
  end;

implementation

uses
  ClpPkixComparers;

{ TNameConstraintHostName }

class function TNameConstraintHostName.Create(AKind: TNameConstraintHostNameKind;
  const AValue, AHost: String): TNameConstraintHostName;
begin
  Result.FKind := AKind;
  Result.FValue := AValue;
  Result.FHost := AHost;
end;

function TNameConstraintHostName.Kind: TNameConstraintHostNameKind;
begin
  Result := FKind;
end;

function TNameConstraintHostName.Value: String;
begin
  Result := FValue;
end;

function TNameConstraintHostName.Host: String;
begin
  Result := FHost;
end;

function TNameConstraintHostName.Equals(const AOther: TNameConstraintHostName): Boolean;
begin
  Result := TStringUtilities.EqualsIgnoreCase(FValue, AOther.FValue);
end;

function TNameConstraintHostName.ToString: String;
begin
  Result := FValue;
end;

{ TNameConstraintUtilities }

class function TNameConstraintUtilities.SameSubstringIgnoreCase(const A: String; AOffA: Int32;
  const B: String; AOffB, ALength: Int32): Boolean;
begin
  Result := TStringUtilities.EqualsIgnoreCase(TStringUtilities.Substring(A, AOffA, ALength),
    TStringUtilities.Substring(B, AOffB, ALength));
end;

class function TNameConstraintUtilities.ExtractHostFromURL(const AUrl: String): String;
var
  LSub: String;
  LIdx, LSchemeEnd, LAtPos, LCloseBracket, LPortColon: Int32;
  LChar: Char;
begin
  // RFC 3986 3.2: authority = [ userinfo "@" ] host [ ":" port ]. Strip scheme, "//",
  // any path/query/fragment tail, userinfo (last '@'), then brackets or ":port".
  LSub := AUrl;

  LSchemeEnd := TStringUtilities.IndexOf(LSub, ':');
  if LSchemeEnd > 0 then
    LSub := TStringUtilities.Substring(LSub, LSchemeEnd + 1);

  if TStringUtilities.StartsWith(LSub, '//') then
    LSub := TStringUtilities.Substring(LSub, 3);

  for LIdx := 1 to System.Length(LSub) do
  begin
    LChar := LSub[LIdx];
    if (LChar = '/') or (LChar = '?') or (LChar = '#') then
    begin
      LSub := TStringUtilities.Substring(LSub, 1, LIdx - 1);
      Break;
    end;
  end;

  LAtPos := TStringUtilities.LastIndexOf(LSub, '@');
  if LAtPos > 0 then
    LSub := TStringUtilities.Substring(LSub, LAtPos + 1);

  if TStringUtilities.StartsWith(LSub, '[') then
  begin
    LCloseBracket := TStringUtilities.IndexOf(LSub, ']');
    if LCloseBracket > 1 then
      Result := TStringUtilities.Substring(LSub, 2, LCloseBracket - 2)
    else
      Result := TStringUtilities.Substring(LSub, 2);
    Exit;
  end;

  LPortColon := TStringUtilities.LastIndexOf(LSub, ':');
  if LPortColon > 0 then
    LSub := TStringUtilities.Substring(LSub, 1, LPortColon - 1);

  Result := LSub;
end;

class function TNameConstraintUtilities.ExtractIA5String(const ANameValue: IAsn1Encodable): String;
begin
  Result := TDerIA5String.GetInstance(ANameValue).GetString();
end;

class function TNameConstraintUtilities.ExtractIA5String(const ASubtree: IGeneralSubtree): String;
begin
  Result := ExtractIA5String(ASubtree.Base.Name);
end;

class function TNameConstraintUtilities.StripTrailingDot(const AStr: String): String;
var
  LLen: Int32;
begin
  LLen := System.Length(AStr);
  if (LLen > 1) and (AStr[LLen] = '.') then
    Result := TStringUtilities.Substring(AStr, 1, LLen - 1)
  else
    Result := AStr;
end;

class procedure TNameConstraintUtilities.CheckHostLabels(const AStr: String; AHostStart: Int32;
  const AGeneralNameType: String);
var
  LLen, LIdx: Int32;
  LBad: Boolean;
begin
  LLen := System.Length(AStr);
  if AHostStart >= LLen then
    Exit;

  LBad := (AStr[AHostStart + 1] = '.') or (AStr[LLen] = '.');
  if not LBad then
  begin
    for LIdx := AHostStart + 1 to LLen - 1 do
    begin
      if (AStr[LIdx] = '.') and (AStr[LIdx + 1] = '.') then
      begin
        LBad := True;
        Break;
      end;
    end;
  end;

  if LBad then
    raise EPkixNameConstraintValidatorCryptoLibException.CreateResFmt(@SEmptyLabelInHost,
      [AGeneralNameType, AStr]);
end;

class function TNameConstraintUtilities.WithinDomain(const ATestDomain, ADomain: String): Boolean;
var
  LDomOff, LDomLen, LBoundary: Int32;
begin
  if TStringUtilities.StartsWith(ADomain, '.') then
    LDomOff := 1
  else
    LDomOff := 0;
  LDomLen := System.Length(ADomain) - LDomOff;

  // at least one extra char, then the '.' label boundary, then the domain itself
  LBoundary := System.Length(ATestDomain) - LDomLen;
  if (LBoundary < 2) or (ATestDomain[LBoundary] <> '.') then
  begin
    Result := False;
    Exit;
  end;

  Result := SameSubstringIgnoreCase(ATestDomain, LBoundary + 1, ADomain, LDomOff + 1, LDomLen);
end;

class function TNameConstraintUtilities.ClassifyHostName(const AValue: String; out AHost: String)
  : TNameConstraintHostNameKind;
var
  LAtPos: Int32;
begin
  LAtPos := TStringUtilities.IndexOf(AValue, '@');

  if LAtPos > 1 then
  begin
    AHost := TStringUtilities.Substring(AValue, LAtPos + 1);
    Result := TNameConstraintHostNameKind.Mailbox;
  end
  else if TStringUtilities.StartsWith(AValue, '.') then
  begin
    AHost := AValue;
    Result := TNameConstraintHostNameKind.Domain;
  end
  else if LAtPos < 1 then
  begin
    AHost := AValue;
    Result := TNameConstraintHostNameKind.Host;
  end
  else
  begin
    AHost := TStringUtilities.Substring(AValue, 2);
    Result := TNameConstraintHostNameKind.AtHost;
  end;
end;

class function TNameConstraintUtilities.RelateDomains(const ADomain1,
  ADomain2: String): TNameConstraintRelation;
var
  LOff1, LOff2, LLen1, LLen2: Int32;
begin
  // a leading dot excludes the apex; without it the value's own name is in the subtree, so equal
  // remainders relate as Equal only with matching apex treatment
  if TStringUtilities.StartsWith(ADomain1, '.') then
    LOff1 := 1
  else
    LOff1 := 0;
  if TStringUtilities.StartsWith(ADomain2, '.') then
    LOff2 := 1
  else
    LOff2 := 0;

  LLen1 := System.Length(ADomain1) - LOff1;
  LLen2 := System.Length(ADomain2) - LOff2;

  if LLen1 = LLen2 then
  begin
    if not SameSubstringIgnoreCase(ADomain1, LOff1 + 1, ADomain2, LOff2 + 1, LLen1) then
      Result := TNameConstraintRelation.Disjoint
    else if LOff1 = LOff2 then
      Result := TNameConstraintRelation.Equal
    else if LOff1 = 0 then
      Result := TNameConstraintRelation.Subsumes // the apex-inclusive form is the broader set
    else
      Result := TNameConstraintRelation.SubsumedBy;
    Exit;
  end;

  if LLen1 < LLen2 then
  begin
    if WithinDomain(ADomain2, ADomain1) then
      Result := TNameConstraintRelation.Subsumes
    else
      Result := TNameConstraintRelation.Disjoint;
    Exit;
  end;

  if WithinDomain(ADomain1, ADomain2) then
    Result := TNameConstraintRelation.SubsumedBy
  else
    Result := TNameConstraintRelation.Disjoint;
end;

class function TNameConstraintUtilities.IsParticularAddress(AKind: TNameConstraintHostNameKind): Boolean;
begin
  Result := (AKind = TNameConstraintHostNameKind.Mailbox) or (AKind = TNameConstraintHostNameKind.AtHost);
end;

class function TNameConstraintUtilities.Relate(const AName1,
  AName2: TNameConstraintHostName): TNameConstraintRelation;
begin
  if IsParticularAddress(AName1.Kind) then
  begin
    if IsParticularAddress(AName2.Kind) then
    begin
      if TStringUtilities.EqualsIgnoreCase(AName1.Value, AName2.Value) then
        Result := TNameConstraintRelation.Equal
      else
        Result := TNameConstraintRelation.Disjoint;
    end
    else if AName2.Kind = TNameConstraintHostNameKind.Domain then
    begin
      if WithinDomain(AName1.Host, AName2.Value) then
        Result := TNameConstraintRelation.SubsumedBy
      else
        Result := TNameConstraintRelation.Disjoint;
    end
    else if TStringUtilities.EqualsIgnoreCase(AName1.Host, AName2.Value) then
      Result := TNameConstraintRelation.SubsumedBy
    else
      Result := TNameConstraintRelation.Disjoint;
    Exit;
  end;

  if AName1.Kind = TNameConstraintHostNameKind.Domain then
  begin
    if IsParticularAddress(AName2.Kind) then
    begin
      if WithinDomain(AName2.Host, AName1.Value) then
        Result := TNameConstraintRelation.Subsumes
      else
        Result := TNameConstraintRelation.Disjoint;
    end
    else if AName2.Kind = TNameConstraintHostNameKind.Domain then
      Result := RelateDomains(AName1.Value, AName2.Value)
    else if WithinDomain(AName2.Value, AName1.Value) then
      Result := TNameConstraintRelation.Subsumes
    else
      Result := TNameConstraintRelation.Disjoint;
    Exit;
  end;

  if IsParticularAddress(AName2.Kind) then
  begin
    if TStringUtilities.EqualsIgnoreCase(AName2.Host, AName1.Value) then
      Result := TNameConstraintRelation.Subsumes
    else
      Result := TNameConstraintRelation.Disjoint;
  end
  else if AName2.Kind = TNameConstraintHostNameKind.Domain then
  begin
    if WithinDomain(AName1.Value, AName2.Value) then
      Result := TNameConstraintRelation.SubsumedBy
    else
      Result := TNameConstraintRelation.Disjoint;
  end
  else if TStringUtilities.EqualsIgnoreCase(AName1.Value, AName2.Value) then
    Result := TNameConstraintRelation.Equal
  else
    Result := TNameConstraintRelation.Disjoint;
end;

class procedure TNameConstraintUtilities.Intersect(const AName1, AName2: TNameConstraintHostName;
  const AIntersect: TCryptoLibHashSet<TNameConstraintHostName>);
begin
  case Relate(AName1, AName2) of
    TNameConstraintRelation.Equal, TNameConstraintRelation.SubsumedBy:
      AIntersect.Add(AName1); // AName1 is the narrower, or equal
    TNameConstraintRelation.Subsumes:
      AIntersect.Add(AName2); // AName2 is the narrower
    TNameConstraintRelation.Disjoint:
      ; // no intersection
  end;
end;

class procedure TNameConstraintUtilities.Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
  const AName: TNameConstraintHostName);
var
  LExisting: TNameConstraintHostName;
  LDropped: TCryptoLibHashSet<TNameConstraintHostName>;
begin
  if AExcluded = nil then
  begin
    AExcluded := TCryptoLibHashSet<TNameConstraintHostName>.Create
      (TPkixComparers.NameConstraintHostNameEqualityComparer);
    AExcluded.Add(AName);
    Exit;
  end;

  LDropped := TCryptoLibHashSet<TNameConstraintHostName>.Create
    (TPkixComparers.NameConstraintHostNameEqualityComparer);
  try
    for LExisting in AExcluded do
    begin
      case Relate(LExisting, AName) of
        TNameConstraintRelation.Equal, TNameConstraintRelation.Subsumes:
          Exit; // AName is covered, the set is already the union
        TNameConstraintRelation.SubsumedBy:
          LDropped.Add(LExisting); // AName will represent it
        TNameConstraintRelation.Disjoint:
          ;
      end;
    end;

    // deferred so the scan above walks a stable set
    for LExisting in LDropped do
    begin
      AExcluded.Remove(LExisting);
    end;
    AExcluded.Add(AName);
  finally
    LDropped.Free;
  end;
end;

{ TNameConstraintDns }

class function TNameConstraintDns.FromConstraint(const AConstraint: String): TNameConstraintHostName;
var
  LValue: String;
  LHostStart: Int32;
begin
  LValue := TNameConstraintUtilities.StripTrailingDot(AConstraint);
  // a constraint may carry the apex-excluding leading dot
  if TStringUtilities.StartsWith(LValue, '.') then
    LHostStart := 1
  else
    LHostStart := 0;
  TNameConstraintUtilities.CheckHostLabels(LValue, LHostStart, 'dNSName');
  Result := TNameConstraintHostName.Create(TNameConstraintHostNameKind.Domain, LValue, LValue);
end;

class function TNameConstraintDns.FromName(const AName: String): TNameConstraintHostName;
var
  LValue: String;
begin
  LValue := TNameConstraintUtilities.StripTrailingDot(AName);
  // a tested name may not carry the leading dot, so it is rejected as an empty first label
  TNameConstraintUtilities.CheckHostLabels(LValue, 0, 'dNSName');
  Result := TNameConstraintHostName.Create(TNameConstraintHostNameKind.Domain, LValue, LValue);
end;

class function TNameConstraintDns.IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintHostName>;
  const ADns: TNameConstraintHostName): Boolean;
var
  LConstraint: TNameConstraintHostName;
  LRelation: TNameConstraintRelation;
begin
  for LConstraint in AConstraints do
  begin
    LRelation := TNameConstraintUtilities.Relate(ADns, LConstraint);
    if (LRelation = TNameConstraintRelation.Equal) or (LRelation = TNameConstraintRelation.SubsumedBy) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TNameConstraintDns.Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintHostName>;
  const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<TNameConstraintHostName>;
var
  LSubtree: IGeneralSubtree;
  LPermitted, LDns: TNameConstraintHostName;
begin
  Result := TCryptoLibHashSet<TNameConstraintHostName>.Create
    (TPkixComparers.NameConstraintHostNameEqualityComparer);
  try
    for LSubtree in ASubtrees do
    begin
      LDns := FromConstraint(TNameConstraintUtilities.ExtractIA5String(LSubtree));
      if APermitted = nil then
        Result.Add(LDns)
      else
      begin
        for LPermitted in APermitted do
        begin
          // existing constraint first, so an equal pair keeps the first-registered instance
          TNameConstraintUtilities.Intersect(LPermitted, LDns, Result);
        end;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class procedure TNameConstraintDns.Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
  const ADns: TNameConstraintHostName);
begin
  TNameConstraintUtilities.Union(AExcluded, ADns);
end;

{ TNameConstraintEmail }

class function TNameConstraintEmail.FromValue(const AValue: String;
  AIsConstraint: Boolean): TNameConstraintHostName;
var
  LValue, LHost: String;
  LKind: TNameConstraintHostNameKind;
  LHostStart: Int32;
begin
  LValue := TNameConstraintUtilities.StripTrailingDot(AValue);
  LKind := TNameConstraintUtilities.ClassifyHostName(LValue, LHost);

  // the domain form's leading dot is constraint-only, so for a tested name it is an empty first label
  if LKind = TNameConstraintHostNameKind.Domain then
  begin
    if AIsConstraint then
      LHostStart := 1
    else
      LHostStart := 0;
  end
  else
    LHostStart := System.Length(LValue) - System.Length(LHost);

  TNameConstraintUtilities.CheckHostLabels(LValue, LHostStart, 'rfc822Name');
  Result := TNameConstraintHostName.Create(LKind, LValue, LHost);
end;

class function TNameConstraintEmail.FromConstraint(const AConstraint: String): TNameConstraintHostName;
begin
  Result := FromValue(AConstraint, True);
end;

class function TNameConstraintEmail.FromAddress(const AAddress: String): TNameConstraintHostName;
begin
  Result := FromValue(AAddress, False);
end;

class function TNameConstraintEmail.IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintHostName>;
  const AEmail: TNameConstraintHostName): Boolean;
var
  LConstraint: TNameConstraintHostName;
  LMatch: Boolean;
begin
  for LConstraint in AConstraints do
  begin
    case LConstraint.Kind of
      TNameConstraintHostNameKind.Mailbox: // a particular mailbox
        LMatch := TStringUtilities.EqualsIgnoreCase(AEmail.Value, LConstraint.Value);
      TNameConstraintHostNameKind.AtHost: // the legacy "@host" form
        LMatch := TStringUtilities.EqualsIgnoreCase(AEmail.Host, LConstraint.Host);
      TNameConstraintHostNameKind.Domain: // an address in a subdomain
        LMatch := TNameConstraintUtilities.WithinDomain(AEmail.Host, LConstraint.Value);
    else // on a particular host
      LMatch := TStringUtilities.EqualsIgnoreCase(AEmail.Host, LConstraint.Value);
    end;

    if LMatch then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TNameConstraintEmail.Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintHostName>;
  const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<TNameConstraintHostName>;
var
  LSubtree: IGeneralSubtree;
  LPermitted, LEmail: TNameConstraintHostName;
begin
  Result := TCryptoLibHashSet<TNameConstraintHostName>.Create
    (TPkixComparers.NameConstraintHostNameEqualityComparer);
  try
    for LSubtree in ASubtrees do
    begin
      LEmail := FromConstraint(TNameConstraintUtilities.ExtractIA5String(LSubtree));
      if APermitted = nil then
        Result.Add(LEmail)
      else
      begin
        for LPermitted in APermitted do
        begin
          TNameConstraintUtilities.Intersect(LPermitted, LEmail, Result);
        end;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class procedure TNameConstraintEmail.Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
  const AEmail: TNameConstraintHostName);
begin
  TNameConstraintUtilities.Union(AExcluded, AEmail);
end;

{ TNameConstraintUri }

class function TNameConstraintUri.FromValue(const AValue: String;
  AIsConstraint: Boolean): TNameConstraintHostName;
var
  LValue, LHost: String;
  LKind: TNameConstraintHostNameKind;
  LHostStart: Int32;
begin
  LValue := TNameConstraintUtilities.StripTrailingDot(AValue);
  LKind := TNameConstraintUtilities.ClassifyHostName(LValue, LHost);

  // the domain form is constraint-only, so an extracted host's leading dot is an empty first label
  if LKind = TNameConstraintHostNameKind.Domain then
  begin
    if AIsConstraint then
      LHostStart := 1
    else
      LHostStart := 0;
  end
  else
    LHostStart := System.Length(LValue) - System.Length(LHost);

  TNameConstraintUtilities.CheckHostLabels(LValue, LHostStart, 'uniformResourceIdentifier');
  Result := TNameConstraintHostName.Create(LKind, LValue, LHost);
end;

class function TNameConstraintUri.FromConstraint(const AConstraint: String): TNameConstraintHostName;
begin
  Result := FromValue(AConstraint, True);
end;

class function TNameConstraintUri.FromUri(const AUri: String): TNameConstraintHostName;
begin
  Result := FromValue(TNameConstraintUtilities.ExtractHostFromURL(AUri), False);
end;

class function TNameConstraintUri.IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintHostName>;
  const AUri: TNameConstraintHostName): Boolean;
var
  LConstraint: TNameConstraintHostName;
  LMatch: Boolean;
begin
  for LConstraint in AConstraints do
  begin
    if LConstraint.Kind = TNameConstraintHostNameKind.Domain then
      LMatch := TNameConstraintUtilities.WithinDomain(AUri.Value, LConstraint.Value)
    else
      // an extracted host cannot contain '@', so the address forms never match here
      LMatch := TStringUtilities.EqualsIgnoreCase(AUri.Value, LConstraint.Value);

    if LMatch then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TNameConstraintUri.Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintHostName>;
  const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<TNameConstraintHostName>;
var
  LSubtree: IGeneralSubtree;
  LPermitted, LUri: TNameConstraintHostName;
begin
  Result := TCryptoLibHashSet<TNameConstraintHostName>.Create
    (TPkixComparers.NameConstraintHostNameEqualityComparer);
  try
    for LSubtree in ASubtrees do
    begin
      LUri := FromConstraint(TNameConstraintUtilities.ExtractIA5String(LSubtree));
      if APermitted = nil then
        Result.Add(LUri)
      else
      begin
        for LPermitted in APermitted do
        begin
          TNameConstraintUtilities.Intersect(LPermitted, LUri, Result);
        end;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class procedure TNameConstraintUri.Union(var AExcluded: TCryptoLibHashSet<TNameConstraintHostName>;
  const AUri: TNameConstraintHostName);
begin
  TNameConstraintUtilities.Union(AExcluded, AUri);
end;

end.
