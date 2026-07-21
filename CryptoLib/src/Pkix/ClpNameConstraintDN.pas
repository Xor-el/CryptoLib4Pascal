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

unit ClpNameConstraintDN;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIAsn1Objects,
  ClpAsn1Objects,
  ClpIX500Asn1Objects,
  ClpX500Asn1Objects,
  ClpIX509Asn1Objects,
  ClpX509Asn1Objects,
  ClpIPkixTypes,
  ClpIetfUtilities,
  ClpStringUtilities,
  ClpNameConstraintTypes,
  ClpPkixComparers,
  ClpCryptoLibHashSet,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// A directoryName (tested name or constraint) parsed into its RDNs. Equality and display are those of
  /// the underlying sequence; MATCHING uses the broader normalized RDN comparison of RFC 5280 7.1.
  /// </summary>
  TNameConstraintDN = class(TInterfacedObject, INameConstraintDN)

  strict private
  var
    FSeq: IAsn1Sequence;
    FRdns: TCryptoLibGenericArray<IRdn>;

  strict protected
    function GetSequence: IAsn1Sequence;
    function GetRdns: TCryptoLibGenericArray<IRdn>;

  private
    class function WithinDNSubtree(const ADn, ASubtree: INameConstraintDN): Boolean; static;
    class function WithinDNSubtreeSgp22(const ADn, ASubtree: INameConstraintDN): Boolean; static;
    class function RdnMatchesSgp22Any(const ASubtreeRdn: IRdn;
      const ADnRdns: TCryptoLibGenericArray<IRdn>): Boolean; static;
    class function RdnMatchesSgp22(const ASubtreeRdn, ADnRdn: IRdn): Boolean; static;
    class function Relate(const ADn1, ADn2: INameConstraintDN): TNameConstraintRelation; static;

  public
    constructor Create(const ADn: IAsn1Sequence);

    function Equals(const AOther: INameConstraintDN): Boolean; reintroduce;
    function ToString: String; override;
  end;

  /// <summary>
  /// Subtree matching and set algebra for directoryName constraints.
  /// </summary>
  TNameConstraintDNUtilities = class sealed(TObject)
  public
    /// <summary>RFC 5280 7.1 matching: the constraint must be an initial prefix of the subject's RDNs.</summary>
    class function IsConstrained(const AConstraints: TCryptoLibHashSet<INameConstraintDN>;
      const ADn: INameConstraintDN): Boolean; static;
    /// <summary>
    /// Relaxed matching for GSMA SGP.22: every constraint RDN must be matched by some subject RDN
    /// regardless of position, and a serialNumber RDN matches on a prefix.
    /// </summary>
    class function IsConstrainedSgp22(const AConstraints: TCryptoLibHashSet<INameConstraintDN>;
      const ADn: INameConstraintDN): Boolean; static;

    class function Intersect(const APermitted: TCryptoLibHashSet<INameConstraintDN>;
      const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<INameConstraintDN>; static;
    class procedure Union(var AExcluded: TCryptoLibHashSet<INameConstraintDN>;
      const ADn: INameConstraintDN); static;
  end;

implementation

{ TNameConstraintDN }

constructor TNameConstraintDN.Create(const ADn: IAsn1Sequence);
var
  LIdx: Int32;
begin
  inherited Create();
  FSeq := ADn;
  System.SetLength(FRdns, ADn.Count);
  for LIdx := 0 to ADn.Count - 1 do
  begin
    FRdns[LIdx] := TRdn.GetInstance(ADn[LIdx]);
  end;
end;

function TNameConstraintDN.GetSequence: IAsn1Sequence;
begin
  Result := FSeq;
end;

function TNameConstraintDN.GetRdns: TCryptoLibGenericArray<IRdn>;
begin
  Result := FRdns;
end;

function TNameConstraintDN.Equals(const AOther: INameConstraintDN): Boolean;
begin
  Result := (AOther <> nil) and (FSeq <> nil) and FSeq.Equals(AOther.Sequence);
end;

function TNameConstraintDN.ToString: String;
begin
  if FSeq = nil then
    Result := ''
  else
    Result := FSeq.ToString();
end;

class function TNameConstraintDN.WithinDNSubtree(const ADn, ASubtree: INameConstraintDN): Boolean;
var
  LIdx: Int32;
begin
  Result := False;

  // an empty subtree would prefix every DN, so treat it as no match instead
  if System.Length(ASubtree.Rdns) < 1 then
    Exit;

  if System.Length(ASubtree.Rdns) > System.Length(ADn.Rdns) then
    Exit;

  // RFC 5280 4.2.1.10 / 7.1: match from index 0 only, else RDNs could be prepended ahead of the
  // permitted sequence and still pass.
  for LIdx := 0 to System.High(ASubtree.Rdns) do
  begin
    if not TIetfUtilities.RdnAreEqual(ASubtree.Rdns[LIdx], ADn.Rdns[LIdx]) then
      Exit;
  end;

  Result := True;
end;

class function TNameConstraintDN.RdnMatchesSgp22(const ASubtreeRdn, ADnRdn: IRdn): Boolean;
var
  LSubtreeFirst, LDnFirst: IAttributeTypeAndValue;
  LDnValue: IDerPrintableString;
  LSubtreeValue: IAsn1String;
begin
  if ASubtreeRdn.Count <> ADnRdn.Count then
  begin
    Result := False;
    Exit;
  end;

  LSubtreeFirst := ASubtreeRdn.First;
  LDnFirst := ADnRdn.First;

  if not LSubtreeFirst.AttrType.Equals(LDnFirst.AttrType) then
  begin
    Result := False;
    Exit;
  end;

  // the constraint's issuer identifier is a prefix of the subject's identifier
  if (ASubtreeRdn.Count = 1) and LSubtreeFirst.AttrType.Equals(TX509Name.SerialNumber) then
  begin
    LDnValue := TDerPrintableString.GetOptional(LDnFirst.Value);
    if (LDnValue <> nil) and Supports(LSubtreeFirst.Value.ToAsn1Object(), IAsn1String, LSubtreeValue) then
    begin
      Result := TStringUtilities.StartsWith(LDnValue.GetString(), LSubtreeValue.GetString());
      Exit;
    end;
  end;

  Result := TIetfUtilities.RdnAreEqual(ASubtreeRdn, ADnRdn);
end;

class function TNameConstraintDN.RdnMatchesSgp22Any(const ASubtreeRdn: IRdn;
  const ADnRdns: TCryptoLibGenericArray<IRdn>): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(ADnRdns) do
  begin
    if RdnMatchesSgp22(ASubtreeRdn, ADnRdns[LIdx]) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TNameConstraintDN.WithinDNSubtreeSgp22(const ADn, ASubtree: INameConstraintDN): Boolean;
var
  LIdx: Int32;
begin
  Result := False;

  if System.Length(ASubtree.Rdns) < 1 then
    Exit;

  if System.Length(ASubtree.Rdns) > System.Length(ADn.Rdns) then
    Exit;

  for LIdx := 0 to System.High(ASubtree.Rdns) do
  begin
    if not RdnMatchesSgp22Any(ASubtree.Rdns[LIdx], ADn.Rdns) then
      Exit;
  end;

  Result := True;
end;

class function TNameConstraintDN.Relate(const ADn1, ADn2: INameConstraintDN): TNameConstraintRelation;
var
  LLen1, LLen2, LCommon, LIdx: Int32;
begin
  LLen1 := System.Length(ADn1.Rdns);
  LLen2 := System.Length(ADn2.Rdns);

  // an empty RDNSequence would prefix everything, so it relates to nothing - not even another empty
  if (LLen1 < 1) or (LLen2 < 1) then
  begin
    Result := TNameConstraintRelation.Disjoint;
    Exit;
  end;

  if LLen1 < LLen2 then
    LCommon := LLen1
  else
    LCommon := LLen2;

  for LIdx := 0 to LCommon - 1 do
  begin
    if not TIetfUtilities.RdnAreEqual(ADn1.Rdns[LIdx], ADn2.Rdns[LIdx]) then
    begin
      Result := TNameConstraintRelation.Disjoint;
      Exit;
    end;
  end;

  if LLen1 = LLen2 then
    Result := TNameConstraintRelation.Equal
  else if LLen1 < LLen2 then
    Result := TNameConstraintRelation.Subsumes // the shorter prefix is the broader subtree
  else
    Result := TNameConstraintRelation.SubsumedBy;
end;

{ TNameConstraintDNUtilities }

class function TNameConstraintDNUtilities.IsConstrained(const AConstraints: TCryptoLibHashSet<INameConstraintDN>;
  const ADn: INameConstraintDN): Boolean;
var
  LConstraint: INameConstraintDN;
begin
  for LConstraint in AConstraints do
  begin
    if TNameConstraintDN.WithinDNSubtree(ADn, LConstraint) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TNameConstraintDNUtilities.IsConstrainedSgp22(const AConstraints: TCryptoLibHashSet<INameConstraintDN>;
  const ADn: INameConstraintDN): Boolean;
var
  LConstraint: INameConstraintDN;
begin
  for LConstraint in AConstraints do
  begin
    if TNameConstraintDN.WithinDNSubtreeSgp22(ADn, LConstraint) then
    begin
      Result := True;
      Exit;
    end;
  end;
  Result := False;
end;

class function TNameConstraintDNUtilities.Intersect(const APermitted: TCryptoLibHashSet<INameConstraintDN>;
  const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<INameConstraintDN>;
var
  LSubtree: IGeneralSubtree;
  LPermitted, LDn1: INameConstraintDN;
begin
  Result := TCryptoLibHashSet<INameConstraintDN>.Create(TPkixComparers.NameConstraintDNEqualityComparer);
  try
    for LSubtree in ASubtrees do
    begin
      LDn1 := TNameConstraintDN.Create(TAsn1Sequence.GetInstance(LSubtree.Base.Name));

      if APermitted = nil then
        Result.Add(LDn1)
      else
      begin
        for LPermitted in APermitted do
        begin
          // existing constraint first, so an equal pair keeps the first-registered instance
          case TNameConstraintDN.Relate(LPermitted, LDn1) of
            TNameConstraintRelation.Equal, TNameConstraintRelation.SubsumedBy:
              Result.Add(LPermitted);
            TNameConstraintRelation.Subsumes:
              Result.Add(LDn1);
            TNameConstraintRelation.Disjoint:
              ;
          end;
        end;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class procedure TNameConstraintDNUtilities.Union(var AExcluded: TCryptoLibHashSet<INameConstraintDN>;
  const ADn: INameConstraintDN);
var
  LExisting: INameConstraintDN;
  LDropped: TCryptoLibHashSet<INameConstraintDN>;
begin
  if AExcluded = nil then
  begin
    AExcluded := TCryptoLibHashSet<INameConstraintDN>.Create
      (TPkixComparers.NameConstraintDNEqualityComparer);
    AExcluded.Add(ADn);
    Exit;
  end;

  LDropped := TCryptoLibHashSet<INameConstraintDN>.Create(TPkixComparers.NameConstraintDNEqualityComparer);
  try
    for LExisting in AExcluded do
    begin
      case TNameConstraintDN.Relate(LExisting, ADn) of
        TNameConstraintRelation.Equal, TNameConstraintRelation.Subsumes:
          Exit; // ADn is covered, the set is already the union
        TNameConstraintRelation.SubsumedBy:
          LDropped.Add(LExisting); // ADn will represent it
        TNameConstraintRelation.Disjoint:
          ;
      end;
    end;

    // deferred so the scan above walks a stable set
    for LExisting in LDropped do
    begin
      AExcluded.Remove(LExisting);
    end;
    AExcluded.Add(ADn);
  finally
    LDropped.Free;
  end;
end;

end.
