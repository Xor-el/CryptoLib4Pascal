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

unit ClpNameConstraintIP;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpArrayUtilities,
  ClpAsn1Objects,
  ClpIX509Asn1Objects,
  ClpNameConstraintTypes,
  ClpCryptoLibHashSet,
  ClpCryptoLibConfig,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidIPAddressLength = 'iPAddress name has invalid length: %d';
  SInvalidIPRangeLength = 'iPAddress constraint has invalid length: %d';
  SNonContiguousSubnetMask = 'iPAddress constraint has a non-contiguous subnet mask';

type
  /// <summary>
  /// A tested iPAddress name in canonical form: an IPv4-mapped IPv6 address (RFC 4291 sec. 2.5.5.2)
  /// is reduced to 4 bytes, and anything but 4 or 16 bytes fails closed.
  /// </summary>
  TNameConstraintIPAddress = record

  private
  var
    FBytes: TCryptoLibByteArray;

    /// <summary>Is the 16-byte span at AOff an IPv4-mapped IPv6 address (RFC 4291 sec. 2.5.5.2)?</summary>
    class function IsIPv4MappedIPv6Address(const AIp: TCryptoLibByteArray; AOff: Int32): Boolean;
      overload; static;
    class function IsIPv4MappedIPv6Address(const AIp: TCryptoLibByteArray): Boolean; overload; static;

  public
    class function Create(const AOctets: TCryptoLibByteArray): TNameConstraintIPAddress; static;
    function Bytes: TCryptoLibByteArray;
  end;

  /// <summary>
  /// An iPAddress name constraint in canonical CIDR form. The DER value is base address || subnet mask
  /// (RFC 5280 4.2.1.10), so 8 bytes for IPv4 and 32 for IPv6.
  /// </summary>
  TNameConstraintIPRange = record

  strict private
  var
    FBytes: TCryptoLibByteArray;
    FPrefixLength: Int32;

    class function GetBit(const AOctets: TCryptoLibByteArray; AOff, ABit: Int32): Boolean; static;
    /// <summary>Is the ALen-byte mask at AOff a contiguous CIDR prefix (leading 1-bits then all 0-bits)?</summary>
    class function IsContiguousMask(const AOctets: TCryptoLibByteArray; AOff, ALen: Int32)
      : Boolean; static;
    /// <summary>The contiguous prefix length to round a non-contiguous mask to: excluded takes the index
    /// of the first 0-bit (broader), permitted takes one past the last 1-bit (narrower).</summary>
    class function MaskPrefixLength(const AOctets: TCryptoLibByteArray; AOff, ALen: Int32;
      AExcluded: Boolean): Int32; static;
    /// <summary>Overwrite the ALen-byte mask at AOff with a contiguous prefix of APrefixBits 1-bits.</summary>
    class procedure WritePrefixMask(var AOctets: TCryptoLibByteArray;
      AOff, ALen, APrefixBits: Int32); static;
    /// <summary>Zero the base's host bits (those cleared by the mask) so equal networks are byte-equal.</summary>
    class procedure ZeroHostBits(var AOctets: TCryptoLibByteArray); static;
    /// <summary>Collapse an IPv4-mapped IPv6 constraint to its 8-byte form. The mask must cover the full
    /// ::ffff:0:0/96 prefix, else it is an IPv6 range and collapsing would change which addresses match.</summary>
    class function NormalizeIPv4MappedIPv6Constraint(const AConstraint: TCryptoLibByteArray)
      : TCryptoLibByteArray; static;
    /// <summary>Canonical CIDR ranges nest or are disjoint: they overlap iff their bases agree within the
    /// shared prefix, and then the shorter prefix is the broader range.</summary>
    class function Relate(const ARange1, ARange2: TNameConstraintIPRange)
      : TNameConstraintRelation; static;

  private
    class function Create(const AEncoded: TCryptoLibByteArray; AExcluded: Boolean)
      : TNameConstraintIPRange; overload; static;
    class function CreateFrom(const ABytes: TCryptoLibByteArray): TNameConstraintIPRange; static;


  public
    /// <summary>Permitted subtree: a salvaged non-contiguous mask is narrowed.</summary>
    class function CreatePermitted(const AEncoded: TCryptoLibByteArray): TNameConstraintIPRange; static;
    /// <summary>Excluded subtree: a salvaged non-contiguous mask is broadened.</summary>
    class function CreateExcluded(const AEncoded: TCryptoLibByteArray): TNameConstraintIPRange; static;

    function Equals(const AOther: TNameConstraintIPRange): Boolean;
    function ToString: String;

    class function IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintIPRange>;
      const AAddress: TNameConstraintIPAddress): Boolean; static;
    /// <summary>APermitted nil means unrestricted so far. Returns a new set the caller owns.</summary>
    class function Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintIPRange>;
      const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>)
      : TCryptoLibHashSet<TNameConstraintIPRange>; static;
    /// <summary>Creates the set if AExcluded is nil; otherwise updates it in place.</summary>
    class procedure Union(var AExcluded: TCryptoLibHashSet<TNameConstraintIPRange>;
      const ARange: TNameConstraintIPRange); static;
  end;

implementation

uses
  ClpPkixComparers;

{ TNameConstraintIPAddress }

class function TNameConstraintIPAddress.IsIPv4MappedIPv6Address(const AIp: TCryptoLibByteArray;
  AOff: Int32): Boolean;
var
  LIdx: Int32;
begin
  for LIdx := 0 to 9 do
  begin
    if AIp[AOff + LIdx] <> 0 then
    begin
      Result := False;
      Exit;
    end;
  end;
  Result := (AIp[AOff + 10] = $FF) and (AIp[AOff + 11] = $FF);
end;

class function TNameConstraintIPAddress.IsIPv4MappedIPv6Address(const AIp: TCryptoLibByteArray): Boolean;
begin
  Result := (System.Length(AIp) = 16) and IsIPv4MappedIPv6Address(AIp, 0);
end;

class function TNameConstraintIPAddress.Create(const AOctets: TCryptoLibByteArray)
  : TNameConstraintIPAddress;
var
  LCanonical: TCryptoLibByteArray;
  LLength: Int32;
begin
  // An IPv4-mapped IPv6 address (RFC 4291 sec. 2.5.5.2) reduces to its 4-byte IPv4 form.
  if IsIPv4MappedIPv6Address(AOctets) then
  begin
    LCanonical := TArrayUtilities.CopyOfRange<Byte>(AOctets, 12, 16);
  end
  else
  begin
    LCanonical := AOctets;
  end;

  LLength := System.Length(LCanonical);
  if (LLength <> 4) and (LLength <> 16) then
  begin
    raise EPkixNameConstraintValidatorCryptoLibException.CreateResFmt(@SInvalidIPAddressLength, [LLength]);
  end;

  Result.FBytes := LCanonical;
end;

function TNameConstraintIPAddress.Bytes: TCryptoLibByteArray;
begin
  Result := FBytes;
end;

{ TNameConstraintIPRange }

class function TNameConstraintIPRange.GetBit(const AOctets: TCryptoLibByteArray;
  AOff, ABit: Int32): Boolean;
begin
  Result := (AOctets[AOff + (ABit shr 3)] and ($80 shr (ABit and 7))) <> 0;
end;

class function TNameConstraintIPRange.IsContiguousMask(const AOctets: TCryptoLibByteArray;
  AOff, ALen: Int32): Boolean;
var
  LIdx, LComplement: Int32;
begin
  LIdx := 0;
  while (LIdx < ALen) and (AOctets[AOff + LIdx] = $FF) do
  begin
    System.Inc(LIdx);
  end;
  if LIdx < ALen then
  begin
    // The partial byte must be a left-aligned run of 1s, i.e. its complement is a right-aligned run.
    LComplement := (not AOctets[AOff + LIdx]) and $FF;
    if (LComplement and (LComplement + 1)) <> 0 then
    begin
      Result := False;
      Exit;
    end;
    System.Inc(LIdx);
    while LIdx < ALen do
    begin
      if AOctets[AOff + LIdx] <> 0 then
      begin
        Result := False;
        Exit;
      end;
      System.Inc(LIdx);
    end;
  end;
  Result := True;
end;

class function TNameConstraintIPRange.MaskPrefixLength(const AOctets: TCryptoLibByteArray;
  AOff, ALen: Int32; AExcluded: Boolean): Int32;
var
  LTotalBits, LBit: Int32;
begin
  LTotalBits := ALen * 8;
  if AExcluded then
  begin
    for LBit := 0 to LTotalBits - 1 do
    begin
      if not GetBit(AOctets, AOff, LBit) then
      begin
        Result := LBit;
        Exit;
      end;
    end;
    Result := LTotalBits;
    Exit;
  end;

  for LBit := LTotalBits - 1 downto 0 do
  begin
    if GetBit(AOctets, AOff, LBit) then
    begin
      Result := LBit + 1;
      Exit;
    end;
  end;
  Result := 0;
end;

class procedure TNameConstraintIPRange.WritePrefixMask(var AOctets: TCryptoLibByteArray;
  AOff, ALen, APrefixBits: Int32);
var
  LIdx, LRemaining, LOnes: Int32;
begin
  for LIdx := 0 to ALen - 1 do
  begin
    LRemaining := APrefixBits - LIdx * 8;
    if LRemaining <= 0 then
    begin
      LOnes := 0;
    end
    else if LRemaining >= 8 then
    begin
      LOnes := 8;
    end
    else
    begin
      LOnes := LRemaining;
    end;
    if LOnes = 0 then
    begin
      AOctets[AOff + LIdx] := 0;
    end
    else
    begin
      AOctets[AOff + LIdx] := Byte($FF shl (8 - LOnes));
    end;
  end;
end;

class procedure TNameConstraintIPRange.ZeroHostBits(var AOctets: TCryptoLibByteArray);
var
  LHalf, LIdx: Int32;
begin
  LHalf := System.Length(AOctets) div 2;
  for LIdx := 0 to LHalf - 1 do
  begin
    AOctets[LIdx] := AOctets[LIdx] and AOctets[LHalf + LIdx];
  end;
end;

class function TNameConstraintIPRange.NormalizeIPv4MappedIPv6Constraint(const AConstraint
  : TCryptoLibByteArray): TCryptoLibByteArray;
var
  LIdx: Int32;
begin
  Result := AConstraint;
  if System.Length(AConstraint) <> 32 then
  begin
    Exit;
  end;
  if not TNameConstraintIPAddress.IsIPv4MappedIPv6Address(AConstraint, 0) then
  begin
    Exit;
  end;
  for LIdx := 16 to 27 do
  begin
    if AConstraint[LIdx] <> $FF then
    begin
      Exit;
    end;
  end;

  System.SetLength(Result, 8);
  System.Move(AConstraint[12], Result[0], 4); // IPv4 address, the low 32 bits of the mapped address
  System.Move(AConstraint[28], Result[4], 4); // IPv4 mask, the low 32 bits of the mask
end;

class function TNameConstraintIPRange.Relate(const ARange1, ARange2: TNameConstraintIPRange)
  : TNameConstraintRelation;
var
  LHalf, LIdx, LCommon, LPrefix1, LPrefix2: Int32;
begin
  if System.Length(ARange1.FBytes) <> System.Length(ARange2.FBytes) then
  begin
    Result := TNameConstraintRelation.Disjoint; // different address families never overlap
    Exit;
  end;

  LHalf := System.Length(ARange1.FBytes) div 2;
  for LIdx := 0 to LHalf - 1 do
  begin
    LCommon := ARange1.FBytes[LHalf + LIdx] and ARange2.FBytes[LHalf + LIdx];
    if ((ARange1.FBytes[LIdx] xor ARange2.FBytes[LIdx]) and LCommon) <> 0 then
    begin
      Result := TNameConstraintRelation.Disjoint; // the networks differ within the shared prefix
      Exit;
    end;
  end;

  LPrefix1 := ARange1.FPrefixLength;
  LPrefix2 := ARange2.FPrefixLength;
  if LPrefix1 = LPrefix2 then
  begin
    Result := TNameConstraintRelation.Equal;
  end
  else if LPrefix1 < LPrefix2 then
  begin
    Result := TNameConstraintRelation.Subsumes;
  end
  else
  begin
    Result := TNameConstraintRelation.SubsumedBy;
  end;
end;

class function TNameConstraintIPRange.CreateFrom(const ABytes: TCryptoLibByteArray)
  : TNameConstraintIPRange;
var
  LHalf: Int32;
begin
  LHalf := System.Length(ABytes) div 2;
  Result.FBytes := ABytes;
  // For a contiguous mask the index of the first 0-bit IS the prefix length.
  Result.FPrefixLength := MaskPrefixLength(ABytes, LHalf, LHalf, True);
end;

class function TNameConstraintIPRange.Create(const AEncoded: TCryptoLibByteArray; AExcluded: Boolean)
  : TNameConstraintIPRange;
var
  LCanonical: TCryptoLibByteArray;
  LLength, LHalf: Int32;
begin
  LLength := System.Length(AEncoded);
  if (LLength <> 8) and (LLength <> 32) then
  begin
    raise EPkixNameConstraintValidatorCryptoLibException.CreateResFmt(@SInvalidIPRangeLength, [LLength]);
  end;

  // Work on a copy: canonicalisation mutates in place and the caller's array may be shared.
  LCanonical := System.Copy(AEncoded);
  LHalf := LLength div 2;

  if not IsContiguousMask(LCanonical, LHalf, LHalf) then
  begin
    // A non-contiguous mask is not valid CIDR and would let the set algebra mint new ranges. Reject it
    // unless leniency rounds it to the most-restrictive contiguous mask for the context.
    if not TCryptoLibConfig.X509.AllowLenientIPAddressMask then
    begin
      raise EPkixNameConstraintValidatorCryptoLibException.CreateRes(@SNonContiguousSubnetMask);
    end;
    WritePrefixMask(LCanonical, LHalf, LHalf, MaskPrefixLength(LCanonical, LHalf, LHalf, AExcluded));
  end;

  LCanonical := NormalizeIPv4MappedIPv6Constraint(LCanonical);
  ZeroHostBits(LCanonical);

  Result := CreateFrom(LCanonical);
end;

class function TNameConstraintIPRange.CreatePermitted(const AEncoded: TCryptoLibByteArray)
  : TNameConstraintIPRange;
begin
  Result := Create(AEncoded, False);
end;

class function TNameConstraintIPRange.CreateExcluded(const AEncoded: TCryptoLibByteArray)
  : TNameConstraintIPRange;
begin
  Result := Create(AEncoded, True);
end;

function TNameConstraintIPRange.Equals(const AOther: TNameConstraintIPRange): Boolean;
begin
  Result := TArrayUtilities.AreEqual(FBytes, AOther.FBytes);
end;

function TNameConstraintIPRange.ToString: String;
var
  LHalf, LIdx: Int32;
  LBuilder: TStringBuilder;
begin
  LHalf := System.Length(FBytes) div 2;
  LBuilder := TStringBuilder.Create();
  try
    for LIdx := 0 to LHalf - 1 do
    begin
      if LIdx > 0 then
      begin
        LBuilder.Append('.');
      end;
      LBuilder.Append(IntToStr(Int32(FBytes[LIdx])));
    end;
    LBuilder.Append('/');
    for LIdx := LHalf to System.Length(FBytes) - 1 do
    begin
      if LIdx > LHalf then
      begin
        LBuilder.Append('.');
      end;
      LBuilder.Append(IntToStr(Int32(FBytes[LIdx])));
    end;
    Result := LBuilder.ToString();
  finally
    LBuilder.Free;
  end;
end;

class function TNameConstraintIPRange.IsConstrained(const AConstraints: TCryptoLibHashSet<TNameConstraintIPRange>;
  const AAddress: TNameConstraintIPAddress): Boolean;
var
  LByteIdx, LIpLength, LMask: Int32;
  LConstraintBytes, LIpBytes: TCryptoLibByteArray;
  LConstraint: TNameConstraintIPRange;
  LMatched: Boolean;
begin
  if AConstraints = nil then
  begin
    Result := False;
    Exit;
  end;

  LIpBytes := AAddress.Bytes;
  LIpLength := System.Length(LIpBytes);
  for LConstraint in AConstraints do
  begin
    LConstraintBytes := LConstraint.FBytes;
    // Both operands are canonical, so the length pre-filter compares like-for-like address families.
    if LIpLength = (System.Length(LConstraintBytes) div 2) then
    begin
      LMatched := True;
      // Match iff both agree on every masked bit; the mask half follows the base half.
      for LByteIdx := 0 to LIpLength - 1 do
      begin
        LMask := LConstraintBytes[LIpLength + LByteIdx];
        if (LIpBytes[LByteIdx] and LMask) <> (LConstraintBytes[LByteIdx] and LMask) then
        begin
          LMatched := False;
          Break;
        end;
      end;
      if LMatched then
      begin
        Result := True;
        Exit;
      end;
    end;
  end;
  Result := False;
end;

class function TNameConstraintIPRange.Intersect(const APermitted: TCryptoLibHashSet<TNameConstraintIPRange>;
  const ASubtrees: TCryptoLibHashSet<IGeneralSubtree>): TCryptoLibHashSet<TNameConstraintIPRange>;
var
  LSubtree: IGeneralSubtree;
  LPermitted, LRange: TNameConstraintIPRange;
begin
  Result := TCryptoLibHashSet<TNameConstraintIPRange>.Create
    (TPkixComparers.NameConstraintIPRangeEqualityComparer);
  try
    if ASubtrees <> nil then
    begin
      for LSubtree in ASubtrees do
      begin
        LRange := CreatePermitted(TAsn1OctetString.GetInstance(LSubtree.Base.Name).GetOctets());

        if APermitted = nil then
        begin
          Result.Add(LRange);
        end
        else
        begin
          for LPermitted in APermitted do
          begin
            // The narrower of an overlapping pair is the intersection. The existing constraint comes
            // first, so an equal pair keeps the first-registered instance.
            case Relate(LPermitted, LRange) of
              TNameConstraintRelation.Equal, TNameConstraintRelation.SubsumedBy:
                Result.Add(LPermitted);
              TNameConstraintRelation.Subsumes:
                Result.Add(LRange);
              TNameConstraintRelation.Disjoint:
                ; // no intersection
            end;
          end;
        end;
      end;
    end;
  except
    Result.Free;
    raise;
  end;
end;

class procedure TNameConstraintIPRange.Union(var AExcluded: TCryptoLibHashSet<TNameConstraintIPRange>;
  const ARange: TNameConstraintIPRange);
var
  LExisting: TNameConstraintIPRange;
  LDropped: TCryptoLibHashSet<TNameConstraintIPRange>;
begin
  if AExcluded = nil then
  begin
    AExcluded := TCryptoLibHashSet<TNameConstraintIPRange>.Create
      (TPkixComparers.NameConstraintIPRangeEqualityComparer);
    AExcluded.Add(ARange);
    Exit;
  end;

  LDropped := nil;
  try
    for LExisting in AExcluded do
    begin
      // Covered (contained or equal, an equal pair keeping the first-registered instance) means the set
      // is already the union; otherwise ARange replaces whatever it strictly contains.
      case Relate(LExisting, ARange) of
        TNameConstraintRelation.Equal, TNameConstraintRelation.Subsumes:
          Exit;
        TNameConstraintRelation.SubsumedBy:
          begin
            if LDropped = nil then
            begin
              LDropped := TCryptoLibHashSet<TNameConstraintIPRange>.Create
                (TPkixComparers.NameConstraintIPRangeEqualityComparer);
            end;
            LDropped.Add(LExisting);
          end;
        TNameConstraintRelation.Disjoint:
          ; // keep it
      end;
    end;

    // Deferred so the scan above walks a stable set.
    if LDropped <> nil then
    begin
      for LExisting in LDropped do
      begin
        AExcluded.Remove(LExisting);
      end;
    end;
    AExcluded.Add(ARange);
  finally
    LDropped.Free;
  end;
end;

end.
