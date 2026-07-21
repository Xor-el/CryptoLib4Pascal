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

unit ClpPkixComparers;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Defaults,
  ClpIPkixTypes,
  ClpIX509Asn1Objects,
  ClpNameConstraintTypes,
  ClpNameConstraintIP,
  ClpCryptoLibComparers,
  ClpStringUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Comparer for TNameConstraintHostName that uses the record's own value equality instead of a
  /// binary field compare. Used with TList so Contains, IndexOf and Remove work correctly.
  /// </summary>
  TNameConstraintHostNameComparer = class(TInterfacedObject, IComparer<TNameConstraintHostName>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: TNameConstraintHostName): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: TNameConstraintHostName): Integer;
{$ENDIF}
  end;

  /// <summary>
  /// Comparer for TNameConstraintIPRange that uses the record's own value equality instead of a
  /// binary field compare. Used with TList so Contains, IndexOf and Remove work correctly.
  /// </summary>
  TNameConstraintIPRangeComparer = class(TInterfacedObject, IComparer<TNameConstraintIPRange>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: TNameConstraintIPRange): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: TNameConstraintIPRange): Integer;
{$ENDIF}
  end;

  /// <summary>
  /// Comparer for INameConstraintDN that uses value equality instead of reference identity.
  /// Used with TList so Contains, IndexOf and Remove work correctly.
  /// </summary>
  TNameConstraintDNComparer = class(TInterfacedObject, IComparer<INameConstraintDN>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: INameConstraintDN): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: INameConstraintDN): Integer;
{$ENDIF}
  end;

  /// <summary>
  /// Comparer for IOtherName that uses ASN.1 value equality instead of reference identity.
  /// Used with TList so Contains, IndexOf and Remove work correctly.
  /// </summary>
  TOtherNameComparer = class(TInterfacedObject, IComparer<IOtherName>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: IOtherName): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: IOtherName): Integer;
{$ENDIF}
  end;

  /// <summary>
  /// Comparer for IPolicyQualifierInfo that uses ASN.1 value equality instead of reference identity.
  /// Used with TList so Contains, IndexOf and Remove work correctly.
  /// </summary>
  TPolicyQualifierInfoComparer = class(TInterfacedObject, IComparer<IPolicyQualifierInfo>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Compare(constref ALeft, ARight: IPolicyQualifierInfo): Integer;
{$ELSE}
    function Compare(const ALeft, ARight: IPolicyQualifierInfo): Integer;
{$ENDIF}
  end;

  /// <summary>
  /// Equality comparer for TNameConstraintHostName. Hashes the case-folded value, matching the
  /// record's case-insensitive equality. Used with TCryptoLibHashSet.
  /// </summary>
  TNameConstraintHostNameEqualityComparer = class(TInterfacedObject,
    IEqualityComparer<TNameConstraintHostName>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: TNameConstraintHostName): Boolean; reintroduce;
    function GetHashCode(constref AValue: TNameConstraintHostName): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: TNameConstraintHostName): Boolean; reintroduce;
    function GetHashCode(const AValue: TNameConstraintHostName): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
{$ENDIF}
  end;

  /// <summary>
  /// Equality comparer for TNameConstraintIPRange. Hashes the range's string form, which is derived
  /// solely from the bytes the record compares. Used with TCryptoLibHashSet.
  /// </summary>
  TNameConstraintIPRangeEqualityComparer = class(TInterfacedObject,
    IEqualityComparer<TNameConstraintIPRange>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: TNameConstraintIPRange): Boolean; reintroduce;
    function GetHashCode(constref AValue: TNameConstraintIPRange): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: TNameConstraintIPRange): Boolean; reintroduce;
    function GetHashCode(const AValue: TNameConstraintIPRange): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
{$ENDIF}
  end;

  /// <summary>
  /// Equality comparer for INameConstraintDN. Hashes the underlying sequence, matching the ASN.1
  /// value equality the type uses. Used with TCryptoLibHashSet.
  /// </summary>
  TNameConstraintDNEqualityComparer = class(TInterfacedObject, IEqualityComparer<INameConstraintDN>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: INameConstraintDN): Boolean; reintroduce;
    function GetHashCode(constref AValue: INameConstraintDN): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: INameConstraintDN): Boolean; reintroduce;
    function GetHashCode(const AValue: INameConstraintDN): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
{$ENDIF}
  end;

  /// <summary>
  /// Equality comparer for IOtherName using ASN.1 value equality over the DER encoding.
  /// Used with TCryptoLibHashSet.
  /// </summary>
  TOtherNameEqualityComparer = class(TInterfacedObject, IEqualityComparer<IOtherName>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: IOtherName): Boolean; reintroduce;
    function GetHashCode(constref AValue: IOtherName): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: IOtherName): Boolean; reintroduce;
    function GetHashCode(const AValue: IOtherName): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
{$ENDIF}
  end;

  /// <summary>
  /// Equality comparer for IGeneralSubtree using ASN.1 value equality over the DER encoding.
  /// Used with TCryptoLibHashSet.
  /// </summary>
  TGeneralSubtreeEqualityComparer = class(TInterfacedObject, IEqualityComparer<IGeneralSubtree>)
  strict private
{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
    function Equals(constref ALeft, ARight: IGeneralSubtree): Boolean; reintroduce;
    function GetHashCode(constref AValue: IGeneralSubtree): UInt32; reintroduce;
{$ELSE}
    function Equals(const ALeft, ARight: IGeneralSubtree): Boolean; reintroduce;
    function GetHashCode(const AValue: IGeneralSubtree): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI} reintroduce;
{$ENDIF}
  end;

  /// <summary>
  /// Static utility class providing PKIX-related comparers.
  /// </summary>
  TPkixComparers = class sealed(TObject)
  strict private
    class var
      FNameConstraintHostNameComparer: IComparer<TNameConstraintHostName>;
      FNameConstraintIPRangeComparer: IComparer<TNameConstraintIPRange>;
      FNameConstraintDNComparer: IComparer<INameConstraintDN>;
      FOtherNameComparer: IComparer<IOtherName>;
      FPolicyQualifierInfoComparer: IComparer<IPolicyQualifierInfo>;
      FNameConstraintHostNameEqualityComparer: IEqualityComparer<TNameConstraintHostName>;
      FNameConstraintIPRangeEqualityComparer: IEqualityComparer<TNameConstraintIPRange>;
      FNameConstraintDNEqualityComparer: IEqualityComparer<INameConstraintDN>;
      FOtherNameEqualityComparer: IEqualityComparer<IOtherName>;
      FGeneralSubtreeEqualityComparer: IEqualityComparer<IGeneralSubtree>;
    class constructor Create;
  public
    /// <summary>
    /// Gets the string-host name constraint comparer for use with TList.
    /// </summary>
    class property NameConstraintHostNameComparer: IComparer<TNameConstraintHostName>
      read FNameConstraintHostNameComparer;

    /// <summary>
    /// Gets the iPAddress name constraint comparer for use with TList.
    /// </summary>
    class property NameConstraintIPRangeComparer: IComparer<TNameConstraintIPRange>
      read FNameConstraintIPRangeComparer;

    /// <summary>
    /// Gets the directoryName constraint comparer for use with TList.
    /// </summary>
    class property NameConstraintDNComparer: IComparer<INameConstraintDN> read FNameConstraintDNComparer;

    /// <summary>
    /// Gets the otherName comparer for use with TList.
    /// </summary>
    class property OtherNameComparer: IComparer<IOtherName> read FOtherNameComparer;

    /// <summary>
    /// Gets the policy qualifier comparer for use with TList.
    /// </summary>
    class property PolicyQualifierInfoComparer: IComparer<IPolicyQualifierInfo>
      read FPolicyQualifierInfoComparer;

    /// <summary>
    /// Gets the string-host name constraint equality comparer for use with TCryptoLibHashSet.
    /// </summary>
    class property NameConstraintHostNameEqualityComparer: IEqualityComparer<TNameConstraintHostName>
      read FNameConstraintHostNameEqualityComparer;

    /// <summary>
    /// Gets the iPAddress name constraint equality comparer for use with TCryptoLibHashSet.
    /// </summary>
    class property NameConstraintIPRangeEqualityComparer: IEqualityComparer<TNameConstraintIPRange>
      read FNameConstraintIPRangeEqualityComparer;

    /// <summary>
    /// Gets the directoryName constraint equality comparer for use with TCryptoLibHashSet.
    /// </summary>
    class property NameConstraintDNEqualityComparer: IEqualityComparer<INameConstraintDN>
      read FNameConstraintDNEqualityComparer;

    /// <summary>
    /// Gets the otherName equality comparer for use with TCryptoLibHashSet.
    /// </summary>
    class property OtherNameEqualityComparer: IEqualityComparer<IOtherName>
      read FOtherNameEqualityComparer;

    /// <summary>
    /// Gets the GeneralSubtree equality comparer for use with TCryptoLibHashSet.
    /// </summary>
    class property GeneralSubtreeEqualityComparer: IEqualityComparer<IGeneralSubtree>
      read FGeneralSubtreeEqualityComparer;
  end;

implementation

// Lexicographic order on the encodings, shortest first. Only a stable total order for lookup.
// Only a stable total order for lookup; the strings carry no ordering meaning.
function CompareStrings(const ALeft, ARight: String): Integer;
begin
  if ALeft < ARight then
    Result := -1
  else if ALeft > ARight then
    Result := 1
  else
    Result := 0;
end;

{ TNameConstraintHostNameComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintHostNameComparer.Compare(constref ALeft, ARight: TNameConstraintHostName): Integer;
{$ELSE}
function TNameConstraintHostNameComparer.Compare(const ALeft, ARight: TNameConstraintHostName): Integer;
{$ENDIF}
begin
  if ALeft.Equals(ARight) then
  begin
    Result := 0;
    Exit;
  end;

  Result := CompareStrings(TStringUtilities.ToLowerInvariant(ALeft.Value),
    TStringUtilities.ToLowerInvariant(ARight.Value));
end;

{ TNameConstraintIPRangeComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintIPRangeComparer.Compare(constref ALeft, ARight: TNameConstraintIPRange): Integer;
{$ELSE}
function TNameConstraintIPRangeComparer.Compare(const ALeft, ARight: TNameConstraintIPRange): Integer;
{$ENDIF}
begin
  if ALeft.Equals(ARight) then
  begin
    Result := 0;
    Exit;
  end;

  Result := CompareStrings(ALeft.ToString(), ARight.ToString());
end;

{ TNameConstraintDNComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintDNComparer.Compare(constref ALeft, ARight: INameConstraintDN): Integer;
{$ELSE}
function TNameConstraintDNComparer.Compare(const ALeft, ARight: INameConstraintDN): Integer;
{$ENDIF}
begin
  if (ALeft = nil) and (ARight = nil) then
  begin
    Result := 0;
    Exit;
  end;

  if ALeft = nil then
  begin
    Result := -1;
    Exit;
  end;

  if ARight = nil then
  begin
    Result := 1;
    Exit;
  end;

  if ALeft.Equals(ARight) then
  begin
    Result := 0;
    Exit;
  end;

  Result := CompareStrings(ALeft.ToString(), ARight.ToString());
end;

{ TOtherNameComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TOtherNameComparer.Compare(constref ALeft, ARight: IOtherName): Integer;
{$ELSE}
function TOtherNameComparer.Compare(const ALeft, ARight: IOtherName): Integer;
{$ENDIF}
begin
  if (ALeft = nil) and (ARight = nil) then
  begin
    Result := 0;
    Exit;
  end;

  if ALeft = nil then
  begin
    Result := -1;
    Exit;
  end;

  if ARight = nil then
  begin
    Result := 1;
    Exit;
  end;

  if ALeft.Equals(ARight) then
  begin
    Result := 0;
    Exit;
  end;

  Result := TArrayUtilities.LexicographicCompare(ALeft.GetEncoded(), ARight.GetEncoded());
end;

{ TPolicyQualifierInfoComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TPolicyQualifierInfoComparer.Compare(constref ALeft, ARight: IPolicyQualifierInfo): Integer;
{$ELSE}
function TPolicyQualifierInfoComparer.Compare(const ALeft, ARight: IPolicyQualifierInfo): Integer;
{$ENDIF}
begin
  if (ALeft = nil) and (ARight = nil) then
  begin
    Result := 0;
    Exit;
  end;

  if ALeft = nil then
  begin
    Result := -1;
    Exit;
  end;

  if ARight = nil then
  begin
    Result := 1;
    Exit;
  end;

  if ALeft.Equals(ARight) then
  begin
    Result := 0;
    Exit;
  end;

  Result := TArrayUtilities.LexicographicCompare(ALeft.GetEncoded(), ARight.GetEncoded());
end;

{ TNameConstraintHostNameEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintHostNameEqualityComparer.Equals(constref ALeft,
  ARight: TNameConstraintHostName): Boolean;
{$ELSE}
function TNameConstraintHostNameEqualityComparer.Equals(const ALeft,
  ARight: TNameConstraintHostName): Boolean;
{$ENDIF}
begin
  Result := ALeft.Equals(ARight);
end;

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintHostNameEqualityComparer.GetHashCode(constref AValue: TNameConstraintHostName): UInt32;
{$ELSE}
function TNameConstraintHostNameEqualityComparer.GetHashCode(const AValue: TNameConstraintHostName): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
{$ENDIF}
begin
  // equality is case-insensitive, so the hash must be too
  Result := TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer.GetHashCode(AValue.Value);
end;

{ TNameConstraintIPRangeEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintIPRangeEqualityComparer.Equals(constref ALeft,
  ARight: TNameConstraintIPRange): Boolean;
{$ELSE}
function TNameConstraintIPRangeEqualityComparer.Equals(const ALeft,
  ARight: TNameConstraintIPRange): Boolean;
{$ENDIF}
begin
  Result := ALeft.Equals(ARight);
end;

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintIPRangeEqualityComparer.GetHashCode(constref AValue: TNameConstraintIPRange): UInt32;
{$ELSE}
function TNameConstraintIPRangeEqualityComparer.GetHashCode(const AValue: TNameConstraintIPRange): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
{$ENDIF}
begin
  // ToString is a pure function of the bytes Equals compares, and is digits and separators only,
  // so case folding is a no-op on it
  Result := TCryptoLibComparers.OrdinalIgnoreCaseEqualityComparer.GetHashCode(AValue.ToString());
end;

{ TNameConstraintDNEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintDNEqualityComparer.Equals(constref ALeft, ARight: INameConstraintDN): Boolean;
{$ELSE}
function TNameConstraintDNEqualityComparer.Equals(const ALeft, ARight: INameConstraintDN): Boolean;
{$ENDIF}
begin
  if ALeft = ARight then
  begin
    Result := True;
    Exit;
  end;

  if (ALeft = nil) or (ARight = nil) then
  begin
    Result := False;
    Exit;
  end;

  Result := ALeft.Equals(ARight);
end;

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TNameConstraintDNEqualityComparer.GetHashCode(constref AValue: INameConstraintDN): UInt32;
{$ELSE}
function TNameConstraintDNEqualityComparer.GetHashCode(const AValue: INameConstraintDN): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
{$ENDIF}
begin
  if (AValue = nil) or (AValue.Sequence = nil) then
  begin
    Result := 0;
    Exit;
  end;

  Result := TArrayUtilities.GetArrayHashCode(AValue.Sequence.GetEncoded());
end;

{ TOtherNameEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TOtherNameEqualityComparer.Equals(constref ALeft, ARight: IOtherName): Boolean;
{$ELSE}
function TOtherNameEqualityComparer.Equals(const ALeft, ARight: IOtherName): Boolean;
{$ENDIF}
begin
  if ALeft = ARight then
  begin
    Result := True;
    Exit;
  end;

  if (ALeft = nil) or (ARight = nil) then
  begin
    Result := False;
    Exit;
  end;

  Result := ALeft.Equals(ARight);
end;

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TOtherNameEqualityComparer.GetHashCode(constref AValue: IOtherName): UInt32;
{$ELSE}
function TOtherNameEqualityComparer.GetHashCode(const AValue: IOtherName): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
{$ENDIF}
begin
  if AValue = nil then
  begin
    Result := 0;
    Exit;
  end;

  Result := TArrayUtilities.GetArrayHashCode(AValue.GetEncoded());
end;

{ TGeneralSubtreeEqualityComparer }

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TGeneralSubtreeEqualityComparer.Equals(constref ALeft, ARight: IGeneralSubtree): Boolean;
{$ELSE}
function TGeneralSubtreeEqualityComparer.Equals(const ALeft, ARight: IGeneralSubtree): Boolean;
{$ENDIF}
begin
  if ALeft = ARight then
  begin
    Result := True;
    Exit;
  end;

  if (ALeft = nil) or (ARight = nil) then
  begin
    Result := False;
    Exit;
  end;

  Result := ALeft.Equals(ARight);
end;

{$IFDEF CRYPTOLIB_FPC_HAS_CONSTREF_GENERIC_COMPARER}
function TGeneralSubtreeEqualityComparer.GetHashCode(constref AValue: IGeneralSubtree): UInt32;
{$ELSE}
function TGeneralSubtreeEqualityComparer.GetHashCode(const AValue: IGeneralSubtree): {$IFDEF DELPHI}Int32; {$ELSE}UInt32; {$ENDIF DELPHI}
{$ENDIF}
begin
  if AValue = nil then
  begin
    Result := 0;
    Exit;
  end;

  Result := TArrayUtilities.GetArrayHashCode(AValue.GetEncoded());
end;

{ TPkixComparers }

class constructor TPkixComparers.Create;
begin
  FNameConstraintHostNameComparer := TNameConstraintHostNameComparer.Create();
  FNameConstraintIPRangeComparer := TNameConstraintIPRangeComparer.Create();
  FNameConstraintDNComparer := TNameConstraintDNComparer.Create();
  FOtherNameComparer := TOtherNameComparer.Create();
  FPolicyQualifierInfoComparer := TPolicyQualifierInfoComparer.Create();
  FNameConstraintHostNameEqualityComparer := TNameConstraintHostNameEqualityComparer.Create();
  FNameConstraintIPRangeEqualityComparer := TNameConstraintIPRangeEqualityComparer.Create();
  FNameConstraintDNEqualityComparer := TNameConstraintDNEqualityComparer.Create();
  FOtherNameEqualityComparer := TOtherNameEqualityComparer.Create();
  FGeneralSubtreeEqualityComparer := TGeneralSubtreeEqualityComparer.Create();
end;

end.
