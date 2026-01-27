{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.             * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCryptoLibComparers;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Defaults,
  ClpIAsn1Objects,
  ClpStringUtilities,
  ClpPlatformUtilities;

type
  /// <summary>
  /// Equality comparer for IDerObjectIdentifier that uses value-based comparison
  /// (Asn1Equals) instead of reference equality. Used with TDictionary.
  /// </summary>
  TOidEqualityComparer = class(TInterfacedObject, IEqualityComparer<IDerObjectIdentifier>)
  strict private
    function Equals(const ALeft, ARight: IDerObjectIdentifier): Boolean; reintroduce;
    function GetHashCode(const AValue: IDerObjectIdentifier): Integer;
  end;

  /// <summary>
  /// Comparer for IDerObjectIdentifier that uses value-based comparison
  /// (Asn1Equals) for equality and ID string comparison for ordering.
  /// Used with TList to ensure Contains, IndexOf, and Remove work correctly.
  /// </summary>
  TOidComparer = class(TInterfacedObject, IComparer<IDerObjectIdentifier>)
  strict private
    function Compare(const ALeft, ARight: IDerObjectIdentifier): Integer;
  end;

  /// <summary>
  /// Equality comparer for String that uses ordinal case-insensitive comparison.
  /// Uses invariant culture for case conversion (OrdinalIgnoreCase).
  /// Used with TDictionary for case-insensitive string keys.
  /// </summary>
  TOrdinalIgnoreCaseEqualityComparer = class(TInterfacedObject, IEqualityComparer<String>)
  strict private
    function Equals(const ALeft, ARight: String): Boolean; reintroduce;
    function GetHashCode(const AValue: String): Integer;
  end;

  /// <summary>
  /// Static utility class providing access to custom comparers for CryptoLib types.
  /// </summary>
  TCryptoLibComparers = class sealed(TObject)
  strict private
    class var
      FOidEqualityComparer: IEqualityComparer<IDerObjectIdentifier>;
      FOidComparer: IComparer<IDerObjectIdentifier>;
      FOrdinalIgnoreCaseEqualityComparer: IEqualityComparer<String>;
    class constructor Create;
  public
    /// <summary>
    /// Gets the OID equality comparer for use with TDictionary.
    /// </summary>
    class property OidEqualityComparer: IEqualityComparer<IDerObjectIdentifier> read FOidEqualityComparer;
    
    /// <summary>
    /// Gets the OID comparer for use with TList.
    /// </summary>
    class property OidComparer: IComparer<IDerObjectIdentifier> read FOidComparer;
    
    /// <summary>
    /// Gets the string ordinal ignore case equality comparer for use with TDictionary.
    /// </summary>
    class property OrdinalIgnoreCaseEqualityComparer: IEqualityComparer<String> read FOrdinalIgnoreCaseEqualityComparer;
  end;

implementation

{ TOidEqualityComparer }

function TOidEqualityComparer.Equals(const ALeft, ARight: IDerObjectIdentifier): Boolean;
begin
  // Use value-based comparison via Asn1Equals
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
  
  // Use Asn1Equals which compares the contents byte arrays
  Result := ALeft.Equals(ARight);
end;

function TOidEqualityComparer.GetHashCode(const AValue: IDerObjectIdentifier): Integer;
begin
  if AValue = nil then
  begin
    Result := 0;
    Exit;
  end;
  
  // Use Asn1GetHashCode which is based on contents byte array
  Result := AValue.CallAsn1GetHashCode();
end;

{ TOidComparer }

function TOidComparer.Compare(const ALeft, ARight: IDerObjectIdentifier): Integer;
begin
  // If both are nil, they're equal
  if (ALeft = nil) and (ARight = nil) then
  begin
    Result := 0;
    Exit;
  end;
  
  // nil is less than non-nil
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
  
  // If they're the same reference, they're equal
  if ALeft = ARight then
  begin
    Result := 0;
    Exit;
  end;
  
  // Use value-based equality check (Asn1Equals)
  if ALeft.Equals(ARight) then
  begin
    Result := 0;
    Exit;
  end;
  
  // If not equal, compare by ID string for ordering
  if ALeft.Id < ARight.Id then
    Result := -1
  else if ALeft.Id > ARight.Id then
    Result := 1
  else
    Result := 0; // Should not happen if Equals returned False, but handle it
end;

{ TOrdinalIgnoreCaseEqualityComparer }

function TOrdinalIgnoreCaseEqualityComparer.Equals(const ALeft, ARight: String): Boolean;
begin
  // Use ordinal case-insensitive comparison (invariant culture)
  Result := TStringUtilities.EqualsIgnoreCase(ALeft, ARight);
end;

function TOrdinalIgnoreCaseEqualityComparer.GetHashCode(const AValue: String): Integer;
var
  LLowerValue: String;
  I: Int32;
begin
  if System.Length(AValue) = 0 then
  begin
    Result := 0;
    Exit;
  end;
  
  // Convert to lowercase using invariant culture for consistent hashing
  LLowerValue := TStringUtilities.ToLowerInvariant(AValue);
  
  // Compute hash code from lowercase string
  // Using a simple hash algorithm (FNV-1a style)
  Result := 2166136261; // FNV offset basis
  for I := 1 to System.Length(LLowerValue) do
  begin
    Result := (Result xor Ord(LLowerValue[I])) * 16777619; // FNV prime
  end;
end;

{ TCryptoLibComparers }

class constructor TCryptoLibComparers.Create;
begin
  FOidEqualityComparer := TOidEqualityComparer.Create();
  FOidComparer := TOidComparer.Create();
  FOrdinalIgnoreCaseEqualityComparer := TOrdinalIgnoreCaseEqualityComparer.Create();
end;

end.
