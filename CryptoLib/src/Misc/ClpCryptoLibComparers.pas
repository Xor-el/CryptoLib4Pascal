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
  ClpStringUtilities;

type
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
      FOrdinalIgnoreCaseEqualityComparer: IEqualityComparer<String>;
    class constructor Create;
  public
    /// <summary>
    /// Gets the string ordinal ignore case equality comparer for use with TDictionary.
    /// </summary>
    class property OrdinalIgnoreCaseEqualityComparer: IEqualityComparer<String> read FOrdinalIgnoreCaseEqualityComparer;
  end;

implementation

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
  FOrdinalIgnoreCaseEqualityComparer := TOrdinalIgnoreCaseEqualityComparer.Create();
end;

end.
