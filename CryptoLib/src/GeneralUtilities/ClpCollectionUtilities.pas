{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpCollectionUtilities;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Collection utility class with static methods.
  /// </summary>
  TCollectionUtilities = class sealed(TObject)
  public
    /// <summary>
    /// Convert a collection to an array.
    /// </summary>
    class function ToArray<T>(const AC: TList<T>): TCryptoLibGenericArray<T>; static;
    /// <summary>
    /// Convert a list to a string representation using a converter function.
    /// </summary>
    class function ToString<T>(const AC: TList<T>;
      const AConverter: TCryptoLibFunc<T, String>): String; static;
    /// <summary>
    /// Create a proxy array from an enumerable collection (like TDictionary.Keys).
    /// </summary>
    class function Proxy<T>(const AEnumerable: TEnumerable<T>): TCryptoLibGenericArray<T>; static;
    /// <summary>
    /// Return all keys of the dictionary as an array.
    /// </summary>
    class function Keys<K, V>(const AD: TDictionary<K, V>): TCryptoLibGenericArray<K>; static;
    /// <summary>
    /// Return all values of the dictionary as an array.
    /// </summary>
    class function Values<K, V>(const AD: TDictionary<K, V>): TCryptoLibGenericArray<V>; static;
    /// <summary>
    /// Get the value for AKey if it exists, otherwise Default(V) (e.g. '' for string, nil for class/interface).
    /// </summary>
    class function GetValueOrNull<K, V>(const D: TDictionary<K, V>; const AKey: K): V; static;
    /// <summary>
    /// Get D[AKey] if the key exists, otherwise return AKey. For TDictionary&lt;T,T&gt;.
    /// </summary>
    class function GetValueOrKey<T>(const D: TDictionary<T, T>; const AKey: T): T; static;
    /// <summary>
    /// Try to remove the entry behind the AKey. Returns True if the key was found and removed.
    /// </summary>
    class function Remove<K, V>(const AD: TDictionary<K, V>; const AKey: K): Boolean; overload; static;
    /// <summary>
    /// Try to get the value for AKey and remove the entry. Returns True if the key was found and removed.
    /// </summary>
    class function Remove<K, V>(const AD: TDictionary<K, V>; const AKey: K; out AValue: V): Boolean; overload; static;
  end;

implementation

{ TCollectionUtilities }

class function TCollectionUtilities.ToArray<T>(const AC: TList<T>): TCryptoLibGenericArray<T>;
var
  LCount, LI: Int32;
begin
  LCount := AC.Count;
  System.SetLength(Result, LCount);
  for LI := 0 to LCount - 1 do
  begin
    Result[LI] := AC[LI];
  end;
end;

class function TCollectionUtilities.ToString<T>(const AC: TList<T>;
  const AConverter: TCryptoLibFunc<T, String>): String;
var
  LI, LCount: Int32;
  LSB: TStringBuilder;
begin
  LCount := AC.Count;
  if LCount = 0 then
  begin
    Result := '[]';
    Exit;
  end;
  LSB := TStringBuilder.Create;
  try
    LSB.Append('[');
    LSB.Append(AConverter(AC[0]));
    for LI := 1 to LCount - 1 do
    begin
      LSB.Append(', ');
      LSB.Append(AConverter(AC[LI]));
    end;
    LSB.Append(']');
    Result := LSB.ToString;
  finally
    LSB.Free;
  end;
end;

class function TCollectionUtilities.Proxy<T>(const AEnumerable: TEnumerable<T>): TCryptoLibGenericArray<T>;
var
  LList: TList<T>;
  LItem: T;
begin
  LList := TList<T>.Create();
  try
    for LItem in AEnumerable do
    begin
      LList.Add(LItem);
    end;
    Result := ToArray<T>(LList);
  finally
    LList.Free;
  end;
end;

class function TCollectionUtilities.Keys<K, V>(const AD: TDictionary<K, V>): TCryptoLibGenericArray<K>;
begin
  Result := Proxy<K>(AD.Keys);
end;

class function TCollectionUtilities.Values<K, V>(const AD: TDictionary<K, V>): TCryptoLibGenericArray<V>;
begin
  Result := Proxy<V>(AD.Values);
end;

class function TCollectionUtilities.GetValueOrNull<K, V>(const D: TDictionary<K, V>;
  const AKey: K): V;
begin
  if D.TryGetValue(AKey, Result) then
    { Result already set }
  else
    Result := Default(V);
end;

class function TCollectionUtilities.GetValueOrKey<T>(const D: TDictionary<T, T>;
  const AKey: T): T;
begin
  if D.TryGetValue(AKey, Result) then
    { Result already set }
  else
    Result := AKey;
end;

class function TCollectionUtilities.Remove<K, V>(const AD: TDictionary<K, V>;
  const AKey: K): Boolean;
begin
  if not AD.ContainsKey(AKey) then
  begin
    Result := False;
    Exit;
  end;
  AD.Remove(AKey);
  Result := True;
end;

class function TCollectionUtilities.Remove<K, V>(const AD: TDictionary<K, V>;
  const AKey: K; out AValue: V): Boolean;
begin
  if not AD.TryGetValue(AKey, AValue) then
  begin
    Result := False;
    Exit;
  end;
  AD.Remove(AKey);
  Result := True;
end;

end.
