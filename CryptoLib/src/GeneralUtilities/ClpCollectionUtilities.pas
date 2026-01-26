{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                Copyright (c) 2018 - 20XX Ugochukwu Mmaduekwe                    * }
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
    /// Map an array or collection using a function.
    /// </summary>
    class function Map<T, TResult>(const ATs: TCryptoLibGenericArray<T>;
      const AFunc: TFunc<T, TResult>): TCryptoLibGenericArray<TResult>; static;
    /// <summary>
    /// Convert a collection to an array.
    /// </summary>
    class function ToArray<T>(const AC: TList<T>): TCryptoLibGenericArray<T>; static;
    /// <summary>
    /// Convert a collection to a string representation using a converter function.
    /// </summary>
    class function ToString<T>(const AC: TCryptoLibGenericArray<T>;
      const AConverter: TFunc<T, String>): String; reintroduce; overload; static;
    /// <summary>
    /// Create a proxy array from an enumerable collection (like TDictionary.Keys).
    /// </summary>
    class function Proxy<T>(const AEnumerable: IEnumerable<T>): TCryptoLibGenericArray<T>; static;
    /// <summary>
    /// Get the value for AKey if it exists, otherwise Default(V) (e.g. '' for string, nil for class/interface).
    /// </summary>
    class function GetValueOrNull<K, V>(const D: TDictionary<K, V>; const AKey: K): V; static;
    /// <summary>
    /// Get D[AKey] if the key exists, otherwise return AKey. For TDictionary&lt;T,T&gt;.
    /// </summary>
    class function GetValueOrKey<T>(const D: TDictionary<T, T>; const AKey: T): T; static;
  end;

implementation

{ TCollectionUtilities }

class function TCollectionUtilities.Map<T, TResult>(const ATs: TCryptoLibGenericArray<T>;
  const AFunc: TFunc<T, TResult>): TCryptoLibGenericArray<TResult>;
var
  LCount, I: Int32;
begin
  LCount := System.Length(ATs);
  System.SetLength(Result, LCount);
  for I := 0 to LCount - 1 do
  begin
    Result[I] := AFunc(ATs[I]);
  end;
end;

class function TCollectionUtilities.ToArray<T>(const AC: TList<T>): TCryptoLibGenericArray<T>;
var
  LCount, I: Int32;
begin
  LCount := AC.Count;
  System.SetLength(Result, LCount);
  for I := 0 to LCount - 1 do
  begin
    Result[I] := AC[I];
  end;
end;

class function TCollectionUtilities.ToString<T>(const AC: TCryptoLibGenericArray<T>;
  const AConverter: TFunc<T, String>): String;
var
  LCount, I: Int32;
  SB: TStringBuilder;
begin
  LCount := System.Length(AC);
  if LCount = 0 then
  begin
    Result := '[]';
    Exit;
  end;

  SB := TStringBuilder.Create;
  try
    SB.Append('[');
    SB.Append(AConverter(AC[0]));
    for I := 1 to LCount - 1 do
    begin
      SB.Append(', ');
      SB.Append(AConverter(AC[I]));
    end;
    SB.Append(']');
    Result := SB.ToString();
  finally
    SB.Free;
  end;
end;

class function TCollectionUtilities.Proxy<T>(const AEnumerable: IEnumerable<T>): TCryptoLibGenericArray<T>;
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
    Result := LList.ToArray();
  finally
    LList.Free;
  end;
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

end.
