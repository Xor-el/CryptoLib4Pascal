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
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Collection utility class with static methods.
  /// </summary>
  TCollectionUtilities = class sealed(TObject)
  strict private
    constructor Create;
  public
    /// <summary>
    /// Map an array or collection using a function.
    /// </summary>
    class function Map<T, TResult>(const ATs: TCryptoLibGenericArray<T>;
      const AFunc: TFunc<T, TResult>): TCryptoLibGenericArray<TResult>; static;
    /// <summary>
    /// Convert a collection to an array.
    /// </summary>
    class function ToArray<T>(const AC: TCryptoLibGenericArray<T>): TCryptoLibGenericArray<T>; static;
    /// <summary>
    /// Convert a collection to a string representation using a converter function.
    /// </summary>
    class function ToString<T>(const AC: TCryptoLibGenericArray<T>;
      const AConverter: TFunc<T, String>): String; overload; static;
  end;

implementation

{ TCollectionUtilities }

constructor TCollectionUtilities.Create;
begin
  raise ENotSupportedException.Create('TCollectionUtilities is a static class');
end;

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

class function TCollectionUtilities.ToArray<T>(const AC: TCryptoLibGenericArray<T>): TCryptoLibGenericArray<T>;
var
  LCount, I: Int32;
begin
  LCount := System.Length(AC);
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

end.
