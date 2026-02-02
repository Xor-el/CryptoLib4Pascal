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

unit ClpNullable;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Defaults,
  TypInfo;

type
  /// <summary>
  /// Generic nullable wrapper restricted at runtime to value types (non-class).
  /// Accepted kinds: Integer/Int64, Float, Enumeration, Set, Char/WChar, Record.
  /// Rejected kinds: Class, Interface, String types, Dynamic array, Variant, Method, etc.
  /// </summary>
  TNullable<T> = record
  private
    FHasValue: Boolean;
    FValue: T;

    class constructor Create; // runs once per closed generic (e.g., TNullable<Int64>)
    class procedure AssertSupported; static;

  public
    class function Some(const V: T): TNullable<T>; static;
    class function None: TNullable<T>; static;

    function HasValue: Boolean; inline;
    function Value: T;
    function TryGetValue(out V: T): Boolean; inline;
    function ValueOrDefault(const DefaultValue: T): T; inline;

    procedure Clear; inline;

    class operator Implicit(const V: T): TNullable<T>;
    class operator Explicit(const N: TNullable<T>): T;

    class operator Equal(const A, B: TNullable<T>): Boolean;
    class operator NotEqual(const A, B: TNullable<T>): Boolean;

    class operator Equal(const A: TNullable<T>; const B: T): Boolean;
    class operator NotEqual(const A: TNullable<T>; const B: T): Boolean;
    class operator Equal(const A: T; const B: TNullable<T>): Boolean;
    class operator NotEqual(const A: T; const B: TNullable<T>): Boolean;
  end;

implementation

class procedure TNullable<T>.AssertSupported;
var
  K: TTypeKind;
begin
  K := PTypeInfo(TypeInfo(T)).Kind;

  case K of
    tkInteger, tkInt64, tkEnumeration, tkFloat, tkSet, tkChar, tkWChar, tkRecord:
      Exit; // OK
  else
    raise EInvalidOp.CreateFmt(
      'TNullable<%s> only supports value types (got %s). ' +
      'Disallowed: class/interface/string/dyn array/variant/etc.',
      [GetTypeName(TypeInfo(T)), GetEnumName(TypeInfo(TTypeKind), Ord(K))]
    );
  end;
end;

class constructor TNullable<T>.Create;
begin
  AssertSupported; // fires once per T
end;

class function TNullable<T>.Some(const V: T): TNullable<T>;
begin
  Result.FHasValue := True;
  Result.FValue := V;
end;

class function TNullable<T>.None: TNullable<T>;
begin
  Result.FHasValue := False;
  Result.FValue := Default(T);
end;

function TNullable<T>.HasValue: Boolean;
begin
  Result := FHasValue;
end;

function TNullable<T>.Value: T;
begin
  if not FHasValue then
    raise EInvalidOp.Create('TNullable: value is null');
  Result := FValue;
end;

function TNullable<T>.TryGetValue(out V: T): Boolean;
begin
  Result := FHasValue;
  if Result then
    V := FValue
  else
    V := Default(T);
end;

function TNullable<T>.ValueOrDefault(const DefaultValue: T): T;
begin
  if FHasValue then
    Result := FValue
  else
    Result := DefaultValue;
end;

procedure TNullable<T>.Clear;
begin
  FHasValue := False;
  FValue := Default(T);
end;

class operator TNullable<T>.Implicit(const V: T): TNullable<T>;
begin
  Result := Some(V);
end;

class operator TNullable<T>.Explicit(const N: TNullable<T>): T;
begin
  Result := N.Value; // will raise if FHasValue = false
end;

class operator TNullable<T>.Equal(const A, B: TNullable<T>): Boolean;
var
  Cmp: IEqualityComparer<T>;
begin
  if A.FHasValue <> B.FHasValue then
    Exit(False);
  if not A.FHasValue then
    Exit(True); // both null
  Cmp := TEqualityComparer<T>.Default;
  Result := Cmp.Equals(A.FValue, B.FValue);
end;

class operator TNullable<T>.NotEqual(const A, B: TNullable<T>): Boolean;
begin
  Result := not (A = B);
end;

class operator TNullable<T>.Equal(const A: TNullable<T>; const B: T): Boolean;
begin
  Result := A.FHasValue and TEqualityComparer<T>.Default.Equals(A.FValue, B);
end;

class operator TNullable<T>.NotEqual(const A: TNullable<T>; const B: T): Boolean;
begin
  Result := not (A = B);
end;

class operator TNullable<T>.Equal(const A: T; const B: TNullable<T>): Boolean;
begin
  Result := B = A;
end;

class operator TNullable<T>.NotEqual(const A: T; const B: TNullable<T>): Boolean;
begin
  Result := not (A = B);
end;

end.


