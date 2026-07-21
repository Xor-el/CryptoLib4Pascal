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

unit ClpCryptoLibHashSet;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  Generics.Defaults,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// An unordered collection of distinct items, backed by a dictionary keyed on the item.
  /// </summary>
  /// <remarks>
  /// Membership is decided by the supplied <see cref="IEqualityComparer&lt;T&gt;" />. The default
  /// comparer compares interfaces by reference and records byte-wise, so any type whose equality is
  /// by value MUST be given an explicit comparer.
  /// </remarks>
  TCryptoLibHashSet<T> = class(TObject)

  strict private
  type
    /// <summary>Placeholder dictionary value; it has a size of zero and is never read.</summary>
    TVoid = record
    end;

  var
    FDict: TDictionary<T, TVoid>;

    function GetCount: Int32;

  public
    constructor Create(); overload;
    constructor Create(const AComparer: IEqualityComparer<T>); overload;
    destructor Destroy(); override;

    /// <summary>Adds AItem, returning False when it was already present.</summary>
    function Add(const AItem: T): Boolean;
    procedure AddRange(const AItems: TCryptoLibGenericArray<T>);
    function Contains(const AItem: T): Boolean;
    /// <summary>Removes AItem, returning False when it was not present.</summary>
    function Remove(const AItem: T): Boolean;
    procedure Clear();

    function ToArray(): TCryptoLibGenericArray<T>;
    function GetEnumerator(): TEnumerator<T>;

    property Count: Int32 read GetCount;
  end;

implementation

{ TCryptoLibHashSet<T> }

constructor TCryptoLibHashSet<T>.Create();
begin
  inherited Create();
  FDict := TDictionary<T, TVoid>.Create();
end;

constructor TCryptoLibHashSet<T>.Create(const AComparer: IEqualityComparer<T>);
begin
  inherited Create();
  FDict := TDictionary<T, TVoid>.Create(AComparer);
end;

destructor TCryptoLibHashSet<T>.Destroy();
begin
  FDict.Free;
  inherited Destroy();
end;

function TCryptoLibHashSet<T>.GetCount: Int32;
begin
  Result := FDict.Count;
end;

function TCryptoLibHashSet<T>.Add(const AItem: T): Boolean;
var
  LVoid: TVoid;
begin
  Result := not FDict.ContainsKey(AItem);
  if Result then
  begin
    LVoid := Default(TVoid);
    FDict.Add(AItem, LVoid);
  end;
end;

procedure TCryptoLibHashSet<T>.AddRange(const AItems: TCryptoLibGenericArray<T>);
var
  LIdx: Int32;
begin
  for LIdx := 0 to System.High(AItems) do
  begin
    Add(AItems[LIdx]);
  end;
end;

function TCryptoLibHashSet<T>.Contains(const AItem: T): Boolean;
begin
  Result := FDict.ContainsKey(AItem);
end;

function TCryptoLibHashSet<T>.Remove(const AItem: T): Boolean;
begin
  Result := FDict.ContainsKey(AItem);
  if Result then
  begin
    FDict.Remove(AItem);
  end;
end;

procedure TCryptoLibHashSet<T>.Clear();
begin
  FDict.Clear;
end;

function TCryptoLibHashSet<T>.ToArray(): TCryptoLibGenericArray<T>;
var
  LItem: T;
  LIdx: Int32;
begin
  System.SetLength(Result, FDict.Count);
  LIdx := 0;
  for LItem in FDict.Keys do
  begin
    Result[LIdx] := LItem;
    System.Inc(LIdx);
  end;
end;

function TCryptoLibHashSet<T>.GetEnumerator(): TEnumerator<T>;
begin
  Result := FDict.Keys.GetEnumerator();
end;

end.
