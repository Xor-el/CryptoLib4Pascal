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

unit ClpCollectionStore;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIStore,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// In-memory <see cref="IStore&lt;T&gt;" /> backed by a fixed snapshot of its contents.
  /// </summary>
  TCollectionStore<T> = class(TInterfacedObject, IStore<T>)

  strict private
  var
    FContents: TCryptoLibGenericArray<T>;

  public
    constructor Create(const AContents: TCryptoLibGenericArray<T>);
    function EnumerateMatches(const ASelector: ISelector<T>): TCryptoLibGenericArray<T>;
  end;

implementation

{ TCollectionStore<T> }

constructor TCollectionStore<T>.Create(const AContents: TCryptoLibGenericArray<T>);
var
  LIdx: Int32;
begin
  inherited Create();
  System.SetLength(FContents, System.Length(AContents));
  for LIdx := 0 to System.High(AContents) do
  begin
    FContents[LIdx] := AContents[LIdx];
  end;
end;

function TCollectionStore<T>.EnumerateMatches(const ASelector: ISelector<T>): TCryptoLibGenericArray<T>;
var
  LIdx, LCount: Int32;
begin
  System.SetLength(Result, System.Length(FContents));
  LCount := 0;
  for LIdx := 0 to System.High(FContents) do
  begin
    if (ASelector = nil) or ASelector.Match(FContents[LIdx]) then
    begin
      Result[LCount] := FContents[LIdx];
      System.Inc(LCount);
    end;
  end;
  System.SetLength(Result, LCount);
end;

end.
