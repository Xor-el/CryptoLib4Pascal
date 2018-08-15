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

unit ClpAsn1EncodableVector;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIAsn1EncodableVector;

type
  TAsn1EncodableVector = class(TInterfacedObject, IAsn1EncodableVector)

  strict private
  var

    Flist: TList<IAsn1Encodable>;

    function GetCount: Int32;
    function GetSelf(Index: Int32): IAsn1Encodable;

  public
    class function FromEnumerable(const e: TList<IAsn1Encodable>)
      : IAsn1EncodableVector; static;

    constructor Create(); overload;
    constructor Create(const v: array of IAsn1Encodable); overload;

    destructor Destroy(); override;

    procedure Add(const objs: array of IAsn1Encodable);

    procedure AddOptional(const objs: array of IAsn1Encodable);

    property Self[Index: Int32]: IAsn1Encodable read GetSelf; default;

    property Count: Int32 read GetCount;

    function GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>; virtual;

  end;

implementation

{ TAsn1EncodableVector }

procedure TAsn1EncodableVector.Add(const objs: array of IAsn1Encodable);
var
  obj: IAsn1Encodable;
begin
  for obj in objs do
  begin
    Flist.Add(obj);
  end;
end;

procedure TAsn1EncodableVector.AddOptional(const objs: array of IAsn1Encodable);
var
  obj: IAsn1Encodable;
begin
  if (System.Length(objs) <> 0) then
  begin
    for obj in objs do
    begin
      if (obj <> Nil) then
      begin
        Flist.Add(obj);
      end;
    end;
  end;
end;

constructor TAsn1EncodableVector.Create(const v: array of IAsn1Encodable);
begin
  inherited Create();
  Flist := TList<IAsn1Encodable>.Create();
  Add(v);
end;

constructor TAsn1EncodableVector.Create();
begin
  inherited Create();
  Flist := TList<IAsn1Encodable>.Create();
end;

destructor TAsn1EncodableVector.Destroy;
begin
  Flist.Free;
  inherited Destroy;
end;

class function TAsn1EncodableVector.FromEnumerable
  (const e: TList<IAsn1Encodable>): IAsn1EncodableVector;
var
  v: IAsn1EncodableVector;
  obj: IAsn1Encodable;
begin
  v := TAsn1EncodableVector.Create();
  for obj in e do
  begin
    v.Add(obj);
  end;
  result := v;
end;

function TAsn1EncodableVector.GetCount: Int32;
begin
  result := Flist.Count;
end;

function TAsn1EncodableVector.GetEnumerable
  : TCryptoLibGenericArray<IAsn1Encodable>;
begin
  result := Flist.ToArray;
end;

function TAsn1EncodableVector.GetSelf(Index: Int32): IAsn1Encodable;
begin
  result := Flist[index];
end;

end.
