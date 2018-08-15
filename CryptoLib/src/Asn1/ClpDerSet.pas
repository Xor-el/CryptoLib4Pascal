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

unit ClpDerSet;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpDerOutputStream,
  ClpAsn1Tags,
  ClpAsn1Set,
  ClpIDerSet,
  ClpIProxiedInterface,
  ClpIAsn1EncodableVector;

type

  /// <summary>
  /// A Der encoded set object
  /// </summary>
  TDerSet = class(TAsn1Set, IDerSet)

  strict private
    class var

      FEmpty: IDerSet;
    class constructor DerSet();
    class function GetEmpty: IDerSet; static; inline;

  public

    class function FromVector(const v: IAsn1EncodableVector): IDerSet;
      overload; static;
    class function FromVector(const v: IAsn1EncodableVector;
      needsSorting: Boolean): IDerSet; overload; static;

    /// <summary>
    /// create an empty set
    /// </summary>
    constructor Create(); overload;

    /// <param name="obj">
    /// a single object that makes up the set.
    /// </param>
    constructor Create(const obj: IAsn1Encodable); overload;

    constructor Create(const v: array of IAsn1Encodable); overload;

    /// <param name="v">
    /// a vector of objects making up the set.
    /// </param>
    constructor Create(const v: IAsn1EncodableVector); overload;

    constructor Create(const v: IAsn1EncodableVector;
      needsSorting: Boolean); overload;

    destructor Destroy(); override;

    /// <summary>
    /// A note on the implementation: <br />As Der requires the constructed,
    /// definite-length model to <br />be used for structured types, this
    /// varies slightly from the <br />ASN.1 descriptions given. Rather than
    /// just outputing Set, <br />we also have to specify Constructed, and
    /// the objects length. <br />
    /// </summary>
    procedure Encode(const derOut: IDerOutputStream); override;

    class property Empty: IDerSet read GetEmpty;

  end;

implementation

{ TDerSet }

class function TDerSet.GetEmpty: IDerSet;
begin
  result := FEmpty;
end;

constructor TDerSet.Create(const v: array of IAsn1Encodable);
var
  o: IAsn1Encodable;
begin
  Inherited Create(System.Length(v));
  for o in v do
  begin
    AddObject(o);
  end;

  Sort();
end;

constructor TDerSet.Create;
begin
  Inherited Create(0);
end;

constructor TDerSet.Create(const v: IAsn1EncodableVector;
  needsSorting: Boolean);
var
  o: IAsn1Encodable;
  LListAsn1Encodable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Inherited Create(v.Count);
  LListAsn1Encodable := v.GetEnumerable;
  for o in LListAsn1Encodable do
  begin
    AddObject(o);
  end;

  if (needsSorting) then
  begin
    Sort();
  end;
end;

constructor TDerSet.Create(const obj: IAsn1Encodable);
begin
  Inherited Create(1);
  AddObject(obj);
end;

constructor TDerSet.Create(const v: IAsn1EncodableVector);
begin
  Create(v, true);
end;

class constructor TDerSet.DerSet;
begin
  FEmpty := TDerSet.Create();
end;

destructor TDerSet.Destroy;
begin

  inherited Destroy;
end;

procedure TDerSet.Encode(const derOut: IDerOutputStream);
var
  bOut: TMemoryStream;
  dOut: TDerOutputStream;
  obj: IAsn1Encodable;
  bytes: TCryptoLibByteArray;
  LListAsn1Encodable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  // TODO Intermediate buffer could be avoided if we could calculate expected length
  bOut := TMemoryStream.Create();
  dOut := TDerOutputStream.Create(bOut);

  try
    LListAsn1Encodable := Self.GetEnumerable;
    for obj in LListAsn1Encodable do
    begin
      dOut.WriteObject(obj);
    end;

    System.SetLength(bytes, bOut.Size);
    bOut.Position := 0;
    bOut.Read(bytes[0], bOut.Size);
  finally
    bOut.Free;
    dOut.Free;
  end;

  derOut.WriteEncoded(TAsn1Tags.&Set or TAsn1Tags.Constructed, bytes);
end;

class function TDerSet.FromVector(const v: IAsn1EncodableVector;
  needsSorting: Boolean): IDerSet;
begin
  if v.Count < 1 then
  begin
    result := Empty;
  end
  else
  begin
    result := TDerSet.Create(v, needsSorting);
  end;
end;

class function TDerSet.FromVector(const v: IAsn1EncodableVector): IDerSet;
begin
  if v.Count < 1 then
  begin
    result := Empty;
  end
  else
  begin
    result := TDerSet.Create(v);
  end;
end;

end.
