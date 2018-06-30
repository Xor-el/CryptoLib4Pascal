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

unit ClpBerSet;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpAsn1Tags,
  ClpDerSet,
  ClpIBerSet,
  ClpAsn1OutputStream,
  ClpBerOutputStream,
  ClpIProxiedInterface,
  ClpIAsn1EncodableVector,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// A Ber encoded set object
  /// </summary>
  TBerSet = class sealed(TDerSet, IBerSet)

  strict private
    class var

      FEmpty: IBerSet;
    class constructor BerSet();
    class function GetEmpty: IBerSet; static; inline;

  public

    class function FromVector(const v: IAsn1EncodableVector): IBerSet;
      overload; static;
    class function FromVector(const v: IAsn1EncodableVector;
      needsSorting: Boolean): IBerSet; overload; static;

    /// <summary>
    /// create an empty set
    /// </summary>
    constructor Create(); overload;

    /// <param name="obj">
    /// a single object that makes up the set.
    /// </param>
    constructor Create(const obj: IAsn1Encodable); overload;

    /// <param name="v">
    /// a vector of objects making up the set.
    /// </param>
    constructor Create(const v: IAsn1EncodableVector); overload;

    constructor Create(const v: IAsn1EncodableVector;
      needsSorting: Boolean); overload;

    destructor Destroy(); override;

    /// <summary>
    /// A note on the implementation: <br />As Ber requires the constructed,
    /// definite-length model to <br />be used for structured types, this
    /// varies slightly from the <br />ASN.1 descriptions given. Rather than
    /// just outputing Set, <br />we also have to specify Constructed, and
    /// the objects length. <br />
    /// </summary>
    procedure Encode(const derOut: IDerOutputStream); override;

    class property Empty: IBerSet read GetEmpty;

  end;

implementation

{ TBerSet }

class function TBerSet.GetEmpty: IBerSet;
begin
  result := FEmpty;
end;

constructor TBerSet.Create;
begin
  Inherited Create();
end;

constructor TBerSet.Create(const v: IAsn1EncodableVector;
  needsSorting: Boolean);
begin
  Inherited Create(v, needsSorting);
end;

destructor TBerSet.Destroy;
begin

  inherited Destroy;
end;

constructor TBerSet.Create(const obj: IAsn1Encodable);
begin
  Inherited Create(obj);
end;

constructor TBerSet.Create(const v: IAsn1EncodableVector);
begin
  Inherited Create(v, false);
end;

class constructor TBerSet.BerSet;
begin
  FEmpty := TBerSet.Create();
end;

procedure TBerSet.Encode(const derOut: IDerOutputStream);
var
  o: IAsn1Encodable;
  LListAsn1Encodable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  if ((derOut is TAsn1OutputStream) or (derOut is TBerOutputStream)) then
  begin
    derOut.WriteByte(TAsn1Tags.&Set or TAsn1Tags.Constructed);

    derOut.WriteByte($80);

    LListAsn1Encodable := Self.GetEnumerable;
    for o in LListAsn1Encodable do
    begin
      derOut.WriteObject(o);
    end;

    derOut.WriteByte($00);
    derOut.WriteByte($00);
  end
  else
  begin
    (Inherited Encode(derOut));
  end;
end;

class function TBerSet.FromVector(const v: IAsn1EncodableVector;
  needsSorting: Boolean): IBerSet;
begin
  if v.Count < 1 then
  begin
    result := Empty;
  end
  else
  begin
    result := TBerSet.Create(v, needsSorting);
  end;
end;

class function TBerSet.FromVector(const v: IAsn1EncodableVector): IBerSet;
begin
  if v.Count < 1 then
  begin
    result := Empty;
  end
  else
  begin
    result := TBerSet.Create(v);
  end;
end;

end.
