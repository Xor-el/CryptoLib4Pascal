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

unit ClpDerSequence;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  ClpCryptoLibTypes,
  ClpDerOutputStream,
  ClpIProxiedInterface,
  ClpAsn1Tags,
  ClpIAsn1EncodableVector,
  ClpAsn1Sequence,
  ClpIDerSequence;

type
  TDerSequence = class(TAsn1Sequence, IDerSequence)

  strict private

    class var

      FEmpty: IDerSequence;

    class constructor DerSequence();

    class function GetEmpty: IDerSequence; static; inline;

  public

    class function FromVector(const v: IAsn1EncodableVector)
      : IDerSequence; static;

    /// <summary>
    /// create an empty sequence
    /// </summary>
    constructor Create(); overload;

    /// <summary>
    /// create a sequence containing one object
    /// </summary>
    constructor Create(const obj: IAsn1Encodable); overload;

    constructor Create(const v: array of IAsn1Encodable); overload;

    /// <summary>
    /// create a sequence containing a vector of objects.
    /// </summary>
    constructor Create(const v: IAsn1EncodableVector); overload;

    destructor Destroy(); override;

    /// <summary>
    /// A note on the implementation: <br />As Der requires the constructed,
    /// definite-length model to <br />be used for structured types, this
    /// varies slightly from the <br />ASN.1 descriptions given. Rather than
    /// just outputing Sequence, <br />we also have to specify Constructed,
    /// and the objects length. <br />
    /// </summary>
    procedure Encode(const derOut: IDerOutputStream); override;

    class property Empty: IDerSequence read GetEmpty;

  end;

implementation

{ TDerSequence }

class function TDerSequence.GetEmpty: IDerSequence;
begin
  result := FEmpty;
end;

constructor TDerSequence.Create(const obj: IAsn1Encodable);
begin
  Inherited Create(1);
  AddObject(obj);
end;

constructor TDerSequence.Create;
begin
  Inherited Create(0);
end;

constructor TDerSequence.Create(const v: IAsn1EncodableVector);
var
  ae: IAsn1Encodable;
  LListAsn1Encodable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  Inherited Create(v.Count);
  LListAsn1Encodable := v.GetEnumerable;
  for ae in LListAsn1Encodable do
  begin
    AddObject(ae);
  end;
end;

constructor TDerSequence.Create(const v: array of IAsn1Encodable);
var
  ae: IAsn1Encodable;
begin
  Inherited Create(System.Length(v));
  for ae in v do
  begin
    AddObject(ae);
  end;
end;

class constructor TDerSequence.DerSequence;
begin
  FEmpty := TDerSequence.Create();
end;

destructor TDerSequence.Destroy;
begin

  inherited Destroy;
end;

procedure TDerSequence.Encode(const derOut: IDerOutputStream);
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

  derOut.WriteEncoded(TAsn1Tags.Sequence or TAsn1Tags.Constructed, bytes);
end;

class function TDerSequence.FromVector(const v: IAsn1EncodableVector)
  : IDerSequence;
begin
  if v.Count < 1 then
  begin
    result := Empty;
  end
  else
  begin
    result := TDerSequence.Create(v);
  end;

end;

end.
