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

unit ClpAsn1Sequence;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpCollectionUtilities,
  ClpDerNull,
{$IFDEF DELPHI}
  ClpIDerNull,
{$ENDIF DELPHI}
  ClpIBerTaggedObject,
  ClpAsn1TaggedObject,
  ClpIAsn1TaggedObject,
  ClpIAsn1Set,
  ClpAsn1Encodable,
  ClpIProxiedInterface,
  ClpIAsn1SequenceParser,
  ClpIAsn1Sequence,
  ClpAsn1Object;

resourcestring
  SInvalidObject = 'Object Implicit - Explicit Expected.';
  SUnknownObject = 'Unknown object in GetInstance:  %s, "obj"';
  SInvalidSequence = '"Failed to Construct Sequence from byte array: " %s';

type
  /// <summary>
  /// return an Asn1Sequence from the given object.
  /// </summary>
  TAsn1Sequence = class abstract(TAsn1Object, IAsn1Sequence)

  strict private
  var
    FSeq: TList<IAsn1Encodable>;

    function GetCount: Int32; virtual;
    function GetParser: IAsn1SequenceParser; virtual;
    function GetSelf(Index: Integer): IAsn1Encodable; virtual;
    function GetCurrent(const e: IAsn1Encodable): IAsn1Encodable;

  type
    TAsn1SequenceParserImpl = class sealed(TInterfacedObject,
      IAsn1SequenceParserImpl, IAsn1SequenceParser)

    strict private
    var
      Fouter: IAsn1Sequence;
      Fmax, Findex: Int32;

    public
      constructor Create(const outer: IAsn1Sequence);
      function ReadObject(): IAsn1Convertible;
      function ToAsn1Object(): IAsn1Object;

    end;

  strict protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
    procedure AddObject(const obj: IAsn1Encodable); inline;

    constructor Create(capacity: Int32);

  public

    destructor Destroy(); override;

    function ToString(): String; override;

    function GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>; virtual;

    // /**
    // * return the object at the sequence position indicated by index.
    // *
    // * @param index the sequence number (starting at zero) of the object
    // * @return the object at the sequence position indicated by index.
    // */
    property Self[Index: Int32]: IAsn1Encodable read GetSelf; default;

    /// <summary>
    /// return an Asn1Sequence from the given object.
    /// </summary>
    /// <param name="obj">
    /// the object we want converted.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IAsn1Sequence;
      overload; static;

    /// <summary>
    /// return an Asn1Sequence from the given object.
    /// </summary>
    /// <param name="obj">
    /// the byte array we want converted.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TCryptoLibByteArray): IAsn1Sequence;
      overload; static;

    // /**
    // * Return an ASN1 sequence from a tagged object. There is a special
    // * case here, if an object appears to have been explicitly tagged on
    // * reading but we were expecting it to be implicitly tagged in the
    // * normal course of events it indicates that we lost the surrounding
    // * sequence - so we need to add it back (this will happen if the tagged
    // * object is a sequence that contains other sequences). If you are
    // * dealing with implicitly tagged sequences you really <b>should</b>
    // * be using this method.
    // *
    // * @param obj the tagged object.
    // * @param explicitly true if the object is meant to be explicitly tagged,
    // *          false otherwise.
    // * @exception ArgumentException if the tagged object cannot
    // *          be converted.
    // */
    class function GetInstance(const obj: IAsn1TaggedObject;
      explicitly: Boolean): IAsn1Sequence; overload; static;

    property Parser: IAsn1SequenceParser read GetParser;
    property Count: Int32 read GetCount;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpBerSequence,
  ClpDerSequence;

{ TAsn1Sequence }

function TAsn1Sequence.GetCurrent(const e: IAsn1Encodable): IAsn1Encodable;
var
  encObj: IAsn1Encodable;
begin
  encObj := e;

  // unfortunately null was allowed as a substitute for DER null
  if (encObj = Nil) then
  begin
    result := TDerNull.Instance;
    Exit;
  end;

  result := encObj;
end;

procedure TAsn1Sequence.AddObject(const obj: IAsn1Encodable);
begin
  FSeq.Add(obj);
end;

function TAsn1Sequence.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IAsn1Sequence;
  l1, l2: TCryptoLibGenericArray<IAsn1Encodable>;
  o1, o2: IAsn1Object;
  Idx: Int32;
begin

  if (not Supports(asn1Object, IAsn1Sequence, other)) then
  begin
    result := false;
    Exit;
  end;

  if (Count <> other.Count) then
  begin
    result := false;
    Exit;
  end;

  l1 := GetEnumerable;
  l2 := other.GetEnumerable;

  for Idx := System.Low(l1) to System.High(l1) do
  begin
    o1 := GetCurrent(l1[Idx]).ToAsn1Object();
    o2 := GetCurrent(l2[Idx]).ToAsn1Object();

    if (not(o1.Equals(o2))) then
    begin
      result := false;
      Exit;
    end;
  end;

  result := true;
end;

function TAsn1Sequence.Asn1GetHashCode: Int32;
var
  hc: Int32;
  o: IAsn1Encodable;
  LListAsn1Encodable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  hc := Count;

  LListAsn1Encodable := Self.GetEnumerable;
  for o in LListAsn1Encodable do
  begin
    hc := hc * 17;
    if (o = Nil) then
    begin
      hc := hc xor TDerNull.Instance.GetHashCode();
    end
    else
    begin
      hc := hc xor o.GetHashCode();
    end;
  end;

  result := hc;
end;

constructor TAsn1Sequence.Create(capacity: Int32);
begin
  inherited Create();
  FSeq := TList<IAsn1Encodable>.Create();
  FSeq.capacity := capacity;
end;

destructor TAsn1Sequence.Destroy;
begin
  FSeq.Free;
  inherited Destroy;
end;

function TAsn1Sequence.GetCount: Int32;
begin
  result := FSeq.Count;
end;

function TAsn1Sequence.GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  result := FSeq.ToArray;
end;

class function TAsn1Sequence.GetInstance(const obj: TObject): IAsn1Sequence;
var
  primitive: IAsn1Object;
  sequence: IAsn1Sequence;
  res: IAsn1SequenceParser;
begin
  if ((obj = Nil) or (obj is TAsn1Sequence)) then
  begin
    result := obj as TAsn1Sequence;
    Exit;
  end;

  if (Supports(obj, IAsn1SequenceParser, res)) then
  begin
    result := TAsn1Sequence.GetInstance(res.ToAsn1Object() as TAsn1Object);
    Exit;

  end;

  if (obj is TAsn1Encodable) then
  begin
    primitive := (obj as TAsn1Encodable).ToAsn1Object();

    if (Supports(primitive, IAsn1Sequence, sequence)) then
    begin
      result := sequence;
      Exit;
    end;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SUnknownObject,
    [obj.ClassName]);

end;

class function TAsn1Sequence.GetInstance(const obj: TCryptoLibByteArray)
  : IAsn1Sequence;
begin
  try
    result := TAsn1Sequence.GetInstance(FromByteArray(obj) as TAsn1Object);
  except
    on e: EIOCryptoLibException do
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidSequence,
        [e.Message]);
    end;
  end;
end;

class function TAsn1Sequence.GetInstance(const obj: IAsn1TaggedObject;
  explicitly: Boolean): IAsn1Sequence;
var
  inner: IAsn1Object;
  sequence: IAsn1Sequence;
begin
  inner := obj.GetObject();

  if (explicitly) then
  begin
    if (not(obj.IsExplicit())) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidObject);

    result := inner as IAsn1Sequence;
    Exit;
  end;

  //
  // constructed object which appears to be explicitly tagged
  // when it should be implicit means we have to add the
  // surrounding sequence.
  //
  if (obj.IsExplicit()) then
  begin
    if (Supports(obj, IBerTaggedObject)) then
    begin
      result := TBerSequence.Create(inner);
      Exit;
    end;

    result := TDerSequence.Create(inner);
    Exit;
  end;

  if (Supports(inner, IAsn1Sequence, sequence)) then
  begin
    result := sequence;
    Exit;
  end;
  raise EArgumentCryptoLibException.CreateResFmt(@SUnknownObject,
    [(obj as TAsn1TaggedObject).ClassName]);

end;

function TAsn1Sequence.GetParser: IAsn1SequenceParser;
begin
  result := TAsn1SequenceParserImpl.Create(Self as IAsn1Sequence);
end;

function TAsn1Sequence.GetSelf(Index: Integer): IAsn1Encodable;
begin
  result := FSeq[index];
end;

function TAsn1Sequence.ToString: String;
begin
  result := TCollectionUtilities.ToStructuredString(FSeq);
end;

{ TAsn1Sequence.TAsn1SequenceParserImpl }

constructor TAsn1Sequence.TAsn1SequenceParserImpl.Create
  (const outer: IAsn1Sequence);
begin
  inherited Create();
  Fouter := outer;
  Fmax := outer.Count;
end;

function TAsn1Sequence.TAsn1SequenceParserImpl.ReadObject: IAsn1Convertible;
var
  obj: IAsn1Encodable;
  sequence: IAsn1Sequence;
  asn1Set: IAsn1Set;
begin
  if (Findex = Fmax) then
  begin
    result := Nil;
    Exit;
  end;

  obj := Fouter[Findex];
  System.Inc(Findex);

  if (Supports(obj, IAsn1Sequence, sequence)) then
  begin
    result := sequence.Parser;
    Exit;
  end;

  if (Supports(obj, IAsn1Set, asn1Set)) then
  begin
    result := asn1Set.Parser;
    Exit;
  end;

  // NB: Asn1OctetString implements Asn1OctetStringParser directly
  // if (obj is Asn1OctetString)
  // return ((Asn1OctetString)obj).Parser;

  result := obj;
end;

function TAsn1Sequence.TAsn1SequenceParserImpl.ToAsn1Object: IAsn1Object;
begin
  result := Fouter;
end;

end.
