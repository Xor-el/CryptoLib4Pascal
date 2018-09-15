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

unit ClpAsn1Set;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpCollectionUtilities,
  ClpDerNull,
{$IFDEF DELPHI}
  ClpIDerNull,
{$ENDIF DELPHI}
  ClpIAsn1TaggedObject,
  ClpIAsn1EncodableVector,
  ClpAsn1EncodableVector,
  ClpIAsn1Sequence,
  ClpAsn1Encodable,
  ClpIProxiedInterface,
  ClpIAsn1SetParser,
  ClpIAsn1Set,
  ClpAsn1Object;

resourcestring
  SInvalidObject = 'Object Implicit - Explicit Expected.';
  SUnknownObject = 'Unknown object in GetInstance:  %s, "obj"';
  SInvalidSequence = '"Failed to Construct Sequence from byte array: " %s';

type
  /// <summary>
  /// return an Asn1Set from the given object.
  /// </summary>
  TAsn1Set = class abstract(TAsn1Object, IAsn1Set)

  strict private
  var
    F_set: TList<IAsn1Encodable>;
    FisSorted: Boolean;

    function GetCount: Int32; virtual;
    function GetParser: IAsn1SetParser; inline;
    function GetSelf(Index: Integer): IAsn1Encodable; virtual;
    function GetCurrent(const e: IAsn1Encodable): IAsn1Encodable;

    /// <summary>
    /// return true if a &lt;= b (arrays are assumed padded with zeros).
    /// </summary>
    function LessThanOrEqual(const a, b: TCryptoLibByteArray): Boolean; inline;

  type
    TAsn1SetParserImpl = class sealed(TInterfacedObject, IAsn1SetParserImpl,
      IAsn1SetParser)

    strict private
      Fouter: IAsn1Set;
      Fmax, Findex: Int32;

    public
      constructor Create(const outer: IAsn1Set);
      function ReadObject(): IAsn1Convertible;
      function ToAsn1Object(): IAsn1Object;

    end;

  strict protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
    procedure AddObject(const obj: IAsn1Encodable); inline;
    procedure Sort();

    constructor Create(capacity: Int32);

  public
    destructor Destroy(); override;

  public

    function ToString(): String; override;

    function ToArray(): TCryptoLibGenericArray<IAsn1Encodable>; virtual;

    function GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>; virtual;

    // /**
    // * return the object at the sequence position indicated by index.
    // *
    // * @param index the sequence number (starting at zero) of the object
    // * @return the object at the sequence position indicated by index.
    // */
    property Self[Index: Int32]: IAsn1Encodable read GetSelf; default;

    /// <summary>
    /// return an ASN1Set from the given object.
    /// </summary>
    /// <param name="obj">
    /// the object we want converted.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IAsn1Set; overload; static;

    /// <summary>
    /// return an Asn1Set from the given object.
    /// </summary>
    /// <param name="obj">
    /// the byte array we want converted.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TCryptoLibByteArray): IAsn1Set;
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
      explicitly: Boolean): IAsn1Set; overload; static;

    property Parser: IAsn1SetParser read GetParser;
    property Count: Int32 read GetCount;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpDerSet,
  ClpAsn1TaggedObject;

{ TAsn1Set }

procedure TAsn1Set.AddObject(const obj: IAsn1Encodable);
begin
  F_set.Add(obj);
end;

function TAsn1Set.GetCurrent(const e: IAsn1Encodable): IAsn1Encodable;
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

function TAsn1Set.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IAsn1Set;
  l1, l2: TCryptoLibGenericArray<IAsn1Encodable>;
  o1, o2: IAsn1Object;
  Idx: Int32;
begin

  if (not Supports(asn1Object, IAsn1Set, other)) then
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

function TAsn1Set.Asn1GetHashCode: Int32;
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

constructor TAsn1Set.Create(capacity: Int32);
begin
  Inherited Create();
  F_set := TList<IAsn1Encodable>.Create();
  F_set.capacity := capacity;
  FisSorted := false;
end;

destructor TAsn1Set.Destroy;
begin
  F_set.Free;
  inherited Destroy;
end;

function TAsn1Set.GetCount: Int32;
begin
  result := F_set.Count;
end;

function TAsn1Set.GetEnumerable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  result := F_set.ToArray;
end;

class function TAsn1Set.GetInstance(const obj: TCryptoLibByteArray): IAsn1Set;
begin
  try
    result := TAsn1Set.GetInstance(FromByteArray(obj) as TAsn1Object);
  except
    on e: EIOCryptoLibException do
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidSequence,
        [e.Message]);
    end;
  end;
end;

class function TAsn1Set.GetInstance(const obj: IAsn1TaggedObject;
  explicitly: Boolean): IAsn1Set;
var
  inner: IAsn1Object;
  asn1Set: IAsn1Set;
  asn1Sequence: IAsn1Sequence;
  v: IAsn1EncodableVector;
  ae: IAsn1Encodable;
  LListAsn1Encodable: TCryptoLibGenericArray<IAsn1Encodable>;
begin
  inner := obj.GetObject();

  if (explicitly) then
  begin
    if (not(obj.IsExplicit())) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidObject);

    result := inner as IAsn1Set;
    Exit;
  end;

  //
  // constructed object which appears to be explicitly tagged
  // when it should be implicit means we have to add the
  // surrounding sequence.
  //
  if (obj.IsExplicit()) then
  begin

    result := TDerSet.Create(inner);
    Exit;
  end;

  if (Supports(inner, IAsn1Set, asn1Set)) then
  begin
    result := asn1Set;
    Exit;
  end;
  //
  // in this case the parser returns a sequence, convert it
  // into a set.
  //

  if (Supports(inner, IAsn1Sequence, asn1Sequence)) then
  begin
    v := TAsn1EncodableVector.Create();

    LListAsn1Encodable := asn1Sequence.GetEnumerable;
    for ae in LListAsn1Encodable do
    begin
      v.Add(ae);
    end;

    // TODO Should be able to construct set directly from sequence?
    result := TDerSet.Create(v, false);
    Exit;
  end;
  raise EArgumentCryptoLibException.CreateResFmt(@SUnknownObject,
    [(obj as TAsn1TaggedObject).ClassName]);

end;

class function TAsn1Set.GetInstance(const obj: TObject): IAsn1Set;
var
  primitive: IAsn1Object;
  asn1Set: IAsn1Set;
  res: IAsn1SetParser;
begin
  if ((obj = Nil) or (obj is TAsn1Set)) then
  begin
    result := obj as TAsn1Set;
    Exit;
  end;

  if (Supports(obj, IAsn1SetParser, res)) then
  begin
    result := TAsn1Set.GetInstance(res.ToAsn1Object() as TAsn1Object);
    Exit;

  end;

  if (obj is TAsn1Encodable) then
  begin
    primitive := (obj as TAsn1Encodable).ToAsn1Object();

    if (Supports(primitive, IAsn1Set, asn1Set)) then
    begin
      result := asn1Set;
      Exit;
    end;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SUnknownObject,
    [obj.ClassName]);

end;

function TAsn1Set.GetParser: IAsn1SetParser;
begin
  result := TAsn1SetParserImpl.Create(Self as IAsn1Set);
end;

function TAsn1Set.GetSelf(Index: Integer): IAsn1Encodable;
begin
  result := F_set[index];
end;

function TAsn1Set.LessThanOrEqual(const a, b: TCryptoLibByteArray): Boolean;
var
  len, I: Int32;
begin
  len := Math.Min(System.length(a), System.length(b));

  I := 0;
  while I <> len do
  begin

    if (a[I] <> b[I]) then
    begin

      result := (a[I]) < (b[I]);
      Exit;
    end;
    System.Inc(I);
  end;

  result := len = System.length(a);
end;

procedure TAsn1Set.Sort;
var
  swapped: Boolean;
  lastSwap, Index, swapIndex: Int32;
  a, b: TCryptoLibByteArray;
  temp: IAsn1Encodable;

begin
  if (not FisSorted) then
  begin
    FisSorted := true;
    if (F_set.Count > 1) then
    begin
      swapped := true;
      lastSwap := F_set.Count - 1;

      while (swapped) do
      begin
        index := 0;
        swapIndex := 0;
        a := F_set[0].GetEncoded(TAsn1Encodable.Der);

        swapped := false;

        while (index <> lastSwap) do
        begin
          b := F_set[index + 1].GetEncoded(TAsn1Encodable.Der);

          if (LessThanOrEqual(a, b)) then
          begin
            a := b;
          end
          else
          begin
            temp := F_set[index];
            // Review being picky for copy
            // temp := System.Copy(F_set.List, Index, 1)[0];
            F_set[index] := F_set[index + 1];
            F_set[index + 1] := temp;

            swapped := true;
            swapIndex := index;
          end;

          System.Inc(index);
        end;

        lastSwap := swapIndex;
      end;
    end;
  end;
end;

function TAsn1Set.ToArray: TCryptoLibGenericArray<IAsn1Encodable>;
var
  values: TCryptoLibGenericArray<IAsn1Encodable>;
  I: Int32;
begin
  System.SetLength(values, Count);
  for I := 0 to System.Pred(Count) do
  begin
    values[I] := Self[I];
  end;

  result := values;
end;

function TAsn1Set.ToString: String;
begin
  result := TCollectionUtilities.ToStructuredString(F_set);
end;

{ TAsn1Set.TAsn1SetParserImpl }

constructor TAsn1Set.TAsn1SetParserImpl.Create(const outer: IAsn1Set);
begin
  Inherited Create();
  Fouter := outer;
  Fmax := outer.Count;
end;

function TAsn1Set.TAsn1SetParserImpl.ReadObject: IAsn1Convertible;
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

function TAsn1Set.TAsn1SetParserImpl.ToAsn1Object: IAsn1Object;
begin
  result := Fouter;
end;

end.
