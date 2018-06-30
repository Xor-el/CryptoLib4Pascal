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

unit ClpAsn1TaggedObject;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpIAsn1Sequence,
  ClpAsn1Tags,
  ClpAsn1Set,
  ClpIAsn1Set,
  ClpIAsn1Choice,
  ClpAsn1Encodable,
  ClpAsn1Object,
  ClpIProxiedInterface,
  ClpIAsn1TaggedObject,
  ClpIAsn1TaggedObjectParser;

resourcestring
  SImplicitObject = 'Implicitly Tagged Object';
  SUnknownObject = 'Unknown object in GetInstance: %s  "obj"';
  SImplicitTag = 'Implicit Tagging for Tag:  %d';

type
  /// **
  // * ASN.1 TaggedObject - in ASN.1 notation this is any object preceded by
  // * a [n] where n is some number - these are assumed to follow the construction
  // * rules (as with sequences).
  // */
  TAsn1TaggedObject = class abstract(TAsn1Object, IAsn1TaggedObject,
    IAsn1TaggedObjectParser)

  strict private
    FtagNo: Int32;
    Fexplicitly: Boolean;
    Fobj: IAsn1Encodable;

    function GetTagNo: Int32; inline;
    function Getexplicitly: Boolean; inline;
    function Getobj: IAsn1Encodable; inline;

  strict protected
    // /**
    // * @param tagNo the tag number for this object.
    // * @param obj the tagged object.
    // */
    constructor Create(tagNo: Int32; const obj: IAsn1Encodable); overload;
    // /**
    // * @param explicitly true if the object is explicitly tagged.
    // * @param tagNo the tag number for this object.
    // * @param obj the tagged object.
    // */
    constructor Create(explicitly: Boolean; tagNo: Int32;
      const obj: IAsn1Encodable); overload;

    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;

    function Asn1GetHashCode(): Int32; override;

  public
    class function IsConstructed(isExplicit: Boolean; const obj: IAsn1Object)
      : Boolean; static;
    class function GetInstance(const obj: IAsn1TaggedObject;
      explicitly: Boolean): IAsn1TaggedObject; overload; static; inline;
    class function GetInstance(obj: TObject): IAsn1TaggedObject; overload;
      static; inline;

    property tagNo: Int32 read GetTagNo;
    property explicitly: Boolean read Getexplicitly;
    property obj: IAsn1Encodable read Getobj;

    // /**
    // * return whether or not the object may be explicitly tagged.
    // * <p>
    // * Note: if the object has been read from an input stream, the only
    // * time you can be sure if isExplicit is returning the true state of
    // * affairs is if it returns false. An implicitly tagged object may appear
    // * to be explicitly tagged, so you need to understand the context under
    // * which the reading was done as well, see GetObject below.</p>
    // */

    function isExplicit(): Boolean; inline;

    function IsEmpty(): Boolean; inline;
    // /**
    // * return whatever was following the tag.
    // * <p>
    // * Note: tagged objects are generally context dependent if you're
    // * trying to extract a tagged object you should be going via the
    // * appropriate GetInstance method.</p>
    // */
    function GetObject(): IAsn1Object; inline;
    // /**
    // * Return the object held in this tagged object as a parser assuming it has
    // * the type of the passed in tag. If the object doesn't have a parser
    // * associated with it, the base object is returned.
    // */
    function GetObjectParser(tag: Int32; isExplicit: Boolean): IAsn1Convertible;

    function ToString(): String; override;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpAsn1Sequence,
  ClpAsn1OctetString;

{ TAsn1TaggedObject }

function TAsn1TaggedObject.GetObject: IAsn1Object;
begin
  if (Fobj <> Nil) then
  begin
    result := Fobj.ToAsn1Object();
    Exit;
  end;

  result := Nil;
end;

function TAsn1TaggedObject.GetTagNo: Int32;
begin
  result := FtagNo;
end;

function TAsn1TaggedObject.Getexplicitly: Boolean;
begin
  result := Fexplicitly;
end;

function TAsn1TaggedObject.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IAsn1TaggedObject;
begin

  if (not Supports(asn1Object, IAsn1TaggedObject, other)) then
  begin
    result := false;
    Exit;
  end;

  result := ((tagNo = other.tagNo) and
    // TODO Should this be part of equality?
    (explicitly = other.explicitly)) and
    (GetObject().Equals(other.GetObject()));
end;

function TAsn1TaggedObject.Asn1GetHashCode: Int32;
var
  code: Int32;
begin
  code := Abs(tagNo);

  // TODO: actually this is wrong - the problem is that a re-encoded
  // object may end up with a different hashCode due to implicit
  // tagging. As implicit tagging is ambiguous if a sequence is involved
  // it seems the only correct method for both equals and hashCode is to
  // compare the encodings...
  // code := code xor explicitly.GetHashCode();

  if (Fobj <> Nil) then
  begin
    code := code xor Fobj.GetHashCode();
  end;

  result := code;
end;

constructor TAsn1TaggedObject.Create(tagNo: Int32; const obj: IAsn1Encodable);
begin
  Inherited Create();
  Fexplicitly := true;
  FtagNo := tagNo;
  Fobj := obj;
end;

constructor TAsn1TaggedObject.Create(explicitly: Boolean; tagNo: Int32;
  const obj: IAsn1Encodable);
begin
  Inherited Create();
  // IAsn1Choice marker interface 'insists' on explicit tagging
  Fexplicitly := explicitly or (Supports(obj, IAsn1Choice));
  FtagNo := tagNo;
  Fobj := obj;
end;

class function TAsn1TaggedObject.GetInstance(obj: TObject): IAsn1TaggedObject;
begin
  if ((obj = Nil) or (obj is TAsn1TaggedObject)) then
  begin
    result := obj as TAsn1TaggedObject;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SUnknownObject,
    [obj.ClassName]);
end;

function TAsn1TaggedObject.Getobj: IAsn1Encodable;
begin
  result := Fobj;
end;

class function TAsn1TaggedObject.GetInstance(const obj: IAsn1TaggedObject;
  explicitly: Boolean): IAsn1TaggedObject;
begin
  if (explicitly) then
  begin
    result := obj.GetObject() as IAsn1TaggedObject;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateRes(@SImplicitObject);
end;

function TAsn1TaggedObject.GetObjectParser(tag: Int32; isExplicit: Boolean)
  : IAsn1Convertible;
begin
  case tag of

    TAsn1Tags.&Set:
      begin
        result := TAsn1Set.GetInstance(Self as IAsn1TaggedObject,
          isExplicit).Parser;
        Exit;
      end;
    TAsn1Tags.Sequence:
      begin
        result := TAsn1Sequence.GetInstance(Self as IAsn1TaggedObject,
          isExplicit).Parser;
        Exit;
      end;
    TAsn1Tags.OctetString:
      begin
        result := TAsn1OctetString.GetInstance(Self as IAsn1TaggedObject,
          isExplicit).Parser;
        Exit;
      end;
  end;

  if (isExplicit) then
  begin
    result := GetObject();
    Exit;
  end;

  raise ENotImplementedCryptoLibException.CreateResFmt(@SImplicitTag, [tag]);

end;

class function TAsn1TaggedObject.IsConstructed(isExplicit: Boolean;
  const obj: IAsn1Object): Boolean;
var
  tagged: IAsn1TaggedObject;
begin
  if ((isExplicit) or (Supports(obj, IAsn1Sequence)) or
    (Supports(obj, IAsn1Set))) then
  begin
    result := true;
    Exit;
  end;

  if (not Supports(obj, IAsn1TaggedObject, tagged)) then
  begin
    result := false;
    Exit;
  end;
  result := IsConstructed(tagged.isExplicit(), tagged.GetObject());
end;

function TAsn1TaggedObject.IsEmpty: Boolean;
begin
  result := false; // empty;
end;

function TAsn1TaggedObject.isExplicit: Boolean;
begin
  result := Fexplicitly;
end;

function TAsn1TaggedObject.ToString: String;
begin
  result := '[' + IntToStr(tagNo) + ']' + (Fobj as TAsn1Encodable).ClassName;
end;

end.
