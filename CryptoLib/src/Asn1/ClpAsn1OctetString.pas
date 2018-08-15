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

unit ClpAsn1OctetString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes,
  ClpArrayUtils,
  ClpAsn1Object,
  ClpIProxiedInterface,
  ClpIAsn1OctetString,
  ClpIAsn1TaggedObject,
  ClpAsn1Encodable,
  ClpAsn1Sequence,
  ClpHex,
  ClpIDerOctetString,
  ClpIAsn1OctetStringParser;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance:  %s, "obj"';
  SStrNil = '"Str" Cannot be Nil';
  SProcessingError = 'Error Processing Object : "%s"';

type
  TAsn1OctetString = class abstract(TAsn1Object, IAsn1OctetString,
    IAsn1OctetStringParser)

  strict private
  var
    FStr: TCryptoLibByteArray;
    function GetStr: TCryptoLibByteArray; inline;
    function GetParser: IAsn1OctetStringParser; inline;

  strict protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;

  public
    property Str: TCryptoLibByteArray read GetStr;
    property Parser: IAsn1OctetStringParser read GetParser;

    /// <summary>
    /// return an Octet string from a tagged object.
    /// </summary>
    /// <param name="obj">
    /// the tagged object holding the object we want.
    /// </param>
    /// <param name="isExplicit">
    /// explicitly true if the object is meant to be explicitly tagged false
    /// otherwise.
    /// </param>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the tagged object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: IAsn1TaggedObject;
      isExplicit: Boolean): IAsn1OctetString; overload; static;
    /// <summary>
    /// return an Octet string from the given object.
    /// </summary>
    /// <param name="obj">
    /// the object we want converted.
    /// </param>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IAsn1OctetString;
      overload; static;

    /// <param name="Str">
    /// the octets making up the octet string.
    /// </param>
    constructor Create(const Str: TCryptoLibByteArray); overload;

    constructor Create(const obj: IAsn1Encodable); overload;

    function GetOctetStream(): TStream;

    function GetOctets(): TCryptoLibByteArray; virtual;

    function ToString(): String; override;

  end;

implementation

uses
  ClpBerOctetString; // included here to avoid circular dependency :)

{ TAsn1OctetString }

function TAsn1OctetString.GetStr: TCryptoLibByteArray;
begin
  result := FStr;
end;

function TAsn1OctetString.GetParser: IAsn1OctetStringParser;
begin
  result := Self as IAsn1OctetStringParser;
end;

constructor TAsn1OctetString.Create(const Str: TCryptoLibByteArray);
begin
  Inherited Create();
  if (Str = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;

  FStr := Str;
end;

function TAsn1OctetString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerOctetString;
begin

  if (not Supports(asn1Object, IDerOctetString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := TArrayUtils.AreEqual(GetOctets(), other.GetOctets());
end;

function TAsn1OctetString.Asn1GetHashCode: Int32;
begin
  result := TArrayUtils.GetArrayHashCode(GetOctets());
end;

constructor TAsn1OctetString.Create(const obj: IAsn1Encodable);
begin
  Inherited Create();
  try
    FStr := obj.GetEncoded(TAsn1Encodable.Der);
  except
    on e: EIOCryptoLibException do
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SProcessingError,
        [e.Message]);
    end;
  end;
end;

class function TAsn1OctetString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IAsn1OctetString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IAsn1OctetString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TBerOctetString.FromSequence
    (TAsn1Sequence.GetInstance(o as TAsn1Object));
end;

class function TAsn1OctetString.GetInstance(const obj: TObject)
  : IAsn1OctetString;
var
  asn1TaggedObject: IAsn1TaggedObject;
begin
  if ((obj = Nil) or (obj is TAsn1OctetString)) then
  begin
    result := obj as TAsn1OctetString;
    Exit;
  end;

  // TODO: this needs to be deleted in V2
  if Supports(obj, IAsn1TaggedObject, asn1TaggedObject) then
  begin
    result := GetInstance(asn1TaggedObject.GetObject() as TAsn1Object);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

function TAsn1OctetString.GetOctets: TCryptoLibByteArray;
begin
  result := Str;
end;

function TAsn1OctetString.GetOctetStream: TStream;
begin
  // used TBytesStream here for one pass creation and population with byte array :)
  result := TBytesStream.Create(Str);
end;

function TAsn1OctetString.ToString: String;
begin
  result := '#' + THex.Encode(Str);
end;

end.
