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

unit ClpDerApplicationSpecific;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpCryptoLibTypes,
  ClpArrayUtils,
  ClpAsn1TaggedObject,
  ClpAsn1Tags,
  ClpIProxiedInterface,
  ClpIDerApplicationSpecific,
  ClpIAsn1EncodableVector,
  ClpAsn1Object;

resourcestring
  SMalformedObject = 'Malformed Object %s';
  SUnSupportedTag = 'Unsupported Tag Number';
  SInvalidDerLength = 'DER Length More Than 4 Bytes: %d';
  SCorruptedStream = 'Corrupted Stream - Invalid High Tag Number Found';

type

  /// <summary>
  /// Base class for an application specific object
  /// </summary>
  TDerApplicationSpecific = class(TAsn1Object, IDerApplicationSpecific)

  strict private
  var
    FisConstructed: Boolean;
    Ftag: Int32;
    Foctets: TCryptoLibByteArray;

    function GetApplicationTag: Int32; inline;
    function GetLengthOfHeader(const data: TCryptoLibByteArray): Int32; inline;

    class function ReplaceTagNumber(newTag: Int32;
      const input: TCryptoLibByteArray): TCryptoLibByteArray; static;

  strict protected
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;

  public
    constructor Create(isConstructed: Boolean; tag: Int32;
      const octets: TCryptoLibByteArray); overload;
    constructor Create(tag: Int32; const octets: TCryptoLibByteArray); overload;
    constructor Create(tag: Int32; const obj: IAsn1Encodable); overload;
    constructor Create(isExplicit: Boolean; tag: Int32;
      const obj: IAsn1Encodable); overload;
    constructor Create(tagNo: Int32; const vec: IAsn1EncodableVector); overload;

    function isConstructed(): Boolean; inline;
    function GetContents(): TCryptoLibByteArray; inline;

    /// <summary>
    /// Return the enclosed object assuming explicit tagging.
    /// </summary>
    /// <returns>
    /// the resulting object
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EIOCryptoLibException">
    /// if reconstruction fails.
    /// </exception>
    function GetObject(): IAsn1Object; overload; inline;

    /// <summary>
    /// Return the enclosed object assuming implicit tagging.
    /// </summary>
    /// <param name="derTagNo">
    /// the type tag that should be applied to the object's contents.
    /// </param>
    /// <returns>
    /// the resulting object
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EIOCryptoLibException">
    /// if reconstruction fails.
    /// </exception>
    function GetObject(derTagNo: Int32): IAsn1Object; overload; inline;

    procedure Encode(const derOut: IDerOutputStream); override;

    property ApplicationTag: Int32 read GetApplicationTag;
  end;

implementation

{ TDerApplicationSpecific }

function TDerApplicationSpecific.GetApplicationTag: Int32;
begin
  result := Ftag;
end;

function TDerApplicationSpecific.GetContents: TCryptoLibByteArray;
begin
  result := Foctets;
end;

function TDerApplicationSpecific.isConstructed: Boolean;
begin
  result := FisConstructed;
end;

function TDerApplicationSpecific.GetLengthOfHeader
  (const data: TCryptoLibByteArray): Int32;
var
  &length, Size: Int32;
begin
  Length := data[1]; // TODO: assumes 1 byte tag

  if (Length = $80) then
  begin
    result := 2; // indefinite-length encoding
    Exit;
  end;

  if (Length > 127) then
  begin
    Size := Length and $7F;

    // Note: The invalid long form "0xff" (see X.690 8.1.3.5c) will be caught here
    if (Size > 4) then
    begin
      raise EInvalidOperationCryptoLibException.CreateResFmt
        (@SInvalidDerLength, [Size]);
    end;

    result := Size + 2;
    Exit;
  end;

  result := 2;
end;

constructor TDerApplicationSpecific.Create(tag: Int32;
  const obj: IAsn1Encodable);
begin
  Create(true, tag, obj);
end;

constructor TDerApplicationSpecific.Create(tag: Int32;
  const octets: TCryptoLibByteArray);
begin
  Create(false, tag, octets);
end;

constructor TDerApplicationSpecific.Create(isConstructed: Boolean; tag: Int32;
  const octets: TCryptoLibByteArray);
begin
  Inherited Create();
  FisConstructed := isConstructed;
  Ftag := tag;
  Foctets := octets;
end;

function TDerApplicationSpecific.Asn1Equals(const asn1Object
  : IAsn1Object): Boolean;
var
  other: IDerApplicationSpecific;
begin

  if (not Supports(asn1Object, IDerApplicationSpecific, other)) then
  begin
    result := false;
    Exit;
  end;

  result := (isConstructed = other.isConstructed) and
    (ApplicationTag = other.ApplicationTag) and
    TArrayUtils.AreEqual(GetContents, other.GetContents);
end;

function TDerApplicationSpecific.Asn1GetHashCode: Int32;
var
  HashCode: Int32;
begin
  case isConstructed of
    true:
      HashCode := 1;
    false:
      HashCode := 0;
  end;
  result := HashCode xor Ftag xor TArrayUtils.GetArrayHashCode(Foctets);
end;

constructor TDerApplicationSpecific.Create(tagNo: Int32;
  const vec: IAsn1EncodableVector);
var
  bOut: TMemoryStream;
  bs: TCryptoLibByteArray;
  i: Int32;
  val: IAsn1Encodable;
begin
  Inherited Create();
  Ftag := tagNo;
  FisConstructed := true;

  bOut := TMemoryStream.Create();
  try
    i := 0;
    while i <> vec.Count do

    begin
      try
        val := vec[i];
        bs := val.GetDerEncoded();
        bOut.Write(bs[0], System.Length(bs));
      except
        on e: EIOCryptoLibException do
        begin
          raise EInvalidOperationCryptoLibException.CreateResFmt
            (@SMalformedObject, [e.Message]);
        end;
      end;
      System.Inc(i);
    end;

    System.SetLength(Foctets, bOut.Size);
    bOut.Position := 0;
    bOut.Read(Foctets[0], bOut.Size);

  finally
    bOut.Free;
  end;

end;

procedure TDerApplicationSpecific.Encode(const derOut: IDerOutputStream);
var
  classBits: Int32;
begin
  classBits := TAsn1Tags.Application;
  if (isConstructed) then
  begin
    classBits := classBits or TAsn1Tags.Constructed;
  end;

  derOut.WriteEncoded(classBits, Ftag, Foctets);
end;

constructor TDerApplicationSpecific.Create(isExplicit: Boolean; tag: Int32;
  const obj: IAsn1Encodable);
var
  asn1Obj: IAsn1Object;
  data, tmp: TCryptoLibByteArray;
  lenBytes: Int32;
begin
  Inherited Create();
  asn1Obj := obj.ToAsn1Object();

  data := asn1Obj.GetDerEncoded();

  FisConstructed := TAsn1TaggedObject.isConstructed(isExplicit, asn1Obj);
  Ftag := tag;

  if (isExplicit) then
  begin
    Foctets := data;
  end
  else
  begin
    lenBytes := GetLengthOfHeader(data);
    System.SetLength(tmp, System.Length(data) - lenBytes);
    System.Move(data[lenBytes], tmp[0], System.Length(tmp) *
      System.SizeOf(Byte));
    Foctets := tmp;
  end;
end;

function TDerApplicationSpecific.GetObject: IAsn1Object;
begin
  result := FromByteArray(GetContents());
end;

function TDerApplicationSpecific.GetObject(derTagNo: Int32): IAsn1Object;
var
  orig, tmp: TCryptoLibByteArray;
begin
  if (derTagNo >= $1F) then
  begin
    raise EIOCryptoLibException.CreateRes(@SUnSupportedTag);
  end;

  orig := GetEncoded();
  tmp := ReplaceTagNumber(derTagNo, orig);

  if ((orig[0] and TAsn1Tags.Constructed) <> 0) then
  begin
    tmp[0] := tmp[0] or TAsn1Tags.Constructed;
  end;

  result := FromByteArray(tmp);
end;

class function TDerApplicationSpecific.ReplaceTagNumber(newTag: Int32;
  const input: TCryptoLibByteArray): TCryptoLibByteArray;
var
  tagNo, index, b, remaining: Int32;
  tmp: TCryptoLibByteArray;
begin
  tagNo := input[0] and $1F;
  index := 1;
  //
  // with tagged object tag number is bottom 5 bits, or stored at the start of the content
  //
  if (tagNo = $1F) then
  begin

    b := input[index];
    System.Inc(index);

    // X.690-0207 8.1.2.4.2
    // "c) bits 7 to 1 of the first subsequent octet shall not all be zero."
    if ((b and $7F) = 0) then // Note: -1 will pass
    begin
      raise EIOCryptoLibException.CreateRes(@SCorruptedStream);
    end;

    while ((b and $80) <> 0) do
    begin
      b := input[index];
      System.Inc(index);
    end;

  end;

  remaining := System.Length(input) - index;
  System.SetLength(tmp, 1 + remaining);
  tmp[0] := Byte(newTag);
  System.Move(input[index], tmp[1], remaining * System.SizeOf(Byte));

  result := tmp;
end;

end.
