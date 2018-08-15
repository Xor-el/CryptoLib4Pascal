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

unit ClpDerBitString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  Math,
  ClpBits,
  ClpArrayUtils,
  ClpDerStringBase,
  ClpAsn1Tags,
  ClpBigInteger,
  ClpAsn1Object,
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIAsn1TaggedObject,
  ClpIAsn1OctetString,
  ClpIDerBitString;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SEncodingError = 'Encoding Error in GetInstance:  %s  "obj"';
  SDataNil = '"data"';
  SInvalidRange = 'Must be in the Range 0 to 7", "padBits"';
  SPadBitError = 'If ''data'' is Empty, ''padBits'' Must be 0';
  SUnalignedData = 'Attempt to Get non-octet Aligned Data from BIT STRING"';
  STruncatedBitString = 'Truncated BIT STRING Detected", "octets"';

type

  /// <summary>
  /// Der Bit string object.
  /// </summary>
  TDerBitString = class(TDerStringBase, IDerBitString)

  strict private
  const
    FTable: array [0 .. 15] of Char = ('0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');

  strict protected
  var
    FmData: TCryptoLibByteArray;
    FmPadBits: Int32;

    function GetmPadBits: Int32; inline;
    function GetmData: TCryptoLibByteArray; inline;

    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;

    property mPadBits: Int32 read GetmPadBits;
    property mData: TCryptoLibByteArray read GetmData;
  public

    constructor Create(const data: TCryptoLibByteArray;
      padBits: Int32); overload;

    constructor Create(const data: TCryptoLibByteArray); overload;

    constructor Create(namedBits: Int32); overload;

    constructor Create(const obj: IAsn1Encodable); overload;

    function GetString(): String; override;

    function GetOctets(): TCryptoLibByteArray; virtual;

    function GetBytes(): TCryptoLibByteArray; virtual;

    procedure Encode(const derOut: IDerOutputStream); override;

    function GetInt32Value: Int32; virtual;
    property Int32Value: Int32 read GetInt32Value;

    /// <summary>
    /// return a Der Bit string from the passed in object
    /// </summary>
    /// <param name="obj">
    /// a Bit string or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a Der Bit string instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerBitString; overload;
      static; inline;

    class function GetInstance(const obj: TCryptoLibByteArray): IDerBitString;
      overload; static;

    /// <summary>
    /// return a Der Bit string from a tagged object.
    /// </summary>
    /// <param name="obj">
    /// the tagged object holding the object we want
    /// </param>
    /// <param name="isExplicit">
    /// true if the object is meant to be explicitly tagged false otherwise.
    /// </param>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the tagged object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: IAsn1TaggedObject;
      isExplicit: Boolean): IDerBitString; overload; static; inline;

    class function FromAsn1Octets(const octets: TCryptoLibByteArray)
      : IDerBitString; static;

  end;

implementation

uses
  // included here to avoid circular dependency :)
  ClpBerBitString;

{ TDerBitString }

class function TDerBitString.GetInstance(const obj: TCryptoLibByteArray)
  : IDerBitString;
begin
  try
    result := FromByteArray(obj) as IDerBitString;
  except
    on e: Exception do
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SEncodingError,
        [e.Message]);
    end;

  end;
end;

function TDerBitString.GetmData: TCryptoLibByteArray;
begin
  result := FmData;
end;

function TDerBitString.GetmPadBits: Int32;
begin
  result := FmPadBits;
end;

function TDerBitString.GetOctets: TCryptoLibByteArray;
begin
  if (mPadBits <> 0) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SUnalignedData);
  end;
  result := System.Copy(mData);
end;

function TDerBitString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerBitString;
begin

  if (not Supports(asn1Object, IDerBitString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := (mPadBits = other.mPadBits) and
    (TArrayUtils.AreEqual(mData, other.mData));
end;

constructor TDerBitString.Create(const data: TCryptoLibByteArray;
  padBits: Int32);
begin
  Inherited Create();
  if (data = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SDataNil);
  end;

  if ((padBits < 0) or (padBits > 7)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRange);
  end;

  if ((System.Length(data) = 0) and (padBits <> 0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SPadBitError);
  end;

  FmData := System.Copy(data);
  FmPadBits := padBits;

end;

constructor TDerBitString.Create(const data: TCryptoLibByteArray);
begin
  Create(data, 0);
end;

constructor TDerBitString.Create(namedBits: Int32);
var
  bits, bytes, i, padBits: Int32;
  data: TCryptoLibByteArray;
begin
  Inherited Create();
  if (namedBits = 0) then
  begin
    System.SetLength(FmData, 0);
    FmPadBits := 0;
    Exit;
  end;
  bits := TBigInteger.BitLen(namedBits);
  bytes := (bits + 7) div 8;

{$IFDEF DEBUG}
  System.Assert((0 < bytes) and (bytes <= 4));
{$ENDIF DEBUG}
  System.SetLength(data, bytes);

  System.Dec(bytes);

  for i := 0 to System.Pred(bytes) do
  begin
    data[i] := Byte(namedBits);
    namedBits := TBits.Asr32(namedBits, 8);
  end;

{$IFDEF DEBUG}
  System.Assert((namedBits and $FF) <> 0);
{$ENDIF DEBUG}
  data[bytes] := Byte(namedBits);

  padBits := 0;
  while ((namedBits and (1 shl padBits)) = 0) do
  begin
    System.Inc(padBits);
  end;

{$IFDEF DEBUG}
  System.Assert(padBits < 8);
{$ENDIF DEBUG}
  FmData := data;
  FmPadBits := padBits;
end;

procedure TDerBitString.Encode(const derOut: IDerOutputStream);
var
  last, mask, unusedBits: Int32;
  contents: TCryptoLibByteArray;
begin
  if (mPadBits > 0) then
  begin
    last := mData[System.Length(mData) - 1];
    mask := (1 shl mPadBits) - 1;
    unusedBits := last and mask;

    if (unusedBits <> 0) then
    begin
      contents := TArrayUtils.Prepend(mData, Byte(mPadBits));

      // /*
      // * X.690-0207 11.2.1: Each unused bit in the final octet of the encoding of a bit string value shall be set to zero.
      // */
      contents[System.Length(contents) - 1] := Byte(last xor unusedBits);

      derOut.WriteEncoded(TAsn1Tags.BitString, contents);
      Exit;
    end;
  end;

  derOut.WriteEncoded(TAsn1Tags.BitString, Byte(mPadBits), mData);
end;

class function TDerBitString.FromAsn1Octets(const octets: TCryptoLibByteArray)
  : IDerBitString;
var
  padBits, last, mask: Int32;
  data: TCryptoLibByteArray;
begin
  if (System.Length(octets) < 1) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@STruncatedBitString);
  end;

  padBits := octets[0];
  data := TArrayUtils.CopyOfRange(octets, 1, System.Length(octets));

  if ((padBits > 0) and (padBits < 8) and (System.Length(data) > 0)) then
  begin
    last := data[System.Length(data) - 1];
    mask := (1 shl padBits) - 1;

    if ((last and mask) <> 0) then
    begin
      result := TBerBitString.Create(data, padBits);
      Exit;
    end;
  end;

  result := TDerBitString.Create(data, padBits);
end;

function TDerBitString.GetBytes: TCryptoLibByteArray;
begin
  result := System.Copy(mData);

  // DER requires pad bits be zero
  if (mPadBits > 0) then
  begin
    result[System.Length(result) - 1] := result[System.Length(result) - 1] and
      Byte($FF shl mPadBits);
  end;

end;

class function TDerBitString.GetInstance(const obj: TObject): IDerBitString;
begin
  if ((obj = Nil) or (obj is TDerBitString)) then
  begin
    result := obj as TDerBitString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerBitString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerBitString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerBitString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := FromAsn1Octets((o as IAsn1OctetString).GetOctets());
end;

function TDerBitString.GetInt32Value: Int32;
var
  value, &length, i, mask: Int32;
begin
  value := 0;
  Length := Min(4, System.Length(mData));
  for i := 0 to System.Pred(Length) do
  begin
    value := value or (Int32(mData[i]) shl (8 * i));
  end;

  if ((mPadBits > 0) and (Length = System.Length(mData))) then
  begin
    mask := (1 shl mPadBits) - 1;
    value := value and (not(mask shl (8 * (Length - 1))));
  end;
  result := value;
end;

function TDerBitString.GetString: String;
var
  buffer: TStringList;
  i: Int32;
  str: TCryptoLibByteArray;
  ubyte: UInt32;
begin
  buffer := TStringList.Create();
  buffer.LineBreak := '';
  str := GetDerEncoded();
  buffer.Add('#');
  i := 0;
  try
    while i <> System.Length(str) do
    begin
      ubyte := str[i];
      buffer.Add(FTable[(ubyte shr 4) and $F]);
      buffer.Add(FTable[str[i] and $F]);
      System.Inc(i);
    end;
    result := buffer.Text;
  finally
    buffer.Free;
  end;
end;

function TDerBitString.Asn1GetHashCode: Int32;
begin
  result := mPadBits xor TArrayUtils.GetArrayHashCode(mData);
end;

constructor TDerBitString.Create(const obj: IAsn1Encodable);
begin
  Create(obj.GetDerEncoded());
end;

end.
