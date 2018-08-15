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

unit ClpDerUniversalString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Classes,
  ClpArrayUtils,
  ClpDerStringBase,
  ClpAsn1Tags,
  ClpAsn1OctetString,
  ClpAsn1Object,
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIAsn1TaggedObject,
  ClpIDerUniversalString;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SStrNil = '"str"';

type

  /// <summary>
  /// Der UniversalString object.
  /// </summary>
  TDerUniversalString = class(TDerStringBase, IDerUniversalString)

  strict private
  var
    FStr: TCryptoLibByteArray;

  const
    FTable: array [0 .. 15] of Char = ('0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');

    function GetStr: TCryptoLibByteArray; inline;
    property Str: TCryptoLibByteArray read GetStr;

  strict protected
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
  public

    /// <summary>
    /// basic constructor - byte encoded string.
    /// </summary>
    constructor Create(const Str: TCryptoLibByteArray); overload;

    function GetString(): String; override;

    function GetOctets(): TCryptoLibByteArray; inline;

    procedure Encode(const derOut: IDerOutputStream); override;

    /// <summary>
    /// return a Universal String from the passed in object.
    /// </summary>
    /// <param name="obj">
    /// a Der T61 string or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a Der UniversalString instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerUniversalString;
      overload; static; inline;

    /// <summary>
    /// return a Der UniversalString from a tagged object.
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
      isExplicit: Boolean): IDerUniversalString; overload; static; inline;

  end;

implementation

{ TDerUniversalString }

function TDerUniversalString.GetStr: TCryptoLibByteArray;
begin
  result := FStr;
end;

function TDerUniversalString.GetOctets: TCryptoLibByteArray;
begin
  result := System.Copy(Str);
end;

function TDerUniversalString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerUniversalString;
begin

  if (not Supports(asn1Object, IDerUniversalString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := TArrayUtils.AreEqual(Str, other.Str);
end;

constructor TDerUniversalString.Create(const Str: TCryptoLibByteArray);
begin
  Inherited Create();
  if (Str = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;

  FStr := Str;
end;

procedure TDerUniversalString.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.UniversalString, Str);
end;

class function TDerUniversalString.GetInstance(const obj: TObject)
  : IDerUniversalString;
begin
  if ((obj = Nil) or (obj is TDerUniversalString)) then
  begin
    result := obj as TDerUniversalString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerUniversalString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerUniversalString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerUniversalString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerUniversalString.Create
    (TAsn1OctetString.GetInstance(o as TAsn1Object).GetOctets());
end;

function TDerUniversalString.GetString: String;
var
  buffer: TStringList;
  i: Int32;
  enc: TCryptoLibByteArray;
  ubyte: UInt32;
begin
  buffer := TStringList.Create();
  buffer.LineBreak := '';
  enc := GetDerEncoded();
  buffer.Add('#');
  i := 0;
  try
    while i <> System.Length(enc) do
    begin
      ubyte := enc[i];
      buffer.Add(FTable[(ubyte shr 4) and $F]);
      buffer.Add(FTable[enc[i] and $F]);
      System.Inc(i);
    end;
    result := buffer.Text;
  finally
    buffer.Free;
  end;
end;

end.
