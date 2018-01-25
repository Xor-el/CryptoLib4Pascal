{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                    Copyright (c) 2018 Ugochukwu Mmaduekwe                       * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *        Thanks to Sphere 10 Software (http://sphere10.com) for sponsoring        * }
{ *                        the development of this library                          * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpDerBmpString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpAsn1Object,
  ClpAsn1Tags,
  ClpAsn1OctetString,
  ClpIProxiedInterface,
  ClpIDerBmpString,
  ClpIAsn1TaggedObject,
  ClpDerStringBase;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SEmptyInput = 'Input Cannot be Empty "astr"';

type
  TDerBmpString = class(TDerStringBase, IDerBmpString)

  strict private
  var
    FStr: String;

    function GetStr: String; inline;

  strict protected
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;

  public
    property Str: String read GetStr;

    /// <summary>
    /// basic constructor - byte encoded string.
    /// </summary>
    constructor Create(astr: TCryptoLibByteArray); overload;

    /// <summary>
    /// basic constructor
    /// </summary>
    constructor Create(const astr: String); overload;

    function GetString(): String; override;

    procedure Encode(const derOut: IDerOutputStream); override;

    /// <summary>
    /// return a BMP string from the given object.
    /// </summary>
    /// <param name="obj">
    /// the object we want converted.
    /// </param>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(obj: TObject): IDerBmpString; overload;
      static; inline;

    /// <summary>
    /// return a BMP string from a tagged object.
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
      isExplicit: Boolean): IDerBmpString; overload; static; inline;

  end;

implementation

{ TDerBmpString }

function TDerBmpString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerBmpString;
begin

  if (not Supports(asn1Object, IDerBmpString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

constructor TDerBmpString.Create(astr: TCryptoLibByteArray);
var
  cs: TCryptoLibCharArray;
  i: Int32;
begin
  Inherited Create();
  if (astr = Nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SEmptyInput);
  end;

  System.SetLength(cs, System.Length(astr) div 2);

  i := 0;

  while i <> System.Length(cs) do
  begin
    cs[i] := Char((astr[2 * i] shl 8) or (astr[2 * i + 1] and $FF));
    System.Inc(i);
  end;

  System.SetString(FStr, PChar(@cs[0]), System.Length(cs));
end;

constructor TDerBmpString.Create(const astr: String);
begin
  Inherited Create();
  if (astr = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SEmptyInput);
  end;

  FStr := astr;
end;

procedure TDerBmpString.Encode(const derOut: IDerOutputStream);
var
  c: TCryptoLibCharArray;
  b: TCryptoLibByteArray;
  i: Int32;
begin
  System.SetLength(c, System.Length(Str));
  StrPLCopy(PChar(@c[0]), Str, System.Length(c));
  System.SetLength(b, System.Length(c) * 2);

  i := 0;

  while i <> System.Length(c) do
  begin
    b[2 * i] := Byte(Ord(c[i]) shr 8);
    b[2 * i + 1] := Byte(c[i]);
    System.Inc(i);
  end;

  derOut.WriteEncoded(TAsn1Tags.BmpString, b);
end;

class function TDerBmpString.GetInstance(obj: TObject): IDerBmpString;
begin
  if ((obj = Nil) or (obj is TDerBmpString)) then
  begin
    result := obj as TDerBmpString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerBmpString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerBmpString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerBmpString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerBmpString.Create(TAsn1OctetString.GetInstance(o as TAsn1Object)
    .GetOctets());
end;

function TDerBmpString.GetStr: String;
begin
  result := FStr;
end;

function TDerBmpString.GetString: String;
begin
  result := FStr;
end;

end.
