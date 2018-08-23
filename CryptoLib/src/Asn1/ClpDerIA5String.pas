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

unit ClpDerIA5String;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpDerStringBase,
  ClpAsn1Tags,
  ClpAsn1OctetString,
  ClpAsn1Object,
  ClpStringUtils,
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIAsn1TaggedObject,
  ClpIDerIA5String,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SIllegalCharacters = 'String Contains Illegal Characters "str"';
  SStrNil = '"str"';

type

  /// <summary>
  /// Der IA5String object - this is an ascii string.
  /// </summary>
  TDerIA5String = class(TDerStringBase, IDerIA5String)

  strict private
  var
    FStr: String;

    function GetStr: String; inline;
    property Str: String read GetStr;

  strict protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
  public

    /// <summary>
    /// basic constructor - with bytes.
    /// </summary>
    constructor Create(const Str: TCryptoLibByteArray); overload;

    /// <summary>
    /// basic constructor - without validation.
    /// </summary>
    constructor Create(const Str: String); overload;

    /// <summary>
    /// Constructor with optional validation.
    /// </summary>
    /// <param name="Str">
    /// the base string to wrap.
    /// </param>
    /// <param name="validate">
    /// whether or not to check the string.
    /// </param>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if validate is true and the string contains characters that should
    /// not be in an IA5String.
    /// </exception>
    constructor Create(const Str: String; validate: Boolean); overload;

    function GetString(): String; override;

    function GetOctets(): TCryptoLibByteArray; inline;

    procedure Encode(const derOut: IDerOutputStream); override;

    /// <summary>
    /// return a DerIA5String from the passed in object
    /// </summary>
    /// <param name="obj">
    /// a DerIA5String or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a DerIA5String instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerIA5String; overload;
      static; inline;

    /// <summary>
    /// return a DerIA5String from a tagged object.
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
      isExplicit: Boolean): IDerIA5String; overload; static; inline;

    /// <summary>
    /// return true if the passed in String can be represented without loss
    /// as an IA5String, false otherwise.
    /// </summary>
    /// <param name="Str">
    /// true if in printable set, false otherwise.
    /// </param>
    class function IsIA5String(const Str: String): Boolean; static; inline;

  end;

implementation

{ TDerIA5String }

function TDerIA5String.GetStr: String;
begin
  result := FStr;
end;

function TDerIA5String.GetOctets: TCryptoLibByteArray;
begin
  result := TConverters.ConvertStringToBytes(Str, TEncoding.ASCII);
end;

class function TDerIA5String.IsIA5String(const Str: String): Boolean;
var
  ch: Char;
begin
  for ch in Str do
  begin
    if (Ord(ch) > $007F) then
    begin
      result := false;
      Exit;
    end;
  end;

  result := true;
end;

function TDerIA5String.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerIA5String;
begin

  if (not Supports(asn1Object, IDerIA5String, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

function TDerIA5String.Asn1GetHashCode: Int32;
begin
  result := TStringUtils.GetStringHashCode(FStr);
end;

constructor TDerIA5String.Create(const Str: TCryptoLibByteArray);
begin
  Create(TConverters.ConvertBytesToString(Str, TEncoding.ASCII), false);
end;

constructor TDerIA5String.Create(const Str: String);
begin
  Create(Str, false);
end;

constructor TDerIA5String.Create(const Str: String; validate: Boolean);
begin
  Inherited Create();
  if (Str = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;
  if (validate and (not IsIA5String(Str))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SIllegalCharacters);
  end;

  FStr := Str;
end;

procedure TDerIA5String.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.IA5String, GetOctets());
end;

class function TDerIA5String.GetInstance(const obj: TObject): IDerIA5String;
begin
  if ((obj = Nil) or (obj is TDerIA5String)) then
  begin
    result := obj as TDerIA5String;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerIA5String.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerIA5String;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerIA5String))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerIA5String.Create(TAsn1OctetString.GetInstance(o as TAsn1Object)
    .GetOctets());
end;

function TDerIA5String.GetString: String;
begin
  result := Str;
end;

end.
