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

unit ClpDerNumericString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpDerStringBase,
  ClpAsn1Tags,
  ClpAsn1OctetString,
  ClpAsn1Object,
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIAsn1TaggedObject,
  ClpIDerNumericString,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SIllegalCharacters = 'String Contains Illegal Characters "str"';
  SStrNil = '"str"';

type

  /// <summary>
  /// Der NumericString object - this is an ascii string of characters
  /// {0,1,2,3,4,5,6,7,8,9, }.
  /// </summary>
  TDerNumericString = class(TDerStringBase, IDerNumericString)

  strict private
  var
    FStr: String;

    function GetStr: String; inline;
    property Str: String read GetStr;

  strict protected
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
    /// return a Numeric string from the passed in object
    /// </summary>
    /// <param name="obj">
    /// a DerNumericString or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a DerNumericString instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerNumericString; overload;
      static; inline;

    /// <summary>
    /// return a Numeric String from a tagged object.
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
      isExplicit: Boolean): IDerNumericString; overload; static; inline;

    /// <summary>
    /// Return true if the string can be represented as a NumericString
    /// ('0'..'9', ' ')
    /// </summary>
    /// <param name="Str">
    /// string to validate.
    /// </param>
    /// <returns>
    /// true if numeric, false otherwise.
    /// </returns>
    class function IsNumericString(const Str: String): Boolean; static; inline;

  end;

implementation

{ TDerNumericString }

function TDerNumericString.GetStr: String;
begin
  result := FStr;
end;

function TDerNumericString.GetOctets: TCryptoLibByteArray;
begin
  result := TConverters.ConvertStringToBytes(Str, TEncoding.ASCII);
end;

class function TDerNumericString.IsNumericString(const Str: String): Boolean;
var
  ch: Char;
begin
  for ch in Str do
  begin
    // char.IsDigit(ch)
    if ((Ord(ch) > $007F) or ((ch <> ' ') and (not CharInSet(ch, ['0' .. '9']))))
    then
    begin
      result := false;
      Exit;
    end;
  end;

  result := true;
end;

function TDerNumericString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerNumericString;
begin

  if (not Supports(asn1Object, IDerNumericString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

constructor TDerNumericString.Create(const Str: TCryptoLibByteArray);
begin
  Create(TConverters.ConvertBytesToString(Str, TEncoding.ASCII), false);
end;

constructor TDerNumericString.Create(const Str: String);
begin
  Create(Str, false);
end;

constructor TDerNumericString.Create(const Str: String; validate: Boolean);
begin
  Inherited Create();
  if (Str = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;
  if (validate and (not IsNumericString(Str))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SIllegalCharacters);
  end;

  FStr := Str;
end;

procedure TDerNumericString.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.NumericString, GetOctets());
end;

class function TDerNumericString.GetInstance(const obj: TObject)
  : IDerNumericString;
begin
  if ((obj = Nil) or (obj is TDerNumericString)) then
  begin
    result := obj as TDerNumericString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerNumericString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerNumericString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerNumericString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerNumericString.Create
    (TAsn1OctetString.GetInstance(o as TAsn1Object).GetOctets());
end;

function TDerNumericString.GetString: String;
begin
  result := Str;
end;

end.
