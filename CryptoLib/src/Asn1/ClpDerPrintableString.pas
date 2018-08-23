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

unit ClpDerPrintableString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  StrUtils,
  ClpDerStringBase,
  ClpAsn1Tags,
  ClpAsn1OctetString,
  ClpAsn1Object,
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIAsn1TaggedObject,
  ClpIDerPrintableString,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SIllegalCharacters = 'String Contains Illegal Characters "str"';
  SStrNil = '"str"';

type

  /// <summary>
  /// Der PrintableString object.
  /// </summary>
  TDerPrintableString = class(TDerStringBase, IDerPrintableString)

  strict private
  var
    FStr: String;

    function GetStr: String; inline;

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
    /// not be in an PrintableString.
    /// </exception>
    constructor Create(const Str: String; validate: Boolean); overload;

    function GetString(): String; override;

    function GetOctets(): TCryptoLibByteArray; inline;

    procedure Encode(const derOut: IDerOutputStream); override;

    property Str: String read GetStr;

    /// <summary>
    /// return a printable string from the passed in object.
    /// </summary>
    /// <param name="obj">
    /// a DerPrintableString or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a DerPrintableString instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerPrintableString;
      overload; static; inline;

    /// <summary>
    /// return a Printable string from a tagged object.
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
      isExplicit: Boolean): IDerPrintableString; overload; static; inline;

    /// <summary>
    /// return true if the passed in String can be represented without loss
    /// as a PrintableString, false otherwise.
    /// </summary>
    /// <param name="Str">
    /// string to validate.
    /// </param>
    /// <returns>
    /// return true if in printable set, false otherwise.
    /// </returns>
    class function IsPrintableString(const Str: String): Boolean;
      static; inline;

  end;

implementation

{ TDerPrintableString }

function TDerPrintableString.GetStr: String;
begin
  result := FStr;
end;

function TDerPrintableString.GetString: String;
begin
  result := Str;
end;

function TDerPrintableString.GetOctets: TCryptoLibByteArray;
begin
  result := TConverters.ConvertStringToBytes(Str, TEncoding.ASCII);
end;

class function TDerPrintableString.IsPrintableString(const Str: String)
  : Boolean;
var
  ch: Char;
begin
  for ch in Str do
  begin

    if ((Ord(ch) > $007F)) then
    begin
      result := false;
      Exit;
    end;

    // if (char.IsLetterOrDigit(ch))
    if CharInSet(ch, ['a' .. 'z', 'A' .. 'Z', '0' .. '9']) then
    begin
      continue;
    end;

    case IndexStr(UnicodeString(ch), [''' ''', '\', '(', ')', '+', '-', '.',
      ':', '=', '?', '/', ',']) of
      0 .. 11:
        begin
          continue;
        end;
    end;

    result := false;
    Exit;
  end;

  result := true;
end;

function TDerPrintableString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerPrintableString;
begin

  if (not Supports(asn1Object, IDerPrintableString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

constructor TDerPrintableString.Create(const Str: TCryptoLibByteArray);
begin
  Create(TConverters.ConvertBytesToString(Str, TEncoding.ASCII), false);
end;

constructor TDerPrintableString.Create(const Str: String);
begin
  Create(Str, false);
end;

constructor TDerPrintableString.Create(const Str: String; validate: Boolean);
begin
  Inherited Create();
  if (Str = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;
  if (validate and (not IsPrintableString(Str))) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SIllegalCharacters);
  end;

  FStr := Str;
end;

procedure TDerPrintableString.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.PrintableString, GetOctets());
end;

class function TDerPrintableString.GetInstance(const obj: TObject)
  : IDerPrintableString;
begin
  if ((obj = Nil) or (obj is TDerPrintableString)) then
  begin
    result := obj as TDerPrintableString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerPrintableString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerPrintableString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerPrintableString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerPrintableString.Create
    (TAsn1OctetString.GetInstance(o as TAsn1Object).GetOctets());
end;

end.
