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

unit ClpDerUtf8String;

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
  ClpIDerUtf8String,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SStrNil = '"str"';

type

  /// <summary>
  /// Der UTF8String object.
  /// </summary>
  TDerUtf8String = class(TDerStringBase, IDerUtf8String)

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
    /// basic constructor
    /// </summary>
    constructor Create(const Str: String); overload;

    function GetString(): String; override;

    procedure Encode(const derOut: IDerOutputStream); override;

    /// <summary>
    /// return an UTF8 string from the passed in object.
    /// </summary>
    /// <param name="obj">
    /// a Der UTF8String or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a Der UTF8String instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerUtf8String; overload;
      static; inline;

    /// <summary>
    /// return a Der UTF8String from a tagged object.
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
      isExplicit: Boolean): IDerUtf8String; overload; static; inline;

  end;

implementation

{ TDerUtf8String }

function TDerUtf8String.GetStr: String;
begin
  result := FStr;
end;

function TDerUtf8String.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerUtf8String;
begin

  if (not Supports(asn1Object, IDerUtf8String, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

constructor TDerUtf8String.Create(const Str: TCryptoLibByteArray);
begin
  Create(TConverters.ConvertBytesToString(Str, TEncoding.UTF8));
end;

constructor TDerUtf8String.Create(const Str: String);
begin
  Inherited Create();
  if (Str = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;

  FStr := Str;
end;

procedure TDerUtf8String.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.Utf8String,
    TConverters.ConvertStringToBytes(Str, TEncoding.UTF8));
end;

class function TDerUtf8String.GetInstance(const obj: TObject): IDerUtf8String;
begin
  if ((obj = Nil) or (obj is TDerUtf8String)) then
  begin
    result := obj as TDerUtf8String;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerUtf8String.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerUtf8String;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerUtf8String))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerUtf8String.Create(TAsn1OctetString.GetInstance(o as TAsn1Object)
    .GetOctets());
end;

function TDerUtf8String.GetString: String;
begin
  result := Str;
end;

end.
