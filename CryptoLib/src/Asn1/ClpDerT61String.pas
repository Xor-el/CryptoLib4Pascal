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

unit ClpDerT61String;

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
  ClpIDerT61String,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SStrNil = '"str"';

type

  /// <summary>
  /// Der T61String (also the teletex string) - 8-bit characters
  /// </summary>
  TDerT61String = class(TDerStringBase, IDerT61String)

  strict private
    class var

      FEncoding: TEncoding;

  var
    FStr: String;

    function GetStr: String; inline;
    property Str: String read GetStr;

    class constructor CreateDerT61String();
    class destructor DestroyDerT61String();

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

    function GetOctets(): TCryptoLibByteArray; inline;

    procedure Encode(const derOut: IDerOutputStream); override;

    /// <summary>
    /// return a T61 string from the passed in object.
    /// </summary>
    /// <param name="obj">
    /// a Der T61 string or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a Der T61 string instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerT61String; overload;
      static; inline;

    /// <summary>
    /// return a Der T61 string from a tagged object.
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
      isExplicit: Boolean): IDerT61String; overload; static; inline;

  end;

implementation

{ TDerT61String }

function TDerT61String.GetStr: String;
begin
  result := FStr;
end;

function TDerT61String.GetOctets: TCryptoLibByteArray;
begin
  result := TConverters.ConvertStringToBytes(Str, FEncoding);
end;

function TDerT61String.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerT61String;
begin

  if (not Supports(asn1Object, IDerT61String, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

constructor TDerT61String.Create(const Str: TCryptoLibByteArray);
begin
  Inherited Create();
  Create(TConverters.ConvertBytesToString(Str, FEncoding));
end;

constructor TDerT61String.Create(const Str: String);
begin
  Inherited Create();
  if (Str = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;

  FStr := Str;
end;

class constructor TDerT61String.CreateDerT61String;
begin
  FEncoding := TEncoding.GetEncoding('iso-8859-1');
end;

class destructor TDerT61String.DestroyDerT61String;
begin
  FEncoding.Free;
end;

procedure TDerT61String.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.T61String, GetOctets());
end;

class function TDerT61String.GetInstance(const obj: TObject): IDerT61String;
begin
  if ((obj = Nil) or (obj is TDerT61String)) then
  begin
    result := obj as TDerT61String;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerT61String.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerT61String;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerT61String))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerT61String.Create(TAsn1OctetString.GetInstance(o as TAsn1Object)
    .GetOctets());
end;

function TDerT61String.GetString: String;
begin
  result := Str;
end;

end.
