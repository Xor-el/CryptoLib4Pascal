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

unit ClpDerVisibleString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpDerStringBase,
  ClpAsn1Tags,
  ClpAsn1Object,
  ClpIAsn1OctetString,
  ClpStringUtils,
  ClpIProxiedInterface,
  ClpCryptoLibTypes,
  ClpIAsn1TaggedObject,
  ClpIDerVisibleString,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SStrNil = '"str"';

type

  /// <summary>
  /// Der VisibleString object.
  /// </summary>
  TDerVisibleString = class(TDerStringBase, IDerVisibleString)

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
    /// basic constructor - byte encoded string.
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
    /// return a DerVisibleString from the passed in object
    /// </summary>
    /// <param name="obj">
    /// a DerVisibleString or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a DerVisibleString instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerVisibleString; overload;
      static; inline;

    /// <summary>
    /// return a DerVisibleString from a tagged object.
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
      isExplicit: Boolean): IDerVisibleString; overload; static; inline;

  end;

implementation

{ TDerVisibleString }

function TDerVisibleString.GetStr: String;
begin
  result := FStr;
end;

function TDerVisibleString.GetOctets: TCryptoLibByteArray;
begin
  result := TConverters.ConvertStringToBytes(Str, TEncoding.ASCII);
end;

function TDerVisibleString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerVisibleString;
begin

  if (not Supports(asn1Object, IDerVisibleString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

function TDerVisibleString.Asn1GetHashCode: Int32;
begin
  result := TStringUtils.GetStringHashCode(FStr);
end;

constructor TDerVisibleString.Create(const Str: TCryptoLibByteArray);
begin
  Create(TConverters.ConvertBytesToString(Str, TEncoding.ASCII));
end;

constructor TDerVisibleString.Create(const Str: String);
begin
  Inherited Create();
  if (Str = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;

  FStr := Str;
end;

procedure TDerVisibleString.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.VisibleString, GetOctets());
end;

class function TDerVisibleString.GetInstance(const obj: TObject)
  : IDerVisibleString;
var
  asn1OctetString: IAsn1OctetString;
  asn1TaggedObject: IAsn1TaggedObject;
begin
  if ((obj = Nil) or (obj is TDerVisibleString)) then
  begin
    result := obj as TDerVisibleString;
    Exit;
  end;

  if Supports(obj, IAsn1OctetString, asn1OctetString) then
  begin
    result := TDerVisibleString.Create(asn1OctetString.GetOctets());
    Exit;
  end;

  if Supports(obj, IAsn1TaggedObject, asn1TaggedObject) then
  begin
    result := GetInstance(asn1TaggedObject.GetObject() as TAsn1Object);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

{$IFNDEF _FIXINSIGHT_}

class function TDerVisibleString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerVisibleString;
begin
  result := GetInstance(obj.GetObject() as TAsn1Object);
end;
{$ENDIF}

function TDerVisibleString.GetString: String;
begin
  result := Str;
end;

end.
