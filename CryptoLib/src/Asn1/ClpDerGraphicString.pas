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

unit ClpDerGraphicString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpArrayUtils,
  ClpCryptoLibTypes,
  ClpAsn1Object,
  ClpAsn1Tags,
  ClpAsn1OctetString,
  ClpIProxiedInterface,
  ClpIDerGraphicString,
  ClpIAsn1TaggedObject,
  ClpDerStringBase,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SEncodingError = 'Encoding Error in GetInstance:  %s  "obj"';

type
  TDerGraphicString = class(TDerStringBase, IDerGraphicString)

  strict private
  var
    FmString: TCryptoLibByteArray;

    function GetmString: TCryptoLibByteArray; inline;

  protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;

  public
    property mString: TCryptoLibByteArray read GetmString;

    /// <summary>
    /// basic constructor - with bytes.
    /// </summary>
    /// <param name="encoding">
    /// the byte encoding of the characters making up the string.
    /// </param>
    constructor Create(const encoding: TCryptoLibByteArray);

    function GetString(): String; override;

    function GetOctets(): TCryptoLibByteArray; inline;

    procedure Encode(const derOut: IDerOutputStream); override;

    /// <summary>
    /// return a Graphic String from the passed in object
    /// </summary>
    /// <param name="obj">
    /// a DerGraphicString or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a DerGraphicString instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerGraphicString; overload;
      static; inline;

    class function GetInstance(const obj: TCryptoLibByteArray)
      : IDerGraphicString; overload; static;

    /// <summary>
    /// return a Graphic string from a tagged object.
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
      isExplicit: Boolean): IDerGraphicString; overload; static; inline;

  end;

implementation

{ TDerGraphicString }

function TDerGraphicString.GetmString: TCryptoLibByteArray;
begin
  result := FmString;
end;

function TDerGraphicString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerGraphicString;
begin

  if (not Supports(asn1Object, IDerGraphicString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := TArrayUtils.AreEqual(mString, other.mString);
end;

function TDerGraphicString.Asn1GetHashCode: Int32;
begin
  result := TArrayUtils.GetArrayHashCode(mString);
end;

constructor TDerGraphicString.Create(const encoding: TCryptoLibByteArray);
begin
  Inherited Create();
  FmString := System.Copy(encoding);
end;

procedure TDerGraphicString.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.GraphicString, mString);
end;

class function TDerGraphicString.GetInstance(const obj: TObject)
  : IDerGraphicString;
begin
  if ((obj = Nil) or (obj is TDerGraphicString)) then
  begin
    result := obj as TDerGraphicString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerGraphicString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerGraphicString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerGraphicString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerGraphicString.Create
    (TAsn1OctetString.GetInstance(o as TAsn1Object).GetOctets());
end;

class function TDerGraphicString.GetInstance(const obj: TCryptoLibByteArray)
  : IDerGraphicString;
begin
  try
    result := FromByteArray(obj) as IDerGraphicString;
  except
    on e: Exception do
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SEncodingError,
        [e.Message]);
    end;

  end;
end;

function TDerGraphicString.GetOctets: TCryptoLibByteArray;
begin
  result := System.Copy(mString);
end;

function TDerGraphicString.GetString: String;
begin
  result := TConverters.ConvertBytesToString(mString, TEncoding.ANSI);
end;

end.
