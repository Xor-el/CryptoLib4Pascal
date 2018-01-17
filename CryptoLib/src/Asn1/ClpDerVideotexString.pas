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

unit ClpDerVideotexString;

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
  ClpIDerVideotexString,
  ClpIAsn1TaggedObject,
  ClpDerStringBase;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SEncodingError = 'Encoding Error in GetInstance:  %s  "obj"';

type
  TDerVideotexString = class(TDerStringBase, IDerVideotexString)

  strict private
  var
    FmString: TCryptoLibByteArray;

    function GetmString: TCryptoLibByteArray; inline;

  protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(asn1Object: IAsn1Object): Boolean; override;

  public
    property mString: TCryptoLibByteArray read GetmString;

    /// <summary>
    /// basic constructor - with bytes.
    /// </summary>
    /// <param name="encoding">
    /// the byte encoding of the characters making up the string.
    /// </param>
    constructor Create(encoding: TCryptoLibByteArray);

    function GetString(): String; override;

    function GetOctets(): TCryptoLibByteArray; inline;

    procedure Encode(derOut: IDerOutputStream); override;

    /// <summary>
    /// return a Videotex String from the passed in object
    /// </summary>
    /// <param name="obj">
    /// a DerVideotexString or an object that can be converted into one.
    /// </param>
    /// <returns>
    /// return a DerVideotexString instance, or null.
    /// </returns>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(obj: TObject): IDerVideotexString; overload;
      static; inline;

    class function GetInstance(obj: TCryptoLibByteArray): IDerVideotexString;
      overload; static;

    /// <summary>
    /// return a Videotex string from a tagged object.
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
    class function GetInstance(obj: IAsn1TaggedObject; isExplicit: Boolean)
      : IDerVideotexString; overload; static; inline;

  end;

implementation

{ TDerVideotexString }

function TDerVideotexString.Asn1Equals(asn1Object: IAsn1Object): Boolean;
var
  other: IDerVideotexString;
begin

  if (not Supports(asn1Object, IDerVideotexString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := TArrayUtils.AreEqual(mString, other.mString);
end;

function TDerVideotexString.Asn1GetHashCode: Int32;
begin
  result := TArrayUtils.GetArrayHashCode(mString);
end;

constructor TDerVideotexString.Create(encoding: TCryptoLibByteArray);
begin
  Inherited Create();
  FmString := System.Copy(encoding);
end;

procedure TDerVideotexString.Encode(derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.VideotexString, mString);
end;

class function TDerVideotexString.GetInstance(obj: TObject): IDerVideotexString;
begin
  if ((obj = Nil) or (obj is TDerVideotexString)) then
  begin
    result := obj as TDerVideotexString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerVideotexString.GetInstance(obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerVideotexString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerVideotexString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerVideotexString.Create
    (TAsn1OctetString.GetInstance(o as TAsn1Object).GetOctets());
end;

class function TDerVideotexString.GetInstance(obj: TCryptoLibByteArray)
  : IDerVideotexString;
begin
  try
    result := FromByteArray(obj) as IDerVideotexString;
  except
    on e: Exception do
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SEncodingError,
        [e.Message]);
    end;

  end;
end;

function TDerVideotexString.GetmString: TCryptoLibByteArray;
begin
  result := FmString;
end;

function TDerVideotexString.GetOctets: TCryptoLibByteArray;
begin
  result := System.Copy(mString);
end;

function TDerVideotexString.GetString: String;
begin
{$IFDEF FPC}
  result := String(TEncoding.ASCII.GetString(mString)); // encoding.default
{$ELSE}
  result := TEncoding.ASCII.GetString(mString); // encoding.default
{$ENDIF FPC}
end;

end.
