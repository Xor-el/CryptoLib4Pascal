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

unit ClpDerBoolean;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAsn1Tags,
  ClpIAsn1OctetString,
  ClpIDerBoolean,
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIAsn1TaggedObject,
  ClpAsn1Object;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SInvalidValue = 'Byte Value Should Have 1 Byte in it'', "val"';
  SInvalidBooleanValue = 'BOOLEAN Value Should Have 1 Byte in it", "Value"';

type
  TDerBoolean = class(TAsn1Object, IDerBoolean)

  strict private
  var

    Fvalue: Byte;

    class var

      FFalse, FTrue: IDerBoolean;

    function GetIsTrue: Boolean; inline;

    constructor Create(value: Boolean); overload;

    class function GetFalse: IDerBoolean; static; inline;
    class function GetTrue: IDerBoolean; static; inline;

    class constructor DerBoolean();

  strict protected
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;

  public

    constructor Create(const val: TCryptoLibByteArray); overload;

    procedure Encode(const derOut: IDerOutputStream); override;

    function ToString(): String; override;

    property IsTrue: Boolean read GetIsTrue;

    class property True: IDerBoolean read GetTrue;

    class property False: IDerBoolean read GetFalse;

    /// <summary>
    /// return a DerBoolean from the passed in object.
    /// </summary>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: TObject): IDerBoolean; overload;
      static; inline;

    /// <summary>
    /// return a DerBoolean from the passed in boolean.
    /// </summary>
    class function GetInstance(value: Boolean): IDerBoolean; overload;
      static; inline;

    /// <summary>
    /// return a Boolean from a tagged object.
    /// </summary>
    /// <param name="obj">
    /// the tagged object holding the object we want
    /// </param>
    /// <param name="isExplicit">
    /// explicitly true if the object is meant to be explicitly tagged false
    /// otherwise.
    /// </param>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the tagged object cannot be converted.
    /// </exception>
    class function GetInstance(const obj: IAsn1TaggedObject;
      isExplicit: Boolean): IDerBoolean; overload; static; inline;

    class function FromOctetString(const value: TCryptoLibByteArray)
      : IDerBoolean; static;

  end;

implementation

{ TDerBoolean }

function TDerBoolean.GetIsTrue: Boolean;
begin
  result := Fvalue <> 0;
end;

function TDerBoolean.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerBoolean;
begin

  if (not Supports(asn1Object, IDerBoolean, other)) then
  begin
    result := System.False;
    Exit;
  end;

  result := IsTrue = other.IsTrue;
end;

function TDerBoolean.Asn1GetHashCode: Int32;
begin
  result := Ord(IsTrue);
end;

constructor TDerBoolean.Create(const val: TCryptoLibByteArray);
begin
  Inherited Create();
  if (System.Length(val) <> 1) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidValue);
  end;

  // TODO Are there any constraints on the possible byte values?
  Fvalue := val[0];
end;

constructor TDerBoolean.Create(value: Boolean);
begin
  Inherited Create();
  if value then
  begin
    Fvalue := Byte($FF)
  end
  else
  begin
    Fvalue := Byte(0)
  end;
end;

class constructor TDerBoolean.DerBoolean;
begin
  FFalse := TDerBoolean.Create(System.False);
  FTrue := TDerBoolean.Create(System.True);
end;

procedure TDerBoolean.Encode(const derOut: IDerOutputStream);
begin
  // TODO Should we make sure the byte value is one of '0' or '0xff' here?
  derOut.WriteEncoded(TAsn1Tags.Boolean, TCryptoLibByteArray.Create(Fvalue));
end;

class function TDerBoolean.FromOctetString(const value: TCryptoLibByteArray)
  : IDerBoolean;
var
  b: Byte;
begin
  if (System.Length(value) <> 1) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBooleanValue);
  end;

  b := value[0];

  case b of
    0:
      result := FFalse;
    $FF:
      result := FTrue
  else
    begin
      result := TDerBoolean.Create(value);
    end;
  end;

end;

class function TDerBoolean.GetInstance(value: Boolean): IDerBoolean;
begin
  if value then
  begin
    result := FTrue;
  end
  else
  begin
    result := FFalse;
  end;
end;

class function TDerBoolean.GetInstance(const obj: TObject): IDerBoolean;
begin
  if ((obj = Nil) or (obj is TDerBoolean)) then
  begin
    Supports(obj, IDerBoolean, result);
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerBoolean.GetFalse: IDerBoolean;
begin
  result := FFalse;
end;

class function TDerBoolean.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerBoolean;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerBoolean))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := FromOctetString((o as IAsn1OctetString).GetOctets());
end;

class function TDerBoolean.GetTrue: IDerBoolean;
begin
  result := FTrue;
end;

function TDerBoolean.ToString: String;
begin
  result := BoolToStr(IsTrue, System.True);
end;

end.
