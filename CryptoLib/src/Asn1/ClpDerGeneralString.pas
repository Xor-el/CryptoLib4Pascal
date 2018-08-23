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

unit ClpDerGeneralString;

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
  ClpIDerGeneralString,
  ClpConverters;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SStrNil = '"str"';

type

  TDerGeneralString = class(TDerStringBase, IDerGeneralString)

  strict private
  var
    FStr: String;

    function GetStr: String; inline;

    property Str: String read GetStr;

  strict protected
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
  public

    constructor Create(const Str: TCryptoLibByteArray); overload;

    constructor Create(const Str: String); overload;

    function GetString(): String; override;

    function GetOctets(): TCryptoLibByteArray; inline;

    procedure Encode(const derOut: IDerOutputStream); override;

    class function GetInstance(const obj: TObject): IDerGeneralString; overload;
      static; inline;

    class function GetInstance(const obj: IAsn1TaggedObject;
      isExplicit: Boolean): IDerGeneralString; overload; static; inline;

  end;

implementation

{ TDerGeneralString }

function TDerGeneralString.GetStr: String;
begin
  result := FStr;
end;

function TDerGeneralString.GetOctets: TCryptoLibByteArray;
begin
  result := TConverters.ConvertStringToBytes(Str, TEncoding.ASCII);
end;

function TDerGeneralString.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerGeneralString;
begin

  if (not Supports(asn1Object, IDerGeneralString, other)) then
  begin
    result := false;
    Exit;
  end;

  result := Str = other.Str;
end;

constructor TDerGeneralString.Create(const Str: TCryptoLibByteArray);
begin
  Create(TConverters.ConvertBytesToString(Str, TEncoding.ASCII));
end;

constructor TDerGeneralString.Create(const Str: String);
begin
  Inherited Create();
  if (Str = '') then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SStrNil);
  end;

  FStr := Str;
end;

procedure TDerGeneralString.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.GeneralString, GetOctets());
end;

class function TDerGeneralString.GetInstance(const obj: TObject)
  : IDerGeneralString;
begin
  if ((obj = Nil) or (obj is TDerGeneralString)) then
  begin
    result := obj as TDerGeneralString;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerGeneralString.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerGeneralString;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerGeneralString))) then
  begin
    result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  result := TDerGeneralString.Create
    (TAsn1OctetString.GetInstance(o as TAsn1Object).GetOctets());
end;

function TDerGeneralString.GetString: String;
begin
  result := Str;
end;

end.
