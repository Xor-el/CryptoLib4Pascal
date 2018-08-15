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

unit ClpDerInteger;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpBigInteger,
  ClpAsn1Object,
  ClpIProxiedInterface,
  ClpIAsn1TaggedObject,
  ClpAsn1OctetString,
  ClpAsn1Tags,
  ClpArrayUtils,
  ClpIDerInteger;

resourcestring
  SIllegalObject = 'Illegal Object in GetInstance: %s';
  SObjectNil = ' "obj" Can''t be Nil';
  SValueNil = ' "value" Can''t be Nil';
  SMalformedInteger = 'Malformed Integer';

type
  TDerInteger = class sealed(TAsn1Object, IDerInteger)

  strict private
  var
    Fbytes: TCryptoLibByteArray;

    function GetBytes: TCryptoLibByteArray; inline;
    function GetPositiveValue: TBigInteger; inline;
    function GetValue: TBigInteger; inline;
  strict protected
    function Asn1GetHashCode(): Int32; override;
    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;

  public

    constructor Create(value: Int32); overload;
    constructor Create(const value: TBigInteger); overload;
    constructor Create(const bytes: TCryptoLibByteArray); overload;

    property value: TBigInteger read GetValue;
    property PositiveValue: TBigInteger read GetPositiveValue;
    property bytes: TCryptoLibByteArray read GetBytes;

    procedure Encode(const derOut: IDerOutputStream); override;

    function ToString(): String; override;

    // /**
    // * return an integer from the passed in object
    // *
    // * @exception ArgumentException if the object cannot be converted.
    // */

    class function GetInstance(const obj: TObject): IDerInteger;
      overload; static;

    // /**
    // * return an Integer from a tagged object.
    // *
    // * @param obj the tagged object holding the object we want
    // * @param isExplicit true if the object is meant to be explicitly
    // *              tagged false otherwise.
    // * @exception ArgumentException if the tagged object cannot
    // *               be converted.
    // */
    class function GetInstance(const obj: IAsn1TaggedObject;
      isExplicit: Boolean): IDerInteger; overload; static; inline;

  end;

implementation

{ TDerInteger }

function TDerInteger.GetBytes: TCryptoLibByteArray;
begin
  Result := Fbytes;
end;

class function TDerInteger.GetInstance(const obj: TObject): IDerInteger;
begin
  if ((obj = Nil) or (obj is TDerInteger)) then
  begin
    Result := obj as TDerInteger;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);

end;

function TDerInteger.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerInteger;
begin

  if (not Supports(asn1Object, IDerInteger, other)) then
  begin
    Result := false;
    Exit;
  end;

  Result := TArrayUtils.AreEqual(bytes, other.bytes);
end;

function TDerInteger.Asn1GetHashCode: Int32;
begin
  Result := TArrayUtils.GetArrayHashCode(Fbytes);
end;

constructor TDerInteger.Create(const value: TBigInteger);
begin
  inherited Create();
  if (not value.IsInitialized) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SValueNil);
  end;

  Fbytes := value.ToByteArray();
end;

constructor TDerInteger.Create(value: Int32);
begin
  inherited Create();
  Fbytes := TBigInteger.ValueOf(value).ToByteArray();
end;

constructor TDerInteger.Create(const bytes: TCryptoLibByteArray);
begin
  inherited Create();
  if (System.Length(bytes) > 1) then
  begin
    if ((bytes[0] = 0) and ((bytes[1] and $80) = 0)) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SMalformedInteger);
    end;
    if ((bytes[0] = Byte($FF)) and ((bytes[1] and $80) <> 0)) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SMalformedInteger);
    end;
  end;
  Fbytes := System.Copy(bytes);
end;

procedure TDerInteger.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.Integer, Fbytes);
end;

class function TDerInteger.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerInteger;
var
  o: IAsn1Object;
begin
  if (obj = Nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SObjectNil);

  o := obj.GetObject();

  if ((isExplicit) or (Supports(o, IDerInteger))) then
  begin
    Result := GetInstance(o as TAsn1Object);
    Exit;
  end;

  Result := TDerInteger.Create(TAsn1OctetString.GetInstance(o as TAsn1Object)
    .GetOctets());

end;

function TDerInteger.GetPositiveValue: TBigInteger;
begin
  Result := TBigInteger.Create(1, Fbytes);
end;

function TDerInteger.GetValue: TBigInteger;
begin
  Result := TBigInteger.Create(Fbytes);
end;

function TDerInteger.ToString: String;
begin
  Result := value.ToString();
end;

end.
