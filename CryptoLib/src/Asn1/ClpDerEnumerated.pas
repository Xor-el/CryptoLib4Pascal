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

unit ClpDerEnumerated;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCryptoLibTypes,
  ClpArrayUtils,
  ClpBigInteger,
  ClpIAsn1OctetString,
  ClpAsn1Tags,
  ClpIProxiedInterface,
  ClpIDerEnumerated,
  ClpIAsn1TaggedObject,
  ClpAsn1Object;

resourcestring
  SMalformedEnumerated = 'Malformed Enumerated';
  SZeroLength = 'Enumerated has Zero Length, "enc"';
  SIllegalObject = 'Illegal Object in GetInstance: %s';

type
  TDerEnumerated = class(TAsn1Object, IDerEnumerated)

  strict private

    class var

      Fcache: TCryptoLibGenericArray<IDerEnumerated>;

    function GetValue: TBigInteger; inline;
    function GetBytes: TCryptoLibByteArray; inline;
    class constructor DerEnumerated();

  var
    Fbytes: TCryptoLibByteArray;

  strict protected

    function Asn1Equals(const asn1Object: IAsn1Object): Boolean; override;
    function Asn1GetHashCode(): Int32; override;

  public

    constructor Create(val: Int32); overload;
    constructor Create(const val: TBigInteger); overload;
    constructor Create(const bytes: TCryptoLibByteArray); overload;

    procedure Encode(const derOut: IDerOutputStream); override;

    property Value: TBigInteger read GetValue;
    property bytes: TCryptoLibByteArray read GetBytes;

    /// <summary>
    /// return an integer from the passed in object
    /// </summary>
    /// <exception cref="ClpCryptoLibTypes|EArgumentCryptoLibException">
    /// if the object cannot be converted.
    /// </exception>

    class function GetInstance(const obj: TObject): IDerEnumerated; overload;
      static; inline;

    /// <summary>
    /// return an Enumerated from a tagged object.
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
      isExplicit: Boolean): IDerEnumerated; overload; static; inline;

    class function FromOctetString(const enc: TCryptoLibByteArray)
      : IDerEnumerated; static;

  end;

implementation

{ TDerEnumerated }

function TDerEnumerated.GetBytes: TCryptoLibByteArray;
begin
  result := Fbytes;
end;

function TDerEnumerated.Asn1Equals(const asn1Object: IAsn1Object): Boolean;
var
  other: IDerEnumerated;
begin

  if (not Supports(asn1Object, IDerEnumerated, other)) then
  begin
    result := false;
    Exit;
  end;

  result := TArrayUtils.AreEqual(bytes, other.bytes);
end;

function TDerEnumerated.Asn1GetHashCode: Int32;
begin
  result := TArrayUtils.GetArrayHashCode(bytes);
end;

constructor TDerEnumerated.Create(val: Int32);
begin
  Inherited Create();
  Fbytes := TBigInteger.ValueOf(val).ToByteArray();
end;

constructor TDerEnumerated.Create(const val: TBigInteger);
begin
  Inherited Create();
  Fbytes := val.ToByteArray();
end;

constructor TDerEnumerated.Create(const bytes: TCryptoLibByteArray);
begin
  Inherited Create();
  if (System.Length(bytes) > 1) then
  begin
    if ((bytes[0] = 0) and ((bytes[1] and $80) = 0)) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SMalformedEnumerated);
    end;
    if ((bytes[0] = Byte($FF)) and ((bytes[1] and $80) <> 0)) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SMalformedEnumerated);
    end;
  end;
  Fbytes := System.Copy(bytes);
end;

class constructor TDerEnumerated.DerEnumerated;
begin
  System.SetLength(Fcache, 12);
end;

procedure TDerEnumerated.Encode(const derOut: IDerOutputStream);
begin
  derOut.WriteEncoded(TAsn1Tags.Enumerated, Fbytes);
end;

class function TDerEnumerated.FromOctetString(const enc: TCryptoLibByteArray)
  : IDerEnumerated;
var
  LValue: Int32;
  cached: IDerEnumerated;
begin
  if (System.Length(enc) = 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SZeroLength);
  end;

  if (System.Length(enc) = 1) then
  begin
    LValue := enc[0];
    if (LValue < System.Length(Fcache)) then
    begin
      cached := Fcache[LValue];
      if (cached <> Nil) then
      begin
        result := cached;
        Exit;
      end;
      Fcache[LValue] := TDerEnumerated.Create(System.Copy(enc));
      result := Fcache[LValue];
      Exit;
    end;
  end;

  result := TDerEnumerated.Create(System.Copy(enc));
end;

class function TDerEnumerated.GetInstance(const obj: TObject): IDerEnumerated;
begin
  if ((obj = Nil) or (obj is TDerEnumerated)) then
  begin
    result := obj as TDerEnumerated;
    Exit;
  end;

  raise EArgumentCryptoLibException.CreateResFmt(@SIllegalObject,
    [obj.ClassName]);
end;

class function TDerEnumerated.GetInstance(const obj: IAsn1TaggedObject;
  isExplicit: Boolean): IDerEnumerated;
var
  o: IAsn1Object;
begin
  o := obj.GetObject();

  if (isExplicit or (Supports(o, IDerEnumerated))) then
  begin
    result := GetInstance(o as TObject);
    Exit;
  end;

  result := FromOctetString((o as IAsn1OctetString).GetOctets());
end;

function TDerEnumerated.GetValue: TBigInteger;
begin
  result := TBigInteger.Create(Fbytes);
end;

end.
