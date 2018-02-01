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

unit ClpBerOctetString;

{$I ..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  Math,
  Generics.Collections,
  ClpCryptoLibTypes,
  ClpIProxiedInterface,
  ClpIAsn1Sequence,
  ClpAsn1Tags,
  ClpIAsn1OutputStream,
  ClpIBerOutputStream,
  ClpIBerOctetString,
  ClpIDerOctetString,
  ClpDerOctetString;

type
  TBerOctetString = class(TDerOctetString, IBerOctetString)

  strict private
  const
    MaxLength = Int32(1000);

  var
    Focts: TEnumerable<IDerOctetString>;

    function GenerateOcts(): TList<IDerOctetString>;

    class function ToBytes(octs: TEnumerable<IDerOctetString>)
      : TCryptoLibByteArray; static;

  public

    /// <inheritdoc />
    /// <param name="str">The octets making up the octet string.</param>
    constructor Create(str: TCryptoLibByteArray); overload;
    constructor Create(octets: TEnumerable<IDerOctetString>); overload;
    constructor Create(const obj: IAsn1Object); overload;
    constructor Create(const obj: IAsn1Encodable); overload;

    destructor Destroy(); override;

    function GetOctets(): TCryptoLibByteArray; override;

    /// <summary>
    /// return the DER octets that make up this string.
    /// </summary>
    function GetEnumerator: TEnumerator<IDerOctetString>;

    procedure Encode(const derOut: IDerOutputStream); override;

    class function FromSequence(const seq: IAsn1Sequence)
      : IBerOctetString; static;

  end;

implementation

{ TBerOctetString }

constructor TBerOctetString.Create(octets: TEnumerable<IDerOctetString>);
begin
  Inherited Create(ToBytes(octets));
  Focts := octets;
end;

constructor TBerOctetString.Create(str: TCryptoLibByteArray);
begin
  Inherited Create(str);
end;

constructor TBerOctetString.Create(const obj: IAsn1Encodable);
begin
  Inherited Create(obj.ToAsn1Object());
end;

destructor TBerOctetString.Destroy;
begin
  Focts.Free;
  inherited Destroy;
end;

constructor TBerOctetString.Create(const obj: IAsn1Object);
begin
  Inherited Create(obj);
end;

procedure TBerOctetString.Encode(const derOut: IDerOutputStream);
var
  oct: IDerOctetString;
begin
  if ((Supports(derOut, IAsn1OutputStream)) or
    (Supports(derOut, IBerOutputStream))) then
  begin
    derOut.WriteByte(TAsn1Tags.Constructed or TAsn1Tags.OctetString);

    derOut.WriteByte($80);

    //
    // write out the octet array
    //
    for oct in Self do
    begin
      derOut.WriteObject(oct);
    end;

    derOut.WriteByte($00);
    derOut.WriteByte($00);
  end
  else
  begin
    (Inherited Encode(derOut));
  end;
end;

class function TBerOctetString.FromSequence(const seq: IAsn1Sequence)
  : IBerOctetString;
var
  v: TList<IDerOctetString>;
  obj: IAsn1Encodable;
begin
  v := TList<IDerOctetString>.Create();

  for obj in seq do
  begin
    v.Add(obj as IDerOctetString);
  end;

  result := TBerOctetString.Create(v);

end;

function TBerOctetString.GenerateOcts: TList<IDerOctetString>;
var
  i, endPoint: Int32;
  nStr: TCryptoLibByteArray;
  temp: IDerOctetString;
begin
  result := TList<IDerOctetString>.Create();
  i := 0;
  while i < System.Length(str) do
  begin
    endPoint := Min(System.Length(str), i + MaxLength);

    System.SetLength(nStr, endPoint - i);

    System.Move(str[i], nStr[0], System.Length(nStr) * System.SizeOf(Byte));
    result.Add(TDerOctetString.Create(nStr) as IDerOctetString);
    System.Inc(i, MaxLength);
  end;
  Focts := result; // review removal
end;

function TBerOctetString.GetEnumerator: TEnumerator<IDerOctetString>;
begin
  if (Focts = Nil) then
  begin
    result := GenerateOcts().GetEnumerator();
    Exit;
  end;

  result := Focts.GetEnumerator();
end;

function TBerOctetString.GetOctets: TCryptoLibByteArray;
begin
  result := str;
end;

class function TBerOctetString.ToBytes(octs: TEnumerable<IDerOctetString>)
  : TCryptoLibByteArray;
var
  bOut: TMemoryStream;
  o: IDerOctetString;
  octets: TCryptoLibByteArray;
begin
  bOut := TMemoryStream.Create();
  try
    for o in octs do
    begin
      octets := o.GetOctets();
      bOut.Write(octets[0], System.Length(octets));
    end;

    System.SetLength(result, bOut.Size);
    bOut.Position := 0;
    bOut.Read(result[0], bOut.Size);
  finally
    bOut.Free;
  end;
end;

end.
