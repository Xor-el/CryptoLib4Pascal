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

unit ClpStandardDsaEncoding;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAsn1Sequence,
  ClpIDerInteger,
  ClpBigInteger,
  ClpIDsaEncoding,
  ClpIStandardDsaEncoding,
  ClpAsn1Object,
  ClpDerInteger,
  ClpDerSequence,
  ClpIDerSequence,
  ClpAsn1Encodable,
  ClpArrayUtils,
  ClpCryptoLibTypes;

resourcestring
  SMalformedSignature = 'Malformed signature, "%s"';
  SValueOutOfRange = 'Value out of range, "%s"';

type
  TStandardDsaEncoding = class(TInterfacedObject, IDsaEncoding,
    IStandardDsaEncoding)

  strict private
    class var

      FInstance: IStandardDsaEncoding;

    class function GetInstance: IStandardDsaEncoding; static; inline;

    class constructor StandardDsaEncoding();

  strict protected

    function CheckValue(const n, x: TBigInteger): TBigInteger; virtual;
    function DecodeValue(const n: TBigInteger; const s: IAsn1Sequence;
      pos: Int32): TBigInteger; virtual;
    function EncodeValue(const n, x: TBigInteger): IDerInteger; virtual;

  public

    function Decode(const n: TBigInteger; const encoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    function Encode(const n, r, s: TBigInteger): TCryptoLibByteArray; virtual;

    class property Instance: IStandardDsaEncoding read GetInstance;

  end;

implementation

{ TStandardDsaEncoding }

function TStandardDsaEncoding.CheckValue(const n, x: TBigInteger): TBigInteger;
begin
  if ((x.SignValue < 0) or ((n.IsInitialized) and (x.CompareTo(n) >= 0))) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SValueOutOfRange, ['x']);
  end;
  result := x;
end;

function TStandardDsaEncoding.Decode(const n: TBigInteger;
  const encoding: TCryptoLibByteArray): TCryptoLibGenericArray<TBigInteger>;
var
  seq: IAsn1Sequence;
  r, s: TBigInteger;
  expectedEncoding: TCryptoLibByteArray;
begin
  seq := TAsn1Object.FromByteArray(encoding) as IAsn1Sequence;
  if (seq.Count = 2) then
  begin
    r := DecodeValue(n, seq, 0);
    s := DecodeValue(n, seq, 1);
    expectedEncoding := Encode(n, r, s);
    if (TArrayUtils.AreEqual(expectedEncoding, encoding)) then
    begin
      result := TCryptoLibGenericArray<TBigInteger>.Create(r, s);
      Exit;
    end;
  end;
  raise EArgumentCryptoLibException.CreateResFmt(@SMalformedSignature,
    ['encoding']);
end;

function TStandardDsaEncoding.DecodeValue(const n: TBigInteger;
  const s: IAsn1Sequence; pos: Int32): TBigInteger;
begin
  result := CheckValue(n, (s[pos] as IDerInteger).Value);
end;

function TStandardDsaEncoding.Encode(const n, r, s: TBigInteger)
  : TCryptoLibByteArray;
var
  LTemp: IDerSequence;
begin
  LTemp := TDerSequence.Create([EncodeValue(n, r), EncodeValue(n, s)])
    as IDerSequence;
  result := LTemp.GetEncoded(TAsn1Encodable.Der);
end;

function TStandardDsaEncoding.EncodeValue(const n, x: TBigInteger): IDerInteger;
begin
  result := TDerInteger.Create(CheckValue(n, x));
end;

class function TStandardDsaEncoding.GetInstance: IStandardDsaEncoding;
begin
  result := FInstance;
end;

class constructor TStandardDsaEncoding.StandardDsaEncoding;
begin
  FInstance := TStandardDsaEncoding.Create();
end;

end.
