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

unit ClpSignersEncodings;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  ClpAsn1Objects,
  ClpBigInteger,
  ClpAsn1Core,
  ClpISignersEncodings,
  ClpIAsn1Objects,
  ClpArrayUtilities,
  ClpBigIntegers,
  ClpCryptoLibTypes;

resourcestring
  SMalformedSignature = 'Malformed signature, "%s"';
  SValueOutOfRange = 'Value out of range, "%s"';
  SInvalidEncodingLength = 'Encoding has incorrect length, "%s"';

type
  TStandardDsaEncoding = class(TInterfacedObject, IDsaEncoding,
    IStandardDsaEncoding)

  strict private

    class function GetInstance: IStandardDsaEncoding; static; inline;

  strict protected

    function CheckValue(const AN, AX: TBigInteger): TBigInteger; virtual;
    function DecodeValue(const AN: TBigInteger; const &AS: IAsn1Sequence;
      APos: Int32): TBigInteger; virtual;
    function EncodeValue(const AN, AX: TBigInteger): IDerInteger; virtual;

  public

    function Decode(const AN: TBigInteger; const AEncoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    function Encode(const AN, AR, &AS: TBigInteger): TCryptoLibByteArray; virtual;

    function GetMaxEncodingSize(const AN: TBigInteger): Int32; virtual;

    class property Instance: IStandardDsaEncoding read GetInstance;

  end;

type
  TPlainDsaEncoding = class(TInterfacedObject, IDsaEncoding, IPlainDsaEncoding)

  strict private

    class function GetInstance: IPlainDsaEncoding; static; inline;

  strict protected

    function CheckValue(const AN, AX: TBigInteger): TBigInteger; virtual;
    function DecodeValue(const AN: TBigInteger; const ABuf: TCryptoLibByteArray;
      AOff, ALength: Int32): TBigInteger; virtual;
    procedure EncodeValue(const AN, AX: TBigInteger;
      const ABuf: TCryptoLibByteArray; AOff, ALength: Int32); virtual;

  public

    function Decode(const AN: TBigInteger; const AEncoding: TCryptoLibByteArray)
      : TCryptoLibGenericArray<TBigInteger>; virtual;

    function Encode(const AN, AR, &AS: TBigInteger): TCryptoLibByteArray; virtual;

    function GetMaxEncodingSize(const AN: TBigInteger): Int32; virtual;

    class property Instance: IPlainDsaEncoding read GetInstance;

  end;

implementation

{ TStandardDsaEncoding }

function TStandardDsaEncoding.CheckValue(const AN, AX: TBigInteger): TBigInteger;
begin
  if ((AX.SignValue < 0) or ((AN.IsInitialized) and (AX.CompareTo(AN) >= 0))) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SValueOutOfRange, ['x']);
  end;
  Result := AX;
end;

function TStandardDsaEncoding.Decode(const AN: TBigInteger;
  const AEncoding: TCryptoLibByteArray): TCryptoLibGenericArray<TBigInteger>;
var
  LSeq: IAsn1Sequence;
  LR, LS: TBigInteger;
  LExpectedEncoding: TCryptoLibByteArray;
begin
  LSeq := TAsn1Object.FromByteArray(AEncoding) as IAsn1Sequence;
  if (LSeq.Count = 2) then
  begin
    LR := DecodeValue(AN, LSeq, 0);
    LS := DecodeValue(AN, LSeq, 1);
    LExpectedEncoding := Encode(AN, LR, LS);
    if TArrayUtilities.AreEqual<Byte>(LExpectedEncoding, AEncoding) then
    begin
      Result := TCryptoLibGenericArray<TBigInteger>.Create(LR, LS);
      Exit;
    end;
  end;
  raise EArgumentCryptoLibException.CreateResFmt(@SMalformedSignature,
    ['encoding']);
end;

function TStandardDsaEncoding.DecodeValue(const AN: TBigInteger;
  const &AS: IAsn1Sequence; APos: Int32): TBigInteger;
begin
  Result := CheckValue(AN, (&AS[APos] as IDerInteger).Value);
end;

function TStandardDsaEncoding.Encode(const AN, AR, &AS: TBigInteger)
  : TCryptoLibByteArray;
var
  LTemp: IDerSequence;
begin
  LTemp := TDerSequence.Create([EncodeValue(AN, AR), EncodeValue(AN, &AS)])
    as IDerSequence;
  Result := LTemp.GetEncoded(TAsn1Encodable.Der);
end;

function TStandardDsaEncoding.EncodeValue(const AN, AX: TBigInteger): IDerInteger;
begin
  Result := TDerInteger.Create(CheckValue(AN, AX));
end;

function TStandardDsaEncoding.GetMaxEncodingSize(const AN: TBigInteger): Int32;
begin
  Result := TDerSequence.GetEncodingLength(TDerInteger.GetEncodingLength(AN) * 2);
end;

class function TStandardDsaEncoding.GetInstance: IStandardDsaEncoding;
begin
  Result := TStandardDsaEncoding.Create();
end;

{ TPlainDsaEncoding }

function TPlainDsaEncoding.CheckValue(const AN, AX: TBigInteger): TBigInteger;
begin
  if ((AX.SignValue < 0) or ((AX.CompareTo(AN) >= 0))) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SValueOutOfRange, ['x']);
  end;
  Result := AX;
end;

function TPlainDsaEncoding.Decode(const AN: TBigInteger;
  const AEncoding: TCryptoLibByteArray): TCryptoLibGenericArray<TBigInteger>;
var
  LValueLength: Int32;
begin
  LValueLength := TBigIntegers.GetUnsignedByteLength(AN);
  if (System.Length(AEncoding) <> (LValueLength * 2)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidEncodingLength,
      ['encoding']);
  end;
  Result := TCryptoLibGenericArray<TBigInteger>.Create
    (DecodeValue(AN, AEncoding, 0, LValueLength), DecodeValue(AN, AEncoding,
    LValueLength, LValueLength));
end;

function TPlainDsaEncoding.DecodeValue(const AN: TBigInteger;
  const ABuf: TCryptoLibByteArray; AOff, ALength: Int32): TBigInteger;
begin
  Result := CheckValue(AN, TBigInteger.Create(1, ABuf, AOff, ALength));
end;

function TPlainDsaEncoding.Encode(const AN, AR, &AS: TBigInteger)
  : TCryptoLibByteArray;
var
  LValueLength: Int32;
begin
  LValueLength := TBigIntegers.GetUnsignedByteLength(AN);
  System.SetLength(result, LValueLength * 2);
  EncodeValue(AN, AR, result, 0, LValueLength);
  EncodeValue(AN, &AS, result, LValueLength, LValueLength);
end;

procedure TPlainDsaEncoding.EncodeValue(const AN, AX: TBigInteger;
  const ABuf: TCryptoLibByteArray; AOff, ALength: Int32);
var
  LBs: TCryptoLibByteArray;
  LBsOff, LBsLen, LPos: Int32;
begin
  LBs := CheckValue(AN, AX).ToByteArrayUnsigned();
  LBsOff := Max(0, System.Length(LBs) - ALength);
  LBsLen := System.Length(LBs) - LBsOff;
  LPos := ALength - LBsLen;
  TArrayUtilities.Fill<Byte>(ABuf, AOff, AOff + LPos, Byte(0));
  System.Move(LBs[LBsOff], ABuf[AOff + LPos], LBsLen * System.SizeOf(Byte));
end;

function TPlainDsaEncoding.GetMaxEncodingSize(const AN: TBigInteger): Int32;
begin
  Result := TBigIntegers.GetUnsignedByteLength(AN) * 2;
end;

class function TPlainDsaEncoding.GetInstance: IPlainDsaEncoding;
begin
  Result := TPlainDsaEncoding.Create();
end;

end.
