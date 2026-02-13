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

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpAsn1Objects,
  ClpBigInteger,
  ClpAsn1Core,
  ClpIDsaEncoding,
  ClpIStandardDsaEncoding,
  ClpIAsn1Objects,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SMalformedSignature = 'Malformed signature, "%s"';
  SValueOutOfRange = 'Value out of range, "%s"';

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

implementation

function TStandardDsaEncoding.CheckValue(const AN, AX: TBigInteger): TBigInteger;
begin
  if ((AX.SignValue < 0) or ((AN.IsInitialized) and (AX.CompareTo(AN) >= 0))) then
    raise EArgumentCryptoLibException.CreateResFmt(@SValueOutOfRange, ['x']);
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
    if TArrayUtilities.AreEqual(LExpectedEncoding, AEncoding) then
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

end.
