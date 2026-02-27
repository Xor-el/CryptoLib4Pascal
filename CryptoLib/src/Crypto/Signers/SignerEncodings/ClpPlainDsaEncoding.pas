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

unit ClpPlainDsaEncoding;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  ClpBigInteger,
  ClpIDsaEncoding,
  ClpIPlainDsaEncoding,
  ClpArrayUtilities,
  ClpBigIntegerUtilities,
  ClpCryptoLibTypes;

resourcestring
  SValueOutOfRange = 'Value out of range, "%s"';
  SInvalidEncodingLength = 'Encoding has incorrect length, "%s"';

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

function TPlainDsaEncoding.CheckValue(const AN, AX: TBigInteger): TBigInteger;
begin
  if ((AX.SignValue < 0) or ((AX.CompareTo(AN) >= 0))) then
    raise EArgumentCryptoLibException.CreateResFmt(@SValueOutOfRange, ['x']);
  Result := AX;
end;

function TPlainDsaEncoding.Decode(const AN: TBigInteger;
  const AEncoding: TCryptoLibByteArray): TCryptoLibGenericArray<TBigInteger>;
var
  LValueLength: Int32;
begin
  LValueLength := TBigIntegerUtilities.GetUnsignedByteLength(AN);
  if (System.Length(AEncoding) <> (LValueLength * 2)) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidEncodingLength,
      ['encoding']);
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
  LValueLength := TBigIntegerUtilities.GetUnsignedByteLength(AN);
  System.SetLength(Result, LValueLength * 2);
  EncodeValue(AN, AR, Result, 0, LValueLength);
  EncodeValue(AN, &AS, Result, LValueLength, LValueLength);
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
  Result := TBigIntegerUtilities.GetUnsignedByteLength(AN) * 2;
end;

class function TPlainDsaEncoding.GetInstance: IPlainDsaEncoding;
begin
  Result := TPlainDsaEncoding.Create();
end;

end.
