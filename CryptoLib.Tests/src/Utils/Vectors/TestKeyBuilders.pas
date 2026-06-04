{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }
{ *                                                                                 * }
{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }
{ *                                                                                 * }
{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                         the development of this library                         * }
{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit TestKeyBuilders;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  ClpBigInteger,
  ClpCryptoLibTypes,
  ClpEncoders,
  ClpIRsaParameters,
  ClpRsaParameters;

type
  TRsaCrtHexRecord = record
    Modulus, PubExp, PrivExp, P, Q, DP, DQ, QInv: string;
  end;

  TTestKeyBuilders = class sealed
  public
    class function CreateRsaPublicFromHexRecord(const ARecord: TRsaCrtHexRecord)
      : IRsaKeyParameters; static;
    class function CreateRsaPrivateCrtFromHexRecord(const ARecord: TRsaCrtHexRecord)
      : IRsaPrivateCrtKeyParameters; static;
    class function CreateRsaPublicFromDecodedHex(const ARecord: TRsaCrtHexRecord)
      : IRsaKeyParameters; static;
    class function CreateRsaPrivateCrtFromDecodedHex(const ARecord: TRsaCrtHexRecord)
      : IRsaPrivateCrtKeyParameters; static;
  end;

implementation

{ TTestKeyBuilders }

class function TTestKeyBuilders.CreateRsaPublicFromHexRecord(const ARecord: TRsaCrtHexRecord)
  : IRsaKeyParameters;
begin
  Result := TRsaKeyParameters.Create(False,
    TBigInteger.Create(ARecord.Modulus, 16),
    TBigInteger.Create(ARecord.PubExp, 16));
end;

class function TTestKeyBuilders.CreateRsaPrivateCrtFromHexRecord(const ARecord: TRsaCrtHexRecord)
  : IRsaPrivateCrtKeyParameters;
begin
  Result := TRsaPrivateCrtKeyParameters.Create(
    TBigInteger.Create(ARecord.Modulus, 16),
    TBigInteger.Create(ARecord.PubExp, 16),
    TBigInteger.Create(ARecord.PrivExp, 16),
    TBigInteger.Create(ARecord.P, 16),
    TBigInteger.Create(ARecord.Q, 16),
    TBigInteger.Create(ARecord.DP, 16),
    TBigInteger.Create(ARecord.DQ, 16),
    TBigInteger.Create(ARecord.QInv, 16));
end;

class function TTestKeyBuilders.CreateRsaPublicFromDecodedHex(const ARecord: TRsaCrtHexRecord)
  : IRsaKeyParameters;
begin
  Result := TRsaKeyParameters.Create(False,
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.Modulus)),
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.PubExp)));
end;

class function TTestKeyBuilders.CreateRsaPrivateCrtFromDecodedHex(const ARecord: TRsaCrtHexRecord)
  : IRsaPrivateCrtKeyParameters;
var
  LPub: IRsaKeyParameters;
begin
  LPub := CreateRsaPublicFromDecodedHex(ARecord);
  Result := TRsaPrivateCrtKeyParameters.Create(
    LPub.Modulus,
    LPub.Exponent,
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.PrivExp)),
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.P)),
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.Q)),
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.DP)),
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.DQ)),
    TBigInteger.Create(1, THexEncoder.Decode(ARecord.QInv)));
end;

end.
