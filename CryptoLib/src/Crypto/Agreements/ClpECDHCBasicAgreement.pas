{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit ClpECDHCBasicAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpECAlgorithms,
  ClpICipherParameters,
  ClpIECCommon,
  ClpIBasicAgreement,
  ClpIECParameters,
  ClpIECDHCBasicAgreement,
  ClpIParametersWithRandom,
  ClpCryptoLibTypes;

resourcestring
  SNotECPrivateKeyParameters =
    'ECDHCBasicAgreement expects ECPrivateKeyParameters';
  SWrongDomainParameter =
    'ECDHC Public Key has Wrong Domain Parameters';
  SInvalidAgreementValue =
    'Infinity is not a Valid Agreement Value for ECDHC';
  SInfinityInvalidPublicKey =
    'Infinity is not a Valid Public Key for ECDHC';

type
  TECDHCBasicAgreement = class(TInterfacedObject, IECDHCBasicAgreement,
    IBasicAgreement)

  strict private
  var
    FPrivKey: IECPrivateKeyParameters;

  public
    procedure Init(const AParameters: ICipherParameters); virtual;
    function GetFieldSize(): Int32; virtual;
    function CalculateAgreement(const APubKey: ICipherParameters): TBigInteger; virtual;

  end;

implementation

{ TECDHCBasicAgreement }

function TECDHCBasicAgreement.CalculateAgreement(const APubKey
  : ICipherParameters): TBigInteger;
var
  LPub: IECPublicKeyParameters;
  LParams: IECDomainParameters;
  LHd: TBigInteger;
  LP, LPubPoint: IECPoint;
begin
  if not Supports(APubKey, IECPublicKeyParameters, LPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SWrongDomainParameter);

  LParams := FPrivKey.Parameters;
  if not LParams.Equals(LPub.Parameters) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SWrongDomainParameter);

  LHd := LParams.H.Multiply(FPrivKey.D).&Mod(LParams.N);

  LPubPoint := TECAlgorithms.CleanPoint(LParams.Curve, LPub.Q);
  if LPubPoint.IsInfinity then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInfinityInvalidPublicKey);

  LP := LParams.Curve.Multiplier.Multiply(LPubPoint, LHd).Normalize();

  if LP.IsInfinity then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInvalidAgreementValue);

  Result := LP.XCoord.ToBigInteger();
end;

function TECDHCBasicAgreement.GetFieldSize: Int32;
begin
  Result := FPrivKey.Parameters.Curve.FieldElementEncodingLength;
end;

procedure TECDHCBasicAgreement.Init(const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LWithRandom: IParametersWithRandom;
  LECPriv: IECPrivateKeyParameters;
begin
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithRandom, LWithRandom) then
    LParameters := LWithRandom.Parameters;

  if not Supports(LParameters, IECPrivateKeyParameters, LECPriv) then
    raise EArgumentCryptoLibException.CreateRes(@SNotECPrivateKeyParameters);

  FPrivKey := LECPriv;
end;

end.
