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

unit ClpECDHCBasicAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpECAlgorithms,
  ClpICipherParameters,
  ClpIECCommon,
  ClpIECFieldElement,
  ClpIBasicAgreement,
  ClpIECParameters,
  ClpIECDHCBasicAgreement,
  ClpIParametersWithRandom,
  ClpCryptoLibTypes;

resourcestring
  SNotECPrivateKeyParameters =
    'ECDHCBasicAgreement expects ECPrivateKeyParameters';
  SWrongDomainParameter =
    'ECDHC public key has wrong domain parameters';
  SInvalidAgreementValue =
    'infinity is not a valid agreement value for ECDHC';
  SInfinityInvalidPublicKey =
    'infinity is not a valid public key for ECDHC';

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

    class function CalculateAgreementFieldElement(const APrivateKey: IECPrivateKeyParameters;
      const APublicKey: IECPublicKeyParameters): IECFieldElement; static;

  end;

implementation

{ TECDHCBasicAgreement }

function TECDHCBasicAgreement.CalculateAgreement(const APubKey
  : ICipherParameters): TBigInteger;
var
  LPub: IECPublicKeyParameters;
begin
  if not Supports(APubKey, IECPublicKeyParameters, LPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SWrongDomainParameter);

  Result := CalculateAgreementFieldElement(FPrivKey, LPub).ToBigInteger();
end;

class function TECDHCBasicAgreement.CalculateAgreementFieldElement(
  const APrivateKey: IECPrivateKeyParameters; const APublicKey: IECPublicKeyParameters)
  : IECFieldElement;
var
  LParams: IECDomainParameters;
  LHd: TBigInteger;
  LP, LPubPoint: IECPoint;
begin
  LParams := APrivateKey.Parameters;
  if not LParams.Equals(APublicKey.Parameters) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SWrongDomainParameter);

  LHd := LParams.H.Multiply(APrivateKey.D).&Mod(LParams.N);

  LPubPoint := TECAlgorithms.CleanPoint(LParams.Curve, APublicKey.Q);
  if LPubPoint.IsInfinity then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInfinityInvalidPublicKey);

  LP := LParams.Curve.Multiplier.Multiply(LPubPoint, LHd).Normalize();

  if LP.IsInfinity then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInvalidAgreementValue);

  Result := LP.XCoord;
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
