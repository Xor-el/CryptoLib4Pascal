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

unit ClpECDHCRawAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIRawAgreement,
  ClpIECDHCRawAgreement,
  ClpICipherParameters,
  ClpIECParameters,
  ClpECDHCBasicAgreement,
  ClpIParametersWithRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SECDHCRawAgreementExpectsECPrivateKeyParameters =
    'ECDHCRawAgreement expects ECPrivateKeyParameters';
  SECDHCRawAgreementPublicKeyExpected = 'EC public key parameters expected';

type
  TECDHCRawAgreement = class sealed(TInterfacedObject, IECDHCRawAgreement,
    IRawAgreement)

  strict private
  var
    FPrivateKey: IECPrivateKeyParameters;

    function GetAgreementSize(): Int32;

  public
    procedure Init(const AParameters: ICipherParameters);

    procedure CalculateAgreement(const APublicKey: ICipherParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    property AgreementSize: Int32 read GetAgreementSize;
  end;

implementation

{ TECDHCRawAgreement }

function TECDHCRawAgreement.GetAgreementSize: Int32;
begin
  Result := FPrivateKey.Parameters.Curve.FieldElementEncodingLength;
end;

procedure TECDHCRawAgreement.Init(const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LWithRandom: IParametersWithRandom;
  LECPriv: IECPrivateKeyParameters;
begin
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithRandom, LWithRandom) then
    LParameters := LWithRandom.Parameters;

  if not Supports(LParameters, IECPrivateKeyParameters, LECPriv) then
    raise EArgumentCryptoLibException.CreateRes(@SECDHCRawAgreementExpectsECPrivateKeyParameters);

  FPrivateKey := LECPriv;
end;

procedure TECDHCRawAgreement.CalculateAgreement(const APublicKey: ICipherParameters;
  const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LECPub: IECPublicKeyParameters;
  LBuf: TCryptoLibByteArray;
begin
  if not Supports(APublicKey, IECPublicKeyParameters, LECPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SECDHCRawAgreementPublicKeyExpected);

  LBuf := ABuf;
  TECDHCBasicAgreement.CalculateAgreementFieldElement(FPrivateKey, LECPub)
    .EncodeTo(LBuf, AOff);
end;

end.
