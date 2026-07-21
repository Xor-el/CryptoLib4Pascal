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

unit ClpECDHRawAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIRawAgreement,
  ClpIECDHRawAgreement,
  ClpICipherParameters,
  ClpIECParameters,
  ClpECDHBasicAgreement,
  ClpIParametersWithRandom,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SECDHRawAgreementExpectsECPrivateKeyParameters =
    'ECDHRawAgreement expects ECPrivateKeyParameters';
  SECDHRawAgreementPublicKeyExpected = 'EC public key parameters expected';

type
  TECDHRawAgreement = class sealed(TInterfacedObject, IECDHRawAgreement,
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

{ TECDHRawAgreement }

function TECDHRawAgreement.GetAgreementSize: Int32;
begin
  Result := FPrivateKey.Parameters.Curve.FieldElementEncodingLength;
end;

procedure TECDHRawAgreement.Init(const AParameters: ICipherParameters);
var
  LParameters: ICipherParameters;
  LWithRandom: IParametersWithRandom;
  LECPriv: IECPrivateKeyParameters;
begin
  LParameters := AParameters;
  if Supports(LParameters, IParametersWithRandom, LWithRandom) then
    LParameters := LWithRandom.Parameters;

  if not Supports(LParameters, IECPrivateKeyParameters, LECPriv) then
    raise EArgumentCryptoLibException.CreateRes(@SECDHRawAgreementExpectsECPrivateKeyParameters);

  FPrivateKey := LECPriv;
end;

procedure TECDHRawAgreement.CalculateAgreement(const APublicKey: ICipherParameters;
  const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LECPub: IECPublicKeyParameters;
  LBuf: TCryptoLibByteArray;
begin
  if not Supports(APublicKey, IECPublicKeyParameters, LECPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SECDHRawAgreementPublicKeyExpected);

  LBuf := ABuf;
  TECDHBasicAgreement.CalculateAgreementFieldElement(FPrivateKey, LECPub)
    .EncodeTo(LBuf, AOff);
end;

end.
