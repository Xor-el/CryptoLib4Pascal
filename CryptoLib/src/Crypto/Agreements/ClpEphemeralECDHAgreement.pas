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

unit ClpEphemeralECDHAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpICipherParameters,
  ClpIECParameters,
  ClpIECCommon,
  ClpIEphemeralECDHAgreement,
  ClpECDHBasicAgreement,
  ClpECCurveConstants,
  ClpCryptoLibExceptions;

resourcestring
  SEphemeralAgreementReused =
    'ephemeral ECDH agreement is single-use and has already produced a secret';
  SWrongPublicKey = 'ephemeral ECDH public key has wrong domain parameters';

type
  /// <summary>Single-use ECDH agreement for a freshly generated ephemeral private
  /// key. See <see cref="IEphemeralECDHAgreement"/>.</summary>
  TEphemeralECDHAgreement = class sealed(TInterfacedObject, IEphemeralECDHAgreement)
  strict private
    FPrivKey: IECPrivateKeyParameters;
    FMultiplier: IECMultiplier;
    FUsed: Boolean;
  public
    /// <summary>Binds the single-use private key and resolves a dedicated
    /// constant-time multiplier for it. ABlindBits selects the scalar-blind width
    /// (default: minimal, single-use). Curves that do not implement the CT
    /// multiplier factory fall back to their fully-blinded default multiplier.</summary>
    constructor Create(const APrivateKey: IECPrivateKeyParameters;
      ABlindBits: Int32 = TECCurveConstants.SCALAR_BLIND_MINIMAL);
    function CalculateAgreement(const APubKey: ICipherParameters): TBigInteger;
  end;

implementation

{ TEphemeralECDHAgreement }

constructor TEphemeralECDHAgreement.Create(const APrivateKey: IECPrivateKeyParameters;
  ABlindBits: Int32);
var
  LFactory: IECCTMultiplierFactory;
begin
  Inherited Create;
  FPrivKey := APrivateKey;
  // Dedicated single-use multiplier, never the shared curve default. Curves
  // without the factory (F2m, generic Fp) fall back to the fully-blinded default,
  // so the degraded posture is opt-in per curve and never a failure path.
  if Supports(APrivateKey.Parameters.Curve, IECCTMultiplierFactory, LFactory) then
    FMultiplier := LFactory.CreateCTMultiplier(ABlindBits)
  else
    FMultiplier := APrivateKey.Parameters.Curve.Multiplier;
end;

function TEphemeralECDHAgreement.CalculateAgreement(const APubKey: ICipherParameters): TBigInteger;
var
  LPub: IECPublicKeyParameters;
begin
  if FUsed then
    raise EInvalidOperationCryptoLibException.CreateRes(@SEphemeralAgreementReused);
  FUsed := True; // set before compute: an exception still consumes this object
  if not Supports(APubKey, IECPublicKeyParameters, LPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SWrongPublicKey);
  try
    Result := TECDHBasicAgreement.CalculateAgreementFieldElement(
      FPrivKey, LPub, FMultiplier).ToBigInteger();
  finally
    FPrivKey := nil;
    FMultiplier := nil;
  end;
end;

end.
