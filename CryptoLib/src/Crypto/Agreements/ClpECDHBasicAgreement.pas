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

unit ClpECDHBasicAgreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpECAlgorithms,
  ClpICipherParameters,
  ClpIECParameters,
  ClpIECCommon,
  ClpIBasicAgreement,
  ClpIECDHBasicAgreement,
  ClpIParametersWithRandom,
  ClpCryptoLibTypes;

resourcestring
  SNotECPrivateKeyParameters = 'ECDHBasicAgreement expects ECPrivateKeyParameters';
  SWrongDomainParameter = 'ECDH Public Key has Wrong Domain Parameters';
  SInvalidAgreementValue = 'Infinity is not a Valid Agreement Value for ECDH';
  SInfinityInvalidPublicKey = 'Infinity is not a Valid Public Key for ECDH';

type
  /// <summary>
  /// P1363 7.2.1 ECSVDP-DH <br />ECSVDP-DH is Elliptic Curve Secret Value
  /// Derivation Primitive, <br />Diffie-Hellman version. It is based on the
  /// work of [DH76], [Mil86], <br />and [Kob87]. This primitive derives a
  /// shared secret value from one <br />party's private key and another
  /// party's public key, where both have <br />the same set of EC domain
  /// parameters. If two parties correctly <br />execute this primitive, they
  /// will produce the same output. This <br />primitive can be invoked by a
  /// scheme to derive a shared secret key; <br />specifically, it may be
  /// used with the schemes ECKAS-DH1 and <br />DL/ECKAS-DH2. It assumes that
  /// the input keys are valid (see also <br />Section 7.2.2). <br />
  /// </summary>
  TECDHBasicAgreement = class(TInterfacedObject, IECDHBasicAgreement,
    IBasicAgreement)

  protected
  var
    FPrivKey: IECPrivateKeyParameters;

  public
    /// <summary>
    /// initialise the agreement engine.
    /// </summary>
    procedure Init(const AParameters: ICipherParameters); virtual;

    /// <summary>
    /// return the field size for the agreement algorithm in bytes.
    /// </summary>
    function GetFieldSize(): Int32; virtual;

    /// <summary>
    /// given a public key from a given party calculate the next message
    /// in the agreement sequence.
    /// </summary>
    function CalculateAgreement(const APubKey: ICipherParameters): TBigInteger; virtual;

  end;

implementation

{ TECDHBasicAgreement }

function TECDHBasicAgreement.CalculateAgreement(const APubKey: ICipherParameters)
  : TBigInteger;
var
  LPub: IECPublicKeyParameters;
  LParams: IECDomainParameters;
  LP, LQ: IECPoint;
  LD, LH: TBigInteger;
begin
  if not Supports(APubKey, IECPublicKeyParameters, LPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SWrongDomainParameter);

  LParams := FPrivKey.Parameters;
  if not LParams.Equals(LPub.Parameters) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SWrongDomainParameter);

  LD := FPrivKey.d;

  LQ := TECAlgorithms.CleanPoint(LParams.Curve, LPub.Q);

  if LQ.IsInfinity then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInfinityInvalidPublicKey);

  LH := LParams.H;

  if not LH.Equals(TBigInteger.One) then
  begin
    LD := LParams.HInv.Multiply(LD).&Mod(LParams.N);
    LQ := TECAlgorithms.ReferenceMultiply(LQ, LH);
  end;

  LP := LParams.Curve.Multiplier.Multiply(LQ, LD).Normalize();

  if LP.IsInfinity then
    raise EInvalidOperationCryptoLibException.CreateRes
      (@SInvalidAgreementValue);

  Result := LP.XCoord.ToBigInteger();
end;

function TECDHBasicAgreement.GetFieldSize: Int32;
begin
  Result := FPrivKey.Parameters.Curve.FieldElementEncodingLength;
end;

procedure TECDHBasicAgreement.Init(const AParameters: ICipherParameters);
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
