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

unit ClpX448Agreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIRawAgreement,
  ClpIX448Agreement,
  ClpICipherParameters,
  ClpIX448Parameters,
  ClpX448Parameters,
  ClpCryptoLibTypes;

resourcestring
  SWrongInitCipherParameter =
    'the init parameter does not contain the private key';
  SPublicKeyParametersExpected = 'public key parameters expected';

type
  /// <summary>
  /// X448 (RFC 7748) Diffie-Hellman raw agreement. Init takes the local
  /// <see cref="IX448PrivateKeyParameters"/>; CalculateAgreement writes the 56-byte shared secret
  /// derived against the peer's <see cref="IX448PublicKeyParameters"/>.
  /// </summary>
  TX448Agreement = class sealed(TInterfacedObject, IX448Agreement,
    IRawAgreement)

  strict private
  var
    FPrivateKey: IX448PrivateKeyParameters;

    function GetAgreementSize(): Int32;

  public

    /// <summary>Capture the local private key used for subsequent agreements.</summary>
    /// <exception cref="EInvalidParameterCryptoLibException">
    /// If <paramref name="AParameters"/> is not an
    /// <see cref="IX448PrivateKeyParameters"/>.
    /// </exception>
    procedure Init(const AParameters: ICipherParameters);

    /// <summary>
    /// Perform the agreement against <paramref name="APublicKey"/> and write the shared secret into
    /// <paramref name="ABuf"/> starting at <paramref name="AOff"/>.
    /// </summary>
    /// <exception cref="EInvalidCastCryptoLibException">
    /// If <paramref name="APublicKey"/> is not an
    /// <see cref="IX448PublicKeyParameters"/>.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the agreement produces an all-zero secret (degenerate peer key).
    /// </exception>
    procedure CalculateAgreement(const APublicKey: ICipherParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    /// <summary>Length in bytes of the shared secret produced by the agreement (56).</summary>
    property AgreementSize: Int32 read GetAgreementSize;

  end;

implementation

{ TX448Agreement }

function TX448Agreement.GetAgreementSize: Int32;
begin
  Result := TX448PrivateKeyParameters.SecretSize;
end;

procedure TX448Agreement.Init(const AParameters: ICipherParameters);
var
  LPriv: IX448PrivateKeyParameters;
begin
  if not Supports(AParameters, IX448PrivateKeyParameters, LPriv) then
    raise EInvalidParameterCryptoLibException.CreateRes
      (@SWrongInitCipherParameter);

  FPrivateKey := LPriv;
end;

procedure TX448Agreement.CalculateAgreement(const APublicKey
  : ICipherParameters; const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPub: IX448PublicKeyParameters;
begin
  if not Supports(APublicKey, IX448PublicKeyParameters, LPub) then
    raise EInvalidCastCryptoLibException.CreateRes(@SPublicKeyParametersExpected);

  FPrivateKey.GenerateSecret(LPub, ABuf, AOff);
end;

end.
