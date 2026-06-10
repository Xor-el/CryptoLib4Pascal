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

unit ClpX25519Agreement;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIRawAgreement,
  ClpIX25519Agreement,
  ClpICipherParameters,
  ClpIX25519Parameters,
  ClpX25519Parameters,
  ClpCryptoLibTypes;

resourcestring
  SWrongInitCipherParameter =
    'The Init Parameter does not Contain the Private Key';

type
  /// <summary>
  /// X25519 (RFC 7748) Diffie-Hellman raw agreement. Init takes the local
  /// <see cref="IX25519PrivateKeyParameters"/>; CalculateAgreement writes the 32-byte shared secret
  /// derived against the peer's <see cref="IX25519PublicKeyParameters"/>.
  /// </summary>
  TX25519Agreement = class sealed(TInterfacedObject, IX25519Agreement,
    IRawAgreement)

  strict private
  var
    FPrivateKey: IX25519PrivateKeyParameters;

    function GetAgreementSize(): Int32;

  public

    /// <summary>Capture the local private key used for subsequent agreements.</summary>
    /// <exception cref="EInvalidParameterCryptoLibException">
    /// If <paramref name="AParameters"/> is not an
    /// <see cref="IX25519PrivateKeyParameters"/>.
    /// </exception>
    procedure Init(const AParameters: ICipherParameters);

    /// <summary>
    /// Perform the agreement against <paramref name="APublicKey"/> and write the shared secret into
    /// <paramref name="ABuf"/> starting at <paramref name="AOff"/>.
    /// </summary>
    /// <exception cref="EInvalidCastCryptoLibException">
    /// If <paramref name="APublicKey"/> is not an
    /// <see cref="IX25519PublicKeyParameters"/>.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// If the agreement produces an all-zero secret (degenerate peer key).
    /// </exception>
    procedure CalculateAgreement(const APublicKey: ICipherParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

    /// <summary>Length in bytes of the shared secret produced by the agreement (32).</summary>
    property AgreementSize: Int32 read GetAgreementSize;

  end;

implementation

{ TX25519Agreement }

function TX25519Agreement.GetAgreementSize: Int32;
begin
  Result := TX25519PrivateKeyParameters.SecretSize;
end;

procedure TX25519Agreement.Init(const AParameters: ICipherParameters);
var
  LPriv: IX25519PrivateKeyParameters;
begin
  if not Supports(AParameters, IX25519PrivateKeyParameters, LPriv) then
    raise EInvalidParameterCryptoLibException.CreateRes
      (@SWrongInitCipherParameter);

  FPrivateKey := LPriv;
end;

procedure TX25519Agreement.CalculateAgreement(const APublicKey
  : ICipherParameters; const ABuf: TCryptoLibByteArray; AOff: Int32);
var
  LPub: IX25519PublicKeyParameters;
begin
  if not Supports(APublicKey, IX25519PublicKeyParameters, LPub) then
    raise EInvalidCastCryptoLibException.Create('APublicKey');

  FPrivateKey.GenerateSecret(LPub, ABuf, AOff);
end;

end.
