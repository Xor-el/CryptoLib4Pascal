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
  TX25519Agreement = class sealed(TInterfacedObject, IX25519Agreement,
    IRawAgreement)

  strict private
  var
    FPrivateKey: IX25519PrivateKeyParameters;

    function GetAgreementSize(): Int32;

  public

    procedure Init(const AParameters: ICipherParameters);

    procedure CalculateAgreement(const APublicKey: ICipherParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

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
