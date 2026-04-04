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
    'The Init Parameter does not Contain the Private Key';

type
  TX448Agreement = class sealed(TInterfacedObject, IX448Agreement,
    IRawAgreement)

  strict private
  var
    FPrivateKey: IX448PrivateKeyParameters;

    function GetAgreementSize(): Int32;

  public

    procedure Init(const AParameters: ICipherParameters);

    procedure CalculateAgreement(const APublicKey: ICipherParameters;
      const ABuf: TCryptoLibByteArray; AOff: Int32);

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
    raise EInvalidCastCryptoLibException.Create('APublicKey');

  FPrivateKey.GenerateSecret(LPub, ABuf, AOff);
end;

end.
