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

unit ClpRsaBlindingParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBigInteger,
  ClpIRsaKeyParameters,
  ClpIRsaBlindingParameters,
  ClpCryptoLibTypes;

resourcestring
  SPublicKeyRequired = 'RSA parameters should be for a public key';

type
  /// <summary>
  /// Parameters for RSA blinding operations.
  /// </summary>
  TRsaBlindingParameters = class(TInterfacedObject, IRsaBlindingParameters)

  strict private
  var
    FPublicKey: IRsaKeyParameters;
    FBlindingFactor: TBigInteger;

  strict protected
    function GetPublicKey: IRsaKeyParameters;
    function GetBlindingFactor: TBigInteger;

  public
    constructor Create(const publicKey: IRsaKeyParameters;
      const blindingFactor: TBigInteger);

    property PublicKey: IRsaKeyParameters read GetPublicKey;
    property BlindingFactor: TBigInteger read GetBlindingFactor;

  end;

implementation

{ TRsaBlindingParameters }

constructor TRsaBlindingParameters.Create(const publicKey: IRsaKeyParameters;
  const blindingFactor: TBigInteger);
begin
  inherited Create();

  if publicKey.IsPrivate then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SPublicKeyRequired);
  end;

  FPublicKey := publicKey;
  FBlindingFactor := blindingFactor;
end;

function TRsaBlindingParameters.GetBlindingFactor: TBigInteger;
begin
  Result := FBlindingFactor;
end;

function TRsaBlindingParameters.GetPublicKey: IRsaKeyParameters;
begin
  Result := FPublicKey;
end;

end.
