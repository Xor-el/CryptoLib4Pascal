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

unit ClpECKeyEncoder;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIAsymmetricKeyParameter,
  ClpIECParameters,
  ClpIKeyEncoder,
  ClpCryptoLibTypes;

resourcestring
  SKeyParameterNotECPublicKey = 'AKeyParameter is not an IECPublicKeyParameters';

type
  TECKeyEncoder = class(TInterfacedObject, IKeyEncoder)

  strict private
  var
    FUsePointCompression: Boolean;

  public
    constructor Create(AUsePointCompression: Boolean);
    function GetEncoded(const AKeyParameter: IAsymmetricKeyParameter)
      : TCryptoLibByteArray;

  end;

implementation

{ TECKeyEncoder }

constructor TECKeyEncoder.Create(AUsePointCompression: Boolean);
begin
  Inherited Create();
  FUsePointCompression := AUsePointCompression;
end;

function TECKeyEncoder.GetEncoded(const AKeyParameter: IAsymmetricKeyParameter)
  : TCryptoLibByteArray;
var
  LEcPub: IECPublicKeyParameters;
begin
  if not Supports(AKeyParameter, IECPublicKeyParameters, LEcPub) then
    raise EArgumentCryptoLibException.CreateRes(@SKeyParameterNotECPublicKey);
  Result := LEcPub.Q.GetEncoded(FUsePointCompression);
end;

end.
