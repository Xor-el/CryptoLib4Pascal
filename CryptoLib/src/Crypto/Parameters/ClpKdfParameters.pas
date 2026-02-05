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

unit ClpKdfParameters;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIKdfParameters,
  ClpIDerivationParameters,
  ClpCryptoLibTypes;

type

  /// <summary>
  /// parameters for Key derivation functions for IEEE P1363a
  /// </summary>
  TKdfParameters = class(TInterfacedObject, IKdfParameters,
    IDerivationParameters)

  strict private
    FIv, FShared: TCryptoLibByteArray;

  public
    function GetSharedSecret(): TCryptoLibByteArray; inline;
    function GetIV(): TCryptoLibByteArray; inline;

    constructor Create(const AShared, AIv: TCryptoLibByteArray);
  end;

implementation

{ TKdfParameters }

constructor TKdfParameters.Create(const AShared, AIv: TCryptoLibByteArray);
begin
  inherited Create();
  FShared := AShared;
  FIv := AIv;
end;

function TKdfParameters.GetIV: TCryptoLibByteArray;
begin
  Result := FIv;
end;

function TKdfParameters.GetSharedSecret: TCryptoLibByteArray;
begin
  Result := FShared;
end;

end.
