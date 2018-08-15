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

unit ClpIECSchnorrSigner;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpISigner,
  ClpIECPublicKeyParameters,
  ClpIECPrivateKeyParameters,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  IECSchnorrSigner = interface(ISigner)
    ['{A941F9C5-81BE-4F0D-9294-2488C21035E3}']

    function Do_Sign(const pv_key: IECPrivateKeyParameters;
      const k: TBigInteger): TCryptoLibByteArray;

    function Do_Verify(const pu_key: IECPublicKeyParameters;
      const sig: TCryptoLibByteArray): Boolean;

  end;

implementation

end.
