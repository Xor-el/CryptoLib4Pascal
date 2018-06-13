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

unit ClpISchnorr;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpIECPrivateKeyParameters,
  ClpIECPublicKeyParameters,
  ClpIDigest,
  ClpBigInteger,
  ClpCryptoLibTypes;

type
  ISchnorr = interface(IInterface)
    ['{D3E88536-CE8D-4933-ADD8-235CAD65819F}']

    function GetAlgorithmName: String;
    property AlgorithmName: String read GetAlgorithmName;

    function Do_Sign(const &message: TCryptoLibByteArray; const digest: IDigest;
      const pv_key: IECPrivateKeyParameters; const k: TBigInteger)
      : TCryptoLibByteArray;

    function Do_Verify(const &message: TCryptoLibByteArray;
      const digest: IDigest; const pu_key: IECPublicKeyParameters;
      const sig: TCryptoLibByteArray): Boolean;

  end;

implementation

end.
