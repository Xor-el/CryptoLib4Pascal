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

unit ClpIRsaBlindingParameters;

{$I ..\Include\CryptoLib.inc}

interface

uses
  ClpBigInteger,
  ClpIRsaKeyParameters,
  ClpICipherParameters;

type
  /// <summary>
  /// Interface for RSA blinding parameters.
  /// </summary>
  IRsaBlindingParameters = interface(ICipherParameters)
    ['{F2A3B4C5-D6E7-8901-2345-6789ABCDEF01}']

    function GetPublicKey: IRsaKeyParameters;
    function GetBlindingFactor: TBigInteger;

    property PublicKey: IRsaKeyParameters read GetPublicKey;
    property BlindingFactor: TBigInteger read GetBlindingFactor;

  end;

implementation

end.
