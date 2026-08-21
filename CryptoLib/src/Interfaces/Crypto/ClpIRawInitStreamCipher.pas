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

unit ClpIRawInitStreamCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  ///   Zero-allocation (re)init for a stream cipher engine from raw key and
  ///   nonce byte spans, avoiding the per-message TParametersWithIV /
  ///   TKeyParameter wrappers Init would need. AKey = nil reuses the established
  ///   key (raises if the engine was never keyed). Validation is identical to
  ///   Init.
  /// </summary>
  IRawInitStreamCipher = interface
    ['{6E0B7A32-4C51-49D8-9F2A-1B8D5E3C0A74}']

    procedure InitRaw(const AKey, AIv: TCryptoLibByteArray);
  end;

implementation

end.
