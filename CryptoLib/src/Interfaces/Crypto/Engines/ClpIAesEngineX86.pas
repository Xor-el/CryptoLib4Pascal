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

unit ClpIAesEngineX86;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// X86 AES-NI Engine. Adds a four-block API for GCM CTR batching.
  /// </summary>
  IAesEngineX86 = interface(IBlockCipher)
    ['{B2F8C4A1-9E3D-4F6B-8C0D-1A2B3C4D5E6F}']

    function ProcessFourBlocks(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
  end;

implementation

end.
