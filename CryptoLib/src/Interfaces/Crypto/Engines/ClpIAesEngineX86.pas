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
  ClpIBulkBlockCipher;

type
  /// <summary>
  /// AES-NI engine interface. Extends IBulkBlockCipher (which itself extends
  /// IBlockCipher) with AES-specific capability hooks needed by the fused
  /// GCM + AES-NI pipeline kernel. Generic multi-block batching is inherited
  /// from IBulkBlockCipher.ProcessBlocks; modes that only want the fast
  /// bulk path should query IBulkBlockCipher, not IAesEngineX86, to stay
  /// cipher-agnostic.
  /// </summary>
  IAesEngineX86 = interface(IBulkBlockCipher)
    ['{B2F8C4A1-9E3D-4F6B-8C0D-1A2B3C4D5E6F}']
  end;

implementation

end.
