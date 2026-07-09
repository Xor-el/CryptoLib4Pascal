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

unit ClpIBulkStreamCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Capability interface for stream ciphers that emit many consecutive 64-byte
  /// keystream blocks per call via a SIMD kernel. Resolved with Supports() and
  /// driven through ProcessBlocks; its absence means "no fast path".
  /// </summary>
  IBulkStreamCipher = interface(IStreamCipher)
    ['{7F1C4E62-9A3D-4B18-8E5A-2D6F1B0C7A94}']

    /// <summary>
    /// Transform ABlockCount 64-byte blocks; byte-identical to ABlockCount
    /// single-block transforms and advances the counter by ABlockCount. Requires
    /// block-aligned state; input and output must be identical or fully disjoint.
    /// </summary>
    /// <returns>Bytes produced (ABlockCount * 64).</returns>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload;

    /// <summary>Pointer overload of ProcessBlocks; same semantics.</summary>
    function ProcessBlocks(AInput, AOutput: PByte;
      ABlockCount: Int32): Int32; overload;
  end;

implementation

end.
