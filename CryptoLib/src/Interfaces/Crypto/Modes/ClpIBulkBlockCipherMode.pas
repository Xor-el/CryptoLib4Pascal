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

unit ClpIBulkBlockCipherMode;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Optional capability interface implemented by block-cipher modes that
  /// can process multiple consecutive blocks per call, typically by
  /// delegating to a SIMD-accelerated underlying engine (e.g. AES-NI via
  /// TAesEngineX86). This interface is a sibling of IBlockCipherMode (it
  /// does NOT extend it) so existing mode clients that only know about
  /// IBlockCipher / IBlockCipherMode keep working unchanged. Callers that
  /// want to exploit the fast path opt in via Supports(FCipherMode,
  /// IBulkBlockCipherMode, FBulkMode).
  /// </summary>
  /// <remarks>
  /// Implementations must produce byte-identical output to ABlockCount
  /// sequential IBlockCipher.ProcessBlock calls. When no accelerated
  /// engine is available, the implementation is expected to fall back to
  /// such a per-block loop so the behaviour is stable across engines and
  /// build configurations (e.g. NOSIMD).
  /// </remarks>
  IBulkBlockCipherMode = interface(IInterface)
    ['{E2B4D6C9-1F8A-4A6E-93D1-7C5B2F3E8A4D}']

    /// <summary>
    /// Process ABlockCount consecutive blocks of GetBlockSize bytes each.
    /// ABlockCount * GetBlockSize bytes are consumed from AInBuf starting
    /// at AInOff and produced into AOutBuf starting at AOutOff. Aliasing
    /// rules are the same as IBlockCipher.ProcessBlock.
    /// </summary>
    /// <param name="AInBuf">The input buffer.</param>
    /// <param name="AInOff">The offset into AInBuf where the first input block begins.</param>
    /// <param name="ABlockCount">Number of consecutive blocks to process. Must be &gt;= 0.</param>
    /// <param name="AOutBuf">The output buffer.</param>
    /// <param name="AOutOff">The offset into AOutBuf where the first output block begins.</param>
    /// <returns>The number of bytes processed and produced (ABlockCount * GetBlockSize).</returns>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32;
  end;

implementation

end.
