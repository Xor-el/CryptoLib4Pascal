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

unit ClpIBulkBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Engine-side capability interface implemented by block ciphers that can
  /// transform multiple consecutive blocks per call, typically by dispatching
  /// to a SIMD-accelerated inner kernel (e.g. AES-NI via TAesEngineX86). This
  /// interface is the cipher-side companion to IBulkBlockCipherMode: modes
  /// (CTR/SIC, CBC, ECB, the non-fused GCM CTR dispatcher, ...) query for it
  /// via Supports(FCipher, IBulkBlockCipher, FBulkCipher) and let the engine
  /// own the "best batch size" decision (8-wide / 4-wide / 1-wide ladders on
  /// AES-NI today; a hypothetical AVX-512 16-wide or ARMv8 engine would just
  /// plug in here with no mode-side changes).
  /// </summary>
  /// <remarks>
  /// Contract: ProcessBlocks(..., ABlockCount) produces byte-identical output
  /// to ABlockCount sequential IBlockCipher.ProcessBlock calls. Implementations
  /// that cannot beat per-block dispatch should NOT implement this interface;
  /// mode callers treat its absence as "no fast path" and fall through to the
  /// per-block loop.
  ///
  /// Aliasing: AInput and AOutput MUST be either identical pointers (in-place
  /// transform) or reference fully disjoint ranges of ABlockCount * BlockSize
  /// bytes. Partially overlapping ranges are NOT supported; callers that need
  /// that behaviour must pre-stage into disjoint memory themselves. This is
  /// the narrowest contract that every current mode call site already
  /// satisfies (CBC decrypt stages ciphertext into a scratch buffer first;
  /// CTR runs in-place on its keystream buffer; ECB passes caller-owned
  /// buffers that are identical-or-disjoint; GCM non-fused CTR runs in-place
  /// on its counter buffer). Keeping it narrow lets engines dispatch to their
  /// strict-path internals without a per-batch overlap probe.
  /// </remarks>
  IBulkBlockCipher = interface(IBlockCipher)
    ['{3B9D7E2F-8C1A-4F5D-B4A6-9E7C2D5F3A8B}']

    /// <summary>
    /// Transform ABlockCount consecutive blocks of GetBlockSize bytes each.
    /// ABlockCount * GetBlockSize bytes are consumed from AInBuf starting at
    /// AInOff and produced into AOutBuf starting at AOutOff. Aliasing rules
    /// as documented on the interface.
    /// </summary>
    /// <param name="AInBuf">The input buffer.</param>
    /// <param name="AInOff">Offset into AInBuf of the first input block.</param>
    /// <param name="ABlockCount">Number of consecutive blocks to process. Must be &gt;= 0.</param>
    /// <param name="AOutBuf">The output buffer.</param>
    /// <param name="AOutOff">Offset into AOutBuf of the first output block.</param>
    /// <returns>Number of bytes processed and produced (ABlockCount * GetBlockSize).</returns>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload;

    /// <summary>
    /// Pointer-overload of ProcessBlocks for mode-internal stack buffers that
    /// are not TCryptoLibByteArray (e.g. CTR's keystream 'array [0..127] of
    /// Byte'). Same semantics and aliasing rules as the array overload.
    /// Callers are responsible for ensuring at least ABlockCount * BlockSize
    /// bytes of valid memory behind each pointer.
    /// </summary>
    /// <returns>Number of bytes processed and produced (ABlockCount * GetBlockSize).</returns>
    function ProcessBlocks(AInput, AOutput: PByte;
      ABlockCount: Int32): Int32; overload;
  end;

implementation

end.
