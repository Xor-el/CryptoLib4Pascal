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

unit ClpIFusedOcbKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpFusedKernelTypes;

type
  /// <summary>
  ///   Mode-specific contract for a fused OCB body kernel. All cipher
  ///   state lives inside the implementation; the mode sees only this
  ///   interface.
  /// </summary>
  IFusedOcbKernel = interface
    ['{ADAF5C2A-FD31-42EF-A266-EB4B0F9AC06D}']

    /// <summary>The minimum (and alignment) batch width the kernel
    /// accepts. ABlockCount passed to ProcessBlocks must be a positive
    /// multiple of this value.</summary>
    function MinimumBlockCount: Int32;

    /// <summary>
    ///   Process ABlockCount blocks of OCB body in a single call with
    ///   the offset ladder, L-table lookup and checksum fold all fused
    ///   inside the kernel.
    ///   ABlockCount MUST be a positive multiple of MinimumBlockCount;
    ///   the kernel iterates internally in MinimumBlockCount-sized
    ///   chunks so the caller can amortise call overhead across large
    ///   batches.
    ///
    ///   AInPtr / AOutPtr cover ABlockCount * 16 contiguous bytes each
    ///   and MAY alias.
    ///
    ///   AOffsetPtr points at the 16-byte live FOffsetMAIN value; the
    ///   kernel loads it at entry, updates it in-place as it walks the
    ///   offset ladder, and writes the final value back at exit.
    ///
    ///   AChecksumPtr points at the 16-byte live FChecksum value; the
    ///   kernel loads it at entry, folds each plaintext block
    ///   (pre-AES on encrypt; post-AES on decrypt) into it, and writes
    ///   the final value back at exit.
    ///
    ///   ALTablePtr points at a read-only contiguous buffer of L-table
    ///   entries L[0], L[1], ..., L[LMax], each 16 bytes. The caller
    ///   guarantees it covers every ntz value referenced by ANtzPtr.
    ///
    ///   ANtzPtr points at a read-only ABlockCount-byte array where
    ///   ANtzPtr[i] = OCB_ntz(FMainBlockCount + i + 1). The caller
    ///   pre-computes these so the kernel can index the L-table with a
    ///   single byte load per block (cheaper and simpler than doing
    ///   BSF + 64-bit counter bookkeeping inside the kernel, especially
    ///   on i386).
    ///
    ///   ABlock0Ptr points at the 16-byte source of block 0 of the very
    ///   first kernel iteration. It MAY equal AInPtr (the common case,
    ///   used by encrypt and by small-MAC decrypt which still stages a
    ///   contiguous scratch buffer), or it MAY point at an unrelated
    ///   16-byte buffer (used by full-MAC decrypt to splice the
    ///   FMainBlock lookahead prefix into the input stream without a
    ///   per-batch memcpy). Subsequent iterations load block 0 from
    ///   (AInPtr advanced by one stride), so the kernel itself
    ///   transparently transitions from the prefix source to the main
    ///   stream after iteration 0.
    /// </summary>
    procedure ProcessBlocks(AInPtr, AOutPtr, AOffsetPtr, AChecksumPtr,
      ALTablePtr, ANtzPtr, ABlock0Ptr: Pointer; ABlockCount: Int32);
  end;

  IFusedOcbKernelFactory = interface
    ['{A430371B-1B11-46C2-AFC8-EF9B07DE4CFA}']

    function ProviderName: String;
    function Priority: TFusedKernelPriority;

    /// <summary>
    ///   Attempt to construct an OCB kernel bound to ACipher for the
    ///   requested ADirection. Returns False with AKernel = nil on any
    ///   failure (cipher not supported, CPU feature missing,
    ///   construction exception); never raises.
    /// </summary>
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedOcbKernel): Boolean;
  end;

implementation

end.
