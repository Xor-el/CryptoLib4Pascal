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
  ClpFusedModeDirection;

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
    ///   Process ABlockCount blocks of OCB body in a single call.
    ///   ABlockCount MUST be a positive multiple of MinimumBlockCount;
    ///   the kernel iterates internally in MinimumBlockCount-sized
    ///   chunks so the caller can amortise call overhead across large
    ///   batches. AOffsets points at ABlockCount consecutive 16-byte
    ///   raw Delta values (the kernel folds them through the cipher's
    ///   pre/post-whitening internally). AInPtr / AOutPtr cover
    ///   ABlockCount * 16 contiguous bytes each and MAY alias.
    /// </summary>
    procedure ProcessBlocks(AInPtr, AOutPtr, AOffsets: Pointer;
      ABlockCount: Int32);
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
