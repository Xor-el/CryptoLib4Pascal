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

unit ClpIFusedCbcEncryptKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpCryptoLibTypes,
  ClpFusedKernelTypes;

type
  /// <summary>
  ///   Mode-specific contract for a fused CBC-encrypt body kernel: apply the
  ///   serial CBC chain C_i = E_K(P_i xor C_{i-1}) over a whole run in a single
  ///   call, keeping the chaining value in a register between blocks. Unlike the
  ///   CTR / AEAD kernels this direction is inherently serial (each block depends
  ///   on the previous ciphertext), so the win is orchestration - no per-block
  ///   dispatch, XOR helper call, or IV store/reload - not parallelism. All
  ///   cipher state (the key schedule) lives inside the implementation; the mode
  ///   sees only this interface.
  /// </summary>
  IFusedCbcEncryptKernel = interface
    ['{898E71F2-B3C8-4B44-A3AB-2A493B4AE126}']

    /// <summary>
    ///   Encrypt ABlockCount consecutive 16-byte blocks in CBC mode in one pass:
    ///   for each block i, AOutPtr[i] := E_K(AInPtr[i] xor chain), where chain is
    ///   AIvPtr for i = 0 and the previous ciphertext block thereafter. On return
    ///   the final ciphertext block is written back to AIvPtr (the chaining value
    ///   for a subsequent call), matching sequential single-block CBC encryption.
    ///   ABlockCount MUST be >= 1. AInPtr and AOutPtr are identical (in-place) or
    ///   fully disjoint; partial overlap is not supported.
    /// </summary>
    procedure ProcessCbcEncryptBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
      ABlockCount: NativeInt);
  end;

  /// <summary>
  ///   Factory contract for CBC-encrypt kernel providers. Registered with
  ///   TFusedKernelRegistry; the registry walks the factory list (highest
  ///   priority first) and returns the first kernel whose TryCreate succeeds.
  ///   Factories self-probe (CPU features, cipher identity) and wrap construction
  ///   in try/except; TryCreate MUST return False on failure rather than
  ///   propagating.
  /// </summary>
  IFusedCbcEncryptKernelFactory = interface
    ['{A4FBAB88-8E80-45A0-86E1-B95B6AFBA9A2}']

    /// <summary>Stable human-readable provider label (diagnostics / tests).</summary>
    function ProviderName: String;

    /// <summary>Priority class controlling factory order inside the registry;
    /// see TFusedKernelPriority.</summary>
    function Priority: TFusedKernelPriority;

    /// <summary>
    ///   Attempt to construct a CBC-encrypt kernel bound to ACipher. ADirection
    ///   is accepted for signature symmetry with the other factories; CBC encrypt
    ///   is requested as Encrypt (the kernel encrypts regardless).
    /// </summary>
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedCbcEncryptKernel): Boolean;
  end;

implementation

end.
