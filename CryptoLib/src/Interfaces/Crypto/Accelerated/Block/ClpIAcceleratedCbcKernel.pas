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

unit ClpIAcceleratedCbcKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpCryptoLibTypes,
  ClpAcceleratedKernelTypes,
  ClpIAcceleratedKernelFactory;

type
  /// <summary>
  ///   Mode-specific contract for an accelerated CBC body kernel, direction-bound at
  ///   construction (like the OCB / CCM kernels). Applies the CBC chain over a
  ///   whole run in one call, keeping the chaining value in a register between
  ///   blocks. Encrypt is inherently serial (C_i = E_K(P_i xor C_{i-1})), so its
  ///   win is orchestration, not parallelism; decrypt (P_i = D_K(C_i) xor
  ///   C_{i-1}) parallelises and is not yet implemented. Cipher state lives
  ///   inside the implementation; the mode sees only this interface.
  /// </summary>
  IAcceleratedCbcKernel = interface
    ['{898E71F2-B3C8-4B44-A3AB-2A493B4AE126}']

    /// <summary>
    ///   Process ABlockCount consecutive 16-byte CBC blocks in one pass, in the
    ///   direction fixed at construction. Encrypt: AOutPtr[i] := E_K(AInPtr[i] xor
    ///   chain), chain = AIvPtr for i = 0 else the previous ciphertext; the final
    ///   ciphertext block is written back to AIvPtr. ABlockCount MUST be >= 1.
    ///   AInPtr and AOutPtr are identical (in-place) or fully disjoint; partial
    ///   overlap is not supported.
    /// </summary>
    procedure ProcessCbcBlocks(AInPtr, AOutPtr, AIvPtr: Pointer;
      ABlockCount: NativeInt);
  end;

  /// <summary>
  ///   Factory contract for CBC-encrypt kernel providers. Registered with
  ///   TAcceleratedKernelRegistry; the registry walks the factory list (highest
  ///   priority first) and returns the first kernel whose TryCreate succeeds.
  ///   Factories self-probe (CPU features, cipher identity) and wrap construction
  ///   in try/except; TryCreate MUST return False on failure rather than
  ///   propagating.
  /// </summary>
  IAcceleratedCbcKernelFactory = interface(IAcceleratedKernelFactory)
    ['{A4FBAB88-8E80-45A0-86E1-B95B6AFBA9A2}']

    /// <summary>
    ///   Attempt to construct a CBC kernel bound to ACipher for ADirection.
    ///   Only Encrypt is implemented today; a Decrypt request returns False
    ///   (the mode then falls back). Returns False with AKernel = nil on any
    ///   failure; never raises.
    /// </summary>
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TAcceleratedKernelDirection;
      out AKernel: IAcceleratedCbcKernel): Boolean;
  end;

implementation

end.
