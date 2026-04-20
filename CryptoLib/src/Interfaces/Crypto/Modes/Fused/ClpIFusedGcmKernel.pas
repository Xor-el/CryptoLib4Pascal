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

unit ClpIFusedGcmKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpFusedKernelTypes;

type
  /// <summary>
  ///   Mode-specific contract for a fused GCM body kernel: produce
  ///   keystream for the current batch, XOR it into the payload, and
  ///   fold the previous batch's ciphertext into the running GHASH
  ///   accumulator. All cipher state (key schedule, H-power table,
  ///   static constants) lives inside the implementation; the mode
  ///   sees only this interface.
  /// </summary>
  IFusedGcmKernel = interface
    ['{D4D7F5F0-3C56-44E0-8BDD-944AC05E4D2E}']

    /// <summary>Number of 16-byte blocks consumed per
    /// ProcessCtrGhashBatch invocation.</summary>
    function MinimumBlockCount: Int32;

    /// <summary>
    ///   Process exactly MinimumBlockCount blocks of the GCM body.
    ///   Per-call buffers:
    ///     AInPtr       MinimumBlockCount * 16 bytes of input.
    ///     AOutPtr      MinimumBlockCount * 16 bytes of output; may
    ///                  alias AInPtr.
    ///     ARawCtrs     MinimumBlockCount * 16 bytes of pre-populated
    ///                  raw counter blocks (encrypted in place by the
    ///                  kernel to produce keystream).
    ///     APrevCipher  MinimumBlockCount * 16 bytes of the previous
    ///                  batch's ciphertext, folded into GHASH by this
    ///                  call. The mode seeds this from the prime batch
    ///                  and rotates it between iterations.
    ///     AGhashState  16-byte running GHASH accumulator, updated in
    ///                  place.
    ///   ABlockCount MUST equal MinimumBlockCount.
    /// </summary>
    procedure ProcessCtrGhashBatch(AInPtr, AOutPtr, ARawCtrs, APrevCipher,
      AGhashState: Pointer; ABlockCount: Int32);
  end;

  /// <summary>
  ///   Factory contract for GCM kernel providers. Registered with
  ///   TFusedKernelRegistry; the registry walks the per-mode factory
  ///   list (highest-priority first) and returns the first kernel
  ///   whose TryCreate succeeds. Factories self-probe (CPU features,
  ///   cipher identity, direction support) and wrap construction in
  ///   try/except; TryCreate MUST return False on failure rather than
  ///   propagating.
  /// </summary>
  IFusedGcmKernelFactory = interface
    ['{6F25C598-3089-40DA-8A81-9C898A5FCBE1}']

    /// <summary>Stable human-readable provider label (used for
    /// diagnostics, benchmark labelling, and test assertions).</summary>
    function ProviderName: String;

    /// <summary>Priority class controlling factory order inside the
    /// registry; see TFusedKernelPriority.</summary>
    function Priority: TFusedKernelPriority;

    /// <summary>
    ///   Attempt to construct a kernel bound to ACipher for the
    ///   requested ADirection, capturing AHPowers as its pre-computed
    ///   H-power table pointer. The mode owns the H-power storage; the
    ///   pointer MUST outlive the returned kernel.
    /// </summary>
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection; AHPowers: Pointer;
      out AKernel: IFusedGcmKernel): Boolean;
  end;

implementation

end.
