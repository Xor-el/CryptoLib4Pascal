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

unit ClpIGcmKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpCipherKernelTypes,
  ClpICipherKernelFactory;

type
  /// <summary>
  ///   Mode-specific contract for an accelerated GCM body kernel: produce
  ///   keystream for the current batch, XOR it into the payload, and
  ///   fold the previous batch's ciphertext into the running GHASH
  ///   accumulator. All cipher state (key schedule, H-power table,
  ///   static constants) lives inside the implementation; the mode
  ///   sees only this interface.
  /// </summary>
  IGcmKernel = interface
    ['{D4D7F5F0-3C56-44E0-8BDD-944AC05E4D2E}']

    /// <summary>Number of 16-byte blocks per batch consumed by
    /// ProcessCtrGhashBatches.</summary>
    function MinimumBlockCount: Int32;

    /// <summary>
    ///   Process ABatchCount consecutive 8-block batches in one call: generate
    ///   the GCM keystream (32-bit counter starting at ACounter32, J0 upper 96
    ///   bits from AJ0Template), XOR AInPtr into AOutPtr, and fold each batch's
    ///   ciphertext into the running GHASH state (AGhashState). APrevInit is the
    ///   ciphertext of the batch immediately before this run (the prime batch);
    ///   the pipeline GHASHes it first and lags by one, leaving the final batch
    ///   for the caller's drain. AForEncrypt selects whether the GHASHed
    ///   ciphertext is the output (encrypt) or the input (decrypt). Returns the
    ///   advanced 32-bit counter (ACounter32 + 8*ABatchCount).
    /// </summary>
    function ProcessCtrGhashBatches(AInPtr, AOutPtr, APrevInit, AGhashState,
      AJ0Template: Pointer; ACounter32: UInt32; ABatchCount: NativeInt;
      AForEncrypt: Boolean): UInt32;
  end;

  /// <summary>
  ///   Factory contract for GCM kernel providers. Registered with
  ///   TCipherKernelRegistry; the registry walks the per-mode factory
  ///   list (highest-priority first) and returns the first kernel
  ///   whose TryCreate succeeds. Factories self-probe (CPU features,
  ///   cipher identity, direction support) and wrap construction in
  ///   try/except; TryCreate MUST return False on failure rather than
  ///   propagating.
  /// </summary>
  IGcmKernelFactory = interface(ICipherKernelFactory)
    ['{6F25C598-3089-40DA-8A81-9C898A5FCBE1}']

    /// <summary>
    ///   Attempt to construct a kernel bound to ACipher for the
    ///   requested ADirection, capturing AHPowers as its pre-computed
    ///   H-power table pointer. The mode owns the H-power storage; the
    ///   pointer MUST outlive the returned kernel.
    /// </summary>
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TCipherKernelDirection; AHPowers: Pointer;
      out AKernel: IGcmKernel): Boolean;
  end;

implementation

end.
