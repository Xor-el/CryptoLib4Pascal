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

unit ClpIFusedCtrKernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockCipher,
  ClpCryptoLibTypes,
  ClpFusedKernelTypes;

type
  /// <summary>
  ///   Mode-specific contract for a fused counter (CTR / SIC) body kernel:
  ///   generate AES-CTR keystream and XOR it into the payload in a single pass,
  ///   advancing the counter. It is the non-authenticated, MAC-free member of
  ///   the fused-kernel family - the shared core the AEAD kernels are built on
  ///   (GCM = CTR + GHASH, CCM = CTR + CBC-MAC, EAX = CTR + OMAC). All cipher
  ///   state (the key schedule) lives inside the implementation; the mode sees
  ///   only this interface.
  /// </summary>
  IFusedCtrKernel = interface
    ['{2A9F4C71-6E38-4B0D-9C57-1F3B8E26D4A5}']

    /// <summary>The batch granularity: ProcessCtrBlocks requires ABlockCount to
    /// be a positive multiple of this (the kernel processes the whole run in
    /// one call, looping internally).</summary>
    function BatchBlockCount: Int32;

    /// <summary>
    ///   Encrypt-and-XOR ABlockCount consecutive counter blocks in one pass:
    ///   for each block i, AOutPtr[i] := AInPtr[i] xor E_K(ACounter + i), then
    ///   advance ACounter. ACounter is a 16-byte big-endian value incremented
    ///   by one per block with carry across all 16 bytes (NIST SP 800-38A CTR,
    ///   matching TSicBlockCipher's per-block increment), updated in place.
    ///   ABlockCount MUST be a positive multiple of BatchBlockCount. AInPtr and
    ///   AOutPtr are identical (in-place) or fully disjoint.
    /// </summary>
    procedure ProcessCtrBlocks(AInPtr, AOutPtr, ACounter: Pointer;
      ABlockCount: NativeInt);
  end;

  /// <summary>
  ///   Factory contract for CTR kernel providers. Registered with
  ///   TFusedKernelRegistry; the registry walks the per-mode factory list
  ///   (highest-priority first) and returns the first kernel whose TryCreate
  ///   succeeds. Factories self-probe (CPU features, cipher identity) and wrap
  ///   construction in try/except; TryCreate MUST return False on failure
  ///   rather than propagating.
  /// </summary>
  IFusedCtrKernelFactory = interface
    ['{7D1E6B02-4A9C-4F58-8B3D-2C57F1E96A4D}']

    /// <summary>Stable human-readable provider label (diagnostics / tests).</summary>
    function ProviderName: String;

    /// <summary>Priority class controlling factory order inside the registry;
    /// see TFusedKernelPriority.</summary>
    function Priority: TFusedKernelPriority;

    /// <summary>
    ///   Attempt to construct a CTR kernel bound to ACipher. ADirection is
    ///   accepted for signature symmetry with the AEAD factories but ignored:
    ///   CTR keystream is direction-independent (both encrypt and decrypt XOR
    ///   the same E_K(counter) stream).
    /// </summary>
    function TryCreate(const ACipher: IBlockCipher;
      ADirection: TFusedModeDirection;
      out AKernel: IFusedCtrKernel): Boolean;
  end;

implementation

end.
