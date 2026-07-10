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

unit ClpIAcceleratedChaCha20Poly1305Kernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCipher,
  ClpAcceleratedKernelTypes,
  ClpIAcceleratedKernelFactory;

type
  /// <summary>
  ///   Mode-specific contract for an accelerated ChaCha20-Poly1305 body kernel: in a
  ///   single pass over a run of 512-byte (8 x 64-byte) strides, generate the
  ///   ChaCha20 keystream, XOR it into the payload, and fold the appropriate
  ///   bytes into the running Poly1305 accumulator - encrypt folds the produced
  ///   ciphertext (encrypt-then-MAC per stride), decrypt folds the input
  ///   ciphertext before the XOR (MAC-then-decrypt). This is the stream-cipher
  ///   analogue of the block-cipher accelerated kernels (GCM = CTR + GHASH); the
  ///   engine key schedule and Poly1305 r/s clamp live inside the implementation.
  /// </summary>
  IAcceleratedChaCha20Poly1305Kernel = interface
    ['{87051735-EA07-4800-A6D9-A8922BFDF6A2}']

    /// <summary>Stride granularity in bytes (512 = 8 x 64-byte ChaCha blocks).
    /// ProcessStrides consumes a positive multiple of this in one call.</summary>
    function StrideBytes: Int32;

    /// <summary>
    ///   Process AStrideCount consecutive StrideBytes-sized strides in one pass,
    ///   interleaving ChaCha20 keystream XOR with Poly1305 accumulation.
    ///   AChaChaState points at the engine block state (counter advanced in
    ///   place); APoly1305State points at the running Poly1305 accumulator
    ///   (updated in place). AForEncrypt selects encrypt-then-MAC vs
    ///   MAC-then-decrypt. AInPtr and AOutPtr are identical (in-place) or fully
    ///   disjoint.
    /// </summary>
    procedure ProcessStrides(AInPtr, AOutPtr, AChaChaState, APoly1305State: Pointer;
      AStrideCount: NativeInt; AForEncrypt: Boolean);
  end;

  /// <summary>
  ///   Factory contract for accelerated ChaCha20-Poly1305 kernel providers. Registered
  ///   with TAcceleratedKernelRegistry through the family-agnostic IAcceleratedKernelFactory
  ///   base; the registry re-discovers it via Supports(). Factories self-probe
  ///   (CPU features, Supports(ACipher, IChaCha7539Engine)) and wrap construction
  ///   in try/except; TryCreate MUST return False on failure rather than
  ///   propagating.
  /// </summary>
  IAcceleratedChaCha20Poly1305KernelFactory = interface(IAcceleratedKernelFactory)
    ['{A633B415-7A54-44D7-B983-18BBECC2B32F}']

    /// <summary>
    ///   Attempt to construct an accelerated kernel bound to ACipher (a stream cipher;
    ///   the factory probes Supports(ACipher, IChaCha7539Engine) for the concrete
    ///   engine). ADirection is accepted for symmetry with the AEAD factories;
    ///   the kernel handles both directions via ProcessStrides' AForEncrypt.
    /// </summary>
    function TryCreate(const ACipher: IStreamCipher;
      ADirection: TAcceleratedKernelDirection;
      out AKernel: IAcceleratedChaCha20Poly1305Kernel): Boolean;
  end;

implementation

end.
