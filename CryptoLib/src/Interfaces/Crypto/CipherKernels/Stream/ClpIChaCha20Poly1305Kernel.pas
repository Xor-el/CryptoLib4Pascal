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

unit ClpIChaCha20Poly1305Kernel;

{$I ..\..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIStreamCipher,
  ClpCipherKernelTypes,
  ClpICipherKernelFactory;

type
  /// <summary>
  ///   Mode-specific contract for an accelerated, fused ChaCha20-Poly1305 body
  ///   kernel. The kernel OWNS the whole Poly1305 lifecycle in its own internal
  ///   representation, so the mode stays agnostic to it: it derives the one-time
  ///   poly key, then drives
  ///   InitPoly -&gt; (UpdatePoly | ProcessStrides)* -&gt; FinishPoly. ProcessStrides is
  ///   the fused bulk path (generate keystream, XOR the payload, fold the
  ///   ciphertext into the accumulator in one pass); UpdatePoly is the poly-only
  ///   drain for AAD and the sub-stride tail. This is the stream-cipher analogue
  ///   of the block-cipher accelerated kernels (GCM = CTR + GHASH). The engine
  ///   key schedule and the Poly1305 r/s clamp live inside the implementation.
  /// </summary>
  IChaCha20Poly1305Kernel = interface
    ['{445983F0-6A17-4F2A-925B-90D46BCAC89A}']

    /// <summary>Stride granularity in bytes (512 = 8 x 64-byte ChaCha blocks).
    /// ProcessStrides consumes a positive multiple of this in one call.</summary>
    function StrideBytes: Int32;

    /// <summary>
    ///   Seed the internal Poly1305 state from the 32-byte one-time key (r || s)
    ///   at APolyKey: clamp r, precompute the fold multiplier, capture the pad,
    ///   and fully reset the accumulator (h := 0). Copies immediately; never
    ///   retains APolyKey. Called once per message, before any UpdatePoly /
    ///   ProcessStrides.
    /// </summary>
    procedure InitPoly(APolyKey: PByte);

    /// <summary>
    ///   Poly-only drain: fold ABlockCount whole 16-byte blocks at ASrc into the
    ///   running accumulator (each a full block, high 2^128 bit set). The mode
    ///   zero-pads AAD and the tail to a 16-byte boundary before calling, so no
    ///   partial-block handling is needed here. Used for AAD and the sub-stride
    ///   ciphertext tail. ASrc is fully consumed before return and never
    ///   retained, so the mode's in-place MAC-then-decrypt may overwrite it
    ///   immediately afterwards.
    /// </summary>
    procedure UpdatePoly(ASrc: PByte; ABlockCount: NativeInt);

    /// <summary>
    ///   Fused bulk path: process AStrideCount consecutive StrideBytes-sized
    ///   strides in one pass, interleaving ChaCha20 keystream XOR with Poly1305
    ///   accumulation, updating the kernel's internal poly state and advancing
    ///   the engine's block counter in place. The kernel binds to the engine
    ///   at construction (like the AES kernels bind to the key schedule), so no
    ///   engine state is passed here. AForEncrypt selects encrypt-then-MAC (fold
    ///   produced ciphertext) vs MAC-then-decrypt (fold input ciphertext before
    ///   XOR). AInPtr and AOutPtr are identical (in-place) or fully disjoint.
    ///   Any lagged MAC is drained before return - no caller pointer is retained.
    /// </summary>
    procedure ProcessStrides(AInPtr, AOutPtr: PByte;
      AStrideCount: NativeInt; AForEncrypt: Boolean);

    /// <summary>
    ///   Absorb the final length block (LE(AAadLen) || LE(ADataLen)), fully
    ///   reduce the accumulator mod 2^130-5, add the pad, and write the 16-byte
    ///   tag to ATagOut. Zeroizes the accumulator on exit (r/s persist until the
    ///   next InitPoly).
    /// </summary>
    procedure FinishPoly(AAadLen, ADataLen: UInt64; ATagOut: PByte);
  end;

  /// <summary>
  ///   Factory contract for accelerated ChaCha20-Poly1305 kernel providers. Registered
  ///   with TCipherKernelRegistry through the family-agnostic ICipherKernelFactory
  ///   base; the registry re-discovers it via Supports(). Factories self-probe
  ///   (CPU features, Supports(ACipher, IChaCha7539Engine)) and wrap construction
  ///   in try/except; TryCreate MUST return False on failure rather than
  ///   propagating.
  /// </summary>
  IChaCha20Poly1305KernelFactory = interface(ICipherKernelFactory)
    ['{A633B415-7A54-44D7-B983-18BBECC2B32F}']

    /// <summary>
    ///   Attempt to construct a cipher kernel bound to ACipher (a stream cipher;
    ///   the factory probes Supports(ACipher, IChaCha7539Engine) for the concrete
    ///   engine). ADirection is accepted for symmetry with the AEAD factories;
    ///   the kernel handles both directions via ProcessStrides' AForEncrypt.
    /// </summary>
    function TryCreate(const ACipher: IStreamCipher;
      ADirection: TCipherKernelDirection;
      out AKernel: IChaCha20Poly1305Kernel): Boolean;
  end;

implementation

end.
