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

unit ClpIPacketCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpICipherParameters,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot, reusable AEAD context (the small-message hot path). Modelled on
  /// Bouncy Castle LTS's <c>PacketCipher</c>: a single call performs the whole
  /// seal/open (init + process + finalize) so it avoids the streaming API's
  /// per-message parameter-object churn and buffered-wrapper layering. Instances
  /// are reusable across messages under the same or different keys; a per-instance
  /// key cache means repeated same-key calls skip the key schedule and MAC
  /// subkey derivation.
  ///
  /// Two entry shapes: the parameter-object <c>ProcessPacket</c> (compatible with
  /// the LTS signature) and an additive raw-span overload that takes key, nonce
  /// and AAD directly for a truly allocation-free per-message path. Not
  /// thread-safe: use one instance per thread.
  /// </summary>
  IPacketCipher = interface(IInterface)
    ['{6C3E7F1A-2B4D-4E5F-9A0B-7C1D2E3F4A5B}']

    /// <summary>Exact output length for an <c>AInLen</c>-byte packet: on encrypt
    /// <c>AInLen + macSize</c>, on decrypt <c>AInLen - macSize</c> (>= 0). Pure
    /// arithmetic; <c>AMacSizeBits</c> is the tag size in bits.</summary>
    function GetOutputSize(AForEncryption: Boolean;
      AInLen, AMacSizeBits: Int32): Int32;

    /// <summary>
    /// Allocation-free per-message seal/open from raw spans. Encrypt writes
    /// ciphertext followed by the tag; decrypt verifies the trailing tag and
    /// writes plaintext (raising on tag mismatch). <c>AKey</c> may be nil to
    /// reuse the key from the previous call on this instance. <c>AAad</c> may be
    /// nil. Returns the number of output bytes written at <c>AOutOff</c>.
    /// </summary>
    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload;

    /// <summary>
    /// Parameter-object entry point (LTS-compatible shape). Extracts key, nonce,
    /// AAD and MAC size from <c>AParameters</c> (an AEAD parameters object) and
    /// delegates to the raw overload. Convenience / compatibility path; the raw
    /// overload is the zero-allocation one.
    /// </summary>
    function ProcessPacket(AForEncryption: Boolean;
      const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload;
  end;

implementation

end.
