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

unit ClpIAeadPacketCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot, reusable AEAD packet cipher. Adds the AEAD-shaped entry points to
  /// <see cref="IPacketCipher"/>: the tag-aware output-size arithmetic and an
  /// allocation-free raw-span seal/open taking key, nonce and AAD directly. Not
  /// thread-safe: use one instance per thread.
  /// </summary>
  IAeadPacketCipher = interface(IPacketCipher)
    ['{19402E21-515F-449F-B5C5-43E20F0C8195}']

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
  end;

implementation

end.
