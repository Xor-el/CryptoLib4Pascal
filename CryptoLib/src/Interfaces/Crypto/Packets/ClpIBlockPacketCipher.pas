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

unit ClpIBlockPacketCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot, reusable block-mode packet cipher (no AAD, no tag) for CBC and
  /// CTR. Adds the IV-shaped entry points to <see cref="IPacketCipher"/>: an
  /// output-size query and a raw-span encrypt/decrypt taking key and IV directly.
  /// The whole message is present in a single call, so there is no buffered
  /// holdback; CTR handles any length, CBC requires whole blocks. Not thread-safe:
  /// use one instance per thread.
  /// </summary>
  IBlockPacketCipher = interface(IPacketCipher)
    ['{9D2A0AC2-1234-4F08-8CD9-77F3DC19AD4C}']

    /// <summary>Output length for an <c>AInLen</c>-byte packet. CTR is a stream
    /// (equal to <c>AInLen</c>); CBC equals <c>AInLen</c> but requires a whole
    /// number of blocks and raises otherwise.</summary>
    function GetOutputSize(AForEncryption: Boolean; AInLen: Int32): Int32;

    /// <summary>
    /// Per-message encrypt/decrypt from raw spans. <c>AKey</c> may be nil to reuse
    /// the key from the previous call on this instance; <c>AIV</c> is the
    /// per-message IV. Returns the number of output bytes written at
    /// <c>AOutOff</c>.
    /// </summary>
    function ProcessPacket(AForEncryption: Boolean;
      const AKey, AIV, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload;
  end;

implementation

end.
