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

unit ClpIGcmBlockCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadBlockCipher,
  ClpCryptoLibTypes;

type
  /// <summary>GCM (<see cref="IAeadBlockCipher"/>): AEAD over a 128-bit <see cref="IBlockCipher"/> (typically AES).</summary>
  IGcmBlockCipher = interface(IAeadBlockCipher)
    ['{EFA22310-0A01-49B5-BCDE-9AFBF996F85C}']

    /// <summary>
    /// One-shot seal/open of a whole message after <c>InitPacket</c>/<c>Init</c>:
    /// encrypt writes ciphertext then the tag; decrypt verifies the trailing tag
    /// and writes plaintext (wiping it and raising on a MAC mismatch). Single pass,
    /// no streaming partial-block buffering. Returns bytes written to <c>AOutput</c>.
    /// </summary>
    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
  end;

implementation

end.
