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

unit ClpIChaCha20Poly1305;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadCipher,
  ClpCryptoLibTypes;

type
  /// <summary>ChaCha20-Poly1305 AEAD (<c>IChaCha20Poly1305</c>): ChaCha20 stream cipher per RFC&nbsp;8439 layout with Poly1305 tag.</summary>
  IChaCha20Poly1305 = interface(IAeadCipher)
    ['{87EFAE50-A9BC-4969-BC65-F300F28ACDAD}']

    /// <summary>
    /// One-shot seal/open of a whole message after <c>InitPacket</c>/<c>Init</c>:
    /// encrypt writes ciphertext then the tag; decrypt verifies the trailing tag
    /// and writes plaintext (wiping it and raising on a MAC mismatch). Returns
    /// bytes written to <c>AOutput</c>.
    /// </summary>
    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
  end;

implementation

end.
