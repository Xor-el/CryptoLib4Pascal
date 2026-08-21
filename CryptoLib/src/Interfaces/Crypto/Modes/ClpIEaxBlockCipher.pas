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

unit ClpIEaxBlockCipher;

{$I ..\..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadBlockCipher,
  ClpCryptoLibTypes;

type
  IEaxBlockCipher = interface(IAeadBlockCipher)
    ['{016F12A1-1E61-4A3A-AD87-B763CD63F694}']

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
