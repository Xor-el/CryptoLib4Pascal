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

unit ClpAbstractAeadPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpAbstractPacketCipher,
  ClpIAeadCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// Base for the AEAD packet ciphers (see <see cref="IPacketCipher"/>). Drives a
  /// single reused AEAD mode through its <c>InitPacket</c> entry point, so a
  /// per-message seal/open pays only the irreducible nonce-dependent work - key
  /// identity is cached inside the mode by its own same-key gate, and a mode with
  /// a raw <c>InitPacket</c> override skips the parameter objects entirely. The
  /// concrete facades only construct the mode and assign <c>FCipher</c>; they add
  /// no cryptography of their own. Not thread-safe: one instance per thread.
  /// </summary>
  TAbstractAeadPacketCipher = class abstract(TAbstractPacketCipher)
  strict protected
  var
    FCipher: IAeadCipher;
  public
    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload; override;
  end;

implementation

{ TAbstractAeadPacketCipher }

function TAbstractAeadPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32): Int32;
var
  LLen: Int32;
begin
  FCipher.InitPacket(AForEncryption, AKey, ANonce, AAad, AMacSizeBits);
  if AInLen > 0 then
    LLen := FCipher.ProcessBytes(AInput, AInOff, AInLen, AOutput, AOutOff)
  else
    LLen := 0;
  Result := LLen + FCipher.DoFinal(AOutput, AOutOff + LLen);
end;

end.
