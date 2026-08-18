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

unit ClpChaCha20Poly1305PacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadPacketCipher,
  ClpIAeadCipher,
  ClpChaCha20Poly1305,
  ClpAbstractAeadPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot / reusable ChaCha20-Poly1305 packet cipher (see
  /// <see cref="IAeadPacketCipher"/>): a per-message seal/open over a single reused
  /// <c>TChaCha20Poly1305</c>. Holds no cryptography of its own; not thread-safe
  /// (one instance per thread).
  /// </summary>
  TChaCha20Poly1305PacketCipher = class sealed(TAbstractAeadPacketCipher)
  public
    constructor Create();

    class function GetInstance(): IAeadPacketCipher; static;
  end;

implementation

{ TChaCha20Poly1305PacketCipher }

constructor TChaCha20Poly1305PacketCipher.Create();
begin
  inherited Create();
  FCipher := TChaCha20Poly1305.Create() as IAeadCipher;
end;

class function TChaCha20Poly1305PacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TChaCha20Poly1305PacketCipher.Create() as IAeadPacketCipher;
end;

end.
