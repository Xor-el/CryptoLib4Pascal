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
  ClpIChaCha20Poly1305,
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
  strict private
    FChaCha: IChaCha20Poly1305;
  public
    constructor Create();

    class function GetInstance(): IAeadPacketCipher; static;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload; override;
  end;

implementation

{ TChaCha20Poly1305PacketCipher }

constructor TChaCha20Poly1305PacketCipher.Create();
begin
  inherited Create();
  FChaCha := TChaCha20Poly1305.Create() as IChaCha20Poly1305;
  FCipher := FChaCha; // FChaCha is the typed one-shot view of the base FCipher
end;

class function TChaCha20Poly1305PacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TChaCha20Poly1305PacketCipher.Create() as IAeadPacketCipher;
end;

function TChaCha20Poly1305PacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32): Int32;
begin
  FChaCha.InitPacket(AForEncryption, AKey, ANonce, AAad, AMacSizeBits);
  Result := FChaCha.ProcessPacket(AInput, AInOff, AInLen, AOutput, AOutOff);
end;

end.
