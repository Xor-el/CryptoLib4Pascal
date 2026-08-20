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

unit ClpAesOcbPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadPacketCipher,
  ClpIBlockCipher,
  ClpIOcbBlockCipher,
  ClpOcbBlockCipher,
  ClpAesUtilities,
  ClpAbstractAeadPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot / reusable AES-OCB packet cipher (see <see cref="IAeadPacketCipher"/>):
  /// a per-message seal/open over a single reused <c>TOcbBlockCipher</c>. Holds no
  /// cryptography of its own; not thread-safe (one instance per thread).
  /// </summary>
  TAesOcbPacketCipher = class sealed(TAbstractAeadPacketCipher)
  strict private
    FOcb: IOcbBlockCipher;
  public
    constructor Create(); overload;
    constructor Create(const AHashCipher, AMainCipher: IBlockCipher); overload;
    class function GetInstance(): IAeadPacketCipher; static;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload; override;
  end;

implementation

{ TAesOcbPacketCipher }

constructor TAesOcbPacketCipher.Create();
begin
  Create(TAesUtilities.CreateEngine(), TAesUtilities.CreateEngine());
end;

constructor TAesOcbPacketCipher.Create(const AHashCipher,
  AMainCipher: IBlockCipher);
begin
  inherited Create();
  FOcb := TOcbBlockCipher.Create(AHashCipher, AMainCipher) as IOcbBlockCipher;
  FCipher := FOcb; // FOcb is the typed one-shot view of the base FCipher
end;

class function TAesOcbPacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TAesOcbPacketCipher.Create() as IAeadPacketCipher;
end;

function TAesOcbPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32): Int32;
begin
  FOcb.InitPacket(AForEncryption, AKey, ANonce, AAad, AMacSizeBits);
  Result := FOcb.ProcessPacket(AInput, AInOff, AInLen, AOutput, AOutOff);
end;

end.
