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

unit ClpAesCcmPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadPacketCipher,
  ClpIBlockCipher,
  ClpICcmBlockCipher,
  ClpCcmBlockCipher,
  ClpAesUtilities,
  ClpAbstractAeadPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot / reusable AES-CCM packet cipher (see <see cref="IAeadPacketCipher"/>):
  /// a per-message seal/open over a single reused <c>TCcmBlockCipher</c>. Holds no
  /// cryptography of its own; not thread-safe (one instance per thread).
  /// </summary>
  TAesCcmPacketCipher = class sealed(TAbstractAeadPacketCipher)
  strict private
    FCcm: ICcmBlockCipher;
  public
    constructor Create(); overload;
    constructor Create(const AEngine: IBlockCipher); overload;
    class function GetInstance(): IAeadPacketCipher; static;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload; override;
  end;

implementation

{ TAesCcmPacketCipher }

constructor TAesCcmPacketCipher.Create();
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TAesCcmPacketCipher.Create(const AEngine: IBlockCipher);
begin
  inherited Create();
  FCcm := TCcmBlockCipher.Create(AEngine) as ICcmBlockCipher;
  FCipher := FCcm; // FCcm is the typed one-shot view of the base FCipher
end;

class function TAesCcmPacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TAesCcmPacketCipher.Create() as IAeadPacketCipher;
end;

function TAesCcmPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32): Int32;
begin
  FCcm.InitPacket(AForEncryption, AKey, ANonce, AAad, AMacSizeBits);
  Result := FCcm.ProcessPacket(AInput, AInOff, AInLen, AOutput, AOutOff);
end;

end.
