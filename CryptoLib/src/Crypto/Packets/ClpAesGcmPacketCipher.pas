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

unit ClpAesGcmPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadPacketCipher,
  ClpIBlockCipher,
  ClpIGcmBlockCipher,
  ClpIGcmMultiplier,
  ClpGcmBlockCipher,
  ClpAesUtilities,
  ClpAbstractAeadPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot / reusable AES-GCM packet cipher (see <see cref="IAeadPacketCipher"/>):
  /// a per-message seal/open over a single reused <c>TGcmBlockCipher</c>. Holds no
  /// cryptography of its own; not thread-safe (one instance per thread).
  /// </summary>
  TAesGcmPacketCipher = class sealed(TAbstractAeadPacketCipher)
  strict private
    FGcm: IGcmBlockCipher;
  public
    constructor Create(); overload;
    constructor Create(const AEngine: IBlockCipher); overload;
    constructor Create(const AEngine: IBlockCipher;
      const AMultiplier: IGcmMultiplier); overload;

    class function GetInstance(): IAeadPacketCipher; static;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload; override;
  end;

implementation

{ TAesGcmPacketCipher }

constructor TAesGcmPacketCipher.Create();
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TAesGcmPacketCipher.Create(const AEngine: IBlockCipher);
begin
  // nil multiplier lets TGcmBlockCipher pick the best one (CreateGcmMultiplier).
  Create(AEngine, nil);
end;

constructor TAesGcmPacketCipher.Create(const AEngine: IBlockCipher;
  const AMultiplier: IGcmMultiplier);
begin
  inherited Create();
  FGcm := TGcmBlockCipher.Create(AEngine, AMultiplier) as IGcmBlockCipher;
  FCipher := FGcm; // FGcm is the typed one-shot view of the base FCipher
end;

class function TAesGcmPacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TAesGcmPacketCipher.Create() as IAeadPacketCipher;
end;

function TAesGcmPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32): Int32;
begin
  FGcm.InitPacket(AForEncryption, AKey, ANonce, AAad, AMacSizeBits);
  Result := FGcm.ProcessPacket(AInput, AInOff, AInLen, AOutput, AOutOff);
end;

end.
