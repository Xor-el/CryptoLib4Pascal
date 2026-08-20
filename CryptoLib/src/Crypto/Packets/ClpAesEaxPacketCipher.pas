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

unit ClpAesEaxPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadPacketCipher,
  ClpIBlockCipher,
  ClpIEaxBlockCipher,
  ClpEaxBlockCipher,
  ClpAesUtilities,
  ClpAbstractAeadPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot / reusable AES-EAX packet cipher (see <see cref="IAeadPacketCipher"/>):
  /// a per-message seal/open over a single reused <c>TEaxBlockCipher</c>. Holds no
  /// cryptography of its own; not thread-safe (one instance per thread).
  /// </summary>
  TAesEaxPacketCipher = class sealed(TAbstractAeadPacketCipher)
  strict private
    FEax: IEaxBlockCipher;
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

{ TAesEaxPacketCipher }

constructor TAesEaxPacketCipher.Create();
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TAesEaxPacketCipher.Create(const AEngine: IBlockCipher);
begin
  inherited Create();
  FEax := TEaxBlockCipher.Create(AEngine) as IEaxBlockCipher;
  FCipher := FEax; // FEax is the typed one-shot view of the base FCipher
end;

class function TAesEaxPacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TAesEaxPacketCipher.Create() as IAeadPacketCipher;
end;

function TAesEaxPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32): Int32;
begin
  FEax.InitPacket(AForEncryption, AKey, ANonce, AAad, AMacSizeBits);
  Result := FEax.ProcessPacket(AInput, AInOff, AInLen, AOutput, AOutOff);
end;

end.
