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
  ClpIAeadCipher,
  ClpOcbBlockCipher,
  ClpAesUtilities,
  ClpAbstractAeadPacketCipher;

type
  /// <summary>
  /// One-shot / reusable AES-OCB packet cipher (see <see cref="IAeadPacketCipher"/>):
  /// a per-message seal/open over a single reused <c>TOcbBlockCipher</c>. Holds no
  /// cryptography of its own; not thread-safe (one instance per thread).
  /// </summary>
  TAesOcbPacketCipher = class sealed(TAbstractAeadPacketCipher)
  public
    constructor Create(); overload;
    constructor Create(const AHashCipher, AMainCipher: IBlockCipher); overload;
    class function GetInstance(): IAeadPacketCipher; static;
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
  FCipher := TOcbBlockCipher.Create(AHashCipher, AMainCipher) as IAeadCipher;
end;

class function TAesOcbPacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TAesOcbPacketCipher.Create() as IAeadPacketCipher;
end;

end.
