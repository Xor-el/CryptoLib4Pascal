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
  ClpIAeadCipher,
  ClpEaxBlockCipher,
  ClpAesUtilities,
  ClpAbstractAeadPacketCipher;

type
  /// <summary>
  /// One-shot / reusable AES-EAX packet cipher (see <see cref="IAeadPacketCipher"/>):
  /// a per-message seal/open over a single reused <c>TEaxBlockCipher</c>. Holds no
  /// cryptography of its own; not thread-safe (one instance per thread).
  /// </summary>
  TAesEaxPacketCipher = class sealed(TAbstractAeadPacketCipher)
  public
    constructor Create(); overload;
    constructor Create(const AEngine: IBlockCipher); overload;
    class function GetInstance(): IAeadPacketCipher; static;
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
  FCipher := TEaxBlockCipher.Create(AEngine) as IAeadCipher;
end;

class function TAesEaxPacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TAesEaxPacketCipher.Create() as IAeadPacketCipher;
end;

end.
