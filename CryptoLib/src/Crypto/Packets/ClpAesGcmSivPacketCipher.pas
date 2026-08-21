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

unit ClpAesGcmSivPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIAeadPacketCipher,
  ClpIBlockCipher,
  ClpIAeadCipher,
  ClpIGcmMultiplier,
  ClpGcmSivBlockCipher,
  ClpAesUtilities,
  ClpAbstractAeadPacketCipher;

type
  /// <summary>
  /// One-shot / reusable AES-GCM-SIV packet cipher (see
  /// <see cref="IAeadPacketCipher"/>): a per-message seal/open over a single
  /// reused <c>TGcmSivBlockCipher</c>. Holds no cryptography of its own; not
  /// thread-safe (one instance per thread).
  /// </summary>
  TAesGcmSivPacketCipher = class sealed(TAbstractAeadPacketCipher)
  public
    constructor Create(); overload;
    constructor Create(const AEngine: IBlockCipher); overload;
    constructor Create(const AEngine: IBlockCipher;
      const AMultiplier: IGcmMultiplier); overload;

    class function GetInstance(): IAeadPacketCipher; static;
  end;

implementation

{ TAesGcmSivPacketCipher }

constructor TAesGcmSivPacketCipher.Create();
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TAesGcmSivPacketCipher.Create(const AEngine: IBlockCipher);
begin
  Create(AEngine, nil);
end;

constructor TAesGcmSivPacketCipher.Create(const AEngine: IBlockCipher;
  const AMultiplier: IGcmMultiplier);
begin
  inherited Create();
  FCipher := TGcmSivBlockCipher.Create(AEngine, AMultiplier) as IAeadCipher;
end;

class function TAesGcmSivPacketCipher.GetInstance(): IAeadPacketCipher;
begin
  Result := TAesGcmSivPacketCipher.Create() as IAeadPacketCipher;
end;

end.
