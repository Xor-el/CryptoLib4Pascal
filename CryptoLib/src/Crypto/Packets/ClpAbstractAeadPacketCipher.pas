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
  SysUtils,
  ClpAbstractPacketCipher,
  ClpIAeadPacketCipher,
  ClpIAeadCipher,
  ClpIAeadParameters,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidPacketParameters = 'packet cipher requires AEAD parameters';

type
  /// <summary>
  /// Base for the AEAD packet ciphers (see <see cref="IAeadPacketCipher"/>). Drives
  /// a single reused AEAD mode through its <c>InitPacket</c> entry point, so a
  /// per-message seal/open pays only the irreducible nonce-dependent work - key
  /// identity is cached inside the mode by its own same-key gate, and a mode with
  /// a raw <c>InitPacket</c> override skips the parameter objects entirely. Every
  /// AEAD facade constructs its concrete mode, assigns <c>FCipher</c>, and overrides
  /// <c>ProcessPacket</c> to call the mode's own one-shot <c>ProcessPacket</c> (which
  /// also gives the no-unverified-plaintext-on-failure contract); the drive below is
  /// the reference fallback for any facade that does not. They add no cryptography of
  /// their own. Not thread-safe: one instance per thread.
  /// </summary>
  TAbstractAeadPacketCipher = class abstract(TAbstractPacketCipher,
    IAeadPacketCipher)
  strict protected
  var
    FCipher: IAeadCipher;
  public
    function GetOutputSize(AForEncryption: Boolean;
      AInLen, AMacSizeBits: Int32): Int32;

    function ProcessPacket(AForEncryption: Boolean;
      const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload; virtual;
  end;

implementation

{ TAbstractAeadPacketCipher }

function TAbstractAeadPacketCipher.GetOutputSize(AForEncryption: Boolean;
  AInLen, AMacSizeBits: Int32): Int32;
var
  LMacSize: Int32;
begin
  LMacSize := AMacSizeBits shr 3;
  if AForEncryption then
    Result := AInLen + LMacSize
  else
    Result := AInLen - LMacSize;
  if Result < 0 then
    Result := 0;
end;

function TAbstractAeadPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LAead: IAeadParameters;
begin
  if not Supports(AParameters, IAeadParameters, LAead) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidPacketParameters);

  Result := ProcessPacket(AForEncryption, LAead.Key.GetKey(), LAead.GetNonce(),
    LAead.GetAssociatedText(), AInput, AInOff, AInLen, AOutput, AOutOff,
    LAead.MacSize);
end;

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
