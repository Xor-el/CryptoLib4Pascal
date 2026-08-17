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

unit ClpAbstractPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIPacketCipher,
  ClpIAeadParameters,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidPacketParameters = 'packet cipher requires AEAD parameters';

type
  /// <summary>
  /// Common base for the AEAD packet ciphers (see <see cref="IPacketCipher"/>).
  /// Provides the shared output-size arithmetic and the parameter-object entry
  /// point (which unpacks the AEAD parameters and delegates to the raw span
  /// overload). The raw <c>ProcessPacket</c> is the single customization point:
  /// GCM/ChaCha override it with a zero-allocation path over the mode's raw
  /// <c>InitPacket</c>, while <see cref="TAbstractAeadPacketCipher"/> provides a
  /// general default that drives any mode's ordinary <c>Init</c>.
  /// </summary>
  TAbstractPacketCipher = class abstract(TInterfacedObject, IPacketCipher)
  public
    function GetOutputSize(AForEncryption: Boolean;
      AInLen, AMacSizeBits: Int32): Int32;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff, AMacSizeBits: Int32)
      : Int32; overload; virtual; abstract;

    function ProcessPacket(AForEncryption: Boolean;
      const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload;
  end;

implementation

{ TAbstractPacketCipher }

function TAbstractPacketCipher.GetOutputSize(AForEncryption: Boolean;
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

function TAbstractPacketCipher.ProcessPacket(AForEncryption: Boolean;
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

end.
