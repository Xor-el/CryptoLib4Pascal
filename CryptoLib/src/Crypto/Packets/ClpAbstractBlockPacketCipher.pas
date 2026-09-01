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

unit ClpAbstractBlockPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpAbstractPacketCipher,
  ClpIBlockPacketCipher,
  ClpIBulkBlockCipherMode,
  ClpIRawInitBlockCipherMode,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpICipherParameters,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidBlockPacketParameters =
    'block packet cipher requires an IV over a key';
  SKeyMustBeSpecified = 'key must be specified on the first call';

type
  /// <summary>
  /// Base for the block-mode packet ciphers (see <see cref="IBlockPacketCipher"/>).
  /// Drives a single reused CBC/CTR mode: the AES key schedule is cached inside the
  /// engine by its raw-key same-key gate, and the mode re-inits per message from
  /// the raw key + IV byte spans (no per-message parameter objects). The concrete facades
  /// supply the mode and the per-mode seal/open (whole-block for CBC, stream for
  /// CTR). They add no cryptography of their own. Not thread-safe: one instance per
  /// thread.
  /// </summary>
  TAbstractBlockPacketCipher = class abstract(TAbstractPacketCipher,
    IBlockPacketCipher)
  strict protected
  var
    FCipher: IBulkBlockCipherMode;
    // True once the mode has been keyed at least once, so a nil-key call (reuse)
    // before any key was supplied is rejected. No key bytes are cached here -
    // key identity lives in the engine's raw-key gate.
    FKeyed: Boolean;
    // Zero-alloc raw-IV re-init view of FCipher (nil if the mode does not
    // implement it); probed once. Lets InitMode skip the per-message
    // TParametersWithIV wrapper.
    FRawMode: IRawInitBlockCipherMode;
    FRawModeProbed: Boolean;

    // Cache the key parameter across same-key calls (nil key = reuse previous);
    // then init the mode with the per-message IV. The engine's own same-key gate
    // skips the key schedule rebuild.
    procedure InitMode(AForEncryption: Boolean;
      const AKey, AIV: TCryptoLibByteArray);
  public
    function GetOutputSize(AForEncryption: Boolean; AInLen: Int32)
      : Int32; virtual; abstract;

    function ProcessPacket(AForEncryption: Boolean;
      const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
      AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, AIV, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; virtual; abstract;
  end;

implementation

{ TAbstractBlockPacketCipher }

procedure TAbstractBlockPacketCipher.InitMode(AForEncryption: Boolean;
  const AKey, AIV: TCryptoLibByteArray);
begin
  if AKey <> nil then
    FKeyed := True
  else if not FKeyed then
    raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);

  if not FRawModeProbed then
  begin
    if not Supports(FCipher, IRawInitBlockCipherMode, FRawMode) then
      FRawMode := nil;
    FRawModeProbed := True;
  end;

  // Zero-alloc path: hand the raw key (nil = reuse) and the raw IV straight to
  // the mode - no per-message TParametersWithIV, no TKeyParameter. The engine's
  // raw-key compare-only gate reuses the schedule; a key or direction change
  // rebuilds it.
  if FRawMode <> nil then
    FRawMode.InitRaw(AForEncryption, AKey, AIV)
  else if AKey <> nil then
    FCipher.Init(AForEncryption, TParametersWithIV.Create(
      TKeyParameter.Create(AKey) as IKeyParameter, AIV) as ICipherParameters)
  else
    FCipher.Init(AForEncryption, TParametersWithIV.Create(nil, AIV)
      as ICipherParameters);
end;

function TAbstractBlockPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AParameters: ICipherParameters; const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LWithIV: IParametersWithIV;
  LKey: IKeyParameter;
begin
  if (not Supports(AParameters, IParametersWithIV, LWithIV)) or
    (not Supports(LWithIV.GetParameters(), IKeyParameter, LKey)) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidBlockPacketParameters);

  Result := ProcessPacket(AForEncryption, LKey.GetKey(), LWithIV.GetIV(), AInput,
    AInOff, AInLen, AOutput, AOutOff);
end;

end.
