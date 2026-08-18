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
  ClpIPacketCipher,
  ClpIBlockPacketCipher,
  ClpIBulkBlockCipherMode,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpICipherParameters,
  ClpArrayUtilities,
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
  /// engine by its same-key gate, and the key parameter is cached here so a
  /// same-key call only rebuilds the per-message IV wrapper. The concrete facades
  /// supply the mode and the per-mode seal/open (whole-block for CBC, stream for
  /// CTR). They add no cryptography of their own. Not thread-safe: one instance per
  /// thread.
  /// </summary>
  TAbstractBlockPacketCipher = class abstract(TAbstractPacketCipher,
    IBlockPacketCipher)
  strict protected
  var
    FCipher: IBulkBlockCipherMode;
    FKeyParam: IKeyParameter;
    FLastKey: TCryptoLibByteArray;

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
  begin
    if (FKeyParam = nil) or (System.Length(FLastKey) <> System.Length(AKey)) or
      (not TArrayUtilities.FixedTimeEquals(AKey, FLastKey)) then
    begin
      FKeyParam := TKeyParameter.Create(AKey) as IKeyParameter;
      FLastKey := System.Copy(AKey);
    end;
  end
  else if FKeyParam = nil then
    raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);

  FCipher.Init(AForEncryption, TParametersWithIV.Create(FKeyParam, AIV)
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
