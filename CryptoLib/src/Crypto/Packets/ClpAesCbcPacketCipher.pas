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

unit ClpAesCbcPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIBlockPacketCipher,
  ClpIBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpCbcBlockCipher,
  ClpAesUtilities,
  ClpAbstractBlockPacketCipher,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SPartialBlock = 'CBC packet length must be a whole number of blocks';

type
  /// <summary>
  /// One-shot / reusable AES-CBC packet cipher (see <see cref="IBlockPacketCipher"/>),
  /// no padding: the input must be a whole number of blocks. Holds no cryptography
  /// of its own; not thread-safe (one instance per thread).
  /// </summary>
  TAesCbcPacketCipher = class sealed(TAbstractBlockPacketCipher)
  public
    constructor Create(); overload;
    constructor Create(const AEngine: IBlockCipher); overload;
    class function GetInstance(): IBlockPacketCipher; static;

    function GetOutputSize(AForEncryption: Boolean; AInLen: Int32): Int32; override;

    function ProcessPacket(AForEncryption: Boolean;
      const AKey, AIV, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;
  end;

implementation

{ TAesCbcPacketCipher }

constructor TAesCbcPacketCipher.Create();
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TAesCbcPacketCipher.Create(const AEngine: IBlockCipher);
begin
  inherited Create();
  FCipher := TCbcBlockCipher.Create(AEngine) as IBulkBlockCipherMode;
end;

class function TAesCbcPacketCipher.GetInstance(): IBlockPacketCipher;
begin
  Result := TAesCbcPacketCipher.Create() as IBlockPacketCipher;
end;

function TAesCbcPacketCipher.GetOutputSize(AForEncryption: Boolean;
  AInLen: Int32): Int32;
begin
  if (AInLen mod FCipher.GetBlockSize()) <> 0 then
    raise EArgumentCryptoLibException.CreateRes(@SPartialBlock);
  Result := AInLen;
end;

function TAesCbcPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, AIV, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBlockSize: Int32;
begin
  LBlockSize := FCipher.GetBlockSize();
  if (AInLen mod LBlockSize) <> 0 then
    raise EArgumentCryptoLibException.CreateRes(@SPartialBlock);

  InitMode(AForEncryption, AKey, AIV);
  if AInLen > 0 then
    FCipher.ProcessBlocks(AInput, AInOff, AInLen div LBlockSize, AOutput, AOutOff);
  Result := AInLen;
end;

end.
