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

unit ClpAesCtrPacketCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  ClpIPacketCipher,
  ClpIBlockPacketCipher,
  ClpIBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpSicBlockCipher,
  ClpAesUtilities,
  ClpArrayUtilities,
  ClpAbstractBlockPacketCipher,
  ClpCryptoLibTypes;

type
  /// <summary>
  /// One-shot / reusable AES-CTR packet cipher (see <see cref="IBlockPacketCipher"/>):
  /// a stream, so any length is accepted. Holds no cryptography of its own; not
  /// thread-safe (one instance per thread).
  /// </summary>
  TAesCtrPacketCipher = class sealed(TAbstractBlockPacketCipher)
  strict private
  var
    FTailIn, FTailOut: TCryptoLibByteArray;
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

{ TAesCtrPacketCipher }

constructor TAesCtrPacketCipher.Create();
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TAesCtrPacketCipher.Create(const AEngine: IBlockCipher);
begin
  inherited Create();
  FCipher := TSicBlockCipher.Create(AEngine) as IBulkBlockCipherMode;
  System.SetLength(FTailIn, FCipher.GetBlockSize());
  System.SetLength(FTailOut, FCipher.GetBlockSize());
end;

class function TAesCtrPacketCipher.GetInstance(): IBlockPacketCipher;
begin
  Result := TAesCtrPacketCipher.Create() as IBlockPacketCipher;
end;

function TAesCtrPacketCipher.GetOutputSize(AForEncryption: Boolean;
  AInLen: Int32): Int32;
begin
  Result := AInLen;
end;

function TAesCtrPacketCipher.ProcessPacket(AForEncryption: Boolean;
  const AKey, AIV, AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBlockSize, LBlocks, LTail, LTailOff: Int32;
begin
  InitMode(AForEncryption, AKey, AIV);

  LBlockSize := FCipher.GetBlockSize();
  LBlocks := AInLen div LBlockSize;
  LTail := AInLen mod LBlockSize;

  if LBlocks > 0 then
    FCipher.ProcessBlocks(AInput, AInOff, LBlocks, AOutput, AOutOff);

  if LTail > 0 then
  begin
    LTailOff := LBlocks * LBlockSize;
    TArrayUtilities.Fill(FTailIn, 0, LBlockSize, Byte(0));
    System.Move(AInput[AInOff + LTailOff], FTailIn[0], LTail);
    FCipher.ProcessBlock(FTailIn, 0, FTailOut, 0);
    System.Move(FTailOut[0], AOutput[AOutOff + LTailOff], LTail);
  end;

  Result := AInLen;
end;

end.
