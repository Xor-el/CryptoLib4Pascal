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

unit ClpEcbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpIEcbBlockCipher,
  ClpICipherParameters,
  ClpBlockCipherBulkUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer Too Short';
  SOutputBufferTooShort = 'Output Buffer Too Short';

type
  TEcbBlockCipher = class(TInterfacedObject, IEcbBlockCipher,
    IBlockCipherMode, IBlockCipher, IBulkBlockCipherMode)

  strict private
  var
    FCipher: IBlockCipher;
    // Cached on Init. Non-nil when the underlying engine exposes the
    // IBulkBlockCipher capability (any bulk-capable block cipher lights
    // up automatically by implementing the interface; the mode does not
    // care which cipher is underneath). ECB has no chain state, so the
    // fast path is one delegated call that lets the engine pick its best
    // batch ladder internally.
    FBulkCipher: IBulkBlockCipher;

  strict protected
    function GetAlgorithmName: String; inline;
    function GetIsPartialBlockOkay: Boolean; inline;
    function GetUnderlyingCipher(): IBlockCipher; inline;

  public
    class function GetBlockCipherMode(const ABlockCipher: IBlockCipher)
      : IBlockCipherMode; static;

    constructor Create(const ACipher: IBlockCipher);

    function GetBlockSize(): Int32;

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters);

    function ProcessBlock(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32): Int32;

    /// <summary>
    /// IBulkBlockCipherMode: process ABlockCount consecutive blocks of
    /// GetBlockSize bytes. ECB has no chaining between blocks, so each
    /// block is independent: when the underlying engine exposes an
    /// accelerated multi-block path (IBulkBlockCipher), the whole slice
    /// is handed to it in one call; otherwise the implementation loops
    /// ProcessBlock. Output is byte-identical to ABlockCount sequential
    /// ProcessBlock calls.
    /// </summary>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32;

    procedure Reset();

    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
  end;

implementation

{ TEcbBlockCipher }

class function TEcbBlockCipher.GetBlockCipherMode(
  const ABlockCipher: IBlockCipher): IBlockCipherMode;
var
  LBlockCipherMode: IBlockCipherMode;
begin
  if Supports(ABlockCipher, IBlockCipherMode, LBlockCipherMode) then
    Result := LBlockCipherMode
  else
    Result := TEcbBlockCipher.Create(ABlockCipher);
end;

constructor TEcbBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  if ACipher = nil then
    raise EArgumentNilCryptoLibException.Create('ACipher');
  FCipher := ACipher;
  FBulkCipher := nil;
end;

function TEcbBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/ECB';
end;

function TEcbBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

function TEcbBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := False;
end;

function TEcbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TEcbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
begin
  FCipher.Init(AForEncryption, AParameters);

  // Re-probe every Init: a user can re-key the same TEcbBlockCipher with a
  // different underlying cipher reference (rare, but well within the
  // public contract).
  TBlockCipherBulkUtilities.TryResolveBulkCipher(FCipher, FBulkCipher);
end;

function TEcbBlockCipher.ProcessBlock(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := FCipher.ProcessBlock(AInBuf, AInOff, AOutBuf, AOutOff);
end;

function TEcbBlockCipher.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize, LTotalBytes: Int32;
begin
  if ABlockCount <= 0 then
  begin
    Result := 0;
    Exit;
  end;

  LBlockSize := FCipher.GetBlockSize();
  LTotalBytes := ABlockCount * LBlockSize;

  if ((AInOff < 0) or ((AInOff + LTotalBytes) > System.Length(AInBuf))) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff < 0) or ((AOutOff + LTotalBytes) > System.Length(AOutBuf))) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  // Fast path: engine-owned 8/4/1 ladder. One interface call per bulk
  // request, regardless of ABlockCount; the engine picks the best batch
  // shape for its architecture.
  if FBulkCipher <> nil then
  begin
    FBulkCipher.ProcessBlocks(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff);
    Result := LTotalBytes;
    Exit;
  end;

  // Fallback: no bulk capability wired up. Semantically byte-identical to
  // the fast path.
  while ABlockCount > 0 do
  begin
    FCipher.ProcessBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    System.Inc(AInOff, LBlockSize);
    System.Inc(AOutOff, LBlockSize);
    System.Dec(ABlockCount);
  end;

  Result := LTotalBytes;
end;

procedure TEcbBlockCipher.Reset;
begin
  // no-op
end;

end.
