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
  ClpIBulkBlockCipherMode,
  ClpIEcbBlockCipher,
  ClpICipherParameters,
  ClpIAesEngineX86,
  ClpAesEngineX86,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type
  TEcbBlockCipher = class(TInterfacedObject, IEcbBlockCipher,
    IBlockCipherMode, IBlockCipher, IBulkBlockCipherMode)

  strict private
  var
    FCipher: IBlockCipher;
{$IFDEF CRYPTOLIB_X86_SIMD}
    // Cached once per Init; non-nil only when the underlying block cipher is
    // the AES-NI engine. Lets the bulk path skip per-call Supports() and
    // hit ProcessEightBlocks / ProcessFourBlocks directly. ECB has no chain
    // state, so the fast path is simply: batch-transform the input slice.
    FAesEngineX86: TAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}

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
    /// accelerated multi-block path, the slice is handed to it directly;
    /// otherwise the implementation loops ProcessBlock. Output is
    /// byte-identical to ABlockCount sequential ProcessBlock calls.
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
{$IFDEF CRYPTOLIB_X86_SIMD}
  FAesEngineX86 := nil;
{$ENDIF CRYPTOLIB_X86_SIMD}
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
{$IFDEF CRYPTOLIB_X86_SIMD}
var
  LAesEngineX86: IAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}
begin
  FCipher.Init(AForEncryption, AParameters);

{$IFDEF CRYPTOLIB_X86_SIMD}
  // Re-probe every Init: a user can re-key the same TEcbBlockCipher with a
  // different underlying cipher reference (rare, but well within the
  // public contract).
  FAesEngineX86 := nil;
  if Supports(FCipher, IAesEngineX86, LAesEngineX86) then
    FAesEngineX86 := LAesEngineX86 as TAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}
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

{$IFDEF CRYPTOLIB_X86_SIMD}
  // AES-NI fast path: 8-block then 4-block batches. FAesEngineX86 is
  // only assigned for TAesEngineX86 (implicit 16-byte block), so no
  // separate block-size guard is needed. The engine's PByte overloads
  // handle in-place / disjoint / overlapping inputs internally, so we
  // just forward raw pointers into the caller-owned buffers.
  if FAesEngineX86 <> nil then
  begin
    while ABlockCount >= 8 do
    begin
      FAesEngineX86.ProcessEightBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff]);
      System.Inc(AInOff, 128);
      System.Inc(AOutOff, 128);
      System.Dec(ABlockCount, 8);
    end;
    if ABlockCount >= 4 then
    begin
      FAesEngineX86.ProcessFourBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff]);
      System.Inc(AInOff, 64);
      System.Inc(AOutOff, 64);
      System.Dec(ABlockCount, 4);
    end;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}

  // Tail / fallback: any blocks not consumed by the fast path above
  // (residue < 4 blocks, or the whole batch whenever no accelerated
  // multi-block path is wired up).
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
