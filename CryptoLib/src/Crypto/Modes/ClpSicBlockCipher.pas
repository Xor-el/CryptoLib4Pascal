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

unit ClpSicBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpBlockCipherBulkUtilities,
  ClpISicBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer Too Short';
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SInvalidParameterArgument = 'CTR/SIC Mode Requires ParametersWithIV';
  SInvalidTooLargeIVLength =
    'CTR/SIC mode requires IV no greater than: %u bytes';
  SInvalidTooSmallIVLength = 'CTR/SIC mode requires IV of at least: %u bytes';

type
  TSicBlockCipher = class(TInterfacedObject, ISicBlockCipher,
    IBlockCipherMode, IBlockCipher, IBulkBlockCipherMode)

  strict private
  var
    FIV, FCounter, FCounterOut: TCryptoLibByteArray;
    FBlockSize: Int32;
    FCipher: IBlockCipher;
    // Cached on Init; non-nil when the underlying engine implements the
    // generic multi-block capability (IBulkBlockCipher). The engine owns
    // the 8/4/1 batch ladder internally, so the mode here only ever asks
    // for "8 blocks at a time" and lets the residue go per-block. Any
    // bulk-capable engine plugs in unchanged by implementing the
    // interface -- the mode does not care which cipher is underneath.
    FBulkCipher: IBulkBlockCipher;

    /// <summary>
    /// Snapshot FCounter into APlainCounters and advance FCounter by ABlockCount
    /// using the same byte-wise big-endian increment as ProcessBlock, so that
    /// the bulk path produces the exact same counter sequence as N sequential
    /// ProcessBlock calls would.
    /// </summary>
    procedure FillNextCounterBlocks(ABlockCount: Int32; APlainCounters: PByte);
    /// <summary>
    /// Single eight-block bulk step: build eight pre-encrypt counter
    /// blocks, run them through the engine's IBulkBlockCipher in-place
    /// path to turn them into keystream, then XOR 128 bytes of keystream
    /// with input into output. Advances FCounter by 8 via
    /// FillNextCounterBlocks.
    /// </summary>
    procedure ProcessEightBlocksBulk(const AInBuf: TCryptoLibByteArray;
      AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);

  strict protected
    function GetAlgorithmName: String; virtual;
    function GetIsPartialBlockOkay: Boolean; virtual;
    function GetUnderlyingCipher(): IBlockCipher; inline;

  public
    constructor Create(const ACipher: IBlockCipher);
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;
    function GetBlockSize(): Int32; virtual;
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    /// <summary>
    /// IBulkBlockCipherMode: process ABlockCount consecutive FBlockSize-byte
    /// blocks. Output is byte-identical to ABlockCount sequential
    /// ProcessBlock calls, including the advance of the internal counter.
    /// When the underlying engine exposes IBulkBlockCipher, 8-block batches
    /// of counter blocks are run through it in one shot and XORed with the
    /// input in a single pass; 1..7 residue goes per-block. Without a bulk
    /// capability, the whole request loops ProcessBlock.
    /// </summary>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32; virtual;
    procedure Reset(); virtual;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
    property IsPartialBlockOkay: Boolean read GetIsPartialBlockOkay;
  end;

implementation

{ TSicBlockCipher }

constructor TSicBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := FCipher.GetBlockSize();

  System.SetLength(FCounter, FBlockSize);
  System.SetLength(FCounterOut, FBlockSize);
  System.SetLength(FIV, FBlockSize);
  FBulkCipher := nil;
end;

procedure TSicBlockCipher.Reset;
begin
  TArrayUtilities.Fill<Byte>(FCounter, 0, System.Length(FCounter), Byte(0));
  System.Move(FIV[0], FCounter[0], System.Length(FIV) * System.SizeOf(Byte));
end;

function TSicBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/SIC';
end;

function TSicBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

function TSicBlockCipher.GetIsPartialBlockOkay: Boolean;
begin
  Result := True;
end;

function TSicBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TSicBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParam: IParametersWithIV;
  LParameters: ICipherParameters;
  LMaxCounterSize: Int32;
begin
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithIV, LIvParam) then
  begin
    FIV := LIvParam.GetIV();

    if (FBlockSize < System.Length(FIV)) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidTooLargeIVLength,
        [FBlockSize]);

    LMaxCounterSize := Min(8, FBlockSize div 2);

    if ((FBlockSize - System.Length(FIV)) > LMaxCounterSize) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidTooSmallIVLength,
        [FBlockSize - LMaxCounterSize]);

    LParameters := LIvParam.Parameters;
  end
  else
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParameterArgument);

  if (LParameters <> nil) then
    FCipher.Init(True, LParameters);

  // Probe once per Init. When the underlying cipher implements the bulk
  // interface the batched path dispatches straight through FBulkCipher;
  // otherwise we stay on the per-block path.
  TBlockCipherBulkUtilities.TryResolveBulkCipher(FCipher, FBulkCipher);

  Reset();
end;

function TSicBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LJ: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff + FBlockSize) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  FCipher.ProcessBlock(FCounter, 0, FCounterOut, 0);

  for LI := 0 to System.Pred(System.Length(FCounterOut)) do
    AOutput[AOutOff + LI] := Byte(FCounterOut[LI] xor AInput[AInOff + LI]);

  LJ := System.Length(FCounter);
  System.Dec(LJ);
  System.Inc(FCounter[LJ]);
  while ((LJ >= 0) and (FCounter[LJ] = 0)) do
  begin
    System.Dec(LJ);
    System.Inc(FCounter[LJ]);
  end;

  Result := System.Length(FCounter);
end;

function TSicBlockCipher.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LTotalBytes: Int32;
begin
  if ABlockCount <= 0 then
  begin
    Result := 0;
    Exit;
  end;

  LTotalBytes := ABlockCount * FBlockSize;

  if ((AInOff < 0) or ((AInOff + LTotalBytes) > System.Length(AInBuf))) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);

  if ((AOutOff < 0) or ((AOutOff + LTotalBytes) > System.Length(AOutBuf))) then
    raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooShort);

  // Fast path: 128-byte (8-block) batches through the bulk engine.
  // FBulkCipher is only assigned in Init when the underlying cipher
  // implements IBulkBlockCipher. The ProcessEightBlocksBulk helper
  // hard-codes a 128-byte XOR/counter layout, so we additionally gate on
  // FBlockSize = 16 to stay correct if a future bulk engine advertises a
  // different block size. 1..7 block residue falls through to the per-
  // block path.
  if (FBulkCipher <> nil) and (FBlockSize = 16) then
  begin
    while ABlockCount >= 8 do
    begin
      ProcessEightBlocksBulk(AInBuf, AInOff, AOutBuf, AOutOff);
      System.Inc(AInOff, 128);
      System.Inc(AOutOff, 128);
      System.Dec(ABlockCount, 8);
    end;
  end;

  // Tail / scalar fallback: identical semantics to repeated ProcessBlock.
  while ABlockCount > 0 do
  begin
    ProcessBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    System.Inc(AInOff, FBlockSize);
    System.Inc(AOutOff, FBlockSize);
    System.Dec(ABlockCount);
  end;

  Result := LTotalBytes;
end;

procedure TSicBlockCipher.FillNextCounterBlocks(ABlockCount: Int32;
  APlainCounters: PByte);
var
  LI, LJ: Int32;
begin
  for LI := 0 to ABlockCount - 1 do
  begin
    System.Move(FCounter[0], APlainCounters[LI * FBlockSize], FBlockSize);

    LJ := System.Length(FCounter);
    System.Dec(LJ);
    System.Inc(FCounter[LJ]);
    while ((LJ >= 0) and (FCounter[LJ] = 0)) do
    begin
      System.Dec(LJ);
      System.Inc(FCounter[LJ]);
    end;
  end;
end;

procedure TSicBlockCipher.ProcessEightBlocksBulk(
  const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LKs: array [0 .. 127] of Byte;
begin
  FillNextCounterBlocks(8, @LKs[0]);
  // In-place bulk transform (identical pointers satisfy the
  // IBulkBlockCipher aliasing contract) turns LKs from raw counter
  // blocks into keystream.
  FBulkCipher.ProcessBlocks(@LKs[0], @LKs[0], 8);
  TBlockCipherBulkUtilities.Xor128Bytes(@AOutBuf[AOutOff], @AInBuf[AInOff],
    @LKs[0]);
end;

end.
