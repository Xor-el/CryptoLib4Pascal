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
  ClpIBulkBlockCipherMode,
  ClpISicBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpIAesEngineX86,
  ClpAesEngineX86,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';
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
{$IFDEF CRYPTOLIB_X86_SIMD}
    // Cached once per Init; non-nil only when the underlying block cipher is
    // the AES-NI engine. Lets the bulk path skip per-call Supports() checks
    // and dispatch straight to ProcessEightBlocks / ProcessFourBlocks.
    FAesEngineX86: TAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_X86_SIMD}
    /// <summary>
    /// Snapshot FCounter into APlainCounters and advance FCounter by ABlockCount
    /// using the same byte-wise big-endian increment as ProcessBlock, so that
    /// the bulk path produces the exact same counter sequence as N sequential
    /// ProcessBlock calls would.
    /// </summary>
    procedure FillNextCounterBlocks(ABlockCount: Int32; APlainCounters: PByte);
    /// <summary>
    /// Scalar 128-byte (16 x UInt64) and 64-byte (8 x UInt64) XORs, factored
    /// out as static class procedures for the same reason as the identically
    /// shaped helpers in TGcmBlockCipher: the CALL boundary forces a fresh
    /// register allocation and dodges an FPC 3.2 i386 -O3 miscompile that
    /// aliases the loop counter with a caller-side temporary.
    /// </summary>
    class procedure Xor128BytesScalar(PDst, PSrcA, PSrcB: PByte); static;
    class procedure Xor64BytesScalar(PDst, PSrcA, PSrcB: PByte); static;
    /// <summary>
    /// Single eight-block bulk step: build eight pre-AES counter blocks,
    /// in-place AES-NI them (identical pointers), then XOR the resulting
    /// keystream with 128 bytes of input into output. Advances FCounter by 8.
    /// </summary>
    procedure ProcessEightBlocksBulk(const AInBuf: TCryptoLibByteArray;
      AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    /// <summary>
    /// Four-block counterpart of ProcessEightBlocksBulk (64 bytes per call).
    /// </summary>
    procedure ProcessFourBlocksBulk(const AInBuf: TCryptoLibByteArray;
      AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
{$ENDIF CRYPTOLIB_X86_SIMD}

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
    /// When the underlying engine exposes an accelerated multi-block path,
    /// batches of counter blocks are generated, run through that path in
    /// one shot, and XORed with the input in a single pass; otherwise the
    /// implementation simply loops ProcessBlock.
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
{$IFDEF CRYPTOLIB_X86_SIMD}
  FAesEngineX86 := nil;
{$ENDIF CRYPTOLIB_X86_SIMD}
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
{$IFDEF CRYPTOLIB_X86_SIMD}
  LAesEngineX86: IAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}
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

{$IFDEF CRYPTOLIB_X86_SIMD}
  // Probe once per Init. When the underlying cipher is TAesEngineX86 the
  // bulk path dispatches straight through FAesEngineX86, skipping the
  // per-call Supports() round-trip.
  FAesEngineX86 := nil;
  if Supports(FCipher, IAesEngineX86, LAesEngineX86) then
    FAesEngineX86 := LAesEngineX86 as TAesEngineX86;
{$ENDIF CRYPTOLIB_X86_SIMD}

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

{$IFDEF CRYPTOLIB_X86_SIMD}
  // Fast path: 128-byte (8-block) and 64-byte (4-block) AES-NI batches.
  // FAesEngineX86 is only assigned in Init when the underlying engine is
  // TAesEngineX86, which implies a 16-byte block, so no separate block-
  // size guard is needed. Anything else falls through to the loop below.
  if FAesEngineX86 <> nil then
  begin
    while ABlockCount >= 8 do
    begin
      ProcessEightBlocksBulk(AInBuf, AInOff, AOutBuf, AOutOff);
      System.Inc(AInOff, 128);
      System.Inc(AOutOff, 128);
      System.Dec(ABlockCount, 8);
    end;
    if ABlockCount >= 4 then
    begin
      ProcessFourBlocksBulk(AInBuf, AInOff, AOutBuf, AOutOff);
      System.Inc(AInOff, 64);
      System.Inc(AOutOff, 64);
      System.Dec(ABlockCount, 4);
    end;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}

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

{$IFDEF CRYPTOLIB_X86_SIMD}

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

class procedure TSicBlockCipher.Xor128BytesScalar(PDst, PSrcA, PSrcB: PByte);
var
  LI: Int32;
begin
  for LI := 0 to 15 do
    PUInt64(PDst + LI * 8)^ := PUInt64(PSrcA + LI * 8)^ xor PUInt64(PSrcB + LI * 8)^;
end;

class procedure TSicBlockCipher.Xor64BytesScalar(PDst, PSrcA, PSrcB: PByte);
var
  LI: Int32;
begin
  for LI := 0 to 7 do
    PUInt64(PDst + LI * 8)^ := PUInt64(PSrcA + LI * 8)^ xor PUInt64(PSrcB + LI * 8)^;
end;

procedure TSicBlockCipher.ProcessEightBlocksBulk(
  const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LKs: array [0 .. 127] of Byte;
begin
  FillNextCounterBlocks(8, @LKs[0]);
  // In-place AES-NI transforms LKs into the keystream for these 8 counters.
  FAesEngineX86.ProcessEightBlocks(@LKs[0], @LKs[0]);
  Xor128BytesScalar(@AOutBuf[AOutOff], @AInBuf[AInOff], @LKs[0]);
end;

procedure TSicBlockCipher.ProcessFourBlocksBulk(
  const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LKs: array [0 .. 63] of Byte;
begin
  FillNextCounterBlocks(4, @LKs[0]);
  FAesEngineX86.ProcessFourBlocks(@LKs[0], @LKs[0]);
  Xor64BytesScalar(@AOutBuf[AOutOff], @AInBuf[AInOff], @LKs[0]);
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

end.
