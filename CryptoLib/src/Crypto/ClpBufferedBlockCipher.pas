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

unit ClpBufferedBlockCipher;

{$I ..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCheck,
  ClpBufferedCipherBase,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIBulkBlockCipherMode,
  ClpBlockCipherBulkUtilities,
  ClpEcbBlockCipher,
  ClpIBufferedBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithRandom,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidLength = 'Can''t Have a Negative Input Length!';
  SInputNil = 'Input Cannot be Nil';
  SCipherModeNil = 'CipherMode Cannot be Nil';
  SCipherModeInvalidBlockSize = 'CipherMode Must Have a Positive Block Size';
  SOutputBufferTooSmall = 'Output Buffer Too Short';
  SDataNotBlockSizeAligned = 'Data not Block Size Aligned';
  SOutputBufferTooSmallForDoFinal = 'Output Buffer Too Short for DoFinal()';

type

  /// <summary>
  /// <para>
  /// A wrapper class that allows block ciphers to be used to process
  /// data in a piecemeal fashion. The BufferedBlockCipher outputs a
  /// block only when the buffer is full and more data is being added, or
  /// on a doFinal.
  /// </para>
  /// <para>
  /// Note: in the case where the underlying cipher is either a CFB
  /// cipher or an OFB one the last block may not be a multiple of the
  /// block size.
  /// </para>
  /// </summary>
  TBufferedBlockCipher = class(TBufferedCipherBase, IBufferedBlockCipher)

  strict protected
  var
    FBuf: TCryptoLibByteArray;
    FBufOff: Int32;
    FForEncryption: Boolean;
    FCipherMode: IBlockCipherMode;
    // Cached on Init when FCipherMode also implements IBulkBlockCipherMode.
    // Non-nil lets ProcessBytes collapse its aligned inner loop into a
    // single ProcessBlocks call, which the mode is free to forward to an
    // accelerated multi-block backend. Modes that only implement
    // IBlockCipherMode leave this nil and keep using the per-block loop.
    FBulkCipherMode: IBulkBlockCipherMode;

    /// <summary>
    /// constructor for subclasses
    /// </summary>
    constructor Create(); overload;

    /// <summary>
    /// Processes the aligned middle chunk of a ProcessBytes call, after
    /// the in-flight FBuf block has been emitted by the gap-fill step.
    /// Default implementation consumes <c>(ALen - 1) div BlockSize</c>
    /// blocks from AInput using the cached FBulkCipherMode fast path
    /// (single ProcessBlocks call) when available, or a per-block
    /// ProcessBlock loop otherwise. Subclasses override to add semantic
    /// restrictions such as "hold the last block back for padding /
    /// DoFinal" (CTS holds the last two). The hook must update AInOff
    /// and ALen to reflect exactly what it consumed, and return the
    /// number of output bytes written at AOutput[AOutOff..].
    /// </summary>
    function ProcessBytesBulkMiddle(const AInput: TCryptoLibByteArray;
      var AInOff: Int32; var ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    /// <summary>
    /// Called from ProcessBytes after the tail bytes have been stored
    /// into FBuf whenever FBuf ends up completely full. Default flushes
    /// the single in-flight block with one ProcessBlock call and resets
    /// FBufOff to 0. Subclasses that MUST hold the tail back for
    /// finalisation (padded ciphers, CTS) override to a no-op so the
    /// final block(s) remain in FBuf until DoFinal.
    /// </summary>
    function AfterTailStored(const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; virtual;

  public
    constructor Create(const ACipher: IBlockCipher); overload;

    /// <summary>
    /// Create a buffered block cipher without padding.
    /// </summary>
    /// <param name="ACipherMode">
    /// the underlying block cipher mode this buffering object wraps.
    /// </param>
    constructor Create(const ACipherMode: IBlockCipherMode); overload;

    /// <summary>
    /// initialise the cipher.
    /// </summary>
    /// <param name="AForEncryption">
    /// forEncryption if true the cipher is initialised for encryption, if
    /// false for decryption.
    /// </param>
    /// <param name="AParameters">
    /// the key and other data required by the cipher.
    /// </param>
    /// <exception cref="EArgumentCryptoLibException">
    /// if the parameters argument is inappropriate.
    /// </exception>
    // Note: This doubles as the Init in the event that this cipher is being used as an IWrapper
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); override;

    /// <summary>
    /// return the blocksize for the underlying cipher.
    /// </summary>
    /// <returns>
    /// return the blocksize for the underlying cipher.
    /// </returns>
    function GetBlockSize(): Int32; override;

    /// <summary>
    /// return the size of the output buffer required for an update an input
    /// of len bytes.
    /// </summary>
    /// <param name="ALength">
    /// the length of the input.
    /// </param>
    /// <returns>
    /// return the space required to accommodate a call to update with length
    /// bytes of input.
    /// </returns>
    function GetUpdateOutputSize(ALength: Int32): Int32; override;

    /// <summary>
    /// return the size of the output buffer required for an update plus a
    /// doFinal with an input of length bytes.
    /// </summary>
    /// <param name="ALength">
    /// the length of the input.
    /// </param>
    /// <returns>
    /// the space required to accommodate a call to update and doFinal with
    /// length bytes of input.
    /// </returns>
    function GetOutputSize(ALength: Int32): Int32; override;

    /// <summary>
    /// process a single byte, producing an output block if necessary.
    /// </summary>
    /// <param name="AInput">
    /// the input byte.
    /// </param>
    /// <param name="AOutput">
    /// the space for any output that might be produced.
    /// </param>
    /// <param name="AOutOff">
    /// the offset from which the output will be copied.
    /// </param>
    /// <returns>
    /// the number of output bytes copied to output.
    /// </returns>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there isn't enough space in output.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the cipher isn't initialised.
    /// </exception>
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload; override;

    function ProcessByte(AInput: Byte): TCryptoLibByteArray; overload; override;

    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32): TCryptoLibByteArray; overload; override;

    /// <summary>
    /// process an array of bytes, producing output if necessary.
    /// </summary>
    /// <param name="AInput">
    /// the input byte array.
    /// </param>
    /// <param name="AInOff">
    /// the offset at which the input data starts.
    /// </param>
    /// <param name="ALength">
    /// the number of bytes to be copied out of the input array.
    /// </param>
    /// <param name="AOutput">
    /// the space for any output that might be produced.
    /// </param>
    /// <param name="AOutOff">
    /// the offset from which the output will be copied.
    /// </param>
    /// <returns>
    /// the number of output bytes copied to output.
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there isn't enough space in output.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the cipher isn't initialised.
    /// </exception>
    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    function DoFinal(): TCryptoLibByteArray; overload; override;
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32)
      : TCryptoLibByteArray; overload; override;

    /// <summary>
    /// Process the last block in the buffer.
    /// </summary>
    /// <param name="AOutput">
    /// the array the block currently being held is copied into.
    /// </param>
    /// <param name="AOutOff">
    /// the offset at which the copying starts.
    /// </param>
    /// <returns>
    /// the number of output bytes copied to output.
    /// </returns>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if there is insufficient space in output for the output, or the input
    /// is not block size aligned and should be.
    /// </exception>
    /// <exception cref="EInvalidOperationCryptoLibException">
    /// if the underlying cipher is not initialised.
    /// </exception>
    /// <exception cref="EInvalidCipherTextCryptoLibException">
    /// if padding is expected and not found.
    /// </exception>
    /// <exception cref="EDataLengthCryptoLibException">
    /// if the input is not block size aligned.
    /// </exception>
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
      overload; override;

    /// <summary>
    /// Reset the buffer and cipher. After resetting the object is in the
    /// same state as it was after the last init (if there was one).
    /// </summary>
    procedure Reset(); override;

    function GetAlgorithmName: String; override;
    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TBufferedBlockCipher }

constructor TBufferedBlockCipher.Create(const ACipher: IBlockCipher);
begin
  Create(TEcbBlockCipher.GetBlockCipherMode(ACipher));
end;

constructor TBufferedBlockCipher.Create(const ACipherMode: IBlockCipherMode);
var
  LBlockSize: Int32;
begin
  Inherited Create();
  if (ACipherMode = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SCipherModeNil);

  LBlockSize := ACipherMode.GetBlockSize();
  if (LBlockSize < 1) then
    raise EArgumentCryptoLibException.CreateRes(@SCipherModeInvalidBlockSize);

  FCipherMode := ACipherMode;
  System.SetLength(FBuf, LBlockSize);
  FBufOff := 0;
end;

constructor TBufferedBlockCipher.Create;
begin
  Inherited Create();
end;

function TBufferedBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  try
    if (FBufOff <> 0) then
    begin
      TCheck.DataLength(not FCipherMode.IsPartialBlockOkay,
        SDataNotBlockSizeAligned);
      TCheck.OutputLength(AOutput, AOutOff, FBufOff,
        SOutputBufferTooSmallForDoFinal);

      // NB: Can't copy directly, or we may write too much output
      FCipherMode.ProcessBlock(FBuf, 0, FBuf, 0);
      System.Move(FBuf[0], AOutput[AOutOff], FBufOff * System.SizeOf(Byte));
    end;

    Result := FBufOff;
    Exit;
  finally
    Reset();
  end;
end;

function TBufferedBlockCipher.DoFinal(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LLength, LPos: Int32;
  LOutBytes, LTmp: TCryptoLibByteArray;
begin
  if (AInput = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SInputNil);
  end;

  LLength := GetOutputSize(AInLen);

  LOutBytes := EmptyBuffer;

  if (LLength > 0) then
  begin
    System.SetLength(LOutBytes, LLength);

    if (AInLen > 0) then
    begin
      LPos := ProcessBytes(AInput, AInOff, AInLen, LOutBytes, 0);
    end
    else
    begin
      LPos := 0;
    end;

    LPos := LPos + DoFinal(LOutBytes, LPos);

    if (LPos < System.Length(LOutBytes)) then
    begin
      System.SetLength(LTmp, LPos);
      System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));
      LOutBytes := LTmp;
    end
  end
  else
  begin
    Reset();
  end;

  Result := LOutBytes;
end;

function TBufferedBlockCipher.DoFinal: TCryptoLibByteArray;
var
  LOutBytes, LTmp: TCryptoLibByteArray;
  LLength, LPos: Int32;
begin
  LOutBytes := EmptyBuffer;

  LLength := GetOutputSize(0);
  if (LLength > 0) then
  begin
    System.SetLength(LOutBytes, LLength);

    LPos := DoFinal(LOutBytes, 0);
    if (LPos < System.Length(LOutBytes)) then
    begin
      System.SetLength(LTmp, LPos);
      System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));
      LOutBytes := LTmp;
    end
  end
  else
  begin
    Reset();
  end;

  Result := LOutBytes;
end;

function TBufferedBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipherMode.AlgorithmName;
end;

function TBufferedBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipherMode.GetBlockSize();
end;

function TBufferedBlockCipher.GetOutputSize(ALength: Int32): Int32;
begin
  // Note: Can assume IsPartialBlockOkay is true for purposes of this calculation
  Result := ALength + FBufOff;
end;

function TBufferedBlockCipher.GetUpdateOutputSize(ALength: Int32): Int32;
var
  LTotal, LLeftOver: Int32;
begin
  LTotal := ALength + FBufOff;
  LLeftOver := LTotal mod System.Length(FBuf);
  Result := LTotal - LLeftOver;
end;

procedure TBufferedBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LPwr: IParametersWithRandom;
  LParameters: ICipherParameters;
begin
  FForEncryption := AForEncryption;
  LParameters := AParameters;

  if Supports(LParameters, IParametersWithRandom, LPwr) then
  begin
    LParameters := LPwr.Parameters;
  end;

  Reset();

  FCipherMode.Init(AForEncryption, LParameters);

  // Probe after the inner Init so modes that only decide their fast-path
  // wiring at Init time are observed in their post-Init state. The result
  // is held for the lifetime of this wrapper to keep ProcessBytes free of
  // per-call QueryInterface overhead.
  TBlockCipherBulkUtilities.TryResolveBulkCipherMode(FCipherMode,
    FBulkCipherMode);
end;

function TBufferedBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin

  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);

  if (FBufOff = System.Length(FBuf)) then
  begin
    if ((AOutOff + System.Length(FBuf)) > System.Length(AOutput)) then
    begin
      raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
    end;

    FBufOff := 0;
    Result := FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    Exit;
  end;

  Result := 0;
end;

function TBufferedBlockCipher.ProcessByte(AInput: Byte): TCryptoLibByteArray;
var
  LOutLength, LPos: Int32;
  LOutBytes, LTmp: TCryptoLibByteArray;
begin
  LOutLength := GetUpdateOutputSize(1);

  if LOutLength > 0 then
  begin
    System.SetLength(LOutBytes, LOutLength);
  end
  else
  begin
    LOutBytes := nil;
  end;

  LPos := ProcessByte(AInput, LOutBytes, 0);

  if ((LOutLength > 0) and (LPos < LOutLength)) then
  begin
    System.SetLength(LTmp, LPos);
    System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));

    LOutBytes := LTmp;
  end;

  Result := LOutBytes;
end;

function TBufferedBlockCipher.ProcessBytesBulkMiddle(
  const AInput: TCryptoLibByteArray; var AInOff: Int32; var ALen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBlockSize, LBulkBlocks, LBulkBytes: Int32;
begin
  Result := 0;
  LBlockSize := GetBlockSize();

  // Dispatch every full aligned block that would have been fed to
  // FCipherMode.ProcessBlock in the original per-block loop. The loop
  // ran while ALen > LBlockSize, which consumes exactly
  // floor((ALen - 1) / LBlockSize) blocks before the trailing bytes
  // accumulate into FBuf again.
  if (FBulkCipherMode <> nil) and (ALen > LBlockSize) then
  begin
    LBulkBlocks := (ALen - 1) div LBlockSize;
    LBulkBytes := LBulkBlocks * LBlockSize;
    Result := Result + FBulkCipherMode.ProcessBlocks(AInput, AInOff,
      LBulkBlocks, AOutput, AOutOff);
    ALen := ALen - LBulkBytes;
    AInOff := AInOff + LBulkBytes;
  end
  else
  begin
    while (ALen > LBlockSize) do
    begin
      Result := Result + FCipherMode.ProcessBlock(AInput, AInOff,
        AOutput, AOutOff + Result);
      ALen := ALen - LBlockSize;
      AInOff := AInOff + LBlockSize;
    end;
  end;
end;

function TBufferedBlockCipher.AfterTailStored(
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
  FBufOff := 0;
end;

function TBufferedBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LOutLength, LResultLen, LGapLen, LShiftBytes, LBlockSize: Int32;
begin
  if (ALength < 1) then
  begin
    if (ALength < 0) then
    begin
      raise EArgumentCryptoLibException.CreateRes(@SInvalidLength);
    end;
    Result := 0;
    Exit;
  end;

  LBlockSize := GetBlockSize();
  LOutLength := GetUpdateOutputSize(ALength);

  if (LOutLength > 0) then
  begin
    TCheck.OutputLength(AOutput, AOutOff, LOutLength, SOutputBufferTooSmall);
  end;

  LResultLen := 0;
  LGapLen := System.Length(FBuf) - FBufOff;
  if (ALength > LGapLen) then
  begin
    // Gap-fill: complete the in-flight FBuf block, emit it, and shift
    // any remaining buffered bytes (for multi-block FBuf subclasses such
    // as CTS) down so FBuf[0..LBlockSize-1] holds the next lookahead
    // block. For single-block FBuf (the TBuffered and TPadded default)
    // the shift is a no-op and FBufOff simply resets to 0.
    System.Move(AInput[AInOff], FBuf[FBufOff], LGapLen * System.SizeOf(Byte));
    LResultLen := LResultLen + FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    LShiftBytes := System.Length(FBuf) - LBlockSize;
    if (LShiftBytes > 0) then
      System.Move(FBuf[LBlockSize], FBuf[0], LShiftBytes * System.SizeOf(Byte));
    FBufOff := LShiftBytes;
    ALength := ALength - LGapLen;
    AInOff := AInOff + LGapLen;

    // Aligned middle: process every full block that the original
    // sequential code would have emitted before starting to accumulate
    // into FBuf again. Delegated to the virtual hook so CTS can plug in
    // its "stage first block through FBuf lookahead, bulk the rest,
    // refresh lookahead" semantics.
    LResultLen := LResultLen + ProcessBytesBulkMiddle(AInput, AInOff, ALength,
      AOutput, AOutOff + LResultLen);
  end;
  System.Move(AInput[AInOff], FBuf[FBufOff], ALength * System.SizeOf(Byte));
  FBufOff := FBufOff + ALength;
  if (FBufOff = System.Length(FBuf)) then
  begin
    // Let subclasses decide whether a full FBuf should flush (default
    // TBuffered) or be held back for DoFinal (TPadded, CTS).
    LResultLen := LResultLen + AfterTailStored(AOutput, AOutOff + LResultLen);
  end;
  Result := LResultLen;
end;

function TBufferedBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32): TCryptoLibByteArray;
var
  LOutLength, LPos: Int32;
  LOutBytes, LTmp: TCryptoLibByteArray;
begin
  if (AInput = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SInputNil);
  end;
  if (ALength < 1) then
  begin
    Result := nil;
    Exit;
  end;

  LOutLength := GetUpdateOutputSize(ALength);

  if LOutLength > 0 then
  begin
    System.SetLength(LOutBytes, LOutLength);
  end
  else
  begin
    LOutBytes := nil;
  end;

  LPos := ProcessBytes(AInput, AInOff, ALength, LOutBytes, 0);

  if ((LOutLength > 0) and (LPos < LOutLength)) then
  begin
    System.SetLength(LTmp, LPos);
    System.Move(LOutBytes[0], LTmp[0], LPos * System.SizeOf(Byte));

    LOutBytes := LTmp;
  end;

  Result := LOutBytes;

end;

procedure TBufferedBlockCipher.Reset;
begin
  TArrayUtilities.Fill<Byte>(FBuf, 0, System.Length(FBuf), Byte(0));
  FBufOff := 0;

  FCipherMode.Reset();
end;

end.
