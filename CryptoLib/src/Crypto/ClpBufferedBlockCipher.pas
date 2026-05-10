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
  ClpParameterUtilities,
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
  /// A wrapper class that allows block ciphers to be used to process data in a piecemeal fashion.
  /// </summary>
  /// <remarks>
  /// <para>
  /// The instance outputs a block only when the buffer is full and more data is being added, or on
  /// <c>DoFinal</c>.
  /// </para>
  /// <para>
  /// In the case where the underlying cipher is a stream-oriented mode (like CFB or OFB), the last
  /// block may not be a multiple of the block size.
  /// </para>
  /// </remarks>
  TBufferedBlockCipher = class(TBufferedCipherBase, IBufferedBlockCipher)

  strict protected
  var
    /// <summary>Buffer holding input until a full block is available or <c>DoFinal</c> flushes it.</summary>
    FBuf: TCryptoLibByteArray;
    /// <summary>Number of valid bytes currently in <see cref="FBuf"/>.</summary>
    FBufOff: Int32;
    /// <summary>True if initialised for encryption; False for decryption.</summary>
    FForEncryption: Boolean;
    /// <summary>Underlying block cipher mode (<see cref="IBlockCipherMode"/>) being buffered.</summary>
    FCipherMode: IBlockCipherMode;
    // Cached on Init when FCipherMode also implements IBulkBlockCipherMode.
    // Non-nil lets ProcessBytes collapse its aligned inner loop into a
    // single ProcessBlocks call, which the mode is free to forward to an
    // accelerated multi-block backend. Modes that only implement
    // IBlockCipherMode leave this nil and keep using the per-block loop.
    /// <summary>Optional fast path when <see cref="FCipherMode"/> also implements <see cref="IBulkBlockCipherMode"/>.</summary>
    FBulkCipherMode: IBulkBlockCipherMode;

    /// <summary>
    /// Constructor for subclasses.
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
    /// <summary>
    /// Basic constructor: wraps <paramref name="ACipher"/> as ECB mode internally.
    /// </summary>
    /// <param name="ACipher">The underlying <see cref="IBlockCipher"/>.</param>
    constructor Create(const ACipher: IBlockCipher); overload;

    /// <summary>
    /// Create a buffered block cipher without padding.
    /// </summary>
    /// <param name="ACipherMode">The underlying block cipher mode this buffering object wraps.</param>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="ACipherMode"/> is nil.</exception>
    /// <exception cref="EArgumentCryptoLibException">If the mode reports a non-positive block size.</exception>
    constructor Create(const ACipherMode: IBlockCipherMode); overload;

    /// <summary>
    /// Initialise the cipher.
    /// </summary>
    /// <param name="AForEncryption">True for encryption, False for decryption.</param>
    /// <param name="AParameters">The key and other data required by the cipher.</param>
    /// <exception cref="EArgumentCryptoLibException">If the parameters argument is inappropriate.</exception>
    // Note: This doubles as Init when this cipher is used as an IWrapper.
    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); override;

    /// <summary>
    /// Return the block size for the underlying cipher.
    /// </summary>
    /// <returns>The block size in bytes.</returns>
    function GetBlockSize(): Int32; override;

    /// <summary>
    /// Return the size of the output buffer required for an <c>Update</c>
    /// (<c>ProcessBytes</c>) with an input of <paramref name="ALength"/> bytes.
    /// </summary>
    /// <param name="ALength">The length of the input.</param>
    /// <returns>The space required to accommodate a call to ProcessBytes with that many bytes of input.</returns>
    function GetUpdateOutputSize(ALength: Int32): Int32; override;

    /// <summary>
    /// Return the size of the output buffer required for an update plus a
    /// <c>DoFinal</c> with an input of <paramref name="ALength"/> bytes.
    /// </summary>
    /// <param name="ALength">The length of the input.</param>
    /// <returns>The space required to accommodate ProcessBytes plus DoFinal.</returns>
    /// <remarks>When <see cref="IBlockCipherMode.IsPartialBlockOkay"/> is true, this equals <c>FBufOff + ALength</c>.</remarks>
    function GetOutputSize(ALength: Int32): Int32; override;

    /// <summary>
    /// Process a single byte, producing an output block if necessary.
    /// </summary>
    /// <param name="AInput">The input byte.</param>
    /// <param name="AOutput">The buffer for any output that might be produced.</param>
    /// <param name="AOutOff">The offset at which output is written.</param>
    /// <returns>The number of output bytes copied to <paramref name="AOutput"/>.</returns>
    /// <exception cref="EDataLengthCryptoLibException">If there is not enough space in <paramref name="AOutput"/>.</exception>
    /// <exception cref="EInvalidOperationCryptoLibException">If the cipher is not initialised.</exception>
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload; override;

    /// <summary>
    /// Process a single byte, returning the produced output or an empty buffer if none yet.
    /// </summary>
    function ProcessByte(AInput: Byte): TCryptoLibByteArray; overload; override;

    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32): TCryptoLibByteArray; overload; override;

    /// <summary>
    /// Process an array of bytes, producing output if necessary.
    /// </summary>
    /// <param name="AInput">The input byte array.</param>
    /// <param name="AInOff">The offset at which the input data starts.</param>
    /// <param name="ALength">The number of bytes to process.</param>
    /// <param name="AOutput">The buffer for any output produced.</param>
    /// <param name="AOutOff">The offset at which output is written.</param>
    /// <returns>The number of output bytes copied.</returns>
    /// <exception cref="EDataLengthCryptoLibException">If there is not enough space in <paramref name="AOutput"/>.</exception>
    /// <exception cref="EInvalidOperationCryptoLibException">If the cipher is not initialised.</exception>
    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

    /// <summary>
    /// Process any remaining bytes in the buffer, returning the produced output.
    /// </summary>
    /// <returns>The output bytes, trimmed to actual length.</returns>
    /// <exception cref="EInvalidCipherTextCryptoLibException">If padding is corrupted (padded buffering subclasses).</exception>
    function DoFinal(): TCryptoLibByteArray; overload; override;

    /// <summary>
    /// Process an array of bytes plus any remaining buffered data; return concatenated output.
    /// </summary>
    /// <param name="AInput">The final input slice (may be empty).</param>
    /// <param name="AInOff">Start offset in <paramref name="AInput"/>.</param>
    /// <param name="AInLen">Length of input to process.</param>
    /// <returns>Combined output bytes.</returns>
    /// <exception cref="EArgumentNilCryptoLibException">If <paramref name="AInput"/> is nil while <paramref name="AInLen"/> is positive.</exception>
    function DoFinal(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32)
      : TCryptoLibByteArray; overload; override;

    /// <summary>
    /// Process the last block in the buffer.
    /// </summary>
    /// <param name="AOutput">The buffer receiving any held ciphertext/plaintext.</param>
    /// <param name="AOutOff">Offset at which output is written.</param>
    /// <returns>The number of output bytes written.</returns>
    /// <exception cref="EDataLengthCryptoLibException">If insufficient space or data not block-aligned when required.</exception>
    /// <exception cref="EInvalidOperationCryptoLibException">If the cipher is not initialised.</exception>
    /// <exception cref="EInvalidCipherTextCryptoLibException">If padding is expected and invalid.</exception>
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
      overload; override;

    /// <summary>
    /// Reset the buffer and cipher.
    /// </summary>
    /// <remarks>After resetting, the instance matches the post-<c>Init</c> state of the last successful <c>Init</c>.</remarks>
    procedure Reset(); override;

    /// <summary>The algorithm name of the underlying cipher mode.</summary>
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

  LOutBytes := nil;

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
  LOutBytes := nil;

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
begin
  FForEncryption := AForEncryption;

  Reset();

  FCipherMode.Init(AForEncryption, TParameterUtilities.IgnoreRandom(AParameters));

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
