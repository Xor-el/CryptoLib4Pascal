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
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidLength = 'cannot have a negative input length';
  SInputNil = 'input cannot be nil';
  SCipherModeNil = 'cipher mode cannot be nil';
  SCipherModeInvalidBlockSize = 'cipher mode must have a positive block size';
  SOutputBufferTooSmall = 'output buffer too short';
  SDataNotBlockSizeAligned = 'data not block size aligned';
  SOutputBufferTooSmallForDoFinal = 'output buffer too short for DoFinal()';

type
  /// <summary>
  /// A wrapper class that allows block ciphers to be used to process data in a piecemeal fashion.
  /// </summary>
  /// <remarks>
  /// <para>
  /// In this plain (non-padded) base class the instance flushes a block as soon as <see cref="FBuf"/>
  /// becomes full during <c>ProcessByte</c> / <c>ProcessBytes</c>; any leftover partial block is
  /// emitted by <c>DoFinal</c> (only legal when the underlying mode reports
  /// <see cref="IBlockCipherMode.IsPartialBlockOkay"/>). Subclasses that need to hold the last full
  /// block back for finalisation (padded ciphers, CTS) override <see cref="IsFullBufferRetained"/>
  /// to change this timing.
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
    /// True when a fully-populated <see cref="FBuf"/> must be retained
    /// for <c>DoFinal</c> rather than flushed by <c>ProcessBytes</c> or
    /// <c>ProcessByte</c>. The plain <see cref="TBufferedBlockCipher"/>
    /// returns False so a just-filled FBuf is flushed eagerly during
    /// streaming. Padded subclasses return True so DoFinal can apply
    /// (encrypting) or strip (decrypting) the padding on the held
    /// block. Subclasses that own their own <c>ProcessBytes</c> (such
    /// as CTS) do not rely on this decision but should still override
    /// it for honesty.
    /// </summary>
    function IsFullBufferRetained: Boolean; virtual;

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
  // wiring at Init time are observed in their post-Init state.
  TBlockCipherBulkUtilities.TryResolveBulkCipherMode(FCipherMode,
    FBulkCipherMode);
end;

function TBufferedBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LRetain: Boolean;
  LBlockSize: Int32;
begin
  Result := 0;
  LRetain := IsFullBufferRetained();
  LBlockSize := System.Length(FBuf);

  // Retained-buffer ciphers (padded) may carry a full FBuf from a
  // previous call. The arrival of another byte proves more data is
  // coming, so the held block can now be emitted before we store.
  if LRetain and (FBufOff = LBlockSize) then
  begin
    if ((AOutOff + LBlockSize) > System.Length(AOutput)) then
      raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
    Result := FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    FBufOff := 0;
  end;

  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);

  // Eager-flush ciphers (plain) emit immediately when this byte just
  // filled FBuf.
  if (not LRetain) and (FBufOff = LBlockSize) then
  begin
    if ((AOutOff + Result + LBlockSize) > System.Length(AOutput)) then
      raise EDataLengthCryptoLibException.CreateRes(@SOutputBufferTooSmall);
    Result := Result + FCipherMode.ProcessBlock(FBuf, 0, AOutput,
      AOutOff + Result);
    FBufOff := 0;
  end;
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

function TBufferedBlockCipher.IsFullBufferRetained: Boolean;
begin
  Result := False;
end;

function TBufferedBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LOutLength, LResultLen, LGapLen, LBlockSize,
    LBulkBlocks, LBulkBytes: Int32;
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
  LGapLen := LBlockSize - FBufOff;

  if (ALength > LGapLen) then
  begin
    // Gap-fill: complete the in-flight FBuf block and emit it. FBuf is
    // always exactly one block here, so no lookahead shift is needed -
    // subclasses with a multi-block FBuf (CTS) own their own
    // ProcessBytes.
    System.Move(AInput[AInOff], FBuf[FBufOff], LGapLen * System.SizeOf(Byte));
    LResultLen := LResultLen + FCipherMode.ProcessBlock(FBuf, 0, AOutput,
      AOutOff);
    FBufOff := 0;
    ALength := ALength - LGapLen;
    AInOff := AInOff + LGapLen;

    // Aligned middle: process (ALength - 1) div LBlockSize full blocks
    // directly from AInput, leaving at least one byte to seed the tail
    // store below. The cached bulk fast path collapses the per-block
    // ProcessBlock loop into a single ProcessBlocks call so accelerated
    // modes can pipeline / SIMD across many blocks.
    if (FBulkCipherMode <> nil) and (ALength > LBlockSize) then
    begin
      LBulkBlocks := (ALength - 1) div LBlockSize;
      LBulkBytes := LBulkBlocks * LBlockSize;
      LResultLen := LResultLen + FBulkCipherMode.ProcessBlocks(AInput, AInOff,
        LBulkBlocks, AOutput, AOutOff + LResultLen);
      ALength := ALength - LBulkBytes;
      AInOff := AInOff + LBulkBytes;
    end
    else
    begin
      while (ALength > LBlockSize) do
      begin
        LResultLen := LResultLen + FCipherMode.ProcessBlock(AInput, AInOff,
          AOutput, AOutOff + LResultLen);
        ALength := ALength - LBlockSize;
        AInOff := AInOff + LBlockSize;
      end;
    end;
  end;

  // Tail store + optional eager flush. Retained-buffer subclasses
  // (padded) leave the now-full FBuf for DoFinal to consume; plain
  // cipher flushes the block immediately.
  System.Move(AInput[AInOff], FBuf[FBufOff], ALength * System.SizeOf(Byte));
  FBufOff := FBufOff + ALength;
  if (FBufOff = LBlockSize) and (not IsFullBufferRetained()) then
  begin
    LResultLen := LResultLen + FCipherMode.ProcessBlock(FBuf, 0, AOutput,
      AOutOff + LResultLen);
    FBufOff := 0;
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
  TArrayUtilities.Fill(FBuf, 0, System.Length(FBuf), Byte(0));
  FBufOff := 0;

  FCipherMode.Reset();
end;

end.
