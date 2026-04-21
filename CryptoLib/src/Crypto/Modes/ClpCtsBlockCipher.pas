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

unit ClpCtsBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpICtsBlockCipher,
  ClpICbcBlockCipher,
  ClpIEcbBlockCipher,
  ClpEcbBlockCipher,
  ClpBufferedBlockCipher,
  ClpCryptoLibTypes;

resourcestring
  SUnsupportedCipher = 'CtsBlockCipher can only accept ECB, or CBC ciphers';
  SCTSDoFinalError = 'Need at Least One Block of Input For CTS';
  SOutputBufferTooSmallForDoFinal = 'Output Buffer Too Short for DoFinal()';

type
  TCtsBlockCipher = class sealed(TBufferedBlockCipher, ICtsBlockCipher)

  strict private
  var
    FBlockSize: Int32;

  strict protected
    /// <summary>
    /// CTS holds the last two FBuf blocks back for DoFinal, so we walk
    /// the aligned middle differently from the default: the first post
    /// gap-fill block always comes from the FBuf lookahead (staging one
    /// AInput block into FBuf, processing the lookahead, shifting the
    /// staged block into the lookahead slot), then any remaining N-1
    /// blocks run through FBulkCipherMode.ProcessBlocks directly on
    /// AInput. After the bulk call we refresh FBuf[0..LBlockSize-1] with
    /// the last AInput block the bulk call consumed so DoFinal and any
    /// follow-up ProcessBytes observe the same lookahead state the
    /// scalar path would have produced.
    /// </summary>
    function ProcessBytesBulkMiddle(const AInput: TCryptoLibByteArray;
      var AInOff: Int32; var ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;

    /// <summary>
    /// CTS never flushes on tail-store: the last two blocks must remain
    /// in FBuf for DoFinal's ciphertext-stealing finalisation.
    /// </summary>
    function AfterTailStored(const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; override;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipherMode: IBlockCipherMode); overload;
    function GetOutputSize(AInputLen: Int32): Int32; override;
    function GetUpdateOutputSize(AInputLen: Int32): Int32; override;
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; override;
    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
      override;
  end;

implementation

{ TCtsBlockCipher }

constructor TCtsBlockCipher.Create(const ACipher: IBlockCipher);
begin
  Create(TEcbBlockCipher.GetBlockCipherMode(ACipher));
end;

constructor TCtsBlockCipher.Create(const ACipherMode: IBlockCipherMode);
begin
  Inherited Create();
  if not (Supports(ACipherMode, ICbcBlockCipher) or
    Supports(ACipherMode, IEcbBlockCipher)) then
    raise EArgumentCryptoLibException.CreateRes(@SUnsupportedCipher);

  FCipherMode := ACipherMode;

  FBlockSize := ACipherMode.GetBlockSize();

  System.SetLength(FBuf, FBlockSize * 2);
  FBufOff := 0;
end;

function TCtsBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LBlockSize, LLen, LI: Int32;
  LBlock, LLastBlock: TCryptoLibByteArray;
begin
  if ((FBufOff + AOutOff) > System.Length(AOutput)) then
    raise EDataLengthCryptoLibException.CreateRes
      (@SOutputBufferTooSmallForDoFinal);

  LBlockSize := FCipherMode.GetBlockSize();
  LLen := FBufOff - LBlockSize;
  System.SetLength(LBlock, LBlockSize);

  if (FForEncryption) then
  begin
    if (FBufOff < LBlockSize) then
      raise EDataLengthCryptoLibException.CreateRes(@SCTSDoFinalError);

    FCipherMode.ProcessBlock(FBuf, 0, LBlock, 0);

    if (FBufOff > LBlockSize) then
    begin
      LI := FBufOff;
      while LI <> System.Length(FBuf) do
      begin
        FBuf[LI] := LBlock[LI - LBlockSize];
        System.Inc(LI);
      end;

      LI := LBlockSize;
      while LI <> FBufOff do
      begin
        FBuf[LI] := FBuf[LI] xor (LBlock[LI - LBlockSize]);
        System.Inc(LI);
      end;

      FCipherMode.UnderlyingCipher.ProcessBlock(FBuf, LBlockSize, AOutput, AOutOff);

      System.Move(LBlock[0], AOutput[AOutOff + LBlockSize],
        LLen * System.SizeOf(Byte));
    end
    else
      System.Move(LBlock[0], AOutput[AOutOff], LBlockSize * System.SizeOf(Byte));
  end
  else
  begin
    if (FBufOff < LBlockSize) then
      raise EDataLengthCryptoLibException.CreateRes(@SCTSDoFinalError);

    System.SetLength(LLastBlock, LBlockSize);

    if (FBufOff > LBlockSize) then
    begin
      FCipherMode.UnderlyingCipher.ProcessBlock(FBuf, 0, LBlock, 0);

      LI := LBlockSize;
      while LI <> FBufOff do
      begin
        LLastBlock[LI - LBlockSize] := Byte(LBlock[LI - LBlockSize] xor FBuf[LI]);
        System.Inc(LI);
      end;

      System.Move(FBuf[LBlockSize], LBlock[0], LLen * System.SizeOf(Byte));
      FCipherMode.ProcessBlock(LBlock, 0, AOutput, AOutOff);
      System.Move(LLastBlock[0], AOutput[AOutOff + LBlockSize],
        LLen * System.SizeOf(Byte));
    end
    else
    begin
      FCipherMode.ProcessBlock(FBuf, 0, LBlock, 0);
      System.Move(LBlock[0], AOutput[AOutOff], LBlockSize * System.SizeOf(Byte));
    end;
  end;

  Result := FBufOff;
  Reset();
end;

function TCtsBlockCipher.GetOutputSize(AInputLen: Int32): Int32;
begin
  Result := AInputLen + FBufOff;
end;

function TCtsBlockCipher.GetUpdateOutputSize(AInputLen: Int32): Int32;
var
  LTotal, LLeftOver: Int32;
begin
  LTotal := AInputLen + FBufOff;
  LLeftOver := LTotal mod System.Length(FBuf);

  if (LLeftOver = 0) then
  begin
    Result := LTotal - System.Length(FBuf);
    Exit;
  end;
  Result := LTotal - LLeftOver;
end;

function TCtsBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  Result := 0;

  if (FBufOff = System.Length(FBuf)) then
  begin
    Result := FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    System.Move(FBuf[FBlockSize], FBuf[0], FBlockSize * System.SizeOf(Byte));
    FBufOff := FBlockSize;
  end;

  FBuf[FBufOff] := AInput;
  System.Inc(FBufOff);
end;

function TCtsBlockCipher.ProcessBytesBulkMiddle(
  const AInput: TCryptoLibByteArray; var AInOff: Int32; var ALen: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LBlockSize, LN, LBulkBlocks, LBulkBytes: Int32;
begin
  Result := 0;
  LBlockSize := GetBlockSize();

  // FBuf[0..LBlockSize-1] holds the lookahead from gap-fill and FBufOff
  // equals LBlockSize (single-slot staging area at FBuf[LBlockSize..]).
  // The scalar loop below stages one AInput block into FBuf[LBlockSize],
  // processes FBuf[0] (the lookahead), and shifts. The first iteration
  // MUST stay scalar because its input is the FBuf lookahead, not
  // AInput; iterations 1..N-1 are pure contiguous-AInput transforms and
  // can be routed through one ProcessBlocks call. N = (ALen - 1) div BS
  // is the total iteration count the scalar loop would perform, so we
  // need N >= 2 (i.e. ALen > 2*BS) to get at least one bulk block.
  if (FBulkCipherMode <> nil) and (ALen > 2 * LBlockSize) then
  begin
    LN := (ALen - 1) div LBlockSize;

    System.Move(AInput[AInOff], FBuf[FBufOff], LBlockSize * System.SizeOf(Byte));
    Result := Result + FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff);
    System.Move(FBuf[LBlockSize], FBuf[0], LBlockSize * System.SizeOf(Byte));
    ALen := ALen - LBlockSize;
    AInOff := AInOff + LBlockSize;

    LBulkBlocks := LN - 1;
    LBulkBytes := LBulkBlocks * LBlockSize;
    Result := Result + FBulkCipherMode.ProcessBlocks(AInput, AInOff,
      LBulkBlocks, AOutput, AOutOff + Result);

    // Refresh FBuf[0..LBlockSize-1] with the last AInput block the bulk
    // call consumed. That block would have been the post-shift lookahead
    // after the scalar loop's final iteration, so DoFinal and subsequent
    // ProcessBytes observe the same FBuf state either way.
    System.Move(AInput[AInOff + LBulkBytes - LBlockSize], FBuf[0],
      LBlockSize * System.SizeOf(Byte));

    ALen := ALen - LBulkBytes;
    AInOff := AInOff + LBulkBytes;
  end
  else
  begin
    while (ALen > LBlockSize) do
    begin
      System.Move(AInput[AInOff], FBuf[FBufOff], LBlockSize * System.SizeOf(Byte));
      Result := Result + FCipherMode.ProcessBlock(FBuf, 0, AOutput, AOutOff + Result);
      System.Move(FBuf[LBlockSize], FBuf[0], LBlockSize * System.SizeOf(Byte));

      ALen := ALen - LBlockSize;
      AInOff := AInOff + LBlockSize;
    end;
  end;
end;

function TCtsBlockCipher.AfterTailStored(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  Result := 0;
end;

end.
