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
  ClpCheck,
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
  SCTSDoFinalError = 'need at least one block of input for CTS';
  SOutputBufferTooSmallForDoFinal = 'output buffer too short for DoFinal()';

type
  TCtsBlockCipher = class sealed(TBufferedBlockCipher, ICtsBlockCipher)

  strict private
  var
    FBlockSize: Int32;

  strict protected
    /// <summary>
    /// CTS retains both FBuf blocks for DoFinal's ciphertext-stealing
    /// finalisation. Reported for honesty; CTS owns its own
    /// ProcessBytes / ProcessByte so the predicate is not consulted
    /// internally.
    /// </summary>
    function IsFullBufferRetained: Boolean; override;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipherMode: IBlockCipherMode); overload;
    function GetOutputSize(AInputLen: Int32): Int32; override;
    function GetUpdateOutputSize(AInputLen: Int32): Int32; override;
    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray;
      AOutOff: Int32): Int32; override;

    /// <summary>
    /// CTS-specific ProcessBytes. FBuf is two blocks wide and is used
    /// as a one-block lookahead, so this override carries its own
    /// gap-fill (with the shift to refresh the lookahead) and its own
    /// aligned middle (stage one scalar block, bulk-process the rest,
    /// refresh the lookahead from the last bulk-consumed block). The
    /// final two blocks always remain in FBuf for DoFinal.
    /// </summary>
    function ProcessBytes(const AInput: TCryptoLibByteArray;
      AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32)
      : Int32; overload; override;

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

function TCtsBlockCipher.IsFullBufferRetained: Boolean;
begin
  Result := True;
end;

function TCtsBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALength: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LOutLength, LResultLen, LGapLen, LN,
    LBulkBlocks, LBulkBytes: Int32;
begin
  if (ALength < 1) then
  begin
    if (ALength < 0) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidLength);
    Result := 0;
    Exit;
  end;

  LOutLength := GetUpdateOutputSize(ALength);
  if (LOutLength > 0) then
    TCheck.OutputLength(AOutput, AOutOff, LOutLength, SOutputBufferTooSmall);

  LResultLen := 0;
  LGapLen := System.Length(FBuf) - FBufOff;

  if (ALength > LGapLen) then
  begin
    // Gap-fill: complete the in-flight FBuf (two blocks wide), emit
    // FBuf[0..FBlockSize-1], and shift FBuf[FBlockSize..] down so
    // FBuf[0..FBlockSize-1] now holds the lookahead.
    System.Move(AInput[AInOff], FBuf[FBufOff], LGapLen * System.SizeOf(Byte));
    LResultLen := LResultLen + FCipherMode.ProcessBlock(FBuf, 0, AOutput,
      AOutOff);
    System.Move(FBuf[FBlockSize], FBuf[0],
      FBlockSize * System.SizeOf(Byte));
    FBufOff := FBlockSize;
    ALength := ALength - LGapLen;
    AInOff := AInOff + LGapLen;

    // Aligned middle. FBuf[0..FBlockSize-1] holds the lookahead and
    // FBufOff equals FBlockSize. The scalar loop stages one AInput
    // block into FBuf[FBlockSize..], processes FBuf[0..FBlockSize-1]
    // (the lookahead), then shifts. The first iteration MUST stay
    // scalar because its input is the lookahead, not AInput; the next
    // N-1 iterations are pure contiguous-AInput transforms and can ride
    // the bulk fast path. N = (ALength - 1) div FBlockSize is the
    // scalar iteration count, so we need N >= 2 (i.e.
    // ALength > 2 * FBlockSize) for the bulk path to amortise.
    if (FBulkCipherMode <> nil) and (ALength > 2 * FBlockSize) then
    begin
      LN := (ALength - 1) div FBlockSize;

      System.Move(AInput[AInOff], FBuf[FBufOff],
        FBlockSize * System.SizeOf(Byte));
      LResultLen := LResultLen + FCipherMode.ProcessBlock(FBuf, 0, AOutput,
        AOutOff + LResultLen);
      System.Move(FBuf[FBlockSize], FBuf[0],
        FBlockSize * System.SizeOf(Byte));
      ALength := ALength - FBlockSize;
      AInOff := AInOff + FBlockSize;

      LBulkBlocks := LN - 1;
      LBulkBytes := LBulkBlocks * FBlockSize;
      LResultLen := LResultLen + FBulkCipherMode.ProcessBlocks(AInput, AInOff,
        LBulkBlocks, AOutput, AOutOff + LResultLen);

      // Refresh FBuf[0..FBlockSize-1] with the last AInput block the
      // bulk call consumed - the post-shift lookahead the scalar loop's
      // final iteration would have left behind. DoFinal and any
      // follow-up ProcessBytes observe the same FBuf state either way.
      System.Move(AInput[AInOff + LBulkBytes - FBlockSize], FBuf[0],
        FBlockSize * System.SizeOf(Byte));

      ALength := ALength - LBulkBytes;
      AInOff := AInOff + LBulkBytes;
    end
    else
    begin
      while (ALength > FBlockSize) do
      begin
        System.Move(AInput[AInOff], FBuf[FBufOff],
          FBlockSize * System.SizeOf(Byte));
        LResultLen := LResultLen + FCipherMode.ProcessBlock(FBuf, 0, AOutput,
          AOutOff + LResultLen);
        System.Move(FBuf[FBlockSize], FBuf[0],
          FBlockSize * System.SizeOf(Byte));
        ALength := ALength - FBlockSize;
        AInOff := AInOff + FBlockSize;
      end;
    end;
  end;

  // Tail store. CTS always retains both blocks for DoFinal's
  // ciphertext-stealing finalisation, so we never flush here.
  System.Move(AInput[AInOff], FBuf[FBufOff], ALength * System.SizeOf(Byte));
  FBufOff := FBufOff + ALength;
  Result := LResultLen;
end;

end.
