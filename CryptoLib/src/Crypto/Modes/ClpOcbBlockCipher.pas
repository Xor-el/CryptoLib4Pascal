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

unit ClpOcbBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Generics.Collections,
  ClpIBlockCipher,
  ClpIBulkBlockCipher,
  ClpCipherKernelTypes,
  ClpIOcbKernel,
  ClpCipherKernelRegistry,
  ClpCipherKernelDefaults, // registers in-tree fused AEAD kernel factories
  ClpIOcbBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpBlockCipherBulkUtilities,
  ClpCipherModeParameterUtilities,
  ClpCheck,
  ClpBitOperations,
  ClpByteUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SHashCipherNil = 'hash cipher cannot be nil';
  SMainCipherNil = 'main cipher cannot be nil';
  SBlockSizeRequired = 'must have a block size of %d';
  SCiphersMustMatch = 'hashCipher and mainCipher must be the same algorithm';
  SInvalidParameters = 'invalid parameters passed to %s';
  SIVTooLong = 'IV must be no more than 15 bytes';
  SCannotChangeEncState = 'cannot change encrypting state without providing key';
  SInvalidMacSize = 'invalid value for MAC size: %d';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in %s failed';
  SOutputBufferTooShort = 'output buffer too short';
  SInputBufferTooShort = 'input buffer too short';
  SCannotReuseNonce = 'cannot reuse nonce for %s encryption';

type
  TOcbBlockCipher = class(TInterfacedObject, IOcbBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    BLOCK_SIZE = 16;

    // Block cap for the ONE fused path that stages a per-batch stack
    // scratch buffer: truncated-MAC decrypt (FMacSize < BLOCK_SIZE). The
    // encrypt and full-MAC-decrypt paths need no scratch and are dispatched
    // as a single whole-span call, so this bound does not apply to them.
    // Must be a multiple of the fused kernel's MinimumBlockCount; Init
    // rejects any kernel whose stride does not divide it.
    FUSED_BATCH_BLOCKS = 96;

    // Number of 16-byte L-table entries the mode materialises contiguously
    // for the kernel (FLTableFlat, cached across calls). An OCB session is
    // bounded by the security proof to well under 2^48 blocks per nonce, and
    // OCB_ntz of any Int64 block count is at most 63, so 64 entries covers
    // every practically reachable max ntz. At BLOCK_SIZE bytes each the
    // footprint is 1 KiB.
    FUSED_LTABLE_ENTRIES = 64;

  var
    FHashCipher: IBlockCipher;
    FMainCipher: IBlockCipher;

    FForEncryption: Boolean;
    FMacSize: Int32;
    FInitialAssociatedText: TCryptoLibByteArray;

    FL: TList<TCryptoLibByteArray>;
    FL_Asterisk, FL_Dollar: TCryptoLibByteArray;

    // Cached contiguous snapshot of FL[0..FLTableFlatCount-1] handed to the
    // fused kernel. FL is key-stable and only ever grows, so the flat copy is
    // materialised lazily (EnsureLTableFlat) and reused across every batch and
    // ProcessBytes call; it is invalidated only on Init, when FL is rebuilt for
    // a new key.
    FLTableFlat: TCryptoLibByteArray;
    FLTableFlatCount: Int32;

    FKTopInput: TCryptoLibByteArray;
    FStretch: TCryptoLibByteArray;
    FOffsetMAIN_0: TCryptoLibByteArray;

    FHashBlock, FMainBlock: TCryptoLibByteArray;
    FHashBlockPos, FMainBlockPos: Int32;
    FHashBlockCount, FMainBlockCount: Int64;
    FOffsetHASH: TCryptoLibByteArray;
    FSum: TCryptoLibByteArray;
    FOffsetMAIN: TCryptoLibByteArray;
    FChecksum: TCryptoLibByteArray;

    FMacBlock: TCryptoLibByteArray;
    FLastN: TCryptoLibByteArray;
    FLastKey: TCryptoLibByteArray;

    // 8-wide bulk-cipher fast path: cached bulk-capable view of
    // FMainCipher. When the main cipher exposes IBulkBlockCipher,
    // ProcessBytes folds 8 consecutive blocks through a single
    // ProcessBlocks call inside ProcessEightBlocksBulk instead of the
    // per-byte FMainBlock fill path. Nil -> scalar fallback.
    FMainBulk: IBulkBlockCipher;

    // Fused-kernel fast path: cipher-agnostic fused OCB kernel
    // resolved via TCipherKernelRegistry on every Init. Nil when no
    // registered factory accepts the cipher / direction pair or the
    // registry-wide kill switch is on; ProcessBytes then falls through
    // to the 8-wide bulk / scalar paths unchanged.
    // FOcbKernelMinBlocks is also the batch alignment: the kernel
    // loops internally in MinimumBlockCount chunks so the mode stages
    // up to FUSED_BATCH_BLOCKS worth of offsets per dispatch.
    FOcbKernel: IOcbKernel;
    FOcbKernelMinBlocks: Int32;

    procedure CheckNonceReuse(AForEncryption: Boolean;
      const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);

    procedure ProcessFusedBulk(const AInput: TCryptoLibByteArray;
      AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32;
      ABlockCount: Int32);

    // Grow FL and the cached flat L-table so entries [0..AMaxNtz] are present
    // in FLTableFlat, extending only the not-yet-materialised tail.
    procedure EnsureLTableFlat(AMaxNtz: Int32);

    procedure ProcessEightBlocksBulk(const AInput: TCryptoLibByteArray;
      AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32);

    class function OCB_double(const ABlock: TCryptoLibByteArray): TCryptoLibByteArray; static;
    class procedure OCB_extend(const ABlock: TCryptoLibByteArray; APos: Int32); static;
    class function OCB_ntz(AX: Int64): Int32; static; inline;
    class function ShiftLeft(const ABlock, AOutput: TCryptoLibByteArray): Int32; static;

  strict protected
    function ProcessNonce(const AN: TCryptoLibByteArray): Int32; virtual;
    procedure Clear(const ABs: TCryptoLibByteArray); virtual;
    function GetLSub(AN: Int32): TCryptoLibByteArray; virtual;
    procedure ProcessHashBlock(); virtual;
    procedure ProcessMainBlock(const AOutput: TCryptoLibByteArray; AOutOff: Int32); virtual;
    procedure Reset(AClearMac: Boolean); overload; virtual;
    procedure UpdateHASH(const ALSub: TCryptoLibByteArray); virtual;

    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(const AHashCipher, AMainCipher: IBlockCipher);
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;
    function GetBlockSize(): Int32; virtual;

    procedure ProcessAadByte(AInput: Byte); virtual;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); virtual;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function GetMac(): TCryptoLibByteArray; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;
    function GetOutputSize(ALen: Int32): Int32; virtual;
    procedure Reset(); overload; virtual;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TOcbBlockCipher }

constructor TOcbBlockCipher.Create(const AHashCipher, AMainCipher: IBlockCipher);
begin
  inherited Create();

  if (AHashCipher = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SHashCipherNil);
  if (AHashCipher.GetBlockSize() <> BLOCK_SIZE) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBlockSizeRequired, [BLOCK_SIZE]);
  if (AMainCipher = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SMainCipherNil);
  if (AMainCipher.GetBlockSize() <> BLOCK_SIZE) then
    raise EArgumentCryptoLibException.CreateResFmt(@SBlockSizeRequired, [BLOCK_SIZE]);

  if (AHashCipher.AlgorithmName <> AMainCipher.AlgorithmName) then
    raise EArgumentCryptoLibException.CreateRes(@SCiphersMustMatch);

  FHashCipher := AHashCipher;
  FMainCipher := AMainCipher;

  System.SetLength(FStretch, 24);
  System.SetLength(FOffsetMAIN_0, 16);
  System.SetLength(FOffsetMAIN, 16);
  FL := TList<TCryptoLibByteArray>.Create;
  System.SetLength(FLTableFlat, FUSED_LTABLE_ENTRIES * BLOCK_SIZE);
  FLTableFlatCount := 0;
end;

destructor TOcbBlockCipher.Destroy;
begin
  FL.Free;
  inherited Destroy;
end;

class function TOcbBlockCipher.OCB_ntz(AX: Int64): Int32;
begin
  Result := TBitOperations.NumberOfTrailingZeros64(UInt64(AX));
end;

function TOcbBlockCipher.GetAlgorithmName: String;
begin
  Result := FMainCipher.AlgorithmName + '/OCB';
end;

function TOcbBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FMainCipher;
end;

procedure TOcbBlockCipher.CheckNonceReuse(AForEncryption: Boolean;
  const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);
begin
  if not AForEncryption then
    Exit;

  if (FLastN = nil) or (not TArrayUtilities.AreEqual(FLastN, ANewNonce)) then
    Exit;

  if AKeyParam = nil then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce, ['OCB']);

  if (FLastKey <> nil) and AKeyParam.FixedTimeEquals(FLastKey) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce, ['OCB']);
end;

procedure TOcbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LOldForEncryption: Boolean;
  LKeyParameter: IKeyParameter;
  LChoice: TCipherAeadChoice;
  LN: TCryptoLibByteArray;
  LMacSizeBits, LBottom, LBits, LBytes, LI: Int32;
  LB1, LB2: UInt32;
  LFusedDirection: TCipherKernelDirection;
begin
  LOldForEncryption := FForEncryption;
  FForEncryption := AForEncryption;
  FMacBlock := nil;

  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['OCB']);

  if (not LChoice.IsAead) and (LChoice.CipherKey <> nil) and
    (LChoice.KeyParameter = nil) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['OCB']);

  LN := LChoice.Nonce;
  CheckNonceReuse(FForEncryption, LN, LChoice.KeyParameter);
  FLastN := System.Copy(LN);
  if LChoice.KeyParameter <> nil then
    FLastKey := LChoice.KeyParameter.GetKey();

  FInitialAssociatedText := LChoice.AssociatedText;
  LKeyParameter := LChoice.KeyParameter;

  if LChoice.IsAead then
  begin
    LMacSizeBits := LChoice.MacSizeBits;
    if (LMacSizeBits < 64) or (LMacSizeBits > 128) or (LMacSizeBits mod 8 <> 0) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize, [LMacSizeBits]);
    FMacSize := LMacSizeBits div 8;
  end
  else
    FMacSize := 16;

  System.SetLength(FHashBlock, 16);
  TArrayUtilities.Fill(FHashBlock, 0, 16, Byte(0));
  if FForEncryption then
  begin
    System.SetLength(FMainBlock, BLOCK_SIZE);
    TArrayUtilities.Fill(FMainBlock, 0, BLOCK_SIZE, Byte(0));
  end
  else
  begin
    System.SetLength(FMainBlock, BLOCK_SIZE + FMacSize);
    TArrayUtilities.Fill(FMainBlock, 0, BLOCK_SIZE + FMacSize, Byte(0));
  end;

  if (System.Length(LN) > 15) then
    raise EArgumentCryptoLibException.CreateRes(@SIVTooLong);

  if (LKeyParameter <> nil) then
  begin
    FHashCipher.Init(True, LKeyParameter);
    FMainCipher.Init(AForEncryption, LKeyParameter);
    FKTopInput := nil;
  end
  else if (LOldForEncryption <> AForEncryption) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCannotChangeEncState);
  end;

  // Re-probe IBulkBlockCipher on every Init because the same FMainCipher
  // instance can be re-keyed with different engines that may not share the
  // same capability set. Kept as a plain interface QI (no algorithm-name
  // assumption); any engine that advertises the contract in ClpIBulkBlockCipher
  // is eligible for the 8-wide path in ProcessEightBlocksBulk.
  TBlockCipherBulkUtilities.TryResolveBulkCipher(FMainCipher, FMainBulk);

  // Resolve a fused OCB kernel via the open factory registry; the
  // first factory whose TryCreate accepts the cipher / direction pair
  // wins, and the result is cached for the whole Init cycle.
  FOcbKernel := nil;
  FOcbKernelMinBlocks := 0;
  if FForEncryption then
    LFusedDirection := TCipherKernelDirection.Encrypt
  else
    LFusedDirection := TCipherKernelDirection.Decrypt;
  if TCipherKernelRegistry.TryAcquireOcb(FMainCipher, LFusedDirection,
    FOcbKernel) and (FOcbKernel <> nil) then
  begin
    FOcbKernelMinBlocks := FOcbKernel.MinimumBlockCount;
    // The fused batch buffer holds FUSED_BATCH_BLOCKS offsets; reject
    // kernels whose stride does not divide that capacity so the mode
    // can always present a full-stride batch.
    if (FOcbKernelMinBlocks <= 0) or
      (FUSED_BATCH_BLOCKS mod FOcbKernelMinBlocks <> 0) then
    begin
      FOcbKernel := nil;
      FOcbKernelMinBlocks := 0;
    end;
  end;

  System.SetLength(FL_Asterisk, 16);
  TArrayUtilities.Fill(FL_Asterisk, 0, 16, Byte(0));
  FHashCipher.ProcessBlock(FL_Asterisk, 0, FL_Asterisk, 0);

  FL_Dollar := OCB_double(FL_Asterisk);

  FL.Clear;
  FL.Add(OCB_double(FL_Dollar));
  FLTableFlatCount := 0; // FL rebuilt for the new key; drop the flattened cache

  LBottom := ProcessNonce(LN);

  LBits := LBottom mod 8;
  LBytes := LBottom div 8;
  if (LBits = 0) then
  begin
    System.Move(FStretch[LBytes], FOffsetMAIN_0[0], 16);
  end
  else
  begin
    for LI := 0 to 15 do
    begin
      LB1 := UInt32(FStretch[LBytes]);
      System.Inc(LBytes);
      LB2 := UInt32(FStretch[LBytes]);
      FOffsetMAIN_0[LI] := Byte((LB1 shl LBits) or (LB2 shr (8 - LBits)));
    end;
  end;

  FHashBlockPos := 0;
  FMainBlockPos := 0;

  FHashBlockCount := 0;
  FMainBlockCount := 0;

  System.SetLength(FOffsetHASH, 16);
  TArrayUtilities.Fill(FOffsetHASH, 0, 16, Byte(0));
  System.SetLength(FSum, 16);
  TArrayUtilities.Fill(FSum, 0, 16, Byte(0));
  System.Move(FOffsetMAIN_0[0], FOffsetMAIN[0], 16);
  System.SetLength(FChecksum, 16);
  TArrayUtilities.Fill(FChecksum, 0, 16, Byte(0));

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

function TOcbBlockCipher.ProcessNonce(const AN: TCryptoLibByteArray): Int32;
var
  LNonce, LKTop: TCryptoLibByteArray;
  LBottom, LI: Int32;
begin
  System.SetLength(LNonce, 16);
  System.Move(AN[0], LNonce[System.Length(LNonce) - System.Length(AN)], System.Length(AN));
  LNonce[0] := Byte(FMacSize shl 4);
  LNonce[15 - System.Length(AN)] := LNonce[15 - System.Length(AN)] or 1;

  LBottom := LNonce[15] and $3F;
  LNonce[15] := LNonce[15] and Byte($C0);

  if (FKTopInput = nil) or (not TArrayUtilities.AreEqual(LNonce, FKTopInput)) then
  begin
    System.SetLength(LKTop, 16);
    FKTopInput := LNonce;
    FHashCipher.ProcessBlock(FKTopInput, 0, LKTop, 0);
    System.Move(LKTop[0], FStretch[0], 16);
    for LI := 0 to 7 do
    begin
      FStretch[16 + LI] := Byte(LKTop[LI] xor LKTop[LI + 1]);
    end;
  end;

  Result := LBottom;
end;

function TOcbBlockCipher.GetBlockSize: Int32;
begin
  Result := BLOCK_SIZE;
end;

function TOcbBlockCipher.GetMac: TCryptoLibByteArray;
begin
  if FMacBlock = nil then
    System.SetLength(Result, FMacSize)
  else
    Result := System.Copy(FMacBlock);
end;

function TOcbBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FMainBlockPos;
  if FForEncryption then
  begin
    Result := LTotalData + FMacSize;
    Exit;
  end;
  if LTotalData < FMacSize then
    Result := 0
  else
    Result := LTotalData - FMacSize;
end;

function TOcbBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FMainBlockPos;
  if (not FForEncryption) then
  begin
    if (LTotalData < FMacSize) then
    begin
      Result := 0;
      Exit;
    end;
    LTotalData := LTotalData - FMacSize;
  end;
  Result := LTotalData - LTotalData mod BLOCK_SIZE;
end;

procedure TOcbBlockCipher.ProcessAadByte(AInput: Byte);
begin
  FHashBlock[FHashBlockPos] := AInput;
  System.Inc(FHashBlockPos);
  if (FHashBlockPos = System.Length(FHashBlock)) then
  begin
    ProcessHashBlock();
  end;
end;

procedure TOcbBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LI: Int32;
begin
  for LI := 0 to System.Pred(ALen) do
  begin
    FHashBlock[FHashBlockPos] := AInput[AInOff + LI];
    System.Inc(FHashBlockPos);
    if (FHashBlockPos = System.Length(FHashBlock)) then
    begin
      ProcessHashBlock();
    end;
  end;
end;

function TOcbBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  FMainBlock[FMainBlockPos] := AInput;
  System.Inc(FMainBlockPos);
  if (FMainBlockPos = System.Length(FMainBlock)) then
  begin
    ProcessMainBlock(AOutput, AOutOff);
    Result := BLOCK_SIZE;
    Exit;
  end;
  Result := 0;
end;

function TOcbBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LResultLen, LSteadyPos, LRemaining, LBatchBlocks, LBatchBytes: Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);

  LResultLen := 0;
  LI := 0;

  // FMainBlockPos after a successful ProcessMainBlock is 0 for encrypt and
  // FMacSize for decrypt (the decrypt-side FMainBlock is 16 + FMacSize bytes
  // wide, holding a FMacSize-byte ciphertext lookahead). Bulk only kicks in
  // from that steady state so the batch aligns cleanly with the per-byte
  // fill contract that feeds FChecksum and the offset ladder.
  if FForEncryption then
    LSteadyPos := 0
  else
    LSteadyPos := FMacSize;

  while (LI < ALen) do
  begin
    // Fused-kernel fast path: a hardware-accelerated AEAD kernel resolved
    // from the registry (any accelerator whose factory accepts the cipher /
    // direction). FOcbKernel is nil when no factory accepted this
    // cipher / direction (always so off-SIMD), in which case this branch
    // is skipped and the 8-wide bulk / scalar paths below run unchanged.
    // Takes priority over the 8-wide bulk-cipher path below whenever at
    // least one kernel-stride batch fits the steady-state window. The kernel
    // loops internally in MinimumBlockCount strides and owns the offset ladder,
    // ntz derivation and checksum fold, so encrypt and full-MAC decrypt hand it
    // the ENTIRE remaining whole-block span in one dispatch (no per-batch
    // marshalling). Only the truncated-MAC decrypt path stages a sliding
    // scratch buffer, so it stays bounded by FUSED_BATCH_BLOCKS.
    if (FOcbKernel <> nil) and (FMainBlockPos = LSteadyPos) and
      ((ALen - LI) >= FOcbKernelMinBlocks * BLOCK_SIZE) then
    begin
      LRemaining := (ALen - LI) div BLOCK_SIZE;
      if FForEncryption or (FMacSize = BLOCK_SIZE) then
        LBatchBlocks := LRemaining // whole-span dispatch (no scratch needed)
      else if LRemaining > FUSED_BATCH_BLOCKS then
        LBatchBlocks := FUSED_BATCH_BLOCKS
      else
        LBatchBlocks := LRemaining;
      LBatchBlocks := (LBatchBlocks div FOcbKernelMinBlocks) *
        FOcbKernelMinBlocks;
      LBatchBytes := LBatchBlocks * BLOCK_SIZE;
      ProcessFusedBulk(AInput, AInOff + LI, AOutput,
        AOutOff + LResultLen, LBatchBlocks);
      LResultLen := LResultLen + LBatchBytes;
      LI := LI + LBatchBytes;
      Continue;
    end;

    // 8-wide bulk-cipher fast path. Entered only when no fused kernel
    // accepted this cipher / direction (FOcbKernel = nil) or the
    // remaining data is too small for a fused batch but still >= 8
    // blocks. The offset ladder and checksum fold stay in Pascal here;
    // only the AES calls are bulked through FMainBulk.
    if (FMainBulk <> nil) and (FMainBlockPos = LSteadyPos) and
      ((ALen - LI) >= 8 * BLOCK_SIZE) then
    begin
      ProcessEightBlocksBulk(AInput, AInOff + LI, AOutput,
        AOutOff + LResultLen);
      LResultLen := LResultLen + 8 * BLOCK_SIZE;
      LI := LI + 8 * BLOCK_SIZE;
      Continue;
    end;

    FMainBlock[FMainBlockPos] := AInput[AInOff + LI];
    System.Inc(FMainBlockPos);
    if (FMainBlockPos = System.Length(FMainBlock)) then
    begin
      ProcessMainBlock(AOutput, AOutOff + LResultLen);
      LResultLen := LResultLen + BLOCK_SIZE;
    end;
    System.Inc(LI);
  end;

  Result := LResultLen;
end;

procedure TOcbBlockCipher.ProcessFusedBulk(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32;
  ABlockCount: Int32);
var
  // Decrypt fallback (FMacSize < BLOCK_SIZE): FMacSize-byte lookahead
  // followed by fresh AInput bytes. This path is the ONLY per-batch scratch
  // user, so ProcessBytes bounds its ABlockCount by FUSED_BATCH_BLOCKS; the
  // encrypt and full-MAC-decrypt fast paths bypass this buffer entirely (they
  // hand the kernel raw pointers) and are dispatched as a single whole-span
  // call.
  LScratch: array [0 .. FUSED_BATCH_BLOCKS * BLOCK_SIZE - 1] of Byte;
  LBatchBytes, LMaxNtz: Int32;
  LStartBlockCount: UInt64;
  LInPtr, LBlock0Ptr: Pointer;
begin
  LBatchBytes := ABlockCount * BLOCK_SIZE;

  // Block count consumed just before the first block of this batch. The kernel
  // seeds a running counter from it and derives ntz per block itself, so there
  // is no per-block ntz precompute loop.
  LStartBlockCount := UInt64(FMainBlockCount);
  System.Inc(FMainBlockCount, ABlockCount);
  // Upper bound on ntz over (start+1..start+ABlockCount): floor(log2(endCount))
  // = index of the most significant set bit. The kernel indexes L up to this; a
  // slightly loose bound just flattens a few extra entries.
  LMaxNtz := 63 - TBitOperations.NumberOfLeadingZeros64(UInt64(FMainBlockCount));

  // Materialise FLTableFlat through LMaxNtz (lazy, cached across calls) so the
  // kernel can index the L-table with a single contiguous load per block.
  EnsureLTableFlat(LMaxNtz);

  if FForEncryption then
  begin
    // Encrypt: block 0 of iteration 0 is the first block of AInput --
    // identical to the main-stream base -- so Block0Ptr and InPtr
    // alias. The fused kernel owns the offset ladder, the L-XOR step
    // and the plaintext-into-FChecksum fold; Pascal only supplies the
    // state pointers it reads/writes in-place.
    LInPtr := @AInput[AInOff];
    LBlock0Ptr := LInPtr;
    FOcbKernel.ProcessBlocks(LInPtr, @AOutput[AOutOff],
      @FOffsetMAIN[0], @FChecksum[0], @FLTableFlat[0],
      LBlock0Ptr, ABlockCount, LStartBlockCount);
  end
  else if FMacSize = BLOCK_SIZE then
  begin
    // Decrypt fast path (full-width MAC): the ciphertext stream S is
    // S[0..15]   = FMainBlock[0..15]   (the BLOCK_SIZE-byte lookahead
    //                                  produced by the previous call)
    // S[16..*]   = AInput[AInOff..]    (fresh ciphertext)
    // so block 0 reads from FMainBlock and blocks 1.. read from
    // AInput with no copy. We hand the kernel Block0Ptr = FMainBlock
    // and InPtr = AInput - BLOCK_SIZE: on iter 0 the kernel sources
    // block 0 from Block0Ptr (never dereferencing InPtr + 0), and on
    // iter >= 1 it refreshes its block-0 source from the advanced
    // InPtr so [InPtr + k*stride] reads straight from AInput. This
    // eliminates the LBatchBytes - BLOCK_SIZE byte memcpy the old
    // LScratch reshape had to do on every fused decrypt batch.
    //
    // The `InPtr - BLOCK_SIZE` pointer is never dereferenced at offset 0 by
    // the kernel (guaranteed by the IOcbKernel.ProcessBlocks contract for
    // Block0Ptr); the address itself only feeds register arithmetic and the
    // `[InPtr + 16..]` loads, all of which resolve inside AInput.
    LBlock0Ptr := @FMainBlock[0];
    LInPtr := PByte(@AInput[AInOff]) - BLOCK_SIZE;
    FOcbKernel.ProcessBlocks(LInPtr, @AOutput[AOutOff],
      @FOffsetMAIN[0], @FChecksum[0], @FLTableFlat[0],
      LBlock0Ptr, ABlockCount, LStartBlockCount);

    // Refresh the BLOCK_SIZE lookahead from the tail of the consumed
    // AInput window so subsequent calls (fused, 8-wide, or scalar)
    // observe the identical FMainBlock prefix the per-byte loop would
    // have produced after consuming LBatchBytes bytes.
    System.Move(AInput[AInOff + LBatchBytes - BLOCK_SIZE], FMainBlock[0],
      BLOCK_SIZE);
  end
  else
  begin
    // Decrypt fallback (FMacSize < BLOCK_SIZE): the lookahead straddles
    // a block boundary so we can't splice two pointers; stage the same
    // sliding-window buffer the 8-wide scalar path uses and feed the
    // kernel a single contiguous source. Block0Ptr aliases InPtr here
    // (kernel reads iter-0 block 0 from LScratch[0..15] just like any
    // later iteration).
    System.Move(FMainBlock[0], LScratch[0], FMacSize);
    System.Move(AInput[AInOff], LScratch[FMacSize], LBatchBytes - FMacSize);

    LInPtr := @LScratch[0];
    LBlock0Ptr := LInPtr;
    FOcbKernel.ProcessBlocks(LInPtr, @AOutput[AOutOff],
      @FOffsetMAIN[0], @FChecksum[0], @FLTableFlat[0],
      LBlock0Ptr, ABlockCount, LStartBlockCount);

    System.Move(AInput[AInOff + LBatchBytes - FMacSize], FMainBlock[0],
      FMacSize);
  end;
end;

procedure TOcbBlockCipher.ProcessEightBlocksBulk(
  const AInput: TCryptoLibByteArray; AInOff: Int32;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32);
var
  LOffsets: array [0 .. 127] of Byte;
  LScratch: array [0 .. 127] of Byte;
  LI: Int32;
  LLSub: TCryptoLibByteArray;
begin
  // Evolve the per-block offset ladder the exact same way ProcessMainBlock
  // would: FOffsetMAIN_{k+1} = FOffsetMAIN_k XOR L[ntz(count+1)]. Materialise
  // all 8 offsets consecutively in LOffsets[0..127] so the downstream XORs
  // run as a single 128-byte sweep via TByteUtilities.Xor.
  for LI := 0 to 7 do
  begin
    System.Inc(FMainBlockCount);
    LLSub := GetLSub(OCB_ntz(FMainBlockCount));
    TByteUtilities.&Xor(16, PByte(FOffsetMAIN), PByte(LLSub), PByte(FOffsetMAIN));
    System.Move(FOffsetMAIN[0], LOffsets[LI * BLOCK_SIZE], BLOCK_SIZE);
  end;

  if FForEncryption then
  begin
    // FChecksum folds every plaintext block (order does not matter; XOR is
    // commutative). Eight 16-byte folds keep us on the existing XorTo path.
    for LI := 0 to 7 do
      TByteUtilities.XorTo(BLOCK_SIZE, AInput, AInOff + LI * BLOCK_SIZE,
        FChecksum, 0);

    // LScratch := AInput XOR LOffsets (one 128-byte XOR)
    TByteUtilities.&Xor(128, PByte(AInput) + AInOff, PByte(@LOffsets[0]), PByte(@LScratch[0]));

    // In-place bulk encrypt (aliasing-safe per IBulkBlockCipher contract).
    FMainBulk.ProcessBlocks(@LScratch[0], @LScratch[0], 8);

    // AOutput := LScratch XOR LOffsets (one 128-byte XOR)
    TByteUtilities.&Xor(128, PByte(@LScratch[0]), PByte(@LOffsets[0]), PByte(AOutput) + AOutOff);
  end
  else
  begin
    // Decrypt-side ciphertext stream = FMacSize-byte lookahead held in
    // FMainBlock[0..FMacSize-1] followed by (128 - FMacSize) fresh AInput
    // bytes. This mirrors the sliding-window the per-byte path walks; the
    // 8-block batch leaves the lookahead slot refreshed from the tail of
    // the consumed AInput range.
    System.Move(FMainBlock[0], LScratch[0], FMacSize);
    System.Move(AInput[AInOff], LScratch[FMacSize], 128 - FMacSize);

    TByteUtilities.&Xor(128, PByte(@LScratch[0]), PByte(@LOffsets[0]), PByte(@LScratch[0]));

    FMainBulk.ProcessBlocks(@LScratch[0], @LScratch[0], 8);

    TByteUtilities.&Xor(128, PByte(@LScratch[0]), PByte(@LOffsets[0]), PByte(@LScratch[0]));

    System.Move(LScratch[0], AOutput[AOutOff], 128);

    // Fold the freshly recovered plaintext blocks into FChecksum directly
    // from AOutput; folding from LScratch would need a PByte-aware XOR
    // helper. XorTo over TCryptoLibByteArray is enough here.
    for LI := 0 to 7 do
      TByteUtilities.XorTo(BLOCK_SIZE, AOutput, AOutOff + LI * BLOCK_SIZE,
        FChecksum, 0);

    // Refresh the FMacSize lookahead from the tail of the AInput window so
    // subsequent calls (bulk or scalar) see identical state to the per-byte
    // loop after 128 consumed bytes.
    System.Move(AInput[AInOff + 128 - FMacSize], FMainBlock[0], FMacSize);
  end;
end;

function TOcbBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LTag, LPad: TCryptoLibByteArray;
  LResultLen: Int32;
begin
  LTag := nil;
  if (not FForEncryption) then
  begin
    if (FMainBlockPos < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    FMainBlockPos := FMainBlockPos - FMacSize;
    System.SetLength(LTag, FMacSize);
    System.Move(FMainBlock[FMainBlockPos], LTag[0], FMacSize);
  end;

  if (FHashBlockPos > 0) then
  begin
    OCB_extend(FHashBlock, FHashBlockPos);
    UpdateHASH(FL_Asterisk);
  end;

  if (FMainBlockPos > 0) then
  begin
    if FForEncryption then
    begin
      OCB_extend(FMainBlock, FMainBlockPos);
      TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FMainBlock), PByte(FChecksum));
    end;

    TByteUtilities.&Xor(16, PByte(FOffsetMAIN), PByte(FL_Asterisk), PByte(FOffsetMAIN));

    System.SetLength(LPad, 16);
    FHashCipher.ProcessBlock(FOffsetMAIN, 0, LPad, 0);

    TByteUtilities.&Xor(16, PByte(FMainBlock), PByte(LPad), PByte(FMainBlock));

    TCheck.OutputLength(AOutput, AOutOff, FMainBlockPos, SOutputBufferTooShort);
    System.Move(FMainBlock[0], AOutput[AOutOff], FMainBlockPos);

    if (not FForEncryption) then
    begin
      OCB_extend(FMainBlock, FMainBlockPos);
      TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FMainBlock), PByte(FChecksum));
    end;
  end;

  TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FOffsetMAIN), PByte(FChecksum));
  TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FL_Dollar), PByte(FChecksum));
  FHashCipher.ProcessBlock(FChecksum, 0, FChecksum, 0);
  TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FSum), PByte(FChecksum));

  System.SetLength(FMacBlock, FMacSize);
  System.Move(FChecksum[0], FMacBlock[0], FMacSize);

  LResultLen := FMainBlockPos;

  if FForEncryption then
  begin
    TCheck.OutputLength(AOutput, AOutOff, LResultLen + FMacSize, SOutputBufferTooShort);

    System.Move(FMacBlock[0], AOutput[AOutOff + LResultLen], FMacSize);
    LResultLen := LResultLen + FMacSize;
  end
  else
  begin
    if (not TArrayUtilities.FixedTimeEquals(FMacBlock, LTag)) then
      raise EInvalidCipherTextCryptoLibException.CreateResFmt(@SMacCheckFailed,
        ['OCB']);
  end;

  Reset(False);

  Result := LResultLen;
end;

procedure TOcbBlockCipher.Reset;
begin
  Reset(True);
end;

procedure TOcbBlockCipher.Clear(const ABs: TCryptoLibByteArray);
begin
  if (ABs <> nil) then
  begin
    TArrayUtilities.Fill(ABs, 0, System.Length(ABs), Byte(0));
  end;
end;

function TOcbBlockCipher.GetLSub(AN: Int32): TCryptoLibByteArray;
begin
  while (AN >= FL.Count) do
  begin
    FL.Add(OCB_double(FL[FL.Count - 1]));
  end;
  Result := FL[AN];
end;

procedure TOcbBlockCipher.EnsureLTableFlat(AMaxNtz: Int32);
var
  LI: Int32;
begin
  if (AMaxNtz < FLTableFlatCount) then
    Exit; // already materialised through AMaxNtz
  GetLSub(AMaxNtz); // grow FL to cover AMaxNtz
  for LI := FLTableFlatCount to AMaxNtz do
    System.Move(FL[LI][0], FLTableFlat[LI * BLOCK_SIZE], BLOCK_SIZE);
  FLTableFlatCount := AMaxNtz + 1;
end;

procedure TOcbBlockCipher.ProcessHashBlock;
begin
  System.Inc(FHashBlockCount);
  UpdateHASH(GetLSub(OCB_ntz(FHashBlockCount)));
  FHashBlockPos := 0;
end;

procedure TOcbBlockCipher.ProcessMainBlock(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32);
var
  LLSub: TCryptoLibByteArray;
begin
  TCheck.OutputLength(AOutput, AOutOff, BLOCK_SIZE, SOutputBufferTooShort);

  if FForEncryption then
  begin
    TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FMainBlock), PByte(FChecksum));
    FMainBlockPos := 0;
  end;

  System.Inc(FMainBlockCount);
  LLSub := GetLSub(OCB_ntz(FMainBlockCount));
  TByteUtilities.&Xor(16, PByte(FOffsetMAIN), PByte(LLSub), PByte(FOffsetMAIN));

  TByteUtilities.&Xor(16, PByte(FMainBlock), PByte(FOffsetMAIN), PByte(FMainBlock));
  FMainCipher.ProcessBlock(FMainBlock, 0, FMainBlock, 0);
  TByteUtilities.&Xor(16, PByte(FMainBlock), PByte(FOffsetMAIN), PByte(FMainBlock));

  System.Move(FMainBlock[0], AOutput[AOutOff], 16);

  if (not FForEncryption) then
  begin
    TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FMainBlock), PByte(FChecksum));
    System.Move(FMainBlock[BLOCK_SIZE], FMainBlock[0], FMacSize);
    FMainBlockPos := FMacSize;
  end;
end;

procedure TOcbBlockCipher.Reset(AClearMac: Boolean);
begin
  Clear(FHashBlock);
  Clear(FMainBlock);

  FHashBlockPos := 0;
  FMainBlockPos := 0;

  FHashBlockCount := 0;
  FMainBlockCount := 0;

  Clear(FOffsetHASH);
  Clear(FSum);
  System.Move(FOffsetMAIN_0[0], FOffsetMAIN[0], 16);
  Clear(FChecksum);

  if AClearMac then
    FMacBlock := nil;

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

procedure TOcbBlockCipher.UpdateHASH(const ALSub: TCryptoLibByteArray);
begin
  TByteUtilities.&Xor(16, PByte(FOffsetHASH), PByte(ALSub), PByte(FOffsetHASH));
  TByteUtilities.&Xor(16, PByte(FHashBlock), PByte(FOffsetHASH), PByte(FHashBlock));
  FHashCipher.ProcessBlock(FHashBlock, 0, FHashBlock, 0);
  TByteUtilities.&Xor(16, PByte(FSum), PByte(FHashBlock), PByte(FSum));
end;

class function TOcbBlockCipher.OCB_double(
  const ABlock: TCryptoLibByteArray): TCryptoLibByteArray;
var
  LCarry: Int32;
begin
  System.SetLength(Result, 16);
  LCarry := ShiftLeft(ABlock, Result);
  Result[15] := Result[15] xor Byte($87 shr ((1 - LCarry) shl 3));
end;

class procedure TOcbBlockCipher.OCB_extend(const ABlock: TCryptoLibByteArray;
  APos: Int32);
begin
  ABlock[APos] := Byte($80);
  System.Inc(APos);
  while (APos < 16) do
  begin
    ABlock[APos] := 0;
    System.Inc(APos);
  end;
end;

class function TOcbBlockCipher.ShiftLeft(const ABlock,
  AOutput: TCryptoLibByteArray): Int32;
var
  LI: Int32;
  LBit, LB: UInt32;
begin
  LI := 16;
  LBit := 0;
  while (LI > 0) do
  begin
    System.Dec(LI);
    LB := UInt32(ABlock[LI]);
    AOutput[LI] := Byte((LB shl 1) or LBit);
    LBit := (LB shr 7) and 1;
  end;
  Result := Int32(LBit);
end;

end.
