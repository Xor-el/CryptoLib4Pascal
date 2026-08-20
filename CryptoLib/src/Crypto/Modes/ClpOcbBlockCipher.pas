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
  ClpKeyParameter,
  ClpBlockCipherBulkUtilities,
  ClpCipherModeParameterUtilities,
  ClpAbstractAeadCipher,
  ClpAbstractAeadBlockCipher,
  ClpCheck,
  ClpBitOperations,
  ClpByteUtilities,
  ClpGaloisFieldUtilities,
  ClpArrayUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SHashCipherNil = 'hash cipher cannot be nil';
  SMainCipherNil = 'main cipher cannot be nil';
  SBlockSizeRequired = 'must have a block size of %d';
  SCiphersMustMatch = 'hashCipher and mainCipher must be the same algorithm';
  SInvalidParameters = 'invalid parameters passed to %s';
  SIVTooLong = 'IV must be no more than 15 bytes';
  SCannotChangeEncState = 'cannot change encrypting state without providing key';
  SKeyMustBeSpecified = 'key must be specified in initial packet';
  SDataTooShort = 'data too short';
  SOutputBufferTooShort = 'output buffer too short';
  SInputBufferTooShort = 'input buffer too short';

type
  TOcbBlockCipher = class(TAbstractAeadBlockCipher, IOcbBlockCipher,
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

    FL: TList<TCryptoLibByteArray>;
    FL_Asterisk, FL_Dollar: TCryptoLibByteArray;

    // Cached contiguous snapshot of FL[0..FLTableFlatCount-1] handed to the
    // fused kernel. FL is key-stable and only ever grows, so the flat copy is
    // materialised lazily (EnsureLTableFlat) and reused across every batch and
    // ProcessBytes call; it is invalidated only on Init, when FL is rebuilt for
    // a new key.
    FLTableFlat: TCryptoLibByteArray;
    FLTableFlatCount: Int32;

    // Persisted KTop cache key (the masked nonce whose top bits produced the
    // cached FStretch). Owned 16-byte buffer; FKTopValid marks it live. Both are
    // invalidated on rekey so a new key never reuses a stale KTop.
    FKTopInput: TCryptoLibByteArray;
    FKTopValid: Boolean;
    FStretch: TCryptoLibByteArray;
    FInitialOffsetMain: TCryptoLibByteArray;

    // Reused 16-byte per-message scratch (allocated once, overwritten each use):
    // the nonce builder, the KTop keystream, the decrypt tag copy and the
    // final-block pad.
    FNonceScratch: TCryptoLibByteArray;
    FKTopScratch: TCryptoLibByteArray;
    FTagScratch: TCryptoLibByteArray;
    FPadScratch: TCryptoLibByteArray;

    FHashBlock, FMainBlock: TCryptoLibByteArray;
    FHashBlockPos, FMainBlockPos: Int32;
    FHashBlockCount, FMainBlockCount: Int64;
    FOffsetHash: TCryptoLibByteArray;
    FSum: TCryptoLibByteArray;
    FOffsetMain: TCryptoLibByteArray;
    FChecksum: TCryptoLibByteArray;

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

  strict protected
    function ProcessNonce(const AN: TCryptoLibByteArray): Int32; virtual;
    procedure Clear(const ABs: TCryptoLibByteArray); virtual;
    function GetLSub(AN: Int32): TCryptoLibByteArray; virtual;
    procedure ProcessHashBlock(); virtual;
    procedure ProcessMainBlock(const AOutput: TCryptoLibByteArray; AOutOff: Int32); virtual;
    procedure Reset(AClearMac: Boolean); reintroduce; overload; virtual;
    procedure UpdateHASH(const ALSub: TCryptoLibByteArray); virtual;

    function GetAlgorithmName: String; override;
    function GetModeName: String; override;
    function GetBufferedLength(): Int32; override;
    procedure WipeKeyMaterial(); override;

  public
    constructor Create(const AHashCipher, AMainCipher: IBlockCipher);
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); override;
    procedure InitPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32); override;

    procedure ProcessAadByte(AInput: Byte); override;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); override;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;

    /// <summary>One-shot seal/open after InitPacket/Init: drives the whole message
    /// through ProcessBytes + DoFinal and, on a decrypt MAC failure, wipes the
    /// plaintext output before re-raising (no unverified plaintext leaves).</summary>
    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;

    procedure Reset(); overload; override;
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
  FBlockSize := BLOCK_SIZE;
  FUnderlyingCipher := FMainCipher;

  System.SetLength(FStretch, 24);
  System.SetLength(FInitialOffsetMain, 16);
  System.SetLength(FOffsetMain, 16);
  // Owned KTop cache key + reused per-message scratch, allocated once.
  System.SetLength(FKTopInput, 16);
  FKTopValid := False;
  System.SetLength(FNonceScratch, 16);
  System.SetLength(FKTopScratch, 16);
  System.SetLength(FPadScratch, 16);
  FL := TList<TCryptoLibByteArray>.Create;
  System.SetLength(FLTableFlat, FUSED_LTABLE_ENTRIES * BLOCK_SIZE);
  FLTableFlatCount := 0;
end;

destructor TOcbBlockCipher.Destroy;
var
  LI: Int32;
begin
  // Wipe the key-derived L-table entries before releasing the list; the base
  // destructor then wipes the remaining secret arrays (WipeKeyMaterial) and
  // FLastKey.
  if FL <> nil then
  begin
    for LI := 0 to FL.Count - 1 do
      TArrayUtilities.Fill(FL[LI], 0, System.Length(FL[LI]), Byte(0));
  end;
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

function TOcbBlockCipher.GetModeName: String;
begin
  Result := 'OCB';
end;

function TOcbBlockCipher.GetBufferedLength: Int32;
begin
  Result := FMainBlockPos;
end;

procedure TOcbBlockCipher.WipeKeyMaterial;
begin
  // FL entries are wiped in the destructor (before the list is freed); here we
  // clear the remaining key-derived / plaintext-bearing scratch arrays.
  TArrayUtilities.Fill(FL_Asterisk, 0, System.Length(FL_Asterisk), Byte(0));
  TArrayUtilities.Fill(FL_Dollar, 0, System.Length(FL_Dollar), Byte(0));
  TArrayUtilities.Fill(FLTableFlat, 0, System.Length(FLTableFlat), Byte(0));
  TArrayUtilities.Fill(FStretch, 0, System.Length(FStretch), Byte(0));
  TArrayUtilities.Fill(FKTopInput, 0, System.Length(FKTopInput), Byte(0));
  FKTopValid := False;
  TArrayUtilities.Fill(FNonceScratch, 0, System.Length(FNonceScratch), Byte(0));
  TArrayUtilities.Fill(FKTopScratch, 0, System.Length(FKTopScratch), Byte(0));
  TArrayUtilities.Fill(FPadScratch, 0, System.Length(FPadScratch), Byte(0));
  TArrayUtilities.Fill(FTagScratch, 0, System.Length(FTagScratch), Byte(0));
  TArrayUtilities.Fill(FInitialOffsetMain, 0, System.Length(FInitialOffsetMain), Byte(0));
  TArrayUtilities.Fill(FOffsetMain, 0, System.Length(FOffsetMain), Byte(0));
  TArrayUtilities.Fill(FOffsetHash, 0, System.Length(FOffsetHash), Byte(0));
  TArrayUtilities.Fill(FSum, 0, System.Length(FSum), Byte(0));
  TArrayUtilities.Fill(FChecksum, 0, System.Length(FChecksum), Byte(0));
  TArrayUtilities.Fill(FHashBlock, 0, System.Length(FHashBlock), Byte(0));
  TArrayUtilities.Fill(FMainBlock, 0, System.Length(FMainBlock), Byte(0));
  TArrayUtilities.Fill(FMacBlock, 0, System.Length(FMacBlock), Byte(0));
end;

procedure TOcbBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LOldForEncryption: Boolean;
  LKeyParameter: IKeyParameter;
  LChoice: TCipherAeadChoice;
  LN: TCryptoLibByteArray;
  LBottom, LBits, LBytes, LI: Int32;
  LB1, LB2: UInt32;
  LFusedDirection: TCipherKernelDirection;
  LSameKey, LSameKeyDir, LNeedReKey: Boolean;
begin
  LOldForEncryption := FForEncryption;
  FForEncryption := AForEncryption;
  // Invalidate the previous tag in place (keep the buffer; DoFinal sizes it).
  TArrayUtilities.Fill(FMacBlock, 0, System.Length(FMacBlock), Byte(0));

  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['OCB']);

  if (not LChoice.IsAead) and (LChoice.CipherKey <> nil) and
    (LChoice.KeyParameter = nil) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['OCB']);

  LN := LChoice.Nonce;
  CheckNonceReuse(FForEncryption, LN, LChoice.KeyParameter);
  FLastNonce := System.Copy(LN);

  FInitialAssociatedText := LChoice.AssociatedText;
  LKeyParameter := LChoice.KeyParameter;

  // Nonce-only rotation is the hot AEAD path: when the key (and, for the main
  // cipher / fused kernel, the direction) is unchanged, the key schedules, the
  // L table and the kernel binding all stay valid and are not recomputed.
  if LKeyParameter <> nil then
    LNeedReKey := NeedsReKey(LKeyParameter)
  else
  begin
    // nil key reuses the established key; there must be one.
    if not FKeyReady then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
    LNeedReKey := False;
  end;
  LSameKey := not LNeedReKey;
  LSameKeyDir := LSameKey and (LOldForEncryption = AForEncryption);

  if LChoice.IsAead then
    FMacSize := ValidateAeadMacSizeBits(LChoice.MacSizeBits, 64, 128, 8)
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

  if (LKeyParameter <> nil) and (not LSameKeyDir) then
  begin
    if not LSameKey then
    begin
      FHashCipher.Init(True, LKeyParameter);
      FKTopValid := False;
    end;
    FMainCipher.Init(AForEncryption, LKeyParameter);
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
  if not LSameKeyDir then
  begin
    TBlockCipherBulkUtilities.TryResolveBulkCipher(FMainCipher, FMainBulk);

    // Resolve a fused OCB kernel via the open factory registry; the
    // first factory whose TryCreate accepts the cipher / direction pair
    // wins, and the result stays bound until the key or direction changes
    // (the engine schedule the kernel captured is untouched until then).
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
  end;

  if not LSameKey then
  begin
    System.SetLength(FL_Asterisk, 16);
    TArrayUtilities.Fill(FL_Asterisk, 0, 16, Byte(0));
    FHashCipher.ProcessBlock(FL_Asterisk, 0, FL_Asterisk, 0);

    FL_Dollar := OCB_double(FL_Asterisk);

    FL.Clear;
    FL.Add(OCB_double(FL_Dollar));
    FLTableFlatCount := 0; // FL rebuilt for the new key; drop the flattened cache
  end;

  // All key-dependent schedules are rebuilt; mark the key committed and ready.
  if LNeedReKey then
    CommitKey(LKeyParameter);

  LBottom := ProcessNonce(LN);

  LBits := LBottom mod 8;
  LBytes := LBottom div 8;
  if (LBits = 0) then
  begin
    System.Move(FStretch[LBytes], FInitialOffsetMain[0], 16);
  end
  else
  begin
    for LI := 0 to 15 do
    begin
      LB1 := UInt32(FStretch[LBytes]);
      System.Inc(LBytes);
      LB2 := UInt32(FStretch[LBytes]);
      FInitialOffsetMain[LI] := Byte((LB1 shl LBits) or (LB2 shr (8 - LBits)));
    end;
  end;

  FHashBlockPos := 0;
  FMainBlockPos := 0;

  FHashBlockCount := 0;
  FMainBlockCount := 0;

  System.SetLength(FOffsetHash, 16);
  TArrayUtilities.Fill(FOffsetHash, 0, 16, Byte(0));
  System.SetLength(FSum, 16);
  TArrayUtilities.Fill(FSum, 0, 16, Byte(0));
  System.Move(FInitialOffsetMain[0], FOffsetMain[0], 16);
  System.SetLength(FChecksum, 16);
  TArrayUtilities.Fill(FChecksum, 0, 16, Byte(0));

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

procedure TOcbBlockCipher.InitPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32);
var
  LOldForEncryption, LSameKey, LSameKeyDir, LNeedReKey: Boolean;
  LKeyParam: IKeyParameter;
  LMainLen, LBottom, LBits, LBytes, LI: Int32;
  LB1, LB2: UInt32;
  LFusedDirection: TCipherKernelDirection;
begin
  LOldForEncryption := FForEncryption;
  FForEncryption := AForEncryption;
  // Invalidate the previous tag in place (keep the buffer; DoFinal sizes it).
  TArrayUtilities.Fill(FMacBlock, 0, System.Length(FMacBlock), Byte(0));

  CheckNonceReuseRaw(FForEncryption, ANonce, AKey);

  if (FLastNonce = nil) or (System.Length(FLastNonce) <> System.Length(ANonce)) then
    System.SetLength(FLastNonce, System.Length(ANonce));
  System.Move(ANonce[0], FLastNonce[0], System.Length(ANonce));

  FInitialAssociatedText := AAad;

  if AKey <> nil then
    LNeedReKey := NeedsReKeyRaw(AKey)
  else
  begin
    // nil key reuses the established key; there must be one.
    if not FKeyReady then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
    LNeedReKey := False;
  end;
  LSameKey := not LNeedReKey;
  LSameKeyDir := LSameKey and (LOldForEncryption = AForEncryption);

  FMacSize := ValidateAeadMacSizeBits(AMacSizeBits, 64, 128, 8);

  System.SetLength(FHashBlock, 16);
  TArrayUtilities.Fill(FHashBlock, 0, 16, Byte(0));
  if FForEncryption then
    LMainLen := BLOCK_SIZE
  else
    LMainLen := BLOCK_SIZE + FMacSize;
  if (FMainBlock = nil) or (System.Length(FMainBlock) <> LMainLen) then
    System.SetLength(FMainBlock, LMainLen);
  TArrayUtilities.Fill(FMainBlock, 0, LMainLen, Byte(0));

  if (System.Length(ANonce) > 15) then
    raise EArgumentCryptoLibException.CreateRes(@SIVTooLong);

  if (AKey <> nil) and (not LSameKeyDir) then
    LKeyParam := TKeyParameter.Create(AKey) as IKeyParameter
  else
    LKeyParam := nil;

  if (LKeyParam <> nil) then
  begin
    if not LSameKey then
    begin
      FHashCipher.Init(True, LKeyParam);
      FKTopValid := False;
    end;
    FMainCipher.Init(AForEncryption, LKeyParam);
  end
  else if (LOldForEncryption <> AForEncryption) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SCannotChangeEncState);
  end;

  if not LSameKeyDir then
  begin
    TBlockCipherBulkUtilities.TryResolveBulkCipher(FMainCipher, FMainBulk);

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
      if (FOcbKernelMinBlocks <= 0) or
        (FUSED_BATCH_BLOCKS mod FOcbKernelMinBlocks <> 0) then
      begin
        FOcbKernel := nil;
        FOcbKernelMinBlocks := 0;
      end;
    end;
  end;

  if not LSameKey then
  begin
    System.SetLength(FL_Asterisk, 16);
    TArrayUtilities.Fill(FL_Asterisk, 0, 16, Byte(0));
    FHashCipher.ProcessBlock(FL_Asterisk, 0, FL_Asterisk, 0);

    FL_Dollar := OCB_double(FL_Asterisk);

    FL.Clear;
    FL.Add(OCB_double(FL_Dollar));
    FLTableFlatCount := 0;
  end;

  // All key-dependent schedules are rebuilt; mark the key committed and ready.
  if LNeedReKey then
    CommitKeyRaw(AKey);

  LBottom := ProcessNonce(ANonce);

  LBits := LBottom mod 8;
  LBytes := LBottom div 8;
  if (LBits = 0) then
  begin
    System.Move(FStretch[LBytes], FInitialOffsetMain[0], 16);
  end
  else
  begin
    for LI := 0 to 15 do
    begin
      LB1 := UInt32(FStretch[LBytes]);
      System.Inc(LBytes);
      LB2 := UInt32(FStretch[LBytes]);
      FInitialOffsetMain[LI] := Byte((LB1 shl LBits) or (LB2 shr (8 - LBits)));
    end;
  end;

  FHashBlockPos := 0;
  FMainBlockPos := 0;

  FHashBlockCount := 0;
  FMainBlockCount := 0;

  System.SetLength(FOffsetHash, 16);
  TArrayUtilities.Fill(FOffsetHash, 0, 16, Byte(0));
  System.SetLength(FSum, 16);
  TArrayUtilities.Fill(FSum, 0, 16, Byte(0));
  System.Move(FInitialOffsetMain[0], FOffsetMain[0], 16);
  System.SetLength(FChecksum, 16);
  TArrayUtilities.Fill(FChecksum, 0, 16, Byte(0));

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

function TOcbBlockCipher.ProcessNonce(const AN: TCryptoLibByteArray): Int32;
var
  LBottom, LI: Int32;
begin
  // Build the masked nonce into the reused scratch (zeroed first: the leading
  // pad bytes must be 0 before the nonce is placed in the tail).
  TArrayUtilities.Fill(FNonceScratch, 0, 16, Byte(0));
  System.Move(AN[0], FNonceScratch[16 - System.Length(AN)], System.Length(AN));
  FNonceScratch[0] := Byte(FMacSize shl 4);
  FNonceScratch[15 - System.Length(AN)] := FNonceScratch[15 - System.Length(AN)] or 1;

  LBottom := FNonceScratch[15] and $3F;
  FNonceScratch[15] := FNonceScratch[15] and Byte($C0);

  // KTop cache: recompute FStretch only when the masked-nonce top bits changed.
  // On a miss, persist the key into the owned FKTopInput (copy, so the scratch
  // stays free to be rebuilt next call) and mark it live.
  if (not FKTopValid) or (not TArrayUtilities.AreEqual(FNonceScratch, FKTopInput)) then
  begin
    System.Move(FNonceScratch[0], FKTopInput[0], 16);
    FKTopValid := True;
    FHashCipher.ProcessBlock(FKTopInput, 0, FKTopScratch, 0);
    System.Move(FKTopScratch[0], FStretch[0], 16);
    for LI := 0 to 7 do
    begin
      FStretch[16 + LI] := Byte(FKTopScratch[LI] xor FKTopScratch[LI + 1]);
    end;
  end;

  Result := LBottom;
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
      @FOffsetMain[0], @FChecksum[0], @FLTableFlat[0],
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
      @FOffsetMain[0], @FChecksum[0], @FLTableFlat[0],
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
      @FOffsetMain[0], @FChecksum[0], @FLTableFlat[0],
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
  // would: FOffsetMain_{k+1} = FOffsetMain_k XOR L[ntz(count+1)]. Materialise
  // all 8 offsets consecutively in LOffsets[0..127] so the downstream XORs
  // run as a single 128-byte sweep via TByteUtilities.Xor.
  for LI := 0 to 7 do
  begin
    System.Inc(FMainBlockCount);
    LLSub := GetLSub(OCB_ntz(FMainBlockCount));
    TByteUtilities.&Xor(16, PByte(FOffsetMain), PByte(LLSub), PByte(FOffsetMain));
    System.Move(FOffsetMain[0], LOffsets[LI * BLOCK_SIZE], BLOCK_SIZE);
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
  LResultLen: Int32;
begin
  if (not FForEncryption) then
  begin
    if (FMainBlockPos < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    FMainBlockPos := FMainBlockPos - FMacSize;
    // Reused tag copy, sized to the current MAC length.
    System.SetLength(FTagScratch, FMacSize);
    System.Move(FMainBlock[FMainBlockPos], FTagScratch[0], FMacSize);
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

    TByteUtilities.&Xor(16, PByte(FOffsetMain), PByte(FL_Asterisk), PByte(FOffsetMain));

    FHashCipher.ProcessBlock(FOffsetMain, 0, FPadScratch, 0);

    TByteUtilities.&Xor(16, PByte(FMainBlock), PByte(FPadScratch), PByte(FMainBlock));

    TCheck.OutputLength(AOutput, AOutOff, FMainBlockPos, SOutputBufferTooShort);
    System.Move(FMainBlock[0], AOutput[AOutOff], FMainBlockPos);

    if (not FForEncryption) then
    begin
      OCB_extend(FMainBlock, FMainBlockPos);
      TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FMainBlock), PByte(FChecksum));
    end;
  end;

  TByteUtilities.&Xor(16, PByte(FChecksum), PByte(FOffsetMain), PByte(FChecksum));
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
    if (not TArrayUtilities.FixedTimeEquals(FMacBlock, FTagScratch)) then
      RaiseMacCheckFailed();
  end;

  Reset(False);

  Result := LResultLen;
end;

function TOcbBlockCipher.ProcessPacket(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LLen, LPlainLen: Int32;
begin
  LLen := 0;
  if AInLen > 0 then
    LLen := ProcessBytes(AInput, AInOff, AInLen, AOutput, AOutOff);
  try
    Result := LLen + DoFinal(AOutput, AOutOff + LLen);
  except
    on EInvalidCipherTextCryptoLibException do
    begin
      // Decrypt MAC failure: wipe the tentative plaintext so none leaves the
      // call. The data-too-short guard yields LPlainLen <= 0 (nothing written).
      LPlainLen := AInLen - FMacSize;
      if LPlainLen > 0 then
        TArrayUtilities.Fill(AOutput, AOutOff, AOutOff + LPlainLen, Byte(0));
      raise;
    end;
  end;
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
  TByteUtilities.&Xor(16, PByte(FOffsetMain), PByte(LLSub), PByte(FOffsetMain));

  TByteUtilities.&Xor(16, PByte(FMainBlock), PByte(FOffsetMain), PByte(FMainBlock));
  FMainCipher.ProcessBlock(FMainBlock, 0, FMainBlock, 0);
  TByteUtilities.&Xor(16, PByte(FMainBlock), PByte(FOffsetMain), PByte(FMainBlock));

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

  Clear(FOffsetHash);
  Clear(FSum);
  System.Move(FInitialOffsetMain[0], FOffsetMain[0], 16);
  Clear(FChecksum);

  if AClearMac then
    Clear(FMacBlock);

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

procedure TOcbBlockCipher.UpdateHASH(const ALSub: TCryptoLibByteArray);
begin
  TByteUtilities.&Xor(16, PByte(FOffsetHash), PByte(ALSub), PByte(FOffsetHash));
  TByteUtilities.&Xor(16, PByte(FHashBlock), PByte(FOffsetHash), PByte(FHashBlock));
  FHashCipher.ProcessBlock(FHashBlock, 0, FHashBlock, 0);
  TByteUtilities.&Xor(16, PByte(FSum), PByte(FHashBlock), PByte(FSum));
end;

class function TOcbBlockCipher.OCB_double(
  const ABlock: TCryptoLibByteArray): TCryptoLibByteArray;
begin
  System.SetLength(Result, 16);
  TGaloisFieldUtilities.DoubleBlock(ABlock, Result);
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


end.
