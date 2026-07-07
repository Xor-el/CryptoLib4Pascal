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

unit ClpGcmBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Math,
  SysUtils,
  ClpIBlockCipher,
  ClpIGcmBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIAeadParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpIGcmMultiplier,
  ClpIGcmExponentiator,
  ClpGcmUtilities,
  ClpGhashSimd,
  ClpBasicGcmExponentiator,
  ClpTables4kGcmMultiplier,
  ClpIBulkBlockCipher,
  ClpBlockCipherBulkUtilities,
  ClpByteUtilities,
  ClpFusedKernelTypes,
  ClpIFusedGcmKernel,
  ClpFusedKernelRegistry,
  ClpFusedKernelDefaults, // registers in-tree fused AEAD kernel factories
  ClpPack,
  ClpCheck,
  ClpBasicGcmMultiplier,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCipherBlockSizeRequired = 'cipher required with a block size of %d';
  SInvalidParameters = 'invalid parameters passed to %s';
  SInvalidMacSize = 'invalid value for MAC size: %d';
  SIVMustBeAtLeastOneByte = 'IV must be at least 1 byte';
  SCannotReuseNonce = 'cannot reuse nonce for %s encryption';
  SKeyMustBeSpecified = 'key must be specified in initial init';
  STooManyBlocks = 'attempt to process too many blocks';
  SGcmCannotReuse = 'GCM cipher cannot be reused for encryption';
  SGcmNeedsInit = 'GCM cipher needs to be initialized';
  SOutputBufferTooShort = 'output buffer too short';
  SInputBufferTooShort = 'input buffer too short';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in %s failed';
  SGcmBlockPathNotSupported = 'GCM %s-block path is not available on this platform';
  SGcmBlockHStateMissing = 'GCM fused %s-block multiplier state is not initialized';
  SGcmDecryptBadLimit = 'invalid limit for GCM %s-block decrypt';

type
  /// <summary>
  /// Galois/Counter Mode (GCM): authenticated encryption combining CTR-mode encryption over a block
  /// cipher with GHASH (<c>IBlockCipher</c> block size must be 128 bits; typically AES).
  /// </summary>
  /// <remarks>
  /// Treat the IV / nonce as unique for each message under a fixed key. Counter-based GCM fails
  /// catastrophically if a (key, IV) pair is ever reused; callers must generate IVs with a strong
  /// RNG or a strictly monotonic counter (the construction enforces several runtime checks, but
  /// correct protocol design is mandatory).
  /// </remarks>
  TGcmBlockCipher = class(TInterfacedObject, IGcmBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    BlockSize: Int32 = 16;

  public
    class function CreateGcmMultiplier(): IGcmMultiplier; static;
    /// <summary>
    /// True when the fused four-block SIMD path may run: hardware shuffled GHASH,
    /// batched counter AES, and a packed 16-byte vector layout.
    /// </summary>
    class function IsFourWaySupported: Boolean; static;
    /// <summary>
    /// True when the fused eight-block SIMD path may run (128-byte CTR batch + wider GHASH).
    /// </summary>
    class function IsEightWaySupported: Boolean; static;

  strict private

  var
    FCipher: IBlockCipher;
    // Cached once per key Init; non-nil when the underlying engine
    // exposes the generic IBulkBlockCipher capability. Drives the
    // non-fused 4/8-block CTR dispatchers (GetNextCtrBlocks4/8).
    FBulkCipher: IBulkBlockCipher;
    // Fused CTR+GHASH kernel resolved via TFusedKernelRegistry at Init
    // time. Non-nil only when an accelerator factory accepts the
    // underlying cipher + direction and the fused gate is open (always nil
    // off-SIMD; IFusedGcmKernel is arch-neutral).
    FGcmKernel: IFusedGcmKernel;
    FGcmKernelMinBlocks: Int32;
    FMultiplier: IGcmMultiplier;
    FExp: IGcmExponentiator;

    FForEncryption: Boolean;
    FInitialised: Boolean;
    FMacSize: Int32;
    FLastKey: TCryptoLibByteArray;
    FNonce: TCryptoLibByteArray;
    FInitialAssociatedText: TCryptoLibByteArray;
    FH: TCryptoLibByteArray;
    FJ0: TCryptoLibByteArray;

    FBufBlock: TCryptoLibByteArray;
    FMacBlock: TCryptoLibByteArray;
    FS: TCryptoLibByteArray;
    FS_at: TCryptoLibByteArray;
    FS_atPre: TCryptoLibByteArray;
    FCounter: TCryptoLibByteArray;
    FCounter32: UInt32;
    FBlocksRemaining: UInt32;
    FBufOff: Int32;
    FTotalLength: UInt64;
    FAtBlock: TCryptoLibByteArray;
    FAtBlockPos: Int32;
    FAtLength: UInt64;
    FAtLengthPre: UInt64;
    /// <summary>HPow limbs H^8..H^1 (128 bytes) for fused GHASH; indices 64..112 hold H^4..H^1 for the four-block path; nil if path off.</summary>
    FHPow: TCryptoLibByteArray;
    /// <summary>Reused 128-byte buffer for batched CTR keystream (first 64 bytes used by four-block fused path).</summary>
    FWorkCtr: TCryptoLibByteArray;
    /// <summary>Second 128-byte keystream buffer for the pipeline-by-one path (look-ahead batch). nil if fused paths are off.</summary>
    FWorkCtrAhead: TCryptoLibByteArray;

    // ---------------------------------------------------------------------
    // GHASH primitives and scalar triple-XOR helpers.
    // ---------------------------------------------------------------------
    class procedure GcmReverse16(const ASrc, ADst: PByte); static;
    procedure GhashFourShuffledBlocks(PC0, PC16, PC32, PC48: PByte);
    procedure GhashEightShuffledBlocks(PBase: PByte);
    /// <summary>
    /// Big-endian counter-word packing for `GetNextCtrBlocks8`'s SIMD fast path.
    /// Advances `ACounter32` by 8 and writes the eight 16-byte counter blocks
    /// (pre-AES form) into `ABlocks[0..127]`. Also mutates `ACounter[12..15]` in
    /// place (the block-index tail) as a side effect of the byte-packing strategy.
    /// </summary>
    class procedure FillCtr8BlocksRaw(const ACounter: TCryptoLibByteArray;
      var ACounter32: UInt32; const ABlocks: TCryptoLibByteArray); static;

    // ---------------------------------------------------------------------
    // Fused / pipelined batch routines (the GCM performance core).
    // Each routine consumes 64 B (4-way) or 128 B (8-way) of plaintext /
    // ciphertext per inner iteration and interleaves AES counter-keystream
    // generation with GHASH on the prior batch; AForEncrypt chooses which
    // buffer feeds GHASH (output on encrypt, input on decrypt).
    // ---------------------------------------------------------------------
    /// <summary>Single-batch fused 4-way (64-byte) GCM step: generate 4 CTR blocks,
    /// XOR with plaintext/ciphertext, then 4-way GHASH. AForEncrypt selects whether
    /// GHASH consumes the output (encrypt) or the input (decrypt).</summary>
    procedure ProcessBlocks4Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32; AForEncrypt: Boolean);
    /// <summary>Single-batch fused 8-way (128-byte) GCM step: generate 8 CTR blocks,
    /// XOR with plaintext/ciphertext, then 8-way GHASH. AForEncrypt selects whether
    /// GHASH consumes the output (encrypt) or the input (decrypt).</summary>
    procedure ProcessBlocks8Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32; AForEncrypt: Boolean);
    /// <summary>Pipeline-by-one fused 4-way (64-byte) GCM step. For encrypt, pass
    /// ALimit=0; for decrypt, pass the caller's tail hold-back threshold. Encrypt
    /// does XOR-then-GHASH(output); decrypt does GHASH(input)-then-XOR.</summary>
    procedure ProcessBlocks4Pipelined(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32;
      ALimit: Int32; AForEncrypt: Boolean);
    /// <summary>Pipeline-by-one fused 8-way (128-byte) GCM step. Same tail / direction
    /// semantics as ProcessBlocks4Pipelined.</summary>
    procedure ProcessBlocks8Pipelined(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32;
      ALimit: Int32; AForEncrypt: Boolean);
    // =====================================================================
    // Fused block-cipher keystream + 8-way GHASH pipeline (provided by the
    // fused kernel registry; nil kernel -> not used, e.g. off-SIMD).
    // =====================================================================
    // This outer driver is arch-agnostic: pure Pascal batch orchestration
    // plus one call into an IFusedGcmKernel per 8-block stride. The kernel
    // fuses CTR-mode keystream generation with the GHASH multiply-reduce in a
    // single pass, interleaving the two at the instruction level so their
    // independent execution units overlap. How wide that interleave runs and
    // how it is scheduled against the available vector-register budget is a
    // backend detail hidden entirely behind the IFusedGcmKernel surface, so
    // this driver only ever sees the kernel interface.
    /// <summary>
    /// Pipelined GCM path driven by FGcmKernel (when a fused kernel is
    /// registered). Active when a fused CTR+GHASH kernel was acquired at Init; otherwise the
    /// caller falls back to ProcessBlocks8Pipelined. AForEncrypt selects
    /// direction: encrypt GHASHes the prior iteration's OUTPUT
    /// ciphertext, decrypt GHASHes the prior iteration's INPUT
    /// ciphertext. For encrypt pass ALimit=0; for decrypt pass the
    /// caller's tail hold-back threshold.
    /// </summary>
    procedure ProcessBlocks8FusedILP(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32;
      ALimit: Int32; AForEncrypt: Boolean);

    // ---------------------------------------------------------------------
    // Cipher-state setup / per-call initialization.
    // ---------------------------------------------------------------------
    procedure InitCipher();

    // ---------------------------------------------------------------------
    // Init() sub-steps (strict private). Init() is kept small by delegating
    // to these helpers in a fixed order. Each helper owns exactly one
    // concern so the GCM reinit contract remains easy to audit.
    // ---------------------------------------------------------------------
    /// <summary>Parse AParameters (IAeadParameters or IParametersWithIV), populate
    /// FInitialAssociatedText and FMacSize, and return the new nonce and key parameter.
    /// Raises on unsupported parameter types or invalid MAC sizes.</summary>
    procedure ResolveInitParameters(const AParameters: ICipherParameters;
      out ANewNonce: TCryptoLibByteArray; out AKeyParam: IKeyParameter);
    /// <summary>Encrypt-only guard that forbids reusing the same (nonce, key) pair.
    /// No-op on decrypt. Must be called before FNonce/FLastKey are updated.</summary>
    procedure CheckNonceReuse(AForEncryption: Boolean;
      const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);
    /// <summary>Rekey path: initialize the underlying block cipher, compute the hash
    /// subkey H, cache the bulk-capable cipher engine (when available), and (re)allocate the
    /// 8-way SIMD buffers (FHPow / FWorkCtr / FWorkCtrAhead) on capable hardware.
    /// Called only when a new key is supplied.</summary>
    procedure InitCipherAndHashSubKey(const AKeyParam: IKeyParameter);
    /// <summary>Compute the pre-counter J0 from FNonce per NIST SP 800-38D
    /// (fast path for 96-bit IV, GHASH fallback otherwise).</summary>
    procedure ComputeJ0();
    /// <summary>Zero and (re)allocate all per-message transient state:
    /// FS, FS_at, FS_atPre, FAtBlock, counters, positions, totals.</summary>
    procedure ResetTransientState();

    // ---------------------------------------------------------------------
    // Single-block AES wrapper. AForEncrypt selects GHASH ordering:
    //   * encrypt: emit ciphertext, then GHASH-absorb the output.
    //   * decrypt: GHASH-absorb the input ciphertext, then emit plaintext.
    // ---------------------------------------------------------------------
    procedure CipherBlock(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32; AForEncrypt: Boolean);

    // ---------------------------------------------------------------------
    // Batch dispatchers: select the fastest available fused / pipelined
    // routine for the current CPU feature set and operation direction.
    // ---------------------------------------------------------------------
    procedure CipherBlocks2(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32; AForEncrypt: Boolean);
    procedure EncryptBlocks4(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32);
    procedure EncryptBlocks8(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32);
    procedure DecryptBlocks4(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32;
      ALimit: Int32);
    procedure DecryptBlocks8(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32;
      ALimit: Int32);

    // ---------------------------------------------------------------------
    // CTR keystream generation helpers (scalar + 4-way + 8-way).
    // ---------------------------------------------------------------------
    procedure GetNextCtrBlock(const ABlock: TCryptoLibByteArray);
    procedure GetNextCtrBlocks4(const ABlocks: TCryptoLibByteArray);
    procedure GetNextCtrBlocks8(const ABlocks: TCryptoLibByteArray);

    // ---------------------------------------------------------------------
    // GHASH tail / partial-block processing and state accumulation.
    // ---------------------------------------------------------------------
    procedure ProcessPartial(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32);
    procedure GHASH(const AY, AB: TCryptoLibByteArray; ALen: Int32);
    procedure GHASHBlock(const AY, AB: TCryptoLibByteArray); overload;
    procedure GHASHBlock(const AY, AB: TCryptoLibByteArray; AOff: Int32); overload;
    procedure GHASHPartial(const AY, AB: TCryptoLibByteArray; AOff, ALen: Int32);

    // ---------------------------------------------------------------------
    // Lifecycle: argument validation and reset.
    // ---------------------------------------------------------------------
    procedure CheckStatus();
    procedure DoReset(AClearMac: Boolean);

  strict protected
    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipher: IBlockCipher; const AMultiplier: IGcmMultiplier); overload;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;
    function GetBlockSize(): Int32; virtual;

    procedure ProcessAadByte(AInput: Byte); virtual;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); virtual;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function GetMac(): TCryptoLibByteArray; virtual;
    function GetOutputSize(ALen: Int32): Int32; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;

    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;
    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
  end;

implementation

// =======================================================================
// Class-level capability probes and multiplier factory. All arch-neutral:
// the GHASH SIMD facade answers False off-SIMD, so the mode's fast paths
// simply fall through to their scalar reference code.
// =======================================================================

class function TGcmBlockCipher.IsFourWaySupported: Boolean;
begin
  Result := TGhashSimd.IsShuffledGhashSupported;
end;

class function TGcmBlockCipher.IsEightWaySupported: Boolean;
begin
  Result := TGhashSimd.IsShuffledGhashSupported;
end;

{ TGcmBlockCipher }

class function TGcmBlockCipher.CreateGcmMultiplier: IGcmMultiplier;
begin
  if TGhashSimd.HasCarrylessMultiply then
  begin
    Result := TBasicGcmMultiplier.Create();
    Exit;
  end;
  Result := TTables4kGcmMultiplier.Create();
end;

// =======================================================================
// Constructors, basic accessors, and public AEAD API entry points.
// =======================================================================

constructor TGcmBlockCipher.Create(const ACipher: IBlockCipher);
begin
  Create(ACipher, nil);
end;

constructor TGcmBlockCipher.Create(const ACipher: IBlockCipher;
  const AMultiplier: IGcmMultiplier);
begin
  inherited Create;
  if ACipher.GetBlockSize() <> BlockSize then
    raise EArgumentCryptoLibException.CreateResFmt(@SCipherBlockSizeRequired, [BlockSize]);

  if AMultiplier <> nil then
    FMultiplier := AMultiplier
  else
    FMultiplier := CreateGcmMultiplier();

  FCipher := ACipher;
end;

function TGcmBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/GCM';
end;

function TGcmBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

function TGcmBlockCipher.GetBlockSize: Int32;
begin
  Result := BlockSize;
end;

procedure TGcmBlockCipher.ResolveInitParameters(const AParameters: ICipherParameters;
  out ANewNonce: TCryptoLibByteArray; out AKeyParam: IKeyParameter);
var
  LAeadParameters: IAeadParameters;
  LParametersWithIV: IParametersWithIV;
  LMacSizeBits: Int32;
begin
  if Supports(AParameters, IAeadParameters, LAeadParameters) then
  begin
    ANewNonce := LAeadParameters.GetNonce();
    FInitialAssociatedText := LAeadParameters.GetAssociatedText();

    LMacSizeBits := LAeadParameters.MacSize;
    if (LMacSizeBits < 32) or (LMacSizeBits > 128) or (LMacSizeBits mod 8 <> 0) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize, [LMacSizeBits]);

    FMacSize := LMacSizeBits div 8;
    AKeyParam := LAeadParameters.Key;
  end
  else if Supports(AParameters, IParametersWithIV, LParametersWithIV) then
  begin
    ANewNonce := LParametersWithIV.GetIV();
    FInitialAssociatedText := nil;
    FMacSize := 16;
    if not Supports(LParametersWithIV.Parameters, IKeyParameter, AKeyParam) then
      AKeyParam := nil;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['GCM']);
  end;
end;

procedure TGcmBlockCipher.CheckNonceReuse(AForEncryption: Boolean;
  const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);
begin
  if not AForEncryption then
    Exit;

  if (FNonce = nil) or (not TArrayUtilities.AreEqual(FNonce, ANewNonce)) then
    Exit;

  if AKeyParam = nil then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce, ['GCM']);

  if (FLastKey <> nil) and AKeyParam.FixedTimeEquals(FLastKey) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce, ['GCM']);
end;

procedure TGcmBlockCipher.InitCipherAndHashSubKey(const AKeyParam: IKeyParameter);
begin
  FCipher.Init(True, AKeyParam as ICipherParameters);

  TBlockCipherBulkUtilities.TryResolveBulkCipher(FCipher, FBulkCipher);

  FGcmKernel := nil;
  FGcmKernelMinBlocks := 0;

  FH := nil;
  System.SetLength(FH, BlockSize);
  FCipher.ProcessBlock(FH, 0, FH, 0);

  FMultiplier.Init(FH);
  FExp := nil;
  FHPow := nil;
  FWorkCtr := nil;
  FWorkCtrAhead := nil;
  if TGcmBlockCipher.IsFourWaySupported then
  begin
    System.SetLength(FHPow, 128);
    TGcmUtilities.InitEightWayHPowFromH(FH, FHPow);
    System.SetLength(FWorkCtr, 128);
    TArrayUtilities.Fill<Byte>(FWorkCtr, 0, System.Length(FWorkCtr), Byte(0));
    System.SetLength(FWorkCtrAhead, 128);
    TArrayUtilities.Fill<Byte>(FWorkCtrAhead, 0, System.Length(FWorkCtrAhead), Byte(0));

    if TFusedKernelRegistry.TryAcquireGcm(FCipher, TFusedModeDirection.Encrypt,
      @FHPow[0], FGcmKernel) and (FGcmKernel <> nil) then
    begin
      FGcmKernelMinBlocks := FGcmKernel.MinimumBlockCount;
      if FGcmKernelMinBlocks <> 8 then
      begin
        FGcmKernel := nil;
        FGcmKernelMinBlocks := 0;
      end;
    end;
  end;
end;

procedure TGcmBlockCipher.ComputeJ0();
var
  LX: TCryptoLibByteArray;
begin
  System.SetLength(FJ0, BlockSize);

  if System.Length(FNonce) = 12 then
  begin
    System.Move(FNonce[0], FJ0[0], System.Length(FNonce));
    FJ0[BlockSize - 1] := $01;
  end
  else
  begin
    GHASH(FJ0, FNonce, System.Length(FNonce));
    System.SetLength(LX, BlockSize);
    TPack.UInt64_To_BE(UInt64(System.Length(FNonce)) * UInt64(8), LX, 8);
    GHASHBlock(FJ0, LX);
  end;
end;

procedure TGcmBlockCipher.ResetTransientState();
begin
  System.SetLength(FS, BlockSize);
  System.SetLength(FS_at, BlockSize);
  System.SetLength(FS_atPre, BlockSize);
  System.SetLength(FAtBlock, BlockSize);
  FAtBlockPos := 0;
  FAtLength := 0;
  FAtLengthPre := 0;
  FCounter := System.Copy(FJ0);
  FCounter32 := TPack.BE_To_UInt32(FCounter, 12);
  FBlocksRemaining := UInt32($FFFFFFFF) - 1;
  FBufOff := 0;
  FTotalLength := 0;
end;

procedure TGcmBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LKeyParam: IKeyParameter;
  LNewNonce: TCryptoLibByteArray;
  LBufLength: Int32;
begin
  FForEncryption := AForEncryption;
  FMacBlock := nil;
  FBufBlock := nil;
  FJ0 := nil;

  FS := nil;
  FS_at := nil;
  FS_atPre := nil;
  FAtBlock := nil;
  FInitialised := True;

  ResolveInitParameters(AParameters, LNewNonce, LKeyParam);

  if FForEncryption then
    LBufLength := BlockSize
  else
    LBufLength := BlockSize + FMacSize;
  System.SetLength(FBufBlock, LBufLength);

  if System.Length(LNewNonce) < 1 then
    raise EArgumentCryptoLibException.CreateRes(@SIVMustBeAtLeastOneByte);

  CheckNonceReuse(FForEncryption, LNewNonce, LKeyParam);

  FNonce := LNewNonce;

  if LKeyParam <> nil then
  begin
    FLastKey := LKeyParam.GetKey();
    InitCipherAndHashSubKey(LKeyParam);
  end
  else if FH = nil then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end;

  ComputeJ0();
  ResetTransientState();

  if FInitialAssociatedText <> nil then
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
end;

function TGcmBlockCipher.GetMac: TCryptoLibByteArray;
begin
  if FMacBlock = nil then
  begin
    System.SetLength(Result, FMacSize);
  end
  else
  begin
    Result := System.Copy(FMacBlock);
  end;
end;

function TGcmBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FBufOff;

  if FForEncryption then
    Result := LTotalData + FMacSize
  else
  begin
    if LTotalData < FMacSize then
      Result := 0
    else
      Result := LTotalData - FMacSize;
  end;
end;

function TGcmBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FBufOff;
  if not FForEncryption then
  begin
    if LTotalData < FMacSize then
    begin
      Result := 0;
      Exit;
    end;
    LTotalData := LTotalData - FMacSize;
  end;
  Result := LTotalData - (LTotalData mod BlockSize);
end;

procedure TGcmBlockCipher.ProcessAadByte(AInput: Byte);
begin
  CheckStatus();

  FAtBlock[FAtBlockPos] := AInput;
  System.Inc(FAtBlockPos);
  if FAtBlockPos = BlockSize then
  begin
    GHASHBlock(FS_at, FAtBlock);
    FAtBlockPos := 0;
    FAtLength := FAtLength + UInt64(BlockSize);
  end;
end;

procedure TGcmBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LAvailable, LInLimit: Int32;
begin
  CheckStatus();

  if FAtBlockPos > 0 then
  begin
    LAvailable := BlockSize - FAtBlockPos;
    if ALen < LAvailable then
    begin
      System.Move(AInput[AInOff], FAtBlock[FAtBlockPos], ALen);
      FAtBlockPos := FAtBlockPos + ALen;
      Exit;
    end;

    System.Move(AInput[AInOff], FAtBlock[FAtBlockPos], LAvailable);
    GHASHBlock(FS_at, FAtBlock);
    FAtLength := FAtLength + UInt64(BlockSize);
    AInOff := AInOff + LAvailable;
    ALen := ALen - LAvailable;
  end;

  LInLimit := AInOff + ALen - BlockSize;

  while AInOff <= LInLimit do
  begin
    GHASHBlock(FS_at, AInput, AInOff);
    FAtLength := FAtLength + UInt64(BlockSize);
    AInOff := AInOff + BlockSize;
  end;

  FAtBlockPos := BlockSize + LInLimit - AInOff;
  System.Move(AInput[AInOff], FAtBlock[0], FAtBlockPos);
end;

procedure TGcmBlockCipher.InitCipher;
begin
  if FAtLength > 0 then
  begin
    System.Move(FS_at[0], FS_atPre[0], BlockSize);
    FAtLengthPre := FAtLength;
  end;

  if FAtBlockPos > 0 then
  begin
    GHASHPartial(FS_atPre, FAtBlock, 0, FAtBlockPos);
    FAtLengthPre := FAtLengthPre + UInt64(FAtBlockPos);
  end;

  if FAtLengthPre > 0 then
    System.Move(FS_atPre[0], FS[0], BlockSize);
end;

function TGcmBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  CheckStatus();

  FBufBlock[FBufOff] := AInput;
  System.Inc(FBufOff);
  if FBufOff = System.Length(FBufBlock) then
  begin
    TCheck.OutputLength(AOutput, AOutOff, BlockSize, SOutputBufferTooShort);

    if FBlocksRemaining = 0 then
      raise EInvalidOperationCryptoLibException.CreateRes(@STooManyBlocks);

    System.Dec(FBlocksRemaining);

    if FTotalLength = 0 then
      InitCipher();

    if FForEncryption then
    begin
      CipherBlock(FBufBlock, 0, AOutput, AOutOff, True);
      FBufOff := 0;
    end
    else
    begin
      CipherBlock(FBufBlock, 0, AOutput, AOutOff, False);
      System.Move(FBufBlock[BlockSize], FBufBlock[0], FMacSize);
      FBufOff := FMacSize;
    end;

    FTotalLength := FTotalLength + UInt64(BlockSize);
    Result := BlockSize;
    Exit;
  end;
  Result := 0;
end;

function TGcmBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LResultLen, LAvailable: Int32;
  LBufLen, LThresh2, LThresh4, LThresh8: Int32;
  LBlocksNeeded: UInt32;
begin
  CheckStatus();

  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);

  LResultLen := FBufOff + ALen;

  if FForEncryption then
  begin
    LResultLen := LResultLen and (not (BlockSize - 1));
    if LResultLen > 0 then
    begin
      TCheck.OutputLength(AOutput, AOutOff, LResultLen, SOutputBufferTooShort);

      LBlocksNeeded := UInt32(LResultLen) shr 4;
      if FBlocksRemaining < LBlocksNeeded then
        raise EInvalidOperationCryptoLibException.CreateRes(@STooManyBlocks);

      FBlocksRemaining := FBlocksRemaining - LBlocksNeeded;

      if FTotalLength = 0 then
        InitCipher();
    end;

    if FBufOff > 0 then
    begin
      LAvailable := BlockSize - FBufOff;
      if ALen < LAvailable then
      begin
        System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
        FBufOff := FBufOff + ALen;
        Result := 0;
        Exit;
      end;

      System.Move(AInput[AInOff], FBufBlock[FBufOff], LAvailable);
      AInOff := AInOff + LAvailable;
      ALen := ALen - LAvailable;

      CipherBlock(FBufBlock, 0, AOutput, AOutOff, True);
      AOutOff := AOutOff + BlockSize;
    end;

    if TGcmBlockCipher.IsEightWaySupported and (ALen >= BlockSize * 8) then
    begin
      EncryptBlocks8(AInput, AInOff, ALen, AOutput, AOutOff);
      if ALen >= BlockSize * 4 then
      begin
        EncryptBlocks4(AInput, AInOff, ALen, AOutput, AOutOff);
        if ALen >= BlockSize * 2 then
        begin
          CipherBlocks2(AInput, AInOff, AOutput, AOutOff, True);
          AInOff := AInOff + (BlockSize * 2);
          ALen := ALen - (BlockSize * 2);
          AOutOff := AOutOff + (BlockSize * 2);
        end;
      end
      else if ALen >= BlockSize * 2 then
      begin
        CipherBlocks2(AInput, AInOff, AOutput, AOutOff, True);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end
    else if TGcmBlockCipher.IsFourWaySupported and (ALen >= BlockSize * 4) then
    begin
      EncryptBlocks4(AInput, AInOff, ALen, AOutput, AOutOff);
      if ALen >= BlockSize * 2 then
      begin
        CipherBlocks2(AInput, AInOff, AOutput, AOutOff, True);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end
    else
    begin
      while ALen >= BlockSize * 2 do
      begin
        CipherBlocks2(AInput, AInOff, AOutput, AOutOff, True);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end;

    if ALen >= BlockSize then
    begin
      CipherBlock(AInput, AInOff, AOutput, AOutOff, True);
      AInOff := AInOff + BlockSize;
      ALen := ALen - BlockSize;
    end;

    FBufOff := ALen;
    System.Move(AInput[AInOff], FBufBlock[0], FBufOff);
  end
  else
  begin
    LResultLen := LResultLen - FMacSize;
    LResultLen := LResultLen and (not (BlockSize - 1));
    if LResultLen > 0 then
    begin
      TCheck.OutputLength(AOutput, AOutOff, LResultLen, SOutputBufferTooShort);

      LBlocksNeeded := UInt32(LResultLen) shr 4;
      if FBlocksRemaining < LBlocksNeeded then
        raise EInvalidOperationCryptoLibException.CreateRes(@STooManyBlocks);

      FBlocksRemaining := FBlocksRemaining - LBlocksNeeded;

      if FTotalLength = 0 then
        InitCipher();
    end;

    LAvailable := System.Length(FBufBlock) - FBufOff;
    if ALen < LAvailable then
    begin
      System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
      FBufOff := FBufOff + ALen;
      Result := 0;
      Exit;
    end;

    if FBufOff >= BlockSize then
    begin
      CipherBlock(FBufBlock, 0, AOutput, AOutOff, False);
      AOutOff := AOutOff + BlockSize;

      FBufOff := FBufOff - BlockSize;
      System.Move(FBufBlock[BlockSize], FBufBlock[0], FBufOff);

      LAvailable := LAvailable + BlockSize;
      if ALen < LAvailable then
      begin
        System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
        FBufOff := FBufOff + ALen;

        FTotalLength := FTotalLength + UInt64(BlockSize);
        Result := BlockSize;
        Exit;
      end;
    end;

    LAvailable := BlockSize - FBufOff;
    System.Move(AInput[AInOff], FBufBlock[FBufOff], LAvailable);
    AInOff := AInOff + LAvailable;
    ALen := ALen - LAvailable;

    CipherBlock(FBufBlock, 0, AOutput, AOutOff, False);
    AOutOff := AOutOff + BlockSize;

    LBufLen := System.Length(FBufBlock);
    LThresh2 := LBufLen + BlockSize;
    LThresh4 := LBufLen + (BlockSize * 3);
    LThresh8 := LBufLen + (BlockSize * 7);

    if TGcmBlockCipher.IsEightWaySupported and (ALen >= LThresh8) then
    begin
      DecryptBlocks8(AInput, AInOff, ALen, AOutput, AOutOff, LThresh8);
      if ALen >= LThresh4 then
      begin
        DecryptBlocks4(AInput, AInOff, ALen, AOutput, AOutOff, LThresh4);
        if ALen >= LThresh2 then
        begin
          CipherBlocks2(AInput, AInOff, AOutput, AOutOff, False);
          AInOff := AInOff + (BlockSize * 2);
          ALen := ALen - (BlockSize * 2);
          AOutOff := AOutOff + (BlockSize * 2);
        end;
      end
      else if ALen >= LThresh2 then
      begin
        CipherBlocks2(AInput, AInOff, AOutput, AOutOff, False);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end
    else if TGcmBlockCipher.IsFourWaySupported and (ALen >= LThresh4) then
    begin
      DecryptBlocks4(AInput, AInOff, ALen, AOutput, AOutOff, LThresh4);
      if ALen >= LThresh2 then
      begin
        CipherBlocks2(AInput, AInOff, AOutput, AOutOff, False);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end
    else
    begin
      while ALen >= LThresh2 do
      begin
        CipherBlocks2(AInput, AInOff, AOutput, AOutOff, False);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end;

    if ALen >= LBufLen then
    begin
      CipherBlock(AInput, AInOff, AOutput, AOutOff, False);
      AInOff := AInOff + BlockSize;
      ALen := ALen - BlockSize;
    end;

    FBufOff := ALen;
    System.Move(AInput[AInOff], FBufBlock[0], FBufOff);
  end;

  FTotalLength := FTotalLength + UInt64(LResultLen);
  Result := LResultLen;
end;

function TGcmBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LExtra, LResultLen: Int32;
  LC: Int64;
  LH_c, LX, LTag, LMsgMac: TCryptoLibByteArray;
begin
  CheckStatus();
  LH_c := nil;
  LX := nil;
  LTag := nil;
  LMsgMac := nil;

  LExtra := FBufOff;

  if FForEncryption then
  begin
    TCheck.OutputLength(AOutput, AOutOff, LExtra + FMacSize, SOutputBufferTooShort);
  end
  else
  begin
    if LExtra < FMacSize then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    LExtra := LExtra - FMacSize;

    TCheck.OutputLength(AOutput, AOutOff, LExtra, SOutputBufferTooShort);
  end;

  if FTotalLength = 0 then
    InitCipher();

  if LExtra > 0 then
  begin
    if FBlocksRemaining = 0 then
      raise EInvalidOperationCryptoLibException.CreateRes(@STooManyBlocks);

    System.Dec(FBlocksRemaining);

    ProcessPartial(FBufBlock, 0, LExtra, AOutput, AOutOff);
  end;

  FAtLength := FAtLength + UInt64(FAtBlockPos);

  if FAtLength > FAtLengthPre then
  begin
    if FAtBlockPos > 0 then
      GHASHPartial(FS_at, FAtBlock, 0, FAtBlockPos);

    if FAtLengthPre > 0 then
      TGcmUtilities.&Xor(FS_at, FS_atPre);

    LC := Int64(((FTotalLength * 8) + 127) shr 7);

    System.SetLength(LH_c, 16);
    if FExp = nil then
    begin
      FExp := TBasicGcmExponentiator.Create() as IGcmExponentiator;
      FExp.Init(FH);
    end;
    FExp.ExponentiateX(LC, LH_c);

    TGcmUtilities.Multiply(FS_at, LH_c);

    TGcmUtilities.&Xor(FS, FS_at);
  end;

  System.SetLength(LX, BlockSize);
  TPack.UInt64_To_BE(FAtLength * UInt64(8), LX, 0);
  TPack.UInt64_To_BE(FTotalLength * UInt64(8), LX, 8);

  GHASHBlock(FS, LX);

  System.SetLength(LTag, BlockSize);
  FCipher.ProcessBlock(FJ0, 0, LTag, 0);
  TGcmUtilities.&Xor(LTag, FS);

  LResultLen := LExtra;

  System.SetLength(FMacBlock, FMacSize);
  System.Move(LTag[0], FMacBlock[0], FMacSize);

  if FForEncryption then
  begin
    System.Move(FMacBlock[0], AOutput[AOutOff + FBufOff], FMacSize);
    LResultLen := LResultLen + FMacSize;
  end
  else
  begin
    System.SetLength(LMsgMac, FMacSize);
    System.Move(FBufBlock[LExtra], LMsgMac[0], FMacSize);
    if not TArrayUtilities.FixedTimeEquals(FMacBlock, LMsgMac) then
      raise EInvalidCipherTextCryptoLibException.CreateResFmt(@SMacCheckFailed,
        ['GCM']);
  end;

  DoReset(False);

  Result := LResultLen;
end;

procedure TGcmBlockCipher.Reset;
begin
  DoReset(True);
end;

procedure TGcmBlockCipher.DoReset(AClearMac: Boolean);
begin
  TArrayUtilities.Fill<Byte>(FS, 0, System.Length(FS), Byte(0));
  TArrayUtilities.Fill<Byte>(FS_at, 0, System.Length(FS_at), Byte(0));
  TArrayUtilities.Fill<Byte>(FS_atPre, 0, System.Length(FS_atPre), Byte(0));
  TArrayUtilities.Fill<Byte>(FAtBlock, 0, System.Length(FAtBlock), Byte(0));
  FAtBlockPos := 0;
  FAtLength := 0;
  FAtLengthPre := 0;
  FCounter := System.Copy(FJ0);
  FCounter32 := TPack.BE_To_UInt32(FCounter, 12);
  FBlocksRemaining := UInt32($FFFFFFFF) - 1;
  FBufOff := 0;
  FTotalLength := 0;

  if FBufBlock <> nil then
    TArrayUtilities.Fill<Byte>(FBufBlock, 0, System.Length(FBufBlock), Byte(0));

  if AClearMac then
    FMacBlock := nil;

  if FForEncryption then
  begin
    FInitialised := False;
  end
  else if FInitialAssociatedText <> nil then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

// =======================================================================
// Byte-reverse primitive and shuffled-block GHASH kernels used by the
// fused / pipelined batch routines below. The 64-byte / 128-byte triple-
// XOR helpers live in TBlockCipherBulkUtilities and are shared with the
// other bulk-capable modes (SIC, GCM-SIV, OCB, ...).
// =======================================================================

class procedure TGcmBlockCipher.GcmReverse16(const ASrc, ADst: PByte);
var
  LI: Int32;
begin
  if TGhashSimd.TryBlockReverse128(ADst, ASrc) then
    Exit;
  for LI := 0 to 15 do
    ADst[LI] := ASrc[15 - LI];
end;

procedure TGcmBlockCipher.GhashFourShuffledBlocks(PC0, PC16, PC32, PC48: PByte);
var
  LB, LI: Int32;
  LDblk: array[0..15] of Byte;
  LBuf48: array[0..47] of Byte;
  LU0, LU1, LU2: array[0..15] of Byte;
  LSRev: array[0..15] of Byte;
  LPCiph: PByte;
begin
  if TGhashSimd.TryFusedFourShuffledGhash(@FS[0], PC0, @FHPow[64]) then
    Exit;
  GcmReverse16(@FS[0], @LSRev[0]);
  FillChar(LU0, 16, 0);
  FillChar(LU1, 16, 0);
  FillChar(LU2, 16, 0);
  for LB := 0 to 3 do
  begin
    case LB of
      0:
        LPCiph := PC0;
      1:
        LPCiph := PC16;
      2:
        LPCiph := PC32;
    else
      LPCiph := PC48;
    end;
    GcmReverse16(LPCiph, @LDblk[0]);
    if LB = 0 then
      for LI := 0 to 15 do
        LDblk[LI] := LDblk[LI] xor LSRev[LI];
    TGcmUtilities.MultiplyExt(@LDblk[0], @FHPow[64 + (LB * 16)], @LBuf48[0]);
    TGcmUtilities.XorMultiplyExtLimbs48(@LU0[0], @LU1[0], @LU2[0], @LBuf48[0]);
  end;
  TGcmUtilities.Reduce3(@LU0[0], @LU1[0], @LU2[0], @LSRev[0]);
  GcmReverse16(@LSRev[0], @FS[0]);
end;

// =======================================================================
// Fused and pipelined batch routines -- GCM performance core.
// =======================================================================
// Each routine consumes 64 bytes (4-way) or 128 bytes (8-way) of
// plaintext / ciphertext per iteration. The "fused" variants run
// counter-keystream generation then GHASH back-to-back. The
// "pipelined" variants overlap current-batch keystream with previous-batch
// GHASH to reclaim instruction-level parallelism across the two independent
// execution units. The FusedILP variant (further below) pushes this further
// by interleaving both at the instruction level inside a single kernel
// supplied by the fused-kernel registry (nil off-SIMD, so that path is
// simply skipped there). AForEncrypt selects which buffer feeds GHASH:
// output ciphertext on encrypt, input ciphertext on decrypt.
// =======================================================================

// Single-batch fused 4-way GCM step. AForEncrypt=True hashes the output ciphertext;
// AForEncrypt=False hashes the input ciphertext. Everything else is identical
// between the two directions.
procedure TGcmBlockCipher.ProcessBlocks4Fused(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32;
  AForEncrypt: Boolean);
var
  LPHash: PByte;
begin
  GetNextCtrBlocks4(FWorkCtr);
  TByteUtilities.&Xor(64, PByte(AInBuf) + AInOff, PByte(FWorkCtr), PByte(AOutBuf) + AOutOff);
  if AForEncrypt then
    LPHash := PByte(AOutBuf) + AOutOff
  else
    LPHash := PByte(AInBuf) + AInOff;
  GhashFourShuffledBlocks(LPHash, LPHash + 16, LPHash + 32, LPHash + 48);
end;

procedure TGcmBlockCipher.GhashEightShuffledBlocks(PBase: PByte);
var
  LB, LI: Int32;
  LDblk: array [0 .. 15] of Byte;
  LBuf48: array [0 .. 47] of Byte;
  LU0, LU1, LU2: array [0 .. 15] of Byte;
  LSRev: array [0 .. 15] of Byte;
  LPCiph: PByte;
begin
  if TGhashSimd.TryFusedEightShuffledGhash(@FS[0], PBase, @FHPow[0]) then
    Exit;
  GcmReverse16(@FS[0], @LSRev[0]);
  FillChar(LU0, 16, 0);
  FillChar(LU1, 16, 0);
  FillChar(LU2, 16, 0);
  for LB := 0 to 7 do
  begin
    LPCiph := PBase + (LB * 16);
    GcmReverse16(LPCiph, @LDblk[0]);
    if LB = 0 then
      for LI := 0 to 15 do
        LDblk[LI] := LDblk[LI] xor LSRev[LI];
    TGcmUtilities.MultiplyExt(@LDblk[0], @FHPow[LB * 16], @LBuf48[0]);
    TGcmUtilities.XorMultiplyExtLimbs48(@LU0[0], @LU1[0], @LU2[0], @LBuf48[0]);
  end;
  TGcmUtilities.Reduce3(@LU0[0], @LU1[0], @LU2[0], @LSRev[0]);
  GcmReverse16(@LSRev[0], @FS[0]);
end;

// Single-batch fused 8-way GCM step. See ProcessBlocks4Fused for direction semantics.
procedure TGcmBlockCipher.ProcessBlocks8Fused(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32;
  AForEncrypt: Boolean);
var
  LPHash: PByte;
begin
  GetNextCtrBlocks8(FWorkCtr);
  TByteUtilities.&Xor(128, PByte(AInBuf) + AInOff, PByte(FWorkCtr), PByte(AOutBuf) + AOutOff);
  if AForEncrypt then
    LPHash := PByte(AOutBuf) + AOutOff
  else
    LPHash := PByte(AInBuf) + AInOff;
  GhashEightShuffledBlocks(LPHash);
end;

// Pipeline-by-one fused four-block step. Requires ALen >= ALimit + BlockSize*4*2
// (i.e. at least two 4-block batches remain after honouring the caller's tail
// hold-back) so we can overlap each batch's GHASH with the next batch's
// CTR-keystream generation via CPU out-of-order scheduling (the block-cipher
// keystream and the GHASH multiply-reduce use independent execution units).
// After this method returns, 0 or 1 full
// four-block batches remain; the caller's non-pipelined loop handles the tail.
// AForEncrypt=True does XOR then GHASH(output); AForEncrypt=False does
// GHASH(input) then XOR (the only per-direction difference).
// Encrypt callers pass ALimit=0 (threshold collapses to BlockSize*8).
procedure TGcmBlockCipher.ProcessBlocks4Pipelined(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32; AForEncrypt: Boolean);
var
  LCurr, LNext, LTmp: TCryptoLibByteArray;
  LPIn, LPOut, LPKey: PByte;
begin
  if ALen < ALimit + (BlockSize * 4) * 2 then
    Exit;

  LCurr := FWorkCtr;
  LNext := FWorkCtrAhead;

  GetNextCtrBlocks4(LCurr);

  while ALen >= ALimit + (BlockSize * 4) * 2 do
  begin
    LPIn := PByte(AInBuf) + AInOff;
    LPOut := PByte(AOutBuf) + AOutOff;
    LPKey := PByte(LCurr);

    GetNextCtrBlocks4(LNext);

    if AForEncrypt then
    begin
      TByteUtilities.&Xor(64, LPIn, LPKey, LPOut);
      GhashFourShuffledBlocks(LPOut, LPOut + 16, LPOut + 32, LPOut + 48);
    end
    else
    begin
      GhashFourShuffledBlocks(LPIn, LPIn + 16, LPIn + 32, LPIn + 48);
      TByteUtilities.&Xor(64, LPIn, LPKey, LPOut);
    end;

    LTmp := LCurr; LCurr := LNext; LNext := LTmp;
    AInOff := AInOff + (BlockSize * 4);
    AOutOff := AOutOff + (BlockSize * 4);
    ALen := ALen - (BlockSize * 4);
  end;

  LPIn := PByte(AInBuf) + AInOff;
  LPOut := PByte(AOutBuf) + AOutOff;
  LPKey := PByte(LCurr);
  if AForEncrypt then
  begin
    TByteUtilities.&Xor(64, LPIn, LPKey, LPOut);
    GhashFourShuffledBlocks(LPOut, LPOut + 16, LPOut + 32, LPOut + 48);
  end
  else
  begin
    GhashFourShuffledBlocks(LPIn, LPIn + 16, LPIn + 32, LPIn + 48);
    TByteUtilities.&Xor(64, LPIn, LPKey, LPOut);
  end;

  AInOff := AInOff + (BlockSize * 4);
  AOutOff := AOutOff + (BlockSize * 4);
  ALen := ALen - (BlockSize * 4);
end;

// Pipeline-by-one fused eight-block step. Same ordering strategy as the
// four-block variant; see ProcessBlocks4Pipelined for threshold and direction
// semantics. Encrypt callers pass ALimit=0 (threshold collapses to BlockSize*16).
procedure TGcmBlockCipher.ProcessBlocks8Pipelined(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32; AForEncrypt: Boolean);
var
  LCurr, LNext, LTmp: TCryptoLibByteArray;
  LPIn, LPOut, LPKey: PByte;
begin
  if ALen < ALimit + (BlockSize * 8) * 2 then
    Exit;

  LCurr := FWorkCtr;
  LNext := FWorkCtrAhead;

  GetNextCtrBlocks8(LCurr);

  while ALen >= ALimit + (BlockSize * 8) * 2 do
  begin
    LPIn := PByte(AInBuf) + AInOff;
    LPOut := PByte(AOutBuf) + AOutOff;
    LPKey := PByte(LCurr);

    GetNextCtrBlocks8(LNext);

    if AForEncrypt then
    begin
      TByteUtilities.&Xor(128, LPIn, LPKey, LPOut);
      GhashEightShuffledBlocks(LPOut);
    end
    else
    begin
      GhashEightShuffledBlocks(LPIn);
      TByteUtilities.&Xor(128, LPIn, LPKey, LPOut);
    end;

    LTmp := LCurr; LCurr := LNext; LNext := LTmp;
    AInOff := AInOff + (BlockSize * 8);
    AOutOff := AOutOff + (BlockSize * 8);
    ALen := ALen - (BlockSize * 8);
  end;

  LPIn := PByte(AInBuf) + AInOff;
  LPOut := PByte(AOutBuf) + AOutOff;
  LPKey := PByte(LCurr);
  if AForEncrypt then
  begin
    TByteUtilities.&Xor(128, LPIn, LPKey, LPOut);
    GhashEightShuffledBlocks(LPOut);
  end
  else
  begin
    GhashEightShuffledBlocks(LPIn);
    TByteUtilities.&Xor(128, LPIn, LPKey, LPOut);
  end;

  AInOff := AInOff + (BlockSize * 8);
  AOutOff := AOutOff + (BlockSize * 8);
  ALen := ALen - (BlockSize * 8);
end;

class procedure TGcmBlockCipher.FillCtr8BlocksRaw(
  const ACounter: TCryptoLibByteArray; var ACounter32: UInt32;
  const ABlocks: TCryptoLibByteArray);
var
  Lc0, Lc1, Lc2, Lc3, Lc4, Lc5, Lc6, Lc7, Lc8: UInt32;
begin
  Lc0 := ACounter32;
  Lc1 := Lc0 + UInt32(1);
  Lc2 := Lc0 + UInt32(2);
  Lc3 := Lc0 + UInt32(3);
  Lc4 := Lc0 + UInt32(4);
  Lc5 := Lc0 + UInt32(5);
  Lc6 := Lc0 + UInt32(6);
  Lc7 := Lc0 + UInt32(7);
  Lc8 := Lc0 + UInt32(8);
  ACounter32 := Lc8;

  System.Move(ACounter[0], ABlocks[0], 16);
  System.Move(ACounter[0], ABlocks[16], 16);
  System.Move(ACounter[0], ABlocks[32], 16);
  TPack.UInt32_To_BE(Lc4, ACounter, 12);
  TPack.UInt32_To_BE(Lc1, ABlocks, 12);
  TPack.UInt32_To_BE(Lc2, ABlocks, 28);
  TPack.UInt32_To_BE(Lc3, ABlocks, 44);
  System.Move(ACounter[0], ABlocks[48], 16);

  System.Move(ACounter[0], ABlocks[64], 16);
  System.Move(ACounter[0], ABlocks[80], 16);
  System.Move(ACounter[0], ABlocks[96], 16);
  TPack.UInt32_To_BE(Lc8, ACounter, 12);
  TPack.UInt32_To_BE(Lc5, ABlocks, 76);
  TPack.UInt32_To_BE(Lc6, ABlocks, 92);
  TPack.UInt32_To_BE(Lc7, ABlocks, 108);
  System.Move(ACounter[0], ABlocks[112], 16);
end;

// =======================================================================
// Fused block-cipher keystream + 8-way GHASH pipeline. The driver is
// arch-agnostic: it drives the outer 8-block stride loop and delegates the
// fused work to whichever IFusedGcmKernel the registry resolved (nil
// off-SIMD, so the callers never invoke this path there). The kernel's
// internal interleave and register budget are backend details behind the
// interface, summarised on the matching banner in the class declaration.
// =======================================================================

// Fused block-cipher keystream + 8-way GHASH pipeline. The cipher engine is
// always in encrypt mode (CTR keystream) regardless of GCM direction.
// AForEncrypt selects the per-direction bookkeeping only:
//   * encrypt: GHASH consumes the prior iteration's OUTPUT ciphertext.
//   * decrypt: GHASH consumes the prior iteration's INPUT  ciphertext.
// Dispatches to the 128 / 192 / 256-bit fused wrapper based on the engine's
// current round-key schedule length (10 / 12 / 14 rounds). Encrypt
// callers pass ALimit=0 (threshold collapses to BlockSize*16). Decrypt callers
// pass the tail hold-back threshold; the loop leaves at least ALimit bytes for
// the caller to process after the pipelined block.
// Prime: batch 0 is produced via the regular 8-wide keystream path + Pascal XOR,
// leaving its ciphertext reference at LPrevCipher awaiting GHASH in the next
// iteration.
// Body: each loop iteration invokes the interleaved fused kernel which
//   (a) encrypts eight fresh counter blocks to keystream,
//   (b) XORs the keystream with the current plaintext/ciphertext,
//   (c) GHASHes the previous iteration's ciphertext into the running state.
// Tail: the last pending ciphertext is GHASH'd, then the final batch is
// produced with the regular 8-wide path and also GHASH'd, mirroring the tail
// shape of ProcessBlocks8Pipelined.
procedure TGcmBlockCipher.ProcessBlocks8FusedILP(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32; AForEncrypt: Boolean);
var
  LCurrCtrs: TCryptoLibByteArray;
  LPrevCipher, LPOut, LPIn: PByte;
  LBatches: Int32;
begin
  if FGcmKernel = nil then
    Exit;
  if ALen < ALimit + (BlockSize * 8) * 2 then
    Exit;

  LCurrCtrs := FWorkCtr;

  // Prime batch 0: regular 8-wide keystream into LCurrCtrs (now holds keystream),
  // XOR with plaintext/ciphertext at LPOut, defer GHASH of batch 0.
  GetNextCtrBlocks8(LCurrCtrs);
  LPIn := PByte(AInBuf) + AInOff;
  LPOut := PByte(AOutBuf) + AOutOff;
  TByteUtilities.&Xor(128, LPIn, PByte(LCurrCtrs), LPOut);

  if AForEncrypt then
    LPrevCipher := LPOut
  else
    LPrevCipher := LPIn;
  AInOff := AInOff + (BlockSize * 8);
  AOutOff := AOutOff + (BlockSize * 8);
  ALen := ALen - (BlockSize * 8);

  // Bulk: process all full batches in one kernel call (counters and the
  // lagging GHASH pipeline run internally), seeded with the prime batch's
  // ciphertext and leaving the final batch for the drain below.
  LBatches := 0;
  if ALen >= ALimit + (BlockSize * 8) * 2 then
    LBatches := (ALen - ALimit - (BlockSize * 8)) div (BlockSize * 8);
  if LBatches > 0 then
  begin
    LPIn := PByte(AInBuf) + AInOff;
    LPOut := PByte(AOutBuf) + AOutOff;
    FCounter32 := FGcmKernel.ProcessCtrGhashBatches(LPIn, LPOut, LPrevCipher,
      @FS[0], @FJ0[0], FCounter32, LBatches, AForEncrypt);
    if AForEncrypt then
      LPrevCipher := LPOut + (LBatches - 1) * (BlockSize * 8)
    else
      LPrevCipher := LPIn + (LBatches - 1) * (BlockSize * 8);
    AInOff := AInOff + LBatches * (BlockSize * 8);
    AOutOff := AOutOff + LBatches * (BlockSize * 8);
    ALen := ALen - LBatches * (BlockSize * 8);
  end;

  // Tail: GHASH the last pending ciphertext, then produce and GHASH the final batch.
  GhashEightShuffledBlocks(LPrevCipher);

  GetNextCtrBlocks8(LCurrCtrs);
  LPIn := PByte(AInBuf) + AInOff;
  LPOut := PByte(AOutBuf) + AOutOff;
  if AForEncrypt then
  begin
    TByteUtilities.&Xor(128, LPIn, PByte(LCurrCtrs), LPOut);
    GhashEightShuffledBlocks(LPOut);
  end
  else
  begin
    GhashEightShuffledBlocks(LPIn);
    TByteUtilities.&Xor(128, LPIn, PByte(LCurrCtrs), LPOut);
  end;

  AInOff := AInOff + (BlockSize * 8);
  AOutOff := AOutOff + (BlockSize * 8);
  ALen := ALen - (BlockSize * 8);
end;

// =======================================================================
// Batch dispatchers: route each N-block call to the fastest available
// fused / pipelined / fallback routine for the active CPU feature set
// and operation direction (encrypt or decrypt). The single-block
// EncryptBlock wrapper lives alongside these for locality.
// =======================================================================

procedure TGcmBlockCipher.EncryptBlocks4(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32);
begin
  if not TGcmBlockCipher.IsFourWaySupported then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockPathNotSupported, ['four']);
  if FHPow = nil then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockHStateMissing, ['four']);
  if ALen >= BlockSize * 8 then
    ProcessBlocks4Pipelined(AInBuf, AInOff, ALen, AOutBuf, AOutOff, 0, True);
  while ALen >= BlockSize * 4 do
  begin
    ProcessBlocks4Fused(AInBuf, AInOff, AOutBuf, AOutOff, True);
    AInOff := AInOff + (BlockSize * 4);
    ALen := ALen - (BlockSize * 4);
    AOutOff := AOutOff + (BlockSize * 4);
  end;
end;

procedure TGcmBlockCipher.EncryptBlocks8(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32);
begin
  if not TGcmBlockCipher.IsEightWaySupported then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockPathNotSupported, ['eight']);
  if (FHPow = nil) or (System.Length(FHPow) < 128) then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockHStateMissing, ['eight']);
  if ALen >= BlockSize * 16 then
  begin
    // FusedILP is worthwhile only when the inner loop actually iterates:
    // prime batch + >=1 kernel iter + tail batch = 3 strides of 128 B. Below
    // that the fused kernel is bypassed (prime + tail only) and the driver's
    // entry cost regresses small payloads, especially on register-constrained
    // targets where that overhead is amplified. FGcmKernel is nil off-SIMD, so
    // this branch is simply skipped there.
    if (FGcmKernel <> nil) and (ALen >= BlockSize * 24) then
      ProcessBlocks8FusedILP(AInBuf, AInOff, ALen, AOutBuf, AOutOff, 0, True);
    if ALen >= BlockSize * 16 then
      ProcessBlocks8Pipelined(AInBuf, AInOff, ALen, AOutBuf, AOutOff, 0, True);
  end;
  while ALen >= BlockSize * 8 do
  begin
    ProcessBlocks8Fused(AInBuf, AInOff, AOutBuf, AOutOff, True);
    AInOff := AInOff + (BlockSize * 8);
    ALen := ALen - (BlockSize * 8);
    AOutOff := AOutOff + (BlockSize * 8);
  end;
end;

procedure TGcmBlockCipher.CipherBlock(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32;
  AForEncrypt: Boolean);
var
  LCtrBlock: TCryptoLibByteArray;
begin
  LCtrBlock := nil;
  System.SetLength(LCtrBlock, BlockSize);
  GetNextCtrBlock(LCtrBlock);
  // Encrypt: C := keystream xor In; FS := FS xor C; Out := C.
  // Decrypt: FS := FS xor In (= ciphertext); Out := In xor keystream.
  if AForEncrypt then
  begin
    System.Move(LCtrBlock[0], AOutBuf[AOutOff], BlockSize);
    TByteUtilities.XorTo(BlockSize, PByte(@AInBuf[AInOff]), PByte(@AOutBuf[AOutOff]));
    TByteUtilities.XorTo(BlockSize, PByte(@AOutBuf[AOutOff]), PByte(@FS[0]));
  end
  else
  begin
    System.Move(AInBuf[AInOff], AOutBuf[AOutOff], BlockSize);
    TByteUtilities.XorTo(BlockSize, PByte(@LCtrBlock[0]), PByte(@AOutBuf[AOutOff]));
    TByteUtilities.XorTo(BlockSize, PByte(@AInBuf[AInOff]), PByte(@FS[0]));
  end;
  FMultiplier.MultiplyH(FS);
end;

procedure TGcmBlockCipher.DecryptBlocks4(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32);
begin
  if not TGcmBlockCipher.IsFourWaySupported then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockPathNotSupported, ['four']);
  if ALimit < BlockSize * 4 then
    raise EArgumentCryptoLibException.CreateResFmt(@SGcmDecryptBadLimit, ['four']);
  if FHPow = nil then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockHStateMissing, ['four']);
  if ALen >= ALimit + (BlockSize * 4) * 2 then
    ProcessBlocks4Pipelined(AInBuf, AInOff, ALen, AOutBuf, AOutOff, ALimit, False);
  while ALen >= ALimit do
  begin
    ProcessBlocks4Fused(AInBuf, AInOff, AOutBuf, AOutOff, False);
    AInOff := AInOff + (BlockSize * 4);
    ALen := ALen - (BlockSize * 4);
    AOutOff := AOutOff + (BlockSize * 4);
  end;
end;

procedure TGcmBlockCipher.DecryptBlocks8(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32);
begin
  if not TGcmBlockCipher.IsEightWaySupported then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockPathNotSupported, ['eight']);
  if ALimit < BlockSize * 8 then
    raise EArgumentCryptoLibException.CreateResFmt(@SGcmDecryptBadLimit, ['eight']);
  if (FHPow = nil) or (System.Length(FHPow) < 128) then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockHStateMissing, ['eight']);
  if ALen >= ALimit + (BlockSize * 8) * 2 then
  begin
    // See EncryptBlocks8: require prime + >=1 kernel iter + tail
    // (3 strides of 128 B above ALimit) before entering FusedILP.
    // FGcmKernel is nil off-SIMD, so this branch is skipped there.
    if (FGcmKernel <> nil) and (ALen >= ALimit + (BlockSize * 8) * 3) then
      ProcessBlocks8FusedILP(AInBuf, AInOff, ALen, AOutBuf, AOutOff, ALimit, False);
    if ALen >= ALimit + (BlockSize * 8) * 2 then
      ProcessBlocks8Pipelined(AInBuf, AInOff, ALen, AOutBuf, AOutOff, ALimit, False);
  end;
  while ALen >= ALimit do
  begin
    ProcessBlocks8Fused(AInBuf, AInOff, AOutBuf, AOutOff, False);
    AInOff := AInOff + (BlockSize * 8);
    ALen := ALen - (BlockSize * 8);
    AOutOff := AOutOff + (BlockSize * 8);
  end;
end;

procedure TGcmBlockCipher.CipherBlocks2(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32;
  AForEncrypt: Boolean);
var
  LCtrBlock: TCryptoLibByteArray;
  LB: Int32;
begin
  LCtrBlock := nil;
  System.SetLength(LCtrBlock, BlockSize);

  for LB := 0 to 1 do
  begin
    GetNextCtrBlock(LCtrBlock);
    if AForEncrypt then
    begin
      System.Move(LCtrBlock[0], AOutBuf[AOutOff], BlockSize);
      TByteUtilities.XorTo(BlockSize, PByte(@AInBuf[AInOff]), PByte(@AOutBuf[AOutOff]));
      TByteUtilities.XorTo(BlockSize, PByte(@AOutBuf[AOutOff]), PByte(@FS[0]));
    end
    else
    begin
      System.Move(AInBuf[AInOff], AOutBuf[AOutOff], BlockSize);
      TByteUtilities.XorTo(BlockSize, PByte(@LCtrBlock[0]), PByte(@AOutBuf[AOutOff]));
      TByteUtilities.XorTo(BlockSize, PByte(@AInBuf[AInOff]), PByte(@FS[0]));
    end;
    FMultiplier.MultiplyH(FS);
    AInOff := AInOff + BlockSize;
    AOutOff := AOutOff + BlockSize;
  end;
end;

// =======================================================================
// CTR keystream helpers (scalar, 4-way, and 8-way).
// =======================================================================

procedure TGcmBlockCipher.GetNextCtrBlock(const ABlock: TCryptoLibByteArray);
begin
  System.Inc(FCounter32);
  TPack.UInt32_To_BE(FCounter32, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlock, 0);
end;

procedure TGcmBlockCipher.GetNextCtrBlocks4(const ABlocks: TCryptoLibByteArray);
var
  Lc0, Lc1, Lc2, Lc3, Lc4: UInt32;
begin
  Lc0 := FCounter32;
  Lc1 := Lc0 + UInt32(1);
  Lc2 := Lc0 + UInt32(2);
  Lc3 := Lc0 + UInt32(3);
  Lc4 := Lc0 + UInt32(4);
  FCounter32 := Lc4;

  if FBulkCipher <> nil then
  begin
    System.Move(FCounter[0], ABlocks[0], 16);
    System.Move(FCounter[0], ABlocks[16], 16);
    System.Move(FCounter[0], ABlocks[32], 16);
    TPack.UInt32_To_BE(Lc4, FCounter, 12);
    TPack.UInt32_To_BE(Lc1, ABlocks, 12);
    TPack.UInt32_To_BE(Lc2, ABlocks, 28);
    TPack.UInt32_To_BE(Lc3, ABlocks, 44);
    System.Move(FCounter[0], ABlocks[48], 16);
    FBulkCipher.ProcessBlocks(@ABlocks[0], @ABlocks[0], 4);
    Exit;
  end;

  TPack.UInt32_To_BE(Lc1, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 0);
  TPack.UInt32_To_BE(Lc2, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 16);
  TPack.UInt32_To_BE(Lc3, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 32);
  TPack.UInt32_To_BE(Lc4, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 48);
end;

procedure TGcmBlockCipher.GetNextCtrBlocks8(const ABlocks: TCryptoLibByteArray);
var
  Lc0, Lc1, Lc2, Lc3, Lc4, Lc5, Lc6, Lc7, Lc8: UInt32;
begin
  if FBulkCipher <> nil then
  begin
    FillCtr8BlocksRaw(FCounter, FCounter32, ABlocks);
    FBulkCipher.ProcessBlocks(@ABlocks[0], @ABlocks[0], 8);
    Exit;
  end;

  Lc0 := FCounter32;
  Lc1 := Lc0 + UInt32(1);
  Lc2 := Lc0 + UInt32(2);
  Lc3 := Lc0 + UInt32(3);
  Lc4 := Lc0 + UInt32(4);
  Lc5 := Lc0 + UInt32(5);
  Lc6 := Lc0 + UInt32(6);
  Lc7 := Lc0 + UInt32(7);
  Lc8 := Lc0 + UInt32(8);
  FCounter32 := Lc8;

  TPack.UInt32_To_BE(Lc1, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 0);
  TPack.UInt32_To_BE(Lc2, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 16);
  TPack.UInt32_To_BE(Lc3, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 32);
  TPack.UInt32_To_BE(Lc4, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 48);
  TPack.UInt32_To_BE(Lc5, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 64);
  TPack.UInt32_To_BE(Lc6, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 80);
  TPack.UInt32_To_BE(Lc7, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 96);
  TPack.UInt32_To_BE(Lc8, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlocks, 112);
end;

// =======================================================================
// Tail / partial-block processing, GHASH state accumulation, and
// lifecycle (argument validation).
// =======================================================================

procedure TGcmBlockCipher.ProcessPartial(const ABuf: TCryptoLibByteArray;
  AOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32);
var
  LCtrBlock: TCryptoLibByteArray;
begin
  LCtrBlock := nil;
  System.SetLength(LCtrBlock, BlockSize);
  GetNextCtrBlock(LCtrBlock);

  if FForEncryption then
  begin
    TGcmUtilities.&Xor(ABuf, AOff, LCtrBlock, 0, ALen);
    GHASHPartial(FS, ABuf, AOff, ALen);
  end
  else
  begin
    GHASHPartial(FS, ABuf, AOff, ALen);
    TGcmUtilities.&Xor(ABuf, AOff, LCtrBlock, 0, ALen);
  end;

  System.Move(ABuf[AOff], AOutput[AOutOff], ALen);
  FTotalLength := FTotalLength + UInt64(ALen);
end;

procedure TGcmBlockCipher.GHASH(const AY, AB: TCryptoLibByteArray; ALen: Int32);
var
  LPos, LNum: Int32;
begin
  LPos := 0;
  while LPos < ALen do
  begin
    LNum := Math.Min(ALen - LPos, BlockSize);
    GHASHPartial(AY, AB, LPos, LNum);
    LPos := LPos + BlockSize;
  end;
end;

procedure TGcmBlockCipher.GHASHBlock(const AY, AB: TCryptoLibByteArray);
begin
  TGcmUtilities.&Xor(AY, AB);
  FMultiplier.MultiplyH(AY);
end;

procedure TGcmBlockCipher.GHASHBlock(const AY, AB: TCryptoLibByteArray;
  AOff: Int32);
begin
  TGcmUtilities.&Xor(AY, AB, AOff);
  FMultiplier.MultiplyH(AY);
end;

procedure TGcmBlockCipher.GHASHPartial(const AY, AB: TCryptoLibByteArray;
  AOff, ALen: Int32);
begin
  TGcmUtilities.&Xor(AY, AB, AOff, ALen);
  FMultiplier.MultiplyH(AY);
end;

procedure TGcmBlockCipher.CheckStatus;
begin
  if not FInitialised then
  begin
    if FForEncryption then
      raise EInvalidOperationCryptoLibException.CreateRes(@SGcmCannotReuse);

    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmNeedsInit);
  end;
end;

end.
