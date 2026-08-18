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
  ClpCipherKernelTypes,
  ClpIGcmKernel,
  ClpCipherKernelRegistry,
  ClpCipherKernelDefaults, // registers in-tree fused AEAD kernel factories
  ClpPack,
  ClpCheck,
  ClpBasicGcmMultiplier,
  ClpKeyParameter,
  ClpArrayUtilities,
  ClpAbstractAeadCipher,
  ClpAbstractAeadBlockCipher,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCipherBlockSizeRequired = 'cipher required with a block size of %d';
  SInvalidParameters = 'invalid parameters passed to %s';
  SIVMustBeAtLeastOneByte = 'IV must be at least 1 byte';
  SKeyMustBeSpecified = 'key must be specified in initial init';
  STooManyBlocks = 'attempt to process too many blocks';
  SGcmCannotReuse = 'GCM cipher cannot be reused for encryption';
  SGcmNeedsInit = 'GCM cipher needs to be initialized';
  SOutputBufferTooShort = 'output buffer too short';
  SInputBufferTooShort = 'input buffer too short';
  SDataTooShort = 'data too short';
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
  TGcmBlockCipher = class(TAbstractAeadBlockCipher, IGcmBlockCipher,
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
    // Fused CTR+GHASH kernel resolved via TCipherKernelRegistry at Init
    // time. Non-nil only when an accelerator factory accepts the
    // underlying cipher + direction and the cipher-kernel gate is open (always nil
    // off-SIMD; IGcmKernel is arch-neutral).
    FGcmKernel: IGcmKernel;
    FGcmKernelMinBlocks: Int32;
    FMultiplier: IGcmMultiplier;
    FExponentiator: IGcmExponentiator;

    FInitialised: Boolean;
    FHashSubKey: TCryptoLibByteArray;
    FPreCounterBlock: TCryptoLibByteArray;

    FBufferBlock: TCryptoLibByteArray;
    // Reusable DoFinal scratch (allocated once, fully overwritten each call):
    // the length block, the computed tag, the received MAC (decrypt) and the
    // AAD-length exponent H^c. Avoids four heap allocations per DoFinal.
    FLengthBlock: TCryptoLibByteArray;
    FTagBlock: TCryptoLibByteArray;
    FReceivedMac: TCryptoLibByteArray;
    FLengthExponent: TCryptoLibByteArray;
    FGHashState: TCryptoLibByteArray;
    FAadHashState: TCryptoLibByteArray;
    FAadHashStatePre: TCryptoLibByteArray;
    FCounterBlock: TCryptoLibByteArray;
    FCounterWord: UInt32;
    FBlocksRemaining: UInt32;
    FBufferOffset: Int32;
    FTotalLength: UInt64;
    FAadBlock: TCryptoLibByteArray;
    FAadBlockPos: Int32;
    FAadLength: UInt64;
    FAadLengthPre: UInt64;
    /// <summary>HPow limbs H^8..H^1 (128 bytes) for fused GHASH; indices 64..112 hold H^4..H^1 for the four-block path; nil if path off.</summary>
    FHashSubKeyPowers: TCryptoLibByteArray;
    /// <summary>Reused 128-byte buffer for batched CTR keystream (first 64 bytes used by four-block fused path).</summary>
    FCounterKeystream: TCryptoLibByteArray;
    /// <summary>Second 128-byte keystream buffer for the pipeline-by-one path (look-ahead batch). nil if fused paths are off.</summary>
    FCounterKeystreamAhead: TCryptoLibByteArray;
    /// <summary>True when the underlying cipher is bulk-capable but SIMD GHASH is unavailable:
    /// drives the software-GHASH 4-block batch path (bulk AES + scalar aggregated GHASH).</summary>
    FSoftwareBulkGHash: Boolean;
    /// <summary>H^1..H^4 as field elements for the scalar aggregated 4-block GHASH; set when FSoftwareBulkGHash.</summary>
    FHashSubKeyPow1, FHashSubKeyPow2, FHashSubKeyPow3, FHashSubKeyPow4: TFieldElement;

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
    // cipher-kernel registry; nil kernel -> not used, e.g. off-SIMD).
    // =====================================================================
    // This outer driver is arch-agnostic: pure Pascal batch orchestration
    // plus one call into an IGcmKernel per 8-block stride. The kernel
    // fuses CTR-mode keystream generation with the GHASH multiply-reduce in a
    // single pass, interleaving the two at the instruction level so their
    // independent execution units overlap. How wide that interleave runs and
    // how it is scheduled against the available vector-register budget is a
    // backend detail hidden entirely behind the IGcmKernel surface, so
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
    /// <summary>Rekey path: initialize the underlying block cipher, compute the hash
    /// subkey H, cache the bulk-capable cipher engine (when available), and (re)allocate the
    /// 8-way SIMD buffers (FHashSubKeyPowers / FCounterKeystream / FCounterKeystreamAhead) on capable hardware.
    /// Called only when a new key is supplied.</summary>
    procedure InitCipherAndHashSubKey(const AKeyParam: IKeyParameter);
    /// <summary>Compute the pre-counter J0 from FLastNonce per NIST SP 800-38D
    /// (fast path for 96-bit IV, GHASH fallback otherwise).</summary>
    procedure ComputeJ0();
    /// <summary>Zero and (re)allocate all per-message transient state:
    /// FGHashState, FAadHashState, FAadHashStatePre, FAadBlock, counters, positions, totals.</summary>
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
    // Software-GHASH 4-block batch path: bulk AES keystream (FBulkCipher) plus
    // the scalar aggregated 4-way GHASH. Used when the cipher is bulk-capable
    // but SIMD GHASH is unavailable (FSoftwareBulkGHash). Counter keystream comes from
    // GetNextCtrBlocks4 (GCM inc32); do NOT substitute SIC's 128-bit counter.
    // ---------------------------------------------------------------------
    procedure SoftAggregateGhash4(const ABuf: TCryptoLibByteArray; AOff: Int32);
    procedure ProcessSoftBulk4(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32; AForEncrypt: Boolean);
    procedure EncryptBlocksSoftBulk4(const AInBuf: TCryptoLibByteArray;
      var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
      var AOutOff: Int32);
    procedure DecryptBlocksSoftBulk4(const AInBuf: TCryptoLibByteArray;
      var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
      var AOutOff: Int32; ALimit: Int32);

    // Run the whole-block dispatch staircase (widest supported tier down to a
    // 2-block tail plus a single trailing block) over [AInOff, AInOff+ALen).
    // AHoldBack is the byte count kept back beyond the last processed block: 0
    // for encrypt, FMacSize for decrypt (so the trailing tag is never consumed
    // as payload). Direction selects the encrypt vs decrypt tier methods; the
    // tier methods themselves are unchanged. Advances AInOff/ALen/AOutOff.
    procedure RunTieredWholeBlocks(AForEncrypt: Boolean;
      const AInBuf: TCryptoLibByteArray; var AInOff: Int32; var ALen: Int32;
      const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32; AHoldBack: Int32);

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
    function GetAlgorithmName: String; override;
    function GetModeName: String; override;
    function GetBufferedLength(): Int32; override;

    /// <summary>Zeroize the hash subkey, H-power tables, keystream buffers, and
    /// aggregated GHASH powers. Not called from Reset (same-key re-Init reuses them).</summary>
    procedure WipeKeyMaterial(); override;

  public
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipher: IBlockCipher; const AMultiplier: IGcmMultiplier); overload;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); override;

    /// <summary>
    /// One-shot / reusable-context entry point: initialise directly from raw
    /// key, nonce and AAD spans, with no <c>TKeyParameter</c>/<c>TAeadParameters</c>
    /// allocation on the per-message (same-key) path. Mirrors <see cref="Init"/>
    /// exactly (same helpers, same nonce-reuse guard) but skips the parameter
    /// object parsing. Pass <c>AKey = nil</c> to reuse the established key.
    /// Used by TAesGcmPacketCipher; ordinary streaming callers use Init.
    /// </summary>
    procedure InitPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32); override;

    procedure ProcessAadByte(AInput: Byte); override;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); override;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;

    procedure Reset(); override;
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
  FBlockSize := BlockSize;
  FUnderlyingCipher := FCipher;
end;

function TGcmBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/GCM';
end;

function TGcmBlockCipher.GetModeName: String;
begin
  Result := 'GCM';
end;

function TGcmBlockCipher.GetBufferedLength: Int32;
begin
  Result := FBufferOffset;
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
    FMacSize := ValidateAeadMacSizeBits(LMacSizeBits, 32, 128, 8);
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

procedure TGcmBlockCipher.InitCipherAndHashSubKey(const AKeyParam: IKeyParameter);
begin
  // Zeroize any prior key-derived material before this rekey overwrites it.
  WipeKeyMaterial();

  FCipher.Init(True, AKeyParam as ICipherParameters);

  TBlockCipherBulkUtilities.TryResolveBulkCipher(FCipher, FBulkCipher);

  FGcmKernel := nil;
  FGcmKernelMinBlocks := 0;

  FHashSubKey := nil;
  System.SetLength(FHashSubKey, BlockSize);
  FCipher.ProcessBlock(FHashSubKey, 0, FHashSubKey, 0);

  FMultiplier.Init(FHashSubKey);
  FExponentiator := nil;
  FHashSubKeyPowers := nil;
  FCounterKeystream := nil;
  FCounterKeystreamAhead := nil;
  FSoftwareBulkGHash := False;
  if TGcmBlockCipher.IsFourWaySupported then
  begin
    System.SetLength(FHashSubKeyPowers, 128);
    TGcmUtilities.InitEightWayHPowFromH(FHashSubKey, FHashSubKeyPowers);
    System.SetLength(FCounterKeystream, 128);
    TArrayUtilities.Fill(FCounterKeystream, 0, System.Length(FCounterKeystream), Byte(0));
    System.SetLength(FCounterKeystreamAhead, 128);
    TArrayUtilities.Fill(FCounterKeystreamAhead, 0, System.Length(FCounterKeystreamAhead), Byte(0));

    if TCipherKernelRegistry.TryAcquireGcm(FCipher, TCipherKernelDirection.Encrypt,
      @FHashSubKeyPowers[0], FGcmKernel) and (FGcmKernel <> nil) then
    begin
      FGcmKernelMinBlocks := FGcmKernel.MinimumBlockCount;
      if FGcmKernelMinBlocks <> 8 then
      begin
        FGcmKernel := nil;
        FGcmKernelMinBlocks := 0;
      end;
    end;
  end
  else if FBulkCipher <> nil then
  begin
    FSoftwareBulkGHash := True;
    System.SetLength(FCounterKeystream, BlockSize * 4);
    TArrayUtilities.Fill(FCounterKeystream, 0, System.Length(FCounterKeystream), Byte(0));
    TGcmUtilities.ComputePowers1To4(FHashSubKey, FHashSubKeyPow1, FHashSubKeyPow2, FHashSubKeyPow3, FHashSubKeyPow4);
  end;
end;

procedure TGcmBlockCipher.ComputeJ0();
var
  LX: TCryptoLibByteArray;
begin
  // Reuse FPreCounterBlock across messages; zero it in place. The 12-byte-nonce path relies
  // on bytes [12..14] being zero, and the GHASH fallback accumulates into a
  // zeroed FPreCounterBlock -- the Fill guarantees both without a per-message allocation.
  if FPreCounterBlock = nil then
    System.SetLength(FPreCounterBlock, BlockSize);
  TArrayUtilities.Fill(FPreCounterBlock, 0, BlockSize, Byte(0));

  if System.Length(FLastNonce) = 12 then
  begin
    System.Move(FLastNonce[0], FPreCounterBlock[0], System.Length(FLastNonce));
    FPreCounterBlock[BlockSize - 1] := $01;
  end
  else
  begin
    GHASH(FPreCounterBlock, FLastNonce, System.Length(FLastNonce));
    System.SetLength(LX, BlockSize);
    TPack.UInt64_To_BE(UInt64(System.Length(FLastNonce)) * UInt64(8), LX, 8);
    GHASHBlock(FPreCounterBlock, LX);
  end;
end;

procedure TGcmBlockCipher.ResetTransientState();
begin
  // Allocate the fixed 16-byte transient buffers once per object lifetime and
  // zero them in place each message (they were reallocated every Init before).
  if FGHashState = nil then
    System.SetLength(FGHashState, BlockSize);
  TArrayUtilities.Fill(FGHashState, 0, BlockSize, Byte(0));
  if FAadHashState = nil then
    System.SetLength(FAadHashState, BlockSize);
  TArrayUtilities.Fill(FAadHashState, 0, BlockSize, Byte(0));
  if FAadHashStatePre = nil then
    System.SetLength(FAadHashStatePre, BlockSize);
  TArrayUtilities.Fill(FAadHashStatePre, 0, BlockSize, Byte(0));
  if FAadBlock = nil then
    System.SetLength(FAadBlock, BlockSize);
  TArrayUtilities.Fill(FAadBlock, 0, BlockSize, Byte(0));
  FAadBlockPos := 0;
  FAadLength := 0;
  FAadLengthPre := 0;
  if FCounterBlock = nil then
    System.SetLength(FCounterBlock, BlockSize);
  System.Move(FPreCounterBlock[0], FCounterBlock[0], BlockSize);
  FCounterWord := TPack.BE_To_UInt32(FCounterBlock, 12);
  FBlocksRemaining := UInt32($FFFFFFFF) - 1;
  FBufferOffset := 0;
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
  FInitialised := True;

  ResolveInitParameters(AParameters, LNewNonce, LKeyParam);

  if FForEncryption then
    LBufLength := BlockSize
  else
    LBufLength := BlockSize + FMacSize;
  // Reuse FBufferBlock across messages; only (re)allocate when the required length
  // changes (encrypt vs decrypt, or a different MAC size on decrypt), otherwise
  // zero it in place. Preserves the "FBufferBlock zeroed after Init" contract.
  if (FBufferBlock = nil) or (System.Length(FBufferBlock) <> LBufLength) then
    System.SetLength(FBufferBlock, LBufLength)
  else
    TArrayUtilities.Fill(FBufferBlock, 0, LBufLength, Byte(0));

  if System.Length(LNewNonce) < 1 then
    raise EArgumentCryptoLibException.CreateRes(@SIVMustBeAtLeastOneByte);

  CheckNonceReuse(FForEncryption, LNewNonce, LKeyParam);

  FLastNonce := LNewNonce;

  // Same-key fast path: the key schedule, hash subkey, multiplier state,
  // H-power table and fused kernel all depend only on the key, so a re-Init
  // with the same key (fresh nonce per message) keeps them all -- and, on the
  // same-key path, SameKeyReuse leaves FLastKey intact (no per-message copy).
  // A nil key parameter is the bc-csharp "reuse last key" convention.
  if LKeyParam <> nil then
  begin
    if not SameKeyReuse(LKeyParam) then
      InitCipherAndHashSubKey(LKeyParam);
  end
  else if FHashSubKey = nil then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end;

  ComputeJ0();
  ResetTransientState();

  if FInitialAssociatedText <> nil then
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
end;

procedure TGcmBlockCipher.InitPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32);
var
  LBufLength: Int32;
begin
  FForEncryption := AForEncryption;
  FMacBlock := nil;
  FInitialised := True;

  // AAD is consumed in place below; store a reference (no clone).
  FInitialAssociatedText := AAad;
  FMacSize := ValidateAeadMacSizeBits(AMacSizeBits, 32, 128, 8);

  if FForEncryption then
    LBufLength := BlockSize
  else
    LBufLength := BlockSize + FMacSize;
  if (FBufferBlock = nil) or (System.Length(FBufferBlock) <> LBufLength) then
    System.SetLength(FBufferBlock, LBufLength)
  else
    TArrayUtilities.Fill(FBufferBlock, 0, LBufLength, Byte(0));

  if System.Length(ANonce) < 1 then
    raise EArgumentCryptoLibException.CreateRes(@SIVMustBeAtLeastOneByte);

  CheckNonceReuseRaw(FForEncryption, ANonce, AKey);

  // Snapshot the nonce into a reusable owned buffer: the nonce-reuse guard must
  // compare against a stable previous nonce, and callers routinely reuse one
  // nonce buffer across messages. One small Move, no alloc on the steady path.
  if (FLastNonce = nil) or (System.Length(FLastNonce) <> System.Length(ANonce)) then
    System.SetLength(FLastNonce, System.Length(ANonce));
  System.Move(ANonce[0], FLastNonce[0], System.Length(ANonce));

  // Same-key fast path (raw): key schedule / H / multiplier / kernel retained;
  // a fresh TKeyParameter is created only on an actual rekey. nil = reuse key.
  if AKey <> nil then
  begin
    if not SameKeyReuseRaw(AKey) then
      InitCipherAndHashSubKey(TKeyParameter.Create(AKey) as IKeyParameter);
  end
  else if FHashSubKey = nil then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end;

  ComputeJ0();
  ResetTransientState();

  if FInitialAssociatedText <> nil then
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
end;

procedure TGcmBlockCipher.ProcessAadByte(AInput: Byte);
begin
  CheckStatus();

  FAadBlock[FAadBlockPos] := AInput;
  System.Inc(FAadBlockPos);
  if FAadBlockPos = BlockSize then
  begin
    GHASHBlock(FAadHashState, FAadBlock);
    FAadBlockPos := 0;
    FAadLength := FAadLength + UInt64(BlockSize);
  end;
end;

procedure TGcmBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
var
  LAvailable, LInLimit, LBatches: Int32;
begin
  CheckStatus();

  if FAadBlockPos > 0 then
  begin
    LAvailable := BlockSize - FAadBlockPos;
    if ALen < LAvailable then
    begin
      System.Move(AInput[AInOff], FAadBlock[FAadBlockPos], ALen);
      FAadBlockPos := FAadBlockPos + ALen;
      Exit;
    end;

    System.Move(AInput[AInOff], FAadBlock[FAadBlockPos], LAvailable);
    GHASHBlock(FAadHashState, FAadBlock);
    FAadLength := FAadLength + UInt64(BlockSize);
    AInOff := AInOff + LAvailable;
    ALen := ALen - LAvailable;
  end;

  // Bulk fast path: fold whole 128-byte spans through the fused 8-way GHASH
  // kernel in one call; the per-block loop below handles the remainder.
  if (FHashSubKeyPowers <> nil) and (ALen >= 128) then
  begin
    LBatches := ALen div 128;
    if TGhashSimd.TryFusedEightShuffledGhash(@FAadHashState[0], @AInput[AInOff],
      @FHashSubKeyPowers[0], LBatches) then
    begin
      AInOff := AInOff + LBatches * 128;
      ALen := ALen - LBatches * 128;
      FAadLength := FAadLength + UInt64(LBatches) * 128;
    end;
  end;

  LInLimit := AInOff + ALen - BlockSize;

  while AInOff <= LInLimit do
  begin
    GHASHBlock(FAadHashState, AInput, AInOff);
    FAadLength := FAadLength + UInt64(BlockSize);
    AInOff := AInOff + BlockSize;
  end;

  FAadBlockPos := BlockSize + LInLimit - AInOff;
  System.Move(AInput[AInOff], FAadBlock[0], FAadBlockPos);
end;

procedure TGcmBlockCipher.InitCipher;
begin
  if FAadLength > 0 then
  begin
    System.Move(FAadHashState[0], FAadHashStatePre[0], BlockSize);
    FAadLengthPre := FAadLength;
  end;

  if FAadBlockPos > 0 then
  begin
    GHASHPartial(FAadHashStatePre, FAadBlock, 0, FAadBlockPos);
    FAadLengthPre := FAadLengthPre + UInt64(FAadBlockPos);
  end;

  if FAadLengthPre > 0 then
    System.Move(FAadHashStatePre[0], FGHashState[0], BlockSize);
end;

function TGcmBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  CheckStatus();

  FBufferBlock[FBufferOffset] := AInput;
  System.Inc(FBufferOffset);
  if FBufferOffset = System.Length(FBufferBlock) then
  begin
    TCheck.OutputLength(AOutput, AOutOff, BlockSize, SOutputBufferTooShort);

    if FBlocksRemaining = 0 then
      raise EInvalidOperationCryptoLibException.CreateRes(@STooManyBlocks);

    System.Dec(FBlocksRemaining);

    if FTotalLength = 0 then
      InitCipher();

    if FForEncryption then
    begin
      CipherBlock(FBufferBlock, 0, AOutput, AOutOff, True);
      FBufferOffset := 0;
    end
    else
    begin
      CipherBlock(FBufferBlock, 0, AOutput, AOutOff, False);
      System.Move(FBufferBlock[BlockSize], FBufferBlock[0], FMacSize);
      FBufferOffset := FMacSize;
    end;

    FTotalLength := FTotalLength + UInt64(BlockSize);
    Result := BlockSize;
    Exit;
  end;
  Result := 0;
end;

procedure TGcmBlockCipher.RunTieredWholeBlocks(AForEncrypt: Boolean;
  const AInBuf: TCryptoLibByteArray; var AInOff: Int32; var ALen: Int32;
  const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32; AHoldBack: Int32);

  // Consume every remaining 2-block group above the hold-back. After a 4-tier
  // drain this iterates at most once (ALen < AHoldBack + 4*BlockSize); in the
  // scalar case it is the full 2-block loop.
  procedure RunTwoBlockTail;
  begin
    while ALen >= AHoldBack + BlockSize * 2 do
    begin
      CipherBlocks2(AInBuf, AInOff, AOutBuf, AOutOff, AForEncrypt);
      System.Inc(AInOff, BlockSize * 2);
      System.Dec(ALen, BlockSize * 2);
      System.Inc(AOutOff, BlockSize * 2);
    end;
  end;

begin
  // Widest supported tier first. Each tier method loops internally over its
  // stride, so after it the remainder is < that stride; the encrypt/decrypt
  // pair share the same shape (decrypt just carries the tag hold-back as its
  // per-tier limit). The 8-way branch runs the 4-way tier without re-checking
  // IsFourWaySupported because 8-way implies 4-way; FSoftwareBulkGHash is an exclusive
  // peer of the hardware tiers, never a fall-through below them.
  if TGcmBlockCipher.IsEightWaySupported and (ALen >= AHoldBack + BlockSize * 8)
  then
  begin
    if AForEncrypt then
      EncryptBlocks8(AInBuf, AInOff, ALen, AOutBuf, AOutOff)
    else
      DecryptBlocks8(AInBuf, AInOff, ALen, AOutBuf, AOutOff,
        AHoldBack + BlockSize * 8);
    if ALen >= AHoldBack + BlockSize * 4 then
    begin
      if AForEncrypt then
        EncryptBlocks4(AInBuf, AInOff, ALen, AOutBuf, AOutOff)
      else
        DecryptBlocks4(AInBuf, AInOff, ALen, AOutBuf, AOutOff,
          AHoldBack + BlockSize * 4);
    end;
    RunTwoBlockTail;
  end
  else if TGcmBlockCipher.IsFourWaySupported and
    (ALen >= AHoldBack + BlockSize * 4) then
  begin
    if AForEncrypt then
      EncryptBlocks4(AInBuf, AInOff, ALen, AOutBuf, AOutOff)
    else
      DecryptBlocks4(AInBuf, AInOff, ALen, AOutBuf, AOutOff,
        AHoldBack + BlockSize * 4);
    RunTwoBlockTail;
  end
  else if FSoftwareBulkGHash and (ALen >= AHoldBack + BlockSize * 4) then
  begin
    if AForEncrypt then
      EncryptBlocksSoftBulk4(AInBuf, AInOff, ALen, AOutBuf, AOutOff)
    else
      DecryptBlocksSoftBulk4(AInBuf, AInOff, ALen, AOutBuf, AOutOff,
        AHoldBack + BlockSize * 4);
    RunTwoBlockTail;
  end
  else
    RunTwoBlockTail;

  // Trailing single block above the hold-back (encrypt: ALen >= BlockSize;
  // decrypt: ALen >= BlockSize + FMacSize, i.e. Length(FBufferBlock)).
  if ALen >= AHoldBack + BlockSize then
  begin
    CipherBlock(AInBuf, AInOff, AOutBuf, AOutOff, AForEncrypt);
    System.Inc(AInOff, BlockSize);
    System.Dec(ALen, BlockSize);
  end;
end;

function TGcmBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LResultLen, LAvailable: Int32;
  LBlocksNeeded: UInt32;
begin
  CheckStatus();

  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);

  LResultLen := FBufferOffset + ALen;

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

    if FBufferOffset > 0 then
    begin
      LAvailable := BlockSize - FBufferOffset;
      if ALen < LAvailable then
      begin
        System.Move(AInput[AInOff], FBufferBlock[FBufferOffset], ALen);
        FBufferOffset := FBufferOffset + ALen;
        Result := 0;
        Exit;
      end;

      System.Move(AInput[AInOff], FBufferBlock[FBufferOffset], LAvailable);
      AInOff := AInOff + LAvailable;
      ALen := ALen - LAvailable;

      CipherBlock(FBufferBlock, 0, AOutput, AOutOff, True);
      AOutOff := AOutOff + BlockSize;
    end;

    RunTieredWholeBlocks(True, AInput, AInOff, ALen, AOutput, AOutOff, 0);

    FBufferOffset := ALen;
    System.Move(AInput[AInOff], FBufferBlock[0], FBufferOffset);
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

    LAvailable := System.Length(FBufferBlock) - FBufferOffset;
    if ALen < LAvailable then
    begin
      System.Move(AInput[AInOff], FBufferBlock[FBufferOffset], ALen);
      FBufferOffset := FBufferOffset + ALen;
      Result := 0;
      Exit;
    end;

    if FBufferOffset >= BlockSize then
    begin
      CipherBlock(FBufferBlock, 0, AOutput, AOutOff, False);
      AOutOff := AOutOff + BlockSize;

      FBufferOffset := FBufferOffset - BlockSize;
      System.Move(FBufferBlock[BlockSize], FBufferBlock[0], FBufferOffset);

      LAvailable := LAvailable + BlockSize;
      if ALen < LAvailable then
      begin
        System.Move(AInput[AInOff], FBufferBlock[FBufferOffset], ALen);
        FBufferOffset := FBufferOffset + ALen;

        FTotalLength := FTotalLength + UInt64(BlockSize);
        Result := BlockSize;
        Exit;
      end;
    end;

    LAvailable := BlockSize - FBufferOffset;
    System.Move(AInput[AInOff], FBufferBlock[FBufferOffset], LAvailable);
    AInOff := AInOff + LAvailable;
    ALen := ALen - LAvailable;

    CipherBlock(FBufferBlock, 0, AOutput, AOutOff, False);
    AOutOff := AOutOff + BlockSize;

    // Hold-back = FMacSize (= Length(FBufferBlock) - BlockSize on decrypt) so the
    // trailing tag is never consumed as payload; the thresholds LThreshN in the
    // former inline staircase equalled AHoldBack + BlockSize*N.
    RunTieredWholeBlocks(False, AInput, AInOff, ALen, AOutput, AOutOff,
      System.Length(FBufferBlock) - BlockSize);

    FBufferOffset := ALen;
    System.Move(AInput[AInOff], FBufferBlock[0], FBufferOffset);
  end;

  FTotalLength := FTotalLength + UInt64(LResultLen);
  Result := LResultLen;
end;

function TGcmBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LExtra, LResultLen: Int32;
  LC: Int64;
begin
  CheckStatus();

  LExtra := FBufferOffset;

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

    ProcessPartial(FBufferBlock, 0, LExtra, AOutput, AOutOff);
  end;

  FAadLength := FAadLength + UInt64(FAadBlockPos);

  if FAadLength > FAadLengthPre then
  begin
    if FAadBlockPos > 0 then
      GHASHPartial(FAadHashState, FAadBlock, 0, FAadBlockPos);

    if FAadLengthPre > 0 then
      TGcmUtilities.&Xor(FAadHashState, FAadHashStatePre);

    LC := Int64(((FTotalLength * 8) + 127) shr 7);

    if FLengthExponent = nil then
      System.SetLength(FLengthExponent, 16);
    if FExponentiator = nil then
    begin
      FExponentiator := TBasicGcmExponentiator.Create() as IGcmExponentiator;
      FExponentiator.Init(FHashSubKey);
    end;
    FExponentiator.ExponentiateX(LC, FLengthExponent);

    TGcmUtilities.Multiply(FAadHashState, FLengthExponent);

    TGcmUtilities.&Xor(FGHashState, FAadHashState);
  end;

  if FLengthBlock = nil then
    System.SetLength(FLengthBlock, BlockSize);
  TPack.UInt64_To_BE(FAadLength * UInt64(8), FLengthBlock, 0);
  TPack.UInt64_To_BE(FTotalLength * UInt64(8), FLengthBlock, 8);

  GHASHBlock(FGHashState, FLengthBlock);

  if FTagBlock = nil then
    System.SetLength(FTagBlock, BlockSize);
  FCipher.ProcessBlock(FPreCounterBlock, 0, FTagBlock, 0);
  TGcmUtilities.&Xor(FTagBlock, FGHashState);

  LResultLen := LExtra;

  if (FMacBlock = nil) or (System.Length(FMacBlock) <> FMacSize) then
    System.SetLength(FMacBlock, FMacSize);
  System.Move(FTagBlock[0], FMacBlock[0], FMacSize);

  if FForEncryption then
  begin
    System.Move(FMacBlock[0], AOutput[AOutOff + FBufferOffset], FMacSize);
    LResultLen := LResultLen + FMacSize;
  end
  else
  begin
    if (FReceivedMac = nil) or (System.Length(FReceivedMac) <> FMacSize) then
      System.SetLength(FReceivedMac, FMacSize);
    System.Move(FBufferBlock[LExtra], FReceivedMac[0], FMacSize);
    if not TArrayUtilities.FixedTimeEquals(FMacBlock, FReceivedMac) then
      RaiseMacCheckFailed();
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
  TArrayUtilities.Fill(FGHashState, 0, System.Length(FGHashState), Byte(0));
  TArrayUtilities.Fill(FAadHashState, 0, System.Length(FAadHashState), Byte(0));
  TArrayUtilities.Fill(FAadHashStatePre, 0, System.Length(FAadHashStatePre), Byte(0));
  TArrayUtilities.Fill(FAadBlock, 0, System.Length(FAadBlock), Byte(0));
  FAadBlockPos := 0;
  FAadLength := 0;
  FAadLengthPre := 0;
  if FCounterBlock = nil then
    System.SetLength(FCounterBlock, BlockSize);
  System.Move(FPreCounterBlock[0], FCounterBlock[0], BlockSize);
  FCounterWord := TPack.BE_To_UInt32(FCounterBlock, 12);
  FBlocksRemaining := UInt32($FFFFFFFF) - 1;
  FBufferOffset := 0;
  FTotalLength := 0;

  if FBufferBlock <> nil then
    TArrayUtilities.Fill(FBufferBlock, 0, System.Length(FBufferBlock), Byte(0));

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

procedure TGcmBlockCipher.WipeKeyMaterial();
begin
  TArrayUtilities.Fill(FHashSubKey, 0, System.Length(FHashSubKey), Byte(0));
  TArrayUtilities.Fill(FHashSubKeyPowers, 0, System.Length(FHashSubKeyPowers), Byte(0));
  TArrayUtilities.Fill(FCounterKeystream, 0, System.Length(FCounterKeystream), Byte(0));
  TArrayUtilities.Fill(FCounterKeystreamAhead, 0, System.Length(FCounterKeystreamAhead), Byte(0));
  FHashSubKeyPow1.N0 := 0; FHashSubKeyPow1.N1 := 0;
  FHashSubKeyPow2.N0 := 0; FHashSubKeyPow2.N1 := 0;
  FHashSubKeyPow3.N0 := 0; FHashSubKeyPow3.N1 := 0;
  FHashSubKeyPow4.N0 := 0; FHashSubKeyPow4.N1 := 0;
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
  LB: Int32;
  LPCiph: PByte;
begin
  if TGhashSimd.TryFusedFourShuffledGhash(@FGHashState[0], PC0, @FHashSubKeyPowers[64], 1) then
    Exit;
  // Unreachable in practice (the caller gates on the same predicate as the
  // kernel); fold per block through the multiplier, which is independent of
  // the x-pre-multiplied FHashSubKeyPowers layout.
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
    TByteUtilities.&Xor(BlockSize, @FGHashState[0], LPCiph, @FGHashState[0]);
    FMultiplier.MultiplyH(FGHashState);
  end;
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
// supplied by the cipher-kernel registry (nil off-SIMD, so that path is
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
  LPIn, LPOut: PByte;
begin
  GetNextCtrBlocks4(FCounterKeystream);
  LPIn := PByte(AInBuf) + AInOff;
  LPOut := PByte(AOutBuf) + AOutOff;
  // Decrypt hashes the input ciphertext, read before the XOR overwrites it
  // (the in-place case aliases input and output).
  if AForEncrypt then
  begin
    TByteUtilities.&Xor(64, LPIn, PByte(FCounterKeystream), LPOut);
    GhashFourShuffledBlocks(LPOut, LPOut + 16, LPOut + 32, LPOut + 48);
  end
  else
  begin
    GhashFourShuffledBlocks(LPIn, LPIn + 16, LPIn + 32, LPIn + 48);
    TByteUtilities.&Xor(64, LPIn, PByte(FCounterKeystream), LPOut);
  end;
end;

procedure TGcmBlockCipher.GhashEightShuffledBlocks(PBase: PByte);
var
  LB: Int32;
begin
  if TGhashSimd.TryFusedEightShuffledGhash(@FGHashState[0], PBase, @FHashSubKeyPowers[0], 1) then
    Exit;
  // Unreachable in practice (the caller gates on the same predicate as the
  // kernel); fold per block through the multiplier, which is independent of
  // the x-pre-multiplied FHashSubKeyPowers layout.
  for LB := 0 to 7 do
  begin
    TByteUtilities.&Xor(BlockSize, @FGHashState[0], PBase + (LB * BlockSize), @FGHashState[0]);
    FMultiplier.MultiplyH(FGHashState);
  end;
end;

// Single-batch fused 8-way GCM step. See ProcessBlocks4Fused for direction semantics.
procedure TGcmBlockCipher.ProcessBlocks8Fused(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32;
  AForEncrypt: Boolean);
var
  LPIn, LPOut: PByte;
begin
  GetNextCtrBlocks8(FCounterKeystream);
  LPIn := PByte(AInBuf) + AInOff;
  LPOut := PByte(AOutBuf) + AOutOff;
  // Decrypt hashes the input ciphertext, read before the XOR overwrites it
  // (the in-place case aliases input and output).
  if AForEncrypt then
  begin
    TByteUtilities.&Xor(128, LPIn, PByte(FCounterKeystream), LPOut);
    GhashEightShuffledBlocks(LPOut);
  end
  else
  begin
    GhashEightShuffledBlocks(LPIn);
    TByteUtilities.&Xor(128, LPIn, PByte(FCounterKeystream), LPOut);
  end;
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

  LCurr := FCounterKeystream;
  LNext := FCounterKeystreamAhead;

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

  LCurr := FCounterKeystream;
  LNext := FCounterKeystreamAhead;

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
// fused work to whichever IGcmKernel the registry resolved (nil
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

  // Non-lagged decrypt: the kernel GHASHes each batch's own input ciphertext
  // (read before its XOR), so there is no prime batch to seed and no trailing
  // batch to drain, and input/output may alias. Process every full batch that
  // clears the tail hold-back and let the caller's per-batch loop mop up.
  if not AForEncrypt then
  begin
    LBatches := (ALen - ALimit) div (BlockSize * 8);
    if LBatches > 0 then
    begin
      LPIn := PByte(AInBuf) + AInOff;
      LPOut := PByte(AOutBuf) + AOutOff;
      FCounterWord := FGcmKernel.ProcessCtrGhashBatches(LPIn, LPOut, LPIn,
        @FGHashState[0], @FPreCounterBlock[0], FCounterWord, LBatches, False);
      AInOff := AInOff + LBatches * (BlockSize * 8);
      AOutOff := AOutOff + LBatches * (BlockSize * 8);
      ALen := ALen - LBatches * (BlockSize * 8);
    end;
    Exit;
  end;

  LCurrCtrs := FCounterKeystream;

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
    FCounterWord := FGcmKernel.ProcessCtrGhashBatches(LPIn, LPOut, LPrevCipher,
      @FGHashState[0], @FPreCounterBlock[0], FCounterWord, LBatches, AForEncrypt);
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
  if FHashSubKeyPowers = nil then
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
  if (FHashSubKeyPowers = nil) or (System.Length(FHashSubKeyPowers) < 128) then
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
  // Read the input block through the three-operand XOR before it can be
  // overwritten, so the in-place case (Out aliases In) stays correct.
  if AForEncrypt then
  begin
    // Out := In xor keystream (ciphertext); FGHashState := FGHashState xor Out.
    TByteUtilities.&Xor(BlockSize, PByte(@AInBuf[AInOff]), PByte(@LCtrBlock[0]),
      PByte(@AOutBuf[AOutOff]));
    TByteUtilities.XorTo(BlockSize, PByte(@AOutBuf[AOutOff]), PByte(@FGHashState[0]));
  end
  else
  begin
    // FGHashState := FGHashState xor In (ciphertext) first; then Out := In xor keystream.
    TByteUtilities.XorTo(BlockSize, PByte(@AInBuf[AInOff]), PByte(@FGHashState[0]));
    TByteUtilities.&Xor(BlockSize, PByte(@AInBuf[AInOff]), PByte(@LCtrBlock[0]),
      PByte(@AOutBuf[AOutOff]));
  end;
  FMultiplier.MultiplyH(FGHashState);
end;

procedure TGcmBlockCipher.DecryptBlocks4(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32);
begin
  if not TGcmBlockCipher.IsFourWaySupported then
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SGcmBlockPathNotSupported, ['four']);
  if ALimit < BlockSize * 4 then
    raise EArgumentCryptoLibException.CreateResFmt(@SGcmDecryptBadLimit, ['four']);
  if FHashSubKeyPowers = nil then
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
  if (FHashSubKeyPowers = nil) or (System.Length(FHashSubKeyPowers) < 128) then
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

// Scalar aggregated 4-way GHASH over four consecutive 16-byte blocks at
// ABuf[AOff..AOff+63], folding them into the running state FGHashState in one reduction.
procedure TGcmBlockCipher.SoftAggregateGhash4(const ABuf: TCryptoLibByteArray;
  AOff: Int32);
var
  LY, LX1, LX2, LX3, LX4: TFieldElement;
begin
  TGcmUtilities.AsFieldElement(FGHashState, LY);
  LX1.N0 := TPack.BE_To_UInt64(ABuf, AOff);
  LX1.N1 := TPack.BE_To_UInt64(ABuf, AOff + 8);
  LX2.N0 := TPack.BE_To_UInt64(ABuf, AOff + 16);
  LX2.N1 := TPack.BE_To_UInt64(ABuf, AOff + 24);
  LX3.N0 := TPack.BE_To_UInt64(ABuf, AOff + 32);
  LX3.N1 := TPack.BE_To_UInt64(ABuf, AOff + 40);
  LX4.N0 := TPack.BE_To_UInt64(ABuf, AOff + 48);
  LX4.N1 := TPack.BE_To_UInt64(ABuf, AOff + 56);
  TGcmUtilities.AggregateGhash4(LY, LX1, LX2, LX3, LX4,
    FHashSubKeyPow1, FHashSubKeyPow2, FHashSubKeyPow3, FHashSubKeyPow4);
  TGcmUtilities.AsBytes(LY, FGHashState);
end;

// Single software-bulk 4-way step: bulk AES keystream via FBulkCipher, XOR,
// then aggregated GHASH. AForEncrypt hashes the output (encrypt) or input (decrypt).
procedure TGcmBlockCipher.ProcessSoftBulk4(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32;
  AForEncrypt: Boolean);
begin
  GetNextCtrBlocks4(FCounterKeystream);
  // Decrypt hashes the input ciphertext, which must be read before the XOR
  // overwrites it (the in-place case aliases input and output).
  if AForEncrypt then
  begin
    TByteUtilities.&Xor(64, PByte(AInBuf) + AInOff, PByte(FCounterKeystream),
      PByte(AOutBuf) + AOutOff);
    SoftAggregateGhash4(AOutBuf, AOutOff);
  end
  else
  begin
    SoftAggregateGhash4(AInBuf, AInOff);
    TByteUtilities.&Xor(64, PByte(AInBuf) + AInOff, PByte(FCounterKeystream),
      PByte(AOutBuf) + AOutOff);
  end;
end;

procedure TGcmBlockCipher.EncryptBlocksSoftBulk4(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32);
begin
  while ALen >= BlockSize * 4 do
  begin
    ProcessSoftBulk4(AInBuf, AInOff, AOutBuf, AOutOff, True);
    AInOff := AInOff + (BlockSize * 4);
    ALen := ALen - (BlockSize * 4);
    AOutOff := AOutOff + (BlockSize * 4);
  end;
end;

procedure TGcmBlockCipher.DecryptBlocksSoftBulk4(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32);
begin
  while ALen >= ALimit do
  begin
    ProcessSoftBulk4(AInBuf, AInOff, AOutBuf, AOutOff, False);
    AInOff := AInOff + (BlockSize * 4);
    ALen := ALen - (BlockSize * 4);
    AOutOff := AOutOff + (BlockSize * 4);
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
    // Read the input block through the three-operand XOR before it can be
    // overwritten, so the in-place case (Out aliases In) stays correct.
    if AForEncrypt then
    begin
      TByteUtilities.&Xor(BlockSize, PByte(@AInBuf[AInOff]), PByte(@LCtrBlock[0]),
        PByte(@AOutBuf[AOutOff]));
      TByteUtilities.XorTo(BlockSize, PByte(@AOutBuf[AOutOff]), PByte(@FGHashState[0]));
    end
    else
    begin
      TByteUtilities.XorTo(BlockSize, PByte(@AInBuf[AInOff]), PByte(@FGHashState[0]));
      TByteUtilities.&Xor(BlockSize, PByte(@AInBuf[AInOff]), PByte(@LCtrBlock[0]),
        PByte(@AOutBuf[AOutOff]));
    end;
    FMultiplier.MultiplyH(FGHashState);
    AInOff := AInOff + BlockSize;
    AOutOff := AOutOff + BlockSize;
  end;
end;

// =======================================================================
// CTR keystream helpers (scalar, 4-way, and 8-way).
// =======================================================================

procedure TGcmBlockCipher.GetNextCtrBlock(const ABlock: TCryptoLibByteArray);
begin
  System.Inc(FCounterWord);
  TPack.UInt32_To_BE(FCounterWord, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlock, 0);
end;

procedure TGcmBlockCipher.GetNextCtrBlocks4(const ABlocks: TCryptoLibByteArray);
var
  Lc0, Lc1, Lc2, Lc3, Lc4: UInt32;
begin
  Lc0 := FCounterWord;
  Lc1 := Lc0 + UInt32(1);
  Lc2 := Lc0 + UInt32(2);
  Lc3 := Lc0 + UInt32(3);
  Lc4 := Lc0 + UInt32(4);
  FCounterWord := Lc4;

  if FBulkCipher <> nil then
  begin
    System.Move(FCounterBlock[0], ABlocks[0], 16);
    System.Move(FCounterBlock[0], ABlocks[16], 16);
    System.Move(FCounterBlock[0], ABlocks[32], 16);
    TPack.UInt32_To_BE(Lc4, FCounterBlock, 12);
    TPack.UInt32_To_BE(Lc1, ABlocks, 12);
    TPack.UInt32_To_BE(Lc2, ABlocks, 28);
    TPack.UInt32_To_BE(Lc3, ABlocks, 44);
    System.Move(FCounterBlock[0], ABlocks[48], 16);
    FBulkCipher.ProcessBlocks(@ABlocks[0], @ABlocks[0], 4);
    Exit;
  end;

  TPack.UInt32_To_BE(Lc1, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 0);
  TPack.UInt32_To_BE(Lc2, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 16);
  TPack.UInt32_To_BE(Lc3, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 32);
  TPack.UInt32_To_BE(Lc4, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 48);
end;

procedure TGcmBlockCipher.GetNextCtrBlocks8(const ABlocks: TCryptoLibByteArray);
var
  Lc0, Lc1, Lc2, Lc3, Lc4, Lc5, Lc6, Lc7, Lc8: UInt32;
begin
  if FBulkCipher <> nil then
  begin
    FillCtr8BlocksRaw(FCounterBlock, FCounterWord, ABlocks);
    FBulkCipher.ProcessBlocks(@ABlocks[0], @ABlocks[0], 8);
    Exit;
  end;

  Lc0 := FCounterWord;
  Lc1 := Lc0 + UInt32(1);
  Lc2 := Lc0 + UInt32(2);
  Lc3 := Lc0 + UInt32(3);
  Lc4 := Lc0 + UInt32(4);
  Lc5 := Lc0 + UInt32(5);
  Lc6 := Lc0 + UInt32(6);
  Lc7 := Lc0 + UInt32(7);
  Lc8 := Lc0 + UInt32(8);
  FCounterWord := Lc8;

  TPack.UInt32_To_BE(Lc1, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 0);
  TPack.UInt32_To_BE(Lc2, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 16);
  TPack.UInt32_To_BE(Lc3, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 32);
  TPack.UInt32_To_BE(Lc4, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 48);
  TPack.UInt32_To_BE(Lc5, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 64);
  TPack.UInt32_To_BE(Lc6, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 80);
  TPack.UInt32_To_BE(Lc7, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 96);
  TPack.UInt32_To_BE(Lc8, FCounterBlock, 12);
  FCipher.ProcessBlock(FCounterBlock, 0, ABlocks, 112);
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
    GHASHPartial(FGHashState, ABuf, AOff, ALen);
  end
  else
  begin
    GHASHPartial(FGHashState, ABuf, AOff, ALen);
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
