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

unit ClpCbcBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBulkBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpICbcBlockCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpIRawKeyedCipher,
  ClpIRawInitBlockCipherMode,
  ClpAbstractBlockCipherMode,
  ClpBlockCipherBulkUtilities,
  ClpCipherKernelTypes,
  ClpCipherKernelBinding,
  ClpICbcKernel,
  ClpCipherKernelRegistry,
  ClpArrayUtilities,
  ClpByteUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SInvalidIVLength =
    'initialization vector must be the same length as block size';
  SInvalidChangeState = 'cannot change encrypting state without providing key';
  SInputBufferTooShort = 'input buffer too short';

type
  /// <summary>
  /// Implements cipher block chaining (<c>CBC</c>) over a symmetric block cipher: each plaintext block
  /// is XORed with the prior ciphertext block before encrypting (<c>C[i] := E(K, P[i] xor C[i-1])</c>),
  /// with the chaining vector seeded from an IV passed at <c>Init</c>.
  /// </summary>
  /// <remarks>
  /// Pass key and IV together using <see cref="IParametersWithIV" />; the IV byte count must match
  /// the block size. Each <c>ProcessBlock</c> call consumes and produces one block; padding of the
  /// last block is a separate concern.
  /// </remarks>
  TCbcBlockCipher = class sealed(TAbstractBlockCipherMode, ICbcBlockCipher,
    IBulkBlockCipherMode, IRawInitBlockCipherMode)

  strict private
  var
    FIV, FCbcV, FCbcNextV: TCryptoLibByteArray;
    // Cached on Init. Non-nil only when the underlying engine implements
    // IBulkBlockCipher. CBC decrypt exposes 8 independent inverse
    // transforms per call, which a parallel-capable engine can pipeline;
    // CBC encrypt stays serial (C[i] depends on C[i-1]) but still saves
    // one interface dispatch per block. Any bulk-capable block cipher
    // lights up both paths automatically by implementing the interface.
    FBulkCipher: IBulkBlockCipher;
    // Cached on Init, direction-matched to FForEncryption. Non-nil when a
    // registered accelerator claims the underlying cipher. Encrypt runs the
    // whole serial chain C[i] = E(P[i] xor C[i-1]) in one register-held call;
    // decrypt runs P[i] = DEC(C[i]) xor C[i-1] as a single fused pass (parallel
    // aesdec + chain XOR). Both update FCbcV in place, matching the per-block
    // post-state exactly. nil otherwise -- the bulk fallbacks below take over.
    FCbcKernel: ICbcKernel;
    // Gate for the bulk probe + kernel acquire: lets a same-key same-direction
    // re-Init skip the registry walk and reuse the cached handles.
    FKernelBinding: TCipherKernelBinding;
    // Raw-key view of FCipher (nil if the engine does not implement it); probed
    // once. Lets InitRaw re-key from raw bytes with no per-message key parameter.
    FRawEngine: IRawKeyedCipher;
    FRawEngineProbed: Boolean;

    function EncryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function DecryptBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;

    // Bulk encrypt via cached bulk engine. Serial by definition (each
    // ciphertext block feeds the next XOR), but dispatches through the
    // engine's IBlockCipher.ProcessBlock, inherited from the same vtable
    // as IBulkBlockCipher so there's no extra probe.
    procedure CbcEncryptBulk(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32);
    // Bulk decrypt via cached bulk engine. Decrypts in 8-block batches
    // with ciphertext staging (so in-place aliasing cannot corrupt the
    // chain XOR), then applies FCbcV + staged ciphertext. 1..7 block
    // residue goes through per-block DecryptBlock -- engine-owned
    // batch ladder handles anything smaller internally if needed.
    procedure CbcDecryptBulk(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32);

  strict protected
    function GetModeName: String; override;

  public
    /// <summary>Construct a CBC wrapper around <paramref name="ACipher" /> (block size taken from it).</summary>
    constructor Create(const ACipher: IBlockCipher);
    /// <summary>Initialise for encryption or decryption; key and IV from <paramref name="AParameters" />.</summary>
    /// <param name="AForEncryption"><c>True</c> to encrypt, <c>False</c> to decrypt.</param>
    /// <param name="AParameters">Typically <see cref="IParametersWithIV" /> over a <see cref="IKeyParameter"/>.</param>
    /// <exception cref="EArgumentCryptoLibException">If the IV length is wrong or cipher state cannot change without a key.</exception>
    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); override;
    procedure InitRaw(AForEncryption: Boolean;
      const AKey, AIv: TCryptoLibByteArray);
    /// <summary>Encrypt or decrypt exactly one block (<c>GetBlockSize</c> bytes).</summary>
    /// <exception cref="EDataLengthCryptoLibException">If input or output ranges are shorter than one block.</exception>
    function ProcessBlock(const AInput: TCryptoLibByteArray; AInOff: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; override;

    /// <summary>
    /// IBulkBlockCipherMode: process ABlockCount consecutive CBC blocks.
    /// Output is byte-identical to ABlockCount sequential ProcessBlock
    /// calls and the chaining state (FCbcV) is left exactly as if those
    /// calls had been made. When the underlying engine exposes an
    /// accelerated IBulkBlockCipher path and the block size is 16 bytes,
    /// batches are dispatched through it; otherwise the implementation
    /// falls back to the per-block ProcessBlock loop with no change in
    /// semantics.
    /// </summary>
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32;

    /// <summary>Reset the chaining vector from the stored IV and clear the next-block buffer used during decrypt.</summary>
    procedure Reset(); override;
  end;

implementation

{ TCbcBlockCipher }

constructor TCbcBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create(ACipher);
  System.SetLength(FIV, FBlockSize);
  System.SetLength(FCbcV, FBlockSize);
  System.SetLength(FCbcNextV, FBlockSize);
  FBulkCipher := nil;
end;

function TCbcBlockCipher.DecryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LLength: Int32;
  LTmp: TCryptoLibByteArray;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  System.Move(AInput[AInOff], FCbcNextV[0], FBlockSize * System.SizeOf(Byte));
  LLength := FCipher.ProcessBlock(AInput, AInOff, AOutBytes, AOutOff);
  TByteUtilities.XorTo(FBlockSize, PByte(@FCbcV[0]), PByte(@AOutBytes[AOutOff]));
  LTmp := FCbcV;
  FCbcV := FCbcNextV;
  FCbcNextV := LTmp;
  Result := LLength;
end;

function TCbcBlockCipher.EncryptBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LLen: Int32;
begin
  if ((AInOff + FBlockSize) > System.Length(AInput)) then
    raise EDataLengthCryptoLibException.CreateRes(@SInputBufferTooShort);
  TByteUtilities.XorTo(FBlockSize, PByte(@AInput[AInOff]), PByte(@FCbcV[0]));
  LLen := FCipher.ProcessBlock(FCbcV, 0, AOutBytes, AOutOff);
  System.Move(AOutBytes[AOutOff], FCbcV[0], System.Length(FCbcV) * System.SizeOf(Byte));
  Result := LLen;
end;

procedure TCbcBlockCipher.CbcEncryptBulk(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32);
var
  LPCbcV, LPIn, LPOut: PByte;
begin
  // 16-byte CBC encryption: C[i] = ENC(P[i] XOR C[i-1]). Serial chain.
  // We mutate FCbcV in place across the batch; the final value equals the
  // last produced ciphertext block, exactly matching sequential EncryptBlock.

  // Fast path: a registered accelerator runs the whole serial chain in one
  // call, holding the chaining value in a register (no per-block dispatch,
  // XOR helper call, or FCbcV store/reload). It updates FCbcV in place, so the
  // post-state matches the per-block path exactly.
  if FCbcKernel <> nil then
  begin
    FCbcKernel.ProcessCbcBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff],
      @FCbcV[0], ABlockCount);
    Exit;
  end;

  // Dispatches via FBulkCipher.ProcessBlock (inherited from IBlockCipher);
  // this is the same vtable entry the engine already services for single-
  // block calls, so no extra probe per iteration.
  LPCbcV := @FCbcV[0];
  while ABlockCount > 0 do
  begin
    LPIn := @AInBuf[AInOff];
    LPOut := @AOutBuf[AOutOff];
    TByteUtilities.XorTo(16, LPIn, LPCbcV);
    FBulkCipher.ProcessBlock(FCbcV, 0, AOutBuf, AOutOff);
    System.Move(LPOut^, LPCbcV^, 16);
    System.Inc(AInOff, 16);
    System.Inc(AOutOff, 16);
    System.Dec(ABlockCount);
  end;
end;

procedure TCbcBlockCipher.CbcDecryptBulk(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32);
var
  LCtStage: array [0 .. 127] of Byte;
  LPIn, LPOut: PByte;
  LTotal: Int32;
begin
  // 16-byte CBC decryption: P[i] = DEC(C[i]) XOR C[i-1] (with C[-1] = IV
  // carried in FCbcV). DEC(C[i]) are all independent (8-wide parallel), and
  // every XOR feed C[i-1] is *input* ciphertext -- so there is no serial
  // dependency; the whole run parallelises.

  // Fast path: a registered accelerator fuses the parallel aesdec and the chain
  // XOR into a single pass over memory (vs the decrypt-then-XOR two passes
  // below), handling any block count and in-place aliasing internally, and
  // updates FCbcV in place to the last ciphertext block.
  if FCbcKernel <> nil then
  begin
    FCbcKernel.ProcessCbcBlocks(@AInBuf[AInOff], @AOutBuf[AOutOff],
      @FCbcV[0], ABlockCount);
    Exit;
  end;

  LPIn := @AInBuf[AInOff];
  LPOut := @AOutBuf[AOutOff];
  LTotal := ABlockCount * 16;

  // Fast path: input and output regions do not overlap (the usual case -- the
  // buffered cipher hands us separate buffers). Decrypt the entire run in one
  // engine call (full 8-wide throughput, = ECB decrypt), then apply the chain
  // XOR in a single pass reading the still-intact input: out[0] ^= FCbcV,
  // out[i] ^= C[i-1] (= input block i-1). No per-batch staging.
  if (NativeUInt(LPIn) + NativeUInt(LTotal) <= NativeUInt(LPOut)) or
    (NativeUInt(LPOut) + NativeUInt(LTotal) <= NativeUInt(LPIn)) then
  begin
    FBulkCipher.ProcessBlocks(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff);
    TByteUtilities.&Xor(16, LPOut, @FCbcV[0], LPOut);
    if ABlockCount > 1 then
      TByteUtilities.&Xor((ABlockCount - 1) * 16, LPOut + 16, LPIn, LPOut + 16);
    System.Move((LPIn + (ABlockCount - 1) * 16)^, FCbcV[0], 16);
    Exit;
  end;

  // Overlapping / in-place path: stage each 8-block batch's ciphertext up front
  // (so the in-place decrypt cannot corrupt the XOR feed), then chain-XOR.
  while ABlockCount >= 8 do
  begin
    System.Move(AInBuf[AInOff], LCtStage[0], 128);
    FBulkCipher.ProcessBlocks(AInBuf, AInOff, 8, AOutBuf, AOutOff);

    LPOut := @AOutBuf[AOutOff];
    TByteUtilities.&Xor(16, LPOut, @FCbcV[0], LPOut);
    TByteUtilities.&Xor(112, LPOut + 16, @LCtStage[0], LPOut + 16);

    System.Move(LCtStage[7 * 16], FCbcV[0], 16);
    System.Inc(AInOff, 128);
    System.Inc(AOutOff, 128);
    System.Dec(ABlockCount, 8);
  end;

  // Tail 1..7 blocks fall through to per-block DecryptBlock.
  while ABlockCount > 0 do
  begin
    DecryptBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    System.Inc(AInOff, 16);
    System.Inc(AOutOff, 16);
    System.Dec(ABlockCount);
  end;
end;

procedure TCbcBlockCipher.Reset;
begin
  System.Move(FIV[0], FCbcV[0], System.Length(FIV));
  TArrayUtilities.Fill(FCbcNextV, 0, System.Length(FCbcNextV), Byte(0));
end;

function TCbcBlockCipher.GetModeName: String;
begin
  Result := '/CBC';
end;

procedure TCbcBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParam: IParametersWithIV;
  LKeyParam: IKeyParameter;
  LKey, LIv: TCryptoLibByteArray;
begin
  LIv := nil;
  if Supports(AParameters, IParametersWithIV, LIvParam) then
  begin
    LIv := LIvParam.GetIV();
    Supports(LIvParam.Parameters, IKeyParameter, LKeyParam);
  end
  else
    Supports(AParameters, IKeyParameter, LKeyParam);

  if LKeyParam <> nil then
    LKey := LKeyParam.GetKey()
  else
    LKey := nil;

  InitRaw(AForEncryption, LKey, LIv);
end;

procedure TCbcBlockCipher.InitRaw(AForEncryption: Boolean;
  const AKey, AIv: TCryptoLibByteArray);
var
  LOldEncrypting: Boolean;
  LDir: TCipherKernelDirection;
begin
  LOldEncrypting := FForEncryption;
  FForEncryption := AForEncryption;

  // AIv <> nil: copy it in place (no GetIV allocation). AIv = nil keeps the
  // current FIV (a bare-key re-Init).
  if AIv <> nil then
  begin
    if (System.Length(AIv) <> FBlockSize) then
      raise EArgumentCryptoLibException.CreateRes(@SInvalidIVLength);
    System.Move(AIv[0], FIV[0], FBlockSize * System.SizeOf(Byte));
  end;

  Reset();

  // nil key = reuse the established schedule (raw-key compare-only gate for a
  // real key); CBC cannot flip direction without a key (schedule differs enc/dec).
  if AKey <> nil then
  begin
    if not FRawEngineProbed then
    begin
      if not Supports(FCipher, IRawKeyedCipher, FRawEngine) then
        FRawEngine := nil;
      FRawEngineProbed := True;
    end;
    if FRawEngine <> nil then
      FRawEngine.InitRaw(FForEncryption, AKey)
    else
      FCipher.Init(FForEncryption, TKeyParameter.Create(AKey) as ICipherParameters);
  end
  else if (LOldEncrypting <> FForEncryption) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidChangeState);

  // Bulk probe + direction-matched fused kernel are bound to FCipher's key
  // schedule, so only (re)acquire when the binding reports the schedule or
  // direction changed; a same-key same-direction re-Init reuses both cached
  // handles. Encrypt folds the serial chain into one register-held pass; decrypt
  // folds the chain XOR into the parallel aesdec pass. nil -> the bulk fallbacks.
  if FForEncryption then
    LDir := TCipherKernelDirection.Encrypt
  else
    LDir := TCipherKernelDirection.Decrypt;
  if FKernelBinding.NeedsRebind(FCipher, LDir) then
  begin
    TBlockCipherBulkUtilities.TryResolveBulkCipher(FCipher, FBulkCipher);
    TCipherKernelRegistry.TryAcquireCbc(FCipher, LDir, FCbcKernel);
  end;
end;

function TCbcBlockCipher.ProcessBlock(const AInput: TCryptoLibByteArray;
  AInOff: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  if FForEncryption then
    Result := EncryptBlock(AInput, AInOff, AOutput, AOutOff)
  else
    Result := DecryptBlock(AInput, AInOff, AOutput, AOutOff);
end;

function TCbcBlockCipher.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LTotalBytes: Int32;
begin
  LTotalBytes := CheckBlockBuffers(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff);
  if LTotalBytes = 0 then
  begin
    Result := 0;
    Exit;
  end;

  // Fast path: bulk engine available AND classic 16-byte block size. The
  // block-size guard matches the 16-byte-specific strides inside CbcEncryptBulk
  // (per-byte XOR over 0..15) and CbcDecryptBulk (128-byte stage buffer).
  if (FBulkCipher <> nil) and (FBlockSize = 16) then
  begin
    if FForEncryption then
      CbcEncryptBulk(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff)
    else
      CbcDecryptBulk(AInBuf, AInOff, ABlockCount, AOutBuf, AOutOff);
    Result := LTotalBytes;
    Exit;
  end;

  // Fallback: no bulk capability wired up (or non-16-byte block).
  while ABlockCount > 0 do
  begin
    if FForEncryption then
      EncryptBlock(AInBuf, AInOff, AOutBuf, AOutOff)
    else
      DecryptBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    System.Inc(AInOff, FBlockSize);
    System.Inc(AOutOff, FBlockSize);
    System.Dec(ABlockCount);
  end;

  Result := LTotalBytes;
end;

end.
