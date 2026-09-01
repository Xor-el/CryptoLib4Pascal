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

unit ClpCcmBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  SysUtils,
  ClpIBlockCipher,
  ClpICcmBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpBlockCipherBulkUtilities,
  ClpCipherKernelTypes,
  ClpCipherKernelBinding,
  ClpIRawInitBlockCipherMode,
  ClpICcmKernel,
  ClpCipherKernelRegistry,
  ClpCipherKernelDefaults, // registers in-tree fused AEAD kernel factories
  ClpCipherModeParameterUtilities,
  ClpKeyParameter,
  ClpCbcBlockCipherMac,
  ClpIMac,
  ClpParametersWithIV,
  ClpAbstractAeadCipher,
  ClpAbstractAeadBlockCipher,
  ClpCheck,
  ClpArrayUtilities,
  ClpByteUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SCipherRequired = 'cipher required with a block size of %d';
  SInvalidParameters = 'invalid parameters passed to %s';
  SNonceLengthRange = 'nonce must have length from 7 to 13 octets';
  SKeyMustBeSpecified = 'key must be specified in initial packet';
  SCcmUninitialised = 'CCM cipher uninitialized';
  SCcmPacketTooLarge = 'CCM packet too large for choice of q';
  SDataTooShort = 'data too short';
  STagLengthOctets = 'tag length in octets must be one of {4,6,8,10,12,14,16}';
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';

type
  // Per-packet inputs a body decryptor needs (Dest/DestOff set by RunDecrypt).
  TCcmDecryptCtx = record
    Input: TCryptoLibByteArray;
    InOff: Int32;
    OutputLen: Int32;
    Dest: TCryptoLibByteArray;
    DestOff: Int32;
    Iv: TCryptoLibByteArray;
    CtrCipher: ISicBlockCipher;
    BulkCtr: IBulkBlockCipherMode;
  end;

  // Per-packet inputs an encrypt body needs.
  TCcmEncryptCtx = record
    Input: TCryptoLibByteArray;
    InOff: Int32;
    InLen: Int32;
    Output: TCryptoLibByteArray;
    OutOff: Int32;
    Iv: TCryptoLibByteArray;
    CtrCipher: ISicBlockCipher;
    BulkCtr: IBulkBlockCipherMode;
  end;

  TCcmBlockCipher = class(TAbstractAeadBlockCipher, ICcmBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    BlockSize: Int32 = 16;

  var
    FCipher: IBlockCipher;
    FKeyParam: ICipherParameters;
    // CTR wrapper cached across packets (created once per keyed cipher); each
    // packet re-inits it IV-only, so the AES schedule is never recomputed.
    FCtrCipher: ISicBlockCipher;
    // Raw-IV re-init view of FCtrCipher; QI'd when the CTR wrapper is created.
    // Lets the per-packet IV-only re-init skip its TParametersWithIV.
    FCtrRaw: IRawInitBlockCipherMode;
    FBulkCtr: IBulkBlockCipherMode;
    // CBC-MAC cached across packets like FCtrCipher; it wraps the shared FCipher,
    // so a rekey flows through the engine. Rebuilt only on tag-size change.
    FCbcMac: IMac;
    FCbcMacSize: Int32;
    FAssociatedText: TMemoryStream;
    // Accumulated body input (plaintext on encrypt, ciphertext+tag on decrypt).
    // CCM needs the total length before processing (B_0 encodes it), so input is
    // buffered here and consumed once in DoFinal. Capacity grows by doubling and
    // is reused across packets (FDataLen is the used prefix); DoFinal hands this
    // buffer straight to ProcessPacket, avoiding the readback copy a stream needs.
    FData: TCryptoLibByteArray;
    FDataLen: Int32;
    // Cached once per Init; non-nil when the registry resolved a fused
    // CCM kernel for the underlying cipher and current direction.
    FCcmKernel: ICcmKernel;
    // Gate for FCcmKernel: bound to FCipher's key schedule, so a same-key
    // same-direction re-Init reuses the cached kernel (replaces the old
    // nil/rekey/direction hand-check + FKernelForEnc field).
    FCcmBinding: TCipherKernelBinding;

    // Reused 16-byte per-packet scratch, allocated once and overwritten each
    // use. Only one body method runs per packet, so the fused/scalar roles share
    // fields; within a single method each simultaneously-live block has its own
    // field (no aliasing). All hold key-/plaintext-derived state, wiped on rekey
    // with FData/FMacBlock.
    FScratchIv: TCryptoLibByteArray;
    FScratchB0: TCryptoLibByteArray;
    FScratchHdrBlock: TCryptoLibByteArray;
    FScratchS0: TCryptoLibByteArray;
    FScratchMacState: TCryptoLibByteArray;
    FScratchCtrBlock: TCryptoLibByteArray;
    FScratchTailBlock: TCryptoLibByteArray;
    FScratchEncMac: TCryptoLibByteArray;
    FScratchBody: TCryptoLibByteArray;
    FScratchRecvMac: TCryptoLibByteArray;
    FScratchCompMac: TCryptoLibByteArray;

    class function GetMacSize(ARequestedMacBits: Int32): Int32; static;
    function GetAssociatedTextLength(): Int32;
    function HasAssociatedText(): Boolean;
    function CalculateMac(const AData: TCryptoLibByteArray; ADataOff, ADataLen: Int32;
      const AMacBlock: TCryptoLibByteArray): Int32;
    // Runs AES CBC-MAC over the CCM header (B_0 || AAD length-prefix ||
    // AAD || zero-pad) and writes the post-header 16-byte state into
    // AMacState. Matches the scalar CalculateMac contract.
    procedure ComputePostHeaderMacState(AInLen: Int32;
      const AMacState: TCryptoLibByteArray);
    // Encrypt bodies (fused kernel / scalar SIC).
    procedure EncryptBodyFused(const ACtx: TCcmEncryptCtx);
    procedure EncryptBodyScalar(const ACtx: TCcmEncryptCtx);
    // Decrypt bodies (fused kernel / scalar SIC); return whether the tag verifies.
    function DecryptBodyFused(const ACtx: TCcmDecryptCtx): Boolean;
    function DecryptBodyScalar(const ACtx: TCcmDecryptCtx): Boolean;

    // Decrypts into scratch, verifies, releases to output only on success.
    function RunDecrypt(AUseFused: Boolean; var ACtx: TCcmDecryptCtx;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Boolean;

  strict protected
    function GetAlgorithmName: String; override;
    function GetModeName: String; override;
    function GetBufferedLength(): Int32; override;
    procedure WipeKeyMaterial(); override;

  public
    constructor Create(const ACipher: IBlockCipher);
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

    procedure Reset(); override;

    function GetUpdateOutputSize(ALen: Int32): Int32; override;

    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; overload; virtual;
    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;
  end;

implementation

{ TCcmBlockCipher }

constructor TCcmBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  FBlockSize := BlockSize;
  FUnderlyingCipher := FCipher;
  System.SetLength(FMacBlock, BlockSize);
  // Allocate the reused per-packet scratch blocks once (see field group).
  System.SetLength(FScratchIv, BlockSize);
  System.SetLength(FScratchB0, BlockSize);
  System.SetLength(FScratchHdrBlock, BlockSize);
  System.SetLength(FScratchS0, BlockSize);
  System.SetLength(FScratchMacState, BlockSize);
  System.SetLength(FScratchCtrBlock, BlockSize);
  System.SetLength(FScratchTailBlock, BlockSize);
  System.SetLength(FScratchEncMac, BlockSize);
  System.SetLength(FScratchBody, BlockSize);
  System.SetLength(FScratchRecvMac, BlockSize);
  System.SetLength(FScratchCompMac, BlockSize);
  FAssociatedText := TMemoryStream.Create;
  FData := nil;
  FDataLen := 0;

  if (ACipher.GetBlockSize() <> BlockSize) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCipherRequired, [BlockSize]);
end;

destructor TCcmBlockCipher.Destroy;
begin
  FAssociatedText.Free;
  inherited Destroy;
end;

function TCcmBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.AlgorithmName + '/CCM';
end;

function TCcmBlockCipher.GetModeName: String;
begin
  Result := 'CCM';
end;

function TCcmBlockCipher.GetBufferedLength: Int32;
begin
  Result := FDataLen;
end;

procedure TCcmBlockCipher.WipeKeyMaterial;
begin
  TArrayUtilities.Fill(FMacBlock, 0, System.Length(FMacBlock), Byte(0));
  TArrayUtilities.Fill(FData, 0, System.Length(FData), Byte(0));
  // Reused per-packet scratch holding key-/plaintext-derived state.
  TArrayUtilities.Fill(FScratchIv, 0, System.Length(FScratchIv), Byte(0));
  TArrayUtilities.Fill(FScratchB0, 0, System.Length(FScratchB0), Byte(0));
  TArrayUtilities.Fill(FScratchHdrBlock, 0, System.Length(FScratchHdrBlock), Byte(0));
  TArrayUtilities.Fill(FScratchS0, 0, System.Length(FScratchS0), Byte(0));
  TArrayUtilities.Fill(FScratchMacState, 0, System.Length(FScratchMacState), Byte(0));
  TArrayUtilities.Fill(FScratchCtrBlock, 0, System.Length(FScratchCtrBlock), Byte(0));
  TArrayUtilities.Fill(FScratchTailBlock, 0, System.Length(FScratchTailBlock), Byte(0));
  TArrayUtilities.Fill(FScratchEncMac, 0, System.Length(FScratchEncMac), Byte(0));
  TArrayUtilities.Fill(FScratchBody, 0, System.Length(FScratchBody), Byte(0));
  TArrayUtilities.Fill(FScratchRecvMac, 0, System.Length(FScratchRecvMac), Byte(0));
  TArrayUtilities.Fill(FScratchCompMac, 0, System.Length(FScratchCompMac), Byte(0));
end;

procedure TCcmBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LRequestedMacSizeBits: Int32;
  LDirection: TCipherKernelDirection;
  LNeedReKey: Boolean;
begin
  FForEncryption := AForEncryption;

  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['CCM']);

  if (not LChoice.IsAead) and (LChoice.CipherKey <> nil) and
    (LChoice.KeyParameter = nil) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['CCM']);

  CheckNonceReuse(FForEncryption, LChoice.Nonce, LChoice.KeyParameter);

  FLastNonce := LChoice.Nonce;
  FInitialAssociatedText := LChoice.AssociatedText;
  if LChoice.IsAead then
    LRequestedMacSizeBits := LChoice.MacSizeBits
  else
    LRequestedMacSizeBits := 64;
  FMacSize := GetMacSize(LRequestedMacSizeBits);

  if (LChoice.CipherKey <> nil) then
  begin
    FKeyParam := LChoice.CipherKey;
    if LChoice.KeyParameter <> nil then
      LNeedReKey := NeedsReKey(LChoice.KeyParameter)
    else
    begin
      // non-IKeyParameter key: cannot be compared, so always rebuild and never
      // mark it reusable; invalidate readiness before the destructive Init.
      FKeyReady := False;
      LNeedReKey := True;
    end;
  end
  else
  begin
    // nil key reuses the established schedule; require a ready one.
    if not FKeyReady then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
    LNeedReKey := False;
  end;

  if (System.Length(FLastNonce) < 7) or (System.Length(FLastNonce) > 13) then
    raise EArgumentCryptoLibException.CreateRes(@SNonceLengthRange);

  // Nonce-only rotation is the hot AEAD path: with the key and direction
  // unchanged the AES schedule, the CTR wrapper and the fused-kernel binding
  // all stay valid, so none of them are recomputed.
  if FKeyParam <> nil then
  begin
    if LNeedReKey then
    begin
      FCipher.Init(True, FKeyParam);
      // Commit (and mark ready) only for a comparable key; a non-IKeyParameter
      // key stays "not ready" so the next init always rebuilds.
      if LChoice.KeyParameter <> nil then
        CommitKey(LChoice.KeyParameter);
    end;
    if AForEncryption then
      LDirection := TCipherKernelDirection.Encrypt
    else
      LDirection := TCipherKernelDirection.Decrypt;
    if FCcmBinding.NeedsRebind(FCipher, LDirection) then
    begin
      FCcmKernel := nil;
      TCipherKernelRegistry.TryAcquireCcm(FCipher, LDirection, FCcmKernel);
    end;
    if FCtrCipher = nil then
    begin
      FCtrCipher := TSicBlockCipher.Create(FCipher);
      Supports(FCtrCipher, IRawInitBlockCipherMode, FCtrRaw);
      TBlockCipherBulkUtilities.TryResolveBulkCipherMode(FCtrCipher, FBulkCtr);
    end;
  end
  else
    FCcmKernel := nil;

  Reset();
end;

procedure TCcmBlockCipher.InitPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32);
var
  LDirection: TCipherKernelDirection;
  LNeedReKey: Boolean;
begin
  FForEncryption := AForEncryption;

  CheckNonceReuseRaw(FForEncryption, ANonce, AKey);

  if (FLastNonce = nil) or (System.Length(FLastNonce) <> System.Length(ANonce)) then
    System.SetLength(FLastNonce, System.Length(ANonce));
  System.Move(ANonce[0], FLastNonce[0], System.Length(ANonce));

  FInitialAssociatedText := AAad;
  FMacSize := GetMacSize(AMacSizeBits);

  if (System.Length(FLastNonce) < 7) or (System.Length(FLastNonce) > 13) then
    raise EArgumentCryptoLibException.CreateRes(@SNonceLengthRange);

  if AKey <> nil then
    LNeedReKey := NeedsReKeyRaw(AKey)
  else
  begin
    // nil key reuses the established key; there must be one.
    if not FKeyReady then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
    LNeedReKey := False;
  end;

  if LNeedReKey then
  begin
    FKeyParam := TKeyParameter.Create(AKey) as ICipherParameters;
    FCipher.Init(True, FKeyParam);
    CommitKeyRaw(AKey);
  end;
  if AForEncryption then
    LDirection := TCipherKernelDirection.Encrypt
  else
    LDirection := TCipherKernelDirection.Decrypt;
  if FCcmBinding.NeedsRebind(FCipher, LDirection) then
  begin
    FCcmKernel := nil;
    TCipherKernelRegistry.TryAcquireCcm(FCipher, LDirection, FCcmKernel);
  end;
  if FCtrCipher = nil then
  begin
    FCtrCipher := TSicBlockCipher.Create(FCipher);
    TBlockCipherBulkUtilities.TryResolveBulkCipherMode(FCtrCipher, FBulkCtr);
  end;

  Reset();
end;

procedure TCcmBlockCipher.ProcessAadByte(AInput: Byte);
begin
  FAssociatedText.WriteByte(AInput);
end;

procedure TCcmBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  FAssociatedText.WriteBuffer(AInput[AInOff], ALen);
end;

function TCcmBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  TArrayUtilities.AppendTo(FData, FDataLen, AInput);
  Result := 0;
end;

function TCcmBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);
  TArrayUtilities.AppendTo(FData, FDataLen, AInput, AInOff, ALen);
  Result := 0;
end;

function TCcmBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  // The accumulator is already a contiguous byte array, so hand its used
  // prefix straight to ProcessPacket (no readback copy / staging alloc).
  Result := ProcessPacket(FData, 0, FDataLen, AOutput, AOutOff);

  Reset();
end;

procedure TCcmBlockCipher.Reset;
begin
  FAssociatedText.Size := 0;
  FDataLen := 0;
end;

function TCcmBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
begin
  Result := 0;
end;

function TCcmBlockCipher.ProcessPacket(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32): TCryptoLibByteArray;
var
  LOutput: TCryptoLibByteArray;
begin
  TCheck.DataLength(AInput, AInOff, AInLen, SInputBufferTooShort);

  if FForEncryption then
  begin
    System.SetLength(LOutput, AInLen + FMacSize);
  end
  else
  begin
    if (AInLen < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    System.SetLength(LOutput, AInLen - FMacSize);
  end;

  ProcessPacket(AInput, AInOff, AInLen, LOutput, 0);
  Result := LOutput;
end;

function TCcmBlockCipher.ProcessPacket(const AInput: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LN, LQ, LLimitLen, LInputAdjustment, LOutputLen: Int32;
  LCtrCipher: ISicBlockCipher;
  // Cached IBulkBlockCipherMode view of LCtrCipher. TSicBlockCipher always
  // implements IBulkBlockCipherMode, so this is non-nil in practice; the
  // Supports() guard keeps us robust to a future SIC variant that opts out.
  LBulkCtr: IBulkBlockCipherMode;
  LEncCtx: TCcmEncryptCtx;
  LDecCtx: TCcmDecryptCtx;
  LUseFused: Boolean;
begin
  TCheck.DataLength(AInput, AInOff, AInLen, SInputBufferTooShort);

  if (FKeyParam = nil) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SCcmUninitialised);

  LN := System.Length(FLastNonce);
  LQ := 15 - LN;
  if (LQ < 4) then
  begin
    LLimitLen := 1 shl (8 * LQ);

    LInputAdjustment := 0;

    if (not FForEncryption) then
    begin
      LInputAdjustment := 1 + 15;
    end;

    if ((AInLen - LInputAdjustment) >= LLimitLen) then
      raise EInvalidOperationCryptoLibException.CreateRes(@SCcmPacketTooLarge);
  end;

  FScratchIv[0] := Byte((LQ - 1) and $7);
  System.Move(FLastNonce[0], FScratchIv[1], LN);
  // Zero the counter tail (LQ bytes past the nonce): the block is reused, so
  // stale bytes from a prior packet must not leak into this IV / counter base.
  TArrayUtilities.Fill(FScratchIv, 1 + LN, BlockSize, Byte(0));

  // IV-only re-init of the cached CTR wrapper: the inner parameters are nil,
  // so the (unchanged) AES schedule is not recomputed per packet.
  LCtrCipher := FCtrCipher;
  if FCtrRaw <> nil then
    FCtrRaw.InitRaw(FForEncryption, nil, FScratchIv)
  else
    LCtrCipher.Init(FForEncryption, TParametersWithIV.Create(nil, FScratchIv) as IParametersWithIV);
  LBulkCtr := FBulkCtr;

  if FForEncryption then
  begin
    LOutputLen := AInLen + FMacSize;
    TCheck.OutputLength(AOutput, AOutOff, LOutputLen, SOutputBufferTooShort);

    LEncCtx.Input := AInput;
    LEncCtx.InOff := AInOff;
    LEncCtx.InLen := AInLen;
    LEncCtx.Output := AOutput;
    LEncCtx.OutOff := AOutOff;
    LEncCtx.Iv := FScratchIv;
    LEncCtx.CtrCipher := LCtrCipher;
    LEncCtx.BulkCtr := LBulkCtr;

    // Fused kernel when it can cover at least one stride; scalar otherwise.
    if (FCcmKernel <> nil) and
      ((AInLen - 1) div BlockSize >= FCcmKernel.MinimumBlockCount) then
      EncryptBodyFused(LEncCtx)
    else
      EncryptBodyScalar(LEncCtx);
  end
  else
  begin
    if (AInLen < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    LOutputLen := AInLen - FMacSize;
    TCheck.OutputLength(AOutput, AOutOff, LOutputLen, SOutputBufferTooShort);

    LDecCtx.Input := AInput;
    LDecCtx.InOff := AInOff;
    LDecCtx.OutputLen := LOutputLen;
    LDecCtx.Iv := FScratchIv;
    LDecCtx.CtrCipher := LCtrCipher;
    LDecCtx.BulkCtr := LBulkCtr;

    // Fused kernel when it can cover at least one stride; scalar otherwise.
    LUseFused := (FCcmKernel <> nil) and
      ((LOutputLen - 1) div BlockSize >= FCcmKernel.MinimumBlockCount);

    RunDecrypt(LUseFused, LDecCtx, AOutput, AOutOff);
  end;

  Result := LOutputLen;
end;

function TCcmBlockCipher.CalculateMac(const AData: TCryptoLibByteArray;
  ADataOff, ADataLen: Int32; const AMacBlock: TCryptoLibByteArray): Int32;
var
  LCMac: IMac;
  LQ, LCount, LExtra, LTextLength, LLen: Int32;
  LInput: TCryptoLibByteArray;
begin
  if (FCbcMac = nil) or (FCbcMacSize <> FMacSize) then
  begin
    FCbcMac := TCbcBlockCipherMac.Create(FCipher, FMacSize * 8) as IMac;
    FCbcMac.Init(FKeyParam);
    FCbcMacSize := FMacSize;
  end
  else
    FCbcMac.Reset();
  LCMac := FCbcMac;

  // B_0 is assembled by OR / partial writes, so the reused block must start
  // fully zeroed each call.
  TArrayUtilities.Fill(FScratchB0, 0, BlockSize, Byte(0));

  if HasAssociatedText() then
  begin
    FScratchB0[0] := FScratchB0[0] or $40;
  end;

  FScratchB0[0] := FScratchB0[0] or Byte((((LCMac.GetMacSize() - 2) div 2) and $7) shl 3);

  FScratchB0[0] := FScratchB0[0] or Byte(((15 - System.Length(FLastNonce)) - 1) and $7);

  System.Move(FLastNonce[0], FScratchB0[1], System.Length(FLastNonce));

  LQ := ADataLen;
  LCount := 1;
  while (LQ > 0) do
  begin
    FScratchB0[System.Length(FScratchB0) - LCount] := Byte(LQ and $FF);
    LQ := LQ shr 8;
    System.Inc(LCount);
  end;

  LCMac.BlockUpdate(FScratchB0, 0, System.Length(FScratchB0));

  if HasAssociatedText() then
  begin
    LTextLength := GetAssociatedTextLength();
    if (LTextLength < ((1 shl 16) - (1 shl 8))) then
    begin
      LCMac.Update(Byte(LTextLength shr 8));
      LCMac.Update(Byte(LTextLength));
      LExtra := 2;
    end
    else
    begin
      LCMac.Update(Byte($FF));
      LCMac.Update(Byte($FE));
      LCMac.Update(Byte(LTextLength shr 24));
      LCMac.Update(Byte(LTextLength shr 16));
      LCMac.Update(Byte(LTextLength shr 8));
      LCMac.Update(Byte(LTextLength));
      LExtra := 6;
    end;

    if (FInitialAssociatedText <> nil) then
    begin
      LCMac.BlockUpdate(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
    end;

    if (FAssociatedText.Size > 0) then
    begin
      LLen := Int32(FAssociatedText.Size);
      System.SetLength(LInput, LLen);
      FAssociatedText.Position := 0;
      FAssociatedText.ReadBuffer(LInput[0], LLen);
      LCMac.BlockUpdate(LInput, 0, LLen);
    end;

    LExtra := (LExtra + LTextLength) mod 16;
    if (LExtra <> 0) then
    begin
      while LExtra < 16 do
      begin
        LCMac.Update(Byte($00));
        System.Inc(LExtra);
      end;
    end;
  end;

  LCMac.BlockUpdate(AData, ADataOff, ADataLen);

  Result := LCMac.DoFinal(AMacBlock, 0);
end;

class function TCcmBlockCipher.GetMacSize(ARequestedMacBits: Int32): Int32;
begin
  if (ARequestedMacBits < 32) or (ARequestedMacBits > 128) or
    (0 <> (ARequestedMacBits and 15)) then
    raise EArgumentCryptoLibException.CreateRes(@STagLengthOctets);

  Result := ARequestedMacBits shr 3;
end;

function TCcmBlockCipher.GetAssociatedTextLength: Int32;
begin
  Result := Int32(FAssociatedText.Size);
  if (FInitialAssociatedText <> nil) then
    Result := Result + System.Length(FInitialAssociatedText);
end;

function TCcmBlockCipher.HasAssociatedText: Boolean;
begin
  Result := GetAssociatedTextLength() > 0;
end;


procedure TCcmBlockCipher.ComputePostHeaderMacState(AInLen: Int32;
  const AMacState: TCryptoLibByteArray);
var
  LHeader: TCryptoLibByteArray;
  LOffset, LI, LTextLength, LExtra, LNonceLen, LQ, LTmp, LHeaderLen,
    LInitLen, LRuntimeLen: Int32;
begin
  LNonceLen := System.Length(FLastNonce);
  LQ := 15 - LNonceLen;

  if HasAssociatedText() then
  begin
    LTextLength := GetAssociatedTextLength();
    if LTextLength < ((1 shl 16) - (1 shl 8)) then
      LExtra := 2
    else
      LExtra := 6;
    LHeaderLen := 16 + LExtra + LTextLength;
    LHeaderLen := ((LHeaderLen + 15) div 16) * 16;
  end
  else
  begin
    LExtra := 0;
    LTextLength := 0;
    LHeaderLen := 16;
  end;

  System.SetLength(LHeader, LHeaderLen);

  // B_0: flags byte [reserved:1][adata:1][(t-2)/2:3][q-1:3] per RFC 3610 2.2.
  if HasAssociatedText() then
    LHeader[0] := LHeader[0] or $40;
  LHeader[0] := LHeader[0] or Byte((((FMacSize - 2) div 2) and $7) shl 3);
  LHeader[0] := LHeader[0] or Byte((LQ - 1) and $7);
  System.Move(FLastNonce[0], LHeader[1], LNonceLen);
  LTmp := AInLen;
  LI := 1;
  while LTmp > 0 do
  begin
    LHeader[16 - LI] := Byte(LTmp and $FF);
    LTmp := LTmp shr 8;
    System.Inc(LI);
  end;

  if HasAssociatedText() then
  begin
    if LExtra = 2 then
    begin
      LHeader[16] := Byte(LTextLength shr 8);
      LHeader[17] := Byte(LTextLength);
    end
    else
    begin
      LHeader[16] := $FF;
      LHeader[17] := $FE;
      LHeader[18] := Byte(LTextLength shr 24);
      LHeader[19] := Byte(LTextLength shr 16);
      LHeader[20] := Byte(LTextLength shr 8);
      LHeader[21] := Byte(LTextLength);
    end;
    LOffset := 16 + LExtra;
    LInitLen := 0;
    if FInitialAssociatedText <> nil then
    begin
      LInitLen := System.Length(FInitialAssociatedText);
      System.Move(FInitialAssociatedText[0], LHeader[LOffset], LInitLen);
    end;
    LRuntimeLen := Int32(FAssociatedText.Size);
    if LRuntimeLen > 0 then
    begin
      FAssociatedText.Position := 0;
      FAssociatedText.ReadBuffer(LHeader[LOffset + LInitLen], LRuntimeLen);
    end;
  end;

  TArrayUtilities.Fill(AMacState, 0, BlockSize, Byte(0));
  LOffset := 0;
  while LOffset < LHeaderLen do
  begin
    TByteUtilities.&Xor(BlockSize, PByte(@AMacState[0]), PByte(@LHeader[LOffset]),
      PByte(@FScratchHdrBlock[0]));
    FCipher.ProcessBlock(FScratchHdrBlock, 0, AMacState, 0);
    System.Inc(LOffset, BlockSize);
  end;
end;

procedure TCcmBlockCipher.EncryptBodyFused(const ACtx: TCcmEncryptCtx);
var
  LBulkBlocks, LTailLen, LTailStart: Int32;
begin
  LBulkBlocks := (ACtx.InLen - 1) div BlockSize;

  // S_0 = E_K(J_0); XOR with the final MAC to emit the tag.
  FCipher.ProcessBlock(ACtx.Iv, 0, FScratchS0, 0);

  ComputePostHeaderMacState(ACtx.InLen, FScratchMacState);

  // Body counter block (counter = 1).
  System.Move(ACtx.Iv[0], FScratchCtrBlock[0], BlockSize);
  FScratchCtrBlock[BlockSize - 1] := FScratchCtrBlock[BlockSize - 1] or 1;

  // Fused CTR + CBC-MAC over the body.
  FCcmKernel.ProcessBody(@ACtx.Input[ACtx.InOff], @ACtx.Output[ACtx.OutOff],
    @FScratchCtrBlock[0], @FScratchMacState[0], LBulkBlocks);

  // Scalar tail: kernel held back the last 1..16 bytes. FScratchCtrBlock now
  // carries counter_{1 + LBulkBlocks}.
  LTailLen := ACtx.InLen - LBulkBlocks * BlockSize;
  LTailStart := ACtx.InOff + LBulkBlocks * BlockSize;

  // Reused tail block: zero it first, then take the (<= BlockSize) tail so the
  // CBC-MAC fold sees a zero-padded final block, not stale bytes.
  TArrayUtilities.Fill(FScratchTailBlock, 0, BlockSize, Byte(0));
  System.Move(ACtx.Input[LTailStart], FScratchTailBlock[0], LTailLen);
  TByteUtilities.XorTo(BlockSize, PByte(@FScratchTailBlock[0]), PByte(@FScratchMacState[0]));
  FCipher.ProcessBlock(FScratchMacState, 0, FScratchMacState, 0);

  FCipher.ProcessBlock(FScratchCtrBlock, 0, FScratchTailBlock, 0);
  TByteUtilities.&Xor(LTailLen, PByte(@ACtx.Input[LTailStart]), PByte(@FScratchTailBlock[0]),
    PByte(@ACtx.Output[ACtx.OutOff + LBulkBlocks * BlockSize]));

  // FMacBlock holds the raw pre-encryption MAC (GetMac contract).
  System.Move(FScratchMacState[0], FMacBlock[0], BlockSize);
  TByteUtilities.&Xor(FMacSize, PByte(@FScratchMacState[0]), PByte(@FScratchS0[0]),
    PByte(@ACtx.Output[ACtx.OutOff + ACtx.InLen]));
end;

procedure TCcmBlockCipher.EncryptBodyScalar(const ACtx: TCcmEncryptCtx);
var
  LInIndex, LOutIndex, LBulkBlocks, LBulkBytes: Int32;
begin
  CalculateMac(ACtx.Input, ACtx.InOff, ACtx.InLen, FMacBlock);

  // Encrypt the tag with S_0 (CtrCipher's first block); this advances CtrCipher
  // to counter 1, which the body CTR below continues from.
  ACtx.CtrCipher.ProcessBlock(FMacBlock, 0, FScratchEncMac, 0);

  LInIndex := ACtx.InOff;
  LOutIndex := ACtx.OutOff;

  // The last (possibly full) 16-byte block is held back for the final-block
  // scratch path so behaviour matches the pre-bulk loop byte-for-byte.
  LBulkBlocks := (ACtx.InLen - 1) div BlockSize;
  if (ACtx.BulkCtr <> nil) and (LBulkBlocks > 0) then
  begin
    LBulkBytes := ACtx.BulkCtr.ProcessBlocks(ACtx.Input, LInIndex, LBulkBlocks,
      ACtx.Output, LOutIndex);
    LInIndex := LInIndex + LBulkBytes;
    LOutIndex := LOutIndex + LBulkBytes;
  end
  else
  begin
    while (LInIndex < (ACtx.InOff + ACtx.InLen - BlockSize)) do
    begin
      ACtx.CtrCipher.ProcessBlock(ACtx.Input, LInIndex, ACtx.Output, LOutIndex);
      LOutIndex := LOutIndex + BlockSize;
      LInIndex := LInIndex + BlockSize;
    end;
  end;

  // Reused block: zero-pad the high bytes past the final partial tail.
  TArrayUtilities.Fill(FScratchBody, 0, BlockSize, Byte(0));
  System.Move(ACtx.Input[LInIndex], FScratchBody[0], ACtx.InLen + ACtx.InOff - LInIndex);
  ACtx.CtrCipher.ProcessBlock(FScratchBody, 0, FScratchBody, 0);
  System.Move(FScratchBody[0], ACtx.Output[LOutIndex], ACtx.InLen + ACtx.InOff - LInIndex);

  System.Move(FScratchEncMac[0], ACtx.Output[ACtx.OutOff + ACtx.InLen], FMacSize);
end;

function TCcmBlockCipher.DecryptBodyFused(const ACtx: TCcmDecryptCtx): Boolean;
var
  LBulkBlocks, LTailLen, LI, LTailStart: Int32;
begin
  LBulkBlocks := (ACtx.OutputLen - 1) div BlockSize;

  FCipher.ProcessBlock(ACtx.Iv, 0, FScratchS0, 0);

  // Decrypt the received MAC: R = (enc_tag || 0..) XOR S_0 truncated. Zero the
  // reused block first so the high (BlockSize - FMacSize) bytes stay 0 for the
  // full-width FixedTimeEquals below.
  TArrayUtilities.Fill(FScratchRecvMac, 0, BlockSize, Byte(0));
  System.Move(ACtx.Input[ACtx.InOff + ACtx.OutputLen], FScratchRecvMac[0], FMacSize);
  TByteUtilities.XorTo(FMacSize, PByte(@FScratchS0[0]), PByte(@FScratchRecvMac[0]));
  System.Move(FScratchRecvMac[0], FMacBlock[0], BlockSize);

  ComputePostHeaderMacState(ACtx.OutputLen, FScratchMacState);

  // Body counter block (counter = 1).
  System.Move(ACtx.Iv[0], FScratchCtrBlock[0], BlockSize);
  FScratchCtrBlock[BlockSize - 1] := FScratchCtrBlock[BlockSize - 1] or 1;

  // Fused CTR + CBC-MAC over the body, straight into the caller-chosen dest.
  FCcmKernel.ProcessBody(@ACtx.Input[ACtx.InOff], @ACtx.Dest[ACtx.DestOff],
    @FScratchCtrBlock[0], @FScratchMacState[0], LBulkBlocks);

  // Scalar tail: decrypt via keystream XOR, then fold into the MAC.
  LTailLen := ACtx.OutputLen - LBulkBlocks * BlockSize;
  LTailStart := ACtx.InOff + LBulkBlocks * BlockSize;

  FCipher.ProcessBlock(FScratchCtrBlock, 0, FScratchTailBlock, 0);
  TByteUtilities.&Xor(LTailLen, PByte(@ACtx.Input[LTailStart]), PByte(@FScratchTailBlock[0]),
    PByte(@ACtx.Dest[ACtx.DestOff + LBulkBlocks * BlockSize]));

  // Zero-pad plaintext tail and fold one last CBC step.
  TArrayUtilities.Fill(FScratchTailBlock, 0, BlockSize, Byte(0));
  for LI := 0 to LTailLen - 1 do
    FScratchTailBlock[LI] := ACtx.Dest[ACtx.DestOff + LBulkBlocks * BlockSize + LI];
  TByteUtilities.XorTo(BlockSize, PByte(@FScratchTailBlock[0]), PByte(@FScratchMacState[0]));
  FCipher.ProcessBlock(FScratchMacState, 0, FScratchMacState, 0);

  TArrayUtilities.Fill(FScratchCompMac, 0, BlockSize, Byte(0));
  System.Move(FScratchMacState[0], FScratchCompMac[0], FMacSize);

  Result := TArrayUtilities.FixedTimeEquals(FScratchRecvMac, FScratchCompMac);
end;

function TCcmBlockCipher.DecryptBodyScalar(const ACtx: TCcmDecryptCtx): Boolean;
var
  LInIndex, LOutIndex, LI, LBulkBlocks, LBulkBytes: Int32;
begin
  // Expected MAC: received tag XOR S_0 keystream (CtrCipher's first block),
  // then zero-pad. Consuming S_0 here advances CtrCipher to counter 1, which
  // the body CTR below continues from.
  System.Move(ACtx.Input[ACtx.InOff + ACtx.OutputLen], FMacBlock[0], FMacSize);
  ACtx.CtrCipher.ProcessBlock(FMacBlock, 0, FMacBlock, 0);
  for LI := FMacSize to System.Pred(System.Length(FMacBlock)) do
    FMacBlock[LI] := 0;

  LInIndex := ACtx.InOff;
  LOutIndex := ACtx.DestOff;

  // LBulkBlocks / tail split: the last (possibly full) 16-byte block is held
  // back for the final-block scratch path so behaviour matches the pre-bulk loop.
  LBulkBlocks := (ACtx.OutputLen - 1) div BlockSize;
  if (ACtx.BulkCtr <> nil) and (LBulkBlocks > 0) then
  begin
    LBulkBytes := ACtx.BulkCtr.ProcessBlocks(ACtx.Input, LInIndex, LBulkBlocks,
      ACtx.Dest, LOutIndex);
    LInIndex := LInIndex + LBulkBytes;
    LOutIndex := LOutIndex + LBulkBytes;
  end
  else
  begin
    while (LInIndex < (ACtx.InOff + ACtx.OutputLen - BlockSize)) do
    begin
      ACtx.CtrCipher.ProcessBlock(ACtx.Input, LInIndex, ACtx.Dest, LOutIndex);
      LOutIndex := LOutIndex + BlockSize;
      LInIndex := LInIndex + BlockSize;
    end;
  end;

  // Reused block: zero-pad the high bytes past the final partial tail.
  TArrayUtilities.Fill(FScratchBody, 0, BlockSize, Byte(0));
  System.Move(ACtx.Input[LInIndex], FScratchBody[0],
    ACtx.OutputLen - (LInIndex - ACtx.InOff));
  ACtx.CtrCipher.ProcessBlock(FScratchBody, 0, FScratchBody, 0);
  System.Move(FScratchBody[0], ACtx.Dest[LOutIndex],
    ACtx.OutputLen - (LInIndex - ACtx.InOff));

  // Zero first so the high bytes match FMacBlock's zero-pad in the full-width
  // FixedTimeEquals (CalculateMac writes only FMacSize bytes).
  TArrayUtilities.Fill(FScratchCompMac, 0, BlockSize, Byte(0));
  CalculateMac(ACtx.Dest, ACtx.DestOff, ACtx.OutputLen, FScratchCompMac);

  Result := TArrayUtilities.FixedTimeEquals(FMacBlock, FScratchCompMac);
end;

function TCcmBlockCipher.RunDecrypt(AUseFused: Boolean;
  var ACtx: TCcmDecryptCtx; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Boolean;
var
  LOk: Boolean;
begin
  // Decrypt straight into the caller's buffer (no scratch bounce); on a MAC
  // failure the tentative plaintext is wiped before the exception leaves, so
  // no unverified plaintext survives the call.
  ACtx.Dest := AOutput;
  ACtx.DestOff := AOutOff;
  if AUseFused then
    LOk := DecryptBodyFused(ACtx)
  else
    LOk := DecryptBodyScalar(ACtx);
  if not LOk then
  begin
    TArrayUtilities.Fill(AOutput, AOutOff, AOutOff + ACtx.OutputLen, Byte(0));
    RaiseMacCheckFailed();
  end;
  Result := True;
end;

end.
