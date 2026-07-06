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
  ClpFusedKernelTypes,
  ClpIFusedCcmKernel,
  ClpFusedKernelRegistry,
  ClpFusedKernelDefaults, // registers in-tree fused AEAD kernel factories
  ClpCipherModeParameterUtilities,
  ClpIKeyParameter,
  ClpCbcBlockCipherMac,
  ClpIMac,
  ClpParametersWithIV,
  ClpCheck,
  ClpArrayUtilities,
  ClpByteUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCipherRequired = 'cipher required with a block size of %d';
  SInvalidParameters = 'invalid parameters passed to %s';
  SNonceLengthRange = 'nonce must have length from 7 to 13 octets';
  SCcmUninitialised = 'CCM cipher uninitialized';
  SCcmPacketTooLarge = 'CCM packet too large for choice of q';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in %s failed';
  STagLengthOctets = 'tag length in octets must be one of {4,6,8,10,12,14,16}';
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';
  SCannotReuseNonce = 'cannot reuse nonce for %s encryption';

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

  TCcmBlockCipher = class(TInterfacedObject, ICcmBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    BlockSize: Int32 = 16;

  var
    FCipher: IBlockCipher;
    FMacBlock: TCryptoLibByteArray;
    FForEncryption: Boolean;
    FNonce: TCryptoLibByteArray;
    FInitialAssociatedText: TCryptoLibByteArray;
    FMacSize: Int32;
    FKeyParam: ICipherParameters;
    FLastKey: TCryptoLibByteArray;
    FAssociatedText: TMemoryStream;
    // Accumulated body input (plaintext on encrypt, ciphertext+tag on decrypt).
    // CCM needs the total length before processing (B_0 encodes it), so input is
    // buffered here and consumed once in DoFinal. Capacity grows by doubling and
    // is reused across packets (FDataLen is the used prefix); DoFinal hands this
    // buffer straight to ProcessPacket, avoiding the readback copy a stream needs.
    FData: TCryptoLibByteArray;
    FDataLen: Int32;
    // Reused decrypt staging buffer. CCM must not release unverified plaintext,
    // so decrypt lands here first; the tag is verified, and only on success is
    // the plaintext copied to the caller's output (which stays untouched on
    // failure). Grown by doubling and reused across packets, and wiped after
    // every packet (in a finally) so no recovered plaintext lingers.
    FPlainScratch: TCryptoLibByteArray;
    // Cached once per Init; non-nil when the registry resolved a fused
    // CCM kernel for the underlying cipher and current direction.
    FCcmKernel: IFusedCcmKernel;

    // Ensure ABuf holds at least ANeeded bytes of capacity, growing by doubling
    // (amortised O(1) append) and never shrinking.
    class procedure EnsureCapacity(var ABuf: TCryptoLibByteArray;
      ANeeded: Int32); static;
    class function GetMacSize(ARequestedMacBits: Int32): Int32; static;
    procedure CheckNonceReuse(AForEncryption: Boolean;
      const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);
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
    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(const ACipher: IBlockCipher);
    destructor Destroy; override;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); virtual;
    function GetBlockSize(): Int32; virtual;

    procedure ProcessAadByte(AInput: Byte); virtual;
    procedure ProcessAadBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32); virtual;

    function ProcessByte(AInput: Byte; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;
    function ProcessBytes(const AInput: TCryptoLibByteArray; AInOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    function DoFinal(const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; virtual;

    procedure Reset(); virtual;

    function GetMac(): TCryptoLibByteArray; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;
    function GetOutputSize(ALen: Int32): Int32; virtual;

    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32): TCryptoLibByteArray; overload; virtual;
    function ProcessPacket(const AInput: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32; overload; virtual;

    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
    property AlgorithmName: String read GetAlgorithmName;
  end;

implementation

{ TCcmBlockCipher }

constructor TCcmBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FCipher := ACipher;
  System.SetLength(FMacBlock, BlockSize);
  FAssociatedText := TMemoryStream.Create;
  FData := nil;
  FDataLen := 0;
  FPlainScratch := nil;

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

function TCcmBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

procedure TCcmBlockCipher.CheckNonceReuse(AForEncryption: Boolean;
  const ANewNonce: TCryptoLibByteArray; const AKeyParam: IKeyParameter);
begin
  if not AForEncryption then
    Exit;

  if (FNonce = nil) or (not TArrayUtilities.AreEqual(FNonce, ANewNonce)) then
    Exit;

  if AKeyParam = nil then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce, ['CCM']);

  if (FLastKey <> nil) and AKeyParam.FixedTimeEquals(FLastKey) then
    raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce, ['CCM']);
end;

procedure TCcmBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LRequestedMacSizeBits: Int32;
  LDirection: TFusedModeDirection;
begin
  FForEncryption := AForEncryption;

  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['CCM']);

  if (not LChoice.IsAead) and (LChoice.CipherKey <> nil) and
    (LChoice.KeyParameter = nil) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters, ['CCM']);

  CheckNonceReuse(FForEncryption, LChoice.Nonce, LChoice.KeyParameter);

  FNonce := LChoice.Nonce;
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
      FLastKey := LChoice.KeyParameter.GetKey();
  end;

  if (System.Length(FNonce) < 7) or (System.Length(FNonce) > 13) then
    raise EArgumentCryptoLibException.CreateRes(@SNonceLengthRange);

  FCcmKernel := nil;
  if FKeyParam <> nil then
  begin
    // Key FCipher now so the factory can read the finalised AES
    // schedule. ProcessPacket re-keys through the SIC wrapper later; the
    // schedule contents are identical across those re-keys.
    FCipher.Init(True, FKeyParam);
    if AForEncryption then
      LDirection := TFusedModeDirection.Encrypt
    else
      LDirection := TFusedModeDirection.Decrypt;
    TFusedKernelRegistry.TryAcquireCcm(FCipher, LDirection, FCcmKernel);
  end;

  Reset();
end;

function TCcmBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
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
  EnsureCapacity(FData, FDataLen + 1);
  FData[FDataLen] := AInput;
  System.Inc(FDataLen);
  Result := 0;
end;

function TCcmBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);
  if ALen > 0 then
  begin
    EnsureCapacity(FData, FDataLen + ALen);
    System.Move(AInput[AInOff], FData[FDataLen], ALen);
    System.Inc(FDataLen, ALen);
  end;
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

class procedure TCcmBlockCipher.EnsureCapacity(var ABuf: TCryptoLibByteArray;
  ANeeded: Int32);
var
  LCap: Int32;
begin
  LCap := System.Length(ABuf);
  if ANeeded <= LCap then
    Exit;
  if LCap = 0 then
    LCap := 64;
  while (LCap < ANeeded) and (LCap > 0) do
    LCap := LCap * 2;
  if LCap < ANeeded then // Int32 overflow guard for very large packets
    LCap := ANeeded;
  System.SetLength(ABuf, LCap);
end;

procedure TCcmBlockCipher.Reset;
begin
  FAssociatedText.Size := 0;
  FDataLen := 0;
end;

function TCcmBlockCipher.GetMac: TCryptoLibByteArray;
begin
  Result := TArrayUtilities.CopyOfRange<Byte>(FMacBlock, 0, FMacSize);
end;

function TCcmBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
begin
  Result := 0;
end;

function TCcmBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := FDataLen + ALen;

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
  LIV: TCryptoLibByteArray;
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

  LN := System.Length(FNonce);
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

  System.SetLength(LIV, BlockSize);
  LIV[0] := Byte((LQ - 1) and $7);
  System.Move(FNonce[0], LIV[1], LN);

  LCtrCipher := TSicBlockCipher.Create(FCipher);
  LCtrCipher.Init(FForEncryption, TParametersWithIV.Create(FKeyParam, LIV) as IParametersWithIV);
  TBlockCipherBulkUtilities.TryResolveBulkCipherMode(LCtrCipher, LBulkCtr);

  if FForEncryption then
  begin
    LOutputLen := AInLen + FMacSize;
    TCheck.OutputLength(AOutput, AOutOff, LOutputLen, SOutputBufferTooShort);

    LEncCtx.Input := AInput;
    LEncCtx.InOff := AInOff;
    LEncCtx.InLen := AInLen;
    LEncCtx.Output := AOutput;
    LEncCtx.OutOff := AOutOff;
    LEncCtx.Iv := LIV;
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
    LDecCtx.Iv := LIV;
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
  LB0: TCryptoLibByteArray;
  LQ, LCount, LExtra, LTextLength, LLen: Int32;
  LInput: TCryptoLibByteArray;
begin
  LCMac := TCbcBlockCipherMac.Create(FCipher, FMacSize * 8);
  LCMac.Init(FKeyParam);

  System.SetLength(LB0, 16);

  if HasAssociatedText() then
  begin
    LB0[0] := LB0[0] or $40;
  end;

  LB0[0] := LB0[0] or Byte((((LCMac.GetMacSize() - 2) div 2) and $7) shl 3);

  LB0[0] := LB0[0] or Byte(((15 - System.Length(FNonce)) - 1) and $7);

  System.Move(FNonce[0], LB0[1], System.Length(FNonce));

  LQ := ADataLen;
  LCount := 1;
  while (LQ > 0) do
  begin
    LB0[System.Length(LB0) - LCount] := Byte(LQ and $FF);
    LQ := LQ shr 8;
    System.Inc(LCount);
  end;

  LCMac.BlockUpdate(LB0, 0, System.Length(LB0));

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
  LHeader, LBlock: TCryptoLibByteArray;
  LOffset, LI, LTextLength, LExtra, LNonceLen, LQ, LTmp, LHeaderLen,
    LInitLen, LRuntimeLen: Int32;
begin
  LNonceLen := System.Length(FNonce);
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
  System.Move(FNonce[0], LHeader[1], LNonceLen);
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

  System.FillChar(AMacState[0], BlockSize, 0);
  System.SetLength(LBlock, BlockSize);
  LOffset := 0;
  while LOffset < LHeaderLen do
  begin
    TByteUtilities.&Xor(BlockSize, PByte(@AMacState[0]), PByte(@LHeader[LOffset]),
      PByte(@LBlock[0]));
    FCipher.ProcessBlock(LBlock, 0, AMacState, 0);
    System.Inc(LOffset, BlockSize);
  end;
end;

procedure TCcmBlockCipher.EncryptBodyFused(const ACtx: TCcmEncryptCtx);
var
  LBulkBlocks, LTailLen, LTailStart: Int32;
  LS0, LMacState, LCtrBlock, LTailBlock: TCryptoLibByteArray;
begin
  LBulkBlocks := (ACtx.InLen - 1) div BlockSize;

  // S_0 = E_K(J_0); XOR with the final MAC to emit the tag.
  System.SetLength(LS0, BlockSize);
  FCipher.ProcessBlock(ACtx.Iv, 0, LS0, 0);

  System.SetLength(LMacState, BlockSize);
  ComputePostHeaderMacState(ACtx.InLen, LMacState);

  // Body counter block (counter = 1).
  System.SetLength(LCtrBlock, BlockSize);
  System.Move(ACtx.Iv[0], LCtrBlock[0], BlockSize);
  LCtrBlock[BlockSize - 1] := LCtrBlock[BlockSize - 1] or 1;

  // Fused CTR + CBC-MAC over the body.
  FCcmKernel.ProcessBody(@ACtx.Input[ACtx.InOff], @ACtx.Output[ACtx.OutOff],
    @LCtrBlock[0], @LMacState[0], LBulkBlocks);

  // Scalar tail: kernel held back the last 1..16 bytes. LCtrBlock now
  // carries counter_{1 + LBulkBlocks}.
  LTailLen := ACtx.InLen - LBulkBlocks * BlockSize;
  LTailStart := ACtx.InOff + LBulkBlocks * BlockSize;

  System.SetLength(LTailBlock, BlockSize);
  System.Move(ACtx.Input[LTailStart], LTailBlock[0], LTailLen);
  TByteUtilities.XorTo(BlockSize, PByte(@LTailBlock[0]), PByte(@LMacState[0]));
  FCipher.ProcessBlock(LMacState, 0, LMacState, 0);

  FCipher.ProcessBlock(LCtrBlock, 0, LTailBlock, 0);
  TByteUtilities.&Xor(LTailLen, PByte(@ACtx.Input[LTailStart]), PByte(@LTailBlock[0]),
    PByte(@ACtx.Output[ACtx.OutOff + LBulkBlocks * BlockSize]));

  // FMacBlock holds the raw pre-encryption MAC (GetMac contract).
  System.Move(LMacState[0], FMacBlock[0], BlockSize);
  TByteUtilities.&Xor(FMacSize, PByte(@LMacState[0]), PByte(@LS0[0]),
    PByte(@ACtx.Output[ACtx.OutOff + ACtx.InLen]));
end;

procedure TCcmBlockCipher.EncryptBodyScalar(const ACtx: TCcmEncryptCtx);
var
  LInIndex, LOutIndex, LBulkBlocks, LBulkBytes: Int32;
  LEncMac, LBlock: TCryptoLibByteArray;
begin
  CalculateMac(ACtx.Input, ACtx.InOff, ACtx.InLen, FMacBlock);

  // Encrypt the tag with S_0 (CtrCipher's first block); this advances CtrCipher
  // to counter 1, which the body CTR below continues from.
  System.SetLength(LEncMac, BlockSize);
  ACtx.CtrCipher.ProcessBlock(FMacBlock, 0, LEncMac, 0);

  LInIndex := ACtx.InOff;
  LOutIndex := ACtx.OutOff;

  // The last (possibly full) 16-byte block is held back for the LBlock scratch
  // path so behaviour matches the pre-bulk loop byte-for-byte.
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

  System.SetLength(LBlock, BlockSize);
  System.Move(ACtx.Input[LInIndex], LBlock[0], ACtx.InLen + ACtx.InOff - LInIndex);
  ACtx.CtrCipher.ProcessBlock(LBlock, 0, LBlock, 0);
  System.Move(LBlock[0], ACtx.Output[LOutIndex], ACtx.InLen + ACtx.InOff - LInIndex);

  System.Move(LEncMac[0], ACtx.Output[ACtx.OutOff + ACtx.InLen], FMacSize);
end;

function TCcmBlockCipher.DecryptBodyFused(const ACtx: TCcmDecryptCtx): Boolean;
var
  LBulkBlocks, LTailLen, LI, LTailStart: Int32;
  LS0, LMacState, LCtrBlock, LTailBlock, LReceivedRawMac,
    LComputedMac: TCryptoLibByteArray;
begin
  LBulkBlocks := (ACtx.OutputLen - 1) div BlockSize;

  System.SetLength(LS0, BlockSize);
  FCipher.ProcessBlock(ACtx.Iv, 0, LS0, 0);

  // Decrypt the received MAC: R = (enc_tag || 0..) XOR S_0 truncated.
  System.SetLength(LReceivedRawMac, BlockSize);
  System.Move(ACtx.Input[ACtx.InOff + ACtx.OutputLen], LReceivedRawMac[0], FMacSize);
  TByteUtilities.XorTo(FMacSize, PByte(@LS0[0]), PByte(@LReceivedRawMac[0]));
  System.Move(LReceivedRawMac[0], FMacBlock[0], BlockSize);

  System.SetLength(LMacState, BlockSize);
  ComputePostHeaderMacState(ACtx.OutputLen, LMacState);

  // Body counter block (counter = 1).
  System.SetLength(LCtrBlock, BlockSize);
  System.Move(ACtx.Iv[0], LCtrBlock[0], BlockSize);
  LCtrBlock[BlockSize - 1] := LCtrBlock[BlockSize - 1] or 1;

  // Fused CTR + CBC-MAC over the body, straight into the caller-chosen dest.
  FCcmKernel.ProcessBody(@ACtx.Input[ACtx.InOff], @ACtx.Dest[ACtx.DestOff],
    @LCtrBlock[0], @LMacState[0], LBulkBlocks);

  // Scalar tail: decrypt via keystream XOR, then fold into the MAC.
  LTailLen := ACtx.OutputLen - LBulkBlocks * BlockSize;
  LTailStart := ACtx.InOff + LBulkBlocks * BlockSize;

  System.SetLength(LTailBlock, BlockSize);
  FCipher.ProcessBlock(LCtrBlock, 0, LTailBlock, 0);
  TByteUtilities.&Xor(LTailLen, PByte(@ACtx.Input[LTailStart]), PByte(@LTailBlock[0]),
    PByte(@ACtx.Dest[ACtx.DestOff + LBulkBlocks * BlockSize]));

  // Zero-pad plaintext tail and fold one last CBC step.
  System.FillChar(LTailBlock[0], BlockSize, 0);
  for LI := 0 to LTailLen - 1 do
    LTailBlock[LI] := ACtx.Dest[ACtx.DestOff + LBulkBlocks * BlockSize + LI];
  TByteUtilities.XorTo(BlockSize, PByte(@LTailBlock[0]), PByte(@LMacState[0]));
  FCipher.ProcessBlock(LMacState, 0, LMacState, 0);

  System.SetLength(LComputedMac, BlockSize);
  System.Move(LMacState[0], LComputedMac[0], FMacSize);

  Result := TArrayUtilities.FixedTimeEquals(LReceivedRawMac, LComputedMac);
end;

function TCcmBlockCipher.DecryptBodyScalar(const ACtx: TCcmDecryptCtx): Boolean;
var
  LInIndex, LOutIndex, LI, LBulkBlocks, LBulkBytes: Int32;
  LBlock, LCalculatedMacBlock: TCryptoLibByteArray;
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
  // back for the LBlock scratch path so behaviour matches the pre-bulk loop.
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

  System.SetLength(LBlock, BlockSize);
  System.Move(ACtx.Input[LInIndex], LBlock[0],
    ACtx.OutputLen - (LInIndex - ACtx.InOff));
  ACtx.CtrCipher.ProcessBlock(LBlock, 0, LBlock, 0);
  System.Move(LBlock[0], ACtx.Dest[LOutIndex],
    ACtx.OutputLen - (LInIndex - ACtx.InOff));

  System.SetLength(LCalculatedMacBlock, BlockSize);
  CalculateMac(ACtx.Dest, ACtx.DestOff, ACtx.OutputLen, LCalculatedMacBlock);

  Result := TArrayUtilities.FixedTimeEquals(FMacBlock, LCalculatedMacBlock);
end;

function TCcmBlockCipher.RunDecrypt(AUseFused: Boolean;
  var ACtx: TCcmDecryptCtx; const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Boolean;
var
  LOk: Boolean;
begin
  EnsureCapacity(FPlainScratch, ACtx.OutputLen);
  ACtx.Dest := FPlainScratch;
  ACtx.DestOff := 0;
  try
    if AUseFused then
      LOk := DecryptBodyFused(ACtx)
    else
      LOk := DecryptBodyScalar(ACtx);
    if not LOk then
      raise EInvalidCipherTextCryptoLibException.CreateResFmt(@SMacCheckFailed, ['CCM']);
    System.Move(FPlainScratch[0], AOutput[AOutOff], ACtx.OutputLen);
    Result := True;
  finally
    TArrayUtilities.Fill<Byte>(FPlainScratch, 0, ACtx.OutputLen, Byte(0));
  end;
end;

end.
