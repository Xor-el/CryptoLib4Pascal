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
  ClpBasicGcmExponentiator,
  ClpTables4kGcmMultiplier,
  ClpIAesEngineX86,
  ClpAesEngineX86,
  ClpPack,
  ClpCheck,
  ClpBasicGcmMultiplier,
  ClpCpuFeatures,
  ClpIntrinsicsVector,
  ClpArrayUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCipherBlockSizeRequired = 'cipher required with a block size of %d.';
  SInvalidParametersGCM = 'invalid parameters passed to GCM';
  SInvalidMacSize = 'Invalid value for MAC size: %d';
  SIVMustBeAtLeast1Byte = 'IV must be at least 1 byte';
  SCannotReuseNonce = 'cannot reuse nonce for GCM encryption';
  SKeyMustBeSpecified = 'Key must be specified in initial Init';
  STooManyBlocks = 'Attempt to process too many blocks';
  SGcmCannotReuse = 'GCM cipher cannot be reused for encryption';
  SGcmNeedsInit = 'GCM cipher needs to be initialized';
  SOutputBufferTooShort = 'output buffer too short';
  SInputBufferTooShort = 'input buffer too short';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in GCM failed';
  SGcmFourWayNotSupported = 'GCM four-block path is not available on this platform.';
  SGcmFourWayHStateMissing = 'GCM fused four-block multiplier state is not initialized.';
  SGcmDecryptFourWayBadLimit = 'Invalid limit for GCM four-block decrypt.';
  SGcmEightWayNotSupported = 'GCM eight-block path is not available on this platform.';
  SGcmEightWayHStateMissing = 'GCM fused eight-block multiplier state is not initialized.';
  SGcmDecryptEightWayBadLimit = 'Invalid limit for GCM eight-block decrypt.';

type
  TGcmBlockCipher = class(TInterfacedObject, IGcmBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    BlockSize: Int32 = 16;

  public
    class function CreateGcmMultiplier(): IGcmMultiplier; static;
    /// <summary>
    /// True when the fused four-block SIMD path may run: PCLMULQDQ + SSSE3 shuffled GHASH,
    /// batched counter AES, and a packed 16-byte XMM layout.
    /// </summary>
    class function IsFourWaySupported: Boolean; static;
    /// <summary>
    /// True when the fused eight-block SIMD path may run (128-byte CTR batch + wider GHASH).
    /// </summary>
    class function IsEightWaySupported: Boolean; static;
    /// <summary>
    /// True when the 128-bit SSE2 XOR fast path may run for one and two-block steps (with packed layout).
    /// </summary>
    class function IsSse2PackedVectorXorSupported: Boolean; static;

  strict private

  var
    FCipher: IBlockCipher;
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

    procedure GcmReverse16(const ASrc, ADst: PByte);
    procedure GhashFourShuffledBlocks(PC0, PC16, PC32, PC48: PByte);
    procedure GhashEightShuffledBlocks(PBase: PByte);
    procedure EncryptBlocks4Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    procedure DecryptBlocks4Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    procedure EncryptBlocks8Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    procedure DecryptBlocks8Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);

    procedure InitCipher();
    procedure EncryptBlock(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    procedure DecryptBlock(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    procedure EncryptBlocks2(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    procedure EncryptBlocks4(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32);
    procedure EncryptBlocks8(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32);
    procedure DecryptBlocks2(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
    procedure DecryptBlocks4(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32;
      ALimit: Int32);
    procedure DecryptBlocks8(const AInBuf: TCryptoLibByteArray; var AInOff: Int32;
      var ALen: Int32; const AOutBuf: TCryptoLibByteArray; var AOutOff: Int32;
      ALimit: Int32);
    procedure GetNextCtrBlock(const ABlock: TCryptoLibByteArray);
    procedure GetNextCtrBlocks4(const ABlocks: TCryptoLibByteArray);
    procedure GetNextCtrBlocks8(const ABlocks: TCryptoLibByteArray);
    procedure ProcessPartial(const ABuf: TCryptoLibByteArray; AOff, ALen: Int32;
      const AOutput: TCryptoLibByteArray; AOutOff: Int32);
    procedure GHASH(const AY, AB: TCryptoLibByteArray; ALen: Int32);
    procedure GHASHBlock(const AY, AB: TCryptoLibByteArray); overload;
    procedure GHASHBlock(const AY, AB: TCryptoLibByteArray; AOff: Int32); overload;
    procedure GHASHPartial(const AY, AB: TCryptoLibByteArray; AOff, ALen: Int32);
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

{$IFDEF CRYPTOLIB_X86_SIMD}
const
  ReverseBytesMask: packed array[0..15] of Byte = (
    $0F, $0E, $0D, $0C, $0B, $0A, $09, $08, $07, $06, $05, $04, $03, $02, $01, $00);
{$ENDIF}

class function TGcmBlockCipher.IsFourWaySupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasPCLMULQDQ and TCpuFeatures.X86.HasSSSE3 and
    TIntrinsicsVector.IsPacked;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGcmBlockCipher.IsEightWaySupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TGcmBlockCipher.IsFourWaySupported;
{$ELSE}
  Result := False;
{$ENDIF}
end;

class function TGcmBlockCipher.IsSse2PackedVectorXorSupported: Boolean;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  Result := TCpuFeatures.X86.HasSSE2 and TIntrinsicsVector.IsPacked;
{$ELSE}
  Result := False;
{$ENDIF}
end;

{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
procedure GcmBlockXor128Sse2(PDst, PSrc: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
{$I ..\..\Include\Simd\Gcm\GcmBlockXor128Sse2_x86_64.inc}
end;
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
procedure GcmBlockXor128Sse2(PDst, PSrc: PByte);
{$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
{$I ..\..\Include\Simd\Gcm\GcmBlockXor128Sse2_i386.inc}
end;
{$ENDIF}

{$IFDEF CRYPTOLIB_X86_64_ASM}
procedure GcmBlockReverse128Ssse3(PDst, PSrc, PMask: PByte);
{$I ..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\Gcm\GcmBlockReverse128Ssse3_x86_64.inc}
end;
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
procedure GcmBlockReverse128Ssse3(PDst, PSrc, PMask: PByte);
{$I ..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\Gcm\GcmBlockReverse128Ssse3_i386.inc}
end;
{$ENDIF}
{$ENDIF}

{ TGcmBlockCipher }

class function TGcmBlockCipher.CreateGcmMultiplier: IGcmMultiplier;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasPCLMULQDQ then
  begin
    Result := TBasicGcmMultiplier.Create();
    Exit;
  end;
{$ENDIF}
  Result := TTables4kGcmMultiplier.Create();
end;

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

procedure TGcmBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LAeadParameters: IAeadParameters;
  LParametersWithIV: IParametersWithIV;
  LKeyParam: IKeyParameter;
  LNewNonce: TCryptoLibByteArray;
  LMacSizeBits, LBufLength: Int32;
  LX: TCryptoLibByteArray;
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

  if Supports(AParameters, IAeadParameters, LAeadParameters) then
  begin
    LNewNonce := LAeadParameters.GetNonce();
    FInitialAssociatedText := LAeadParameters.GetAssociatedText();

    LMacSizeBits := LAeadParameters.MacSize;
    if (LMacSizeBits < 32) or (LMacSizeBits > 128) or (LMacSizeBits mod 8 <> 0) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize, [LMacSizeBits]);

    FMacSize := LMacSizeBits div 8;
    LKeyParam := LAeadParameters.Key;
  end
  else if Supports(AParameters, IParametersWithIV, LParametersWithIV) then
  begin
    LNewNonce := LParametersWithIV.GetIV();
    FInitialAssociatedText := nil;
    FMacSize := 16;
    if not Supports(LParametersWithIV.Parameters, IKeyParameter, LKeyParam) then
      LKeyParam := nil;
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersGCM);
  end;

  if FForEncryption then
    LBufLength := BlockSize
  else
    LBufLength := BlockSize + FMacSize;

  System.SetLength(FBufBlock, LBufLength);

  if System.Length(LNewNonce) < 1 then
    raise EArgumentCryptoLibException.CreateRes(@SIVMustBeAtLeast1Byte);

  if FForEncryption then
  begin
    if (FNonce <> nil) and TArrayUtilities.AreEqual(FNonce, LNewNonce) then
    begin
      if LKeyParam = nil then
        raise EArgumentCryptoLibException.CreateRes(@SCannotReuseNonce);

      if (FLastKey <> nil) and LKeyParam.FixedTimeEquals(FLastKey) then
        raise EArgumentCryptoLibException.CreateRes(@SCannotReuseNonce);
    end;
  end;

  FNonce := LNewNonce;

  if LKeyParam <> nil then
    FLastKey := LKeyParam.GetKey();

  if LKeyParam <> nil then
  begin
    FCipher.Init(True, LKeyParam as ICipherParameters);

    FH := nil;
    System.SetLength(FH, BlockSize);
    FCipher.ProcessBlock(FH, 0, FH, 0);

    FMultiplier.Init(FH);
    FExp := nil;
    FHPow := nil;
    FWorkCtr := nil;
{$IFDEF CRYPTOLIB_X86_SIMD}
    if TGcmBlockCipher.IsFourWaySupported then
    begin
      System.SetLength(FHPow, 128);
      TGcmUtilities.InitEightWayHPowFromH(FH, FHPow);
      System.SetLength(FWorkCtr, 128);
      TArrayUtilities.Fill<Byte>(FWorkCtr, 0, System.Length(FWorkCtr), Byte(0));
    end;
{$ENDIF}
  end
  else if FH = nil then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end;

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
      EncryptBlock(FBufBlock, 0, AOutput, AOutOff);
      FBufOff := 0;
    end
    else
    begin
      DecryptBlock(FBufBlock, 0, AOutput, AOutOff);
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

      EncryptBlock(FBufBlock, 0, AOutput, AOutOff);
      AOutOff := AOutOff + BlockSize;
    end;

{$IFDEF CRYPTOLIB_X86_SIMD}
    if TGcmBlockCipher.IsEightWaySupported and (ALen >= BlockSize * 8) then
    begin
      EncryptBlocks8(AInput, AInOff, ALen, AOutput, AOutOff);
      if ALen >= BlockSize * 4 then
      begin
        EncryptBlocks4(AInput, AInOff, ALen, AOutput, AOutOff);
        if ALen >= BlockSize * 2 then
        begin
          EncryptBlocks2(AInput, AInOff, AOutput, AOutOff);
          AInOff := AInOff + (BlockSize * 2);
          ALen := ALen - (BlockSize * 2);
          AOutOff := AOutOff + (BlockSize * 2);
        end;
      end
      else if ALen >= BlockSize * 2 then
      begin
        EncryptBlocks2(AInput, AInOff, AOutput, AOutOff);
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
        EncryptBlocks2(AInput, AInOff, AOutput, AOutOff);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end
    else
{$ENDIF}
    begin
      while ALen >= BlockSize * 2 do
      begin
        EncryptBlocks2(AInput, AInOff, AOutput, AOutOff);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end;

    if ALen >= BlockSize then
    begin
      EncryptBlock(AInput, AInOff, AOutput, AOutOff);
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
      DecryptBlock(FBufBlock, 0, AOutput, AOutOff);
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

    DecryptBlock(FBufBlock, 0, AOutput, AOutOff);
    AOutOff := AOutOff + BlockSize;

    LBufLen := System.Length(FBufBlock);
    LThresh2 := LBufLen + BlockSize;
    LThresh4 := LBufLen + (BlockSize * 3);
    LThresh8 := LBufLen + (BlockSize * 7);

{$IFDEF CRYPTOLIB_X86_SIMD}
    if TGcmBlockCipher.IsEightWaySupported and (ALen >= LThresh8) then
    begin
      DecryptBlocks8(AInput, AInOff, ALen, AOutput, AOutOff, LThresh8);
      if ALen >= LThresh4 then
      begin
        DecryptBlocks4(AInput, AInOff, ALen, AOutput, AOutOff, LThresh4);
        if ALen >= LThresh2 then
        begin
          DecryptBlocks2(AInput, AInOff, AOutput, AOutOff);
          AInOff := AInOff + (BlockSize * 2);
          ALen := ALen - (BlockSize * 2);
          AOutOff := AOutOff + (BlockSize * 2);
        end;
      end
      else if ALen >= LThresh2 then
      begin
        DecryptBlocks2(AInput, AInOff, AOutput, AOutOff);
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
        DecryptBlocks2(AInput, AInOff, AOutput, AOutOff);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end
    else
{$ENDIF}
    begin
      while ALen >= LThresh2 do
      begin
        DecryptBlocks2(AInput, AInOff, AOutput, AOutOff);
        AInOff := AInOff + (BlockSize * 2);
        ALen := ALen - (BlockSize * 2);
        AOutOff := AOutOff + (BlockSize * 2);
      end;
    end;

    if ALen >= LBufLen then
    begin
      DecryptBlock(AInput, AInOff, AOutput, AOutOff);
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
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailed);
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

procedure TGcmBlockCipher.DecryptBlock(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LCtrBlock: TCryptoLibByteArray;
  LI: Int32;
  LC0, LC1, LC2, LC3: Byte;
begin
  LCtrBlock := nil;
  System.SetLength(LCtrBlock, BlockSize);
  GetNextCtrBlock(LCtrBlock);
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TGcmBlockCipher.IsSse2PackedVectorXorSupported then
  begin
    System.Move(AInBuf[AInOff], AOutBuf[AOutOff], BlockSize);
    GcmBlockXor128Sse2(@AOutBuf[AOutOff], @LCtrBlock[0]);
    GcmBlockXor128Sse2(@FS[0], @AInBuf[AInOff]);
    FMultiplier.MultiplyH(FS);
    Exit;
  end;
{$ENDIF}

  for LI := 0 to (BlockSize - 1) div 4 do
  begin
    LC0 := AInBuf[AInOff + (LI * 4) + 0];
    LC1 := AInBuf[AInOff + (LI * 4) + 1];
    LC2 := AInBuf[AInOff + (LI * 4) + 2];
    LC3 := AInBuf[AInOff + (LI * 4) + 3];

    FS[(LI * 4) + 0] := FS[(LI * 4) + 0] xor LC0;
    FS[(LI * 4) + 1] := FS[(LI * 4) + 1] xor LC1;
    FS[(LI * 4) + 2] := FS[(LI * 4) + 2] xor LC2;
    FS[(LI * 4) + 3] := FS[(LI * 4) + 3] xor LC3;

    AOutBuf[AOutOff + (LI * 4) + 0] := Byte(LC0 xor LCtrBlock[(LI * 4) + 0]);
    AOutBuf[AOutOff + (LI * 4) + 1] := Byte(LC1 xor LCtrBlock[(LI * 4) + 1]);
    AOutBuf[AOutOff + (LI * 4) + 2] := Byte(LC2 xor LCtrBlock[(LI * 4) + 2]);
    AOutBuf[AOutOff + (LI * 4) + 3] := Byte(LC3 xor LCtrBlock[(LI * 4) + 3]);
  end;
  FMultiplier.MultiplyH(FS);
end;

procedure TGcmBlockCipher.DecryptBlocks2(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LCtrBlock: TCryptoLibByteArray;
  LI: Int32;
  LC0, LC1, LC2, LC3: Byte;
begin
  LCtrBlock := nil;
  System.SetLength(LCtrBlock, BlockSize);

{$IFDEF CRYPTOLIB_X86_SIMD}
  if TGcmBlockCipher.IsSse2PackedVectorXorSupported then
  begin
    GetNextCtrBlock(LCtrBlock);
    System.Move(AInBuf[AInOff], AOutBuf[AOutOff], BlockSize);
    GcmBlockXor128Sse2(@AOutBuf[AOutOff], @LCtrBlock[0]);
    GcmBlockXor128Sse2(@FS[0], @AInBuf[AInOff]);
    FMultiplier.MultiplyH(FS);
    AInOff := AInOff + BlockSize;
    AOutOff := AOutOff + BlockSize;
    GetNextCtrBlock(LCtrBlock);
    System.Move(AInBuf[AInOff], AOutBuf[AOutOff], BlockSize);
    GcmBlockXor128Sse2(@AOutBuf[AOutOff], @LCtrBlock[0]);
    GcmBlockXor128Sse2(@FS[0], @AInBuf[AInOff]);
    FMultiplier.MultiplyH(FS);
    Exit;
  end;
{$ENDIF}

  GetNextCtrBlock(LCtrBlock);
  for LI := 0 to (BlockSize - 1) div 4 do
  begin
    LC0 := AInBuf[AInOff + (LI * 4) + 0];
    LC1 := AInBuf[AInOff + (LI * 4) + 1];
    LC2 := AInBuf[AInOff + (LI * 4) + 2];
    LC3 := AInBuf[AInOff + (LI * 4) + 3];

    FS[(LI * 4) + 0] := FS[(LI * 4) + 0] xor LC0;
    FS[(LI * 4) + 1] := FS[(LI * 4) + 1] xor LC1;
    FS[(LI * 4) + 2] := FS[(LI * 4) + 2] xor LC2;
    FS[(LI * 4) + 3] := FS[(LI * 4) + 3] xor LC3;

    AOutBuf[AOutOff + (LI * 4) + 0] := Byte(LC0 xor LCtrBlock[(LI * 4) + 0]);
    AOutBuf[AOutOff + (LI * 4) + 1] := Byte(LC1 xor LCtrBlock[(LI * 4) + 1]);
    AOutBuf[AOutOff + (LI * 4) + 2] := Byte(LC2 xor LCtrBlock[(LI * 4) + 2]);
    AOutBuf[AOutOff + (LI * 4) + 3] := Byte(LC3 xor LCtrBlock[(LI * 4) + 3]);
  end;
  FMultiplier.MultiplyH(FS);

  AInOff := AInOff + BlockSize;
  AOutOff := AOutOff + BlockSize;

  GetNextCtrBlock(LCtrBlock);
  for LI := 0 to (BlockSize - 1) div 4 do
  begin
    LC0 := AInBuf[AInOff + (LI * 4) + 0];
    LC1 := AInBuf[AInOff + (LI * 4) + 1];
    LC2 := AInBuf[AInOff + (LI * 4) + 2];
    LC3 := AInBuf[AInOff + (LI * 4) + 3];

    FS[(LI * 4) + 0] := FS[(LI * 4) + 0] xor LC0;
    FS[(LI * 4) + 1] := FS[(LI * 4) + 1] xor LC1;
    FS[(LI * 4) + 2] := FS[(LI * 4) + 2] xor LC2;
    FS[(LI * 4) + 3] := FS[(LI * 4) + 3] xor LC3;

    AOutBuf[AOutOff + (LI * 4) + 0] := Byte(LC0 xor LCtrBlock[(LI * 4) + 0]);
    AOutBuf[AOutOff + (LI * 4) + 1] := Byte(LC1 xor LCtrBlock[(LI * 4) + 1]);
    AOutBuf[AOutOff + (LI * 4) + 2] := Byte(LC2 xor LCtrBlock[(LI * 4) + 2]);
    AOutBuf[AOutOff + (LI * 4) + 3] := Byte(LC3 xor LCtrBlock[(LI * 4) + 3]);
  end;
  FMultiplier.MultiplyH(FS);
end;

procedure TGcmBlockCipher.GcmReverse16(const ASrc, ADst: PByte);
var
  LI: Int32;
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TCpuFeatures.X86.HasSSSE3 then
  begin
    GcmBlockReverse128Ssse3(ADst, ASrc, @ReverseBytesMask[0]);
    Exit;
  end;
{$ENDIF}
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
  GcmReverse16(@FS[0], @LSRev[0]);
  System.FillChar(LU0[0], 16, 0);
  System.FillChar(LU1[0], 16, 0);
  System.FillChar(LU2[0], 16, 0);
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

procedure TGcmBlockCipher.EncryptBlocks4Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LI, LBase: Int32;
begin
  GetNextCtrBlocks4(FWorkCtr);
  for LBase := 0 to 3 do
  begin
    LI := LBase * 16;
    PUInt64(@AOutBuf[AOutOff + LI])^ := PUInt64(@AInBuf[AInOff + LI])^ xor
      PUInt64(@FWorkCtr[LI])^;
    PUInt64(@AOutBuf[AOutOff + LI + 8])^ := PUInt64(@AInBuf[AInOff + LI + 8])^ xor
      PUInt64(@FWorkCtr[LI + 8])^;
  end;
  GhashFourShuffledBlocks(@AOutBuf[AOutOff], @AOutBuf[AOutOff + 16], @AOutBuf[AOutOff + 32],
    @AOutBuf[AOutOff + 48]);
end;

procedure TGcmBlockCipher.DecryptBlocks4Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LI, LBase: Int32;
begin
  GetNextCtrBlocks4(FWorkCtr);
  for LBase := 0 to 3 do
  begin
    LI := LBase * 16;
    PUInt64(@AOutBuf[AOutOff + LI])^ := PUInt64(@AInBuf[AInOff + LI])^ xor
      PUInt64(@FWorkCtr[LI])^;
    PUInt64(@AOutBuf[AOutOff + LI + 8])^ := PUInt64(@AInBuf[AInOff + LI + 8])^ xor
      PUInt64(@FWorkCtr[LI + 8])^;
  end;
  GhashFourShuffledBlocks(@AInBuf[AInOff], @AInBuf[AInOff + 16], @AInBuf[AInOff + 32],
    @AInBuf[AInOff + 48]);
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
  GcmReverse16(@FS[0], @LSRev[0]);
  System.FillChar(LU0[0], 16, 0);
  System.FillChar(LU1[0], 16, 0);
  System.FillChar(LU2[0], 16, 0);
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

procedure TGcmBlockCipher.EncryptBlocks8Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LI, LBase: Int32;
begin
  GetNextCtrBlocks8(FWorkCtr);
  for LBase := 0 to 7 do
  begin
    LI := LBase * 16;
    PUInt64(@AOutBuf[AOutOff + LI])^ := PUInt64(@AInBuf[AInOff + LI])^ xor
      PUInt64(@FWorkCtr[LI])^;
    PUInt64(@AOutBuf[AOutOff + LI + 8])^ := PUInt64(@AInBuf[AInOff + LI + 8])^ xor
      PUInt64(@FWorkCtr[LI + 8])^;
  end;
  GhashEightShuffledBlocks(@AOutBuf[AOutOff]);
end;

procedure TGcmBlockCipher.DecryptBlocks8Fused(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LI, LBase: Int32;
begin
  GetNextCtrBlocks8(FWorkCtr);
  for LBase := 0 to 7 do
  begin
    LI := LBase * 16;
    PUInt64(@AOutBuf[AOutOff + LI])^ := PUInt64(@AInBuf[AInOff + LI])^ xor
      PUInt64(@FWorkCtr[LI])^;
    PUInt64(@AOutBuf[AOutOff + LI + 8])^ := PUInt64(@AInBuf[AInOff + LI + 8])^ xor
      PUInt64(@FWorkCtr[LI + 8])^;
  end;
  GhashEightShuffledBlocks(@AInBuf[AInOff]);
end;

procedure TGcmBlockCipher.EncryptBlocks4(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TGcmBlockCipher.IsFourWaySupported then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmFourWayNotSupported);
  if FHPow = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmFourWayHStateMissing);
  while ALen >= BlockSize * 4 do
  begin
    EncryptBlocks4Fused(AInBuf, AInOff, AOutBuf, AOutOff);
    AInOff := AInOff + (BlockSize * 4);
    ALen := ALen - (BlockSize * 4);
    AOutOff := AOutOff + (BlockSize * 4);
  end;
{$ELSE}
  raise EInvalidOperationCryptoLibException.CreateRes(@SGcmFourWayNotSupported);
{$ENDIF}
end;

procedure TGcmBlockCipher.EncryptBlocks8(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TGcmBlockCipher.IsEightWaySupported then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmEightWayNotSupported);
  if (FHPow = nil) or (System.Length(FHPow) < 128) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmEightWayHStateMissing);
  while ALen >= BlockSize * 8 do
  begin
    EncryptBlocks8Fused(AInBuf, AInOff, AOutBuf, AOutOff);
    AInOff := AInOff + (BlockSize * 8);
    ALen := ALen - (BlockSize * 8);
    AOutOff := AOutOff + (BlockSize * 8);
  end;
{$ELSE}
  raise EInvalidOperationCryptoLibException.CreateRes(@SGcmEightWayNotSupported);
{$ENDIF}
end;

procedure TGcmBlockCipher.EncryptBlock(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LCtrBlock: TCryptoLibByteArray;
  LI: Int32;
  LC0, LC1, LC2, LC3: Byte;
begin
  LCtrBlock := nil;
  System.SetLength(LCtrBlock, BlockSize);
  GetNextCtrBlock(LCtrBlock);
{$IFDEF CRYPTOLIB_X86_SIMD}
  if TGcmBlockCipher.IsSse2PackedVectorXorSupported then
  begin
    System.Move(LCtrBlock[0], AOutBuf[AOutOff], BlockSize);
    GcmBlockXor128Sse2(@AOutBuf[AOutOff], @AInBuf[AInOff]);
    GcmBlockXor128Sse2(@FS[0], @AOutBuf[AOutOff]);
    FMultiplier.MultiplyH(FS);
    Exit;
  end;
{$ENDIF}

  for LI := 0 to (BlockSize - 1) div 4 do
  begin
    LC0 := Byte(LCtrBlock[(LI * 4) + 0] xor AInBuf[AInOff + (LI * 4) + 0]);
    LC1 := Byte(LCtrBlock[(LI * 4) + 1] xor AInBuf[AInOff + (LI * 4) + 1]);
    LC2 := Byte(LCtrBlock[(LI * 4) + 2] xor AInBuf[AInOff + (LI * 4) + 2]);
    LC3 := Byte(LCtrBlock[(LI * 4) + 3] xor AInBuf[AInOff + (LI * 4) + 3]);

    FS[(LI * 4) + 0] := FS[(LI * 4) + 0] xor LC0;
    FS[(LI * 4) + 1] := FS[(LI * 4) + 1] xor LC1;
    FS[(LI * 4) + 2] := FS[(LI * 4) + 2] xor LC2;
    FS[(LI * 4) + 3] := FS[(LI * 4) + 3] xor LC3;

    AOutBuf[AOutOff + (LI * 4) + 0] := LC0;
    AOutBuf[AOutOff + (LI * 4) + 1] := LC1;
    AOutBuf[AOutOff + (LI * 4) + 2] := LC2;
    AOutBuf[AOutOff + (LI * 4) + 3] := LC3;
  end;
  FMultiplier.MultiplyH(FS);
end;

procedure TGcmBlockCipher.DecryptBlocks4(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TGcmBlockCipher.IsFourWaySupported then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmFourWayNotSupported);
  if ALimit < BlockSize * 4 then
    raise EArgumentCryptoLibException.CreateRes(@SGcmDecryptFourWayBadLimit);
  if FHPow = nil then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmFourWayHStateMissing);
  while ALen >= ALimit do
  begin
    DecryptBlocks4Fused(AInBuf, AInOff, AOutBuf, AOutOff);
    AInOff := AInOff + (BlockSize * 4);
    ALen := ALen - (BlockSize * 4);
    AOutOff := AOutOff + (BlockSize * 4);
  end;
{$ELSE}
  raise EInvalidOperationCryptoLibException.CreateRes(@SGcmFourWayNotSupported);
{$ENDIF}
end;

procedure TGcmBlockCipher.DecryptBlocks8(const AInBuf: TCryptoLibByteArray;
  var AInOff: Int32; var ALen: Int32; const AOutBuf: TCryptoLibByteArray;
  var AOutOff: Int32; ALimit: Int32);
begin
{$IFDEF CRYPTOLIB_X86_SIMD}
  if not TGcmBlockCipher.IsEightWaySupported then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmEightWayNotSupported);
  if ALimit < BlockSize * 8 then
    raise EArgumentCryptoLibException.CreateRes(@SGcmDecryptEightWayBadLimit);
  if (FHPow = nil) or (System.Length(FHPow) < 128) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SGcmEightWayHStateMissing);
  while ALen >= ALimit do
  begin
    DecryptBlocks8Fused(AInBuf, AInOff, AOutBuf, AOutOff);
    AInOff := AInOff + (BlockSize * 8);
    ALen := ALen - (BlockSize * 8);
    AOutOff := AOutOff + (BlockSize * 8);
  end;
{$ELSE}
  raise EInvalidOperationCryptoLibException.CreateRes(@SGcmEightWayNotSupported);
{$ENDIF}
end;

procedure TGcmBlockCipher.EncryptBlocks2(const AInBuf: TCryptoLibByteArray;
  AInOff: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LCtrBlock: TCryptoLibByteArray;
  LI: Int32;
  LC0, LC1, LC2, LC3: Byte;
begin
  LCtrBlock := nil;
  System.SetLength(LCtrBlock, BlockSize);

{$IFDEF CRYPTOLIB_X86_SIMD}
  if TGcmBlockCipher.IsSse2PackedVectorXorSupported then
  begin
    GetNextCtrBlock(LCtrBlock);
    System.Move(LCtrBlock[0], AOutBuf[AOutOff], BlockSize);
    GcmBlockXor128Sse2(@AOutBuf[AOutOff], @AInBuf[AInOff]);
    GcmBlockXor128Sse2(@FS[0], @AOutBuf[AOutOff]);
    FMultiplier.MultiplyH(FS);
    AInOff := AInOff + BlockSize;
    AOutOff := AOutOff + BlockSize;
    GetNextCtrBlock(LCtrBlock);
    System.Move(LCtrBlock[0], AOutBuf[AOutOff], BlockSize);
    GcmBlockXor128Sse2(@AOutBuf[AOutOff], @AInBuf[AInOff]);
    GcmBlockXor128Sse2(@FS[0], @AOutBuf[AOutOff]);
    FMultiplier.MultiplyH(FS);
    Exit;
  end;
{$ENDIF}

  GetNextCtrBlock(LCtrBlock);
  for LI := 0 to (BlockSize - 1) div 4 do
  begin
    LC0 := Byte(LCtrBlock[(LI * 4) + 0] xor AInBuf[AInOff + (LI * 4) + 0]);
    LC1 := Byte(LCtrBlock[(LI * 4) + 1] xor AInBuf[AInOff + (LI * 4) + 1]);
    LC2 := Byte(LCtrBlock[(LI * 4) + 2] xor AInBuf[AInOff + (LI * 4) + 2]);
    LC3 := Byte(LCtrBlock[(LI * 4) + 3] xor AInBuf[AInOff + (LI * 4) + 3]);

    FS[(LI * 4) + 0] := FS[(LI * 4) + 0] xor LC0;
    FS[(LI * 4) + 1] := FS[(LI * 4) + 1] xor LC1;
    FS[(LI * 4) + 2] := FS[(LI * 4) + 2] xor LC2;
    FS[(LI * 4) + 3] := FS[(LI * 4) + 3] xor LC3;

    AOutBuf[AOutOff + (LI * 4) + 0] := LC0;
    AOutBuf[AOutOff + (LI * 4) + 1] := LC1;
    AOutBuf[AOutOff + (LI * 4) + 2] := LC2;
    AOutBuf[AOutOff + (LI * 4) + 3] := LC3;
  end;
  FMultiplier.MultiplyH(FS);

  AInOff := AInOff + BlockSize;
  AOutOff := AOutOff + BlockSize;

  GetNextCtrBlock(LCtrBlock);
  for LI := 0 to (BlockSize - 1) div 4 do
  begin
    LC0 := Byte(LCtrBlock[(LI * 4) + 0] xor AInBuf[AInOff + (LI * 4) + 0]);
    LC1 := Byte(LCtrBlock[(LI * 4) + 1] xor AInBuf[AInOff + (LI * 4) + 1]);
    LC2 := Byte(LCtrBlock[(LI * 4) + 2] xor AInBuf[AInOff + (LI * 4) + 2]);
    LC3 := Byte(LCtrBlock[(LI * 4) + 3] xor AInBuf[AInOff + (LI * 4) + 3]);

    FS[(LI * 4) + 0] := FS[(LI * 4) + 0] xor LC0;
    FS[(LI * 4) + 1] := FS[(LI * 4) + 1] xor LC1;
    FS[(LI * 4) + 2] := FS[(LI * 4) + 2] xor LC2;
    FS[(LI * 4) + 3] := FS[(LI * 4) + 3] xor LC3;

    AOutBuf[AOutOff + (LI * 4) + 0] := LC0;
    AOutBuf[AOutOff + (LI * 4) + 1] := LC1;
    AOutBuf[AOutOff + (LI * 4) + 2] := LC2;
    AOutBuf[AOutOff + (LI * 4) + 3] := LC3;
  end;
  FMultiplier.MultiplyH(FS);
end;

procedure TGcmBlockCipher.GetNextCtrBlock(const ABlock: TCryptoLibByteArray);
begin
  System.Inc(FCounter32);
  TPack.UInt32_To_BE(FCounter32, FCounter, 12);
  FCipher.ProcessBlock(FCounter, 0, ABlock, 0);
end;

procedure TGcmBlockCipher.GetNextCtrBlocks4(const ABlocks: TCryptoLibByteArray);
var
  Lc0, Lc1, Lc2, Lc3, Lc4: UInt32;
  LAesX86: IAesEngineX86;
begin
  Lc0 := FCounter32;
  Lc1 := Lc0 + UInt32(1);
  Lc2 := Lc0 + UInt32(2);
  Lc3 := Lc0 + UInt32(3);
  Lc4 := Lc0 + UInt32(4);
  FCounter32 := Lc4;

{$IFDEF CRYPTOLIB_X86_SIMD}
  if TAesEngineX86.IsSupported and Supports(FCipher, IAesEngineX86, LAesX86) then
  begin
    System.Move(FCounter[0], ABlocks[0], 16);
    System.Move(FCounter[0], ABlocks[16], 16);
    System.Move(FCounter[0], ABlocks[32], 16);
    TPack.UInt32_To_BE(Lc4, FCounter, 12);
    TPack.UInt32_To_BE(Lc1, ABlocks, 12);
    TPack.UInt32_To_BE(Lc2, ABlocks, 28);
    TPack.UInt32_To_BE(Lc3, ABlocks, 44);
    System.Move(FCounter[0], ABlocks[48], 16);
    LAesX86.ProcessFourBlocks(@ABlocks[0], @ABlocks[0]);
    Exit;
  end;
{$ENDIF}

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
  LAesX86: IAesEngineX86;
begin
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

{$IFDEF CRYPTOLIB_X86_SIMD}
  if TAesEngineX86.IsSupported and Supports(FCipher, IAesEngineX86, LAesX86) then
  begin
    System.Move(FCounter[0], ABlocks[0], 16);
    System.Move(FCounter[0], ABlocks[16], 16);
    System.Move(FCounter[0], ABlocks[32], 16);
    TPack.UInt32_To_BE(Lc4, FCounter, 12);
    TPack.UInt32_To_BE(Lc1, ABlocks, 12);
    TPack.UInt32_To_BE(Lc2, ABlocks, 28);
    TPack.UInt32_To_BE(Lc3, ABlocks, 44);
    System.Move(FCounter[0], ABlocks[48], 16);
    LAesX86.ProcessFourBlocks(@ABlocks[0], @ABlocks[0]);

    System.Move(FCounter[0], ABlocks[64], 16);
    System.Move(FCounter[0], ABlocks[80], 16);
    System.Move(FCounter[0], ABlocks[96], 16);
    TPack.UInt32_To_BE(Lc8, FCounter, 12);
    TPack.UInt32_To_BE(Lc5, ABlocks, 76);
    TPack.UInt32_To_BE(Lc6, ABlocks, 92);
    TPack.UInt32_To_BE(Lc7, ABlocks, 108);
    System.Move(FCounter[0], ABlocks[112], 16);
    LAesX86.ProcessFourBlocks(@ABlocks[64], @ABlocks[64]);
    Exit;
  end;
{$ENDIF}

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
