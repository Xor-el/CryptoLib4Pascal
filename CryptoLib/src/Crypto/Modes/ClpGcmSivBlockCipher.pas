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

unit ClpGcmSivBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  Classes,
  Math,
  SysUtils,
  ClpIBlockCipher,
  ClpIGcmSivBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCipherModeParameterUtilities,
  ClpIGcmMultiplier,
  ClpIBulkBlockCipher,
  ClpBlockCipherBulkUtilities,
  ClpGcmBlockCipher,
  ClpGcmUtilities,
  ClpGcmSivUtilities,
  ClpFusedKernelTypes,
  ClpIFusedGcmSivKernel,
  ClpFusedKernelRegistry,
{$IFDEF CRYPTOLIB_X86_SIMD}
  // Link the built-in PCLMULQDQ GCM-SIV accelerator so its initialization
  // section registers with TFusedKernelRegistry.
  ClpPclmulGcmSivKernel,
{$ENDIF CRYPTOLIB_X86_SIMD}
  ClpKeyParameter,
  ClpAesUtilities,
  ClpInt64Utilities,
  ClpByteUtilities,
  ClpPack,
  ClpCheck,
  ClpArrayUtilities,
  ClpStreamUtilities,
  ClpCryptoLibTypes;

resourcestring
  SCipherBlockSizeRequiredSiv = 'Cipher required with a block size of %d.';
  SInvalidParametersGcmSiv = 'invalid parameters passed to GCM_SIV';
  SInvalidNonce = 'Invalid nonce';
  SInvalidKey = 'Invalid key';
  SCipherNotInitialised = 'Cipher is not initialised';
  SAeadAfterData = 'AEAD data cannot be processed after ordinary data';
  SAeadByteCountExceeded = 'AEAD byte count exceeded';
  SByteCountExceeded = 'byte count exceeded';
  SOutputBufferTooShortSiv = 'Output Buffer Too Short';
  SInputBufferTooShortSiv = 'Input Buffer Too Short';
  SDataTooShortSiv = 'Data too short';
  SMacCheckFailedSiv = 'mac check failed';

type
  TGcmSivBlockCipher = class(TInterfacedObject, IGcmSivBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  type
    TGcmSivCache = class(TMemoryStream)
    end;

    TGcmSivHasher = class(TObject)
    strict private
      FBuffer: TCryptoLibByteArray;
      FSingleByte: TCryptoLibByteArray;
      FNumActive: Int32;
      FNumHashed: UInt64;
      FParent: TGcmSivBlockCipher;
    public
      constructor Create(AParent: TGcmSivBlockCipher);
      function GetBytesProcessed(): UInt64;
      procedure Reset();
      procedure UpdateHash(AByte: Byte); overload;
      procedure UpdateHash(const ABuffer: TCryptoLibByteArray; AOffset, ALen: Int32); overload;
      procedure CompleteHash();
    end;

  strict private
  const
    BUFLEN: Int32 = 16;
    HALFBUFLEN: Int32 = 8;
    NONCELEN: Int32 = 12;
    MAX_DATALEN: Int32 = Int32($7FFFFFF8) - 16;
    MASK: Byte = $80;
    ADD: Byte = $E1;
    INITIAL: Int32 = 1;
    AEAD_COMPLETE: Int32 = 2;

  var
    FTheCipher: IBlockCipher;
    // Cached bulk-capable view of FTheCipher. Populated once in the
    // constructor via TBlockCipherBulkUtilities.TryResolveBulkCipher;
    // stays nil when the underlying engine cannot beat per-block dispatch.
    // Drives the 8-wide EncryptPlain / DecryptPlain pipeline below.
    FBulkCipher: IBulkBlockCipher;
    FTheMultiplier: IGcmMultiplier;
    FTheGHash: TCryptoLibByteArray;
    FTheReverse: TCryptoLibByteArray;
    FTheAEADHasher: TGcmSivHasher;
    FTheDataHasher: TGcmSivHasher;
    FThePlain: TGcmSivCache;
    FTheEncData: TGcmSivCache;
    FForEncryption: Boolean;
    FTheInitialAEAD: TCryptoLibByteArray;
    FTheNonce: TCryptoLibByteArray;
    FTheFlags: Int32;

{$IFDEF CRYPTOLIB_X86_SIMD}
    // POLYVAL H-power table (H^8..H^1 as 16-byte limbs in GHASH
    // canonical form, 128 bytes). Populated once per key in DeriveKeys
    // when the fused kernel is available; captured by reference by the
    // kernel and consumed read-only by TGcmSivHasher.UpdateHash.
    FHPow128: TCryptoLibByteArray;
    // Fused POLYVAL kernel resolved via TFusedKernelRegistry. Non-nil
    // only when the registry produced a kernel whose MinimumBlockCount
    // matches the mode's 8-block batch contract.
    FGcmSivKernel: IFusedGcmSivKernel;
    FGcmSivKernelBatchBytes: Int32;
{$ENDIF CRYPTOLIB_X86_SIMD}

    procedure CheckAeadStatus(ALen: Int32);
    procedure CheckStatus(ALen: Int32);
    procedure DeriveKeys(const AKey: IKeyParameter);
    function CalculateTag(): TCryptoLibByteArray;
    function EncryptPlain(const ACounter: TCryptoLibByteArray;
      const ATarget: TCryptoLibByteArray; AOffset: Int32): Int32;
    procedure DecryptPlain();
    /// <summary>
    /// Fill ACounters (8 x 16 bytes) with the next 8 consecutive GCM-SIV
    /// CTR blocks derived from ACounter, advance ACounter's LE-32 counter
    /// field by 8, and run one 8-wide AES call on the bulk engine in
    /// place. Caller then XORs the 128 encrypted counter bytes against
    /// 128 bytes of plaintext/ciphertext to drive the stream.
    ///
    /// Only the first four bytes of ACounter are treated as the counter
    /// (little-endian 32-bit); the trailing 12 bytes are held fixed and
    /// copied into each of the 8 produced blocks. This matches the
    /// scalar IncrementCounter contract exactly, so byte-for-byte output
    /// is preserved between the bulk and scalar paths.
    /// </summary>
    procedure ProcessEightBlocksSivCtr(const ACounter: TCryptoLibByteArray;
      const ACounters: TCryptoLibByteArray);
    function CompletePolyVal(): TCryptoLibByteArray;
    procedure GHashLengths();
    procedure GHASH(const ANext: TCryptoLibByteArray);
    procedure ResetStreams();

    class procedure FillReverse(const AInput: TCryptoLibByteArray;
      AOffset, ALength: Int32; const AOutput: TCryptoLibByteArray); static;
    class procedure XorBlock(const ALeft, ARight: TCryptoLibByteArray); overload; static;
    class procedure XorBlock(const ALeft, ARight: TCryptoLibByteArray;
      AOffset, ALength: Int32); overload; static;
    class procedure IncrementCounter(const ACounter: TCryptoLibByteArray); static;

  strict protected
    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(); overload;
    constructor Create(const ACipher: IBlockCipher); overload;
    constructor Create(const ACipher: IBlockCipher; const AMultiplier: IGcmMultiplier); overload;
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
    function GetOutputSize(ALen: Int32): Int32; virtual;
    function GetUpdateOutputSize(ALen: Int32): Int32; virtual;

    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;
    property UnderlyingCipher: IBlockCipher read GetUnderlyingCipher;
  end;

implementation

{ TGcmSivBlockCipher.TGcmSivHasher }

constructor TGcmSivBlockCipher.TGcmSivHasher.Create(AParent: TGcmSivBlockCipher);
begin
  inherited Create;
  FParent := AParent;
  System.SetLength(FBuffer, 16);
  System.SetLength(FSingleByte, 1);
  FNumActive := 0;
  FNumHashed := 0;
end;

function TGcmSivBlockCipher.TGcmSivHasher.GetBytesProcessed: UInt64;
begin
  Result := FNumHashed;
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.Reset;
begin
  FNumActive := 0;
  FNumHashed := 0;
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.UpdateHash(AByte: Byte);
begin
  FSingleByte[0] := AByte;
  UpdateHash(FSingleByte, 0, 1);
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.UpdateHash(const ABuffer: TCryptoLibByteArray;
  AOffset, ALen: Int32);
var
  LMySpace, LNumProcessed, LMyRemaining: Int32;
begin
  LMySpace := 16 - FNumActive;
  LNumProcessed := 0;
  LMyRemaining := ALen;

  if (FNumActive > 0) and (ALen >= LMySpace) then
  begin
    System.Move(ABuffer[AOffset], FBuffer[FNumActive], LMySpace);
    TGcmSivBlockCipher.FillReverse(FBuffer, 0, 16, FParent.FTheReverse);
    FParent.GHASH(FParent.FTheReverse);

    LNumProcessed := LNumProcessed + LMySpace;
    LMyRemaining := LMyRemaining - LMySpace;
    FNumActive := 0;
  end;

{$IFDEF CRYPTOLIB_X86_SIMD}
  // Fused POLYVAL Horner-by-8 fast path for full 128-byte batches.
  if (FParent.FGcmSivKernel <> nil) and
    (LMyRemaining >= FParent.FGcmSivKernelBatchBytes) then
  begin
    while LMyRemaining >= FParent.FGcmSivKernelBatchBytes do
    begin
      FParent.FGcmSivKernel.ProcessPolyvalBatch(
        @ABuffer[AOffset + LNumProcessed],
        @FParent.FTheGHash[0],
        FParent.FGcmSivKernel.MinimumBlockCount);
      LNumProcessed := LNumProcessed + FParent.FGcmSivKernelBatchBytes;
      LMyRemaining := LMyRemaining - FParent.FGcmSivKernelBatchBytes;
    end;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}

  while LMyRemaining >= 16 do
  begin
    TGcmSivBlockCipher.FillReverse(ABuffer, AOffset + LNumProcessed, 16, FParent.FTheReverse);
    FParent.GHASH(FParent.FTheReverse);

    LNumProcessed := LNumProcessed + 16;
    LMyRemaining := LMyRemaining - 16;
  end;

  if LMyRemaining > 0 then
  begin
    System.Move(ABuffer[AOffset + LNumProcessed], FBuffer[FNumActive], LMyRemaining);
    FNumActive := FNumActive + LMyRemaining;
  end;

  FNumHashed := FNumHashed + UInt64(ALen);
end;

procedure TGcmSivBlockCipher.TGcmSivHasher.CompleteHash;
begin
  if FNumActive > 0 then
  begin
    TArrayUtilities.Fill<Byte>(FParent.FTheReverse, 0, System.Length(FParent.FTheReverse), Byte(0));
    TGcmSivBlockCipher.FillReverse(FBuffer, 0, FNumActive, FParent.FTheReverse);

    FParent.GHASH(FParent.FTheReverse);
  end;
end;

{ TGcmSivBlockCipher }

constructor TGcmSivBlockCipher.Create;
begin
  Create(TAesUtilities.CreateEngine());
end;

constructor TGcmSivBlockCipher.Create(const ACipher: IBlockCipher);
begin
  Create(ACipher, nil);
end;

constructor TGcmSivBlockCipher.Create(const ACipher: IBlockCipher;
  const AMultiplier: IGcmMultiplier);
begin
  inherited Create;
  if ACipher.GetBlockSize() <> BUFLEN then
    raise EArgumentCryptoLibException.CreateResFmt(@SCipherBlockSizeRequiredSiv, [BUFLEN]);

  if AMultiplier <> nil then
    FTheMultiplier := AMultiplier
  else
    FTheMultiplier := TGcmBlockCipher.CreateGcmMultiplier();

  FTheCipher := ACipher;
  // Cache the bulk-capable view of the underlying AES engine so the
  // 8-wide EncryptPlain / DecryptPlain pipeline can dispatch to a single
  // SIMD call per 128-byte batch. Left nil when the engine only exposes
  // scalar IBlockCipher, in which case both hot loops stay on the
  // pre-existing per-block path.
  TBlockCipherBulkUtilities.TryResolveBulkCipher(FTheCipher, FBulkCipher);

  System.SetLength(FTheGHash, BUFLEN);
  System.SetLength(FTheReverse, BUFLEN);

  FTheAEADHasher := TGcmSivHasher.Create(Self);
  FTheDataHasher := TGcmSivHasher.Create(Self);
end;

destructor TGcmSivBlockCipher.Destroy;
begin
  FTheAEADHasher.Free;
  FTheDataHasher.Free;
  FThePlain.Free;
  FTheEncData.Free;
  inherited Destroy;
end;

function TGcmSivBlockCipher.GetAlgorithmName: String;
begin
  Result := FTheCipher.AlgorithmName + '-GCM-SIV';
end;

function TGcmSivBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FTheCipher;
end;

function TGcmSivBlockCipher.GetBlockSize: Int32;
begin
  Result := FTheCipher.GetBlockSize();
end;

procedure TGcmSivBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LMyKey: IKeyParameter;
  LMyNonce: TCryptoLibByteArray;
  LMyInitialAEAD: TCryptoLibByteArray;
  LKeyLength: Int32;
begin
  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersGcmSiv);

  LMyInitialAEAD := LChoice.AssociatedText;
  LMyNonce := LChoice.Nonce;
  LMyKey := LChoice.KeyParameter;

  if System.Length(LMyNonce) <> NONCELEN then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidNonce);

  if LMyKey = nil then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKey);

  LKeyLength := LMyKey.GetKeyLength();
  if (LKeyLength <> BUFLEN) and (LKeyLength <> (BUFLEN shl 1)) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidKey);

  FForEncryption := AForEncryption;
  FTheInitialAEAD := LMyInitialAEAD;
  FTheNonce := LMyNonce;

  DeriveKeys(LMyKey);
  ResetStreams();
end;

procedure TGcmSivBlockCipher.CheckAeadStatus(ALen: Int32);
begin
  if (FTheFlags and INITIAL) = 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SCipherNotInitialised);

  if (FTheFlags and AEAD_COMPLETE) <> 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAeadAfterData);

  if FTheAEADHasher.GetBytesProcessed() > UInt64(MAX_DATALEN - ALen) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAeadByteCountExceeded);
end;

procedure TGcmSivBlockCipher.CheckStatus(ALen: Int32);
var
  LDataLimit: Int64;
  LCurrBytes: Int64;
begin
  if (FTheFlags and INITIAL) = 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SCipherNotInitialised);

  if (FTheFlags and AEAD_COMPLETE) = 0 then
  begin
    FTheAEADHasher.CompleteHash();
    FTheFlags := FTheFlags or AEAD_COMPLETE;
  end;

  LDataLimit := MAX_DATALEN;
  LCurrBytes := FThePlain.Size;
  if not FForEncryption then
  begin
    LDataLimit := LDataLimit + BUFLEN;
    LCurrBytes := FTheEncData.Size;
  end;

  if TInt64Utilities.CompareUnsigned(LCurrBytes, LDataLimit - ALen) > 0 then
    raise EInvalidOperationCryptoLibException.CreateRes(@SByteCountExceeded);
end;

procedure TGcmSivBlockCipher.ProcessAadByte(AInput: Byte);
begin
  CheckAeadStatus(1);
  FTheAEADHasher.UpdateHash(AInput);
end;

procedure TGcmSivBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShortSiv);
  CheckAeadStatus(ALen);
  FTheAEADHasher.UpdateHash(AInput, AInOff, ALen);
end;

function TGcmSivBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  CheckStatus(1);

  if FForEncryption then
  begin
    FThePlain.WriteByte(AInput);
    FTheDataHasher.UpdateHash(AInput);
  end
  else
  begin
    FTheEncData.WriteByte(AInput);
  end;

  Result := 0;
end;

function TGcmSivBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShortSiv);
  CheckStatus(ALen);

  if FForEncryption then
  begin
    FThePlain.Write(AInput[AInOff], ALen);
    FTheDataHasher.UpdateHash(AInput, AInOff, ALen);
  end
  else
  begin
    FTheEncData.Write(AInput[AInOff], ALen);
  end;

  Result := 0;
end;

function TGcmSivBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LMyTag: TCryptoLibByteArray;
  LMyDataLen: Int32;
begin
  TCheck.OutputLength(AOutput, AOutOff, GetOutputSize(0), SOutputBufferTooShortSiv);
  CheckStatus(0);

  if FForEncryption then
  begin
    LMyTag := CalculateTag();

    LMyDataLen := BUFLEN + EncryptPlain(LMyTag, AOutput, AOutOff);

    System.Move(LMyTag[0], AOutput[AOutOff + FThePlain.Size], BUFLEN);

    ResetStreams();
    Result := LMyDataLen;
  end
  else
  begin
    DecryptPlain();

    LMyDataLen := TStreamUtilities.WriteBufTo(FThePlain, AOutput, AOutOff);

    ResetStreams();
    Result := LMyDataLen;
  end;
end;

function TGcmSivBlockCipher.GetMac: TCryptoLibByteArray;
begin
  raise EInvalidOperationCryptoLibException.Create('');
end;

function TGcmSivBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
begin
  Result := 0;
end;

function TGcmSivBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LMyCurr: Int32;
begin
  if FForEncryption then
  begin
    Result := ALen + Int32(FThePlain.Size) + BUFLEN;
  end
  else
  begin
    LMyCurr := ALen + Int32(FTheEncData.Size);
    if LMyCurr > BUFLEN then
      Result := LMyCurr - BUFLEN
    else
      Result := 0;
  end;
end;

procedure TGcmSivBlockCipher.Reset;
begin
  ResetStreams();
end;

procedure TGcmSivBlockCipher.ResetStreams;
var
  LCount: Int32;
begin
  if FThePlain <> nil then
  begin
    LCount := Int32(FThePlain.Size);
    if LCount > 0 then
      FillChar(PByte(FThePlain.Memory)^, LCount, 0);
    FThePlain.Size := 0;
  end;

  FTheAEADHasher.Reset();
  FTheDataHasher.Reset();

  FThePlain.Free;
  FThePlain := TGcmSivCache.Create();

  FTheEncData.Free;
  if FForEncryption then
    FTheEncData := nil
  else
    FTheEncData := TGcmSivCache.Create();

  FTheFlags := FTheFlags and (not AEAD_COMPLETE);
  TArrayUtilities.Fill<Byte>(FTheGHash, 0, System.Length(FTheGHash), Byte(0));

  if FTheInitialAEAD <> nil then
    FTheAEADHasher.UpdateHash(FTheInitialAEAD, 0, System.Length(FTheInitialAEAD));
end;

procedure TGcmSivBlockCipher.ProcessEightBlocksSivCtr(
  const ACounter: TCryptoLibByteArray;
  const ACounters: TCryptoLibByteArray);
var
  LC0, LCk: UInt32;
  LI, LBase: Int32;
begin
  LC0 := UInt32(ACounter[0]) or (UInt32(ACounter[1]) shl 8) or
    (UInt32(ACounter[2]) shl 16) or (UInt32(ACounter[3]) shl 24);

  // Fill 8 consecutive counter blocks in ACounters. For each block k we
  // copy the fixed trailing 12 bytes from ACounter[4..15] (these never
  // change during a GCM-SIV stream; RFC 8452 only varies the first four)
  // and pack LE-32 (LC0 + k) into bytes [0..3]. We intentionally read
  // ACounter[4..15] BEFORE touching ACounter[0..3] so that the LE-32
  // update below does not race the fill.
  for LI := 0 to 7 do
  begin
    LBase := LI * BUFLEN;
    System.Move(ACounter[4], ACounters[LBase + 4], BUFLEN - 4);
    LCk := LC0 + UInt32(LI);
    ACounters[LBase + 0] := Byte(LCk);
    ACounters[LBase + 1] := Byte(LCk shr 8);
    ACounters[LBase + 2] := Byte(LCk shr 16);
    ACounters[LBase + 3] := Byte(LCk shr 24);
  end;

  // Advance ACounter's LE-32 field by 8 so the caller's subsequent bulk
  // or scalar iteration picks up at LC0 + 8. UInt32 arithmetic wraps
  // naturally, matching the scalar IncrementCounter behaviour.
  LCk := LC0 + UInt32(8);
  ACounter[0] := Byte(LCk);
  ACounter[1] := Byte(LCk shr 8);
  ACounter[2] := Byte(LCk shr 16);
  ACounter[3] := Byte(LCk shr 24);

  // One SIMD-backed call encrypts all 8 counter blocks in place.
  FBulkCipher.ProcessBlocks(@ACounters[0], @ACounters[0], 8);
end;

function TGcmSivBlockCipher.EncryptPlain(const ACounter: TCryptoLibByteArray;
  const ATarget: TCryptoLibByteArray; AOffset: Int32): Int32;
var
  LThePlainBuf: TCryptoLibByteArray;
  LThePlainLen: Int32;
  LMySrc, LMyCounter, LMyMask, LMyCounters: TCryptoLibByteArray;
  LMyRemaining: Int64;
  LMyOff, LMyLen: Int32;
begin
  System.SetLength(LThePlainBuf, FThePlain.Size);
  FThePlain.Position := 0;
  FThePlain.ReadBuffer(LThePlainBuf[0], System.Length(LThePlainBuf));
  LThePlainLen := System.Length(LThePlainBuf);

  LMySrc := LThePlainBuf;
  LMyCounter := System.Copy(ACounter);
  LMyCounter[BUFLEN - 1] := LMyCounter[BUFLEN - 1] or MASK;
  System.SetLength(LMyMask, BUFLEN);
  LMyRemaining := LThePlainLen;
  LMyOff := 0;

  // Bulk 8-wide CTR path. Each iteration derives 128 bytes of AES keystream
  // in one SIMD call and XORs it directly into the destination via the
  // shared 128-byte triple-XOR primitive. Counter bookkeeping (including
  // the LE-32 wrap) is handled inside ProcessEightBlocksSivCtr, so the
  // scalar tail below resumes exactly where the last batch left off.
  if (FBulkCipher <> nil) and (LMyRemaining >= 128) then
  begin
    System.SetLength(LMyCounters, 8 * BUFLEN);
    while LMyRemaining >= 128 do
    begin
      ProcessEightBlocksSivCtr(LMyCounter, LMyCounters);
      TBlockCipherBulkUtilities.Xor128Bytes(
        PByte(@ATarget[AOffset + LMyOff]),
        PByte(@LMyCounters[0]),
        PByte(@LMySrc[LMyOff]));
      LMyRemaining := LMyRemaining - 128;
      LMyOff := LMyOff + 128;
    end;
  end;

  while LMyRemaining > 0 do
  begin
    FTheCipher.ProcessBlock(LMyCounter, 0, LMyMask, 0);

    LMyLen := Int32(Math.Min(BUFLEN, LMyRemaining));
    XorBlock(LMyMask, LMySrc, LMyOff, LMyLen);

    System.Move(LMyMask[0], ATarget[AOffset + LMyOff], LMyLen);

    LMyRemaining := LMyRemaining - LMyLen;
    LMyOff := LMyOff + LMyLen;
    IncrementCounter(LMyCounter);
  end;

  Result := LThePlainLen;
end;

procedure TGcmSivBlockCipher.DecryptPlain;
var
  LTheEncDataBuf: TCryptoLibByteArray;
  LTheEncDataLen: Int32;
  LMySrc, LMyExpected, LMyCounter, LMyMask, LMyTag, LMyCounters,
    LMyScratch128: TCryptoLibByteArray;
  LMyRemaining, LMyOff, LMyLen: Int32;
begin
  System.SetLength(LTheEncDataBuf, FTheEncData.Size);
  FTheEncData.Position := 0;
  FTheEncData.ReadBuffer(LTheEncDataBuf[0], System.Length(LTheEncDataBuf));
  LTheEncDataLen := System.Length(LTheEncDataBuf);

  LMySrc := LTheEncDataBuf;
  LMyRemaining := LTheEncDataLen - BUFLEN;

  if LMyRemaining < 0 then
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShortSiv);

  LMyExpected := TArrayUtilities.CopyOfRange<Byte>(LMySrc, LMyRemaining, LMyRemaining + BUFLEN);
  LMyCounter := System.Copy(LMyExpected);
  LMyCounter[BUFLEN - 1] := LMyCounter[BUFLEN - 1] or MASK;
  System.SetLength(LMyMask, BUFLEN);
  LMyOff := 0;

  // Bulk 8-wide CTR path. In contrast with the scalar loop (which called
  // FThePlain.Write + FTheDataHasher.UpdateHash eight times per 128-byte
  // batch), the bulk variant materialises the plaintext into a 128-byte
  // scratch and makes ONE UpdateHash call per batch. That collapses the
  // per-batch PolyVal bookkeeping (FNumActive tests, FillReverse inner
  // loops, GHASH calls) into a single cold path and is the main win of
  // this bulk path on large payloads.
  if (FBulkCipher <> nil) and (LMyRemaining >= 128) then
  begin
    System.SetLength(LMyCounters, 8 * BUFLEN);
    System.SetLength(LMyScratch128, 128);
    while LMyRemaining >= 128 do
    begin
      ProcessEightBlocksSivCtr(LMyCounter, LMyCounters);
      TBlockCipherBulkUtilities.Xor128Bytes(
        PByte(@LMyScratch128[0]),
        PByte(@LMyCounters[0]),
        PByte(@LMySrc[LMyOff]));
      FThePlain.Write(LMyScratch128[0], 128);
      FTheDataHasher.UpdateHash(LMyScratch128, 0, 128);
      LMyRemaining := LMyRemaining - 128;
      LMyOff := LMyOff + 128;
    end;
  end;

  while LMyRemaining > 0 do
  begin
    FTheCipher.ProcessBlock(LMyCounter, 0, LMyMask, 0);

    LMyLen := Math.Min(BUFLEN, LMyRemaining);
    XorBlock(LMyMask, LMySrc, LMyOff, LMyLen);

    FThePlain.Write(LMyMask[0], LMyLen);
    FTheDataHasher.UpdateHash(LMyMask, 0, LMyLen);

    LMyRemaining := LMyRemaining - LMyLen;
    LMyOff := LMyOff + LMyLen;
    IncrementCounter(LMyCounter);
  end;

  LMyTag := CalculateTag();
  if not TArrayUtilities.FixedTimeEquals(LMyTag, LMyExpected) then
  begin
    Reset();
    raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailedSiv);
  end;
end;

function TGcmSivBlockCipher.CalculateTag: TCryptoLibByteArray;
var
  LMyPolyVal, LMyResult: TCryptoLibByteArray;
  LI: Int32;
begin
  FTheDataHasher.CompleteHash();
  LMyPolyVal := CompletePolyVal();

  System.SetLength(LMyResult, BUFLEN);

  for LI := 0 to NONCELEN - 1 do
    LMyPolyVal[LI] := LMyPolyVal[LI] xor FTheNonce[LI];

  LMyPolyVal[BUFLEN - 1] := LMyPolyVal[BUFLEN - 1] and Byte(MASK - 1);

  FTheCipher.ProcessBlock(LMyPolyVal, 0, LMyResult, 0);
  Result := LMyResult;
end;

function TGcmSivBlockCipher.CompletePolyVal: TCryptoLibByteArray;
var
  LMyResult: TCryptoLibByteArray;
begin
  System.SetLength(LMyResult, BUFLEN);
  GHashLengths();
  FillReverse(FTheGHash, 0, BUFLEN, LMyResult);
  Result := LMyResult;
end;

procedure TGcmSivBlockCipher.GHashLengths;
var
  LMyIn: TCryptoLibByteArray;
begin
  System.SetLength(LMyIn, BUFLEN);
  TPack.UInt64_To_BE(UInt64(TByteUtilities.NumBits) * FTheDataHasher.GetBytesProcessed(), LMyIn, 0);
  TPack.UInt64_To_BE(UInt64(TByteUtilities.NumBits) * FTheAEADHasher.GetBytesProcessed(), LMyIn, TInt64Utilities.NumBytes);
  GHASH(LMyIn);
end;

procedure TGcmSivBlockCipher.GHASH(const ANext: TCryptoLibByteArray);
begin
  XorBlock(FTheGHash, ANext);
  FTheMultiplier.MultiplyH(FTheGHash);
end;

class procedure TGcmSivBlockCipher.FillReverse(const AInput: TCryptoLibByteArray;
  AOffset, ALength: Int32; const AOutput: TCryptoLibByteArray);
var
  LI, LJ: Int32;
begin
  LJ := 16 - 1;
  for LI := 0 to ALength - 1 do
  begin
    AOutput[LJ] := AInput[AOffset + LI];
    System.Dec(LJ);
  end;
end;

class procedure TGcmSivBlockCipher.XorBlock(const ALeft, ARight: TCryptoLibByteArray);
var
  LI: Int32;
begin
  for LI := 0 to 15 do
    ALeft[LI] := ALeft[LI] xor ARight[LI];
end;

class procedure TGcmSivBlockCipher.XorBlock(const ALeft, ARight: TCryptoLibByteArray;
  AOffset, ALength: Int32);
var
  LI: Int32;
begin
  for LI := 0 to ALength - 1 do
    ALeft[LI] := ALeft[LI] xor ARight[LI + AOffset];
end;

class procedure TGcmSivBlockCipher.IncrementCounter(const ACounter: TCryptoLibByteArray);
var
  LI: Int32;
begin
  for LI := 0 to 3 do
  begin
    ACounter[LI] := Byte(ACounter[LI] + 1);
    if ACounter[LI] <> 0 then
      Break;
  end;
end;

procedure TGcmSivBlockCipher.DeriveKeys(const AKey: IKeyParameter);
var
  LMyIn, LMyOut, LMyResult, LMyEncKey: TCryptoLibByteArray;
  LMyOff: Int32;
begin
  System.SetLength(LMyIn, BUFLEN);
  System.SetLength(LMyOut, BUFLEN);
  System.SetLength(LMyResult, BUFLEN);
  System.SetLength(LMyEncKey, AKey.GetKeyLength());

  System.Move(FTheNonce[0], LMyIn[BUFLEN - NONCELEN], NONCELEN);
  FTheCipher.Init(True, AKey as ICipherParameters);

  LMyOff := 0;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyResult[LMyOff], HALFBUFLEN);
  LMyIn[0] := Byte(LMyIn[0] + 1);
  LMyOff := LMyOff + HALFBUFLEN;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyResult[LMyOff], HALFBUFLEN);

  LMyIn[0] := Byte(LMyIn[0] + 1);
  LMyOff := 0;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyEncKey[LMyOff], HALFBUFLEN);
  LMyIn[0] := Byte(LMyIn[0] + 1);
  LMyOff := LMyOff + HALFBUFLEN;
  FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
  System.Move(LMyOut[0], LMyEncKey[LMyOff], HALFBUFLEN);

  if System.Length(LMyEncKey) = (BUFLEN shl 1) then
  begin
    LMyIn[0] := Byte(LMyIn[0] + 1);
    LMyOff := LMyOff + HALFBUFLEN;
    FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
    System.Move(LMyOut[0], LMyEncKey[LMyOff], HALFBUFLEN);
    LMyIn[0] := Byte(LMyIn[0] + 1);
    LMyOff := LMyOff + HALFBUFLEN;
    FTheCipher.ProcessBlock(LMyIn, 0, LMyOut, 0);
    System.Move(LMyOut[0], LMyEncKey[LMyOff], HALFBUFLEN);
  end;

  FTheCipher.Init(True, TKeyParameter.Create(LMyEncKey) as ICipherParameters);

  FillReverse(LMyResult, 0, BUFLEN, LMyOut);
  TGcmSivUtilities.MulX(LMyOut);
  FTheMultiplier.Init(LMyOut);

{$IFDEF CRYPTOLIB_X86_SIMD}
  // Precompute the POLYVAL H-power table and resolve the fused kernel
  // for this key. LMyOut is already conditioned for GHASH. The H-power
  // table is captured by reference by the kernel and must outlive it;
  // it is owned by this cipher instance.
  FGcmSivKernel := nil;
  FGcmSivKernelBatchBytes := 0;
  if System.Length(FHPow128) < 128 then
    System.SetLength(FHPow128, 128);
  TGcmUtilities.InitEightWayHPowFromH(LMyOut, FHPow128);
  if TFusedKernelRegistry.TryAcquireGcmSiv(FTheCipher,
    TFusedModeDirection.Encrypt, @FHPow128[0], FGcmSivKernel) and
    (FGcmSivKernel <> nil) then
  begin
    if FGcmSivKernel.MinimumBlockCount = 8 then
      FGcmSivKernelBatchBytes := FGcmSivKernel.MinimumBlockCount * BUFLEN
    else
      FGcmSivKernel := nil;
  end;
{$ENDIF CRYPTOLIB_X86_SIMD}

  FTheFlags := FTheFlags or INITIAL;
end;

end.
