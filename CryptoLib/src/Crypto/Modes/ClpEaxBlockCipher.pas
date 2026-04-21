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

unit ClpEaxBlockCipher;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIBlockCipherMode,
  ClpIEaxBlockCipher,
  ClpIAeadBlockCipher,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpBlockCipherBulkUtilities,
  ClpFusedKernelTypes,
  ClpIFusedEaxKernel,
  ClpFusedKernelRegistry,
  ClpFusedKernelDefaults, // registers in-tree fused AEAD kernel factories
  ClpCipherModeParameterUtilities,
  ClpCMac,
  ClpIMac,
  ClpParametersWithIV,
  ClpCheck,
  ClpArrayUtilities,
  ClpBitOperations,
  ClpCryptoLibTypes;

resourcestring
  SInvalidParametersEAX = 'invalid parameters passed to EAX';
  SOutputBufferTooShort = 'Output Buffer Too Short';
  SDataTooShort = 'data too short';
  SMacCheckFailed = 'mac check in EAX failed';
  SAadAfterProcessing = 'AAD data cannot be added after encryption/decryption processing has begun.';

type
  TEaxBlockCipher = class(TInterfacedObject, IEaxBlockCipher,
    IAeadBlockCipher, IAeadCipher)

  strict private
  const
    // OMAC / CMAC GF(2^128) reduction polynomial constant (x^128 + x^7 +
    // x^2 + x + 1). Applied to the high bit of the MSB shift when
    // deriving subkeys B = 2*L and P = 4*L.
    CMAC_CONSTANT_128 = Byte($87);

  type
    TTag = (TagN = 0, TagH = 1, TagC = 2);
  var
    FUnderlyingAes: IBlockCipher;
    FCipher: ISicBlockCipher;
    // Cached IBulkBlockCipherMode view of FCipher. TSicBlockCipher always
    // implements IBulkBlockCipherMode so this is non-nil in practice; the
    // Supports() call in the constructor keeps us robust against future
    // variants that might opt out.
    FBulkCipher: IBulkBlockCipherMode;
    FForEncryption: Boolean;
    FBlockSize: Int32;
    FMac: IMac;
    FNonceMac: TCryptoLibByteArray;
    FAssociatedTextMac: TCryptoLibByteArray;
    FMacBlock: TCryptoLibByteArray;
    FMacSize: Int32;
    FBufBlock: TCryptoLibByteArray;
    FBufOff: Int32;
    FCipherInitialized: Boolean;
    FInitialAssociatedText: TCryptoLibByteArray;

{$IFDEF CRYPTOLIB_X86_SIMD}
    // Cached once per Init; non-nil when the registry resolved a fused
    // EAX kernel for the underlying cipher and encrypt direction. Decrypt
    // and non-AES ciphers stay on the TCMac / TSicBlockCipher scalar
    // path; set via FUseFusedBody below.
    FEaxKernel: IFusedEaxKernel;
{$ENDIF CRYPTOLIB_X86_SIMD}
    // True iff a fused body kernel is live for this Init cycle. Gates
    // the mode-owned OMAC substrate (FOmac* + FCtrBlock) against the
    // legacy FMac/FCipher substrate. Set exactly once per Init.
    FUseFusedBody: Boolean;

    // Mode-owned OMAC / CTR substrate, valid only when FUseFusedBody.
    // FOmacState      - running CBC-MAC state over ciphertext, excluding
    //                   the lookahead block (see below).
    // FOmacLookahead  - one held-back full ciphertext block. Not yet
    //                   folded into FOmacState because it might be the
    //                   OMAC-final block (closed with B or P subkey at
    //                   DoFinal). Seeded to TagC at InitCipher so an
    //                   empty body OMAC-closes on TagC alone.
    // FHasOmacLookahead - True iff FOmacLookahead is populated.
    // FOmacB, FOmacP  - OMAC subkeys B = 2*AES_K(0), P = 4*AES_K(0).
    // FCtrBlock       - Full 128-bit BE EAX counter (initial value =
    //                   FNonceMac). Advanced by the fused kernel and by
    //                   the mode's scalar CTR helper.
    FOmacState: TCryptoLibByteArray;
    FOmacLookahead: TCryptoLibByteArray;
    FHasOmacLookahead: Boolean;
    FOmacB: TCryptoLibByteArray;
    FOmacP: TCryptoLibByteArray;
    FCtrBlock: TCryptoLibByteArray;

    procedure InitCipher();
    procedure CalculateMac();
    procedure Reset(AClearMac: Boolean); overload;
    function Process(AB: Byte; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32): Int32;
    function VerifyMac(const AMac: TCryptoLibByteArray; AOff: Int32): Boolean;

    // ----- Fused-body helpers (only touched when FUseFusedBody). -----
    /// <summary>Derive OMAC subkeys B = 2*L and P = 4*L from
    /// L = AES_K(0^128) using the GF(2^128) doubling primitive from
    /// RFC 4493 section 2.3. Called once per Init after the underlying
    /// cipher is keyed.</summary>
    procedure DeriveOmacSubkeys();

    /// <summary>GF(2^128) x-times operation on a 16-byte block (BE bit
    /// order, reduction by x^128 + x^7 + x^2 + x + 1).</summary>
    class procedure DoubleBlock(const ASrc, ADst: TCryptoLibByteArray); static;

    /// <summary>Single-block CBC-MAC step: FOmacState :=
    /// AES_K(FOmacState XOR ABlock). Used by the scalar OMAC lookahead
    /// flush.</summary>
    procedure CbcMacStep(const ABlock: TCryptoLibByteArray;
      AOff: Int32); overload;
    procedure CbcMacStep(ABlockPtr: PByte); overload;

    /// <summary>If FHasOmacLookahead, absorb FOmacLookahead into
    /// FOmacState as a normal CBC-MAC step and clear the flag.</summary>
    procedure FlushOmacLookahead();

    /// <summary>Scalar CTR-encrypt one full 16-byte block from AInPtr to
    /// AOutPtr using FCtrBlock as the pre-increment counter. Advances
    /// FCtrBlock by 1 on return.</summary>
    procedure CtrEncryptBlock(AInPtr, AOutPtr: PByte);

    /// <summary>Scalar CTR-encrypt a partial (&lt; FBlockSize) tail from
    /// AInPtr to AOutPtr. FCtrBlock is NOT advanced - this is always the
    /// final body block.</summary>
    procedure CtrEncryptTail(AInPtr, AOutPtr: PByte; ALen: Int32);

    /// <summary>Advance FCtrBlock by 1 as a 128-bit big-endian counter.
    /// EAX's counter is the full OMAC_K^0(N) tag treated as a BE int so
    /// we ripple carry from the LSB to the MSB.</summary>
    procedure IncrementCtrBlock();

    /// <summary>OMAC-close the body where the final block is the full
    /// 16-byte FOmacLookahead (LExtra = 0 case): FOmacState :=
    /// AES_K(FOmacState XOR FOmacLookahead XOR FOmacB).</summary>
    procedure FinalizeBodyOmacFullFromLookahead();

    /// <summary>OMAC-close the body where the final block is a partial
    /// tail of APartialLen bytes at APartialPtr (LExtra &gt; 0 case).
    /// Flushes the pending lookahead first, then pads, XOR P, AES_K.
    /// APartialLen must satisfy 0 &lt; APartialLen &lt; FBlockSize.</summary>
    procedure FinalizeBodyOmacPartial(APartialPtr: PByte;
      APartialLen: Int32);

  strict protected
    function GetAlgorithmName: String; virtual;
    function GetUnderlyingCipher(): IBlockCipher; virtual;

  public
    constructor Create(const ACipher: IBlockCipher);

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

{ TEaxBlockCipher }

constructor TEaxBlockCipher.Create(const ACipher: IBlockCipher);
begin
  inherited Create();
  FBlockSize := ACipher.GetBlockSize();
  FUnderlyingAes := ACipher;
  FMac := TCMac.Create(ACipher);
  System.SetLength(FMacBlock, FBlockSize);
  System.SetLength(FAssociatedTextMac, FMac.GetMacSize());
  System.SetLength(FNonceMac, FMac.GetMacSize());
  FCipher := TSicBlockCipher.Create(ACipher);
  TBlockCipherBulkUtilities.TryResolveBulkCipherMode(FCipher, FBulkCipher);
  FUseFusedBody := False;
end;

function TEaxBlockCipher.GetAlgorithmName: String;
begin
  Result := FCipher.GetUnderlyingCipher().AlgorithmName + '/EAX';
end;

function TEaxBlockCipher.GetUnderlyingCipher: IBlockCipher;
begin
  Result := FCipher;
end;

function TEaxBlockCipher.GetBlockSize: Int32;
begin
  Result := FCipher.GetBlockSize();
end;

procedure TEaxBlockCipher.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LTag: TCryptoLibByteArray;
begin
  FForEncryption := AForEncryption;

  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidParametersEAX);

  FInitialAssociatedText := LChoice.AssociatedText;
  if LChoice.IsAead then
    FMacSize := LChoice.MacSizeBits div 8
  else
    FMacSize := FMac.GetMacSize() div 2;

  if FForEncryption then
    System.SetLength(FBufBlock, FBlockSize)
  else
    System.SetLength(FBufBlock, FBlockSize + FMacSize);

  System.SetLength(LTag, FBlockSize);

  FMac.Init(LChoice.CipherKey);

  LTag[FBlockSize - 1] := Byte(Ord(TTag.TagN));
  FMac.BlockUpdate(LTag, 0, FBlockSize);
  FMac.BlockUpdate(LChoice.Nonce, 0, System.Length(LChoice.Nonce));
  FMac.DoFinal(FNonceMac, 0);

  FCipher.Init(True, TParametersWithIV.Create(nil, FNonceMac) as IParametersWithIV);

  // Fused-body acquisition for both directions. Decrypt layers the OMAC
  // block-lookahead on top of the existing (FBlockSize + FMacSize)-byte
  // tag-lookahead in FBufBlock: the first FBlockSize bytes of FBufBlock
  // are the block that has just been confirmed as ciphertext (not tag),
  // the last FMacSize bytes remain the trailing tag candidate.
{$IFDEF CRYPTOLIB_X86_SIMD}
  FEaxKernel := nil;
  if FForEncryption then
    TFusedKernelRegistry.TryAcquireEax(FCipher,
      TFusedModeDirection.Encrypt, FEaxKernel)
  else
    TFusedKernelRegistry.TryAcquireEax(FCipher,
      TFusedModeDirection.Decrypt, FEaxKernel);
  FUseFusedBody := FEaxKernel <> nil;
{$ELSE}
  FUseFusedBody := False;
{$ENDIF CRYPTOLIB_X86_SIMD}

  if FUseFusedBody then
  begin
    System.SetLength(FOmacState, FBlockSize);
    System.SetLength(FOmacLookahead, FBlockSize);
    System.SetLength(FCtrBlock, FBlockSize);
    DeriveOmacSubkeys();
  end;

  Reset(True);
end;

procedure TEaxBlockCipher.DeriveOmacSubkeys;
var
  LZeros, LL: TCryptoLibByteArray;
begin
  System.SetLength(LZeros, FBlockSize);
  System.SetLength(LL, FBlockSize);
  FUnderlyingAes.ProcessBlock(LZeros, 0, LL, 0);
  System.SetLength(FOmacB, FBlockSize);
  System.SetLength(FOmacP, FBlockSize);
  DoubleBlock(LL, FOmacB);
  DoubleBlock(FOmacB, FOmacP);
end;

class procedure TEaxBlockCipher.DoubleBlock(const ASrc,
  ADst: TCryptoLibByteArray);
var
  LI: Int32;
  LCarry, LB: UInt32;
begin
  LCarry := 0;
  LI := System.Length(ASrc);
  while LI > 0 do
  begin
    System.Dec(LI);
    LB := ASrc[LI];
    ADst[LI] := Byte((LB shl 1) or LCarry);
    LCarry := (LB shr 7) and 1;
  end;
  // When the original MSB was 1, reduce by the GF(2^128) polynomial via
  // conditional XOR of the $87 constant on the LSB. Use the right-shift
  // arithmetic trick from TCMac to avoid a branch on LCarry.
  ADst[System.Length(ASrc) - 1] :=
    ADst[System.Length(ASrc) - 1] xor Byte(TBitOperations.Asr32(Int32(CMAC_CONSTANT_128),
    (1 - Int32(LCarry)) shl 3));
end;

procedure TEaxBlockCipher.CbcMacStep(const ABlock: TCryptoLibByteArray;
  AOff: Int32);
var
  LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  System.SetLength(LTmp, FBlockSize);
  for LI := 0 to System.Pred(FBlockSize) do
    LTmp[LI] := Byte(FOmacState[LI] xor ABlock[AOff + LI]);
  FUnderlyingAes.ProcessBlock(LTmp, 0, FOmacState, 0);
end;

procedure TEaxBlockCipher.CbcMacStep(ABlockPtr: PByte);
var
  LI: Int32;
  LTmp: TCryptoLibByteArray;
  LPSrc: PByte;
begin
  System.SetLength(LTmp, FBlockSize);
  LPSrc := ABlockPtr;
  for LI := 0 to System.Pred(FBlockSize) do
  begin
    LTmp[LI] := Byte(FOmacState[LI] xor LPSrc^);
    System.Inc(LPSrc);
  end;
  FUnderlyingAes.ProcessBlock(LTmp, 0, FOmacState, 0);
end;

procedure TEaxBlockCipher.FlushOmacLookahead;
begin
  if FHasOmacLookahead then
  begin
    CbcMacStep(FOmacLookahead, 0);
    FHasOmacLookahead := False;
  end;
end;

procedure TEaxBlockCipher.IncrementCtrBlock;
var
  LI: Int32;
  LSum: UInt32;
begin
  LI := FBlockSize - 1;
  LSum := 1;
  while (LI >= 0) and (LSum <> 0) do
  begin
    LSum := LSum + FCtrBlock[LI];
    FCtrBlock[LI] := Byte(LSum);
    LSum := LSum shr 8;
    System.Dec(LI);
  end;
end;

procedure TEaxBlockCipher.CtrEncryptBlock(AInPtr, AOutPtr: PByte);
var
  LI: Int32;
  LKeystream: TCryptoLibByteArray;
  LPIn, LPOut: PByte;
begin
  System.SetLength(LKeystream, FBlockSize);
  FUnderlyingAes.ProcessBlock(FCtrBlock, 0, LKeystream, 0);
  LPIn := AInPtr;
  LPOut := AOutPtr;
  for LI := 0 to System.Pred(FBlockSize) do
  begin
    LPOut^ := Byte(LPIn^ xor LKeystream[LI]);
    System.Inc(LPIn);
    System.Inc(LPOut);
  end;
  IncrementCtrBlock();
end;

procedure TEaxBlockCipher.CtrEncryptTail(AInPtr, AOutPtr: PByte; ALen: Int32);
var
  LI: Int32;
  LKeystream: TCryptoLibByteArray;
  LPIn, LPOut: PByte;
begin
  System.SetLength(LKeystream, FBlockSize);
  FUnderlyingAes.ProcessBlock(FCtrBlock, 0, LKeystream, 0);
  LPIn := AInPtr;
  LPOut := AOutPtr;
  for LI := 0 to System.Pred(ALen) do
  begin
    LPOut^ := Byte(LPIn^ xor LKeystream[LI]);
    System.Inc(LPIn);
    System.Inc(LPOut);
  end;
end;

procedure TEaxBlockCipher.FinalizeBodyOmacFullFromLookahead;
var
  LI: Int32;
  LTmp: TCryptoLibByteArray;
begin
  System.SetLength(LTmp, FBlockSize);
  for LI := 0 to System.Pred(FBlockSize) do
    LTmp[LI] := Byte(FOmacState[LI] xor FOmacLookahead[LI] xor FOmacB[LI]);
  FUnderlyingAes.ProcessBlock(LTmp, 0, FOmacState, 0);
  FHasOmacLookahead := False;
end;

procedure TEaxBlockCipher.FinalizeBodyOmacPartial(APartialPtr: PByte;
  APartialLen: Int32);
var
  LI: Int32;
  LPadded, LTmp: TCryptoLibByteArray;
  LPSrc: PByte;
begin
  FlushOmacLookahead();

  System.SetLength(LPadded, FBlockSize);
  LPSrc := APartialPtr;
  for LI := 0 to System.Pred(APartialLen) do
  begin
    LPadded[LI] := LPSrc^;
    System.Inc(LPSrc);
  end;
  LPadded[APartialLen] := $80;

  System.SetLength(LTmp, FBlockSize);
  for LI := 0 to System.Pred(FBlockSize) do
    LTmp[LI] := Byte(FOmacState[LI] xor LPadded[LI] xor FOmacP[LI]);
  FUnderlyingAes.ProcessBlock(LTmp, 0, FOmacState, 0);
end;

procedure TEaxBlockCipher.InitCipher;
var
  LTag: TCryptoLibByteArray;
begin
  if FCipherInitialized then
    Exit;

  FCipherInitialized := True;

  FMac.DoFinal(FAssociatedTextMac, 0);

  System.SetLength(LTag, FBlockSize);
  LTag[FBlockSize - 1] := Byte(Ord(TTag.TagC));

  if FUseFusedBody then
  begin
    // Stage TagC as the initial lookahead; FOmacState stays at zero. The
    // first full body block will flush TagC as a normal CBC-MAC step,
    // giving the same running state as FMac's TagC absorption would
    // have produced. An empty body takes the FinalizeBodyOmacFullFromLookahead
    // branch and OMAC-closes on TagC with subkey B.
    System.Move(LTag[0], FOmacLookahead[0], FBlockSize);
    FHasOmacLookahead := True;
  end
  else
  begin
    FMac.BlockUpdate(LTag, 0, FBlockSize);
  end;
end;

procedure TEaxBlockCipher.CalculateMac;
var
  LOutC: TCryptoLibByteArray;
  LI: Int32;
begin
  System.SetLength(LOutC, FBlockSize);
  if FUseFusedBody then
  begin
    // DoFinal has already invoked OMAC-close so FOmacState holds the
    // finalized OMAC of TagC || ciphertext.
    System.Move(FOmacState[0], LOutC[0], FBlockSize);
  end
  else
  begin
    FMac.DoFinal(LOutC, 0);
  end;

  for LI := 0 to System.Pred(System.Length(FMacBlock)) do
  begin
    FMacBlock[LI] := Byte(FNonceMac[LI] xor FAssociatedTextMac[LI] xor LOutC[LI]);
  end;
end;

procedure TEaxBlockCipher.Reset;
begin
  Reset(True);
end;

procedure TEaxBlockCipher.Reset(AClearMac: Boolean);
var
  LTag: TCryptoLibByteArray;
begin
  FCipher.Reset();
  FMac.Reset();

  FBufOff := 0;
  TArrayUtilities.Fill<Byte>(FBufBlock, 0, System.Length(FBufBlock), Byte(0));

  if AClearMac then
  begin
    TArrayUtilities.Fill<Byte>(FMacBlock, 0, System.Length(FMacBlock), Byte(0));
  end;

  System.SetLength(LTag, FBlockSize);
  LTag[FBlockSize - 1] := Byte(Ord(TTag.TagH));
  FMac.BlockUpdate(LTag, 0, FBlockSize);

  FCipherInitialized := False;

  if FUseFusedBody then
  begin
    System.Move(FNonceMac[0], FCtrBlock[0], FBlockSize);
    TArrayUtilities.Fill<Byte>(FOmacState, 0, FBlockSize, Byte(0));
    TArrayUtilities.Fill<Byte>(FOmacLookahead, 0, FBlockSize, Byte(0));
    FHasOmacLookahead := False;
  end;

  if (FInitialAssociatedText <> nil) then
  begin
    ProcessAadBytes(FInitialAssociatedText, 0, System.Length(FInitialAssociatedText));
  end;
end;

procedure TEaxBlockCipher.ProcessAadByte(AInput: Byte);
begin
  if FCipherInitialized then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAadAfterProcessing);

  FMac.Update(AInput);
end;

procedure TEaxBlockCipher.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  if FCipherInitialized then
    raise EInvalidOperationCryptoLibException.CreateRes(@SAadAfterProcessing);

  FMac.BlockUpdate(AInput, AInOff, ALen);
end;

function TEaxBlockCipher.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  InitCipher();
  Result := Process(AInput, AOutput, AOutOff);
end;

function TEaxBlockCipher.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LI, LResultLen, LToFill, LBulkBlocks, LBulkBytes, LKernelBlocks, LLastInOff,
    LLastOutOff, LMiddleBlocks, LMiddleInOff, LMiddleOutOff: Int32;
  LScratch: TCryptoLibByteArray;
begin
  InitCipher();

  LResultLen := 0;

  // Fused decrypt path: layers the OMAC block-lookahead (FOmacLookahead)
  // on top of the original scalar path's (FBlockSize + FMacSize)-byte
  // tag-lookahead in FBufBlock. For every aligned bulk window of K >= 4
  // confirmed ciphertext blocks: block 0 is scalar (requires stitching
  // FBufBlock[0..FMacSize-1] with AInput[0..FBlockSize-FMacSize-1]),
  // blocks 1..K-2 run through the fused kernel, and block K-1 is
  // scalar so it can seed FOmacLookahead for the next iteration / for
  // DoFinal's subkey-B-vs-P decision. K < 4 falls through to scalar.
  if FUseFusedBody and (not FForEncryption) and (ALen > 0) then
  begin
    LToFill := (FBlockSize + FMacSize) - FBufOff;
    if LToFill > ALen then
      LToFill := ALen;
    System.Move(AInput[AInOff], FBufBlock[FBufOff], LToFill);
    FBufOff := FBufOff + LToFill;
    AInOff := AInOff + LToFill;
    ALen := ALen - LToFill;
    if FBufOff = FBlockSize + FMacSize then
    begin
      TCheck.OutputLength(AOutput, AOutOff + LResultLen, FBlockSize,
        SOutputBufferTooShort);
      CtrEncryptBlock(@FBufBlock[0], @AOutput[AOutOff + LResultLen]);
      FlushOmacLookahead();
      System.Move(FBufBlock[0], FOmacLookahead[0], FBlockSize);
      FHasOmacLookahead := True;
      LResultLen := LResultLen + FBlockSize;
      System.Move(FBufBlock[FBlockSize], FBufBlock[0], FMacSize);
      FBufOff := FMacSize;
    end;

    if (FBufOff = FMacSize) and (ALen >= FBlockSize) then
    begin
      LBulkBlocks := ALen div FBlockSize;
      LBulkBytes := LBulkBlocks * FBlockSize;
      TCheck.OutputLength(AOutput, AOutOff + LResultLen, LBulkBytes,
        SOutputBufferTooShort);

      LMiddleBlocks := LBulkBlocks - 2;
      if (LBulkBlocks >= 3) and (LMiddleBlocks >= FEaxKernel.MinimumBlockCount)
      then
      begin
        // Scalar block 0 (stitching the held FMacSize-byte tail of the
        // previous buffer with the first (FBlockSize - FMacSize) AInput
        // bytes into one confirmed ciphertext block).
        System.SetLength(LScratch, FBlockSize);
        System.Move(FBufBlock[0], LScratch[0], FMacSize);
        if FBlockSize > FMacSize then
          System.Move(AInput[AInOff], LScratch[FMacSize],
            FBlockSize - FMacSize);
        CtrEncryptBlock(@LScratch[0], @AOutput[AOutOff + LResultLen]);
        FlushOmacLookahead();
        System.Move(LScratch[0], FOmacLookahead[0], FBlockSize);
        FHasOmacLookahead := True;

        // Kernel on the contiguous AInput run covering confirmed blocks
        // 1..LBulkBlocks-2. Fold lookahead first so FOmacState is
        // consistent when the kernel begins absorbing ciphertext.
        FlushOmacLookahead();
        LMiddleInOff := AInOff + FBlockSize - FMacSize;
        LMiddleOutOff := AOutOff + LResultLen + FBlockSize;
        FEaxKernel.ProcessBody(@AInput[LMiddleInOff],
          @AOutput[LMiddleOutOff],
          @FCtrBlock[0], @FOmacState[0], LMiddleBlocks);

        // Scalar block LBulkBlocks - 1 (new lookahead, so DoFinal can
        // choose subkey B or P on the final block).
        LLastInOff := AInOff + (LBulkBlocks - 1) * FBlockSize - FMacSize;
        LLastOutOff := AOutOff + LResultLen + (LBulkBlocks - 1) * FBlockSize;
        CtrEncryptBlock(@AInput[LLastInOff], @AOutput[LLastOutOff]);
        System.Move(AInput[LLastInOff], FOmacLookahead[0], FBlockSize);
        FHasOmacLookahead := True;
      end
      else
      begin
        // Scalar slow path: confirmed block 0 stitches; blocks 1..N-1 run
        // directly from AInput. OMAC lookahead is threaded through each
        // block so the last confirmed block is always the lookahead.
        System.SetLength(LScratch, FBlockSize);
        System.Move(FBufBlock[0], LScratch[0], FMacSize);
        if FBlockSize > FMacSize then
          System.Move(AInput[AInOff], LScratch[FMacSize],
            FBlockSize - FMacSize);
        CtrEncryptBlock(@LScratch[0], @AOutput[AOutOff + LResultLen]);
        FlushOmacLookahead();
        System.Move(LScratch[0], FOmacLookahead[0], FBlockSize);
        FHasOmacLookahead := True;

        for LI := 1 to System.Pred(LBulkBlocks) do
        begin
          LLastInOff := AInOff + LI * FBlockSize - FMacSize;
          LLastOutOff := AOutOff + LResultLen + LI * FBlockSize;
          CtrEncryptBlock(@AInput[LLastInOff], @AOutput[LLastOutOff]);
          FlushOmacLookahead();
          System.Move(AInput[LLastInOff], FOmacLookahead[0], FBlockSize);
          FHasOmacLookahead := True;
        end;
      end;

      System.Move(AInput[AInOff + LBulkBytes - FMacSize], FBufBlock[0],
        FMacSize);
      LResultLen := LResultLen + LBulkBytes;
      AInOff := AInOff + LBulkBytes;
      ALen := ALen - LBulkBytes;
    end;

    if ALen > 0 then
    begin
      System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
      FBufOff := FBufOff + ALen;
    end;

    Result := LResultLen;
    Exit;
  end;

  // Fused encrypt path: mode-owned FOmacState + FCtrBlock + lookahead
  // scheme. Kernel processes (K-1) of every K aligned body blocks; the
  // last block is scalar-processed and becomes the new lookahead. The
  // lookahead defers the OMAC-final subkey XOR until DoFinal knows
  // whether the final MAC block is full (B) or partial (P).
  if FUseFusedBody and FForEncryption and (ALen > 0) then
  begin
    if FBufOff > 0 then
    begin
      LToFill := FBlockSize - FBufOff;
      if LToFill > ALen then
        LToFill := ALen;
      System.Move(AInput[AInOff], FBufBlock[FBufOff], LToFill);
      FBufOff := FBufOff + LToFill;
      AInOff := AInOff + LToFill;
      ALen := ALen - LToFill;
      if FBufOff = FBlockSize then
      begin
        TCheck.OutputLength(AOutput, AOutOff + LResultLen, FBlockSize,
          SOutputBufferTooShort);
        CtrEncryptBlock(@FBufBlock[0], @AOutput[AOutOff + LResultLen]);
        FlushOmacLookahead();
        System.Move(AOutput[AOutOff + LResultLen], FOmacLookahead[0],
          FBlockSize);
        FHasOmacLookahead := True;
        LResultLen := LResultLen + FBlockSize;
        FBufOff := 0;
      end;
    end;

    if (FBufOff = 0) and (ALen >= FBlockSize) then
    begin
      LBulkBlocks := ALen div FBlockSize;
      LBulkBytes := LBulkBlocks * FBlockSize;
      TCheck.OutputLength(AOutput, AOutOff + LResultLen, LBulkBytes,
        SOutputBufferTooShort);

      LKernelBlocks := LBulkBlocks - 1;
      if (LBulkBlocks >= 1) and (LKernelBlocks >= FEaxKernel.MinimumBlockCount)
      then
      begin
        FlushOmacLookahead();
        FEaxKernel.ProcessBody(@AInput[AInOff],
          @AOutput[AOutOff + LResultLen],
          @FCtrBlock[0], @FOmacState[0], LKernelBlocks);

        LLastInOff := AInOff + LKernelBlocks * FBlockSize;
        LLastOutOff := AOutOff + LResultLen + LKernelBlocks * FBlockSize;
        CtrEncryptBlock(@AInput[LLastInOff], @AOutput[LLastOutOff]);
        System.Move(AOutput[LLastOutOff], FOmacLookahead[0], FBlockSize);
        FHasOmacLookahead := True;
      end
      else
      begin
        for LI := 0 to System.Pred(LBulkBlocks) do
        begin
          CtrEncryptBlock(@AInput[AInOff + LI * FBlockSize],
            @AOutput[AOutOff + LResultLen + LI * FBlockSize]);
          FlushOmacLookahead();
          System.Move(AOutput[AOutOff + LResultLen + LI * FBlockSize],
            FOmacLookahead[0], FBlockSize);
          FHasOmacLookahead := True;
        end;
      end;

      LResultLen := LResultLen + LBulkBytes;
      AInOff := AInOff + LBulkBytes;
      ALen := ALen - LBulkBytes;
    end;

    if ALen > 0 then
    begin
      System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
      FBufOff := FBufOff + ALen;
    end;

    Result := LResultLen;
    Exit;
  end;

  // Bulk fast path: only activates when the underlying CTR cipher exposes
  // the generic multi-block capability. The scalar per-byte loop below
  // remains as the fallback and preserves byte-for-byte semantics with the
  // pre-bulk code; the bulk path reproduces the exact same state transitions
  // (MAC update order, FBufBlock lookahead shifts, FBufOff invariants) via
  // a direct buffer-drain + aligned-run + tail-repack sequence.
  if (FBulkCipher <> nil) and (ALen > 0) then
  begin
    if FForEncryption then
    begin
      // Drain any partial block accumulated from previous ProcessBytes
      // calls. If we can complete FBufBlock, flush it exactly as
      // Process() would.
      if FBufOff > 0 then
      begin
        LToFill := FBlockSize - FBufOff;
        if LToFill > ALen then
          LToFill := ALen;
        System.Move(AInput[AInOff], FBufBlock[FBufOff], LToFill);
        FBufOff := FBufOff + LToFill;
        AInOff := AInOff + LToFill;
        ALen := ALen - LToFill;
        if FBufOff = FBlockSize then
        begin
          TCheck.OutputLength(AOutput, AOutOff + LResultLen, FBlockSize,
            SOutputBufferTooShort);
          FCipher.ProcessBlock(FBufBlock, 0, AOutput, AOutOff + LResultLen);
          FMac.BlockUpdate(AOutput, AOutOff + LResultLen, FBlockSize);
          LResultLen := LResultLen + FBlockSize;
          FBufOff := 0;
        end;
      end;

      // Aligned full-block run directly from AInput -> AOutput. CTR
      // encrypts in place via the bulk cipher, then ciphertext is handed
      // to CMAC in one BlockUpdate call.
      if (FBufOff = 0) and (ALen >= FBlockSize) then
      begin
        LBulkBlocks := ALen div FBlockSize;
        LBulkBytes := LBulkBlocks * FBlockSize;
        TCheck.OutputLength(AOutput, AOutOff + LResultLen, LBulkBytes,
          SOutputBufferTooShort);
        FBulkCipher.ProcessBlocks(AInput, AInOff, LBulkBlocks, AOutput,
          AOutOff + LResultLen);
        FMac.BlockUpdate(AOutput, AOutOff + LResultLen, LBulkBytes);
        LResultLen := LResultLen + LBulkBytes;
        AInOff := AInOff + LBulkBytes;
        ALen := ALen - LBulkBytes;
      end;

      // Residue (< FBlockSize bytes) goes into FBufBlock; DoFinal will
      // consume it.
      if ALen > 0 then
      begin
        System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
        FBufOff := FBufOff + ALen;
      end;

      Result := LResultLen;
      Exit;
    end
    else
    begin
      // Decrypt path. FBufBlock is (FBlockSize + FMacSize) bytes; the last
      // FMacSize bytes are a look-ahead that we do not MAC / decrypt until
      // we are certain they are payload and not the trailing tag. The
      // scalar Process() keeps this invariant by shifting the trailing
      // FMacSize bytes down after every flush.
      //
      // Drain the buffer to its canonical post-first-flush state
      // (FBufOff = FMacSize). If the first flush has not yet happened,
      // this step may trigger it. After this step either FBufOff equals
      // FMacSize and ALen may still be > 0, or we ran out of input while
      // filling.
      LToFill := (FBlockSize + FMacSize) - FBufOff;
      if LToFill > ALen then
        LToFill := ALen;
      System.Move(AInput[AInOff], FBufBlock[FBufOff], LToFill);
      FBufOff := FBufOff + LToFill;
      AInOff := AInOff + LToFill;
      ALen := ALen - LToFill;
      if FBufOff = FBlockSize + FMacSize then
      begin
        TCheck.OutputLength(AOutput, AOutOff + LResultLen, FBlockSize,
          SOutputBufferTooShort);
        FMac.BlockUpdate(FBufBlock, 0, FBlockSize);
        FCipher.ProcessBlock(FBufBlock, 0, AOutput, AOutOff + LResultLen);
        LResultLen := LResultLen + FBlockSize;
        System.Move(FBufBlock[FBlockSize], FBufBlock[0], FMacSize);
        FBufOff := FMacSize;
      end;

      // Aligned bulk run: once FBufOff = FMacSize, each subsequent flush
      // consumes exactly FBlockSize bytes of AInput. For N flushes the
      // MAC / decrypt stream is:
      //   chunk 0     = FBufBlock[0..FMacSize-1] || AInput[0..FBlockSize-FMacSize-1]
      //   chunk 1..N-1= AInput[FBlockSize-FMacSize..N*FBlockSize-FMacSize-1] (contiguous)
      //   new FBufBlock[0..FMacSize-1] = AInput[N*FBlockSize-FMacSize..N*FBlockSize-1]
      // Block 0 needs a small FBlockSize-byte scratch to stitch the
      // look-ahead to the first AInput bytes; blocks 1..N-1 reference
      // AInput directly.
      if (FBufOff = FMacSize) and (ALen >= FBlockSize) then
      begin
        LBulkBlocks := ALen div FBlockSize;
        LBulkBytes := LBulkBlocks * FBlockSize;
        TCheck.OutputLength(AOutput, AOutOff + LResultLen, LBulkBytes,
          SOutputBufferTooShort);

        System.SetLength(LScratch, FBlockSize);
        System.Move(FBufBlock[0], LScratch[0], FMacSize);
        if FBlockSize > FMacSize then
          System.Move(AInput[AInOff], LScratch[FMacSize],
            FBlockSize - FMacSize);
        FMac.BlockUpdate(LScratch, 0, FBlockSize);
        FCipher.ProcessBlock(LScratch, 0, AOutput, AOutOff + LResultLen);

        if LBulkBlocks > 1 then
        begin
          FMac.BlockUpdate(AInput, AInOff + FBlockSize - FMacSize,
            (LBulkBlocks - 1) * FBlockSize);
          FBulkCipher.ProcessBlocks(AInput, AInOff + FBlockSize - FMacSize,
            LBulkBlocks - 1, AOutput, AOutOff + LResultLen + FBlockSize);
        end;

        System.Move(AInput[AInOff + LBulkBytes - FMacSize], FBufBlock[0],
          FMacSize);

        LResultLen := LResultLen + LBulkBytes;
        AInOff := AInOff + LBulkBytes;
        ALen := ALen - LBulkBytes;
      end;

      // Pack remaining bytes (strictly less than FBlockSize on this
      // branch) into FBufBlock. No flush is possible with < FBlockSize
      // new bytes: we would not reach FBlockSize + FMacSize total.
      if ALen > 0 then
      begin
        System.Move(AInput[AInOff], FBufBlock[FBufOff], ALen);
        FBufOff := FBufOff + ALen;
      end;

      Result := LResultLen;
      Exit;
    end;
  end;

  for LI := 0 to System.Pred(ALen) do
  begin
    LResultLen := LResultLen + Process(AInput[AInOff + LI], AOutput, AOutOff + LResultLen);
  end;

  Result := LResultLen;
end;

function TEaxBlockCipher.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LExtra: Int32;
  LTmp: TCryptoLibByteArray;
begin
  InitCipher();

  LExtra := FBufOff;
  System.SetLength(LTmp, System.Length(FBufBlock));

  FBufOff := 0;

  if FForEncryption then
  begin
    TCheck.OutputLength(AOutput, AOutOff, LExtra + FMacSize, SOutputBufferTooShort);

    if FUseFusedBody then
    begin
      if LExtra > 0 then
      begin
        CtrEncryptTail(@FBufBlock[0], @AOutput[AOutOff], LExtra);
        FinalizeBodyOmacPartial(@AOutput[AOutOff], LExtra);
      end
      else
      begin
        FinalizeBodyOmacFullFromLookahead();
      end;
    end
    else
    begin
      FCipher.ProcessBlock(FBufBlock, 0, LTmp, 0);
      System.Move(LTmp[0], AOutput[AOutOff], LExtra);
      FMac.BlockUpdate(LTmp, 0, LExtra);
    end;

    CalculateMac();

    System.Move(FMacBlock[0], AOutput[AOutOff + LExtra], FMacSize);

    Reset(False);

    Result := LExtra + FMacSize;
  end
  else
  begin
    if (LExtra < FMacSize) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

    TCheck.OutputLength(AOutput, AOutOff, LExtra - FMacSize, SOutputBufferTooShort);

    if FUseFusedBody then
    begin
      if (LExtra > FMacSize) then
      begin
        FinalizeBodyOmacPartial(@FBufBlock[0], LExtra - FMacSize);
        CtrEncryptTail(@FBufBlock[0], @AOutput[AOutOff], LExtra - FMacSize);
      end
      else
      begin
        FinalizeBodyOmacFullFromLookahead();
      end;
    end
    else if (LExtra > FMacSize) then
    begin
      FMac.BlockUpdate(FBufBlock, 0, LExtra - FMacSize);

      FCipher.ProcessBlock(FBufBlock, 0, LTmp, 0);

      System.Move(LTmp[0], AOutput[AOutOff], LExtra - FMacSize);
    end;

    CalculateMac();

    if (not VerifyMac(FBufBlock, LExtra - FMacSize)) then
      raise EInvalidCipherTextCryptoLibException.CreateRes(@SMacCheckFailed);

    Reset(False);

    Result := LExtra - FMacSize;
  end;
end;

function TEaxBlockCipher.GetMac: TCryptoLibByteArray;
begin
  System.SetLength(Result, FMacSize);
  System.Move(FMacBlock[0], Result[0], FMacSize);
end;

function TEaxBlockCipher.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FBufOff;
  if (not FForEncryption) then
  begin
    if (LTotalData < FMacSize) then
    begin
      Result := 0;
      Exit;
    end;
    LTotalData := LTotalData - FMacSize;
  end;
  Result := LTotalData - LTotalData mod FBlockSize;
end;

function TEaxBlockCipher.GetOutputSize(ALen: Int32): Int32;
var
  LTotalData: Int32;
begin
  LTotalData := ALen + FBufOff;

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

function TEaxBlockCipher.Process(AB: Byte; const AOutBytes: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LSize: Int32;
begin
  FBufBlock[FBufOff] := AB;
  System.Inc(FBufOff);

  if (FBufOff = System.Length(FBufBlock)) then
  begin
    TCheck.OutputLength(AOutBytes, AOutOff, FBlockSize, SOutputBufferTooShort);

    if FForEncryption then
    begin
      if FUseFusedBody then
      begin
        CtrEncryptBlock(@FBufBlock[0], @AOutBytes[AOutOff]);
        FlushOmacLookahead();
        System.Move(AOutBytes[AOutOff], FOmacLookahead[0], FBlockSize);
        FHasOmacLookahead := True;
      end
      else
      begin
        FCipher.ProcessBlock(FBufBlock, 0, AOutBytes, AOutOff);
        FMac.BlockUpdate(AOutBytes, AOutOff, FBlockSize);
      end;
      LSize := FBlockSize;
    end
    else
    begin
      if FUseFusedBody then
      begin
        CtrEncryptBlock(@FBufBlock[0], @AOutBytes[AOutOff]);
        FlushOmacLookahead();
        System.Move(FBufBlock[0], FOmacLookahead[0], FBlockSize);
        FHasOmacLookahead := True;
        LSize := FBlockSize;
      end
      else
      begin
        FMac.BlockUpdate(FBufBlock, 0, FBlockSize);
        LSize := FCipher.ProcessBlock(FBufBlock, 0, AOutBytes, AOutOff);
      end;
    end;

    FBufOff := 0;
    if (not FForEncryption) then
    begin
      System.Move(FBufBlock[FBlockSize], FBufBlock[0], FMacSize);
      FBufOff := FMacSize;
    end;

    Result := LSize;
    Exit;
  end;

  Result := 0;
end;

function TEaxBlockCipher.VerifyMac(const AMac: TCryptoLibByteArray;
  AOff: Int32): Boolean;
begin
  Result := TArrayUtilities.FixedTimeEquals(FMacSize, AMac, AOff, FMacBlock, 0);
end;

end.
