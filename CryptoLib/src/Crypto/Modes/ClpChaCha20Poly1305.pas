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

unit ClpChaCha20Poly1305;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  Math,
  ClpIChaCha20Poly1305,
  ClpIAeadCipher,
  ClpICipherParameters,
  ClpIKeyParameter,
  ClpCipherModeParameterUtilities,
  ClpIBulkStreamCipher,
  ClpIChaCha7539Engine,
  ClpChaCha7539Engine,
  ClpCipherKernelTypes,
  ClpCipherKernelBinding,
  ClpCipherKernelRegistry,
  ClpIChaCha20Poly1305Kernel,
  ClpPoly1305,
  ClpIMac,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIRawInitStreamCipher,
  ClpPack,
  ClpCheck,
  ClpArrayUtilities,
  ClpAbstractAeadCipher,
  ClpCryptoLibTypes,
  ClpCryptoLibExceptions;

resourcestring
  SPoly1305Nil = 'Poly1305 cannot be nil';
  SPoly1305MustBeOneTwentyEight = 'must be a 128-bit MAC';
  SInvalidParameters = 'invalid parameters passed to %s';
  SKeyMustBeSpecified = 'key must be specified in initial init';
  SKeyMustBeTwoFiftySix = 'key must be 256 bits';
  SNonceMustBeBits = 'nonce must be %d bits';
  SCannotReuseNonce = 'cannot reuse nonce for %s encryption';
  SInvalidMacSize = 'invalid value for MAC size: %d';
  SCannotBeNegative = 'cannot be negative';
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';
  SDataTooShort = 'data too short';
  SCannotReuseEncryption = '%s cannot be reused for encryption';
  SNeedsInit = '%s needs to be initialized';
  SLimitExceeded = 'limit exceeded';
  SCipherEngine = 'cipher engine';
  SInvalidNonceOctetLength = 'invalid nonce octet length';
  SInvalidOperationState = 'invalid operation state for current cipher state';

type
  /// <summary>
  /// ChaCha20 stream cipher with Poly1305 one-time authenticator (RFC 8439 style construction).
  /// </summary>
  /// <remarks>
  /// Using the same ChaCha nonce more than once under a fixed key allows an attacker to forge tags and
  /// recover keystream; assign a fresh random or monotonic nonce for every message and never retry a
  /// (key, nonce) pair in production.
  /// </remarks>
  TChaCha20Poly1305 = class(TAbstractAeadCipher, IChaCha20Poly1305, IAeadCipher)

  strict protected
  type
    TState = (
      Uninitialized = 0,
      EncInit = 1,
      EncAad = 2,
      EncData = 3,
      EncFinal = 4,
      DecInit = 5,
      DecAad = 6,
      DecData = 7,
      DecFinal = 8
    );

  const
    BufSize: Int32 = 64;
    KeySize: Int32 = 32;
    MacSize: Int32 = 16;

  var
    FState: TState;

    function GetAlgorithmName: String; override;
    function GetModeName: String; override;
    procedure WipeKeyMaterial(); override;

  strict private
  const
    AadLimit: UInt64 = UInt64($FFFFFFFFFFFFFFFF);
    DataLimit: UInt64 = ((UInt64(1) shl 32) - 1) * 64;

  class var
    FZeroes: TCryptoLibByteArray;

  var
    FChaCha20: IChaCha7539Engine;
    // The cipher engine's bulk stream interface when it exposes one (resolved once);
    // enables the 512B/8-way tier. nil => the narrower per-tier path is used.
    FBulkChaCha: IBulkStreamCipher;
    // A registered ChaCha20-Poly1305 kernel bound to the (fixed) engine.
    // Resolved once, direction-agnostic (the kernel handles both directions via
    // ProcessStrides' AForEncrypt); cached across same-object re-Inits.
    FChaChaKernel: IChaCha20Poly1305Kernel;
    // Resolve-once gate for FChaChaKernel (an engine-independent poly-path
    // kernel): re-resolves only on a direction change or a kernel-availability
    // change, not per message.
    FChaChaBinding: TCipherKernelBinding;
    // Raw-IV re-init view of FChaCha20 (probed once); lets InitPacket re-key from
    // raw key + nonce spans with no per-message TParametersWithIV/TKeyParameter.
    FChaChaRaw: IRawInitStreamCipher;
    FChaChaRawProbed: Boolean;
    // Frozen per-message: True routes all Poly1305 through the active kernel.
    FUseKernelPoly: Boolean;
    FNonceBytes: Int32;
    FPoly1305: IMac;

    FKey: TCryptoLibByteArray;
    FNonce: TCryptoLibByteArray;
    FBuffer: TCryptoLibByteArray;
    // Reused 64-byte block for the per-message Poly1305 key derivation (was a
    // fresh allocation in InitMac every message).
    FMacKeyBlock: TCryptoLibByteArray;
    // 16-byte AAD/tail staging for the kernel poly path (whole-block feed).
    FMacStage: TCryptoLibByteArray;
    FMacStagePos: Int32;
    // Reused 16-byte length block for the scalar Poly1305 finish (holds the
    // LE AAD/data length words; not secret). Was a fresh alloc per message.
    FLengthsScratch: TCryptoLibByteArray;

    FInitialAad: TCryptoLibByteArray;

    FAadCount: UInt64;
    FDataCount: UInt64;
    FBufferPos: Int32;

    procedure CheckAad();
    procedure CheckData();
    procedure FinishAad(ANextState: TState);
    procedure FinishData(ANextState: TState);
    function IncrementCount(ACount: UInt64; AIncrement: UInt32; ALimit: UInt64): UInt64;
    procedure InitMac();
    // Poly routing: kernel path stages whole 16-byte blocks, scalar path
    // delegates to FPoly1305. Frozen per message by FUseKernelPoly.
    procedure MacUpdate(const ASrc: TCryptoLibByteArray; AOff, ALen: Int32);
    procedure MacUpdateByte(AByte: Byte);
    procedure MacPad(ACount: UInt64);
    procedure ProcessBlock(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
    // Bulk tier via the engine's IBulkStreamCipher (ACount whole 64B blocks); keeps
    // the same running data-count bookkeeping as the single-block ProcessBlock.
    procedure ProcessBlocksBulk(const AInBytes: TCryptoLibByteArray;
      AInOff, ACount: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
    procedure ProcessData(const AInBytes: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
    procedure Reset(AClearMac, AResetCipher: Boolean); reintroduce; overload;

    class constructor Create; overload;

  public
    constructor Create(); overload;
    constructor Create(const APoly1305: IMac); overload;
    constructor Create(const APoly1305: IMac; const AEngine: IChaCha7539Engine;
      ANonceBytes: Int32); overload;

    procedure Init(AForEncryption: Boolean; const AParameters: ICipherParameters); override;

    /// <summary>One-shot / reusable-context init from raw key, nonce and AAD
    /// spans (no parameter objects). Pass <c>AKey = nil</c> to reuse the
    /// established key. Backing for TChaCha20Poly1305PacketCipher; ordinary
    /// callers use Init.</summary>
    procedure InitPacket(AForEncryption: Boolean;
      const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32); override;

    function GetOutputSize(ALen: Int32): Int32; override;
    function GetUpdateOutputSize(ALen: Int32): Int32; override;

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

{ TChaCha20Poly1305 }

class constructor TChaCha20Poly1305.Create;
begin
  System.SetLength(FZeroes, MacSize - 1);
end;

constructor TChaCha20Poly1305.Create;
begin
  Create(TPoly1305.Create() as IMac);
end;

constructor TChaCha20Poly1305.Create(const APoly1305: IMac);
begin
  Create(APoly1305, TChaCha7539Engine.Create() as IChaCha7539Engine, 12);
end;

constructor TChaCha20Poly1305.Create(const APoly1305: IMac;
  const AEngine: IChaCha7539Engine; ANonceBytes: Int32);
begin
  inherited Create();

  if (APoly1305 = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SPoly1305Nil);
  if (MacSize <> APoly1305.GetMacSize()) then
    raise EArgumentCryptoLibException.CreateRes(@SPoly1305MustBeOneTwentyEight);
  if (AEngine = nil) then
    raise EArgumentNilCryptoLibException.CreateRes(@SCipherEngine);

  if (ANonceBytes < 1) then
    raise EArgumentCryptoLibException.CreateRes(@SInvalidNonceOctetLength);

  FPoly1305 := APoly1305;
  FChaCha20 := AEngine;
  if not Supports(FChaCha20, IBulkStreamCipher, FBulkChaCha) then
    FBulkChaCha := nil;
  FNonceBytes := ANonceBytes;

  FMacSize := MacSize;
  System.SetLength(FKey, KeySize);
  System.SetLength(FNonce, FNonceBytes);
  System.SetLength(FBuffer, BufSize + MacSize);
  System.SetLength(FMacBlock, MacSize);
  System.SetLength(FMacKeyBlock, BufSize);
  System.SetLength(FMacStage, MacSize);
  System.SetLength(FLengthsScratch, 16);

  FState := TState.Uninitialized;
end;

function TChaCha20Poly1305.GetAlgorithmName: String;
begin
  Result := 'ChaCha20Poly1305';
end;

function TChaCha20Poly1305.GetModeName: String;
begin
  // Used only for the unified "mac check in %s failed" message; delegating to
  // the (virtual) algorithm name keeps XChaCha20Poly1305's message correct.
  Result := GetAlgorithmName;
end;

procedure TChaCha20Poly1305.WipeKeyMaterial;
begin
  TArrayUtilities.Fill(FKey, 0, System.Length(FKey), Byte(0));
  TArrayUtilities.Fill(FNonce, 0, System.Length(FNonce), Byte(0));
  TArrayUtilities.Fill(FBuffer, 0, System.Length(FBuffer), Byte(0));
  TArrayUtilities.Fill(FMacBlock, 0, System.Length(FMacBlock), Byte(0));
  TArrayUtilities.Fill(FMacKeyBlock, 0, System.Length(FMacKeyBlock), Byte(0));
  TArrayUtilities.Fill(FMacStage, 0, System.Length(FMacStage), Byte(0));
end;

procedure TChaCha20Poly1305.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LChoice: TCipherAeadChoice;
  LInitKeyParam: IKeyParameter;
  LInitNonce: TCryptoLibByteArray;
  LChaCha20Params: ICipherParameters;
  LMacSizeBits: Int32;
  LDir: TCipherKernelDirection;
begin
  if not TCipherModeParameterUtilities.TryResolveAeadOrIv(AParameters, LChoice)
  then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidParameters,
      [AlgorithmName]);

  LInitKeyParam := LChoice.KeyParameter;
  LInitNonce := LChoice.Nonce;
  FInitialAad := LChoice.AssociatedText;

  if LChoice.IsAead then
  begin
    LMacSizeBits := LChoice.MacSizeBits;
    if ((MacSize * 8) <> LMacSizeBits) then
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize, [LMacSizeBits]);
  end;

  if (LInitKeyParam = nil) then
  begin
    if (TState.Uninitialized = FState) then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end
  else
  begin
    if (KeySize <> LInitKeyParam.KeyLength) then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeTwoFiftySix);
  end;

  if (FNonceBytes <> System.Length(LInitNonce)) then
    raise EArgumentCryptoLibException.CreateResFmt(@SNonceMustBeBits,
      [UInt32(FNonceBytes) shl 3]);

  if (TState.Uninitialized <> FState) and AForEncryption and
    TArrayUtilities.AreEqual(FNonce, LInitNonce) then
  begin
    if (LInitKeyParam = nil) or LInitKeyParam.FixedTimeEquals(FKey) then
      raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce,
        [AlgorithmName]);
  end;

  // Refresh the retained key from the caller; a nil key reuses the retained one
  // ("reuse last key" convention). The engine is always handed the real key --
  // ChaCha key setup is only a handful of word writes, so there is nothing worth
  // caching, and handing over the real key keeps XChaCha correct (it re-derives
  // its per-nonce subkey on every Init). Only the nonce and the per-message
  // Poly1305 key change between same-key messages; the resolved kernel is kept.
  if LInitKeyParam <> nil then
    LInitKeyParam.CopyKeyTo(FKey, 0, KeySize);

  System.Move(LInitNonce[0], FNonce[0], FNonceBytes);

  LChaCha20Params := TParametersWithIV.Create(TKeyParameter.Create(FKey)
    as IKeyParameter, LInitNonce);
  FChaCha20.Init(True, LChaCha20Params);

  // The poly-path kernel is engine-independent, so resolve it once and reuse it
  // across re-Inits; the binding re-resolves only on a direction change or a
  // kernel-availability change (register/unregister or the runtime gate flip).
  if AForEncryption then
    LDir := TCipherKernelDirection.Encrypt
  else
    LDir := TCipherKernelDirection.Decrypt;
  if FChaChaBinding.NeedsResolve(LDir) then
  begin
    FChaChaKernel := nil;
    TCipherKernelRegistry.TryAcquireChaCha20Poly1305(FChaCha20, LDir,
      FChaChaKernel);
    // Reject a kernel whose stride granularity the mode cannot carve cleanly
    // (StrideBytes must be a positive whole number of 64-byte blocks).
    if (FChaChaKernel <> nil) and ((FChaChaKernel.StrideBytes < BufSize) or
      (FChaChaKernel.StrideBytes mod BufSize <> 0)) then
      FChaChaKernel := nil;
  end;

  if AForEncryption then
    FState := TState.EncInit
  else
    FState := TState.DecInit;

  Reset(True, False);
end;

procedure TChaCha20Poly1305.InitPacket(AForEncryption: Boolean;
  const AKey, ANonce, AAad: TCryptoLibByteArray; AMacSizeBits: Int32);
var
  LChaCha20Params: ICipherParameters;
  LDir: TCipherKernelDirection;
begin
  // Raw-span mirror of Init (no TryResolveAeadOrIv, no caller parameter objects).
  if ((MacSize * 8) <> AMacSizeBits) then
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidMacSize,
      [AMacSizeBits]);

  if (AKey = nil) then
  begin
    if (TState.Uninitialized = FState) then
      raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeSpecified);
  end
  else if (KeySize <> System.Length(AKey)) then
    raise EArgumentCryptoLibException.CreateRes(@SKeyMustBeTwoFiftySix);

  if (FNonceBytes <> System.Length(ANonce)) then
    raise EArgumentCryptoLibException.CreateResFmt(@SNonceMustBeBits,
      [UInt32(FNonceBytes) shl 3]);

  if (TState.Uninitialized <> FState) and AForEncryption and
    TArrayUtilities.AreEqual(FNonce, ANonce) then
  begin
    if (AKey = nil) or TArrayUtilities.FixedTimeEquals(AKey, FKey) then
      raise EArgumentCryptoLibException.CreateResFmt(@SCannotReuseNonce,
        [AlgorithmName]);
  end;

  FInitialAad := AAad;

  // Refresh the retained key from the caller (a nil key reuses it); the engine
  // is always handed the real key, as in Init.
  if AKey <> nil then
    System.Move(AKey[0], FKey[0], KeySize);

  System.Move(ANonce[0], FNonce[0], FNonceBytes);

  // Re-init the engine from the raw key + nonce (no per-message parameter
  // objects). The engine is always handed the real key (XChaCha derives a
  // per-nonce subkey from it), matching Init.
  if not FChaChaRawProbed then
  begin
    if not Supports(FChaCha20, IRawInitStreamCipher, FChaChaRaw) then
      FChaChaRaw := nil;
    FChaChaRawProbed := True;
  end;
  if FChaChaRaw <> nil then
    FChaChaRaw.InitRaw(FKey, ANonce)
  else
  begin
    LChaCha20Params := TParametersWithIV.Create(TKeyParameter.Create(FKey)
      as IKeyParameter, ANonce);
    FChaCha20.Init(True, LChaCha20Params);
  end;

  // The poly-path kernel is engine-independent, so resolve it once and reuse it
  // across re-Inits; the binding re-resolves only on a direction change or a
  // kernel-availability change (register/unregister or the runtime gate flip).
  if AForEncryption then
    LDir := TCipherKernelDirection.Encrypt
  else
    LDir := TCipherKernelDirection.Decrypt;
  if FChaChaBinding.NeedsResolve(LDir) then
  begin
    FChaChaKernel := nil;
    TCipherKernelRegistry.TryAcquireChaCha20Poly1305(FChaCha20, LDir,
      FChaChaKernel);
    // Reject a kernel whose stride granularity the mode cannot carve cleanly
    // (StrideBytes must be a positive whole number of 64-byte blocks).
    if (FChaChaKernel <> nil) and ((FChaChaKernel.StrideBytes < BufSize) or
      (FChaChaKernel.StrideBytes mod BufSize <> 0)) then
      FChaChaKernel := nil;
  end;

  if AForEncryption then
    FState := TState.EncInit
  else
    FState := TState.DecInit;

  Reset(True, False);
end;

function TChaCha20Poly1305.GetOutputSize(ALen: Int32): Int32;
var
  LTotal: Int32;
begin
  LTotal := Math.Max(0, ALen);

  case FState of
    TState.DecInit, TState.DecAad:
      Result := Math.Max(0, LTotal - MacSize);
    TState.DecData, TState.DecFinal:
      Result := Math.Max(0, LTotal + FBufferPos - MacSize);
    TState.EncData, TState.EncFinal:
      Result := LTotal + FBufferPos + MacSize;
  else
    Result := LTotal + MacSize;
  end;
end;

function TChaCha20Poly1305.GetUpdateOutputSize(ALen: Int32): Int32;
var
  LTotal: Int32;
begin
  LTotal := Math.Max(0, ALen);

  case FState of
    TState.DecInit, TState.DecAad:
      LTotal := Math.Max(0, LTotal - MacSize);
    TState.DecData, TState.DecFinal:
      LTotal := Math.Max(0, LTotal + FBufferPos - MacSize);
    TState.EncData, TState.EncFinal:
      LTotal := LTotal + FBufferPos;
  else
    ;
  end;

  Result := LTotal - LTotal mod BufSize;
end;

procedure TChaCha20Poly1305.ProcessAadByte(AInput: Byte);
begin
  CheckAad();
  FAadCount := IncrementCount(FAadCount, 1, AadLimit);
  MacUpdateByte(AInput);
end;

procedure TChaCha20Poly1305.ProcessAadBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32);
begin
  if (AInOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  if (ALen < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);

  CheckAad();

  if (ALen > 0) then
  begin
    FAadCount := IncrementCount(FAadCount, UInt32(ALen), AadLimit);
    MacUpdate(AInput, AInOff, ALen);
  end;
end;

function TChaCha20Poly1305.ProcessByte(AInput: Byte;
  const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
begin
  CheckData();

  case FState of
    TState.DecData:
    begin
      FBuffer[FBufferPos] := AInput;
      System.Inc(FBufferPos);
      if (FBufferPos = System.Length(FBuffer)) then
      begin
        MacUpdate(FBuffer, 0, BufSize);
        ProcessBlock(FBuffer, 0, AOutput, AOutOff);
        System.Move(FBuffer[BufSize], FBuffer[0], MacSize);
        FBufferPos := MacSize;
        Result := BufSize;
        Exit;
      end;
      Result := 0;
      Exit;
    end;
    TState.EncData:
    begin
      FBuffer[FBufferPos] := AInput;
      System.Inc(FBufferPos);
      if (FBufferPos = BufSize) then
      begin
        ProcessBlock(FBuffer, 0, AOutput, AOutOff);
        MacUpdate(AOutput, AOutOff, BufSize);
        FBufferPos := 0;
        Result := BufSize;
        Exit;
      end;
      Result := 0;
      Exit;
    end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOperationState);
  end;
end;

function TChaCha20Poly1305.ProcessBytes(const AInput: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutput: TCryptoLibByteArray; AOutOff: Int32): Int32;
var
  LResultLen, LAvailable, LInLimit1, LRemBlocks: Int32;
  LStrides, LStrideBlocks, LStrideBlks: Int32;
begin
  if (AInOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  if (ALen < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);
  TCheck.DataLength(AInput, AInOff, ALen, SInputBufferTooShort);
  if (AOutOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);

  CheckData();

  LResultLen := 0;

  case FState of
    TState.DecData:
    begin
      LAvailable := System.Length(FBuffer) - FBufferPos;
      if (ALen < LAvailable) then
      begin
        System.Move(AInput[AInOff], FBuffer[FBufferPos], ALen);
        FBufferPos := FBufferPos + ALen;
        Result := 0;
        Exit;
      end;

      if (FBufferPos >= BufSize) then
      begin
        MacUpdate(FBuffer, 0, BufSize);
        ProcessBlock(FBuffer, 0, AOutput, AOutOff);
        FBufferPos := FBufferPos - BufSize;
        System.Move(FBuffer[BufSize], FBuffer[0], FBufferPos);
        LResultLen := BufSize;

        LAvailable := LAvailable + BufSize;
        if (ALen < LAvailable) then
        begin
          System.Move(AInput[AInOff], FBuffer[FBufferPos], ALen);
          FBufferPos := FBufferPos + ALen;
          Result := LResultLen;
          Exit;
        end;
      end;

      LInLimit1 := AInOff + ALen - System.Length(FBuffer);

      LAvailable := BufSize - FBufferPos;
      System.Move(AInput[AInOff], FBuffer[FBufferPos], LAvailable);
      MacUpdate(FBuffer, 0, BufSize);
      ProcessBlock(FBuffer, 0, AOutput, AOutOff + LResultLen);
      AInOff := AInOff + LAvailable;
      LResultLen := LResultLen + BufSize;

      if (FBulkChaCha <> nil) then
      begin
        // Bulk MAC-then-decrypt. Fused kernel path folds whole StrideBytes runs
        // (MAC-before-XOR in-asm); the sub-stride remainder streams as before.
        if (AInOff <= LInLimit1) then
        begin
          LRemBlocks := ((LInLimit1 - AInOff) div BufSize) + 1;
          if FUseKernelPoly then
          begin
            LStrideBlocks := FChaChaKernel.StrideBytes div BufSize;
            LStrides := LRemBlocks div LStrideBlocks;
            if (LStrides > 0) then
            begin
              LStrideBlks := LStrides * LStrideBlocks;
              // Count BEFORE the kernel call (load-bearing): DataLimit caps total
              // blocks <= 2^32-1, so the counter cannot wrap inside the stride.
              FDataCount := IncrementCount(FDataCount,
                UInt32(LStrideBlks * BufSize), DataLimit);
              FChaChaKernel.ProcessStrides(@AInput[AInOff],
                @AOutput[AOutOff + LResultLen], LStrides, False);
              AInOff := AInOff + LStrideBlks * BufSize;
              LResultLen := LResultLen + LStrideBlks * BufSize;
              LRemBlocks := LRemBlocks - LStrideBlks;
            end;
          end;
          if (LRemBlocks > 0) then
          begin
            MacUpdate(AInput, AInOff, LRemBlocks * BufSize);
            ProcessBlocksBulk(AInput, AInOff, LRemBlocks, AOutput, AOutOff + LResultLen);
            AInOff := AInOff + LRemBlocks * BufSize;
            LResultLen := LResultLen + LRemBlocks * BufSize;
          end;
        end;
      end
      else
      begin
        // No bulk engine: single-block MAC-then-decrypt.
        while (AInOff <= LInLimit1) do
        begin
          MacUpdate(AInput, AInOff, BufSize);
          ProcessBlock(AInput, AInOff, AOutput, AOutOff + LResultLen);
          AInOff := AInOff + BufSize;
          LResultLen := LResultLen + BufSize;
        end;
      end;

      FBufferPos := System.Length(FBuffer) + LInLimit1 - AInOff;
      System.Move(AInput[AInOff], FBuffer[0], FBufferPos);
    end;
    TState.EncData:
    begin
      LAvailable := BufSize - FBufferPos;
      if (ALen < LAvailable) then
      begin
        System.Move(AInput[AInOff], FBuffer[FBufferPos], ALen);
        FBufferPos := FBufferPos + ALen;
        Result := 0;
        Exit;
      end;

      LInLimit1 := AInOff + ALen - BufSize;

      if (FBufferPos > 0) then
      begin
        System.Move(AInput[AInOff], FBuffer[FBufferPos], LAvailable);
        ProcessBlock(FBuffer, 0, AOutput, AOutOff);
        // Kernel path MACs inline (the blanket MAC below is skipped); the fused
        // strides don't cover this pre-stride block.
        if FUseKernelPoly then
          MacUpdate(AOutput, AOutOff, BufSize);
        AInOff := AInOff + LAvailable;
        LResultLen := BufSize;
      end;

      if (FBulkChaCha <> nil) then
      begin
        // Bulk encrypt. Fused kernel path encrypts+MACs whole StrideBytes runs
        // in one pass (first block + remainder MAC inline, blanket MAC skipped);
        // otherwise encrypt all blocks and MAC the ciphertext once below.
        if (AInOff <= LInLimit1) then
        begin
          LRemBlocks := ((LInLimit1 - AInOff) div BufSize) + 1;
          if FUseKernelPoly then
          begin
            LStrideBlocks := FChaChaKernel.StrideBytes div BufSize;
            LStrides := LRemBlocks div LStrideBlocks;
            if (LStrides > 0) then
            begin
              LStrideBlks := LStrides * LStrideBlocks;
              // Count BEFORE the kernel call (load-bearing): DataLimit caps total
              // blocks <= 2^32-1, so the counter cannot wrap inside the stride.
              FDataCount := IncrementCount(FDataCount,
                UInt32(LStrideBlks * BufSize), DataLimit);
              FChaChaKernel.ProcessStrides(@AInput[AInOff],
                @AOutput[AOutOff + LResultLen], LStrides, True);
              AInOff := AInOff + LStrideBlks * BufSize;
              LResultLen := LResultLen + LStrideBlks * BufSize;
              LRemBlocks := LRemBlocks - LStrideBlks;
            end;
            if (LRemBlocks > 0) then
            begin
              ProcessBlocksBulk(AInput, AInOff, LRemBlocks, AOutput, AOutOff + LResultLen);
              MacUpdate(AOutput, AOutOff + LResultLen, LRemBlocks * BufSize);
              AInOff := AInOff + LRemBlocks * BufSize;
              LResultLen := LResultLen + LRemBlocks * BufSize;
            end;
          end
          else
          begin
            ProcessBlocksBulk(AInput, AInOff, LRemBlocks, AOutput, AOutOff + LResultLen);
            AInOff := AInOff + LRemBlocks * BufSize;
            LResultLen := LResultLen + LRemBlocks * BufSize;
          end;
        end;
      end
      else
      begin
        while (AInOff <= LInLimit1) do
        begin
          ProcessBlock(AInput, AInOff, AOutput, AOutOff + LResultLen);
          AInOff := AInOff + BufSize;
          LResultLen := LResultLen + BufSize;
        end;
      end;

      if not FUseKernelPoly then
        MacUpdate(AOutput, AOutOff, LResultLen);

      FBufferPos := BufSize + LInLimit1 - AInOff;
      System.Move(AInput[AInOff], FBuffer[0], FBufferPos);
    end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOperationState);
  end;

  Result := LResultLen;
end;

function TChaCha20Poly1305.DoFinal(const AOutput: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
var
  LResultLen: Int32;
begin
  if (AOutOff < 0) then
    raise EArgumentCryptoLibException.CreateRes(@SCannotBeNegative);

  CheckData();

  TArrayUtilities.Fill(FMacBlock, 0, MacSize, Byte(0));

  case FState of
    TState.DecData:
    begin
      if (FBufferPos < MacSize) then
        raise EInvalidCipherTextCryptoLibException.CreateRes(@SDataTooShort);

      LResultLen := FBufferPos - MacSize;

      TCheck.OutputLength(AOutput, AOutOff, LResultLen, SOutputBufferTooShort);

      if (LResultLen > 0) then
      begin
        MacUpdate(FBuffer, 0, LResultLen);
        ProcessData(FBuffer, 0, LResultLen, AOutput, AOutOff);
      end;

      FinishData(TState.DecFinal);

      if (not VerifyMac(FBuffer, LResultLen)) then
        RaiseMacCheckFailed();
    end;
    TState.EncData:
    begin
      LResultLen := FBufferPos + MacSize;

      TCheck.OutputLength(AOutput, AOutOff, LResultLen, SOutputBufferTooShort);

      if (FBufferPos > 0) then
      begin
        ProcessData(FBuffer, 0, FBufferPos, AOutput, AOutOff);
        MacUpdate(AOutput, AOutOff, FBufferPos);
      end;

      FinishData(TState.EncFinal);

      System.Move(FMacBlock[0], AOutput[AOutOff + FBufferPos], MacSize);
    end;
  else
    raise EInvalidOperationCryptoLibException.CreateRes(@SInvalidOperationState);
  end;

  Reset(False, True);

  Result := LResultLen;
end;

function TChaCha20Poly1305.ProcessPacket(const AInput: TCryptoLibByteArray;
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

procedure TChaCha20Poly1305.Reset;
begin
  Reset(True, True);
end;

procedure TChaCha20Poly1305.CheckAad;
begin
  case FState of
    TState.DecInit:
      FState := TState.DecAad;
    TState.EncInit:
      FState := TState.EncAad;
    TState.DecAad, TState.EncAad:
      ;
    TState.EncFinal:
      raise EInvalidOperationCryptoLibException.CreateResFmt(@SCannotReuseEncryption, [AlgorithmName]);
  else
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNeedsInit, [AlgorithmName]);
  end;
end;

procedure TChaCha20Poly1305.CheckData;
begin
  case FState of
    TState.DecInit, TState.DecAad:
      FinishAad(TState.DecData);
    TState.EncInit, TState.EncAad:
      FinishAad(TState.EncData);
    TState.DecData, TState.EncData:
      ;
    TState.EncFinal:
      raise EInvalidOperationCryptoLibException.CreateResFmt(@SCannotReuseEncryption, [AlgorithmName]);
  else
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNeedsInit, [AlgorithmName]);
  end;
end;

procedure TChaCha20Poly1305.FinishAad(ANextState: TState);
begin
  MacPad(FAadCount);
  FState := ANextState;
end;

procedure TChaCha20Poly1305.FinishData(ANextState: TState);
begin
  MacPad(FDataCount);

  if FUseKernelPoly then
    FChaChaKernel.FinishPoly(FAadCount, FDataCount, @FMacBlock[0])
  else
  begin
    TPack.UInt64_To_LE(FAadCount, FLengthsScratch, 0);
    TPack.UInt64_To_LE(FDataCount, FLengthsScratch, 8);
    FPoly1305.BlockUpdate(FLengthsScratch, 0, 16);
    FPoly1305.DoFinal(FMacBlock, 0);
  end;

  FState := ANextState;
end;

function TChaCha20Poly1305.IncrementCount(ACount: UInt64;
  AIncrement: UInt32; ALimit: UInt64): UInt64;
begin
  if (ACount > (ALimit - AIncrement)) then
    raise EInvalidOperationCryptoLibException.CreateRes(@SLimitExceeded);

  Result := ACount + AIncrement;
end;

procedure TChaCha20Poly1305.InitMac;
begin
  // Derive the one-time Poly1305 key from ChaCha block 0 (nonce-dependent, so
  // this runs every message); FMacKeyBlock is reused instead of reallocated.
  TArrayUtilities.Fill(FMacKeyBlock, 0, 64, Byte(0));
  // Freeze per-message routing: an active kernel owns the whole poly lifecycle.
  // Requires the bulk engine tier - the fused stride path lives in that branch,
  // so without it the per-block loops would leave ciphertext unMAC'd.
  FUseKernelPoly := (FChaChaKernel <> nil) and (FBulkChaCha <> nil);
  try
    FChaCha20.ProcessBytes(FMacKeyBlock, 0, 64, FMacKeyBlock, 0);
    if FUseKernelPoly then
      FChaChaKernel.InitPoly(@FMacKeyBlock[0])
    else
      FPoly1305.Init(TKeyParameter.Create(FMacKeyBlock, 0, 32) as IKeyParameter);
  finally
    TArrayUtilities.Fill(FMacKeyBlock, 0, 64, Byte(0));
  end;
  FMacStagePos := 0;
end;

procedure TChaCha20Poly1305.MacUpdate(const ASrc: TCryptoLibByteArray;
  AOff, ALen: Int32);
var
  LFill, LWhole: Int32;
begin
  if not FUseKernelPoly then
  begin
    FPoly1305.BlockUpdate(ASrc, AOff, ALen);
    Exit;
  end;

  // Complete any pending partial block, then feed whole 16-byte blocks direct.
  if (FMacStagePos > 0) then
  begin
    LFill := MacSize - FMacStagePos;
    if (LFill > ALen) then
      LFill := ALen;
    System.Move(ASrc[AOff], FMacStage[FMacStagePos], LFill);
    FMacStagePos := FMacStagePos + LFill;
    AOff := AOff + LFill;
    ALen := ALen - LFill;
    if (FMacStagePos = MacSize) then
    begin
      FChaChaKernel.UpdatePoly(@FMacStage[0], 1);
      FMacStagePos := 0;
    end;
  end;

  LWhole := ALen div MacSize;
  if (LWhole > 0) then
  begin
    FChaChaKernel.UpdatePoly(@ASrc[AOff], LWhole);
    AOff := AOff + LWhole * MacSize;
    ALen := ALen - LWhole * MacSize;
  end;

  if (ALen > 0) then
  begin
    System.Move(ASrc[AOff], FMacStage[0], ALen);
    FMacStagePos := ALen;
  end;
end;

procedure TChaCha20Poly1305.MacUpdateByte(AByte: Byte);
begin
  if not FUseKernelPoly then
  begin
    FPoly1305.Update(AByte);
    Exit;
  end;
  FMacStage[FMacStagePos] := AByte;
  System.Inc(FMacStagePos);
  if (FMacStagePos = MacSize) then
  begin
    FChaChaKernel.UpdatePoly(@FMacStage[0], 1);
    FMacStagePos := 0;
  end;
end;

procedure TChaCha20Poly1305.MacPad(ACount: UInt64);
var
  LPartial: Int32;
begin
  if not FUseKernelPoly then
  begin
    LPartial := Int32(ACount) and (MacSize - 1);
    if (0 <> LPartial) then
      FPoly1305.BlockUpdate(FZeroes, 0, MacSize - LPartial);
    Exit;
  end;
  // Flush a staged partial as one zero-padded full block (scalar-equivalent pad).
  if (FMacStagePos > 0) then
  begin
    TArrayUtilities.Fill(FMacStage, FMacStagePos, MacSize, Byte(0));
    FChaChaKernel.UpdatePoly(@FMacStage[0], 1);
    FMacStagePos := 0;
  end;
end;

procedure TChaCha20Poly1305.ProcessBlock(const AInBytes: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  TCheck.OutputLength(AOutBytes, AOutOff, 64, SOutputBufferTooShort);

  FChaCha20.ProcessBlock(AInBytes, AInOff, AOutBytes, AOutOff);

  FDataCount := IncrementCount(FDataCount, 64, DataLimit);
end;

procedure TChaCha20Poly1305.ProcessBlocksBulk(const AInBytes: TCryptoLibByteArray;
  AInOff, ACount: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  TCheck.OutputLength(AOutBytes, AOutOff, ACount * BufSize, SOutputBufferTooShort);

  FBulkChaCha.ProcessBlocks(AInBytes, AInOff, ACount, AOutBytes, AOutOff);

  FDataCount := IncrementCount(FDataCount, ACount * BufSize, DataLimit);
end;

procedure TChaCha20Poly1305.ProcessData(const AInBytes: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  TCheck.OutputLength(AOutBytes, AOutOff, AInLen, SOutputBufferTooShort);

  FChaCha20.ProcessBytes(AInBytes, AInOff, AInLen, AOutBytes, AOutOff);

  FDataCount := IncrementCount(FDataCount, UInt32(AInLen), DataLimit);
end;

procedure TChaCha20Poly1305.Reset(AClearMac, AResetCipher: Boolean);
begin
  TArrayUtilities.Fill(FBuffer, 0, System.Length(FBuffer), Byte(0));

  if AClearMac then
  begin
    TArrayUtilities.Fill(FMacBlock, 0, System.Length(FMacBlock), Byte(0));
  end;

  FAadCount := UInt64(0);
  FDataCount := UInt64(0);
  FBufferPos := 0;

  case FState of
    TState.DecInit, TState.EncInit:
      ;
    TState.DecAad, TState.DecData, TState.DecFinal:
      FState := TState.DecInit;
    TState.EncAad, TState.EncData, TState.EncFinal:
    begin
      FState := TState.EncFinal;
      Exit;
    end;
  else
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNeedsInit, [AlgorithmName]);
  end;

  if AResetCipher then
  begin
    FChaCha20.Reset();
  end;

  InitMac();

  if (FInitialAad <> nil) then
  begin
    ProcessAadBytes(FInitialAad, 0, System.Length(FInitialAad));
  end;
end;

end.
