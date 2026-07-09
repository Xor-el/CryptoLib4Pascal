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

unit ClpSalsa20Engine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpBitOperations,
  ClpCheck,
  ClpIStreamCipher,
  ClpIBulkStreamCipher,
  ClpISalsa20Engine,
  ClpIKeyParameter,
  ClpICipherParameters,
  ClpIParametersWithIV,
  ClpPack,
  ClpSalsaSimd,
  ClpByteUtilities,
  ClpCryptoLibTypes;

resourcestring
  SInvalidRound = 'rounds must be a positive, even number';
  SInvalidKeySize = '%s requires 128 bit or 256 bit key';
  SMaxByteExceeded = '2^70 byte limit per IV would be exceeded; change IV';
  SEngineNotInitialized = '%s not initialized';
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';
  SRoundsMustBeEven = 'number of rounds must be even';
  SIVRequired = '%s init requires an IV';
  SInvalidIV = '%s requires exactly %d bytes of IV';
  SInitError =
    '%s init parameters must contain a KeyParameter (or nil for re-init)';
  SKeyParameterNullForFirstInit =
    'KeyParameter cannot be nil for first initialization';
  SInputStateMustBeSixteen = 'Salsa20 input state must be 16 UInt32 values';
  SOutputStateMustBeSixteen = 'Salsa20 output buffer must be 16 UInt32 values';
  SNotBlockAligned = '%s not in block-aligned state';

type
  /// <summary>
  /// Implementation of Daniel J. Bernstein's Salsa20 stream cipher, Snuffle 2005
  /// </summary>
  TSalsa20Engine = class(TInterfacedObject, ISalsa20Engine, IStreamCipher,
    IBulkStreamCipher)

  strict private
  const
    DEFAULT_ROUNDS = Int32(20);
    STATE_SIZE = Int32(16); // 16, 32 bit ints = 64 bytes
    // representation of 'expand 16-byte k' + 'expand 32-byte k' as an array of UInt32
    TAU_SIGMA: array [0 .. 7] of UInt32 = (1634760805, 824206446, 2036477238,
      1797285236, 1634760805, 857760878, 2036477234, 1797285236);

  var
    // internal counter
    FCW0, FCW1, FCW2: UInt32;

    class procedure QuarterRound(var A, B, C, D: UInt32); static; inline;

    // Pointer-form, unvalidated inner helpers (1 / 2 blocks).
    procedure ProcessBlockFast(AIn, AOut: PByte);
    procedure ProcessBlocks2Fast(AIn, AOut: PByte);

  strict protected
  var
    FIndex: Int32;
    FKeyStream: TCryptoLibByteArray;
    FInitialised: Boolean;
    FRounds: Int32;
    FEngineState, FX: TCryptoLibUInt32Array;

    procedure ResetLimitCounter(); inline;
    function LimitExceeded(): Boolean; overload; inline;
    function LimitExceeded(ALen: UInt32): Boolean; overload; inline;

    function GetAlgorithmName: String; virtual;
    function GetNonceSize: Int32; virtual;
    property NonceSize: Int32 read GetNonceSize;

    procedure AdvanceCounter(); virtual;
    procedure ResetCounter(); virtual;
    procedure SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray); virtual;
    procedure GenerateKeyStream(const AOutput: TCryptoLibByteArray); virtual;

    procedure AssertInitialisedAndBlockAligned; inline;
    procedure ImplProcessBlock(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32); inline;

    // 2 -> 1 bulk ladder; the ChaCha engine overrides with 8 -> 4 -> 2 -> 1.
    function DoProcessBlocks(AIn, AOut: PByte; ABlockCount: Int32): Int32; virtual;

    /// <summary>
    /// Rotate left
    /// </summary>
    /// <param name="AX">
    /// value to rotate
    /// </param>
    /// <param name="AY">
    /// amount to rotate AX
    /// </param>
    /// <returns>
    /// rotated AX
    /// </returns>
    class function R(AX: UInt32; AY: Int32): UInt32; static; inline;
    class procedure PackTauOrSigma(AKeyLength: Int32;
      const AState: TCryptoLibUInt32Array); static;
    class procedure SalsaCore(ARounds: Int32;
      const AInput, AX: TCryptoLibUInt32Array); static;

  public
    /// <summary>
    /// Creates a 20 round Salsa20 engine.
    /// </summary>
    constructor Create(); overload;
    /// <summary>
    /// Creates a Salsa20 engine with a specific number of rounds.
    /// </summary>
    /// <param name="ARounds">the number of rounds (must be an even number).</param>
    constructor Create(ARounds: Int32); overload;

    procedure Init(AForEncryption: Boolean;
      const AParameters: ICipherParameters); virtual;
    function ReturnByte(AInput: Byte): Byte; virtual;

    procedure ProcessBlocks2(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32); virtual;

    // IBulkStreamCipher: bulk keystream over whole 64B blocks; engine owns the ladder.
    function ProcessBlocks(const AInBuf: TCryptoLibByteArray;
      AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
      AOutOff: Int32): Int32; overload;
    function ProcessBlocks(AInput, AOutput: PByte; ABlockCount: Int32): Int32; overload;

    procedure ProcessBytes(const AInBytes: TCryptoLibByteArray;
      AInOff, ALen: Int32; const AOutBytes: TCryptoLibByteArray;
      AOutOff: Int32); virtual;

    procedure Reset(); virtual;

    property AlgorithmName: String read GetAlgorithmName;

  end;

implementation

{ TSalsa20Engine }

constructor TSalsa20Engine.Create;
begin
  Create(DEFAULT_ROUNDS);
end;

procedure TSalsa20Engine.AdvanceCounter;
begin
  System.Inc(FEngineState[8]);
  if (FEngineState[8] = 0) then
  begin
    System.Inc(FEngineState[9]);
  end;
end;

constructor TSalsa20Engine.Create(ARounds: Int32);
begin
  Inherited Create();
  if ((ARounds <= 0) or ((ARounds and 1) <> 0)) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInvalidRound);
  end;
  FRounds := ARounds;
  FIndex := 0;
  FInitialised := False;
  System.SetLength(FEngineState, STATE_SIZE); // state
  System.SetLength(FX, STATE_SIZE); // internal buffer
  System.SetLength(FKeyStream, STATE_SIZE * 4); // expanded state, 64 bytes
end;

procedure TSalsa20Engine.GenerateKeyStream(const AOutput: TCryptoLibByteArray);
begin
  SalsaCore(FRounds, FEngineState, FX);
  TPack.UInt32_To_LE(FX, 0, System.Length(FX), AOutput, 0);
end;

function TSalsa20Engine.GetAlgorithmName: String;
begin
  Result := 'Salsa20';
  if (FRounds <> DEFAULT_ROUNDS) then
  begin
    Result := Format('%s/%d', [Result, FRounds]);
  end;
end;

function TSalsa20Engine.GetNonceSize: Int32;
begin
  Result := 8;
end;

procedure TSalsa20Engine.AssertInitialisedAndBlockAligned;
begin
  if (not FInitialised) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SEngineNotInitialized, [AlgorithmName]);
  end;
  if (FIndex <> 0) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNotBlockAligned,
      [AlgorithmName]);
  end;
end;

procedure TSalsa20Engine.Init(AForEncryption: Boolean;
  const AParameters: ICipherParameters);
var
  LIvParams: IParametersWithIV;
  LIv: TCryptoLibByteArray;
  LKeyParam: ICipherParameters;
  LKeyParameter: IKeyParameter;
begin
  (*
    * Salsa20 encryption and decryption is completely
    * symmetrical, so the 'forEncryption' is
    * irrelevant. (Like 90% of stream ciphers)
  *)

  if not Supports(AParameters, IParametersWithIV, LIvParams) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SIVRequired,
      [AlgorithmName]);
  end;

  LIv := LIvParams.GetIV();
  if ((LIv = nil) or (System.Length(LIv) <> NonceSize)) then
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInvalidIV,
      [AlgorithmName, NonceSize]);
  end;

  LKeyParam := LIvParams.Parameters;
  if (LKeyParam = nil) then
  begin
    if (not FInitialised) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt
        (@SKeyParameterNullForFirstInit, [AlgorithmName]);
    end;

    SetKey(nil, LIv);
  end
  else if Supports(LKeyParam, IKeyParameter, LKeyParameter) then
  begin
    SetKey(LKeyParameter.GetKey(), LIv);
  end
  else
  begin
    raise EArgumentCryptoLibException.CreateResFmt(@SInitError,
      [AlgorithmName]);
  end;

  Reset();
  FInitialised := True;
end;

function TSalsa20Engine.LimitExceeded: Boolean;
begin
  System.Inc(FCW0);
  if (FCW0 = 0) then
  begin
    System.Inc(FCW1);
    if (FCW1 = 0) then
    begin
      System.Inc(FCW2);
      Result := (FCW2 and $20) <> 0; // 2^(32 + 32 + 6)
      Exit;
    end;
  end;

  Result := False;
end;

function TSalsa20Engine.LimitExceeded(ALen: UInt32): Boolean;
var
  LOld: UInt32;
begin
  LOld := FCW0;
  System.Inc(FCW0, ALen);
  if (FCW0 < LOld) then
  begin
    System.Inc(FCW1);
    if (FCW1 = 0) then
    begin
      System.Inc(FCW2);
      Result := (FCW2 and $20) <> 0; // 2^(32 + 32 + 6)
      Exit;
    end;
  end;

  Result := False;
end;

procedure TSalsa20Engine.ImplProcessBlock(
  const AInBytes: TCryptoLibByteArray; AInOff: Int32;
  const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
var
  LInP, LOutP, LKeyP: PByte;
begin
  AssertInitialisedAndBlockAligned;
  GenerateKeyStream(FKeyStream);
  AdvanceCounter();
  LInP := PByte(AInBytes) + AInOff;
  LOutP := PByte(AOutBytes) + AOutOff;
  LKeyP := PByte(FKeyStream);
  TByteUtilities.&Xor(64, LInP, LKeyP, LOutP);
end;

procedure TSalsa20Engine.ProcessBlocks2(
  const AInBytes: TCryptoLibByteArray; AInOff: Int32;
  const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  AssertInitialisedAndBlockAligned;
  ProcessBlocks2Fast(PByte(@AInBytes[AInOff]), PByte(@AOutBytes[AOutOff]));
end;

procedure TSalsa20Engine.ProcessBlockFast(AIn, AOut: PByte);
begin
  GenerateKeyStream(FKeyStream);
  AdvanceCounter();
  TByteUtilities.&Xor(64, AIn, PByte(FKeyStream), AOut);
end;

procedure TSalsa20Engine.ProcessBlocks2Fast(AIn, AOut: PByte);
begin
  if TSalsaSimd.TryProcessBlocks2(FRounds, PByte(@FEngineState[0]),
    AIn, AOut) then
    Exit;

  ProcessBlockFast(AIn, AOut);
  ProcessBlockFast(AIn + 64, AOut + 64);
end;

function TSalsa20Engine.DoProcessBlocks(AIn, AOut: PByte;
  ABlockCount: Int32): Int32;
begin
  Result := ABlockCount * 64;
  while ABlockCount >= 2 do
  begin
    ProcessBlocks2Fast(AIn, AOut);
    AIn := AIn + 128;
    AOut := AOut + 128;
    System.Dec(ABlockCount, 2);
  end;
  while ABlockCount >= 1 do
  begin
    ProcessBlockFast(AIn, AOut);
    AIn := AIn + 64;
    AOut := AOut + 64;
    System.Dec(ABlockCount);
  end;
end;

function TSalsa20Engine.ProcessBlocks(const AInBuf: TCryptoLibByteArray;
  AInOff, ABlockCount: Int32; const AOutBuf: TCryptoLibByteArray;
  AOutOff: Int32): Int32;
begin
  AssertInitialisedAndBlockAligned;
  if (ABlockCount <= 0) then
  begin
    Result := 0;
    Exit;
  end;
  if (LimitExceeded(UInt32(ABlockCount) * 64)) then
  begin
    raise EMaxBytesExceededCryptoLibException.CreateRes(@SMaxByteExceeded);
  end;

  Result := DoProcessBlocks(PByte(@AInBuf[AInOff]), PByte(@AOutBuf[AOutOff]),
    ABlockCount);
end;

function TSalsa20Engine.ProcessBlocks(AInput, AOutput: PByte;
  ABlockCount: Int32): Int32;
begin
  AssertInitialisedAndBlockAligned;
  if (ABlockCount <= 0) then
  begin
    Result := 0;
    Exit;
  end;
  if (LimitExceeded(UInt32(ABlockCount) * 64)) then
  begin
    raise EMaxBytesExceededCryptoLibException.CreateRes(@SMaxByteExceeded);
  end;

  Result := DoProcessBlocks(AInput, AOutput, ABlockCount);
end;

class procedure TSalsa20Engine.PackTauOrSigma(AKeyLength: Int32;
  const AState: TCryptoLibUInt32Array);
var
  LTsOff: Int32;
begin
  LTsOff := (AKeyLength div 4) - 4;
  AState[0] := TAU_SIGMA[LTsOff];
  AState[1] := TAU_SIGMA[LTsOff + 1];
  AState[2] := TAU_SIGMA[LTsOff + 2];
  AState[3] := TAU_SIGMA[LTsOff + 3];
end;

procedure TSalsa20Engine.ProcessBytes(const AInBytes: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
var
  LIdx, LTake, LQ: Int32;
  LInP, LOutP, LKeyP: PByte;
begin
  if (not FInitialised) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SEngineNotInitialized, [AlgorithmName]);
  end;

  TCheck.DataLength(AInBytes, AInOff, ALen, SInputBufferTooShort);
  TCheck.OutputLength(AOutBytes, AOutOff, ALen, SOutputBufferTooShort);

  if (LimitExceeded(UInt32(ALen))) then
  begin
    raise EMaxBytesExceededCryptoLibException.CreateRes(@SMaxByteExceeded);
  end;

  while ALen > 0 do
  begin
    if (FIndex <> 0) then
    begin
      LTake := ALen;
      if LTake > (64 - FIndex) then
        LTake := 64 - FIndex;
      for LIdx := 0 to System.Pred(LTake) do
      begin
        AOutBytes[AOutOff + LIdx] := Byte(
          FKeyStream[FIndex + LIdx] xor AInBytes[AInOff + LIdx]);
      end;
      FIndex := (FIndex + LTake) and 63;
      AInOff := AInOff + LTake;
      AOutOff := AOutOff + LTake;
      System.Dec(ALen, LTake);
      continue;
    end;

    if (ALen >= 128) then
    begin
      ProcessBlocks2(AInBytes, AInOff, AOutBytes, AOutOff);
      AInOff := AInOff + 128;
      AOutOff := AOutOff + 128;
      System.Dec(ALen, 128);
      continue;
    end
    else if (ALen >= 64) then
    begin
      ImplProcessBlock(AInBytes, AInOff, AOutBytes, AOutOff);
      AInOff := AInOff + 64;
      AOutOff := AOutOff + 64;
      System.Dec(ALen, 64);
      continue;
    end
    else
    begin
      GenerateKeyStream(FKeyStream);
      AdvanceCounter();
      LTake := ALen;
      LInP := @AInBytes[AInOff];
      LOutP := @AOutBytes[AOutOff];
      LKeyP := @FKeyStream[0];
      LQ := LTake shr 3;
      if LQ > 0 then
        TByteUtilities.&Xor(LQ * 8, LInP, LKeyP, LOutP);
      for LIdx := (LQ * 8) to System.Pred(LTake) do
      begin
        LOutP[LIdx] := LInP[LIdx] xor LKeyP[LIdx];
      end;
      FIndex := (FIndex + LTake) and 63;
      AInOff := AInOff + LTake;
      AOutOff := AOutOff + LTake;
      System.Dec(ALen, LTake);
    end;
  end;
end;

class function TSalsa20Engine.R(AX: UInt32; AY: Int32): UInt32;
begin
  Result := TBitOperations.RotateLeft32(AX, AY);
end;

class procedure TSalsa20Engine.QuarterRound(var A, B, C, D: UInt32);
begin
  B := B xor R(A + D, 7);
  C := C xor R(B + A, 9);
  D := D xor R(C + B, 13);
  A := A xor R(D + C, 18);
end;

procedure TSalsa20Engine.ResetCounter;
begin
  FEngineState[8] := 0;
  FEngineState[9] := 0;
end;

procedure TSalsa20Engine.ResetLimitCounter;
begin
  FCW0 := 0;
  FCW1 := 0;
  FCW2 := 0;
end;

procedure TSalsa20Engine.Reset;
begin
  FIndex := 0;
  ResetLimitCounter();
  ResetCounter();
end;

function TSalsa20Engine.ReturnByte(AInput: Byte): Byte;
var
  LOutput: Byte;
begin
  if (LimitExceeded()) then
  begin
    raise EMaxBytesExceededCryptoLibException.CreateRes(@SMaxByteExceeded);
  end;

  if (FIndex = 0) then
  begin
    GenerateKeyStream(FKeyStream);
    AdvanceCounter();
  end;

  LOutput := Byte(FKeyStream[FIndex] xor AInput);
  FIndex := (FIndex + 1) and 63;

  Result := LOutput;
end;

class procedure TSalsa20Engine.SalsaCore(ARounds: Int32;
  const AInput, AX: TCryptoLibUInt32Array);
var
  LX00, LX01, LX02, LX03, LX04, LX05, LX06, LX07, LX08, LX09, LX10, LX11, LX12, LX13, LX14,
    LX15: UInt32;
  LIdx: Int32;
begin
  if (System.Length(AInput) <> 16) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SInputStateMustBeSixteen);
  end;
  if (System.Length(AX) <> 16) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SOutputStateMustBeSixteen);
  end;
  if ((ARounds mod 2) <> 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SRoundsMustBeEven);
  end;
  if TSalsaSimd.TryCore(ARounds, @AInput[0], @AX[0]) then
    Exit;

  LX00 := AInput[0];
  LX01 := AInput[1];
  LX02 := AInput[2];
  LX03 := AInput[3];
  LX04 := AInput[4];
  LX05 := AInput[5];
  LX06 := AInput[6];
  LX07 := AInput[7];
  LX08 := AInput[8];
  LX09 := AInput[9];
  LX10 := AInput[10];
  LX11 := AInput[11];
  LX12 := AInput[12];
  LX13 := AInput[13];
  LX14 := AInput[14];
  LX15 := AInput[15];

  LIdx := ARounds;
  while LIdx > 0 do
  begin
    QuarterRound(LX00, LX04, LX08, LX12);
    QuarterRound(LX05, LX09, LX13, LX01);
    QuarterRound(LX10, LX14, LX02, LX06);
    QuarterRound(LX15, LX03, LX07, LX11);

    QuarterRound(LX00, LX01, LX02, LX03);
    QuarterRound(LX05, LX06, LX07, LX04);
    QuarterRound(LX10, LX11, LX08, LX09);
    QuarterRound(LX15, LX12, LX13, LX14);

    System.Dec(LIdx, 2);
  end;

  AX[0] := LX00 + AInput[0];
  AX[1] := LX01 + AInput[1];
  AX[2] := LX02 + AInput[2];
  AX[3] := LX03 + AInput[3];
  AX[4] := LX04 + AInput[4];
  AX[5] := LX05 + AInput[5];
  AX[6] := LX06 + AInput[6];
  AX[7] := LX07 + AInput[7];
  AX[8] := LX08 + AInput[8];
  AX[9] := LX09 + AInput[9];
  AX[10] := LX10 + AInput[10];
  AX[11] := LX11 + AInput[11];
  AX[12] := LX12 + AInput[12];
  AX[13] := LX13 + AInput[13];
  AX[14] := LX14 + AInput[14];
  AX[15] := LX15 + AInput[15];

end;

procedure TSalsa20Engine.SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray);
var
  LTsOff: Int32;
begin
  if (AKeyBytes <> nil) then
  begin
    if not(System.Length(AKeyBytes) in [16, 32]) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidKeySize,
        [AlgorithmName]);
    end;

    LTsOff := (System.Length(AKeyBytes) - 16) div 4;
    FEngineState[0] := TAU_SIGMA[LTsOff];
    FEngineState[5] := TAU_SIGMA[LTsOff + 1];
    FEngineState[10] := TAU_SIGMA[LTsOff + 2];
    FEngineState[15] := TAU_SIGMA[LTsOff + 3];

    // Key
    TPack.LE_To_UInt32(AKeyBytes, 0, FEngineState, 1, 4);
    TPack.LE_To_UInt32(AKeyBytes, System.Length(AKeyBytes) - 16, FEngineState, 11, 4);
  end;

  // IV
  TPack.LE_To_UInt32(AIvBytes, 0, FEngineState, 6, 2);
end;

end.
