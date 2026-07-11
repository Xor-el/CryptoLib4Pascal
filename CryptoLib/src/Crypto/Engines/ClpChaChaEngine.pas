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

unit ClpChaChaEngine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCheck,
  ClpIStreamCipher,
  ClpIChaChaEngine,
  ClpSalsa20Engine,
  ClpPack,
  ClpChaChaSimd,
  ClpByteUtilities,
  ClpCryptoLibTypes;

resourcestring
  SChaChaStateWords = 'ChaCha state must be at least 16 UInt32 values';
  SChaChaOut64 = 'ChaCha key stream output must be at least 64 bytes';
  SRoundsEven = 'number of rounds must be even';
  SHChaChaKeyNil = 'HChaCha20 key cannot be nil';
  SHChaChaKey256 = 'HChaCha20 key must be 256 bits';
  SHChaChaNonceNil = 'HChaCha20 nonce cannot be nil';
  SHChaChaNonce128 = 'HChaCha20 nonce must be 128 bits';
  SHChaChaOutNil = 'HChaCha20 output buffer cannot be nil';
  SHChaChaOutSpace = 'HChaCha20 output buffer too short';
  SNotInitialised = '%s not initialized';
  SNotBlockAligned = '%s not in block-aligned state';
  SMaxByteExceeded =
    '2^38 byte limit per IV would be exceeded; change IV';
  SInputBufferTooShort = 'input buffer too short';
  SOutputBufferTooShort = 'output buffer too short';

type

  /// <summary>
  /// Shared ChaCha core (block function + SIMD bulk ladder) for the IETF and DJB
  /// engines; they differ only in counter width (CounterIs64Bit) and key/nonce layout.
  /// </summary>
  TChaChaBaseEngine = class(TSalsa20Engine)

  strict private
    // Pointer-form, unvalidated inner helpers (1 / 2 blocks).
    procedure ProcessBlockFast(AIn, AOut: PByte);
    procedure ProcessBlocks2Fast(AIn, AOut: PByte);
    // One streaming SIMD tier (AGroupBlocks = 8 or 4): clamps to the wrap-safe
    // span, runs the kernel once over every whole group, advances the cursors.
    // False = no SIMD kernel for that width or no safe groups (degrade a tier).
    function TryProcessWide(AGroupBlocks: Int32; var AIn, AOut: PByte;
      var ABlockCount: Int32): Boolean;

  strict protected
    // 8 -> 4 -> 2 -> 1 bulk ladder (widest kernel first).
    function DoProcessBlocks(AIn, AOut: PByte; ABlockCount: Int32): Int32; override;

    // True for the DJB 64-bit counter (words 12-13); False (IETF).
    function CounterIs64Bit: Boolean; virtual;
    // Wide kernels broadcast word 13, valid only while word 12 does not wrap
    // inside the processed span: clamps a span of AGroups x AGroupBlocks
    // blocks to the groups fully before the wrap (identity for IETF).
    function WideGroupsSafe(AGroups, AGroupBlocks: Int32): Int32;

    procedure GenerateKeyStream(const AOutput: TCryptoLibByteArray); override;

  public
    procedure DoFinal(const AInBuf: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);

    procedure ProcessBytes(const AInBytes: TCryptoLibByteArray;
      AInOff, ALen: Int32; const AOutBytes: TCryptoLibByteArray;
      AOutOff: Int32); override;

    procedure ProcessBlock(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);

    class procedure ChaChaCore(ARounds: Int32;
      const AInput: TCryptoLibUInt32Array;
      const AOutput: TCryptoLibByteArray); static;

    /// <summary>
    /// HChaCha20 subkey derivation (draft-irtf-cfrg-xchacha). Writes 32 bytes to ASubKeyOut at ASubKeyOutOff.
    /// </summary>
    class procedure HChaCha20(const AKey256, ANonce128: TCryptoLibByteArray;
      const ASubKeyOut: TCryptoLibByteArray; ASubKeyOutOff: Int32); static;

  end;

  /// <summary>
  /// Implementation of Daniel J. Bernstein's ChaCha stream cipher.
  /// </summary>
  TChaChaEngine = class(TChaChaBaseEngine, IChaChaEngine, IStreamCipher)

  strict protected
    function GetAlgorithmName: String; override;
    function CounterIs64Bit: Boolean; override;

    procedure AdvanceCounter(); override;
    procedure ResetCounter(); override;
    procedure SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray); override;

  public
    /// <summary>
    /// Creates a 20 rounds ChaCha engine.
    /// </summary>
    constructor Create(); overload;
    /// <summary>
    /// Creates a ChaCha engine with a specific number of rounds.
    /// </summary>
    /// <param name="ARounds">the number of rounds (must be an even number).</param>
    constructor Create(ARounds: Int32); overload;

  end;

implementation

{ TChaChaBaseEngine }

function TChaChaBaseEngine.CounterIs64Bit: Boolean;
begin
  Result := False;
end;

function TChaChaBaseEngine.WideGroupsSafe(AGroups, AGroupBlocks: Int32): Int32;
var
  LSafeBlocks: UInt64;
begin
  Result := AGroups;
  if CounterIs64Bit then
  begin
    LSafeBlocks := UInt64($100000000) - FEngineState[12];
    if (UInt64(Result) * UInt32(AGroupBlocks)) > LSafeBlocks then
      Result := Int32(LSafeBlocks div UInt32(AGroupBlocks));
  end;
end;


procedure TChaChaBaseEngine.GenerateKeyStream(const AOutput: TCryptoLibByteArray);
begin
  ChaChaCore(FRounds, FEngineState, AOutput);
end;

procedure TChaChaBaseEngine.DoFinal(const AInBuf: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LIdx, LQ, LWholeBytes: Int32;
begin
  if (not FInitialised) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNotInitialised,
      [AlgorithmName]);
  end;
  if (FIndex <> 0) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNotBlockAligned,
      [AlgorithmName]);
  end;

  TCheck.DataLength(AInBuf, AInOff, AInLen, SInputBufferTooShort);
  TCheck.OutputLength(AOutBuf, AOutOff, AInLen, SOutputBufferTooShort);

  if (AInLen >= 64) then
  begin
    LWholeBytes := (AInLen shr 6) shl 6; // whole 64B blocks, engine ladders 8/4/2/1
    DoProcessBlocks(PByte(@AInBuf[AInOff]), PByte(@AOutBuf[AOutOff]), AInLen shr 6);
    AInOff := AInOff + LWholeBytes;
    AInLen := AInLen - LWholeBytes;
    AOutOff := AOutOff + LWholeBytes;
  end;

  if (AInLen > 0) then
  begin
    GenerateKeyStream(FKeyStream);
    AdvanceCounter();

    LQ := AInLen shr 3;
    if LQ > 0 then
      TByteUtilities.&Xor(LQ * 8, AInBuf, AInOff, FKeyStream, 0, AOutBuf, AOutOff);
    for LIdx := (LQ * 8) to System.Pred(AInLen) do
    begin
      AOutBuf[AOutOff + LIdx] := Byte(
        AInBuf[AInOff + LIdx] xor FKeyStream[LIdx]);
    end;
  end;

  ResetCounter();
end;

procedure TChaChaBaseEngine.ProcessBytes(const AInBytes: TCryptoLibByteArray;
  AInOff, ALen: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
var
  LIdx, LTake, LQ: Int32;
  LInP, LOutP, LKeyP: PByte;
begin
  if (not FInitialised) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt
      (@SNotInitialised, [AlgorithmName]);
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
      begin
        LTake := 64 - FIndex;
      end;
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
    if (ALen >= 64) then
    begin
      LTake := (ALen shr 6) shl 6; // whole 64B blocks; engine ladders 8/4/2/1
      DoProcessBlocks(PByte(@AInBytes[AInOff]), PByte(@AOutBytes[AOutOff]), ALen shr 6);
      AInOff := AInOff + LTake;
      AOutOff := AOutOff + LTake;
      System.Dec(ALen, LTake);
    end
    else
    begin
      GenerateKeyStream(FKeyStream);
      AdvanceCounter();
      LTake := ALen;
      LInP := PByte(AInBytes) + AInOff;
      LOutP := PByte(AOutBytes) + AOutOff;
      LKeyP := PByte(FKeyStream);
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

procedure TChaChaBaseEngine.ProcessBlock(const AInBytes: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
begin
  if (not FInitialised) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNotInitialised,
      [AlgorithmName]);
  end;
  if (FIndex <> 0) then
  begin
    raise EInvalidOperationCryptoLibException.CreateResFmt(@SNotBlockAligned,
      [AlgorithmName]);
  end;
  if (LimitExceeded(UInt32(64))) then
  begin
    raise EMaxBytesExceededCryptoLibException.CreateRes(@SMaxByteExceeded);
  end;

  ImplProcessBlock(AInBytes, AInOff, AOutBytes, AOutOff);
end;

procedure TChaChaBaseEngine.ProcessBlockFast(AIn, AOut: PByte);
begin
  ChaChaCore(FRounds, FEngineState, FKeyStream);
  AdvanceCounter();
  TByteUtilities.&Xor(64, AIn, PByte(FKeyStream), AOut);
end;

procedure TChaChaBaseEngine.ProcessBlocks2Fast(AIn, AOut: PByte);
begin
  if TChaChaSimd.TryProcessBlocks2(FRounds, PByte(@FEngineState[0]),
    AIn, AOut, CounterIs64Bit) then
    Exit;

  ProcessBlockFast(AIn, AOut);
  ProcessBlockFast(AIn + 64, AOut + 64);
end;

function TChaChaBaseEngine.TryProcessWide(AGroupBlocks: Int32;
  var AIn, AOut: PByte; var ABlockCount: Int32): Boolean;
var
  LGroups: Int32;
begin
  Result := False;
  LGroups := WideGroupsSafe(ABlockCount div AGroupBlocks, AGroupBlocks);
  if LGroups = 0 then
    Exit;
  case AGroupBlocks of
    8:
      Result := TChaChaSimd.TryProcessBlocks8(FRounds,
        PByte(@FEngineState[0]), AIn, AOut, LGroups, CounterIs64Bit);
  else
    Result := TChaChaSimd.TryProcessBlocks4(FRounds,
      PByte(@FEngineState[0]), AIn, AOut, LGroups, CounterIs64Bit);
  end;
  if Result then
  begin
    AIn := AIn + LGroups * (AGroupBlocks * 64);
    AOut := AOut + LGroups * (AGroupBlocks * 64);
    System.Dec(ABlockCount, LGroups * AGroupBlocks);
  end;
end;

function TChaChaBaseEngine.DoProcessBlocks(AIn, AOut: PByte;
  ABlockCount: Int32): Int32;
begin
  Result := ABlockCount * 64;
  while ABlockCount >= 8 do
  begin
    // Widest streaming tier that lands, over all safe groups at once.
    if TryProcessWide(8, AIn, AOut, ABlockCount) then
      continue;
    if TryProcessWide(4, AIn, AOut, ABlockCount) then
      continue;
    // No wide SIMD (or at the DJB wrap boundary): one 8-block group via 2/1.
    ProcessBlocks2Fast(AIn, AOut);
    ProcessBlocks2Fast(AIn + 128, AOut + 128);
    ProcessBlocks2Fast(AIn + 256, AOut + 256);
    ProcessBlocks2Fast(AIn + 384, AOut + 384);
    AIn := AIn + 512;
    AOut := AOut + 512;
    System.Dec(ABlockCount, 8);
  end;
  if (ABlockCount >= 4) and (not TryProcessWide(4, AIn, AOut, ABlockCount)) then
  begin
    ProcessBlocks2Fast(AIn, AOut);
    ProcessBlocks2Fast(AIn + 128, AOut + 128);
    AIn := AIn + 256;
    AOut := AOut + 256;
    System.Dec(ABlockCount, 4);
  end;
  if ABlockCount >= 2 then
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

class procedure TChaChaBaseEngine.ChaChaCore(ARounds: Int32;
  const AInput: TCryptoLibUInt32Array; const AOutput: TCryptoLibByteArray);
var
  LX00, LX01, LX02, LX03, LX04, LX05, LX06, LX07, LX08, LX09, LX10, LX11, LX12, LX13, LX14,
    LX15: UInt32;
  LIdx: Int32;
begin
  if (System.Length(AInput) < 16) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SChaChaStateWords);
  end;
  if (System.Length(AOutput) < 64) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SChaChaOut64);
  end;
  if ((ARounds mod 2) <> 0) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SRoundsEven);
  end;
  if TChaChaSimd.TryCore(ARounds, PByte(@AInput[0]), PByte(@AOutput[0])) then
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
    System.Inc(LX00, LX04);
    LX12 := R(LX12 xor LX00, 16);
    System.Inc(LX01, LX05);
    LX13 := R(LX13 xor LX01, 16);
    System.Inc(LX02, LX06);
    LX14 := R(LX14 xor LX02, 16);
    System.Inc(LX03, LX07);
    LX15 := R(LX15 xor LX03, 16);

    System.Inc(LX08, LX12);
    LX04 := R(LX04 xor LX08, 12);
    System.Inc(LX09, LX13);
    LX05 := R(LX05 xor LX09, 12);
    System.Inc(LX10, LX14);
    LX06 := R(LX06 xor LX10, 12);
    System.Inc(LX11, LX15);
    LX07 := R(LX07 xor LX11, 12);

    System.Inc(LX00, LX04);
    LX12 := R(LX12 xor LX00, 8);
    System.Inc(LX01, LX05);
    LX13 := R(LX13 xor LX01, 8);
    System.Inc(LX02, LX06);
    LX14 := R(LX14 xor LX02, 8);
    System.Inc(LX03, LX07);
    LX15 := R(LX15 xor LX03, 8);

    System.Inc(LX08, LX12);
    LX04 := R(LX04 xor LX08, 7);
    System.Inc(LX09, LX13);
    LX05 := R(LX05 xor LX09, 7);
    System.Inc(LX10, LX14);
    LX06 := R(LX06 xor LX10, 7);
    System.Inc(LX11, LX15);
    LX07 := R(LX07 xor LX11, 7);

    System.Inc(LX00, LX05);
    LX15 := R(LX15 xor LX00, 16);
    System.Inc(LX01, LX06);
    LX12 := R(LX12 xor LX01, 16);
    System.Inc(LX02, LX07);
    LX13 := R(LX13 xor LX02, 16);
    System.Inc(LX03, LX04);
    LX14 := R(LX14 xor LX03, 16);

    System.Inc(LX10, LX15);
    LX05 := R(LX05 xor LX10, 12);
    System.Inc(LX11, LX12);
    LX06 := R(LX06 xor LX11, 12);
    System.Inc(LX08, LX13);
    LX07 := R(LX07 xor LX08, 12);
    System.Inc(LX09, LX14);
    LX04 := R(LX04 xor LX09, 12);

    System.Inc(LX00, LX05);
    LX15 := R(LX15 xor LX00, 8);
    System.Inc(LX01, LX06);
    LX12 := R(LX12 xor LX01, 8);
    System.Inc(LX02, LX07);
    LX13 := R(LX13 xor LX02, 8);
    System.Inc(LX03, LX04);
    LX14 := R(LX14 xor LX03, 8);

    System.Inc(LX10, LX15);
    LX05 := R(LX05 xor LX10, 7);
    System.Inc(LX11, LX12);
    LX06 := R(LX06 xor LX11, 7);
    System.Inc(LX08, LX13);
    LX07 := R(LX07 xor LX08, 7);
    System.Inc(LX09, LX14);
    LX04 := R(LX04 xor LX09, 7);

    System.Dec(LIdx, 2);
  end;

  TPack.UInt32_To_LE(LX00 + AInput[0], AOutput, 0);
  TPack.UInt32_To_LE(LX01 + AInput[1], AOutput, 4);
  TPack.UInt32_To_LE(LX02 + AInput[2], AOutput, 8);
  TPack.UInt32_To_LE(LX03 + AInput[3], AOutput, 12);
  TPack.UInt32_To_LE(LX04 + AInput[4], AOutput, 16);
  TPack.UInt32_To_LE(LX05 + AInput[5], AOutput, 20);
  TPack.UInt32_To_LE(LX06 + AInput[6], AOutput, 24);
  TPack.UInt32_To_LE(LX07 + AInput[7], AOutput, 28);
  TPack.UInt32_To_LE(LX08 + AInput[8], AOutput, 32);
  TPack.UInt32_To_LE(LX09 + AInput[9], AOutput, 36);
  TPack.UInt32_To_LE(LX10 + AInput[10], AOutput, 40);
  TPack.UInt32_To_LE(LX11 + AInput[11], AOutput, 44);
  TPack.UInt32_To_LE(LX12 + AInput[12], AOutput, 48);
  TPack.UInt32_To_LE(LX13 + AInput[13], AOutput, 52);
  TPack.UInt32_To_LE(LX14 + AInput[14], AOutput, 56);
  TPack.UInt32_To_LE(LX15 + AInput[15], AOutput, 60);

end;

class procedure TChaChaBaseEngine.HChaCha20(const AKey256, ANonce128: TCryptoLibByteArray;
  const ASubKeyOut: TCryptoLibByteArray; ASubKeyOutOff: Int32);
var
  LState: TCryptoLibUInt32Array;
  LOut: TCryptoLibByteArray;
begin
  if (AKey256 = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SHChaChaKeyNil);
  end;
  if (System.Length(AKey256) <> 32) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SHChaChaKey256);
  end;
  if (ANonce128 = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SHChaChaNonceNil);
  end;
  if (System.Length(ANonce128) <> 16) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SHChaChaNonce128);
  end;
  if (ASubKeyOut = nil) then
  begin
    raise EArgumentNilCryptoLibException.CreateRes(@SHChaChaOutNil);
  end;
  if (System.Length(ASubKeyOut) < ASubKeyOutOff + 32) then
  begin
    raise EArgumentCryptoLibException.CreateRes(@SHChaChaOutSpace);
  end;

  System.SetLength(LState, 16);
  PackTauOrSigma(32, LState);
  TPack.LE_To_UInt32(AKey256, 0, LState, 4, 8);
  TPack.LE_To_UInt32(ANonce128, 0, LState, 12, 4);

  System.SetLength(LOut, 64);
  ChaChaCore(20, LState, LOut);

  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 0) - LState[0], ASubKeyOut, ASubKeyOutOff);
  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 4) - LState[1], ASubKeyOut, ASubKeyOutOff + 4);
  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 8) - LState[2], ASubKeyOut, ASubKeyOutOff + 8);
  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 12) - LState[3], ASubKeyOut, ASubKeyOutOff + 12);
  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 48) - LState[12], ASubKeyOut, ASubKeyOutOff + 16);
  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 52) - LState[13], ASubKeyOut, ASubKeyOutOff + 20);
  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 56) - LState[14], ASubKeyOut, ASubKeyOutOff + 24);
  TPack.UInt32_To_LE(TPack.LE_To_UInt32(LOut, 60) - LState[15], ASubKeyOut, ASubKeyOutOff + 28);
end;

{ TChaChaEngine }

constructor TChaChaEngine.Create;
begin
  Inherited Create();
end;

constructor TChaChaEngine.Create(ARounds: Int32);
begin
  Inherited Create(ARounds);
end;

function TChaChaEngine.CounterIs64Bit: Boolean;
begin
  Result := True;
end;

procedure TChaChaEngine.AdvanceCounter;
begin
  System.Inc(FEngineState[12]);
  if (FEngineState[12] = 0) then
  begin
    System.Inc(FEngineState[13]);
  end;
end;

function TChaChaEngine.GetAlgorithmName: String;
begin
  Result := Format('ChaCha%d', [FRounds]);
end;

procedure TChaChaEngine.ResetCounter;
begin
  FEngineState[12] := 0;
  FEngineState[13] := 0;
end;

procedure TChaChaEngine.SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray);
begin
  if (AKeyBytes <> nil) then
  begin
    if not(System.Length(AKeyBytes) in [16, 32]) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidKeySize,
        [AlgorithmName]);
    end;

    PackTauOrSigma(System.Length(AKeyBytes), FEngineState);

    // Key
    TPack.LE_To_UInt32(AKeyBytes, 0, FEngineState, 4, 4);
    TPack.LE_To_UInt32(AKeyBytes, System.Length(AKeyBytes) - 16, FEngineState, 8, 4);
  end;

  // IV
  TPack.LE_To_UInt32(AIvBytes, 0, FEngineState, 14, 2);
end;

end.
