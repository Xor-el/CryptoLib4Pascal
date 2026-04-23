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

unit ClpChaCha7539Engine;

{$I ..\..\Include\CryptoLib.inc}

interface

uses
  SysUtils,
  ClpCheck,
  ClpIStreamCipher,
  ClpIChaCha7539Engine,
  ClpSalsa20Engine,
  ClpChaChaEngine,
  ClpPack,
  ClpCryptoLibTypes,
  ClpCpuFeatures;

resourcestring
  SInvalidKeySize256 = '%s Requires 256 bit key';
  SCounterExceeded = 'Attempt to Increase Counter Past 2^32.';
  SNotInitialised = '%s not Initialized';
  SNotBlockAligned = '%s not in Block-Aligned State';
  SMaxByteExceeded38 =
    '2^38 Byte Limit per IV Would be Exceeded; Change IV';
  SInputBufferTooShort = 'Input Buffer too Short';
  SOutputBufferTooShort = 'Output Buffer too Short';

type

  TChaCha7539Engine = class(TSalsa20Engine, IChaCha7539Engine, IStreamCipher)

  strict protected
    function GetAlgorithmName: String; override;
    function GetNonceSize: Int32; override;

    procedure AdvanceCounter(); override;
    procedure ResetCounter(); override;
    procedure SetKey(const AKeyBytes, AIvBytes: TCryptoLibByteArray); override;
    procedure GenerateKeyStream(const AOutput: TCryptoLibByteArray); override;

  strict private
    procedure ImplProcessBlock(const AInBuf: TCryptoLibByteArray; AInOff: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32); inline;

  public
    constructor Create();

    procedure DoFinal(const AInBuf: TCryptoLibByteArray; AInOff, AInLen: Int32;
      const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);

    procedure ProcessBlock(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);

    procedure ProcessBlocks2(const AInBytes: TCryptoLibByteArray; AInOff: Int32;
      const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);

  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
procedure ChaCha7539ProcessBlocks2Avx2(ARounds: Int32; AState, AIn, AOut: PByte);
{$I ..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha7539ProcessBlocks2Avx2_x86_64.inc}
end;
{$ENDIF}

procedure ChaCha7539BlockSse2(ARounds: Int32; AState, AKeyStream: PByte);
{$IFDEF CRYPTOLIB_X86_64_ASM}
{$I ..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha20BlockSse2_x86_64.inc}
{$ENDIF}
{$IFDEF CRYPTOLIB_I386_ASM}
{$I ..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
{$I ..\..\Include\Simd\ChaCha\ChaCha20BlockSse2_i386.inc}
{$ENDIF}
end;
{$ENDIF}

{ TChaCha7539Engine }

constructor TChaCha7539Engine.Create;
begin
  inherited Create();
end;

function TChaCha7539Engine.GetAlgorithmName: String;
begin
  Result := 'ChaCha7539';
end;

function TChaCha7539Engine.GetNonceSize: Int32;
begin
  Result := 12;
end;

procedure TChaCha7539Engine.AdvanceCounter;
begin
  System.Inc(FEngineState[12]);
  if (FEngineState[12] = 0) then
  begin
    raise EInvalidOperationCryptoLibException.CreateRes(@SCounterExceeded);
  end;
end;

procedure TChaCha7539Engine.ResetCounter;
begin
  FEngineState[12] := 0;
end;

procedure TChaCha7539Engine.SetKey(const AKeyBytes,
  AIvBytes: TCryptoLibByteArray);
begin
  if (AKeyBytes <> nil) then
  begin
    if (System.Length(AKeyBytes) <> 32) then
    begin
      raise EArgumentCryptoLibException.CreateResFmt(@SInvalidKeySize256,
        [AlgorithmName]);
    end;

    PackTauOrSigma(System.Length(AKeyBytes), FEngineState, 0);

    // Key
    TPack.LE_To_UInt32(AKeyBytes, 0, FEngineState, 4, 8);
  end;

  // IV
  TPack.LE_To_UInt32(AIvBytes, 0, FEngineState, 13, 3);
end;

procedure TChaCha7539Engine.GenerateKeyStream(
  const AOutput: TCryptoLibByteArray);
begin
  TChaChaEngine.ChaChaCore(FRounds, FEngineState, AOutput);
end;

procedure TChaCha7539Engine.DoFinal(const AInBuf: TCryptoLibByteArray;
  AInOff, AInLen: Int32; const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LIdx: Int32;
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

  while (AInLen >= 128) do
  begin
    ProcessBlocks2(AInBuf, AInOff, AOutBuf, AOutOff);
    AInOff := AInOff + 128;
    AInLen := AInLen - 128;
    AOutOff := AOutOff + 128;
  end;

  if (AInLen >= 64) then
  begin
    ImplProcessBlock(AInBuf, AInOff, AOutBuf, AOutOff);
    AInOff := AInOff + 64;
    AInLen := AInLen - 64;
    AOutOff := AOutOff + 64;
  end;

  if (AInLen > 0) then
  begin
    GenerateKeyStream(FKeyStream);
    AdvanceCounter();

    for LIdx := 0 to System.Pred(AInLen) do
    begin
      AOutBuf[AOutOff + LIdx] := Byte(AInBuf[LIdx + AInOff] xor FKeyStream[LIdx]);
    end;
  end;

  FEngineState[12] := 0;
end;

procedure TChaCha7539Engine.ProcessBlock(const AInBytes: TCryptoLibByteArray;
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
    raise EMaxBytesExceededCryptoLibException.CreateRes(@SMaxByteExceeded38);
  end;

  ImplProcessBlock(AInBytes, AInOff, AOutBytes, AOutOff);
end;

procedure TChaCha7539Engine.ProcessBlocks2(const AInBytes: TCryptoLibByteArray;
  AInOff: Int32; const AOutBytes: TCryptoLibByteArray; AOutOff: Int32);
var
  LIdx: Int32;
  LK: array[0..63] of Byte;
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
  if (LimitExceeded(UInt32(128))) then
  begin
    raise EMaxBytesExceededCryptoLibException.CreateRes(@SMaxByteExceeded38);
  end;
{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_X86_64_ASM}
  if TCpuFeatures.X86.HasAVX2() then
  begin
    ChaCha7539ProcessBlocks2Avx2(FRounds, PByte(@FEngineState[0]), PByte(@AInBytes[AInOff]),
      PByte(@AOutBytes[AOutOff]));
    Exit;
  end;
{$ENDIF}
  if TCpuFeatures.X86.HasSSE2() then
  begin
    ChaCha7539BlockSse2(FRounds, PByte(@FEngineState[0]), @LK[0]);
    for LIdx := 0 to 63 do
    begin
      AOutBytes[AOutOff + LIdx] := Byte(LK[LIdx] xor AInBytes[AInOff + LIdx]);
    end;
    AdvanceCounter();
    ChaCha7539BlockSse2(FRounds, PByte(@FEngineState[0]), @LK[0]);
    for LIdx := 0 to 63 do
    begin
      AOutBytes[AOutOff + 64 + LIdx] := Byte(
        LK[LIdx] xor AInBytes[AInOff + 64 + LIdx]);
    end;
    AdvanceCounter();
    Exit;
  end;
{$ENDIF}
  ImplProcessBlock(AInBytes, AInOff, AOutBytes, AOutOff);
  ImplProcessBlock(AInBytes, AInOff + 64, AOutBytes, AOutOff + 64);
end;

procedure TChaCha7539Engine.ImplProcessBlock(
  const AInBuf: TCryptoLibByteArray; AInOff: Int32;
  const AOutBuf: TCryptoLibByteArray; AOutOff: Int32);
var
  LIdx: Int32;
begin
  TChaChaEngine.ChaChaCore(FRounds, FEngineState, FKeyStream);
  AdvanceCounter();

  for LIdx := 0 to 63 do
  begin
    AOutBuf[AOutOff + LIdx] := Byte(FKeyStream[LIdx] xor AInBuf[AInOff + LIdx]);
  end;
end;

end.
