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

unit AeadModeTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
  ClpIBlockCipher,
  ClpIAeadCipher,
  ClpIAeadParameters,
  ClpAeadParameters,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpICipherParameters,
  ClpISecureRandom,
  ClpSecureRandom,
  ClpAesUtilities,
  ClpAesEngine,
  ClpAesBitSlicedEngine,
  ClpCryptoLibTypes,
  CipherKernelToggle,
  CryptoLibTestBase,
  BlockCipherTestBase;

type
  /// <summary>
  /// Shared scaffolding for the AEAD block-cipher mode suites (GCM, EAX, OCB,
  /// CCM, GCM-SIV). Holds the engine seam used for multi-engine coverage and
  /// the in-place round-trip harness generalised over <c>IAeadCipher</c>.
  /// Concrete suites keep their own published tests and simply delegate the
  /// shared bodies here.
  /// </summary>
  // A worker rerun once per engine by ForEachExtraEngine.
  TAeadEngineProc = procedure of object;

  TAeadModeTestBase = class abstract(TCryptoLibAlgorithmTestCase)
  strict protected
    // The block-cipher engine factory the current pass builds its mode over.
    // nil => the default AES engine (hardware if available, else scalar).
    FEngineFactory: TBlockCipherFactory;
    // Human label for the engine of the current pass (for failure messages).
    FCurrentEngineLabel: String;

    // The engine for the current pass. Concrete CreateAeadCipher builds its
    // mode over this (OCB calls it twice, for the hash and main ciphers).
    function CurrentEngine: IBlockCipher;

    // Rerun AProc once per NON-default AES engine: the constant-time bit-sliced
    // engine always, and the explicit scalar engine only when the default
    // (utilities) engine is hardware-accelerated (otherwise it already IS the
    // scalar engine, so running it again would be pure duplication). The
    // default-engine pass, and any kernel-toggle sweep, are the caller's job.
    procedure ForEachExtraEngine(AProc: TAeadEngineProc);

    // Build a fresh mode cipher over CurrentEngine. Supplied by the suite.
    function CreateAeadCipher: IAeadCipher; virtual; abstract;
    // Short human label for failure messages (e.g. 'GCM', 'EAX').
    function ModeLabel: String; virtual; abstract;

    // One in-place (output buffer aliases input) round-trip at a single length.
    // Returns '' on success, else a short description of the failing direction.
    function RunInPlaceCase(const ARandom: ISecureRandom;
      APlainLen, AKeyLen: Int32; const AAad: TBytes): String;

    // Drive RunInPlaceCase across ALens, once with a 16-byte key and no AAD and
    // once with a 32-byte key and 20 bytes of AAD, from a fixed seed.
    procedure DoInPlaceSweep(const ALens: array of Int32; ASeed: Int64);

    // One streaming-equivalence case at a single plaintext length: feed the
    // message through ProcessBytes in many chunk sizes and assert, for both
    // directions and both out-of-place and in-place, that the concatenated
    // output equals the one-shot result AND the summed per-call Result values
    // (+ DoFinal) equal the total. Returns '' on success, else a description.
    function RunStreamingCase(const ARandom: ISecureRandom;
      APlainLen, AKeyLen: Int32; const AAad: TBytes): String;

    // Drive RunStreamingCase across ALens x {16-byte key/no AAD, 32-byte key/AAD}.
    procedure DoStreamingSweep(const ALens: array of Int32; ASeed: Int64);

    // Parameterless worker (fixed lengths + seed) for the engine / kernel sweeps.
    procedure DoTestStreaming;
  published
    // Chunk-boundary safety net for ProcessBytes: runs the streaming sweep under
    // the kernel on/off toggle and across the extra engines (bit-sliced soft-bulk
    // + scalar), so every dispatch tier is exercised. Inherited by every suite.
    procedure TestStreamingEquivalence;
  end;

implementation

// Standalone factories: TBlockCipherFactory is a plain function pointer and
// cannot capture an engine-table index, so each engine gets its own function.
function AeadEngineScalar: IBlockCipher;
begin
  Result := TAesEngine.Create();
end;

function AeadEngineBitSliced: IBlockCipher;
begin
  Result := TAesBitSlicedEngine.Create();
end;

{ TAeadModeTestBase }

function TAeadModeTestBase.CurrentEngine: IBlockCipher;
begin
  if Assigned(FEngineFactory) then
    Result := FEngineFactory()
  else
    Result := TAesUtilities.CreateEngine();
end;

procedure TAeadModeTestBase.ForEachExtraEngine(AProc: TAeadEngineProc);
var
  LSavedFactory: TBlockCipherFactory;
  LSavedLabel: String;
begin
  LSavedFactory := FEngineFactory;
  LSavedLabel := FCurrentEngineLabel;
  try
    FEngineFactory := AeadEngineBitSliced;
    FCurrentEngineLabel := 'bit-sliced';
    AProc();

    if TAesUtilities.IsHardwareAccelerated() then
    begin
      FEngineFactory := AeadEngineScalar;
      FCurrentEngineLabel := 'scalar';
      AProc();
    end;
  finally
    FEngineFactory := LSavedFactory;
    FCurrentEngineLabel := LSavedLabel;
  end;
end;

function TAeadModeTestBase.RunInPlaceCase(const ARandom: ISecureRandom;
  APlainLen, AKeyLen: Int32; const AAad: TBytes): String;
var
  LK, LIV, LP, LRef, LBuf: TBytes;
  LParams: IAeadParameters;
  LCipher: IAeadCipher;
  LLen, LTotal: Int32;
begin
  Result := '';
  System.SetLength(LK, AKeyLen);
  ARandom.NextBytes(LK);
  System.SetLength(LIV, 12);
  ARandom.NextBytes(LIV);
  System.SetLength(LP, APlainLen);
  if APlainLen > 0 then
    ARandom.NextBytes(LP);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LIV, AAad);

  // Reference ciphertext||tag, produced out of place.
  LCipher := CreateAeadCipher;
  LCipher.Init(True, LParams as ICipherParameters);
  System.SetLength(LRef, LCipher.GetOutputSize(APlainLen));
  LLen := LCipher.ProcessBytes(LP, 0, APlainLen, LRef, 0);
  LLen := LLen + LCipher.DoFinal(LRef, LLen);
  System.SetLength(LRef, LLen);
  LTotal := LLen;

  // In-place encrypt: the buffer starts as plaintext and is encrypted over itself.
  System.SetLength(LBuf, LTotal);
  if APlainLen > 0 then
    System.Move(LP[0], LBuf[0], APlainLen);
  LCipher := CreateAeadCipher;
  LCipher.Init(True, LParams as ICipherParameters);
  try
    LLen := LCipher.ProcessBytes(LBuf, 0, APlainLen, LBuf, 0);
    LLen := LLen + LCipher.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[enc len=%d exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if (LLen <> LTotal) or (not AreEqual(LBuf, LRef)) then
  begin
    Result := Format('[enc len=%d mismatch] ', [APlainLen]);
    Exit;
  end;

  // In-place decrypt: the buffer starts as ciphertext||tag, decrypted over itself.
  System.SetLength(LBuf, LTotal);
  System.Move(LRef[0], LBuf[0], LTotal);
  LCipher := CreateAeadCipher;
  LCipher.Init(False, LParams as ICipherParameters);
  try
    LLen := LCipher.ProcessBytes(LBuf, 0, LTotal, LBuf, 0);
    LLen := LLen + LCipher.DoFinal(LBuf, LLen);
  except
    on E: Exception do
    begin
      Result := Format('[dec len=%d exc %s] ', [APlainLen, E.Message]);
      Exit;
    end;
  end;
  if LLen <> APlainLen then
  begin
    Result := Format('[dec len=%d got %d] ', [APlainLen, LLen]);
    Exit;
  end;
  System.SetLength(LBuf, LLen);
  if (APlainLen > 0) and (not AreEqual(LBuf, LP)) then
    Result := Format('[dec len=%d mismatch] ', [APlainLen]);
end;

procedure TAeadModeTestBase.DoInPlaceSweep(const ALens: array of Int32;
  ASeed: Int64);
var
  LRnd: ISecureRandom;
  LFails: String;
  LI: Int32;
  LAad: TBytes;
begin
  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(ASeed);
  System.SetLength(LAad, 20);
  LRnd.NextBytes(LAad);
  LFails := '';
  for LI := 0 to High(ALens) do
    LFails := LFails + RunInPlaceCase(LRnd, ALens[LI], 16, nil);
  for LI := 0 to High(ALens) do
    LFails := LFails + RunInPlaceCase(LRnd, ALens[LI], 32, LAad);
  if LFails <> '' then
  begin
    if FCurrentEngineLabel <> '' then
      Fail(Format('in-place %s [%s]: %s', [ModeLabel, FCurrentEngineLabel, LFails]))
    else
      Fail(Format('in-place %s: %s', [ModeLabel, LFails]));
  end;
end;

function TAeadModeTestBase.RunStreamingCase(const ARandom: ISecureRandom;
  APlainLen, AKeyLen: Int32; const AAad: TBytes): String;
const
  CChunks: array [0 .. 9] of Int32 = (1, 7, 15, 16, 17, 31, 63, 64, 65, 1048576);
var
  LK, LIV, LP, LRefCt, LOut: TBytes;
  LParams: IAeadParameters;
  LRefLen, LCi, LN, LMode: Int32;
  LInPlace: Boolean;

  // Stream AInLen bytes of AIn through a fresh cipher (direction AEnc) in
  // AChunk-sized pieces; return the total produced (summed ProcessBytes Results
  // + DoFinal), with the truncated output in AOut. AInPlace => a single buffer
  // holds the input and is written over itself (output cursor trails input).
  function Stream(AEnc: Boolean; const AIn: TBytes; AInLen, AChunk: Int32;
    AInPlace: Boolean; out AOut: TBytes): Int32;
  var
    LCipher: IAeadCipher;
    LBuf: TBytes;
    LOff, LInOff, LCs, LCap: Int32;
  begin
    LCipher := CreateAeadCipher;
    LCipher.Init(AEnc, LParams as ICipherParameters);
    LCap := LCipher.GetOutputSize(AInLen);
    // In-place: one buffer must hold BOTH the input and the (possibly larger on
    // encrypt) output; decrypt output is smaller but the input is bigger.
    if AInPlace and (AInLen > LCap) then
      LCap := AInLen;
    System.SetLength(LBuf, LCap);
    if AInPlace and (AInLen > 0) then
      System.Move(AIn[0], LBuf[0], AInLen);

    LOff := 0;
    LInOff := 0;
    while LInOff < AInLen do
    begin
      LCs := AInLen - LInOff;
      if LCs > AChunk then
        LCs := AChunk;
      if AInPlace then
        LOff := LOff + LCipher.ProcessBytes(LBuf, LInOff, LCs, LBuf, LOff)
      else
        LOff := LOff + LCipher.ProcessBytes(AIn, LInOff, LCs, LBuf, LOff);
      LInOff := LInOff + LCs;
    end;
    LOff := LOff + LCipher.DoFinal(LBuf, LOff);
    System.SetLength(LBuf, LOff);
    AOut := LBuf;
    Result := LOff;
  end;

begin
  Result := '';
  System.SetLength(LK, AKeyLen);
  ARandom.NextBytes(LK);
  System.SetLength(LIV, 12);
  ARandom.NextBytes(LIV);
  System.SetLength(LP, APlainLen);
  if APlainLen > 0 then
    ARandom.NextBytes(LP);
  LParams := TAeadParameters.Create(TKeyParameter.Create(LK) as IKeyParameter,
    16 * 8, LIV, AAad);

  // One-shot reference ciphertext||tag.
  LRefLen := Stream(True, LP, APlainLen, 1048576, False, LRefCt);

  for LCi := 0 to High(CChunks) do
    for LMode := 0 to 1 do
    begin
      LInPlace := LMode = 1;

      // Encrypt: chunked output+tag must equal the one-shot reference, and the
      // summed Result values must total the reference length.
      LN := Stream(True, LP, APlainLen, CChunks[LCi], LInPlace, LOut);
      if LN <> LRefLen then
        Exit(Format('[enc len=%d chunk=%d inplace=%d total=%d want=%d] ',
          [APlainLen, CChunks[LCi], LMode, LN, LRefLen]));
      if not AreEqual(LOut, LRefCt) then
        Exit(Format('[enc len=%d chunk=%d inplace=%d ct-mismatch] ',
          [APlainLen, CChunks[LCi], LMode]));

      // Decrypt: chunked recovery must equal the plaintext, total = APlainLen.
      LN := Stream(False, LRefCt, LRefLen, CChunks[LCi], LInPlace, LOut);
      if LN <> APlainLen then
        Exit(Format('[dec len=%d chunk=%d inplace=%d got=%d] ',
          [APlainLen, CChunks[LCi], LMode, LN]));
      if (APlainLen > 0) and (not AreEqual(LOut, LP)) then
        Exit(Format('[dec len=%d chunk=%d inplace=%d pt-mismatch] ',
          [APlainLen, CChunks[LCi], LMode]));
    end;
end;

procedure TAeadModeTestBase.DoStreamingSweep(const ALens: array of Int32;
  ASeed: Int64);
var
  LRnd: ISecureRandom;
  LFails: String;
  LI: Int32;
  LAad: TBytes;
begin
  LRnd := TSecureRandom.Create();
  LRnd.SetSeed(ASeed);
  System.SetLength(LAad, 20);
  LRnd.NextBytes(LAad);
  LFails := '';
  for LI := 0 to High(ALens) do
    LFails := LFails + RunStreamingCase(LRnd, ALens[LI], 16, nil);
  for LI := 0 to High(ALens) do
    LFails := LFails + RunStreamingCase(LRnd, ALens[LI], 32, LAad);
  if LFails <> '' then
  begin
    if FCurrentEngineLabel <> '' then
      Fail(Format('streaming %s [%s]: %s',
        [ModeLabel, FCurrentEngineLabel, LFails]))
    else
      Fail(Format('streaming %s: %s', [ModeLabel, LFails]));
  end;
end;

procedure TAeadModeTestBase.DoTestStreaming;
const
  CLens: array [0 .. 9] of Int32 = (0, 1, 16, 17, 63, 64, 65, 4 * 16 + 7,
    17 * 16 + 9, 200);
begin
  DoStreamingSweep(CLens, Int64(20260727));
end;

procedure TAeadModeTestBase.TestStreamingEquivalence;
begin
  DoTestStreaming;
  RunWithCipherKernelToggle(DoTestStreaming);
  ForEachExtraEngine(DoTestStreaming);
end;

end.
