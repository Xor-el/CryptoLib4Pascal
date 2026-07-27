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

{ dudect statistical timing leak detector (Reparaz, Balasch, Verbauwhede 2017).

  Two input classes, interleaved in random order so class never correlates with
  drift/thermal state:
    class 0 = a FIXED secret (same value every sample),
    class 1 = a FRESH RANDOM secret per sample.
  Each sample times one operation and pushes the raw tick delta into the class it
  belongs to. Per-class stats are kept online with Welford's algorithm (no sample
  storage). Tail latencies (scheduler/interrupts) are handled by percentile
  cropping: several crop thresholds are derived from a warmup histogram, a Welch
  t-test is computed per crop, and the reported statistic is max |t| over crops.

  Decision: |t| > 4.5  =>  a data-dependent timing difference was detected (the
  dudect canonical threshold, ~1e-5 false positive at these sample sizes). A
  subject that keeps |t| < 4.5 as the sample count grows is reported clean; a
  known-leaky control MUST cross 4.5 or the run is not sensitive (INVALID).

  This is a benchmark/diagnostic tool: it measures, it is not part of the library. }

unit ClpDudect;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  SysUtils;

const
  DUDECT_THRESHOLD = Double(4.5);
  // Percentile crops span median->far-tail (canonical dudect uses ~100; the last
  // crop is a no-crop). More crops = more sensitive to distribution-shape leaks
  // (e.g. cache-timing, where the mean barely moves but the tail does).
  DUDECT_NUM_CROPS = Int32(13);

type
  { Deterministic SplitMix64 stream - reproducible fixed-vs-random draws. Not a
    CSPRNG; it only needs to be unbiased and seedable for the class coin and the
    class-1 (random) secrets. The seed is recorded in every result. }
  TCtRandom = record
  strict private
    FState: UInt64;
  public
    class function Create(ASeed: UInt64): TCtRandom; static;
    function NextUInt64: UInt64;
    function NextByte: Byte;
    function NextBit: Boolean;
    procedure NextBytes(var ABuf: TBytes; AOff, ALen: Int32);
  end;

  { A single measured operation. PrepareSecret builds the class-0 (fixed) or
    class-1 (random) secret and does any secret-dependent setup that is NOT the
    thing under test (e.g. an AES key schedule); it is untimed. RunOp performs the
    exact primitive being measured, using the secret prepared by the last
    PrepareSecret call; only RunOp is timed. Both classes go through the identical
    RunOp call shape so only the secret's value differs. }
  TDudectOp = class abstract(TObject)
  public
    procedure PrepareSecret(AClass: Int32); virtual; abstract;
    procedure RunOp; virtual; abstract;

    { Optional taint-tracking (ctgrind/Valgrind) support. A subject overrides
      these when its secret is a contiguous byte buffer that flows directly into
      the measured routine (no non-constant-time preprocessing in between), so
      the memory can be marked undefined, the routine run, and the output
      re-defined. Default: not poisonable (SecretLen = 0). }
    function PoisonSupported: Boolean; virtual;
    function SecretPtr: Pointer; virtual;
    function SecretLen: Int32; virtual;
    function OutputPtr: Pointer; virtual;
    function OutputLen: Int32; virtual;
    { Runs the full secret-dependent routine from the (possibly poisoned) secret
      buffer to the output buffer. Default: PrepareSecret is assumed already done
      and this just calls RunOp; override when the routine must re-consume the
      secret bytes (e.g. an AES key schedule) so the whole path is under taint. }
    procedure RunPoisonedRoutine; virtual;
  end;

  TDudectConfig = record
    WarmupSamples: Int64;        // discarded from stats; used only for crop thresholds
    BatchSamples: Int64;         // first checkpoint interval (then doubles)
    MaxSamples: Int64;           // hard cap on measured samples
    MinSamplesForDecision: Int64;// no early "leak" verdict before this many samples
    Threshold: Double;           // |t| leak threshold (default 4.5)
    Seed: UInt64;
    class function Default: TDudectConfig; static;
  end;

  TDudectResult = record
    MaxT: Double;                // max |t| over crops at the final sample count
    CropPercentile: Double;      // crop that produced MaxT (1.0 = no crop)
    NA, NB: Int64;               // per-class sample counts at the winning crop
    TotalSamples: Int64;
    Threshold: Double;
    Leaky: Boolean;              // MaxT > Threshold
    OpNanos: UInt64;             // rough per-op time (warmup median) for context
    Seed: UInt64;
  end;

  // Optional progress callback fired at each (doubling) checkpoint.
  TDudectProgress = procedure(ATotalSamples: Int64; AMaxT: Double; ALeaky: Boolean);

  TDudect = class sealed(TObject)
  public
    class function Run(const AOp: TDudectOp; const AConfig: TDudectConfig;
      AProgress: TDudectProgress = nil): TDudectResult; static;
  end;

implementation

uses
  Math,
  ClpCtClock;

// Canonical dudect percentile for crop LK of LN crops: 1 - 0.5^(10*(LK+1)/LN),
// giving a spread of thresholds from about the median to the far tail.
function CropPercentile(ALK, ACount: Int32): Double;
begin
  Result := 1.0 - Power(0.5, (10.0 * (ALK + 1)) / ACount);
end;

{ TCtRandom }

class function TCtRandom.Create(ASeed: UInt64): TCtRandom;
begin
  Result.FState := ASeed;
end;

function TCtRandom.NextUInt64: UInt64;
var
  LZ: UInt64;
begin
  FState := FState + UInt64($9E3779B97F4A7C15);
  LZ := FState;
  LZ := (LZ xor (LZ shr 30)) * UInt64($BF58476D1CE4E5B9);
  LZ := (LZ xor (LZ shr 27)) * UInt64($94D049BB133111EB);
  LZ := LZ xor (LZ shr 31);
  Result := LZ;
end;

function TCtRandom.NextByte: Byte;
begin
  Result := Byte(NextUInt64);
end;

function TCtRandom.NextBit: Boolean;
begin
  Result := (NextUInt64 and UInt64(1)) <> 0;
end;

procedure TCtRandom.NextBytes(var ABuf: TBytes; AOff, ALen: Int32);
var
  LI: Int32;
  LWord: UInt64;
  LShift: Int32;
begin
  LWord := 0;
  LShift := 0;
  for LI := 0 to ALen - 1 do
  begin
    if LShift = 0 then
    begin
      LWord := NextUInt64;
      LShift := 8;
    end;
    ABuf[AOff + LI] := Byte(LWord);
    LWord := LWord shr 8;
    Dec(LShift);
  end;
end;

{ TDudectOp - default (non-poisonable) taint hooks }

function TDudectOp.PoisonSupported: Boolean;
begin
  Result := SecretLen > 0;
end;

function TDudectOp.SecretPtr: Pointer;
begin
  Result := nil;
end;

function TDudectOp.SecretLen: Int32;
begin
  Result := 0;
end;

function TDudectOp.OutputPtr: Pointer;
begin
  Result := nil;
end;

function TDudectOp.OutputLen: Int32;
begin
  Result := 0;
end;

procedure TDudectOp.RunPoisonedRoutine;
begin
  RunOp;
end;

{ TDudectConfig }

class function TDudectConfig.Default: TDudectConfig;
begin
  Result.WarmupSamples := 10000;
  Result.BatchSamples := 100000;
  Result.MaxSamples := 2000000;
  Result.MinSamplesForDecision := 100000;
  Result.Threshold := DUDECT_THRESHOLD;
  Result.Seed := UInt64($C0FFEE123456789A);
end;

{ small in-place quicksort over UInt64 (warmup percentiles only) }

procedure SortU64(var A: array of UInt64; ALo, AHi: Int32);
var
  LI, LJ: Int32;
  LPivot, LTmp: UInt64;
begin
  if ALo >= AHi then
    Exit;
  LI := ALo;
  LJ := AHi;
  LPivot := A[(ALo + AHi) shr 1];
  repeat
    while A[LI] < LPivot do
      Inc(LI);
    while A[LJ] > LPivot do
      Dec(LJ);
    if LI <= LJ then
    begin
      LTmp := A[LI];
      A[LI] := A[LJ];
      A[LJ] := LTmp;
      Inc(LI);
      Dec(LJ);
    end;
  until LI > LJ;
  SortU64(A, ALo, LJ);
  SortU64(A, LI, AHi);
end;

{ TDudect }

class function TDudect.Run(const AOp: TDudectOp; const AConfig: TDudectConfig;
  AProgress: TDudectProgress): TDudectResult;
var
  LRnd: TCtRandom;
  LWarm: array of UInt64;
  LThresh: array [0 .. DUDECT_NUM_CROPS - 1] of UInt64;
  LPctl: array [0 .. DUDECT_NUM_CROPS - 1] of Double;
  // Welford accumulators [crop][class].
  LN: array [0 .. DUDECT_NUM_CROPS - 1, 0 .. 1] of Int64;
  LMean: array [0 .. DUDECT_NUM_CROPS - 1, 0 .. 1] of Double;
  LM2: array [0 .. DUDECT_NUM_CROPS - 1, 0 .. 1] of Double;
  LI, LK: Int32;
  LClass: Int32;
  LT0, LT1, LDelta: UInt64;
  LDeltaF: Double;
  LTotal, LNextCheckpoint: Int64;
  LMaxT, LT, LWinPctl: Double;
  LWinCrop: Int32;
  LnA, LnB: Int64;
  LvA, LvB, LDenom, LDVal: Double;
  LWarmCount: Int64;

  procedure Push(ACrop, AClass: Int32; ADeltaVal: Double);
  var
    LNi: Int64;
    LDlt: Double;
  begin
    Inc(LN[ACrop, AClass]);
    LNi := LN[ACrop, AClass];
    LDlt := ADeltaVal - LMean[ACrop, AClass];
    LMean[ACrop, AClass] := LMean[ACrop, AClass] + (LDlt / LNi);
    LM2[ACrop, AClass] := LM2[ACrop, AClass] +
      (LDlt * (ADeltaVal - LMean[ACrop, AClass]));
  end;

begin
  LRnd := TCtRandom.Create(AConfig.Seed);

  // Reset accumulators.
  for LK := 0 to DUDECT_NUM_CROPS - 1 do
  begin
    LN[LK, 0] := 0;
    LN[LK, 1] := 0;
    LMean[LK, 0] := 0;
    LMean[LK, 1] := 0;
    LM2[LK, 0] := 0;
    LM2[LK, 1] := 0;
  end;

  // --- Warmup: collect a timing histogram to derive crop thresholds. ---
  LWarmCount := AConfig.WarmupSamples;
  if LWarmCount < 100 then
    LWarmCount := 100;
  System.SetLength(LWarm, LWarmCount);
  for LI := 0 to LWarmCount - 1 do
  begin
    if LRnd.NextBit then
      LClass := 1
    else
      LClass := 0;
    AOp.PrepareSecret(LClass);
    LT0 := TCtClock.TicksNow;
    AOp.RunOp;
    LT1 := TCtClock.TicksNow;
    LWarm[LI] := LT1 - LT0;
  end;

  SortU64(LWarm, 0, System.Length(LWarm) - 1);
  for LK := 0 to DUDECT_NUM_CROPS - 1 do
  begin
    if LK = DUDECT_NUM_CROPS - 1 then
    begin
      LPctl[LK] := 1.0;
      LThresh[LK] := High(UInt64); // last test keeps every sample (no crop)
    end
    else
    begin
      LPctl[LK] := CropPercentile(LK, DUDECT_NUM_CROPS - 1);
      LThresh[LK] := LWarm[Trunc(LPctl[LK] * (System.Length(LWarm) - 1))];
    end;
  end;

  // Rough per-op time for the report (median of warmup).
  Result.OpNanos := TCtClock.TicksToNanos(LWarm[System.Length(LWarm) shr 1]);

  // --- Measurement: interleaved classes, online stats, doubling checkpoints. ---
  LTotal := 0;
  LNextCheckpoint := AConfig.BatchSamples;
  if LNextCheckpoint < 1 then
    LNextCheckpoint := 1;
  LMaxT := 0;
  LWinCrop := DUDECT_NUM_CROPS - 1;
  LWinPctl := 1.0;

  while LTotal < AConfig.MaxSamples do
  begin
    if LRnd.NextBit then
      LClass := 1
    else
      LClass := 0;
    AOp.PrepareSecret(LClass);
    LT0 := TCtClock.TicksNow;
    AOp.RunOp;
    LT1 := TCtClock.TicksNow;
    LDelta := LT1 - LT0;

    LDeltaF := LDelta; // numeric UInt64->Double conversion (NOT a Double(...) bit-cast)
    for LK := 0 to DUDECT_NUM_CROPS - 1 do
      if LDelta <= LThresh[LK] then
        Push(LK, LClass, LDeltaF);

    Inc(LTotal);

    if LTotal >= LNextCheckpoint then
    begin
      // max |t| over crops with enough samples in both classes.
      LMaxT := 0;
      LWinCrop := DUDECT_NUM_CROPS - 1;
      for LK := 0 to DUDECT_NUM_CROPS - 1 do
      begin
        LnA := LN[LK, 0];
        LnB := LN[LK, 1];
        if (LnA < 2) or (LnB < 2) then
          Continue;
        LvA := LM2[LK, 0] / (LnA - 1);
        LvB := LM2[LK, 1] / (LnB - 1);
        LDenom := Sqrt((LvA / LnA) + (LvB / LnB));
        if LDenom <= 0 then
          Continue;
        LT := Abs((LMean[LK, 0] - LMean[LK, 1]) / LDenom);
        if LT > LMaxT then
        begin
          LMaxT := LT;
          LWinCrop := LK;
        end;
      end;
      LWinPctl := LPctl[LWinCrop];

      if Assigned(AProgress) then
        AProgress(LTotal, LMaxT, LMaxT > AConfig.Threshold);

      // Early exit once a leak is unambiguous (mainly for the controls).
      if (LTotal >= AConfig.MinSamplesForDecision) and
        (LMaxT > AConfig.Threshold) then
        Break;

      LNextCheckpoint := LNextCheckpoint * 2;
    end;
  end;

  // Final recompute (covers the case the loop ended between checkpoints).
  LMaxT := 0;
  LWinCrop := DUDECT_NUM_CROPS - 1;
  for LK := 0 to DUDECT_NUM_CROPS - 1 do
  begin
    LnA := LN[LK, 0];
    LnB := LN[LK, 1];
    if (LnA < 2) or (LnB < 2) then
      Continue;
    LvA := LM2[LK, 0] / (LnA - 1);
    LvB := LM2[LK, 1] / (LnB - 1);
    LDenom := Sqrt((LvA / LnA) + (LvB / LnB));
    if LDenom <= 0 then
      Continue;
    LDVal := Abs((LMean[LK, 0] - LMean[LK, 1]) / LDenom);
    if LDVal > LMaxT then
    begin
      LMaxT := LDVal;
      LWinCrop := LK;
    end;
  end;
  LWinPctl := LPctl[LWinCrop];

  Result.MaxT := LMaxT;
  Result.CropPercentile := LWinPctl;
  Result.NA := LN[LWinCrop, 0];
  Result.NB := LN[LWinCrop, 1];
  Result.TotalSamples := LTotal;
  Result.Threshold := AConfig.Threshold;
  Result.Leaky := LMaxT > AConfig.Threshold;
  Result.Seed := AConfig.Seed;
end;

end.
