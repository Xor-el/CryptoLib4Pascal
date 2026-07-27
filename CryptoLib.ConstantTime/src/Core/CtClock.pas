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

{ Portable high-resolution monotonic tick source for the constant-time leak
  detector. The shared benchmark harness times with TThread.GetTickCount (~15 ms),
  which is useless for per-operation timing; this gives the best counter each
  platform offers. The dudect t-test is scale invariant (both classes measured in
  identical units), so the harness runs in raw ticks; nanosecond conversion is for
  reporting only.

  Sources:
    Windows : QueryPerformanceCounter / QueryPerformanceFrequency.
    Linux   : clock_gettime(CLOCK_MONOTONIC_RAW) -> nanoseconds.
    x86_64  : optional RDTSCP fast path behind the USE_RDTSC define (OFF by default;
              TSC frequency != wall time under frequency scaling / turbo, so it
              sharpens resolution on bare metal only and adds no correctness). }

unit CtClock;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

// {$DEFINE USE_RDTSC}   // opt-in x86_64 RDTSCP source; keep OFF by default.

{$IF DEFINED(USE_RDTSC) AND DEFINED(CPUX86_64)}
{$DEFINE CT_RDTSC_ACTIVE}
{$ASMMODE INTEL}
{$ENDIF}

interface

uses
  SysUtils;

type
  TCtClock = record
  public
    // Monotonic raw counter. Units are platform defined; only differences are meaningful.
    class function TicksNow: UInt64; static; {$IFNDEF CT_RDTSC_ACTIVE}inline;{$ENDIF}
    // Ticks per wall-clock second (for nanosecond reporting only). 0 if unknown.
    class function TicksPerSecond: UInt64; static;
    class function TicksToNanos(ADelta: UInt64): UInt64; static;
    // Startup guard: verifies the counter is monotonic and sub-microsecond.
    class function SelfCheck(out AErr: string): Boolean; static;
    // Short human description of the active source, for the run banner.
    class function SourceName: string; static;
  end;

implementation

uses
{$IF DEFINED(MSWINDOWS)}
  Windows;
{$ELSEIF DEFINED(UNIX)}
  ctypes,
  UnixType;
{$ELSE}
  Classes;
{$ENDIF}

{$IF DEFINED(UNIX) AND NOT DEFINED(CT_RDTSC_ACTIVE)}
const
  CLOCK_MONOTONIC_RAW = cint(4);

function clock_gettime(clk_id: cint; tp: Ptimespec): cint; cdecl;
  external 'c' name 'clock_gettime';
{$ENDIF}

{$IF DEFINED(MSWINDOWS) AND NOT DEFINED(CT_RDTSC_ACTIVE)}
var
  GQpcFreq: UInt64 = 0;

function WinFreq: UInt64;
var
  LFreq: Int64;
begin
  if GQpcFreq = 0 then
  begin
    if QueryPerformanceFrequency(LFreq) and (LFreq > 0) then
      GQpcFreq := UInt64(LFreq)
    else
      GQpcFreq := 0;
  end;
  Result := GQpcFreq;
end;
{$ENDIF}

{ TCtClock }

{$IF DEFINED(CT_RDTSC_ACTIVE)}
class function TCtClock.TicksNow: UInt64; assembler; nostackframe;
asm
  rdtscp            // EDX:EAX = TSC, ECX = processor id (clobbered, volatile)
  shl   rdx, 32
  or    rax, rdx    // RAX = full 64-bit counter (return value)
end;
{$ELSEIF DEFINED(MSWINDOWS)}
class function TCtClock.TicksNow: UInt64;
var
  LCounter: Int64;
begin
  QueryPerformanceCounter(LCounter);
  Result := UInt64(LCounter);
end;
{$ELSEIF DEFINED(UNIX)}
class function TCtClock.TicksNow: UInt64;
var
  LTs: timespec;
begin
  clock_gettime(CLOCK_MONOTONIC_RAW, @LTs);
  Result := (UInt64(LTs.tv_sec) * UInt64(1000000000)) + UInt64(LTs.tv_nsec);
end;
{$ELSE}
class function TCtClock.TicksNow: UInt64;
begin
  Result := UInt64(TThread.GetTickCount64); // coarse fallback; SelfCheck will reject it
end;
{$ENDIF}

class function TCtClock.TicksPerSecond: UInt64;
begin
{$IF DEFINED(CT_RDTSC_ACTIVE)}
  Result := 0; // TSC frequency is not wall time; report in raw ticks only
{$ELSEIF DEFINED(MSWINDOWS)}
  Result := WinFreq;
{$ELSEIF DEFINED(UNIX)}
  Result := UInt64(1000000000); // clock_gettime is in nanoseconds
{$ELSE}
  Result := UInt64(1000); // GetTickCount64 is milliseconds
{$ENDIF}
end;

class function TCtClock.TicksToNanos(ADelta: UInt64): UInt64;
var
  LFreq: UInt64;
begin
  LFreq := TicksPerSecond;
  if LFreq = 0 then
    Result := ADelta // frequency unknown (e.g. RDTSC): report raw ticks
  else
    Result := (ADelta * UInt64(1000000000)) div LFreq;
end;

class function TCtClock.SourceName: string;
begin
{$IF DEFINED(CT_RDTSC_ACTIVE)}
  Result := 'RDTSCP (raw TSC ticks)';
{$ELSEIF DEFINED(MSWINDOWS)}
  Result := Format('QueryPerformanceCounter (%d Hz)', [TicksPerSecond]);
{$ELSEIF DEFINED(UNIX)}
  Result := 'clock_gettime(CLOCK_MONOTONIC_RAW) (1e9 Hz)';
{$ELSE}
  Result := 'GetTickCount64 (coarse)';
{$ENDIF}
end;

class function TCtClock.SelfCheck(out AErr: string): Boolean;
var
  LI: Int32;
  LA, LB, LMinDelta, LD, LAcc, LNs: UInt64;
begin
  Result := False;
  AErr := '';

  // Non-decreasing over a stretch of work.
  LA := TicksNow;
  LAcc := 0;
  for LI := 1 to 1000000 do
    LAcc := LAcc + UInt64(LI);
  LB := TicksNow;
  if LAcc = 0 then // defeat dead-code elimination
    AErr := '';
  if LB < LA then
  begin
    AErr := 'clock is not monotonic (went backwards)';
    Exit;
  end;

  // Resolution: smallest positive delta between two adjacent reads.
  LMinDelta := High(UInt64);
  for LI := 1 to 200000 do
  begin
    LA := TicksNow;
    LB := TicksNow;
    if LB > LA then
    begin
      LD := LB - LA;
      if LD < LMinDelta then
        LMinDelta := LD;
    end;
  end;

  if LMinDelta = High(UInt64) then
  begin
    AErr := 'clock resolution too coarse (no positive delta over 200k reads)';
    Exit;
  end;

  LNs := TicksToNanos(LMinDelta);
  // For an unknown-frequency source (RDTSC) TicksToNanos returns raw ticks; a
  // minimum delta of a few ticks is fine there, so only enforce the 1 us ceiling
  // when the frequency is known.
  if (TicksPerSecond <> 0) and (LNs > 1000) then
  begin
    AErr := Format('clock resolution ~%d ns exceeds the 1000 ns ceiling', [LNs]);
    Exit;
  end;

  Result := True;
end;

end.
