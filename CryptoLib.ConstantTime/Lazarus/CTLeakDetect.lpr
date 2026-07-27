program CTLeakDetect;

{ dudect constant-time gate. For each registry row it runs the statistical
  fix-vs-random timing test on the known-leaky CONTROL and on the constant-time
  SUBJECT, then applies the gate:

    * every control with a leaky implementation MUST exceed |t| = 4.5, else the
      run is INVALID (the measurement is not sensitive - not a pass);
    * every subject MUST stay below |t| = 4.5.

  Exit code: 0 only if all controls fired AND all subjects stayed clean; 2 if any
  control failed to fire (invalid run); 1 if any subject leaked.

  MUST be built with -dCRYPTOLIB_FORCE_SCALAR so the software kernels (bit-sliced
  AES, ImplMul64 GHASH, CT scalar mults) are what actually execute; the startup
  banner asserts scalar dispatch and refuses to run if hardware kernels are live.

  CLI: [--quick] [--row=<substr>]  (--quick shrinks sample budgets for a fast
  smoke run; --row filters to rows whose name contains <substr>). }

{$MODE DELPHI}

uses
  SysUtils,
  ClpCtClock,
  ClpDudect,
  ClpCtSubjects,
{$IF DEFINED(CPUX86_64) OR DEFINED(CPUI386)}
  ClpSimdLevels,
  ClpX86SimdFeatures,
{$ELSEIF DEFINED(CPUAARCH64) OR DEFINED(CPUARM)}
  ClpSimdLevels,
  ClpArmSimdFeatures,
{$ENDIF}
  ClpCryptoLibTypes;

var
  GQuick: Boolean = False;
  GRowFilter: string = '';
  GCurLabel: string = '';

// OS/CPU/compiler line for the run banner (kept local so this diagnostic tool
// carries no dependency on the benchmark tree).
function PlatformInfo: string;
var
  LOS, LCPU: string;
begin
{$IF DEFINED(MSWINDOWS)}
  LOS := 'Windows';
{$ELSEIF DEFINED(LINUX)}
  LOS := 'Linux';
{$ELSEIF DEFINED(DARWIN)}
  LOS := 'macOS';
{$ELSE}
  LOS := 'Unknown OS';
{$ENDIF}
{$IF DEFINED(CPUX86_64)}
  LCPU := 'x86_64';
{$ELSEIF DEFINED(CPUI386)}
  LCPU := 'i386';
{$ELSEIF DEFINED(CPUAARCH64)}
  LCPU := 'AArch64';
{$ELSEIF DEFINED(CPUARM)}
  LCPU := 'ARM';
{$ELSE}
  LCPU := 'Unknown CPU';
{$ENDIF}
  Result := Format('Platform: %s %s, FPC %s', [LOS, LCPU, {$I %FPCVERSION%}]);
end;

function DispatchDescription(out AIsScalar: Boolean): string;
{$IF DEFINED(CPUX86_64) OR DEFINED(CPUI386)}
var
  LLevel: TX86SimdLevel;
begin
  LLevel := TX86SimdFeatures.GetActiveSimdLevel();
  AIsScalar := LLevel = TX86SimdLevel.Scalar;
  case LLevel of
    TX86SimdLevel.Scalar: Result := 'x86 SIMD level = Scalar';
    TX86SimdLevel.SSE2: Result := 'x86 SIMD level = SSE2';
    TX86SimdLevel.SSE3: Result := 'x86 SIMD level = SSE3';
    TX86SimdLevel.SSSE3: Result := 'x86 SIMD level = SSSE3';
    TX86SimdLevel.SSE41: Result := 'x86 SIMD level = SSE4.1';
    TX86SimdLevel.SSE42: Result := 'x86 SIMD level = SSE4.2';
    TX86SimdLevel.AVX2: Result := 'x86 SIMD level = AVX2';
  else
    Result := 'x86 SIMD level = (unknown)';
  end;
end;
{$ELSEIF DEFINED(CPUAARCH64) OR DEFINED(CPUARM)}
var
  LLevel: TArmSimdLevel;
begin
  LLevel := TArmSimdFeatures.GetActiveSimdLevel();
  AIsScalar := LLevel = TArmSimdLevel.Scalar;
  case LLevel of
    TArmSimdLevel.Scalar: Result := 'ARM SIMD level = Scalar';
    TArmSimdLevel.NEON: Result := 'ARM SIMD level = NEON';
    TArmSimdLevel.SVE: Result := 'ARM SIMD level = SVE';
    TArmSimdLevel.SVE2: Result := 'ARM SIMD level = SVE2';
  else
    Result := 'ARM SIMD level = (unknown)';
  end;
end;
{$ELSE}
begin
  AIsScalar := True; // no SIMD crypto engines on this architecture
  Result := 'no SIMD engines on this architecture';
end;
{$ENDIF}

procedure OnProgress(ATotalSamples: Int64; AMaxT: Double; ALeaky: Boolean);
var
  LTag: string;
begin
  if ALeaky then
    LTag := ' *LEAK*'
  else
    LTag := '';
  Writeln(Format('    %-22s n=%-9d  max|t|=%8.2f%s',
    [GCurLabel, ATotalSamples, AMaxT, LTag]));
end;

procedure ApplyQuick(var ACfg: TDudectConfig);
begin
  // Small, fast budgets for a smoke run; the leak signal on the controls is
  // strong enough to still fire, subjects rarely reach 4.5 by chance here.
  ACfg.WarmupSamples := ACfg.WarmupSamples div 4;
  if ACfg.WarmupSamples < 200 then
    ACfg.WarmupSamples := 200;
  ACfg.MaxSamples := ACfg.MaxSamples div 8;
  if ACfg.MaxSamples < 4000 then
    ACfg.MaxSamples := 4000;
  ACfg.MinSamplesForDecision := ACfg.MaxSamples div 4;
  if ACfg.BatchSamples > ACfg.MaxSamples div 2 then
    ACfg.BatchSamples := ACfg.MaxSamples div 4;
end;

function RunOne(AFactory: TCtOpFactory; const ALabel: string;
  const ACfg: TDudectConfig): TDudectResult;
var
  LOp: TDudectOp;
begin
  GCurLabel := ALabel;
  LOp := AFactory(ACfg.Seed);
  try
    Result := TDudect.Run(LOp, ACfg, OnProgress);
  finally
    LOp.Free;
  end;
end;

procedure ParseArgs;
var
  LI: Int32;
  LArg: string;
begin
  for LI := 1 to ParamCount do
  begin
    LArg := ParamStr(LI);
    if LArg = '--quick' then
      GQuick := True
    else if Copy(LArg, 1, 6) = '--row=' then
      GRowFilter := LowerCase(Copy(LArg, 7, System.Length(LArg)));
  end;
end;

var
  LRows: TCtRowArray;
  LRow: TCtRow;
  LI: Int32;
  LIsScalar, LGateFail, LGateInvalid: Boolean;
  LDesc, LErr, LVerdict: string;
  LCfg: TDudectConfig;
  LSubjRes, LCtrlRes: TDudectResult;
  LHasControl, LControlFired, LSubjectLeaky: Boolean;
  LCtrlTStr: string;
begin
  ParseArgs;

  Writeln('Constant-time leak detector (dudect)');
  Writeln('====================================');
  Writeln(PlatformInfo);
  Writeln('Clock : ', TCtClock.SourceName);

  LDesc := DispatchDescription(LIsScalar);
  if LIsScalar then
    Writeln('Dispatch: ', LDesc, '  [OK: software kernels active]')
  else
  begin
    Writeln('Dispatch: ', LDesc);
    Writeln('ABORT: hardware SIMD kernels are live. Rebuild with -dCRYPTOLIB_FORCE_SCALAR');
    Writeln('       so the constant-time software kernels are what is measured.');
    Halt(2);
  end;

  if not TCtClock.SelfCheck(LErr) then
  begin
    Writeln('ABORT: clock self-check failed: ', LErr);
    Halt(3);
  end;
  Writeln('Clock self-check: OK');
  if GQuick then
    Writeln('Mode  : --quick (reduced sample budgets)');
  Writeln('Threshold: |t| > ', FormatFloat('0.0', DUDECT_THRESHOLD),
    ' => data-dependent timing detected');
  Writeln;

  LRows := GetDudectRows;
  LGateFail := False;
  LGateInvalid := False;

  for LI := 0 to System.High(LRows) do
  begin
    LRow := LRows[LI];
    if (GRowFilter <> '') and (Pos(GRowFilter, LowerCase(LRow.Name)) = 0) then
      Continue;

    LHasControl := Assigned(LRow.MakeControl);

    Writeln('--- ', LRow.Name, ' ---');

    // Control first (fires fast; early-exit saves time).
    LControlFired := False;
    LCtrlRes.MaxT := 0;
    if LHasControl then
    begin
      LCfg := LRow.Cfg;
      if GQuick then
        ApplyQuick(LCfg);
      LCtrlRes := RunOne(LRow.MakeControl, 'control: ' + LRow.ControlLabel, LCfg);
      LControlFired := LCtrlRes.Leaky;
    end;

    // Subject.
    LCfg := LRow.Cfg;
    if GQuick then
      ApplyQuick(LCfg);
    LSubjRes := RunOne(LRow.MakeSubject, 'subject: ' + LRow.SubjectLabel, LCfg);
    LSubjectLeaky := LSubjRes.Leaky;

    // Row verdict.
    if LHasControl and (not LControlFired) then
    begin
      LVerdict := 'INVALID (control did not fire - measurement not sensitive)';
      LGateInvalid := True;
    end
    else if LSubjectLeaky then
    begin
      LVerdict := 'FAIL (subject leaks)';
      LGateFail := True;
    end
    else if LHasControl then
      LVerdict := 'OK (control fired, subject clean)'
    else
      LVerdict := 'CLEAN (baseline subject clean)';

    if LHasControl then
      LCtrlTStr := Format('%.2f', [LCtrlRes.MaxT])
    else
      LCtrlTStr := '  -  ';

    Writeln(Format('  subject max|t|=%.2f (n=%d, ~%d ns/op)   control max|t|=%s   => %s',
      [LSubjRes.MaxT, LSubjRes.TotalSamples, LSubjRes.OpNanos, LCtrlTStr, LVerdict]));
    Writeln;
  end;

  Writeln('====================================');
  if LGateInvalid then
    Writeln('GATE: INVALID - at least one control failed to fire. The detector is not '
      + 'sensitive on this run; do NOT read the subjects as clean.')
  else if LGateFail then
    Writeln('GATE: FAIL - at least one subject shows a data-dependent timing signal.')
  else
    Writeln('GATE: PASS - all controls fired and all subjects stayed clean.');
  Writeln('Seed is per-row and fixed; re-run is reproducible.');

  if LGateInvalid then
    Halt(2)
  else if LGateFail then
    Halt(1)
  else
    Halt(0);
end.
