program CTValgrind;

{ ctgrind / Valgrind constant-time check (WSL2 / Linux, deterministic).

  Marks a primitive's secret bytes "undefined" to Memcheck, runs the routine, and
  then re-defines the output before it is read. Memcheck reports any conditional
  branch or memory index that depends on the (undefined) secret - i.e. a
  data-dependent access, a constant-time violation - with no timing and no
  threshold. Stronger than dudect but path- and build-specific.

  One target per invocation (the arg names it) so a failure names the primitive.
  Targets whose ExpectLeak is true are known-leaky controls that MUST make
  Valgrind report an error; the constant-time subjects must run clean.

  Build + run (see the runbook, CryptoLib.Benchmark/Lazarus/CTValgrind.README.md):
    valgrind --error-exitcode=1 --track-origins=yes \
             --suppressions=ct.supp ./CTValgrind <target>

  Built with -dCRYPTOLIB_FORCE_SCALAR so the software kernels are what runs. }

{$MODE DELPHI}

{$IFDEF CT_VALGRIND_STUB}
  // Windows compile-check stub: no Valgrind, poison/unpoison are no-ops. Lets the
  // Pascal be validated on the dev box; the real check is the Linux build.
{$ELSE}
{$LINK ct_poison.o}
{$LINKLIB c}
{$ENDIF}

uses
  SysUtils,
  CtDudect,
  CtPlatform,
  CtSubjects,
  ClpCryptoLibTypes;

{$IFDEF CT_VALGRIND_STUB}
procedure ct_poison(p: Pointer; n: NativeUInt);
begin
end;

procedure ct_unpoison(p: Pointer; n: NativeUInt);
begin
end;
{$ELSE}
procedure ct_poison(p: Pointer; n: NativeUInt); cdecl; external name 'ct_poison';
procedure ct_unpoison(p: Pointer; n: NativeUInt); cdecl; external name 'ct_unpoison';
{$ENDIF}

procedure ListTargets;
var
  LTargets: TCtVgTargetArray;
  LI: Int32;
  LKind: string;
begin
  LTargets := GetValgrindTargets;
  Writeln('Usage: CTValgrind <target>');
  Writeln('Targets:');
  for LI := 0 to System.High(LTargets) do
  begin
    if LTargets[LI].ExpectLeak then
      LKind := 'control (MUST report an error)'
    else
      LKind := 'subject (MUST be clean)';
    Writeln(Format('  %-16s %s', [LTargets[LI].Name, LKind]));
  end;
end;

var
  LTargets: TCtVgTargetArray;
  LName: string;
  LI, LJ: Int32;
  LOp: TDudectOp;
  LFound: Boolean;
  LSink: Byte;
  LP: PByte;
begin
  if not TCtPlatform.ScalarDispatchActive then
  begin
    Writeln('ABORT: hardware SIMD kernels are live. Rebuild with -dCRYPTOLIB_FORCE_SCALAR.');
    Halt(2);
  end;

  if ParamCount < 1 then
  begin
    ListTargets;
    Halt(2);
  end;

  LName := ParamStr(1);
  LTargets := GetValgrindTargets;
  LFound := False;

  for LI := 0 to System.High(LTargets) do
  begin
    if LTargets[LI].Name <> LName then
      Continue;
    LFound := True;

    LOp := LTargets[LI].Factory.Make(UInt64(1));
    try
      // Allocate buffers + set the fixed inputs (their concrete values are
      // irrelevant - the secret is about to be marked undefined).
      LOp.PrepareSecret(0);
      if not LOp.PoisonSupported then
      begin
        Writeln(LName, ': not taint-checkable (no contiguous secret buffer)');
        Halt(2);
      end;

      ct_poison(LOp.SecretPtr, NativeUInt(LOp.SecretLen));
      LOp.RunPoisonedRoutine;
      ct_unpoison(LOp.OutputPtr, NativeUInt(LOp.OutputLen));

      // Force-read the (now defined) output so nothing is optimised away.
      LP := PByte(LOp.OutputPtr);
      LSink := 0;
      for LJ := 0 to LOp.OutputLen - 1 do
        LSink := LSink xor LP[LJ];

      Writeln(Format('%s: completed (output checksum=%d). If Memcheck printed no '
        + 'error above, this run is clean.', [LName, LSink]));
    finally
      LOp.Free;
    end;
    Break;
  end;

  if not LFound then
  begin
    Writeln('Unknown target: ', LName);
    ListTargets;
    Halt(2);
  end;
end.
