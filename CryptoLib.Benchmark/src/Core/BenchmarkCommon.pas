{ *********************************************************************************** }
{ *                              CryptoLib Library                                  * }
{ *                           Author - Ugochukwu Mmaduekwe                          * }
{ *                 Github Repository <https://github.com/Xor-el>                   * }

{ *  Distributed under the MIT software license, see the accompanying file LICENSE  * }
{ *          or visit http://www.opensource.org/licenses/mit-license.php.           * }

{ *                              Acknowledgements:                                  * }
{ *                                                                                 * }
{ *      Thanks to Sphere 10 Software (http://www.sphere10.com/) for sponsoring     * }
{ *                           development of this library                           * }

{ * ******************************************************************************* * }

(* &&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&& *)

unit BenchmarkCommon;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  SysUtils;

type
  TBenchmarkLogProc = procedure(const AMessage: String);
  TBenchmarkTimedOpMethodProc = procedure of object;

const
  BENCH_DURATION_MS = UInt32(3000);
  BENCH_ROUNDS = 3;
  BENCH_LABEL_COL_WIDTH = 32;
  BENCH_VALUE_COL_WIDTH = 16;
  BENCH_KDF_VALUE_COL_WIDTH = 22;
  { Wide enough for "9,999.99 MB/s / 9,999.99 MB/s" in cipher combined cells. }
  BENCH_CIPHER_COMBINED_COL_WIDTH = 36;
  DEFAULT_BENCH_BUFFER_SIZES: array [0 .. 4] of Int32 =
    (256, 1024, 8192, 65536, 1048576);

procedure BenchFillRandom(var ADest: TBytes);
procedure BenchAllocRandom(ALen: Int32; var ADest: TBytes);

type
  TBenchmarkReport = class sealed(TObject)
  public
  class var
    FloatFormat: TFormatSettings;
  strict private
    class constructor Create;
  public
    class function GetPlatformInfo: String;
    class function BuildSeparator(AWidth: Int32): String;
    class function BuildHeaderRow(const AFirstColTitle: String;
      const AColumnLabels: array of String): String; overload;
    class function BuildHeaderRow(const AFirstColTitle: String;
      const AColumnLabels: array of String;
      AValueColumnWidth: Int32): String; overload;
    class function BuildHeaderRowForBufferSizes(const AFirstColTitle: String;
      const ABufferSizes: array of Int32): String; overload;
    class function BuildHeaderRowForBufferSizes(const AFirstColTitle: String;
      const ABufferSizes: array of Int32;
      AValueColumnWidth: Int32): String; overload;
    class function BuildDataRow(const ARowLabel: String;
      const ACells: array of String): String; overload;
    class function BuildDataRow(const ARowLabel: String;
      const ACells: array of String;
      AValueColumnWidth: Int32): String; overload;
    class procedure WriteStandardFooter(ALogProc: TBenchmarkLogProc;
      ATableWidth: Int32);
  end;

  { Shared column / cell formatting for benchmark tables. }
  TBenchmarkFormat = class sealed(TObject)
  public
    class function FormatBufferSize(ASize: Int32): String;
    class function FormatThroughputMbPerSec(ARate: Double): String;
    class function FormatThroughputEncDecMbPerPair(AEncMbPerSec,
      ADecMbPerSec: Double): String;
    class function FormatMeanMilliseconds(AMs: Double): String;
  end;

  { Fixed-window timing loops (shared by all benchmark sections). Uses TThread.GetTickCount (UInt32).}
  TBenchmarkTiming = class sealed(TObject)
  public
    class function MeasureThroughputMbPerSec(
      const RunOnePass: TBenchmarkTimedOpMethodProc; ABytesPerPass: Int64): Double;
    class function MeasureMeanMillisecondsPerOp(
      const RunOneOp: TBenchmarkTimedOpMethodProc): Double;
  end;

implementation

uses
  Classes,
  Math;

procedure BenchFillRandom(var ADest: TBytes);
var
  Li: Int32;
begin
  for Li := 0 to System.High(ADest) do
    ADest[Li] := Byte(Random(256));
end;

procedure BenchAllocRandom(ALen: Int32; var ADest: TBytes);
begin
  System.SetLength(ADest, ALen);
  BenchFillRandom(ADest);
end;

{ TBenchmarkReport }

class constructor TBenchmarkReport.Create;
begin
{$IFDEF FPC}
  FloatFormat := DefaultFormatSettings;
{$ELSE}
  FloatFormat := FormatSettings;
{$ENDIF}
  FloatFormat.ThousandSeparator := ',';
  FloatFormat.DecimalSeparator := '.';
end;

class function TBenchmarkReport.BuildSeparator(AWidth: Int32): String;
begin
  Result := StringOfChar('-', AWidth);
end;

class function TBenchmarkReport.BuildHeaderRow(const AFirstColTitle: String;
  const AColumnLabels: array of String): String;
begin
  Result := BuildHeaderRow(AFirstColTitle, AColumnLabels, BENCH_VALUE_COL_WIDTH);
end;

class function TBenchmarkReport.BuildHeaderRow(const AFirstColTitle: String;
  const AColumnLabels: array of String; AValueColumnWidth: Int32): String;
var
  LIdx: Int32;
  LCell: String;
begin
  Result := AFirstColTitle;
  while System.Length(Result) < BENCH_LABEL_COL_WIDTH do
    Result := Result + ' ';

  for LIdx := System.Low(AColumnLabels) to System.High(AColumnLabels) do
  begin
    LCell := AColumnLabels[LIdx];
    while System.Length(LCell) < AValueColumnWidth do
      LCell := ' ' + LCell;
    Result := Result + LCell;
  end;
end;

class function TBenchmarkReport.BuildHeaderRowForBufferSizes(
  const AFirstColTitle: String; const ABufferSizes: array of Int32): String;
begin
  Result := BuildHeaderRowForBufferSizes(AFirstColTitle, ABufferSizes,
    BENCH_VALUE_COL_WIDTH);
end;

class function TBenchmarkReport.BuildHeaderRowForBufferSizes(
  const AFirstColTitle: String; const ABufferSizes: array of Int32;
  AValueColumnWidth: Int32): String;
var
  LIdx: Int32;
  LLabels: array of String;
begin
  System.SetLength(LLabels, System.Length(ABufferSizes));
  for LIdx := System.Low(ABufferSizes) to System.High(ABufferSizes) do
    LLabels[LIdx] := TBenchmarkFormat.FormatBufferSize(ABufferSizes[LIdx]);
  Result := BuildHeaderRow(AFirstColTitle, LLabels, AValueColumnWidth);
end;

class function TBenchmarkReport.BuildDataRow(const ARowLabel: String;
  const ACells: array of String): String;
begin
  Result := BuildDataRow(ARowLabel, ACells, BENCH_VALUE_COL_WIDTH);
end;

class function TBenchmarkReport.BuildDataRow(const ARowLabel: String;
  const ACells: array of String; AValueColumnWidth: Int32): String;
var
  LIdx: Int32;
  LCell: String;
begin
  Result := ARowLabel;
  while System.Length(Result) < BENCH_LABEL_COL_WIDTH do
    Result := Result + ' ';

  for LIdx := System.Low(ACells) to System.High(ACells) do
  begin
    LCell := ACells[LIdx];
    while System.Length(LCell) < AValueColumnWidth do
      LCell := ' ' + LCell;
    Result := Result + LCell;
  end;
end;

class function TBenchmarkReport.GetPlatformInfo: String;
var
  LOS, LCompiler, LCPU: String;
begin
{$IFDEF FPC}
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
{$ELSE}
  {$IF DEFINED(MSWINDOWS)}
  LOS := 'Windows';
  {$ELSEIF DEFINED(ANDROID)}
  LOS := 'Android';
  {$ELSEIF DEFINED(IOS)}
  LOS := 'iOS';
  {$ELSEIF DEFINED(MACOS)}
  LOS := 'macOS';
  {$ELSEIF DEFINED(LINUX)}
  LOS := 'Linux';
  {$ELSE}
  LOS := 'Unknown OS';
  {$ENDIF}

  {$IF DEFINED(CPUX64)}
  LCPU := 'x86_64';
  {$ELSEIF DEFINED(CPUX86)}
  LCPU := 'i386';
  {$ELSEIF DEFINED(CPUARM64)}
  LCPU := 'AArch64';
  {$ELSEIF DEFINED(CPUARM)}
  LCPU := 'ARM';
  {$ELSE}
  LCPU := 'Unknown CPU';
  {$ENDIF}
{$ENDIF}

{$IFDEF FPC}
  LCompiler := 'FPC ' + {$I %FPCVERSION%};
{$ELSE}
  LCompiler := Format('Delphi (CompilerVersion %.1f)', [CompilerVersion]);
{$ENDIF}

  Result := Format('Platform: %s %s, %s', [LOS, LCPU, LCompiler]);
end;

class procedure TBenchmarkReport.WriteStandardFooter(ALogProc: TBenchmarkLogProc;
  ATableWidth: Int32);
begin
  if ATableWidth < 40 then
    ATableWidth := 40;
  ALogProc(BuildSeparator(ATableWidth));
  ALogProc('Benchmark complete.');
  ALogProc(GetPlatformInfo);
  ALogProc('Date: ' + FormatDateTime('yyyy-mm-dd', Now));
end;

{ TBenchmarkFormat }

class function TBenchmarkFormat.FormatBufferSize(ASize: Int32): String;
begin
  if ASize >= 1024 * 1024 then
    Result := Format('%d MB', [ASize div (1024 * 1024)])
  else if ASize >= 1024 then
    Result := Format('%d KB', [ASize div 1024])
  else
    Result := Format('%d B', [ASize]);
end;

class function TBenchmarkFormat.FormatThroughputMbPerSec(ARate: Double): String;
begin
  Result := FormatFloat('#,##0.00', ARate, TBenchmarkReport.FloatFormat) + ' MB/s';
end;

class function TBenchmarkFormat.FormatThroughputEncDecMbPerPair(AEncMbPerSec,
  ADecMbPerSec: Double): String;
begin
  Result := FormatThroughputMbPerSec(AEncMbPerSec) + ' / ' +
    FormatThroughputMbPerSec(ADecMbPerSec);
end;

class function TBenchmarkFormat.FormatMeanMilliseconds(AMs: Double): String;
begin
  if not (AMs > 0.0) then
    Result := '0.00 ms'
  else
    Result := FormatFloat('#,##0.00', AMs, TBenchmarkReport.FloatFormat) + ' ms';
end;

{ TBenchmarkTiming }

class function TBenchmarkTiming.MeasureThroughputMbPerSec(
  const RunOnePass: TBenchmarkTimedOpMethodProc; ABytesPerPass: Int64): Double;
var
  LRound: Int32;
  LTotal: Int64;
  LTickStart, LTickEnd, LElapsed: UInt32;
begin
  Result := 0.0;
  for LRound := 1 to BENCH_ROUNDS do
  begin
    LTotal := 0;
    LElapsed := 0;
    while LElapsed <= BENCH_DURATION_MS do
    begin
      LTickStart := TThread.GetTickCount;
      RunOnePass();
      LTickEnd := TThread.GetTickCount;
      LTotal := LTotal + ABytesPerPass;
      LElapsed := LElapsed + (LTickEnd - LTickStart);
    end;
    if LElapsed > 0 then
      Result := Math.Max(LTotal / (LElapsed / 1000.0) / 1024.0 / 1024.0, Result);
  end;
end;

class function TBenchmarkTiming.MeasureMeanMillisecondsPerOp(
  const RunOneOp: TBenchmarkTimedOpMethodProc): Double;
var
  LRound: Int32;
  LCount: Int64;
  LTickStart, LTickEnd, LElapsed: UInt32;
  LMeanMs: Double;
  LHaveAny: Boolean;
begin
  LHaveAny := False;
  Result := 0.0;
  for LRound := 1 to BENCH_ROUNDS do
  begin
    LCount := 0;
    LElapsed := 0;
    while LElapsed <= BENCH_DURATION_MS do
    begin
      LTickStart := TThread.GetTickCount;
      RunOneOp();
      LTickEnd := TThread.GetTickCount;
      System.Inc(LCount);
      LElapsed := LElapsed + (LTickEnd - LTickStart);
    end;
    if LCount > 0 then
    begin
      LMeanMs := LElapsed / LCount;
      if (not LHaveAny) or (LMeanMs < Result) then
      begin
        Result := LMeanMs;
        LHaveAny := True;
      end;
    end;
  end;
  if not LHaveAny then
    Result := 0.0;
end;

end.
