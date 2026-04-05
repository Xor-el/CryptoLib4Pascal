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

unit DigestPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  BenchmarkCommon;

type
  TDigestPerformanceBenchmark = class sealed(TObject)
  strict private
    class function BuildHeaderRow(const ABufferSizes: array of Int32): String;
    class function BuildTableRow(const AName: String;
      const ARates: array of Double): String;
    class function MeasureDigestMbPerSec(const ADigestName: String;
      ASize: Int32): Double;
    class procedure RunDigestList(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32);
  public
    class function Run(ALogProc: TBenchmarkLogProc): Int32; overload;
    class function Run(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32): Int32; overload;
  end;

implementation

uses
  SysUtils,
  ClpIDigest,
  ClpDigestUtilities;

type
  TDigestBenchRunner = class
  private
    FDigest: IDigest;
    FData: TBytes;
    FLen: Int32;
  public
    constructor Create(const ADigest: IDigest; const AData: TBytes;
      ALen: Int32);
    procedure RunOnce;
  end;

  TDigestBenchSpec = record
    DigestName: String;
    RowLabel: String;
  end;

const
  DIGEST_BENCH_SPECS: array [0 .. 8] of TDigestBenchSpec = (
    (DigestName: 'SHA-256'; RowLabel: 'SHA-256'),
    (DigestName: 'SHA-384'; RowLabel: 'SHA-384'),
    (DigestName: 'SHA-512'; RowLabel: 'SHA-512'),
    (DigestName: 'SHA-1'; RowLabel: 'SHA-1'),
    (DigestName: 'SHA3-256'; RowLabel: 'SHA3-256'),
    (DigestName: 'SHA3-512'; RowLabel: 'SHA3-512'),
    (DigestName: 'BLAKE2B-256'; RowLabel: 'BLAKE2B-256'),
    (DigestName: 'BLAKE2B-512'; RowLabel: 'BLAKE2B-512'),
    (DigestName: 'BLAKE3-256'; RowLabel: 'BLAKE3-256'));

{ TDigestBenchRunner }

constructor TDigestBenchRunner.Create(const ADigest: IDigest;
  const AData: TBytes; ALen: Int32);
begin
  inherited Create;
  FDigest := ADigest;
  FData := AData;
  FLen := ALen;
end;

procedure TDigestBenchRunner.RunOnce;
begin
  FDigest.Reset;
  FDigest.BlockUpdate(FData, 0, FLen);
  FDigest.DoFinal;
end;

{ TDigestPerformanceBenchmark }

class function TDigestPerformanceBenchmark.BuildHeaderRow(
  const ABufferSizes: array of Int32): String;
begin
  Result := TBenchmarkReport.BuildHeaderRowForBufferSizes('Digest Name',
    ABufferSizes);
end;

class function TDigestPerformanceBenchmark.BuildTableRow(const AName: String;
  const ARates: array of Double): String;
var
  LIdx: Int32;
  LParts: array of String;
begin
  System.SetLength(LParts, System.Length(ARates));
  for LIdx := System.Low(ARates) to System.High(ARates) do
    LParts[LIdx] := TBenchmarkFormat.FormatThroughputMbPerSec(ARates[LIdx]);
  Result := TBenchmarkReport.BuildDataRow(AName, LParts);
end;

class function TDigestPerformanceBenchmark.MeasureDigestMbPerSec(
  const ADigestName: String; ASize: Int32): Double;
var
  LDigest: IDigest;
  LData: TBytes;
  LRunner: TDigestBenchRunner;
begin
  LDigest := TDigestUtilities.GetDigest(ADigestName);
  BenchAllocRandom(ASize, LData);
  LRunner := TDigestBenchRunner.Create(LDigest, LData, ASize);
  try
    Result := TBenchmarkTiming.MeasureThroughputMbPerSec(LRunner.RunOnce, ASize);
  finally
    LRunner.Free;
  end;
end;

class procedure TDigestPerformanceBenchmark.RunDigestList(
  ALogProc: TBenchmarkLogProc; const ABufferSizes: array of Int32);
var
  LRates: array of Double;
  LSpecIdx, LIdx: Int32;
begin
  System.SetLength(LRates, System.Length(ABufferSizes));
  for LSpecIdx := System.Low(DIGEST_BENCH_SPECS) to System.High(DIGEST_BENCH_SPECS)
    do
  begin
    for LIdx := 0 to System.High(ABufferSizes) do
      LRates[LIdx] := MeasureDigestMbPerSec(DIGEST_BENCH_SPECS[LSpecIdx].DigestName,
        ABufferSizes[LIdx]);
    ALogProc(BuildTableRow(DIGEST_BENCH_SPECS[LSpecIdx].RowLabel, LRates));
  end;
end;

class function TDigestPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc;
  const ABufferSizes: array of Int32): Int32;
var
  LHeaderRow: String;
begin
  ALogProc('CryptoLib4Pascal digest throughput (IDigest BlockUpdate + DoFinal)');
  ALogProc('===========================================================');
  ALogProc('Random input per size; ' + IntToStr(BENCH_DURATION_MS) +
    ' ms budget per round, ' + IntToStr(BENCH_ROUNDS) +
    ' rounds; reported MB/s is max over rounds.');
  ALogProc('');

  LHeaderRow := BuildHeaderRow(ABufferSizes);
  Result := System.Length(LHeaderRow);
  ALogProc(LHeaderRow);
  ALogProc(TBenchmarkReport.BuildSeparator(Result));

  RunDigestList(ALogProc, ABufferSizes);

  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

class function TDigestPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
begin
  Result := Run(ALogProc, DEFAULT_BENCH_BUFFER_SIZES);
end;

end.
