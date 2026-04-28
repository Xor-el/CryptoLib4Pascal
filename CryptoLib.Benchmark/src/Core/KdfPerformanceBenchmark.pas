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

unit KdfPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  BenchmarkCommon;

type
  TKdfPerformanceBenchmark = class sealed(TObject)
  public
    class function Run(ALogProc: TBenchmarkLogProc): Int32;
  end;

implementation

uses
  SysUtils,
  Math,
  ClpDigestUtilities,
  ClpIDigest,
  ClpPkcs5S2ParametersGenerator,
  ClpIPkcs5S2ParametersGenerator,
  ClpArgon2ParametersGenerator,
  ClpIArgon2ParametersGenerator,
  ClpScryptParametersGenerator,
  ClpIScryptParametersGenerator;

const
  BENCH_KDF_OUTPUT_BYTES = 32;
  BENCH_SECRET_LEN = 24;

var
  GBenchPassword: TBytes;
  GBenchSalt: TBytes;

type
  TPbkdf2BenchRunner = class
  private
    FDigestName: String;
    FIterations: Int32;
  public
    constructor Create(const ADigestName: String; AIterations: Int32);
    procedure RunOnce;
  end;

  TArgon2BenchRunner = class
  private
    FArgonType: TCryptoLibArgon2Type;
    FMemoryKiB: Int32;
    FTimeCost: Int32;
  public
    constructor Create(AArgonType: TCryptoLibArgon2Type;
      AMemoryKiB, ATimeCost: Int32);
    procedure RunOnce;
  end;

  TScryptBenchRunner = class
  private
    FCost: Int32;
  public
    constructor Create(ACost: Int32);
    procedure RunOnce;
  end;

{ TPbkdf2BenchRunner }

constructor TPbkdf2BenchRunner.Create(const ADigestName: String;
  AIterations: Int32);
begin
  inherited Create;
  FDigestName := ADigestName;
  FIterations := AIterations;
end;

procedure TPbkdf2BenchRunner.RunOnce;
var
  LGen: IPkcs5S2ParametersGenerator;
  LDigest: IDigest;
begin
  LDigest := TDigestUtilities.GetDigest(FDigestName);
  LGen := TPkcs5S2ParametersGenerator.Create(LDigest);
  LGen.Init(GBenchPassword, GBenchSalt, FIterations);
  LGen.GenerateDerivedMacParameters(256);
  LGen.Clear;
end;

{ TArgon2BenchRunner }

constructor TArgon2BenchRunner.Create(AArgonType: TCryptoLibArgon2Type;
  AMemoryKiB, ATimeCost: Int32);
begin
  inherited Create;
  FArgonType := AArgonType;
  FMemoryKiB := AMemoryKiB;
  FTimeCost := ATimeCost;
end;

procedure TArgon2BenchRunner.RunOnce;
var
  LGen: IArgon2ParametersGenerator;
begin
  LGen := TArgon2ParametersGenerator.Create;
  LGen.Init(FArgonType, TCryptoLibArgon2Version.Argon2Version13,
    GBenchPassword, GBenchSalt, nil, nil, FTimeCost, FMemoryKiB, 1,
    TCryptoLibArgon2MemoryCostType.MemoryAsKB);
  LGen.GenerateDerivedMacParameters(BENCH_KDF_OUTPUT_BYTES * 8);
  LGen.Clear;
end;

{ TScryptBenchRunner }

constructor TScryptBenchRunner.Create(ACost: Int32);
begin
  inherited Create;
  FCost := ACost;
end;

procedure TScryptBenchRunner.RunOnce;
var
  LGen: IScryptParametersGenerator;
begin
  LGen := TScryptParametersGenerator.Create;
  LGen.Init(GBenchPassword, GBenchSalt, FCost, 8, 1);
  LGen.GenerateDerivedMacParameters(BENCH_KDF_OUTPUT_BYTES * 8);
  LGen.Clear;
end;

procedure InitializeBenchSecrets;
begin
  BenchAllocRandom(BENCH_SECRET_LEN, GBenchPassword);
  BenchAllocRandom(BENCH_SECRET_LEN, GBenchSalt);
end;

function WriteKdfSubTableHeader(ALogProc: TBenchmarkLogProc;
  const AHeadingLines: array of String; const AFirstColTitle: String;
  const AColumnLabels: array of String; AValueColumnWidth: Int32): Int32;
var
  LIdx: Int32;
  LHeader: String;
begin
  for LIdx := System.Low(AHeadingLines) to System.High(AHeadingLines) do
    ALogProc(AHeadingLines[LIdx]);
  LHeader := TBenchmarkReport.BuildHeaderRow(AFirstColTitle, AColumnLabels,
    AValueColumnWidth);
  Result := System.Length(LHeader);
  ALogProc(LHeader);
  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

procedure CloseKdfSubTable(ALogProc: TBenchmarkLogProc; ATableWidth: Int32);
begin
  ALogProc(TBenchmarkReport.BuildSeparator(ATableWidth));
  ALogProc('');
end;

procedure WriteMatrixRow(ALogProc: TBenchmarkLogProc; const ARowLabel: String;
  const AOps: array of TBenchmarkTimedOpMethodProc; AValueW: Int32);
var
  Li: Int32;
  LCells: array of String;
begin
  System.SetLength(LCells, System.Length(AOps));
  for Li := 0 to System.High(AOps) do
    LCells[Li] := TBenchmarkFormat.FormatMeanMilliseconds(
      TBenchmarkTiming.MeasureMeanMillisecondsPerOp(AOps[Li]));
  ALogProc(TBenchmarkReport.BuildDataRow(ARowLabel, LCells, AValueW));
end;

procedure WriteSingleRow(ALogProc: TBenchmarkLogProc; const ARowLabel: String;
  R: TBenchmarkTimedOpMethodProc; AValueW: Int32);
var
  LCells: array [0 .. 0] of String;
begin
  LCells[0] := TBenchmarkFormat.FormatMeanMilliseconds(
    TBenchmarkTiming.MeasureMeanMillisecondsPerOp(R));
  ALogProc(TBenchmarkReport.BuildDataRow(ARowLabel, LCells, AValueW));
end;

type
  TPbkdf2PrfSpec = record
    RowLabel: String;
    DigestName: String;
  end;

  TArgon2VariantSpec = record
    RowLabel: String;
    Variant: TCryptoLibArgon2Type;
  end;

const
  PBKDF2_PRF_SPECS: array [0 .. 2] of TPbkdf2PrfSpec = (
    (RowLabel: 'SHA-256'; DigestName: 'SHA-256'),
    (RowLabel: 'SHA-512'; DigestName: 'SHA-512'),
    (RowLabel: 'SHA-1'; DigestName: 'SHA-1'));

  ARGON2_VARIANT_SPECS: array [0 .. 2] of TArgon2VariantSpec = (
    (RowLabel: 'Argon2id'; Variant: TCryptoLibArgon2Type.Argon2ID),
    (RowLabel: 'Argon2i'; Variant: TCryptoLibArgon2Type.Argon2I),
    (RowLabel: 'Argon2d'; Variant: TCryptoLibArgon2Type.Argon2D));

  PBKDF2_COLUMN_ITERATIONS: array [0 .. 2] of Int32 =
    (10000, 100000, 600000);

  PBKDF2_COLUMN_LABELS: array [0 .. 2] of String =
    ('10k iter', '100k iter', '600k iter');

  ARGON2_COLUMN_MEMORY_KIB: array [0 .. 2] of Int32 = (8, 32, 64);

  ARGON2_COLUMN_TIME_COST: array [0 .. 2] of Int32 = (1, 2, 3);

  ARGON2_COLUMN_LABELS: array [0 .. 2] of String =
    ('m=8KiB t=1 p=1', 'm=32KiB t=2 p=1', 'm=64KiB t=3 p=1');

  SCRYPT_COLUMN_N: array [0 .. 2] of Int32 = (1024, 4096, 16384);

  SCRYPT_COLUMN_LABELS: array [0 .. 2] of String =
    ('N=1024', 'N=4096', 'N=16384');

{ TKdfPerformanceBenchmark }

class function TKdfPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
var
  LCol: array [0 .. 2] of String;
  LPartW: Int32;
  LValueW: Int32;
  Li: Int32;
  P1, P2, P3: TPbkdf2BenchRunner;
  A1, A2, A3: TArgon2BenchRunner;
  S1, S2, S3: TScryptBenchRunner;
begin
  InitializeBenchSecrets;
  Result := 0;
  LValueW := BENCH_KDF_VALUE_COL_WIDTH;

  ALogProc('Key derivation (CryptoLib generators, mean ms per derivation)');
  ALogProc('--------------------------------------------------------------');
  ALogProc('Each timed operation: construct generator, derive ' +
    IntToStr(BENCH_KDF_OUTPUT_BYTES) + ' bytes (or keyed output of that size), Clear.');
  ALogProc('Do not compare PBKDF2 vs Argon2 vs scrypt numerically (different costs).');
  ALogProc('Approximate rate: derivations/s ~ 1000 / (mean ms).');
  ALogProc('');

  LCol[0] := PBKDF2_COLUMN_LABELS[0];
  LCol[1] := PBKDF2_COLUMN_LABELS[1];
  LCol[2] := PBKDF2_COLUMN_LABELS[2];
  LPartW := WriteKdfSubTableHeader(ALogProc, ['PBKDF2 (PKCS#5 scheme 2)'], 'PRF',
    LCol, LValueW);
  Result := Math.Max(Result, LPartW);

  for Li := System.Low(PBKDF2_PRF_SPECS) to System.High(PBKDF2_PRF_SPECS) do
  begin
    P1 := TPbkdf2BenchRunner.Create(PBKDF2_PRF_SPECS[Li].DigestName,
      PBKDF2_COLUMN_ITERATIONS[0]);
    P2 := TPbkdf2BenchRunner.Create(PBKDF2_PRF_SPECS[Li].DigestName,
      PBKDF2_COLUMN_ITERATIONS[1]);
    P3 := TPbkdf2BenchRunner.Create(PBKDF2_PRF_SPECS[Li].DigestName,
      PBKDF2_COLUMN_ITERATIONS[2]);
    try
      WriteMatrixRow(ALogProc, PBKDF2_PRF_SPECS[Li].RowLabel,
        [P1.RunOnce, P2.RunOnce, P3.RunOnce], LValueW);
    finally
      P1.Free;
      P2.Free;
      P3.Free;
    end;
  end;

  CloseKdfSubTable(ALogProc, LPartW);

  LCol[0] := ARGON2_COLUMN_LABELS[0];
  LCol[1] := ARGON2_COLUMN_LABELS[1];
  LCol[2] := ARGON2_COLUMN_LABELS[2];
  LPartW := WriteKdfSubTableHeader(ALogProc,
    ['Argon2 (memory in KiB, t = time cost)'], 'Type', LCol, LValueW);
  Result := Math.Max(Result, LPartW);

  for Li := System.Low(ARGON2_VARIANT_SPECS) to System.High(ARGON2_VARIANT_SPECS)
    do
  begin
    A1 := TArgon2BenchRunner.Create(ARGON2_VARIANT_SPECS[Li].Variant,
      ARGON2_COLUMN_MEMORY_KIB[0], ARGON2_COLUMN_TIME_COST[0]);
    A2 := TArgon2BenchRunner.Create(ARGON2_VARIANT_SPECS[Li].Variant,
      ARGON2_COLUMN_MEMORY_KIB[1], ARGON2_COLUMN_TIME_COST[1]);
    A3 := TArgon2BenchRunner.Create(ARGON2_VARIANT_SPECS[Li].Variant,
      ARGON2_COLUMN_MEMORY_KIB[2], ARGON2_COLUMN_TIME_COST[2]);
    try
      WriteMatrixRow(ALogProc, ARGON2_VARIANT_SPECS[Li].RowLabel,
        [A1.RunOnce, A2.RunOnce, A3.RunOnce], LValueW);
    finally
      A1.Free;
      A2.Free;
      A3.Free;
    end;
  end;

  CloseKdfSubTable(ALogProc, LPartW);

  LCol[0] := SCRYPT_COLUMN_LABELS[0];
  LCol[1] := SCRYPT_COLUMN_LABELS[1];
  LCol[2] := SCRYPT_COLUMN_LABELS[2];
  LPartW := WriteKdfSubTableHeader(ALogProc, ['Scrypt (r=8, p=1)'], 'KDF', LCol,
    LValueW);
  Result := Math.Max(Result, LPartW);

  S1 := TScryptBenchRunner.Create(SCRYPT_COLUMN_N[0]);
  S2 := TScryptBenchRunner.Create(SCRYPT_COLUMN_N[1]);
  S3 := TScryptBenchRunner.Create(SCRYPT_COLUMN_N[2]);
  try
    WriteMatrixRow(ALogProc, 'Scrypt', [S1.RunOnce, S2.RunOnce, S3.RunOnce],
      LValueW);
  finally
    S1.Free;
    S2.Free;
    S3.Free;
  end;

  CloseKdfSubTable(ALogProc, LPartW);

  LPartW := WriteKdfSubTableHeader(ALogProc,
    ['Reference-style profiles (illustrative)'], 'Profile', ['Mean ms'], LValueW);
  Result := Math.Max(Result, LPartW);

  P1 := TPbkdf2BenchRunner.Create('SHA-256', 600000);
  A1 := TArgon2BenchRunner.Create(TCryptoLibArgon2Type.Argon2ID, 19456, 2);
  S1 := TScryptBenchRunner.Create(131072);
  try
    WriteSingleRow(ALogProc, 'PBKDF2-HMAC-SHA-256 600k iter', P1.RunOnce,
      LValueW);
    WriteSingleRow(ALogProc, 'Argon2id m=19456 t=2 p=1', A1.RunOnce, LValueW);
    WriteSingleRow(ALogProc, 'Scrypt N=131072 r=8 p=1', S1.RunOnce, LValueW);
  finally
    P1.Free;
    A1.Free;
    S1.Free;
  end;

  CloseKdfSubTable(ALogProc, LPartW);
end;

end.
