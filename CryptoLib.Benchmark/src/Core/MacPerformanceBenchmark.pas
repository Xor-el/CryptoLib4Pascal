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

unit MacPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  BenchmarkCommon;

type
  TMacPerformanceBenchmark = class sealed(TObject)
  strict private
    class function BuildHeaderRow(const ABufferSizes: array of Int32): String;
    class function BuildTableRow(const AName: String;
      const ARates: array of Double): String;
    class function MeasureMacMbPerSec(ASpecIdx, ASize: Int32): Double;
    class procedure RunMacList(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32);
  public
    class function Run(ALogProc: TBenchmarkLogProc): Int32; overload;
    class function Run(ALogProc: TBenchmarkLogProc;
      const ABufferSizes: array of Int32): Int32; overload;
  end;

implementation

uses
  SysUtils,
  ClpIMac,
  ClpPoly1305,
  ClpGMac,
  ClpGcmBlockCipher,
  ClpIGcmBlockCipher,
  ClpAesUtilities,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpICipherParameters;

type
  // Each timed iteration is the full per-message MAC operation - Init with
  // the message's parameters, absorb the payload, produce the tag. Poly1305
  // keys are single-use by contract and GMAC needs a fresh nonce per
  // message (GCM rejects nonce reuse), so re-keying belongs in the
  // measured cost. When ANonce is supplied the runner advances it per
  // message and wraps it with the key for Init; otherwise the fixed
  // AParams is used as-is.
  TMacBenchRunner = class
  private
    FMac: IMac;
    FParams: ICipherParameters;
    FKeyParam: IKeyParameter;
    FNonce: TBytes;
    FData: TBytes;
    FLen: Int32;
    FTag: TBytes;
  public
    constructor Create(const AMac: IMac; const AParams: ICipherParameters;
      const AKeyParam: IKeyParameter; const ANonce: TBytes;
      const AData: TBytes; ALen: Int32);
    procedure RunOnce;
  end;

  TMacBenchSpec = record
    RowLabel: String;
  end;

const
  MAC_BENCH_SPEC_POLY1305 = 0;
  MAC_BENCH_SPEC_GMAC_AES128 = 1;

  MAC_BENCH_SPECS: array [0 .. 1] of TMacBenchSpec = (
    (RowLabel: 'Poly1305'),
    (RowLabel: 'GMAC-AES-128 (GHASH)'));

{ TMacBenchRunner }

constructor TMacBenchRunner.Create(const AMac: IMac;
  const AParams: ICipherParameters; const AKeyParam: IKeyParameter;
  const ANonce: TBytes; const AData: TBytes; ALen: Int32);
begin
  inherited Create;
  FMac := AMac;
  FParams := AParams;
  FKeyParam := AKeyParam;
  FNonce := ANonce;
  FData := AData;
  FLen := ALen;
  System.SetLength(FTag, AMac.GetMacSize);
end;

procedure TMacBenchRunner.RunOnce;
var
  LIdx: Int32;
begin
  if FNonce <> nil then
  begin
    // fresh nonce per message: increment as a little-endian counter
    LIdx := 0;
    repeat
      Inc(FNonce[LIdx]);
      Inc(LIdx);
    until (FNonce[LIdx - 1] <> 0) or (LIdx > System.High(FNonce));
    FMac.Init(TParametersWithIV.Create(FKeyParam, FNonce)
      as IParametersWithIV);
  end
  else
    FMac.Init(FParams);
  FMac.BlockUpdate(FData, 0, FLen);
  FMac.DoFinal(FTag, 0);
end;

{ TMacPerformanceBenchmark }

class function TMacPerformanceBenchmark.BuildHeaderRow(
  const ABufferSizes: array of Int32): String;
begin
  Result := TBenchmarkReport.BuildHeaderRowForBufferSizes('MAC Name',
    ABufferSizes);
end;

class function TMacPerformanceBenchmark.BuildTableRow(const AName: String;
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

class function TMacPerformanceBenchmark.MeasureMacMbPerSec(ASpecIdx,
  ASize: Int32): Double;
var
  LMac: IMac;
  LParams: ICipherParameters;
  LKeyParam: IKeyParameter;
  LKey, LNonce, LData: TBytes;
  LRunner: TMacBenchRunner;
begin
  LParams := nil;
  LKeyParam := nil;
  LNonce := nil;
  LMac := nil;
  case ASpecIdx of
    MAC_BENCH_SPEC_POLY1305:
      begin
        BenchAllocRandom(32, LKey);
        LMac := TPoly1305.Create();
        LParams := TKeyParameter.Create(LKey) as IKeyParameter;
      end;
    MAC_BENCH_SPEC_GMAC_AES128:
      begin
        BenchAllocRandom(16, LKey);
        BenchAllocRandom(12, LNonce);
        LMac := TGMac.Create(TGcmBlockCipher.Create(TAesUtilities.CreateEngine())
          as IGcmBlockCipher);
        LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;
      end;
  end;
  BenchAllocRandom(ASize, LData);
  LRunner := TMacBenchRunner.Create(LMac, LParams, LKeyParam, LNonce, LData,
    ASize);
  try
    Result := TBenchmarkTiming.MeasureThroughputMbPerSec(LRunner.RunOnce,
      ASize);
  finally
    LRunner.Free;
  end;
end;

class procedure TMacPerformanceBenchmark.RunMacList(
  ALogProc: TBenchmarkLogProc; const ABufferSizes: array of Int32);
var
  LRates: array of Double;
  LSpecIdx, LIdx: Int32;
begin
  System.SetLength(LRates, System.Length(ABufferSizes));
  for LSpecIdx := System.Low(MAC_BENCH_SPECS) to System.High(MAC_BENCH_SPECS)
    do
  begin
    for LIdx := 0 to System.High(ABufferSizes) do
      LRates[LIdx] := MeasureMacMbPerSec(LSpecIdx, ABufferSizes[LIdx]);
    ALogProc(BuildTableRow(MAC_BENCH_SPECS[LSpecIdx].RowLabel, LRates));
  end;
end;

class function TMacPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc;
  const ABufferSizes: array of Int32): Int32;
var
  LHeaderRow: String;
begin
  ALogProc('CryptoLib4Pascal MAC throughput (IMac Init + BlockUpdate + DoFinal per message)');
  ALogProc('===========================================================');
  ALogProc('Random input per size; ' + IntToStr(BENCH_DURATION_MS) +
    ' ms budget per round, ' + IntToStr(BENCH_ROUNDS) +
    ' rounds; reported MB/s is max over rounds.');
  ALogProc('Implementations route through runtime CPU dispatch: accelerated');
  ALogProc('paths where the CPU supports them, scalar fallback otherwise.');
  ALogProc('');

  LHeaderRow := BuildHeaderRow(ABufferSizes);
  Result := System.Length(LHeaderRow);
  ALogProc(LHeaderRow);
  ALogProc(TBenchmarkReport.BuildSeparator(Result));

  RunMacList(ALogProc, ABufferSizes);

  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

class function TMacPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
begin
  Result := Run(ALogProc, DEFAULT_BENCH_BUFFER_SIZES);
end;

end.
