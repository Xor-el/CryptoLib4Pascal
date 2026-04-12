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

unit PerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  BenchmarkCommon;

type
  TPerformanceBenchmark = class sealed(TObject)
  public
    class procedure Run(ALogProc: TBenchmarkLogProc); overload;
    class procedure Run(ALogProc: TBenchmarkLogProc;
      const ADigestSizes, AEncryptSizes, ADecryptSizes: array of Int32); overload;
  end;

implementation

uses
  SysUtils,
  Math,
  DigestPerformanceBenchmark,
  CipherPerformanceBenchmark,
  SignerPerformanceBenchmark,
  KdfPerformanceBenchmark;

{ TPerformanceBenchmark }

class procedure TPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc);
begin
  Run(ALogProc, DEFAULT_BENCH_BUFFER_SIZES, DEFAULT_BENCH_BUFFER_SIZES,
    DEFAULT_BENCH_BUFFER_SIZES);
end;

class procedure TPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc;
  const ADigestSizes, AEncryptSizes, ADecryptSizes: array of Int32);
var
  WD, WC, WS, WK, LMax: Int32;
begin
  Randomize;
  //WD := TDigestPerformanceBenchmark.Run(ALogProc, ADigestSizes);
  //ALogProc('');
  WC := TCipherPerformanceBenchmark.Run(ALogProc, AEncryptSizes, ADecryptSizes);
  ALogProc('');
  //WS := TSignerPerformanceBenchmark.Run(ALogProc);
  //ALogProc('');
  //WK := TKdfPerformanceBenchmark.Run(ALogProc);
  LMax := Math.Max(WD, WC);
  //LMax := Math.Max(LMax, WS);
  //LMax := Math.Max(LMax, WK);
  TBenchmarkReport.WriteStandardFooter(ALogProc, LMax);
end;

end.
