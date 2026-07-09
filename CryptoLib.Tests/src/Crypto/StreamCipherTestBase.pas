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

unit StreamCipherTestBase;

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIStreamCipher,
  ClpIBulkStreamCipher,
  ClpICipherParameters,
  ClpKeyParameter,
  ClpIKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  TStreamCipherFactory = function: IStreamCipher;

  /// <summary>
  /// Base for the Salsa/ChaCha stream-cipher suites. A concrete suite supplies an
  /// engine factory + label + key/nonce sizes; the reusable runners below cover the
  /// engine-agnostic properties (whole-vs-chunked, ProcessBytes-vs-ReturnByte,
  /// bulk-vs-single-block). Concrete suites add their own KAT vectors.
  /// </summary>
  TStreamCipherTestBase = class(TCryptoLibAlgorithmTestCase)
  strict protected
    function GetEngineFactory: TStreamCipherFactory; virtual; abstract;
    function EngineLabel: String; virtual; abstract;
    function KeySizeInBytes: Int32; virtual; abstract;
    function NonceSizeInBytes: Int32; virtual; abstract;

    function SampleBytes(ALen, ASeed: Int32): TBytes;
    function InitEngine(const ACreateEngine: TStreamCipherFactory;
      const AKey, ANonce: TBytes): IStreamCipher;

    // Reusable property checks, each taking the factory + label (house pattern).
    procedure RunWholeVsChunked(const ACreateEngine: TStreamCipherFactory;
      const AEngineLabel: String);
    procedure RunProcessBytesVsReturnByte(const ACreateEngine: TStreamCipherFactory;
      const AEngineLabel: String);
    procedure RunBulkBlocksVsSingleBlock(const ACreateEngine: TStreamCipherFactory;
      const AEngineLabel: String);
  published
    procedure TestWholeVsChunked;
    procedure TestProcessBytesVsReturnByte;
    procedure TestBulkBlocksVsSingleBlock;
  end;

implementation

{ TStreamCipherTestBase }

function TStreamCipherTestBase.SampleBytes(ALen, ASeed: Int32): TBytes;
var
  LI: Int32;
begin
  System.SetLength(Result, ALen);
  for LI := 0 to ALen - 1 do
    Result[LI] := Byte((LI * ASeed + (ASeed shr 1)) and $FF);
end;

function TStreamCipherTestBase.InitEngine(
  const ACreateEngine: TStreamCipherFactory; const AKey, ANonce: TBytes): IStreamCipher;
begin
  Result := ACreateEngine();
  Result.Init(True, TParametersWithIV.Create(
    TKeyParameter.Create(AKey) as IKeyParameter, ANonce) as IParametersWithIV);
end;

// Processing a buffer in one call must equal processing it in ragged chunks.
procedure TStreamCipherTestBase.RunWholeVsChunked(
  const ACreateEngine: TStreamCipherFactory; const AEngineLabel: String);
const
  LTotal = 1500;
var
  LKey, LNonce, LIn, LWhole, LChunk: TBytes;
  LEng: IStreamCipher;
  LOff, LStep: Int32;
begin
  LKey := SampleBytes(KeySizeInBytes, 7);
  LNonce := SampleBytes(NonceSizeInBytes, 11);
  LIn := SampleBytes(LTotal, 31);
  System.SetLength(LWhole, LTotal);
  System.SetLength(LChunk, LTotal);

  LEng := InitEngine(ACreateEngine, LKey, LNonce);
  LEng.ProcessBytes(LIn, 0, LTotal, LWhole, 0);

  LEng := InitEngine(ACreateEngine, LKey, LNonce);
  LOff := 0;
  LStep := 1;
  while LOff < LTotal do
  begin
    if LStep > (LTotal - LOff) then
      LStep := LTotal - LOff;
    LEng.ProcessBytes(LIn, LOff, LStep, LChunk, LOff);
    LOff := LOff + LStep;
    LStep := LStep + 7; // ragged, block-straddling chunk sizes
  end;

  if not AreEqual(LWhole, LChunk) then
    Fail(Format('%s: whole vs chunked ProcessBytes mismatch', [AEngineLabel]));
end;

// ProcessBytes over the whole buffer must equal ReturnByte one byte at a time.
procedure TStreamCipherTestBase.RunProcessBytesVsReturnByte(
  const ACreateEngine: TStreamCipherFactory; const AEngineLabel: String);
const
  LTotal = 517;
var
  LKey, LNonce, LIn, LBulk, LByByte: TBytes;
  LEng: IStreamCipher;
  LI: Int32;
begin
  LKey := SampleBytes(KeySizeInBytes, 7);
  LNonce := SampleBytes(NonceSizeInBytes, 11);
  LIn := SampleBytes(LTotal, 31);
  System.SetLength(LBulk, LTotal);
  System.SetLength(LByByte, LTotal);

  LEng := InitEngine(ACreateEngine, LKey, LNonce);
  LEng.ProcessBytes(LIn, 0, LTotal, LBulk, 0);

  LEng := InitEngine(ACreateEngine, LKey, LNonce);
  for LI := 0 to LTotal - 1 do
    LByByte[LI] := LEng.ReturnByte(LIn[LI]);

  if not AreEqual(LBulk, LByByte) then
    Fail(Format('%s: ProcessBytes vs ReturnByte mismatch', [AEngineLabel]));
end;

// IBulkStreamCipher.ProcessBlocks(N) must equal N single 64B block transforms.
procedure TStreamCipherTestBase.RunBulkBlocksVsSingleBlock(
  const ACreateEngine: TStreamCipherFactory; const AEngineLabel: String);
const
  LCounts: array [0 .. 9] of Int32 = (1, 2, 3, 4, 5, 7, 8, 9, 16, 33);
var
  LKey, LNonce, LIn, LBulkOut, LRefOut: TBytes;
  LBulk: IBulkStreamCipher;
  LRef: IStreamCipher;
  LCount, LLen, LOff: Int32;
begin
  if not Supports(ACreateEngine(), IBulkStreamCipher) then
    Exit; // engine has no bulk fast path; nothing to compare

  LKey := SampleBytes(KeySizeInBytes, 7);
  LNonce := SampleBytes(NonceSizeInBytes, 11);
  for LCount in LCounts do
  begin
    LLen := LCount * 64;
    LIn := SampleBytes(LLen, 31);
    System.SetLength(LBulkOut, LLen);
    System.SetLength(LRefOut, LLen);

    LBulk := InitEngine(ACreateEngine, LKey, LNonce) as IBulkStreamCipher;
    LBulk.ProcessBlocks(LIn, 0, LCount, LBulkOut, 0);

    LRef := InitEngine(ACreateEngine, LKey, LNonce);
    LOff := 0;
    while LOff < LLen do
    begin
      LRef.ProcessBytes(LIn, LOff, 64, LRefOut, LOff);
      LOff := LOff + 64;
    end;

    if not AreEqual(LBulkOut, LRefOut) then
      Fail(Format('%s: ProcessBlocks(%d) vs single-block mismatch',
        [AEngineLabel, LCount]));
  end;
end;

procedure TStreamCipherTestBase.TestWholeVsChunked;
begin
  RunWholeVsChunked(GetEngineFactory(), EngineLabel);
end;

procedure TStreamCipherTestBase.TestProcessBytesVsReturnByte;
begin
  RunProcessBytesVsReturnByte(GetEngineFactory(), EngineLabel);
end;

procedure TStreamCipherTestBase.TestBulkBlocksVsSingleBlock;
begin
  RunBulkBlocksVsSingleBlock(GetEngineFactory(), EngineLabel);
end;

end.
