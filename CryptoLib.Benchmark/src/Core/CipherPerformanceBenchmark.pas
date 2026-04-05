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

unit CipherPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

interface

uses
  SysUtils,
  BenchmarkCommon,
  ClpICipherParameters;

type
  TCipherBenchRowSpec = record
    Algorithm: String;
    RowLabel: String;
    KeyByteCount: Int32;
    IvOrNonceByteCount: Int32;
    { When > 0: TAeadParameters with this MAC size in bits. When 0: TParametersWithIV + CreateKeyParameter. }
    AeadMacBitLength: Int32;
    { Non-AEAD: CreateKeyParameter name. AEAD: empty = raw TKeyParameter; non-empty = CreateKeyParameter. }
    KeyParameterAlgorithm: String;
  end;

  TCipherPerformanceBenchmark = class sealed(TObject)
  strict private
    class function BuildCipherHeaderSizeLine(const ASizes: array of Int32;
      AValueW: Int32): String;
    class function BuildCipherHeaderEncDecLine(AColumnCount: Int32;
      AValueW: Int32): String;
    class function BuildCipherCombinedRow(const ALabel: String;
      const AEncRates, ADecRates: array of Double; AValueW: Int32): String;
    class function EncryptPlainToCipher(const AAlgorithm: String;
      const AParams: ICipherParameters; const APlain: TBytes)
      : TBytes;
    class function MeasureEncryptMbPerSec(const ASpec: TCipherBenchRowSpec;
      const AKey: TBytes; const APlain: TBytes; APlainLen: Int32): Double;
    class function MeasureDecryptMbPerSec(const AAlgorithm: String;
      const AParams: ICipherParameters;
      const ACipherText: TBytes; ACipherLen: Int32): Double;
    class procedure RunBufferedCipherEncDecRow(ALogProc: TBenchmarkLogProc;
      const ASpec: TCipherBenchRowSpec;
      const AEncSizes, ADecSizes: array of Int32; AValueW: Int32);
  public
    class function Run(ALogProc: TBenchmarkLogProc;
      const AEncSizes, ADecSizes: array of Int32): Int32;
  end;

implementation

uses
  Math,
  ClpIBufferedCipher,
  ClpCipherUtilities,
  ClpParameterUtilities,
  ClpParametersWithIV,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpAeadParameters;

const
  CIPHER_BENCH_ROWS: array [0 .. 4] of TCipherBenchRowSpec = (
    (Algorithm: 'AES/GCM/NOPADDING'; RowLabel: 'AES-256-GCM';
    KeyByteCount: 32; IvOrNonceByteCount: 12; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''),
    (Algorithm: 'AES/CBC/PKCS7PADDING'; RowLabel: 'AES-256-CBC + PKCS7';
    KeyByteCount: 32; IvOrNonceByteCount: 16; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'AES256'),
    (Algorithm: 'CHACHA20-POLY1305'; RowLabel: 'ChaCha20-Poly1305';
    KeyByteCount: 32; IvOrNonceByteCount: 12; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''),
    (Algorithm: 'SALSA20'; RowLabel: 'Salsa20 (256-bit key)';
    KeyByteCount: 32; IvOrNonceByteCount: 8; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'SALSA20'),
    (Algorithm: 'BLOWFISH/CBC/PKCS7PADDING'; RowLabel: 'Blowfish-CBC + PKCS7 (128-bit key)';
    KeyByteCount: 16; IvOrNonceByteCount: 8; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'BLOWFISH'));

type
  TCipherEncryptRunner = class
  private
    FSpec: TCipherBenchRowSpec;
    FKey: TBytes;
    FIv: TBytes;
    FPlain: TBytes;
    FPlainLen: Int32;
    FOut: TBytes;
  public
    constructor Create(const ASpec: TCipherBenchRowSpec; const AKey: TBytes;
      const APlain: TBytes; APlainLen: Int32);
    procedure RunOnce;
  end;

  TCipherDecryptRunner = class
  private
    FAlgorithm: String;
    FParams: ICipherParameters;
    FCipherText: TBytes;
    FCipherLen: Int32;
    FOut: TBytes;
  public
    constructor Create(const AAlgorithm: String; const AParams: ICipherParameters;
      const ACipherText: TBytes; ACipherLen: Int32);
    procedure RunOnce;
  end;

function BuildBenchCipherParams(const ASpec: TCipherBenchRowSpec;
  const AKey, AIvOrNonce: TBytes): ICipherParameters;
var
  LKeyParam: IKeyParameter;
begin
  if ASpec.AeadMacBitLength > 0 then
  begin
    if ASpec.KeyParameterAlgorithm = '' then
      LKeyParam := TKeyParameter.Create(AKey) as IKeyParameter
    else
      LKeyParam := TParameterUtilities.CreateKeyParameter(
        ASpec.KeyParameterAlgorithm, AKey);
    Result := TAeadParameters.Create(LKeyParam, ASpec.AeadMacBitLength,
      AIvOrNonce, nil);
  end
  else
    Result := TParametersWithIV.Create(
      TParameterUtilities.CreateKeyParameter(ASpec.KeyParameterAlgorithm, AKey),
      AIvOrNonce);
end;

function BufferedEncryptPlainToBytes(const AAlgorithm: String;
  const AParams: ICipherParameters; const APlain: TBytes; APlainLen: Int32): TBytes;
var
  LCipher: IBufferedCipher;
  Ln: Int32;
begin
  LCipher := TCipherUtilities.GetCipher(AAlgorithm);
  LCipher.Init(True, AParams);
  System.SetLength(Result, LCipher.GetOutputSize(APlainLen));
  Ln := LCipher.ProcessBytes(APlain, 0, APlainLen, Result, 0);
  Ln := Ln + LCipher.DoFinal(Result, Ln);
  if Ln <> System.Length(Result) then
    System.SetLength(Result, Ln);
end;

{ TCipherEncryptRunner }

constructor TCipherEncryptRunner.Create(const ASpec: TCipherBenchRowSpec;
  const AKey: TBytes; const APlain: TBytes; APlainLen: Int32);
begin
  inherited Create;
  FSpec := ASpec;
  FKey := AKey;
  FPlain := APlain;
  FPlainLen := APlainLen;
  System.SetLength(FIv, ASpec.IvOrNonceByteCount);
end;

procedure TCipherEncryptRunner.RunOnce;
var
  LParams: ICipherParameters;
  Ln: Int32;
begin
  for Ln := 0 to System.High(FIv) do
    FIv[Ln] := Byte(Random(256));
  LParams := BuildBenchCipherParams(FSpec, FKey, FIv);
  FOut := BufferedEncryptPlainToBytes(FSpec.Algorithm, LParams, FPlain,
    FPlainLen);
end;

{ TCipherDecryptRunner }

constructor TCipherDecryptRunner.Create(const AAlgorithm: String;
  const AParams: ICipherParameters; const ACipherText: TBytes;
  ACipherLen: Int32);
begin
  inherited Create;
  FAlgorithm := AAlgorithm;
  FParams := AParams;
  FCipherText := ACipherText;
  FCipherLen := ACipherLen;
  FOut := nil;
end;

procedure TCipherDecryptRunner.RunOnce;
var
  LCipher: IBufferedCipher;
  Ln, LNeed: Int32;
begin
  LCipher := TCipherUtilities.GetCipher(FAlgorithm);
  LCipher.Init(False, FParams);
  LNeed := LCipher.GetOutputSize(FCipherLen);
  System.SetLength(FOut, LNeed);
  Ln := LCipher.ProcessBytes(FCipherText, 0, FCipherLen, FOut, 0);
  Ln := Ln + LCipher.DoFinal(FOut, Ln);
  if Ln <> System.Length(FOut) then
    System.SetLength(FOut, Ln);
end;

{ TCipherPerformanceBenchmark }

class function TCipherPerformanceBenchmark.BuildCipherHeaderSizeLine(
  const ASizes: array of Int32; AValueW: Int32): String;
begin
  Result := TBenchmarkReport.BuildHeaderRowForBufferSizes('Cipher / mode', ASizes,
    AValueW);
end;

class function TCipherPerformanceBenchmark.BuildCipherHeaderEncDecLine(
  AColumnCount: Int32; AValueW: Int32): String;
var
  LLabels: array of String;
  Li: Int32;
begin
  System.SetLength(LLabels, AColumnCount);
  for Li := 0 to AColumnCount - 1 do
    LLabels[Li] := 'E / D';
  Result := TBenchmarkReport.BuildHeaderRow('', LLabels, AValueW);
end;

class function TCipherPerformanceBenchmark.BuildCipherCombinedRow(
  const ALabel: String; const AEncRates, ADecRates: array of Double;
  AValueW: Int32): String;
var
  LCells: array of String;
  Lj: Int32;
begin
  System.SetLength(LCells, System.Length(AEncRates));
  for Lj := System.Low(AEncRates) to System.High(AEncRates) do
    LCells[Lj] := TBenchmarkFormat.FormatThroughputEncDecMbPerPair(
      AEncRates[Lj], ADecRates[Lj]);
  Result := TBenchmarkReport.BuildDataRow(ALabel, LCells, AValueW);
end;

class function TCipherPerformanceBenchmark.EncryptPlainToCipher(
  const AAlgorithm: String; const AParams: ICipherParameters;
  const APlain: TBytes): TBytes;
begin
  Result := BufferedEncryptPlainToBytes(AAlgorithm, AParams, APlain,
    System.Length(APlain));
end;

class function TCipherPerformanceBenchmark.MeasureEncryptMbPerSec(
  const ASpec: TCipherBenchRowSpec; const AKey: TBytes; const APlain: TBytes;
  APlainLen: Int32): Double;
var
  LRunner: TCipherEncryptRunner;
begin
  LRunner := TCipherEncryptRunner.Create(ASpec, AKey, APlain, APlainLen);
  try
    Result := TBenchmarkTiming.MeasureThroughputMbPerSec(LRunner.RunOnce,
      APlainLen);
  finally
    LRunner.Free;
  end;
end;

class function TCipherPerformanceBenchmark.MeasureDecryptMbPerSec(
  const AAlgorithm: String; const AParams: ICipherParameters;
  const ACipherText: TBytes; ACipherLen: Int32): Double;
var
  LRunner: TCipherDecryptRunner;
begin
  LRunner := TCipherDecryptRunner.Create(AAlgorithm, AParams, ACipherText,
    ACipherLen);
  try
    Result := TBenchmarkTiming.MeasureThroughputMbPerSec(LRunner.RunOnce,
      ACipherLen);
  finally
    LRunner.Free;
  end;
end;

class procedure TCipherPerformanceBenchmark.RunBufferedCipherEncDecRow(
  ALogProc: TBenchmarkLogProc; const ASpec: TCipherBenchRowSpec;
  const AEncSizes, ADecSizes: array of Int32; AValueW: Int32);
var
  LKey, LPlain, LIvOrNonce, LCt: TBytes;
  Li: Int32;
  LParams: ICipherParameters;
  LEncRates, LDecRates: array of Double;
begin
  Assert(ASpec.KeyByteCount > 0,
    'Cipher benchmark: KeyByteCount must be positive.');
  Assert(ASpec.IvOrNonceByteCount > 0,
    'Cipher benchmark: IvOrNonceByteCount must be positive.');
  if ASpec.AeadMacBitLength = 0 then
    Assert(ASpec.KeyParameterAlgorithm <> '',
      'Cipher benchmark: KeyParameterAlgorithm required for non-AEAD rows.');

  BenchAllocRandom(ASpec.KeyByteCount, LKey);
  System.SetLength(LEncRates, System.Length(AEncSizes));
  System.SetLength(LDecRates, System.Length(ADecSizes));
  System.SetLength(LIvOrNonce, ASpec.IvOrNonceByteCount);

  for Li := System.Low(AEncSizes) to System.High(AEncSizes) do
  begin
    BenchAllocRandom(AEncSizes[Li], LPlain);
    LEncRates[Li] := MeasureEncryptMbPerSec(ASpec, LKey, LPlain,
      AEncSizes[Li]);
  end;

  for Li := System.Low(ADecSizes) to System.High(ADecSizes) do
  begin
    BenchAllocRandom(ADecSizes[Li], LPlain);
    BenchFillRandom(LIvOrNonce);
    LParams := BuildBenchCipherParams(ASpec, LKey, LIvOrNonce);
    LCt := EncryptPlainToCipher(ASpec.Algorithm, LParams, LPlain);
    LDecRates[Li] := MeasureDecryptMbPerSec(ASpec.Algorithm, LParams, LCt,
      System.Length(LCt));
  end;

  ALogProc(BuildCipherCombinedRow(ASpec.RowLabel, LEncRates, LDecRates, AValueW));
end;

class function TCipherPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc;
  const AEncSizes, ADecSizes: array of Int32): Int32;
var
  LLine1, LLine2: String;
  LValueW: Int32;
  Li: Int32;
begin
  Assert(System.Length(AEncSizes) = System.Length(ADecSizes),
    'Cipher benchmark: encrypt and decrypt size grids must match.');
  LValueW := BENCH_CIPHER_COMBINED_COL_WIDTH;
  ALogProc('Symmetric cipher throughput (IBufferedCipher)');
  ALogProc('==============================================');
  ALogProc('Each column: payload size (plaintext length). Cell = encrypt MB/s / decrypt MB/s.');
  ALogProc('Decrypt rate uses ciphertext bytes per second (AEAD tag included where applicable).');
  ALogProc('');

  LLine1 := BuildCipherHeaderSizeLine(AEncSizes, LValueW);
  LLine2 := BuildCipherHeaderEncDecLine(System.Length(AEncSizes), LValueW);
  Result := Math.Max(System.Length(LLine1), System.Length(LLine2));
  ALogProc(LLine1);
  ALogProc(LLine2);
  ALogProc(TBenchmarkReport.BuildSeparator(Result));

  for Li := System.Low(CIPHER_BENCH_ROWS) to System.High(CIPHER_BENCH_ROWS) do
    RunBufferedCipherEncDecRow(ALogProc, CIPHER_BENCH_ROWS[Li], AEncSizes,
      ADecSizes, LValueW);

  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

end.
