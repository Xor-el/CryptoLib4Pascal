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

unit CipherPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}

{$SCOPEDENUMS ON}

interface

uses
  SysUtils,
  BenchmarkCommon,
  ClpICipherParameters;

type
  { Dispatches runner construction and ciphertext pre-build inside RunRow.
    Buffered rows route through TCipherUtilities; GcmSiv rows drive
    TGcmSivBlockCipher directly (SIV is not registered in CipherUtilities
    and its two-pass ProcessBytes/DoFinal contract differs). }
  TCipherBenchKind = (Buffered, GcmSiv);

  TCipherBenchRowSpec = record
    Algorithm: String;
    RowLabel: String;
    KeyByteCount: Int32;
    IvOrNonceByteCount: Int32;
    { When > 0: TAeadParameters with this MAC size in bits. When 0: TParametersWithIV + CreateKeyParameter. }
    AeadMacBitLength: Int32;
    { Non-AEAD: CreateKeyParameter name. AEAD: empty = raw TKeyParameter; non-empty = CreateKeyParameter. }
    KeyParameterAlgorithm: String;
    Kind: TCipherBenchKind;
  end;

  TCipherPerformanceBenchmark = class sealed(TObject)
  strict private
    class function BuildCipherHeaderSizeLine(const ASizes: array of Int32;
      AValueW: Int32): String;
    class function BuildCipherHeaderEncDecLine(AColumnCount: Int32;
      AValueW: Int32): String;
    class function BuildCipherCombinedRow(const ALabel: String;
      const AEncRates, ADecRates: array of Double; AValueW: Int32): String;
    class procedure ValidateSpec(const ASpec: TCipherBenchRowSpec);
    class procedure RunRow(ALogProc: TBenchmarkLogProc;
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
  ClpAeadParameters,
  ClpIGcmSivBlockCipher,
  ClpGcmSivBlockCipher;

const
  { Unified row table. Each entry's Kind picks the runner / ciphertext-prebuild
    strategy inside RunRow. Ordering mirrors the report layout: AES AEAD
    family, AES block-chained modes, AES ECB control (bounds the bulk-engine
    ceiling), stream ciphers, then AES-256-GCM-SIV (unregistered in
    TCipherUtilities, driven through TGcmSivBlockCipher directly), then
    Blowfish at the end so its 64-bit block size does not sit next to the
    AES-128 bulk rows where a side-by-side cell comparison would mislead. }
  CIPHER_BENCH_ROWS: array [0 .. 12] of TCipherBenchRowSpec = (
    (Algorithm: 'AES/GCM/NOPADDING'; RowLabel: 'AES-256-GCM';
    KeyByteCount: 32; IvOrNonceByteCount: 12; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/CCM/NOPADDING'; RowLabel: 'AES-256-CCM';
    KeyByteCount: 32; IvOrNonceByteCount: 12; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/EAX/NOPADDING'; RowLabel: 'AES-256-EAX';
    KeyByteCount: 32; IvOrNonceByteCount: 16; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/OCB/NOPADDING'; RowLabel: 'AES-256-OCB';
    KeyByteCount: 32; IvOrNonceByteCount: 12; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/CBC/PKCS7PADDING'; RowLabel: 'AES-256-CBC + PKCS7';
    KeyByteCount: 32; IvOrNonceByteCount: 16; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'AES256'; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/CTS/NOPADDING'; RowLabel: 'AES-256-CBC + CTS';
    KeyByteCount: 32; IvOrNonceByteCount: 16; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'AES256'; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/CFB/NOPADDING'; RowLabel: 'AES-256-CFB';
    KeyByteCount: 32; IvOrNonceByteCount: 16; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'AES256'; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/CTR/NOPADDING'; RowLabel: 'AES-256-CTR';
    KeyByteCount: 32; IvOrNonceByteCount: 16; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'AES256'; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/ECB/NOPADDING'; RowLabel: 'AES-256-ECB (control)';
    KeyByteCount: 32; IvOrNonceByteCount: 0; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'AES256'; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'CHACHA20-POLY1305'; RowLabel: 'ChaCha20-Poly1305';
    KeyByteCount: 32; IvOrNonceByteCount: 12; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'SALSA20'; RowLabel: 'Salsa20 (256-bit key)';
    KeyByteCount: 32; IvOrNonceByteCount: 8; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'SALSA20'; Kind: TCipherBenchKind.Buffered),
    (Algorithm: 'AES/GCM-SIV'; RowLabel: 'AES-256-GCM-SIV';
    KeyByteCount: 32; IvOrNonceByteCount: 12; AeadMacBitLength: 128;
    KeyParameterAlgorithm: ''; Kind: TCipherBenchKind.GcmSiv),
    (Algorithm: 'BLOWFISH/CBC/PKCS7PADDING';
    RowLabel: 'Blowfish-CBC + PKCS7 (128-bit key)';
    KeyByteCount: 16; IvOrNonceByteCount: 8; AeadMacBitLength: 0;
    KeyParameterAlgorithm: 'BLOWFISH'; Kind: TCipherBenchKind.Buffered));

type
  { Shared abstract base for every row's encrypt / decrypt runner. Holds the
    per-iteration output buffer; subclasses supply the Init + ProcessBytes +
    DoFinal sequence that matches their cipher's handoff contract. }
  TCipherBenchRunner = class abstract
  protected
    FOut: TBytes;
  public
    procedure RunOnce; virtual; abstract;
  end;

  TBufferedCipherEncryptRunner = class(TCipherBenchRunner)
  private
    FSpec: TCipherBenchRowSpec;
    FKey: TBytes;
    FIv: TBytes;
    FPlain: TBytes;
    FPlainLen: Int32;
    FCipher: IBufferedCipher;
  public
    constructor Create(const ASpec: TCipherBenchRowSpec; const AKey: TBytes;
      const APlain: TBytes; APlainLen: Int32);
    procedure RunOnce; override;
  end;

  TBufferedCipherDecryptRunner = class(TCipherBenchRunner)
  private
    FAlgorithm: String;
    FParams: ICipherParameters;
    FCipherText: TBytes;
    FCipherLen: Int32;
    FCipher: IBufferedCipher;
  public
    constructor Create(const AAlgorithm: String;
      const AParams: ICipherParameters;
      const ACipherText: TBytes; ACipherLen: Int32);
    procedure RunOnce; override;
  end;

  { GCM-SIV is not registered in TCipherUtilities, so these runners wrap
    TGcmSivBlockCipher directly. The cipher buffers the entire plaintext
    until DoFinal (see ClpGcmSivBlockCipher.pas; SIV mode requires two passes
    over the input), so ProcessBytes is invoked with a nil output buffer and
    DoFinal emits the full ciphertext-plus-tag in one shot. This matches the
    usage pattern documented by the GcmSiv test harness. }
  TGcmSivEncryptRunner = class(TCipherBenchRunner)
  private
    FSpec: TCipherBenchRowSpec;
    FKey: TBytes;
    FNonce: TBytes;
    FPlain: TBytes;
    FPlainLen: Int32;
    FCipher: IGcmSivBlockCipher;
    FKeyParam: IKeyParameter;
  public
    constructor Create(const ASpec: TCipherBenchRowSpec;
      const AKey, APlain: TBytes; APlainLen: Int32);
    procedure RunOnce; override;
  end;

  TGcmSivDecryptRunner = class(TCipherBenchRunner)
  private
    FParams: ICipherParameters;
    FCipherText: TBytes;
    FCipherLen: Int32;
    FCipher: IGcmSivBlockCipher;
  public
    constructor Create(const AParams: ICipherParameters;
      const ACipherText: TBytes; ACipherLen: Int32);
    procedure RunOnce; override;
  end;

function BuildBenchCipherParams(const ASpec: TCipherBenchRowSpec;
  const AKey, AIvOrNonce: TBytes): ICipherParameters;
var
  LKeyParam: IKeyParameter;
begin
  if ASpec.AeadMacBitLength > 0 then
  begin
    if ASpec.KeyParameterAlgorithm = '' then
      LKeyParam := TKeyParameter.Create(AKey)
    else
      LKeyParam := TParameterUtilities.CreateKeyParameter(
        ASpec.KeyParameterAlgorithm, AKey);
    Result := TAeadParameters.Create(LKeyParam, ASpec.AeadMacBitLength,
      AIvOrNonce, nil);
  end
  else if ASpec.IvOrNonceByteCount = 0 then
    // ECB-style rows: the IBufferedCipher pipeline unwraps TParametersWithIV
    // down to IKeyParameter before calling the engine, but a raw key-parameter
    // is the simpler, IV-free path here. The 0-byte IV case is only reachable
    // on the explicit ECB row; every chained/AEAD mode rejects it earlier.
    Result := TParameterUtilities.CreateKeyParameter(
      ASpec.KeyParameterAlgorithm, AKey)
  else
    Result := TParametersWithIV.Create(
      TParameterUtilities.CreateKeyParameter(ASpec.KeyParameterAlgorithm, AKey),
      AIvOrNonce);
end;

function BufferedEncryptPlainToBytes(const AAlgorithm: String;
  const AParams: ICipherParameters;
  const APlain: TBytes; APlainLen: Int32): TBytes;
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

function GcmSivEncryptPlainToBytes(const AParams: ICipherParameters;
  const APlain: TBytes; APlainLen: Int32): TBytes;
var
  LCipher: IGcmSivBlockCipher;
begin
  LCipher := TGcmSivBlockCipher.Create();
  LCipher.Init(True, AParams);
  System.SetLength(Result, LCipher.GetOutputSize(APlainLen));
  // SIV buffers all plaintext internally; DoFinal emits ct+tag in one shot.
  LCipher.ProcessBytes(APlain, 0, APlainLen, nil, 0);
  LCipher.DoFinal(Result, 0);
end;

function MakeEncryptRunner(const ASpec: TCipherBenchRowSpec;
  const AKey, APlain: TBytes; APlainLen: Int32): TCipherBenchRunner;
begin
  case ASpec.Kind of
    TCipherBenchKind.Buffered:
      Result := TBufferedCipherEncryptRunner.Create(ASpec, AKey, APlain,
        APlainLen);
    TCipherBenchKind.GcmSiv:
      Result := TGcmSivEncryptRunner.Create(ASpec, AKey, APlain, APlainLen);
  else
    // Unreachable; every TCipherBenchKind value is handled above.
    Result := nil;
  end;
end;

function MakeDecryptRunner(const ASpec: TCipherBenchRowSpec;
  const AParams: ICipherParameters;
  const ACipherText: TBytes; ACipherLen: Int32): TCipherBenchRunner;
begin
  case ASpec.Kind of
    TCipherBenchKind.Buffered:
      Result := TBufferedCipherDecryptRunner.Create(ASpec.Algorithm, AParams,
        ACipherText, ACipherLen);
    TCipherBenchKind.GcmSiv:
      Result := TGcmSivDecryptRunner.Create(AParams, ACipherText, ACipherLen);
  else
    Result := nil;
  end;
end;

function EncryptPlainToCipherFor(const ASpec: TCipherBenchRowSpec;
  const AParams: ICipherParameters;
  const APlain: TBytes; APlainLen: Int32): TBytes;
begin
  case ASpec.Kind of
    TCipherBenchKind.Buffered:
      Result := BufferedEncryptPlainToBytes(ASpec.Algorithm, AParams, APlain,
        APlainLen);
    TCipherBenchKind.GcmSiv:
      Result := GcmSivEncryptPlainToBytes(AParams, APlain, APlainLen);
  else
    System.SetLength(Result, 0);
  end;
end;

function MeasureRunnerMbPerSec(ARunner: TCipherBenchRunner;
  ABytes: Int32): Double;
begin
  try
    Result := TBenchmarkTiming.MeasureThroughputMbPerSec(ARunner.RunOnce,
      ABytes);
  finally
    ARunner.Free;
  end;
end;

{ TBufferedCipherEncryptRunner }

constructor TBufferedCipherEncryptRunner.Create(
  const ASpec: TCipherBenchRowSpec; const AKey: TBytes; const APlain: TBytes;
  APlainLen: Int32);
var
  LProbeParams: ICipherParameters;
  LIvProbe: TBytes;
begin
  inherited Create;
  FSpec := ASpec;
  FKey := AKey;
  FPlain := APlain;
  FPlainLen := APlainLen;
  System.SetLength(FIv, ASpec.IvOrNonceByteCount);
  // Hoist cipher acquisition and output-buffer sizing out of the timed loop. The cipher
  // is looked up once via the registry; Init is called once here to size the output buffer
  // (re-Init happens per-iteration with a fresh nonce). For AEAD modes (e.g. GCM) the
  // per-iteration Init swaps in the new nonce, so no AEAD nonce reuse occurs at the boundary.
  FCipher := TCipherUtilities.GetCipher(FSpec.Algorithm);
  System.SetLength(LIvProbe, ASpec.IvOrNonceByteCount);
  LProbeParams := BuildBenchCipherParams(FSpec, FKey, LIvProbe);
  FCipher.Init(True, LProbeParams);
  System.SetLength(FOut, FCipher.GetOutputSize(FPlainLen));
end;

procedure TBufferedCipherEncryptRunner.RunOnce;
var
  LParams: ICipherParameters;
  Ln: Int32;
begin
  for Ln := 0 to System.High(FIv) do
    FIv[Ln] := Byte(Random(256));
  LParams := BuildBenchCipherParams(FSpec, FKey, FIv);
  FCipher.Init(True, LParams);
  Ln := FCipher.ProcessBytes(FPlain, 0, FPlainLen, FOut, 0);
  FCipher.DoFinal(FOut, Ln);
end;

{ TBufferedCipherDecryptRunner }

constructor TBufferedCipherDecryptRunner.Create(const AAlgorithm: String;
  const AParams: ICipherParameters; const ACipherText: TBytes;
  ACipherLen: Int32);
begin
  inherited Create;
  FAlgorithm := AAlgorithm;
  FParams := AParams;
  FCipherText := ACipherText;
  FCipherLen := ACipherLen;
  FCipher := TCipherUtilities.GetCipher(FAlgorithm);
  FCipher.Init(False, FParams);
  System.SetLength(FOut, FCipher.GetOutputSize(FCipherLen));
end;

procedure TBufferedCipherDecryptRunner.RunOnce;
var
  Ln: Int32;
begin
  FCipher.Init(False, FParams);
  Ln := FCipher.ProcessBytes(FCipherText, 0, FCipherLen, FOut, 0);
  FCipher.DoFinal(FOut, Ln);
end;

{ TGcmSivEncryptRunner }

constructor TGcmSivEncryptRunner.Create(const ASpec: TCipherBenchRowSpec;
  const AKey, APlain: TBytes; APlainLen: Int32);
var
  LParams: ICipherParameters;
begin
  inherited Create;
  FSpec := ASpec;
  FKey := AKey;
  FPlain := APlain;
  FPlainLen := APlainLen;
  System.SetLength(FNonce, ASpec.IvOrNonceByteCount);
  FKeyParam := TKeyParameter.Create(AKey);
  FCipher := TGcmSivBlockCipher.Create();
  // Probe Init with a zero nonce to size FOut; per-iteration RunOnce will
  // re-Init with a freshly randomised nonce so the steady-state cost reflects
  // realistic SIV-family usage (no nonce reuse at the benchmark boundary).
  LParams := TAeadParameters.Create(FKeyParam, FSpec.AeadMacBitLength,
    FNonce, nil);
  FCipher.Init(True, LParams);
  System.SetLength(FOut, FCipher.GetOutputSize(FPlainLen));
end;

procedure TGcmSivEncryptRunner.RunOnce;
var
  Ln: Int32;
  LParams: ICipherParameters;
begin
  for Ln := 0 to System.High(FNonce) do
    FNonce[Ln] := Byte(Random(256));
  LParams := TAeadParameters.Create(FKeyParam, FSpec.AeadMacBitLength,
    FNonce, nil);
  FCipher.Init(True, LParams);
  // GCM-SIV buffers the entire plaintext internally; pass nil for the
  // intermediate output and let DoFinal emit the full ciphertext + tag.
  FCipher.ProcessBytes(FPlain, 0, FPlainLen, nil, 0);
  FCipher.DoFinal(FOut, 0);
end;

{ TGcmSivDecryptRunner }

constructor TGcmSivDecryptRunner.Create(const AParams: ICipherParameters;
  const ACipherText: TBytes; ACipherLen: Int32);
begin
  inherited Create;
  FParams := AParams;
  FCipherText := ACipherText;
  FCipherLen := ACipherLen;
  FCipher := TGcmSivBlockCipher.Create();
  FCipher.Init(False, FParams);
  System.SetLength(FOut, FCipher.GetOutputSize(FCipherLen));
end;

procedure TGcmSivDecryptRunner.RunOnce;
begin
  FCipher.Init(False, FParams);
  FCipher.ProcessBytes(FCipherText, 0, FCipherLen, nil, 0);
  FCipher.DoFinal(FOut, 0);
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

class procedure TCipherPerformanceBenchmark.ValidateSpec(
  const ASpec: TCipherBenchRowSpec);
begin
  Assert(ASpec.KeyByteCount > 0,
    'Cipher benchmark: KeyByteCount must be positive.');
  // IvOrNonceByteCount = 0 is only valid on non-AEAD rows (ECB control); AEAD
  // modes always carry a nonce, so the asymmetric assertion catches a
  // mis-specified AEAD row before the TAeadParameters constructor masks the
  // bug with an opaque "nonce length" error.
  Assert((ASpec.IvOrNonceByteCount > 0) or
    ((ASpec.AeadMacBitLength = 0) and (ASpec.IvOrNonceByteCount = 0)),
    'Cipher benchmark: IvOrNonceByteCount must be positive except for ECB-style rows.');
  if ASpec.AeadMacBitLength = 0 then
    Assert(ASpec.KeyParameterAlgorithm <> '',
      'Cipher benchmark: KeyParameterAlgorithm required for non-AEAD rows.');
end;

class procedure TCipherPerformanceBenchmark.RunRow(ALogProc: TBenchmarkLogProc;
  const ASpec: TCipherBenchRowSpec;
  const AEncSizes, ADecSizes: array of Int32; AValueW: Int32);
var
  LKey, LPlain, LIvOrNonce, LCt: TBytes;
  Li: Int32;
  LParams: ICipherParameters;
  LEncRates, LDecRates: array of Double;
begin
  ValidateSpec(ASpec);

  BenchAllocRandom(ASpec.KeyByteCount, LKey);
  System.SetLength(LEncRates, System.Length(AEncSizes));
  System.SetLength(LDecRates, System.Length(ADecSizes));

  for Li := System.Low(AEncSizes) to System.High(AEncSizes) do
  begin
    BenchAllocRandom(AEncSizes[Li], LPlain);
    LEncRates[Li] := MeasureRunnerMbPerSec(
      MakeEncryptRunner(ASpec, LKey, LPlain, AEncSizes[Li]), AEncSizes[Li]);
  end;

  for Li := System.Low(ADecSizes) to System.High(ADecSizes) do
  begin
    BenchAllocRandom(ADecSizes[Li], LPlain);
    BenchAllocRandom(ASpec.IvOrNonceByteCount, LIvOrNonce);
    LParams := BuildBenchCipherParams(ASpec, LKey, LIvOrNonce);
    LCt := EncryptPlainToCipherFor(ASpec, LParams, LPlain, ADecSizes[Li]);
    LDecRates[Li] := MeasureRunnerMbPerSec(
      MakeDecryptRunner(ASpec, LParams, LCt, System.Length(LCt)),
      System.Length(LCt));
  end;

  ALogProc(BuildCipherCombinedRow(ASpec.RowLabel, LEncRates, LDecRates,
    AValueW));
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
    RunRow(ALogProc, CIPHER_BENCH_ROWS[Li], AEncSizes, ADecSizes, LValueW);

  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

end.
