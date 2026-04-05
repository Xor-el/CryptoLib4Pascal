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

unit SignerPerformanceBenchmark;

{$IFDEF FPC}
{$MODE DELPHI}
{$WARNINGS OFF}
{$ENDIF FPC}
{$SCOPEDENUMS ON}

interface

uses
  SysUtils,
  BenchmarkCommon,
  ClpIAsymmetricCipherKeyPair;

type
  TSignerPerformanceBenchmark = class sealed(TObject)
  strict private
    class function BuildHeaderRow(AValueW: Int32): String;
    class function BuildDataRow(const ALabel: String; AKeygenMs, ASignMs,
      AVerifyMs: Double; AValueW: Int32): String;
    class procedure BenchSignerRow(ALogProc: TBenchmarkLogProc;
      const ARowLabel, ASignerMechanism: String;
      const APair: IAsymmetricCipherKeyPair;
      const AMessage: TBytes; AKeygenMs: Double; AValueW: Int32);
  public
    class function Run(ALogProc: TBenchmarkLogProc): Int32;
  end;

implementation

uses
  ClpSecureRandom,
  ClpISecureRandom,
  ClpGeneratorUtilities,
  ClpIAsymmetricCipherKeyPairGenerator,
  ClpKeyGenerationParameters,
  ClpIKeyGenerationParameters,
  ClpSignerUtilities,
  ClpECUtilities,
  ClpISigner,
  ClpICipherParameters,
  ClpIX9ECAsn1Objects,
  ClpECParameters,
  ClpIECParameters,
  ClpEd25519Parameters,
  ClpIEd25519Parameters,
  ClpEd448Parameters,
  ClpIEd448Parameters;

const
  BENCH_SIGN_MESSAGE_BYTES = 1024;

type
  TRsaSignerBenchSpec = record
    RowLabel: String;
    Mechanism: String;
    KeyBits: Int32;
  end;

  TEcdsaBenchSpec = record
    RowLabel: String;
    CurveName: String;
  end;

  TEdDsaBenchSpec = record
    RowLabel: String;
    Mechanism: String;
  end;

  TKeygenRoute = (Rsa, Ecdsa, Edwards);

  TKeygenBenchRunner = class
  private
    FRoute: TKeygenRoute;
    FRsaKeyBits: Int32;
    FEcdsaCurve: String;
    FEdwardsMechanism: String;
  public
    class function CreateForRsa(AKeyBits: Int32): TKeygenBenchRunner; static;
    class function CreateForEcdsa(const ACurveName: String): TKeygenBenchRunner;
      static;
    class function CreateForEdwards(const AMechanism: String): TKeygenBenchRunner;
      static;
    procedure RunOnce;
  end;

  TSignRunner = class
  private
    FSignerName: String;
    FPrivateKey: ICipherParameters;
    FMessage: TBytes;
  public
    constructor Create(const ASignerName: String;
      const APrivateKey: ICipherParameters; const AMessage: TBytes);
    procedure RunOnce;
  end;

  TVerifyRunner = class
  private
    FSignerName: String;
    FPublicKey: ICipherParameters;
    FMessage: TBytes;
    FSignature: TBytes;
  public
    constructor Create(const ASignerName: String;
      const APublicKey: ICipherParameters; const AMessage,
      ASignature: TBytes);
    procedure RunOnce;
  end;

const
  RSA_SIGNER_BENCH_SPECS: array [0 .. 3] of TRsaSignerBenchSpec = (
    (RowLabel: 'SHA-256withRSA (RSA-1024)'; Mechanism: 'SHA-256withRSA';
    KeyBits: 1024),
    (RowLabel: 'SHA-256withRSA-PSS (RSA-1024)';
    Mechanism: 'SHA-256withRSAandMGF1'; KeyBits: 1024),
    (RowLabel: 'SHA-256withRSA (RSA-2048)'; Mechanism: 'SHA-256withRSA';
    KeyBits: 2048),
    (RowLabel: 'SHA-256withRSA-PSS (RSA-2048)';
    Mechanism: 'SHA-256withRSAandMGF1'; KeyBits: 2048));

  ECDSA_BENCH_SPECS: array [0 .. 1] of TEcdsaBenchSpec = (
    (RowLabel: 'ECDSA (secp256r1)'; CurveName: 'secp256r1'),
    (RowLabel: 'ECDSA (secp256k1)'; CurveName: 'secp256k1'));

  EDDSA_BENCH_SPECS: array [0 .. 1] of TEdDsaBenchSpec = (
    (RowLabel: 'Ed25519'; Mechanism: 'Ed25519'),
    (RowLabel: 'Ed448'; Mechanism: 'Ed448'));

function GenerateRsaPair(AKeyBits: Int32): IAsymmetricCipherKeyPair;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create;
  LGen := TGeneratorUtilities.GetKeyPairGenerator('RSA');
  LGen.Init(TKeyGenerationParameters.Create(LRandom, AKeyBits)
    as IKeyGenerationParameters);
  Result := LGen.GenerateKeyPair;
end;

function GenerateEcdsaPair(const ACurveName: String): IAsymmetricCipherKeyPair;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LRandom: ISecureRandom;
  LEcP: IX9ECParameters;
  LDomain: IECDomainParameters;
begin
  LRandom := TSecureRandom.Create;
  LEcP := TECUtilities.FindECCurveByName(ACurveName);
  LDomain := TECDomainParameters.Create(LEcP.Curve, LEcP.G, LEcP.N, LEcP.H,
    LEcP.GetSeed);
  LGen := TGeneratorUtilities.GetKeyPairGenerator('ECDSA');
  LGen.Init(TECKeyGenerationParameters.Create(LDomain, LRandom)
    as IECKeyGenerationParameters);
  Result := LGen.GenerateKeyPair;
end;

function GenerateEdwardsCipherPair(const AMechanism: String)
  : IAsymmetricCipherKeyPair;
var
  LGen: IAsymmetricCipherKeyPairGenerator;
  LRandom: ISecureRandom;
begin
  LRandom := TSecureRandom.Create;
  LGen := TGeneratorUtilities.GetKeyPairGenerator(AMechanism);
  if SameText(AMechanism, 'Ed25519') then
    LGen.Init(TEd25519KeyGenerationParameters.Create(LRandom)
      as IEd25519KeyGenerationParameters)
  else if SameText(AMechanism, 'Ed448') then
    LGen.Init(TEd448KeyGenerationParameters.Create(LRandom)
      as IEd448KeyGenerationParameters)
  else
    raise Exception.Create('Unknown EdDSA mechanism: ' + AMechanism);
  Result := LGen.GenerateKeyPair;
end;

{ TKeygenBenchRunner }

class function TKeygenBenchRunner.CreateForRsa(AKeyBits: Int32): TKeygenBenchRunner;
begin
  Result := TKeygenBenchRunner.Create;
  Result.FRoute := TKeygenRoute.Rsa;
  Result.FRsaKeyBits := AKeyBits;
end;

class function TKeygenBenchRunner.CreateForEcdsa(const ACurveName: String)
  : TKeygenBenchRunner;
begin
  Result := TKeygenBenchRunner.Create;
  Result.FRoute := TKeygenRoute.Ecdsa;
  Result.FEcdsaCurve := ACurveName;
end;

class function TKeygenBenchRunner.CreateForEdwards(const AMechanism: String)
  : TKeygenBenchRunner;
begin
  Result := TKeygenBenchRunner.Create;
  Result.FRoute := TKeygenRoute.Edwards;
  Result.FEdwardsMechanism := AMechanism;
end;

procedure TKeygenBenchRunner.RunOnce;
begin
  case FRoute of
    TKeygenRoute.Rsa:
      GenerateRsaPair(FRsaKeyBits);
    TKeygenRoute.Ecdsa:
      GenerateEcdsaPair(FEcdsaCurve);
    TKeygenRoute.Edwards:
      GenerateEdwardsCipherPair(FEdwardsMechanism);
  end;
end;

{ TSignRunner }

constructor TSignRunner.Create(const ASignerName: String;
  const APrivateKey: ICipherParameters; const AMessage: TBytes);
begin
  inherited Create;
  FSignerName := ASignerName;
  FPrivateKey := APrivateKey;
  FMessage := AMessage;
end;

procedure TSignRunner.RunOnce;
var
  LS: ISigner;
begin
  LS := TSignerUtilities.GetSigner(FSignerName);
  LS.Init(True, FPrivateKey);
  LS.BlockUpdate(FMessage, 0, System.Length(FMessage));
  LS.GenerateSignature;
  LS.Reset;
end;

{ TVerifyRunner }

constructor TVerifyRunner.Create(const ASignerName: String;
  const APublicKey: ICipherParameters; const AMessage,
  ASignature: TBytes);
begin
  inherited Create;
  FSignerName := ASignerName;
  FPublicKey := APublicKey;
  FMessage := AMessage;
  FSignature := ASignature;
end;

procedure TVerifyRunner.RunOnce;
var
  LS: ISigner;
begin
  LS := TSignerUtilities.GetSigner(FSignerName);
  LS.Init(False, FPublicKey);
  LS.BlockUpdate(FMessage, 0, System.Length(FMessage));
  LS.VerifySignature(FSignature);
  LS.Reset;
end;

{ TSignerPerformanceBenchmark }

class function TSignerPerformanceBenchmark.BuildHeaderRow(AValueW: Int32): String;
begin
  Result := TBenchmarkReport.BuildHeaderRow('Signer / curve',
    ['Keygen ms', 'Sign ms', 'Verify ms'], AValueW);
end;

class function TSignerPerformanceBenchmark.BuildDataRow(const ALabel: String;
  AKeygenMs, ASignMs, AVerifyMs: Double; AValueW: Int32): String;
var
  LCells: array [0 .. 2] of String;
begin
  LCells[0] := TBenchmarkFormat.FormatMeanMilliseconds(AKeygenMs);
  LCells[1] := TBenchmarkFormat.FormatMeanMilliseconds(ASignMs);
  LCells[2] := TBenchmarkFormat.FormatMeanMilliseconds(AVerifyMs);
  Result := TBenchmarkReport.BuildDataRow(ALabel, LCells, AValueW);
end;

class procedure TSignerPerformanceBenchmark.BenchSignerRow(
  ALogProc: TBenchmarkLogProc; const ARowLabel, ASignerMechanism: String;
  const APair: IAsymmetricCipherKeyPair; const AMessage: TBytes;
  AKeygenMs: Double; AValueW: Int32);
var
  LSignMs, LVerifyMs: Double;
  LSign: TSignRunner;
  LVer: TVerifyRunner;
  LS: ISigner;
  LSig: TBytes;
begin
  LSign := TSignRunner.Create(ASignerMechanism,
    APair.Private as ICipherParameters, AMessage);
  try
    LSignMs := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LSign.RunOnce);
  finally
    LSign.Free;
  end;

  LS := TSignerUtilities.GetSigner(ASignerMechanism);
  LS.Init(True, APair.Private as ICipherParameters);
  LS.BlockUpdate(AMessage, 0, System.Length(AMessage));
  LSig := LS.GenerateSignature;

  LVer := TVerifyRunner.Create(ASignerMechanism,
    APair.Public as ICipherParameters, AMessage, LSig);
  try
    LVerifyMs := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LVer.RunOnce);
  finally
    LVer.Free;
  end;

  ALogProc(BuildDataRow(ARowLabel, AKeygenMs, LSignMs, LVerifyMs, AValueW));
end;

class function TSignerPerformanceBenchmark.Run(ALogProc: TBenchmarkLogProc): Int32;
var
  LHeader: String;
  LValueW: Int32;
  LMsg: TBytes;
  Li: Int32;
  LPair: IAsymmetricCipherKeyPair;
  LKeygen: TKeygenBenchRunner;
  LKeygenMs: Double;
begin
  LValueW := BENCH_KDF_VALUE_COL_WIDTH;
  ALogProc('Digital signatures (mean ms per operation)');
  ALogProc('===========================================');
  ALogProc('Keygen: one fresh key pair per timed iteration.');
  ALogProc('Sign/Verify: fixed key pair; message length ' +
    IntToStr(BENCH_SIGN_MESSAGE_BYTES) + ' bytes.');
  ALogProc(IntToStr(BENCH_DURATION_MS) + ' ms budget per round, ' +
    IntToStr(BENCH_ROUNDS) + ' rounds; reported ms is min mean over rounds.');
  ALogProc('');

  BenchAllocRandom(BENCH_SIGN_MESSAGE_BYTES, LMsg);

  LHeader := BuildHeaderRow(LValueW);
  Result := System.Length(LHeader);
  ALogProc(LHeader);
  ALogProc(TBenchmarkReport.BuildSeparator(Result));

  for Li := System.Low(RSA_SIGNER_BENCH_SPECS) to System.High(RSA_SIGNER_BENCH_SPECS) do
  begin
    LKeygen := TKeygenBenchRunner.CreateForRsa(RSA_SIGNER_BENCH_SPECS[Li].KeyBits);
    try
      LKeygenMs := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(
        LKeygen.RunOnce);
      LPair := GenerateRsaPair(RSA_SIGNER_BENCH_SPECS[Li].KeyBits);
      BenchSignerRow(ALogProc, RSA_SIGNER_BENCH_SPECS[Li].RowLabel,
        RSA_SIGNER_BENCH_SPECS[Li].Mechanism, LPair, LMsg, LKeygenMs, LValueW);
    finally
      LKeygen.Free;
    end;
  end;

  for Li := System.Low(ECDSA_BENCH_SPECS) to System.High(ECDSA_BENCH_SPECS) do
  begin
    LKeygen := TKeygenBenchRunner.CreateForEcdsa(ECDSA_BENCH_SPECS[Li].CurveName);
    try
      LKeygenMs := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(
        LKeygen.RunOnce);
      LPair := GenerateEcdsaPair(ECDSA_BENCH_SPECS[Li].CurveName);
      BenchSignerRow(ALogProc, ECDSA_BENCH_SPECS[Li].RowLabel, 'ECDSA', LPair,
        LMsg, LKeygenMs, LValueW);
    finally
      LKeygen.Free;
    end;
  end;

  for Li := System.Low(EDDSA_BENCH_SPECS) to System.High(EDDSA_BENCH_SPECS) do
  begin
    LKeygen := TKeygenBenchRunner.CreateForEdwards(EDDSA_BENCH_SPECS[Li].Mechanism);
    try
      LKeygenMs := TBenchmarkTiming.MeasureMeanMillisecondsPerOp(LKeygen.RunOnce);
      LPair := GenerateEdwardsCipherPair(EDDSA_BENCH_SPECS[Li].Mechanism);
      BenchSignerRow(ALogProc, EDDSA_BENCH_SPECS[Li].RowLabel,
        EDDSA_BENCH_SPECS[Li].Mechanism, LPair, LMsg, LKeygenMs, LValueW);
    finally
      LKeygen.Free;
    end;
  end;

  ALogProc(TBenchmarkReport.BuildSeparator(Result));
end;

end.
