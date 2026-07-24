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

unit SicBulkParityTests;

{$I ..\..\..\CryptoLib\src\Include\CryptoLib.inc}

interface

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpIBlockCipher,
  ClpIBulkBlockCipherMode,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpAesEngineX86,
{$ENDIF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpAesEngineArm,
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  BlockCipherTestBase,
  BulkParityTestBase;

type
  /// <summary>
  /// Parity tests for TSicBlockCipher.ProcessBlocks (IBulkBlockCipherMode):
  /// for every supported underlying engine, ProcessBlocks on N blocks MUST
  /// produce byte-identical output to N sequential ProcessBlock calls. Three
  /// engines are exercised so that every branch of the bulk dispatch is
  /// covered (AES-NI 8/4/tail, FAesEngineX86 = nil fallback, and the
  /// FBlockSize &lt;&gt; 16 fallback via Blowfish). The counter-wrap cases
  /// additionally pin behaviour across 2^32 / 2^128 boundaries.
  /// </summary>
  TTestSicBulkParity = class(TBulkParityTestBase)
  strict private
    // Engine-agnostic: any bulk/kernel provider must produce
    // per-block-identical output across counter wrap boundaries.
    procedure RunWrapCaseForEngine(AEngineFactory: TBlockCipherFactory;
      const AIvHex: String; ABlockCount: Int32; const ALabel: String);
    procedure RunWrapCasesForEngine(AEngineFactory: TBlockCipherFactory;
      const ALabel: String);
  published
{$IFDEF CRYPTOLIB_X86_SIMD}
    procedure TestAesX86SicBulkParity;
    procedure TestAesX86SicCounterWrapParity;
{$ENDIF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
    procedure TestAesArmSicBulkParity;
    procedure TestAesArmSicCounterWrapParity;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
    procedure TestAesScalarSicBulkParity;
    procedure TestAesScalarSicCounterWrapParity;
    procedure TestBlowfishSicBulkParity;
  end;

implementation

function MakeSic(const AEngineFactory: TBlockCipherFactory): IBlockCipher;
begin
  Result := TSicBlockCipher.Create(AEngineFactory()) as ISicBlockCipher;
end;

{ TTestSicBulkParity }

procedure TTestSicBulkParity.RunWrapCaseForEngine(
  AEngineFactory: TBlockCipherFactory; const AIvHex: String;
  ABlockCount: Int32; const ALabel: String);
var
  LRnd: ISecureRandom;
  LKey, LIV, LPlain, LOutRef, LOutBulk: TBytes;
  LKeyParam: IKeyParameter;
  LParams: IParametersWithIV;
  LRefSic, LBulkSic: ISicBlockCipher;
  LBulkMode: IBulkBlockCipherMode;
  LOff, LTotalBytes: Int32;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 16);
  LRnd.NextBytes(LKey);
  LIV := DecodeHex(AIvHex);
  LTotalBytes := ABlockCount * 16;
  System.SetLength(LPlain, LTotalBytes);
  LRnd.NextBytes(LPlain);
  System.SetLength(LOutRef, LTotalBytes);
  System.SetLength(LOutBulk, LTotalBytes);

  LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;
  LParams := TParametersWithIV.Create(LKeyParam, LIV) as IParametersWithIV;

  // Reference: per-block ProcessBlock loop (scalar big-endian counter carry).
  LRefSic := TSicBlockCipher.Create(AEngineFactory()) as ISicBlockCipher;
  LRefSic.Init(True, LParams);
  LOff := 0;
  while LOff < LTotalBytes do
  begin
    LRefSic.ProcessBlock(LPlain, LOff, LOutRef, LOff);
    System.Inc(LOff, 16);
  end;

  // Bulk: single ProcessBlocks call across the counter boundary.
  LBulkSic := TSicBlockCipher.Create(AEngineFactory()) as ISicBlockCipher;
  LBulkSic.Init(True, LParams);
  if not Supports(LBulkSic, IBulkBlockCipherMode, LBulkMode) then
    Fail(Format('%s wrap case: TSicBlockCipher does not expose IBulkBlockCipherMode',
      [ALabel]));
  LBulkMode.ProcessBlocks(LPlain, 0, ABlockCount, LOutBulk, 0);

  if not AreEqual(LOutRef, LOutBulk) then
    Fail(Format('%s SIC counter-wrap parity mismatch (iv=%s, %d blocks)',
      [ALabel, AIvHex, ABlockCount]));
end;

procedure TTestSicBulkParity.RunWrapCasesForEngine(
  AEngineFactory: TBlockCipherFactory; const ALabel: String);
begin
  // Full 16-byte IVs landing the low-dword 2^32 boundary at different points
  // within one bulk call. Accelerated kernels that split runs at that boundary
  // must stay per-block-identical; the scalar bulk path must too.
  // Boundary exactly 8 blocks in: batch-aligned split + upper-bytes carry.
  RunWrapCaseForEngine(AEngineFactory, '000102030405060708090A0BFFFFFFF8', 24, ALabel);
  // Boundary mid-batch: crossing handled block-at-a-time.
  RunWrapCaseForEngine(AEngineFactory, '000102030405060708090A0BFFFFFFFE', 24, ALabel);
  // Carry cascade through several upper counter bytes.
  RunWrapCaseForEngine(AEngineFactory, '000102030405FFFFFFFFFFFFFFFFFFFC', 24, ALabel);
  // Full 128-bit wrap: counter returns to zero mid-run.
  RunWrapCaseForEngine(AEngineFactory, 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE', 24, ALabel);
end;

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure TTestSicBulkParity.TestAesX86SicBulkParity;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  // 16-byte block, 16-byte key, 12-byte IV (leaves a 4-byte counter suffix).
  RunBulkParity(CreateAesX86Engine, MakeSic, 16, 12, 16, True, False, False,
    'SIC', 'AES-NI (TAesEngineX86)');
end;

procedure TTestSicBulkParity.TestAesX86SicCounterWrapParity;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunWrapCasesForEngine(CreateAesX86Engine, 'AES-NI (TAesEngineX86)');
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_AARCH64_ASM}
procedure TTestSicBulkParity.TestAesArmSicBulkParity;
begin
  if not TAesEngineArm.IsSupported then
    Exit;
  RunBulkParity(CreateAesArmEngine, MakeSic, 16, 12, 16, True, False, False,
    'SIC', 'AES-CryptoExt (TAesEngineArm)');
end;

procedure TTestSicBulkParity.TestAesArmSicCounterWrapParity;
begin
  if not TAesEngineArm.IsSupported then
    Exit;
  RunWrapCasesForEngine(CreateAesArmEngine, 'AES-CryptoExt (TAesEngineArm)');
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

procedure TTestSicBulkParity.TestAesScalarSicBulkParity;
begin
  // 16-byte block + 12-byte IV: same dimensions as the AES-NI case so that
  // FAesEngineX86 = nil is the only code-path difference under test.
  RunBulkParity(CreateAesScalarEngine, MakeSic, 16, 12, 16, True, False, False,
    'SIC', 'AES scalar (TAesEngine)');
end;

procedure TTestSicBulkParity.TestAesScalarSicCounterWrapParity;
begin
  RunWrapCasesForEngine(CreateAesScalarEngine, 'AES scalar (TAesEngine)');
end;

procedure TTestSicBulkParity.TestBlowfishSicBulkParity;
begin
  // 8-byte block Blowfish: 16-byte key (well within the 4..56 range), 6-byte
  // IV (2-byte counter suffix). Guaranteed to land on the FBlockSize <> 16
  // fallback, no matter how the fast-path detection is wired.
  RunBulkParity(CreateBlowfishEngine, MakeSic, 16, 6, 8, True, False, False,
    'SIC', 'Blowfish (TBlowfishEngine)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSicBulkParity);
{$ELSE}
  RegisterTest(TTestSicBulkParity.Suite);
{$ENDIF FPC}

end.
