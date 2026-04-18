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

interface

{$IFDEF FPC}
{$MODE DELPHI}
{$ENDIF FPC}

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
  ClpAesEngine,
  ClpBlowfishEngine,
  ClpAesEngineX86,
  ClpSicBlockCipher,
  ClpISicBlockCipher,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// Parity tests for TSicBlockCipher.ProcessBlocks (IBulkBlockCipherMode):
  /// for every supported underlying engine, ProcessBlocks on N blocks MUST
  /// produce byte-identical output to N sequential ProcessBlock calls.
  /// Three engines are exercised so that every branch of the bulk dispatch
  /// is covered:
  ///   1. TAesEngineX86   -> 16-byte blocks, AES-NI fast path (8/4/tail).
  ///   2. TAesEngine      -> 16-byte blocks, FAesEngineX86 = nil fallback.
  ///   3. TBlowfishEngine -> 8-byte blocks, FBlockSize &lt;&gt; 16 fallback.
  /// </summary>
  TTestSicBulkParity = class(TCryptoLibAlgorithmTestCase)
  strict private
  type
    TEngineFactory = function: IBlockCipher;

    procedure RunParityForEngine(AEngineFactory: TEngineFactory;
      AKeyLen, AIvLen, ABlockSize: Int32; const ALabel: String);
  published
    procedure TestAesX86SicBulkParity;
    procedure TestAesScalarSicBulkParity;
    procedure TestBlowfishSicBulkParity;
  end;

implementation

{ Engine factories - returning IBlockCipher lets the TSicBlockCipher ctor
  work unchanged across all three; the Supports(FCipher, IAesEngineX86, ...)
  probe inside Init is what selects the fast path. }

function CreateAesX86Engine: IBlockCipher;
begin
  Result := TAesEngineX86.Create();
end;

function CreateAesScalarEngine: IBlockCipher;
begin
  Result := TAesEngine.Create();
end;

function CreateBlowfishEngine: IBlockCipher;
begin
  Result := TBlowfishEngine.Create();
end;

{ TTestSicBulkParity }

procedure TTestSicBulkParity.RunParityForEngine(AEngineFactory: TEngineFactory;
  AKeyLen, AIvLen, ABlockSize: Int32; const ALabel: String);
const
  // Chosen to stress every branch of the bulk dispatch:
  //  - < 4 blocks   -> tail-only, no fast path at all
  //  - 4..7         -> 4-block branch only
  //  - 8..11        -> 8-block branch once + tail
  //  - 8-multiples  -> 8-block branch only, no tail
  //  - 8n + 4..7    -> 8-block loop + 4-block + tail
  BlockCounts: array [0 .. 15] of Int32 = (1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 15,
    16, 17, 24, 64, 100);
  IterationsPerCount: Int32 = 3;
var
  LRnd: ISecureRandom;
  LKey, LIV, LPlain, LOutRef, LOutBulk: TBytes;
  LKeyParam: IKeyParameter;
  LParams: IParametersWithIV;
  LRefSic, LBulkSic: ISicBlockCipher;
  LBulkMode: IBulkBlockCipherMode;
  LI, LJ, LOff, LBlockCount, LTotalBytes: Int32;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeyLen);
  System.SetLength(LIV, AIvLen);

  for LI := 0 to System.Length(BlockCounts) - 1 do
  begin
    LBlockCount := BlockCounts[LI];
    LTotalBytes := LBlockCount * ABlockSize;
    System.SetLength(LPlain, LTotalBytes);
    System.SetLength(LOutRef, LTotalBytes);
    System.SetLength(LOutBulk, LTotalBytes);

    for LJ := 0 to IterationsPerCount - 1 do
    begin
      LRnd.NextBytes(LKey);
      LRnd.NextBytes(LIV);
      LRnd.NextBytes(LPlain);

      LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;
      LParams := TParametersWithIV.Create(LKeyParam, LIV) as IParametersWithIV;

      // Reference: one ISicBlockCipher, per-block ProcessBlock loop.
      LRefSic := TSicBlockCipher.Create(AEngineFactory()) as ISicBlockCipher;
      LRefSic.Init(True, LParams);
      LOff := 0;
      while LOff < LTotalBytes do
      begin
        LRefSic.ProcessBlock(LPlain, LOff, LOutRef, LOff);
        System.Inc(LOff, ABlockSize);
      end;

      // Bulk: independent ISicBlockCipher (own engine instance + own counter),
      // single ProcessBlocks call dispatched through the IBulkBlockCipherMode
      // contract -- which is exactly how TBufferedBlockCipher will use it in
      // Phase 4, so this also validates the public interface surface.
      LBulkSic := TSicBlockCipher.Create(AEngineFactory()) as ISicBlockCipher;
      LBulkSic.Init(True, LParams);
      if not Supports(LBulkSic, IBulkBlockCipherMode, LBulkMode) then
        Fail(Format('%s: TSicBlockCipher does not expose IBulkBlockCipherMode',
          [ALabel]));
      LBulkMode.ProcessBlocks(LPlain, 0, LBlockCount, LOutBulk, 0);

      if not AreEqual(LOutRef, LOutBulk) then
        Fail(Format(
          '%s SIC parity mismatch: %d blocks, iteration %d (key=%s iv=%s)',
          [ALabel, LBlockCount, LJ, EncodeHex(LKey), EncodeHex(LIV)]));

      // Round-trip: decrypting the bulk ciphertext must recover the plaintext.
      LBulkSic := TSicBlockCipher.Create(AEngineFactory()) as ISicBlockCipher;
      LBulkSic.Init(False, LParams);
      if not Supports(LBulkSic, IBulkBlockCipherMode, LBulkMode) then
        Fail(Format('%s: TSicBlockCipher does not expose IBulkBlockCipherMode (decrypt)',
          [ALabel]));
      // CTR/SIC uses the same keystream for encrypt and decrypt, so we re-use
      // LOutRef as scratch for the decrypted plaintext.
      LBulkMode.ProcessBlocks(LOutBulk, 0, LBlockCount, LOutRef, 0);
      if not AreEqual(LPlain, LOutRef) then
        Fail(Format(
          '%s SIC bulk round-trip failed: %d blocks, iteration %d',
          [ALabel, LBlockCount, LJ]));
    end;
  end;
end;

procedure TTestSicBulkParity.TestAesX86SicBulkParity;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  // 16-byte block, 16-byte key, 12-byte IV (leaves a 4-byte counter suffix).
  RunParityForEngine(@CreateAesX86Engine, 16, 12, 16, 'AES-NI (TAesEngineX86)');
end;

procedure TTestSicBulkParity.TestAesScalarSicBulkParity;
begin
  // 16-byte block + 12-byte IV: same dimensions as the AES-NI case so that
  // FAesEngineX86 = nil is the only code-path difference under test.
  RunParityForEngine(@CreateAesScalarEngine, 16, 12, 16,
    'AES scalar (TAesEngine)');
end;

procedure TTestSicBulkParity.TestBlowfishSicBulkParity;
begin
  // 8-byte block Blowfish: 16-byte key (well within the 4..56 range), 6-byte
  // IV (2-byte counter suffix). Guaranteed to land on the FBlockSize <> 16
  // fallback, no matter how the fast-path detection is wired.
  RunParityForEngine(@CreateBlowfishEngine, 16, 6, 8, 'Blowfish (TBlowfishEngine)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestSicBulkParity);
{$ELSE}
  RegisterTest(TTestSicBulkParity.Suite);
{$ENDIF FPC}

end.
