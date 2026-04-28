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

unit EcbBulkParityTests;

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
  ClpIEcbBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpICipherParameters,
  ClpAesEngine,
  ClpBlowfishEngine,
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpAesEngineX86,
{$ENDIF CRYPTOLIB_X86_SIMD}
  ClpEcbBlockCipher,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// Parity tests for TEcbBlockCipher.ProcessBlocks (IBulkBlockCipherMode):
  /// the bulk path MUST produce byte-identical output to N sequential
  /// ProcessBlock calls in BOTH directions (encrypt and decrypt). Three
  /// engines exercise every branch of the bulk dispatch:
  ///   1. TAesEngineX86   -> 16-byte blocks, AES-NI 8/4/tail fast path.
  ///   2. TAesEngine      -> 16-byte blocks, FAesEngineX86 = nil fallback.
  ///   3. TBlowfishEngine -> 8-byte blocks, FBlockSize &lt;&gt; 16 fallback.
  /// </summary>
  TTestEcbBulkParity = class(TCryptoLibAlgorithmTestCase)
  strict private
  type
    TEngineFactory = function: IBlockCipher;

    procedure RunParityForEngine(AEngineFactory: TEngineFactory;
      AKeyLen, ABlockSize: Int32; const ALabel: String);
  published
{$IFDEF CRYPTOLIB_X86_SIMD}
    procedure TestAesX86EcbBulkParity;
{$ENDIF CRYPTOLIB_X86_SIMD}
    procedure TestAesScalarEcbBulkParity;
    procedure TestBlowfishEcbBulkParity;
  end;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
function CreateAesX86Engine: IBlockCipher;
begin
  Result := TAesEngineX86.Create();
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

function CreateAesScalarEngine: IBlockCipher;
begin
  Result := TAesEngine.Create();
end;

function CreateBlowfishEngine: IBlockCipher;
begin
  Result := TBlowfishEngine.Create();
end;

{ TTestEcbBulkParity }

procedure TTestEcbBulkParity.RunParityForEngine(AEngineFactory: TEngineFactory;
  AKeyLen, ABlockSize: Int32; const ALabel: String);
const
  BlockCounts: array [0 .. 15] of Int32 = (1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 15,
    16, 17, 24, 64, 100);
  IterationsPerCount: Int32 = 3;
var
  LRnd: ISecureRandom;
  LKey, LPlain, LOutRef, LOutBulk, LRoundTrip: TBytes;
  LKeyParam: ICipherParameters;
  LRefEcb, LBulkEcb: IEcbBlockCipher;
  LBulkMode: IBulkBlockCipherMode;
  LI, LJ, LOff, LBlockCount, LTotalBytes: Int32;
  LDir: Boolean;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeyLen);

  for LI := 0 to System.Length(BlockCounts) - 1 do
  begin
    LBlockCount := BlockCounts[LI];
    LTotalBytes := LBlockCount * ABlockSize;
    System.SetLength(LPlain, LTotalBytes);
    System.SetLength(LOutRef, LTotalBytes);
    System.SetLength(LOutBulk, LTotalBytes);
    System.SetLength(LRoundTrip, LTotalBytes);

    for LJ := 0 to IterationsPerCount - 1 do
    begin
      LRnd.NextBytes(LKey);
      LRnd.NextBytes(LPlain);
      LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;

      // Exercise both directions so that both the AES-NI encrypt kernel and
      // the inverse-rounds decrypt kernel are hit through the bulk path.
      for LDir := False to True do
      begin
        // Reference: per-block ProcessBlock loop.
        LRefEcb := TEcbBlockCipher.Create(AEngineFactory()) as IEcbBlockCipher;
        LRefEcb.Init(LDir, LKeyParam);
        LOff := 0;
        while LOff < LTotalBytes do
        begin
          LRefEcb.ProcessBlock(LPlain, LOff, LOutRef, LOff);
          System.Inc(LOff, ABlockSize);
        end;

        // Bulk: single ProcessBlocks via the IBulkBlockCipherMode contract.
        LBulkEcb := TEcbBlockCipher.Create(AEngineFactory()) as IEcbBlockCipher;
        LBulkEcb.Init(LDir, LKeyParam);
        if not Supports(LBulkEcb, IBulkBlockCipherMode, LBulkMode) then
          Fail(Format('%s: TEcbBlockCipher does not expose IBulkBlockCipherMode',
            [ALabel]));
        LBulkMode.ProcessBlocks(LPlain, 0, LBlockCount, LOutBulk, 0);

        if not AreEqual(LOutRef, LOutBulk) then
          Fail(Format(
            '%s ECB parity mismatch: dir=%s blocks=%d iter=%d (key=%s)',
            [ALabel, SysUtils.BoolToStr(LDir, True), LBlockCount, LJ,
             EncodeHex(LKey)]));
      end;

      // Round-trip: encrypt then decrypt through the bulk path must recover
      // the original plaintext.
      LBulkEcb := TEcbBlockCipher.Create(AEngineFactory()) as IEcbBlockCipher;
      LBulkEcb.Init(True, LKeyParam);
      Supports(LBulkEcb, IBulkBlockCipherMode, LBulkMode);
      LBulkMode.ProcessBlocks(LPlain, 0, LBlockCount, LOutBulk, 0);

      LBulkEcb := TEcbBlockCipher.Create(AEngineFactory()) as IEcbBlockCipher;
      LBulkEcb.Init(False, LKeyParam);
      Supports(LBulkEcb, IBulkBlockCipherMode, LBulkMode);
      LBulkMode.ProcessBlocks(LOutBulk, 0, LBlockCount, LRoundTrip, 0);

      if not AreEqual(LPlain, LRoundTrip) then
        Fail(Format('%s ECB bulk round-trip failed: %d blocks, iter %d',
          [ALabel, LBlockCount, LJ]));
    end;
  end;
end;

{$IFDEF CRYPTOLIB_X86_SIMD}
procedure TTestEcbBulkParity.TestAesX86EcbBulkParity;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunParityForEngine(@CreateAesX86Engine, 16, 16, 'AES-NI (TAesEngineX86)');
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

procedure TTestEcbBulkParity.TestAesScalarEcbBulkParity;
begin
  RunParityForEngine(@CreateAesScalarEngine, 16, 16, 'AES scalar (TAesEngine)');
end;

procedure TTestEcbBulkParity.TestBlowfishEcbBulkParity;
begin
  // 8-byte block Blowfish; key well within the 4..56 byte range. Guarantees
  // the FBlockSize <> 16 fallback is covered.
  RunParityForEngine(@CreateBlowfishEngine, 16, 8, 'Blowfish (TBlowfishEngine)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestEcbBulkParity);
{$ELSE}
  RegisterTest(TTestEcbBulkParity.Suite);
{$ENDIF FPC}

end.
