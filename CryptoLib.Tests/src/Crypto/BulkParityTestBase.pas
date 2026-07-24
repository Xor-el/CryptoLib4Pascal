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

unit BulkParityTestBase;

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
  ClpIParametersWithIV,
  ClpParametersWithIV,
  ClpICipherParameters,
  ClpAesEngine,
  ClpBlowfishEngine,
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpAesEngineX86,
{$ENDIF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
  ClpAesEngineArm,
{$ENDIF CRYPTOLIB_AARCH64_ASM}
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase,
  BlockCipherTestBase;

type
  /// <summary>
  /// Builds a fresh bulk-capable mode cipher (ECB/CBC/SIC) wrapping a fresh
  /// engine from AEngineFactory. Returned as IBlockCipher: it must expose
  /// ProcessBlock/Init and Support IBulkBlockCipherMode.
  /// </summary>
  TModeCipherFactory = function(const AEngineFactory: TBlockCipherFactory)
    : IBlockCipher;

  /// <summary>
  /// Shared scaffolding for the ECB/CBC/SIC bulk-parity suites: a common set
  /// of underlying engines and a parameterised parity runner asserting that
  /// ProcessBlocks (IBulkBlockCipherMode) is byte-identical to N sequential
  /// ProcessBlock calls. Mode-specific extras (e.g. SIC counter-wrap) stay in
  /// the concrete suite.
  /// </summary>
  TBulkParityTestBase = class abstract(TCryptoLibAlgorithmTestCase)
  strict protected
    /// <summary>
    /// For each block count and iteration: compare a per-block ProcessBlock
    /// reference against a single ProcessBlocks call. AWithIV selects
    /// ParametersWithIV vs a bare key; AWithInPlace also checks the in-place
    /// bulk path; ABothDirections runs decrypt as well as encrypt (CTR-style
    /// modes pass False and are exercised encrypt-only). A bulk encrypt then
    /// bulk decrypt round-trip must recover the plaintext.
    /// </summary>
    procedure RunBulkParity(const AEngineFactory: TBlockCipherFactory;
      AMakeMode: TModeCipherFactory; AKeyLen, AIvLen, ABlockSize: Int32;
      AWithIV, AWithInPlace, ABothDirections: Boolean;
      const AModeName, ALabel: String);
  end;

// Shared underlying-engine factories. Returning IBlockCipher lets every mode
// ctor work unchanged; the mode's own Supports(...) probe selects any fast path.
{$IFDEF CRYPTOLIB_X86_SIMD}
function CreateAesX86Engine: IBlockCipher;
{$ENDIF CRYPTOLIB_X86_SIMD}
{$IFDEF CRYPTOLIB_AARCH64_ASM}
function CreateAesArmEngine: IBlockCipher;
{$ENDIF CRYPTOLIB_AARCH64_ASM}
function CreateAesScalarEngine: IBlockCipher;
function CreateBlowfishEngine: IBlockCipher;

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}
function CreateAesX86Engine: IBlockCipher;
begin
  Result := TAesEngineX86.Create();
end;
{$ENDIF CRYPTOLIB_X86_SIMD}

{$IFDEF CRYPTOLIB_AARCH64_ASM}
function CreateAesArmEngine: IBlockCipher;
begin
  Result := TAesEngineArm.Create();
end;
{$ENDIF CRYPTOLIB_AARCH64_ASM}

function CreateAesScalarEngine: IBlockCipher;
begin
  Result := TAesEngine.Create();
end;

function CreateBlowfishEngine: IBlockCipher;
begin
  Result := TBlowfishEngine.Create();
end;

{ TBulkParityTestBase }

procedure TBulkParityTestBase.RunBulkParity(const AEngineFactory: TBlockCipherFactory;
  AMakeMode: TModeCipherFactory; AKeyLen, AIvLen, ABlockSize: Int32;
  AWithIV, AWithInPlace, ABothDirections: Boolean;
  const AModeName, ALabel: String);
const
  // Chosen to stress every branch of the bulk dispatch: < 4 tail-only, 4..7
  // four-block, 8..11 eight-block + tail, 8-multiples, 8n + 4..7, etc.
  BlockCounts: array [0 .. 15] of Int32 = (1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 15,
    16, 17, 24, 64, 100);
  IterationsPerCount: Int32 = 3;
var
  LRnd: ISecureRandom;
  LKey, LIV, LPlain, LOutRef, LOutBulk, LRoundTrip, LInplace: TBytes;
  LKeyParam: IKeyParameter;
  LParams: ICipherParameters;
  LRef, LBulk: IBlockCipher;
  LBulkMode: IBulkBlockCipherMode;
  LI, LJ, LOff, LBlockCount, LTotalBytes: Int32;
  LDir, LDirLow: Boolean;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeyLen);
  if AWithIV then
    System.SetLength(LIV, AIvLen);

  // Encrypt-only modes start (and end) the direction loop at True.
  if ABothDirections then
    LDirLow := False
  else
    LDirLow := True;

  for LI := 0 to System.Length(BlockCounts) - 1 do
  begin
    LBlockCount := BlockCounts[LI];
    LTotalBytes := LBlockCount * ABlockSize;
    System.SetLength(LPlain, LTotalBytes);
    System.SetLength(LOutRef, LTotalBytes);
    System.SetLength(LOutBulk, LTotalBytes);
    System.SetLength(LRoundTrip, LTotalBytes);
    if AWithInPlace then
      System.SetLength(LInplace, LTotalBytes);

    for LJ := 0 to IterationsPerCount - 1 do
    begin
      LRnd.NextBytes(LKey);
      if AWithIV then
        LRnd.NextBytes(LIV);
      LRnd.NextBytes(LPlain);

      LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;
      if AWithIV then
        LParams := TParametersWithIV.Create(LKeyParam, LIV) as ICipherParameters
      else
        LParams := LKeyParam as ICipherParameters;

      for LDir := LDirLow to True do
      begin
        // Reference: per-block ProcessBlock loop.
        LRef := AMakeMode(AEngineFactory);
        LRef.Init(LDir, LParams);
        LOff := 0;
        while LOff < LTotalBytes do
        begin
          LRef.ProcessBlock(LPlain, LOff, LOutRef, LOff);
          System.Inc(LOff, ABlockSize);
        end;

        // Bulk: single ProcessBlocks via the IBulkBlockCipherMode contract.
        LBulk := AMakeMode(AEngineFactory);
        LBulk.Init(LDir, LParams);
        if not Supports(LBulk, IBulkBlockCipherMode, LBulkMode) then
          Fail(Format('%s: %s does not expose IBulkBlockCipherMode',
            [ALabel, AModeName]));
        LBulkMode.ProcessBlocks(LPlain, 0, LBlockCount, LOutBulk, 0);

        if not AreEqual(LOutRef, LOutBulk) then
          Fail(Format('%s %s parity mismatch: dir=%s blocks=%d iter=%d (key=%s)',
            [ALabel, AModeName, SysUtils.BoolToStr(LDir, True), LBlockCount, LJ,
             EncodeHex(LKey)]));

        // In-place bulk (output buffer aliases input) must also match.
        if AWithInPlace then
        begin
          System.Move(LPlain[0], LInplace[0], LTotalBytes);
          LBulk := AMakeMode(AEngineFactory);
          LBulk.Init(LDir, LParams);
          Supports(LBulk, IBulkBlockCipherMode, LBulkMode);
          LBulkMode.ProcessBlocks(LInplace, 0, LBlockCount, LInplace, 0);
          if not AreEqual(LOutRef, LInplace) then
            Fail(Format('%s %s in-place bulk mismatch: dir=%s blocks=%d iter=%d',
              [ALabel, AModeName, SysUtils.BoolToStr(LDir, True), LBlockCount, LJ]));
        end;
      end;

      // Round-trip: bulk encrypt then bulk decrypt recovers the plaintext.
      LBulk := AMakeMode(AEngineFactory);
      LBulk.Init(True, LParams);
      Supports(LBulk, IBulkBlockCipherMode, LBulkMode);
      LBulkMode.ProcessBlocks(LPlain, 0, LBlockCount, LOutBulk, 0);

      LBulk := AMakeMode(AEngineFactory);
      LBulk.Init(False, LParams);
      Supports(LBulk, IBulkBlockCipherMode, LBulkMode);
      LBulkMode.ProcessBlocks(LOutBulk, 0, LBlockCount, LRoundTrip, 0);

      if not AreEqual(LPlain, LRoundTrip) then
        Fail(Format('%s %s bulk round-trip failed: %d blocks, iter %d',
          [ALabel, AModeName, LBlockCount, LJ]));
    end;
  end;
end;

end.
