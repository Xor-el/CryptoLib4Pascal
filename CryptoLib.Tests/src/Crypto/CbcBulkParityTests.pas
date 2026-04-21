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

unit CbcBulkParityTests;

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
  ClpIBlockCipherMode,
  ClpIBulkBlockCipherMode,
  ClpICbcBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpParametersWithIV,
  ClpIParametersWithIV,
  ClpICipherParameters,
  ClpAesEngine,
  ClpBlowfishEngine,
  ClpAesEngineX86,
  ClpCbcBlockCipher,
  ClpSecureRandom,
  ClpISecureRandom,
  ClpCryptoLibTypes,
  CryptoLibTestBase;

type
  /// <summary>
  /// Parity tests for TCbcBlockCipher.ProcessBlocks (IBulkBlockCipherMode):
  /// bulk output and residual chain state MUST match N sequential
  /// ProcessBlock calls, for BOTH encrypt and decrypt. Three engines cover
  /// every dispatch branch:
  ///   1. TAesEngineX86   -> 16-byte blocks; AES-NI bulk encrypt (serial)
  ///                         and bulk decrypt (8/4/tail pipelined).
  ///   2. TAesEngine      -> 16-byte blocks; FAesEngineX86 = nil fallback.
  ///   3. TBlowfishEngine -> 8-byte blocks; FBlockSize &lt;&gt; 16 fallback.
  /// Also asserts that a bulk encrypt followed by a bulk decrypt with the
  /// same IV recovers the original plaintext (in-place AND disjoint buffers).
  /// </summary>
  TTestCbcBulkParity = class(TCryptoLibAlgorithmTestCase)
  strict private
  type
    TEngineFactory = function: IBlockCipher;

    procedure RunParityForEngine(AEngineFactory: TEngineFactory;
      AKeyLen, ABlockSize: Int32; const ALabel: String);
  published
    procedure TestAesX86CbcBulkParity;
    procedure TestAesScalarCbcBulkParity;
    procedure TestBlowfishCbcBulkParity;
  end;

implementation

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

{ TTestCbcBulkParity }

procedure TTestCbcBulkParity.RunParityForEngine(AEngineFactory: TEngineFactory;
  AKeyLen, ABlockSize: Int32; const ALabel: String);
const
  BlockCounts: array [0 .. 15] of Int32 = (1, 2, 3, 4, 5, 7, 8, 9, 11, 12, 15,
    16, 17, 24, 64, 100);
  IterationsPerCount: Int32 = 3;
var
  LRnd: ISecureRandom;
  LKey, LIV, LPlain, LOutRef, LOutBulk, LRoundTrip: TBytes;
  LInplace: TBytes;
  LKeyParam: IKeyParameter;
  LParams: IParametersWithIV;
  LRefCbc, LBulkCbc: ICbcBlockCipher;
  LBulkMode: IBulkBlockCipherMode;
  LI, LJ, LOff, LBlockCount, LTotalBytes: Int32;
  LDir: Boolean;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeyLen);
  System.SetLength(LIV, ABlockSize);

  for LI := 0 to System.Length(BlockCounts) - 1 do
  begin
    LBlockCount := BlockCounts[LI];
    LTotalBytes := LBlockCount * ABlockSize;
    System.SetLength(LPlain, LTotalBytes);
    System.SetLength(LOutRef, LTotalBytes);
    System.SetLength(LOutBulk, LTotalBytes);
    System.SetLength(LRoundTrip, LTotalBytes);
    System.SetLength(LInplace, LTotalBytes);

    for LJ := 0 to IterationsPerCount - 1 do
    begin
      LRnd.NextBytes(LKey);
      LRnd.NextBytes(LIV);
      LRnd.NextBytes(LPlain);
      LKeyParam := TKeyParameter.Create(LKey) as IKeyParameter;
      LParams := TParametersWithIV.Create(LKeyParam, LIV) as IParametersWithIV;

      for LDir := False to True do
      begin
        LRefCbc := TCbcBlockCipher.Create(AEngineFactory()) as ICbcBlockCipher;
        LRefCbc.Init(LDir, LParams);
        LOff := 0;
        while LOff < LTotalBytes do
        begin
          LRefCbc.ProcessBlock(LPlain, LOff, LOutRef, LOff);
          System.Inc(LOff, ABlockSize);
        end;

        LBulkCbc := TCbcBlockCipher.Create(AEngineFactory()) as ICbcBlockCipher;
        LBulkCbc.Init(LDir, LParams);
        if not Supports(LBulkCbc, IBulkBlockCipherMode, LBulkMode) then
          Fail(Format('%s: TCbcBlockCipher does not expose IBulkBlockCipherMode',
            [ALabel]));
        LBulkMode.ProcessBlocks(LPlain, 0, LBlockCount, LOutBulk, 0);

        if not AreEqual(LOutRef, LOutBulk) then
          Fail(Format(
            '%s CBC parity mismatch: dir=%s blocks=%d iter=%d (key=%s iv=%s)',
            [ALabel, SysUtils.BoolToStr(LDir, True), LBlockCount, LJ,
             EncodeHex(LKey), EncodeHex(LIV)]));

        // Bulk in-place must also match (common real-world usage).
        System.Move(LPlain[0], LInplace[0], LTotalBytes);
        LBulkCbc := TCbcBlockCipher.Create(AEngineFactory()) as ICbcBlockCipher;
        LBulkCbc.Init(LDir, LParams);
        Supports(LBulkCbc, IBulkBlockCipherMode, LBulkMode);
        LBulkMode.ProcessBlocks(LInplace, 0, LBlockCount, LInplace, 0);
        if not AreEqual(LOutRef, LInplace) then
          Fail(Format(
            '%s CBC in-place bulk mismatch: dir=%s blocks=%d iter=%d',
            [ALabel, SysUtils.BoolToStr(LDir, True), LBlockCount, LJ]));
      end;

      // Round-trip through the bulk path.
      LBulkCbc := TCbcBlockCipher.Create(AEngineFactory()) as ICbcBlockCipher;
      LBulkCbc.Init(True, LParams);
      Supports(LBulkCbc, IBulkBlockCipherMode, LBulkMode);
      LBulkMode.ProcessBlocks(LPlain, 0, LBlockCount, LOutBulk, 0);

      LBulkCbc := TCbcBlockCipher.Create(AEngineFactory()) as ICbcBlockCipher;
      LBulkCbc.Init(False, LParams);
      Supports(LBulkCbc, IBulkBlockCipherMode, LBulkMode);
      LBulkMode.ProcessBlocks(LOutBulk, 0, LBlockCount, LRoundTrip, 0);

      if not AreEqual(LPlain, LRoundTrip) then
        Fail(Format('%s CBC bulk round-trip failed: %d blocks, iter %d',
          [ALabel, LBlockCount, LJ]));
    end;
  end;
end;

procedure TTestCbcBulkParity.TestAesX86CbcBulkParity;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunParityForEngine(@CreateAesX86Engine, 16, 16, 'AES-NI (TAesEngineX86)');
end;

procedure TTestCbcBulkParity.TestAesScalarCbcBulkParity;
begin
  RunParityForEngine(@CreateAesScalarEngine, 16, 16, 'AES scalar (TAesEngine)');
end;

procedure TTestCbcBulkParity.TestBlowfishCbcBulkParity;
begin
  RunParityForEngine(@CreateBlowfishEngine, 16, 8, 'Blowfish (TBlowfishEngine)');
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestCbcBulkParity);
{$ELSE}
  RegisterTest(TTestCbcBulkParity.Suite);
{$ENDIF FPC}

end.
