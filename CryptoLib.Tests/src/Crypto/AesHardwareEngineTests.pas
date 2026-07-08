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

unit AesHardwareEngineTests;

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
  ClpIAesHardwareEngine,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpSecureRandom,
  ClpISecureRandom,
{$IFDEF CRYPTOLIB_X86_SIMD}
  ClpAesEngineX86,
{$ENDIF CRYPTOLIB_X86_SIMD}
  BlockCipherTestBase,
  AesBlockCipherTestBase;

type
  /// <summary>
  /// Engine-agnostic test suite for hardware-accelerated AES engines. All the
  /// vector / Monte-Carlo / engine-check coverage plus the SIMD batch (4-/8-wide)
  /// parity and memory-layout coverage lives here, written against
  /// <see cref="IAesHardwareEngine" />. A concrete per-architecture suite only
  /// has to supply four hooks (CreateHwEngine / EngineSupported / EngineLabel /
  /// GetEngineFactory) and register itself under its architecture guard; the
  /// published tests are inherited and discovered automatically.
  /// </summary>
  TAesHardwareEngineTestBase = class abstract(TAesBlockCipherTestBase)
  strict protected
    // ---- architecture hooks (implemented by the concrete per-arch suite) ----
    // GetEngineFactory / EngineLabel / EngineSupported are inherited from
    // TAesBlockCipherTestBase; only CreateHwEngine is hardware-specific.
    function CreateHwEngine: IAesHardwareEngine; virtual; abstract;

    // ---- shared SIMD test logic ----
    procedure ImplTestFourBlocks(AForEncryption: Boolean; AKeySizeBytes: Int32);
    procedure ImplTestEightBlocks(AForEncryption: Boolean; AKeySizeBytes: Int32);
    procedure ImplTestPByteOverloadParity(AKeySizeBytes: Int32);
    procedure ImplTestProcessBlockMemoryLayouts(AKeySizeBytes: Int32);
    procedure ImplTestProcessFourBlocksMemoryLayouts(AKeySizeBytes: Int32);
    procedure ImplTestProcessEightBlocksMemoryLayouts(AKeySizeBytes: Int32);
  published
    // TestBlockCipherVector / TestMonteCarloAES / TestBadParameters are
    // inherited from TAesBlockCipherTestBase (guarded by EngineSupported).
    procedure TestEngineChecks128;
    procedure TestEngineChecks192;
    procedure TestEngineChecks256;
    procedure TestFourBlocksEncrypt128;
    procedure TestFourBlocksEncrypt192;
    procedure TestFourBlocksEncrypt256;
    procedure TestFourBlocksDecrypt128;
    procedure TestFourBlocksDecrypt192;
    procedure TestFourBlocksDecrypt256;
    procedure TestEightBlocksEncrypt128;
    procedure TestEightBlocksEncrypt192;
    procedure TestEightBlocksEncrypt256;
    procedure TestEightBlocksDecrypt128;
    procedure TestEightBlocksDecrypt192;
    procedure TestEightBlocksDecrypt256;
    procedure TestPByteOverloadParity128;
    procedure TestPByteOverloadParity192;
    procedure TestPByteOverloadParity256;
    procedure TestProcessBlockMemoryLayouts128;
    procedure TestProcessBlockMemoryLayouts192;
    procedure TestProcessBlockMemoryLayouts256;
    procedure TestProcessFourBlocksMemoryLayouts128;
    procedure TestProcessFourBlocksMemoryLayouts192;
    procedure TestProcessFourBlocksMemoryLayouts256;
    procedure TestProcessEightBlocksMemoryLayouts128;
    procedure TestProcessEightBlocksMemoryLayouts192;
    procedure TestProcessEightBlocksMemoryLayouts256;
  end;

{$IFDEF CRYPTOLIB_X86_SIMD}

  /// <summary>
  /// x86 (AES-NI) instantiation of the hardware AES test suite. Registered only
  /// when CRYPTOLIB_X86_SIMD is defined.
  /// </summary>
  TTestAesX86 = class(TAesHardwareEngineTestBase)
  strict protected
    function CreateHwEngine: IAesHardwareEngine; override;
    function EngineSupported: Boolean; override;
    function EngineLabel: String; override;
    function GetEngineFactory: TBlockCipherFactory; override;
  end;

{$ENDIF CRYPTOLIB_X86_SIMD}

// To add an aarch64 (NEON / Crypto-Ext) suite later: under
// {$IFDEF CRYPTOLIB_ARM_SIMD}, declare
//   TTestAesAArch64 = class(TAesHardwareEngineTestBase) ... override the four
//   hooks for TAesEngineAArch64 ... end;
// and RegisterTest it in the initialization section under the same guard. No
// test bodies need to be re-declared.

implementation

{ TAesHardwareEngineTestBase }

procedure TAesHardwareEngineTestBase.ImplTestFourBlocks(AForEncryption: Boolean;
  AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LData, LFourOut, LSingleOut, LKey: TBytes;
  LI, LJ: Int32;
  LEngine: IAesHardwareEngine;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LData, 64);
  System.SetLength(LFourOut, 64);
  System.SetLength(LSingleOut, 64);
  System.SetLength(LKey, AKeySizeBytes);

  for LI := 0 to 99 do
  begin
    LRnd.NextBytes(LData);
    LRnd.NextBytes(LKey);
    LEngine := CreateHwEngine;
    LEngine.Init(AForEncryption, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessFourBlocks(LData, 0, LFourOut, 0);
    for LJ := 0 to 3 do
      LEngine.ProcessBlock(LData, LJ * 16, LSingleOut, LJ * 16);
    if not AreEqual(LFourOut, LSingleOut) then
    begin
      Fail(Format(
        'ProcessFourBlocks vs ProcessBlock mismatch (key %d bytes, iteration %d)',
        [AKeySizeBytes, LI]));
    end;
  end;
end;

procedure TAesHardwareEngineTestBase.ImplTestEightBlocks(AForEncryption: Boolean;
  AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LData, LEightOut, LSingleOut, LKey: TBytes;
  LI, LJ: Int32;
  LEngine: IAesHardwareEngine;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LData, 128);
  System.SetLength(LEightOut, 128);
  System.SetLength(LSingleOut, 128);
  System.SetLength(LKey, AKeySizeBytes);

  for LI := 0 to 49 do
  begin
    LRnd.NextBytes(LData);
    LRnd.NextBytes(LKey);
    LEngine := CreateHwEngine;
    LEngine.Init(AForEncryption, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessEightBlocks(LData, 0, LEightOut, 0);
    for LJ := 0 to 7 do
      LEngine.ProcessBlock(LData, LJ * 16, LSingleOut, LJ * 16);
    if not AreEqual(LEightOut, LSingleOut) then
    begin
      Fail(Format(
        'ProcessEightBlocks vs ProcessBlock mismatch (key %d bytes, iteration %d)',
        [AKeySizeBytes, LI]));
    end;
  end;
end;

procedure TAesHardwareEngineTestBase.ImplTestPByteOverloadParity(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LIn16, LOutArr, LOutPtr, LIn64, LFourArr, LFourPtr,
    LIn128, LEightArr, LEightPtr: TBytes;
  LI: Int32;
  LEngine: IAesHardwareEngine;
begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeySizeBytes);
  System.SetLength(LIn16, 16);
  System.SetLength(LOutArr, 16);
  System.SetLength(LOutPtr, 16);
  System.SetLength(LIn64, 64);
  System.SetLength(LFourArr, 64);
  System.SetLength(LFourPtr, 64);
  System.SetLength(LIn128, 128);
  System.SetLength(LEightArr, 128);
  System.SetLength(LEightPtr, 128);

  for LI := 0 to 49 do
  begin
    LRnd.NextBytes(LKey);
    LRnd.NextBytes(LIn16);
    LEngine := CreateHwEngine;
    LEngine.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);

    LOutArr := System.Copy(LIn16);
    LOutPtr := System.Copy(LIn16);
    LEngine.ProcessBlock(LIn16, 0, LOutArr, 0);
    LEngine.ProcessBlock(@LIn16[0], @LOutPtr[0]);
    if not AreEqual(LOutArr, LOutPtr) then
      Fail(Format('ProcessBlock PByte disjoint mismatch (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LOutPtr := System.Copy(LIn16);
    LEngine.ProcessBlock(@LOutPtr[0], @LOutPtr[0]);
    if not AreEqual(LOutArr, LOutPtr) then
      Fail(Format('ProcessBlock PByte in-place mismatch (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LRnd.NextBytes(LIn64);
    LFourArr := System.Copy(LIn64);
    LFourPtr := System.Copy(LIn64);
    LEngine.ProcessFourBlocks(LIn64, 0, LFourArr, 0);
    LEngine.ProcessFourBlocks(@LIn64[0], @LFourPtr[0]);
    if not AreEqual(LFourArr, LFourPtr) then
      Fail(Format('ProcessFourBlocks PByte disjoint mismatch (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LFourPtr := System.Copy(LIn64);
    LEngine.ProcessFourBlocks(@LFourPtr[0], @LFourPtr[0]);
    if not AreEqual(LFourArr, LFourPtr) then
      Fail(Format('ProcessFourBlocks PByte in-place mismatch (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LRnd.NextBytes(LIn128);
    LEightArr := System.Copy(LIn128);
    LEightPtr := System.Copy(LIn128);
    LEngine.ProcessEightBlocks(LIn128, 0, LEightArr, 0);
    LEngine.ProcessEightBlocks(@LIn128[0], @LEightPtr[0]);
    if not AreEqual(LEightArr, LEightPtr) then
      Fail(Format('ProcessEightBlocks PByte disjoint mismatch (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LEightPtr := System.Copy(LIn128);
    LEngine.ProcessEightBlocks(@LEightPtr[0], @LEightPtr[0]);
    if not AreEqual(LEightArr, LEightPtr) then
      Fail(Format('ProcessEightBlocks PByte in-place mismatch (key %d, iter %d)',
        [AKeySizeBytes, LI]));
  end;
end;

procedure TAesHardwareEngineTestBase.ImplTestProcessBlockMemoryLayouts(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LPlain, LCipher, LExpectedPt, LScratch: TBytes;
  LI: Int32;
  LEngine: IAesHardwareEngine;

  function MemEq(const A: TBytes; AOff: Int32; const B: TBytes; BOff, ALen: Int32): Boolean;
  begin
    Result := CompareMem(@A[AOff], @B[BOff], ALen);
  end;

begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeySizeBytes);
  System.SetLength(LPlain, 16);
  System.SetLength(LCipher, 16);
  System.SetLength(LExpectedPt, 16);

  for LI := 0 to 39 do
  begin
    LRnd.NextBytes(LKey);
    LRnd.NextBytes(LPlain);
    LEngine := CreateHwEngine;
    LEngine.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessBlock(LPlain, 0, LCipher, 0);

    LScratch := System.Copy(LPlain);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[0]);
    if not AreEqual(LCipher, LScratch) then
      Fail(Format('ProcessBlock enc in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 48);
    System.Move(LPlain[0], LScratch[0], 16);
    System.FillChar(LScratch[16], 32, $7D);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[16]);
    if not MemEq(LCipher, 0, LScratch, 16, 16) then
      Fail(Format('ProcessBlock enc disjoint same allocation (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 40);
    System.Move(LPlain[0], LScratch[0], 16);
    System.FillChar(LScratch[16], 24, 0);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[8]);
    if not MemEq(LCipher, 0, LScratch, 8, 16) then
      Fail(Format('ProcessBlock enc overlap dst=src+8 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.FillChar(LScratch[0], 32, 0);
    System.Move(LPlain[0], LScratch[8], 16);
    LEngine.ProcessBlock(@LScratch[8], @LScratch[0]);
    if not MemEq(LCipher, 0, LScratch, 0, 16) then
      Fail(Format('ProcessBlock enc overlap dst=src-8 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 32);
    System.Move(LPlain[0], LScratch[0], 16);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[15]);
    if not MemEq(LCipher, 0, LScratch, 15, 16) then
      Fail(Format('ProcessBlock enc overlap dst=src+15 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LEngine.Init(False, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessBlock(LCipher, 0, LExpectedPt, 0);
    if not AreEqual(LPlain, LExpectedPt) then
      Fail(Format('ProcessBlock dec reference sanity (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LScratch := System.Copy(LCipher);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[0]);
    if not AreEqual(LPlain, LScratch) then
      Fail(Format('ProcessBlock dec in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 48);
    System.Move(LCipher[0], LScratch[0], 16);
    System.FillChar(LScratch[16], 32, $3C);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[16]);
    if not MemEq(LPlain, 0, LScratch, 16, 16) then
      Fail(Format('ProcessBlock dec disjoint same allocation (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 40);
    System.Move(LCipher[0], LScratch[0], 16);
    System.FillChar(LScratch[16], 24, $11);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[8]);
    if not MemEq(LPlain, 0, LScratch, 8, 16) then
      Fail(Format('ProcessBlock dec overlap dst=src+8 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.FillChar(LScratch[0], 32, $22);
    System.Move(LCipher[0], LScratch[8], 16);
    LEngine.ProcessBlock(@LScratch[8], @LScratch[0]);
    if not MemEq(LPlain, 0, LScratch, 0, 16) then
      Fail(Format('ProcessBlock dec overlap dst=src-8 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 32);
    System.Move(LCipher[0], LScratch[0], 16);
    LEngine.ProcessBlock(@LScratch[0], @LScratch[15]);
    if not MemEq(LPlain, 0, LScratch, 15, 16) then
      Fail(Format('ProcessBlock dec overlap dst=src+15 (key %d, iter %d)',
        [AKeySizeBytes, LI]));
  end;
end;

procedure TAesHardwareEngineTestBase.ImplTestProcessFourBlocksMemoryLayouts(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LPlain, LCipher, LScratch: TBytes;
  LI: Int32;
  LEngine: IAesHardwareEngine;

  function MemEq(const A: TBytes; AOff: Int32; const B: TBytes; BOff, ALen: Int32): Boolean;
  begin
    Result := CompareMem(@A[AOff], @B[BOff], ALen);
  end;

begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeySizeBytes);
  System.SetLength(LPlain, 64);
  System.SetLength(LCipher, 64);

  for LI := 0 to 24 do
  begin
    LRnd.NextBytes(LKey);
    LRnd.NextBytes(LPlain);
    LEngine := CreateHwEngine;
    LEngine.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessFourBlocks(LPlain, 0, LCipher, 0);

    LScratch := System.Copy(LPlain);
    LEngine.ProcessFourBlocks(@LScratch[0], @LScratch[0]);
    if not AreEqual(LCipher, LScratch) then
      Fail(Format('ProcessFourBlocks enc in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 192);
    System.Move(LPlain[0], LScratch[0], 64);
    System.FillChar(LScratch[64], 128, $5A);
    LEngine.ProcessFourBlocks(@LScratch[0], @LScratch[64]);
    if not MemEq(LCipher, 0, LScratch, 64, 64) then
      Fail(Format('ProcessFourBlocks enc disjoint same allocation (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 128);
    System.Move(LPlain[0], LScratch[0], 64);
    System.FillChar(LScratch[64], 64, 0);
    LEngine.ProcessFourBlocks(@LScratch[0], @LScratch[32]);
    if not MemEq(LCipher, 0, LScratch, 32, 64) then
      Fail(Format('ProcessFourBlocks enc overlap dst=src+32 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.FillChar(LScratch[0], 128, 0);
    System.Move(LPlain[0], LScratch[32], 64);
    LEngine.ProcessFourBlocks(@LScratch[32], @LScratch[0]);
    if not MemEq(LCipher, 0, LScratch, 0, 64) then
      Fail(Format('ProcessFourBlocks enc overlap dst=src-32 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LEngine.Init(False, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessFourBlocks(LCipher, 0, LPlain, 0);

    LScratch := System.Copy(LCipher);
    LEngine.ProcessFourBlocks(@LScratch[0], @LScratch[0]);
    if not AreEqual(LPlain, LScratch) then
      Fail(Format('ProcessFourBlocks dec in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 192);
    System.Move(LCipher[0], LScratch[0], 64);
    System.FillChar(LScratch[64], 128, $4B);
    LEngine.ProcessFourBlocks(@LScratch[0], @LScratch[64]);
    if not MemEq(LPlain, 0, LScratch, 64, 64) then
      Fail(Format('ProcessFourBlocks dec disjoint same allocation (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 128);
    System.Move(LCipher[0], LScratch[0], 64);
    System.FillChar(LScratch[64], 64, $33);
    LEngine.ProcessFourBlocks(@LScratch[0], @LScratch[32]);
    if not MemEq(LPlain, 0, LScratch, 32, 64) then
      Fail(Format('ProcessFourBlocks dec overlap dst=src+32 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.FillChar(LScratch[0], 128, $44);
    System.Move(LCipher[0], LScratch[32], 64);
    LEngine.ProcessFourBlocks(@LScratch[32], @LScratch[0]);
    if not MemEq(LPlain, 0, LScratch, 0, 64) then
      Fail(Format('ProcessFourBlocks dec overlap dst=src-32 (key %d, iter %d)',
        [AKeySizeBytes, LI]));
  end;
end;

procedure TAesHardwareEngineTestBase.ImplTestProcessEightBlocksMemoryLayouts(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LPlain, LCipher, LScratch: TBytes;
  LI: Int32;
  LEngine: IAesHardwareEngine;

  function MemEq(const A: TBytes; AOff: Int32; const B: TBytes; BOff, ALen: Int32): Boolean;
  begin
    Result := CompareMem(@A[AOff], @B[BOff], ALen);
  end;

begin
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, AKeySizeBytes);
  System.SetLength(LPlain, 128);
  System.SetLength(LCipher, 128);

  for LI := 0 to 14 do
  begin
    LRnd.NextBytes(LKey);
    LRnd.NextBytes(LPlain);
    LEngine := CreateHwEngine;
    LEngine.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessEightBlocks(LPlain, 0, LCipher, 0);

    LScratch := System.Copy(LPlain);
    LEngine.ProcessEightBlocks(@LScratch[0], @LScratch[0]);
    if not AreEqual(LCipher, LScratch) then
      Fail(Format('ProcessEightBlocks enc in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 384);
    System.Move(LPlain[0], LScratch[0], 128);
    System.FillChar(LScratch[128], 256, $5A);
    LEngine.ProcessEightBlocks(@LScratch[0], @LScratch[128]);
    if not MemEq(LCipher, 0, LScratch, 128, 128) then
      Fail(Format('ProcessEightBlocks enc disjoint same allocation (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 256);
    System.Move(LPlain[0], LScratch[0], 128);
    System.FillChar(LScratch[128], 128, 0);
    LEngine.ProcessEightBlocks(@LScratch[0], @LScratch[64]);
    if not MemEq(LCipher, 0, LScratch, 64, 128) then
      Fail(Format('ProcessEightBlocks enc overlap dst=src+64 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.FillChar(LScratch[0], 256, 0);
    System.Move(LPlain[0], LScratch[64], 128);
    LEngine.ProcessEightBlocks(@LScratch[64], @LScratch[0]);
    if not MemEq(LCipher, 0, LScratch, 0, 128) then
      Fail(Format('ProcessEightBlocks enc overlap dst=src-64 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    LEngine.Init(False, TKeyParameter.Create(LKey) as IKeyParameter);
    LEngine.ProcessEightBlocks(LCipher, 0, LPlain, 0);

    LScratch := System.Copy(LCipher);
    LEngine.ProcessEightBlocks(@LScratch[0], @LScratch[0]);
    if not AreEqual(LPlain, LScratch) then
      Fail(Format('ProcessEightBlocks dec in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 384);
    System.Move(LCipher[0], LScratch[0], 128);
    System.FillChar(LScratch[128], 256, $4B);
    LEngine.ProcessEightBlocks(@LScratch[0], @LScratch[128]);
    if not MemEq(LPlain, 0, LScratch, 128, 128) then
      Fail(Format('ProcessEightBlocks dec disjoint same allocation (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.SetLength(LScratch, 256);
    System.Move(LCipher[0], LScratch[0], 128);
    System.FillChar(LScratch[128], 128, $33);
    LEngine.ProcessEightBlocks(@LScratch[0], @LScratch[64]);
    if not MemEq(LPlain, 0, LScratch, 64, 128) then
      Fail(Format('ProcessEightBlocks dec overlap dst=src+64 (key %d, iter %d)',
        [AKeySizeBytes, LI]));

    System.FillChar(LScratch[0], 256, $44);
    System.Move(LCipher[0], LScratch[64], 128);
    LEngine.ProcessEightBlocks(@LScratch[64], @LScratch[0]);
    if not MemEq(LPlain, 0, LScratch, 0, 128) then
      Fail(Format('ProcessEightBlocks dec overlap dst=src-64 (key %d, iter %d)',
        [AKeySizeBytes, LI]));
  end;
end;

procedure TAesHardwareEngineTestBase.TestEngineChecks128;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not EngineSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 16);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(CreateHwEngine,
    TKeyParameter.Create(LKey) as IKeyParameter, EngineLabel + ' 128-bit');
end;

procedure TAesHardwareEngineTestBase.TestEngineChecks192;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not EngineSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 24);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(CreateHwEngine,
    TKeyParameter.Create(LKey) as IKeyParameter, EngineLabel + ' 192-bit');
end;

procedure TAesHardwareEngineTestBase.TestEngineChecks256;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not EngineSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 32);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(CreateHwEngine,
    TKeyParameter.Create(LKey) as IKeyParameter, EngineLabel + ' 256-bit');
end;

procedure TAesHardwareEngineTestBase.TestFourBlocksEncrypt128;
begin
  if not EngineSupported then
    Exit;
  ImplTestFourBlocks(True, 16);
end;

procedure TAesHardwareEngineTestBase.TestFourBlocksEncrypt192;
begin
  if not EngineSupported then
    Exit;
  ImplTestFourBlocks(True, 24);
end;

procedure TAesHardwareEngineTestBase.TestFourBlocksEncrypt256;
begin
  if not EngineSupported then
    Exit;
  ImplTestFourBlocks(True, 32);
end;

procedure TAesHardwareEngineTestBase.TestFourBlocksDecrypt128;
begin
  if not EngineSupported then
    Exit;
  ImplTestFourBlocks(False, 16);
end;

procedure TAesHardwareEngineTestBase.TestFourBlocksDecrypt192;
begin
  if not EngineSupported then
    Exit;
  ImplTestFourBlocks(False, 24);
end;

procedure TAesHardwareEngineTestBase.TestFourBlocksDecrypt256;
begin
  if not EngineSupported then
    Exit;
  ImplTestFourBlocks(False, 32);
end;

procedure TAesHardwareEngineTestBase.TestEightBlocksEncrypt128;
begin
  if not EngineSupported then
    Exit;
  ImplTestEightBlocks(True, 16);
end;

procedure TAesHardwareEngineTestBase.TestEightBlocksEncrypt192;
begin
  if not EngineSupported then
    Exit;
  ImplTestEightBlocks(True, 24);
end;

procedure TAesHardwareEngineTestBase.TestEightBlocksEncrypt256;
begin
  if not EngineSupported then
    Exit;
  ImplTestEightBlocks(True, 32);
end;

procedure TAesHardwareEngineTestBase.TestEightBlocksDecrypt128;
begin
  if not EngineSupported then
    Exit;
  ImplTestEightBlocks(False, 16);
end;

procedure TAesHardwareEngineTestBase.TestEightBlocksDecrypt192;
begin
  if not EngineSupported then
    Exit;
  ImplTestEightBlocks(False, 24);
end;

procedure TAesHardwareEngineTestBase.TestEightBlocksDecrypt256;
begin
  if not EngineSupported then
    Exit;
  ImplTestEightBlocks(False, 32);
end;

procedure TAesHardwareEngineTestBase.TestPByteOverloadParity128;
begin
  if not EngineSupported then
    Exit;
  ImplTestPByteOverloadParity(16);
end;

procedure TAesHardwareEngineTestBase.TestPByteOverloadParity192;
begin
  if not EngineSupported then
    Exit;
  ImplTestPByteOverloadParity(24);
end;

procedure TAesHardwareEngineTestBase.TestPByteOverloadParity256;
begin
  if not EngineSupported then
    Exit;
  ImplTestPByteOverloadParity(32);
end;

procedure TAesHardwareEngineTestBase.TestProcessBlockMemoryLayouts128;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessBlockMemoryLayouts(16);
end;

procedure TAesHardwareEngineTestBase.TestProcessBlockMemoryLayouts192;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessBlockMemoryLayouts(24);
end;

procedure TAesHardwareEngineTestBase.TestProcessBlockMemoryLayouts256;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessBlockMemoryLayouts(32);
end;

procedure TAesHardwareEngineTestBase.TestProcessFourBlocksMemoryLayouts128;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessFourBlocksMemoryLayouts(16);
end;

procedure TAesHardwareEngineTestBase.TestProcessFourBlocksMemoryLayouts192;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessFourBlocksMemoryLayouts(24);
end;

procedure TAesHardwareEngineTestBase.TestProcessFourBlocksMemoryLayouts256;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessFourBlocksMemoryLayouts(32);
end;

procedure TAesHardwareEngineTestBase.TestProcessEightBlocksMemoryLayouts128;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessEightBlocksMemoryLayouts(16);
end;

procedure TAesHardwareEngineTestBase.TestProcessEightBlocksMemoryLayouts192;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessEightBlocksMemoryLayouts(24);
end;

procedure TAesHardwareEngineTestBase.TestProcessEightBlocksMemoryLayouts256;
begin
  if not EngineSupported then
    Exit;
  ImplTestProcessEightBlocksMemoryLayouts(32);
end;

{$IFDEF CRYPTOLIB_X86_SIMD}

function CreateAesX86Engine: IBlockCipher;
begin
  Result := TAesEngineX86.Create();
end;

{ TTestAesX86 }

function TTestAesX86.CreateHwEngine: IAesHardwareEngine;
begin
  Result := TAesEngineX86.Create();
end;

function TTestAesX86.EngineSupported: Boolean;
begin
  Result := TAesEngineX86.IsSupported;
end;

function TTestAesX86.EngineLabel: String;
begin
  Result := 'TAesEngineX86';
end;

function TTestAesX86.GetEngineFactory: TBlockCipherFactory;
begin
  Result := @CreateAesX86Engine;
end;

{$ENDIF CRYPTOLIB_X86_SIMD}

initialization

{$IFDEF CRYPTOLIB_X86_SIMD}
{$IFDEF FPC}
  RegisterTest(TTestAesX86);
{$ELSE}
  RegisterTest(TTestAesX86.Suite);
{$ENDIF FPC}
{$ENDIF CRYPTOLIB_X86_SIMD}

end.
