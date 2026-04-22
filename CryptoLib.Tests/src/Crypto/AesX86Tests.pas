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

unit AesX86Tests;

{$I ..\..\..\CryptoLib\src\Include\CryptoLib.inc}

interface

{$IFDEF CRYPTOLIB_X86_SIMD}

uses
  SysUtils,
{$IFDEF FPC}
  fpcunit,
  testregistry,
{$ELSE}
  TestFramework,
{$ENDIF FPC}
  ClpAesEngineX86,
  ClpIBlockCipher,
  ClpIKeyParameter,
  ClpKeyParameter,
  ClpSecureRandom,
  ClpISecureRandom,
  AesBlockCipherTestBase;

type

  TTestAesX86 = class(TAesBlockCipherTestBase)
  strict private
    procedure ImplTestFourBlocks(AForEncryption: Boolean; AKeySizeBytes: Int32);
    procedure ImplTestEightBlocks(AForEncryption: Boolean; AKeySizeBytes: Int32);
    procedure ImplTestPByteOverloadParity(AKeySizeBytes: Int32);
    procedure ImplTestProcessBlockMemoryLayouts(AKeySizeBytes: Int32);
    procedure ImplTestProcessFourBlocksMemoryLayouts(AKeySizeBytes: Int32);
    procedure ImplTestProcessEightBlocksMemoryLayouts(AKeySizeBytes: Int32);
  published
    procedure TestBlockCipherVectors;
    procedure TestMonteCarloAES;
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

{$ENDIF CRYPTOLIB_X86_SIMD}

implementation

{$IFDEF CRYPTOLIB_X86_SIMD}

function CreateAesX86Engine: IBlockCipher;
begin
  Result := TAesEngineX86.Create();
end;

{ TTestAesX86 }

procedure TTestAesX86.ImplTestFourBlocks(AForEncryption: Boolean;
  AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LData, LFourOut, LSingleOut, LKey: TBytes;
  LI, LJ: Int32;
  LX86: TAesEngineX86;
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
    LX86 := TAesEngineX86.Create();
    try
      LX86.Init(AForEncryption, TKeyParameter.Create(LKey) as IKeyParameter);
      LX86.ProcessFourBlocks(LData, 0, LFourOut, 0);
      for LJ := 0 to 3 do
        LX86.ProcessBlock(LData, LJ * 16, LSingleOut, LJ * 16);
      if not AreEqual(LFourOut, LSingleOut) then
      begin
        Fail(Format(
          'ProcessFourBlocks vs ProcessBlock mismatch (key %d bytes, iteration %d)',
          [AKeySizeBytes, LI]));
      end;
    finally
      LX86.Free;
    end;
  end;
end;

procedure TTestAesX86.ImplTestEightBlocks(AForEncryption: Boolean;
  AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LData, LEightOut, LSingleOut, LKey: TBytes;
  LI, LJ: Int32;
  LX86: TAesEngineX86;
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
    LX86 := TAesEngineX86.Create();
    try
      LX86.Init(AForEncryption, TKeyParameter.Create(LKey) as IKeyParameter);
      LX86.ProcessEightBlocks(LData, 0, LEightOut, 0);
      for LJ := 0 to 7 do
        LX86.ProcessBlock(LData, LJ * 16, LSingleOut, LJ * 16);
      if not AreEqual(LEightOut, LSingleOut) then
      begin
        Fail(Format(
          'ProcessEightBlocks vs ProcessBlock mismatch (key %d bytes, iteration %d)',
          [AKeySizeBytes, LI]));
      end;
    finally
      LX86.Free;
    end;
  end;
end;

procedure TTestAesX86.ImplTestPByteOverloadParity(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LIn16, LOutArr, LOutPtr, LIn64, LFourArr, LFourPtr,
    LIn128, LEightArr, LEightPtr: TBytes;
  LI: Int32;
  LObj: TAesEngineX86;
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
    LObj := TAesEngineX86.Create();
    try
      LObj.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);

      LOutArr := System.Copy(LIn16);
      LOutPtr := System.Copy(LIn16);
      LObj.ProcessBlock(LIn16, 0, LOutArr, 0);
      LObj.ProcessBlock(@LIn16[0], @LOutPtr[0]);
      if not AreEqual(LOutArr, LOutPtr) then
        Fail(Format('ProcessBlock PByte disjoint mismatch (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LOutPtr := System.Copy(LIn16);
      LObj.ProcessBlock(@LOutPtr[0], @LOutPtr[0]);
      if not AreEqual(LOutArr, LOutPtr) then
        Fail(Format('ProcessBlock PByte in-place mismatch (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LRnd.NextBytes(LIn64);
      LFourArr := System.Copy(LIn64);
      LFourPtr := System.Copy(LIn64);
      LObj.ProcessFourBlocks(LIn64, 0, LFourArr, 0);
      LObj.ProcessFourBlocks(@LIn64[0], @LFourPtr[0]);
      if not AreEqual(LFourArr, LFourPtr) then
        Fail(Format('ProcessFourBlocks PByte disjoint mismatch (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LFourPtr := System.Copy(LIn64);
      LObj.ProcessFourBlocks(@LFourPtr[0], @LFourPtr[0]);
      if not AreEqual(LFourArr, LFourPtr) then
        Fail(Format('ProcessFourBlocks PByte in-place mismatch (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LRnd.NextBytes(LIn128);
      LEightArr := System.Copy(LIn128);
      LEightPtr := System.Copy(LIn128);
      LObj.ProcessEightBlocks(LIn128, 0, LEightArr, 0);
      LObj.ProcessEightBlocks(@LIn128[0], @LEightPtr[0]);
      if not AreEqual(LEightArr, LEightPtr) then
        Fail(Format('ProcessEightBlocks PByte disjoint mismatch (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LEightPtr := System.Copy(LIn128);
      LObj.ProcessEightBlocks(@LEightPtr[0], @LEightPtr[0]);
      if not AreEqual(LEightArr, LEightPtr) then
        Fail(Format('ProcessEightBlocks PByte in-place mismatch (key %d, iter %d)',
          [AKeySizeBytes, LI]));
    finally
      LObj.Free;
    end;
  end;
end;

procedure TTestAesX86.ImplTestProcessBlockMemoryLayouts(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LPlain, LCipher, LExpectedPt, LScratch: TBytes;
  LI: Int32;
  LObj: TAesEngineX86;

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
    LObj := TAesEngineX86.Create();
    try
      LObj.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);
      LObj.ProcessBlock(LPlain, 0, LCipher, 0);

      LScratch := System.Copy(LPlain);
      LObj.ProcessBlock(@LScratch[0], @LScratch[0]);
      if not AreEqual(LCipher, LScratch) then
        Fail(Format('ProcessBlock enc in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 48);
      System.Move(LPlain[0], LScratch[0], 16);
      System.FillChar(LScratch[16], 32, $7D);
      LObj.ProcessBlock(@LScratch[0], @LScratch[16]);
      if not MemEq(LCipher, 0, LScratch, 16, 16) then
        Fail(Format('ProcessBlock enc disjoint same allocation (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 40);
      System.Move(LPlain[0], LScratch[0], 16);
      System.FillChar(LScratch[16], 24, 0);
      LObj.ProcessBlock(@LScratch[0], @LScratch[8]);
      if not MemEq(LCipher, 0, LScratch, 8, 16) then
        Fail(Format('ProcessBlock enc overlap dst=src+8 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.FillChar(LScratch[0], 32, 0);
      System.Move(LPlain[0], LScratch[8], 16);
      LObj.ProcessBlock(@LScratch[8], @LScratch[0]);
      if not MemEq(LCipher, 0, LScratch, 0, 16) then
        Fail(Format('ProcessBlock enc overlap dst=src-8 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 32);
      System.Move(LPlain[0], LScratch[0], 16);
      LObj.ProcessBlock(@LScratch[0], @LScratch[15]);
      if not MemEq(LCipher, 0, LScratch, 15, 16) then
        Fail(Format('ProcessBlock enc overlap dst=src+15 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LObj.Init(False, TKeyParameter.Create(LKey) as IKeyParameter);
      LObj.ProcessBlock(LCipher, 0, LExpectedPt, 0);
      if not AreEqual(LPlain, LExpectedPt) then
        Fail(Format('ProcessBlock dec reference sanity (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LScratch := System.Copy(LCipher);
      LObj.ProcessBlock(@LScratch[0], @LScratch[0]);
      if not AreEqual(LPlain, LScratch) then
        Fail(Format('ProcessBlock dec in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 48);
      System.Move(LCipher[0], LScratch[0], 16);
      System.FillChar(LScratch[16], 32, $3C);
      LObj.ProcessBlock(@LScratch[0], @LScratch[16]);
      if not MemEq(LPlain, 0, LScratch, 16, 16) then
        Fail(Format('ProcessBlock dec disjoint same allocation (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 40);
      System.Move(LCipher[0], LScratch[0], 16);
      System.FillChar(LScratch[16], 24, $11);
      LObj.ProcessBlock(@LScratch[0], @LScratch[8]);
      if not MemEq(LPlain, 0, LScratch, 8, 16) then
        Fail(Format('ProcessBlock dec overlap dst=src+8 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.FillChar(LScratch[0], 32, $22);
      System.Move(LCipher[0], LScratch[8], 16);
      LObj.ProcessBlock(@LScratch[8], @LScratch[0]);
      if not MemEq(LPlain, 0, LScratch, 0, 16) then
        Fail(Format('ProcessBlock dec overlap dst=src-8 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 32);
      System.Move(LCipher[0], LScratch[0], 16);
      LObj.ProcessBlock(@LScratch[0], @LScratch[15]);
      if not MemEq(LPlain, 0, LScratch, 15, 16) then
        Fail(Format('ProcessBlock dec overlap dst=src+15 (key %d, iter %d)',
          [AKeySizeBytes, LI]));
    finally
      LObj.Free;
    end;
  end;
end;

procedure TTestAesX86.ImplTestProcessFourBlocksMemoryLayouts(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LPlain, LCipher, LScratch: TBytes;
  LI: Int32;
  LObj: TAesEngineX86;

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
    LObj := TAesEngineX86.Create();
    try
      LObj.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);
      LObj.ProcessFourBlocks(LPlain, 0, LCipher, 0);

      LScratch := System.Copy(LPlain);
      LObj.ProcessFourBlocks(@LScratch[0], @LScratch[0]);
      if not AreEqual(LCipher, LScratch) then
        Fail(Format('ProcessFourBlocks enc in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 192);
      System.Move(LPlain[0], LScratch[0], 64);
      System.FillChar(LScratch[64], 128, $5A);
      LObj.ProcessFourBlocks(@LScratch[0], @LScratch[64]);
      if not MemEq(LCipher, 0, LScratch, 64, 64) then
        Fail(Format('ProcessFourBlocks enc disjoint same allocation (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 128);
      System.Move(LPlain[0], LScratch[0], 64);
      System.FillChar(LScratch[64], 64, 0);
      LObj.ProcessFourBlocks(@LScratch[0], @LScratch[32]);
      if not MemEq(LCipher, 0, LScratch, 32, 64) then
        Fail(Format('ProcessFourBlocks enc overlap dst=src+32 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.FillChar(LScratch[0], 128, 0);
      System.Move(LPlain[0], LScratch[32], 64);
      LObj.ProcessFourBlocks(@LScratch[32], @LScratch[0]);
      if not MemEq(LCipher, 0, LScratch, 0, 64) then
        Fail(Format('ProcessFourBlocks enc overlap dst=src-32 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LObj.Init(False, TKeyParameter.Create(LKey) as IKeyParameter);
      LObj.ProcessFourBlocks(LCipher, 0, LPlain, 0);

      LScratch := System.Copy(LCipher);
      LObj.ProcessFourBlocks(@LScratch[0], @LScratch[0]);
      if not AreEqual(LPlain, LScratch) then
        Fail(Format('ProcessFourBlocks dec in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 192);
      System.Move(LCipher[0], LScratch[0], 64);
      System.FillChar(LScratch[64], 128, $4B);
      LObj.ProcessFourBlocks(@LScratch[0], @LScratch[64]);
      if not MemEq(LPlain, 0, LScratch, 64, 64) then
        Fail(Format('ProcessFourBlocks dec disjoint same allocation (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 128);
      System.Move(LCipher[0], LScratch[0], 64);
      System.FillChar(LScratch[64], 64, $33);
      LObj.ProcessFourBlocks(@LScratch[0], @LScratch[32]);
      if not MemEq(LPlain, 0, LScratch, 32, 64) then
        Fail(Format('ProcessFourBlocks dec overlap dst=src+32 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.FillChar(LScratch[0], 128, $44);
      System.Move(LCipher[0], LScratch[32], 64);
      LObj.ProcessFourBlocks(@LScratch[32], @LScratch[0]);
      if not MemEq(LPlain, 0, LScratch, 0, 64) then
        Fail(Format('ProcessFourBlocks dec overlap dst=src-32 (key %d, iter %d)',
          [AKeySizeBytes, LI]));
    finally
      LObj.Free;
    end;
  end;
end;

procedure TTestAesX86.ImplTestProcessEightBlocksMemoryLayouts(AKeySizeBytes: Int32);
var
  LRnd: ISecureRandom;
  LKey, LPlain, LCipher, LScratch: TBytes;
  LI: Int32;
  LObj: TAesEngineX86;

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
    LObj := TAesEngineX86.Create();
    try
      LObj.Init(True, TKeyParameter.Create(LKey) as IKeyParameter);
      LObj.ProcessEightBlocks(LPlain, 0, LCipher, 0);

      LScratch := System.Copy(LPlain);
      LObj.ProcessEightBlocks(@LScratch[0], @LScratch[0]);
      if not AreEqual(LCipher, LScratch) then
        Fail(Format('ProcessEightBlocks enc in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 384);
      System.Move(LPlain[0], LScratch[0], 128);
      System.FillChar(LScratch[128], 256, $5A);
      LObj.ProcessEightBlocks(@LScratch[0], @LScratch[128]);
      if not MemEq(LCipher, 0, LScratch, 128, 128) then
        Fail(Format('ProcessEightBlocks enc disjoint same allocation (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 256);
      System.Move(LPlain[0], LScratch[0], 128);
      System.FillChar(LScratch[128], 128, 0);
      LObj.ProcessEightBlocks(@LScratch[0], @LScratch[64]);
      if not MemEq(LCipher, 0, LScratch, 64, 128) then
        Fail(Format('ProcessEightBlocks enc overlap dst=src+64 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.FillChar(LScratch[0], 256, 0);
      System.Move(LPlain[0], LScratch[64], 128);
      LObj.ProcessEightBlocks(@LScratch[64], @LScratch[0]);
      if not MemEq(LCipher, 0, LScratch, 0, 128) then
        Fail(Format('ProcessEightBlocks enc overlap dst=src-64 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      LObj.Init(False, TKeyParameter.Create(LKey) as IKeyParameter);
      LObj.ProcessEightBlocks(LCipher, 0, LPlain, 0);

      LScratch := System.Copy(LCipher);
      LObj.ProcessEightBlocks(@LScratch[0], @LScratch[0]);
      if not AreEqual(LPlain, LScratch) then
        Fail(Format('ProcessEightBlocks dec in-place (key %d, iter %d)', [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 384);
      System.Move(LCipher[0], LScratch[0], 128);
      System.FillChar(LScratch[128], 256, $4B);
      LObj.ProcessEightBlocks(@LScratch[0], @LScratch[128]);
      if not MemEq(LPlain, 0, LScratch, 128, 128) then
        Fail(Format('ProcessEightBlocks dec disjoint same allocation (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.SetLength(LScratch, 256);
      System.Move(LCipher[0], LScratch[0], 128);
      System.FillChar(LScratch[128], 128, $33);
      LObj.ProcessEightBlocks(@LScratch[0], @LScratch[64]);
      if not MemEq(LPlain, 0, LScratch, 64, 128) then
        Fail(Format('ProcessEightBlocks dec overlap dst=src+64 (key %d, iter %d)',
          [AKeySizeBytes, LI]));

      System.FillChar(LScratch[0], 256, $44);
      System.Move(LCipher[0], LScratch[64], 128);
      LObj.ProcessEightBlocks(@LScratch[64], @LScratch[0]);
      if not MemEq(LPlain, 0, LScratch, 0, 128) then
        Fail(Format('ProcessEightBlocks dec overlap dst=src-64 (key %d, iter %d)',
          [AKeySizeBytes, LI]));
    finally
      LObj.Free;
    end;
  end;
end;

procedure TTestAesX86.TestBlockCipherVectors;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunBlockCipherVectorTests(@CreateAesX86Engine, 'TAesEngineX86');
end;

procedure TTestAesX86.TestMonteCarloAES;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  RunBlockCipherMonteCarloTests(@CreateAesX86Engine, 'TAesEngineX86');
end;

procedure TTestAesX86.TestEngineChecks128;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 16);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(TAesEngineX86.Create() as IBlockCipher,
    TKeyParameter.Create(LKey) as IKeyParameter, 'TAesEngineX86 128-bit');
end;

procedure TTestAesX86.TestEngineChecks192;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 24);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(TAesEngineX86.Create() as IBlockCipher,
    TKeyParameter.Create(LKey) as IKeyParameter, 'TAesEngineX86 192-bit');
end;

procedure TTestAesX86.TestEngineChecks256;
var
  LKey: TBytes;
  LRnd: ISecureRandom;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  LRnd := TSecureRandom.Create();
  System.SetLength(LKey, 32);
  LRnd.NextBytes(LKey);
  RunCipherEngineChecks(TAesEngineX86.Create() as IBlockCipher,
    TKeyParameter.Create(LKey) as IKeyParameter, 'TAesEngineX86 256-bit');
end;

procedure TTestAesX86.TestFourBlocksEncrypt128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(True, 16);
end;

procedure TTestAesX86.TestFourBlocksEncrypt192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(True, 24);
end;

procedure TTestAesX86.TestFourBlocksEncrypt256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(True, 32);
end;

procedure TTestAesX86.TestFourBlocksDecrypt128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(False, 16);
end;

procedure TTestAesX86.TestFourBlocksDecrypt192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(False, 24);
end;

procedure TTestAesX86.TestFourBlocksDecrypt256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestFourBlocks(False, 32);
end;

procedure TTestAesX86.TestEightBlocksEncrypt128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestEightBlocks(True, 16);
end;

procedure TTestAesX86.TestEightBlocksEncrypt192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestEightBlocks(True, 24);
end;

procedure TTestAesX86.TestEightBlocksEncrypt256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestEightBlocks(True, 32);
end;

procedure TTestAesX86.TestEightBlocksDecrypt128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestEightBlocks(False, 16);
end;

procedure TTestAesX86.TestEightBlocksDecrypt192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestEightBlocks(False, 24);
end;

procedure TTestAesX86.TestEightBlocksDecrypt256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestEightBlocks(False, 32);
end;

procedure TTestAesX86.TestPByteOverloadParity128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestPByteOverloadParity(16);
end;

procedure TTestAesX86.TestPByteOverloadParity192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestPByteOverloadParity(24);
end;

procedure TTestAesX86.TestPByteOverloadParity256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestPByteOverloadParity(32);
end;

procedure TTestAesX86.TestProcessBlockMemoryLayouts128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessBlockMemoryLayouts(16);
end;

procedure TTestAesX86.TestProcessBlockMemoryLayouts192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessBlockMemoryLayouts(24);
end;

procedure TTestAesX86.TestProcessBlockMemoryLayouts256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessBlockMemoryLayouts(32);
end;

procedure TTestAesX86.TestProcessFourBlocksMemoryLayouts128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessFourBlocksMemoryLayouts(16);
end;

procedure TTestAesX86.TestProcessFourBlocksMemoryLayouts192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessFourBlocksMemoryLayouts(24);
end;

procedure TTestAesX86.TestProcessFourBlocksMemoryLayouts256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessFourBlocksMemoryLayouts(32);
end;

procedure TTestAesX86.TestProcessEightBlocksMemoryLayouts128;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessEightBlocksMemoryLayouts(16);
end;

procedure TTestAesX86.TestProcessEightBlocksMemoryLayouts192;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessEightBlocksMemoryLayouts(24);
end;

procedure TTestAesX86.TestProcessEightBlocksMemoryLayouts256;
begin
  if not TAesEngineX86.IsSupported then
    Exit;
  ImplTestProcessEightBlocksMemoryLayouts(32);
end;

initialization

{$IFDEF FPC}
  RegisterTest(TTestAesX86);
{$ELSE}
  RegisterTest(TTestAesX86.Suite);
{$ENDIF FPC}

{$ENDIF CRYPTOLIB_X86_SIMD}

end.
